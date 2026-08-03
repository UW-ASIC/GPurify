//! Fixtures shared by the DRC suite.
//!
//! Three things live here and nothing else: the interned ids and layer ids the
//! whole suite uses, the borrowed-table bundle every transform takes, and the
//! caller-owned buffer set every transform writes into. Each exists because it
//! would otherwise be repeated in every one of the two hundred-odd tests below,
//! not because it hides anything — every field is public and every transform
//! call still names all five of its parameters.
//!
//! `StrTable::intern` and `LayerTable` are frozen signatures a test cannot
//! reach (`docs/NEED_TESTING.md`), so rule ids and layer ids are constructed
//! directly from their public tuple fields. That is legitimate: a `StrId` is a
//! `u32` and nothing in `drc` resolves one back to text.

#![allow(dead_code)]

use gpurify_core::view::validate_layer_into;
use gpurify_core::{GeometryStore, LayerId, ValidatedLayer};
use gpurify_derived::Evaluator;
use gpurify_drc::{Design, Scratch};
use gpurify_ingest::StrId;
use gpurify_report::{RuleRun, Violations};
use gpurify_topology::{DeviceTable, NetTable};

/// The rule under test in almost every case.
pub const RULE: StrId = StrId(0);
/// A second rule id, for the cases that need two rows in one table.
pub const OTHER_RULE: StrId = StrId(1);

/// The primary layer. `LayerId(0)` because `LayoutBuilder` sizes its layer
/// table from the highest id a shape names.
pub const A: LayerId = LayerId(0);
/// The second layer, for the two-layer families.
pub const B: LayerId = LayerId(1);

/// The tables a [`Design`] borrows, owned so a test can hand out the borrow.
///
/// `nets` and `devices` are empty in every geometric test. That is not a
/// convenience: `Design` deliberately takes them unconditionally rather than as
/// `Option`, so "no topology extracted" and "topology with nothing in it" are
/// the same input, and every rule outside the antenna family must reach the
/// same verdict either way.
#[derive(Debug, Default)]
pub struct Env {
    pub derived: Evaluator,
    pub nets: NetTable,
    pub devices: DeviceTable,
}

impl Env {
    pub fn design<'a>(&'a self, store: &'a GeometryStore) -> Design<'a> {
        Design {
            store,
            derived: &self.derived,
            nets: &self.nets,
            devices: &self.devices,
        }
    }
}

/// The three caller-owned buffers every rule transform writes into.
///
/// One struct rather than three locals, so the three-parameter tail of every
/// `check_*` call is `&mut sink.scratch, &mut sink.out, &mut sink.runs` and the
/// borrows stay disjoint.
#[derive(Debug, Default)]
pub struct Sink {
    pub scratch: Scratch,
    pub out: Violations,
    pub runs: Vec<RuleRun>,
}

/// Validate one layer, panicking with the reason if it will not.
///
/// The decision tests below take a `PolygonRef`, and this is the only
/// constructor for one.
///
/// # Panics
///
/// When the layer holds geometry the tool does not represent exactly.
#[must_use]
pub fn validated(store: &GeometryStore, layer: LayerId) -> ValidatedLayer {
    let mut out = ValidatedLayer::default();
    validate_layer_into(store, layer, &mut out)
        .unwrap_or_else(|error| panic!("the fixture layer {layer:?} did not validate: {error}"));
    out
}
