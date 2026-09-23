//! Fixtures shared by the DRC suite: ids, layers, and a one-call rule runner.

#![allow(
    dead_code,
    reason = "each test binary links only the fixtures it names"
)]

use gpurify_check::drc::{Rule, RuleSet};
use gpurify_check::report::{RuleRun, Violations};
use gpurify_geom::view::validate_layer_into;
use gpurify_geom::{GeometryStore, LayerId, ValidatedLayer};
use gpurify_ingest::StrId;

pub const RULE: StrId = StrId(0);
pub const OTHER_RULE: StrId = StrId(1);

/// `LayerId(0)` because `LayoutBuilder` sizes its layer table from the highest id.
pub const A: LayerId = LayerId(0);
pub const B: LayerId = LayerId(1);

/// What one run of some rules produced.
#[derive(Debug, Default)]
pub struct Sink {
    pub out: Violations,
    pub runs: Vec<RuleRun>,
}

impl Sink {
    /// Run `rules` over `store`, replacing what the sink held.
    pub fn run(&mut self, store: &GeometryStore, rules: &[(StrId, Rule)]) {
        let set = RuleSet {
            rules: rules.to_vec(),
        };
        set.run(store, &mut self.out, &mut self.runs);
    }
}

/// Validate one layer, panicking with the reason if it will not.
#[must_use]
pub fn validated(store: &GeometryStore, layer: LayerId) -> ValidatedLayer {
    let mut out = ValidatedLayer::default();
    validate_layer_into(store, layer, &mut out)
        .unwrap_or_else(|error| panic!("the fixture layer {layer:?} did not validate: {error}"));
    out
}
