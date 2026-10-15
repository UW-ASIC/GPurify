//! Two layouts compared layer by layer: `gpurify xor <layout> <other> --deck <deck>`.
//!
//! For every drawn layer the deck declares, the region where exactly one of
//! the two layouts has material, the symmetric difference `A xor B` of the
//! layer's merged shapes, as `KLayout`'s `xor` computes it (its DRC `^` and
//! `Region#^`, and its XOR tool; [DRC
//! reference](https://www.klayout.de/doc-qt5/about/drc_ref_layer.html#xor)).
//! Each connected piece of that region is one violation, measured by its area
//! (holes excluded), so a layer's total measured area is the area the two
//! layouts disagree on. On a cut layer whose cuts in `B` lie within those
//! of `A`, that total is the cut area `A` lost: the sky130 IR-drop rules
//! compare it between "the Al database and the slotted Cu database for the
//! same product (2 gds files)" (sky130 periphery rules `ct.irdrop`,
//! `via.irdrop`, and the `(IR)` note). Catalog DRC-068.
//!
//! What it does not do: hold a connector's cut-area change to a tolerance by
//! its cut count, as those rules do, because their text leaves unsettled
//! what a connector is and the unit of the limit; derived layers and text
//! labels are not compared.
//!
//! Data in: [`Inputs`] (the first layout and the deck) and the second
//! layout's path. Data out: one [`RuleRun`] per drawn layer, id
//! `xor.<layer>`, and the violations, reported as the DRC stage.

use crate::engine::pipeline::{load_with, Inputs, LoadError, Loaded};
use crate::engine::run::{summarize, EngineError, Outputs, StageStatus, Summary};
use gpurify_check::deck::DeckFn;
use gpurify_check::report::{Measurement, Outcome, RuleRun, Severity, Violation};
use gpurify_geom::boolean::{subtraction_into, union_into};
use gpurify_geom::ops::Point;
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::{DbuArea, GeometryStore, LayerId, PolyId};
use gpurify_ingest::layout::{gds::Library, read_gds_bytes, UnknownLayers};
use std::path::Path;

/// Loads `inputs` and the layout at `other` against the same deck, and
/// compares them layer by layer, as the module docs say. The second layout's
/// text labels are read but not bound.
///
/// # Errors
///
/// - [`EngineError::Load`]: either layout, or the deck, cannot be read, as
///   [`load`](crate::engine::pipeline::load) says; the second layout is held to the deck's layers as the
///   first is.
/// - [`EngineError::GridMismatch`]: the two layouts' `UNITS` differ.
pub fn run(inputs: &Inputs, other: &Path) -> Result<(Loaded, Outputs, Summary), EngineError> {
    run_with(inputs, other, &[])
}

/// [`run`], with the decks a binary carries by name, as
/// [`load_with`] reads them.
///
/// # Errors
///
/// As [`run`].
pub fn run_with(
    inputs: &Inputs,
    other: &Path,
    decks: &[(&str, DeckFn)],
) -> Result<(Loaded, Outputs, Summary), EngineError> {
    let mut loaded = load_with(inputs, decks)?;
    let bytes = read_gds_bytes(other).map_err(LoadError::from)?;
    let library = Library::parse(&bytes, &mut loaded.strings).map_err(LoadError::from)?;
    let grid = library.grid().map_err(LoadError::from)?;
    if grid != loaded.grid {
        return Err(EngineError::GridMismatch {
            first: loaded.grid.dbu_per_um(),
            second: grid.dbu_per_um(),
        });
    }
    let (store, _labels) = library
        .flatten(&loaded.deck, &loaded.strings, UnknownLayers::Reject)
        .map_err(LoadError::from)?;
    let mut out = Outputs::default();
    compare_into(&mut loaded, &store, &mut out);
    let summary = summarize(
        &mut out,
        [
            StageStatus::Ran,
            StageStatus::NotSelected,
            StageStatus::NotSelected,
            StageStatus::NotSelected,
        ],
    );
    Ok((loaded, out, summary))
}

/// One row per drawn layer of `loaded`'s deck: `Ran` with a violation per
/// piece of `A xor B`, or `Refused` when either side's layer does not
/// validate (a non-rectilinear shape). `examined` counts both sides' polygons.
fn compare_into(loaded: &mut Loaded, other: &GeometryStore, out: &mut Outputs) {
    let [mut a, mut b, mut a_only, mut b_only, mut differ]: [ValidatedLayer; 5] =
        Default::default();
    for index in 0..loaded.deck.layers.len() {
        let layer = LayerId(u16::try_from(index).expect("a LayerId is a u16"));
        if loaded.deck.layers.is_derived(layer) {
            continue;
        }
        let name = format!(
            "xor.{}",
            loaded.strings.resolve(loaded.deck.layers.name(layer))
        );
        let rule = loaded.strings.intern(&name);
        let polygons = |store: &GeometryStore| {
            let rows = store.polys_on_layer(layer);
            u64::from(rows.end - rows.start)
        };
        let examined = polygons(&loaded.store) + polygons(other);
        let compared = validate_layer_into(&loaded.store, layer, &mut a).is_ok()
            && validate_layer_into(other, layer, &mut b).is_ok()
            && subtraction_into(&a, &b, &mut a_only).is_ok()
            && subtraction_into(&b, &a, &mut b_only).is_ok()
            && union_into(&a_only, &b_only, &mut differ).is_ok();
        let before = out.violations.len();
        if compared {
            for piece in
                0..u32::try_from(differ.len()).expect("a layer indexes polygons with a u32")
            {
                let polygon = differ.get(piece);
                let area2 = polygon
                    .rings()
                    .fold(0i128, |sum, ring| sum + ring.area2().raw());
                let (xs, ys) = polygon.outer().coords();
                out.violations.push(Violation {
                    rule,
                    layer,
                    severity: Severity::Error,
                    at: Point { x: xs[0], y: ys[0] },
                    measured: Measurement::Area(DbuArea::new(area2 / 2)),
                    limit: Measurement::Area(DbuArea::new(0)),
                    shapes: (PolyId(u32::MAX), None),
                });
            }
        }
        out.runs.push(RuleRun {
            rule,
            outcome: if compared {
                Outcome::Ran
            } else {
                Outcome::Refused
            },
            examined,
            violations: u32::try_from(out.violations.len() - before).unwrap_or(u32::MAX),
        });
    }
}
