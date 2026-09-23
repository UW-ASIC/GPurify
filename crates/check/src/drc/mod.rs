//! Design rule checking: a deck's DRC rows as one [`RuleSet`], run row by row.
//!
//! Data in: the deck (via [`RuleSet::from_deck`]) and the layout's `GeometryStore`.
//! Data out: `Violations` plus one `RuleRun` per rule row. A rule that cannot run
//! says so (`Skipped` / `Refused`); neither is ever collapsed into a clean `Ran`.

pub mod rules;
pub mod ruleset;

pub use ruleset::{Rule, RuleSet};

use gpurify_geom::connectivity::ComponentLabel;
use gpurify_geom::index::SpatialIndex;
use gpurify_geom::view::{validate_layer_into, ValidityError};
use gpurify_geom::{Bbox, DbuArea, GeometryStore, LayerId, PolyId, ValidatedLayer};

/// Why a deck could not be turned into a [`RuleSet`]. Load time only: geometry a
/// rule cannot handle is that rule's `Refused` row, not an error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DrcError {
    #[error("rule {rule}: unknown rule kind {kind}")]
    UnknownKind { rule: String, kind: String },
    #[error("rule {rule}: missing required parameter {param}")]
    MissingParam { rule: String, param: &'static str },
    #[error("rule {rule}: parameter {param} is not the kind of value this rule takes")]
    WrongParamType { rule: String, param: &'static str },
    #[error("rule {rule}: takes {expected} layers, the deck names {found}")]
    WrongLayerCount {
        rule: String,
        expected: u32,
        found: u32,
    },
    #[error("rule {rule}: limit {limit} is not positive")]
    NonPositiveLimit { rule: String, limit: i64 },
    /// Only multiples of 45 degrees are exact integer edge directions.
    #[error("rule {rule}: {degrees} degrees is not exactly representable")]
    UnrepresentableAngle { rule: String, degrees: i32 },
    #[error("duplicate rule id {0}")]
    DuplicateRule(String),
}

/// The buffers every rule refills; one `&mut` means rules run sequentially.
#[derive(Debug, Default)]
pub(crate) struct Scratch {
    validated: Validated,
    /// A boolean result: a merged layer.
    layer_out: ValidatedLayer,
    index_a: SpatialIndex,
    index_b: SpatialIndex,
    /// Candidate pairs from the proximity prune — a superset, checked exactly.
    pairs: Vec<(PolyId, PolyId)>,
    /// Exact squared distance per candidate pair.
    dists: Vec<DbuArea>,
    /// Rectilinear decomposition of `layer_out`, CSR by figure.
    rects: Vec<Bbox>,
    rect_start: Vec<u32>,
    edges: Vec<(u32, u32)>,
    labels: Vec<ComponentLabel>,
    /// Per-row flags (wide shapes), per-node colours.
    bytes: Vec<u8>,
    facing: gpurify_geom::width::FacingScratch,
    rects_a: rules::LayerRects,
    rects_b: rules::LayerRects,
}

/// Each layer validated at most once per run, kept until the last rule that
/// reads it (`RuleSet::run` forgets it then).
#[derive(Debug, Default)]
pub(crate) struct Validated {
    /// Per layer: `None` until first asked.
    slots: Vec<Option<Result<ValidatedLayer, ValidityError>>>,
}

impl Validated {
    /// `layer` validated, or `None` when it does not validate (the rule is `Refused`).
    pub(crate) fn get(&mut self, store: &GeometryStore, layer: LayerId) -> Option<&ValidatedLayer> {
        if self.slots.len() <= layer.idx() {
            self.slots.resize_with(layer.idx() + 1, || None);
        }
        self.slots[layer.idx()]
            .get_or_insert_with(|| {
                let mut out = ValidatedLayer::default();
                validate_layer_into(store, layer, &mut out).map(|()| out)
            })
            .as_ref()
            .ok()
    }

    pub(crate) fn forget(&mut self, layer: LayerId) {
        if let Some(slot) = self.slots.get_mut(layer.idx()) {
            *slot = None;
        }
    }
}
