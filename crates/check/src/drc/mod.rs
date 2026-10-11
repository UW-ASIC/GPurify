//! Design rule checking: a deck's DRC rows as one [`RuleSet`], run row by row.
//!
//! Data in: the deck (via [`RuleSet::from_deck`], usually through
//! [`deck::compile`](crate::deck::compile)) and the layout's
//! [`GeometryStore`], plus its extracted nets for [`Rule::NetSpacing`]
//! ([`RuleSet::run_with_nets`]). Data out:
//! [`Violations`](crate::report::Violations) plus one
//! [`RuleRun`](crate::report::RuleRun) per rule row. A rule that cannot run
//! says so ([`Outcome::Skipped`](crate::report::Outcome::Skipped) or
//! [`Outcome::Refused`](crate::report::Outcome::Refused)); neither is ever
//! collapsed into a clean `Ran`.
//!
//! [`Rule`] defines every kind: what it flags, how it measures, where it
//! reports, and which foundry rules it implements.

pub mod rules;
pub mod ruleset;

pub use ruleset::{Rule, RuleSet, SpacingQuery, StepKind};

use gpurify_geom::connectivity::ComponentLabel;
use gpurify_geom::index::SpatialIndex;
use gpurify_geom::view::{validate_layer_into, ValidityError};
use gpurify_geom::{Bbox, DbuArea, GeometryStore, LayerId, PolyId, ValidatedLayer};

/// Why a deck could not be turned into a [`RuleSet`]. Load time only: geometry a
/// rule cannot handle is that rule's `Refused` row, not an error.
///
/// The deck parser already refuses most of these with a line and column;
/// [`RuleSet::from_deck`] and [`Rule::validate`] check them again for a deck
/// built in code. Every `rule` field is the row's id as the deck spells it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DrcError {
    /// A row's kind is in neither the DRC nor the ERC
    /// [`KINDS`](ruleset::KINDS). Raised by
    /// [`CompiledDeck::from_deck`](crate::deck::CompiledDeck::from_deck);
    /// `RuleSet::from_deck` alone steps over such a row.
    #[error("rule {rule}: unknown rule kind {kind}")]
    UnknownKind {
        /// The row's id.
        rule: String,
        /// The kind it names.
        kind: String,
    },
    /// A required parameter is absent; for `angle`, the allowed list is empty.
    #[error("rule {rule}: missing required parameter {param}")]
    MissingParam {
        /// The row's id.
        rule: String,
        /// The parameter's kind-level name, which can differ from the deck's
        /// (`prl_threshold` for `prl:`).
        param: &'static str,
    },
    /// A parameter holds the wrong kind of value, or a count too large for
    /// its [`Rule`] field (`u16` cut counts, `u8` colours).
    #[error("rule {rule}: parameter {param} is not the kind of value this rule takes")]
    WrongParamType {
        /// The row's id.
        rule: String,
        /// The parameter's kind-level name.
        param: &'static str,
    },
    /// A row names too few or too many layers for its kind.
    #[error("rule {rule}: takes {expected} layers, the deck names {found}")]
    WrongLayerCount {
        /// The row's id.
        rule: String,
        /// How many layers the kind takes (the larger count where a second
        /// layer is optional).
        expected: u32,
        /// How many the row names.
        found: u32,
    },
    /// A length, area or fraction is zero or negative, a fraction is not
    /// finite, or a required count (`min_count`, `colors`) is zero.
    #[error("rule {rule}: limit {limit} is not positive")]
    NonPositiveLimit {
        /// The row's id.
        rule: String,
        /// The offending value for display only: a length or area in grid
        /// units, a fraction truncated toward zero (NaN shows as 0), a count.
        limit: i64,
    },
    /// An allowed angle is not a multiple of 45 degrees. Only those are exact
    /// integer edge directions.
    #[error("rule {rule}: {degrees} degrees is not exactly representable")]
    UnrepresentableAngle {
        /// The row's id.
        rule: String,
        /// The angle, reduced modulo 360.
        degrees: i32,
    },
    /// Two deck rows, DRC or ERC, share this id.
    #[error("duplicate rule id {0}")]
    DuplicateRule(String),
    /// The named row's spacing table fails
    /// [`SpacingTable::is_valid`](ruleset::SpacingTable::is_valid), or its class
    /// table fails its kind's check
    /// ([`ClassTable::is_valid_tips`](ruleset::ClassTable::is_valid_tips)).
    #[error("rule {0}: its table is not well formed")]
    BadTable(String),
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
    /// Hole rows bound to their outers, for the layers of the current rule.
    holes: crate::topology::net::Holes,
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
