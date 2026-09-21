//! Design rule checking: one table per rule kind, one transform per table.
//!
//! A rule that cannot run says so — [`Outcome::Skipped`] when a required input
//! is absent, [`Outcome::Refused`] when the geometry is outside what this tool
//! represents exactly. Neither is ever collapsed into a clean result, and an
//! empty [`Violations`] alone cannot tell a clean design from a rule that never
//! ran; `record_run` is the one place the two are separated.

pub mod rules;
pub mod ruleset;

pub use ruleset::RuleSet;

use gpurify_geom::connectivity::ComponentLabel;
use gpurify_geom::index::SpatialIndex;
use gpurify_geom::rects::Rect;
use gpurify_geom::{GeometryStore, PolyId, ValidatedLayer};
use gpurify_geom::Evaluator;
// Imported for the intra-doc links above and in `DrcError`; the rule modules
// take their own copies.
#[allow(unused_imports)]
use gpurify_report::{Outcome, RuleRun, Violations};
use gpurify_topology::{DeviceTable, NetTable};
use gpurify_geom::DbuArea;

/// Why a deck could not be turned into a [`RuleSet`].
///
/// Construction-time only: a rule that meets geometry it cannot handle records
/// [`Outcome::Refused`] against itself and the run continues, because one
/// unrepresentable polygon must not suppress every other rule's verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DrcError {
    /// The deck names a rule kind this crate does not implement.
    ///
    /// Fail closed: skipping it would leave a deck that looks fully checked and
    /// is not.
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
    /// A limit that is zero or negative — a `0` spacing limit passes everything
    /// silently.
    #[error("rule {rule}: limit {limit} is not positive")]
    NonPositiveLimit { rule: String, limit: i64 },
    /// An angle no integer edge vector expresses exactly; only multiples of 45
    /// degrees do.
    #[error("rule {rule}: {degrees} degrees is not exactly representable")]
    UnrepresentableAngle { rule: String, degrees: i32 },
    /// The deck defines the same rule id twice; two [`RuleRun`] rows sharing an
    /// id are attributable to nothing.
    #[error("duplicate rule id {0}")]
    DuplicateRule(String),
}

/// Everything a rule reads, borrowed for the length of one run.
///
/// `nets` and `devices` are deliberately not `Option`: an absent topology and
/// an empty one are indistinguishable once inside a rule, and reading "no nets
/// extracted" as "nothing to report" is fail-open.
#[derive(Debug, Clone, Copy)]
pub struct Design<'a> {
    pub store: &'a GeometryStore,
    /// Pre-evaluated named derived layers.
    pub derived: &'a Evaluator,
    pub nets: &'a NetTable,
    pub devices: &'a DeviceTable,
}

/// The buffer set every rule transform borrows and refills.
///
/// ponytail: one scratch means rules run sequentially — one `&mut Scratch` is
/// one exclusive borrow, so the dispatcher hands it to one transform at a time.
/// Splitting it into worker slots is private, but a parallel dispatcher needs a
/// worker count and there is no route for one to arrive: [`RuleSet::run`] takes
/// no thread budget and `gpurify_engine::run::run_drc` does not receive
/// `&RunOptions`, so `RunOptions::threads` cannot reach this crate.
#[derive(Debug, Default)]
pub struct Scratch {
    /// Validated geometry of the rule's primary layer.
    layer_a: ValidatedLayer,
    /// The second operand, for two-layer rules. Never aliases `layer_a`.
    layer_b: ValidatedLayer,
    /// Boolean result — a merged layer, an intersection, an enclosure region.
    layer_out: ValidatedLayer,
    index_a: SpatialIndex,
    index_b: SpatialIndex,
    /// Candidate pairs from the proximity prune — a superset, still checked
    /// exactly.
    pairs: Vec<(PolyId, PolyId)>,
    /// Rectilinear decomposition of `layer_a`, CSR by polygon: polygon `i`'s
    /// rectangles are `rects[rect_start[i] .. rect_start[i + 1]]`.
    rects: Vec<Rect>,
    rect_start: Vec<u32>,
    /// Edge list for the rules that group shapes before measuring them.
    edges: Vec<(u32, u32)>,
    labels: Vec<ComponentLabel>,
    /// Per-group area accumulator.
    areas: Vec<DbuArea>,
    /// Per-node scratch for the colouring search.
    colors: Vec<u8>,
}

impl Scratch {
    /// Drop every buffer's capacity.
    pub fn shrink(&mut self) {
        // Reassignment rather than per-field `shrink_to_fit`: `ValidatedLayer`
        // and `SpatialIndex` own their columns privately and expose no way to
        // release them.
        *self = Self::default();
    }
}

/// Re-exported so the rule modules keep saying `crate::record_run`; the one
/// implementation is [`gpurify_report::record_run`].
pub(crate) use gpurify_report::record_run;
