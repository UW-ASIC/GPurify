//! Electrical rule checking: one table per rule kind, one transform per table.
//!
//! Six kinds read an [`IntentMap`]; when it does not declare what they need they
//! record themselves skipped rather than clean.

pub mod facts;
pub mod power;
pub mod rules;
pub mod ruleset;

pub use facts::{classify_nets_into, resolve_intent_into, IntentMap, NetFacts, RoleMask};
pub use power::{NetNetworks, PowerError, PowerGrid, PowerSolution, Process, Solved};
pub use ruleset::{RuleHead, RuleSet, RunInputs, KINDS};

use crate::report::{Outcome, RuleRun, Violations};
use crate::topology::{DeviceTable, NetTable};
use gpurify_geom::connectivity::ComponentLabel;
use gpurify_geom::ops::Point;
use gpurify_geom::{prefix, Dbu, DbuArea, Qty, Resistance};
use gpurify_geom::{Bbox, GeometryStore, LayerId, PolyId, ValidatedLayer};
use gpurify_geom::{Evaluator, LayerRef};
use gpurify_ingest::StrId;

/// Why a deck could not be turned into a [`RuleSet`].
///
/// Construction-time only. A rule that meets an unusable input at run time
/// records [`Outcome::Skipped`] or [`Outcome::Refused`] against itself instead,
/// so one bad net cannot suppress every other rule's verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErcError {
    /// The deck names a rule kind this crate does not implement. Fail closed:
    /// skipping it would leave a deck that looks fully checked and is not.
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
    /// A limit that is zero or negative: a `0` antenna ratio flags everything,
    /// a `0` resistance limit flags nothing.
    #[error("rule {rule}: limit {limit} is not positive")]
    NonPositiveLimit { rule: String, limit: String },
    /// A fraction outside `0.0 ..= 1.0`.
    #[error("rule {rule}: {param} must be a fraction in [0, 1]")]
    NotAFraction { rule: String, param: &'static str },
    /// The deck defines the same rule id twice: two [`RuleRun`] rows sharing an
    /// id are attributable to nothing.
    #[error("duplicate rule id {0}")]
    DuplicateRule(String),
}

/// Everything a rule reads about the layout, borrowed for the length of one run.
///
/// Role masks, design intent and the solved supply grid are deliberately *not*
/// here: they stay per-rule parameters so that "this rule needs design intent"
/// is visible at the signature.
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
/// Each transform clears the buffers it wants before filling them; no transform
/// reads what another left behind.
#[derive(Debug, Default)]
pub struct Scratch {
    /// Validated geometry of a rule's primary layer.
    layer_a: ValidatedLayer,
    /// The second operand, for two-layer rules. Never aliases `layer_a`.
    layer_b: ValidatedLayer,
    /// One `u32` per net: a mark, a count, a driver signature.
    net_marks: Vec<u32>,
    /// Per-net or per-window area accumulator.
    areas: Vec<DbuArea>,
    /// Edge list and component labels for the rules that partition a net.
    edges: Vec<(u32, u32)>,
    labels: Vec<ComponentLabel>,
    /// The linear-solve workspace.
    solve: power::SolveScratch,
    /// Effective resistance per terminal pair: `(terminal_a, terminal_b, r)`.
    probes: Vec<(u32, u32, Qty<Resistance, { prefix::BASE }>)>,
    /// Bounding boxes of one layer's shapes.
    boxes: Vec<Bbox>,
}

impl Scratch {
    /// Drop every buffer's capacity.
    pub fn shrink(&mut self) {
        *self = Self::default();
    }
}

/// The store layer a rule row names, or `None` when it names a derived one.
///
/// A derived layer hands out no [`PolyId`], so a row naming one records
/// [`Outcome::Refused`] rather than being checked against geometry it cannot
/// attribute.
pub(crate) const fn base_layer(layer: LayerRef) -> Option<LayerId> {
    match layer {
        LayerRef::Base(id) => Some(id),
        LayerRef::Named(_) => None,
    }
}

/// A point on a polygon, for [`crate::report::Violation::at`].
///
/// Vertex zero, not a bounding-box corner: the point must lie *on* the geometry
/// the row names, and an L-shaped conductor's box corner sits in the notch.
pub(crate) fn first_vertex(store: &GeometryStore, poly: PolyId) -> Point {
    let (xs, ys) = store.poly_verts(poly);
    debug_assert_eq!(xs.len(), ys.len(), "the store's columns are parallel");
    debug_assert!(!xs.is_empty(), "a polygon in the store has vertices");
    Point { x: xs[0], y: ys[0] }
}

/// The centre of a box, truncated: a box of odd span reports the coordinate
/// just inside its lower half rather than a half unit, which is not a
/// coordinate.
pub(crate) fn centre(box_: Bbox) -> Point {
    debug_assert!(
        box_.xlo.raw() <= box_.xhi.raw() && box_.ylo.raw() <= box_.yhi.raw(),
        "a box's bounds run low to high"
    );
    debug_assert!(
        box_.xlo.raw().abs() <= gpurify_geom::MAX_ABS_DBU
            && box_.ylo.raw().abs() <= gpurify_geom::MAX_ABS_DBU
            && box_.xhi.raw().abs() <= gpurify_geom::MAX_ABS_DBU
            && box_.yhi.raw().abs() <= gpurify_geom::MAX_ABS_DBU,
        "a box outside the coordinate domain has no representable centre"
    );
    Point {
        x: Dbu::new_unchecked(i64::midpoint(box_.xlo.raw(), box_.xhi.raw())),
        y: Dbu::new_unchecked(i64::midpoint(box_.ylo.raw(), box_.yhi.raw())),
    }
}

/// `0 .. n` as a column, so a `compact_into` over a per-net column can carry the
/// net each kept row came from.
pub(crate) fn ascending(n: usize) -> Vec<u32> {
    let n = u32::try_from(n).expect("an extracted net count fits a u32");
    (0..n).collect()
}

/// Report one violation per flagged net, at that net's lowest-numbered polygon.
///
/// [`NetTable::polys_of`] is ascending, so the shape named does not depend on
/// how the rule arrived at the net.
///
/// [`NetTable::polys_of`]: crate::topology::NetTable::polys_of
pub(crate) fn push_net_violations<T: Copy>(
    design: Design<'_>,
    flagged: &[(u32, T)],
    rule: StrId,
    severity: crate::report::Severity,
    measured: crate::report::Measurement,
    limit: crate::report::Measurement,
    out: &mut Violations,
) {
    let before = out.len();
    for &(net, _) in flagged {
        let polys = design.nets.polys_of(crate::topology::NetId(net));
        // A violation naming no shape is worse than none at all.
        let Some(&poly) = polys.first() else {
            continue;
        };
        out.push(crate::report::Violation {
            rule,
            layer: design.store.poly_layer(poly),
            severity,
            at: first_vertex(design.store, poly),
            measured,
            limit,
            shapes: (poly, None),
        });
    }
    debug_assert!(
        out.len() - before <= flagged.len(),
        "one violation per flagged net at most"
    );
}

/// Record every row of a rule table as skipped for want of design intent.
///
/// A rule that returned early instead would report nothing at all, which reads
/// as clean.
pub(crate) fn skip_rows(head: &RuleHead, out: &Violations, runs: &mut Vec<RuleRun>) {
    // Not bulk: a deck configures tens of rows per kind.
    for row in 0..head.len() {
        record_run(
            runs,
            out,
            out.len(),
            head.rule[row],
            Outcome::Skipped(crate::report::SkipReason::NoDesignIntent),
            0,
        );
    }
}

/// Record every row of a rule table as refused, for an input the rule cannot
/// represent.
///
/// The twin of [`skip_rows`]: *skipped* is nothing was asked, *refused* is
/// something was asked and this rule will not answer it.
pub(crate) fn refuse_rows(head: &RuleHead, out: &Violations, runs: &mut Vec<RuleRun>) {
    // Not bulk: a deck configures tens of rows per kind.
    for row in 0..head.len() {
        record_run(runs, out, out.len(), head.rule[row], Outcome::Refused, 0);
    }
}

/// Re-exported so the rule modules keep saying `crate::erc::record_run`; the one
/// implementation is [`crate::report::record_run`].
pub(crate) use crate::report::record_run;
