//! Spacing family: how close two shapes may come.
//!
//! Every rule here starts from the same two steps —
//! [`SpatialIndex::build_into`] over the layer, then
//! [`candidate_pairs_into`] at the rule's limit — and then differs only in what
//! makes a pair *interesting* and what the limit is once it is. That shared
//! prefix is why they share a file, and it is also this family's one real risk.
//!
//! # The prune is the dangerous part
//!
//! A candidate list is a superset: every pair in it is measured exactly
//! afterwards, so a pair that survives wrongly costs time. A pair that is
//! *dropped* wrongly is never looked at again by anyone, and the rule reports
//! clean. That is fail-open on a spacing rule, and it is why
//! `core::index` carries a test adapter and why `Bbox::within` is inclusive.
//! Nothing in this file may narrow the prune below the rule's own limit.
//!
//! # Merged shapes have no gap
//!
//! Two polygons that overlap or touch are one figure, and the distance between
//! them is zero — which is not a spacing violation, it is a wire. So every rule
//! here first labels the layer's connected figures
//! ([`components_into`](gpurify_core::connectivity::components_into) over the
//! touching pairs) and skips pairs within one figure. The old tree made this
//! optional behind a `strict` flag; it is not optional, it is what "external
//! spacing" means, and the flag is gone.

use crate::{Design, Scratch};
use gpurify_core::index::{candidate_pairs_into, SpatialIndex};
use gpurify_core::{Bbox, LayerId};
use gpurify_ingest::StrId;
use gpurify_report::{RuleRun, Violations};
use gpurify_units::Dbu;

/// Minimum spacing between two shapes on the same layer.
#[derive(Debug, Default)]
pub struct MinSpacingTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// Violated below. Also the radius the candidate prune is built at, so it
    /// is load-bearing twice.
    pub limit: Vec<Dbu>,
}

/// Minimum spacing between shapes on two *different* layers.
///
/// A separate table and a separate transform from [`MinSpacingTable`], not a
/// second layer column on it, because the same-layer case emits only `a < b`
/// pairs and does half the work. Folding them would put a layer-equality branch
/// in the innermost loop, which is the split `core::index` already made.
#[derive(Debug, Default)]
pub struct MinSpacingDiffTable {
    pub rule: Vec<StrId>,
    pub a: Vec<LayerId>,
    pub b: Vec<LayerId>,
    pub limit: Vec<Dbu>,
}

/// End-of-line spacing: a line end narrower than `eol_width` needs more room
/// than an ordinary edge.
///
/// The physics is lithographic — a short edge prints with rounded corners and
/// pulls back — so the enlarged keep-out applies only to edges below the width
/// threshold, and only in the direction that edge faces.
#[derive(Debug, Default)]
pub struct EolSpacingTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// An edge shorter than this is an end of line. Not a limit: nothing is
    /// violated by being short, it just triggers the larger spacing.
    pub eol_width: Vec<Dbu>,
    /// The spacing an end of line must have. Violated below.
    pub limit: Vec<Dbu>,
}

/// Parallel-run-length dependent spacing: two shapes that run alongside each
/// other for longer than `prl_threshold` must be further apart.
///
/// Coupling and yield both scale with how far two edges track each other, so a
/// long parallel run buys a larger limit than a corner clip does.
#[derive(Debug, Default)]
pub struct PrlSpacingTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// The run length at or above which the larger limit applies.
    pub prl_threshold: Vec<Dbu>,
    /// The spacing required once it does. Violated below.
    pub limit: Vec<Dbu>,
}

/// Corner-to-corner spacing between diagonally offset shapes.
///
/// The case ordinary spacing misses: two shapes whose projections overlap on
/// neither axis have no facing edge pair at all, so their closest approach is
/// vertex to vertex. Measured as a true Euclidean distance — the one place in
/// this crate where the answer is irrational, which is why the comparison is
/// done on squared values and only the *reported* number is rounded.
#[derive(Debug, Default)]
pub struct CornerToCornerTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    pub limit: Vec<Dbu>,
}

/// Wide-metal spacing: when either shape of a pair is wide, both need more
/// room.
///
/// A wide conductor stores more charge and dissipates more heat into its
/// neighbour, so the foundry raises the limit for its whole perimeter, not just
/// the wide part. "Wide" is on [`narrowest_width`](super::width::narrowest_width),
/// so an L-shaped plate with one thin arm is wide.
#[derive(Debug, Default)]
pub struct WideDependentSpacingTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// A shape whose narrowest width is at or above this is wide.
    pub width_threshold: Vec<Dbu>,
    /// The spacing a pair containing a wide shape must have. Violated below.
    pub limit: Vec<Dbu>,
}

impl MinSpacingTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl MinSpacingDiffTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl EolSpacingTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl PrlSpacingTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl CornerToCornerTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl WideDependentSpacingTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

/// How far two shapes run alongside each other.
///
/// **Decision** — two boxes in, one length out, pure and table-testable. The
/// overlap of the two projections onto whichever axis the shapes face each
/// other across; zero when they face across neither, which is the
/// corner-to-corner case and is why that rule exists separately.
///
/// Bounding boxes rather than polygons, deliberately and *conservatively*: a
/// box's projection is a superset of its polygon's, so this over-reports the
/// run length and therefore over-applies the larger limit. That direction fails
/// closed.
pub fn parallel_run_length(a: Bbox, b: Bbox) -> Dbu {
    todo!()
}

/// Check every same-layer minimum-spacing rule.
///
/// **Transform, gatherer.** Builds one [`SpatialIndex`] per row into the
/// scratch, generates candidates with [`candidate_pairs_into`] at that row's
/// limit, drops pairs belonging to one merged figure, then measures each
/// surviving pair exactly with `ops::seg_seg_dist2`.
///
/// One violation per offending pair, reported at the midpoint of the closest
/// approach with both polygon ids in `shapes`.
///
/// `examined` counts candidate pairs — the primitive this rule looks at, and
/// the number that tells a reader whether the prune did anything. A layer of
/// 10 000 shapes reporting 40 000 pairs examined is healthy; the same layer
/// reporting 50 million means the index degenerated.
pub fn check_min_spacing(
    design: Design<'_>,
    table: &MinSpacingTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every cross-layer minimum-spacing rule.
///
/// `cross_layer_pairs_into` rather than [`candidate_pairs_into`], and no merged
/// figure exemption: two shapes on different layers are never one figure, and a
/// pair that overlaps has zero spacing, which for this rule *is* a violation —
/// two layers required to stay apart have failed if they intersect.
///
/// `examined` counts candidate pairs.
pub fn check_min_spacing_diff(
    design: Design<'_>,
    table: &MinSpacingDiffTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every end-of-line spacing rule.
///
/// The prune is built at `limit`, which is larger than an ordinary spacing
/// limit, so this rule sees strictly more pairs than [`check_min_spacing`] does
/// and then discards those whose near edge is not an end of line.
///
/// `examined` counts candidate pairs whose near edge qualified as an end of
/// line — the population the rule actually judged. Counting all candidates
/// would make a layer with no short edges look thoroughly checked.
pub fn check_eol_spacing(
    design: Design<'_>,
    table: &EolSpacingTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every parallel-run-length dependent spacing rule.
///
/// `examined` counts candidate pairs whose [`parallel_run_length`] reached the
/// threshold.
pub fn check_prl_spacing(
    design: Design<'_>,
    table: &PrlSpacingTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every corner-to-corner rule.
///
/// Only pairs that overlap on neither axis are judged; everything else is an
/// edge-spacing situation and belongs to [`check_min_spacing`]. Reported at the
/// vertex of the first shape in the closest vertex pair, measured with
/// `ops::isqrt` of the exact squared distance — the rounding is toward zero, so
/// a reported measurement never *overstates* the gap.
///
/// `examined` counts diagonally offset candidate pairs.
pub fn check_corner_to_corner(
    design: Design<'_>,
    table: &CornerToCornerTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every wide-metal spacing rule.
///
/// Width is computed once per polygon into the scratch and reused across every
/// pair that polygon appears in — the two-pass split the kernel rule asks for,
/// rather than recomputing a polygon's width inside the pair loop.
///
/// `examined` counts candidate pairs in which at least one shape was wide.
pub fn check_wide_dependent_spacing(
    design: Design<'_>,
    table: &WideDependentSpacingTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}
