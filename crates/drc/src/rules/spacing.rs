//! Spacing family: how close two shapes may come.
//!
//! Every rule here starts from the same two steps —
//! [`build_into`](gpurify_core::index::SpatialIndex::build_into) over the
//! layer, then [`candidate_pairs_into`] at the rule's limit — and then differ
//! only in what makes a pair *interesting* and what the limit is once it is.
//! That shared prefix is why they share a file, and it is also this family's
//! one real risk.
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
//!
//! [`candidate_pairs_into`]: gpurify_core::index::candidate_pairs_into

use super::{COLUMNS_DIVERGED, gap_midpoint, poly_dist2, ring_segs, row_columns, seg_bbox};
use crate::rules::width::narrowest_width;
use crate::{record_run, Design, Scratch};
use gpurify_core::connectivity::{components_into, ComponentLabel};
use gpurify_core::index::{candidate_pairs_into, cross_layer_pairs_into, SpatialIndex};
use gpurify_core::ops::{isqrt, seg_seg_dist2, winding_of, Seg, Winding};
use gpurify_core::view::validate_layer_into;
use gpurify_core::{Bbox, GeometryStore, LayerId, PolyId};
use gpurify_ingest::StrId;
use gpurify_report::{Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use gpurify_units::{Dbu, DbuArea, MAX_ABS_DBU};

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

row_columns! {
    MinSpacingTable { rule, layer, limit },
    MinSpacingDiffTable { rule, a, b, limit },
    EolSpacingTable { rule, layer, eol_width, limit },
    PrlSpacingTable { rule, layer, prl_threshold, limit },
    CornerToCornerTable { rule, layer, limit },
    WideDependentSpacingTable { rule, layer, width_threshold, limit },
}

// ---------------------------------------------------------------------------
// The primitives every rule below shares.
// ---------------------------------------------------------------------------

/// The signed overlap of the two boxes' projections, one per axis.
///
/// **Decision** — two boxes in, two lengths out. Positive is the length the two
/// projections share; negative is the size of the gap between them. One
/// expression covering both is what lets every caller here stay branchless.
fn projection_overlaps(a: Bbox, b: Bbox) -> (i64, i64) {
    (
        a.xhi.raw().min(b.xhi.raw()) - a.xlo.raw().max(b.xlo.raw()),
        a.yhi.raw().min(b.yhi.raw()) - a.ylo.raw().max(b.ylo.raw()),
    )
}

/// Exact squared distance for every candidate pair.
///
/// **Transform, A-to-B.** Caller owns `dists`, cleared and refilled to one row
/// per pair. This is the rule family's one genuinely bulk elementwise pass.
fn pair_distances_into(
    store: &GeometryStore,
    pairs: &[(PolyId, PolyId)],
    dists: &mut Vec<DbuArea>,
) {
    dists.clear();
    dists.reserve(pairs.len());

    // No length check: one input column has nothing to disagree with. `push`
    // rather than a `spare_capacity_mut` fill because `poly_dist2` is an
    // all-pairs edge scan over two rings — the capacity compare it hides behind
    // is unmeasurable next to that, and it predicts perfectly after the reserve.
    for &(a, b) in pairs {
        dists.push(poly_dist2(store, a, b));
    }

    debug_assert_eq!(dists.len(), pairs.len(), "one distance per candidate pair");
}

/// Label the layer's merged figures over the candidate pairs.
///
/// **Transform, A-to-B.** Two polygons that touch or overlap are one figure and
/// the distance between them is zero because they are a wire, not because they
/// are too close.
///
/// The candidate list is a complete edge set for this labelling and not an
/// approximation of one: a touching pair is at distance zero, so it is inside
/// *any* prune built at a positive limit. Nothing here can drop a figure edge
/// the prune kept.
///
/// Nodes are layer-relative rows, so `labels` is one column over the layer
/// rather than over the whole store.
fn label_figures(
    first_row: u32,
    node_count: u32,
    pairs: &[(PolyId, PolyId)],
    dists: &[DbuArea],
    edges: &mut Vec<(u32, u32)>,
    labels: &mut Vec<ComponentLabel>,
) {
    debug_assert_eq!(pairs.len(), dists.len(), "the pair columns are parallel");

    edges.clear();
    edges.reserve(pairs.len());

    // Branchless: a pair that does not touch becomes a self-edge, which the
    // union-find treats as the no-op it is. Not a compact — the kept rows change
    // type on the way out, so a predicate could not carry the payload.
    //
    // `zip` truncates to the shorter column, which is why the length check above
    // this loop is not optional: without it a short `dists` would silently emit
    // fewer figure edges, merge fewer polygons and report a wire as a violation.
    for (&(a, b), &d2) in pairs.iter().zip(dists.iter()) {
        debug_assert!(a < b, "the same-layer prune emits `a < b` only");
        let (ra, rb) = (a.0 - first_row, b.0 - first_row);
        let touching = u32::from(d2.raw() == 0);
        edges.push((ra, ra + touching * (rb - ra)));
    }

    debug_assert_eq!(edges.len(), pairs.len(), "one edge slot per candidate pair");
    debug_assert!(
        edges.iter().all(|&(u, v)| u < node_count && v < node_count),
        "a figure edge names a row outside the layer"
    );
    components_into(node_count, edges, labels);
    debug_assert_eq!(labels.len(), node_count as usize, "one label per polygon");
}

/// Whether two rows of one layer belong to two different merged figures.
///
/// Two closed-over gathers and a compare, which is what makes it legal in a
/// compact's predicate: a data-dependent *address* is not a branch. It carries
/// no assert of its own on purpose — an assert is a panic edge, and a panic edge
/// between the load and the store is what makes the unconditional store
/// conditional again. What it would have asserted per pair,
/// [`prepare_same_layer`] asserts once over the whole candidate column, which is
/// the stronger statement anyway.
fn separate_figures(labels: &[ComponentLabel], first_row: u32, a: PolyId, b: PolyId) -> bool {
    let (ra, rb) = ((a.0 - first_row) as usize, (b.0 - first_row) as usize);
    labels[ra] != labels[rb]
}

/// One spacing violation, in the shape every rule in this file reports it.
fn spacing_violation(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    a: PolyId,
    b: PolyId,
    dist2: DbuArea,
    limit: Dbu,
) -> Violation {
    let measured = isqrt(dist2);
    debug_assert!(
        measured.mul_wide(measured) <= dist2,
        "isqrt rounds toward zero, so a reported gap never overstates the real one"
    );
    Violation {
        rule,
        layer,
        severity: Severity::Error,
        at: gap_midpoint(store.poly_bbox(a), store.poly_bbox(b)),
        measured: Measurement::Length(measured),
        limit: Measurement::Length(limit),
        shapes: (a, Some(b)),
    }
}

/// Prepare one same-layer rule row: validate, index, pair, measure, label.
///
/// Returns `false` when the layer will not validate, which is the row's
/// [`Outcome::Refused`] — fail closed, never a silently clean result. The
/// caller has already read the row's uniforms; everything this fills is scratch.
#[allow(
    clippy::too_many_arguments,
    reason = "every buffer this fills is a \
    disjoint borrow out of one `Scratch`; bundling them back into it is what \
    the destructure at each call site exists to undo"
)]
fn prepare_same_layer(
    store: &GeometryStore,
    layer: LayerId,
    limit: Dbu,
    validated: &mut gpurify_core::ValidatedLayer,
    index: &mut SpatialIndex,
    pairs: &mut Vec<(PolyId, PolyId)>,
    dists: &mut Vec<DbuArea>,
    edges: &mut Vec<(u32, u32)>,
    labels: &mut Vec<ComponentLabel>,
) -> bool {
    if validate_layer_into(store, layer, validated).is_err() {
        return false;
    }
    let rows = store.polys_on_layer(layer);
    SpatialIndex::build_into(store, layer, index);
    candidate_pairs_into(store, index, limit, pairs);
    pair_distances_into(store, pairs, dists);
    label_figures(
        rows.start,
        rows.end - rows.start,
        pairs,
        dists,
        edges,
        labels,
    );

    // The precondition every `separate_figures` gather in this file rests on,
    // stated once over the whole column instead of once per pair — the row loops
    // below run it inside a `compact_into` predicate, where an assert would be a
    // panic edge and would put the conditional store back.
    debug_assert!(
        pairs
            .iter()
            .all(|&(a, b)| rows.contains(&a.0) && rows.contains(&b.0)),
        "a candidate pair names a row outside the layer it was pruned on"
    );
    true
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
    let (along_x, along_y) = projection_overlaps(a, b);

    // They face across the axis whose projections share *less*, so the run is
    // along the other one — which is the larger of the two overlaps. A pair
    // disjoint on both axes has two negative overlaps and clamps to zero, and
    // that is the corner-to-corner case. `clamp`, no branch, and symmetric in
    // the two operands because `projection_overlaps` is.
    //
    // The upper clamp is not cosmetic. Two boxes spanning the whole coordinate
    // domain overlap by `2^41`, one bit past `MAX_ABS_DBU`, and an unclamped
    // `Dbu::new_unchecked` would hand a public caller a coordinate outside the
    // domain the whole `i128` area argument rests on — `mul_wide` on one is the
    // overflow `MAX_ABS_DBU` was chosen to make impossible. Saturating here
    // changes no verdict: every threshold this is compared against is itself a
    // legal coordinate, so `run >= threshold` answers the same at the clamp as
    // above it. Fail-closed, because the clamp can only keep the larger limit
    // applying, never drop it.
    let run = along_x.max(along_y).clamp(0, MAX_ABS_DBU);

    debug_assert!(run >= 0, "a run length is never negative");
    debug_assert!(run <= MAX_ABS_DBU, "a run length is a legal coordinate");
    Dbu::new_unchecked(run)
}

/// Check every same-layer minimum-spacing rule.
///
/// **Transform, gatherer.** Builds one spatial index per row into the scratch,
/// generates candidates with [`candidate_pairs_into`] at that row's limit,
/// drops pairs belonging to one merged figure, then measures each surviving
/// pair exactly with `ops::seg_seg_dist2`.
///
/// One violation per offending pair, reported at the midpoint of the closest
/// approach with both polygon ids in `shapes`.
///
/// `examined` counts candidate pairs — the primitive this rule looks at, and
/// the number that tells a reader whether the prune did anything. A layer of
/// 10 000 shapes reporting 40 000 pairs examined is healthy; the same layer
/// reporting 50 million means the index degenerated.
///
/// [`candidate_pairs_into`]: gpurify_core::index::candidate_pairs_into
pub fn check_min_spacing(
    design: Design<'_>,
    table: &MinSpacingTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let store = design.store;
    let Scratch {
        layer_a,
        index_a,
        pairs,
        edges,
        labels,
        areas,
        ..
    } = scratch;

    // One buffer for the whole call, refilled per rule row. `compact_into`
    // clears and reserves it itself, so this allocates at most once no matter
    // how many rows the table holds.
    let mut violating: Vec<((PolyId, PolyId), DbuArea)> = Vec::new();

    // Not a bulk loop: a deck holds tens of rows per table, and each row's
    // three columns are read once and hoisted as uniforms over the pair loop.
    for row in 0..table.len() {
        let (rule, layer, limit) = (table.rule[row], table.layer[row], table.limit[row]);
        debug_assert!(
            limit.raw() > 0,
            "the deck loader refuses a non-positive limit"
        );
        debug_assert!(limit.raw() <= MAX_ABS_DBU, "a limit is a legal coordinate");
        let before = out.len();

        if !prepare_same_layer(
            store, layer, limit, layer_a, index_a, pairs, areas, edges, labels,
        ) {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }
        let first_row = store.polys_on_layer(layer).start;
        let limit2 = limit.mul_wide(limit);

        // The bulk pass is a compact, not a loop with a branch in it: the store
        // is unconditional and the write index carries the decision. Non-
        // short-circuiting `&`: both operands are already-loaded values, so
        // there is nothing to save by skipping one, and `&` keeps the predicate
        // free of the branch that would put the conditional store back.
        let n = pairs.len();
        debug_assert_eq!(n, areas.len(), "the pair columns are parallel");
        let (ps, ds) = (&pairs[..n], &areas[..n]);

        // Reserved for the whole input, not the survivors — that over-allocation
        // is the memory-for-branches trade that buys the unconditional store.
        violating.clear();
        violating.reserve(n);
        let slots = &mut violating.spare_capacity_mut()[..n];

        let mut w = 0usize;
        for i in 0..n {
            let (a, b) = ps[i];
            let d2 = ds[i];
            let p = separate_figures(labels, first_row, a, b) & (d2 < limit2);
            // SAFETY: `w <= i` by induction — `w` starts at 0 and `usize::from`
            // of a `bool` advances it by at most 1 per iteration — so
            // `w <= i < n == slots.len()`. Rejected slots stay uninit and are
            // truncated away by `set_len(w)`; the payload is `Copy`, no `Drop`.
            debug_assert!(w <= i);
            unsafe { slots.get_unchecked_mut(w) }.write(((a, b), d2));
            w += usize::from(p);
        }

        // SAFETY: slot `k` was written on the iteration where `w == k`, for every
        // `k < w`, and `w <= n <= capacity`.
        unsafe { violating.set_len(w) };
        let found = w;
        debug_assert_eq!(found, violating.len(), "the compact kept what it counted");
        debug_assert!(found <= pairs.len(), "a compact cannot grow its input");

        // Not a bulk loop: what survived the compact is exactly the violations,
        // which a signoff-clean layer has none of and a broken one has few. The
        // push into eight `Violations` columns is why this is a second pass
        // rather than the compact's own callback.
        for &((a, b), dist2) in &violating {
            out.push(spacing_violation(store, rule, layer, a, b, dist2, limit));
        }

        let examined = u64::try_from(pairs.len()).expect("a pair count fits a u64");
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Check every cross-layer minimum-spacing rule.
///
/// `cross_layer_pairs_into` rather than [`candidate_pairs_into`], and no merged
/// figure exemption: two shapes on different layers are never one figure, and a
/// pair that overlaps has zero spacing, which for this rule *is* a violation —
/// two layers required to stay apart have failed if they intersect.
///
/// `examined` counts candidate pairs.
///
/// [`candidate_pairs_into`]: gpurify_core::index::candidate_pairs_into
pub fn check_min_spacing_diff(
    design: Design<'_>,
    table: &MinSpacingDiffTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let store = design.store;
    let Scratch {
        layer_a,
        layer_b,
        index_a,
        index_b,
        pairs,
        areas,
        ..
    } = scratch;

    let mut violating: Vec<((PolyId, PolyId), DbuArea)> = Vec::new();

    for row in 0..table.len() {
        let (rule, a_layer, b_layer) = (table.rule[row], table.a[row], table.b[row]);
        let limit = table.limit[row];
        debug_assert!(
            limit.raw() > 0,
            "the deck loader refuses a non-positive limit"
        );
        debug_assert_ne!(a_layer, b_layer, "a cross-layer rule names two layers");
        let before = out.len();

        let validated = validate_layer_into(store, a_layer, layer_a).is_ok()
            && validate_layer_into(store, b_layer, layer_b).is_ok();
        if !validated {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }

        SpatialIndex::build_into(store, a_layer, index_a);
        SpatialIndex::build_into(store, b_layer, index_b);
        cross_layer_pairs_into(store, index_a, index_b, limit, pairs);
        pair_distances_into(store, pairs, areas);
        let limit2 = limit.mul_wide(limit);

        // Stated once over the column rather than once per pair, so the compact
        // below carries no panic edge.
        debug_assert!(
            pairs.iter().all(|&(a, b)| store.poly_layer(a) == a_layer
                && store.poly_layer(b) == b_layer),
            "a cross-layer candidate names its two layers in the order the rule does"
        );

        // No merged figure step above this: two shapes on different layers are
        // never one figure, so a pair that overlaps has a spacing of zero and
        // that *is* the violation this rule exists to find. Which leaves one
        // predicate, and the compact is the whole bulk pass.
        let n = pairs.len();
        debug_assert_eq!(n, areas.len(), "the pair columns are parallel");
        let (ps, ds) = (&pairs[..n], &areas[..n]);

        violating.clear();
        violating.reserve(n);
        let slots = &mut violating.spare_capacity_mut()[..n];

        let mut w = 0usize;
        for i in 0..n {
            let d2 = ds[i];
            // SAFETY: `w <= i` by induction — `w` advances by `usize::from` of a
            // `bool`, so by at most 1 per iteration — hence
            // `w <= i < n == slots.len()`. Rejected slots stay uninit and
            // `set_len(w)` truncates them; the payload is `Copy`.
            debug_assert!(w <= i);
            unsafe { slots.get_unchecked_mut(w) }.write((ps[i], d2));
            w += usize::from(d2 < limit2);
        }

        // SAFETY: slot `k` was written on the iteration where `w == k`, for every
        // `k < w`, and `w <= n <= capacity`.
        unsafe { violating.set_len(w) };
        let found = w;
        debug_assert_eq!(found, violating.len(), "the compact kept what it counted");
        debug_assert!(found <= pairs.len(), "a compact cannot grow its input");

        // Not a bulk loop: the survivors are the violations. Attributed to `a`,
        // the first layer the rule names.
        for &((a, b), dist2) in &violating {
            out.push(spacing_violation(store, rule, a_layer, a, b, dist2, limit));
        }

        let examined = u64::try_from(pairs.len()).expect("a pair count fits a u64");
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
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
    /// Not a saturating *distance* standing in for an answer — the fail-open
    /// sentinel this project fears — it is "this pair has no end of line, so
    /// this rule has no jurisdiction over it". Step 3 excludes it from
    /// `examined` for exactly that reason, so a pair carrying it is reported as
    /// unjudged rather than as clean.
    const NO_EOL: DbuArea = DbuArea::new(i128::MAX);

    let store = design.store;
    let Scratch {
        layer_a,
        index_a,
        pairs,
        edges,
        labels,
        areas,
        ..
    } = scratch;

    let mut separate: Vec<(PolyId, PolyId)> = Vec::new();
    let mut violating: Vec<((PolyId, PolyId), DbuArea)> = Vec::new();

    for row in 0..table.len() {
        let (rule, layer) = (table.rule[row], table.layer[row]);
        let (eol_width, limit) = (table.eol_width[row], table.limit[row]);
        debug_assert!(
            limit.raw() > 0,
            "the deck loader refuses a non-positive limit"
        );
        debug_assert!(eol_width.raw() > 0, "an end-of-line width is positive");
        let before = out.len();

        if !prepare_same_layer(
            store, layer, limit, layer_a, index_a, pairs, areas, edges, labels,
        ) {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }
        let first_row = store.polys_on_layer(layer).start;
        let limit2 = limit.mul_wide(limit);

        // Four bulk passes in place of one loop carrying a counter and two
        // branches.
        //
        // 1. Drop the merged pairs. A pair inside one figure has no gap for an
        //    end of line to stand across, and this is the same prune every rule
        //    in this file opens with. No length check: one input column.
        let n = pairs.len();
        let ps = &pairs[..n];
        separate.clear();
        separate.reserve(n);
        let slots = &mut separate.spare_capacity_mut()[..n];

        let mut w = 0usize;
        for (i, &(a, b)) in ps.iter().enumerate() {
            // SAFETY: `w <= i` by induction — `w` advances by `usize::from` of a
            // `bool`, at most 1 per iteration — so `w <= i < n == slots.len()`.
            // Rejected slots stay uninit and `set_len(w)` truncates them; a
            // `(PolyId, PolyId)` is `Copy`.
            debug_assert!(w <= i);
            unsafe { slots.get_unchecked_mut(w) }.write((a, b));
            w += usize::from(separate_figures(labels, first_row, a, b));
        }

        // SAFETY: slot `k` was written on the iteration where `w == k`, for every
        // `k < w`, and `w <= n <= capacity`.
        unsafe { separate.set_len(w) };
        let merged_dropped = w;
        debug_assert_eq!(merged_dropped, separate.len(), "the compact kept what it counted");

        // 2. Measure. `areas` is dead once `label_figures` has read it, so the
        //    eol distances land back in it rather than in a fourth buffer. The
        //    pairs with no end of line carry `NO_EOL`.
        areas.clear();
        areas.reserve(separate.len());
        // `push` rather than a `spare_capacity_mut` fill: the body is two full
        // ring-against-ring scans, so the capacity compare is unmeasurable and
        // predicts perfectly after the reserve. No length check: one input
        // column.
        for &(a, b) in &separate {
            // Either shape's end of line qualifies the pair: the enlarged
            // keep-out belongs to the short edge, and which of the two carries
            // it is not something the pair order should decide.
            areas.push(
                eol_hit(store, a, b, eol_width, limit)
                    .into_iter()
                    .chain(eol_hit(store, b, a, eol_width, limit))
                    .min()
                    .unwrap_or(NO_EOL),
            );
        }
        debug_assert_eq!(areas.len(), separate.len(), "one measurement per separate pair");

        // 3. Count what was judged, branchlessly. The population this rule
        //    judged is the pairs that had an end of line at all; counting the
        //    rest would make a layer with no short edges look thoroughly
        //    checked.
        let mut examined = 0u64;
        for &d2 in areas.iter() {
            examined += u64::from(d2 != NO_EOL);
        }

        // 4. Keep the ones over the limit. `NO_EOL` excludes itself: it is
        //    larger than any squared limit a legal coordinate can produce.
        let n = separate.len();
        debug_assert_eq!(n, areas.len(), "the pair columns are parallel");
        let (ss, ds) = (&separate[..n], &areas[..n]);

        violating.clear();
        violating.reserve(n);
        let slots = &mut violating.spare_capacity_mut()[..n];

        let mut w = 0usize;
        for i in 0..n {
            let d2 = ds[i];
            // SAFETY: `w <= i` by induction — `w` advances by `usize::from` of a
            // `bool`, at most 1 per iteration — so `w <= i < n == slots.len()`.
            // Rejected slots stay uninit and `set_len(w)` truncates them; the
            // payload is `Copy`.
            debug_assert!(w <= i);
            unsafe { slots.get_unchecked_mut(w) }.write((ss[i], d2));
            w += usize::from(d2 < limit2);
        }

        // SAFETY: slot `k` was written on the iteration where `w == k`, for every
        // `k < w`, and `w <= n <= capacity`.
        unsafe { violating.set_len(w) };
        let found = w;
        debug_assert_eq!(found, violating.len(), "the compact kept what it counted");

        // Not a bulk loop: the survivors are the violations.
        for &((a, b), dist2) in &violating {
            out.push(spacing_violation(store, rule, layer, a, b, dist2, limit));
        }

        debug_assert!(
            usize::try_from(examined).is_ok_and(|judged| judged <= pairs.len()),
            "the judged population is a subset of the candidates"
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// The keep-out an end of line projects: its own span, pushed out by `depth`
/// along its outward normal.
///
/// A short edge prints with rounded corners and pulls back *in the direction it
/// faces*, so the enlarged spacing applies only ahead of the edge. A neighbour
/// standing beside the wire end is ordinary spacing territory.
///
/// Clamped to the coordinate domain, which loses nothing: every coordinate the
/// zone is tested against is inside it already.
fn eol_zone(edge: Seg, normal_sign: i64, depth: Dbu) -> Bbox {
    let (dx, dy) = (
        edge.b.x.raw() - edge.a.x.raw(),
        edge.b.y.raw() - edge.a.y.raw(),
    );
    // The outward normal of a counter-clockwise boundary is its direction
    // turned clockwise; a hole winds the other way and so does its outside.
    let (nx, ny) = (normal_sign * dy.signum(), -normal_sign * dx.signum());
    let d = depth.raw();
    let span = seg_bbox(edge);
    let grow =
        |coord: i64, by: i64| Dbu::new_unchecked((coord + by * d).clamp(-MAX_ABS_DBU, MAX_ABS_DBU));
    Bbox {
        xlo: grow(span.xlo.raw(), nx.min(0)),
        ylo: grow(span.ylo.raw(), ny.min(0)),
        xhi: grow(span.xhi.raw(), nx.max(0)),
        yhi: grow(span.yhi.raw(), ny.max(0)),
    }
}

/// The closest approach between an end of line on `eol` and anything of `other`
/// standing in its keep-out, or `None` when `eol` has no end of line facing
/// `other` at all.
///
/// **Decision** — two rows and two limits in, one squared length or nothing out.
/// `None` is what makes `examined` mean "the pair was judged": a pair with no
/// qualifying edge is not clean, it is out of this rule's scope.
///
/// An edge *at* `eol_width` is not shorter than it, so it is an ordinary edge
/// and the enlarged limit never applies. That is the whole trigger condition.
fn eol_hit(
    store: &GeometryStore,
    eol: PolyId,
    other: PolyId,
    eol_width: Dbu,
    limit: Dbu,
) -> Option<DbuArea> {
    let (xs, ys) = store.poly_verts(eol);
    let (oxs, oys) = store.poly_verts(other);
    let normal_sign = match winding_of(xs, ys)? {
        Winding::CounterClockwise => 1,
        Winding::Clockwise => -1,
    };
    let width2 = eol_width.mul_wide(eol_width);

    // Nested, over the *cross product* of two rings, and the inner scan is
    // entered per qualifying edge rather than per row — so there is no single
    // trip count here at all. The bulk dimension is the candidate-pair list this
    // is called from, and that one is the measurement loop in
    // `check_eol_spacing`.
    //
    // The inner loop *could* be flattened into one unconditional fold over
    // `other`'s edges, but only by deleting the zone prune below and measuring
    // every edge — the "taken side is expensive" escape valve, in the direction
    // that makes it slower. `poly_dist2` carries the same shape and the same
    // note.
    let mut best: Option<DbuArea> = None;
    for edge in ring_segs(xs, ys) {
        let (dx, dy) = (
            edge.b.x.raw() - edge.a.x.raw(),
            edge.b.y.raw() - edge.a.y.raw(),
        );
        let len2 = DbuArea::new(i128::from(dx) * i128::from(dx) + i128::from(dy) * i128::from(dy));
        // Surviving `if`, guarding a whole scan of `other`'s boundary — the
        // expensive side. Two rejections in one: an edge at or above the
        // threshold is not an end of line, and a diagonal edge has no
        // axis-aligned keep-out to project. Nearly every edge of a real shape
        // takes it, so it also predicts well.
        if (len2 >= width2) | ((dx != 0) & (dy != 0)) {
            continue;
        }
        let zone = eol_zone(edge, normal_sign, limit);

        for far in ring_segs(oxs, oys) {
            // Surviving `if`: the taken side is four point-to-segment drops,
            // and the zone rejects almost every edge of almost every neighbour.
            if !zone.overlaps(seg_bbox(far)) {
                continue;
            }
            let dist2 = seg_seg_dist2(edge, far);
            best = Some(best.map_or(dist2, |seen| seen.min(dist2)));
        }
    }

    debug_assert!(
        best.is_none_or(|d| d.raw() >= 0),
        "a squared distance is non-negative"
    );
    best
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
    let store = design.store;
    let Scratch {
        layer_a,
        index_a,
        pairs,
        edges,
        labels,
        areas,
        ..
    } = scratch;

    let mut judged: Vec<((PolyId, PolyId), DbuArea)> = Vec::new();
    let mut violating: Vec<((PolyId, PolyId), DbuArea)> = Vec::new();

    for row in 0..table.len() {
        let (rule, layer) = (table.rule[row], table.layer[row]);
        let (threshold, limit) = (table.prl_threshold[row], table.limit[row]);
        debug_assert!(
            limit.raw() > 0,
            "the deck loader refuses a non-positive limit"
        );
        let before = out.len();

        if !prepare_same_layer(
            store, layer, limit, layer_a, index_a, pairs, areas, edges, labels,
        ) {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }
        let first_row = store.polys_on_layer(layer).start;
        let limit2 = limit.mul_wide(limit);

        // Two compacts, because this rule has two populations and they are not
        // the same set: what it judged, and what it found. `examined` is the
        // first compact's return value rather than a counter with a loop-carried
        // dependence on it.
        //
        // A run one unit short of the threshold is a corner clip, not a long
        // parallel run, and it buys the layer's ordinary spacing instead — this
        // rule does not judge it at all.
        let n = pairs.len();
        debug_assert_eq!(n, areas.len(), "the pair columns are parallel");
        let (ps, ds) = (&pairs[..n], &areas[..n]);

        judged.clear();
        judged.reserve(n);
        let slots = &mut judged.spare_capacity_mut()[..n];

        let mut kept = 0usize;
        for i in 0..n {
            let (a, b) = ps[i];
            let run = parallel_run_length(store.poly_bbox(a), store.poly_bbox(b));
            let p = separate_figures(labels, first_row, a, b) & (run >= threshold);
            // SAFETY: `kept <= i` by induction — it advances by `usize::from` of
            // a `bool`, at most 1 per iteration — so
            // `kept <= i < n == slots.len()`. Rejected slots stay uninit and
            // `set_len` truncates them; the payload is `Copy`.
            debug_assert!(kept <= i);
            unsafe { slots.get_unchecked_mut(kept) }.write(((a, b), ds[i]));
            kept += usize::from(p);
        }

        // SAFETY: slot `k` was written on the iteration where `kept == k`, for
        // every `k < kept`, and `kept <= n <= capacity`.
        unsafe { judged.set_len(kept) };
        debug_assert_eq!(kept, judged.len(), "the compact kept what it counted");
        let examined = u64::try_from(kept).expect("a pair count fits a u64");

        let m = judged.len();
        let js = &judged[..m];
        violating.clear();
        violating.reserve(m);
        let slots = &mut violating.spare_capacity_mut()[..m];

        let mut found = 0usize;
        for (i, &row) in js.iter().enumerate() {
            // SAFETY: `found <= i` by the same induction as above, so
            // `found <= i < m == slots.len()`; the payload is `Copy` and
            // `set_len` truncates the rejected slots.
            debug_assert!(found <= i);
            unsafe { slots.get_unchecked_mut(found) }.write(row);
            found += usize::from(row.1 < limit2);
        }

        // SAFETY: slot `k` was written on the iteration where `found == k`, for
        // every `k < found`, and `found <= m <= capacity`.
        unsafe { violating.set_len(found) };
        debug_assert_eq!(found, violating.len(), "the compact kept what it counted");

        // Not a bulk loop: the survivors are the violations.
        for &((a, b), dist2) in &violating {
            out.push(spacing_violation(store, rule, layer, a, b, dist2, limit));
        }

        debug_assert!(
            kept <= pairs.len(),
            "the judged population is a subset of the candidates"
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Check every corner-to-corner rule.
///
/// Only pairs that overlap on neither axis are judged; everything else is an
/// edge-spacing situation and belongs to [`check_min_spacing`]. Reported at the
/// midpoint of the segment joining the closest vertex pair — the same "middle
/// of the gap" convention [`check_min_spacing`] uses, since the segment *is*
/// the closest approach here. Measured with `ops::isqrt` of the exact squared
/// distance: the rounding is toward zero, so a reported measurement never
/// *overstates* the gap.
///
/// `examined` counts diagonally offset candidate pairs.
pub fn check_corner_to_corner(
    design: Design<'_>,
    table: &CornerToCornerTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let store = design.store;
    let Scratch {
        layer_a,
        index_a,
        pairs,
        edges,
        labels,
        areas,
        ..
    } = scratch;

    let mut judged: Vec<((PolyId, PolyId), DbuArea)> = Vec::new();
    let mut violating: Vec<((PolyId, PolyId), DbuArea)> = Vec::new();

    for row in 0..table.len() {
        let (rule, layer, limit) = (table.rule[row], table.layer[row], table.limit[row]);
        debug_assert!(
            limit.raw() > 0,
            "the deck loader refuses a non-positive limit"
        );
        let before = out.len();

        if !prepare_same_layer(
            store, layer, limit, layer_a, index_a, pairs, areas, edges, labels,
        ) {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }
        let first_row = store.polys_on_layer(layer).start;
        let limit2 = limit.mul_wide(limit);

        // Two compacts, the same split `check_prl_spacing` makes: the pairs this
        // rule has jurisdiction over, then the ones over the limit. `examined`
        // is the first one's return value.
        //
        // Sharing a projection on either axis means the two have a facing edge
        // pair, which is `check_min_spacing`'s situation; judging them here would
        // double-report every ordinary gap under a second rule id. Only the pair
        // that faces across neither axis has its closest approach vertex to
        // vertex.
        let n = pairs.len();
        debug_assert_eq!(n, areas.len(), "the pair columns are parallel");
        let (ps, ds) = (&pairs[..n], &areas[..n]);

        judged.clear();
        judged.reserve(n);
        let slots = &mut judged.spare_capacity_mut()[..n];

        let mut kept = 0usize;
        for i in 0..n {
            let (a, b) = ps[i];
            let (along_x, along_y) = projection_overlaps(store.poly_bbox(a), store.poly_bbox(b));
            let diagonal = (along_x < 0) & (along_y < 0);
            let p = separate_figures(labels, first_row, a, b) & diagonal;
            // SAFETY: `kept <= i` by induction — it advances by `usize::from` of
            // a `bool`, at most 1 per iteration — so
            // `kept <= i < n == slots.len()`. Rejected slots stay uninit and
            // `set_len` truncates them; the payload is `Copy`.
            debug_assert!(kept <= i);
            unsafe { slots.get_unchecked_mut(kept) }.write(((a, b), ds[i]));
            kept += usize::from(p);
        }

        // SAFETY: slot `k` was written on the iteration where `kept == k`, for
        // every `k < kept`, and `kept <= n <= capacity`.
        unsafe { judged.set_len(kept) };
        debug_assert_eq!(kept, judged.len(), "the compact kept what it counted");
        let examined = u64::try_from(kept).expect("a pair count fits a u64");

        let m = judged.len();
        let js = &judged[..m];
        violating.clear();
        violating.reserve(m);
        let slots = &mut violating.spare_capacity_mut()[..m];

        let mut found = 0usize;
        for (i, &row) in js.iter().enumerate() {
            // SAFETY: `found <= i` by the same induction as above, so
            // `found <= i < m == slots.len()`; the payload is `Copy` and
            // `set_len` truncates the rejected slots.
            debug_assert!(found <= i);
            unsafe { slots.get_unchecked_mut(found) }.write(row);
            found += usize::from(row.1 < limit2);
        }

        // SAFETY: slot `k` was written on the iteration where `found == k`, for
        // every `k < found`, and `found <= m <= capacity`.
        unsafe { violating.set_len(found) };
        debug_assert_eq!(found, violating.len(), "the compact kept what it counted");

        // Not a bulk loop: the survivors are the violations.
        for &((a, b), dist2) in &violating {
            out.push(spacing_violation(store, rule, layer, a, b, dist2, limit));
        }

        debug_assert!(
            kept <= pairs.len(),
            "the judged population is a subset of the candidates"
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// One "this shape is wide" flag per *store row* of a validated layer.
///
/// **Transform, A-to-B.** Caller owns `flags`, cleared and refilled to one row
/// per row on the layer, so the pair loop reads a polygon's width back rather
/// than recomputing it — the two-pass split the kernel rule asks for.
///
/// Store rows and validated polygons are not the same population: a hole is its
/// own store row, and validation folds it into the boundary it punctures. The
/// counter-clockwise rows are the validated polygons, ascending, which is what
/// makes the running count below the right index into `validated`.
///
/// # Known imprecision, blocked on a signature
///
/// A hole row inherits *the layer's* widest verdict rather than its own
/// polygon's, because `ValidatedLayer` publishes no store-row provenance — it
/// exposes `len`, `get(idx)` and `bboxes()` and nothing that says which boundary
/// a hole was bound to — and rederiving the containment here would be a second,
/// disagreeing copy of `validate_layer_into`'s pass two. The direction is
/// deliberate: over-applying the wide limit costs a re-check, under-applying it
/// misses a violation, so this fails closed.
///
/// The fix is hole-to-polygon provenance on `ValidatedLayer`, which is a
/// signature change and therefore a bug report. Logged in
/// `docs/SIGNATURE_DEFECTS.md`.
fn wide_flags_into(
    store: &GeometryStore,
    layer: LayerId,
    validated: &gpurify_core::ValidatedLayer,
    threshold: Dbu,
    flags: &mut Vec<u8>,
) {
    /// A row that is a hole, before the second pass resolves it.
    const HOLE: u8 = 2;

    let rows = store.polys_on_layer(layer);
    flags.clear();
    flags.reserve(rows.len());

    // `outers` is a running count of the counter-clockwise rows seen so far,
    // which makes this a *prefix scan*: row N's index into `validated` is a
    // function of rows `0..N`. That is the one loop-carried dependency class
    // that does not partition by index range, so this loop is serial by shape —
    // splitting it in two does not help, because both halves would need the same
    // prefix.
    let mut outers = 0u32;
    for row in rows.clone() {
        let (xs, ys) = store.poly_verts(PolyId(row));
        // Surviving `if`: the layer validated, so a ring winds one way or the
        // other and the outer side is taken for nearly every row of a real
        // layer — it predicts at ~100% and its taken side is the whole width
        // scan, which is what a branch is for.
        if matches!(winding_of(xs, ys), Some(Winding::CounterClockwise)) {
            let width = narrowest_width(validated.get(store, outers));
            flags.push(u8::from(width >= threshold));
            outers += 1;
        } else {
            flags.push(HOLE);
        }
    }
    debug_assert_eq!(flags.len(), rows.len(), "one flag per store row");
    debug_assert_eq!(
        outers as usize,
        validated.len(),
        "the counter-clockwise rows are exactly the validated polygons"
    );

    // Resolve the holes, order-independently: the layer's verdict is folded
    // first, then blended in wherever the marker stands. `& 1` is what keeps a
    // marker out of its own fold.
    let mut any_wide = 0u8;
    for &flag in flags.iter() {
        any_wide |= flag & 1;
    }
    for flag in flags.iter_mut() {
        *flag = (*flag & 1) | (u8::from(*flag == HOLE) * any_wide);
    }

    debug_assert!(
        flags.iter().all(|&flag| flag <= 1),
        "every marker was resolved to a flag"
    );
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
    let store = design.store;
    let Scratch {
        layer_a,
        index_a,
        pairs,
        edges,
        labels,
        areas,
        colors,
        ..
    } = scratch;

    let mut judged: Vec<((PolyId, PolyId), DbuArea)> = Vec::new();
    let mut violating: Vec<((PolyId, PolyId), DbuArea)> = Vec::new();

    for row in 0..table.len() {
        let (rule, layer) = (table.rule[row], table.layer[row]);
        let (threshold, limit) = (table.width_threshold[row], table.limit[row]);
        debug_assert!(
            limit.raw() > 0,
            "the deck loader refuses a non-positive limit"
        );
        debug_assert!(threshold.raw() > 0, "a wide-metal threshold is positive");
        let before = out.len();

        if !prepare_same_layer(
            store, layer, limit, layer_a, index_a, pairs, areas, edges, labels,
        ) {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }
        let rows = store.polys_on_layer(layer);
        let row_count = (rows.end - rows.start) as usize;
        wide_flags_into(store, layer, layer_a, threshold, colors);
        debug_assert_eq!(colors.len(), row_count, "one wide flag per store row");

        let limit2 = limit.mul_wide(limit);
        let first_row = rows.start;

        // Two compacts, the same split `check_prl_spacing` makes. Both flag
        // reads are gathers into a closed-over column, which the callback
        // contract allows and which is why `wide_flags_into` ran first: a wide
        // conductor raises the limit for its whole perimeter, so one wide shape
        // in the pair is enough for both.
        let n = pairs.len();
        debug_assert_eq!(n, areas.len(), "the pair columns are parallel");
        let (ps, ds) = (&pairs[..n], &areas[..n]);

        judged.clear();
        judged.reserve(n);
        let slots = &mut judged.spare_capacity_mut()[..n];

        let mut kept = 0usize;
        for i in 0..n {
            let (a, b) = ps[i];
            let wide = colors[(a.0 - first_row) as usize] | colors[(b.0 - first_row) as usize];
            let p = separate_figures(labels, first_row, a, b) & (wide != 0);
            // SAFETY: `kept <= i` by induction — it advances by `usize::from` of
            // a `bool`, at most 1 per iteration — so
            // `kept <= i < n == slots.len()`. Rejected slots stay uninit and
            // `set_len` truncates them; the payload is `Copy`.
            debug_assert!(kept <= i);
            unsafe { slots.get_unchecked_mut(kept) }.write(((a, b), ds[i]));
            kept += usize::from(p);
        }

        // SAFETY: slot `k` was written on the iteration where `kept == k`, for
        // every `k < kept`, and `kept <= n <= capacity`.
        unsafe { judged.set_len(kept) };
        debug_assert_eq!(kept, judged.len(), "the compact kept what it counted");
        let examined = u64::try_from(kept).expect("a pair count fits a u64");

        let m = judged.len();
        let js = &judged[..m];
        violating.clear();
        violating.reserve(m);
        let slots = &mut violating.spare_capacity_mut()[..m];

        let mut found = 0usize;
        for (i, &row) in js.iter().enumerate() {
            // SAFETY: `found <= i` by the same induction as above, so
            // `found <= i < m == slots.len()`; the payload is `Copy` and
            // `set_len` truncates the rejected slots.
            debug_assert!(found <= i);
            unsafe { slots.get_unchecked_mut(found) }.write(row);
            found += usize::from(row.1 < limit2);
        }

        // SAFETY: slot `k` was written on the iteration where `found == k`, for
        // every `k < found`, and `found <= m <= capacity`.
        unsafe { violating.set_len(found) };
        debug_assert_eq!(found, violating.len(), "the compact kept what it counted");

        // Not a bulk loop: the survivors are the violations.
        for &((a, b), dist2) in &violating {
            out.push(spacing_violation(store, rule, layer, a, b, dist2, limit));
        }

        debug_assert!(
            kept <= pairs.len(),
            "the judged population is a subset of the candidates"
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}
