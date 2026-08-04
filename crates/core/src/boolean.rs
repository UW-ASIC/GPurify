//! Exact rectilinear boolean operations.
//!
//! **Rectilinear only, by decision.** The previous implementation dispatched
//! arbitrary-angle input to a general arrangement solver that failed *open* in
//! three places: a hole with no containing outer ring was silently dropped, a
//! `Ring` that failed to construct from a split-produced sliver was skipped
//! with `Err(_) => {}`, and shared boundary edges were skipped on an unproven
//! "the rest will close correctly" argument. Each of those removes area from a
//! verification result without saying so.
//!
//! So: non-rectilinear input is [`BooleanError::NotRectilinear`], and a caller
//! that cannot proceed reports that rather than a clean result.
//!
//! # Where a result lives
//!
//! `out` is a [`ValidatedLayer`], which owns its coordinate columns. A union of
//! two partially overlapping rectangles is an L whose vertices exist in no
//! store row, and those vertices are written into `out`'s columns; `out.layer`
//! is `None`, because a result belongs to no single input layer. Reading one
//! back needs no store beyond the one the operands were validated from.
//!
//! # Testing
//!
//! This module has the strongest oracle in the tree, because the laws are
//! unconditional and independent of any implementation:
//!
//! - `(a − b) ∪ (a ∩ b) == a`
//! - `a ∩ b ⊆ a` and `a ∪ b ⊇ a`
//! - union and intersection are commutative; self-union is idempotent
//! - `area(a ∪ b) + area(a ∩ b) == area(a) + area(b)`
//! - the result is invariant under translation of both inputs

use core::cmp::Ordering;

use crate::ids::LayerId;
use crate::store::GeometryStoreBuilder;
use crate::view::{validate_layer_into, RingRef, ValidatedLayer, ValidityError};
use gpurify_units::{Dbu, MAX_ABS_DBU};

/// Why a boolean could not be computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BooleanError {
    #[error("input is not rectilinear; arbitrary-angle geometry is unsupported")]
    NotRectilinear,
    #[error(transparent)]
    Validity(#[from] ValidityError),
}

/// Union of two validated layers.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled, so a chain
/// of booleans in a derived-layer expression reuses two buffers by swapping
/// rather than allocating per node.
///
/// Both inputs and the output are [`ValidatedLayer`], so a result is
/// immediately usable as the next operand with no revalidation — the property
/// that makes a derived-layer expression tree cheap.
pub fn union_into(
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    combine_into(a, b, out, |in_a, in_b| in_a | in_b)
}

pub fn intersection_into(
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    combine_into(a, b, out, |in_a, in_b| in_a & in_b)
}

/// `a` minus `b`.
///
/// Not commutative, and the only one of the three where operand order is a
/// silent-wrong-answer risk rather than a compile error. Named `subtraction`
/// rather than `difference` because "difference" reads as symmetric.
pub fn subtraction_into(
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    combine_into(a, b, out, |in_a, in_b| in_a & !in_b)
}

/// Grow (`amount > 0`) or shrink (`amount < 0`) by an exact L-infinity square
/// kernel.
///
/// L-infinity, not Euclidean: a square kernel keeps a rectilinear input
/// rectilinear, so the result is representable exactly. A round kernel would
/// need arbitrary angles, which this module refuses on purpose.
pub fn offset_into(
    a: &ValidatedLayer,
    amount: gpurify_units::Dbu,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    let amt = amount.raw();
    debug_assert!(
        amt.unsigned_abs() <= MAX_ABS_DBU.unsigned_abs(),
        "an offset is a coordinate distance and lives in the coordinate domain"
    );

    let mut sweep = Sweep::default();
    let mut rings = Rings::default();
    collect_rings(a, &mut sweep, &mut rings)?;

    let mut edges = Vec::new();
    vedges_into(&rings, &mut edges);
    let mut xs = Vec::new();
    axis_into(&edges, &mut xs);

    let mut region = Slabs::default();
    occupancy(&edges, &xs, &mut sweep, &mut region);

    // Three cases, and only the sign of `amt` selects between them — a uniform,
    // hoisted above every loop below, not a per-row branch. The empty operand
    // falls out of the first: it has no slab, so every case emits nothing.
    if amt == 0 || xs.len() < 2 {
        return emit(&xs, &region, &mut sweep, out);
    }
    if amt > 0 {
        let mut grown = Vec::new();
        grown_edges_into(&xs, &region, amt, &mut grown);
        let mut gxs = Vec::new();
        axis_into(&grown, &mut gxs);
        let mut dilated = Slabs::default();
        occupancy(&grown, &gxs, &mut sweep, &mut dilated);
        return emit(&gxs, &dilated, &mut sweep, out);
    }

    // Erosion is the complement of the dilation of the complement. The
    // complement is only representable over a bounded universe, so the universe
    // is the operand's own bounding box grown by `|amt| + 1`: every point of
    // the true complement that this one omits lies more than `|amt|` away from
    // every point of the operand, so it cannot reach the operand under a
    // dilation by `|amt|`, and the final subtraction is from the operand
    // itself. Deriving shrink this way rather than from a separate erosion
    // kernel is what keeps it from being a second implementation that can
    // disagree with grow.
    let reach = -amt;
    let margin = reach + 1;
    let (mut ylo, mut yhi) = (i64::MAX, i64::MIN);
    for edge in &edges {
        ylo = ylo.min(edge.ylo);
        yhi = yhi.max(edge.yhi);
    }
    let universe = [
        VEdge {
            x: clamp_dbu(xs[0] - margin),
            ylo: clamp_dbu(ylo - margin),
            yhi: clamp_dbu(yhi + margin),
            delta: 1,
        },
        VEdge {
            x: clamp_dbu(xs[xs.len() - 1] + margin),
            ylo: clamp_dbu(ylo - margin),
            yhi: clamp_dbu(yhi + margin),
            delta: -1,
        },
    ];

    let mut uxs = xs.clone();
    uxs.push(universe[0].x);
    uxs.push(universe[1].x);
    sort_dedup(&mut uxs);

    let mut complement = Slabs::default();
    difference_over(&uxs, &universe, &edges, &mut sweep, &mut complement);

    let mut grown = Vec::new();
    grown_edges_into(&uxs, &complement, reach, &mut grown);

    let mut rxs = Vec::new();
    axis_into(&grown, &mut rxs);
    rxs.extend_from_slice(&xs);
    sort_dedup(&mut rxs);

    let mut eroded = Slabs::default();
    difference_over(&rxs, &edges, &grown, &mut sweep, &mut eroded);
    emit(&rxs, &eroded, &mut sweep, out)
}

/// `p` minus `q`, both swept over the same axis.
///
/// **Transform, A-to-B.** The erosion above is two of these back to back — the
/// complement of the operand, then the operand minus what the dilated
/// complement reached — and running them through one function is what keeps the
/// two sweeps from drifting apart.
fn difference_over(
    axis: &[i64],
    p: &[VEdge],
    q: &[VEdge],
    sweep: &mut Sweep,
    out: &mut Slabs,
) {
    let mut sp = Slabs::default();
    let mut sq = Slabs::default();
    occupancy(p, axis, sweep, &mut sp);
    occupancy(q, axis, sweep, &mut sq);
    combine_slabs(axis.len(), &sp, &sq, |in_p, in_q| in_p & !in_q, sweep, out);
}

// ---------------------------------------------------------------------------
// The one implementation the four transforms above are spellings of.
//
// A left-to-right sweep over the operands' distinct x-coordinates. Every edge
// is axis-aligned, so between two consecutive x the occupied set is a constant
// list of y-intervals, and a set operation is that list combined interval by
// interval — exact, canonical, and with no arrangement solver to fail open in.
//
// The sweep carries one running y-map per operand: a sorted list of the
// coordinates where the nonzero-winding count changes, with the entries that
// cancel dropped as they cancel. So the state is the active boundary, not the
// grid: `O(V + F)` memory for `V` distinct coordinates and `F` edges crossing
// the current cut, where a dense cell grid over the same coordinates would be
// `O(V^2)` and unusable on a full-chip layer.
//
// The boundary of the combined region comes straight off the slab lists —
// vertical segments where two adjacent slabs disagree, horizontal ones at each
// slab's interval ends, both grouped into maximal runs — and feeds `link` and
// `emit` unchanged.
// ---------------------------------------------------------------------------

/// Every ring of one operand, flattened.
///
/// `start` is a CSR offset array of length `ring count + 1`, so ring `r` owns
/// `xs[start[r] .. start[r + 1]]`. Flat columns rather than a `Vec<Vec<_>>` for
/// the reason the rest of this crate gives: the nested form is one allocation
/// per ring on a path that runs per boolean per node of an expression tree.
#[derive(Default)]
struct Rings {
    xs: Vec<i64>,
    ys: Vec<i64>,
    start: Vec<u32>,
}

/// One vertical edge of an operand, as the half-open y-range it spans and the
/// winding it contributes to every cut to its right.
///
/// Horizontal edges cross no horizontal ray and contribute nothing, so they are
/// never collected. `AoS`: the sweep reads all four fields of one edge together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VEdge {
    x: i64,
    ylo: i64,
    yhi: i64,
    delta: i32,
}

/// One boundary segment of a result region, directed so the interior is on its
/// left. `AoS`: linking reads all four fields of one segment together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seg {
    sx: i64,
    sy: i64,
    ex: i64,
    ey: i64,
}

/// The occupied y-intervals of every x-slab, CSR.
///
/// Slab `c` spans `x[c] ..= x[c + 1]` of whichever axis it was swept over and
/// owns `ivals[start[c] .. start[c + 1]]`, ascending and disjoint, each
/// half-open in y. The axis is not stored here: a slab list is only ever read
/// against the axis it was produced over, and two operands share one.
#[derive(Default)]
struct Slabs {
    start: Vec<u32>,
    ivals: Vec<(i64, i64)>,
}

impl Slabs {
    fn open(&mut self) {
        self.start.clear();
        self.start.push(0);
        self.ivals.clear();
    }

    fn close_slab(&mut self) {
        self.start.push(ring_mark(self.ivals.len()));
    }

    fn count(&self) -> usize {
        self.start.len().saturating_sub(1)
    }

    fn slab(&self, c: usize) -> &[(i64, i64)] {
        debug_assert!(c < self.count(), "slab {c} is past the end of the axis");
        &self.ivals[self.start[c] as usize..self.start[c + 1] as usize]
    }
}

/// Every buffer the sweep reuses, grouped by lifetime: one set per call, each
/// cleared where it is filled, so a chain of booleans allocates a fixed handful
/// of times rather than once per slab.
#[derive(Default)]
struct Sweep {
    /// `push_ring`'s raw coordinate columns and its two rectilinearity masks.
    ring_x: Vec<i64>,
    ring_y: Vec<i64>,
    ring_dx: Vec<bool>,
    ring_dy: Vec<bool>,
    /// The running winding-change map of one operand, ascending in y.
    ymap: Vec<(i64, i32)>,
    pending: Vec<(i64, i32)>,
    merged: Vec<(i64, i32)>,
    /// The merged interval endpoints of whichever two lists are being walked.
    ends: Vec<i64>,
    /// The horizontal runs still open, and one slab's horizontal boundary.
    open: Vec<(i64, i32, i64)>,
    next_open: Vec<(i64, i32, i64)>,
    cur: Vec<(i64, i32)>,
    horizontals: Vec<Seg>,
    segs: Vec<Seg>,
    /// The segments ordered by start point and by end point, and the successor
    /// each pair of orders resolves to.
    order: Vec<u32>,
    by_end: Vec<u32>,
    next: Vec<u32>,
    /// `link`'s output columns and its visited mask.
    link_x: Vec<i64>,
    link_y: Vec<i64>,
    link_start: Vec<u32>,
    used: Vec<bool>,
    /// `emit`'s per-ring `map_into` destinations.
    col_x: Vec<Dbu>,
    col_y: Vec<Dbu>,
}

/// Clamp to the legal coordinate domain.
///
/// Only reachable from [`offset_into`], where growing a shape already at
/// `±MAX_ABS_DBU` would leave it. Clamping rather than erroring is the same
/// call [`crate::Bbox::EMPTY`] makes: the domain edge dominates the whole legal
/// coordinate space, so a shape pushed against it is at the edge of what the
/// tool can represent, not outside it.
fn clamp_dbu(value: i64) -> i64 {
    value.clamp(-MAX_ABS_DBU, MAX_ABS_DBU)
}

fn sort_dedup(values: &mut Vec<i64>) {
    values.sort_unstable();
    values.dedup();
}

/// The sweep axis: the distinct x of every edge, ascending.
fn axis_into(edges: &[VEdge], out: &mut Vec<i64>) {
    out.clear();
    out.reserve(edges.len());
    for edge in edges {
        out.push(edge.x);
    }
    sort_dedup(out);
}

fn ring_mark(len: usize) -> u32 {
    u32::try_from(len).expect("a layer's vertex count is a u32 index space")
}

/// Copy one validated ring into the flat columns, refusing arbitrary angles.
///
/// The rectilinearity test is `(x0 != x1) & (y0 != y1)` over every edge. It is
/// accumulated as two per-axis masks and one branchless fold over them, with
/// the ring's wrap edge as the one scalar fixup outside, so the early return
/// happens once per call, above every loop, instead of inside one.
fn push_ring(
    ring: RingRef<'_>,
    sweep: &mut Sweep,
    rings: &mut Rings,
) -> Result<(), BooleanError> {
    let (xs, ys) = ring.coords();
    debug_assert_eq!(xs.len(), ys.len(), "a ring's two columns are parallel");
    let n = xs.len();
    if n == 0 {
        rings.start.push(ring_mark(rings.xs.len()));
        return Ok(());
    }

    sweep.ring_x.clear();
    sweep.ring_x.reserve(n);
    for &x in xs {
        sweep.ring_x.push(x.raw());
    }
    sweep.ring_y.clear();
    sweep.ring_y.reserve(n);
    for &y in ys {
        sweep.ring_y.push(y.raw());
    }
    debug_assert_eq!(
        sweep.ring_x.len(),
        sweep.ring_y.len(),
        "the two raw columns stay parallel"
    );
    debug_assert!(
        (0..n).fold(true, |ok, i| ok
            & Dbu::new(sweep.ring_x[i]).is_some()
            & Dbu::new(sweep.ring_y[i]).is_some()),
        "a validated coordinate is inside the domain MAX_ABS_DBU bounds"
    );

    // The adjacent-pair scan, one output row per edge but the wrap edge, which
    // is the scalar fixup below. One loop rather than two: the two masks are
    // written from disjoint columns, so neither depends on the other.
    sweep.ring_dx.clear();
    sweep.ring_dx.reserve(n - 1);
    sweep.ring_dy.clear();
    sweep.ring_dy.reserve(n - 1);
    for i in 0..n - 1 {
        sweep.ring_dx.push(sweep.ring_x[i] != sweep.ring_x[i + 1]);
        sweep.ring_dy.push(sweep.ring_y[i] != sweep.ring_y[i + 1]);
    }

    let (dx, dy) = (&sweep.ring_dx[..], &sweep.ring_dy[..]);
    debug_assert_eq!(dx.len(), dy.len(), "the two masks stay parallel");
    // Branchless: `|=` and `&` on `bool` do not short-circuit, so the fold is
    // an unconditional two-input `or` per edge with no branch to mispredict.
    let mut skew = false;
    for i in 0..dx.len() {
        skew |= dx[i] & dy[i];
    }
    let wrap = (sweep.ring_x[n - 1] != sweep.ring_x[0]) & (sweep.ring_y[n - 1] != sweep.ring_y[0]);
    // Escape valve: the taken side abandons the whole transform, and it is
    // taken at most once per call rather than once per vertex.
    if skew | wrap {
        return Err(BooleanError::NotRectilinear);
    }

    rings.xs.extend_from_slice(&sweep.ring_x);
    rings.ys.extend_from_slice(&sweep.ring_y);
    rings.start.push(ring_mark(rings.xs.len()));
    Ok(())
}

/// Flatten every ring of every polygon of one operand.
fn collect_rings(
    layer: &ValidatedLayer,
    sweep: &mut Sweep,
    rings: &mut Rings,
) -> Result<(), BooleanError> {
    rings.xs.clear();
    rings.ys.clear();
    rings.start.clear();
    rings.start.push(0);

    // `poly_rings` rather than `get`: these four frozen signatures carry no
    // store, and `get`'s exists only to check a layer against the store it was
    // validated from. An empty scratch store would silence that check for every
    // caller that does have one.
    let polys = u32::try_from(layer.len()).expect("a layer's polygon count is a u32 index space");
    for idx in 0..polys {
        for ring in layer.poly_rings(idx) {
            push_ring(ring, sweep, rings)?;
        }
    }

    debug_assert_eq!(rings.xs.len(), rings.ys.len(), "flat columns stay parallel");
    debug_assert_eq!(
        rings.start[rings.start.len() - 1] as usize,
        rings.xs.len(),
        "the CSR offsets cover every vertex pushed"
    );
    debug_assert!(
        rings.start.len() > polys as usize,
        "every polygon contributed at least its outer boundary"
    );
    Ok(())
}

/// Every vertical edge of one operand, ascending in x.
///
/// A downward edge counts `+1` and an upward one `-1`, so the winding at a
/// point is the signed count of the edges at or left of it that span its y —
/// the ray-crossing rule read from the left, which is what turns the sweep into
/// a running sum rather than a per-point query.
fn vedges_into(rings: &Rings, out: &mut Vec<VEdge>) {
    out.clear();
    out.reserve(rings.xs.len());

    for ring in 0..rings.start.len().saturating_sub(1) {
        let (lo, hi) = (
            rings.start[ring] as usize,
            rings.start[ring + 1] as usize,
        );
        let n = hi - lo;
        for i in 0..n {
            let (a, b) = (lo + i, lo + (i + 1) % n);
            // Escape valve: the taken side is a push. Half of a rectilinear
            // ring's edges are horizontal, so the two sides alternate perfectly
            // and the predictor has it.
            if rings.xs[a] != rings.xs[b] {
                continue;
            }
            let (y0, y1) = (rings.ys[a], rings.ys[b]);
            out.push(VEdge {
                x: rings.xs[a],
                ylo: y0.min(y1),
                yhi: y0.max(y1),
                // Branchless: a zero-length edge writes `+1` and `-1` at one y
                // and cancels itself whatever this says.
                delta: 1 - 2 * i32::from(y1 > y0),
            });
        }
    }

    out.sort_unstable_by_key(|edge| edge.x);
}

/// Merge one cut's winding changes into the running map, dropping what cancels.
///
/// Both inputs are ascending in y; `base` has one entry per y and `add` may
/// have several. Dropping the entries that reach zero is what keeps the map the
/// size of the active boundary rather than the size of the operand.
fn merge_deltas(base: &[(i64, i32)], add: &[(i64, i32)], out: &mut Vec<(i64, i32)>) {
    out.clear();
    out.reserve(base.len() + add.len());

    let (mut i, mut j) = (0usize, 0usize);
    while i < base.len() || j < add.len() {
        // Branchless: the sentinel makes the exhausted side lose every compare.
        let left = base.get(i).map_or(i64::MAX, |&(y, _)| y);
        let right = add.get(j).map_or(i64::MAX, |&(y, _)| y);
        let y = left.min(right);

        let mut acc = 0i32;
        while i < base.len() && base[i].0 == y {
            acc += base[i].1;
            i += 1;
        }
        while j < add.len() && add[j].0 == y {
            acc += add[j].1;
            j += 1;
        }
        // Always store, conditionally advance: a cancelled y leaves the map.
        out.push((y, acc));
        out.truncate(out.len() - usize::from(acc == 0));
    }

    debug_assert!(
        out.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "the running map holds one nonzero entry per y, ascending"
    );
}

/// Turn one cut's winding-change map into the occupied y-intervals, appended.
fn intervals_into(ymap: &[(i64, i32)], out: &mut Vec<(i64, i64)>) {
    let mut sum = 0i32;
    let mut open = 0i64;

    for &(y, delta) in ymap {
        let was = sum;
        sum += delta;
        // Escape valve: an interval opens or closes once per interval, not once
        // per entry, so the taken side is the rare one. `ymap` holds no zero
        // delta, so `was == 0` implies the sum just left zero.
        if was == 0 {
            open = y;
        } else if sum == 0 {
            out.push((open, y));
        }
    }

    debug_assert_eq!(sum, 0, "a closed boundary's winding returns to zero");
}

/// Occupancy of every x-slab, by the nonzero-winding rule.
///
/// **Transform, A-to-B.** `edges` ascending in x, `xs` the distinct x of the
/// axis being swept — which must contain every edge's x, and may contain more,
/// because two operands are always swept over one shared axis. Extra lines only
/// split a slab into two with the same occupancy, which [`segments`] merges
/// back into one run.
fn occupancy(edges: &[VEdge], xs: &[i64], sweep: &mut Sweep, out: &mut Slabs) {
    debug_assert!(
        edges.windows(2).all(|pair| pair[0].x <= pair[1].x),
        "the sweep consumes its edges in one ascending pass"
    );
    debug_assert!(
        edges.iter().all(|edge| xs.binary_search(&edge.x).is_ok()),
        "every edge's x is a line of the axis being swept"
    );

    out.open();
    sweep.ymap.clear();
    let mut next = 0usize;

    for &x in &xs[..xs.len().saturating_sub(1)] {
        sweep.pending.clear();
        while next < edges.len() && edges[next].x == x {
            let edge = edges[next];
            sweep.pending.push((edge.ylo, edge.delta));
            sweep.pending.push((edge.yhi, -edge.delta));
            next += 1;
        }
        // Escape valve: a cut with no edge on it is the common case once the
        // axis is shared between two operands, and the taken side is a sort
        // plus a full merge of the running map.
        if !sweep.pending.is_empty() {
            sweep.pending.sort_unstable();
            merge_deltas(&sweep.ymap, &sweep.pending, &mut sweep.merged);
            std::mem::swap(&mut sweep.ymap, &mut sweep.merged);
        }
        intervals_into(&sweep.ymap, &mut out.ivals);
        out.close_slab();
    }

    debug_assert_eq!(
        out.count(),
        xs.len().saturating_sub(1),
        "one interval run per slab of the axis"
    );
    debug_assert!(
        next == edges.len() || edges[next].x >= xs[xs.len() - 1],
        "an edge was left unswept inside the axis"
    );
}

/// Does an ascending, disjoint interval list cover `y`?
fn covers(ivals: &[(i64, i64)], y: i64) -> bool {
    let after = ivals.partition_point(|&(lo, _)| lo <= y);
    (after > 0) && (ivals[after - 1].1 > y)
}

/// Every endpoint of two interval lists, ascending and deduplicated.
///
/// The values at which either list can change, and therefore the only y at
/// which a combination of the two can start or stop a run.
fn endpoints(a: &[(i64, i64)], b: &[(i64, i64)], out: &mut Vec<i64>) {
    out.clear();
    out.reserve(2 * (a.len() + b.len()));
    for &(lo, hi) in a.iter().chain(b) {
        out.push(lo);
        out.push(hi);
    }
    sort_dedup(out);
}

/// Apply a set operation slab by slab.
///
/// **Transform, A-to-B.** Both operands must have been swept over one axis, so
/// slab `c` of each names the same x-range.
fn combine_slabs(
    lines: usize,
    a: &Slabs,
    b: &Slabs,
    op: impl Fn(bool, bool) -> bool,
    sweep: &mut Sweep,
    out: &mut Slabs,
) {
    let slabs = lines.saturating_sub(1);
    debug_assert_eq!(a.count(), slabs, "both operands share one axis");
    debug_assert_eq!(b.count(), slabs, "both operands share one axis");
    out.open();

    for c in 0..slabs {
        let (left, right) = (a.slab(c), b.slab(c));
        endpoints(left, right, &mut sweep.ends);

        let mut open = false;
        let mut from = 0i64;
        for k in 0..sweep.ends.len() {
            let y = sweep.ends[k];
            // The last endpoint is above both operands, so nothing is occupied
            // there and every run is forced closed inside the axis.
            let keep = (k + 1 < sweep.ends.len()) & op(covers(left, y), covers(right, y));
            // Escape valve: taken once per run of the *result*, not once per
            // endpoint, and the two arms are a push and an assignment.
            if keep != open {
                if open {
                    out.ivals.push((from, y));
                }
                from = y;
                open = keep;
            }
        }
        debug_assert!(!open, "a slab's occupancy closes inside the axis");
        out.close_slab();
    }
}

/// Every vertical edge of a region grown by an exact L-infinity square kernel.
///
/// **Transform, A-to-B.** A dilation distributes over union, and a slab list is
/// a union of axis-aligned rectangles, so growing each rectangle by `amount` on
/// all four sides and re-sweeping the result is the whole operation. That is
/// what keeps grow and the erosion that is built out of it on one code path.
fn grown_edges_into(xs: &[i64], region: &Slabs, amount: i64, out: &mut Vec<VEdge>) {
    debug_assert!(amount > 0, "a dilation grows; the caller picks the case");
    debug_assert_eq!(
        region.count(),
        xs.len().saturating_sub(1),
        "one interval run per slab of the axis"
    );
    out.clear();
    out.reserve(2 * region.ivals.len());

    for c in 0..region.count() {
        // A slab is at least one unit wide and `amount` is positive, so the two
        // sides can only clamp to one value if the operand already spanned the
        // whole legal domain, which `Dbu`'s own bound rules out.
        let x0 = clamp_dbu(xs[c] - amount);
        let x1 = clamp_dbu(xs[c + 1] + amount);
        debug_assert!(x0 < x1, "clamping collapsed a grown slab");
        for &(lo, hi) in region.slab(c) {
            let ylo = clamp_dbu(lo - amount);
            let yhi = clamp_dbu(hi + amount);
            debug_assert!(ylo < yhi, "clamping collapsed a grown interval");
            // A counter-clockwise rectangle: its left side runs down and its
            // right side runs up, so the winding inside it is `+1` and two
            // overlapping rectangles union rather than cancel.
            out.push(VEdge {
                x: x0,
                ylo,
                yhi,
                delta: 1,
            });
            out.push(VEdge {
                x: x1,
                ylo,
                yhi,
                delta: -1,
            });
        }
    }

    out.sort_unstable_by_key(|edge| edge.x);
}

/// Every boundary segment of a slab list, directed interior-on-the-left.
///
/// **Transform, A-to-B.** A segment exists where two adjacent slabs disagree
/// (vertical) or where a slab's occupancy starts or stops (horizontal), and
/// maximal runs of agreeing direction are emitted as one segment, so the L that
/// two rectangles union into comes back as six vertices rather than as one per
/// coordinate it happens to cross. Interior-on-the-left is what makes an outer
/// boundary counter-clockwise and a hole clockwise with no post-hoc reversal.
fn segments(xs: &[i64], region: &Slabs, sweep: &mut Sweep) {
    let slabs = xs.len().saturating_sub(1);
    debug_assert_eq!(region.count(), slabs, "one interval run per slab");
    sweep.segs.clear();
    sweep.horizontals.clear();

    // `i` survives as an index because it addresses `region`'s slabs at two
    // different offsets, `i - 1` and `i`; `x` is the axis coordinate it would
    // otherwise re-read out of `xs` twice per run.
    for (i, &x) in xs.iter().enumerate() {
        let left = if i > 0 { region.slab(i - 1) } else { &[][..] };
        let right = if i < slabs { region.slab(i) } else { &[][..] };
        endpoints(left, right, &mut sweep.ends);

        let mut run = 0i32;
        let mut from = 0i64;
        for k in 0..sweep.ends.len() {
            let y = sweep.ends[k];
            // Left slab inside means the boundary runs up; right slab inside
            // means it runs down; both or neither means there is no boundary.
            // The last endpoint is above both, which forces the closing run.
            let side = i32::from(k + 1 < sweep.ends.len())
                * (i32::from(covers(left, y)) - i32::from(covers(right, y)));
            // Escape valve: taken once per run, not once per endpoint.
            if side != run {
                push_run(&mut sweep.segs, run, (x, from), (x, y));
                run = side;
                from = y;
            }
        }
        debug_assert_eq!(run, 0, "a boundary run cannot leave the axis");
    }

    // The horizontal boundary of a slab is its intervals' own ends: a start has
    // the interior above it and runs right, an end has it below and runs left.
    // A run continues into the next slab when that slab has the same end with
    // the same sense, which is one merge of two ascending lists per slab.
    sweep.open.clear();
    // `0 .. xs.len()`, not `0 ..= slabs`: an empty region has no axis at all,
    // and there is then no right edge to close a run against.
    // `c` survives as an index because it addresses `region`'s slabs, which is
    // one shorter than `xs`; `x` is the axis coordinate.
    for (c, &x) in xs.iter().enumerate() {
        sweep.cur.clear();
        // Escape valve: false on exactly one iteration, so the predictor has
        // it. It exists to close every run at the right edge of the last slab.
        if c < slabs {
            for &(lo, hi) in region.slab(c) {
                sweep.cur.push((lo, 1));
                sweep.cur.push((hi, -1));
            }
        }
        debug_assert!(
            sweep.cur.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "a slab's intervals are ascending and disjoint"
        );

        sweep.next_open.clear();
        let (mut p, mut q) = (0usize, 0usize);
        while p < sweep.open.len() || q < sweep.cur.len() {
            // Branchless: the sentinel makes the exhausted side lose every
            // compare, so the merge has one three-way branch rather than five.
            let ahead = sweep
                .open
                .get(p)
                .map_or((i64::MAX, i32::MAX), |&(y, side, _)| (y, side));
            let here = sweep.cur.get(q).copied().unwrap_or((i64::MAX, i32::MAX));
            // Escape valve: a three-way on a merge's own control flow, taken
            // once per output row. There is no arithmetic form of "advance one
            // of two cursors".
            match ahead.cmp(&here) {
                Ordering::Equal => {
                    sweep.next_open.push(sweep.open[p]);
                    p += 1;
                    q += 1;
                }
                Ordering::Less => {
                    let (y, side, from) = sweep.open[p];
                    push_run(&mut sweep.horizontals, side, (from, y), (x, y));
                    p += 1;
                }
                Ordering::Greater => {
                    sweep.next_open.push((here.0, here.1, x));
                    q += 1;
                }
            }
        }
        std::mem::swap(&mut sweep.open, &mut sweep.next_open);
    }
    debug_assert!(
        sweep.open.is_empty(),
        "a boundary run cannot leave the axis"
    );

    // Canonical, and therefore reproducible: the verticals come off the sweep
    // ordered by x then y, and this is the same order for the horizontals.
    sweep
        .horizontals
        .sort_unstable_by_key(|seg| (seg.sy, seg.sx.min(seg.ex)));
    sweep.segs.extend_from_slice(&sweep.horizontals);

    debug_assert!(
        sweep.segs.len().is_multiple_of(2),
        "boundary segments alternate between the two axes around every loop"
    );
}

/// Close one run of the trace: `+1` keeps the walk's own direction, `-1`
/// reverses it, `0` is not a boundary at all.
fn push_run(segs: &mut Vec<Seg>, run: i32, low: (i64, i64), high: (i64, i64)) {
    // Escape valve: three-way on a run's sign, taken once per *run*, and the
    // zero arm is the common one. There is no arithmetic form of "push nothing".
    if run > 0 {
        segs.push(Seg {
            sx: low.0,
            sy: low.1,
            ex: high.0,
            ey: high.1,
        });
    } else if run < 0 {
        segs.push(Seg {
            sx: high.0,
            sy: high.1,
            ex: low.0,
            ey: low.1,
        });
    }
}

/// Unit direction of a segment.
fn dir_of(seg: Seg) -> (i64, i64) {
    ((seg.ex - seg.sx).signum(), (seg.ey - seg.sy).signum())
}

fn head_of(seg: Seg) -> (i64, i64) {
    (seg.sx, seg.sy)
}

fn tail_of(seg: Seg) -> (i64, i64) {
    (seg.ex, seg.ey)
}

/// Which segment continues the walk from each segment's tail.
///
/// **Transform, A-to-B.** One output row per input row, each a function of its
/// own segment and the two orders, so any row order is legal and the pass is a
/// kernel. Splitting it out of the walk below is what leaves that walk nothing
/// but a `next[cur]` load: the search used to sit *inside* the chain, one binary
/// probe plus a scan per step with the answer feeding the next probe, so no
/// prefetch could run ahead of it. Here it is a single linear merge of the
/// segments ordered by head against the same segments ordered by tail, and both
/// cursors advance in step because a boundary vertex's in-degree equals its
/// out-degree — the merge never searches for its counterpart group.
///
/// Every vertex of an interior-on-the-left boundary has degree two or degree
/// four and never three. At degree two there is one candidate and the walk is
/// forced. At a degree-four pinch — two cells meeting at a corner — the leftmost
/// turn is taken, which keeps the two cells as two simple rings; the rightmost
/// turn joins them into one ring that touches itself, which `view`'s simplicity
/// check would then refuse. The left turn always exists at a pinch, and it pairs
/// the two arrivals with the two departures one to one, which is what makes
/// `next` a permutation and therefore makes the walk a cycle decomposition.
///
/// The old form consulted the visited mask while choosing, so a successor
/// depended on how much of the boundary had already been walked. Nothing here
/// reads it: a successor is a function of the geometry alone.
fn successors_into(segs: &[Seg], order: &mut Vec<u32>, by_end: &mut Vec<u32>, next: &mut Vec<u32>) {
    order.clear();
    order.extend(0..ring_mark(segs.len()));
    by_end.clear();
    by_end.extend_from_slice(order);
    order.sort_unstable_by_key(|&i| head_of(segs[i as usize]));
    by_end.sort_unstable_by_key(|&i| tail_of(segs[i as usize]));

    next.clear();
    next.resize(segs.len(), u32::MAX);

    let (mut head, mut tail) = (0usize, 0usize);
    while tail < by_end.len() {
        let point = tail_of(segs[by_end[tail] as usize]);

        // Two group scans, each of at most two iterations because the degree is
        // two or four. Escape valve on both: the trip count is the degree, not
        // the segment count, so the exit predicts as well as a fixed bound.
        let mut tail_end = tail;
        while tail_end < by_end.len() && tail_of(segs[by_end[tail_end] as usize]) == point {
            tail_end += 1;
        }
        let mut head_end = head;
        while head_end < order.len() && head_of(segs[order[head_end] as usize]) == point {
            head_end += 1;
        }

        // Fail closed, in every profile, and it is what keeps the two cursors
        // in step: a point that a segment enters and none leaves is a dropped
        // segment, and the alternative is to hand `link` a boundary that never
        // closes and `emit` a ring that is a polyline — it would validate as a
        // polygon of the wrong area and be reported as a clean result. One
        // compare per vertex is not a cost worth trading for that.
        assert!(
            head < head_end,
            "a boundary segment ends at a point no segment leaves"
        );
        debug_assert_eq!(
            head_end - head,
            tail_end - tail,
            "a boundary vertex's in-degree equals its out-degree"
        );
        debug_assert!(
            head_end - head <= 2,
            "a boundary vertex has degree two or degree four, never more"
        );

        for &arrival in &by_end[tail..tail_end] {
            let (dx, dy) = dir_of(segs[arrival as usize]);
            let want = (-dy, dx);
            // Branchless: the group is one or two wide and the fallback is its
            // first member, so the left turn is a select over the group rather
            // than a search with an early exit. A degree-two reflex corner has
            // no left turn and keeps the fallback, which is its one candidate.
            let mut pick = order[head];
            for &departure in &order[head..head_end] {
                let hit = dir_of(segs[departure as usize]) == want;
                pick = if hit { departure } else { pick };
            }
            next[arrival as usize] = pick;
        }

        head = head_end;
        tail = tail_end;
    }

    debug_assert_eq!(
        head,
        order.len(),
        "every segment's head is the tail of some segment"
    );
    debug_assert!(
        next.iter().all(|&n| (n as usize) < segs.len()),
        "every segment got a successor inside the segment table"
    );
}

/// Walk the successor permutation into closed rings.
///
/// **Transform, A-to-B.** Output is flat coordinate columns plus a CSR offset
/// array, one entry per ring. `next` is a permutation, so this is a cycle
/// decomposition, and the only loop-carried dependency left is the `next[cur]`
/// load itself — `/simd-loops` triage classifies that as a chain, and it is one
/// no layout change removes: a cycle's length is not known until it has been
/// walked. Distinct cycles are independent of each other, so this is the pass to
/// hand to a tasker if ring counts ever justify one.
fn link(
    segs: &[Seg],
    next: &[u32],
    xs: &mut Vec<i64>,
    ys: &mut Vec<i64>,
    start: &mut Vec<u32>,
    used: &mut Vec<bool>,
) {
    debug_assert_eq!(next.len(), segs.len(), "one successor per segment");
    xs.clear();
    xs.reserve(segs.len());
    ys.clear();
    ys.reserve(segs.len());
    start.clear();
    start.push(0);
    used.clear();
    used.resize(segs.len(), false);

    for seed in 0..segs.len() {
        // Escape valve: taken for every segment but one per ring, so it is the
        // overwhelmingly common side and the predictor has it.
        if used[seed] {
            continue;
        }
        let mut cur = seed;
        loop {
            used[cur] = true;
            xs.push(segs[cur].sx);
            ys.push(segs[cur].sy);

            let step = next[cur] as usize;
            // Escape valve: closes the ring, taken once per cycle rather than
            // once per segment.
            if step == seed {
                break;
            }
            // Fail closed, in every profile. Re-entering a segment means `next`
            // is not a permutation, which is the same defect the assert in
            // `successors_into` guards from the other side: a ring that is a
            // polyline validates as a polygon of the wrong area and is reported
            // as a clean result. The precondition is `segments`' own
            // postcondition, so this is an internal contract, not an input the
            // caller can trip.
            assert!(
                !used[step],
                "a region boundary is a union of disjoint closed loops"
            );
            cur = step;
        }
        start.push(ring_mark(xs.len()));

        let ring = start.len() - 1;
        let length = start[ring] - start[ring - 1];
        debug_assert!(
            length >= 4 && length.is_multiple_of(2),
            "a rectilinear ring has an even number of vertices, at least four"
        );
    }

    // Every profile, for the reason the assert above gives: a segment that
    // landed in no ring is area missing from a verification result, and one
    // compare amortised over the whole link is not a cost worth trading for it.
    assert_eq!(
        xs.len(),
        segs.len(),
        "every boundary segment lands in exactly one ring"
    );
    debug_assert_eq!(xs.len(), ys.len(), "flat columns stay parallel");
}

/// Trace, link, and validate the result into `out`.
///
/// **Transform, A-to-B.** The rings go through a one-layer `GeometryStore` and
/// [`validate_layer_into`] rather than into `out`'s columns directly, because
/// that is the only route this module has to them — see `collect_rings` — and
/// because grouping outer boundaries with the holes they contain is work
/// `view` already owns. Doing it here would be a second implementation of
/// containment that can disagree with the first.
fn emit(
    xs: &[i64],
    region: &Slabs,
    sweep: &mut Sweep,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    segments(xs, region, sweep);
    successors_into(
        &sweep.segs,
        &mut sweep.order,
        &mut sweep.by_end,
        &mut sweep.next,
    );
    link(
        &sweep.segs,
        &sweep.next,
        &mut sweep.link_x,
        &mut sweep.link_y,
        &mut sweep.link_start,
        &mut sweep.used,
    );

    let ring_count = sweep.link_start.len() - 1;
    let mut builder = GeometryStoreBuilder::with_capacity(ring_count, sweep.link_x.len());
    debug_assert_eq!(
        sweep.link_x.len(),
        sweep.link_y.len(),
        "the linked columns stay parallel"
    );
    for ring in 0..ring_count {
        let (lo, hi) = (
            sweep.link_start[ring] as usize,
            sweep.link_start[ring + 1] as usize,
        );
        // Every coordinate here is either a copy of an operand's, which was in
        // domain, or a clamped displacement of one, so `new_unchecked` is
        // honest — and it still asserts the claim in a debug build.
        sweep.col_x.clear();
        sweep.col_x.reserve(hi - lo);
        sweep.col_y.clear();
        sweep.col_y.reserve(hi - lo);
        for i in lo..hi {
            sweep.col_x.push(Dbu::new_unchecked(sweep.link_x[i]));
            sweep.col_y.push(Dbu::new_unchecked(sweep.link_y[i]));
        }
        builder.push(RESULT_LAYER, &sweep.col_x, &sweep.col_y);
    }

    let (store, _permutation) = builder.finish(1);
    validate_layer_into(&store, RESULT_LAYER, out)?;
    debug_assert!(
        out.len() <= ring_count,
        "a result polygon is an outer boundary plus the holes it swallowed"
    );
    Ok(())
}

/// Apply a set operation to two operands over one shared sweep axis.
fn combine_into(
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut ValidatedLayer,
    op: impl Fn(bool, bool) -> bool,
) -> Result<(), BooleanError> {
    let mut sweep = Sweep::default();
    let mut ra = Rings::default();
    let mut rb = Rings::default();
    collect_rings(a, &mut sweep, &mut ra)?;
    collect_rings(b, &mut sweep, &mut rb)?;

    let mut ea = Vec::new();
    let mut eb = Vec::new();
    vedges_into(&ra, &mut ea);
    vedges_into(&rb, &mut eb);

    let mut xs = Vec::new();
    let mut bxs = Vec::new();
    axis_into(&ea, &mut xs);
    axis_into(&eb, &mut bxs);
    xs.extend_from_slice(&bxs);
    sort_dedup(&mut xs);

    let mut sa = Slabs::default();
    let mut sb = Slabs::default();
    occupancy(&ea, &xs, &mut sweep, &mut sa);
    occupancy(&eb, &xs, &mut sweep, &mut sb);

    let mut result = Slabs::default();
    combine_slabs(xs.len(), &sa, &sb, op, &mut sweep, &mut result);
    emit(&xs, &result, &mut sweep, out)
}

/// The layer of the one-layer store `emit` builds. A result belongs to no input
/// layer, and this tag never leaves this module.
const RESULT_LAYER: LayerId = LayerId(0);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::GeometryStore;
    use gpurify_units::DbuArea;

    /// Area of a result layer, read without a store — the boolean's own rings
    /// are the only thing a caller of [`offset_into`] can reach when the result
    /// coordinates exist in no store row.
    fn area(layer: &ValidatedLayer) -> i128 {
        let mut doubled = 0i128;
        for idx in 0..u32::try_from(layer.len()).expect("a test layer fits a u32") {
            for ring in layer.poly_rings(idx) {
                doubled += ring.area2().raw();
            }
        }
        debug_assert!(doubled % 2 == 0, "a rectilinear area is an integer");
        doubled / 2
    }

    fn square(half: i64) -> (GeometryStore, ValidatedLayer) {
        let mut builder = GeometryStoreBuilder::with_capacity(1, 4);
        let xs = [-half, half, half, -half].map(Dbu::new_unchecked);
        let ys = [-half, -half, half, half].map(Dbu::new_unchecked);
        builder.push(RESULT_LAYER, &xs, &ys);
        let (store, _) = builder.finish(1);
        let mut layer = ValidatedLayer::default();
        validate_layer_into(&store, RESULT_LAYER, &mut layer).expect("a square is valid");
        (store, layer)
    }

    /// Oracle: closed form. An L-infinity offset of a square by `r` is a square
    /// of side `2 * (half + r)`, for either sign of `r`. Nothing else in the
    /// tree exercises a non-zero offset, because a grown result's coordinates
    /// exist in no store row and the integration tests read results through
    /// one.
    #[test]
    fn offsetting_a_square_gives_the_square_the_closed_form_names() {
        let (_store, a) = square(100);
        let mut out = ValidatedLayer::default();

        for amount in [-99i64, -40, -1, 0, 1, 40, 250] {
            offset_into(&a, Dbu::new_unchecked(amount), &mut out).expect("a square is rectilinear");
            let side = 2 * (100 + amount);
            assert_eq!(
                area(&out),
                i128::from(side) * i128::from(side),
                "offsetting a 200x200 square by {amount}"
            );
            assert_eq!(out.len(), 1, "an offset square is one polygon at {amount}");
        }
    }

    /// Oracle: law. A shrink by more than the half-width leaves nothing, and
    /// "nothing" has to be an empty layer rather than a layer of empty
    /// polygons — an empty clean result and a result that was never computed
    /// have to stay distinguishable.
    #[test]
    fn shrinking_past_the_half_width_leaves_nothing() {
        let (_store, a) = square(100);
        let mut out = ValidatedLayer::default();
        offset_into(&a, Dbu::new_unchecked(-100), &mut out).expect("a square is rectilinear");
        assert!(out.is_empty(), "a square shrunk to nothing kept polygons");
        assert_eq!(area(&out), 0);
    }

    /// Oracle: closed form. An L is the union of two bars, so growing it is the
    /// union of the two grown bars, and eroding it is the L inset by the same
    /// amount — the reflex corner is the one place a square kernel and a round
    /// one would disagree, and the one this module's erosion is derived rather
    /// than written.
    #[test]
    fn offsetting_an_l_agrees_with_the_two_bars_it_is_made_of() {
        let mut builder = GeometryStoreBuilder::with_capacity(1, 6);
        let xs = [0i64, 90, 90, 20, 20, 0].map(Dbu::new_unchecked);
        let ys = [0i64, 0, 20, 20, 90, 90].map(Dbu::new_unchecked);
        builder.push(RESULT_LAYER, &xs, &ys);
        let (store, _) = builder.finish(1);
        let mut a = ValidatedLayer::default();
        validate_layer_into(&store, RESULT_LAYER, &mut a).expect("an L is valid");
        assert_eq!(area(&a), 90 * 20 + 20 * 70);

        let mut out = ValidatedLayer::default();
        offset_into(&a, Dbu::new_unchecked(5), &mut out).expect("an L is rectilinear");
        // `[-5, 95] x [-5, 25]` and `[-5, 25] x [-5, 95]`, overlapping in the
        // `30 x 30` corner they share.
        assert_eq!(area(&out), 100 * 30 + 30 * 100 - 30 * 30);
        assert_eq!(out.len(), 1, "a grown L is still one polygon");

        offset_into(&a, Dbu::new_unchecked(-5), &mut out).expect("an L is rectilinear");
        // `[5, 85] x [5, 15]` and `[5, 15] x [15, 85]`.
        assert_eq!(area(&out), 80 * 10 + 10 * 70);
        assert_eq!(out.len(), 1, "an eroded L is still one polygon");
    }

    /// Oracle: law. Growing distributes over union, so growing two squares far
    /// enough apart to stay apart is two grown squares, and growing them until
    /// they touch is one.
    #[test]
    fn growing_merges_two_squares_exactly_when_they_meet() {
        let mut builder = GeometryStoreBuilder::with_capacity(2, 8);
        for centre in [0i64, 300] {
            let xs = [centre - 50, centre + 50, centre + 50, centre - 50].map(Dbu::new_unchecked);
            let ys = [-50, -50, 50, 50].map(Dbu::new_unchecked);
            builder.push(RESULT_LAYER, &xs, &ys);
        }
        let (store, _) = builder.finish(1);
        let mut a = ValidatedLayer::default();
        validate_layer_into(&store, RESULT_LAYER, &mut a).expect("two squares are valid");

        // The squares span [-50, 50] and [250, 350], so the gap is 200 and each
        // side of it has to close by 100 for them to meet.
        let mut out = ValidatedLayer::default();
        offset_into(&a, Dbu::new_unchecked(50), &mut out).expect("a square is rectilinear");
        assert_eq!(out.len(), 2, "the gap of 200 is still open at a grow of 50");
        assert_eq!(area(&out), 2 * 200 * 200);

        offset_into(&a, Dbu::new_unchecked(100), &mut out).expect("a square is rectilinear");
        assert_eq!(out.len(), 1, "the gap of 200 closes at a grow of 100");
        // They meet edge to edge at x = 150, so the union is one 600 x 300
        // rectangle and not two overlapping squares.
        assert_eq!(area(&out), 600 * 300);
    }

    /// Oracle: law. `DbuArea` is the tree's area type and this module's own
    /// laws are stated over it; a rectilinear region's doubled area is even.
    #[test]
    fn a_union_conserves_area_against_its_intersection() {
        let mut builder = GeometryStoreBuilder::with_capacity(2, 8);
        let xs = [0i64, 100, 100, 0].map(Dbu::new_unchecked);
        let ys = [0i64, 0, 100, 100].map(Dbu::new_unchecked);
        builder.push(LayerId(0), &xs, &ys);
        let xs = [50i64, 150, 150, 50].map(Dbu::new_unchecked);
        let ys = [50i64, 50, 150, 150].map(Dbu::new_unchecked);
        builder.push(LayerId(1), &xs, &ys);
        let (store, _) = builder.finish(2);

        let mut a = ValidatedLayer::default();
        let mut b = ValidatedLayer::default();
        validate_layer_into(&store, LayerId(0), &mut a).expect("valid");
        validate_layer_into(&store, LayerId(1), &mut b).expect("valid");

        let mut joined = ValidatedLayer::default();
        let mut shared = ValidatedLayer::default();
        union_into(&a, &b, &mut joined).expect("rectilinear");
        intersection_into(&a, &b, &mut shared).expect("rectilinear");

        assert_eq!(area(&shared), 50 * 50, "the overlap is 50x50");
        assert_eq!(
            DbuArea::new(area(&joined) + area(&shared)),
            DbuArea::new(100 * 100 + 100 * 100),
            "area is not conserved across the union and the intersection"
        );
        assert_eq!(joined.len(), 1, "two overlapping squares union into an L");
    }
}
