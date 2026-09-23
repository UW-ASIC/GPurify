//! Exact rectilinear booleans by an x-sweep with nonzero-winding occupancy.
//!
//! Data in: [`ValidatedLayer`] operands (or one raw GDS ring for [`canonical_rings_into`]).
//! Data out: a [`ValidatedLayer`], outer rings CCW, holes CW; provenance is the
//! lowest contributing `PolyId`. Non-rectilinear input is refused, never approximated.

use core::cmp::Ordering;

use crate::ids::LayerId;
use crate::store::GeometryStoreBuilder;
use crate::view::{validate_layer_into, ValidatedLayer, ValidityError};
use crate::{Dbu, MAX_ABS_DBU};

/// Why a boolean could not be computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BooleanError {
    #[error("input is not rectilinear; arbitrary-angle geometry is unsupported")]
    NotRectilinear,
    #[error(transparent)]
    Validity(#[from] ValidityError),
}

/// Union of two validated layers into `out` (cleared and refilled).
pub fn union_into(
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    combine_into(a, b, out, |in_a, in_b| in_a | in_b)
}

/// Intersection of two validated layers into `out` (cleared and refilled).
pub fn intersection_into(
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    combine_into(a, b, out, |in_a, in_b| in_a & in_b)
}

/// `a` minus `b` into `out` (cleared and refilled).
pub fn subtraction_into(
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    combine_into(a, b, out, |in_a, in_b| in_a & !in_b)
}

// Between two consecutive axis x the occupied set is a constant list of
// y-intervals; a set operation combines those lists slab by slab.

/// Every ring of one operand, flattened; CSR `start`, `ring count + 1` long.
#[derive(Default)]
struct Rings {
    xs: Vec<i64>,
    ys: Vec<i64>,
    start: Vec<u32>,
}

/// One vertical edge: the half-open y-range it spans and the winding it adds to
/// every cut to its right. Horizontal edges contribute nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VEdge {
    x: i64,
    ylo: i64,
    yhi: i64,
    delta: i32,
}

/// One boundary segment of a result region, directed so the interior is on its
/// left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seg {
    sx: i64,
    sy: i64,
    ex: i64,
    ey: i64,
}

/// The occupied y-intervals of every x-slab, CSR. Slab `c` spans `axis[c] ..=
/// axis[c + 1]`; its intervals are ascending, disjoint, half-open in y.
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

    fn slab(&self, c: usize) -> &[(i64, i64)] {
        &self.ivals[self.start[c] as usize..self.start[c + 1] as usize]
    }
}

/// Every buffer the sweep reuses, each cleared where it is filled.
#[derive(Default)]
struct Sweep {
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

/// Flatten every ring of every polygon of one operand. Validated rings are
/// rectilinear already, so nothing is re-checked.
fn collect_rings(layer: &ValidatedLayer, rings: &mut Rings) {
    rings.xs.clear();
    rings.ys.clear();
    rings.start.clear();
    rings.start.push(0);

    let polys = u32::try_from(layer.len()).expect("a layer's polygon count is a u32 index space");
    for idx in 0..polys {
        for ring in layer.poly_rings(idx) {
            let (xs, ys) = ring.coords();
            rings.xs.extend(xs.iter().map(|x| x.raw()));
            rings.ys.extend(ys.iter().map(|y| y.raw()));
            rings.start.push(ring_mark(rings.xs.len()));
        }
    }
}

/// Every vertical edge of one operand, ascending in x; downward `+1`, upward `-1`.
fn vedges_into(rings: &Rings, out: &mut Vec<VEdge>) {
    out.clear();
    out.reserve(rings.xs.len());

    for ring in 0..rings.start.len().saturating_sub(1) {
        let (lo, hi) = (rings.start[ring] as usize, rings.start[ring + 1] as usize);
        let n = hi - lo;
        for i in 0..n {
            let (a, b) = (lo + i, lo + (i + 1) % n);
            if rings.xs[a] != rings.xs[b] {
                continue;
            }
            let (y0, y1) = (rings.ys[a], rings.ys[b]);
            out.push(VEdge {
                x: rings.xs[a],
                ylo: y0.min(y1),
                yhi: y0.max(y1),
                delta: 1 - 2 * i32::from(y1 > y0),
            });
        }
    }

    out.sort_unstable_by_key(|edge| edge.x);
}

/// Merge one cut's winding changes (ascending in y) into the running map,
/// dropping entries that cancel to zero.
fn merge_deltas(base: &[(i64, i32)], add: &[(i64, i32)], out: &mut Vec<(i64, i32)>) {
    out.clear();
    out.reserve(base.len() + add.len());

    let (mut i, mut j) = (0usize, 0usize);
    while i < base.len() || j < add.len() {
        // The sentinel makes the exhausted side lose every compare.
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
}

/// Turn one cut's winding-change map into the occupied y-intervals, appended.
fn intervals_into(ymap: &[(i64, i32)], out: &mut Vec<(i64, i64)>) {
    let mut sum = 0i32;
    let mut open = 0i64;

    for &(y, delta) in ymap {
        let was = sum;
        sum += delta;
        // `ymap` holds no zero delta, so `was == 0` means the sum just left zero.
        if was == 0 {
            open = y;
        } else if sum == 0 {
            out.push((open, y));
        }
    }
}

/// Occupancy of every x-slab, by the nonzero-winding rule. `xs` holds every
/// edge's x and may hold more (a shared axis); [`segments`] merges the extra splits.
fn occupancy(edges: &[VEdge], xs: &[i64], sweep: &mut Sweep, out: &mut Slabs) {
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
        if !sweep.pending.is_empty() {
            sweep.pending.sort_unstable();
            merge_deltas(&sweep.ymap, &sweep.pending, &mut sweep.merged);
            std::mem::swap(&mut sweep.ymap, &mut sweep.merged);
        }
        intervals_into(&sweep.ymap, &mut out.ivals);
        out.close_slab();
    }
}

/// Does an ascending, disjoint interval list cover `y`?
fn covers(ivals: &[(i64, i64)], y: i64) -> bool {
    let after = ivals.partition_point(|&(lo, _)| lo <= y);
    (after > 0) && (ivals[after - 1].1 > y)
}

/// Every endpoint of two interval lists, ascending and deduplicated.
fn endpoints(a: &[(i64, i64)], b: &[(i64, i64)], out: &mut Vec<i64>) {
    out.clear();
    out.reserve(2 * (a.len() + b.len()));
    for &(lo, hi) in a.iter().chain(b) {
        out.push(lo);
        out.push(hi);
    }
    sort_dedup(out);
}

/// Apply a set operation slab by slab; both operands share one axis.
fn combine_slabs(
    lines: usize,
    a: &Slabs,
    b: &Slabs,
    op: impl Fn(bool, bool) -> bool,
    sweep: &mut Sweep,
    out: &mut Slabs,
) {
    let slabs = lines.saturating_sub(1);
    out.open();

    for c in 0..slabs {
        let (left, right) = (a.slab(c), b.slab(c));
        endpoints(left, right, &mut sweep.ends);

        let mut open = false;
        let mut from = 0i64;
        for k in 0..sweep.ends.len() {
            let y = sweep.ends[k];
            // The last endpoint forces every run closed.
            let keep = (k + 1 < sweep.ends.len()) & op(covers(left, y), covers(right, y));
            if keep != open {
                if open {
                    out.ivals.push((from, y));
                }
                from = y;
                open = keep;
            }
        }
        out.close_slab();
    }
}

/// Every boundary segment of a slab list, interior on the left (so outers come
/// out CCW, holes CW), with maximal collinear runs merged into one segment.
fn segments(xs: &[i64], region: &Slabs, sweep: &mut Sweep) {
    let slabs = xs.len().saturating_sub(1);
    sweep.segs.clear();
    sweep.horizontals.clear();

    for (i, &x) in xs.iter().enumerate() {
        let left = if i > 0 { region.slab(i - 1) } else { &[][..] };
        let right = if i < slabs { region.slab(i) } else { &[][..] };
        endpoints(left, right, &mut sweep.ends);

        let mut run = 0i32;
        let mut from = 0i64;
        for k in 0..sweep.ends.len() {
            let y = sweep.ends[k];
            // Left inside: runs up; right inside: runs down; the last endpoint closes.
            let side = i32::from(k + 1 < sweep.ends.len())
                * (i32::from(covers(left, y)) - i32::from(covers(right, y)));
            if side != run {
                push_run(&mut sweep.segs, run, (x, from), (x, y));
                run = side;
                from = y;
            }
        }
    }

    // Horizontals: an interval start runs right, an end runs left. A run
    // continues while the next slab has the same end with the same sense.
    sweep.open.clear();
    for (c, &x) in xs.iter().enumerate() {
        sweep.cur.clear();
        // Past the last slab `cur` stays empty, closing every run.
        if c < slabs {
            for &(lo, hi) in region.slab(c) {
                sweep.cur.push((lo, 1));
                sweep.cur.push((hi, -1));
            }
        }

        sweep.next_open.clear();
        let (mut p, mut q) = (0usize, 0usize);
        while p < sweep.open.len() || q < sweep.cur.len() {
            // Sentinel: the exhausted side loses every compare.
            let ahead = sweep
                .open
                .get(p)
                .map_or((i64::MAX, i32::MAX), |&(y, side, _)| (y, side));
            let here = sweep.cur.get(q).copied().unwrap_or((i64::MAX, i32::MAX));
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

    // Canonical order: verticals by (x, y) off the sweep, horizontals by (y, x).
    sweep
        .horizontals
        .sort_unstable_by_key(|seg| (seg.sy, seg.sx.min(seg.ex)));
    sweep.segs.extend_from_slice(&sweep.horizontals);
}

/// Close one run: `+1` keeps the walk's direction, `-1` reverses it, `0` is no boundary.
fn push_run(segs: &mut Vec<Seg>, run: i32, low: (i64, i64), high: (i64, i64)) {
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

fn dir_of(seg: Seg) -> (i64, i64) {
    ((seg.ex - seg.sx).signum(), (seg.ey - seg.sy).signum())
}

fn head_of(seg: Seg) -> (i64, i64) {
    (seg.sx, seg.sy)
}

fn tail_of(seg: Seg) -> (i64, i64) {
    (seg.ex, seg.ey)
}

/// Which segment continues the walk from each segment's tail: a linear merge of
/// segments ordered by head against the same ordered by tail.
///
/// Vertices have degree two or four. At a degree-four pinch the **left turn** is
/// taken, keeping two cells meeting at a corner as two simple rings; that makes
/// `next` a permutation, so the walk is a cycle decomposition.
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

        let mut tail_end = tail;
        while tail_end < by_end.len() && tail_of(segs[by_end[tail_end] as usize]) == point {
            tail_end += 1;
        }
        let mut head_end = head;
        while head_end < order.len() && head_of(segs[order[head_end] as usize]) == point {
            head_end += 1;
        }

        // Release assert: a dropped segment would trace a polyline that validates
        // as a polygon of the wrong area.
        assert!(
            head < head_end,
            "a boundary segment ends at a point no segment leaves"
        );

        for &arrival in &by_end[tail..tail_end] {
            let (dx, dy) = dir_of(segs[arrival as usize]);
            let want = (-dy, dx);
            // Left turn if present, else the group's first (a degree-two corner).
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
}

/// Walk the successor permutation into closed rings: flat columns plus CSR `start`.
fn link(
    segs: &[Seg],
    next: &[u32],
    xs: &mut Vec<i64>,
    ys: &mut Vec<i64>,
    start: &mut Vec<u32>,
    used: &mut Vec<bool>,
) {
    xs.clear();
    xs.reserve(segs.len());
    ys.clear();
    ys.reserve(segs.len());
    start.clear();
    start.push(0);
    used.clear();
    used.resize(segs.len(), false);

    for seed in 0..segs.len() {
        if used[seed] {
            continue;
        }
        let mut cur = seed;
        loop {
            used[cur] = true;
            xs.push(segs[cur].sx);
            ys.push(segs[cur].sy);

            let step = next[cur] as usize;
            if step == seed {
                break;
            }
            // Release assert: `next` must be a permutation (see `successors_into`).
            assert!(
                !used[step],
                "a region boundary is a union of disjoint closed loops"
            );
            cur = step;
        }
        start.push(ring_mark(xs.len()));
    }

    // Release assert: a segment in no ring is area missing from the result.
    assert_eq!(
        xs.len(),
        segs.len(),
        "every boundary segment lands in exactly one ring"
    );
}

/// Segments, successors, and link: the region's rings into `sweep.link_*`.
fn trace(xs: &[i64], region: &Slabs, sweep: &mut Sweep) {
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
}

/// Trace the region and validate its rings into `out`, through a one-layer store
/// so hole binding is `view`'s single implementation.
fn emit(
    xs: &[i64],
    region: &Slabs,
    sweep: &mut Sweep,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    trace(xs, region, sweep);

    let ring_count = sweep.link_start.len() - 1;
    let mut builder = GeometryStoreBuilder::with_capacity(ring_count, sweep.link_x.len());
    for ring in 0..ring_count {
        let (lo, hi) = (
            sweep.link_start[ring] as usize,
            sweep.link_start[ring + 1] as usize,
        );
        // Copies of in-domain operand coordinates, or clamped offsets of them.
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
    collect_rings(a, &mut ra);
    collect_rings(b, &mut rb);

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

/// The canonical rings of one raw rectilinear GDS ring: outers CCW, holes CW.
///
/// GDSII writes a polygon with holes as one weakly simple *keyhole* ring, which
/// [`validate_layer_into`] refuses as self-intersecting. Retracing it through the
/// sweep cancels the slit and yields the outer and holes, for any number of holes.
/// Raw `i64` file coordinates; asserted inside `±MAX_ABS_DBU`.
pub fn canonical_rings_into(
    xs: &[i64],
    ys: &[i64],
    out_xs: &mut Vec<i64>,
    out_ys: &mut Vec<i64>,
    out_start: &mut Vec<u32>,
) -> Result<(), BooleanError> {
    assert_eq!(xs.len(), ys.len(), "a ring's two columns are parallel");
    assert!(
        xs.iter()
            .chain(ys)
            .all(|&c| c.unsigned_abs() <= MAX_ABS_DBU.unsigned_abs()),
        "a coordinate is outside the domain the sweep clamps against"
    );

    let n = xs.len();
    // An edge (the closing one included) with both deltas non-zero is skew.
    let skew = (0..n.saturating_sub(1)).fold(false, |acc, i| {
        acc | ((xs[i] != xs[i + 1]) & (ys[i] != ys[i + 1]))
    });
    let wrap = n > 1 && (xs[n - 1] != xs[0]) && (ys[n - 1] != ys[0]);
    if skew | wrap {
        return Err(BooleanError::NotRectilinear);
    }

    let mut rings = Rings::default();
    rings.start.push(0);
    rings.xs.extend_from_slice(xs);
    rings.ys.extend_from_slice(ys);
    rings.start.push(ring_mark(rings.xs.len()));

    let mut sweep = Sweep::default();
    let mut edges = Vec::new();
    vedges_into(&rings, &mut edges);

    let mut axis = Vec::new();
    axis_into(&edges, &mut axis);

    let mut region = Slabs::default();
    occupancy(&edges, &axis, &mut sweep, &mut region);
    trace(&axis, &region, &mut sweep);

    out_xs.clear();
    out_ys.clear();
    out_start.clear();
    out_xs.extend_from_slice(&sweep.link_x);
    out_ys.extend_from_slice(&sweep.link_y);
    out_start.extend_from_slice(&sweep.link_start);
    Ok(())
}

/// The layer of the one-layer store `emit` builds; never leaves this module.
const RESULT_LAYER: LayerId = LayerId(0);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DbuArea;

    /// Area of a result layer, read from its own rings.
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

    /// `DbuArea` is the tree's area type and this module's own laws are stated
    /// over it; a rectilinear region's doubled area is even.
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

    /// Oracle: closed form — a keyhole ring denotes an outer minus its hole.
    ///
    /// The input is the ring KLayout writes for a 1000x1000 square with a
    /// 400x400 hole: one weakly simple loop that runs in to the hole along
    /// `y = 700` and back out along the same line. `validate_layer_into`
    /// refuses it, so a reader that passed it through refused every layer it
    /// appeared on. Decomposed, it is two rings whose signed areas sum to the
    /// area the shape has.
    #[test]
    fn a_keyhole_ring_decomposes_into_its_outer_and_its_hole() {
        // Written in the order KLayout emits, closing point already dropped.
        let xs = [0, 0, 300, 300, 700, 700, 0, 0, 1000, 1000];
        let ys = [0, 700, 700, 300, 300, 700, 700, 1000, 1000, 0];

        let (mut rx, mut ry, mut start) = (Vec::new(), Vec::new(), Vec::new());
        canonical_rings_into(&xs, &ys, &mut rx, &mut ry, &mut start)
            .expect("a keyhole is rectilinear");

        assert_eq!(start.len() - 1, 2, "one outer and one hole");

        let mut signed = Vec::new();
        for ring in 0..start.len() - 1 {
            let (lo, hi) = (start[ring] as usize, start[ring + 1] as usize);
            let n = hi - lo;
            let mut area2 = 0i128;
            for i in 0..n {
                let (a, b) = (lo + i, lo + (i + 1) % n);
                area2 +=
                    i128::from(rx[a]) * i128::from(ry[b]) - i128::from(rx[b]) * i128::from(ry[a]);
            }
            signed.push(area2 / 2);
        }
        signed.sort_unstable();

        assert_eq!(
            signed,
            vec![-400 * 400, 1000 * 1000],
            "the hole comes back clockwise and the outer counter-clockwise, so \
             their signed areas carry opposite sign"
        );
        assert_eq!(
            signed.iter().sum::<i128>(),
            1000 * 1000 - 400 * 400,
            "outer minus hole is the area the keyhole denotes"
        );
    }

    /// A ring that is already simple survives decomposition unchanged in area
    /// and in ring count, so a reader may run every boundary through this
    /// without inventing geometry.
    #[test]
    fn a_simple_ring_decomposes_to_itself() {
        let xs = [0, 400, 400, 0];
        let ys = [0, 0, 400, 400];

        let (mut rx, mut ry, mut start) = (Vec::new(), Vec::new(), Vec::new());
        canonical_rings_into(&xs, &ys, &mut rx, &mut ry, &mut start).expect("a square");

        assert_eq!(start.len() - 1, 1, "a square is one ring");
        assert_eq!(rx.len(), 4, "and it keeps its four corners");

        let n = rx.len();
        let mut area2 = 0i128;
        for i in 0..n {
            let j = (i + 1) % n;
            area2 += i128::from(rx[i]) * i128::from(ry[j]) - i128::from(rx[j]) * i128::from(ry[i]);
        }
        assert_eq!(area2 / 2, 400 * 400, "and its area, counter-clockwise");
    }
}
