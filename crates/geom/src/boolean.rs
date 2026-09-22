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

/// Grow (`amount > 0`) or shrink (`amount < 0`) by an exact L-infinity square
/// kernel, which keeps rectilinear input rectilinear.
pub fn offset_into(
    a: &ValidatedLayer,
    amount: crate::Dbu,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    let amt = amount.raw();
    let mut sweep = Sweep::default();
    let mut rings = Rings::default();
    collect_rings(a, &mut rings);

    let mut edges = Vec::new();
    vedges_into(&rings, &mut edges);
    let mut xs = Vec::new();
    axis_into(&edges, &mut xs);

    let mut region = Slabs::default();
    occupancy(&edges, &xs, &mut sweep, &mut region);

    // An empty operand has no slab and emits nothing.
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

    // Erosion = complement of the dilated complement, over the operand's box grown
    // by `|amt| + 1` (anything farther cannot reach the operand).
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
fn difference_over(axis: &[i64], p: &[VEdge], q: &[VEdge], sweep: &mut Sweep, out: &mut Slabs) {
    let mut sp = Slabs::default();
    let mut sq = Slabs::default();
    occupancy(p, axis, sweep, &mut sp);
    occupancy(q, axis, sweep, &mut sq);
    combine_slabs(axis.len(), &sp, &sq, |in_p, in_q| in_p & !in_q, sweep, out);
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

    fn count(&self) -> usize {
        self.start.len().saturating_sub(1)
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

/// Clamp a shape [`offset_into`] grew past `±MAX_ABS_DBU` to the domain edge.
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

/// Every vertical edge of a region dilated by an L-infinity square: each slab
/// rectangle grown by `amount` on all sides (dilation distributes over union).
fn grown_edges_into(xs: &[i64], region: &Slabs, amount: i64, out: &mut Vec<VEdge>) {
    out.clear();
    out.reserve(2 * region.ivals.len());

    for c in 0..region.count() {
        let x0 = clamp_dbu(xs[c] - amount);
        let x1 = clamp_dbu(xs[c + 1] + amount);
        for &(lo, hi) in region.slab(c) {
            let ylo = clamp_dbu(lo - amount);
            let yhi = clamp_dbu(hi + amount);
            // CCW rectangle: winding +1 inside, so overlaps union.
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
/// Raw `i64` file coordinates; asserted inside `±MAX_ABS_DBU`, since the sweep clamps.
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
    use crate::store::GeometryStore;
    use crate::DbuArea;

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

    /// An L-infinity offset of a square by `r` is a square of side `2 * (half +
    /// r)`, for either sign of `r`. Nothing else in the tree exercises a
    /// non-zero offset, because a grown result's coordinates exist in no store
    /// row and the integration tests read results through one.
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

    /// A shrink by more than the half-width leaves nothing, and "nothing" has
    /// to be an empty layer rather than a layer of empty polygons — an empty
    /// clean result and a result that was never computed have to stay
    /// distinguishable.
    #[test]
    fn shrinking_past_the_half_width_leaves_nothing() {
        let (_store, a) = square(100);
        let mut out = ValidatedLayer::default();
        offset_into(&a, Dbu::new_unchecked(-100), &mut out).expect("a square is rectilinear");
        assert!(out.is_empty(), "a square shrunk to nothing kept polygons");
        assert_eq!(area(&out), 0);
    }

    /// An L is the union of two bars, so growing it is the union of the two
    /// grown bars, and eroding it is the L inset by the same amount — the
    /// reflex corner is the one place a square kernel and a round one would
    /// disagree, and the one this module's erosion is derived rather than
    /// written.
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

    /// Growing distributes over union, so growing two squares far enough apart
    /// to stay apart is two grown squares, and growing them until they touch is
    /// one.
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
                area2 += i128::from(rx[a]) * i128::from(ry[b])
                    - i128::from(rx[b]) * i128::from(ry[a]);
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
