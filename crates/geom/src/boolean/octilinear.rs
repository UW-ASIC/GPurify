//! The boolean sweep for octilinear operands: every edge horizontal, vertical
//! or at 45 degrees.
//!
//! Data in: rings at doubled scale (every coordinate times two), so the point
//! where two octilinear edges cross is always an integer. Data out: the
//! result's rings at doubled scale, outer counter-clockwise, holes clockwise,
//! in the connected corner model ([`super::union_into`]); [`snap_into`] then
//! moves a vertex that lies between grid points onto the grid.
//!
//! The sweep cuts the plane into vertical slabs at every vertex and every
//! crossing, so inside a slab no two edges cross and each operand's winding
//! number is constant between consecutive edges. A slab's result boundary is
//! the edges where the set operation's answer changes; the vertical boundary
//! is where the answers of two neighbouring slabs differ along their shared
//! line. Every coordinate the sweep forms is an integer combination of the
//! input's, so it is exact.

use core::cmp::Ordering;

use super::Rings;
use crate::ops::angle_cmp;

/// One non-vertical edge of an operand, its left end first.
#[derive(Debug, Clone, Copy)]
struct Edge {
    x0: i64,
    y0: i64,
    x1: i64,
    /// Rise per unit of x: -1, 0 or 1.
    slope: i64,
    /// `+1` where the ring runs toward `+x` along it (material above it),
    /// `-1` where it runs toward `-x`.
    wind: i32,
    /// `false` for the left operand, `true` for the right.
    right: bool,
}

impl Edge {
    const fn y_at(self, x: i64) -> i64 {
        self.y0 + self.slope * (x - self.x0)
    }
}

/// One boundary segment of the result, directed with its material on the left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Seg {
    pub(super) sx: i64,
    pub(super) sy: i64,
    pub(super) ex: i64,
    pub(super) ey: i64,
}

impl Seg {
    const fn head(self) -> (i64, i64) {
        (self.sx, self.sy)
    }

    const fn tail(self) -> (i64, i64) {
        (self.ex, self.ey)
    }

    /// Whether `other` runs the same way as `self`: parallel, not opposite.
    /// Exact at any angle; on the octilinear grid, equal unit steps.
    fn same_way(self, other: Self) -> bool {
        let (ax, ay) = (i128::from(self.ex - self.sx), i128::from(self.ey - self.sy));
        let (bx, by) = (
            i128::from(other.ex - other.sx),
            i128::from(other.ey - other.sy),
        );
        ax * by == ay * bx && ax * bx + ay * by > 0
    }
}

/// Every non-vertical edge of one operand, appended.
///
/// # Panics
///
/// On an edge that is not octilinear: its crossings would not be integers.
fn edges_into(rings: &Rings, right: bool, out: &mut Vec<Edge>) {
    for ring in 0..rings.start.len().saturating_sub(1) {
        let (lo, hi) = (rings.start[ring] as usize, rings.start[ring + 1] as usize);
        let n = hi - lo;
        for i in 0..n {
            let (a, b) = (lo + i, lo + (i + 1) % n);
            let (xa, ya, xb, yb) = (rings.xs[a], rings.ys[a], rings.xs[b], rings.ys[b]);
            if xa == xb {
                continue;
            }
            let (dx, dy) = (xb - xa, yb - ya);
            // Release assert: a skew edge would cross others between grid points.
            assert!(
                dy == 0 || dy.abs() == dx.abs(),
                "the octilinear sweep was given an edge at another angle"
            );
            let (x0, y0, x1) = if xa < xb { (xa, ya, xb) } else { (xb, yb, xa) };
            out.push(Edge {
                x0,
                y0,
                x1,
                slope: dy.signum() * dx.signum(),
                wind: if xb > xa { 1 } else { -1 },
                right,
            });
        }
    }
}

/// The order of two edges just right of `x`: by height at `x`, then by slope.
fn order_at(edges: &[Edge], x: i64, p: u32, q: u32) -> Ordering {
    let (e, f) = (edges[p as usize], edges[q as usize]);
    (e.y_at(x), e.slope).cmp(&(f.y_at(x), f.slope))
}

/// The boundary pieces on the vertical line `x`: where the answer just left of
/// it (`left`, the heights at which the slab ending at `x` changes answer)
/// differs from the answer just right of it (`right`, likewise for the slab
/// starting there). Material on the left of a piece: up where the left side
/// is inside. One piece per gap between consecutive heights, so a piece never
/// passes a point where another boundary segment ends.
fn verticals(x: i64, left: &[i64], right: &[i64], segs: &mut Vec<Seg>) {
    let (mut i, mut j) = (0usize, 0usize);
    let (mut left_in, mut right_in) = (false, false);
    let height = |list: &[i64], k: usize| list.get(k).copied().unwrap_or(i64::MAX);
    while i < left.len() || j < right.len() {
        let y = height(left, i).min(height(right, j));
        while i < left.len() && left[i] == y {
            left_in = !left_in;
            i += 1;
        }
        while j < right.len() && right[j] == y {
            right_in = !right_in;
            j += 1;
        }
        if left_in != right_in {
            // Both sides are outside above their last height, so one follows.
            let above = height(left, i).min(height(right, j));
            let (from, to) = if left_in { (y, above) } else { (above, y) };
            segs.push(Seg {
                sx: x,
                sy: from,
                ex: x,
                ey: to,
            });
        }
    }
}

/// The rings of `op(a, b)` into `out` (cleared and refilled), all at the
/// doubled scale the operands are given at.
///
/// `op` answers "is this point in the result" from "is it in `a`" and "is it
/// in `b`" (a nonzero winding number), and must answer `false` for neither.
///
/// Cost: `O(s · k)` for `s` slabs (vertices plus crossings) and `k` edges
/// crossing a slab, as the rectilinear sweep's.
pub(super) fn combine_into(a: &Rings, b: &Rings, op: impl Fn(bool, bool) -> bool, out: &mut Rings) {
    let mut edges = Vec::new();
    edges_into(a, false, &mut edges);
    edges_into(b, true, &mut edges);
    edges.sort_by_key(|e| e.x0);

    let mut xs: Vec<i64> = a.xs.iter().chain(&b.xs).copied().collect();
    xs.sort_unstable();
    xs.dedup();

    let mut segs: Vec<Seg> = Vec::new();
    let mut active: Vec<u32> = Vec::new();
    // Heights at `x` where the slab ending there changes answer.
    let mut left: Vec<i64> = Vec::new();
    let (mut starts, mut ends) = (Vec::new(), Vec::new());
    let (mut next_edge, mut next_vertex) = (0usize, 0usize);
    let mut x = xs.first().copied().unwrap_or(0);

    while !xs.is_empty() {
        while next_vertex < xs.len() && xs[next_vertex] <= x {
            next_vertex += 1;
        }
        active.retain(|&e| edges[e as usize].x1 > x);
        while next_edge < edges.len() && edges[next_edge].x0 <= x {
            active.push(u32::try_from(next_edge).expect("a layer's edges fit a u32"));
            next_edge += 1;
        }
        // Stable and adaptive: the order only changes where edges cross at `x`.
        active.sort_by(|&p, &q| order_at(&edges, x, p, q));

        let Some(&vertex) = xs.get(next_vertex) else {
            // Past the last vertex every edge has ended.
            debug_assert!(active.is_empty(), "an edge runs past the last vertex");
            verticals(x, &left, &[], &mut segs);
            break;
        };
        // The slab runs to the next vertex or the nearest crossing of two
        // neighbours, whichever is first; neighbours cross first (the
        // Bentley-Ottmann lemma), so no two edges cross inside it.
        let mut next = vertex;
        for pair in active.windows(2) {
            let (e, f) = (edges[pair[0] as usize], edges[pair[1] as usize]);
            if e.slope > f.slope {
                let (gap, rate) = (f.y_at(x) - e.y_at(x), e.slope - f.slope);
                debug_assert!(gap > 0 && gap % rate == 0, "crossings are integers");
                next = next.min(x + gap / rate);
            }
        }

        starts.clear();
        ends.clear();
        let (mut in_a, mut in_b) = (0i32, 0i32);
        let mut inside = false;
        let mut k = 0usize;
        while k < active.len() {
            let head = edges[active[k] as usize];
            let (y, slope) = (head.y_at(x), head.slope);
            // Edges on one line through this slab are one boundary candidate.
            while k < active.len() {
                let e = edges[active[k] as usize];
                if e.y_at(x) != y || e.slope != slope {
                    break;
                }
                if e.right {
                    in_b += e.wind;
                } else {
                    in_a += e.wind;
                }
                k += 1;
            }
            let above = op(in_a != 0, in_b != 0);
            if above != inside {
                let y_end = head.y_at(next);
                // Material above: run toward +x; below: toward -x.
                segs.push(if above {
                    Seg {
                        sx: x,
                        sy: y,
                        ex: next,
                        ey: y_end,
                    }
                } else {
                    Seg {
                        sx: next,
                        sy: y_end,
                        ex: x,
                        ey: y,
                    }
                });
                starts.push(y);
                ends.push(y_end);
                inside = above;
            }
        }
        debug_assert!(!inside, "every operand's winding returns to zero above it");

        verticals(x, &left, &starts, &mut segs);
        std::mem::swap(&mut left, &mut ends);
        x = next;
    }

    link(&segs, out);
}

/// Walk the boundary segments into rings, flat into `out` (cleared and
/// refilled): CSR `start`, one longer than the ring count.
///
/// At a point where more than one segment arrives, each arrival continues
/// along the departure next counter-clockwise from the way it came in: the
/// one across the empty sector to its right. So a ring keeps every empty
/// sector at a point apart and joins the material sectors there, which is the
/// connected corner model at any angle (in rectilinear terms, the right turn
/// at a pinch). A run of collinear segments through a point no other segment
/// visits is one edge. Reads segments at any angle.
pub(super) fn link(segs: &[Seg], out: &mut Rings) {
    let count = segs.len();
    let index = |i: usize| u32::try_from(i).expect("a boundary has under 2^32 segments");
    let mut by_head: Vec<u32> = (0..count).map(index).collect();
    let mut by_tail = by_head.clone();
    by_head.sort_unstable_by_key(|&i| segs[i as usize].head());
    by_tail.sort_unstable_by_key(|&i| segs[i as usize].tail());

    let mut next = vec![u32::MAX; count];
    // Whether a segment's tail is reached by no other segment.
    let mut alone = vec![true; count];
    let mut rays: Vec<((i64, i64), bool, u32)> = Vec::new();
    let (mut h, mut t) = (0usize, 0usize);
    while t < count {
        let point = segs[by_tail[t] as usize].tail();
        let mut t_end = t;
        while t_end < count && segs[by_tail[t_end] as usize].tail() == point {
            t_end += 1;
        }
        let mut h_end = h;
        while h_end < count && segs[by_head[h_end] as usize].head() == point {
            h_end += 1;
        }
        // Release assert: a dropped segment would trace a ring of the wrong area.
        assert!(
            h_end - h == t_end - t,
            "a boundary point has as many segments in as out"
        );
        if t_end - t == 1 {
            next[by_tail[t] as usize] = by_head[h];
        } else {
            rays.clear();
            for &s in &by_tail[t..t_end] {
                let seg = segs[s as usize];
                rays.push(((seg.sx - seg.ex, seg.sy - seg.ey), false, s));
                alone[s as usize] = false;
            }
            for &s in &by_head[h..h_end] {
                let seg = segs[s as usize];
                rays.push(((seg.ex - seg.sx, seg.ey - seg.sy), true, s));
            }
            rays.sort_by(|p, q| angle_cmp(p.0, q.0));
            for k in 0..rays.len() {
                let (_, out_ray, s) = rays[k];
                if !out_ray {
                    let (_, leaves, d) = rays[(k + 1) % rays.len()];
                    assert!(
                        leaves,
                        "a region's boundary alternates in and out round a point"
                    );
                    next[s as usize] = d;
                }
            }
        }
        h = h_end;
        t = t_end;
    }

    out.xs.clear();
    out.ys.clear();
    out.start.clear();
    out.start.push(0);
    let mut used = vec![false; count];
    let mut cycle: Vec<u32> = Vec::new();
    for seed in 0..count {
        if used[seed] {
            continue;
        }
        cycle.clear();
        let mut cur = seed;
        loop {
            used[cur] = true;
            cycle.push(index(cur));
            cur = next[cur] as usize;
            if cur == seed {
                break;
            }
            // Release assert: `next` must be a permutation.
            assert!(!used[cur], "a region boundary is a union of disjoint loops");
        }
        let len = cycle.len();
        for (k, &s) in cycle.iter().enumerate() {
            let before = cycle[(k + len - 1) % len] as usize;
            let seg = segs[s as usize];
            if !(alone[before] && segs[before].same_way(seg)) {
                out.xs.push(seg.sx);
                out.ys.push(seg.sy);
            }
        }
        out.start
            .push(u32::try_from(out.xs.len()).expect("a layer's vertices fit a u32"));
    }
}

/// Whether some vertex lies between grid points: an odd doubled coordinate.
pub(super) fn off_grid(rings: &Rings) -> bool {
    rings.xs.iter().chain(&rings.ys).any(|&c| c % 2 != 0)
}

/// Every ring with each vertex that lies between grid points snapped onto the
/// grid, into `out` (cleared and refilled), at doubled scale.
///
/// Such a vertex is where a rising and a falling 45-degree edge meet, at a
/// half-grid point `(i + ½, j + ½)`. It is replaced by the two grid points half
/// a diagonal step from it, back along its way in and on along its way out,
/// joined by a unit horizontal or vertical edge: the tip of the right angle
/// between its two edges is cut off. That is a convex corner losing a
/// quarter-unit triangle, a concave one gaining one, and a pinch of the
/// connected model becoming a neck one unit wide. Every edge stays octilinear.
/// The rings may then hold a slit or a vanished sliver, which a pass through
/// [`combine_into`] removes.
pub(super) fn snap_into(rings: &Rings, out: &mut Rings) {
    out.xs.clear();
    out.ys.clear();
    out.start.clear();
    out.start.push(0);
    for ring in 0..rings.start.len().saturating_sub(1) {
        let (lo, hi) = (rings.start[ring] as usize, rings.start[ring + 1] as usize);
        let n = hi - lo;
        for i in 0..n {
            let at = lo + i;
            let (x, y) = (rings.xs[at], rings.ys[at]);
            if x % 2 == 0 {
                debug_assert!(
                    y % 2 == 0,
                    "a crossing is on the grid or at a half-grid point"
                );
                out.xs.push(x);
                out.ys.push(y);
                continue;
            }
            let (back, on) = (lo + (i + n - 1) % n, lo + (i + 1) % n);
            let way_in = ((x - rings.xs[back]).signum(), (y - rings.ys[back]).signum());
            let way_out = ((rings.xs[on] - x).signum(), (rings.ys[on] - y).signum());
            // Release assert: only two diagonals pass a half-grid point.
            assert!(
                way_in.0 != 0 && way_in.1 != 0 && way_out.0 != 0 && way_out.1 != 0,
                "an off-grid vertex joins two diagonal edges"
            );
            out.xs.extend([x - way_in.0, x + way_out.0]);
            out.ys.extend([y - way_in.1, y + way_out.1]);
        }
        out.start
            .push(u32::try_from(out.xs.len()).expect("a layer's vertices fit a u32"));
    }
}
