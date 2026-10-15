//! The boolean sweep for operands with an edge at any angle, by snap rounding.
//!
//! Data in: rings on the grid, edges at any angle. Data out: the result's
//! rings on the grid, outer counter-clockwise, holes clockwise, in the
//! connected corner model ([`super::union_into`]).
//!
//! Two edges at arbitrary angles cross at a rational point, which the result
//! cannot keep. [`snap_round`] rounds every crossing to its nearest grid point
//! and bends every edge passing that point's pixel through it (snap rounding:
//! J. D. Hobby, "Practical segment intersection with finite precision output",
//! Computational Geometry 13 (1999) 199-214; L. Guibas and D. Marimont,
//! "Rounding arrangements dynamically", IJCGA 8 (1998) 157-176), so the
//! rounded edges meet only at grid points and no crossing is created. An edge
//! that no rounded crossing bends keeps its shape: a vertex near it becomes a
//! point it passes through only once the edge is bent anyway, as `KLayout`'s
//! edge processor makes such a vertex a weak attractor (`dbEdgeProcessor.cc`,
//! `is_point_on_fuzzy`, `add_attractor`). The rounded edges form a planar
//! graph, and a sweep reads each operand's winding number on both sides of
//! every edge of it; the result's boundary is where the set operation's
//! answer changes.
//!
//! Every predicate is exact integer arithmetic in `i128` over the whole
//! coordinate domain (`±2^40`).

use core::cmp::Ordering;

use super::octilinear::{link, Seg};
use super::Rings;

type P = (i64, i64);

/// One directed ring edge and the operand it came from.
#[derive(Debug, Clone, Copy)]
struct Edge {
    a: P,
    b: P,
    right: bool,
}

/// One edge of the rounded arrangement, `p < q` (by x, then y), with each
/// operand's winding contribution: `+1` per ring edge running from `p` to
/// `q`, `-1` per one running back.
#[derive(Debug, Clone, Copy)]
struct Frag {
    p: P,
    q: P,
    wind: [i32; 2],
}

fn cross(o: P, a: P, b: P) -> i128 {
    let (ax, ay) = (i128::from(a.0 - o.0), i128::from(a.1 - o.1));
    let (bx, by) = (i128::from(b.0 - o.0), i128::from(b.1 - o.1));
    ax * by - ay * bx
}

/// `n / d` rounded to the nearest integer, a half away from zero, as `KLayout`
/// rounds a coordinate (`coord_traits::rounded`).
fn round_div(n: i128, d: i128) -> i64 {
    let (n, d) = if d < 0 { (-n, -d) } else { (n, d) };
    let q = (2 * n.abs() + d) / (2 * d);
    i64::try_from(if n < 0 { -q } else { q }).expect("a crossing lies in the domain")
}

/// Where two edges cross at a point inside both, rounded to the grid; `None`
/// when they do not, or only touch (an end on the other, or a shared stretch).
fn crossing(s: Edge, e: Edge) -> Option<P> {
    let (d1, d2) = (cross(e.a, e.b, s.a).signum(), cross(e.a, e.b, s.b).signum());
    let (d3, d4) = (cross(s.a, s.b, e.a).signum(), cross(s.a, s.b, e.b).signum());
    if d1 * d2 >= 0 || d3 * d4 >= 0 {
        return None;
    }
    let (dx, dy) = (i128::from(s.b.0 - s.a.0), i128::from(s.b.1 - s.a.1));
    let (fx, fy) = (i128::from(e.b.0 - e.a.0), i128::from(e.b.1 - e.a.1));
    let (wx, wy) = (i128::from(e.a.0 - s.a.0), i128::from(e.a.1 - s.a.1));
    // s.a + t·d on e: t = (w × f) / (d × f), both under 2^84 in magnitude.
    let den = dx * fy - dy * fx;
    let num = wx * fy - wy * fx;
    Some((
        round_div(i128::from(s.a.0) * den + dx * num, den),
        round_div(i128::from(s.a.1) * den + dy * num, den),
    ))
}

/// A bound on the parameter `t` along an edge: `num / den` (`den > 0`), and
/// whether `t` may equal it.
#[derive(Debug, Clone, Copy)]
struct Bound {
    num: i128,
    den: i128,
    closed: bool,
}

impl Bound {
    fn cmp(self, o: Self) -> Ordering {
        (self.num * o.den).cmp(&(o.num * self.den))
    }
}

/// The parameters at which the edge `a`-`b` lies in the pixel of the grid
/// point `h`, as a lower and an upper bound, or `None` when it misses it.
///
/// The pixel of `h` is the set of points that round to it (half away from
/// zero): `[c - ½, c + ½)` across each axis for a coordinate `c > 0`, `(c -
/// ½, c + ½]` for `c < 0`, `(-½, ½)` for `c = 0`, so the pixels tile the plane
/// and are symmetric under the grid's eight symmetries.
fn pixel_span(a: P, b: P, h: P) -> Option<(Bound, Bound)> {
    let mut lo = Bound {
        num: 0,
        den: 1,
        closed: true,
    };
    let mut hi = Bound {
        num: 1,
        den: 1,
        closed: true,
    };
    for (from, to, c) in [(a.0, b.0, h.0), (a.1, b.1, h.1)] {
        // Doubled: the pixel spans 2c - 1 .. 2c + 1.
        let (low, high) = (i128::from(2 * c - 1), i128::from(2 * c + 1));
        let (low_closed, high_closed) = (c > 0, c < 0);
        let (start, delta) = (i128::from(2 * from), i128::from(2 * (to - from)));
        if delta == 0 {
            let above = start > low || (start == low && low_closed);
            let below = start < high || (start == high && high_closed);
            if !(above && below) {
                return None;
            }
            continue;
        }
        let at = |edge: i128, closed: bool| {
            let (num, den) = (edge - start, delta);
            if den < 0 {
                Bound {
                    num: -num,
                    den: -den,
                    closed,
                }
            } else {
                Bound { num, den, closed }
            }
        };
        let (enter, leave) = if delta > 0 {
            (at(low, low_closed), at(high, high_closed))
        } else {
            (at(high, high_closed), at(low, low_closed))
        };
        lo = match enter.cmp(lo) {
            Ordering::Greater => enter,
            Ordering::Equal => Bound {
                closed: lo.closed && enter.closed,
                ..lo
            },
            Ordering::Less => lo,
        };
        hi = match leave.cmp(hi) {
            Ordering::Less => leave,
            Ordering::Equal => Bound {
                closed: hi.closed && leave.closed,
                ..hi
            },
            Ordering::Greater => hi,
        };
    }
    match lo.cmp(hi) {
        Ordering::Less => Some((lo, hi)),
        Ordering::Equal if lo.closed && hi.closed => Some((lo, hi)),
        _ => None,
    }
}

/// Whether the grid point `h` lies on the closed segment `a`-`b`.
fn on_segment(a: P, b: P, h: P) -> bool {
    cross(a, b, h) == 0
        && (a.0.min(b.0)..=a.0.max(b.0)).contains(&h.0)
        && (a.1.min(b.1)..=a.1.max(b.1)).contains(&h.1)
}

/// A point that may route edges: an edge end, a rounded crossing, or both.
#[derive(Debug, Clone, Copy)]
struct Hot {
    at: P,
    /// Every edge whose pixel span holds it is bent through it; otherwise
    /// only one it lies on exactly is cut there.
    hot: bool,
}

/// The candidate points in the box `[x0, x1] x [y0, y1]`, from `points`
/// sorted by coordinate.
fn in_box(points: &[Hot], x0: i64, x1: i64, y0: i64, y1: i64) -> impl Iterator<Item = usize> + '_ {
    let from = points.partition_point(|h| h.at.0 < x0);
    let to = points.partition_point(|h| h.at.0 <= x1);
    (from..to).filter(move |&i| (y0..=y1).contains(&points[i].at.1))
}

fn edge_box(e: Edge) -> (i64, i64, i64, i64) {
    (
        e.a.0.min(e.b.0),
        e.a.0.max(e.b.0),
        e.a.1.min(e.b.1),
        e.a.1.max(e.b.1),
    )
}

/// The snap-rounded arrangement of every operand edge: each edge cut at, or
/// bent through, the grid points described in the module doc, as fragments
/// meeting only at their ends; coincident fragments are one, their windings
/// summed, and one whose windings cancel is dropped.
///
/// Which points route an edge: a rounded crossing (hot) bends every edge
/// whose pixel span holds it; an edge end bends an edge already bent whose
/// pixel span holds it, which makes it hot in turn, to a fixed point; and a
/// point lying exactly on an edge cuts it without moving it.
// ponytail: candidate points by an x-sorted scan and edge pairs by x-overlap,
// O(n²) when every edge spans one column; a grid of buckets if large curved
// layers make this slow.
fn snap_round(edges: &[Edge]) -> Vec<Frag> {
    let mut points: Vec<Hot> = Vec::with_capacity(2 * edges.len());
    for e in edges {
        points.push(Hot {
            at: e.a,
            hot: false,
        });
    }
    let mut order: Vec<usize> = (0..edges.len()).collect();
    order.sort_unstable_by_key(|&i| edge_box(edges[i]).0);
    for (k, &i) in order.iter().enumerate() {
        let xmax = edge_box(edges[i]).1;
        for &j in &order[k + 1..] {
            if edge_box(edges[j]).0 > xmax {
                break;
            }
            if let Some(at) = crossing(edges[i], edges[j]) {
                points.push(Hot { at, hot: true });
            }
        }
    }
    points.sort_unstable_by_key(|h| (h.at, !h.hot));
    points.dedup_by(|later, kept| later.at == kept.at);

    // Bent edges attract the edge ends in their pixel spans, which bend
    // other edges in turn.
    let mut bent = vec![false; edges.len()];
    loop {
        for (i, &e) in edges.iter().enumerate() {
            let (x0, x1, y0, y1) = edge_box(e);
            bent[i] = in_box(&points, x0, x1, y0, y1).any(|k| {
                let h = points[k];
                h.hot && !on_segment(e.a, e.b, h.at) && pixel_span(e.a, e.b, h.at).is_some()
            });
        }
        let mut grew = false;
        for (i, &e) in edges.iter().enumerate() {
            if !bent[i] {
                continue;
            }
            let (x0, x1, y0, y1) = edge_box(e);
            let attracted: Vec<usize> = in_box(&points, x0, x1, y0, y1)
                .filter(|&k| !points[k].hot && pixel_span(e.a, e.b, points[k].at).is_some())
                .collect();
            for k in attracted {
                points[k].hot = true;
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }

    let mut frags: Vec<Frag> = Vec::new();
    let mut route: Vec<(Bound, P)> = Vec::new();
    for e in edges {
        let (x0, x1, y0, y1) = edge_box(*e);
        route.clear();
        for k in in_box(&points, x0, x1, y0, y1) {
            let h = points[k];
            if h.hot || on_segment(e.a, e.b, h.at) {
                if let Some((enter, _)) = pixel_span(e.a, e.b, h.at) {
                    route.push((enter, h.at));
                }
            }
        }
        // Pixels are disjoint, so an edge enters them in a strict order; a
        // closed entry comes before an open one at the same parameter.
        route.sort_by(|p, q| p.0.cmp(q.0).then(q.0.closed.cmp(&p.0.closed)));
        let w = usize::from(e.right);
        for pair in route.windows(2) {
            let (from, to) = (pair[0].1, pair[1].1);
            debug_assert_ne!(from, to, "pixels are disjoint");
            let mut wind = [0i32; 2];
            wind[w] = if from < to { 1 } else { -1 };
            let (p, q) = if from < to { (from, to) } else { (to, from) };
            frags.push(Frag { p, q, wind });
        }
    }

    // A fragment end exactly inside another fragment cuts it, so fragments
    // meet only at their ends and coincide whole or not at all.
    let mut ends: Vec<P> = frags.iter().flat_map(|f| [f.p, f.q]).collect();
    ends.sort_unstable();
    ends.dedup();
    let mut cut: Vec<Frag> = Vec::with_capacity(frags.len());
    let mut stops: Vec<P> = Vec::new();
    for f in &frags {
        let (x0, x1) = (f.p.0, f.q.0);
        let (y0, y1) = (f.p.1.min(f.q.1), f.p.1.max(f.q.1));
        stops.clear();
        let from = ends.partition_point(|v| v.0 < x0);
        let to = ends.partition_point(|v| v.0 <= x1);
        stops.extend(
            ends[from..to]
                .iter()
                .copied()
                .filter(|&v| (y0..=y1).contains(&v.1) && on_segment(f.p, f.q, v)),
        );
        // `p < q` by (x, y), and so is every point between them on the segment.
        stops.sort_unstable();
        for pair in stops.windows(2) {
            cut.push(Frag {
                p: pair[0],
                q: pair[1],
                wind: f.wind,
            });
        }
    }
    cut.sort_unstable_by_key(|f| (f.p, f.q));
    let mut merged: Vec<Frag> = Vec::with_capacity(cut.len());
    for f in cut {
        match merged.last_mut() {
            Some(m) if (m.p, m.q) == (f.p, f.q) => {
                m.wind[0] += f.wind[0];
                m.wind[1] += f.wind[1];
            }
            _ => merged.push(f),
        }
    }
    merged.retain(|f| f.wind != [0, 0]);
    merged
}

/// A non-vertical fragment's height at `x2 / 2`, as `num / den`, `den > 0`.
fn y_at(f: &Frag, x2: i64) -> (i128, i128) {
    let (dx, dy) = (i128::from(f.q.0 - f.p.0), i128::from(f.q.1 - f.p.1));
    let num = 2 * i128::from(f.p.1) * dx + dy * (i128::from(x2) - 2 * i128::from(f.p.0));
    (num, 2 * dx)
}

/// The order of two non-vertical fragments' heights at `x2 / 2`.
fn order_at(f: &Frag, g: &Frag, x2: i64) -> Ordering {
    let ((n1, d1), (n2, d2)) = (y_at(f, x2), y_at(g, x2));
    (n1 * d2).cmp(&(n2 * d1))
}

fn add(w: [i32; 2], v: [i32; 2], sign: i32) -> [i32; 2] {
    [w[0] + sign * v[0], w[1] + sign * v[1]]
}

/// The rings of `op(a, b)` into `out` (cleared and refilled).
///
/// `op` answers "is this point in the result" from "is it in `a`" and "is it
/// in `b`" (a nonzero winding number), and must answer `false` for neither.
pub(super) fn combine_into(a: &Rings, b: &Rings, op: impl Fn(bool, bool) -> bool, out: &mut Rings) {
    let mut edges = Vec::new();
    for (rings, right) in [(a, false), (b, true)] {
        for ring in rings.ranges() {
            let (lo, n) = (ring.start, ring.len());
            for i in 0..n {
                let (s, t) = (lo + i, lo + (i + 1) % n);
                edges.push(Edge {
                    a: (rings.xs[s], rings.ys[s]),
                    b: (rings.xs[t], rings.ys[t]),
                    right,
                });
            }
        }
    }
    let frags = snap_round(&edges);
    let inside = |w: [i32; 2]| op(w[0] != 0, w[1] != 0);

    let mut xs: Vec<i64> = frags.iter().flat_map(|f| [f.p.0, f.q.0]).collect();
    xs.sort_unstable();
    xs.dedup();
    // Non-vertical fragments by left end; vertical ones by x.
    let (mut sloped, mut upright): (Vec<usize>, Vec<usize>) =
        (0..frags.len()).partition(|&i| frags[i].p.0 != frags[i].q.0);
    sloped.sort_unstable_by_key(|&i| frags[i].p.0);
    upright.sort_unstable_by_key(|&i| frags[i].p);

    let mut segs: Vec<Seg> = Vec::new();
    let mut push = |from: P, to: P| {
        segs.push(Seg {
            sx: from.0,
            sy: from.1,
            ex: to.0,
            ey: to.1,
        });
    };
    let mut active: Vec<usize> = Vec::new();
    // The slab ending at the current x: its fragments bottom to top, each
    // with the winding just above it.
    let mut before: Vec<(usize, [i32; 2])> = Vec::new();
    let mut now: Vec<(usize, [i32; 2])> = Vec::new();
    let (mut next_sloped, mut next_upright) = (0usize, 0usize);
    for (k, &x) in xs.iter().enumerate() {
        // Vertical fragments at `x`: the winding just left of each is the
        // left slab's below its middle; no fragment ends inside one.
        while next_upright < upright.len() && frags[upright[next_upright]].p.0 == x {
            let f = frags[upright[next_upright]];
            next_upright += 1;
            let mid2 = i128::from(f.p.1) + i128::from(f.q.1);
            let below = before.partition_point(|&(g, _)| {
                let (num, den) = y_at(&frags[g], 2 * x);
                2 * num < mid2 * den
            });
            let left = below.checked_sub(1).map_or([0, 0], |i| before[i].1);
            // Running up, `p` to `q`, the material of a ring is on the left.
            let right = add(left, f.wind, -1);
            match (inside(left), inside(right)) {
                (true, false) => push(f.p, f.q),
                (false, true) => push(f.q, f.p),
                _ => {}
            }
        }
        let Some(&next) = xs.get(k + 1) else {
            debug_assert!(
                next_sloped == sloped.len(),
                "every sloped fragment has started"
            );
            break;
        };
        active.retain(|&i| frags[i].q.0 > x);
        while next_sloped < sloped.len() && frags[sloped[next_sloped]].p.0 == x {
            active.push(sloped[next_sloped]);
            next_sloped += 1;
        }
        let mid = x + next;
        active.sort_by(|&i, &j| order_at(&frags[i], &frags[j], mid));
        now.clear();
        let mut w = [0i32; 2];
        for (n, &i) in active.iter().enumerate() {
            if let Some(&j) = active.get(n + 1) {
                // Release assert: snap rounding leaves no two fragments crossing.
                assert!(
                    order_at(&frags[i], &frags[j], 2 * x) != Ordering::Greater
                        && order_at(&frags[i], &frags[j], 2 * next) != Ordering::Greater,
                    "the rounded arrangement has no crossing"
                );
            }
            let f = frags[i];
            let above = add(w, f.wind, 1);
            // Only a fragment's first slab emits it.
            if f.p.0 == x {
                // Running toward +x, the material of a ring is above.
                match (inside(w), inside(above)) {
                    (false, true) => push(f.p, f.q),
                    (true, false) => push(f.q, f.p),
                    _ => {}
                }
            }
            w = above;
            now.push((i, w));
        }
        // Release assert: a dropped fragment would trace a ring of the wrong area.
        assert_eq!(
            w,
            [0, 0],
            "every operand's winding returns to zero above it"
        );
        std::mem::swap(&mut before, &mut now);
    }

    link(&segs, out);
}
