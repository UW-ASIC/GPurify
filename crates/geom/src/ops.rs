//! Exact geometric predicates and measurements, integer-only (products in `i128`).

use crate::view::RingRef;
use crate::{Dbu, DbuArea, MAX_ABS_DBU};

/// A coordinate pair, passed by value to a predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Point {
    pub x: Dbu,
    pub y: Dbu,
}

/// A closed line segment between two points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seg {
    pub a: Point,
    pub b: Point,
}

/// Direction a closed ring is wound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Winding {
    /// Positive signed area. Canonical for an outer boundary.
    CounterClockwise,
    /// Negative signed area. Canonical for a hole.
    Clockwise,
}

/// `(b - a) × (c - a)`. Differences reach `2^41`, the product 83 bits, hence `i128`.
#[inline]
fn cross(a: Point, b: Point, c: Point) -> i128 {
    let ux = i128::from(b.x.raw() - a.x.raw());
    let uy = i128::from(b.y.raw() - a.y.raw());
    let vx = i128::from(c.x.raw() - a.x.raw());
    let vy = i128::from(c.y.raw() - a.y.raw());
    ux * vy - uy * vx
}

/// With a zero [`cross`], exactly "`p` is on the segment `s`".
#[inline]
fn in_seg_bbox(s: Seg, p: Point) -> bool {
    (p.x >= s.a.x.min(s.b.x))
        & (p.x <= s.a.x.max(s.b.x))
        & (p.y >= s.a.y.min(s.b.y))
        & (p.y <= s.a.y.max(s.b.y))
}

/// How far `v` lies outside the closed interval spanned by `a` and `b`, signed;
/// zero when it lies within.
#[inline]
fn gap_outside(v: Dbu, a: Dbu, b: Dbu) -> i128 {
    i128::from(v.raw().clamp(a.min(b).raw(), a.max(b).raw()) - v.raw())
}

/// Whether two closed segments share at least one point.
///
/// Inclusive of endpoints and collinear overlap: touching counts.
pub fn segments_intersect(p: Seg, q: Seg) -> bool {
    // Each endpoint's side of the *other* segment's line, as a sign in
    // `{-1, 0, 1}`.
    let d1 = cross(q.a, q.b, p.a).signum();
    let d2 = cross(q.a, q.b, p.b).signum();
    let d3 = cross(p.a, p.b, q.a).signum();
    let d4 = cross(p.a, p.b, q.b).signum();

    // Strict straddle both ways; `< 0`, since a zero is an endpoint on the line.
    let proper = (d1 * d2 < 0) & (d3 * d4 < 0);
    // Otherwise: an endpoint of one lies on the other.
    proper
        | ((d1 == 0) & in_seg_bbox(q, p.a))
        | ((d2 == 0) & in_seg_bbox(q, p.b))
        | ((d3 == 0) & in_seg_bbox(p, q.a))
        | ((d4 == 0) & in_seg_bbox(p, q.b))
}

/// Whether a point lies inside a ring, boundary counting as inside (a via on a
/// conductor edge is connected).
pub fn point_in_ring(ring: RingRef<'_>, p: Point) -> bool {
    let (xs, ys) = ring.coords();
    point_in_coords(xs, ys, p)
}

/// [`point_in_ring`] over raw columns: even-odd ray cast toward +x with the
/// half-open vertex rule, OR an exact on-edge test.
pub(crate) fn point_in_coords(xs: &[Dbu], ys: &[Dbu], p: Point) -> bool {
    let n = xs.len();
    if n < 3 {
        return false;
    }

    // Seeded with the last vertex so the closing edge is the first iteration.
    let mut crossings = 0u32;
    let mut boundary = 0u32;
    let mut ax = xs[n - 1];
    let mut ay = ys[n - 1];
    for (&bx, &by) in xs.iter().zip(ys) {
        let a = Point { x: ax, y: ay };
        let b = Point { x: bx, y: by };
        let side = cross(a, b, p);

        let on_edge = (side == 0) & in_seg_bbox(Seg { a, b }, p);
        // Half-open: a vertex is counted by exactly one of its two edges.
        let straddles = (ay > p.y) != (by > p.y);
        let crosses = straddles & (side != 0) & ((side > 0) == (by > ay));

        crossings ^= u32::from(crosses);
        boundary |= u32::from(on_edge);
        ax = bx;
        ay = by;
    }

    (boundary | crossings) != 0
}

/// One edge of a closed run, carrying the x-interval the sweep orders it on.
#[derive(Debug, Clone, Copy)]
struct SweptEdge {
    /// Leftmost x. The sort key, and what the binary search compares against.
    xlo: Dbu,
    /// Rightmost x. Where this edge's sweep window closes.
    xhi: Dbu,
    seg: Seg,
    /// Position in the ring; ids differing by 1 or `n - 1` are adjacent.
    id: u32,
}

/// The edge from vertex `from` to vertex `to`, with its x-interval ordered so
/// the sweep can sort on `xlo` and stop on `xhi`.
fn swept_edge(xs: &[Dbu], ys: &[Dbu], from: usize, to: usize, id: u32) -> SweptEdge {
    let a = Point {
        x: xs[from],
        y: ys[from],
    };
    let b = Point {
        x: xs[to],
        y: ys[to],
    };
    SweptEdge {
        xlo: a.x.min(b.x),
        xhi: a.x.max(b.x),
        seg: Seg { a, b },
        id,
    }
}

/// Whether a closed coordinate run crosses itself (non-adjacent edges share a point).
///
/// Sweep by `xlo`, testing only edges whose x-intervals overlap: same verdict as
/// all pairs. Not Shamos–Hoey, whose neighbour argument fails on rectilinear degeneracies.
pub fn self_intersects(xs: &[Dbu], ys: &[Dbu]) -> bool {
    let n = xs.len();
    // Under four edges, every pair shares a vertex.
    if n < 4 {
        return false;
    }
    let last = u32::try_from(n - 1).expect("a coordinate run is under 2^32 vertices");

    let mut edges: Vec<SweptEdge> = Vec::with_capacity(n);
    for (i, id) in (0..n - 1).zip(0u32..) {
        edges.push(swept_edge(xs, ys, i, i + 1, id));
    }
    edges.push(swept_edge(xs, ys, n - 1, 0, last));
    edges.sort_unstable_by_key(|e| e.xlo);

    let mut found = false;
    for (i, &e) in edges.iter().enumerate() {
        let rest = &edges[i + 1..];
        let window = rest.partition_point(|o| o.xlo <= e.xhi);

        for &o in &rest[..window] {
            let apart = e.id.abs_diff(o.id);
            let adjacent = (apart == 1) | (apart == last);
            found |= !adjacent & segments_intersect(e.seg, o.seg);
        }
    }

    found
}

/// Twice the signed area of a closed coordinate run, by the shoelace formula.
///
/// Positive for counter-clockwise.
pub fn area2(xs: &[Dbu], ys: &[Dbu]) -> DbuArea {
    let n = xs.len();
    if n < 3 {
        return DbuArea::new(0);
    }

    // Two folds over offset views plus the closing edge; each term <= 2^80.
    let (fx, fy) = (&xs[..n - 1], &ys[1..]);
    let mut forward = DbuArea::new(0);
    for (&x, &y) in fx.iter().zip(fy) {
        forward = forward + x.mul_wide(y);
    }

    let (bx, by) = (&xs[1..], &ys[..n - 1]);
    let mut backward = DbuArea::new(0);
    for (&x, &y) in bx.iter().zip(by) {
        backward = backward + x.mul_wide(y);
    }
    let closing = xs[n - 1].mul_wide(ys[0]) - xs[0].mul_wide(ys[n - 1]);

    (forward - backward) + closing
}

/// Winding direction, from the sign of [`area2`]; `None` for a degenerate run
/// with zero signed area.
pub fn winding_of(xs: &[Dbu], ys: &[Dbu]) -> Option<Winding> {
    match area2(xs, ys).raw().signum() {
        1 => Some(Winding::CounterClockwise),
        -1 => Some(Winding::Clockwise),
        _ => None,
    }
}

/// Squared distance from a point to a closed segment, rounded up: zero only when
/// `p` is on the segment.
pub fn point_seg_dist2(p: Point, seg: Seg) -> DbuArea {
    let vx = i128::from(seg.b.x.raw() - seg.a.x.raw());
    let vy = i128::from(seg.b.y.raw() - seg.a.y.raw());

    // Axis-aligned (or a point): clamp `p` into the segment's box. The production path.
    if (vx == 0) | (vy == 0) {
        let dx = gap_outside(p.x, seg.a.x, seg.b.x);
        let dy = gap_outside(p.y, seg.a.y, seg.b.y);
        return DbuArea::new(dx * dx + dy * dy);
    }

    let wx = i128::from(p.x.raw() - seg.a.x.raw());
    let wy = i128::from(p.y.raw() - seg.a.y.raw());
    // Projection of `w` onto `v`, scaled by `|v|²`.
    let along = vx * wx + vy * wy;
    let len2 = vx * vx + vy * vy;

    // Foot outside the segment: nearest endpoint.
    if along <= 0 {
        return DbuArea::new(wx * wx + wy * wy);
    }
    if along >= len2 {
        let ux = i128::from(p.x.raw() - seg.b.x.raw());
        let uy = i128::from(p.y.raw() - seg.b.y.raw());
        return DbuArea::new(ux * ux + uy * uy);
    }

    // Foot strictly inside: `ceil(cross² / |v|²)`.
    let drop = cross(seg.a, seg.b, p).unsigned_abs();
    let scale = len2.unsigned_abs();

    let dist2 = match drop.checked_mul(drop) {
        Some(num) => num / scale + u128::from(num % scale != 0),
        // `cross²` reaches 166 bits at the domain corners: divide at 256 bits.
        None => ceil_sq_div(drop, scale),
    };

    #[expect(
        clippy::cast_possible_wrap,
        reason = "asserted under 2^84; DbuArea is i128"
    )]
    let dist2 = dist2 as i128;
    DbuArea::new(dist2)
}

/// `ceil(a² / d)` exactly, for `d > 0`: `a²` as a 256-bit pair, restoring division.
fn ceil_sq_div(a: u128, d: u128) -> u128 {
    const HALF: u128 = u64::MAX as u128;

    // `a = h·2^64 + l`, so `a² = h²·2^128 + 2hl·2^64 + l²`.
    let (l, h) = (a & HALF, a >> 64);
    let (ll, hl, hh) = (l * l, l * h, h * h);
    let mid = (ll >> 64) + (hl & HALF) + (hl & HALF);
    let lo = (ll & HALF) | (mid << 64);
    let hi = hh + (hl >> 64) + (hl >> 64) + (mid >> 64);


    let mut rem: u128 = 0;
    let mut quo: u128 = 0;
    for word in [hi, lo] {
        for bit in (0..128u32).rev() {
            // A carried-out bit means rem >= d; the wrapping subtract is still exact.
            let carried = rem >> 127;
            rem = (rem << 1) | ((word >> bit) & 1);
            let take = (carried != 0) | (rem >= d);
            rem = rem.wrapping_sub(d * u128::from(take));
            quo = (quo << 1) | u128::from(take);
        }
    }

    quo + u128::from(rem != 0)
}

/// Integer square root, truncating; negatives give 0, results clamp to `MAX_ABS_DBU`.
pub fn isqrt(value: DbuArea) -> Dbu {
    let root = value.raw().max(0).isqrt();

    #[expect(
        clippy::cast_possible_truncation,
        reason = "clamped to MAX_ABS_DBU, which is 2^40"
    )]
    let clamped = root.min(i128::from(MAX_ABS_DBU)) as i64;
    Dbu::new_unchecked(clamped)
}

/// Squared distance between two closed segments; zero when they touch or
/// cross.
pub fn seg_seg_dist2(p: Seg, q: Seg) -> DbuArea {
    if segments_intersect(p, q) {
        return DbuArea::new(0);
    }
    // Disjoint segments are nearest at an endpoint of one of them.
    point_seg_dist2(p.a, q)
        .min(point_seg_dist2(p.b, q))
        .min(point_seg_dist2(q.a, p))
        .min(point_seg_dist2(q.b, p))
}
