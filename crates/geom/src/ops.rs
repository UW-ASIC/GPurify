//! Exact geometric predicates and measurements, integer-only (products in `i128`).

use core::cmp::Ordering;

use crate::view::RingRef;
use crate::{Dbu, DbuArea, MAX_ABS_DBU};

/// A coordinate pair, passed by value to a predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Point {
    /// Horizontal coordinate, in database units.
    pub x: Dbu,
    /// Vertical coordinate, in database units.
    pub y: Dbu,
}

/// A closed line segment between two points, both ends included.
///
/// On an edge layer the direction carries meaning: the shape's material lies
/// to the left of travel from `a` to `b`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seg {
    /// Start point.
    pub a: Point,
    /// End point.
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

/// The counter-clockwise order of two non-zero direction vectors by their
/// angle from `+x` in `[0, 2π)`: exact, by half-plane and then by the sign of
/// their cross product. Components up to `2^62` in magnitude.
pub(crate) fn angle_cmp(a: (i64, i64), b: (i64, i64)) -> Ordering {
    let lower = |(x, y): (i64, i64)| y < 0 || (y == 0 && x < 0);
    lower(a).cmp(&lower(b)).then_with(|| {
        let turn = i128::from(a.0) * i128::from(b.1) - i128::from(a.1) * i128::from(b.0);
        0i128.cmp(&turn)
    })
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
pub(crate) struct SweptEdge {
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

/// Whether a closed coordinate run crosses itself: two non-adjacent edges
/// share a point, touching included. A run of fewer than four vertices never does.
///
/// Gives the all-pairs verdict at the cost of the pairs whose x-intervals
/// overlap: `O(n log n)` for typical rings, `O(n²)` when every edge spans a
/// common x.
pub fn self_intersects(xs: &[Dbu], ys: &[Dbu]) -> bool {
    self_intersects_with(xs, ys, false, &mut Vec::new())
}

/// [`self_intersects`] with the edge buffer passed in, for a caller looping over
/// rings. With `pinches`, a vertex the run passes twice as a pinch
/// ([`pinches_are_corners`]) is a touch the run may make, not a crossing.
pub(crate) fn self_intersects_with(
    xs: &[Dbu],
    ys: &[Dbu],
    pinches: bool,
    edges: &mut Vec<SweptEdge>,
) -> bool {
    let n = xs.len();
    // Under four edges, every pair shares a vertex.
    if n < 4 {
        return false;
    }
    let last = u32::try_from(n - 1).expect("a coordinate run is under 2^32 vertices");

    edges.clear();
    for (i, id) in (0..n - 1).zip(0u32..) {
        edges.push(swept_edge(xs, ys, i, i + 1, id));
    }
    edges.push(swept_edge(xs, ys, n - 1, 0, last));
    edges.sort_unstable_by_key(|e| e.xlo);

    let (mut found, mut touched) = (false, false);
    for (i, &e) in edges.iter().enumerate() {
        let rest = &edges[i + 1..];
        let window = rest.partition_point(|o| o.xlo <= e.xhi);

        for &o in &rest[..window] {
            let apart = e.id.abs_diff(o.id);
            let adjacent = (apart == 1) | (apart == last);
            let hit = !adjacent && segments_intersect(e.seg, o.seg);
            let touch = hit && pinches && meet_only_at_an_end(e.seg, o.seg);
            found |= hit & !touch;
            touched |= touch;
        }
    }

    // Edges meeting end to end put one point at two places in the run.
    found || (touched && !pinches_are_corners(xs, ys))
}

/// Whether two segments share one endpoint of each and no other point: the
/// shared end, and no stretch of a common line out of it.
fn meet_only_at_an_end(p: Seg, q: Seg) -> bool {
    let mut shared = 0;
    let mut overlap = false;
    for (end, far) in [(p.a, p.b), (p.b, p.a)] {
        for (other_end, other_far) in [(q.a, q.b), (q.b, q.a)] {
            if end == other_end {
                shared += 1;
                let along = i128::from(far.x.raw() - end.x.raw())
                    * i128::from(other_far.x.raw() - end.x.raw())
                    + i128::from(far.y.raw() - end.y.raw())
                        * i128::from(other_far.y.raw() - end.y.raw());
                overlap |= cross(end, far, other_far) == 0 && along > 0;
            }
        }
    }
    shared == 1 && !overlap
}

/// Whether every point a closed run visits more than once is a **pinch**,
/// where parts of one figure meet at a point: the edges out of it point in
/// distinct directions, and taken counter-clockwise round it they alternate
/// between a way back (toward a visit's previous vertex) and a way on.
///
/// Material lies left of travel, so going round the point it starts after
/// each way on and ends after each way back: alternation is exactly "no point
/// near the vertex is covered twice". Two visits as corners turning the same
/// way alternate (a checkerboard corner, either way it is traced); a straight
/// pass through a touch, turns that differ, or a crossing put two ways back,
/// or two ways on, next to each other. Edges at any angle are read exactly.
fn pinches_are_corners(xs: &[Dbu], ys: &[Dbu]) -> bool {
    let n = xs.len();
    let mut visits: Vec<(Dbu, Dbu, usize)> = (0..n).map(|i| (xs[i], ys[i], i)).collect();
    visits.sort_unstable();
    let toward = |from: usize, to: usize| ((xs[to] - xs[from]).raw(), (ys[to] - ys[from]).raw());
    // Each ray out of the point, and whether it is a way on.
    let mut rays: Vec<((i64, i64), bool)> = Vec::new();
    visits
        .chunk_by(|a, b| (a.0, a.1) == (b.0, b.1))
        .all(|visit| {
            if visit.len() < 2 {
                return true;
            }
            rays.clear();
            for &(.., i) in visit {
                rays.push((toward(i, (i + n - 1) % n), false));
                rays.push((toward(i, (i + 1) % n), true));
            }
            rays.sort_by(|a, b| angle_cmp(a.0, b.0));
            let m = rays.len();
            (0..m).all(|k| {
                let (here, next) = (rays[k], rays[(k + 1) % m]);
                angle_cmp(here.0, next.0) != Ordering::Equal && here.1 != next.1
            })
        })
}

/// Twice the signed area of a closed coordinate run, by the shoelace formula.
///
/// Positive for counter-clockwise.
///
/// # Panics
///
/// When `xs` and `ys` differ in length.
pub fn area2(xs: &[Dbu], ys: &[Dbu]) -> DbuArea {
    assert_eq!(xs.len(), ys.len(), "one y per x");
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

/// Squared distance from a point to a closed segment, rounded up to a whole
/// square unit: zero only when `p` is on the segment, so a comparison against
/// a squared limit never passes a point that is too close.
///
/// # Panics
///
/// In debug builds, when a skew segment's distance reaches `2^42`, which
/// only points outside `±`[`crate::MAX_ABS_DBU`] can.
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
    // At most the squared diagonal of the `±2^40` domain, `2^83`.
    debug_assert!(
        dist2 < 1 << 84,
        "a squared distance in the domain is under 2^84"
    );

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
    debug_assert!(d > 0, "a divisor is positive");

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

/// Twice the squared distance from `p` to the closed segment `seg`, and the
/// segment's nearest point, both coordinates doubled.
///
/// Exact when the segment is horizontal, vertical or at 45 degrees: twice a
/// squared distance to such a line through grid points is an integer, and
/// the foot of the perpendicular is a half-grid point. For a segment at any
/// other angle the distance is twice [`point_seg_dist2`] (rounded up) and the
/// point is rounded.
pub fn point_seg_near2(p: Point, seg: Seg) -> (i128, (i64, i64)) {
    let (ax, ay) = (seg.a.x.raw(), seg.a.y.raw());
    let (vx, vy) = (seg.b.x.raw() - ax, seg.b.y.raw() - ay);
    let (wx, wy) = (p.x.raw() - ax, p.y.raw() - ay);
    let to = |x: i64, y: i64| {
        let (dx, dy) = (i128::from(p.x.raw() - x), i128::from(p.y.raw() - y));
        (2 * (dx * dx + dy * dy), (2 * x, 2 * y))
    };
    let along = i128::from(vx) * i128::from(wx) + i128::from(vy) * i128::from(wy);
    let len2 = i128::from(vx) * i128::from(vx) + i128::from(vy) * i128::from(vy);
    if along <= 0 {
        return to(ax, ay);
    }
    if along >= len2 {
        return to(seg.b.x.raw(), seg.b.y.raw());
    }
    if vx == 0 || vy == 0 {
        // The foot keeps `p`'s coordinate along the segment.
        let (fx, fy) = if vx == 0 {
            (ax, p.y.raw())
        } else {
            (p.x.raw(), ay)
        };
        return to(fx, fy);
    }
    if vx.abs() == vy.abs() {
        let (sx, sy) = (vx.signum(), vy.signum());
        // `v = k·s`: twice the squared offset is `(s × w)²`, and the foot,
        // doubled, is `2a + (s·w)·s`.
        let side = i128::from(sx * wy - sy * wx);
        let t = sx * wx + sy * wy;
        return (side * side, (2 * ax + t * sx, 2 * ay + t * sy));
    }
    let d2 = point_seg_dist2(p, seg).raw();
    let scaled = |a: i64, v: i64| {
        let num = 2 * along * i128::from(v);
        i64::try_from(i128::from(2 * a) + num.div_euclid(len2)).expect("in domain")
    };
    (2 * d2, (scaled(ax, vx), scaled(ay, vy)))
}

/// Twice the squared distance between two closed segments, with a nearest
/// point on each, doubled: `(twice d², on p, on q)`. Zero, at a shared point,
/// when they touch or cross. Exact for horizontal, vertical and 45-degree
/// segments, as [`point_seg_near2`].
pub fn seg_seg_near2(p: Seg, q: Seg) -> (i128, (i64, i64), (i64, i64)) {
    let doubled = |pt: Point| (2 * pt.x.raw(), 2 * pt.y.raw());
    let candidates = [
        (point_seg_near2(p.a, q), doubled(p.a), true),
        (point_seg_near2(p.b, q), doubled(p.b), true),
        (point_seg_near2(q.a, p), doubled(q.a), false),
        (point_seg_near2(q.b, p), doubled(q.b), false),
    ];
    let ((d2, foot), end, from_p) = candidates
        .into_iter()
        .min_by_key(|&((d2, _), _, _)| d2)
        .expect("four candidates");
    if d2 > 0 && segments_intersect(p, q) {
        // A proper crossing; its point is reported as the nearer ends' middle.
        let mid = (i64::midpoint(end.0, foot.0), i64::midpoint(end.1, foot.1));
        return (0, mid, mid);
    }
    if from_p {
        (d2, end, foot)
    } else {
        (d2, foot, end)
    }
}
