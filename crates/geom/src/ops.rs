//! Exact geometric predicates and measurements: integer-only, never floating
//! point.

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

/// Which side of a directed line a point falls on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Orientation {
    Clockwise,
    CounterClockwise,
    /// All three points are collinear.
    Collinear,
}

/// Direction a closed ring is wound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Winding {
    /// Positive signed area. Canonical for an outer boundary.
    CounterClockwise,
    /// Negative signed area. Canonical for a hole.
    Clockwise,
}

/// Whether a coordinate is inside the legal domain — the bound every `i128`
/// product below rests on.
#[inline]
fn in_domain(c: Dbu) -> bool {
    c.raw().unsigned_abs() <= MAX_ABS_DBU.unsigned_abs()
}

/// Twice the signed area of the triangle `(a, b, c)`: the cross product of
/// `b - a` and `c - a`.
///
/// Not [`Dbu::mul_wide`]: the operands are coordinate *differences*, which
/// legally reach `2^41` and leave the domain `mul_wide` asserts on. The product
/// needs 83 bits, so `i64` would silently wrap.
///
/// No assert: callers assert their columns once, rather than once per vertex
/// inside the ray-cast loop.
#[inline]
fn cross(a: Point, b: Point, c: Point) -> i128 {
    let ux = i128::from(b.x.raw() - a.x.raw());
    let uy = i128::from(b.y.raw() - a.y.raw());
    let vx = i128::from(c.x.raw() - a.x.raw());
    let vy = i128::from(c.y.raw() - a.y.raw());
    ux * vy - uy * vx
}

/// Whether `p` lies inside `s`'s bounding box.
///
/// Alone this says nothing; paired with a zero [`cross`] it is exactly "`p` is
/// on the segment `s`", which is the collinear half of every predicate here.
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

/// Orientation of the triple `(a, b, c)`.
pub fn orientation(a: Point, b: Point, c: Point) -> Orientation {
    debug_assert!(
        in_domain(a.x) && in_domain(a.y),
        "a is off the coordinate domain"
    );
    debug_assert!(
        in_domain(b.x) && in_domain(b.y),
        "b is off the coordinate domain"
    );
    debug_assert!(
        in_domain(c.x) && in_domain(c.y),
        "c is off the coordinate domain"
    );

    match cross(a, b, c).signum() {
        1 => Orientation::CounterClockwise,
        -1 => Orientation::Clockwise,
        _ => Orientation::Collinear,
    }
}

/// Whether two closed segments share at least one point.
///
/// Inclusive of endpoints and handling the collinear-overlap case: shapes in a
/// real layout touch constantly, and "they only touch" is not a reason to
/// report no intersection.
///
/// No domain assert, for [`cross`]'s reason: callers assert their columns once
/// per column rather than once per pair.
pub fn segments_intersect(p: Seg, q: Seg) -> bool {
    // Each endpoint's side of the *other* segment's line, as a sign in
    // `{-1, 0, 1}`.
    let d1 = cross(q.a, q.b, p.a).signum();
    let d2 = cross(q.a, q.b, p.b).signum();
    let d3 = cross(p.a, p.b, q.a).signum();
    let d4 = cross(p.a, p.b, q.b).signum();

    // A proper crossing: each segment's endpoints straddle the other's line
    // strictly. `d1 * d2 < 0` and not `(d1 > 0) != (d2 > 0)`, because the
    // latter calls a zero a straddle and would claim a crossing for an endpoint
    // that merely lies on the line, well outside the segment.
    let proper = (d1 * d2 < 0) & (d3 * d4 < 0);

    // Everything else two closed segments can share: an endpoint of one on the
    // other — the collinear-overlap and shared-endpoint case.
    proper
        | ((d1 == 0) & in_seg_bbox(q, p.a))
        | ((d2 == 0) & in_seg_bbox(q, p.b))
        | ((d3 == 0) & in_seg_bbox(p, q.a))
        | ((d4 == 0) & in_seg_bbox(p, q.b))
}

/// Whether a point lies inside a ring, boundary counting as inside.
///
/// Boundary-inclusive because a via landing exactly on a conductor edge is
/// connected, and the alternative loses that connection silently.
pub fn point_in_ring(ring: RingRef<'_>, p: Point) -> bool {
    let (xs, ys) = ring.coords();
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    debug_assert!(
        in_domain(p.x) && in_domain(p.y),
        "p is off the coordinate domain"
    );
    debug_assert!(
        xs.iter().chain(ys).all(|&c| in_domain(c)),
        "a ring vertex is off the coordinate domain"
    );

    let n = xs.len();
    // Under three vertices there is no interior and no boundary to land on.
    if n < 3 {
        return false;
    }

    // Seeded with the last vertex so the ring's closing edge is the first
    // iteration rather than a fixup afterwards. `crossings` is an even-odd ray
    // cast towards +x; `boundary` is the on-edge test.
    let mut crossings = 0u32;
    let mut boundary = 0u32;
    let mut ax = xs[n - 1];
    let mut ay = ys[n - 1];
    for (&bx, &by) in xs.iter().zip(ys) {
        let a = Point { x: ax, y: ay };
        let b = Point { x: bx, y: by };
        let side = cross(a, b, p);

        let on_edge = (side == 0) & in_seg_bbox(Seg { a, b }, p);
        // The half-open convention `(ay > py) != (by > py)`: a vertex is
        // counted by exactly one of the two edges meeting at it, so a ray
        // grazing a vertex is not double-counted.
        let straddles = (ay > p.y) != (by > p.y);
        // `p` is left of the edge when the sign of `side` agrees with the
        // edge's direction of travel in y. `side != 0` excludes the point
        // lying on the edge's line, which `on_edge` has already decided.
        let crosses = straddles & (side != 0) & ((side > 0) == (by > ay));

        crossings ^= u32::from(crosses);
        boundary |= u32::from(on_edge);
        ax = bx;
        ay = by;
    }

    debug_assert!(
        crossings <= 1 && boundary <= 1,
        "both accumulators are parities"
    );
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
    /// Position in the ring. Two edges are cyclically adjacent — and so are
    /// entitled to share a vertex — exactly when their ids differ by one or by
    /// `n - 1`.
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

/// Whether a coordinate run crosses itself; the guarantee
/// [`crate::PolygonRef`] is built on.
///
/// Edges are swept left to right, each tested only against later edges whose
/// x-interval can still reach it. The dropped pairs are exactly those with
/// disjoint x-intervals, which share no point, so the verdict is identical to
/// the all-pairs scan. A status-structure sweep (Shamos–Hoey) would be cheaper
/// but its neighbour argument does not survive the degeneracies rectilinear
/// layout is made of, and it fails by *missing* a crossing — a
/// self-intersecting polygon validated as clean.
pub fn self_intersects(xs: &[Dbu], ys: &[Dbu]) -> bool {
    debug_assert_eq!(
        xs.len(),
        ys.len(),
        "a coordinate run's columns are parallel"
    );
    debug_assert!(
        xs.iter().chain(ys).all(|&c| in_domain(c)),
        "a vertex is off the coordinate domain"
    );

    let n = xs.len();
    // Under four vertices there are under four edges, and every pair of them
    // then shares a vertex. Sharing a vertex is not crossing.
    if n < 4 {
        return false;
    }
    // The id space, and the cyclic-adjacency distance in one. Fails closed:
    // truncating the id would silently exempt real crossings from the
    // adjacency test.
    let last = u32::try_from(n - 1).expect("a coordinate run is under 2^32 vertices");

    // A closed run has one edge per vertex, with the closing edge lifted out
    // of the loop so the wrap back to vertex 0 is not a branch in the body.
    let mut edges: Vec<SweptEdge> = Vec::with_capacity(n);
    for (i, id) in (0..n - 1).zip(0u32..) {
        edges.push(swept_edge(xs, ys, i, i + 1, id));
    }
    edges.push(swept_edge(xs, ys, n - 1, 0, last));
    debug_assert_eq!(edges.len(), n, "one edge per vertex of a closed run");
    debug_assert!(
        edges.iter().all(|e| e.xlo <= e.xhi),
        "an x-interval runs low to high"
    );

    edges.sort_unstable_by_key(|e| e.xlo);
    debug_assert!(
        edges.windows(2).all(|w| w[0].xlo <= w[1].xlo),
        "the sweep runs left to right"
    );

    let mut found = false;
    for (i, &e) in edges.iter().enumerate() {
        let rest = &edges[i + 1..];
        // Sorted ascending by `xlo`, so the partners whose x-interval can still
        // reach `e`'s are a prefix of `rest`.
        let window = rest.partition_point(|o| o.xlo <= e.xhi);
        debug_assert!(
            window == 0 || rest[window - 1].xlo <= e.xhi,
            "the window holds only edges that can still reach this one"
        );
        debug_assert!(
            window == rest.len() || rest[window].xlo > e.xhi,
            "the window ends at the first edge that starts past this one"
        );

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
/// Doubled so it stays an exact integer. Sign encodes winding, which is why
/// [`winding_of`] is a thin wrapper rather than a separate traversal.
pub fn area2(xs: &[Dbu], ys: &[Dbu]) -> DbuArea {
    debug_assert_eq!(
        xs.len(),
        ys.len(),
        "a coordinate run's columns are parallel"
    );
    debug_assert!(
        xs.iter().chain(ys).all(|&c| in_domain(c)),
        "a vertex is off the coordinate domain"
    );

    let n = xs.len();
    // Under three vertices encloses nothing, and the offset views below would
    // have nothing to slice.
    if n < 3 {
        return DbuArea::new(0);
    }

    // The shoelace as two folds over offset views of the same columns, with the
    // ring's closing edge as one scalar fixup outside. Each term is at most
    // `2^80`, so a million-vertex ring still sums inside `i128`.
    let (fx, fy) = (&xs[..n - 1], &ys[1..]);
    debug_assert_eq!(
        fx.len(),
        fy.len(),
        "the shoelace's offset views are parallel"
    );
    let mut forward = DbuArea::new(0);
    for (&x, &y) in fx.iter().zip(fy) {
        forward = forward + x.mul_wide(y);
    }

    let (bx, by) = (&xs[1..], &ys[..n - 1]);
    debug_assert_eq!(
        bx.len(),
        by.len(),
        "the shoelace's offset views are parallel"
    );
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

/// Squared distance from a point to a closed segment.
///
/// Squared to stay exact: the true distance is irrational in general, and every
/// caller compares against a squared limit anyway. Returns [`DbuArea`] because
/// that is the dimension of a squared coordinate.
pub fn point_seg_dist2(p: Point, seg: Seg) -> DbuArea {
    debug_assert!(
        in_domain(p.x) && in_domain(p.y),
        "p is off the coordinate domain"
    );
    debug_assert!(
        in_domain(seg.a.x) && in_domain(seg.a.y) && in_domain(seg.b.x) && in_domain(seg.b.y),
        "a segment endpoint is off the coordinate domain"
    );

    let vx = i128::from(seg.b.x.raw() - seg.a.x.raw());
    let vy = i128::from(seg.b.y.raw() - seg.a.y.raw());

    // Axis-aligned, including the degenerate segment that is a point: the
    // nearest point is `p` clamped into the segment's box, so the answer is a
    // sum of two squares with no division. Every shape this tree accepts is
    // rectilinear, so this is the path production takes.
    if (vx == 0) | (vy == 0) {
        let dx = gap_outside(p.x, seg.a.x, seg.b.x);
        let dy = gap_outside(p.y, seg.a.y, seg.b.y);
        return DbuArea::new(dx * dx + dy * dy);
    }

    let wx = i128::from(p.x.raw() - seg.a.x.raw());
    let wy = i128::from(p.y.raw() - seg.a.y.raw());
    // Where the perpendicular foot falls, as the projection of `w` onto `v`
    // scaled by `|v|²` so it stays an integer.
    let along = vx * wx + vy * wy;
    let len2 = vx * vx + vy * vy;
    debug_assert!(
        len2 > 0,
        "a zero-length segment is axis-aligned and took the branch above"
    );

    // Foot before `a`, or past `b`: the answer is that endpoint's own distance.
    if along <= 0 {
        return DbuArea::new(wx * wx + wy * wy);
    }
    if along >= len2 {
        let ux = i128::from(p.x.raw() - seg.b.x.raw());
        let uy = i128::from(p.y.raw() - seg.b.y.raw());
        return DbuArea::new(ux * ux + uy * uy);
    }

    // Foot strictly inside: the drop is `cross² / |v|²`. Both operands are
    // magnitudes — the quotient is a squared length and the signs cancel.
    let drop = cross(seg.a, seg.b, p).unsigned_abs();
    let scale = len2.unsigned_abs();

    // Rounded away from zero, not truncated: a zero result has to mean "`p` is
    // on the segment" and nothing else, and truncation reports zero for every
    // drop under one unit.
    let dist2 = match drop.checked_mul(drop) {
        Some(num) => num / scale + u128::from(num % scale != 0),
        // `cross²` reaches 166 bits at the top of the coordinate domain, so the
        // square is formed and divided at 256 bits instead.
        None => ceil_sq_div(drop, scale),
    };

    debug_assert!(
        dist2 <= 1u128 << 84,
        "a squared distance between two in-domain points"
    );
    #[expect(
        clippy::cast_possible_wrap,
        reason = "asserted under 2^84; DbuArea is i128"
    )]
    let dist2 = dist2 as i128;
    DbuArea::new(dist2)
}

/// `ceil(a² / d)` exactly, for `d > 0` and any `a`.
///
/// `a` reaches `2^83` at the corners of the coordinate domain, so `a²` reaches
/// 166 bits and is formed as a 256-bit pair, divided by restoring
/// shift-and-subtract. Slow, and only reachable from an oblique edge spanning
/// most of the domain; it has to be exact because zero is the answer that means
/// "`p` is on the segment".
fn ceil_sq_div(a: u128, d: u128) -> u128 {
    /// Low half of a `u128`, the split the schoolbook square below works in.
    const HALF: u128 = u64::MAX as u128;

    debug_assert!(d > 0, "a squared segment length is positive here");

    // `a²` as (high, low). `a = h·2^64 + l`, so
    // `a² = h²·2^128 + 2hl·2^64 + l²`; each 64×64 partial fits a `u128`, and
    // the true product is under `2^256`, so neither word overflows.
    let (l, h) = (a & HALF, a >> 64);
    let (ll, hl, hh) = (l * l, l * h, h * h);
    let mid = (ll >> 64) + (hl & HALF) + (hl & HALF);
    let lo = (ll & HALF) | (mid << 64);
    let hi = hh + (hl >> 64) + (hl >> 64) + (mid >> 64);

    // The quotient is `(a/|v|)²`, a squared length, so it fits one word.
    debug_assert!(hi < d, "a squared perpendicular drop fits 128 bits");

    let mut rem: u128 = 0;
    let mut quo: u128 = 0;
    for word in [hi, lo] {
        for bit in (0..128u32).rev() {
            // `rem < d` on entry, so doubling it overflows only when `d`
            // itself is past `2^127` — and in that case the true remainder is
            // already at least `d`, so the same wrapping subtraction is the
            // right one. Either way exactly one subtraction restores `rem < d`.
            let carried = rem >> 127;
            rem = (rem << 1) | ((word >> bit) & 1);
            let take = (carried != 0) | (rem >= d);
            rem = rem.wrapping_sub(d * u128::from(take));
            quo = (quo << 1) | u128::from(take);
        }
    }

    debug_assert!(rem < d, "a remainder is under its divisor");
    quo + u128::from(rem != 0)
}

/// Integer square root, rounding toward zero.
pub fn isqrt(value: DbuArea) -> Dbu {
    let raw = value.raw();
    debug_assert!(raw >= 0, "a negative area has no real square root");
    debug_assert!(
        raw.unsigned_abs() <= 1u128 << 80,
        "area past the 2^80 ceiling MAX_ABS_DBU exists to set"
    );

    // `max(0)` rather than `abs`: zero is the fail-closed answer, because a
    // reported distance of zero over-reports.
    let root = raw.max(0).isqrt();
    debug_assert!(
        root <= i128::from(MAX_ABS_DBU),
        "the root of a legal area is a legal coordinate"
    );

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
    // Zero when they touch or cross, and only then. This branch is what makes
    // that exact rather than a rounding artefact of the drops below.
    if segments_intersect(p, q) {
        return DbuArea::new(0);
    }

    // Disjoint segments take their nearest approach at an endpoint of one of
    // them.
    let d = point_seg_dist2(p.a, q)
        .min(point_seg_dist2(p.b, q))
        .min(point_seg_dist2(q.a, p))
        .min(point_seg_dist2(q.b, p));

    debug_assert!(
        d > DbuArea::new(0),
        "segments that share no point are a positive distance apart"
    );
    d
}
