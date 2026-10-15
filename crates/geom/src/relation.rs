//! `KLayout`'s edge-pair relation on octilinear edges, exact.
//!
//! Data in: two directed edges, in `KLayout`'s orientation (a polygon's hull
//! clockwise, its material on the right of travel; a `GPurify` ring reversed),
//! and how the pair is read: the relation, the metric and the zero-distance
//! mode. Data out: the least distance at which the pair is reported, as twice
//! its square, or `None` when no distance reports it.
//!
//! A port of `EdgeRelationFilter::check` with the default `angle_limit` (90
//! degrees) and no projection bounds, and of `euclidian_near_part_of_edge` and
//! `var_near_part_of_edge` (`dbEdgePairRelations.cc`): each edge is cut to the
//! other's inner side, and a pair holds at a distance `d` when each edge has a
//! stretch of positive length within `d` of the other, Euclidean or measured
//! square to it over its span (projection). `KLayout` computes that in floating
//! point; here every crossing of an axis edge with a 45-degree line, and every
//! distance, is exact. Two 45-degree edges at right angles never pair, so no
//! crossing between them is needed.
//!
//! At any other angle [`pair_threshold_any`] reads the same relation under
//! the Euclidean metric: an edge is cut where it crosses the other's line, at
//! a rational point, and the distance from there is a fraction compared in
//! 256-bit integers, so it too is exact.

use crate::ops::{
    point_seg_near2, point_seg_twice2, seg_seg_near2, seg_seg_twice2, segments_intersect, Point,
    Seg,
};
use crate::wide::{twice_ratio, I256};
use crate::Dbu;

/// Which sides of the two edges face each other (`KLayout`'s
/// `edge_relation_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// Two edges of one polygon across its material (`width`).
    Width,
    /// Two edges across empty space (`space`, `notch`, `separation`).
    Space,
    /// The first edge's polygon around the second's (`enclosing`).
    Overlap,
    /// The first edge's polygon inside the second's (`enclosed`, `inside`).
    Inside,
}

/// How a distance between two edges is measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metric {
    /// Point to point (`euclidian`).
    Euclidean,
    /// Square to the edge, over its span (`projection`).
    Projection,
}

/// When a pair at distance 0 is reported (`zero_distance_mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Zero {
    /// Never (`without_touching_edges`).
    Never,
    /// Where the edges touch (the default).
    WhenTouching,
    /// Where collinear edges overlap (`without_touching_corners`).
    WhenOverlapping,
}

type P = (i64, i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct E {
    p1: P,
    p2: P,
}

impl E {
    fn of(s: Seg) -> Self {
        Self {
            p1: (s.a.x.raw(), s.a.y.raw()),
            p2: (s.b.x.raw(), s.b.y.raw()),
        }
    }
    fn seg(self) -> Seg {
        Seg {
            a: pt(self.p1),
            b: pt(self.p2),
        }
    }
    fn swapped(self) -> Self {
        Self {
            p1: self.p2,
            p2: self.p1,
        }
    }
    fn d(self) -> (i128, i128) {
        (
            i128::from(self.p2.0 - self.p1.0),
            i128::from(self.p2.1 - self.p1.1),
        )
    }
    fn degenerate(self) -> bool {
        self.p1 == self.p2
    }
    /// The side of `p`: `1` left of travel, `-1` right, `0` on the line.
    fn side_of(self, p: P) -> i32 {
        let (dx, dy) = self.d();
        let (wx, wy) = (i128::from(p.0 - self.p1.0), i128::from(p.1 - self.p1.1));
        match (dx * wy - dy * wx).signum() {
            1 => 1,
            -1 => -1,
            _ => 0,
        }
    }
    fn parallel(self, o: Self) -> bool {
        let ((ax, ay), (bx, by)) = (self.d(), o.d());
        ax * by == ay * bx
    }
}

fn pt(p: P) -> Point {
    Point {
        x: Dbu::new_unchecked(p.0),
        y: Dbu::new_unchecked(p.1),
    }
}

fn sprod(a: (i128, i128), b: (i128, i128)) -> i128 {
    a.0 * b.0 + a.1 * b.1
}

/// `KLayout`'s `include_zero_flag`.
fn include_zero(zero: Zero, a: E, b: E) -> bool {
    let (s1, s2) = (a.side_of(b.p1), a.side_of(b.p2));
    if s1 == 0 && s2 == 0 {
        return match zero {
            Zero::WhenTouching => segments_intersect(a.seg(), b.seg()),
            // Collinear and sharing a stretch of positive length.
            Zero::WhenOverlapping => {
                let d = a.d();
                let at = |p: P| sprod((i128::from(p.0), i128::from(p.1)), d);
                let (a0, a1) = (at(a.p1).min(at(a.p2)), at(a.p1).max(at(a.p2)));
                let (b0, b1) = (at(b.p1).min(at(b.p2)), at(b.p1).max(at(b.p2)));
                a0.max(b0) < a1.min(b1)
            }
            Zero::Never => false,
        };
    }
    if (s1 == 0 || s2 == 0) && a.p1 != b.p2 && a.p2 != b.p1 {
        return zero == Zero::WhenTouching && segments_intersect(a.seg(), b.seg());
    }
    false
}

/// Where `g` crosses `e`'s line, on the lattice: an axis edge and a 45-degree
/// line, or a 45-degree edge and an axis line, cross at a lattice point.
fn cut_point(g: E, e: E) -> P {
    let (ex, ey) = e.d();
    let (gx, gy) = g.d();
    let det = ex * gy - ey * gx;
    let (wx, wy) = (i128::from(e.p1.0 - g.p1.0), i128::from(e.p1.1 - g.p1.1));
    // g.p1 + t·g.d on e's line: t = (w × e.d) / (g.d × e.d).
    let num = wx * ey - wy * ex;
    let den = gx * ey - gy * ex;
    debug_assert_ne!(det, 0, "a crossing of non-parallel edges");
    along_lattice(g, num, den)
}

/// The point `g.p1 + (num / den)·g.d`, which must be a lattice point: on the
/// octilinear grid every crossing and foot this module forms is one.
fn along_lattice(g: E, num: i128, den: i128) -> P {
    let (gx, gy) = g.d();
    let step = |p: i64, d: i128| {
        let v = d * num;
        debug_assert_eq!(v % den, 0, "an octilinear point is on the lattice");
        p + i64::try_from(v / den).expect("on the edge")
    };
    (step(g.p1.0, gx), step(g.p1.1, gy))
}

/// The part of an edge on another's inner side, when it has one.
enum Part {
    /// All of it.
    Whole,
    /// The stretch from this end of it to where it crosses the other's line.
    From(P),
}

/// How much of `other` lies on `e`'s inner (right) side, `e`'s line counted
/// in as `include_zero` says; `None` for none of it.
fn inner_end(zero: Zero, e: E, other: E) -> Option<Part> {
    let (s1, s2) = if e.degenerate() {
        if segments_intersect(other.seg(), e.seg()) {
            (0, 0)
        } else {
            (-1, -1)
        }
    } else {
        (e.side_of(other.p1), e.side_of(other.p2))
    };
    let thr = if include_zero(zero, e, other) { 0 } else { -1 };
    if s1 > thr && s2 > thr {
        return None;
    }
    Some(if s2 > thr {
        Part::From(other.p1)
    } else if s1 > thr {
        Part::From(other.p2)
    } else {
        Part::Whole
    })
}

/// `other` cut to `e`'s inner (right) side, as both near-part functions do
/// first; `None` when nothing of it is there.
fn inner_part(zero: Zero, e: E, other: E) -> Option<E> {
    // The kept end first: every reader of the part (distance, projection,
    // touch) is blind to its direction.
    Some(match inner_end(zero, e, other)? {
        Part::Whole => other,
        Part::From(end) => E {
            p1: end,
            p2: cut_point(other, e),
        },
    })
}

/// Twice the squared distance between two points.
fn point2(a: P, b: P) -> i128 {
    let (dx, dy) = (i128::from(a.0 - b.0), i128::from(a.1 - b.1));
    2 * (dx * dx + dy * dy)
}

/// Twice the squared Euclidean distance between two edges, either possibly a
/// point.
fn dist2(a: E, b: E) -> i128 {
    match (a.degenerate(), b.degenerate()) {
        (true, true) => point2(a.p1, b.p1),
        (true, false) => point_seg_near2(pt(a.p1), b.seg()).0,
        (false, true) => point_seg_near2(pt(b.p1), a.seg()).0,
        (false, false) => seg_seg_near2(a.seg(), b.seg()).0,
    }
}

/// Twice the squared distance of `p` from `e`'s line, square to it.
fn perp2(e: E, p: P) -> i128 {
    let (dx, dy) = e.d();
    let (sx, sy) = (dx.signum(), dy.signum());
    // On the octilinear grid `e.d` is a whole multiple of (sx, sy).
    let c = sx * i128::from(p.1 - e.p1.1) - sy * i128::from(p.0 - e.p1.0);
    2 * c * c / (sx * sx + sy * sy)
}

/// The least `d` (twice squared) at which `other` has a near part against
/// `e` under `metric`: a stretch of positive length on `e`'s inner side,
/// within `d` of `e` (Euclidean), or within `d` square to `e`'s line over
/// `e`'s span (projection); a single point only where the cut leaves one.
fn near(metric: Metric, zero: Zero, e: E, other: E) -> Option<i128> {
    let g = inner_part(zero, e, other)?;
    if metric == Metric::Euclidean {
        return Some(dist2(e, g));
    }
    let d = e.d();
    let span = sprod(d, d);
    let along = |p: P| sprod((i128::from(p.0 - e.p1.0), i128::from(p.1 - e.p1.1)), d);
    if g.degenerate() {
        let a = along(g.p1);
        return (0..=span).contains(&a).then(|| perp2(e, g.p1));
    }
    if e.parallel(g) {
        let (a, b) = (along(g.p1), along(g.p2));
        let (lo, hi) = (a.min(b).max(0), a.max(b).min(span));
        return (lo < hi).then(|| perp2(e, g.p1));
    }
    // The stretch of `g` whose foot falls on `e`: along(g.p1 + t·g.d) is
    // linear in t; its ends are where it is 0 or `span`, lattice points.
    let (a1, a2) = (along(g.p1), along(g.p2));
    if a1 == a2 {
        // `g` square to `e` (excluded by the angle test before here).
        return None;
    }
    let at = |target: i128| {
        // The point of `g` whose foot is `target`, clamped to `g`.
        // t = num / den, clamped to 0..=1.
        let (mut num, mut den) = (target - a1, a2 - a1);
        if den < 0 {
            (num, den) = (-num, -den);
        }
        if num <= 0 {
            return g.p1;
        }
        if num >= den {
            return g.p2;
        }
        along_lattice(g, num, den)
    };
    let (lo, hi) = (a1.min(a2), a1.max(a2));
    if lo.max(0) >= hi.min(span) {
        return None;
    }
    let (p, q) = (at(0), at(span));
    Some(perp2(e, p).min(perp2(e, q)))
}

/// `a` and `b` turned so the side each is read from is its right, as the
/// near-part functions take them.
fn oriented(relation: Relation, a: E, b: E) -> (E, E) {
    let a_turned = matches!(relation, Relation::Space | Relation::Inside);
    let b_turned = matches!(relation, Relation::Space | Relation::Overlap);
    (
        if a_turned { a.swapped() } else { a },
        if b_turned { b.swapped() } else { b },
    )
}

/// [`oriented`], or `None` when the edges, both of positive length, run at
/// 90 degrees or less to each other once `a` faces `b` under `relation`
/// (`KLayout`'s default `angle_limit`): such a pair is never reported.
fn facing(relation: Relation, a: Seg, b: Seg) -> Option<(E, E)> {
    let (a, b) = (E::of(a), E::of(b));
    let aa = if matches!(relation, Relation::Overlap | Relation::Inside) {
        a.swapped()
    } else {
        a
    };
    if !a.degenerate() && !b.degenerate() && sprod(aa.d(), b.d()) >= 0 {
        return None;
    }
    Some(oriented(relation, a, b))
}

/// The least distance, as twice its square, at which `KLayout` reports the
/// pair `(a, b)` under `relation`, `metric` and `zero` with its default
/// `angle_limit`; `None` when it never does. A check at `d` reports the pair
/// when the result is below `2·d²`. Both edges are in `KLayout`'s orientation
/// (material on the right of travel), `a` from the first layer.
#[must_use]
pub fn pair_threshold2(
    relation: Relation,
    metric: Metric,
    zero: Zero,
    a: Seg,
    b: Seg,
) -> Option<i128> {
    let (an, bn) = facing(relation, a, b)?;
    let second = near(metric, zero, an, bn)?;
    let first = near(metric, zero, bn, an)?;
    Some(first.max(second))
}

/// The least distance, twice squared, at which the part of `b` that
/// [`pair_threshold2`] reports under projection reaches `v`, a point of `b`:
/// `v` on `a`'s inner side, its foot on `a`, square to it closer than the
/// limit. `None` when it never does. With [`pair_threshold2`] this reads
/// whether a reported edge reaches a corner of its polygon (`KLayout`'s
/// `second_edges` meeting at a corner).
#[must_use]
pub fn projected_reach2(relation: Relation, zero: Zero, a: Seg, b: Seg, v: Point) -> Option<i128> {
    let (an, bn) = oriented(relation, E::of(a), E::of(b));
    let v = (v.x.raw(), v.y.raw());
    let part = inner_part(zero, an, bn)?;
    if !segments_intersect(part.seg(), E { p1: v, p2: v }.seg()) {
        return None;
    }
    let d = an.d();
    let along = sprod((i128::from(v.0 - an.p1.0), i128::from(v.1 - an.p1.1)), d);
    (0..=sprod(d, d)).contains(&along).then(|| perp2(an, v))
}

/// The Euclidean distance, twice squared as `(floor, inexact)`, from `e` to
/// the part of `other` on `e`'s inner side, at any angle: `None` when
/// nothing of it is there. The part may end where `other` crosses `e`'s
/// line, at a rational point `c = (X / W, Y / W)`; then the candidates are
/// its whole end to `e`, `c` to `e`'s ends (`c` lies on `e`'s line, outside
/// `e` unless the two meet), and `e`'s ends to the part.
fn near_any(zero: Zero, e: E, other: E) -> Option<(i128, bool)> {
    let g = inner_part_any(zero, e, other)?;
    let Some((keep, (x, y, w))) = g else {
        return Some(seg_seg_twice2(e.seg(), other.seg()));
    };
    if segments_intersect(e.seg(), other.seg()) {
        return Some((0, false));
    }
    let wide = |v: i64| I256::from_i128(i128::from(v));
    // Twice the squared distance from `c` to the grid point `p`.
    let to_c = |p: P| {
        let dx = x.sub(wide(p.0).mul(w));
        let dy = y.sub(wide(p.1).mul(w));
        twice_ratio(dx.mul(dx).add(dy.mul(dy)), w.mul(w))
    };
    // From `keep` toward `c`, along `other`.
    let u = if keep == other.p1 {
        other.d()
    } else {
        (-other.d().0, -other.d().1)
    };
    let along_c = x
        .sub(wide(keep.0).mul(w))
        .mul(I256::from_i128(u.0))
        .add(y.sub(wide(keep.1).mul(w)).mul(I256::from_i128(u.1)));
    let to_part = |p: P| {
        let along = sprod((i128::from(p.0 - keep.0), i128::from(p.1 - keep.1)), u);
        if along <= 0 {
            return point_seg_twice2(pt(p), E { p1: keep, p2: keep }.seg());
        }
        if I256::from_i128(along).mul(w) >= along_c {
            return to_c(p);
        }
        let side = I256::from_i128(u.0 * i128::from(p.1 - keep.1) - u.1 * i128::from(p.0 - keep.0));
        twice_ratio(side.mul(side), I256::from_i128(sprod(u, u)))
    };
    let mut best = point_seg_twice2(pt(keep), e.seg())
        .min(to_c(e.p1))
        .min(to_c(e.p2))
        .min(to_part(e.p1));
    if !e.degenerate() {
        best = best.min(to_part(e.p2));
    }
    Some(best)
}

/// [`inner_part`] at any angle: `None` when nothing of `other` is on `e`'s
/// inner side, `Some(None)` when all of it is, and `Some(Some((keep, c)))`
/// when the part runs from its end `keep` to `c`, where `other` crosses
/// `e`'s line, as `(X, Y, W)` with `W > 0`.
#[allow(clippy::type_complexity)]
fn inner_part_any(zero: Zero, e: E, other: E) -> Option<Option<(P, (I256, I256, I256))>> {
    let Part::From(keep) = inner_end(zero, e, other)? else {
        return Some(None);
    };
    // other.p1 + t·od on e's line: t = cross(ed, e.p1 - other.p1) / cross(ed, od).
    let ((ex, ey), (ox, oy)) = (e.d(), other.d());
    let (wx, wy) = (
        i128::from(e.p1.0 - other.p1.0),
        i128::from(e.p1.1 - other.p1.1),
    );
    let (mut num, mut den) = (ex * wy - ey * wx, ex * oy - ey * ox);
    if den < 0 {
        (num, den) = (-num, -den);
    }
    let w = I256::from_i128(den);
    let at = |p: i64, d: i128| {
        I256::from_i128(i128::from(p))
            .mul(w)
            .add(I256::from_i128(d).mul(I256::from_i128(num)))
    };
    Some(Some((keep, (at(other.p1.0, ox), at(other.p1.1, oy), w))))
}

/// [`pair_threshold2`] under the Euclidean metric at any angle, exact: the
/// least distance at which `KLayout` reports the pair, twice squared, as its
/// floor and whether the true value lies above it (a fraction where a skew
/// edge is involved). On octilinear edges it is `(pair_threshold2(..), false)`.
#[must_use]
pub fn pair_threshold_any(relation: Relation, zero: Zero, a: Seg, b: Seg) -> Option<(i128, bool)> {
    let (an, bn) = facing(relation, a, b)?;
    let second = near_any(zero, an, bn)?;
    let first = near_any(zero, bn, an)?;
    Some(first.max(second))
}
