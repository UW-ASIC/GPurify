//! Exact classification predicates: segment/segment topology and point-in-ring.

use super::point::{cross, on_segment, Point};

/// The exact topological relationship between two closed segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentIntersection {
    None,
    /// A single shared endpoint or a point-on-segment contact.
    Touch,
    /// Interior points of both non-collinear segments cross.
    Proper,
    /// A collinear interval of positive length is shared.
    Overlap,
}

/// Classification of a point against a simple ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointClassification {
    Outside,
    Boundary,
    Inside,
}

/// Classify the intersection of two closed segments exactly.
#[must_use]
pub fn classify_segment_intersection(
    a0: Point,
    a1: Point,
    b0: Point,
    b1: Point,
) -> SegmentIntersection {
    if a0.x.max(a1.x) < b0.x.min(b1.x)
        || b0.x.max(b1.x) < a0.x.min(a1.x)
        || a0.y.max(a1.y) < b0.y.min(b1.y)
        || b0.y.max(b1.y) < a0.y.min(a1.y)
    {
        return SegmentIntersection::None;
    }

    let o1 = cross(a0, a1, b0);
    let o2 = cross(a0, a1, b1);
    let o3 = cross(b0, b1, a0);
    let o4 = cross(b0, b1, a1);

    if o1 == 0 && o2 == 0 && o3 == 0 && o4 == 0 {
        let use_x = a0.x != a1.x || b0.x != b1.x;
        let (a_lo, a_hi, b_lo, b_hi) = if use_x {
            (
                a0.x.min(a1.x),
                a0.x.max(a1.x),
                b0.x.min(b1.x),
                b0.x.max(b1.x),
            )
        } else {
            (
                a0.y.min(a1.y),
                a0.y.max(a1.y),
                b0.y.min(b1.y),
                b0.y.max(b1.y),
            )
        };
        let lo = a_lo.max(b_lo);
        let hi = a_hi.min(b_hi);
        return if lo < hi {
            SegmentIntersection::Overlap
        } else if lo == hi {
            SegmentIntersection::Touch
        } else {
            SegmentIntersection::None
        };
    }

    if opposite_signs(o1, o2) && opposite_signs(o3, o4) {
        return SegmentIntersection::Proper;
    }
    if (o1 == 0 && on_segment(a0, a1, b0))
        || (o2 == 0 && on_segment(a0, a1, b1))
        || (o3 == 0 && on_segment(b0, b1, a0))
        || (o4 == 0 && on_segment(b0, b1, a1))
    {
        SegmentIntersection::Touch
    } else {
        SegmentIntersection::None
    }
}

#[inline]
fn opposite_signs(a: i128, b: i128) -> bool {
    (a < 0 && b > 0) || (a > 0 && b < 0)
}

/// Classify an integer point against a simple ring.
#[must_use]
pub fn classify_point_in_ring(points: &[Point], p: Point) -> PointClassification {
    classify_point_scaled2(points, p.x as i128 * 2, p.y as i128 * 2)
}

/// Point-in-ring over doubled coordinates, so edge midpoints (exact rationals)
/// can be classified without rounding.
pub(super) fn classify_point_scaled2(
    points: &[Point],
    px2: i128,
    py2: i128,
) -> PointClassification {
    let mut inside = false;
    for i in 0..points.len() {
        let a = points[i];
        let b = points[(i + 1) % points.len()];
        let ax2 = a.x as i128 * 2;
        let ay2 = a.y as i128 * 2;
        let bx2 = b.x as i128 * 2;
        let by2 = b.y as i128 * 2;
        let det = (bx2 - ax2) * (py2 - ay2) - (by2 - ay2) * (px2 - ax2);
        if det == 0
            && px2 >= ax2.min(bx2)
            && px2 <= ax2.max(bx2)
            && py2 >= ay2.min(by2)
            && py2 <= ay2.max(by2)
        {
            return PointClassification::Boundary;
        }
        if (ay2 > py2) != (by2 > py2) && ((by2 > ay2 && det > 0) || (by2 < ay2 && det < 0)) {
            inside = !inside;
        }
    }
    if inside {
        PointClassification::Inside
    } else {
        PointClassification::Outside
    }
}
