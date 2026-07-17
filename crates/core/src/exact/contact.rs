//! Exact filled-area contact classification between simple rings.

use super::predicates::{classify_segment_intersection, PointClassification, SegmentIntersection};
use super::ring::{rotate_to_minimum, Ring};

/// Filled-area relationship of two simple polygon rings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolygonContact {
    Disjoint,
    /// Boundaries meet, but interiors do not overlap.
    Touch,
    /// The intersection has positive area (including equality/containment).
    AreaOverlap,
}

/// Classify two filled simple rings without using their bounding boxes as a decision.
pub fn classify_polygon_contact(a: &Ring, b: &Ring) -> PolygonContact {
    if !bbox_may_touch(a, b) {
        return PolygonContact::Disjoint;
    }

    let mut boundary_contact = false;
    for i in 0..a.vertices.len() {
        let a0 = a.vertices[i];
        let a1 = a.vertices[(i + 1) % a.vertices.len()];
        for j in 0..b.vertices.len() {
            let b0 = b.vertices[j];
            let b1 = b.vertices[(j + 1) % b.vertices.len()];
            match classify_segment_intersection(a0, a1, b0, b1) {
                SegmentIntersection::Proper => return PolygonContact::AreaOverlap,
                SegmentIntersection::Touch | SegmentIntersection::Overlap => {
                    boundary_contact = true;
                }
                SegmentIntersection::None => {}
            }
        }
    }

    // Vertices alone are insufficient for aligned containment (for example a
    // half-width rectangle whose four corners lie on the containing boundary).
    // Edge midpoints are exact rationals represented in doubled coordinates.
    if ring_has_strict_sample_inside(a, b) || ring_has_strict_sample_inside(b, a) {
        return PolygonContact::AreaOverlap;
    }
    if canonical_cycle_equal(a, b) {
        return PolygonContact::AreaOverlap;
    }
    if boundary_contact {
        PolygonContact::Touch
    } else {
        PolygonContact::Disjoint
    }
}

/// Boundary-only contact classification (no containment sampling); used to
/// validate hole placement against the outer ring.
pub(super) fn classify_ring_boundary_contact(a: &Ring, b: &Ring) -> PolygonContact {
    let mut touch = false;
    for i in 0..a.vertices.len() {
        let a0 = a.vertices[i];
        let a1 = a.vertices[(i + 1) % a.vertices.len()];
        for j in 0..b.vertices.len() {
            let b0 = b.vertices[j];
            let b1 = b.vertices[(j + 1) % b.vertices.len()];
            match classify_segment_intersection(a0, a1, b0, b1) {
                SegmentIntersection::Proper => return PolygonContact::AreaOverlap,
                SegmentIntersection::Touch | SegmentIntersection::Overlap => touch = true,
                SegmentIntersection::None => {}
            }
        }
    }
    if touch {
        PolygonContact::Touch
    } else {
        PolygonContact::Disjoint
    }
}

fn ring_has_strict_sample_inside(subject: &Ring, container: &Ring) -> bool {
    for i in 0..subject.vertices.len() {
        let a = subject.vertices[i];
        if container.classify_point(a) == PointClassification::Inside {
            return true;
        }
        let b = subject.vertices[(i + 1) % subject.vertices.len()];
        if container.classify_scaled2(a.x as i128 + b.x as i128, a.y as i128 + b.y as i128)
            == PointClassification::Inside
        {
            return true;
        }
    }
    false
}

fn canonical_cycle_equal(a: &Ring, b: &Ring) -> bool {
    if a.vertices.len() != b.vertices.len() {
        return false;
    }
    if a.vertices == b.vertices {
        return true;
    }
    let mut reversed = b.vertices.clone();
    reversed.reverse();
    rotate_to_minimum(&mut reversed);
    a.vertices == reversed
}

fn bbox_may_touch(a: &Ring, b: &Ring) -> bool {
    let bbox = |ring: &Ring| {
        let mut xmin = i32::MAX;
        let mut ymin = i32::MAX;
        let mut xmax = i32::MIN;
        let mut ymax = i32::MIN;
        for p in ring.vertices() {
            xmin = xmin.min(p.x);
            ymin = ymin.min(p.y);
            xmax = xmax.max(p.x);
            ymax = ymax.max(p.y);
        }
        (xmin, ymin, xmax, ymax)
    };
    let aa = bbox(a);
    let bb = bbox(b);
    aa.0 <= bb.2 && bb.0 <= aa.2 && aa.1 <= bb.3 && bb.1 <= aa.3
}
