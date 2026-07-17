//! Exact layout-geometry foundation.
//!
//! # Supported semantics
//!
//! Predicates in this module accept the complete `i32` coordinate domain and make
//! every topological decision with `i128` integer arithmetic. Rings are stored
//! without a repeated closing vertex, must be simple and non-degenerate, and may
//! contain arbitrary-angle edges. [`Polygon`] canonicalizes outer rings to
//! counter-clockwise winding and holes to clockwise winding. Holes must be
//! strictly contained and may not touch or overlap each other.
//!
//! Boolean union, intersection, and subtraction are exact for rectilinear input.
//! They build the arrangement induced by input x/y coordinates, classify each
//! open arrangement face, and reconstruct oriented boundaries. This is coordinate
//! decomposition, not a fixed-resolution raster: no rounding or sampling scale is
//! involved, and output vertices are input coordinates. Disconnected components,
//! holes, and boundary-connected cut-outs (often called keyholes/notches) are
//! preserved. Arbitrary-angle boolean input returns [`ExactGeometryError::Unsupported`].
//!
//! # Checker migration contract
//!
//! DRC/LVS callers may use a bbox only to reject impossible candidates. A candidate
//! that survives must be decided by these predicates or booleans. Unsupported
//! geometry and capacity limits are errors and must propagate to the run status;
//! callers must never substitute bbox overlap, a raster estimate, or `CLEAN`.
//! Arbitrary-angle booleans, exact offsets, and scalable sweep-line construction
//! remain future work, so this module intentionally exposes no approximate fallback.
//!
//! One public type per file: [`point`], [`predicates`], [`ring`], [`polygon`],
//! [`polygon_set`], [`contact`], [`boolean`], [`error`]. Everything is
//! re-exported here so `core::exact::X` paths are stable.

pub mod boolean;
pub mod contact;
pub mod error;
pub mod point;
pub mod polygon;
pub mod polygon_set;
pub mod predicates;
pub mod ring;

pub use boolean::{
    general_boolean, rectilinear_boolean, rectilinear_intersection, rectilinear_subtraction,
    rectilinear_union, BooleanOp, MAX_RECTILINEAR_BOOLEAN_CELLS, MAX_SWEEP_EVENTS,
};
pub use contact::{classify_polygon_contact, PolygonContact};
pub use error::ExactGeometryError;
pub use point::{
    on_segment, orientation, segment_intersection_rational, Orientation, Point, RationalPoint,
};
pub use polygon::{OffsetKernel, Polygon, MAX_BOUNDARY_WALK_VERTICES, MAX_BOUNDARY_WALK_WORK};
pub use polygon_set::PolygonSet;
pub use predicates::{
    classify_point_in_ring, classify_segment_intersection, PointClassification, SegmentIntersection,
};
pub use ring::{classify_edge, ring_signed_area2, EdgeKind, Ring, Winding};

#[cfg(test)]
mod tests {
    use super::*;

    fn p(x: i32, y: i32) -> Point {
        Point::new(x, y)
    }

    fn rectangle(x0: i32, y0: i32, x1: i32, y1: i32) -> PolygonSet {
        PolygonSet::from_polygon(
            Polygon::from_outer(vec![p(x0, y0), p(x1, y0), p(x1, y1), p(x0, y1)]).unwrap(),
        )
    }

    #[test]
    fn predicates_cover_extreme_coordinates_without_overflow() {
        let lo = i32::MIN;
        let hi = i32::MAX;
        assert_eq!(
            orientation(p(lo, lo), p(hi, lo), p(hi, hi)),
            Orientation::CounterClockwise
        );
        let ring = Ring::new(vec![p(lo, lo), p(hi, lo), p(hi, hi), p(lo, hi)]).unwrap();
        let span = hi as i128 - lo as i128;
        assert_eq!(ring.signed_area2(), 2 * span * span);
        assert_eq!(ring.classify_point(p(0, 0)), PointClassification::Inside);
    }

    #[test]
    fn boundary_walk_decomposition_is_orientation_invariant_and_multi_hole() {
        let points = vec![
            p(0, 0),
            p(100, 0),
            p(100, 100),
            p(70, 100),
            p(70, 80),
            p(90, 80),
            p(90, 60),
            p(60, 60),
            p(60, 80),
            p(70, 80),
            p(70, 100),
            p(40, 100),
            p(40, 80),
            p(50, 80),
            p(50, 60),
            p(20, 60),
            p(20, 80),
            p(40, 80),
            p(40, 100),
            p(0, 100),
        ];
        let polygon = Polygon::from_boundary_walk(points.clone()).unwrap();
        assert_eq!(polygon.holes().len(), 2);
        assert_eq!(polygon.area2(), 17_600);

        let reversed = Polygon::from_boundary_walk(points.into_iter().rev().collect()).unwrap();
        assert_eq!(reversed, polygon);
    }

    #[test]
    fn boundary_walk_rejects_external_and_disjoint_retraced_lobes() {
        let external = vec![
            p(0, 0),
            p(-5, 0),
            p(-5, -5),
            p(-10, -5),
            p(-10, 0),
            p(-5, 0),
            p(0, 0),
            p(10, 0),
            p(10, 10),
            p(0, 10),
        ];
        assert!(matches!(
            Polygon::from_boundary_walk(external),
            Err(ExactGeometryError::InvalidBoundaryWalk(_))
        ));

        let disjoint = vec![
            p(10, 5),
            p(20, 5),
            p(20, 10),
            p(30, 10),
            p(30, 0),
            p(20, 0),
            p(20, 5),
            p(10, 5),
            p(10, 10),
            p(0, 10),
            p(0, 0),
            p(10, 0),
        ];
        assert!(matches!(
            Polygon::from_boundary_walk(disjoint),
            Err(ExactGeometryError::InvalidBoundaryWalk(_))
        ));

        let same_polarity = vec![
            p(0, 0),
            p(10, 0),
            p(10, 10),
            p(5, 10),
            p(5, 8),
            p(3, 8),
            p(3, 3),
            p(8, 3),
            p(8, 8),
            p(5, 8),
            p(5, 10),
            p(0, 10),
        ];
        assert!(matches!(
            Polygon::from_boundary_walk(same_polarity),
            Err(ExactGeometryError::InvalidBoundaryWalk(_))
        ));
    }

    #[test]
    fn boundary_walk_vertex_and_pair_work_limits_are_typed() {
        let oversized = vec![p(0, 0); MAX_BOUNDARY_WALK_VERTICES + 1];
        assert!(matches!(
            Polygon::from_boundary_walk(oversized),
            Err(ExactGeometryError::CapacityExceeded { cells, limit })
                if cells == MAX_BOUNDARY_WALK_VERTICES + 1
                    && limit == MAX_BOUNDARY_WALK_VERTICES
        ));

        // No reverse edges: decomposition must scan the pairs, then charge the
        // simple-ring validation rather than entering unbounded O(n²) work.
        let work_limited = (0..4_000)
            .map(|index| p(index, if index % 2 == 0 { 0 } else { 1 }))
            .collect();
        assert!(matches!(
            Polygon::from_boundary_walk(work_limited),
            Err(ExactGeometryError::CapacityExceeded { limit, .. })
                if limit == MAX_BOUNDARY_WALK_WORK
        ));
    }

    #[test]
    fn segment_classification_distinguishes_cross_touch_and_overlap() {
        assert_eq!(
            classify_segment_intersection(p(0, 0), p(4, 4), p(0, 4), p(4, 0)),
            SegmentIntersection::Proper
        );
        assert_eq!(
            classify_segment_intersection(p(0, 0), p(4, 0), p(4, 0), p(4, 4)),
            SegmentIntersection::Touch
        );
        assert_eq!(
            classify_segment_intersection(p(0, 0), p(4, 0), p(2, 0), p(6, 0)),
            SegmentIntersection::Overlap
        );
        assert_eq!(
            classify_segment_intersection(p(0, 0), p(1, 0), p(2, 0), p(3, 0)),
            SegmentIntersection::None
        );
    }

    #[test]
    fn ring_validation_rejects_degeneracy_and_self_contact() {
        assert!(matches!(
            Ring::new(vec![p(0, 0), p(1, 0), p(2, 0)]),
            Err(ExactGeometryError::TooFewVertices { .. })
                | Err(ExactGeometryError::DegenerateRing)
                | Err(ExactGeometryError::SelfIntersection { .. })
        ));
        assert!(matches!(
            Ring::new(vec![p(0, 0), p(4, 4), p(0, 4), p(4, 0)]),
            Err(ExactGeometryError::SelfIntersection {
                kind: SegmentIntersection::Proper,
                ..
            })
        ));
        assert!(matches!(
            Ring::new(vec![p(0, 0), p(4, 0), p(2, 0), p(2, 2), p(0, 2)]),
            Err(ExactGeometryError::SelfIntersection { .. })
        ));
    }

    #[test]
    fn polygon_canonicalizes_reversed_winding_and_validates_holes() {
        let outer = Ring::new(vec![p(0, 0), p(0, 10), p(10, 10), p(10, 0)]).unwrap();
        let hole = Ring::new(vec![p(2, 2), p(8, 2), p(8, 8), p(2, 8)]).unwrap();
        let polygon = Polygon::new(outer, vec![hole]).unwrap();
        assert_eq!(polygon.outer().winding(), Winding::CounterClockwise);
        assert_eq!(polygon.holes()[0].winding(), Winding::Clockwise);
        assert_eq!(polygon.area2(), 128);
        assert_eq!(polygon.classify_point(p(1, 1)), PointClassification::Inside);
        assert_eq!(
            polygon.classify_point(p(5, 5)),
            PointClassification::Outside
        );

        let touching = Ring::new(vec![p(0, 2), p(2, 2), p(2, 4), p(0, 4)]).unwrap();
        assert!(matches!(
            Polygon::new(polygon.outer().clone(), vec![touching]),
            Err(ExactGeometryError::HoleTouchesOuter { .. })
        ));
    }

    #[test]
    fn polygon_contact_rejects_the_concave_bbox_trap() {
        let concave = Ring::new(vec![
            p(0, 0),
            p(10, 0),
            p(10, 2),
            p(2, 2),
            p(2, 10),
            p(0, 10),
        ])
        .unwrap();
        let in_bbox_but_disjoint = Ring::new(vec![p(4, 4), p(9, 4), p(9, 9), p(4, 9)]).unwrap();
        assert_eq!(
            classify_polygon_contact(&concave, &in_bbox_but_disjoint),
            PolygonContact::Disjoint
        );
        let edge_touch = Ring::new(vec![p(2, 4), p(4, 4), p(4, 6), p(2, 6)]).unwrap();
        assert_eq!(
            classify_polygon_contact(&concave, &edge_touch),
            PolygonContact::Touch
        );
    }

    #[test]
    fn rectilinear_booleans_preserve_holes_keyholes_and_components() {
        let outer = rectangle(0, 0, 10, 10);
        let inner = rectangle(2, 2, 8, 8);
        let donut = rectilinear_subtraction(&outer, &inner).unwrap();
        assert_eq!(donut.component_count(), 1);
        assert_eq!(donut.polygons()[0].holes().len(), 1);
        assert_eq!(donut.area2(), 128);

        let boundary_cut = rectangle(0, 3, 6, 7);
        let keyhole = rectilinear_subtraction(&outer, &boundary_cut).unwrap();
        assert_eq!(keyhole.component_count(), 1);
        assert!(keyhole.polygons()[0].holes().is_empty());
        assert_eq!(
            keyhole.classify_point(p(1, 5)),
            PointClassification::Outside
        );
        assert_eq!(keyhole.classify_point(p(8, 5)), PointClassification::Inside);

        let disjoint = rectilinear_union(&rectangle(0, 0, 2, 2), &rectangle(5, 0, 7, 2)).unwrap();
        assert_eq!(disjoint.component_count(), 2);
        assert_eq!(disjoint.area2(), 16);

        let splitter = rectangle(4, -1, 6, 11);
        let split = rectilinear_subtraction(&outer, &splitter).unwrap();
        assert_eq!(split.component_count(), 2);
        assert_eq!(split.area2(), 160);
    }

    #[test]
    fn corner_touch_stays_disconnected_and_edge_touch_merges() {
        let a = rectangle(0, 0, 2, 2);
        let corner = rectilinear_union(&a, &rectangle(2, 2, 4, 4)).unwrap();
        assert_eq!(corner.component_count(), 2);
        let edge = rectilinear_union(&a, &rectangle(2, 0, 4, 2)).unwrap();
        assert_eq!(edge.component_count(), 1);
        assert_eq!(edge.polygons()[0].outer().vertices().len(), 4);
    }

    #[test]
    fn arbitrary_angle_rectilinear_boolean_fails_closed() {
        // The rectilinear-only entry point still rejects non-rectilinear input.
        let triangle =
            PolygonSet::from_polygon(Polygon::from_outer(vec![p(0, 0), p(4, 0), p(2, 3)]).unwrap());
        let err = rectilinear_union(&triangle, &rectangle(0, 0, 1, 1)).unwrap_err();
        assert_eq!(
            err,
            ExactGeometryError::Unsupported {
                operation: BooleanOp::Union,
                reason: "arbitrary-angle boolean topology is not implemented",
            }
        );
    }

    // -----------------------------------------------------------------------
    // General (all-angle) boolean tests
    // -----------------------------------------------------------------------

    fn triangle(x0: i32, y0: i32, x1: i32, y1: i32, x2: i32, y2: i32) -> PolygonSet {
        PolygonSet::from_polygon(
            Polygon::from_outer(vec![p(x0, y0), p(x1, y1), p(x2, y2)]).unwrap(),
        )
    }

    #[test]
    fn general_boolean_triangle_union_with_rectangle() {
        let tri = triangle(0, 0, 10, 0, 5, 8);
        let rect = rectangle(3, -2, 7, 4);
        let result = general_boolean(&tri, &rect, BooleanOp::Union).unwrap();
        // The result should contain all points that are in either shape.
        assert_eq!(
            result.classify_point(p(5, 2)),
            PointClassification::Inside,
            "center of overlap"
        );
        assert_eq!(
            result.classify_point(p(5, 6)),
            PointClassification::Inside,
            "inside triangle only"
        );
        assert_eq!(
            result.classify_point(p(5, -1)),
            PointClassification::Inside,
            "inside rectangle only"
        );
        assert_eq!(
            result.classify_point(p(0, 8)),
            PointClassification::Outside,
            "outside both"
        );
    }

    #[test]
    fn general_boolean_two_overlapping_triangles_intersection() {
        let t1 = triangle(0, 0, 10, 0, 5, 10);
        let t2 = triangle(0, 5, 10, 5, 5, -5);
        let result = general_boolean(&t1, &t2, BooleanOp::Intersection).unwrap();
        // The intersection region should be a quadrilateral around the center.
        assert_eq!(
            result.classify_point(p(5, 4)),
            PointClassification::Inside,
            "center of intersection"
        );
        assert_eq!(
            result.classify_point(p(5, 9)),
            PointClassification::Outside,
            "inside t1 only"
        );
        assert_eq!(
            result.classify_point(p(5, -3)),
            PointClassification::Outside,
            "inside t2 only"
        );
    }

    #[test]
    fn general_boolean_subtraction_rect_minus_triangle() {
        let rect = rectangle(0, 0, 10, 10);
        let tri = triangle(2, 2, 8, 2, 5, 8);
        let result = general_boolean(&rect, &tri, BooleanOp::Subtraction).unwrap();
        // Inside rectangle but outside triangle.
        assert_eq!(
            result.classify_point(p(1, 1)),
            PointClassification::Inside,
            "corner of rect, outside tri"
        );
        // Inside triangle.
        assert_eq!(
            result.classify_point(p(5, 4)),
            PointClassification::Outside,
            "inside triangle = subtracted"
        );
    }

    #[test]
    fn general_boolean_rectilinear_still_uses_fast_path_via_convenience() {
        // The PolygonSet convenience methods should dispatch rectilinear to the fast path.
        let a = rectangle(0, 0, 4, 4);
        let b = rectangle(2, 2, 6, 6);
        let union = a.union(&b).unwrap();
        assert_eq!(union.classify_point(p(1, 1)), PointClassification::Inside);
        assert_eq!(union.classify_point(p(5, 5)), PointClassification::Inside);
        assert_eq!(union.classify_point(p(7, 7)), PointClassification::Outside);
    }

    #[test]
    fn general_boolean_touching_vertices() {
        // Two triangles sharing a vertex.
        let t1 = triangle(0, 0, 4, 0, 2, 3);
        let t2 = triangle(4, 0, 8, 0, 6, 3);
        let result = general_boolean(&t1, &t2, BooleanOp::Union).unwrap();
        assert_eq!(
            result.component_count(),
            2,
            "touching at a vertex = two components"
        );
        assert_eq!(result.classify_point(p(1, 1)), PointClassification::Inside);
        assert_eq!(result.classify_point(p(6, 1)), PointClassification::Inside);
    }

    #[test]
    fn general_boolean_collinear_edges_at_intersection() {
        // Rectangle and triangle sharing part of an edge.
        let rect = rectangle(0, 0, 6, 4);
        let tri = triangle(2, 4, 8, 4, 5, 8);
        let result = general_boolean(&rect, &tri, BooleanOp::Union).unwrap();
        assert_eq!(
            result.classify_point(p(3, 3)),
            PointClassification::Inside,
            "inside rect"
        );
        assert_eq!(
            result.classify_point(p(5, 6)),
            PointClassification::Inside,
            "inside tri"
        );
    }

    #[test]
    fn general_boolean_empty_inputs() {
        let empty = PolygonSet::empty();
        let tri = triangle(0, 0, 4, 0, 2, 3);
        assert_eq!(
            general_boolean(&empty, &tri, BooleanOp::Union).unwrap(),
            tri
        );
        assert_eq!(
            general_boolean(&tri, &empty, BooleanOp::Subtraction).unwrap(),
            tri
        );
        assert_eq!(
            general_boolean(&empty, &tri, BooleanOp::Intersection)
                .unwrap()
                .component_count(),
            0
        );
    }

    // -----------------------------------------------------------------------
    // RationalPoint / segment_intersection_rational tests
    // -----------------------------------------------------------------------

    #[test]
    fn segment_intersection_rational_proper_crossing() {
        let rp = segment_intersection_rational(p(0, 0), p(4, 4), p(0, 4), p(4, 0));
        assert!(rp.is_some());
        let rp = rp.unwrap();
        let snapped = rp.try_snap().unwrap();
        assert_eq!(snapped, p(2, 2));
    }

    #[test]
    fn segment_intersection_rational_no_crossing() {
        // Parallel lines.
        assert!(segment_intersection_rational(p(0, 0), p(4, 0), p(0, 2), p(4, 2)).is_none());
        // Touching at endpoint.
        assert!(segment_intersection_rational(p(0, 0), p(2, 2), p(2, 2), p(4, 0)).is_none());
    }

    // -----------------------------------------------------------------------
    // EdgeKind tests
    // -----------------------------------------------------------------------

    #[test]
    fn classify_edge_kinds() {
        assert_eq!(classify_edge(p(0, 0), p(5, 0)), EdgeKind::Horizontal);
        assert_eq!(classify_edge(p(0, 0), p(0, 5)), EdgeKind::Vertical);
        assert_eq!(classify_edge(p(0, 0), p(3, 3)), EdgeKind::Diagonal45);
        assert_eq!(classify_edge(p(0, 0), p(3, -3)), EdgeKind::Diagonal45);
        assert_eq!(classify_edge(p(0, 0), p(3, 5)), EdgeKind::Arbitrary);
    }

    // -----------------------------------------------------------------------
    // Offset tests
    // -----------------------------------------------------------------------

    #[test]
    fn offset_rectangle_square_kernel() {
        let poly = Polygon::from_outer(vec![p(0, 0), p(4, 0), p(4, 4), p(0, 4)]).unwrap();
        let result = poly.offset(1, OffsetKernel::Square).unwrap();
        // A 4×4 square offset by 1 with square kernel should cover at least
        // the original area plus the corner squares.
        assert_eq!(
            result.classify_point(p(2, 2)),
            PointClassification::Inside,
            "original interior"
        );
        // The corner square at (-1,-1) to (1,1) should be in the result.
        // Test (0,0): it's a vertex of the original rect but strictly inside
        // the corner square, hence strictly inside the union.
        assert_eq!(
            result.classify_point(p(0, 0)),
            PointClassification::Inside,
            "corner offset covers original vertex"
        );
        // The corner point itself is on the boundary of the union.
        assert!(
            result.classify_point(p(-1, -1)) != PointClassification::Outside,
            "corner of offset region is not outside"
        );
    }

    #[test]
    fn offset_zero_is_identity() {
        let poly = Polygon::from_outer(vec![p(0, 0), p(4, 0), p(4, 4), p(0, 4)]).unwrap();
        let result = poly.offset(0, OffsetKernel::Square).unwrap();
        assert_eq!(result.component_count(), 1);
        assert_eq!(result.polygons()[0].area2(), poly.area2());
    }

    // -----------------------------------------------------------------------
    // Fracture tests
    // -----------------------------------------------------------------------

    #[test]
    fn fracture_concave_polygon() {
        // L-shape: concave polygon with 6 vertices.
        let poly = Polygon::from_outer(vec![p(0, 0), p(4, 0), p(4, 2), p(2, 2), p(2, 4), p(0, 4)])
            .unwrap();
        let pieces = poly.deterministic_fracture().unwrap();
        assert!(
            pieces.len() >= 2,
            "concave polygon should produce multiple triangles"
        );
        // Total area should be preserved.
        let total_area: i128 = pieces.iter().map(|p| p.area2()).sum();
        assert_eq!(total_area, poly.area2());
    }

    #[test]
    fn fracture_triangle_is_identity() {
        let poly = Polygon::from_outer(vec![p(0, 0), p(4, 0), p(2, 3)]).unwrap();
        let pieces = poly.deterministic_fracture().unwrap();
        assert_eq!(pieces.len(), 1);
    }

    #[derive(Clone, Copy)]
    struct LShape {
        ox: i32,
        oy: i32,
        width: i32,
        height: i32,
        cut_x: i32,
        cut_y: i32,
    }

    impl LShape {
        fn polygon(self) -> PolygonSet {
            let x = self.ox;
            let y = self.oy;
            let w = self.width;
            let h = self.height;
            let cx = self.cut_x;
            let cy = self.cut_y;
            PolygonSet::from_polygon(
                Polygon::from_outer(vec![
                    p(x, y),
                    p(x + w, y),
                    p(x + w, y + cy),
                    p(x + cx, y + cy),
                    p(x + cx, y + h),
                    p(x, y + h),
                ])
                .unwrap(),
            )
        }

        /// Independent unit-cell oracle: bounding rectangle minus the top-right cutout.
        fn covers_cell(self, x: i32, y: i32) -> bool {
            let local_x = x - self.ox;
            let local_y = y - self.oy;
            local_x >= 0
                && local_y >= 0
                && local_x < self.width
                && local_y < self.height
                && !(local_x >= self.cut_x && local_y >= self.cut_y)
        }
    }

    fn next(seed: &mut u64) -> u32 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (*seed >> 32) as u32
    }

    #[test]
    fn randomized_rectilinear_differential_against_independent_cell_oracle() {
        let mut seed = 0x5eed_cafe_d15c_a11u64;
        for case in 0..250 {
            let make = |seed: &mut u64| {
                let width = 2 + (next(seed) % 5) as i32;
                let height = 2 + (next(seed) % 5) as i32;
                LShape {
                    ox: (next(seed) % 7) as i32 - 3,
                    oy: (next(seed) % 7) as i32 - 3,
                    width,
                    height,
                    cut_x: 1 + (next(seed) % (width as u32 - 1)) as i32,
                    cut_y: 1 + (next(seed) % (height as u32 - 1)) as i32,
                }
            };
            let a = make(&mut seed);
            let b = make(&mut seed);
            for operation in [
                BooleanOp::Union,
                BooleanOp::Intersection,
                BooleanOp::Subtraction,
            ] {
                let actual = rectilinear_boolean(&a.polygon(), &b.polygon(), operation)
                    .unwrap_or_else(|e| panic!("case {case} {operation:?}: {e}"));
                for y in -4..9 {
                    for x in -4..9 {
                        let expected = match operation {
                            BooleanOp::Union => a.covers_cell(x, y) || b.covers_cell(x, y),
                            BooleanOp::Intersection => a.covers_cell(x, y) && b.covers_cell(x, y),
                            BooleanOp::Subtraction => a.covers_cell(x, y) && !b.covers_cell(x, y),
                        };
                        let got = actual.classify_scaled2(x as i128 * 2 + 1, y as i128 * 2 + 1)
                            == PointClassification::Inside;
                        assert_eq!(got, expected, "case {case} {operation:?} cell ({x},{y})");
                    }
                }
            }
        }
    }
}
