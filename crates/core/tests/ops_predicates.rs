//! Exact predicates: orientation, segment intersection, point-in-ring,
//! simplicity, signed area, distances, and the integer square root.
//!
//! The module's own doc comment records where the previous implementation's
//! mutation survivors lived — eleven in `segments_intersect`, nine in the
//! self-intersection check, six in point-in-polygon, one in `isqrt`. Every one
//! of those is a degenerate case, so the cases below are degenerate on purpose:
//! collinear triples, shared endpoints, overlapping collinear segments, points
//! exactly on a boundary, and perfect squares with their immediate neighbours.

use gpurify_core::ops::{
    area2, isqrt, orientation, point_in_ring, point_seg_dist2, seg_seg_dist2, segments_intersect,
    self_intersects, winding_of, Orientation, Seg, Winding,
};
use gpurify_core::view::{validate_layer_into, ValidatedLayer};
use gpurify_core::{GeometryStore, LayerId};
use gpurify_testgen::shapes::{
    dbu, l_shape, l_shape_area, plus_shape, plus_shape_area, point, rect, u_shape, u_shape_area,
    LayoutBuilder,
};
use gpurify_testgen::Rng;
use gpurify_units::{Dbu, DbuArea, MAX_ABS_DBU};

const LAYER: LayerId = LayerId(0);

/// A coordinate run as the generator hands it over: parallel `i64` columns.
type Shape = (Vec<i64>, Vec<i64>);

/// Three points, as the `i64` pairs the test chose them from.
type Triple = ((i64, i64), (i64, i64), (i64, i64));

fn seg(ax: i64, ay: i64, bx: i64, by: i64) -> Seg {
    Seg {
        a: point(ax, ay),
        b: point(bx, by),
    }
}

fn coords(shape: &Shape) -> (Vec<Dbu>, Vec<Dbu>) {
    (
        shape.0.iter().copied().map(dbu).collect(),
        shape.1.iter().copied().map(dbu).collect(),
    )
}

/// Twice the signed area by the shoelace formula in `i128`, so the expected
/// value is computed here and not read back out of the code under test.
fn shoelace(shape: &Shape) -> i128 {
    let (xs, ys) = shape;
    (0..xs.len())
        .map(|i| {
            let j = (i + 1) % xs.len();
            i128::from(xs[i]) * i128::from(ys[j]) - i128::from(xs[j]) * i128::from(ys[i])
        })
        .sum()
}

/// Cross product of `b - a` and `c - a`, over the `i64` coordinates the test
/// chose rather than over the `Dbu` it handed to the predicate.
fn cross(a: (i64, i64), b: (i64, i64), c: (i64, i64)) -> i128 {
    i128::from(b.0 - a.0) * i128::from(c.1 - a.1) - i128::from(b.1 - a.1) * i128::from(c.0 - a.0)
}

fn reverse(o: Orientation) -> Orientation {
    match o {
        Orientation::Clockwise => Orientation::CounterClockwise,
        Orientation::CounterClockwise => Orientation::Clockwise,
        Orientation::Collinear => Orientation::Collinear,
    }
}

fn flip(s: Seg) -> Seg {
    Seg { a: s.b, b: s.a }
}

/// One shape on layer zero, validated. The store must outlive the layer, so
/// both come back together and the caller borrows from the pair.
fn validated(shape: &Shape) -> (GeometryStore, ValidatedLayer) {
    let mut layout = LayoutBuilder::new(1);
    layout.shape(LAYER, shape);
    let (store, _ids) = layout.finish();
    let mut layer = ValidatedLayer::default();
    validate_layer_into(&store, LAYER, &mut layer).expect("a generated shape is valid");
    (store, layer)
}

/// Oracle: closed form. Orientation is the sign of the cross product of
/// `b - a` and `c - a`, which the test computes directly in `i128` from the
/// coordinates it chose. Eight of the fixed cases are collinear, which is where
/// every one of the old survivors lived.
#[test]
fn orientation_is_the_sign_of_the_cross_product() {
    let mut rng = Rng::new(21);
    let mut cases: Vec<Triple> = vec![
        ((0, 0), (10, 0), (20, 0)),
        ((0, 0), (10, 0), (-10, 0)),
        ((0, 0), (0, 10), (0, 20)),
        ((0, 0), (3, 3), (7, 7)),
        ((0, 0), (7, 7), (3, 3)),
        ((5, 5), (5, 5), (9, 1)),
        ((5, 5), (9, 1), (5, 5)),
        ((5, 5), (5, 5), (5, 5)),
        ((0, 0), (10, 0), (0, 10)),
        ((0, 0), (0, 10), (10, 0)),
    ];
    for _ in 0..300 {
        let mut draw = || (rng.range(-50, 50), rng.range(-50, 50));
        cases.push((draw(), draw(), draw()));
    }

    let mut collinear = 0u32;
    for &(a, b, c) in &cases {
        let turn = cross(a, b, c);
        let expected = match turn {
            n if n > 0 => Orientation::CounterClockwise,
            n if n < 0 => Orientation::Clockwise,
            _ => Orientation::Collinear,
        };
        collinear += u32::from(turn == 0);
        assert_eq!(
            orientation(point(a.0, a.1), point(b.0, b.1), point(c.0, c.1)),
            expected,
            "{a:?} {b:?} {c:?} has cross product {turn}"
        );
    }
    assert!(collinear >= 8, "the corpus lost its collinear cases");
}

/// Oracle: law. Swapping two of the three points reverses a turn and leaves a
/// collinear triple collinear, for every triple. A predicate with one
/// comparison backwards satisfies whatever fixture it was written against and
/// fails this.
#[test]
fn orientation_reverses_when_two_points_are_swapped() {
    let mut rng = Rng::new(22);
    for _ in 0..400 {
        let a = point(rng.range(-40, 40), rng.range(-40, 40));
        let b = point(rng.range(-40, 40), rng.range(-40, 40));
        let c = point(rng.range(-40, 40), rng.range(-40, 40));
        let forward = orientation(a, b, c);
        assert_eq!(orientation(a, c, b), reverse(forward), "swapped b and c");
        assert_eq!(orientation(b, a, c), reverse(forward), "swapped a and b");
        assert_eq!(orientation(c, b, a), reverse(forward), "swapped a and c");
        // A cyclic rotation is two swaps, so it leaves the orientation alone.
        assert_eq!(orientation(b, c, a), forward, "rotated once");
        assert_eq!(orientation(c, a, b), forward, "rotated twice");
    }
}

/// Oracle: construct-from-answer. Shapes in a real layout touch constantly, so
/// the endpoint and collinear cases decide whether a spacing rule sees a pair at
/// all. Each assertion names the configuration it is, and the disjoint cases sit
/// one database unit clear of the touching ones.
#[test]
fn segments_intersect_covers_endpoints_and_collinear_overlap() {
    // Proper crossing: the interiors meet at one point.
    assert!(segments_intersect(seg(0, 0, 10, 10), seg(0, 10, 10, 0)));

    // A shared endpoint, in each of the four ways two endpoints can pair up.
    assert!(segments_intersect(seg(0, 0, 10, 0), seg(10, 0, 10, 10)));
    assert!(segments_intersect(seg(0, 0, 10, 0), seg(10, 10, 10, 0)));
    assert!(segments_intersect(seg(10, 0, 0, 0), seg(10, 0, 10, 10)));
    assert!(segments_intersect(seg(10, 0, 0, 0), seg(10, 10, 10, 0)));

    // T-junction: an endpoint lands in the other segment's interior.
    assert!(segments_intersect(seg(0, 0, 10, 0), seg(5, 0, 5, 10)));
    assert!(segments_intersect(seg(5, 0, 5, 10), seg(0, 0, 10, 0)));

    // Collinear, overlapping over a run of points, in every operand order.
    assert!(segments_intersect(seg(0, 0, 10, 0), seg(5, 0, 15, 0)));
    assert!(segments_intersect(seg(0, 0, 10, 0), seg(2, 0, 8, 0)));
    assert!(segments_intersect(seg(2, 0, 8, 0), seg(0, 0, 10, 0)));
    assert!(segments_intersect(seg(0, 0, 10, 0), seg(15, 0, 5, 0)));
    assert!(segments_intersect(seg(0, 0, 0, 10), seg(0, 4, 0, 20)));

    // Collinear, meeting at exactly one shared endpoint.
    assert!(segments_intersect(seg(0, 0, 10, 0), seg(10, 0, 20, 0)));

    // Collinear and clear by one unit — the boundary that decides the rule.
    assert!(!segments_intersect(seg(0, 0, 10, 0), seg(11, 0, 20, 0)));
    assert!(!segments_intersect(seg(0, 0, 0, 10), seg(0, 11, 0, 20)));

    // Parallel, never meeting.
    assert!(!segments_intersect(seg(0, 0, 10, 0), seg(0, 1, 10, 1)));

    // Skew: the lines cross, but outside both segments.
    assert!(!segments_intersect(seg(0, 0, 4, 4), seg(6, 0, 10, 10)));

    // Degenerate segments: a point on the other segment, and a point beside it.
    assert!(segments_intersect(seg(5, 0, 5, 0), seg(0, 0, 10, 0)));
    assert!(segments_intersect(seg(5, 0, 5, 0), seg(5, 0, 5, 0)));
    assert!(!segments_intersect(seg(5, 1, 5, 1), seg(0, 0, 10, 0)));
    assert!(!segments_intersect(seg(5, 1, 5, 1), seg(9, 9, 9, 9)));
}

/// Oracle: law. Sharing a point is symmetric and does not depend on which end
/// of a segment is called `a`, so all four rewritings of a pair agree for
/// arbitrary segments. The old survivors were asymmetric checks that read one
/// operand's endpoints and not the other's.
#[test]
fn segment_intersection_is_symmetric_in_both_operands_and_both_endpoints() {
    let mut rng = Rng::new(23);
    let mut met = 0u32;
    for _ in 0..600 {
        // A tight coordinate range so collinear and touching cases actually
        // occur instead of being astronomically unlikely.
        let mut draw = || {
            seg(
                rng.range(-6, 6),
                rng.range(-6, 6),
                rng.range(-6, 6),
                rng.range(-6, 6),
            )
        };
        let (p, q) = (draw(), draw());
        let base = segments_intersect(p, q);
        met += u32::from(base);
        assert_eq!(
            base,
            segments_intersect(q, p),
            "{p:?} {q:?} is not symmetric"
        );
        assert_eq!(base, segments_intersect(flip(p), q), "flipping p mattered");
        assert_eq!(base, segments_intersect(p, flip(q)), "flipping q mattered");
    }
    assert!(
        met > 0,
        "no generated pair intersected; the corpus is useless"
    );
}

/// Oracle: law. Two segments share a point exactly when the distance between
/// them is zero. Two independently written predicates agreeing over arbitrary
/// input is a stronger claim than either agreeing with a fixture.
#[test]
fn segments_touch_exactly_when_their_distance_is_zero() {
    let mut rng = Rng::new(24);
    for _ in 0..600 {
        let mut draw = || {
            seg(
                rng.range(-6, 6),
                rng.range(-6, 6),
                rng.range(-6, 6),
                rng.range(-6, 6),
            )
        };
        let (p, q) = (draw(), draw());
        assert_eq!(
            seg_seg_dist2(p, q) == DbuArea::new(0),
            segments_intersect(p, q),
            "distance and intersection disagree on {p:?} and {q:?}"
        );
        assert_eq!(seg_seg_dist2(p, q), seg_seg_dist2(q, p), "not symmetric");
    }
}

/// Oracle: closed form. The squared distance from a point to a segment is
/// either the perpendicular drop, when the foot lands inside the segment, or
/// the nearer endpoint. Both branches are written out, plus the degenerate
/// segment where they coincide.
#[test]
fn point_to_segment_distance_is_the_perpendicular_or_the_nearer_endpoint() {
    let base = seg(0, 0, 10, 0);
    // Perpendicular foot inside the segment.
    assert_eq!(point_seg_dist2(point(5, 10), base), DbuArea::new(100));
    assert_eq!(point_seg_dist2(point(0, 3), base), DbuArea::new(9));
    assert_eq!(point_seg_dist2(point(10, 4), base), DbuArea::new(16));
    // Foot beyond an endpoint: the answer is that endpoint's distance.
    assert_eq!(point_seg_dist2(point(-5, 0), base), DbuArea::new(25));
    assert_eq!(point_seg_dist2(point(15, 0), base), DbuArea::new(25));
    assert_eq!(point_seg_dist2(point(-3, 4), base), DbuArea::new(25));
    assert_eq!(point_seg_dist2(point(13, 4), base), DbuArea::new(25));
    // On the segment, both endpoints included.
    for x in [0, 1, 5, 9, 10] {
        assert_eq!(point_seg_dist2(point(x, 0), base), DbuArea::new(0));
    }
    // A degenerate segment is a point.
    let dot = seg(4, 4, 4, 4);
    assert_eq!(point_seg_dist2(point(4, 4), dot), DbuArea::new(0));
    assert_eq!(point_seg_dist2(point(7, 8), dot), DbuArea::new(25));
    // A diagonal segment, where the foot is not axis-aligned: (2, 6) drops onto
    // the line y = x at (4, 4), so the squared drop is 4 + 4.
    assert_eq!(
        point_seg_dist2(point(2, 6), seg(0, 0, 10, 10)),
        DbuArea::new(8)
    );
}

/// Oracle: closed form for the parallel and collinear cases, law for the rest.
/// Segment distance is bounded above by the distance from any of the four
/// endpoints to the other segment, which pins it without stating an answer.
#[test]
fn segment_distance_is_bounded_by_its_endpoint_distances() {
    // Two parallel horizontal segments three units apart.
    assert_eq!(
        seg_seg_dist2(seg(0, 0, 10, 0), seg(0, 3, 10, 3)),
        DbuArea::new(9)
    );
    // Two collinear segments separated by a gap of four.
    assert_eq!(
        seg_seg_dist2(seg(0, 0, 10, 0), seg(14, 0, 20, 0)),
        DbuArea::new(16)
    );
    // Perpendicular, nearest approach between an endpoint and an interior.
    assert_eq!(
        seg_seg_dist2(seg(0, 0, 10, 0), seg(5, 6, 5, 20)),
        DbuArea::new(36)
    );

    let mut rng = Rng::new(25);
    for _ in 0..400 {
        let mut draw = || {
            seg(
                rng.range(-20, 20),
                rng.range(-20, 20),
                rng.range(-20, 20),
                rng.range(-20, 20),
            )
        };
        let (p, q) = (draw(), draw());
        let d = seg_seg_dist2(p, q);
        for probe in [p.a, p.b] {
            assert!(
                d <= point_seg_dist2(probe, q),
                "{d:?} exceeds the distance from {probe:?} to {q:?}"
            );
        }
        for probe in [q.a, q.b] {
            assert!(d <= point_seg_dist2(probe, p));
        }
    }
}

/// Oracle: closed form. `isqrt` rounds toward zero, so its defining boundary is
/// a perfect square and the values either side of it. An off-by-one here broke
/// three tests in the old tree and still survived a mutation, so the sweep runs
/// over every square up to a thousand and then over the domain's far end.
#[test]
fn isqrt_is_exact_at_perfect_squares_and_rounds_toward_zero_beside_them() {
    for n in 0..=1_000i64 {
        let square = i128::from(n) * i128::from(n);
        assert_eq!(
            isqrt(DbuArea::new(square)),
            dbu(n),
            "the root of {n} squared"
        );
        // Both neighbour cases need `n > 0`. Below is obvious — `-1` leaves the
        // domain. Above is the one that reads as an off-by-one and is not: at
        // `n == 0` the value one above is `1`, itself a perfect square, whose
        // exact root is `1`. Only from `n == 1` up is `n² + 1` strictly below
        // `(n + 1)²` and therefore a genuine round-down case.
        if n > 0 {
            assert_eq!(
                isqrt(DbuArea::new(square - 1)),
                dbu(n - 1),
                "one below {n} squared must round down"
            );
            assert_eq!(
                isqrt(DbuArea::new(square + 1)),
                dbu(n),
                "one above {n} squared must round down"
            );
        }
    }

    // MAX_ABS_DBU squared is the largest area two legal coordinates can make,
    // and its root has to come back exact rather than saturating.
    let max = i128::from(MAX_ABS_DBU);
    assert_eq!(isqrt(DbuArea::new(max * max)), dbu(MAX_ABS_DBU));
    assert_eq!(isqrt(DbuArea::new(max * max - 1)), dbu(MAX_ABS_DBU - 1));
}

/// Oracle: law. The integer square root is defined by
/// `r * r <= v < (r + 1) * (r + 1)`, which is checkable against any value
/// without knowing the answer beforehand. The values are products of two legal
/// coordinates, which is the only way an area is produced anywhere in the tree.
#[test]
fn isqrt_satisfies_its_defining_inequality_for_arbitrary_values() {
    let mut rng = Rng::new(26);
    for _ in 0..2_000 {
        let value = i128::from(rng.range(0, MAX_ABS_DBU)) * i128::from(rng.range(0, MAX_ABS_DBU));
        let root = isqrt(DbuArea::new(value));
        // The floor of the root, by bisection over the integers.
        let (mut low, mut high) = (0i64, MAX_ABS_DBU + 1);
        while low + 1 < high {
            let mid = low + (high - low) / 2;
            if i128::from(mid) * i128::from(mid) <= value {
                low = mid;
            } else {
                high = mid;
            }
        }
        assert_eq!(root, dbu(low), "the root of {value} floors to {low}");
    }
}

/// Oracle: closed form. Shoelace over a run the test wrote, doubled, against
/// the areas the generator states as formulas in its own doc comments. The
/// generator's tests prove those formulas; this proves `area2` agrees with them
/// and that reversing a run negates the result.
#[test]
fn area2_is_twice_the_polygon_area_and_flips_sign_with_winding() {
    let cases: Vec<(Shape, i128)> = vec![
        (rect(0, 0, 10, 5), 50),
        (rect(-30, -30, -10, -10), 400),
        (l_shape(0, 0, 100, 30), l_shape_area(100, 30)),
        (plus_shape(11, -7, 50, 2), plus_shape_area(50, 2)),
        (u_shape(4, 4, 100, 20, 40), u_shape_area(100, 20, 40)),
    ];

    for (shape, area) in cases {
        let (xs, ys) = coords(&shape);
        assert_eq!(area2(&xs, &ys), DbuArea::new(2 * area), "{shape:?}");
        assert_eq!(area2(&xs, &ys), DbuArea::new(shoelace(&shape)));
        assert_eq!(winding_of(&xs, &ys), Some(Winding::CounterClockwise));

        let rxs: Vec<Dbu> = xs.iter().copied().rev().collect();
        let rys: Vec<Dbu> = ys.iter().copied().rev().collect();
        assert_eq!(area2(&rxs, &rys), DbuArea::new(-2 * area), "reversed run");
        assert_eq!(winding_of(&rxs, &rys), Some(Winding::Clockwise));
    }
}

/// Oracle: law. Signed area is a property of the region, so it survives a
/// translation and a change of start vertex. Winding follows its sign for the
/// same reason, and a run enclosing nothing has no winding at all.
#[test]
fn area2_is_invariant_under_translation_and_rotation_of_the_start_vertex() {
    let mut rng = Rng::new(27);
    for _ in 0..48 {
        let arm = rng.range(20, 400);
        let thickness = rng.range(1, arm);
        let shape = l_shape(
            rng.range(-1_000, 1_000),
            rng.range(-1_000, 1_000),
            arm,
            thickness,
        );
        let (xs, ys) = coords(&shape);
        let expected = DbuArea::new(2 * l_shape_area(arm, thickness));
        assert_eq!(area2(&xs, &ys), expected);

        let (dx, dy) = (rng.range(-100_000, 100_000), rng.range(-100_000, 100_000));
        let moved = (
            shape.0.iter().map(|&x| x + dx).collect::<Vec<i64>>(),
            shape.1.iter().map(|&y| y + dy).collect::<Vec<i64>>(),
        );
        let (mxs, mys) = coords(&moved);
        assert_eq!(area2(&mxs, &mys), expected, "translation changed the area");
        assert_eq!(winding_of(&mxs, &mys), winding_of(&xs, &ys));

        for start in 1..xs.len() {
            let mut rxs = xs.clone();
            let mut rys = ys.clone();
            rxs.rotate_left(start);
            rys.rotate_left(start);
            assert_eq!(area2(&rxs, &rys), expected, "start vertex {start}");
        }
    }

    // Runs enclosing nothing: three collinear points, and a path that retraces
    // itself. Zero signed area is not clockwise and not counter-clockwise.
    let flat = coords(&(vec![0, 10, 20], vec![0, 0, 0]));
    assert_eq!(area2(&flat.0, &flat.1), DbuArea::new(0));
    assert_eq!(winding_of(&flat.0, &flat.1), None);
    let retraced = coords(&(vec![0, 10, 20, 10], vec![0, 0, 0, 0]));
    assert_eq!(area2(&retraced.0, &retraced.1), DbuArea::new(0));
    assert_eq!(winding_of(&retraced.0, &retraced.1), None);
}

/// Oracle: construct-from-answer. A bowtie is the canonical crossing run and a
/// pinched rectangle is its rectilinear equivalent, while every shape the
/// generator emits is simple by construction. Adjacent edges share an endpoint
/// and the closing edge shares two, and neither of those is a crossing.
#[test]
fn self_intersects_finds_a_crossing_and_accepts_every_generated_shape() {
    let bowtie = coords(&(vec![0, 10, 10, 0], vec![0, 10, 0, 10]));
    assert!(
        self_intersects(&bowtie.0, &bowtie.1),
        "a bowtie crosses itself"
    );

    // The rectilinear equivalent: the edge from (10, 10) down to (10, -5)
    // crosses the opening edge from (0, 0) to (20, 0) at (10, 0), which is in
    // the interior of both and belongs to neither's endpoints.
    let crossing = coords(&(
        vec![0, 20, 20, 10, 10, 30, 30, 0],
        vec![0, 0, 10, 10, -5, -5, 20, 20],
    ));
    assert!(
        self_intersects(&crossing.0, &crossing.1),
        "the run crosses its own opening edge at (10, 0)"
    );

    for shape in [
        rect(0, 0, 10, 5),
        l_shape(0, 0, 100, 30),
        plus_shape(0, 0, 50, 2),
        u_shape(0, 0, 100, 20, 40),
    ] {
        let (xs, ys) = coords(&shape);
        assert!(
            !self_intersects(&xs, &ys),
            "{shape:?} is simple by construction"
        );
    }

    // A triangle is not rectilinear, but simplicity is a separate question and
    // the predicate has to answer the one it was asked.
    let triangle = coords(&(vec![0, 10, 5], vec![0, 0, 9]));
    assert!(!self_intersects(&triangle.0, &triangle.1));
}

/// Oracle: construct-from-answer. A via landing exactly on a conductor edge is
/// connected, so the boundary counts as inside. The L is the shape whose
/// bounding box lies about it: the square from (30, 30) to (100, 100) is inside
/// the box and outside the polygon, so an implementation measuring the box
/// passes on rectangles and fails here.
#[test]
fn point_in_ring_includes_the_boundary_and_excludes_the_reflex_notch() {
    let (store, layer) = validated(&l_shape(0, 0, 100, 30));
    let ring = layer.get(&store, 0).outer();

    for inside in [point(50, 15), point(15, 50), point(15, 15), point(29, 29)] {
        assert!(point_in_ring(ring, inside), "{inside:?} is in the L");
    }

    // An edge midpoint on each of the six edges, plus a convex and a reflex
    // vertex.
    for on_edge in [
        point(50, 0),
        point(100, 15),
        point(65, 30),
        point(30, 65),
        point(15, 100),
        point(0, 50),
        point(0, 0),
        point(30, 30),
    ] {
        assert!(
            point_in_ring(ring, on_edge),
            "{on_edge:?} is on the boundary"
        );
    }

    // The notch a bounding box would wrongly claim.
    for outside in [point(60, 60), point(99, 99), point(31, 31), point(50, 31)] {
        assert!(
            !point_in_ring(ring, outside),
            "{outside:?} is inside the bounding box but outside the L"
        );
    }

    for outside in [point(-1, 50), point(101, 15), point(15, 101), point(50, -1)] {
        assert!(
            !point_in_ring(ring, outside),
            "{outside:?} is clear of the L"
        );
    }
}

/// Oracle: law. Membership is a property of the region, so translating the ring
/// and the probe together cannot change the answer — for a probe inside, one
/// outside, or one exactly on the boundary. The U's notch means the probe grid
/// lands in all three.
#[test]
fn point_in_ring_is_invariant_under_translation() {
    let mut rng = Rng::new(28);
    let probes: Vec<(i64, i64)> = (0..200)
        .map(|_| (rng.range(-20, 100), rng.range(-20, 120)))
        .collect();

    let (here_store, here_layer) = validated(&u_shape(0, 0, 100, 20, 40));
    let here_ring = here_layer.get(&here_store, 0).outer();

    let mut agreed_inside = 0u32;
    for _ in 0..8 {
        let (dx, dy) = (rng.range(-500_000, 500_000), rng.range(-500_000, 500_000));
        let (there_store, there_layer) = validated(&u_shape(dx, dy, 100, 20, 40));
        let there_ring = there_layer.get(&there_store, 0).outer();

        for &(x, y) in &probes {
            let here = point_in_ring(here_ring, point(x, y));
            assert_eq!(
                here,
                point_in_ring(there_ring, point(x + dx, y + dy)),
                "({x}, {y}) changed membership under a shift of ({dx}, {dy})"
            );
            agreed_inside += u32::from(here);
        }
    }
    assert!(
        agreed_inside > 0,
        "every probe fell outside; the grid missed the shape"
    );
}
