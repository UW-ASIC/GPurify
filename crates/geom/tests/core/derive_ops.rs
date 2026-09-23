//! Derived-layer operations against hand-derived regions, areas and edges.

use gpurify_geom::boolean::{intersection_into, subtraction_into, BooleanError};
use gpurify_geom::derive::{
    edge_boolean_into, edge_interacting_into, edge_part_into, edges_into, extents_into, holes_into,
    inside_into, interacting_into, merge_into, outside_into, sized_into, with_area_into,
    with_length_into, with_width_into, EdgeOp,
};
use gpurify_geom::ops::{Point, Seg};
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::{Dbu, GeometryStoreBuilder, LayerId, MAX_ABS_DBU};

fn d(v: i64) -> Dbu {
    Dbu::new(v).expect("in domain")
}

/// A merged layer from rings given as `(xs, ys)`; CCW outers, CW holes.
fn layer(rings: &[(&[i64], &[i64])]) -> ValidatedLayer {
    let mut builder = GeometryStoreBuilder::with_capacity(rings.len(), 0);
    for (xs, ys) in rings {
        let xs: Vec<Dbu> = xs.iter().map(|&v| d(v)).collect();
        let ys: Vec<Dbu> = ys.iter().map(|&v| d(v)).collect();
        builder.push(LayerId(0), &xs, &ys);
    }
    let (store, _) = builder.finish(1);
    let mut raw = ValidatedLayer::default();
    validate_layer_into(&store, LayerId(0), &mut raw).expect("valid test rings");
    let mut out = ValidatedLayer::default();
    merge_into(&raw, &mut out).expect("rectilinear");
    out
}

/// CCW rectangles.
fn rects(boxes: &[(i64, i64, i64, i64)]) -> ValidatedLayer {
    let rings: Vec<([i64; 4], [i64; 4])> = boxes
        .iter()
        .map(|&(x0, y0, x1, y1)| ([x0, x1, x1, x0], [y0, y0, y1, y1]))
        .collect();
    let refs: Vec<(&[i64], &[i64])> = rings.iter().map(|(x, y)| (&x[..], &y[..])).collect();
    layer(&refs)
}

/// The rectangle as a CW ring, for a hole.
fn hole(x0: i64, y0: i64, x1: i64, y1: i64) -> ([i64; 4], [i64; 4]) {
    ([x0, x0, x1, x1], [y0, y1, y1, y0])
}

fn area(l: &ValidatedLayer) -> i128 {
    (0..u32::try_from(l.len()).expect("small"))
        .flat_map(|i| l.poly_rings(i))
        .map(|r| r.area2().raw())
        .sum::<i128>()
        / 2
}

/// Same region: equal area and neither side has area the other lacks.
fn same(got: &ValidatedLayer, want: &ValidatedLayer, what: &str) {
    let mut diff = ValidatedLayer::default();
    subtraction_into(got, want, &mut diff).expect("rectilinear");
    assert_eq!(area(&diff), 0, "{what}: extra area");
    subtraction_into(want, got, &mut diff).expect("rectilinear");
    assert_eq!(area(&diff), 0, "{what}: missing area");
}

fn sized(a: &ValidatedLayer, by: i64) -> ValidatedLayer {
    let mut out = ValidatedLayer::default();
    sized_into(a, Dbu::new(by).expect("in domain"), &mut out).expect("in range");
    out
}

#[test]
fn growing_a_square_adds_the_distance_on_every_side_with_square_corners() {
    let grown = sized(&rects(&[(0, 0, 10, 10)]), 2);
    same(&grown, &rects(&[(-2, -2, 12, 12)]), "grown square");
    assert_eq!(area(&grown), 14 * 14);
}

#[test]
fn growing_closes_a_gap_no_wider_than_twice_the_distance() {
    // Gap 4 closes at 2 (edges meet), gap 5 stays open.
    assert_eq!(
        sized(&rects(&[(0, 0, 10, 10), (14, 0, 24, 10)]), 2).len(),
        1
    );
    assert_eq!(
        sized(&rects(&[(0, 0, 10, 10), (15, 0, 25, 10)]), 2).len(),
        2
    );
}

#[test]
fn shrinking_deletes_a_shape_no_wider_than_twice_the_distance() {
    assert!(
        sized(&rects(&[(0, 0, 4, 20)]), -2).is_empty(),
        "width 4 = 2 * 2"
    );
    same(
        &sized(&rects(&[(0, 0, 5, 20)]), -2),
        &rects(&[(2, 2, 3, 18)]),
        "width 5 leaves a 1-wide core",
    );
}

#[test]
fn shrinking_a_ring_widens_its_hole() {
    let (hx, hy) = hole(8, 8, 12, 12);
    let ring = layer(&[(&[0, 20, 20, 0], &[0, 0, 20, 20]), (&hx, &hy)]);
    let got = sized(&ring, -2);
    assert_eq!(area(&got), 16 * 16 - 8 * 8);
    let (wx, wy) = hole(6, 6, 14, 14);
    same(
        &got,
        &layer(&[(&[2, 18, 18, 2], &[2, 2, 18, 18]), (&wx, &wy)]),
        "shrunk ring",
    );
}

/// An L: a vertical arm 4 wide, `[0,4]x[0,10]`, and a horizontal arm
/// `[0,10]x[0,arm]`.
fn l_shape(arm: i64) -> ValidatedLayer {
    layer(&[(&[0, 10, 10, 4, 4, 0], &[0, 0, arm, arm, 10, 10])])
}

#[test]
fn shrink_then_grow_keeps_only_the_parts_wider_than_twice_the_distance() {
    // The sky130 "huge metal" idiom at a = 1: the 2-wide arm is not wider than
    // 2a and goes, the 4-wide arm stays whole.
    let arm_two = sized(&sized(&l_shape(2), -1), 1);
    same(&arm_two, &rects(&[(0, 0, 4, 10)]), "thin arm removed");
    assert_eq!(area(&arm_two), 40);
    // A 3-wide arm is wider than 2a: the L comes back exactly.
    same(
        &sized(&sized(&l_shape(3), -1), 1),
        &l_shape(3),
        "opening of a wide L",
    );
}

#[test]
fn sizing_past_the_coordinate_domain_is_refused() {
    let edge = MAX_ABS_DBU - 1;
    let mut out = ValidatedLayer::default();
    assert_eq!(
        sized_into(&rects(&[(0, 0, edge, 10)]), d(5), &mut out),
        Err(BooleanError::OutOfRange)
    );
}

/// `B` is one 10x10 square at the origin; each `A` square is placed to probe
/// one relation, named in the order the tests index them.
fn probes() -> (ValidatedLayer, ValidatedLayer) {
    let b = rects(&[(0, 0, 10, 10)]);
    let a = rects(&[
        (6, 6, 9, 9),     // 0: strictly inside
        (0, 0, 5, 5),     // 1: inside, sharing B's corner and two edges
        (8, 2, 12, 4),    // 2: straddles B's right edge
        (10, 5, 14, 8),   // 3: touches B's right edge from outside
        (12, 12, 14, 14), // 4: far away (gap 2 from B's corner)
        (-4, 10, 0, 14),  // 5: touches B's top-left corner only
        (-5, -5, 15, -2), // 6: below, gap 2
    ]);
    (a, b)
}

/// The polygons of `got`, as their bounding boxes, sorted.
fn boxes(got: &ValidatedLayer) -> Vec<(i64, i64, i64, i64)> {
    let mut out: Vec<_> = got
        .bboxes()
        .iter()
        .map(|b| (b.xlo.raw(), b.ylo.raw(), b.xhi.raw(), b.yhi.raw()))
        .collect();
    out.sort_unstable();
    out
}

#[test]
fn interacting_takes_touching_and_overlapping_shapes_and_a_shared_corner() {
    let (a, b) = probes();
    let mut yes = ValidatedLayer::default();
    let mut no = ValidatedLayer::default();
    interacting_into(&a, &b, true, &mut yes);
    interacting_into(&a, &b, false, &mut no);
    assert_eq!(
        boxes(&yes),
        [
            (-4, 10, 0, 14),
            (0, 0, 5, 5),
            (6, 6, 9, 9),
            (8, 2, 12, 4),
            (10, 5, 14, 8)
        ]
    );
    assert_eq!(boxes(&no), [(-5, -5, 15, -2), (12, 12, 14, 14)]);
    assert_eq!(
        area(&yes) + area(&no),
        area(&a),
        "the two selections split A"
    );
}

#[test]
fn a_shape_in_a_hole_does_not_interact_but_one_over_the_ring_does() {
    let (hx, hy) = hole(5, 5, 15, 15);
    let ring = layer(&[(&[0, 20, 20, 0], &[0, 0, 20, 20]), (&hx, &hy)]);
    let a = rects(&[(8, 8, 12, 12), (18, -2, 22, 2)]);
    let mut got = ValidatedLayer::default();
    interacting_into(&a, &ring, true, &mut got);
    assert_eq!(
        boxes(&got),
        [(18, -2, 22, 2)],
        "the island in the hole is apart"
    );
}

#[test]
fn inside_is_covered_by_b_and_outside_shares_no_area_with_it() {
    let (a, b) = probes();
    let mut inside = ValidatedLayer::default();
    let mut outside = ValidatedLayer::default();
    inside_into(&a, &b, &mut inside).expect("rectilinear");
    outside_into(&a, &b, &mut outside).expect("rectilinear");
    assert_eq!(boxes(&inside), [(0, 0, 5, 5), (6, 6, 9, 9)]);
    assert_eq!(
        boxes(&outside),
        [
            (-5, -5, 15, -2),
            (-4, 10, 0, 14),
            (10, 5, 14, 8),
            (12, 12, 14, 14)
        ]
    );
    // Only the straddler is neither.
    assert_eq!(area(&a) - area(&inside) - area(&outside), 4 * 2);
}

#[test]
fn a_shape_covered_by_two_abutting_shapes_of_b_is_inside() {
    let b = rects(&[(0, 0, 5, 10), (5, 0, 10, 10)]);
    let a = rects(&[(2, 2, 8, 8)]);
    let mut got = ValidatedLayer::default();
    inside_into(&a, &b, &mut got).expect("rectilinear");
    assert_eq!(got.len(), 1, "B is merged before the test");
}

#[test]
fn holes_fill_each_hole_and_a_hole_holding_an_island_covers_it() {
    // A ring with a 12x12 hole; in the hole an island ring with a 2x2 hole.
    let (h1x, h1y) = hole(4, 4, 16, 16);
    let (h2x, h2y) = hole(9, 9, 11, 11);
    let l = layer(&[
        (&[0, 20, 20, 0], &[0, 0, 20, 20]),
        (&h1x, &h1y),
        (&[6, 14, 14, 6], &[6, 6, 14, 14]),
        (&h2x, &h2y),
    ]);
    let mut got = ValidatedLayer::default();
    holes_into(&l, &mut got).expect("rectilinear");
    same(
        &got,
        &rects(&[(4, 4, 16, 16)]),
        "the outer hole, island included",
    );
    holes_into(&rects(&[(0, 0, 5, 5)]), &mut got).expect("rectilinear");
    assert!(got.is_empty(), "a plain rectangle has no hole");
}

#[test]
fn extents_are_bounding_boxes_merged() {
    let mut got = ValidatedLayer::default();
    extents_into(&l_shape(2), &mut got).expect("rectilinear");
    same(&got, &rects(&[(0, 0, 10, 10)]), "extent of the L");
    // Two Ls whose boxes overlap merge into one box region.
    let two = layer(&[
        (&[0, 10, 10, 2, 2, 0], &[0, 0, 2, 2, 10, 10]),
        (
            &[12, 20, 20, 8, 8, 18, 18, 12],
            &[4, 4, 14, 14, 12, 12, 6, 6],
        ),
    ]);
    extents_into(&two, &mut got).expect("rectilinear");
    same(
        &got,
        &rects(&[(0, 0, 10, 10), (8, 4, 20, 14)]),
        "union of boxes",
    );
    assert_eq!(area(&got), 100 + 120 - 2 * 6);
}

#[test]
fn with_area_selects_on_the_area_net_of_holes() {
    let (hx, hy) = hole(1, 1, 3, 3);
    let l = layer(&[
        (&[0, 2, 2, 0], &[0, 0, 2, 2]),     // 4
        (&[10, 13, 13, 10], &[0, 0, 3, 3]), // 9
        (&[20, 24, 24, 20], &[0, 0, 4, 4]), // 16
        (&[30, 34, 34, 30], &[0, 0, 4, 4]), // 16 - 4 = 12 once holed below
    ]);
    let holed = layer(&[(&[0, 4, 4, 0], &[0, 0, 4, 4]), (&hx, &hy)]);
    let mut got = ValidatedLayer::default();
    with_area_into(&l, 5..=9, &mut got);
    assert_eq!(boxes(&got), [(10, 0, 13, 3)]);
    with_area_into(&holed, 12..=12, &mut got);
    assert_eq!(got.len(), 1, "4x4 minus 2x2 is 12");
    with_area_into(&holed, 16..=16, &mut got);
    assert!(got.is_empty(), "the hole is not area");
}

#[test]
fn with_width_selects_on_the_narrowest_width() {
    let l = layer(&[
        (&[0, 10, 10, 4, 4, 0], &[0, 0, 2, 2, 10, 10]), // L, narrowest 2
        (&[20, 23, 23, 20], &[0, 0, 10, 10]),           // 3 x 10
    ]);
    let mut got = ValidatedLayer::default();
    with_width_into(&l, 3..=i128::MAX, &mut got);
    assert_eq!(boxes(&got), [(20, 0, 23, 10)], "the L is 2 wide at its arm");
    with_width_into(&l, 0..=2, &mut got);
    assert_eq!(boxes(&got), [(0, 0, 10, 10)]);
}

fn seg(ax: i64, ay: i64, bx: i64, by: i64) -> Seg {
    Seg {
        a: Point { x: d(ax), y: d(ay) },
        b: Point { x: d(bx), y: d(by) },
    }
}

fn sorted(v: &[Seg]) -> Vec<(i64, i64, i64, i64)> {
    let mut out: Vec<_> = v
        .iter()
        .map(|s| (s.a.x.raw(), s.a.y.raw(), s.b.x.raw(), s.b.y.raw()))
        .collect();
    out.sort_unstable();
    out
}

fn length(v: &[Seg]) -> i64 {
    v.iter()
        .map(|s| (s.b.x.raw() - s.a.x.raw()).abs() + (s.b.y.raw() - s.a.y.raw()).abs())
        .sum()
}

fn edges(l: &ValidatedLayer) -> Vec<Seg> {
    let mut out = Vec::new();
    edges_into(l, &mut out);
    out
}

#[test]
fn edges_run_counter_clockwise_round_an_outer_with_material_on_the_left() {
    assert_eq!(
        sorted(&edges(&rects(&[(0, 0, 10, 10)]))),
        [
            (0, 0, 10, 0),
            (0, 10, 0, 0),
            (10, 0, 10, 10),
            (10, 10, 0, 10)
        ]
    );
}

#[test]
fn butting_edges_are_the_coincident_parts_and_booleans_split_length() {
    // A = [0,10]^2; B = [10,20]x[5,15] butts A's right edge along y 5..10.
    let a = edges(&rects(&[(0, 0, 10, 10)]));
    let b = edges(&rects(&[(10, 5, 20, 15)]));
    let mut and = Vec::new();
    let mut not = Vec::new();
    let mut or = Vec::new();
    edge_boolean_into(&a, &b, EdgeOp::And, &mut and);
    edge_boolean_into(&a, &b, EdgeOp::Not, &mut not);
    edge_boolean_into(&a, &b, EdgeOp::Or, &mut or);
    assert_eq!(sorted(&and), [(10, 5, 10, 10)], "A's direction, up");
    assert_eq!(length(&not), 40 - 5);
    assert_eq!(length(&or), 40 + 40 - 5, "the shared part counted once");
}

#[test]
fn edge_parts_split_at_the_other_layers_boundary_and_the_boundary_is_neither() {
    let a = edges(&rects(&[(0, 0, 10, 10)]));
    let over = rects(&[(5, -5, 15, 15)]);
    let (mut inside, mut outside) = (Vec::new(), Vec::new());
    edge_part_into(&a, &over, true, &mut inside);
    edge_part_into(&a, &over, false, &mut outside);
    assert_eq!(
        sorted(&inside),
        [(5, 0, 10, 0), (10, 0, 10, 10), (10, 10, 5, 10)]
    );
    assert_eq!(length(&outside), 5 + 5 + 10);
    // Butting: A's right edge lies on B's boundary, so it is in neither part.
    let butt = rects(&[(10, 0, 20, 10)]);
    edge_part_into(&a, &butt, true, &mut inside);
    edge_part_into(&a, &butt, false, &mut outside);
    assert!(inside.is_empty());
    assert_eq!(length(&outside), 30);
}

#[test]
fn edge_interacting_takes_whole_edges_that_touch_and_with_length_filters() {
    let a = vec![
        seg(0, 0, 10, 0),   // crosses B
        seg(20, 0, 20, 5),  // runs along B's right edge
        seg(12, 1, 12, 3),  // inside B
        seg(30, 0, 30, 10), // far away
    ];
    let b = rects(&[(5, -2, 20, 4)]);
    let (mut yes, mut no) = (Vec::new(), Vec::new());
    edge_interacting_into(&a, &b, true, &mut yes);
    edge_interacting_into(&a, &b, false, &mut no);
    assert_eq!(
        sorted(&yes),
        [(0, 0, 10, 0), (12, 1, 12, 3), (20, 0, 20, 5)],
        "(20,0)-(20,5) runs along B's right edge"
    );
    assert_eq!(sorted(&no), [(30, 0, 30, 10)]);
    let mut kept = Vec::new();
    with_length_into(&a, 5..=9, &mut kept);
    assert_eq!(sorted(&kept), [(20, 0, 20, 5)]);
}

#[test]
fn intersection_and_difference_split_area() {
    // A = (A and B) + (A not B), for the operands the selections test on.
    let (a, b) = probes();
    let (mut and, mut not) = (ValidatedLayer::default(), ValidatedLayer::default());
    intersection_into(&a, &b, &mut and).expect("rectilinear");
    subtraction_into(&a, &b, &mut not).expect("rectilinear");
    assert_eq!(area(&and) + area(&not), area(&a));
}
