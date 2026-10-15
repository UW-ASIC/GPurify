//! Derived-layer operations against hand-derived regions, areas and edges.

use gpurify_geom::boolean::{intersection_into, subtraction_into, BooleanError};
use gpurify_geom::derive::{
    covering_into, edge_boolean_into, edge_interacting_into, edge_part_into, edges_into,
    extended_into, extents_into, holes_into, inside_into, interacting_into, merge_into,
    outside_into, overlapping_into, rectangles_into, sized_into, with_area_into, with_length_into,
    with_width_into, EdgeOp,
};
use gpurify_geom::ops::{Point, Seg};
use gpurify_geom::view::{validate_layer_into, validate_layer_with, Angles, ValidatedLayer};
use gpurify_geom::width::narrowest_neck;
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
        .flat_map(|i| l.get(i).rings())
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
    let by = Dbu::new(by).expect("in domain");
    sized_into(a, by, by, &mut out).expect("in range");
    out
}

/// Oracle: hand-derived. A 10 square grown by 2 with square corners is (-2,
/// -2)-(12, 12), area 14^2.
#[test]
fn growing_a_square_adds_the_distance_on_every_side_with_square_corners() {
    let grown = sized(&rects(&[(0, 0, 10, 10)]), 2);
    same(&grown, &rects(&[(-2, -2, 12, 12)]), "grown square");
    assert_eq!(area(&grown), 14 * 14);
}

/// Oracle: the Minkowski sum with, and erosion by, the box `[-dx, dx] x
/// [-dy, dy]` (`KLayout`'s `sized(dx, dy)`), worked by hand: a 10 x 6 box
/// grown by (2, 3) is 14 x 12; shrunk by (1, 2) it is 8 x 2; shrunk by (1, 3)
/// it is gone; and two boxes 4 apart across x merge when grown by (2, 0) but
/// not by (1, 0) or (0, 5).
#[test]
fn sizing_each_axis_by_its_own_distance() {
    let box_ = rects(&[(0, 0, 10, 6)]);
    let mut out = ValidatedLayer::default();
    sized_into(&box_, d(2), d(3), &mut out).expect("in range");
    same(&out, &rects(&[(-2, -3, 12, 9)]), "grown box");
    sized_into(&box_, d(-1), d(-2), &mut out).expect("in range");
    same(&out, &rects(&[(1, 2, 9, 4)]), "shrunk box");
    sized_into(&box_, d(-1), d(-3), &mut out).expect("in range");
    assert!(out.is_empty(), "6 tall shrinks away under 2 x 3");
    let pair = rects(&[(0, 0, 10, 6), (14, 0, 24, 6)]);
    sized_into(&pair, d(2), d(0), &mut out).expect("in range");
    assert_eq!(out.len(), 1, "the 4 gap closes");
    sized_into(&pair, d(1), d(0), &mut out).expect("in range");
    assert_eq!(out.len(), 2, "a 2 gap is left");
    sized_into(&pair, d(0), d(5), &mut out).expect("in range");
    assert_eq!(out.len(), 2, "growing in y leaves the x gap");
}

/// Oracle: hand-derived. Growing each side by 2 closes a gap of 4 (the edges
/// meet) and leaves one of 5 open: one shape, then two.
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

/// Oracle: hand-derived. Shrinking by 2 from both sides empties a 4-wide bar
/// and leaves a 5-wide one its 1-wide core, (2, 2)-(3, 18).
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

/// Oracle: hand-derived. A 20 ring with an 8..12 hole shrunk by 2 is the
/// 2..18 square less a 6..14 hole, area 16^2 - 8^2.
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

/// Oracle: hand-derived, sky130's huge-metal idiom at 1: shrinking then growing
/// by 1 removes the 2-wide arm and keeps the 4-wide one, (0, 0)-(4, 10), area
/// 40; an L whose arms are all wider than 2 comes back exactly.
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

/// Oracle: construct-from-answer. A rectangle ending one unit inside
/// `MAX_ABS_DBU` grown by 5 would leave the coordinate domain, so the only
/// correct answer is `OutOfRange`.
#[test]
fn sizing_past_the_coordinate_domain_is_refused() {
    let edge = MAX_ABS_DBU - 1;
    let mut out = ValidatedLayer::default();
    assert_eq!(
        sized_into(&rects(&[(0, 0, edge, 10)]), d(5), d(5), &mut out),
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

/// Oracle: hand-derived, from `probes`: `KLayout`'s `interacting` takes every `A`
/// square that overlaps or touches `B`, a shared corner included (probes 0, 1,
/// 2, 3, 5), and leaves the two with a gap; the two selections partition `A`'s
/// area.
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

/// Oracle: construct-from-answer. The island lies in the ring's hole, apart
/// from its material; the other square overlaps the ring's corner.
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

/// Oracle: hand-derived, from `probes`: probes 0 and 1 lie in `B`, 3, 4, 5 and
/// 6 share no area with it, and the straddler, 4 x 2 of it, is neither.
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

/// Oracle: construct-from-answer. The two halves of `B` abut to cover (0,
/// 0)-(10, 10), which holds `A` (2..8); `B` merged, `A` is inside.
#[test]
fn a_shape_covered_by_two_abutting_shapes_of_b_is_inside() {
    let b = rects(&[(0, 0, 5, 10), (5, 0, 10, 10)]);
    let a = rects(&[(2, 2, 8, 8)]);
    let mut got = ValidatedLayer::default();
    inside_into(&a, &b, &mut got).expect("rectilinear");
    assert_eq!(got.len(), 1, "B is merged before the test");
}

/// Oracle: hand-derived. The outer ring's hole is 4..16, island included, so
/// `holes` is that square; a plain rectangle has none.
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

/// Oracle: hand-derived, with `KLayout`'s `extents` ("The boxes will not be
/// merged"): the L's box is 10 x 10, and the two Ls keep their own boxes, 100 +
/// 120 with the overlap counted twice.
#[test]
fn extents_give_each_shape_its_own_box() {
    let mut got = ValidatedLayer::default();
    extents_into(&l_shape(2), &mut got).expect("rectilinear");
    same(&got, &rects(&[(0, 0, 10, 10)]), "extent of the L");
    // Two disjoint Ls whose boxes overlap on [8, 10] x [4, 10]: each keeps its
    // own box, 10 x 10 and 12 x 10, so the areas add with the overlap counted
    // twice (`KLayout`: "The boxes will not be merged").
    let two = layer(&[
        (&[0, 10, 10, 2, 2, 0], &[0, 0, 2, 2, 10, 10]),
        (
            &[12, 20, 20, 8, 8, 18, 18, 12],
            &[4, 4, 14, 14, 12, 12, 6, 6],
        ),
    ]);
    extents_into(&two, &mut got).expect("rectilinear");
    assert_eq!(boxes(&got), [(0, 0, 10, 10), (8, 4, 20, 14)]);
    assert_eq!(area(&got), 100 + 120);
}

/// Oracle: hand-derived areas in the comments: 4, 9, 16, and 16 - 4 = 12 for
/// the holed square, so `5..=9` keeps the 9 and the holed square is 12, not 16.
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

/// Oracle: `KLayout`'s `covering` and `overlapping` definitions, on four
/// 10 x 10 squares each drawn with one `b` shape: held inside, across the
/// edge, touching from outside, touching from inside. Covering takes the
/// first and the last; overlapping all but the one touched from outside,
/// which `outside` keeps.
#[test]
fn covering_holds_a_whole_shape_and_overlapping_shares_area() {
    let a = rects(&[
        (0, 0, 10, 10),
        (20, 0, 30, 10),
        (40, 0, 50, 10),
        (60, 0, 70, 10),
    ]);
    let b = rects(&[(2, 2, 4, 4), (28, 4, 32, 6), (50, 4, 52, 6), (60, 4, 62, 6)]);
    let mut got = ValidatedLayer::default();
    covering_into(&a, &b, true, &mut got).expect("rectilinear");
    assert_eq!(boxes(&got), [(0, 0, 10, 10), (60, 0, 70, 10)]);
    covering_into(&a, &b, false, &mut got).expect("rectilinear");
    assert_eq!(boxes(&got), [(20, 0, 30, 10), (40, 0, 50, 10)]);
    overlapping_into(&a, &b, true, &mut got).expect("rectilinear");
    assert_eq!(
        boxes(&got),
        [(0, 0, 10, 10), (20, 0, 30, 10), (60, 0, 70, 10)]
    );
    outside_into(&a, &b, &mut got).expect("rectilinear");
    assert_eq!(boxes(&got), [(40, 0, 50, 10)]);
}

/// Oracle: `KLayout`'s `rectangles` / `squares` definition, on shapes drawn
/// to be or not be a box: a square, a 3 x 2 box, two abutting squares that
/// merge into a 4 x 2 box, a box one unit off square, an L, and a square with
/// a hole (no box). The `non_` forms are the complement.
#[test]
fn rectangles_and_squares_select_holeless_boxes() {
    let (hx, hy) = hole(41, 1, 43, 3);
    let l = layer(&[
        (&[0, 2, 2, 0], &[0, 0, 2, 2]),
        (&[10, 13, 13, 10], &[0, 0, 2, 2]),
        (&[20, 22, 22, 20], &[0, 0, 2, 2]),
        (&[22, 24, 24, 22], &[0, 0, 2, 2]),
        (&[30, 33, 33, 30], &[0, 0, 4, 4]),
        (&[30, 34, 34, 30], &[10, 10, 13, 13]),
        (&[50, 54, 54, 52, 52, 50], &[0, 0, 2, 2, 4, 4]),
        (&[40, 44, 44, 40], &[0, 0, 4, 4]),
        (&hx, &hy),
    ]);
    let mut got = ValidatedLayer::default();
    rectangles_into(&l, false, true, &mut got);
    assert_eq!(
        boxes(&got),
        [
            (0, 0, 2, 2),
            (10, 0, 13, 2),
            (20, 0, 24, 2),
            (30, 0, 33, 4),
            (30, 10, 34, 13)
        ]
    );
    rectangles_into(&l, false, false, &mut got);
    assert_eq!(boxes(&got), [(40, 0, 44, 4), (50, 0, 54, 4)]);
    rectangles_into(&l, true, true, &mut got);
    assert_eq!(boxes(&got), [(0, 0, 2, 2)]);
    rectangles_into(&l, true, false, &mut got);
    assert_eq!(got.len(), 6, "every shape but the square");
}

/// Oracle: hand-derived. The L's narrowest width is its 2-wide arm and the bar
/// is 3 wide; the ranges are on twice the square (`>= 3` is `18..`, `<= 2`
/// `..=8`).
#[test]
fn with_width_selects_on_the_narrowest_width() {
    let l = layer(&[
        (&[0, 10, 10, 4, 4, 0], &[0, 0, 2, 2, 10, 10]), // L, narrowest 2
        (&[20, 23, 23, 20], &[0, 0, 10, 10]),           // 3 x 10
    ]);
    // The range is on twice the squared width: `>= 3` is `18..`, `<= 2` `..=8`.
    let mut got = ValidatedLayer::default();
    with_width_into(&l, 18..=i128::MAX, &mut got);
    assert_eq!(boxes(&got), [(20, 0, 23, 10)], "the L is 2 wide at its arm");
    with_width_into(&l, 0..=8, &mut got);
    assert_eq!(boxes(&got), [(0, 0, 10, 10)]);
}

/// Oracle: hand-derived. The concave corners (10, 8) and (8, 10) are sqrt(8)
/// apart, 8 squared exactly (16 twice), so the neck is in `10..` and `..=18`
/// and in neither `..=8` nor `18..` (F65; the ranges are on twice the square).
#[test]
fn with_width_counts_the_diagonal_neck_width_measures() {
    // Two 10-squares overlapping 2 x 2 at a corner: every facing pair is 10
    // apart, but the concave corners (10, 8) and (8, 10) are sqrt(8) = 2.83
    // apart: 8 squared, exactly. So the neck is `> 2` (`5..`) and `<= 3`
    // (`..=9`), and neither `<= 2` (`..=4`) nor `>= 3` (`9..`): a floor to 2
    // would put it in `<= 2` and out of `> 2` (F65).
    let plates = rects(&[(0, 0, 10, 10), (8, 8, 18, 18)]);
    let mut got = ValidatedLayer::default();
    with_width_into(&plates, 10..=i128::MAX, &mut got);
    assert_eq!(boxes(&got), [(0, 0, 18, 18)], "the neck is wider than 2");
    with_width_into(&plates, 0..=18, &mut got);
    assert_eq!(boxes(&got), [(0, 0, 18, 18)], "the neck is at most 3");
    with_width_into(&plates, 0..=8, &mut got);
    assert!(got.is_empty(), "the neck is not at most 2");
    with_width_into(&plates, 18..=i128::MAX, &mut got);
    assert!(got.is_empty(), "nothing is 3 wide at the neck");
}

/// Oracle: closed form, worked in the comment: the neck squared is n^2 - 1 for
/// n = 98 000 001, whose integer root is n - 1, at the midpoint of the two
/// corners.
#[test]
fn a_neck_past_two_to_the_53_is_floored_exactly() {
    // Plates overlapping 98_000_000 x 14_000 at a corner: the concave corners
    // (198_000_000, 200_000_000) and (100_000_000, 200_014_000) are
    // sqrt(98e6² + 14e3²) apart, squared 9_604_000_196_000_000 = n² - 1 for
    // n = 98_000_001, past 2^53. Its floor is n - 1. Every facing pair is
    // wider than n. An f64 root rounds n² - 1 to n.
    let plates = rects(&[
        (0, 0, 198_000_000, 200_014_000),
        (100_000_000, 200_000_000, 400_000_000, 400_000_000),
    ]);
    let (gap, at) = narrowest_neck(plates.get(0), d(98_000_001)).expect("a neck under n");
    assert_eq!(gap, d(98_000_000));
    assert_eq!((at.x, at.y), (d(149_000_000), d(200_007_000)));
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

/// Oracle: hand-derived. The 10 square's four edges, counter-clockwise from the
/// origin, each with the material on its left.
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

/// Oracle: hand-derived. `B` butts `A`'s right edge along y 5..10: `and` is
/// that 5, `not` the other 35 of `A`'s 40, `or` 80 - 5.
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

/// Oracle: hand-derived. `over` covers x 5..15, so the inside part is the right
/// halves of the bottom and top and the whole right edge; the outside part is
/// 5 + 5 + 10. A butting square takes the right edge from both, leaving
/// 30 outside.
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

/// Oracle: `KLayout`'s `extended(begin, end, out, in)`, worked by hand on a
/// 10 x 4 rectangle's counter-clockwise edges: each lengthened by 1 before
/// the corner it leaves and widened by 2 away from the rectangle, one box per
/// edge, unmerged.
#[test]
fn extended_edges_grow_a_box_before_their_start_and_away_from_their_shape() {
    let mut boxes_out = ValidatedLayer::default();
    extended_into(
        &edges(&rects(&[(0, 0, 10, 4)])),
        (d(1), d(0), d(2), d(0)),
        &mut boxes_out,
    )
    .expect("in range");
    assert_eq!(
        boxes(&boxes_out),
        [
            (-2, 0, 0, 5),
            (-1, -2, 10, 0),
            (0, 4, 11, 6),
            (10, -1, 12, 4)
        ]
    );
}

/// Oracle: hand-derived. Each segment's relation to `B` is in its comment:
/// crossing, along the edge and inside interact, the far one does not; only the
/// 5-long segment is in `5..=9`.
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

/// Oracle: law. `area(A and B) + area(A not B) = area(A)`, on the `probes`
/// operands.
#[test]
fn intersection_and_difference_split_area() {
    // A = (A and B) + (A not B), for the operands the selections test on.
    let (a, b) = probes();
    let (mut and, mut not) = (ValidatedLayer::default(), ValidatedLayer::default());
    intersection_into(&a, &b, &mut and).expect("rectilinear");
    subtraction_into(&a, &b, &mut not).expect("rectilinear");
    assert_eq!(area(&and) + area(&not), area(&a));
}

/// A merged layer from octilinear rings given as `(xs, ys)`.
fn oct_layer(rings: &[(&[i64], &[i64])]) -> ValidatedLayer {
    let mut builder = GeometryStoreBuilder::with_capacity(rings.len(), 0);
    for (xs, ys) in rings {
        let xs: Vec<Dbu> = xs.iter().map(|&v| d(v)).collect();
        let ys: Vec<Dbu> = ys.iter().map(|&v| d(v)).collect();
        builder.push(LayerId(0), &xs, &ys);
    }
    let (store, _) = builder.finish(1);
    let mut raw = ValidatedLayer::default();
    validate_layer_with(&store, LayerId(0), Angles::Octilinear, &mut raw)
        .expect("valid octilinear test rings");
    let mut out = ValidatedLayer::default();
    merge_into(&raw, &mut out).expect("octilinear");
    out
}

const DIAMOND: (&[i64], &[i64]) = (&[10, 0, -10, 0], &[0, 10, 0, -10]);

/// Oracle: hand-derived Minkowski sums with the square `[-1, 1]²`. The
/// radius-10 diamond (area 200) grows to the octagon inside the 22-square
/// less four corner triangles of legs 10 (`484 - 4·50 = 284`), and erodes to
/// the radius-8 diamond (`2·8² = 128`): the square moves each diagonal edge
/// 1 in x and 1 in y.
#[test]
fn a_diamond_sizes_by_the_square_both_ways() {
    let diamond = oct_layer(&[DIAMOND]);
    let mut got = ValidatedLayer::default();
    sized_into(&diamond, d(1), d(1), &mut got).expect("in range");
    assert_eq!(area(&got), 284);
    assert_eq!(boxes(&got), [(-11, -11, 11, 11)]);
    sized_into(&diamond, d(-1), d(-1), &mut got).expect("in range");
    assert_eq!(area(&got), 128);
    assert_eq!(boxes(&got), [(-8, -8, 8, 8)]);
}

/// Oracle: hand-derived. A diamond's edges are its four diagonals, material
/// on the left, each `10·√2 ≈ 14.14` long, so `14..=15` keeps all four and
/// `15..` and `..=14` none. A box over `x ≥ 2` holds the parts of the right
/// two edges from `x = 2`.
#[test]
fn diagonal_edges_measure_and_split_exactly() {
    let diamond = oct_layer(&[DIAMOND]);
    let all = edges(&diamond);
    assert_eq!(
        sorted(&all),
        [
            (-10, 0, 0, -10),
            (0, -10, 10, 0),
            (0, 10, -10, 0),
            (10, 0, 0, 10)
        ]
    );
    let mut kept = Vec::new();
    with_length_into(&all, 14..=15, &mut kept);
    assert_eq!(kept.len(), 4);
    with_length_into(&all, 15..=i128::MAX, &mut kept);
    assert!(kept.is_empty());
    with_length_into(&all, 0..=14, &mut kept);
    assert!(kept.is_empty());
    let right = rects(&[(2, -20, 20, 20)]);
    let mut inside = Vec::new();
    edge_part_into(&all, &right, true, &mut inside);
    assert_eq!(sorted(&inside), [(2, -8, 10, 0), (10, 0, 2, 8)]);
}

/// Oracle: hand-derived, and the snapping rule of `boolean::union_into`
/// applied to an edge. The rising edge (0, 0)-(10, 10) meets the falling
/// boundary `x + y = 7` of the other layer at (3.5, 3.5), between grid
/// points; each part ends at the last grid point inside it.
#[test]
fn an_edge_cut_between_grid_points_ends_on_the_grid_inside_its_part() {
    let a = vec![seg(0, 0, 10, 10)];
    let b = oct_layer(&[(&[7, 30, 30, 0, 0], &[0, 0, 30, 30, 7])]);
    let (mut inside, mut outside) = (Vec::new(), Vec::new());
    edge_part_into(&a, &b, true, &mut inside);
    edge_part_into(&a, &b, false, &mut outside);
    assert_eq!(sorted(&inside), [(4, 4, 10, 10)]);
    assert_eq!(sorted(&outside), [(0, 0, 3, 3)]);
}

/// Oracle: hand-derived selections. A diamond under a covering square is
/// `inside` it and not `outside`; a square far off is the reverse; and
/// `interacting` finds the diamond, whose right vertex a small square's
/// corner touches.
#[test]
fn octilinear_selections_read_whole_shapes() {
    let a = oct_layer(&[DIAMOND, (&[40, 50, 50, 40], &[0, 0, 10, 10])]);
    let cover = rects(&[(-10, -10, 10, 10)]);
    let (mut inside, mut outside) = (ValidatedLayer::default(), ValidatedLayer::default());
    inside_into(&a, &cover, &mut inside).expect("octilinear");
    outside_into(&a, &cover, &mut outside).expect("octilinear");
    assert_eq!(boxes(&inside), [(-10, -10, 10, 10)]);
    assert_eq!(boxes(&outside), [(40, 0, 50, 10)]);
    let corner = rects(&[(10, 0, 12, 2)]);
    let mut touching = ValidatedLayer::default();
    interacting_into(&a, &corner, true, &mut touching);
    assert_eq!(boxes(&touching), [(-10, -10, 10, 10)]);
}
