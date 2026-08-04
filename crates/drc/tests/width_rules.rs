//! Width family: `min_width`, `max_width`, `min_edge_length`, `notch`, and the
//! three pure decisions underneath them.
//!
//! Every case in this file is one geometry measured against two limits. The
//! geometry fixes the answer — a rectangle the generator built exactly 200
//! units across is 200 units across — so the limit at that number passes and
//! the limit one unit past it fails. That single unit is the whole rule, and it
//! is the only thing separating a width check from a shape that happens to be
//! flagged.

mod common;

use common::{Env, Sink, A, RULE};
use gpurify_core::LayerId;
use gpurify_drc::rules::width::{
    check_max_width, check_min_edge_length, check_min_width, check_notch, narrowest_notch,
    narrowest_width, shortest_edge, MaxWidthTable, MinEdgeLengthTable, MinWidthTable, NotchTable,
};
use gpurify_report::{Severity, Violation};
use gpurify_testgen::shapes::{hole, l_shape, plus_shape, rect, u_shape, LayoutBuilder};
use gpurify_testgen::{
    assert_clean, assert_has_violation, assert_only_violation, assert_rule_ran, dbu, point,
    layout_with_violation, Amount, ShapeKind, ViolationCase, ViolationShape,
};

/// A rectangle exactly `measured` units across and 1000 long.
fn width_case(measured: i64, limit: i64) -> ViolationCase {
    layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::Width { layer: A, run: 1_000 },
        },
        (0, 0),
        Amount::Length(measured),
        Amount::Length(limit),
    )
}

fn min_width_table(limit: i64) -> MinWidthTable {
    let mut table = MinWidthTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.limit.push(dbu(limit));
    table
}

// ---------------------------------------------------------------- min_width

/// Oracle: construct-from-answer. The generator built a rectangle 200 units
/// across, so 200 is the measurement and the coordinate it is measured at is
/// the rectangle's centre. Both are asserted, because a rule that finds the
/// right shape and reports the wrong number is the failure the previous suite
/// could not see.
#[test]
fn a_width_one_unit_under_the_limit_is_reported_at_the_narrow_span_with_its_measurement() {
    let case = width_case(200, 201);
    let env = Env::default();
    let mut sink = Sink::default();

    check_min_width(
        env.design(&case.store),
        &min_width_table(201),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_only_violation(&sink.out, &case.expected);
    let run = assert_rule_ran(&sink.runs, RULE);
    assert_eq!(
        run.examined,
        u64::from(case.shapes),
        "min_width examines polygons on its layer, and the layout holds {}",
        case.shapes
    );
    assert_eq!(run.violations, 1);
}

/// Oracle: construct-from-answer, the other side of the same unit. A shape
/// exactly at the limit is not a violation, and the assertion says so through
/// the `RuleRun` as well as through the empty table — an empty table alone is
/// what a rule that never executed also produces.
#[test]
fn a_width_exactly_at_the_limit_is_clean_and_the_rule_says_it_looked() {
    let case = width_case(200, 200);
    let env = Env::default();
    let mut sink = Sink::default();

    check_min_width(
        env.design(&case.store),
        &min_width_table(200),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    let run = assert_rule_ran(&sink.runs, RULE);
    assert_eq!(run.examined, u64::from(case.shapes));
}

// ---------------------------------------------------------------- max_width

/// Oracle: construct-from-answer. Same scan and same measurement as
/// `min_width`, compared the other way: 200 is above a limit of 199 and is not
/// above a limit of 200.
#[test]
fn a_width_one_unit_over_the_maximum_is_reported_with_the_same_measurement() {
    let case = width_case(200, 199);
    let env = Env::default();
    let mut sink = Sink::default();

    let mut table = MaxWidthTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.limit.push(dbu(199));

    check_max_width(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_only_violation(&sink.out, &case.expected);
    assert_eq!(
        assert_rule_ran(&sink.runs, RULE).examined,
        u64::from(case.shapes)
    );
}

#[test]
fn a_width_exactly_at_the_maximum_is_clean() {
    let case = width_case(200, 200);
    let env = Env::default();
    let mut sink = Sink::default();

    let mut table = MaxWidthTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.limit.push(dbu(200));

    check_max_width(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
}

// ---------------------------------------------------------- min_edge_length

/// Oracle: construct-from-answer. The generator's rectangle is 40 units wide
/// and 1000 tall, so it has *two* 40-unit edges — bottom and top — and the doc
/// is explicit that this rule reports per edge rather than per polygon. Both
/// coordinates are asserted: reporting one violation for a shape with two short
/// jogs loses the second place a mask fails.
///
/// `check_min_edge_length` reports at the edge's *midpoint* — the crate-wide
/// convention stated on `rules::mod`, and the one `testgen::violation` already
/// followed. The rectangle is `(-20, 0) .. (20, 1000)`, so its two short edges
/// run along `y = 0` and `y = 1000` and their midpoints are `(0, 0)` and
/// `(0, 1000)`. A midpoint has no winding, which is why it is the convention:
/// the first-vertex reading made the answer depend on which corner the builder
/// happened to push first.
#[test]
fn two_short_edges_on_one_shape_are_two_violations_at_two_coordinates() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::EdgeLength { layer: A, body: 1_000 },
        },
        (0, 0),
        Amount::Length(40),
        Amount::Length(41),
    );

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = MinEdgeLengthTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.limit.push(dbu(41));

    check_min_edge_length(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_eq!(
        sink.out.rule.len(),
        2,
        "a rectangle 40 across has two 40-unit edges, and each is its own edit"
    );
    for midpoint in [point(0, 0), point(0, 1_000)] {
        let _ = assert_has_violation(
            &sink.out,
            &Violation {
                at: midpoint,
                ..case.expected
            },
        );
    }

    let run = assert_rule_ran(&sink.runs, RULE);
    assert_eq!(
        run.examined, 4,
        "examined counts edges, and a rectangle has four"
    );
    assert_eq!(run.violations, 2);
}

#[test]
fn edges_exactly_at_the_minimum_length_are_clean_over_a_nonzero_edge_count() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::EdgeLength { layer: A, body: 1_000 },
        },
        (0, 0),
        Amount::Length(40),
        Amount::Length(40),
    );

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = MinEdgeLengthTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.limit.push(dbu(40));

    check_min_edge_length(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 4);
}

// -------------------------------------------------------------------- notch

/// Oracle: construct-from-answer. A U's internal gap is a notch, not a spacing:
/// it is one polygon, and the coordinate is inside the polygon's bounding box
/// and outside the polygon. A bounding-box implementation cannot produce that
/// point, which is why it is asserted rather than the shape's centre.
#[test]
fn a_notch_one_unit_under_the_limit_is_reported_inside_the_void() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::Notch {
                layer: A,
                arm: 400,
                thickness: 100,
            },
        },
        (0, 0),
        Amount::Length(60),
        Amount::Length(61),
    );

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = NotchTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.limit.push(dbu(61));

    check_notch(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_only_violation(&sink.out, &case.expected);
    assert_eq!(
        assert_rule_ran(&sink.runs, RULE).examined,
        u64::from(case.shapes)
    );
}

#[test]
fn a_notch_exactly_at_the_limit_is_clean() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::Notch {
                layer: A,
                arm: 400,
                thickness: 100,
            },
        },
        (0, 0),
        Amount::Length(60),
        Amount::Length(60),
    );

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = NotchTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.limit.push(dbu(60));

    check_notch(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
}

/// Oracle: construct-from-answer. A convex shape has no facing pair whose gap
/// lies outside it, so it has no notch at all — and a rule that measured the
/// external gap between the two arms of nothing would flag every rectangle in
/// a design.
#[test]
fn a_convex_shape_has_no_notch_to_report() {
    let mut layout = LayoutBuilder::new(1);
    layout.rect(A, 0, 0, 40, 40);
    let (store, _ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = NotchTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.limit.push(dbu(1_000_000));

    check_notch(
        env.design(&store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
}

// --------------------------------------------------------------- decisions

/// Oracle: closed form. Every shape below has its narrowest width written down
/// in `testgen::shapes`' doc comments as a parameter of its construction: an L
/// and a plus are as narrow as their thickness, a rectangle is as narrow as its
/// shorter side. All three lie strictly inside their bounding box, which is
/// what an implementation measuring `min(bbox.width, bbox.height)` would return
/// instead.
#[test]
fn narrowest_width_is_the_thickness_of_the_shape_not_of_its_bounding_box() {
    let mut layout = LayoutBuilder::new(3);
    layout.rect(A, 0, 0, 300, 120);
    layout.shape(LayerId(1), &l_shape(0, 0, 500, 70));
    layout.shape(LayerId(2), &plus_shape(0, 0, 400, 90));
    let (store, _ids) = layout.finish();

    for (layer, expected) in [(A, 120), (LayerId(1), 70), (LayerId(2), 90)] {
        let layer_geometry = common::validated(&store, layer);
        assert_eq!(
            narrowest_width(layer_geometry.get(&store, 0)),
            dbu(expected),
            "layer {layer:?} should be {expected} across at its narrowest"
        );
    }
}

/// Oracle: closed form. A ring of outer side 200 with a 120-side hole has walls
/// of `(200 - 120) / 2 = 40`, and that wall is the narrowest material in the
/// shape. Ignoring the hole gives 200, which is how a thin-walled ring passes a
/// width rule it should fail.
#[test]
fn narrowest_width_counts_the_wall_between_an_outer_edge_and_a_hole() {
    let mut layout = LayoutBuilder::new(1);
    layout.shape(A, &rect(0, 0, 200, 200));
    layout.shape(A, &hole(40, 40, 160, 160));
    let (store, _ids) = layout.finish();

    let layer_geometry = common::validated(&store, A);
    assert_eq!(narrowest_width(layer_geometry.get(&store, 0)), dbu(40));
}

/// Oracle: closed form. A U's gap is its notch by construction, and a convex
/// shape has none — which is a different answer from a notch of zero and is why
/// the return type is an `Option`.
#[test]
fn narrowest_notch_is_the_gap_of_a_u_and_absent_for_a_convex_shape() {
    let mut layout = LayoutBuilder::new(2);
    layout.shape(A, &u_shape(0, 0, 300, 50, 80));
    layout.rect(LayerId(1), 0, 0, 100, 100);
    let (store, _ids) = layout.finish();

    let with_notch = common::validated(&store, A);
    assert_eq!(
        narrowest_notch(with_notch.get(&store, 0)),
        Some(dbu(80)),
        "the U was built with a gap of 80"
    );

    let convex = common::validated(&store, LayerId(1));
    assert_eq!(narrowest_notch(convex.get(&store, 0)), None);
}

/// Oracle: closed form. An L of arm 500 and thickness 70 has edges of
/// 500, 70, 430, 430, 70 and 500 — enumerable straight off the coordinate run
/// in `l_shape` — so its shortest edge is 70.
#[test]
fn shortest_edge_is_the_shortest_side_of_the_coordinate_run() {
    let mut layout = LayoutBuilder::new(2);
    layout.shape(A, &l_shape(0, 0, 500, 70));
    layout.rect(LayerId(1), 0, 0, 90, 3_000);
    let (store, _ids) = layout.finish();

    let ell = common::validated(&store, A);
    assert_eq!(shortest_edge(ell.get(&store, 0)), dbu(70));

    let stripe = common::validated(&store, LayerId(1));
    assert_eq!(shortest_edge(stripe.get(&store, 0)), dbu(90));
}
