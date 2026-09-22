//! Width family: `min_width`, `max_width`, `min_edge_length`, `notch`. Each case
//! is one geometry against the limit at its answer (clean) and one unit past it.

use crate::common;

use common::{Sink, A, RULE};
use gpurify_check::drc::Rule;
use gpurify_check::report::{Severity, Violation};
use gpurify_ingest::StrId;
use gpurify_testgen::shapes::LayoutBuilder;
use gpurify_testgen::{
    assert_clean, assert_has_violation, assert_only_violation, assert_rule_ran, dbu,
    layout_with_violation, point, Amount, ShapeKind, ViolationCase, ViolationShape,
};

/// A rectangle exactly `measured` units across and 1000 long.
fn width_case(measured: i64, limit: i64) -> ViolationCase {
    layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::Width {
                layer: A,
                run: 1_000,
            },
        },
        (0, 0),
        Amount::Length(measured),
        Amount::Length(limit),
    )
}

fn min_width_table(limit: i64) -> Vec<(StrId, Rule)> {
    vec![(
        RULE,
        Rule::MinWidth {
            layer: A,
            limit: dbu(limit),
        },
    )]
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
    let mut sink = Sink::default();

    sink.run(&case.store, &min_width_table(201));

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
    let mut sink = Sink::default();

    sink.run(&case.store, &min_width_table(200));

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
    let mut sink = Sink::default();

    let table = vec![(
        RULE,
        Rule::MaxWidth {
            layer: A,
            limit: dbu(199),
        },
    )];

    sink.run(&case.store, &table);

    assert_only_violation(&sink.out, &case.expected);
    assert_eq!(
        assert_rule_ran(&sink.runs, RULE).examined,
        u64::from(case.shapes)
    );
}

#[test]
fn a_width_exactly_at_the_maximum_is_clean() {
    let case = width_case(200, 200);
    let mut sink = Sink::default();

    let table = vec![(
        RULE,
        Rule::MaxWidth {
            layer: A,
            limit: dbu(200),
        },
    )];

    sink.run(&case.store, &table);

    assert_clean(&sink.runs, &sink.out, RULE);
}

// ---------------------------------------------------------- min_edge_length

/// Oracle: construct-from-answer. The generator's rectangle is 40 units wide
/// and 1000 tall, so it has *two* 40-unit edges — bottom and top — and the doc
/// is explicit that this rule reports per edge rather than per polygon. Both
/// coordinates are asserted: reporting one violation for a shape with two short
/// jogs loses the second place a mask fails.
///
/// `min_edge_length` reports at the edge's *midpoint* — the crate-wide
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
            kind: ShapeKind::EdgeLength {
                layer: A,
                body: 1_000,
            },
        },
        (0, 0),
        Amount::Length(40),
        Amount::Length(41),
    );

    let mut sink = Sink::default();
    let table = vec![(
        RULE,
        Rule::MinEdgeLength {
            layer: A,
            limit: dbu(41),
        },
    )];

    sink.run(&case.store, &table);

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
            kind: ShapeKind::EdgeLength {
                layer: A,
                body: 1_000,
            },
        },
        (0, 0),
        Amount::Length(40),
        Amount::Length(40),
    );

    let mut sink = Sink::default();
    let table = vec![(
        RULE,
        Rule::MinEdgeLength {
            layer: A,
            limit: dbu(40),
        },
    )];

    sink.run(&case.store, &table);

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

    let mut sink = Sink::default();
    let table = vec![(
        RULE,
        Rule::Notch {
            layer: A,
            limit: dbu(61),
        },
    )];

    sink.run(&case.store, &table);

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

    let mut sink = Sink::default();
    let table = vec![(
        RULE,
        Rule::Notch {
            layer: A,
            limit: dbu(60),
        },
    )];

    sink.run(&case.store, &table);

    assert_clean(&sink.runs, &sink.out, RULE);
}

/// A U drawn as three touching rectangles, arms 80 units apart.
///
/// The same conductor as [`u_shape`], fractured the way a router or a GDS writer
/// emits it. Nothing distinguishes the two electrically, and no rule may
/// distinguish them either.
fn fractured_u() -> gpurify_geom::GeometryStore {
    let mut layout = LayoutBuilder::new(1);
    layout.rect(A, 0, 0, 300, 100); // the base, touching both arms along y = 100
    layout.rect(A, 0, 100, 110, 500); // left arm
    layout.rect(A, 190, 100, 300, 500); // right arm, 80 across the gap
    layout.finish().0
}

/// Oracle: construct-from-answer, and the `notch_no_outer_merge` defect.
///
/// A U whose arms are 80 units apart has an 80-unit notch. Drawing that U as one
/// polygon reports it; drawing it as three touching rectangles used to report
/// **nothing**, because `facing` ran `validate_layer_into` per store row
/// and each rectangle is convex on its own. `min_spacing` did not report it
/// either — the three rows are one merged figure and the gap is exempt as
/// intra-figure, which is correct for spacing.
///
/// So a real 80-unit defect passed both rules, and which one it passed depended
/// on nothing but how the layout happened to be fractured. Notch and spacing
/// must partition the same merged geometry, and this is the half that was
/// missing.
#[test]
fn a_notch_across_two_rectangles_of_one_merged_figure_is_still_a_notch() {
    let store = fractured_u();

    let mut sink = Sink::default();
    let table = vec![(
        RULE,
        Rule::Notch {
            layer: A,
            limit: dbu(81),
        },
    )];

    sink.run(&store, &table);

    let found = assert_rule_ran(&sink.runs, RULE);
    assert_eq!(
        sink.out.len(),
        1,
        "an 80-unit notch across a fractured figure went unreported; found \
         {found:?}"
    );
    assert_eq!(
        sink.out.measured[0],
        gpurify_check::report::Measurement::Length(dbu(80)),
        "the notch is the 80-unit gap between the two arms"
    );
}

/// The other side of the same boundary, so the test above is not satisfied by a
/// rule that reports every same-figure pair it sees. Exactly at the limit is
/// clean, which is what every other case in this file asserts of its own rule.
#[test]
fn a_fractured_notch_exactly_at_the_limit_is_clean() {
    let store = fractured_u();

    let mut sink = Sink::default();
    let table = vec![(
        RULE,
        Rule::Notch {
            layer: A,
            limit: dbu(80),
        },
    )];

    sink.run(&store, &table);

    assert_clean(&sink.runs, &sink.out, RULE);
}

/// The partition, stated directly: the two rules that share this geometry must
/// cover the 80-unit gap exactly once between them.
///
/// `min_spacing` exempting it is correct — the three rectangles are one
/// conductor, and a wire is not too close to itself. What made the pair a
/// fail-open was that `notch` did not pick up what `min_spacing` put down.
#[test]
fn spacing_exempts_the_intra_figure_gap_that_notch_now_reports() {
    let store = fractured_u();

    let mut sink = Sink::default();
    let table = vec![(
        RULE,
        Rule::MinSpacing {
            layer: A,
            limit: dbu(81),
        },
    )];

    sink.run(&store, &table);

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

    let mut sink = Sink::default();
    let table = vec![(
        RULE,
        Rule::Notch {
            layer: A,
            limit: dbu(1_000_000),
        },
    )];

    sink.run(&store, &table);

    assert_clean(&sink.runs, &sink.out, RULE);
}
