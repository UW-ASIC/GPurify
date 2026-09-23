//! Width family: `min_width`, `max_width`, `cut_size`, `min_edge_length`, `notch`. Each case
//! is one geometry against the limit at its answer (clean) and one unit past it.

use crate::common;

use common::{Sink, A, RULE};
use gpurify_check::drc::Rule;
use gpurify_check::report::{Measurement, Severity, Violation};
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

// ---------------------------------------------- max_width by region, cut_size

fn max_width_table(limit: i64) -> Vec<(StrId, Rule)> {
    vec![(
        RULE,
        Rule::MaxWidth {
            layer: A,
            limit: dbu(limit),
        },
    )]
}

/// IHP Slt.c: metal wider than 30 um must be slotted, so an unslotted
/// `max_width` of 30 um. A 40 um plate with a 0.2 um tab is 40 um wide where
/// the plate is; the old rule read the polygon's narrowest width (the tab) and
/// passed it.
#[test]
fn ihp_slt_c_a_plate_with_a_thin_tab_is_as_wide_as_the_plate() {
    let mut layout = LayoutBuilder::new(1);
    let plate = layout.push(
        A,
        &[0, 40_000, 40_000, 20_200, 20_200, 20_000, 20_000, 0],
        &[0, 0, 40_000, 40_000, 41_000, 41_000, 40_000, 40_000],
    );
    let (store, ids) = layout.finish();

    let mut sink = Sink::default();
    sink.run(&store, &max_width_table(30_000));

    assert_eq!(sink.out.len(), 1);
    assert_eq!(sink.out.measured[0], Measurement::Length(dbu(40_000)));
    assert_eq!(sink.out.get(0).shapes, (ids.of(plate), None));
}

/// Two abutting 20 um rectangles are one 40 um plate on the merged layer.
#[test]
fn two_abutting_narrow_rectangles_are_as_wide_as_their_union() {
    let mut layout = LayoutBuilder::new(1);
    let first = layout.rect(A, 0, 0, 20_000, 40_000);
    layout.rect(A, 20_000, 0, 40_000, 40_000);
    let (store, ids) = layout.finish();

    let mut sink = Sink::default();
    sink.run(&store, &max_width_table(30_000));

    assert_eq!(sink.out.len(), 1);
    assert_eq!(sink.out.measured[0], Measurement::Length(dbu(40_000)));
    assert_eq!(sink.out.get(0).shapes, (ids.of(first), None));
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 2);
}

fn cut_size_table(width: i64, height: i64) -> Vec<(StrId, Rule)> {
    vec![(
        RULE,
        Rule::CutSize {
            layer: A,
            width: dbu(width),
            height: dbu(height),
        },
    )]
}

/// sky130 licon.1: "min and max L and W of licon: 0.17 um". A 0.17 x 0.34 slot
/// passes a 0.17 min width and a 0.17 max width (its narrowest width is 0.17);
/// it is not a licon.
#[test]
fn sky130_licon_1_a_slot_is_not_a_licon() {
    let mut layout = LayoutBuilder::new(1);
    let slot = layout.rect(A, 0, 0, 170, 340);
    let (store, ids) = layout.finish();

    let mut widths = Sink::default();
    widths.run(&store, &max_width_table(170));
    assert_clean(&widths.runs, &widths.out, RULE);

    let mut sink = Sink::default();
    sink.run(&store, &cut_size_table(170, 170));
    assert_only_violation(
        &sink.out,
        &Violation {
            rule: RULE,
            layer: A,
            severity: Severity::Error,
            at: point(85, 170),
            measured: Measurement::Length(dbu(340)),
            limit: Measurement::Length(dbu(170)),
            shapes: (ids.of(slot), None),
        },
    );
}

/// The licon itself, and two licons drawn abutting (one 0.34 slot once merged).
#[test]
fn sky130_licon_1_a_square_passes_and_two_abutting_squares_do_not() {
    let mut layout = LayoutBuilder::new(1);
    // The good square is drawn first but lies right of the slot.
    layout.rect(A, 5_000, 0, 5_170, 170);
    let first = layout.rect(A, 0, 0, 170, 170);
    layout.rect(A, 170, 0, 340, 170);
    let (store, ids) = layout.finish();

    let mut sink = Sink::default();
    sink.run(&store, &cut_size_table(170, 170));

    assert_eq!(sink.out.len(), 1);
    assert_eq!(sink.out.measured[0], Measurement::Length(dbu(340)));
    // Blamed on a drawn row of the slot, not on the merge's own numbering.
    assert_eq!(sink.out.shape_a[0], ids.of(first));
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 2);
}

/// A rectangular cut either way round, and an L inside the right box.
#[test]
fn a_cut_size_accepts_either_orientation_and_refuses_a_non_rectangle() {
    let mut layout = LayoutBuilder::new(1);
    layout.rect(A, 0, 0, 170, 510);
    layout.rect(A, 1_000, 0, 1_510, 170);
    layout.push(
        A,
        &[2_000, 2_510, 2_510, 2_100, 2_100, 2_000],
        &[0, 0, 100, 100, 170, 170],
    );
    let (store, _ids) = layout.finish();

    let mut sink = Sink::default();
    sink.run(&store, &cut_size_table(170, 510));

    assert_eq!(sink.out.len(), 1);
    assert_eq!(
        sink.out.measured[0],
        Measurement::Area(gpurify_geom::DbuArea::new(510 * 100 + 100 * 70))
    );
}

/// Oracle: construct-from-answer. The notch is measured on the merged layer,
/// whose figures are numbered by the merge's own scratch store: here the plain
/// square left of the U is its figure 0 and the U its figure 1. The finding
/// must name the U's lowest drawn row, the base drawn first, not row 1 (the
/// U's left arm), which is what the scratch number would read as.
#[test]
fn a_notch_names_the_lowest_drawn_row_of_its_own_figure() {
    let mut layout = LayoutBuilder::new(1);
    let base = layout.rect(A, 1_000, 0, 1_300, 100);
    layout.rect(A, 1_000, 100, 1_110, 500);
    layout.rect(A, 1_190, 100, 1_300, 500);
    let square = layout.rect(A, 0, 0, 100, 100);
    let (store, ids) = layout.finish();
    assert!(ids.of(base) < ids.of(square), "the base is drawn first");

    let mut sink = Sink::default();
    sink.run(
        &store,
        &[(
            RULE,
            Rule::Notch {
                layer: A,
                limit: dbu(81),
            },
        )],
    );

    assert_eq!(sink.out.len(), 1, "one notch, in the U");
    assert_eq!(sink.out.shape_a[0], ids.of(base));
}
