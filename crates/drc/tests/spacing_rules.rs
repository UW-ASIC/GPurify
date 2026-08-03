//! Spacing family: the six rules built on a candidate-pair prune, and
//! `parallel_run_length`.
//!
//! Two things are asserted everywhere in this file and nowhere else in the
//! crate. The first is the coordinate: a spacing violation is reported at the
//! midpoint of the gap, so a rule that finds the right pair and points at the
//! wrong shape fails here. The second is `examined`, which counts *candidate
//! pairs* rather than shapes — the number that says whether the prune did
//! anything, and the number a fail-open prune would quietly shrink.

mod common;

use common::{Env, Sink, A, B, RULE};
use gpurify_core::Bbox;
use gpurify_drc::rules::spacing::{
    check_corner_to_corner, check_eol_spacing, check_min_spacing, check_min_spacing_diff,
    check_prl_spacing, check_wide_dependent_spacing, parallel_run_length, CornerToCornerTable,
    EolSpacingTable, MinSpacingDiffTable, MinSpacingTable, PrlSpacingTable,
    WideDependentSpacingTable,
};
use gpurify_report::{Measurement, Outcome, Severity, Violation};
use gpurify_testgen::shapes::LayoutBuilder;
use gpurify_testgen::{
    assert_clean, assert_only_violation, assert_rule_ran, dbu, layout_with_violation, point, Amount,
    ShapeKind, ViolationCase, ViolationShape,
};

/// Two 200-sided squares on layer A facing across an exact gap, 400 tall so
/// their parallel run length is 400.
fn spaced(gap: i64, limit: i64) -> ViolationCase {
    layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::Spacing { layer: A, extent: 200 },
        },
        (0, 0),
        Amount::Length(gap),
        Amount::Length(limit),
    )
}

fn min_spacing_table(limit: i64) -> MinSpacingTable {
    let mut table = MinSpacingTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.limit.push(dbu(limit));
    table
}

// -------------------------------------------------------------- min_spacing

/// Oracle: construct-from-answer. The generator placed two shapes exactly 100
/// apart and fixed the reported coordinate at the midpoint of that gap. A limit
/// of 101 is the smallest that fails it.
#[test]
fn a_gap_one_unit_under_the_limit_is_reported_at_the_midpoint_of_that_gap() {
    let case = spaced(100, 101);
    let env = Env::default();
    let mut sink = Sink::default();

    check_min_spacing(
        env.design(&case.store),
        &min_spacing_table(101),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_only_violation(&sink.out, &case.expected);
    let run = assert_rule_ran(&sink.runs, RULE);
    assert_eq!(
        run.examined, 1,
        "two shapes within the prune radius are exactly one candidate pair"
    );
    assert_eq!(run.violations, 1);
}

/// Oracle: construct-from-answer. A gap exactly at the limit is a gap that
/// meets the rule. The candidate pair still has to be *generated* and measured,
/// which is what the `examined` assertion checks: a prune narrowed below the
/// rule's own limit would drop this pair, report clean, and be indistinguishable
/// from a pass without it.
#[test]
fn a_gap_exactly_at_the_limit_is_clean_and_the_pair_was_still_examined() {
    let case = spaced(100, 100);
    let env = Env::default();
    let mut sink = Sink::default();

    check_min_spacing(
        env.design(&case.store),
        &min_spacing_table(100),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

/// Oracle: construct-from-answer. Two overlapping shapes on one layer are one
/// merged figure, and the distance between them is zero because they are a
/// wire, not because they are too close. The old tree made this exemption
/// optional; a rule that reported here would flag every conductor in a design.
#[test]
fn two_shapes_of_one_merged_figure_have_no_gap_to_violate() {
    let mut layout = LayoutBuilder::new(1);
    layout.rect(A, 0, 0, 400, 200);
    layout.rect(A, 300, 0, 700, 200);
    let (store, _ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();
    check_min_spacing(
        env.design(&store),
        &min_spacing_table(1_000),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(
        assert_rule_ran(&sink.runs, RULE).examined,
        1,
        "the touching pair is still a candidate; it is dropped after the figure \
         labelling, not before it"
    );
}

// --------------------------------------------------------- min_spacing_diff

/// Oracle: construct-from-answer. The cross-layer twin of the case above: a
/// shape on A and a shape on B, 100 apart, reported at the midpoint against a
/// limit of 101. The violation is attributed to layer A, which is the first
/// layer the rule names.
#[test]
fn a_cross_layer_gap_one_unit_under_the_limit_is_reported_at_the_midpoint() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::Separation { a: A, b: B, size: 200 },
        },
        (0, 0),
        Amount::Length(100),
        Amount::Length(101),
    );

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = MinSpacingDiffTable::default();
    table.rule.push(RULE);
    table.a.push(A);
    table.b.push(B);
    table.limit.push(dbu(101));

    check_min_spacing_diff(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_only_violation(&sink.out, &case.expected);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

/// Oracle: construct-from-answer. The cross-layer pair exactly at its limit is
/// clean, and the pair was still generated and measured — which is the half a
/// prune narrowed below the rule's own limit would quietly skip.
#[test]
fn a_cross_layer_gap_exactly_at_the_limit_is_clean_and_the_pair_was_examined() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::Separation { a: A, b: B, size: 200 },
        },
        (0, 0),
        Amount::Length(100),
        Amount::Length(100),
    );

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = MinSpacingDiffTable::default();
    table.rule.push(RULE);
    table.a.push(A);
    table.b.push(B);
    table.limit.push(dbu(100));

    check_min_spacing_diff(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

/// Oracle: construct-from-answer. Two shapes on different layers are never one
/// figure, so the merged-figure exemption that saves the same-layer case above
/// must not apply here: touching is a spacing of zero, and two layers required
/// to stay apart have failed if they meet at all.
///
/// The two squares meet at exactly one point, so the closest approach is that
/// point and its midpoint is that point — which is what makes the coordinate
/// assertable at all for a pair whose gap is zero.
#[test]
fn two_layers_that_meet_have_a_spacing_of_zero_and_have_failed() {
    let mut layout = LayoutBuilder::new(2);
    let lower = layout.rect(A, 0, 0, 100, 100);
    let upper = layout.rect(B, 100, 100, 200, 200);
    let (store, ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = MinSpacingDiffTable::default();
    table.rule.push(RULE);
    table.a.push(A);
    table.b.push(B);
    table.limit.push(dbu(50));

    check_min_spacing_diff(
        env.design(&store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_only_violation(
        &sink.out,
        &Violation {
            rule: RULE,
            layer: A,
            severity: Severity::Error,
            at: point(100, 100),
            measured: Measurement::Length(dbu(0)),
            limit: Measurement::Length(dbu(50)),
            shapes: (ids.of(lower), Some(ids.of(upper))),
        },
    );
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

// -------------------------------------------------------------- eol_spacing

/// Oracle: construct-from-answer. The line's 40-unit end faces a wide
/// neighbour across 100. With `eol_width` at 41 that end qualifies as an end of
/// line, so the enlarged limit of 101 applies and is violated by one unit.
#[test]
fn an_end_of_line_one_unit_under_its_enlarged_limit_is_reported_at_the_gap() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::EndOfLine {
                layer: A,
                width: 40,
                extent: 300,
            },
        },
        (0, 0),
        Amount::Length(100),
        Amount::Length(101),
    );

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = EolSpacingTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.eol_width.push(dbu(41));
    table.limit.push(dbu(101));

    check_eol_spacing(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_only_violation(&sink.out, &case.expected);
    assert_eq!(
        assert_rule_ran(&sink.runs, RULE).examined,
        1,
        "examined counts the pairs whose near edge qualified, not every candidate"
    );
}

/// Oracle: construct-from-answer. A qualifying end of line exactly at its
/// enlarged limit is clean, and the qualifying pair was still counted — so this
/// distinguishes "the end of line had enough room" from "no end of line was
/// found", which the violation table alone cannot.
#[test]
fn a_qualifying_end_of_line_exactly_at_its_limit_is_clean() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::EndOfLine {
                layer: A,
                width: 40,
                extent: 300,
            },
        },
        (0, 0),
        Amount::Length(100),
        Amount::Length(100),
    );

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = EolSpacingTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.eol_width.push(dbu(41));
    table.limit.push(dbu(100));

    check_eol_spacing(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

/// Oracle: construct-from-answer. An edge exactly at `eol_width` is not shorter
/// than it, so it is an ordinary edge and the enlarged limit never applies —
/// which is the whole trigger condition, expressed in one unit. `examined`
/// falls to zero here on purpose: the population the rule judged is empty, and
/// counting every candidate instead would make a layer with no short edges look
/// thoroughly checked.
#[test]
fn an_edge_exactly_at_the_end_of_line_width_is_not_an_end_of_line() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::EndOfLine {
                layer: A,
                width: 40,
                extent: 300,
            },
        },
        (0, 0),
        Amount::Length(100),
        Amount::Length(101),
    );

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = EolSpacingTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.eol_width.push(dbu(40));
    table.limit.push(dbu(101));

    check_eol_spacing(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_eq!(sink.runs.len(), 1);
    assert_eq!(sink.runs[0].outcome, Outcome::Ran);
    assert_eq!(sink.runs[0].examined, 0);
    assert_eq!(sink.runs[0].violations, 0);
    assert!(sink.out.rule.is_empty());
}

// -------------------------------------------------------------- prl_spacing

/// Oracle: construct-from-answer. The pair runs alongside itself for 400 units,
/// which reaches a threshold of 400, so the larger limit applies and a gap of
/// 100 fails it by one.
#[test]
fn a_pair_at_the_parallel_run_threshold_is_held_to_the_larger_limit() {
    let case = spaced(100, 101);
    let env = Env::default();
    let mut sink = Sink::default();

    let mut table = PrlSpacingTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.prl_threshold.push(dbu(400));
    table.limit.push(dbu(101));

    check_prl_spacing(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_only_violation(&sink.out, &case.expected);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

/// Oracle: construct-from-answer. One unit of run length the other way and the
/// rule does not apply at all — the pair is a corner clip, not a long parallel
/// run, and it buys the layer's ordinary spacing instead. The `examined` count
/// falling to zero is how a report distinguishes that from a pass.
#[test]
fn a_run_one_unit_short_of_the_threshold_is_not_judged_by_this_rule() {
    let case = spaced(100, 101);
    let env = Env::default();
    let mut sink = Sink::default();

    let mut table = PrlSpacingTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.prl_threshold.push(dbu(401));
    table.limit.push(dbu(101));

    check_prl_spacing(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_eq!(sink.runs.len(), 1);
    assert_eq!(sink.runs[0].outcome, Outcome::Ran);
    assert_eq!(sink.runs[0].examined, 0);
    assert!(sink.out.rule.is_empty());
}

#[test]
fn a_qualifying_run_exactly_at_the_larger_limit_is_clean() {
    let case = spaced(100, 100);
    let env = Env::default();
    let mut sink = Sink::default();

    let mut table = PrlSpacingTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.prl_threshold.push(dbu(400));
    table.limit.push(dbu(100));

    check_prl_spacing(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

// --------------------------------------------------------- corner_to_corner

/// Oracle: construct-from-answer, on a Pythagorean triple so the answer is an
/// exact integer. Two squares offset by 60 and 80 have nearest corners exactly
/// 100 apart, and 100 is representable only because 60-80-100 is a right
/// triangle — an arbitrary offset would give an irrational distance and the
/// test would be asserting on the rounding rather than on the measurement.
///
/// `check_corner_to_corner` reports at the vertex of the *first* shape in the
/// closest vertex pair, not at the midpoint of the segment joining them. The
/// first shape is the one `shapes.0` names — the lower-left square, spanning
/// `(-130, -140) .. (-30, -40)` — so the vertex is its upper-right corner.
#[test]
fn a_diagonal_corner_gap_is_measured_exactly_on_a_pythagorean_offset() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::CornerToCorner {
                layer: A,
                size: 100,
                legs: (60, 80),
            },
        },
        (0, 0),
        Amount::Length(100),
        Amount::Length(101),
    );

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = CornerToCornerTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.limit.push(dbu(101));

    check_corner_to_corner(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_only_violation(
        &sink.out,
        &Violation {
            at: point(-30, -40),
            ..case.expected
        },
    );
    assert_eq!(
        assert_rule_ran(&sink.runs, RULE).examined,
        1,
        "examined counts diagonally offset pairs, and there is one"
    );
}

#[test]
fn a_diagonal_corner_gap_exactly_at_the_limit_is_clean() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::CornerToCorner {
                layer: A,
                size: 100,
                legs: (60, 80),
            },
        },
        (0, 0),
        Amount::Length(100),
        Amount::Length(100),
    );

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = CornerToCornerTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.limit.push(dbu(100));

    check_corner_to_corner(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

/// Oracle: construct-from-answer. Two shapes whose projections overlap on an
/// axis face each other across an edge, not across a corner, so they belong to
/// `min_spacing` and this rule must not judge them at all. Judging them would
/// double-report every ordinary gap in a design under a second rule id.
#[test]
fn a_pair_that_overlaps_on_an_axis_is_not_a_corner_to_corner_situation() {
    let case = spaced(100, 101);
    let env = Env::default();
    let mut sink = Sink::default();

    let mut table = CornerToCornerTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.limit.push(dbu(1_000));

    check_corner_to_corner(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_eq!(sink.runs.len(), 1);
    assert_eq!(sink.runs[0].outcome, Outcome::Ran);
    assert_eq!(sink.runs[0].examined, 0);
    assert!(sink.out.rule.is_empty());
}

// -------------------------------------------------- wide_dependent_spacing

/// Oracle: construct-from-answer. Each square is 200 across at its narrowest,
/// so a width threshold of 200 makes both wide and the enlarged limit applies —
/// failed by one unit at a gap of 100.
#[test]
fn a_pair_containing_a_wide_shape_is_held_to_the_wide_limit() {
    let case = spaced(100, 101);
    let env = Env::default();
    let mut sink = Sink::default();

    let mut table = WideDependentSpacingTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.width_threshold.push(dbu(200));
    table.limit.push(dbu(101));

    check_wide_dependent_spacing(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_only_violation(&sink.out, &case.expected);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

/// Oracle: construct-from-answer. A qualifying wide pair exactly at the wide
/// limit is clean, over a population of one — which separates "the wide pair had
/// enough room" from "nothing was found to be wide".
#[test]
fn a_qualifying_wide_pair_exactly_at_the_wide_limit_is_clean() {
    let case = spaced(100, 100);
    let env = Env::default();
    let mut sink = Sink::default();

    let mut table = WideDependentSpacingTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.width_threshold.push(dbu(200));
    table.limit.push(dbu(100));

    check_wide_dependent_spacing(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

/// Oracle: construct-from-answer. One unit more threshold and neither shape is
/// wide, so no pair qualifies. "Wide" is measured on the narrowest width, not
/// on a bounding box, which is what makes the 200 in this test the same 200 the
/// width family measures.
#[test]
fn a_shape_one_unit_narrower_than_the_wide_threshold_does_not_trigger_the_rule() {
    let case = spaced(100, 101);
    let env = Env::default();
    let mut sink = Sink::default();

    let mut table = WideDependentSpacingTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.width_threshold.push(dbu(201));
    table.limit.push(dbu(101));

    check_wide_dependent_spacing(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_eq!(sink.runs.len(), 1);
    assert_eq!(sink.runs[0].outcome, Outcome::Ran);
    assert_eq!(sink.runs[0].examined, 0);
    assert!(sink.out.rule.is_empty());
}

// ------------------------------------------------------- parallel_run_length

fn bbox(xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> Bbox {
    Bbox {
        xlo: dbu(xlo),
        ylo: dbu(ylo),
        xhi: dbu(xhi),
        yhi: dbu(yhi),
    }
}

/// Oracle: closed form. Two boxes separated along x face each other across x,
/// so the run length is the overlap of their y projections — `[0, 100]` against
/// `[40, 200]` is 60. The same pair rotated a quarter turn gives the same
/// answer, which is the check that the axis is chosen from the geometry rather
/// than hard-coded.
#[test]
fn parallel_run_length_is_the_projection_overlap_on_the_facing_axis() {
    assert_eq!(
        parallel_run_length(bbox(0, 0, 10, 100), bbox(20, 40, 30, 200)),
        dbu(60)
    );
    assert_eq!(
        parallel_run_length(bbox(0, 0, 100, 10), bbox(40, 20, 200, 30)),
        dbu(60)
    );
}

/// Oracle: closed form. Two boxes overlapping on neither axis face each other
/// across neither, so they have no parallel run at all — which is exactly the
/// corner-to-corner case, and the reason that rule exists separately.
#[test]
fn a_diagonally_offset_pair_has_no_parallel_run() {
    assert_eq!(
        parallel_run_length(bbox(0, 0, 10, 10), bbox(20, 20, 30, 30)),
        dbu(0)
    );
}

/// Oracle: law. Two shapes run alongside each other for the same distance
/// whichever one is named first, for any pair. An implementation that projected
/// only the first operand would pass the fixed cases above and fail here.
#[test]
fn parallel_run_length_is_symmetric_in_its_two_operands() {
    let cases = [
        (bbox(0, 0, 10, 100), bbox(20, 40, 30, 200)),
        (bbox(-500, -30, -400, 70), bbox(-100, 0, 0, 1_000)),
        (bbox(0, 0, 10, 10), bbox(20, 20, 30, 30)),
        (bbox(0, 0, 100, 10), bbox(40, 20, 200, 30)),
    ];
    for (a, b) in cases {
        assert_eq!(
            parallel_run_length(a, b),
            parallel_run_length(b, a),
            "the run length of {a:?} against {b:?} depends on the operand order"
        );
    }
}
