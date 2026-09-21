//! Area family: `min_area`, `min_enclosed_area`, `cheesing`, `density`.
//!
//! Two properties in this file are worth more than the rest put together.
//!
//! `min_area` measures *connected figures*, not input polygons, so the test
//! below builds a figure out of two fragments that are each below the limit and
//! together above it. A per-polygon implementation reports two violations that
//! do not exist and passes every other test in this file.
//!
//! `density` sweeps in steps smaller than the window, and the step test builds
//! the one layout that distinguishes the two: a hot spot centred on a
//! whole-window boundary, which every stepped window sees and no unstepped
//! window does.

use crate::common;

use common::{Env, Sink, A, B, RULE};
use gpurify_check::drc::rules::area::{
    check_cheesing, check_density, check_min_area, check_min_enclosed_area, CheesingTable,
    DensityTable, MinAreaTable, MinEnclosedAreaTable,
};
use gpurify_check::report::{LimitSense, Measurement, Outcome, Severity, SkipReason, Violation};
use gpurify_testgen::shapes::{area, hole, rect, LayoutBuilder};
use gpurify_testgen::{
    assert_clean, assert_has_violation, assert_only_violation, assert_rule_ran, dbu,
    layout_with_violation, point, Amount, ShapeKind, ViolationCase, ViolationShape,
};

/// A rectangle 100 wide whose area is exactly `measured`.
fn area_case(measured: i128, limit: i128) -> ViolationCase {
    layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::Area {
                layer: A,
                width: 100,
            },
        },
        (0, 0),
        Amount::Area(measured),
        Amount::Area(limit),
    )
}

fn min_area_table(limit: i128) -> MinAreaTable {
    let mut table = MinAreaTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.limit.push(area(limit));
    table
}

// ----------------------------------------------------------------- min_area

/// Oracle: construct-from-answer. A rectangle 100 wide and 400 tall has an area
/// of 40 000 exactly, so 40 001 is the smallest limit it fails. The measurement
/// is an area, not a length — a distinction the old tree lost by giving both the
/// same integer type.
#[test]
fn a_figure_one_square_unit_under_the_limit_is_reported_at_its_centre() {
    let case = area_case(40_000, 40_001);
    let env = Env::default();
    let mut sink = Sink::default();

    check_min_area(
        env.design(&case.store),
        &min_area_table(40_001),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_only_violation(&sink.out, &case.expected);
    let run = assert_rule_ran(&sink.runs, RULE);
    assert_eq!(
        run.examined, 1,
        "examined counts merged figures, and one rectangle is one figure"
    );
    assert_eq!(run.violations, 1);
}

#[test]
fn a_figure_exactly_at_the_area_limit_is_clean() {
    let case = area_case(40_000, 40_000);
    let env = Env::default();
    let mut sink = Sink::default();

    check_min_area(
        env.design(&case.store),
        &min_area_table(40_000),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

/// Oracle: construct-from-answer, and the property this rule exists for. Two
/// overlapping rectangles of 10 000 each share 5 000, so their union is 15 000
/// and their intersection is counted once — inclusion and exclusion, on
/// disjoint decomposed rectangles, with no correction term needed.
///
/// Against a limit of 12 001 the figure passes and each fragment alone would
/// not. A per-polygon implementation reports two violations here; `examined`
/// dropping from two polygons to one figure is the visible half of the same
/// claim.
#[test]
fn two_overlapping_fragments_are_one_figure_whose_area_is_their_union() {
    let mut layout = LayoutBuilder::new(1);
    layout.rect(A, 0, 0, 100, 100);
    layout.rect(A, 50, 0, 150, 100);
    let (store, _ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();
    check_min_area(
        env.design(&store),
        &min_area_table(12_001),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(
        assert_rule_ran(&sink.runs, RULE).examined,
        1,
        "two overlapping polygons merge into one figure before being measured"
    );
}

/// Oracle: construct-from-answer, the failing direction of the same merge. The
/// union of the two fragments is 15 000, so a limit of 15 001 fails it — once,
/// with the merged area as the measurement, not twice with 10 000 each.
#[test]
fn a_merged_figure_below_the_limit_is_reported_once_with_its_merged_area() {
    let mut layout = LayoutBuilder::new(1);
    layout.rect(A, 0, 0, 100, 100);
    layout.rect(A, 50, 0, 150, 100);
    let (store, _ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();
    check_min_area(
        env.design(&store),
        &min_area_table(15_001),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_eq!(sink.out.rule.len(), 1);
    assert_eq!(sink.out.measured[0], Measurement::Area(area(15_000)));
    assert_eq!(sink.out.limit[0], Measurement::Area(area(15_001)));
    assert_eq!(sink.out.layer[0], A);

    // The marker must land inside the figure it names, which is the one thing
    // `Violation::at` promises for an area rule. The union spans x in [0, 150]
    // and y in [0, 100], and a point outside that is pointing at nothing.
    let at = sink.out.at[0];
    assert!(
        at.x >= dbu(0) && at.x <= dbu(150) && at.y >= dbu(0) && at.y <= dbu(100),
        "the violation is marked at {at:?}, which is outside the figure it names"
    );
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

// -------------------------------------------------------- min_enclosed_area

/// Oracle: construct-from-answer. The ring's hole is 100 by 200, so its area is
/// 20 000 and a limit of 20 001 fails it by one square unit. The measurement is
/// the *hole*, not the figure: the figure is larger than the hole by the margin
/// on every side, and an implementation measuring the wrong one passes nothing
/// here.
///
/// `check_min_enclosed_area` reports at *a* vertex of the hole ring without
/// saying which, so the coordinate is asserted against the four the hole has —
/// `(±50, ±100)` — rather than against a fifth point the interface never
/// promised. Which of the four is a Definition-Phase gap, recorded in
/// `docs/NEED_TESTING.md`.
#[test]
fn a_hole_one_square_unit_under_the_limit_is_reported_at_the_hole() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::EnclosedArea {
                layer: A,
                margin: 50,
                hole_width: 100,
            },
        },
        (0, 0),
        Amount::Area(20_000),
        Amount::Area(20_001),
    );

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = MinEnclosedAreaTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.limit.push(area(20_001));

    check_min_enclosed_area(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_eq!(sink.out.rule.len(), 1, "the ring has exactly one hole");
    // The centre of the hole's bounding box, per the crate's convention. The
    // hole spans `(-50, -100) .. (50, 100)`, so that is the origin — and it is
    // inside the hole, which no vertex of the ring is.
    assert_eq!(sink.out.at[0], point(0, 0));
    let _ = assert_has_violation(&sink.out, &case.expected);

    let run = assert_rule_ran(&sink.runs, RULE);
    assert_eq!(
        run.examined, 1,
        "examined counts holes, and the ring has one"
    );
    assert_eq!(run.violations, 1);
}

#[test]
fn a_hole_exactly_at_the_enclosed_area_limit_is_clean() {
    let case = layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::EnclosedArea {
                layer: A,
                margin: 50,
                hole_width: 100,
            },
        },
        (0, 0),
        Amount::Area(20_000),
        Amount::Area(20_000),
    );

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = MinEnclosedAreaTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.limit.push(area(20_000));

    check_min_enclosed_area(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

// ----------------------------------------------------------------- cheesing

fn cheesing_table(max_unslotted: i128) -> CheesingTable {
    let mut table = CheesingTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.max_unslotted.push(area(max_unslotted));
    table
}

/// Oracle: construct-from-answer. A solid 500-by-400 plate is 200 000 square
/// units with no relief in its boundary, so 199 999 is the largest limit it
/// fails. Reported at the centre of the figure, with the figure's area as the
/// measurement.
#[test]
fn an_unslotted_plate_one_square_unit_over_the_limit_is_reported_at_its_centre() {
    let mut layout = LayoutBuilder::new(1);
    let plate = layout.rect(A, 0, 0, 500, 400);
    let (store, ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();
    check_cheesing(
        env.design(&store),
        &cheesing_table(199_999),
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
            at: point(250, 200),
            measured: Measurement::Area(area(200_000)),
            limit: Measurement::Area(area(199_999)),
            shapes: (ids.of(plate), None),
        },
    );
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

#[test]
fn a_plate_exactly_at_the_unslotted_limit_is_clean() {
    let mut layout = LayoutBuilder::new(1);
    layout.rect(A, 0, 0, 500, 400);
    let (store, _ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();
    check_cheesing(
        env.design(&store),
        &cheesing_table(200_000),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

/// Oracle: construct-from-answer, and the half of the rule that area alone
/// cannot express. The same plate with a hole cut in it is 190 000 square units
/// and is *perforated*, so it passes a limit of 100 000 that its area alone
/// fails by ninety thousand. A rule testing area without testing for relief
/// flags every legitimately slotted plate in a design.
#[test]
fn a_slotted_plate_passes_a_limit_its_area_alone_would_fail() {
    let mut layout = LayoutBuilder::new(1);
    layout.shape(A, &rect(0, 0, 500, 400));
    layout.shape(A, &hole(200, 150, 300, 250));
    let (store, _ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();
    check_cheesing(
        env.design(&store),
        &cheesing_table(100_000),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

// ------------------------------------------------------------------ density

/// The step-column layout, and the reason that column exists.
///
/// Two ten-unit anchors fix the layer's extent at `[0, 2000]` square. A
/// 500-square block sits centred on `(1000, 1000)`, straddling the boundary
/// between the two whole-window positions on both axes.
///
/// - A 1000-window at origin `(500, 500)` contains the whole block: coverage is
///   250 000 / 1 000 000 = 0.25 exactly.
/// - Every 1000-window at a multiple of 1000 contains one quarter of it:
///   62 500 / 1 000 000 = 0.0625.
///
/// So a limit of 0.2 is exceeded by the stepped sweep and by no unstepped one,
/// and both numbers are exactly representable in binary floating point, so the
/// comparison is not a tolerance question.
fn straddling_hot_spot() -> gpurify_geom::GeometryStore {
    let mut layout = LayoutBuilder::new(1);
    layout.rect(A, 0, 0, 10, 10);
    layout.rect(A, 1_990, 1_990, 2_000, 2_000);
    layout.rect(A, 750, 750, 1_250, 1_250);
    let (store, _ids) = layout.finish();
    store
}

fn density_table(window: i64, step: i64, limit: f64, sense: LimitSense) -> DensityTable {
    let mut table = DensityTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.window.push(dbu(window));
    table.step.push(dbu(step));
    table.limit.push(limit);
    table.sense.push(sense);
    table
}

/// Oracle: construct-from-answer. The one window whose coverage exceeds 0.2 is
/// the one spanning `[500, 1500]` on both axes, and `check_density` reports at
/// the window's *centre*, so the coordinate is `(1000, 1000)`. Nine windows
/// are evaluated — three step positions per axis over a 2000-unit extent — which
/// is what `examined` must report.
#[test]
fn a_hot_spot_straddling_two_windows_is_caught_by_the_stepped_sweep() {
    let store = straddling_hot_spot();
    let env = Env::default();
    let mut sink = Sink::default();

    check_density(
        env.design(&store),
        &density_table(1_000, 500, 0.2, LimitSense::Maximum),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_eq!(
        sink.out.rule.len(),
        1,
        "only the half-step window covers the whole block"
    );
    assert_eq!(sink.out.at[0], point(1_000, 1_000));
    assert_eq!(sink.out.measured[0], Measurement::Ratio(0.25));
    assert_eq!(sink.out.limit[0], Measurement::Ratio(0.2));
    assert_eq!(sink.out.layer[0], A);

    let run = assert_rule_ran(&sink.runs, RULE);
    assert_eq!(
        run.examined, 9,
        "a 2000-unit extent swept by a 1000 window in 500 steps is three \
         positions per axis"
    );
    assert_eq!(run.violations, 1);
}

/// Oracle: construct-from-answer, the same layout with the step the deck should
/// not have written. Whole-window steps see four windows, each holding a
/// quarter of the block at 0.0625, and the rule reports clean — which is the
/// exact miss the step column exists to prevent. The `RuleRun` is what makes
/// this test say something: the rule ran and examined four windows, so its
/// silence is a measurement rather than an absence.
#[test]
fn the_same_hot_spot_is_missed_when_the_window_advances_a_whole_window() {
    let store = straddling_hot_spot();
    let env = Env::default();
    let mut sink = Sink::default();

    check_density(
        env.design(&store),
        &density_table(1_000, 1_000, 0.2, LimitSense::Maximum),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(
        assert_rule_ran(&sink.runs, RULE).examined,
        4,
        "a whole-window step over a 2000-unit extent is two positions per axis"
    );
}

/// Oracle: construct-from-answer. The densest window covers a quarter of
/// itself, so a maximum of 0.25 is met exactly and is not exceeded. One unit of
/// coverage the other way — a limit of 0.2499 — and it is.
#[test]
fn a_window_exactly_at_the_density_limit_is_clean_and_just_over_it_is_not() {
    let store = straddling_hot_spot();
    let env = Env::default();

    let mut clean = Sink::default();
    check_density(
        env.design(&store),
        &density_table(1_000, 500, 0.25, LimitSense::Maximum),
        &mut clean.scratch,
        &mut clean.out,
        &mut clean.runs,
    );
    assert_clean(&clean.runs, &clean.out, RULE);
    assert_eq!(assert_rule_ran(&clean.runs, RULE).examined, 9);

    let mut over = Sink::default();
    check_density(
        env.design(&store),
        &density_table(1_000, 500, 0.2499, LimitSense::Maximum),
        &mut over.scratch,
        &mut over.out,
        &mut over.runs,
    );
    assert_eq!(over.out.rule.len(), 1);
    assert_eq!(over.out.at[0], point(1_000, 1_000));
    assert_eq!(over.out.measured[0], Measurement::Ratio(0.25));
}

/// Oracle: construct-from-answer. A minimum-density rule wants *enough* metal,
/// so the sparse corners of the same layout fail it while the hot spot does
/// not. Both senses over one geometry is what makes the `sense` column a
/// uniform rather than a branch in the sweep.
#[test]
fn the_minimum_sense_flags_the_sparse_windows_the_maximum_sense_ignores() {
    let store = straddling_hot_spot();
    let env = Env::default();
    let mut sink = Sink::default();

    check_density(
        env.design(&store),
        &density_table(1_000, 500, 0.2, LimitSense::Minimum),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    let run = assert_rule_ran(&sink.runs, RULE);
    assert_eq!(run.examined, 9);
    assert_eq!(
        sink.out.rule.len(),
        8,
        "eight of the nine windows fall below 0.2; only the centred one reaches \
         0.25"
    );
    assert!(
        sink.out.at.iter().all(|&at| at != point(1_000, 1_000)),
        "the densest window is the one window a minimum-density rule must not \
         flag; its centre is (1000, 1000), the centre of the span [500, 1500]"
    );
}

/// Oracle: construct-from-answer, fail closed. A density fraction over an empty
/// extent has no denominator, so the rule refuses to answer rather than
/// answering zero — and `Skipped` is a different claim from `Ran` with nothing
/// found, which is the whole reason `Outcome` is not a boolean.
#[test]
fn density_over_a_layer_with_no_geometry_is_skipped_not_clean() {
    let mut layout = LayoutBuilder::new(2);
    layout.rect(A, 0, 0, 100, 100);
    let (store, _ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = density_table(1_000, 500, 0.2, LimitSense::Maximum);
    table.layer[0] = B;

    check_density(
        env.design(&store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_eq!(sink.runs.len(), 1);
    assert_eq!(
        sink.runs[0].outcome,
        Outcome::Skipped(SkipReason::EmptyLayer)
    );
    assert!(sink.out.rule.is_empty());
}
