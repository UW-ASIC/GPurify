//! Overlay family: `min_enclosure`, `asymmetric_enclosure`, `min_extension`,
//! `overlap`, `max_distance_to_tap`, and the `Margins` reductions underneath the
//! first two.
//!
//! One layout carries both enclosure rules: an inner square clearing its host by
//! 40 on the left, 60 on the right and 100 top and bottom. The symmetric rule
//! reduces that to its worst side, 40; the relaxed rule reduces it to the better
//! side of the worse axis, 60. Two different numbers off one geometry is what
//! stops the two rules being written as one with a flag, and it is why the two
//! tables use different names for their limit.

mod common;

use common::{Env, Sink, A, B, RULE};
use gpurify_core::{Bbox, PolyId};
use gpurify_drc::rules::overlay::{
    check_asymmetric_enclosure, check_max_distance_to_tap, check_min_enclosure,
    check_min_extension, check_overlap, margins, AsymmetricEnclosureTable, Margins,
    MaxDistanceToTapTable, MinEnclosureTable, MinExtensionTable, OverlapTable,
};
use gpurify_report::{Measurement, Outcome, Severity, SkipReason, Violation};
use gpurify_testgen::shapes::{l_shape, LayoutBuilder};
use gpurify_testgen::{
    assert_clean, assert_only_violation, assert_rule_ran, dbu, layout_with_violation, point,
    Amount, ShapeKind, ViolationCase, ViolationShape,
};

/// An inner square clearing its host by exactly `enclosure` on the left and
/// generously on every other side.
fn enclosure_case(enclosure: i64, limit: i64) -> ViolationCase {
    layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::Enclosure {
                outer: B,
                inner: A,
                inner_size: 100,
            },
        },
        (0, 0),
        Amount::Length(enclosure),
        Amount::Length(limit),
    )
}

fn min_enclosure_table(limit: i64) -> MinEnclosureTable {
    let mut table = MinEnclosureTable::default();
    table.rule.push(RULE);
    table.outer.push(B);
    table.inner.push(A);
    table.limit.push(dbu(limit));
    table
}

// ------------------------------------------------------------ min_enclosure

/// Oracle: construct-from-answer. The host clears the inner shape by 40 on its
/// left and by a full inner width elsewhere, so the worst side is 40 and a limit
/// of 41 fails it by one. The violation is attributed to the *inner* layer,
/// which is the shape a designer has to move.
///
/// `check_min_enclosure` reports at the *midpoint of the deficient margin* —
/// the side `Margins::worst` named — which is the crate-wide convention and
/// what `testgen::violation` already computes. The generator centres that
/// margin on the origin, so the expected point comes straight from
/// `case.expected` with no override.
#[test]
fn an_enclosure_one_unit_under_the_limit_is_reported_on_the_deficient_margin() {
    let case = enclosure_case(40, 41);
    let env = Env::default();
    let mut sink = Sink::default();

    check_min_enclosure(
        env.design(&case.store),
        &min_enclosure_table(41),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_only_violation(&sink.out, &case.expected);
    let run = assert_rule_ran(&sink.runs, RULE);
    assert_eq!(run.examined, 1, "examined counts inner shapes");
    assert_eq!(run.violations, 1);
}

/// Oracle: construct-from-answer, and the `bbox_only_enclosure` defect.
///
/// The host is an L on layer B — arms along `x` and along `y`, notch in the
/// upper right. The inner square on layer A sits *in the notch*: entirely inside
/// the L's bounding box and entirely outside the L. Its enclosure is zero, which
/// is what a shape sitting on bare substrate has.
///
/// `Bbox::contains` decided hosting and `margins` measured boxes, so the L's box
/// contained the square, the square was declared hosted, and the margins came
/// back generous. A shape with no host material anywhere near it reported a
/// comfortable pass — fail-open, on the rule that says a via must be covered by
/// metal.
///
/// Reported at the inner shape's own centre, which is the unhosted convention
/// `an_inner_shape_with_no_host_has_an_enclosure_of_zero_not_no_enclosure`
/// already pins.
#[test]
fn an_inner_shape_in_a_concave_hosts_notch_is_not_enclosed_by_it() {
    let mut layout = LayoutBuilder::new(2);
    // 400 arms, 200 thick, so the notch is the square (200, 200) .. (400, 400).
    layout.shape(B, &l_shape(0, 0, 400, 200));
    let stranded = layout.rect(A, 250, 250, 330, 330);
    let (store, ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();

    check_min_enclosure(
        env.design(&store),
        &min_enclosure_table(10),
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
            at: point(290, 290),
            measured: Measurement::Length(dbu(0)),
            limit: Measurement::Length(dbu(10)),
            shapes: (ids.of(stranded), None),
        },
    );
}

/// The other side of the same boundary, so the test above is not satisfied by a
/// rule that calls every concave host a miss. Same L, an inner square well
/// inside the horizontal arm: 50 clear below, 50 above in a 200-thick arm, and
/// further than that from either end.
#[test]
fn an_inner_shape_inside_a_concave_hosts_arm_is_enclosed_by_it() {
    let mut layout = LayoutBuilder::new(2);
    layout.shape(B, &l_shape(0, 0, 400, 200));
    layout.rect(A, 250, 50, 330, 150);
    let (store, _ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();

    check_min_enclosure(
        env.design(&store),
        &min_enclosure_table(50),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
}

/// The generalisation, and the case a *vertex-only* containment test passes
/// wrongly: a bar whose two ends are both inside the host and whose middle spans
/// the host's opening. Every vertex of the inner shape is inside the host, and
/// the inner shape is still not enclosed by it, because its middle sits over
/// nothing.
///
/// Containment therefore has to be an edge-crossing test rather than a vertex
/// test, which is the whole reason this case is written down.
#[test]
fn a_bar_bridging_a_hosts_opening_is_not_enclosed_though_its_corners_are() {
    let mut layout = LayoutBuilder::new(2);
    // A U opening upward: base (0,0)-(400,100), arms at x 0..100 and 300..400
    // rising to y 500. One polygon, wound counter-clockwise.
    layout.push(
        B,
        &[0, 400, 400, 300, 300, 100, 100, 0],
        &[0, 0, 500, 500, 100, 100, 500, 500],
    );
    // Spans the opening at y 200..300; both ends sit inside the arms.
    layout.rect(A, 50, 200, 350, 300);
    let (store, _ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();

    check_min_enclosure(
        env.design(&store),
        &min_enclosure_table(10),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_eq!(
        sink.out.len(),
        1,
        "a bar spanning the host's opening is not enclosed by it"
    );
    assert_eq!(sink.out.measured[0], Measurement::Length(dbu(0)));
}

#[test]
fn an_enclosure_exactly_at_the_limit_is_clean() {
    let case = enclosure_case(40, 40);
    let env = Env::default();
    let mut sink = Sink::default();

    check_min_enclosure(
        env.design(&case.store),
        &min_enclosure_table(40),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

/// Oracle: construct-from-answer, and the case that matters most. A via with no
/// metal under it at all has an enclosure of zero and fails every enclosure
/// rule. Skipping it because no host was found is fail-open, and it is exactly
/// the layout a broken pairing step produces no output for.
#[test]
fn an_inner_shape_with_no_host_has_an_enclosure_of_zero_not_no_enclosure() {
    let mut layout = LayoutBuilder::new(2);
    let orphan = layout.rect(A, 0, 0, 100, 100);
    layout.rect(B, 5_000, 5_000, 6_000, 6_000);
    let (store, ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();
    check_min_enclosure(
        env.design(&store),
        &min_enclosure_table(40),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_eq!(sink.out.rule.len(), 1, "an unhosted inner shape violates");
    assert_eq!(sink.out.measured[0], Measurement::Length(dbu(0)));
    assert_eq!(sink.out.layer[0], A);
    assert_eq!(sink.out.shape_a[0], ids.of(orphan));
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

/// Oracle: construct-from-answer. The inner square sits inside two hosts at
/// once — a generous one that encloses it by 100 on every side and a narrow one
/// that clips it. The rule is satisfied by the best host, because after the
/// outer layer is merged there is only one host and it is the union. Taking the
/// first or the worst host fails a via whose pad encloses it perfectly, and
/// "first" depends on polygon order, so that variant is nondeterministic too.
#[test]
fn an_inner_shape_inside_two_hosts_is_judged_by_the_better_of_them() {
    let mut layout = LayoutBuilder::new(2);
    layout.rect(A, 1_000, 1_000, 1_100, 1_100);
    // The clipping host, pushed first so a first-host implementation picks it.
    layout.rect(B, 1_010, 1_010, 1_090, 1_090);
    layout.rect(B, 900, 900, 1_200, 1_200);
    let (store, _ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();
    check_min_enclosure(
        env.design(&store),
        &min_enclosure_table(100),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

// ------------------------------------------------------ asymmetric_enclosure

/// The two-sided layout: margins of 40 left, 60 right, 100 bottom, 100 top.
///
/// Returns the store and the two polygon ids, inner first.
fn two_sided_enclosure() -> (gpurify_core::GeometryStore, PolyId, PolyId) {
    let mut layout = LayoutBuilder::new(2);
    let inner = layout.rect(A, 100, 100, 200, 200);
    let outer = layout.rect(B, 60, 0, 260, 300);
    let (store, ids) = layout.finish();
    (store, ids.of(inner), ids.of(outer))
}

/// Oracle: construct-from-answer. `min(max(40, 60), max(100, 100))` is 60, so
/// the shape has 60 on the better side of its worse axis and a requirement of
/// 61 fails it by one.
///
/// The coordinate is the midpoint of the margin `Margins::worst_axis_best_side`
/// named — the better side of the worse axis, which the rule now restates for
/// itself. Here that is the right-hand strip, `x` from 200 to 260 and `y` from
/// 100 to 200, so the point is `(230, 150)`. It is not a corner of either
/// shape: the whole claim is that this one side is the one to widen.
#[test]
fn an_asymmetric_enclosure_one_unit_under_the_requirement_is_reported_on_the_better_side() {
    let (store, inner, outer) = two_sided_enclosure();
    let env = Env::default();
    let mut sink = Sink::default();

    let mut table = AsymmetricEnclosureTable::default();
    table.rule.push(RULE);
    table.outer.push(B);
    table.inner.push(A);
    table.min_one_side.push(dbu(61));

    check_asymmetric_enclosure(
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
            at: point(230, 150),
            measured: Measurement::Length(dbu(60)),
            limit: Measurement::Length(dbu(61)),
            shapes: (inner, Some(outer)),
        },
    );
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

/// Oracle: construct-from-answer, and the whole point of the relaxed form. The
/// same geometry the symmetric rule fails at 41 passes the asymmetric rule at
/// 60, because a landing pad on one side of each axis is what an overlay-error
/// budget actually needs. A rule sharing a comparison with `min_enclosure`
/// cannot produce both answers.
#[test]
fn the_relaxed_rule_passes_a_shape_the_symmetric_rule_fails() {
    let (store, _inner, _outer) = two_sided_enclosure();
    let env = Env::default();

    let mut symmetric = Sink::default();
    check_min_enclosure(
        env.design(&store),
        &min_enclosure_table(41),
        &mut symmetric.scratch,
        &mut symmetric.out,
        &mut symmetric.runs,
    );
    assert_eq!(symmetric.out.rule.len(), 1);
    assert_eq!(symmetric.out.measured[0], Measurement::Length(dbu(40)));

    let mut relaxed = Sink::default();
    let mut table = AsymmetricEnclosureTable::default();
    table.rule.push(RULE);
    table.outer.push(B);
    table.inner.push(A);
    table.min_one_side.push(dbu(60));
    check_asymmetric_enclosure(
        env.design(&store),
        &table,
        &mut relaxed.scratch,
        &mut relaxed.out,
        &mut relaxed.runs,
    );
    assert_clean(&relaxed.runs, &relaxed.out, RULE);
    assert_eq!(assert_rule_ran(&relaxed.runs, RULE).examined, 1);
}

// ------------------------------------------------------------ min_extension

fn extension_case(extension: i64, limit: i64) -> ViolationCase {
    layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::Extension {
                line: A,
                crossed: B,
                width: 100,
            },
        },
        (0, 0),
        Amount::Length(extension),
        Amount::Length(limit),
    )
}

/// Oracle: construct-from-answer. The stripe crosses the bar and runs 60 units
/// past it on the right, which is the smallest protrusion on any side where it
/// protrudes at all, so a limit of 61 fails by one. Reported at the midpoint of
/// the overhanging stub.
#[test]
fn an_extension_one_unit_under_the_limit_is_reported_at_the_overhang() {
    let case = extension_case(60, 61);
    let env = Env::default();
    let mut sink = Sink::default();

    let mut table = MinExtensionTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.reference.push(B);
    table.limit.push(dbu(61));

    check_min_extension(
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
        "examined counts overlapping shape pairs"
    );
}

#[test]
fn an_extension_exactly_at_the_limit_is_clean() {
    let case = extension_case(60, 60);
    let env = Env::default();
    let mut sink = Sink::default();

    let mut table = MinExtensionTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.reference.push(B);
    table.limit.push(dbu(60));

    check_min_extension(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
}

/// Oracle: construct-from-answer. A layer that never meets the reference is not
/// failing to extend past it, it is somewhere else entirely — so no pair is
/// judged and `examined` says so. Reporting here would flag every unrelated
/// shape on the layer.
#[test]
fn a_shape_that_does_not_meet_the_reference_is_not_failing_to_extend_past_it() {
    let mut layout = LayoutBuilder::new(2);
    layout.rect(A, 0, 0, 100, 100);
    layout.rect(B, 5_000, 5_000, 6_000, 6_000);
    let (store, _ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();
    let mut table = MinExtensionTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.reference.push(B);
    table.limit.push(dbu(1_000));

    check_min_extension(
        env.design(&store),
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

// ------------------------------------------------------------------ overlap

fn overlap_case(overlap: i64, limit: i64) -> ViolationCase {
    layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::Overlap {
                a: A,
                b: B,
                extent: 400,
            },
        },
        (0, 0),
        Amount::Length(overlap),
        Amount::Length(limit),
    )
}

/// Oracle: construct-from-answer. The intersection of the two rectangles is 80
/// by 400, so its smaller dimension is 80 and a limit of 81 fails it by one.
/// The limit is on the smaller *dimension* rather than on area precisely so a
/// long thin sliver — which does not conduct — cannot pass.
#[test]
fn an_overlap_one_unit_under_the_limit_is_reported_inside_the_intersection() {
    let case = overlap_case(80, 81);
    let env = Env::default();
    let mut sink = Sink::default();

    let mut table = OverlapTable::default();
    table.rule.push(RULE);
    table.a.push(A);
    table.b.push(B);
    table.limit.push(dbu(81));

    check_overlap(
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
        "examined counts intersection figures"
    );
}

#[test]
fn an_overlap_exactly_at_the_limit_is_clean() {
    let case = overlap_case(80, 80);
    let env = Env::default();
    let mut sink = Sink::default();

    let mut table = OverlapTable::default();
    table.rule.push(RULE);
    table.a.push(A);
    table.b.push(B);
    table.limit.push(dbu(80));

    check_overlap(
        env.design(&case.store),
        &table,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

// ------------------------------------------------------- max_distance_to_tap

/// A well whose farthest corner is exactly 500 from the nearest tap.
///
/// The 3-4-5 triangle is what makes that number exact: the corner at the origin
/// is 400 across and 300 up from the tap's nearest point, and every other corner
/// of the well is strictly closer. So the answer is one number and it belongs to
/// one corner, which is what a test needs in order to assert a coordinate.
fn untied_well() -> (gpurify_core::GeometryStore, PolyId) {
    let mut layout = LayoutBuilder::new(2);
    let well = layout.rect(A, 0, 0, 100, 100);
    layout.rect(B, 400, 300, 500, 400);
    let (store, ids) = layout.finish();
    (store, ids.of(well))
}

fn tap_table(limit: i64) -> MaxDistanceToTapTable {
    let mut table = MaxDistanceToTapTable::default();
    table.rule.push(RULE);
    table.well.push(A);
    table.tap.push(B);
    table.limit.push(dbu(limit));
    table
}

/// Oracle: construct-from-answer. The farthest corner of the well is 500 from
/// the nearest point of the tap, so a limit of 499 is exceeded by one. The
/// report points at that corner: it is the place a designer adds a tie, and it
/// is on the well geometry, which is what `Violation::at` promises and which the
/// midpoint of a well-to-tap segment would not be.
///
/// Distance is to the tap's nearest point, not its centre. A centre-based
/// measurement here would read 550 and over-report.
#[test]
fn a_well_corner_one_unit_beyond_reach_of_a_tap_is_reported_at_that_corner() {
    let (store, well) = untied_well();
    let env = Env::default();
    let mut sink = Sink::default();

    check_max_distance_to_tap(
        env.design(&store),
        &tap_table(499),
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
            at: point(0, 0),
            measured: Measurement::Length(dbu(500)),
            limit: Measurement::Length(dbu(499)),
            shapes: (well, None),
        },
    );
    assert_eq!(
        assert_rule_ran(&sink.runs, RULE).examined,
        1,
        "examined counts well shapes"
    );
}

#[test]
fn a_well_corner_exactly_at_the_reach_limit_is_clean() {
    let (store, _well) = untied_well();
    let env = Env::default();
    let mut sink = Sink::default();

    check_max_distance_to_tap(
        env.design(&store),
        &tap_table(500),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

/// Oracle: construct-from-answer, fail closed. A well layer with no taps
/// anywhere is not a layer the rule cannot judge — it is a layer where every
/// well is untied, which is the latch-up condition the rule exists for. Skipping
/// it would pass the worst possible layout.
#[test]
fn a_well_layer_with_no_taps_at_all_violates_on_every_well_shape() {
    let mut layout = LayoutBuilder::new(2);
    let near = layout.rect(A, 0, 0, 100, 100);
    let far = layout.rect(A, 900, 900, 1_000, 1_000);
    let (store, ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();
    check_max_distance_to_tap(
        env.design(&store),
        &tap_table(500),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    let run = assert_rule_ran(&sink.runs, RULE);
    assert_eq!(run.examined, 2, "two well shapes were examined");
    assert_eq!(
        run.violations, 2,
        "with no tap on the design, every well shape is out of reach"
    );

    // Each well is named once and marked at one of its own corners. The
    // *measurement* is deliberately not asserted: with no tap in the design
    // there is no distance to report, and inventing one here would be the test
    // choosing a convention the interface does not state.
    let mut named = vec![sink.out.shape_a[0], sink.out.shape_a[1]];
    named.sort_unstable();
    assert_eq!(named, ids.sorted(&[near, far]));
    for row in 0..2 {
        let corners = if sink.out.shape_a[row] == ids.of(near) {
            [point(0, 0), point(100, 0), point(100, 100), point(0, 100)]
        } else {
            [
                point(900, 900),
                point(1_000, 900),
                point(1_000, 1_000),
                point(900, 1_000),
            ]
        };
        assert!(
            corners.contains(&sink.out.at[row]),
            "row {row} is marked at {:?}, which is not a corner of the well it names",
            sink.out.at[row]
        );
    }
}

/// Oracle: construct-from-answer, fail closed the other way. An *empty* well
/// layer has nothing to judge, and that is `Skipped`, not clean — a different
/// claim from "checked and found nothing", and the only one the violation table
/// cannot distinguish on its own.
#[test]
fn an_empty_well_layer_is_skipped_rather_than_reported_clean() {
    let mut layout = LayoutBuilder::new(2);
    layout.rect(B, 0, 0, 100, 100);
    let (store, _ids) = layout.finish();

    let env = Env::default();
    let mut sink = Sink::default();
    check_max_distance_to_tap(
        env.design(&store),
        &tap_table(500),
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

// ----------------------------------------------------------------- margins

fn bbox(xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> Bbox {
    Bbox {
        xlo: dbu(xlo),
        ylo: dbu(ylo),
        xhi: dbu(xhi),
        yhi: dbu(yhi),
    }
}

/// Oracle: closed form. Each margin is one subtraction, written out here so the
/// sign convention is checked rather than assumed: positive where the outer
/// shape extends past the inner, negative where the inner sticks out.
#[test]
fn margins_are_the_four_signed_differences_between_the_two_boxes() {
    assert_eq!(
        margins(bbox(10, 20, 30, 40), bbox(0, 0, 100, 100)),
        Margins {
            left: dbu(10),
            right: dbu(70),
            bottom: dbu(20),
            top: dbu(60),
        }
    );
}

/// Oracle: closed form. An inner shape hanging over its host's left edge by 5
/// has a margin of minus five there. Clamping that to zero would hide how badly
/// the rule failed, and would make an overhanging via indistinguishable from one
/// that merely touches the edge.
#[test]
fn a_margin_is_negative_where_the_inner_shape_sticks_out() {
    let overhanging = margins(bbox(-5, 20, 30, 40), bbox(0, 0, 100, 100));
    assert_eq!(overhanging.left, dbu(-5));
    assert_eq!(overhanging.worst(), dbu(-5));
}

/// Oracle: closed form. `worst` is the minimum of the four; the relaxed
/// reduction is `min(max(left, right), max(bottom, top))`. Both are written out
/// on a case where every one of the four sides differs, so a reduction that
/// picked the wrong pair cannot agree by accident.
#[test]
fn the_two_reductions_differ_on_a_shape_deficient_on_one_side_of_one_axis() {
    let asymmetric = Margins {
        left: dbu(40),
        right: dbu(60),
        bottom: dbu(100),
        top: dbu(120),
    };
    assert_eq!(asymmetric.worst(), dbu(40));
    assert_eq!(asymmetric.worst_axis_best_side(), dbu(60));
}

/// Oracle: law. Where every side is equal the two reductions cannot disagree —
/// `min` of four equals and `min(max, max)` of the same four are both that
/// value. An implementation that transposed an axis passes the case above and
/// fails nothing here, so this is the pair of tests, not either one alone.
#[test]
fn the_two_reductions_agree_on_a_symmetric_enclosure() {
    for side in [0, 1, 250, -3] {
        let even = Margins {
            left: dbu(side),
            right: dbu(side),
            bottom: dbu(side),
            top: dbu(side),
        };
        assert_eq!(even.worst(), dbu(side));
        assert_eq!(even.worst_axis_best_side(), dbu(side));
    }
}
