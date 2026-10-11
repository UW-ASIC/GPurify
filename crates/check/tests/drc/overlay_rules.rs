//! Overlay family: `min_enclosure`, `asymmetric_enclosure`, `min_extension`,
//! `overlap`, `max_distance_to_tap`. One enclosure layout (40 left, 60 right, 100
//! top/bottom) gives 40 under the symmetric rule and 60 under the asymmetric one.

use crate::common;

use common::{Sink, A, B, RULE};
use gpurify_check::drc::{Rule, WireBand};
use gpurify_check::report::{Measurement, Outcome, Severity, SkipReason, Violation};
use gpurify_geom::PolyId;
use gpurify_ingest::StrId;
use gpurify_testgen::shapes::{hole, l_shape, LayoutBuilder};
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

fn min_enclosure_table(limit: i64) -> Vec<(StrId, Rule)> {
    vec![(
        RULE,
        Rule::MinEnclosure {
            outer: B,
            inner: A,
            limit: dbu(limit),
            wire: WireBand::ANY,
        },
    )]
}

// ------------------------------------------------------------ min_enclosure

/// Oracle: construct-from-answer. The host clears the inner shape by 40 on its
/// left and by a full inner width elsewhere, so the worst side is 40 and a limit
/// of 41 fails it by one. The violation is attributed to the *inner* layer,
/// which is the shape a designer has to move.
///
/// `min_enclosure` reports at the *midpoint of the deficient margin* —
/// the worst side — which is the crate-wide convention and
/// what `testgen::violation` already computes. The generator centres that
/// margin on the origin, so the expected point comes straight from
/// `case.expected` with no override.
#[test]
fn an_enclosure_one_unit_under_the_limit_is_reported_on_the_deficient_margin() {
    let case = enclosure_case(40, 41);
    let mut sink = Sink::default();

    sink.run(&case.store, &min_enclosure_table(41));

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

    let mut sink = Sink::default();

    sink.run(&store, &min_enclosure_table(10));

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
///
/// Oracle: construct-from-answer. The inner square clears the arm by 50 above
/// and below and more from either end, so a 50 enclosure is met.
#[test]
fn an_inner_shape_inside_a_concave_hosts_arm_is_enclosed_by_it() {
    let mut layout = LayoutBuilder::new(2);
    layout.shape(B, &l_shape(0, 0, 400, 200));
    layout.rect(A, 250, 50, 330, 150);
    let (store, _ids) = layout.finish();

    let mut sink = Sink::default();

    sink.run(&store, &min_enclosure_table(50));

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
///
/// Oracle: construct-from-answer. The bar's middle lies over the U's opening,
/// outside the host, so it is not enclosed: one violation, measuring 0.
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

    let mut sink = Sink::default();

    sink.run(&store, &min_enclosure_table(10));

    assert_eq!(
        sink.out.len(),
        1,
        "a bar spanning the host's opening is not enclosed by it"
    );
    assert_eq!(sink.out.measured[0], Measurement::Length(dbu(0)));
}

/// Oracle: construct-from-answer. The enclosure is drawn at exactly the
/// 40 limit, and a minimum is violated only below it, so one inner shape is
/// examined and none reported.
#[test]
fn an_enclosure_exactly_at_the_limit_is_clean() {
    let case = enclosure_case(40, 40);
    let mut sink = Sink::default();

    sink.run(&case.store, &min_enclosure_table(40));

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

    let mut sink = Sink::default();
    sink.run(&store, &min_enclosure_table(40));

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

    let mut sink = Sink::default();
    sink.run(&store, &min_enclosure_table(100));

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

// ------------------------------------------------------ asymmetric_enclosure

/// The two-sided layout: margins of 40 left, 60 right, 100 bottom, 100 top.
///
/// Returns the store and the two polygon ids, inner first.
fn two_sided_enclosure() -> (gpurify_geom::GeometryStore, PolyId, PolyId) {
    let mut layout = LayoutBuilder::new(2);
    let inner = layout.rect(A, 100, 100, 200, 200);
    let outer = layout.rect(B, 60, 0, 260, 300);
    let (store, ids) = layout.finish();
    (store, ids.of(inner), ids.of(outer))
}

/// Oracle: construct-from-answer. `max(min(40, 60), min(100, 100))` is 100:
/// the vertical axis has 100 on both sides, so a requirement of 101 fails by
/// one. Reported on the worse side of that better axis, the bottom strip
/// `x` 100..200, `y` 0..100, at `(150, 50)`.
#[test]
fn an_asymmetric_enclosure_one_unit_under_the_requirement_is_reported_on_the_better_axis() {
    let (store, inner, outer) = two_sided_enclosure();
    let mut sink = Sink::default();

    sink.run(&store, &asymmetric_table(101));

    assert_only_violation(
        &sink.out,
        &Violation {
            rule: RULE,
            layer: A,
            severity: Severity::Error,
            at: point(150, 50),
            measured: Measurement::Length(dbu(100)),
            limit: Measurement::Length(dbu(101)),
            shapes: (inner, Some(outer)),
        },
    );
    assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
}

fn asymmetric_table(limit: i64) -> Vec<(StrId, Rule)> {
    vec![(
        RULE,
        Rule::AsymmetricEnclosure {
            outer: B,
            inner: A,
            min_one_side: dbu(limit),
            wire: WireBand::ANY,
        },
    )]
}

/// sky130 m1.5: "Mcon must be enclosed by Met1 on two opposite sides by
/// 0.060 um". A 170 nm mcon pushed into a corner of its pad, 85 nm clear on
/// the left and bottom and 55 nm on the right and top, has no axis with 60 on
/// both sides, so it fails. The old `min(max(L, R), max(B, T))` read 85 and
/// passed it.
///
/// Oracle: foundry example, sky130 m1.5 ("enclosed by Met1 on two opposite
/// sides by 0.060 um"), by hand: 85 and 55 on each axis, so neither axis has
/// 60 on both sides; the worse side of the first axis, 55, at (282, 170).
#[test]
fn sky130_m1_5_an_mcon_pushed_into_a_pad_corner_fails_two_opposite_sides() {
    let mut layout = LayoutBuilder::new(2);
    let mcon = layout.rect(A, 85, 85, 255, 255);
    let met1 = layout.rect(B, 0, 0, 310, 310);
    let (store, ids) = layout.finish();

    let mut sink = Sink::default();
    sink.run(&store, &asymmetric_table(60));

    assert_only_violation(
        &sink.out,
        &Violation {
            rule: RULE,
            layer: A,
            severity: Severity::Error,
            // The worse (right) side of the first best axis, x 255..310.
            at: point(282, 170),
            measured: Measurement::Length(dbu(55)),
            limit: Measurement::Length(dbu(60)),
            shapes: (ids.of(mcon), Some(ids.of(met1))),
        },
    );
}

/// sky130 m1.4 + m1.5 at their minimum: 60 on the left and right, 30 on the
/// bottom and top. One axis has 60 on both sides, so m1.5 is met.
///
/// Oracle: foundry example, sky130 m1.4 and m1.5 at their minimums: 60 on the
/// left and right, so one axis meets m1.5 whatever the other two are.
#[test]
fn sky130_m1_5_sixty_on_two_opposite_sides_passes_with_thirty_on_the_others() {
    let mut layout = LayoutBuilder::new(2);
    layout.rect(A, 60, 30, 230, 200);
    layout.rect(B, 0, 0, 290, 230);
    let (store, _ids) = layout.finish();

    let mut sink = Sink::default();
    sink.run(&store, &asymmetric_table(60));

    assert_clean(&sink.runs, &sink.out, RULE);
}

/// The L via of the shapes below: lower arm `[0, 200] x [0, 100]`, upper arm
/// `[0, 100] x [100, 200]`.
fn l_via(layout: &mut LayoutBuilder) -> gpurify_testgen::shapes::Handle {
    layout.push(A, &[0, 200, 200, 100, 100, 0], &[0, 0, 100, 100, 200, 200])
}

/// Oracle: construct-from-answer (DRC-041). An L via 100 clear of its host
/// left and right of every vertical edge, and flush with it above and below,
/// has the limit on both sides along x, so it passes. Held to every side, as
/// a non-rectangle once was, it read 0.
#[test]
fn an_l_shaped_inner_with_the_limit_along_one_axis_passes() {
    let mut layout = LayoutBuilder::new(2);
    l_via(&mut layout);
    layout.rect(B, -100, 0, 300, 200);
    let (store, _ids) = layout.finish();

    let mut sink = Sink::default();
    sink.run(&store, &asymmetric_table(100));

    assert_clean(&sink.runs, &sink.out, RULE);
}

/// Oracle: construct-from-answer (DRC-041). The host clears the L via by 100
/// all round but for a notch from its top over `x` 150..250 down to `y` 199.
/// The via's concave top edge (`y` 100, `x` 100..200) reads 99 up to the
/// notch and its upper arm's right edge (`x` 100) 50, so `x` measures 50 and
/// `y` 99: 99 under a requirement of 100, reported in the strip above the
/// concave edge, at `(150, 149)`. A bounding-box reading sees 100 on every
/// side and passes it.
#[test]
fn an_l_shaped_inner_is_measured_edge_by_edge_on_its_better_axis() {
    let mut layout = LayoutBuilder::new(2);
    let via = l_via(&mut layout);
    let host = layout.push(
        B,
        &[-100, 300, 300, 250, 250, 150, 150, -100],
        &[-100, -100, 300, 300, 199, 199, 300, 300],
    );
    let (store, ids) = layout.finish();

    let mut sink = Sink::default();
    sink.run(&store, &asymmetric_table(100));

    assert_only_violation(
        &sink.out,
        &Violation {
            rule: RULE,
            layer: A,
            severity: Severity::Error,
            at: point(150, 149),
            measured: Measurement::Length(dbu(99)),
            limit: Measurement::Length(dbu(100)),
            shapes: (ids.of(via), Some(ids.of(host))),
        },
    );
}

/// Oracle: construct-from-answer (DRC-043, LEF `ENCLOSURE ... WIDTH`). A
/// 3000 plate with a 500 tab off its right side; one via 40 into the plate's
/// corner, one 10 from the tab's top edge. A 2000 square fits around the
/// first and no 1000 square around the second, so a rule from 2000 holds only
/// the first (40 under 50) and one below 1000 only the second (10 under 50).
/// Without a band both are held.
#[test]
fn a_wire_band_holds_only_the_inner_shapes_on_wires_of_its_widths() {
    let mut layout = LayoutBuilder::new(2);
    let corner = layout.rect(A, 40, 40, 240, 240);
    let tab_via = layout.rect(A, 3_400, 1_150, 3_600, 1_490);
    layout.rect(B, 0, 0, 3_000, 3_000);
    layout.rect(B, 3_000, 1_000, 3_800, 1_500);
    let (store, ids) = layout.finish();
    let banded = |from: i64, below: Option<i64>| {
        vec![(
            RULE,
            Rule::MinEnclosure {
                outer: B,
                inner: A,
                limit: dbu(50),
                wire: WireBand {
                    from: dbu(from),
                    below: below.map(dbu),
                },
            },
        )]
    };
    for (from, below, held, measured) in [(2_000, None, corner, 40), (0, Some(1_000), tab_via, 10)]
    {
        let mut sink = Sink::default();
        sink.run(&store, &banded(from, below));
        assert_eq!(sink.out.len(), 1, "from {from}, below {below:?}");
        assert_eq!(sink.out.shape_a[0], ids.of(held));
        assert_eq!(sink.out.measured[0], Measurement::Length(dbu(measured)));
        assert_eq!(assert_rule_ran(&sink.runs, RULE).examined, 1);
    }
    let mut sink = Sink::default();
    sink.run(&store, &banded(0, None));
    assert_eq!(sink.out.len(), 2);
}

/// A host's hole is not host. A via 100 clear of the pad's outer edge but 20
/// from a slot on its right and another above has 20 on both axes' near side.
/// Measured on bounding boxes it read 100 and passed.
///
/// Oracle: hand-derived. The slots sit 20 right of and 20 above the via, so
/// each axis has 20 on its near side: one violation measuring 20, naming the
/// via and the pad.
#[test]
fn an_opposite_sides_enclosure_counts_the_hosts_holes() {
    let mut layout = LayoutBuilder::new(2);
    let via = layout.rect(A, 100, 100, 270, 270);
    let pad = layout.rect(B, 0, 0, 1_000, 1_000);
    layout.shape(B, &hole(290, 100, 500, 270));
    layout.shape(B, &hole(100, 290, 270, 500));
    let (store, ids) = layout.finish();

    let mut sink = Sink::default();
    sink.run(&store, &asymmetric_table(60));

    assert_eq!(sink.out.len(), 1);
    assert_eq!(sink.out.measured[0], Measurement::Length(dbu(20)));
    assert_eq!(sink.out.shape_a[0], ids.of(via));
    assert_eq!(sink.out.shape_b[0], Some(ids.of(pad)));
}

/// A via sitting in a hole of its pad is on no metal at all: enclosure zero.
/// The old containment test read only the outer ring and passed it.
///
/// Oracle: construct-from-answer. The via lies wholly in the pad's hole, on no
/// metal: enclosure 0, with no host to name.
#[test]
fn an_inner_shape_inside_a_hosts_hole_is_not_enclosed() {
    let mut layout = LayoutBuilder::new(2);
    let via = layout.rect(A, 400, 400, 600, 600);
    layout.rect(B, 0, 0, 1_000, 1_000);
    layout.shape(B, &hole(300, 300, 700, 700));
    let (store, ids) = layout.finish();

    let mut sink = Sink::default();
    sink.run(&store, &min_enclosure_table(40));

    assert_eq!(sink.out.len(), 1);
    assert_eq!(sink.out.measured[0], Measurement::Length(dbu(0)));
    assert_eq!(sink.out.get(0).shapes, (ids.of(via), None));
}

/// An L-shaped pad around a via at its bend: the bounding box reads 60 of
/// margin at worst, the metal itself only 42 at the notch's corner (the via's
/// corner (170, 170) is 30 by 30 from it). All-sides enclosure is euclidean to
/// the real boundary.
///
/// Oracle: hand-derived. The via's corner (170, 170) is 30 by 30 from the notch
/// corner (200, 200), sqrt(1800) = 42.4, floored to 42: clean at 42, reported
/// as 42 at 43.
#[test]
fn a_min_enclosure_in_an_l_measures_to_the_inner_corner() {
    let mut layout = LayoutBuilder::new(2);
    // 1000 arms, 200 thick: the notch is (200, 200) .. (1000, 1000).
    layout.shape(B, &l_shape(0, 0, 1_000, 200));
    layout.rect(A, 60, 60, 170, 170);
    let (store, _ids) = layout.finish();

    let mut sink = Sink::default();
    sink.run(&store, &min_enclosure_table(42));
    assert_clean(&sink.runs, &sink.out, RULE);
    sink.run(&store, &min_enclosure_table(43));
    assert_eq!(sink.out.len(), 1);
    assert_eq!(sink.out.measured[0], Measurement::Length(dbu(42)));
}

/// Oracle: construct-from-answer, and the whole point of the relaxed form. The
/// same geometry the symmetric rule fails at 41 passes the asymmetric rule at
/// 60, because a landing pad on one side of each axis is what an overlay-error
/// budget actually needs. A rule sharing a comparison with `min_enclosure`
/// cannot produce both answers.
#[test]
fn the_relaxed_rule_passes_a_shape_the_symmetric_rule_fails() {
    let (store, _inner, _outer) = two_sided_enclosure();

    let mut symmetric = Sink::default();
    symmetric.run(&store, &min_enclosure_table(41));
    assert_eq!(symmetric.out.rule.len(), 1);
    assert_eq!(symmetric.out.measured[0], Measurement::Length(dbu(40)));

    let mut relaxed = Sink::default();
    relaxed.run(&store, &asymmetric_table(60));
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
    let mut sink = Sink::default();

    let table = vec![(
        RULE,
        Rule::MinExtension {
            layer: A,
            reference: B,
            limit: dbu(61),
        },
    )];

    sink.run(&case.store, &table);

    assert_only_violation(&sink.out, &case.expected);
    assert_eq!(
        assert_rule_ran(&sink.runs, RULE).examined,
        1,
        "examined counts overlapping shape pairs"
    );
}

/// Oracle: construct-from-answer. The extension is drawn at exactly the
/// 60 limit, and a minimum is violated only below it, so nothing is reported.
#[test]
fn an_extension_exactly_at_the_limit_is_clean() {
    let case = extension_case(60, 60);
    let mut sink = Sink::default();

    let table = vec![(
        RULE,
        Rule::MinExtension {
            layer: A,
            reference: B,
            limit: dbu(60),
        },
    )];

    sink.run(&case.store, &table);

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

    let mut sink = Sink::default();
    let table = vec![(
        RULE,
        Rule::MinExtension {
            layer: A,
            reference: B,
            limit: dbu(1_000),
        },
    )];

    sink.run(&store, &table);

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
    let mut sink = Sink::default();

    let table = vec![(
        RULE,
        Rule::Overlap {
            a: A,
            b: B,
            limit: dbu(81),
        },
    )];

    sink.run(&case.store, &table);

    assert_only_violation(&sink.out, &case.expected);
    assert_eq!(
        assert_rule_ran(&sink.runs, RULE).examined,
        1,
        "examined counts intersection figures"
    );
}

/// Oracle: construct-from-answer. The overlap is drawn at exactly the 80 limit,
/// and a minimum is violated only below it, so one pair is examined and none
/// reported.
#[test]
fn an_overlap_exactly_at_the_limit_is_clean() {
    let case = overlap_case(80, 80);
    let mut sink = Sink::default();

    let table = vec![(
        RULE,
        Rule::Overlap {
            a: A,
            b: B,
            limit: dbu(80),
        },
    )];

    sink.run(&case.store, &table);

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
fn untied_well() -> (gpurify_geom::GeometryStore, PolyId) {
    let mut layout = LayoutBuilder::new(2);
    let well = layout.rect(A, 0, 0, 100, 100);
    layout.rect(B, 400, 300, 500, 400);
    let (store, ids) = layout.finish();
    (store, ids.of(well))
}

fn tap_table(limit: i64) -> Vec<(StrId, Rule)> {
    vec![(
        RULE,
        Rule::MaxDistanceToTap {
            well: A,
            tap: B,
            limit: dbu(limit),
        },
    )]
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
    let mut sink = Sink::default();

    sink.run(&store, &tap_table(499));

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

/// Oracle: closed form. `untied_well`'s far corner is a 3-4-5 triangle from the
/// tap, exactly 500, and a maximum is violated only above it.
#[test]
fn a_well_corner_exactly_at_the_reach_limit_is_clean() {
    let (store, _well) = untied_well();
    let mut sink = Sink::default();

    sink.run(&store, &tap_table(500));

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

    let mut sink = Sink::default();
    sink.run(&store, &tap_table(500));

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

    let mut sink = Sink::default();
    sink.run(&store, &tap_table(500));

    assert_eq!(sink.runs.len(), 1);
    assert_eq!(
        sink.runs[0].outcome,
        Outcome::Skipped(SkipReason::EmptyLayer)
    );
    assert!(sink.out.rule.is_empty());
}

/// IHP LU.a: "Max. distance from any point of N+Activ to the nearest
/// substrate tie 20 um" (`nact.not(ptap.sized(20))`). A 46 um strip tied at
/// both ends has every vertex inside a tie, but its middle is 21 um from
/// either one. The old rule measured vertices only and passed it.
///
/// Oracle: foundry example, IHP LU.a (20 um to the nearest tie), by hand: the
/// 46 um strip's middle, x 23 um, is 21 um from either 2 um tie.
#[test]
fn ihp_lu_a_the_middle_of_a_well_tied_at_both_ends_is_too_far() {
    let mut layout = LayoutBuilder::new(2);
    let well = layout.rect(A, 0, 0, 46_000, 2_000);
    layout.rect(B, 0, 0, 2_000, 2_000);
    layout.rect(B, 44_000, 0, 46_000, 2_000);
    let (store, ids) = layout.finish();

    let mut sink = Sink::default();
    sink.run(
        &store,
        &[(
            RULE,
            Rule::MaxDistanceToTap {
                well: A,
                tap: B,
                limit: dbu(20_000),
            },
        )],
    );

    assert_eq!(sink.out.len(), 1);
    assert_eq!(sink.out.measured[0], Measurement::Length(dbu(21_000)));
    assert_eq!(sink.out.at[0].x, dbu(23_000));
    assert_eq!(sink.out.shape_a[0], ids.of(well));
}
