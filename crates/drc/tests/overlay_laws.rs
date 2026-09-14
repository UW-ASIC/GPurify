//! Two metamorphic laws over the whole overlay family, run as one deck.
//!
//! `overlay_rules.rs` next door checks each of the five rules against a
//! constructed answer. These two check the *family* against transformations of
//! its input that must not change the answer, which is a different oracle and
//! catches a different defect: a constructed case pins one geometry, a law
//! quantifies over all of them.
//!
//! Both laws run all five rules into one `Violations` and one `Vec<RuleRun>`,
//! in a fixed call order, so the sequence — not just the set — is part of what
//! is compared. That is the claim every writer downstream depends on.
//!
//! # Why the fixture sits entirely at negative coordinates
//!
//! `rules::mod::mid` is `(a + b).div_euclid(2)`, and its doc comment names the
//! bug it exists to prevent: truncation toward zero would put the midpoint of an
//! odd span one unit away depending on which side of the origin the shape sits.
//! That is invisible to any translation test whose geometry never crosses the
//! origin — `determinism.rs`'s `SHIFT = 1_000_000` over a layout already at
//! `x, y >= -100` is exactly that shape, and a `/`-based `mid` passes it.
//!
//! So every shape here is drawn wholly negative and every strip and gap it
//! reports on has an **odd** width, and the translation moves the whole design
//! wholly positive. `the_fixture_reports_at_odd_negative_midpoints` asserts that
//! property arithmetically rather than trusting this paragraph, and lists the
//! answer truncation would have given for each of the nine midpoints.

mod common;

use common::{Env, Sink};
use gpurify_core::{GeometryStore, LayerId};
use gpurify_drc::rules::overlay::{
    check_asymmetric_enclosure, check_max_distance_to_tap, check_min_enclosure,
    check_min_extension, check_overlap, AsymmetricEnclosureTable, MaxDistanceToTapTable,
    MinEnclosureTable, MinExtensionTable, OverlapTable,
};
use gpurify_ingest::StrId;
use gpurify_report::{Measurement, Outcome, RuleRun, SkipReason, Violations};
use gpurify_testgen::shapes::LayoutBuilder;
use gpurify_testgen::{dbu, point};
use gpurify_units::MAX_ABS_DBU;

// ------------------------------------------------------------------- fixture

const ENC_INNER: LayerId = LayerId(0);
const ENC_OUTER: LayerId = LayerId(1);
const EXT_LINE: LayerId = LayerId(2);
const EXT_REF: LayerId = LayerId(3);
const OVL_A: LayerId = LayerId(4);
const OVL_B: LayerId = LayerId(5);
const WELL: LayerId = LayerId(6);
const TAP_LAYER: LayerId = LayerId(7);
/// Holds one triangle, so every rule row naming it records `Outcome::Refused`.
const BAD: LayerId = LayerId(8);
/// Declared and never drawn on, so the tap rule records
/// `Outcome::Skipped(EmptyLayer)` for a row naming it as the well.
const EMPTY: LayerId = LayerId(9);
const LAYER_COUNT: usize = 10;

const ENC: StrId = StrId(0);
const ENC_REFUSED: StrId = StrId(1);
const ASYM: StrId = StrId(2);
const EXT: StrId = StrId(3);
const OVL: StrId = StrId(4);
const TAP: StrId = StrId(5);
const TAP_EMPTY: StrId = StrId(6);

/// The five rules that must each report at least one violation before either law
/// compares anything. Per rule, not in aggregate: `determinism.rs` guards only
/// that the whole table is non-empty, under which four of five rules can be
/// silently empty and the law holds over nothing.
const RULES_THAT_MUST_FIRE: [StrId; 5] = [ENC, ASYM, EXT, OVL, TAP];

/// The largest coordinate magnitude any shape below reaches. The scale law
/// checks `k * COORD_REACH` against the coordinate domain before it builds.
const COORD_REACH: i64 = 3_000;
/// The largest limit any table below carries, for the same reason — and it is a
/// separate bound, because `check_max_distance_to_tap` hands its limit straight
/// to `pair_layers` as the prune distance, which `debug_assert`s it against
/// `MAX_ABS_DBU`.
const LIMIT_REACH: i64 = 499;

/// The whole overlay fixture, with `t` applied to every vertex.
///
/// One builder for both laws, so neither can be reading different geometry from
/// the other. The push order fixes the `PolyId`s: `GeometryStoreBuilder::finish`
/// counting-sorts by layer and is stable within one, and it never looks at a
/// coordinate — so every transform below leaves `Violation::shapes` alone by
/// construction and a disagreement there is a real one.
fn fixture(t: impl Fn(i64, i64) -> (i64, i64)) -> GeometryStore {
    let mut layout = LayoutBuilder::new(LAYER_COUNT);
    let rect = |layout: &mut LayoutBuilder, layer: LayerId, b: [i64; 4]| {
        let (xlo, ylo) = t(b[0], b[1]);
        let (xhi, yhi) = t(b[2], b[3]);
        layout.rect(layer, xlo, ylo, xhi, yhi);
    };

    // Margins 9 left, 29 right, 29 bottom, 30 top. `worst` is the left 9 and
    // `worst_axis_best_side` is `min(max(9, 29), max(29, 30))` = the right 29,
    // so the two enclosure rules name two different sides off one geometry.
    rect(&mut layout, ENC_INNER, [-101, -101, -50, -50]);
    // No host anywhere: enclosure zero, `shapes.1 == None`, reported at its own
    // centre. 101 by 103, both odd, so that centre is a floored midpoint too.
    rect(&mut layout, ENC_INNER, [-501, -403, -400, -300]);
    rect(&mut layout, ENC_OUTER, [-110, -130, -21, -20]);

    // The stripe runs 39 past the bar on the left and 111 past it on the right,
    // and is swallowed on both of the other sides, so the smallest protrusion is
    // the left 39.
    rect(&mut layout, EXT_LINE, [-300, -251, -100, -200]);
    rect(&mut layout, EXT_REF, [-261, -400, -211, -50]);

    // Intersection is 51 by 51: the smaller side is 51 whichever axis wins, so
    // the measurement does not depend on a tie-break.
    rect(&mut layout, OVL_A, [-800, -700, -700, -600]);
    rect(&mut layout, OVL_B, [-751, -651, -650, -550]);

    // 3-4-5 again: the well's vertex 0 is 400 across and 300 up from the tap's
    // nearest point, so the answer is exactly 500 and belongs to one corner.
    rect(&mut layout, WELL, [-1_000, -1_000, -900, -900]);
    rect(&mut layout, TAP_LAYER, [-600, -700, -500, -600]);

    // Not rectilinear under any of the transforms below — a uniform scale and a
    // translation both leave the slanted edge slanted — so `validate_layer_into`
    // refuses it in every run.
    let apex = t(-2_950, -2_900);
    let left = t(-3_000, -3_000);
    let right = t(-2_900, -3_000);
    layout.push(BAD, &[left.0, right.0, apex.0], &[left.1, right.1, apex.1]);

    let (store, _ids) = layout.finish();
    store
}

/// Every overlay rule over one store, with every limit multiplied by `k`.
///
/// The five calls share one `Violations` and one `Vec<RuleRun>` in this order,
/// which is what makes "the same sequence" a claim about the family rather than
/// about five unrelated tables.
fn run_overlay(store: &GeometryStore, k: i64) -> (Violations, Vec<RuleRun>) {
    let env = Env::default();
    let mut sink = Sink::default();

    let mut enclosure = MinEnclosureTable::default();
    enclosure.rule.push(ENC);
    enclosure.outer.push(ENC_OUTER);
    enclosure.inner.push(ENC_INNER);
    enclosure.limit.push(dbu(10 * k));
    // Second row, same inner layer against the triangle: `Outcome::Refused`.
    enclosure.rule.push(ENC_REFUSED);
    enclosure.outer.push(BAD);
    enclosure.inner.push(ENC_INNER);
    enclosure.limit.push(dbu(10 * k));
    check_min_enclosure(
        env.design(store),
        &enclosure,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    let mut asymmetric = AsymmetricEnclosureTable::default();
    asymmetric.rule.push(ASYM);
    asymmetric.outer.push(ENC_OUTER);
    asymmetric.inner.push(ENC_INNER);
    asymmetric.min_one_side.push(dbu(30 * k));
    check_asymmetric_enclosure(
        env.design(store),
        &asymmetric,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    let mut extension = MinExtensionTable::default();
    extension.rule.push(EXT);
    extension.layer.push(EXT_LINE);
    extension.reference.push(EXT_REF);
    extension.limit.push(dbu(40 * k));
    check_min_extension(
        env.design(store),
        &extension,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    let mut overlap = OverlapTable::default();
    overlap.rule.push(OVL);
    overlap.a.push(OVL_A);
    overlap.b.push(OVL_B);
    overlap.limit.push(dbu(52 * k));
    check_overlap(
        env.design(store),
        &overlap,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    let mut tap = MaxDistanceToTapTable::default();
    tap.rule.push(TAP);
    tap.well.push(WELL);
    tap.tap.push(TAP_LAYER);
    tap.limit.push(dbu(499 * k));
    // Second row over a layer with no geometry: `Skipped(EmptyLayer)`, which is
    // a different claim from judged-and-clean and the only one the violation
    // table cannot make on its own.
    tap.rule.push(TAP_EMPTY);
    tap.well.push(EMPTY);
    tap.tap.push(TAP_LAYER);
    tap.limit.push(dbu(499 * k));
    check_max_distance_to_tap(
        env.design(store),
        &tap,
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    (sink.out, sink.runs)
}

fn length(m: Measurement) -> i64 {
    match m {
        Measurement::Length(d) => d.raw(),
        other => panic!("the overlay family reports lengths, and this is {other:?}"),
    }
}

fn violations_of(out: &Violations, rule: StrId) -> usize {
    out.rule.iter().filter(|&&r| r == rule).count()
}

/// Every rule fired, and the two non-`Ran` outcomes were both produced.
///
/// Per rule rather than in aggregate: a table that is non-empty overall still
/// lets four of the five rules contribute nothing, and a law that quantifies
/// over no rows holds over nothing.
fn assert_base_is_not_vacuous(out: &Violations, runs: &[RuleRun]) {
    for rule in RULES_THAT_MUST_FIRE {
        assert!(
            violations_of(out, rule) >= 1,
            "rule {rule:?} reported nothing, so the law holds over none of its rows"
        );
    }
    assert!(
        runs.iter()
            .any(|r| r.rule == ENC_REFUSED && r.outcome == Outcome::Refused),
        "the refusal row did not refuse, so neither law exercises that arm"
    );
    assert!(
        runs.iter()
            .any(|r| r.rule == TAP_EMPTY && r.outcome == Outcome::Skipped(SkipReason::EmptyLayer)),
        "the empty-layer row did not skip, so neither law exercises that arm"
    );
    assert!(
        out.shape_b.iter().any(Option::is_none),
        "no unhosted inner shape was reported, so the `at` fallback is untested"
    );
}

// ------------------------------------------------------- the fixture's teeth

/// The nine midpoints this fixture makes the family compute, each as the two
/// operands, the floored answer `mid` gives, and the answer truncation would.
///
/// Every sum is odd and negative, which is the only regime where
/// `div_euclid(2)` and `/ 2` disagree — so every one of these nine is a place
/// the translation law below can actually fail.
const MIDPOINTS: [(i64, i64, i64, i64); 9] = [
    (-110, -101, -106, -105), // min_enclosure, deficient left strip, x
    (-101, -50, -76, -75),    // both enclosure rules, the inner shape's span, y
    (-501, -400, -451, -450), // the unhosted shape's own centre, x
    (-403, -300, -352, -351), // the unhosted shape's own centre, y
    (-50, -21, -36, -35),     // asymmetric_enclosure, the best right strip, x
    (-300, -261, -281, -280), // min_extension, the left overhang, x
    (-251, -200, -226, -225), // min_extension, the shared span, y
    (-751, -700, -726, -725), // overlap, the intersection figure, x
    (-651, -600, -626, -625), // overlap, the intersection figure, y
];

/// The base run's reported points, in the order the five calls produce them.
const BASE_POINTS: [(i64, i64); 7] = [
    (-106, -76),      // min_enclosure, the hosted inner shape
    (-451, -352),     // min_enclosure, the unhosted one
    (-36, -76),       // asymmetric_enclosure, the hosted inner shape
    (-451, -352),     // asymmetric_enclosure, the unhosted one
    (-281, -226),     // min_extension
    (-726, -626),     // overlap
    (-1_000, -1_000), // max_distance_to_tap, a raw vertex rather than a midpoint
];

/// Oracle: closed form, and the anti-vacuity guard for the translation law.
///
/// Asserts arithmetically what the module doc claims in prose: every midpoint
/// this fixture drives is the floor of an *odd, negative* half-sum, so the two
/// candidate implementations of `mid` give different answers at all nine, and
/// the reported points are the floored ones. Without this the translation law
/// still passes on a fixture that has drifted to even spans — and would then be
/// asserting nothing about the bug `rules::mod::mid` names.
#[test]
fn the_fixture_reports_at_odd_negative_midpoints() {
    for (a, b, floored, truncated) in MIDPOINTS {
        let sum = a + b;
        assert!(
            sum < 0,
            "({a}, {b}) does not straddle: the law loses its teeth"
        );
        assert_ne!(
            sum % 2,
            0,
            "({a}, {b}) has an even span, so both midpoints agree"
        );
        assert_eq!(sum.div_euclid(2), floored, "({a}, {b})");
        assert_eq!(sum / 2, truncated, "({a}, {b})");
        assert_ne!(floored, truncated, "({a}, {b}) cannot distinguish the two");
    }

    let (out, runs) = run_overlay(&fixture(|x, y| (x, y)), 1);
    assert_base_is_not_vacuous(&out, &runs);
    assert_eq!(out.len(), BASE_POINTS.len());
    for (row, (x, y)) in BASE_POINTS.into_iter().enumerate() {
        assert_eq!(out.at[row], point(x, y), "row {row}");
    }
}

/// Oracle: closed form. The scale law asserts the tap distance scales *exactly*
/// by `k`, and that is only sound because this fixture sits on a 3-4-5 triangle:
/// the well's vertex 0 at `(-1000, -1000)` is 400 across and 300 up from the
/// tap's nearest corner at `(-600, -700)`, so the distance is the integer 500
/// and `ceil(sqrt(k^2 * 500^2))` is `500k` with nothing left to round.
///
/// Pinned here because the drift is silent: move the tap off the triple and the
/// distance becomes irrational, `ceil` starts rounding, and the exact assertion
/// in the scale law becomes *wrong* rather than failing loudly. The interval
/// form this replaced admitted `k - 1` passing values on this geometry.
#[test]
fn the_tap_distance_is_an_exact_integer() {
    let (out, runs) = run_overlay(&fixture(|x, y| (x, y)), 1);
    assert_base_is_not_vacuous(&out, &runs);

    let row = out
        .rule
        .iter()
        .position(|rule| *rule == TAP)
        .expect("the fixture must drive max_distance_to_tap, or the scale law is vacuous there");

    assert_eq!(
        400i64 * 400 + 300 * 300,
        500 * 500,
        "the derivation below rests on 3-4-5"
    );
    assert_eq!(
        length(out.measured[row]),
        500,
        "the tap geometry has drifted off the Pythagorean triple, so the scale \
         law's exact `k * m` no longer follows"
    );
}

// --------------------------------------------------------- law 5: translation

/// Odd, and different per axis so a transposed coordinate cannot pass. Large
/// enough that the whole design — which reaches `-3_000` — lands strictly
/// positive, which is what makes every one of the nine midpoints above cross the
/// origin.
const DX: i64 = 3_001;
const DY: i64 = 3_003;

/// Oracle: law. Layout geometry has no privileged origin. Adding a constant to
/// every coordinate on every layer, with the deck untouched, must move every
/// reported point by that constant and change nothing else at all: the same
/// outcomes, the same `examined`, the same violation sequence in the same order,
/// and every other column bit-identical. No tolerance — these are integers.
///
/// The value is in the origin crossing. `mid` is `div_euclid`, which floors on
/// both sides of zero; truncation toward zero would agree with it everywhere the
/// half-sum is non-negative and differ by one everywhere it is negative and odd.
/// `the_fixture_reports_at_odd_negative_midpoints` pins that the base run sits
/// entirely in that second regime and the translated run entirely in the first,
/// so a `/`-based `mid` fails six of these seven rows.
#[test]
fn translating_the_overlay_design_across_the_origin_moves_only_the_report() {
    let (base, base_runs) = run_overlay(&fixture(|x, y| (x, y)), 1);
    assert_base_is_not_vacuous(&base, &base_runs);
    for row in 0..base.len() {
        assert!(
            base.at[row].x.raw() < 0 && base.at[row].y.raw() < 0,
            "row {row} is not on the negative side of the origin before the shift"
        );
    }

    let (moved, moved_runs) = run_overlay(&fixture(|x, y| (x + DX, y + DY)), 1);
    for row in 0..moved.len() {
        assert!(
            moved.at[row].x.raw() > 0 && moved.at[row].y.raw() > 0,
            "row {row} is not on the positive side of the origin after the shift"
        );
    }

    assert_eq!(
        base_runs, moved_runs,
        "translation changed an outcome or an examined count"
    );
    assert_eq!(
        base.len(),
        moved.len(),
        "translation changed how many violations there are"
    );
    for row in 0..base.len() {
        assert_eq!(base.rule[row], moved.rule[row], "row {row}");
        assert_eq!(base.layer[row], moved.layer[row], "row {row}");
        assert_eq!(base.severity[row], moved.severity[row], "row {row}");
        assert_eq!(base.measured[row], moved.measured[row], "row {row}");
        assert_eq!(base.limit[row], moved.limit[row], "row {row}");
        assert_eq!(base.shape_a[row], moved.shape_a[row], "row {row}");
        assert_eq!(base.shape_b[row], moved.shape_b[row], "row {row}");
        assert_eq!(
            base.at[row].x + dbu(DX),
            moved.at[row].x,
            "row {row} moved in x by something other than the translation"
        );
        assert_eq!(
            base.at[row].y + dbu(DY),
            moved.at[row].y,
            "row {row} moved in y by something other than the translation"
        );
    }
}

// --------------------------------------------------------------- law 6: scale

/// Oracle: law. A lithographic constraint is a ratio between geometry and deck,
/// so multiplying every coordinate *and* every limit by the same integer `k`
/// re-states the identical question in a finer grid. The four lithographic rules
/// must reach the same verdict on the same shapes with every measurement exactly
/// `k` times what it was.
///
/// `at` is deliberately **not** compared for those four. `mid` floors, so a
/// scaled odd span's midpoint is `floor(k * (a + b) / 2)`, which is `k` times the
/// unscaled midpoint only when `a + b` is even — and this fixture is built so it
/// never is. Even `k` does not save it: the two answers differ by `k / 2`. That
/// is `mid` being correct, not wrong, so the law drops the clause rather than
/// weakening it.
///
/// `check_max_distance_to_tap` is the exception on both counts. It reports a raw
/// vertex, so `at` scales exactly and is asserted. Its measurement is
/// `ceil(sqrt(k^2 * d2))`, which is `ceil(k * d)` — bounded by
/// `k * (m - 1) < m' <= k * m` rather than equal to `k * m`, because the ceiling
/// of a scaled irrational is not the scaling of a ceiling.
#[test]
fn scaling_the_overlay_geometry_and_deck_together_scales_only_the_measurements() {
    let (base, base_runs) = run_overlay(&fixture(|x, y| (x, y)), 1);
    assert_base_is_not_vacuous(&base, &base_runs);

    for k in [2i64, 3, 7] {
        // The scaled *limit* is the tighter bound, not the scaled coordinate:
        // `check_max_distance_to_tap` passes its limit to `pair_layers` as the
        // prune distance, which `debug_assert`s it against the coordinate
        // domain, so a `k` that overflows the limit panics before it can fail
        // the law.
        assert!(
            k * COORD_REACH <= MAX_ABS_DBU && k * LIMIT_REACH <= MAX_ABS_DBU,
            "k = {k} takes the fixture or its deck past the coordinate domain"
        );

        let (scaled, scaled_runs) = run_overlay(&fixture(|x, y| (x * k, y * k)), k);

        assert_eq!(
            base_runs.len(),
            scaled_runs.len(),
            "scaling by {k} changed the number of rule runs"
        );
        for row in 0..base_runs.len() {
            assert_eq!(
                base_runs[row].rule, scaled_runs[row].rule,
                "k = {k}, run {row}"
            );
            assert_eq!(
                base_runs[row].outcome, scaled_runs[row].outcome,
                "k = {k}, run {row}"
            );
            assert_eq!(
                base_runs[row].examined, scaled_runs[row].examined,
                "k = {k}, run {row}"
            );
            assert_eq!(
                base_runs[row].violations, scaled_runs[row].violations,
                "k = {k}, run {row}"
            );
        }

        assert_eq!(
            base.len(),
            scaled.len(),
            "scaling by {k} changed how many violations there are"
        );
        for row in 0..base.len() {
            assert_eq!(base.rule[row], scaled.rule[row], "k = {k}, row {row}");
            assert_eq!(base.layer[row], scaled.layer[row], "k = {k}, row {row}");
            assert_eq!(
                base.severity[row], scaled.severity[row],
                "k = {k}, row {row}"
            );
            assert_eq!(base.shape_a[row], scaled.shape_a[row], "k = {k}, row {row}");
            assert_eq!(base.shape_b[row], scaled.shape_b[row], "k = {k}, row {row}");
            assert_eq!(
                length(base.limit[row]) * k,
                length(scaled.limit[row]),
                "k = {k}, row {row}: the deck was not scaled with the geometry"
            );

            let m = length(base.measured[row]);
            let scaled_m = length(scaled.measured[row]);
            if base.rule[row] == TAP {
                // Exactly `k`, not the interval the law states in general. The
                // tap geometry here is a 3-4-5 triangle, so the distance is the
                // integer 500 and `ceil(sqrt(k^2 * 500^2))` is `500k` with
                // nothing to round. The interval form admits `k - 1` wrong
                // values on this fixture and so tests weaker than it can.
                // `the_tap_distance_is_an_exact_integer` pins the triple.
                assert_eq!(
                    k * m,
                    scaled_m,
                    "k = {k}, row {row}: an exact distance of {m} scaled to {scaled_m}"
                );
                assert_eq!(
                    base.at[row].x.raw() * k,
                    scaled.at[row].x.raw(),
                    "k = {k}, row {row}: a reported vertex is a raw coordinate and scales exactly"
                );
                assert_eq!(
                    base.at[row].y.raw() * k,
                    scaled.at[row].y.raw(),
                    "k = {k}, row {row}"
                );
            } else {
                assert_eq!(
                    m * k,
                    scaled_m,
                    "k = {k}, row {row}: a lithographic measurement is a distance and scales exactly"
                );
            }
        }
    }
}
