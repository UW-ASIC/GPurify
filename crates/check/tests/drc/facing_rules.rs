//! Spacing kinds read off the edges of the merged layer
//! (`drc::rules::facing`). Every case asserts what was measured, the limit it
//! was held to, the marker, and `examined`, so a table looked up in the wrong
//! cell or a pair dropped from the scan shows.

use crate::common::{A, RULE};
use gpurify_check::drc::ruleset::ClassTable;
use gpurify_check::drc::{Rule, RuleSet};
use gpurify_check::report::{Measurement, Outcome, RuleRun, Violations};
use gpurify_geom::GeometryStore;
use gpurify_testgen::shapes::LayoutBuilder;
use gpurify_testgen::{assert_rule_ran, dbu, point};

/// Runs `rule` alone, with `class_tables` for a table kind.
fn run(
    store: &GeometryStore,
    rule: Rule,
    class_tables: Vec<ClassTable>,
) -> (Violations, Vec<RuleRun>) {
    let set = RuleSet {
        rules: vec![(RULE, rule)],
        class_tables,
        ..RuleSet::default()
    };
    let (mut out, mut runs) = (Violations::default(), Vec::new());
    set.run(store, &mut out, &mut runs);
    (out, runs)
}

/// Rectangles `[xlo, ylo, xhi, yhi]` on layer A.
fn layout(rects: &[[i64; 4]]) -> GeometryStore {
    let mut builder = LayoutBuilder::new(1);
    for &[xlo, ylo, xhi, yhi] in rects {
        builder.rect(A, xlo, ylo, xhi, yhi);
    }
    builder.finish().0
}

fn len(v: i64) -> Measurement {
    Measurement::Length(dbu(v))
}

/// The one rule's run row, whatever it examined.
fn only(runs: &[RuleRun]) -> RuleRun {
    assert_eq!(runs.len(), 1, "one rule, one run row");
    runs[0]
}

// -------------------------------------------------------- tip_spacing_table

/// The ASAP7 M1 table, DRM r1p7 Table 3.12.1: edges below 24 nm, from 24 to
/// 36 nm, above 36 nm; M1.S.1 18, M1.S.2 25, M1.S.3 27, M1.S.4 31, M1.S.5 31.
fn asap7_m1() -> Vec<ClassTable> {
    vec![ClassTable {
        class: vec![dbu(0), dbu(24), dbu(37)],
        prl: Vec::new(),
        space: [31, 31, 25, 31, 27, 25, 25, 25, 18]
            .into_iter()
            .map(dbu)
            .collect(),
    }]
}

const TIPS: Rule = Rule::TipSpacingTable { layer: A, table: 0 };

/// Two lines `wa` and `wb` wide, tip to tip `gap` apart.
fn tips(wa: i64, wb: i64, gap: i64) -> GeometryStore {
    layout(&[[0, 0, wa, 1000], [0, 1000 + gap, wb, 2000 + gap]])
}

/// Oracle: ASAP7 M1.S.3, two tips 24 to 36 nm wide need 27; construct from
/// answer for the marker, the middle of the 30-wide stretch the two ends
/// face each other over, (15, (1000 + 1026) / 2). A lookup in any other cell
/// reads 31, 25 or 18.
#[test]
fn tips_one_unit_inside_their_cell_are_reported_with_that_cell() {
    let (out, runs) = run(&tips(30, 30, 26), TIPS, asap7_m1());

    assert_eq!(out.measured, [len(26)]);
    assert_eq!(out.limit, [len(27)]);
    assert_eq!(out.at, [point(15, 1013)]);
    assert!(out.shape_b[0].is_some(), "a pair names both shapes");
    let run = assert_rule_ran(&runs, RULE);
    assert_eq!(run.examined, 1, "one facing pair of edges");
}

/// Oracle: construct-from-answer. A gap exactly at its cell meets the rule;
/// the facing pair was still examined.
#[test]
fn tips_exactly_at_their_cell_are_clean_and_still_examined() {
    let (out, runs) = run(&tips(30, 30, 27), TIPS, asap7_m1());

    assert!(out.is_empty());
    assert_eq!(assert_rule_ran(&runs, RULE).examined, 1);
}

/// Oracle: ASAP7 M1.S.3 against M1.S.4. A 24 wide tip reaches the 24 nm
/// threshold, so it is in the middle class and 26 apart breaks 27; a 23
/// wide one is below it and breaks 31. Classing by "exceeds" would put 24
/// in the first class too.
#[test]
fn the_last_threshold_a_length_reaches_picks_its_class() {
    let store = layout(&[
        [0, 0, 24, 1000],
        [0, 1026, 24, 2026],
        [5000, 0, 5023, 1000],
        [5000, 1026, 5023, 2026],
    ]);
    let (out, _) = run(&store, TIPS, asap7_m1());

    let mut found: Vec<(Measurement, Measurement)> = out
        .measured
        .iter()
        .copied()
        .zip(out.limit.iter().copied())
        .collect();
    found.sort_by_key(|&(_, limit)| match limit {
        Measurement::Length(l) => l.raw(),
        _ => 0,
    });
    assert_eq!(found, [(len(26), len(27)), (len(26), len(31))]);
}

/// Oracle: construct-from-answer. Two tips whose spans meet only at the
/// point x = 30 do not face each other: their gap is diagonal, a corner
/// rule's. A scan accepting a zero-length overlap would hold them to 31.
#[test]
fn edges_meeting_only_at_a_point_do_not_face() {
    let store = layout(&[[0, 0, 30, 1000], [30, 1010, 60, 2000]]);
    let (out, runs) = run(&store, TIPS, asap7_m1());

    assert!(out.is_empty());
    assert_eq!(only(&runs).outcome, Outcome::Ran);
    assert_eq!(only(&runs).examined, 0);
}

/// Oracle: construct-from-answer at the scan's reach. Two 20 wide tips need
/// 31, the table's widest cell: 30 apart is the farthest pair that can fail
/// and is examined and reported; 31 apart cannot fail and is not examined.
#[test]
fn the_scan_reaches_one_unit_inside_the_widest_cell() {
    let (out, runs) = run(&tips(20, 20, 30), TIPS, asap7_m1());
    assert_eq!(out.measured, [len(30)]);
    assert_eq!(out.limit, [len(31)]);
    assert_eq!(assert_rule_ran(&runs, RULE).examined, 1);

    let (out, runs) = run(&tips(20, 20, 31), TIPS, asap7_m1());
    assert!(out.is_empty());
    assert_eq!(only(&runs).examined, 0);
}

/// Oracle: construct-from-answer. A bar's side faces one figure along two
/// steps, 15 apart over y = 0..400 and 10 apart over y = 400..1000; both
/// break M1.S.1's 18. One finding for the pair of figures, the nearer step,
/// marked in its middle (105, 700).
#[test]
fn the_nearer_of_two_offending_steps_is_the_finding() {
    let store = layout(&[[0, 0, 100, 1000], [115, 0, 215, 400], [110, 400, 210, 1000]]);
    let (out, runs) = run(&store, TIPS, asap7_m1());

    assert_eq!(out.measured, [len(10)]);
    assert_eq!(out.limit, [len(18)]);
    assert_eq!(out.at, [point(105, 700)]);
    assert_eq!(assert_rule_ran(&runs, RULE).examined, 2);
}

// -------------------------------------------------------- forbidden_spacing

/// A forbidden range of 100 to 150 for runs longer than 200.
fn forbidden() -> Rule {
    Rule::ForbiddenSpacing {
        layer: A,
        min: dbu(100),
        max: dbu(150),
        prl: dbu(200),
    }
}

/// Two 1000 long bars `gap` apart.
fn bars(gap: i64) -> GeometryStore {
    layout(&[[0, 0, 100, 1000], [100 + gap, 0, 200 + gap, 1000]])
}

/// Oracle: `TritonRoute`'s `isForbiddenSpacing`, a closed range. Both ends
/// of it are forbidden and reported against the narrowest legal gap above
/// it, 151, at the middle of the gap; one step outside either end is legal
/// though still examined.
#[test]
fn both_ends_of_the_range_are_forbidden_and_one_step_out_is_legal() {
    for (gap, forbidden) in [(99, false), (100, true), (150, true), (151, false)] {
        let (out, runs) = run(&bars(gap), forbidden(), Vec::new());
        if forbidden {
            assert_eq!(out.measured, [len(gap)], "gap {gap}");
            assert_eq!(out.limit, [len(151)], "gap {gap}");
            assert_eq!(out.at, [point((200 + gap) / 2, 500)], "gap {gap}");
        } else {
            assert!(out.is_empty(), "gap {gap}");
        }
        let examined = u64::from(gap <= 150);
        assert_eq!(only(&runs).examined, examined, "gap {gap}");
    }
}

/// Oracle: `TritonRoute`'s `isValidPrl`, a run strictly longer than `prl`.
/// Two bars 120 apart overlapping by 200 are not judged at all; by 201 they
/// are, and fail.
#[test]
fn a_run_must_be_longer_than_prl() {
    let store = |run: i64| layout(&[[0, 0, 100, 1000], [220, 1000 - run, 320, 2000 - run]]);
    let (out, runs) = run(&store(200), forbidden(), Vec::new());
    assert!(out.is_empty());
    assert_eq!(only(&runs).examined, 0);

    let (out, runs) = run(&store(201), forbidden(), Vec::new());
    assert_eq!(out.measured, [len(120)]);
    assert_eq!(only(&runs).examined, 1);
}

/// Oracle: construct-from-answer. A figure faces a bar 90 away along one
/// step (below the range: legal) and 130 along another (forbidden): the
/// finding is the forbidden 130, marked in the middle of its stretch
/// (165, 700), not the nearer legal gap.
#[test]
fn a_narrower_legal_gap_does_not_hide_a_forbidden_one() {
    let store = layout(&[[0, 0, 100, 1000], [190, 0, 290, 400], [230, 400, 330, 1000]]);
    let (out, runs) = run(&store, forbidden(), Vec::new());

    assert_eq!(out.measured, [len(130)]);
    assert_eq!(out.at, [point(165, 700)]);
    assert_eq!(assert_rule_ran(&runs, RULE).examined, 2);
}

/// Oracle: the kind's contract. A layer the rule cannot represent exactly
/// (a triangle) is refused, never read as clean.
#[test]
fn a_layer_that_does_not_validate_is_refused() {
    let mut builder = LayoutBuilder::new(1);
    builder.push(A, &[0, 100, 0], &[0, 0, 100]);
    let (store, _) = builder.finish();
    let (out, runs) = run(&store, TIPS, asap7_m1());

    assert!(out.is_empty());
    assert_eq!(only(&runs).outcome, Outcome::Refused);
}
