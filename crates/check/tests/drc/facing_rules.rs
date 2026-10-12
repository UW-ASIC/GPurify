//! Spacing kinds read off the edges of the merged layer
//! (`drc::rules::facing`), and the two-width spacing table. Every case
//! asserts what was measured, the limit it was held to, the marker, and
//! `examined`, so a table looked up in the wrong cell or a pair dropped from
//! the scan shows.

use crate::common::{A, RULE};
use gpurify_check::drc::ruleset::{ClassTable, EolParallel, SpanTable};
use gpurify_check::drc::{DrcError, Rule, RuleSet};
use gpurify_check::report::{Measurement, Outcome, RuleRun, Violations};
use gpurify_geom::{Dbu, DbuArea, GeometryStore, Grid};
use gpurify_ingest::deck::parse_deck;
use gpurify_ingest::StrTable;
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
    for (gap, in_range) in [(99, false), (100, true), (150, true), (151, false)] {
        let (out, runs) = run(&bars(gap), forbidden(), Vec::new());
        if in_range {
            assert_eq!(out.measured, [len(gap)], "gap {gap}");
            assert_eq!(out.limit, [len(151)], "gap {gap}");
            assert_eq!(out.at, [point(i64::midpoint(200, gap), 500)], "gap {gap}");
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

// ------------------------------------------------------- eol_within_spacing

/// LEF/DEF 5.8 Example 1-18 in nanometres: `SPACING 1.2 ENDOFLINE 1.3
/// WITHIN 0.6`, with `parallel` and `end_to_end`.
fn lef_eol(parallel: Option<EolParallel>, end_to_end: Option<i64>) -> Rule {
    Rule::EolWithinSpacing {
        layer: A,
        eol_width: dbu(1300),
        within: dbu(600),
        parallel,
        end_to_end: end_to_end.map(dbu),
        limit: dbu(1200),
    }
}

/// `PARALLELEDGE 1.1 WITHIN 0.5`, with or without `TWOEDGES`.
fn parallel_edge(two_edges: bool) -> EolParallel {
    EolParallel {
        space: dbu(1100),
        within: dbu(500),
        two_edges,
    }
}

/// A 1000 wide line ending at y = 0, so its top is an end of line.
const LINE: [i64; 4] = [0, -5000, 1000, 0];

/// A 7000 wide bar 1000 above the line, inside its keep-out.
const BAR: [i64; 4] = [-3000, 1000, 4000, 2000];

/// Oracle: LEF 5.8 Figure 1-23 b, construct-from-answer for the marker. A
/// bar 1199 above the end is one unit inside the keep-out: depth 1199,
/// marked over the end widened by 600, x = -600..1600, midway up the gap.
/// The line's two ends and the bar's two 1000 long sides are the ends of
/// line examined.
#[test]
fn a_facing_edge_inside_the_keep_out_fails_by_its_depth() {
    let (out, runs) = run(
        &layout(&[LINE, [-2000, 1199, 3000, 2199]]),
        lef_eol(None, None),
        Vec::new(),
    );

    assert_eq!(out.measured, [len(1199)]);
    assert_eq!(out.limit, [len(1200)]);
    assert_eq!(out.at, [point(500, 599)]);
    assert_eq!(assert_rule_ran(&runs, RULE).examined, 4);

    let (out, _) = run(
        &layout(&[LINE, [-2000, 1200, 3000, 2200]]),
        lef_eol(None, None),
        Vec::new(),
    );
    assert!(out.is_empty(), "exactly at the space is legal");
}

/// Oracle: LEF 5.8 Figure 1-23 c and d, "within (that is, less than)
/// eolWithin". A square 300 above whose side lies 599 past the end's side
/// is in the keep-out; 600 past it is not.
#[test]
fn the_keep_out_reaches_less_than_within_past_the_end() {
    let (out, _) = run(
        &layout(&[LINE, [1599, 300, 3599, 2300]]),
        lef_eol(None, None),
        Vec::new(),
    );
    assert_eq!(out.measured, [len(300)]);

    let (out, _) = run(
        &layout(&[LINE, [1600, 300, 3600, 2300]]),
        lef_eol(None, None),
        Vec::new(),
    );
    assert!(out.is_empty());
}

/// Oracle: `TritonRoute`'s end of line, both corners convex. A tab's side is
/// 1000 long but meets its base at a concave corner, so it is no end: the
/// wide shape 500 beside it is clean, and only the tab's top is examined.
#[test]
fn an_edge_with_a_concave_corner_is_no_end() {
    let store = layout(&[
        [-3000, -5000, 4000, -1000],
        [0, -1000, 1000, 0],
        [-3000, -900, -500, 3000],
    ]);
    let (out, runs) = run(&store, lef_eol(None, None), Vec::new());

    assert!(out.is_empty());
    assert_eq!(assert_rule_ran(&runs, RULE).examined, 1);
}

/// Oracle: LEF 5.8 Figure 1-24, `PARALLELEDGE 1.1 WITHIN 0.5`. The bar
/// 1000 above fails only when a neighbour runs beside the line less than
/// 1100 from its side (1099 does, 1100 does not), with its top reaching
/// less than 500 behind the end's line (-499 does, -500 does not).
#[test]
fn a_parallel_edge_beside_the_line_triggers_the_rule() {
    let rule = lef_eol(Some(parallel_edge(false)), None);
    let with = |neighbour: [i64; 4]| run(&layout(&[LINE, BAR, neighbour]), rule, Vec::new()).0;

    assert_eq!(with([-3099, -5000, -1099, 0]).measured, [len(1000)]);
    assert!(with([-3100, -5000, -1100, 0]).is_empty());
    assert_eq!(with([-2500, -5000, -500, -499]).measured, [len(1000)]);
    assert!(with([-2500, -5000, -500, -500]).is_empty());
    assert!(run(&layout(&[LINE, BAR]), rule, Vec::new()).0.is_empty());
}

/// Oracle: LEF 5.8 Figure 1-19, `TWOEDGES`. One neighbour beside the line
/// is not enough; one on each side is.
#[test]
fn two_edges_needs_a_parallel_edge_on_both_sides() {
    let rule = lef_eol(Some(parallel_edge(true)), None);
    let left = [-2500, -5000, -500, 0];
    let right = [1500, -5000, 3500, 0];

    assert!(run(&layout(&[LINE, BAR, left]), rule, Vec::new())
        .0
        .is_empty());
    let (out, _) = run(&layout(&[LINE, BAR, left, right]), rule, Vec::new());
    assert_eq!(out.measured, [len(1000)]);
}

/// Oracle: `LEF58_SPACING ENDOFLINE ... ENDTOEND`, construct-from-answer.
/// Two ends of line 1399 apart need the end-to-end 1400; an end 1300 below
/// a wide bar (no end) needs only 1200.
#[test]
fn two_ends_facing_each_other_need_the_end_to_end_space() {
    let rule = lef_eol(None, Some(1400));
    let (out, _) = run(&layout(&[LINE, [0, 1399, 1000, 6399]]), rule, Vec::new());
    assert_eq!(out.measured, [len(1399)]);
    assert_eq!(out.limit, [len(1400)]);

    assert!(run(
        &layout(&[LINE, [-2000, 1300, 3000, 2300]]),
        rule,
        Vec::new()
    )
    .0
    .is_empty());
}

// -------------------------------------------------------------- eol_keep_out

/// `LEF58_EOLKEEPOUT 1.3 EXTENSION 0.2 0.3 1.0` in nanometres: the line's
/// end keeps out x = -300..1300, y = -200..1000.
const KEEP_OUT: Rule = Rule::EolKeepOut {
    layer: A,
    eol_width: Dbu::new_unchecked(1300),
    backward: Dbu::new_unchecked(200),
    side: Dbu::new_unchecked(300),
    forward: Dbu::new_unchecked(1000),
};

fn area(v: i128) -> Measurement {
    Measurement::Area(DbuArea::new(v))
}

/// Oracle: construct-from-answer, the box as `TritonRoute`'s
/// `getEolKeepOutQueryBox` builds it. A bar whose bottom is 999 past the
/// end overlaps the box by 1600 x 1, marked at the centre of that strip,
/// (500, 999) floored; at 1000 it only touches the box. The line's two ends
/// and the bar's two 500 long sides are the ends examined.
#[test]
fn a_shape_one_unit_inside_the_far_side_of_the_box_is_reported_by_area() {
    let (out, runs) = run(
        &layout(&[LINE, [-2000, 999, 3000, 1499]]),
        KEEP_OUT,
        Vec::new(),
    );
    assert_eq!(out.measured, [area(1600)]);
    assert_eq!(out.limit, [area(0)]);
    assert_eq!(out.at, [point(500, 999)]);
    assert_eq!(assert_rule_ran(&runs, RULE).examined, 4);

    let (out, _) = run(
        &layout(&[LINE, [-2000, 1000, 3000, 1500]]),
        KEEP_OUT,
        Vec::new(),
    );
    assert!(out.is_empty(), "touching the box is not inside it");
}

/// Oracle: construct-from-answer at the box's side and back. A block 299
/// past the end's side overlaps it by 1 x 500, at 300 it touches; a block
/// beside the line whose top is 199 behind the end overlaps by 200 x 1, at
/// 200 behind it touches.
#[test]
fn the_box_reaches_side_past_the_end_and_backward_behind_it() {
    let inside = |block: [i64; 4]| run(&layout(&[LINE, block]), KEEP_OUT, Vec::new()).0;

    assert_eq!(inside([1299, 500, 3299, 2500]).measured, [area(500)]);
    assert!(inside([1300, 500, 3300, 2500]).is_empty());
    assert_eq!(inside([1100, -2199, 3100, -199]).measured, [area(200)]);
    assert!(inside([1100, -2200, 3100, -200]).is_empty());
}

/// Oracle: construct-from-answer. One finding per intruding figure: two
/// blocks are two (500 x 700 and 600 x 700), a bar drawn as two rectangles
/// is one with the summed 1600 x 500, and the line's own figure turning
/// back into the box is none.
#[test]
fn each_intruding_figure_is_one_finding() {
    let (out, _) = run(
        &layout(&[LINE, [-2000, 300, 200, 1800], [700, 300, 2500, 1800]]),
        KEEP_OUT,
        Vec::new(),
    );
    let mut areas = out.measured.clone();
    areas.sort_by_key(|m| match m {
        Measurement::Area(a) => a.raw(),
        _ => 0,
    });
    assert_eq!(areas, [area(350_000), area(420_000)]);

    let (out, _) = run(
        &layout(&[LINE, [-2000, 500, 500, 1500], [500, 500, 3000, 1500]]),
        KEEP_OUT,
        Vec::new(),
    );
    assert_eq!(out.measured, [area(800_000)]);

    let (out, _) = run(
        &layout(&[
            LINE,
            [0, -6000, 3000, -5000],
            [2000, -6000, 3000, 1100],
            [-500, 600, 3000, 1100],
        ]),
        KEEP_OUT,
        Vec::new(),
    );
    assert!(out.is_empty());
}

// --------------------------------------------------- two_width_spacing_table

/// LEF/DEF 5.8's two-width table ("Two-Width Spacing Tables") in
/// nanometres: widths 0, 250, 1500 and 3000 with runs none, 0, 1500, 3000.
fn lef_two_widths() -> Vec<ClassTable> {
    vec![ClassTable {
        class: [0, 250, 1500, 3000].into_iter().map(dbu).collect(),
        prl: vec![None, Some(dbu(0)), Some(dbu(1500)), Some(dbu(3000))],
        space: [
            150, 200, 500, 1000, 200, 250, 500, 1000, 500, 500, 600, 1000, 1000, 1000, 1000, 1200,
        ]
        .into_iter()
        .map(dbu)
        .collect(),
    }]
}

const TWO_WIDTHS: Rule = Rule::TwoWidthSpacingTable { layer: A, table: 0 };

/// Lines `wa` and `wb` wide, `gap` apart, running alongside for `run`.
fn lines(wa: i64, wb: i64, gap: i64, run: i64) -> GeometryStore {
    layout(&[
        [0, 0, wa, 2000],
        [wa + gap, 2000 - run, wa + gap + wb, 4000 - run],
    ])
}

/// Oracle: LEF 5.8's worked example, verbatim: "If width1 = 0.25, width2 =
/// 0.25, and prl = 0.0, then spacing = 0.15. If width1 = 0.25, width2 =
/// 0.26, and prl = 0.0, then spacing = 0.15. If width1 = 0.25, width2 =
/// 0.26, and prl = 0.1, then spacing = 0.20. If width1 = 0.26, width2 =
/// 0.26, and prl = 0.1, then spacing = 0.25." Each pair one unit under its
/// space reports that space as its limit.
#[test]
fn lef_s_worked_example_picks_each_cell() {
    for (wa, wb, overlap, space) in [
        (250, 250, 0, 150),
        (250, 260, 0, 150),
        (250, 260, 100, 200),
        (260, 260, 100, 250),
    ] {
        let (out, runs) = run(
            &lines(wa, wb, space - 1, overlap),
            TWO_WIDTHS,
            lef_two_widths(),
        );
        assert_eq!(out.measured, [len(space - 1)], "{wa} {wb} {overlap}");
        assert_eq!(out.limit, [len(space)], "{wa} {wb} {overlap}");
        assert_eq!(assert_rule_ran(&runs, RULE).examined, 1);

        let (out, _) = run(&lines(wa, wb, space, overlap), TWO_WIDTHS, lef_two_widths());
        assert!(out.is_empty(), "{wa} {wb} {overlap} at its space");
    }
}

/// Oracle: construct-from-answer. Two 1600 wide plates 550 apart need 600
/// only when they run alongside for more than the 1500 width's run: at 1500
/// they are held to 250 and pass; at 1501 they fail 600, marked in the
/// middle of the 1501 run.
#[test]
fn a_width_s_run_must_be_exceeded() {
    let plates = |r: i64| layout(&[[0, 0, 1600, 3000], [2150, 3000 - r, 3750, 6000 - r]]);
    let (out, _) = run(&plates(1500), TWO_WIDTHS, lef_two_widths());
    assert!(out.is_empty());

    let (out, _) = run(&plates(1501), TWO_WIDTHS, lef_two_widths());
    assert_eq!(out.measured, [len(550)]);
    assert_eq!(out.limit, [len(600)]);
    assert_eq!(out.at, [point(1875, 2249)]);
}

/// Oracle: construct-from-answer. A 260 wide line 220 from the 100 wide tab
/// of a 2 µm plate: the tab is not wider than 250, the plate is 500 away,
/// so every cell passes (a whole-shape width would hold the tab to 250).
/// Both rows of the plate's figure pair with the line.
#[test]
fn a_thin_tab_of_a_wide_plate_is_held_as_thin() {
    let store = layout(&[
        [0, 0, 2000, 2000],
        [900, 2000, 1000, 3000],
        [1220, 2500, 1480, 4000],
    ]);
    let (out, runs) = run(&store, TWO_WIDTHS, lef_two_widths());

    assert!(out.is_empty());
    assert_eq!(assert_rule_ran(&runs, RULE).examined, 2);
}

// ---------------------------------------------------------------- span_length

/// LEF 5.8's METAL2 span tables: horizontal spans 60, 80, 120, 160 or at
/// least 200; vertical spans 120, 160 or at least 200.
fn lef_spans() -> Rule {
    Rule::SpanLength { layer: A, table: 0 }
}

fn run_spans(store: &GeometryStore) -> (Violations, Vec<RuleRun>) {
    let set = RuleSet {
        rules: vec![(RULE, lef_spans())],
        span_tables: vec![SpanTable {
            x: [60, 80, 120, 160, 200].into_iter().map(dbu).collect(),
            y: [120, 160, 200].into_iter().map(dbu).collect(),
            x_except: None,
            y_except: None,
        }],
        ..RuleSet::default()
    };
    let (mut out, mut runs) = (Violations::default(), Vec::new());
    set.run(store, &mut out, &mut runs);
    (out, runs)
}

/// Oracle: `LEF58_SPANLENGTHTABLE`, "all of the given span lengths are exact
/// values, except for the last one, which is greater than equal to the
/// value". A vertical wire 61 wide is between 60 and 80 and reports 80 as
/// the shortest legal span above it, at the wire's centre; 59 reports 60;
/// 60 and 201 are legal.
#[test]
fn a_span_is_legal_exactly_on_the_list_or_past_its_last() {
    let wire = |w: i64| layout(&[[0, 0, w, 1000]]);
    let (out, runs) = run_spans(&wire(61));
    assert_eq!(out.measured, [len(61)]);
    assert_eq!(out.limit, [len(80)]);
    assert_eq!(out.at, [point(30, 500)]);
    assert_eq!(
        assert_rule_ran(&runs, RULE).examined,
        2,
        "one chord each way"
    );

    assert_eq!(run_spans(&wire(59)).0.limit, [len(60)]);
    assert!(run_spans(&wire(60)).0.is_empty());
    assert!(run_spans(&wire(201)).0.is_empty());
}

/// Oracle: construct-from-answer. A U whose right arm steps from 100 to 150
/// wide: the left arm's 100 is one region from y = 100 to 1000 though the
/// step splits the lines at y = 500, and the base's 100 one region from
/// x = 100 to 900 though the step splits it at x = 850. Four findings over
/// the eight regions of unchanged chord.
#[test]
fn a_chord_that_stays_the_same_is_one_region() {
    let store = layout(&[
        [0, 0, 1000, 100],
        [0, 0, 100, 1000],
        [900, 0, 1000, 500],
        [850, 500, 1000, 1000],
    ]);
    let (out, runs) = run_spans(&store);

    let mut found: Vec<_> = out
        .at
        .iter()
        .zip(&out.measured)
        .map(|(at, measured)| (at.x.raw(), at.y.raw(), *measured))
        .collect();
    found.sort_by_key(|&(x, y, _)| (x, y));
    assert_eq!(
        found,
        [
            (50, 550, len(100)),
            (500, 50, len(100)),
            (925, 750, len(150)),
            (950, 300, len(100)),
        ]
    );
    assert_eq!(assert_rule_ran(&runs, RULE).examined, 8);
}

// ---------------------------------------------------- convex_corner_spacing

fn corners(corner_to_corner: bool, except_eol: Option<i64>) -> Rule {
    Rule::ConvexCornerSpacing {
        layer: A,
        corner_to_corner,
        except_eol: except_eol.map(dbu),
        limit: dbu(101),
    }
}

/// Oracle: `TritonRoute`'s `maxXY`, the longer side of the box between two
/// facing corners. Corners 100 apart on x and 50 on y are 100 apart by the
/// larger gap, under 101, marked midway (1050, 1025); Euclidean they are
/// 111.8 apart and clean. Two squares 71 apart on both axes are 71 by the
/// larger gap and 100.4, floored to 100, Euclidean.
#[test]
fn the_corner_distance_is_the_larger_axis_gap_or_euclidean() {
    let skewed = layout(&[[0, 0, 1000, 1000], [1100, 1050, 2100, 2050]]);
    let (out, runs) = run(&skewed, corners(false, None), Vec::new());
    assert_eq!(out.measured, [len(100)]);
    assert_eq!(out.limit, [len(101)]);
    assert_eq!(out.at, [point(1050, 1025)]);
    assert_eq!(assert_rule_ran(&runs, RULE).examined, 1);
    assert!(run(&skewed, corners(true, None), Vec::new()).0.is_empty());

    let diagonal = layout(&[[0, 0, 1000, 1000], [1071, 1071, 2071, 2071]]);
    assert_eq!(
        run(&diagonal, corners(false, None), Vec::new()).0.measured,
        [len(71)]
    );
    assert_eq!(
        run(&diagonal, corners(true, None), Vec::new()).0.measured,
        [len(100)]
    );
}

/// Oracle: `LEF58_CORNERSPACING ... EXCEPTEOL eolWidth`, as `TritonRoute`
/// skips a corner on an edge shorter than `eolWidth` whose corners are both
/// convex, on either shape. A 100 wide line end's corner 50 from a square's
/// is exempt with `except_eol: 200`, whichever shape the line is; two
/// squares' corners are not, and neither is the line's without the
/// exception.
#[test]
fn an_end_of_line_s_corners_are_exempt_on_either_shape() {
    let line_first = layout(&[[0, 0, 100, 1000], [150, 1050, 1150, 2050]]);
    let line_second = layout(&[[0, 0, 1000, 1000], [1050, 1050, 1150, 2050]]);
    let squares = layout(&[[0, 0, 1000, 1000], [1050, 1050, 2050, 2050]]);
    let with = corners(false, Some(200));

    let (out, runs) = run(&line_first, with, Vec::new());
    assert!(out.is_empty());
    assert_eq!(only(&runs).examined, 0);
    assert!(run(&line_second, with, Vec::new()).0.is_empty());
    assert_eq!(run(&squares, with, Vec::new()).0.measured, [len(50)]);
    assert_eq!(
        run(&line_first, corners(false, None), Vec::new())
            .0
            .measured,
        [len(50)]
    );
}

// ---------------------------------------------------------------- exact_pitch

/// ASAP7 FIN.S.1, "Exact vertical FIN pitch", 27 nm.
const FIN_PITCH: Rule = Rule::ExactPitch {
    layer: A,
    vertical: true,
    pitch: Dbu::new_unchecked(27),
};

/// Three 7 nm fins `p` apart.
fn fins(p: i64) -> GeometryStore {
    layout(&[
        [0, 0, 1000, 7],
        [0, p, 1000, p + 7],
        [0, 2 * p, 1000, 2 * p + 7],
    ])
}

/// Oracle: ASAP7 FIN.S.1, construct-from-answer for the markers. Fins 26
/// apart are off the 27 pitch twice, each pair marked in the middle of its
/// gap; at 27 they are clean. Both neighbouring pairs are examined either way.
#[test]
fn neighbouring_fins_off_the_pitch_are_reported_once_per_pair() {
    let (out, runs) = run(&fins(26), FIN_PITCH, Vec::new());
    assert_eq!(out.measured, [len(26), len(26)]);
    assert_eq!(out.limit, [len(27), len(27)]);
    let mut at = out.at.clone();
    at.sort_by_key(|p| p.y);
    assert_eq!(at, [point(500, 16), point(500, 42)]);
    assert_eq!(assert_rule_ran(&runs, RULE).examined, 2);

    let (out, runs) = run(&fins(27), FIN_PITCH, Vec::new());
    assert!(out.is_empty());
    assert_eq!(assert_rule_ran(&runs, RULE).examined, 2);
}

/// Oracle: construct-from-answer. A missing fin leaves its neighbours 54
/// apart, a violation; a fin that does not overlap another across is no
/// neighbour of it; a bent shape refuses the rule.
#[test]
fn a_missing_fin_is_a_double_pitch_and_a_bent_one_refuses() {
    let missing = layout(&[[0, 0, 1000, 7], [0, 27, 1000, 34], [0, 81, 1000, 88]]);
    assert_eq!(run(&missing, FIN_PITCH, Vec::new()).0.measured, [len(54)]);

    let apart = layout(&[[0, 0, 1000, 7], [2000, 30, 3000, 37]]);
    let (out, runs) = run(&apart, FIN_PITCH, Vec::new());
    assert!(out.is_empty());
    assert_eq!(only(&runs).examined, 0);

    let mut builder = LayoutBuilder::new(1);
    builder.push(A, &[0, 1000, 1000, 7, 7, 0], &[0, 0, 7, 7, 500, 500]);
    let (bent, _) = builder.finish();
    assert_eq!(
        only(&run(&bent, FIN_PITCH, Vec::new()).1).outcome,
        Outcome::Refused
    );
}

// ---------------------------------------------------------------- the deck

/// Oracle: construct-from-answer, the deck language (`docs/deck.md`). Each
/// new kind's deck row builds exactly the rule its parameters spell, with
/// optional parameters given and left out.
#[test]
fn the_deck_spells_each_kind_s_parameters() {
    let text = "grid 1nm\nlayer met1 = gds(68, 20)\n\
        rule e eol_space(met1; eol_width: 1300nm, within: 600nm, \
        parallel: (space: 1100nm, within: 500nm, two_edges: true), end_to_end: 1400nm) >= 1200nm\n\
        rule p eol_space(met1; eol_width: 1300nm, within: 0nm, parallel: none, end_to_end: none) >= 1200nm\n\
        rule k eol_keep_out(met1; eol_width: 1300nm, backward: 0nm, side: 300nm, forward: 1000nm)\n\
        rule f forbidden_space(met1; min: 100nm, max: 150nm, prl: 0nm)\n\
        rule s span_length(met1; x: [60nm, 200nm], y: [120nm])\n";
    let mut strings = StrTable::default();
    let deck =
        parse_deck(text, Grid::new(1000).expect("a 1 nm grid"), &mut strings).expect("parses");
    let set = RuleSet::from_deck(&deck, &strings).expect("builds");

    let rules: Vec<Rule> = set.rules.iter().map(|&(_, rule)| rule).collect();
    assert_eq!(
        rules,
        [
            Rule::EolWithinSpacing {
                layer: A,
                eol_width: dbu(1300),
                within: dbu(600),
                parallel: Some(parallel_edge(true)),
                end_to_end: Some(dbu(1400)),
                limit: dbu(1200),
            },
            Rule::EolWithinSpacing {
                layer: A,
                eol_width: dbu(1300),
                within: dbu(0),
                parallel: None,
                end_to_end: None,
                limit: dbu(1200),
            },
            Rule::EolKeepOut {
                layer: A,
                eol_width: dbu(1300),
                backward: dbu(0),
                side: dbu(300),
                forward: dbu(1000),
            },
            Rule::ForbiddenSpacing {
                layer: A,
                min: dbu(100),
                max: dbu(150),
                prl: dbu(0),
            },
            lef_spans(),
        ]
    );
    assert_eq!(
        set.span_tables,
        [SpanTable {
            x: vec![dbu(60), dbu(200)],
            y: vec![dbu(120)],
            x_except: None,
            y_except: None,
        }]
    );
}

/// Oracle: the kinds' contracts. A tip table that is not symmetric, a
/// forbidden range that ends before it starts, a two-width table whose first
/// width states a run, and a span list that does not rise are each refused
/// when the rules are built, never run.
#[test]
fn malformed_tables_and_ranges_are_refused_at_load() {
    for rule in [
        "tip_space_table(met1; length: [0nm, 24nm], space: [[31nm, 25nm], [27nm, 18nm]])",
        "forbidden_space(met1; min: 150nm, max: 100nm, prl: 0nm)",
        "two_width_table(met1; width: [0nm, 250nm], prl: [0nm, 0nm], \
         space: [[150nm, 200nm], [200nm, 250nm]])",
        "span_length(met1; x: [120nm, 120nm], y: [60nm])",
    ] {
        let mut strings = StrTable::default();
        let text = format!("grid 1nm\nlayer met1 = gds(68, 20)\nrule t {rule}\n");
        let deck =
            parse_deck(&text, Grid::new(1000).expect("a 1 nm grid"), &mut strings).expect("parses");
        assert_eq!(
            RuleSet::from_deck(&deck, &strings).unwrap_err(),
            DrcError::BadTable("t".into()),
            "{rule}"
        );
    }
}

/// Oracle: the kinds' contract. Every new kind refuses a layer it cannot
/// represent exactly (a triangle), and never reads it as clean.
#[test]
fn every_new_kind_refuses_a_layer_that_does_not_validate() {
    let mut builder = LayoutBuilder::new(1);
    builder.push(A, &[0, 100, 0], &[0, 0, 100]);
    let (store, _) = builder.finish();
    let set = RuleSet {
        rules: [
            TIPS,
            Rule::TwoWidthSpacingTable { layer: A, table: 1 },
            forbidden(),
            lef_eol(Some(parallel_edge(false)), Some(1400)),
            KEEP_OUT,
            lef_spans(),
            corners(false, Some(200)),
            FIN_PITCH,
        ]
        .into_iter()
        .map(|rule| (RULE, rule))
        .collect(),
        class_tables: asap7_m1().into_iter().chain(lef_two_widths()).collect(),
        span_tables: vec![SpanTable {
            x: vec![dbu(60)],
            y: vec![dbu(60)],
            x_except: None,
            y_except: None,
        }],
        ..RuleSet::default()
    };
    let (mut out, mut runs) = (Violations::default(), Vec::new());
    set.run(&store, &mut out, &mut runs);

    assert!(out.is_empty());
    assert_eq!(runs.len(), 8);
    assert!(
        runs.iter().all(|run| run.outcome == Outcome::Refused),
        "{runs:?}"
    );
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
