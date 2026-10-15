//! `min_step` (LEF `MINSTEP`) and its `LEF58_MINSTEP` qualifiers (DRC-020),
//! from deck text, under the eight symmetries of the square. The cases are
//! the root suite's exhaustive fixtures (`tests/exhaustive/drc_dimension.rs`)
//! at the crate level, with the same oracles.

use crate::common::deck::{check, count, deck, len, rect, Shape, Want};

/// One polygon on `met1`.
fn met1(points: &[(i64, i64)]) -> Vec<Shape> {
    vec![("met1", points.to_vec())]
}

const STEP: &str = "rule out min_step(met1; corner: outside, length_sum: none) >= 50nm\n\
     rule sum min_step(met1; corner: outside, length_sum: 80nm) >= 50nm\n\
     rule in min_step(met1; corner: inside, length_sum: none) >= 50nm\n\
     rule st min_step(met1; corner: step, length_sum: none) >= 50nm\n\
     rule e1 min_step(met1; max_edges: 1) >= 50nm\n\
     rule e2 min_step(met1; max_edges: 2) >= 50nm";

const STEP_IDS: [&str; 6] = ["out", "sum", "in", "st", "e1", "e2"];

/// A 1000 square whose top right corner is a staircase of two edges `s`.
fn outside_two(s: i64) -> Vec<(i64, i64)> {
    vec![
        (0, 0),
        (1000, 0),
        (1000, 1000 - s),
        (1000 - s, 1000 - s),
        (1000 - s, 1000),
        (0, 1000),
    ]
}

/// Oracle: LEF 5.8 Figure 1-14 a and Example 1-16, swept one unit either
/// side of the 50 nm minStepLength. Two edges `s` under 50 at an outside
/// corner are one run of two short edges: `corner: outside` rejects it
/// (measuring 2 edges), `LENGTHSUM 0.08` only when `2s > 80`, `MAXEDGES 1`
/// (two is more than one) but not `MAXEDGES 2`; no inside corner or step.
/// The marker is the centre of the run's vertices, `(1000 - s/2, 1000 -
/// s/2)`. At and above 50 both edges are long and nothing is reported.
#[test]
fn an_outside_staircase_is_one_run_judged_by_count_and_by_length_sum() {
    let deck = deck(STEP);
    for s in [39, 40, 41, 49, 50, 51] {
        let mut want = Vec::new();
        if s < 50 {
            let at = |w: Want| w.at2(2000 - s, 2000 - s);
            want.push(at(count("out", 2)));
            want.push(at(count("e1", 2)));
            if 2 * s > 80 {
                want.push(at(len("sum", 2 * s)));
            }
        }
        check(
            &format!("outside_two/{s}"),
            &deck,
            &met1(&outside_two(s)),
            &STEP_IDS,
            &want,
        );
    }
}

/// Oracle: LEF 5.8 Figure 1-14 d: four 40 nm edges (160 in all) at an
/// outside corner. Every outside row rejects the run of four, `LENGTHSUM
/// 0.08` too (160 > 80, measuring 160), and both `MAXEDGES` rows (four is
/// more than one and than two); the marker is the centre of the staircase's
/// vertices, (960, 960).
#[test]
fn lef_figure_d_four_short_edges_break_every_outside_row() {
    let shape = met1(&[
        (0, 0),
        (1000, 0),
        (1000, 920),
        (960, 920),
        (960, 960),
        (920, 960),
        (920, 1000),
        (0, 1000),
    ]);
    let want = [
        count("out", 4).at(960, 960),
        len("sum", 160).at(960, 960),
        count("e1", 4).at(960, 960),
        count("e2", 4).at(960, 960),
    ];
    check("lef_figure_d", &deck(STEP), &shape, &STEP_IDS, &want);
}

/// Oracle: by construction. Two 40 nm edges where the long edges either side
/// turn right (an inside corner, the notch of an L): only `corner: inside`
/// and `MAXEDGES 1` reject the run of two, at (520, 520).
#[test]
fn an_inside_staircase_breaks_only_the_inside_row() {
    let shape = met1(&[
        (0, 0),
        (1000, 0),
        (1000, 500),
        (540, 500),
        (540, 540),
        (500, 540),
        (500, 1000),
        (0, 1000),
    ]);
    let want = [count("in", 2).at(520, 520), count("e1", 2).at(520, 520)];
    check("inside_two", &deck(STEP), &shape, &STEP_IDS, &want);
}

/// Oracle: by construction. One 40 nm jog between two long edges running the
/// same way is a step: only `corner: step` rejects it, a run of one edge,
/// at the jog's middle (500, 520). One short edge is not more than one, so
/// neither `MAXEDGES` row fires.
#[test]
fn a_single_jog_is_a_step_and_nothing_else() {
    let shape = met1(&[
        (0, 0),
        (1000, 0),
        (1000, 500),
        (500, 500),
        (500, 540),
        (0, 540),
    ]);
    check(
        "step",
        &deck(STEP),
        &shape,
        &STEP_IDS,
        &[count("st", 1).at(500, 520)],
    );
}

/// Oracle: by construction. A 40 nm wide line's two short ends each sit
/// between long edges running opposite ways: no corner and no step, and one
/// short edge is within either `MAXEDGES`.
#[test]
fn a_narrow_line_end_is_no_corner_and_no_step() {
    check(
        "line_end",
        &deck(STEP),
        &[rect("met1", 0, 0, 1000, 40)],
        &STEP_IDS,
        &[],
    );
}

/// Oracle: by construction. A 40 x 30 rectangle has no edge of 50 or more,
/// so the whole ring is one run of four short edges with no long edge on
/// either side: no corner kind applies, and `MAXEDGES 1` and `2` both see
/// four, at the rectangle's centre.
#[test]
fn a_ring_of_only_short_edges_is_one_run_with_no_corner() {
    check(
        "all_short",
        &deck(STEP),
        &[rect("met1", 0, 0, 40, 30)],
        &STEP_IDS,
        &[count("e1", 4).at(20, 15), count("e2", 4).at(20, 15)],
    );
}

const ADJ: &str = "rule adj min_step(met1; adjacent: 60nm, except_rectangle: false) >= 50nm\n\
     rule adj.rect min_step(met1; adjacent: 60nm, except_rectangle: true) >= 50nm\n\
     rule eol min_step(met1; adjacent: 30nm, adjacent_eol: 120nm, except_rectangle: false) >= 50nm\n\
     rule between min_step(met1; between_eol: 120nm) >= 50nm";

const ADJ_IDS: [&str; 4] = ["adj", "adj.rect", "eol", "between"];

/// A bump `w` wide and `h` high on a 1000 x 200 bar, from x = l to r.
fn bump(w: i64, h: i64) -> (Vec<Shape>, i64, i64) {
    let l = 500 - w / 2;
    let r = l + w;
    let shape = met1(&[
        (0, 0),
        (1000, 0),
        (1000, 200),
        (r, 200),
        (r, 200 + h),
        (l, 200 + h),
        (l, 200),
        (0, 200),
    ]);
    (shape, l, r)
}

/// Oracle: `TritonRoute`'s `checkMetalShape_lef58MinStep_minAdjLength` and
/// `_noBetweenEol`, swept one unit either side of 60. A bump 40 high: each
/// 40 side offends `adj` while the top beside it is under 60, and `eol`
/// always (the top is an end of line under 120); side, top and side are one
/// `between` finding. Each side's box runs from the bar's corner to the top's
/// far end, 200 to 240 high.
#[test]
fn a_bump_s_short_sides_offend_adjacent_by_its_top_s_length() {
    for t in [59, 60, 61] {
        let (shape, l, r) = bump(t, 40);
        let sides = [
            len("adj", 40).at2(l + 1000, 440),
            len("adj", 40).at2(r, 440),
        ];
        let mut want = Vec::new();
        for rule in ["eol"].into_iter().chain(
            (t < 60)
                .then_some(["adj", "adj.rect"])
                .into_iter()
                .flatten(),
        ) {
            want.extend(sides.iter().map(|w| Want { rule, ..*w }));
        }
        want.push(len("between", 40).at2(l + r, 440));
        check(
            &format!("bump_top/{t}"),
            &deck(ADJ),
            &shape,
            &ADJ_IDS,
            &want,
        );
    }
}

/// Oracle: the same checker, a bump 40 wide with its height swept around 50.
/// Its 40 top offends `adj` beside sides under 60; below 50 the sides are
/// short too and offend `adj`, `eol` (beside the top's end of line) and
/// make one `between` row.
#[test]
fn a_bump_s_top_offends_adjacent_and_its_sides_join_below_the_limit() {
    for h in [49, 50, 51] {
        let (shape, l, r) = bump(40, h);
        let mut want = Vec::new();
        for rule in ["adj", "adj.rect"] {
            want.push(len(rule, 40).at2(l + r, 400 + h));
            if h < 50 {
                want.push(len(rule, h).at2(l + 1000, 400 + h));
                want.push(len(rule, h).at2(r, 400 + h));
            }
        }
        if h < 50 {
            want.push(len("eol", h).at2(l + 1000, 400 + h));
            want.push(len("eol", h).at2(r, 400 + h));
            want.push(len("between", h).at2(l + r, 400 + h));
        }
        check(
            &format!("bump_height/{h}"),
            &deck(ADJ),
            &shape,
            &ADJ_IDS,
            &want,
        );
    }
}

/// Oracle: the same checker and LEF's `EXCEPTRECTANGLE`. A 40 x 56
/// rectangle: its 40 ends offend `adj` beside 56 sides and `eol` beside the
/// sides' ends of line, `EXCEPTRECTANGLE` exempts it, and each end starts a
/// `between` row; every box is the whole rectangle, centred at (20, 28).
#[test]
fn a_small_rectangle_offends_unless_rectangles_are_excepted() {
    let ends = |rule| [len(rule, 40).at(20, 28), len(rule, 40).at(20, 28)];
    let want: Vec<Want> = ["adj", "eol", "between"]
        .into_iter()
        .flat_map(ends)
        .collect();
    check(
        "rectangle",
        &deck(ADJ),
        &[rect("met1", 0, 0, 40, 56)],
        &ADJ_IDS,
        &want,
    );
}

/// Oracle: the same checker, a tab 40 wide on a bar's end, its end of line
/// swept around 120: the tab's 40 top offends `eol` only while the end of
/// line beside it is under 120, at the centre of the two edges' box.
#[test]
fn a_tab_s_top_offends_adjacent_eol_by_the_end_of_line_beside_it() {
    for e in [119, 120, 121] {
        let shape = met1(&[
            (0, 0),
            (1040, 0),
            (1040, e),
            (1000, e),
            (1000, 200),
            (0, 200),
        ]);
        let want: Vec<Want> = if e < 120 {
            vec![len("eol", 40).at(1020, 100)]
        } else {
            Vec::new()
        };
        check(&format!("tab_end/{e}"), &deck(ADJ), &shape, &ADJ_IDS, &want);
    }
}

/// Oracle: the same checker, a tip 40 long on a bar's end, its end swept
/// around 120: under 120 its two 40 sides offend `eol` and make one
/// `between` row (side, end of line, side).
#[test]
fn a_tip_s_sides_offend_by_its_end_of_line() {
    for e in [119, 120, 121] {
        let shape = met1(&[
            (0, 0),
            (1000, 0),
            (1000, 100),
            (1040, 100),
            (1040, 100 + e),
            (1000, 100 + e),
            (1000, 400),
            (0, 400),
        ]);
        let want = if e < 120 {
            vec![
                len("eol", 40).at2(2040, 100 + e),
                len("eol", 40).at2(2040, 500),
                len("between", 40).at2(2040, 200 + e),
            ]
        } else {
            Vec::new()
        };
        check(&format!("tip/{e}"), &deck(ADJ), &shape, &ADJ_IDS, &want);
    }
}
