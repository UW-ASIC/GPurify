//! The one-layer spacing kinds through deck text: end of line (plain,
//! LEF `ENDOFLINE ... WITHIN`, keep-out), run length, corners, wide and
//! attached-wide spacing, net spacing, the spacing tables (width x run,
//! two widths, tips), forbidden spacing, span length and exact pitch. Each
//! case is the root `tests/exhaustive/drc_dimension.rs` or `drc_overlay.rs`
//! fixture of the same name, its oracle restated on the test, run through
//! this crate's deck compiler and rule set.

use crate::deck_fixture::{
    below, check_axes, check_everywhere, floor_sqrt, met1, new_deck, one_layer_deck, pin, ring,
    row, run, sweep, Finding, Layout,
};
use gpurify_check::report::Outcome;

/// Every `(gap, side)` of [`sweep`], the gap alone.
fn steps(limit: i64) -> [i64; 3] {
    sweep(limit).map(|(v, _)| v)
}

/// `eol_space(met1; eol_width: 200nm) >= 101nm` (DRC-029, DRC-031): an edge
/// strictly shorter than 200 is an end of line; its keep-out is its own
/// span pushed 101 straight out. One finding per pair of separate figures
/// with an edge in a keep-out, measuring the nearest approach, at its
/// midpoint.
///
/// Oracle: gaps and widths by construction: tip to tip and tip to side,
/// the gap swept; the line width swept around 200 at a gap of 50 (a
/// 200-wide end is no end of line); two lines side by side; a wide shape
/// just beside the keep-out (no sideways reach, though Euclidean 51 away);
/// a line end facing its own figure; a 300-wide end drawn as three strips
/// (no end); a line under a bar whose shared edge is no end; a hole's slot
/// whose end keeps out into the hole, 90 from an island (at (500, 1005)),
/// and the slot's end that would reach through the band if pushed the
/// wrong way. Holed figures are drawn as abutting rectangles that merge.
#[test]
fn eol_space_holds_each_line_end_keep_out() {
    let deck = one_layer_deck("rule eol eol_space(met1; eol_width: 200nm) >= 101nm");
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("eol", findings)]);
    };
    for g in steps(101) {
        let found = if g < 101 {
            vec![pin(Finding::length(g), 100, 4000 + g)]
        } else {
            Vec::new()
        };
        case(
            "tip_to_tip",
            met1(&[[0, 0, 100, 2000], [0, 2000 + g, 100, 4000 + g]]),
            found.clone(),
        );
        case(
            "tip_to_side",
            met1(&[[0, 0, 100, 2000], [-1000, 2000 + g, 1100, 2200 + g]]),
            found,
        );
    }
    for w in steps(200) {
        let found = if w < 200 {
            vec![pin(Finding::length(50), w, 4050)]
        } else {
            Vec::new()
        };
        case(
            "line_width",
            met1(&[[0, 0, w, 2000], [0, 2050, w, 4050]]),
            found,
        );
    }
    case(
        "side_by_side",
        met1(&[[0, 0, 100, 2000], [150, 0, 250, 2000]]),
        vec![],
    );
    case(
        "beside_the_keep_out",
        met1(&[[0, 0, 100, 2000], [110, 2050, 2000, 4000]]),
        vec![],
    );
    case(
        "facing_its_own_figure",
        met1(&[
            [0, 0, 100, 1000],
            [0, -500, 1000, 0],
            [900, -500, 1000, 1550],
            [0, 1050, 1000, 1550],
        ]),
        vec![],
    );
    case(
        "wide_end_drawn_as_strips",
        met1(&[
            [0, 0, 100, 2000],
            [100, 0, 200, 2000],
            [200, 0, 300, 2000],
            [0, 2050, 300, 4050],
        ]),
        vec![],
    );
    case(
        "shared_edge_is_no_end",
        met1(&[
            [0, 0, 100, 1000],
            [-500, 1000, 600, 1050],
            [-200, 1080, 300, 1500],
        ]),
        vec![],
    );
    case(
        "hole_end_of_line",
        met1(&[
            [-500, -500, 1500, 0],
            [-500, 0, 0, 1600],
            [1000, 0, 1500, 1600],
            [0, 1000, 450, 1600],
            [550, 1000, 1000, 1600],
            [450, 1050, 550, 1600],
            [100, 100, 900, 960],
        ]),
        vec![pin(Finding::length(90), 450 + 550, 1050 + 960)],
    );
    case(
        "hole_end_keeps_out_of_the_band",
        ring(
            Layout::default(),
            "met1",
            [0, 0, 200, 1000],
            [50, 50, 150, 950],
        )
        .rect("met1", -500, 1030, 700, 1500),
        vec![],
    );
}

/// LEF/DEF 5.8 Example 1-18 in nm, `SPACING 1.2 ENDOFLINE 1.3 WITHIN 0.6`,
/// with `parallel` and `end_to_end` as the deck writes them.
fn lef_eol(parallel: &str, end_to_end: &str) -> String {
    one_layer_deck(&format!(
        "rule e eol_space(met1; eol_width: 1300nm, within: 600nm, parallel: {parallel}, \
         end_to_end: {end_to_end}) >= 1200nm"
    ))
}

/// A 1000 wide line ending at y = 0: its top is an end of line facing up,
/// keeping out x in (-600, 1600), y from 0 up to 1200.
const LINE: [i64; 4] = [0, -5000, 1000, 0];

/// `eol_space(met1; eol_width: 1300nm, within: 600nm, ..) >= 1200nm`
/// (DRC-029), LEF's `SPACING ENDOFLINE`: a facing edge of another figure in
/// an end's keep-out (the end widened by `within` each side, out to the
/// limit) fails by its depth, at the middle of the stretch where it
/// overlaps the widened end.
///
/// Oracle: LEF Figures 1-23 and 1-24, every distance drawn: a 5000 wide
/// bar's depth swept around 1200; a 2000 square 300 above, its side swept
/// around 600 past the end ("less than"); an edge with a concave corner (no
/// end); an end facing its own figure. With `PARALLELEDGE 1.1 WITHIN 0.5`,
/// a bar 1000 above fails only with a neighbour beside the line, its
/// distance swept around 1100 and its top around 500 behind the end; none,
/// clean. With `TWOEDGES` one side is not enough and two are. With
/// `end_to_end: 1400nm`, two facing ends need 1400 (swept), an end facing
/// a side 1200.
#[test]
fn eol_within_space_reads_lef_endofline() {
    let plain = lef_eol("none", "none");
    let parallel = lef_eol("(space: 1100nm, within: 500nm, two_edges: false)", "none");
    let two_edges = lef_eol("(space: 1100nm, within: 500nm, two_edges: true)", "none");
    let ends = lef_eol("none", "1400nm");
    let case = |name: &str, deck: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(name, deck, &layout, &[("e", findings)]);
    };
    let bar_above = [-3000, 1000, 4000, 2000];
    let at_1000 = || vec![pin(Finding::length(1000), 1000, 1000)];
    for g in steps(1200) {
        let found = if g < 1200 {
            vec![pin(Finding::length(g), 1000, g)]
        } else {
            vec![]
        };
        case(
            "depth",
            &plain,
            met1(&[LINE, [-2000, g, 3000, g + 1000]]),
            found,
        );
    }
    for d in steps(600) {
        let found = if d < 600 {
            vec![pin(Finding::length(300), 2600 + d, 300)]
        } else {
            vec![]
        };
        case(
            "within",
            &plain,
            met1(&[LINE, [1000 + d, 300, 3000 + d, 2300]]),
            found,
        );
    }
    case(
        "concave_corner_is_no_end",
        &plain,
        met1(&[
            [-3000, -5000, 4000, -1000],
            [0, -1000, 1000, 0],
            [-3000, -900, -500, 3000],
        ]),
        vec![],
    );
    case(
        "facing_its_own_figure",
        &plain,
        met1(&[
            LINE,
            [0, -6000, 3000, -5000],
            [2000, -6000, 3000, 1000],
            [-2000, 1000, 3000, 2000],
        ]),
        vec![],
    );
    for p in steps(1100) {
        let found = if p < 1100 { at_1000() } else { vec![] };
        case(
            "parallel_space",
            &parallel,
            met1(&[LINE, bar_above, [-p - 2000, -5000, -p, 0]]),
            found,
        );
    }
    for t in steps(-500) {
        let found = if t > -500 { at_1000() } else { vec![] };
        case(
            "parallel_within",
            &parallel,
            met1(&[LINE, bar_above, [-2500, -5000, -500, t]]),
            found,
        );
    }
    case(
        "no_parallel_edge",
        &parallel,
        met1(&[LINE, bar_above]),
        vec![],
    );
    case(
        "two_edges/one_side",
        &two_edges,
        met1(&[LINE, bar_above, [-2500, -5000, -500, 0]]),
        vec![],
    );
    case(
        "two_edges/both_sides",
        &two_edges,
        met1(&[
            LINE,
            bar_above,
            [-2500, -5000, -500, 0],
            [1500, -5000, 3500, 0],
        ]),
        at_1000(),
    );
    for g in steps(1400) {
        let found = if g < 1400 {
            vec![pin(Finding::length(g), 1000, g)]
        } else {
            vec![]
        };
        case(
            "end_to_end",
            &ends,
            met1(&[LINE, [0, g, 1000, g + 5000]]),
            found,
        );
    }
    case(
        "end_to_side_keeps_the_limit",
        &ends,
        met1(&[LINE, [-2000, 1300, 3000, 2300]]),
        vec![],
    );
}

/// `eol_keep_out(met1; eol_width: 1300nm, backward: 200nm, side: 300nm,
/// forward: 1000nm)` (DRC-030), `LEF58_EOLKEEPOUT 1.3 EXTENSION 0.2 0.3
/// 1.0`: the line's end keeps out x = -300..1300, y = -200..1000; each
/// other figure overlapping that box with a positive area is one finding,
/// measuring the area inside, at the centre of its box.
///
/// Oracle: areas by hand: the box's far side swept with a bar's bottom
/// around y = 1000 (1600 x (1000 - g)), its side with a block's left side
/// around x = 1300 ((300 - d) x 500), its back with a block beside the line
/// whose top is swept around y = -200 (200 x (b + 200)); two figures
/// inside (350000 and 420000); a bar drawn as two rectangles (one figure,
/// 800000); the line's own figure turning back into the box (not an
/// intruder).
#[test]
fn eol_keep_out_measures_the_intruding_area() {
    let deck = one_layer_deck(
        "rule k eol_keep_out(met1; eol_width: 1300nm, backward: 200nm, side: 300nm, forward: 1000nm)",
    );
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("k", findings)]);
    };
    for g in steps(1000) {
        let found = if g < 1000 {
            vec![pin(
                Finding::area(i128::from(1600 * (1000 - g))),
                1000,
                g + 1000,
            )]
        } else {
            vec![]
        };
        case("forward", met1(&[LINE, [-2000, g, 3000, g + 500]]), found);
    }
    for d in steps(300) {
        let found = if d < 300 {
            vec![pin(
                Finding::area(i128::from((300 - d) * 500)),
                2300 + d,
                1500,
            )]
        } else {
            vec![]
        };
        case(
            "side",
            met1(&[LINE, [1000 + d, 500, 3000 + d, 2500]]),
            found,
        );
    }
    for b in steps(-200) {
        let found = if b > -200 {
            vec![pin(
                Finding::area(i128::from(200 * (b + 200))),
                2400,
                b - 200,
            )]
        } else {
            vec![]
        };
        case("backward", met1(&[LINE, [1100, b - 2000, 3100, b]]), found);
    }
    case(
        "two_figures",
        met1(&[LINE, [-2000, 300, 200, 1800], [700, 300, 2500, 1800]]),
        vec![
            pin(Finding::area(350_000), -100, 1300),
            pin(Finding::area(420_000), 2000, 1300),
        ],
    );
    case(
        "one_figure_drawn_twice",
        met1(&[LINE, [-2000, 500, 500, 1500], [500, 500, 3000, 1500]]),
        vec![pin(Finding::area(800_000), 1000, 1500)],
    );
    case(
        "own_figure_in_the_box",
        met1(&[
            LINE,
            [0, -6000, 3000, -5000],
            [2000, -6000, 3000, 1100],
            [-500, 600, 3000, 1100],
        ]),
        vec![],
    );
}

/// `prl_space(met1; prl: 500nm) >= 101nm` (DRC-026): pairs in different
/// figures whose facing edges at most 101 apart run alongside at least 500
/// are held to 101, at the midpoint of the nearest points.
///
/// Oracle: runs and gaps by construction: the run swept around 500 at a
/// gap of 100; the gap swept at a long run; an L whose box would overstate
/// the run (its facing edges run 100: clean); a diagonal pair; touching
/// shapes; a wire of four 500 segments beside another, held under a 600
/// threshold by its whole 2000 run, one finding per segment.
#[test]
fn prl_space_holds_pairs_that_run_far_enough() {
    let deck = one_layer_deck("rule prl prl_space(met1; prl: 500nm) >= 101nm");
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("prl", findings)]);
    };
    for r in steps(500) {
        let found = if r >= 500 {
            vec![pin(Finding::length(100), 300, 4000 - r)]
        } else {
            vec![]
        };
        case(
            "run",
            met1(&[[0, 0, 100, 2000], [200, 2000 - r, 300, 4000 - r]]),
            found,
        );
    }
    for g in steps(101) {
        let found = if g < 101 {
            vec![pin(Finding::length(g), 200 + g, 2000)]
        } else {
            vec![]
        };
        case(
            "gap",
            met1(&[[0, 0, 100, 2000], [100 + g, 0, 200 + g, 2000]]),
            found,
        );
    }
    case(
        "l_box_overstates_run",
        Layout::default()
            .polygon(
                "met1",
                &[
                    (0, 0),
                    (2000, 0),
                    (2000, 100),
                    (100, 100),
                    (100, 2000),
                    (0, 2000),
                ],
            )
            .rect("met1", 200, 1900, 1500, 2000),
        vec![],
    );
    case(
        "diagonal",
        met1(&[[0, 0, 1000, 1000], [1050, 1050, 2050, 2050]]),
        vec![],
    );
    case(
        "touching",
        met1(&[[0, 0, 100, 2000], [100, 0, 200, 2000]]),
        vec![],
    );
    check_everywhere(
        "segmented_run",
        &one_layer_deck("rule prl prl_space(met1; prl: 600nm) >= 101nm"),
        &met1(&[
            [0, 0, 100, 2000],
            [200, 0, 300, 500],
            [200, 500, 300, 1000],
            [200, 1000, 300, 1500],
            [200, 1500, 300, 2000],
        ]),
        &[(
            "prl",
            vec![
                Finding::length(100).at(150, 250),
                Finding::length(100).at(150, 750),
                Finding::length(100).at(150, 1250),
                Finding::length(100).at(150, 1750),
            ],
        )],
    );
}

/// Two 1000 squares `d` apart on both axes, and what a Euclidean minimum
/// of 101 finds: the floored gap `floor(d√2)`, midway between the corners.
fn diagonal_pair(d: i64) -> (Layout, Vec<Finding>) {
    let layout = met1(&[[0, 0, 1000, 1000], [1000 + d, 1000 + d, 2000 + d, 2000 + d]]);
    let gap2 = 2 * d * d;
    let found = if gap2 < 101 * 101 {
        vec![pin(Finding::length(floor_sqrt(gap2)), 2000 + d, 2000 + d)]
    } else {
        Vec::new()
    };
    (layout, found)
}

/// `corner_space(met1) >= 101nm` (DRC-032): pairs in different figures with
/// convex corners facing each other (each beyond the other on both axes),
/// Euclidean between the nearest such corners, midway between them.
///
/// Oracle: the diagonal swept over 70, 71, 72 (98.99, 100.4, 101.8); a pair
/// 50 apart on x and 1 on y (50.01, reported 50); no gap on one axis
/// (`min_spacing`'s); side by side; two squares corner to corner but one
/// figure; an L whose arm's corner (1000, 100) faces a square's (1050,
/// 150): √5000, 70; a hook whose inner corner (1060, 1060) faces the
/// square's (1000, 1000): √7200, 84; a square's corner that a bar on top
/// turns into a stretch of edge (no corner).
#[test]
fn corner_space_measures_facing_convex_corners() {
    let deck = one_layer_deck("rule cc corner_space(met1) >= 101nm");
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("cc", findings)]);
    };
    for d in [70, 71, 72] {
        let (layout, found) = diagonal_pair(d);
        case("diagonal", layout, found);
    }
    case(
        "skew",
        met1(&[[0, 0, 1000, 1000], [1050, 1001, 2050, 2001]]),
        vec![Finding::length(50)],
    );
    case(
        "no_gap_on_one_axis",
        met1(&[[0, 0, 1000, 1000], [1050, 1000, 2050, 2000]]),
        vec![],
    );
    case(
        "side_by_side",
        met1(&[[0, 0, 1000, 1000], [1050, 0, 2050, 1000]]),
        vec![],
    );
    case(
        "one_figure",
        met1(&[
            [0, 0, 1000, 1000],
            [1050, 1050, 2050, 2050],
            [-500, 0, 0, 3500],
            [-500, 3000, 2050, 3500],
            [1050, 2050, 2050, 3000],
        ]),
        vec![],
    );
    case(
        "l_corner_inside_its_box",
        Layout::default()
            .polygon(
                "met1",
                &[
                    (0, 0),
                    (1000, 0),
                    (1000, 100),
                    (100, 100),
                    (100, 1000),
                    (0, 1000),
                ],
            )
            .rect("met1", 1050, 150, 1150, 250),
        vec![pin(Finding::length(70), 1000 + 1050, 100 + 150)],
    );
    case(
        "corner_beside_an_edge_gap",
        Layout::default().rect("met1", 0, 0, 1000, 1000).polygon(
            "met1",
            &[
                (1050, -500),
                (1600, -500),
                (1600, 1500),
                (1060, 1500),
                (1060, 1060),
                (1500, 1060),
                (1500, 500),
                (1050, 500),
            ],
        ),
        vec![pin(Finding::length(84), 1000 + 1060, 1000 + 1060)],
    );
    case(
        "row_corner_inside_a_figure_edge",
        met1(&[
            [0, 0, 1000, 1000],
            [0, 1000, 1000, 1010],
            [1050, 1005, 2050, 2005],
        ]),
        vec![],
    );
}

/// `corner_space(met1; corner_to_corner: .., except_eol: ..) >= 101nm`.
fn corner_deck(corner_to_corner: bool, except_eol: &str) -> String {
    one_layer_deck(&format!(
        "rule c corner_space(met1; corner_to_corner: {corner_to_corner}, except_eol: {except_eol}) \
         >= 101nm"
    ))
}

/// `corner_space(met1; corner_to_corner: .., except_eol: ..) >= 101nm`
/// (DRC-032), `LEF58_CORNERSPACING CONVEXCORNER`: facing convex corners of
/// different figures measured by the larger axis gap (`TritonRoute`'s
/// `maxXY`), or Euclidean with `corner_to_corner`, midway between the
/// nearest corners.
///
/// Oracle: diagonal pairs `d` apart on both axes: the larger gap is `d`,
/// the Euclidean one `d√2`. A pair 50 apart on y with the x gap swept
/// around 101: the larger gap is the x gap; Euclidean, 111.8 at 100, clean.
/// Side by side; one figure. With `except_eol: 200nm`, a 100 wide line
/// end's corners are exempt on either shape, two wide squares' are not.
#[test]
fn convex_corner_space_reads_the_larger_axis_gap() {
    let square = corner_deck(false, "none");
    let euclid = corner_deck(true, "none");
    let eol = corner_deck(false, "200nm");
    let case = |name: &str, deck: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(name, deck, &layout, &[("c", findings)]);
    };
    for d in [70, 71, 72, 100, 101] {
        let (layout, euclidean) = diagonal_pair(d);
        let larger = if d < 101 {
            vec![pin(Finding::length(d), 2000 + d, 2000 + d)]
        } else {
            vec![]
        };
        case("diagonal/square", &square, layout.clone(), larger);
        case("diagonal/euclidean", &euclid, layout, euclidean);
    }
    for d in steps(101) {
        let found = if d < 101 {
            vec![pin(Finding::length(d), 2000 + d, 2050)]
        } else {
            vec![]
        };
        case(
            "skewed",
            &square,
            met1(&[[0, 0, 1000, 1000], [1000 + d, 1050, 2000 + d, 2050]]),
            found,
        );
    }
    case(
        "skewed_euclidean",
        &euclid,
        met1(&[[0, 0, 1000, 1000], [1100, 1050, 2100, 2050]]),
        vec![],
    );
    case(
        "side_by_side",
        &square,
        met1(&[[0, 0, 1000, 1000], [1050, 0, 2050, 1000]]),
        vec![],
    );
    case(
        "one_figure",
        &square,
        met1(&[[0, 0, 1000, 1000], [1000, 1000, 2000, 2000]]),
        vec![],
    );
    case(
        "except_eol/line_end",
        &eol,
        met1(&[[0, 0, 100, 1000], [150, 1050, 1150, 2050]]),
        vec![],
    );
    case(
        "except_eol/other_line_end",
        &eol,
        met1(&[[0, 0, 1000, 1000], [1050, 1050, 1150, 2050]]),
        vec![],
    );
    case(
        "except_eol/wide_corners",
        &eol,
        met1(&[[0, 0, 1000, 1000], [1050, 1050, 2050, 2050]]),
        vec![pin(Finding::length(50), 2050, 2050)],
    );
    case(
        "line_end_without_except",
        &square,
        met1(&[[0, 0, 100, 1000], [150, 1050, 1150, 2050]]),
        vec![pin(Finding::length(50), 250, 2050)],
    );
}

/// `wide_space(met1; width: 1000nm) >= 301nm` (DRC-025): the wide part is
/// where a 1000 square fits (exactly 1000 wide counts); pairs in different
/// figures where either has one, measured from that part, at the midpoint
/// of the nearest points.
///
/// Oracle: widths and gaps by construction: the plate width swept around
/// 1000 beside a line 200 off; the gap swept at a wide plate; a thin tab of
/// a wide plate 200 from a line 500 from the plate (not held), drawn as one
/// polygon and as touching rectangles; a 1200 x 1000 plate drawn as two
/// halves, neither wide alone (two row pairs, both held, at (1300, 250)
/// and (1300, 750)); two thin lines; a thin line between the plate and
/// another (only the near pair); a staircase 100 from the plate over y =
/// 1500..2000 whose box reaches far below (marked at (2050, 1750)); a plate
/// whose facing side the wide part's rectangles cut in three (marked at the
/// whole side's middle (1500, 2100)).
#[test]
fn wide_space_holds_pairs_beside_a_wide_part() {
    let deck = one_layer_deck("rule wd wide_space(met1; width: 1000nm) >= 301nm");
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("wd", findings)]);
    };
    for w in steps(1000) {
        let found = if w >= 1000 {
            vec![pin(Finding::length(200), 2 * w + 200, 3000)]
        } else {
            vec![]
        };
        case(
            "plate_width",
            met1(&[[0, 0, w, 3000], [w + 200, 0, w + 300, 3000]]),
            found,
        );
    }
    for g in steps(301) {
        let found = if g < 301 {
            vec![pin(Finding::length(g), 4000 + g, 3000)]
        } else {
            vec![]
        };
        case(
            "gap",
            met1(&[[0, 0, 2000, 3000], [2000 + g, 0, 2100 + g, 3000]]),
            found,
        );
    }
    let finger = [
        (0, 0),
        (2000, 0),
        (2000, 2000),
        (1000, 2000),
        (1000, 3000),
        (900, 3000),
        (900, 2000),
        (0, 2000),
    ];
    case(
        "thin_tab_not_held",
        Layout::default()
            .polygon("met1", &finger)
            .rect("met1", 1200, 2500, 1300, 3000),
        vec![],
    );
    case(
        "thin_tab_touching_not_held",
        met1(&[
            [0, 0, 2000, 2000],
            [900, 2000, 1000, 3000],
            [1200, 2500, 1300, 3000],
        ]),
        vec![],
    );
    case(
        "wide_only_merged",
        met1(&[
            [0, 0, 1200, 500],
            [0, 500, 1200, 1000],
            [1400, 0, 1500, 1000],
        ]),
        vec![
            Finding::length(200).at(1300, 250),
            Finding::length(200).at(1300, 750),
        ],
    );
    case(
        "two_thin_lines",
        met1(&[[0, 0, 100, 3000], [300, 0, 400, 3000]]),
        vec![],
    );
    case(
        "line_between",
        met1(&[
            [0, 0, 2000, 2000],
            [2100, 0, 2200, 2000],
            [2400, 0, 2500, 2000],
        ]),
        vec![Finding::length(100).at(2050, 1000)],
    );
    case(
        "staircase_beside_the_plate",
        Layout::default().rect("met1", 0, 0, 2000, 2000).polygon(
            "met1",
            &[
                (2100, 1500),
                (2200, 1500),
                (2200, -1000),
                (2300, -1000),
                (2300, 1600),
                (2200, 1600),
                (2200, 4000),
                (2100, 4000),
            ],
        ),
        vec![pin(Finding::length(100), 2000 + 2100, 1500 + 2000)],
    );
    case(
        "wide_side_cut_into_slabs",
        Layout::default()
            .polygon(
                "met1",
                &[
                    (0, 0),
                    (500, 0),
                    (500, -1000),
                    (1500, -1000),
                    (1500, 0),
                    (3000, 0),
                    (3000, 2000),
                    (0, 2000),
                ],
            )
            .rect("met1", 0, 2200, 3000, 2300),
        vec![pin(Finding::length(200), 3000, 2000 + 2200)],
    );
}

/// `wide_space(met1; width: 1000nm, attached: 300nm) >= 301nm` (DRC-028)
/// beside the same rule without `attached`: the wide part grown by 300 and
/// clipped to its own figure also holds what is attached to it.
///
/// Oracle: a 2000 plate with a 100-wide finger up its middle, and a line
/// 200 beside the finger starting `a` above the plate: the attached stub
/// reaches 300 up the finger, so the line is `min(a, √(200² + (a −
/// 300)²))` from the grown part and `a` from the plate, floored. A thin
/// line between the plate and another line holds only the near pair.
#[test]
fn attached_wide_space_holds_what_is_attached_to_the_wide_part() {
    let deck = one_layer_deck(
        "rule wd wide_space(met1; width: 1000nm) >= 301nm\n\
         rule aw wide_space(met1; width: 1000nm, attached: 300nm) >= 301nm",
    );
    let held = |gap2: i64| {
        if gap2 < 301 * 301 {
            vec![Finding::length(floor_sqrt(gap2))]
        } else {
            vec![]
        }
    };
    for a in [100, 250, 300, 400, 500, 600] {
        let stub2 = if a <= 300 {
            200 * 200
        } else {
            200 * 200 + (a - 300) * (a - 300)
        };
        check_everywhere(
            &format!("finger/a{a}"),
            &deck,
            &Layout::default()
                .polygon(
                    "met1",
                    &[
                        (0, 0),
                        (2000, 0),
                        (2000, 2000),
                        (1000, 2000),
                        (1000, 3000),
                        (900, 3000),
                        (900, 2000),
                        (0, 2000),
                    ],
                )
                .rect("met1", 1200, 2000 + a, 1300, 3000),
            &[("wd", held(a * a)), ("aw", held(stub2.min(a * a)))],
        );
    }
    check_everywhere(
        "line_between",
        &deck,
        &met1(&[
            [0, 0, 2000, 2000],
            [2100, 0, 2200, 2000],
            [2400, 0, 2500, 2000],
        ]),
        &[
            ("wd", vec![Finding::length(100).at(2050, 1000)]),
            ("aw", vec![Finding::length(100).at(2050, 1000)]),
        ],
    );
}

/// `space(met1; nets: same) >= 301nm` and `nets: different` (DRC-080):
/// pairs in different figures, by extracted net, at the midpoint of the
/// nearest points.
///
/// Oracle: nets by construction: two bars `g` apart strapped through vias
/// and `met2` (one net: only the same-net rule holds them) or not (two
/// nets); touching bars (one figure, no pair); an empty `met1`.
#[test]
fn net_space_tells_one_net_from_two() {
    let deck = new_deck(
        &["met1", "via1", "met2"],
        "connect conductors [met1, met2]\n\
         connect touch_within_layer\n\
         connect via via1 [met1, met2]\n\
         rule sn space(met1; nets: same) >= 301nm\n\
         rule dn space(met1; nets: different) >= 301nm\n",
    );
    for g in steps(301) {
        let near = if g < 301 {
            vec![pin(Finding::length(g), 1000 + g, 2000)]
        } else {
            vec![]
        };
        let bars = met1(&[[0, 0, 500, 2000], [500 + g, 0, 1000 + g, 2000]]);
        let strapped = bars
            .clone()
            .rect("via1", 200, 200, 300, 300)
            .rect("via1", 700 + g, 200, 800 + g, 300)
            .rect("met2", 100, 100, 900 + g, 400);
        check_everywhere(
            "strapped",
            &deck,
            &strapped,
            &[("sn", near.clone()), ("dn", vec![])],
        );
        check_everywhere("apart", &deck, &bars, &[("sn", vec![]), ("dn", near)]);
    }
    check_everywhere(
        "touching",
        &deck,
        &met1(&[[0, 0, 500, 2000], [500, 0, 1000, 2000]]),
        &[("sn", vec![]), ("dn", vec![])],
    );
    check_everywhere(
        "vacuous",
        &deck,
        &Layout::default().rect("met2", 0, 0, 1000, 1000),
        &[("sn", vec![]), ("dn", vec![])],
    );
}

/// `space(met1, met2; nets: different) >= 301nm` (DRC-081, as sky130
/// nwell.7): a met1 bar and a met2 bar `g` apart on two nets are flagged
/// at the midpoint of the gap below the limit; the same bars joined into
/// one net through a via are not judged however close; a met2 bar crossing
/// the met1 bar on another net overlaps it, a distance of 0.
///
/// Oracle: nets and gaps by construction: the met2 bar drawn `g` = 300,
/// 301, 302 right of the met1 bar (two nets: a finding of `g` at the gap's
/// midpoint `((1000 + g) / 2, 1000)` for 300, nothing at or above 301);
/// the same bars strapped by a met2 bar and a via onto met1 (one net:
/// nothing); a met2 bar drawn across the met1 bar (overlap: 0).
#[test]
fn net_space_across_two_layers_reads_their_nets() {
    let deck = new_deck(
        &["met1", "via1", "met2"],
        "connect conductors [met1, met2]\n\
         connect touch_within_layer\n\
         connect via via1 [met1, met2]\n\
         rule dn2 space(met1, met2; nets: different) >= 301nm\n",
    );
    for g in steps(301) {
        let near = if g < 301 {
            vec![pin(Finding::length(g), 1000 + g, 2000)]
        } else {
            vec![]
        };
        let bars = met1(&[[0, 0, 500, 2000]]).rect("met2", 500 + g, 0, 1000 + g, 2000);
        let joined = bars
            .clone()
            .rect("met2", 0, 2000, 1000 + g, 2500)
            .rect("met1", 0, 2000, 500, 2500)
            .rect("via1", 200, 2200, 300, 2300);
        check_everywhere("apart", &deck, &bars, &[("dn2", near)]);
        check_everywhere("one_net", &deck, &joined, &[("dn2", vec![])]);
    }
    check_everywhere(
        "crossing",
        &deck,
        &met1(&[[0, 0, 500, 2000]]).rect("met2", -500, 900, 1000, 1100),
        &[("dn2", vec![Finding::length(0)])],
    );
}

/// Net spacing on a derived layer (DRC-081): sky130 hvnwell.8 "Min space
/// between HV_nwell and any nwell on different nets" 2 µm, `hv_nwell =
/// nwell.interacting(hvi)`, which takes the nets of the n-well it is
/// computed from.
///
/// Oracle: nets by construction: an HV well and a plain well 1999, 2000,
/// 2001 apart (separate: one finding of 1999); the two joined by an n-well
/// bridge (one net: nothing, though 1000 apart); the HV well against its
/// own n-well (one net, overlapping: nothing). `nwell or hvi` with the
/// `hvi` shape bridging two wells is one shape over two nets, so the rule
/// refuses rather than guess.
#[test]
fn net_space_on_a_derived_layer_takes_its_sources_nets() {
    let deck = new_deck(
        &["nwell", "hvi"],
        "connect conductors [nwell]\n\
         connect touch_within_layer\n\
         layer hv_nwell = nwell.interacting(hvi)\n\
         rule hvnwell.8 space(hv_nwell, nwell; nets: different) >= 2um\n",
    );
    let hv = || {
        Layout::default()
            .rect("nwell", 0, 0, 3000, 3000)
            .rect("hvi", -500, -500, 3500, 3500)
    };
    for g in steps(2000) {
        check_everywhere(
            "apart",
            &deck,
            &hv().rect("nwell", 3000 + g, 0, 6000 + g, 3000),
            &[("hvnwell.8", below(g, 2000))],
        );
    }
    check_everywhere(
        "bridged",
        &deck,
        &hv()
            .rect("nwell", 4000, 0, 7000, 3000)
            .rect("nwell", 3000, 1000, 4000, 2000),
        &[("hvnwell.8", vec![])],
    );
    check_everywhere("alone", &deck, &hv(), &[("hvnwell.8", vec![])]);
    let either = new_deck(
        &["nwell", "hvi"],
        "connect conductors [nwell]\n\
         connect touch_within_layer\n\
         layer either = nwell or hvi\n\
         rule e space(either, nwell; nets: different) >= 2um\n",
    );
    let rows = run(
        &either,
        &Layout::default()
            .rect("nwell", 0, 0, 1000, 1000)
            .rect("nwell", 2000, 0, 3000, 1000)
            .rect("hvi", 500, 400, 2500, 600),
    );
    assert_eq!(row(&rows, "e").outcome, Outcome::Refused);
}

/// `space_table`: 180 everywhere, 220 for a pair whose wider shape is wider
/// than 300 running alongside for more than 1000.
const TABLE: &str = "rule t space_table(met1;
    prl:   [0nm, 1000nm],
    width: [0nm, 300nm],
    space: [[180nm, 180nm],
            [180nm, 220nm]])";

/// `space_table` (DRC-025, DRC-026, DRC-027): the column of the last `prl`
/// strictly exceeded by the run of facing edges at most that column's cell
/// apart, the row of the last `width` the wider shape strictly exceeds;
/// one finding per pair, at the midpoint of the points it measured.
///
/// Oracle: a `wa`-wide line beside a 100-wide one, `g` apart with a run
/// `r`: the width swept around 300 (exactly 300 is the first row), the run
/// around 1000 (exactly 1000 the first column), the gap around 220 and,
/// for two thin lines, around 180. A thin tab of a wide plate is held to
/// the first row; a ring's own hole is no pair; touching lines are one
/// figure; an L whose box would overstate the run keeps the first column;
/// a bar beside a stub keeps column 0 within the cell (run 50 within 200);
/// a wire of four segments takes the column of its whole run.
#[test]
fn space_table_picks_the_cell_of_width_and_run() {
    let deck = one_layer_deck(TABLE);
    let pair = |name: &str, wa: i64, g: i64, r: i64| {
        let column = usize::from(r > 1000);
        let need = if wa > 300 { [180, 220][column] } else { 180 };
        let found = if g < need {
            vec![pin(Finding::length(g), 2 * wa + g, 4000 - r)]
        } else {
            vec![]
        };
        check_everywhere(
            name,
            &deck,
            &met1(&[[0, 0, wa, 2000], [wa + g, 2000 - r, wa + g + 100, 4000 - r]]),
            &[("t", found)],
        );
    };
    for wa in steps(300) {
        pair("width", wa, 200, 2000);
    }
    for r in steps(1000) {
        pair("run", 400, 200, r);
    }
    for g in steps(220) {
        pair("gap_wide", 400, g, 2000);
    }
    for g in steps(180) {
        pair("gap_thin", 100, g, 2000);
    }
    let clean = |name: &str, deck: &str, layout: Layout| {
        check_everywhere(name, deck, &layout, &[("t", vec![])]);
    };
    clean(
        "thin_tab_first_row",
        &deck,
        Layout::default()
            .polygon(
                "met1",
                &[
                    (0, 0),
                    (2000, 0),
                    (2000, 2000),
                    (1000, 2000),
                    (1000, 4000),
                    (900, 4000),
                    (900, 2000),
                    (0, 2000),
                ],
            )
            .rect("met1", 1200, 2500, 1300, 4000),
    );
    clean(
        "own_hole",
        &deck,
        ring(
            Layout::default(),
            "met1",
            [0, 0, 2000, 2000],
            [100, 100, 1900, 1900],
        ),
    );
    clean(
        "touching",
        &deck,
        met1(&[[0, 0, 400, 2000], [400, 0, 500, 2000]]),
    );
    clean(
        "l_box_overstates_run",
        &deck,
        Layout::default().rect("met1", 0, 0, 400, 2000).polygon(
            "met1",
            &[
                (1500, 0),
                (1600, 0),
                (1600, 2000),
                (600, 2000),
                (600, 1900),
                (1500, 1900),
            ],
        ),
    );
    clean(
        "run_within_the_cell",
        &one_layer_deck(
            "rule t space_table(met1;
    prl:   [0nm, 1000nm],
    width: [0nm, 300nm],
    space: [[180nm, 200nm],
            [180nm, 260nm]])",
        ),
        met1(&[
            [0, 0, 100, 3000],
            [330, 0, 430, 3000],
            [290, 1000, 330, 1050],
        ]),
    );
    check_everywhere(
        "segmented_run",
        &deck,
        &met1(&[
            [0, 0, 400, 2000],
            [600, 0, 700, 500],
            [600, 500, 700, 1000],
            [600, 1000, 700, 1500],
            [600, 1500, 700, 2000],
        ]),
        &[(
            "t",
            vec![
                Finding::length(200).at(500, 250),
                Finding::length(200).at(500, 750),
                Finding::length(200).at(500, 1250),
                Finding::length(200).at(500, 1750),
            ],
        )],
    );
}

/// LEF/DEF 5.8's two-width table in nm: widths 0, 0.25, 1.5 and 3.0 µm
/// with runs none, 0, 1.5 and 3.0 µm, and the manual's cells.
const TWO_WIDTHS: &str = "rule t two_width_table(met1;
    width: [0nm, 250nm, 1500nm, 3000nm],
    prl:   [none, 0nm, 1500nm, 3000nm],
    space: [[150nm, 200nm, 500nm, 1000nm],
            [200nm, 250nm, 500nm, 1000nm],
            [500nm, 500nm, 600nm, 1000nm],
            [1000nm, 1000nm, 1000nm, 1200nm]])";

/// `two_width_table` (DRC-027): a pair needs the cell at the last width
/// that applies to each shape, a width applying to a shape wider than it
/// whose figures run alongside for more than its run.
///
/// Oracle: LEF's own worked example, each gap swept around its space:
/// widths 250 and 250 with no run, 150; 250 and 260 with no run, 150; 250
/// and 260 with a run of 100, 200; 260 and 260 with a run of 100, 250. The
/// 1500 run swept between two 1600 wide plates 550 apart (600 only past
/// it). A 260 wide line 220 from the thin tab of a 2 µm plate is clean (the
/// tab is not wide). A ring's own hole and touching shapes are no pair.
#[test]
fn two_width_table_reads_each_shapes_width_and_run() {
    let deck = one_layer_deck(TWO_WIDTHS);
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("t", findings)]);
    };
    for (name, wa, wb, r, need) in [
        ("w250_w250_run0", 250, 250, 0, 150),
        ("w250_w260_run0", 250, 260, 0, 150),
        ("w250_w260_run100", 250, 260, 100, 200),
        ("w260_w260_run100", 260, 260, 100, 250),
    ] {
        for g in steps(need) {
            let found = if g < need {
                vec![pin(Finding::length(g), 2 * wa + g, 4000 - r)]
            } else {
                vec![]
            };
            case(
                name,
                met1(&[[0, 0, wa, 2000], [wa + g, 2000 - r, wa + g + wb, 4000 - r]]),
                found,
            );
        }
    }
    for r in steps(1500) {
        let found = if r > 1500 {
            vec![pin(Finding::length(550), 3750, 6000 - r)]
        } else {
            vec![]
        };
        case(
            "run_1500",
            met1(&[[0, 0, 1600, 3000], [2150, 3000 - r, 3750, 6000 - r]]),
            found,
        );
    }
    case(
        "thin_tab_is_thin",
        met1(&[
            [0, 0, 2000, 2000],
            [900, 2000, 1000, 3000],
            [1220, 2500, 1480, 4000],
        ]),
        vec![],
    );
    case(
        "own_hole",
        ring(
            Layout::default(),
            "met1",
            [0, 0, 2000, 2000],
            [100, 100, 1900, 1900],
        ),
        vec![],
    );
    case(
        "touching",
        met1(&[[0, 0, 400, 2000], [400, 0, 500, 2000]]),
        vec![],
    );
}

/// The ASAP7 M1 tip table (DRM r1p7, Table 3.12.1): edges below 24 nm,
/// from 24 to 36 nm, and above 36 nm.
const TIPS: &str = "rule t tip_space_table(met1;
    length: [0nm, 24nm, 37nm],
    space: [[31nm, 31nm, 25nm],
            [31nm, 27nm, 25nm],
            [25nm, 25nm, 18nm]])";

/// `tip_space_table` (DRC-031): whole edges of the merged layer in
/// different figures facing each other over a positive run need the cell
/// of their two length classes; one finding per pair of figures, its
/// smallest offending gap, at the middle of the stretch the edges face.
///
/// Oracle: each ASAP7 rule's gap swept around its value (side to side 18,
/// tip to side 25 from a 20 and a 30 wide line, tip to tip 27, 31, 31);
/// each class boundary swept at a gap between its two cells (tips 23, 24,
/// 25 wide 28 apart; 36, 37, 38 wide 20 apart). Clean: a diagonal pair, a
/// notch inside one figure, a 30 wide tip drawn as two strips 28 from
/// another. Three bars: two findings; a figure 15 and 10 away along two
/// steps: one finding, at the nearer.
#[test]
fn tip_space_table_classes_whole_edges_by_length() {
    let deck = one_layer_deck(TIPS);
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("t", findings)]);
    };
    let tips = |wa: i64, wb: i64, g: i64| met1(&[[0, 0, wa, 1000], [0, 1000 + g, wb, 2000 + g]]);
    let found = |g: i64, need: i64, x2: i64, y2: i64| {
        if g < need {
            vec![pin(Finding::length(g), x2, y2)]
        } else {
            vec![]
        }
    };
    for g in steps(18) {
        case(
            "side_to_side",
            met1(&[[0, 0, 100, 1000], [100 + g, 0, 200 + g, 1000]]),
            found(g, 18, 200 + g, 1000),
        );
    }
    for w in [20, 30] {
        for g in steps(25) {
            case(
                "tip_to_side",
                met1(&[[0, 0, w, 1000], [-500, 1000 + g, 500, 1100 + g]]),
                found(g, 25, w, 2000 + g),
            );
        }
    }
    for (wa, wb, need) in [(30, 30, 27), (20, 20, 31), (30, 20, 31)] {
        for g in steps(need) {
            case(
                "tip_to_tip",
                tips(wa, wb, g),
                found(g, need, wa.min(wb), 2000 + g),
            );
        }
    }
    let class_need = |w: i64| {
        if w < 24 {
            31
        } else if w < 37 {
            27
        } else {
            18
        }
    };
    for w in steps(24) {
        case(
            "class_24",
            tips(w, w, 28),
            found(28, class_need(w), w, 2028),
        );
    }
    for w in steps(37) {
        case(
            "class_37",
            tips(w, w, 20),
            found(20, class_need(w), w, 2020),
        );
    }
    case(
        "diagonal",
        met1(&[[0, 0, 30, 1000], [40, 1010, 70, 2000]]),
        vec![],
    );
    case(
        "notch_in_one_figure",
        met1(&[[0, 0, 20, 500], [30, 0, 50, 500], [0, -20, 50, 0]]),
        vec![],
    );
    case(
        "tip_drawn_as_strips",
        met1(&[[0, 0, 15, 1000], [15, 0, 30, 1000], [0, 1028, 30, 2028]]),
        vec![],
    );
    case(
        "three_bars",
        met1(&[[0, 0, 100, 1000], [110, 0, 210, 1000], [220, 0, 320, 1000]]),
        vec![
            Finding::length(10).at(105, 500),
            Finding::length(10).at(215, 500),
        ],
    );
    case(
        "nearest_of_two_steps",
        met1(&[[0, 0, 100, 1000], [115, 0, 215, 400], [110, 400, 210, 1000]]),
        vec![Finding::length(10).at(105, 700)],
    );
}

/// `forbidden_space(met1; min: 100nm, max: 150nm, prl: 200nm)` (DRC-033):
/// facing edges of different figures that run alongside for more than 200
/// at a gap from 100 to 150, both included, are forbidden; one finding per
/// pair, its smallest forbidden gap, at the middle of the facing stretch.
///
/// Oracle: the gap swept around both ends of the range (99 and 151 legal),
/// the run swept around 200 at a gap of 120 (200 is not more than 200).
/// Clean: a diagonal pair, a U whose arms are 120 apart (one figure).
/// Three bars 120 apart: two findings. A figure 90 away along one step and
/// 130 along another: the 90 is below the range, the finding is the 130.
#[test]
fn forbidden_space_flags_gaps_inside_the_range() {
    let deck = one_layer_deck("rule f forbidden_space(met1; min: 100nm, max: 150nm, prl: 200nm)");
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("f", findings)]);
    };
    let bars = |g: i64| met1(&[[0, 0, 100, 1000], [100 + g, 0, 200 + g, 1000]]);
    for limit in [100, 150] {
        for g in steps(limit) {
            let found = if (100..=150).contains(&g) {
                vec![pin(Finding::length(g), 200 + g, 1000)]
            } else {
                vec![]
            };
            case("gap", bars(g), found);
        }
    }
    for r in steps(200) {
        let found = if r > 200 {
            vec![pin(Finding::length(120), 320, 2000 - r)]
        } else {
            vec![]
        };
        case(
            "run",
            met1(&[[0, 0, 100, 1000], [220, 1000 - r, 320, 2000 - r]]),
            found,
        );
    }
    case(
        "diagonal",
        met1(&[[0, 0, 100, 1000], [220, 1100, 320, 2000]]),
        vec![],
    );
    case(
        "one_figure",
        met1(&[[0, 0, 100, 1000], [220, 0, 320, 1000], [0, -100, 320, 0]]),
        vec![],
    );
    case(
        "three_bars",
        met1(&[[0, 0, 100, 1000], [220, 0, 320, 1000], [440, 0, 540, 1000]]),
        vec![
            Finding::length(120).at(160, 500),
            Finding::length(120).at(380, 500),
        ],
    );
    case(
        "narrower_step_is_legal",
        met1(&[[0, 0, 100, 1000], [190, 0, 290, 400], [230, 400, 330, 1000]]),
        vec![Finding::length(130).at(165, 700)],
    );
}

/// `pitch(met1, vertical) == 27nm` and `pitch(met1, horizontal) == 54nm`
/// (DRC-035), ASAP7 FIN.S.1 and GATE.S.1: each rectangle's nearest
/// neighbours past it that overlap it across must have their centre lines
/// exactly the pitch apart; one finding per pair off it, in the middle of
/// their gap.
///
/// Oracle: three fins and three gates, the pitch swept one step either
/// side: both pairs off the pitch, none at it. A missing fin is a pitch of
/// 54. Fins that do not overlap across are no neighbours. A bent shape
/// refuses. Placed under the symmetries that keep the axes.
#[test]
fn exact_pitch_wants_centre_lines_exactly_apart() {
    let fins = one_layer_deck("rule p pitch(met1, vertical) == 27nm");
    let gates = one_layer_deck("rule p pitch(met1, horizontal) == 54nm");
    for p in steps(27) {
        let found = if p == 27 {
            vec![]
        } else {
            vec![
                pin(Finding::length(p), 1000, p + 7),
                pin(Finding::length(p), 1000, 3 * p + 7),
            ]
        };
        check_axes(
            "fins",
            &fins,
            &met1(&[
                [0, 0, 1000, 7],
                [0, p, 1000, p + 7],
                [0, 2 * p, 1000, 2 * p + 7],
            ]),
            &[("p", found)],
        );
    }
    for p in steps(54) {
        let found = if p == 54 {
            vec![]
        } else {
            vec![
                pin(Finding::length(p), p + 20, 1000),
                pin(Finding::length(p), 3 * p + 20, 1000),
            ]
        };
        check_axes(
            "gates",
            &gates,
            &met1(&[
                [0, 0, 20, 1000],
                [p, 0, p + 20, 1000],
                [2 * p, 0, 2 * p + 20, 1000],
            ]),
            &[("p", found)],
        );
    }
    check_axes(
        "missing_fin",
        &fins,
        &met1(&[[0, 0, 1000, 7], [0, 27, 1000, 34], [0, 81, 1000, 88]]),
        &[("p", vec![pin(Finding::length(54), 1000, 115)])],
    );
    check_axes(
        "no_overlap_across",
        &fins,
        &met1(&[[0, 0, 1000, 7], [2000, 30, 3000, 37]]),
        &[("p", vec![])],
    );
    let rows = run(
        &fins,
        &Layout::default().polygon(
            "met1",
            &[(0, 0), (1000, 0), (1000, 7), (7, 7), (7, 500), (0, 500)],
        ),
    );
    assert_eq!(row(&rows, "p").outcome, Outcome::Refused);
}

/// LEF/DEF 5.8's span tables for its vertical METAL2.
const SPANS: &str =
    "rule s span_length(met1; x: [60nm, 80nm, 120nm, 160nm, 200nm], y: [120nm, 160nm, 200nm])";

/// `span_length` (DRC-036): every chord a horizontal or vertical line cuts
/// from a merged figure is one of its axis's lengths, or at least the
/// last; one finding per maximal region of an unchanged illegal chord, at
/// its centre, measuring the chord.
///
/// Oracle: LEF's own lists, each value and one step either side: a
/// vertical wire's width on `x`, a horizontal piece's height on `y`. A U
/// with a stepped arm: the left arm's 100 is one region, the base's 100
/// one region across the step. A ring's band, four regions. A 200 long
/// piece drawn as two halves is one legal span. Under the symmetries that
/// keep the axes.
#[test]
fn span_length_reads_each_axis_list() {
    let deck = one_layer_deck(SPANS);
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        check_axes(name, &deck, &layout, &[("s", findings)]);
    };
    for w in [60, 80, 120, 160, 200]
        .into_iter()
        .flat_map(|v| [v - 1, v, v + 1])
    {
        let legal = [60, 80, 120, 160].contains(&w) || w >= 200;
        let found = if legal {
            vec![]
        } else {
            vec![pin(Finding::length(w), w, 1000)]
        };
        case("x", met1(&[[0, 0, w, 1000]]), found);
    }
    for h in [120, 160, 200].into_iter().flat_map(|v| [v - 1, v, v + 1]) {
        let legal = [120, 160].contains(&h) || h >= 200;
        let found = if legal {
            vec![]
        } else {
            vec![pin(Finding::length(h), 1000, h)]
        };
        case("y", met1(&[[0, 0, 1000, h]]), found);
    }
    case(
        "stepped_u",
        met1(&[
            [0, 0, 1000, 100],
            [0, 0, 100, 1000],
            [900, 0, 1000, 500],
            [850, 500, 1000, 1000],
        ]),
        vec![
            pin(Finding::length(100), 100, 1100),
            pin(Finding::length(100), 1900, 600),
            pin(Finding::length(150), 1850, 1500),
            pin(Finding::length(100), 1000, 100),
        ],
    );
    case(
        "ring",
        ring(
            Layout::default(),
            "met1",
            [0, 0, 1000, 1000],
            [100, 100, 900, 900],
        ),
        vec![
            pin(Finding::length(100), 100, 1000),
            pin(Finding::length(100), 1900, 1000),
            pin(Finding::length(100), 1000, 100),
            pin(Finding::length(100), 1000, 1900),
        ],
    );
    case(
        "drawn_in_halves",
        met1(&[[0, 0, 100, 120], [100, 0, 200, 120]]),
        vec![],
    );
}

/// `span_length(met1; x: [100nm, 300nm], y: [100nm, 300nm], x_except:
/// 200nm, y_except: none)` (DRC-036): LEF58 `SPANLENGTHTABLE 0.1 0.3
/// EXCEPTOTHERSPAN 0.2`, "the span length rule only applies if the span
/// length on the perpendicular direction is greater than the specified
/// otherSpanlength", on the `x` list only.
///
/// Oracle: a 150 wide rectangle, its height swept around 200: its 150
/// horizontal span is held only above 200, its vertical span (199 to 201,
/// illegal on `y`) always. An L is held with no exception: its 150 x 100
/// foot reports 150.
#[test]
fn span_length_except_skips_short_crosswise_spans() {
    let deck = one_layer_deck(
        "rule s span_length(met1; x: [100nm, 300nm], y: [100nm, 300nm], x_except: 200nm, \
         y_except: none)",
    );
    for h in steps(200) {
        let mut found = vec![pin(Finding::length(h), 150, h)];
        if h > 200 {
            found.push(pin(Finding::length(150), 150, h));
        }
        check_axes(
            "rectangle",
            &deck,
            &met1(&[[0, 0, 150, h]]),
            &[("s", found)],
        );
    }
    check_axes(
        "l_shape",
        &deck,
        &met1(&[[0, 0, 150, 100], [0, 100, 100, 1000]]),
        &[("s", vec![Finding::length(150).at(75, 50)])],
    );
}

/// A diamond of radius `r` centred at `(x, y)`, counter-clockwise.
fn diamond(x: i64, y: i64, r: i64) -> [(i64, i64); 4] {
    [(x, y - r), (x + r, y), (x, y + r), (x - r, y)]
}

/// `space(a, b) >= 20nm` (`min_spacing_diff`) where a shape has 45-degree
/// edges: the Euclidean gap, marked at the midpoint of the nearest pair of
/// points, the touch where boundaries touch, and the middle of the boxes'
/// overlap for a nested pair (0 with its boundaries apart), as `whole_at`'s
/// rustdoc states.
///
/// Oracle: points by construction: two diamonds of radius 10, tips (10, 0)
/// and (20, 0), 10 apart, marked at (15, 0); a diamond and a square whose
/// left side is at x = 20, the tip 10 from it, marked at (15, 0); diamonds
/// touching tip to tip at (10, 0), 0 there; a radius-5 diamond inside a
/// radius-30 one, 0, at the boxes' common centre (0, 0).
#[test]
fn a_45_degree_pair_is_marked_at_its_nearest_points() {
    let deck = new_deck(&["a", "b"], "rule s space(a, b) >= 20nm\n");
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("s", findings)]);
    };
    let a = Layout::default().polygon("a", &diamond(0, 0, 10));
    case(
        "tip_to_tip",
        a.clone().polygon("b", &diamond(30, 0, 10)),
        vec![Finding::length(10).at(15, 0)],
    );
    case(
        "tip_to_side",
        a.clone().rect("b", 20, -5, 30, 5),
        vec![Finding::length(10).at(15, 0)],
    );
    case(
        "touching",
        a.polygon("b", &diamond(20, 0, 10)),
        vec![Finding::length(0).at(10, 0)],
    );
    case(
        "nested",
        Layout::default()
            .polygon("a", &diamond(0, 0, 30))
            .polygon("b", &diamond(0, 0, 5)),
        vec![Finding::length(0).at(0, 0)],
    );
}
