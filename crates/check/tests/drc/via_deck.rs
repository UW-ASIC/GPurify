//! The cut-layer kinds through deck text: `max_space`, `keep_out_zone`,
//! `cut_class_space`, cut spacing (edge, centre and adjacent-cut forms),
//! `redundant_via`, `min_cuts`, `via_stack`, `via_map`, `stack_space`,
//! `via_redundancy` and `cut_area_change`. Each case is the root
//! `tests/exhaustive/drc_overlay.rs` fixture of the same name, its oracle
//! restated on the test, run through this crate's deck compiler and rule set
//! under the eight symmetries of the square at two translations.

use crate::deck_fixture::{
    areas, below, check_everywhere, lengths, new_deck, row, run, sweep, Finding, Layout,
};
use gpurify_check::report::{Measurement, Outcome};

type Rect = (i64, i64, i64, i64);

/// `max_space(v1) <= 1000nm` and `max_space(big, v1) <= 1000nm` with `big =
/// v1.with_bbox_min(>= 150nm)` (DRC-034): `LEF58_MAXSPACING 1.0 [CUTCLASS]`
/// as `OpenROAD`'s `getLonelyVias` reads it, a cut (of the class) with no
/// other cut whose centre is within 1000 of its own is lonely, one finding
/// at its centre measuring the nearest centre distance rounded up.
///
/// Oracle: centres placed by construction: two 100 cuts 999, 1000 and 1001
/// apart (both lonely only at 1001); a 600 x 800 diagonal (1000 by the
/// 3-4-5 triangle, legal) and a 600 x 801 one (1000.8, rounded up to 1001);
/// a lone cut (a count of 0 against 1); a chain 1000 then 1500 apart, whose
/// far cut alone is lonely (1500). With a class: a 200 cut 900 from a 100
/// cut is not lonely; 1200 apart it is; a 200 cut alone does not count its
/// own row on the whole layer.
#[test]
fn max_space_finds_each_lonely_cut_at_its_centre() {
    let deck = new_deck(
        &["v1"],
        "layer big = v1.with_bbox_min(>= 150nm)\n\
         rule lone max_space(v1) <= 1000nm\nrule cls max_space(big, v1) <= 1000nm\n",
    );
    let cut = |x: i64, y: i64| (x, y, x + 100, y + 100);
    let far = |d: i64, at: &[(i64, i64)]| -> Vec<Finding> {
        at.iter()
            .map(|&(x, y)| Finding::length(d).at(x, y))
            .collect()
    };
    let v1 = |cuts: &[Rect]| Layout::default().rects("v1", cuts);
    let case = |name: &str, layout: Layout, lone: Vec<Finding>, cls: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("lone", lone), ("cls", cls)]);
    };
    for (d, side) in sweep(1000) {
        let lonely = if d > 1000 {
            far(d, &[(50, 50), (d + 50, 50)])
        } else {
            Vec::new()
        };
        case(
            &format!("pair/{side}"),
            v1(&[cut(0, 0), cut(d, 0)]),
            lonely,
            vec![],
        );
    }
    case(
        "diagonal/at",
        v1(&[cut(0, 0), cut(600, 800)]),
        vec![],
        vec![],
    );
    case(
        "diagonal/above",
        v1(&[cut(0, 0), cut(600, 801)]),
        far(1001, &[(50, 50), (650, 851)]),
        vec![],
    );
    case(
        "alone",
        v1(&[cut(0, 0)]),
        vec![Finding::count(0).at(50, 50)],
        vec![],
    );
    case(
        "chain",
        v1(&[cut(0, 0), cut(1000, 0), cut(2500, 0)]),
        far(1500, &[(2550, 50)]),
        vec![],
    );
    let big = (0, 0, 200, 200);
    case(
        "class/near",
        v1(&[big, (950, 50, 1050, 150)]),
        vec![],
        vec![],
    );
    case(
        "class/far",
        v1(&[big, (1250, 50, 1350, 150)]),
        far(1200, &[(100, 100), (1300, 100)]),
        far(1200, &[(100, 100)]),
    );
    case(
        "class/alone",
        v1(&[big]),
        vec![Finding::count(0)],
        vec![Finding::count(0)],
    );
}

/// The limit a lonely cut is held to, and what `examined` counts.
///
/// Oracle: `Rule::MaxCutSpacing`'s rustdoc: a lonely cut with a nearest
/// cut is held to the deck's 1000 nm; one with no other cut at all
/// measures a count of 0 against a count of 1; `examined` counts the
/// held layer's cuts, three here whatever their spacing.
#[test]
fn max_space_reports_its_limit_and_counts_every_cut() {
    let deck = new_deck(&["v1"], "rule lone max_space(v1) <= 1000nm\n");
    let rows = run(
        &deck,
        &Layout::default().rects(
            "v1",
            &[(0, 0, 100, 100), (3000, 0, 3100, 100), (3500, 0, 3600, 100)],
        ),
    );
    let lone = row(&rows, "lone");
    assert_eq!(lone.examined, 3);
    assert_eq!(
        lone.findings,
        [(
            Measurement::Length(gpurify_testgen::dbu(3000)),
            Measurement::Length(gpurify_testgen::dbu(1000)),
            (50, 50)
        )]
    );
    let rows = run(&deck, &Layout::default().rect("v1", 0, 0, 100, 100));
    assert_eq!(
        row(&rows, "lone").findings,
        [(Measurement::Count(0), Measurement::Count(1), (50, 50))]
    );
}

/// `keep_out_zone` (DRC-126): a 100 x 300 class bar (`k`) and its turn
/// (`kt`, held only against 100 x 100 cuts) with end zones 10 to the side
/// and 80 forward, side zones 50 to the side and 20 forward; one finding
/// per held cut and other cut in its zones, measuring that cut's area
/// inside them.
///
/// Oracle: areas by hand from the zones: a square past the bar's end 19,
/// 20, 21 from it (in the side zone below 20: 100 at 19; touching is
/// outside), a square above it 79, 80, 81 off (in the end zone below 80); a
/// square 20 above it, in both zones (6000, their union: summing the two
/// gives 9000); a square off the corner (125, in the end zone only); a
/// second bar 79 above (300 each way for `k`, two findings, none for `kt`);
/// two squares 10 apart (no class owns a zone).
#[test]
fn keep_out_zone_measures_the_area_inside_the_zones() {
    const ZONES: &str = "end_side: 10nm, end_forward: 80nm, side_side: 50nm, side_forward: 20nm";
    let deck = new_deck(
        &["v"],
        &format!(
            "rule k keep_out_zone(v; class: 100nm x 300nm, to: none, {ZONES})\n\
             rule kt keep_out_zone(v; class: 300nm x 100nm, to: 100nm x 100nm, {ZONES})\n"
        ),
    );
    let bar = || Layout::default().rect("v", 0, 0, 300, 100);
    let square = |x: i64, y: i64| bar().rect("v", x, y, x + 100, y + 100);
    let case = |name: &str, layout: Layout, k: Vec<Finding>, kt: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("k", k), ("kt", kt)]);
    };
    for (gap, side) in sweep(20) {
        let found = if gap < 20 { areas(&[100]) } else { Vec::new() };
        case(
            &format!("past_the_end/{side}"),
            square(300 + gap, 0),
            found.clone(),
            found,
        );
    }
    for (gap, side) in sweep(80) {
        let found = if gap < 80 { areas(&[100]) } else { Vec::new() };
        case(
            &format!("above/{side}"),
            square(100, 100 + gap),
            found.clone(),
            found,
        );
    }
    case(
        "in_both_zones",
        square(100, 120),
        areas(&[6000]),
        areas(&[6000]),
    );
    case(
        "off_the_corner",
        square(305, 155),
        areas(&[125]),
        areas(&[125]),
    );
    case(
        "two_bars",
        bar().rect("v", 0, 179, 300, 279),
        areas(&[300, 300]),
        Vec::new(),
    );
    case(
        "two_squares",
        Layout::default()
            .rect("v", 0, 0, 100, 100)
            .rect("v", 110, 0, 210, 100),
        Vec::new(),
        Vec::new(),
    );
    let rows = run(&deck, &Layout::default().rect("v", 0, 0, 100, 100));
    assert_eq!(row(&rows, "k").outcome, Outcome::Ran);
    assert_eq!(row(&rows, "k").examined, 0, "no cut of the class");
}

/// sky130 licon.2 to licon.2d as one cut-class table (DRC-063, DRC-064):
/// square 170 nm licons 170 apart (licon.2), slotted 190 x 2000 licons 350
/// apart end to end (licon.2b) and 510 otherwise (licon.2c), and 510 from a
/// square (licon.2d). One finding per pair closer than its cell, measuring
/// the gap.
///
/// Oracle: the sky130 manual's values, gaps drawn to them; a pair apart
/// along both axes needs the larger of its two readings (`OpenROAD`'s
/// `checkLef58CutSpacingTbl_helper` checks both directions): slots offset
/// diagonally by (110, 400) are floor(sqrt(110² + 400²)) = 414 apart and
/// held to 510. A 200 nm cut has no class; overlapping squares and a slot
/// abutting a square measure 0.
#[test]
fn cut_class_space_holds_each_pair_to_its_cell() {
    let deck = new_deck(
        &["licon"],
        "rule licon.2 cut_class_space(licon;\n\
         short: [170nm, 190nm], long: [170nm, 2000nm],\n\
         space: [[170nm, 170nm, 510nm, 510nm], [170nm, 170nm, 510nm, 510nm],\n\
         [510nm, 510nm, 350nm, 510nm], [510nm, 510nm, 510nm, 510nm]])\n",
    );
    let case = |name: &str, cuts: &[Rect], findings: Vec<Finding>| {
        check_everywhere(
            name,
            &deck,
            &Layout::default().rects("licon", cuts),
            &[("licon.2", findings)],
        );
    };
    let slot: Rect = (0, 0, 190, 2000);
    for (g, side) in sweep(170) {
        case(
            &format!("squares/{side}"),
            &[(0, 0, 170, 170), (170 + g, 0, 340 + g, 170)],
            below(g, 170),
        );
    }
    for (g, side) in sweep(350) {
        case(
            &format!("end_to_end/{side}"),
            &[slot, (0, 2000 + g, 190, 4000 + g)],
            below(g, 350),
        );
    }
    for (g, side) in sweep(510) {
        case(
            &format!("side_by_side/{side}"),
            &[slot, (190 + g, 0, 380 + g, 2000)],
            below(g, 510),
        );
        case(
            &format!("slot_beside_square/{side}"),
            &[slot, (190 + g, 900, 360 + g, 1070)],
            below(g, 510),
        );
        case(
            &format!("square_past_slot_end/{side}"),
            &[slot, (10, 2000 + g, 180, 2170 + g)],
            below(g, 510),
        );
    }
    case("end_to_end_400", &[slot, (0, 2400, 190, 4400)], vec![]);
    case("diagonal", &[slot, (300, 2400, 490, 4400)], lengths(&[414]));
    case("unclassed", &[(0, 0, 170, 170), (180, 0, 380, 200)], vec![]);
    case(
        "overlapping_squares",
        &[(0, 0, 170, 170), (100, 0, 270, 170)],
        lengths(&[0]),
    );
    case(
        "slot_abutting_square",
        &[slot, (190, 0, 360, 170)],
        lengths(&[0]),
    );
}

/// A cut-class table whose square class has an END unlike its SIDE: a
/// 100 x 100 square and a 100 x 300 slot, rows and columns square END,
/// square SIDE, slot END, slot SIDE.
const SQUARE_AND_SLOT: &str = "rule cs cut_class_space(cut;\n\
     short: [100nm, 100nm], long: [100nm, 300nm],\n\
     space: [[200nm, 300nm, 400nm, 400nm], [300nm, 300nm, 400nm, 400nm],\n\
     [400nm, 400nm, 350nm, 500nm], [400nm, 400nm, 500nm, 500nm]])\n";

/// Oracle: `Rule::CutClassSpacing`'s rustdoc: "A square cut always faces
/// with its END", and "A pair that touches or overlaps is held to the
/// largest cell of its two classes", the finding's `limit` the cell. Two
/// squares 250 apart face END to END, 200: clean (SIDE to SIDE would need
/// 300). Two slots touching end to end are not apart along either axis:
/// held to the largest slot-slot cell, 500, not the END-END 350 an apart
/// pair would take; the finding measures 0.
#[test]
fn cut_class_space_reads_squares_as_ends_and_touching_pairs_at_the_largest_cell() {
    let deck = new_deck(&["cut"], SQUARE_AND_SLOT);
    check_everywhere(
        "squares",
        &deck,
        &Layout::default().rects("cut", &[(0, 0, 100, 100), (0, 350, 100, 450)]),
        &[("cs", vec![])],
    );
    check_everywhere(
        "squares_closer",
        &deck,
        &Layout::default().rects("cut", &[(0, 0, 100, 100), (0, 299, 100, 399)]),
        &[("cs", vec![Finding::length(199).held(200)])],
    );
    check_everywhere(
        "touching_slots",
        &deck,
        &Layout::default().rects("cut", &[(0, 0, 100, 300), (0, 300, 100, 600)]),
        &[("cs", vec![Finding::length(0).held(500)])],
    );
}

/// Oracle: `Rule::MaxCutSpacing`'s rustdoc: the nearest centre distance
/// rounded up. A 100 cut and a 100 x 101 cut 1000 along: centres (50, 50)
/// and (1050, 50.5), `√(1000² + 0.5²) ≈ 1000.0001` apart: lonely, measuring
/// 1001. A 100 cut and a 101 x 100 cut 1001 along: centres 1101.5 apart,
/// rounded up to 1102.
#[test]
fn max_space_rounds_a_half_unit_distance_up() {
    let deck = new_deck(&["v1"], "rule lone max_space(v1) <= 1000nm\n");
    check_everywhere(
        "half_unit_off_axis",
        &deck,
        &Layout::default().rects("v1", &[(0, 0, 100, 100), (1000, 0, 1100, 101)]),
        &[("lone", vec![Finding::length(1001); 2])],
    );
    check_everywhere(
        "half_unit_along",
        &deck,
        &Layout::default().rects("v1", &[(0, 0, 100, 100), (1101, 0, 1202, 100)]),
        &[("lone", vec![Finding::length(1102); 2])],
    );
}

/// Cut-to-cut spacing `space(cut) >= 100nm` (DRC-060) and cross-layer
/// `space(via1, via2) >= 100nm` (DRC-065): one finding per pair closer than
/// the limit, measuring the Euclidean gap floored.
///
/// Oracle: gaps by construction: side by side, swept; diagonal at (60,
/// 79/80/81) beyond the first cut's corner, so the gap is exactly 99.2, 100
/// and 100.8 (a 60-80-100 triangle); two cuts on one layer abutting, and
/// touching only at a corner (one figure, no gap); a via2 stacked on a via1
/// (0).
#[test]
fn cut_space_measures_the_euclidean_gap() {
    let one = new_deck(&["cut"], "rule via.2 space(cut) >= 100nm\n");
    let two = new_deck(&["via1", "via2"], "rule v12 space(via1, via2) >= 100nm\n");
    let both = |name: &str, a: Rect, b: Rect, findings: Vec<Finding>| {
        check_everywhere(
            name,
            &one,
            &Layout::default().rects("cut", &[a, b]),
            &[("via.2", findings.clone())],
        );
        check_everywhere(
            name,
            &two,
            &Layout::default().rects("via1", &[a]).rects("via2", &[b]),
            &[("v12", findings)],
        );
    };
    for (g, side) in sweep(100) {
        both(
            &format!("side/{side}"),
            (0, 0, 100, 100),
            (100 + g, 0, 200 + g, 100),
            below(g, 100),
        );
    }
    for (dy, side, findings) in [
        (79, "below", lengths(&[99])),
        (80, "at", vec![]),
        (81, "above", vec![]),
    ] {
        both(
            &format!("diagonal/{side}"),
            (0, 0, 100, 100),
            (160, 100 + dy, 260, 200 + dy),
            findings,
        );
    }
    check_everywhere(
        "abutting",
        &one,
        &Layout::default().rects("cut", &[(0, 0, 100, 100), (100, 0, 200, 100)]),
        &[("via.2", vec![])],
    );
    check_everywhere(
        "stacked",
        &two,
        &Layout::default()
            .rect("via1", 0, 0, 100, 100)
            .rect("via2", 0, 0, 100, 100),
        &[("v12", lengths(&[0]))],
    );
    check_everywhere(
        "corner_touch",
        &one,
        &Layout::default().rects("cut", &[(0, 0, 100, 100), (100, 100, 200, 200)]),
        &[("via.2", vec![])],
    );
}

/// `space(cut, center) >= 300nm` (DRC-061): one finding per pair whose box
/// centres are closer than the limit, measuring that distance floored, at
/// the midpoint of the two centres.
///
/// Oracle: centres placed a chosen distance apart: two 100 squares, swept
/// (centres d apart, midpoint ((d + 100) / 2, 50)); a 100 and a 200 cut
/// whose centres are d apart while their edges are 150 closer; a 101 and a
/// 100 cut whose centres are d - 0.5 apart (floored to d - 1, so 300.5
/// passes); centre offsets (180, 239/240/241), 299.2, 300 and 300.8 apart
/// (a 180-240-300 triangle); overlapping cuts (50) and a cut nested in
/// another (0); a row of three at a 250 pitch (the outer pair, 500 apart,
/// passes).
#[test]
fn center_space_measures_centre_to_centre() {
    let deck = new_deck(&["cut"], "rule c2c space(cut, center) >= 300nm\n");
    let case = |name: &str, cuts: &[Rect], findings: Vec<Finding>| {
        check_everywhere(
            name,
            &deck,
            &Layout::default().rects("cut", cuts),
            &[("c2c", findings)],
        );
    };
    for (d, side) in sweep(300) {
        let pinned = below(d, 300)
            .into_iter()
            .map(|f| {
                if d % 2 == 0 {
                    f.at((d + 100) / 2, 50)
                } else {
                    f
                }
            })
            .collect();
        case(
            &format!("squares/{side}"),
            &[(0, 0, 100, 100), (d, 0, d + 100, 100)],
            pinned,
        );
        case(
            &format!("unequal/{side}"),
            &[(0, 0, 100, 100), (d - 50, 0, d + 150, 100)],
            below(d, 300),
        );
        case(
            &format!("half_unit/{side}"),
            &[(0, 0, 101, 100), (d, 0, d + 100, 100)],
            below(d - 1, 300),
        );
    }
    for (dy, side, findings) in [
        (239, "below", lengths(&[299])),
        (240, "at", vec![]),
        (241, "above", vec![]),
    ] {
        case(
            &format!("diagonal/{side}"),
            &[(0, 0, 100, 100), (180, dy, 280, dy + 100)],
            findings,
        );
    }
    case(
        "overlapping",
        &[(0, 0, 100, 100), (50, 0, 150, 100)],
        lengths(&[50]),
    );
    case(
        "nested",
        &[(0, 0, 300, 300), (100, 100, 200, 200)],
        lengths(&[0]),
    );
    case(
        "row_of_three",
        &[(0, 0, 100, 100), (250, 0, 350, 100), (500, 0, 600, 100)],
        lengths(&[250, 250]),
    );
}

/// `adjacent_space(cut; cuts: 3, within: 250nm) >= 220nm` (DRC-062, LEF
/// Spacing Rule Example 2) on 200 nm cuts, and `adjacent_space(cut,
/// center; cuts: 3, within: 300nm) >= 300nm` (Example 4) on 100 nm cuts: a
/// pair closer than the limit fails when either cut has at least three
/// other cuts strictly closer than `within`.
///
/// Oracle: the manual's Figure 1-6. With the diagonal beyond `within`, a
/// cut of a 1 x n row or a 2 x 2 array has two adjacent cuts, a middle cut
/// of a 3 x 2 array three, and the centre of a 3 x 3 four; so at a 219 gap
/// a row and a 2 x 2 pass, a 3 x 2 fails on the five pairs that touch its
/// middle cuts, a 3 x 3 on all twelve side pairs. A 3 x 2 array 219 apart
/// along its rows with its rows 249, 250, 251 apart holds its middle cuts
/// only at 249 (`within` is strict). For the centre form, a T of four at a
/// 299/300/301 pitch (its middle has three neighbours) and a 2 x 2 at 299
/// (two each, clean). `examined` counts the cuts held: the two middle
/// cuts of a 3 x 2 at 219.
#[test]
fn adjacent_space_holds_only_cuts_with_enough_neighbours() {
    let deck = new_deck(
        &["cut"],
        "rule adj adjacent_space(cut; cuts: 3, within: 250nm) >= 220nm\n",
    );
    let case = |name: &str, cuts: &[Rect], findings: Vec<Finding>| {
        check_everywhere(
            name,
            &deck,
            &Layout::default().rects("cut", cuts),
            &[("adj", findings)],
        );
    };
    let array = |cols: i64, rows: i64, gx: i64, gy: i64| -> Vec<Rect> {
        (0..cols)
            .flat_map(|c| {
                (0..rows).map(move |r| {
                    let (x, y) = (c * (200 + gx), r * (200 + gy));
                    (x, y, x + 200, y + 200)
                })
            })
            .collect()
    };
    for (g, side) in sweep(220) {
        let close = |n: usize| {
            if g < 220 {
                lengths(&vec![g; n])
            } else {
                vec![]
            }
        };
        case(&format!("row4/{side}"), &array(4, 1, g, g), vec![]);
        case(&format!("array2x2/{side}"), &array(2, 2, g, g), vec![]);
        case(&format!("array3x2/{side}"), &array(3, 2, g, g), close(5));
        case(&format!("array3x3/{side}"), &array(3, 3, g, g), close(12));
    }
    for (gy, side, findings) in [
        (249, "below", lengths(&[219; 4])),
        (250, "at", vec![]),
        (251, "above", vec![]),
    ] {
        case(
            &format!("rows_apart/{side}"),
            &array(3, 2, 219, gy),
            findings,
        );
    }
    let rows = run(
        &deck,
        &Layout::default().rects("cut", &array(3, 2, 219, 219)),
    );
    assert_eq!(
        row(&rows, "adj").examined,
        2,
        "the two middle cuts are held"
    );
    let centred = new_deck(
        &["cut"],
        "rule adjc adjacent_space(cut, center; cuts: 3, within: 300nm) >= 300nm\n",
    );
    for (p, side) in sweep(300) {
        check_everywhere(
            &format!("tee/{side}"),
            &centred,
            &Layout::default().rects(
                "cut",
                &[
                    (0, 0, 100, 100),
                    (-p, 0, 100 - p, 100),
                    (p, 0, 100 + p, 100),
                    (0, p, 100, 100 + p),
                ],
            ),
            &[("adjc", if p < 300 { lengths(&[p; 3]) } else { vec![] })],
        );
    }
    check_everywhere(
        "array2x2",
        &centred,
        &Layout::default().rects(
            "cut",
            &[
                (0, 0, 100, 100),
                (299, 0, 399, 100),
                (0, 299, 100, 399),
                (299, 299, 399, 399),
            ],
        ),
        &[("adjc", vec![])],
    );
}

/// `redundant_via(cut; within: 100nm) >= 2`, and `>= 3` (DRC-066,
/// DRC-117): one finding per drawn cut with fewer cuts, itself included,
/// within 100 nm (inclusive, Euclidean), measuring the count, at the cut's
/// centre.
///
/// Oracle: counts by construction: a pair side by side at 99/100/101; a
/// pair diagonal at Euclidean 99.2/100/100.8; one cut alone; two abutting
/// and two overlapping cuts (each counts the other); a row of three 100
/// apart, where the ends see two and the middle three.
#[test]
fn redundant_via_counts_the_cuts_within_reach() {
    let deck = new_deck(
        &["cut", "other"],
        "rule two redundant_via(cut; within: 100nm) >= 2\n\
         rule three redundant_via(cut; within: 100nm) >= 3\n",
    );
    let case = |name: &str, cuts: &[Rect], two: Vec<Finding>, three: Vec<Finding>| {
        check_everywhere(
            name,
            &deck,
            &Layout::default()
                .rect("other", -1000, -1000, -900, -900)
                .rects("cut", cuts),
            &[("two", two), ("three", three)],
        );
    };
    let at = |n: u32, centres: &[(i64, i64)]| -> Vec<Finding> {
        centres
            .iter()
            .map(|&(x, y)| Finding::count(n).at(x, y))
            .collect()
    };
    for (g, side) in sweep(100) {
        let centres = [(50, 50), (150 + g, 50)];
        let n = if g > 100 { 1 } else { 2 };
        case(
            &format!("pair/{side}"),
            &[(0, 0, 100, 100), (100 + g, 0, 200 + g, 100)],
            if g > 100 { at(1, &centres) } else { vec![] },
            at(n, &centres),
        );
    }
    for (dy, side, near) in [(79, "below", true), (80, "at", true), (81, "above", false)] {
        let n = if near { 2 } else { 1 };
        case(
            &format!("diagonal/{side}"),
            &[(0, 0, 100, 100), (160, 100 + dy, 260, 200 + dy)],
            if near {
                vec![]
            } else {
                vec![Finding::count(1); 2]
            },
            vec![Finding::count(n); 2],
        );
    }
    case(
        "single",
        &[(0, 0, 100, 100)],
        at(1, &[(50, 50)]),
        at(1, &[(50, 50)]),
    );
    case(
        "abutting",
        &[(0, 0, 100, 100), (100, 0, 200, 100)],
        vec![],
        vec![Finding::count(2); 2],
    );
    case(
        "overlapping",
        &[(0, 0, 100, 100), (50, 0, 150, 100)],
        vec![],
        vec![Finding::count(2); 2],
    );
    case(
        "row_of_three",
        &[(0, 0, 100, 100), (200, 0, 300, 100), (400, 0, 500, 100)],
        vec![],
        at(2, &[(50, 50), (450, 50)]),
    );
    case("empty", &[], vec![], vec![]);
}

/// LEF `MINIMUMCUT 2 WIDTH 0.11 LENGTH 2.0 WITHIN 0.5` on `m1` (Minimum Cut
/// Rule Example 4 scaled by a tenth): `min_cuts(via, m1, m2; width: 110nm,
/// length: 2000nm, distance: 500nm) >= 2` (DRC-066), "the rule applies for
/// thin wires directly connected to wide wires, if the wide wire has a
/// width that is greater than width and a length that is greater than
/// length, and the vias on the thin wire are less than distance from the
/// wide wire ... and does not check the wide wire itself". A one-cut via
/// held is one finding, its count 1, at the cut's centre.
///
/// Oracle: the LEF text and Figure 1-11, wires drawn to a width, a length
/// and a distance, each swept one step either side: a 50 wide stub up from
/// a 200 x 3000 bar with a 30 cut 499, 500 and 501 above the bar (held
/// below 500); the bar 1999, 2000 and 2001 long (held above 2000); the bar
/// 110 and 111 high (wide only above 110). Not held: a cut on the bar
/// itself, a two-cut via on the stub, a thin wire 100 off the bar.
#[test]
fn min_cuts_with_a_distance_holds_thin_wires_near_wide_ones() {
    let deck = new_deck(
        &["via", "m1", "m2"],
        "rule mct min_cuts(via, m1, m2; width: 110nm, length: 2000nm, distance: 500nm) >= 2\n",
    );
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(
            name,
            &deck,
            &layout.rect("m2", 900, -500, 1200, 3000),
            &[("mct", findings)],
        );
    };
    let stub = |long: i64, high: i64, gap: i64| {
        Layout::default()
            .rect("m1", 0, 0, long, high)
            .rect("m1", 1000, high, 1050, high + 2000)
            .rect("via", 1010, high + gap, 1040, high + gap + 30)
    };
    let one = |x: i64, y: i64| vec![Finding::count(1).at(x, y)];
    for (gap, side) in sweep(500) {
        let found = if gap < 500 {
            one(1025, 215 + gap)
        } else {
            vec![]
        };
        case(&format!("distance/{side}"), stub(3000, 200, gap), found);
    }
    for (long, side) in sweep(2000) {
        let found = if long > 2000 { one(1025, 315) } else { vec![] };
        case(&format!("length/{side}"), stub(long, 200, 100), found);
    }
    for (high, found) in [(110, vec![]), (111, one(1025, 226))] {
        case(&format!("width/{high}"), stub(3000, high, 100), found);
    }
    case(
        "on_the_wide_wire",
        Layout::default()
            .rect("m1", 0, 0, 3000, 200)
            .rect("via", 1010, 100, 1040, 130),
        vec![],
    );
    case(
        "two_cuts",
        stub(3000, 200, 100).rect("via", 1010, 360, 1040, 390),
        vec![],
    );
    case(
        "not_joined",
        Layout::default()
            .rect("m1", 0, 0, 3000, 200)
            .rect("m1", 1000, 300, 1050, 2300)
            .rect("via", 1010, 400, 1040, 430),
        vec![],
    );
}

/// LEF `MINIMUMCUT 2 WIDTH 1.0` on `m1`, vias from `m2`: `min_cuts(via, m1,
/// m2; width: 1000nm) >= 2` (`mc`) and with `within: 300nm` (`mcw`)
/// (DRC-066): a via is the cuts joining one `m1` figure to one `m2` figure,
/// split by `within` into groups of cuts closer than 300 nm; one held by
/// the part of `m1` wider than 1000 nm needs two cuts, and each of its cuts
/// is reported with its count.
///
/// Oracle: LEF/DEF 5.8 "the number of cuts a via must have when it is on a
/// wide wire or pin whose width is greater than width", on vias and wires
/// drawn to a count and a width: one cut under an `m2` pad; two under one
/// pad 200 apart (one via, one group) and 400 apart (two groups under
/// `within`); two cuts under two pads (two vias); a cut with no `m2` over
/// it; a wire 999, 1000, 1001 wide with one cut (held only when strictly
/// wider); a cut on a 500 tab off the plate; a cut on no `m1`.
#[test]
fn min_cuts_counts_the_cuts_of_each_via_on_a_wide_wire() {
    let deck = new_deck(
        &["via", "m1", "m2"],
        "rule mc min_cuts(via, m1, m2; width: 1000nm) >= 2\n\
         rule mcw min_cuts(via, m1, m2; width: 1000nm, within: 300nm) >= 2\n",
    );
    let case = |name: &str, layout: Layout, mc: &[u32], mcw: &[u32]| {
        let counts = |n: &[u32]| n.iter().map(|&c| Finding::count(c)).collect::<Vec<_>>();
        check_everywhere(
            name,
            &deck,
            &layout,
            &[("mc", counts(mc)), ("mcw", counts(mcw))],
        );
    };
    let plate = || Layout::default().rect("m1", 0, 0, 3000, 3000);
    case(
        "single",
        plate()
            .rect("via", 1000, 1000, 1100, 1100)
            .rect("m2", 900, 900, 1200, 1200),
        &[1],
        &[1],
    );
    for (gap, name, mcw) in [(200, "pair_close", &[][..]), (400, "pair_far", &[1, 1][..])] {
        let x = 1100 + gap;
        case(
            name,
            plate()
                .rect("via", 1000, 1000, 1100, 1100)
                .rect("via", x, 1000, x + 100, 1100)
                .rect("m2", 900, 900, x + 200, 1200),
            &[],
            mcw,
        );
    }
    case(
        "two_pads",
        plate()
            .rect("via", 1000, 1000, 1100, 1100)
            .rect("via", 1300, 1000, 1400, 1100)
            .rect("m2", 900, 900, 1150, 1200)
            .rect("m2", 1250, 900, 1500, 1200),
        &[1, 1],
        &[1, 1],
    );
    case(
        "no_far_metal",
        plate().rect("via", 1000, 1000, 1100, 1100),
        &[1],
        &[1],
    );
    for (w, held) in [(999, false), (1000, false), (1001, true)] {
        let one: &[u32] = if held { &[1] } else { &[] };
        case(
            &format!("wire/{w}"),
            Layout::default()
                .rect("m1", 0, 0, 5000, w)
                .rect("via", 2000, 100, 2100, 200)
                .rect("m2", 1900, 0, 2200, 300),
            one,
            one,
        );
    }
    case(
        "narrow_tab",
        plate()
            .rect("m1", 3000, 1000, 4000, 1500)
            .rect("via", 3500, 1200, 3600, 1300)
            .rect("m2", 3400, 1100, 3700, 1400),
        &[],
        &[],
    );
    case(
        "off_metal",
        plate()
            .rect("via", 5000, 5000, 5100, 5100)
            .rect("m2", 4900, 4900, 5200, 5200),
        &[],
        &[],
    );
}

/// `via_stack(v1, v2, v3, v4) <= 2` (DRC-065, LEF `MAXVIASTACK 2`): a cut
/// stacks on a cut of the layer below that it overlaps; the cut third from
/// the bottom of each stack taller than two is one finding, measuring the
/// stack's height.
///
/// Oracle: LEF/DEF 5.8 "a via is considered to be in a stack with another
/// via if the cut of the first via overlaps any part of the cut of the
/// second via", on 100 nm cuts stacked to a height: towers of two, three
/// and four (the four-high one reported once, measuring 4, at its third
/// cut's centre); three cuts overlapping by half; a v3 cut beside the v2
/// cut (two stacks of two); a v2 cut abutting the v1 cut (touching is not
/// stacking); a v1 bar under two v2 cuts each carrying a v3 (two stacks of
/// three).
#[test]
fn via_stack_reports_each_stack_taller_than_the_limit() {
    let deck = new_deck(
        &["v1", "v2", "v3", "v4"],
        "rule stack via_stack(v1, v2, v3, v4) <= 2\n",
    );
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("stack", findings)]);
    };
    let cut =
        |layout: Layout, layer: &str, x: i64, y: i64| layout.rect(layer, x, y, x + 100, y + 100);
    let tower = |height: usize| {
        ["v1", "v2", "v3", "v4"][..height]
            .iter()
            .fold(Layout::default(), |l, layer| cut(l, layer, 0, 0))
    };
    for (height, findings) in [
        (2, vec![]),
        (3, vec![Finding::count(3).at(50, 50)]),
        (4, vec![Finding::count(4).at(50, 50)]),
    ] {
        case(&format!("tower/{height}"), tower(height), findings);
    }
    case(
        "half_overlap",
        cut(
            cut(cut(Layout::default(), "v1", 0, 0), "v2", 50, 0),
            "v3",
            100,
            0,
        ),
        vec![Finding::count(3)],
    );
    case(
        "broken",
        cut(
            cut(
                cut(cut(Layout::default(), "v1", 0, 0), "v2", 0, 0),
                "v3",
                300,
                0,
            ),
            "v4",
            300,
            0,
        ),
        vec![],
    );
    case(
        "abutting",
        cut(
            cut(cut(Layout::default(), "v1", 0, 0), "v2", 100, 0),
            "v3",
            100,
            0,
        ),
        vec![],
    );
    case(
        "branching",
        Layout::default()
            .rect("v1", 0, 0, 300, 100)
            .rect("v2", 0, 0, 100, 100)
            .rect("v2", 200, 0, 300, 100)
            .rect("v3", 0, 0, 100, 100)
            .rect("v3", 200, 0, 300, 100),
        vec![Finding::count(3), Finding::count(3)],
    );
}

/// `via_stack(m1, v1, …, m5, single) <= 2` (DRC-065): LEF `MAXVIASTACK 2`
/// over single-cut vias only, "A double-cut or larger via interrupts the
/// stack".
///
/// Oracle: the LEF text's own example, "a via stack consisting of single
/// via12, single via23, double-cut via34, and single via45 has a single-cut
/// stack of height 2 for via12 and via23, and a single-cut stack of height
/// 1 for via45" (legal at 2); three single cuts stacked (height 3, at its
/// top cut's centre); the same with the middle via doubled (no stack over
/// 1); a tower of four single cuts where a second v2 cut sits on another
/// m3 figure (each via still single: height 4).
#[test]
fn via_stack_single_counts_only_single_cut_vias() {
    let deck = new_deck(
        &["m1", "v1", "m2", "v2", "m3", "v3", "m4", "v4", "m5"],
        "rule stack via_stack(m1, v1, m2, v2, m3, v3, m4, v4, m5, single) <= 2\n",
    );
    let tower = |cuts: &[&str], double: &[&str]| {
        let mut layout = Layout::default();
        for m in ["m1", "m2", "m3", "m4", "m5"] {
            layout = layout.rect(m, -100, -100, 500, 200);
        }
        for &v in cuts {
            layout = layout.rect(v, 0, 0, 100, 100);
        }
        for &v in double {
            layout = layout.rect(v, 300, 0, 400, 100);
        }
        layout
    };
    let top = |n: u32| vec![Finding::count(n).at(50, 50)];
    for (name, layout, findings) in [
        (
            "lef_example",
            tower(&["v1", "v2", "v3", "v4"], &["v3"]),
            vec![],
        ),
        ("three_single", tower(&["v1", "v2", "v3"], &[]), top(3)),
        ("middle_double", tower(&["v1", "v2", "v3"], &["v2"]), vec![]),
        (
            "split_pads",
            tower(&["v1", "v2", "v3", "v4"], &[])
                .rect("m3", 1000, -100, 1500, 200)
                .rect("v2", 1100, 0, 1200, 100),
            top(4),
        ),
    ] {
        check_everywhere(name, &deck, &layout, &[("stack", findings)]);
    }
}

/// `LEF58_METALWIDTHVIAMAP` (`via_map`, DRC-067), as `OpenROAD` parses it
/// (`VIA cutLayer w1 w2 viaName`): `vm`, exact widths 50 and 80 with a 30
/// x 30 cut; `vr`, ranges 40..60 and 70..90 with a 30 x 40 cut, either way
/// round. A cut where the widths fall in the row's bands but whose size is
/// not the mapped cut is one finding measuring a count of 0.
///
/// Oracle: the parser's grammar, wires drawn to a width: an `m1` bar `w1`
/// high crossing an `m2` bar `w2` wide, a cut where they cross. The mapped
/// cut passes, a 40 x 40 cut fails both rows while both widths are in
/// their bands: `w1` swept around 50 (only 50 is `vm`'s) and `w2` around 80
/// (only 80); a 40 x 30 cut is `vr`'s 30 x 40 turned; a cut off the bars is
/// held by neither.
#[test]
fn via_map_flags_a_wrong_cut_between_mapped_widths() {
    let deck = new_deck(
        &["v1", "m1", "m2"],
        "rule vm via_map(v1, m1, m2; below_min: 50nm, below_max: 50nm, above_min: 80nm, \
         above_max: 80nm, cut: 30nm x 30nm)\n\
         rule vr via_map(v1, m1, m2; below_min: 40nm, below_max: 60nm, above_min: 70nm, \
         above_max: 90nm, cut: 30nm x 40nm)\n",
    );
    let case = |name: &str, w1: i64, w2: i64, (cw, ch): (i64, i64), vm: bool, vr: bool| {
        let layout = Layout::default()
            .rect("m1", 0, 0, 1000, w1)
            .rect("m2", 460, -500, 460 + w2, 500)
            .rect("v1", 480, 5, 480 + cw, 5 + ch);
        let found = |wrong: bool| {
            if wrong {
                vec![Finding::count(0)]
            } else {
                vec![]
            }
        };
        check_everywhere(
            name,
            &deck,
            &layout,
            &[("vm", found(vm)), ("vr", found(vr))],
        );
    };
    case("mapped", 50, 80, (30, 30), false, true);
    case("range_mapped", 50, 80, (30, 40), true, false);
    case("range_turned", 50, 80, (40, 30), true, false);
    for (w1, side) in sweep(50) {
        case(&format!("below/{side}"), w1, 80, (40, 40), w1 == 50, true);
    }
    for (w2, side) in sweep(80) {
        case(&format!("above/{side}"), 50, w2, (40, 40), w2 == 80, true);
    }
    check_everywhere(
        "off_the_wires",
        &deck,
        &Layout::default()
            .rect("m1", 0, 0, 1000, 50)
            .rect("m2", 460, -500, 540, 500)
            .rect("v1", 2000, 2000, 2040, 2040),
        &[("vm", vec![]), ("vr", vec![])],
    );
}

/// `stack_space(v2, v1, m2; same_net: true) >= 200nm` (`ss`, LEF Spacing
/// Rule Example 7's `SPACING 0.20 SAMENET LAYER cut12 STACK`) and
/// `stack_space(v2, v1, m2) >= 200nm` (`all`) (DRC-065): "same-net cuts on
/// two different layers can be stacked if they are aligned. If the cuts
/// are not the same size, the smaller cut must be completely covered by the
/// larger cut ... If both cuts are the same size, the centers of the cuts
/// must be aligned ... otherwise, the cuts must have cutSpacing between
/// them".
///
/// Oracle: the LEF text, cuts by construction, one net through pads on
/// every metal unless stated: aligned equal cuts and a cut covered by a
/// larger one (stacked, legal); equal cuts offset by half (overlapping, not
/// aligned: a gap of 0); a `v1` cut beside the `v2` cut 199, 200 and 201
/// away; two cuts 150 apart on different nets, which only `all` holds.
#[test]
fn stack_space_exempts_only_aligned_same_net_stacks() {
    let deck = new_deck(
        &["m1", "v1", "m2", "v2", "m3"],
        "connect conductors [m1, m2, m3]\nconnect touch_within_layer\n\
         connect via v1 [m1, m2]\nconnect via v2 [m2, m3]\n\
         rule ss stack_space(v2, v1, m2; same_net: true) >= 200nm\n\
         rule all stack_space(v2, v1, m2) >= 200nm\n",
    );
    let case = |name: &str, layout: Layout, ss: Vec<Finding>, all: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("ss", ss), ("all", all)]);
    };
    let pads = |layout: Layout| {
        ["m1", "m2", "m3"]
            .iter()
            .fold(layout, |l, m| l.rect(m, -500, -500, 1000, 600))
    };
    case(
        "aligned",
        pads(Layout::default())
            .rect("v1", 0, 0, 100, 100)
            .rect("v2", 0, 0, 100, 100),
        vec![],
        vec![],
    );
    case(
        "covered",
        pads(Layout::default())
            .rect("v1", -20, -20, 120, 120)
            .rect("v2", 0, 0, 100, 100),
        vec![],
        vec![],
    );
    case(
        "offset",
        pads(Layout::default())
            .rect("v1", 50, 0, 150, 100)
            .rect("v2", 0, 0, 100, 100),
        lengths(&[0]),
        lengths(&[0]),
    );
    for (g, side) in sweep(200) {
        let near = below(g, 200);
        case(
            &format!("apart/{side}"),
            pads(Layout::default())
                .rect("v1", 100 + g, 0, 200 + g, 100)
                .rect("v2", 0, 0, 100, 100),
            near.clone(),
            near,
        );
    }
    let two_nets = ["m1", "m2", "m3"]
        .iter()
        .fold(Layout::default(), |l, m| {
            l.rect(m, -100, -100, 200, 200).rect(m, 250, -100, 550, 200)
        })
        .rect("v1", 250, 0, 350, 100)
        .rect("v2", 0, 0, 100, 100);
    case("different_nets", two_nets, vec![], lengths(&[150]));
}

/// The redundant-via rate (`via_redundancy`, DRC-117, Xu et al. ASP-DAC
/// 2005 with deck-supplied values): cuts `v` 100 square between `m1` and
/// `m2`, a second cut 200 along an axis, 100 from every cut, a rate of 0.5
/// signing off.
///
/// Oracle: the rate `1 - dead / vias` by hand: a cut on a 1000 square pad
/// (room: rate 1), on pads no larger than itself (dead: 0, found), two cuts
/// on such a pad (doubled already: 1); a cut whose only free neighbour
/// lies 99, 100, 101 from a stray cut (dead at 99: found); one dead of two
/// vias (0.5, at the sign-off) and two of three (1/3, found).
#[test]
fn via_redundancy_rates_the_vias_with_room_for_a_second_cut() {
    let deck = new_deck(
        &["v", "m1", "m2"],
        "rule vr via_redundancy(v, m1, m2; pitch: 200nm, space: 100nm) >= 0.5\n",
    );
    let pad = |layout: Layout, (xlo, ylo, xhi, yhi): Rect| {
        layout
            .rect("m1", xlo, ylo, xhi, yhi)
            .rect("m2", xlo, ylo, xhi, yhi)
    };
    let tight =
        |layout: Layout, x: i64| pad(layout, (x, 0, x + 100, 100)).rect("v", x, 0, x + 100, 100);
    let roomy = |layout: Layout| pad(layout, (0, 0, 1000, 1000)).rect("v", 100, 100, 200, 200);
    let rate = |dead: u32, vias: u32| -> Vec<Finding> {
        let r = 1.0 - f64::from(dead) / f64::from(vias);
        if r < 0.5 {
            vec![Finding::ratio(r)]
        } else {
            Vec::new()
        }
    };
    let case = |name: &str, layout: Layout, found: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("vr", found)]);
    };
    case("room", roomy(Layout::default()), rate(0, 1));
    case("no_room", tight(Layout::default(), 0), rate(1, 1));
    case(
        "doubled",
        pad(Layout::default(), (0, 0, 100, 300))
            .rect("v", 0, 0, 100, 100)
            .rect("v", 0, 200, 100, 300),
        rate(0, 1),
    );
    case(
        "one_of_two",
        tight(roomy(Layout::default()), 3000),
        rate(1, 2),
    );
    case(
        "two_of_three",
        tight(tight(roomy(Layout::default()), 3000), 5000),
        rate(2, 3),
    );
    for (gap, side) in sweep(100) {
        case(
            &format!("stray/{side}"),
            Layout::default()
                .rect("m1", 0, 0, 2000, 300)
                .rect("m2", 100, 0, 400, 300)
                .rect("v", 100, 100, 200, 200)
                .rect("v", 400 + gap, 100, 500 + gap, 200),
            rate(u32::from(gap < 100), 1),
        );
    }
}

/// A connector's cut area between two databases (`cut_area_change`,
/// DRC-068, sky130 ct.irdrop in shape with deck-supplied values): pre cuts
/// on `v`, post cuts on `vc`, connectors `m1` x `m2`; bands from 1 cut
/// allow 10000 nm², from 4 cuts 40000 nm².
///
/// Oracle: areas by hand: three 100 nm pre cuts (30000) on one connector
/// against post 19999, 20000, 20001 (a change of 10001, 10000, 9999: one
/// finding of 10001); four pre cuts against none (40000, allowed) and five
/// (50000, found); two connectors on one m1 bar of two pre cuts each, only
/// the one whose cuts went missing found (20000); two pre cuts on m1 off m2
/// count for nothing; a connector with post cuts and no pre cut is not
/// judged; a post cut half off the footprint counts its inside half (a
/// change of 10000, allowed; the whole cut would be 30000).
#[test]
fn cut_area_change_holds_each_connector_to_its_band() {
    let deck = new_deck(
        &["v", "vc", "m1", "m2"],
        "rule ir cut_area_change(v, vc, m1, m2; cuts: [1, 4], change: [10000nm2, 40000nm2])\n",
    );
    let pad = |layout: Layout, x: i64| {
        layout
            .rect("m1", x, 0, x + 1000, 1000)
            .rect("m2", x, 0, x + 1000, 1000)
    };
    let pre = |layout: Layout, x: i64, n: i64| {
        (0..n).fold(layout, |layout, i| {
            layout.rect("v", x + 50 + 150 * i, 50, x + 150 + 150 * i, 150)
        })
    };
    let case = |name: &str, layout: Layout, found: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("ir", found)]);
    };
    let three = || pre(pad(Layout::default(), 0), 0, 3);
    case(
        "post_19999",
        three()
            .rect("vc", 0, 500, 100, 699)
            .rect("vc", 0, 699, 99, 700),
        areas(&[10_001]),
    );
    case(
        "post_20000",
        three().rect("vc", 0, 500, 100, 700),
        Vec::new(),
    );
    case(
        "post_20001",
        three()
            .rect("vc", 0, 500, 100, 700)
            .rect("vc", 500, 500, 501, 501),
        Vec::new(),
    );
    case(
        "four_lost",
        pre(pad(Layout::default(), 0), 0, 4),
        Vec::new(),
    );
    case(
        "five_lost",
        pre(pad(Layout::default(), 0), 0, 5),
        areas(&[50_000]),
    );
    case(
        "one_lost_of_two",
        pre(
            pre(
                Layout::default()
                    .rect("m1", 0, 0, 3000, 1000)
                    .rect("m2", 0, 0, 1000, 1000)
                    .rect("m2", 2000, 0, 3000, 1000),
                0,
                2,
            ),
            2000,
            2,
        )
        .rect("vc", 2050, 50, 2150, 150)
        .rect("vc", 2200, 50, 2300, 150),
        areas(&[20_000]),
    );
    case(
        "off_the_upper",
        pad(Layout::default(), 0)
            .rect("m1", 1000, 0, 2000, 1000)
            .rect("v", 1200, 200, 1300, 300)
            .rect("v", 1400, 200, 1500, 300),
        Vec::new(),
    );
    case(
        "post_only",
        pad(Layout::default(), 0).rect("vc", 100, 100, 600, 600),
        Vec::new(),
    );
    case(
        "post_half_off",
        pre(pad(Layout::default(), 0), 0, 1).rect("vc", 800, 400, 1200, 500),
        Vec::new(),
    );
}
