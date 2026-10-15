//! The two-layer overlay kinds through deck text: the enclosure readings
//! (`opposite`, `noncoincident`, by wire width), `full_width`,
//! `max_enclosure`, `extension`, `bend`/`covers_corner` and `projection`
//! spacing. Each case is the root `tests/exhaustive/drc_overlay.rs` fixture
//! of the same name, its oracle restated on the test, run through this
//! crate's deck compiler and rule set.

use crate::common::deck::{
    below, check_everywhere, lengths, new_deck, row, run, sweep, Finding, Layout,
};
use gpurify_check::report::Measurement;

type Rect = (i64, i64, i64, i64);

/// An L-shaped host, `[0, 2000] x [0, 1000]` with `[0, 1000] x [0, 2000]`:
/// its concave corner is `(1000, 1000)`.
const L_HOST: [(i64, i64); 6] = [
    (0, 0),
    (2000, 0),
    (2000, 1000),
    (1000, 1000),
    (1000, 2000),
    (0, 2000),
];

/// A plus-shaped host, bars `[0, 1000] x [400, 600]` and `[400, 600] x [0,
/// 1000]`.
const PLUS_HOST: [(i64, i64); 12] = [
    (400, 0),
    (600, 0),
    (600, 400),
    (1000, 400),
    (1000, 600),
    (600, 600),
    (600, 1000),
    (400, 1000),
    (400, 600),
    (0, 600),
    (0, 400),
    (400, 400),
];

/// `enclosure(via, met1, opposite) >= 100nm` (DRC-041, DRC-042): each edge
/// of a via is read straight out to the nearest host edge facing it; the
/// via measures `max(min over its vertical edges, min over its horizontal
/// edges)`, for a rectangle `max(min(left, right), min(bottom, top))`.
///
/// Oracle: every margin drawn, so each straight-out reading is a number the
/// layout was built to have: the limit on one axis with the other touching;
/// one side short with the other axis far; both axes short; a host with
/// notches down to the via on two sides; the plus host (straight strips
/// 450); an L via swept; an L via with the limit only along x (clean); an L
/// via whose concave top edge decides the y axis while a notch 50 right of
/// its upper arm spoils x only while it reaches below y = 200; an unhosted
/// via (0).
#[test]
fn opposite_enclosure_reads_each_edge_straight_out() {
    let deck = new_deck(
        &["via", "met1"],
        "rule m1.5 enclosure(via, met1, opposite) >= 100nm\n",
    );
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("m1.5", findings)]);
    };
    let hosted = |(l, r, b, t): Rect| {
        Layout::default()
            .rect("via", 0, 0, 100, 100)
            .rect("met1", -l, -b, 100 + r, 100 + t)
    };
    let measure = |(l, r, b, t): Rect| below(l.min(r).max(b.min(t)), 100);
    let l_via = [
        (0, 0),
        (200, 0),
        (200, 100),
        (100, 100),
        (100, 200),
        (0, 200),
    ];
    for (m, side) in sweep(100) {
        for (name, margins) in [
            ("x_axis", (m, m, 0, 0)),
            ("y_axis", (0, 0, m, m)),
            ("one_side_short", (m, 400, 0, 400)),
            ("both_axes_short", (m, 400, 400, 99)),
        ] {
            case(&format!("{name}/{side}"), hosted(margins), measure(margins));
        }
        let notched = [
            (-400, -400),
            (500, -400),
            (500, 0),
            (100 + m, 0),
            (100 + m, 100),
            (500, 100),
            (500, 500),
            (100, 500),
            (100, 100 + m),
            (0, 100 + m),
            (0, 500),
            (-400, 500),
        ];
        case(
            &format!("notched_host/{side}"),
            Layout::default()
                .rect("via", 0, 0, 100, 100)
                .polygon("met1", &notched),
            below(m, 100),
        );
        case(
            &format!("l_via/{side}"),
            Layout::default()
                .polygon("via", &l_via)
                .rect("met1", -m, -m, 200 + m, 200 + m),
            below(m, 100),
        );
    }
    case("every_side_zero", hosted((0, 0, 0, 0)), lengths(&[0]));
    case(
        "plus_host",
        Layout::default()
            .rect("via", 450, 450, 550, 550)
            .polygon("met1", &PLUS_HOST),
        Vec::new(),
    );
    case(
        "l_via_one_axis",
        Layout::default()
            .polygon("via", &l_via)
            .rect("met1", -100, 0, 300, 200),
        Vec::new(),
    );
    for (k, side) in sweep(100) {
        let host = [
            (-100, -100),
            (300, -100),
            (300, 300),
            (250, 300),
            (250, 100 + k),
            (150, 100 + k),
            (150, 300),
            (-100, 300),
        ];
        let x = if 100 + k < 200 { 50 } else { 100 };
        case(
            &format!("l_via_concave_edge/{side}"),
            Layout::default()
                .polygon("via", &l_via)
                .polygon("met1", &host),
            below(x.max(k.min(100)), 100),
        );
    }
    case(
        "unhosted",
        Layout::default()
            .rect("via", 0, 0, 100, 100)
            .rect("met1", 50, -400, 600, 500),
        lengths(&[0]),
    );
}

/// Enclosure by wire width, LEF/DEF 5.8 Example 1-3's `via23` in nm:
/// `narrow` (opposite, below 1000), `mid` (1000 to 2000) and `wide` (from
/// 2000) (DRC-043): each 200 nm via is held by the one row whose band holds
/// the width of the wire it lies on, an unhosted via by the lowest.
///
/// Oracle: wires drawn to a width, margins 15 left and 30 below: `narrow`
/// reads `max(min(15, far), min(30, far)) = 30`, the others 15. Widths 999,
/// 1000, 1001, 1999, 2000, 2001 (inclusive below, exclusive above); a via on
/// a 500 tab off a 3000 plate (the tab's width: `narrow`, 20); a via 40 into
/// the plate's corner (`wide`, 40); an unhosted via (`narrow`, 0).
#[test]
fn enclosure_by_wire_width_holds_each_via_to_its_band() {
    let deck = new_deck(
        &["via", "met2"],
        "rule narrow enclosure(via, met2, opposite; below: 1000nm) >= 50nm\n\
         rule mid enclosure(via, met2; width: 1000nm, below: 2000nm) >= 20nm\n\
         rule wide enclosure(via, met2; width: 2000nm) >= 50nm\n",
    );
    let case = |name: &str, layout: Layout, [narrow, mid, wide]: [Vec<Finding>; 3]| {
        check_everywhere(
            name,
            &deck,
            &layout,
            &[("narrow", narrow), ("mid", mid), ("wide", wide)],
        );
    };
    let via = || Layout::default().rect("via", 0, 0, 200, 200);
    for w in [999, 1000, 1001, 1999, 2000, 2001] {
        let rows = if w < 1000 {
            [lengths(&[30]), vec![], vec![]]
        } else if w < 2000 {
            [vec![], lengths(&[15]), vec![]]
        } else {
            [vec![], vec![], lengths(&[15])]
        };
        case(
            &format!("wire/{w}"),
            via().rect("met2", -15, -30, 3000, w - 30),
            rows,
        );
    }
    case(
        "tab",
        Layout::default()
            .rect("met2", 0, 0, 3000, 3000)
            .rect("met2", 3000, 1000, 3800, 1500)
            .rect("via", 3580, 1150, 3780, 1490),
        [lengths(&[20]), vec![], vec![]],
    );
    case(
        "plate",
        Layout::default()
            .rect("met2", 0, 0, 3000, 3000)
            .rect("via", 40, 40, 240, 240),
        [vec![], vec![], lengths(&[40])],
    );
    case(
        "unhosted",
        via().rect("met2", 5000, 5000, 6000, 6000),
        [lengths(&[0]), vec![], vec![]],
    );
}

/// `enclosure(lvtn, nwell, noncoincident) >= 380nm` (DRC-054, sky130
/// lvtn.10 "(exclude coincident edges)") beside the plain `enclosure(lvtn,
/// nwell) >= 380nm`: an lvtn edge lying on the nwell's edge, or an lvtn
/// corner touching it, is exempt from the first and measures 0 under the
/// second.
///
/// Oracle: drawn margins, the touching pairs drawn to coincide; lvtn is
/// `[0, 1000]²`: concentric at 379/380/381 (both alike); the left edge on
/// the nwell's, the other margins swept; the corner on two edges; the left
/// edge on the nwell's for its lower half only, the nwell stepping 400 out
/// above it (exempt, then 400); lvtn in an L nwell's concave corner,
/// touching it only there (exempt; 600 elsewhere); an unhosted lvtn (0).
/// The finding sits in the middle of the gap of the pair that measured it:
/// with the left side 100 off and the rest 600, at `(-50, 500)`.
#[test]
fn noncoincident_enclosure_exempts_touching_edges() {
    let deck = new_deck(
        &["lvtn", "nwell"],
        "rule lvtn.10 enclosure(lvtn, nwell, noncoincident) >= 380nm\n\
         rule plain enclosure(lvtn, nwell) >= 380nm\n",
    );
    let case = |name: &str, layout: Layout, apart: Vec<Finding>, plain: Vec<Finding>| {
        check_everywhere(
            name,
            &deck,
            &layout,
            &[("lvtn.10", apart), ("plain", plain)],
        );
    };
    let lvtn = || Layout::default().rect("lvtn", 0, 0, 1000, 1000);
    for (m, side) in sweep(380) {
        case(
            &format!("concentric/{side}"),
            lvtn().rect("nwell", -m, -m, 1000 + m, 1000 + m),
            below(m, 380),
            below(m, 380),
        );
        case(
            &format!("left_on_edge/{side}"),
            lvtn().rect("nwell", 0, -m, 1000 + m, 1000 + m),
            below(m, 380),
            lengths(&[0]),
        );
        case(
            &format!("corner_on_edges/{side}"),
            lvtn().rect("nwell", 0, 0, 1000 + m, 1000 + m),
            below(m, 380),
            lengths(&[0]),
        );
    }
    case(
        "partly_on_edge",
        lvtn().polygon(
            "nwell",
            &[
                (0, -400),
                (1400, -400),
                (1400, 1400),
                (-400, 1400),
                (-400, 500),
                (0, 500),
            ],
        ),
        vec![],
        lengths(&[0]),
    );
    case(
        "kissing_corner",
        Layout::default()
            .rect("lvtn", 600, 600, 1000, 1000)
            .polygon("nwell", &L_HOST),
        vec![],
        lengths(&[0]),
    );
    case(
        "unhosted",
        lvtn().rect("nwell", 2000, 2000, 3000, 3000),
        lengths(&[0]),
        lengths(&[0]),
    );
    // One short side, the rest far: the finding is in that gap's middle.
    let rows = run(&deck, &lvtn().rect("nwell", -100, -600, 1600, 1600));
    assert_eq!(
        row(&rows, "lvtn.10").findings,
        [(
            Measurement::Length(gpurify_testgen::dbu(100)),
            Measurement::Length(gpurify_testgen::dbu(380)),
            (-50, 500)
        )]
    );
}

/// `enclosure(via, met1, adjacent)` (sky130 li.5's "one of two adjacent
/// sides"): the least, over the via's convex corners, of the better of the
/// two edges meeting there, each read straight out from just inside that
/// corner's end of the edge.
///
/// Oracle: readings by construction. The via is `[0, 100]²`; the host is
/// `[-50, 200] x [0, 200]` over `[-10, 200] x [-20, 0]`, its left side
/// stepping in from 50 to 10 exactly at the via's bottom. At (0, 0) the
/// left edge reads 50 (the step's lower edge ends at y = 0 and covers none
/// of the side) and the bottom edge 20: better 50. The other corners' better
/// edges read 100. So `>= 51nm` finds 50 and `>= 50nm` nothing.
#[test]
fn adjacent_enclosure_reads_a_side_from_just_inside_its_end() {
    let layout = Layout::default()
        .rect("via", 0, 0, 100, 100)
        .rect("met1", -50, 0, 200, 200)
        .rect("met1", -10, -20, 200, 0);
    check_everywhere(
        "step_at_the_corner",
        &new_deck(
            &["via", "met1"],
            "rule a51 enclosure(via, met1, adjacent) >= 51nm\n\
             rule a50 enclosure(via, met1, adjacent) >= 50nm\n",
        ),
        &layout,
        &[("a51", lengths(&[50])), ("a50", vec![])],
    );
}

/// `full_width(v1, m2)` (DRC-053, ASAP7 V1.M2.AUX.2 "V1 must exactly be the
/// same width as M2 along the direction perpendicular to the M2 length"):
/// one finding per via that meets the wire's edges on neither axis,
/// measuring the widest straight-out gap on its better axis.
///
/// Oracle: drawn gaps, a 100 nm via: spanning a 100 wide horizontal wire
/// (clean); 0 or 1 short of its top edge; 10 short of both; in a vertical
/// wire (clean); on a 300 pad (100 every side); on an equal pad (clean); off
/// the wire (not measured).
#[test]
fn full_width_wants_the_via_as_wide_as_its_wire() {
    let deck = new_deck(&["v1", "m2"], "rule V1.M2.AUX.2 full_width(v1, m2)\n");
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("V1.M2.AUX.2", findings)]);
    };
    let wire = || Layout::default().rect("m2", -500, 0, 1000, 100);
    for short in [0, 1] {
        case(
            &format!("top_short/{short}"),
            wire().rect("v1", 0, 0, 100, 100 - short),
            if short > 0 { lengths(&[short]) } else { vec![] },
        );
    }
    case(
        "narrower",
        wire().rect("v1", 0, 10, 100, 90),
        lengths(&[10]),
    );
    case(
        "vertical_wire",
        Layout::default()
            .rect("m2", 0, -200, 100, 1000)
            .rect("v1", 0, 0, 100, 100),
        vec![],
    );
    case(
        "pad",
        Layout::default()
            .rect("m2", -100, -100, 200, 200)
            .rect("v1", 0, 0, 100, 100),
        lengths(&[100]),
    );
    case(
        "equal_pad",
        Layout::default()
            .rect("m2", 0, 0, 100, 100)
            .rect("v1", 0, 0, 100, 100),
        vec![],
    );
    case("off_wire", wire().rect("v1", 3000, 0, 3100, 100), vec![]);
}

/// `space(lvtn, sd, projection) >= 235nm` (DRC-055, sky130 lvtn.3b) beside
/// the Euclidean `space(lvtn, sd) >= 235nm`: a pair is measured across
/// facing edges that overlap in projection.
///
/// Oracle: drawn gaps, lvtn `[0, 500]²`: sd beside it at 234/235/236; sd
/// diagonally (100, 100) off its corner (clean, Euclid floor(100√2) = 141);
/// sd overlapping lvtn's side by 1 of projection, 100 away; sd whose
/// projection meets lvtn's at a point, 50 away (clean, Euclid 50); sd
/// touching and overlapping (0 for both).
#[test]
fn projection_space_measures_only_facing_edges() {
    let deck = new_deck(
        &["lvtn", "sd"],
        "rule lvtn.3b space(lvtn, sd, projection) >= 235nm\n\
         rule euclid space(lvtn, sd) >= 235nm\n",
    );
    let case = |name: &str, (a, b, c, d): Rect, projection: Vec<Finding>, euclid: Vec<Finding>| {
        check_everywhere(
            name,
            &deck,
            &Layout::default()
                .rect("lvtn", 0, 0, 500, 500)
                .rect("sd", a, b, c, d),
            &[("lvtn.3b", projection), ("euclid", euclid)],
        );
    };
    for (g, side) in sweep(235) {
        case(
            &format!("beside/{side}"),
            (500 + g, 100, 900 + g, 400),
            below(g, 235),
            below(g, 235),
        );
    }
    case("diagonal", (600, 600, 900, 900), vec![], lengths(&[141]));
    case(
        "one_unit_of_projection",
        (600, 499, 900, 900),
        lengths(&[100]),
        lengths(&[100]),
    );
    case(
        "projection_meets_at_a_point",
        (550, 500, 900, 900),
        vec![],
        lengths(&[50]),
    );
    case(
        "touching",
        (500, 100, 900, 400),
        lengths(&[0]),
        lengths(&[0]),
    );
    case(
        "overlapping",
        (400, 100, 900, 400),
        lengths(&[0]),
        lengths(&[0]),
    );
}

/// `enclosure(licon, npc) <= 95nm` (DRC-044, sky130 npc.5): each npc figure
/// holding licons must lie inside their union grown by 95 nm with square
/// corners; one finding per npc figure that reaches further, measuring its
/// furthest reach rounded up.
///
/// Oracle: the reach is drawn. A licon `[0, 100]²` in npc 50 past it on
/// three sides and `m` on the fourth reaches `max(50, m)`, swept 94/95/96;
/// a corner square to (195, 195) and (196, 196) reaches its Chebyshev 95
/// and 96 though every straight strip reads 50; two licons 190, 191, 192
/// apart under one npc reach 95, 95.5 (up to 96) and 96 midway; an npc
/// holding no licon and one only straddled by a licon are not measured.
#[test]
fn max_enclosure_measures_the_furthest_reach() {
    let deck = new_deck(
        &["licon", "npc"],
        "rule npc.5 enclosure(licon, npc) <= 95nm\n",
    );
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("npc.5", findings)]);
    };
    let above = |reach: i64| {
        if reach > 95 {
            lengths(&[reach])
        } else {
            vec![]
        }
    };
    let licon = || Layout::default().rect("licon", 0, 0, 100, 100);
    for (m, side) in sweep(95) {
        case(
            &format!("side/{side}"),
            licon().rect("npc", -50, -50, 100 + m, 150),
            above(m),
        );
    }
    for c in [195, 196] {
        case(
            &format!("corner/{c}"),
            licon()
                .rect("npc", -50, -50, 150, 150)
                .rect("npc", 100, 100, c, c),
            above(c - 100),
        );
    }
    for (g, reach) in [(190, 95), (191, 96), (192, 96)] {
        case(
            &format!("two_licons/{g}"),
            licon()
                .rect("licon", 100 + g, 0, 200 + g, 100)
                .rect("npc", -50, -50, 250 + g, 150),
            above(reach),
        );
    }
    case(
        "holding_nothing",
        licon()
            .rect("npc", -50, -50, 150, 150)
            .rect("npc", 1000, 1000, 2000, 2000),
        vec![],
    );
    case(
        "straddled",
        licon().rect("npc", 50, -500, 1000, 500),
        vec![],
    );
}

/// `extension(poly, diff) >= 100nm` (DRC-045): a poly crossing diffusion
/// must run past each diffusion edge it crosses by the limit; one finding
/// per offending pair, measuring the shortest such run, 0 where the poly
/// stops inside the diffusion or at its edge.
///
/// Oracle: drawn runs, diffusion `[0, 1000] x [0, 400]`: a gate with both
/// ends at the swept length; one end swept with the other far; a poly
/// covering the diffusion; a U poly whose far arm makes its box reach past
/// every side while the gate end is swept; a gate over a step in the
/// diffusion's edge (the step's edge faces sideways); a gate ending inside
/// (0); a poly abutting without crossing, also with a short far end (no
/// gate: clean); a split diffusion crossed with 200 to spare.
#[test]
fn extension_measures_the_shortest_run_past_the_diffusion() {
    let deck = new_deck(
        &["diff", "poly"],
        "rule poly.8 extension(poly, diff) >= 100nm\n",
    );
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        check_everywhere(name, &deck, &layout, &[("poly.8", findings)]);
    };
    let diff = || Layout::default().rect("diff", 0, 0, 1000, 400);
    let gate = |bottom: i64, top: i64| {
        (
            diff().rect("poly", 400, -bottom, 500, 400 + top),
            below(bottom.min(top).max(0), 100),
        )
    };
    for (m, side) in sweep(100) {
        let (layout, findings) = gate(m, m);
        case(&format!("crossing/{side}"), layout, findings);
        let (layout, findings) = gate(500, m);
        case(&format!("one_end/{side}"), layout, findings);
        case(
            &format!("covering/{side}"),
            diff().rect("poly", -m, -m, 1000 + m, 400 + m),
            below(m, 100),
        );
        let u = [
            (400, -200),
            (1300, -200),
            (1300, 1000),
            (1200, 1000),
            (1200, -100),
            (500, -100),
            (500, 400 + m),
            (400, 400 + m),
        ];
        case(
            &format!("u_shape/{side}"),
            diff().polygon("poly", &u),
            below(m, 100),
        );
        case(
            &format!("diffusion_jog/{side}"),
            Layout::default()
                .rect("diff", 0, 0, 450, 400)
                .rect("diff", 450, 0, 1000, 300)
                .rect("poly", 400, -m, 500, 600),
            below(m, 100),
        );
    }
    let (layout, findings) = gate(500, -100);
    case("ends_inside", layout, findings);
    case(
        "abutting",
        diff().rect("poly", 400, 400, 500, 900),
        Vec::new(),
    );
    case(
        "abutting_short",
        diff().rect("poly", 400, 400, 500, 450),
        Vec::new(),
    );
    case(
        "split_diffusion",
        Layout::default()
            .rect("diff", 0, 0, 450, 400)
            .rect("diff", 450, 0, 1000, 400)
            .rect("poly", 400, -200, 500, 600),
        Vec::new(),
    );
    for bottom in [-100, 0, 99, 100, 101, 500] {
        for top in [-100, 0, 99, 100, 101, 500] {
            let (layout, findings) = gate(bottom, top);
            case(&format!("ends/b{bottom}_t{top}"), layout, findings);
        }
    }
}

/// `bend(poly, diff)` (sky130 poly.11, "No 90 deg turns of poly on diff")
/// and `covers_corner(poly, diff)` (poly.10, "Poly can't overlap inner
/// corners of diff") (DRC-052): one finding per concave corner of the
/// shared area that is a concave corner of poly, or of diff, at the corner.
///
/// Oracle: every corner drawn where it is; a concave corner of an
/// intersection of rectilinear shapes is a concave corner of one of them.
/// Diffusion `[0, 1000]²` unless said: a straight gate (clean); an L poly
/// bent inside (a bend at (500, 500)), above it (clean), with its bend on
/// the diffusion's top edge (clean); a gate with a stub inside (two bends);
/// a gate over a jog in the diffusion's edge (an inner corner at (450,
/// 300)); a poly square over an L diffusion's inner corner (500, 500).
#[test]
fn gate_corner_finds_bends_and_covered_inner_corners() {
    let deck = new_deck(
        &["diff", "poly"],
        "rule poly.11 bend(poly, diff)\nrule poly.10 covers_corner(poly, diff)\n",
    );
    let corner = |x: i64, y: i64| Finding::count(1).at(x, y);
    let case = |name: &str, layout: Layout, bends: Vec<Finding>, covers: Vec<Finding>| {
        check_everywhere(
            name,
            &deck,
            &layout,
            &[("poly.11", bends), ("poly.10", covers)],
        );
    };
    let diff = || Layout::default().rect("diff", 0, 0, 1000, 1000);
    let l_poly = |y: i64| {
        [
            (400, -200),
            (500, -200),
            (500, y),
            (1200, y),
            (1200, y + 100),
            (400, y + 100),
        ]
    };
    case(
        "straight",
        diff().rect("poly", 400, -200, 500, 1200),
        vec![],
        vec![],
    );
    case(
        "bent_inside",
        diff().polygon("poly", &l_poly(500)),
        vec![corner(500, 500)],
        vec![],
    );
    case(
        "bent_outside",
        diff().polygon("poly", &l_poly(1100)),
        vec![],
        vec![],
    );
    case(
        "bent_on_edge",
        diff().polygon("poly", &l_poly(1000)),
        vec![],
        vec![],
    );
    case(
        "stub",
        diff()
            .rect("poly", 400, -200, 500, 1200)
            .rect("poly", 500, 400, 700, 500),
        vec![corner(500, 400), corner(500, 500)],
        vec![],
    );
    case(
        "diffusion_jog",
        Layout::default()
            .rect("diff", 0, 0, 450, 400)
            .rect("diff", 450, 0, 1000, 300)
            .rect("poly", 400, -200, 500, 600),
        vec![],
        vec![corner(450, 300)],
    );
    case(
        "inner_corner_covered",
        Layout::default()
            .rect("diff", 0, 0, 1000, 500)
            .rect("diff", 0, 500, 500, 1000)
            .rect("poly", 300, 300, 700, 700),
        vec![],
        vec![corner(500, 500)],
    );
    case("empty_poly", diff(), vec![], vec![]);
}
