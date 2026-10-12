//! Design rules between layers, on cuts and on coverage, the net, chip and
//! device rows the deck can express, and every derived-layer operation: one
//! generator per rule kind or operation, each the matrix of
//! `docs/testing-plan.md` §6 (X2, catalog rows DRC-040 to DRC-122).
//!
//! Every expectation is derived from the rule's definition (the `drc::Rule`
//! rustdoc and `docs/deck.md`) by construction: a margin, gap, area, count or
//! coverage is a number the layout was drawn to have. Limits are swept one
//! grid step either side, and every case is repeated under the eight
//! symmetries at two translations (`every_placement`), except where a rule
//! anchors on the die's lower-left corner, which only translations preserve.
//! A derived layer is proved through `forbidden(L)`, which reports each
//! resulting shape with its area (holes excluded) and each edge with its
//! length.
//!
//! An edge layer is read as a set of maximal segments, one per run of a line
//! with its shape on one side, as `KLayout` merges edges: a merged rectangle has
//! four edges whatever pieces drew it.
//!
//! Where `GPurify` falls short of a definition, the fixture keeps the
//! definition and names the finding that explains the gap (`known`). None
//! are carried today: F19, F34, F40, F54, F55 and F56, once pinned here, are
//! fixed (B15, B16) and their fixtures hold.

use crate::drc_dimension::{every_placement, DRC, OFFSETS};
use crate::harness::{Depth, Expect, Finding, Fixture, Layout, Symmetry, Want};
use gpurify::check::report::Measurement;
use std::fmt::Write as _;

/// An axis-aligned rectangle, `(xlo, ylo, xhi, yhi)` in nanometres.
type Rect = (i64, i64, i64, i64);

/// Every fixture this module generates at `depth`.
pub fn fixtures(depth: Depth) -> Vec<Fixture> {
    [
        min_enclosure(depth),
        asymmetric_enclosure(depth),
        wire_enclosure(),
        noncoincident_enclosure(),
        full_width(),
        projection_spacing(),
        max_enclosure(),
        min_extension(depth),
        gate_corner(),
        overlap(depth),
        must_contain(),
        must_be_inside(),
        edge_min_length(),
        edge_spacing(),
        edge_enclosure(),
        cut_spacing(),
        redundant_via(),
        minimum_cut(),
        via_stack(),
        via_array_spacing(depth),
        center_spacing(),
        adjacent_cut_spacing(),
        cut_class_spacing(),
        keep_out_zone(),
        protrusion_width(),
        global_density(),
        density(depth),
        cheesing(),
        region_density(),
        fill(),
        net_spacing(),
        tap_distance(),
        labelled_short(),
        exemption(),
        rule_flags(),
        cell_selections(),
        chip_and_device(),
        device_family(),
        chip_count(),
        seal_origin(),
        chip_area(),
        frame(),
        dangling_metal(),
        drc_warning(),
        multi_patterning(depth),
        anchored_patterning(),
        colour_spacing(),
        density_balance(),
        cover_density(),
        cut_area_change(),
        pattern_match(),
        critical_area(),
        stitch(),
        trim_cut(),
        booleans(),
        sizing(),
        selections(),
        shape_class(),
        feature_length(),
        enclose_rect(),
        covering_overlapping(),
        sized_xy(),
        edge_operations(),
        edge_extended(),
    ]
    .concat()
}

// ------------------------------------------------------------------ helpers

/// A deck on a 1 nm grid with each of `layers` drawn on its own GDS layer,
/// then `body`.
fn new_deck(layers: &[&str], body: &str) -> String {
    let mut out = String::from("grid 1nm\n");
    for (gds, name) in (1..).zip(layers) {
        writeln!(out, "layer {name} = gds({gds}, 0)").expect("a String takes any write");
    }
    out + body
}

/// The limit swept one grid step either side, each value with its side's name.
fn sweep(limit: i64) -> [(i64, &'static str); 3] {
    [(limit - 1, "below"), (limit, "at"), (limit + 1, "above")]
}

/// A `>=` rule's verdict on one measurement: a finding measuring it when it
/// is below `limit`, nothing at or above.
fn below(measured: i64, limit: i64) -> Vec<Finding> {
    if measured < limit {
        vec![Finding::length(measured)]
    } else {
        Vec::new()
    }
}

/// One finding per length.
fn lengths(values: &[i64]) -> Vec<Finding> {
    values.iter().map(|&v| Finding::length(v)).collect()
}

/// One finding per area, in square nanometres.
fn areas(values: &[i128]) -> Vec<Finding> {
    values.iter().map(|&v| Finding::area(v)).collect()
}

/// A finding with a measured count.
fn count(n: u32) -> Finding {
    Finding {
        measured: Some(Measurement::Count(n)),
        at: None,
    }
}

/// A finding with a measured fraction, at `at`.
fn ratio(fraction: f64, at: (i64, i64)) -> Finding {
    Finding {
        measured: Some(Measurement::Ratio(fraction)),
        at: Some(at),
    }
}

/// `layout` with each of `rects` added on `layer`.
fn rects(layout: Layout, layer: &str, rects: &[Rect]) -> Layout {
    rects.iter().fold(layout, |layout, &(xlo, ylo, xhi, yhi)| {
        layout.rect(layer, xlo, ylo, xhi, yhi)
    })
}

/// `outer` with `hole` cut out, drawn as four abutting bands that only merge
/// into a ring: a shape with a hole, which one drawn outline cannot be.
fn ring(layout: Layout, layer: &str, outer: Rect, hole: Rect) -> Layout {
    let (xlo, ylo, xhi, yhi) = outer;
    let (hxlo, hylo, hxhi, hyhi) = hole;
    rects(
        layout,
        layer,
        &[
            (xlo, ylo, xhi, hylo),
            (xlo, hyhi, xhi, yhi),
            (xlo, hylo, hxlo, hyhi),
            (hxhi, hylo, xhi, hyhi),
        ],
    )
}

/// One fixture: `layout` under `deck`, each rule claimed to run and to find
/// exactly its findings.
fn fixture(
    name: &str,
    catalog: &[&'static str],
    deck: &str,
    layout: Layout,
    rules: &[(&str, Vec<Finding>)],
) -> Fixture {
    rules.iter().fold(
        Fixture::new(name, catalog, deck, DRC).layout(layout),
        |fixture, (id, findings)| fixture.expect(Expect::rule(id, findings.clone())),
    )
}

/// Each fixture at every offset, unturned: for rules anchored on the die's
/// lower-left corner, which a turn or mirror moves.
fn every_offset(fixtures: &[Fixture]) -> Vec<Fixture> {
    fixtures
        .iter()
        .flat_map(|fixture| {
            OFFSETS
                .iter()
                .map(move |&(dx, dy)| fixture.transformed(Symmetry::IDENTITY, dx, dy))
        })
        .collect()
}

/// The margins every enumeration sweeps: touching, one step below, at and above
/// a 100 nm limit, and far.
const MARGINS: [i64; 5] = [0, 99, 100, 101, 400];

// ---------------------------------------------------------------- enclosure

/// An L-shaped host, `[0, 2000] x [0, 1000]` with `[0, 1000] x [0, 2000]`: its
/// concave corner is `(1000, 1000)`.
const L_HOST: [(i64, i64); 6] = [
    (0, 0),
    (2000, 0),
    (2000, 1000),
    (1000, 1000),
    (1000, 2000),
    (0, 2000),
];

/// A plus-shaped host, bars `[0, 1000] x [400, 600]` and `[400, 600] x [0,
/// 1000]`: its concave corners are 50 nm diagonally off `[450, 550]^2` on
/// both axes, Euclidean `floor(sqrt(5000)) = 70`, while every straight strip
/// from that square runs 450 nm.
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

/// `enclosure(via, met1) >= 100nm` (`min_enclosure`, DRC-040): one finding per
/// drawn via whose Euclidean distance to its host's boundary, holes and
/// concave corners included, is below the limit, measuring that distance
/// floored. A via no merged host figure covers measures 0.
///
/// Shapes, each margin swept 99/100/101:
/// - concentric, and one side short (the symmetries visit the other three);
/// - the host drawn as two abutting halves meeting under the via, which only
///   the merged host covers;
/// - a host ring (four bands) with the via beside its hole, so the hole's edge
///   counts;
/// - the via drawn as two abutting halves, each measured on its own;
/// - an L host with the via off its concave corner at Pythagorean offsets
///   (60, 79/80/81), so the Euclidean distance is exact and a projection
///   measure, which sees only the far edges, is caught; drawn as one outline
///   and as two overlapping rectangles.
///
/// And: a plus-shaped host (Euclidean 70 at its concave corners); a via
/// straddling the host's edge, outside it, or touching it from inside or
/// outside (all 0); a via with a hole (`cut not hole`), one polygon, swept;
/// each layer empty. Nightly: every combination of four rectangular margins.
fn min_enclosure(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 100;
    let deck = new_deck(&["via", "met1"], "rule enc enclosure(via, met1) >= 100nm\n");
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        fixture(
            &format!("min_enclosure/{name}"),
            &["DRC-040"],
            &deck,
            layout,
            &[("enc", findings)],
        )
    };
    let via = || Layout::default().rect("via", 0, 0, 100, 100);
    let mut cases = Vec::new();
    for (m, side) in sweep(LIMIT) {
        let short = below(m, LIMIT);
        cases.push(case(
            &format!("concentric/{side}"),
            via().rect("met1", -m, -m, 100 + m, 100 + m),
            short.clone(),
        ));
        cases.push(case(
            &format!("one_side/{side}"),
            via().rect("met1", -400, -400, 100 + m, 500),
            short.clone(),
        ));
        cases.push(case(
            &format!("seam/{side}"),
            via()
                .rect("met1", -400, -400, 50, 500)
                .rect("met1", 50, -400, 100 + m, 500),
            short.clone(),
        ));
        cases.push(case(
            &format!("beside_hole/{side}"),
            ring(
                Layout::default().rect("via", 1000 - m, 950, 1100 - m, 1050),
                "met1",
                (0, 0, 2000, 2000),
                (1100, 700, 1500, 1300),
            ),
            short.clone(),
        ));
        cases.push(case(
            &format!("via_halves/{side}"),
            Layout::default()
                .rect("via", 0, 0, 50, 100)
                .rect("via", 50, 0, 100, 100)
                .rect("met1", -m, -m, 100 + m, 100 + m),
            [short.clone(), short].concat(),
        ));
    }
    for (dy, side, findings) in [
        (79, "below", lengths(&[99])),
        (80, "at", Vec::new()),
        (81, "above", Vec::new()),
    ] {
        let via = Layout::default().rect("via", 840, 900 - dy, 940, 1000 - dy);
        cases.push(case(
            &format!("concave_corner/{side}"),
            via.clone().polygon("met1", &L_HOST),
            findings.clone(),
        ));
        cases.push(case(
            &format!("concave_corner_two_rects/{side}"),
            via.rect("met1", 0, 0, 2000, 1000)
                .rect("met1", 0, 0, 1000, 2000),
            findings,
        ));
    }
    cases.push(case(
        "plus_host",
        Layout::default()
            .rect("via", 450, 450, 550, 550)
            .polygon("met1", &PLUS_HOST),
        lengths(&[70]),
    ));
    for (name, host) in [
        ("straddling", (50, -400, 600, 500)),
        ("outside", (200, -400, 800, 500)),
        ("touching_inside", (0, -400, 600, 500)),
        ("touching_outside", (100, -400, 600, 500)),
    ] {
        cases.push(case(name, rects(via(), "met1", &[host]), lengths(&[0])));
    }
    cases.push(case(
        "empty_via",
        Layout::default().rect("met1", 0, 0, 1000, 1000),
        Vec::new(),
    ));
    cases.push(case("empty_met1", via(), lengths(&[0])));
    // A via with a hole, derived as `cut not hole`, is one polygon: its
    // material is `m` from the host's edge on every side.
    let deck_ring = new_deck(
        &["cut", "hole", "met1"],
        "layer via = cut not hole\nrule enc enclosure(via, met1) >= 100nm\n",
    );
    for (m, side) in sweep(LIMIT) {
        cases.push(fixture(
            &format!("min_enclosure/ring_via/{side}"),
            &["DRC-040", "DRC-120"],
            &deck_ring,
            Layout::default()
                .rect("cut", 0, 0, 300, 300)
                .rect("hole", 100, 100, 200, 200)
                .rect("met1", -m, -m, 300 + m, 300 + m),
            &[("enc", below(m, LIMIT))],
        ));
    }
    if depth == Depth::Nightly {
        for (l, r, b, t) in margins4() {
            cases.push(case(
                &format!("margins/l{l}_r{r}_b{b}_t{t}"),
                via().rect("met1", -l, -b, 100 + r, 100 + t),
                below(l.min(r).min(b).min(t), LIMIT),
            ));
        }
    }
    every_placement(cases)
}

/// Every `(left, right, bottom, top)` drawn from [`MARGINS`].
fn margins4() -> Vec<(i64, i64, i64, i64)> {
    let mut out = Vec::new();
    for l in MARGINS {
        for r in MARGINS {
            for b in MARGINS {
                for t in MARGINS {
                    out.push((l, r, b, t));
                }
            }
        }
    }
    out
}

/// `enclosure(via, met1, opposite) >= 100nm` (`asymmetric_enclosure`, DRC-041
/// and DRC-042): each edge of a via is read straight out to the nearest host
/// edge facing it; the via measures `max(min over its vertical edges, min
/// over its horizontal edges)`, which for a rectangle is `max(min(left,
/// right), min(bottom, top))`.
///
/// Oracle: every margin is drawn, so each edge's straight-out reading is a
/// number the layout was built to have.
///
/// Shapes: the limit on one axis with the other axis touching; one side short
/// with the other axis far; both axes short; every side touching; a host with
/// notches down to the via on two sides (a bounding-box measure sees the far
/// edges); the plus host, clean here because its straight strips run 450 nm
/// although its concave corners are 70 nm off; an L-shaped via, swept; an L
/// via with the limit only along x (clean: the old every-side fallback read
/// 0); an L via whose concave top edge decides the y axis, swept, while a
/// host notch 50 nm right of its upper arm spoils the x axis (an every-side
/// or bounding-box measure reads 50 or the box's 100 at every step); an
/// unhosted via; an empty via layer. Nightly: every combination of four
/// margins.
fn asymmetric_enclosure(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 100;
    let deck = new_deck(
        &["via", "met1"],
        "rule m1.5 enclosure(via, met1, opposite) >= 100nm\n",
    );
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        fixture(
            &format!("asymmetric_enclosure/{name}"),
            &["DRC-041", "DRC-042"],
            &deck,
            layout,
            &[("m1.5", findings)],
        )
    };
    let hosted = |(l, r, b, t): (i64, i64, i64, i64)| {
        Layout::default()
            .rect("via", 0, 0, 100, 100)
            .rect("met1", -l, -b, 100 + r, 100 + t)
    };
    let measure = |(l, r, b, t): (i64, i64, i64, i64)| below(l.min(r).max(b.min(t)), LIMIT);
    let l_via = [
        (0, 0),
        (200, 0),
        (200, 100),
        (100, 100),
        (100, 200),
        (0, 200),
    ];
    let mut cases = Vec::new();
    for (m, side) in sweep(LIMIT) {
        for (name, margins) in [
            ("x_axis", (m, m, 0, 0)),
            ("y_axis", (0, 0, m, m)),
            ("one_side_short", (m, 400, 0, 400)),
            ("both_axes_short", (m, 400, 400, 99)),
        ] {
            cases.push(case(
                &format!("{name}/{side}"),
                hosted(margins),
                measure(margins),
            ));
        }
        // Notches come down to `m` above and right of the via; the host's
        // box is 400 nm out on every side.
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
        cases.push(case(
            &format!("notched_host/{side}"),
            Layout::default()
                .rect("via", 0, 0, 100, 100)
                .polygon("met1", &notched),
            below(m, LIMIT),
        ));
        cases.push(case(
            &format!("l_via/{side}"),
            Layout::default()
                .polygon("via", &l_via)
                .rect("met1", -m, -m, 200 + m, 200 + m),
            below(m, LIMIT),
        ));
    }
    cases.push(case("every_side_zero", hosted((0, 0, 0, 0)), lengths(&[0])));
    cases.push(case(
        "plus_host",
        Layout::default()
            .rect("via", 450, 450, 550, 550)
            .polygon("met1", &PLUS_HOST),
        Vec::new(),
    ));
    cases.push(case(
        "l_via_one_axis",
        Layout::default()
            .polygon("via", &l_via)
            .rect("met1", -100, 0, 300, 200),
        Vec::new(),
    ));
    // A notch comes down from the host's top over x in [150, 250] to
    // 100 + k: the via's concave top edge (y = 100, x in [100, 200]) reads k,
    // its other horizontal edges 100, so y measures min(k, 100). The upper
    // arm's right edge (x = 100) reads 50 to the notch while the notch
    // reaches below y = 200, so x measures 50 then, else 100.
    for (k, side) in sweep(LIMIT) {
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
        cases.push(case(
            &format!("l_via_concave_edge/{side}"),
            Layout::default()
                .polygon("via", &l_via)
                .polygon("met1", &host),
            below(x.max(k.min(100)), LIMIT),
        ));
    }
    cases.push(case(
        "unhosted",
        Layout::default()
            .rect("via", 0, 0, 100, 100)
            .rect("met1", 50, -400, 600, 500),
        lengths(&[0]),
    ));
    cases.push(case(
        "empty_via",
        Layout::default().rect("met1", 0, 0, 1000, 1000),
        Vec::new(),
    ));
    if depth == Depth::Nightly {
        for margins in margins4() {
            let (l, r, b, t) = margins;
            cases.push(case(
                &format!("margins/l{l}_r{r}_b{b}_t{t}"),
                hosted(margins),
                measure(margins),
            ));
        }
    }
    every_placement(cases)
}

/// Enclosure by wire width, LEF/DEF 5.8 Example 1-3's `via23` in nm:
/// `enclosure(via, met2, opposite; below: 1000nm) >= 50nm` (`narrow`),
/// `enclosure(via, met2; width: 1000nm, below: 2000nm) >= 20nm` (`mid`) and
/// `enclosure(via, met2; width: 2000nm) >= 50nm` (`wide`) (`min_enclosure`
/// and `asymmetric_enclosure` with a wire band, DRC-043): each 200 nm via is
/// held by exactly one row, the one whose band holds the width of the wire it
/// lies on (where a square that wide fits around all of it), and an unhosted
/// via by the lowest.
///
/// Oracle: the wires are drawn to a width, and the via's margins to the
/// wire's edges are drawn: 15 to the left, 30 below. So `narrow` reads
/// `max(min(15, far), min(30, far)) = 30` and the others 15.
///
/// Shapes: a wire 999, 1000, 1001, 1999, 2000 and 2001 wide (the bands'
/// edges, inclusive below, exclusive above); a via on a 500 nm tab off a
/// 3000 nm plate (the tab's width, not the plate's, so `narrow` reads 20);
/// a via 40 into a corner of the plate (`wide` only); an unhosted via
/// (`narrow`, 0).
fn wire_enclosure() -> Vec<Fixture> {
    let deck = new_deck(
        &["via", "met2"],
        "rule narrow enclosure(via, met2, opposite; below: 1000nm) >= 50nm\n\
         rule mid enclosure(via, met2; width: 1000nm, below: 2000nm) >= 20nm\n\
         rule wide enclosure(via, met2; width: 2000nm) >= 50nm\n",
    );
    let case = |name: &str, layout: Layout, rows: [Vec<Finding>; 3]| {
        let [narrow, mid, wide] = rows;
        fixture(
            &format!("wire_enclosure/{name}"),
            &["DRC-043", "DRC-040", "DRC-041"],
            &deck,
            layout,
            &[("narrow", narrow), ("mid", mid), ("wide", wide)],
        )
    };
    let via = || Layout::default().rect("via", 0, 0, 200, 200);
    let mut cases = Vec::new();
    for w in [999, 1000, 1001, 1999, 2000, 2001] {
        let rows = if w < 1000 {
            [lengths(&[30]), vec![], vec![]]
        } else if w < 2000 {
            [vec![], lengths(&[15]), vec![]]
        } else {
            [vec![], vec![], lengths(&[15])]
        };
        cases.push(case(
            &format!("wire/{w}"),
            via().rect("met2", -15, -30, 3000, w - 30),
            rows,
        ));
    }
    cases.push(case(
        "tab",
        Layout::default()
            .rect("met2", 0, 0, 3000, 3000)
            .rect("met2", 3000, 1000, 3800, 1500)
            .rect("via", 3580, 1150, 3780, 1490),
        [lengths(&[20]), vec![], vec![]],
    ));
    cases.push(case(
        "plate",
        Layout::default()
            .rect("met2", 0, 0, 3000, 3000)
            .rect("via", 40, 40, 240, 240),
        [vec![], vec![], lengths(&[40])],
    ));
    cases.push(case(
        "unhosted",
        via().rect("met2", 5000, 5000, 6000, 6000),
        [lengths(&[0]), vec![], vec![]],
    ));
    every_placement(cases)
}

/// `enclosure(lvtn, nwell, noncoincident) >= 380nm` (`noncoincident_enclosure`,
/// DRC-054, sky130 lvtn.10 "(exclude coincident edges)") beside the plain
/// `enclosure(lvtn, nwell) >= 380nm`: an lvtn edge lying on the nwell's edge,
/// or an lvtn corner touching it, is exempt from the first and measures 0
/// under the second.
///
/// Oracle: drawn margins; the touching pairs are drawn to coincide.
///
/// lvtn is `[0, 1000]^2`. Shapes: concentric at 379/380/381 (both rules
/// alike); the left edge on the nwell's left edge with the other margins
/// swept, and also the bottom edge; the left edge on the nwell's edge for
/// its lower half only, the nwell stepping 400 out above it (exempt, then
/// 400); lvtn in an L nwell's concave corner, touching it only at that
/// corner (exempt; 600 elsewhere); an unhosted lvtn (0 for both).
fn noncoincident_enclosure() -> Vec<Fixture> {
    const LIMIT: i64 = 380;
    let deck = new_deck(
        &["lvtn", "nwell"],
        "rule lvtn.10 enclosure(lvtn, nwell, noncoincident) >= 380nm\n\
         rule plain enclosure(lvtn, nwell) >= 380nm\n",
    );
    let case = |name: &str, layout: Layout, apart: Vec<Finding>, plain: Vec<Finding>| {
        fixture(
            &format!("noncoincident_enclosure/{name}"),
            &["DRC-054"],
            &deck,
            layout,
            &[("lvtn.10", apart), ("plain", plain)],
        )
    };
    let lvtn = || Layout::default().rect("lvtn", 0, 0, 1000, 1000);
    let mut cases = Vec::new();
    for (m, side) in sweep(LIMIT) {
        cases.push(case(
            &format!("concentric/{side}"),
            lvtn().rect("nwell", -m, -m, 1000 + m, 1000 + m),
            below(m, LIMIT),
            below(m, LIMIT),
        ));
        cases.push(case(
            &format!("left_on_edge/{side}"),
            lvtn().rect("nwell", 0, -m, 1000 + m, 1000 + m),
            below(m, LIMIT),
            lengths(&[0]),
        ));
        cases.push(case(
            &format!("corner_on_edges/{side}"),
            lvtn().rect("nwell", 0, 0, 1000 + m, 1000 + m),
            below(m, LIMIT),
            lengths(&[0]),
        ));
    }
    cases.push(case(
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
    ));
    cases.push(case(
        "kissing_corner",
        Layout::default()
            .rect("lvtn", 600, 600, 1000, 1000)
            .polygon("nwell", &L_HOST),
        vec![],
        lengths(&[0]),
    ));
    cases.push(case(
        "unhosted",
        lvtn().rect("nwell", 2000, 2000, 3000, 3000),
        lengths(&[0]),
        lengths(&[0]),
    ));
    every_placement(cases)
}

/// `full_width(v1, m2)` (`full_width`, DRC-053, ASAP7 V1.M2.AUX.2 "V1 must
/// exactly be the same width as M2 along the direction perpendicular to the
/// M2 length"): one finding per via that meets the wire's edges on neither
/// axis, measuring the widest straight-out gap on its better axis.
///
/// Oracle: drawn gaps between the via's edges and the wire's.
///
/// Shapes, a 100 nm via: in a horizontal wire 100 wide, spanning it (clean);
/// 0 or 1 short of its top edge, and 10 short of both; in a vertical wire 100
/// wide (spanning it along x: clean); on a 300 nm pad (100 on every side);
/// alone on a 100 nm pad (both axes span: clean); a via on no wire (not
/// measured: `inside` is that rule).
fn full_width() -> Vec<Fixture> {
    let deck = new_deck(&["v1", "m2"], "rule V1.M2.AUX.2 full_width(v1, m2)\n");
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        fixture(
            &format!("full_width/{name}"),
            &["DRC-053"],
            &deck,
            layout,
            &[("V1.M2.AUX.2", findings)],
        )
    };
    let wire = || Layout::default().rect("m2", -500, 0, 1000, 100);
    let mut cases = Vec::new();
    for short in [0, 1] {
        cases.push(case(
            &format!("top_short/{short}"),
            wire().rect("v1", 0, 0, 100, 100 - short),
            if short > 0 { lengths(&[short]) } else { vec![] },
        ));
    }
    cases.push(case(
        "narrower",
        wire().rect("v1", 0, 10, 100, 90),
        lengths(&[10]),
    ));
    cases.push(case(
        "vertical_wire",
        Layout::default()
            .rect("m2", 0, -200, 100, 1000)
            .rect("v1", 0, 0, 100, 100),
        vec![],
    ));
    cases.push(case(
        "pad",
        Layout::default()
            .rect("m2", -100, -100, 200, 200)
            .rect("v1", 0, 0, 100, 100),
        lengths(&[100]),
    ));
    cases.push(case(
        "equal_pad",
        Layout::default()
            .rect("m2", 0, 0, 100, 100)
            .rect("v1", 0, 0, 100, 100),
        vec![],
    ));
    cases.push(case(
        "off_wire",
        wire().rect("v1", 3000, 0, 3100, 100),
        vec![],
    ));
    every_placement(cases)
}

/// `space(lvtn, sd, projection) >= 235nm` (`projection_spacing`, DRC-055,
/// sky130 lvtn.3b as its `KLayout` deck writes it) beside the Euclidean
/// `space(lvtn, sd) >= 235nm`: a pair is measured across facing edges that
/// overlap in projection, so a pair offset diagonally passes the first.
///
/// Oracle: drawn gaps; a diagonal pair at offsets (100, 100) is 141 apart by
/// Euclid and has no facing edges.
///
/// lvtn is `[0, 500]^2`. Shapes: sd beside it at 234/235/236; sd diagonally
/// off its corner (100, 100) away (clean here, 141 there); sd overlapping
/// lvtn's side by 1 nm of projection, 100 away (100); sd whose projection
/// only meets lvtn's at a point, 50 away (clean here, 50 there); sd touching
/// (0 for both) and overlapping lvtn (0 for both).
fn projection_spacing() -> Vec<Fixture> {
    const LIMIT: i64 = 235;
    let deck = new_deck(
        &["lvtn", "sd"],
        "rule lvtn.3b space(lvtn, sd, projection) >= 235nm\n\
         rule euclid space(lvtn, sd) >= 235nm\n",
    );
    let case = |name: &str, sd: Rect, projection: Vec<Finding>, euclid: Vec<Finding>| {
        fixture(
            &format!("projection_spacing/{name}"),
            &["DRC-055"],
            &deck,
            Layout::default()
                .rect("lvtn", 0, 0, 500, 500)
                .rect("sd", sd.0, sd.1, sd.2, sd.3),
            &[("lvtn.3b", projection), ("euclid", euclid)],
        )
    };
    let mut cases = Vec::new();
    for (g, side) in sweep(LIMIT) {
        cases.push(case(
            &format!("beside/{side}"),
            (500 + g, 100, 900 + g, 400),
            below(g, LIMIT),
            below(g, LIMIT),
        ));
    }
    cases.push(case(
        "diagonal",
        (600, 600, 900, 900),
        vec![],
        lengths(&[141]),
    ));
    cases.push(case(
        "one_unit_of_projection",
        (600, 499, 900, 900),
        lengths(&[100]),
        lengths(&[100]),
    ));
    cases.push(case(
        "projection_meets_at_a_point",
        (550, 500, 900, 900),
        vec![],
        lengths(&[50]),
    ));
    cases.push(case(
        "touching",
        (500, 100, 900, 400),
        lengths(&[0]),
        lengths(&[0]),
    ));
    cases.push(case(
        "overlapping",
        (400, 100, 900, 400),
        lengths(&[0]),
        lengths(&[0]),
    ));
    every_placement(cases)
}

/// `enclosure(licon, npc) <= 95nm` (`max_enclosure`, DRC-044, sky130 npc.5):
/// each npc figure holding licons must lie inside their union grown by 95 nm
/// with square corners; one finding per npc figure that reaches further,
/// measuring its furthest reach rounded up.
///
/// Oracle: the reach is drawn. A licon `[0, 100]^2` in npc 50 past it on
/// three sides and `m` on the fourth reaches `max(50, m)`; a corner square
/// added off the npc's corner reaches its diagonal point's Chebyshev
/// distance; between two licons `g` apart under one npc the furthest point
/// is midway, `g / 2` from both.
///
/// Shapes: one side swept 94/95/96; a corner square to (195, 195) and to
/// (196, 196), which every straight strip from the licon reads as 50; two
/// licons 190, 191 and 192 apart under one npc (reach 95, 95.5 and 96); an
/// npc holding no licon, and one only straddled by a licon (neither is
/// measured).
fn max_enclosure() -> Vec<Fixture> {
    const LIMIT: i64 = 95;
    let deck = new_deck(
        &["licon", "npc"],
        "rule npc.5 enclosure(licon, npc) <= 95nm\n",
    );
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        fixture(
            &format!("max_enclosure/{name}"),
            &["DRC-044"],
            &deck,
            layout,
            &[("npc.5", findings)],
        )
    };
    let above = |reach: i64| {
        if reach > LIMIT {
            lengths(&[reach])
        } else {
            vec![]
        }
    };
    let licon = || Layout::default().rect("licon", 0, 0, 100, 100);
    let mut cases = Vec::new();
    for (m, side) in sweep(LIMIT) {
        cases.push(case(
            &format!("side/{side}"),
            licon().rect("npc", -50, -50, 100 + m, 150),
            above(m),
        ));
    }
    for c in [195, 196] {
        cases.push(case(
            &format!("corner/{c}"),
            licon()
                .rect("npc", -50, -50, 150, 150)
                .rect("npc", 100, 100, c, c),
            above(c - 100),
        ));
    }
    for (g, reach) in [(190, 95), (191, 96), (192, 96)] {
        cases.push(case(
            &format!("two_licons/{g}"),
            licon()
                .rect("licon", 100 + g, 0, 200 + g, 100)
                .rect("npc", -50, -50, 250 + g, 150),
            above(reach),
        ));
    }
    cases.push(case(
        "holding_nothing",
        licon()
            .rect("npc", -50, -50, 150, 150)
            .rect("npc", 1000, 1000, 2000, 2000),
        vec![],
    ));
    cases.push(case(
        "straddled",
        licon().rect("npc", 50, -500, 1000, 500),
        vec![],
    ));
    every_placement(cases)
}

// --------------------------------------------------------- extension, overlap

/// `extension(poly, diff) >= 100nm` (`min_extension`, DRC-045): a poly that
/// crosses diffusion must run past each diffusion edge it crosses by the limit;
/// one finding per offending pair, measuring the shortest such run, 0 where
/// the poly stops inside the diffusion or at its edge.
///
/// Diffusion is `[0, 1000] x [0, 400]`. Shapes: a gate with both ends at the
/// swept length, one end swept with the other far, a poly covering the
/// diffusion; a U-shaped poly whose far arm makes its bounding box reach past
/// on every side while the gate end is swept, and a gate ending inside the
/// diffusion at one end (both F19); a gate over a step in the diffusion's
/// edge, its near end swept; a legal gate over a diffusion drawn as
/// two pieces abutting under it (F56); a poly abutting the diffusion
/// without crossing it, one with a far end that is short (no gate, clean;
/// F41); an empty poly layer. Nightly: both ends across {inside, flush, 99,
/// 100, 101, far}.
fn min_extension(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 100;
    let deck = new_deck(
        &["diff", "poly"],
        "rule poly.8 extension(poly, diff) >= 100nm\n",
    );
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        fixture(
            &format!("min_extension/{name}"),
            &["DRC-045"],
            &deck,
            layout,
            &[("poly.8", findings)],
        )
    };
    let diff = || Layout::default().rect("diff", 0, 0, 1000, 400);
    // The gate's two ends past the diffusion, bottom then top; at or below
    // zero it stops inside, measuring 0.
    let gate = |bottom: i64, top: i64| {
        (
            diff().rect("poly", 400, -bottom, 500, 400 + top),
            below(bottom.min(top).max(0), LIMIT),
        )
    };
    let mut cases = Vec::new();
    for (m, side) in sweep(LIMIT) {
        let (layout, findings) = gate(m, m);
        cases.push(case(&format!("crossing/{side}"), layout, findings));
        let (layout, findings) = gate(500, m);
        cases.push(case(&format!("one_end/{side}"), layout, findings));
        cases.push(case(
            &format!("covering/{side}"),
            diff().rect("poly", -m, -m, 1000 + m, 400 + m),
            below(m, LIMIT),
        ));
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
        cases.push(case(
            &format!("u_shape/{side}"),
            diff().polygon("poly", &u),
            below(m, LIMIT),
        ));
        // The diffusion steps down from 400 to 300 under the gate. Every gate
        // edge facing up or down is still on the diffusion's edge, so the
        // runs are m below, 200 and 300 above; the step's own 50 nm edge
        // faces sideways, a side of the gate.
        cases.push(case(
            &format!("diffusion_jog/{side}"),
            Layout::default()
                .rect("diff", 0, 0, 450, 400)
                .rect("diff", 450, 0, 1000, 300)
                .rect("poly", 400, -m, 500, 600),
            below(m, LIMIT),
        ));
    }
    let (layout, findings) = gate(500, -100);
    cases.push(case("ends_inside", layout, findings));
    cases.push(case(
        "abutting",
        diff().rect("poly", 400, 400, 500, 900),
        Vec::new(),
    ));
    // F41: no gate, so its far end, 50 past the diffusion, is not measured.
    cases.push(case(
        "abutting_short",
        diff().rect("poly", 400, 400, 500, 450),
        Vec::new(),
    ));
    cases.push(case("empty_poly", diff(), Vec::new()));
    // The diffusion drawn as two pieces abutting under the gate: one
    // diffusion, which the gate crosses with 200 nm to spare at both ends
    // (F56: each drawn piece was paired on its own).
    cases.push(case(
        "split_diffusion",
        Layout::default()
            .rect("diff", 0, 0, 450, 400)
            .rect("diff", 450, 0, 1000, 400)
            .rect("poly", 400, -200, 500, 600),
        Vec::new(),
    ));
    if depth == Depth::Nightly {
        let ends = [-100, 0, 99, 100, 101, 500];
        for bottom in ends {
            for top in ends {
                let (layout, findings) = gate(bottom, top);
                cases.push(case(&format!("ends/b{bottom}_t{top}"), layout, findings));
            }
        }
    }
    every_placement(cases)
}

/// `bend(poly, diff)` (sky130 poly.11, "No 90 deg turns of poly on diff")
/// and `covers_corner(poly, diff)` (poly.10, "Poly can't overlap inner
/// corners of diff") (`gate_corner`, DRC-052): one finding per concave
/// corner of the shared area that is a concave corner of poly, or of diff,
/// at the corner.
///
/// Oracle: every corner is drawn where it is; a concave corner of an
/// intersection of rectilinear shapes is a concave corner of one of them.
///
/// Diffusion is `[0, 1000]^2` unless said. Shapes: a straight gate (clean);
/// an L poly bent inside the diffusion (a bend at (500, 500)), above it
/// (clean), and with its bend on the diffusion's top edge (the gate is a
/// rectangle: clean); a gate with a stub inside the diffusion (two bends);
/// a gate over a jog in the diffusion's edge (an inner corner at (450,
/// 300)); a poly square over an L diffusion's inner corner (500, 500), with
/// no gate bend; an empty poly layer.
fn gate_corner() -> Vec<Fixture> {
    let deck = new_deck(
        &["diff", "poly"],
        "rule poly.11 bend(poly, diff)\nrule poly.10 covers_corner(poly, diff)\n",
    );
    let corner = |x: i64, y: i64| Finding {
        measured: Some(Measurement::Count(1)),
        at: Some((x, y)),
    };
    let case = |name: &str, layout: Layout, bends: Vec<Finding>, covers: Vec<Finding>| {
        fixture(
            &format!("gate_corner/{name}"),
            &["DRC-052"],
            &deck,
            layout,
            &[("poly.11", bends), ("poly.10", covers)],
        )
    };
    let diff = || Layout::default().rect("diff", 0, 0, 1000, 1000);
    // An L poly: a bar x 400..500 from y -200 up to `y + 100`, turning right
    // along y..y + 100 to x 1200; its concave corner is (500, y).
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
    let mut cases = vec![case(
        "straight",
        diff().rect("poly", 400, -200, 500, 1200),
        vec![],
        vec![],
    )];
    cases.push(case(
        "bent_inside",
        diff().polygon("poly", &l_poly(500)),
        vec![corner(500, 500)],
        vec![],
    ));
    cases.push(case(
        "bent_outside",
        diff().polygon("poly", &l_poly(1100)),
        vec![],
        vec![],
    ));
    cases.push(case(
        "bent_on_edge",
        diff().polygon("poly", &l_poly(1000)),
        vec![],
        vec![],
    ));
    cases.push(case(
        "stub",
        diff()
            .rect("poly", 400, -200, 500, 1200)
            .rect("poly", 500, 400, 700, 500),
        vec![corner(500, 400), corner(500, 500)],
        vec![],
    ));
    cases.push(case(
        "diffusion_jog",
        Layout::default()
            .rect("diff", 0, 0, 450, 400)
            .rect("diff", 450, 0, 1000, 300)
            .rect("poly", 400, -200, 500, 600),
        vec![],
        vec![corner(450, 300)],
    ));
    cases.push(case(
        "inner_corner_covered",
        Layout::default()
            .rect("diff", 0, 0, 1000, 500)
            .rect("diff", 0, 500, 500, 1000)
            .rect("poly", 300, 300, 700, 700),
        vec![],
        vec![corner(500, 500)],
    ));
    cases.push(case("empty_poly", diff(), vec![], vec![]));
    every_placement(cases)
}

/// `overlap(a, b) >= 100nm` (`overlap`, DRC-046): one finding per pair whose
/// shared area is narrower than the limit, measuring the narrower side of that
/// area; shapes that share no area do not overlap.
///
/// `b` is `[0, 1000]^2`. Shapes: an edge overlap and a contained bar, swept;
/// boxes that only touch, an L whose material overlaps 500 x 50 inside a
/// 500 x 500 box intersection, and a notched square whose box overlaps `b`
/// while its material keeps 50 nm away (all F19); an `a` drawn as two
/// abutting pieces that together overlap by 100 (F56); an empty `a`.
/// Nightly: the edge overlap from 90 to 110.
fn overlap(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 100;
    let deck = new_deck(&["a", "b"], "rule ov overlap(a, b) >= 100nm\n");
    let case = |name: &str, a: Layout, findings: Vec<Finding>| {
        fixture(
            &format!("overlap/{name}"),
            &["DRC-046"],
            &deck,
            a.rect("b", 0, 0, 1000, 1000),
            &[("ov", findings)],
        )
    };
    let edge = |m: i64| Layout::default().rect("a", 1000 - m, 200, 2000, 800);
    let mut cases = Vec::new();
    for (m, side) in sweep(LIMIT) {
        cases.push(case(&format!("edge/{side}"), edge(m), below(m, LIMIT)));
        cases.push(case(
            &format!("contained/{side}"),
            Layout::default().rect("a", 300, 300, 300 + m, 700),
            below(m, LIMIT),
        ));
    }
    cases.push(case("touching", edge(0), Vec::new()));
    let l_shape = [
        (500, 950),
        (1900, 950),
        (1900, 500),
        (2000, 500),
        (2000, 1000),
        (500, 1000),
    ];
    cases.push(case(
        "l_shape",
        Layout::default().polygon("a", &l_shape),
        lengths(&[50]),
    ));
    let notched = [
        (950, 1050),
        (1050, 1050),
        (1050, 950),
        (2000, 950),
        (2000, 2000),
        (950, 2000),
    ];
    cases.push(case(
        "notched_square",
        Layout::default().polygon("a", &notched),
        Vec::new(),
    ));
    cases.push(case("empty_a", Layout::default(), Vec::new()));
    // `a` drawn as two abutting pieces: together they overlap `b` by 100
    // (F56: each drawn piece was paired on its own).
    cases.push(case(
        "split_a",
        Layout::default()
            .rect("a", 900, 200, 950, 800)
            .rect("a", 950, 200, 2000, 800),
        Vec::new(),
    ));
    if depth == Depth::Nightly {
        for m in 90..=110 {
            cases.push(case(&format!("edge_sweep/{m}"), edge(m), below(m, LIMIT)));
        }
    }
    every_placement(cases)
}

// ------------------------------------------------------- containment, inside

/// `contains(tap, licon) >= 1`, `>= 2`, `<= 1` and `== 2` (`must_contain`,
/// DRC-048 and DRC-049), and `contains(nwell, ntap) >= 1` (DRC-085, tap
/// presence per well): one finding per merged outer figure holding fewer, or
/// more, merged inner figures entirely than its bound, measuring what it
/// holds.
///
/// Oracle: each case states how many licons each tap holds, by
/// construction, and every rule's findings follow from that count and the
/// rule's bound.
///
/// Shapes: none, one, two and three held; one touching the tap's edge from
/// inside (held); one straddling the edge and one touching it from outside
/// (not held); two touching or overlapping licons (one figure); a tap of two
/// abutting halves holding a licon across the seam; two taps; a licon in a
/// tap ring's hole (not held); an empty tap layer. For wells: tapped,
/// untapped, a tap across the well's edge.
fn must_contain() -> Vec<Fixture> {
    let deck_tap = new_deck(
        &["tap", "licon"],
        "rule one contains(tap, licon) >= 1\nrule two contains(tap, licon) >= 2\n\
         rule most contains(tap, licon) <= 1\nrule exact contains(tap, licon) == 2\n",
    );
    // `held` is what each tap figure holds.
    let case = |name: &str, layout: Layout, held: &[u32]| {
        let failing = |bad: fn(u32) -> bool| -> Vec<Finding> {
            held.iter()
                .filter(|&&h| bad(h))
                .map(|&h| count(h))
                .collect()
        };
        fixture(
            &format!("must_contain/{name}"),
            &["DRC-048", "DRC-049"],
            &deck_tap,
            layout,
            &[
                ("one", failing(|h| h < 1)),
                ("two", failing(|h| h < 2)),
                ("most", failing(|h| h > 1)),
                ("exact", failing(|h| h != 2)),
            ],
        )
    };
    let tap = || Layout::default().rect("tap", 0, 0, 1000, 500);
    let mut cases = Vec::new();
    for (name, licons, held) in [
        ("none", vec![], 0),
        ("one", vec![(100, 100, 200, 200)], 1),
        ("two", vec![(100, 100, 200, 200), (400, 100, 500, 200)], 2),
        (
            "three",
            vec![
                (100, 100, 200, 200),
                (400, 100, 500, 200),
                (700, 100, 800, 200),
            ],
            3,
        ),
        ("edge_inside", vec![(0, 0, 100, 100)], 1),
        ("straddling", vec![(950, 100, 1050, 200)], 0),
        ("touching_outside", vec![(1000, 100, 1100, 200)], 0),
        (
            "touching_pair",
            vec![(100, 100, 200, 200), (200, 100, 300, 200)],
            1,
        ),
        (
            "overlapping_pair",
            vec![(100, 100, 250, 200), (200, 100, 300, 200)],
            1,
        ),
    ] {
        cases.push(case(name, rects(tap(), "licon", &licons), &[held]));
    }
    cases.push(case(
        "tap_halves",
        Layout::default()
            .rect("tap", 0, 0, 500, 500)
            .rect("tap", 500, 0, 1000, 500)
            .rect("licon", 450, 100, 550, 200),
        &[1],
    ));
    cases.push(case(
        "two_taps",
        tap()
            .rect("licon", 100, 100, 200, 200)
            .rect("tap", 2000, 0, 3000, 500),
        &[1, 0],
    ));
    cases.push(case(
        "empty_tap",
        Layout::default().rect("licon", 100, 100, 200, 200),
        &[],
    ));
    cases.push(case(
        "in_hole",
        ring(
            Layout::default().rect("licon", 450, 200, 550, 300),
            "tap",
            (0, 0, 1000, 500),
            (300, 100, 700, 400),
        ),
        &[0],
    ));

    let deck_well = new_deck(
        &["nwell", "ntap"],
        "rule nwell.4 contains(nwell, ntap) >= 1\n",
    );
    for (name, taps, findings) in [
        ("tapped", vec![(100, 100, 300, 300)], vec![]),
        ("untapped", vec![], vec![count(0)]),
        (
            "tap_across_edge",
            vec![(1900, 100, 2100, 300)],
            vec![count(0)],
        ),
    ] {
        cases.push(fixture(
            &format!("well_tap/{name}"),
            &["DRC-085", "DRC-048"],
            &deck_well,
            rects(
                Layout::default().rect("nwell", 0, 0, 2000, 1000),
                "ntap",
                &taps,
            ),
            &[("nwell.4", findings)],
        ));
    }
    every_placement(cases)
}

/// `inside(licon, npc)` (`must_be_inside`, DRC-048): one finding per merged
/// licon figure not covered by one merged npc figure, measuring the area left
/// outside the npc.
///
/// npc is `[0, 1000]^2`. Shapes: inside; touching npc's edge from inside;
/// straddling the edge by 1, 50 and 99 nm of its 100; outside, and touching
/// from outside (the whole area); spanning a 10 nm gap between two npc
/// shapes (the gap's area); spanning the seam of two abutting npc shapes
/// (inside); a licon inside touching one that sticks out (one figure); a
/// licon in an npc ring's hole (all outside) and across the hole's edge
/// (half); each layer empty.
fn must_be_inside() -> Vec<Fixture> {
    let deck = new_deck(&["npc", "licon"], "rule licon.18 inside(licon, npc)\n");
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        fixture(
            &format!("must_be_inside/{name}"),
            &["DRC-048"],
            &deck,
            layout,
            &[("licon.18", findings)],
        )
    };
    let npc = || Layout::default().rect("npc", 0, 0, 1000, 1000);
    let mut cases = vec![
        case("inside", npc().rect("licon", 100, 100, 200, 200), vec![]),
        case(
            "touching_inside",
            npc().rect("licon", 0, 0, 100, 100),
            vec![],
        ),
        case(
            "outside",
            npc().rect("licon", 1100, 400, 1200, 500),
            areas(&[10_000]),
        ),
        case(
            "touching_outside",
            npc().rect("licon", 1000, 400, 1100, 500),
            areas(&[10_000]),
        ),
        case(
            "across_gap",
            npc()
                .rect("npc", 1010, 0, 2000, 1000)
                .rect("licon", 950, 400, 1060, 500),
            areas(&[1000]),
        ),
        case(
            "across_seam",
            Layout::default()
                .rect("npc", 0, 0, 1000, 1000)
                .rect("npc", 1000, 0, 2000, 1000)
                .rect("licon", 950, 400, 1050, 500),
            vec![],
        ),
        case(
            "touching_licons",
            npc()
                .rect("licon", 800, 400, 900, 500)
                .rect("licon", 900, 400, 1100, 500),
            areas(&[10_000]),
        ),
        case("empty_licon", npc(), vec![]),
        case(
            "in_hole",
            ring(
                Layout::default().rect("licon", 450, 450, 550, 550),
                "npc",
                (0, 0, 1000, 1000),
                (300, 300, 700, 700),
            ),
            areas(&[10_000]),
        ),
        case(
            "across_hole_edge",
            ring(
                Layout::default().rect("licon", 250, 450, 350, 550),
                "npc",
                (0, 0, 1000, 1000),
                (300, 300, 700, 700),
            ),
            areas(&[5_000]),
        ),
        case(
            "empty_npc",
            Layout::default().rect("licon", 0, 0, 100, 100),
            areas(&[10_000]),
        ),
    ];
    for k in [1, 50, 99] {
        cases.push(case(
            &format!("straddling/{k}"),
            npc().rect("licon", 1000 - k, 400, 1100 - k, 500),
            areas(&[i128::from(100 - k) * 100]),
        ));
    }
    every_placement(cases)
}

// ------------------------------------------------------------- edge checks

/// `length(tap.edges() and diff.edges()) >= 100nm` (`edge_min_length`,
/// DRC-051, sky130 difftap.4): one finding per butting edge shorter than the
/// limit, measuring it.
///
/// Shapes: a tap whose whole side butts a taller diffusion, and one butting
/// only part of its side, swept; a tap overlapping the diffusion, which leaves
/// no butting edge.
fn edge_min_length() -> Vec<Fixture> {
    const LIMIT: i64 = 100;
    let deck = new_deck(
        &["diff", "tap"],
        "layer butt = tap.edges() and diff.edges()\nrule difftap.4 length(butt) >= 100nm\n",
    );
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        fixture(
            &format!("edge_min_length/{name}"),
            &["DRC-051", "DRC-122"],
            &deck,
            layout,
            &[("difftap.4", findings)],
        )
    };
    let mut cases = Vec::new();
    for (len, side) in sweep(LIMIT) {
        cases.push(case(
            &format!("whole_side/{side}"),
            Layout::default()
                .rect("tap", 0, 0, 500, len)
                .rect("diff", 500, -200, 1500, 800),
            below(len, LIMIT),
        ));
        cases.push(case(
            &format!("part_side/{side}"),
            Layout::default()
                .rect("tap", 0, 0, 500, 300)
                .rect("diff", 500, 300 - len, 1500, 1000),
            below(len, LIMIT),
        ));
    }
    cases.push(case(
        "overlapping",
        Layout::default()
            .rect("tap", 0, 0, 600, 50)
            .rect("diff", 500, -200, 1500, 800),
        vec![],
    ));
    every_placement(cases)
}

/// `space(butt) >= 200nm` on the butting edges (`edge_spacing`, DRC-051,
/// sky130 difftap.5), and `space(tap.edges(), nsdm.edges()) >= 200nm`: one
/// finding per pair of parallel edges closer than the limit, measured edge to
/// edge, Euclidean; perpendicular edges are not paired.
///
/// Shapes: a tap between two diffusions (its two butting edges face each other
/// across its width); two taps whose butting edges are collinear, end to end;
/// a tap inside nsdm, whose four facing pairs are the margin apart.
fn edge_spacing() -> Vec<Fixture> {
    const LIMIT: i64 = 200;
    let deck_butt = new_deck(
        &["diff", "tap"],
        "layer butt = tap.edges() and diff.edges()\nrule difftap.5 space(butt) >= 200nm\n",
    );
    let deck_two = new_deck(
        &["tap", "nsdm"],
        "rule e2 space(tap.edges(), nsdm.edges()) >= 200nm\n",
    );
    let catalog = &["DRC-051", "DRC-122"];
    let mut cases = Vec::new();
    for (g, side) in sweep(LIMIT) {
        cases.push(fixture(
            &format!("edge_spacing/between/{side}"),
            catalog,
            &deck_butt,
            Layout::default()
                .rect("diff", -1000, -500, 0, 1000)
                .rect("tap", 0, 0, g, 500)
                .rect("diff", g, -500, g + 1000, 1000),
            &[("difftap.5", below(g, LIMIT))],
        ));
        cases.push(fixture(
            &format!("edge_spacing/end_to_end/{side}"),
            catalog,
            &deck_butt,
            Layout::default()
                .rect("tap", 0, 0, 500, 300)
                .rect("tap", 0, 300 + g, 500, 600 + g)
                .rect("diff", 500, -500, 1500, 1500),
            &[("difftap.5", below(g, LIMIT))],
        ));
        let four = if g < LIMIT { lengths(&[g; 4]) } else { vec![] };
        cases.push(fixture(
            &format!("edge_spacing/two_layers/{side}"),
            catalog,
            &deck_two,
            Layout::default()
                .rect("tap", 0, 0, 400, 400)
                .rect("nsdm", -g, -g, 400 + g, 400 + g),
            &[("e2", four)],
        ));
    }
    every_placement(cases)
}

/// `enclosure(diff.edges(), nsdm) >= 100nm` and `enclosure(diff.edges() not
/// tap.edges(), nsdm) >= 100nm` (`edge_enclosure`, DRC-051, sky130 nsd.5a):
/// one finding per edge whose strip straight out, along its whole length, is
/// covered less than the limit deep, measuring the covered depth.
///
/// Diffusion is `[0, 1000] x [0, 500]`. Shapes: one side's margin swept, and
/// all four; nsdm stopping short of the diffusion's top (three edges at 0);
/// nsdm missing only a corner square diagonally off the diffusion (clean: the
/// documented diagonal blind spot); no nsdm at all; a hole in nsdm 50 nm out
/// from one edge (covered 50 deep); the butting edge to a tap excluded, with
/// nsdm not reaching over the tap; and a diffusion ring, whose hole edges face
/// into the hole: nsdm filling it covers them, nsdm reaching 50 nm into it
/// covers them 50 deep.
fn edge_enclosure() -> Vec<Fixture> {
    const LIMIT: i64 = 100;
    let deck_all = new_deck(
        &["diff", "tap", "nsdm"],
        "rule nsd.5a enclosure(diff.edges(), nsdm) >= 100nm\n",
    );
    let deck_butt = new_deck(
        &["diff", "tap", "nsdm"],
        "rule nsd.5a enclosure(diff.edges() not tap.edges(), nsdm) >= 100nm\n",
    );
    let case = |name: &str, deck: &str, layout: Layout, findings: Vec<Finding>| {
        fixture(
            &format!("edge_enclosure/{name}"),
            &["DRC-051", "DRC-122"],
            deck,
            layout.rect("diff", 0, 0, 1000, 500),
            &[("nsd.5a", findings)],
        )
    };
    let mut cases = Vec::new();
    for (m, side) in sweep(LIMIT) {
        cases.push(case(
            &format!("one_side/{side}"),
            &deck_all,
            Layout::default().rect("nsdm", -300, -300, 1000 + m, 800),
            below(m, LIMIT),
        ));
        cases.push(case(
            &format!("every_side/{side}"),
            &deck_all,
            Layout::default().rect("nsdm", -m, -m, 1000 + m, 500 + m),
            if m < LIMIT { lengths(&[m; 4]) } else { vec![] },
        ));
        cases.push(case(
            &format!("butting_excluded/{side}"),
            &deck_butt,
            Layout::default()
                .rect("tap", -400, 0, 0, 500)
                .rect("nsdm", 0, -m, 1000 + m, 500 + m),
            if m < LIMIT { lengths(&[m; 3]) } else { vec![] },
        ));
    }
    cases.push(case(
        "short_of_top",
        &deck_all,
        Layout::default().rect("nsdm", -300, -300, 1300, 400),
        lengths(&[0; 3]),
    ));
    let corner_missing = [
        (-300, -300),
        (1300, -300),
        (1300, 500),
        (1000, 500),
        (1000, 800),
        (-300, 800),
    ];
    cases.push(case(
        "corner_missing",
        &deck_all,
        Layout::default().polygon("nsdm", &corner_missing),
        vec![],
    ));
    cases.push(case(
        "no_nsdm",
        &deck_all,
        Layout::default(),
        lengths(&[0; 4]),
    ));
    cases.push(case(
        "hole_in_strip",
        &deck_all,
        ring(
            Layout::default(),
            "nsdm",
            (-300, -300, 1300, 800),
            (1050, 100, 1150, 400),
        ),
        lengths(&[50]),
    ));
    // A diffusion ring: its hole's edges face into the hole, so nsdm reaching
    // 50 nm into the hole covers them 50 deep, and nsdm filling it covers them.
    for (name, nsdm_hole, findings) in [
        ("ring_hole_covered", None, vec![]),
        (
            "ring_hole_partly",
            Some((350, 350, 650, 650)),
            lengths(&[50; 4]),
        ),
    ] {
        let nsdm = match nsdm_hole {
            None => Layout::default().rect("nsdm", -200, -200, 1200, 1200),
            Some(hole) => ring(Layout::default(), "nsdm", (-200, -200, 1200, 1200), hole),
        };
        cases.push(fixture(
            &format!("edge_enclosure/{name}"),
            &["DRC-051", "DRC-122"],
            &deck_all,
            ring(nsdm, "diff", (0, 0, 1000, 1000), (300, 300, 700, 700)),
            &[("nsd.5a", findings)],
        ));
    }
    every_placement(cases)
}

// -------------------------------------------------------------------- cuts

/// Cut-to-cut spacing `space(cut) >= 100nm` (`min_spacing` on a cut layer,
/// DRC-060) and cross-layer cut spacing `space(via1, via2) >= 100nm`
/// (`min_spacing_diff`, DRC-065): one finding per pair closer than the limit,
/// measuring the Euclidean gap floored.
///
/// Shapes: side by side, swept; diagonal at (60, 79/80/81) beyond the first
/// cut's corner, so the gap is exactly 99.2, 100 and 100.8; two cuts on one
/// layer abutting, and touching only at a corner (one figure, no gap); a via2
/// stacked on a via1 (0).
fn cut_spacing() -> Vec<Fixture> {
    const LIMIT: i64 = 100;
    let deck_one = new_deck(&["cut"], "rule via.2 space(cut) >= 100nm\n");
    let deck_two = new_deck(&["via1", "via2"], "rule v12 space(via1, via2) >= 100nm\n");
    let mut cases = Vec::new();
    let mut both = |name: &str, first: Rect, second: Rect, findings: Vec<Finding>| {
        cases.push(fixture(
            &format!("cut_spacing/one_layer/{name}"),
            &["DRC-060"],
            &deck_one,
            rects(Layout::default(), "cut", &[first, second]),
            &[("via.2", findings.clone())],
        ));
        cases.push(fixture(
            &format!("cut_spacing/two_layers/{name}"),
            &["DRC-065"],
            &deck_two,
            Layout::default()
                .rect("via1", first.0, first.1, first.2, first.3)
                .rect("via2", second.0, second.1, second.2, second.3),
            &[("v12", findings)],
        ));
    };
    for (g, side) in sweep(LIMIT) {
        both(
            &format!("side/{side}"),
            (0, 0, 100, 100),
            (100 + g, 0, 200 + g, 100),
            below(g, LIMIT),
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
    cases.push(fixture(
        "cut_spacing/one_layer/abutting",
        &["DRC-060"],
        &deck_one,
        rects(
            Layout::default(),
            "cut",
            &[(0, 0, 100, 100), (100, 0, 200, 100)],
        ),
        &[("via.2", vec![])],
    ));
    cases.push(fixture(
        "cut_spacing/two_layers/stacked",
        &["DRC-065"],
        &deck_two,
        Layout::default()
            .rect("via1", 0, 0, 100, 100)
            .rect("via2", 0, 0, 100, 100),
        &[("v12", lengths(&[0]))],
    ));
    cases.push(fixture(
        "cut_spacing/one_layer/corner_touch",
        &["DRC-060"],
        &deck_one,
        rects(
            Layout::default(),
            "cut",
            &[(0, 0, 100, 100), (100, 100, 200, 200)],
        ),
        &[("via.2", vec![])],
    ));
    every_placement(cases)
}

/// `redundant_via(cut; within: 100nm) >= 2`, and `>= 3` (`redundant_via`,
/// DRC-066 and DRC-117): one finding per drawn cut with fewer cuts, itself
/// included, within 100 nm (inclusive, Euclidean), measuring the count.
///
/// Shapes: a pair side by side at 99/100/101; a pair diagonal at Euclidean
/// 99.2/100/100.8; one cut alone; two abutting and two overlapping cuts (each
/// counts the other: cuts are counted as drawn); a row of three, where the
/// ends see two and the middle three; an empty layer.
fn redundant_via() -> Vec<Fixture> {
    const WITHIN: i64 = 100;
    let deck = new_deck(
        &["cut", "other"],
        "rule two redundant_via(cut; within: 100nm) >= 2\n\
         rule three redundant_via(cut; within: 100nm) >= 3\n",
    );
    let case = |name: &str, cuts: &[Rect], two: Vec<Finding>, three: Vec<Finding>| {
        fixture(
            &format!("redundant_via/{name}"),
            &["DRC-066", "DRC-117"],
            &deck,
            rects(
                Layout::default().rect("other", -1000, -1000, -900, -900),
                "cut",
                cuts,
            ),
            &[("two", two), ("three", three)],
        )
    };
    let mut cases = Vec::new();
    for (g, side) in sweep(WITHIN) {
        let alone = if g > WITHIN { 1 } else { 2 };
        cases.push(case(
            &format!("pair/{side}"),
            &[(0, 0, 100, 100), (100 + g, 0, 200 + g, 100)],
            if g > WITHIN {
                vec![count(1); 2]
            } else {
                vec![]
            },
            vec![count(alone); 2],
        ));
    }
    for (dy, side, near) in [(79, "below", true), (80, "at", true), (81, "above", false)] {
        let n = if near { 2 } else { 1 };
        cases.push(case(
            &format!("diagonal/{side}"),
            &[(0, 0, 100, 100), (160, 100 + dy, 260, 200 + dy)],
            if near { vec![] } else { vec![count(1); 2] },
            vec![count(n); 2],
        ));
    }
    cases.push(case(
        "single",
        &[(0, 0, 100, 100)],
        vec![count(1)],
        vec![count(1)],
    ));
    cases.push(case(
        "abutting",
        &[(0, 0, 100, 100), (100, 0, 200, 100)],
        vec![],
        vec![count(2); 2],
    ));
    cases.push(case(
        "overlapping",
        &[(0, 0, 100, 100), (50, 0, 150, 100)],
        vec![],
        vec![count(2); 2],
    ));
    cases.push(case(
        "row_of_three",
        &[(0, 0, 100, 100), (200, 0, 300, 100), (400, 0, 500, 100)],
        vec![],
        vec![count(2); 2],
    ));
    cases.push(case("empty", &[], vec![], vec![]));
    every_placement(cases)
}

/// LEF `MINIMUMCUT 2 WIDTH 1.0` on `m1`, vias from `m2`: `min_cuts(via, m1,
/// m2; width: 1000nm) >= 2` (`mc`) and with `within: 300nm` (`mcw`,
/// `MINIMUMCUT 2 WIDTH 1.0 WITHIN 0.3`) (`minimum_cut`, DRC-066): a via is the
/// cuts joining one `m1` figure to one `m2` figure, split by `within` into
/// groups of cuts closer than 300 nm; one held by the part of `m1` wider than
/// 1000 nm needs two cuts, and each of its cuts is reported with its count.
///
/// Oracle: LEF/DEF 5.8 "the number of cuts a via must have when it is on a
/// wide wire or pin whose width is greater than width", on vias and wires
/// drawn to a count and a width.
///
/// Shapes, 100 nm cuts on a 3000 nm `m1` plate: one cut under an `m2` pad;
/// two under one pad 200 apart (one via, one group) and 400 apart (one via,
/// two groups under `within`); two cuts under two pads (two vias); a cut with
/// no `m2` over it; a wire 999, 1000 and 1001 wide with one cut (held only
/// when strictly wider); a cut on a 500 nm tab off the plate (not held); a cut
/// on no `m1` (not held).
fn minimum_cut() -> Vec<Fixture> {
    let deck = new_deck(
        &["via", "m1", "m2"],
        "rule mc min_cuts(via, m1, m2; width: 1000nm) >= 2\n\
         rule mcw min_cuts(via, m1, m2; width: 1000nm, within: 300nm) >= 2\n",
    );
    let case = |name: &str, layout: Layout, mc: &[u32], mcw: &[u32]| {
        let counts = |n: &[u32]| n.iter().map(|&c| count(c)).collect::<Vec<_>>();
        fixture(
            &format!("minimum_cut/{name}"),
            &["DRC-066"],
            &deck,
            layout,
            &[("mc", counts(mc)), ("mcw", counts(mcw))],
        )
    };
    let plate = || Layout::default().rect("m1", 0, 0, 3000, 3000);
    let mut cases = Vec::new();
    cases.push(case(
        "single",
        plate()
            .rect("via", 1000, 1000, 1100, 1100)
            .rect("m2", 900, 900, 1200, 1200),
        &[1],
        &[1],
    ));
    for (gap, name, mcw) in [(200, "pair_close", &[][..]), (400, "pair_far", &[1, 1][..])] {
        let x = 1100 + gap;
        cases.push(case(
            name,
            plate()
                .rect("via", 1000, 1000, 1100, 1100)
                .rect("via", x, 1000, x + 100, 1100)
                .rect("m2", 900, 900, x + 200, 1200),
            &[],
            mcw,
        ));
    }
    cases.push(case(
        "two_pads",
        plate()
            .rect("via", 1000, 1000, 1100, 1100)
            .rect("via", 1300, 1000, 1400, 1100)
            .rect("m2", 900, 900, 1150, 1200)
            .rect("m2", 1250, 900, 1500, 1200),
        &[1, 1],
        &[1, 1],
    ));
    cases.push(case(
        "no_far_metal",
        plate().rect("via", 1000, 1000, 1100, 1100),
        &[1],
        &[1],
    ));
    for (w, held) in [(999, false), (1000, false), (1001, true)] {
        let one: &[u32] = if held { &[1] } else { &[] };
        cases.push(case(
            &format!("wire/{w}"),
            Layout::default()
                .rect("m1", 0, 0, 5000, w)
                .rect("via", 2000, 100, 2100, 200)
                .rect("m2", 1900, 0, 2200, 300),
            one,
            one,
        ));
    }
    cases.push(case(
        "narrow_tab",
        plate()
            .rect("m1", 3000, 1000, 4000, 1500)
            .rect("via", 3500, 1200, 3600, 1300)
            .rect("m2", 3400, 1100, 3700, 1400),
        &[],
        &[],
    ));
    cases.push(case(
        "off_metal",
        plate()
            .rect("via", 5000, 5000, 5100, 5100)
            .rect("m2", 4900, 4900, 5200, 5200),
        &[],
        &[],
    ));
    every_placement(cases)
}

/// `via_stack(v1, v2, v3, v4) <= 2` (`via_stack`, DRC-065, LEF `MAXVIASTACK
/// 2`): a cut stacks on a cut of the layer below that it overlaps; the cut
/// third from the bottom of each stack taller than two is one finding,
/// measuring the stack's height.
///
/// Oracle: LEF/DEF 5.8 "a via is considered to be in a stack with another
/// via if the cut of the first via overlaps any part of the cut of the
/// second via", on stacks drawn to a height.
///
/// Shapes, 100 nm cuts: stacks of two, three and four aligned cuts (the
/// four-high stack is reported once, on its third cut, measuring 4); a stack
/// of three whose cuts overlap by half; a v3 cut beside the v2 cut, not on
/// it (two stacks of two); a v2 cut abutting the v1 cut (touching is not
/// stacking); a v1 cut under two v2 cuts each carrying a v3 (two stacks of
/// three, two findings).
fn via_stack() -> Vec<Fixture> {
    let deck = new_deck(
        &["v1", "v2", "v3", "v4"],
        "rule stack via_stack(v1, v2, v3, v4) <= 2\n",
    );
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        fixture(
            &format!("via_stack/{name}"),
            &["DRC-065"],
            &deck,
            layout,
            &[("stack", findings)],
        )
    };
    let cut =
        |layout: Layout, layer: &str, x: i64, y: i64| layout.rect(layer, x, y, x + 100, y + 100);
    let tower = |height: usize| {
        ["v1", "v2", "v3", "v4"][..height]
            .iter()
            .fold(Layout::default(), |l, layer| cut(l, layer, 0, 0))
    };
    let mut cases = Vec::new();
    for (height, findings) in [(2, vec![]), (3, vec![count(3)]), (4, vec![count(4)])] {
        cases.push(case(&format!("tower/{height}"), tower(height), findings));
    }
    cases.push(case(
        "half_overlap",
        cut(
            cut(cut(Layout::default(), "v1", 0, 0), "v2", 50, 0),
            "v3",
            100,
            0,
        ),
        vec![count(3)],
    ));
    cases.push(case(
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
    ));
    cases.push(case(
        "abutting",
        cut(
            cut(cut(Layout::default(), "v1", 0, 0), "v2", 100, 0),
            "v3",
            100,
            0,
        ),
        vec![],
    ));
    cases.push(case(
        "branching",
        Layout::default()
            .rect("v1", 0, 0, 300, 100)
            .rect("v2", 0, 0, 100, 100)
            .rect("v2", 200, 0, 300, 100)
            .rect("v3", 0, 0, 100, 100)
            .rect("v3", 200, 0, 300, 100),
        vec![count(3), count(3)],
    ));
    every_placement(cases)
}

/// `via_array_space(cut; array: 3) >= 100nm` (`via_array_spacing`, DRC-062):
/// cuts joined by gaps of at most 100 nm form a cluster, a cluster of more
/// than 3 is an array, and each pair in an array closer than 100 nm is one
/// finding measuring its gap, at the midpoint of its nearest points.
///
/// Shapes: rows of 3 and 4 cuts at 99/100/101 (3 is not an array; at 100 the
/// row is one array with no close pair; at 101 nothing joins); a 3 x 3 grid at
/// 90 (12 side pairs; the diagonals are 127 apart); two close pairs joined
/// into one array by a 100 nm gap, and kept apart by 101; an array with a cut
/// drawn overlapping another (cuts are as drawn: a gap of 0); an L-shaped cut
/// marked on the stretch it measured, not its box (F82); an empty layer.
/// Nightly: rows of 1 to 6 cuts at 95 to 105.
fn via_array_spacing(depth: Depth) -> Vec<Fixture> {
    const LIMIT: i64 = 100;
    let deck = new_deck(
        &["cut", "other"],
        "rule cnt.b1 via_array_space(cut; array: 3) >= 100nm\n",
    );
    let case = |name: &str, cuts: Vec<Rect>, findings: Vec<Finding>| {
        fixture(
            &format!("via_array_spacing/{name}"),
            &["DRC-062"],
            &deck,
            rects(
                Layout::default().rect("other", -1000, -1000, -900, -900),
                "cut",
                &cuts,
            ),
            &[("cnt.b1", findings)],
        )
    };
    let row = |n: i64, g: i64| -> Vec<Rect> {
        (0..n)
            .map(|i| (i * (100 + g), 0, i * (100 + g) + 100, 100))
            .collect()
    };
    let row_findings = |n: i64, g: i64| {
        if n > 3 && g < LIMIT {
            lengths(&vec![g; usize::try_from(n - 1).expect("a small row")])
        } else {
            vec![]
        }
    };
    let mut cases = Vec::new();
    for (g, side) in sweep(LIMIT) {
        for n in [3, 4] {
            cases.push(case(
                &format!("row{n}/{side}"),
                row(n, g),
                row_findings(n, g),
            ));
        }
    }
    let grid: Vec<Rect> = (0..3)
        .flat_map(|i| (0..3).map(move |j| (i * 190, j * 190, i * 190 + 100, j * 190 + 100)))
        .collect();
    cases.push(case("grid3x3", grid, lengths(&[90; 12])));
    for (middle, name, findings) in [
        (100, "joined_pairs", lengths(&[90, 90])),
        (101, "separate_pairs", vec![]),
    ] {
        let x3 = 290 + middle;
        cases.push(case(
            name,
            vec![
                (0, 0, 100, 100),
                (190, 0, 290, 100),
                (x3, 0, x3 + 100, 100),
                (x3 + 190, 0, x3 + 290, 100),
            ],
            findings,
        ));
    }
    let mut doubled = row(4, 100);
    doubled.push((-50, 0, 50, 100));
    cases.push(case("overlapping_cut", doubled, lengths(&[0])));
    // F82: the second cut is an L, its foot x = 190..290 up to y = 50 and its
    // stem x = 240..290 up to y = 200. The first cut's right side, x = 100,
    // faces the foot's left side x = 190 only over y = 0..50: 90, marked at
    // (145, 25). The boxes' gap is centred at (145, 50), beside the foot.
    // The stem's right side faces the third cut over y = 0..100 at (335, 50),
    // and the third the fourth at (525, 50).
    cases.push(fixture(
        "via_array_spacing/l_cut_beside_a_square",
        &["DRC-062"],
        &deck,
        rects(
            Layout::default().rect("other", -1000, -1000, -900, -900),
            "cut",
            &[(0, 0, 100, 100), (380, 0, 480, 100), (570, 0, 670, 100)],
        )
        .polygon(
            "cut",
            &[
                (190, 0),
                (290, 0),
                (290, 200),
                (240, 200),
                (240, 50),
                (190, 50),
            ],
        ),
        &[(
            "cnt.b1",
            vec![
                Finding::length(90).at(145, 25),
                Finding::length(90).at(335, 50),
                Finding::length(90).at(525, 50),
            ],
        )],
    ));
    cases.push(case("empty", vec![], vec![]));
    if depth == Depth::Nightly {
        for n in 1..=6 {
            for g in 95..=105 {
                cases.push(case(
                    &format!("rows/n{n}_g{g}"),
                    row(n, g),
                    row_findings(n, g),
                ));
            }
        }
    }
    every_placement(cases)
}

/// `space(cut, center) >= 300nm` (`cut_spacing`, DRC-061, LEF `SPACING
/// CENTERTOCENTER`): one finding per pair of drawn cuts whose bounding-box
/// centres are closer than the limit, measuring that distance floored.
///
/// Oracle: the cuts are drawn so their centres are a chosen distance apart;
/// the diagonal pair at centre offsets (180, 239/240/241) is 299.2, 300 and
/// 300.8 apart (a 180-240-300 triangle).
///
/// Shapes: two 100 nm squares, swept; a 100 nm and a 200 nm cut, swept, whose
/// 150 nm edge gap an edge measure would flag at every step; a 101 nm and a
/// 100 nm cut, whose centres are a half unit off the grid (299.5 floors to
/// 299, 300.5 passes); the diagonal pair; overlapping cuts (50) and a cut
/// nested in another (0); a row of three at a 250 nm pitch (the outer pair,
/// 500 apart, passes); an empty layer.
fn center_spacing() -> Vec<Fixture> {
    const LIMIT: i64 = 300;
    let deck = new_deck(&["cut"], "rule c2c space(cut, center) >= 300nm\n");
    let case = |name: &str, cuts: &[Rect], findings: Vec<Finding>| {
        fixture(
            &format!("center_spacing/{name}"),
            &["DRC-061"],
            &deck,
            rects(Layout::default(), "cut", cuts),
            &[("c2c", findings)],
        )
    };
    let mut cases = Vec::new();
    for (d, side) in sweep(LIMIT) {
        cases.push(case(
            &format!("squares/{side}"),
            &[(0, 0, 100, 100), (d, 0, d + 100, 100)],
            below(d, LIMIT),
        ));
        // Centres 50 and x + 100 apart by d: x = d - 50.
        cases.push(case(
            &format!("unequal/{side}"),
            &[(0, 0, 100, 100), (d - 50, 0, d + 150, 100)],
            below(d, LIMIT),
        ));
        // Centres 50.5 and x + 50 along x, both 50 along y: d - 0.5 apart
        // for x = d, floored to d - 1.
        cases.push(case(
            &format!("half_unit/{side}"),
            &[(0, 0, 101, 100), (d, 0, d + 100, 100)],
            below(d - 1, LIMIT),
        ));
    }
    for (dy, side, findings) in [
        (239, "below", lengths(&[299])),
        (240, "at", vec![]),
        (241, "above", vec![]),
    ] {
        cases.push(case(
            &format!("diagonal/{side}"),
            &[(0, 0, 100, 100), (180, dy, 280, dy + 100)],
            findings,
        ));
    }
    cases.push(case(
        "overlapping",
        &[(0, 0, 100, 100), (50, 0, 150, 100)],
        lengths(&[50]),
    ));
    cases.push(case(
        "nested",
        &[(0, 0, 300, 300), (100, 100, 200, 200)],
        lengths(&[0]),
    ));
    cases.push(case(
        "row_of_three",
        &[(0, 0, 100, 100), (250, 0, 350, 100), (500, 0, 600, 100)],
        lengths(&[250, 250]),
    ));
    cases.push(fixture(
        "center_spacing/empty",
        &["DRC-061"],
        &new_deck(&["cut", "other"], "rule c2c space(cut, center) >= 300nm\n"),
        Layout::default().rect("other", 0, 0, 100, 100),
        &[("c2c", vec![])],
    ));
    every_placement(cases)
}

/// `adjacent_space(cut; cuts: 3, within: 250nm) >= 220nm` (`cut_spacing`,
/// DRC-062, LEF Spacing Rule Example 2 "SPACING 0.22 ADJACENTCUTS 3 WITHIN
/// 0.25") on 200 nm cuts, and `adjacent_space(cut, center; cuts: 3, within:
/// 300nm) >= 300nm` (DRC-061 and DRC-062, Example 4 "a cut can have only two
/// other cuts with center-to-center spacing that is less than 0.30 um") on
/// 100 nm cuts: a pair closer than the limit fails when either cut has at
/// least three other cuts strictly closer than `within`.
///
/// Oracle: the manual's own Figure 1-6. With the diagonal beyond `within`, a
/// cut of a 1 x n row or a 2 x 2 array has two adjacent cuts, a middle cut of
/// a 2 x 3 array three, and the centre of a 3 x 3 four; so at a 219 nm gap a
/// row and a 2 x 2 pass, a 2 x 3 fails on the five pairs that touch its
/// middle cuts, and a 3 x 3 on all twelve side pairs.
///
/// Shapes: those arrays at gaps 219/220/221; a 2 x 3 array 219 apart along
/// its rows with its rows 249, 250 and 251 apart (its middle cuts are held
/// only at 249: `within` is strict); for the centre form, a T of four cuts at
/// a 299/300/301 pitch (its middle has three neighbours) and a 2 x 2 at 299
/// (two each, clean).
fn adjacent_cut_spacing() -> Vec<Fixture> {
    const LIMIT: i64 = 220;
    let deck = new_deck(
        &["cut"],
        "rule adj adjacent_space(cut; cuts: 3, within: 250nm) >= 220nm\n",
    );
    let case = |name: &str, cuts: Vec<Rect>, findings: Vec<Finding>| {
        fixture(
            &format!("adjacent_cut_spacing/{name}"),
            &["DRC-062"],
            &deck,
            rects(Layout::default(), "cut", &cuts),
            &[("adj", findings)],
        )
    };
    // `cols` x `rows` cuts of 200 nm, `gx` apart along a row and `gy` apart
    // between rows.
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
    let mut cases = Vec::new();
    for (g, side) in sweep(LIMIT) {
        let close = |n: usize| {
            if g < LIMIT {
                lengths(&vec![g; n])
            } else {
                vec![]
            }
        };
        cases.push(case(&format!("row4/{side}"), array(4, 1, g, g), vec![]));
        cases.push(case(&format!("array2x2/{side}"), array(2, 2, g, g), vec![]));
        cases.push(case(
            &format!("array3x2/{side}"),
            array(3, 2, g, g),
            close(5),
        ));
        cases.push(case(
            &format!("array3x3/{side}"),
            array(3, 3, g, g),
            close(12),
        ));
    }
    for (gy, side, findings) in [
        (249, "below", lengths(&[219; 4])),
        (250, "at", vec![]),
        (251, "above", vec![]),
    ] {
        cases.push(case(
            &format!("rows_apart/{side}"),
            array(3, 2, 219, gy),
            findings,
        ));
    }
    let deck_center = new_deck(
        &["cut"],
        "rule adjc adjacent_space(cut, center; cuts: 3, within: 300nm) >= 300nm\n",
    );
    let centred = |name: &str, cuts: &[Rect], findings: Vec<Finding>| {
        fixture(
            &format!("adjacent_cut_spacing/center/{name}"),
            &["DRC-061", "DRC-062"],
            &deck_center,
            rects(Layout::default(), "cut", cuts),
            &[("adjc", findings)],
        )
    };
    for (p, side) in sweep(300) {
        cases.push(centred(
            &format!("tee/{side}"),
            &[
                (0, 0, 100, 100),
                (-p, 0, 100 - p, 100),
                (p, 0, 100 + p, 100),
                (0, p, 100, 100 + p),
            ],
            if p < 300 { lengths(&[p; 3]) } else { vec![] },
        ));
    }
    cases.push(centred(
        "array2x2",
        &[
            (0, 0, 100, 100),
            (299, 0, 399, 100),
            (0, 299, 100, 399),
            (299, 299, 399, 399),
        ],
        vec![],
    ));
    every_placement(cases)
}

/// LEF 5.8 `PROTRUSIONWIDTH 0.28 LENGTH 0 WIDTH 1.20` (`protrusion_width`,
/// DRC-125): `protrusion_width(m; wide: 1200nm) >= 280nm`, one finding per
/// narrow part attached to a wide part, measuring its width.
///
/// Oracle: widths drawn by construction against LEF's statement: a stub 279,
/// 280, 281 wide on a 2000 plate (one finding of 279); a 200 stub on a plate
/// 1199, 1200, 1201 wide (a plate exactly 1200 wide is wide); the stub drawn
/// as two abutting 100 halves (one finding of 200: an unmerged reading gives
/// two of 100); a 200 neck joining two plates (one); a lone 200 wire and a
/// 200 tip on a 500 stub on the plate (none: neither touches a wide part).
fn protrusion_width() -> Vec<Fixture> {
    let deck = new_deck(
        &["m"],
        "rule pw protrusion_width(m; wide: 1200nm) >= 280nm\n",
    );
    let plate = || Layout::default().rect("m", 0, 0, 2000, 2000);
    let case = |name: &str, layout: Layout, found: Vec<Finding>| {
        fixture(
            &format!("protrusion_width/{name}"),
            &["DRC-125"],
            &deck,
            layout,
            &[("pw", found)],
        )
    };
    let mut cases = Vec::new();
    for (w, side) in sweep(280) {
        cases.push(case(
            &format!("stub/{side}"),
            plate().rect("m", 500, 2000, 500 + w, 2600),
            below(w, 280),
        ));
    }
    for (p, side) in sweep(1200) {
        let found = if p >= 1200 {
            lengths(&[200])
        } else {
            Vec::new()
        };
        cases.push(case(
            &format!("plate/{side}"),
            Layout::default()
                .rect("m", 0, 0, p, 3000)
                .rect("m", p, 1000, p + 600, 1200),
            found,
        ));
    }
    cases.push(case(
        "stub_halves",
        plate()
            .rect("m", 500, 2000, 600, 2600)
            .rect("m", 600, 2000, 700, 2600),
        lengths(&[200]),
    ));
    cases.push(case(
        "neck",
        plate()
            .rect("m", 2600, 0, 4600, 2000)
            .rect("m", 2000, 900, 2600, 1100),
        lengths(&[200]),
    ));
    cases.push(case(
        "lone_wire",
        Layout::default().rect("m", 0, 0, 200, 3000),
        Vec::new(),
    ));
    cases.push(case(
        "tip_on_a_stub",
        plate()
            .rect("m", 800, 2000, 1300, 2600)
            .rect("m", 950, 2600, 1150, 3000),
        Vec::new(),
    ));
    every_placement(cases)
}

/// `LEF58_KEEPOUTZONE CUTCLASS c1 [TO c2] ENDEXTENSION 0.010 0.080
/// SIDEEXTENSION 0.050 0.020` (`keep_out_zone`, DRC-126) on a 100 x 300 class:
/// `k` holds out every cut, `kt` (its class written 300 x 100) only 100 nm
/// squares. Round a bar `[0, 300] x [0, 100]` the side zone is `[-20, 320] x
/// [-50, 150]` and the end zone `[-10, 310] x [-80, 180]`, as `OpenROAD`'s
/// `checKeepOutZone_main` bloats a horizontal via. One finding per cut of the
/// class and cut in its zones, measuring that cut's area inside them.
///
/// Oracle: areas by hand from the zones: a square past the bar's end 19, 20,
/// 21 from it (in the side zone below 20: 100 at 19; touching is outside), a
/// square above it 79, 80, 81 off (in the end zone below 80); a square 20
/// above it, in both zones (6000, their union: summing the two gives 9000); a
/// square off the corner (125, in the end zone only); a second bar 79 above
/// (300 each way for `k`, two findings, none for `kt`); two squares 10 apart
/// (no class owns a zone: a check holding squares breaks it).
fn keep_out_zone() -> Vec<Fixture> {
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
        fixture(
            &format!("keep_out_zone/{name}"),
            &["DRC-126"],
            &deck,
            layout,
            &[("k", k), ("kt", kt)],
        )
    };
    let mut cases = Vec::new();
    for (gap, side) in sweep(20) {
        let found = if gap < 20 { areas(&[100]) } else { Vec::new() };
        cases.push(case(
            &format!("past_the_end/{side}"),
            square(300 + gap, 0),
            found.clone(),
            found,
        ));
    }
    for (gap, side) in sweep(80) {
        let found = if gap < 80 { areas(&[100]) } else { Vec::new() };
        cases.push(case(
            &format!("above/{side}"),
            square(100, 100 + gap),
            found.clone(),
            found,
        ));
    }
    cases.push(case(
        "in_both_zones",
        square(100, 120),
        areas(&[6000]),
        areas(&[6000]),
    ));
    cases.push(case(
        "off_the_corner",
        square(305, 155),
        areas(&[125]),
        areas(&[125]),
    ));
    cases.push(case(
        "two_bars",
        bar().rect("v", 0, 179, 300, 279),
        areas(&[300, 300]),
        Vec::new(),
    ));
    cases.push(case(
        "two_squares",
        Layout::default()
            .rect("v", 0, 0, 100, 100)
            .rect("v", 110, 0, 210, 100),
        Vec::new(),
        Vec::new(),
    ));
    let mut out = every_placement(cases);
    out.push(
        Fixture::new("keep_out_zone/vacuous", &["DRC-126"], &deck, DRC)
            .layout(Layout::default().rect("v", 0, 0, 100, 100))
            .expect(Expect::rule("k", Vec::new()).examined(0)),
    );
    out
}

/// sky130 licon.2 to licon.2d as one cut-class table (`cut_class_spacing`,
/// DRC-063 and DRC-064): square 170 nm licons 170 apart (licon.2), slotted
/// 190 x 2000 licons 350 apart end to end (licon.2b, "when both the edges are
/// 0.19um in length") and 510 otherwise (licon.2c), and 510 from a square
/// (licon.2d). One finding per pair closer than its cell, measuring the gap.
///
/// Oracle: the sky130 manual's values, and gaps drawn to them; a pair apart
/// along both axes needs the larger of its two readings (`OpenROAD`'s
/// `checkLef58CutSpacingTbl_helper` checks both directions).
///
/// Shapes: squares, slots end to end, slots side by side, a slot beside a
/// square and a square past a slot's end, each swept around its cell; slots
/// end to end 400 apart (only an END-to-END reading passes them); slots
/// offset diagonally 414.8 apart (END to END along y, SIDE to SIDE along x:
/// 510); a 200 nm cut of no class 10 from a square (not checked);
/// overlapping squares, and a slot abutting a square (0, held to the
/// largest cell).
fn cut_class_spacing() -> Vec<Fixture> {
    let deck = new_deck(
        &["licon"],
        "rule licon.2 cut_class_space(licon;\n\
         short: [170nm, 190nm], long: [170nm, 2000nm],\n\
         space: [[170nm, 170nm, 510nm, 510nm], [170nm, 170nm, 510nm, 510nm],\n\
         [510nm, 510nm, 350nm, 510nm], [510nm, 510nm, 510nm, 510nm]])\n",
    );
    let case = |name: &str, cuts: &[Rect], findings: Vec<Finding>| {
        fixture(
            &format!("cut_class_spacing/{name}"),
            &["DRC-063", "DRC-064"],
            &deck,
            rects(Layout::default(), "licon", cuts),
            &[("licon.2", findings)],
        )
    };
    let slot: Rect = (0, 0, 190, 2000);
    let mut cases = Vec::new();
    for (g, side) in sweep(170) {
        cases.push(case(
            &format!("squares/{side}"),
            &[(0, 0, 170, 170), (170 + g, 0, 340 + g, 170)],
            below(g, 170),
        ));
    }
    for (g, side) in sweep(350) {
        cases.push(case(
            &format!("end_to_end/{side}"),
            &[slot, (0, 2000 + g, 190, 4000 + g)],
            below(g, 350),
        ));
    }
    for (g, side) in sweep(510) {
        cases.push(case(
            &format!("side_by_side/{side}"),
            &[slot, (190 + g, 0, 380 + g, 2000)],
            below(g, 510),
        ));
        cases.push(case(
            &format!("slot_beside_square/{side}"),
            &[slot, (190 + g, 900, 360 + g, 1070)],
            below(g, 510),
        ));
        cases.push(case(
            &format!("square_past_slot_end/{side}"),
            &[slot, (10, 2000 + g, 180, 2170 + g)],
            below(g, 510),
        ));
    }
    cases.push(case(
        "end_to_end_400",
        &[slot, (0, 2400, 190, 4400)],
        vec![],
    ));
    cases.push(case(
        "diagonal",
        &[slot, (300, 2400, 490, 4400)],
        lengths(&[414]),
    ));
    cases.push(case(
        "unclassed",
        &[(0, 0, 170, 170), (180, 0, 380, 200)],
        vec![],
    ));
    cases.push(case(
        "overlapping_squares",
        &[(0, 0, 170, 170), (100, 0, 270, 170)],
        lengths(&[0]),
    ));
    cases.push(case(
        "slot_abutting_square",
        &[slot, (190, 0, 360, 170)],
        lengths(&[0]),
    ));
    every_placement(cases)
}

// ----------------------------------------------------------------- density

/// The area two rectangles share.
fn shared(a: Rect, b: Rect) -> i64 {
    let w = a.2.min(b.2) - a.0.max(b.0);
    let h = a.3.min(b.3) - a.1.max(b.1);
    if w > 0 && h > 0 {
        w * h
    } else {
        0
    }
}

/// Every density window by the definition: `side`-square windows from the
/// die's lower-left corner every `step`, as many as cover the die's far
/// edges; each covers the area of `covered` (disjoint rectangles inside the
/// die) inside it over its whole area. Returns `(centre, fraction)`.
fn windows(die: Rect, side: i64, step: i64, covered: &[Rect]) -> Vec<((i64, i64), f64)> {
    let along = |span: i64| {
        let mut origins = vec![0];
        while origins[origins.len() - 1] + side < span {
            origins.push(origins[origins.len() - 1] + step);
        }
        origins
    };
    let mut out = Vec::new();
    for x in along(die.2 - die.0) {
        for y in along(die.3 - die.1) {
            let (x, y) = (die.0 + x, die.1 + y);
            let window = (x, y, x + side, y + side);
            let area: i64 = covered.iter().map(|&r| shared(r, window)).sum();
            #[allow(
                clippy::cast_precision_loss,
                reason = "areas below 2^53 convert exactly"
            )]
            let fraction = area as f64 / (side * side) as f64;
            out.push(((x + side / 2, y + side / 2), fraction));
        }
    }
    out
}

/// The windows a `>= limit` rule (`minimum`) or a `<= limit` rule flags.
fn density_findings(windows: &[((i64, i64), f64)], limit: f64, minimum: bool) -> Vec<Finding> {
    windows
        .iter()
        .filter(|(_, f)| if minimum { *f < limit } else { *f > limit })
        .map(|&(at, f)| ratio(f, at))
        .collect()
}

/// `global_density(met1, die) >= 50%` and `<= 50%`, and
/// `global_density(met1) >= 50%` (`global_density`, DRC-070): at most one
/// finding, at the die's centre, measuring the merged met1 area inside the die
/// over the die's area. The die is the boundary layer's extent, or the whole
/// layout's.
///
/// The die is `[0, 1000]^2`. Shapes: a stripe covering 49.9/50/50.1%; the same
/// with more met1 outside the die (clipped by the boundary rule, widening the
/// die of the other); the stripe drawn as two overlapping halves (counted
/// once); the die drawn as two corner markers (its extent counts); no met1
/// (0); no die (the boundary rules skip, the other measures met1 alone); and
/// a grown derived layer beside a boundary-less rule (F40).
fn global_density() -> Vec<Fixture> {
    let deck_gd = new_deck(
        &["met1", "die"],
        "rule gd.min global_density(met1, die) >= 50%\n\
         rule gd.max global_density(met1, die) <= 50%\n\
         rule gd.all global_density(met1) >= 50%\n",
    );
    let die = || Layout::default().rect("die", 0, 0, 1000, 1000);
    #[allow(clippy::cast_precision_loss, reason = "small areas convert exactly")]
    let fraction = |area: i64, die: i64| area as f64 / die as f64;
    let mut cases = Vec::new();
    for (w, side) in sweep(500) {
        let f = fraction(w * 1000, 1_000_000);
        let min = if w < 500 {
            vec![ratio(f, (500, 500))]
        } else {
            vec![]
        };
        let max = if w > 500 {
            vec![ratio(f, (500, 500))]
        } else {
            vec![]
        };
        let wide = fraction(w * 1000 + 1_000_000, 3_000_000);
        let wide_min = if wide < 0.5 {
            vec![ratio(wide, (1500, 500))]
        } else {
            vec![]
        };
        for (name, layout, all) in [
            ("stripe", die().rect("met1", 0, 0, w, 1000), min.clone()),
            (
                "outside_die",
                die()
                    .rect("met1", 0, 0, w, 1000)
                    .rect("met1", 2000, 0, 3000, 1000),
                wide_min,
            ),
            (
                "overlapping_drawn",
                die()
                    .rect("met1", 0, 0, w, 600)
                    .rect("met1", 0, 400, w, 1000),
                min.clone(),
            ),
        ] {
            cases.push(fixture(
                &format!("global_density/{name}/{side}"),
                &["DRC-070"],
                &deck_gd,
                layout,
                &[
                    ("gd.min", min.clone()),
                    ("gd.max", max.clone()),
                    ("gd.all", all),
                ],
            ));
        }
    }
    let below_half = vec![ratio(0.499, (500, 500))];
    cases.push(fixture(
        "global_density/die_two_markers",
        &["DRC-070"],
        &deck_gd,
        Layout::default()
            .rect("die", 0, 0, 100, 100)
            .rect("die", 900, 900, 1000, 1000)
            .rect("met1", 0, 0, 499, 1000),
        &[
            ("gd.min", below_half.clone()),
            ("gd.max", vec![]),
            ("gd.all", below_half),
        ],
    ));
    cases.push(fixture(
        "global_density/empty_met1",
        &["DRC-070"],
        &deck_gd,
        die(),
        &[
            ("gd.min", vec![ratio(0.0, (500, 500))]),
            ("gd.max", vec![]),
            ("gd.all", vec![ratio(0.0, (500, 500))]),
        ],
    ));
    cases.push(
        Fixture::new("global_density/empty_die", &["DRC-070"], &deck_gd, DRC)
            .layout(Layout::default().rect("met1", 0, 0, 400, 1000))
            .expect(Expect::outcome("gd.min", Want::Skipped))
            .expect(Expect::outcome("gd.max", Want::Skipped))
            .expect(Expect::clean("gd.all")),
    );
    // Without a boundary the die is the whole layout, `[0, 1000]^2` here, so
    // met1 covers 70%. A derived layer grown past the drawing is not layout:
    // it must not widen the die (F40), which would hide the maximum's
    // violation and invent the minimum's.
    cases.push(fixture(
        "global_density/derived_halo",
        &["DRC-070"],
        &new_deck(
            &["met1", "other"],
            "layer halo = met1.sized(500nm)\n\
             rule gd.min global_density(met1) >= 50%\n\
             rule gd.max global_density(met1) <= 60%\n",
        ),
        Layout::default()
            .rect("other", 0, 0, 1000, 1000)
            .rect("met1", 0, 0, 700, 1000),
        &[("gd.min", vec![]), ("gd.max", vec![ratio(0.7, (500, 500))])],
    ));
    every_placement(cases)
}

/// `density(met1, die; window: 1000nm, step: 500nm) >= 50%` and `<= 50%`
/// (`density`, DRC-071): one finding per window, at its centre, whose merged
/// met1 area inside the die over the whole window is outside the limit.
///
/// The die is `[0, 2000]^2`, tiled by 3 x 3 windows exactly, so every symmetry
/// maps the windows onto themselves. Shapes: met1 covering `[0, 1000 + d]`
/// for d of -1, 0, 1, which sweeps the middle column through 50%; the same
/// drawn as two overlapping pieces; with met1 outside the die (clipped); the
/// die drawn as two corner markers; no met1 (every window 0); no die
/// (skipped); a boundary-less rule beside a grown derived layer, which must
/// not move the die (F40). Then, without a boundary, windows
/// that hang past the die's far edge or exceed the die (counted empty outside
/// it), under translations only since the windows anchor on the lower-left
/// corner. Nightly: d from -20 to 20.
fn density(depth: Depth) -> Vec<Fixture> {
    let deck_pd = new_deck(
        &["met1", "die"],
        "rule pd.min density(met1, die; window: 1000nm, step: 500nm) >= 50%\n\
         rule pd.max density(met1, die; window: 1000nm, step: 500nm) <= 50%\n",
    );
    let die = (0, 0, 2000, 2000);
    let case = |name: &str, layout: Layout, covered: &[Rect]| {
        let windows = windows(die, 1000, 500, covered);
        fixture(
            &format!("density/{name}"),
            &["DRC-071"],
            &deck_pd,
            layout.rect("die", die.0, die.1, die.2, die.3),
            &[
                ("pd.min", density_findings(&windows, 0.5, true)),
                ("pd.max", density_findings(&windows, 0.5, false)),
            ],
        )
    };
    let stripe = |d: i64| (0, 0, 1000 + d, 2000);
    let mut cases = Vec::new();
    for (d, side) in [(-1, "below"), (0, "at"), (1, "above")] {
        let s = stripe(d);
        cases.push(case(
            &format!("stripe/{side}"),
            rects(Layout::default(), "met1", &[s]),
            &[s],
        ));
        cases.push(case(
            &format!("overlapping_drawn/{side}"),
            Layout::default()
                .rect("met1", 0, 0, 700, 2000)
                .rect("met1", 300, 0, s.2, 2000),
            &[s],
        ));
        cases.push(case(
            &format!("outside_die/{side}"),
            rects(Layout::default(), "met1", &[s, (3000, 0, 4000, 2000)]),
            &[s],
        ));
    }
    cases.push(case("empty_met1", Layout::default(), &[]));
    // The die drawn as two corner markers: its extent, not its area, counts.
    let markers = windows(die, 1000, 500, &[stripe(-1)]);
    cases.push(fixture(
        "density/die_two_markers",
        &["DRC-071"],
        &deck_pd,
        Layout::default()
            .rect("die", 0, 0, 100, 100)
            .rect("die", 1900, 1900, 2000, 2000)
            .rect("met1", 0, 0, 999, 2000),
        &[
            ("pd.min", density_findings(&markers, 0.5, true)),
            ("pd.max", density_findings(&markers, 0.5, false)),
        ],
    ));
    // Without a boundary, the same windows over the drawn layout; a derived
    // layer grown past it must not move the die (F40).
    cases.push(fixture(
        "density/derived_halo",
        &["DRC-071"],
        &new_deck(
            &["met1", "other"],
            "layer halo = met1.sized(500nm)\n\
             rule pd.min density(met1; window: 1000nm, step: 500nm) >= 50%\n\
             rule pd.max density(met1; window: 1000nm, step: 500nm) <= 50%\n",
        ),
        Layout::default()
            .rect("other", 0, 0, 2000, 2000)
            .rect("met1", 0, 0, 999, 2000),
        &[
            ("pd.min", density_findings(&markers, 0.5, true)),
            ("pd.max", density_findings(&markers, 0.5, false)),
        ],
    ));
    cases.push(
        Fixture::new("density/empty_die", &["DRC-071"], &deck_pd, DRC)
            .layout(Layout::default().rect("met1", 0, 0, 1000, 2000))
            .expect(Expect::outcome("pd.min", Want::Skipped))
            .expect(Expect::outcome("pd.max", Want::Skipped)),
    );
    if depth == Depth::Nightly {
        for d in -20..=20 {
            let s = stripe(d);
            cases.push(case(
                &format!("stripe_sweep/{d}"),
                rects(Layout::default(), "met1", &[s]),
                &[s],
            ));
        }
    }
    let mut out = every_placement(cases);

    let deck_die = new_deck(
        &["met1"],
        "rule pd density(met1; window: 1000nm, step: 1000nm) >= 60%\n",
    );
    let anchored: Vec<Fixture> = [
        ("hanging", (0, 0, 1500, 1000), vec![ratio(0.5, (1500, 500))]),
        (
            "die_smaller_than_window",
            (0, 0, 500, 500),
            vec![ratio(0.25, (500, 500))],
        ),
    ]
    .into_iter()
    .map(|(name, met1, findings)| {
        fixture(
            &format!("density/{name}"),
            &["DRC-071"],
            &deck_die,
            rects(Layout::default(), "met1", &[met1]),
            &[("pd", findings)],
        )
    })
    .collect();
    out.extend(every_offset(&anchored));
    out
}

/// Pattern density inside each shape of a region layer (`region_density`,
/// DRC-072: sky130 vpp.5a "max pattern density of met3.dg over capacitor.dg",
/// vpp.11 the minimum): `region_density(met3, cap) <= 25%` and `>= 10%`, one
/// finding per capacitor outside a limit, at the centre of its first
/// rectangle, measuring the fraction.
///
/// Oracle: coverages fixed by construction: the met3 inside a 1000 square
/// swept 249/250/251 rows tall against 25%; two capacitors at 30% and 5%,
/// each a finding of its own (one extent for the whole layer, as `density`
/// takes a boundary, reads 17.5% and passes both); met3 reaching outside its
/// capacitor counted only inside (37.5% if counted whole); met3 filling only
/// the hole of a ring-shaped capacitor, 0 (a check that fills the hole reads
/// 25% and passes); met3 with no capacitor, nothing.
fn region_density() -> Vec<Fixture> {
    let deck = new_deck(
        &["met3", "cap"],
        "rule dmax region_density(met3, cap) <= 25%\nrule dmin region_density(met3, cap) >= 10%\n",
    );
    let case = |name: &str, layout: Layout, max: Vec<Finding>, min: Vec<Finding>| {
        fixture(
            &format!("region_density/{name}"),
            &["DRC-072"],
            &deck,
            layout,
            &[("dmax", max), ("dmin", min)],
        )
    };
    let cap = |layout: Layout| layout.rect("cap", 0, 0, 1000, 1000);
    let mut cases = Vec::new();
    for (h, side) in sweep(250) {
        #[allow(clippy::cast_precision_loss, reason = "small integers")]
        let max = if h > 250 {
            vec![ratio(h as f64 / 1000.0, (500, 500))]
        } else {
            vec![]
        };
        cases.push(case(
            &format!("coverage/{side}"),
            cap(Layout::default()).rect("met3", 0, 0, 1000, h),
            max,
            vec![],
        ));
    }
    cases.push(case(
        "two_regions",
        cap(Layout::default())
            .rect("met3", 0, 0, 1000, 300)
            .rect("cap", 3000, 0, 4000, 1000)
            .rect("met3", 3000, 0, 4000, 50),
        vec![ratio(0.3, (500, 500))],
        vec![ratio(0.05, (3500, 500))],
    ));
    cases.push(case(
        "outside_not_counted",
        cap(Layout::default()).rect("met3", -500, 0, 1000, 250),
        vec![],
        vec![],
    ));
    cases.push(case(
        "holed_region",
        ring(
            Layout::default(),
            "cap",
            (0, 0, 1000, 1000),
            (250, 250, 750, 750),
        )
        .rect("met3", 250, 250, 750, 750),
        vec![],
        vec![Finding {
            measured: Some(Measurement::Ratio(0.0)),
            at: None,
        }],
    ));
    cases.push(case(
        "no_region",
        Layout::default().rect("met3", 0, 0, 1000, 1000),
        vec![],
        vec![],
    ));
    every_placement(cases)
}

/// `cheesing(met1) <= 1um2` (`cheesing`, DRC-075): one finding per merged
/// figure strictly larger than 1 µm² with no hole, measuring its area.
///
/// Shapes: a plate of 0.999/1/1.001 µm²; a large slotted plate (a ring of
/// bands, clean); the 1.001 µm² plate as two abutting halves each under the
/// limit; a U whose notch is not a slot; a slotted and an unslotted plate side
/// by side; an empty layer.
fn cheesing() -> Vec<Fixture> {
    let deck = new_deck(&["met1", "other"], "rule slot cheesing(met1) <= 1um2\n");
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        fixture(
            &format!("cheesing/{name}"),
            &["DRC-075"],
            &deck,
            layout.rect("other", -1000, -1000, -900, -900),
            &[("slot", findings)],
        )
    };
    let slotted = || {
        ring(
            Layout::default(),
            "met1",
            (0, 0, 2000, 2000),
            (900, 900, 1100, 1100),
        )
    };
    let mut cases = Vec::new();
    for (h, side) in sweep(1000) {
        let area = i128::from(h) * 1000;
        let findings = if area > 1_000_000 {
            areas(&[area])
        } else {
            vec![]
        };
        cases.push(case(
            &format!("plate/{side}"),
            Layout::default().rect("met1", 0, 0, 1000, h),
            findings.clone(),
        ));
        cases.push(case(
            &format!("halves/{side}"),
            Layout::default()
                .rect("met1", 0, 0, 500, h)
                .rect("met1", 500, 0, 1000, h),
            findings,
        ));
    }
    cases.push(case("slotted", slotted(), vec![]));
    let u = [
        (0, 0),
        (2000, 0),
        (2000, 2000),
        (1100, 2000),
        (1100, 1000),
        (900, 1000),
        (900, 2000),
        (0, 2000),
    ];
    cases.push(case(
        "notched_u",
        Layout::default().polygon("met1", &u),
        areas(&[3_800_000]),
    ));
    cases.push(case(
        "slotted_beside_unslotted",
        slotted().rect("met1", 3000, 0, 5000, 2000),
        areas(&[4_000_000]),
    ));
    cases.push(case("empty", Layout::default(), vec![]));
    every_placement(cases)
}

/// Fill rules: fill width and fill-to-drawn spacing (`min_width`,
/// `min_spacing_diff`, DRC-073), and no fill in an exclusion region
/// (`forbidden(fill and nofill)`, DRC-074), each measured as its kind
/// defines.
fn fill() -> Vec<Fixture> {
    let deck_fill = new_deck(
        &["met1", "fill"],
        "rule fill.w width(fill) >= 100nm\nrule fill.s space(fill, met1) >= 200nm\n",
    );
    let deck_nofill = new_deck(
        &["fill", "nofill"],
        "rule dcf.8 forbidden(fill and nofill)\n",
    );
    let metal = || Layout::default().rect("met1", 0, 0, 1000, 1000);
    let mut cases = Vec::new();
    for (g, side) in sweep(200) {
        cases.push(fixture(
            &format!("fill/spacing/{side}"),
            &["DRC-073"],
            &deck_fill,
            metal().rect("fill", 1000 + g, 0, 1500 + g, 500),
            &[("fill.w", vec![]), ("fill.s", below(g, 200))],
        ));
    }
    for (w, side) in sweep(100) {
        cases.push(fixture(
            &format!("fill/width/{side}"),
            &["DRC-073"],
            &deck_fill,
            metal().rect("fill", 2000, 0, 2000 + w, 1000),
            &[("fill.w", below(w, 100)), ("fill.s", vec![])],
        ));
    }
    for (name, nofill, findings) in [
        ("inside_exclusion", (800, 200, 1500, 700), areas(&[100_000])),
        ("touching_exclusion", (1000, 200, 1500, 700), vec![]),
        ("apart", (1100, 200, 1500, 700), vec![]),
    ] {
        cases.push(fixture(
            &format!("fill/nofill/{name}"),
            &["DRC-074", "DRC-050"],
            &deck_nofill,
            rects(
                Layout::default().rect("fill", 0, 0, 1000, 1000),
                "nofill",
                &[nofill],
            ),
            &[("dcf.8", findings)],
        ));
    }
    every_placement(cases)
}

// -------------------------------------------------------- nets, taps, chip

/// `space(met1; nets: same) >= 200nm` and `space(met1; nets: different) >=
/// 300nm` (`net_spacing`, DRC-080): pairs of shapes in different merged
/// figures, on the same net or on different extracted nets, closer than the
/// limit.
///
/// Two met1 bars a swept gap apart: strapped through cuts and met2 into one
/// net (only the same-net rule sees them), or left apart (only the
/// different-net rule); and abutting (one figure, no pair).
fn net_spacing() -> Vec<Fixture> {
    let deck = new_deck(
        &["met1", "cut", "met2"],
        "connect conductors [met1, met2]\n\
         connect touch_within_layer\n\
         connect via cut [met1, met2]\n\
         rule same space(met1; nets: same) >= 200nm\n\
         rule diff space(met1; nets: different) >= 300nm\n",
    );
    let case = |name: &str, layout: Layout, same: Vec<Finding>, diff: Vec<Finding>| {
        fixture(
            &format!("net_spacing/{name}"),
            &["DRC-080"],
            &deck,
            layout,
            &[("same", same), ("diff", diff)],
        )
    };
    let bars = |g: i64| {
        Layout::default()
            .rect("met1", 0, 0, 500, 1000)
            .rect("met1", 500 + g, 0, 1000 + g, 1000)
    };
    let mut cases = Vec::new();
    for (g, side) in sweep(200) {
        cases.push(case(
            &format!("strapped/{side}"),
            bars(g)
                .rect("cut", 200, 450, 300, 550)
                .rect("cut", 700 + g, 450, 800 + g, 550)
                .rect("met2", 100, 400, 900 + g, 600),
            below(g, 200),
            vec![],
        ));
    }
    for (g, side) in sweep(300) {
        cases.push(case(
            &format!("separate/{side}"),
            bars(g).rect("met2", 3000, 0, 3100, 100),
            vec![],
            below(g, 300),
        ));
    }
    cases.push(case(
        "abutting",
        bars(0).rect("met2", 3000, 0, 3100, 100),
        vec![],
        vec![],
    ));
    every_placement(cases)
}

/// `tap_distance(nwell, ntap) <= 1000nm` (`max_distance_to_tap`, ERC-D1): one
/// finding per well row whose furthest point is more than the limit from
/// every tap's edges, measuring that distance rounded up; a well with no tap
/// at all measures 2^40, and an empty well layer is skipped.
///
/// Shapes: a bar whose far end is 999/1000/1001 from the tap; a corner tap
/// with the far corner at Euclidean 999.2/1000/1000.8 (rounded up to 1001);
/// taps at both ends (the middle is furthest); two wells, one too long; no
/// tap; no well. And a well ring, derived as `nwell not hole`, with taps all
/// round it: the rustdoc measures its hole as filled (one finding, 500), and
/// the hole's ring is not a well of its own (F34). And a tap with
/// a real hole (`ntap not hole`) over the whole well, whose centre lies in the
/// hole 1001/1000/999 from its edge (holes count).
fn tap_distance() -> Vec<Fixture> {
    const LIMIT: i64 = 1000;
    let deck_tap = new_deck(
        &["nwell", "ntap"],
        "rule lu tap_distance(nwell, ntap) <= 1000nm\n",
    );
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        fixture(
            &format!("tap_distance/{name}"),
            &["ERC-D1"],
            &deck_tap,
            layout,
            &[("lu", findings)],
        )
    };
    let above = |d: i64| if d > LIMIT { lengths(&[d]) } else { vec![] };
    let mut cases = Vec::new();
    for (d, side) in sweep(LIMIT) {
        cases.push(case(
            &format!("bar/{side}"),
            Layout::default()
                .rect("ntap", 0, 0, 100, 500)
                .rect("nwell", 0, 0, 100 + d, 500),
            above(d),
        ));
    }
    for (dy, side, findings) in [
        (799, "below", vec![]),
        (800, "at", vec![]),
        (801, "above", lengths(&[1001])),
    ] {
        cases.push(case(
            &format!("corner/{side}"),
            Layout::default()
                .rect("ntap", 0, 0, 100, 100)
                .rect("nwell", 0, 0, 700, 100 + dy),
            findings,
        ));
    }
    cases.push(case(
        "both_ends",
        Layout::default()
            .rect("nwell", 0, 0, 3000, 100)
            .rect("ntap", 0, 0, 100, 100)
            .rect("ntap", 2900, 0, 3000, 100),
        lengths(&[1400]),
    ));
    cases.push(case(
        "two_wells",
        Layout::default()
            .rect("nwell", 0, 0, 1500, 100)
            .rect("ntap", 0, 0, 100, 100)
            .rect("nwell", 0, 1000, 1000, 1100)
            .rect("ntap", 0, 1000, 100, 1100),
        lengths(&[1400]),
    ));
    cases.push(case(
        "no_tap",
        Layout::default().rect("nwell", 0, 0, 1000, 100),
        lengths(&[1 << 40]),
    ));
    cases.push(
        Fixture::new("tap_distance/no_well", &["ERC-D1"], &deck_tap, DRC)
            .layout(Layout::default().rect("ntap", 0, 0, 100, 100))
            .expect(Expect::outcome("lu", Want::Skipped)),
    );
    let deck_ring = new_deck(
        &["nwell", "hole", "ntap"],
        "layer ring = nwell not hole\nrule lu tap_distance(ring, ntap) <= 200nm\n",
    );
    cases.push(fixture(
        "tap_distance/ring_well",
        &["ERC-D1"],
        &deck_ring,
        ring(
            Layout::default()
                .rect("nwell", 0, 0, 1000, 1000)
                .rect("hole", 100, 100, 900, 900),
            "ntap",
            (-100, -100, 1100, 1100),
            (0, 0, 1000, 1000),
        ),
        &[("lu", lengths(&[500]))],
    ));
    // A tap with a real hole, `ntap not hole`, over the whole well: the well's
    // centre is in the hole, `1100 - h` from its edge.
    let deck_tap_ring = new_deck(
        &["nwell", "hole", "ntap"],
        "layer tap_ring = ntap not hole\nrule lu tap_distance(nwell, tap_ring) <= 1000nm\n",
    );
    for (h, side) in sweep(100) {
        cases.push(fixture(
            &format!("tap_distance/tap_ring/{side}"),
            &["ERC-D1"],
            &deck_tap_ring,
            Layout::default()
                .rect("nwell", 0, 0, 2200, 2200)
                .rect("ntap", 0, 0, 2200, 2200)
                .rect("hole", h, h, 2200 - h, 2200 - h),
            &[("lu", above(1100 - h))],
        ));
    }
    every_placement(cases)
}

/// A short between two labelled nets (DRC-086): a DRC run reports it as one
/// `lvs.net_seed_conflict` row (testing-plan F14), so the run does not pass,
/// and where it runs as `lvs.short_path`, one row per step between the
/// polygons joining the two labelled shapes. Shorted on one shape (one row,
/// 1 of 1), through two abutting shapes (one step) and through a chain of
/// three (two steps); two labels naming one net and two separate labelled
/// shapes pass.
///
/// Oracle: the steps counted by hand from the drawn chain (`check_layout`'s
/// rustdoc: the fewest polygons joining the two labelled ones).
fn labelled_short() -> Vec<Fixture> {
    let deck = new_deck(
        &["met1", "lbl"],
        "connect conductors [met1]\n\
         connect touch_within_layer\n\
         connect label lbl names met1\n\
         rule w width(met1) >= 100nm\n",
    );
    let refused = |name: &str, layout: Layout, steps: &[u32]| {
        Fixture::new(&format!("labelled_short/{name}"), &["DRC-086"], &deck, DRC)
            .layout(layout)
            .expect(Expect::clean("w"))
            .expect(Expect::rule("lvs.net_seed_conflict", vec![Finding::any()]))
            .expect(Expect::rule(
                "lvs.short_path",
                steps.iter().map(|&k| count(k)).collect(),
            ))
            .expect(Expect::Passes(false))
    };
    let passes = |name: &str, layout: Layout| {
        Fixture::new(&format!("labelled_short/{name}"), &["DRC-086"], &deck, DRC)
            .layout(layout)
            .expect(Expect::clean("w"))
            .expect(Expect::Passes(true))
    };
    let named = |layout: Layout, a: &str, b: &str| {
        layout.label("lbl", 100, 250, a).label("lbl", 1900, 250, b)
    };
    every_placement(vec![
        refused(
            "one_shape",
            named(Layout::default().rect("met1", 0, 0, 2000, 500), "A", "B"),
            &[1],
        ),
        refused(
            "abutting_shapes",
            named(
                Layout::default()
                    .rect("met1", 0, 0, 1000, 500)
                    .rect("met1", 1000, 0, 2000, 500),
                "A",
                "B",
            ),
            &[1],
        ),
        refused(
            "chain_of_three",
            named(
                Layout::default()
                    .rect("met1", 0, 0, 700, 500)
                    .rect("met1", 700, 0, 1300, 500)
                    .rect("met1", 1300, 0, 2000, 500),
                "A",
                "B",
            ),
            &[1, 2],
        ),
        passes(
            "same_name",
            named(Layout::default().rect("met1", 0, 0, 2000, 500), "A", "A"),
        ),
        passes(
            "separate_shapes",
            named(
                Layout::default()
                    .rect("met1", 0, 0, 900, 500)
                    .rect("met1", 1100, 0, 2000, 500),
                "A",
                "B",
            ),
        ),
    ])
}

/// A rule flag (DRC-092: a deck switch, as sky130's deck switches and a
/// Calibre deck's `#IFDEF`): `let strict = true | false`, then `if strict {
/// rule w width(m) >= 200nm }` and `if not strict { rule w width(m) >=
/// 100nm }`, the `not` block nesting a second switch that adds a rule only
/// when both hold. One id, so which block was read shows in its limit.
///
/// Oracle: the switch's documented reading (the block is read when the name
/// is true, its `not` form when false): a bar 199, 200, 201 wide is held to
/// 200 when strict (a finding of 199) and to 100 when not (none); the nested
/// rule runs only with `strict` false and `edges` true.
fn rule_flags() -> Vec<Fixture> {
    let deck = |strict: bool, edges: bool| {
        new_deck(
            &["m"],
            &format!(
                "let strict = {strict}\nlet edges = {edges}\n\
                 if strict {{\n    rule w width(m) >= 200nm\n}}\n\
                 if not strict {{\n    rule w width(m) >= 100nm\n    \
                 if edges {{\n        rule e edge_length(m) >= 10um\n    }}\n}}\n"
            ),
        )
    };
    let mut cases = Vec::new();
    for (w, side) in sweep(200) {
        for (strict, edges) in [(true, true), (false, true), (false, false)] {
            let bar = Layout::default().rect("m", 0, 0, w, 3000);
            let mut fixture = fixture(
                &format!("rule_flags/{strict}_{edges}/{side}"),
                &["DRC-092"],
                &deck(strict, edges),
                bar,
                &[("w", if strict { below(w, 200) } else { Vec::new() })],
            );
            if !strict && edges {
                // Every edge of the bar is under 10 um.
                fixture = fixture.expect(Expect::rule("e", vec![Finding::any(); 4]));
            }
            cases.push(fixture);
        }
    }
    every_placement(cases)
}

/// An exemption region (DRC-092): `width(met1 not areaid) >= 100nm` flags a
/// narrow bar outside the region (swept), not one inside it, the part of a
/// bar left outside a region that covers only half of it, and the 50 nm
/// sliver a region leaves of a wide plate.
fn exemption() -> Vec<Fixture> {
    let deck = new_deck(
        &["met1", "areaid"],
        "layer met1_chk = met1 not areaid\nrule m1.1 width(met1_chk) >= 100nm\n",
    );
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        fixture(
            &format!("exemption/{name}"),
            &["DRC-092", "DRC-120"],
            &deck,
            layout,
            &[("m1.1", findings)],
        )
    };
    let mut cases = Vec::new();
    for (w, side) in sweep(100) {
        cases.push(case(
            &format!("outside/{side}"),
            Layout::default()
                .rect("met1", 0, 0, w, 1000)
                .rect("areaid", 2000, 0, 3000, 1000),
            below(w, 100),
        ));
    }
    cases.push(case(
        "inside",
        Layout::default()
            .rect("met1", 0, 0, 50, 1000)
            .rect("areaid", -500, -500, 500, 1500),
        vec![],
    ));
    cases.push(case(
        "half_inside",
        Layout::default()
            .rect("met1", 0, 0, 50, 2000)
            .rect("areaid", -500, -500, 500, 1000),
        lengths(&[50]),
    ));
    // The exemption cuts a wide plate, and what it leaves is a narrow sliver.
    cases.push(case(
        "leaves_sliver",
        Layout::default()
            .rect("met1", 0, 0, 1000, 1000)
            .rect("areaid", -500, -500, 950, 1500),
        lengths(&[50]),
    ));
    every_placement(cases)
}

/// A hierarchy for the cell-name selections: `TOP` holds a 100 × 50 bar and
/// places `PAD_1` (turned 90°), `core` (mirrored) and `INNER` (turned 180°);
/// `PAD_1` holds a 300 × 100 bar and places `INNER`, a 100 × 100 square;
/// `core` holds a 200 × 200 square. No two placed shapes touch.
fn cell_tree(core: &str) -> Layout {
    let r = |turns: u8, mirror: bool| Symmetry { turns, mirror };
    Layout::default()
        .rect("a", -5000, -5000, -4900, -4950)
        .place("PAD_1", r(1, false), 0, 0)
        .place(core, r(0, true), 0, 5000)
        .place("INNER", r(2, false), 5000, 0)
        .cell(
            "PAD_1",
            Layout::default()
                .rect("a", 0, 0, 300, 100)
                .place("INNER", Symmetry::IDENTITY, 1000, 0),
        )
        .cell(core, Layout::default().rect("a", 0, 0, 200, 200))
        .cell("INNER", Layout::default().rect("a", 0, 0, 100, 100))
}

/// Cell-name selections (DRC-092): `in_cells` keeps the shapes placed under
/// a matching cell, nested ones included (`INNER` under `PAD_1`), and
/// `not_in_cells` the rest (`INNER` placed by `TOP`); several patterns are
/// a union, the root's own name counts, and the glob is case-sensitive.
/// Then the rules the selections state: a width exempted inside `PAD*`
/// cells, swept, and sky130 x.25's "pnp.dg must be only within cell name
/// `s8rf_pnp`, `s8rf_pnp5x`, `s8tesd_iref_pnp`, `stk14ecx_*`" (DRC-097), where a
/// longer name does not match a whole-name pattern; and a maximum cell-name
/// length (DRC-097, Calibre's DRC MAXIMUM CELL NAME LENGTH) as
/// `forbidden(a.in_cells("?????*"))`. Every case is placed
/// under all eight symmetries, which turn each placement with the design.
fn cell_selections() -> Vec<Fixture> {
    let mut cases = vec![derived(
        "derived/in_cells/tree",
        &["DRC-092", "DRC-120"],
        &["a"],
        &[
            ("a.in_cells(\"PAD_*\")", areas(&[30_000, 10_000])),
            ("a.not_in_cells(\"PAD_*\")", areas(&[5_000, 40_000, 10_000])),
            (
                "a.in_cells(\"core\", \"T?P\")",
                areas(&[5_000, 30_000, 10_000, 40_000, 10_000]),
            ),
            ("a.in_cells(\"pad_*\")", vec![]),
        ],
        cell_tree("core"),
    )];

    let deck = new_deck(
        &["met1"],
        "rule m1.w width(met1.not_in_cells(\"PAD*\")) >= 100nm\n\
         rule m1.wa width(met1.in_cells(\"PAD*\")) >= 40nm\n",
    );
    for (w, side) in sweep(100) {
        let bar = |layout: Layout| layout.rect("met1", 0, 0, w, 1000);
        cases.push(fixture(
            &format!("cell_exemption/top/{side}"),
            &["DRC-092"],
            &deck,
            bar(Layout::default()),
            &[("m1.w", below(w, 100)), ("m1.wa", vec![])],
        ));
        cases.push(fixture(
            &format!("cell_exemption/in_pad/{side}"),
            &["DRC-092"],
            &deck,
            Layout::default()
                .place("PADX", Symmetry::IDENTITY, 0, 0)
                .cell("PADX", bar(Layout::default())),
            &[("m1.w", vec![]), ("m1.wa", vec![])],
        ));
    }
    for (w, side) in sweep(40) {
        cases.push(fixture(
            &format!("cell_exemption/in_pad_narrow/{side}"),
            &["DRC-092"],
            &deck,
            Layout::default()
                .place("PAD", Symmetry::IDENTITY, 0, 0)
                .cell("PAD", Layout::default().rect("met1", 0, 0, w, 1000)),
            &[("m1.w", vec![]), ("m1.wa", below(w, 40))],
        ));
    }

    let x25 = new_deck(
        &["pnp"],
        "rule x.25 forbidden(pnp.not_in_cells(\"s8rf_pnp\", \"s8rf_pnp5x\", \"s8tesd_iref_pnp\", \"stk14ecx_*\"))\n",
    );
    let square = || Layout::default().rect("pnp", 0, 0, 100, 100);
    let r0 = Symmetry::IDENTITY;
    cases.push(fixture(
        "cell_exemption/x25",
        &["DRC-097", "DRC-092"],
        &x25,
        Layout::default()
            .rect("pnp", -1000, -1000, -900, -800)
            .place("s8rf_pnp", r0, 0, 0)
            .place("stk14ecx_12", r0, 1000, 0)
            .place("wrapper", r0, 2000, 0)
            .place("s8rf_pnp_big", r0, 3000, 0)
            .place("my_pnp", r0, 4000, 0)
            .cell("s8rf_pnp", square())
            .cell("stk14ecx_12", square())
            .cell(
                "wrapper",
                Layout::default().place("s8tesd_iref_pnp", r0, 0, 0),
            )
            .cell("s8tesd_iref_pnp", square())
            .cell("s8rf_pnp_big", square())
            .cell("my_pnp", Layout::default().rect("pnp", 0, 0, 200, 100)),
        &[("x.25", areas(&[20_000, 10_000, 20_000]))],
    ));
    // A maximum cell-name length of 4 (Calibre's DRC MAXIMUM CELL NAME
    // LENGTH, as a forbidden selection): five `?` and a `*` match a name of
    // five or more characters. A short cell under a long one is flagged with
    // it; `TOP` and `ABCD` are not.
    let length = new_deck(&["a"], "rule name.max forbidden(a.in_cells(\"?????*\"))\n");
    cases.push(fixture(
        "cell_exemption/name_length",
        &["DRC-097"],
        &length,
        Layout::default()
            .rect("a", -1000, 0, -900, 100)
            .place("ABCD", r0, 0, 0)
            .place("ABCDE", r0, 1000, 0)
            .place("LONGNAME", r0, 2000, 0)
            .cell("ABCD", Layout::default().rect("a", 0, 0, 100, 100))
            .cell("ABCDE", Layout::default().rect("a", 0, 0, 200, 100))
            .cell("LONGNAME", Layout::default().place("AB", r0, 0, 0))
            .cell("AB", Layout::default().rect("a", 0, 0, 300, 100)),
        &[("name.max", areas(&[20_000, 30_000]))],
    ));
    every_placement(cases)
}

/// The harness writes a placement as GDS `STRANS` and quarter turns
/// (`Symmetry::gds`); the reader must land an off-centre rectangle where the
/// harness's own symmetry puts its corners.
///
/// Oracle: round trip through the GDS writer (`write_library`) and reader,
/// against `Symmetry::apply` on the corners, the map every flat fixture is
/// transformed by.
#[test]
fn a_placed_cell_lands_where_its_symmetry_maps_it() {
    for symmetry in Symmetry::ALL {
        let fixture = Fixture::new("placement", &["DRC-092"], &new_deck(&["a"], ""), DRC).layout(
            Layout::default()
                .place("C", symmetry, 7, 11)
                .cell("C", Layout::default().rect("a", 100, 200, 400, 300)),
        );
        let ran = crate::harness::run(&fixture).expect("runs");
        let store = &ran.loaded.store;
        let layer = ran
            .loaded
            .deck
            .layers
            .id(&ran.loaded.strings, "a")
            .expect("declared");
        let rows: Vec<_> = store.polys_on_layer(layer).collect();
        assert_eq!(rows.len(), 1, "{}", symmetry.name());
        let b = store.poly_bbox(gpurify::geom::PolyId(rows[0]));
        let corners = [(100, 200), (400, 300)].map(|p| symmetry.apply(p));
        let want = (
            corners[0].0.min(corners[1].0) + 7,
            corners[0].1.min(corners[1].1) + 11,
            corners[0].0.max(corners[1].0) + 7,
            corners[0].1.max(corners[1].1) + 11,
        );
        assert_eq!(
            (b.xlo.raw(), b.ylo.raw(), b.xhi.raw(), b.yhi.raw()),
            want,
            "{}",
            symmetry.name()
        );
    }
}

/// Renaming a cell the patterns do not match changes no finding, and
/// renaming it into a pattern moves its shape from `not_in_cells` to
/// `in_cells` and nothing else (DRC-092).
///
/// Oracle: metamorphic: a cell's name is read only by the selections; the
/// predicted report is the original one with `core`'s finding (the only
/// 200 × 200 square) moved from rule `f1` to rule `f0`.
#[test]
fn renaming_a_cell_changes_only_what_its_name_selects() {
    let deck = new_deck(
        &["a"],
        "layer d0 = a.in_cells(\"PAD_*\")\nrule f0 forbidden(d0)\n\
         layer d1 = a.not_in_cells(\"PAD_*\")\nrule f1 forbidden(d1)\n",
    );
    let findings = |core: &str| {
        let fixture = Fixture::new("rename", &["DRC-092"], &deck, DRC).layout(cell_tree(core));
        let mut out: Vec<String> = crate::harness::run(&fixture)
            .expect("runs")
            .findings
            .into_iter()
            .map(|(rule, measured, at)| format!("{rule} {measured:?} {at:?}"))
            .collect();
        out.sort();
        out
    };
    let before = findings("core");
    assert_eq!(findings("other_core"), before);
    let core = Measurement::Area(gpurify::geom::DbuArea::new(40_000));
    let mut predicted: Vec<String> = before
        .iter()
        .map(|line| {
            if line.starts_with(&format!("f1 {core:?} ")) {
                line.replacen("f1", "f0", 1)
            } else {
                line.clone()
            }
        })
        .collect();
    predicted.sort();
    assert_ne!(
        predicted, before,
        "core's finding is in f1 before the rename"
    );
    assert_eq!(findings("PAD_core"), predicted);
}

/// Chip and device geometry the deck expresses with the generic kinds: a pad
/// opening enclosed by top metal (`enclosure(pad, met5) >= 1um`, DRC-096), a
/// seal ring's width (`width(seal) >= 1um` on a ring of bands, DRC-095), and
/// a resistor body enclosed by its marker (`enclosure(poly, rpm) >= 200nm`,
/// DRC-090), each swept one step either side.
fn chip_and_device() -> Vec<Fixture> {
    let deck_pad = new_deck(&["pad", "met5"], "rule pad.2 enclosure(pad, met5) >= 1um\n");
    let deck_seal = new_deck(&["seal"], "rule seal.w width(seal) >= 1um\n");
    let deck_res = new_deck(
        &["poly", "rpm"],
        "rule rpm.1c enclosure(poly, rpm) >= 200nm\n",
    );
    let mut cases = Vec::new();
    for (m, side) in sweep(1000) {
        cases.push(fixture(
            &format!("pad_enclosure/{side}"),
            &["DRC-096", "DRC-040"],
            &deck_pad,
            Layout::default().rect("pad", 0, 0, 10_000, 10_000).rect(
                "met5",
                -m,
                -3000,
                10_000 + 3000,
                13_000,
            ),
            &[("pad.2", below(m, 1000))],
        ));
        cases.push(fixture(
            &format!("seal_ring/{side}"),
            &["DRC-095"],
            &deck_seal,
            rects(
                Layout::default(),
                "seal",
                &[
                    (-1200, -1200, 20_000, 0),
                    (-1200, 20_000, 20_000, 21_200),
                    (-1200, 0, 0, 20_000),
                    (20_000, -1200, 20_000 + m, 21_200),
                ],
            ),
            &[("seal.w", below(m, 1000))],
        ));
    }
    for (m, side) in sweep(200) {
        cases.push(fixture(
            &format!("resistor_marker/{side}"),
            &["DRC-090", "DRC-040"],
            &deck_res,
            Layout::default()
                .rect("poly", 0, 0, 330, 2000)
                .rect("rpm", -m, -1000, 330 + m, 3000),
            &[("rpm.1c", below(m, 200))],
        ));
    }
    every_placement(cases)
}

/// The device-family rules DRC-090 listed as missing, written with the
/// generic kinds (SkyWater SKY130 periphery rules, varac and rpm sections):
///
/// - varac.2 "Min channel width (tap width) of `Var_channel`" 1.0 µm, the
///   channel's extent along the poly, between its edges on the tap's edge:
///   `width(var_channel.edges() and tap.edges()) >= 1um`, as difftap.2 is
///   written for a MOS channel (DRC-011). `RTimothyEdwards/open_pdks`
///   `sky130.lydrc` measures the same subject, the varactor channel's edges
///   that are tap edges;
/// - varac.6 "Min spacing between `VaracTap` and difftap" 0.27 µm, the tap
///   holding a channel against every other diffusion or tap figure:
///   `space(var_tap, difftap.not_interacting(var_tap)) >= 270nm`, so a
///   diffusion butted to the varactor tap (one figure with it) is not
///   measured, as `sky130.lydrc` drops its zero-area edge pairs;
/// - rpm.1g "Only 1 licon is allowed in `xhrpoly_0p35`
///   `prec_resistor_terminal`" and rpm.1i "Only 2 licons ... `xhrpoly_1p41`":
///   `contains(term, licon) <= n` on each terminal, the resistor's poly under
///   its marker off the body (`poly_rs`). The manual does not define
///   `prec_resistor_terminal`; this derivation is the fixture's, not a
///   foundry deck's, and no public deck writes rpm.1g-1k.
///
/// Oracle: construct-from-answer at the manual's numbers: a 180-wide poly
/// crossing a tap `W` tall (`W` = 999, 1000, 1001: one finding of `W` below
/// 1000; `width(var_channel)` would read the 180 channel length); a diffusion
/// 269, 270 or 271 from the varactor tap, and one butted to it; terminals
/// holding 1 and 2 licons, each terminal counted alone.
fn device_family() -> Vec<Fixture> {
    let deck_var = new_deck(
        &["poly", "tap", "nwell", "diff"],
        "layer var_channel = (poly and tap) and nwell\n\
         layer var_tap = tap.overlapping(var_channel)\n\
         layer difftap = diff or tap\n\
         rule varac.2 width(var_channel.edges() and tap.edges()) >= 1um\n\
         rule varac.6 space(var_tap, difftap.not_interacting(var_tap)) >= 270nm\n",
    );
    // A varactor: poly 180 wide crossing a tap `w` tall, all in n-well.
    let varactor = |w: i64| {
        Layout::default()
            .rect("nwell", -2000, -2000, 2180, w + 2000)
            .rect("tap", -600, 0, 780, w)
            .rect("poly", 0, -300, 180, w + 300)
    };
    let mut cases = Vec::new();
    for (w, side) in sweep(1000) {
        cases.push(fixture(
            &format!("device_family/varac_width/{side}"),
            &["DRC-090", "DRC-011"],
            &deck_var,
            varactor(w),
            &[("varac.2", below(w, 1000)), ("varac.6", Vec::new())],
        ));
    }
    for (gap, side) in sweep(270) {
        cases.push(fixture(
            &format!("device_family/varac_tap_space/{side}"),
            &["DRC-090"],
            &deck_var,
            varactor(1000).rect("diff", 780 + gap, 0, 1780 + gap, 1000),
            &[("varac.2", Vec::new()), ("varac.6", below(gap, 270))],
        ));
    }
    cases.push(fixture(
        "device_family/varac_tap_butted",
        &["DRC-090"],
        &deck_var,
        varactor(1000).rect("diff", 780, 0, 1780, 1000),
        &[("varac.2", Vec::new()), ("varac.6", Vec::new())],
    ));

    let deck_rpm = new_deck(
        &["poly", "rpm", "poly_rs", "licon"],
        "layer term = (poly and rpm) not poly_rs\n\
         rule rpm.1g contains(term, licon) <= 1\n\
         rule rpm.1i contains(term, licon) <= 2\n",
    );
    // A resistor along y: two terminals either side of its body, each
    // holding `low` and `high` licons, 100 square and 100 apart.
    let resistor = |low: i64, high: i64| {
        let licons = |layout: Layout, n: i64, y: i64| {
            (0..n).fold(layout, |layout, i| {
                layout.rect("licon", 50 + 200 * i, y, 150 + 200 * i, y + 100)
            })
        };
        let layout = Layout::default()
            .rect("rpm", -500, -500, 1100, 5500)
            .rect("poly", 0, 0, 600, 5000)
            .rect("poly_rs", -100, 1000, 700, 4000);
        licons(licons(layout, low, 400), high, 4500)
    };
    for (low, high) in [(1, 1), (1, 2), (2, 3), (0, 1)] {
        let over = |n: i64| -> Vec<Finding> {
            [low, high]
                .into_iter()
                .filter(|&held| held > n)
                .map(|held| count(u32::try_from(held).expect("a small count")))
                .collect()
        };
        cases.push(fixture(
            &format!("device_family/rpm_terminal/{low}_{high}"),
            &["DRC-090", "DRC-049"],
            &deck_rpm,
            resistor(low, high),
            &[("rpm.1g", over(1)), ("rpm.1i", over(2))],
        ));
    }
    every_placement(cases)
}

/// sky130 x.19 "Lower left corner of the seal ring should be at origin i.e
/// (0,0)" (`origin(seal)`, DRC-095, DRC-097): a 4000 square seal ring with a
/// 100 wall, drawn from `(dx, dy)` with a met1 square inside, under each of
/// the eight symmetries about the origin. The rule is anchored on the origin,
/// so a turn or mirror moves the corner it reads, and each placement's
/// expectation is computed, not mapped.
///
/// Oracle: the image of the ring's box under the symmetry: its lower-left
/// corner, and that corner's distance from the origin (3, 4 is 5), one
/// finding there unless it is `(0, 0)`: only the unturned ring drawn from
/// the origin passes, so a rule reading the box's first vertex, or any
/// other corner, breaks a turned case.
fn seal_origin() -> Vec<Fixture> {
    let deck = new_deck(&["seal", "met1"], "rule x.19 origin(seal)\n");
    let root = |d2: i64| (0..=d2).take_while(|r| r * r <= d2).last().unwrap_or(0);
    let mut out = Vec::new();
    for (dx, dy) in [(0, 0), (1, 0), (0, -1), (3, 4)] {
        let drawn = ring(
            Layout::default().rect("met1", dx + 500, dy + 500, dx + 600, dy + 600),
            "seal",
            (dx, dy, dx + 4000, dy + 4000),
            (dx + 100, dy + 100, dx + 3900, dy + 3900),
        );
        for symmetry in Symmetry::ALL {
            let corners = [
                (dx, dy),
                (dx + 4000, dy),
                (dx, dy + 4000),
                (dx + 4000, dy + 4000),
            ]
            .map(|p| symmetry.apply(p));
            let x = corners.iter().map(|c| c.0).min().expect("four corners");
            let y = corners.iter().map(|c| c.1).min().expect("four corners");
            let found = if (x, y) == (0, 0) {
                Vec::new()
            } else {
                vec![Finding::length(root(x * x + y * y)).at(x, y)]
            };
            out.push(fixture(
                &format!("origin/{dx}_{dy}/{}", symmetry.name()),
                &["DRC-095", "DRC-097"],
                &deck,
                drawn.transformed(symmetry, 0, 0),
                &[("x.19", found)],
            ));
        }
    }
    out
}

/// A count per chip (`count`, DRC-091: IHP npn13G2.bR's devices per chip) and
/// one seal ring per chip (DRC-095): `count(a) <= 2` and `count(a) >= 2` on
/// one, two and three shapes, each finding at the die's centre measuring the
/// count; the die is a frame on another layer, `[0, 4000]²`.
///
/// Oracle: counts fixed by construction, at the limit and one either side:
/// three drawn boxes two of which abut, or meet only at a corner, are two
/// shapes (a check counting drawn rows reads three), and an empty layer on a
/// drawn die counts zero. A seal ring drawn as four abutting bands is one
/// ring; a second ring is two.
fn chip_count() -> Vec<Fixture> {
    let deck = new_deck(
        &["a", "frame"],
        "rule cmax count(a) <= 2\nrule cmin count(a) >= 2\n",
    );
    let at = |n: u32| count(n).at(2000, 2000);
    let case = |name: &str, boxes: &[Rect], max: Vec<Finding>, min: Vec<Finding>| {
        fixture(
            &format!("count/{name}"),
            &["DRC-091"],
            &deck,
            rects(
                Layout::default().rect("frame", 0, 0, 4000, 4000),
                "a",
                boxes,
            ),
            &[("cmax", max), ("cmin", min)],
        )
    };
    let (p, q, r) = (
        (100, 100, 300, 300),
        (500, 100, 700, 300),
        (900, 100, 1100, 300),
    );
    let mut cases = vec![
        case("none", &[], vec![], vec![at(0)]),
        case("one", &[p], vec![], vec![at(1)]),
        case("two", &[p, q], vec![], vec![]),
        case("three", &[p, q, r], vec![at(3)], vec![]),
        case(
            "three_drawn_two_abut",
            &[p, q, (700, 100, 900, 300)],
            vec![],
            vec![],
        ),
        case(
            "three_drawn_two_at_a_corner",
            &[p, q, (700, 300, 900, 500)],
            vec![],
            vec![],
        ),
    ];
    let seal_deck = new_deck(
        &["seal", "frame"],
        "rule seal.one count(seal) <= 1\nrule seal.any count(seal) >= 1\n",
    );
    let seal = |layout: Layout, max: Vec<Finding>, min: Vec<Finding>, name: &str| {
        fixture(
            &format!("count/seal_ring/{name}"),
            &["DRC-095", "DRC-091"],
            &seal_deck,
            layout.rect("frame", 0, 0, 4000, 4000),
            &[("seal.one", max), ("seal.any", min)],
        )
    };
    let ring_at = |layout, lo: i64, hi: i64| {
        ring(
            layout,
            "seal",
            (lo, lo, hi, hi),
            (lo + 100, lo + 100, hi - 100, hi - 100),
        )
    };
    cases.push(seal(
        ring_at(Layout::default(), 0, 4000),
        vec![],
        vec![],
        "one",
    ));
    cases.push(seal(
        ring_at(ring_at(Layout::default(), 0, 4000), 1000, 3000),
        vec![at(2)],
        vec![],
        "two",
    ));
    cases.push(seal(Layout::default(), vec![], vec![at(0)], "none"));
    // Nothing outside the seal ring: the ring with its hole filled is the
    // chip, and what lies off it is forbidden, reported with its area.
    cases.push(fixture(
        "count/seal_ring/outside",
        &["DRC-095"],
        &new_deck(
            &["seal", "met1"],
            "layer chip = seal or seal.holes()\nrule seal.out forbidden(met1 not chip)\n",
        ),
        rects(
            ring_at(Layout::default(), 0, 4000),
            "met1",
            &[
                (500, 500, 1000, 1000),
                (5000, 0, 5100, 100),
                (3950, 100, 4100, 200),
            ],
        ),
        &[("seal.out", areas(&[10_000, 10_000]))],
    ));
    every_placement(cases)
}

/// Frame and die rules the generic kinds express (DRC-097): sky130 x.23a
/// "areaid.sl must not overlap diff" as `forbidden(sl and diff)`, x.23b "diff
/// cannot straddle areaid.sl" as `forbidden((diff and sl).interacting(diff
/// not sl))`, and IHP LBE.h "no LBE ring allowed" as `forbidden(lbe.holes())`,
/// each finding reporting its shape's area.
///
/// Oracle: areas fixed by construction: a diffusion apart from the scribe
/// marker (nothing), inside it (an overlap, no straddle), across its edge
/// (both, on the 100 x 200 part inside); an LBE ring (its 400 square hole)
/// and a solid LBE plate (nothing).
fn frame() -> Vec<Fixture> {
    let deck = new_deck(
        &["diff", "sl", "lbe"],
        "rule x.23a forbidden(sl and diff)\n\
         rule x.23b forbidden((diff and sl).interacting(diff not sl))\n\
         rule LBE.h forbidden(lbe.holes())\n",
    );
    let case = |name: &str, layout: Layout, rows: [Vec<Finding>; 3]| {
        let [a, b, h] = rows;
        fixture(
            &format!("frame/{name}"),
            &["DRC-097"],
            &deck,
            layout.rect("sl", 0, 0, 1000, 1000),
            &[("x.23a", a), ("x.23b", b), ("LBE.h", h)],
        )
    };
    every_placement(vec![
        case(
            "diff_apart",
            Layout::default().rect("diff", 2000, 0, 2500, 500),
            [vec![], vec![], vec![]],
        ),
        case(
            "diff_inside",
            Layout::default().rect("diff", 100, 100, 300, 300),
            [areas(&[40_000]), vec![], vec![]],
        ),
        case(
            "diff_across",
            Layout::default().rect("diff", 900, 100, 1100, 300),
            [areas(&[20_000]), areas(&[20_000]), vec![]],
        ),
        case(
            "lbe_ring",
            ring(
                Layout::default(),
                "lbe",
                (3000, 0, 4000, 1000),
                (3300, 300, 3700, 700),
            ),
            [vec![], vec![], areas(&[160_000])],
        ),
        case(
            "lbe_plate",
            Layout::default().rect("lbe", 3000, 0, 4000, 1000),
            [vec![], vec![], vec![]],
        ),
    ])
}

/// A total area per chip (`total_area`, DRC-091: IHP MIM.gR's total MIM
/// area): `total_area(a) <= 30000nm2`, one finding at the die's centre
/// measuring the area; the die is a frame on another layer, `[0, 4000]²`.
///
/// Oracle: areas fixed by construction at the limit and one 100 nm² step
/// either side; the area summed over separate shapes; two overlapping shapes
/// counted once (summing drawn rows reads 40100 for the 30100 they cover); a
/// ring of 30200 whose filled box is 40200; an empty layer.
fn chip_area() -> Vec<Fixture> {
    let deck = new_deck(&["a", "frame"], "rule ta total_area(a) <= 30000nm2\n");
    let at = |area: i128| Finding::area(area).at(2000, 2000);
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        fixture(
            &format!("total_area/{name}"),
            &["DRC-091"],
            &deck,
            layout.rect("frame", 0, 0, 4000, 4000),
            &[("ta", findings)],
        )
    };
    let a = |boxes: &[Rect]| rects(Layout::default(), "a", boxes);
    let mut cases = Vec::new();
    for (h, side) in sweep(300) {
        let area = i128::from(100 * h);
        let findings = if area > 30_000 {
            vec![at(area)]
        } else {
            vec![]
        };
        cases.push(case(
            &format!("bar/{side}"),
            a(&[(100, 100, 200, 100 + h)]),
            findings,
        ));
    }
    cases.push(case(
        "summed_over_shapes",
        a(&[(100, 100, 200, 250), (500, 100, 600, 251)]),
        vec![at(30_100)],
    ));
    cases.push(case(
        "overlap_counted_once",
        a(&[(100, 100, 200, 300), (100, 200, 200, 401)]),
        vec![at(30_100)],
    ));
    cases.push(case(
        "ring",
        ring(
            Layout::default(),
            "a",
            (100, 100, 300, 301),
            (150, 150, 250, 250),
        ),
        vec![at(30_200)],
    ));
    cases.push(case("empty", Layout::default(), vec![]));
    every_placement(cases)
}

/// Floating interconnect (DRC-084, `unconnected_pin(met1)`, an ERC kind): a
/// met1 shape whose net reaches no device terminal is flagged, one wired
/// through a contact to a transistor's source is not, and one touching that
/// wired shape shares its net.
fn dangling_metal() -> Vec<Fixture> {
    let deck = new_deck(
        &["diff", "poly", "cont", "met1"],
        "layer gate = poly and diff\n\
         layer sd = diff not poly\n\
         connect conductors [sd, poly, met1]\n\
         connect touch_within_layer\n\
         connect via cont [sd, met1]\n\
         device mos gate model \"n\" terminals [poly, sd, sd]\n\
         rule x.22 unconnected_pin(met1)\n",
    );
    let transistor = || {
        Layout::default()
            .rect("diff", 0, 0, 1000, 400)
            .rect("poly", 450, -200, 550, 600)
            .rect("cont", 100, 150, 200, 250)
            .rect("met1", 50, 100, 250, 300)
    };
    let erc = gpurify::engine::run::Checks {
        erc: true,
        ..crate::harness::NONE
    };
    let case = |name: &str, layout: Layout, findings: Vec<Finding>| {
        Fixture::new(&format!("dangling_metal/{name}"), &["DRC-084"], &deck, erc)
            .layout(layout)
            .expect(Expect::rule("x.22", findings))
    };
    every_placement(vec![
        case("wired", transistor(), vec![]),
        case(
            "wired_through_touch",
            transistor().rect("met1", 250, 100, 1500, 300),
            vec![],
        ),
        case(
            "floating",
            transistor().rect("met1", 2000, 0, 2200, 200),
            vec![Finding::any()],
        ),
    ])
}

/// A DRC rule written `warning` (DRC-110): a foundry's recommended rule.
/// deck.md, "Rules": its findings are reported as the same rule unmarked would
/// report them, but do not fail the run.
///
/// The rule is IHP SG13G2 TM2.bR as `pdks/ihp_sg13g2.deck` transcribes it (a
/// spacing table: 5 um between `TopMetal2` lines wider than 5 um running in
/// parallel for more than 50 um), beside the required TM2.b (2 um), on two
/// 6 um x 60 um bars swept about the recommended 5 um. Below it, the warning
/// rule reports the gap and the run still passes; at and above it, nothing.
/// The same layout under the unmarked rule fails the run below the limit.
fn drc_warning() -> Vec<Fixture> {
    const TM2_BR: &str = "space_table(topmetal2; prl: [0um, 50um], width: [0um, 5um], \
                          space: [[2um, 2um], [2um, 5um]])";
    let bars = |g: i64| {
        Layout::default()
            .rect("topmetal2", 0, 0, 6000, 60_000)
            .rect("topmetal2", 6000 + g, 0, 12_000 + g, 60_000)
    };
    let mut cases = Vec::new();
    for (g, side) in sweep(5000) {
        let flagged = g < 5000;
        cases.push(
            Fixture::new(
                &format!("drc_warning/tm2_br/{side}"),
                &["DRC-110"],
                &new_deck(
                    &["topmetal2"],
                    &format!("rule TM2.b space(topmetal2) >= 2um\nrule TM2.bR warning {TM2_BR}\n"),
                ),
                DRC,
            )
            .layout(bars(g))
            .expect(Expect::clean("TM2.b"))
            .expect(Expect::rule("TM2.bR", below(g, 5000)))
            .expect(Expect::Passes(true)),
        );
        cases.push(
            Fixture::new(
                &format!("drc_warning/unmarked/{side}"),
                &["DRC-110"],
                &new_deck(&["topmetal2"], &format!("rule TM2.bR {TM2_BR}\n")),
                DRC,
            )
            .layout(bars(g))
            .expect(Expect::rule("TM2.bR", below(g, 5000)))
            .expect(Expect::Passes(!flagged)),
        );
    }
    every_placement(cases)
}

// --------------------------------------------------------- multi-patterning

/// A cycle of `n >= 4` bars around a 4000 nm square frame, each `gap` from the
/// next and far from every other: the bottom side split into `ceil((n - 2) /
/// 2)` bars, the top into the rest, and one bar up each side.
fn bar_cycle(n: i64, gap: i64) -> Layout {
    const S: i64 = 4000;
    const T: i64 = 100;
    let bottom = (n - 1) / 2;
    let top = n - 2 - bottom;
    let pieces = |to: i64, k: i64| -> Vec<(i64, i64)> {
        let len = (to - (k - 1) * gap) / k;
        (0..k)
            .map(|i| {
                let lo = i * (len + gap);
                (lo, if i == k - 1 { to } else { lo + len })
            })
            .collect()
    };
    let mut layout = Layout::default().rect("met1", S - T, T + gap, S, S).rect(
        "met1",
        0,
        T + gap,
        T,
        S - T - gap,
    );
    for (lo, hi) in pieces(S, bottom) {
        layout = layout.rect("met1", lo, 0, hi, T);
    }
    for (lo, hi) in pieces(S - T - gap, top) {
        layout = layout.rect("met1", lo, S - T, hi, S);
    }
    layout
}

/// `patterning(met1; colors: k) >= 100nm` for k of 1, 2 and 3
/// (`multi_patterning`, DRC-100, DRC-101): figures closer than 100 nm
/// conflict, and a layer whose conflict graph needs more than k masks is one
/// finding counting k + 1; an empty layer is skipped.
///
/// Each layout's chromatic number is known by construction: a triangle of
/// mutual gaps 99/100/101 (3, or 1 when no gap conflicts); a pair at 99/100/
/// 101 (2 or 1); cycles of 4 to 7 bars (2 when even, 3 when odd); a 2 x 2
/// block at 50 nm whose diagonals are 70.7 apart (K4, 4); a triangle whose two
/// lower shapes abut, merging into one figure (2); two squares touching only
/// at a corner (one figure, 1); a shape drawn inside another, 50 nm from its
/// boundary (one figure, 1), and that pair beside a third (2); an island
/// 50 nm inside a ring's hole (a real gap, 2); one shape (1); none. A figure
/// whose own notch is below 100 nm conflicts with itself (Calibre's
/// self-conflict) and no palette colours it: a U whose arms are 99/100/101
/// apart, and a ring whose slot hole is (one figure, 1, at 100 and above).
/// Nightly: cycles of 4 to 15 bars.
fn multi_patterning(depth: Depth) -> Vec<Fixture> {
    let deck = new_deck(
        &["met1", "other"],
        "rule mp1 patterning(met1; colors: 1) >= 100nm\n\
         rule mp2 patterning(met1; colors: 2) >= 100nm\n\
         rule mp3 patterning(met1; colors: 3) >= 100nm\n",
    );
    let case = |name: &str, layout: Layout, chromatic: u32| {
        let rows: Vec<(&str, Vec<Finding>)> = [("mp1", 1), ("mp2", 2), ("mp3", 3)]
            .into_iter()
            .map(|(id, k)| {
                (
                    id,
                    if chromatic > k {
                        vec![count(k + 1)]
                    } else {
                        vec![]
                    },
                )
            })
            .collect();
        fixture(
            &format!("multi_patterning/{name}"),
            &["DRC-100", "DRC-101"],
            &deck,
            layout,
            &rows,
        )
    };
    let triangle = |g: i64| {
        Layout::default()
            .rect("met1", 0, 0, 500, 500)
            .rect("met1", 500 + g, 0, 1000 + g, 500)
            .rect("met1", 0, 500 + g, 1000 + g, 1000 + g)
    };
    let mut cases = Vec::new();
    for (g, side) in sweep(100) {
        let conflicts = g < 100;
        cases.push(case(
            &format!("triangle/{side}"),
            triangle(g),
            if conflicts { 3 } else { 1 },
        ));
        let notched = if conflicts { u32::MAX } else { 1 };
        cases.push(case(
            &format!("u_notch/{side}"),
            Layout::default().polygon(
                "met1",
                &[
                    (0, 0),
                    (1000 + g, 0),
                    (1000 + g, 2000),
                    (500 + g, 2000),
                    (500 + g, 500),
                    (500, 500),
                    (500, 2000),
                    (0, 2000),
                ],
            ),
            notched,
        ));
        cases.push(case(
            &format!("slot_hole/{side}"),
            ring(
                Layout::default(),
                "met1",
                (0, 0, 2000, 2000),
                (900, 500, 900 + g, 1500),
            ),
            notched,
        ));
        cases.push(case(
            &format!("pair/{side}"),
            Layout::default()
                .rect("met1", 0, 0, 500, 500)
                .rect("met1", 500 + g, 0, 1000 + g, 500),
            if conflicts { 2 } else { 1 },
        ));
    }
    let longest = if depth == Depth::Nightly { 15 } else { 7 };
    for n in 4..=longest {
        cases.push(case(
            &format!("cycle/{n}"),
            bar_cycle(n, 50),
            if n % 2 == 0 { 2 } else { 3 },
        ));
    }
    cases.push(case(
        "k4",
        rects(
            Layout::default(),
            "met1",
            &[
                (0, 0, 500, 500),
                (550, 0, 1050, 500),
                (0, 550, 500, 1050),
                (550, 550, 1050, 1050),
            ],
        ),
        4,
    ));
    cases.push(case(
        "merged_triangle",
        Layout::default()
            .rect("met1", 0, 0, 500, 500)
            .rect("met1", 500, 0, 1000, 500)
            .rect("met1", 0, 550, 1000, 1050),
        2,
    ));
    cases.push(case(
        "single",
        Layout::default().rect("met1", 0, 0, 500, 500),
        1,
    ));
    // An island 50 nm inside a ring's hole is a real gap; a shape drawn
    // inside another's material, its boundary 50 nm from the other's, is one
    // figure with it.
    cases.push(case(
        "island_in_hole",
        ring(
            Layout::default().rect("met1", 550, 550, 1450, 1450),
            "met1",
            (0, 0, 2000, 2000),
            (500, 500, 1500, 1500),
        ),
        2,
    ));
    let drawn_inside = || {
        Layout::default()
            .rect("met1", 0, 0, 2000, 2000)
            .rect("met1", 50, 50, 1950, 1950)
    };
    cases.push(case("drawn_inside", drawn_inside(), 1));
    cases.push(case(
        "corner_touch",
        Layout::default()
            .rect("met1", 0, 0, 500, 500)
            .rect("met1", 500, 500, 1000, 1000),
        1,
    ));
    cases.push(case(
        "drawn_inside_beside_one",
        drawn_inside().rect("met1", 2050, 0, 2550, 2000),
        2,
    ));
    cases.push(
        Fixture::new("multi_patterning/empty", &["DRC-100"], &deck, DRC)
            .layout(Layout::default().rect("other", 0, 0, 100, 100))
            .expect(Expect::outcome("mp1", Want::Skipped))
            .expect(Expect::outcome("mp2", Want::Skipped))
            .expect(Expect::outcome("mp3", Want::Skipped)),
    );
    every_placement(cases)
}

/// Stitches (DRC-103), written in the deck language: a wire split across
/// masks `c1` and `c2` overlaps itself where the pieces meet, and that
/// overlap must run at least the overlap margin along the wire,
/// `overlap(c1, c2) >= 10nm` (Ghaida et al., IEEE TCAD 2013, Table I: 10 nm;
/// Kahng et al., ICCAD 2008: the overlap length), and must sit where no
/// other figure is within the same-mask spacing, `space(c1 and c2, (c1 or
/// c2).not_interacting(c1 and c2)) >= 110nm` ("stitches should be located
/// only in non-violating parts", Ghaida et al.).
///
/// A 40 nm wire, its two pieces overlapping 9/10/11 along it, with a `c1`
/// wire 500 above; and the same wire overlapping 20, with that `c1` wire
/// 109/110/111 above. Orientation-free: all symmetries.
fn stitch() -> Vec<Fixture> {
    let deck = new_deck(
        &["c1", "c2"],
        "rule ST.OV overlap(c1, c2) >= 10nm\n\
         rule ST.SP space(c1 and c2, (c1 or c2).not_interacting(c1 and c2)) >= 110nm\n",
    );
    let wire = |t: i64| {
        Layout::default()
            .rect("c1", 0, 0, 500, 40)
            .rect("c2", 500 - t, 0, 1000, 40)
    };
    let mut cases = Vec::new();
    for (t, side) in sweep(10) {
        cases.push(fixture(
            &format!("stitch/overlap/{side}"),
            &["DRC-103"],
            &deck,
            wire(t).rect("c1", 0, 540, 1000, 580),
            &[("ST.OV", below(t, 10)), ("ST.SP", vec![])],
        ));
    }
    for (g, side) in sweep(110) {
        cases.push(fixture(
            &format!("stitch/keep_out/{side}"),
            &["DRC-103"],
            &deck,
            wire(20).rect("c1", 0, 40 + g, 1000, 80 + g),
            &[("ST.OV", vec![]), ("ST.SP", below(g, 110))],
        ));
    }
    every_placement(cases)
}

/// Trim and cut layers (DRC-105), written in the deck language: ASAP7's gate
/// cut, DRM Table 3.6.1. GCUT.W.1 `width(GCUT) >= 17nm`; GCUT.GATE.EX.1
/// `extension(GCUT, GATE) >= 17nm`, past each gate edge it crosses;
/// GCUT.AUX.1 "GCUT layer may not exist without the layer GATE",
/// `forbidden(GCUT.not_interacting(GATE))`; GCUT.AUX.2 "GCUT layer vertical
/// edge may not lie inside, or coincide with, the GATE layer", the vertical
/// GCUT edges strictly inside GATE or on a GATE edge.
///
/// A 20 x 200 gate. A 17-tall cut across it reaching 16/17/18 past each side
/// (EX.1 at the limit); a cut 16/17/18 tall reaching 30 past (W.1 at the
/// limit); a cut ending inside the gate and one ending on its far edge (each
/// a 17 nm vertical edge for AUX.2, and an extension of 0); a cut away from
/// any gate (AUX.1, its area). AUX.2 names an axis, so only the symmetries
/// that keep each axis apply.
fn trim_cut() -> Vec<Fixture> {
    let deck = new_deck(
        &["GATE", "GCUT"],
        "rule GCUT.W.1 width(GCUT) >= 17nm\n\
         rule GCUT.GATE.EX.1 extension(GCUT, GATE) >= 17nm\n\
         rule GCUT.AUX.1 forbidden(GCUT.not_interacting(GATE))\n\
         rule GCUT.AUX.2 forbidden(GCUT.edges().vertical().inside_part(GATE) \
         or (GCUT.edges().vertical() and GATE.edges()))\n",
    );
    let gate = || Layout::default().rect("GATE", 0, 0, 20, 200);
    let case = |name: &str, cut: Rect, rules: [Vec<Finding>; 4]| {
        let [w1, ex1, aux1, aux2] = rules;
        fixture(
            &format!("trim_cut/{name}"),
            &["DRC-105"],
            &deck,
            rects(gate(), "GCUT", &[cut]),
            &[
                ("GCUT.W.1", w1),
                ("GCUT.GATE.EX.1", ex1),
                ("GCUT.AUX.1", aux1),
                ("GCUT.AUX.2", aux2),
            ],
        )
    };
    let mut cases = Vec::new();
    for (e, side) in sweep(17) {
        cases.push(case(
            &format!("extension/{side}"),
            (-e, 90, 20 + e, 107),
            [vec![], below(e, 17), vec![], vec![]],
        ));
    }
    for (h, side) in sweep(17) {
        cases.push(case(
            &format!("width/{side}"),
            (-30, 90, 50, 90 + h),
            [below(h, 17), vec![], vec![], vec![]],
        ));
    }
    cases.push(case(
        "ends_inside",
        (-30, 90, 10, 107),
        [vec![], lengths(&[0]), vec![], lengths(&[17])],
    ));
    cases.push(case(
        "ends_on_edge",
        (-30, 90, 20, 107),
        [vec![], lengths(&[0]), vec![], lengths(&[17])],
    ));
    cases.push(case(
        "alone",
        (100, 90, 150, 107),
        [vec![], vec![], areas(&[850]), vec![]],
    ));
    let mut out = Vec::new();
    for fixture in &cases {
        for symmetry in Symmetry::ALL.into_iter().filter(|s| s.turns % 2 == 0) {
            for &(dx, dy) in &OFFSETS {
                out.push(fixture.transformed(symmetry, dx, dy));
            }
        }
    }
    out
}

/// `critical_area(met1; radius: r) <= a` (`critical_area`, DRC-112): the
/// short-circuit critical area for a square defect of half-side `r`, the
/// union over every pair of figures of their intersection once each is
/// grown by `r`, reported once when above the limit, measuring it, at the
/// centre of its box.
///
/// Closed form (Papadopoulou and Lee, 1999; Koren and Koren, 1998): two
/// parallel lines of length 1000 and a gap 200, under a defect of half-side
/// 150, have `(1000 + 300)(300 - 200) = 130000`, against limits one square
/// unit either side and at it. Three such lines 200 apart under half-side
/// 350 overlap three ways: the pairwise regions cover 1700 x 800 =
/// 1360000, not their sum (the 150 defect sees 260000 there, above every
/// limit). Lines 400 apart are out of reach of a 300 defect and leave 510000
/// under a 700 one, within its 1 um2; one L-shaped figure has no pair.
fn critical_area() -> Vec<Fixture> {
    let deck = new_deck(
        &["met1"],
        "rule below critical_area(met1; radius: 150nm) <= 129999nm2\n\
         rule at critical_area(met1; radius: 150nm) <= 130000nm2\n\
         rule above critical_area(met1; radius: 150nm) <= 130001nm2\n\
         rule wide critical_area(met1; radius: 350nm) <= 1um2\n",
    );
    let lines = |ys: &[i64]| {
        rects(
            Layout::default(),
            "met1",
            &ys.iter()
                .map(|&y| (0, y, 1000, y + 100))
                .collect::<Vec<_>>(),
        )
    };
    let case = |name: &str, layout: Layout, rules: [Vec<Finding>; 4]| {
        let [below, at, above, wide] = rules;
        fixture(
            &format!("critical_area/{name}"),
            &["DRC-112"],
            &deck,
            layout,
            &[
                ("below", below),
                ("at", at),
                ("above", above),
                ("wide", wide),
            ],
        )
    };
    let three = || vec![Finding::area(260_000).at(500, 350)];
    every_placement(vec![
        case(
            "two_lines",
            lines(&[0, 300]),
            [
                vec![Finding::area(130_000).at(500, 200)],
                vec![],
                vec![],
                vec![],
            ],
        ),
        case(
            "three_lines",
            lines(&[0, 300, 600]),
            [
                three(),
                three(),
                three(),
                vec![Finding::area(1_360_000).at(500, 350)],
            ],
        ),
        case("apart", lines(&[0, 500]), [vec![], vec![], vec![], vec![]]),
        case(
            "one_figure",
            rects(
                Layout::default(),
                "met1",
                &[(0, 0, 1000, 100), (0, 100, 100, 1000)],
            ),
            [vec![], vec![], vec![], vec![]],
        ),
    ])
}

/// Pattern matching (`pattern`, DRC-114): a 300 nm window holding an L of
/// 100-wide arms, `p` exact and `pd` with the window's upper-right
/// `[150, 300]²` don't-care; one finding per matching window, measuring the
/// L's 50000 nm².
///
/// Oracle: matches by construction from the patents' definition (the layout
/// inside the window equals the pattern, in any of the eight orientations,
/// don't-care regions matching anything): the L drawn exactly (both match),
/// with arms running on past the window (both: only the window is compared),
/// its arm 99, 100, 101 wide (only 100), a square in the window's
/// upper-right (only `pd`) and one beside the inner corner (neither), two Ls
/// apart (two each), and a solid 300 square (neither). Every case is placed
/// under the eight symmetries, so a mirrored L is matched too.
fn pattern_match() -> Vec<Fixture> {
    const L: &str = "shapes: [0nm x 0nm, 300nm x 100nm, 0nm x 100nm, 100nm x 300nm]";
    let deck = new_deck(
        &["m"],
        &format!(
            "rule p pattern(m; window: 300nm x 300nm, {L}, ignore: none)\n\
             rule pd pattern(m; window: 300nm x 300nm, {L}, ignore: [150nm x 150nm, 300nm x 300nm])\n"
        ),
    );
    let ell = |layout: Layout, x: i64, arm: i64, run: i64| {
        layout
            .rect("m", x, 0, x + run, arm)
            .rect("m", x, arm, x + 100, run)
    };
    let case = |name: &str, layout: Layout, (p, pd): (usize, usize)| {
        let found = |n: usize| vec![Finding::area(50_000); n];
        fixture(
            &format!("pattern/{name}"),
            &["DRC-114"],
            &deck,
            layout,
            &[("p", found(p)), ("pd", found(pd))],
        )
    };
    let mut cases = Vec::new();
    for (arm, side) in sweep(100) {
        let n = usize::from(arm == 100);
        cases.push(case(
            &format!("arm/{side}"),
            ell(Layout::default(), 0, arm, 300),
            (n, n),
        ));
    }
    cases.extend([
        case("long_arms", ell(Layout::default(), 0, 100, 600), (1, 1)),
        case(
            "square_in_the_dont_care",
            ell(Layout::default(), 0, 100, 300).rect("m", 200, 200, 250, 250),
            (0, 1),
        ),
        case(
            "square_by_the_corner",
            ell(Layout::default(), 0, 100, 300).rect("m", 120, 120, 140, 140),
            (0, 0),
        ),
        case(
            "two",
            ell(ell(Layout::default(), 0, 100, 300), 2000, 100, 300),
            (2, 2),
        ),
        case("solid", Layout::default().rect("m", 0, 0, 300, 300), (0, 0)),
    ]);
    every_placement(cases)
}

/// A connector's cut area between two databases (`cut_area_change`,
/// DRC-068, sky130 ct.irdrop in shape with deck-supplied values): pre cuts on
/// `v`, post cuts on `vc`, connectors `m1` x `m2`; bands from 1 cut allow
/// 10000 nm², from 4 cuts 40000 nm².
///
/// Oracle: areas by hand: three 100 nm pre cuts (30000) on one connector
/// against post 19999, 20000, 20001 (a change of 10001, 10000, 9999: one
/// finding of 10001); four pre cuts against none (40000, allowed) and five
/// (50000, a finding); two connectors on one m1 bar of two pre cuts each,
/// only the one whose cuts went missing found (20000); two pre cuts on m1 off
/// m2 count for nothing (counted, they would be a 20000 change); a connector
/// with post cuts and no pre cut is not judged; a post cut half off the
/// footprint counts its inside half (a change of 10000, allowed; the whole
/// cut would be 30000).
fn cut_area_change() -> Vec<Fixture> {
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
        fixture(
            &format!("cut_area_change/{name}"),
            &["DRC-068"],
            &deck,
            layout,
            &[("ir", found)],
        )
    };
    let three = || pre(pad(Layout::default(), 0), 0, 3);
    let cases = vec![
        case(
            "post_19999",
            three()
                .rect("vc", 0, 500, 100, 699)
                .rect("vc", 0, 699, 99, 700),
            areas(&[10_001]),
        ),
        case(
            "post_20000",
            three().rect("vc", 0, 500, 100, 700),
            Vec::new(),
        ),
        case(
            "post_20001",
            three()
                .rect("vc", 0, 500, 100, 700)
                .rect("vc", 500, 500, 501, 501),
            Vec::new(),
        ),
        case(
            "four_lost",
            pre(pad(Layout::default(), 0), 0, 4),
            Vec::new(),
        ),
        case(
            "five_lost",
            pre(pad(Layout::default(), 0), 0, 5),
            areas(&[50_000]),
        ),
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
        ),
        case(
            "off_the_upper",
            pad(Layout::default(), 0)
                .rect("m1", 1000, 0, 2000, 1000)
                .rect("v", 1200, 200, 1300, 300)
                .rect("v", 1400, 200, 1500, 300),
            Vec::new(),
        ),
        case(
            "post_only",
            pad(Layout::default(), 0).rect("vc", 100, 100, 600, 600),
            Vec::new(),
        ),
        case(
            "post_half_off",
            pre(pad(Layout::default(), 0), 0, 1).rect("vc", 800, 400, 1200, 500),
            Vec::new(),
        ),
    ];
    every_placement(cases)
}

/// Density held to the band a cover layer picks (`cover_density`, DRC-076,
/// sky130's waffle-drop rule shape with deck-supplied values): one 1000 nm
/// window over a die `[0, 1000]²`, bands starting at cover 25%, 50% and 100%
/// asking density 25%, 50% and 75%, read `inclusive` and not.
///
/// Oracle: coverage and density by hand from the drawn areas (window area
/// 10^6): a cover of exactly 50% is the 50% band inclusive (need 0.5) and the
/// 25% band exclusive (need 0.25); a full cover is the 100% band inclusive
/// (0.75) and the 50% band exclusive (0.5); 49.9% and 50.1% fall either side
/// alike; 20% is below every band (not judged, even with nothing drawn on
/// the held layer). The held layer's area is swept a step either side of
/// each need (499 000, 500 000, 501 000 for 0.5), one finding below it.
fn cover_density() -> Vec<Fixture> {
    let deck = |inclusive: bool| {
        new_deck(
            &["m", "c", "die"],
            &format!(
                "rule cd cover_density(m, c, die; window: 1000nm, step: 1000nm, \
                 cover: [25%, 50%, 100%], density: [25%, 50%, 75%], inclusive: {inclusive})\n"
            ),
        )
    };
    let ratio = |d: f64| Finding {
        measured: Some(Measurement::Ratio(d)),
        at: None,
    };
    let mut cases = Vec::new();
    // (cover area, need inclusive, need exclusive), areas of 10^6.
    for (cover, incl, excl) in [
        (500_000, Some(500_000), Some(250_000)),
        (1_000_000, Some(750_000), Some(500_000)),
        (499_000, Some(250_000), Some(250_000)),
        (501_000, Some(500_000), Some(500_000)),
        (200_000, None, None),
    ] {
        for (inclusive, need) in [(true, incl), (false, excl)] {
            let held = match need {
                Some(need) => vec![need - 1000, need, need + 1000],
                None => vec![0, 100_000],
            };
            for area in held {
                let mut layout = Layout::default().rect("die", 0, 0, 1000, 1000).rect(
                    "c",
                    0,
                    0,
                    1000,
                    cover / 1000,
                );
                if area > 0 {
                    layout = layout.rect("m", 0, 0, area / 1000, 1000);
                }
                let found = match need {
                    Some(need) if area < need => {
                        vec![ratio(f64::from(i32::try_from(area).expect("small")) / 1e6)]
                    }
                    _ => Vec::new(),
                };
                cases.push(fixture(
                    &format!("cover_density/{cover}/{inclusive}/{area}"),
                    &["DRC-076"],
                    &deck(inclusive),
                    layout,
                    &[("cd", found)],
                ));
            }
        }
    }
    every_placement(cases)
}

/// `density_balance(c1, c2, die; window: 1000nm, step: 1000nm) >= 0.5`
/// (`density_balance`, DRC-104): in each window, the lesser of the two
/// masks' coverage over the greater, and a window below 0.5 is one finding
/// at its centre, measuring that balance.
///
/// The die is 3000 x 1000, three windows. The first holds 500 x 1000 of
/// `c1` and `c2` 1000 tall and 249/250/251 wide (balance 0.498, 0.5, 0.502:
/// one step either side of the limit); the second only `c1` (balance 0);
/// the third neither (not judged). Windows anchor on the die's corner, so
/// translations only.
fn density_balance() -> Vec<Fixture> {
    let deck = new_deck(
        &["die", "c1", "c2"],
        "rule bal density_balance(c1, c2, die; window: 1000nm, step: 1000nm) >= 0.5\n",
    );
    let mut cases = Vec::new();
    for (w, side) in sweep(250) {
        let mut findings = vec![ratio(0.0, (1500, 500))];
        if w < 250 {
            // 249 x 1000 over 500 x 1000.
            findings.push(ratio(0.498, (500, 500)));
        }
        cases.push(fixture(
            &format!("density_balance/{side}"),
            &["DRC-104"],
            &deck,
            Layout::default()
                .rect("die", 0, 0, 3000, 1000)
                .rect("c1", 0, 0, 500, 1000)
                .rect("c2", 600, 0, 600 + w, 1000)
                .rect("c1", 1000, 0, 1400, 1000),
            &[("bal", findings)],
        ));
    }
    every_offset(&cases)
}

/// Same-mask and different-mask spacing of pre-coloured shapes (DRC-102), as
/// a deck writes LEF `SPACING ... SAMEMASK`: each mask's shapes are a layer
/// (`met1 and c1`), so same-mask spacing is `space` on it and different-mask
/// spacing is `space` between two of them. Two 500 x 500 squares `g` apart,
/// swept about the 100 nm same-mask limit: both on mask 1, the same-mask rule
/// reports the gap below it; one on each mask, only the 40 nm different-mask
/// rule applies and the gap clears it.
fn colour_spacing() -> Vec<Fixture> {
    let deck = new_deck(
        &["met1", "c1", "c2"],
        "rule same space(met1 and c1) >= 100nm\n\
         rule apart space(met1 and c1, met1 and c2) >= 40nm\n",
    );
    let mut cases = Vec::new();
    for (g, side) in sweep(100) {
        let squares = || {
            Layout::default()
                .rect("met1", 0, 0, 500, 500)
                .rect("met1", 500 + g, 0, 1000 + g, 500)
                .rect("c1", 0, 0, 500, 500)
        };
        cases.push(fixture(
            &format!("colour_spacing/same/{side}"),
            &["DRC-102"],
            &deck,
            squares().rect("c1", 500 + g, 0, 1000 + g, 500),
            &[("same", below(g, 100)), ("apart", vec![])],
        ));
        cases.push(fixture(
            &format!("colour_spacing/apart/{side}"),
            &["DRC-102"],
            &deck,
            squares().rect("c2", 500 + g, 0, 1000 + g, 500),
            &[("same", vec![]), ("apart", vec![])],
        ));
    }
    every_placement(cases)
}

/// `patterning(met1, c1, c2; colors: 2) >= 100nm` (`anchored_patterning`,
/// DRC-101, DRC-102): a figure sharing area with a `c1` shape must take mask
/// 1, with a `c2` shape mask 2, and an anchor conflict is a component two
/// masks can split but not with its anchors. Its finding names the lowest
/// anchored figure and the first whose chain of conflicts to it has the
/// wrong parity, at the middle of the gap between them, or one figure both
/// anchor layers claim, at its centre; it measures 3 masks against 2. The
/// plain `patterning(met1; colors: 2)` row beside it reports what no split
/// fixes.
///
/// Bars 100 x 500, 150 apart in x (a 50 gap, a conflict), in a chain, as
/// US8473873B2's FIG. 1, 5 and 6: four bars anchored alike at both ends
/// (three conflicts, odd: an anchor path), or apart (honoured); five bars
/// (four conflicts) alike (honoured) or apart (a path); four unanchored; the
/// end anchored only in part (any overlap anchors); an anchor that only
/// touches its bar (no anchor); one bar under both anchor layers (anchor
/// self-conflict); a triangle with an anchor (no split at all: the plain
/// row's). With three masks: a triangle with two corners anchored to mask 1
/// (the lowest anchored, 4 against 3), and with one anchor per mask
/// (honoured). The empty layer is skipped.
fn anchored_patterning() -> Vec<Fixture> {
    let deck = new_deck(
        &["met1", "c1", "c2", "c3"],
        "rule odd patterning(met1; colors: 2) >= 100nm\n\
         rule ap patterning(met1, c1, c2; colors: 2) >= 100nm\n\
         rule ap3 patterning(met1, c1, c2, c3; colors: 3) >= 100nm\n",
    );
    let bar = |i: i64| (150 * i, 0, 150 * i + 100, 500);
    let chain = |n: i64| {
        rects(
            Layout::default(),
            "met1",
            &(0..n).map(bar).collect::<Vec<_>>(),
        )
    };
    let case =
        |name: &str, layout: Layout, odd: Vec<Finding>, ap: Vec<Finding>, ap3: Vec<Finding>| {
            fixture(
                &format!("anchored_patterning/{name}"),
                &["DRC-101", "DRC-102"],
                &deck,
                layout,
                &[("odd", odd), ("ap", ap), ("ap3", ap3)],
            )
        };
    let triangle = || {
        rects(
            Layout::default(),
            "met1",
            &[(0, 0, 500, 500), (550, 0, 1050, 500), (0, 550, 1050, 1050)],
        )
    };
    let mut cases = vec![
        case(
            "chain4/alike",
            chain(4)
                .rect("c1", 0, 0, 100, 500)
                .rect("c1", 450, 0, 550, 500),
            vec![],
            vec![count(3).at(275, 250)],
            vec![],
        ),
        case(
            "chain4/apart",
            chain(4)
                .rect("c1", 0, 0, 100, 500)
                .rect("c2", 450, 0, 550, 500),
            vec![],
            vec![],
            vec![],
        ),
        case(
            "chain5/alike",
            chain(5)
                .rect("c1", 0, 0, 100, 500)
                .rect("c1", 600, 0, 700, 500),
            vec![],
            vec![],
            vec![],
        ),
        case(
            "chain5/apart",
            chain(5)
                .rect("c1", 0, 0, 100, 500)
                .rect("c2", 600, 0, 700, 500),
            vec![],
            vec![count(3).at(350, 250)],
            vec![],
        ),
        case("chain4/unanchored", chain(4), vec![], vec![], vec![]),
        case(
            "chain4/partial_anchor",
            chain(4)
                .rect("c1", 0, 0, 50, 50)
                .rect("c1", 450, 0, 550, 500),
            vec![],
            vec![count(3).at(275, 250)],
            vec![],
        ),
        case(
            "chain4/touching_anchor",
            chain(4)
                .rect("c1", -100, 0, 0, 500)
                .rect("c1", 450, 0, 550, 500),
            vec![],
            vec![],
            vec![],
        ),
        case(
            "self_conflict",
            chain(1)
                .rect("c1", 0, 0, 100, 500)
                .rect("c2", 0, 0, 100, 500),
            vec![],
            vec![count(3).at(50, 250)],
            vec![count(4).at(50, 250)],
        ),
        case(
            "odd_cycle",
            triangle().rect("c1", 0, 0, 500, 500),
            vec![count(3)],
            vec![],
            vec![],
        ),
        case(
            "triangle/alike",
            triangle()
                .rect("c1", 0, 0, 500, 500)
                .rect("c1", 550, 0, 1050, 500),
            vec![count(3)],
            vec![],
            vec![count(4).at(250, 250)],
        ),
        case(
            "triangle/each",
            triangle()
                .rect("c1", 0, 0, 500, 500)
                .rect("c2", 550, 0, 1050, 500)
                .rect("c3", 0, 550, 1050, 1050),
            vec![count(3)],
            vec![],
            vec![],
        ),
    ];
    cases = every_placement(cases);
    cases.push(
        Fixture::new("anchored_patterning/empty", &["DRC-101"], &deck, DRC)
            .layout(Layout::default().rect("c1", 0, 0, 100, 100))
            .expect(Expect::outcome("ap", Want::Skipped))
            .expect(Expect::outcome("ap3", Want::Skipped)),
    );
    cases
}

// --------------------------------------------------- derived-layer operations

/// One fixture per layout proving derived layers through `forbidden`: rule
/// `f{i}` forbids `exprs[i].0`, declared as layer `d{i}`, and must report
/// exactly `exprs[i].1`.
fn derived(
    name: &str,
    catalog: &[&'static str],
    layers: &[&str],
    exprs: &[(&str, Vec<Finding>)],
    layout: Layout,
) -> Fixture {
    const IDS: [&str; 4] = ["f0", "f1", "f2", "f3"];
    let mut body = String::new();
    for (i, (expr, _)) in exprs.iter().enumerate() {
        writeln!(body, "layer d{i} = {expr}\nrule f{i} forbidden(d{i})")
            .expect("a String takes any write");
    }
    let rules: Vec<(&str, Vec<Finding>)> = IDS
        .iter()
        .zip(exprs)
        .map(|(&id, (_, findings))| (id, findings.clone()))
        .collect();
    fixture(name, catalog, &new_deck(layers, &body), layout, &rules)
}

/// `and`, `or` and `not` (DRC-120, and DRC-050 for a forbidden overlap): each
/// resulting merged shape reported with its area, holes excluded.
///
/// `a` is `[0, 1000]^2` unless stated. `and`: a partial overlap, edge and
/// corner contact (empty), `b` splitting the overlap in two, `a` drawn as two
/// overlapping pieces (one result), and sky130 licon.17 written inline,
/// `forbidden(licon and poly and (diff or tap))`. `or`: overlapping, abutting
/// (one shape) and apart. `not`: a bite, a split, a hole (one shape with its
/// hole excluded), an abutting `b` (no change), a covering `b` (empty), and
/// three operands folded left.
fn booleans() -> Vec<Fixture> {
    let cat = &["DRC-120"];
    let ab = &["a", "b"];
    let a = || Layout::default().rect("a", 0, 0, 1000, 1000);
    let with_b = |rs: &[Rect]| rects(a(), "b", rs);
    let mut cases = vec![
        derived(
            "derived/and/overlap",
            &["DRC-120", "DRC-050"],
            ab,
            &[("a and b", areas(&[160_000]))],
            with_b(&[(600, 300, 1600, 700)]),
        ),
        derived(
            "derived/and/edge_contact",
            cat,
            ab,
            &[("a and b", vec![])],
            with_b(&[(1000, 300, 1600, 700)]),
        ),
        derived(
            "derived/and/corner_contact",
            cat,
            ab,
            &[("a and b", vec![])],
            with_b(&[(1000, 1000, 1600, 1600)]),
        ),
        derived(
            "derived/and/split",
            cat,
            ab,
            &[("a and b", areas(&[200_000, 200_000]))],
            with_b(&[(-100, -100, 200, 1100), (800, -100, 1100, 1100)]),
        ),
        derived(
            "derived/and/overlapping_operand",
            cat,
            ab,
            &[("a and b", areas(&[160_000]))],
            Layout::default()
                .rect("a", 0, 0, 600, 1000)
                .rect("a", 400, 0, 1000, 1000)
                .rect("b", 300, 300, 700, 700),
        ),
        derived(
            "derived/or/overlap",
            cat,
            ab,
            &[("a or b", areas(&[1_240_000]))],
            with_b(&[(600, 300, 1600, 700)]),
        ),
        derived(
            "derived/or/abutting",
            cat,
            ab,
            &[("a or b", areas(&[2_000_000]))],
            with_b(&[(1000, 0, 2000, 1000)]),
        ),
        derived(
            "derived/or/apart",
            cat,
            ab,
            &[("a or b", areas(&[1_000_000, 1_000_000]))],
            with_b(&[(1001, 0, 2001, 1000)]),
        ),
        derived(
            "derived/not/bite",
            cat,
            ab,
            &[("a not b", areas(&[800_000]))],
            with_b(&[(800, -100, 1200, 1100)]),
        ),
        derived(
            "derived/not/split",
            cat,
            ab,
            &[("a not b", areas(&[400_000, 400_000]))],
            with_b(&[(400, -100, 600, 1100)]),
        ),
        derived(
            "derived/not/hole",
            cat,
            ab,
            &[("a not b", areas(&[960_000]))],
            with_b(&[(400, 400, 600, 600)]),
        ),
        derived(
            "derived/not/abutting",
            cat,
            ab,
            &[("a not b", areas(&[1_000_000]))],
            with_b(&[(1000, 0, 2000, 1000)]),
        ),
        derived(
            "derived/not/covered",
            cat,
            ab,
            &[("a not b", vec![])],
            with_b(&[(-100, -100, 1100, 1100)]),
        ),
        derived(
            "derived/not/three_operands",
            cat,
            &["a", "b", "c"],
            &[("a not b not c", areas(&[400_000]))],
            a().rect("b", 0, 0, 300, 1000).rect("c", 700, 0, 1000, 1000),
        ),
    ];
    cases.push(fixture(
        "derived/and/licon_17_inline",
        &["DRC-050", "DRC-120"],
        &new_deck(
            &["licon", "poly", "diff", "tap"],
            "rule licon.17 forbidden(licon and poly and (diff or tap))\n",
        ),
        rects(
            Layout::default()
                .rect("poly", 0, 0, 1000, 200)
                .rect("diff", 0, -500, 400, 500)
                .rect("tap", 600, -500, 1000, 500),
            "licon",
            &[
                (100, 50, 200, 150),
                (700, 50, 850, 150),
                (450, 50, 550, 150),
                (100, 300, 200, 400),
            ],
        ),
        &[("licon.17", areas(&[10_000, 15_000]))],
    ));
    every_placement(cases)
}

/// `.sized` (DRC-120): growth by `a` on every side with square corners;
/// shrinking, where a part no wider than twice the shrink disappears; and the
/// opening `.sized(-a).sized(a)`, which keeps the parts wider than `2a`.
///
/// Shapes: a bar grown by 50; an L grown and shrunk by 50 (its concave corner
/// stays); two squares 99 and 101 apart grown by 50 (one shape, or two); bars
/// 99/100/101 wide shrunk by 50 (gone, gone, 1 x 900); a ring with a 200 nm
/// hole grown by 99/100/101 (the hole 2 x 2, then closed) and shrunk by 100;
/// a plate with a 100-wide tab (two abutting pieces) opened by 49/50/51 (tab
/// kept, then gone); a dumbbell opened by 60, which splits it into its two
/// plates.
fn sizing() -> Vec<Fixture> {
    let cat = &["DRC-120"];
    let only_a = &["a"];
    let mut cases = vec![derived(
        "derived/sized/grow",
        cat,
        only_a,
        &[("a.sized(50nm)", areas(&[80_000]))],
        Layout::default().rect("a", 0, 0, 100, 300),
    )];
    // An L keeps its concave corner: grown by 50 it is two 1100 x 300 arms
    // sharing 300 x 300, shrunk by 50 two 900 x 100 arms sharing 100 x 100.
    let l_shape = [
        (0, 0),
        (1000, 0),
        (1000, 200),
        (200, 200),
        (200, 1000),
        (0, 1000),
    ];
    for (by, area) in [(50, 570_000), (-50, 170_000)] {
        cases.push(derived(
            &format!("derived/sized/l_shape{by}"),
            cat,
            only_a,
            &[(&format!("a.sized({by}nm)"), areas(&[area]))],
            Layout::default().polygon("a", &l_shape),
        ));
    }
    for (g, grown) in [(99, areas(&[79_800])), (101, areas(&[40_000, 40_000]))] {
        cases.push(derived(
            &format!("derived/sized/grow_gap{g}"),
            cat,
            only_a,
            &[("a.sized(50nm)", grown)],
            Layout::default()
                .rect("a", 0, 0, 100, 100)
                .rect("a", 100 + g, 0, 200 + g, 100),
        ));
    }
    for (w, side) in sweep(100) {
        cases.push(derived(
            &format!("derived/sized/shrink/{side}"),
            cat,
            only_a,
            &[(
                "a.sized(-50nm)",
                if w > 100 { areas(&[900]) } else { vec![] },
            )],
            Layout::default().rect("a", 0, 0, w, 1000),
        ));
    }
    for (by, side) in sweep(50) {
        cases.push(derived(
            &format!("derived/sized/opening/{side}"),
            cat,
            only_a,
            &[(
                &format!("a.sized(-{by}nm).sized({by}nm)"),
                areas(&[if by < 50 { 1_100_000 } else { 1_000_000 }]),
            )],
            Layout::default()
                .rect("a", 0, 0, 1000, 1000)
                .rect("a", 1000, 450, 2000, 550),
        ));
    }
    // A ring with a 200 nm hole: grown by 99 the hole is 2 x 2, by 100 it
    // closes; shrunk by 100 the hole widens to 400.
    let ringed = || {
        ring(
            Layout::default(),
            "a",
            (0, 0, 1000, 1000),
            (400, 400, 600, 600),
        )
    };
    for (by, side, area) in [
        (99, "below", 1_198 * 1_198 - 4),
        (100, "at", 1_200 * 1_200),
        (101, "above", 1_202 * 1_202),
    ] {
        cases.push(derived(
            &format!("derived/sized/ring_closes/{side}"),
            cat,
            only_a,
            &[(&format!("a.sized({by}nm)"), areas(&[area]))],
            ringed(),
        ));
    }
    cases.push(derived(
        "derived/sized/ring_shrinks",
        cat,
        only_a,
        &[("a.sized(-100nm)", areas(&[640_000 - 160_000]))],
        ringed(),
    ));
    cases.push(derived(
        "derived/sized/opening_splits",
        cat,
        only_a,
        &[("a.sized(-60nm).sized(60nm)", areas(&[1_000_000, 1_000_000]))],
        rects(
            Layout::default(),
            "a",
            &[
                (0, 0, 1000, 1000),
                (1000, 450, 1500, 550),
                (1500, 0, 2500, 1000),
            ],
        ),
    ));
    every_placement(cases)
}

/// The selections (DRC-120, DRC-121): `interacting` and `not_interacting`
/// (corner-only contact counts, 1 nm apart does not, an `a` shape far from
/// `b` is selected through a shape it abuts, and a ring interacts with an
/// island of `b` in its hole only when they touch), and the straddle
/// `interacting not inside not outside`; `inside` and `outside` against a `b`
/// drawn as two halves (touching the boundary from inside is inside, from
/// outside is outside, straddling is neither) and against a `b` ring (a shape
/// in its hole is outside); `holes` (one, one with an island, two, and a U
/// with none); `extents` (an L, two touching shapes, two apart, a ring, and
/// two interlocking Ls whose boxes overlap, F54); `with_area` and
/// `with_width` across their bounds, holes excluded and touching pieces
/// merged, and a corner neck `width` measures Euclidean (F55); and
/// `with_text` / `without_text` with `*`, `?`, case, a text on the edge, one
/// off the shape and one in a ring's hole.
fn selections() -> Vec<Fixture> {
    let cat = &["DRC-120", "DRC-121"];
    let ab = &["a", "b"];
    let mut cases = Vec::new();

    let contact = rects(
        Layout::default().rect("b", 0, 0, 1000, 1000),
        "a",
        &[
            (900, 100, 1200, 200),
            (1200, 100, 1500, 200),
            (1000, 300, 1300, 400),
            (1000, 1000, 1100, 1100),
            (-101, 500, -1, 600),
            (-500, -500, -400, -400),
        ],
    );
    cases.push(derived(
        "derived/interacting",
        cat,
        ab,
        &[
            ("a.interacting(b)", areas(&[60_000, 30_000, 10_000])),
            ("a.not_interacting(b)", areas(&[10_000, 10_000])),
            (
                "a.interacting(b) not a.inside(b) not a.outside(b)",
                areas(&[60_000]),
            ),
        ],
        contact,
    ));
    cases.push(derived(
        "derived/inside_outside_ring",
        cat,
        ab,
        &[
            ("a.inside(b)", areas(&[10_000])),
            ("a.outside(b)", areas(&[20_000])),
        ],
        ring(
            rects(
                Layout::default(),
                "a",
                &[
                    (100, 100, 200, 200),
                    (400, 450, 600, 550),
                    (250, 450, 350, 550),
                ],
            ),
            "b",
            (0, 0, 1000, 1000),
            (300, 300, 700, 700),
        ),
    ));
    // A ring and an island of `b` in its hole: apart they do not interact,
    // touching the hole's edge they do.
    for (name, island, hit, miss) in [
        (
            "island_apart",
            (400, 400, 600, 600),
            vec![],
            areas(&[840_000]),
        ),
        (
            "island_touching",
            (300, 400, 400, 600),
            areas(&[840_000]),
            vec![],
        ),
    ] {
        cases.push(derived(
            &format!("derived/interacting_ring/{name}"),
            cat,
            ab,
            &[("a.interacting(b)", hit), ("a.not_interacting(b)", miss)],
            ring(
                rects(Layout::default(), "b", &[island]),
                "a",
                (0, 0, 1000, 1000),
                (300, 300, 700, 700),
            ),
        ));
    }

    let placed = rects(
        Layout::default()
            .rect("b", 0, 0, 500, 1000)
            .rect("b", 500, 0, 1000, 1000),
        "a",
        &[
            (100, 100, 200, 200),
            (0, 400, 200, 500),
            (400, 700, 700, 800),
            (900, 100, 1100, 300),
            (1000, 400, 1500, 500),
            (1500, 0, 1800, 200),
        ],
    );
    cases.push(derived(
        "derived/inside_outside",
        cat,
        ab,
        &[
            ("a.inside(b)", areas(&[10_000, 20_000, 30_000])),
            ("a.outside(b)", areas(&[50_000, 60_000])),
        ],
        placed,
    ));

    let ring_a = |layout| ring(layout, "a", (0, 0, 1000, 1000), (400, 300, 600, 700));
    for (name, layout, holes) in [
        ("ring", ring_a(Layout::default()), areas(&[80_000])),
        (
            "ring_with_island",
            ring_a(Layout::default()).rect("a", 450, 450, 550, 550),
            areas(&[80_000]),
        ),
        (
            "two_holes",
            rects(
                Layout::default(),
                "a",
                &[
                    (0, 0, 1000, 100),
                    (0, 900, 1000, 1000),
                    (0, 100, 100, 900),
                    (900, 100, 1000, 900),
                    (450, 100, 550, 900),
                ],
            ),
            areas(&[280_000, 280_000]),
        ),
        (
            "u_shape",
            rects(
                Layout::default(),
                "a",
                &[
                    (0, 0, 1000, 100),
                    (0, 100, 100, 1000),
                    (900, 100, 1000, 1000),
                ],
            ),
            vec![],
        ),
    ] {
        cases.push(derived(
            &format!("derived/holes/{name}"),
            cat,
            &["a"],
            &[("a.holes()", holes)],
            layout,
        ));
    }

    for (name, layout, extents) in [
        (
            "l_shape",
            Layout::default().polygon(
                "a",
                &[
                    (0, 0),
                    (1000, 0),
                    (1000, 200),
                    (200, 200),
                    (200, 1000),
                    (0, 1000),
                ],
            ),
            areas(&[1_000_000]),
        ),
        (
            "touching",
            Layout::default()
                .rect("a", 0, 0, 500, 200)
                .rect("a", 500, 0, 1000, 400),
            areas(&[400_000]),
        ),
        (
            "apart",
            Layout::default()
                .rect("a", 0, 0, 500, 200)
                .rect("a", 600, 0, 1000, 400),
            areas(&[100_000, 160_000]),
        ),
        (
            "ring",
            ring(
                Layout::default(),
                "a",
                (0, 0, 1000, 1000),
                (300, 300, 700, 700),
            ),
            areas(&[1_000_000]),
        ),
        (
            "interlocking",
            Layout::default()
                .polygon(
                    "a",
                    &[
                        (0, 0),
                        (1000, 0),
                        (1000, 100),
                        (100, 100),
                        (100, 1000),
                        (0, 1000),
                    ],
                )
                .polygon(
                    "a",
                    &[
                        (1100, 200),
                        (1200, 200),
                        (1200, 1200),
                        (200, 1200),
                        (200, 1100),
                        (1100, 1100),
                    ],
                ),
            areas(&[1_000_000, 1_000_000]),
        ),
    ] {
        cases.push(derived(
            &format!("derived/extents/{name}"),
            cat,
            &["a"],
            &[("a.extents()", extents)],
            layout,
        ));
    }

    let sized = ring(
        rects(
            Layout::default(),
            "a",
            &[
                (0, 0, 100, 99),
                (200, 0, 300, 100),
                (400, 0, 500, 101),
                (600, 0, 650, 100),
                (650, 0, 700, 100),
            ],
        ),
        "a",
        (0, 1000, 200, 1200),
        (50, 1050, 150, 1150),
    );
    cases.push(derived(
        "derived/with_area",
        cat,
        &["a"],
        &[
            (
                "a.with_area(>= 10000nm2)",
                areas(&[10_000, 10_100, 10_000, 30_000]),
            ),
            ("a.with_area(== 30000nm2)", areas(&[30_000])),
            (
                "a.with_area(> 9999nm2, < 10001nm2)",
                areas(&[10_000, 10_000]),
            ),
        ],
        sized,
    ));

    let bars = rects(
        Layout::default().polygon(
            "a",
            &[
                (0, 2000),
                (1000, 2000),
                (1000, 2500),
                (99, 2500),
                (99, 3500),
                (0, 3500),
            ],
        ),
        "a",
        &[
            (0, 0, 99, 1000),
            (200, 0, 300, 1000),
            (400, 0, 501, 1000),
            (600, 0, 650, 1000),
            (650, 0, 700, 1000),
        ],
    );
    cases.push(derived(
        "derived/with_width",
        cat,
        &["a"],
        &[
            ("a.with_width(< 100nm)", areas(&[99_000, 599_000])),
            (
                "a.with_width(>= 100nm)",
                areas(&[100_000, 101_000, 100_000]),
            ),
        ],
        bars,
    ));
    // Two plates overlapping 50 x 50 at a corner: the Euclidean neck between
    // their concave corners is sqrt(5000), 70.7 nm, which `width` measures.
    // It is more than 70 nm and less than 71 (F65: not floored to 70).
    let plates = || {
        Layout::default()
            .rect("a", 0, 0, 1000, 1000)
            .rect("a", 950, 950, 1950, 1950)
    };
    cases.push(derived(
        "derived/with_width_neck",
        cat,
        &["a"],
        &[
            ("a.with_width(< 100nm)", areas(&[1_997_500])),
            ("a.with_width(>= 100nm)", vec![]),
        ],
        plates(),
    ));
    cases.push(derived(
        "derived/with_width_neck_strict",
        cat,
        &["a"],
        &[
            ("a.with_width(> 70nm)", areas(&[1_997_500])),
            ("a.with_width(<= 70nm)", vec![]),
            ("a.with_width(== 70nm)", vec![]),
            ("a.with_width(> 70nm, < 71nm)", areas(&[1_997_500])),
        ],
        plates(),
    ));
    // Plates overlapping 70 x 1: a neck of sqrt(70² + 1²) = sqrt(4901), within
    // half a unit of 70, where a whole-unit `width` limit at x2 cannot tell it
    // from 70 (the KLayout mirror measures it exactly).
    cases.push(derived(
        "derived/with_width_neck_band",
        cat,
        &["a"],
        &[
            ("a.with_width(<= 70nm)", vec![]),
            ("a.with_width(> 70nm)", areas(&[1_999_930])),
        ],
        Layout::default()
            .rect("a", 0, 0, 1000, 1000)
            .rect("a", 930, 999, 1930, 1999),
    ));

    let texts = rects(
        ring(
            Layout::default(),
            "a",
            (3000, 0, 3600, 600),
            (3100, 100, 3500, 500),
        )
        .label("t", 3300, 300, "VDD"),
        "a",
        &[
            (0, 0, 100, 100),
            (200, 0, 400, 100),
            (500, 0, 800, 100),
            (900, 0, 1300, 100),
            (1400, 0, 1900, 100),
            (2000, 0, 2600, 100),
        ],
    )
    .label("t", 50, 50, "VDD")
    .label("t", 200, 50, "VDDA")
    .label("t", 650, 50, "vdd")
    .label("t", 1100, 50, "VSD")
    .label("t", 1650, 200, "VDD");
    cases.push(derived(
        "derived/with_text",
        cat,
        &["a", "t"],
        &[
            ("a.with_text(t, \"VDD*\")", areas(&[10_000, 20_000])),
            (
                "a.without_text(t, \"VDD*\")",
                areas(&[30_000, 40_000, 50_000, 60_000, 200_000]),
            ),
            ("a.with_text(t, \"V?D\")", areas(&[10_000, 40_000])),
        ],
        texts,
    ));
    every_placement(cases)
}

/// `sized(dx, dy)` (DRC-121), `KLayout`'s anisotropic sizing: each shape
/// grown by `dx` left and right and `dy` above and below, or shrunk when both
/// are negative. Each result is reported with its area, worked by hand.
///
/// A 1000 x 500 box grown by (100, 50) (1200 x 600), shrunk by (100, 50)
/// (800 x 400), grown in y only (1000 x 700), and grown then shrunk back;
/// two 1000 x 500 bars 100 apart across x, which (50, 0) joins and (49, 0)
/// leaves 2 apart, while (0, 50) leaves the gap; a 1000 x 200 bar that
/// (-50, -100) shrinks away and (-50, -99) leaves 2 tall. The rule names an
/// axis, so only the symmetries that keep each axis (no quarter turn) apply.
fn sized_xy() -> Vec<Fixture> {
    let cat = &["DRC-121"];
    let cases = [
        derived(
            "derived/sized_xy/box",
            cat,
            &["a"],
            &[
                ("a.sized(100nm, 50nm)", areas(&[720_000])),
                ("a.sized(-100nm, -50nm)", areas(&[320_000])),
                ("a.sized(0nm, 100nm)", areas(&[700_000])),
                (
                    "a.sized(100nm, 50nm).sized(-100nm, -50nm)",
                    areas(&[500_000]),
                ),
            ],
            Layout::default().rect("a", 0, 0, 1000, 500),
        ),
        derived(
            "derived/sized_xy/gap",
            cat,
            &["a"],
            &[
                ("a.sized(50nm, 0nm)", areas(&[1_100_000])),
                ("a.sized(49nm, 0nm)", areas(&[549_000, 549_000])),
                ("a.sized(0nm, 50nm)", areas(&[600_000, 600_000])),
            ],
            rects(
                Layout::default(),
                "a",
                &[(0, 0, 1000, 500), (1100, 0, 2100, 500)],
            ),
        ),
        derived(
            "derived/sized_xy/vanish",
            cat,
            &["a"],
            &[
                ("a.sized(-50nm, -100nm)", vec![]),
                ("a.sized(-50nm, -99nm)", areas(&[1800])),
            ],
            Layout::default().rect("a", 0, 0, 1000, 200),
        ),
    ];
    cases
        .iter()
        .flat_map(|fixture| {
            Symmetry::ALL
                .into_iter()
                .filter(|symmetry| symmetry.turns % 2 == 0)
                .flat_map(move |symmetry| {
                    OFFSETS
                        .iter()
                        .map(move |&(dx, dy)| fixture.transformed(symmetry, dx, dy))
                })
        })
        .collect()
}

/// `covering`, `not_covering`, `overlapping` and `not_overlapping` (DRC-121),
/// `KLayout`'s operations of those names: an `a` shape covers when it holds a
/// whole `b` shape (touching its boundary from inside allowed), and overlaps
/// when it shares area with one (touching is not). Each selected `a` shape is
/// reported with its area, which names it.
///
/// `a` shapes: holding a `b` (1000000); with a `b` across its edge (900000);
/// touched by a `b` from outside (800000); with a `b` touching its edge from
/// inside (700000); holding a `b` drawn as two abutting halves (600000);
/// drawn as two abutting halves holding a `b` across the seam (500000); a
/// ring with a `b` island in its hole (840000); alone (400000); and inside a
/// larger `b` (90000).
fn covering_overlapping() -> Vec<Fixture> {
    let layout = ring(
        rects(
            rects(
                Layout::default(),
                "a",
                &[
                    (0, 0, 1000, 1000),
                    (2000, 0, 2900, 1000),
                    (4000, 0, 4800, 1000),
                    (6000, 0, 6700, 1000),
                    (8000, 0, 8600, 1000),
                    (10_000, 0, 10_250, 1000),
                    (10_250, 0, 10_500, 1000),
                    (14_000, 0, 14_400, 1000),
                    (16_200, 200, 16_500, 500),
                ],
            ),
            "b",
            &[
                (200, 200, 400, 400),
                (2800, 400, 3000, 600),
                (4800, 400, 5000, 600),
                (6000, 400, 6200, 600),
                (8100, 100, 8200, 300),
                (8200, 100, 8300, 300),
                (10_200, 400, 10_300, 600),
                (12_400, 400, 12_600, 600),
                (16_000, 0, 17_000, 1000),
            ],
        ),
        "a",
        (12_000, 0, 13_000, 1000),
        (12_300, 300, 12_700, 700),
    );
    every_placement(vec![derived(
        "derived/covering_overlapping",
        &["DRC-121"],
        &["a", "b"],
        &[
            (
                "a.covering(b)",
                areas(&[1_000_000, 700_000, 600_000, 500_000]),
            ),
            (
                "a.not_covering(b)",
                areas(&[900_000, 800_000, 840_000, 400_000, 90_000]),
            ),
            (
                "a.overlapping(b)",
                areas(&[1_000_000, 900_000, 700_000, 600_000, 500_000, 90_000]),
            ),
            ("a.not_overlapping(b)", areas(&[800_000, 840_000, 400_000])),
        ],
        layout,
    )])
}

/// Rectangle-only and square-only shapes (DRC-005: sky130 capm.7 "only
/// rectangular capacitors", LEF58 `RECTONLY`), as `forbidden(L.non_rectangles())`
/// and the other three selections, each shape reported with its area.
///
/// Oracle: hand-derived areas of shapes whose class is fixed by construction,
/// read merged as `KLayout`'s `rectangles` and `squares` read them. A square
/// and a 100 x 200 bar; a square drawn as two abutting halves, which only the
/// merged layer sees as one square; a bar drawn twice, and as two overlapping
/// boxes (one box each); an L; two squares meeting only at a corner (one shape
/// under the corner model, no rectangle); and a square ring, whose box is
/// square but whose hole makes it none. A check that reads drawn rows calls
/// the halves two non-squares; one blind to holes calls the ring a square.
fn shape_class() -> Vec<Fixture> {
    let layout = ring(
        rects(
            Layout::default(),
            "a",
            &[
                (0, 0, 100, 100),
                (300, 0, 400, 200),
                (600, 0, 650, 100),
                (650, 0, 700, 100),
                (500, 500, 600, 600),
                (600, 600, 700, 700),
                (1500, 0, 1700, 100),
                (1550, 0, 1650, 100),
                (2000, 0, 2100, 100),
                (2050, 0, 2150, 100),
            ],
        )
        .polygon(
            "a",
            &[
                (0, 500),
                (300, 500),
                (300, 600),
                (100, 600),
                (100, 800),
                (0, 800),
            ],
        ),
        "a",
        (1000, 0, 1300, 300),
        (1100, 100, 1200, 200),
    );
    every_placement(vec![derived(
        "derived/shape_class",
        &["DRC-005"],
        &["a"],
        &[
            (
                "a.rectangles()",
                areas(&[10_000, 20_000, 10_000, 20_000, 15_000]),
            ),
            ("a.non_rectangles()", areas(&[50_000, 20_000, 80_000])),
            ("a.squares()", areas(&[10_000, 10_000])),
            (
                "a.non_squares()",
                areas(&[20_000, 20_000, 15_000, 50_000, 20_000, 80_000]),
            ),
        ],
        layout,
    )])
}

/// `extended` on edge layers (DRC-122), `KLayout`'s `extended(begin, end,
/// out, in)`: a box round each edge, lengthened before its start and past
/// its end, widened away from its shape (`out`) and into it (`in`), one box
/// per edge, reported with its area.
///
/// On a 1000 x 500 rectangle's four edges: 100 out (two 1000 x 100 and two
/// 500 x 100 boxes), 50 in, and 100 at both ends with 10 either side (two
/// 1200 x 20, two 700 x 20); and the edge `a` butts `b` with, 100 out, which
/// lies in `b` (100 x 500). All eight symmetries. Which end is the start
/// depends on the edges' turning sense, which a mirror reverses, so the
/// `begin`/`end` cases run under rotations only: lengthened 100 at its start,
/// 10 out, the bottom edge reaches a 200 x 5 probe below the rectangle's
/// lower-left corner (100 x 5 inside it); lengthened at its end instead, only
/// the left edge does (10 x 5).
fn edge_extended() -> Vec<Fixture> {
    let cat = &["DRC-122"];
    let sides = derived(
        "derived/extended/sides",
        cat,
        &["a", "b"],
        &[
            (
                "a.edges().extended(begin: 0nm, end: 0nm, out: 100nm, in: 0nm)",
                areas(&[100_000, 100_000, 50_000, 50_000]),
            ),
            (
                "a.edges().extended(begin: 0nm, end: 0nm, out: 0nm, in: 50nm)",
                areas(&[50_000, 50_000, 25_000, 25_000]),
            ),
            (
                "a.edges().extended(begin: 100nm, end: 100nm, out: 10nm, in: 10nm)",
                areas(&[24_000, 24_000, 14_000, 14_000]),
            ),
            (
                "(a.edges() and b.edges()).extended(begin: 0nm, end: 0nm, out: 100nm, in: 0nm) \
                 and b",
                areas(&[50_000]),
            ),
        ],
        Layout::default()
            .rect("a", 0, 0, 1000, 500)
            .rect("b", 1000, 0, 1500, 500),
    );
    let ends = derived(
        "derived/extended/ends",
        cat,
        &["a", "b"],
        &[
            (
                "a.edges().extended(begin: 100nm, end: 0nm, out: 10nm, in: 0nm) and b",
                areas(&[500]),
            ),
            (
                "a.edges().extended(begin: 0nm, end: 100nm, out: 10nm, in: 0nm) and b",
                areas(&[50]),
            ),
        ],
        Layout::default()
            .rect("a", 0, 0, 1000, 500)
            .rect("b", -200, -5, 0, 0),
    );
    let mut out = every_placement(vec![sides]);
    for symmetry in Symmetry::ALL.into_iter().filter(|s| !s.mirror) {
        for &(dx, dy) in &OFFSETS {
            out.push(ends.transformed(symmetry, dx, dy));
        }
    }
    out
}

/// A feature's length, the longer side of its bounding box (DRC-021: sky130
/// mf.2 "length of fuse", IHP Rsil.f "min. RES length"), and its shorter
/// side: `with_bbox_max` and `with_bbox_min`, each shape reported with its
/// area.
///
/// Oracle: boxes fixed by construction: bars 499, 500 and 501 long against
/// bounds at 500 (strict and `==`); a 500 bar drawn as two abutting halves
/// (250 each unmerged); an L of two 100-wide arms in a 500 square box (its
/// arms are not its box); a 50 x 500 bar under `with_bbox_min(< 100nm)`.
fn feature_length() -> Vec<Fixture> {
    let layout = rects(
        Layout::default(),
        "a",
        &[
            (0, 0, 100, 499),
            (300, 0, 400, 500),
            (600, 0, 700, 501),
            (900, 0, 1000, 250),
            (900, 250, 1000, 500),
            (1200, 0, 1700, 100),
            (1200, 100, 1300, 500),
            (2000, 0, 2050, 500),
        ],
    );
    every_placement(vec![derived(
        "derived/feature_length",
        &["DRC-021"],
        &["a"],
        &[
            ("a.with_bbox_max(< 500nm)", areas(&[49_900])),
            ("a.with_bbox_max(> 500nm)", areas(&[50_100])),
            (
                "a.with_bbox_max(== 500nm)",
                areas(&[50_000, 50_000, 90_000, 25_000]),
            ),
            ("a.with_bbox_min(< 100nm)", areas(&[25_000])),
        ],
        layout,
    )])
}

/// Room for a rectangle (DRC-130, Calibre `ENCLOSE RECTANGLE`):
/// `with_rect(300nm x 100nm)`, `without_rect(300nm x 100nm)` and
/// `without_rect(100nm x 100nm)`, each shape reported with its area.
///
/// Oracle: boxes fixed by construction, the box's sides swept a grid step:
/// a 300 x 100 bar (holds it, at the limit), 299 x 100 and 300 x 99 (do not),
/// a 100 x 300 bar (holds it turned); an L of 50-wide arms in a 300 square
/// box (a bounding-box reading says it holds); the bar drawn as two abutting
/// 150 halves (holds, merged); a 400 square ring with 100 walls (its band
/// holds); two 200 x 60 bars overlapping in a stagger whose box is 300 x 100
/// (holds no 300 x 100 box, but a 100 square across the overlap).
fn enclose_rect() -> Vec<Fixture> {
    let layout = ring(
        rects(
            Layout::default(),
            "a",
            &[
                (0, 0, 300, 100),
                (1000, 0, 1299, 100),
                (2000, 0, 2300, 99),
                (3000, 0, 3100, 300),
                (4000, 0, 4300, 50),
                (4000, 50, 4050, 300),
                (5000, 0, 5150, 100),
                (5150, 0, 5300, 100),
                (7000, 0, 7200, 60),
                (7100, 40, 7300, 100),
            ],
        ),
        "a",
        (6000, 0, 6400, 400),
        (6100, 100, 6300, 300),
    );
    every_placement(vec![derived(
        "derived/enclose_rect",
        &["DRC-130"],
        &["a"],
        &[
            (
                "a.with_rect(300nm x 100nm)",
                areas(&[30_000, 30_000, 30_000, 120_000]),
            ),
            (
                "a.without_rect(300nm x 100nm)",
                areas(&[29_900, 29_700, 27_500, 22_000]),
            ),
            ("a.without_rect(100nm x 100nm)", areas(&[29_700, 27_500])),
        ],
        layout,
    )])
}

/// Edge layers (DRC-122): `.edges()` (a rectangle, the same drawn as two
/// abutting halves, an L, a ring's outer and inner edges, an outline with a
/// redundant collinear vertex); edge `and`, `not` and `or` on two butting
/// rectangles and on two whose shapes share edges on the same side;
/// `inside_part` and `outside_part`, with the part on the other layer's
/// boundary in neither; edge `interacting`, touching and lying wholly inside;
/// and `with_length` across its bounds. Each edge is reported with its
/// length.
fn edge_operations() -> Vec<Fixture> {
    let cat = &["DRC-122"];
    let mut cases = Vec::new();
    for (name, layout, edges) in [
        (
            "rect",
            Layout::default().rect("a", 0, 0, 300, 100),
            lengths(&[300, 100, 300, 100]),
        ),
        (
            "abutting_halves",
            Layout::default()
                .rect("a", 0, 0, 150, 100)
                .rect("a", 150, 0, 300, 100),
            lengths(&[300, 100, 300, 100]),
        ),
        (
            "l_shape",
            Layout::default().polygon(
                "a",
                &[
                    (0, 0),
                    (1000, 0),
                    (1000, 200),
                    (200, 200),
                    (200, 1000),
                    (0, 1000),
                ],
            ),
            lengths(&[1000, 200, 800, 800, 200, 1000]),
        ),
        (
            "ring",
            ring(
                Layout::default(),
                "a",
                (0, 0, 1000, 1000),
                (300, 300, 700, 700),
            ),
            lengths(&[1000, 1000, 1000, 1000, 400, 400, 400, 400]),
        ),
        (
            "collinear_vertex",
            Layout::default().polygon("a", &[(0, 0), (400, 0), (1000, 0), (1000, 100), (0, 100)]),
            lengths(&[1000, 100, 1000, 100]),
        ),
    ] {
        cases.push(derived(
            &format!("derived/edges/{name}"),
            cat,
            &["a"],
            &[("a.edges()", edges)],
            layout,
        ));
    }
    cases.push(derived(
        "derived/edge_booleans",
        cat,
        &["a", "b"],
        &[
            ("a.edges() and b.edges()", lengths(&[200])),
            ("a.edges() not b.edges()", lengths(&[500, 100, 500, 300])),
            (
                "a.edges() or b.edges()",
                lengths(&[500, 300, 500, 300, 500, 300, 500, 100]),
            ),
        ],
        Layout::default()
            .rect("a", 0, 0, 500, 300)
            .rect("b", 500, -100, 1000, 200),
    ));
    // `b` inside `a` along its left side: edges that coincide with their
    // shapes on the same side.
    cases.push(derived(
        "derived/edge_booleans_same_side",
        cat,
        &["a", "b"],
        &[
            ("a.edges() and b.edges()", lengths(&[1000, 500, 500])),
            ("a.edges() not b.edges()", lengths(&[500, 500, 1000])),
            ("a.edges() or b.edges()", lengths(&[1000; 5])),
        ],
        Layout::default()
            .rect("a", 0, 0, 1000, 1000)
            .rect("b", 0, 0, 500, 1000),
    ));
    cases.push(derived(
        "derived/edge_interacting_within",
        cat,
        &["a", "b"],
        &[
            ("a.edges().interacting(b)", lengths(&[200; 4])),
            ("a.edges().not_interacting(b)", vec![]),
        ],
        Layout::default()
            .rect("a", 400, 400, 600, 600)
            .rect("b", 0, 0, 1000, 1000),
    ));
    let bar = || Layout::default().rect("a", 0, 0, 1000, 100);
    for (name, b, inside) in [
        ("crossing", (300, -100, 600, 200), lengths(&[300, 300])),
        ("on_boundary", (300, 0, 600, 100), vec![]),
    ] {
        cases.push(derived(
            &format!("derived/edge_parts/{name}"),
            cat,
            &["a", "b"],
            &[
                ("a.edges().inside_part(b)", inside),
                (
                    "a.edges().outside_part(b)",
                    lengths(&[300, 400, 300, 400, 100, 100]),
                ),
            ],
            bar().rect("b", b.0, b.1, b.2, b.3),
        ));
    }
    cases.push(derived(
        "derived/edge_interacting",
        cat,
        &["a", "b"],
        &[
            ("a.edges().interacting(b)", lengths(&[1000])),
            ("a.edges().not_interacting(b)", lengths(&[1000, 100, 100])),
        ],
        bar().rect("b", 400, 100, 600, 300),
    ));
    cases.push(derived(
        "derived/with_length",
        cat,
        &["a"],
        &[
            ("a.edges().with_length(== 100nm)", lengths(&[100, 100])),
            (
                "a.edges().with_length(> 100nm, <= 300nm)",
                lengths(&[300, 300]),
            ),
            ("a.edges().with_length(< 100nm)", vec![]),
        ],
        Layout::default().rect("a", 0, 0, 300, 100),
    ));
    every_placement(cases)
}
