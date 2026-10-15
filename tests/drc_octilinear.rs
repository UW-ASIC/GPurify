//! The DRC kinds proved on 45-degree geometry (H12, DRC-038) and on edges at
//! any angle (DRC-116), end to end: deck text, a layout written as GDSII and
//! read back, and the DRC stage.
//!
//! Oracle throughout: construct-from-answer on a 1 nm grid, each measurement
//! read off the coordinates by hand, each rule passing exactly at its
//! measurement and failing one unit above it. The shape a plausible wrong
//! implementation gets wrong is drawn on purpose: a 45-degree gap of `7/√2`
//! (`√24.5`, so 4.95), which a squared distance rounded up to 25 passes at a
//! limit of 5; IHP SG13G2 M1.g/M1.i are the foundry rules these measure.

use gpurify::engine::pipeline::{extract, Loaded};
use gpurify::engine::run::{run_checks, Checks, RunOptions};
use gpurify_check::lvs::CompareOptions;
use gpurify_check::report::{Measurement, Outcome};
use gpurify_geom::{Dbu, DbuArea, Grid};
use gpurify_ingest::deck::parse_deck;
use gpurify_ingest::layout::{gds, UnknownLayers};
use gpurify_ingest::StrTable;
use gpurify_testgen::gds::write_store;
use gpurify_testgen::shapes::LayoutBuilder;
fn grid() -> Grid {
    Grid::new(1_000).expect("a 1 nm grid")
}

/// Each rule's findings as `(measured, limit)`, and each rule's outcome.
struct Found {
    findings: Vec<(String, Measurement, Measurement)>,
    outcomes: Vec<(String, Outcome)>,
}

impl Found {
    fn of(&self, rule: &str) -> Vec<(Measurement, Measurement)> {
        self.findings
            .iter()
            .filter(|f| f.0 == rule)
            .map(|f| (f.1, f.2))
            .collect()
    }

    fn outcome(&self, rule: &str) -> Outcome {
        self.outcomes
            .iter()
            .find(|(id, _)| id == rule)
            .unwrap_or_else(|| panic!("no run row for {rule}"))
            .1
    }
}

/// Parse `rules` under one layer `met1`, draw `rings` on it, round trip
/// through GDSII, extract, and run the DRC stage.
fn run(rules: &str, rings: &[Vec<(i64, i64)>]) -> Found {
    let on_met1: Vec<(&str, Vec<(i64, i64)>)> = rings.iter().map(|r| ("met1", r.clone())).collect();
    run_on(rules, &on_met1)
}

/// [`run`] with `met2` declared too, each ring drawn on the layer it names.
fn run_on(rules: &str, rings: &[(&str, Vec<(i64, i64)>)]) -> Found {
    let deck = format!("grid 1nm\nlayer met1 = gds(68, 20)\nlayer met2 = gds(69, 20)\n{rules}");
    let mut strings = StrTable::default();
    let deck = parse_deck(&deck, grid(), &mut strings).unwrap_or_else(|why| panic!("{why}"));
    let mut layout = LayoutBuilder::new(deck.layers.len());
    for (name, ring) in rings {
        let layer = deck.layers.id(&strings, name).expect("declared");
        let (xs, ys): (Vec<i64>, Vec<i64>) = ring.iter().copied().unzip();
        layout.push(layer, &xs, &ys);
    }
    let (base, _) = layout.finish();
    let mut bytes = Vec::new();
    write_store(&base, &deck.layers, "TOP", &mut bytes).expect("writable");
    let library = gds::Library::parse(&bytes, &mut strings).expect("parses");
    let (store, provenance) = library
        .flatten(&deck, &strings, UnknownLayers::Reject)
        .expect("reads back");
    let deck =
        gpurify::deck::CompiledDeck::from_deck(deck, grid(), &strings).expect("the deck compiles");
    let loaded = Loaded {
        strings,
        grid: grid(),
        deck,
        store,
        provenance,
        reference: None,
        intent: None,
        design: None,
    };
    let extracted = extract(&loaded).expect("extracts");
    let options = RunOptions {
        checks: Checks {
            drc: true,
            erc: false,
            lvs: false,
            pex: false,
        },
        lvs: CompareOptions::default(),
        quasistatic_nets: Vec::new(),
    };
    let (out, _) = run_checks(&loaded, &extracted, &options).expect("the deck builds");
    let name = |id| loaded.strings.resolve(id).to_owned();
    let v = &out.violations;
    Found {
        findings: (0..v.len())
            .map(|i| (name(v.rule[i]), v.measured[i], v.limit[i]))
            .collect(),
        outcomes: out.runs.iter().map(|r| (name(r.rule), r.outcome)).collect(),
    }
}

fn len(v: i64) -> Measurement {
    Measurement::Length(Dbu::new_unchecked(v))
}

fn area(v: i128) -> Measurement {
    Measurement::Area(DbuArea::new(v))
}

/// A 45-degree bar between the lines `y = x + c` and `y = x + c + d`, 1000
/// long in x, each end inside a pad 1010 wide: its narrowest width is the
/// bar's own. A bar's end on its own is narrower, a short side and the far
/// 45-degree edge being a width pair at 135 degrees (`KLayout`'s Euclidean
/// `width`); the pads meet the bar at concave corners only.
fn padded(c: i64, d: i64) -> [Vec<(i64, i64)>; 3] {
    let pad = |x0: i64, x1: i64, y0: i64, y1: i64| vec![(x0, y0), (x1, y0), (x1, y1), (x0, y1)];
    [
        vec![(0, c), (1000, 1000 + c), (1000, 1000 + c + d), (0, c + d)],
        pad(-1000, 10, c - 1000, c + d + 1010),
        pad(990, 2000, c - 10, 2000 + c + d),
    ]
}

/// N-f2-3: a 45-degree shape feeding derived layers no longer refuses the
/// whole layout. Two derived layers are computed from a right triangle on
/// met1 (`sized`, `with_width`): `width` and `forbidden` on them run, a kind
/// not yet proved on 45-degree edges (maximum width) refuses alone, and a
/// rule on met2 reports as it would without the triangle.
///
/// Oracle: hand-derived. The triangle grown by the 10 square has no acute
/// corner (its tips gain a vertical or horizontal side), and every width is
/// over 5; the triangle's acute tips make its width 0, so `with_width(< 1nm)`
/// holds it, area `100·100/2 = 5000`; the met2 bar is 50 wide against 100.
#[test]
fn a_45_degree_shape_scopes_its_refusal_to_the_rules_that_read_it() {
    let found = run_on(
        "layer fat = met1.sized(10nm)\nlayer slim = met1.with_width(< 1nm)\n\
         rule wf width(fat) >= 5nm\nrule mf width(fat) <= 1000nm\n\
         rule fs forbidden(slim)\nrule w2 width(met2) >= 100nm",
        &[
            ("met1", vec![(0, 0), (100, 0), (0, 100)]),
            ("met2", vec![(500, 0), (550, 0), (550, 1000), (500, 1000)]),
        ],
    );
    assert_eq!(found.outcome("wf"), Outcome::Ran);
    assert!(found.of("wf").is_empty());
    assert_eq!(found.outcome("mf"), Outcome::Refused);
    assert_eq!(found.of("fs"), [(area(5000), area(0))]);
    assert_eq!(found.outcome("w2"), Outcome::Ran);
    assert_eq!(found.of("w2"), [(len(50), len(100))]);
}

/// N-H12-1: a derived layer that cannot be computed refuses only the rules
/// that read it. `with_rect` reads a layer as rectangles, so a triangle with
/// an edge of slope 1/2 on met1 makes `met1.with_rect(10nm x 10nm)` and
/// everything built on it uncomputable (since DRC-116 `sized` itself takes
/// that edge); the rule on that layer records `Refused`, a rule on met2
/// reports as usual, and the load does not fail.
///
/// Oracle: the scope the H12 brief states (refusal limited to the rules that
/// read the layer) and a hand-derived width: the met2 bar is 50 wide.
#[test]
fn an_uncomputable_derived_layer_refuses_only_its_rules() {
    let found = run_on(
        "layer fat = met1.with_rect(10nm x 10nm)\nlayer fatter = fat.sized(10nm)\n\
         rule wf width(fatter) >= 5nm\nrule ef length(fat.edges()) >= 5nm\n\
         rule w2 width(met2) >= 100nm",
        &[
            ("met1", vec![(0, 0), (200, 0), (0, 100)]),
            ("met2", vec![(500, 0), (550, 0), (550, 1000), (500, 1000)]),
        ],
    );
    assert_eq!(found.outcome("wf"), Outcome::Refused);
    assert_eq!(found.outcome("ef"), Outcome::Refused);
    assert_eq!(found.outcome("w2"), Outcome::Ran);
    assert_eq!(found.of("w2"), [(len(50), len(100))]);
}

/// N-H12-2: a strict `with_width` bound is exact on a 45-degree width whose
/// square is a half unit. The bar between `y = x` and `y = x + 99` is
/// `99/√2 ≈ 70.004` wide (squared 4900.5): `> 70nm` holds it and `<= 70nm`
/// does not. Stored as `>= 70² + 1` it would be missed.
///
/// Oracle: hand-derived, `99² = 9801 = 2·4900 + 1`.
#[test]
fn a_strict_width_bound_is_exact_on_a_half_unit_square() {
    let found = run(
        "rule over forbidden(met1.with_width(> 70nm))\n\
         rule under forbidden(met1.with_width(<= 70nm))",
        &padded(0, 99),
    );
    assert_eq!(found.of("over").len(), 1);
    assert!(found.of("under").is_empty());
    assert_eq!(found.outcome("under"), Outcome::Ran);
}

/// Oracle: hand-derived. A 40 square with a diamond hole of radius 5 (area
/// `2·5² = 50`), written as one keyhole ring as GDSII does: `hole_area >=
/// 51nm2` flags the hole at 50, `>= 50nm2` passes.
#[test]
fn a_diamond_hole_is_measured() {
    let keyhole = vec![
        (0, 20),
        (0, 0),
        (40, 0),
        (40, 40),
        (0, 40),
        (0, 20),
        (15, 20),
        (20, 25),
        (25, 20),
        (20, 15),
        (15, 20),
    ];
    let found = run(
        "rule h51 hole_area(met1) >= 51nm2\nrule h50 hole_area(met1) >= 50nm2",
        &[keyhole],
    );
    assert_eq!(found.of("h51"), [(area(50), area(51))]);
    assert!(found.of("h50").is_empty());
}

// ---- Any angle (DRC-116) ----
//
// The point-to-line case a rounding-up implementation misses: the point
// (10, 7) lies `cross((5, 1), (10, 7)) / √26 = 25/√26` from the line through
// the origin along (5, 1), squared `625/26 ≈ 24.04`, so 4.90. A square
// rounded up to 25 reads 5 and passes a limit of 5.

/// A quadrilateral whose top edge runs from (25, 5) to (0, 0), along (5, 1).
fn slanted_base() -> Vec<(i64, i64)> {
    vec![(0, -10), (25, -5), (25, 5), (0, 0)]
}

/// A triangle whose lowest vertex is (10, 7), `25/√26` above [`slanted_base`].
fn tip_above() -> Vec<(i64, i64)> {
    vec![(10, 7), (20, 20), (0, 20)]
}

/// A rectangle along (5, 1), (0,0),(25,5),(22,20),(-3,15), with a V notch
/// cut from its top side down to (10, 7) between (12, 18) and (7, 17): its
/// narrowest width is from the V's tip to the bottom side.
fn notched_slab() -> Vec<(i64, i64)> {
    vec![
        (0, 0),
        (25, 5),
        (22, 20),
        (12, 18),
        (10, 7),
        (7, 17),
        (-3, 15),
    ]
}

/// DRC-116: space and width at any angle are exact fractions.
///
/// Oracle: hand-derived (the section note): the tip (10, 7) is `√(625/26)
/// ≈ 4.90` from the edge along (5, 1), the nearest the two shapes come (the
/// base's corner (25, 5) is `215/√269 ≈ 13.1` from the triangle), so
/// `space >= 5nm` flags it at 4 and `>= 4nm` passes; across two layers the
/// same. In [`notched_slab`] every corner is at least 90 degrees and every
/// other edge pair is farther (the V's tip from the left side `57/√26`, the
/// V's sides and the top side running apart), so `width >= 5nm` flags it at
/// 4 and `>= 4nm` passes.
#[test]
fn space_and_width_at_any_angle_compare_their_fractions_exactly() {
    let found = run(
        "rule s5 space(met1) >= 5nm\nrule s4 space(met1) >= 4nm",
        &[slanted_base(), tip_above()],
    );
    assert_eq!(found.outcome("s5"), Outcome::Ran);
    assert_eq!(found.of("s5"), [(len(4), len(5))]);
    assert!(found.of("s4").is_empty());
    let found = run_on(
        "rule d5 space(met1, met2) >= 5nm\nrule d4 space(met1, met2) >= 4nm",
        &[("met1", slanted_base()), ("met2", tip_above())],
    );
    assert_eq!(found.of("d5"), [(len(4), len(5))]);
    assert!(found.of("d4").is_empty());
    let found = run(
        "rule w5 width(met1) >= 5nm\nrule w4 width(met1) >= 4nm",
        &[notched_slab()],
    );
    assert_eq!(found.outcome("w5"), Outcome::Ran);
    assert_eq!(found.of("w5"), [(len(4), len(5))]);
    assert!(found.of("w4").is_empty());
}

/// DRC-116: area, hole area and edge length at any angle.
///
/// Oracle: hand-derived. The triangle (0,0),(3,1),(1,2) has area `|3·2 −
/// 1·1|/2 = 2.5`: `area >= 3nm2` flags it at 2 (floored), `>= 2nm2` passes.
/// A triangle of the same area as a hole in a 40-square (one keyhole ring):
/// `hole_area >= 3nm2` flags it at 2. The triangle (0,0),(4,1),(1,3) has
/// edges `√17 ≈ 4.12`, `√13 ≈ 3.61` and `√10 ≈ 3.16`: `edge_length >= 4nm`
/// flags two at 3, `>= 5nm` all three, at 4, 3, 3.
#[test]
fn areas_and_edge_lengths_at_any_angle_are_exact() {
    let found = run(
        "rule a3 area(met1) >= 3nm2\nrule a2 area(met1) >= 2nm2",
        &[vec![(0, 0), (3, 1), (1, 2)]],
    );
    assert_eq!(found.of("a3"), [(area(2), area(3))]);
    assert!(found.of("a2").is_empty());
    let keyhole = vec![
        (0, 20),
        (0, 0),
        (40, 0),
        (40, 40),
        (0, 40),
        (0, 20),
        (20, 20),
        (21, 22),
        (23, 21),
        (20, 20),
    ];
    let found = run(
        "rule h3 hole_area(met1) >= 3nm2\nrule h2 hole_area(met1) >= 2nm2",
        &[keyhole],
    );
    assert_eq!(found.of("h3"), [(area(2), area(3))]);
    assert!(found.of("h2").is_empty());
    let found = run(
        "rule e4 edge_length(met1) >= 4nm\nrule e5 edge_length(met1) >= 5nm",
        &[vec![(0, 0), (4, 1), (1, 3)]],
    );
    assert_eq!(found.of("e4"), vec![(len(3), len(4)); 2]);
    let mut e5 = found.of("e5");
    e5.sort_by_key(|f| format!("{f:?}"));
    assert_eq!(e5, [(len(3), len(5)), (len(3), len(5)), (len(4), len(5))]);
}

/// A host whose bottom edge runs along (5, 1) from (0, 0) to (25, 5).
fn slanted_host() -> (&'static str, Vec<(i64, i64)>) {
    ("met2", vec![(0, 0), (25, 5), (25, 30), (0, 30)])
}

/// DRC-116: enclosure at any angle, every side and non-coincident.
///
/// Oracle: hand-derived. The square (5..10, 7..12) in [`slanted_host`] has
/// its corner (10, 7) `25/√26 ≈ 4.90` from the slanted bottom (its corner
/// (5, 7) is `30/√26` from it, its left side 5 from the host's, its right
/// side 15, its top 18): `enclosure >= 5nm` flags it at 4, `>= 4nm` passes,
/// and so does the non-coincident reading, the square's bottom pairing with
/// the slanted bottom (more than 90 degrees between them as `KLayout` orients
/// them). Opposite measures by projection and refuses an edge at such an
/// angle.
#[test]
fn enclosure_at_any_angle_is_exact() {
    let square = ("met1", vec![(5, 7), (10, 7), (10, 12), (5, 12)]);
    let rules = "rule e5 enclosure(met1, met2) >= 5nm\nrule e4 enclosure(met1, met2) >= 4nm\n\
                 rule n5 enclosure(met1, met2, noncoincident) >= 5nm\n\
                 rule o5 enclosure(met1, met2, opposite) >= 5nm";
    let layout = [slanted_host(), square];
    let found = run_on(rules, &layout);
    assert_eq!(found.outcome("e5"), Outcome::Ran);
    assert_eq!(found.of("e5"), [(len(4), len(5))]);
    assert!(found.of("e4").is_empty());
    assert_eq!(found.of("n5"), [(len(4), len(5))]);
    assert_eq!(found.outcome("o5"), Outcome::Refused);
    holds_under_symmetries(rules, &layout);
}

/// DRC-116: every kind measured at any angle gives the same findings under
/// the eight symmetries of the grid.
///
/// Oracle: metamorphic, the symmetry law: a mirror or a quarter turn about
/// the origin maps the grid onto itself and keeps every distance and area,
/// and rounding a half away from zero commutes with it.
#[test]
fn the_any_angle_kinds_are_invariant_under_the_symmetries_of_the_grid() {
    let rules = "rule s5 space(met1) >= 5nm\nrule w5 width(met1) >= 5nm\n\
                 rule n5 notch(met1) >= 50nm\nrule a3 area(met1) >= 3nm2\n\
                 rule e4 edge_length(met1) >= 4nm\nrule i inside(met1, met2)\n\
                 rule c contains(met2, met1) >= 2";
    let shift = |ring: Vec<(i64, i64)>, dx: i64| -> Vec<(i64, i64)> {
        ring.into_iter().map(|(x, y)| (x + dx, y)).collect()
    };
    let layout = [
        ("met1", slanted_base()),
        ("met1", tip_above()),
        ("met1", shift(notched_slab(), 100)),
        ("met1", vec![(200, 0), (203, 1), (201, 2)]),
        ("met1", vec![(300, 0), (304, 1), (301, 3)]),
        ("met2", vec![(395, -5), (420, 0), (420, 30), (395, 30)]),
        ("met1", vec![(400, 7), (405, 7), (405, 12), (400, 12)]),
    ];
    holds_under_symmetries(rules, &layout);
}

/// DRC-116: the Pythagorean rotation law, end to end. `(x, y) → (3x − 4y,
/// 4x + 3y)` maps the grid into itself and every length times 5, so the U of
/// [`a_turned_u_has_its_width_and_notch_times_root_two`] (width 50, notch
/// 100, area 45000, three 100-long edges) turned so has width 250, notch
/// 500, area `25·45000` and three 500-long edges, every edge now along
/// (3, 4) or (−4, 3).
///
/// Oracle: construct-from-answer by the rotation law; each rule flags at the
/// turned value one unit above it and passes at it.
#[test]
fn a_pythagorean_turn_scales_every_measure_by_five() {
    let u = [
        (0, 0),
        (300, 0),
        (300, 200),
        (200, 200),
        (200, 50),
        (100, 50),
        (100, 200),
        (0, 200),
    ];
    let turned: Vec<(i64, i64)> = u
        .iter()
        .map(|&(x, y)| (3 * x - 4 * y, 4 * x + 3 * y))
        .collect();
    let found = run(
        "rule w251 width(met1) >= 251nm\nrule w250 width(met1) >= 250nm\n\
         rule n501 notch(met1) >= 501nm\nrule n500 notch(met1) >= 500nm\n\
         rule e501 edge_length(met1) >= 501nm\nrule e500 edge_length(met1) >= 500nm\n\
         rule a area(met1) >= 1125001nm2",
        &[turned],
    );
    assert_eq!(found.of("w251"), [(len(250), len(251))]);
    assert!(found.of("w250").is_empty());
    assert_eq!(found.of("n501"), [(len(500), len(501))]);
    assert!(found.of("n500").is_empty());
    assert_eq!(found.of("e501"), vec![(len(500), len(501)); 3]);
    assert!(found.of("e500").is_empty());
    assert_eq!(found.of("a"), [(area(1_125_000), area(1_125_001))]);
}

/// DRC-116: derived layers compute at any angle. `sized` grows a slanted
/// triangle by the box, and a boolean of two slanted shapes rounds its
/// crossings to the grid; rules on both run.
///
/// Oracle: hand-derived. The triangle (0,0),(30,10),(0,20) grown by the
/// 10-square is convex with no corner under 90 degrees and at least 20
/// across, so `width >= 5nm` passes; the triangle with its tip at (110, 0)
/// pokes below the slanted top of the quadrilateral (at x = 110 that top is
/// at y = 2), so `met1 and met2` holds one figure, which `forbidden`
/// reports.
#[test]
fn derived_layers_compute_at_any_angle() {
    let found = run_on(
        "layer fat = met1.sized(10nm)\nlayer both = met1 and met2\n\
         rule wf width(fat) >= 5nm\nrule fb forbidden(both)",
        &[
            ("met1", vec![(0, 0), (30, 10), (0, 20)]),
            ("met1", vec![(100, -10), (125, -5), (125, 5), (100, 0)]),
            ("met2", vec![(110, 0), (120, 17), (100, 17)]),
        ],
    );
    assert_eq!(found.outcome("wf"), Outcome::Ran);
    assert!(found.of("wf").is_empty());
    assert_eq!(found.outcome("fb"), Outcome::Ran);
    assert_eq!(found.of("fb").len(), 1);
}
