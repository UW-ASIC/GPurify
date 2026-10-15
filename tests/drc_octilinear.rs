//! The DRC kinds proved on 45-degree geometry (H12, DRC-038), end to end:
//! deck text, a layout written as GDSII and read back, and the DRC stage.
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
/// that read it. A triangle with an edge of slope 1/2 (neither axis nor 45
/// degrees) on met1 makes `met1.sized(10nm)` and everything built on it
/// uncomputable; the rule on that layer records `Refused`, a rule on met2
/// reports as usual, and the load does not fail.
///
/// Oracle: the scope the H12 brief states (refusal limited to the rules that
/// read the layer) and a hand-derived width: the met2 bar is 50 wide.
#[test]
fn an_uncomputable_derived_layer_refuses_only_its_rules() {
    let found = run_on(
        "layer fat = met1.sized(10nm)\nlayer fatter = fat.sized(10nm)\n\
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
