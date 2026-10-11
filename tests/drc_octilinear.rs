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
    let deck = format!("grid 1nm\nlayer met1 = gds(68, 20)\n{rules}");
    let mut strings = StrTable::default();
    let deck = parse_deck(&deck, grid(), &mut strings).unwrap_or_else(|why| panic!("{why}"));
    let met1 = deck.layers.id(&strings, "met1").expect("declared");
    let mut layout = LayoutBuilder::new(deck.layers.len());
    for ring in rings {
        let (xs, ys): (Vec<i64>, Vec<i64>) = ring.iter().copied().unzip();
        layout.push(met1, &xs, &ys);
    }
    let (base, _) = layout.finish();
    let mut bytes = Vec::new();
    write_store(&base, &deck.layers, "TOP", &mut bytes).expect("writable");
    let library = gds::Library::parse(&bytes, &mut strings).expect("parses");
    let (store, provenance) = library
        .flatten(&deck, &strings, UnknownLayers::Reject)
        .expect("reads back");
    let loaded = Loaded {
        strings,
        grid: grid(),
        deck,
        store,
        provenance,
        reference: None,
        intent: None,
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

/// A 45-degree bar 100 long between the lines `y = x + c` and `y = x + c +
/// d`, its ends cut by a step (one horizontal and one vertical edge), so
/// every corner is 90 or 135 degrees and none is an acute tip. Its width is
/// `d/√2`.
fn bar(c: i64, d: i64) -> Vec<(i64, i64)> {
    let s = d / 2;
    vec![
        (0, c),
        (100, 100 + c),
        (100, 100 + c + d - s),
        (100 - s, 100 + c + d - s),
        (-s, c + d - s),
        (-s, c),
    ]
}

/// Oracle: hand-derived. The bar between `y = x` and `y = x + 7` is `7/√2 =
/// √24.5 ≈ 4.95` wide: `width >= 5nm` flags it at 4 (floored), `width >=
/// 4nm` passes. A width squared and rounded up (25) would pass at 5. The bar
/// between `y = x` and `y = x + 283` is `200.1` wide: clean at 200, 200 at
/// 201.
#[test]
fn a_45_degree_bar_is_as_wide_as_its_perpendicular() {
    let found = run(
        "rule w5 width(met1) >= 5nm\nrule w4 width(met1) >= 4nm",
        &[bar(0, 7)],
    );
    assert_eq!(found.outcome("w5"), Outcome::Ran);
    assert_eq!(found.of("w5"), [(len(4), len(5))]);
    assert!(found.of("w4").is_empty());
    let found = run(
        "rule w200 width(met1) >= 200nm\nrule w201 width(met1) >= 201nm",
        &[bar(0, 283)],
    );
    assert!(found.of("w200").is_empty());
    assert_eq!(found.of("w201"), [(len(200), len(201))]);
}

/// Oracle: hand-derived. Bars between `y = x .. x + 10` and `y = x + 17 ..
/// x + 27` are `7/√2 ≈ 4.95` apart, the nearest any two of their points come
/// (two parallel strips): `space >= 5nm` flags them at 4, `>= 4nm` passes.
/// IHP M1.i measures the space of 45-degree lines this way (Euclidean).
#[test]
fn two_45_degree_bars_are_as_far_apart_as_their_lines() {
    let found = run(
        "rule s5 space(met1) >= 5nm\nrule s4 space(met1) >= 4nm",
        &[bar(0, 10), bar(17, 10)],
    );
    assert_eq!(found.outcome("s5"), Outcome::Ran);
    assert_eq!(found.of("s5"), [(len(4), len(5))]);
    assert!(found.of("s4").is_empty());
}

/// Oracle: the 45-degree law, construct-from-answer. A U with arms 100 wide,
/// a base 50 tall and a slot 100 wide, turned by `(x, y) -> (x - y, x + y)`
/// (45 degrees, every length times `√2`): width `50·√2 ≈ 70.7`, notch
/// `100·√2 ≈ 141.4`. Each rule flags it one unit above the floor and passes
/// at the floor.
#[test]
fn a_turned_u_has_its_width_and_notch_times_root_two() {
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
    let turned: Vec<(i64, i64)> = u.iter().map(|&(x, y)| (x - y, x + y)).collect();
    let found = run(
        "rule w71 width(met1) >= 71nm\nrule w70 width(met1) >= 70nm\n\
         rule n142 notch(met1) >= 142nm\nrule n141 notch(met1) >= 141nm",
        &[turned],
    );
    assert_eq!(found.of("w71"), [(len(70), len(71))]);
    assert!(found.of("w70").is_empty());
    assert_eq!(found.of("n142"), [(len(141), len(142))]);
    assert!(found.of("n141").is_empty());
}

/// Oracle: hand-derived. The right triangle with legs 9 has area 40.5: `area
/// >= 41nm2` flags it at 40 (floored), `>= 40nm2` passes. A diamond of radius
/// 10 has four edges `10·√2 ≈ 14.14` long: `edge_length >= 15nm` flags all
/// four at 14, `>= 14nm` none.
#[test]
fn half_unit_areas_and_diagonal_edge_lengths_compare_exactly() {
    let found = run(
        "rule a41 area(met1) >= 41nm2\nrule a40 area(met1) >= 40nm2",
        &[vec![(0, 0), (9, 0), (0, 9)]],
    );
    assert_eq!(found.of("a41"), [(area(40), area(41))]);
    assert!(found.of("a40").is_empty());
    let found = run(
        "rule e15 edge_length(met1) >= 15nm\nrule e14 edge_length(met1) >= 14nm",
        &[vec![(10, 0), (0, 10), (-10, 0), (0, -10)]],
    );
    assert_eq!(found.of("e15"), vec![(len(14), len(15)); 4]);
    assert!(found.of("e14").is_empty());
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

/// Oracle: the rule's documented scope (`docs/limitations.md`): a kind not yet
/// proved on 45-degree geometry records `Refused` on such a layer, never a
/// clean `Ran`.
#[test]
fn a_kind_not_proved_on_45_degree_edges_still_refuses_them() {
    let found = run("rule p prl_space(met1; prl: 50nm) >= 20nm", &[bar(0, 10)]);
    assert_eq!(found.outcome("p"), Outcome::Refused);
}
