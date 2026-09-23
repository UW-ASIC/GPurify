//! Rules `pdks/sky130.deck` states from the SKY130 periphery manual, each drawn
//! by hand at the manual's limit and one grid step (5 nm) inside it.
//!
//! Oracle: the manual's own number. Each pass layout sits exactly on the limit
//! the manual states, so a rule that measured one step wrong, or read the wrong
//! derived layer, flips one of the two cases. The pass case also asserts the
//! rule ran over at least one shape: a rule that examined nothing passes every
//! layout.

use gpurify::check::drc::RuleSet;
use gpurify::check::report::{Outcome, RuleRun, Violations};
use gpurify::check::topology::device::recognise_into;
use gpurify::check::topology::{extract_nets_into, DeviceTable, NetTable};
use gpurify_geom::{GeometryStore, Grid, LayerId};
use gpurify_ingest::deck::{parse_deck, Deck};
use gpurify_ingest::layout::{gds, UnknownLayers};
use gpurify_ingest::StrTable;
use gpurify_testgen::gds::write_store;
use gpurify_testgen::shapes::LayoutBuilder;

/// One nanometre per database unit.
fn grid() -> Grid {
    Grid::new(1_000).expect("1000 database units per micrometre is a legal grid")
}

fn sky130() -> (Deck, StrTable) {
    let source = include_str!("../pdks/sky130.deck");
    let mut strings = StrTable::default();
    let deck = parse_deck(source, grid(), &mut strings).expect("pdks/sky130.deck parses");
    (deck, strings)
}

/// Draw rectangles `(layer, xlo, ylo, xhi, yhi)` and derive the deck's layers
/// by writing GDSII and reading it back.
fn draw(deck: &Deck, strings: &StrTable, rects: &[(&str, i64, i64, i64, i64)]) -> GeometryStore {
    let mut layout = LayoutBuilder::new(deck.layers.len());
    for &(name, xlo, ylo, xhi, yhi) in rects {
        let layer: LayerId = deck
            .layers
            .id(strings, name)
            .unwrap_or_else(|| panic!("sky130.deck declares no layer {name}"));
        layout.rect(layer, xlo, ylo, xhi, yhi);
    }
    let (base, _) = layout.finish();

    let mut bytes = Vec::new();
    write_store(&base, &deck.layers, "TOP", &mut bytes).expect("base geometry is writable");
    {
        let mut texts = StrTable::default();
        let library = gds::Library::parse(&bytes, &mut texts).expect("the library parses");
        library.flatten(deck, &texts, UnknownLayers::Reject)
    }
    .expect("the layout reads back")
    .0
}

/// Run the DRC set over `rects` and return the violation count and runs of
/// rule `id`.
fn run(id: &str, rects: &[(&str, i64, i64, i64, i64)]) -> (u32, Vec<RuleRun>) {
    let (deck, strings) = sky130();
    let store = draw(&deck, &strings, rects);
    let rules = RuleSet::from_deck(&deck, &strings).expect("the DRC set builds");
    let (mut out, mut runs) = (Violations::default(), Vec::new());
    rules.run(&store, &mut out, &mut runs);

    let mine: Vec<RuleRun> = runs
        .into_iter()
        .filter(|r| strings.resolve(r.rule) == id)
        .collect();
    assert!(!mine.is_empty(), "sky130.deck has no rule {id}");
    let count = mine.iter().map(|r| r.violations).sum();
    (count, mine)
}

/// `rects` passes rule `id` and the rule examined something; `failing` does not.
fn at_limit(
    id: &str,
    passing: &[(&str, i64, i64, i64, i64)],
    failing: &[(&str, i64, i64, i64, i64)],
) {
    let (count, runs) = run(id, passing);
    assert!(
        runs.iter()
            .all(|r| r.outcome == Outcome::Ran && r.examined > 0),
        "{id} did not run over the passing layout: {runs:?}"
    );
    assert_eq!(
        count, 0,
        "{id} flags a layout exactly at the manual's limit"
    );
    let (count, _) = run(id, failing);
    assert!(
        count > 0,
        "{id} passes a layout 5 nm inside the manual's limit"
    );
}

/// licon.5a: enclosure of licon by diff, 0.040 um.
#[test]
fn licon_5a_diff_encloses_licon_by_40nm() {
    let base = [("diff", 0, 0, 1000, 500), ("nsdm", -200, -200, 1200, 700)];
    let pass = [base[0], base[1], ("licon", 40, 165, 210, 335)];
    let fail = [base[0], base[1], ("licon", 35, 165, 205, 335)];
    at_limit("licon.5a", &pass, &fail);
}

/// licon.14: spacing of `poly_licon` to diff or tap, 0.190 um.
#[test]
fn licon_14_poly_licon_to_diff_190nm() {
    let base = [("poly", 0, 0, 500, 500), ("licon", 165, 165, 335, 335)];
    let pass = [base[0], base[1], ("diff", 525, 0, 1000, 500)];
    let fail = [base[0], base[1], ("diff", 520, 0, 1000, 500)];
    at_limit("licon.14", &pass, &fail);
}

/// npc.4: spacing, no overlap, of npc to gate, 0.090 um.
#[test]
fn npc_4_npc_to_gate_90nm() {
    let base = [("diff", 0, 0, 1000, 420), ("poly", 400, -200, 550, 620)];
    let pass = [base[0], base[1], ("npc", 640, 0, 1000, 420)];
    let fail = [base[0], base[1], ("npc", 635, 0, 1000, 420)];
    at_limit("npc.4", &pass, &fail);
}

/// difftap.10: enclosure of n+ tap by n-well, 0.180 um.
#[test]
fn difftap_10_nwell_encloses_ntap_by_180nm() {
    let base = [("tap", 0, 0, 500, 500), ("nsdm", -130, -130, 630, 630)];
    let pass = [base[0], base[1], ("nwell", -180, -180, 680, 680)];
    let fail = [base[0], base[1], ("nwell", -175, -180, 680, 680)];
    at_limit("difftap.10", &pass, &fail);
}

/// rpm.6: spacing, no overlap, of rpm to nsdm, 0.200 um.
#[test]
fn rpm_6_rpm_to_nsdm_200nm() {
    let pass = [("rpm", 0, 0, 2000, 2000), ("nsdm", 2200, 0, 3000, 1000)];
    let fail = [("rpm", 0, 0, 2000, 2000), ("nsdm", 2195, 0, 3000, 1000)];
    at_limit("rpm.6", &pass, &fail);
}

/// poly.3: minimum poly resistor width (poly under `poly_rs`), 0.330 um.
#[test]
fn poly_3_poly_resistor_width_330nm() {
    let pass = [("poly", 0, 0, 330, 2000), ("poly_rs", -100, 500, 430, 1500)];
    let fail = [("poly", 0, 0, 325, 2000), ("poly_rs", -100, 500, 430, 1500)];
    at_limit("poly.3", &pass, &fail);
}

/// The models recognised in `rects`, each with its terminal nets.
fn devices(rects: &[(&str, i64, i64, i64, i64)]) -> Vec<(String, Vec<u32>)> {
    let (deck, strings) = sky130();
    let store = draw(&deck, &strings, rects);
    let (mut nets, mut table) = (NetTable::default(), DeviceTable::default());
    extract_nets_into(&store, &deck.connectivity, &mut nets);
    recognise_into(&store, &nets, &deck.devices, &mut table);
    (0..table.kind.len())
        .map(|row| {
            let span = table.terminal_start[row] as usize..table.terminal_start[row + 1] as usize;
            let terminals = table.terminal_net[span].iter().map(|n| n.0).collect();
            (strings.resolve(table.model[row]).to_owned(), terminals)
        })
        .collect()
}

/// A 1.8 V nfet is one device whose gate, source and drain are three nets:
/// the gate is on poly, source and drain are the n+ diffusion either side.
#[test]
fn a_plain_nfet_extracts_as_nfet_01v8_with_three_nets() {
    let found = devices(&[
        ("diff", 0, 0, 1000, 420),
        ("nsdm", -125, -125, 1125, 545),
        ("poly", 425, -130, 575, 550),
    ]);
    assert_eq!(found.len(), 1, "{found:?}");
    let (model, nets) = &found[0];
    assert_eq!(model, "sky130_fd_pr__nfet_01v8");
    assert_eq!(nets.len(), 3);
    assert!(
        nets[0] != nets[1] && nets[1] != nets[2] && nets[0] != nets[2],
        "{nets:?}"
    );
}

/// A generic poly resistor: the body under `poly_rs` is cut out of the poly
/// conductor, so the two heads are two nets.
#[test]
fn a_poly_resistor_has_two_distinct_heads() {
    let found = devices(&[
        ("poly", 0, 0, 330, 3000),
        ("poly_rs", -100, 1000, 430, 2000),
    ]);
    assert_eq!(found.len(), 1, "{found:?}");
    let (model, nets) = &found[0];
    assert_eq!(model, "sky130_fd_pr__res_generic_po");
    assert_eq!(nets.len(), 2);
    assert_ne!(nets[0], nets[1], "the resistor's heads are shorted");
}
