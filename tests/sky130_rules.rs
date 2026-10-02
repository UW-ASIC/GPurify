//! Rules `pdks/sky130.deck` states from the SKY130 periphery manual (and a few
//! from the gf180mcu and IHP SG13G2 decks), each drawn by hand at the manual's
//! limit and one grid step (5 nm) inside it.
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

const SKY130: &str = include_str!("../pdks/sky130.deck");
const GF180: &str = include_str!("../pdks/gf180mcu.deck");
const IHP: &str = include_str!("../pdks/ihp_sg13g2.deck");

fn sky130() -> (Deck, StrTable) {
    load(SKY130)
}

fn load(source: &str) -> (Deck, StrTable) {
    let mut strings = StrTable::default();
    let deck = parse_deck(source, grid(), &mut strings).expect("the shipped deck parses");
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
            .unwrap_or_else(|| panic!("the deck declares no layer {name}"));
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
fn run(source: &str, id: &str, rects: &[(&str, i64, i64, i64, i64)]) -> (u32, Vec<RuleRun>) {
    let (deck, strings) = load(source);
    let store = draw(&deck, &strings, rects);
    let rules = RuleSet::from_deck(&deck, &strings).expect("the DRC set builds");
    let (mut out, mut runs) = (Violations::default(), Vec::new());
    rules.run(&store, &mut out, &mut runs);

    let mine: Vec<RuleRun> = runs
        .into_iter()
        .filter(|r| strings.resolve(r.rule) == id)
        .collect();
    assert!(!mine.is_empty(), "the deck has no rule {id}");
    let count = mine.iter().map(|r| r.violations).sum();
    (count, mine)
}

/// `rects` passes sky130 rule `id` and the rule examined something; `failing` does not.
fn at_limit(
    id: &str,
    passing: &[(&str, i64, i64, i64, i64)],
    failing: &[(&str, i64, i64, i64, i64)],
) {
    at_limit_in(SKY130, id, passing, failing);
}

/// [`at_limit`] for the deck `source`.
fn at_limit_in(
    source: &str,
    id: &str,
    passing: &[(&str, i64, i64, i64, i64)],
    failing: &[(&str, i64, i64, i64, i64)],
) {
    let (count, runs) = run(source, id, passing);
    assert!(
        runs.iter()
            .all(|r| r.outcome == Outcome::Ran && r.examined > 0),
        "{id} did not run over the passing layout: {runs:?}"
    );
    assert_eq!(
        count, 0,
        "{id} flags a layout exactly at the manual's limit"
    );
    let (count, _) = run(source, id, failing);
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

/// A 1.8 V nfet is one device whose gate, source, drain and bulk are four
/// nets: the gate is on poly, source and drain are the n+ diffusion either
/// side, and the bulk is the substrate under it.
#[test]
fn a_plain_nfet_extracts_as_nfet_01v8_with_four_nets() {
    let found = devices(&[
        ("diff", 0, 0, 1000, 420),
        ("nsdm", -125, -125, 1125, 545),
        ("poly", 425, -130, 575, 550),
    ]);
    assert_eq!(found.len(), 1, "{found:?}");
    let (model, nets) = &found[0];
    assert_eq!(model, "sky130_fd_pr__nfet_01v8");
    assert_eq!(nets.len(), 4);
    let mut distinct = nets.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), 4, "{nets:?}");
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

/// difftap.4: min tap bound by one diffusion, the butting edge, 0.290 um.
#[test]
fn difftap_4_butting_edge_290nm() {
    let pass = [("diff", 0, 0, 1000, 500), ("tap", 1000, 0, 1500, 290)];
    let fail = [("diff", 0, 0, 1000, 500), ("tap", 1000, 0, 1500, 285)];
    at_limit("difftap.4", &pass, &fail);
}

/// nsd.5a on a diff butting a tap: enclosure by nsdm of every edge but the
/// butting one, 0.125 um. The nsdm stops at the butting edge.
#[test]
fn nsd_5a_butted_diff_enclosed_by_125nm() {
    let base = [("diff", 0, 0, 1000, 500), ("tap", 1000, 0, 1300, 500)];
    let pass = [base[0], base[1], ("nsdm", -125, -125, 1000, 625)];
    let fail = [base[0], base[1], ("nsdm", -120, -125, 1000, 625)];
    at_limit("nsd.5a.butted", &pass, &fail);
}

/// m1.3a: spacing of met1 attached to huge met1 within 0.28 um, 0.280 um. The
/// line is 280 above the plate and 280 beside the finger's attached part.
#[test]
fn m1_3a_attached_to_huge_metal_280nm() {
    let base = [("met1", 0, 0, 4000, 4000), ("met1", 1000, 4000, 1140, 5000)];
    let pass = [base[0], base[1], ("met1", 1420, 4280, 1560, 4600)];
    let fail = [base[0], base[1], ("met1", 1415, 4280, 1560, 4600)];
    at_limit("m1.3a", &pass, &fail);
}

/// licon.16: every tap encloses a licon; one touching the tap's edge from
/// inside is enclosed, one 5 nm across it is not.
#[test]
fn licon_16_tap_encloses_a_licon() {
    let pass = [("tap", 0, 0, 500, 500), ("licon", 330, 165, 500, 335)];
    let fail = [("tap", 0, 0, 500, 500), ("licon", 335, 165, 505, 335)];
    at_limit("licon.16", &pass, &fail);
}

/// gf180 DF.11: min length of a butting COMP edge (N+ COMP to P+ COMP), 0.3 um.
#[test]
fn gf180_df_11_butting_comp_edge_300nm() {
    let implants = [
        ("nplus", -100, -100, 1000, 400),
        ("pplus", 1000, -100, 2100, 400),
    ];
    let pass = [implants[0], implants[1], ("comp", 0, 0, 2000, 300)];
    let fail = [implants[0], implants[1], ("comp", 0, 0, 2000, 295)];
    at_limit_in(GF180, "DF.11", &pass, &fail);
}

/// IHP M1.e: 0.22 um between Metal1 lines when one is wider than 0.3 um and
/// they run alongside for more than 1 um.
#[test]
fn ihp_m1_e_wide_line_long_run_220nm() {
    let wide = ("metal1", 0, 0, 305, 1005);
    let pass = [wide, ("metal1", 525, 0, 725, 1005)];
    let fail = [wide, ("metal1", 520, 0, 720, 1005)];
    at_limit_in(IHP, "M1.e", &pass, &fail);
}

/// IHP Cnt.h: Cont must be covered by Metal1 (enclosure 0).
#[test]
fn ihp_cnt_h_metal1_covers_cont() {
    let pass = [("cont", 0, 0, 160, 160), ("metal1", 0, 0, 160, 160)];
    let fail = [("cont", 0, 0, 160, 160), ("metal1", 5, 0, 165, 160)];
    at_limit_in(IHP, "Cnt.h", &pass, &fail);
}

/// capm.4: a via3 on the MiM top plate is enclosed by capm by 0.140 um. The
/// pass layout also carries a plain met3-met4 via3 with no capm over it, which
/// the rule must leave alone.
#[test]
fn capm_4_capm_encloses_via3_on_the_plate_by_140nm() {
    let plain = ("via3", 5000, 0, 5200, 200);
    let pass = [
        ("capm", 0, 0, 2000, 2000),
        ("via3", 140, 140, 340, 340),
        plain,
    ];
    let fail = [
        ("capm", 0, 0, 2000, 2000),
        ("via3", 135, 140, 335, 340),
        plain,
    ];
    at_limit("capm.4", &pass, &fail);
    assert_eq!(
        run(SKY130, "capm.4", &[plain]).0,
        0,
        "a via3 with no capm is flagged"
    );
}

/// cap2m.4: the same for via4 on cap2m, 0.200 um.
#[test]
fn cap2m_4_cap2m_encloses_via4_on_the_plate_by_200nm() {
    let plain = ("via4", 5000, 0, 5800, 800);
    let pass = [
        ("cap2m", 0, 0, 2000, 2000),
        ("via4", 200, 200, 1000, 1000),
        plain,
    ];
    let fail = [
        ("cap2m", 0, 0, 2000, 2000),
        ("via4", 195, 200, 995, 1000),
        plain,
    ];
    at_limit("cap2m.4", &pass, &fail);
    assert_eq!(
        run(SKY130, "cap2m.4", &[plain]).0,
        0,
        "a via4 with no cap2m is flagged"
    );
}

/// m1.1 on the field report's repro (`neck.gds`): two 300 nm met1 squares
/// overlapping at a corner leave a 134.5 nm diagonal neck. KLayout reports it
/// as two edge pairs; here it is one violation on the one merged figure.
#[test]
fn m1_1_diagonal_neck_at_overlapping_rectangles() {
    let neck = [
        ("met1", 17020, 9950, 17320, 10250),
        ("met1", 17230, 9750, 17530, 10050),
    ];
    assert_eq!(run(SKY130, "m1.1", &neck).0, 1);
    // Shift the second square 10 nm left: the neck is √(100² + 100²) ≈ 141 nm.
    let wider = [neck[0], ("met1", 17220, 9750, 17520, 10050)];
    assert_eq!(run(SKY130, "m1.1", &wider).0, 0);
}
