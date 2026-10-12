//! The printer is the parser's inverse: a deck shared as text is the deck
//! (deck-library plan §4.7, testing-plan L9b "a shared deck survives
//! printing").
//!
//! Oracle: round trip. `compile(print(d))` in the same string table equals
//! `d`, typed rule by typed rule and layer by layer, and printing that again
//! gives the same text.

use super::{grid, twins, DECKS};
use gpurify_check::deck::{compile, print, BuildError, CompiledDeck, Origin};
use gpurify_geom::StrTable;

/// `deck` printed, compiled back into `strings`, equal to itself, and
/// printed again to the same text. Text states no provenance: every rule of
/// the deck read back is the base deck's own.
pub(crate) fn assert_round_trip(what: &str, deck: &CompiledDeck, strings: &mut StrTable) {
    let printed = print(deck, strings).unwrap_or_else(|why| panic!("{what}: {why}"));
    let again = compile(&printed, grid(), strings)
        .unwrap_or_else(|why| panic!("{what}: the printed deck does not compile: {why}"));
    let mut expected = deck.clone();
    for (_, origin) in &mut expected.provenance {
        *origin = Origin::Base;
    }
    super::builder::assert_same(what, &expected, &again, strings);
    let reprinted = print(&again, strings).unwrap_or_else(|why| panic!("{what}: {why}"));
    assert!(
        reprinted == printed,
        "{what}: printing the reprinted deck gave other text"
    );
}

/// Every shipped deck, compiled from its text, survives printing.
/// Oracle: round trip.
#[test]
fn every_shipped_deck_survives_printing() {
    for (name, text) in DECKS {
        let mut strings = StrTable::default();
        let deck = compile(text, grid(), &mut strings).expect("a shipped deck compiles");
        assert_round_trip(name, &deck, &mut strings);
    }
}

/// Every Rust twin, built with the builder, survives printing: a deck built
/// in Rust can be shared as text.
/// Oracle: round trip.
#[test]
fn every_rust_twin_survives_printing() {
    type Build = fn(&mut StrTable) -> Result<CompiledDeck, BuildError>;
    let builds: [(&str, Build); 4] = [
        ("generic_finfet", twins::generic_finfet::build),
        ("gf180mcu", twins::gf180mcu::build),
        ("ihp_sg13g2", twins::ihp_sg13g2::build),
        ("sky130", twins::sky130::build),
    ];
    for (name, build) in builds {
        let mut strings = StrTable::default();
        let deck = build(&mut strings).unwrap_or_else(|why| panic!("{name}: {why}"));
        assert_round_trip(name, &deck, &mut strings);
    }
}

/// A deck the printer cannot state is refused, not written wrong: a length
/// on a grid of thirds of a nanometre has no terminating decimal.
/// Oracle: hand-derived: 1 nm is 3 units of the grid, and one unit is 1/3 nm.
#[test]
fn a_length_no_decimal_states_is_refused() {
    let thirds = gpurify_geom::Grid::new(3000).expect("a third of a nanometre");
    let mut strings = StrTable::default();
    let deck = compile(
        "grid 1nm\nlayer m = gds(1, 0)\nrule w width(m) >= 1nm\n",
        thirds,
        &mut strings,
    )
    .expect("1 nm is 3 units of a 1/3 nm grid");
    assert!(print(&deck, &strings).is_err());
}

/// A deck with a `temperature` survives printing: it is written as stated,
/// each `pex` row's sheet at the nominal temperature with its `tc1` and
/// `tc2`, and the text says so.
/// Oracle: round trip.
#[test]
fn a_deck_with_a_temperature_survives_printing() {
    let text = "grid 1nm
layer met1 = gds(68, 20)
layer met2 = gds(69, 20)
temperature 358.15K nominal 303.15K
pex met1 thickness 360nm height 1376nm sheet 0.125ohm dielectric 3.9 area_cap 25.8aF/um2 fringe_cap 40.5aF/um tc1 3.179e-3/K tc2 3.094e-7/K2
pex met2 thickness 360nm height 2006nm sheet 0.125ohm area_cap 17.5aF/um2 fringe_cap 37.6aF/um tc1 3.161e-3/K tc2 -7.272e-7/K2
";
    let mut strings = StrTable::default();
    let deck = compile(text, grid(), &mut strings).expect("the deck compiles");
    assert!(deck.temperature.is_some());
    assert_round_trip("temperature", &deck, &mut strings);
    let printed = print(&deck, &strings).expect("the deck prints");
    assert!(
        printed.contains("temperature 3.5815e2K nominal 3.0315e2K"),
        "{printed}"
    );
    assert!(printed.contains("sheet 1.25e-1ohm"), "{printed}");
    assert!(
        printed.contains("tc1 3.179e-3/K tc2 3.094e-7/K2"),
        "{printed}"
    );
}

/// A deck with every kind of `lvs` statement survives printing: each control
/// is written back as stated, an absolute tolerance in its parameter's unit,
/// a permutation by its pin names and a range on the layout's grid.
/// Oracle: round trip.
#[test]
fn a_deck_with_lvs_statements_survives_printing() {
    let text = "grid 1nm
layer diff = gds(65, 20)
layer poly = gds(66, 20)
layer res = gds(66, 13)
layer cap = gds(75, 20)
device mos poly model \"nfet\" terminals [poly, diff, diff, diff]
device resistor res model \"rpoly\" terminals [poly, poly]
device capacitor cap model \"cmim\" terminals [poly, diff]
lvs tolerance \"nfet\" w relative 1%
lvs tolerance \"nfet\" l relative 0.005 absolute 5nm
lvs tolerance \"nfet\" as absolute 0.2um2
lvs tolerance \"rpoly\" r absolute 2kohm
lvs tolerance \"cmim\" c relative 0.02 absolute 3fF
lvs tolerance \"nfet\" m absolute 1
lvs ignore_parameter \"rpoly\" l
lvs asymmetric \"nfet\"
lvs permute \"cmim\" top bottom
lvs ignore \"cmim\"
lvs ignore_shorted \"nfet\"
lvs ports_by_name
lvs range \"nfet\" l >= 150nm <= 20um
lvs range \"nfet\" ad >= 0.1um2
lvs range \"nfet\" nf <= 8
lvs topology relaxed
lvs connect_implicit \"VDD*\"
lvs connect_explicit \"VSS\" \"GND\"
";
    let mut strings = StrTable::default();
    let deck = compile(text, grid(), &mut strings).expect("the deck compiles");
    assert_eq!(deck.lvs.tolerance.len(), 6);
    assert_round_trip("lvs", &deck, &mut strings);
    let printed = print(&deck, &strings).expect("the deck prints");
    for line in [
        "lvs tolerance \"nfet\" l relative 5e-3 absolute 5e0nm",
        "lvs tolerance \"rpoly\" r absolute 2e3ohm",
        "lvs permute \"cmim\" top bottom",
        "lvs range \"nfet\" l >= 150nm <= 20000nm",
        "lvs connect_explicit \"VSS\" \"GND\"",
    ] {
        assert!(printed.contains(line), "{line} not in\n{printed}");
    }
}

/// A deck with process corners, an extraction type, stages and waivers
/// (PEX-006, PEX-008, FLOW-001, FLOW-002) survives printing: each statement
/// is written back as stated, a corner's sheet at the nominal temperature
/// with its own coefficients, the coupling threshold in attofarads, each
/// stage ahead of its rules.
/// Oracle: round trip.
#[test]
fn a_deck_with_corners_stages_and_waivers_survives_printing() {
    let text = "grid 1nm
layer met1 = gds(68, 20)
layer met2 = gds(69, 20)
layer waiver = gds(200, 0)
stage gross
rule m1.w width(met1) >= 140nm
stage fine
rule m1.s space(met1) >= 140nm
rule m2.w width(met2) >= 140nm
stage last
temperature 358.15K nominal 303.15K
pex met1 thickness 360nm height 1376nm sheet 0.125ohm dielectric 3.9 area_cap 25.8aF/um2 fringe_cap 40.5aF/um tc1 3.179e-3/K tc2 3.094e-7/K2
pex met2 thickness 360nm height 2006nm sheet 0.125ohm area_cap 17.5aF/um2 fringe_cap 37.6aF/um tc1 3.161e-3/K tc2 -7.272e-7/K2
corner cmax met1 thickness 396nm sheet 0.11ohm
corner cmax met2 sheet 0.2ohm tc1 0/K tc2 0/K2
corner cmin met1 fringe_cap 36aF/um
waive m1.s waiver
waive m2.w waiver
extraction rcc coupling_threshold 0.1fF
";
    let mut strings = StrTable::default();
    let deck = compile(text, grid(), &mut strings).expect("the deck compiles");
    assert_eq!(deck.corners.len(), 2);
    assert_eq!(deck.stages.name.len(), 3);
    assert_eq!(deck.waivers.len(), 2);
    assert_round_trip("corners, stages and waivers", &deck, &mut strings);
    let printed = print(&deck, &strings).expect("the deck prints");
    for line in [
        "stage gross\nrule m1.w",
        "stage fine\nrule m1.s",
        "stage last\n",
        "corner cmax met1 thickness 3.96e2nm sheet 1.1e-1ohm",
        "corner cmax met2 sheet 2e-1ohm tc1 0e0/K tc2 0e0/K2",
        "waive m1.s waiver",
        "extraction rcc coupling_threshold 1e2aF",
    ] {
        assert!(printed.contains(line), "{line} not in\n{printed}");
    }
}

/// A deck's parasitic models (`pex_fill`, `pex_device`) survive printing,
/// and one naming what the deck lacks is refused.
/// Oracle: round trip; and the refusals `docs/deck.md` states (a fill
/// layer that carries no net, a model no `device mos` declares, a key
/// missing).
#[test]
fn a_deck_with_pex_models_survives_printing() {
    let text = "grid 1nm
layer poly = gds(66, 20)
layer diff = gds(65, 20)
layer met1 = gds(68, 20)
layer fill1 = gds(68, 28)
layer gate = poly and diff
connect conductors [poly, diff, met1, fill1]
device mos gate model \"nfet\" terminals [poly, diff, diff]
pex fill1 thickness 360nm height 1376nm sheet 0.125ohm dielectric 3.9 area_cap 25.8aF/um2 fringe_cap 40.5aF/um
pex_fill fill1 floating
pex_device \"nfet\" gate_contact_cap 0.3aF/um gate_diffusion_cap 0.25aF/um
";
    let mut strings = StrTable::default();
    let deck = compile(text, grid(), &mut strings).expect("the deck compiles");
    assert_eq!(deck.pex_models.fill.len(), 1);
    assert_eq!(deck.pex_models.device[0].gate_diffusion_af_um, 0.25);
    assert_round_trip("pex models", &deck, &mut strings);
    let refused = |swap: (&str, &str)| {
        let text = text.replace(swap.0, swap.1);
        compile(&text, grid(), &mut StrTable::default()).is_err()
    };
    assert!(refused(("pex_fill fill1", "pex_fill gate")));
    assert!(refused(("pex_device \"nfet\"", "pex_device \"pfet\"")));
    assert!(refused((" gate_diffusion_cap 0.25aF/um", "")));
    assert!(refused(("floating", "sometimes")));
}
