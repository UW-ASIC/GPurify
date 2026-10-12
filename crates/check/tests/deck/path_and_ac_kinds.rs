//! The path, loop, supply-piece, matching, power-switch, clamp-resistance
//! and AC current-density kinds in the deck library: each constructor states what its deck
//! spelling does, and each survives the printer.

use super::builder::assert_same;
use super::grid;
use super::printer::assert_round_trip;
use gpurify_check::deck::rules::{
    combinational_loop, em_peak, em_rms, esd_clamp_resistance, floating_supply, gate_path,
    matching, power_switch, supply_path,
};
use gpurify_check::deck::{compile, CompiledDeck, DeckBuilder};
use gpurify_geom::{Dbu, StrTable};
use gpurify_ingest::deck::{DeviceKind, DeviceValue};

const TEXT: &str = "grid 1nm
layer pad = gds(1, 0)
layer met1 = gds(2, 0)
layer via1 = gds(3, 0)
layer mk = gds(4, 0)
connect conductors [pad, met1]
device diode mk model \"dio\" terminals [met1, pad]
rule sp supply_path(; both: true)
rule gp gate_path(; ground: false, max_devices: 3)
rule cl combinational_loop()
rule fs floating_supply()
rule mt matching(mk; tolerance: 50nm)
rule ps power_switch(; models: [\"dio\"])
rule cr esd_clamp_resistance(pad; clamps: [\"dio\"], max_resistance: 1ohm)
rule rms em_rms(met1, via1; frequency: [100MHz, 300MHz], width: [500nm, 1500nm], \
density: [[1mA/um, 2mA/um], [3mA/um, 4mA/um]], max_current_per_cut: 1mA)
rule pk em_peak(met1; frequency: [1GHz], width: [0nm], density: [[6.1mA/um]], \
max_current_per_cut: 100uA)
";

/// [`TEXT`] built in Rust, statement by statement.
fn build(strings: &mut StrTable) -> CompiledDeck {
    let mut d = DeckBuilder::new(grid(), strings);
    let pad = d.layer("pad", (1, 0));
    let met1 = d.layer("met1", (2, 0));
    let via1 = d.layer("via1", (3, 0));
    let mk = d.layer("mk", (4, 0));
    d.conductors(&[pad, met1]);
    d.device(
        DeviceKind::Diode,
        mk,
        "dio",
        &[met1, pad],
        DeviceValue::default(),
    );
    d.rule("sp", supply_path(true));
    d.rule("gp", gate_path(false, 3));
    d.rule("cl", combinational_loop());
    d.rule("fs", floating_supply());
    d.rule("mt", matching(mk, Dbu::new_unchecked(50)));
    d.rule("ps", power_switch(&["dio"]));
    d.rule("cr", esd_clamp_resistance(pad, &["dio"], 1.0));
    d.rule(
        "rms",
        em_rms(
            &[met1, via1],
            &[100.0, 300.0],
            &[Dbu::new_unchecked(500), Dbu::new_unchecked(1500)],
            &[1000.0, 2000.0, 3000.0, 4000.0],
            1000.0,
        ),
    );
    d.rule(
        "pk",
        em_peak(
            &[met1],
            &[1000.0],
            &[Dbu::new_unchecked(0)],
            &[6100.0],
            100.0,
        ),
    );
    d.finish().expect("the Rust deck builds")
}

/// Each kind's constructor states what its deck spelling does.
/// Oracle: differential against the parser, the same deck written as text.
#[test]
fn every_path_and_ac_kind_has_a_constructor_equal_to_its_text() {
    let mut strings = StrTable::default();
    let parsed = compile(TEXT, grid(), &mut strings).expect("the text compiles");
    let built = build(&mut strings);
    assert_same("path and AC kinds", &parsed, &built, &strings);
}

/// Every kind, an AC table of two frequencies by two widths and one of a
/// single entry, survives printing.
/// Oracle: round trip.
#[test]
fn every_path_and_ac_kind_survives_printing() {
    let mut strings = StrTable::default();
    let deck = compile(TEXT, grid(), &mut strings).expect("the text compiles");
    assert_round_trip("path and AC kinds", &deck, &mut strings);
}
