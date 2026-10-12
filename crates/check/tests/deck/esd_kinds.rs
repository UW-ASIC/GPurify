//! The ESD and latch-up kinds in the deck library: each constructor states
//! what its deck spelling does, and each survives the printer.

use super::builder::assert_same;
use super::grid;
use super::printer::assert_round_trip;
use gpurify_check::deck::rules::{
    conditional_tie, esd_cross_domain, esd_exposed, esd_ground_coupling, esd_parasitic, esd_path,
    forward_diode, guard_ring, guard_ring_bias, latchup_victim, tie_area,
};
use gpurify_check::deck::{compile, CompiledDeck, DeckBuilder};
use gpurify_geom::{Dbu, StrTable};
use gpurify_ingest::deck::{DeviceKind, DeviceValue};

const TEXT: &str = "grid 1nm
layer pad = gds(1, 0)
layer diff = gds(2, 0)
layer ring = gds(3, 0)
layer well = gds(4, 0)
layer cont = gds(5, 0)
layer mk = gds(6, 0)
layer gate = gds(7, 0)
connect conductors [pad, diff, ring]
device diode mk model \"dio\" terminals [diff, pad]
rule ep esd_path(pad; clamps: [\"dio\"], current: 1330mA, clamp_resistance: 1ohm, \
max_resistance: 2ohm, clamp_it2: 9.25mA/um, max_density: none, max_current_per_cut: 10mA, \
max_voltage: 5V)
rule ep.ring esd_path(pad, ring; clamps: none, current: 100mA, clamp_resistance: 1ohm, \
max_resistance: 1ohm, clamp_it2: none, max_density: 1mA/um, max_current_per_cut: none, \
max_voltage: none)
rule gc esd_ground_coupling(; diodes: [\"dio\"])
rule xd esd_cross_domain(; diodes: [\"dio\"], local: none)
rule xd.local esd_cross_domain(; diodes: [\"dio\"], local: [\"dio\"])
rule par esd_parasitic(pad, diff; min_spacing: 5um)
rule exp esd_exposed(pad; clamps: [\"dio\"], resistors: none, rated: [\"dio\"])
rule grb guard_ring_bias(ring; power: false)
rule ta tie_area(well, cont, gate; min_ratio: 3%)
rule gr guard_ring(diff, ring; max_space: 15um, min_width: 2um, pad: pad, near: none, within: none)
rule gr.near guard_ring(mk, ring; max_space: none, min_width: none, pad: none, near: well, within: 50um)
rule fd forward_diode(mk; models: [\"dio\"])
rule ct conditional_tie(diff, cont, well, gate; within: 50um, spacing: [1um, 2um], \
max_distance: [15um, 30um, 50um])
rule lv latchup_victim(pad, diff, cont; within: 15um, max_distance: 2um, pad: pad)
";

fn um(value: i64) -> Dbu {
    Dbu::new_unchecked(value * 1000)
}

/// [`TEXT`] built in Rust, statement by statement.
fn build(strings: &mut StrTable) -> CompiledDeck {
    let mut d = DeckBuilder::new(grid(), strings);
    let pad = d.layer("pad", (1, 0));
    let diff = d.layer("diff", (2, 0));
    let ring = d.layer("ring", (3, 0));
    let well = d.layer("well", (4, 0));
    let cont = d.layer("cont", (5, 0));
    let mk = d.layer("mk", (6, 0));
    let gate = d.layer("gate", (7, 0));
    d.conductors(&[pad, diff, ring]);
    d.device(
        DeviceKind::Diode,
        mk,
        "dio",
        &[diff, pad],
        DeviceValue::default(),
    );
    d.rule(
        "ep",
        esd_path(
            pad,
            None,
            &["dio"],
            1_330_000.0,
            1.0,
            Some(2.0),
            Some(9250.0),
            None,
            Some(10_000.0),
            Some(5000.0),
        ),
    );
    d.rule(
        "ep.ring",
        esd_path(
            pad,
            Some(ring.into()),
            &[],
            100_000.0,
            1.0,
            Some(1.0),
            None,
            Some(1000.0),
            None,
            None,
        ),
    );
    d.rule("gc", esd_ground_coupling(&["dio"]));
    d.rule("xd", esd_cross_domain(&["dio"], &[]));
    d.rule("xd.local", esd_cross_domain(&["dio"], &["dio"]));
    d.rule("par", esd_parasitic(pad, diff, um(5)));
    d.rule("exp", esd_exposed(pad, &["dio"], &[], &["dio"]));
    d.rule("grb", guard_ring_bias(ring, false));
    d.rule("ta", tie_area(well, cont, gate, 0.03));
    d.rule(
        "gr",
        guard_ring(diff, ring, Some(um(15)), Some(um(2)), Some(pad), None, None),
    );
    d.rule(
        "gr.near",
        guard_ring(mk, ring, None, None, None, Some(well), Some(um(50))),
    );
    d.rule("fd", forward_diode(mk, &["dio"]));
    d.rule(
        "ct",
        conditional_tie(
            diff,
            cont,
            well,
            gate,
            um(50),
            &[um(1), um(2)],
            &[um(15), um(30), um(50)],
        ),
    );
    d.rule(
        "lv",
        latchup_victim(pad, diff, cont, um(15), um(2), Some(pad)),
    );
    d.finish().expect("the Rust deck builds")
}

/// Each ESD and latch-up kind's constructor states what its deck spelling
/// does.
/// Oracle: differential against the parser, the same deck written as text.
#[test]
fn every_esd_and_latchup_kind_has_a_constructor_equal_to_its_text() {
    let mut strings = StrTable::default();
    let parsed = compile(TEXT, grid(), &mut strings).expect("the text compiles");
    let built = build(&mut strings);
    assert_same("esd and latch-up kinds", &parsed, &built, &strings);
}

/// Every ESD and latch-up kind, each optional limit stated and left out,
/// survives printing.
/// Oracle: round trip.
#[test]
fn every_esd_and_latchup_kind_survives_printing() {
    let mut strings = StrTable::default();
    let deck = compile(TEXT, grid(), &mut strings).expect("the text compiles");
    assert_round_trip("esd and latch-up kinds", &deck, &mut strings);
}
