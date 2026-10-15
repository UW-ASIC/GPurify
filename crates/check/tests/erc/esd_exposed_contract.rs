//! `esd_exposed`'s `min_series` where the ported secondary-stage fixtures
//! leave it open: which resistors make up the series network. Drawn as
//! `esd_secondary` draws its circuits: the pad on SIG with dio clamps to
//! VDD1 and VSS1, a gate on OUT with its own local clamps, each `rs`
//! resistor marker 400 nm along its ends and 200 nm across at
//! `sheet 100ohm`, so 200 Ω.

use crate::fixture::{check_all, Expect, Fixture};
use crate::ported::{
    circuit_pins, dev, diode_process, domain_intent, ohms, rect, track_y, Model, TRACK_H,
};

const LABELS: [&str; 8] = ["VDD1", "VSS1", "VDD2", "VSS2", "VSS3", "SIG", "OUT", "MID"];
const VDD1: usize = 0;
const VSS1: usize = 1;
const VSS3: usize = 4;
const SIG: usize = 5;
const OUT: usize = 6;

/// One `esd_exposed` row over `dio` clamps and `rs` resistors, valued, with
/// a second resistor model `rs2` (`mkres2`) the row does not list.
fn deck(min: f64) -> String {
    let process = diode_process().replace(
        "model \"rs\" terminals [diff, diff]",
        "model \"rs\" terminals [diff, diff] sheet 100ohm",
    );
    format!(
        "{process}layer mkres2 = gds(29, 0)\n\
         device resistor mkres2 model \"rs2\" terminals [diff, diff] sheet 100ohm\n\
         rule exp esd_exposed(pad; clamps: [\"dio\"], resistors: [\"rs\"], rated: none, \
         min_series: {min}ohm)\n"
    )
}

/// The gate on OUT behind one listed resistor from SIG, with `extra`
/// diode or resistor columns `(marker, anode, cathode)`.
fn fixture(
    name: &str,
    extra: &[(&'static str, usize, usize)],
    min: f64,
    expect: Expect,
) -> Fixture {
    let mut pins = vec![
        ("mkdi", VSS1, SIG),
        ("mkdi", SIG, VDD1),
        ("mkres", SIG, OUT),
        ("mkdi", VSS1, OUT),
        ("mkdi", OUT, VDD1),
    ];
    pins.extend_from_slice(extra);
    let mut l = circuit_pins(&LABELS, &[dev(Model::Nfet, OUT, VSS1, VSS3)], &pins);
    let ty = track_y(SIG);
    rect(&mut l, "pad", (-1000, ty, -400, ty + TRACK_H));
    rect(&mut l, "padv", (-800, ty + 150, -600, ty + 250));
    let mut f = Fixture::new(name, &["ERC-C3"], &deck(min))
        .layout(l)
        .expect(expect);
    f.intent = Some(domain_intent());
    f
}

/// A resistor of the unlisted model `rs2` in parallel with the listed one.
///
/// Oracle: the rustdoc: the series network is the `resistors` models' alone,
/// so the gate stays 200 Ω behind the pad, clean against 150 Ω; counted, the
/// two in parallel would be 100 Ω and flagged.
#[test]
fn a_resistor_of_an_unlisted_model_is_not_in_the_series_network() {
    check_all(&[fixture(
        "esd_exposed/unlisted_parallel",
        &[("mkres2", SIG, OUT)],
        150.0,
        Expect::clean("exp"),
    )]);
}

/// A listed resistor from the gate's net OUT down to the rail VSS1.
///
/// Oracle: the rustdoc: only resistors with both ends among the exposed nets
/// (the pads and what listed resistors reach, never a rail) are in the
/// network, so the pull-down is left out and the gate is 200 Ω behind the
/// pad, flagged against 300 Ω.
#[test]
fn a_resistor_to_a_rail_is_not_in_the_series_network() {
    check_all(&[fixture(
        "esd_exposed/pull_down",
        &[("mkres", OUT, VSS1)],
        300.0,
        Expect::rule("exp", vec![ohms(200.0)]),
    )]);
}
