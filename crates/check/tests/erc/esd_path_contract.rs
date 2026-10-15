//! `esd_path`'s contract where the ported strip fixtures leave it open: a
//! clamp's on-resistance other than 1 Ω under `clamp_voltage`, a turned-on
//! network that drives a clamp backwards, a source polygon on no net, a
//! reverse-biased diode of an unlisted model, and pins that are not the
//! supply's feed point; and a transistor clamp on three path nets. Every
//! strip value is hand-derived on [`esd_layout`]'s three strips: the pad
//! (0.0625 Ω/sq), VSS on met1 (0.125 Ω/sq) and VDD on met2 (0.0625 Ω/sq),
//! each 20 µm by 1 µm, the pad entered at its centre.

use crate::fixture::{check_all, Expect, Finding, Fixture, Want};
use crate::ported::{
    circuit_pins, dev, diode_process, esd_intent, esd_layout, microamps, millivolts, ohms, rect,
    side, track_y, Diode, Model, ESD_CLAMPS, ESD_PROCESS, TRACK_H,
};

/// One `esd_path` row `ep` forcing 1.33 A with every limit written out.
fn deck(process: &str, clamps: &str, ohm: f64, limits: &str) -> String {
    format!(
        "{process}rule ep esd_path(pad; clamps: {clamps}, current: 1330mA, \
         clamp_resistance: {ohm}ohm, {limits})\n"
    )
}

fn fixture(name: &str, deck: &str, layout: crate::fixture::Layout, expect: Expect) -> Fixture {
    let mut f = Fixture::new(name, &["ERC-C8"], deck)
        .layout(layout)
        .expect(expect);
    f.intent = Some(esd_intent());
    f
}

/// One down diode at 2 µm, its clamp 2 Ω and holding 700 mV once on. The
/// path is the pad's 8 squares (0.5 Ω), the clamp (2 Ω) and VSS's 8 squares
/// (1 Ω): the pin rises 1.33 A × 3.5 Ω + 700 mV = 5355 mV (White Paper 2's
/// sum), and the clamp, alone in series, carries all 1.33 A, rated `it2`
/// times its 4.8 µm perimeter.
///
/// Oracle: that closed form, each limit a part in a thousand either side.
/// A turn-on source scaled by the resistance the wrong way (700 mV × 2 Ω
/// instead of / 2 Ω) raises the pin to 7455 mV; a clamp current read with
/// the source added, or divided by its sign, misses 1.33 A.
#[test]
fn a_two_ohm_clamp_holding_700_mv_raises_the_pin_by_the_white_paper_sum() {
    let rise = 1330.0 * 3.5 + 700.0;
    let rated = 1.33 / 4.8e-6;
    let mut all = Vec::new();
    for scale in [0.999, 1.001] {
        let limits = format!(
            "max_resistance: none, clamp_it2: {}A/m, max_density: none, \
             max_current_per_cut: none, max_voltage: {}mV, min_width: none, \
             clamp_voltage: 700mV",
            rated * scale,
            rise * scale
        );
        let findings = if scale < 1.0 {
            vec![millivolts(rise).at(0, 0), microamps(1.33e6).at(1900, -2100)]
        } else {
            Vec::new()
        };
        all.push(fixture(
            &format!("esd_path/two_ohm_turn_on/{}", side(scale, 1.0)),
            &deck(ESD_PROCESS, ESD_CLAMPS, 2.0, &limits),
            esd_layout([1000; 3], &[(Diode::Down, 2000)]),
            Expect::rule("ep", findings),
        ));
    }
    check_all(&all);
}

/// A down diode at 2 µm, an up diode at 18 µm and a rail diode at 10 µm,
/// each 1 Ω and holding 5 V once on. To VSS the down path is 2.5 Ω with one
/// clamp and the up-rail path 3 Ω with two; with the pin at `P`,
/// `P = 2.5 (1.33 A − I) + 5 V = 3 I + 10 V`, so the up-rail path carries
/// `I = −304.5 mA`: the turned-on network drives its clamps backwards. To
/// VDD likewise, `2 (1.33 A − I) + 5 V = 3.5 I + 10 V`, `I = −425.8 mA`.
///
/// Oracle: that solve, and the rustdoc: a clamp the turned-on network would
/// drive backwards is not modelled, so the row is refused, whichever pair
/// is solved first, before it finds anything.
#[test]
fn a_turn_on_that_drives_a_parallel_clamp_backwards_refuses_the_row() {
    let limits = "max_resistance: none, clamp_it2: none, max_density: none, \
                  max_current_per_cut: none, max_voltage: 100000mV, min_width: none, \
                  clamp_voltage: 5000mV";
    check_all(&[fixture(
        "esd_path/backwards",
        &deck(ESD_PROCESS, ESD_CLAMPS, 1.0, limits),
        esd_layout(
            [1000; 3],
            &[
                (Diode::Down, 2000),
                (Diode::Up, 18_000),
                (Diode::Rail, 10_000),
            ],
        ),
        Expect::outcome("ep", Want::Refused),
    )]);
}

const RESISTANCE_ONLY: &str = "clamp_it2: none, max_density: none, max_current_per_cut: none, \
                               max_voltage: none, min_width: none, clamp_voltage: none";

/// The current entering at each polygon of the diode markers, which are no
/// conductor: a marker is on no net, so nothing enters there and no pair is
/// solved, under a limit every real pair (2.5 Ω) would break.
///
/// Oracle: the rustdoc: each source polygon's net reaches supplies; a
/// polygon on no net reaches none.
#[test]
fn a_source_polygon_on_no_net_is_never_stressed() {
    let rule = format!(
        "{ESD_PROCESS}rule ep esd_path(pad, mkd; clamps: {ESD_CLAMPS}, current: 1330mA, \
         clamp_resistance: 1ohm, max_resistance: 1ohm, {RESISTANCE_ONLY})\n"
    );
    check_all(&[fixture(
        "esd_path/source_on_no_net",
        &rule,
        esd_layout([1000; 3], &[(Diode::Down, 2000)]),
        Expect::rule("ep", Vec::new()).examined(0),
    )]);
}

/// The series down diode at 2 µm (2.5 Ω to VSS) beside a second
/// reverse-biased diode between the pad and VSS at 18 µm whose model,
/// `down2`, the row does not list.
///
/// Oracle: the rustdoc: only devices of the listed models are clamps, so
/// the unlisted diode carries nothing and the pair stays 2.5 Ω, flagged
/// against 2.4975 Ω; counted as a clamp it would open a parallel path and
/// lower the resistance below that limit.
#[test]
fn a_reverse_biased_diode_of_an_unlisted_model_is_no_clamp() {
    let process = format!(
        "{ESD_PROCESS}layer mkd2 = gds(15, 0)\ndevice diode mkd2 model \"down2\" terminals [met1, pad]\n"
    );
    let mut layout = esd_layout([1000; 3], &[(Diode::Down, 2000)]);
    rect(&mut layout, "mkd2", (17_900, -2100, 18_100, 100));
    let limits = format!("max_resistance: {}ohm, {RESISTANCE_ONLY}", 2.5 * 0.999);
    check_all(&[fixture(
        "esd_path/unlisted_diode",
        &deck(&process, "[\"down\"]", 1.0, &limits),
        layout,
        Expect::rule("ep", vec![ohms(2.5).at(0, 0)]),
    )]);
}

/// VSS given its own pin, a pad square centred at 18 µm joined to the rail
/// by one `padv` cut (0.25 Ω), with the pad layer drawn below met1 (50 nm
/// against 100 nm), so VSS's highest shape, its feed point, is the met1
/// strip, not the pin.
///
/// Oracle: the rustdoc: a supply with pins is held at its pins, never its
/// feed point: the pad's 0.5 Ω, the 1 Ω diode, VSS's 16 squares (2 Ω) and
/// the cut, 3.75 Ω, flagged against 3.746 Ω. Held at the feed point it
/// would be the 2.5 Ω series path, clean. The pin is a pin of VSS too,
/// stressed against VSS itself at 0 Ω: two pairs.
#[test]
fn a_supply_with_pins_is_held_at_its_pins_not_its_feed_point() {
    let low_pad = ESD_PROCESS.replace("height 500nm", "height 50nm");
    assert_ne!(low_pad, ESD_PROCESS, "the pad's height is stated");
    let mut layout = esd_layout([1000; 3], &[(Diode::Down, 2000)]);
    rect(&mut layout, "pad", (17_500, -3000, 18_500, -2000));
    rect(&mut layout, "padv", (17_900, -2600, 18_100, -2400));
    let limits = format!("max_resistance: {}ohm, {RESISTANCE_ONLY}", 3.75 * 0.999);
    check_all(&[fixture(
        "esd_path/pinned_below_the_feed_point",
        &deck(&low_pad, ESD_CLAMPS, 1.0, &limits),
        layout,
        Expect::rule("ep", vec![ohms(3.75).at(0, 0)]).examined(2),
    )]);
}

/// One MOS clamp of the topology process (gate on VDD, source on the pad,
/// drain on VSS, 1 µm wide) drawn as `circuit_pins` draws a transistor,
/// the pad on its track, rated a token 1 A/m: every pair of its three nets
/// carries part of the stress current, far above 1 µA.
///
/// Oracle: the rustdoc: a clamp joining three or more path nets carries the
/// largest current of its pairs, one violation per clamp, so each of the
/// two pin pairs (to VDD, to VSS) flags the clamp once: two findings, at
/// its marker. Reported per pair of nets it would be more.
#[test]
fn a_clamp_on_three_path_nets_is_flagged_once_per_pin_pair() {
    let labels = ["PAD", "VDD", "VSS"];
    let (pad, vdd, vss) = (0, 1, 2);
    let mut l = circuit_pins(&labels, &[dev(Model::Clamp, vdd, pad, vss)], &[]);
    let ty = track_y(pad);
    rect(&mut l, "pad", (-1000, ty, -400, ty + TRACK_H));
    rect(&mut l, "padv", (-800, ty + 150, -600, ty + 250));
    let rule = format!(
        "{}rule ep esd_path(pad; clamps: [\"clamp\"], current: 1330mA, clamp_resistance: 1ohm, \
         max_resistance: none, clamp_it2: 1A/m, max_density: none, max_current_per_cut: none, \
         max_voltage: none, min_width: none, clamp_voltage: none)\n",
        diode_process()
    );
    let marker = Finding::any().at(1000, 0);
    check_all(&[fixture(
        "esd_path/three_net_clamp",
        &rule,
        l,
        Expect::rule("ep", vec![marker, marker]).examined(2),
    )]);
}
