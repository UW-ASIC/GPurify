//! `ir_drop`, `electromigration` and `reliability` against numbers worked out
//! by hand, through the public path: deck text, drawn geometry, an intent file,
//! then the engine's ERC stage at its 85 C sign-off temperature.
//!
//! Every layout is a 1 nm grid. Metal is modelled as sheet resistance times
//! squares along each bar, one via cut is one sheet value, and a device's
//! share of its net's current budget enters at the point its marker touches
//! the rail. The supply pad is the centre of the rail's topmost shape. All
//! resistances are powers of two so the solve lands on exact binary values and
//! a measurement can sit exactly on its limit.

#![allow(
    clippy::float_cmp,
    reason = "the networks are built so the solve is exact in binary"
)]

use gpurify::check::lvs::CompareOptions;
use gpurify::check::report::{Measurement, Outcome, RuleRun, Violations};
use gpurify::engine::pipeline::{extract, Loaded};
use gpurify::engine::run::{run_checks, Checks, RunOptions, StageStatus};
use gpurify::geom::{Grid, LayerId};
use gpurify::ingest::{Provenance, StrTable};
use gpurify_testgen::shapes::Handle;
use gpurify_testgen::LayoutBuilder;

/// Boltzmann's constant in eV/K (CODATA 2018).
const K_EV: f64 = 8.617_333_262e-5;
/// The engine's sign-off temperature: 85 C.
const T_SIGNOFF: f64 = 85.0 + 273.15;

/// met1 0.125 ohm/sq at 100 nm, via1 0.0625 ohm per cut, met2 0.0625 ohm/sq at
/// 300 nm, so a via spans 200 nm. A `load` device is an `mk` marker over one
/// rail shape and one private poly stub.
const PROCESS: &str = "grid 1nm
layer met1 = gds(1, 0)
layer via1 = gds(2, 0)
layer met2 = gds(3, 0)
layer poly = gds(4, 0)
layer mk   = gds(5, 0)
connect conductors [met1, met2, poly]
connect touch_within_layer
connect via via1 [met1, met2]
device resistor mk model \"load\" terminals [met1, poly]
pex met1 thickness 100nm height 100nm sheet 0.125ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex via1 thickness 100nm height 200nm sheet 0.0625ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex met2 thickness 100nm height 300nm sheet 0.0625ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
pex poly thickness 100nm height 50nm sheet 8ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
";

#[derive(Clone, Copy)]
struct Layers {
    met1: LayerId,
    via1: LayerId,
    met2: LayerId,
    poly: LayerId,
    mk: LayerId,
    /// A net-only layer and a cut into it, when the rules declare them.
    sub: Option<LayerId>,
    tie: Option<LayerId>,
}

/// What one ERC run reported.
struct Report {
    layers: Layers,
    violations: Violations,
    runs: Vec<RuleRun>,
    strings: StrTable,
}

impl Report {
    fn run(&self, rule: &str) -> RuleRun {
        let id = self.strings.get(rule).expect("the deck names this rule");
        *self
            .runs
            .iter()
            .find(|run| run.rule == id)
            .expect("every deck row records a run")
    }

    /// `(layer, at, measured, limit)` of each violation of `rule`, in report order.
    fn rows(&self, rule: &str) -> Vec<(LayerId, (i64, i64), Measurement, Measurement)> {
        let id = self.strings.get(rule).expect("the deck names this rule");
        let v = &self.violations;
        (0..v.len())
            .filter(|&row| v.rule[row] == id)
            .map(|row| {
                (
                    v.layer[row],
                    (v.at[row].x.raw(), v.at[row].y.raw()),
                    v.measured[row],
                    v.limit[row],
                )
            })
            .collect()
    }
}

/// Parse `PROCESS` plus `rules`, draw, label, attach `intent`, extract, run ERC.
fn erc(
    rules: &str,
    intent: &str,
    draw: impl FnOnce(Layers, &mut LayoutBuilder) -> Vec<(Handle, &'static str)>,
) -> Report {
    let grid = Grid::new(1_000).expect("a 1 nm grid");
    let mut strings = StrTable::default();
    let deck = gpurify::ingest::deck::parse_deck(&format!("{PROCESS}{rules}"), grid, &mut strings)
        .expect("the deck parses");
    let layer = |name| deck.layers.id(&strings, name).expect("declared");
    let layers = Layers {
        met1: layer("met1"),
        via1: layer("via1"),
        met2: layer("met2"),
        poly: layer("poly"),
        mk: layer("mk"),
        sub: deck.layers.id(&strings, "sub"),
        tie: deck.layers.id(&strings, "tie"),
    };
    let mut layout = LayoutBuilder::new(deck.layers.len());
    let labels = draw(layers, &mut layout);
    let (store, ids) = layout.finish();
    let mut provenance = Provenance::default();
    for (handle, name) in labels {
        provenance.label(ids.of(handle), strings.intern(name));
    }
    let intent =
        gpurify::ingest::intent::parse_intent(intent, &mut strings).expect("intent parses");
    let loaded = Loaded {
        strings,
        grid,
        deck,
        store,
        provenance,
        reference: None,
        intent: Some(intent),
    };
    let extracted = extract(&loaded).expect("the layout extracts");
    let options = RunOptions {
        checks: Checks {
            drc: false,
            erc: true,
            lvs: false,
            pex: false,
        },
        lvs: CompareOptions::default(),
        quasistatic_nets: Vec::new(),
        quasistatic_inductance: false,
    };
    let (out, summary) = run_checks(&loaded, &extracted, &options).expect("ERC runs");
    assert_eq!(summary.erc, StageStatus::Ran, "the supply grid solved");
    Report {
        layers,
        violations: out.violations,
        runs: out.runs,
        strings: loaded.strings,
    }
}

/// One `load` device whose marker is centred on `(x, y)`, the lower edge of a
/// rail bar: the marker overlaps the bar above and a private poly stub below.
fn load_at(l: Layers, layout: &mut LayoutBuilder, x: i64, y: i64) {
    layout.rect(l.mk, x - 100, y - 100, x + 100, y + 100);
    layout.rect(l.poly, x - 100, y - 400, x + 100, y - 50);
}

/// An intent declaring `nets` in one domain, with `limits` as the JSON of the
/// `limits` array.
fn intent(domain_mv: f64, supplies: &[(&str, &str)], limits: &str) -> String {
    let supplies: Vec<String> = supplies
        .iter()
        .map(|(net, role)| format!(r#"{{"net":"{net}","domain":"core","role":"{role}"}}"#))
        .collect();
    format!(
        r#"{{"domains":{{"core":{{"voltage_mv":{domain_mv}}}}},"supplies":[{}],"limits":[{limits}]}}"#,
        supplies.join(",")
    )
}

fn millivolts(m: Measurement) -> f64 {
    match m {
        Measurement::Voltage(v) => v.raw(),
        other => panic!("{other:?} is not a voltage"),
    }
}

fn microamps(m: Measurement) -> f64 {
    match m {
        Measurement::Current(c) => c.raw(),
        other => panic!("{other:?} is not a current"),
    }
}

fn hours(m: Measurement) -> f64 {
    match m {
        Measurement::Ratio(h) => h,
        other => panic!("{other:?} is not a lifetime"),
    }
}

fn close(got: f64, want: f64, what: &str) {
    assert!(
        (got - want).abs() <= 1e-9 * want.abs().max(1.0),
        "{what}: got {got}, want {want}"
    );
}

// ---------------------------------------------------------------- ir_drop

/// A 20 um x 1 um met1 bar, pad at its centre x = 10000, with three loads at
/// x = 12000, 14000 and 18000.
fn ladder(l: Layers, layout: &mut LayoutBuilder) -> Vec<(Handle, &'static str)> {
    let bar = layout.rect(l.met1, 0, 0, 20_000, 1_000);
    for x in [12_000, 14_000, 18_000] {
        load_at(l, layout, x, 0);
    }
    vec![(bar, "VDD")]
}

/// Oracle: Ohm's law on a series ladder. 3000 uA splits 1000 uA per load.
/// Segments are 2, 2 and 4 squares of 0.125 ohm: 0.25, 0.25 and 0.5 ohm,
/// carrying 3000, 2000 and 1000 uA. Drops: 0.75, 0.75 + 0.5 = 1.25 and
/// 1.25 + 0.5 = 1.75 mV, the last at (18000, 500).
///
/// A limit of 1.75 mV sits exactly on the worst node (legal, strict); 1.7 mV is
/// just under it (one row); 1.25 mV sits on the middle node and still catches
/// only the far one; 100 mV is far above everything.
#[test]
fn ir_drop_on_a_series_ladder_is_ohms_law_and_strict_at_the_limit() {
    for (limit, expect) in [(1.75, 0usize), (1.7, 1), (1.25, 1), (100.0, 0)] {
        let report = erc(
            "rule ir ir_drop()\n",
            &intent(
                1800.0,
                &[("VDD", "power")],
                &format!(r#"{{"net":"VDD","max_drop_mv":{limit},"budget_current_ua":3000}}"#),
            ),
            ladder,
        );
        let run = report.run("ir");
        assert_eq!(run.outcome, Outcome::Ran);
        assert_eq!(run.examined, 4, "the pad and three load taps");
        let rows = report.rows("ir");
        assert_eq!(rows.len(), expect, "limit {limit} mV");
        for (_, at, measured, bound) in rows {
            assert_eq!(at, (18_000, 500));
            assert_eq!(millivolts(measured), 1.75, "exact binary drop");
            assert_eq!(millivolts(bound), limit);
        }
    }
}

/// A supply ring is one polygon with a hole, and the store keeps the hole as a
/// clockwise row of its own. That row is no conductor, so it is no grid node:
/// made one, nothing links it and the whole ERC stage is refused as an island.
/// Reported by the Philis session (a VDD guard ring).
#[test]
fn a_supply_ring_with_a_hole_solves() {
    let report = erc(
        "rule ir ir_drop()\n",
        &intent(
            1800.0,
            &[("VDD", "power")],
            r#"{"net":"VDD","max_drop_mv":100,"budget_current_ua":1000}"#,
        ),
        |l, layout| {
            let ring = layout.rect(l.met1, 0, 0, 4_000, 4_000);
            layout.shape(
                l.met1,
                &gpurify_testgen::shapes::hole(1_000, 1_000, 3_000, 3_000),
            );
            load_at(l, layout, 3_000, 0);
            vec![(ring, "VDD")]
        },
    );
    let run = report.run("ir");
    assert_eq!(run.outcome, Outcome::Ran);
    assert_eq!(run.examined, 2, "the pad and the load tap, not the hole");
}

/// A cut into a global (net-only) layer joins the net but is no grid link: the
/// substrate has no node, so a tie from the rail into it must not become one.
/// Every per-net network is built for `p2p_resistance`, so this ran into a
/// shape index the network never assigned. Reported by the Philis session (a
/// p-tap ring tied to sky130's `psub`).
#[test]
fn a_via_into_a_global_layer_is_no_grid_link() {
    let report = erc(
        "layer sub = gds(6, 0)\nlayer tie = gds(7, 0)\nconnect global sub\nconnect via tie [met1, sub]\nrule ir ir_drop()\n",
        &intent(
            1800.0,
            &[("VDD", "power")],
            r#"{"net":"VDD","max_drop_mv":100,"budget_current_ua":1000}"#,
        ),
        |l, layout| {
            let (sub, tie) = (l.sub.expect("declared"), l.tie.expect("declared"));
            let bar = layout.rect(l.met1, 0, 0, 4_000, 1_000);
            layout.rect(sub, 0, 0, 4_000, 1_000);
            layout.rect(tie, 200, 200, 400, 400);
            load_at(l, layout, 3_000, 0);
            vec![(bar, "VDD")]
        },
    );
    assert_eq!(report.run("ir").outcome, Outcome::Ran);
}

/// Two 12 um x 1 um bars, met2 (pad, centre x = 6000) above met1, joined by
/// one via at x = 5000 and one at x = 11000; one load on met1 at x = 6000.
fn divider(l: Layers, layout: &mut LayoutBuilder) -> Vec<(Handle, &'static str)> {
    let lower = layout.rect(l.met1, 0, 0, 12_000, 1_000);
    let upper = layout.rect(l.met2, 0, 500, 12_000, 1_500);
    layout.rect(l.via1, 4_900, 650, 5_100, 850);
    layout.rect(l.via1, 10_900, 650, 11_100, 850);
    load_at(l, layout, 6_000, 0);
    vec![(lower, "VDD"), (upper, "VDD")]
}

/// Oracle: a current divider. Branch A (x = 5000) is 1 square of met2, one
/// cut and 1 square of met1: 0.0625 + 0.0625 + 0.125 = 0.25 ohm. Branch B
/// (x = 11000) is 5 squares of met2, one cut and 5 squares of met1:
/// 0.3125 + 0.0625 + 0.625 = 1.0 ohm. 5000 uA divides 4:1, 4000 uA through A
/// and 1000 uA through B, and both give the load node 4000 * 0.25 =
/// 1000 * 1.0 = 1.0 mV.
///
/// The via currents are read back through an electromigration row with a
/// 2000 uA per-cut limit rated at the sign-off temperature (derate 1) and an
/// unreachable metal limit: only via A is over it, measuring 4000 uA.
#[test]
fn ir_drop_through_two_parallel_vias_divides_the_current_inversely_to_resistance() {
    let rules = "rule ir ir_drop()
rule em electromigration(via1, met1, max_density: 1000mA/um, max_current_per_cut: 2000uA,
    blech_limit: 1nA, reference_temperature: 85C, activation_energy: 0.9eV, current_exponent: 2)
";
    for (limit, expect) in [(1.1, 0usize), (0.99, 1)] {
        let report = erc(
            rules,
            &intent(
                1800.0,
                &[("VDD", "power")],
                &format!(r#"{{"net":"VDD","max_drop_mv":{limit},"budget_current_ua":5000}}"#),
            ),
            divider,
        );
        let rows = report.rows("ir");
        assert_eq!(rows.len(), expect, "limit {limit} mV");
        for (layer, at, measured, _) in rows {
            assert_eq!((layer, at), (report.layers.met1, (6_000, 500)));
            close(millivolts(measured), 1.0, "the load node's drop");
        }

        let em = report.rows("em");
        assert_eq!(em.len(), 1, "only via A carries more than 2000 uA");
        let (_, at, measured, bound) = em[0];
        assert_eq!(at.0, 5_000);
        close(microamps(measured), 4_000.0, "branch A's share");
        assert_eq!(microamps(bound), 2_000.0);
        assert_eq!(
            report.run("em").examined,
            2 + 2,
            "two cuts and two met1 edges"
        );
    }
}

// -------------------------------------------------------- electromigration

/// One 20 um x 1 um met1 bar, pad at x = 10000, one load at x = 18000: a
/// single edge 8000 nm long and 1000 nm wide.
fn single_edge(l: Layers, layout: &mut LayoutBuilder) -> Vec<(Handle, &'static str)> {
    let bar = layout.rect(l.met1, 0, 0, 20_000, 1_000);
    load_at(l, layout, 18_000, 0);
    vec![(bar, "VDD")]
}

fn one_ma(net: &str) -> String {
    intent(
        1800.0,
        &[(net, "power")],
        &format!(r#"{{"net":"{net}","budget_current_ua":1000}}"#),
    )
}

/// Black's equation `MTTF = A J^-n exp(Ea / kT)`: holding MTTF fixed, the
/// allowed current scales by `exp(Ea / (n k) (1/T - 1/T_ref))`. Rated at
/// 105 C (378.15 K), operated at 85 C (358.15 K), Ea 0.9 eV, n 2:
/// `exp(0.9 / (2 * 8.617333262e-5) * (1/358.15 - 1/378.15)) = 2.16225793047`.
const DERATE_105C: f64 = 2.162_257_930_473_676;

fn em_row(density: &str, blech: &str) -> String {
    format!(
        "rule em electromigration(met1, max_density: {density}, max_current_per_cut: 1mA,
    blech_limit: {blech}, reference_temperature: 105C, activation_energy: 0.9eV, current_exponent: 2)\n"
    )
}

/// Oracle: Black with Arrhenius derating, with the reference temperature
/// written in Celsius. The edge carries 1000 uA over 1 um of width. At
/// 0.462 mA/um the derated limit is 462 A/m * 1e-6 m * 2.16226 = 998.96 uA,
/// just below the current: one violation. At 0.463 mA/um it is 1001.12 uA,
/// just above: clean. At 10 mA/um it is far above. The formula is written out
/// here rather than read from the code.
#[test]
fn electromigration_derates_a_celsius_rating_by_black_and_arrhenius() {
    let derate = (0.9 / (2.0 * K_EV) * (1.0 / T_SIGNOFF - 1.0 / (105.0 + 273.15))).exp();
    close(derate, DERATE_105C, "the hand value of the derating");
    for (density, per_um, expect) in [
        ("0.462mA/um", 462.0, 1usize),
        ("0.463mA/um", 463.0, 0),
        ("10mA/um", 10_000.0, 0),
    ] {
        let report = erc(&em_row(density, "1nA"), &one_ma("VDD"), single_edge);
        let run = report.run("em");
        assert_eq!((run.outcome, run.examined), (Outcome::Ran, 1));
        let rows = report.rows("em");
        assert_eq!(rows.len(), expect, "{density}");
        for (layer, at, measured, bound) in rows {
            assert_eq!(layer, report.layers.met1);
            assert_eq!(at, (10_000, 500), "reported at the edge's pad end");
            close(microamps(measured), 1_000.0, "the branch current");
            close(
                microamps(bound),
                per_um * 1e-6 * 1e6 * DERATE_105C,
                "the derated limit",
            );
        }
    }
}

/// Oracle: the Blech product `J L = I L / W`. The edge's is
/// 1000 uA * 8000 / 1000 = 8 mA. At a Blech limit of exactly 8 mA the segment
/// is immortal (the exemption is inclusive): not examined, not reported, even
/// against a density limit it exceeds a thousandfold. At 7.999 mA it is mortal
/// and the same density limit reports it.
#[test]
fn a_blech_immortal_segment_is_exempt_exactly_up_to_its_product() {
    let immortal = erc(&em_row("0.001mA/um", "8mA"), &one_ma("VDD"), single_edge);
    let run = immortal.run("em");
    assert_eq!(
        (run.outcome, run.examined, run.violations),
        (Outcome::Ran, 0, 0)
    );

    let mortal = erc(
        &em_row("0.001mA/um", "7.999mA"),
        &one_ma("VDD"),
        single_edge,
    );
    let run = mortal.run("em");
    assert_eq!(
        (run.outcome, run.examined, run.violations),
        (Outcome::Ran, 1, 1)
    );
}

/// met2 bar (pad, centre x = 4000) over a met1 bar, one via at x = 6000, one
/// load on met1 at x = 2000. Every element carries the full 1000 uA: the met2
/// edge 4000 -> 6000, the cut, and the met1 edges 6000 -> 4000 -> 2000 (the
/// met1 bar's own centre is a tap).
fn stack(l: Layers, layout: &mut LayoutBuilder) -> Vec<(Handle, &'static str)> {
    let lower = layout.rect(l.met1, 0, 0, 8_000, 1_000);
    let upper = layout.rect(l.met2, 0, 500, 8_000, 1_500);
    layout.rect(l.via1, 5_900, 650, 6_100, 850);
    load_at(l, layout, 2_000, 0);
    vec![(lower, "VDD"), (upper, "VDD")]
}

/// Oracle: one row over three layers applies the per-width limit to metal and
/// the per-cut limit to the via, each derated by the same 2.16226. Metal:
/// 0.4 mA/um over 1 um is 400 uA, derated 864.90 uA, under the 1000 uA every
/// metal edge carries: three violations (met2 once, met1 twice). Via: 500 uA
/// per cut derated to 1081.13 uA, over 1000 uA: clean. Blech products are
/// 2 mA per metal edge and 1000 uA * 200 nm / 1000 nm = 200 uA for the cut,
/// all above the 100 uA limit, so all four are examined.
///
/// With the reference temperature at 85 C the derating is exactly 1, and a
/// 1000 uA per-cut limit sits exactly on the via's current: clean; 999 uA
/// reports it.
#[test]
fn a_multi_layer_electromigration_row_limits_metal_per_width_and_cuts_per_cut() {
    let rules = "rule em electromigration(met1, met2, via1, max_density: 0.4mA/um,
    max_current_per_cut: 500uA, blech_limit: 100uA, reference_temperature: 105C,
    activation_energy: 0.9eV, current_exponent: 2)\n";
    let report = erc(rules, &one_ma("VDD"), stack);
    let run = report.run("em");
    assert_eq!((run.outcome, run.examined), (Outcome::Ran, 4));
    let mut layers: Vec<LayerId> = Vec::new();
    for (layer, _, measured, bound) in report.rows("em") {
        layers.push(layer);
        close(
            microamps(measured),
            1_000.0,
            "every element carries the budget",
        );
        close(
            microamps(bound),
            400.0 * DERATE_105C,
            "the derated per-width limit",
        );
    }
    let l = report.layers;
    let mut want = vec![l.met1, l.met1, l.met2];
    layers.sort();
    want.sort();
    assert_eq!(layers, want, "met1 twice, met2 once, no via");

    for (per_cut, expect) in [("1000uA", 0usize), ("999uA", 1)] {
        let rules = format!(
            "rule em electromigration(via1, max_density: 1000mA/um, max_current_per_cut: {per_cut},
    blech_limit: 100uA, reference_temperature: 85C, activation_energy: 0.9eV, current_exponent: 2)\n"
        );
        let report = erc(&rules, &one_ma("VDD"), stack);
        let rows = report.rows("em");
        assert_eq!(rows.len(), expect, "{per_cut}");
        for (layer, _, measured, _) in rows {
            assert_eq!(layer, report.layers.via1);
            assert_eq!(microamps(measured), 1_000.0, "exact binary current");
        }
    }
}

// ------------------------------------------------------------- reliability

/// A VDD bar and a VSS bar, no loads: every node sits at its pad.
fn two_rails(l: Layers, layout: &mut LayoutBuilder) -> Vec<(Handle, &'static str)> {
    let vdd = layout.rect(l.met1, 0, 0, 4_000, 1_000);
    let vss = layout.rect(l.met1, 0, 3_000, 4_000, 4_000);
    vec![(vdd, "VDD"), (vss, "VSS")]
}

fn rel_row(required: &str, reference_temperature: &str, duty: &str) -> String {
    format!(
        "rule rel reliability(required_lifetime: {required}, reference_lifetime: 1000h,
    reference_stress: 1800mV, stress_exponent: 4, reference_temperature: {reference_temperature},
    activation_energy: 0.7eV, max_abs_voltage: 10V, duty_cycle: {duty})\n"
    )
}

/// Oracle: the model at its own reference point. Characterised at 1800 mV and
/// 85 C for 1000 h with full duty, a node at 1800 mV and 85 C lasts exactly
/// `1000 * (1800/1800)^4 * exp(0) / 1 = 1000 h`. A 1000 h requirement is met
/// exactly (strict); 1001 h is not. VSS sits at 0 V, no stress at all, so it
/// is never reported.
#[test]
fn reliability_at_its_reference_point_is_strict_at_the_required_lifetime() {
    let supplies = [("VDD", "power"), ("VSS", "ground")];
    for (required, expect) in [("1000h", 0usize), ("1001h", 1)] {
        let report = erc(
            &rel_row(required, "85C", "1"),
            &intent(1800.0, &supplies, ""),
            two_rails,
        );
        let run = report.run("rel");
        assert_eq!((run.outcome, run.examined), (Outcome::Ran, 2), "{required}");
        let rows = report.rows("rel");
        assert_eq!(rows.len(), expect, "{required}");
        for (_, at, measured, _) in rows {
            assert_eq!(at, (2_000, 500), "the VDD bar's centre, not VSS");
            assert_eq!(hours(measured), 1_000.0);
        }
    }
}

/// Oracle: inverse power law times Arrhenius, with the reference temperature
/// in Celsius and a duty cycle. Rated 1000 h at 1800 mV and 125 C
/// (398.15 K), Ea 0.7 eV, n 4, stressed half the time. The Arrhenius factor
/// is `exp(0.7 / 8.617333262e-5 * (1/358.15 - 1/398.15)) = 9.76327790`, the
/// stress factor `(1800/3300)^4 = 0.0885216`, the duty factor 1/0.5 = 2, so at
/// 85 C and 3300 mV the part lasts 1000 * 9.76327790 * 2 * 0.0885216 =
/// 1728.4623 h.
/// Required 1730 h is just missed; 1728 h is just met. At 1800 mV the same part
/// lasts 19526.56 h, far above either.
#[test]
fn reliability_scales_by_stress_power_law_arrhenius_and_duty() {
    let thermal = (0.7 / K_EV * (1.0 / T_SIGNOFF - 1.0 / (125.0 + 273.15))).exp();
    close(
        thermal,
        9.763_277_903_048_08,
        "the hand value of the Arrhenius factor",
    );
    let at_3v3 = 1_000.0 * thermal / 0.5 * (1_800.0f64 / 3_300.0).powi(4);
    close(
        at_3v3,
        1_728.462_285_684_08,
        "the hand value of the lifetime",
    );

    let supplies = [("VDD", "power"), ("VSS", "ground")];
    for (domain, required, expect) in [
        (3300.0, "1730h", 1usize),
        (3300.0, "1728h", 0),
        (1800.0, "1730h", 0),
    ] {
        let report = erc(
            &rel_row(required, "125C", "50%"),
            &intent(domain, &supplies, ""),
            two_rails,
        );
        assert_eq!(report.run("rel").outcome, Outcome::Ran);
        let rows = report.rows("rel");
        assert_eq!(rows.len(), expect, "{domain} mV, {required}");
        for (_, at, measured, _) in rows {
            assert_eq!(at, (2_000, 500));
            close(hours(measured), at_3v3, "the predicted lifetime");
        }
    }
}

/// Oracle: Ohm's law on the ground rail. VSS returns 1000 uA through 8
/// squares of 0.125 ohm, so the far node rises 1.0 mV above 0 V: ground bounce
/// is the ground rail's drop, and a 0.5 mV limit reports it.
#[test]
fn ir_drop_on_a_ground_rail_is_its_bounce_above_zero() {
    let report = erc(
        "rule ir ir_drop()\n",
        &intent(
            1800.0,
            &[("VSS", "ground")],
            r#"{"net":"VSS","max_drop_mv":0.5,"budget_current_ua":1000}"#,
        ),
        |l, layout| {
            let bar = layout.rect(l.met1, 0, 0, 20_000, 1_000);
            load_at(l, layout, 18_000, 0);
            vec![(bar, "VSS")]
        },
    );
    let rows = report.rows("ir");
    assert_eq!(rows.len(), 1);
    let (_, at, measured, _) = rows[0];
    assert_eq!(at, (18_000, 500));
    assert_eq!(millivolts(measured), 1.0);
}
