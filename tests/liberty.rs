//! `liberty`: the interface level end to end on a corpus cell, and the pin
//! cross-check's refusals, which need no simulator; and, in the oracle shell,
//! the `spice` level against a direct ngspice run (`ngspice_differential`).
//!
//! `LVS_CLEAN_MATCH` is one inverter whose four nets are labelled
//! `LVS_INV_n0`, `_n1`, `_n4` and `_n5`; its schematic, `lvs_inv.cdl`, calls
//! the ports A, Y, VDD and VSS. Those names are the answer every spec below
//! is checked against.

#[path = "common/gen_fixtures.rs"]
mod gen_fixtures;

use gen_fixtures::fixtures;
use gpurify::engine::pipeline::{extract, load, Inputs};
use gpurify::ingest::deck::ProcessStack;
use gpurify::liberty::{generate, spec, Accuracy, LibError, Request};

fn inputs(reference: bool) -> Inputs {
    Inputs {
        layout: fixtures().join("lvs/LVS_CLEAN_MATCH.gds"),
        deck: fixtures().join("params.deck"),
        reference: reference.then(|| fixtures().join("lvs_inv.cdl")),
        ..Inputs::default()
    }
}

/// The inverter's spec with `pins` as its pin list.
fn spec_with(pins: &str) -> spec::MacroSpec {
    spec::parse(&format!(
        r#"{{"cell": "LVS_INV", "pins": [{pins}],
            "corners": [{{"name": "tt_025C_1v80", "temperature": 25,
                          "supplies": {{"LVS_INV_n1": 1.8, "LVS_INV_n0": 0}}, "models": []}}]}}"#
    ))
    .expect("a valid spec")
}

const PINS: &str = r#"
    {"name": "LVS_INV_n5", "role": "input", "power": "LVS_INV_n1", "ground": "LVS_INV_n0"},
    {"name": "LVS_INV_n4", "role": "output", "power": "LVS_INV_n1", "ground": "LVS_INV_n0"},
    {"name": "LVS_INV_n1", "role": "power"},
    {"name": "LVS_INV_n0", "role": "ground"}"#;

fn run(
    spec: &spec::MacroSpec,
    reference: bool,
    lef: Option<&str>,
) -> Result<gpurify::liberty::Generated, LibError> {
    let loaded = load(&inputs(reference)).expect("the corpus cell loads");
    let extracted = extract(&loaded).expect("and extracts");
    let work = std::env::temp_dir().join(format!("gpurify-liberty-test-{}", std::process::id()));
    let request = Request {
        spec,
        accuracy: Accuracy::Interface,
        lef,
        work: &work,
        tool_version: "test",
    };
    let generated = generate(&loaded, &extracted, &request);
    let _ = std::fs::remove_dir_all(&work);
    generated
}

#[test]
fn the_interface_level_writes_pins_supplies_and_area_and_no_arcs() {
    let generated = run(&spec_with(PINS), false, None).expect("the spec matches the cell");
    let names: Vec<String> = generated
        .files
        .iter()
        .map(|(path, _)| path.display().to_string())
        .collect();
    assert_eq!(names, ["LVS_INV.v", "LVS_INV__tt_025C_1v80.lib"]);
    let lib = &generated.files[1].1;
    for needle in [
        "library (\"LVS_INV__tt_025C_1v80\")",
        "pg_pin (\"LVS_INV_n1\")",
        "pg_type : primary_power;",
        "pin (\"LVS_INV_n5\")",
        "direction : input;",
        "related_power_pin : \"LVS_INV_n1\";",
        "is_macro_cell : true;",
        "voltage_map(\"LVS_INV_n1\", 1.8000000000);",
    ] {
        assert!(lib.contains(needle), "missing {needle:?} in\n{lib}");
    }
    assert!(!lib.contains("timing ()"), "an interface model has no arcs");
    assert!(!lib.contains("capacitance :"), "nor a capacitance");
    let area: f64 = lib
        .split("area : ")
        .nth(1)
        .and_then(|rest| rest.split(';').next())
        .and_then(|v| v.parse().ok())
        .expect("an area");
    assert!(area > 0.0, "the cell has geometry, so it has an area");
    let verilog = &generated.files[0].1;
    assert!(
        verilog.contains("(* blackbox *)\nmodule LVS_INV ("),
        "{verilog}"
    );
}

/// Each drift between the spec and the other views is refused, naming it.
#[test]
fn a_pin_the_views_disagree_on_is_refused_by_name() {
    // The spec lists Z, nothing in the layout carries it.
    let extra = format!(
        r#"{PINS}, {{"name": "Z", "role": "input", "power": "LVS_INV_n1", "ground": "LVS_INV_n0"}}"#
    );
    let why = run(&spec_with(&extra), false, None).expect_err("Z is nowhere");
    assert!(why.to_string().contains("pin Z"), "{why}");

    // The schematic's ports are A, Y, VDD and VSS; the spec's are the labels.
    let why = run(&spec_with(PINS), true, None).expect_err("the schematic names differ");
    assert!(
        why.to_string()
            .contains("lacks [LVS_INV_n0, LVS_INV_n1, LVS_INV_n4, LVS_INV_n5]")
            && why.to_string().contains("has [A, VDD, VSS, Y]"),
        "{why}"
    );

    // The LEF's macro has a pin the spec does not.
    let lef = "MACRO LVS_INV\n PIN LVS_INV_n0\n END LVS_INV_n0\n PIN LVS_INV_n1\n END LVS_INV_n1\n \
               PIN LVS_INV_n4\n END LVS_INV_n4\n PIN LVS_INV_n5\n END LVS_INV_n5\n PIN EN\n END EN\nEND LVS_INV\n";
    let why = run(&spec_with(PINS), false, Some(lef)).expect_err("EN is only in the LEF");
    assert!(why.to_string().contains("has [EN]"), "{why}");
}

/// Testing-plan F14. A second label, the input's name, on the output's net is
/// a short between the two pins in the layout. Extraction keeps both names,
/// and the circuit refuses the pair rather than characterise one node as two
/// pins; without the extra label the same cell's pins resolve.
#[test]
fn two_pins_labelled_on_one_net_are_refused_as_shorted() {
    use gpurify::liberty::circuit::{pin_nets, CircuitError};

    let mut loaded = load(&inputs(false)).expect("the corpus cell loads");
    let spec = spec_with(PINS);
    let extracted = extract(&loaded).expect("and extracts");
    assert!(
        pin_nets(&loaded, &extracted, &spec).is_ok(),
        "four pins, four nets"
    );

    let output = loaded.strings.get("LVS_INV_n4").expect("labelled");
    let net = extracted.ports.net_of(output).expect("one net");
    let input = loaded.strings.get("LVS_INV_n5").expect("labelled");
    loaded
        .provenance
        .label(extracted.nets.polys_of(net)[0], input);
    let extracted = extract(&loaded).expect("a labelled short extracts");
    match pin_nets(&loaded, &extracted, &spec) {
        Err(CircuitError::ShortedPins(first, second)) => {
            assert_eq!(
                (first.as_str(), second.as_str()),
                ("LVS_INV_n5", "LVS_INV_n4")
            );
        }
        other => panic!("{other:?}"),
    }
}

/// Testing-plan F78. A PEX refusal in `lib` names the layer as the deck
/// does, as `pex` reports it, rather than passing the extractor's message
/// through with no layer. Both refusals come before any simulation: the
/// closed forms (`analytical`) with `poly` given no sheet resistance, and
/// the field solve (`field`) with `poly` given no dielectric, which the
/// input pin's gate is drawn on.
#[test]
fn a_pex_refusal_names_the_deck_layer() {
    let refusal = |accuracy: Accuracy, unstate: fn(&mut ProcessStack, usize)| {
        let mut loaded = load(&inputs(false)).expect("the corpus cell loads");
        let poly = loaded
            .deck
            .layers
            .id(&loaded.strings, "poly")
            .expect("params.deck has poly")
            .idx();
        unstate(&mut loaded.deck.stack, poly);
        let extracted = extract(&loaded).expect("and extracts");
        let work = std::env::temp_dir().join(format!("gpurify-liberty-pex-{}", std::process::id()));
        let spec = spec_with(PINS);
        let request = Request {
            spec: &spec,
            accuracy,
            lef: None,
            work: &work,
            tool_version: "test",
        };
        let why = generate(&loaded, &extracted, &request).expect_err("poly is not described");
        let _ = std::fs::remove_dir_all(&work);
        why
    };
    match refusal(Accuracy::Analytical, |stack, poly| {
        stack.sheet_res_ohm_sq[poly] = 0.0;
    }) {
        LibError::Pex(why) => assert!(
            why.starts_with("layer poly: ") && why.contains("sheet resistance"),
            "{why}"
        ),
        other => panic!("{other:?}, want a PEX refusal naming poly"),
    }
    match refusal(Accuracy::Field, |stack, poly| {
        stack.dielectric_k[poly] = 0.0;
    }) {
        LibError::Solve(why) => assert!(
            why.starts_with("layer poly: ") && why.contains("permittivity"),
            "{why}"
        ),
        other => panic!("{other:?}, want a field-solve refusal naming poly"),
    }
}

/// The device models of [`ngspice_differential_inverter`]: BSIM4 at its
/// defaults, behind three-terminal subcircuits of the deck's model names
/// (the deck's MOS have no bulk), the bulk on ground for the nfet and on the
/// source for the pfet, which in an inverter is the supply. Any model would
/// do: both runs simulate the same netlist with the same models.
const MODELS: &str = r#"[
    ".model nch nmos level=54 version=4.5",
    ".model pch pmos level=54 version=4.5",
    ".subckt nfet_01v8 d g s w=1 l=1 nf=1 ad=0 as=0 pd=0 ps=0 sa=0 sb=0",
    "m0 d g s 0 nch w={w} l={l} ad={ad} as={as} pd={pd} ps={ps}",
    ".ends",
    ".subckt pfet_01v8 d g s w=1 l=1 nf=1 ad=0 as=0 pd=0 ps=0 sa=0 sb=0",
    "m0 d g s s pch w={w} l={l} ad={ad} as={as} pd={pd} ps={ps}",
    ".ends"]"#;

/// The values of the first table named `group` (`cell_rise`, ...) in `lib`,
/// row-major.
fn lib_table(lib: &str, group: &str) -> Vec<f64> {
    let start = lib
        .find(&format!("{group} ("))
        .unwrap_or_else(|| panic!("no {group} in\n{lib}"));
    let rest = &lib[start..];
    let values = &rest[rest.find("values(").expect("a table") + 7..];
    values[..values.find(");").expect("closed")]
        .split(|c: char| c == '"' || c == ',' || c == '\\' || c.is_whitespace())
        .filter(|w| !w.is_empty())
        .map(|w| w.parse().expect("a number"))
        .collect()
}

/// The `value` of the `leakage_power` group whose `when` is `when`, nW.
fn lib_leakage(lib: &str, when: &str) -> f64 {
    lib.split("leakage_power () {")
        .skip(1)
        .find(|group| group.contains(&format!("when : \"{when}\";")))
        .and_then(|group| group.split("value : ").nth(1))
        .and_then(|v| v.split(';').next())
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_else(|| panic!("no leakage when {when} in\n{lib}"))
}

/// Testing-plan §4 L6, ledger F3: the inverter's `spice`-accuracy delay,
/// transition and leakage against a direct ngspice run.
///
/// `GPurify` characterises the cell on its extracted RC netlist, driving
/// ngspice sessions over a pipe (`liberty::spice`). The reference takes that
/// netlist, the `.subckt` `GPurify` wrote, and nothing else from it: its own
/// batch-mode deck per table point, with the documented stimulus (a linear
/// ramp whose full swing takes `slew / 0.6`, the input held at its old level
/// beforehand), its own `.meas` of the documented definitions (50 % to 50 %
/// delay, 20 %–80 % transition), at a fixed 0.5 ps maximum step; and a DC
/// operating point per input state for leakage, `Σ V·(−I)` over the
/// supplies.
///
/// Tolerances: a delay or transition within 0.5 % plus 0.1 ps, against
/// `GPurify`'s documented 0.03 % between its step control and a 0.1 ps-step
/// run, plus the two runs' different edge times and step sequences; the
/// 0.1 ps is for a delay near zero, which a slow input into a light load
/// gives. A leakage within 1e-4, since both are the same DC operating point
/// solved to reltol 1e-6.
#[test]
#[ignore = "release tier: needs ngspice (nix develop .#oracles)"]
fn ngspice_differential_inverter() {
    use gpurify_testgen::oracle;
    use std::time::Duration;

    // Relative, and absolute in ns.
    const EDGE: (f64, f64) = (5e-3, 1e-4);
    let ngspice = oracle::tool("ngspice");
    let (slews, loads) = ([0.05, 0.5], [0.002, 0.02]);
    let spec = spec::parse(&format!(
        r#"{{"cell": "LVS_INV", "pins": [{PINS}],
            "arcs": [{{"from": "LVS_INV_n5", "to": "LVS_INV_n4", "kind": "combinational",
                       "cases": [{{"vectors": [{{"LVS_INV_n5": "0"}}], "edge": "rise", "output": "fall"}},
                                 {{"vectors": [{{"LVS_INV_n5": "1"}}], "edge": "fall", "output": "rise"}}]}}],
            "corners": [{{"name": "tt", "temperature": 25,
                          "supplies": {{"LVS_INV_n1": 1.8, "LVS_INV_n0": 0}}, "models": {MODELS}}}],
            "characterization": {{"slews_ns": {slews:?}, "loads_pf": {loads:?}}},
            "simulator": {{"workers": 1}}}}"#
    ))
    .expect("a valid spec");
    let loaded = load(&inputs(false)).expect("the corpus cell loads");
    let extracted = extract(&loaded).expect("and extracts");
    let work = oracle::scratch("liberty");
    let request = Request {
        spec: &spec,
        accuracy: Accuracy::Spice,
        lef: None,
        work: &work,
        tool_version: "test",
    };
    let generated = generate(&loaded, &extracted, &request).expect("the inverter characterises");
    let lib = &generated.files[1].1;
    let deck = std::fs::read_to_string(work.join("LVS_INV__tt.cir")).expect("the deck is kept");
    let subckt = &deck[deck.find(".subckt LVS_INV").expect("the macro")..];
    let subckt = &subckt[..subckt.find(".ends LVS_INV").expect("its end") + 13];
    let models: Vec<String> = serde_json::from_str(MODELS).expect("a list of lines");

    // The reference deck; the spec's pin order is A, Y, VDD, VSS.
    let bench = |stimulus: &str, analysis: &str| {
        format!(
            "* F3 reference\n{}\n.option scale=1e-6 reltol=1e-6 abstol=1e-15 vntol=1e-7\n\
             .temp 25\n{subckt}\nxdut a y vdd vss LVS_INV\nvdd vdd 0 1.8\nvss vss 0 0\n\
             {stimulus}\n{analysis}\n.end\n",
            models.join("\n")
        )
    };
    let simulate = |name: &str, text: String| {
        std::fs::write(work.join(name), text).expect("the work directory is writable");
        let out = oracle::run(&ngspice, &["-b", name], &work, Duration::from_mins(2));
        let name = name.to_owned();
        move |key: &str| -> f64 {
            out.lines()
                .find_map(|l| {
                    let (k, v) = l.split_once('=')?;
                    if k.trim() != key {
                        return None;
                    }
                    v.split_whitespace().next()?.parse().ok()
                })
                .unwrap_or_else(|| panic!("{key} not measured in {name}:\n{out}"))
        }
    };
    let mut broken = Vec::new();
    let mut check = |what: String, got: f64, want: f64, (relative, absolute): (f64, f64)| {
        println!(
            "{what}: GPurify {got:e}, ngspice {want:e}, {:+.4} %",
            (got - want) / want * 100.0
        );
        if (got - want).abs() > relative * want.abs() + absolute {
            broken.push(format!("{what}: GPurify {got:e}, ngspice {want:e}"));
        }
    };
    for (rise, out_edge, delay, transition) in [
        (true, "FALL", "cell_fall", "fall_transition"),
        (false, "RISE", "cell_rise", "rise_transition"),
    ] {
        let (delays, transitions) = (lib_table(lib, delay), lib_table(lib, transition));
        for (s, slew) in slews.iter().enumerate() {
            for (l, load) in loads.iter().enumerate() {
                let (v0, v1, in_edge) = if rise {
                    (0.0, 1.8, "RISE")
                } else {
                    (1.8, 0.0, "FALL")
                };
                let stimulus = format!(
                    "va a 0 PWL(0 {v0} 1n {v0} {}n {v1})\ncload y 0 {load}p",
                    1.0 + slew / 0.6
                );
                let analysis = format!(
                    ".tran 0.1p 12n 0 0.5p\n\
                     .meas tran d TRIG v(a) VAL=0.9 {in_edge}=1 TARG v(y) VAL=0.9 {out_edge}=1\n\
                     .meas tran tlo WHEN v(y)=0.36 {out_edge}=1\n\
                     .meas tran thi WHEN v(y)=1.44 {out_edge}=1"
                );
                let read = simulate(&format!("{delay}_{s}_{l}.cir"), bench(&stimulus, &analysis));
                let at = |what: &str| format!("{what} at slew {slew} ns, load {load} pF");
                let k = s * loads.len() + l;
                check(at(delay), delays[k], read("d") * 1e9, EDGE);
                let measured = (read("thi") - read("tlo")).abs() * 1e9;
                check(at(transition), transitions[k], measured, EDGE);
            }
        }
    }
    for (level, when) in [(0.0, "!LVS_INV_n5"), (1.8, "LVS_INV_n5")] {
        let read = simulate(
            &format!("leak_{level}.cir"),
            bench(
                &format!("va a 0 {level}\ncload y 0 1e-18"),
                ".control\nop\nlet p = -1.8 * vdd#branch * 1e9\nprint p\n.endc",
            ),
        );
        check(
            format!("leakage when {when}"),
            lib_leakage(lib, when),
            read("p"),
            (1e-4, 0.0),
        );
    }
    assert!(broken.is_empty(), "{}", broken.join("\n"));
    let _ = std::fs::remove_dir_all(&work);
}
