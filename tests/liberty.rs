//! `liberty`: the interface level end to end on a corpus cell, and the pin
//! cross-check's refusals. No simulator is needed for either.
//!
//! `LVS_CLEAN_MATCH` is one inverter whose four nets are labelled
//! `LVS_INV_n0`, `_n1`, `_n4` and `_n5`; its schematic, `lvs_inv.cdl`, calls
//! the ports A, Y, VDD and VSS. Those names are the answer every spec below
//! is checked against.

use gpurify::engine::pipeline::{extract, load, Inputs};
use gpurify::liberty::{generate, spec, Accuracy, LibError, Request};
use std::path::PathBuf;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

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
