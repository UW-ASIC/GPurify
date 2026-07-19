mod common;

use common::{case_string, cases, deck, load_case_store, manifest};
use gdsverify::{run_lvs, DeviceFlavor, DeviceKind, RefDevice, RefNetlist};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};

const EXPECTED_CASES: [&str; 16] = [
    "LVS_CLEAN_MATCH",
    "LVS_SD_PERMUTE",
    "LVS_DEVICE_MISMATCH",
    "LVS_TOPO_MISMATCH",
    "LVS_INTENTIONAL_SHORT",
    "LVS_INTENTIONAL_OPEN",
    "LVS_FINGERS_MATCH",
    "LVS_FINGERS_MISMATCH",
    "LVS_PARAM_MATCH",
    "LVS_PARAM_MISMATCH",
    "LVS_HVT_MATCH",
    "LVS_HVT_MISMATCH",
    "LVS_LVT_MATCH",
    "LVS_SERIES_MERGE",
    "LVS_PARALLEL_MERGE",
    "LVS_ISOMORPHIC",
];

fn build_reference(value: &Value) -> RefNetlist {
    let devices = value
        .get("devices")
        .and_then(Value::as_array)
        .expect("reference_netlist.devices must be an array")
        .iter()
        .map(|device| {
            let kind = match device.get("type").and_then(Value::as_str) {
                Some("nmos") => DeviceKind::Nmos,
                Some("pmos") => DeviceKind::Pmos,
                other => panic!("unsupported reference device type {other:?}"),
            };
            let flavor = match device.get("flavor").and_then(Value::as_str) {
                Some("lvt") => DeviceFlavor::Lvt,
                Some("hvt") => DeviceFlavor::Hvt,
                Some("standard") => DeviceFlavor::Standard,
                Some(other) => panic!("unsupported reference flavor `{other}`"),
                None => DeviceFlavor::Standard,
            };
            RefDevice {
                kind,
                gate: device["g"].as_str().expect("reference gate").to_string(),
                source: device["s"].as_str().expect("reference source").to_string(),
                drain: device["d"].as_str().expect("reference drain").to_string(),
                w: device.get("w").and_then(Value::as_i64).unwrap_or(0) as i32,
                l: device.get("l").and_then(Value::as_i64).unwrap_or(0) as i32,
                flavor,
                body: device.get("b").and_then(Value::as_str).map(str::to_string),
                ad: None,
                as_: None,
                pd: None,
                ps: None,
            }
        })
        .collect();
    RefNetlist {
        devices,
        net_seeds: HashMap::new(),
        ref_two_terminal: Vec::new(),
        ref_bjt: Vec::new(),
    }
}

#[test]
fn lvs_fixture_inventory_covers_the_comparison_matrix() {
    let manifest = manifest();
    let actual: BTreeSet<&str> = cases(&manifest, "lvs")
        .iter()
        .map(|case| case_string(case, "id"))
        .collect();
    let expected: BTreeSet<&str> = EXPECTED_CASES.into_iter().collect();
    assert_eq!(actual, expected, "LVS fixture inventory drifted");

    let positive = cases(&manifest, "lvs")
        .iter()
        .filter(|case| case["expect_match"].as_bool() == Some(true))
        .count();
    let negative = cases(&manifest, "lvs").len() - positive;
    assert_eq!((positive, negative), (9, 7));
}

#[test]
fn lvs_gds_conformance_matches_reference_netlists() {
    let manifest = manifest();
    let deck = deck();
    let mut failures = Vec::new();

    for case in cases(&manifest, "lvs") {
        let id = case_string(case, "id");
        let expected = case["expect_match"]
            .as_bool()
            .unwrap_or_else(|| panic!("{id}: expect_match must be Boolean"));
        let reference = build_reference(&case["reference_netlist"]);
        let store = load_case_store("lvs", case, &deck);
        let result = run_lvs(&store, &deck, &reference);

        if result.matched != expected {
            failures.push(format!(
                "{id}: matched={} expected={expected}; reason={}; mismatches={}",
                result.matched,
                result.reason,
                serde_json::to_string(&result.mismatches).expect("serialize LVS mismatches")
            ));
            continue;
        }
        if expected && result.extracted_devices != reference.devices.len() {
            failures.push(format!(
                "{id}: clean match mapped {} extracted devices to {} reference devices",
                result.extracted_devices,
                reference.devices.len()
            ));
        }
        if !expected && result.reason.trim().is_empty() && result.mismatches.is_empty() {
            failures.push(format!("{id}: mismatch has no diagnostic or witness"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} LVS fixture(s) failed:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
