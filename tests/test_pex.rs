mod common;

use common::{case_string, cases, close, deck, load_case_store, manifest};
use gdsverify::{extract_netlist, run_pex, run_pex_by_net, Parasitic};
use serde_json::Value;
use std::collections::BTreeSet;

const COVERED_KINDS: [&str; 8] = [
    "area_cap",
    "coupling_cap",
    "coupling_cap_met2",
    "interlayer_cap",
    "per_net",
    "resistance",
    "resistance_met2",
    "via_resistance",
];

fn sum_parasitics(report: &gdsverify::PexReport, kind: &str) -> (f64, &'static str) {
    match kind {
        "resistance" => (report.total_resistance("met1"), "r_ohm"),
        "resistance_met2" => (report.total_resistance("met2"), "r_ohm"),
        "area_cap" => (
            report
                .area_caps()
                .iter()
                .filter_map(|parasitic| match parasitic {
                    Parasitic::AreaCap { af, .. } => Some(*af),
                    _ => None,
                })
                .sum(),
            "c_af",
        ),
        "coupling_cap" => (
            report
                .coupling_caps()
                .iter()
                .filter_map(|parasitic| match parasitic {
                    Parasitic::CouplingCap { af, .. } => Some(*af),
                    _ => None,
                })
                .sum(),
            "c_af",
        ),
        "coupling_cap_met2" => (
            report
                .coupling_caps()
                .iter()
                .filter_map(|parasitic| match parasitic {
                    Parasitic::CouplingCap { layer, af, .. } if layer == "met2" => Some(*af),
                    _ => None,
                })
                .sum(),
            "c_af",
        ),
        "interlayer_cap" => (
            report
                .interlayer_caps()
                .iter()
                .filter_map(|parasitic| match parasitic {
                    Parasitic::InterlayerCap { af, .. } => Some(*af),
                    _ => None,
                })
                .sum(),
            "c_af",
        ),
        "via_resistance" => (
            report
                .via_resistances()
                .iter()
                .filter_map(|parasitic| match parasitic {
                    Parasitic::ViaResistance { ohm, .. } => Some(*ohm),
                    _ => None,
                })
                .sum(),
            "r_ohm",
        ),
        other => panic!("unsupported scalar PEX fixture kind `{other}`"),
    }
}

#[test]
fn every_analytical_pex_result_family_has_a_gds_fixture() {
    let manifest = manifest();
    let actual: BTreeSet<&str> = cases(&manifest, "pex")
        .iter()
        .map(|case| case_string(case, "kind"))
        .collect();
    let expected: BTreeSet<&str> = COVERED_KINDS.into_iter().collect();
    assert_eq!(actual, expected, "PEX fixture inventory drifted");
    assert_eq!(cases(&manifest, "pex").len(), 27);

    let negative = cases(&manifest, "pex")
        .iter()
        .filter(|case| case.get("expect_mismatch").and_then(Value::as_bool) == Some(true))
        .count();
    assert_eq!(negative, 8, "negative goldens prove harness sensitivity");
}

#[test]
fn analytical_pex_gds_conformance_matches_numeric_goldens() {
    let manifest = manifest();
    let deck = deck();
    let mut failures = Vec::new();

    for case in cases(&manifest, "pex") {
        let id = case_string(case, "id");
        let kind = case_string(case, "kind");
        let tolerance = case.get("tol").and_then(Value::as_f64).unwrap_or(1.0e-6);
        let expect_mismatch = case
            .get("expect_mismatch")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let store = load_case_store("pex", case, &deck);
        let report = run_pex(&store, &deck);

        if !report.is_complete() {
            failures.push(format!(
                "{id}: analytical extraction emitted unsupported-geometry diagnostics: {:?}",
                report.diagnostics()
            ));
            continue;
        }

        if kind == "per_net" {
            let extracted = extract_netlist(&store, &deck)
                .unwrap_or_else(|error| panic!("{id}: connectivity extraction: {error}"));
            let got = run_pex_by_net(&store, &deck, &extracted.net_of_poly);
            let expected = case["expected"]
                .as_object()
                .unwrap_or_else(|| panic!("{id}: expected must be a per-net object"));
            let mut all_match = true;
            let mut detail = Vec::new();
            for (net, values) in expected {
                let net_id = net.parse::<u32>().unwrap_or(u32::MAX);
                let actual = got.get(&net_id).copied().unwrap_or_default();
                if let Some(expected_r) = values.get("r_ohm").and_then(Value::as_f64) {
                    let matches = close(actual.r_ohm, expected_r, tolerance);
                    all_match &= matches;
                    detail.push(format!(
                        "net {net_id} R={} expected={expected_r}",
                        actual.r_ohm
                    ));
                }
                if let Some(expected_c) = values.get("cap_af").and_then(Value::as_f64) {
                    let matches = close(actual.cap_af, expected_c, tolerance);
                    all_match &= matches;
                    detail.push(format!(
                        "net {net_id} C={} expected={expected_c}",
                        actual.cap_af
                    ));
                }
            }
            if all_match == expect_mismatch {
                failures.push(format!(
                    "{id}: per-net golden sensitivity mismatch (expect_mismatch={expect_mismatch}); {}",
                    detail.join(", ")
                ));
            }
            continue;
        }

        let (got, expected_field) = sum_parasitics(&report, kind);
        let expected = case["expected"]
            .get(expected_field)
            .and_then(Value::as_f64)
            .unwrap_or_else(|| panic!("{id}: expected.{expected_field} must be numeric"));
        let matches = close(got, expected, tolerance);
        if matches == expect_mismatch {
            failures.push(format!(
                "{id}: {kind} got={got} expected={expected} tolerance={tolerance} expect_mismatch={expect_mismatch}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} PEX fixture(s) failed:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
