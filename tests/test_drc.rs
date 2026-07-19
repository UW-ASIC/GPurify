mod common;

use common::{case_string, cases, deck, load_case_store, manifest};
use gdsverify::{run_drc_backend_strict, Backend, Violation};
use std::collections::BTreeSet;
use std::process::Command;

const COVERED_RULES: [&str; 28] = [
    "angle",
    "antenna",
    "antenna_car",
    "asymmetric_enclosure",
    "cheesing",
    "corner_to_corner",
    "eol_spacing",
    "max_density",
    "max_distance_to_tap",
    "max_width",
    "min_area",
    "min_density",
    "min_edge_length",
    "min_enclosed_area",
    "min_enclosure",
    "min_extension",
    "min_spacing",
    "min_spacing_diff",
    "min_width",
    "multi_patterning",
    "notch",
    "off_grid",
    "overlap",
    "polygon_validity",
    "prl_spacing",
    "redundant_via",
    "via_array_spacing",
    "wide_dependent_spacing",
];

fn measured_values(findings: &[&Violation]) -> Vec<i64> {
    let mut values: Vec<i64> = findings.iter().map(|finding| finding.measured).collect();
    values.sort_unstable();
    values
}

#[test]
fn every_registered_drc_family_has_a_gds_fixture() {
    let manifest = manifest();
    let actual: BTreeSet<&str> = cases(&manifest, "drc")
        .iter()
        .map(|case| case_string(case, "rule"))
        .collect();
    let expected: BTreeSet<&str> = COVERED_RULES.into_iter().collect();

    assert_eq!(actual, expected, "DRC fixture inventory drifted");
    assert_eq!(cases(&manifest, "drc").len(), 94);

    let deck = deck();
    assert_eq!(
        deck.drc_rules.len(),
        28,
        "the fixture deck should mount all 27 variants plus well enclosure"
    );
    assert_eq!(
        gdsverify::drc::rules::FACTORIES.len(),
        26,
        "a DRC factory was added or removed; update the fixture matrix"
    );
}

#[test]
fn drc_gds_conformance_matches_expected_markers_and_measurements() {
    let manifest = manifest();
    let deck = deck();
    let mut failures = Vec::new();

    for case in cases(&manifest, "drc") {
        let id = case_string(case, "id");
        let rule = case_string(case, "rule");
        let expected_count = case["expect_violations"]
            .as_u64()
            .unwrap_or_else(|| panic!("{id}: expect_violations must be an integer"))
            as usize;
        let strict = case
            .get("strict")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let store = load_case_store("drc", case, &deck);
        let report = run_drc_backend_strict(&store, &deck, Backend::Cpu, strict);
        let findings: Vec<&Violation> = report
            .violations
            .iter()
            .filter(|finding| finding.kind == rule)
            .collect();

        if findings.len() != expected_count {
            failures.push(format!(
                "{id}: {rule} marker count {} != {expected_count}; all findings={}",
                findings.len(),
                report.to_canonical_json()
            ));
            continue;
        }
        if expected_count == 0 {
            continue;
        }

        let expected_findings = case["violations"]
            .as_array()
            .unwrap_or_else(|| panic!("{id}: violations must be an array"));
        let mut expected_measured: Vec<i64> = expected_findings
            .iter()
            .filter_map(|finding| finding.get("measured").and_then(|value| value.as_i64()))
            .collect();
        if !expected_measured.is_empty() {
            expected_measured.sort_unstable();
            let mut unmatched = measured_values(&findings);
            let all_present = expected_measured.iter().all(|expected| {
                unmatched
                    .iter()
                    .position(|got| got == expected)
                    .is_some_and(|index| {
                        unmatched.remove(index);
                        true
                    })
            });
            if !all_present {
                failures.push(format!(
                    "{id}: measured {:?} does not contain expected {expected_measured:?}",
                    measured_values(&findings)
                ));
            }
        }

        if let Some(expected_fraction) = expected_findings
            .first()
            .and_then(|finding| finding.get("measured_frac"))
            .and_then(|value| value.as_f64())
        {
            let got = findings[0].measured as f64 / 1_000_000.0;
            if (got - expected_fraction).abs() > 1.0e-4 {
                failures.push(format!(
                    "{id}: density fraction {got:.6} != {expected_fraction:.6}"
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} DRC fixture(s) failed:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

#[test]
fn drc_reports_are_deterministic_for_every_fixture() {
    let manifest = manifest();
    let deck = deck();
    for case in cases(&manifest, "drc") {
        let id = case_string(case, "id");
        let strict = case
            .get("strict")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let store = load_case_store("drc", case, &deck);
        let first = run_drc_backend_strict(&store, &deck, Backend::Cpu, strict).to_canonical_json();
        let second =
            run_drc_backend_strict(&store, &deck, Backend::Cpu, strict).to_canonical_json();
        assert_eq!(first, second, "{id}: DRC report is nondeterministic");
    }
}

#[test]
fn klayout_native_drc_oracle_matches_directly_mappable_rules() {
    let Ok(klayout) = std::env::var("KLAYOUT_BIN") else {
        eprintln!("KLAYOUT_BIN is not set; skipping live KLayout DRC parity");
        return;
    };
    let manifest = manifest();
    let fixture_root = common::fixture_root();
    let oracle = fixture_root.join("klayout/drc_oracle.rb");
    let directly_mappable: BTreeSet<&str> = [
        "min_width",
        "min_spacing",
        "min_spacing_diff",
        "min_enclosure",
        "min_area",
        "max_width",
        "notch",
        "off_grid",
        "overlap",
    ]
    .into_iter()
    .collect();
    let mut failures = Vec::new();
    let mut ran = 0usize;

    for case in cases(&manifest, "drc") {
        let id = case_string(case, "id");
        let rule = case_string(case, "rule");
        if !directly_mappable.contains(rule)
            || case.get("strict").and_then(|value| value.as_bool()) == Some(true)
            || id == "DRC_FUZZ_ZERO_W"
        {
            continue;
        }
        ran += 1;
        let gds = fixture_root.join("drc").join(format!("{id}.gds"));
        let output = Command::new(&klayout)
            .args(["-b", "-r"])
            .arg(&oracle)
            .env("GPUVERIFY_GDS", &gds)
            .env("GPUVERIFY_RULE", rule)
            .env("GPUVERIFY_CASE", id)
            .output()
            .unwrap_or_else(|error| panic!("launch KLayout for {id}: {error}"));
        if !output.status.success() {
            failures.push(format!(
                "{id}: KLayout failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
            continue;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let payload = stdout
            .lines()
            .find_map(|line| line.strip_prefix("GPUVERIFY_KLAYOUT "));
        let Some(payload) = payload else {
            failures.push(format!("{id}: KLayout emitted no oracle record: {stdout}"));
            continue;
        };
        let oracle_result: serde_json::Value = serde_json::from_str(payload)
            .unwrap_or_else(|error| panic!("{id}: parse KLayout oracle JSON: {error}"));
        let got = oracle_result["count"]
            .as_u64()
            .unwrap_or_else(|| panic!("{id}: KLayout count must be an integer"))
            as usize;
        let expected = case["expect_violations"].as_u64().expect("manifest count") as usize;
        if got != expected {
            failures.push(format!(
                "{id}: KLayout {rule} count {got} != GPUVerify golden {expected}"
            ));
        }
    }

    assert!(ran >= 35, "live KLayout parity ran only {ran} fixture(s)");
    assert!(
        failures.is_empty(),
        "{} KLayout parity fixture(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
