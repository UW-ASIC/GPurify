mod common;

use common::{case_string, cases, deck, load_case_store, manifest};
use gdsverify::{run_erc, CheckStatus, SignoffCheck, SignoffConfig};
use std::collections::BTreeSet;

const COVERED_CHECKS: [&str; 13] = [
    "antenna_electrical",
    "em_current_density",
    "esd_missing",
    "floating_gate",
    "floating_well",
    "hv_domain_crossing",
    "missing_tie",
    "multiple_drivers",
    "p2p_resistance",
    "soft_connection",
    "supply_short",
    "tie_high_low",
    "unconnected_pin",
];

#[test]
fn every_layout_derived_erc_check_has_a_gds_fixture() {
    let manifest = manifest();
    let actual: BTreeSet<&str> = cases(&manifest, "erc")
        .iter()
        .map(|case| case_string(case, "check"))
        .collect();
    let expected: BTreeSet<&str> = COVERED_CHECKS.into_iter().collect();
    assert_eq!(actual, expected, "ERC fixture inventory drifted");
    assert_eq!(cases(&manifest, "erc").len(), 23);

    // Thirteen heuristic factories plus six always-mounted typed signoff
    // factories. A registry change must be accompanied by fixture planning.
    assert_eq!(gdsverify::erc::rules::FACTORIES.len(), 19);
}

#[test]
fn erc_gds_conformance_matches_expected_findings() {
    let manifest = manifest();
    let deck = deck();
    let mut failures = Vec::new();

    for case in cases(&manifest, "erc") {
        let id = case_string(case, "id");
        let check = case_string(case, "check");
        let expected = case["expect_violations"]
            .as_u64()
            .unwrap_or_else(|| panic!("{id}: expect_violations must be an integer"))
            as usize;
        let store = load_case_store("erc", case, &deck);
        let report = run_erc(&store, &deck, &SignoffConfig::default());
        let findings = report.by_check(check);
        if findings.len() != expected {
            failures.push(format!(
                "{id}: {check} finding count {} != {expected}; report={}",
                findings.len(),
                serde_json::to_string_pretty(&report).expect("serialize ERC report")
            ));
        }

        for signoff in report.signoff.checks() {
            // Fabrication-stage antenna can derive its complete input from the
            // deck and layout. The other typed analyses require explicit CMP,
            // power, reliability, or ESD stimulus.
            if signoff.check == SignoffCheck::Antenna {
                continue;
            }
            if signoff.status != CheckStatus::NotRun {
                failures.push(format!(
                    "{id}: {:?} should fail closed as NotRun without qualified stimulus, got {:?}",
                    signoff.check, signoff.status
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} ERC fixture assertion(s) failed:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
