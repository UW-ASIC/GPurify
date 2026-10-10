//! Exhaustive generated fixtures: proof, check kind by check kind, that DRC,
//! ERC, LVS and PEX do what their definitions say.
//!
//! Every fixture is generated, not drawn by hand, from the rule's definition:
//! the limit swept one grid step either side, every symmetry of the square,
//! translations, and the shapes a plausible wrong implementation gets wrong.
//! Small domains are enumerated outright against an independent reference: a
//! bitmap DRC, a brute-force graph isomorphism for LVS, closed forms for ERC and
//! PEX. Each fixture names the catalog rows (`docs/check-catalog.tsv`) it
//! proves, and `every_catalog_row_of_a_complete_domain_is_proved` holds the
//! catalog to it.
//!
//! `cargo test --test exhaustive` runs the merge depth;
//! `cargo test --test exhaustive -- --ignored` the full enumerations.

mod bitmap;
mod corpus;
mod drc_dimension;
mod drc_overlay;
mod erc;
mod harness;
mod lvs;
mod pex;

#[path = "../common/gen_fixtures.rs"]
mod gen_fixtures;

use harness::{Depth, Fixture};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

/// The domains whose fixtures are finished: every implemented, partial and
/// expressible catalog row of these must be proved by at least one fixture, or
/// by a named test in [`PROVED_BY_TEST`].
const COMPLETE: &[&str] = &["pex"];

/// Catalog rows whose claim a fixture cannot state, and the `#[test]` in this
/// binary that proves each.
const PROVED_BY_TEST: &[(&str, &str)] = &[("PEX-010", "pex::spef_carries_the_closed_form_totals")];

fn all(depth: Depth) -> Vec<Fixture> {
    [
        drc_dimension::fixtures(depth),
        drc_overlay::fixtures(depth),
        bitmap::fixtures(depth),
        erc::fixtures(depth),
        lvs::fixtures(depth),
        pex::fixtures(depth),
        corpus::fixtures(depth),
    ]
    .concat()
}

/// Runs every fixture on all cores, and fails listing every broken one.
fn run_all(fixtures: &[Fixture]) {
    let next = Mutex::new(0usize);
    let failures = Mutex::new(Vec::new());
    let workers = std::thread::available_parallelism().map_or(4, usize::from);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let fixture = {
                    let mut next = next.lock().expect("not poisoned");
                    let Some(fixture) = fixtures.get(*next) else {
                        break;
                    };
                    *next += 1;
                    fixture
                };
                if let Some(failure) = harness::check(fixture) {
                    failures.lock().expect("not poisoned").push(failure);
                }
            });
        }
    });
    let mut failures = failures.into_inner().expect("not poisoned");
    failures.sort();
    let shown: Vec<&String> = failures.iter().take(60).collect();
    assert!(
        failures.is_empty(),
        "{} of {} fixtures failed{}:\n{}",
        failures.len(),
        fixtures.len(),
        if failures.len() > shown.len() {
            " (first 60)"
        } else {
            ""
        },
        shown
            .iter()
            .map(|f| f.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn every_fixture_holds() {
    run_all(&all(Depth::Merge));
}

/// The nightly list, built once: every fixture holds, and the structural checks
/// the merge tier makes on its sample hold for the whole list.
#[test]
#[ignore = "nightly: every enumeration in full"]
fn every_fixture_holds_at_nightly_depth() {
    let fixtures = all(Depth::Nightly);
    names_are_unique_and_prove_a_row(&fixtures);
    complete_domains_are_proved(&fixtures);
    known_failures_name_open_findings(&fixtures);
    run_all(&fixtures);
}

#[test]
fn fixture_names_are_unique_and_every_fixture_proves_a_catalog_row() {
    names_are_unique_and_prove_a_row(&all(Depth::Merge));
}

/// Every implemented, partial and expressible row of a finished domain has a
/// fixture that proves it, and every row a fixture names exists.
#[test]
fn every_catalog_row_of_a_complete_domain_is_proved() {
    complete_domains_are_proved(&all(Depth::Merge));
}

/// Every expected failure names a finding the testing plan records and has not
/// fixed: a fixture marked for a fixed finding must be flipped to pass, and an
/// unrecorded id is a finding nobody will look for.
#[test]
fn every_known_failure_names_an_open_finding() {
    known_failures_name_open_findings(&all(Depth::Merge));
}

fn names_are_unique_and_prove_a_row(fixtures: &[Fixture]) {
    let mut seen = BTreeSet::new();
    for fixture in fixtures {
        assert!(
            !fixture.catalog.is_empty(),
            "{} proves no catalog row",
            fixture.name
        );
        assert!(
            !fixture.expect.is_empty(),
            "{} claims nothing",
            fixture.name
        );
        assert!(
            seen.insert(fixture.name.clone()),
            "{} is generated twice",
            fixture.name
        );
    }
}

fn complete_domains_are_proved(fixtures: &[Fixture]) {
    let catalog = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/check-catalog.tsv"),
    )
    .expect("the catalog is readable");
    let rows: BTreeMap<String, (String, String)> = catalog
        .lines()
        .skip(1)
        .map(|line| {
            let cells: Vec<&str> = line.split('\t').collect();
            (
                cells[0].to_owned(),
                (cells[1].to_owned(), cells[6].to_owned()),
            )
        })
        .collect();
    let mut proved: BTreeMap<&str, usize> = BTreeMap::new();
    for fixture in fixtures {
        for id in &fixture.catalog {
            assert!(
                rows.contains_key(*id),
                "{}: catalog row {id} does not exist",
                fixture.name
            );
            *proved.entry(id).or_default() += 1;
        }
    }
    for (id, test) in PROVED_BY_TEST {
        let (module, name) = test.split_once("::").expect("module::test");
        let source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("tests/exhaustive/{module}.rs")),
        )
        .expect("the module is readable");
        assert!(
            source.contains(&format!("fn {name}()")),
            "{id}: no test {test}"
        );
        *proved.entry(id).or_default() += 1;
    }
    let missing: Vec<&String> = rows
        .iter()
        .filter(|(_, (domain, status))| {
            COMPLETE.contains(&domain.as_str())
                && matches!(status.as_str(), "implemented" | "partial" | "expressible")
        })
        .map(|(id, _)| id)
        .filter(|id| !proved.contains_key(id.as_str()))
        .collect();
    assert!(missing.is_empty(), "rows no fixture proves: {missing:?}");
}

fn known_failures_name_open_findings(fixtures: &[Fixture]) {
    let plan = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/testing-plan.md"),
    )
    .expect("the testing plan is readable");
    let open: BTreeMap<&str, bool> = plan
        .lines()
        .filter_map(|line| {
            let id = line.strip_prefix("| ")?.split(' ').next()?;
            (id.starts_with('F') && id[1..].parse::<u32>().is_ok())
                .then(|| (id, !line.contains("**Fixed in")))
        })
        .collect();
    let mut bad: BTreeMap<&str, String> = BTreeMap::new();
    for fixture in fixtures {
        let Some(id) = fixture.known else { continue };
        let why = match open.get(id) {
            Some(true) => continue,
            Some(false) => "is fixed",
            None => "is not in the findings table",
        };
        bad.entry(id)
            .or_insert_with(|| format!("{why} (first fixture: {})", fixture.name));
    }
    assert!(bad.is_empty(), "{bad:#?}");
}
