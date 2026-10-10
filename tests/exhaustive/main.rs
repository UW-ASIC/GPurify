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
mod drc_dimension;
mod drc_overlay;
mod erc;
mod harness;
mod lvs;
mod pex;

use harness::{Depth, Fixture};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

/// The domains whose fixtures are finished: every implemented, partial and
/// expressible catalog row of these must be proved by at least one fixture.
const COMPLETE: &[&str] = &[];

fn all(depth: Depth) -> Vec<Fixture> {
    [
        drc_dimension::fixtures(depth),
        drc_overlay::fixtures(depth),
        bitmap::fixtures(depth),
        erc::fixtures(depth),
        lvs::fixtures(depth),
        pex::fixtures(depth),
    ]
    .concat()
}

/// Runs every fixture on all cores, and fails listing every broken one.
fn run_all(depth: Depth) {
    let fixtures = all(depth);
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
    run_all(Depth::Merge);
}

#[test]
#[ignore = "nightly: every enumeration in full"]
fn every_fixture_holds_at_nightly_depth() {
    run_all(Depth::Nightly);
}

#[test]
fn fixture_names_are_unique_and_every_fixture_proves_a_catalog_row() {
    let mut seen = BTreeSet::new();
    for fixture in all(Depth::Nightly) {
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

/// Every implemented, partial and expressible row of a finished domain has a
/// fixture that proves it, and every row a fixture names exists.
#[test]
fn every_catalog_row_of_a_complete_domain_is_proved() {
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
    let fixtures = all(Depth::Nightly);
    for fixture in &fixtures {
        for id in &fixture.catalog {
            assert!(
                rows.contains_key(*id),
                "{}: catalog row {id} does not exist",
                fixture.name
            );
            *proved.entry(id).or_default() += 1;
        }
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
