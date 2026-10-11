//! Exhaustive generated fixtures: proof, check kind by check kind, that DRC,
//! ERC, LVS and PEX do what their definitions say.
//!
//! Every fixture is generated, not drawn by hand, from the rule's definition:
//! the limit swept one grid step either side, every symmetry of the square,
//! translations, and the shapes a plausible wrong implementation gets wrong.
//! Small domains are enumerated outright against an independent reference: a
//! bitmap DRC, a brute-force graph isomorphism for LVS, closed forms for ERC and
//! PEX. Each fixture names the catalog rows (`docs/check-catalog.tsv`) it
//! proves, and `every_supported_catalog_row_is_proved` holds the catalog to
//! it. Two ERC references run on generated inputs outside the
//! fixture table (`erc_reference`): a dense nodal solve of supply grids and a
//! search of extracted net graphs.
//!
//! `cargo test --test exhaustive` runs the merge depth;
//! `cargo test --test exhaustive -- --ignored` the full enumerations.

mod bitmap;
mod corpus;
mod drc_dimension;
mod drc_overlay;
mod erc;
mod erc_reference;
mod flow;
mod harness;
mod lvs;
mod pex;
mod xor;

#[path = "../common/gen_fixtures.rs"]
mod gen_fixtures;

use harness::{Depth, Fixture};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

/// Catalog rows whose claim a fixture cannot state, and the `#[test]` that
/// proves each, as `file::function` from the repository root. The test's
/// doc comment names the row.
///
/// With these, every implemented, partial and expressible row of every
/// domain, flow included, is proved by a fixture or a named test.
const PROVED_BY_TEST: &[(&str, &str)] = &[
    (
        "PEX-010",
        "tests/exhaustive/pex.rs::spef_carries_the_closed_form_totals",
    ),
    // A fixture holds one layout; xor compares two.
    (
        "DRC-068",
        "tests/exhaustive/xor.rs::a_lost_and_a_slotted_cut_add_up_to_the_cut_area_lost",
    ),
    (
        "PEX-009",
        "tests/exhaustive/pex.rs::a_qualification_of_rc_against_rcc_finds_every_net_s_totals_unchanged",
    ),
    (
        "PEX-006",
        "tests/exhaustive/pex.rs::process_corners_extract_at_their_own_values",
    ),
    // The harness writes one flat cell; flattening is proved where it is done.
    (
        "DRC-123",
        "crates/ingest/src/layout.rs::a_mirror_composed_with_each_quarter_turn_still_flattens_counter_clockwise",
    ),
    // 45-degree shapes are drawn as polygons; the harness draws rectangles.
    (
        "DRC-038",
        "tests/drc_octilinear.rs::two_45_degree_bars_are_as_far_apart_as_their_lines",
    ),
    // Live DRC is a library consumer's loop, not a run of the CLI.
    (
        "FLOW-005",
        "tests/engine/main.rs::a_consumer_checks_each_edit_against_one_shared_deck",
    ),
    // A custom rule is the user's Rust function, run by the engine.
    (
        "FLOW-006",
        "tests/engine/custom.rs::a_binary_s_own_deck_runs_its_custom_rules_by_name",
    ),
    // A system is several dies, which one fixture's single layout cannot hold.
    (
        "LVS-073",
        "tests/exhaustive/lvs/system.rs::a_two_die_stack_matches_and_a_missing_or_misordered_bump_does_not",
    ),
    (
        "ERC-C12",
        "tests/exhaustive/lvs/system.rs::die_to_die_and_package_pins_need_their_esd_paths",
    ),
    (
        "ERC-C13",
        "tests/exhaustive/lvs/system.rs::a_system_pin_needs_a_system_rated_clamp",
    ),
];

fn all(depth: Depth) -> Vec<Fixture> {
    [
        drc_dimension::fixtures(depth),
        drc_overlay::fixtures(depth),
        bitmap::fixtures(depth),
        erc::fixtures(depth),
        lvs::fixtures(depth),
        pex::fixtures(depth),
        flow::fixtures(depth),
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

/// Oracle: each fixture's expected answer, derived from the rule's definition:
/// the limit one grid step either side, under every symmetry and translation,
/// or the independent references the module doc names (the bitmap DRC,
/// brute-force isomorphism, closed forms), at the merge depth.
#[test]
fn every_fixture_holds() {
    run_all(&all(Depth::Merge));
}

/// The nightly list, built once: every fixture holds, and the structural checks
/// the merge tier makes on its sample hold for the whole list.
///
/// Oracle: each fixture's expected answer, derived from the rule's definition:
/// the limit one grid step either side, under every symmetry and translation,
/// or the independent references the module doc names (the bitmap DRC,
/// brute-force isomorphism, closed forms), every enumeration in full; and the
/// structural checks below over the whole list.
#[test]
#[ignore = "nightly: every enumeration in full"]
fn every_fixture_holds_at_nightly_depth() {
    let fixtures = all(Depth::Nightly);
    names_are_unique_and_prove_a_row(&fixtures);
    supported_rows_are_proved(&fixtures);
    known_failures_name_open_findings(&fixtures);
    run_all(&fixtures);
}

/// Oracle: the catalog's ids (`docs/check-catalog.tsv`): each fixture's name is
/// unique and every row it claims exists.
#[test]
fn fixture_names_are_unique_and_every_fixture_proves_a_catalog_row() {
    names_are_unique_and_prove_a_row(&all(Depth::Merge));
}

/// Every implemented, partial and expressible catalog row, in every domain,
/// has a fixture or a named test that proves it (A5), and every row a
/// fixture names exists.
///
/// Oracle: the catalog's rows: each implemented, partial and expressible row
/// of every domain, flow included, is named by a fixture or in
/// `PROVED_BY_TEST`, whose test's doc comment names the row.
#[test]
fn every_supported_catalog_row_is_proved() {
    supported_rows_are_proved(&all(Depth::Merge));
}

/// Every expected failure names a finding the testing plan records and has not
/// fixed: a fixture marked for a fixed finding must be flipped to pass, and an
/// unrecorded id is a finding nobody will look for.
///
/// Oracle: the testing plan's findings table: each expected failure names a
/// finding recorded there and not marked fixed.
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

fn supported_rows_are_proved(fixtures: &[Fixture]) {
    let catalog = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/check-catalog.tsv"),
    )
    .expect("the catalog is readable");
    // Row id to status.
    let rows: BTreeMap<String, String> = catalog
        .lines()
        .skip(1)
        .map(|line| {
            let cells: Vec<&str> = line.split('\t').collect();
            (cells[0].to_owned(), cells[6].to_owned())
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
        let (file, name) = test.rsplit_once("::").expect("file::test");
        let source =
            std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file))
                .expect("the file is readable");
        let at = source
            .find(&format!("fn {name}()"))
            .unwrap_or_else(|| panic!("{id}: no test {test}"));
        // The doc comment and attributes right above it.
        let named = source[..at]
            .trim_end()
            .lines()
            .rev()
            .take_while(|line| {
                let line = line.trim_start();
                line.starts_with("///") || line.starts_with("#[")
            })
            .any(|line| line.contains(id));
        assert!(
            named,
            "{id}: the doc comment of {test} does not name the row"
        );
        *proved.entry(id).or_default() += 1;
    }
    let missing: Vec<&String> = rows
        .iter()
        .filter(|(_, status)| matches!(status.as_str(), "implemented" | "partial" | "expressible"))
        .map(|(id, _)| id)
        .filter(|id| !proved.contains_key(id.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "rows no fixture or named test proves: {missing:?}"
    );
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

/// The catalog names the evidence its fixtures give, so its oracle column is
/// a record of what is proved, not a plan: `SY` for every row a synthetic
/// fixture with a hand-derived answer proves, `MR` where the fixture is also
/// placed under the square's symmetries or is a corpus relation, and `BM`
/// where the bitmap reference decides it.
///
/// Oracle: the fixtures themselves: a row a synthetic fixture proves must carry
/// `SY`, one under the symmetries `MR`, one the bitmap decides `BM`, in the
/// catalog's oracle column.
#[test]
fn the_catalog_names_the_evidence_its_fixtures_give() {
    let catalog = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/check-catalog.tsv"),
    )
    .expect("the catalog is readable");
    let oracles: BTreeMap<String, BTreeSet<String>> = catalog
        .lines()
        .skip(1)
        .map(|line| {
            let cells: Vec<&str> = line.split('\t').collect();
            let codes = cells[7]
                .split(';')
                .map(|code| code.trim().split(':').next().unwrap_or_default().to_owned())
                .collect();
            (cells[0].to_owned(), codes)
        })
        .collect();
    let symmetric = |name: &str| {
        name.split('/').any(|part| {
            ["r0", "r90", "r180", "r270", "m0", "m90", "m180", "m270"]
                .iter()
                .any(|s| part.starts_with(s))
        })
    };
    let mut missing: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for fixture in all(Depth::Merge) {
        let mut codes = Vec::new();
        if fixture.name.starts_with("corpus/") {
            codes.push("MR");
        } else {
            codes.push("SY");
            if symmetric(&fixture.name) {
                codes.push("MR");
            }
        }
        if fixture.name.starts_with("bitmap/") {
            codes.push("BM");
        }
        for id in &fixture.catalog {
            let have = oracles.get(*id).expect("the row exists");
            for code in &codes {
                if !have.contains(*code) {
                    missing.entry(id).or_default().insert(code);
                }
            }
        }
    }
    assert!(
        missing.is_empty(),
        "catalog rows whose oracle column omits evidence a fixture gives:\n{}",
        missing
            .iter()
            .map(|(id, codes)| format!(
                "{id}\t{}",
                codes.iter().copied().collect::<Vec<_>>().join(",")
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
