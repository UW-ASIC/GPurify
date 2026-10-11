//! The numbers the docs state, recomputed from the code and the corpus.
//!
//! A count written in prose is an output like any other, and these went stale:
//! README said 24 design-rule kinds while the code had 35, and a `counts` block
//! stored in `expectations.json` drifted from the cases beside it. So every
//! number a doc states about the code or the corpus is computed here, and a
//! change to either fails this until the doc says the same.
//!
//! Oracle: the code's own kind tables and the cases in `expectations.json`.
//! Each assertion builds the exact sentence or table row the doc must contain,
//! so a failure names the doc to fix and what it should now say.

use gpurify_check::{drc, erc};
use serde_json::Value;
use std::path::Path;

const DOMAINS: [&str; 4] = ["drc", "erc", "lvs", "pex"];

/// The `corroboration` values, in the fixtures README's column order.
const CORROBORATION: [&str; 6] = [
    "manifest_agrees",
    "manifest_count_only",
    "manifest_disagrees",
    "manifest_partial",
    "manifest_uncheckable",
    "none",
];

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|why| panic!("{}: {why}", path.display()))
}

/// Every case of every domain, by domain.
fn corpus() -> Vec<(&'static str, Vec<Value>)> {
    let expectations: Value = serde_json::from_str(&read("tests/fixtures/expectations.json"))
        .expect("expectations.json is JSON");
    DOMAINS
        .iter()
        .map(|&domain| {
            let cases = expectations[domain]["cases"]
                .as_array()
                .unwrap_or_else(|| panic!("expectations.json has no {domain}.cases"));
            (domain, cases.clone())
        })
        .collect()
}

fn all_cases(corpus: &[(&str, Vec<Value>)]) -> Vec<Value> {
    corpus.iter().flat_map(|(_, cases)| cases.clone()).collect()
}

/// How many `cases` have `field` equal to `value`.
fn count(cases: &[Value], field: &str, value: &str) -> u64 {
    u64::try_from(
        cases
            .iter()
            .filter(|case| case[field].as_str() == Some(value))
            .count(),
    )
    .expect("a case count fits in u64")
}

/// Every distinct string `field` takes, sorted; cases without one are skipped.
fn values_of(cases: &[Value], field: &str) -> Vec<String> {
    let mut values: Vec<String> = cases
        .iter()
        .filter_map(|case| case[field].as_str().map(str::to_owned))
        .collect();
    values.sort_unstable();
    values.dedup();
    values
}

/// Every unsigned integer written in `text`, in order.
fn numbers(text: &str) -> Vec<u64> {
    text.split(|c: char| !c.is_ascii_digit())
        .filter(|run| !run.is_empty())
        .map(|run| run.parse().expect("a run of ASCII digits"))
        .collect()
}

/// The one line of `doc` starting with `prefix`.
fn line<'a>(doc: &'a str, name: &str, prefix: &str) -> &'a str {
    let mut found = doc.lines().filter(|text| text.starts_with(prefix));
    let first = found
        .next()
        .unwrap_or_else(|| panic!("{name}: no line starts with {prefix:?}"));
    assert!(
        found.next().is_none(),
        "{name}: more than one line starts with {prefix:?}"
    );
    first
}

/// The last number on the one line of `doc` starting with `prefix`.
fn last_number(doc: &str, name: &str, prefix: &str) -> u64 {
    let text = line(doc, name, prefix);
    *numbers(text)
        .last()
        .unwrap_or_else(|| panic!("{name}: {text:?} states no number"))
}

fn assert_says(doc: &str, name: &str, sentence: &str) {
    assert!(doc.contains(sentence), "{name} should say: {sentence:?}");
}

/// Oracle: the code's own kind tables, `drc::ruleset::KINDS` and
/// `erc::ruleset::KINDS`, counted into the sentence README must hold.
#[test]
fn the_readme_counts_the_rule_kinds_the_code_has() {
    let readme = read("README.md");
    assert_says(
        &readme,
        "README.md",
        &format!(
            "There are {} design-rule kinds and {} electrical-rule kinds.",
            drc::ruleset::KINDS.len(),
            erc::ruleset::KINDS.len()
        ),
    );
}

/// The README's shipped-deck table, recomputed from the decks `gpurify::pdks`
/// compiles in: how many ship, and per deck its drawn layers, rules (each
/// `for` iteration a rule) and device recognisers. Breaks when a deck gains
/// or loses a layer, rule or device and the README row does not follow.
/// Oracle: the decks as the parser reads them.
#[test]
fn the_readme_deck_table_is_the_shipped_decks() {
    use gpurify::geom::{Grid, LayerId, StrTable};

    const WORDS: [&str; 10] = [
        "No", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine",
    ];
    let readme = read("README.md");
    let shipped = gpurify::pdks::ALL;
    assert_says(
        &readme,
        "README.md",
        &format!("{} decks ship in `pdks/`", WORDS[shipped.len()]),
    );
    let grid = Grid::new(1000).expect("1000 database units per micrometre is a grid");
    for (name, text) in shipped {
        let mut strings = StrTable::default();
        let deck = gpurify::ingest::deck::parse_deck(text, grid, &mut strings)
            .unwrap_or_else(|why| panic!("{name} does not parse: {why}"));
        let drawn = (0..deck.layers.len())
            .map(|id| LayerId(u16::try_from(id).expect("a LayerId is a u16")))
            .filter(|&layer| !deck.layers.is_derived(layer))
            .count();
        let want = [drawn, deck.rules.spec.len(), deck.devices.kind.len()].map(|n| n as u64);
        let row = numbers(line(&readme, "README.md", &format!("| `{name}`")));
        assert_eq!(
            row[row.len().saturating_sub(3)..],
            want,
            "README.md: the {name} row should state {} drawn layers, {} rules and {} devices",
            want[0],
            want[1],
            want[2]
        );
    }
}

/// Oracle: the cases in `tests/fixtures/expectations.json`, counted in total
/// and per domain, against the numbers README states.
#[test]
fn the_readme_accuracy_section_is_the_corpus() {
    let readme = read("README.md");
    let corpus = corpus();
    let cases = all_cases(&corpus);
    let total = cases.len();

    assert_says(
        &readme,
        "README.md",
        &format!("tested against {total} GDSII cells"),
    );
    assert_says(
        &readme,
        "README.md",
        &format!("All {total} agree with their expected answer."),
    );

    for (domain, domain_cases) in &corpus {
        let bar = format!("{}   ", domain.to_uppercase());
        assert_eq!(
            last_number(&readme, "README.md", &bar),
            domain_cases.len() as u64,
            "README.md: the {domain} bar"
        );
    }

    let agree = count(&cases, "corroboration", "manifest_agrees");
    let disagree = count(&cases, "corroboration", "manifest_disagrees");
    assert_says(&readme, "README.md", &format!("{agree} agree, so two"));
    assert_says(
        &readme,
        "README.md",
        &format!("{disagree} disagree, and each"),
    );

    // Every grade the corpus uses has a bar, and each bar is its count.
    for strength in values_of(&cases, "strength") {
        assert_eq!(
            last_number(&readme, "README.md", &format!("{strength} ")),
            count(&cases, "strength", &strength),
            "README.md: the {strength} bar"
        );
    }
}

/// Oracle: the cases in `tests/fixtures/expectations.json`, counted per domain,
/// strength, corroboration and the outcome and examined guard, against the
/// fixtures README's table and sentences.
#[test]
fn the_fixtures_readme_is_the_corpus() {
    const NAME: &str = "tests/fixtures/README.md";
    let doc = read(NAME);
    let corpus = corpus();
    let cases = all_cases(&corpus);

    let sizes: Vec<String> = corpus.iter().map(|(_, c)| c.len().to_string()).collect();
    assert_says(
        &doc,
        NAME,
        &format!("{} single-case extracts", sizes.join(" + ")),
    );

    for strength in values_of(&cases, "strength") {
        assert_eq!(
            last_number(&doc, NAME, &format!("| `{strength}` |")),
            count(&cases, "strength", &strength),
            "{NAME}: the {strength} row"
        );
    }

    // A new corroboration value needs a new column before it can be counted.
    for value in values_of(&cases, "corroboration") {
        assert!(
            CORROBORATION.contains(&value.as_str()),
            "{NAME}: corroboration {value:?} has no column"
        );
    }
    let row = |domain_cases: &[Value]| -> Vec<u64> {
        std::iter::once(domain_cases.len() as u64)
            .chain(
                CORROBORATION
                    .iter()
                    .map(|value| count(domain_cases, "corroboration", value)),
            )
            .collect()
    };
    for (domain, domain_cases) in &corpus {
        let text = line(&doc, NAME, &format!("| {domain} |"));
        assert_eq!(numbers(text), row(domain_cases), "{NAME}: the {domain} row");
    }
    let text = line(&doc, NAME, "| **total** | **");
    assert_eq!(numbers(text), row(&cases), "{NAME}: the total row");

    for dispute in values_of(&cases, "dispute") {
        assert_eq!(
            last_number(&doc, NAME, &format!("| `{dispute}` |")),
            count(&cases, "dispute", &dispute),
            "{NAME}: the {dispute} row"
        );
    }
    // The no-vacuous-pass guard: a case without both can pass on a check
    // that ran over nothing (testing-plan F6).
    let guarded = cases
        .iter()
        .filter(|case| !case["expect_outcome"].is_null() && !case["examined_min"].is_null())
        .count();
    assert_says(
        &doc,
        NAME,
        &format!(
            "{guarded} of {} cases carry `expect_outcome` and `examined_min`",
            cases.len()
        ),
    );

    let disputed = cases
        .iter()
        .filter(|case| case["dispute"].is_string())
        .count();
    assert_eq!(
        last_number(&doc, NAME, "| **total** | |"),
        disputed as u64,
        "{NAME}: the dispute total"
    );
}
