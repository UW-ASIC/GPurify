//! The check catalog against the code.
//!
//! `docs/check-catalog.tsv` lists every check kind a signoff verifier must
//! handle, one row per kind, with the sources that define it
//! (`docs/check-sources.md`) and what the code has for it. This keeps it, the
//! code and the user docs from drifting apart:
//!
//! - every kind the catalog names exists in the code, and every kind the code
//!   has is in the catalog, so nothing ships undocumented and nothing is
//!   claimed that does not exist;
//! - every check the catalog marks `missing` or `partial` is listed in
//!   `docs/limitations.md`, so a clean report can be read for what it is;
//! - the status counts `check-sources.md` states are the catalog's.
//!
//! Oracle: the code's own kind lists (`drc::ruleset::KINDS`,
//! `erc::ruleset::KINDS`, `lvs::RULE_IDS`). The limitations block is generated:
//! when it is stale this test rewrites it and fails, so the change is reviewed
//! and committed like a golden file.

use gpurify_check::{drc, erc, lvs};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const STATUSES: [&str; 6] = [
    "implemented",
    "expressible",
    "partial",
    "missing",
    "verify",
    "out_of_scope",
];

/// Feature tags in the `gpurify` column: a capability, not a rule kind.
const TAGS: [&str; 6] = ["deck:", "erc:", "lvs:", "pex:", "ingest:", "lib:"];

/// The domains in the order the docs list them, with their headings.
const DOMAINS: [(&str, &str); 5] = [
    ("drc", "Design rules (DRC)"),
    ("lvs", "Layout against schematic (LVS)"),
    ("erc", "Electrical rules (ERC)"),
    ("pex", "Parasitic extraction (PEX)"),
    ("flow", "Flow"),
];

const BEGIN: &str =
    "<!-- generated from docs/check-catalog.tsv by tests/catalog.rs; edit the catalog, not this block -->";
const END: &str = "<!-- end of generated block -->";

struct Row {
    id: String,
    domain: String,
    check: String,
    gpurify: Vec<String>,
    status: String,
    sources: String,
    oracle: String,
    notes: String,
}

fn path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read(relative: &str) -> String {
    let path = path(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|why| panic!("{}: {why}", path.display()))
}

fn catalog() -> Vec<Row> {
    let text = read("docs/check-catalog.tsv");
    let mut lines = text.lines();
    assert_eq!(
        lines.next(),
        Some("id\tdomain\tcategory\tcheck\tsources\tgpurify\tstatus\toracle\tnotes"),
        "the catalog's header row"
    );
    lines
        .map(|line| {
            let cells: Vec<&str> = line.split('\t').collect();
            assert_eq!(cells.len(), 9, "nine columns: {line}");
            Row {
                id: cells[0].to_owned(),
                domain: cells[1].to_owned(),
                check: cells[3].to_owned(),
                gpurify: cells[5]
                    .split(',')
                    .map(str::trim)
                    .filter(|name| !name.is_empty() && *name != "-")
                    .map(str::to_owned)
                    .collect(),
                status: cells[6].to_owned(),
                sources: cells[4].to_owned(),
                oracle: cells[7].to_owned(),
                notes: cells[8].to_owned(),
            }
        })
        .collect()
}

/// Every rule kind and report id the code has.
fn code_kinds() -> BTreeSet<&'static str> {
    drc::ruleset::KINDS
        .iter()
        .chain(&erc::ruleset::KINDS)
        .chain(&lvs::RULE_IDS)
        .copied()
        .collect()
}

#[test]
fn every_row_is_well_formed_and_resolved() {
    let rows = catalog();
    let mut ids = BTreeSet::new();
    for row in &rows {
        assert!(ids.insert(&row.id), "{}: the id appears twice", row.id);
        assert!(
            DOMAINS.iter().any(|(domain, _)| *domain == row.domain),
            "{}: unknown domain {:?}",
            row.id,
            row.domain
        );
        assert!(
            STATUSES.contains(&row.status.as_str()),
            "{}: unknown status {:?}",
            row.id,
            row.status
        );
        // `verify` is for research in progress, never for a committed catalog.
        assert_ne!(
            row.status, "verify",
            "{}: coverage is not yet known",
            row.id
        );
        if matches!(
            row.status.as_str(),
            "implemented" | "partial" | "expressible"
        ) {
            assert!(
                !row.gpurify.is_empty(),
                "{}: {} but names nothing in GPurify that covers it",
                row.id,
                row.status
            );
        }
        if matches!(row.status.as_str(), "partial" | "out_of_scope") {
            assert!(
                !row.notes.is_empty(),
                "{}: say what is missing, or why",
                row.id
            );
        }
    }
}

#[test]
fn every_kind_the_catalog_names_exists_in_the_code() {
    let known = code_kinds();
    for row in catalog() {
        for name in &row.gpurify {
            if TAGS.iter().any(|tag| name.starts_with(tag)) {
                continue;
            }
            assert!(
                known.contains(name.as_str()),
                "{}: names {name:?}, which is no rule kind or LVS report id in the code",
                row.id
            );
        }
    }
}

#[test]
fn every_kind_the_code_has_is_in_the_catalog() {
    let named: BTreeSet<String> = catalog().into_iter().flat_map(|row| row.gpurify).collect();
    for kind in code_kinds() {
        assert!(
            named.contains(kind),
            "{kind} exists in the code but no catalog row names it: add one"
        );
    }
}

/// The status-count table and the row total of check-sources.md, kept in step
/// with the catalog: a stale table is rewritten (so CI's `regenerated` artifact
/// carries it) and the test fails for review.
#[test]
fn check_sources_states_the_catalog_s_status_counts() {
    let file = path("docs/check-sources.md");
    let doc = read("docs/check-sources.md");
    let rows = catalog();
    let columns = [
        "implemented",
        "expressible",
        "partial",
        "missing",
        "verify",
        "out_of_scope",
    ];
    assert_eq!(columns, STATUSES, "the doc's column order");
    let total = rows.len();
    let mut lines: Vec<String> = doc.lines().map(str::to_owned).collect();
    let mut stale = Vec::new();
    for line in &mut lines {
        if line.starts_with("**Snapshot") && line.ends_with(" rows):") {
            let want = match line.rfind('(') {
                Some(open) => format!("{}({total} rows):", &line[..open]),
                None => line.clone(),
            };
            if *line != want {
                stale.push(want.clone());
                *line = want;
            }
        }
    }
    for (domain, _) in DOMAINS {
        let counts: Vec<String> = columns
            .iter()
            .map(|status| {
                rows.iter()
                    .filter(|row| row.domain == domain && row.status == *status)
                    .count()
                    .to_string()
            })
            .collect();
        let label = if domain == "flow" {
            "Flow".to_owned()
        } else {
            domain.to_uppercase()
        };
        let want = format!("| {label} | {} |", counts.join(" | "));
        let Some(line) = lines
            .iter_mut()
            .find(|line| line.starts_with(&format!("| {label} | ")))
        else {
            panic!("check-sources.md has no status-count row for {label}");
        };
        if *line != want {
            stale.push(want.clone());
            *line = want;
        }
    }
    if !stale.is_empty() {
        let mut updated = lines.join("\n");
        if doc.ends_with('\n') {
            updated.push('\n');
        }
        std::fs::write(&file, updated).expect("docs/check-sources.md is writable");
        panic!(
            "docs/check-sources.md's status counts were stale against the catalog; they are \
             rewritten: review and commit them:\n{}",
            stale.join("\n")
        );
    }
}

/// The limitations block as the catalog says it should read.
fn limitations_block(rows: &[Row]) -> String {
    let cell = |text: &str| {
        if text.is_empty() {
            "—".to_owned()
        } else {
            text.replace('|', "\\|")
        }
    };
    let mut out = format!("{BEGIN}\n");
    for (domain, heading) in DOMAINS {
        let listed: Vec<&Row> = rows
            .iter()
            .filter(|row| {
                row.domain == domain && matches!(row.status.as_str(), "missing" | "partial")
            })
            .collect();
        if listed.is_empty() {
            continue;
        }
        let _ = write!(
            out,
            "\n### {heading}\n\n| Id | Check | Status | What is missing |\n|---|---|---|---|\n"
        );
        for row in listed {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} |",
                row.id,
                cell(&row.check),
                row.status,
                cell(&row.notes)
            );
        }
    }
    let _ = write!(out, "\n{END}");
    out
}

#[test]
fn limitations_lists_every_missing_and_partial_check() {
    let file = path("docs/limitations.md");
    let doc = read("docs/limitations.md");
    let want = limitations_block(&catalog());
    let (Some(start), Some(end)) = (doc.find(BEGIN), doc.find(END)) else {
        panic!("docs/limitations.md has no generated block; add the {BEGIN} and {END} markers");
    };
    let have = &doc[start..end + END.len()];
    if have != want {
        let updated = format!("{}{want}{}", &doc[..start], &doc[end + END.len()..]);
        std::fs::write(&file, updated).expect("docs/limitations.md is writable");
        panic!("docs/limitations.md was stale against the catalog; it is rewritten: review and commit it");
    }
}

/// The rule reference in `gpurify_check`'s crate docs has a row for every kind
/// the code has, and each row cites exactly the catalog rows that name it.
#[test]
fn the_rule_reference_cites_the_catalog() {
    let doc = read("crates/check/src/lib.rs");
    let rows = catalog();
    for kind in code_kinds() {
        let needle = format!("| `{kind}` |");
        let line = doc
            .lines()
            .find(|line| line.contains(&needle))
            .unwrap_or_else(|| {
                panic!("crates/check/src/lib.rs: the rule reference has no row for {kind}")
            });
        let cited = line
            .trim_end()
            .trim_end_matches('|')
            .rsplit('|')
            .next()
            .expect("a table row has cells")
            .trim();
        let named: Vec<&str> = rows
            .iter()
            .filter(|row| row.gpurify.iter().any(|name| name == kind))
            .map(|row| row.id.as_str())
            .collect();
        let want = if named.is_empty() {
            "—".to_owned()
        } else {
            named.join(", ")
        };
        assert_eq!(
            cited, want,
            "crates/check/src/lib.rs: the {kind} row's catalog cell"
        );
    }
}

/// Open tools the catalog cites, as they appear in `sources` and in a
/// `TX:<tool>` oracle.
const OPEN_TOOLS: [&str; 9] = [
    "KL",
    "NG",
    "MAG",
    "OR",
    "drt",
    "YOSYS",
    "ngspice",
    "FasterCap",
    "FastHenry",
];

/// Oracles that do not borrow another tool's answer.
const INDEPENDENT: [&str; 7] = ["CF", "SE", "FR", "SY", "NV", "BM", "MR"];

/// Rows beyond open source that still rest on fewer than two independent
/// oracles. Ledger P1 adds the second; this list may only shrink.
const EVIDENCE_GAPS: [&str; 8] = [
    "ERC-D3", "ERC-F12", "ERC-F6", "FLOW-005", "LVS-020", "LVS-066", "LVS-071", "PEX-010",
];

fn codes(oracle: &str) -> BTreeSet<&str> {
    oracle
        .split(';')
        .map(|code| code.trim().split(':').next().unwrap_or_default())
        .filter(|code| !code.is_empty() && *code != "-")
        .collect()
}

/// A supported row no open tool defines and none was compared against: what
/// `GPurify` must prove on its own evidence.
fn beyond_open_source(row: &Row) -> bool {
    let words = |text: &str| {
        text.split(|c: char| !c.is_ascii_alphanumeric())
            .any(|word| OPEN_TOOLS.contains(&word))
    };
    matches!(
        row.status.as_str(),
        "implemented" | "partial" | "expressible"
    ) && !words(&row.sources)
        && !codes(&row.oracle).contains("TX")
}

/// The generated "beyond open source" block of check-sources.md.
fn beyond_block(rows: &[Row]) -> String {
    let cell = |text: &str| {
        if text.is_empty() {
            "—".to_owned()
        } else {
            text.replace('|', "\\|")
        }
    };
    let mut out = format!(
        "{BEGIN}\n\n| Id | Check | Status | Defined by (public) | Evidence |\n|---|---|---|---|---|\n"
    );
    for row in rows.iter().filter(|row| beyond_open_source(row)) {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            row.id,
            cell(&row.check),
            row.status,
            cell(&row.sources),
            cell(&row.oracle)
        );
    }
    let _ = write!(out, "\n{END}");
    out
}

/// `check-sources.md` lists every check `GPurify` performs that no open tool
/// defines, with the public source that defines it and the evidence that
/// proves it; each rests on two independent oracles, or is a named gap.
#[test]
fn checks_beyond_open_source_are_listed_with_two_independent_oracles() {
    let rows = catalog();
    let mut weak: Vec<&str> = rows
        .iter()
        .filter(|row| beyond_open_source(row))
        .filter(|row| {
            codes(&row.oracle)
                .iter()
                .filter(|code| INDEPENDENT.contains(code))
                .count()
                < 2
        })
        .map(|row| row.id.as_str())
        .collect();
    weak.sort_unstable();
    assert_eq!(
        weak, EVIDENCE_GAPS,
        "rows beyond open source with fewer than two independent oracles; add the evidence, or \
         (only when a row is new) list it in EVIDENCE_GAPS"
    );
    let file = path("docs/check-sources.md");
    let doc = read("docs/check-sources.md");
    let want = beyond_block(&rows);
    let (Some(start), Some(end)) = (doc.find(BEGIN), doc.find(END)) else {
        panic!("docs/check-sources.md has no generated block; add the {BEGIN} and {END} markers");
    };
    let have = &doc[start..end + END.len()];
    if have != want {
        let updated = format!("{}{want}{}", &doc[..start], &doc[end + END.len()..]);
        std::fs::write(&file, updated).expect("docs/check-sources.md is writable");
        panic!("docs/check-sources.md was stale against the catalog; it is rewritten: review and commit it");
    }
}
