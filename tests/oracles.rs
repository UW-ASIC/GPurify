//! Every test states its oracle.
//!
//! A test is only as good as the independent thing that says its expected
//! value is right (`docs/testing-plan.md`: "A layer without one is not a
//! test"). So every `#[test]` in the repository names it on a line of its
//! doc comment that starts `Oracle:`: a hand-derived value, a closed form, a
//! foundry or spec example, a law or metamorphic relation, a differential
//! against another tool, construct-from-answer, a round trip, or a golden.
//! The scan below reads the `.rs` files as text, so a test added without
//! one fails here, naming it.

use std::path::{Path, PathBuf};

/// Every `.rs` file under `dir`, skipping build output and hidden
/// directories (`.git`, worktrees).
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|why| panic!("{}: {why}", dir.display()));
    for entry in entries {
        let entry = entry.expect("a readable directory entry");
        let (path, name) = (entry.path(), entry.file_name());
        let name = name.to_string_lossy();
        if path.is_dir() {
            if !name.starts_with('.') && name != "target" {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The tests in `source` whose doc comment has no line starting `Oracle:`,
/// by function name.
///
/// A test is a line holding only `#[test]`. Its doc comment is every `///`
/// line among the attributes and comments around it: those above it up to
/// the first line that is none of these (a multi-line attribute counts as
/// one), and those below it down to its `fn`.
fn tests_without_an_oracle(source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().map(str::trim).collect();
    let is_oracle = |line: &&str| {
        line.strip_prefix("///")
            .is_some_and(|doc| doc.trim_start().starts_with("Oracle:"))
    };
    let mut missing = Vec::new();
    for (at, _) in lines.iter().enumerate().filter(|(_, l)| **l == "#[test]") {
        let mut start = at;
        while start > 0 {
            let line = lines[start - 1];
            if line.starts_with("//") || line.starts_with("#[") {
                start -= 1;
            } else if line.ends_with(']') {
                // The last line of a multi-line attribute: back to its `#[`.
                start -= 1;
                while start > 0 && !lines[start].starts_with("#[") {
                    start -= 1;
                }
            } else {
                break;
            }
        }
        let Some((end, signature)) = lines[at..].iter().enumerate().find_map(|(i, line)| {
            Some((at + i, line.trim_start_matches("pub ").strip_prefix("fn ")?))
        }) else {
            missing.push(format!("<no fn after line {}>", at + 1));
            continue;
        };
        if !lines[start..end].iter().any(is_oracle) {
            let name = signature
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .next()
                .unwrap_or_default();
            missing.push(name.to_owned());
        }
    }
    missing
}

/// Oracle: the methodology's rule itself, read from the sources. Each failure
/// names the file and the test to give an `Oracle:` line, or to delete if it
/// has none.
#[test]
fn every_test_in_the_repository_states_its_oracle() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(root, &mut files);
    files.sort();
    let mut tests = 0;
    let mut missing = Vec::new();
    for file in &files {
        let source = std::fs::read_to_string(file).expect("a readable source file");
        tests += source.lines().filter(|l| l.trim() == "#[test]").count();
        for name in tests_without_an_oracle(&source) {
            let file = file.strip_prefix(root).unwrap_or(file);
            missing.push(format!("{}: {name}", file.display()));
        }
    }
    // The scan reached the test suites: there are hundreds, so a handful
    // means it read the wrong directory.
    assert!(
        tests > 500,
        "only {tests} tests found under {}",
        root.display()
    );
    assert!(
        missing.is_empty(),
        "{} tests state no `Oracle:` line in their doc comment:\n{}",
        missing.len(),
        missing.join("\n")
    );
}

/// Oracle: construct-from-answer. A source written here with one test that
/// states its oracle (above a multi-line attribute), one that states it
/// below `#[test]`, one with only a plain comment, one whose doc says
/// "oracle" mid-sentence, and one with no doc: the scan names exactly the
/// last three.
#[test]
fn the_scan_names_each_test_without_an_oracle_line() {
    let source = [
        "/// Oracle: closed form.",
        "#[allow(",
        "    clippy::float_cmp,",
        "    reason = \"exact\"",
        ")]",
        "#[test]",
        "fn stated_above() {}",
        "",
        "#[test]",
        "/// Oracle: law.",
        "fn stated_below() {}",
        "",
        "// Oracle: a plain comment is not a doc.",
        "#[test]",
        "fn in_a_plain_comment() {}",
        "",
        "/// Its oracle is mentioned, not stated.",
        "#[test]",
        "fn mentioned_mid_sentence() {}",
        "",
        "#[test]",
        "pub fn undocumented() {}",
    ]
    .join("\n");
    assert_eq!(
        tests_without_an_oracle(&source),
        [
            "in_a_plain_comment",
            "mentioned_mid_sentence",
            "undocumented"
        ]
    );
}
