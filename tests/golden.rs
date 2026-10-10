//! Every corpus case through every output the CLI has, byte for byte.
//!
//! The report is the product: its bytes are what a user diffs against
//! yesterday's run and what a flow parses. So each corpus cell is run through
//! the real binary, the way a user runs it, and the exit code, stdout and stderr
//! are compared with a checked-in file under `tests/golden/<domain>/`.
//!
//! Oracles:
//! - **Golden.** A reviewed snapshot. A missing file is written and fails the
//!   test, so every new snapshot passes review before it counts. To accept an
//!   intended change, delete the affected files and rerun; the diff of
//!   `tests/golden/` is then the review.
//! - **Determinism.** Every run is made twice, and must be byte-identical.
//!   Quasistatic runs are made a third time on a one-thread rayon pool (the
//!   field solve is the only parallel code), and must match too. The eight
//!   `PEX_NEG_*` cells take ~40 CPU-seconds per solve, so in the merge gate
//!   only the other cells (same code paths, milliseconds each) get the
//!   one-thread run; the `#[ignore]`d nightly twin gives it to every cell.
//!
//! A golden file no run produces is stale and fails the test.

#[path = "common/gen_fixtures.rs"]
mod gen_fixtures;

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

const BIN: &str = env!("CARGO_BIN_EXE_gpurify");

/// One invocation of the binary, and where its golden lives.
struct Job {
    golden: PathBuf,
    args: Vec<String>,
    /// Also run on a one-thread pool and compare.
    parallel: bool,
}

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Exit code, stdout and stderr, in one comparable text.
fn run(args: &[String], threads: Option<&str>) -> String {
    let mut command = Command::new(BIN);
    command.args(args).current_dir(repo());
    if let Some(threads) = threads {
        command.env("RAYON_NUM_THREADS", threads);
    }
    let out = command.output().expect("the gpurify binary runs");
    format!(
        "exit {}\n--- stdout\n{}--- stderr\n{}",
        out.status
            .code()
            .map_or("signal".to_string(), |c| c.to_string()),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    )
}

/// The arguments every corpus run shares, after the command and the layout.
fn common(gds: &str) -> Vec<String> {
    [gds, "--deck", "tests/fixtures/params.deck"]
        .map(str::to_owned)
        .to_vec()
}

fn args(command: &str, gds: &str, rest: &[&str]) -> Vec<String> {
    let mut all = vec![command.to_owned()];
    all.extend(common(gds));
    all.extend(rest.iter().map(|s| (*s).to_owned()));
    all
}

/// The first eight nets a SPEF names, as `--quasistatic` arguments.
fn quasistatic_nets(spef: &str) -> Vec<String> {
    spef.lines()
        .filter_map(|line| line.strip_prefix("*D_NET "))
        .filter_map(|rest| rest.split_whitespace().next())
        .take(8)
        .flat_map(|net| ["--quasistatic".to_owned(), net.to_owned()])
        .collect()
}

/// Every run for one case: the full JSON report, plus SPEF and quasistatic
/// SPEF for PEX cells and, for LVS cells, the compare against the case's own
/// reference netlist (`tests/fixtures/lvs_refs/<id>.spice`).
fn jobs_for(domain: &str, id: &str, every_thread_check: bool) -> Vec<Job> {
    let gds = format!("tests/fixtures/{domain}/{id}.gds");
    let golden = |run: &str| {
        repo()
            .join("tests/golden")
            .join(domain)
            .join(format!("{id}.{run}"))
    };
    let mut jobs = vec![Job {
        golden: golden("all"),
        args: args("all", &gds, &["--format", "json"]),
        parallel: false,
    }];
    if domain == "pex" {
        let spef = args("pex", &gds, &["--format", "spef"]);
        let nets = quasistatic_nets(&run(&spef, None));
        jobs.push(Job {
            golden: golden("spef"),
            args: spef.clone(),
            parallel: false,
        });
        if !nets.is_empty() {
            let mut quasistatic = spef.clone();
            quasistatic.extend(nets);
            // ponytail: the slow cells skip the one-thread run outside the
            // nightly twin; drop the condition once the field solve is faster.
            let parallel = every_thread_check || !id.starts_with("PEX_NEG_");
            jobs.push(Job {
                golden: golden("qs"),
                args: quasistatic,
                parallel,
            });
        }
    }
    if domain == "lvs" {
        let reference = format!("tests/fixtures/lvs_refs/{id}.spice");
        jobs.push(Job {
            golden: golden("lvs"),
            args: args(
                "lvs",
                &gds,
                &["--reference", &reference, "--format", "json"],
            ),
            parallel: false,
        });
    }
    jobs
}

/// Every case id in `expectations.json`, by domain.
fn cases() -> Vec<(String, String)> {
    let path = gen_fixtures::fixtures().join("expectations.json");
    let text = std::fs::read_to_string(&path).expect("expectations.json is readable");
    let expectations: Value = serde_json::from_str(&text).expect("expectations.json is JSON");
    ["drc", "erc", "lvs", "pex"]
        .iter()
        .flat_map(|&domain| {
            expectations[domain]["cases"]
                .as_array()
                .expect("a cases array per domain")
                .iter()
                .map(move |case| {
                    let id = case["id"].as_str().expect("every case has an id");
                    (domain.to_owned(), id.to_owned())
                })
        })
        .collect()
}

/// What went wrong with one job, or `None`.
fn check(job: &Job) -> Option<String> {
    let name = job
        .golden
        .strip_prefix(repo())
        .unwrap_or(&job.golden)
        .display();
    let first = run(&job.args, None);
    if run(&job.args, None) != first {
        return Some(format!("{name}: two runs of the same inputs differ"));
    }
    if job.parallel && run(&job.args, Some("1")) != first {
        return Some(format!("{name}: one thread and many threads differ"));
    }
    match std::fs::read_to_string(&job.golden) {
        Err(_) => {
            std::fs::create_dir_all(job.golden.parent().expect("a golden has a directory"))
                .expect("the golden directory can be made");
            std::fs::write(&job.golden, &first).expect("the golden can be written");
            Some(format!("{name}: new golden written; review it and commit"))
        }
        Ok(golden) if golden == first => None,
        Ok(golden) => {
            let at = golden
                .lines()
                .zip(first.lines())
                .position(|(want, got)| want != got)
                .unwrap_or_else(|| golden.lines().count().min(first.lines().count()));
            Some(format!(
                "{name}: differs from its golden at line {}\n    golden: {:?}\n    now:    {:?}\n    \
                 (delete the file and rerun to accept the change)",
                at + 1,
                golden.lines().nth(at).unwrap_or("<end>"),
                first.lines().nth(at).unwrap_or("<end>"),
            ))
        }
    }
}

/// Every file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .flat_map(|entry| {
            let path = entry.path();
            if path.is_dir() {
                files_under(&path)
            } else {
                vec![path]
            }
        })
        .collect()
}

#[test]
fn every_corpus_output_is_its_golden_and_deterministic() {
    check_all(false);
}

/// The nightly depth: the one-thread run for every quasistatic cell.
#[test]
#[ignore = "nightly: ~6 CPU-minutes of single-thread field solves"]
fn every_field_solve_is_the_same_on_one_thread() {
    check_all(true);
}

fn check_all(every_thread_check: bool) {
    let mut jobs: Vec<Job> = cases()
        .iter()
        .flat_map(|(domain, id)| jobs_for(domain, id, every_thread_check))
        .collect();
    // The field solves take seconds and the rest milliseconds: start them first.
    jobs.sort_by_key(|job| !job.parallel);

    let next = Mutex::new(0usize);
    let failures = Mutex::new(Vec::new());
    let workers = std::thread::available_parallelism().map_or(4, usize::from);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let job = {
                    let mut next = next.lock().expect("the job counter is not poisoned");
                    let Some(job) = jobs.get(*next) else { break };
                    *next += 1;
                    job
                };
                if let Some(failure) = check(job) {
                    failures.lock().expect("not poisoned").push(failure);
                }
            });
        }
    });

    let produced: BTreeSet<&Path> = jobs.iter().map(|job| job.golden.as_path()).collect();
    let mut failures = failures.into_inner().expect("not poisoned");
    for stale in files_under(&repo().join("tests/golden")) {
        if !produced.contains(stale.as_path()) {
            failures.push(format!(
                "{}: no run produces this golden; delete it",
                stale.strip_prefix(repo()).unwrap_or(&stale).display()
            ));
        }
    }
    failures.sort();
    assert!(
        failures.is_empty(),
        "{} of {} runs failed:\n{}",
        failures.len(),
        jobs.len(),
        failures.join("\n")
    );
}
