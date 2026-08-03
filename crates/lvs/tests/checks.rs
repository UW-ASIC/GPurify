//! The layout-only checks, and the `RuleRun` discipline they are the crate's
//! only carrier of.
//!
//! `docs/TESTING.md` records why: half the DRC corpus of the suite this project
//! replaced asserted only that nothing was found, so a rule that never executed
//! passed every one of them. A clean result is therefore two claims, not one —
//! *this rule ran, it examined N things, and it found nothing* — and both are
//! asserted here every time.
//!
//! One of `checks`'s six functions is reachable from outside the crate.
//! `check_floating_nets`, `check_label_conflicts` and `check_net_seed_conflicts`
//! take a `NetTable` or a `PortTable`; `check_device_counts` and
//! `check_parametric` take a `DeviceTable`. All three types hold private fields
//! and offer no constructor, so no test outside `topology` can build one. Only
//! `check_topology` takes a [`LayoutGraph`], whose columns are public, and it is
//! what this file covers. The gap is recorded in `docs/NEED_TESTING.md`.

mod common;

use common::{mos_and_bjt, stacked_pair};
use gpurify_lvs::checks::check_topology;
use gpurify_lvs::LayoutGraph;
use gpurify_report::{Outcome, RuleRun, Violations};

/// Assert a rule reported itself as having executed over a non-empty input, and
/// that the rows it wrote are the rows it says it wrote.
///
/// The second half is a law rather than a fixture fact: `RuleRun::violations`
/// counts what the run pushed into `out`, so for a single rule over an empty
/// table the two agree by definition however many rows there are. A rule that
/// under-reports its own findings is how a summary comes back green over a
/// violation table that is not.
fn assert_ran(runs: &[RuleRun], out: &Violations, expected_violations: usize) {
    assert!(!runs.is_empty(), "the rule did not record a run at all");
    let mut reported = 0u64;
    for run in runs {
        assert_eq!(
            run.outcome,
            Outcome::Ran,
            "the rule reported {:?} over an input that is present and non-empty",
            run.outcome
        );
        reported += u64::from(run.violations);
    }
    assert!(
        runs.iter().any(|run| run.examined > 0),
        "the rule ran and examined nothing, over an input holding devices"
    );
    assert_eq!(
        reported,
        out.len() as u64,
        "the runs claim {reported} violations against {} rows in the table",
        out.len()
    );
    assert_eq!(out.len(), expected_violations);
}

/// Oracle: construct-from-answer. Every device in `stacked_pair` and
/// `mos_and_bjt` has the full terminal set its family declares — gate, source,
/// drain and bulk for a MOS, base, emitter and collector for a bipolar — and
/// every terminal names a net that exists. There is nothing structurally wrong
/// to find, and the run has to say so *while also saying it looked*.
#[test]
fn a_well_formed_graph_is_structurally_clean_and_the_check_says_it_looked() {
    for (name, graph) in [
        ("stacked pair", stacked_pair()),
        ("a MOS and a bipolar", mos_and_bjt()),
    ] {
        let mut out = Violations::default();
        let mut runs = Vec::new();
        check_topology(&LayoutGraph(graph), &mut out, &mut runs);
        assert!(out.is_empty(), "{name}: a clean graph produced findings");
        assert_ran(&runs, &out, 0);
    }
}

/// Oracle: construct-from-answer. One terminal is repointed at net 6 of a graph
/// that has six nets, numbered 0 to 5. "A terminal on no net" is the first
/// condition `check_topology`'s own documentation names, and this is the only
/// way to state it in a [`Graph`](gpurify_lvs::Graph): the index is out of the
/// net table's range, so nothing can be on the other end of it.
///
/// Built by writing the column directly rather than through `GraphBuilder`,
/// which refuses a terminal naming a net that does not exist — the fixture
/// builder enforcing the invariant is exactly why the invariant needs a check
/// on the extractor's output, which has no such builder in front of it.
#[test]
fn a_terminal_naming_a_net_that_does_not_exist_is_found() {
    let mut graph = stacked_pair();
    let net_count = u32::try_from(graph.net_name.len()).expect("a small fixture");
    let dangling = graph.device_terminal_start[1] as usize;
    graph.terminal_net[dangling] = net_count;

    let mut out = Violations::default();
    let mut runs = Vec::new();
    check_topology(&LayoutGraph(graph), &mut out, &mut runs);

    assert_ran(&runs, &out, 1);
}
