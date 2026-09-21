//! `run_checks`: which checks ran, which were declined, and which were denied
//! an input they needed.
//!
//! Oracle: **construct-from-answer**, on statuses. [`Loaded`] and [`Extracted`]
//! are both `Default`, and the absences that decide a status are fields on
//! them — a `Loaded` with no reference netlist is a run whose LVS status is
//! known before the call. That is the whole of what this seam decides, and it
//! is decided from data the test supplies.
//!
//! Every assertion here reads the public columns of [`Outputs`] rather than the
//! accessors: `Violations::len` is a frozen signature over a `todo!()` body
//! until the Implementation-Phase, and an assertion that panics inside itself
//! reports nothing. `testgen::assertions` does the same, for the same reason.

use gpurify_drc::DrcError;
use gpurify_engine::pipeline::{Extracted, Loaded};
use gpurify_engine::run::{
    run_checks, Checks, EngineError, Outputs, RunOptions, StageStatus, Summary,
};
use gpurify_ingest::deck::{DeviceKind, RuleSpec};
use gpurify_ingest::netlist::{Netlist, RefNetId, SubcktId};
use gpurify_ingest::StrId;
use gpurify_lvs::refine::TieBreak;
use gpurify_lvs::verdict::{Discrepancy, Side};
use gpurify_lvs::{CompareOptions, Verdict};

/// Every field written out rather than `CompareOptions::default()`, which is a
/// `todo!()` body until Phase 4 — a fixture that panics before reaching the
/// function under test would make every failure below look like the same bug.
fn options(checks: Checks, threads: usize) -> RunOptions {
    RunOptions {
        checks,
        lvs: CompareOptions {
            max_rounds: 64,
            tie_break: TieBreak::LowestIndex,
            param_tolerance: 1e-3,
            match_names: false,
        },
        quasistatic_nets: Vec::new(),
        quasistatic_inductance: false,
        threads: Some(threads),
    }
}

const NONE_SELECTED: Checks = Checks {
    drc: false,
    erc: false,
    lvs: false,
    pex: false,
};

/// The model name of the one device the reference netlist below declares.
///
/// Written as a bare `StrId` rather than interned: `StrTable::intern` is a
/// `todo!()` body until Phase 4, and nothing here resolves an id back to text.
/// `crates/lvs/tests/common` states its fixture ids the same way and for the
/// same reason.
const NCH: StrId = StrId(1);

/// A reference netlist holding one four-terminal transistor, and nothing else.
///
/// One subcircuit, so [`Netlist::top`] is unambiguous and the comparison cannot
/// come back `Inconclusive(AmbiguousTop)`. The CSR columns carry one more entry
/// than the table they index, which is the convention `Netlist`'s `_start`
/// fields document.
fn reference_with_one_transistor() -> Netlist {
    Netlist {
        subckt_name: vec![StrId(2)],
        subckt_port_start: vec![0, 0],
        port_net: Vec::new(),
        subckt_device_start: vec![0, 1],
        device_name: vec![StrId(3)],
        device_model: vec![NCH],
        device_kind: vec![DeviceKind::Mos],
        device_terminal_start: vec![0, 4],
        terminal_net: vec![RefNetId(0), RefNetId(1), RefNetId(2), RefNetId(3)],
        device_param_start: vec![0, 0],
        param: Vec::new(),
        net_name: vec![StrId(4), StrId(5), StrId(6), StrId(7)],
        net_subckt: vec![SubcktId(0); 4],
        // One subcircuit instantiating nothing, which is what makes `top`
        // unambiguous above.
        ..Netlist::default()
    }
}

/// Oracle: construct-from-answer. Nothing was asked for, so every stage is the
/// caller's own choice not to run it, and nothing produced output. The case
/// matters because it is the only one where `NotSelected` is the right answer
/// for all four at once, and an implementation defaulting a status to `Ran`
/// would claim four checks it never performed.
#[test]
fn a_run_selecting_no_check_reports_four_declines_and_produces_nothing() {
    let loaded = Loaded::default();
    let extracted = Extracted::default();
    let mut out = Outputs::default();

    let summary = run_checks(&loaded, &extracted, &options(NONE_SELECTED, 1), &mut out)
        .expect("a run that was asked for nothing cannot fail");

    assert_eq!(
        summary.drc,
        StageStatus::NotSelected,
        "drc was not requested"
    );
    assert_eq!(
        summary.erc,
        StageStatus::NotSelected,
        "erc was not requested"
    );
    assert_eq!(
        summary.lvs,
        StageStatus::NotSelected,
        "lvs was not requested"
    );
    assert_eq!(
        summary.pex,
        StageStatus::NotSelected,
        "pex was not requested"
    );
    assert!(
        out.runs.is_empty(),
        "no check ran, so no rule can have a RuleRun row: {:?}",
        out.runs
    );
    assert!(
        out.violations.rule.is_empty(),
        "no check ran, so nothing can have been found"
    );
    assert!(
        out.lvs.is_none(),
        "lvs was not requested and produced no verdict"
    );
    assert!(
        out.parasitics.is_none(),
        "pex was not requested and produced no network"
    );
    assert_eq!(summary.rules_skipped, 0, "declining a check skips no rule");
    assert!(
        summary.passed(),
        "a run that was asked for nothing has denied the caller nothing: {summary:?}"
    );
}

/// Oracle: construct-from-answer. `Inputs::reference` absent is documented to
/// disable LVS "loudly", and `StageStatus::Skipped` names this exact case. The
/// verdict slot must stay empty: a `Match` here would be the tool reporting
/// that two netlists agree when it never read the second one.
#[test]
fn lvs_without_a_reference_netlist_is_skipped_and_never_a_match() {
    let loaded = Loaded::default();
    assert!(
        loaded.reference.is_none(),
        "the premise of this test is that nothing supplied a reference netlist"
    );
    let extracted = Extracted::default();
    let mut out = Outputs::default();
    let checks = Checks {
        lvs: true,
        ..NONE_SELECTED
    };

    let summary = run_checks(&loaded, &extracted, &options(checks, 1), &mut out)
        .expect("a missing reference netlist is a skip, not an error");

    assert!(
        matches!(summary.lvs, StageStatus::Skipped(_)),
        "lvs was requested with no reference netlist and reported {:?}; \
         a missing input is a skip with a reason, never a quiet clean",
        summary.lvs
    );
    assert!(
        out.lvs.is_none(),
        "lvs produced a verdict without a reference netlist to compare against"
    );
    assert_ne!(
        out.lvs,
        Some(Verdict::Match),
        "a comparison that never happened cannot have matched"
    );
    assert!(
        !summary.passed(),
        "a requested check that could not run must fail the run: {summary:?}"
    );
}

/// Oracle: construct-from-answer. Every other case here proves a check did
/// *not* run, and a `run_checks` that reported `Skipped` for everything would
/// satisfy all of them — the absence-only failure, one level up from a rule.
/// This is the case that pins the other side: LVS was requested, its reference
/// netlist was supplied, so the status is `Ran` and a verdict exists.
///
/// The verdict is known before the call. The reference declares one transistor
/// and the extraction is empty, so nothing on either side pairs; the only
/// difference lives on the reference, and it is the device at index 0. Match is
/// wrong because the two netlists differ, and `Inconclusive` is wrong because
/// there is a unique top and one device is not a symmetry refinement can fail
/// to break.
///
/// # The eight rows, and why three of them are skipped
///
/// This used to assert `rules_skipped == 0`, on the argument that no DRC or ERC
/// rule was requested so none could have been skipped. The argument was sound and
/// the assertion was accidentally true: `lvs::checks`'s six checks had no
/// production caller, so **LVS filed no run row at all** and the count could only
/// come from the two domains that were not selected. `run_lvs` calls them now, so
/// the count is LVS's own — five rows ran and found nothing, and three record
/// [`SkipReason::NotInDeck`] because `check_device_counts` and `check_parametric`
/// compare against a limit no signature in that module is handed. Those three are
/// deliberate tripwires, not a defect here, and a run selecting LVS therefore
/// cannot report a pass until the deck reaches them — which is fail-closed and
/// is the answer this project wants.
#[test]
fn lvs_with_a_reference_netlist_runs_and_blames_the_device_the_layout_lacks() {
    let loaded = Loaded {
        reference: Some(reference_with_one_transistor()),
        ..Loaded::default()
    };
    let extracted = Extracted::default();
    let mut out = Outputs::default();
    let checks = Checks {
        lvs: true,
        ..NONE_SELECTED
    };

    let summary = run_checks(&loaded, &extracted, &options(checks, 1), &mut out)
        .expect("a reference netlist and an empty layout compare, they do not error");

    assert_eq!(
        summary.lvs,
        StageStatus::Ran,
        "lvs was requested and given the input it needs, so it ran; anything else \
         is the check reporting a skip it cannot justify"
    );
    assert_eq!(
        out.runs.len(),
        8,
        "lvs::checks files eight rows between its six checks, and a stage that \
         filed none is a domain whose empty violation table means nothing: {:?}",
        out.runs
    );
    assert_eq!(
        summary.rules_skipped, 3,
        "the two device-count families and the parametric check cannot be \
         configured from these signatures and record themselves unrun; the other \
         five ran: {summary:?}"
    );
    assert_eq!(
        summary.rules_clean, 5,
        "an empty extraction has no floating net, no label conflict, no merged \
         seed and no malformed device, so all five runnable checks are clean: \
         {summary:?}"
    );
    assert!(
        !summary.passed(),
        "three checks did not run, and a rule that did not run must block the \
         pass whatever the verdict says: {summary:?}"
    );

    let verdict = out
        .lvs
        .expect("a check that ran must leave its verdict behind");
    let Verdict::Mismatch(found) = &verdict else {
        panic!(
            "a one-device reference against an empty layout is a mismatch, and \
             reporting {verdict:?} either claims agreement that does not exist or \
             declines to conclude what the input already decides"
        );
    };
    assert!(
        found.contains(&Discrepancy::UnpairedDevice {
            side: Side::Reference,
            device: 0,
            model: NCH,
        }),
        "the unpaired transistor is on the reference side at index 0 and no other \
         difference exists, yet the discrepancies are {found:#?}"
    );
    assert!(
        !found.iter().any(|d| matches!(
            d,
            Discrepancy::UnpairedDevice {
                side: Side::Layout,
                ..
            }
        )),
        "the layout holds no device at all, so nothing in it can be unpaired: {found:#?}"
    );
}

/// Oracle: construct-from-answer. The same mismatch as above, read through the
/// summary instead of the verdict.
///
/// `Summary::passed()` is the one bit a CI job reads, and a comparison that ran
/// and found two different netlists reaching it as a pass is the fail-open this
/// mapping closes. The count is known before the call: one row per discrepancy,
/// every one an error, because a netlist difference is never a warning.
#[test]
fn an_lvs_mismatch_is_an_error_in_the_report_and_fails_the_run() {
    let loaded = Loaded {
        reference: Some(reference_with_one_transistor()),
        ..Loaded::default()
    };
    let extracted = Extracted::default();
    let mut out = Outputs::default();
    let checks = Checks {
        lvs: true,
        ..NONE_SELECTED
    };

    let summary = run_checks(&loaded, &extracted, &options(checks, 1), &mut out)
        .expect("a reference netlist and an empty layout compare, they do not error");

    let Some(Verdict::Mismatch(found)) = out.lvs.as_ref() else {
        panic!(
            "the premise of this test is a mismatch, and the verdict is {:?}",
            out.lvs
        );
    };
    assert_eq!(
        out.violations.rule.len(),
        found.len(),
        "the comparison found {} discrepancies and the report carries {} rows; \
         a difference that reaches no row is a difference nobody reading the \
         report will see",
        found.len(),
        out.violations.rule.len()
    );
    assert_eq!(
        summary.errors as usize,
        found.len(),
        "a netlist difference is never a warning: {summary:?}"
    );
    assert_eq!(
        summary.warnings, 0,
        "a discrepancy downgraded to a warning would pass the run: {summary:?}"
    );
    assert!(
        !summary.passed(),
        "two different netlists compared and the run reports a pass, which is \
         the fail-open the mapping exists to close: {summary:?}"
    );
}

/// Oracle: construct-from-answer. The same inputs, twice, differing only in
/// whether LVS was asked for. The reference netlist is absent both times, so
/// the only thing that can produce two different statuses is the distinction
/// between the caller declining and the run being denied — which is the
/// distinction the summary exists to make.
#[test]
fn the_same_missing_input_reads_as_a_decline_or_a_skip_by_what_was_requested() {
    let loaded = Loaded::default();
    let extracted = Extracted::default();

    let mut declined_out = Outputs::default();
    let declined = run_checks(
        &loaded,
        &extracted,
        &options(NONE_SELECTED, 1),
        &mut declined_out,
    )
    .expect("declining lvs cannot fail");

    let mut denied_out = Outputs::default();
    let denied = run_checks(
        &loaded,
        &extracted,
        &options(
            Checks {
                lvs: true,
                ..NONE_SELECTED
            },
            1,
        ),
        &mut denied_out,
    )
    .expect("a missing reference netlist is a skip, not an error");

    assert_eq!(
        declined.lvs,
        StageStatus::NotSelected,
        "lvs was not requested, so its absence is the caller's decision"
    );
    assert_ne!(
        declined.lvs, denied.lvs,
        "the same absent reference netlist produced the same status whether or \
         not lvs was requested, which is the two cases conflated"
    );
    assert!(
        declined.passed() && !denied.passed(),
        "exactly one of these is a pass: declined {declined:?}, denied {denied:?}"
    );
}

/// Oracle: determinism. `RunOptions::threads` is documented as affecting speed
/// only, so two runs of one input at two thread counts must agree in every
/// column — that is the gate, and this is the seam where a caller sets the
/// thread count.
///
/// The reference netlist is supplied so the comparison has something to
/// produce. Two empty output tables agree for free, and a determinism test that
/// cannot tell a stable run from an unstable one is a determinism test in name.
#[test]
fn the_same_run_at_two_thread_counts_produces_the_same_summary_and_outputs() {
    let loaded = Loaded {
        reference: Some(reference_with_one_transistor()),
        ..Loaded::default()
    };
    let extracted = Extracted::default();

    let mut single = Outputs::default();
    let one_thread = run_checks(&loaded, &extracted, &options(Checks::ALL, 1), &mut single)
        .expect("running every check on an empty design cannot fail");

    let mut parallel = Outputs::default();
    let four_threads = run_checks(&loaded, &extracted, &options(Checks::ALL, 4), &mut parallel)
        .expect("running every check on an empty design cannot fail");

    assert_summaries_agree("thread count", &one_thread, &four_threads);
    assert_outputs_agree("thread count", &single, &parallel);
}

/// Oracle: determinism. The same call twice at one thread count. Distinct from
/// the test above: that one catches a race, this one catches a run whose output
/// order comes from a hash seed, which reproduces at any thread count. The
/// discrepancy list is where that would show, so the reference netlist is
/// supplied here too.
#[test]
fn running_the_same_input_twice_produces_the_same_summary_and_outputs() {
    let loaded = Loaded {
        reference: Some(reference_with_one_transistor()),
        ..Loaded::default()
    };
    let extracted = Extracted::default();

    let mut first_out = Outputs::default();
    let first = run_checks(
        &loaded,
        &extracted,
        &options(Checks::ALL, 2),
        &mut first_out,
    )
    .expect("running every check on an empty design cannot fail");

    let mut second_out = Outputs::default();
    let second = run_checks(
        &loaded,
        &extracted,
        &options(Checks::ALL, 2),
        &mut second_out,
    )
    .expect("running every check on an empty design cannot fail");

    assert_summaries_agree("repeated run", &first, &second);
    assert_outputs_agree("repeated run", &first_out, &second_out);
}

/// Compare two summaries column by column.
///
/// `Summary` does not derive `PartialEq` — a frozen signature, recorded rather
/// than widened — so the comparison is written out. Naming the field that
/// differs is what a determinism failure needs anyway.
fn assert_summaries_agree(what: &str, first: &Summary, second: &Summary) {
    assert_eq!(
        first.drc, second.drc,
        "{what}: drc status differs between runs"
    );
    assert_eq!(
        first.erc, second.erc,
        "{what}: erc status differs between runs"
    );
    assert_eq!(
        first.lvs, second.lvs,
        "{what}: lvs status differs between runs"
    );
    assert_eq!(
        first.pex, second.pex,
        "{what}: pex status differs between runs"
    );
    assert_eq!(
        first.violations, second.violations,
        "{what}: violation count differs between runs"
    );
    assert_eq!(
        first.errors, second.errors,
        "{what}: error count differs between runs"
    );
    assert_eq!(
        first.warnings, second.warnings,
        "{what}: warning count differs between runs"
    );
    assert_eq!(
        first.rules_clean, second.rules_clean,
        "{what}: clean-rule count differs between runs"
    );
    assert_eq!(
        first.rules_skipped, second.rules_skipped,
        "{what}: skipped-rule count differs between runs"
    );
    assert_eq!(
        first.passed(),
        second.passed(),
        "{what}: the two runs disagree on whether the design passed"
    );
}

/// Compare two output tables column by column, in order.
///
/// Order is part of the interface — `Violations::sort_canonical` establishes it
/// and every consumer relies on it, so two tables holding the same rows in a
/// different order is a determinism failure and not a formatting detail.
///
/// The parasitic columns are compared with a bare `==` inside `assert!` rather
/// than `assert_eq!`, because `Parasitic` wraps a `Qty` whose `Debug` is a
/// `todo!()` body until Phase 4: formatting the values on failure would panic
/// inside the failure message.
fn assert_outputs_agree(what: &str, first: &Outputs, second: &Outputs) {
    gpurify_testgen::assert_violations_eq(&first.violations, &second.violations);
    assert_eq!(
        first.runs, second.runs,
        "{what}: the RuleRun rows differ between runs, so the record of which \
         rules executed is not reproducible"
    );
    assert_eq!(
        first.lvs, second.lvs,
        "{what}: the lvs verdict differs between runs"
    );

    match (&first.parasitics, &second.parasitics) {
        (None, None) => {}
        (Some(a), Some(b)) => {
            assert!(
                a.node_net == b.node_net && a.node_layer == b.node_layer,
                "{what}: the parasitic node columns differ between runs"
            );
            assert!(
                a.from == b.from && a.to == b.to && a.value == b.value,
                "{what}: the parasitic element columns differ between runs"
            );
        }
        _ => panic!("{what}: one run extracted parasitics and the other did not"),
    }
}

/// A `Loaded` whose deck holds one rule row per kind named, and nothing else.
///
/// Ids are `rule.0`, `rule.1`, … so a refusal names which row it refused. No
/// layers and no parameters: the rows never reach a rule set in the test below,
/// because the union check runs before one is built.
fn loaded_with_rule_kinds(kinds: &[&str]) -> Loaded {
    let mut loaded = Loaded::default();
    for (at, kind) in kinds.iter().enumerate() {
        let id = loaded.strings.intern(&format!("rule.{at}"));
        let kind = loaded.strings.intern(kind);
        loaded.deck.rules.spec.push(RuleSpec {
            id,
            kind,
            layer_start: 0,
            layer_len: 0,
            param_start: 0,
            param_len: 0,
        });
    }
    loaded
}

/// Oracle: construct-from-answer. One deck holding a DRC row and an ERC row is
/// accepted, which is the whole point of each rule set stepping over the other's
/// kinds.
///
/// `ingest` produces one `RuleTable` and does not know what a kind means, so
/// both domains read every row. Before they learned to skip, a deck could hold
/// one domain's rules or the other's but never both, and every ERC rule was
/// unreachable through `run_checks`.
#[test]
fn one_deck_may_hold_a_drc_rule_and_an_erc_rule() {
    let loaded = loaded_with_rule_kinds(&["min_width", "antenna_electrical"]);

    run_checks(
        &loaded,
        &Extracted::default(),
        &options(NONE_SELECTED, 1),
        &mut Outputs::default(),
    )
    .expect("min_width is drc's kind and antenna_electrical is erc's; both are known");
}

/// Oracle: construct-from-answer, on the fail-closed path. A kind in neither
/// domain's vocabulary is refused, and refused *before* `options.checks` is
/// read.
///
/// This is the half that the skip above would otherwise have thrown away. It
/// runs with no check selected on purpose: a misspelled ERC kind must not be
/// able to hide behind a DRC-only run, so the refusal cannot live inside either
/// stage's `if`.
#[test]
fn a_kind_in_neither_domains_vocabulary_is_refused_whatever_was_selected() {
    let loaded = loaded_with_rule_kinds(&["min_width", "min_widht"]);

    let error = run_checks(
        &loaded,
        &Extracted::default(),
        &options(NONE_SELECTED, 1),
        &mut Outputs::default(),
    )
    .expect_err("min_widht is nobody's rule kind");

    assert!(
        matches!(
            error,
            EngineError::Drc(DrcError::UnknownKind { ref kind, .. }) if kind == "min_widht"
        ),
        "expected the unknown kind to be named, got {error:?}"
    );
}

/// Oracle: construct-from-answer, on the opt-in seam. `quasistatic_inductance`
/// is off by default and the off path never reaches the inductance bridge, so
/// an off run's network holds no [`Parasitic::Inductance`] element at all —
/// exactly the pre-flag output. On, the same run gains at least one inductance
/// and one resistance row per field-solved net.
#[test]
fn the_inductance_flag_adds_elements_only_when_asked() {
    use gpurify_engine::pipeline::Inputs;
    use gpurify_extract::Parasitic;
    use std::path::Path;

    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let inputs = Inputs {
        layout: fixtures.join("pex/PEX_COUPLING_C.gds"),
        deck: fixtures.join("params.json"),
        grid: Some(
            gpurify_geom::Grid::new(1_000)
                .expect("1000 database units per micrometre is a 1 nm grid"),
        ),
        ..Inputs::default()
    };
    let pex_only = Checks {
        drc: false,
        erc: false,
        lvs: false,
        pex: true,
    };
    let run_with = |inductance: bool| -> Outputs {
        let mut opts = options(pex_only, 1);
        opts.quasistatic_nets = vec!["PEX_CC_n0".to_string(), "PEX_CC_n1".to_string()];
        opts.quasistatic_inductance = inductance;
        let mut out = Outputs::default();
        let summary = gpurify_engine::run::run(&inputs, &opts, &mut out)
            .expect("the coupling fixture field-solves");
        assert_eq!(summary.pex, StageStatus::Ran, "the solve must not refuse");
        out
    };
    let count = |out: &Outputs, want_inductance: bool| -> usize {
        out.parasitics.as_ref().map_or(0, |network| {
            network
                .value
                .iter()
                .filter(|value| matches!(value, Parasitic::Inductance(_)) == want_inductance)
                .count()
        })
    };

    let off = run_with(false);
    assert_eq!(
        count(&off, true),
        0,
        "off is the default, and the bridge must not have run"
    );

    let on = run_with(true);
    assert!(
        count(&on, true) >= 1,
        "on, the two field-solved nets carry inductance elements"
    );
    assert!(
        count(&on, false) >= count(&off, false),
        "the capacitive elements survive beside the inductive ones"
    );
}
