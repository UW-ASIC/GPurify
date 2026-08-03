//! `Summary::passed()`, which is the one bit a CI job reads.
//!
//! Oracle: **construct-from-answer**, on statuses. A [`Summary`] is a record of
//! public fields describing a run that already happened, so a test states the
//! run and already knows the verdict. No geometry, nothing to derive.
//!
//! Three doc comments between them fix the criterion, and every case below
//! cites the one it comes from:
//!
//! - [`Summary::passed`] — "a skipped rule is **not** a pass", and a caller who
//!   wants a partial run says so by not selecting the check, which is
//!   `NotSelected` rather than `Skipped`.
//! - [`StageStatus::Refused`] — requested, attempted, and refused because the
//!   input was outside what the tool represents. Fail closed.
//! - `report::Severity::Warning` — "exists so a rule can report something it is
//!   unsure about **without either failing the run** or staying silent".

use gpurify_engine::{StageStatus, Summary};

/// Sets one of the four stage fields, so a case can be written once and applied
/// to each stage in turn.
type SetStage = fn(&mut Summary, StageStatus);

/// A run that asked for all four checks, got all four, and found nothing.
///
/// Every case is this record with one field changed, so the name of the case is
/// also the whole of the difference from a pass.
fn clean_run() -> Summary {
    Summary {
        drc: StageStatus::Ran,
        erc: StageStatus::Ran,
        lvs: StageStatus::Ran,
        pex: StageStatus::Ran,
        violations: 0,
        errors: 0,
        warnings: 0,
        rules_clean: 17,
        rules_skipped: 0,
    }
}

/// Oracle: construct-from-answer. The baseline every other case is measured
/// against. If this one were false the suite below would be vacuous, since a
/// criterion that never passes rejects the bad cases for free.
#[test]
fn a_run_that_asked_for_everything_and_found_nothing_passes() {
    let summary = clean_run();
    assert!(
        summary.passed(),
        "four stages ran, nothing was skipped and nothing was found, \
         yet this is not a pass: {summary:?}"
    );
}

/// Oracle: construct-from-answer. The false clean, stated as directly as it can
/// be: zero violations, every stage ran, and one rule that did not. The old
/// suite's whole failure mode was reading the first half of that sentence, so
/// the assertion is that `passed()` reads the second half.
#[test]
fn zero_violations_with_a_skipped_rule_is_not_a_pass() {
    let summary = Summary {
        rules_skipped: 1,
        ..clean_run()
    };
    assert!(
        !summary.passed(),
        "a run with a rule that never executed reported a pass on the strength \
         of an empty violation table: {summary:?}"
    );
}

/// Oracle: construct-from-answer. `NotSelected` and `Skipped` are the
/// distinction the tool turns on, so they are checked as a pair on otherwise
/// identical runs: the user declining LVS is a pass, LVS asked for and denied
/// its reference netlist is not. An implementation that collapsed the two into
/// "did not run" passes exactly one of these two assertions.
#[test]
fn a_check_the_caller_declined_passes_where_the_same_check_skipped_does_not() {
    let declined = Summary {
        lvs: StageStatus::NotSelected,
        ..clean_run()
    };
    let denied = Summary {
        lvs: StageStatus::Skipped("no reference netlist"),
        ..clean_run()
    };

    assert_ne!(
        declined.lvs, denied.lvs,
        "NotSelected and Skipped must not compare equal; conflating them is the \
         false clean in type form"
    );
    assert!(
        declined.passed(),
        "not asking for LVS is how a caller requests a partial run, and it must \
         not fail the run: {declined:?}"
    );
    assert!(
        !denied.passed(),
        "LVS was requested and could not run, so the run learned nothing about \
         the netlist and must not report a pass: {denied:?}"
    );
}

/// Oracle: construct-from-answer. The criterion is per-stage, not per-`lvs`, so
/// it is exercised on each of the four in turn. An implementation that checked
/// only the stage it was written against would pass a single-stage test and
/// fail three of these twelve.
#[test]
fn a_skip_blocks_the_pass_whichever_stage_it_lands_on() {
    let stages: [(&str, SetStage); 4] = [
        ("drc", |summary, status| summary.drc = status),
        ("erc", |summary, status| summary.erc = status),
        ("lvs", |summary, status| summary.lvs = status),
        ("pex", |summary, status| summary.pex = status),
    ];

    for (stage, set) in stages {
        let mut skipped = clean_run();
        set(
            &mut skipped,
            StageStatus::Skipped("a required input was absent"),
        );
        assert!(
            !skipped.passed(),
            "{stage} was requested and did not run, so the run is not a pass: {skipped:?}"
        );

        let mut refused = clean_run();
        set(
            &mut refused,
            StageStatus::Refused("geometry is not rectilinear".to_string()),
        );
        assert!(
            !refused.passed(),
            "{stage} refused its input, which is fail-closed and not a pass: {refused:?}"
        );

        let mut declined = clean_run();
        set(&mut declined, StageStatus::NotSelected);
        assert!(
            declined.passed(),
            "{stage} was never asked for, which is a partial run the caller chose \
             and not a failure: {declined:?}"
        );
    }
}

/// Oracle: construct-from-answer. Nothing was selected, so nothing could be
/// skipped and nothing could be found. The extreme of the `NotSelected` rule
/// rather than a separate one, and it is here because it is the shape a caller
/// building up a `Checks` from flags reaches by accident.
#[test]
fn selecting_no_check_at_all_is_a_pass_because_nothing_was_denied() {
    let summary = Summary {
        drc: StageStatus::NotSelected,
        erc: StageStatus::NotSelected,
        lvs: StageStatus::NotSelected,
        pex: StageStatus::NotSelected,
        rules_clean: 0,
        ..clean_run()
    };
    assert!(
        summary.passed(),
        "a run that was asked for nothing has denied the caller nothing: {summary:?}"
    );
}

/// Oracle: construct-from-answer, against `report::Severity`. A warning is
/// defined as a finding a rule is unsure about, reported "without either
/// failing the run or staying silent" — so it appears in the counts and does
/// not change the verdict, while an error of the same shape does.
#[test]
fn an_error_fails_the_run_where_a_warning_of_the_same_count_does_not() {
    let warned = Summary {
        violations: 1,
        errors: 0,
        warnings: 1,
        ..clean_run()
    };
    let errored = Summary {
        violations: 1,
        errors: 1,
        warnings: 0,
        ..clean_run()
    };

    assert!(
        warned.passed(),
        "a warning is a finding the rule was unsure about and must not fail the \
         run, or no rule can ever report one: {warned:?}"
    );
    assert!(
        !errored.passed(),
        "one error-severity violation is a failing run: {errored:?}"
    );
}

/// Oracle: construct-from-answer. The two blocking conditions are independent,
/// so a run holding both is still one verdict, and a run holding neither but
/// carrying a large clean-rule count is still a pass. This is the case that
/// catches an `||` written as an `&&`.
#[test]
fn violations_and_skips_block_a_pass_independently_of_each_other() {
    let cases: [(&str, Summary, bool); 4] = [
        (
            "errors alone",
            Summary {
                violations: 3,
                errors: 3,
                ..clean_run()
            },
            false,
        ),
        (
            "skips alone",
            Summary {
                rules_skipped: 2,
                ..clean_run()
            },
            false,
        ),
        (
            "errors and skips together",
            Summary {
                violations: 3,
                errors: 3,
                rules_skipped: 2,
                ..clean_run()
            },
            false,
        ),
        ("neither", clean_run(), true),
    ];

    for (what, summary, expected) in cases {
        assert_eq!(
            summary.passed(),
            expected,
            "{what}: expected passed() == {expected} for {summary:?}"
        );
    }
}
