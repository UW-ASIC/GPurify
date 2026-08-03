//! `gpurify` — the command line.
//!
//! Deliberately shallow. Argument parsing, formatting and an exit code; every
//! decision about what a run does belongs to `engine`, so a library consumer
//! gets exactly the run the command line gets.
//!
//! There is one binary rather than four. The flags that matter — deck, layout,
//! output format — are shared by every check, and four binaries would mean four
//! copies of them drifting apart, with no natural home for a combined signoff
//! run.
//!
//! `clap` lives here and only here, so nothing that links `gpurify-engine` as a
//! library pays for an argument parser.

// Definition-Phase; see CLAUDE.md
#![allow(unused_variables, dead_code)]

mod args;
mod format;

/// Exit code is part of the interface: a script gates on it.
///
/// `0` only when every selected check ran and passed. A **skipped** check is
/// not a pass and does not exit `0` — that is the false-clean failure in the
/// one place it would do the most damage, since a CI job reads nothing but this
/// number.
fn main() -> std::process::ExitCode {
    todo!()
}

/// The exit-code contract.
///
/// `main` returns an `ExitCode` and takes no arguments, so the mapping from a
/// finished run to a number cannot be called from a test. What *can* be called
/// is the decision underneath it — [`gpurify_engine::Summary::passed`], which
/// its own doc comment names as the single place the pass criterion is written.
/// These tests pin that criterion, and the Implementation-Phase owes `main`
/// nothing more than `if summary.passed() { SUCCESS } else { FAILURE }`.
///
/// The gap between the two is recorded rather than closed: extracting a pure
/// `fn exit_code(&Summary) -> ExitCode` would be a signature change, and the
/// freeze exists to stop an agent widening an interface to make its own test
/// easier.
#[cfg(test)]
mod tests {
    use gpurify_engine::{StageStatus, Summary};

    /// A run where all four checks ran, every rule was clean, and nothing was
    /// skipped. The only shape that may exit zero.
    fn clean_run() -> Summary {
        Summary {
            drc: StageStatus::Ran,
            erc: StageStatus::Ran,
            lvs: StageStatus::Ran,
            pex: StageStatus::Ran,
            violations: 0,
            errors: 0,
            warnings: 0,
            rules_clean: 26,
            rules_skipped: 0,
        }
    }

    /// Oracle: construct-from-answer. The baseline the rest of this module
    /// varies one field of. Asserting it separately matters because every
    /// other test here asserts a *failure*, and a `passed` that always
    /// returned false would satisfy all of them.
    #[test]
    fn a_run_where_every_selected_check_ran_and_found_nothing_passes() {
        assert!(clean_run().passed());
    }

    /// Oracle: construct-from-answer. The false-clean case, in the one place
    /// it does the most damage: no violations, and a rule that never ran. A
    /// CI job reads nothing but this number, so a skipped rule cannot be
    /// allowed to look like a clean one.
    #[test]
    fn a_skipped_rule_is_not_a_pass_even_with_no_violations() {
        let summary = Summary {
            rules_skipped: 1,
            ..clean_run()
        };
        assert!(
            !summary.passed(),
            "a run with a skipped rule and no violations must not exit zero"
        );
    }

    /// Oracle: construct-from-answer. The same claim one level up: a whole
    /// stage that could not run for want of an input is not a pass, and the
    /// reason it carries is what a caller acts on.
    #[test]
    fn a_stage_skipped_for_a_missing_input_is_not_a_pass() {
        let summary = Summary {
            lvs: StageStatus::Skipped("no reference netlist was supplied"),
            ..clean_run()
        };
        assert!(!summary.passed());
    }

    /// Oracle: construct-from-answer. Fail closed. A stage that refused its
    /// input checked nothing, so it cannot report success — this is the
    /// unsupported-geometry path, and treating it as clean is the defect the
    /// whole tool is built against.
    #[test]
    fn a_refused_stage_is_not_a_pass() {
        let summary = Summary {
            drc: StageStatus::Refused("non-rectilinear geometry on m1".to_string()),
            ..clean_run()
        };
        assert!(!summary.passed());
    }

    /// Oracle: construct-from-answer. The distinction `StageStatus` exists to
    /// draw: a check the caller did not ask for is not a check that failed to
    /// run. `gpurify drc` must be able to exit zero.
    #[test]
    fn a_check_that_was_never_selected_does_not_prevent_a_pass() {
        let summary = Summary {
            erc: StageStatus::NotSelected,
            lvs: StageStatus::NotSelected,
            pex: StageStatus::NotSelected,
            ..clean_run()
        };
        assert!(
            summary.passed(),
            "a drc-only run that found nothing is a pass; the other three were \
             never asked for"
        );
    }

    /// Oracle: construct-from-answer. An error-severity violation fails the
    /// run whatever else is true of it.
    #[test]
    fn an_error_severity_violation_is_not_a_pass() {
        let summary = Summary {
            violations: 1,
            errors: 1,
            ..clean_run()
        };
        assert!(!summary.passed());
    }

    /// Oracle: construct-from-answer. `Severity::Warning` exists, in its own
    /// words, "so a rule can report something it is unsure about without
    /// either failing the run or staying silent". A warning that failed the
    /// run would collapse that distinction and leave nothing between silence
    /// and a failed signoff.
    #[test]
    fn a_warning_on_its_own_does_not_fail_the_run() {
        let summary = Summary {
            violations: 2,
            errors: 0,
            warnings: 2,
            ..clean_run()
        };
        assert!(
            summary.passed(),
            "warnings are reported without failing the run"
        );
    }
}
