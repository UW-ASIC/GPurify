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
//! The argument parser is hand-written, in `args.rs` and nowhere else. No
//! parser crate is a dependency of this workspace: nothing that links
//! `gpurify-engine` as a library pays for an argument parser, and
//! [`args::parse`] stays a pure function over `&[String]` that a table test
//! calls without spawning a process.

mod args;
mod format;

/// Exit code is part of the interface: a script gates on it.
///
/// `0` only when every selected check ran and passed. A **skipped** check is
/// not a pass and does not exit `0` — that is the false-clean failure in the
/// one place it would do the most damage, since a CI job reads nothing but this
/// number.
///
/// The criterion itself is not written here. `main` reads arguments, runs, and
/// hands the outcome to [`exit_code`]; everything a test needs to see lives in
/// that function and in [`gpurify_engine::Summary::passed`].
fn main() -> std::process::ExitCode {
    use std::process::ExitCode;

    // Every failure path below renders the same way: the error's own message on
    // stderr and a nonzero code. A closure rather than a function so no new
    // signature enters a frozen file.
    let fail = |error: &dyn std::error::Error| -> ExitCode {
        let mut text = String::new();
        format::write_error(error, &mut text);
        eprintln!("{}", text.trim_end());
        ExitCode::FAILURE
    };

    // `parse` documents argv as excluding the program name.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match args::parse(&argv) {
        Ok(args) => args,
        Err(error) => return fail(&error),
    };

    // `--format gds` is refused rather than approximated, and this is not a
    // shortcut with an upgrade path inside this file: no marker-layer identity
    // reaches this crate at all. `export::gds::write_markers` takes the marker
    // `LayerId` from its caller because the number has to agree with whatever
    // the viewer is configured to show, and `Common` carries no field that
    // could hold one. Naming the type is not the obstacle — `LayerTable::id`
    // hands a `LayerId` back from a name, and a value flows through this crate
    // whether or not it can be spelled here. Nor is there a conventional name
    // to fall back on: the marker layers a deck declares are device-recognition
    // markers, which is a different thing from a violation overlay. Recorded in
    // `docs/SIGNATURE_DEFECTS.md`; refusing is what keeps an empty marker
    // library from reading as a clean layout, which is the false-clean failure
    // the exit code exists to prevent.
    if args.common.format == args::Format::Gds {
        eprintln!(
            "--format gds is not available yet: no marker layer reaches the \
             writer, and an empty marker library would read as a clean layout"
        );
        return ExitCode::FAILURE;
    }

    let (inputs, mut options) = args::to_inputs(&args);

    // `--check-determinism` runs the whole pipeline a second time and compares
    // the two rendered reports byte for byte.
    //
    // The second pass runs on a different worker count on purpose:
    // `RunOptions::threads` names byte-identical output *at any value of it* as
    // the property this flag exists to catch, so re-running at the same count
    // would answer a weaker question — whether a run repeats itself — and pass
    // a run whose results depend on how the work was divided.
    //
    // Compared as rendered bytes rather than as `Outputs`, because rendered
    // bytes are what `export` promises to reproduce and comparing them covers
    // the writers as well as the checks. `Summary` is compared beside them: it
    // is where the exit code comes from, and a renderer that drops a field
    // would otherwise hide a difference in it.
    //
    // Each pass gets fresh buffers. Reusing one set would compare the second
    // run against whatever the first left behind, which is the one thing this
    // gate must not do.
    let mut first: Option<(gpurify_engine::Summary, String)> = None;
    let mut pass = 0u8;

    let (result, text) = loop {
        pass += 1;
        debug_assert!(pass <= 2, "the determinism gate runs the pipeline twice");

        let mut loaded = gpurify_engine::Loaded::default();
        let mut extracted = gpurify_engine::Extracted::default();
        let mut outputs = gpurify_engine::Outputs::default();

        let result = gpurify_engine::pipeline::load_into(&inputs, &mut loaded)
            .map_err(gpurify_engine::EngineError::from)
            .and_then(|()| {
                gpurify_engine::pipeline::extract_into(&loaded, &mut extracted)
                    .map_err(gpurify_engine::EngineError::from)
            })
            .and_then(|()| {
                gpurify_engine::run::run_checks(&loaded, &extracted, &options, &mut outputs)
            });

        // A run that did not finish produced no verdict, so there is nothing to
        // render into the output file — the message belongs on stderr, and
        // `exit_code` reads the same `Err`.
        let summary = match &result {
            Ok(summary) => summary,
            Err(error) => return fail(error),
        };

        let grid = loaded
            .grid
            .expect("load_into returns LoadError::NoGrid rather than a Loaded without a grid");
        // No column check here. Both renderers open with one over all eight
        // columns — `Violations::len` on the text path, `json::write_report`'s
        // `columns_agree` on the other — and a third, weaker copy over two of
        // them is the assertion that goes stale when a ninth column is added.

        let mut text = String::new();
        match args.common.format {
            args::Format::Text => {
                format::write_violations(&outputs, &loaded.strings, grid, &mut text);
                format::write_summary(summary, &mut text);
            }
            args::Format::Json => {
                let header = gpurify_export::Header {
                    tool_version: env!("CARGO_PKG_VERSION"),
                    deck_path: inputs.deck.display().to_string(),
                    layout_path: inputs.layout.display().to_string(),
                    // Never from the clock: the determinism gate compares two
                    // JSON reports byte for byte.
                    timestamp: None,
                };
                let report = gpurify_export::json::Report {
                    header: &header,
                    violations: &outputs.violations,
                    runs: &outputs.runs,
                    strings: &loaded.strings,
                    grid,
                };
                if let Err(error) = gpurify_export::json::write_report(&report, &mut text) {
                    return fail(&error);
                }
            }
            // Refused above, before anything was read.
            args::Format::Gds => unreachable!("--format gds is refused before the run starts"),
        }
        debug_assert!(!text.is_empty(), "a finished run rendered nothing at all");

        // Second pass. A report that cannot be reproduced is not a result, so
        // the mismatch is reported before anything is written anywhere.
        if let Some((first_summary, first_text)) = &first {
            if first_summary != summary || first_text != &text {
                eprintln!(
                    "--check-determinism: two runs of the same inputs produced \
                     different reports, so the output depends on how the work \
                     was divided rather than on the design"
                );
                return ExitCode::FAILURE;
            }
            break (result, text);
        }
        if !args.common.check_determinism {
            break (result, text);
        }

        first = Some((summary.clone(), text));
        // Any value other than the one the first pass used. `threads` affects
        // speed only, by its own doc comment, so this changes nothing a correct
        // run can observe — which is exactly the claim being tested.
        options.threads = match options.threads {
            Some(2) => Some(1),
            _ => Some(2),
        };
    };
    debug_assert!(
        !args.common.check_determinism || pass == 2,
        "--check-determinism reported on a single run"
    );

    // A report that could not be delivered is not a pass, whatever the run
    // found, so a write failure short-circuits `exit_code`.
    match &args.common.output {
        Some(path) => {
            if let Err(error) = std::fs::write(path, text.as_bytes()) {
                eprintln!("{}: {error}", path.display());
                return ExitCode::FAILURE;
            }
        }
        None => print!("{text}"),
    }

    exit_code(&result)
}

/// The exit-code contract, as a value.
///
/// **Decision** — pure, a finished run in and a number out. Extracted from
/// `main` because `fn main() -> ExitCode` takes no arguments and so cannot be
/// called from a test: without this, nothing checks that an `EngineError` exits
/// nonzero, or that the number comes from
/// [`gpurify_engine::Summary::passed`] rather than from a violation count that
/// a skipped rule leaves at zero.
///
/// A run that failed to complete is not a pass. It produced no verdict at all,
/// which is further from a clean result than a run that found violations, so it
/// exits nonzero without consulting anything else.
fn exit_code(
    result: &Result<gpurify_engine::Summary, gpurify_engine::EngineError>,
) -> std::process::ExitCode {
    match result {
        Ok(summary) if summary.passed() => std::process::ExitCode::SUCCESS,
        _ => std::process::ExitCode::FAILURE,
    }
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
/// The gap between the two is closed by [`exit_code`] above, which is where the
/// mapping now lives. These tests still go through `passed()` rather than
/// through it, because the criterion is the part worth pinning and `exit_code`
/// is two arms over it.
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
