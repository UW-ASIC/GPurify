//! `gpurify` — argument parsing, formatting and an exit code.

mod args;
mod format;

/// Runs the pipeline and exits `0` only when every selected check ran and passed.
fn main() -> std::process::ExitCode {
    use std::process::ExitCode;

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

    // Refused rather than approximated: no marker-layer identity reaches this
    // crate, and an empty marker library would read as a clean layout.
    if args.common.format == args::Format::Gds {
        eprintln!(
            "--format gds is not available yet: no marker layer reaches the \
             writer, and an empty marker library would read as a clean layout"
        );
        return ExitCode::FAILURE;
    }

    let (inputs, mut options) = args::to_inputs(&args);

    // `--check-determinism` runs the pipeline twice, at different worker counts,
    // and compares the two rendered reports byte for byte. Each pass gets fresh
    // buffers: reusing one set would compare a run against what the first left
    // behind.
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
        // render: the message belongs on stderr.
        let summary = match &result {
            Ok(summary) => summary,
            Err(error) => return fail(error),
        };

        let grid = loaded
            .grid
            .expect("load_into returns LoadError::NoGrid rather than a Loaded without a grid");

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
            args::Format::Spef | args::Format::Dspf => {
                // Refused rather than written empty: an empty netlist is a
                // design with no parasitics, which is never true.
                let Some(network) = &outputs.parasitics else {
                    eprintln!(
                        "--format {} asked for a parasitic network, but extraction \
                         produced none, and an empty netlist would read as a design \
                         with no parasitics",
                        if args.common.format == args::Format::Spef {
                            "spef"
                        } else {
                            "dspf"
                        }
                    );
                    return ExitCode::FAILURE;
                };
                let header = gpurify_export::Header {
                    tool_version: env!("CARGO_PKG_VERSION"),
                    deck_path: inputs.deck.display().to_string(),
                    layout_path: inputs.layout.display().to_string(),
                    // Never from the clock, for `json`'s reason.
                    timestamp: None,
                };
                let write = if args.common.format == args::Format::Spef {
                    gpurify_export::parasitic::write_spef
                } else {
                    gpurify_export::parasitic::write_dspf
                };
                if let Err(error) = write(
                    network,
                    &extracted.ports,
                    &loaded.strings,
                    &header,
                    &mut text,
                ) {
                    return fail(&error);
                }
            }
        }
        debug_assert!(!text.is_empty(), "a finished run rendered nothing at all");

        // A report that cannot be reproduced is not a result, so the mismatch is
        // reported before anything is written anywhere.
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
        // Any value other than the one the first pass used: re-running at the
        // same worker count would pass a run whose output depends on how the
        // work was divided.
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

/// A finished run in, a process exit code out. A run that failed to complete is
/// not a pass: it produced no verdict at all.
fn exit_code(
    result: &Result<gpurify_engine::Summary, gpurify_engine::EngineError>,
) -> std::process::ExitCode {
    match result {
        Ok(summary) if summary.passed() => std::process::ExitCode::SUCCESS,
        _ => std::process::ExitCode::FAILURE,
    }
}

/// The exit-code contract, pinned through [`gpurify_engine::Summary::passed`].
#[cfg(test)]
mod tests {
    use gpurify_engine::{StageStatus, Summary};

    /// The only summary shape that may exit zero.
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

    /// The baseline; a `passed` that always returned false would satisfy every
    /// other test here.
    #[test]
    fn a_run_where_every_selected_check_ran_and_found_nothing_passes() {
        assert!(clean_run().passed());
    }

    /// The false-clean case: no violations, and a rule that never ran.
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

    /// The same claim one level up, for a whole stage.
    #[test]
    fn a_stage_skipped_for_a_missing_input_is_not_a_pass() {
        let summary = Summary {
            lvs: StageStatus::Skipped("no reference netlist was supplied"),
            ..clean_run()
        };
        assert!(!summary.passed());
    }

    /// A stage that refused its input checked nothing, so it cannot pass.
    #[test]
    fn a_refused_stage_is_not_a_pass() {
        let summary = Summary {
            drc: StageStatus::Refused("non-rectilinear geometry on m1".to_string()),
            ..clean_run()
        };
        assert!(!summary.passed());
    }

    /// A check the caller did not ask for is not a check that failed to run.
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

    /// An error-severity violation fails the run whatever else is true of it.
    #[test]
    fn an_error_severity_violation_is_not_a_pass() {
        let summary = Summary {
            violations: 1,
            errors: 1,
            ..clean_run()
        };
        assert!(!summary.passed());
    }

    /// A warning reports doubt without failing the run.
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
