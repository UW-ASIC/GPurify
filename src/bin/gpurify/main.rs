//! `gpurify` — parse the command line, run, render, exit `0` only on a pass.

mod args;
mod format;

use gpurify::engine::Summary;
use gpurify::export::{json, parasitic, Header};
use std::process::ExitCode;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut cli = match args::parse(&argv) {
        Ok(cli) => cli,
        Err(error) => return fail(&error),
    };

    let (summary, text) = match render(&cli) {
        Ok(first) => first,
        Err(code) => return code,
    };

    if cli.check_determinism {
        // Any other worker count than the first pass used.
        cli.options.threads = if cli.options.threads == Some(2) {
            Some(1)
        } else {
            Some(2)
        };
        let (second_summary, second_text) = match render(&cli) {
            Ok(second) => second,
            Err(code) => return code,
        };
        if second_summary != summary || second_text != text {
            eprintln!(
                "--check-determinism: two runs of the same inputs produced \
                 different reports, so the output depends on how the work \
                 was divided rather than on the design"
            );
            return ExitCode::FAILURE;
        }
    }

    match &cli.output {
        Some(path) => {
            if let Err(error) = std::fs::write(path, text.as_bytes()) {
                eprintln!("{}: {error}", path.display());
                return ExitCode::FAILURE;
            }
        }
        None => print!("{text}"),
    }

    if summary.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// One whole run, rendered in the requested format. An error has already been
/// reported on stderr when this returns `Err`.
fn render(cli: &args::Cli) -> Result<(Summary, String), ExitCode> {
    let (loaded, extracted, outputs, summary) =
        gpurify::engine::run::run(&cli.inputs, &cli.options).map_err(|error| fail(&error))?;

    let header = Header {
        tool_version: env!("CARGO_PKG_VERSION"),
        deck_path: cli.inputs.deck.display().to_string(),
        layout_path: cli.inputs.layout.display().to_string(),
        timestamp: None,
    };
    let mut text = String::new();
    let written = match cli.format {
        args::Format::Text => {
            format::write_violations(&outputs, &loaded.strings, loaded.grid, &mut text);
            format::write_summary(&summary, &mut text);
            Ok(())
        }
        args::Format::Json => json::write_report(
            &json::Report {
                header: &header,
                violations: &outputs.violations,
                runs: &outputs.runs,
                strings: &loaded.strings,
                grid: loaded.grid,
            },
            &mut text,
        ),
        args::Format::Spef | args::Format::Dspf => {
            let spef = cli.format == args::Format::Spef;
            // An empty netlist would read as a design with no parasitics.
            let Some(network) = &outputs.parasitics else {
                eprintln!(
                    "--format {} asked for a parasitic network, but extraction \
                     produced none, and an empty netlist would read as a design \
                     with no parasitics",
                    if spef { "spef" } else { "dspf" }
                );
                return Err(ExitCode::FAILURE);
            };
            let write = if spef {
                parasitic::write_spef
            } else {
                parasitic::write_dspf
            };
            write(
                network,
                &extracted.ports,
                &loaded.strings,
                &header,
                &mut text,
            )
        }
    };
    written.map_err(|error| fail(&error))?;
    Ok((summary, text))
}

fn fail(error: &dyn std::error::Error) -> ExitCode {
    let mut text = String::new();
    format::write_error(error, &mut text);
    eprintln!("{}", text.trim_end());
    ExitCode::FAILURE
}
