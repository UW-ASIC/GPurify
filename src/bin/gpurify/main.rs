//! `gpurify` — parse the command line, run, render, exit `0` only on a pass.

mod args;
mod format;

use gpurify::engine::Summary;
use gpurify::export::{json, parasitic, Header};
use std::process::ExitCode;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cli = match args::parse(&argv) {
        Ok(cli) => cli,
        Err(error) => return fail(&error),
    };
    if let Some(lib) = &cli.lib {
        return liberty(&cli, lib);
    }

    let (summary, text) = match render(&cli) {
        Ok(first) => first,
        Err(code) => return code,
    };
    print!("{text}");

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

/// `lib`: load and extract once, then generate every requested accuracy.
/// `--accuracy all` writes each level under its own subdirectory.
fn liberty(cli: &args::Cli, lib: &args::LibArgs) -> ExitCode {
    let spec = match std::fs::read_to_string(&lib.spec)
        .map_err(|e| format!("{}: {e}", lib.spec.display()))
        .and_then(|text| gpurify::liberty::spec::parse(&text).map_err(|e| e.to_string()))
    {
        Ok(spec) => spec,
        Err(why) => {
            eprintln!("error: {why}");
            return ExitCode::FAILURE;
        }
    };
    let lef = match &lib.lef {
        None => None,
        Some(path) => match std::fs::read_to_string(path) {
            Ok(text) => Some(text),
            Err(e) => {
                eprintln!("error: {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        },
    };
    let loaded = match gpurify::engine::pipeline::load(&cli.inputs) {
        Ok(loaded) => loaded,
        Err(error) => return fail(&error),
    };
    let extracted = match gpurify::engine::pipeline::extract(&loaded) {
        Ok(extracted) => extracted,
        Err(error) => return fail(&error),
    };
    // Simulator decks and logs; kept only when a simulation fails, to debug it.
    let scratch = std::env::temp_dir().join(format!("gpurify-lib-{}", std::process::id()));
    let many = lib.accuracy.len() > 1;
    for &accuracy in &lib.accuracy {
        let (dir, work) = if many {
            (
                lib.output_dir.join(accuracy.name()),
                scratch.join(accuracy.name()),
            )
        } else {
            (lib.output_dir.clone(), scratch.clone())
        };
        let request = gpurify::liberty::Request {
            spec: &spec,
            accuracy,
            lef: lef.as_deref(),
            work: &work,
            tool_version: env!("CARGO_PKG_VERSION"),
        };
        let started = std::time::Instant::now();
        let generated = match gpurify::liberty::generate(&loaded, &extracted, &request) {
            Ok(generated) => generated,
            Err(error) => {
                eprintln!("error: {} accuracy: {error}", accuracy.name());
                let written = std::fs::read_dir(&work).is_ok_and(|mut d| d.next().is_some());
                if written {
                    eprintln!("simulator decks and logs are kept in {}", work.display());
                }
                return ExitCode::FAILURE;
            }
        };
        for (path, text) in &generated.files {
            let path = dir.join(path);
            let written = path
                .parent()
                .map_or(Ok(()), std::fs::create_dir_all)
                .and_then(|()| std::fs::write(&path, text));
            if let Err(e) = written {
                eprintln!("error: {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
            println!("{}: wrote {}", accuracy.name(), path.display());
        }
        for note in &generated.notes {
            println!("{}: note: {note}", accuracy.name());
        }
        println!(
            "{}: done in {:.1} s",
            accuracy.name(),
            started.elapsed().as_secs_f64()
        );
        let _ = std::fs::remove_dir_all(&work);
    }
    let _ = std::fs::remove_dir_all(&scratch);
    ExitCode::SUCCESS
}

fn fail(error: &dyn std::error::Error) -> ExitCode {
    let mut text = String::new();
    format::write_error(error, &mut text);
    eprintln!("{}", text.trim_end());
    ExitCode::FAILURE
}
