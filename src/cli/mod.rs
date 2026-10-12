//! The command line, as a library: what the `gpurify` binary runs, and what
//! a binary that carries its own decks runs ([`main_with`]).
//!
//! `gpurify <drc|erc|lvs|pex|all|lib> <layout> --deck <deck> [options]`,
//! or `gpurify system <system.json> --reference <netlist>` for several dies;
//! [usage.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/usage.md)
//! documents every option, the reports and the exit codes. Every binary
//! built on [`main_with`] has the same flags, report and exit codes.

mod args;
mod compare;
mod format;

use crate::deck::DeckFn;
use crate::engine::Summary;
use crate::export::{json, parasitic, Header};
use std::process::ExitCode;

/// Parses the process's command line, runs, prints the report, and exits
/// `0` only on a pass, as the `gpurify` binary does (it is
/// `main_with(&[])`). `decks` are the decks this binary carries: `--deck`
/// with one of their names builds that deck on the layout's grid
/// ([`load_with`](crate::engine::pipeline::load_with)); anything else is
/// read as a deck file.
///
/// # Examples
///
/// A binary that checks against sky130 as shipped with one rule tightened,
/// as `tight-sky130 drc my.gds --deck tight-sky130`:
///
/// ```no_run
/// use gpurify::deck::{rules, BuildError, CompiledDeck, DeckBuilder};
/// use gpurify::geom::{Grid, StrTable};
///
/// fn tight_sky130(grid: Grid, strings: &mut StrTable) -> Result<CompiledDeck, BuildError> {
///     let base = gpurify::pdks::sky130(grid, strings)?;
///     let mut d = DeckBuilder::from_deck(&base, strings);
///     let met1 = d.get("met1");
///     let area = d.area(90_000.0);
///     d.replace("m1.6", rules::min_area(met1, area));
///     d.finish()
/// }
///
/// fn main() -> std::process::ExitCode {
///     gpurify::cli::main_with(&[("tight-sky130", tight_sky130)])
/// }
/// ```
pub fn main_with(decks: &[(&str, DeckFn)]) -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    // Two netlists and no layout or deck: its own command line.
    if argv.first().map(String::as_str) == Some("compare") {
        return compare::main(&argv[1..]);
    }
    let cli = match args::parse(&argv) {
        Ok(cli) => cli,
        Err(error) => return fail(&error),
    };
    if let Some(lib) = &cli.lib {
        return liberty(&cli, lib, decks);
    }

    let (summary, text) = match render(&cli, decks) {
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
fn render(cli: &args::Cli, decks: &[(&str, DeckFn)]) -> Result<(Summary, String), ExitCode> {
    if let Some(system) = &cli.system {
        let reference = cli
            .inputs
            .reference
            .as_deref()
            .expect("the parser requires a system netlist");
        let run = crate::engine::system::run(system, reference).map_err(|error| fail(&error))?;
        // A system has no one deck or layout: both name the system file.
        let header = Header {
            tool_version: env!("CARGO_PKG_VERSION"),
            deck_path: system.display().to_string(),
            layout_path: system.display().to_string(),
            timestamp: None,
        };
        let mut text = String::new();
        if cli.format == args::Format::Json {
            json::write_report(
                &json::Report {
                    header: &header,
                    violations: &run.outputs.violations,
                    waived: &run.outputs.waived,
                    runs: &run.outputs.runs,
                    strings: &run.strings,
                    grid: run.grid,
                },
                &mut text,
            )
            .map_err(|error| fail(&error))?;
        } else {
            format::write_violations(&run.outputs, &run.strings, run.grid, &mut text);
            format::write_summary(&run.summary, &mut text);
        }
        return Ok((run.summary, text));
    }
    let (loaded, extracted, outputs, summary) = if let Some(other) = &cli.other {
        let (loaded, outputs, summary) = crate::engine::xor::run_with(&cli.inputs, other, decks)
            .map_err(|error| fail(&error))?;
        (loaded, None, outputs, summary)
    } else {
        let (loaded, extracted, outputs, summary) =
            crate::engine::run::run_with(&cli.inputs, &cli.options, decks)
                .map_err(|error| fail(&error))?;
        (loaded, Some(extracted), outputs, summary)
    };

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
            if let Some(extracted) = &extracted {
                reports(cli, &loaded, extracted, &outputs, &mut text).map_err(|why| {
                    eprintln!("error: {why}");
                    ExitCode::FAILURE
                })?;
            }
            Ok(())
        }
        args::Format::Json => json::write_report(
            &json::Report {
                header: &header,
                violations: &outputs.violations,
                waived: &outputs.waived,
                runs: &outputs.runs,
                strings: &loaded.strings,
                grid: loaded.grid,
            },
            &mut text,
        ),
        args::Format::Spef | args::Format::Dspf => {
            let spef = cli.format == args::Format::Spef;
            // An empty netlist would read as a design with no parasitics.
            // `xor` extracts nothing, and its arguments refuse these formats.
            let (Some(network), Some(extracted)) = (&outputs.parasitics, &extracted) else {
                eprintln!(
                    "--format {} asked for a parasitic network, but extraction \
                     produced none, and an empty netlist would read as a design \
                     with no parasitics",
                    if spef { "spef" } else { "dspf" }
                );
                return Err(ExitCode::FAILURE);
            };
            if spef {
                // The deck's process corners, if any, as min:typ:max triplets.
                let corners: Vec<_> = outputs.corners.iter().map(|(_, network)| network).collect();
                parasitic::write_spef_corners(
                    network,
                    &corners,
                    &extracted.ports,
                    &loaded.strings,
                    &header,
                    &mut text,
                )
            } else {
                parasitic::write_dspf(
                    network,
                    &extracted.ports,
                    &loaded.strings,
                    &header,
                    &mut text,
                )
            }
        }
    };
    written.map_err(|error| fail(&error))?;
    Ok((summary, text))
}

/// The `--p2p` and `--coupling` reports, one line per pair (PEX-016), and
/// the `--cluster` list, one line per cluster (FLOW-010).
fn reports(
    cli: &args::Cli,
    loaded: &crate::engine::Loaded,
    extracted: &crate::engine::Extracted,
    outputs: &crate::engine::Outputs,
    text: &mut String,
) -> Result<(), String> {
    use std::fmt::Write as _;
    let network = outputs.parasitics.as_ref();
    for (net, points) in &cli.p2p {
        for (i, j, ohms) in crate::engine::p2p::resistance(loaded, extracted, net, points)? {
            let ((xa, ya), (xb, yb)) = (points[i], points[j]);
            let _ = writeln!(
                text,
                "p2p {net} ({xa}, {ya}) um to ({xb}, {yb}) um: {ohms:.6} ohm"
            );
        }
    }
    if let Some(reach_um) = cli.cluster {
        #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
        let per_um = loaded.grid.dbu_per_um() as f64;
        #[expect(clippy::cast_possible_truncation, reason = "a reach in database units")]
        let reach = gpurify_geom::Dbu::new_unchecked((reach_um * per_um).round() as i64);
        let um = |d: gpurify_geom::Dbu| {
            #[expect(clippy::cast_precision_loss, reason = "a coordinate")]
            let v = d.raw() as f64 / per_um;
            v
        };
        for c in crate::engine::triage::cluster(&outputs.violations, reach) {
            let _ = writeln!(
                text,
                "cluster {} {} violations within ({}, {})-({}, {}) um",
                loaded.strings.resolve(c.rule),
                c.rows.len(),
                um(c.lo.x),
                um(c.lo.y),
                um(c.hi.x),
                um(c.hi.y)
            );
        }
    }
    for (a, b) in &cli.coupling {
        let network = network.ok_or("--coupling needs a parasitic network, and PEX made none")?;
        let ff = crate::engine::p2p::coupling(loaded, extracted, network, a, b)?;
        let _ = writeln!(text, "coupling {a} {b}: {ff:.6} fF");
    }
    Ok(())
}

/// `lib`: load and extract once, then generate every requested accuracy.
/// `--accuracy all` writes each level under its own subdirectory.
fn liberty(cli: &args::Cli, lib: &args::LibArgs, decks: &[(&str, DeckFn)]) -> ExitCode {
    let spec = match std::fs::read_to_string(&lib.spec)
        .map_err(|e| format!("{}: {e}", lib.spec.display()))
        .and_then(|text| crate::liberty::spec::parse(&text).map_err(|e| e.to_string()))
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
    let loaded = match crate::engine::pipeline::load_with(&cli.inputs, decks) {
        Ok(loaded) => loaded,
        Err(error) => return fail(&error),
    };
    let extracted = match crate::engine::pipeline::extract(&loaded) {
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
        let request = crate::liberty::Request {
            spec: &spec,
            accuracy,
            lef: lef.as_deref(),
            work: &work,
            tool_version: env!("CARGO_PKG_VERSION"),
        };
        let started = std::time::Instant::now();
        let generated = match crate::liberty::generate(&loaded, &extracted, &request) {
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
