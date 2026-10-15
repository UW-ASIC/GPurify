//! The command line, as a library: what the `gpurify` binary runs, and what
//! a binary that carries its own decks runs ([`main_with`]).
//!
//! `gpurify <drc|erc|lvs|pex|all|lib> <layout> --deck <deck> [options]`,
//! `gpurify <fill|enhance> <layout> <output.gds> --deck <deck>` for the
//! layout edits the deck configures (each then reports DRC on its output),
//! or `gpurify system <system.json> --reference <netlist>` for several dies;
//! [usage.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/usage.md)
//! documents every option, the reports and the exit codes. Every binary
//! built on [`main_with`] has the same flags, report and exit codes.

mod args;
mod compare;
mod format;

use crate::deck::DeckFn;
use crate::engine::{Extracted, Inputs, Loaded, Outputs, Summary};
use crate::export::{json, parasitic, Header};
use gpurify_geom::Grid;
use gpurify_ingest::StrTable;
use std::path::Path;
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
    let mut cli = match args::parse(&argv) {
        Ok(cli) => cli,
        Err(error) => return fail(&error),
    };
    match &cli.command {
        args::Command::Lib(lib) => {
            return liberty(&cli.inputs, lib, decks)
                .map_or_else(|code| code, |()| ExitCode::SUCCESS)
        }
        // An edit writes its layout, then reports DRC on what it wrote.
        args::Command::Edit(edit, output) => {
            if let Err(code) = write_edit(&cli.inputs, *edit, output, decks) {
                return code;
            }
            cli.inputs.layout.clone_from(output);
        }
        _ => {}
    }
    match render(&cli, decks) {
        Ok((summary, text)) => {
            print!("{text}");
            if summary.passed() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(code) => code,
    }
}

/// `fill` or `enhance`: the edited layout, written to `output`, and what
/// was added, on stderr (stdout carries the report).
fn write_edit(
    inputs: &Inputs,
    edit: args::Edit,
    output: &Path,
    decks: &[(&str, DeckFn)],
) -> Result<(), ExitCode> {
    let (bytes, note) = match edit {
        args::Edit::Fill => {
            let (bytes, squares) =
                crate::engine::fill::fill_gds(inputs, decks).map_err(|error| fail(&error))?;
            let total: usize = squares.iter().sum();
            (bytes, format!("{total} fill squares"))
        }
        args::Edit::Enhance => {
            let (bytes, kept) =
                crate::engine::enhance::enhance_gds(inputs, decks).map_err(|error| fail(&error))?;
            let note = format!(
                "{} redundant cuts, {} strap sides widened",
                kept.cuts, kept.sides
            );
            (bytes, note)
        }
    };
    std::fs::write(output, bytes).map_err(|why| {
        eprintln!("error: {}: {why}", output.display());
        ExitCode::FAILURE
    })?;
    eprintln!("wrote {}: {note}", output.display());
    Ok(())
}

/// One whole run, rendered in the requested format. An error has already been
/// reported on stderr when this returns `Err`.
fn render(cli: &args::Cli, decks: &[(&str, DeckFn)]) -> Result<(Summary, String), ExitCode> {
    let mut text = String::new();
    if let args::Command::System(system) = &cli.command {
        let reference =
            (cli.inputs.reference.first()).expect("the parser requires a system netlist");
        let run = crate::engine::system::run(system, reference).map_err(|error| fail(&error))?;
        // A system has no one deck or layout: both name the system file.
        let header = header(system, system);
        let report = (&run.outputs, &run.summary, &run.strings, run.grid);
        write_checks(cli.format, &header, report, &mut text)?;
        return Ok((run.summary, text));
    }
    let (loaded, extracted, outputs, summary) = if let args::Command::Xor(other) = &cli.command {
        let (loaded, outputs, summary) = crate::engine::xor::run_with(&cli.inputs, other, decks)
            .map_err(|error| fail(&error))?;
        (loaded, None, outputs, summary)
    } else {
        let (loaded, extracted, outputs, summary) =
            crate::engine::run::run_with(&cli.inputs, &cli.options, decks)
                .map_err(|error| fail(&error))?;
        (loaded, Some(extracted), outputs, summary)
    };

    let header = header(&cli.inputs.deck, &cli.inputs.layout);
    let written = match cli.format {
        args::Format::Text | args::Format::Json => {
            let report = (&outputs, &summary, &loaded.strings, loaded.grid);
            write_checks(cli.format, &header, report, &mut text)?;
            if cli.format == args::Format::Text {
                let pex = cli.options.checks.pex;
                reports(pex, &loaded, extracted.as_ref(), &outputs, &mut text).map_err(|why| {
                    eprintln!("error: {why}");
                    ExitCode::FAILURE
                })?;
            }
            Ok(())
        }
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

/// `text` or `json`: the rule records, violations and summary of a run
/// whose names are in `strings` and locations on `grid`.
fn write_checks(
    format: args::Format,
    header: &Header,
    (outputs, summary, strings, grid): (&Outputs, &Summary, &StrTable, Grid),
    text: &mut String,
) -> Result<(), ExitCode> {
    if format == args::Format::Json {
        let report = json::Report {
            header,
            violations: &outputs.violations,
            waived: &outputs.waived,
            runs: &outputs.runs,
            strings,
            grid,
        };
        return json::write_report(&report, text).map_err(|error| fail(&error));
    }
    format::write_violations(outputs, strings, grid, text);
    format::write_summary(summary, text);
    Ok(())
}

/// The report header of a run on `deck` and `layout`, undated.
fn header(deck: &Path, layout: &Path) -> Header {
    Header {
        tool_version: env!("CARGO_PKG_VERSION"),
        deck_path: deck.display().to_string(),
        layout_path: layout.display().to_string(),
        timestamp: None,
    }
}

/// The deck's `report` lines: `cluster`, one line per cluster, after any
/// check (FLOW-010), and, when `pex` ran, `p2p` and `coupling`, one line
/// per pair (PEX-016).
fn reports(
    pex: bool,
    loaded: &Loaded,
    extracted: Option<&Extracted>,
    outputs: &Outputs,
    text: &mut String,
) -> Result<(), String> {
    use std::fmt::Write as _;
    let wanted = &loaded.deck.reports;
    #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
    let per_um = loaded.grid.dbu_per_um() as f64;
    #[expect(clippy::cast_precision_loss, reason = "a coordinate")]
    let um = |d: gpurify_geom::Dbu| d.raw() as f64 / per_um;
    if let Some(reach) = wanted.cluster {
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
    // A deck serves every check; its PEX reports print when PEX ran.
    let Some(extracted) = extracted.filter(|_| pex) else {
        return Ok(());
    };
    for (net, points) in &wanted.p2p {
        for (i, j, ohms) in crate::engine::p2p::resistance(loaded, extracted, net, points)? {
            let ((xa, ya), (xb, yb)) = (points[i], points[j]);
            let _ = writeln!(
                text,
                "p2p {net} ({}, {}) um to ({}, {}) um: {ohms:.6} ohm",
                um(xa),
                um(ya),
                um(xb),
                um(yb)
            );
        }
    }
    for (a, b) in &wanted.coupling {
        let network = (outputs.parasitics.as_ref())
            .ok_or("report coupling needs a parasitic network, and PEX made none")?;
        let ff = crate::engine::p2p::coupling(loaded, extracted, network, a, b)?;
        let _ = writeln!(text, "coupling {a} {b}: {ff:.6} fF");
    }
    Ok(())
}

/// `lib`: load and extract once, then generate every accuracy the spec
/// asks for. `"accuracy": "all"` writes each level under its own
/// subdirectory. An error has already been reported on stderr when this
/// returns `Err`.
fn liberty(inputs: &Inputs, lib: &args::LibArgs, decks: &[(&str, DeckFn)]) -> Result<(), ExitCode> {
    let error = |why: String| {
        eprintln!("error: {why}");
        ExitCode::FAILURE
    };
    let spec = std::fs::read_to_string(&lib.spec)
        .map_err(|e| format!("{}: {e}", lib.spec.display()))
        .and_then(|text| crate::liberty::spec::parse(&text).map_err(|e| e.to_string()))
        .map_err(error)?;
    let lef = (lib.lef.as_ref())
        .map(|path| {
            std::fs::read_to_string(path).map_err(|e| error(format!("{}: {e}", path.display())))
        })
        .transpose()?;
    let loaded = crate::engine::pipeline::load_with(inputs, decks).map_err(|e| fail(&e))?;
    let extracted = crate::engine::pipeline::extract(&loaded).map_err(|e| fail(&e))?;
    // Simulator decks and logs; kept only when a simulation fails, to debug it.
    let scratch = std::env::temp_dir().join(format!("gpurify-lib-{}", std::process::id()));
    let many = spec.accuracy.len() > 1;
    for &accuracy in &spec.accuracy {
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
        let generated = crate::liberty::generate(&loaded, &extracted, &request).map_err(|e| {
            eprintln!("error: {} accuracy: {e}", accuracy.name());
            if std::fs::read_dir(&work).is_ok_and(|mut d| d.next().is_some()) {
                eprintln!("simulator decks and logs are kept in {}", work.display());
            }
            ExitCode::FAILURE
        })?;
        for (path, text) in &generated.files {
            let path = dir.join(path);
            (path.parent())
                .map_or(Ok(()), std::fs::create_dir_all)
                .and_then(|()| std::fs::write(&path, text))
                .map_err(|e| error(format!("{}: {e}", path.display())))?;
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
    Ok(())
}

fn fail(error: &dyn std::error::Error) -> ExitCode {
    let mut text = String::new();
    format::write_error(error, &mut text);
    eprintln!("{}", text.trim_end());
    ExitCode::FAILURE
}
