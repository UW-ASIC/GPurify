//! Command line: `gpurify <drc|erc|lvs|pex|all> <layout> --deck <deck> [options]`.

use gpurify::engine::{Checks, Inputs, RunOptions};
use gpurify_ingest::layout::UnknownLayers;
use std::path::PathBuf;

/// How to render the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
    Spef,
    Dspf,
}

/// A parsed command line.
#[derive(Debug)]
pub struct Cli {
    pub inputs: Inputs,
    pub options: RunOptions,
    pub format: Format,
    /// `None` is stdout.
    pub output: Option<PathBuf>,
    /// Run twice at two thread counts and fail if the reports differ.
    pub check_determinism: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ArgError(String);

fn usage<T>(message: String) -> Result<T, ArgError> {
    Err(ArgError(message))
}

/// Parse `argv` (without the program name). An option a subcommand has no use
/// for is refused, never dropped; `--grid` has no default.
pub fn parse(argv: &[String]) -> Result<Cli, ArgError> {
    let Some((subcommand, rest)) = argv.split_first() else {
        return usage("expected a subcommand: drc, erc, lvs, pex or all".to_string());
    };

    let mut layout: Option<&str> = None;
    let mut deck: Option<&str> = None;
    let mut format = Format::Text;
    let mut output: Option<&str> = None;
    let mut threads: Option<usize> = None;
    let mut grid: Option<u32> = None;
    let mut check_determinism = false;
    let mut strict_layers = true;
    let mut intent: Option<&str> = None;
    let mut reference: Option<&str> = None;
    let mut quasistatic: Vec<String> = Vec::new();
    let mut quasistatic_inductance = false;

    let mut tokens = rest.iter().map(String::as_str);
    while let Some(token) = tokens.next() {
        // Every valued option names a path, a net or a number: none is empty.
        let mut value = || match tokens.next() {
            None => usage(format!("{token} wants a value")),
            Some("") => usage(format!("{token} was given an empty value")),
            Some(value) => Ok(value),
        };
        match token {
            "--deck" => deck = Some(value()?),
            "--output" => output = Some(value()?),
            "--intent" => intent = Some(value()?),
            "--reference" => reference = Some(value()?),
            "--quasistatic" => quasistatic.push(value()?.to_string()),
            "--format" => {
                format = match value()? {
                    "text" => Format::Text,
                    "json" => Format::Json,
                    "spef" => Format::Spef,
                    "dspf" => Format::Dspf,
                    other => {
                        return usage(format!(
                            "unknown --format {other}; expected text, json, spef or dspf"
                        ))
                    }
                }
            }
            "--threads" => {
                let raw = value()?;
                match raw.parse().ok().filter(|count| *count > 0) {
                    Some(count) => threads = Some(count),
                    None => return usage(format!("--threads wants a positive count, not {raw:?}")),
                }
            }
            "--grid" => {
                let raw = value()?;
                match raw.parse().ok().filter(|per_um| *per_um > 0) {
                    Some(per_um) => grid = Some(per_um),
                    None => {
                        return usage(format!(
                            "--grid wants a positive count of database units per \
                             micrometre, not {raw:?}"
                        ))
                    }
                }
            }
            "--quasistatic-inductance" => quasistatic_inductance = true,
            "--check-determinism" => check_determinism = true,
            "--strict-layers" => strict_layers = true,
            "--no-strict-layers" => strict_layers = false,
            _ if token.starts_with('-') => return usage(format!("unknown option {token}")),
            "" => return usage("the layout file was given as an empty path".to_string()),
            positional => {
                if layout.replace(positional).is_some() {
                    return usage(format!(
                        "one layout file, but a second was given: {positional}"
                    ));
                }
            }
        }
    }

    let none = Checks {
        drc: false,
        erc: false,
        lvs: false,
        pex: false,
    };
    // (checks, takes --intent, takes --reference, takes --quasistatic*)
    let (checks, takes_intent, takes_reference, takes_quasistatic) = match subcommand.as_str() {
        "drc" => (Checks { drc: true, ..none }, false, false, false),
        "erc" => (Checks { erc: true, ..none }, true, false, false),
        "lvs" => (Checks { lvs: true, ..none }, false, true, false),
        "pex" => (Checks { pex: true, ..none }, false, false, true),
        // `all` keeps LVS selected without a reference, so it reports Skipped.
        "all" => (Checks::ALL, true, true, false),
        other => {
            return usage(format!(
                "unknown subcommand {other}; expected drc, erc, lvs, pex or all"
            ))
        }
    };
    for (flag, given, allowed) in [
        ("--intent", intent.is_some(), takes_intent),
        ("--reference", reference.is_some(), takes_reference),
        ("--quasistatic", !quasistatic.is_empty(), takes_quasistatic),
        ("--quasistatic-inductance", quasistatic_inductance, takes_quasistatic),
    ] {
        if given && !allowed {
            return usage(format!("{subcommand} takes no {flag}"));
        }
    }
    if checks == (Checks { lvs: true, ..none }) && reference.is_none() {
        return usage("lvs requires a reference netlist (--reference)".to_string());
    }
    // A check with no parasitic network would write an empty file that reads as clean.
    if matches!(format, Format::Spef | Format::Dspf) && !checks.pex {
        let name = if format == Format::Spef { "spef" } else { "dspf" };
        return usage(format!(
            "--format {name} is not something this check produces"
        ));
    }
    let Some(layout) = layout else {
        return usage(format!(
            "{subcommand} needs a layout file: {subcommand} <layout> --deck <deck>"
        ));
    };
    let Some(deck) = deck else {
        return usage("--deck <deck> is required".to_string());
    };

    Ok(Cli {
        inputs: Inputs {
            layout: PathBuf::from(layout),
            deck: PathBuf::from(deck),
            grid: grid.map(|per_um| {
                gpurify_geom::Grid::new(i64::from(per_um)).expect("the parser refuses zero")
            }),
            reference: reference.map(PathBuf::from),
            intent: intent.map(PathBuf::from),
            unknown_layers: if strict_layers {
                UnknownLayers::Reject
            } else {
                UnknownLayers::Drop
            },
        },
        options: RunOptions {
            checks,
            lvs: gpurify_check::lvs::CompareOptions::default(),
            quasistatic_nets: quasistatic,
            quasistatic_inductance,
            threads,
        },
        format,
        output: output.map(PathBuf::from),
        check_determinism,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse, Cli, Format};
    use gpurify::engine::Checks;

    fn parse_str(argv: &str) -> Result<Cli, String> {
        let argv: Vec<String> = argv.split_whitespace().map(str::to_string).collect();
        parse(&argv).map_err(|error| error.to_string())
    }

    #[test]
    fn a_full_command_line_reaches_every_field() {
        let cli = parse_str(
            "pex top.gds --deck d.json --grid 1000 --format spef --output o --threads 4 \
             --check-determinism --no-strict-layers --quasistatic vdd --quasistatic clk \
             --quasistatic-inductance",
        )
        .expect("a legal command line");
        assert_eq!(cli.inputs.layout.to_str(), Some("top.gds"));
        assert_eq!(cli.inputs.deck.to_str(), Some("d.json"));
        assert_eq!(cli.inputs.grid.map(gpurify_geom::Grid::dbu_per_um), Some(1000));
        assert_eq!(cli.format, Format::Spef);
        assert_eq!(cli.output.as_deref().and_then(|p| p.to_str()), Some("o"));
        assert_eq!(cli.options.threads, Some(4));
        assert!(cli.check_determinism);
        assert_eq!(
            cli.inputs.unknown_layers,
            gpurify_ingest::layout::UnknownLayers::Drop
        );
        assert_eq!(cli.options.quasistatic_nets, ["vdd", "clk"]);
        assert!(cli.options.quasistatic_inductance);

        let all = parse_str("all t --deck d --reference r --intent i").expect("legal");
        assert_eq!(all.options.checks, Checks::ALL);
        assert!(all.inputs.reference.is_some() && all.inputs.intent.is_some());
    }

    #[test]
    fn the_defaults_are_text_strict_and_gridless() {
        let cli = parse_str("drc t --deck d").expect("legal");
        assert_eq!(cli.format, Format::Text);
        assert!(cli.inputs.grid.is_none() && cli.output.is_none());
        assert_eq!(
            cli.inputs.unknown_layers,
            gpurify_ingest::layout::UnknownLayers::Reject
        );
        assert_eq!(parse_str("all t --deck d").expect("legal").options.checks, Checks::ALL);
    }

    #[test]
    fn every_malformed_command_line_is_refused_with_its_message() {
        let cases = [
            ("", "expected a subcommand: drc, erc, lvs, pex or all"),
            ("dcr t --deck d", "unknown subcommand dcr; expected drc, erc, lvs, pex or all"),
            ("drc --deck d", "drc needs a layout file: drc <layout> --deck <deck>"),
            ("drc t", "--deck <deck> is required"),
            ("drc t u --deck d", "one layout file, but a second was given: u"),
            ("drc t --deck", "--deck wants a value"),
            ("drc t --deck d --nonsense", "unknown option --nonsense"),
            ("drc t --deck d --format gds", "unknown --format gds; expected text, json, spef or dspf"),
            ("drc t --deck d --threads 0", "--threads wants a positive count, not \"0\""),
            ("drc t --deck d --grid 1.5", "--grid wants a positive count of database units per micrometre, not \"1.5\""),
            ("drc t --deck d --intent i", "drc takes no --intent"),
            ("erc t --deck d --reference r", "erc takes no --reference"),
            ("all t --deck d --quasistatic-inductance", "all takes no --quasistatic-inductance"),
            ("lvs t --deck d", "lvs requires a reference netlist (--reference)"),
            ("drc t --deck d --format dspf", "--format dspf is not something this check produces"),
        ];
        for (argv, message) in cases {
            assert_eq!(parse_str(argv).err().as_deref(), Some(message), "{argv:?}");
        }
    }
}
