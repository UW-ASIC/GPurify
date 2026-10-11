//! Command line: `gpurify <drc|erc|lvs|pex|all|lib> <layout> --deck <deck> [options]`.

use gpurify::engine::{Checks, Inputs, RunOptions};
use gpurify::liberty::Accuracy;
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
    /// `lib`: generate a macro's Liberty files instead of checking.
    pub lib: Option<LibArgs>,
}

/// What `lib` was asked for.
#[derive(Debug)]
pub struct LibArgs {
    pub spec: PathBuf,
    /// One entry, or every level for `--accuracy all`.
    pub accuracy: Vec<Accuracy>,
    pub output_dir: PathBuf,
    pub lef: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ArgError(String);

fn usage<T>(message: String) -> Result<T, ArgError> {
    Err(ArgError(message))
}

/// Parse `argv` (without the program name). An option a subcommand has no use
/// for is refused, never dropped.
///
/// The only options are the files a run reads, the output form, and the choice
/// of method (`--quasistatic` for PEX, `--accuracy` for `lib`). Everything else
/// lives where it is already stated: the grid in the layout's `UNITS` record,
/// layers to skip in the deck (`ignore gds(L, D)`).
pub fn parse(argv: &[String]) -> Result<Cli, ArgError> {
    let Some((subcommand, rest)) = argv.split_first() else {
        return usage("expected a subcommand: drc, erc, lvs, pex, all or lib".to_string());
    };

    let mut layout: Option<&str> = None;
    let mut deck: Option<&str> = None;
    let mut format = Format::Text;
    let mut intent: Option<&str> = None;
    let mut reference: Option<&str> = None;
    let mut quasistatic: Vec<String> = Vec::new();
    let mut spec: Option<&str> = None;
    let mut accuracy: Option<&str> = None;
    let mut output_dir: Option<&str> = None;
    let mut lef: Option<&str> = None;

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
            "--intent" => intent = Some(value()?),
            "--reference" => reference = Some(value()?),
            "--quasistatic" => quasistatic.push(value()?.to_string()),
            "--spec" => spec = Some(value()?),
            "--accuracy" => accuracy = Some(value()?),
            "--output-dir" => output_dir = Some(value()?),
            "--lef" => lef = Some(value()?),
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
        // A reference is cross-checked against the spec's pins, never compared.
        "lib" => (none, false, true, false),
        other => {
            return usage(format!(
                "unknown subcommand {other}; expected drc, erc, lvs, pex, all or lib"
            ))
        }
    };
    let is_lib = subcommand == "lib";
    for (flag, given) in [
        ("--spec", spec.is_some()),
        ("--accuracy", accuracy.is_some()),
        ("--output-dir", output_dir.is_some()),
        ("--lef", lef.is_some()),
    ] {
        if given && !is_lib {
            return usage(format!("{subcommand} takes no {flag}"));
        }
    }
    if is_lib && format != Format::Text {
        return usage("lib writes its files under --output-dir and takes no --format".to_string());
    }
    let lib = if is_lib {
        let Some(spec) = spec else {
            return usage("lib requires a macro spec (--spec)".to_string());
        };
        let Some(output_dir) = output_dir else {
            return usage("lib requires --output-dir".to_string());
        };
        let accuracy = match accuracy.unwrap_or("spice") {
            "all" => Accuracy::ALL.to_vec(),
            text => match Accuracy::parse(text) {
                Some(level) => vec![level],
                None => {
                    return usage(format!(
                        "unknown --accuracy {text}; expected interface, analytical, field, \
                         spice, statistical (or 0 to 4), or all"
                    ))
                }
            },
        };
        Some(LibArgs {
            spec: PathBuf::from(spec),
            accuracy,
            output_dir: PathBuf::from(output_dir),
            lef: lef.map(PathBuf::from),
        })
    } else {
        None
    };
    for (flag, given, allowed) in [
        ("--intent", intent.is_some(), takes_intent),
        ("--reference", reference.is_some(), takes_reference),
        ("--quasistatic", !quasistatic.is_empty(), takes_quasistatic),
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
        let name = if format == Format::Spef {
            "spef"
        } else {
            "dspf"
        };
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
            reference: reference.map(PathBuf::from),
            intent: intent.map(PathBuf::from),
        },
        options: RunOptions {
            checks,
            lvs: gpurify_check::lvs::CompareOptions::default(),
            quasistatic_nets: quasistatic,
        },
        format,
        lib,
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

    /// Oracle: construct-from-answer, against `docs/usage.md`: every value
    /// reads back as given, `--quasistatic` repeats in order, and `all` selects
    /// all four checks.
    #[test]
    fn a_full_command_line_reaches_every_field() {
        let cli = parse_str(
            "pex top.gds --deck d.deck --format spef --quasistatic vdd --quasistatic clk",
        )
        .expect("a legal command line");
        assert_eq!(cli.inputs.layout.to_str(), Some("top.gds"));
        assert_eq!(cli.inputs.deck.to_str(), Some("d.deck"));
        assert_eq!(cli.format, Format::Spef);
        assert_eq!(cli.options.quasistatic_nets, ["vdd", "clk"]);

        let all = parse_str("all t --deck d --reference r --intent i").expect("legal");
        assert_eq!(all.options.checks, Checks::ALL);
        assert!(all.inputs.reference.is_some() && all.inputs.intent.is_some());
    }

    /// Oracle: `docs/liberty.md`: `--accuracy all` is the five levels, `2` is
    /// `field` (levels 0 to 4 from `interface`), and `docs/usage.md`: `lib`
    /// runs no check.
    #[test]
    fn lib_takes_its_spec_accuracy_and_directory() {
        let cli =
            parse_str("lib t --deck d --spec s.json --output-dir o --accuracy all --lef m.lef")
                .expect("legal");
        let lib = cli.lib.expect("a lib run");
        assert_eq!(lib.accuracy.len(), 5);
        assert!(lib.lef.is_some());
        assert_eq!(
            cli.options.checks,
            Checks {
                drc: false,
                erc: false,
                lvs: false,
                pex: false
            }
        );
        let one = parse_str("lib t --deck d --spec s --output-dir o --accuracy 2").expect("legal");
        assert_eq!(
            one.lib.expect("lib").accuracy,
            [gpurify::liberty::Accuracy::Field]
        );
    }

    /// Oracle: `docs/usage.md`: `--format` defaults to `text`, and `all` is all
    /// four checks.
    #[test]
    fn the_default_format_is_text() {
        let cli = parse_str("drc t --deck d").expect("legal");
        assert_eq!(cli.format, Format::Text);
        assert_eq!(
            parse_str("all t --deck d").expect("legal").options.checks,
            Checks::ALL
        );
    }

    /// Oracle: the command line `docs/usage.md` documents. Each line breaks one
    /// of its rules (a missing or unknown subcommand, option or value, an
    /// option the command does not take, an option the docs moved elsewhere),
    /// and the expected message names that rule.
    #[test]
    fn every_malformed_command_line_is_refused_with_its_message() {
        let cases = [
            ("", "expected a subcommand: drc, erc, lvs, pex, all or lib"),
            (
                "dcr t --deck d",
                "unknown subcommand dcr; expected drc, erc, lvs, pex, all or lib",
            ),
            (
                "lib t --deck d --output-dir o",
                "lib requires a macro spec (--spec)",
            ),
            ("lib t --deck d --spec s", "lib requires --output-dir"),
            ("drc t --deck d --spec s", "drc takes no --spec"),
            (
                "lib t --deck d --spec s --output-dir o --accuracy 9",
                "unknown --accuracy 9; expected interface, analytical, field, spice, \
                 statistical (or 0 to 4), or all",
            ),
            (
                "drc --deck d",
                "drc needs a layout file: drc <layout> --deck <deck>",
            ),
            ("drc t", "--deck <deck> is required"),
            (
                "drc t u --deck d",
                "one layout file, but a second was given: u",
            ),
            ("drc t --deck", "--deck wants a value"),
            ("drc t --deck d --nonsense", "unknown option --nonsense"),
            (
                "drc t --deck d --format gds",
                "unknown --format gds; expected text, json, spef or dspf",
            ),
            // The grid is the layout's UNITS record; layers to skip are in the deck.
            ("drc t --deck d --grid 1000", "unknown option --grid"),
            (
                "drc t --deck d --no-strict-layers",
                "unknown option --no-strict-layers",
            ),
            ("drc t --deck d --output o", "unknown option --output"),
            (
                "drc t --deck d --check-determinism",
                "unknown option --check-determinism",
            ),
            (
                "lib t --deck d --spec s --output-dir o --work w",
                "unknown option --work",
            ),
            ("drc t --deck d --intent i", "drc takes no --intent"),
            ("erc t --deck d --reference r", "erc takes no --reference"),
            (
                "all t --deck d --quasistatic n",
                "all takes no --quasistatic",
            ),
            (
                "pex t --deck d --quasistatic-inductance",
                "unknown option --quasistatic-inductance",
            ),
            (
                "lib t --deck d --spec s --output-dir o --format json",
                "lib writes its files under --output-dir and takes no --format",
            ),
            (
                "lvs t --deck d",
                "lvs requires a reference netlist (--reference)",
            ),
            (
                "drc t --deck d --format dspf",
                "--format dspf is not something this check produces",
            ),
        ];
        for (argv, message) in cases {
            assert_eq!(parse_str(argv).err().as_deref(), Some(message), "{argv:?}");
        }
    }
}
