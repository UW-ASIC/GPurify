//! Command line: `gpurify <drc|erc|lvs|pex|all|lib> <layout> --deck <deck> [options]`,
//! `gpurify xor <layout> <other> --deck <deck> [--format text|json]`, or
//! `gpurify system <system.json> --reference <netlist> [--format text|json]`.

use crate::engine::{Checks, Inputs, RunOptions};
use crate::liberty::Accuracy;
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
    /// `xor`: the layout compared with `inputs.layout`, instead of checking.
    pub other: Option<PathBuf>,
    /// `system`: the system description, checked with `inputs.reference`
    /// as its system netlist; `inputs.layout` and `inputs.deck` are empty.
    pub system: Option<PathBuf>,
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
/// layers to skip and the operating temperature in the deck (`ignore gds(L,
/// D)`, `temperature`). `xor`'s second layout is its second positional input.
pub fn parse(argv: &[String]) -> Result<Cli, ArgError> {
    let Some((subcommand, rest)) = argv.split_first() else {
        return usage(
            "expected a subcommand: drc, erc, lvs, pex, all, lib, xor or system".to_string(),
        );
    };

    let mut layouts: Vec<&str> = Vec::new();
    let mut deck: Option<&str> = None;
    let mut format = Format::Text;
    let mut intent: Option<&str> = None;
    let mut reference: Vec<&str> = Vec::new();
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
            "--reference" => reference.push(value()?),
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
            positional => layouts.push(positional),
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
        // `xor` compares two layouts; its rows report as the DRC stage.
        "drc" | "xor" => (Checks { drc: true, ..none }, false, false, false),
        "erc" => (Checks { erc: true, ..none }, true, false, false),
        "lvs" => (Checks { lvs: true, ..none }, false, true, false),
        "pex" => (Checks { pex: true, ..none }, false, false, true),
        // `all` keeps LVS selected without a reference, so it reports Skipped.
        "all" => (Checks::ALL, true, true, false),
        // `lib`: a reference is cross-checked against the spec's pins, never
        // compared. `system`: each die names its deck and intent in the
        // system file, and the reference is the system netlist.
        "lib" | "system" => (none, false, true, false),
        other => {
            return usage(format!(
                "unknown subcommand {other}; expected drc, erc, lvs, pex, all, lib, xor or system"
            ))
        }
    };
    let is_xor = subcommand == "xor";
    match (is_xor, layouts.as_slice()) {
        (false, [_, second, ..]) => {
            return usage(format!("one layout file, but a second was given: {second}"))
        }
        (true, [_, _, third, ..]) => {
            return usage(format!("two layout files, but a third was given: {third}"))
        }
        (true, [] | [_]) => {
            return usage(
                "xor compares two layout files: xor <layout> <other> --deck <deck>".to_string(),
            )
        }
        _ => {}
    }
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
        ("--reference", !reference.is_empty(), takes_reference),
        ("--quasistatic", !quasistatic.is_empty(), takes_quasistatic),
    ] {
        if given && !allowed {
            return usage(format!("{subcommand} takes no {flag}"));
        }
    }
    if checks == (Checks { lvs: true, ..none }) && reference.is_empty() {
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
    if subcommand == "system" {
        if deck.is_some() {
            return usage(
                "system takes no --deck: each die names its deck in the system file".to_string(),
            );
        }
        let Some(&system) = layouts.first() else {
            return usage(
                "system needs a system description: system <system.json> --reference <netlist>"
                    .to_string(),
            );
        };
        let [reference] = reference.as_slice() else {
            return usage("system requires one system netlist (--reference)".to_string());
        };
        return Ok(Cli {
            inputs: Inputs {
                reference: vec![PathBuf::from(reference)],
                ..Inputs::default()
            },
            options: RunOptions {
                checks,
                lvs: gpurify_check::lvs::CompareOptions::default(),
                quasistatic_nets: Vec::new(),
            },
            format,
            lib: None,
            other: None,
            system: Some(PathBuf::from(system)),
        });
    }
    let Some(&layout) = layouts.first() else {
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
            reference: reference.into_iter().map(PathBuf::from).collect(),
            intent: intent.map(PathBuf::from),
        },
        options: RunOptions {
            checks,
            lvs: gpurify_check::lvs::CompareOptions::default(),
            quasistatic_nets: quasistatic,
        },
        format,
        lib,
        other: layouts.get(1).copied().map(PathBuf::from),
        system: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse, Cli, Format};
    use crate::engine::Checks;

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
        assert!(!all.inputs.reference.is_empty() && all.inputs.intent.is_some());
        // `docs/usage.md`: a Verilog top is given beside its cell library.
        let two =
            parse_str("lvs t --deck d --reference cells.spice --reference top.v").expect("legal");
        assert_eq!(
            two.inputs.reference,
            [
                std::path::PathBuf::from("cells.spice"),
                std::path::PathBuf::from("top.v")
            ]
        );
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
            [crate::liberty::Accuracy::Field]
        );
    }

    /// Oracle: `docs/usage.md` ("Multi-die systems"): `system` takes the
    /// system description as its one positional file and the system netlist
    /// as `--reference`, and selects none of the single-die checks.
    #[test]
    fn system_takes_its_description_and_netlist() {
        let cli =
            parse_str("system stack.json --reference sys.spice --format json").expect("legal");
        assert_eq!(
            cli.system.as_deref(),
            Some(std::path::Path::new("stack.json"))
        );
        assert_eq!(
            cli.inputs
                .reference
                .first()
                .map(std::path::PathBuf::as_path),
            Some(std::path::Path::new("sys.spice"))
        );
        assert_eq!(cli.format, Format::Json);
        assert!(cli.lib.is_none());
        assert_eq!(parse_str("drc t --deck d").expect("legal").system, None);
    }

    /// Oracle: construct-from-answer, against `docs/usage.md`: `xor` takes its
    /// two layouts in the order given and a report format; no other command
    /// has a second layout.
    #[test]
    fn xor_takes_its_two_layouts_in_order() {
        let cli = parse_str("xor a.gds b.gds --deck d --format json").expect("legal");
        assert_eq!(cli.inputs.layout.to_str(), Some("a.gds"));
        assert_eq!(
            cli.other.as_deref().and_then(std::path::Path::to_str),
            Some("b.gds")
        );
        assert_eq!(cli.format, Format::Json);
        assert!(parse_str("drc a.gds --deck d")
            .expect("legal")
            .other
            .is_none());
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
            (
                "",
                "expected a subcommand: drc, erc, lvs, pex, all, lib, xor or system",
            ),
            (
                "dcr t --deck d",
                "unknown subcommand dcr; expected drc, erc, lvs, pex, all, lib, xor or system",
            ),
            (
                "system s.json --deck d --reference r",
                "system takes no --deck: each die names its deck in the system file",
            ),
            (
                "system --reference r",
                "system needs a system description: system <system.json> --reference <netlist>",
            ),
            (
                "system s.json",
                "system requires a system netlist (--reference)",
            ),
            (
                "system s.json --reference r --intent i",
                "system takes no --intent",
            ),
            (
                "system s.json --reference r --format spef",
                "--format spef is not something this check produces",
            ),
            (
                "xor t --deck d",
                "xor compares two layout files: xor <layout> <other> --deck <deck>",
            ),
            (
                "xor t u v --deck d",
                "two layout files, but a third was given: v",
            ),
            ("xor t u --deck d --intent i", "xor takes no --intent"),
            (
                "xor t u --deck d --quasistatic n",
                "xor takes no --quasistatic",
            ),
            (
                "xor t u --deck d --format spef",
                "--format spef is not something this check produces",
            ),
            // The temperature is the deck's, never a flag.
            (
                "pex t --deck d --temperature 85",
                "unknown option --temperature",
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
