//! Command line surface.
//!
//! Usage-driven: the shape below is what someone running a signoff check
//! actually types, not a mirror of the library's structure. Where the two
//! disagree, this follows the usage and translates.

use std::path::PathBuf;

/// `gpurify <check> --deck <deck> <layout> [options]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub command: Command,
    pub common: Common,
}

/// Which check to run.
///
/// A subcommand rather than a flag, because the required inputs differ: `lvs`
/// needs a reference netlist and the others do not, and a subcommand can say so
/// in its own usage line instead of failing at runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Design rule check.
    Drc,
    /// Electrical rule check. Takes `--intent` for the rules that need it.
    Erc { intent: Option<PathBuf> },
    /// Layout versus schematic. The reference netlist is required.
    Lvs { reference: PathBuf },
    /// Parasitic extraction.
    Pex {
        /// Nets to solve by field solve rather than closed form. Everything
        /// else is analytical.
        quasistatic: Vec<String>,
    },
    /// Everything at once. Optional inputs disable their checks, and the
    /// summary reports each as skipped rather than passed.
    All {
        reference: Option<PathBuf>,
        intent: Option<PathBuf>,
    },
}

/// Flags every subcommand shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Common {
    pub layout: PathBuf,
    pub deck: PathBuf,
    pub format: Format,
    /// Where output goes. `None` is stdout.
    pub output: Option<PathBuf>,
    /// Worker threads. Speed only — output must be byte-identical at any
    /// value, and `--check-determinism` is how you confirm that.
    pub threads: Option<usize>,
    /// Run twice, at one thread and at many, and fail if the outputs differ.
    /// Exposed on the command line because it is the determinism gate, and a
    /// gate nobody can run is not a gate.
    pub check_determinism: bool,
    /// Reject geometry on layers the deck does not describe, rather than
    /// dropping it. On by default; a signoff run wants it.
    pub strict_layers: bool,
    /// Database units per micrometre, from `--grid`.
    ///
    /// `None` is the absence of the flag, and it stops the run at
    /// [`LoadError::NoGrid`](gpurify_ingest::layout::LoadError) before a file is
    /// opened. That is deliberate and must stay: a deck file does **not** declare
    /// a resolution — `read_deck` is *handed* one — so defaulting a value here
    /// would silently reinterpret every limit in the deck, turning a loud dead
    /// binary into a quiet wrong one. Absent means absent.
    pub grid: Option<u32>,
}

/// How to render the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// For a person: grouped by rule, counts first, skipped rules called out.
    Text,
    /// For a machine, and what the determinism gate compares.
    Json,
    /// Violation markers as GDS, for a layout viewer.
    Gds,
    /// The extracted parasitic network as SPEF, for a timing tool.
    Spef,
    /// The same network as DSPF, for a circuit simulator.
    Dspf,
}

impl Format {
    /// True for the formats whose body is the parasitic network rather than the
    /// violation table.
    ///
    /// Only `pex` and `all` fill [`Outputs::parasitics`](gpurify_engine::Outputs),
    /// so asking any other check for one is a usage error caught before a file
    /// is read — not an empty netlist written after a run that had nothing to
    /// put in it.
    pub fn is_parasitic(self) -> bool {
        matches!(self, Format::Spef | Format::Dspf)
    }
}

/// Parse and validate.
///
/// **Decision** — pure, argv in, either [`Args`] or a message out. Pure so the
/// whole surface is table-testable without a process: a list of argument
/// vectors and their expected parses, including every rejection.
///
/// `argv` **excludes the program name**: `argv[0]` is the subcommand, so a
/// caller passes `std::env::args().skip(1)` and a test passes the arguments it
/// means. An empty slice is a usage error, not a default run.
pub fn parse(argv: &[String]) -> Result<Args, ArgError> {
    let (subcommand, rest) = argv.split_first().ok_or_else(|| {
        ArgError::Usage("expected a subcommand: drc, erc, lvs, pex or all".to_string())
    })?;

    let mut layout: Option<&str> = None;
    let mut deck: Option<&str> = None;
    let mut format = Format::Text;
    let mut output: Option<&str> = None;
    let mut threads: Option<usize> = None;
    let mut grid: Option<u32> = None;
    let mut check_determinism = false;
    // On by default. Dropping geometry from a layer the deck never described
    // is the fail-open case, so it takes an explicit `--no-strict-layers`.
    let mut strict_layers = true;
    let mut intent: Option<&str> = None;
    let mut reference: Option<&str> = None;
    let mut quasistatic: Vec<String> = Vec::new();

    // An index walk, and permanently so: the bulk-loop discipline scopes to
    // thousands of homogeneous rows, and argv is tens of heterogeneous tokens
    // whose meanings differ per token. An option also consumes the token after
    // it, so `taken` carries state from one iteration to the next — the chain
    // dependency `/simd-loops` triage names as the blocker. Not debt.
    //
    // Every option a subcommand has no field for is accepted here and refused
    // below, so the refusal message can name the subcommand.
    let mut index = 0;
    while index < rest.len() {
        let token = rest[index].as_str();
        let mut taken = 1;
        match token {
            "--deck" => {
                deck = Some(value(rest, index)?);
                taken = 2;
            }
            "--format" => {
                format = format_named(value(rest, index)?)?;
                taken = 2;
            }
            "--output" => {
                output = Some(value(rest, index)?);
                taken = 2;
            }
            "--threads" => {
                let raw = value(rest, index)?;
                threads = Some(raw.parse().ok().filter(|count| *count > 0).ok_or_else(|| {
                    ArgError::Usage(format!("--threads wants a positive count, not {raw:?}"))
                })?);
                taken = 2;
            }
            // Optional, not required, and that is the whole grammar decision:
            // making it required would invalidate every command line that
            // already parses, while defaulting it would reinterpret the deck.
            // Absent keeps exactly the behaviour this binary had — a refusal at
            // load — and supplying it is what makes any stage reachable at all.
            "--grid" => {
                let raw = value(rest, index)?;
                grid = Some(raw.parse().ok().filter(|per_um| *per_um > 0).ok_or_else(|| {
                    ArgError::Usage(format!(
                        "--grid wants a positive count of database units per \
                         micrometre, not {raw:?}"
                    ))
                })?);
                taken = 2;
            }
            "--intent" => {
                intent = Some(value(rest, index)?);
                taken = 2;
            }
            "--reference" => {
                reference = Some(value(rest, index)?);
                taken = 2;
            }
            "--quasistatic" => {
                quasistatic.push(value(rest, index)?.to_string());
                taken = 2;
            }
            "--check-determinism" => check_determinism = true,
            "--strict-layers" => strict_layers = true,
            "--no-strict-layers" => strict_layers = false,
            _ if token.starts_with('-') => {
                return Err(ArgError::Usage(format!("unknown option {token}")));
            }
            // An empty positional is refused for the same reason `value` refuses
            // an empty option value, and separately: it would satisfy the
            // `layout.ok_or_else` below and reach `Inputs::layout` as a path
            // that names no file, which `to_inputs` already debug-asserts
            // against.
            "" => {
                return Err(ArgError::Usage(
                    "the layout file was given as an empty path".to_string(),
                ))
            }
            positional => {
                // Branchy on purpose: the taken side returns, and one token
                // per command line is not a loop the predictor can miss on.
                if layout.replace(positional).is_some() {
                    return Err(ArgError::Usage(format!(
                        "one layout file, but a second was given: {positional}"
                    )));
                }
            }
        }
        index += taken;
    }
    // Every option that consumed a second token proved it existed first, so
    // the walk lands exactly on the end rather than one past it.
    debug_assert_eq!(index, rest.len());
    debug_assert!(quasistatic.len() * 2 <= rest.len());

    // An option this subcommand has no field for is refused rather than
    // dropped: accepting `--intent` on a drc run discards an input the caller
    // asked to be checked against, and says nothing about having done so.
    let refuse = |flag: &str, given: bool| {
        if given {
            Err(ArgError::Usage(format!("{subcommand} takes no {flag}")))
        } else {
            Ok(())
        }
    };
    let command = match subcommand.as_str() {
        "drc" => {
            refuse("--intent", intent.is_some())?;
            refuse("--reference", reference.is_some())?;
            refuse("--quasistatic", !quasistatic.is_empty())?;
            Command::Drc
        }
        "erc" => {
            refuse("--reference", reference.is_some())?;
            refuse("--quasistatic", !quasistatic.is_empty())?;
            Command::Erc {
                intent: intent.map(PathBuf::from),
            }
        }
        "lvs" => {
            refuse("--intent", intent.is_some())?;
            refuse("--quasistatic", !quasistatic.is_empty())?;
            Command::Lvs {
                reference: reference
                    .map(PathBuf::from)
                    .ok_or(ArgError::MissingReference)?,
            }
        }
        "pex" => {
            refuse("--intent", intent.is_some())?;
            refuse("--reference", reference.is_some())?;
            Command::Pex { quasistatic }
        }
        "all" => {
            refuse("--quasistatic", !quasistatic.is_empty())?;
            Command::All {
                reference: reference.map(PathBuf::from),
                intent: intent.map(PathBuf::from),
            }
        }
        other => return Err(ArgError::UnknownCommand(other.to_string())),
    };

    // GDS output is violation markers. The two checks that produce none would
    // write an empty layout, which reads in a viewer exactly like a clean run.
    if format == Format::Gds && matches!(command, Command::Lvs { .. } | Command::Pex { .. }) {
        return Err(ArgError::FormatMismatch("gds"));
    }
    // The mirror of it: SPEF and DSPF are the parasitic network, and only `pex`
    // and `all` extract one. Writing an empty netlist for a check that never
    // ran extraction is the same false clean read from the other end.
    if format.is_parasitic() && !matches!(command, Command::Pex { .. } | Command::All { .. }) {
        return Err(ArgError::FormatMismatch(match format {
            Format::Spef => "spef",
            _ => "dspf",
        }));
    }

    let layout = layout.ok_or_else(|| {
        ArgError::Usage(format!(
            "{subcommand} needs a layout file: {subcommand} <layout> --deck <deck>"
        ))
    })?;
    let deck = deck.ok_or_else(|| ArgError::Usage("--deck <deck> is required".to_string()))?;
    // The guarantee `to_inputs` opens by asserting. Stated at the producing end
    // too, because a consumer asserting what its producer never promised is a
    // panic waiting on an input nobody tried.
    debug_assert!(!layout.is_empty() && !deck.is_empty());

    Ok(Args {
        command,
        common: Common {
            layout: PathBuf::from(layout),
            deck: PathBuf::from(deck),
            format,
            output: output.map(PathBuf::from),
            threads,
            check_determinism,
            strict_layers,
            grid,
        },
    })
}

/// The token after the option at `index`, or the usage error naming what was
/// left off the end of the command line.
///
/// The empty string is refused here rather than at each call site: every option
/// on this command line names a path or a net, and neither has an empty
/// spelling. `--deck ""` would otherwise reach `engine` as a path that opens
/// nothing, and `--quasistatic ""` as a net name that matches nothing and so
/// silently field-solves one net fewer than was asked for.
fn value(rest: &[String], index: usize) -> Result<&str, ArgError> {
    debug_assert!(index < rest.len());
    let token = rest
        .get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| ArgError::Usage(format!("{} wants a value", rest[index])))?;
    if token.is_empty() {
        Err(ArgError::Usage(format!(
            "{} was given an empty value",
            rest[index]
        )))
    } else {
        Ok(token)
    }
}

/// One name, one variant. An unknown name is a usage error rather than a silent
/// fall back to text — a run asked for JSON and given text is a run whose output
/// nothing downstream can read.
fn format_named(name: &str) -> Result<Format, ArgError> {
    match name {
        "text" => Ok(Format::Text),
        "json" => Ok(Format::Json),
        "gds" => Ok(Format::Gds),
        "spef" => Ok(Format::Spef),
        "dspf" => Ok(Format::Dspf),
        other => Err(ArgError::Usage(format!(
            "unknown --format {other}; expected text, json, gds, spef or dspf"
        ))),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArgError {
    #[error("{0}")]
    Usage(String),
    #[error("unknown subcommand {0}; expected drc, erc, lvs, pex or all")]
    UnknownCommand(String),
    #[error("lvs requires a reference netlist (--reference)")]
    MissingReference,
    #[error("--format {0} is not something this check produces")]
    FormatMismatch(&'static str),
}

/// Translate the parsed arguments into what `engine` wants.
///
/// **Decision** — pure. Separate from [`parse`] so the mapping from a
/// convenient command line to a precise library call is testable on its own,
/// and so the two can differ without one deforming the other.
pub fn to_inputs(args: &Args) -> (gpurify_engine::Inputs, gpurify_engine::RunOptions) {
    debug_assert!(
        !args.common.layout.as_os_str().is_empty() && !args.common.deck.as_os_str().is_empty(),
        "parse rejects a command line missing either path"
    );

    let off = gpurify_engine::Checks {
        drc: false,
        erc: false,
        lvs: false,
        pex: false,
    };
    // One match, because all four outputs are the same decision: the
    // subcommand names both the check to select and the inputs it may carry.
    // `All` selects LVS whether or not a reference was given — the run then
    // reports it Skipped, where dropping the check would leave a summary that
    // never mentions LVS at all.
    let (checks, reference, intent, quasistatic_nets) = match &args.command {
        Command::Drc => (
            gpurify_engine::Checks { drc: true, ..off },
            None,
            None,
            Vec::new(),
        ),
        Command::Erc { intent } => (
            gpurify_engine::Checks { erc: true, ..off },
            None,
            intent.clone(),
            Vec::new(),
        ),
        Command::Lvs { reference } => (
            gpurify_engine::Checks { lvs: true, ..off },
            Some(reference.clone()),
            None,
            Vec::new(),
        ),
        Command::Pex { quasistatic } => (
            gpurify_engine::Checks { pex: true, ..off },
            None,
            None,
            quasistatic.clone(),
        ),
        Command::All { reference, intent } => (
            gpurify_engine::Checks::ALL,
            reference.clone(),
            intent.clone(),
            Vec::new(),
        ),
    };
    debug_assert!(checks != off, "every subcommand selects at least one check");
    debug_assert!(quasistatic_nets.is_empty() || checks.pex);

    let inputs = gpurify_engine::Inputs {
        layout: args.common.layout.clone(),
        deck: args.common.deck.clone(),
        // Supplied by `--grid`, and `None` when the flag is absent. `Grid::new`
        // refuses a zero, which the parser has already excluded, so the
        // `and_then` keeps the absence and cannot invent a resolution.
        grid: args.common.grid.map(|per_um| {
            gpurify_units::Grid::new(i64::from(per_um))
                .expect("the parser refuses a non-positive resolution, so this cannot fail")
        }),
        reference,
        intent,
        unknown_layers: if args.common.strict_layers {
            gpurify_ingest::layout::UnknownLayers::Reject
        } else {
            gpurify_ingest::layout::UnknownLayers::Drop
        },
    };
    #[expect(
        clippy::default_trait_access,
        reason = "the lint wants `CompareOptions::default()`, but `gpurify_lvs` is \
                  not a dependency of `cli` and the module graph does not have that \
                  edge; naming the type would mean adding a dependency to satisfy a \
                  spelling. `engine` does not re-export it either"
    )]
    let options = gpurify_engine::RunOptions {
        checks,
        lvs: Default::default(),
        quasistatic_nets,
        threads: args.common.threads,
    };
    (inputs, options)
}

/// The command line, table-tested.
///
/// [`parse`] and [`to_inputs`] are private to the binary, so their tests live
/// here rather than in `tests/` — there is no library target to reach them
/// through. Every case below is **construct-from-answer**: an argument vector
/// whose correct parse is decided before the parser runs, which is the whole
/// reason the Definition-Phase made these two functions pure.
///
/// # The grammar these tests fix
///
/// The frozen signatures name the fields but not their spelling on the command
/// line, so the spelling is settled here and the Implementation-Phase conforms
/// to it:
///
/// ```text
/// gpurify <check> <layout> --deck <deck> [options]
///
/// checks    drc | erc | lvs | pex | all
/// shared    --deck <path>              required
///           --format text|json|gds     default text
///           --output <path>            default stdout
///           --threads <n>              default: unset
///           --check-determinism        default off
///           --strict-layers            default on
///           --no-strict-layers         turns it off
/// erc, all  --intent <path>            optional
/// lvs       --reference <path>         required
/// all       --reference <path>         optional
/// pex       --quasistatic <net>        repeatable
/// ```
///
/// `argv` here is the arguments **without** the program name: `argv[0]` is the
/// subcommand. The signature says only "argv in", so that is a choice, and it
/// is recorded here because nothing else in the tree states it.
#[cfg(test)]
mod tests {
    use super::{parse, to_inputs, ArgError, Args, Command, Format};
    use gpurify_engine::Checks;
    use gpurify_testgen::Rng;
    use std::path::{Path, PathBuf};

    /// The shortest command line that parses, as a starting point for the
    /// tests that vary one thing about it.
    const BASE: &[&str] = &["drc", "top.gds", "--deck", "rules.json"];

    fn owned(argv: &[&str]) -> Vec<String> {
        argv.iter().map(|arg| (*arg).to_string()).collect()
    }

    fn parse_ok(argv: &[&str]) -> Args {
        match parse(&owned(argv)) {
            Ok(parsed) => parsed,
            Err(error) => panic!("{argv:?} should parse, but was rejected: {error}"),
        }
    }

    fn parse_err(argv: &[&str]) -> ArgError {
        match parse(&owned(argv)) {
            Ok(parsed) => panic!("{argv:?} should be rejected, but parsed as {parsed:?}"),
            Err(error) => error,
        }
    }

    /// `Args` and `Command` carry no `PartialEq`, so a table test names the
    /// variant rather than comparing values. Recorded in the return value as a
    /// Definition-Phase gap.
    fn command_name(command: &Command) -> &'static str {
        match command {
            Command::Drc => "drc",
            Command::Erc { .. } => "erc",
            Command::Lvs { .. } => "lvs",
            Command::Pex { .. } => "pex",
            Command::All { .. } => "all",
        }
    }

    /// `BASE` with more arguments appended.
    fn with(extra: &[&str]) -> Vec<String> {
        let mut argv = owned(BASE);
        argv.extend(owned(extra));
        argv
    }

    /// Oracle: construct-from-answer. Each row is an argument vector and the
    /// subcommand it must select; the shared flags must survive every one of
    /// them, which is the claim that justifies one binary rather than four.
    #[test]
    fn every_subcommand_selects_its_own_command_and_keeps_the_shared_flags() {
        let cases: [(&[&str], &str); 5] = [
            (&["drc", "top.gds", "--deck", "rules.json"], "drc"),
            (&["erc", "top.gds", "--deck", "rules.json"], "erc"),
            (
                &[
                    "lvs",
                    "top.gds",
                    "--deck",
                    "rules.json",
                    "--reference",
                    "ref.cdl",
                ],
                "lvs",
            ),
            (&["pex", "top.gds", "--deck", "rules.json"], "pex"),
            (&["all", "top.gds", "--deck", "rules.json"], "all"),
        ];
        for (argv, expected) in cases {
            let args = parse_ok(argv);
            assert_eq!(command_name(&args.command), expected, "parsing {argv:?}");
            assert_eq!(args.common.layout, PathBuf::from("top.gds"), "{argv:?}");
            assert_eq!(args.common.deck, PathBuf::from("rules.json"), "{argv:?}");
        }
    }

    /// Oracle: construct-from-answer. The defaults are part of the interface —
    /// a run that says nothing about output gets text on stdout, one unstated
    /// thread count, no determinism re-run, and strict layer checking, which
    /// the doc comment on `Common` calls what a signoff run wants.
    #[test]
    fn the_defaults_are_text_on_stdout_with_strict_layers_on() {
        let args = parse_ok(BASE);
        assert_eq!(args.common.format, Format::Text);
        assert_eq!(args.common.output, None);
        assert_eq!(args.common.threads, None);
        assert!(!args.common.check_determinism);
        assert!(
            args.common.strict_layers,
            "strict layer checking must be on by default; dropping geometry on \
             an undescribed layer is the fail-open case"
        );
    }

    /// Oracle: construct-from-answer, and the reason `--grid` exists.
    ///
    /// A deck file does **not** declare a resolution — `read_deck` is *handed*
    /// one — so before this flag there was no way to supply it and every run of
    /// this binary stopped at `LoadError::NoGrid` before a file was opened.
    /// Measured at the time: no CLI invocation could reach the LVS stage, or any
    /// other.
    #[test]
    fn a_stated_grid_reaches_the_inputs_that_carry_it() {
        let args = parse_ok(&["drc", "top.gds", "--deck", "rules.json", "--grid", "1000"]);
        assert_eq!(args.common.grid, Some(1000));
        let (inputs, _) = to_inputs(&args);
        assert_eq!(
            inputs.grid.map(gpurify_units::Grid::dbu_per_um),
            Some(1000),
            "the parsed resolution must reach `Inputs`, or the flag is decoration"
        );
    }

    /// Oracle: the fail-closed half, and the one that must never be traded for
    /// convenience. Absent means **absent**: a defaulted grid would silently
    /// reinterpret every limit in the deck — a 100 nm rule read against the
    /// wrong resolution is a different rule — turning a loud dead binary into a
    /// quiet wrong one. So the flag is optional and its absence still refuses.
    #[test]
    fn no_grid_flag_leaves_the_resolution_absent_rather_than_defaulted() {
        let args = parse_ok(BASE);
        assert_eq!(args.common.grid, None);
        let (inputs, _) = to_inputs(&args);
        assert!(
            inputs.grid.is_none(),
            "an unstated resolution must stay unstated; `load_into` refuses it, \
             and that refusal is the whole safety of this flag being optional"
        );
    }

    /// Oracle: construct-from-answer. A resolution is a positive count of
    /// database units per micrometre. Zero is what `Grid::new` refuses, and the
    /// parser refuses it first so the conversion in `to_inputs` cannot fail.
    #[test]
    fn a_grid_that_is_not_a_positive_count_is_refused() {
        for bad in ["0", "-4", "eleven", "1.5"] {
            assert!(
                matches!(
                    parse_err(&["drc", "top.gds", "--deck", "rules.json", "--grid", bad]),
                    ArgError::Usage(_)
                ),
                "--grid {bad:?} is not a resolution and must be refused"
            );
        }
    }

    /// Oracle: construct-from-answer. Every shared flag, given explicitly, and
    /// the value it must land on.
    #[test]
    fn every_shared_flag_reaches_the_field_it_names() {
        let args = parse_ok(&[
            "drc",
            "top.gds",
            "--deck",
            "rules.json",
            "--format",
            "json",
            "--output",
            "run.json",
            "--threads",
            "12",
            "--check-determinism",
        ]);
        assert_eq!(args.common.format, Format::Json);
        assert_eq!(args.common.output.as_deref(), Some(Path::new("run.json")));
        assert_eq!(args.common.threads, Some(12));
        assert!(args.common.check_determinism);
    }

    /// Oracle: construct-from-answer. Three names, three variants, and no
    /// fourth name — an unrecognised format is a usage error rather than a
    /// silent fall back to text.
    #[test]
    fn each_format_name_maps_to_its_variant_and_no_other_name_is_accepted() {
        let cases = [
            ("text", Format::Text),
            ("json", Format::Json),
            ("gds", Format::Gds),
        ];
        for (name, expected) in cases {
            let args = parse_ok(&["drc", "top.gds", "--deck", "rules.json", "--format", name]);
            assert_eq!(args.common.format, expected, "--format {name}");
        }
        assert!(matches!(
            parse_err(&["drc", "top.gds", "--deck", "rules.json", "--format", "yaml"]),
            ArgError::Usage(_)
        ));
    }

    /// Oracle: construct-from-answer. `strict_layers` defaults on, so the
    /// interesting case is turning it off, and both spellings must reach the
    /// field rather than one of them being quietly ignored.
    #[test]
    fn strict_layers_stays_on_until_it_is_explicitly_turned_off() {
        assert!(parse_ok(BASE).common.strict_layers);
        let asked_for = with(&["--strict-layers"]);
        let turned_off = with(&["--no-strict-layers"]);
        let asked_for = parse(&asked_for).expect("--strict-layers is a legal flag");
        let turned_off = parse(&turned_off).expect("--no-strict-layers is a legal flag");
        assert!(asked_for.common.strict_layers);
        assert!(!turned_off.common.strict_layers);
    }

    /// Oracle: construct-from-answer. The optional input each subcommand
    /// accepts lands on that subcommand's own field, and its absence is
    /// `None` rather than a default path.
    #[test]
    fn each_subcommands_own_inputs_land_on_its_own_fields() {
        let erc = parse_ok(&[
            "erc",
            "top.gds",
            "--deck",
            "rules.json",
            "--intent",
            "intent.json",
        ]);
        match &erc.command {
            Command::Erc { intent } => {
                assert_eq!(intent.as_deref(), Some(Path::new("intent.json")));
            }
            other => panic!("expected erc, parsed {other:?}"),
        }

        let bare_erc = parse_ok(&["erc", "top.gds", "--deck", "rules.json"]);
        match &bare_erc.command {
            Command::Erc { intent } => assert_eq!(intent.as_deref(), None),
            other => panic!("expected erc, parsed {other:?}"),
        }

        let lvs = parse_ok(&[
            "lvs",
            "top.gds",
            "--deck",
            "rules.json",
            "--reference",
            "ref.cdl",
        ]);
        match &lvs.command {
            Command::Lvs { reference } => assert_eq!(reference, Path::new("ref.cdl")),
            other => panic!("expected lvs, parsed {other:?}"),
        }
    }

    /// Oracle: construct-from-answer. Repeated options accumulate in the order
    /// given, because the order is what the caller wrote and reordering it
    /// would make two equivalent command lines produce different run options.
    #[test]
    fn pex_collects_every_quasistatic_net_in_the_order_given() {
        let args = parse_ok(&[
            "pex",
            "top.gds",
            "--deck",
            "rules.json",
            "--quasistatic",
            "vdd",
            "--quasistatic",
            "clk",
            "--quasistatic",
            "vss",
        ]);
        match &args.command {
            Command::Pex { quasistatic } => {
                assert_eq!(quasistatic.as_slice(), ["vdd", "clk", "vss"]);
            }
            other => panic!("expected pex, parsed {other:?}"),
        }
    }

    /// Oracle: construct-from-answer. `lvs` without a reference is its own
    /// error, not a generic usage message, because the caller can act on it —
    /// and the contrasting half is that `all` without one is legal, since it
    /// reports LVS as skipped rather than refusing the whole run.
    #[test]
    fn lvs_without_a_reference_is_missing_reference_but_all_without_one_is_legal() {
        assert!(matches!(
            parse_err(&["lvs", "top.gds", "--deck", "rules.json"]),
            ArgError::MissingReference
        ));

        let args = parse_ok(&["all", "top.gds", "--deck", "rules.json"]);
        match &args.command {
            Command::All { reference, intent } => {
                assert_eq!(reference.as_deref(), None);
                assert_eq!(intent.as_deref(), None);
            }
            other => panic!("expected all, parsed {other:?}"),
        }
    }

    /// Oracle: construct-from-answer. `all` takes both optional inputs and
    /// must carry both through; dropping one would turn a requested check into
    /// a skipped one without saying so.
    #[test]
    fn all_carries_both_optional_inputs_when_they_are_given() {
        let args = parse_ok(&[
            "all",
            "top.gds",
            "--deck",
            "rules.json",
            "--reference",
            "ref.cdl",
            "--intent",
            "intent.json",
        ]);
        match &args.command {
            Command::All { reference, intent } => {
                assert_eq!(reference.as_deref(), Some(Path::new("ref.cdl")));
                assert_eq!(intent.as_deref(), Some(Path::new("intent.json")));
            }
            other => panic!("expected all, parsed {other:?}"),
        }
    }

    /// Oracle: construct-from-answer. GDS output is violation markers, so the
    /// two checks that produce no markers refuse it rather than writing an
    /// empty layout that reads as a clean result.
    #[test]
    fn gds_output_is_refused_for_the_checks_that_produce_no_markers() {
        let refused: [&[&str]; 2] = [
            &[
                "lvs",
                "top.gds",
                "--deck",
                "rules.json",
                "--reference",
                "ref.cdl",
                "--format",
                "gds",
            ],
            &[
                "pex",
                "top.gds",
                "--deck",
                "rules.json",
                "--format",
                "gds",
                "--quasistatic",
                "vdd",
            ],
        ];
        for argv in refused {
            assert!(
                matches!(parse_err(argv), ArgError::FormatMismatch(_)),
                "{argv:?} should be a format mismatch"
            );
        }

        for check in ["drc", "erc", "all"] {
            let args = parse_ok(&[check, "top.gds", "--deck", "rules.json", "--format", "gds"]);
            assert_eq!(args.common.format, Format::Gds, "{check} --format gds");
        }
    }

    /// Oracle: construct-from-answer. The unknown subcommand comes back in the
    /// error so a script can log what was typed, and the message names the
    /// alternatives so a person does not have to find the usage text.
    #[test]
    fn an_unknown_subcommand_is_named_back_alongside_the_valid_ones() {
        let error = parse_err(&["dcr", "top.gds", "--deck", "rules.json"]);
        let ArgError::UnknownCommand(token) = &error else {
            panic!("expected UnknownCommand, got {error:?}")
        };
        assert_eq!(token, "dcr");
        let message = error.to_string();
        for valid in ["drc", "erc", "lvs", "pex", "all"] {
            assert!(
                message.contains(valid),
                "the message for an unknown subcommand omits {valid}: {message}"
            );
        }
    }

    /// Oracle: construct-from-answer. Every rejection the parser owns, in one
    /// table. The last three are the fail-closed cases: an option a subcommand
    /// has no field for is refused rather than accepted and dropped, which is
    /// the silent-loss failure this workspace is built against.
    #[test]
    fn every_malformed_command_line_is_a_usage_error() {
        let cases: &[&[&str]] = &[
            &[],
            &["drc"],
            &["drc", "top.gds"],
            &["drc", "--deck", "rules.json"],
            &["drc", "top.gds", "second.gds", "--deck", "rules.json"],
            &["drc", "top.gds", "--deck"],
            &["drc", "top.gds", "--deck", "rules.json", "--format"],
            &["drc", "top.gds", "--deck", "rules.json", "--output"],
            &["drc", "top.gds", "--deck", "rules.json", "--threads"],
            &[
                "drc",
                "top.gds",
                "--deck",
                "rules.json",
                "--threads",
                "some",
            ],
            &["drc", "top.gds", "--deck", "rules.json", "--nonsense"],
            &[
                "drc",
                "top.gds",
                "--deck",
                "rules.json",
                "--intent",
                "i.json",
            ],
            &[
                "drc",
                "top.gds",
                "--deck",
                "rules.json",
                "--reference",
                "r.cdl",
            ],
            &[
                "erc",
                "top.gds",
                "--deck",
                "rules.json",
                "--quasistatic",
                "vdd",
            ],
        ];
        for argv in cases {
            let error = parse_err(argv);
            assert!(
                matches!(error, ArgError::Usage(_)),
                "{argv:?} should be a usage error, got {error:?}"
            );
        }
    }

    /// Oracle: law. Options are a set, not a sequence: permuting them must not
    /// change the parse. The permutations come from the seeded generator so
    /// this covers arrangements nobody would think to write into a table, and
    /// the positional layout moves with them, which is what pins down how a
    /// bare token is told apart from an option's value.
    #[test]
    fn permuting_the_options_does_not_change_the_parse() {
        let groups: [&[&str]; 7] = [
            &["top.gds"],
            &["--deck", "rules.json"],
            &["--format", "json"],
            &["--output", "run.json"],
            &["--threads", "8"],
            &["--check-determinism"],
            &["--intent", "intent.json"],
        ];
        let mut rng = Rng::new(19);
        for _ in 0..32 {
            let mut order = groups;
            rng.shuffle(&mut order);
            let mut argv = vec!["erc".to_string()];
            for group in order {
                argv.extend(owned(group));
            }
            let parsed = match parse(&argv) {
                Ok(parsed) => parsed,
                Err(error) => panic!("{argv:?} should parse, but was rejected: {error}"),
            };
            assert_eq!(parsed.common.layout, PathBuf::from("top.gds"), "{argv:?}");
            assert_eq!(parsed.common.deck, PathBuf::from("rules.json"), "{argv:?}");
            assert_eq!(parsed.common.format, Format::Json, "{argv:?}");
            assert_eq!(parsed.common.output.as_deref(), Some(Path::new("run.json")));
            assert_eq!(parsed.common.threads, Some(8), "{argv:?}");
            assert!(parsed.common.check_determinism, "{argv:?}");
            match &parsed.command {
                Command::Erc { intent } => {
                    assert_eq!(intent.as_deref(), Some(Path::new("intent.json")));
                }
                other => panic!("{argv:?} parsed as {other:?}"),
            }
        }
    }

    /// Oracle: determinism. `parse` is documented pure, so the same argument
    /// vector gives the same answer twice. Compared through `Debug` because
    /// `Args` carries no `PartialEq`.
    #[test]
    fn parsing_the_same_argv_twice_gives_the_same_answer() {
        let argv = [
            "all",
            "top.gds",
            "--deck",
            "rules.json",
            "--reference",
            "ref.cdl",
            "--intent",
            "intent.json",
            "--threads",
            "4",
        ];
        let first = format!("{:?}", parse_ok(&argv));
        let second = format!("{:?}", parse_ok(&argv));
        assert_eq!(first, second);
    }

    /// Oracle: construct-from-answer. One row per subcommand, and the set of
    /// checks it must select. `all` selects all four **including LVS**, which
    /// is the case the next test turns on.
    #[test]
    fn each_subcommand_selects_only_its_own_check() {
        let none = Checks {
            drc: false,
            erc: false,
            lvs: false,
            pex: false,
        };
        let cases: [(&[&str], Checks); 5] = [
            (BASE, Checks { drc: true, ..none }),
            (
                &["erc", "top.gds", "--deck", "rules.json"],
                Checks { erc: true, ..none },
            ),
            (
                &[
                    "lvs",
                    "top.gds",
                    "--deck",
                    "rules.json",
                    "--reference",
                    "ref.cdl",
                ],
                Checks { lvs: true, ..none },
            ),
            (
                &["pex", "top.gds", "--deck", "rules.json"],
                Checks { pex: true, ..none },
            ),
            (&["all", "top.gds", "--deck", "rules.json"], Checks::ALL),
        ];
        for (argv, expected) in cases {
            let (_, options) = to_inputs(&parse_ok(argv));
            assert_eq!(options.checks, expected, "{argv:?}");
        }
    }

    /// Oracle: construct-from-answer. The case the plan singles out: `all`
    /// without `--reference` must still **select** LVS and leave the path
    /// `None`, so the run reports it as skipped. Dropping the check instead
    /// would produce a summary that never mentions LVS at all.
    #[test]
    fn all_without_a_reference_still_selects_lvs_so_the_run_reports_it_skipped() {
        let (inputs, options) = to_inputs(&parse_ok(&["all", "top.gds", "--deck", "rules.json"]));
        assert!(
            inputs.reference.is_none(),
            "no --reference was given, so no path may be invented"
        );
        assert!(
            options.checks.lvs,
            "lvs must stay selected so the summary says Skipped rather than \
             omitting the check"
        );
        assert_eq!(options.checks, Checks::ALL);
    }

    /// Oracle: construct-from-answer. Layout and deck reach `Inputs` from
    /// every subcommand; the optional inputs reach it only from the
    /// subcommands that accept them, and their absence stays absent.
    #[test]
    fn the_paths_on_the_command_line_are_the_paths_in_inputs() {
        let (erc, _) = to_inputs(&parse_ok(&[
            "erc",
            "top.gds",
            "--deck",
            "rules.json",
            "--intent",
            "intent.json",
        ]));
        assert_eq!(erc.layout, PathBuf::from("top.gds"));
        assert_eq!(erc.deck, PathBuf::from("rules.json"));
        assert_eq!(erc.intent.as_deref(), Some(Path::new("intent.json")));
        assert!(
            erc.reference.is_none(),
            "erc names no reference netlist, so none may appear in Inputs"
        );

        let (bare_erc, _) = to_inputs(&parse_ok(&["erc", "top.gds", "--deck", "rules.json"]));
        assert!(
            bare_erc.intent.is_none(),
            "no --intent means the intent-dependent rules report skipped"
        );

        let (lvs, _) = to_inputs(&parse_ok(&[
            "lvs",
            "top.gds",
            "--deck",
            "rules.json",
            "--reference",
            "ref.cdl",
        ]));
        assert_eq!(lvs.reference.as_deref(), Some(Path::new("ref.cdl")));
        assert!(lvs.intent.is_none());

        let (all, _) = to_inputs(&parse_ok(&[
            "all",
            "top.gds",
            "--deck",
            "rules.json",
            "--reference",
            "ref.cdl",
            "--intent",
            "intent.json",
        ]));
        assert_eq!(all.reference.as_deref(), Some(Path::new("ref.cdl")));
        assert_eq!(all.intent.as_deref(), Some(Path::new("intent.json")));
    }

    /// Oracle: construct-from-answer. The two `RunOptions` fields the command
    /// line feeds, and what they must hold when the command line is silent
    /// about them.
    #[test]
    fn the_thread_count_and_the_quasistatic_nets_reach_the_run_options() {
        let (_, threaded) = to_inputs(&parse_ok(&[
            "drc",
            "top.gds",
            "--deck",
            "rules.json",
            "--threads",
            "4",
        ]));
        assert_eq!(threaded.threads, Some(4));
        assert!(
            threaded.quasistatic_nets.is_empty(),
            "a drc run names no nets to field-solve"
        );

        let (_, silent) = to_inputs(&parse_ok(BASE));
        assert_eq!(
            silent.threads, None,
            "an unstated thread count stays unstated rather than becoming one"
        );

        let (_, pex) = to_inputs(&parse_ok(&[
            "pex",
            "top.gds",
            "--deck",
            "rules.json",
            "--quasistatic",
            "vdd",
            "--quasistatic",
            "clk",
        ]));
        assert_eq!(pex.quasistatic_nets.as_slice(), ["vdd", "clk"]);
    }
}
