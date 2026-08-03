//! Command line surface.
//!
//! Usage-driven: the shape below is what someone running a signoff check
//! actually types, not a mirror of the library's structure. Where the two
//! disagree, this follows the usage and translates.

use std::path::PathBuf;

/// `gpurify <check> --deck <deck> <layout> [options]`
#[derive(Debug, Clone)]
pub struct Args {
    pub command: Command,
    pub common: Common,
}

/// Which check to run.
///
/// A subcommand rather than a flag, because the required inputs differ: `lvs`
/// needs a reference netlist and the others do not, and a subcommand can say so
/// in its own usage line instead of failing at runtime.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
}

/// Parse and validate.
///
/// **Decision** — pure, argv in, either [`Args`] or a message out. Pure so the
/// whole surface is table-testable without a process: a list of argument
/// vectors and their expected parses, including every rejection.
pub fn parse(argv: &[String]) -> Result<Args, ArgError> {
    todo!()
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ArgError {
    #[error("{0}")]
    Usage(String),
    #[error("unknown subcommand {0}; expected drc, erc, lvs, pex or all")]
    UnknownCommand(String),
    #[error("lvs requires a reference netlist (--reference)")]
    MissingReference,
    #[error("--format gds is only meaningful for checks that produce markers")]
    FormatMismatch,
}

/// Translate the parsed arguments into what `engine` wants.
///
/// **Decision** — pure. Separate from [`parse`] so the mapping from a
/// convenient command line to a precise library call is testable on its own,
/// and so the two can differ without one deforming the other.
pub fn to_inputs(args: &Args) -> (gpurify_engine::Inputs, gpurify_engine::RunOptions) {
    todo!()
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
                matches!(parse_err(argv), ArgError::FormatMismatch),
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
            &["drc", "top.gds", "--deck", "rules.json", "--threads", "some"],
            &["drc", "top.gds", "--deck", "rules.json", "--nonsense"],
            &["drc", "top.gds", "--deck", "rules.json", "--intent", "i.json"],
            &["drc", "top.gds", "--deck", "rules.json", "--reference", "r.cdl"],
            &["erc", "top.gds", "--deck", "rules.json", "--quasistatic", "vdd"],
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
