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
