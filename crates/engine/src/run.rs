//! Running the checks, and reporting honestly about which ones ran.

use crate::pipeline::{Extracted, Inputs, Loaded};
use gpurify_lvs::Verdict;
use gpurify_pex::ParasiticNetwork;
use gpurify_report::{RuleRun, Violations};

/// Which checks to run.
///
/// Named flags rather than a bitmask: `Checks { drc: true, .. }` reads at the
/// call site, and there is no combination that is illegal, so a struct of
/// `bool` is honest here where a sum type would be forced.
///
/// CONVENTIONS §3 prefers a sum type over a flag-bag, but the rule it states is
/// "an `enum` beats a struct of `bool`s **whose combinations are mostly
/// illegal**". All sixteen combinations here are meaningful, including none,
/// so the condition does not hold and the lint is answered rather than obeyed.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checks {
    pub drc: bool,
    pub erc: bool,
    pub lvs: bool,
    pub pex: bool,
}

impl Checks {
    /// All four.
    pub const ALL: Self = Self { drc: true, erc: true, lvs: true, pex: true };
}

/// How to run.
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub checks: Checks,
    pub lvs: gpurify_lvs::CompareOptions,
    /// Nets to extract by field solve. Empty means analytical extraction only,
    /// which is what a full-chip run wants.
    pub quasistatic_nets: Vec<String>,
    /// Worker threads. Affects speed only: the determinism gate requires
    /// byte-identical output at any value of this, so if changing it changes
    /// the output that is a bug this field exists to catch.
    pub threads: Option<usize>,
}

/// Whether a check ran, and if not, why.
///
/// The distinction the whole tool turns on. `Skipped` is not a quieter
/// `Ran` — a caller that treats them alike has learned nothing from a clean
/// report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageStatus {
    Ran,
    /// Not requested.
    NotSelected,
    /// Requested, but a required input was absent — no reference netlist for
    /// LVS, no design intent for the electrical ERC rules.
    Skipped(&'static str),
    /// Requested, attempted, and refused because the input was outside what
    /// this tool represents exactly.
    Refused(String),
}

/// Everything a run produced.
#[derive(Debug, Default)]
pub struct Outputs {
    /// DRC and ERC findings, in one table because they are one shape. Sorted
    /// canonically before this is returned.
    pub violations: Violations,
    /// One row per rule, including rules that found nothing and rules that did
    /// not run. This is what makes an empty `violations` interpretable.
    pub runs: Vec<RuleRun>,
    pub lvs: Option<Verdict>,
    pub parasitics: Option<ParasiticNetwork>,
}

/// What happened, at a glance.
///
/// Deliberately not just counts. A summary reporting `0 violations` without
/// reporting `3 rules skipped` is the false-clean failure in report form.
#[derive(Debug, Clone)]
pub struct Summary {
    pub drc: StageStatus,
    pub erc: StageStatus,
    pub lvs: StageStatus,
    pub pex: StageStatus,
    pub violations: u32,
    pub errors: u32,
    pub warnings: u32,
    /// Rules that ran and found nothing. Evidence the run did work.
    pub rules_clean: u32,
    /// Rules that did not run. The number to look at before believing a clean
    /// result.
    pub rules_skipped: u32,
}

impl Summary {
    /// Whether the run is a pass.
    ///
    /// **Decision** — pure, and the single place the pass criterion is written.
    /// A skipped rule is **not** a pass: this returns `false` when anything was
    /// skipped, so a run missing an input fails loudly instead of appearing to
    /// succeed. A caller that genuinely wants a partial run says so explicitly
    /// by not selecting the check, which is `NotSelected` rather than `Skipped`.
    pub fn passed(&self) -> bool {
        todo!()
    }
}

/// Run the selected checks against an extraction.
///
/// **Transform.** Caller owns `out`. The four checks read `loaded` and
/// `extracted` immutably and write into separate buffers that are concatenated
/// here, so they are independent and the concatenation order does not affect
/// the result — `Violations::sort_canonical` is called before returning.
pub fn run_checks(
    loaded: &Loaded,
    extracted: &Extracted,
    options: &RunOptions,
    out: &mut Outputs,
) -> Result<Summary, EngineError> {
    todo!()
}

/// Load, extract and check in one call.
///
/// The whole pipeline, and what the CLI calls. Kept thin — it sequences
/// [`crate::pipeline::load_into`], [`crate::pipeline::extract_into`] and
/// [`run_checks`] and does nothing else, so a caller wanting to run two layouts
/// against one deck can call the stages directly and skip the reload.
pub fn run(
    inputs: &Inputs,
    options: &RunOptions,
    out: &mut Outputs,
) -> Result<Summary, EngineError> {
    todo!()
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Load(#[from] crate::pipeline::LoadError),
    #[error(transparent)]
    Extract(#[from] crate::pipeline::ExtractError),
    #[error(transparent)]
    Solve(#[from] gpurify_pex::quasistatic::solve::SolveError),
    #[error(transparent)]
    Mesh(#[from] gpurify_pex::quasistatic::mesh::MeshError),
}
