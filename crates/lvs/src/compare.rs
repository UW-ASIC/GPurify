//! The comparison driver: refine, then read the partition as a verdict.

use crate::graph::{LayoutGraph, RefGraph};
use crate::refine::{Partition, TieBreak};
use crate::verdict::Verdict;

/// How to run a comparison.
///
/// Every field changes what a run *concludes*, so each has a documented reason
/// to exist. None of them is a performance knob.
#[derive(Debug, Clone, Copy)]
pub struct CompareOptions {
    /// Bound on refinement rounds. Exceeding it yields
    /// [`Verdict::Inconclusive`], never a mismatch.
    pub max_rounds: u32,
    /// What to do with a genuine symmetry.
    pub tie_break: TieBreak,
    /// Relative tolerance for parametric comparison. Applied deliberately here,
    /// which is why `topology` measures devices in exact integers rather than
    /// accumulating a tolerance by accident upstream.
    pub param_tolerance: f64,
    /// Compare declared net names as well as structure. Off by default: a
    /// layout is allowed to name nets differently from its schematic, and
    /// requiring agreement turns a naming convention into an LVS failure.
    pub match_names: bool,
}

impl Default for CompareOptions {
    fn default() -> Self {
        todo!()
    }
}

/// Compare one cell.
///
/// **Transform.** `scratch` is the caller's refinement state, reused across
/// every cell of a hierarchical run — the allocation that would otherwise
/// dominate a large comparison.
pub fn compare(
    layout: &LayoutGraph,
    reference: &RefGraph,
    options: CompareOptions,
    scratch: &mut Partition,
) -> Verdict {
    todo!()
}

/// Turn a stable partition into discrepancies.
///
/// **Decision** — pure, a partition and two graphs in, a verdict out, with no
/// mutation anywhere. Separate from [`compare`] because it is the part worth a
/// table of cases: constructed partitions in, expected discrepancy lists out,
/// with no refinement involved.
pub fn interpret(
    layout: &LayoutGraph,
    reference: &RefGraph,
    partition: &Partition,
    options: CompareOptions,
) -> Verdict {
    todo!()
}
