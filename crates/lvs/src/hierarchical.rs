//! Bottom-up hierarchical comparison.
//!
//! Comparing a full chip flat is quadratic in a way that does not finish.
//! Instead cells are compared in dependency order, deepest first; a cell that
//! matches becomes an opaque device with pins at its parent's level, so the
//! parent's graph is small. A cell that does *not* match is flattened into its
//! parent and compared there, because the difference may be one the parent's
//! context resolves.
//!
//! # Flattening a failure is not hiding it
//!
//! A cell that fails and is then flattened still reports its own failure. The
//! flattening is so the parent's comparison is not derailed by it, not so the
//! result is quieter.

use crate::compare::CompareOptions;
use crate::graph::{LayoutGraph, RefGraph};
use crate::verdict::Verdict;
use gpurify_ingest::netlist::{Netlist, SubcktId};
use gpurify_ingest::StrId;

/// The order cells are compared in, and which pair with which.
///
/// **Five questions.** In: the reference hierarchy and the layout's instance
/// tree. Out: an ordered list of cell pairings. How many: hundreds to thousands
/// of cells. Access pattern: built once, walked once in order. Lifetime: one
/// run. Parallelisable: cells at the same depth are independent, which is the
/// point of computing the order up front rather than recursing.
#[derive(Debug, Default)]
pub struct ComparisonPlan {
    /// Cells in evaluation order, deepest first.
    layout_cell: Vec<StrId>,
    ref_subckt: Vec<SubcktId>,
    /// Depth of each entry, so same-depth runs can be dispatched together.
    depth: Vec<u32>,
}

/// Why a plan could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("cell hierarchy contains a cycle")]
    Cyclic,
    #[error("layout cell has no reference counterpart and no rule to flatten it")]
    Unpairable,
}

/// Pair cells by name and order them bottom-up.
///
/// **Decision** — pure, two hierarchies in, an order out. Table-testable
/// independently of any geometry, which is why it is separate from the run.
pub fn plan(
    netlist: &Netlist,
    layout_cells: &[StrId],
    out: &mut ComparisonPlan,
) -> Result<(), PlanError> {
    todo!()
}

/// One cell's result within a hierarchical run.
#[derive(Debug, Clone)]
pub struct CellResult {
    pub cell: StrId,
    pub verdict: Verdict,
    /// True when this cell was flattened into its parent after failing, so a
    /// reader knows why the parent's device count is larger than its schematic.
    pub flattened: bool,
}

/// Run a planned hierarchical comparison.
///
/// **Transform, A-to-B.** Caller owns `out`. Cells are compared in plan order;
/// a matched cell is abstracted into its parent, a failed one is flattened, and
/// both facts are recorded per cell.
pub fn run(
    plan: &ComparisonPlan,
    layout: &LayoutGraph,
    reference: &RefGraph,
    options: CompareOptions,
    out: &mut Vec<CellResult>,
) {
    todo!()
}
