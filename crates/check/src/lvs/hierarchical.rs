//! Bottom-up hierarchical comparison: cells in dependency order, deepest first.
//! A failed cell is flattened into its parent and still reports its own failure.

use crate::lvs::compare::{compare, CompareOptions};
use crate::lvs::graph::{narrow, LayoutGraph, RefGraph};
use crate::lvs::refine::Partition;
use crate::lvs::verdict::{Inconclusive, Verdict};
use gpurify_ingest::netlist::{Netlist, SubcktId};
use gpurify_ingest::StrId;

/// The order cells are compared in: row `i` pairs `layout_cell[i]` with
/// `ref_subckt[i]` at `depth[i]`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ComparisonPlan {
    /// Cells in evaluation order, deepest first.
    pub layout_cell: Vec<StrId>,
    pub ref_subckt: Vec<SubcktId>,
    /// Depth of each entry. Deepest first, so `depth` is non-increasing along the
    /// table — *not* non-decreasing.
    pub depth: Vec<u32>,
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
pub fn plan(
    netlist: &Netlist,
    layout_cells: &[StrId],
    out: &mut ComparisonPlan,
) -> Result<(), PlanError> {
    let subckts = netlist.subckt_count();
    debug_assert!(
        subckts < NO_SUBCKT as usize,
        "{subckts} subcircuits leaves no room for the unpaired sentinel"
    );
    let rows = narrow(layout_cells.len());

    // Cleared before either refusal, so a plan that was not built is empty.
    out.layout_cell.clear();
    out.ref_subckt.clear();
    out.depth.clear();

    let mut subckt_depth = Vec::new();
    hierarchy_depths(netlist, &mut subckt_depth)?;
    debug_assert_eq!(subckt_depth.len(), subckts, "one depth per subcircuit");

    // Pair by name; a miss rides in the value as `NO_SUBCKT` rather than breaking
    // the scan.
    let names = &netlist.subckt_name[..];

    // `row` is part of the key, so an unstable sort is deterministic.
    let mut by_name: Vec<u32> = (0..narrow(subckts)).collect();
    by_name.sort_unstable_by_key(|&row| (names[row as usize], row));
    debug_assert_eq!(by_name.len(), subckts, "one index entry per subcircuit");
    debug_assert!(
        by_name.is_sorted_by_key(|&row| (names[row as usize], row)),
        "the by-name index is unsorted, so a pairing that exists could be missed"
    );

    let mut resolved: Vec<u32> = Vec::with_capacity(layout_cells.len());
    for &cell in layout_cells {
        resolved.push(first_subckt_named(names, &by_name, cell));
    }
    debug_assert_eq!(resolved.len(), layout_cells.len(), "one pairing per cell");

    let mut unpaired = 0u32;
    for &subckt in &resolved {
        unpaired += u32::from(subckt == NO_SUBCKT);
    }
    debug_assert!(unpaired <= rows, "more unpaired cells than cells");
    if unpaired != 0 {
        return Err(PlanError::Unpairable);
    }

    // Stable: "deepest first" says nothing about a tie, and settling one by sort
    // instability would make the plan differ between runs.
    let mut perm: Vec<u32> = (0..rows).collect();
    perm.sort_by_key(|&row| std::cmp::Reverse(subckt_depth[resolved[row as usize] as usize]));

    debug_assert_eq!(resolved.len(), layout_cells.len(), "one pairing per cell");
    debug_assert!(
        out.layout_cell.is_empty() && out.ref_subckt.is_empty() && out.depth.is_empty(),
        "the plan's columns were cleared above and must still be empty"
    );
    out.layout_cell.reserve(perm.len());
    out.ref_subckt.reserve(perm.len());
    out.depth.reserve(perm.len());
    for &row in &perm {
        let subckt = resolved[row as usize];
        out.layout_cell.push(layout_cells[row as usize]);
        out.ref_subckt.push(SubcktId(subckt));
        out.depth.push(subckt_depth[subckt as usize]);
    }

    debug_assert_eq!(out.layout_cell.len(), layout_cells.len(), "a cell was lost");
    debug_assert_eq!(out.ref_subckt.len(), out.layout_cell.len());
    debug_assert_eq!(out.depth.len(), out.layout_cell.len());
    debug_assert!(
        out.depth.is_sorted_by(|a, b| a >= b),
        "the plan is not deepest-first, so a parent is compared before its child"
    );
    Ok(())
}

/// No subcircuit of that name. Held as a sentinel in the resolved column so
/// name resolution stays one pass with no early exit.
const NO_SUBCKT: u32 = u32::MAX;

/// The first row of `names` holding `want`, or [`NO_SUBCKT`]. `by_name` must be
/// [`plan`]'s `(name, row)` sort, whose row tie-break is what makes this land on
/// the *lowest* row carrying a duplicated name.
fn first_subckt_named(names: &[StrId], by_name: &[u32], want: StrId) -> u32 {
    debug_assert_eq!(names.len(), by_name.len(), "one index entry per subcircuit");
    // `(want, 0)` sorts below every row that carries `want`, so the partition
    // point is that name's first row and not an arbitrary one of its rows.
    let at = by_name.partition_point(|&row| (names[row as usize], row) < (want, 0));
    debug_assert!(at <= by_name.len(), "partition point left the index");
    match by_name.get(at) {
        Some(&row) if names[row as usize] == want => row,
        _ => NO_SUBCKT,
    }
}

/// Longest distance from an uninstantiated cell down to each subcircuit.
///
/// `depth(callee) >= depth(caller) + 1` is exactly the guarantee that a child is
/// compared before its parent. The fixpoint is reached within `subckts` passes,
/// so a depth still moving after that is a cycle.
fn hierarchy_depths(netlist: &Netlist, out: &mut Vec<u32>) -> Result<(), PlanError> {
    let subckts = netlist.subckt_count();
    out.clear();
    out.resize(subckts, 0);

    let callers = &netlist.instance_subckt[..];
    let callees = &netlist.instance_of[..];
    debug_assert_eq!(
        callers.len(),
        callees.len(),
        "every instance names both a caller and a callee"
    );

    let mut moving = !callees.is_empty();
    let mut pass = 0;
    while moving && pass < subckts {
        moving = relax_depths(callers, callees, out);
        pass += 1;
    }
    // Fail closed: still moving at the bound means no bottom-up order exists.
    if moving {
        return Err(PlanError::Cyclic);
    }
    debug_assert!(
        out.iter().all(|&d| (d as usize) < subckts.max(1)),
        "a depth exceeds the longest possible chain of cells"
    );
    Ok(())
}

/// One relaxation pass over the instance edges. Returns whether a depth moved.
fn relax_depths(callers: &[SubcktId], callees: &[SubcktId], depth: &mut [u32]) -> bool {
    let cells = depth.len();
    let mut moved = 0u32;
    for (&caller, &callee) in callers.iter().zip(callees) {
        let (parent, child) = (caller.0 as usize, callee.0 as usize);
        debug_assert!(
            parent < cells && child < cells,
            "instance edge {parent} -> {child} leaves the {cells} subcircuits"
        );
        // Saturating because a cycle is detected by the pass bound, not by a wrap.
        let want = depth[parent].saturating_add(1);
        let was = depth[child];
        let now = was.max(want);
        depth[child] = now;
        moved |= u32::from(now != was);
    }
    moved != 0
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

/// Run a planned hierarchical comparison, refilling `out`. A plan of more than
/// one cell has no per-cell graph to compare and reports every cell as
/// [`Inconclusive::UncomparedCell`].
pub fn run(
    plan: &ComparisonPlan,
    layout: &LayoutGraph,
    reference: &RefGraph,
    options: CompareOptions,
    out: &mut Vec<CellResult>,
) {
    debug_assert_eq!(
        plan.layout_cell.len(),
        plan.ref_subckt.len(),
        "the plan's columns disagree on how many cells it holds"
    );
    debug_assert_eq!(plan.layout_cell.len(), plan.depth.len());

    // Refilled, not appended to.
    out.clear();
    out.reserve(plan.layout_cell.len());

    // One refinement state for the whole run.
    let mut scratch = Partition::default();

    // A single-cell plan is the one shape where the caller's pair unambiguously
    // belongs to the cell the plan names; repeating it across rows would hand out
    // N `Match`es for one comparison.
    let single = plan.layout_cell.len() == 1;

    for &cell in &plan.layout_cell {
        let verdict = if single {
            compare(layout, reference, options, &mut scratch)
        } else {
            Verdict::Inconclusive(Inconclusive::UncomparedCell(cell))
        };
        // `Inconclusive` counts as "did not match": abstracting away a cell the
        // run could not conclude about is a path from "gave up" to "matched".
        let flattened = !matches!(verdict, Verdict::Match);
        out.push(CellResult {
            cell,
            verdict,
            flattened,
        });
    }

    debug_assert_eq!(
        out.len(),
        plan.layout_cell.len(),
        "a planned cell produced no result"
    );
}
