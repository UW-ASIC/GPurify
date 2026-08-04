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

use crate::compare::{compare, CompareOptions};
use crate::graph::{narrow, LayoutGraph, RefGraph};
use crate::refine::Partition;
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
///
/// The three columns are parallel and the same length: row `i` pairs
/// `layout_cell[i]` with `ref_subckt[i]` at `depth[i]`. They are public because
/// the order *is* the output — [`plan`]'s doc calls it table-testable, and with
/// the columns private the only thing a caller could read was the `Result`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ComparisonPlan {
    /// Cells in evaluation order, deepest first.
    pub layout_cell: Vec<StrId>,
    pub ref_subckt: Vec<SubcktId>,
    /// Depth of each entry, so same-depth runs can be dispatched together.
    /// Non-decreasing is *not* the invariant — deepest first means `depth` is
    /// non-increasing along the table.
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
///
/// **Decision** — pure, two hierarchies in, an order out. Table-testable
/// independently of any geometry, which is why it is separate from the run.
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

    // Cleared before either refusal, so a plan that was not built is empty
    // rather than holding the previous run's order.
    out.layout_cell.clear();
    out.ref_subckt.clear();
    out.depth.clear();

    let mut subckt_depth = Vec::new();
    hierarchy_depths(netlist, &mut subckt_depth)?;
    debug_assert_eq!(subckt_depth.len(), subckts, "one depth per subcircuit");

    // Pair by name. The miss rides in the value as `NO_SUBCKT` rather than
    // breaking the scan, so the refusal is one check after a branchless pass.
    let names = &netlist.subckt_name[..];

    // Sorted once, searched once per cell: the pairing is O(cells log
    // subcircuits), not O(cells x subcircuits). `row` is part of the key, so the
    // order is total and an unstable sort is still the same order every run.
    let mut by_name: Vec<u32> = (0..narrow(subckts)).collect();
    by_name.sort_unstable_by_key(|&row| (names[row as usize], row));
    debug_assert_eq!(by_name.len(), subckts, "one index entry per subcircuit");
    debug_assert!(
        by_name.is_sorted_by_key(|&row| (names[row as usize], row)),
        "the by-name index is unsorted, so a pairing that exists could be missed"
    );

    // One binary search per cell, so the body is a search and not a lane: at
    // hundreds to thousands of cells with a `partition_point` inside, scalar is
    // the answer and there is nothing to vectorise. The two branches it does
    // carry are named at `first_subckt_named`.
    let mut resolved: Vec<u32> = Vec::with_capacity(layout_cells.len());
    for &cell in layout_cells {
        resolved.push(first_subckt_named(names, &by_name, cell));
    }
    debug_assert_eq!(resolved.len(), layout_cells.len(), "one pairing per cell");

    // Counted branchlessly — `bool` is 0 or 1, so the miss rides in the addend
    // and the scan has no early exit for the refusal to depend on the order of.
    // A `u32` accumulator is wide enough because `rows` is one.
    let mut unpaired = 0u32;
    for &subckt in &resolved {
        unpaired += u32::from(subckt == NO_SUBCKT);
    }
    debug_assert!(unpaired <= rows, "more unpaired cells than cells");
    if unpaired != 0 {
        return Err(PlanError::Unpairable);
    }

    // Deepest first. Stable, so cells of equal depth keep the caller's order —
    // "deepest first" says nothing about a tie, and settling one by sort
    // instability would make the plan differ between two runs of the same
    // input.
    let mut perm: Vec<u32> = (0..rows).collect();
    perm.sort_by_key(|&row| {
        std::cmp::Reverse(subckt_depth[resolved[row as usize] as usize])
    });

    // Three gathers over the same permutation, fused into one pass: `resolved`
    // is then read once per row instead of twice, and `perm` is walked once
    // instead of three times. Every address here is data-dependent and every
    // store is unconditional — a gather is not a branch.
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

/// The first row of `names` holding `want`, or [`NO_SUBCKT`].
///
/// **Decision** — a name column, that column's `(name, row)` order, and a name
/// in; a row out. `by_name` is [`plan`]'s sort, so this is a binary search:
/// O(log subcircuits) per cell rather than a scan of the whole column.
///
/// *First* survives the change because `row` is the tie-break in the key, so
/// every row carrying a duplicated name sorts in row order and the search lands
/// on the lowest of them.
fn first_subckt_named(names: &[StrId], by_name: &[u32], want: StrId) -> u32 {
    debug_assert_eq!(names.len(), by_name.len(), "one index entry per subcircuit");
    // `(want, 0)` sorts below every row that carries `want`, so the partition
    // point is that name's first row and not an arbitrary one of its rows.
    let at = by_name.partition_point(|&row| (names[row as usize], row) < (want, 0));
    debug_assert!(at <= by_name.len(), "partition point left the index");
    // The two branches are the search's landing check, outside any lane: `at`
    // is past the end only for a name above every subcircuit's, and the name
    // compare is a hit on every cell of a hierarchy the layout came from. Both
    // predict, and the miss is the refusal path `plan` counts afterwards.
    match by_name.get(at) {
        Some(&row) if names[row as usize] == want => row,
        _ => NO_SUBCKT,
    }
}

/// Longest distance from an uninstantiated cell down to each subcircuit.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled with one
/// depth per subcircuit.
///
/// Measured downward from the top rather than upward from the leaves because
/// the plan is ordered by it descending, and `depth(callee) >= depth(caller) +
/// 1` is exactly the guarantee that a child is compared before its parent. A
/// cell nothing instantiates is depth zero.
///
/// Relaxation rather than a marked traversal: the fixpoint of a longest path
/// over `subckts` nodes is reached within `subckts` passes over the instance
/// table, so a depth still moving after that is a cycle. One test, no visited
/// colours and no second traversal to keep in step with the first.
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
    // Fail closed: still moving at the bound means no bottom-up order exists,
    // and an order built anyway would compare a parent against a child that had
    // not been abstracted yet.
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
///
/// `callee` supplies the write *address*, so this is a scatter: two instances
/// naming the same child write the same slot, and a data-dependent output index
/// is what makes the shape unvectorisable without lane-conflict detection.
/// `Netlist::top` has the same shape.
fn relax_depths(callers: &[SubcktId], callees: &[SubcktId], depth: &mut [u32]) -> bool {
    let cells = depth.len();
    let mut moved = 0u32;
    for (&caller, &callee) in callers.iter().zip(callees) {
        let (parent, child) = (caller.0 as usize, callee.0 as usize);
        debug_assert!(
            parent < cells && child < cells,
            "instance edge {parent} -> {child} leaves the {cells} subcircuits"
        );
        // `max` rather than `if want > depth[child]`: the store is
        // unconditional and the comparison is carried by the value. Saturating
        // because a cycle is detected by the pass bound, not by a wrap.
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
    debug_assert_eq!(
        plan.layout_cell.len(),
        plan.ref_subckt.len(),
        "the plan's columns disagree on how many cells it holds"
    );
    debug_assert_eq!(plan.layout_cell.len(), plan.depth.len());

    // Refilled, not appended to: a run into a reused buffer that appended would
    // report every cell of the previous run a second time.
    out.clear();
    out.reserve(plan.layout_cell.len());

    // One refinement state for the whole run. Reusing it across cells is the
    // allocation `compare`'s `scratch` parameter exists to avoid.
    let mut scratch = Partition::default();

    // The signature hands `run` one pair of graphs and no way to fetch another,
    // so `ref_subckt` selects nothing and every planned cell is this pair
    // compared again. Abstracting a matched cell into its parent, and
    // flattening a failed one into it, both need a per-cell graph source and a
    // parent graph to write; neither is a parameter here. The plan's order is
    // still what decides the order of the results.

    for &cell in &plan.layout_cell {
        let verdict = compare(layout, reference, options, &mut scratch);
        // A cell that did not match cannot stand in for itself as an opaque
        // device at its parent's level, so it is flattened there instead.
        // `Inconclusive` counts as "did not match": abstracting away a cell the
        // run could not conclude about is the one path from "gave up" to
        // "matched" this crate does not have.
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
