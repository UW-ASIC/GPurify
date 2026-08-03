//! Planning a hierarchical run.
//!
//! `plan` is documented as a decision — two hierarchies in, an order out, pure
//! and table-testable with no geometry anywhere — so that is how it is tested
//! here: netlists written out as columns, and the answer stated before the call.
//!
//! What cannot be tested from outside the crate is the *order* it produces.
//! [`ComparisonPlan`](gpurify_lvs::hierarchical::ComparisonPlan)'s three columns
//! are private and it has no accessor, so the only observable consequence of a
//! plan is the sequence of [`CellResult`] rows `run` writes from it. Those tests
//! are here too, and the gap is recorded in `docs/NEED_TESTING.md`.

mod common;

use common::{stacked_pair, CELL_A, CELL_B, CELL_MISSING};
use gpurify_ingest::netlist::Netlist;
use gpurify_ingest::StrId;
use gpurify_lvs::compare::CompareOptions;
use gpurify_lvs::hierarchical::{plan, run, CellResult, ComparisonPlan, PlanError};
use gpurify_lvs::{LayoutGraph, RefGraph};

/// Two subcircuits, no devices and no nets. A plan is about which cells pair
/// with which, so the cells' contents are not part of the question.
fn two_subcircuits() -> Netlist {
    Netlist {
        subckt_name: vec![CELL_A, CELL_B],
        subckt_port_start: vec![0, 0, 0],
        subckt_device_start: vec![0, 0, 0],
        ..Netlist::default()
    }
}

/// Oracle: construct-from-answer. Both layout cells name a subcircuit the
/// reference defines, so a plan exists. Stated as its own test because every
/// negative case below has to be a difference from a case that works.
#[test]
fn a_layout_whose_cells_all_have_counterparts_can_be_planned() {
    let mut out = ComparisonPlan::default();
    let result = plan(&two_subcircuits(), &[CELL_A, CELL_B], &mut out);
    assert_eq!(result, Ok(()));
}

/// Oracle: construct-from-answer. One layout cell names a subcircuit the
/// reference does not define. There is nothing to compare it against and no
/// stated rule for flattening it, so the plan is refused rather than built
/// without it — a plan quietly missing a cell is a cell that never gets checked.
#[test]
fn a_layout_cell_with_no_counterpart_is_refused_rather_than_dropped() {
    let mut out = ComparisonPlan::default();
    let result = plan(&two_subcircuits(), &[CELL_A, CELL_MISSING], &mut out);
    assert_eq!(result, Err(PlanError::Unpairable));
}

/// Oracle: construct-from-answer. Pairing is by name, so a reference holding
/// subcircuits the layout does not instantiate is not an error: those cells are
/// simply not compared. The asymmetry is deliberate — an uninstantiated
/// subcircuit is a library cell, an unpaired layout cell is unverified geometry.
#[test]
fn a_reference_subcircuit_the_layout_never_uses_is_not_an_error() {
    let mut out = ComparisonPlan::default();
    let result = plan(&two_subcircuits(), &[CELL_B], &mut out);
    assert_eq!(result, Ok(()));
}

/// Oracle: construct-from-answer. Every layout cell in the plan produces exactly
/// one result, naming that cell, and no cell is reported twice or dropped.
///
/// The cells are sorted before comparison and that is not laziness: this netlist
/// has no instantiation, so both subcircuits are at depth zero and "deepest
/// first" leaves their relative order undetermined. Asserting one of the two
/// would be choosing an answer the frozen definitions do not state. The order
/// that *is* checked is the one `run` reproduces across two calls, which is the
/// determinism test below.
#[test]
fn every_planned_cell_produces_one_result_naming_it() {
    let results = planned_run(&[CELL_A, CELL_B]);

    assert_eq!(results.len(), 2, "got {results:#?}");
    let mut cells: Vec<StrId> = results.iter().map(|result| result.cell).collect();
    cells.sort_unstable();
    assert_eq!(cells, [CELL_A, CELL_B]);
}

/// Oracle: law, the determinism gate. The same plan run twice reports the same
/// cells in the same order, and the second run into a reused buffer replaces the
/// first rather than appending to it. Both halves matter: a doubled buffer is
/// how a hierarchical run reports every cell twice.
#[test]
fn a_planned_run_reports_the_same_cells_in_the_same_order_every_time() {
    let first = planned_run(&[CELL_A, CELL_B]);

    let netlist = two_subcircuits();
    let mut order = ComparisonPlan::default();
    plan(&netlist, &[CELL_A, CELL_B], &mut order).expect("both cells pair");

    let mut reused: Vec<CellResult> = Vec::new();
    let layout = LayoutGraph(stacked_pair());
    let reference = RefGraph(stacked_pair());
    run(
        &order,
        &layout,
        &reference,
        CompareOptions::default(),
        &mut reused,
    );
    run(
        &order,
        &layout,
        &reference,
        CompareOptions::default(),
        &mut reused,
    );

    assert_eq!(
        reused.len(),
        first.len(),
        "the second run appended to the caller's buffer instead of refilling it"
    );
    assert_eq!(format!("{reused:?}"), format!("{first:?}"));
}

/// Oracle: construct-from-answer. `run` is handed one pair of graphs and its
/// signature gives it no way to fetch another, so every cell in the plan is a
/// netlist compared with itself. Each therefore matches, and a cell that matched
/// was not flattened: the flag exists to explain a parent whose device count
/// exceeds its schematic's, and setting it on a cell that succeeded says the
/// opposite of what happened.
#[test]
fn a_cell_that_matched_is_not_reported_as_flattened() {
    let results = planned_run(&[CELL_A, CELL_B]);
    assert!(!results.is_empty(), "the plan produced no cell results");
    for result in results {
        assert_eq!(
            result.verdict,
            gpurify_lvs::Verdict::Match,
            "cell {:?} was compared with itself and did not match",
            result.cell
        );
        assert!(
            !result.flattened,
            "cell {:?} matched and is still marked flattened",
            result.cell
        );
    }
}

/// Plan the named layout cells against `two_subcircuits` and run them against a
/// graph compared with itself, so every cell that is compared at all matches.
fn planned_run(layout_cells: &[StrId]) -> Vec<CellResult> {
    let netlist = two_subcircuits();
    let mut order = ComparisonPlan::default();
    plan(&netlist, layout_cells, &mut order).expect("every cell pairs");

    let mut out = Vec::new();
    run(
        &order,
        &LayoutGraph(stacked_pair()),
        &RefGraph(stacked_pair()),
        CompareOptions::default(),
        &mut out,
    );
    out
}
