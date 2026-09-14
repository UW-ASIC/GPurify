//! Planning a hierarchical run.
//!
//! `plan` is documented as a decision — two hierarchies in, an order out, pure
//! and table-testable with no geometry anywhere — so that is how it is tested
//! here: netlists written out as columns, and the answer stated before the call.
//!
//! [`ComparisonPlan`]'s three columns are `pub` and it derives `PartialEq`, so
//! the order *is* directly assertable and the deepest-first invariant is checked
//! against a stated hierarchy below. (The header that stood here said the
//! columns were private and the order unobservable, and it was stale: it was
//! written before the resolution recorded under `## lvs` in
//! `docs/SIGNATURE_DEFECTS.md`, and while it stood it hid the fact that nothing
//! asserted the order at all.)
//!
//! # Every fixture here is a genuine difference between the two sides
//!
//! Three of these tests used to hand `stacked_pair()` to both sides of `run`,
//! so `Verdict::Match` was the correct answer whatever the code did — deleting
//! the `compare` call from `run` and pushing a hardcoded `Match` left all three
//! green. That is the relabelling trap, and the fix is that a run's expected
//! verdict now differs between the fixtures: `matching_pair` must come back
//! `Match` and `mismatching_pair` must not.

mod common;

use common::{mos_and_bjt, mos_and_bjt_without_the_bjt, stacked_pair, CELL_A, CELL_B, CELL_MISSING};
use gpurify_ingest::netlist::{Netlist, SubcktId};
use gpurify_ingest::StrId;
use gpurify_lvs::compare::CompareOptions;
use gpurify_lvs::hierarchical::{plan, run, CellResult, ComparisonPlan, PlanError};
use gpurify_lvs::verdict::Inconclusive;
use gpurify_lvs::{LayoutGraph, RefGraph, Verdict};

/// Two subcircuits, no devices, no nets and no instantiation. A plan is about
/// which cells pair with which, so the cells' contents are not part of the
/// question.
fn two_subcircuits() -> Netlist {
    Netlist {
        subckt_name: vec![CELL_A, CELL_B],
        subckt_port_start: vec![0, 0, 0],
        subckt_device_start: vec![0, 0, 0],
        ..Netlist::default()
    }
}

/// The same two subcircuits with one `X` card: `CELL_A` instantiates `CELL_B`.
///
/// The only cell-to-cell edge a `Netlist` has, and therefore the only thing that
/// can give two cells different depths.
fn parent_instantiating_child() -> Netlist {
    Netlist {
        instance_name: vec![StrId(20)],
        instance_of: vec![SubcktId(1)],
        instance_subckt: vec![SubcktId(0)],
        instance_terminal_start: vec![0, 0],
        ..two_subcircuits()
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

/// Oracle: construct-from-answer. `CELL_A` instantiates `CELL_B`, so `B` is one
/// level down and the plan must name it first — that ordering is the whole
/// output of `plan`, and `depth(callee) >= depth(caller) + 1` is exactly the
/// guarantee that a child is compared before the parent that will abstract it
/// away.
///
/// The layout cells are handed over parent-first on purpose, so a plan that
/// simply preserved the caller's order would fail. This is also the only
/// coverage `hierarchy_depths` and `relax_depths` have: both are private, and
/// the `depth` column is the one place their fixpoint is observable.
#[test]
fn a_child_cell_is_planned_before_the_parent_that_instantiates_it() {
    let mut out = ComparisonPlan::default();
    plan(&parent_instantiating_child(), &[CELL_A, CELL_B], &mut out)
        .expect("both cells pair by name");

    assert_eq!(out.layout_cell, [CELL_B, CELL_A], "the plan is not deepest-first");
    assert_eq!(out.ref_subckt, [SubcktId(1), SubcktId(0)]);
    assert_eq!(out.depth, [1, 0], "a child is not one level below its parent");
}

/// Oracle: construct-from-answer. Two cells instantiating each other have no
/// bottom-up order at all: every candidate ordering compares one of them against
/// a child that has not been abstracted yet. `plan` must refuse, and refuse
/// having written nothing — a half-built plan carried forward is a set of cells
/// nobody knows were skipped.
///
/// `PlanError::Cyclic` had no coverage before this. It is reachable only through
/// `Netlist`'s instance table, which is why the fixture above it — an acyclic
/// hierarchy that *does* instantiate — has to exist too: without it this test
/// passes on an implementation that refuses any netlist carrying an `X` card.
#[test]
fn two_cells_that_instantiate_each_other_are_refused_rather_than_ordered() {
    let netlist = Netlist {
        instance_name: vec![StrId(20), StrId(21)],
        instance_of: vec![SubcktId(1), SubcktId(0)],
        instance_subckt: vec![SubcktId(0), SubcktId(1)],
        instance_terminal_start: vec![0, 0, 0],
        ..two_subcircuits()
    };

    let mut out = ComparisonPlan::default();
    let result = plan(&netlist, &[CELL_A, CELL_B], &mut out);

    assert_eq!(result, Err(PlanError::Cyclic));
    assert_eq!(
        out,
        ComparisonPlan::default(),
        "a refused plan still carries an order"
    );
}

/// Oracle: construct-from-answer. Every layout cell in the plan produces exactly
/// one result naming it, **in the plan's order** — no cell reported twice, none
/// dropped, and none reported before the child it will abstract away.
///
/// The hierarchy is what makes that assertable. This used to run against
/// `two_subcircuits`, where nothing is instantiated, both cells sit at depth
/// zero and "deepest first" says nothing about their relative order — so the
/// test sorted the cells it got back and could only claim the *set*, which a
/// `run` walking the plan backwards satisfies. `parent_instantiating_child`
/// fixes the order at `[CELL_B, CELL_A]`, and that is what is asserted.
#[test]
fn every_planned_cell_produces_one_result_naming_it_in_plan_order() {
    let mut order = ComparisonPlan::default();
    plan(&parent_instantiating_child(), &[CELL_A, CELL_B], &mut order)
        .expect("both cells pair by name");

    let (layout, reference) = mismatching_pair();
    let mut results = Vec::new();
    run(&order, &layout, &reference, CompareOptions::default(), &mut results);

    assert_eq!(results.len(), order.layout_cell.len(), "got {results:#?}");
    let cells: Vec<StrId> = results.iter().map(|result| result.cell).collect();
    assert_eq!(cells, order.layout_cell, "the results do not follow the plan");
    assert_eq!(cells, [CELL_B, CELL_A], "the child was not reported first");
}

/// Oracle: law, the determinism gate. The same plan run twice reports the same
/// cells, in the same order, with the same verdicts, and the second run into a
/// reused buffer replaces the first rather than appending to it. Both halves
/// matter: a doubled buffer is how a hierarchical run reports every cell twice.
///
/// Run over the mismatching pair so the verdicts carry discrepancy lists —
/// `Verdict::Match` is one value and two of them are equal however the
/// comparison reached them, so a determinism gate over matches gates nothing.
#[test]
fn a_planned_run_reports_the_same_cells_in_the_same_order_every_time() {
    let netlist = two_subcircuits();
    let mut order = ComparisonPlan::default();
    plan(&netlist, &[CELL_A, CELL_B], &mut order).expect("both cells pair");

    let (layout, reference) = mismatching_pair();
    let mut reused: Vec<CellResult> = Vec::new();
    run(&order, &layout, &reference, CompareOptions::default(), &mut reused);
    let first = rows(&reused);
    run(&order, &layout, &reference, CompareOptions::default(), &mut reused);
    let second = rows(&reused);

    assert_eq!(
        second.len(),
        first.len(),
        "the second run appended to the caller's buffer instead of refilling it"
    );
    assert_eq!(first, second);
}

/// Oracle: construct-from-answer. A one-cell plan is the one shape `run` can
/// compare: it holds a single graph pair, and with a single planned cell there
/// is no question which cell that pair belongs to. Handed two netlists that
/// differ, the cell must not match, and a cell that did not match is flattened
/// into its parent — that is what the flag is for.
///
/// This is the test the three below it were missing. With every fixture a
/// netlist against itself, `flattened` was `false` on every row of every run the
/// suite ever made, so nothing distinguished the flag from a constant.
#[test]
fn a_cell_that_did_not_match_is_reported_as_flattened() {
    let results = planned_run(&[CELL_A], &mismatching_pair());

    assert_eq!(results.len(), 1);
    assert_ne!(
        results[0].verdict,
        Verdict::Match,
        "two netlists differing by one device were matched"
    );
    assert!(
        results[0].flattened,
        "cell {:?} did not match and is not marked flattened",
        results[0].cell
    );
}

/// Oracle: construct-from-answer, the other half of the pair above. The same
/// one-cell plan over a netlist compared with itself matches, and a cell that
/// matched was not flattened: the flag exists to explain a parent whose device
/// count exceeds its schematic's, and setting it on a cell that succeeded says
/// the opposite of what happened.
///
/// Neither half stands alone — an implementation that always reports `Match`
/// passes this one, and one that always reports a difference passes the other.
#[test]
fn a_cell_that_matched_is_not_reported_as_flattened() {
    let results = planned_run(&[CELL_A], &matching_pair());

    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].verdict,
        Verdict::Match,
        "cell {:?} was compared with itself and did not match",
        results[0].cell
    );
    assert!(
        !results[0].flattened,
        "cell {:?} matched and is still marked flattened",
        results[0].cell
    );
}

/// Oracle: the crate's own prohibition. `run` is handed one graph pair whatever
/// the plan's length, and `RefGraph` carries no `SubcktId`, so for a plan of two
/// cells there is nothing that says which cell the pair belongs to. It used to
/// run that one comparison per row and hand out a `Match` for each: with the
/// two graphs equal, both cells came back matched and only one of them had been
/// compared at all — a clean verdict for a cell nothing looked at, which is the
/// path from "gave up" to "matched" `lvs/src/lib.rs` forbids.
///
/// Every row is now `Inconclusive::UncomparedCell`, naming the cell, and
/// therefore flattened. The signature gap that forces this is filed under
/// `## lvs` in `docs/SIGNATURE_DEFECTS.md`.
#[test]
fn a_multi_cell_plan_reports_every_cell_as_uncompared_rather_than_matched() {
    let results = planned_run(&[CELL_A, CELL_B], &matching_pair());

    assert_eq!(results.len(), 2, "got {results:#?}");
    for result in &results {
        assert_eq!(
            result.verdict,
            Verdict::Inconclusive(Inconclusive::UncomparedCell(result.cell)),
            "cell {:?} was never compared and did not say so",
            result.cell
        );
        assert!(result.flattened, "an unconcluded cell was abstracted away");
    }
}

/// Two graphs that are the same netlist, so a comparison of them matches.
fn matching_pair() -> (LayoutGraph, RefGraph) {
    (LayoutGraph(stacked_pair()), RefGraph(stacked_pair()))
}

/// Two graphs differing by exactly one device, so a comparison of them does not.
fn mismatching_pair() -> (LayoutGraph, RefGraph) {
    (
        LayoutGraph(mos_and_bjt()),
        RefGraph(mos_and_bjt_without_the_bjt()),
    )
}

/// Plan the named layout cells against `two_subcircuits` and run them against
/// the given graph pair.
fn planned_run(layout_cells: &[StrId], pair: &(LayoutGraph, RefGraph)) -> Vec<CellResult> {
    let netlist = two_subcircuits();
    let mut order = ComparisonPlan::default();
    plan(&netlist, layout_cells, &mut order).expect("every cell pairs");

    let mut out = Vec::new();
    run(&order, &pair.0, &pair.1, CompareOptions::default(), &mut out);
    out
}

/// One run's results as comparable values.
///
/// `CellResult` derives `Debug` and `Clone` but not `PartialEq`, and every field
/// it holds does derive it — so the rows are compared field by field rather than
/// as `Debug` strings, which cannot tell a real difference from a formatting
/// one. That reading is `graph.rs`'s own doc comment on why `Graph` derives
/// `PartialEq`.
fn rows(results: &[CellResult]) -> Vec<(StrId, Verdict, bool)> {
    results
        .iter()
        .map(|result| (result.cell, result.verdict.clone(), result.flattened))
        .collect()
}
