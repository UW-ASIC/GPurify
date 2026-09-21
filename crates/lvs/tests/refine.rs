//! Partition refinement, on its own, before any verdict is read off it.
//!
//! The claim this module's documentation makes is that refinement is
//! deterministic: it never picks a node arbitrarily, so the same two graphs
//! produce the same partition whatever order their rows happen to be in. That
//! claim is only worth something if a test can fail it, which is what relabelled
//! graphs are for here.

mod common;

use common::{
    chain, differential_pair, mos_and_bjt, mos_and_bjt_without_the_bjt, net_node, node_count,
    permute, random_graph, stacked_pair,
};
use gpurify_lvs::refine::{refine_into, Partition, Refinement, TieBreak};
use gpurify_lvs::{LayoutGraph, RefGraph};
use gpurify_testgen::Rng;

/// A round limit no fixture here comes close to, so a test that is not about
/// the limit cannot accidentally be about the limit.
const GENEROUS: u32 = 512;

/// Oracle: law. A graph refined against itself has an automorphism available for
/// every class, and the identity is one of them, so with a deterministic
/// tie-break the pairing is node `n` to node `n` for every node. Reflexivity is
/// the strongest property available here because it needs no constructed answer
/// and no assumption about how classes are numbered.
#[test]
fn a_graph_refined_against_itself_pairs_every_node_with_itself() {
    let mut scratch = Partition::default();
    let outcome = refine_into(
        &LayoutGraph(stacked_pair()),
        &RefGraph(stacked_pair()),
        TieBreak::LowestIndex,
        GENEROUS,
        &mut scratch,
    );
    assert_eq!(outcome, Refinement::Complete);

    let pairs: Vec<(u32, u32)> = scratch.pairs().collect();
    let expected = node_count(&stacked_pair());
    assert_eq!(
        pairs.len(),
        expected as usize,
        "{} of {expected} nodes paired",
        pairs.len()
    );
    for (layout, reference) in pairs {
        assert_eq!(
            layout, reference,
            "node {layout} paired with {reference} in a comparison against itself"
        );
    }
    assert_eq!(scratch.unresolved().count(), 0);
}

/// Oracle: law. Reflexivity again, over graphs nobody chose. A generated graph
/// has repeated structure, shared nets and nets with nothing on them, and every
/// one of those is a class refinement has to resolve or tie-break; none of them
/// is a reason for a graph to differ from itself.
#[test]
fn reflexivity_holds_for_arbitrary_generated_graphs() {
    for seed in 0..16u64 {
        let mut rng = Rng::new(seed);
        let devices = 3 + u32::try_from(seed).expect("a small seed");
        let graph = random_graph(&mut rng, devices, devices + 2);

        // The same seed twice, because `Graph` is not `Clone` and the two sides
        // must be the same graph rather than two similar ones.
        let mut rng = Rng::new(seed);
        let same = random_graph(&mut rng, devices, devices + 2);

        let mut scratch = Partition::default();
        let outcome = refine_into(
            &LayoutGraph(graph),
            &RefGraph(same),
            TieBreak::LowestIndex,
            GENEROUS,
            &mut scratch,
        );
        assert_eq!(
            outcome,
            Refinement::Complete,
            "seed {seed}: a graph failed to refine against itself"
        );
        for (layout, reference) in scratch.pairs() {
            assert_eq!(
                layout, reference,
                "seed {seed}: {layout} paired with {reference}"
            );
        }
    }
}

/// Oracle: construct-from-answer. A relabelled copy of a rigid graph is
/// isomorphic to it by exactly one map, the one the relabelling used, so
/// refinement must return that map and nothing else. This is the determinism
/// claim stated as something falsifiable: an implementation that resolved a
/// class by index order, or by whatever the row order happened to be, would pair
/// node `n` with node `n` here and be wrong for all but the fixed points.
///
/// **The fixture has to be rigid for the assertion to be legal**, and
/// `stacked_pair` stopped being so when `role_code` collapsed the MOS channel:
/// its upper device's source and drain both dangle, so exchanging them is an
/// automorphism and there are two correct answers here rather than one. Asserted
/// against the old expectation, refinement returned the other one — a *correct*
/// pairing the test called wrong, which is `docs/CORRECTNESS_MAP.md` §5's
/// dangerous class. [`chain`] carries the anchor that keeps one fixture rigid;
/// see its doc comment for why a bare chain is not.
#[test]
fn refinement_recovers_the_relabelling_that_produced_the_graph() {
    // `new_device[old]` and `new_net[old]`. Neither map has a fixed point, so
    // an implementation ignoring the permutation cannot pass.
    let new_device = [1u32, 2, 0];
    let new_net = [1u32, 2, 3, 0];
    let source = chain(3);
    let relabelled = permute(&source, &new_device, &new_net);

    let mut scratch = Partition::default();
    let outcome = refine_into(
        &LayoutGraph(relabelled),
        &RefGraph(chain(3)),
        TieBreak::LowestIndex,
        GENEROUS,
        &mut scratch,
    );
    assert_eq!(outcome, Refinement::Complete);

    let mut expected: Vec<(u32, u32)> = Vec::new();
    for (old, &new) in new_device.iter().enumerate() {
        expected.push((new, u32::try_from(old).expect("three devices")));
    }
    for (old, &new) in new_net.iter().enumerate() {
        let old = u32::try_from(old).expect("four nets");
        expected.push((net_node(&source, new), net_node(&source, old)));
    }
    expected.sort_unstable();

    let pairs: Vec<(u32, u32)> = scratch.pairs().collect();
    assert_eq!(pairs, expected);
}

/// Oracle: law. `Partition::pairs` promises its result ascending by layout
/// index, and a consumer relying on that order is how a canonical report stays
/// canonical. Checked on the relabelled fixture, where the layout order and the
/// reference order genuinely disagree.
#[test]
fn pairs_come_back_ascending_by_layout_node() {
    let source = stacked_pair();
    let relabelled = permute(&source, &[1, 0], &[3, 5, 0, 4, 2, 1]);

    let mut scratch = Partition::default();
    refine_into(
        &LayoutGraph(relabelled),
        &RefGraph(stacked_pair()),
        TieBreak::LowestIndex,
        GENEROUS,
        &mut scratch,
    );

    let layout_side: Vec<u32> = scratch.pairs().map(|(layout, _)| layout).collect();
    let mut sorted = layout_side.clone();
    sorted.sort_unstable();
    assert_eq!(
        layout_side, sorted,
        "pairs are not ascending by layout node"
    );
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        layout_side.len(),
        "a layout node paired twice"
    );
}

/// Oracle: construct-from-answer. Exchanging the two halves of a differential
/// pair, together with their gate and drain nets, is an automorphism, so no
/// signature computed from neighbours can separate them. Under
/// [`TieBreak::Refuse`] the honest answer is that the symmetry survived, and the
/// unresolved class holds two nodes from each side.
#[test]
fn a_differential_pair_stays_symmetric_when_ties_are_refused() {
    let mut scratch = Partition::default();
    let outcome = refine_into(
        &LayoutGraph(differential_pair()),
        &RefGraph(differential_pair()),
        TieBreak::Refuse,
        GENEROUS,
        &mut scratch,
    );
    assert_eq!(outcome, Refinement::Symmetric);

    let unresolved: Vec<(gpurify_lvs::refine::ClassId, u32, u32)> = scratch.unresolved().collect();
    assert!(
        !unresolved.is_empty(),
        "refinement called itself symmetric without naming a class"
    );
    for (class, layout_nodes, ref_nodes) in unresolved {
        assert_eq!(
            layout_nodes, ref_nodes,
            "class {class:?} holds {layout_nodes} layout nodes against {ref_nodes} \
             reference ones, in a comparison of a graph with itself"
        );
        assert!(
            layout_nodes > 1,
            "class {class:?} is reported unresolved with {layout_nodes} node(s)"
        );
    }
}

/// Oracle: construct-from-answer. The same symmetry, with the tie-break allowed
/// to fire. Either pairing of the two halves is correct, so refinement completes
/// and — the graph being compared with itself, and the rule being lowest index
/// on each side — it completes on the identity.
#[test]
fn the_same_symmetry_resolves_when_the_tie_break_is_allowed_to_fire() {
    let mut scratch = Partition::default();
    let outcome = refine_into(
        &LayoutGraph(differential_pair()),
        &RefGraph(differential_pair()),
        TieBreak::LowestIndex,
        GENEROUS,
        &mut scratch,
    );
    assert_eq!(outcome, Refinement::Complete);
    assert_eq!(scratch.unresolved().count(), 0);
    for (layout, reference) in scratch.pairs() {
        assert_eq!(layout, reference);
    }
}

/// Oracle: construct-from-answer. One device is deleted from the reference and
/// nothing else changes, so refinement stabilises with the bipolar's class
/// holding one layout node and no reference one. That is a structural
/// difference, not a budget and not a symmetry, and [`Refinement::Discrepant`]
/// is the one outcome that says so.
///
/// Nothing in this suite reached `Discrepant` before: every fixture was a graph
/// against itself or a relabelling of one, so `Complete`, `Symmetric` and
/// `Exhausted` were the only three ever observed and the fourth arm of the enum
/// was dead in the tests. It is also where the classes with unequal counts come
/// from, which is what `Partition::unresolved` hands `compare::interpret`.
#[test]
fn a_deleted_device_leaves_the_partition_discrepant_rather_than_complete() {
    let mut scratch = Partition::default();
    let outcome = refine_into(
        &LayoutGraph(mos_and_bjt()),
        &RefGraph(mos_and_bjt_without_the_bjt()),
        TieBreak::LowestIndex,
        GENEROUS,
        &mut scratch,
    );
    assert_eq!(outcome, Refinement::Discrepant);

    let unresolved: Vec<(gpurify_lvs::refine::ClassId, u32, u32)> = scratch.unresolved().collect();
    assert!(
        unresolved
            .iter()
            .any(|&(_, layout_nodes, ref_nodes)| layout_nodes != ref_nodes),
        "refinement called itself discrepant with every class balanced: {unresolved:#?}"
    );
}

/// Oracle: construct-from-answer. The same pair under [`TieBreak::Refuse`] is
/// still `Discrepant`, not `Symmetric`. The order of those two tests inside
/// `refine_observed` is load-bearing: an imbalanced class is a structural
/// difference no tie-break can mend, so reporting it as a symmetry would blame
/// the run's configuration for a difference between the netlists — and a caller
/// would then loosen the tie-break and get the same answer.
#[test]
fn a_structural_difference_is_discrepant_even_when_ties_are_refused() {
    let mut scratch = Partition::default();
    let outcome = refine_into(
        &LayoutGraph(mos_and_bjt()),
        &RefGraph(mos_and_bjt_without_the_bjt()),
        TieBreak::Refuse,
        GENEROUS,
        &mut scratch,
    );
    assert_eq!(outcome, Refinement::Discrepant);
}

/// Oracle: construct-from-answer. A chain propagates one hop per round from each
/// end, so twenty-four devices cannot be resolved in three, and the only correct
/// report is that the budget ran out. `Complete` here would be the false match
/// the crate's second doc section says must not exist; `Discrepant` would be a
/// difference invented by the budget.
#[test]
fn a_chain_that_needs_many_rounds_is_exhausted_rather_than_answered() {
    let mut scratch = Partition::default();
    let outcome = refine_into(
        &LayoutGraph(chain(24)),
        &RefGraph(chain(24)),
        TieBreak::LowestIndex,
        3,
        &mut scratch,
    );
    assert_eq!(outcome, Refinement::Exhausted);
}

/// Oracle: law. The round limit bounds work, not truth: for every budget, a
/// graph compared with itself either has not finished yet or has finished and
/// matched. `Discrepant` is never a legitimate outcome of a self-comparison, at
/// any budget, and `Symmetric` cannot arise under a tie-break that resolves.
#[test]
fn no_round_budget_turns_a_graph_into_a_difference_from_itself() {
    for budget in 1..=20u32 {
        let mut scratch = Partition::default();
        let outcome = refine_into(
            &LayoutGraph(chain(24)),
            &RefGraph(chain(24)),
            TieBreak::LowestIndex,
            budget,
            &mut scratch,
        );
        assert!(
            matches!(outcome, Refinement::Exhausted | Refinement::Complete),
            "budget {budget} produced {outcome:?} for a graph against itself"
        );
    }
}

/// Oracle: law. The same inputs give the same partition, and a scratch buffer
/// carrying a previous comparison's state gives the same partition as a fresh
/// one. The second half is what makes the buffer reusable across a hierarchical
/// run at all: if the leftovers were readable, cell order would change the
/// answer.
#[test]
fn a_reused_scratch_partition_gives_the_same_answer_as_a_fresh_one() {
    let mut reused = Partition::default();
    refine_into(
        &LayoutGraph(chain(9)),
        &RefGraph(chain(9)),
        TieBreak::LowestIndex,
        GENEROUS,
        &mut reused,
    );
    let outcome = refine_into(
        &LayoutGraph(stacked_pair()),
        &RefGraph(stacked_pair()),
        TieBreak::LowestIndex,
        GENEROUS,
        &mut reused,
    );

    let mut fresh = Partition::default();
    let expected = refine_into(
        &LayoutGraph(stacked_pair()),
        &RefGraph(stacked_pair()),
        TieBreak::LowestIndex,
        GENEROUS,
        &mut fresh,
    );

    assert_eq!(outcome, expected);
    assert_eq!(
        reused.pairs().collect::<Vec<_>>(),
        fresh.pairs().collect::<Vec<_>>()
    );
    assert_eq!(
        reused.unresolved().collect::<Vec<_>>(),
        fresh.unresolved().collect::<Vec<_>>()
    );
}
