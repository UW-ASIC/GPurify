//! Partition refinement: the matching algorithm.
//!
//! Both graphs' nodes start in one class each — all devices together, all nets
//! together — and are split repeatedly by a signature computed from their
//! neighbours' current classes. When no class splits further, classes
//! containing exactly one node from each side are a forced pairing.
//!
//! This is the standard netlist-comparison approach, and it is chosen here for
//! a specific reason: it is *deterministic*. It never picks a node arbitrarily,
//! so it produces the same partition regardless of iteration order or thread
//! count, which the determinism gate requires. Where it stalls — a symmetric
//! structure where several nodes are genuinely interchangeable — the tie is
//! broken by a rule stated in [`TieBreak`], never by whatever the hash order
//! happened to be.

use crate::graph::{LayoutGraph, RefGraph};
use gpurify_core::observe::{NoObserve, Observer};

/// A class of nodes not yet distinguished from each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ClassId(pub u32);

/// The refinement state for both graphs.
///
/// **Five questions.** In: two graphs. Out: a partition of both node sets into
/// shared classes. How many: one per comparison, sized by node count. Access
/// pattern: every round reads every node's neighbour classes and writes its own
/// new class — a textbook two-pass transform, never read-what-you-just-wrote.
/// Lifetime: one comparison; every buffer is reused across rounds. Parallelisable:
/// the signature pass is; the renumbering pass is a sort.
#[derive(Debug, Default)]
pub struct Partition {
    /// Class of each layout node, devices then nets.
    layout_class: Vec<ClassId>,
    ref_class: Vec<ClassId>,
    /// Scratch for the next round. Two buffers swapped, so a round never reads
    /// what it wrote — the kernel rule, applied to a graph algorithm.
    next_layout: Vec<ClassId>,
    next_ref: Vec<ClassId>,
    /// Per-node signature for the current round, sorted to renumber classes.
    signature: Vec<(u64, u32)>,
    class_count: u32,
}

/// How to break a genuine symmetry.
///
/// Reached only when refinement stalls with classes holding more than one node
/// per side — a real symmetry, such as the two halves of a differential pair.
/// The choice must not depend on memory layout, so every option here is a total
/// order over something intrinsic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TieBreak {
    /// Lowest node index on each side. Deterministic and cheap, and correct
    /// whenever the symmetry is genuine — if the nodes really are
    /// interchangeable, either pairing is right.
    LowestIndex,
    /// Refuse. Report the symmetric group as a discrepancy instead of choosing.
    /// For a run that must not guess.
    Refuse,
}

/// What the refinement did, round by round.
///
/// Not derivable from the final partition: whether refinement converged in
/// three rounds or ninety, how many classes were split each round, and where it
/// stalled are the difference between a fast comparison and one that is about
/// to time out. This is the seam the work counters attach to.
pub trait ObserveRefine: Observer {
    fn round(&mut self, index: u32, classes: u32, split: u32);
    fn stalled(&mut self, class: ClassId, layout_nodes: u32, ref_nodes: u32);
    fn tie_broken(&mut self, class: ClassId);
}

impl ObserveRefine for NoObserve {
    fn round(&mut self, index: u32, classes: u32, split: u32) {}
    fn stalled(&mut self, class: ClassId, layout_nodes: u32, ref_nodes: u32) {}
    fn tie_broken(&mut self, class: ClassId) {}
}

/// Refine until stable.
///
/// **Transform.** Caller owns `out`; its buffers are reused across rounds and
/// across comparisons, so a hierarchical run allocates once for the whole tree.
///
/// `max_rounds` bounds the work. Hitting it is not a mismatch and must not be
/// reported as one — it is [`Verdict::Inconclusive`](crate::Verdict), which is
/// the distinction the "never a false match" rule turns on.
pub fn refine_into(
    layout: &LayoutGraph,
    reference: &RefGraph,
    tie_break: TieBreak,
    max_rounds: u32,
    out: &mut Partition,
) -> Refinement {
    refine_observed(layout, reference, tie_break, max_rounds, out, &mut NoObserve)
}

/// How refinement ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refinement {
    /// No class split further and every class is a one-to-one pairing.
    Complete,
    /// Stable, but some class holds unequal counts from the two sides. That is
    /// a real structural difference and the classes involved name it.
    Discrepant,
    /// Stable with genuine symmetry remaining, and [`TieBreak::Refuse`] was in
    /// force.
    Symmetric,
    /// `max_rounds` was reached. Says nothing about whether the netlists match.
    Exhausted,
}

fn refine_observed<O: ObserveRefine>(
    layout: &LayoutGraph,
    reference: &RefGraph,
    tie_break: TieBreak,
    max_rounds: u32,
    out: &mut Partition,
    observer: &mut O,
) -> Refinement {
    todo!()
}

impl Partition {
    /// The paired nodes, ascending by layout index.
    ///
    /// Only classes that resolved to exactly one node per side. Everything else
    /// is a discrepancy.
    pub fn pairs(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        todo!();
        #[allow(unreachable_code)]
        std::iter::empty()
    }

    /// Classes that did not resolve, with their membership on both sides.
    pub fn unresolved(&self) -> impl Iterator<Item = (ClassId, u32, u32)> + '_ {
        todo!();
        #[allow(unreachable_code)]
        std::iter::empty()
    }
}

/// Tests for the [`ObserveRefine`] seam.
///
/// These live inside the crate because [`refine_observed`] is private. That is
/// the deliberate trade `core::observe` records: the public interface takes no
/// observer, so the seam does not widen it, and the price is that its tests
/// cannot be integration tests.
///
/// Everything here is a property of the *round sequence*, which is the one thing
/// the final partition does not record. Whether a comparison converged in three
/// rounds or ninety, and whether it stalled on a symmetry before the tie-break
/// resolved it, are invisible in `pairs()` and are the difference between a fast
/// comparison and one about to time out.
#[cfg(test)]
mod tests {
    use super::{refine_observed, ClassId, ObserveRefine, Partition, Refinement, TieBreak};
    use crate::graph::{Graph, LayoutGraph, RefGraph};
    use gpurify_core::observe::Observer;
    use gpurify_ingest::deck::DeviceKind;
    use gpurify_ingest::StrId;
    use gpurify_topology::TerminalRole;

    const NCH: StrId = StrId(1);

    /// Records every callback in order. The gate is `true`, which is what makes
    /// it an adapter rather than a second null one.
    #[derive(Debug, Default)]
    struct Recorder {
        rounds: Vec<(u32, u32, u32)>,
        stalled: Vec<(ClassId, u32, u32)>,
        tie_broken: Vec<ClassId>,
    }

    impl Observer for Recorder {
        const ENABLED: bool = true;
    }

    impl ObserveRefine for Recorder {
        fn round(&mut self, index: u32, classes: u32, split: u32) {
            self.rounds.push((index, classes, split));
        }
        fn stalled(&mut self, class: ClassId, layout_nodes: u32, ref_nodes: u32) {
            self.stalled.push((class, layout_nodes, ref_nodes));
        }
        fn tie_broken(&mut self, class: ClassId) {
            self.tie_broken.push(class);
        }
    }

    /// A source-to-drain chain of `devices` transistors over `devices + 1` nets.
    ///
    /// Refinement propagates one hop per round along a chain, so the number of
    /// rounds this needs grows with its length. That is the whole reason the
    /// fixture is a chain: the seam's claim is about how much work happened, so
    /// the fixture has to make the amount of work predictable.
    fn chain(devices: u32) -> Graph {
        let mut graph = Graph::default();
        graph.device_terminal_start.push(0);
        graph.device_param_start.push(0);
        for index in 0..devices {
            graph.device_kind.push(DeviceKind::Mos);
            graph.device_model.push(NCH);
            graph.terminal_net.push(index);
            graph.terminal_role.push(TerminalRole::Source);
            graph.terminal_net.push(index + 1);
            graph.terminal_role.push(TerminalRole::Drain);
            graph.device_terminal_start.push((index + 1) * 2);
            graph.device_param_start.push(0);
        }
        graph.net_terminal_start.push(0);
        for net in 0..=devices {
            if net > 0 {
                graph.net_terminal.push((net - 1, TerminalRole::Drain));
            }
            if net < devices {
                graph.net_terminal.push((net, TerminalRole::Source));
            }
            let filled = u32::try_from(graph.net_terminal.len()).expect("a small fixture");
            graph.net_terminal_start.push(filled);
            graph.net_name.push(None);
        }
        graph
    }

    /// Two transistors sharing a tail and a bulk, gates and drains apart: a
    /// differential pair, whose two halves are interchangeable by an
    /// automorphism no signature can break.
    fn differential_pair() -> Graph {
        use TerminalRole::{Bulk, Drain, Gate, Source};
        let mut graph = Graph::default();
        graph.device_terminal_start.push(0);
        graph.device_param_start.push(0);
        for (gate, drain) in [(1u32, 3u32), (2, 4)] {
            graph.device_kind.push(DeviceKind::Mos);
            graph.device_model.push(NCH);
            for (role, net) in [(Gate, gate), (Source, 0), (Drain, drain), (Bulk, 5)] {
                graph.terminal_net.push(net);
                graph.terminal_role.push(role);
            }
            let filled = u32::try_from(graph.terminal_net.len()).expect("a small fixture");
            graph.device_terminal_start.push(filled);
            graph.device_param_start.push(0);
        }
        graph.net_terminal_start.push(0);
        let per_net: [&[(u32, TerminalRole)]; 6] = [
            &[(0, Source), (1, Source)],
            &[(0, Gate)],
            &[(1, Gate)],
            &[(0, Drain)],
            &[(1, Drain)],
            &[(0, Bulk), (1, Bulk)],
        ];
        for terminals in per_net {
            graph.net_terminal.extend_from_slice(terminals);
            let filled = u32::try_from(graph.net_terminal.len()).expect("a small fixture");
            graph.net_terminal_start.push(filled);
            graph.net_name.push(None);
        }
        graph
    }

    /// Oracle: law. Refinement only ever splits a class, so the class count is
    /// nondecreasing from round to round; rounds are announced consecutively
    /// from zero; and a round that split nothing is the last one, because that
    /// is what stability means. None of this is readable from the final
    /// partition, which is why the seam exists.
    #[test]
    fn rounds_are_announced_consecutively_and_never_lose_a_class() {
        let mut scratch = Partition::default();
        let mut observer = Recorder::default();
        let outcome = refine_observed(
            &LayoutGraph(chain(12)),
            &RefGraph(chain(12)),
            TieBreak::LowestIndex,
            256,
            &mut scratch,
            &mut observer,
        );
        assert_eq!(outcome, Refinement::Complete);

        assert!(
            observer.rounds.len() > 1,
            "a twelve-device chain converged in {} round(s), so the fixture is \
             not exercising propagation at all",
            observer.rounds.len()
        );
        for (position, &(index, classes, split)) in observer.rounds.iter().enumerate() {
            let position = u32::try_from(position).expect("a small round count");
            assert_eq!(index, position, "round indices are not consecutive from zero");
            if position > 0 {
                let previous = observer.rounds[position as usize - 1].1;
                assert!(
                    classes >= previous,
                    "round {index} reports {classes} classes after {previous}"
                );
            }
            if split == 0 {
                assert_eq!(
                    position as usize,
                    observer.rounds.len() - 1,
                    "round {index} split nothing but refinement continued"
                );
            }
        }
    }

    /// Oracle: construct-from-answer. The budget is three rounds and the chain
    /// needs more, so exactly three are announced and the run reports itself
    /// exhausted. A round counted but not announced, or announced past the
    /// budget, is work the seam is failing to account for.
    #[test]
    fn a_run_that_hits_its_budget_announces_exactly_that_many_rounds() {
        let mut scratch = Partition::default();
        let mut observer = Recorder::default();
        let outcome = refine_observed(
            &LayoutGraph(chain(24)),
            &RefGraph(chain(24)),
            TieBreak::LowestIndex,
            3,
            &mut scratch,
            &mut observer,
        );
        assert_eq!(outcome, Refinement::Exhausted);
        assert_eq!(observer.rounds.len(), 3);
    }

    /// Oracle: construct-from-answer. A differential pair stalls on a class
    /// holding both halves. Under [`TieBreak::Refuse`] the stall is reported and
    /// nothing is chosen, and because the graph is being compared with itself
    /// the class holds the same number of nodes on each side.
    #[test]
    fn a_refused_symmetry_is_announced_as_a_stall_and_nothing_is_chosen() {
        let mut scratch = Partition::default();
        let mut observer = Recorder::default();
        let outcome = refine_observed(
            &LayoutGraph(differential_pair()),
            &RefGraph(differential_pair()),
            TieBreak::Refuse,
            256,
            &mut scratch,
            &mut observer,
        );
        assert_eq!(outcome, Refinement::Symmetric);
        assert!(
            !observer.stalled.is_empty(),
            "refinement stalled without announcing which class"
        );
        assert!(
            observer.tie_broken.is_empty(),
            "a tie was broken under TieBreak::Refuse: {:?}",
            observer.tie_broken
        );
        for &(class, layout_nodes, ref_nodes) in &observer.stalled {
            assert_eq!(
                layout_nodes, ref_nodes,
                "class {class:?} is uneven in a comparison of a graph with itself"
            );
            assert!(layout_nodes > 1, "class {class:?} stalled with one node");
        }
    }

    /// Oracle: construct-from-answer. The same structure with the tie-break
    /// allowed to fire announces the classes it chose in, and every one of them
    /// is a class it first announced as stalled. A tie broken without a stall is
    /// a choice made where none was needed.
    #[test]
    fn a_broken_tie_is_announced_on_a_class_that_first_stalled() {
        let mut scratch = Partition::default();
        let mut observer = Recorder::default();
        let outcome = refine_observed(
            &LayoutGraph(differential_pair()),
            &RefGraph(differential_pair()),
            TieBreak::LowestIndex,
            256,
            &mut scratch,
            &mut observer,
        );
        assert_eq!(outcome, Refinement::Complete);
        assert!(
            !observer.tie_broken.is_empty(),
            "a symmetric structure completed without any tie being broken"
        );
        for class in &observer.tie_broken {
            assert!(
                observer.stalled.iter().any(|(stalled, ..)| stalled == class),
                "class {class:?} was tie-broken but never reported as stalled"
            );
        }
    }

    /// Oracle: law. A rigid graph — the chain, whose ends are distinguishable
    /// and whose interior is not symmetric — needs no tie-break at all. Without
    /// this, the two tests above are satisfied by an implementation that
    /// announces a stall on every class it ever looks at.
    #[test]
    fn a_rigid_graph_stalls_on_nothing_and_breaks_no_tie() {
        let mut scratch = Partition::default();
        let mut observer = Recorder::default();
        let outcome = refine_observed(
            &LayoutGraph(chain(7)),
            &RefGraph(chain(7)),
            TieBreak::Refuse,
            256,
            &mut scratch,
            &mut observer,
        );
        assert_eq!(outcome, Refinement::Complete);
        assert!(observer.stalled.is_empty(), "{:?}", observer.stalled);
        assert!(observer.tie_broken.is_empty(), "{:?}", observer.tie_broken);
    }
}
