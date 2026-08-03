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
