//! Network reduction.
//!
//! Extraction produces one node per geometric branch point, which is more
//! detail than any simulator wants. Reduction collapses that to a requested
//! order while preserving the network's behaviour at its terminals.
//!
//! # Preserving what, exactly
//!
//! "Behaviour at the terminals" has a precise meaning, and it is the oracle for
//! this module: total capacitance on each net is invariant, and the driving
//! point resistance between any two terminals is invariant. Both are checkable
//! against the unreduced network without any reference implementation, and both
//! are laws rather than opinions.

use crate::network::{NodeId, ParasiticNetwork};

/// How far to reduce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// Keep every node. Reduction becomes a no-op, which is the identity case
    /// every invariant test starts from.
    Full,
    /// One lumped R and C per net. The smallest useful form.
    Lumped,
    /// Keep terminals and branch points, collapse series and parallel chains.
    /// The usual choice.
    Reduced,
}

/// Reduce a network.
///
/// **Transform, A-to-B.** Caller owns `out`. Not in-place: the unreduced
/// network is what the invariant tests compare against, so destroying it would
/// destroy the only check this module has.
pub fn reduce_into(
    network: &ParasiticNetwork,
    terminals: &[NodeId],
    order: Order,
    out: &mut ParasiticNetwork,
) {
    todo!()
}

/// Collapse chains of resistors in series.
///
/// **Decision-shaped, applied as a transform.** Series resistance adds; that is
/// the whole rule and its oracle. Only collapses a node with exactly two
/// resistive neighbours and no capacitance, because a node with capacitance is
/// electrically observable and removing it changes behaviour.
pub fn collapse_series_into(network: &ParasiticNetwork, out: &mut ParasiticNetwork) {
    todo!()
}

/// Merge resistors in parallel between the same node pair.
///
/// Conductances add. Emitted once per node pair, ordered by `(from, to)`, so
/// the merge order is fixed and the summation is bit-reproducible.
pub fn merge_parallel_into(network: &ParasiticNetwork, out: &mut ParasiticNetwork) {
    todo!()
}

/// Total capacitance, before and after.
///
/// **Decision** — pure, and the invariant that gates this whole module. Exposed
/// rather than kept private precisely so the check is cheap to write.
pub fn total_capacitance(
    network: &ParasiticNetwork,
) -> gpurify_units::Qty<gpurify_units::Capacitance, { gpurify_units::prefix::FEMTO }> {
    todo!()
}
