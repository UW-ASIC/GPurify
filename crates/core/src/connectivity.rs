//! Connected components over an edge list.
//!
//! A generic graph primitive, not net extraction. `topology` builds the edge
//! list from geometry and interprets the labels as nets; this module knows
//! nothing about layers or vias.
//!
//! Weighted union-find with path halving — the direct, cache-friendly answer on
//! a CPU. The previous implementation ran parallel label propagation (`FastSV` /
//! `ECL-CC`) so that one code path could target a GPU through a transpiling
//! macro; with GPU gone from everything but quasi-static PEX, that shape has no
//! reason to exist.

use crate::observe::Observer;

/// The component a node belongs to.
///
/// **Every node is labelled with the minimum node index in its component.**
/// That is what makes the output canonical: two runs on the same graph give
/// identical labels, and two graphs with the same partition give identical
/// labels regardless of edge order. The determinism gate depends on it, and so
/// does any test that compares extracted nets by label rather than by set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ComponentLabel(pub u32);

/// Label every node with its component.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled to
/// `node_count` rows. All data flow is in the signature: the union-find's
/// parent and rank arrays are the only hidden state, they are scratch, and they
/// do not outlive the call.
///
/// `edges` is a flat pair list; an edge naming a node at or beyond
/// `node_count` is a caller bug and is asserted, not silently ignored —
/// silently ignoring it merges nothing and produces a plausible extra net.
pub fn components_into(node_count: u32, edges: &[(u32, u32)], out: &mut Vec<ComponentLabel>) {
    components_observed(node_count, edges, out, &mut crate::observe::NoObserve);
}

/// What the union-find did.
///
/// Component count and merge count are derivable from `out`, but the *shape* of
/// the work is not: how many union calls were no-ops, how deep the trees got.
/// Those are what a performance regression shows up in first, and this is the
/// seam where the allocation-and-work counters attach.
pub trait ObserveUnionFind: Observer {
    /// A union merged two distinct components.
    fn merged(&mut self, a: u32, b: u32);
    /// A union found both nodes already in one component.
    fn redundant(&mut self, a: u32, b: u32);
    /// Path length walked by a find, before compression.
    fn find_depth(&mut self, depth: u32);
}

impl ObserveUnionFind for crate::observe::NoObserve {
    fn merged(&mut self, a: u32, b: u32) {}
    fn redundant(&mut self, a: u32, b: u32) {}
    fn find_depth(&mut self, depth: u32) {}
}

fn components_observed<O: ObserveUnionFind>(
    node_count: u32,
    edges: &[(u32, u32)],
    out: &mut Vec<ComponentLabel>,
    observer: &mut O,
) {
    todo!()
}

/// Number of distinct components in a label array.
///
/// **Decision** — pure, one slice in, one number out. Separate from
/// [`components_into`] because several callers want the count without wanting
/// to re-scan, and because it is exactly the shape that earns a table test.
pub fn component_count(labels: &[ComponentLabel]) -> u32 {
    todo!()
}
