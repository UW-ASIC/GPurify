//! Connected components over an edge list: weighted union-find with path
//! halving.

use crate::observe::Observer;

/// The component a node belongs to.
///
/// Always the minimum node index in the component, which is what makes the
/// output canonical regardless of edge order — the determinism gate depends on
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ComponentLabel(pub u32);

/// Label every node with its component; `out` is cleared and refilled to
/// `node_count` rows.
///
/// An edge naming a node at or beyond `node_count` is asserted, not ignored:
/// ignoring it merges nothing and produces a plausible extra net.
pub fn components_into(node_count: u32, edges: &[(u32, u32)], out: &mut Vec<ComponentLabel>) {
    components_observed(node_count, edges, out, &mut crate::observe::NoObserve);
}

/// Seam reporting the shape of the union-find's work.
pub trait ObserveUnionFind: Observer {
    /// A union merged two distinct components.
    fn merged(&mut self, a: u32, b: u32);
    /// A union found both nodes already in one component.
    fn redundant(&mut self, a: u32, b: u32);
    /// Path length walked by a find, before compression.
    fn find_depth(&mut self, depth: u32);
}

impl ObserveUnionFind for crate::observe::NoObserve {
    fn merged(&mut self, _a: u32, _b: u32) {}
    fn redundant(&mut self, _a: u32, _b: u32) {}
    fn find_depth(&mut self, _depth: u32) {}
}

/// Root of `node`, halving the path it walked on the way out.
fn find<O: ObserveUnionFind>(parent: &mut [u32], node: u32, observer: &mut O) -> u32 {
    debug_assert!((node as usize) < parent.len());

    let mut x = node;
    let mut depth = 0u32;
    while parent[x as usize] != x {
        // Path halving — snap `x` to its grandparent, which is what bounds the
        // tree height and so bounds this loop.
        let grand = parent[parent[x as usize] as usize];
        parent[x as usize] = grand;
        x = grand;
        depth += 1;
    }

    if O::ENABLED {
        observer.find_depth(depth);
    }
    debug_assert_eq!(parent[x as usize], x, "find returned a non-root");
    x
}

fn components_observed<O: ObserveUnionFind>(
    node_count: u32,
    edges: &[(u32, u32)],
    out: &mut Vec<ComponentLabel>,
    observer: &mut O,
) {
    let n = node_count as usize;
    debug_assert!(
        edges.iter().all(|&(a, b)| a < node_count && b < node_count),
        "an edge names a node at or beyond node_count = {node_count}"
    );

    // `rank` is a tree height under path halving, so it never exceeds 64 and a
    // `u8` holds it.
    let mut parent: Vec<u32> = (0..node_count).collect();
    let mut rank: Vec<u8> = vec![0; n];

    // Serial by construction: the union scatters into `parent` at an index only
    // the previous edge's finds can produce, so no row order is legal.
    for &(a, b) in edges {
        let ra = find(&mut parent, a, observer);
        let rb = find(&mut parent, b, observer);
        let joined = ra != rb;

        // Branchless union by rank. When the roots already agree, `hi == lo ==
        // ra`, so the store rewrites a root's own parent and is a no-op; only
        // the rank bump has to be suppressed, and `joined` does that.
        let smaller = rank[ra as usize] < rank[rb as usize];
        let tie = rank[ra as usize] == rank[rb as usize];
        let mask = u32::from(smaller).wrapping_neg();
        let hi = (ra & !mask) | (rb & mask);
        let lo = (ra & mask) | (rb & !mask);
        parent[lo as usize] = hi;
        rank[hi as usize] += u8::from(tie & joined);

        if O::ENABLED {
            if joined {
                observer.merged(a, b);
            } else {
                observer.redundant(a, b);
            }
        }
    }

    out.clear();
    out.reserve(n);

    // Ascending, which is what makes the min-index labelling fall out: the
    // first node of a component reached in index order *is* its minimum, so
    // `label` is already final by the time it is read back.
    let mut label: Vec<u32> = vec![u32::MAX; n];
    for i in 0..node_count {
        let root = find(&mut parent, i, observer) as usize;
        label[root] = label[root].min(i);
        out.push(ComponentLabel(label[root]));
    }

    debug_assert_eq!(out.len(), n, "one row per node");
    debug_assert!(
        out.iter()
            .enumerate()
            .all(|(i, l)| (l.0 as usize) <= i && out[l.0 as usize] == *l),
        "a label must be the minimum node index in its own component"
    );
}

/// Number of distinct components in a label array.
pub fn component_count(labels: &[ComponentLabel]) -> u32 {
    debug_assert!(u32::try_from(labels.len()).is_ok(), "more nodes than a u32");
    debug_assert!(
        labels
            .iter()
            .enumerate()
            .all(|(i, l)| (l.0 as usize) <= i && labels[l.0 as usize] == *l),
        "component_count reads the canonical min-index labelling"
    );

    // Each component is named by exactly one node — the minimum index in it,
    // which is the one node whose label is itself. So the component count is
    // the count of self-labelled rows: one pass, no set and no sort.
    let mut count = 0u32;
    for (i, label) in labels.iter().enumerate() {
        count += u32::from(label.0 as usize == i);
    }

    debug_assert!(count as usize <= labels.len(), "more components than nodes");
    count
}

/// Adapter tests for the union-find seam; `components_observed` is private, so
/// these cannot live in `crates/core/tests/`.
#[cfg(test)]
mod tests {
    use super::{components_observed, ComponentLabel, ObserveUnionFind};
    use crate::observe::Observer;

    /// Records every callback in order.
    #[derive(Debug, Default)]
    struct Recorder {
        merged: Vec<(u32, u32)>,
        redundant: Vec<(u32, u32)>,
        depths: Vec<u32>,
    }

    impl Observer for Recorder {
        const ENABLED: bool = true;
    }

    impl ObserveUnionFind for Recorder {
        fn merged(&mut self, a: u32, b: u32) {
            self.merged.push((a, b));
        }
        fn redundant(&mut self, a: u32, b: u32) {
            self.redundant.push((a, b));
        }
        fn find_depth(&mut self, depth: u32) {
            self.depths.push(depth);
        }
    }

    /// A spanning tree over `n` nodes has `n - 1` edges, each joining two
    /// distinct components, so the merge count is fixed before the call.
    #[test]
    fn every_edge_of_a_spanning_tree_merges_and_none_is_redundant() {
        // A path 0-1-2-...-11: twelve nodes, eleven edges, one component.
        let edges: Vec<(u32, u32)> = (0..11).map(|i| (i, i + 1)).collect();
        let mut out = Vec::new();
        let mut seen = Recorder::default();
        components_observed(12, &edges, &mut out, &mut seen);

        assert_eq!(
            seen.merged.len(),
            11,
            "a spanning tree's every edge joins two distinct components"
        );
        assert!(
            seen.redundant.is_empty(),
            "no edge of a tree can close a cycle, but {:?} were reported as \
             finding both endpoints already joined",
            seen.redundant
        );
        assert_eq!(out, vec![ComponentLabel(0); 12]);
    }

    /// An edge inside an already-whole component cannot change the partition,
    /// so every chord is a redundant union by construction.
    #[test]
    fn an_edge_inside_a_finished_component_is_reported_redundant_not_merged() {
        // The same path, then every chord of it that closes a cycle.
        let mut edges: Vec<(u32, u32)> = (0..5).map(|i| (i, i + 1)).collect();
        edges.extend([(0, 5), (1, 4), (2, 5), (0, 3)]);
        let mut out = Vec::new();
        let mut seen = Recorder::default();
        components_observed(6, &edges, &mut out, &mut seen);

        assert_eq!(
            seen.merged.len(),
            5,
            "six nodes reach one component in five"
        );
        assert_eq!(
            seen.redundant.len(),
            4,
            "the four chords each close a cycle and merge nothing"
        );
        assert_eq!(out, vec![ComponentLabel(0); 6]);
    }

    /// Path halving bounds tree height, so no find walks further than the
    /// component it is walking. A bound, because the exact depth is a property
    /// of the union order the interface does not fix.
    #[test]
    fn no_find_walks_further_than_the_component_it_is_walking() {
        let mut out = Vec::new();

        let mut alone = Recorder::default();
        components_observed(64, &[], &mut out, &mut alone);
        assert!(
            alone.depths.iter().all(|&d| d == 0),
            "a graph with no edges performs no union and so walks nothing"
        );
        assert_eq!(out.len(), 64);

        // A star, which is the worst case for a union-find that never
        // compresses: every edge touches the same node.
        let edges: Vec<(u32, u32)> = (1..64).map(|i| (0, i)).collect();
        let mut star = Recorder::default();
        components_observed(64, &edges, &mut out, &mut star);
        assert!(
            star.depths.iter().all(|&d| d < 64),
            "a find walked {} nodes in a 64-node graph, which means the parent \
             chain is longer than the component",
            star.depths.iter().copied().max().unwrap_or(0)
        );
        assert_eq!(out, vec![ComponentLabel(0); 64]);
    }

    /// The seam is instrumentation: it must not change the partition, and it
    /// must itself be a function of the input.
    #[test]
    fn observing_changes_neither_the_partition_nor_the_sequence_reported() {
        let edges = [(3, 1), (4, 4), (0, 2), (7, 3), (2, 5), (6, 0), (5, 1)];

        let mut first_out = Vec::new();
        let mut first = Recorder::default();
        components_observed(8, &edges, &mut first_out, &mut first);

        let mut second_out = Vec::new();
        let mut second = Recorder::default();
        components_observed(8, &edges, &mut second_out, &mut second);

        assert_eq!(first.merged, second.merged);
        assert_eq!(first.redundant, second.redundant);
        assert_eq!(first.depths, second.depths);
        assert_eq!(first_out, second_out);

        let mut unobserved = Vec::new();
        super::components_into(8, &edges, &mut unobserved);
        assert_eq!(
            unobserved, first_out,
            "the null adapter and the recording one must reach the same labels"
        );
    }
}
