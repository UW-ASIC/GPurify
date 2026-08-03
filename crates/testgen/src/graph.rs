//! Graphs whose connected components are known before anything runs.
//!
//! The oracle is construct-from-answer. Nodes are dealt into components of
//! stated sizes, every edge is drawn *within* a component and none across, and
//! each component is given a spanning tree first — so the partition is a fact
//! about how the graph was built, not a claim about what a union-find returned.
//!
//! Two details make this a real test rather than a warm-up:
//!
//! - **The component of a node is not a function of its index.** Nodes are
//!   dealt by a shuffled assignment, so component `k` is scattered through the
//!   index space. An implementation that labels by block, or that happens to
//!   work only when components are contiguous, fails here.
//! - **The edge list is shuffled.** `core::connectivity` promises a canonical
//!   label — the minimum node index in the component — regardless of edge
//!   order, and shuffling is what turns that promise into something a test can
//!   fail.

use crate::Rng;
use gpurify_core::connectivity::ComponentLabel;

/// A graph and its partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphCase {
    /// Nodes, numbered `0..node_count`. Every one appears in some component,
    /// including the singletons — an isolated node is a component of one and
    /// is exactly the case a label-propagation bug drops.
    pub node_count: u32,
    /// Undirected edges, in shuffled order and with both endpoint orders
    /// occurring.
    pub edges: Vec<(u32, u32)>,
    /// The answer: `expected[n]` is the minimum node index in `n`'s component,
    /// which is the label `core::connectivity` is specified to produce.
    pub expected: Vec<ComponentLabel>,
    /// The members of each component, ascending, in the order the sizes were
    /// requested. Useful where a test wants the partition as sets rather than
    /// as labels.
    pub components: Vec<Vec<u32>>,
}

/// Build a graph with the stated component sizes.
///
/// `extra_edges` are added *within* components on top of the spanning tree, so
/// they create cycles and redundant unions without changing the answer. Zero is
/// a legal value and gives a forest of trees.
///
/// # Panics
///
/// When `sizes` is empty or contains a zero — a component with no nodes is not
/// a component, and accepting one would let a caller state a partition that
/// does not exist.
#[must_use]
pub fn graph_with_partition(rng: &mut Rng, sizes: &[u32], extra_edges: u32) -> GraphCase {
    assert!(!sizes.is_empty(), "a partition needs at least one component");
    assert!(
        sizes.iter().all(|&s| s > 0),
        "a component of zero nodes is not a component"
    );

    let node_count: u32 = sizes
        .iter()
        .copied()
        .try_fold(0u32, u32::checked_add)
        .expect("the component sizes overflow the node index space");

    // Deal component ids to nodes. Shuffling the deal is what stops a
    // component from being a contiguous block of indices.
    let mut owner: Vec<u32> = Vec::with_capacity(node_count as usize);
    for (component, &size) in sizes.iter().enumerate() {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "component indexes `sizes`, whose length is bounded by node_count"
        )]
        let id = component as u32;
        owner.extend(std::iter::repeat_n(id, size as usize));
    }
    rng.shuffle(&mut owner);

    let mut components: Vec<Vec<u32>> = vec![Vec::new(); sizes.len()];
    for (node, &component) in owner.iter().enumerate() {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "node indexes owner, whose length is node_count"
        )]
        components[component as usize].push(node as u32);
    }

    // A spanning tree per component: node `i` of a component joins a uniformly
    // chosen earlier member. That is enough to make the component connected,
    // and it is the minimum that is enough — anything denser would hide a
    // union-find that merges too eagerly.
    let mut edges: Vec<(u32, u32)> = Vec::new();
    for members in &components {
        for i in 1..members.len() {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "below(i as u64) is under i, which came from a usize"
            )]
            let parent = rng.below(i as u64) as usize;
            edges.push((members[parent], members[i]));
        }
    }

    // Redundant edges, drawn within a component so the partition is unchanged.
    // These are the `redundant` unions the observer at the seam counts.
    for _ in 0..extra_edges {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "the draw is bounded by components.len(), a usize"
        )]
        let members = &components[rng.below(components.len() as u64) as usize];
        if members.len() < 2 {
            continue;
        }
        #[allow(
            clippy::cast_possible_truncation,
            reason = "both draws are bounded by members.len(), a usize"
        )]
        let (a, b) = (
            rng.below(members.len() as u64) as usize,
            rng.below(members.len() as u64) as usize,
        );
        edges.push((members[a], members[b]));
    }

    // Half the edges get their endpoints transposed. `components_into` takes an
    // undirected edge list, and a test that only ever passes ascending pairs
    // does not check that.
    for edge in &mut edges {
        if rng.unit() < 0.5 {
            *edge = (edge.1, edge.0);
        }
    }
    rng.shuffle(&mut edges);

    let mut expected = vec![ComponentLabel(0); node_count as usize];
    for members in &components {
        let label = ComponentLabel(*members.first().expect("a component has members"));
        for &node in members {
            expected[node as usize] = label;
        }
    }

    GraphCase {
        node_count,
        edges,
        expected,
        components,
    }
}

#[cfg(test)]
mod tests {
    use super::graph_with_partition;
    use crate::Rng;

    /// Oracle: construct-from-answer, checked against itself. The generator's
    /// own claim is that no edge crosses a component and that every component
    /// is connected; if that were false the "answer" it hands out would be
    /// wrong and every test built on it would be measuring nothing.
    #[test]
    fn no_edge_crosses_a_component_and_every_component_is_connected() {
        let mut rng = Rng::new(42);
        let case = graph_with_partition(&mut rng, &[1, 5, 12, 3, 40], 25);

        for &(a, b) in &case.edges {
            assert_eq!(
                case.expected[a as usize], case.expected[b as usize],
                "edge ({a}, {b}) crosses a component"
            );
        }

        // Connectivity by a plain flood fill over an adjacency list. Not the
        // union-find under test — a second, independent walk, which is what
        // makes it evidence.
        let mut adjacency = vec![Vec::new(); case.node_count as usize];
        for &(a, b) in &case.edges {
            adjacency[a as usize].push(b);
            adjacency[b as usize].push(a);
        }
        for members in &case.components {
            let root = members[0];
            let mut seen = vec![false; case.node_count as usize];
            let mut stack = vec![root];
            seen[root as usize] = true;
            let mut reached = 0;
            while let Some(node) = stack.pop() {
                reached += 1;
                for &next in &adjacency[node as usize] {
                    if !seen[next as usize] {
                        seen[next as usize] = true;
                        stack.push(next);
                    }
                }
            }
            assert_eq!(reached, members.len(), "component {root} is not connected");
        }
    }

    /// Oracle: law. The label of a node is the minimum index in its component,
    /// by definition, and the generator must state exactly that.
    #[test]
    fn every_label_is_the_minimum_index_of_its_component() {
        let mut rng = Rng::new(9);
        let case = graph_with_partition(&mut rng, &[7, 7, 7], 10);
        for members in &case.components {
            let minimum = members.iter().copied().min().expect("non-empty");
            for &node in members {
                assert_eq!(case.expected[node as usize].0, minimum);
            }
        }
    }

    /// Oracle: determinism. Two draws from the same seed give the same graph,
    /// including the shuffled edge order.
    #[test]
    fn one_seed_gives_one_graph() {
        let first = graph_with_partition(&mut Rng::new(2024), &[4, 9, 2], 6);
        let second = graph_with_partition(&mut Rng::new(2024), &[4, 9, 2], 6);
        assert_eq!(first, second);
    }
}
