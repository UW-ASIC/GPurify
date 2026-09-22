//! Graphs whose connected components are known before anything runs.
//!
//! Node-to-component assignment and the edge list are both shuffled, so a
//! component is never a contiguous block of indices and no test depends on
//! edge order.

use crate::Rng;
use gpurify_geom::connectivity::ComponentLabel;

/// A graph and its partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphCase {
    /// Nodes, numbered `0..node_count`. A singleton is a component of one.
    pub node_count: u32,
    /// Undirected edges, shuffled, with both endpoint orders occurring.
    pub edges: Vec<(u32, u32)>,
    /// `expected[n]` is the minimum node index in `n`'s component.
    pub expected: Vec<ComponentLabel>,
    /// The members of each component, ascending, in the requested size order.
    pub components: Vec<Vec<u32>>,
}

/// Build a graph with the stated component sizes.
#[must_use]
pub fn graph_with_partition(rng: &mut Rng, sizes: &[u32], extra_edges: u32) -> GraphCase {
    assert!(
        !sizes.is_empty(),
        "a partition needs at least one component"
    );
    assert!(
        sizes.iter().all(|&s| s > 0),
        "a component of zero nodes is not a component"
    );

    let node_count: u32 = sizes
        .iter()
        .copied()
        .try_fold(0u32, u32::checked_add)
        .expect("the component sizes overflow the node index space");

    // Shuffling the deal stops a component being a contiguous index block.
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

    // A spanning tree per component: node `i` joins a uniformly chosen earlier
    // member. The sparsest edge set that still connects it.
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

    // Half the edges get their endpoints transposed: the edge list is
    // undirected and must not be assumed ascending.
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

    /// No edge crosses a component and every component is connected.
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

        // Flood fill, not the union-find under test: an independent walk.
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

    /// A node's label is the minimum index in its component.
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

    /// One seed gives one graph, edge order included.
    #[test]
    fn one_seed_gives_one_graph() {
        let first = graph_with_partition(&mut Rng::new(2024), &[4, 9, 2], 6);
        let second = graph_with_partition(&mut Rng::new(2024), &[4, 9, 2], 6);
        assert_eq!(first, second);
    }
}
