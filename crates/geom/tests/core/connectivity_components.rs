//! Connected components, and the one property that makes their output usable
//! as a net label: **the label is the minimum node index in the component.**
//!
//! Any correct union-find partitions the nodes. Only a canonical labelling
//! gives the *same* labels twice, and `topology` compares extracted nets by
//! label rather than by set. So the tests below assert the label and not merely
//! the partition, and they shuffle the edge list before every comparison,
//! because "regardless of edge order" is precisely the half a fixture with a
//! sorted edge list cannot check.

use gpurify_geom::connectivity::{component_count, components_into, ComponentLabel};
use gpurify_testgen::graph::graph_with_partition;
use gpurify_testgen::Rng;

/// Oracle: construct-from-answer. The generator deals nodes into components of
/// stated sizes before drawing an edge, so the partition and every label are
/// facts about how the graph was built. Nodes are dealt by a shuffled
/// assignment, so a component is not a contiguous block of indices and an
/// implementation that labels by block fails.
#[test]
fn every_node_is_labelled_with_the_minimum_index_in_its_component() {
    let mut rng = Rng::new(71);
    let case = graph_with_partition(&mut rng, &[1, 2, 5, 13, 1, 40, 7], 60);

    let mut labels = Vec::new();
    components_into(case.node_count, &case.edges, &mut labels);

    assert_eq!(labels, case.expected, "the labels are not the built answer");
    assert_eq!(component_count(&labels), 7, "seven components were built");

    // The same claim stated as sets, which is what catches a labelling that
    // happened to agree numerically while merging the wrong nodes.
    for members in &case.components {
        let label = ComponentLabel(members.iter().copied().min().expect("non-empty"));
        for &node in members {
            assert_eq!(labels[node as usize], label, "node {node}");
        }
    }
}

/// Oracle: law. The label of a component is the minimum index in it, by
/// definition, so the property is checkable from the output alone without
/// consulting the generator's answer. Over a graph with an isolated node, a
/// pair, and a large component, all interleaved in the index space.
#[test]
fn a_label_is_always_a_node_that_carries_that_same_label() {
    let mut rng = Rng::new(72);
    let case = graph_with_partition(&mut rng, &[1, 2, 3, 30, 1, 1, 19], 45);

    let mut labels = Vec::new();
    components_into(case.node_count, &case.edges, &mut labels);
    assert_eq!(labels.len(), case.node_count as usize, "one row per node");

    for (node, &label) in labels.iter().enumerate() {
        assert!(label.0 as usize <= node, "node {node} labelled {label:?}");
        assert_eq!(
            labels[label.0 as usize], label,
            "a label must be a node in its own component"
        );
    }

    // Every edge joins two nodes with the same label. Together with the
    // minimality above, that is the definition of a connected component.
    for &(a, b) in &case.edges {
        assert_eq!(
            labels[a as usize], labels[b as usize],
            "edge ({a}, {b}) spans two labels"
        );
    }
}

/// Oracle: law. The labels are a function of the graph, not of the order its
/// edges arrived in. Shuffling with the seeded generator is what turns that
/// promise into something a test can fail; a fixture with a sorted edge list
/// cannot.
#[test]
fn two_edge_orderings_of_one_graph_give_identical_labels() {
    let mut rng = Rng::new(73);
    let case = graph_with_partition(&mut rng, &[9, 4, 17, 1, 25], 80);

    let mut reference = Vec::new();
    components_into(case.node_count, &case.edges, &mut reference);

    for _ in 0..12 {
        let mut shuffled = case.edges.clone();
        rng.shuffle(&mut shuffled);
        // Transposing endpoints too: the edge list is undirected, so `(a, b)`
        // and `(b, a)` are the same edge and must produce the same labels.
        for edge in &mut shuffled {
            if rng.unit() < 0.5 {
                *edge = (edge.1, edge.0);
            }
        }

        let mut labels = Vec::new();
        components_into(case.node_count, &shuffled, &mut labels);
        assert_eq!(labels, reference, "edge order changed the labels");
    }
}

/// Oracle: construct-from-answer. With no edges every node is alone, so its
/// label is itself and the component count is the node count. This is the case
/// an implementation that never initialises its parent array silently gets
/// wrong, and the one an isolated node in a larger graph hides.
#[test]
fn an_empty_edge_list_leaves_every_node_in_its_own_component() {
    for node_count in [0u32, 1, 2, 37] {
        let mut labels = Vec::new();
        components_into(node_count, &[], &mut labels);

        let expected: Vec<ComponentLabel> = (0..node_count).map(ComponentLabel).collect();
        assert_eq!(labels, expected, "{node_count} isolated nodes");
        assert_eq!(component_count(&labels), node_count);
    }
}

/// Oracle: closed form. A path of `n` nodes is one component; `n` disjoint
/// pairs are `n` components; a star is one. Each answer is arithmetic on the
/// construction, so `component_count` is checked against a number the test
/// derived rather than against a rerun of the labelling.
#[test]
fn component_count_is_the_number_of_distinct_labels() {
    assert_eq!(component_count(&[]), 0, "no nodes, no components");

    // A path through every node, joined back to front so the edge list is not
    // in index order.
    let path: Vec<(u32, u32)> = (1..50u32).map(|n| (50 - n, 49 - n)).collect();
    let mut labels = Vec::new();
    components_into(50, &path, &mut labels);
    assert_eq!(component_count(&labels), 1);
    assert_eq!(labels, vec![ComponentLabel(0); 50], "a path is one net");

    // Twenty-five disjoint pairs. The label of each is its lower node.
    let pairs: Vec<(u32, u32)> = (0..25u32).map(|n| (2 * n + 1, 2 * n)).collect();
    components_into(50, &pairs, &mut labels);
    assert_eq!(component_count(&labels), 25);
    for n in 0..25u32 {
        assert_eq!(labels[(2 * n) as usize], ComponentLabel(2 * n));
        assert_eq!(labels[(2 * n + 1) as usize], ComponentLabel(2 * n));
    }

    // A star centred on the highest node: everything still labels to zero,
    // because the label is the minimum index and not the root the union-find
    // happened to choose.
    let star: Vec<(u32, u32)> = (0..49u32).map(|n| (49, n)).collect();
    components_into(50, &star, &mut labels);
    assert_eq!(component_count(&labels), 1);
    assert_eq!(labels, vec![ComponentLabel(0); 50]);
}

/// Oracle: law. Redundant edges are no-ops. Adding an edge inside a component
/// that is already connected cannot change a single label, whatever order the
/// redundant edges arrive in — which is the union-find's "both nodes already
/// found" path, and the one place a rank or path-halving bug shows up.
#[test]
fn redundant_edges_inside_a_component_change_nothing() {
    let mut rng = Rng::new(74);
    let sizes = [6u32, 1, 14, 3, 22];

    let sparse = graph_with_partition(&mut rng, &sizes, 0);
    let mut reference = Vec::new();
    components_into(sparse.node_count, &sparse.edges, &mut reference);
    assert_eq!(reference, sparse.expected, "a spanning forest, no cycles");

    let mut densest = 0usize;
    for extra in [1u32, 10, 200] {
        let dense = graph_with_partition(&mut Rng::new(74), &sizes, extra);
        let mut labels = Vec::new();
        components_into(dense.node_count, &dense.edges, &mut labels);
        assert_eq!(labels, reference, "{extra} redundant edges moved a label");
        densest = dense.edges.len();
    }
    assert!(
        densest > sparse.edges.len(),
        "the generator added no redundant edges, so nothing was exercised"
    );
}

/// Oracle: determinism. Two runs of the labelling on one graph must be
/// identical, and the output buffer is cleared and refilled rather than
/// appended to — which is what lets a caller hoist one buffer above a loop over
/// nets. Filling it with a wrong answer first is how that gets checked.
#[test]
fn two_runs_agree_and_the_output_buffer_is_refilled_not_appended_to() {
    let mut rng = Rng::new(75);
    let case = graph_with_partition(&mut rng, &[11, 2, 33, 1], 40);

    let mut labels = vec![ComponentLabel(u32::MAX); 500];
    components_into(case.node_count, &case.edges, &mut labels);
    assert_eq!(
        labels.len(),
        case.node_count as usize,
        "the buffer was not resized to the node count"
    );
    let first = labels.clone();

    components_into(case.node_count, &case.edges, &mut labels);
    assert_eq!(labels, first, "the labelling is not reproducible");
    assert_eq!(labels, case.expected);
}
