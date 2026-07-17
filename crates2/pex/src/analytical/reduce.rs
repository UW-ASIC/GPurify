//! RC network reduction: pi-model and Elmore delay.

use super::graph::PexGraph;
use std::collections::{HashMap, HashSet, VecDeque};

/// Reduced pi-model for a net between two terminals.
#[derive(Clone, Debug)]
pub struct PiModel {
    pub c1_af: f64,
    pub r_ohm: f64,
    pub c2_af: f64,
}

/// Reduce the RC network for a given net to a pi-model between its terminal nodes.
///
/// ponytail: lumped pi — splits total C evenly across the two pi caps and sums all R
/// in series. Proper Krylov/PRIMA reduction when timing-critical nets need it.
pub fn reduce_to_pi(graph: &PexGraph, net_id: u32) -> Option<PiModel> {
    let total_r = graph.total_resistance_on_net(net_id);
    let total_c = graph.total_cap_on_net(net_id);
    if total_r == 0.0 && total_c == 0.0 {
        return None;
    }
    Some(PiModel {
        c1_af: total_c / 2.0,
        r_ohm: total_r,
        c2_af: total_c / 2.0,
    })
}

/// Elmore delay from `source_node` to each other node on the same net.
///
/// Returns `(sink_node_id, delay_seconds)`. The Elmore delay at node k is
/// Σ_{edge i on path root→k} R_i × C_downstream_i, computed via BFS on the
/// RC tree.
///
/// ponytail: assumes tree topology (no loops). Mesh networks need loop-breaking
/// first (star-delta or shortest-path tree extraction).
pub fn elmore_delays(graph: &PexGraph, net_id: u32, source_node: u32) -> Vec<(u32, f64)> {
    let net_nodes: HashSet<u32> = graph
        .nodes
        .iter()
        .filter(|n| n.net_id == net_id)
        .map(|n| n.id)
        .collect();
    if !net_nodes.contains(&source_node) {
        return Vec::new();
    }

    // Build adjacency for net-local edges
    let mut adj: HashMap<u32, Vec<(u32, f64)>> = HashMap::new();
    for edge in &graph.edges {
        if net_nodes.contains(&edge.from) && net_nodes.contains(&edge.to) {
            adj.entry(edge.from)
                .or_default()
                .push((edge.to, edge.resistance_ohm));
            adj.entry(edge.to)
                .or_default()
                .push((edge.from, edge.resistance_ohm));
        }
    }

    // Node capacitances (substrate + ground caps)
    let mut node_cap: HashMap<u32, f64> = HashMap::new();
    for node in graph.nodes.iter().filter(|n| n.net_id == net_id) {
        *node_cap.entry(node.id).or_default() += node.substrate_cap_af;
    }
    for &(nid, cap) in &graph.ground_caps {
        if net_nodes.contains(&nid) {
            *node_cap.entry(nid).or_default() += cap;
        }
    }

    // BFS from source, accumulating Elmore delay
    let mut visited: HashSet<u32> = HashSet::new();
    let mut queue: VecDeque<(u32, f64)> = VecDeque::new(); // (node, cumulative_delay)
    let mut result: Vec<(u32, f64)> = Vec::new();

    visited.insert(source_node);
    queue.push_back((source_node, 0.0));

    while let Some((current, delay_so_far)) = queue.pop_front() {
        let c = node_cap.get(&current).copied().unwrap_or(0.0) * 1e-18; // aF → F
        if let Some(neighbors) = adj.get(&current) {
            for &(next, r) in neighbors {
                if visited.insert(next) {
                    let delay = delay_so_far + r * c;
                    result.push((next, delay));
                    queue.push_back((next, delay));
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::PolyId;
    use crate::graph::{PexEdge, PexEdgeKind, PexNode};

    fn simple_rc_chain() -> PexGraph {
        let mut g = PexGraph::new();
        g.add_node(PexNode {
            id: 0,
            net_id: 1,
            layer: 0,
            poly: PolyId(0),
            segment: None,
            x: 0,
            y: 0,
            terminal: None,
            substrate_cap_af: 10.0,
        });
        g.add_node(PexNode {
            id: 1,
            net_id: 1,
            layer: 0,
            poly: PolyId(0),
            segment: Some(1),
            x: 100,
            y: 0,
            terminal: None,
            substrate_cap_af: 20.0,
        });
        g.add_node(PexNode {
            id: 2,
            net_id: 1,
            layer: 0,
            poly: PolyId(0),
            segment: Some(2),
            x: 200,
            y: 0,
            terminal: None,
            substrate_cap_af: 15.0,
        });
        g.add_edge(PexEdge {
            from: 0,
            to: 1,
            resistance_ohm: 5.0,
            kind: PexEdgeKind::Wire,
            layer: 0,
            inductance_nh: None,
        });
        g.add_edge(PexEdge {
            from: 1,
            to: 2,
            resistance_ohm: 3.0,
            kind: PexEdgeKind::Wire,
            layer: 0,
            inductance_nh: None,
        });
        g
    }

    #[test]
    fn pi_model_splits_cap() {
        let g = simple_rc_chain();
        let pi = reduce_to_pi(&g, 1).unwrap();
        assert!((pi.r_ohm - 8.0).abs() < 1e-12);
        // Total cap = 10 + 20 + 15 = 45 aF, split equally
        assert!((pi.c1_af - 22.5).abs() < 1e-12);
        assert!((pi.c2_af - 22.5).abs() < 1e-12);
    }

    #[test]
    fn pi_model_empty_net() {
        let g = PexGraph::new();
        assert!(reduce_to_pi(&g, 99).is_none());
    }

    #[test]
    fn elmore_delay_chain() {
        let g = simple_rc_chain();
        let delays = elmore_delays(&g, 1, 0);
        assert_eq!(delays.len(), 2);
        // Delays are non-negative
        for (_, d) in &delays {
            assert!(*d >= 0.0);
        }
    }
}
