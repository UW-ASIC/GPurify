//! PEX node graph — topology-preserving parasitic RC(L) network.

use crate::geometry::{LayerId, PolyId};
use std::collections::HashMap;

/// Reference to an LVS device terminal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalRef {
    Gate(usize),
    Source(usize),
    Drain(usize),
    Body(usize),
    TwoTerminalA(usize),
    TwoTerminalB(usize),
    Port(String),
}

/// A node in the parasitic RC network.
#[derive(Clone, Debug)]
pub struct PexNode {
    pub id: u32,
    pub net_id: u32,
    pub layer: LayerId,
    pub poly: PolyId,
    pub segment: Option<u32>,
    pub x: i32,
    pub y: i32,
    pub terminal: Option<TerminalRef>,
    pub substrate_cap_af: f64,
}

/// Classification of a parasitic edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PexEdgeKind {
    Wire,
    Via,
    Contact,
}

/// An edge in the parasitic RC network.
#[derive(Clone, Debug)]
pub struct PexEdge {
    pub from: u32,
    pub to: u32,
    pub resistance_ohm: f64,
    pub kind: PexEdgeKind,
    pub layer: LayerId,
    pub inductance_nh: Option<f64>,
}

/// Complete parasitic RC(L) graph for one design.
#[derive(Clone, Debug, Default)]
pub struct PexGraph {
    pub nodes: Vec<PexNode>,
    pub edges: Vec<PexEdge>,
    /// Ground capacitance: (node_id, cap_af).
    pub ground_caps: Vec<(u32, f64)>,
    /// Coupling capacitance: (node_a, node_b, cap_af).
    pub coupling_caps: Vec<(u32, u32, f64)>,
    // ponytail: linear lookup by id; HashMap<u32, usize> index if node count exceeds ~10k
    node_index: HashMap<u32, usize>,
}

impl PexGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: PexNode) -> u32 {
        let id = node.id;
        let idx = self.nodes.len();
        self.node_index.insert(id, idx);
        self.nodes.push(node);
        id
    }

    pub fn add_edge(&mut self, edge: PexEdge) {
        self.edges.push(edge);
    }

    pub fn nodes_on_net(&self, net_id: u32) -> Vec<&PexNode> {
        self.nodes.iter().filter(|n| n.net_id == net_id).collect()
    }

    pub fn edges_from(&self, node_id: u32) -> Vec<&PexEdge> {
        self.edges
            .iter()
            .filter(|e| e.from == node_id || e.to == node_id)
            .collect()
    }

    /// Sum of all wire/via/contact resistances on edges belonging to a net.
    pub fn total_resistance_on_net(&self, net_id: u32) -> f64 {
        let net_nodes: std::collections::HashSet<u32> = self
            .nodes
            .iter()
            .filter(|n| n.net_id == net_id)
            .map(|n| n.id)
            .collect();
        self.edges
            .iter()
            .filter(|e| net_nodes.contains(&e.from) && net_nodes.contains(&e.to))
            .map(|e| e.resistance_ohm)
            .sum()
    }

    /// Total capacitance on a net: substrate caps of nodes + ground caps + coupling caps
    /// where at least one endpoint is on the net.
    pub fn total_cap_on_net(&self, net_id: u32) -> f64 {
        let net_nodes: std::collections::HashSet<u32> = self
            .nodes
            .iter()
            .filter(|n| n.net_id == net_id)
            .map(|n| n.id)
            .collect();
        let substrate: f64 = self
            .nodes
            .iter()
            .filter(|n| n.net_id == net_id)
            .map(|n| n.substrate_cap_af)
            .sum();
        let ground: f64 = self
            .ground_caps
            .iter()
            .filter(|(nid, _)| net_nodes.contains(nid))
            .map(|(_, c)| *c)
            .sum();
        let coupling: f64 = self
            .coupling_caps
            .iter()
            .filter(|(a, b, _)| net_nodes.contains(a) || net_nodes.contains(b))
            .map(|(_, _, c)| *c)
            .sum();
        substrate + ground + coupling
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(id: u32, net_id: u32) -> PexNode {
        PexNode {
            id,
            net_id,
            layer: 0,
            poly: PolyId(0),
            segment: None,
            x: (id * 100) as i32,
            y: 0,
            terminal: None,
            substrate_cap_af: 10.0,
        }
    }

    #[test]
    fn graph_queries() {
        let mut g = PexGraph::new();
        g.add_node(make_node(0, 1));
        g.add_node(make_node(1, 1));
        g.add_node(make_node(2, 2));

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
            kind: PexEdgeKind::Via,
            layer: 0,
            inductance_nh: None,
        });

        assert_eq!(g.nodes_on_net(1).len(), 2);
        assert_eq!(g.nodes_on_net(2).len(), 1);
        assert_eq!(g.edges_from(1).len(), 2);
        assert_eq!(g.edges_from(0).len(), 1);
        // Only the edge fully within net 1
        assert!((g.total_resistance_on_net(1) - 5.0).abs() < 1e-12);
        assert!((g.total_resistance_on_net(2) - 0.0).abs() < 1e-12);
        // Substrate cap: 2 nodes × 10 aF = 20 aF for net 1
        assert!((g.total_cap_on_net(1) - 20.0).abs() < 1e-12);

        g.ground_caps.push((0, 7.0));
        g.coupling_caps.push((0, 2, 4.0));
        assert!((g.total_cap_on_net(1) - 31.0).abs() < 1e-12); // 20 + 7 + 4
    }
}
