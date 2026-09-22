//! The extracted parasitic network, as `SoA` node and element columns.

use gpurify_check::topology::NetId;
use gpurify_geom::LayerId;
use gpurify_geom::{prefix, Capacitance, Inductance, Qty, Resistance};

/// One parasitic element, at a fixed prefix per kind: ohms, femtofarads,
/// picohenries.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Parasitic {
    /// Series resistance between two nodes of one net.
    Resistance(Qty<Resistance, { prefix::BASE }>),
    /// Capacitance from a net to ground.
    GroundCap(Qty<Capacitance, { prefix::FEMTO }>),
    /// Capacitance between two different nets.
    CouplingCap(Qty<Capacitance, { prefix::FEMTO }>),
    /// Loop or partial inductance. Only the quasi-static path produces these.
    Inductance(Qty<Inductance, { prefix::PICO }>),
}

/// A node in the parasitic network: a net plus a position along it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct NodeId(pub u32);

/// The extracted network, as parallel node and element columns.
///
/// Invariant: every net's nodes occupy one contiguous range of `node_net`, in
/// ascending [`NetId`]. The `extract_into` entry points establish it; [`Self::push`]
/// does not check it.
#[derive(Debug, Default, PartialEq)]
pub struct ParasiticNetwork {
    pub node_net: Vec<NetId>,
    pub node_layer: Vec<LayerId>,
    /// One row per element. `to` is `None` for a ground capacitance.
    pub from: Vec<NodeId>,
    pub to: Vec<Option<NodeId>>,
    pub value: Vec<Parasitic>,
}

/// Canonical sort key: `from`, far node with ground first, element kind, value
/// bits. The value bits make the key total, so any permutation sorts to the same bytes.
type CanonicalKey = (u32, u64, u8, u64);

fn canonical_key(from: NodeId, to: Option<NodeId>, value: Parasitic) -> CanonicalKey {
    let (tag, raw) = match value {
        Parasitic::Resistance(q) => (0u8, q.raw()),
        Parasitic::GroundCap(q) => (1u8, q.raw()),
        Parasitic::CouplingCap(q) => (2u8, q.raw()),
        Parasitic::Inductance(q) => (3u8, q.raw()),
    };
    let far = to.map_or(0, |node| u64::from(node.0) + 1);
    (from.0, far, tag, raw.to_bits())
}

impl ParasiticNetwork {
    pub fn node_count(&self) -> usize {
        self.node_net.len()
    }

    pub fn element_count(&self) -> usize {
        self.from.len()
    }

    pub(crate) fn clear(&mut self) {
        self.node_net.clear();
        self.node_layer.clear();
        self.from.clear();
        self.to.clear();
        self.value.clear();
    }

    pub fn push(&mut self, from: NodeId, to: Option<NodeId>, value: Parasitic) {
        self.from.push(from);
        self.to.push(to);
        self.value.push(value);
    }

    /// Total capacitance on one net, ground plus coupling. See [`Self::capacitance_per_net`].
    pub fn net_capacitance(&self, net: NetId) -> Qty<Capacitance, { prefix::FEMTO }> {
        Qty::new(
            self.capacitance_per_net()
                .get(net.0 as usize)
                .copied()
                .unwrap_or(0.0),
        )
    }

    /// Every net's total capacitance in fF, indexed by `NetId`, in one pass.
    ///
    /// Each net's sum is a strict fold in element order, so the bits are fixed.
    /// An element whose node is past `node_net` counts onto no net.
    pub fn capacitance_per_net(&self) -> Vec<f64> {
        let nets = self
            .node_net
            .iter()
            .map(|n| n.0 as usize + 1)
            .max()
            .unwrap_or(0);
        let mut total = vec![0.0_f64; nets];
        let net_of = |node: NodeId| self.node_net.get(node.0 as usize).copied();
        for ((&from, &to), &value) in self.from.iter().zip(&self.to).zip(&self.value) {
            let ff = match value {
                Parasitic::GroundCap(q) | Parasitic::CouplingCap(q) => q.raw(),
                Parasitic::Resistance(_) | Parasitic::Inductance(_) => continue,
            };
            let near = net_of(from);
            let far = to.map_or(near, net_of);
            if let Some(net) = near {
                total[net.0 as usize] += ff;
            }
            if let Some(net) = far.filter(|&far| Some(far) != near) {
                total[net.0 as usize] += ff;
            }
        }
        total
    }

    /// Establish canonical element order (see [`CanonicalKey`]).
    pub fn sort_canonical(&mut self) {
        let mut rows: Vec<(CanonicalKey, NodeId, Option<NodeId>, Parasitic)> = (0..self.from.len())
            .map(|i| {
                let (from, to, value) = (self.from[i], self.to[i], self.value[i]);
                (canonical_key(from, to, value), from, to, value)
            })
            .collect();
        // Unstable is safe because the key is total. `sort_by` rather than
        // `_by_key` avoids copying the 32-byte key on every comparison.
        #[expect(
            clippy::unnecessary_sort_by,
            reason = "avoids copying the key per compare"
        )]
        rows.sort_unstable_by(|left, right| left.0.cmp(&right.0));

        self.from.clear();
        self.to.clear();
        self.value.clear();
        for (_, from, to, value) in rows {
            self.push(from, to, value);
        }
    }
}
