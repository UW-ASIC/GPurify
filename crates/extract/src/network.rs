//! The extracted parasitic network, as `SoA` node and element columns.
//!
//! Both extraction methods write a [`ParasiticNetwork`], and the SPEF, DSPF and
//! SPICE writers read one. A [`NodeId`] is a row of the node columns, so it
//! means something only inside the network that issued it.

use gpurify_check::topology::NetId;
use gpurify_geom::LayerId;
use gpurify_geom::{prefix, Capacitance, Inductance, Qty, Resistance};

/// One parasitic element, at a fixed prefix per kind: ohms, femtofarads,
/// picohenries.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Parasitic {
    /// Series resistance between two nodes of one net.
    Resistance(Qty<Resistance, { prefix::BASE }>),
    /// Capacitance from a net to ground, the substrate: an area and fringe
    /// term for the closed forms, a grounded plane at height 0 for a field
    /// solve.
    GroundCap(Qty<Capacitance, { prefix::FEMTO }>),
    /// Capacitance between two different nets.
    CouplingCap(Qty<Capacitance, { prefix::FEMTO }>),
    /// Series inductance of a field-solved net, between its two nodes. Only
    /// the quasistatic path produces these.
    Inductance(Qty<Inductance, { prefix::PICO }>),
    /// Mutual inductance between two field-solved nets' series inductances.
    /// Its near node is the first net's, its far node the second's: each the
    /// near node of that net's [`Parasitic::Inductance`], which is the end
    /// its port current enters. Signed: positive when currents entering both
    /// near nodes reinforce each other's flux, the SPICE dot convention with
    /// each inductance's near node dotted. Only the quasistatic path
    /// produces these
    /// ([`InductMatrix::m_henry`](crate::field::henry::InductMatrix::m_henry)).
    MutualInductance(Qty<Inductance, { prefix::PICO }>),
}

/// A node in the parasitic network: a net plus a position along it.
///
/// The value is a row of [`ParasiticNetwork::node_net`]. Writers name it
/// `net:index`, where `index` counts from the first node of its net.
/// [`quasistatic::extract_inductance_into`](crate::quasistatic::extract_inductance_into)
/// and [`quasistatic::overlay`](crate::quasistatic::overlay) renumber nodes, so
/// a `NodeId` read before either call is stale after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct NodeId(pub u32);

/// The extracted network, as parallel node and element columns.
///
/// Invariant: every net's nodes occupy one contiguous range of `node_net`, in
/// ascending [`NetId`], and the elements are in canonical order
/// ([`Self::sort_canonical`]). The `extract_into` entry points establish both.
/// [`Self::push`] checks neither, and the SPEF and DSPF writers refuse a
/// network that breaks them.
///
/// The closed forms give a net of `n` conductor regions (its merged shapes,
/// one per connected piece on a layer) `n + 1` nodes. A field solve
/// gives each solved net one node, or two once its inductance is solved.
///
/// # Examples
///
/// ```
/// use gpurify_check::topology::NetId;
/// use gpurify_extract::network::NodeId;
/// use gpurify_extract::{Parasitic, ParasiticNetwork};
/// use gpurify_geom::{LayerId, Qty};
///
/// // Net 0 has nodes 0 and 1, net 1 has node 2.
/// let mut network = ParasiticNetwork::default();
/// network.node_net = vec![NetId(0), NetId(0), NetId(1)];
/// network.node_layer = vec![LayerId(3); 3];
/// network.push(NodeId(0), Some(NodeId(2)), Parasitic::CouplingCap(Qty::new(0.5)));
/// network.push(NodeId(0), Some(NodeId(1)), Parasitic::Resistance(Qty::new(12.0)));
/// network.push(NodeId(0), None, Parasitic::GroundCap(Qty::new(2.0)));
/// network.sort_canonical();
///
/// // Ground first, then by far node.
/// assert_eq!(network.to, [None, Some(NodeId(1)), Some(NodeId(2))]);
/// // A coupling capacitance counts on both of its nets, in fF.
/// assert_eq!(network.capacitance_per_net(), [2.5, 0.5]);
/// ```
#[derive(Debug, Default, PartialEq)]
pub struct ParasiticNetwork {
    /// The net of each node, indexed by [`NodeId`].
    pub node_net: Vec<NetId>,
    /// The layer of each node, indexed by [`NodeId`]. It stands in for a
    /// position the network does not carry: the layer of the polygon an
    /// analytical node starts, or a field-solved net's lowest layer.
    pub node_layer: Vec<LayerId>,
    /// One row per element: its near node.
    pub from: Vec<NodeId>,
    /// Each element's far node, or `None` for ground. Only a
    /// [`Parasitic::GroundCap`] may have `None`.
    pub to: Vec<Option<NodeId>>,
    /// Each element's kind and magnitude.
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
        Parasitic::MutualInductance(q) => (4u8, q.raw()),
    };
    let far = to.map_or(0, |node| u64::from(node.0) + 1);
    (from.0, far, tag, raw.to_bits())
}

impl ParasiticNetwork {
    /// Returns the number of nodes, the length of the node columns.
    pub fn node_count(&self) -> usize {
        self.node_net.len()
    }

    /// Returns the number of elements, the length of the element columns.
    pub fn element_count(&self) -> usize {
        self.from.len()
    }

    /// Debug check of the type's invariant, where the `extract_into` entry
    /// points establish it: parallel columns, each net's nodes one ascending
    /// run, every element's nodes in range, only a ground capacitance to
    /// ground, canonical order, and every value finite (a `NaN` compares
    /// false against every limit and every writer).
    pub(crate) fn debug_check(&self) {
        if !cfg!(debug_assertions) {
            return;
        }
        let nodes = self.node_count();
        debug_assert_eq!(self.node_layer.len(), nodes, "one layer per node");
        debug_assert!(
            self.to.len() == self.from.len() && self.value.len() == self.from.len(),
            "one far node and one value per element"
        );
        debug_assert!(
            self.node_net.windows(2).all(|w| w[0] <= w[1]),
            "each net's nodes are one run, nets ascending"
        );
        debug_assert!(
            (0..self.element_count()).all(|row| {
                let near = (self.from[row].0 as usize) < nodes;
                let far = match self.to[row] {
                    Some(node) => (node.0 as usize) < nodes,
                    None => matches!(self.value[row], Parasitic::GroundCap(_)),
                };
                near && far
            }),
            "every element's nodes exist, and only a ground capacitance has no far node"
        );
        debug_assert!(
            (1..self.element_count()).all(|row| {
                let key = |at: usize| canonical_key(self.from[at], self.to[at], self.value[at]);
                key(row - 1) <= key(row)
            }),
            "the elements are in canonical order"
        );
        debug_assert!(
            self.value.iter().all(|value| match *value {
                Parasitic::Resistance(q) => q.is_finite(),
                Parasitic::GroundCap(q) | Parasitic::CouplingCap(q) => q.is_finite(),
                Parasitic::Inductance(q) => q.is_finite(),
            }),
            "every element's value is finite"
        );
    }

    pub(crate) fn clear(&mut self) {
        self.node_net.clear();
        self.node_layer.clear();
        self.from.clear();
        self.to.clear();
        self.value.clear();
    }

    /// Appends one element.
    ///
    /// Nothing is checked: the nodes need not exist yet, and canonical order
    /// is lost until [`Self::sort_canonical`] runs again.
    pub fn push(&mut self, from: NodeId, to: Option<NodeId>, value: Parasitic) {
        self.from.push(from);
        self.to.push(to);
        self.value.push(value);
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
                Parasitic::Resistance(_)
                | Parasitic::Inductance(_)
                | Parasitic::MutualInductance(_) => continue,
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

    /// Sorts the elements into canonical order: by `from`, then far node with
    /// ground first, then kind (R, ground C, coupling C, L, mutual L), then
    /// the value's bits.
    ///
    /// The key is total, so any permutation of the same elements sorts to the
    /// same columns. The node columns are not touched. Takes *O*(e log e) time
    /// and a scratch buffer of e rows.
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
