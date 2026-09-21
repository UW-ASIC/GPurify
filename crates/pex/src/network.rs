//! The extracted parasitic network.

use gpurify_core::LayerId;
use gpurify_topology::NetId;
use gpurify_units::{prefix, Capacitance, Inductance, Qty, Resistance};

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
/// Invariant: every node of one net occupies one contiguous range of
/// `node_net`, and the ranges run in ascending [`NetId`]. Established by the
/// two `extract_into` entry points and preserved by
/// [`reduce_into`](crate::reduce::reduce_into); [`Self::push`] does not enforce
/// it and [`Self::sort_canonical`] orders *elements* only, so a caller
/// assembling a network row by row owns it.
#[derive(Debug, Default, PartialEq)]
pub struct ParasiticNetwork {
    /// Which net each node belongs to. Grouped and ascending — see the type's
    /// doc comment.
    pub node_net: Vec<NetId>,
    /// Which layer each node sits on.
    pub node_layer: Vec<LayerId>,

    /// One row per element. `to` is `None` for a ground capacitance.
    pub from: Vec<NodeId>,
    pub to: Vec<Option<NodeId>>,
    pub value: Vec<Parasitic>,
}

/// Femtofarads on a capacitive element, zero on any other kind.
///
/// Zero rather than a skip: it lets a capacitance sum fold every element
/// unconditionally.
#[inline]
pub(crate) fn cap_ff(value: Parasitic) -> f64 {
    match value {
        Parasitic::GroundCap(q) | Parasitic::CouplingCap(q) => q.raw(),
        Parasitic::Resistance(_) | Parasitic::Inductance(_) => 0.0,
    }
}

/// The canonical sort key of one element row, in comparison order: `from`, the
/// far node with ground first, the element kind, the value's bits.
type CanonicalKey = (u32, u64, u8, u64);

/// One element row with its key already computed.
type KeyedRow = (CanonicalKey, NodeId, Option<NodeId>, Parasitic);

/// The canonical sort key of one element row.
///
/// The value bits make the key *total*: without that field two permutations of
/// the same multiset of rows could sort to different bytes. Bits and not a
/// float compare because `NaN` has no ordering.
fn canonical_key(from: NodeId, to: Option<NodeId>, value: Parasitic) -> CanonicalKey {
    let (tag, raw) = match value {
        Parasitic::Resistance(q) => (0u8, q.raw()),
        Parasitic::GroundCap(q) => (1u8, q.raw()),
        Parasitic::CouplingCap(q) => (2u8, q.raw()),
        Parasitic::Inductance(q) => (3u8, q.raw()),
    };
    // `None` is ground and sorts first, so a present node is shifted up by one.
    // `u64` because `NodeId(u32::MAX).0 + 1` does not fit a `u32`.
    let far = to.map_or(0, |node| u64::from(node.0) + 1);
    (from.0, far, tag, raw.to_bits())
}

impl ParasiticNetwork {
    pub fn node_count(&self) -> usize {
        debug_assert_eq!(
            self.node_net.len(),
            self.node_layer.len(),
            "the node columns must stay parallel"
        );
        self.node_net.len()
    }

    pub fn element_count(&self) -> usize {
        debug_assert_eq!(
            self.from.len(),
            self.to.len(),
            "the element columns must stay parallel"
        );
        debug_assert_eq!(
            self.from.len(),
            self.value.len(),
            "the element columns must stay parallel"
        );
        self.from.len()
    }

    /// Empty every column, keeping the capacity.
    pub(crate) fn clear(&mut self) {
        self.node_net.clear();
        self.node_layer.clear();
        self.from.clear();
        self.to.clear();
        self.value.clear();

        debug_assert_eq!(self.node_count(), 0, "a cleared network declares no node");
        debug_assert_eq!(
            self.element_count(),
            0,
            "a cleared network holds no element"
        );
    }

    pub fn push(&mut self, from: NodeId, to: Option<NodeId>, value: Parasitic) {
        let before = self.element_count();
        let nodes = self.node_count();

        self.from.push(from);
        self.to.push(to);
        self.value.push(value);

        debug_assert_eq!(self.element_count(), before + 1);
        debug_assert_eq!(self.node_count(), nodes, "a push does not create a node");
    }

    /// Total capacitance on one net, ground plus coupling.
    ///
    /// Summed in canonical element order, so the result is bit-identical across
    /// runs; any other order is a different `f64`.
    pub fn net_capacitance(&self, net: NetId) -> Qty<Capacitance, { prefix::FEMTO }> {
        let elements = self.element_count();
        let nodes = &self.node_net[..];

        // Fail closed on columns that drifted apart: the trip count below is
        // taken from `from` alone.
        debug_assert_eq!(self.from.len(), self.to.len(), "SoA columns must agree");
        debug_assert_eq!(self.from.len(), self.value.len(), "SoA columns must agree");
        let n = self.from.len();
        let (froms, tos, values) = (&self.from[..n], &self.to[..n], &self.value[..n]);

        // Ascending index order is interface, not implementation: it is what
        // makes this sum bit-identical, so it must not be reassociated into
        // lane accumulators.
        let mut total = 0.0f64;
        for i in 0..n {
            let (from, to, value) = (froms[i], tos[i], values[i]);
            // A ground capacitance has no far node; folding `from` in twice
            // leaves the `|` below unchanged.
            let far = to.unwrap_or(from);
            // Fail closed on a node id past the end of the column: an element
            // whose net cannot be resolved is counted onto no net rather than
            // onto every one.
            let touches = (nodes.get(from.0 as usize) == Some(&net))
                | (nodes.get(far.0 as usize) == Some(&net));
            total += cap_ff(value) * f64::from(u8::from(touches));
        }

        debug_assert_eq!(self.element_count(), elements, "a decision mutates nothing");
        debug_assert!(
            total.is_finite(),
            "net {} summed to {total} fF, which no report can carry",
            net.0
        );
        Qty::new(total)
    }

    /// Establish canonical element order: by `from`, then `to` (`None` first),
    /// then element kind.
    pub fn sort_canonical(&mut self) {
        let elements = self.element_count();
        let nodes = self.node_count();

        // Zip to AoS, sort, scatter back: three parallel columns written from
        // the same row at the same index cannot fall out of step.
        debug_assert_eq!(self.from.len(), self.to.len(), "SoA columns must agree");
        debug_assert_eq!(self.from.len(), self.value.len(), "SoA columns must agree");
        let mut rows: Vec<KeyedRow> = Vec::with_capacity(elements);
        for i in 0..elements {
            let (from, to, value) = (self.from[i], self.to[i], self.value[i]);
            rows.push((canonical_key(from, to, value), from, to, value));
        }
        debug_assert_eq!(rows.len(), elements, "zipping the columns dropped a row");

        // Unstable is safe *because* `canonical_key` is total: two rows with
        // equal keys are equal in every field, so their relative order is
        // unobservable.
        #[expect(
            clippy::unnecessary_sort_by,
            reason = "`sort_unstable_by_key(|r| r.0)` yields the identical total order — \
                      tuple `Ord` is the same lexicographic compare — but its extractor is \
                      called on every side of every comparison, so it copies the 32-byte \
                      `CanonicalKey` O(n log n) times. Not making that copy is the only \
                      reason the decoration above exists"
        )]
        rows.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        #[cfg(debug_assertions)]
        {
            let mut previous = CanonicalKey::default();
            let mut ascending = true;
            for row in &rows {
                ascending &= previous <= row.0;
                previous = row.0;
            }
            debug_assert!(
                ascending,
                "the keyed rows must come out of the sort ascending"
            );
        }

        self.from.clear();
        self.to.clear();
        self.value.clear();
        self.from.reserve(rows.len());
        self.to.reserve(rows.len());
        self.value.reserve(rows.len());
        for &(_, from, to, value) in &rows {
            self.from.push(from);
            self.to.push(to);
            self.value.push(value);
        }

        debug_assert_eq!(
            self.element_count(),
            elements,
            "a sort neither invents nor drops a row"
        );
        debug_assert_eq!(self.node_count(), nodes, "a sort does not touch the nodes");
    }
}
