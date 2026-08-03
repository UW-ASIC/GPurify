//! The extracted parasitic network.
//!
//! Not a violation table — PEX does not have verdicts, it has values — so this
//! is its own type rather than a variant of `report`'s.

use gpurify_core::LayerId;
use gpurify_topology::NetId;
use gpurify_units::{prefix, Capacitance, Inductance, Qty, Resistance};

/// One parasitic element.
///
/// Fixed prefixes per kind, chosen so the numbers a report prints are readable
/// without a scale column: ohms, femtofarads, picohenries. Fixing them here
/// also means a whole column shares one scale, so two rows compare directly.
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

/// A node in the parasitic network.
///
/// A net is not one node: extraction splits it at every branch point, because a
/// long wire's resistance is not a single number. So a node is a net plus a
/// position along it, and the net's terminals are the nodes a simulator sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct NodeId(pub u32);

/// The extracted network.
///
/// **Five questions.** In: geometry, nets, and the deck's process stack. Out:
/// `SoA` node and element columns. How many: a few nodes per net for a
/// analytical run, thousands for a quasi-static one on a critical net. Access
/// pattern: written once by extraction, then walked in order by reduction and
/// by the writers — so element order is canonical and stated. Lifetime: whole
/// run. Parallelisable: per-net extraction is independent, and results are
/// concatenated in net order to keep the output deterministic.
#[derive(Debug, Default)]
pub struct ParasiticNetwork {
    /// Which net each node belongs to.
    pub node_net: Vec<NetId>,
    /// Which layer each node sits on. Needed by the writers and by coupling.
    pub node_layer: Vec<LayerId>,

    /// One row per element. `to` is `None` for a ground capacitance, which is
    /// the common case and does not deserve a sentinel node.
    pub from: Vec<NodeId>,
    pub to: Vec<Option<NodeId>>,
    pub value: Vec<Parasitic>,
}

impl ParasiticNetwork {
    pub fn node_count(&self) -> usize {
        todo!()
    }

    pub fn element_count(&self) -> usize {
        todo!()
    }

    pub fn push(&mut self, from: NodeId, to: Option<NodeId>, value: Parasitic) {
        todo!()
    }

    /// Total capacitance on one net, ground plus coupling.
    ///
    /// **Decision** — pure, and the number every timing tool asks for first.
    /// Summed in element order, which is canonical, so the result is
    /// bit-identical across runs. Summing in any other order would be a
    /// different `f64`.
    pub fn net_capacitance(&self, net: NetId) -> Qty<Capacitance, { prefix::FEMTO }> {
        todo!()
    }

    /// Establish canonical element order: by `from`, then `to` (`None` first),
    /// then element kind.
    ///
    /// Part of the interface. The determinism gate compares serialised output,
    /// and this is where that comparability is created.
    pub fn sort_canonical(&mut self) {
        todo!()
    }
}
