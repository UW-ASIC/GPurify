//! The one graph shape both sides are reduced to before matching.
//!
//! The layout side comes from `topology`, the reference side from `ingest`. If
//! the matcher saw two different shapes it would need two of everything, and
//! every asymmetry between the two paths would be a place a mismatch could hide.
//! So both are projected into the same bipartite device/net graph first, and
//! the matcher has exactly one input type.

use gpurify_ingest::netlist::{Netlist, SubcktId};
use gpurify_ingest::{StrId, StrTable};
use gpurify_ingest::deck::DeviceKind;
use gpurify_topology::{DeviceTable, NetTable, PortTable, TerminalRole};

/// A node in the bipartite graph.
///
/// Devices and nets are different kinds of thing and can never be paired with
/// each other, so the distinction is in the type rather than in a convention
/// about index ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Node {
    Device(u32),
    Net(u32),
}

/// A netlist reduced to what matching needs.
///
/// **Five questions.** In: either a `topology` extraction or an `ingest`
/// netlist. Out: `SoA` device and net columns with CSR incidence in both
/// directions. How many: thousands to millions of devices. Access pattern:
/// refinement walks every node's neighbours every round, so both directions are
/// CSR and neither is recomputed. Lifetime: one comparison. Parallelisable:
/// the per-round signature computation is; the partition merge is not.
#[derive(Debug, Default)]
pub struct Graph {
    pub device_kind: Vec<DeviceKind>,
    pub device_model: Vec<StrId>,
    /// Terminals of each device, CSR into `terminal_net` / `terminal_role`.
    pub device_terminal_start: Vec<u32>,
    pub terminal_net: Vec<u32>,
    pub terminal_role: Vec<TerminalRole>,
    /// Device parameters for parametric comparison, CSR into `param`.
    pub device_param_start: Vec<u32>,
    pub param: Vec<(StrId, f64)>,

    /// Devices attached to each net, CSR into `net_terminal`. The reverse
    /// incidence; refinement needs both directions every round.
    pub net_terminal_start: Vec<u32>,
    pub net_terminal: Vec<(u32, TerminalRole)>,
    /// Declared name, for nets that have one. `None` is the common case.
    pub net_name: Vec<Option<StrId>>,
    /// Nets that are ports of this cell. Matching is anchored on these, so
    /// they are held separately rather than found by scanning names.
    pub port_net: Vec<u32>,
}

impl Graph {
    pub fn device_count(&self) -> usize {
        todo!()
    }
    pub fn net_count(&self) -> usize {
        todo!()
    }
    pub fn terminals_of(&self, device: u32) -> (&[u32], &[TerminalRole]) {
        todo!()
    }
    pub fn terminals_on(&self, net: u32) -> &[(u32, TerminalRole)] {
        todo!()
    }
    pub fn params_of(&self, device: u32) -> &[(StrId, f64)] {
        todo!()
    }
}

/// The layout side. A newtype over [`Graph`] so the two sides cannot be
/// transposed at a call site — `compare(layout, reference)` and
/// `compare(reference, layout)` are different questions and the second is a
/// silently reversed report.
#[derive(Debug, Default)]
pub struct LayoutGraph(pub Graph);

/// The reference side.
#[derive(Debug, Default)]
pub struct RefGraph(pub Graph);

/// Project a `topology` extraction into the matching graph.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled.
pub fn from_layout_into(
    nets: &NetTable,
    devices: &DeviceTable,
    ports: &PortTable,
    out: &mut LayoutGraph,
) {
    todo!()
}

/// Project one subcircuit of a reference netlist into the matching graph.
///
/// One subcircuit, not the whole netlist: hierarchical comparison works cell by
/// cell, and flattening first would discard the structure it needs.
pub fn from_reference_into(
    netlist: &Netlist,
    subckt: SubcktId,
    strings: &StrTable,
    out: &mut RefGraph,
) {
    todo!()
}
