//! SPEF and DSPF: the parasitic network, for a timing tool or a simulator.
//!
//! These two writers are the ones with history. The old implementation's
//! interlayer-capacitance rows carried their layer pair in whichever order a
//! `HashMap` happened to yield, so **8 of 27 parasitic outputs differed between
//! runs of the same binary on the same input**. The magnitudes were right; the
//! file was not reproducible, which means it could not be diffed and a
//! regression in it could not be seen.
//!
//! The fix is upstream — `ParasiticNetwork` is `SoA` and canonically ordered —
//! and the job here is to not undo it.

use crate::{Header, WriteError};
use gpurify_ingest::StrTable;
use gpurify_pex::ParasiticNetwork;
use gpurify_topology::PortTable;

/// SPEF.
///
/// Names are emitted through the port table, and every net a SPEF references
/// must have one — an anonymous net is [`WriteError::UnnamedNet`], not a
/// generated placeholder, because a placeholder is a name that changes between
/// runs.
pub fn write_spef(
    network: &ParasiticNetwork,
    ports: &PortTable,
    strings: &StrTable,
    header: &Header,
    out: &mut String,
) -> Result<(), WriteError> {
    todo!()
}

/// DSPF.
///
/// A flat SPICE-like form. Sub-node names are derived from the node's index
/// within its net, which is canonical, rather than from allocation order, which
/// is not.
pub fn write_dspf(
    network: &ParasiticNetwork,
    ports: &PortTable,
    strings: &StrTable,
    header: &Header,
    out: &mut String,
) -> Result<(), WriteError> {
    todo!()
}

/// The name of one parasitic node.
///
/// **Decision** — pure, and shared by both writers so the two formats agree
/// about what a node is called. Two writers naming the same node differently is
/// the kind of thing nobody notices until two tools disagree.
pub fn node_name(
    network: &ParasiticNetwork,
    node: gpurify_pex::network::NodeId,
    ports: &PortTable,
    strings: &StrTable,
    out: &mut String,
) -> Result<(), WriteError> {
    todo!()
}
