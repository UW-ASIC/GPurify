//! SPICE netlist export: the extracted circuit, optionally with its parasitics.
//!
//! The output of a whole run in the form a simulator can consume — extracted
//! devices from `topology`, and if asked, the parasitic R and C from `pex`
//! spliced into the nets between them.
//!
//! This is a *writer*, which is why it is here and not in `lvs`. In the old
//! tree it sat in `lvs` and dragged a `pex` dependency in behind it, so the
//! netlist comparator depended on parasitic extraction in order to write a file.

use crate::{Header, WriteError};
use gpurify_ingest::StrTable;
use gpurify_pex::ParasiticNetwork;
use gpurify_topology::{Extraction, PortTable};

/// What to include.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detail {
    /// Devices and their connectivity only. What LVS compares, and what a
    /// functional simulation needs.
    Schematic,
    /// Devices plus lumped per-net parasitic R and C. What a timing-accurate
    /// simulation needs.
    WithParasitics,
}

/// Write the extracted circuit as a SPICE subcircuit.
///
/// **Transform.** Caller owns `out`, appended to.
///
/// Devices are emitted in ascending `DeviceId`, which is canonical because
/// `topology` assigns ids by sorting on the marker polygon. Nets are named
/// through `ports` where they have a name and by their `NetId` where they do
/// not — and a `NetId` is canonical too, being the minimum polygon index in the
/// component. So the whole file is a function of the layout, with nothing
/// depending on the order anything was discovered in.
///
/// `parasitics` is `None` for [`Detail::Schematic`]. Passing a network and
/// asking for `Schematic` writes the schematic — the parameter is the source,
/// the mode is the decision, and they are separate so neither implies the other.
pub fn write_spice(
    extraction: Extraction<'_>,
    parasitics: Option<&ParasiticNetwork>,
    detail: Detail,
    strings: &StrTable,
    header: &Header,
    out: &mut String,
) -> Result<(), WriteError> {
    todo!()
}

/// The name of one net in the emitted netlist.
///
/// **Decision** — pure. Shared with the parasitic writers so a net has one name
/// across every file a run produces.
pub fn net_name(
    net: gpurify_topology::NetId,
    ports: &PortTable,
    strings: &StrTable,
    out: &mut String,
) {
    todo!()
}
