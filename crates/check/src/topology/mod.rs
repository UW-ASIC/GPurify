//! Electrical structure derived from geometry: nets, devices, terminals, ports.
//!
//! Extraction runs in four steps, each reading what the one before built:
//!
//! 1. [`device::refuse_conducting_channels`] refuses a deck whose MOS channel
//!    marker overlaps conductor on its own source/drain layer, which would
//!    fuse source and drain into one net;
//! 2. [`extract_nets_into`] builds the [`NetTable`] from the deck's
//!    `connect` statements;
//! 3. [`device::recognise_into`] builds the [`DeviceTable`] from its `device`
//!    statements, binding each terminal to a net;
//! 4. [`bind_ports_into`] attaches the layout's text labels to nets, as the
//!    [`PortTable`].
//!
//! The deck syntax is in
//! [deck.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/deck.md)
//! ("Connectivity" and "Devices"). Every table is owned by the caller and
//! refilled in place, so a second extraction reuses the allocations. Ids are
//! dense rows numbered by geometry alone: the same layout gives the same ids
//! on every run.

pub mod device;
pub mod net;
pub mod port;

pub use device::{ChannelError, DeviceId, DeviceTable, TerminalRole};
pub use net::{extract_nets_into, NetId, NetTable};
pub use port::{bind_ports_into, PortTable};

/// One row's run in a CSR offset column; a row past the table panics.
pub(crate) fn csr_run(start: &[u32], row: usize) -> (usize, usize) {
    (start[row] as usize, start[row + 1] as usize)
}

/// The three extracted tables, borrowed together.
///
/// All three must come from one extraction: `devices` and `ports` hold net
/// ids of `nets`, which index nothing meaningful in another table.
#[derive(Debug, Clone, Copy)]
pub struct Extraction<'a> {
    /// The nets.
    pub nets: &'a NetTable,
    /// The devices, recognised against `nets`.
    pub devices: &'a DeviceTable,
    /// The port labels, bound to `nets`.
    pub ports: &'a PortTable,
}
