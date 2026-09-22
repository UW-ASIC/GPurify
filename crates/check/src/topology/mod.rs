//! Electrical structure derived from geometry: nets, devices, terminals, ports.

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
#[derive(Debug, Clone, Copy)]
pub struct Extraction<'a> {
    pub nets: &'a NetTable,
    pub devices: &'a DeviceTable,
    pub ports: &'a PortTable,
}
