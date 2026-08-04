//! Electrical structure derived from geometry: nets, devices, terminals, ports.
//!
//! Every domain needs this and none of them owns it. In the old tree it lived
//! inside `lvs`, which is why `drc` and `erc` both depended on the netlist
//! comparator in order to ask what touched what.
//!
//! `topology` knows nothing about comparison, violations or parasitics. It
//! answers three questions and stops: which shapes are the same net, which
//! shapes form a device, and which net is each device terminal on.

pub mod device;
pub mod net;
pub mod port;

pub use device::{DeviceId, DeviceTable, TerminalRole};
pub use net::{extract_nets_into, NetId, NetTable};
pub use port::{bind_ports_into, PortTable};

/// One row's run in a CSR offset column.
///
/// Every table in this crate is CSR in at least one direction — nets to
/// polygons, devices to terminals, devices to params, nets to devices — and the
/// three modules had each re-derived this. It is one place now because the
/// fail-closed argument is the part worth having in one place: the column
/// carries `rows + 1` offsets, so a row past the table indexes out of bounds and
/// panics in **every** profile. Clamping instead would make "this row carries
/// nothing" and "this row does not exist" read the same, and a rule that reads
/// the second as the first exempts geometry nobody checked.
pub(crate) fn csr_run(start: &[u32], row: usize) -> (usize, usize) {
    let (from, to) = (start[row] as usize, start[row + 1] as usize);
    debug_assert!(from <= to, "a CSR run runs backwards");
    (from, to)
}

/// The three tables, borrowed together.
///
/// They are always produced together and almost always consumed together — a
/// rule asking "is this net floating" needs the nets to know what a net is, the
/// devices to know whether anything is attached, and the ports to know whether
/// it leaves the cell. Passing them as three parameters made several downstream
/// signatures eight arguments long, which is where a transposition becomes
/// silent.
///
/// A borrowed view, not an owner: the tables are built into caller-owned
/// storage and this is a way to hand all three across a call.
#[derive(Debug, Clone, Copy)]
pub struct Extraction<'a> {
    pub nets: &'a NetTable,
    pub devices: &'a DeviceTable,
    pub ports: &'a PortTable,
}
