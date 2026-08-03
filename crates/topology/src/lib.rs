//! Electrical structure derived from geometry: nets, devices, terminals, ports.
//!
//! Every domain needs this and none of them owns it. In the old tree it lived
//! inside `lvs`, which is why `drc` and `erc` both depended on the netlist
//! comparator in order to ask what touched what.
//!
//! `topology` knows nothing about comparison, violations or parasitics. It
//! answers three questions and stops: which shapes are the same net, which
//! shapes form a device, and which net is each device terminal on.

// Definition-Phase; see CLAUDE.md
#![allow(unused_variables, dead_code)]

pub mod device;
pub mod net;
pub mod port;

pub use device::{DeviceId, DeviceTable, TerminalRole};
pub use net::{extract_nets_into, NetId, NetTable};
pub use port::{bind_ports_into, PortTable};
