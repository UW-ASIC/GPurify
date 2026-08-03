//! Reference-netlist readers: SPICE/CDL and Spectre.
//!
//! These are parsers, and parsers belong here — they have nothing in common
//! with the subgraph matching in `lvs` beyond both involving netlists. Both
//! dialects produce the same [`Netlist`], so `lvs` sees one shape.
//!
//! # Declared subset
//!
//! Neither reader guesses. Each implements a stated subset and errors on
//! anything outside it, with the source line, because a reference netlist
//! silently misparsed produces an LVS mismatch that looks like a layout bug and
//! costs a day.

use crate::intern::StrId;

/// Where a token came from, for an error a human can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSpan {
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum NetlistError {
    #[error("line {}: unexpected token {1}", .0.line)]
    Unexpected(SourceSpan, String),
    #[error("line {}: {1} is not in the supported subset", .0.line)]
    Unsupported(SourceSpan, String),
    #[error("line {}: subcircuit {1} is called but never defined", .0.line)]
    UndefinedSubckt(SourceSpan, String),
    #[error("line {}: {1} is defined twice", .0.line)]
    Redefined(SourceSpan, String),
    #[error("line {}: device {1} has {2} terminals, expected {3}", .0.line)]
    TerminalCount(SourceSpan, String, u32, u32),
    #[error("io: {0}")]
    Io(String),
}

/// Identifies a subcircuit definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SubcktId(pub u32);

/// Identifies a net within one subcircuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RefNetId(pub u32);

/// Identifies a device instance within one subcircuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RefDeviceId(pub u32);

/// A parsed reference netlist, hierarchy preserved.
///
/// Hierarchy is kept rather than flattened, because hierarchical LVS compares
/// cell by cell and flattening first would throw away the structure it needs.
/// Flattening, where a run wants it, is a separate explicit step.
///
/// **Five questions.** In: text. Out: `SoA` tables of subcircuits, nets and
/// device instances. How many: thousands of devices for a block, millions for a
/// full chip. Access pattern: `lvs` walks devices per subcircuit and terminals
/// per device, so both are CSR ranges. Lifetime: whole run. Parallelisable:
/// per-subcircuit comparison is independent.
#[derive(Debug, Default)]
pub struct Netlist {
    /// One row per subcircuit definition.
    pub subckt_name: Vec<StrId>,
    /// Ports, as a CSR range into `port_net`.
    pub subckt_port_start: Vec<u32>,
    pub port_net: Vec<RefNetId>,
    /// Devices belonging to each subcircuit, CSR into the device columns.
    pub subckt_device_start: Vec<u32>,

    /// One row per device instance.
    pub device_name: Vec<StrId>,
    pub device_model: Vec<StrId>,
    pub device_kind: Vec<crate::deck::DeviceKind>,
    /// Terminals, CSR into `terminal_net`.
    pub device_terminal_start: Vec<u32>,
    pub terminal_net: Vec<RefNetId>,
    /// Parameters, CSR into `param`.
    pub device_param_start: Vec<u32>,
    /// Interned name and value. Values stay `f64` in the netlist's own units;
    /// `lvs` attaches dimensions when it compares.
    pub param: Vec<(StrId, f64)>,

    /// One row per net.
    pub net_name: Vec<StrId>,
    pub net_subckt: Vec<SubcktId>,
}

impl Netlist {
    pub fn subckt_count(&self) -> usize {
        todo!()
    }
    pub fn devices_of(&self, subckt: SubcktId) -> std::ops::Range<u32> {
        todo!()
    }
    pub fn terminals_of(&self, device: RefDeviceId) -> &[RefNetId] {
        todo!()
    }
    pub fn params_of(&self, device: RefDeviceId) -> &[(StrId, f64)] {
        todo!()
    }
    /// The top-level subcircuit — the one nothing else instantiates.
    ///
    /// `None` when there is no unique top, which is an ambiguity `lvs` must
    /// refuse rather than resolve by guessing.
    pub fn top(&self) -> Option<SubcktId> {
        todo!()
    }
}

/// SPICE and CDL.
///
/// Card keywords are a fixed compile-time vocabulary, so dispatch is a `match`
/// on the leading token rather than a map lookup.
pub mod spice {
    use super::{Netlist, NetlistError};
    use crate::intern::StrTable;

    pub fn read(source: &str, strings: &mut StrTable) -> Result<Netlist, NetlistError> {
        todo!()
    }
}

/// Spectre.
///
/// A different surface syntax over the same model, so it produces the same
/// [`Netlist`] and everything downstream is unchanged.
///
/// ponytail: declared subset — no `inline subckt`, no `alter`, no sweeps.
/// Anything outside it is `NetlistError::Unsupported` with the line. Widen when
/// a real netlist needs it, not before.
pub mod spectre {
    use super::{Netlist, NetlistError};
    use crate::intern::StrTable;

    pub fn read(source: &str, strings: &mut StrTable) -> Result<Netlist, NetlistError> {
        todo!()
    }
}
