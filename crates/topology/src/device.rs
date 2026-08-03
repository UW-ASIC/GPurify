//! Device recognition and terminal binding.
//!
//! A device is recognised by a *marker polygon* — one polygon on the
//! recogniser's marker layer is exactly one device. That is the rule, and it is
//! stated here because the old tree deduplicated BJTs on the net tuple instead,
//! which silently merged two real devices wired identically.

use crate::net::{NetId, NetTable};
use gpurify_core::{GeometryStore, PolyId};
use gpurify_derived::Evaluator;
use gpurify_ingest::deck::{DeviceKind, DeviceRecognition};
use gpurify_ingest::StrId;
use gpurify_units::{Dbu, DbuArea};

/// Identifies one recognised device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DeviceId(pub u32);

/// Which terminal of a device a net is attached to.
///
/// Closed and per-family: a MOS gate and a BJT base are not the same thing, and
/// an enum that pretended otherwise would let a comparison match them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalRole {
    Gate,
    Source,
    Drain,
    Bulk,
    Base,
    Emitter,
    Collector,
    /// Either end of a symmetric two-terminal device. Interchangeable by
    /// definition, which the comparator must know.
    Pin(u8),
}

/// Every device recognised from the layout.
///
/// **Five questions.** In: geometry, derived layers, and the deck's
/// recognisers. Out: `SoA` device rows with CSR terminal ranges. How many:
/// thousands to millions. Access pattern: `lvs` walks terminals per device;
/// `erc` walks devices per net — hence the reverse index. Lifetime: whole run.
/// Parallelisable: recognition per marker polygon is independent; the ordering
/// pass at the end is what makes ids canonical.
#[derive(Debug, Default)]
pub struct DeviceTable {
    pub kind: Vec<DeviceKind>,
    /// The marker polygon that identifies this device. One device per marker
    /// polygon, always.
    pub marker: Vec<PolyId>,
    pub model: Vec<StrId>,
    /// Terminals, CSR into `terminal_net` / `terminal_role`.
    pub terminal_start: Vec<u32>,
    pub terminal_net: Vec<NetId>,
    pub terminal_role: Vec<TerminalRole>,
    /// Measured geometry, CSR into `param`. Width, length, area, perimeter —
    /// whatever the family's comparison needs.
    pub param_start: Vec<u32>,
    pub param: Vec<(DeviceParam, DeviceMeasure)>,

    /// Devices attached to each net, CSR. The reverse index `erc` scans.
    net_start: Vec<u32>,
    net_device: Vec<DeviceId>,
}

/// A measured device parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceParam {
    Width,
    Length,
    Area,
    Perimeter,
    Fingers,
}

/// The measurement itself, exact and in layout units.
///
/// Integer, not `f64`: these feed parametric comparison against a reference
/// netlist, where a tolerance is applied deliberately by the comparator rather
/// than accumulated accidentally by the extractor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceMeasure {
    Length(Dbu),
    Area(DbuArea),
    Count(u32),
}

impl DeviceTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
    pub fn terminals_of(&self, device: DeviceId) -> (&[NetId], &[TerminalRole]) {
        todo!()
    }
    pub fn params_of(&self, device: DeviceId) -> &[(DeviceParam, DeviceMeasure)] {
        todo!()
    }
    /// Devices attached to a net, ascending.
    ///
    /// The question `erc` asks constantly: is this net connected to anything,
    /// and if so what. A net with no devices is a floating net.
    pub fn devices_on(&self, net: NetId) -> &[DeviceId] {
        todo!()
    }
}

/// Recognise every device the deck describes.
///
/// **Transform, dispatcher.** One recogniser per device family, each producing
/// rows into the same table; the families are then run as separate uniform
/// passes rather than a per-polygon branch on kind.
///
/// Device ids are assigned by sorting on the marker polygon, so they are
/// canonical for a given layout.
pub fn recognise_into(
    store: &GeometryStore,
    derived: &Evaluator,
    nets: &NetTable,
    recognition: &DeviceRecognition,
    out: &mut DeviceTable,
) {
    todo!()
}
