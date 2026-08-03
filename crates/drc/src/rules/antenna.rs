//! Antenna family: charge collected during etch, referred to the gate it would
//! damage.
//!
//! The only DRC rules that need electrical structure. Everything else in this
//! crate is geometry; these two ask *what is connected to what*, because the
//! quantity being limited is the ratio of conductor area collecting plasma
//! charge to the gate-oxide area that has to absorb it.
//!
//! # Gates come from `topology`, not from a bounding-box scan
//!
//! The old tree found gates by intersecting the `poly` and `diff` bounding
//! boxes of every polygon pair on those two layers, keyed the result in a
//! `HashMap<u32, i64>`, and reported the violation at whichever polygon the
//! map's iteration reached first. Three defects in one: bounding boxes
//! over-report a non-convex gate, the map's iteration order made the reported
//! coordinate differ between runs, and hard-coding the layer names `poly` and
//! `diff` made the rule silently do nothing on a deck that names them anything
//! else.
//!
//! Here a gate is a recognised MOS device from
//! [`DeviceTable`](gpurify_topology::DeviceTable): its area is the measured
//! `DeviceParam::Area`, and its net is the terminal with
//! [`TerminalRole::Gate`](gpurify_topology::TerminalRole::Gate). Exact,
//! canonical, and it works on whatever the deck calls its layers.
//!
//! # CAR is per fabrication stage, and that is the whole rule
//!
//! At the moment metal *k* is etched, only layers up to *k* exist. A wire that
//! will eventually be tied to a huge upper-level plane is, at that instant,
//! just itself. So the cumulative check is not one measurement over the final
//! stack — it is one measurement per stage, over connectivity rebuilt from the
//! layers present at that stage, and the verdict is the worst of them.
//! Measuring the final stack instead misses exactly the failure the rule is
//! for: a long lower-level collector that is only rescued later by a via to a
//! protected node.

use crate::{Design, Scratch};
use gpurify_core::LayerId;
use gpurify_ingest::StrId;
use gpurify_report::{RuleRun, Violations};

/// Single-layer antenna ratio: collecting area on one layer over gate area.
#[derive(Debug, Default)]
pub struct AntennaTable {
    pub rule: Vec<StrId>,
    /// The collecting layer.
    pub layer: Vec<LayerId>,
    /// Maximum `collector_area / gate_area`. Dimensionless, hence `f64` — a
    /// ratio of two quantities of the same dimension, which is the case
    /// `Qty::div` exists for.
    pub ratio: Vec<f64>,
    /// A protection diode layer, if the process has one. A shape on it
    /// connected to the gate's net leaks the accumulated charge to substrate
    /// before the oxide breaks down, so the gate is waived entirely.
    ///
    /// `Option` rather than a sentinel layer id: absence is a real state here
    /// and it changes the computation rather than skipping a row, which is the
    /// distinction the existence-based rule draws. Rows number in the tens.
    pub diode: Vec<Option<LayerId>>,
}

/// Cumulative antenna ratio, evaluated once per fabrication stage.
#[derive(Debug, Default)]
pub struct AntennaCarTable {
    pub rule: Vec<StrId>,
    /// The metal stack in fabrication order, CSR:
    /// `stack[stack_start[i] .. stack_start[i] + stack_len[i]]` is row `i`'s.
    /// Order is the rule — `stack[k]` is what is being etched at stage `k` and
    /// `stack[..=k]` is what exists — so a deck listing them out of order gets
    /// a different and wrong answer. Reversing this list is the silent-wrong
    /// -answer risk of this table.
    pub stack_start: Vec<u32>,
    pub stack_len: Vec<u32>,
    pub stack: Vec<LayerId>,
    pub ratio: Vec<f64>,
    pub diode: Vec<Option<LayerId>>,
}

impl AntennaTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl AntennaCarTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }

    /// The stack one row names, in fabrication order.
    pub fn stack_of(&self, row: usize) -> &[LayerId] {
        todo!()
    }
}

/// Gate area per net, for every MOS gate in the design.
///
/// **Transform, A-to-B.** Caller owns both buffers, cleared and refilled to the
/// same length: `net[i]` has gate area `area[i]`, ascending by net and with no
/// net repeated. Two columns rather than a map, so the result is canonically
/// ordered and a lookup is a binary search — which is what made the old
/// version's reported coordinates differ between runs of the same binary.
///
/// Shared by both antenna rules, and separately testable: a netlist with known
/// device geometry in, a known area column out.
pub fn gate_areas_into(
    design: Design<'_>,
    net: &mut Vec<gpurify_topology::NetId>,
    area: &mut Vec<gpurify_units::DbuArea>,
) {
    todo!()
}

/// Check every single-layer antenna rule.
///
/// **Transform.** For each gate: the collecting area is the total area of the
/// rule's layer on the gate's net; the ratio is that over the gate's own area;
/// a diode shape on the same net waives it. One violation per offending gate,
/// reported at the gate's marker polygon so the coordinate is the transistor,
/// not whichever wire happened to be found first.
///
/// `examined` counts gates. A design with no recognised MOS devices records
/// `Outcome::Skipped(SkipReason::EmptyLayer)` — no gates means the ratio has no
/// denominator, and reporting that as clean would pass a deck whose device
/// recognisers never matched.
pub fn check_antenna(
    design: Design<'_>,
    table: &AntennaTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every cumulative antenna rule.
///
/// One pass per stage `k`: rebuild connectivity over the gate layers, the metal
/// layers `stack[..=k]`, the diode layer, and every via whose *both* endpoints
/// already exist — a via to a layer not yet deposited does not conduct. Then
/// accumulate the area of `stack[..=k]` on each gate's net and take the worst
/// ratio any stage produced.
///
/// Diffusion is deliberately not a conductor in this graph: poly over diff is a
/// gate, which is the thing being protected, not a path the charge escapes
/// through. Relief is explicit, via the diode layer.
///
/// One violation per offending gate, at its marker polygon, reporting the worst
/// stage's ratio. `examined` counts gate-stage pairs — gates times stages —
/// because a rule that ran three of five stages and a rule that ran all five
/// must not report the same number.
pub fn check_antenna_car(
    design: Design<'_>,
    table: &AntennaCarTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}
