//! Standalone checks that need no reference netlist.
//!
//! These are the LVS findings that come from the layout alone — a floating net,
//! two labels on one net, a device count that cannot be right. They run before
//! comparison, because each of them makes a comparison meaningless, and a
//! mismatch caused by a label conflict is a confusing way to learn about the
//! label conflict.
//!
//! Same table-plus-transform shape as the DRC and ERC rules, and they report
//! into the same [`Violations`] table.

use crate::graph::LayoutGraph;
use gpurify_report::{RuleRun, Violations};
use gpurify_topology::{DeviceTable, NetTable, PortTable};

/// Nets with no device terminal on them.
///
/// **Transform.** A net carrying geometry but no device is either dead metal or
/// a missing connection, and both are worth reporting. A net that is *only* a
/// port is not floating — it connects to something outside this cell — which is
/// why this needs the port table and not just the net table.
pub fn check_floating_nets(
    nets: &NetTable,
    devices: &DeviceTable,
    ports: &PortTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Two different labels resolving to one net, or one label to two nets.
///
/// Reported rather than resolved: choosing a winner produces a comparison that
/// is confidently wrong about which net is which.
pub fn check_label_conflicts(
    nets: &NetTable,
    ports: &PortTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Net seeds that disagree — two labelled shapes that extraction merged into
/// one net when the labels say they should be distinct.
///
/// Distinct from a label conflict: this is a connectivity finding wearing a
/// naming symptom, and the fix is in the layout, not the labels.
pub fn check_net_seed_conflicts(
    nets: &NetTable,
    ports: &PortTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Device counts by family, against what the deck says is possible.
///
/// **Transform.** Separate MOS and BJT passes rather than one loop with a kind
/// branch, because the two families have different validity conditions — the
/// dispatcher pattern at its smallest.
pub fn check_device_counts(
    devices: &DeviceTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Devices whose measured parameters fall outside the deck's declared range for
/// their model.
///
/// A layout-only check: it needs no schematic, only the model's stated limits.
/// A device outside them will not simulate as intended regardless of whether
/// LVS matches.
pub fn check_parametric(
    devices: &DeviceTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Structural sanity of the extracted graph itself — a terminal on no net, a
/// device with the wrong terminal count for its family.
///
/// These indicate an extraction bug rather than a layout bug, and they are
/// checked because an extraction bug that reaches the comparator produces a
/// mismatch report blaming the layout.
pub fn check_topology(
    layout: &LayoutGraph,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}
