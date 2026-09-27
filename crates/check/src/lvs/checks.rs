//! LVS rows for the report: the layout-only checks, which need no reference
//! netlist, and the mapping of a comparison's discrepancies to violations.
//!
//! Data in: the extracted tables and the unreduced layout graph. Data out: eight
//! run rows and their violations. Deck-limited checks record `Skipped`.

use crate::lvs::graph::{narrow, Graph};
use crate::lvs::verdict::Discrepancy;
use crate::report::{
    record_run, Measurement, Outcome, RuleRun, Severity, SkipReason, Violation, Violations,
};
use crate::topology::{DeviceTable, NetId, NetTable, PortTable};
use gpurify_geom::ops::Point;
use gpurify_geom::Dbu;
use gpurify_geom::{LayerId, PolyId};
use gpurify_ingest::{StrId, StrTable};

/// Every rule id LVS reports under, in interning order: one per [`Discrepancy`]
/// variant, then the eight check rows.
const RULE_IDS: [&str; 14] = [
    "lvs.unpaired_device",
    "lvs.unpaired_net",
    "lvs.terminal_mismatch",
    "lvs.parameter_mismatch",
    "lvs.undeclared_param",
    "lvs.class_imbalance",
    "lvs.floating_net",
    "lvs.label_conflict",
    "lvs.net_seed_conflict",
    "lvs.device_count_mos",
    "lvs.device_count_bjt",
    "lvs.parametric",
    "lvs.terminal_net",
    "lvs.terminal_count",
];

/// Intern every LVS rule id; the report looks them up in a table it only borrows.
pub fn intern_rule_ids(strings: &mut StrTable) {
    for name in RULE_IDS {
        strings.intern(name);
    }
}

/// An id [`intern_rule_ids`] missed is `u32::MAX`, which `resolve` panics on
/// rather than misattributing the row.
fn rule_id(strings: &StrTable, name: &str) -> StrId {
    strings.get(name).unwrap_or(StrId(u32::MAX))
}

/// An LVS finding has no layer, place or shape: past-the-end sentinels.
const NOWHERE: Point = Point {
    x: Dbu::new_unchecked(0),
    y: Dbu::new_unchecked(0),
};
const NO_LAYER: LayerId = LayerId(u16::MAX);
const NO_SHAPE: PolyId = PolyId(u32::MAX);

/// Run the layout-only checks on the unreduced layout graph.
pub fn check_layout(
    layout: &Graph,
    nets: &NetTable,
    devices: &DeviceTable,
    ports: &PortTable,
    strings: &StrTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let id = |name| rule_id(strings, name);
    check_floating_nets(nets, devices, ports, id("lvs.floating_net"), out, runs);
    check_label_conflicts(nets, ports, id("lvs.label_conflict"), out, runs);
    check_net_seed_conflicts(nets, ports, id("lvs.net_seed_conflict"), out, runs);
    // Device counts and parameter ranges need limits the deck does not carry.
    let before = out.len();
    for name in [
        "lvs.device_count_mos",
        "lvs.device_count_bjt",
        "lvs.parametric",
    ] {
        let skipped = Outcome::Skipped(SkipReason::NotInDeck);
        record_run(runs, out, before, id(name), skipped, 0);
    }
    check_topology(
        layout,
        (id("lvs.terminal_net"), id("lvs.terminal_count")),
        out,
        runs,
    );
}

/// One error row per discrepancy, which is how a mismatch fails the run.
pub fn record_discrepancies(found: &[Discrepancy], strings: &StrTable, out: &mut Violations) {
    for discrepancy in found {
        let (name, measured, limit) = match *discrepancy {
            Discrepancy::UnpairedDevice { .. } => ("lvs.unpaired_device", 1, 0),
            Discrepancy::UnpairedNet { .. } => ("lvs.unpaired_net", 1, 0),
            Discrepancy::TerminalMismatch { .. } => ("lvs.terminal_mismatch", 1, 0),
            Discrepancy::ParameterMismatch { .. } => ("lvs.parameter_mismatch", 1, 0),
            Discrepancy::UndeclaredParam { .. } => ("lvs.undeclared_param", 1, 0),
            Discrepancy::ClassImbalance {
                layout_nodes,
                ref_nodes,
            } => ("lvs.class_imbalance", layout_nodes, ref_nodes),
        };
        let mut row = graph_violation(rule_id(strings, name), (NO_SHAPE, None), measured, limit);
        // Both values, when they are finite; a non-finite one reports as the rest do.
        if let Discrepancy::ParameterMismatch {
            layout_value,
            ref_value,
            ..
        } = *discrepancy
        {
            if layout_value.is_finite() && ref_value.is_finite() {
                row.measured = Measurement::Ratio(layout_value);
                row.limit = Measurement::Ratio(ref_value);
            }
        }
        out.push(row);
    }
}

/// Legal terminal counts per device kind, as a bitmask indexed by count. Rows past
/// `Diode` admit nothing, so an unknown kind fails closed.
const LEGAL_WIDTHS: [u32; 8] = [
    (1 << 3) | (1 << 4), // Mos: gate, source, drain, and optionally bulk
    1 << 3,              // Bjt
    1 << 2,              // Resistor
    1 << 2,              // Capacitor
    1 << 2,              // Diode
    0,
    0,
    0,
];

/// The full terminal count each kind is reported against.
const FULL_WIDTHS: [u32; 8] = [4, 3, 2, 2, 2, 0, 0, 0];

fn graph_violation(
    rule: StrId,
    shapes: (PolyId, Option<PolyId>),
    measured: u32,
    limit: u32,
) -> Violation {
    Violation {
        rule,
        layer: NO_LAYER,
        severity: Severity::Error,
        at: NOWHERE,
        shapes,
        measured: Measurement::Count(measured),
        limit: Measurement::Count(limit),
    }
}

/// Nets with no device terminal on them; a named (port) net is not floating.
/// Panics when a device terminal names a net past `nets`.
fn check_floating_nets(
    nets: &NetTable,
    devices: &DeviceTable,
    ports: &PortTable,
    rule: StrId,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let before = out.len();
    let net_count = narrow(nets.net_count());

    // Net `n` holds its lowest polygon while still a candidate, `NO_SHAPE` once
    // ruled out.
    let mut lowest: Vec<PolyId> = (0..net_count)
        .map(|row| {
            let net = NetId(row);
            let named = u32::from(ports.name_of(net).is_some()).wrapping_neg();
            PolyId(first_poly(nets, net).0 | named)
        })
        .collect();
    for &net in &devices.terminal_net {
        lowest[net.idx()] = NO_SHAPE;
    }

    for &poly in lowest.iter().filter(|&&poly| poly != NO_SHAPE) {
        out.push(graph_violation(rule, (poly, None), 0, 1));
    }
    record_run(runs, out, before, rule, Outcome::Ran, u64::from(net_count));
}

/// One label resolving to two nets. Reported rather than resolved.
fn check_label_conflicts(
    nets: &NetTable,
    ports: &PortTable,
    rule: StrId,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let before = out.len();
    let net_count = narrow(nets.net_count());

    let mut named: Vec<(StrId, NetId)> = (0..net_count)
        .filter_map(|row| ports.name_of(NetId(row)).map(|name| (name, NetId(row))))
        .collect();
    named.sort_unstable();

    for pair in named.windows(2).filter(|pair| pair[0].0 == pair[1].0) {
        let shapes = (
            first_poly(nets, pair[0].1),
            Some(first_poly(nets, pair[1].1)),
        );
        out.push(graph_violation(rule, shapes, 2, 1));
    }
    record_run(runs, out, before, rule, Outcome::Ran, u64::from(net_count));
}

/// Fewer distinct named nets than labels: two seeds merged onto one net.
fn check_net_seed_conflicts(
    nets: &NetTable,
    ports: &PortTable,
    rule: StrId,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let before = out.len();
    let seeds = narrow(ports.len());
    let resolved = narrow(
        (0..narrow(nets.net_count()))
            .filter(|&row| ports.name_of(NetId(row)).is_some())
            .count(),
    );
    if resolved < seeds {
        out.push(graph_violation(rule, (NO_SHAPE, None), resolved, seeds));
    }
    record_run(runs, out, before, rule, Outcome::Ran, u64::from(seeds));
}

/// Structural sanity of the extracted graph: a terminal on no net, a device with
/// the wrong terminal count for its kind. A graph with devices but no terminal
/// CSR is `Refused` rather than reported clean.
fn check_topology(
    graph: &Graph,
    (terminal_net, terminal_count): (StrId, StrId),
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let devices = graph.device_kind.len();
    let net_count = narrow(graph.net_name.len());

    // `NetId::NONE` is `u32::MAX`, so "no net" and "past the table" are one test;
    // the limit saturates so it never wraps to zero.
    let before = out.len();
    for &net in graph.terminal_net.iter().filter(|&&net| net >= net_count) {
        out.push(graph_violation(
            terminal_net,
            (NO_SHAPE, None),
            net_count,
            net.saturating_add(1),
        ));
    }
    record_run(
        runs,
        out,
        before,
        terminal_net,
        Outcome::Ran,
        graph.terminal_net.len() as u64,
    );

    let before = out.len();
    let width: Vec<u32> = graph
        .device_terminal_start
        .windows(2)
        .map(|pair| pair[1] - pair[0])
        .collect();
    if width.len() != devices {
        record_run(runs, out, before, terminal_count, Outcome::Refused, 0);
        return;
    }
    for (&kind, &count) in graph.device_kind.iter().zip(&width) {
        // A count past 31 clamps onto bit 31, which no kind sets.
        if (LEGAL_WIDTHS[(kind as usize) & 7] >> count.min(31)) & 1 == 0 {
            out.push(graph_violation(
                terminal_count,
                (NO_SHAPE, None),
                count,
                FULL_WIDTHS[(kind as usize) & 7],
            ));
        }
    }
    record_run(
        runs,
        out,
        before,
        terminal_count,
        Outcome::Ran,
        devices as u64,
    );
}

/// The lowest polygon of a net, or [`NO_SHAPE`] for a net carrying none.
fn first_poly(nets: &NetTable, net: NetId) -> PolyId {
    nets.polys_of(net).first().copied().unwrap_or(NO_SHAPE)
}
