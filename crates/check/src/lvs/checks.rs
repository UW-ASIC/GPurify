//! Standalone LVS checks that need no reference netlist.
//!
//! Data in: the extracted tables and the unreduced layout graph. Data out: eight
//! run rows and their violations, filed under sentinel rule ids counted down from
//! `u32::MAX` (the engine renames them). Deck-limited checks record `Skipped`.

use crate::lvs::graph::{narrow, LayoutGraph};
use crate::report::{
    record_run, Measurement, Outcome, RuleRun, Severity, SkipReason, Violation, Violations,
};
use crate::topology::{DeviceTable, NetId, NetTable, PortTable};
use gpurify_geom::ops::Point;
use gpurify_geom::Dbu;
use gpurify_geom::{LayerId, PolyId};
use gpurify_ingest::StrId;

const FLOATING_NET: StrId = StrId(u32::MAX);
const LABEL_CONFLICT: StrId = StrId(u32::MAX - 1);
const NET_SEED_CONFLICT: StrId = StrId(u32::MAX - 2);
const DEVICE_COUNT_MOS: StrId = StrId(u32::MAX - 3);
const DEVICE_COUNT_BJT: StrId = StrId(u32::MAX - 4);
const PARAMETRIC: StrId = StrId(u32::MAX - 5);
const TERMINAL_NET: StrId = StrId(u32::MAX - 6);
const TERMINAL_COUNT: StrId = StrId(u32::MAX - 7);

const NOWHERE: Point = Point {
    x: Dbu::new_unchecked(0),
    y: Dbu::new_unchecked(0),
};
const NO_LAYER: LayerId = LayerId(u16::MAX);
const NO_SHAPE: PolyId = PolyId(u32::MAX);

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
pub fn check_floating_nets(
    nets: &NetTable,
    devices: &DeviceTable,
    ports: &PortTable,
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
        out.push(graph_violation(FLOATING_NET, (poly, None), 0, 1));
    }
    record_run(
        runs,
        out,
        before,
        FLOATING_NET,
        Outcome::Ran,
        u64::from(net_count),
    );
}

/// One label resolving to two nets. Reported rather than resolved.
pub fn check_label_conflicts(
    nets: &NetTable,
    ports: &PortTable,
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
        out.push(graph_violation(LABEL_CONFLICT, shapes, 2, 1));
    }
    record_run(
        runs,
        out,
        before,
        LABEL_CONFLICT,
        Outcome::Ran,
        u64::from(net_count),
    );
}

/// Fewer distinct named nets than labels: two seeds merged onto one net.
pub fn check_net_seed_conflicts(
    nets: &NetTable,
    ports: &PortTable,
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
        out.push(graph_violation(
            NET_SEED_CONFLICT,
            (NO_SHAPE, None),
            resolved,
            seeds,
        ));
    }
    record_run(
        runs,
        out,
        before,
        NET_SEED_CONFLICT,
        Outcome::Ran,
        u64::from(seeds),
    );
}

/// Device counts by family: the limit lives in a deck this signature lacks, so
/// both rows are recorded as skipped.
pub fn check_device_counts(_devices: &DeviceTable, out: &mut Violations, runs: &mut Vec<RuleRun>) {
    let before = out.len();
    let unconfigured = Outcome::Skipped(SkipReason::NotInDeck);
    record_run(runs, out, before, DEVICE_COUNT_MOS, unconfigured, 0);
    record_run(runs, out, before, DEVICE_COUNT_BJT, unconfigured, 0);
}

/// Measured parameters against the deck's model ranges: skipped, as above.
pub fn check_parametric(_devices: &DeviceTable, out: &mut Violations, runs: &mut Vec<RuleRun>) {
    let before = out.len();
    record_run(
        runs,
        out,
        before,
        PARAMETRIC,
        Outcome::Skipped(SkipReason::NotInDeck),
        0,
    );
}

/// Structural sanity of the extracted graph: a terminal on no net, a device with
/// the wrong terminal count for its kind. A graph with devices but no terminal
/// CSR is `Refused` rather than reported clean.
pub fn check_topology(layout: &LayoutGraph, out: &mut Violations, runs: &mut Vec<RuleRun>) {
    let graph = &layout.0;
    let devices = graph.device_kind.len();
    let net_count = narrow(graph.net_name.len());

    // `NetId::NONE` is `u32::MAX`, so "no net" and "past the table" are one test;
    // the limit saturates so it never wraps to zero.
    let before = out.len();
    for &net in graph.terminal_net.iter().filter(|&&net| net >= net_count) {
        out.push(graph_violation(
            TERMINAL_NET,
            (NO_SHAPE, None),
            net_count,
            net.saturating_add(1),
        ));
    }
    record_run(
        runs,
        out,
        before,
        TERMINAL_NET,
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
        record_run(runs, out, before, TERMINAL_COUNT, Outcome::Refused, 0);
        return;
    }
    for (&kind, &count) in graph.device_kind.iter().zip(&width) {
        // A count past 31 clamps onto bit 31, which no kind sets.
        if (LEGAL_WIDTHS[(kind as usize) & 7] >> count.min(31)) & 1 == 0 {
            out.push(graph_violation(
                TERMINAL_COUNT,
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
        TERMINAL_COUNT,
        Outcome::Ran,
        devices as u64,
    );
}

/// The lowest polygon of a net, or [`NO_SHAPE`] for a net carrying none.
fn first_poly(nets: &NetTable, net: NetId) -> PolyId {
    nets.polys_of(net).first().copied().unwrap_or(NO_SHAPE)
}
