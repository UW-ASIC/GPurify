//! LVS rows for the report: the layout-only checks, which need no reference
//! netlist, and the mapping of a comparison's discrepancies to violations.
//!
//! Data in: the extracted tables and the unreduced layout graph. Data out: eight
//! run rows and their violations. Deck-limited checks record `Skipped`.

use crate::erc::first_vertex;
use crate::lvs::graph::{narrow, Graph};
use crate::lvs::verdict::Discrepancy;
use crate::report::{record_run, Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use crate::topology::{DeviceTable, NetId, NetTable, PortTable};
use crate::Design;
use gpurify_geom::ops::Point;
use gpurify_geom::Dbu;
use gpurify_geom::{LayerId, PolyId};
use gpurify_ingest::{StrId, StrTable};

/// Every rule id LVS reports under, in interning order: one per [`Discrepancy`]
/// variant, then the five check rows. Each is a row of the check catalog
/// (`docs/check-catalog.tsv`), which a test keeps in step with this list.
///
/// The first six are defined on the [`Discrepancy`] variant that raises them
/// (`lvs.unpaired_device` is [`Discrepancy::UnpairedDevice`], and so on), the
/// other five under [`check_layout`]. The crate's
/// [rule reference](crate#layout-against-schematic) maps each to its
/// [catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv)
/// rows.
pub const RULE_IDS: [&str; 11] = [
    "lvs.unpaired_device",
    "lvs.unpaired_net",
    "lvs.terminal_mismatch",
    "lvs.parameter_mismatch",
    "lvs.undeclared_param",
    "lvs.class_imbalance",
    "lvs.floating_net",
    "lvs.label_conflict",
    "lvs.net_seed_conflict",
    "lvs.terminal_net",
    "lvs.terminal_count",
];

/// Intern every LVS rule id; the report looks them up in a table it only borrows.
///
/// Call it on the run's table before [`check_layout`] or
/// [`record_discrepancies`] writes a row: a row written before carries
/// `StrId(u32::MAX)`, which `StrTable::resolve` panics on when the report is
/// printed. Interning twice is harmless.
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
///
/// `layout` must be [`from_layout`](crate::lvs::graph::from_layout) of the
/// same `design` and `ports`. Records exactly five [`RuleRun`]s, in the order
/// below, and appends their violations to `out`. Every violation is an error.
/// Unless a row says otherwise, it has no layer and no location (both are
/// sentinels), and its shape is `PolyId(u32::MAX)`.
///
/// # Rows
///
/// - `lvs.floating_net`: a net that no device terminal lands on, other than a
///   net with a port label or one made only of global-layer shapes (the
///   substrate). Shape: the net's lowest polygon. Measured 0 against a limit
///   of 1 terminal. Examines every net. Catalog: LVS-006.
/// - `lvs.label_conflict`: one label text on several nets. That is an open,
///   since a label never joins shapes by itself. One row per pair of
///   consecutive such nets in net order, so a label on `n` nets gives
///   `n - 1` rows. Shapes: each net's lowest polygon. Measured 2 against a
///   limit of 1. Examines every net. Catalog: LVS-001, LVS-002 (KLayout's
///   `connect_implicit` would join them instead).
/// - `lvs.net_seed_conflict`: several label texts on one net, a short between
///   named nets. One row per pair of consecutive names on the net in
///   [`StrId`] order, so `n` names give `n - 1` rows. Shapes: the lowest
///   polygon carrying each of the two names, so the two labels are found
///   from the row; the location is the first vertex of the first, on its
///   layer. No path between the two labels is traced (catalog LVS-005).
///   Measured 2 against a limit of 1. Examines every binding of a name to a
///   net. Catalog: LVS-001.
/// - `lvs.terminal_net`: a terminal of `layout` on no net, or on a net past
///   its net table. Measured the net count against the count the terminal
///   would need. Examines every terminal. Catalog: LVS-004.
/// - `lvs.terminal_count`: a device whose terminal count its kind does not
///   allow: MOS 3 or 4 (bulk optional), BJT 3, resistor, capacitor and diode
///   2. The deck does not fix a recogniser's layer count, so this is where a
///   wrong one shows. Measured the count against the kind's full count.
///   Examines every device, or records [`Outcome::Refused`] when
///   `device_terminal_start` does not hold one run per device. Catalog:
///   LVS-004.
///
/// # Limits
///
/// - `lvs.terminal_net` cannot fire on a graph built by `from_layout`:
///   [`recognise_into`] drops any marker with a terminal on no net.
/// - Per-model device counts and parameter ranges are not checked: the deck
///   has no syntax for their limits (catalog LVS-068). No row is recorded for
///   them, because no deck configures them; a row that could only ever be
///   `Skipped` would fail every run that selects LVS.
///
/// # Panics
///
/// Panics if a device terminal names a net past `design.nets`, or a port
/// binding a polygon past `design.store`.
///
/// [`recognise_into`]: crate::topology::device::recognise_into
pub fn check_layout(
    layout: &Graph,
    design: Design<'_>,
    ports: &PortTable,
    strings: &StrTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let id = |name| rule_id(strings, name);
    let (nets, devices) = (design.nets, design.devices);
    check_floating_nets(nets, devices, ports, id("lvs.floating_net"), out, runs);
    check_label_conflicts(nets, ports, id("lvs.label_conflict"), out, runs);
    check_net_seed_conflicts(design, ports, strings, out, runs);
    check_topology(
        layout,
        (id("lvs.terminal_net"), id("lvs.terminal_count")),
        out,
        runs,
    );
}

/// One error row per discrepancy, which is how a mismatch fails the run.
///
/// Each row reports under its variant's id in [`RULE_IDS`], with no layer,
/// location or shape. Measured and limit are 1 against 0, except
/// `lvs.class_imbalance` (the layout's node count against the reference's)
/// and `lvs.parameter_mismatch` (the layout value against the reference
/// value, when both are finite). Records no [`RuleRun`]: the comparison is
/// accounted for by its verdict, not per id.
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

/// Nets with no device terminal on them; a named (port) net is not floating,
/// nor is the substrate alone (a global-layer net: always there, it floats
/// only in the model). Panics when a device terminal names a net past `nets`.
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
            let named =
                u32::from(ports.name_of(net).is_some() || nets.is_global_only(net)).wrapping_neg();
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

    // Every binding, so a name a short hides behind another is still seen.
    let (names, named) = ports.bindings_by_name();
    for at in 1..names.len() {
        if names[at] == names[at - 1] {
            let shapes = (
                first_poly(nets, named[at - 1]),
                Some(first_poly(nets, named[at])),
            );
            out.push(graph_violation(rule, shapes, 2, 1));
        }
    }
    record_run(runs, out, before, rule, Outcome::Ran, u64::from(net_count));
}

/// The `lvs.net_seed_conflict` row of [`check_layout`] alone: one
/// [`RuleRun`], and a violation per pair of names on one net, as described
/// there.
///
/// For a run that reports labelled shorts without LVS's other layout rows:
/// the `gpurify` engine calls it when [`check_layout`] does not run and a
/// net carries two names, so a short between named nets fails every run.
///
/// # Panics
///
/// Panics if a port binds a polygon past `design.store`.
pub fn check_net_seed_conflicts(
    design: Design<'_>,
    ports: &PortTable,
    strings: &StrTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rule = rule_id(strings, "lvs.net_seed_conflict");
    let before = out.len();
    let (nets, _, polys) = ports.bindings();
    for at in 1..nets.len() {
        if nets[at] == nets[at - 1] {
            let (first, second) = (polys[at - 1], polys[at]);
            out.push(Violation {
                layer: design.store.poly_layer(first),
                at: first_vertex(design.store, first),
                ..graph_violation(rule, (first, Some(second)), 2, 1)
            });
        }
    }
    record_run(runs, out, before, rule, Outcome::Ran, ports.len() as u64);
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
