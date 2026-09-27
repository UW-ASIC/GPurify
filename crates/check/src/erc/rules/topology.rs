//! Rules that ask only what is connected to what.
//!
//! Data in: nets, devices, [`NetFacts`]. Data out: violations and one run per
//! row. Nothing here re-derives connectivity.

use crate::drc::rules::{owners_of, LayerRects, SortedRects};
use crate::erc::facts::{NetFacts, RoleMask};
use crate::erc::ruleset::RuleHead;
use crate::erc::{first_vertex, push_net_violations, record_run, Design, Scratch};
use crate::report::{Measurement, Outcome, RuleRun, Violation, Violations};
use crate::topology::{DeviceId, NetId, PortTable, TerminalRole};
use gpurify_geom::boolean::union_into;
use gpurify_geom::rects::{clipped_area, covered_area, decompose_into};
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::DbuArea;
use gpurify_geom::{LayerId, PolyId};

/// A gate net with nothing driving it: its role mask is exactly
/// [`RoleMask::GATE`].
#[derive(Debug, Default)]
pub struct FloatingGateTable {
    pub head: RuleHead,
    /// Per row: a labelled net is a port, driven from outside the cell. Off by
    /// default, since a layout may label internal nets too.
    pub labels_are_ports: Vec<bool>,
}

/// A well with no tap tying it to a supply.
#[derive(Debug, Default)]
pub struct FloatingWellTable {
    pub head: RuleHead,
    pub well: Vec<LayerId>,
    pub tap: Vec<LayerId>,
}

/// A net driven by more than `max_drivers` distinct gate nets (a parallel pair
/// sharing a gate is one driver).
#[derive(Debug, Default)]
pub struct MultipleDriversTable {
    pub head: RuleHead,
    pub max_drivers: Vec<u32>,
}

/// A conductor on a net no device terminal touches.
#[derive(Debug, Default)]
pub struct UnconnectedPinTable {
    pub head: RuleHead,
    /// `layer[layer_start[i] .. layer_start[i + 1]]` are row `i`'s layers.
    pub layer_start: Vec<u32>,
    pub layer: Vec<LayerId>,
}

/// Flag every net whose only terminals are gates, skipping labelled nets on a
/// row that treats labels as ports. `examined` counts nets carrying a gate
/// terminal.
pub fn check_floating_gate(
    design: Design<'_>,
    facts: &NetFacts,
    ports: &PortTable,
    table: &FloatingGateTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let examined = facts
        .role
        .iter()
        .filter(|role| role.intersects(RoleMask::GATE))
        .count() as u64;
    let flagged: Vec<u32> = (0u32..)
        .zip(&facts.role)
        .filter(|&(_, &role)| role == RoleMask::GATE)
        .map(|(net, _)| net)
        .collect();
    let unlabelled: Vec<u32> = flagged
        .iter()
        .copied()
        .filter(|&net| ports.name_of(NetId(net)).is_none())
        .collect();

    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let nets = if table.labels_are_ports[row] {
            &unlabelled
        } else {
            &flagged
        };
        push_net_violations(
            design,
            nets,
            rule,
            table.head.severity[row],
            Measurement::Count(0),
            Measurement::Count(1),
            out,
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every well that no tap lies in. A well is a figure of the merged well
/// layer, so bands drawn abutting are one well. A tap ties the figure that
/// covers all of its area (exact: a tap in a hole or a notch ties nothing).
/// `examined` counts wells; a violation names the well's lowest drawn row.
pub fn check_floating_well(
    design: Design<'_>,
    table: &FloatingWellTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let mut merged = ValidatedLayer::default();
    let (mut well_rects, mut well_start) = (Vec::new(), Vec::new());
    let (mut tap_rects, mut tap_start) = (Vec::new(), Vec::new());
    let mut drawn = LayerRects::default();

    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let well_layer = table.well[row];
        let store = design.store;

        if validate_layer_into(store, well_layer, &mut scratch.layer_a).is_err()
            || validate_layer_into(store, table.tap[row], &mut scratch.layer_b).is_err()
            || union_into(&scratch.layer_a, &ValidatedLayer::default(), &mut merged).is_err()
        {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }
        decompose_into(&merged, &mut well_rects, &mut well_start);
        decompose_into(&scratch.layer_b, &mut tap_rects, &mut tap_start);
        let span = |start: &[u32], i: usize| start[i] as usize..start[i + 1] as usize;
        let wells = merged.len();
        let by_well = SortedRects::new(
            (0..wells)
                .flat_map(|w| {
                    well_rects[span(&well_start, w)]
                        .iter()
                        .map(move |&r| (r, w))
                })
                .collect(),
        );

        let mut tied = vec![false; wells];
        for tap in 0..scratch.layer_b.len() {
            let mine = &tap_rects[span(&tap_start, tap)];
            let Some(&first) = mine.first() else {
                continue;
            };
            let area = covered_area(mine);
            for (_, w) in by_well.overlapping(first) {
                let theirs = &well_rects[span(&well_start, w)];
                let covered = mine
                    .iter()
                    .fold(DbuArea::new(0), |sum, &r| sum + clipped_area(theirs, r));
                tied[w] |= covered == area;
            }
        }

        drawn.build(store, well_layer, &scratch.layer_a);
        for (w, well) in owners_of(&merged, &drawn).into_iter().enumerate() {
            if tied[w] {
                continue;
            }
            out.push(Violation {
                rule,
                layer: well_layer,
                severity: table.head.severity[row],
                at: first_vertex(store, well),
                measured: Measurement::Count(0),
                limit: Measurement::Count(1),
                shapes: (well, None),
            });
        }
        record_run(runs, out, before, rule, Outcome::Ran, wells as u64);
    }
}

/// The gate slot of a device with no gate (or a gate on no net). Equal to
/// `NetId::NONE`, so it sorts last in a net's group.
const NO_GATE: u32 = u32::MAX;

/// Flag every net driven from more than `max_drivers` distinct gate nets.
pub fn check_multiple_drivers(
    design: Design<'_>,
    table: &MultipleDriversTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    // Every `(driven net, driving gate net)` pair, once above the rows.
    scratch.edges.clear();
    for device in 0..design.devices.len() {
        let id = DeviceId(u32::try_from(device).expect("a device index is a u32"));
        let (nets, roles) = design.devices.terminals_of(id);
        // First gate wins.
        let gate = roles
            .iter()
            .position(|role| matches!(role, TerminalRole::Gate))
            .map_or(NO_GATE, |slot| nets[slot].0);
        for (slot, role) in roles.iter().enumerate() {
            if matches!(role, TerminalRole::Drain) && nets[slot] != NetId::NONE {
                scratch.edges.push((nets[slot].0, gate));
            }
        }
    }
    scratch.edges.sort_unstable();
    scratch.edges.dedup();

    // Collapse each net's run to `(net, distinct drivers)` in place. An ungated
    // drain (`NO_GATE`, last in its run) is not a driver, but its net counts
    // as examined.
    let mut read = 0usize;
    let mut write = 0usize;
    while read < scratch.edges.len() {
        let net = scratch.edges[read].0;
        let end = read + scratch.edges[read..].partition_point(|&(driven, _)| driven == net);
        let ungated = u32::from(scratch.edges[end - 1].1 == NO_GATE);
        let drivers = u32::try_from(end - read).expect("a group is shorter than the pair column");
        scratch.edges[write] = (net, drivers - ungated);
        write += 1;
        read = end;
    }
    scratch.edges.truncate(write);
    let examined = u64::try_from(scratch.edges.len()).expect("a net count is a u64");

    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let max = table.max_drivers[row];
        for &(net, drivers) in &scratch.edges {
            if drivers <= max {
                continue;
            }
            if let Some(&poly) = design.nets.polys_of(NetId(net)).first() {
                out.push(Violation {
                    rule,
                    layer: design.store.poly_layer(poly),
                    severity: table.head.severity[row],
                    at: first_vertex(design.store, poly),
                    measured: Measurement::Count(drivers),
                    limit: Measurement::Count(max),
                    shapes: (poly, None),
                });
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every polygon on a listed layer whose net reaches no device terminal.
pub fn check_unconnected_pin(
    design: Design<'_>,
    facts: &NetFacts,
    table: &UnconnectedPinTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    // With no classified nets, `net_of` has no column to read.
    let extracted = !facts.is_empty();

    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let span = table.layer_start[row] as usize..table.layer_start[row + 1] as usize;

        let mut examined = 0u64;
        for &layer in &table.layer[span] {
            let polys = design.store.polys_on_layer(layer);
            examined += u64::from(polys.end - polys.start);
            for id in polys {
                let poly = PolyId(id);
                let net = if extracted {
                    design.nets.net_of(poly)
                } else {
                    NetId::NONE
                };
                // `NetId::NONE` and ids past the classification both fail the
                // bound: unconnected.
                if net.idx() < facts.len() && facts.is_device_connected(net) {
                    continue;
                }
                out.push(Violation {
                    rule,
                    layer,
                    severity: table.head.severity[row],
                    at: first_vertex(design.store, poly),
                    measured: Measurement::Count(0),
                    limit: Measurement::Count(1),
                    shapes: (poly, None),
                });
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}
