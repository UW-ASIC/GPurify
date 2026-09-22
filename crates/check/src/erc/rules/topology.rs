//! Rules that ask only what is connected to what.
//!
//! Data in: nets, devices, [`NetFacts`]. Data out: violations and one run per
//! row. Nothing here re-derives connectivity.

use crate::erc::facts::{NetFacts, RoleMask};
use crate::erc::ruleset::RuleHead;
use crate::erc::{centre, first_vertex, push_net_violations, record_run, Design, Scratch};
use crate::report::{Measurement, Outcome, RuleRun, Violation, Violations};
use crate::topology::{DeviceId, NetId, TerminalRole};
use gpurify_geom::ops::{winding_of, Winding};
use gpurify_geom::Dbu;
use gpurify_geom::{LayerId, PolyId};

/// A gate net with nothing driving it: its role mask is exactly
/// [`RoleMask::GATE`].
#[derive(Debug, Default)]
pub struct FloatingGateTable {
    pub head: RuleHead,
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

/// Flag every net whose only terminals are gates. `examined` counts nets
/// carrying a gate terminal.
pub fn check_floating_gate(
    design: Design<'_>,
    facts: &NetFacts,
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

    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        push_net_violations(
            design,
            &flagged,
            rule,
            table.head.severity[row],
            Measurement::Count(0),
            Measurement::Count(1),
            out,
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every well ring (counter-clockwise) that no tap lies in. Exact
/// containment; a hole ring is neither examined nor tied by a tap inside it.
pub fn check_floating_well(
    design: Design<'_>,
    table: &FloatingWellTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let mut ring_well: Vec<bool> = Vec::new();
    let mut ring_order: Vec<u32> = Vec::new();
    let mut tied: Vec<bool> = Vec::new();

    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let well_layer = table.well[row];

        // A tap is only tested for containment, so its box is enough.
        scratch.boxes.clear();
        scratch
            .boxes
            .extend_from_slice(design.store.layer_bboxes(table.tap[row]));

        // Row `k` is store row `polys.start + k`.
        let polys = design.store.polys_on_layer(well_layer);
        let boxes = design.store.layer_bboxes(well_layer);
        let ring_count = polys.len();

        // A separate pass: the hole puncturing a well may sit at a later row.
        ring_well.clear();
        ring_well.extend(polys.clone().map(|id| {
            let (xs, ys) = design.store.poly_verts(PolyId(id));
            winding_of(xs, ys) == Some(Winding::CounterClockwise)
        }));

        // Stab order: ascending low x, ties by row. The prefix with
        // `xlo <= p.x` is a superset of the rings containing `p`.
        ring_order.clear();
        ring_order.extend(0..u32::try_from(ring_count).expect("a store row is a u32"));
        ring_order.sort_unstable_by_key(|&k| (boxes[k as usize].xlo.raw(), k));

        tied.clear();
        tied.resize(ring_count, false);

        // Each tap ties the innermost ring (smallest box) holding its centre;
        // a tap in a hole ties the hole, not the well.
        for &tap in &scratch.boxes {
            let probe = centre(tap);
            let end = ring_order.partition_point(|&k| boxes[k as usize].xlo.raw() <= probe.x.raw());
            let mut best = u32::MAX;
            let mut best_area = 0i128;
            for &k in &ring_order[..end] {
                let box_ = boxes[k as usize];
                if probe.x.raw() > box_.xhi.raw()
                    || probe.y.raw() < box_.ylo.raw()
                    || probe.y.raw() > box_.yhi.raw()
                {
                    continue;
                }
                // No smaller than the best cannot be inner to it.
                let area = box_.area().raw();
                if best != u32::MAX && area >= best_area {
                    continue;
                }
                let (xs, ys) = design.store.poly_verts(PolyId(polys.start + k));
                if !inside_ring(xs, ys, probe.x, probe.y) {
                    continue;
                }
                best = k;
                best_area = area;
            }
            if best == u32::MAX {
                continue;
            }
            // The whole tap box must be inside, and a hole ties nothing.
            tied[best as usize] |= ring_well[best as usize] && boxes[best as usize].contains(tap);
        }

        // Store order, so the report follows the layer.
        let mut examined = 0u64;
        for k in 0..ring_count {
            if !ring_well[k] {
                continue;
            }
            examined += 1;
            if tied[k] {
                continue;
            }
            let well = PolyId(polys.start + u32::try_from(k).expect("a store row is a u32"));
            out.push(Violation {
                rule,
                layer: well_layer,
                severity: table.head.severity[row],
                at: first_vertex(design.store, well),
                measured: Measurement::Count(0),
                limit: Measurement::Count(1),
                shapes: (well, None),
            });
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
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

/// Whether a point lies strictly inside a ring: even-odd ray cast toward +x,
/// exact in `i128`.
///
/// Boundary follows the half-open crossing rule, unlike `supply::point_in_region`
/// (boundary inclusive): a tap on a well's edge must not tie it. Keep both.
fn inside_ring(xs: &[Dbu], ys: &[Dbu], px: Dbu, py: Dbu) -> bool {
    let n = xs.len();
    if n < 3 {
        return false;
    }
    let ys = &ys[..n];
    let mut crossings = 0u32;
    let mut ax = xs[n - 1];
    let mut ay = ys[n - 1];
    for i in 0..n {
        let (bx, by) = (xs[i], ys[i]);
        // `(b - a) x (p - a)`, widened: operands reach 2^41.
        let side = i128::from(bx.raw() - ax.raw()) * i128::from(py.raw() - ay.raw())
            - i128::from(by.raw() - ay.raw()) * i128::from(px.raw() - ax.raw());
        let up = by.raw() > ay.raw();
        let straddles = (ay.raw() > py.raw()) != (by.raw() > py.raw());
        crossings += u32::from(straddles & ((side > 0) == up));
        ax = bx;
        ay = by;
    }
    crossings & 1 == 1
}
