//! Rules that ask what is connected to what, and the well-tap containment
//! test.
//!
//! Data in: nets, devices, [`NetFacts`], and for `floating_well` the well and
//! tap geometry. Data out: violations and one run per row. Nothing here
//! re-derives connectivity.

use crate::drc::rules::{owners_of, LayerRects, SortedRects};
use crate::erc::facts::{NetFacts, RoleMask};
use crate::erc::ruleset::RuleHead;
use crate::erc::{first_vertex, push_net_violations, record_run, Design, Scratch};
use crate::report::{Measurement, Outcome, RuleRun, Violation, Violations};
use crate::topology::{DeviceId, NetId, PortTable, TerminalRole};
use gpurify_geom::boolean::union_into;
use gpurify_geom::connectivity::{components_into, ComponentLabel};
use gpurify_geom::rects::{clipped_area, covered_area, decompose_into};
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::DbuArea;
use gpurify_geom::{LayerId, PolyId};

/// A floating gate: deck kind `floating_gate`, written
/// `floating_gate(; labels_are_ports: bool)`.
///
/// A gate net with nothing driving it: its role mask is exactly
/// [`RoleMask::GATE`]. Every device terminal on the net is a transistor gate,
/// so no source, drain, bulk, bipolar or two-terminal device can set its
/// voltage. With `labels_are_ports: true`, a labelled net is a block input
/// driven from outside the cell and is not flagged. Needs no design intent.
///
/// Catalog: ERC-G1 in the [check catalog]. Defined by Calibre PERC (white
/// paper 81822, public material only); [Yosys `check`] (undriven wires).
/// Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [Yosys `check`]: https://yosyshq.readthedocs.io/projects/yosys/en/latest/cmd/index_passes_status.html
#[derive(Debug, Default)]
pub struct FloatingGateTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: a labelled net is a port, driven from outside the cell. Off by
    /// default, since a layout may label internal nets too.
    pub labels_are_ports: Vec<bool>,
}

/// A well with no tap: deck kind `floating_well`, written
/// `floating_well(well, tap)`.
///
/// A well with no tap tying it to a supply. A well is a figure of the merged
/// `well` layer, so bands drawn abutting are one well. A tap ties the well
/// that covers all of its area, so a tap in a hole or a notch, or straddling
/// the well's edge, ties nothing. The test is geometric containment, not
/// connectivity: wells need not be nets. Needs no design intent.
///
/// Catalog: DRC-085, ERC-G2 in the [check catalog]. Defined by [SKY130]
/// nwell.4; [GF180MCU] DN.3; [IHP SG13G2] nmosi.d. Source tags are in
/// [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [SKY130]: https://skywater-pdk.readthedocs.io/en/main/rules/periphery.html
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
/// [IHP SG13G2]: https://github.com/IHP-GmbH/IHP-Open-PDK/tree/main/ihp-sg13g2/libs.doc/doc
#[derive(Debug, Default)]
pub struct FloatingWellTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the well layer, merged into wells.
    pub well: Vec<LayerId>,
    /// Per row: the tap layer.
    pub tap: Vec<LayerId>,
}

/// Contending drivers: deck kind `multiple_drivers`, written
/// `multiple_drivers(; max: count)`.
///
/// A net driven by more than `max_drivers` distinct drivers. A transistor
/// with its drain on the net pulls it, through the network below its source:
/// every transistor reached by following drain to source away from the net
/// (a NAND's series pull-down). Pull networks that share a gate net are one
/// driver, so an inverter's pair is one, a parallel pair sharing a gate is
/// one, and a NAND's or NOR's complementary pull-up and pull-down, gated by
/// the same inputs, are one. A drain with no gate is not a driver. Needs no
/// design intent.
///
/// # Limits
///
/// A transistor's source and drain are as extraction assigns them, by the
/// order of the two diffusion polygons under its marker, not by circuit
/// function, so the verdict can depend on that order: a transistor drawn
/// output side first drives its supply. Telling them apart needs to know
/// which nets are rails.
///
/// Catalog: ERC-G3 in the [check catalog]. Defined by [Yosys `check`]
/// (conflicting drivers). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [Yosys `check`]: https://yosyshq.readthedocs.io/projects/yosys/en/latest/cmd/index_passes_status.html
#[derive(Debug, Default)]
pub struct MultipleDriversTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the most distinct drivers a net may have. At least 1 from a
    /// deck.
    pub max_drivers: Vec<u32>,
}

/// A dangling conductor: deck kind `unconnected_pin`, written
/// `unconnected_pin(layers..)`.
///
/// A conductor on a net no device terminal touches. A row flags every
/// polygon on a listed layer whose net reaches no device terminal, or that is
/// on no net: a floating stripe, a stray shape, a pin wired to nothing. Needs
/// no design intent.
///
/// # Limits
///
/// LEF58 must-join-all-ports is not modelled (DRC-084), and neither are the
/// power-grid checks beyond dangling shapes, such as an instance's supply
/// terminal left unconnected (ERC-E9).
///
/// Catalog: DRC-084 (partial), ERC-E9 (partial), ERC-G6 in the [check
/// catalog]. Defined by [SKY130] x.22; LEF58 `MUSTJOINALLPORTS`;
/// [OpenROAD `check_power_grid`]. Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [SKY130]: https://skywater-pdk.readthedocs.io/en/main/rules/periphery.html
/// [OpenROAD `check_power_grid`]: https://openroad.readthedocs.io/en/latest/main/src/psm/README.html
#[derive(Debug, Default)]
pub struct UnconnectedPinTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// `layer[layer_start[i] .. layer_start[i + 1]]` are row `i`'s layers.
    pub layer_start: Vec<u32>,
    /// Checked layers, CSR by `layer_start`; at least one per row. A layer
    /// listed twice is checked, and reported, twice.
    pub layer: Vec<LayerId>,
}

/// Runs every [`FloatingGateTable`] row.
///
/// `examined` counts nets carrying a gate terminal, labelled or not. A
/// violation sits at the first vertex of the net's lowest-numbered polygon,
/// on its layer, measuring the count of non-gate terminals, 0, against 1.
/// Every row runs.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
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

/// Runs every [`FloatingWellTable`] row.
///
/// `examined` counts wells (merged figures). A violation sits at the first
/// vertex of the well's lowest-numbered drawn polygon, on the well layer,
/// measuring the count of taps, 0, against 1. A row is refused when its well
/// or tap layer will not validate, or the well layer will not merge.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
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

/// Runs every [`MultipleDriversTable`] row.
///
/// `examined` counts nets with at least one drain terminal. A violation sits
/// at the first vertex of the net's lowest-numbered polygon, on its layer,
/// measuring the distinct drivers (pull networks joined by a shared gate net)
/// against `max`. Every row runs.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_multiple_drivers(
    design: Design<'_>,
    table: &MultipleDriversTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    // Per device: its first gate's net (`NO_GATE` for none or no net) and its
    // source's net; every drain on a net as `(net, device)`, sorted, so a
    // net's drains are one run.
    let devices = design.devices;
    let mut gate = vec![NO_GATE; devices.len()];
    let mut source = vec![NO_GATE; devices.len()];
    let mut drains: Vec<(u32, u32)> = Vec::new();
    for device in 0..devices.len() {
        let id = DeviceId(u32::try_from(device).expect("a device index is a u32"));
        let (nets, roles) = devices.terminals_of(id);
        for (&net, role) in nets.iter().zip(roles) {
            match role {
                TerminalRole::Gate if gate[device] == NO_GATE => gate[device] = net.0,
                TerminalRole::Source if source[device] == NO_GATE => source[device] = net.0,
                TerminalRole::Drain if net != NetId::NONE => drains.push((net.0, id.0)),
                _ => {}
            }
        }
    }
    drains.sort_unstable();
    drains.dedup();
    let drains_on = |net: u32| {
        let lo = drains.partition_point(|&(n, _)| n < net);
        &drains[lo..lo + drains[lo..].partition_point(|&(n, _)| n == net)]
    };

    // `(net, distinct drivers)` per net with a drain. A driver is a pull
    // network: a transistor with its drain on the net, and every transistor
    // below its source, followed drain to source away from the net. Members
    // whose networks share a gate net are one driver: a NAND's parallel
    // pull-up and series pull-down share their inputs.
    // ponytail: one walk per member; a pass-transistor array walked from each
    // of its nets is quadratic. Share the walks per source net if that bites.
    scratch.edges.clear();
    let mut seen = vec![0u32; design.nets.net_count()];
    let mut stamp = 0u32;
    let mut queue: Vec<u32> = Vec::new();
    // `(gate net, member)` for every gate of each member's pull network.
    let mut gates: Vec<(u32, u32)> = Vec::new();
    let mut shared: Vec<(u32, u32)> = Vec::new();
    let mut labels = Vec::new();
    let mut start = 0;
    while start < drains.len() {
        let net = drains[start].0;
        let run = drains_on(net);
        start += run.len();
        gates.clear();
        for (member, &(_, device)) in (0u32..).zip(run) {
            // A drain with no gate drives nothing.
            if gate[device as usize] == NO_GATE {
                continue;
            }
            gates.push((gate[device as usize], member));
            stamp += 1;
            queue.clear();
            queue.push(source[device as usize]);
            while let Some(at) = queue.pop() {
                let fresh = seen.get(at as usize).is_some_and(|&s| s != stamp);
                if at == net || !fresh {
                    continue;
                }
                seen[at as usize] = stamp;
                for &(_, below) in drains_on(at) {
                    if gate[below as usize] != NO_GATE {
                        gates.push((gate[below as usize], member));
                    }
                    queue.push(source[below as usize]);
                }
            }
        }
        gates.sort_unstable();
        shared.clear();
        shared.extend(
            gates
                .windows(2)
                .filter(|pair| pair[0].0 == pair[1].0)
                .map(|pair| (pair[0].1, pair[1].1)),
        );
        let members = u32::try_from(run.len()).expect("a net's drains fit a u32");
        components_into(members, &shared, &mut labels);
        let mut drivers: Vec<ComponentLabel> =
            gates.iter().map(|&(_, m)| labels[m as usize]).collect();
        drivers.sort_unstable();
        drivers.dedup();
        let drivers = u32::try_from(drivers.len()).expect("a net's drivers fit a u32");
        scratch.edges.push((net, drivers));
    }
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

/// Runs every [`UnconnectedPinTable`] row.
///
/// `examined` counts the polygons on the row's layers. A violation sits at
/// the polygon's first vertex, on its layer, measuring the device terminals
/// reached, 0, against 1. Every row runs; with no extracted nets every
/// polygon is unconnected.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
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
