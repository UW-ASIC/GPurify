//! Rules that ask what is connected to what, and the well-tap containment
//! test.
//!
//! Data in: nets, devices, [`NetFacts`], for `floating_well` the well and
//! tap geometry, and for `multiple_drivers` the rails the design intent
//! declares. Data out: violations and one run per row. Nothing here
//! re-derives connectivity.

use crate::drc::rules::{owners_of, LayerRects, SortedRects};
use crate::erc::facts::{IntentMap, NetFacts, NetTypes, RoleMask};
use crate::erc::ruleset::RuleHead;
use crate::erc::{
    device_id, first_vertex, push_net_violations, record_run, skip_rows, Design, Scratch,
};
use crate::report::{Measurement, Outcome, RuleRun, Violation, Violations};
use crate::topology::{NetId, PortTable, TerminalRole};
use gpurify_geom::boolean::union_into;
use gpurify_geom::connectivity::{components_into, ComponentLabel};
use gpurify_geom::rects::{clipped_area, covered_area, decompose_into};
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::DbuArea;
use gpurify_geom::{LayerId, PolyId};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::intent::SupplyRole;
use gpurify_ingest::StrId;

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
#[derive(Debug, Default, Clone, PartialEq)]
pub struct FloatingGateTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: a labelled net is a port, driven from outside the cell. Off by
    /// default, since a layout may label internal nets too.
    pub labels_are_ports: Vec<bool>,
}

/// Fanout: deck kind `fanout`, written `fanout(; max: count)`.
///
/// A net that drives more than `max` transistor gates: the count of MOS
/// gate terminals on the net, each transistor counted once per gate it has
/// there. A large fanout slows the net's edges, the high-load, slow-ramp
/// condition hot-carrier guidelines ask to be reviewed. Every net is
/// counted, supplies included (a rail with many gates on it is tie-off
/// fanout). Needs no design intent.
///
/// # Limits
///
/// The count is of gates, not of load: gate area, wire capacitance and the
/// strength of the driver are not weighed.
///
/// Catalog: ERC-H4 in the [check catalog]. Defined by Synopsys IC Validator's
/// programmable electrical rule checks (public product material only);
/// [GF180MCU] §14.1.4.1 ("Review circuits with high capacitive load ... fan
/// out"). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_manual/drm_14_1.html
#[derive(Debug, Default, Clone, PartialEq)]
pub struct FanoutTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the most gates a net may drive. Positive from a deck.
    pub max_gates: Vec<u32>,
}

/// Runs every [`FanoutTable`] row.
///
/// `examined` counts the nets with a gate on them. A violation sits at the
/// first vertex of the net's lowest-numbered polygon, on its layer,
/// measuring the gate count against `max`; a net with no polygon is not
/// reported. Every row runs.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_fanout(
    design: Design<'_>,
    table: &FanoutTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let devices = design.devices;
    let mut gates = vec![0u32; design.nets.net_count()];
    for device in 0..devices.len() {
        if devices.kind[device] != DeviceKind::Mos {
            continue;
        }
        let id = device_id(device);
        let (nets, roles) = devices.terminals_of(id);
        for (&net, &role) in nets.iter().zip(roles) {
            if role == TerminalRole::Gate && net != NetId::NONE && net.idx() < gates.len() {
                gates[net.idx()] += 1;
            }
        }
    }
    let examined = gates.iter().filter(|&&count| count > 0).count() as u64;
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let limit = table.max_gates[row];
        for (net, &count) in (0u32..).zip(&gates) {
            if count <= limit {
                continue;
            }
            let Some(&poly) = design.nets.polys_of(NetId(net)).first() else {
                continue;
            };
            out.push(Violation {
                rule,
                layer: design.store.poly_layer(poly),
                severity: table.head.severity[row],
                at: first_vertex(design.store, poly),
                measured: Measurement::Count(count),
                limit: Measurement::Count(limit),
                shapes: (poly, None),
            });
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
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
#[derive(Debug, Default, Clone, PartialEq)]
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
/// A net driven by more than `max_drivers` distinct drivers. A driver is a
/// pull network: a channel-connected path from the net to a rail, a supply
/// the design intent declares (a pull-up to a power rail, a pull-down to a
/// ground rail). A transistor with either end of its channel on the net
/// pulls it when a walk from its other end, through every transistor whose
/// channel touches the nets reached, stopping at rails and never back
/// through the net, reaches a rail (a NAND's series pull-down); its network
/// is every transistor that walk passes. Source and drain are alike: the
/// rails orient each channel, not the order extraction gives its two ends.
/// Pull networks that share a gate net are one driver, so an inverter's pair
/// is one, a parallel pair sharing a gate is one, and a NAND's or NOR's
/// complementary pull-up and pull-down, gated by the same inputs, are one.
/// A pass gate or transmission gate that reaches no rail drives nothing by
/// itself, and a transistor with no gate is not a driver. A rail is driven
/// by its supply and is not examined. Needs design intent, for which nets
/// are the rails.
///
/// Catalog: ERC-G3 in the [check catalog]. Defined by [Yosys `check`]
/// (conflicting drivers). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [Yosys `check`]: https://yosyshq.readthedocs.io/projects/yosys/en/latest/cmd/index_passes_status.html
#[derive(Debug, Default, Clone, PartialEq)]
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
/// LEF58 must-join-all-ports is not modelled (DRC-084). A labelled piece of
/// a supply cut off from its grid is [`FloatingSupplyTable`]'s (ERC-E9).
///
/// Catalog: DRC-084 (partial), ERC-E9, ERC-G6 in the [check catalog].
/// Defined by [SKY130] x.22; LEF58 `MUSTJOINALLPORTS`; [OpenROAD
/// `check_power_grid`]. Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [SKY130]: https://skywater-pdk.readthedocs.io/en/main/rules/periphery.html
/// [OpenROAD `check_power_grid`]: https://openroad.readthedocs.io/en/latest/main/src/psm/README.html
/// [`FloatingSupplyTable`]: crate::erc::rules::supply::FloatingSupplyTable
#[derive(Debug, Default, Clone, PartialEq)]
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

/// The gate slot of a device with no gate (or a gate on no net), and a
/// channel end on no net. Equal to `NetId::NONE`, so it sorts last in a net's
/// group.
const NO_GATE: u32 = u32::MAX;

/// Runs every [`MultipleDriversTable`] row.
///
/// `examined` counts the nets, other than rails, with a source or drain
/// terminal. A violation sits at the first vertex of the net's
/// lowest-numbered polygon, on its layer, measuring the distinct drivers
/// (pull networks joined by a shared gate net) against `max`. Every row is
/// skipped when no design intent was given or it declares no supply this
/// layout has.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_multiple_drivers(
    design: Design<'_>,
    intent: &IntentMap,
    table: &MultipleDriversTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if intent.supply_net.is_empty() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let is_rail = |net: u32| intent.supply_net.binary_search(&NetId(net)).is_ok();
    // Per device: its first gate's net (`NO_GATE` for none or no net) and the
    // two ends of its channel, source and drain alike; every channel end on a
    // net as `(net, device)`, sorted, so a net's channel ends are one run.
    let devices = design.devices;
    let mut gate = vec![NO_GATE; devices.len()];
    let mut ends = vec![[NO_GATE; 2]; devices.len()];
    let mut channel: Vec<(u32, u32)> = Vec::new();
    for device in 0..devices.len() {
        let id = device_id(device);
        let (nets, roles) = devices.terminals_of(id);
        for (&net, role) in nets.iter().zip(roles) {
            let end = match role {
                TerminalRole::Gate if gate[device] == NO_GATE => {
                    gate[device] = net.0;
                    continue;
                }
                TerminalRole::Source => 0,
                TerminalRole::Drain => 1,
                _ => continue,
            };
            if ends[device][end] == NO_GATE {
                ends[device][end] = net.0;
            }
        }
        channel.extend(
            ends[device]
                .iter()
                .filter(|&&net| net != NO_GATE)
                .map(|&net| (net, id.0)),
        );
    }
    channel.sort_unstable();
    channel.dedup();
    let channel_on = |net: u32| {
        let lo = channel.partition_point(|&(n, _)| n < net);
        &channel[lo..lo + channel[lo..].partition_point(|&(n, _)| n == net)]
    };
    // The end of `device`'s channel away from `net`: `net` itself when both
    // ends are on it.
    let across = |device: u32, net: u32| {
        let [a, b] = ends[device as usize];
        if a == net {
            b
        } else {
            a
        }
    };

    // `(net, distinct drivers)` per examined net. Members whose networks
    // share a gate net are one driver: a NAND's parallel pull-up and series
    // pull-down share their inputs.
    // ponytail: one walk per member; a pass-transistor array walked from each
    // of its nets is quadratic. Share the walks per far net if that bites.
    scratch.edges.clear();
    let mut seen = vec![0u32; design.nets.net_count()];
    let mut stamp = 0u32;
    let mut queue: Vec<u32> = Vec::new();
    // `(gate net, member)` for every gate of each member's pull network.
    let mut gates: Vec<(u32, u32)> = Vec::new();
    let mut shared: Vec<(u32, u32)> = Vec::new();
    let mut labels = Vec::new();
    let mut start = 0;
    while start < channel.len() {
        let net = channel[start].0;
        let run = channel_on(net);
        start += run.len();
        if is_rail(net) {
            continue;
        }
        gates.clear();
        for (member, &(_, device)) in (0u32..).zip(run) {
            if gate[device as usize] == NO_GATE {
                continue;
            }
            let mine = gates.len();
            gates.push((gate[device as usize], member));
            stamp += 1;
            let mut rail = false;
            queue.clear();
            queue.push(across(device, net));
            while let Some(at) = queue.pop() {
                let fresh = seen.get(at as usize).is_some_and(|&s| s != stamp);
                if at == net || !fresh {
                    continue;
                }
                seen[at as usize] = stamp;
                if is_rail(at) {
                    rail = true;
                    continue;
                }
                for &(_, next) in channel_on(at) {
                    if gate[next as usize] != NO_GATE {
                        gates.push((gate[next as usize], member));
                    }
                    queue.push(across(next, at));
                }
            }
            // A pass gate that reaches no rail drives nothing by itself.
            if !rail {
                gates.truncate(mine);
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
        let members = u32::try_from(run.len()).expect("a net's channel ends fit a u32");
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

/// A net with no path to the supplies: deck kind `supply_path`, written
/// `supply_path(; both: bool, labels_are_ports: bool)`.
///
/// A path is the set of nets joined through MOS source and drain pins and
/// resistor pins, never through a gate, a bulk, a diode, a capacitor or a
/// bipolar: Mentor's programmable-ERC patent calls this "the default path
/// definition in LVS" ("paths that lead through source/drain pins of MOS,
/// and positive/negative pins of resistor devices"). A declared supply
/// breaks a path: the path ends there and carries the supply's role, power
/// or ground (the patent's `-break`, its examples `init_5` and `init_6`), so
/// a pull-up and a pull-down meeting at a net make one path that reaches
/// both rails, and the rails do not join the paths beyond them. With
/// `both: false` a row flags a net whose path reaches no supply at all (the
/// patent's `check_1`, "no path to Power and no path to Ground"); with
/// `both: true`, one whose path misses power or misses ground (`check_2`,
/// Calibre's `PATHCHK GROUND && !POWER` and `POWER && !GROUND` together).
/// Supplies themselves are not examined, nor is a net no device terminal
/// reaches (a stray shape is [`UnconnectedPinTable`]'s). With
/// `labels_are_ports: true`, a labelled net is a port of the top cell, and a
/// path stops there too: "a path continues until it reaches an unqualified
/// device or a port in the top cell" (the patent, \[0262\]). A port ends a
/// path as a supply does, joining nothing beyond it, but carries no role:
/// it is its own path, which reaches a supply only through a device between
/// them. The patent states no more of a port than that; reading a port as a
/// break is this kind's. Needs design intent, for which nets are power and
/// ground.
///
/// # Limits
///
/// Only the intent's power and ground are net types: the patent's other net
/// types (by name pattern or by attached device) and Calibre's `LABELED` are
/// not read. Whether Calibre's own `PATHCHK` breaks at supplies, and what its
/// `NOFLOAT` option excludes, is not public; the breaking is the patent's.
///
/// Catalog: ERC-G9 in the [check catalog]. Defined by Calibre `ERC PATHCHK`
/// (the open [ICsprout55] PDK's Calibre LVS deck: "Nodes with a path to
/// ground but not power", "Nodes without a path to both power and
/// ground"); [US20100306720A1] (paths, breaks, `check_1` and `check_2`).
/// Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [US20100306720A1]: https://patents.google.com/patent/US20100306720A1/en
/// [ICsprout55]: https://github.com/openecos-projects/icsprout55-pdk/blob/main/pv/LVS/ICsprout_CalLVS_55LLULP1233_REV1_0_OS.lvs
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SupplyPathTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: a net needs a path to both power and ground, not just one.
    pub both: Vec<bool>,
    /// Per row: a labelled net is a top-cell port, at which a path stops.
    pub labels_are_ports: Vec<bool>,
}

/// A transistor gate too many devices from a rail: deck kind `gate_path`,
/// written `gate_path(; ground: bool, max_devices: count)`.
///
/// "Every transistor gate in the design must have an electrical path to
/// ground that passes through no more than three other devices"
/// ([US20100306720A1], the kind of rule its programmable checks are written
/// for), with three replaced by `max_devices`, and ground by power when
/// `ground` is false. The path runs through MOS source and drain pins and
/// resistor pins, as [`SupplyPathTable`]'s does, but no supply breaks it: it
/// ends at the first declared supply of the asked role and may pass any
/// other net. A path's length is the devices it passes, so a gate on a
/// ground net has 0, one an inverter drives has 1 (its pull-down), and one
/// behind a two-high stack 2; the shortest path counts. A row flags every
/// gate net whose shortest path passes more than `max_devices` devices, or
/// that has no path at all. Each net carrying a MOS gate is examined once.
/// Needs design intent, for which nets are power and ground.
///
/// # Limits
///
/// The patent states the rule as an example and does not define how a
/// device is counted; one per device a path passes is its plain reading,
/// and the convention HP's series pass-FET check states: it "increments a
/// serial pass FET counter" for each FET a walk crosses ([US 6,367,062],
/// col. 11-13; three in series give "a count of three"). Net types beyond
/// the intent's power and ground are [`NetTypeTable`]'s.
///
/// Catalog: ERC-H3 in the [check catalog]. Defined by
/// [US20100306720A1]; the count by [US 6,367,062]. Source tags are in
/// [check-sources.md].
///
/// [US 6,367,062]: https://patents.google.com/patent/US6367062B1/en
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [US20100306720A1]: https://patents.google.com/patent/US20100306720A1/en
#[derive(Debug, Default, Clone, PartialEq)]
pub struct GatePathTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the path ends at a ground (`true`) or a power supply.
    pub ground: Vec<bool>,
    /// Per row: the most devices a gate's shortest path may pass.
    pub max_devices: Vec<u32>,
}

/// Every two-net pair a path may cross: a MOS's source and drain, a
/// resistor's two pins. A device with an end on no net is left out.
fn path_edges(design: Design<'_>) -> Vec<(u32, u32)> {
    let devices = design.devices;
    let mut edges = Vec::new();
    for device in 0..devices.len() {
        let conducts = |role: TerminalRole| match devices.kind[device] {
            DeviceKind::Mos => matches!(role, TerminalRole::Source | TerminalRole::Drain),
            DeviceKind::Resistor => matches!(role, TerminalRole::Pin(_)),
            _ => false,
        };
        let id = device_id(device);
        let (nets, roles) = devices.terminals_of(id);
        let mut ends = nets
            .iter()
            .zip(roles)
            .filter(|&(_, &role)| conducts(role))
            .map(|(&net, _)| net);
        if let (Some(a), Some(b), None) = (ends.next(), ends.next(), ends.next()) {
            if a != NetId::NONE && b != NetId::NONE {
                edges.push((a.0, b.0));
            }
        }
    }
    edges
}

/// Runs every [`SupplyPathTable`] row.
///
/// `examined` counts the nets, supplies aside, that a device terminal
/// reaches. A violation sits at the first vertex of the net's
/// lowest-numbered polygon, on its layer, measuring the supply roles its
/// path reaches (0 or 1) against those needed (1, or 2 with `both`). Every
/// row is skipped when no design intent was given or it declares no supply
/// this layout has.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_supply_path(
    design: Design<'_>,
    facts: &NetFacts,
    ports: &PortTable,
    intent: &IntentMap,
    table: &SupplyPathTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if intent.supply_net.is_empty() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let count = u32::try_from(facts.len()).expect("a net count fits a u32");
    let role = |net: u32| intent.supply(NetId(net)).map(|(role, _)| role);
    let port = |net: u32| role(net).is_none() && ports.name_of(NetId(net)).is_some();
    let edges: Vec<(u32, u32)> = path_edges(design)
        .into_iter()
        .filter(|&(a, b)| a < count && b < count)
        .collect();
    let examined: Vec<u32> = (0..count)
        .filter(|&net| role(net).is_none() && facts.is_device_connected(NetId(net)))
        .collect();
    let mut labels = Vec::new();
    let mut reach = vec![0u8; count as usize];
    for row in 0..table.head.len() {
        // Paths joined away from the supplies (and, with ports, away from
        // them); each edge onto a supply marks its path with that supply's
        // role.
        let stops = table.labels_are_ports[row];
        let inner: Vec<(u32, u32)> = edges
            .iter()
            .copied()
            .filter(|&(a, b)| role(a).is_none() && role(b).is_none())
            .filter(|&(a, b)| !(stops && (port(a) || port(b))))
            .collect();
        components_into(count, &inner, &mut labels);
        // Per path: bit 0 a path to power, bit 1 a path to ground.
        reach.fill(0);
        for &(a, b) in &edges {
            for (from, to) in [(a, b), (b, a)] {
                let bit = match (role(from), role(to)) {
                    (None, Some(SupplyRole::Power)) => 1,
                    (None, Some(SupplyRole::Ground)) => 2,
                    _ => continue,
                };
                reach[labels[from as usize].0 as usize] |= bit;
            }
        }
        let before = out.len();
        let rule = table.head.rule[row];
        let need = if table.both[row] { 2 } else { 1 };
        for found in 0..need {
            let flagged: Vec<u32> = examined
                .iter()
                .copied()
                .filter(|&net| reach[labels[net as usize].0 as usize].count_ones() == found)
                .collect();
            push_net_violations(
                design,
                &flagged,
                rule,
                table.head.severity[row],
                Measurement::Count(found),
                Measurement::Count(need),
                out,
            );
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined.len() as u64);
    }
}

/// Runs every [`GatePathTable`] row.
///
/// `examined` counts the nets carrying a MOS gate. A violation sits at the
/// first vertex of the gate net's lowest-numbered polygon, on its layer,
/// measuring the devices its shortest path passes against `max_devices`, or,
/// with no path at all, the paths found, 0, against 1. Every row is skipped
/// when no design intent was given or it declares no supply this layout has.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_gate_path(
    design: Design<'_>,
    intent: &IntentMap,
    table: &GatePathTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if intent.supply_net.is_empty() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let count = design.nets.net_count();
    let devices = design.devices;
    let mut gate_net = vec![false; count];
    for device in 0..devices.len() {
        if devices.kind[device] != DeviceKind::Mos {
            continue;
        }
        let id = device_id(device);
        let (nets, roles) = devices.terminals_of(id);
        for (&net, &role) in nets.iter().zip(roles) {
            if role == TerminalRole::Gate && net != NetId::NONE && net.idx() < count {
                gate_net[net.idx()] = true;
            }
        }
    }
    let gates: Vec<u32> = (0u32..)
        .zip(&gate_net)
        .filter(|&(_, &gate)| gate)
        .map(|(net, _)| net)
        .collect();
    // Undirected adjacency, CSR by net.
    let edges: Vec<(u32, u32)> = path_edges(design)
        .into_iter()
        .filter(|&(a, b)| (a as usize) < count && (b as usize) < count)
        .collect();
    let mut start = vec![0u32; count + 1];
    for &(a, b) in &edges {
        start[a as usize + 1] += 1;
        start[b as usize + 1] += 1;
    }
    for i in 0..count {
        start[i + 1] += start[i];
    }
    let mut fill = start.clone();
    let mut adjacent = vec![0u32; start[count] as usize];
    for &(a, b) in &edges {
        for (from, to) in [(a, b), (b, a)] {
            adjacent[fill[from as usize] as usize] = to;
            fill[from as usize] += 1;
        }
    }
    let mut dist = vec![u32::MAX; count];
    let mut queue = std::collections::VecDeque::new();
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let want = if table.ground[row] {
            SupplyRole::Ground
        } else {
            SupplyRole::Power
        };
        // Breadth first from every supply of the asked role: devices passed.
        dist.fill(u32::MAX);
        queue.clear();
        for (net, &role) in intent.supply_net.iter().zip(&intent.supply_role) {
            if role == want && net.idx() < count {
                dist[net.idx()] = 0;
                queue.push_back(net.0);
            }
        }
        while let Some(at) = queue.pop_front() {
            let span = start[at as usize] as usize..start[at as usize + 1] as usize;
            for &to in &adjacent[span] {
                if dist[to as usize] == u32::MAX {
                    dist[to as usize] = dist[at as usize] + 1;
                    queue.push_back(to);
                }
            }
        }
        let max = table.max_devices[row];
        for &net in &gates {
            let (measured, limit) = match dist[net as usize] {
                u32::MAX => (0, 1),
                d if d > max => (d, max),
                _ => continue,
            };
            push_net_violations(
                design,
                &[net],
                rule,
                table.head.severity[row],
                Measurement::Count(measured),
                Measurement::Count(limit),
                out,
            );
        }
        record_run(runs, out, before, rule, Outcome::Ran, gates.len() as u64);
    }
}

/// A net check over the design's net types: deck kind `net_type`, written
/// `net_type(; net: types | none, path: types | none, break: types | none,
/// exclude: types | none)`.
///
/// Mentor's programmable-ERC patent ([US20100306720A1]) gives nets types:
/// by name or by the devices on them, declared in the design intent
/// (`net_types`, `type_sets`; see [`NetTypes`]). It then joins nets into
/// paths, "net paths that lead through pins of devices" (\[0248\]), here its
/// default, "source/drain pins of MOS, and positive/negative pins of
/// resistor devices" (`init_1`, \[0267\]). "If -break is specified, then a
/// path also stops when it reaches a net that meets the criteria" (\[0262\]):
/// a net meeting `break` is in no path but its own. A path's types are "the
/// combined net types from all of the nets in the path, plus the net types
/// of its break nets", less `exclude` from the break nets (\[0263\]). A row
/// flags every net whose own types meet `net` and whose path's types meet
/// `path`, the patent's net check `-netType` and `-pathType` (\[0450\]-\[0462\]):
/// its `check_1`, "nets that have no path to Power and no path to Ground", is
/// `net: ["!", "power", "ground"], path: ["!", "power", "ground"]` with
/// supplies typed `power` and `ground` and broken at.
///
/// A condition is a list of type or set names: "all of the net types
/// before the exclamation symbol, and ... not any of the net types after"
/// (\[0262\]), written `["a", "b", "!", "c"]`; `none` is met by every net. A
/// name the intent does not declare is a type no net has. Only nets a
/// device terminal reaches are examined. Needs design intent that declares
/// net types.
///
/// # Limits
///
/// The patent's path definition by device type and pin list (its
/// `perc::commandc -type -pin`) is fixed to the default; its device-property
/// constraints, per-cell (`-cell`) types and checks, and device checks
/// (`-pinNetType`) are not read. Calibre PERC's own commands are not public;
/// this is the patent's text.
///
/// Catalog: ERC-H3 in the [check catalog]. Defined by [US20100306720A1].
/// Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [US20100306720A1]: https://patents.google.com/patent/US20100306720A1/en
#[derive(Debug, Default, Clone, PartialEq)]
pub struct NetTypeTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the condition a net's own types meet, `(name, absent)`.
    pub net: Vec<Vec<(StrId, bool)>>,
    /// Per row: the condition its path's types meet.
    pub path: Vec<Vec<(StrId, bool)>>,
    /// Per row: the condition a net meets to break paths; empty for none.
    pub breaks: Vec<Vec<(StrId, bool)>>,
    /// Per row: types a path does not take from its break nets.
    pub exclude: Vec<Vec<StrId>>,
}

/// A condition as masks: `(present, absent, satisfiable)`.
fn condition_masks(types: &NetTypes, condition: &[(StrId, bool)]) -> (u64, u64, bool) {
    let (mut present, mut absent, mut possible) = (0, 0, true);
    for &(name, negated) in condition {
        match (types.bit(name), negated) {
            (Some(bit), false) => present |= bit,
            (Some(bit), true) => absent |= bit,
            (None, false) => possible = false,
            (None, true) => {}
        }
    }
    (present, absent, possible)
}

/// Runs every [`NetTypeTable`] row.
///
/// `examined` counts the nets a device terminal reaches. A violation sits
/// at the first vertex of the net's lowest-numbered polygon, on its layer,
/// measuring 1 (the net met the row's conditions) against 0. Every row is
/// skipped when the design intent declares no net type.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_net_type(
    design: Design<'_>,
    facts: &NetFacts,
    types: &NetTypes,
    table: &NetTypeTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if types.name.is_empty() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let count = u32::try_from(facts.len()).expect("a net count fits a u32");
    let meets = |mask: u64, (present, absent, possible): (u64, u64, bool)| {
        possible && mask & present == present && mask & absent == 0
    };
    let edges: Vec<(u32, u32)> = path_edges(design)
        .into_iter()
        .filter(|&(a, b)| a < count && b < count)
        .collect();
    let examined: Vec<u32> = (0..count)
        .filter(|&net| facts.is_device_connected(NetId(net)))
        .collect();
    let mut labels = Vec::new();
    let mut path_mask = vec![0u64; count as usize];
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let breaks = condition_masks(types, &table.breaks[row]);
        let breaking =
            |net: u32| !table.breaks[row].is_empty() && meets(types.of(NetId(net)), breaks);
        let exclude = table.exclude[row]
            .iter()
            .filter_map(|&name| types.bit(name))
            .fold(0, |all, bit| all | bit);
        let inner: Vec<(u32, u32)> = edges
            .iter()
            .copied()
            .filter(|&(a, b)| !breaking(a) && !breaking(b))
            .collect();
        components_into(count, &inner, &mut labels);
        path_mask.fill(0);
        for net in 0..count {
            path_mask[labels[net as usize].0 as usize] |= types.of(NetId(net));
        }
        for &(a, b) in &edges {
            for (from, to) in [(a, b), (b, a)] {
                if breaking(to) && labels[from as usize] != labels[to as usize] {
                    path_mask[labels[from as usize].0 as usize] |= types.of(NetId(to)) & !exclude;
                }
            }
        }
        let (net_cond, path_cond) = (
            condition_masks(types, &table.net[row]),
            condition_masks(types, &table.path[row]),
        );
        let flagged: Vec<u32> = examined
            .iter()
            .copied()
            .filter(|&net| meets(types.of(NetId(net)), net_cond))
            .filter(|&net| meets(path_mask[labels[net as usize].0 as usize], path_cond))
            .collect();
        push_net_violations(
            design,
            &flagged,
            rule,
            table.head.severity[row],
            Measurement::Count(1),
            Measurement::Count(0),
            out,
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined.len() as u64);
    }
}

/// A combinational loop: deck kind `combinational_loop`, written
/// `combinational_loop()`.
///
/// The transistor netlist is cut into channel-connected components
/// (Bryant, ICCAD '91: "each consisting of a set of storage nodes connected
/// by the source-drain terminals of transistors"): nets joined through MOS
/// source and drain pins, never through a declared supply, which is an
/// input, not a storage node. A transistor belongs to the component of its
/// channel's non-supply ends. A component drives another when one of its
/// nets is the gate of a transistor in the other. A loop is a cycle of that
/// relation: a strongly connected set of two or more components, or one
/// component driving itself. This is [Yosys `check`]'s "found logic loop", a
/// cycle in the combinational dependency graph, with the component as the
/// cell. Needs design intent, for which nets are the supplies.
///
/// # Limits
///
/// Every cycle is reported: a latch, a register's keeper or an SRAM cell
/// (cross-coupled inverters) is a loop, as Yosys reports a latch built from
/// gates, and so is a transistor whose gate is on its own drain (a diode-
/// connected device). Only MOS channels make components; a resistor or a
/// pass device of another kind does not join them.
///
/// Catalog: ERC-G8 in the [check catalog]. Defined by [Yosys `check`]
/// (logic loops); [Bryant 1991] (channel-connected components and their
/// rank order). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [Yosys `check`]: https://yosyshq.readthedocs.io/projects/yosys/en/latest/cmd/index_passes_status.html
/// [Bryant 1991]: https://www.cs.cmu.edu/~bryant/pubdir/iccad91.pdf
#[derive(Debug, Default, Clone, PartialEq)]
pub struct CombinationalLoopTable {
    /// Rule id and severity per row. Rows differ only in id and severity.
    pub head: RuleHead,
}

/// Runs every [`CombinationalLoopTable`] row.
///
/// `examined` counts channel-connected components. A loop is one violation
/// at the first vertex of the lowest-numbered polygon of its lowest net, on
/// its layer, measuring the components in the loop against 0. Every row is
/// skipped when no design intent was given or it declares no supply this
/// layout has.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_combinational_loop(
    design: Design<'_>,
    intent: &IntentMap,
    table: &CombinationalLoopTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if intent.supply_net.is_empty() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let count = design.nets.net_count();
    let rail = |net: NetId| intent.supply_net.binary_search(&net).is_ok();
    let devices = design.devices;
    // Per MOS: its gate net and its channel's non-rail ends.
    let mut gate_of: Vec<Option<u32>> = Vec::new();
    let mut ends_of: Vec<Vec<u32>> = Vec::new();
    for device in 0..devices.len() {
        if devices.kind[device] != DeviceKind::Mos {
            continue;
        }
        let id = device_id(device);
        let (nets, roles) = devices.terminals_of(id);
        let mut gate = None;
        let mut ends = Vec::new();
        for (&net, &role) in nets.iter().zip(roles) {
            if net == NetId::NONE || net.idx() >= count {
                continue;
            }
            match role {
                TerminalRole::Gate if gate.is_none() => gate = Some(net.0),
                TerminalRole::Source | TerminalRole::Drain if !rail(net) => ends.push(net.0),
                _ => {}
            }
        }
        gate_of.push(gate);
        ends_of.push(ends);
    }
    let joins: Vec<(u32, u32)> = ends_of
        .iter()
        .filter_map(|ends| match ends[..] {
            [a, b] => Some((a, b)),
            _ => None,
        })
        .collect();
    let mut labels = Vec::new();
    components_into(
        u32::try_from(count).expect("a net count fits a u32"),
        &joins,
        &mut labels,
    );
    // Components are the labels of channel ends; number them densely.
    let mut component = vec![u32::MAX; count];
    let mut components = 0u32;
    for ends in &ends_of {
        for &net in ends {
            let root = labels[net as usize].0 as usize;
            if component[root] == u32::MAX {
                component[root] = components;
                components += 1;
            }
        }
    }
    let of_net = |net: u32| {
        let c = component[labels[net as usize].0 as usize];
        (c != u32::MAX && !rail(NetId(net))).then_some(c)
    };
    // Driver component -> driven component, deduplicated, CSR.
    let mut arcs: Vec<(u32, u32)> = gate_of
        .iter()
        .zip(&ends_of)
        .filter_map(|(&gate, ends)| {
            let from = of_net(gate?)?;
            let to = of_net(*ends.first()?)?;
            Some((from, to))
        })
        .collect();
    arcs.sort_unstable();
    arcs.dedup();
    let n = components as usize;
    let scc = strongly_connected(n, &arcs);
    let mut size = vec![0u32; n];
    for &s in &scc {
        size[s as usize] += 1;
    }
    let mut looping: Vec<bool> = size.iter().map(|&k| k > 1).collect();
    for &(a, b) in &arcs {
        if a == b {
            looping[scc[a as usize] as usize] = true;
        }
    }
    // The lowest net of each looping component group.
    let mut lowest = vec![u32::MAX; n];
    for net in 0..u32::try_from(count).expect("a net count fits a u32") {
        if let Some(c) = of_net(net) {
            let s = scc[c as usize] as usize;
            lowest[s] = lowest[s].min(net);
        }
    }
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        for s in (0..n).filter(|&s| looping[s]) {
            push_net_violations(
                design,
                &[lowest[s]],
                rule,
                table.head.severity[row],
                Measurement::Count(size[s]),
                Measurement::Count(0),
                out,
            );
        }
        record_run(runs, out, before, rule, Outcome::Ran, u64::from(components));
    }
}

/// Kosaraju's strongly connected components of a graph on `n` nodes given
/// as sorted, deduplicated arcs: each node's component, numbered by the
/// order the second pass finds them.
fn strongly_connected(n: usize, arcs: &[(u32, u32)]) -> Vec<u32> {
    let csr = |pairs: &mut Vec<(u32, u32)>| {
        pairs.sort_unstable();
        let mut start = vec![0usize; n + 1];
        for &(a, _) in pairs.iter() {
            start[a as usize + 1] += 1;
        }
        for i in 0..n {
            start[i + 1] += start[i];
        }
        let to: Vec<u32> = pairs.iter().map(|&(_, b)| b).collect();
        (start, to)
    };
    let (fwd_start, fwd) = csr(&mut arcs.to_vec());
    let (rev_start, rev) = csr(&mut arcs.iter().map(|&(a, b)| (b, a)).collect());
    // First pass: finishing order, iteratively.
    let mut order = Vec::with_capacity(n);
    let mut seen = vec![false; n];
    for root in 0..n {
        if seen[root] {
            continue;
        }
        seen[root] = true;
        let mut stack = vec![(root, fwd_start[root])];
        while let Some(&mut (node, ref mut next)) = stack.last_mut() {
            if *next < fwd_start[node + 1] {
                let to = fwd[*next] as usize;
                *next += 1;
                if !seen[to] {
                    seen[to] = true;
                    stack.push((to, fwd_start[to]));
                }
            } else {
                order.push(node);
                stack.pop();
            }
        }
    }
    // Second pass on the reversed graph, in reverse finishing order.
    let mut scc = vec![u32::MAX; n];
    let mut found = 0u32;
    for &root in order.iter().rev() {
        if scc[root] != u32::MAX {
            continue;
        }
        scc[root] = found;
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            for &to in &rev[rev_start[node]..rev_start[node + 1]] {
                if scc[to as usize] == u32::MAX {
                    scc[to as usize] = found;
                    stack.push(to as usize);
                }
            }
        }
        found += 1;
    }
    scc
}
