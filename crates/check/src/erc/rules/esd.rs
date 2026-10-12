//! ESD discharge paths: the network an ESD current is forced through, from a
//! pad to each supply its clamps reach, solved for the pin's voltage, the
//! path's resistance and the current each clamp, wire and cut carries; and
//! the coupling between ground domains, alone and where a signal crosses
//! from one power domain to another; the parasitic paths a pad's junctions
//! open to other nets; and the devices a pad exposes.
//!
//! Data in: the store, nets, devices, the deck's process stack and
//! connectivity, the design intent's supplies. Data out: violations and one
//! run per row. Every kind skips without intent, which names the rails.

use crate::erc::facts::IntentMap;
use crate::erc::power::{
    extract_stress_into, solve_into, EdgeKind, PowerSolution, Process, Stress, StressGrid,
};
use crate::erc::rules::domain::{device_id, push_device, terminal};
use crate::erc::rules::electrical::allowed_current;
use crate::erc::rules::latchup::{pad_nets, poly_dist2};
use crate::erc::rules::supply::{clamp_rails, clamp_reach_into, reverse_biased};
use crate::erc::ruleset::RuleHead;
use crate::erc::voltage::NetVoltage;
use crate::erc::{first_vertex, push_net_violations, record_run, skip_rows, Design, Scratch};
use crate::report::{LimitSense, Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use crate::topology::device::{DeviceMeasure, DeviceParam};
use crate::topology::{DeviceId, NetId, TerminalRole};
use gpurify_geom::connectivity::{components_into, ComponentLabel};
use gpurify_geom::ops::{isqrt, winding_of, Winding};
use gpurify_geom::{prefix, Current, CurrentDensity, Grid, Qty, Resistance, Voltage};
use gpurify_geom::{Dbu, LayerId, PolyId};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::intent::SupplyRole;
use gpurify_ingest::StrId;

/// ESD discharge path under a forced current: deck kind `esd_path`, written
/// `esd_path(pad[, source]; clamps: models | none, current: current,
/// clamp_resistance: resistance, max_resistance: resistance | none,
/// clamp_it2: current per width | none, max_density: current per width |
/// none, max_current_per_cut: current | none, max_voltage: voltage | none)`.
///
/// Each polygon on `source` (`pad` when absent) is where a stress current
/// enters: a pin, or with a source layer a guard ring under an injection
/// stress (JESD78's I-test, ±100 mA, with `clamps: none`, so the current
/// flows to the ring's own supply's pins). Its net reaches
/// supplies through clamps as [`EsdTopologicalTable`] defines the path (a
/// clamp from the pad to a declared supply, then rail clamps; a
/// forward-biased diode is no clamp). For every declared supply it reaches,
/// that supply's own net included when the pin is on one, `current` is
/// forced in at the pin and out at the supply's pins: its polygons on `pad`,
/// each held at 0 V, or with none, its feed point (the centre of its highest,
/// then widest, shape). The current flows through the network of every net
/// on the path: each conductor a chain of resistors as
/// [`P2pResistanceTable`] models one, and each clamp `clamp_resistance` (its
/// on-resistance) between its attach points on every two path nets it
/// touches, so parallel clamps share the current. One pin and one supply is
/// one pin pair of JS-001, one row of TR18-01 Fig. 58.
///
/// A row flags a pin pair whose path resistance, the pin's voltage over the
/// forced current, is above `max_resistance`, and one whose pin rises above
/// `max_voltage`: the ESD design window, where the voltage the stress
/// develops must stay below the failure voltage of what the pin reaches. It
/// flags a clamp that carries more of the current than `clamp_it2` (its
/// second-breakdown current per unit size) times its size: a transistor's
/// width, any other device's perimeter, the junction edge a diode's current
/// crosses. A clamp joining
/// three or more path nets carries the largest current of its pairs. It
/// flags a wire segment on the path that carries more than `max_density`
/// times its width (the narrowest width its cross-section finds), and a via
/// cut that carries more than `max_current_per_cut`: the interconnect's
/// rating for the ESD pulse, which a foundry states apart from its DC
/// electromigration limits. A limit written `none` is not checked; a row must
/// state one.
///
/// # Limits
///
/// Pairs are pin to supply: two signal pins are stressed against each other
/// only through the supplies between them, not as a pair. A clamp is linear,
/// its on-resistance alone: a diode's turn-on or a snapback clamp's holding
/// voltage is not modelled, and a transistor clamp is taken as wired whatever
/// its gate is tied to. So `max_voltage` bounds the interconnect's and the
/// clamps' resistive rise only; a deck folds a clamp's holding voltage into
/// it (the protected device's failure voltage less the clamp's holding
/// voltage). The pin's voltage is checked, not each device's own terminals.
///
/// Catalog: ERC-C2, ERC-C6, ERC-C7, ERC-C8, ERC-D4 in the [check catalog]. Defined by
/// [ESDA TR18.0-01] §2.1, Fig. 23, Fig. 24 and Fig. 58; [ESDA TR22] §4.1
/// and §8 (the design window), §4.4 (ESD current density); [ESDA TR18.0-02] Fig. 21
/// and §2.3 (guard-ring resistance under injection); [JESD78] Table 1;
/// [JS-001] Tables 2A and 2B (the pin pairs); [Khazhinsky 2012] Fig. 2
/// ("large resistances in the ESD current path"), Fig. 4 (node voltages
/// under a forced 1.33 A HBM current) and "minimum ESD metal width"; [Hogan 2012] §III ("ESD
/// components widths"); [GF180MCU] §14.5 (It2 per µm of width for each ESD
/// device, and "Vt2 ... always lower than the max allowed voltage at that
/// node"); Calibre PERC, IC Validator, Voltus and `PathFinder` (public
/// material only).
/// Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [ESDA TR18.0-01]: https://www.esda.org/store/standards/product/457/esd-tr18-0-01-25/
/// [ESDA TR18.0-02]: https://www.esda.org/store/standards/product/307/esd-tr18-0-02-20/
/// [ESDA TR22]: https://www.esda.org/store/standards/product/72/esd-tr22-0-01-14
/// [JESD78]: https://www.jedec.org/standards-documents/docs/jesd-78b
/// [JS-001]: https://www.jedec.org/sites/default/files/JTR001-01-12%20Final.pdf
/// [Khazhinsky 2012]: https://www.esda.org/assets/News/8df611267c/ESDEDA-InCompliance-part1.pdf
/// [Hogan 2012]: https://www.esda.org/assets/News/ESDEDA-InCompliance-part2.pdf
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
/// [`EsdTopologicalTable`]: crate::erc::rules::supply::EsdTopologicalTable
/// [`P2pResistanceTable`]: crate::erc::rules::electrical::P2pResistanceTable
#[derive(Debug, Default, Clone, PartialEq)]
pub struct EsdPathTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the layer whose polygons are pins.
    pub pad: Vec<LayerId>,
    /// Per row: the layer whose polygons the current enters at; `pad`'s when
    /// the deck names none.
    pub source: Vec<LayerId>,
    /// Clamp device models per row, CSR.
    pub clamp_start: Vec<u32>,
    /// Clamp models, CSR by `clamp_start`; none leaves only the source's
    /// own supply reachable.
    pub clamp: Vec<StrId>,
    /// Per row: the stress current, µA. Positive from a deck.
    pub current: Vec<Qty<Current, { prefix::MICRO }>>,
    /// Per row: one clamp's on-resistance between two of its nets, Ω.
    /// Positive from a deck.
    pub clamp_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
    /// Per row: the largest path resistance, Ω; `None` is not checked.
    pub max_resistance: Vec<Option<Qty<Resistance, { prefix::BASE }>>>,
    /// Per row: a clamp's rated current per unit of its size, A/m; `None` is
    /// not checked.
    pub clamp_it2: Vec<Option<Qty<CurrentDensity, { prefix::BASE }>>>,
    /// Per row: a wire's rated pulse current per unit width, A/m; `None` is
    /// not checked.
    pub max_density: Vec<Option<Qty<CurrentDensity, { prefix::BASE }>>>,
    /// Per row: a via cut's rated pulse current, µA; `None` is not checked.
    pub max_current_per_cut: Vec<Option<Qty<Current, { prefix::MICRO }>>>,
    /// Per row: the highest voltage a pin may rise to under the stress, mV;
    /// `None` is not checked.
    pub max_voltage: Vec<Option<Qty<Voltage, { prefix::MILLI }>>>,
}

/// Runs every [`EsdPathTable`] row over every pin.
///
/// `examined` counts pin pairs solved. A resistance or voltage violation sits
/// at the first vertex of the source polygon, on its layer, names it and the
/// supply's first held shape, and measures the path resistance in Ω against
/// `max_resistance`, or the source's voltage in mV against `max_voltage`. A
/// clamp violation sits at the first vertex of the clamp's marker, on its
/// layer, names the marker and the source, and measures the clamp's current
/// in µA against its rating. A wire or cut violation sits at the segment's
/// first node, on its layer, names the shapes at both ends, and measures its
/// current in µA against its rating. Every row is skipped without usable
/// intent. A row is refused at the first pair whose network cannot be built
/// (a conductor with no sheet resistance) or solved (a piece of a path net
/// only a global layer joins), or with `clamp_it2`, whose clamps include one
/// with no measured size; violations it found before that stay in `out`.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_esd_path(
    design: Design<'_>,
    intent: &IntentMap,
    process: Process<'_>,
    table: &EsdPathTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let (store, nets, devices) = (design.store, design.nets, design.devices);
    let (mut seen, mut stack, mut path) = (Vec::new(), Vec::new(), Vec::new());
    let mut clamp_devices: Vec<DeviceId> = Vec::new();
    let mut pins: Vec<PolyId> = Vec::new();
    let mut stress = StressGrid::default();
    let mut solution = PowerSolution::default();
    for row in 0..table.head.len() {
        let before = out.len();
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        let clamps =
            &table.clamp[table.clamp_start[row] as usize..table.clamp_start[row + 1] as usize];
        let pad_layer = table.pad[row];
        let current = table.current[row];
        let max_resistance = table.max_resistance[row].map(Measurement::Resistance);
        let max_voltage = table.max_voltage[row].map(Measurement::Voltage);
        let mut examined = 0u64;
        let mut outcome = Outcome::Ran;
        let source_layer = table.source[row];
        'pins: for poly in store.polys_on_layer(source_layer) {
            let source = PolyId(poly);
            let net = nets.net_of(source);
            if net == NetId::NONE || nets.holes.is_hole(source) {
                continue;
            }
            clamp_reach_into(
                design, intent, clamps, net, &mut seen, &mut stack, &mut path,
            );
            path.sort_unstable();
            // Every clamp joining two path nets carries part of the current.
            clamp_devices.clear();
            for &on in &path {
                clamp_devices.extend(devices.devices_on(on).iter().copied().filter(|&d| {
                    clamps.contains(&devices.model[d.0 as usize])
                        && reverse_biased(design, intent, d)
                }));
            }
            clamp_devices.sort_unstable();
            clamp_devices.dedup();

            for &target in &path {
                if intent.supply_net.binary_search(&target).is_err() {
                    continue;
                }
                pins.clear();
                pins.extend(
                    nets.polys_of(target)
                        .iter()
                        .copied()
                        .filter(|&p| store.poly_layer(p) == pad_layer && !nets.holes.is_hole(p)),
                );
                let built = extract_stress_into(
                    store,
                    nets,
                    devices,
                    process,
                    Stress {
                        nets: &path,
                        source,
                        current,
                        sink: target,
                        pins: &pins,
                        devices: &clamp_devices,
                        device_resistance: table.clamp_resistance[row],
                    },
                    &mut stress,
                );
                if built.is_err()
                    || solve_into(&stress.grid, &mut scratch.solve, &mut solution).is_err()
                {
                    outcome = Outcome::Refused;
                    break 'pins;
                }
                examined += 1;
                let grid = &stress.grid;
                let held = grid.node_poly[grid.source_node[0] as usize];
                let mut push = |measured, limit| {
                    out.push(Violation {
                        rule,
                        layer: source_layer,
                        severity,
                        at: first_vertex(store, source),
                        measured,
                        limit,
                        shapes: (source, Some(held)),
                    });
                };
                // Ohm's law in the grid's units: mV * 1000 / µA is Ω.
                let volts = solution.node_voltage[stress.entry as usize];
                let ohms = Measurement::Resistance(Qty::new(volts.raw() * 1000.0 / current.raw()));
                if let Some(limit) = max_resistance {
                    if ohms.violates(limit, LimitSense::Maximum) {
                        push(ohms, limit);
                    }
                }
                let rise = Measurement::Voltage(volts);
                if let Some(limit) = max_voltage {
                    if rise.violates(limit, LimitSense::Maximum) {
                        push(rise, limit);
                    }
                }
                if let Some(it2) = table.clamp_it2[row] {
                    let pair = Pair {
                        source,
                        stress: &stress,
                        solution: &solution,
                    };
                    if !clamp_capacity(design, process.grid, pair, it2, (rule, severity), out) {
                        outcome = Outcome::Refused;
                        break 'pins;
                    }
                }
                let rating = (table.max_density[row], table.max_current_per_cut[row]);
                interconnect_capacity(&stress, &solution, process, rating, (rule, severity), out);
            }
        }
        record_run(runs, out, before, rule, outcome, examined);
    }
}

/// One solved pin pair: where the current entered, and the network's solve.
#[derive(Clone, Copy)]
struct Pair<'a> {
    source: PolyId,
    stress: &'a StressGrid,
    solution: &'a PowerSolution,
}

/// Holds every clamp of a solved pair to `it2` times its size (a
/// transistor's width, any other device's perimeter), pushing one violation
/// per clamp over it, at its marker. `false`, pushing nothing, when a clamp of
/// the network has no measured size.
fn clamp_capacity(
    design: Design<'_>,
    grid: Grid,
    pair: Pair<'_>,
    it2: Qty<CurrentDensity, { prefix::BASE }>,
    head: (StrId, Severity),
    out: &mut Violations,
) -> bool {
    let (store, devices) = (design.store, design.devices);
    let stress = pair.stress;
    // Device edges come last, each clamp's pairs together.
    let first = stress.grid.edge_count() - stress.device.len();
    let mut carried: Vec<(DeviceId, f64)> = Vec::new();
    for (k, &device) in stress.device.iter().enumerate() {
        let amps = pair.solution.branch_current[first + k].raw().abs();
        match carried.last_mut() {
            Some(last) if last.0 == device => last.1 = last.1.max(amps),
            _ => carried.push((device, amps)),
        }
    }
    // Every rating before anything is pushed.
    let mut rated = Vec::with_capacity(carried.len());
    for &(device, _) in &carried {
        let size = if devices.kind[device.0 as usize] == DeviceKind::Mos {
            DeviceParam::Width
        } else {
            DeviceParam::Perimeter
        };
        let measured =
            devices
                .params_of(device)
                .iter()
                .find_map(|&(param, measure)| match measure {
                    DeviceMeasure::Length(length) if param == size => Some(length),
                    _ => None,
                });
        let Some(length) = measured else {
            return false;
        };
        // `A/m * m = A`, on base values.
        rated.push(
            Qty::<Current, { prefix::BASE }>::new(it2.raw() * grid.to_length(length).base())
                .to::<{ prefix::MICRO }>(),
        );
    }
    for (&(device, amps), &allowed) in carried.iter().zip(&rated) {
        let measured = Measurement::Current(Qty::new(amps));
        let limit = Measurement::Current(allowed);
        if measured.violates(limit, LimitSense::Maximum) {
            let marker = devices.marker[device.0 as usize];
            out.push(Violation {
                rule: head.0,
                layer: store.poly_layer(marker),
                severity: head.1,
                at: first_vertex(store, marker),
                measured,
                limit,
                shapes: (marker, Some(pair.source)),
            });
        }
    }
    true
}

/// Holds every wire segment and via cut of a solved pair to its pulse rating:
/// `density` times the segment's width, `per_cut` per cut. One violation per
/// segment or cut over it, at its first node.
fn interconnect_capacity(
    stress: &StressGrid,
    solution: &PowerSolution,
    process: Process<'_>,
    (density, per_cut): (
        Option<Qty<CurrentDensity, { prefix::BASE }>>,
        Option<Qty<Current, { prefix::MICRO }>>,
    ),
    head: (StrId, Severity),
    out: &mut Violations,
) {
    let grid = &stress.grid;
    for edge in 0..grid.edge_count() {
        let kind = grid.edge_kind[edge];
        let allowed = match (kind, density, per_cut) {
            (EdgeKind::Metal, Some(density), _) => {
                // The per-cut limit is not read for metal.
                allowed_current(
                    kind,
                    grid.edge_width[edge],
                    process.grid,
                    density,
                    Qty::new(0.0),
                    None,
                )
            }
            (EdgeKind::Via, _, Some(per_cut)) => per_cut,
            _ => continue,
        };
        let measured = Measurement::Current(Qty::new(solution.branch_current[edge].raw().abs()));
        let limit = Measurement::Current(allowed);
        if !measured.violates(limit, LimitSense::Maximum) {
            continue;
        }
        let (from, to) = (grid.edge_from[edge] as usize, grid.edge_to[edge] as usize);
        out.push(Violation {
            rule: head.0,
            layer: grid.edge_layer[edge],
            severity: head.1,
            at: grid.node_at[from],
            measured,
            limit,
            shapes: (grid.node_poly[from], Some(grid.node_poly[to])),
        });
    }
}

/// Ground domains coupled for ESD: deck kind `esd_ground_coupling`, written
/// `esd_ground_coupling(; diodes: models)`.
///
/// Two declared ground supplies are coupled when a diode of a listed model
/// has its anode (`Pin(0)`) on one and its cathode (`Pin(1)`) on the other,
/// and another the other way round: an anti-parallel pair, which carries an
/// ESD current between the grounds in either direction and, holding them
/// within a diode drop, nothing in operation. Coupling is transitive: grounds
/// joined by a chain of pairs are one group, as each domain's ground is
/// coupled to a common ground in TR18-01 Fig. 5. Every ground-to-ground pin
/// pair needs a discharge path, so the declared grounds must form one group:
/// a row flags each group but the one holding the lowest-numbered ground, at
/// that group's lowest-numbered ground, so `k` groups are `k - 1` findings.
/// Needs design intent, for which nets are the grounds.
///
/// # Limits
///
/// Only diodes couple: a ground pair joined through another clamp, a
/// resistor or a shared substrate is not coupled here.
///
/// Catalog: ERC-C5 in the [check catalog]. Defined by [ESDA TR18.0-01] Fig.
/// 5; [Hogan 2012] Fig. 1 (the anti-parallel diodes ESD2 between VSS1 and
/// VSS2) and §IV ("which ground domains need interface protections");
/// [Khazhinsky 2012] Fig. 2 (a missing ESD device between two ground
/// domains). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [ESDA TR18.0-01]: https://www.esda.org/store/standards/product/457/esd-tr18-0-01-25/
/// [Hogan 2012]: https://www.esda.org/assets/News/ESDEDA-InCompliance-part2.pdf
/// [Khazhinsky 2012]: https://www.esda.org/assets/News/8df611267c/ESDEDA-InCompliance-part1.pdf
#[derive(Debug, Default, Clone, PartialEq)]
pub struct EsdGroundCouplingTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Coupling diode models per row, CSR.
    pub diode_start: Vec<u32>,
    /// Diode models, CSR by `diode_start`; at least one per row.
    pub diode: Vec<StrId>,
}

/// Each declared supply row's coupling group: ground rows joined by
/// anti-parallel pairs of `diodes` models (and chains of them) share a label;
/// every other row is alone.
pub(crate) fn coupling_groups(
    design: Design<'_>,
    intent: &IntentMap,
    diodes: &[StrId],
    labels: &mut Vec<ComponentLabel>,
) {
    let devices = design.devices;
    let ground_row = |net: NetId| {
        intent
            .supply_net
            .binary_search(&net)
            .ok()
            .filter(|&row| intent.supply_role[row] == SupplyRole::Ground)
    };
    // Every diode between two ground rows, as `(anode row, cathode row)`.
    let mut directed: Vec<(u32, u32)> = Vec::new();
    for index in 0..devices.len() {
        if devices.kind[index] != DeviceKind::Diode || !diodes.contains(&devices.model[index]) {
            continue;
        }
        let device = DeviceId(u32::try_from(index).expect("a device table indexes with u32"));
        let (on, roles) = devices.terminals_of(device);
        let pin = |k: u8| {
            on.iter()
                .zip(roles)
                .find(|&(_, &role)| role == TerminalRole::Pin(k))
                .and_then(|(&net, _)| ground_row(net))
        };
        if let (Some(anode), Some(cathode)) = (pin(0), pin(1)) {
            if anode != cathode {
                let row = |r: usize| u32::try_from(r).expect("a supply row is a u32");
                directed.push((row(anode), row(cathode)));
            }
        }
    }
    directed.sort_unstable();
    directed.dedup();
    let pairs: Vec<(u32, u32)> = directed
        .iter()
        .copied()
        .filter(|&(a, c)| directed.binary_search(&(c, a)).is_ok())
        .collect();
    let rows = u32::try_from(intent.supply_net.len()).expect("a supply row is a u32");
    components_into(rows, &pairs, labels);
}

/// Runs every [`EsdGroundCouplingTable`] row over the declared grounds.
///
/// `examined` counts declared ground supplies. A violation sits at the first
/// vertex of the flagged ground's lowest-numbered polygon, on its layer,
/// measuring the count of anti-parallel paths from its group to the first
/// ground's, 0, against 1. Every row is skipped without usable intent.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_esd_ground_coupling(
    design: Design<'_>,
    intent: &IntentMap,
    table: &EsdGroundCouplingTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let mut labels = Vec::new();
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let diodes =
            &table.diode[table.diode_start[row] as usize..table.diode_start[row + 1] as usize];
        coupling_groups(design, intent, diodes, &mut labels);
        let grounds: Vec<usize> = (0..intent.supply_net.len())
            .filter(|&r| intent.supply_role[r] == SupplyRole::Ground)
            .collect();
        // Rows ascend by net, so a group's first row is its lowest ground.
        let mut groups: Vec<ComponentLabel> = Vec::new();
        let mut flagged: Vec<u32> = Vec::new();
        for &r in &grounds {
            if !groups.contains(&labels[r]) {
                if !groups.is_empty() {
                    flagged.push(intent.supply_net[r].0);
                }
                groups.push(labels[r]);
            }
        }
        push_net_violations(
            design,
            &flagged,
            rule,
            table.head.severity[row],
            Measurement::Count(0),
            Measurement::Count(1),
            out,
        );
        let examined = u64::try_from(grounds.len()).expect("a supply count fits a u64");
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// A signal crossing between power domains, protected for ESD: deck kind
/// `esd_cross_domain`, written `esd_cross_domain(; diodes: models, local:
/// models | none)`.
///
/// A receiver is a transistor whose gate a power domain reaches that reaches
/// neither end of its channel (as [`MissingLevelShifterTable`] finds a
/// crossing): the net from its driver crosses into another domain. When one
/// domain's pad is struck against the other's ground, the stress lands across
/// the receiver's gate oxide unless the two grounds are joined: TR18-01 check
/// 5.1.3 asks for anti-parallel diodes between them. A row flags a receiver
/// when a ground domain reaching its gate (the driver's ground) and one
/// reaching its channel (its own) are not coupled as
/// [`EsdGroundCouplingTable`] couples grounds. With `local`, a row also
/// flags a receiver with no local clamp: no device of a `local` model with
/// one terminal on its gate's net and another on a ground of its own domain,
/// the clamp at the interface gate oxide that holds a charged-device
/// discharge off it ("diodes connected to an interface gate oxide",
/// Khazhinsky 2012). A receiver whose gate or channel no ground reaches is
/// not examined. Needs design intent.
///
/// # Limits
///
/// The ground coupling of TR18-01 5.1.3 and the local clamp are checked; a
/// series resistor at the receiver, the resistance between the driver's and
/// the receiver's grounds, and the bus inductance a CDM discharge sees are
/// not. A local clamp is any device of a listed model so wired, whichever way
/// round. Voltages reach a net as [`NetVoltage`] propagates them, through
/// every channel whatever its gate.
///
/// Catalog: ERC-C4, ERC-C9 in the [check catalog]. Defined by
/// [ESDA TR18.0-01] (2011) check 5.1.3, §5.6.2 and §5.6.3 (CDM); [Hogan 2012]
/// §II and its pseudocode ("IF different power domains THEN check for
/// anti-parallel diodes"), Fig. 1; [Khazhinsky 2012] Fig. 5 and its
/// "protection measures already implemented at power domain boundaries
/// (diodes connected to an interface gate oxide, etc.)". Source tags are in
/// [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [ESDA TR18.0-01]: https://www.esda.org/store/standards/product/457/esd-tr18-0-01-25/
/// [Hogan 2012]: https://www.esda.org/assets/News/ESDEDA-InCompliance-part2.pdf
/// [Khazhinsky 2012]: https://www.esda.org/assets/News/8df611267c/ESDEDA-InCompliance-part1.pdf
/// [`MissingLevelShifterTable`]: crate::erc::rules::domain::MissingLevelShifterTable
#[derive(Debug, Default, Clone, PartialEq)]
pub struct EsdCrossDomainTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Coupling diode models per row, CSR.
    pub diode_start: Vec<u32>,
    /// Diode models, CSR by `diode_start`; at least one per row.
    pub diode: Vec<StrId>,
    /// Local clamp models per row, CSR.
    pub local_start: Vec<u32>,
    /// Local clamp models, CSR by `local_start`; none checks no local clamp.
    pub local: Vec<StrId>,
}

/// Runs every [`EsdCrossDomainTable`] row over every transistor.
///
/// `examined` counts receivers whose gate and channel some ground reaches. A
/// violation sits at the first vertex of the receiver's marker, on the marker
/// layer, measuring the coupled ground pairs, or the local clamps, 0, against
/// 1; a receiver can be flagged once for each. Every row is skipped without
/// usable intent.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_esd_cross_domain(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &EsdCrossDomainTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let devices = design.devices;
    let mut labels = Vec::new();
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let diodes =
            &table.diode[table.diode_start[row] as usize..table.diode_start[row + 1] as usize];
        let local =
            &table.local[table.local_start[row] as usize..table.local_start[row + 1] as usize];
        coupling_groups(design, intent, diodes, &mut labels);
        // Two ground domains are coupled when a ground of each is in one group.
        let coupled = |a: u32, b: u32| {
            let of = |domain: u32| {
                (0..intent.supply_net.len()).filter(move |&r| {
                    intent.supply_role[r] == SupplyRole::Ground
                        && intent.supply_domain[r].0 == domain
                })
            };
            a == b || of(a).any(|ra| of(b).any(|rb| labels[ra] == labels[rb]))
        };
        let bits = |mask: u64| (0..64u32).filter(move |&d| (mask >> d) & 1 == 1);
        let mut examined = 0u64;
        for index in 0..devices.len() {
            if devices.kind[index] != DeviceKind::Mos {
                continue;
            }
            let (nets, roles) = devices.terminals_of(device_id(index));
            let gate = terminal(nets, roles, TerminalRole::Gate);
            let ends = [
                terminal(nets, roles, TerminalRole::Source),
                terminal(nets, roles, TerminalRole::Drain),
            ];
            let gate_power = voltage.power_of(gate);
            let channel_power = voltage.power_of(ends[0]) | voltage.power_of(ends[1]);
            if gate_power == 0 || channel_power == 0 || gate_power & !channel_power == 0 {
                continue;
            }
            let driver = voltage.ground_of(gate);
            let receiver = voltage.ground_of(ends[0]) | voltage.ground_of(ends[1]);
            if driver == 0 || receiver == 0 {
                continue;
            }
            examined += 1;
            let protected = bits(driver).all(|a| bits(receiver).all(|b| coupled(a, b)));
            let severity = table.head.severity[row];
            let (measured, limit) = (Measurement::Count(0), Measurement::Count(1));
            if !protected {
                push_device(design, index, rule, severity, measured, limit, out);
            }
            // A ground of the receiver's own domain: a local clamp's far end.
            let own_ground = |net: NetId| {
                intent.supply_net.binary_search(&net).is_ok_and(|r| {
                    intent.supply_role[r] == SupplyRole::Ground
                        && (receiver >> intent.supply_domain[r].0) & 1 == 1
                })
            };
            let clamped = local.is_empty()
                || devices.devices_on(gate).iter().any(|&d| {
                    local.contains(&devices.model[d.0 as usize])
                        && devices.terminals_of(d).0.iter().any(|&n| own_ground(n))
                });
            if !clamped {
                push_device(design, index, rule, severity, measured, limit, out);
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// A parasitic ESD path from a pad's junction to another net: deck kind
/// `esd_parasitic`, written `esd_parasitic(pad, diffusion; min_spacing:
/// len)`.
///
/// A diffusion on a pad net beside a diffusion on another net forms a
/// parasitic bipolar (or a field device) between the two: under an ESD
/// stress at the pad it can conduct, an unintended discharge path through
/// whatever the other net is. A row flags every pair of `diffusion`
/// polygons, one on a pad net (a net that holds a polygon of `pad`) and the
/// other on any other net, closer than `min_spacing` (Euclidean, compared
/// exactly). Two polygons of one net are no parasitic path. Needs no design
/// intent; `diffusion` must conduct, so its polygons carry nets.
///
/// # Limits
///
/// The spacing a parasitic device needs is a foundry's, under NDA; no open
/// manual states one, so a deck names its own. Spacing alone decides: what
/// lies between the two junctions (a guard ring) is not read.
///
/// Catalog: ERC-C10 in the [check catalog]. Defined by [ESDA TR18.0-01]
/// §5.6.1; [Khazhinsky 2012] (the layout checker "could flag ... parasitic
/// bipolars"); [GF180MCU] §14.4 ("all possible current paths, both
/// intentional and parasitic paths"). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [ESDA TR18.0-01]: https://www.esda.org/store/standards/product/457/esd-tr18-0-01-25/
/// [Khazhinsky 2012]: https://www.esda.org/assets/News/8df611267c/ESDEDA-InCompliance-part1.pdf
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
#[derive(Debug, Default, Clone, PartialEq)]
pub struct EsdParasiticTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the pad layer whose nets are pad nets.
    pub pad: Vec<LayerId>,
    /// Per row: the junction (diffusion) layer.
    pub diffusion: Vec<LayerId>,
    /// Per row: the least spacing from a pad's junction to another net's,
    /// database units.
    pub min_spacing: Vec<Dbu>,
}

/// Runs every [`EsdParasiticTable`] row over every pad junction.
///
/// `examined` counts diffusion polygons on pad nets. A violation sits at the
/// first vertex of the pad's junction (the lower-numbered one when both are
/// on pad nets), on the diffusion layer, names both polygons, and measures
/// their distance, rounded down to a database unit, against `min_spacing`.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_esd_parasitic(
    design: Design<'_>,
    table: &EsdParasiticTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let (store, nets) = (design.store, design.nets);
    for row in 0..table.head.len() {
        let before = out.len();
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        let layer = table.diffusion[row];
        let min = table.min_spacing[row];
        let min2 = min.mul_wide(min);
        let pads = pad_nets(design, table.pad[row]);
        let junctions: Vec<PolyId> = store
            .polys_on_layer(layer)
            .map(PolyId)
            .filter(|&poly| {
                let (xs, ys) = store.poly_verts(poly);
                winding_of(xs, ys) != Some(Winding::Clockwise)
            })
            .collect();
        // No pad net, no net to look up: an unextracted design has none.
        let on_pad =
            |poly: PolyId| !pads.is_empty() && pads.binary_search(&nets.net_of(poly)).is_ok();
        let mut examined = 0u64;
        // ponytail: every pad junction against every junction; a spatial
        // index if pads drive many.
        for (i, &a) in junctions.iter().enumerate() {
            if !on_pad(a) {
                continue;
            }
            examined += 1;
            let ab = store.poly_bbox(a);
            for (j, &b) in junctions.iter().enumerate() {
                // A pair of pad junctions is reported once, from the lower.
                let reported = j < i && on_pad(b);
                if j == i || reported || nets.net_of(a) == nets.net_of(b) {
                    continue;
                }
                if !store.poly_bbox(b).within(ab, min) {
                    continue;
                }
                let d2 = poly_dist2(store, a, b);
                if d2 < min2 {
                    out.push(Violation {
                        rule,
                        layer,
                        severity,
                        at: first_vertex(store, a),
                        measured: Measurement::Length(isqrt(d2)),
                        limit: Measurement::Length(min),
                        shapes: (a, Some(b)),
                    });
                }
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// The devices a pad exposes, protected: deck kind `esd_exposed`, written
/// `esd_exposed(pad; clamps: models, resistors: models | none, rated: models |
/// none)`.
///
/// Khazhinsky 2012: the layout checker "could flag input buffer gates and
/// output buffer drains without adequate ESD protection". A gate is exposed
/// when its net is a pad net (a net holding a polygon of `pad`) or is joined
/// to one only through devices of the `resistors` models, the series resistor
/// of a secondary protection stage; a supply is never exposed. An exposed
/// gate is protected when its own net has a clamp path to both a power and a
/// ground supply, walked as [`EsdTopologicalTable`] walks a pad's: at the pad
/// the primary clamps, behind a resistor local ones. A transistor with its
/// source or drain on a pad net is an output driver taking the pad's stress
/// on its junction; it is protected when it is of a `rated` model (an
/// ESD-rated device, gf180mcu's `ESD_MK`) or of a `clamps` model. A row flags
/// every transistor whose gate is exposed and unprotected, and every unrated
/// output driver. Needs design intent, for which nets are the rails.
///
/// # Limits
///
/// A gate on the pad net itself counts as protected by the pad's primary
/// clamps: a deck cannot ask for a secondary stage before every input gate
/// (a CDM rule). A clamp is linear and wired as `esd_topological` takes it.
///
/// Catalog: ERC-C3 in the [check catalog]. Defined by [ESDA TR18.0-01]
/// §4.5.1; [Khazhinsky 2012] ("Protected device checks"; "input buffer gates
/// and output buffer drains"); [GF180MCU] §14.4 (`ESD_MK` on a transistor used
/// for protection). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [ESDA TR18.0-01]: https://www.esda.org/store/standards/product/457/esd-tr18-0-01-25/
/// [Khazhinsky 2012]: https://www.esda.org/assets/News/8df611267c/ESDEDA-InCompliance-part1.pdf
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
/// [`EsdTopologicalTable`]: crate::erc::rules::supply::EsdTopologicalTable
#[derive(Debug, Default, Clone, PartialEq)]
pub struct EsdExposedTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the layer whose polygons are pads.
    pub pad: Vec<LayerId>,
    /// Clamp models per row, CSR.
    pub clamp_start: Vec<u32>,
    /// Clamp models, CSR by `clamp_start`; at least one per row.
    pub clamp: Vec<StrId>,
    /// Series-resistor models per row, CSR.
    pub resistor_start: Vec<u32>,
    /// Resistor models, CSR by `resistor_start`.
    pub resistor: Vec<StrId>,
    /// ESD-rated transistor models per row, CSR.
    pub rated_start: Vec<u32>,
    /// Rated models, CSR by `rated_start`.
    pub rated: Vec<StrId>,
}

/// Runs every [`EsdExposedTable`] row over every transistor.
///
/// `examined` counts transistors with an exposed gate plus output drivers. A
/// violation sits at the first vertex of the transistor's marker, on the
/// marker layer: an unprotected exposed gate measures the rail kinds its
/// net's clamps reach (0 or 1) against 2, an unrated output driver the count
/// of ratings, 0, against 1. Every row is skipped without usable intent.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_esd_exposed(
    design: Design<'_>,
    intent: &IntentMap,
    table: &EsdExposedTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let (nets, devices) = (design.nets, design.devices);
    let (mut seen, mut stack) = (Vec::new(), Vec::new());
    for row in 0..table.head.len() {
        let before = out.len();
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        let csr = |start: &[u32], column: &'_ [StrId]| -> Vec<StrId> {
            column[start[row] as usize..start[row + 1] as usize].to_vec()
        };
        let clamps = csr(&table.clamp_start, &table.clamp);
        let resistors = csr(&table.resistor_start, &table.resistor);
        let rated = csr(&table.rated_start, &table.rated);
        let pads = pad_nets(design, table.pad[row]);
        let supply = |net: NetId| intent.supply_net.binary_search(&net).is_ok();
        // Exposed nets: the pads, then through series resistors, never a rail.
        let mut exposed = vec![false; nets.net_count()];
        let mut walk: Vec<NetId> = pads.iter().copied().filter(|&n| !supply(n)).collect();
        for &net in &walk {
            exposed[net.idx()] = true;
        }
        while let Some(net) = walk.pop() {
            for &device in devices.devices_on(net) {
                if !resistors.contains(&devices.model[device.0 as usize]) {
                    continue;
                }
                for &next in devices.terminals_of(device).0 {
                    if next != NetId::NONE && !exposed[next.idx()] && !supply(next) {
                        exposed[next.idx()] = true;
                        walk.push(next);
                    }
                }
            }
        }
        let mut rails: Vec<Option<u32>> = vec![None; nets.net_count()];
        let mut examined = 0u64;
        for index in 0..devices.len() {
            if devices.kind[index] != DeviceKind::Mos {
                continue;
            }
            let (on, roles) = devices.terminals_of(device_id(index));
            let gate = terminal(on, roles, TerminalRole::Gate);
            if gate != NetId::NONE && exposed[gate.idx()] {
                examined += 1;
                let reached = *rails[gate.idx()].get_or_insert_with(|| {
                    clamp_rails(design, intent, &clamps, gate, &mut seen, &mut stack)
                });
                if reached < 2 {
                    let (measured, limit) = (Measurement::Count(reached), Measurement::Count(2));
                    push_device(design, index, rule, severity, measured, limit, out);
                }
            }
            let driver = [TerminalRole::Source, TerminalRole::Drain]
                .iter()
                .any(|&role| pads.binary_search(&terminal(on, roles, role)).is_ok());
            if driver {
                examined += 1;
                let model = devices.model[index];
                if !(rated.contains(&model) || clamps.contains(&model)) {
                    let (measured, limit) = (Measurement::Count(0), Measurement::Count(1));
                    push_device(design, index, rule, severity, measured, limit, out);
                }
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}
