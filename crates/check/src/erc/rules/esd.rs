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
/// none, max_current_per_cut: current | none, max_voltage: voltage | none,
/// min_width: len | none)`.
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
/// electromigration limits. With `min_width`, it flags a wire segment that
/// carries the stress current (more than a millionth of it, the solve's
/// floor) and is narrower than that: the minimum ESD metal width
/// ([Khazhinsky 2012], "violations of minimum ESD metal width"), a
/// segment's width being the narrowest its cross section finds. A limit
/// written `none` is not checked; a row must state one.
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
/// The minimum ESD-path metal width is one of the ESD layout rules on
/// recognised devices (ERC-C14); the clamp's distance to its pad is
/// [`EsdClampResistanceTable`]'s. No public source states either limit's
/// value: the deck supplies it.
///
/// Catalog: ERC-C2, ERC-C6, ERC-C7, ERC-C8, ERC-C14, ERC-D4 in the [check
/// catalog]. Defined by
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
/// [Bakhali 2020]: https://semiengineering.com/esd-p2p-and-cd-verification-doesnt-have-to-be-hard/
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
    /// Per row: the narrowest a wire carrying the stress current may be,
    /// database units; `None` is not checked.
    pub min_width: Vec<Option<Dbu>>,
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
                        source_net: None,
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
                if let Some(min_width) = table.min_width[row] {
                    narrow_wires(
                        &stress,
                        &solution,
                        current,
                        min_width,
                        (rule, severity),
                        out,
                    );
                }
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

/// Holds every wire segment of a solved pair that carries the stress current
/// to `min_width`: one violation per narrower segment, at its first node,
/// measuring its width. A segment carries the current when its share is above
/// a millionth of `forced`: a dead-end stub carries nothing but the solve's
/// rounding.
fn narrow_wires(
    stress: &StressGrid,
    solution: &PowerSolution,
    forced: Qty<Current, { prefix::MICRO }>,
    min_width: Dbu,
    head: (StrId, Severity),
    out: &mut Violations,
) {
    let grid = &stress.grid;
    let floor = forced.raw().abs() * 1e-6;
    for edge in 0..grid.edge_count() {
        if grid.edge_kind[edge] != EdgeKind::Metal
            || solution.branch_current[edge].raw().abs() <= floor
        {
            continue;
        }
        let measured = Measurement::Length(grid.edge_width[edge]);
        let limit = Measurement::Length(min_width);
        if !measured.violates(limit, LimitSense::Minimum) {
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

/// A clamp too far from its pad: deck kind `esd_clamp_resistance`, written
/// `esd_clamp_resistance(pad; clamps: models, max_resistance: resistance)`.
///
/// Public ESD verification material states a clamp's distance to its pad as
/// the resistance of the interconnect between them: [Bakhali 2020]'s
/// pin-to-clamp check "finds all possible combinations between all pins ...
/// and all specified clamp types. The check then calculates the parasitic
/// resistance on each combination" (its example rule ESD.CDM.SEC.1, "less
/// than 1 Ohm"), measured as a unit current forced in at the pin over the
/// voltage it raises ([US11714117B2]: "Rpath = VIO / IESD"). For every
/// polygon of `pad` on a net and every device of a listed model with a
/// terminal on that net, a current is forced in at the pad (tapped at the
/// net's shape nearest its centre) and out at the clamp's attach point (the
/// net's shape nearest its marker's centre, as [`EsdPathTable`] attaches a
/// clamp), the net's conductors a chain of resistors as
/// [`P2pResistanceTable`] models them; the resistance is the pad's rise over
/// that current. A row flags each pair above `max_resistance`. The clamp
/// itself is not in the path. Needs no design intent.
///
/// # Limits
///
/// Only the pad's own net is read: a clamp reached through a resistor or
/// another device is not this check's. The limit is deck-supplied; no public
/// deck states one.
///
/// Catalog: ERC-C14 in the [check catalog]. Defined by [Bakhali 2020];
/// [US11714117B2]; [Khazhinsky 2012]; Calibre PERC LDL (public material
/// only). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [Bakhali 2020]: https://semiengineering.com/esd-p2p-and-cd-verification-doesnt-have-to-be-hard/
/// [US11714117B2]: https://patents.google.com/patent/US11714117B2/en
/// [Khazhinsky 2012]: https://www.esda.org/assets/News/8df611267c/ESDEDA-InCompliance-part1.pdf
/// [`P2pResistanceTable`]: crate::erc::rules::electrical::P2pResistanceTable
#[derive(Debug, Default, Clone, PartialEq)]
pub struct EsdClampResistanceTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the layer whose polygons are pins.
    pub pad: Vec<LayerId>,
    /// Clamp device models per row, CSR.
    pub clamp_start: Vec<u32>,
    /// Clamp models, CSR by `clamp_start`; at least one per row.
    pub clamp: Vec<StrId>,
    /// Per row: the largest pin-to-clamp resistance, Ω. Positive from a deck.
    pub max_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
}

/// Runs every [`EsdClampResistanceTable`] row over every pin and clamp on
/// its net.
///
/// `examined` counts pin-clamp pairs solved. A violation sits at the first
/// vertex of the pin, on the pad layer, names the pin and the clamp's
/// marker, and measures the resistance in Ω against `max_resistance`. A row
/// is refused at the first pair whose network cannot be built (a conductor
/// with no sheet resistance) or solved; violations it found before that stay
/// in `out`.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_esd_clamp_resistance(
    design: Design<'_>,
    process: Process<'_>,
    table: &EsdClampResistanceTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let (store, nets, devices) = (design.store, design.nets, design.devices);
    // A unit current: the resistance is the rise over it.
    let unit = Qty::<Current, { prefix::MICRO }>::new(1e6);
    let mut stress = StressGrid::default();
    let mut solution = PowerSolution::default();
    for row in 0..table.head.len() {
        let before = out.len();
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        let clamps =
            &table.clamp[table.clamp_start[row] as usize..table.clamp_start[row + 1] as usize];
        let pad_layer = table.pad[row];
        let limit = Measurement::Resistance(table.max_resistance[row]);
        let mut examined = 0u64;
        let mut outcome = Outcome::Ran;
        // With no extracted nets no pin is on one.
        let pins = if nets.net_count() == 0 {
            0..0
        } else {
            store.polys_on_layer(pad_layer)
        };
        'pins: for poly in pins {
            let pin = PolyId(poly);
            let net = nets.net_of(pin);
            if net == NetId::NONE || nets.holes.is_hole(pin) {
                continue;
            }
            for &clamp in devices.devices_on(net) {
                if !clamps.contains(&devices.model[clamp.0 as usize]) {
                    continue;
                }
                let marker = devices.marker[clamp.0 as usize];
                let built = extract_stress_into(
                    store,
                    nets,
                    devices,
                    process,
                    Stress {
                        nets: &[net],
                        source: pin,
                        source_net: None,
                        current: unit,
                        sink: net,
                        pins: &[marker],
                        devices: &[],
                        device_resistance: Qty::new(1.0),
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
                // mV * 1000 / µA is Ω.
                let volts = solution.node_voltage[stress.entry as usize];
                let measured = Measurement::Resistance(Qty::new(volts.raw() * 1000.0 / unit.raw()));
                if measured.violates(limit, LimitSense::Maximum) {
                    out.push(Violation {
                        rule,
                        layer: pad_layer,
                        severity,
                        at: first_vertex(store, pin),
                        measured,
                        limit,
                        shapes: (pin, Some(marker)),
                    });
                }
            }
        }
        record_run(runs, out, before, rule, outcome, examined);
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
/// models | none, resistors: models | none, min_series: resistance | none,
/// max_ground_resistance: resistance | none, coupling_resistance:
/// resistance | none)`.
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
/// not examined.
///
/// The receiver's input is its gate's net and every net joined to it
/// through devices of the `resistors` models; its drivers are the
/// transistors with a source or drain on an input net, the driving nets.
/// With `min_series`, the receiver needs a series resistor: the effective
/// resistance from its driving nets, joined, to its gate's net through
/// those resistors (each `sheet × l / w`), at least that; a gate driven
/// directly has 0 (the local CDM protection's "series resistor 150
/// disposed between the output node ... and the input node", US12021077B2;
/// TSMC's US9035393B2 states 50, 100 or 200 Ω). With
/// `max_ground_resistance`, the driver/receiver ground resistance of
/// Etherton et al. ("The user defines the maximum resistance (Rmax) allowed
/// between D/R ground pins ... computes the effective resistance between
/// the local ground nodes"): for every driver with its other channel end on
/// a ground and a receiver with a channel end on a ground, a unit current
/// from the driver's attach point on its ground to the receiver's on its
/// own, through both grounds' conductors and every coupling diode joining
/// them at `coupling_resistance` each; a pair the coupling does not join
/// is 5.1.3's to report. A row flags a pair above the limit. Needs design
/// intent.
///
/// # Limits
///
/// The bus inductance a CDM discharge sees is not checked: no public source
/// states a static check or a limit for it (TR18-01 Rule 6.4.2 is a title
/// only). The series and ground limits are deck-supplied: no public deck
/// states them (Etherton's 2 Ω and the patents' values are examples). A
/// local clamp is any device of a listed model so wired, whichever way
/// round. Voltages reach a net as [`NetVoltage`] propagates them, through
/// every channel whatever its gate.
///
/// Catalog: ERC-C4, ERC-C9 in the [check catalog]. Defined by
/// [ESDA TR18.0-01] (2011) check 5.1.3, §5.6.2 and §5.6.3 (CDM); [Hogan 2012]
/// §II and its pseudocode ("IF different power domains THEN check for
/// anti-parallel diodes"), Fig. 1; [Khazhinsky 2012] Fig. 5 and its
/// "protection measures already implemented at power domain boundaries
/// (diodes connected to an interface gate oxide, etc.)"; [Etherton] (the
/// driver/receiver ground resistance); US12021077B2 and US9035393B2 (the
/// receiver's series resistor). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [ESDA TR18.0-01]: https://www.esda.org/store/standards/product/457/esd-tr18-0-01-25/
/// [Hogan 2012]: https://www.esda.org/assets/News/ESDEDA-InCompliance-part2.pdf
/// [Khazhinsky 2012]: https://www.esda.org/assets/News/8df611267c/ESDEDA-InCompliance-part1.pdf
/// [`MissingLevelShifterTable`]: crate::erc::rules::domain::MissingLevelShifterTable
/// [Etherton]: https://www.synopsys.com/content/dam/synopsys/implementation&signoff/electrical-layout-verification-documents/cdm-esd-paper.pdf
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
    /// Series-resistor models per row, CSR.
    pub resistor_start: Vec<u32>,
    /// Series-resistor models, CSR by `resistor_start`.
    pub resistor: Vec<StrId>,
    /// Per row: the least series resistance into a receiver's gate, Ω.
    pub min_series: Vec<Option<Qty<Resistance, { prefix::BASE }>>>,
    /// Per row: the largest driver/receiver ground resistance, Ω.
    pub max_ground_resistance: Vec<Option<Qty<Resistance, { prefix::BASE }>>>,
    /// Per row: one coupling diode's on-resistance between two grounds, Ω;
    /// stated with `max_ground_resistance`.
    pub coupling_resistance: Vec<Option<Qty<Resistance, { prefix::BASE }>>>,
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
#[allow(
    clippy::too_many_lines,
    reason = "one receiver's three checks read one walk of its input"
)]
pub fn check_esd_cross_domain(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    process: Process<'_>,
    table: &EsdCrossDomainTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let (store, devices) = (design.store, design.devices);
    let mut labels = Vec::new();
    let mut stress = StressGrid::default();
    let mut solution = PowerSolution::default();
    let ground = |net: NetId| {
        intent
            .supply_net
            .binary_search(&net)
            .is_ok_and(|r| intent.supply_role[r] == SupplyRole::Ground)
    };
    let supply = |net: NetId| intent.supply_net.binary_search(&net).is_ok();
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let mut outcome = Outcome::Ran;
        let diodes =
            &table.diode[table.diode_start[row] as usize..table.diode_start[row + 1] as usize];
        let local =
            &table.local[table.local_start[row] as usize..table.local_start[row + 1] as usize];
        let resistors = &table.resistor
            [table.resistor_start[row] as usize..table.resistor_start[row + 1] as usize];
        let coupling: Vec<DeviceId> = (0..devices.len())
            .filter(|&d| diodes.contains(&devices.model[d]))
            .map(device_id)
            .collect();
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
            if table.min_series[row].is_none() && table.max_ground_resistance[row].is_none() {
                continue;
            }
            // The receiver's input: its gate's net and every net the series
            // resistors join to it, never a supply.
            let mut region = vec![false; design.nets.net_count()];
            let mut walk = vec![gate];
            region[gate.idx()] = true;
            while let Some(net) = walk.pop() {
                for &d in devices.devices_on(net) {
                    if devices.kind[d.0 as usize] != DeviceKind::Resistor
                        || !resistors.contains(&devices.model[d.0 as usize])
                    {
                        continue;
                    }
                    for &next in devices.terminals_of(d).0 {
                        if next != NetId::NONE && !region[next.idx()] && !supply(next) {
                            region[next.idx()] = true;
                            walk.push(next);
                        }
                    }
                }
            }
            // Its drivers: a channel end on an input net.
            let mut driving: Vec<NetId> = Vec::new();
            let mut drivers: Vec<(usize, NetId)> = Vec::new();
            for other in 0..devices.len() {
                if other == index || devices.kind[other] != DeviceKind::Mos {
                    continue;
                }
                let (on, roles) = devices.terminals_of(device_id(other));
                let ends = [
                    terminal(on, roles, TerminalRole::Source),
                    terminal(on, roles, TerminalRole::Drain),
                ];
                for (k, &end) in ends.iter().enumerate() {
                    if end != NetId::NONE && region[end.idx()] {
                        driving.push(end);
                        if ground(ends[1 - k]) {
                            drivers.push((other, ends[1 - k]));
                        }
                    }
                }
            }
            driving.sort_unstable();
            driving.dedup();
            if let (Some(min), false) = (table.min_series[row], driving.is_empty()) {
                let Some(series) = series_resistance(design, &driving, &region, resistors) else {
                    outcome = Outcome::Refused;
                    break;
                };
                let measured = Measurement::Resistance(Qty::new(series[gate.idx()]));
                let limit = Measurement::Resistance(min);
                if measured.violates(limit, LimitSense::Minimum) {
                    push_device(design, index, rule, severity, measured, limit, out);
                }
            }
            let (Some(max), Some(coupling_ohms)) = (
                table.max_ground_resistance[row],
                table.coupling_resistance[row],
            ) else {
                continue;
            };
            let Some(own) = ends.iter().copied().find(|&n| ground(n)) else {
                continue;
            };
            let receiver_marker = devices.marker[index];
            for &(driver, theirs) in &drivers {
                let mut path = vec![theirs, own];
                path.sort_unstable();
                path.dedup();
                // A unit current: the resistance is the rise over it.
                let unit = Qty::<Current, { prefix::MICRO }>::new(1e6);
                let built = extract_stress_into(
                    store,
                    design.nets,
                    devices,
                    process,
                    Stress {
                        nets: &path,
                        source: devices.marker[driver],
                        source_net: Some(theirs),
                        current: unit,
                        sink: own,
                        pins: &[receiver_marker],
                        devices: &coupling,
                        device_resistance: coupling_ohms,
                    },
                    &mut stress,
                );
                if built.is_err() {
                    outcome = Outcome::Refused;
                    break;
                }
                // Grounds no coupling joins: 5.1.3's finding, not this one.
                if solve_into(&stress.grid, &mut scratch.solve, &mut solution).is_err() {
                    continue;
                }
                let volts = solution.node_voltage[stress.entry as usize];
                let measured = Measurement::Resistance(Qty::new(volts.raw() * 1000.0 / unit.raw()));
                let limit = Measurement::Resistance(max);
                if measured.violates(limit, LimitSense::Maximum) {
                    out.push(Violation {
                        rule,
                        layer: store.poly_layer(receiver_marker),
                        severity,
                        at: first_vertex(store, receiver_marker),
                        measured,
                        limit,
                        shapes: (receiver_marker, Some(devices.marker[driver])),
                    });
                }
            }
            if outcome == Outcome::Refused {
                break;
            }
        }
        record_run(runs, out, before, rule, outcome, examined);
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
/// none, min_series: resistance | none)`.
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
/// output driver.
///
/// With `min_series`, every exposed gate needs a secondary stage: a series
/// resistance of at least that between the pad and its gate (Industry
/// Council White Paper 2 §2.3.1: "any IR drop across R1 will reduce the
/// voltage stress seen across the fragile gates ... R1 values from
/// 100-5000 Ω are common"; TR18-01 Rule 6.1.11, "Verify Implementation of
/// Secondary ESD Protection Scheme"). The resistance is the effective
/// resistance from the pad nets, joined, to the gate's net through the
/// `resistors` devices, each `sheet × l / w` as the deck's `device` row
/// states it; a gate on the pad net itself has 0. Together with the local
/// clamps the walk above already asks for behind a resistor, that is the
/// primary-resistor-secondary topology of Siemens's US9378324B2. Needs
/// design intent, for which nets are the rails.
///
/// # Limits
///
/// A clamp is linear and wired as `esd_topological` takes it. The
/// `min_series` value is deck-supplied: no public deck states one (White
/// Paper 2's range is typical, not a rule), and a high-speed input that
/// cannot take a resistor is a waiver.
///
/// Catalog: ERC-C3 in the [check catalog]. Defined by [ESDA TR18.0-01]
/// §4.5.1 and Rule 6.1.11; [Khazhinsky 2012] ("Protected device checks";
/// "input buffer gates and output buffer drains"); [GF180MCU] §14.4
/// (`ESD_MK` on a transistor used for protection); [White Paper 2] §2.3
/// (the secondary stage); US9378324B2 (Siemens: "presence of series
/// resistance in the signal path, presence of secondary high/low ESD
/// clamps"). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [ESDA TR18.0-01]: https://www.esda.org/store/standards/product/457/esd-tr18-0-01-25/
/// [Khazhinsky 2012]: https://www.esda.org/assets/News/8df611267c/ESDEDA-InCompliance-part1.pdf
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
/// [White Paper 2]: https://www.esdindustrycouncil.org/ic/en/shared/industry-council-white-paper-2-rev3.0-may-2021-final.pdf
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
    /// Per row: the least series resistance between a pad and an exposed
    /// gate, Ω; `None` asks for no secondary stage.
    pub min_series: Vec<Option<Qty<Resistance, { prefix::BASE }>>>,
}

/// The effective resistance from the `sources` nets (ascending), joined
/// into one node, to every net of `region` through the resistor devices of
/// the `resistors` models with both ends in it, Ω: 0 on a source net and
/// off the region, `None` for the whole when such a resistor states no
/// value (`sheet`, or a measured width or length). Dense: a region is a
/// pad's input stages or one receiver's input.
#[allow(
    clippy::cast_precision_loss,
    reason = "a resistor's width and length in database units are far below 2^53"
)]
fn series_resistance(
    design: Design<'_>,
    sources: &[NetId],
    region: &[bool],
    resistors: &[StrId],
) -> Option<Vec<f64>> {
    let (nets, devices) = (design.nets, design.devices);
    let (pads, exposed) = (sources, region);
    let is_pad = |net: NetId| pads.binary_search(&net).is_ok();
    // Node 0 is the pads; then every exposed net that is not one.
    let mut node = vec![usize::MAX; nets.net_count()];
    let mut count = 1usize;
    for net in 0..nets.net_count() {
        if exposed[net] {
            node[net] = if is_pad(NetId(u32::try_from(net).expect("a net id is a u32"))) {
                0
            } else {
                count += 1;
                count - 1
            };
        }
    }
    let mut laplacian = vec![vec![0.0f64; count]; count];
    for device in 0..devices.len() {
        if devices.kind[device] != DeviceKind::Resistor
            || !resistors.contains(&devices.model[device])
        {
            continue;
        }
        let (on, _) = devices.terminals_of(device_id(device));
        let ends: Vec<usize> = on
            .iter()
            .filter(|&&n| n != NetId::NONE && exposed[n.idx()])
            .map(|n| node[n.idx()])
            .collect();
        let [a, b] = ends[..] else {
            continue;
        };
        if a == b {
            continue;
        }
        let length_of = |want: DeviceParam| {
            devices.params_of(device_id(device)).iter().find_map(
                |&(param, measure)| match measure {
                    DeviceMeasure::Length(length) if param == want => Some(length.raw() as f64),
                    _ => None,
                },
            )
        };
        let sheet = devices.value[device].sheet_ohm_sq?;
        let ohms = sheet * length_of(DeviceParam::Length)? / length_of(DeviceParam::Width)?;
        if ohms.partial_cmp(&0.0) != Some(std::cmp::Ordering::Greater) {
            return None;
        }
        let g = 1.0 / ohms;
        laplacian[a][a] += g;
        laplacian[b][b] += g;
        laplacian[a][b] -= g;
        laplacian[b][a] -= g;
    }
    // Ground the pads and invert the rest by Gauss-Jordan elimination.
    let n = count - 1;
    let mut m: Vec<Vec<f64>> = (1..count)
        .map(|r| {
            let mut row = laplacian[r][1..].to_vec();
            row.extend((0..n).map(|c| f64::from(u8::from(c + 1 == r))));
            row
        })
        .collect();
    for col in 0..n {
        let pivot = (col..n).max_by(|&a, &b| m[a][col].abs().total_cmp(&m[b][col].abs()))?;
        if m[pivot][col].abs() < f64::MIN_POSITIVE {
            return None;
        }
        m.swap(col, pivot);
        let scale = m[col][col];
        for value in &mut m[col] {
            *value /= scale;
        }
        for row in 0..n {
            if row != col {
                let factor = m[row][col];
                if factor != 0.0 {
                    let pivot_row = m[col].clone();
                    for (value, p) in m[row].iter_mut().zip(&pivot_row) {
                        *value -= factor * p;
                    }
                }
            }
        }
    }
    Some(
        (0..nets.net_count())
            .map(|net| match node[net] {
                usize::MAX | 0 => 0.0,
                k => m[k - 1][n + k - 1],
            })
            .collect(),
    )
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
        let series = if table.min_series[row].is_some() {
            let Some(series) = series_resistance(design, &pads, &exposed, &resistors) else {
                record_run(runs, out, before, rule, Outcome::Refused, 0);
                continue;
            };
            Some(series)
        } else {
            None
        };
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
                if let (Some(series), Some(min)) = (&series, table.min_series[row]) {
                    let measured = Measurement::Resistance(Qty::new(series[gate.idx()]));
                    let limit = Measurement::Resistance(min);
                    if measured.violates(limit, LimitSense::Minimum) {
                        push_device(design, index, rule, severity, measured, limit, out);
                    }
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

/// Pin-to-pin ESD path resistance: deck kind `esd_pin_pair`, written
/// `esd_pin_pair(pad; clamps: models, current: current, clamp_resistance:
/// resistance, max_resistance: resistance)`.
///
/// [`EsdPathTable`] stresses a pin against each supply; a pin pair of two
/// signal pins is stressed through everything between them: [Bakhali
/// 2020]'s pin-to-pin check "finds all possible combinations between all
/// specified 'From' pins and all specified 'To' pins. The check then
/// calculates a full path resistance calculation for each combination",
/// and [Khazhinsky 2012] Fig. 4 stresses one I/O pad against another. For
/// every two signal nets that hold a polygon of `pad` (a pin's net that is
/// a declared supply is [`EsdPathTable`]'s), `current` is forced in at each
/// pin polygon of the first and out at the second's pin polygons, held at
/// 0 V, through every net either pin reaches by clamps (as
/// [`EsdTopologicalTable`] walks a pad's: its clamps to a supply, then rail
/// clamps), each clamp `clamp_resistance` between its attach points. The
/// path resistance is the pin's rise over the current ([US11714117B2]:
/// "Rpath = VIO / IESD"). A pair whose two pins reach no supply in common
/// has no discharge path between them and is not examined. A row flags a
/// pair above `max_resistance`. Needs design intent, for which nets are
/// the supplies.
///
/// # Limits
///
/// A clamp is its on-resistance alone, as in [`EsdPathTable`]. The limit is
/// deck-supplied: no public deck states one (1, 2 and 10 Ω appear only as
/// examples).
///
/// Catalog: ERC-C6 in the [check catalog]. Defined by [Bakhali 2020];
/// [Khazhinsky 2012] Fig. 4; [ESDA TR18.0-01] Fig. 58 and Rule 6.3.5;
/// [US11714117B2]. Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [Bakhali 2020]: https://semiengineering.com/esd-p2p-and-cd-verification-doesnt-have-to-be-hard/
/// [Khazhinsky 2012]: https://www.esda.org/assets/News/8df611267c/ESDEDA-InCompliance-part1.pdf
/// [ESDA TR18.0-01]: https://www.esda.org/store/standards/product/457/esd-tr18-0-01-25/
/// [US11714117B2]: https://patents.google.com/patent/US11714117B2/en
/// [`EsdTopologicalTable`]: crate::erc::rules::supply::EsdTopologicalTable
#[derive(Debug, Default, Clone, PartialEq)]
pub struct EsdPinPairTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the layer whose polygons are pins.
    pub pad: Vec<LayerId>,
    /// Clamp device models per row, CSR.
    pub clamp_start: Vec<u32>,
    /// Clamp models, CSR by `clamp_start`; at least one per row.
    pub clamp: Vec<StrId>,
    /// Per row: the stress current, µA. Positive from a deck.
    pub current: Vec<Qty<Current, { prefix::MICRO }>>,
    /// Per row: one clamp's on-resistance between two of its nets, Ω.
    pub clamp_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
    /// Per row: the largest pin-to-pin path resistance, Ω.
    pub max_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
}

/// Runs every [`EsdPinPairTable`] row over every pair of signal pins.
///
/// `examined` counts pin pairs solved: each pin polygon of the lower net
/// against the higher net. A violation sits at the first vertex of the
/// source pin, on the pad layer, names it and the other net's first pin, and
/// measures the path resistance in Ω against `max_resistance`. Every row is
/// skipped without usable intent, and refused at the first pair whose
/// network cannot be built or solved.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_esd_pin_pair(
    design: Design<'_>,
    intent: &IntentMap,
    process: Process<'_>,
    table: &EsdPinPairTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let (store, nets, devices) = (design.store, design.nets, design.devices);
    let (mut seen, mut stack) = (Vec::new(), Vec::new());
    let (mut reach_a, mut reach_b) = (Vec::new(), Vec::new());
    let mut stress = StressGrid::default();
    let mut solution = PowerSolution::default();
    let supply = |net: NetId| intent.supply_net.binary_search(&net).is_ok();
    for row in 0..table.head.len() {
        let before = out.len();
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        let clamps =
            &table.clamp[table.clamp_start[row] as usize..table.clamp_start[row + 1] as usize];
        let pad_layer = table.pad[row];
        let current = table.current[row];
        let limit = Measurement::Resistance(table.max_resistance[row]);
        let pins_of = |net: NetId| -> Vec<PolyId> {
            nets.polys_of(net)
                .iter()
                .copied()
                .filter(|&p| store.poly_layer(p) == pad_layer && !nets.holes.is_hole(p))
                .collect()
        };
        let signals: Vec<NetId> = pad_nets(design, pad_layer)
            .into_iter()
            .filter(|&net| !supply(net))
            .collect();
        let mut examined = 0u64;
        let mut outcome = Outcome::Ran;
        'pairs: for (k, &a) in signals.iter().enumerate() {
            clamp_reach_into(
                design,
                intent,
                clamps,
                a,
                &mut seen,
                &mut stack,
                &mut reach_a,
            );
            for &b in &signals[k + 1..] {
                clamp_reach_into(
                    design,
                    intent,
                    clamps,
                    b,
                    &mut seen,
                    &mut stack,
                    &mut reach_b,
                );
                if !reach_a.iter().any(|&n| supply(n) && reach_b.contains(&n)) {
                    continue;
                }
                let mut path: Vec<NetId> = reach_a.iter().chain(&reach_b).copied().collect();
                path.sort_unstable();
                path.dedup();
                let mut clamp_devices: Vec<DeviceId> = Vec::new();
                for &on in &path {
                    clamp_devices.extend(devices.devices_on(on).iter().copied().filter(|&d| {
                        clamps.contains(&devices.model[d.0 as usize])
                            && reverse_biased(design, intent, d)
                    }));
                }
                clamp_devices.sort_unstable();
                clamp_devices.dedup();
                let held = pins_of(b);
                for source in pins_of(a) {
                    let built = extract_stress_into(
                        store,
                        nets,
                        devices,
                        process,
                        Stress {
                            nets: &path,
                            source,
                            source_net: None,
                            current,
                            sink: b,
                            pins: &held,
                            devices: &clamp_devices,
                            device_resistance: table.clamp_resistance[row],
                        },
                        &mut stress,
                    );
                    if built.is_err()
                        || solve_into(&stress.grid, &mut scratch.solve, &mut solution).is_err()
                    {
                        outcome = Outcome::Refused;
                        break 'pairs;
                    }
                    examined += 1;
                    // mV * 1000 / µA is Ω.
                    let volts = solution.node_voltage[stress.entry as usize];
                    let measured =
                        Measurement::Resistance(Qty::new(volts.raw() * 1000.0 / current.raw()));
                    if measured.violates(limit, LimitSense::Maximum) {
                        out.push(Violation {
                            rule,
                            layer: pad_layer,
                            severity,
                            at: first_vertex(store, source),
                            measured,
                            limit,
                            shapes: (source, held.first().copied()),
                        });
                    }
                }
            }
        }
        record_run(runs, out, before, rule, outcome, examined);
    }
}
