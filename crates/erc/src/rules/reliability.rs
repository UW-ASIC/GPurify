//! Rules about surviving conditions the layout does not contain.
//!
//! Three kinds, all gated on design intent. Each records
//! [`Skipped`]`(`[`NoDesignIntent`]`)` when its inputs are absent rather than an
//! empty clean result.
//!
//! [`Skipped`]: gpurify_report::Outcome::Skipped
//! [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent

use crate::facts::IntentMap;
use crate::power::{effective_resistance_into, NetNetworks, Solved};
use crate::ruleset::RuleHead;
use crate::{centre, first_vertex, record_run, skip_rows, Design, Scratch};
use gpurify_core::ops::{point_in_ring, segments_intersect, Point, Seg};
use gpurify_core::view::validate_layer_into;
use gpurify_core::{Bbox, GeometryStore, LayerId, PolyId, PolygonRef, RingRef, ValidatedLayer};
use gpurify_ingest::StrId;
use gpurify_report::{
    LimitSense, Measurement, Outcome, RuleRun, Violation, Violations,
};
use gpurify_topology::{DeviceId, NetId};
use gpurify_units::{prefix, Current, Dbu, Qty, Resistance, Temperature, Voltage};
use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// Boltzmann's constant, in electronvolts per kelvin — the activation energies
/// in this file are stated in eV.
const BOLTZMANN_EV_PER_K: f64 = 8.617_333_262e-5;

/// What every column-length assertion in this file says.
const COLUMNS: &str = "a rule table's columns hold one row per configured rule";

/// Lifetime under sustained stress: one inverse-power-and-Arrhenius model,
/// parameterised per row.
///
/// The *applied* stress is not here — it comes from the solve, which is what
/// makes this rule intent-gated.
#[derive(Debug, Default)]
pub struct ReliabilityTable {
    pub head: RuleHead,
    /// How long the design must last.
    pub required_lifetime_hours: Vec<f64>,
    /// The mechanism's name, interned, so a report says which one failed.
    pub mechanism: Vec<StrId>,
    /// The characterised point: this lifetime, at this stress.
    pub reference_lifetime_hours: Vec<f64>,
    pub reference_stress: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Exponent of the inverse-power law, positive.
    pub stress_exponent: Vec<f64>,
    /// Absolute, in kelvin — the lifetime model needs `1/T`, which the Celsius
    /// scale cannot express.
    pub reference_temperature: Vec<Qty<Temperature, { prefix::BASE }>>,
    pub activation_energy_ev: Vec<f64>,
    /// Fraction of the lifetime spent under stress, in `0.0 ..= 1.0`.
    pub duty_cycle: Vec<f64>,
    /// Absolute voltage above which the oxide is out of specification, checked
    /// directly rather than through the lifetime model.
    pub max_abs_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,
}

/// A device or net bridging two voltage domains.
///
/// The test is over *devices* and their terminal domains, not over conductors
/// crossing a well boundary — the latter flags every correctly-built PMOS.
#[derive(Debug, Default)]
pub struct HvDomainTable {
    pub head: RuleHead,
    /// Largest voltage difference two of a device's terminals may span before
    /// the device needs to be a thick-oxide or isolated one.
    pub max_domain_delta: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Marker layer identifying a legal crossing; a device inside one is exempt.
    ///
    /// `None` when the deck configures no exemption, in which case every
    /// crossing is a violation.
    pub isolation: Vec<Option<LayerId>>,
}

/// Pad discharge paths and latch-up guard rings: two failures over one set of
/// inputs.
#[derive(Debug, Default)]
pub struct EsdLatchupTable {
    pub head: RuleHead,
    /// Marker layer whose polygons are bond pads or I/O.
    pub pad: Vec<LayerId>,
    /// Marker layer whose polygons are guard rings.
    pub guard_ring: Vec<LayerId>,

    /// `clamp_*[clamp_start[i] .. clamp_start[i + 1]]` describe row `i`'s
    /// acceptable clamps, parallel columns.
    pub clamp_start: Vec<u32>,
    pub clamp_model: Vec<StrId>,
    /// On-resistance of the clamp itself, added to the interconnect resistance
    /// so the reported path resistance is the whole path.
    pub clamp_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
    pub clamp_capacity: Vec<Qty<Current, { prefix::MILLI }>>,
    /// Highest voltage the clamp lets the protected node reach.
    pub clamp_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,

    /// The discharge event the path must carry.
    pub required_current: Vec<Qty<Current, { prefix::MILLI }>>,
    pub max_path_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
    pub max_clamp_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,

    pub min_guard_ring_width: Vec<Dbu>,
    /// Furthest an injector may be from a tap in its guard ring.
    pub max_tap_distance: Vec<Dbu>,
}

/// Predicted lifetime against the required one, plus the absolute voltage cap.
///
/// `operating_temperature` is the *applied* point; `reference_temperature` is
/// where the lifetime was characterised. Using the latter as the former
/// collapses the Arrhenius factor to unity, which never derates and so never
/// fails. One temperature for the whole run, as in [`check_electromigration`].
///
/// A predicted lifetime that is not finite is [`Refused`], not a pass, and so
/// is a duty cycle outside `0.0 ..= 1.0`.
///
/// Records [`Skipped`]`(`[`NoDesignIntent`]`)` when `power` is `None` or
/// [`IntentMap::is_usable`] is false.
///
/// [`check_electromigration`]: crate::rules::electrical::check_electromigration
/// [`Refused`]: gpurify_report::Outcome::Refused
/// [`Skipped`]: gpurify_report::Outcome::Skipped
/// [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent
pub fn check_reliability(
    power: Option<Solved<'_>>,
    intent: &IntentMap,
    operating_temperature: Qty<Temperature, { prefix::BASE }>,
    table: &ReliabilityTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.len();
    debug_assert_eq!(table.head.severity.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.required_lifetime_hours.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.mechanism.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.reference_lifetime_hours.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.reference_stress.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.stress_exponent.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.reference_temperature.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.activation_energy_ev.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.duty_cycle.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.max_abs_voltage.len(), rows, "{COLUMNS}");

    // With no solve there is no applied stress, and with nothing declared no
    // domain the stress belongs to; either way the model has no input.
    let Some(solved) = power.filter(|_| intent.is_usable()) else {
        skip_rows(&table.head, out, runs);
        return;
    };
    debug_assert!(
        solved.solution.is_consistent_with(solved.grid),
        "a solution reaching a rule must be finite and parallel to its grid"
    );

    // No `power::discarded_budget` gate here, deliberately: with no current
    // every node sits at its pad voltage, which is its nominal and so the
    // *largest* stress this model can be handed. That is the fail-closed
    // direction, and refusing would suppress genuine overstress findings.

    let grid = solved.grid;
    let voltage = &solved.solution.node_voltage[..];
    let applied_k = operating_temperature.raw();
    let examined = u64::try_from(voltage.len()).expect("a node count fits a u64");

    // One predicted lifetime per node, refilled per row: the model is read
    // twice, by the soundness gate and by the report.
    let mut hour: Vec<f64> = Vec::new();

    for row in 0..rows {
        let before = out.len();
        let rule = table.head.rule[row];
        let severity = table.head.severity[row];

        let duty = table.duty_cycle[row];
        let reference_k = table.reference_temperature[row].raw();
        let required = table.required_lifetime_hours[row];
        let cap = table.max_abs_voltage[row];
        let reference_stress = table.reference_stress[row].raw();
        let exponent = table.stress_exponent[row];
        let thermal = (table.activation_energy_ev[row] / BOLTZMANN_EV_PER_K
            * (1.0 / applied_k - 1.0 / reference_k))
            .exp();
        // Hours a node sitting at exactly `reference_stress` would last.
        let unit = table.reference_lifetime_hours[row] * thermal / duty;
        let lifetime = |stress: Qty<Voltage, { prefix::MILLI }>| {
            unit * (reference_stress / stress.raw().abs()).powf(exponent)
        };

        // Fail closed, and decided *before* anything is pushed: a refusal taken
        // half way through the nodes would report findings against a row that
        // refused.
        let usable = (0.0..=1.0).contains(&duty)
            && applied_k > 0.0
            && reference_k > 0.0
            && reference_stress > 0.0
            && exponent.is_finite()
            && required.is_finite()
            && required > 0.0
            && cap.is_finite()
            && unit.is_finite()
            && unit > 0.0;
        // Guarded by `usable` only to skip the work, never the verdict: `sound`
        // starts at the same flag, so a row that leaves `hour` holding the
        // previous row's values refuses before reading it.
        let mut sound = usable;
        if usable {
            hour.clear();
            hour.reserve(voltage.len());
            for &stress in voltage {
                let h = lifetime(stress);
                sound &= h.is_finite();
                hour.push(h);
            }
            debug_assert_eq!(hour.len(), voltage.len(), "one predicted lifetime per node");
        }
        if !sound {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }

        let cap_limit = Measurement::Voltage(cap);
        let required_limit = Measurement::Ratio(required);

        for node in 0..voltage.len() {
            let stress = voltage[node];
            let at = grid.node_at[node];
            let layer = grid.node_layer[node];
            let shapes = (grid.node_poly[node], None);
            let applied = Measurement::Voltage(Qty::new(stress.raw().abs()));
            let hours = Measurement::Ratio(hour[node]);

            if applied.violates(cap_limit, LimitSense::Maximum) {
                out.push(Violation {
                    rule,
                    layer,
                    severity,
                    at,
                    measured: applied,
                    limit: cap_limit,
                    shapes,
                });
            }
            if hours.violates(required_limit, LimitSense::Minimum) {
                out.push(Violation {
                    rule,
                    layer,
                    severity,
                    at,
                    measured: hours,
                    limit: required_limit,
                    shapes,
                });
            }
        }

        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every device whose terminals span more than `max_domain_delta`.
///
/// A device with a terminal on an undeclared net contributes nothing and is not
/// counted in `examined`.
///
/// The isolation marker is tested by *exact* containment — see [`encloses`] —
/// so a ring- or L-shaped marker exempts nothing in the hollow it does not
/// cover. A row naming an isolation layer whose geometry will not validate
/// records [`Refused`]: running with the marker silently ignored flags every
/// correctly-isolated device.
///
/// Records [`Skipped`]`(`[`NoDesignIntent`]`)` when [`IntentMap::is_usable`] is
/// false.
///
/// [`Refused`]: gpurify_report::Outcome::Refused
/// [`Skipped`]: gpurify_report::Outcome::Skipped
/// [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent
pub fn check_hv_domain(
    design: Design<'_>,
    intent: &IntentMap,
    table: &HvDomainTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.len();
    debug_assert_eq!(table.head.severity.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.max_domain_delta.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.isolation.len(), rows, "{COLUMNS}");

    // With no domains declared every device spans a delta of zero, so an
    // ungated run reads the whole design clean.
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }

    let store = design.store;
    let devices = design.devices;
    let device_count = devices.len();
    // An unconfigured exemption is an empty layer rather than a `None` tested
    // per device, so the containment test runs unconditionally and answers
    // `false`.
    let mut isolation = ValidatedLayer::default();
    let unconfigured = ValidatedLayer::default();

    for row in 0..rows {
        let before = out.len();
        let rule = table.head.rule[row];
        let severity = table.head.severity[row];
        let limit = Measurement::Voltage(table.max_domain_delta[row]);
        let mut examined = 0u64;

        // Fail closed: an exemption that cannot be evaluated is not one that is
        // absent.
        if let Some(layer) = table.isolation[row] {
            if validate_layer_into(store, layer, &mut isolation).is_err() {
                record_run(runs, out, before, rule, Outcome::Refused, 0);
                continue;
            }
        }
        let exemption = if table.isolation[row].is_some() {
            &isolation
        } else {
            &unconfigured
        };

        for index in 0..device_count {
            let device = DeviceId(u32::try_from(index).expect("a device table indexes with u32"));
            let (terminal_nets, _) = devices.terminals_of(device);
            // Silence about a net nobody classified, rather than a guess.
            let Some(spread) = domain_spread(intent, terminal_nets) else {
                continue;
            };
            examined += 1;

            let marker = devices.marker[index];
            let measured = Measurement::Voltage(spread);
            // Exact containment, so an annular or L-shaped marker exempts
            // nothing in the hollow it does not cover.
            let exempt = encloses(store, exemption, store.poly_bbox(marker));
            if !exempt & measured.violates(limit, LimitSense::Maximum) {
                out.push(Violation {
                    rule,
                    layer: store.poly_layer(marker),
                    severity,
                    at: first_vertex(store, marker),
                    measured,
                    limit,
                    shapes: (marker, None),
                });
            }
        }

        debug_assert!(
            examined <= u64::try_from(device_count).expect("a device count fits a u64"),
            "more devices examined than the table holds"
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every pad without a qualifying discharge path, and every unguarded
/// injector.
///
/// Dijkstra over [`ClampGraph`]'s CSR adjacency for the lowest-resistance path
/// from each pad net to a declared supply, summing clamp on-resistance and the
/// interconnect between the terminals the path actually enters and leaves each
/// net through.
///
/// A pad with **no** path at all is a violation with an absent measurement
/// rather than an infinite one: the two cases mean different things to a fix.
///
/// Records [`Skipped`]`(`[`NoDesignIntent`]`)` when [`IntentMap::is_usable`] is
/// false.
///
/// [`Skipped`]: gpurify_report::Outcome::Skipped
/// [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent
pub fn check_esd_latchup(
    design: Design<'_>,
    intent: &IntentMap,
    networks: &NetNetworks,
    table: &EsdLatchupTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.len();
    debug_assert_eq!(table.head.severity.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.pad.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.guard_ring.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.required_current.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.max_path_resistance.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.max_clamp_voltage.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.min_guard_ring_width.len(), rows, "{COLUMNS}");
    debug_assert_eq!(table.max_tap_distance.len(), rows, "{COLUMNS}");
    let clamps = table.clamp_model.len();
    debug_assert_eq!(table.clamp_resistance.len(), clamps, "{COLUMNS}");
    debug_assert_eq!(table.clamp_capacity.len(), clamps, "{COLUMNS}");
    debug_assert_eq!(table.clamp_voltage.len(), clamps, "{COLUMNS}");
    debug_assert_eq!(
        table.clamp_start.len(),
        rows + usize::from(rows > 0),
        "a CSR row list is one longer than the table it indexes"
    );

    // With no declared supplies there is no target for a discharge path, so
    // every pad would trivially pass — the exact shape of a false-clean result.
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }

    let store = design.store;
    let nets = design.nets;
    // One `u32` per net, holding the row generation that last saw it. Pad nets
    // deduplicate against it without the buffer being cleared between rows.
    scratch.net_marks.clear();
    scratch.net_marks.resize(nets.net_count(), 0);

    // Locals rather than `scratch.edges` / `scratch.probes`: the first carries
    // no resistance and the second is spoken for by `effective_resistance_into`
    // in the same row.
    let mut graph = ClampGraph::default();
    let mut search = PathSearch::default();
    // One `(net, attach terminal)` pair per terminal of the clamp being read.
    let mut attach: Vec<(u32, u32)> = Vec::new();

    // The declared supplies' bounding boxes, gathered once: no rule row varies
    // them, and one contiguous column makes the per-ring search a linear scan.
    scratch.boxes.clear();
    for &net in &intent.supply_net {
        let polys = nets.polys_of(net);
        scratch.boxes.reserve(polys.len());
        for &poly in polys {
            scratch.boxes.push(store.poly_bbox(poly));
        }
    }

    for row in 0..rows {
        let before = out.len();
        let rule = table.head.rule[row];
        let severity = table.head.severity[row];
        let generation = u32::try_from(row + 1).expect("a rule table is small");
        let mut examined = 0u64;

        let clamp_lo =
            usize::try_from(table.clamp_start[row]).expect("a CSR offset is non-negative");
        let clamp_hi =
            usize::try_from(table.clamp_start[row + 1]).expect("a CSR offset is non-negative");
        debug_assert!(
            clamp_lo <= clamp_hi && clamp_hi <= clamps,
            "the clamp run leaves its column"
        );

        // Qualifying clamp devices become resistive edges between the *nodes*
        // they attach to, a node being a `(net, terminal)` pair. Qualification
        // is per clamp, not per path: a clamp that cannot carry the event is not
        // an edge at all.
        graph.clear();
        for index in 0..design.devices.len() {
            let model = design.devices.model[index];
            let Some(offset) = clamp_row(&table.clamp_model[clamp_lo..clamp_hi], model) else {
                continue;
            };
            let clamp = clamp_lo + offset;
            let carries = table.clamp_capacity[clamp].raw() >= table.required_current[row].raw();
            let holds = table.clamp_voltage[clamp].raw() <= table.max_clamp_voltage[row].raw();
            if !(carries & holds) {
                continue;
            }

            let device = DeviceId(u32::try_from(index).expect("a device table indexes with u32"));
            let (terminal_nets, _) = design.devices.terminals_of(device);
            // Where on each net this clamp lands, resolved once per terminal
            // rather than once per terminal *pair*.
            let marker = centre(store.poly_bbox(design.devices.marker[index]));
            attach.clear();
            attach.extend(
                terminal_nets
                    .iter()
                    .map(|&net| (net.0, attach_terminal(store, networks, net, marker))),
            );
            let resistance = table.clamp_resistance[clamp].raw();
            for a in 0..attach.len() {
                for b in a + 1..attach.len() {
                    graph.clamp.push((attach[a], attach[b], resistance));
                }
            }
        }

        // Fail closed: a network that will not solve leaves the path resistance
        // unknown, and an unknown compared against a maximum reads as clean.
        if graph
            .resolve(networks, intent, &mut scratch.solve, &mut scratch.probes)
            .is_err()
        {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }

        let pad_layer = table.pad[row];
        let max_path = table.max_path_resistance[row];
        for poly in store.polys_on_layer(pad_layer) {
            let pad = PolyId(poly);
            let net = nets.net_of(pad);
            // A pad polygon on no net is a topology finding rather than an ESD
            // verdict, and `NetId::NONE` indexes past `net_marks`.
            if net == NetId::NONE {
                continue;
            }
            let seen = scratch.net_marks[net.idx()] == generation;
            scratch.net_marks[net.idx()] = generation;
            if seen {
                continue;
            }
            examined += 1;

            // The pad injects at its own shape, so the path starts at the
            // terminal nearest it.
            let entry = attach_terminal(store, networks, net, centre(store.poly_bbox(pad)));
            let path = graph.lowest_resistance(net.0, entry, &mut search);
            // No path at all is reported as "zero qualifying paths against a
            // required one" rather than as an infinite resistance.
            let (measured, limit, sense) = path.map_or(
                (
                    Measurement::Count(0),
                    Measurement::Count(1),
                    LimitSense::Minimum,
                ),
                |ohms| {
                    (
                        Measurement::Resistance(Qty::new(ohms)),
                        Measurement::Resistance(max_path),
                        LimitSense::Maximum,
                    )
                },
            );
            if measured.violates(limit, sense) {
                out.push(Violation {
                    rule,
                    layer: pad_layer,
                    severity,
                    at: first_vertex(store, pad),
                    measured,
                    limit,
                    shapes: (pad, None),
                });
            }
        }

        // The guard-ring half, in the same pass over the same row.
        let ring_layer = table.guard_ring[row];
        let min_width = Measurement::Length(table.min_guard_ring_width[row]);
        let max_tap = table.max_tap_distance[row];
        for poly in store.polys_on_layer(ring_layer) {
            let ring = PolyId(poly);
            let box_of = store.poly_bbox(ring);
            examined += 1;

            let at = first_vertex(store, ring);
            // The narrow side is what an injected carrier has to cross, so a
            // ring's width is the smaller of its two spans.
            let width = Measurement::Length(box_of.width().min(box_of.height()));
            if width.violates(min_width, LimitSense::Minimum) {
                out.push(Violation {
                    rule,
                    layer: ring_layer,
                    severity,
                    at,
                    measured: width,
                    limit: min_width,
                    shapes: (ring, None),
                });
            }

            // A ring only works while it is biased, through the nearest tap on
            // a declared supply net.
            let (measured, limit, sense) = nearest_supply(&scratch.boxes, box_of).map_or(
                (
                    Measurement::Count(0),
                    Measurement::Count(1),
                    LimitSense::Minimum,
                ),
                |gap| {
                    (
                        Measurement::Length(gap),
                        Measurement::Length(max_tap),
                        LimitSense::Maximum,
                    )
                },
            );
            if measured.violates(limit, sense) {
                out.push(Violation {
                    rule,
                    layer: ring_layer,
                    severity,
                    at,
                    measured,
                    limit,
                    shapes: (ring, None),
                });
            }
        }

        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// The widest nominal-voltage spread across a device's terminals.
///
/// `None` when any terminal sits on a net design intent did not declare: a
/// spread across a net nobody classified is a guess.
fn domain_spread(
    intent: &IntentMap,
    terminal_nets: &[NetId],
) -> Option<Qty<Voltage, { prefix::MILLI }>> {
    let mut lo = f64::INFINITY;
    let mut hi = f64::NEG_INFINITY;
    for &net in terminal_nets {
        let millivolts = intent.nominal_voltage(net)?.raw();
        lo = lo.min(millivolts);
        hi = hi.max(millivolts);
    }
    (hi >= lo).then(|| Qty::new(hi - lo))
}

/// True when one polygon of `isolation` covers all of `inner`.
///
/// An empty `isolation` answers `false`, so "no exemption configured" is the
/// same code path as "no exemption polygon covers this device". Exact, not by
/// bounding box: the box test can reject, never accept.
fn encloses(store: &GeometryStore, isolation: &ValidatedLayer, inner: Bbox) -> bool {
    debug_assert!(inner.xlo <= inner.xhi && inner.ylo <= inner.yhi, "an empty query box");
    (0..isolation.len())
        .map(|idx| isolation.get(store, u32::try_from(idx).expect("a layer indexes with u32")))
        .any(|poly| poly.bbox().contains(inner) && covers(poly, inner))
}

/// True when the region of `poly` covers every point of `inner`.
///
/// All three facts are needed: a corner of `inner` inside the outer boundary,
/// that corner in no hole, and no ring crossing the rectangle's boundary. Corner
/// containment alone is unsound — a slot of the complement can pass clean
/// through a rectangle whose four corners are all inside.
///
/// Touching counts as crossing, so a marker whose edge lies on the isolation
/// boundary is *not* exempt: the fail-closed direction.
fn covers(poly: PolygonRef<'_>, inner: Bbox) -> bool {
    let corner = Point { x: inner.xlo, y: inner.ylo };
    let inside = point_in_ring(poly.outer(), corner)
        && !poly.holes().any(|hole| point_in_ring(hole, corner));
    inside && !crosses(poly.outer(), inner) && !poly.holes().any(|hole| crosses(hole, inner))
}

/// True when any edge of `ring` meets the boundary of the rectangle `box_`.
fn crosses(ring: RingRef<'_>, box_: Bbox) -> bool {
    let (xs, ys) = ring.coords();
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    debug_assert!(xs.len() >= 3, "a validated ring has at least three vertices");

    let corner = |x: Dbu, y: Dbu| Point { x, y };
    let (lb, rb, rt, lt) = (
        corner(box_.xlo, box_.ylo),
        corner(box_.xhi, box_.ylo),
        corner(box_.xhi, box_.yhi),
        corner(box_.xlo, box_.yhi),
    );
    let sides = [
        Seg { a: lb, b: rb },
        Seg { a: rb, b: rt },
        Seg { a: rt, b: lt },
        Seg { a: lt, b: lb },
    ];

    // Indexed rather than zipped: a zip would silently scan the shorter column
    // and report no crossing — fail-open, for a test whose `false` is an
    // exemption.
    let n = xs.len();
    let (mut ax, mut ay) = (xs[n - 1], ys[n - 1]);
    let mut hit = false;
    for i in 0..n {
        let (bx, by) = (xs[i], ys[i]);
        let edge = Seg {
            a: Point { x: ax, y: ay },
            b: Point { x: bx, y: by },
        };
        let meets = segments_intersect(edge, sides[0])
            | segments_intersect(edge, sides[1])
            | segments_intersect(edge, sides[2])
            | segments_intersect(edge, sides[3]);
        hit |= meets;
        (ax, ay) = (bx, by);
    }
    hit
}

/// The clamp row a device's model names, as an offset into `models`; `None`
/// when the model is not on the list.
fn clamp_row(models: &[StrId], model: StrId) -> Option<usize> {
    models.iter().position(|&m| m == model)
}

/// One clamp edge: two `(net, terminal)` endpoints and the ohms between them.
///
/// A node is a `(net, terminal)` pair and not a net: a scalar per net would let
/// a path cross a net whose two attach points sit in different connected
/// components and have no interconnect between them at all.
type ClampEdge = ((u32, u32), (u32, u32), f64);

#[derive(Debug, Default)]
struct ClampGraph {
    /// `(a, b, ohms)` per qualifying clamp terminal pair; the raw build product
    /// [`ClampGraph::resolve`] turns into the adjacency.
    clamp: Vec<ClampEdge>,

    /// One row per node, ascending by `(net, terminal)` — net first, so one
    /// net's nodes are a contiguous run.
    node: Vec<(u32, u32)>,
    /// Whether the node's net is a declared supply: the search's target set.
    node_supply: Vec<bool>,

    /// Deduplicated nets the nodes touch, ascending.
    net: Vec<u32>,
    /// `probe[probe_start[i] .. probe_start[i + 1]]` is `net[i]`'s effective
    /// resistance between terminal pairs, `(a, b, ohms)` with `a < b`,
    /// ascending. A pair absent from the run has no interconnect path at all.
    probe_start: Vec<u32>,
    probe: Vec<(u32, u32, f64)>,

    /// CSR adjacency over `node`, both directions, clamp edges and intra-net
    /// probe edges together.
    adj_start: Vec<u32>,
    adj_to: Vec<u32>,
    adj_ohms: Vec<f64>,
}

/// The search workspace, caller-owned so a loop over pads allocates once.
#[derive(Debug, Default)]
struct PathSearch {
    dist: Vec<f64>,
    /// Keyed by `f64::to_bits`, which orders non-negative finite floats exactly
    /// as the floats order. The node index breaks ties, so the pop order is a
    /// function of the graph and not of insertion.
    heap: BinaryHeap<Reverse<(u64, u32)>>,
}

impl ClampGraph {
    fn clear(&mut self) {
        self.clamp.clear();
        self.node.clear();
        self.node_supply.clear();
        self.net.clear();
        self.probe_start.clear();
        self.probe.clear();
        self.adj_start.clear();
        self.adj_to.clear();
        self.adj_ohms.clear();
    }

    /// Turn the collected clamp edges into a searchable graph.
    ///
    /// `Err` when a net's network will not solve: the path resistance is then
    /// unknown, and an unknown compared against a maximum reads as clean.
    fn resolve(
        &mut self,
        networks: &NetNetworks,
        intent: &IntentMap,
        solve: &mut crate::power::SolveScratch,
        probes: &mut Vec<(u32, u32, Qty<Resistance, { prefix::BASE }>)>,
    ) -> Result<(), ()> {
        for i in 0..self.clamp.len() {
            let (a, b, _) = self.clamp[i];
            self.node.push(a);
            self.node.push(b);
        }
        self.node.sort_unstable();
        self.node.dedup();

        for i in 0..self.node.len() {
            let (net, _) = self.node[i];
            self.net.push(net);
            self.node_supply
                .push(intent.supply_of(NetId(net)).is_some());
        }
        self.net.dedup();
        debug_assert!(
            self.net.windows(2).all(|w| w[0] < w[1]),
            "the node list is sorted by net first, so deduping it yields the nets ascending"
        );
        debug_assert_eq!(self.node_supply.len(), self.node.len(), "one supply flag per node");

        // One probe run per net, in `net` order, so `probe_start` is CSR over
        // the same index space.
        self.probe_start.push(0);
        for i in 0..self.net.len() {
            // A net with fewer than two attach points has no network row: every
            // clamp on it lands on terminal 0 and traversal is free.
            if let Some(row) = networks.row_of(NetId(self.net[i])) {
                effective_resistance_into(networks, row, solve, probes).map_err(|_| ())?;
                self.probe
                    .extend(probes.iter().map(|&(a, b, r)| (a, b, r.raw())));
            }
            self.probe_start
                .push(u32::try_from(self.probe.len()).expect("a probe list is small"));
        }
        debug_assert_eq!(
            self.probe_start.len(),
            self.net.len() + 1,
            "a CSR row list is one longer than the table it indexes"
        );

        self.build_adjacency();
        Ok(())
    }

    /// Fill the CSR adjacency from `clamp` and `probe`: degrees counted,
    /// prefix-summed, then filled with `adj_start` doubling as the write cursor.
    fn build_adjacency(&mut self) {
        let n = self.node.len();
        self.adj_start.resize(n + 1, 0);

        for i in 0..self.clamp.len() {
            let (a, b) = (self.node_of(self.clamp[i].0), self.node_of(self.clamp[i].1));
            self.adj_start[a + 1] += 1;
            self.adj_start[b + 1] += 1;
        }
        for i in 0..self.net.len() {
            let net = self.net[i];
            let (lo, hi) = (self.probe_start[i] as usize, self.probe_start[i + 1] as usize);
            for p in lo..hi {
                let (ta, tb, _) = self.probe[p];
                // A probe pair whose terminals no clamp lands on is not an edge
                // of this graph.
                let (Some(a), Some(b)) = (self.node_at(net, ta), self.node_at(net, tb)) else {
                    continue;
                };
                self.adj_start[a + 1] += 1;
                self.adj_start[b + 1] += 1;
            }
        }
        for b in 1..=n {
            self.adj_start[b] += self.adj_start[b - 1];
        }
        let edges = self.adj_start[n] as usize;
        self.adj_to.resize(edges, 0);
        self.adj_ohms.resize(edges, 0.0);

        for i in 0..self.clamp.len() {
            let (a, b, ohms) = self.clamp[i];
            let (a, b) = (self.node_of(a), self.node_of(b));
            self.file(a, b, ohms);
        }
        for i in 0..self.net.len() {
            let net = self.net[i];
            let (lo, hi) = (self.probe_start[i] as usize, self.probe_start[i + 1] as usize);
            for p in lo..hi {
                let (ta, tb, ohms) = self.probe[p];
                let (Some(a), Some(b)) = (self.node_at(net, ta), self.node_at(net, tb)) else {
                    continue;
                };
                self.file(a, b, ohms);
            }
        }

        // Every cursor now holds the end of its run, which is the start of the
        // next one: shifting right restores the offsets.
        for b in (1..=n).rev() {
            self.adj_start[b] = self.adj_start[b - 1];
        }
        self.adj_start[0] = 0;
        debug_assert_eq!(self.adj_start[n] as usize, self.adj_to.len());
        debug_assert!(
            self.adj_start.windows(2).all(|w| w[0] <= w[1]),
            "adjacency offsets are non-decreasing"
        );
        debug_assert!(
            self.adj_to.iter().all(|&t| (t as usize) < n),
            "an adjacency entry names a node this graph does not have"
        );
        debug_assert!(
            self.adj_ohms.iter().all(|&r| r >= 0.0 && r.is_finite()),
            "a resistive edge is a non-negative finite number of ohms"
        );
    }

    /// Write one undirected edge into both endpoints' runs.
    fn file(&mut self, a: usize, b: usize, ohms: f64) {
        for (from, to) in [(a, b), (b, a)] {
            let w = self.adj_start[from];
            self.adj_to[w as usize] = u32::try_from(to).expect("a node index is a u32");
            self.adj_ohms[w as usize] = ohms;
            self.adj_start[from] = w + 1;
        }
    }

    /// The node index of a `(net, terminal)` pair the build already filed.
    fn node_of(&self, key: (u32, u32)) -> usize {
        self.node
            .binary_search(&key)
            .expect("every clamp endpoint was folded into the node list")
    }

    /// The node index of a `(net, terminal)` pair, or `None` when no clamp
    /// lands there.
    fn node_at(&self, net: u32, terminal: u32) -> Option<usize> {
        self.node.binary_search(&(net, terminal)).ok()
    }

    /// One net's probe run, by binary search on the net list.
    fn probes_of(&self, net: u32) -> &[(u32, u32, f64)] {
        let Ok(i) = self.net.binary_search(&net) else {
            return &[];
        };
        &self.probe[self.probe_start[i] as usize..self.probe_start[i + 1] as usize]
    }

    /// Interconnect between two terminals of one net, or `None` when they sit
    /// in different connected components and no path joins them.
    fn interconnect(&self, net: u32, a: u32, b: u32) -> Option<f64> {
        // A terminal reaches itself for nothing, and `effective_resistance_into`
        // reports pairs only, so the diagonal is not in the run.
        if a == b {
            return Some(0.0);
        }
        let key = (a.min(b), a.max(b));
        let run = self.probes_of(net);
        run.binary_search_by(|p| (p.0, p.1).cmp(&key))
            .ok()
            .map(|i| run[i].2)
    }

    /// Lowest total resistance from `start_net`'s `start_term` to any node on a
    /// declared supply.
    ///
    /// Dijkstra: every edge is a non-negative resistance, so the first supply
    /// node popped is the answer. The start terminal need not be a node — a pad
    /// injects at its own shape — so the search is multi-source, seeding every
    /// clamp terminal on the pad's own net at the interconnect to it.
    fn lowest_resistance(
        &self,
        start_net: u32,
        start_term: u32,
        search: &mut PathSearch,
    ) -> Option<f64> {
        let n = self.node.len();
        debug_assert_eq!(self.node_supply.len(), n, "one supply flag per node");
        debug_assert_eq!(self.adj_start.len(), n + 1, "one adjacency offset per node plus the end");

        // A pad net no qualifying clamp touches reaches nothing through this
        // graph.
        let lo = self.node.partition_point(|&(net, _)| net < start_net);
        let hi = self.node.partition_point(|&(net, _)| net <= start_net);
        if lo == hi {
            return None;
        }

        search.dist.clear();
        search.dist.resize(n, f64::INFINITY);
        search.heap.clear();
        for node in lo..hi {
            let Some(ohms) = self.interconnect(start_net, start_term, self.node[node].1) else {
                continue;
            };
            search.dist[node] = ohms;
            push(&mut search.heap, ohms, node);
        }

        while let Some(Reverse((key, node))) = search.heap.pop() {
            let here = f64::from_bits(key);
            let node = node as usize;
            // A stale heap entry: this node was popped at a shorter distance
            // already. Cheaper than a decrease-key.
            if here > search.dist[node] {
                continue;
            }
            if self.node_supply[node] {
                debug_assert!(here >= 0.0 && here.is_finite(), "a path resistance is {here}");
                return Some(here);
            }
            for e in self.adj_start[node] as usize..self.adj_start[node + 1] as usize {
                let next = self.adj_to[e] as usize;
                let candidate = here + self.adj_ohms[e];
                if candidate < search.dist[next] {
                    search.dist[next] = candidate;
                    push(&mut search.heap, candidate, next);
                }
            }
        }
        None
    }
}

/// Push one heap entry, keyed by the bit pattern of a non-negative finite
/// distance.
fn push(heap: &mut BinaryHeap<Reverse<(u64, u32)>>, distance: f64, node: usize) {
    debug_assert!(
        distance >= 0.0 && distance.is_finite(),
        "the bit ordering the heap keys on only holds for non-negative finite floats, not {distance}"
    );
    heap.push(Reverse((
        distance.to_bits(),
        u32::try_from(node).expect("a node index is a u32"),
    )));
}

/// Which terminal of `net`'s network a device at `marker` attaches to: the one
/// whose node polygon centre is nearest, matching [`crate::power`]. `0` for a
/// net with no network row.
fn attach_terminal(
    store: &GeometryStore,
    networks: &NetNetworks,
    net: NetId,
    marker: Point,
) -> u32 {
    let Some(row) = networks.row_of(net) else {
        return 0;
    };
    let terminals = networks.terminals_of(row);
    debug_assert!(
        !terminals.is_empty(),
        "a net with a network row has at least two terminals"
    );
    let (_, node_poly) = networks.nodes_of(row);

    // Strictly less, so the lowest-numbered terminal holds a tie and the answer
    // is deterministic.
    let mut nearest = i128::MAX;
    let mut winner = u32::MAX;
    for &terminal in terminals {
        let here = centre(store.poly_bbox(node_poly[terminal as usize]));
        let (dx, dy) = (
            i128::from(here.x.raw() - marker.x.raw()),
            i128::from(here.y.raw() - marker.y.raw()),
        );
        // Both differences are bounded by twice `MAX_ABS_DBU = 2^40`, so the
        // squares and their sum are far inside an `i128`, and exact.
        let distance = dx * dx + dy * dy;
        // Read `nearest` before it is updated, so the mask and the minimum see
        // the same accumulator.
        let closer = u32::from(distance < nearest).wrapping_neg();
        winner = (terminal & closer) | (winner & !closer);
        nearest = distance.min(nearest);
    }
    debug_assert!(
        terminals.contains(&winner),
        "the winner was folded out of this very list"
    );
    winner
}

/// Distance from a guard ring to the nearest of `supply`.
///
/// `None` when `supply` is empty, reported by the caller as an absent tap rather
/// than as a saturating distance — a saturated distance held against a *maximum*
/// reads as clean.
fn nearest_supply(supply: &[Bbox], ring: Bbox) -> Option<Dbu> {
    // Seeded with the first box's own separation rather than a sentinel: one
    // large enough to lose to every real separation is outside the coordinate
    // domain, and one inside it could *win* against a real distance.
    let (&first, rest) = supply.split_first()?;
    let mut gap = separation(ring, first);
    for &box_ in rest {
        gap = gap.min(separation(ring, box_));
    }
    debug_assert!(gap.raw() >= 0, "a separation is never negative");
    Some(gap)
}

/// Rectilinear separation of two boxes; zero when they touch or overlap.
///
/// The exact inverse of [`Bbox::within`]: `separation(a, b) <= d` is
/// `a.within(b, d)`, so the two cannot drift apart.
fn separation(a: Bbox, b: Bbox) -> Dbu {
    let zero = Dbu::new_unchecked(0);
    let dx = (b.xlo - a.xhi).max(a.xlo - b.xhi).max(zero);
    let dy = (b.ylo - a.yhi).max(a.ylo - b.yhi).max(zero);
    dx.max(dy)
}
