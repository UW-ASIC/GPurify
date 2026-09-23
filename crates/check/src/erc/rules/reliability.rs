//! Rules about surviving conditions the layout does not contain.
//!
//! Data in: the solved supply grid, devices, design intent. Data out:
//! violations and one run per row. All three kinds skip without intent.

use crate::erc::facts::IntentMap;
use crate::erc::power::Solved;
use crate::erc::ruleset::RuleHead;
use crate::erc::{first_vertex, record_run, skip_rows, Design, Scratch, BOLTZMANN_EV_PER_K};
use crate::report::{LimitSense, Measurement, Outcome, RuleRun, Violation, Violations};
use crate::topology::{DeviceId, NetId};
use gpurify_geom::ops::{point_in_ring, segments_intersect, Point, Seg};
use gpurify_geom::view::validate_layer_into;
use gpurify_geom::{prefix, Dbu, Qty, Temperature, Voltage};
use gpurify_geom::{Bbox, LayerId, PolyId, PolygonRef, RingRef, ValidatedLayer};

/// Lifetime under sustained voltage stress: inverse power law times
/// Arrhenius, per row. The applied stress comes from the solve.
#[derive(Debug, Default)]
pub struct ReliabilityTable {
    pub head: RuleHead,
    pub required_lifetime_hours: Vec<f64>,
    /// The characterised point: this lifetime at this stress.
    pub reference_lifetime_hours: Vec<f64>,
    pub reference_stress: Vec<Qty<Voltage, { prefix::MILLI }>>,
    pub stress_exponent: Vec<f64>,
    /// Absolute, in kelvin.
    pub reference_temperature: Vec<Qty<Temperature, { prefix::BASE }>>,
    pub activation_energy_ev: Vec<f64>,
    /// Fraction of the lifetime under stress, in `0.0 ..= 1.0`.
    pub duty_cycle: Vec<f64>,
    /// Absolute voltage cap, checked directly.
    pub max_abs_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,
}

/// A device whose terminals span two voltage domains.
#[derive(Debug, Default)]
pub struct HvDomainTable {
    pub head: RuleHead,
    pub max_domain_delta: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Marker layer exempting a device it fully covers; `None` exempts nothing.
    pub isolation: Vec<Option<LayerId>>,
}

/// Pads without a discharge path, and guard rings too narrow or too far from
/// a supply tap.
#[derive(Debug, Default)]
pub struct EsdLatchupTable {
    pub head: RuleHead,
    pub pad: Vec<LayerId>,
    pub guard_ring: Vec<LayerId>,
    pub min_guard_ring_width: Vec<Dbu>,
    /// Furthest a guard ring may be from a declared supply.
    pub max_tap_distance: Vec<Dbu>,
}

/// Every node's predicted lifetime against the required one, plus the absolute
/// voltage cap. A row whose model is unusable or not finite is refused.
///
/// No `discarded_budget` gate: with no current every node sits at nominal, the
/// largest stress, which is the fail-closed direction.
pub fn check_reliability(
    power: Option<Solved<'_>>,
    intent: &IntentMap,
    operating_temperature: Qty<Temperature, { prefix::BASE }>,
    table: &ReliabilityTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let Some(solved) = power.filter(|_| intent.is_usable()) else {
        skip_rows(&table.head, out, runs);
        return;
    };
    let grid = solved.grid;
    let voltage = &solved.solution.node_voltage[..];
    let applied_k = operating_temperature.raw();
    let examined = u64::try_from(voltage.len()).expect("a node count fits a u64");
    let mut hour: Vec<f64> = Vec::new();

    for row in 0..table.head.len() {
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
        // Hours a node at exactly `reference_stress` would last.
        let unit = table.reference_lifetime_hours[row] * thermal / duty;

        // Decided before anything is pushed.
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
        let mut sound = usable;
        if usable {
            hour.clear();
            for &stress in voltage {
                let h = unit * (reference_stress / stress.raw().abs()).powf(exponent);
                sound &= h.is_finite();
                hour.push(h);
            }
        }
        if !sound {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }

        let cap_limit = Measurement::Voltage(cap);
        let required_limit = Measurement::Ratio(required);
        for node in 0..voltage.len() {
            let push = |out: &mut Violations, measured, limit| {
                out.push(Violation {
                    rule,
                    layer: grid.node_layer[node],
                    severity,
                    at: grid.node_at[node],
                    measured,
                    limit,
                    shapes: (grid.node_poly[node], None),
                });
            };
            let applied = Measurement::Voltage(Qty::new(voltage[node].raw().abs()));
            if applied.violates(cap_limit, LimitSense::Maximum) {
                push(out, applied, cap_limit);
            }
            let hours = Measurement::Ratio(hour[node]);
            if hours.violates(required_limit, LimitSense::Minimum) {
                push(out, hours, required_limit);
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every device whose terminals span more than `max_domain_delta`. A
/// device with a terminal on an undeclared net is not examined; an isolation
/// layer that will not validate refuses the row.
pub fn check_hv_domain(
    design: Design<'_>,
    intent: &IntentMap,
    table: &HvDomainTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let store = design.store;
    let devices = design.devices;
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let severity = table.head.severity[row];
        let limit = Measurement::Voltage(table.max_domain_delta[row]);

        // No exemption is an empty layer, so containment answers false.
        let mut isolation = ValidatedLayer::default();
        if let Some(layer) = table.isolation[row] {
            if validate_layer_into(store, layer, &mut isolation).is_err() {
                record_run(runs, out, before, rule, Outcome::Refused, 0);
                continue;
            }
        }

        let mut examined = 0u64;
        for index in 0..devices.len() {
            let device = DeviceId(u32::try_from(index).expect("a device table indexes with u32"));
            let (terminal_nets, _) = devices.terminals_of(device);
            let Some(spread) = domain_spread(intent, terminal_nets) else {
                continue;
            };
            examined += 1;
            let marker = devices.marker[index];
            let measured = Measurement::Voltage(spread);
            let exempt = encloses(&isolation, store.poly_bbox(marker));
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
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every pad net (no clamp model can be listed, so none has a discharge
/// path) and every guard ring narrower than `min_guard_ring_width` or further
/// than `max_tap_distance` from a declared supply.
pub fn check_esd_latchup(
    design: Design<'_>,
    intent: &IntentMap,
    table: &EsdLatchupTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    // With no declared supply there is no discharge target.
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let store = design.store;
    let nets = design.nets;
    // Row generation that last saw each net: dedups pad nets per row.
    scratch.net_marks.clear();
    scratch.net_marks.resize(nets.net_count(), 0);
    // The declared supplies' boxes, once.
    scratch.boxes.clear();
    for &net in &intent.supply_net {
        scratch
            .boxes
            .extend(nets.polys_of(net).iter().map(|&poly| store.poly_bbox(poly)));
    }

    let absent = (
        Measurement::Count(0),
        Measurement::Count(1),
        LimitSense::Minimum,
    );
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let severity = table.head.severity[row];
        let generation = u32::try_from(row + 1).expect("a rule table is small");
        let mut examined = 0u64;

        let pad_layer = table.pad[row];
        for poly in store.polys_on_layer(pad_layer) {
            let pad = PolyId(poly);
            let net = nets.net_of(pad);
            if net == NetId::NONE || scratch.net_marks[net.idx()] == generation {
                continue;
            }
            scratch.net_marks[net.idx()] = generation;
            examined += 1;
            out.push(Violation {
                rule,
                layer: pad_layer,
                severity,
                at: first_vertex(store, pad),
                measured: absent.0,
                limit: absent.1,
                shapes: (pad, None),
            });
        }

        let ring_layer = table.guard_ring[row];
        let min_width = Measurement::Length(table.min_guard_ring_width[row]);
        let max_tap = table.max_tap_distance[row];
        for poly in store.polys_on_layer(ring_layer) {
            let ring = PolyId(poly);
            let box_of = store.poly_bbox(ring);
            examined += 1;
            let at = first_vertex(store, ring);
            let mut push = |measured, limit| {
                out.push(Violation {
                    rule,
                    layer: ring_layer,
                    severity,
                    at,
                    measured,
                    limit,
                    shapes: (ring, None),
                });
            };
            // A ring's width is its narrow side.
            let width = Measurement::Length(box_of.width().min(box_of.height()));
            if width.violates(min_width, LimitSense::Minimum) {
                push(width, min_width);
            }
            // No supply at all is an absent tap, not a saturated distance.
            let (measured, limit, sense) =
                nearest_supply(&scratch.boxes, box_of).map_or(absent, |gap| {
                    (
                        Measurement::Length(gap),
                        Measurement::Length(max_tap),
                        LimitSense::Maximum,
                    )
                });
            if measured.violates(limit, sense) {
                push(measured, limit);
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// The widest nominal spread across a device's terminals; `None` when any
/// terminal is on an undeclared net.
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

/// True when one polygon of `isolation` covers all of `inner`, exactly.
fn encloses(isolation: &ValidatedLayer, inner: Bbox) -> bool {
    (0..isolation.len())
        .map(|idx| isolation.get(u32::try_from(idx).expect("a layer indexes with u32")))
        .any(|poly| poly.bbox().contains(inner) && covers(poly, inner))
}

/// True when `poly`'s region covers every point of `inner`: a corner inside,
/// in no hole, and no ring crossing the rectangle (a slot could pass between
/// four inside corners). Touching counts as crossing: fail closed.
fn covers(poly: PolygonRef<'_>, inner: Bbox) -> bool {
    let corner = Point {
        x: inner.xlo,
        y: inner.ylo,
    };
    let inside = point_in_ring(poly.outer(), corner)
        && !poly.holes().any(|hole| point_in_ring(hole, corner));
    inside && !crosses(poly.outer(), inner) && !poly.holes().any(|hole| crosses(hole, inner))
}

/// True when any edge of `ring` meets the boundary of `box_`.
fn crosses(ring: RingRef<'_>, box_: Bbox) -> bool {
    let (xs, ys) = ring.coords();
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
    let n = xs.len();
    let (mut ax, mut ay) = (xs[n - 1], ys[n - 1]);
    let mut hit = false;
    for i in 0..n {
        let (bx, by) = (xs[i], ys[i]);
        let edge = Seg {
            a: Point { x: ax, y: ay },
            b: Point { x: bx, y: by },
        };
        hit |= sides.iter().any(|&side| segments_intersect(edge, side));
        (ax, ay) = (bx, by);
    }
    hit
}

/// Distance from a guard ring to the nearest supply box; `None` when there is
/// none.
fn nearest_supply(supply: &[Bbox], ring: Bbox) -> Option<Dbu> {
    supply.iter().map(|&box_| separation(ring, box_)).min()
}

/// Rectilinear separation of two boxes; zero when they touch or overlap (the
/// inverse of [`Bbox::within`]).
fn separation(a: Bbox, b: Bbox) -> Dbu {
    let zero = Dbu::new_unchecked(0);
    let dx = (b.xlo - a.xhi).max(a.xlo - b.xhi).max(zero);
    let dy = (b.ylo - a.yhi).max(a.ylo - b.yhi).max(zero);
    dx.max(dy)
}
