//! Rules about surviving conditions the layout does not contain: wear-out,
//! high-voltage stress, ESD and latch-up.
//!
//! Data in: the solved supply grid, devices, design intent. Data out:
//! violations and one run per row. All three kinds skip without intent.

use crate::erc::facts::IntentMap;
use crate::erc::power::Power;
use crate::erc::rules::supply::clamp_rails;
use crate::erc::ruleset::RuleHead;
use crate::erc::voltage::NetVoltage;
use crate::erc::{
    fill_rows, first_vertex, record_run, skip_rows, Design, Scratch, BOLTZMANN_EV_PER_K,
};
use crate::report::{LimitSense, Measurement, Outcome, RuleRun, Violation, Violations};
use crate::topology::{DeviceId, NetId};
use gpurify_geom::rects::{clipped_area, decompose_into};
use gpurify_geom::view::validate_layer_into;
use gpurify_geom::{prefix, Dbu, Qty, Temperature, Voltage};
use gpurify_geom::{Bbox, LayerId, PolyId, ValidatedLayer};
use gpurify_ingest::StrId;

/// Voltage-stress lifetime on the supply grid: deck kind `reliability`,
/// written `reliability(; required_lifetime: h, reference_lifetime: h,
/// reference_stress: voltage, stress_exponent: n, reference_temperature: temp,
/// activation_energy: eV, max_abs_voltage: voltage, duty_cycle: frac)`.
///
/// One wear-out mechanism per row (TDDB, BTI or HCI, each with its own
/// constants), as an inverse power law in voltage times Arrhenius in
/// temperature, characterised as `reference_lifetime` at `reference_stress`
/// and `reference_temperature`:
///
/// `t(V, T) = t_ref * (V_ref / |V|)^n * exp(Ea / k * (1/T - 1/T_ref)) / duty_cycle`.
///
/// `V` is each node's solved voltage on the supply grid of [`IrDropTable`]
/// (`T` the run's operating temperature), so the stress is the supply voltage
/// where it is delivered: the rule reads no device. A row flags a node whose
/// `t` is below `required_lifetime`, and a node whose `|V|` is above
/// `max_abs_voltage`. A node at 0 V (a ground rail) is unstressed and lasts
/// forever.
///
/// # Limits
///
/// One operating temperature for the whole run (85 °C from the CLI), with no
/// self-heating. The stress is a supply node's voltage to ground, not the
/// voltage across any one device's oxide or channel.
///
/// Catalog: ERC-E5, ERC-F5 in the [check catalog]. Defined by [JEP122]
/// (failure models); JESD263, JESD241, JESD28, JESD60 and JESD202 (test
/// methods); [GF180MCU] §14.2; [IHP SG13G2] §2.15. Source tags are in
/// [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [JEP122]: https://www.jedec.org/standards-documents/docs/jep-122e
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
/// [IHP SG13G2]: https://github.com/IHP-GmbH/IHP-Open-PDK/tree/main/ihp-sg13g2/libs.doc/doc
/// [`IrDropTable`]: crate::erc::rules::electrical::IrDropTable
#[derive(Debug, Default)]
pub struct ReliabilityTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the smallest acceptable predicted lifetime, hours.
    pub required_lifetime_hours: Vec<f64>,
    /// The characterised point: this lifetime at this stress.
    pub reference_lifetime_hours: Vec<f64>,
    /// Per row: `V_ref`, the voltage `reference_lifetime_hours` was measured
    /// at, mV. Non-positive refuses the row.
    pub reference_stress: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Per row: `n`, the power-law voltage acceleration exponent.
    pub stress_exponent: Vec<f64>,
    /// Absolute, in kelvin.
    pub reference_temperature: Vec<Qty<Temperature, { prefix::BASE }>>,
    /// Per row: `Ea` of the Arrhenius term, eV.
    pub activation_energy_ev: Vec<f64>,
    /// Fraction of the lifetime under stress, in `0.0 ..= 1.0`.
    pub duty_cycle: Vec<f64>,
    /// Absolute voltage cap, checked directly.
    pub max_abs_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,
}

/// High-voltage domain span across a device: deck kind `hv_domain`, written
/// `hv_domain(; max_delta: voltage, isolation: layer | none)`.
///
/// Each terminal of a device takes the domains of every declared supply that
/// reaches its net through device channels ([`NetVoltage`]). A row flags a
/// device whose terminals see domain voltages more than `max_delta` apart: the
/// highest domain voltage reaching any terminal minus the lowest. A ground
/// supply counts as its own domain's voltage here, not 0 V, so this compares
/// domains, not node voltages. A device whose marker's bounding box is wholly
/// covered by one polygon of `isolation`, edges included (isolation drawn
/// exactly on the marker covers it), is exempt.
///
/// # Limits
///
/// The span across a device is checked. A net shorted to a high-voltage net is
/// not tagged high-voltage (DRC-083), and the tag consistency of low- and
/// high-voltage wells on one net is not checked (ERC-F10). Channels pass
/// voltage whatever their gate, so the span can over-report (ERC-F1).
///
/// Catalog: DRC-083 (partial), ERC-F10 (partial) in the [check catalog].
/// Defined by [SKY130] hv.X.1-hv.X.6, hvnwell.9 and hvnwell.10. Source tags
/// are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [SKY130]: https://skywater-pdk.readthedocs.io/en/main/rules/periphery.html
#[derive(Debug, Default)]
pub struct HvDomainTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the largest allowed domain span across a device, mV. Positive
    /// from a deck.
    pub max_domain_delta: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Marker layer exempting a device it fully covers; `None` exempts nothing.
    pub isolation: Vec<Option<LayerId>>,
}

/// Pad ESD clamping and pad guard rings: deck kind `esd_latchup`, written
/// `esd_latchup(pad, guard_ring; min_guard_ring_width: len,
/// max_tap_distance: len, clamps: models)`.
///
/// A row makes two checks. Pads: every net under a `pad` polygon is held to
/// the clamp path of
/// [`EsdTopologicalTable`](crate::erc::rules::supply::EsdTopologicalTable).
/// Guard rings: every polygon on `guard_ring` is flagged when the narrow side
/// of its bounding box is under `min_guard_ring_width`, or when the gap from
/// its bounding box to the nearest box of a shape on any declared supply net
/// (the larger of the x and y gaps; zero when they touch) is above
/// `max_tap_distance`. With no supply shapes at all, every ring is flagged as
/// having no tap.
///
/// # Limits
///
/// No shipped deck carries this rule: no manual states a pad guard-ring width
/// and tap distance in this form (ERC-D2). Both ring measures are
/// bounding-box measures, so a ring drawn as one closed polygon measures its
/// outer extent, not its band width; draw the ring as bars. The pad check
/// proves a clamp path exists, not its resistance or current capacity.
///
/// Catalog: ERC-C1, ERC-D2 (partial) in the [check catalog]. Defined by
/// [ESDA TR18.0-01] §4.5.2-4.5.4; [Khazhinsky 2012]; [ESDA TR18.0-02]
/// §3.1.2; [GF180MCU] IO.1-IO.4; [IHP SG13G2] §7.2.1. Source tags are in
/// [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [ESDA TR18.0-01]: https://www.esda.org/store/standards/product/457/esd-tr18-0-01-25/
/// [ESDA TR18.0-02]: https://www.esda.org/store/standards/product/307/esd-tr18-0-02-20/
/// [Khazhinsky 2012]: https://www.esda.org/assets/News/8df611267c/ESDEDA-InCompliance-part1.pdf
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
/// [IHP SG13G2]: https://github.com/IHP-GmbH/IHP-Open-PDK/tree/main/ihp-sg13g2/libs.doc/doc
#[derive(Debug, Default)]
pub struct EsdLatchupTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the marker layer whose polygons are pads.
    pub pad: Vec<LayerId>,
    /// Clamp device models per row, CSR.
    pub clamp_start: Vec<u32>,
    /// Clamp models, CSR by `clamp_start`; at least one per row.
    pub clamp: Vec<StrId>,
    /// Per row: the layer whose polygons are guard rings.
    pub guard_ring: Vec<LayerId>,
    /// Per row: the narrowest allowed ring bounding box side, database units.
    pub min_guard_ring_width: Vec<Dbu>,
    /// Furthest a guard ring may be from a declared supply.
    pub max_tap_distance: Vec<Dbu>,
}

/// Runs every [`ReliabilityTable`] row over the solved supply grid.
///
/// `examined` counts grid nodes, every node in every row. A violation sits at
/// the node, on its shape's layer: `|V|` in mV against `max_abs_voltage`, or
/// the predicted lifetime in hours (reported as a ratio) against
/// `required_lifetime`. Every row is refused when the grid could not be built
/// or solved, and skipped as [`check_ir_drop`] is. A row is refused when its
/// model is unusable (`duty_cycle` outside `0.0 ..= 1.0`, a non-positive
/// temperature, stress or required lifetime, or a non-finite result).
///
/// A net's current budget that reached no device does not refuse this rule:
/// with no current every node sits at nominal, the largest stress, which is
/// the fail-closed direction.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
///
/// [`check_ir_drop`]: crate::erc::rules::electrical::check_ir_drop
pub fn check_reliability(
    power: Power<'_>,
    intent: &IntentMap,
    operating_temperature: Qty<Temperature, { prefix::BASE }>,
    table: &ReliabilityTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let Ok(power) = power else {
        fill_rows(&table.head, Outcome::Refused, out, runs);
        return;
    };
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
                // A node at 0 V (a ground rail) is unstressed: infinite hours.
                let h = unit * (reference_stress / stress.raw().abs()).powf(exponent);
                sound &= !h.is_nan();
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
            if hour[node].is_finite() && hours.violates(required_limit, LimitSense::Minimum) {
                push(out, hours, required_limit);
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Runs every [`HvDomainTable`] row over every device.
///
/// `examined` counts devices whose every terminal some supply reaches; a
/// device with a terminal no supply reaches, or on no net, is not examined.
/// A violation sits at the first vertex of the device's marker, on the marker
/// layer, measuring the span in mV against `max_delta`. Every row is skipped
/// without usable intent; a row is refused when its isolation layer will not
/// validate.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_hv_domain(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
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
        let (mut rects, mut start) = (Vec::new(), Vec::new());
        decompose_into(&isolation, &mut rects, &mut start);

        let mut examined = 0u64;
        for index in 0..devices.len() {
            let device = DeviceId(u32::try_from(index).expect("a device table indexes with u32"));
            let (terminal_nets, _) = devices.terminals_of(device);
            let Some(spread) = domain_spread(voltage, terminal_nets) else {
                continue;
            };
            examined += 1;
            let marker = devices.marker[index];
            let measured = Measurement::Voltage(spread);
            let exempt = encloses(&rects, &start, store.poly_bbox(marker));
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

/// Runs every [`EsdLatchupTable`] row: its pad nets, then its guard rings.
///
/// `examined` counts distinct pad nets plus guard-ring polygons. A pad
/// violation sits at the first vertex of the net's first pad polygon on the
/// pad layer, measuring the rail kinds reached (0 or 1) against 2. A ring
/// violation sits at the ring's first vertex, measuring its width or tap gap
/// against the limit, or the count 0 against 1 when no supply shape exists.
/// Every row is skipped without usable intent.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
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

    let (mut seen, mut stack) = (Vec::new(), Vec::new());
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
        let clamps =
            &table.clamp[table.clamp_start[row] as usize..table.clamp_start[row + 1] as usize];
        for poly in store.polys_on_layer(pad_layer) {
            let pad = PolyId(poly);
            let net = nets.net_of(pad);
            if net == NetId::NONE || scratch.net_marks[net.idx()] == generation {
                continue;
            }
            scratch.net_marks[net.idx()] = generation;
            examined += 1;
            let rails = clamp_rails(design, intent, clamps, net, &mut seen, &mut stack);
            if rails < 2 {
                out.push(Violation {
                    rule,
                    layer: pad_layer,
                    severity,
                    at: first_vertex(store, pad),
                    measured: Measurement::Count(rails),
                    limit: Measurement::Count(2),
                    shapes: (pad, None),
                });
            }
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

/// The widest nominal spread across a device's terminals; `None` when no
/// supply reaches some terminal.
fn domain_spread(
    voltage: &NetVoltage,
    terminal_nets: &[NetId],
) -> Option<Qty<Voltage, { prefix::MILLI }>> {
    let mut lo = f64::INFINITY;
    let mut hi = f64::NEG_INFINITY;
    for &net in terminal_nets {
        if !voltage.known(net) {
            return None;
        }
        lo = lo.min(voltage.nominal_lo[net.idx()]);
        hi = hi.max(voltage.nominal_hi[net.idx()]);
    }
    (hi >= lo).then(|| Qty::new(hi - lo))
}

/// True when one polygon of the isolation layer, as disjoint rectangles
/// (`rects[start[p] .. start[p + 1]]`, holes left out), covers all of
/// `inner`: its area inside `inner` is all of `inner`'s. Exact, so isolation
/// drawn on `inner`'s own edges covers it.
fn encloses(rects: &[Bbox], start: &[u32], inner: Bbox) -> bool {
    start
        .windows(2)
        .any(|span| clipped_area(&rects[span[0] as usize..span[1] as usize], inner) == inner.area())
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
