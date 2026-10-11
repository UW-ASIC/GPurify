//! Rules over the voltages each net can reach ([`NetVoltage`]).
//!
//! Data in: devices, design intent, the propagated voltages. Data out:
//! violations at device markers and one run per row. All skip without intent.
//! A device whose measured terminals no supply reaches is not examined.

use crate::erc::facts::IntentMap;
use crate::erc::ruleset::RuleHead;
use crate::erc::voltage::{is_channel, NetVoltage};
use crate::erc::{first_vertex, record_run, skip_rows, Design};
use crate::report::{LimitSense, Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use crate::topology::{DeviceId, NetId, TerminalRole};
use gpurify_geom::{prefix, Dbu, LayerId, Qty, Voltage};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrId;

/// Device models and one voltage limit per row: `gate_oxide` and `drain_source`.
///
/// Two deck kinds share this table type, one table each in
/// [`RuleSet`](crate::erc::RuleSet): `gate_oxide(; models: models, max:
/// voltage)` and `drain_source(; models: models, max: voltage)`. Both
/// compare, for every device of a listed model, the largest voltage two of
/// its terminals can reach apart with `max`. Each net's reachable range comes
/// from the declared supplies ([`NetVoltage`]), and `|V(a) - V(b)|` is worst
/// case: the top of one range minus the bottom of the other. What each kind
/// measures, and who defines it, is on [`check_gate_oxide`] and
/// [`check_drain_source`].
///
/// # Limits
///
/// A net's range is the span of every supply it reaches through a device
/// channel that can conduct: a transistor whose deck row states a gate
/// condition only while its gate allows it, any other channel always
/// ([`propagate_into`](crate::erc::voltage::propagate_into)). Threshold
/// drops and power-down are ignored, so this can over-report. A net no
/// supply reaches that way, such as a primary input
/// with no ESD diode, is not checked, and neither is a device whose measured
/// terminals sit on such nets. The shipped decks state the operating
/// voltages the PDKs document, not an absolute maximum rating.
#[derive(Debug, Default)]
pub struct ModelLimitTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Models each row applies to, CSR.
    pub model_start: Vec<u32>,
    /// Device model names, CSR by `model_start`; at least one per row.
    pub model: Vec<StrId>,
    /// Per row: the largest allowed terminal-to-terminal voltage, mV.
    /// Positive from a deck.
    pub max_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,
}

/// Well and body bias: deck kind `well_bias`, written
/// `well_bias(; pmos: models | none, nmos: models | none)`.
///
/// Which MOS models sit in an n-well (bulk must be highest) and which on the
/// p-substrate (bulk must be lowest). A row flags a `pmos` device whose
/// source or drain can rise above the lowest voltage its bulk can sit at, and
/// an `nmos` device whose source or drain can fall below the highest voltage
/// its bulk can sit at: a junction that can forward-bias, injecting into the
/// substrate and risking latch-up. Ranges come from the declared supplies
/// ([`NetVoltage`]). A row must name at least one model.
///
/// # Limits
///
/// Only transistors are checked, not guard rings (ERC-D3). A device needs a
/// bulk terminal on a net, and of the shipped decks only sky130 connects
/// wells as nets (ERC-F12). Ranges over-report as [`ModelLimitTable`]'s do.
///
/// Catalog: ERC-D3 (partial), ERC-F12 in the [check catalog]. Defined by
/// [GF180MCU] LU.9 and LU.10. Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
#[derive(Debug, Default)]
pub struct WellBiasTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// `pmos[pmos_start[i] .. pmos_start[i + 1]]` are row `i`'s n-well models.
    pub pmos_start: Vec<u32>,
    /// Models whose bulk must be the highest voltage, CSR by `pmos_start`.
    pub pmos: Vec<StrId>,
    /// `nmos[nmos_start[i] .. nmos_start[i + 1]]` are row `i`'s substrate
    /// models.
    pub nmos_start: Vec<u32>,
    /// Models whose bulk must be the lowest voltage, CSR by `nmos_start`.
    pub nmos: Vec<StrId>,
}

/// A missing level shifter: deck kind `missing_level_shifter`, written
/// `missing_level_shifter(; shifters: models | none)`.
///
/// Models allowed to take a gate from another power domain. A row flags a
/// transistor, not of a `shifters` model, whose gate is reached by a power
/// supply of a domain that reaches neither its source nor its drain: a signal
/// from one power domain driving a gate in another without a level shifter.
/// Reach is through device channels from the declared power supplies
/// ([`NetVoltage::power`]); a ground supply carries no domain here.
///
/// # Limits
///
/// Ranges over-report as [`ModelLimitTable`]'s do, and a gate or channel no
/// power supply reaches is not checked. Power states are not modelled, so
/// isolation at switchable-domain outputs (ERC-F7) and power-down undriven
/// gates (ERC-F8) are missing. This is a functional check, not ESD protection
/// of a domain crossing (ERC-C4).
///
/// Catalog: ERC-F6 in the [check catalog]. Defined by Calibre PERC (white
/// paper 81822, public material only); [IEEE 1801] (UPF, cited for scope and
/// not read). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [IEEE 1801]: https://standards.ieee.org/ieee/1801/11890/
#[derive(Debug, Default)]
pub struct MissingLevelShifterTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// `shifter[shifter_start[i] .. shifter_start[i + 1]]` are row `i`'s
    /// exempt models; a row may name none.
    pub shifter_start: Vec<u32>,
    /// Level-shifter models, exempt from the row; CSR by `shifter_start`.
    pub shifter: Vec<StrId>,
}

/// A DC path between power domains: deck kind `domain_crossing`, written
/// `domain_crossing()`.
///
/// A row flags a device whose channel (every terminal but gate and bulk; a
/// capacitor has none) is reached by power supplies of more than one domain:
/// a DC or sneak path that joins two power domains. Reach is through device
/// channels ([`NetVoltage::power`]), so every device touching a group of
/// channel-connected nets that two domains reach is flagged, not only the one
/// that joins them. Every row flags the same devices.
///
/// # Limits
///
/// A transistor whose deck row states no gate condition passes whatever its
/// gate, so it joins domains even when it is off, and this can over-report.
/// This is a functional check, not ESD
/// protection of a domain crossing (ERC-C4).
///
/// Catalog: ERC-F9 in the [check catalog]. Defined by Calibre PERC (datasheet
/// and white paper 81822, public material only). Source tags are in
/// [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
#[derive(Debug, Default)]
pub struct DomainCrossingTable {
    /// Rule id and severity per row. Rows differ only in id and severity.
    pub head: RuleHead,
}

/// Voltage-dependent spacing: deck kind `voltage_spacing`, written
/// `voltage_space(L; voltage: [v, ..], space: [len, ..])`, or
/// `voltage_space(A, B; ..)` between two layers.
///
/// A row is a table of steps: from each step's `voltage` up, two shapes on
/// different nets need that step's `space`. A pair is held to the step with
/// the largest voltage its nets can reach apart, the worst case
/// [`NetVoltage::worst_delta`]: the top of one net's range minus the bottom
/// of the other's. A pair whose voltage difference is below the first step
/// needs nothing from the row. "From the step up" is inclusive: a difference
/// exactly at a step's voltage needs that step's space, and a gap exactly at
/// the space passes. On one layer the pairs are shapes in different merged
/// figures; across two layers every pair, overlap included (a distance of
/// 0), reported on the first layer. Ranges come from the declared supplies
/// ([`NetVoltage`]).
///
/// # Limits
///
/// Shapes on one net are not judged: they sit at one voltage, and same-net
/// spacing is `space(L; nets: same)`'s. A pair with a net no supply reaches
/// is not judged. Ranges over-report as [`ModelLimitTable`]'s do, so two
/// nets that only ever move together read their full swing apart. The
/// layers must be conductors, so a pair is judged on extracted nets, not on
/// marker or tag layers (sky130 hvnwell.8's HV n-well is the n-well under
/// `hvi`). A cut-to-metal variant (LEF58 `TOCUT ABOVE | BELOW`) is the
/// two-layer form with the cut layer named.
///
/// Catalog: DRC-082, ERC-F11 in the [check catalog]. Defined by
/// [LEF58_VOLTAGESPACING] (`VOLTAGESPACING [TOCUT [ABOVE | BELOW]]
/// {voltage spacing} ... ;`, as `OpenROAD` parses it); voltage-aware DRC in
/// Calibre, IC Validator, Pegasus and Empyrean (public product material
/// only: "different spacings based on ... the difference in voltages
/// between different geometries", Siemens Calibre blog, 2015); [SKY130]
/// hvnwell.8 ("Min space between HV_nwell and any nwell on different nets",
/// whose HV n-well is a tag, not a voltage). Source tags are in
/// [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [LEF58_VOLTAGESPACING]: https://github.com/The-OpenROAD-Project/OpenROAD/blob/master/src/odb/src/lefin/lefTechLayerVoltageSpacing.cpp
/// [SKY130]: https://skywater-pdk.readthedocs.io/en/main/rules/periphery.html
#[derive(Debug, Default)]
pub struct VoltageSpacingTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the layer measured, and the one findings are reported on.
    pub layer: Vec<LayerId>,
    /// Per row: the second layer, `None` for spacing within `layer`.
    pub other: Vec<Option<LayerId>>,
    /// `voltage[step_start[i] .. step_start[i + 1]]` and the same range of
    /// `space` are row `i`'s steps; at least one per row.
    pub step_start: Vec<u32>,
    /// Each step's voltage, mV: zero or more, rising strictly within a row.
    pub voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Each step's spacing, database units: positive, never falling within a
    /// row.
    pub space: Vec<Dbu>,
}

/// Row `row` of a CSR column; an empty column (no rows pushed) answers empty.
fn csr<'a>(start: &[u32], column: &'a [StrId], row: usize) -> &'a [StrId] {
    match (start.get(row), start.get(row + 1)) {
        (Some(&lo), Some(&hi)) => &column[lo as usize..hi as usize],
        _ => &[],
    }
}

/// The net on the first terminal with `role`, or `NetId::NONE`.
fn terminal(nets: &[NetId], roles: &[TerminalRole], role: TerminalRole) -> NetId {
    roles
        .iter()
        .position(|&r| r == role)
        .map_or(NetId::NONE, |at| nets[at])
}

fn device_id(index: usize) -> DeviceId {
    DeviceId(u32::try_from(index).expect("a device table indexes with u32"))
}

/// One violation at a device's marker polygon.
fn push_device(
    design: Design<'_>,
    device: usize,
    rule: StrId,
    severity: Severity,
    measured: Measurement,
    limit: Measurement,
    out: &mut Violations,
) {
    let marker = design.devices.marker[device];
    out.push(Violation {
        rule,
        layer: design.store.poly_layer(marker),
        severity,
        at: first_vertex(design.store, marker),
        measured,
        limit,
        shapes: (marker, None),
    });
}

/// Run `measure` over every device of the row's models; flag a result above
/// the row's limit, mV. `None` from `measure` is a device not examined.
fn check_model_limit(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &ModelLimitTable,
    measure: fn(&NetVoltage, &[NetId], &[TerminalRole]) -> Option<f64>,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let devices = design.devices;
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let limit = Measurement::Voltage(table.max_voltage[row]);
        let models = csr(&table.model_start, &table.model, row);
        let mut examined = 0u64;
        for device in 0..devices.len() {
            if !models.contains(&devices.model[device]) {
                continue;
            }
            let (nets, roles) = devices.terminals_of(device_id(device));
            let Some(delta) = measure(voltage, nets, roles) else {
                continue;
            };
            examined += 1;
            let measured = Measurement::Voltage(Qty::new(delta));
            if measured.violates(limit, LimitSense::Maximum) {
                let severity = table.head.severity[row];
                push_device(design, device, rule, severity, measured, limit, out);
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Largest gate-to-source, -drain or -bulk voltage a device can see.
fn gate_stress(voltage: &NetVoltage, nets: &[NetId], roles: &[TerminalRole]) -> Option<f64> {
    let gate = terminal(nets, roles, TerminalRole::Gate);
    [
        TerminalRole::Source,
        TerminalRole::Drain,
        TerminalRole::Bulk,
    ]
    .into_iter()
    .filter_map(|role| voltage.worst_delta(gate, terminal(nets, roles, role)))
    .reduce(f64::max)
}

/// Largest drain-to-source voltage a device can see.
fn drain_source_stress(
    voltage: &NetVoltage,
    nets: &[NetId],
    roles: &[TerminalRole],
) -> Option<f64> {
    voltage.worst_delta(
        terminal(nets, roles, TerminalRole::Source),
        terminal(nets, roles, TerminalRole::Drain),
    )
}

/// Runs every `gate_oxide` row: gate-oxide overstress.
///
/// Flags a device of the row's models whose gate can differ from its source,
/// drain or bulk by more than `max`, the oxide stress its rating bounds. The
/// measure is the largest of those three worst-case differences whose two
/// nets some supply reaches.
///
/// `examined` counts devices of the row's models with at least one such
/// pair. A violation sits at the first vertex of the device's marker, on the
/// marker layer, measuring the difference in mV against `max`. Every row is
/// skipped without usable intent.
///
/// Catalog: ERC-F2 in the [check catalog]. Defined by [GF180MCU] §14.1.4.2;
/// [SKY130] hv rules; [ESDA TR22] §4.1; Calibre (public material only).
/// Limits are on [`ModelLimitTable`]; source tags are in [check-sources.md].
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
/// [SKY130]: https://skywater-pdk.readthedocs.io/en/main/rules/periphery.html
/// [ESDA TR22]: https://www.esda.org/store/standards/product/72/esd-tr22-0-01-14
pub fn check_gate_oxide(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &ModelLimitTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    check_model_limit(design, intent, voltage, table, gate_stress, out, runs);
}

/// Runs every `drain_source` row: junction and channel overstress.
///
/// Flags a device of the row's models whose drain can differ from its source
/// by more than `max`, the worst-case difference of the two nets' ranges.
///
/// `examined` counts devices of the row's models whose source and drain some
/// supply reaches. Violations report as [`check_gate_oxide`]'s do.
///
/// Catalog: ERC-F3 in the [check catalog]. Defined by [SKY130] hv rules; the
/// [IHP SG13G2] process specification. Limits are on [`ModelLimitTable`];
/// source tags are in [check-sources.md].
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [SKY130]: https://skywater-pdk.readthedocs.io/en/main/rules/periphery.html
/// [IHP SG13G2]: https://github.com/IHP-GmbH/IHP-Open-PDK/tree/main/ihp-sg13g2/libs.doc/doc
pub fn check_drain_source(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &ModelLimitTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    check_model_limit(
        design,
        intent,
        voltage,
        table,
        drain_source_stress,
        out,
        runs,
    );
}

/// Runs every [`WellBiasTable`] row.
///
/// `examined` counts devices of the row's models whose bulk, and at least
/// one of source and drain, some supply reaches. A violation sits at the
/// first vertex of the device's marker, on the marker layer, measuring the
/// excess in mV against 0 V. Every row is skipped without usable intent.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_well_bias(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &WellBiasTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let devices = design.devices;
    let limit = Measurement::Voltage(Qty::new(0.0));
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let pmos = csr(&table.pmos_start, &table.pmos, row);
        let nmos = csr(&table.nmos_start, &table.nmos, row);
        let mut examined = 0u64;
        for device in 0..devices.len() {
            let model = devices.model[device];
            let high = pmos.contains(&model);
            if !high && !nmos.contains(&model) {
                continue;
            }
            let (nets, roles) = devices.terminals_of(device_id(device));
            let bulk = terminal(nets, roles, TerminalRole::Bulk);
            let ends = [TerminalRole::Source, TerminalRole::Drain]
                .map(|role| terminal(nets, roles, role))
                .into_iter()
                .filter(|&net| voltage.known(net));
            let excess = if high {
                ends.map(|net| voltage.hi[net.idx()])
                    .reduce(f64::max)
                    .filter(|_| voltage.known(bulk))
                    .map(|top| top - voltage.lo[bulk.idx()])
            } else {
                ends.map(|net| voltage.lo[net.idx()])
                    .reduce(f64::min)
                    .filter(|_| voltage.known(bulk))
                    .map(|bottom| voltage.hi[bulk.idx()] - bottom)
            };
            let Some(excess) = excess else {
                continue;
            };
            examined += 1;
            let measured = Measurement::Voltage(Qty::new(excess));
            if measured.violates(limit, LimitSense::Maximum) {
                let severity = table.head.severity[row];
                push_device(design, device, rule, severity, measured, limit, out);
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Runs every [`MissingLevelShifterTable`] row over every MOS device.
///
/// `examined` counts transistors, not of a shifter model, whose gate and
/// whose source or drain some power supply reaches. A violation sits at the
/// first vertex of the device's marker, on the marker layer, measuring the
/// count of domains that reach the gate but not the channel against 0. Every
/// row is skipped without usable intent.
pub fn check_missing_level_shifter(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &MissingLevelShifterTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let devices = design.devices;
    let limit = Measurement::Count(0);
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let shifters = csr(&table.shifter_start, &table.shifter, row);
        let mut examined = 0u64;
        for device in 0..devices.len() {
            if devices.kind[device] != DeviceKind::Mos || shifters.contains(&devices.model[device])
            {
                continue;
            }
            let (nets, roles) = devices.terminals_of(device_id(device));
            let gate = voltage.power_of(terminal(nets, roles, TerminalRole::Gate));
            let channel = voltage.power_of(terminal(nets, roles, TerminalRole::Source))
                | voltage.power_of(terminal(nets, roles, TerminalRole::Drain));
            if gate == 0 || channel == 0 {
                continue;
            }
            examined += 1;
            let measured = Measurement::Count((gate & !channel).count_ones());
            if measured.violates(limit, LimitSense::Maximum) {
                let severity = table.head.severity[row];
                push_device(design, device, rule, severity, measured, limit, out);
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Runs every [`DomainCrossingTable`] row over every device.
///
/// `examined` counts devices whose channel some power supply reaches. A
/// violation sits at the first vertex of the device's marker, on the marker
/// layer, measuring the count of domains that reach the channel against 1.
/// Every row is skipped without usable intent.
pub fn check_domain_crossing(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &DomainCrossingTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let devices = design.devices;
    let limit = Measurement::Count(1);
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let mut examined = 0u64;
        for device in 0..devices.len() {
            let (nets, roles) = devices.terminals_of(device_id(device));
            let kind = devices.kind[device];
            let mask = nets
                .iter()
                .zip(roles)
                .filter(|&(_, &role)| is_channel(kind, role))
                .fold(0u64, |mask, (&net, _)| mask | voltage.power_of(net));
            if mask == 0 {
                continue;
            }
            examined += 1;
            let measured = Measurement::Count(mask.count_ones());
            if measured.violates(limit, LimitSense::Maximum) {
                let severity = table.head.severity[row];
                push_device(design, device, rule, severity, measured, limit, out);
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// The space a pair needs whose nets can reach `delta` mV apart: the step
/// with the largest voltage at or below `delta`, `None` below the first.
fn step_space(
    voltage: &[Qty<Voltage, { prefix::MILLI }>],
    space: &[Dbu],
    delta: f64,
) -> Option<Dbu> {
    voltage
        .iter()
        .rposition(|step| step.raw() <= delta)
        .map(|step| space[step])
}

/// Runs every [`VoltageSpacingTable`] row.
///
/// `examined` counts the pairs judged: shapes on two different nets that
/// some supply reaches, within the row's largest space of each other (on one
/// layer, in different merged figures). A violation sits at the midpoint of
/// the pair's nearest points, on the first layer, measuring the gap against
/// the step's space, with both shapes named. Every row is skipped without
/// usable intent; a row is refused when a layer will not validate or holds a
/// shape on no net.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_voltage_spacing(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &VoltageSpacingTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let mut scratch = crate::drc::Scratch::default();
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let steps = table.step_start[row] as usize..table.step_start[row + 1] as usize;
        let (volts, spaces) = (&table.voltage[steps.clone()], &table.space[steps]);
        let widest = *spaces.iter().max().expect("a row has a step");
        let need = |a: NetId, b: NetId| {
            if a == b {
                return None;
            }
            let delta = voltage.worst_delta(a, b)?;
            Some(step_space(volts, spaces, delta))
        };
        let (outcome, examined) = crate::drc::rules::spacing::net_pair_spacing(
            design.store,
            design.nets,
            rule,
            (table.layer[row], table.other[row]),
            widest,
            &mut scratch,
            out,
            need,
        );
        let severity = table.head.severity[row];
        for at in &mut out.severity[before..] {
            *at = severity;
        }
        record_run(runs, out, before, rule, outcome, examined);
    }
}
