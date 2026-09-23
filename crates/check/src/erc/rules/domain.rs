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
use gpurify_geom::{prefix, Qty, Voltage};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrId;

/// Device models and one voltage limit per row: `gate_oxide` and `drain_source`.
#[derive(Debug, Default)]
pub struct ModelLimitTable {
    pub head: RuleHead,
    /// Models each row applies to, CSR.
    pub model_start: Vec<u32>,
    pub model: Vec<StrId>,
    pub max_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,
}

/// Which MOS models sit in an n-well (bulk must be highest) and which on the
/// p-substrate (bulk must be lowest).
#[derive(Debug, Default)]
pub struct WellBiasTable {
    pub head: RuleHead,
    pub pmos_start: Vec<u32>,
    pub pmos: Vec<StrId>,
    pub nmos_start: Vec<u32>,
    pub nmos: Vec<StrId>,
}

/// Models allowed to take a gate from another power domain.
#[derive(Debug, Default)]
pub struct MissingLevelShifterTable {
    pub head: RuleHead,
    pub shifter_start: Vec<u32>,
    pub shifter: Vec<StrId>,
}

#[derive(Debug, Default)]
pub struct DomainCrossingTable {
    pub head: RuleHead,
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

/// Flag a device of the row's models whose gate can differ from its source,
/// drain or bulk by more than `max`: gate-oxide overstress.
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

/// Flag a device of the row's models whose drain can differ from its source
/// by more than `max`.
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

/// Flag a `pmos` device whose source or drain can rise above its bulk's
/// lowest voltage, and an `nmos` device whose source or drain can fall below
/// its bulk's highest: a junction that can forward-bias. Measured is that
/// excess, limit 0 V.
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

/// Flag a MOS device, not of a `shifters` model, whose gate is powered from a
/// domain its source and drain are not. Measured is the count of such domains.
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

/// Flag a device whose channel is powered from more than one domain: a DC
/// path between two power domains. Measured is the domain count.
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
