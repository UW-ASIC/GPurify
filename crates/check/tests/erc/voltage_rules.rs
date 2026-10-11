//! Voltage propagation and the rules that read it, plus the ESD clamp path.
//!
//! Oracle throughout: construct-from-answer on hand-drawn netlists. Each
//! circuit is small enough that the range every net can reach is read off the
//! schematic: an inverter's output swings between the rails of the inverter
//! that drives it, so a 3.3 V inverter driving a 1.8 V inverter puts 3.3 V
//! across the 1.8 V gate's oxide when its drain sits at 0 V.

use crate::common;

use common::{head, millivolts, rule};
use gpurify_check::erc::facts::IntentMap;
use gpurify_check::erc::rules::domain::{
    check_domain_crossing, check_drain_source, check_gate_oxide, check_missing_level_shifter,
    check_well_bias, DomainCrossingTable, MissingLevelShifterTable, ModelLimitTable, WellBiasTable,
};
use gpurify_check::erc::rules::supply::{check_esd_topological, EsdTopologicalTable};
use gpurify_check::erc::voltage::{propagate_into, NetVoltage};
use gpurify_check::erc::Design;
use gpurify_check::report::{Measurement, Outcome, RuleRun, Violations};
use gpurify_check::topology::{DeviceTable, NetId, NetTable, TerminalRole};
use gpurify_geom::PolyId;
use gpurify_ingest::deck::{DeviceKind, DeviceRecognition, DeviceValue};
use gpurify_ingest::intent::{DomainId, SupplyRole};
use gpurify_ingest::{StrId, StrTable};
use gpurify_testgen::{layout_from_netlist, DeviceSpec, Floorplan, NetlistCase, NetlistSpec};

const IO: DomainId = DomainId(0);
const CORE: DomainId = DomainId(1);

/// A laid-out netlist, extracted, with the models it names.
struct Circuit {
    case: NetlistCase,
    nets: NetTable,
    devices: DeviceTable,
    strings: StrTable,
}

impl Circuit {
    fn design(&self) -> Design<'_> {
        Design {
            store: &self.case.store,
            nets: &self.nets,
            devices: &self.devices,
        }
    }

    /// The extracted id of netlist net `n`.
    fn net(&self, n: usize) -> NetId {
        self.nets.net_of(self.case.expected_net_polys[n][0])
    }

    fn model(&self, name: &str) -> StrId {
        self.strings
            .get(name)
            .expect("the netlist names this model")
    }

    fn models(&self, names: &[&str]) -> Vec<StrId> {
        names.iter().map(|name| self.model(name)).collect()
    }

    /// Supplies as `(netlist net, role, domain, domain nominal mV)`.
    fn intent(&self, supplies: &[(usize, SupplyRole, DomainId, f64)]) -> IntentMap {
        let mut rows: Vec<_> = supplies
            .iter()
            .map(|&(n, role, domain, mv)| (self.net(n), role, domain, mv))
            .collect();
        rows.sort_by_key(|row| row.0);
        IntentMap {
            declared: true,
            supply_net: rows.iter().map(|row| row.0).collect(),
            supply_role: rows.iter().map(|row| row.1).collect(),
            supply_domain: rows.iter().map(|row| row.2).collect(),
            supply_voltage: rows.iter().map(|row| millivolts(row.3)).collect(),
            limit_net: Vec::new(),
            limit: Vec::new(),
        }
    }

    fn voltage(&self, intent: &IntentMap) -> NetVoltage {
        let mut voltage = NetVoltage::default();
        propagate_into(&self.nets, &self.devices, intent, &mut voltage);
        voltage
    }
}

fn mos(model: &str, gate: u32, source: u32, drain: u32, bulk: u32) -> DeviceSpec {
    DeviceSpec {
        kind: DeviceKind::Mos,
        model: model.to_owned(),
        terminals: vec![
            (TerminalRole::Gate, gate),
            (TerminalRole::Source, source),
            (TerminalRole::Drain, drain),
            (TerminalRole::Bulk, bulk),
        ],
    }
}

fn two_pin(kind: DeviceKind, model: &str, a: u32, b: u32) -> DeviceSpec {
    DeviceSpec {
        kind,
        model: model.to_owned(),
        terminals: vec![(TerminalRole::Pin(0), a), (TerminalRole::Pin(1), b)],
    }
}

/// Lay out and extract `devices`. Every column shares one marker layer, so
/// recognisers with the same terminal layers would each claim every marker:
/// one recogniser per terminal-layer list, then each device takes its spec's
/// kind and model back.
fn build(nets: u32, devices: Vec<DeviceSpec>) -> Circuit {
    let mut strings = StrTable::default();
    let case = layout_from_netlist(
        &NetlistSpec { nets, devices },
        Floorplan::default(),
        &mut strings,
    );
    let mut nets = NetTable::default();
    gpurify_check::topology::extract_nets_into(&case.store, &case.connectivity, &mut nets);

    let full = &case.recognition;
    let mut recognition = DeviceRecognition {
        terminal_start: vec![0],
        ..DeviceRecognition::default()
    };
    for row in 0..full.kind.len() {
        let span = full.terminal_start[row] as usize..full.terminal_start[row + 1] as usize;
        let terminals = &full.terminal[span];
        let seen = (0..recognition.kind.len()).any(|kept| {
            let kept_span = recognition.terminal_start[kept] as usize
                ..recognition.terminal_start[kept + 1] as usize;
            recognition.terminal[kept_span] == *terminals
        });
        if !seen {
            recognition.kind.push(full.kind[row]);
            recognition.marker.push(full.marker[row]);
            recognition.model.push(full.model[row]);
            recognition.terminal.extend_from_slice(terminals);
            recognition
                .terminal_start
                .push(u32::try_from(recognition.terminal.len()).expect("small"));
        }
    }
    let mut devices = DeviceTable::default();
    gpurify_check::topology::device::recognise_into(&case.store, &nets, &recognition, &mut devices);
    assert_eq!(devices.len(), case.expected_devices.len());
    for (index, expected) in case.expected_devices.iter().enumerate() {
        assert_eq!(
            devices.marker[index], expected.marker,
            "device order is spec order"
        );
        devices.kind[index] = expected.kind;
        devices.model[index] = expected.model;
    }
    Circuit {
        case,
        nets,
        devices,
        strings,
    }
}

fn report() -> (Violations, Vec<RuleRun>) {
    (Violations::default(), Vec::new())
}

fn model_limit(id: StrId, models: Vec<StrId>, max_mv: f64) -> ModelLimitTable {
    ModelLimitTable {
        head: head(id),
        model_start: vec![0, u32::try_from(models.len()).expect("small")],
        model: models,
        max_voltage: vec![millivolts(max_mv)],
    }
}

fn shifters(id: StrId, models: Vec<StrId>) -> MissingLevelShifterTable {
    MissingLevelShifterTable {
        head: head(id),
        shifter_start: vec![0, u32::try_from(models.len()).expect("small")],
        shifter: models,
    }
}

/// Nets: 0 VDD33, 1 VDD18, 2 VSS, 3 IN (driven by nothing), 4 A, 5 Y.
/// A 3.3 V inverter (IN to A) drives a 1.8 V inverter (A to Y).
fn direct() -> Circuit {
    build(
        6,
        vec![
            mos("pfet33", 3, 0, 4, 0),
            mos("nfet33", 3, 2, 4, 2),
            mos("pfet18", 4, 1, 5, 1),
            mos("nfet18", 4, 2, 5, 2),
        ],
    )
}

/// VSS is the core domain's ground, stated at the domain's nominal as the
/// intent reader does.
fn two_domains(circuit: &Circuit) -> IntentMap {
    circuit.intent(&[
        (0, SupplyRole::Power, IO, 3_300.0),
        (1, SupplyRole::Power, CORE, 1_800.0),
        (2, SupplyRole::Ground, CORE, 1_800.0),
    ])
}

/// Oracle: construct-from-answer, read off `direct`'s schematic: VDD33 is 3.3 V
/// in the IO domain, VSS 0 V in none, A swings 0 to 3.3 V (the IO inverter's
/// rails), Y 0 to 1.8 V, and IN, driven by nothing through a channel, is
/// unknown.
#[test]
fn propagation_gives_each_inverter_output_its_own_rails() {
    let circuit = direct();
    let voltage = circuit.voltage(&two_domains(&circuit));
    let range = |n| {
        let net = circuit.net(n).idx();
        (voltage.lo[net], voltage.hi[net], voltage.power[net])
    };
    assert_eq!(range(0), (3_300.0, 3_300.0, 1 << IO.0));
    assert_eq!(
        range(2),
        (0.0, 0.0, 0),
        "a ground is 0 V and powers no domain"
    );
    assert_eq!(
        range(4),
        (0.0, 3_300.0, 1 << IO.0),
        "A swings rail to rail of the 3.3 V inverter"
    );
    assert_eq!(range(5), (0.0, 1_800.0, 1 << CORE.0));
    assert!(
        !voltage.known(circuit.net(3)),
        "IN reaches no supply through a channel: a gate passes nothing"
    );
}

/// The 1.8 V devices see A's 3.3 V on the gate while their drain Y can sit at
/// 0 V: 3.3 V across the oxide, over a 1.98 V rating. The 3.3 V devices'
/// gate IN reaches no supply, so they are not examined.
///
/// Oracle: construct-from-answer, read off `direct`'s schematic: both 1.8 V
/// devices see A's 3.3 V across the oxide against a 1.98 V rating, both lack a
/// shifter, and their own channels see only 1.8 V.
#[test]
fn a_3v3_signal_on_a_1v8_gate_overstresses_it_and_lacks_a_level_shifter() {
    let circuit = direct();
    let intent = two_domains(&circuit);
    let voltage = circuit.voltage(&intent);
    let thin = circuit.models(&["pfet18", "nfet18"]);

    let id = rule(1);
    let (mut violations, mut runs) = report();
    check_gate_oxide(
        circuit.design(),
        &intent,
        &voltage,
        &model_limit(id, thin.clone(), 1_980.0),
        &mut violations,
        &mut runs,
    );
    let run = common::run_of(&runs, id);
    assert_eq!(
        (run.outcome, run.examined, run.violations),
        (Outcome::Ran, 2, 2)
    );
    for row in 0..2 {
        assert_eq!(
            violations.measured[row],
            Measurement::Voltage(millivolts(3_300.0))
        );
        assert_eq!(
            violations.shape_a[row],
            circuit.case.expected_devices[row + 2].marker
        );
    }

    let id = rule(2);
    let (mut violations, mut runs) = report();
    check_missing_level_shifter(
        circuit.design(),
        &intent,
        &voltage,
        &shifters(id, Vec::new()),
        &mut violations,
        &mut runs,
    );
    let run = common::run_of(&runs, id);
    assert_eq!((run.examined, run.violations), (2, 2));
    assert_eq!(violations.measured[0], Measurement::Count(1));

    // The same limits on healthy 1.8 V channels: 1.8 V drain to source.
    let id = rule(3);
    let (mut violations, mut runs) = report();
    check_drain_source(
        circuit.design(),
        &intent,
        &voltage,
        &model_limit(id, thin, 1_980.0),
        &mut violations,
        &mut runs,
    );
    let run = common::run_of(&runs, id);
    assert_eq!((run.examined, run.violations), (2, 0));
    assert!(violations.rule.is_empty());
}

/// A 1.98 V-rated model placed in the 3.3 V inverter: its drain A can sit at
/// 3.3 V while its source is at 0 V (nfet33) or the reverse (pfet33).
///
/// Oracle: construct-from-answer. The 1.98 V-rated models sit in the 3.3 V
/// inverter, whose drain A swings to 3.3 V against a 0 V source, so both are
/// flagged at 3.3 V.
#[test]
fn a_thin_device_across_3v3_is_a_drain_source_overvoltage() {
    let circuit = direct();
    let intent = two_domains(&circuit);
    let voltage = circuit.voltage(&intent);
    let id = rule(4);
    let (mut violations, mut runs) = report();
    check_drain_source(
        circuit.design(),
        &intent,
        &voltage,
        &model_limit(id, circuit.models(&["pfet33", "nfet33"]), 1_980.0),
        &mut violations,
        &mut runs,
    );
    let run = common::run_of(&runs, id);
    assert_eq!((run.examined, run.violations), (2, 2));
    assert_eq!(
        violations.measured[0],
        Measurement::Voltage(millivolts(3_300.0))
    );
}

/// Nets: 0 VDD33, 1 VDD18, 2 VSS, 3 IN, 4 A, 5 Y, 6 B. A thick-oxide
/// level-shifter inverter (A to B) powered from 1.8 V sits between the 3.3 V
/// inverter and the 1.8 V inverter (B to Y).
fn shifted() -> Circuit {
    build(
        7,
        vec![
            mos("pfet33", 3, 0, 4, 0),
            mos("nfet33", 3, 2, 4, 2),
            mos("ls_p", 4, 1, 6, 1),
            mos("ls_n", 4, 2, 6, 2),
            mos("pfet18", 6, 1, 5, 1),
            mos("nfet18", 6, 2, 5, 2),
        ],
    )
}

/// Oracle: construct-from-answer, read off `shifted`'s schematic: B swings 0 to
/// 1.8 V, A's 3.3 V is within the shifter's 3.63 V, the declared shifter needs
/// no shifter of its own, an undeclared one is the crossing, and no channel
/// joins the two supplies.
#[test]
fn the_same_signal_through_a_declared_level_shifter_is_clean() {
    let circuit = shifted();
    let intent = two_domains(&circuit);
    let voltage = circuit.voltage(&intent);

    let id = rule(5);
    let (_, mut runs) = report();
    let mut violations = Violations::default();
    check_gate_oxide(
        circuit.design(),
        &intent,
        &voltage,
        &model_limit(id, circuit.models(&["pfet18", "nfet18"]), 1_980.0),
        &mut violations,
        &mut runs,
    );
    let rated = rule(6);
    check_gate_oxide(
        circuit.design(),
        &intent,
        &voltage,
        &model_limit(rated, circuit.models(&["ls_p", "ls_n"]), 3_630.0),
        &mut violations,
        &mut runs,
    );
    assert_eq!(common::run_of(&runs, id).examined, 2);
    assert_eq!(common::run_of(&runs, rated).examined, 2);
    assert!(
        violations.rule.is_empty(),
        "B swings 0 to 1.8 V; A's 3.3 V is within the shifter's 3.63 V"
    );

    let id = rule(7);
    let (mut violations, mut runs) = report();
    let table = shifters(id, circuit.models(&["ls_p", "ls_n"]));
    check_missing_level_shifter(
        circuit.design(),
        &intent,
        &voltage,
        &table,
        &mut violations,
        &mut runs,
    );
    let run = common::run_of(&runs, id);
    assert_eq!(
        (run.examined, run.violations),
        (2, 0),
        "only the 1.8 V inverter is examined"
    );

    // Undeclared, the shifter's own devices are the domain crossing.
    let id = rule(8);
    let (mut violations, mut runs) = report();
    check_missing_level_shifter(
        circuit.design(),
        &intent,
        &voltage,
        &shifters(id, Vec::new()),
        &mut violations,
        &mut runs,
    );
    assert_eq!(common::run_of(&runs, id).violations, 2);
    assert_eq!(
        violations.shape_a[0],
        circuit.case.expected_devices[2].marker
    );

    let id = rule(9);
    let (mut violations, mut runs) = report();
    check_domain_crossing(
        circuit.design(),
        &intent,
        &voltage,
        &DomainCrossingTable { head: head(id) },
        &mut violations,
        &mut runs,
    );
    let run = common::run_of(&runs, id);
    assert_eq!(
        (run.examined, run.violations),
        (6, 0),
        "no channel joins the two supplies"
    );
}

/// Nets: 0 VDD33, 1 VDD18, 2 VSS, 3 OUT, 4 X. A pfet in a well tied to 1.8 V
/// drives OUT from 3.3 V: its source junction forward-biases by 1.5 V. An
/// nfet then passes OUT to X, which a 1.8 V pfet also drives: one channel
/// path from 3.3 V to 1.8 V.
///
/// Oracle: construct-from-answer, read off the schematic above: OUT and X reach
/// 3.3 V through the pass gate, so both 1.8 V-well pfets are 1.5 V
/// forward-biased, and every channel touches OUT or X, which reaches both
/// domains.
#[test]
fn a_well_below_its_source_and_a_pass_gate_between_domains_are_flagged() {
    let circuit = build(
        5,
        vec![
            mos("pfet", 2, 0, 3, 1),
            mos("nfet", 0, 2, 3, 2),
            mos("nfet", 0, 3, 4, 2),
            mos("pfet", 2, 1, 4, 1),
        ],
    );
    let intent = two_domains(&circuit);
    let voltage = circuit.voltage(&intent);

    let id = rule(10);
    let (mut violations, mut runs) = report();
    let table = WellBiasTable {
        head: head(id),
        pmos_start: vec![0, 1],
        pmos: circuit.models(&["pfet"]),
        nmos_start: vec![0, 1],
        nmos: circuit.models(&["nfet"]),
    };
    check_well_bias(
        circuit.design(),
        &intent,
        &voltage,
        &table,
        &mut violations,
        &mut runs,
    );
    let run = common::run_of(&runs, id);
    assert_eq!(run.examined, 4);
    // OUT and X join through the pass gate, so both reach 3.3 V: both pfets'
    // 1.8 V wells sit 1.5 V below a source or drain.
    assert_eq!(run.violations, 2);
    assert_eq!(
        violations.measured[0],
        Measurement::Voltage(millivolts(1_500.0))
    );
    assert_eq!(
        violations.shape_a[0],
        circuit.case.expected_devices[0].marker
    );
    assert_eq!(
        violations.shape_a[1],
        circuit.case.expected_devices[3].marker
    );

    let id = rule(11);
    let (mut violations, mut runs) = report();
    check_domain_crossing(
        circuit.design(),
        &intent,
        &voltage,
        &DomainCrossingTable { head: head(id) },
        &mut violations,
        &mut runs,
    );
    let run = common::run_of(&runs, id);
    assert_eq!(
        (run.examined, run.violations),
        (4, 4),
        "every channel touches OUT or X"
    );
    assert_eq!(violations.measured[0], Measurement::Count(2));
}

/// Oracle: the documented contract of an intent-gated row: with no supply
/// declared it records `Skipped(NoDesignIntent)` and reports nothing.
#[test]
fn the_voltage_rules_skip_without_intent() {
    let circuit = direct();
    let none = IntentMap::default();
    let voltage = circuit.voltage(&none);
    let id = rule(12);
    let (mut violations, mut runs) = report();
    check_gate_oxide(
        circuit.design(),
        &none,
        &voltage,
        &model_limit(id, circuit.models(&["nfet18"]), 1_980.0),
        &mut violations,
        &mut runs,
    );
    common::assert_skipped_for_intent(&runs, &violations, id);
}

/// Nets: 0 VDD, 1 VSS, 2 PAD, 3 PAD2; every rail is a pad. PAD has an up
/// diode to VDD and a down diode from VSS. PAD2 has only the up diode; its
/// resistor to VSS is not a clamp model and must not count.
fn pads(rail_clamp: bool) -> Circuit {
    let mut devices = vec![
        two_pin(DeviceKind::Diode, "esd_diode", 2, 0),
        two_pin(DeviceKind::Diode, "esd_diode", 1, 2),
        two_pin(DeviceKind::Diode, "esd_diode", 3, 0),
        two_pin(DeviceKind::Resistor, "rpoly", 3, 1),
    ];
    if rail_clamp {
        devices.push(mos("rail_clamp", 1, 1, 0, 1));
    }
    build(4, devices)
}

fn run_esd(circuit: &Circuit, id: StrId) -> (Violations, Vec<RuleRun>) {
    let intent = circuit.intent(&[
        (0, SupplyRole::Power, CORE, 1_800.0),
        (1, SupplyRole::Ground, CORE, 1_800.0),
    ]);
    let mut clamps = circuit.models(&["esd_diode"]);
    clamps.extend(circuit.strings.get("rail_clamp"));
    let (mut violations, mut runs) = report();
    check_esd_topological(
        circuit.design(),
        &intent,
        &EsdTopologicalTable {
            head: head(id),
            pad: vec![circuit.case.layers.rail],
            clamp_start: vec![0, u32::try_from(clamps.len()).expect("small")],
            clamp: clamps,
        },
        &mut violations,
        &mut runs,
    );
    (violations, runs)
}

/// With no rail clamp, VDD and VSS reach only themselves and PAD2 only VDD:
/// three pads short of a rail. PAD has a clamp to each and is clean.
///
/// Oracle: construct-from-answer, read off `pads`: PAD has a clamp to each
/// rail, PAD2 only to VDD (its resistor is no clamp model), and the rails reach
/// only themselves: three of four pads flagged.
#[test]
fn a_pad_missing_its_vss_clamp_is_flagged_and_one_with_both_is_clean() {
    let circuit = pads(false);
    let id = rule(13);
    let (violations, runs) = run_esd(&circuit, id);
    let run = common::run_of(&runs, id);
    assert_eq!((run.examined, run.violations), (4, 3));
    let flagged: Vec<PolyId> = violations.shape_a.clone();
    let on = |n: usize| circuit.case.expected_net_polys[n][0];
    assert_eq!(flagged, vec![on(0), on(1), on(3)]);
    assert!(violations
        .measured
        .iter()
        .all(|&m| m == Measurement::Count(1)));
}

/// A rail clamp from VDD to VSS completes PAD2's path (up diode, then the
/// rail clamp) and each supply pad's.
///
/// Oracle: construct-from-answer. The rail clamp joins VDD to VSS, which
/// completes PAD2's path and each rail's: four pads, none flagged.
#[test]
fn a_rail_clamp_completes_every_pad_path() {
    let circuit = pads(true);
    let id = rule(14);
    let (violations, runs) = run_esd(&circuit, id);
    let run = common::run_of(&runs, id);
    assert_eq!((run.examined, run.violations), (4, 0));
    assert!(violations.rule.is_empty());
}

// ----------------------------------------- conditional propagation (ERC-F1)

/// `circuit` with device `device`'s gate condition set as a deck row would:
/// `on_gate_min` or `on_gate_max`, mV.
fn switched(mut circuit: Circuit, device: usize, min: Option<f64>, max: Option<f64>) -> Circuit {
    let count = circuit.devices.len();
    circuit.devices.value.resize(count, DeviceValue::default());
    circuit.devices.value[device] = DeviceValue {
        on_gate_min_mv: min,
        on_gate_max_mv: max,
        ..DeviceValue::default()
    };
    circuit
}

/// Nets: 0 VH (3.3 V), 1 G, 2 X, 3 VSS. One transistor from VH to X, its gate
/// on G, which the test ties to a supply of its own (or to nothing).
fn one_switch(min: Option<f64>, max: Option<f64>) -> Circuit {
    switched(build(4, vec![mos("sw", 1, 0, 2, 3)]), 0, min, max)
}

/// The intent of [`one_switch`]: VH and VSS, and G held at `gate` mV (a
/// ground at 0 V, a power supply of its own domain otherwise), or `None`
/// for a gate no supply reaches.
fn gate_at(circuit: &Circuit, gate: Option<f64>) -> IntentMap {
    let mut supplies = vec![
        (0, SupplyRole::Power, IO, 3_300.0),
        (3, SupplyRole::Ground, IO, 3_300.0),
    ];
    match gate {
        None => {}
        Some(mv) if mv > 0.0 => supplies.push((1, SupplyRole::Power, CORE, mv)),
        Some(_) => supplies.push((1, SupplyRole::Ground, CORE, 1_000.0)),
    }
    circuit.intent(&supplies)
}

/// Oracle: the public Calibre PERC white paper (Siemens 81822, figure 1):
/// "The NMOS is ON when the voltage at gate pin is >= 1 V, and OFF when the
/// voltage at gate pin is < 1 V"; "The PMOS is ON when the voltage at gate
/// pin is <= 0 V, and OFF when the voltage at gate pin is > 0 V". An ON
/// switch passes VH (3.3 V) to X; an OFF one leaves X unreached. Each
/// threshold is swept a millivolt either side, and a gate no supply reaches
/// may be anything, so its switch conducts.
#[test]
fn a_switch_passes_voltage_only_when_its_gate_can_turn_it_on() {
    let reaches = |circuit: &Circuit, gate: Option<f64>| {
        let voltage = circuit.voltage(&gate_at(circuit, gate));
        let x = circuit.net(2);
        voltage
            .known(x)
            .then(|| (voltage.lo[x.idx()], voltage.hi[x.idx()]))
    };
    let nmos = one_switch(Some(1_000.0), None);
    for (gate, on) in [
        (999.0, false),
        (1_000.0, true),
        (1_001.0, true),
        (0.0, false),
    ] {
        assert_eq!(
            reaches(&nmos, Some(gate)),
            on.then_some((3_300.0, 3_300.0)),
            "an on_gate_min 1V switch with its gate at {gate} mV"
        );
    }
    assert_eq!(
        reaches(&nmos, None),
        Some((3_300.0, 3_300.0)),
        "an undriven gate"
    );
    let pmos = one_switch(None, Some(0.0));
    for (gate, on) in [(0.0, true), (1.0, false), (3_300.0, false)] {
        assert_eq!(
            reaches(&pmos, Some(gate)),
            on.then_some((3_300.0, 3_300.0)),
            "an on_gate_max 0V switch with its gate at {gate} mV"
        );
    }
    let plain = build(4, vec![mos("sw", 1, 0, 2, 3)]);
    assert_eq!(
        reaches(&plain, Some(0.0)),
        Some((3_300.0, 3_300.0)),
        "a transistor with no condition conducts whatever its gate"
    );
}

/// Nets: 0 VH (3.3 V), 1 VSS, 2 G, 3 X. Switch 0 (`on_gate_min 1V`, gate on
/// VSS) can never turn on; it is G's only path to a supply. Switch 1 (the
/// same condition, gate on G) joins VH to X.
///
/// Oracle: construct-from-answer. With every channel conducting, G would
/// reach VH, so G is not an input to the cell; but switch 0 is always off,
/// so G floats, may be anything, and switch 1 may conduct: X reaches 3.3 V
/// and G stays unreached. A wrong model either leaves switch 1 off (X
/// unreached) or lets switch 0 conduct (G reached).
#[test]
fn a_gate_behind_a_switch_that_never_turns_on_floats_and_its_switch_conducts() {
    let circuit = build(4, vec![mos("sw", 1, 0, 2, 1), mos("sw", 2, 0, 3, 1)]);
    let circuit = switched(circuit, 0, Some(1_000.0), None);
    let circuit = switched(circuit, 1, Some(1_000.0), None);
    let voltage = circuit.voltage(&circuit.intent(&[
        (0, SupplyRole::Power, IO, 3_300.0),
        (1, SupplyRole::Ground, IO, 3_300.0),
    ]));
    assert!(!voltage.known(circuit.net(2)), "G floats");
    let x = circuit.net(3).idx();
    assert_eq!((voltage.lo[x], voltage.hi[x]), (3_300.0, 3_300.0));
}

/// Nets: 0 VDD (1.8 V), 1 VSS, 2 VH (3.3 V), 3 IN, 4 A, 5 OUT, 6 B. A 1.8 V
/// inverter (IN to A) drives the gates of an `on_gate_min 2.5V` switch from
/// VH to OUT and an `on_gate_min 1V` switch from VH to B.
///
/// Oracle: construct-from-answer. A swings 0 to 1.8 V in the core domain,
/// which never reaches 2.5 V, so the first switch is off and OUT is
/// unreached; it reaches 1 V, so the second conducts and B sits at VH's
/// 3.3 V in the I/O domain. The inverter's own transistors have no
/// condition, and IN no supply.
#[test]
fn a_gate_range_from_propagation_decides_the_switch_it_drives() {
    let circuit = build(
        7,
        vec![
            mos("pfet18", 3, 0, 4, 0),
            mos("nfet18", 3, 1, 4, 1),
            mos("sw", 4, 2, 5, 1),
            mos("sw", 4, 2, 6, 1),
        ],
    );
    let circuit = switched(circuit, 2, Some(2_500.0), None);
    let circuit = switched(circuit, 3, Some(1_000.0), None);
    let voltage = circuit.voltage(&circuit.intent(&[
        (0, SupplyRole::Power, CORE, 1_800.0),
        (1, SupplyRole::Ground, CORE, 1_800.0),
        (2, SupplyRole::Power, IO, 3_300.0),
    ]));
    assert!(
        !voltage.known(circuit.net(5)),
        "OUT: its switch never turns on"
    );
    let a = circuit.net(4).idx();
    assert_eq!((voltage.lo[a], voltage.hi[a]), (0.0, 1_800.0));
    assert_eq!(voltage.power[a], 1 << CORE.0);
    let b = circuit.net(6).idx();
    assert_eq!((voltage.lo[b], voltage.hi[b]), (3_300.0, 3_300.0));
    assert_eq!(voltage.power[b], 1 << IO.0);
}
