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
use gpurify_ingest::deck::{DeviceKind, DeviceRecognition};
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
#[test]
fn a_rail_clamp_completes_every_pad_path() {
    let circuit = pads(true);
    let id = rule(14);
    let (violations, runs) = run_esd(&circuit, id);
    let run = common::run_of(&runs, id);
    assert_eq!((run.examined, run.violations), (4, 0));
    assert!(violations.rule.is_empty());
}
