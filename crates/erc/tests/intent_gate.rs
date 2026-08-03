//! The six intent-gated rules, run both ways.
//!
//! This is the split the crate is shaped around. Six rules cannot answer their
//! question without facts no process supplies — which nets are supplies, at
//! what voltage, drawing what current — and the failure mode being guarded
//! against is not a wrong answer but a *silent* one: with no design intent an
//! ungated rule compares nothing, finds nothing, and reports clean.
//!
//! Every rule below therefore gets two runs over the **same** design, differing
//! only in whether intent was declared. Without it the rule must record
//! `Skipped(NoDesignIntent)`; with it the rule must actually examine something.
//! A test covering only the second half would pass against exactly the bug this
//! design exists to prevent.

mod common;

use common::{
    assert_skipped_for_intent, declared_supplies, head, limit_net, microamps, millivolts, ohms,
    rule, series_chain, solve,
};
use gpurify_core::LayerId;
use gpurify_derived::Evaluator;
use gpurify_erc::facts::IntentMap;
use gpurify_erc::power::{NetNetworks, Solved};
use gpurify_erc::rules::electrical::{
    check_electromigration, check_em_current_density, check_ir_drop, ElectromigrationTable,
    EmCurrentDensityTable, IrDropTable,
};
use gpurify_erc::rules::reliability::{
    check_esd_latchup, check_hv_domain, check_reliability, EsdLatchupTable, HvDomainTable,
    ReliabilityTable,
};
use gpurify_erc::{Design, Scratch};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::intent::{DomainId, NetLimits, SupplyRole};
use gpurify_ingest::{StrId, StrTable};
use gpurify_report::{Outcome, RuleRun, Violations};
use gpurify_testgen::{dbu, DeviceSpec, Floorplan, NetlistCase, NetlistSpec};
use gpurify_topology::{DeviceTable, NetId, NetTable, TerminalRole};
use gpurify_units::{prefix, CurrentDensity, Qty, Temperature};

/// A supply grid and its solution, so the four solve-reading rules have
/// something real to be gated over.
struct Powered {
    grid: gpurify_erc::power::PowerGrid,
    solution: gpurify_erc::power::PowerSolution,
}

impl Powered {
    fn new() -> Self {
        let grid = series_chain(4, 2.5, 1_800.0, 1_000.0);
        let solution = solve(&grid);
        Self { grid, solution }
    }

    fn solved(&self) -> Solved<'_> {
        Solved {
            grid: &self.grid,
            solution: &self.solution,
        }
    }
}

/// Intent declaring the grid's one net as a supply, with a drop limit on it —
/// the minimum a solve-reading rule needs before it has anything to compare.
fn supply_intent() -> IntentMap {
    let mut map = declared_supplies(NetId(0), NetId(1), 1_800.0);
    limit_net(
        &mut map,
        NetId(0),
        NetLimits {
            max_drop: Some(millivolts(6.0)),
            max_drop_fraction: Some(0.05),
            max_overvoltage: Some(millivolts(100.0)),
            budget_current_ua: Some(1_000.0),
        },
    );
    map
}

fn density(value: f64) -> Qty<CurrentDensity, { prefix::BASE }> {
    Qty::new(value)
}

/// A one-row electromigration table with physically stated parameters.
///
/// `reference_temperature` is **kelvin**: 358.15 K is 85 °C, and writing the
/// bare 85 here would be the bug the field's doc comment warns about.
fn electromigration_table(id: StrId, layer: LayerId) -> ElectromigrationTable {
    ElectromigrationTable {
        head: head(id),
        layer_start: vec![0, 1],
        layer: vec![layer],
        max_density: vec![density(1e6)],
        max_current_per_cut: vec![microamps(200.0)],
        blech_limit: vec![microamps(1.0)],
        reference_temperature: vec![Qty::<Temperature, { prefix::BASE }>::new(358.15)],
        activation_energy_ev: vec![0.7],
        current_exponent: vec![2.0],
    }
}

fn reliability_table(id: StrId) -> ReliabilityTable {
    ReliabilityTable {
        head: head(id),
        required_lifetime_hours: vec![87_600.0],
        mechanism: vec![StrId(900)],
        reference_lifetime_hours: vec![10_000.0],
        reference_stress: vec![millivolts(2_000.0)],
        stress_exponent: vec![4.0],
        reference_temperature: vec![Qty::<Temperature, { prefix::BASE }>::new(398.15)],
        activation_energy_ev: vec![0.6],
        duty_cycle: vec![0.5],
        max_abs_voltage: vec![millivolts(1_950.0)],
    }
}

fn empty_report() -> (Violations, Vec<RuleRun>) {
    (Violations::default(), Vec::new())
}

/// Oracle: construct-from-answer. `resolve_intent_into` is the single place the
/// `Option` becomes a table, and `declared` is the flag six rules read before
/// anything else. No intent file must produce a map that says so — and one that
/// says so must not be usable, or the six rules downstream have nothing to
/// stand on.
#[test]
fn no_intent_file_resolves_to_a_map_that_says_nothing_was_declared() {
    let ports = gpurify_topology::PortTable::default();
    let nets = NetTable::default();
    let mut map = IntentMap::default();
    gpurify_erc::resolve_intent_into(None, &ports, &nets, &mut map);

    assert!(
        !map.declared,
        "a run given no intent file must record that, not an empty declaration"
    );
    assert!(
        !map.is_usable(),
        "a map with nothing declared has nothing for an intent-gated rule to check against"
    );
    assert_eq!(map.supply_count(), 0);
    assert_eq!(map.supply_of(NetId(0)), None);
    assert_eq!(map.nominal_voltage(NetId(0)), None);
    let limits = map.limits_of(NetId(0));
    assert!(
        limits.max_drop.is_none()
            && limits.max_drop_fraction.is_none()
            && limits.max_overvoltage.is_none()
            && limits.budget_current_ua.is_none(),
        "an undeclared net is not checked; it is not unlimited"
    );
}

/// Oracle: construct-from-answer. A map holding declared supplies is usable,
/// and answers about the nets it holds and only those. The negative half
/// matters as much as the positive: a lookup that answered about an undeclared
/// net would give an intent-gated rule a nominal voltage nobody stated.
#[test]
fn a_map_holding_declared_supplies_is_usable_and_answers_only_about_them() {
    let map = supply_intent();

    assert!(map.declared);
    assert!(map.is_usable());
    assert_eq!(map.supply_count(), 2);
    assert_eq!(
        map.supply_of(NetId(0)),
        Some((DomainId(0), SupplyRole::Power))
    );
    assert_eq!(
        map.supply_of(NetId(1)),
        Some((DomainId(0), SupplyRole::Ground))
    );
    assert_eq!(map.supply_of(NetId(7)), None);
    assert_eq!(map.nominal_voltage(NetId(0)), Some(millivolts(1_800.0)));
    assert_eq!(map.nominal_voltage(NetId(7)), None);
    assert_eq!(map.limits_of(NetId(0)).max_drop, Some(millivolts(6.0)));
    assert_eq!(map.limits_of(NetId(1)).max_drop, None);
}

/// Oracle: construct-from-answer, on the gate itself. IR drop has two ways to
/// lose its inputs — no solve, or a solve with nothing declared — and both must
/// produce the same loud skip. With the inputs present the rule examines the
/// five nodes of the limited net, which is what makes the skip mean something.
#[test]
fn ir_drop_skips_without_intent_and_examines_every_limited_node_with_it() {
    let powered = Powered::new();
    let id = rule(10);
    let table = IrDropTable { head: head(id) };

    let (mut violations, mut runs) = empty_report();
    check_ir_drop(None, &supply_intent(), &table, &mut violations, &mut runs);
    assert_skipped_for_intent(&runs, &violations, id);

    let (mut violations, mut runs) = empty_report();
    check_ir_drop(
        Some(powered.solved()),
        &IntentMap::default(),
        &table,
        &mut violations,
        &mut runs,
    );
    assert_skipped_for_intent(&runs, &violations, id);

    let (mut violations, mut runs) = empty_report();
    check_ir_drop(
        Some(powered.solved()),
        &supply_intent(),
        &table,
        &mut violations,
        &mut runs,
    );
    let run = common::run_of(&runs, id);
    assert_eq!(run.outcome, Outcome::Ran);
    assert_eq!(
        run.examined, 5,
        "the chain's five nodes all sit on the one net that states a limit"
    );
}

/// Oracle: construct-from-answer, on the gate. Current density needs the branch
/// currents, and there are no branch currents without a solve, and no solve
/// without declared supplies. With them, the rule examines the edges on the
/// layer its row limits and no others.
#[test]
fn em_current_density_skips_without_intent_and_examines_limited_edges_with_it() {
    let powered = Powered::new();
    let id = rule(11);
    let table = EmCurrentDensityTable {
        head: head(id),
        layer_start: vec![0, 1],
        layer: vec![LayerId(0)],
        max_density: vec![density(1e9)],
    };

    let (mut violations, mut runs) = empty_report();
    check_em_current_density(None, &supply_intent(), &table, &mut violations, &mut runs);
    assert_skipped_for_intent(&runs, &violations, id);

    let (mut violations, mut runs) = empty_report();
    check_em_current_density(
        Some(powered.solved()),
        &supply_intent(),
        &table,
        &mut violations,
        &mut runs,
    );
    let run = common::run_of(&runs, id);
    assert_eq!(run.outcome, Outcome::Ran);
    assert_eq!(
        run.examined, 4,
        "the chain's four edges are all on the limited layer"
    );
}

/// Oracle: construct-from-answer, on the gate. Electromigration reads the same
/// solve, so it is gated the same way — and the with-intent run has to reach
/// the edges, or the skip is indistinguishable from a rule that never worked.
#[test]
fn electromigration_skips_without_intent_and_reaches_the_edges_with_it() {
    let powered = Powered::new();
    let id = rule(12);
    let table = electromigration_table(id, LayerId(0));

    let (mut violations, mut runs) = empty_report();
    check_electromigration(None, &supply_intent(), &table, &mut violations, &mut runs);
    assert_skipped_for_intent(&runs, &violations, id);

    let (mut violations, mut runs) = empty_report();
    check_electromigration(
        Some(powered.solved()),
        &supply_intent(),
        &table,
        &mut violations,
        &mut runs,
    );
    let run = common::run_of(&runs, id);
    assert_eq!(run.outcome, Outcome::Ran);
    assert!(
        run.examined > 0,
        "with a solve and declared supplies the rule must actually reach the branches"
    );
}

/// Oracle: construct-from-answer, on the gate. A lifetime computed against a
/// stress nobody stated is a number and not a verdict, which is why this rule
/// is gated; with the stress stated it evaluates the solved nodes.
#[test]
fn reliability_skips_without_intent_and_evaluates_nodes_with_it() {
    let powered = Powered::new();
    let id = rule(13);
    let table = reliability_table(id);

    let (mut violations, mut runs) = empty_report();
    check_reliability(None, &supply_intent(), &table, &mut violations, &mut runs);
    assert_skipped_for_intent(&runs, &violations, id);

    let (mut violations, mut runs) = empty_report();
    check_reliability(
        Some(powered.solved()),
        &IntentMap::default(),
        &table,
        &mut violations,
        &mut runs,
    );
    assert_skipped_for_intent(&runs, &violations, id);

    let (mut violations, mut runs) = empty_report();
    check_reliability(
        Some(powered.solved()),
        &supply_intent(),
        &table,
        &mut violations,
        &mut runs,
    );
    let run = common::run_of(&runs, id);
    assert_eq!(run.outcome, Outcome::Ran);
    assert!(
        run.examined > 0,
        "the solve's nodes are what the model is applied to"
    );
}

/// One MOS with each terminal on its own net, extracted from a layout emitted
/// from that netlist.
fn one_transistor() -> (NetlistCase, NetTable, DeviceTable) {
    let mut strings = StrTable::default();
    let spec = NetlistSpec {
        nets: 4,
        devices: vec![DeviceSpec {
            kind: DeviceKind::Mos,
            model: "nch".to_owned(),
            terminals: vec![
                (TerminalRole::Gate, 0),
                (TerminalRole::Source, 1),
                (TerminalRole::Drain, 2),
                (TerminalRole::Bulk, 3),
            ],
        }],
    };
    let case = gpurify_testgen::layout_from_netlist(&spec, Floorplan::default(), &mut strings);

    let mut nets = NetTable::default();
    gpurify_topology::extract_nets_into(&case.store, &case.connectivity, &mut nets);
    let mut devices = DeviceTable::default();
    gpurify_topology::device::recognise_into(
        &case.store,
        &Evaluator::default(),
        &nets,
        &case.recognition,
        &mut devices,
    );
    (case, nets, devices)
}

/// The extracted net id of the netlist's net `n`.
fn net_of(case: &NetlistCase, nets: &NetTable, n: usize) -> NetId {
    nets.net_of(case.expected_net_polys[n][0])
}

/// Intent declaring every one of the four nets, at the given millivolts.
fn four_domains(case: &NetlistCase, nets: &NetTable, millivolt: [f64; 4]) -> IntentMap {
    let mut rows: Vec<(NetId, f64)> = (0..4)
        .map(|n| (net_of(case, nets, n), millivolt[n]))
        .collect();
    rows.sort_by_key(|&(net, _)| net);
    IntentMap {
        declared: true,
        supply_net: rows.iter().map(|&(net, _)| net).collect(),
        supply_domain: rows
            .iter()
            .enumerate()
            .map(|(index, _)| DomainId(u32::try_from(index).expect("four domains")))
            .collect(),
        supply_role: rows
            .iter()
            .map(|&(_, mv)| {
                if mv > 0.0 {
                    SupplyRole::Power
                } else {
                    SupplyRole::Ground
                }
            })
            .collect(),
        supply_voltage: rows.iter().map(|&(_, mv)| millivolts(mv)).collect(),
        limit_net: Vec::new(),
        limit: Vec::new(),
        undeclared: Vec::new(),
    }
}

/// Oracle: construct-from-answer, on the gate and on the measurement. This is
/// the rule where the gate matters most: with no domains declared every device
/// spans a delta of zero, so an ungated version reports the whole design clean.
/// With the domains declared, the one transistor straddles 3.3 V and 0 V and is
/// reported at its marker polygon.
#[test]
fn hv_domain_skips_without_intent_and_flags_the_straddling_device_with_it() {
    let (case, nets, devices) = one_transistor();
    let derived = Evaluator::default();
    let design = Design {
        store: &case.store,
        derived: &derived,
        nets: &nets,
        devices: &devices,
    };
    let id = rule(14);
    let table = HvDomainTable {
        head: head(id),
        max_domain_delta: vec![millivolts(1_000.0)],
        isolation: vec![None],
    };

    let (mut violations, mut runs) = empty_report();
    check_hv_domain(
        design,
        &IntentMap::default(),
        &table,
        &mut violations,
        &mut runs,
    );
    assert_skipped_for_intent(&runs, &violations, id);

    let intent = four_domains(&case, &nets, [3_300.0, 0.0, 0.0, 0.0]);
    let (mut violations, mut runs) = empty_report();
    check_hv_domain(design, &intent, &table, &mut violations, &mut runs);

    let run = common::run_of(&runs, id);
    assert_eq!(run.outcome, Outcome::Ran);
    assert_eq!(
        run.examined, 1,
        "the one device has every terminal on a declared net"
    );
    assert_eq!(violations.rule.len(), 1);
    assert_eq!(violations.rule[0], id);
    assert_eq!(
        violations.shape_a[0], case.expected_devices[0].marker,
        "a device violation is reported at the polygon that recognised the device"
    );
    assert_eq!(
        violations.measured[0],
        gpurify_report::Measurement::Voltage(millivolts(3_300.0)),
        "the measurement is the widest nominal spread across the device's terminals"
    );
    assert_eq!(
        violations.limit[0],
        gpurify_report::Measurement::Voltage(millivolts(1_000.0))
    );
    common::assert_at_is_on_a_named_shape(&case.store, &violations, 0);
}

/// Oracle: construct-from-answer, on the gate and on the count. With no
/// declared supplies there is no target for a discharge path, so every pad
/// would trivially pass — the exact shape of a false-clean result. The rule
/// must skip instead; and with supplies declared it examines every pad net and
/// every guard ring, and reports the pads that reach no clamp.
///
/// The clamp list is empty, so no device in this layout qualifies as protection
/// and all four pad nets are unprotected. That count is decided by the spec the
/// layout was built from, not read back from the run.
#[test]
fn esd_latchup_skips_without_intent_and_counts_pads_and_rings_with_it() {
    let (case, nets, devices) = one_transistor();
    let derived = Evaluator::default();
    let design = Design {
        store: &case.store,
        derived: &derived,
        nets: &nets,
        devices: &devices,
    };
    let networks = NetNetworks::default();
    let id = rule(15);
    let table = EsdLatchupTable {
        head: head(id),
        pad: vec![case.layers.rail],
        guard_ring: vec![case.layers.marker],
        clamp_start: vec![0, 0],
        clamp_model: Vec::new(),
        clamp_resistance: Vec::new(),
        clamp_capacity: Vec::new(),
        clamp_voltage: Vec::new(),
        required_current: vec![Qty::new(100.0)],
        max_path_resistance: vec![ohms(2.0)],
        max_clamp_voltage: vec![millivolts(4_000.0)],
        min_guard_ring_width: vec![dbu(100)],
        max_tap_distance: vec![dbu(100_000)],
    };

    let mut scratch = Scratch::default();
    let (mut violations, mut runs) = empty_report();
    check_esd_latchup(
        design,
        &IntentMap::default(),
        &networks,
        &table,
        &mut scratch,
        &mut violations,
        &mut runs,
    );
    assert_skipped_for_intent(&runs, &violations, id);

    let intent = four_domains(&case, &nets, [1_800.0, 0.0, 1_800.0, 0.0]);
    let (mut violations, mut runs) = empty_report();
    check_esd_latchup(
        design,
        &intent,
        &networks,
        &table,
        &mut scratch,
        &mut violations,
        &mut runs,
    );

    let run = common::run_of(&runs, id);
    assert_eq!(run.outcome, Outcome::Ran);
    assert_eq!(
        run.examined, 5,
        "four pad nets plus the one guard ring, as the rule's doc comment states"
    );
    assert_eq!(
        run.violations, 4,
        "no device in this layout is on the row's clamp list, so no pad has a path"
    );
    assert_eq!(
        violations.rule.iter().filter(|&&r| r == id).count(),
        4,
        "the run row's count must equal what the rule actually pushed"
    );
}
