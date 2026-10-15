//! `RuleSet::run`, and the claim that makes an ERC report readable.
//!
//! Every configured rule row produces exactly one `RuleRun`, including the rows
//! that could not run. That is the invariant the crate is shaped around: an
//! empty violation table means "clean" only when a run row says the rule
//! executed, and a rule that returned early without recording itself is
//! indistinguishable from a rule that found nothing.
//!
//! Oracle: construct-from-answer. The rule set below is written out by hand
//! with one row of each kind in `KINDS`, so both the expected number of run
//! rows and the expected split between the kinds that always run and the
//! `INTENT_GATED` ones are decided before anything executes.

use crate::common;

use common::{head, manufacturing_grid, operating_temperature, rule};
use gpurify_check::erc::facts::{IntentMap, NetFacts, NetTypes};
use gpurify_check::erc::power::{NetNetworks, PowerError, Process};
use gpurify_check::erc::rules::{
    antenna, domain, electrical, esd, latchup, matching, reliability, supply, topology,
};
use gpurify_check::erc::ruleset::{RuleSet, RunInputs, KINDS};
use gpurify_check::erc::voltage::NetVoltage;
use gpurify_check::erc::{Design, ErcError, Scratch};
use gpurify_check::report::{Outcome, RuleRun, Severity, SkipReason, Violations};
use gpurify_check::topology::{DeviceTable, NetTable, PortTable};
use gpurify_geom::{prefix, Current, CurrentDensity, Qty, Resistance, Temperature, Voltage};
use gpurify_geom::{Bbox, LayerId};
use gpurify_ingest::deck::{
    Connectivity, Deck, DeviceRecognition, LayerTable, LvsControls, ProcessStack, RuleSpec,
    RuleTable,
};
use gpurify_ingest::{StrId, StrTable};
use gpurify_testgen::{dbu, LayoutBuilder};

/// The id given to each kind's single configured row, in the order `KINDS`
/// spells them. Ids are positional so a failure names the kind.
fn id_of(kind: &str) -> StrId {
    let index = KINDS
        .iter()
        .position(|&k| k == kind)
        .unwrap_or_else(|| panic!("{kind} is not a kind this crate implements"));
    rule(u32::try_from(index).expect("a few dozen kinds"))
}

/// The kinds that cannot answer their question without design intent.
const INTENT_GATED: [&str; 37] = [
    "combinational_loop",
    "dielectric_field",
    "domain_crossing",
    "drain_source",
    "dynamic_ir_drop",
    "electromigration",
    "em_current_density",
    "em_peak",
    "em_rms",
    "esd_cross_domain",
    "esd_exposed",
    "esd_ground_coupling",
    "em_thermal",
    "esd_latchup",
    "esd_path",
    "esd_pin_pair",
    "esd_topological",
    "floating_supply",
    "forward_diode",
    "gate_oxide",
    "gate_path",
    "guard_ring_bias",
    "hot_carrier",
    "hv_domain",
    "hv_tag",
    "ir_drop",
    "missing_isolation",
    "missing_level_shifter",
    "multiple_drivers",
    "net_type",
    "power_switch",
    "reliability",
    "supply_path",
    "tie_high_low",
    "undriven_gate",
    "voltage_spacing",
    "well_bias",
];

/// One AC current-density row: a single-entry table on layer 0.
fn ac_table(kind: &str) -> electrical::EmAcTable {
    electrical::EmAcTable {
        head: head(id_of(kind)),
        layer_start: vec![0, 1],
        layer: vec![LayerId(0)],
        frequency_start: vec![0, 1],
        frequency: vec![100.0],
        width_start: vec![0, 1],
        width: vec![dbu(0)],
        density_start: vec![0, 1],
        density: vec![density(1e9)],
        max_current_per_cut: vec![microamps(200.0)],
    }
}

fn ohms(value: f64) -> Qty<Resistance, { prefix::BASE }> {
    Qty::new(value)
}

fn millivolts(value: f64) -> Qty<Voltage, { prefix::MILLI }> {
    Qty::new(value)
}

fn microamps(value: f64) -> Qty<Current, { prefix::MICRO }> {
    Qty::new(value)
}

fn kelvin(value: f64) -> Qty<Temperature, { prefix::BASE }> {
    Qty::new(value)
}

fn density(value: f64) -> Qty<CurrentDensity, { prefix::BASE }> {
    Qty::new(value)
}

/// One row of every kind, all naming layers that exist in the store below.
#[allow(
    clippy::too_many_lines,
    reason = "every table written out once is the point of the test"
)]
fn every_kind() -> RuleSet {
    let base = LayerId(0);
    let other = LayerId(1);
    RuleSet {
        floating_gate: topology::FloatingGateTable {
            head: head(id_of("floating_gate")),
            labels_are_ports: vec![false],
        },
        floating_well: topology::FloatingWellTable {
            head: head(id_of("floating_well")),
            well: vec![base],
            tap: vec![other],
        },
        multiple_drivers: topology::MultipleDriversTable {
            head: head(id_of("multiple_drivers")),
            max_drivers: vec![1],
        },
        fanout: topology::FanoutTable {
            head: head(id_of("fanout")),
            max_gates: vec![4],
        },
        supply_path: topology::SupplyPathTable {
            head: head(id_of("supply_path")),
            both: vec![true],
            labels_are_ports: vec![true],
        },
        power_switch: domain::PowerSwitchTable {
            head: head(id_of("power_switch")),
            model_start: vec![0, 1],
            model: vec![rule(900)],
        },
        hot_carrier: domain::HotCarrierTable {
            head: head(id_of("hot_carrier")),
            model_start: vec![0, 1],
            model: vec![rule(900)],
            max_length: vec![dbu(150)],
        },
        well_sharing: domain::WellSharingTable {
            head: head(id_of("well_sharing")),
            model_start: vec![0, 1],
            model: vec![rule(900)],
            resistors: vec![true],
        },
        matching: matching::MatchingTable {
            head: head(id_of("matching")),
            group: vec![LayerId(0)],
            tolerance: vec![dbu(0)],
        },
        floating_supply: supply::FloatingSupplyTable {
            head: head(id_of("floating_supply")),
        },
        combinational_loop: topology::CombinationalLoopTable {
            head: head(id_of("combinational_loop")),
        },
        gate_path: topology::GatePathTable {
            head: head(id_of("gate_path")),
            ground: vec![true],
            max_devices: vec![3],
        },
        net_type: topology::NetTypeTable {
            head: head(id_of("net_type")),
            net: vec![vec![(rule(900), true)]],
            path: vec![Vec::new()],
            breaks: vec![Vec::new()],
            exclude: vec![Vec::new()],
        },
        unconnected_pin: topology::UnconnectedPinTable {
            head: head(id_of("unconnected_pin")),
            layer_start: vec![0, 1],
            layer: vec![LayerId(0)],
        },

        supply_short: supply::SupplyShortTable {
            head: head(id_of("supply_short")),
            tap_a: vec![base],
            tap_b: vec![other],
            within: vec![None],
        },
        soft_connection: supply::SoftConnectionTable {
            head: head(id_of("soft_connection")),
            soft_start: vec![0, 1],
            soft: vec![other],
            connectivity: Connectivity::default(),
        },
        missing_tie: supply::MissingTieTable {
            head: head(id_of("missing_tie")),
            region: vec![base],
            tap: vec![other],
            max_distance: vec![dbu(50_000)],
        },
        tie_high_low: supply::TieHighLowTable {
            head: head(id_of("tie_high_low")),
        },
        esd_topological: supply::EsdTopologicalTable {
            head: head(id_of("esd_topological")),
            pad: vec![LayerId(0)],
            clamp_start: vec![0, 1],
            clamp: vec![rule(900)],
        },
        mixed_tag: supply::MixedTagTable {
            head: head(id_of("mixed_tag")),
            layer: vec![base],
            tag: vec![other],
        },

        antenna: antenna::AntennaTable {
            head: head(id_of("antenna")),
            gate: vec![base],
            collector_start: vec![0, 1],
            collector: vec![other],
            collector_measure: vec![antenna::AntennaMeasure::Area],
            max_ratio: vec![50.0],
            diode: vec![None],
            diode_area: vec![None],
            diode_min: vec![None],
            stack: antenna::Stack::default(),
        },
        antenna_electrical: antenna::AntennaElectricalTable {
            head: head(id_of("antenna_electrical")),
            gate: vec![base],
            collector_start: vec![0, 1],
            collector: vec![other],
            collector_measure: vec![antenna::AntennaMeasure::Area],
            diode: vec![None],
            diode_credit: vec![0.0],
            diode_bonus: vec![0.0],
            cut_factor: vec![1.0],
            area_minus_diode: vec![0.0],
            gate_plus_diode: vec![0.0],
            diode_reduce: vec![Vec::new()],
            diode_max_ratio: vec![Vec::new()],
            exempt: vec![None],
            max_ratio: vec![50.0],
            stack: antenna::Stack::default(),
        },
        density_cmp: antenna::DensityCmpTable {
            head: head(id_of("density_cmp")),
            layer: vec![base],
            window: vec![(dbu(2_000), dbu(2_000))],
            step: vec![(dbu(2_000), dbu(2_000))],
            min_density: vec![None],
            max_density: vec![Some(0.99)],
            max_neighbour_delta: vec![None],
            cmp: vec![None],
            include_partial_windows: vec![true],
        },

        p2p_resistance: electrical::P2pResistanceTable {
            head: head(id_of("p2p_resistance")),
            max_resistance: vec![ohms(100.0)],
        },
        ir_drop: electrical::IrDropTable {
            head: head(id_of("ir_drop")),
        },
        em_current_density: electrical::EmCurrentDensityTable {
            head: head(id_of("em_current_density")),
            layer_start: vec![0, 1],
            layer: vec![LayerId(0)],
            max_density: vec![density(1e9)],
            max_current_per_cut: vec![microamps(200.0)],
            narrow: vec![None],
        },
        em_rms: ac_table("em_rms"),
        em_peak: ac_table("em_peak"),
        electromigration: electrical::ElectromigrationTable {
            head: head(id_of("electromigration")),
            layer_start: vec![0, 1],
            layer: vec![LayerId(0)],
            max_density: vec![density(1e9)],
            max_current_per_cut: vec![microamps(200.0)],
            blech_limit: vec![microamps(1.0)],
            reference_temperature: vec![kelvin(358.15)],
            activation_energy_ev: vec![0.7],
            current_exponent: vec![2.0],
        },
        dynamic_ir_drop: electrical::DynamicIrDropTable {
            head: head(id_of("dynamic_ir_drop")),
        },
        em_thermal: electrical::EmThermalTable {
            head: head(id_of("em_thermal")),
            layer_start: vec![0, 1],
            layer: vec![LayerId(0)],
            max_density: vec![density(1e9)],
            max_current_per_cut: vec![microamps(200.0)],
            blech_limit: vec![microamps(1.0)],
            reference_temperature: vec![kelvin(358.15)],
            activation_energy_ev: vec![0.7],
            current_exponent: vec![2.0],
            thermal_conductivity: vec![1.4],
            heat_spreading: vec![0.88],
            sigma: vec![0.5],
            limit_failure: vec![0.001],
            max_failure: vec![0.001],
            height_nm: Vec::new(),
        },

        reliability: reliability::ReliabilityTable {
            head: head(id_of("reliability")),
            required_lifetime_hours: vec![87_600.0],
            reference_lifetime_hours: vec![10_000.0],
            reference_stress: vec![millivolts(2_000.0)],
            stress_exponent: vec![4.0],
            reference_temperature: vec![kelvin(398.15)],
            activation_energy_ev: vec![0.6],
            duty_cycle: vec![0.5],
            max_abs_voltage: vec![millivolts(1_950.0)],
        },
        hv_domain: reliability::HvDomainTable {
            head: head(id_of("hv_domain")),
            max_domain_delta: vec![millivolts(1_000.0)],
            isolation: vec![None],
        },
        esd_latchup: reliability::EsdLatchupTable {
            head: head(id_of("esd_latchup")),
            pad: vec![LayerId(0)],
            guard_ring: vec![LayerId(1)],
            min_guard_ring_width: vec![dbu(100)],
            max_tap_distance: vec![dbu(100_000)],
            clamp_start: vec![0, 1],
            clamp: vec![rule(900)],
        },

        esd_path: esd::EsdPathTable {
            head: head(id_of("esd_path")),
            pad: vec![LayerId(0)],
            source: vec![LayerId(0)],
            clamp_start: vec![0, 1],
            clamp: vec![rule(900)],
            current: vec![microamps(1_330_000.0)],
            clamp_resistance: vec![ohms(1.0)],
            max_resistance: vec![Some(ohms(2.0))],
            clamp_it2: vec![None],
            max_density: vec![None],
            max_current_per_cut: vec![None],
            max_voltage: vec![None],
            min_width: vec![None],
            clamp_voltage: vec![None],
        },
        esd_pin_pair: esd::EsdPinPairTable {
            head: head(id_of("esd_pin_pair")),
            pad: vec![LayerId(0)],
            clamp_start: vec![0, 1],
            clamp: vec![rule(900)],
            current: vec![microamps(1_330_000.0)],
            clamp_resistance: vec![ohms(1.0)],
            max_resistance: vec![ohms(2.0)],
        },
        esd_clamp_resistance: esd::EsdClampResistanceTable {
            head: head(id_of("esd_clamp_resistance")),
            pad: vec![LayerId(0)],
            clamp_start: vec![0, 1],
            clamp: vec![rule(900)],
            max_resistance: vec![ohms(2.0)],
        },
        esd_ground_coupling: esd::EsdGroundCouplingTable {
            head: head(id_of("esd_ground_coupling")),
            diode_start: vec![0, 1],
            diode: vec![rule(900)],
        },
        esd_parasitic: esd::EsdParasiticTable {
            head: head(id_of("esd_parasitic")),
            pad: vec![base],
            diffusion: vec![other],
            min_spacing: vec![dbu(5_000)],
        },
        esd_exposed: esd::EsdExposedTable {
            head: head(id_of("esd_exposed")),
            pad: vec![base],
            clamp_start: vec![0, 1],
            clamp: vec![rule(900)],
            resistor_start: vec![0, 0],
            resistor: Vec::new(),
            rated_start: vec![0, 0],
            rated: Vec::new(),
            min_series: vec![None],
        },
        esd_cross_domain: esd::EsdCrossDomainTable {
            head: head(id_of("esd_cross_domain")),
            diode_start: vec![0, 1],
            diode: vec![rule(900)],
            local_start: vec![0, 0],
            local: Vec::new(),
            resistor_start: vec![0, 0],
            resistor: Vec::new(),
            min_series: vec![None],
            max_ground_resistance: vec![None],
            coupling_resistance: vec![None],
        },
        guard_ring_bias: latchup::GuardRingBiasTable {
            head: head(id_of("guard_ring_bias")),
            ring: vec![base],
            power: vec![true],
        },
        guard_ring: latchup::GuardRingTable {
            head: head(id_of("guard_ring")),
            target: vec![base],
            ring: vec![other],
            max_space: vec![None],
            min_width: vec![None],
            pad: vec![None],
            near: vec![None],
            clear: vec![None],
        },
        forward_diode: latchup::ForwardDiodeTable {
            head: head(id_of("forward_diode")),
            marker: vec![other],
            model_start: vec![0, 1],
            model: vec![rule(900)],
        },
        conditional_tie: latchup::ConditionalTieTable {
            head: head(id_of("conditional_tie")),
            region: vec![base],
            tap: vec![other],
            well: vec![base],
            other: vec![other],
            within: vec![dbu(50_000)],
            spacing_start: vec![0, 1],
            spacing: vec![dbu(1_000)],
            max_distance_start: vec![0, 2],
            max_distance: vec![dbu(15_000), dbu(30_000)],
        },
        latchup_victim: latchup::LatchupVictimTable {
            head: head(id_of("latchup_victim")),
            aggressor: vec![base],
            region: vec![other],
            tap: vec![base],
            within: vec![dbu(15_000)],
            max_distance: vec![dbu(2_000)],
            pad: vec![None],
            bias: vec![None],
        },
        tie_area: latchup::TieAreaTable {
            head: head(id_of("tie_area")),
            region: vec![base],
            contact: vec![other],
            channel: vec![base],
            min_ratio: vec![0.03],
        },

        gate_oxide: domain::ModelLimitTable {
            head: head(id_of("gate_oxide")),
            model_start: vec![0, 1],
            model: vec![rule(900)],
            max_voltage: vec![millivolts(1_980.0)],
        },
        drain_source: domain::ModelLimitTable {
            head: head(id_of("drain_source")),
            model_start: vec![0, 1],
            model: vec![rule(900)],
            max_voltage: vec![millivolts(1_980.0)],
        },
        well_bias: domain::WellBiasTable {
            head: head(id_of("well_bias")),
            pmos_start: vec![0, 1],
            pmos: vec![rule(900)],
            nmos_start: vec![0, 0],
            nmos: Vec::new(),
        },
        missing_level_shifter: domain::MissingLevelShifterTable {
            head: head(id_of("missing_level_shifter")),
            shifter_start: vec![0, 0],
            shifter: Vec::new(),
        },
        domain_crossing: domain::DomainCrossingTable {
            head: head(id_of("domain_crossing")),
        },
        voltage_spacing: domain::VoltageSpacingTable {
            head: head(id_of("voltage_spacing")),
            layer: vec![base],
            other: vec![None],
            step_start: vec![0, 1],
            voltage: vec![millivolts(0.0)],
            space: vec![dbu(100)],
        },
        undriven_gate: domain::UndrivenGateTable {
            head: head(id_of("undriven_gate")),
        },
        missing_isolation: domain::MissingIsolationTable {
            head: head(id_of("missing_isolation")),
            isolation_start: vec![0, 0],
            isolation: Vec::new(),
        },
        dielectric_field: domain::DielectricFieldTable {
            head: head(id_of("dielectric_field")),
            layer: vec![base],
            other: vec![None],
            max_field: vec![100.0],
            vertical_nm: vec![Some(0.0)],
        },
        hv_tag: domain::HvTagTable {
            head: head(id_of("hv_tag")),
            layer: vec![base],
            tag: vec![other],
            voltage: vec![millivolts(1_980.0)],
        },
    }
}

/// Everything a run borrows, over a two-layer layout the size of the die.
struct Cell {
    store: gpurify_geom::GeometryStore,
    nets: NetTable,
    devices: DeviceTable,
    facts: NetFacts,
    ports: PortTable,
    net_types: NetTypes,
    voltage: NetVoltage,
    networks: NetNetworks,
    stack: ProcessStack,
    connectivity: Connectivity,
}

impl Cell {
    fn new() -> Self {
        let mut layout = LayoutBuilder::new(2);
        layout.rect(LayerId(0), 0, 0, 1_000, 2_000);
        layout.rect(LayerId(1), 1_200, 200, 1_800, 800);
        let (store, _) = layout.finish();
        Self {
            store,
            nets: NetTable::default(),
            devices: DeviceTable::default(),
            facts: NetFacts::default(),
            ports: PortTable::default(),
            net_types: NetTypes::default(),
            voltage: NetVoltage::default(),
            networks: NetNetworks::default(),
            stack: ProcessStack::default(),
            connectivity: Connectivity::default(),
        }
    }

    fn inputs<'a>(&'a self, intent: &'a IntentMap) -> RunInputs<'a> {
        RunInputs {
            design: Design {
                store: &self.store,
                nets: &self.nets,
                devices: &self.devices,
            },
            facts: &self.facts,
            ports: &self.ports,
            intent,
            net_types: &self.net_types,
            voltage: &self.voltage,
            states: &[],
            switched: &[],
            networks: Ok(&self.networks),
            power: Ok(None),
            rms: (intent, Ok(None)),
            peak: (intent, Ok(None)),
            die: Bbox {
                xlo: dbu(0),
                ylo: dbu(0),
                xhi: dbu(2_000),
                yhi: dbu(2_000),
            },
            process: Process {
                grid: manufacturing_grid(),
                stack: &self.stack,
                connectivity: &self.connectivity,
            },
            operating_temperature: operating_temperature(),
        }
    }
}

/// Oracle: construct-from-answer. One configured row per kind must produce
/// one run row per kind, one per row, each attributable to its own rule id. This
/// comparison is named in `RuleSet::len`'s own doc comment as the thing that
/// catches a transform returning early without recording itself — the exact
/// shape of a false-clean result.
#[test]
fn every_configured_rule_row_produces_exactly_one_run_row() {
    let rules = every_kind();
    let cell = Cell::new();
    let intent = IntentMap::default();
    let mut scratch = Scratch::default();
    let mut violations = Violations::default();
    let mut runs = Vec::new();
    rules.run(
        cell.inputs(&intent),
        &mut scratch,
        &mut violations,
        &mut runs,
    );

    assert_eq!(
        rules.len(),
        KINDS.len(),
        "one row of each kind was configured"
    );
    assert_eq!(
        runs.len(),
        rules.len(),
        "a run row went missing; the rules that recorded themselves were {:?}",
        runs.iter().map(|r| r.rule).collect::<Vec<_>>()
    );

    let mut ids: Vec<StrId> = runs.iter().map(|r| r.rule).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), runs.len(), "two run rows share one rule id");
}

/// Oracle: construct-from-answer. With no design intent the gated kinds
/// must say so and the others must run anyway. Both halves matter: a
/// gated rule reporting clean is the failure this crate is built against, and
/// an ungated rule skipping would quietly stop checking a design that needs no
/// intent file at all.
#[test]
fn without_intent_exactly_the_gated_kinds_record_themselves_skipped() {
    let rules = every_kind();
    let cell = Cell::new();
    let intent = IntentMap::default();
    let mut scratch = Scratch::default();
    let mut violations = Violations::default();
    let mut runs = Vec::new();
    rules.run(
        cell.inputs(&intent),
        &mut scratch,
        &mut violations,
        &mut runs,
    );

    for kind in KINDS {
        let row = common::run_of(&runs, id_of(kind));
        if INTENT_GATED.contains(&kind) {
            assert_eq!(
                row.outcome,
                Outcome::Skipped(SkipReason::NoDesignIntent),
                "{kind} needs design intent and must say so rather than report clean"
            );
            assert_eq!(
                row.examined, 0,
                "{kind} skipped but claims to have examined shapes"
            );
            assert_eq!(row.violations, 0);
        } else {
            assert_eq!(
                row.outcome,
                Outcome::Ran,
                "{kind} needs no design intent and must run without one"
            );
        }
    }
}

/// A failed solve (here an island no pad reaches) refuses exactly the rows
/// that read the solve, and every other rule still runs as it would have:
/// one bad rail must not hide an antenna or a floating gate.
///
/// Oracle: `erc::power::Power`'s contract ("those rows are refused; every
/// other rule still runs"), as a differential against the same rule set over
/// a solved grid: the six grid kinds turn `Refused`, every other outcome is
/// the solved run's.
#[test]
fn a_failed_solve_refuses_only_the_grid_rules() {
    const GRID: [&str; 6] = [
        "ir_drop",
        "dynamic_ir_drop",
        "em_current_density",
        "electromigration",
        "em_thermal",
        "reliability",
    ];
    let rules = every_kind();
    let cell = Cell::new();
    let intent = IntentMap::default();
    let outcomes = |power| {
        let mut inputs = cell.inputs(&intent);
        inputs.power = power;
        let (mut violations, mut runs) = (Violations::default(), Vec::new());
        rules.run(inputs, &mut Scratch::default(), &mut violations, &mut runs);
        KINDS
            .iter()
            .map(|&kind| (kind, common::run_of(&runs, id_of(kind)).outcome))
            .collect::<Vec<_>>()
    };

    let solved = outcomes(Ok(None));
    let failed = outcomes(Err(PowerError::UnanchoredIsland(7)));
    for ((kind, before), (_, after)) in solved.into_iter().zip(failed) {
        if GRID.contains(&kind) {
            assert_eq!(after, Outcome::Refused, "{kind} reads the solve");
        } else {
            assert_eq!(after, before, "{kind} does not read the solve");
        }
    }
}

/// Oracle: construct-from-answer. A kind the deck did not configure produces no
/// run row at all, and that silence is correct: nothing claims the rule was
/// checked. It is a different silence from a skip, which claims the rule was
/// wanted and could not run.
#[test]
fn a_kind_the_deck_did_not_configure_produces_no_run_row() {
    let rules = RuleSet::default();
    let cell = Cell::new();
    let intent = IntentMap::default();
    let mut scratch = Scratch::default();
    let mut violations = Violations::default();
    let mut runs = Vec::new();

    assert!(rules.is_empty());
    assert_eq!(rules.len(), 0);
    rules.run(
        cell.inputs(&intent),
        &mut scratch,
        &mut violations,
        &mut runs,
    );
    assert!(
        runs.is_empty(),
        "an empty rule set claims nothing was checked"
    );
    assert_eq!(violations.rule, []);
}

/// Oracle: construct-from-answer. `run` appends rather than clears, which is
/// what lets a caller accumulate several cells into one report. A transform
/// that cleared the caller's buffers would silently drop everything run before
/// it, and the report would be short rather than wrong.
#[test]
fn run_appends_to_the_buffers_it_is_given() {
    let rules = every_kind();
    let cell = Cell::new();
    let intent = IntentMap::default();
    let mut scratch = Scratch::default();
    let mut violations = Violations::default();
    let mut runs = vec![RuleRun {
        rule: rule(999),
        outcome: Outcome::Ran,
        examined: 7,
        violations: 0,
    }];
    violations.push(gpurify_check::report::Violation {
        rule: rule(999),
        layer: LayerId(0),
        severity: Severity::Warning,
        at: gpurify_testgen::point(1, 1),
        measured: gpurify_check::report::Measurement::Count(1),
        limit: gpurify_check::report::Measurement::Count(0),
        shapes: (gpurify_geom::PolyId(0), None),
    });

    rules.run(
        cell.inputs(&intent),
        &mut scratch,
        &mut violations,
        &mut runs,
    );

    assert_eq!(
        runs[0].rule,
        rule(999),
        "the caller's earlier run row was dropped"
    );
    assert_eq!(runs.len(), rules.len() + 1);
    assert_eq!(
        violations.rule[0],
        rule(999),
        "the caller's earlier violation was dropped"
    );
}

/// Oracle: determinism. One rule set over one cell, run twice, must produce the
/// same rows in the same order. Order across rules is the field order of
/// `RuleSet`, which the dispatcher's doc comment states precisely so that a
/// test may depend on it.
#[test]
fn running_one_rule_set_twice_produces_identical_rows() {
    let rules = every_kind();
    let cell = Cell::new();
    let intent = IntentMap::default();
    let mut scratch = Scratch::default();

    let mut first = Violations::default();
    let mut first_runs = Vec::new();
    rules.run(
        cell.inputs(&intent),
        &mut scratch,
        &mut first,
        &mut first_runs,
    );

    let mut second = Violations::default();
    let mut second_runs = Vec::new();
    rules.run(
        cell.inputs(&intent),
        &mut scratch,
        &mut second,
        &mut second_runs,
    );

    gpurify_testgen::assert_violations_eq(&first, &second);
    assert_eq!(first_runs, second_runs);
}

/// A deck holding one rule row per `(id, kind)` pair, with no layers and no
/// parameters.
///
/// Some kinds take neither — `floating_gate`, `tie_high_low`
/// and `ir_drop` are configuration and nothing else — so a deck of those is the
/// one shape [`RuleSet::from_deck`] can be handed from outside this workspace.
/// The rows below carry no parameters; each kind's own tests cover those.
fn deck_of(strings: &mut StrTable, rows: &[(&str, &str)]) -> (Deck, Vec<StrId>) {
    let ids: Vec<StrId> = rows.iter().map(|&(id, _)| strings.intern(id)).collect();
    let spec = rows
        .iter()
        .zip(&ids)
        .map(|(&(_, kind), &id)| RuleSpec {
            id,
            kind: strings.intern(kind),
            layer_start: 0,
            layer_len: 0,
            param_start: 0,
            param_len: 0,
        })
        .collect();
    let deck = Deck {
        layers: LayerTable::default(),
        rules: RuleTable {
            spec,
            layer_ref: Vec::new(),
            param: Vec::new(),
        },
        connectivity: Connectivity::default(),
        devices: DeviceRecognition::default(),
        stack: ProcessStack::default(),
        temperature: None,
        temperature_law: None,
        lvs: LvsControls::default(),
        ..Deck::default()
    };
    (deck, ids)
}

/// Oracle: construct-from-answer. Two rows of two parameterless kinds must land
/// in those two tables and nowhere else, carrying the ids the deck spelled.
/// `from_deck` is the one place in this crate a kind is matched against a
/// string, so this is where the match is checked; every loop after it is uniform
/// over one table and cannot notice a row filed under the wrong kind.
#[test]
fn from_deck_files_each_row_under_the_kind_the_deck_named() {
    let mut strings = StrTable::default();
    let (deck, ids) = deck_of(
        &mut strings,
        &[
            ("gate.floating", "floating_gate"),
            ("net.tied", "tie_high_low"),
        ],
    );
    let rules = RuleSet::from_deck(&deck, &strings)
        .expect("both kinds are in KINDS and neither takes a layer or a parameter");

    assert_eq!(rules.len(), 2, "two configured rows");
    assert!(!rules.is_empty());
    assert_eq!(rules.floating_gate.head.rule, vec![ids[0]]);
    assert_eq!(rules.tie_high_low.head.rule, vec![ids[1]]);
    assert!(
        rules.ir_drop.head.is_empty() && rules.multiple_drivers.head.is_empty(),
        "a kind the deck did not name must have no row"
    );
    assert_eq!(rules.floating_gate.head.len(), 1);
}

/// Oracle: construct-from-answer. A kind this crate does not implement leaves
/// no row behind — it is another domain's, and one deck feeds every domain.
///
/// This test used to assert `ErcError::UnknownKind`, and the assertion moved
/// rather than disappeared: `deck::CompiledDeck::from_deck` refuses a kind that is in
/// neither `erc::ruleset::KINDS` nor `drc::ruleset::KINDS`, which is the layer
/// that can tell "another domain's rule" from "a typo". What is checkable
/// *here* is the half this crate is responsible for: the skipped row is not
/// half-filed into some table, so no `RuleRun` is ever attributed to it.
#[test]
fn a_deck_naming_a_kind_this_crate_does_not_implement_files_no_row() {
    let mut strings = StrTable::default();
    let (deck, _) = deck_of(
        &mut strings,
        &[
            ("met1.width", "min_width"),
            ("gate.floating", "floating_gate"),
        ],
    );

    let rules = RuleSet::from_deck(&deck, &strings)
        .expect("min_width is drc's row, and this crate steps over it");
    assert_eq!(rules.len(), 1, "only the erc row is filed");
    assert_eq!(rules.floating_gate.head.len(), 1);
}

/// Oracle: construct-from-answer, on the fail-closed path. Two rows sharing one
/// id produce two `RuleRun` rows attributable to nothing, which is what makes
/// the "one run row per configured row" invariant above readable at all. So the
/// duplicate is refused at load rather than reported twice at run time.
#[test]
fn a_deck_defining_one_rule_id_twice_is_refused() {
    let mut strings = StrTable::default();
    let (deck, _) = deck_of(
        &mut strings,
        &[
            ("gate.floating", "floating_gate"),
            ("gate.floating", "tie_high_low"),
        ],
    );

    assert_eq!(
        RuleSet::from_deck(&deck, &strings).unwrap_err(),
        ErcError::DuplicateRule("gate.floating".to_owned())
    );
}

/// Oracle: construct-from-answer. `KINDS` is the deck's contract — a kind
/// present in it must have a table and a transform. That is the checkable half:
/// every name the list spells must be a name `from_deck` files a row for.
///
/// The tell used to be `UnknownKind`. It cannot be any more — `from_deck` now
/// steps over a kind it does not spell, because the deck's one rule table also
/// carries `drc`'s rows — so the tell is `Ok` with an *empty* set instead. A
/// row missing a parameter is a different error and is fine here; a name the
/// match has drifted away from files nothing and reports nothing, which is the
/// silent half this test exists to make loud.
#[test]
fn every_kind_the_list_names_is_a_kind_from_deck_recognises() {
    let mut strings = StrTable::default();
    for kind in KINDS {
        let (deck, _) = deck_of(&mut strings, &[("the.rule", kind)]);
        if let Ok(rules) = RuleSet::from_deck(&deck, &strings) {
            assert_eq!(
                rules.len(),
                1,
                "KINDS names {kind}, but from_deck files no row for it"
            );
        }
    }

    for kind in INTENT_GATED {
        assert!(
            KINDS.contains(&kind),
            "{kind} is gated on design intent but is not a kind the deck can name"
        );
    }
}

/// Five `electromigration` rows spanning 2 and 4 layers.
const EM_DECK: &str = "grid 5nm
layer li = gds(1, 0)
layer licon = gds(2, 0)
layer met1 = gds(3, 0)
layer mcon = gds(4, 0)
layer met2 = gds(5, 0)
layer via1 = gds(6, 0)
layer met3 = gds(7, 0)
layer via2 = gds(8, 0)
layer met4 = gds(9, 0)
layer via3 = gds(10, 0)
layer met5 = gds(11, 0)
layer via4 = gds(12, 0)
rule em_li electromigration(li, licon; max_density: 280A/m, max_current_per_cut: 80uA, blech_limit: 15000uA, reference_temperature: 378K, activation_energy: 0.9eV, current_exponent: 2)
rule em_met1 electromigration(met1, mcon; max_density: 1000A/m, max_current_per_cut: 80uA, blech_limit: 54000uA, reference_temperature: 378K, activation_energy: 0.9eV, current_exponent: 2)
rule em_met2 electromigration(met2, via1; max_density: 1000A/m, max_current_per_cut: 60uA, blech_limit: 54000uA, reference_temperature: 378K, activation_energy: 0.9eV, current_exponent: 2)
rule em_met3_met4 electromigration(met3, via2, met4, via3; max_density: 2350A/m, max_current_per_cut: 110uA, blech_limit: 126750uA, reference_temperature: 378K, activation_energy: 0.9eV, current_exponent: 2)
rule em_met5 electromigration(met5, via4; max_density: 3500A/m, max_current_per_cut: 1800uA, blech_limit: 189000uA, reference_temperature: 378K, activation_energy: 0.9eV, current_exponent: 2)
";

/// Oracle: construct-from-answer, on the deck grammar (docs/deck.md,
/// `voltage_space`). A table lowers to its steps in mV and grid units, on one
/// layer or two; a table whose voltages fall, repeat or go negative, whose
/// spaces fall, or whose lists differ in length is refused by name.
#[test]
fn a_voltage_table_lowers_by_step_and_an_unordered_one_is_refused() {
    let head = "grid 5nm
layer met1 = gds(1, 0)
layer met2 = gds(2, 0)
connect conductors [met1, met2]
";
    let parse = |rows: &str| {
        let mut strings = StrTable::default();
        let deck = gpurify_ingest::deck::parse_deck(
            &format!("{head}{rows}"),
            manufacturing_grid(),
            &mut strings,
        )
        .expect("the deck parses");
        RuleSet::from_deck(&deck, &strings)
    };
    let rules = parse(
        "rule vs voltage_space(met1; voltage: [0V, 3.3V], space: [200nm, 450nm])
rule vs2 voltage_space(met1, met2; voltage: [1.5V], space: [1um])
",
    )
    .expect("both tables are in order");
    let table = &rules.voltage_spacing;
    assert_eq!(table.head.len(), 2);
    assert_eq!(table.step_start, [0, 2, 3]);
    let volts: Vec<f64> = table.voltage.iter().map(|v| v.raw()).collect();
    assert_eq!(volts, [0.0, 3_300.0, 1_500.0]);
    assert_eq!(table.space, [dbu(200), dbu(450), dbu(1_000)]);
    assert_eq!(table.layer, [LayerId(0), LayerId(0)]);
    assert_eq!(table.other, [None, Some(LayerId(1))]);
    for (rows, why) in [
        (
            "rule vs voltage_space(met1; voltage: [3.3V, 1V], space: [200nm, 450nm])\n",
            "rise strictly",
        ),
        (
            "rule vs voltage_space(met1; voltage: [1V, 1V], space: [200nm, 450nm])\n",
            "rise strictly",
        ),
        (
            "rule vs voltage_space(met1; voltage: [-1V], space: [200nm])\n",
            "rise strictly",
        ),
        (
            "rule vs voltage_space(met1; voltage: [0V, 1V], space: [450nm, 200nm])\n",
            "never fall",
        ),
        (
            "rule vs voltage_space(met1; voltage: [0V, 1V], space: [200nm])\n",
            "one space per voltage",
        ),
    ] {
        match parse(rows) {
            Err(ErcError::BadTable { rule, why: said }) => {
                assert_eq!(rule, "vs");
                assert!(said.contains(why), "{rows}: {said}");
            }
            other => panic!("{rows}: {other:?}"),
        }
    }
}

/// Oracle: construct-from-answer. `electromigration` rows spanning 2 and 4
/// layers; every layer must carry its own row's Blech limit.
#[test]
fn a_multi_layer_electromigration_row_gives_every_layer_its_blech_limit() {
    let mut strings = StrTable::default();
    let deck = gpurify_ingest::deck::parse_deck(EM_DECK, manufacturing_grid(), &mut strings)
        .expect("the deck parses");
    let rules = RuleSet::from_deck(&deck, &strings).expect("the deck is valid erc");
    let em = &rules.electromigration;
    assert_eq!(em.blech_limit.len(), em.layer.len());
    let expected = [15_000.0, 54_000.0, 54_000.0, 126_750.0, 189_000.0];
    assert_eq!(em.head.len(), expected.len());
    for (row, want) in expected.into_iter().enumerate() {
        let span = em.layer_start[row] as usize..em.layer_start[row + 1] as usize;
        assert!(span.len() >= 2, "row {row} is multi-layer");
        assert!(
            em.blech_limit[span]
                .iter()
                .all(|b| b.raw().to_bits() == f64::to_bits(want)),
            "row {row}"
        );
    }
}

/// A process with met1 1.2 µm above the substrate and one `em_thermal` row
/// on it and its cut; `{limit}` and `{spreading}` are filled per case.
const THERMAL_DECK: &str = "grid 5nm
layer met1 = gds(1, 0)
layer via1 = gds(2, 0)
layer met2 = gds(3, 0)
connect conductors [met1, met2]
connect via via1 [met1, met2]
pex met1 thickness 350nm height 1200nm sheet 0.1ohm dielectric 3.9 area_cap 1aF/um2 fringe_cap 1aF/um
rule em.hot warning em_thermal(met1, via1; max_density: 1mA/um, max_current_per_cut: 0.2mA, blech_limit: 2000uA, reference_temperature: 110C, activation_energy: 0.9eV, current_exponent: 2, thermal_conductivity: 1.4W/mK, spreading: {spreading}, sigma: 0.4, limit_failure: {limit}, max_failure: 0.01%)
";

/// Oracle: construct-from-answer, against `docs/deck.md`'s spelling of
/// `em_thermal`: every value lands in its column in the engine's unit (A/m,
/// µA, K, W/(m·K), fractions), the table carries the deck's `pex` heights,
/// and a characterisation at 100 % failed or a negative spreading is refused.
#[test]
#[allow(
    clippy::float_cmp,
    reason = "a value read from the deck is the value written, bit for bit"
)]
fn an_em_thermal_row_reads_into_its_columns() {
    let parse = |limit: &str, spreading: &str| {
        let mut strings = StrTable::default();
        let text = THERMAL_DECK
            .replace("{limit}", limit)
            .replace("{spreading}", spreading);
        let deck = gpurify_ingest::deck::parse_deck(&text, manufacturing_grid(), &mut strings)
            .expect("the deck parses");
        RuleSet::from_deck(&deck, &strings)
    };
    let rules = parse("0.1%", "0.88").expect("the row is valid");
    let t = &rules.em_thermal;
    assert_eq!(t.head.len(), 1);
    assert_eq!(t.head.severity, vec![Severity::Warning]);
    assert_eq!(t.layer.len(), 2);
    assert_eq!(t.layer_start, vec![0, 2]);
    assert!(t.max_density.iter().all(|d| d.raw() == 1000.0));
    assert!(t.max_current_per_cut.iter().all(|c| c.raw() == 200.0));
    assert!(t.blech_limit.iter().all(|b| b.raw() == 2000.0));
    assert_eq!(t.reference_temperature[0].raw(), 110.0 + 273.15);
    assert_eq!(t.activation_energy_ev, vec![0.9]);
    assert_eq!(t.current_exponent, vec![2.0]);
    assert_eq!(t.thermal_conductivity, vec![1.4]);
    assert_eq!(t.heat_spreading, vec![0.88]);
    assert_eq!(t.sigma, vec![0.4]);
    assert_eq!(t.limit_failure, vec![0.001]);
    assert_eq!(t.max_failure, vec![0.0001]);
    assert!(t.height_nm.contains(&1200.0), "{:?}", t.height_nm);
    assert!(matches!(
        parse("100%", "0.88"),
        Err(ErcError::NotAFraction {
            param: "limit_failure",
            ..
        })
    ));
    assert!(matches!(
        parse("0.1%", "-1"),
        Err(ErcError::NonPositiveLimit { .. })
    ));
}
