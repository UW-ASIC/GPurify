//! `RuleSet::run`, and the claim that makes an ERC report readable.
//!
//! Every configured rule row produces exactly one `RuleRun`, including the rows
//! that could not run. That is the invariant the crate is shaped around: an
//! empty violation table means "clean" only when a run row says the rule
//! executed, and a rule that returned early without recording itself is
//! indistinguishable from a rule that found nothing.
//!
//! Oracle: construct-from-answer. The rule set below is written out by hand
//! with one row of each of the nineteen kinds, so both the expected number of
//! run rows and the expected split between the thirteen that always run and the
//! six that need design intent are decided before anything executes.

mod common;

use common::{head, manufacturing_grid, operating_temperature, rule};
use gpurify_core::{Bbox, LayerId};
use gpurify_derived::{Evaluator, LayerRef};
use gpurify_erc::facts::{IntentMap, NetFacts};
use gpurify_erc::power::NetNetworks;
use gpurify_erc::rules::{antenna, electrical, reliability, supply, topology};
use gpurify_erc::ruleset::{RuleSet, RunInputs, KINDS};
use gpurify_erc::{Design, ErcError, Scratch};
use gpurify_ingest::deck::{
    Connectivity, Deck, DeviceRecognition, LayerTable, ProcessStack, RuleSpec, RuleTable,
};
use gpurify_ingest::{StrId, StrTable};
use gpurify_report::{Outcome, RuleRun, Severity, SkipReason, Violations};
use gpurify_testgen::{dbu, LayoutBuilder};
use gpurify_topology::{DeviceTable, NetTable};
use gpurify_units::{prefix, Current, CurrentDensity, Qty, Resistance, Temperature, Voltage};

/// The id given to each kind's single configured row, in the order `KINDS`
/// spells them. Ids are positional so a failure names the kind.
fn id_of(kind: &str) -> StrId {
    let index = KINDS
        .iter()
        .position(|&k| k == kind)
        .unwrap_or_else(|| panic!("{kind} is not a kind this crate implements"));
    rule(u32::try_from(index).expect("nineteen kinds"))
}

/// The six kinds that cannot answer their question without design intent.
const INTENT_GATED: [&str; 6] = [
    "electromigration",
    "em_current_density",
    "esd_latchup",
    "hv_domain",
    "ir_drop",
    "reliability",
];

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

/// One row of every one of the nineteen kinds, all naming layers that exist in
/// the store below.
#[allow(
    clippy::too_many_lines,
    reason = "nineteen tables written out once is the point of the test"
)]
fn every_kind() -> RuleSet {
    let base = LayerRef::Base(LayerId(0));
    let other = LayerRef::Base(LayerId(1));
    RuleSet {
        floating_gate: topology::FloatingGateTable {
            head: head(id_of("floating_gate")),
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
        unconnected_pin: topology::UnconnectedPinTable {
            head: head(id_of("unconnected_pin")),
            layer_start: vec![0, 1],
            layer: vec![LayerId(0)],
        },

        supply_short: supply::SupplyShortTable {
            head: head(id_of("supply_short")),
            tap_a: vec![base],
            tap_b: vec![other],
        },
        soft_connection: supply::SoftConnectionTable {
            head: head(id_of("soft_connection")),
            soft_start: vec![0, 1],
            soft: vec![other],
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
            clamp_start: vec![0, 0],
            clamp_model: Vec::new(),
        },

        antenna: antenna::AntennaTable {
            head: head(id_of("antenna")),
            gate: vec![base],
            collector_start: vec![0, 1],
            collector: vec![other],
            collector_measure: vec![antenna::AntennaMeasure::Area],
            max_ratio: vec![50.0],
        },
        antenna_electrical: antenna::AntennaElectricalTable {
            head: head(id_of("antenna_electrical")),
            gate: vec![base],
            collector_start: vec![0, 1],
            collector: vec![other],
            diode: vec![None],
            diode_credit: vec![0.0],
            diode_bonus: vec![0.0],
            max_ratio: vec![50.0],
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
        },
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

        reliability: reliability::ReliabilityTable {
            head: head(id_of("reliability")),
            required_lifetime_hours: vec![87_600.0],
            mechanism: vec![StrId(900)],
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
        },
    }
}

/// Everything a run borrows, over a two-layer layout the size of the die.
struct Cell {
    store: gpurify_core::GeometryStore,
    derived: Evaluator,
    nets: NetTable,
    devices: DeviceTable,
    facts: NetFacts,
    networks: NetNetworks,
}

impl Cell {
    fn new() -> Self {
        let mut layout = LayoutBuilder::new(2);
        layout.rect(LayerId(0), 0, 0, 1_000, 2_000);
        layout.rect(LayerId(1), 1_200, 200, 1_800, 800);
        let (store, _) = layout.finish();
        Self {
            store,
            derived: Evaluator::default(),
            nets: NetTable::default(),
            devices: DeviceTable::default(),
            facts: NetFacts::default(),
            networks: NetNetworks::default(),
        }
    }

    fn inputs<'a>(&'a self, intent: &'a IntentMap) -> RunInputs<'a> {
        RunInputs {
            design: Design {
                store: &self.store,
                derived: &self.derived,
                nets: &self.nets,
                devices: &self.devices,
            },
            facts: &self.facts,
            intent,
            networks: &self.networks,
            power: None,
            die: Bbox {
                xlo: dbu(0),
                ylo: dbu(0),
                xhi: dbu(2_000),
                yhi: dbu(2_000),
            },
            grid: manufacturing_grid(),
            operating_temperature: operating_temperature(),
        }
    }
}

/// Oracle: construct-from-answer. Nineteen configured rows must produce
/// nineteen run rows, one per row, each attributable to its own rule id. This
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

/// Oracle: construct-from-answer. With no design intent the six gated kinds
/// must say so and the thirteen others must run anyway. Both halves matter: a
/// gated rule reporting clean is the failure this crate is built against, and
/// an ungated rule skipping would quietly stop checking a design that needs no
/// intent file at all.
#[test]
fn without_intent_exactly_the_six_gated_kinds_record_themselves_skipped() {
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
    assert!(violations.rule.is_empty());
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
    violations.push(gpurify_report::Violation {
        rule: rule(999),
        layer: LayerId(0),
        severity: Severity::Warning,
        at: gpurify_testgen::point(1, 1),
        measured: gpurify_report::Measurement::Count(1),
        limit: gpurify_report::Measurement::Count(0),
        shapes: (gpurify_core::PolyId(0), None),
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
/// Three of the nineteen kinds take neither — `floating_gate`, `tie_high_low`
/// and `ir_drop` are configuration and nothing else — so a deck of those is the
/// one shape [`RuleSet::from_deck`] can be handed from outside this workspace.
/// The parameter *names* the other sixteen expect are an Implementation-Phase
/// choice that no frozen signature states, which is why the rows below carry
/// none; see `docs/NEED_TESTING.md`.
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
        grid: None,
        layers: LayerTable::default(),
        rules: RuleTable {
            spec,
            layer_ref: Vec::new(),
            param: Vec::new(),
        },
        connectivity: Connectivity::default(),
        devices: DeviceRecognition::default(),
        stack: ProcessStack::default(),
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
/// rather than disappeared: `engine::run::run_checks` refuses a kind that is in
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
