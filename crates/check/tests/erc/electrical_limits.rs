//! What the solve-reading rules do once they are past their intent gate.
//!
//! The gate itself is `intent_gate.rs`. This file is about the comparison on
//! the other side of it: the drop a node actually sits at, which edges a
//! per-layer limit covers, and the two places a physically impossible parameter
//! must produce a refusal rather than a pass.
//!
//! Current density is amps per metre and the conductor widths are database
//! units; the `Grid` that converts between them is a parameter as of the
//! Testing-Phase, so the closed form is reachable here. What is asserted below
//! is still the scope and the direction — which edges the rule looks at, and
//! how its verdict moves with the limit — because those fail against a rule
//! that never performs the comparison at all, which an absolute value taken at
//! one point does not.

use crate::common;

use common::{
    declared_supplies, head, limit_net, manufacturing_grid, microamps, millivolts,
    operating_temperature, rule, series_chain, solve, GridBuilder,
};
use gpurify_check::erc::facts::IntentMap;
use gpurify_check::erc::power::{PowerGrid, PowerSolution, Solved};
use gpurify_check::erc::rules::electrical::{
    check_electromigration, check_em_current_density, check_ir_drop, ElectromigrationTable,
    EmCurrentDensityTable, IrDropTable,
};
use gpurify_check::erc::rules::reliability::{check_reliability, ReliabilityTable};
use gpurify_check::report::{Measurement, Outcome, RuleRun, Violations};
use gpurify_check::topology::NetId;
use gpurify_geom::{prefix, CurrentDensity, Qty, Temperature};
use gpurify_geom::{LayerId, PolyId};
use gpurify_ingest::intent::NetLimits;
use gpurify_ingest::StrId;
use gpurify_testgen::{assert_close, assert_close_relative};

fn density(value: f64) -> Qty<CurrentDensity, { prefix::BASE }> {
    Qty::new(value)
}

/// Intent declaring the grid's net a supply, carrying exactly the limits given.
fn intent_with(limits: NetLimits) -> IntentMap {
    let mut map = declared_supplies(NetId(0), NetId(1), 1_800.0);
    limit_net(&mut map, NetId(0), limits);
    map
}

/// The millivolts on a violation row.
///
/// # Panics
///
/// When the row measured something other than a voltage.
fn measured_millivolts(violations: &Violations, row: usize) -> f64 {
    match violations.measured[row] {
        Measurement::Voltage(v) => v.raw(),
        other => panic!("row {row} measured {other:?}, not a voltage"),
    }
}

/// The row naming a given polygon.
///
/// # Panics
///
/// When no row does.
fn row_naming(violations: &Violations, poly: PolyId) -> usize {
    (0..violations.rule.len())
        .find(|&row| violations.shape_a[row] == poly)
        .unwrap_or_else(|| panic!("no violation names {poly:?}"))
}

fn report() -> (Violations, Vec<RuleRun>) {
    (Violations::default(), Vec::new())
}

/// Oracle: closed form. A milliamp through a chain of 2.5 ohm resistors drops
/// 2.5 mV per resistor, so the nodes sit 0, 2.5, 5, 7.5 and 10 mV below
/// nominal. Against a 6 mV limit exactly the last two are violations, and the
/// number each reports is its own drop — not the worst on the net, and not the
/// total across the chain.
///
/// The coordinate is asserted exactly, because the grid states it: node `n` is
/// at `node_at[n]` and taps `node_poly[n]`, so a rule reporting anywhere else
/// sends a viewer to the wrong place.
#[test]
fn ir_drop_reports_each_node_that_exceeds_its_nets_absolute_limit() {
    let grid = series_chain(4, 2.5, 1_800.0, 1_000.0);
    let solution = solve(&grid);
    let id = rule(20);
    let intent = intent_with(NetLimits {
        max_drop: Some(millivolts(6.0)),
        ..NetLimits::default()
    });

    let (mut violations, mut runs) = report();
    check_ir_drop(
        Some(Solved {
            grid: &grid,
            solution: &solution,
        }),
        &intent,
        &IrDropTable { head: head(id) },
        &mut violations,
        &mut runs,
    );

    assert_eq!(
        violations.rule.len(),
        2,
        "only the two nodes past 6 mV are over the limit"
    );
    for (node, expected_mv) in [(3u32, 7.5), (4, 10.0)] {
        let row = row_naming(&violations, PolyId(node));
        assert_eq!(violations.rule[row], id);
        assert_eq!(violations.at[row], grid.node_at[node as usize]);
        assert_eq!(violations.layer[row], grid.node_layer[node as usize]);
        assert_eq!(violations.limit[row], Measurement::Voltage(millivolts(6.0)));
        assert_close_relative(
            &format!("the drop at node {node}"),
            measured_millivolts(&violations, row),
            expected_mv,
            1e-6,
        );
    }

    let run = common::run_of(&runs, id);
    assert_eq!(run.outcome, Outcome::Ran);
    assert_eq!(run.violations, 2);
}

/// Oracle: closed form. The fractional limit is a different limit over the same
/// solve: 0.2% of a 1.8 V nominal is 3.6 mV, so three of the five nodes are
/// over where the 6 mV absolute limit caught two. Stating them in separate
/// tests is deliberate — the two are independent, and a rule that applied one
/// and silently dropped the other passes whichever test states both together.
#[test]
fn ir_drop_applies_the_fractional_limit_against_the_domains_nominal() {
    let grid = series_chain(4, 2.5, 1_800.0, 1_000.0);
    let solution = solve(&grid);
    let id = rule(21);
    let intent = intent_with(NetLimits {
        max_drop_fraction: Some(0.002),
        ..NetLimits::default()
    });

    let (mut violations, mut runs) = report();
    check_ir_drop(
        Some(Solved {
            grid: &grid,
            solution: &solution,
        }),
        &intent,
        &IrDropTable { head: head(id) },
        &mut violations,
        &mut runs,
    );

    assert_eq!(
        violations.rule.len(),
        3,
        "nodes 2, 3 and 4 drop past 3.6 mV, which is 0.2% of 1800 mV"
    );
    for node in [2u32, 3, 4] {
        let row = row_naming(&violations, PolyId(node));
        assert_eq!(violations.at[row], grid.node_at[node as usize]);
        assert!(
            measured_millivolts(&violations, row) > 3.6,
            "node {node} was reported without exceeding the fraction of nominal"
        );
    }
    assert_eq!(common::run_of(&runs, id).violations, 3);
}

/// Oracle: closed form. Overvoltage is the third limit and it points the other
/// way: a node above its domain's nominal, not below it. The domain's nominal
/// is 1.8 V here — in the grid's `node_nominal` column *and* in the intent map's
/// declared supply voltage, so the two cannot disagree and the expected number
/// does not depend on which of them the rule reads. A pad driven 800 mV above
/// that nominal with no load puts every node exactly 800 mV over, so a 500 mV
/// overvoltage limit catches all three. A rule that only ever compared drops
/// would report nothing here.
#[test]
fn ir_drop_reports_a_node_sitting_above_its_domains_nominal() {
    let mut builder = GridBuilder::new();
    for node in 0..3u32 {
        builder.node(i64::from(node) * 1_000, 1_800.0, 0.0);
    }
    builder.pad(0, 2_600.0);
    builder.edge(0, 1, 1.0);
    builder.edge(1, 2, 1.0);
    let grid = builder.finish();
    let solution = solve(&grid);

    let id = rule(22);
    let intent = intent_with(NetLimits {
        max_overvoltage: Some(millivolts(500.0)),
        ..NetLimits::default()
    });

    let (mut violations, mut runs) = report();
    check_ir_drop(
        Some(Solved {
            grid: &grid,
            solution: &solution,
        }),
        &intent,
        &IrDropTable { head: head(id) },
        &mut violations,
        &mut runs,
    );

    assert_eq!(
        violations.rule.len(),
        3,
        "no current flows, so all three sit at the pad's 2.6 V"
    );
    for row in 0..3 {
        assert_eq!(
            violations.limit[row],
            Measurement::Voltage(millivolts(500.0))
        );
        assert_close(
            "the overvoltage",
            measured_millivolts(&violations, row),
            800.0,
            1e-6,
        );
    }
    assert_eq!(common::run_of(&runs, id).violations, 3);
}

/// A chain whose first two edges are on layer zero and last two on layer one.
fn two_layer_chain() -> (PowerGrid, PowerSolution) {
    let mut builder = GridBuilder::new();
    for node in 0..5u32 {
        let load = if node == 4 { 1_000.0 } else { 0.0 };
        builder.node(i64::from(node) * 1_000, 1_800.0, load);
    }
    builder.pad(0, 1_800.0);
    builder.edge_on(LayerId(0), 0, 1, 1.0);
    builder.edge_on(LayerId(0), 1, 2, 1.0);
    builder.edge_on(LayerId(1), 2, 3, 1.0);
    builder.edge_on(LayerId(1), 3, 4, 1.0);
    let grid = builder.finish();
    let solution = solve(&grid);
    (grid, solution)
}

fn density_table(id: StrId, layer: LayerId, limit: f64) -> EmCurrentDensityTable {
    EmCurrentDensityTable {
        head: head(id),
        layer_start: vec![0, 1],
        layer: vec![layer],
        max_density: vec![density(limit)],
        max_current_per_cut: vec![microamps(200.0)],
    }
}

/// Oracle: construct-from-answer. The rule's scope is stated: an edge on a
/// layer the row does not limit is skipped and not counted in `examined`. Four
/// edges, two on each of two layers, one limited layer — so `examined` is two,
/// whichever limit is set, and no row ever names the unlimited layer.
///
/// This is the assertion that separates "the rule examined the right edges"
/// from "the rule examined everything and got lucky", and neither is visible in
/// a violation count.
#[test]
fn em_current_density_examines_only_the_edges_on_a_limited_layer() {
    let (grid, solution) = two_layer_chain();
    let solved = Solved {
        grid: &grid,
        solution: &solution,
    };

    for limit in [1e-30, 1e30] {
        let id = rule(23);
        let (mut violations, mut runs) = report();
        check_em_current_density(
            Some(solved),
            &intent_with(NetLimits::default()),
            manufacturing_grid(),
            &density_table(id, LayerId(1), limit),
            &mut violations,
            &mut runs,
        );

        let run = common::run_of(&runs, id);
        assert_eq!(run.outcome, Outcome::Ran);
        assert_eq!(
            run.examined, 2,
            "two of the four edges lie on the limited layer"
        );
        for row in 0..violations.rule.len() {
            assert_eq!(
                violations.layer[row],
                LayerId(1),
                "row {row} reports an edge on a layer the deck did not limit"
            );
        }
    }
}

/// Oracle: law. The verdict must move with the limit and in the right
/// direction. Every branch of this chain carries the same current, so against
/// an unreachably small limit all the limited edges are violations and against
/// an unreachably large one none are. That is scale-free — it needs no
/// conversion from database units to metres, which is what the signature cannot
/// supply — and it fails against a rule that never performs the comparison.
#[test]
fn em_current_density_reports_everything_below_a_tiny_limit_and_nothing_below_a_huge_one() {
    let (grid, solution) = two_layer_chain();
    let solved = Solved {
        grid: &grid,
        solution: &solution,
    };

    let strict = rule(24);
    let (mut violations, mut runs) = report();
    check_em_current_density(
        Some(solved),
        &intent_with(NetLimits::default()),
        manufacturing_grid(),
        &density_table(strict, LayerId(0), 1e-30),
        &mut violations,
        &mut runs,
    );
    assert_eq!(
        violations.rule.len(),
        2,
        "both limited edges carry current, and no current is below 1e-30 A/m"
    );
    assert_eq!(common::run_of(&runs, strict).violations, 2);

    let lax = rule(25);
    let (violations, runs) = {
        let (mut v, mut r) = report();
        check_em_current_density(
            Some(solved),
            &intent_with(NetLimits::default()),
            manufacturing_grid(),
            &density_table(lax, LayerId(0), 1e30),
            &mut v,
            &mut r,
        );
        (v, r)
    };
    gpurify_testgen::assert_clean(&runs, &violations, lax);
}

fn electromigration_table(
    id: StrId,
    reference_kelvin: f64,
    layer: LayerId,
) -> ElectromigrationTable {
    ElectromigrationTable {
        head: head(id),
        layer_start: vec![0, 1],
        layer: vec![layer],
        max_density: vec![density(1e12)],
        max_current_per_cut: vec![microamps(200.0)],
        blech_limit: vec![microamps(1e-9)],
        reference_temperature: vec![Qty::<Temperature, { prefix::BASE }>::new(reference_kelvin)],
        activation_energy_ev: vec![0.7],
        current_exponent: vec![2.0],
    }
}

/// Oracle: construct-from-answer, on the fail-closed path, and the one test
/// that pins `reference_temperature` to kelvin.
///
/// Black's equation needs `1/T`. On the Celsius scale that divides by zero at
/// the freezing point and changes sign below it, so a deck value that was never
/// converted lands here as a small or negative number. 358.15 K is 85 °C and
/// the rule runs; the bare 85, the bare 0 and the bare -40 that a Celsius deck
/// would produce have no Arrhenius factor at all, and the honest answer to a
/// derating that is not finite is a refusal.
///
/// A test that fed 85 and got a plausible verdict would be testing the missing
/// conversion, not the rule.
#[test]
fn an_electromigration_reference_temperature_that_is_not_absolute_is_refused() {
    let (grid, solution) = two_layer_chain();
    let solved = Solved {
        grid: &grid,
        solution: &solution,
    };

    let good = rule(26);
    let (mut violations, mut runs) = report();
    check_electromigration(
        Some(solved),
        &intent_with(NetLimits::default()),
        manufacturing_grid(),
        operating_temperature(),
        &electromigration_table(good, 358.15, LayerId(0)),
        &mut violations,
        &mut runs,
    );
    assert_eq!(
        common::run_of(&runs, good).outcome,
        Outcome::Ran,
        "85 degrees Celsius stated as 358.15 K is an ordinary operating point"
    );

    for (index, absolute_zero_or_below) in [0.0f64, -40.0].into_iter().enumerate() {
        let id = rule(27 + u32::try_from(index).expect("two rows"));
        let (mut violations, mut runs) = report();
        check_electromigration(
            Some(solved),
            &intent_with(NetLimits::default()),
            manufacturing_grid(),
            operating_temperature(),
            &electromigration_table(id, absolute_zero_or_below, LayerId(0)),
            &mut violations,
            &mut runs,
        );
        let run = common::run_of(&runs, id);
        assert_eq!(
            run.outcome,
            Outcome::Refused,
            "{absolute_zero_or_below} K has no Arrhenius factor; an infinite allowed \
             current passes every branch silently"
        );
        assert!(
            violations.rule.iter().all(|&r| r != id),
            "a refused row must not also report findings"
        );
    }
}

fn reliability_table(id: StrId, duty_cycle: f64, cap_mv: f64) -> ReliabilityTable {
    ReliabilityTable {
        head: head(id),
        required_lifetime_hours: vec![87_600.0],
        reference_lifetime_hours: vec![10_000.0],
        reference_stress: vec![millivolts(2_000.0)],
        stress_exponent: vec![4.0],
        reference_temperature: vec![Qty::<Temperature, { prefix::BASE }>::new(398.15)],
        activation_energy_ev: vec![0.6],
        duty_cycle: vec![duty_cycle],
        max_abs_voltage: vec![millivolts(cap_mv)],
    }
}

/// Oracle: construct-from-answer, on the fail-closed path. A duty cycle is a
/// fraction of the lifetime spent under stress, so it lives in `0.0 ..= 1.0`.
/// `RuleSet::from_deck` rejects anything else at load; this is the second line
/// of the same defence, and it matters because a duty cycle above one shortens
/// every predicted lifetime and one below zero lengthens them without bound.
#[test]
fn a_reliability_duty_cycle_outside_the_unit_interval_is_refused() {
    let grid = series_chain(3, 1.0, 1_800.0, 500.0);
    let solution = solve(&grid);
    let solved = Solved {
        grid: &grid,
        solution: &solution,
    };

    for (index, duty) in [1.5f64, -0.1].into_iter().enumerate() {
        let id = rule(30 + u32::try_from(index).expect("two rows"));
        let (mut violations, mut runs) = report();
        check_reliability(
            Some(solved),
            &intent_with(NetLimits::default()),
            operating_temperature(),
            &reliability_table(id, duty, 1_950.0),
            &mut violations,
            &mut runs,
        );
        assert_eq!(
            common::run_of(&runs, id).outcome,
            Outcome::Refused,
            "a duty cycle of {duty} is not a fraction of a lifetime"
        );
        assert!(violations.rule.iter().all(|&r| r != id));
    }
}

/// Oracle: construct-from-answer. The absolute voltage cap is checked directly
/// rather than through the lifetime model, which is the one part of this rule
/// with an answer a test can state: every node of this grid sits between 1.79
/// and 1.80 V, so a 1.0 V cap catches all of them, and each row's measurement
/// must be the voltage of a node that is actually in the grid.
///
/// Asserting that the reported number is one of the grid's own node voltages is
/// what separates "over the cap" from "over the cap by the right amount at the
/// right place" — the previous ERC suite compared counts and would have passed
/// a rule reporting the same wrong number five times.
///
/// Only the rows measuring a voltage are the cap's; the lifetime half of this
/// rule reports against a different limit and is read by
/// `docs/NEED_TESTING.md`, not here. There must be exactly five of them,
/// because the grid has five nodes and every one of them is over the cap.
#[test]
fn a_node_over_the_absolute_voltage_cap_is_reported_with_its_own_voltage() {
    let grid = series_chain(4, 2.5, 1_800.0, 1_000.0);
    let solution = solve(&grid);
    let id = rule(32);

    let (mut violations, mut runs) = report();
    check_reliability(
        Some(Solved {
            grid: &grid,
            solution: &solution,
        }),
        &intent_with(NetLimits::default()),
        operating_temperature(),
        &reliability_table(id, 0.5, 1_000.0),
        &mut violations,
        &mut runs,
    );

    let run = common::run_of(&runs, id);
    assert_eq!(run.outcome, Outcome::Ran);

    let over_the_cap: Vec<usize> = (0..violations.rule.len())
        .filter(|&row| matches!(violations.measured[row], Measurement::Voltage(_)))
        .collect();
    assert_eq!(
        over_the_cap.len(),
        grid.node_net.len(),
        "every one of the grid's nodes is 800 mV over a 1.0 V cap"
    );
    for row in over_the_cap {
        assert_eq!(
            violations.limit[row],
            Measurement::Voltage(millivolts(1_000.0))
        );
        let reported = measured_millivolts(&violations, row);
        assert!(
            reported > 1_000.0,
            "row {row} reports {reported} mV, which is not over the 1000 mV cap"
        );
        let matches_a_node = solution
            .node_voltage
            .iter()
            .any(|v| (v.raw() - reported).abs() < 1e-6);
        assert!(
            matches_a_node,
            "row {row} reports {reported} mV, which is no node's solved voltage"
        );
    }
}
