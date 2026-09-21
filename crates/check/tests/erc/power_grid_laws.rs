//! The DC solve, against Ohm's law and against Kirchhoff's.
//!
//! Every test here reads a [`PowerGrid`] built column by column and a
//! [`PowerSolution`] solved from it. Two kinds of oracle appear, and each test
//! names which it uses: a closed form where the network is a series chain or a
//! parallel bundle, and a law where the network is arbitrary. The law-shaped
//! tests are the stronger ones — they hold on any grid the generator emits, so
//! they cannot be satisfied by a solver tuned to one fixture.
//!
//! [`PowerGrid`]: gpurify_check::erc::power::PowerGrid
//! [`PowerSolution`]: gpurify_check::erc::power::PowerSolution

use crate::common;

use common::{
    microamps, millivolts, parallel_bundle, random_grid, series_chain, solve, GridBuilder,
};
use gpurify_check::erc::power::{self, PowerError, PowerSolution, SolveConfig};
use gpurify_testgen::{assert_close, assert_close_relative};

/// Oracle: closed form. Resistances in series add, so the drop at the `k`th
/// node of a uniform chain carrying one current is `k * I * R` — arithmetic the
/// test does directly, per node, rather than only at the far end. Checking
/// every node is what separates "the total is right" from "the profile is
/// right"; a solver that lumped the whole chain into one resistor would pass
/// the first and fail this.
#[test]
fn series_resistances_add_between_the_pad_and_the_load() {
    let grid = series_chain(4, 2.5, 1_800.0, 1_000.0);
    let solution = solve(&grid);

    // 1000 uA through 2.5 ohm is 2.5 mV per resistor.
    for node in 0..=4u32 {
        let expected_mv = 2.5 * f64::from(node);
        let drop = solution.node_drop[node as usize].raw();
        if node == 0 {
            assert_close("the drop at the pad", drop, 0.0, 1e-9);
        } else {
            assert_close_relative("a node drop", drop, expected_mv, 1e-8);
        }
        assert_close_relative(
            "a node voltage",
            solution.node_voltage[node as usize].raw(),
            1_800.0 - expected_mv,
            1e-9,
        );
    }

    for edge in 0..grid.edge_from.len() {
        assert_close_relative(
            "a branch current",
            solution.branch_current[edge].raw(),
            1_000.0,
            1e-8,
        );
    }
}

/// Oracle: closed form. Conductances in parallel add, so four eight-ohm strands
/// between the same two nodes are two ohms and each carries a quarter of the
/// current.
///
/// The parallel strands are a genuine multi-edge, which is the case a solver
/// that assigns into its Laplacian rather than accumulating gets wrong: it
/// keeps one strand, reports eight ohms, and is right about everything else.
#[test]
fn parallel_conductances_add_between_the_pad_and_the_load() {
    let grid = parallel_bundle(4, 8.0, 1_800.0, 1_000.0);
    let solution = solve(&grid);

    // 1000 uA through 8/4 = 2 ohm is 2 mV.
    assert_close(
        "the drop at the pad",
        solution.node_drop[0].raw(),
        0.0,
        1e-9,
    );
    assert_close_relative(
        "the drop at the load",
        solution.node_drop[1].raw(),
        2.0,
        1e-8,
    );
    for edge in 0..4 {
        assert_close_relative(
            "a strand current",
            solution.branch_current[edge].raw(),
            250.0,
            1e-8,
        );
    }
}

/// Oracle: law. Kirchhoff's current law holds at every node of every resistive
/// network, so it needs no constructed answer and applies to arbitrary
/// generated geometry: the signed branch currents at a node sum to the current
/// drawn there.
///
/// Sign convention is the grid's own — `branch_current` is positive from
/// `edge_from` towards `edge_to`, and `node_load` is positive when it draws
/// from the grid. A solver with either sign inverted fails this on any grid
/// with more than one edge at a node.
#[test]
fn kirchhoffs_current_law_holds_at_every_node_of_a_solved_grid() {
    for seed in [1u64, 2, 3] {
        let grid = random_grid(seed, 24, 12);
        let solution = solve(&grid);

        let mut net_in = vec![0.0f64; grid.node_net.len()];
        for edge in 0..grid.edge_from.len() {
            let current = solution.branch_current[edge].raw();
            net_in[grid.edge_from[edge] as usize] -= current;
            net_in[grid.edge_to[edge] as usize] += current;
        }

        for (node, &into_node) in net_in.iter().enumerate() {
            if grid
                .fixed_voltage(u32::try_from(node).expect("small"))
                .is_some()
            {
                // A pad sources whatever the rest of the grid draws; the law
                // there is the global one, checked separately below.
                continue;
            }
            assert_close(
                &format!("Kirchhoff's current law at node {node} of seed {seed}"),
                into_node,
                grid.node_load[node].raw(),
                1e-6,
            );
        }
    }
}

/// Oracle: law. Charge is conserved over the whole grid, so the current the
/// pads deliver equals the current the loads draw. This is the half of
/// Kirchhoff's law the per-node test skips at the pad, and it is what catches a
/// pad elimination that dropped a term.
#[test]
fn the_pads_deliver_exactly_what_the_loads_draw() {
    let grid = random_grid(7, 20, 9);
    let solution = solve(&grid);

    let drawn: f64 = grid.node_load.iter().map(|c| c.raw()).sum();
    let mut delivered = 0.0f64;
    for edge in 0..grid.edge_from.len() {
        let current = solution.branch_current[edge].raw();
        if grid.source_node.contains(&grid.edge_from[edge]) {
            delivered += current;
        }
        if grid.source_node.contains(&grid.edge_to[edge]) {
            delivered -= current;
        }
    }
    assert_close_relative("the current leaving the pads", delivered, drawn, 1e-8);
}

/// Oracle: law. `node_drop` is defined as nominal minus solved, and it is
/// stored rather than recomputed precisely because every consumer wants it —
/// which makes it the one place a sign error would hide from every rule at
/// once. The relation holds for any grid.
#[test]
fn every_node_drop_is_its_nominal_less_its_solved_voltage() {
    let grid = random_grid(11, 16, 6);
    let solution = solve(&grid);

    for node in 0..grid.node_net.len() {
        assert_close(
            &format!("the drop at node {node}"),
            solution.node_drop[node].raw(),
            grid.node_nominal[node].raw() - solution.node_voltage[node].raw(),
            1e-9,
        );
    }
}

/// Oracle: law. A resistive network is linear, so scaling every load current by
/// a constant scales every drop and every branch current by the same constant.
/// True of any network, and it fails against a solver carrying any additive
/// term the loads do not explain — a leaked initial guess, an offset in the
/// right-hand side.
#[test]
fn scaling_every_load_scales_every_drop_by_the_same_factor() {
    let grid = random_grid(13, 18, 8);
    let reference = solve(&grid);

    let mut doubled = random_grid(13, 18, 8);
    for load in &mut doubled.node_load {
        *load = *load * 2.0;
    }
    let scaled = solve(&doubled);

    for node in 0..grid.node_net.len() {
        let expected = 2.0 * reference.node_drop[node].raw();
        if expected.abs() < 1e-12 {
            assert_close(
                "a zero drop stays zero",
                scaled.node_drop[node].raw(),
                0.0,
                1e-9,
            );
        } else {
            assert_close_relative(
                &format!("the doubled drop at node {node}"),
                scaled.node_drop[node].raw(),
                expected,
                1e-8,
            );
        }
    }
    for edge in 0..grid.edge_from.len() {
        let expected = 2.0 * reference.branch_current[edge].raw();
        if expected.abs() < 1e-12 {
            continue;
        }
        assert_close_relative(
            &format!("the doubled current in edge {edge}"),
            scaled.branch_current[edge].raw(),
            expected,
            1e-8,
        );
    }
}

/// Oracle: law. A pad is a boundary condition, so the solve must return it
/// unchanged. A solver that treated a pad as one more unknown converges to
/// something near it and this is the test that says "near" is not the contract.
#[test]
fn a_pad_sits_at_exactly_the_voltage_it_was_fixed_at() {
    let grid = series_chain(3, 1.0, 1_800.0, 500.0);
    let solution = solve(&grid);

    assert_eq!(
        solution.node_voltage[0],
        millivolts(1_800.0),
        "the pad moved off its fixed voltage"
    );
    assert_eq!(grid.fixed_voltage(0), Some(millivolts(1_800.0)));
    assert_eq!(
        grid.fixed_voltage(1),
        None,
        "node 1 is an unknown, not a pad"
    );
}

/// Oracle: construct-from-answer, on the fail-closed path. With no pad the
/// system is singular — every solution plus a constant is also a solution — so
/// the only honest answer is a refusal. A solver returning its initial guess
/// here reports every node at nominal, which is a clean IR-drop result and a
/// lie.
#[test]
fn a_grid_with_no_pad_is_refused_rather_than_solved() {
    let mut builder = GridBuilder::new();
    builder.node(0, 1_800.0, 0.0);
    builder.node(1_000, 1_800.0, 100.0);
    builder.edge(0, 1, 1.0);
    let grid = builder.finish();

    let mut scratch = power::SolveScratch::default();
    let mut solution = PowerSolution::default();
    let result = power::solve_into(&grid, SolveConfig::default(), &mut scratch, &mut solution);
    assert_eq!(result, Err(PowerError::Unanchored));
}

/// Oracle: construct-from-answer, on the fail-closed path. Node two is joined
/// to nothing, so its voltage is undetermined for the same reason. The island
/// is exactly one node, so the error names that node and the test can assert
/// which — an error naming the wrong node would leave a user searching the
/// wrong part of the design.
#[test]
fn an_island_no_pad_reaches_is_refused_and_named() {
    let mut builder = GridBuilder::new();
    builder.node(0, 1_800.0, 0.0);
    builder.node(1_000, 1_800.0, 100.0);
    builder.node(2_000, 1_800.0, 100.0);
    builder.pad(0, 1_800.0);
    builder.edge(0, 1, 1.0);
    let grid = builder.finish();

    let mut scratch = power::SolveScratch::default();
    let mut solution = PowerSolution::default();
    let result = power::solve_into(&grid, SolveConfig::default(), &mut scratch, &mut solution);
    assert_eq!(result, Err(PowerError::UnanchoredIsland(2)));
}

/// Oracle: construct-from-answer, on the fail-closed path. A zero resistance
/// shorts two nodes and silently removes a drop the design has, which is the
/// dangerous direction: it makes a bad grid read clean. The error names the
/// edge, and the edge it names is the one that is zero.
#[test]
fn a_zero_resistance_edge_is_refused_rather_than_shorted() {
    let mut builder = GridBuilder::new();
    builder.node(0, 1_800.0, 0.0);
    builder.node(1_000, 1_800.0, 0.0);
    builder.node(2_000, 1_800.0, 100.0);
    builder.pad(0, 1_800.0);
    builder.edge(0, 1, 1.0);
    builder.edge(1, 2, 0.0);
    let grid = builder.finish();

    let mut scratch = power::SolveScratch::default();
    let mut solution = PowerSolution::default();
    let result = power::solve_into(&grid, SolveConfig::default(), &mut scratch, &mut solution);
    assert_eq!(result, Err(PowerError::BadResistance(1)));
}

/// Oracle: law. `is_consistent_with` is the precondition of every rule reading
/// a solution, so both of its answers matter: a solution from this grid is
/// consistent with it, and one whose columns no longer line up is not. A
/// predicate that only ever said yes would pass a one-sided test and admit the
/// `NaN` this crate exists to refuse.
#[test]
fn a_solution_is_consistent_only_with_the_grid_it_matches() {
    let grid = series_chain(3, 2.0, 1_800.0, 400.0);
    let mut solution = solve(&grid);
    assert!(solution.is_consistent_with(&grid));

    solution.node_voltage.pop();
    assert!(
        !solution.is_consistent_with(&grid),
        "a solution shorter than the grid's node column is not consistent with it"
    );

    let mut infected = solve(&grid);
    infected.node_drop[1] = millivolts(f64::NAN);
    assert!(
        !infected.is_consistent_with(&grid),
        "a NaN drop compares false against every limit and so passes every rule"
    );

    let mut infected_current = solve(&grid);
    infected_current.branch_current[0] = microamps(f64::INFINITY);
    assert!(
        !infected_current.is_consistent_with(&grid),
        "an infinite branch current is not a finite solution"
    );

    // The third column, and the one the other three cases leave unread: the
    // length arm above pops `node_voltage` without ever making one of its
    // entries non-finite, so the fold over it went unverified while the folds
    // over the other two were pinned. `|=` on a flag that starts true can only
    // answer yes, so a NaN node voltage would reach every rule that reads this
    // solution — the fail-open the predicate exists to refuse.
    let mut infected_voltage = solve(&grid);
    infected_voltage.node_voltage[1] = millivolts(f64::NAN);
    assert!(
        !infected_voltage.is_consistent_with(&grid),
        "a NaN node voltage compares false against every limit and so passes every rule"
    );
}

/// Oracle: determinism. The solve is iterative, and an iterative solve whose
/// reduction order depends on anything but the grid produces two different
/// answers for one input. Byte-identical columns across two runs is the gate,
/// so it is asserted on the columns rather than on a tolerance.
#[test]
fn solving_one_grid_twice_produces_identical_columns() {
    let grid = random_grid(29, 32, 20);
    let first = solve(&grid);
    let second = solve(&grid);

    assert_eq!(first.iterations, second.iterations);
    assert_eq!(
        first.relative_residual.to_bits(),
        second.relative_residual.to_bits()
    );
    let bits = |values: &[gpurify_geom::Qty<gpurify_geom::Voltage, -3>]| {
        values.iter().map(|v| v.raw().to_bits()).collect::<Vec<_>>()
    };
    assert_eq!(bits(&first.node_voltage), bits(&second.node_voltage));
    assert_eq!(bits(&first.node_drop), bits(&second.node_drop));
    assert_eq!(
        first
            .branch_current
            .iter()
            .map(|c| c.raw().to_bits())
            .collect::<Vec<_>>(),
        second
            .branch_current
            .iter()
            .map(|c| c.raw().to_bits())
            .collect::<Vec<_>>()
    );
}

/// Oracle: law. A reusable scratch must leave no trace of the previous solve.
/// Solving grid A then grid B through one scratch must give exactly what
/// solving B alone gives, or the workspace is carrying state and the answer
/// depends on what ran before it.
#[test]
fn one_scratch_solving_two_grids_gives_each_its_own_answer() {
    let first_grid = series_chain(6, 3.0, 1_800.0, 900.0);
    let second_grid = parallel_bundle(3, 9.0, 1_200.0, 600.0);

    let alone = solve(&second_grid);

    let mut scratch = power::SolveScratch::default();
    let mut solution = PowerSolution::default();
    power::solve_into(
        &first_grid,
        SolveConfig::default(),
        &mut scratch,
        &mut solution,
    )
    .expect("the chain is anchored");
    power::solve_into(
        &second_grid,
        SolveConfig::default(),
        &mut scratch,
        &mut solution,
    )
    .expect("the bundle is anchored");

    assert_eq!(solution.node_voltage.len(), alone.node_voltage.len());
    for node in 0..alone.node_voltage.len() {
        assert_close(
            &format!("node {node} after a reused scratch"),
            solution.node_voltage[node].raw(),
            alone.node_voltage[node].raw(),
            1e-9,
        );
    }
}
