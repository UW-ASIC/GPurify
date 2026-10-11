//! Naive references for the electrical rules, written here from the
//! definitions and sharing no code with the engine (C6):
//!
//! - a dense nodal solve, Gaussian elimination with partial pivoting on the
//!   full conductance matrix, against the engine's IR drops (its
//!   incomplete-Cholesky conjugate-gradient solve and the `ir_drop` findings
//!   read from it) on generated supply grids, within a tolerance derived from
//!   the solve's stopping rule ([`supply_grids_solve_as_a_dense_nodal_solve_does`]);
//! - a breadth-first search over the extracted net graph of generated
//!   circuits, against `floating_gate`, `esd_topological`, `multiple_drivers`,
//!   `tie_high_low` and `fanout`
//!   ([`topology_rules_agree_with_a_search_of_the_extracted_graph`]);
//! - a brute-force sweep of the voltage propagation rules, gate conditions
//!   included, against `erc::voltage` on the same generated circuits
//!   ([`voltage_propagation_agrees_with_a_naive_sweep_of_the_extracted_graph`]).
//!
//! The boards of `erc.rs` already judge the topology rules against a graph
//! oracle on every small circuit, drawn and extracted, and `supply_short` on
//! every three-tap board; that oracle reads the circuit as planted. The
//! circuits here are larger than a board's four nets, with up to four
//! supplies, so clamp paths and pull networks run through more nets than a
//! board can hold, and the search reads what extraction produced.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    reason = "test sizes: counts far below 2^31"
)]

use gpurify::check::erc::facts::{classify_nets_into, IntentMap, NetFacts};
use gpurify::check::erc::power::{self, EdgeKind, PowerGrid, PowerSolution, Solved};
use gpurify::check::erc::rules::electrical::{check_ir_drop, IrDropTable};
use gpurify::check::erc::rules::supply::{
    check_esd_topological, check_tie_high_low, EsdTopologicalTable, TieHighLowTable,
};
use gpurify::check::erc::rules::topology::{
    check_fanout, check_floating_gate, check_multiple_drivers, FanoutTable, FloatingGateTable,
    MultipleDriversTable,
};
use gpurify::check::erc::ruleset::RuleHead;
use gpurify::check::erc::voltage::{propagate_into, NetVoltage};
use gpurify::check::erc::{Design, Scratch};
use gpurify::check::report::{Measurement, RuleRun, Severity, Violations};
use gpurify::check::topology::{DeviceId, DeviceTable, NetId, NetTable, PortTable, TerminalRole};
use gpurify::geom::ops::Point;
use gpurify::geom::{Dbu, LayerId, PolyId, Qty};
use gpurify::ingest::deck::{DeviceKind, DeviceRecognition, DeviceValue};
use gpurify::ingest::intent::{DomainId, NetLimits, SupplyRole};
use gpurify::ingest::{StrId, StrTable};
use gpurify_testgen::{layout_from_netlist, DeviceSpec, Floorplan, NetlistSpec, Rng};

/// One rule row's head, attributed to `id`.
fn head(id: StrId) -> RuleHead {
    RuleHead {
        rule: vec![id],
        severity: vec![Severity::Error],
    }
}

/// Intent declaring `supplies` as `(net, role)`, every one in a 1.8 V domain,
/// and `limits` as `(net, limits)`.
fn intent_of(supplies: &[(NetId, SupplyRole)], limits: &[(NetId, NetLimits)]) -> IntentMap {
    let mut supplies = supplies.to_vec();
    supplies.sort_by_key(|s| s.0);
    IntentMap {
        declared: true,
        supply_net: supplies.iter().map(|s| s.0).collect(),
        supply_role: supplies.iter().map(|s| s.1).collect(),
        supply_domain: vec![DomainId(0); supplies.len()],
        supply_voltage: vec![Qty::new(1800.0); supplies.len()],
        limit_net: limits.iter().map(|l| l.0).collect(),
        limit: limits.iter().map(|l| l.1).collect(),
    }
}

// ------------------------------------------------------------ the nodal solve

/// Microamps through one ohm per millivolt across it: Ohm's law in the grid's
/// units (mV, µA, Ω).
const UA_PER_MV_PER_SIEMENS: f64 = 1000.0;

/// A `k × k` mesh of one supply net at 1 µm pitch: every mesh edge and a few
/// random chords between 0.05 and 5 Ω, one to three pads, each node drawing
/// up to 0.5 mA. A power grid (nominal 1.8 V) draws its loads; a ground grid
/// (nominal 0 V) has them injected. The first pad sits at the nominal, any
/// other up to 2 mV off it, so current also flows between pads.
fn supply_grid(rng: &mut Rng, k: u32, power: bool) -> PowerGrid {
    let nominal = if power { 1800.0 } else { 0.0 };
    let n = k * k;
    let mut grid = PowerGrid::default();
    for node in 0..n {
        grid.node_net.push(NetId(0));
        grid.node_at.push(Point {
            x: Dbu::new_unchecked(i64::from(node % k) * 1000),
            y: Dbu::new_unchecked(i64::from(node / k) * 1000),
        });
        grid.node_poly.push(PolyId(node));
        grid.node_layer.push(LayerId(0));
        grid.node_nominal.push(Qty::new(nominal));
        let load = 500.0 * rng.unit();
        grid.node_load
            .push(Qty::new(if power { load } else { -load }));
    }
    let edge = |grid: &mut PowerGrid, a: u32, b: u32, rng: &mut Rng| {
        grid.edge_from.push(a);
        grid.edge_to.push(b);
        grid.edge_resistance
            .push(Qty::new(0.05 * 100f64.powf(rng.unit())));
        grid.edge_width.push(Dbu::new_unchecked(1000));
        grid.edge_length.push(Dbu::new_unchecked(1000));
        grid.edge_layer.push(LayerId(0));
        grid.edge_kind.push(EdgeKind::Metal);
    };
    for node in 0..n {
        if node % k + 1 < k {
            edge(&mut grid, node, node + 1, rng);
        }
        if node + k < n {
            edge(&mut grid, node, node + k, rng);
        }
    }
    for _ in 0..k {
        let (a, b) = (
            rng.below(u64::from(n)) as u32,
            rng.below(u64::from(n)) as u32,
        );
        if a != b {
            edge(&mut grid, a, b, rng);
        }
    }
    let mut pads: Vec<u32> = (0..=rng.below(3))
        .map(|_| rng.below(u64::from(n)) as u32)
        .collect();
    pads.sort_unstable();
    pads.dedup();
    let first = rng.below(pads.len() as u64) as usize;
    for (i, &pad) in pads.iter().enumerate() {
        let off = if i == first { 0.0 } else { 2.0 * rng.unit() };
        grid.source_node.push(pad);
        grid.source_voltage
            .push(Qty::new(if power { nominal - off } else { nominal + off }));
    }
    grid
}

/// `x` solving `a x = b` for a dense row-major `n × n` matrix, by Gaussian
/// elimination with partial pivoting. `a` and `b` are consumed.
fn gauss(mut a: Vec<f64>, mut b: Vec<f64>) -> Vec<f64> {
    let n = b.len();
    for col in 0..n {
        let pivot = (col..n)
            .max_by(|&i, &j| a[i * n + col].abs().total_cmp(&a[j * n + col].abs()))
            .expect("a column below the diagonal");
        if pivot != col {
            for c in 0..n {
                a.swap(col * n + c, pivot * n + c);
            }
            b.swap(col, pivot);
        }
        for row in col + 1..n {
            let factor = a[row * n + col] / a[col * n + col];
            if factor != 0.0 {
                for c in col..n {
                    a[row * n + c] -= factor * a[col * n + c];
                }
                b[row] -= factor * b[col];
            }
        }
    }
    let mut x = vec![0.0; n];
    for row in (0..n).rev() {
        let tail: f64 = (row + 1..n).map(|c| a[row * n + c] * x[c]).sum();
        x[row] = (b[row] - tail) / a[row * n + row];
    }
    x
}

/// The grid's node voltages from the full conductance matrix, and the
/// tolerance the engine's answer is held to.
///
/// Kirchhoff's current law at each node that is not a pad: the current a
/// node's neighbours push into it, `Σ g (v_j - v_i)` with `g` in µA/mV, is
/// what its load draws; a pad's voltage moves to the right-hand side.
///
/// The tolerance follows from the engine's stopping rule: the solve stops
/// once the residual is `1e-10` of the one at its start, every unknown at its
/// nominal (`PowerError::NotConverged`'s contract). The reduced matrix `A` is
/// a diagonally dominant M-matrix, so `A⁻¹ ≥ 0` and `‖A⁻¹‖∞` is the largest
/// entry of `A⁻¹ 1`, one more dense solve, and an error `e` with residual
/// `r = A e` obeys `‖e‖∞ ≤ ‖A⁻¹‖∞ ‖r‖∞`. Rounding adds at most
/// `6 n ε ‖A‖∞ ‖v‖∞` to the residual: the engine's recurred residual drifting
/// from the true one, and this elimination's own backward error (its growth
/// factor is at most 2 on such a matrix). So
/// `tolerance = ‖A⁻¹‖∞ (1e-10 ‖r₀‖₂ + 6 n ε ‖A‖∞ ‖v‖∞)`.
fn dense_nodal_solve(grid: &PowerGrid) -> (Vec<f64>, f64) {
    let n = grid.node_count();
    let mut unknown = vec![usize::MAX; n];
    let mut index = 0;
    for (node, slot) in unknown.iter_mut().enumerate() {
        if !grid.source_node.contains(&(node as u32)) {
            *slot = index;
            index += 1;
        }
    }
    let m = index;
    let mut v: Vec<f64> = grid.node_nominal.iter().map(|q| q.raw()).collect();
    for (pad, &node) in grid.source_node.iter().enumerate() {
        v[node as usize] = grid.source_voltage[pad].raw();
    }
    let mut a = vec![0.0; m * m];
    let mut b = vec![0.0; m];
    for (node, &row) in unknown.iter().enumerate() {
        if row != usize::MAX {
            b[row] = -grid.node_load[node].raw();
        }
    }
    for e in 0..grid.edge_count() {
        let (i, j) = (grid.edge_from[e] as usize, grid.edge_to[e] as usize);
        let g = UA_PER_MV_PER_SIEMENS / grid.edge_resistance[e].raw();
        for (here, there) in [(i, j), (j, i)] {
            let row = unknown[here];
            if row == usize::MAX {
                continue;
            }
            a[row * m + row] += g;
            match unknown[there] {
                usize::MAX => b[row] += g * v[there],
                col => a[row * m + col] -= g,
            }
        }
    }

    // The residual at the engine's start: every unknown at its nominal.
    let start: Vec<f64> = (0..n)
        .filter(|&node| unknown[node] != usize::MAX)
        .map(|node| grid.node_nominal[node].raw())
        .collect();
    let r0 = (0..m)
        .map(|row| {
            let ax: f64 = (0..m).map(|c| a[row * m + c] * start[c]).sum();
            (b[row] - ax).powi(2)
        })
        .sum::<f64>()
        .sqrt();
    let norm_a = (0..m)
        .map(|row| (0..m).map(|c| a[row * m + c].abs()).sum::<f64>())
        .fold(0.0, f64::max);
    let inverse_norm = gauss(a.clone(), vec![1.0; m])
        .into_iter()
        .fold(0.0, f64::max);

    let x = gauss(a, b);
    for (node, &row) in unknown.iter().enumerate() {
        if row != usize::MAX {
            v[node] = x[row];
        }
    }
    let largest = v.iter().fold(0.0f64, |acc, x| acc.max(x.abs()));
    let tolerance = inverse_norm * (1e-10 * r0 + 6.0 * m as f64 * f64::EPSILON * norm_a * largest);
    (v, tolerance)
}

/// Oracle: a dense nodal solve. On forty generated supply grids, power and
/// ground, 2 × 2 to 8 × 8, every node voltage the engine solves is within the
/// tolerance [`dense_nodal_solve`] derives of the dense solve's, and an
/// `ir_drop` row whose limit sits between two of the reference drops more
/// than twice that tolerance apart flags exactly the nodes whose reference
/// drop is above it, each measured within the tolerance.
#[test]
fn supply_grids_solve_as_a_dense_nodal_solve_does() {
    let mut strings = StrTable::default();
    let id = strings.intern("ir");
    let mut rng = Rng::new(0xc6_0001);
    let mut checked = 0;
    for case in 0..40u32 {
        let power = case % 2 == 0;
        let k = 2 + case / 2 % 7;
        let grid = supply_grid(&mut rng, k, power);
        let (reference, tolerance) = dense_nodal_solve(&grid);

        let mut scratch = power::SolveScratch::default();
        let mut solution = PowerSolution::default();
        power::solve_into(&grid, &mut scratch, &mut solution)
            .unwrap_or_else(|why| panic!("grid {case} did not solve: {why}"));
        for (node, &want) in reference.iter().enumerate() {
            let got = solution.node_voltage[node].raw();
            assert!(
                (got - want).abs() <= tolerance,
                "grid {case}, node {node}: the engine solves {got} mV, the dense solve \
                 {want} mV, more than {tolerance:e} mV apart"
            );
        }

        // The drop toward the other rail: down for power, up for ground.
        let nominal = grid.node_nominal[0].raw();
        let drop: Vec<f64> = reference
            .iter()
            .map(|v| if power { nominal - v } else { v - nominal })
            .collect();
        let mut sorted = drop.clone();
        sorted.sort_by(f64::total_cmp);
        let Some(gap) = sorted
            .windows(2)
            .skip(sorted.len() / 3)
            .find(|pair| pair[1] - pair[0] > 2.0 * tolerance)
        else {
            continue;
        };
        let limit = 0.5 * (gap[0] + gap[1]);
        let role = if power {
            SupplyRole::Power
        } else {
            SupplyRole::Ground
        };
        let limits = NetLimits {
            max_drop: Some(Qty::new(limit)),
            ..NetLimits::default()
        };
        let intent = intent_of(&[(NetId(0), role)], &[(NetId(0), limits)]);
        let (mut out, mut runs) = (Violations::default(), Vec::new());
        check_ir_drop(
            Ok(Some(Solved {
                grid: &grid,
                solution: &solution,
            })),
            &intent,
            &IrDropTable { head: head(id) },
            &mut out,
            &mut runs,
        );
        let mut found: Vec<(Point, f64)> = (0..out.len())
            .map(|row| {
                let v = out.get(row);
                let Measurement::Voltage(mv) = v.measured else {
                    panic!("an IR drop is a voltage");
                };
                (v.at, mv.raw())
            })
            .collect();
        found.sort_by_key(|f| (f.0.y, f.0.x));
        let want: Vec<(Point, f64)> = (0..grid.node_count())
            .filter(|&node| drop[node] > limit)
            .map(|node| (grid.node_at[node], drop[node]))
            .collect();
        assert_eq!(
            found.iter().map(|f| f.0).collect::<Vec<_>>(),
            want.iter().map(|w| w.0).collect::<Vec<_>>(),
            "grid {case}: ir_drop at {limit} mV flags other nodes than the dense solve"
        );
        for ((at, got), (_, want)) in found.iter().zip(&want) {
            assert!(
                (got - want).abs() <= tolerance,
                "grid {case}: ir_drop measures {got} mV at {at:?}, the dense solve {want} mV"
            );
        }
        checked += 1;
    }
    assert!(checked >= 30, "only {checked} grids had a limit to sweep");
}

// ------------------------------------------------- the extracted net graph

/// A generated circuit, laid out and extracted, and the supplies its intent
/// declares as netlist `(net, role)`.
struct Circuit {
    case: gpurify_testgen::NetlistCase,
    nets: NetTable,
    devices: DeviceTable,
    supplies: Vec<(u32, SupplyRole)>,
}

/// Six to twelve nets, one to four of them supplies of either role, and
/// three to twelve devices: a clamp diode (model `clamp`) one time in four,
/// otherwise a transistor with every terminal on any net.
fn random_circuit(rng: &mut Rng, strings: &mut StrTable) -> Circuit {
    let nets = 6 + rng.below(7) as u32;
    let on = |rng: &mut Rng| rng.below(u64::from(nets)) as u32;
    let mut supplies: Vec<(u32, SupplyRole)> = Vec::new();
    for _ in 0..2 + rng.below(3) {
        let net = on(rng);
        if supplies.iter().all(|s| s.0 != net) {
            let role = if rng.below(2) == 0 {
                SupplyRole::Power
            } else {
                SupplyRole::Ground
            };
            supplies.push((net, role));
        }
    }
    let devices = (0..3 + rng.below(10))
        .map(|_| {
            if rng.below(4) == 0 {
                DeviceSpec {
                    kind: DeviceKind::Diode,
                    model: "clamp".to_owned(),
                    terminals: vec![
                        (TerminalRole::Pin(0), on(rng)),
                        (TerminalRole::Pin(1), on(rng)),
                    ],
                }
            } else {
                DeviceSpec {
                    kind: DeviceKind::Mos,
                    model: "mos".to_owned(),
                    terminals: vec![
                        (TerminalRole::Gate, on(rng)),
                        (TerminalRole::Source, on(rng)),
                        (TerminalRole::Drain, on(rng)),
                        (TerminalRole::Bulk, on(rng)),
                    ],
                }
            }
        })
        .collect();
    let case = layout_from_netlist(
        &NetlistSpec { nets, devices },
        Floorplan::default(),
        strings,
    );
    let mut extracted = NetTable::default();
    gpurify::check::topology::extract_nets_into(&case.store, &case.connectivity, &mut extracted);
    // Every column shares one marker layer, so one recogniser per terminal
    // layer list; each device then takes its spec's kind and model back.
    let full = &case.recognition;
    let mut recognition = DeviceRecognition {
        terminal_start: vec![0],
        ..DeviceRecognition::default()
    };
    for row in 0..full.kind.len() {
        let terminals = &full.terminal
            [full.terminal_start[row] as usize..full.terminal_start[row + 1] as usize];
        let seen = (0..recognition.kind.len()).any(|kept| {
            recognition.terminal[recognition.terminal_start[kept] as usize
                ..recognition.terminal_start[kept + 1] as usize]
                == *terminals
        });
        if !seen {
            recognition.kind.push(full.kind[row]);
            recognition.marker.push(full.marker[row]);
            recognition.model.push(full.model[row]);
            recognition.terminal.extend_from_slice(terminals);
            recognition
                .terminal_start
                .push(recognition.terminal.len() as u32);
        }
    }
    let mut devices = DeviceTable::default();
    gpurify::check::topology::device::recognise_into(
        &case.store,
        &extracted,
        &recognition,
        &mut devices,
    );
    assert_eq!(devices.len(), case.expected_devices.len());
    for (index, expected) in case.expected_devices.iter().enumerate() {
        assert_eq!(devices.marker[index], expected.marker);
        devices.kind[index] = expected.kind;
        devices.model[index] = expected.model;
    }
    Circuit {
        case,
        nets: extracted,
        devices,
        supplies,
    }
}

/// What each rule must find, from the extracted tables alone: `(net,
/// measured)` per finding, nets as extraction numbered them.
struct Expected {
    floating: Vec<(NetId, u32)>,
    esd: Vec<(NetId, u32)>,
    drivers: Vec<(NetId, u32)>,
    tied: Vec<(NetId, u32)>,
    fanout: Vec<(NetId, u32)>,
}

/// The five rules re-derived from their rustdoc over the extracted net graph.
fn search(c: &Circuit, intent: &IntentMap, clamp: StrId) -> Expected {
    let nets = c.nets.net_count();
    let devices: Vec<(StrId, Vec<(NetId, TerminalRole)>)> = (0..c.devices.len())
        .map(|d| {
            let (on, roles) = c.devices.terminals_of(DeviceId(d as u32));
            let terminals = on.iter().copied().zip(roles.iter().copied()).collect();
            (c.devices.model[d], terminals)
        })
        .collect();
    let rail = |n: NetId| intent.supply_net.contains(&n);
    let role_of = |n: NetId| {
        let row = intent.supply_net.iter().position(|&s| s == n)?;
        Some(intent.supply_role[row])
    };
    let all = || (0..nets as u32).map(NetId);

    // floating_gate: every terminal on the net is a gate, and there is one.
    let floating = all()
        .filter(|&n| {
            let mut roles = devices
                .iter()
                .flat_map(|d| &d.1)
                .filter(|t| t.0 == n)
                .map(|t| t.1);
            let first = roles.next();
            first == Some(TerminalRole::Gate) && roles.all(|r| r == TerminalRole::Gate)
        })
        .map(|n| (n, 0))
        .collect();

    // esd_topological, every net a pad: from the pad, through any terminal of
    // a clamp; onward only from a supply.
    let esd = all()
        .filter_map(|pad| {
            let mut seen = vec![false; nets];
            let mut queue = std::collections::VecDeque::from([pad]);
            seen[pad.0 as usize] = true;
            let (mut power, mut ground) = (false, false);
            while let Some(net) = queue.pop_front() {
                match role_of(net) {
                    Some(SupplyRole::Power) => power = true,
                    Some(SupplyRole::Ground) => ground = true,
                    None if net != pad => continue,
                    None => {}
                }
                for d in devices.iter().filter(|d| d.0 == clamp) {
                    if !d.1.iter().any(|t| t.0 == net) {
                        continue;
                    }
                    for t in &d.1 {
                        if !seen[t.0 .0 as usize] {
                            seen[t.0 .0 as usize] = true;
                            queue.push_back(t.0);
                        }
                    }
                }
            }
            let rails = u32::from(power) + u32::from(ground);
            (rails < 2).then_some((pad, rails))
        })
        .collect();

    // multiple_drivers: a transistor with either channel end on a net that is
    // not a rail pulls it when a search from its other end, through every
    // transistor with a channel end on the nets reached, stopping at rails and
    // never back through the net, reaches a rail; its network's gates join
    // drivers that share one.
    let channels: Vec<(NetId, [NetId; 2])> = devices
        .iter()
        .filter_map(|d| {
            let end = |role| d.1.iter().find(|t| t.1 == role).map(|t| t.0);
            Some((
                end(TerminalRole::Gate)?,
                [end(TerminalRole::Source)?, end(TerminalRole::Drain)?],
            ))
        })
        .collect();
    let far = |ends: [NetId; 2], n: NetId| if ends[0] == n { ends[1] } else { ends[0] };
    let drivers = all()
        .filter(|&n| !rail(n))
        .filter_map(|n| {
            let gates: Vec<Vec<NetId>> = channels
                .iter()
                .filter(|c| c.1.contains(&n))
                .filter_map(|&(gate, ends)| {
                    let (mut gates, mut seen, mut reached) = (vec![gate], vec![false; nets], false);
                    let mut queue = std::collections::VecDeque::from([far(ends, n)]);
                    while let Some(at) = queue.pop_front() {
                        if at == n || seen[at.0 as usize] {
                            continue;
                        }
                        seen[at.0 as usize] = true;
                        if rail(at) {
                            reached = true;
                            continue;
                        }
                        for &(g, e) in channels.iter().filter(|c| c.1.contains(&at)) {
                            gates.push(g);
                            queue.push_back(far(e, at));
                        }
                    }
                    reached.then_some(gates)
                })
                .collect();
            // Drivers: classes of networks under "shares a gate net".
            let mut class: Vec<usize> = (0..gates.len()).collect();
            loop {
                let mut merged = false;
                for i in 0..gates.len() {
                    for j in 0..gates.len() {
                        if class[j] > class[i] && gates[i].iter().any(|g| gates[j].contains(g)) {
                            let (old, new) = (class[j], class[i]);
                            class
                                .iter_mut()
                                .filter(|c| **c == old)
                                .for_each(|c| *c = new);
                            merged = true;
                        }
                    }
                }
                if !merged {
                    break;
                }
            }
            class.sort_unstable();
            class.dedup();
            (class.len() > 1).then_some((n, class.len() as u32))
        })
        .collect();

    // tie_high_low: a rail that reaches a gate.
    let tied = all()
        .filter(|&n| {
            rail(n)
                && devices
                    .iter()
                    .flat_map(|d| &d.1)
                    .any(|t| *t == (n, TerminalRole::Gate))
        })
        .map(|n| (n, 0))
        .collect();

    // fanout, at most one gate: the transistor gate terminals on each net.
    let fanout = all()
        .filter_map(|n| {
            let gates = devices
                .iter()
                .flat_map(|d| &d.1)
                .filter(|t| **t == (n, TerminalRole::Gate))
                .count() as u32;
            (gates > 1).then_some((n, gates))
        })
        .collect();

    Expected {
        floating,
        esd,
        drivers,
        tied,
        fanout,
    }
}

/// The findings of one run as `(net, count)`, sorted; each violation's shape
/// is read back to its net.
fn findings(c: &Circuit, out: &Violations, runs: &[RuleRun]) -> Vec<(NetId, u32)> {
    assert_eq!(runs.len(), 1);
    let mut found: Vec<(NetId, u32)> = (0..out.len())
        .map(|row| {
            let v = out.get(row);
            let Measurement::Count(count) = v.measured else {
                panic!("a topology finding is a count");
            };
            (c.nets.net_of(v.shapes.0), count)
        })
        .collect();
    found.sort_unstable();
    found
}

/// Oracle: a breadth-first search over the extracted net graph. On three
/// hundred generated circuits, each rule finds exactly the nets, with the
/// counts, that [`search`] derives from the rules' rustdoc, every finding at
/// its net's lowest-numbered polygon as laid out.
#[test]
fn topology_rules_agree_with_a_search_of_the_extracted_graph() {
    let mut rng = Rng::new(0xc6_0002);
    let mut nonempty = [0u32; 5];
    for case in 0..300 {
        let mut strings = StrTable::default();
        let c = random_circuit(&mut rng, &mut strings);
        let net = |n: u32| c.nets.net_of(c.case.expected_net_polys[n as usize][0]);
        let supplies: Vec<(NetId, SupplyRole)> =
            c.supplies.iter().map(|&(n, role)| (net(n), role)).collect();
        let intent = intent_of(&supplies, &[]);
        let clamp = strings.intern("clamp");
        let id = strings.intern("rule");
        let design = Design {
            store: &c.case.store,
            nets: &c.nets,
            devices: &c.devices,
        };
        let mut facts = NetFacts::default();
        classify_nets_into(&c.nets, &c.devices, &mut facts);
        let want = search(&c, &intent, clamp);

        let runs_of = |run: &mut dyn FnMut(&mut Violations, &mut Vec<RuleRun>)| {
            let (mut out, mut runs) = (Violations::default(), Vec::new());
            run(&mut out, &mut runs);
            for row in 0..out.len() {
                let v = out.get(row);
                let n = c.nets.net_of(v.shapes.0);
                let lowest = (0..c.case.expected_net_polys.len())
                    .find(|&k| net(k as u32) == n)
                    .map(|k| c.case.expected_net_polys[k][0]);
                assert_eq!(
                    Some(v.shapes.0),
                    lowest,
                    "case {case}: a finding off its net's lowest polygon"
                );
            }
            findings(&c, &out, &runs)
        };
        let floating = runs_of(&mut |out, runs| {
            check_floating_gate(
                design,
                &facts,
                &PortTable::default(),
                &FloatingGateTable {
                    head: head(id),
                    labels_are_ports: vec![false],
                },
                out,
                runs,
            );
        });
        let esd = runs_of(&mut |out, runs| {
            check_esd_topological(
                design,
                &intent,
                &EsdTopologicalTable {
                    head: head(id),
                    pad: vec![c.case.layers.rail],
                    clamp_start: vec![0, 1],
                    clamp: vec![clamp],
                },
                out,
                runs,
            );
        });
        let drivers = runs_of(&mut |out, runs| {
            check_multiple_drivers(
                design,
                &intent,
                &MultipleDriversTable {
                    head: head(id),
                    max_drivers: vec![1],
                },
                &mut Scratch::default(),
                out,
                runs,
            );
        });
        let tied = runs_of(&mut |out, runs| {
            check_tie_high_low(
                design,
                &facts,
                &intent,
                &TieHighLowTable { head: head(id) },
                out,
                runs,
            );
        });
        let fanout = runs_of(&mut |out, runs| {
            check_fanout(
                design,
                &FanoutTable {
                    head: head(id),
                    max_gates: vec![1],
                },
                out,
                runs,
            );
        });
        for (k, (rule, got, want)) in [
            ("floating_gate", floating, want.floating),
            ("esd_topological", esd, want.esd),
            ("multiple_drivers", drivers, want.drivers),
            ("tie_high_low", tied, want.tied),
            ("fanout", fanout, want.fanout),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(got, want, "case {case}: {rule}");
            nonempty[k] += u32::from(!want.is_empty());
        }
    }
    assert!(
        nonempty.iter().all(|&n| n >= 20),
        "too few circuits with a finding per rule: {nonempty:?}"
    );
}

// ------------------------------------------- voltages reached from the supplies

/// The domain nominals the voltage rules' circuits draw their supplies from,
/// mV: three domains, so a gate and a channel can be reached by different ones.
const NOMINALS: [f64; 3] = [1800.0, 3300.0, 5000.0];

/// A supply as the reference reads it: its net, role and domain index.
type Supply = (NetId, SupplyRole, u32);

/// What `from` can reach, re-derived from `erc::voltage`'s module docs by a
/// breadth-first search from the net itself: a supply sits at its domain's
/// nominal (power) or 0 V (ground) and passes nothing on; any other net
/// reaches, through device channels (a MOS's source and drain, every pin of
/// a diode, never a gate, a bulk or a capacitor), every supply some chain of
/// channels joins it to. `(lowest, highest, power-domain bits)`, or `None`
/// when no supply is reached.
fn reach(c: &Circuit, supplies: &[Supply], from: NetId) -> Option<(f64, f64, u64)> {
    let held = |net: NetId| {
        let &(_, role, domain) = supplies.iter().find(|s| s.0 == net)?;
        Some(match role {
            SupplyRole::Power => (NOMINALS[domain as usize], 1u64 << domain),
            SupplyRole::Ground => (0.0, 0),
        })
    };
    let channel = |device: usize| -> Vec<NetId> {
        let (nets, roles) = c.devices.terminals_of(DeviceId(device as u32));
        nets.iter()
            .zip(roles)
            .filter(|&(&net, &role)| {
                net != NetId::NONE
                    && !matches!(role, TerminalRole::Gate | TerminalRole::Bulk)
                    && c.devices.kind[device] != DeviceKind::Capacitor
            })
            .map(|(&net, _)| net)
            .collect()
    };
    if from == NetId::NONE {
        return None;
    }
    if let Some((volts, power)) = held(from) {
        return Some((volts, volts, power));
    }
    let mut seen = vec![false; c.nets.net_count()];
    seen[from.0 as usize] = true;
    let mut queue = std::collections::VecDeque::from([from]);
    let mut found: Option<(f64, f64, u64)> = None;
    while let Some(net) = queue.pop_front() {
        if let Some((volts, power)) = held(net) {
            found = Some(found.map_or((volts, volts, power), |(lo, hi, mask)| {
                (lo.min(volts), hi.max(volts), mask | power)
            }));
            continue;
        }
        for device in 0..c.devices.len() {
            let ends = channel(device);
            if !ends.contains(&net) {
                continue;
            }
            for next in ends {
                if !seen[next.0 as usize] {
                    seen[next.0 as usize] = true;
                    queue.push_back(next);
                }
            }
        }
    }
    found
}

/// One rule's findings as `(device, measured)` in device order, and how many
/// devices it examined.
type Judged = (Vec<(usize, f64)>, u64);

/// `well_bias` and `missing_level_shifter` re-derived from their rustdoc
/// (`erc::rules::domain`) over [`reach`].
fn bias_and_shifters(
    c: &Circuit,
    supplies: &[Supply],
    (pmos, nmos, shifter): (StrId, StrId, StrId),
) -> [Judged; 2] {
    let (mut bias, mut shifters): (Judged, Judged) = ((Vec::new(), 0), (Vec::new(), 0));
    for device in 0..c.devices.len() {
        let (nets, roles) = c.devices.terminals_of(DeviceId(device as u32));
        let at = |role: TerminalRole| {
            roles
                .iter()
                .position(|&r| r == role)
                .map_or(NetId::NONE, |k| nets[k])
        };
        let of = |role: TerminalRole| reach(c, supplies, at(role));
        let model = c.devices.model[device];
        let ends: Vec<(f64, f64, u64)> = [TerminalRole::Source, TerminalRole::Drain]
            .into_iter()
            .filter_map(&of)
            .collect();
        // well_bias: a pmos end above its bulk's lowest, an nmos end below
        // its bulk's highest; examined when the bulk and an end are reached.
        let biased = (model == pmos || model == nmos) && !ends.is_empty();
        if let Some(bulk) = of(TerminalRole::Bulk).filter(|_| biased) {
            let excess = if model == pmos {
                ends.iter().map(|e| e.1).fold(f64::NEG_INFINITY, f64::max) - bulk.0
            } else {
                bulk.1 - ends.iter().map(|e| e.0).fold(f64::INFINITY, f64::min)
            };
            bias.1 += 1;
            if excess > 0.0 {
                bias.0.push((device, excess));
            }
        }
        // missing_level_shifter: power domains that reach a transistor's
        // gate and neither its source nor its drain; examined when power
        // reaches the gate and the channel.
        if c.devices.kind[device] == DeviceKind::Mos && model != shifter {
            let mask = |role: TerminalRole| of(role).map_or(0, |r| r.2);
            let gate = mask(TerminalRole::Gate);
            let channel = mask(TerminalRole::Source) | mask(TerminalRole::Drain);
            if gate != 0 && channel != 0 {
                shifters.1 += 1;
                let count = (gate & !channel).count_ones();
                if count > 0 {
                    shifters.0.push((device, f64::from(count)));
                }
            }
        }
    }
    [bias, shifters]
}

/// ERC-D3, ERC-F12, ERC-F6: `well_bias` and `missing_level_shifter`, fed by
/// the engine's own propagation (`erc::voltage::propagate_into`: components
/// and folds, not a search), flag exactly the devices, with the measures,
/// that a search derives, and examine as many.
///
/// Oracle: a naive reference over the extracted graph of three hundred
/// generated circuits ([`reach`], a breadth-first search from each net, and
/// [`bias_and_shifters`], the rules' rustdoc), each MOS a `pmos`, an `nmos`
/// or a level shifter at random and each supply in one of three domains at
/// 1.8, 3.3 or 5 V. A supply that propagates onward, a gate or bulk that
/// conducts, or a bias or domain test the wrong way round breaks it.
#[test]
fn voltage_rules_agree_with_a_search_from_each_net() {
    use gpurify::check::erc::rules::domain::{
        check_missing_level_shifter, check_well_bias, MissingLevelShifterTable, WellBiasTable,
    };
    use gpurify::check::erc::voltage::{propagate_into, NetVoltage};

    let mut rng = Rng::new(0x9_1003);
    let mut nonempty = [0u32; 2];
    for case in 0..300 {
        let mut strings = StrTable::default();
        let mut c = random_circuit(&mut rng, &mut strings);
        let models = (
            strings.intern("pmos"),
            strings.intern("nmos"),
            strings.intern("shifter"),
        );
        for device in 0..c.devices.len() {
            if c.devices.kind[device] == DeviceKind::Mos {
                c.devices.model[device] = [models.0, models.1, models.2][rng.below(3) as usize];
            }
        }
        let net = |n: u32| c.nets.net_of(c.case.expected_net_polys[n as usize][0]);
        let mut supplies: Vec<Supply> = c
            .supplies
            .iter()
            .map(|&(n, role)| (net(n), role, rng.below(3) as u32))
            .collect();
        supplies.sort_by_key(|s| s.0);
        let intent = IntentMap {
            declared: true,
            supply_net: supplies.iter().map(|s| s.0).collect(),
            supply_role: supplies.iter().map(|s| s.1).collect(),
            supply_domain: supplies.iter().map(|s| DomainId(s.2)).collect(),
            supply_voltage: supplies
                .iter()
                .map(|s| Qty::new(NOMINALS[s.2 as usize]))
                .collect(),
            limit_net: Vec::new(),
            limit: Vec::new(),
        };
        let id = strings.intern("rule");
        let design = Design {
            store: &c.case.store,
            nets: &c.nets,
            devices: &c.devices,
        };
        let mut voltage = NetVoltage::default();
        propagate_into(&c.nets, &c.devices, &intent, &mut voltage);

        let judged = |run: &mut dyn FnMut(&mut Violations, &mut Vec<RuleRun>)| -> Judged {
            let (mut out, mut runs) = (Violations::default(), Vec::new());
            run(&mut out, &mut runs);
            assert_eq!(runs.len(), 1);
            let mut found: Vec<(usize, f64)> = (0..out.len())
                .map(|row| {
                    let v = out.get(row);
                    let device = c
                        .devices
                        .marker
                        .iter()
                        .position(|&m| m == v.shapes.0)
                        .expect("a finding sits on a device marker");
                    let measured = match v.measured {
                        Measurement::Voltage(q) => q.raw(),
                        Measurement::Count(n) => f64::from(n),
                        other => panic!("case {case}: measured {other:?}"),
                    };
                    (device, measured)
                })
                .collect();
            found.sort_by_key(|f| f.0);
            (found, runs[0].examined)
        };
        let bias = judged(&mut |out, runs| {
            check_well_bias(
                design,
                &intent,
                &voltage,
                &WellBiasTable {
                    head: head(id),
                    pmos_start: vec![0, 1],
                    pmos: vec![models.0],
                    nmos_start: vec![0, 1],
                    nmos: vec![models.1],
                },
                out,
                runs,
            );
        });
        let shifters = judged(&mut |out, runs| {
            check_missing_level_shifter(
                design,
                &intent,
                &voltage,
                &MissingLevelShifterTable {
                    head: head(id),
                    shifter_start: vec![0, 1],
                    shifter: vec![models.2],
                },
                out,
                runs,
            );
        });
        let want = bias_and_shifters(&c, &supplies, models);
        for (k, (rule, got, want)) in [
            ("well_bias", bias, &want[0]),
            ("missing_level_shifter", shifters, &want[1]),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(got.1, want.1, "case {case}: {rule} examined");
            let same = got.0.len() == want.0.len()
                && got
                    .0
                    .iter()
                    .zip(&want.0)
                    .all(|(g, w)| g.0 == w.0 && (g.1 - w.1).abs() <= 1e-9);
            assert!(
                same,
                "case {case}: {rule} found {:?}, want {:?}",
                got.0, want.0
            );
            nonempty[k] += u32::from(!want.0.is_empty());
        }
    }
    assert!(
        nonempty.iter().all(|&n| n >= 10),
        "too few circuits with a finding per rule: {nonempty:?}"
    );
}

// ---------------------------------------------- conditional propagation

/// One net's reach: `(lo, hi, nominal_lo, nominal_hi, power)`, `None` when no
/// supply reaches it.
type Reach = Option<(f64, f64, f64, f64, u64)>;

fn union(a: Reach, b: Reach) -> Reach {
    match (a, b) {
        (Some(a), Some(b)) => Some((
            a.0.min(b.0),
            a.1.max(b.1),
            a.2.min(b.2),
            a.3.max(b.3),
            a.4 | b.4,
        )),
        (a, None) => a,
        (None, b) => b,
    }
}

/// The propagation of `erc::voltage`'s rustdoc by brute force, sharing no
/// code with it: supplies fixed at their voltage (0 V for a ground); every
/// conducting device widens each of its channel nets (every terminal but a
/// gate or bulk; a capacitor has none) that is not a supply to the union of
/// all of them, swept over every device until nothing changes. A MOS with a
/// gate condition conducts when its gate's range reaches it, or when its
/// gate is free: unreached even with every channel conducting, or still
/// unreached after a sweep. Returns the reach with conditions and the reach
/// with every channel conducting.
fn naive_propagation(c: &Circuit, intent: &IntentMap) -> (Vec<Reach>, Vec<Reach>) {
    let count = c.nets.net_count();
    let supply = |n: usize| intent.supply_net.iter().position(|s| s.idx() == n);
    let seed: Vec<Reach> = (0..count)
        .map(|n| {
            supply(n).map(|row| {
                let nominal = intent.supply_voltage[row].raw();
                match intent.supply_role[row] {
                    SupplyRole::Power => (
                        nominal,
                        nominal,
                        nominal,
                        nominal,
                        1u64 << intent.supply_domain[row].0,
                    ),
                    SupplyRole::Ground => (0.0, 0.0, nominal, nominal, 0),
                }
            })
        })
        .collect();
    let devices = c.devices.len();
    let terminals: Vec<Vec<(usize, TerminalRole)>> = (0..devices)
        .map(|d| {
            let (on, roles) = c.devices.terminals_of(DeviceId(d as u32));
            on.iter()
                .map(|n| n.idx())
                .zip(roles.iter().copied())
                .collect()
        })
        .collect();
    let gate = |d: usize| {
        terminals[d]
            .iter()
            .find(|t| t.1 == TerminalRole::Gate)
            .map(|t| t.0)
    };
    let condition = |d: usize| {
        let value = c.devices.value[d];
        if c.devices.kind[d] != DeviceKind::Mos {
            return None;
        }
        match (value.on_gate_min_mv, value.on_gate_max_mv) {
            (Some(v), _) => Some((true, v)),
            (None, Some(v)) => Some((false, v)),
            (None, None) => None,
        }
    };
    let sweep = |free: &[bool]| -> Vec<Reach> {
        let mut r = seed.clone();
        loop {
            let mut changed = false;
            for d in 0..devices {
                let on = match condition(d) {
                    None => true,
                    Some(_) if free[d] => true,
                    Some((at_least, v)) => gate(d).and_then(|g| r[g]).is_some_and(|g| {
                        if at_least {
                            g.1 >= v
                        } else {
                            g.0 <= v
                        }
                    }),
                };
                if !on {
                    continue;
                }
                let kind = c.devices.kind[d];
                let channel: Vec<usize> = terminals[d]
                    .iter()
                    .filter(|t| {
                        !matches!(t.1, TerminalRole::Gate | TerminalRole::Bulk)
                            && kind != DeviceKind::Capacitor
                    })
                    .map(|t| t.0)
                    .collect();
                let all = channel.iter().fold(None, |acc, &n| union(acc, r[n]));
                for &n in &channel {
                    let widened = union(r[n], all);
                    if supply(n).is_none() && widened != r[n] {
                        r[n] = widened;
                        changed = true;
                    }
                }
            }
            if !changed {
                return r;
            }
        }
    };
    let everything = sweep(&vec![true; devices]);
    let mut free: Vec<bool> = (0..devices)
        .map(|d| gate(d).is_none_or(|g| everything[g].is_none()))
        .collect();
    loop {
        let r = sweep(&free);
        let floating: Vec<usize> = (0..devices)
            .filter(|&d| condition(d).is_some() && !free[d])
            .filter(|&d| gate(d).is_none_or(|g| r[g].is_none()))
            .collect();
        if floating.is_empty() {
            return (r, everything);
        }
        for d in floating {
            free[d] = true;
        }
    }
}

/// Oracle: a naive sweep of the propagation rules (NV, [`naive_propagation`]).
/// On two hundred generated circuits, extracted, with a random gate
/// condition (`on_gate_min`, `on_gate_max` or none, at 0, 0.9, 1.8 or 3.3 V)
/// on each transistor and the supplies spread over three domains at 1.8,
/// 3.3 and 0.9 V, every net's propagated range, domain nominals and power
/// mask equal the sweep's. In at least twenty circuits the conditions change
/// some net's reach, so a propagation that ignores them fails.
#[test]
fn voltage_propagation_agrees_with_a_naive_sweep_of_the_extracted_graph() {
    let mut rng = Rng::new(0xf1_0001);
    let volts = [1800.0, 3300.0, 900.0];
    let mut conditioned = 0;
    for case in 0..200 {
        let mut strings = StrTable::default();
        let mut c = random_circuit(&mut rng, &mut strings);
        let devices = c.devices.len();
        c.devices.value.resize(devices, DeviceValue::default());
        for d in 0..devices {
            if c.devices.kind[d] != DeviceKind::Mos {
                continue;
            }
            let at = [0.0, 900.0, 1800.0, 3300.0][rng.below(4) as usize];
            c.devices.value[d] = match rng.below(3) {
                0 => DeviceValue::default(),
                1 => DeviceValue {
                    on_gate_min_mv: Some(at),
                    ..DeviceValue::default()
                },
                _ => DeviceValue {
                    on_gate_max_mv: Some(at),
                    ..DeviceValue::default()
                },
            };
        }
        let mut rows: Vec<(NetId, SupplyRole, u32)> = c
            .supplies
            .iter()
            .map(|&(n, role)| {
                let net = c.nets.net_of(c.case.expected_net_polys[n as usize][0]);
                (net, role, rng.below(3) as u32)
            })
            .collect();
        rows.sort_by_key(|row| row.0);
        let intent = IntentMap {
            declared: true,
            supply_net: rows.iter().map(|row| row.0).collect(),
            supply_role: rows.iter().map(|row| row.1).collect(),
            supply_domain: rows.iter().map(|row| DomainId(row.2)).collect(),
            supply_voltage: rows
                .iter()
                .map(|row| Qty::new(volts[row.2 as usize]))
                .collect(),
            limit_net: Vec::new(),
            limit: Vec::new(),
        };
        let mut got = NetVoltage::default();
        propagate_into(&c.nets, &c.devices, &intent, &mut got);
        let (want, everything) = naive_propagation(&c, &intent);
        for (n, want) in want.iter().enumerate() {
            let have = got.known(NetId(n as u32)).then(|| {
                (
                    got.lo[n],
                    got.hi[n],
                    got.nominal_lo[n],
                    got.nominal_hi[n],
                    got.power[n],
                )
            });
            assert_eq!(have, *want, "case {case}: net {n}");
        }
        conditioned += u32::from(want != everything);
    }
    assert!(
        conditioned >= 20,
        "only {conditioned} circuits where a gate condition changed a reach"
    );
}
