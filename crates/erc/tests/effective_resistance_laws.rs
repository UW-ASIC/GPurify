//! Effective resistance, against its closed forms and against its laws.
//!
//! Effective resistance is a metric on the nodes of a resistive network. That
//! is not decoration: it means the answer obeys the triangle inequality and
//! Rayleigh monotonicity for *any* network, which makes those two the strongest
//! tests available here and the two that a path length or a sum of squares
//! cannot pass. `crates/erc/src/power.rs` names both properties in its own doc
//! comment, and this file is where that claim is cashed.

mod common;

use common::{one_row_network, probe_of};
use gpurify_erc::power::{self, NetNetworks, SolveScratch};
use gpurify_testgen::{assert_close, assert_close_relative, ladder_network, Rng};
use gpurify_topology::NetId;
use gpurify_units::{prefix, Qty, Resistance};

type Probe = (u32, u32, Qty<Resistance, { prefix::BASE }>);

/// Probe every terminal pair of a one-row network.
fn probe(networks: &NetNetworks) -> Vec<Probe> {
    let mut scratch = SolveScratch::default();
    let mut out = Vec::new();
    power::effective_resistance_into(networks, 0, &mut scratch, &mut out)
        .expect("every resistance in these networks is positive and finite");
    out
}

/// A connected network of arbitrary shape: a spanning path with random
/// resistances, `chords` extra edges, and three terminals spread along it.
fn random_network(seed: u64, nodes: u32, chords: u32) -> NetNetworks {
    assert!(nodes >= 3, "three terminals need at least three nodes");
    let mut rng = Rng::new(seed);
    let mut edges: Vec<(u32, u32, f64)> = (0..nodes - 1)
        .map(|node| (node, node + 1, 0.5 + 9.5 * rng.unit()))
        .collect();
    for _ in 0..chords {
        let from = u32::try_from(rng.below(u64::from(nodes))).expect("bounded by nodes");
        let to = u32::try_from(rng.below(u64::from(nodes))).expect("bounded by nodes");
        if from != to {
            edges.push((from, to, 0.5 + 9.5 * rng.unit()));
        }
    }
    one_row_network(nodes, &[0, nodes / 2, nodes - 1], &edges)
}

/// Oracle: closed form. One resistor between two terminals is that resistor.
/// Trivial, and it is here because it fixes the unit: the reported number is in
/// ohms, at `prefix::BASE`, and nothing rescales it on the way out.
#[test]
fn a_single_edge_reports_its_own_resistance() {
    let networks = one_row_network(2, &[0, 1], &[(0, 1, 47.0)]);
    let probes = probe(&networks);
    assert_eq!(probes.len(), 1, "two terminals make exactly one pair");
    assert_eq!(probes[0].0, 0);
    assert_eq!(probes[0].1, 1);
    assert_close_relative("a lone resistor", probes[0].2.raw(), 47.0, 1e-9);
}

/// Oracle: closed form. `gpurify_testgen::ladder_network` states its own
/// answer: a stage is one series resistor and a parallel pair, so `rungs`
/// stages are `rungs * (series + parallel / 2)`. Its interior nodes are not
/// terminals, so an implementation Kron-eliminating them must land on the same
/// number — which is the invariance `power::effective_resistance_into` claims.
#[test]
fn a_resistor_ladder_matches_its_series_parallel_closed_form() {
    for rungs in [1u32, 2, 7] {
        let case = ladder_network(rungs, 1.5, 3.0);
        let probes = probe(&case.networks);
        let measured = probe_of(&probes, case.terminals.0, case.terminals.1);
        assert_close_relative(
            &format!("a {rungs}-stage ladder"),
            measured.raw(),
            case.expected_ohm,
            1e-9,
        );
    }
}

/// Oracle: closed form. Conductances in parallel add, so `k` identical strands
/// are `R / k`. The strands are a multi-edge between one pair of nodes, which
/// is where a Laplacian built by assignment rather than accumulation keeps one
/// strand and reports `R` — a factor of `k` wrong, in the direction that makes
/// a bad net look good.
#[test]
fn parallel_strands_between_two_terminals_divide_the_resistance() {
    for strands in [1u32, 2, 4, 8] {
        let edges: Vec<(u32, u32, f64)> = (0..strands).map(|_| (0, 1, 8.0)).collect();
        let networks = one_row_network(2, &[0, 1], &edges);
        let probes = probe(&networks);
        assert_close_relative(
            &format!("{strands} parallel strands"),
            probes[0].2.raw(),
            8.0 / f64::from(strands),
            1e-9,
        );
    }
}

/// Oracle: law. Splitting one resistor into two halves in series, through a new
/// interior node, changes no terminal-pair resistance at all. That is exactly
/// the invariance under Kron elimination that lets the implementation reduce
/// the interior before the dense solve, and it holds for any network — so it is
/// checked on a generated one rather than on a fixture.
#[test]
fn subdividing_an_edge_leaves_every_effective_resistance_unchanged() {
    let base = random_network(5, 9, 4);
    let before = probe(&base);

    // Rebuild with edge zero replaced by two halves through a fresh node.
    let nodes = base.node_start[1];
    let mut edges: Vec<(u32, u32, f64)> = (0..base.edge_from.len())
        .map(|e| {
            (
                base.edge_from[e],
                base.edge_to[e],
                base.edge_resistance[e].raw(),
            )
        })
        .collect();
    let (from, to, ohm) = edges.remove(0);
    edges.push((from, nodes, ohm / 2.0));
    edges.push((nodes, to, ohm / 2.0));
    let split = one_row_network(nodes + 1, &[0, nodes / 2, nodes - 1], &edges);
    let after = probe(&split);

    assert_eq!(before.len(), after.len(), "the terminal set did not change");
    for (index, &(a, b, r)) in before.iter().enumerate() {
        assert_eq!((a, b), (after[index].0, after[index].1));
        assert_close_relative(
            &format!("the resistance between terminals {a} and {b}"),
            after[index].2.raw(),
            r.raw(),
            1e-9,
        );
    }
}

/// Oracle: law. Effective resistance is a metric, so it obeys the triangle
/// inequality on every network: no detour through a third terminal is shorter
/// than the direct measurement. A shortest-path or a sum-along-a-route proxy
/// satisfies this by accident; a sum of squares does not, and neither does a
/// solver that mixes up which node it grounded.
#[test]
fn effective_resistance_obeys_the_triangle_inequality() {
    for seed in [1u64, 2, 3, 4] {
        let networks = random_network(seed, 11, 6);
        let probes = probe(&networks);
        let terminals: Vec<u32> = networks.terminal.clone();

        for &a in &terminals {
            for &b in &terminals {
                for &c in &terminals {
                    if a == b || b == c || a == c {
                        continue;
                    }
                    let direct = probe_of(&probes, a, c).raw();
                    let detour = probe_of(&probes, a, b).raw() + probe_of(&probes, b, c).raw();
                    assert!(
                        direct <= detour * (1.0 + 1e-9),
                        "seed {seed}: R({a},{c}) = {direct} exceeds \
                         R({a},{b}) + R({b},{c}) = {detour}"
                    );
                }
            }
        }
    }
}

/// Oracle: law. Rayleigh monotonicity: adding a conductance anywhere in a
/// network cannot raise the effective resistance between any pair of nodes.
/// This is the property a designer relies on when they fix a resistive net by
/// adding metal, and it is the one the old sum-of-squares proxy inverted — the
/// reported number went *up* when the net got better.
#[test]
fn adding_a_conductance_never_raises_any_effective_resistance() {
    for seed in [11u64, 12, 13] {
        let base = random_network(seed, 10, 3);
        let before = probe(&base);

        let mut edges: Vec<(u32, u32, f64)> = (0..base.edge_from.len())
            .map(|e| {
                (
                    base.edge_from[e],
                    base.edge_to[e],
                    base.edge_resistance[e].raw(),
                )
            })
            .collect();
        // A strap straight across the network: the largest conductance a
        // designer could add, and the clearest case of the property.
        edges.push((0, 9, 0.25));
        let strapped = one_row_network(10, &base.terminal.clone(), &edges);
        let after = probe(&strapped);

        for &(a, b, r) in &before {
            let improved = probe_of(&after, a, b).raw();
            assert!(
                improved <= r.raw() * (1.0 + 1e-9),
                "seed {seed}: adding a strap raised R({a},{b}) from {} to {improved}",
                r.raw()
            );
        }
    }
}

/// Oracle: law. Lowering one resistance is the same claim in its other form,
/// and it is worth stating separately because it fails differently: a solver
/// reading conductance where it meant resistance passes the added-edge test and
/// fails this one.
#[test]
fn lowering_one_resistance_never_raises_any_effective_resistance() {
    let base = random_network(21, 8, 3);
    let before = probe(&base);

    let mut edges: Vec<(u32, u32, f64)> = (0..base.edge_from.len())
        .map(|e| {
            (
                base.edge_from[e],
                base.edge_to[e],
                base.edge_resistance[e].raw(),
            )
        })
        .collect();
    edges[2].2 /= 10.0;
    let after = probe(&one_row_network(8, &base.terminal.clone(), &edges));

    for &(a, b, r) in &before {
        let improved = probe_of(&after, a, b).raw();
        assert!(
            improved <= r.raw() * (1.0 + 1e-9),
            "cutting an edge's resistance raised R({a},{b}) from {} to {improved}",
            r.raw()
        );
    }
}

/// Oracle: law. The output is stated as every pair with `a < b`, ascending, and
/// every consumer reads it positionally. So the shape is part of the interface:
/// each pair appears once, in order, with a positive resistance. A duplicated
/// pair would make the worst-pair scan in `check_p2p_resistance` right by
/// accident and a missing one would make it silently incomplete.
#[test]
fn every_terminal_pair_appears_once_ascending_with_a_positive_resistance() {
    let networks = random_network(31, 12, 7);
    let probes = probe(&networks);

    let terminals = networks.terminal.len();
    assert_eq!(
        probes.len(),
        terminals * (terminals - 1) / 2,
        "a connected network has one probe per unordered terminal pair"
    );
    for window in probes.windows(2) {
        assert!(
            (window[0].0, window[0].1) < (window[1].0, window[1].1),
            "probes are not ascending: {:?} then {:?}",
            (window[0].0, window[0].1),
            (window[1].0, window[1].1)
        );
    }
    for &(a, b, r) in &probes {
        assert!(
            a < b,
            "a probe must name its terminals ascending, got ({a},{b})"
        );
        assert!(
            r.raw() > 0.0 && r.raw().is_finite(),
            "R({a},{b}) is {}, which is not a positive finite resistance",
            r.raw()
        );
    }
}

/// Oracle: construct-from-answer. Two halves with no edge between them have no
/// interconnect path, and the documented answer is that the pair is *absent*
/// rather than reported as infinite. An infinity in a report column is a value
/// a reader has to interpret, and it compares below every limit, so it would
/// read as a pass.
#[test]
fn a_terminal_pair_in_another_component_is_absent_rather_than_infinite() {
    // Terminals 0 and 1 are joined; terminal 3 sits in its own component.
    let networks = one_row_network(4, &[0, 1, 3], &[(0, 2, 5.0), (2, 1, 5.0)]);
    let probes = probe(&networks);

    assert_eq!(probes.len(), 1, "only one of the three pairs is connected");
    assert_eq!((probes[0].0, probes[0].1), (0, 1));
    assert_close_relative("the connected pair", probes[0].2.raw(), 10.0, 1e-9);
}

/// Oracle: determinism. The probe is a solve, and the elimination order it uses
/// is chosen by the implementation. Two runs must still agree bit for bit, or
/// the reported resistance of a net depends on nothing a user can see.
#[test]
fn probing_one_network_twice_produces_identical_output() {
    let networks = random_network(41, 14, 9);
    let first = probe(&networks);
    let second = probe(&networks);

    assert_eq!(first.len(), second.len());
    for (a, b) in first.iter().zip(&second) {
        assert_eq!((a.0, a.1), (b.0, b.1));
        assert_eq!(
            a.2.raw().to_bits(),
            b.2.raw().to_bits(),
            "R({},{}) differs between two probes of one network",
            a.0,
            a.1
        );
    }
}

/// Oracle: law. A reused scratch must leave nothing behind, and the caller's
/// output buffer is cleared rather than appended to — both are stated in the
/// transform's doc comment, and both are the kind of thing that only shows up
/// on the second call.
#[test]
fn probing_a_second_network_through_one_scratch_replaces_the_first_answer() {
    let first = one_row_network(2, &[0, 1], &[(0, 1, 100.0)]);
    let second = one_row_network(2, &[0, 1], &[(0, 1, 25.0)]);

    let mut scratch = SolveScratch::default();
    let mut out: Vec<Probe> = Vec::new();
    power::effective_resistance_into(&first, 0, &mut scratch, &mut out).expect("positive");
    power::effective_resistance_into(&second, 0, &mut scratch, &mut out).expect("positive");

    assert_eq!(out.len(), 1, "the second probe did not clear the first");
    assert_close("the second network", out[0].2.raw(), 25.0, 1e-9);
}

/// Oracle: law. The row lookup is the only way into a network, and every caller
/// treats a missing row as "this net has fewer than two terminals, so there is
/// no interconnect to traverse" — `check_reliability` skips the whole probe
/// (`rules/reliability.rs`) and `attach_terminal` collapses the clamp onto
/// terminal 0. A lookup that always answered `None` would therefore disable
/// every per-net probe in the crate and report a clean, fully-populated result,
/// which is the empty-is-indistinguishable-from-passing shape this corpus
/// exists to catch. Both answers are pinned here, and so are both answers of
/// `is_empty`, which has no production caller and was otherwise unreachable.
#[test]
fn a_row_is_found_only_for_a_net_that_has_one() {
    let networks = one_row_network(3, &[0, 2], &[(0, 1, 10.0), (1, 2, 10.0)]);

    assert!(!networks.is_empty(), "one row is not no rows");
    assert_eq!(networks.len(), 1, "one row was built");
    assert_eq!(
        networks.row_of(NetId(0)),
        Some(0),
        "the net the row was built for resolves to it"
    );
    assert_eq!(
        networks.row_of(NetId(7)),
        None,
        "a net with no row is absent, not row 0"
    );

    let none = NetNetworks::default();
    assert!(none.is_empty(), "a default network table holds no rows");
    assert_eq!(none.row_of(NetId(0)), None, "no row is found in an empty table");
}
