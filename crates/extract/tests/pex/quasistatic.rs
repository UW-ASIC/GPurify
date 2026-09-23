//! The field-solve shim: the matrix read out as a [`ParasiticNetwork`].
//!
//! The solver itself is tested in `tests/field`. Here: `extract_into`'s network
//! assembly, and that matrix and network stay two views of one deterministic result.

use crate::common;

use common::{extracted, grid, serialise, serialise_matrix, uniform_stack};
use gpurify_check::topology::NetId;
use gpurify_extract::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_extract::quasistatic::{extract_into, overlay, solve, CapMatrix};
use gpurify_geom::{LayerId, Qty};
use gpurify_testgen::{assert_bytes_identical, assert_close, Rng};

/// Oracle: law. A field solve on
/// generated geometry has no closed form, so what is asserted is what
/// reciprocity guarantees for any geometry: the matrix is square at the
/// selected net count, symmetric, diagonally dominant with non-positive
/// off-diagonals, and non-negative in energy. The achieved residual must meet
/// the tolerance that was asked for, measured rather than assumed.
///
/// The asymmetry tolerance is stated: reciprocity is exact, so the only
/// asymmetry a converged solve may show is discretisation and round-off. A
/// transposed index or an assembly that fills one triangle produces an
/// asymmetry of order one, four orders above the bound here.
#[test]
fn a_field_solve_obeys_reciprocity() {
    let case = extracted(73, 24, 2);
    let mut matrix = CapMatrix::default();
    let mut network = ParasiticNetwork::default();
    let accuracy = extract_into(
        case.store(),
        &case.nets,
        &case.selected,
        &uniform_stack(3, 1.0, 0.25),
        grid(),
        &mut matrix,
        &mut network,
    )
    .expect("a two-conductor solve converges inside four hundred iterations");

    assert_eq!(
        matrix.dim(),
        case.selected.len(),
        "one row and one column per selected net"
    );
    assert_close(
        "the tolerance travels with the result",
        accuracy.tolerance,
        solve::Options::default().tolerance,
        0.0,
    );
    assert!(
        accuracy.iterations > 0,
        "a converged solve took no iterations"
    );

    assert!(
        matrix.asymmetry() < 1e-4,
        "reciprocity is exact; the solve is off by {} relative",
        matrix.asymmetry()
    );
    assert_close(
        "the reported asymmetry against the matrix it describes",
        accuracy.asymmetry,
        matrix.asymmetry(),
        1e-12,
    );

    let n = matrix.dim();
    let at = |i: usize, j: usize| matrix.value[i * n + j];
    for i in 0..n {
        let mut off_diagonal = 0.0;
        for j in 0..n {
            if i == j {
                continue;
            }
            assert!(
                at(i, j) <= 0.0,
                "off-diagonal ({i}, {j}) is {}, and coupling terms are non-positive",
                at(i, j)
            );
            off_diagonal += at(i, j).abs();
        }
        assert!(
            at(i, i) >= off_diagonal,
            "row {i} has a diagonal of {} against {off_diagonal} off it",
            at(i, i)
        );
    }

    let mut rng = Rng::new(73);
    for _ in 0..32 {
        let v: Vec<f64> = (0..matrix.dim()).map(|_| rng.unit() * 4.0 - 2.0).collect();
        // Energy ½ VᵀCV, strict ascending folds.
        let mut energy = 0.0_f64;
        for i in 0..n {
            let flux: f64 = (0..n).map(|j| at(i, j) * v[j]).sum();
            energy += v[i] * flux;
        }
        assert!(
            energy >= 0.0,
            "the solved matrix stored {energy} J at {v:?}"
        );
    }

    assert!(
        network.element_count() > 0,
        "a field solve produced a matrix but no network"
    );
}

/// Oracle: determinism. The matrix is assembled in ascending net order from
/// geometry alone, so two solves of one corpus give the same bits — in the
/// matrix and in the network both. This is the gate the old tree failed.
#[test]
fn a_field_solve_is_byte_identical_across_runs() {
    let case = extracted(79, 24, 2);
    let stack = uniform_stack(3, 1.0, 0.25);

    let run = |matrix: &mut CapMatrix, network: &mut ParasiticNetwork| {
        extract_into(
            case.store(),
            &case.nets,
            &case.selected,
            &stack,
            grid(),
            matrix,
            network,
        )
        .expect("a two-conductor solve converges inside four hundred iterations")
    };

    let (mut first_matrix, mut first_network) = (CapMatrix::default(), ParasiticNetwork::default());
    let first = run(&mut first_matrix, &mut first_network);
    let (mut second_matrix, mut second_network) =
        (CapMatrix::default(), ParasiticNetwork::default());
    let second = run(&mut second_matrix, &mut second_network);

    assert_bytes_identical(
        "two solves of one corpus, matrix",
        &serialise_matrix(&first_matrix),
        &serialise_matrix(&second_matrix),
    );
    assert_bytes_identical(
        "two solves of one corpus, network",
        &serialise(&first_network),
        &serialise(&second_network),
    );
    assert_eq!(
        first, second,
        "two solves of one corpus reported different accuracies"
    );
}

/// Oracle: construct-from-answer. Net 0 has two analytical nodes, net 1 one, net 2
/// one. Net 1 is solved; its analytical couplings to nets 0 (lower id) and 2
/// (higher id) must both survive on net 1's solved node, while its own ground
/// row goes and the solved rows come in.
#[test]
fn an_overlay_keeps_analytical_coupling_to_unsolved_neighbours_on_either_side() {
    let ground = |ff: f64| Parasitic::GroundCap(Qty::new(ff));
    let coupling = |ff: f64| Parasitic::CouplingCap(Qty::new(ff));
    let mut network = ParasiticNetwork {
        node_net: vec![NetId(0), NetId(0), NetId(1), NetId(2)],
        node_layer: vec![LayerId(0); 4],
        ..ParasiticNetwork::default()
    };
    network.push(NodeId(0), None, ground(1.0));
    network.push(
        NodeId(0),
        Some(NodeId(1)),
        Parasitic::Resistance(Qty::new(10.0)),
    );
    network.push(NodeId(1), Some(NodeId(2)), coupling(0.5));
    network.push(NodeId(2), None, ground(7.0));
    network.push(NodeId(2), Some(NodeId(3)), coupling(0.25));
    network.push(NodeId(3), None, ground(3.0));

    // Net 1 solved into two nodes (as with inductance): anchor and far node.
    let mut solved = ParasiticNetwork {
        node_net: vec![NetId(1), NetId(1)],
        node_layer: vec![LayerId(0); 2],
        ..ParasiticNetwork::default()
    };
    solved.push(NodeId(0), None, ground(2.0));
    solved.push(
        NodeId(0),
        Some(NodeId(1)),
        Parasitic::Inductance(Qty::new(4.0)),
    );

    overlay(&mut network, &solved);

    assert_eq!(
        network.node_net,
        vec![NetId(0), NetId(0), NetId(1), NetId(1), NetId(2)]
    );
    let nodes = u32::try_from(network.node_count()).expect("small");
    assert!(
        network
            .from
            .iter()
            .chain(network.to.iter().flatten())
            .all(|n| n.0 < nodes),
        "an element points past the node columns"
    );
    assert_eq!(
        network.element_count(),
        7,
        "one ground row replaced, none lost"
    );
    assert!(network.from.is_sorted(), "canonical order");
    let total = network.capacitance_per_net();
    assert_close("net 0", total[0], 1.5, 1e-12);
    assert_close(
        "net 1: solved ground plus both couplings",
        total[1],
        2.75,
        1e-12,
    );
    assert_close("net 2", total[2], 3.25, 1e-12);
    let couplings: Vec<_> = (0..network.element_count())
        .filter(|&row| matches!(network.value[row], Parasitic::CouplingCap(_)))
        .map(|row| (network.from[row], network.to[row]))
        .collect();
    assert_eq!(
        couplings,
        vec![(NodeId(1), Some(NodeId(2))), (NodeId(2), Some(NodeId(4)))],
        "both couplings land on net 1's anchor node"
    );
}

/// Oracle: law. Field-solving one of two analytically coupled nets, either one,
/// keeps every node in range and keeps the analytical coupling to the other.
#[test]
fn field_solving_one_of_two_coupled_nets_keeps_their_coupling() {
    let case = extracted(73, 24, 2);
    let stack = uniform_stack(3, 1.0, 0.25);
    let analytical = || {
        let mut out = ParasiticNetwork::default();
        gpurify_extract::analytical::extract_into(
            case.store(),
            &case.nets,
            case.connectivity(),
            &stack,
            grid(),
            &mut out,
        );
        out
    };
    let coarse = analytical();
    let coupled: f64 = (0..coarse.element_count())
        .filter_map(|row| match coarse.value[row] {
            Parasitic::CouplingCap(q) => Some(q.raw()),
            _ => None,
        })
        .sum();
    assert!(
        coupled > 0.0,
        "the corpus must couple its two nets analytically"
    );

    for &net in &case.selected {
        let mut matrix = CapMatrix::default();
        let mut solved = ParasiticNetwork::default();
        extract_into(
            case.store(),
            &case.nets,
            &[net],
            &stack,
            grid(),
            &mut matrix,
            &mut solved,
        )
        .expect("a one-conductor solve converges");
        let mut network = analytical();
        overlay(&mut network, &solved);

        let nodes = u32::try_from(network.node_count()).expect("small");
        assert!(
            network
                .from
                .iter()
                .chain(network.to.iter().flatten())
                .all(|n| n.0 < nodes),
            "net {}: an element points past the node columns",
            net.0
        );
        let kept: f64 = (0..network.element_count())
            .filter_map(|row| match network.value[row] {
                Parasitic::CouplingCap(q) => Some(q.raw()),
                _ => None,
            })
            .sum();
        assert_close("analytical coupling kept", kept, coupled, 1e-12);
    }
}
