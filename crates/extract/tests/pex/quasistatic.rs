//! The field-solve shim: the matrix read out as a [`ParasiticNetwork`].
//!
//! The solver itself is tested in `tests/field`. Here: `extract_into`'s network
//! assembly, and that matrix and network stay two views of one deterministic result.

use crate::common;

use common::{extracted, grid, serialise, serialise_matrix, uniform_stack};
use gpurify_extract::network::ParasiticNetwork;
use gpurify_extract::quasistatic::{extract_into, solve, CapMatrix};
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
    let options = solve::Options {
        tolerance: 1e-10,
        restart: 30,
        max_iterations: 1_000,
    };
    let mut matrix = CapMatrix::default();
    let mut network = ParasiticNetwork::default();
    let accuracy = extract_into(
        case.store(),
        &case.nets,
        &case.selected,
        &uniform_stack(3, 1.0, 0.25),
        grid(),
        options,
        &mut matrix,
        &mut network,
    )
    .expect("a two-conductor solve converges inside four hundred iterations");

    assert_eq!(
        matrix.dim(),
        case.selected.len(),
        "one row and one column per selected net"
    );
    assert!(
        accuracy.residual <= accuracy.tolerance,
        "the solve reported a residual of {} against a tolerance of {}",
        accuracy.residual,
        accuracy.tolerance
    );
    assert_close(
        "the tolerance travels with the result",
        accuracy.tolerance,
        options.tolerance,
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
    let options = solve::Options {
        tolerance: 1e-10,
        restart: 30,
        max_iterations: 1_000,
    };
    let stack = uniform_stack(3, 1.0, 0.25);

    let run = |matrix: &mut CapMatrix, network: &mut ParasiticNetwork| {
        extract_into(
            case.store(),
            &case.nets,
            &case.selected,
            &stack,
            grid(),
            options,
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
