//! The field-solve shim: the matrix read out as a [`ParasiticNetwork`].
//!
//! The solver itself — mesh, matvec, GMRES, the capacitance matrix's own laws —
//! is tested in `crates/quasistatic/tests`. What is tested *here* is the one
//! thing `pex` adds on top: `extract_into`'s network assembly, and that the
//! matrix and the network stay two views of one deterministic result.

use crate::common;

use common::{extracted, grid, serialise, serialise_matrix, uniform_stack};
use gpurify_extract::network::ParasiticNetwork;
#[cfg(feature = "gpu")]
use gpurify_extract::quasistatic::gpu::Device;
use gpurify_extract::quasistatic::matvec::Backend;
use gpurify_extract::quasistatic::{extract_into, solve, CapMatrix};
use gpurify_testgen::{assert_bytes_identical, assert_close, Rng};

/// Oracle: law, plus `docs/GPU.md` contract items 4 and 5. A field solve on
/// generated geometry has no closed form, so what is asserted is what
/// reciprocity guarantees for any geometry: the matrix is square at the
/// selected net count, symmetric, diagonally dominant with non-positive
/// off-diagonals, and non-negative in energy. The achieved residual must meet
/// the tolerance that was asked for, measured rather than assumed, and where no
/// device is present the backend must say the host ran it.
///
/// The asymmetry tolerance is stated: reciprocity is exact, so the only
/// asymmetry a converged solve may show is discretisation and round-off. A
/// transposed index or an assembly that fills one triangle produces an
/// asymmetry of order one, four orders above the bound here.
#[test]
fn a_field_solve_obeys_reciprocity_and_reports_the_backend_that_ran_it() {
    let case = extracted(73, 24, 2);
    let options = solve::Options {
        tolerance: 1e-10,
        restart: 30,
        // The documented default. It was 400, which is enough for the host
        // adapter — one refinement pass, because `refine` asks an `f64` operator
        // for the full tolerance — and is not enough for the device one, which
        // reaches the same `1e-10` in about 440 across a dozen `f32` passes.
        // Needing more iterations for cheaper iterations is what mixed-precision
        // refinement *is*, so this widens a budget rather than weakening a
        // claim: the tolerance, the reciprocity check and the byte-identity
        // check below are all untouched.
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

    for i in 0..matrix.dim() {
        let mut off_diagonal = 0.0;
        for j in 0..matrix.dim() {
            if i == j {
                continue;
            }
            assert!(
                matrix.get(i, j) <= 0.0,
                "off-diagonal ({i}, {j}) is {}, and coupling terms are non-positive",
                matrix.get(i, j)
            );
            off_diagonal += matrix.get(i, j).abs();
        }
        assert!(
            matrix.get(i, i) >= off_diagonal,
            "row {i} has a diagonal of {} against {off_diagonal} off it",
            matrix.get(i, i)
        );
    }

    let mut rng = Rng::new(73);
    for _ in 0..32 {
        let v: Vec<f64> = (0..matrix.dim()).map(|_| rng.unit() * 4.0 - 2.0).collect();
        let energy = matrix.energy(&v);
        assert!(
            energy >= 0.0,
            "the solved matrix stored {energy} J at {v:?}"
        );
    }

    // With `gpu` compiled out there is no device to probe and the host is the
    // only backend there is, so the fallback claim is unconditional. With it
    // on, it only has to hold when probing finds nothing.
    #[cfg(feature = "gpu")]
    let no_device = Device::find()
        .expect("probing for a device is not itself a failure")
        .is_none();
    #[cfg(not(feature = "gpu"))]
    let no_device = true;

    if no_device {
        assert_eq!(
            accuracy.backend,
            Backend::Cpu,
            "no device is present, so the solve must report the fallback it took"
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
        // The documented default. It was 400, which is enough for the host
        // adapter — one refinement pass, because `refine` asks an `f64` operator
        // for the full tolerance — and is not enough for the device one, which
        // reaches the same `1e-10` in about 440 across a dozen `f32` passes.
        // Needing more iterations for cheaper iterations is what mixed-precision
        // refinement *is*, so this widens a budget rather than weakening a
        // claim: the tolerance, the reciprocity check and the byte-identity
        // check below are all untouched.
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
