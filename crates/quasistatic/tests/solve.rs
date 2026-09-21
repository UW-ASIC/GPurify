//! GMRES, its residual, and its refusal to return an approximation.
//!
//! The solver takes its operator as a generic parameter, which is the whole
//! reason this file needs no mesh and no physics: a small dense matrix written
//! out here is a legal [`MatVec`], its exact solution is arithmetic, and the
//! solver is exercised independently of everything it normally multiplies.
//!
//! Nothing here consults an implementation for an answer. Either the matrix is
//! small enough to invert on paper, or the right-hand side was formed by
//! applying the operator to a solution chosen first.

use gpurify_quasistatic::matvec::{Backend, MatVec};
use gpurify_quasistatic::solve::{gmres, refine, residual, Options, SolveError, Workspace};
use gpurify_testgen::{assert_close, assert_close_relative, Rng};

/// A dense operator, row-major.
///
/// The reference adapter for these tests: it is `f64` throughout, it allocates
/// nothing in `apply`, and it reports the host, because that is what it is.
struct Dense {
    n: usize,
    a: Vec<f64>,
}

impl Dense {
    fn new(rows: &[&[f64]]) -> Self {
        let n = rows.len();
        let mut a = Vec::with_capacity(n * n);
        for row in rows {
            assert_eq!(row.len(), n, "a dense operator is square");
            a.extend_from_slice(row);
        }
        Self { n, a }
    }

    /// A strictly diagonally dominant symmetric matrix, which is nonsingular
    /// and well enough conditioned that a converged answer is meaningful.
    fn random_dominant(rng: &mut Rng, n: usize) -> Self {
        let mut a = vec![0.0_f64; n * n];
        for i in 0..n {
            for j in (i + 1)..n {
                let off = rng.unit() * 2.0 - 1.0;
                a[i * n + j] = off;
                a[j * n + i] = off;
            }
        }
        for i in 0..n {
            let row: f64 = (0..n).filter(|&j| j != i).map(|j| a[i * n + j].abs()).sum();
            a[i * n + i] = row + 1.0 + rng.unit();
        }
        Self { n, a }
    }

    /// `b` such that this operator maps `x` to it. The construct-from-answer
    /// half: the solution is chosen, then the right-hand side is derived.
    fn rhs_for(&self, x: &[f64]) -> Vec<f64> {
        let mut b = vec![0.0; self.n];
        self.apply(x, &mut b);
        b
    }
}

impl MatVec for Dense {
    fn dim(&self) -> usize {
        self.n
    }

    fn apply(&self, x: &[f64], y: &mut [f64]) {
        assert_eq!(x.len(), self.n, "x is the operator's dimension");
        assert_eq!(y.len(), self.n, "y is the operator's dimension");
        for (i, out) in y.iter_mut().enumerate() {
            *out = (0..self.n).map(|j| self.a[i * self.n + j] * x[j]).sum();
        }
    }

    fn backend(&self) -> Backend {
        Backend::Cpu
    }
}

/// An operator that returns a `NaN` on demand.
///
/// Not a plausible physical operator, and that is the point: `SolveError` names
/// a non-finite value as one of the three things a solve can fail on, so
/// something has to produce one.
struct Poisoned {
    n: usize,
}

impl MatVec for Poisoned {
    fn dim(&self) -> usize {
        self.n
    }

    fn apply(&self, _x: &[f64], y: &mut [f64]) {
        y.fill(f64::NAN);
    }

    fn backend(&self) -> Backend {
        Backend::Cpu
    }
}

fn tight() -> Options {
    Options {
        tolerance: 1e-12,
        restart: 40,
        max_iterations: 400,
    }
}

/// Oracle: closed form. The true relative residual of the exact solution is
/// zero and of a zero guess is one, because the numerator is then the norm of
/// the right-hand side itself. Both are arithmetic over the definition, and
/// neither depends on how a solution was obtained — which is exactly what makes
/// this the check everything else defers to.
#[test]
fn the_residual_of_an_exact_solution_is_zero_and_of_a_zero_guess_is_one() {
    let a = Dense::new(&[&[4.0, 1.0], &[1.0, 3.0]]);
    let x = [2.0, -5.0];
    let b = a.rhs_for(&x);
    let mut scratch = Vec::new();

    assert_close(
        "the residual at the exact solution",
        residual(&a, &b, &x, &mut scratch),
        0.0,
        1e-15,
    );
    assert_close(
        "the residual at the zero guess",
        residual(&a, &b, &[0.0, 0.0], &mut scratch),
        1.0,
        1e-15,
    );
}

/// Oracle: closed form. Scaling a candidate solution away from the answer moves
/// the residual by a known amount: for a linear operator, `A(2x) - b` is `Ax`
/// when `b` is `Ax`, so the residual at twice the solution is exactly one.
#[test]
fn the_residual_is_linear_in_the_error_it_measures() {
    let mut rng = Rng::new(83);
    let a = Dense::random_dominant(&mut rng, 6);
    let x: Vec<f64> = (0..6).map(|_| rng.unit() * 6.0 - 3.0).collect();
    let b = a.rhs_for(&x);
    let mut scratch = Vec::new();

    let doubled: Vec<f64> = x.iter().map(|value| value * 2.0).collect();
    assert_close(
        "the residual at twice the solution",
        residual(&a, &b, &doubled, &mut scratch),
        1.0,
        1e-12,
    );

    let tripled: Vec<f64> = x.iter().map(|value| value * 3.0).collect();
    assert_close(
        "the residual at three times the solution",
        residual(&a, &b, &tripled, &mut scratch),
        2.0,
        1e-12,
    );
}

/// Oracle: closed form. The identity operator maps every vector to itself, so
/// the solution of `I x = b` is `b` and there is nothing to iterate towards.
#[test]
fn the_identity_operator_solves_to_the_right_hand_side_itself() {
    let a = Dense::new(&[&[1.0, 0.0, 0.0], &[0.0, 1.0, 0.0], &[0.0, 0.0, 1.0]]);
    let b = [3.0, -1.0, 0.5];
    let mut x = vec![0.0; 3];
    let mut workspace = Workspace::default();

    let converged =
        gmres(&a, &b, tight(), &mut x, &mut workspace).expect("the identity system converges");
    for (index, (&got, &want)) in x.iter().zip(&b).enumerate() {
        assert_close(&format!("component {index}"), got, want, 1e-12);
    }
    assert!(
        converged.residual <= tight().tolerance,
        "the identity solve reported a residual of {}",
        converged.residual
    );
}

/// Oracle: closed form. A diagonal system decouples completely, so each
/// component of the answer is its own right-hand side over its own diagonal
/// entry — six divisions anyone can do, and no linear algebra at all.
#[test]
fn a_diagonal_system_solves_component_by_component() {
    let diagonal = [0.5, 2.0, 8.0, 100.0, 0.125, 3.0];
    let n = diagonal.len();
    let mut a = vec![0.0; n * n];
    for (i, &d) in diagonal.iter().enumerate() {
        a[i * n + i] = d;
    }
    let operator = Dense { n, a };
    let b = [1.0, -4.0, 16.0, 50.0, 0.25, -9.0];

    let mut x = vec![0.0; n];
    let mut workspace = Workspace::default();
    gmres(&operator, &b, tight(), &mut x, &mut workspace).expect("a diagonal system converges");

    for (index, ((&got, &rhs), &d)) in x.iter().zip(&b).zip(&diagonal).enumerate() {
        assert_close_relative(&format!("component {index}"), got, rhs / d, 1e-10);
    }
}

/// Oracle: construct-from-answer. The solution is chosen first and the
/// right-hand side derived from it, so the answer is known before the solver
/// runs. Stated over generated well-conditioned systems at several sizes: a
/// solver that happens to be right on one matrix is not right.
#[test]
fn gmres_recovers_a_solution_the_right_hand_side_was_built_from() {
    let mut rng = Rng::new(89);
    let mut workspace = Workspace::default();

    for n in [1_usize, 2, 3, 7, 16, 33] {
        let a = Dense::random_dominant(&mut rng, n);
        let expected: Vec<f64> = (0..n).map(|_| rng.unit() * 10.0 - 5.0).collect();
        let b = a.rhs_for(&expected);

        let mut x = vec![0.0; n];
        let converged = gmres(&a, &b, tight(), &mut x, &mut workspace)
            .unwrap_or_else(|error| panic!("a {n} by {n} dominant system failed: {error}"));

        for (index, (&got, &want)) in x.iter().zip(&expected).enumerate() {
            assert_close(
                &format!("component {index} of a {n} by {n} system"),
                got,
                want,
                1e-8,
            );
        }
        assert!(
            converged.iterations > 0 && converged.iterations <= tight().max_iterations,
            "a {n} by {n} system took {} iterations",
            converged.iterations
        );
    }
}

/// Oracle: law. The residual a solve reports is the true one, recomputed
/// explicitly, not the recurrence estimate GMRES carries internally — the doc
/// comment says so, and the old implementation is where the two drifted apart.
/// So handing the returned solution back to `residual` must give the same
/// number, and `residual` knows nothing about how the solution was obtained.
#[test]
fn the_reported_residual_is_the_one_residual_recomputes() {
    let mut rng = Rng::new(97);
    let mut workspace = Workspace::default();
    let mut scratch = Vec::new();

    for n in [4_usize, 11, 25] {
        let a = Dense::random_dominant(&mut rng, n);
        let b: Vec<f64> = (0..n).map(|_| rng.unit() * 2.0 - 1.0).collect();
        let mut x = vec![0.0; n];
        let converged = gmres(&a, &b, tight(), &mut x, &mut workspace)
            .unwrap_or_else(|error| panic!("a {n} by {n} dominant system failed: {error}"));

        assert_close(
            &format!("the reported residual of a {n} by {n} solve"),
            converged.residual,
            residual(&a, &b, &x, &mut scratch),
            1e-14,
        );
    }
}

/// Oracle: law. Exhausting the iteration budget is `NotConverged` carrying the
/// residual actually reached, never a quietly returned approximation. One
/// iteration against a system with several distinct eigenvalues cannot reach a
/// tolerance of `1e-14`, and the error has to say so rather than the solver
/// pretending.
#[test]
fn exhausting_the_iteration_budget_is_an_error_and_not_an_approximation() {
    let a = Dense::new(&[
        &[7.0, 1.0, 0.5, 0.25],
        &[1.0, 5.0, -1.5, 0.75],
        &[0.5, -1.5, 9.0, 2.0],
        &[0.25, 0.75, 2.0, 4.0],
    ]);
    let b = [1.0, -2.0, 3.0, -4.0];
    let options = Options {
        tolerance: 1e-14,
        restart: 1,
        max_iterations: 1,
    };

    let mut x = vec![0.0; 4];
    let mut workspace = Workspace::default();
    let error = gmres(&a, &b, options, &mut x, &mut workspace)
        .expect_err("one iteration cannot reach a tolerance of 1e-14 on this system");

    match error {
        SolveError::NotConverged {
            residual: reached,
            iterations,
        } => {
            assert_eq!(iterations, 1, "the budget was one iteration");
            assert!(
                reached > options.tolerance,
                "a solve that reached {reached} against a tolerance of {} did converge",
                options.tolerance
            );
            assert!(reached.is_finite(), "the reported residual is {reached}");
        }
        other => panic!("expected NotConverged, got {other}"),
    }
}

/// Oracle: law. An operator producing a non-finite value is `NonFinite`, not a
/// `NaN` propagated into the answer. A solve that returns quietly with a `NaN`
/// in it is the fail-open mode this project treats as a defect: every
/// comparison against that number afterwards is false, including the ones that
/// would have caught it.
#[test]
fn an_operator_producing_a_non_finite_value_fails_rather_than_returning_one() {
    let a = Poisoned { n: 3 };
    let b = [1.0, 1.0, 1.0];
    let mut x = vec![0.0; 3];
    let mut workspace = Workspace::default();

    let error = gmres(&a, &b, tight(), &mut x, &mut workspace)
        .expect_err("an operator returning NaN cannot produce a solution");
    assert!(
        matches!(error, SolveError::NonFinite(_)),
        "expected NonFinite, got {error}"
    );
}

/// Oracle: construct-from-answer. Refinement is used unconditionally, including
/// with a host adapter where it converges in one outer step, so it must reach
/// the same solution GMRES does on an operator that is already `f64`-exact.
/// Having one code path rather than two is only worth it if the one path is
/// right on both.
#[test]
fn refinement_reaches_the_same_solution_as_a_bare_solve() {
    let mut rng = Rng::new(101);
    let a = Dense::random_dominant(&mut rng, 12);
    let expected: Vec<f64> = (0..12).map(|_| rng.unit() * 8.0 - 4.0).collect();
    let b = a.rhs_for(&expected);
    let mut workspace = Workspace::default();

    let mut plain = vec![0.0; 12];
    gmres(&a, &b, tight(), &mut plain, &mut workspace).expect("the bare solve converges");

    let mut refined = vec![0.0; 12];
    let converged =
        refine(&a, &a, &b, tight(), &mut refined, &mut workspace).expect("refinement converges");

    for (index, ((&r, &p), &want)) in refined.iter().zip(&plain).zip(&expected).enumerate() {
        assert_close(
            &format!("component {index} against the answer"),
            r,
            want,
            1e-8,
        );
        assert_close(
            &format!("component {index} against the bare solve"),
            r,
            p,
            1e-8,
        );
    }
    assert!(
        converged.residual <= tight().tolerance,
        "refinement reported a residual of {}",
        converged.residual
    );
}

/// Oracle: determinism. Two solves of one system, from one workspace, must give
/// the same bits. Reused scratch is where a solver picks up state from the run
/// before it, and a floating-point answer that drifts by one ulp between runs is
/// the defect this crate is gated on.
#[test]
fn solving_the_same_system_twice_gives_bit_identical_answers() {
    let mut rng = Rng::new(103);
    let a = Dense::random_dominant(&mut rng, 20);
    let b: Vec<f64> = (0..20).map(|_| rng.unit() * 2.0 - 1.0).collect();
    let mut workspace = Workspace::default();

    let mut first = vec![0.0; 20];
    let first_result = gmres(&a, &b, tight(), &mut first, &mut workspace)
        .expect("a twenty by twenty dominant system converges");

    // A different system in between, so the workspace genuinely carries other
    // state into the repeat rather than being untouched.
    let mut interference = vec![0.0; 20];
    let other = a.rhs_for(&[1.0_f64; 20]);
    gmres(&a, &other, tight(), &mut interference, &mut workspace)
        .expect("the interfering system converges");

    let mut second = vec![0.0; 20];
    let second_result = gmres(&a, &b, tight(), &mut second, &mut workspace)
        .expect("a twenty by twenty dominant system converges");

    for (index, (&x, &y)) in first.iter().zip(&second).enumerate() {
        assert_eq!(
            x.to_bits(),
            y.to_bits(),
            "component {index} differs between runs: {x} against {y}"
        );
    }
    assert_eq!(
        first_result, second_result,
        "two solves of one system reported different convergence"
    );
}

/// Oracle: law. Restarting bounds the Krylov basis and therefore the memory, so
/// a solve restarted every few iterations must reach the same answer as one
/// that never restarts. A restart that lost the current iterate would show up
/// here and nowhere else.
///
/// The iteration count is deliberately not asserted to move. Restarted GMRES
/// generally needs more iterations than the unrestarted solve, but the
/// comparison between two finite restart lengths is not monotone in general, and
/// a test asserting it would be asserting a guess.
#[test]
fn restarting_bounds_the_krylov_basis_without_changing_the_answer() {
    let mut rng = Rng::new(107);
    let a = Dense::random_dominant(&mut rng, 24);
    let expected: Vec<f64> = (0..24).map(|_| rng.unit() * 4.0 - 2.0).collect();
    let b = a.rhs_for(&expected);
    let mut workspace = Workspace::default();

    for restart in [3_u32, 8, 24, 100] {
        let mut x = vec![0.0; 24];
        let converged = gmres(
            &a,
            &b,
            Options {
                tolerance: 1e-11,
                restart,
                max_iterations: 2_000,
            },
            &mut x,
            &mut workspace,
        )
        .unwrap_or_else(|error| panic!("restarting every {restart} iterations failed: {error}"));

        for (index, (&got, &want)) in x.iter().zip(&expected).enumerate() {
            assert_close(
                &format!("component {index} restarting every {restart}"),
                got,
                want,
                1e-7,
            );
        }
        assert!(
            converged.residual <= 1e-11,
            "restarting every {restart} reached {}",
            converged.residual
        );
    }
}

/// Oracle: law. The default options have to be internally coherent or nothing
/// built on them can be: a tolerance that is not a positive fraction admits
/// every answer or no answer, and a budget below one restart cycle makes the
/// restart setting unreachable. This is a coherence check on a constant, not a
/// transcription of it — the numbers themselves are the Implementation-Phase's
/// to choose.
#[test]
fn the_default_solve_options_are_internally_coherent() {
    let options = Options::default();
    assert!(
        options.tolerance > 0.0 && options.tolerance < 1.0,
        "a default tolerance of {} is not a relative residual to aim at",
        options.tolerance
    );
    assert!(options.restart >= 1, "a restart of zero bounds nothing");
    assert!(
        options.max_iterations >= options.restart,
        "a budget of {} cannot complete one restart cycle of {}",
        options.max_iterations,
        options.restart
    );
}
