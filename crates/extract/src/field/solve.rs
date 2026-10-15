//! Restarted GMRES with an outer residual-refinement loop. Host `f64`.
//!
//! Every reduction is a strict ascending fold; the iteration trajectory, and so
//! the low bits of every capacitance, depend on it.
//!
//! GMRES is Saad & Schultz (1986). The operator is any `Fn(x, y)` that writes
//! `y = A x` for vectors of one length; it need not be symmetric.

use gpurify_geom::linalg::{axpy, dot, nrm2};

/// Convergence target and iteration budgets for [`gmres`] and [`refine`].
///
/// The default (`1e-10`, restart 50, 1000 iterations) is what the field
/// solve uses for every column.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Relative residual to reach; a worse answer is an error.
    pub tolerance: f64,
    /// Iterations before restarting; bounds the Krylov basis.
    pub restart: u32,
    /// Total budget across restarts; exhausting it is [`SolveError::NotConverged`].
    pub max_iterations: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            tolerance: 1e-10,
            restart: 50,
            max_iterations: 1_000,
        }
    }
}

/// Why a field solve produced no answer. Every variant is a refusal: no
/// capacitance is reported from a solve that did not reach its tolerance.
#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
pub enum SolveError {
    /// The explicit relative residual stayed above the tolerance: the
    /// iteration budget ran out, or a refinement pass stopped reducing it.
    #[error("did not converge: residual {residual} after {iterations} iterations")]
    NotConverged {
        /// The explicit relative residual when the solve stopped.
        residual: f64,
        /// Iterations spent.
        iterations: u32,
    },
    /// The Krylov basis met a direction the operator maps to zero, so the
    /// least-squares step is singular. Carries the iteration count.
    #[error("system broke down at iteration {0}")]
    Breakdown(u32),
    /// The operator produced a NaN or infinity, or a conductor's summed
    /// charge is not finite. Carries the iteration count.
    #[error("the operator produced a non-finite value at iteration {0}")]
    NonFinite(u32),
    /// The selection could not be meshed; nothing was solved.
    #[error(transparent)]
    Mesh(#[from] super::mesh::MeshError),
}

/// Krylov basis, Hessenberg, Givens and residual buffers, reused across columns.
///
/// Only an allocation cache: its contents mean nothing between calls, and
/// each call resizes it to the problem at hand.
#[derive(Debug, Default)]
pub struct Workspace {
    krylov: Vec<f64>,
    hessenberg: Vec<f64>,
    givens: Vec<(f64, f64)>,
    residual: Vec<f64>,
    correction: Vec<f64>,
}

/// What a converged solve achieved.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Converged {
    /// True relative residual, recomputed explicitly.
    pub residual: f64,
    /// Krylov iterations, one operator application each; the explicit
    /// residual checks are not counted, and a [`refine`] pass counts at
    /// least one.
    pub iterations: u32,
    /// Restarts for [`gmres`]; refinement passes for [`refine`].
    pub restarts: u32,
}

/// Solve `A x = b` from the caller's `x`. Returns the explicitly recomputed
/// residual, not the GMRES recurrence estimate.
///
/// `x` is the initial guess and holds the answer on return; it must be as
/// long as `b`. The residual is relative to `‖b‖`, or absolute when `b` is
/// zero. On an error, `x` keeps the progress of every completed cycle.
///
/// # Errors
///
/// [`SolveError::NotConverged`] when `max_iterations` runs out above the
/// tolerance, [`SolveError::Breakdown`] on a singular least-squares step, and
/// [`SolveError::NonFinite`] when the operator returns NaN or infinity.
///
/// # Panics
///
/// When `x` and `b` differ in length.
///
/// # Time complexity
///
/// One operator application per iteration, plus *O*(n · restart) per
/// iteration for the orthogonalisation.
pub fn gmres(
    operator: impl Fn(&[f64], &mut [f64]) + Copy,
    b: &[f64],
    options: Options,
    x: &mut [f64],
    workspace: &mut Workspace,
) -> Result<Converged, SolveError> {
    assert_eq!(x.len(), b.len(), "the initial guess is as long as `b`");
    let n = b.len();
    // Basis no larger than the space; `max(1)` so `restart == 0` still progresses.
    let m = usize::try_from(options.restart)
        .unwrap_or(usize::MAX)
        .min(n)
        .max(1);
    let b_scale = scale_of(nrm2(b));

    workspace.krylov.clear();
    workspace.krylov.resize((m + 1) * n, 0.0);
    workspace.hessenberg.clear();
    workspace.hessenberg.resize((m + 1) * (m + 1), 0.0);
    workspace.givens.clear();
    workspace.givens.resize(m, (0.0, 0.0));
    workspace.correction.clear();
    workspace.correction.resize(n, 0.0);

    // `hessenberg`: `m` columns of `m+1` rows (column `k` at `k*(m+1)`), then the
    // rotated right-hand side `g` at `g0`, overwritten by `y` in back substitution.
    let g0 = m * (m + 1);

    let mut iterations: u32 = 0;
    let mut cycles: u32 = 0;

    loop {
        // Leaves `b − A x` in `workspace.residual`: this cycle's `r0`.
        let rel = residual(operator, b, x, &mut workspace.residual);
        if !rel.is_finite() {
            return Err(SolveError::NonFinite(iterations));
        }
        if rel <= options.tolerance {
            return Ok(Converged {
                residual: rel,
                iterations,
                restarts: cycles.saturating_sub(1),
            });
        }
        if iterations >= options.max_iterations {
            return Err(SolveError::NotConverged {
                residual: rel,
                iterations,
            });
        }
        cycles += 1;

        let beta = nrm2(&workspace.residual);
        let inv_beta = 1.0 / beta;
        for (v, &r) in workspace.krylov[..n].iter_mut().zip(&workspace.residual) {
            *v = r * inv_beta;
        }

        workspace.hessenberg[g0..=g0 + m].fill(0.0);
        workspace.hessenberg[g0] = beta;

        let mut k: usize = 0;
        while k < m && iterations < options.max_iterations {
            iterations += 1;

            operator(
                &workspace.krylov[k * n..k * n + n],
                &mut workspace.correction[..],
            );

            // One finiteness check per matvec, before anything reaches `x`.
            if !dot(&workspace.correction, &workspace.correction).is_finite() {
                return Err(SolveError::NonFinite(iterations));
            }

            // Modified Gram-Schmidt.
            let col = k * (m + 1);
            for i in 0..=k {
                let basis = &workspace.krylov[i * n..i * n + n];
                let h = dot(basis, &workspace.correction);
                workspace.hessenberg[col + i] = h;
                // `w + (−h)·v` is `w − h·v` to the bit: negation is exact.
                axpy(-h, basis, &mut workspace.correction);
            }
            let hk1 = nrm2(&workspace.correction);
            workspace.hessenberg[col + k + 1] = hk1;

            // Replay earlier rotations, then annihilate the subdiagonal.
            for i in 0..k {
                let (c, s) = workspace.givens[i];
                let upper = workspace.hessenberg[col + i];
                let lower = workspace.hessenberg[col + i + 1];
                workspace.hessenberg[col + i] = c * upper + s * lower;
                workspace.hessenberg[col + i + 1] = c * lower - s * upper;
            }

            let hk = workspace.hessenberg[col + k];
            let rot = hk.hypot(hk1);
            // A vanished column: identity rotation, reported as `Breakdown` below.
            let (c, s) = if rot == 0.0 {
                (1.0, 0.0)
            } else {
                (hk / rot, hk1 / rot)
            };
            workspace.givens[k] = (c, s);
            workspace.hessenberg[col + k] = c * hk + s * hk1;
            workspace.hessenberg[col + k + 1] = 0.0;
            let gk = workspace.hessenberg[g0 + k];
            workspace.hessenberg[g0 + k] = c * gk;
            workspace.hessenberg[g0 + k + 1] = -s * gk;

            k += 1;

            // Early exit on the recurrence estimate; the explicit residual decides.
            let estimate = workspace.hessenberg[g0 + k].abs() / b_scale;
            if estimate <= options.tolerance {
                break;
            }
            // Happy breakdown (also catches NaN).
            if !(hk1 > 0.0) {
                break;
            }
            let inv = 1.0 / hk1;
            for (v, &w) in workspace.krylov[k * n..k * n + n]
                .iter_mut()
                .zip(&workspace.correction)
            {
                *v = w * inv;
            }
        }

        // Back-substitute `R y = g` in place.
        for i in (0..k).rev() {
            let mut acc = workspace.hessenberg[g0 + i];
            for j in (i + 1)..k {
                acc -= workspace.hessenberg[j * (m + 1) + i] * workspace.hessenberg[g0 + j];
            }
            let diagonal = workspace.hessenberg[i * (m + 1) + i];
            if diagonal == 0.0 {
                return Err(SolveError::Breakdown(iterations));
            }
            workspace.hessenberg[g0 + i] = acc / diagonal;
        }

        // `x += Σ y_i v_i`, ascending `i`.
        for i in 0..k {
            axpy(
                workspace.hessenberg[g0 + i],
                &workspace.krylov[i * n..i * n + n],
                x,
            );
        }
    }
}

/// Denominator of a relative residual: `‖b‖`, or 1 for `b = 0` (absolute residual).
fn scale_of(norm_b: f64) -> f64 {
    if norm_b == 0.0 {
        1.0
    } else {
        norm_b
    }
}

/// GMRES inside an outer loop that recomputes the true residual after each
/// single-cycle correction solve:
///
/// ```text
/// r ← b − A x
/// while ‖r‖/‖b‖ > tolerance:  solve A d = r (one Krylov cycle); x ← x + d; r ← b − A x
/// ```
///
/// Stops early when a pass fails to reduce the residual.
///
/// `x` is the initial guess and must be as long as `b`. A pass whose inner
/// GMRES did not converge still applies its correction, since recomputing
/// the true residual is what decides.
///
/// # Errors
///
/// [`SolveError::NotConverged`] when the true residual is still above the
/// tolerance after `max_iterations` or after a pass that did not reduce it.
/// [`SolveError::Breakdown`] and [`SolveError::NonFinite`] from an inner
/// solve end the refinement at once, and a true residual that is not finite
/// is [`SolveError::NonFinite`].
///
/// # Panics
///
/// When `x` and `b` differ in length.
pub fn refine(
    operator: impl Fn(&[f64], &mut [f64]) + Copy,
    b: &[f64],
    options: Options,
    x: &mut [f64],
    workspace: &mut Workspace,
) -> Result<Converged, SolveError> {
    assert_eq!(x.len(), b.len(), "the initial guess is as long as `b`");
    let n = b.len();
    let mut scratch = Vec::new();
    let mut correction = vec![0.0_f64; n];

    let mut achieved = residual(operator, b, x, &mut scratch);
    let mut iterations = 0_u32;
    let mut restarts = 0_u32;

    while achieved > options.tolerance && iterations < options.max_iterations {
        // `scratch` already holds `b − A x`: the correction's right-hand side.
        let rhs = std::mem::take(&mut scratch);
        correction.fill(0.0);

        let inner = Options {
            tolerance: options.tolerance,
            restart: options.restart,
            // One Krylov cycle; the outer pass is the restart.
            max_iterations: options.restart.min(options.max_iterations - iterations),
        };
        // An unconverged correction is still a correction; only breakdown is fatal.
        let step = match gmres(operator, &rhs, inner, &mut correction, workspace) {
            Ok(step) => step.iterations,
            Err(SolveError::NotConverged { iterations, .. }) => iterations,
            Err(fatal) => return Err(fatal),
        };
        iterations = iterations.saturating_add(step.max(1));
        restarts = restarts.saturating_add(1);

        for (value, &delta) in x.iter_mut().zip(&correction) {
            *value += delta;
        }

        scratch = rhs;
        let next = residual(operator, b, x, &mut scratch);
        if next >= achieved {
            achieved = next;
            break;
        }
        achieved = next;
    }

    // A `NaN` residual compares false against the tolerance, so it is caught
    // here and never read as converged.
    if !achieved.is_finite() {
        return Err(SolveError::NonFinite(iterations));
    }
    if achieved > options.tolerance {
        return Err(SolveError::NotConverged {
            residual: achieved,
            iterations,
        });
    }
    Ok(Converged {
        residual: achieved,
        iterations,
        restarts,
    })
}

/// True relative residual `‖b − Ax‖ / ‖b‖`; leaves `b − A x` in `scratch`.
///
/// The residual is absolute when `b` is zero. `scratch` is resized to
/// `b.len()`, and its old contents are discarded.
pub fn residual(
    operator: impl Fn(&[f64], &mut [f64]),
    b: &[f64],
    x: &[f64],
    scratch: &mut Vec<f64>,
) -> f64 {
    let n = b.len();
    scratch.clear();
    scratch.resize(n, 0.0);
    operator(x, &mut scratch[..]);
    for (ax, &bi) in scratch.iter_mut().zip(b) {
        *ax = bi - *ax;
    }
    nrm2(scratch) / scale_of(nrm2(b))
}
