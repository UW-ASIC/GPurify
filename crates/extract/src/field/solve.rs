//! Restarted GMRES with an outer residual-refinement loop. Host `f64`.
//!
//! Every reduction is a strict ascending fold; the iteration trajectory, and so
//! the low bits of every capacitance, depend on it.

use super::matvec::MatVec;

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

#[derive(Debug, Clone, Copy, PartialEq, thiserror::Error)]
pub enum SolveError {
    #[error("did not converge: residual {residual} after {iterations} iterations")]
    NotConverged { residual: f64, iterations: u32 },
    #[error("system broke down at iteration {0}")]
    Breakdown(u32),
    #[error("the operator produced a non-finite value at iteration {0}")]
    NonFinite(u32),
}

/// Krylov basis, Hessenberg, Givens and residual buffers, reused across columns.
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
    pub iterations: u32,
    pub restarts: u32,
}

/// Solve `A x = b` from the caller's `x`. Returns the explicitly recomputed
/// residual, not the GMRES recurrence estimate.
pub fn gmres<M: MatVec>(
    operator: &M,
    b: &[f64],
    options: Options,
    x: &mut [f64],
    workspace: &mut Workspace,
) -> Result<Converged, SolveError> {
    let n = b.len();
    // Basis no larger than the space; `max(1)` so `restart == 0` still progresses.
    let m = usize::try_from(options.restart)
        .unwrap_or(usize::MAX)
        .min(n)
        .max(1);
    let b_scale = scale_of(norm(b));

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

        let beta = norm(&workspace.residual[..]);
        let inv_beta = 1.0 / beta;
        for (v, &r) in workspace.krylov[..n].iter_mut().zip(&workspace.residual) {
            *v = r * inv_beta;
        }

        workspace.hessenberg[g0..=g0 + m].fill(0.0);
        workspace.hessenberg[g0] = beta;

        let mut k: usize = 0;
        while k < m && iterations < options.max_iterations {
            iterations += 1;

            operator.apply(
                &workspace.krylov[k * n..k * n + n],
                &mut workspace.correction[..],
            );

            // One finiteness check per matvec, before anything reaches `x`.
            let mut av_sq = 0.0_f64;
            for &w in &workspace.correction {
                av_sq += w * w;
            }
            if !av_sq.is_finite() {
                return Err(SolveError::NonFinite(iterations));
            }

            // Modified Gram-Schmidt.
            let col = k * (m + 1);
            for i in 0..=k {
                let h = dot(
                    &workspace.krylov[i * n..i * n + n],
                    &workspace.correction[..],
                );
                workspace.hessenberg[col + i] = h;
                for (w, &v) in workspace
                    .correction
                    .iter_mut()
                    .zip(&workspace.krylov[i * n..i * n + n])
                {
                    *w -= h * v;
                }
            }
            let hk1 = norm(&workspace.correction[..]);
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
            let y = workspace.hessenberg[g0 + i];
            for (xv, &v) in x.iter_mut().zip(&workspace.krylov[i * n..i * n + n]) {
                *xv += y * v;
            }
        }
    }
}

/// `‖v‖₂` as a strict ascending fold.
fn norm(v: &[f64]) -> f64 {
    let mut sum = 0.0_f64;
    for &value in v {
        sum += value * value;
    }
    sum.sqrt()
}

/// `u · v` as a strict ascending fold.
fn dot(u: &[f64], v: &[f64]) -> f64 {
    let mut acc = 0.0_f64;
    for (&a, &b) in u.iter().zip(v) {
        acc += a * b;
    }
    acc
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
pub fn refine<M: MatVec>(
    operator: &M,
    b: &[f64],
    options: Options,
    x: &mut [f64],
    workspace: &mut Workspace,
) -> Result<Converged, SolveError> {
    let n = b.len();
    let mut scratch = Vec::new();
    let mut correction = vec![0.0_f64; n];

    let mut achieved = residual(operator, b, x, &mut scratch);
    let mut iterations = 0_u32;
    let mut restarts = 0_u32;

    while achieved > options.tolerance && iterations < options.max_iterations {
        // `scratch` already holds `b − A x`: the correction's right-hand side.
        let rhs = std::mem::take(&mut scratch);
        correction.clear();
        correction.resize(n, 0.0);

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
pub fn residual<M: MatVec>(operator: &M, b: &[f64], x: &[f64], scratch: &mut Vec<f64>) -> f64 {
    let n = b.len();
    scratch.clear();
    scratch.resize(n, 0.0);
    operator.apply(x, &mut scratch[..]);
    for (ax, &bi) in scratch.iter_mut().zip(b) {
        *ax = bi - *ax;
    }
    norm(&scratch[..]) / scale_of(norm(b))
}
