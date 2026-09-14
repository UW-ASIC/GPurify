//! GMRES with iterative refinement. Host, `f64`, always.

use super::matvec::{Backend, MatVec};

/// How to solve.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Relative residual to reach. The solve fails rather than returning a
    /// worse answer.
    pub tolerance: f64,
    /// Iterations before restarting. Bounds the Krylov basis.
    pub restart: u32,
    /// Total iteration budget across restarts. Hitting it is
    /// [`SolveError::NotConverged`], never a silently returned approximation.
    pub max_iterations: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            // Two decades below the tolerance any foundry deck states for a
            // coupling capacitance, so the solve is never the dominant error.
            tolerance: 1e-10,
            restart: 50,
            // Twenty restart cycles; needing that many means the mesh is wrong,
            // and the caller should hear `NotConverged` rather than wait.
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

/// The Krylov basis, Hessenberg matrix, Givens rotations and residual vectors,
/// allocated once per matrix rather than once per column.
#[derive(Debug, Default)]
pub struct Workspace {
    krylov: Vec<f64>,
    hessenberg: Vec<f64>,
    givens: Vec<(f64, f64)>,
    residual: Vec<f64>,
    correction: Vec<f64>,
}

/// Solve `A x = b`.
///
/// Caller owns `x` and `workspace`, both reused across right-hand sides.
/// Returns the achieved residual measured explicitly in `f64`, not the
/// recurrence estimate GMRES carries internally.
pub fn gmres<M: MatVec>(
    operator: &M,
    b: &[f64],
    options: Options,
    x: &mut [f64],
    workspace: &mut Workspace,
) -> Result<Converged, SolveError> {
    let n = b.len();
    debug_assert_eq!(operator.dim(), n, "the operator's dimension is `b`'s length");
    debug_assert_eq!(x.len(), n, "`x` is the operator's dimension");
    debug_assert!(
        options.tolerance > 0.0,
        "a tolerance of zero or less is unreachable"
    );

    // A Krylov subspace cannot outrank the space it lives in, so a `restart`
    // above `n` only buys unreachable basis vectors. `max(1)` is the fail-closed
    // reading of `restart == 0`, which would make no progress and spin against
    // the iteration budget forever.
    let m = usize::try_from(options.restart)
        .unwrap_or(usize::MAX)
        .min(n)
        .max(1);
    let b_scale = scale_of(norm(b));

    // Refilled from scratch, so nothing a previous solve left behind reaches
    // this one — which is what makes two solves of one system bit-identical.
    workspace.krylov.clear();
    workspace.krylov.resize((m + 1) * n, 0.0);
    workspace.hessenberg.clear();
    workspace.hessenberg.resize((m + 1) * (m + 1), 0.0);
    workspace.givens.clear();
    workspace.givens.resize(m, (0.0, 0.0));
    workspace.correction.clear();
    workspace.correction.resize(n, 0.0);

    // `hessenberg` holds `m` columns of `m+1` rows — column `k` at `k*(m+1)`,
    // rows `0..=k+1` — followed by `g`, the rotated right-hand side, at `g0`.
    // The back substitution writes `y` over `g` in place.
    let g0 = m * (m + 1);

    let mut iterations: u32 = 0;
    let mut cycles: u32 = 0;

    loop {
        // Leaves `b − A x` in `workspace.residual`, which is exactly the `r0`
        // this cycle needs, so a restart costs no extra matvec.
        let rel = residual(operator, b, x, &mut workspace.residual);
        debug_assert_eq!(workspace.residual.len(), n, "`residual` refills to `n`");

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

        // `v0 := r / ‖r‖`. `rel > tolerance > 0` and `rel` is finite, so `beta`
        // is strictly positive and finite.
        let beta = norm(&workspace.residual[..]);
        debug_assert!(beta > 0.0 && beta.is_finite(), "a restart needs a residual");
        let inv_beta = 1.0 / beta;
        debug_assert_eq!(
            workspace.krylov[..n].len(),
            workspace.residual.len(),
            "`v0` and the residual are the same column"
        );
        // `zip` stops at the shorter column, so the assert above is the whole
        // length check: a short `residual` would leave the tail of `v0` stale
        // and the solve would report success on a basis it never built.
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
            debug_assert_eq!(workspace.correction.len(), n, "`apply` must not resize `y`");

            // One finiteness check per matvec: a NaN or infinity in any lane
            // poisons this sum, and catching it here stops it reaching `x`.
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
                debug_assert_eq!(
                    workspace.correction.len(),
                    n,
                    "`w` and every basis vector are the same column"
                );
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

            // Replay the earlier rotations onto the new column, then annihilate
            // its subdiagonal with a fresh one.
            for i in 0..k {
                let (c, s) = workspace.givens[i];
                let upper = workspace.hessenberg[col + i];
                let lower = workspace.hessenberg[col + i + 1];
                workspace.hessenberg[col + i] = c * upper + s * lower;
                workspace.hessenberg[col + i + 1] = c * lower - s * upper;
            }

            let hk = workspace.hessenberg[col + k];
            let rot = hk.hypot(hk1);
            // `rot == 0` means the whole column vanished, leaving `R` singular;
            // the identity rotation keeps the recurrence well-formed until the
            // back substitution reports it as `Breakdown`.
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

            // The cheap recurrence estimate, used only to leave the loop early.
            // Convergence is decided by the explicit residual at the top of the
            // next cycle.
            let estimate = workspace.hessenberg[g0 + k].abs() / b_scale;
            if estimate <= options.tolerance {
                break;
            }
            // A vanished `hk1` is a happy breakdown: no `v_k` to normalise, so
            // stop rather than divide by it. `!(hk1 > 0.0)` and not `== 0.0` so
            // a NaN takes this exit too.
            if !(hk1 > 0.0) {
                break;
            }
            let inv = 1.0 / hk1;
            debug_assert_eq!(
                workspace.correction.len(),
                n,
                "the new basis vector and `w` are the same column"
            );
            for (v, &w) in workspace.krylov[k * n..k * n + n]
                .iter_mut()
                .zip(&workspace.correction)
            {
                *v = w * inv;
            }
        }
        debug_assert!(k >= 1 && k <= m, "a cycle runs between one and `m` steps");

        // Back-substitute `R y = g` over `g` in place.
        for i in (0..k).rev() {
            let mut acc = workspace.hessenberg[g0 + i];
            for j in (i + 1)..k {
                acc -= workspace.hessenberg[j * (m + 1) + i] * workspace.hessenberg[g0 + j];
            }
            let diagonal = workspace.hessenberg[i * (m + 1) + i];
            // A zero pivot means the least-squares problem is rank deficient and
            // there is no correction to apply — an error, never a silently
            // unchanged `x`.
            if diagonal == 0.0 {
                return Err(SolveError::Breakdown(iterations));
            }
            workspace.hessenberg[g0 + i] = acc / diagonal;
        }

        // `x += Σ y_i v_i`, in ascending `i` so the sum is reproducible.
        for i in 0..k {
            let y = workspace.hessenberg[g0 + i];
            debug_assert_eq!(x.len(), n, "`x` and every basis vector are the same column");
            for (xv, &v) in x.iter_mut().zip(&workspace.krylov[i * n..i * n + n]) {
                *xv += y * v;
            }
        }
    }
}

/// `‖v‖₂`, as a strict left fold in ascending index order.
///
/// That order is interface: every byte-reproducible export downstream rests on
/// it, so it must not be reassociated into lane accumulators.
fn norm(v: &[f64]) -> f64 {
    let mut sum = 0.0_f64;
    for &value in v {
        sum += value * value;
    }
    sum.sqrt()
}

/// `u · v`, in ascending index order, so the sum is bit-reproducible.
fn dot(u: &[f64], v: &[f64]) -> f64 {
    debug_assert_eq!(u.len(), v.len(), "a dot product needs matched columns");
    let mut acc = 0.0_f64;
    for (&a, &b) in u.iter().zip(v) {
        acc += a * b;
    }
    acc
}

/// The denominator of a relative residual.
///
/// A zero right-hand side has no relative residual, so the absolute one is
/// reported instead of `0/0`, which [`gmres`] would read as a non-finite
/// operator and blame on the adapter.
fn scale_of(norm_b: f64) -> f64 {
    if norm_b == 0.0 {
        1.0
    } else {
        norm_b
    }
}

/// What a converged solve achieved.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Converged {
    /// True relative residual, recomputed explicitly at the end.
    pub residual: f64,
    pub iterations: u32,
    pub restarts: u32,
}

/// Solve with mixed-precision iterative refinement.
///
/// `accurate` forms the residual in `f64`; `fast` solves the correction equation
/// and may be an `f32` adapter. They may be the same value, which is the host
/// path.
///
/// ```text
/// r ← b − A_accurate x                     (f64)
/// while ‖r‖/‖b‖ > tolerance:
///     solve A_fast d = r    loosely        (f32, the expensive part)
///     x ← x + d
///     r ← b − A_accurate x                 (f64)
/// ```
///
/// Both operators are needed: a single-operator loop puts `A x` inside the
/// residual on the fast adapter too, so the bound carries that adapter's error
/// however many cycles run — measured, a device solve stalls at `7.87e-7`, which
/// is `f32` epsilon with the fold's `√n` on it.
///
/// The correction is solved to `INNER_TOLERANCE` because a correction accurate
/// to more digits than `fast` carries is digits that do not exist. The reported
/// residual is always `accurate`'s.
pub fn refine<A: MatVec, F: MatVec>(
    accurate: &A,
    fast: &F,
    b: &[f64],
    options: Options,
    x: &mut [f64],
    workspace: &mut Workspace,
) -> Result<Converged, SolveError> {
    let n = b.len();
    debug_assert_eq!(accurate.dim(), n, "the residual operator is `b`'s length");
    debug_assert_eq!(fast.dim(), n, "both operators are the same problem");
    debug_assert_eq!(x.len(), n, "`x` is the operator's dimension");

    let mut scratch = Vec::new();
    let mut correction = vec![0.0_f64; n];

    // Decided by what `fast` is *declared* to carry, never a constant: asking an
    // `f32` operator for `1e-10` spends the whole budget on digits it does not
    // have, and asking an `f64` operator for `1e-3` spends it on outer passes it
    // does not need — an outer pass being an `f64` matvec.
    let inner_tolerance = match fast.backend() {
        Backend::Cpu => options.tolerance,
        Backend::GpuF32 => INNER_TOLERANCE,
    };

    let mut achieved = residual(accurate, b, x, &mut scratch);
    let mut iterations = 0_u32;
    let mut restarts = 0_u32;

    // Bounded by the same `max_iterations` the inner solver is, so a caller that
    // asked for a small budget gets it honoured rather than multiplied.
    while achieved > options.tolerance && iterations < options.max_iterations {
        // `residual` left `b − A x` in `scratch`, so the correction equation's
        // right-hand side is already formed and needs no second matvec.
        let rhs = std::mem::take(&mut scratch);
        correction.clear();
        correction.resize(n, 0.0);

        let inner = Options {
            tolerance: inner_tolerance,
            restart: options.restart,
            // One Krylov cycle, never a restart: an inner restart recomputes
            // `rhs − A_fast d` and carries on, which is what an outer pass does
            // with the *accurate* operator instead. The outer pass is strictly
            // better at the same price.
            max_iterations: options.restart.min(options.max_iterations - iterations),
        };
        // A correction that did not converge is still a correction: the outer
        // residual decides, and it is recomputed below in `f64`. Only a
        // breakdown — a genuinely singular system — is fatal.
        let step = match gmres(fast, &rhs, inner, &mut correction, workspace) {
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
        let next = residual(accurate, b, x, &mut scratch);
        // The difference between "hard problem", "wrong inner tolerance" and
        // "the operator is less accurate than it claims" is invisible in the
        // returned error and obvious in the per-pass trace.
        if std::env::var_os("GPURIFY_REFINE_TRACE").is_some() {
            eprintln!(
                "refine pass {restarts}: {achieved:e} -> {next:e}, \
                 inner steps {step}, budget {iterations}/{}",
                options.max_iterations
            );
        }
        // Fail closed on a refinement that has stopped refining: a stalled loop
        // would spend the whole budget re-deriving the same number, which reads
        // as "hard problem" when it is "this is the floor".
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

/// How loosely the correction equation is solved when `fast` is an `f32`
/// adapter: three decades, roughly what an `f32` operator can be trusted for
/// after the fold's `√n`.
const INNER_TOLERANCE: f64 = 1e-3;

/// True relative residual `‖b − Ax‖ / ‖b‖`.
///
/// `scratch` is caller-owned and is left holding `b − A x`, which is what lets
/// [`gmres`] reuse its convergence check as the next restart's starting
/// residual.
pub fn residual<M: MatVec>(operator: &M, b: &[f64], x: &[f64], scratch: &mut Vec<f64>) -> f64 {
    let n = b.len();
    debug_assert_eq!(operator.dim(), n, "the operator's dimension is `b`'s length");
    debug_assert_eq!(x.len(), n, "`x` is the operator's dimension");

    scratch.clear();
    scratch.resize(n, 0.0);
    operator.apply(x, &mut scratch[..]);
    debug_assert_eq!(scratch.len(), n, "`apply` must not resize `y`");

    debug_assert_eq!(scratch.len(), b.len(), "the residual is `b`'s column");
    for (ax, &bi) in scratch.iter_mut().zip(b) {
        *ax = bi - *ax;
    }

    norm(&scratch[..]) / scale_of(norm(b))
}
