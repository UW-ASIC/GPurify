//! GMRES with iterative refinement. Host, `f64`, always.
//!
//! Nothing in this file knows whether the matvec ran on a CPU or a GPU. That is
//! the point of the seam: every decision about whether an answer is good enough
//! is made here, in double precision, once.

use super::matvec::MatVec;

/// How to solve.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Relative residual to reach. The solve fails rather than returning a
    /// worse answer.
    pub tolerance: f64,
    /// Iterations before restarting. Bounds the Krylov basis, and therefore
    /// memory.
    pub restart: u32,
    /// Total iteration budget across restarts. Hitting it is
    /// [`SolveError::NotConverged`], never a silently returned approximation.
    pub max_iterations: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            // A relative residual two decades below the tolerance any foundry
            // deck states for a coupling capacitance, so the solve is never the
            // dominant error term in the number that ships.
            tolerance: 1e-10,
            // The Krylov basis costs `restart × panels` doubles. Fifty is the
            // usual compromise: long enough that restarting rarely stalls
            // convergence, short enough that the basis stays a fraction of the
            // panel geometry it sits beside.
            restart: 50,
            // Twenty restart cycles. A well-conditioned quasi-static system
            // converges in one or two; needing twenty means the mesh is wrong,
            // and the caller should hear that as `NotConverged` rather than as
            // an hour of wall clock.
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

/// Reusable solver workspace.
///
/// The Krylov basis, Hessenberg matrix, Givens rotations and residual vectors.
/// Allocated once and reused across every right-hand side — a capacitance
/// matrix needs one solve per conductor, so this is allocated once per *matrix*,
/// not once per column.
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
/// **Transform.** Caller owns `x` and `workspace`; both are reused across
/// right-hand sides. All data flow is in the signature — the operator is a
/// parameter, so a test can pass a small matrix with a known solution and
/// exercise the whole solver without meshing anything.
///
/// Generic over the operator rather than taking `&dyn MatVec`, so a test can
/// supply its own third adapter alongside the CPU and GPU ones, and so the
/// inner loop is monomorphised.
///
/// Returns the achieved residual, measured in `f64` after the final iteration —
/// not the recurrence estimate GMRES carries internally, which can drift from
/// the true residual and did so in the old implementation.
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

    // Uniforms, hoisted above every loop below.
    //
    // A Krylov subspace cannot outrank the space it lives in, so a `restart`
    // above `n` only buys unreachable basis vectors — capping it is what keeps
    // `krylov` at `(m+1) × n` instead of `(restart+1) × n`. `max(1)` is the
    // fail-closed reading of `restart == 0`: a cycle of zero Arnoldi steps
    // makes no progress and would spin against the iteration budget forever.
    let m = usize::try_from(options.restart)
        .unwrap_or(usize::MAX)
        .min(n)
        .max(1);
    let b_scale = scale_of(norm(b));

    // Every buffer is refilled from scratch, so nothing a previous solve left
    // behind can reach this one. `clear` then `resize` keeps the capacity and
    // zeroes the whole length, which is what makes two solves of one system
    // bit-identical.
    workspace.krylov.clear();
    workspace.krylov.resize((m + 1) * n, 0.0);
    workspace.hessenberg.clear();
    workspace.hessenberg.resize((m + 1) * (m + 1), 0.0);
    workspace.givens.clear();
    workspace.givens.resize(m, (0.0, 0.0));
    workspace.correction.clear();
    workspace.correction.resize(n, 0.0);

    // `hessenberg` holds `m` columns of `m+1` rows — column `k` at `k*(m+1)`,
    // rows `0..=k+1` — followed by `g`, the rotated right-hand side of the
    // least-squares problem, at `g0`. `g` is where the back substitution writes
    // `y`, in place, which is why one buffer covers both.
    let g0 = m * (m + 1);

    let mut iterations: u32 = 0;
    let mut cycles: u32 = 0;

    loop {
        // The true relative residual, from the same function the caller can
        // check the answer with. It leaves `b − A x` in `workspace.residual`,
        // which is exactly the `r0` this cycle needs — so a restart costs no
        // extra matvec, and the number reported at the end is the number
        // `residual` recomputes rather than the recurrence estimate below.
        let rel = residual(operator, b, x, &mut workspace.residual);
        debug_assert_eq!(workspace.residual.len(), n, "`residual` refills to `n`");

        // Three loop-control branches per restart cycle, not per row. `restart`
        // Arnoldi steps sit between any two of them.
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
        // length check; without it a short `residual` would leave the tail of
        // `v0` stale and the solve would report success on a basis it never
        // built.
        for (v, &r) in workspace.krylov[..n].iter_mut().zip(&workspace.residual) {
            *v = r * inv_beta;
        }

        // `g := beta e1`. Bounded by `restart`, not by the panel count.
        workspace.hessenberg[g0..=g0 + m].fill(0.0);
        workspace.hessenberg[g0] = beta;

        let mut k: usize = 0;
        while k < m && iterations < options.max_iterations {
            iterations += 1;

            // `w := A v_k`.
            operator.apply(
                &workspace.krylov[k * n..k * n + n],
                &mut workspace.correction[..],
            );
            debug_assert_eq!(workspace.correction.len(), n, "`apply` must not resize `y`");

            // One finiteness check per matvec, over the whole vector at once —
            // a `NaN` or an infinity in any lane poisons this sum. Catching it
            // here is what stops it reaching `x` and making every later
            // comparison against the answer quietly false.
            let mut av_sq = 0.0_f64;
            for &w in &workspace.correction {
                av_sq += w * w;
            }
            if !av_sq.is_finite() {
                return Err(SolveError::NonFinite(iterations));
            }

            // Modified Gram-Schmidt. The `i` loop runs at most `restart` times
            // and is not bulk; each of its two bodies walks all `n` rows.
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
            // its subdiagonal with a fresh one. `k` steps, bounded by `restart`.
            for i in 0..k {
                let (c, s) = workspace.givens[i];
                let upper = workspace.hessenberg[col + i];
                let lower = workspace.hessenberg[col + i + 1];
                workspace.hessenberg[col + i] = c * upper + s * lower;
                workspace.hessenberg[col + i + 1] = c * lower - s * upper;
            }

            let hk = workspace.hessenberg[col + k];
            let rot = hk.hypot(hk1);
            // One compare per Arnoldi step. `rot == 0` means the whole column
            // vanished, which leaves `R` singular; the identity rotation keeps
            // the recurrence well-formed until the back substitution below
            // reports it as `Breakdown`.
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

            // `|g[k]|` is the norm of the residual this cycle would achieve if
            // it stopped here — the cheap estimate, used only to leave the loop
            // early. The number that decides convergence is the explicit one at
            // the top of the next cycle.
            let estimate = workspace.hessenberg[g0 + k].abs() / b_scale;
            if estimate <= options.tolerance {
                break;
            }
            // A vanished `hk1` is a happy breakdown: the Krylov space is
            // exhausted and the estimate above already reached zero in exact
            // arithmetic. There is no `v_k` to normalise, so stop rather than
            // divide by it. `!(hk1 > 0.0)` rather than `== 0.0` so a `NaN`
            // takes this exit too.
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

        // Back-substitute `R y = g` over `g` in place. `k ≤ restart`, so this is
        // a small triangular solve, not a bulk loop.
        for i in (0..k).rev() {
            let mut acc = workspace.hessenberg[g0 + i];
            for j in (i + 1)..k {
                acc -= workspace.hessenberg[j * (m + 1) + i] * workspace.hessenberg[g0 + j];
            }
            let diagonal = workspace.hessenberg[i * (m + 1) + i];
            // One compare per solved row. A zero pivot means the least-squares
            // problem is rank deficient and there is no correction to apply —
            // an error, never a silently unchanged `x`.
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

/// `‖v‖₂`.
///
/// A strict left fold in ascending index order. That is interface: `net_capacitance`
/// and every byte-reproducible export downstream rest on the same sum coming out
/// of the same input, so this must not be reassociated into lane accumulators.
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
/// reported instead of `0/0`. Returning `NaN` there would read as a non-finite
/// operator to [`gmres`] and blame the adapter for the caller's input.
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
/// For an operator whose `apply` is less accurate than `f64` — the GPU adapter,
/// which multiplies in `f32`. The correction equation is solved with the fast
/// inaccurate operator; the residual is formed in `f64` on the host from the
/// exact right-hand side. Iterating that recovers `f64` accuracy at close to
/// `f32` speed.
///
/// Used unconditionally, including with the CPU adapter, where it converges in
/// one outer step and costs one extra residual evaluation. Having one code path
/// rather than two is worth that: two paths means the accuracy argument has to
/// be made twice.
pub fn refine<M: MatVec>(
    operator: &M,
    b: &[f64],
    options: Options,
    x: &mut [f64],
    workspace: &mut Workspace,
) -> Result<Converged, SolveError> {
    // Restarted GMRES *is* the refinement loop, so `refine` is one call to it.
    // Every cycle forms `b − A x` on the host in `f64` from the exact
    // right-hand side, builds the next Krylov basis from that residual, solves
    // the correction equation with the operator, and adds the correction to
    // `x` — the refinement iteration, term for term. The explicit `residual()`
    // at the top of each cycle is what makes the identity exact rather than
    // approximate: textbook restarted GMRES carries the recurrence estimate
    // across a restart, this one recomputes. A second outer loop would
    // recompute the same residual and hand it to the same inner solver.
    //
    // Not a shortcut with an upgrade path — a fact about the seam. Refinement
    // does something restarting cannot only when the residual is computed
    // *more accurately* than the correction, and both go through `operator`.
    // `MatVec::apply` has one precision, so an outer loop cannot ask for a
    // better `A x` than the inner solve already used: under a `GpuF32` adapter
    // the residual carries that adapter's ~1e-7 error however many outer steps
    // run, and Wilkinson's extended-precision residual is unreachable for the
    // same reason. Genuine mixed precision is *two* operators at this seam, an
    // accurate one for the residual and a fast one for the correction — a
    // signature, not a body. `docs/SIGNATURE_DEFECTS.md`, "pex
    // quasistatic/solve.rs".
    //
    // The one thing an outer loop was previously said to buy, a looser
    // tolerance for the correction equation, is `options.restart` under another
    // name: for a Krylov inner solver, solving more loosely is taking fewer
    // Arnoldi steps, and the cycle already exits early on the same tolerance.
    // A separate inner tolerance earns its keep when the inner solve is a
    // factorisation whose accuracy is fixed by its precision rather than by an
    // iteration count. There is none here.
    gmres(operator, b, options, x, workspace)
}

/// True relative residual `‖b − Ax‖ / ‖b‖`.
///
/// **Decision** — pure, and the number everything else defers to. Separate and
/// public because it is the check: any claimed solution can be handed to this
/// with any operator, and the answer does not depend on how the solution was
/// obtained.
///
/// `scratch` is caller-owned and is left holding `b − A x`, which is what lets
/// [`gmres`] use its convergence check as the next restart's starting residual
/// instead of paying for a second matvec.
pub fn residual<M: MatVec>(operator: &M, b: &[f64], x: &[f64], scratch: &mut Vec<f64>) -> f64 {
    let n = b.len();
    debug_assert_eq!(operator.dim(), n, "the operator's dimension is `b`'s length");
    debug_assert_eq!(x.len(), n, "`x` is the operator's dimension");

    scratch.clear();
    scratch.resize(n, 0.0);
    operator.apply(x, &mut scratch[..]);
    debug_assert_eq!(scratch.len(), n, "`apply` must not resize `y`");

    // `scratch := b − A x`.
    debug_assert_eq!(scratch.len(), b.len(), "the residual is `b`'s column");
    for (ax, &bi) in scratch.iter_mut().zip(b) {
        *ax = bi - *ax;
    }

    norm(&scratch[..]) / scale_of(norm(b))
}
