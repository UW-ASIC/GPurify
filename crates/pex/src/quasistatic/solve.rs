//! GMRES with iterative refinement. Host, `f64`, always.
//!
//! Nothing in this file knows whether the matvec ran on a CPU or a GPU. That is
//! the point of the seam: every decision about whether an answer is good enough
//! is made here, in double precision, once.

use super::matvec::{Backend, MatVec};

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
/// # Two operators, and why one was never enough
///
/// `accurate` forms the residual; `fast` solves the correction equation. They
/// may be the same value — `refine(&cpu, &cpu, ..)` is the host path and costs
/// one extra residual evaluation over plain GMRES.
///
/// This signature used to take one operator and the body was one call to
/// [`gmres`], on the argument that restarted GMRES *is* the refinement loop:
/// every cycle forms `b − A x` on the host in `f64` and builds the next Krylov
/// basis from it, which is the refinement iteration term for term. That argument
/// is correct and it is not sufficient, and the comment that carried it said so:
/// "Refinement does something restarting cannot only when the residual is
/// computed *more accurately* than the correction, and both go through
/// `operator`."
///
/// Both did. `residual` calls `operator.apply`, so under a `GpuF32` adapter the
/// `A x` inside the residual is itself `f32` and the bound carries that
/// adapter's own error however many cycles run. **Measured**: with the device
/// live, a two-conductor solve stalled at a relative residual of `7.87e-7`
/// against a `1e-10` tolerance and returned [`SolveError::NotConverged`] after
/// 400 iterations. `7.87e-7` is `f32` epsilon with the fold's `√n` on it — not a
/// hard problem, a precision floor.
///
/// That was fail-*closed*, which is why it was a refusal and not a wrong
/// capacitance. It also made the GPU path useless: every field solve above the
/// device's crossover refused. `docs/GPU.md` specifies the fix in as many words
/// — "the GMRES matvec runs on the GPU in `f32`; the residual and the correction
/// are computed on the host in `f64`" — so the defect was this signature, and it
/// is the one filed under "pex quasistatic/solve.rs".
///
/// ## The loop
///
/// Classic mixed-precision iterative refinement:
///
/// ```text
/// r ← b − A_accurate x                     (f64)
/// while ‖r‖/‖b‖ > tolerance:
///     solve A_fast d = r    loosely        (f32, the expensive part)
///     x ← x + d
///     r ← b − A_accurate x                 (f64)
/// ```
///
/// The correction equation is solved to a *loose* tolerance, because a
/// correction accurate to more digits than `fast` carries is digits that do not
/// exist. `INNER_TOLERANCE` is that looseness, and the outer loop is what
/// recovers the accuracy: each pass multiplies the error by roughly the inner
/// tolerance, so three or four passes reach `1e-10` from `1e-3`.
///
/// The accurate operator costs one matvec per outer pass. At 8192 panels that is
/// 183 ms against the device's 8.3 ms, so three outer passes plus thirty inner
/// iterations each is about 1.3 s where a pure `f64` solve is 18 s — which is
/// the whole point of the algorithm and the reason the measurement in
/// `gpu::MEASURED_CROSSOVER` is worth anything.
///
/// The residual reported is always `accurate`'s, so [`Converged::residual`] is
/// an `f64` bound whichever adapter did the work. That is contract item 4.
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

    // The whole-loop residual buffer, and the correction. Two `Vec`s per solve,
    // not per pass.
    let mut scratch = Vec::new();
    let mut correction = vec![0.0_f64; n];

    // How hard to press the correction equation, decided by what `fast` is
    // *declared* to carry rather than by a constant. `Backend` is that
    // declaration and this is what it is for.
    //
    // Both directions are wrong if this is a constant. Asking an `f32` operator
    // for `1e-10` asks for digits it does not have, and the inner solve spends
    // the whole budget not finding them — which is the `7.87e-7` stall this
    // function's doc comment records. Asking an `f64` operator for `1e-3` is the
    // opposite waste: the host path then takes several outer passes, and an
    // outer pass is an `f64` matvec, the expensive thing the arrangement exists
    // to avoid. Measured: it turned a host solve that converged into
    // `NotConverged { residual: 8.39e-10 }` against a `1e-10` tolerance, purely
    // by spending the iteration budget on passes it did not need.
    //
    // So the host path asks for the full tolerance and converges in one outer
    // pass, which is exactly the plain `gmres` this function used to be.
    let inner_tolerance = match fast.backend() {
        Backend::Cpu => options.tolerance,
        Backend::GpuF32 => INNER_TOLERANCE,
    };

    let mut achieved = residual(accurate, b, x, &mut scratch);
    let mut iterations = 0_u32;
    let mut restarts = 0_u32;

    // `<=` on the budget rather than a fixed pass count: the outer loop is
    // bounded by the same `max_iterations` the inner solver is, so a caller that
    // asked for a small budget gets it honoured rather than multiplied.
    while achieved > options.tolerance && iterations < options.max_iterations {
        // `scratch` is `b − A x` — `residual` leaves it there, which is the
        // whole reason it is caller-owned — so the correction equation's
        // right-hand side is already formed and needs no second matvec.
        let rhs = std::mem::take(&mut scratch);
        correction.clear();
        correction.resize(n, 0.0);

        let inner = Options {
            tolerance: inner_tolerance,
            restart: options.restart,
            // **One Krylov cycle, never a restart.** A restart *inside* the
            // correction equation recomputes `rhs − A_fast d` and carries on
            // from it — which is what an outer refinement pass does, except
            // with the inaccurate operator instead of the accurate one. The
            // outer pass is strictly better at the same price, so an inner
            // restart is work spent chasing a residual that is already at its
            // own floor.
            //
            // Measured, with the device live and a `1e-3` inner tolerance:
            // pass 1 reached it in 21 steps, passes 2 and 3 took 179 and 196 —
            // four inner restarts each, grinding against the `f32` floor for
            // the same three decades pass 1 got in twenty steps. Capped, each
            // pass stops at the cycle boundary and hands whatever it has to an
            // `f64` residual.
            max_iterations: options.restart.min(options.max_iterations - iterations),
        };
        // A correction that did not converge is still a correction. It is the
        // *outer* residual that decides, and it is recomputed below in `f64`, so
        // a loose inner solve costs a pass rather than an answer. Only a
        // breakdown — a genuinely singular system — is fatal, and it is
        // propagated rather than retried.
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
        // One line of diagnostics, behind an environment variable and off by
        // default. It is here because the difference between "this problem is
        // hard", "the inner tolerance is wrong" and "the operator is less
        // accurate than it claims" is invisible in the returned error and
        // obvious in the per-pass trace — which is how the `7.87e-7` stall and
        // the inner-restart waste were both found. `var_os`, not `var`: the
        // value is never read, only its presence.
        if std::env::var_os("GPURIFY_REFINE_TRACE").is_some() {
            eprintln!(
                "refine pass {restarts}: {achieved:e} -> {next:e}, \
                 inner steps {step}, budget {iterations}/{}",
                options.max_iterations
            );
        }
        // Fail closed on a refinement that has stopped refining. Without this a
        // stalled loop spends the whole budget re-deriving the same number,
        // which reads as "hard problem" when it is "this is the floor". One
        // exact compare, not a tolerance: the loop exits on `>` above, so any
        // real progress at all keeps it going.
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
/// adapter.
///
/// Three decades, which is roughly what an `f32` operator can be trusted for
/// after the fold's `√n`. Each outer pass multiplies the error by about this, so
/// four passes reach `1e-12` from `1e-0` — comfortably past the `1e-10` default
/// tolerance, and cheap because the passes are the `f32` ones.
///
/// Looser would cost more outer passes, and an outer pass is an `f64` matvec —
/// the expensive thing this whole arrangement exists to avoid. Tighter would ask
/// the fast operator for digits it does not have and simply not converge.
const INNER_TOLERANCE: f64 = 1e-3;

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
