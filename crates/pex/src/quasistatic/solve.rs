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
        todo!()
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
    todo!()
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
    todo!()
}

/// True relative residual `‖b − Ax‖ / ‖b‖`.
///
/// **Decision** — pure, and the number everything else defers to. Separate and
/// public because it is the check: any claimed solution can be handed to this
/// with any operator, and the answer does not depend on how the solution was
/// obtained.
pub fn residual<M: MatVec>(operator: &M, b: &[f64], x: &[f64], scratch: &mut Vec<f64>) -> f64 {
    todo!()
}
