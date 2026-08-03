//! The seam.
//!
//! Everything expensive about a quasi-static solve is one operation: multiply
//! the dense influence matrix by a vector, without forming the matrix. So that
//! is where the CPU and GPU adapters meet, and it is the *only* place they
//! differ.
//!
//! # Why this seam and not the solver
//!
//! Putting the seam at the whole solver would give each adapter its own
//! iteration strategy and its own accuracy story — and an accuracy story each
//! adapter tells separately is how the old implementation ended up silently
//! computing a signoff number in `f32`. Here, GMRES, the residual, the
//! refinement loop and every decision about whether the answer is good enough
//! live once, on the host, in `f64`. An adapter multiplies. That is all it can
//! do, so that is all it can get wrong.
//!
//! The precision boundary and the module boundary coincide, which is the
//! property worth having.
//!
//! # Mixed precision
//!
//! On the development target — an Ada consumer part — `f64` runs at 1/64 of
//! `f32` rate, so a straight `f64` port would be slower than the host. The
//! resolution is iterative refinement: the matvec runs in `f32` on the device,
//! the residual and correction are computed in `f64` on the host, and iteration
//! continues until the `f64` residual meets tolerance. The answer is
//! `f64`-accurate and the accuracy is *measured*, not assumed.

use gpurify_core::observe::{NoObserve, Observer};

/// Multiply the influence matrix by a vector.
///
/// The interface is deliberately this small. An adapter receives a vector and
/// fills another; it has no access to the tolerance, the iteration count, or
/// the decision to stop.
///
/// `y` is caller-owned and fully overwritten — not accumulated — so the caller
/// keeps one buffer for the whole solve and an adapter cannot accidentally
/// depend on `y`'s prior contents.
pub trait MatVec {
    /// Panel count. `x` and `y` are both this long.
    fn dim(&self) -> usize;

    /// `y := A x`.
    fn apply(&self, x: &[f64], y: &mut [f64]);

    /// Which adapter this is, for [`super::Accuracy::backend`].
    fn backend(&self) -> Backend;
}

/// Which adapter performed the matvec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Host, `f64` throughout.
    Cpu,
    /// Device, `f32` matvec inside host `f64` refinement.
    GpuF32,
}

/// FMM-accelerated matvec on the host, in `f64`.
///
/// The reference implementation in every sense: it is what the GPU adapter is
/// differentially tested against, and it is what runs whenever no device is
/// present or the problem is below the crossover.
///
/// **Five questions.** In: a panel mesh. Out: the machinery to apply the
/// operator. How many: one per solve. Access pattern: the near-field is a
/// sparse block product over spatially sorted panels; the far-field is a tree
/// traversal — so panels are stored in tree order and both passes are
/// contiguous. Lifetime: one solve; every buffer is reused across iterations.
/// Parallelisable: yes, but the reduction order is fixed, because a
/// reassociated sum is a different `f64` and the output is byte-gated.
#[derive(Debug, Default)]
pub struct CpuMatVec {
    // The panel tree, multipole and local expansions, and the near-field block
    // list. All allocated once per solve and reused across iterations.
}

impl MatVec for CpuMatVec {
    fn dim(&self) -> usize {
        todo!()
    }
    fn apply(&self, x: &[f64], y: &mut [f64]) {
        todo!()
    }
    fn backend(&self) -> Backend {
        todo!()
    }
}

/// Choose an adapter.
///
/// **Decision** — pure, and automatic. GPU is selected only above the panel
/// count at which it was *measured* to win, and only when a device is actually
/// present. Not a user flag: a flag would let someone select a slower path, or
/// a path their machine cannot run, and neither is a choice worth offering.
///
/// The crossover is a measured constant, and where it came from is recorded
/// next to it.
pub fn select(panels: usize, device: Option<&gpu::Device>) -> Backend {
    todo!()
}

/// What the matvec seam did.
///
/// Iteration count is visible in [`super::Accuracy`], but the work *inside* a
/// matvec is not: how many near-field blocks were evaluated, how many
/// far-field expansions, how much time went to transfer rather than compute.
/// That is the difference between a GPU path that wins and one that loses, and
/// it is invisible in the result.
pub trait ObserveMatVec: Observer {
    fn near_blocks(&mut self, count: u64);
    fn far_expansions(&mut self, count: u64);
    fn bytes_transferred(&mut self, bytes: u64);
}

impl ObserveMatVec for NoObserve {
    fn near_blocks(&mut self, count: u64) {}
    fn far_expansions(&mut self, count: u64) {}
    fn bytes_transferred(&mut self, bytes: u64) {}
}

use super::gpu;
