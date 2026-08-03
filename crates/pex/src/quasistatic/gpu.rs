//! The `f32` device adapter, and the contract it must meet to exist.
//!
//! This is the only GPU code in the workspace. Everything else that ran on a
//! device in the old tree was an advisory prefilter — flag candidates, then
//! check them exactly on the CPU anyway — which pays the whole transfer cost to
//! save part of the work, on kernels doing one integer modulo per element. No
//! amount of tuning clears that ceiling, so those are gone.
//!
//! # The contract
//!
//! From `docs/GPU.md`. This adapter does not ship unless all six hold, and if
//! any fails the CPU adapter is the answer and saying so is a complete result.
//!
//! 1. **Persistent buffers.** Allocated once per solve, reused across every
//!    iteration. No allocation inside the iteration loop.
//! 2. **Async submission.** No host wait between dependent dispatches. The old
//!    path called `.wait(None)` after every dispatch, so a 50–100 iteration
//!    GMRES became 50–100 round trips — that alone is why it measured ~1000×
//!    slower than the CPU.
//! 3. **Batched dispatch.** The far-field batch is one dispatch, not one per
//!    block.
//! 4. **`f64` residual.** Accuracy is bounded by a host `f64` residual check
//!    and the achieved value is reported. The old path computed in `f32` and
//!    never re-verified, on a signoff tool.
//! 5. **Equality tests that actually run.** Not `#[ignore]`d. Where no device
//!    exists the test asserts the fallback was taken; where one does, it
//!    asserts agreement with [`super::matvec::CpuMatVec`] within the documented
//!    tolerance.
//! 6. **A measured crossover.** Selected only above the size it was benchmarked
//!    to win at. Automatic, never a flag.

use super::matvec::{Backend, MatVec};
use super::mesh::Mesh;

/// A usable compute device.
///
/// `None` everywhere it appears means no device, or one that does not meet the
/// requirements. That is an ordinary outcome, not an error: the CPU adapter
/// produces the same answers.
#[derive(Debug)]
pub struct Device {
    // Instance, physical device, queue, and the compiled pipelines. AOT SPIR-V
    // compiled from GLSL at build time — no runtime shader compilation, so a
    // shader that does not compile is a build failure rather than a surprise on
    // a customer's machine.
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DeviceError {
    #[error("no compute device present")]
    NoDevice,
    #[error("device lacks a required feature: {0}")]
    MissingFeature(String),
    #[error("device has {available} bytes available, solve needs {needed}")]
    OutOfMemory { needed: u64, available: u64 },
    #[error("device lost during a solve")]
    Lost,
}

impl Device {
    /// Find a device meeting the requirements.
    ///
    /// Returns `Ok(None)` when there is simply no device — the common case on
    /// CI and on many desktops, and not a failure. `Err` is reserved for a
    /// device that exists but is unusable, which is worth telling someone about.
    pub fn find() -> Result<Option<Self>, DeviceError> {
        todo!()
    }

    /// Panel count above which this device beat the host, measured on the scale
    /// corpus.
    ///
    /// A property of the device, not a constant: the crossover on a laptop
    /// integrated part and on a discrete card are not the same number.
    pub fn crossover(&self) -> usize {
        todo!()
    }
}

/// Device-resident `f32` matvec.
///
/// **Five questions.** In: a mesh, uploaded once. Out: `y := A x` per call.
/// How many: one per solve, called once per GMRES iteration. Access pattern:
/// panel data is device-resident for the solve's lifetime and only the vectors
/// cross the bus — which is the difference between this and the old path, where
/// the input vector was re-uploaded on every call despite the matrix already
/// being resident. Lifetime: one solve. Parallelisable: it is the parallelism.
///
/// Multiplies in `f32`. That is safe only because
/// [`super::solve::refine`] wraps it in host `f64` refinement and the achieved
/// residual is measured, never assumed.
#[derive(Debug)]
pub struct GpuMatVec<'d> {
    device: &'d Device,
    // Persistent device buffers: panels, tree, expansions, and the two vectors.
    // Allocated in `upload`, never inside `apply`.
}

impl<'d> GpuMatVec<'d> {
    /// Upload a mesh and allocate every buffer the solve will use.
    ///
    /// Everything that can be allocated is allocated here, so [`MatVec::apply`]
    /// contains no allocation and no host synchronisation beyond the single
    /// fence on the result.
    pub fn upload(device: &'d Device, mesh: &Mesh) -> Result<Self, DeviceError> {
        todo!()
    }
}

impl MatVec for GpuMatVec<'_> {
    fn dim(&self) -> usize {
        todo!()
    }

    /// `y := A x`, with `x` converted to `f32` on upload and `y` widened back
    /// on readback.
    ///
    /// One fence, at the end, where the result is genuinely needed.
    fn apply(&self, x: &[f64], y: &mut [f64]) {
        todo!()
    }

    fn backend(&self) -> Backend {
        todo!()
    }
}
