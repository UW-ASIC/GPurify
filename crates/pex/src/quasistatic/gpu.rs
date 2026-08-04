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
        // ponytail: no device support is compiled in, so the honest probe
        // result is "no device". `vulkano`/`vulkano-shaders` are pinned in the
        // workspace manifest but are *not* dependencies of `gpurify-pex`, so
        // there is no path from here to a Vulkan instance. `docs/GPU.md`:
        // "Failing any of these, the CPU path is the answer, and saying so is a
        // complete result."
        //
        // Blocked, not unstarted — `docs/SIGNATURE_DEFECTS.md`, "pex
        // quasistatic/gpu.rs". Every step of the upgrade below lands in a file
        // other than this one, and the last needs hardware.
        //
        // Which contract items are open. 1, 2 and 3 are device-side and have
        // nothing to allocate, submit or batch until there is a queue. 6 needs
        // a benchmark, and inventing the number one would produce is exactly
        // the fail-open reading of the crossover that `matvec::select` asserts
        // against. Item 5 is met and met on the *host*, so no device gates it:
        // `tests/quasistatic.rs`
        // `the_device_is_selected_only_above_its_own_measured_crossover` runs
        // unignored, asserting the fallback on its no-device branch.
        //
        // Item 4 is met for the host adapter and **not** for a device one, and
        // an earlier version of this comment claimed otherwise. `solve::refine`
        // forms `b − A x` in `f64`, but the `A x` inside `solve::residual` goes
        // through the same operator as the inner solve, so under a `GpuF32`
        // adapter the bound carries that adapter's own ~1e-7 error and no
        // amount of iteration removes it. Textbook mixed-precision refinement
        // needs two operators — an accurate one for the residual, a fast one
        // for the correction — and `refine` takes one. Fail-closed, not a wrong
        // number: the achieved residual stalls above the default `1e-10` and
        // the caller gets `SolveError::NotConverged` rather than a quietly
        // `f32`-accurate capacitance. Filed under "pex quasistatic/solve.rs".
        //
        // `Ok(None)` rather than `Err(NoDevice)` deliberately: `NoDevice` is
        // for a probe that failed, and this one succeeded — it found nothing.
        // Every caller already handles `None` by taking the host adapter, which
        // is the reference implementation, so the fallback is fail-closed.
        //
        // What the probe must do once a Vulkan instance is reachable, since
        // that is the only step of the upgrade that lands in this body. The
        // return type already separates the two answers a user needs to tell
        // apart, and the split is: no loader, or an instance with zero physical
        // devices, is `Ok(None)` — "no GPU here". A physical device that exists
        // and is then *rejected* is `Err`, carrying which requirement it missed
        // — "a GPU is here and this is why it did not run". Enumerate, and for
        // each device check a queue family with `COMPUTE` set (`TRANSFER` is
        // implied by it, and `GRAPHICS` is not needed), then the two limits the
        // P2P Laplace kernel actually reads:
        // `max_compute_work_group_invocations` and
        // `max_compute_work_group_size[0]` against the workgroup size the
        // shader was compiled for, and `max_storage_buffer_range` against the
        // five `f32` panel columns plus the two vectors. Reject with
        // `MissingFeature`, naming the limit and both numbers. `shader_float64`
        // is deliberately *not* required — the `f32` matvec inside host `f64`
        // refinement is the whole design, and demanding `f64` on the device
        // would reject the target part for a feature this path does not use.
        //
        // Two things the probe cannot do, both frozen-signature facts rather
        // than omissions. `find` takes no arguments, so it does not know the
        // panel count and cannot size a heap against a solve — `OutOfMemory` is
        // reachable only from `upload`, which has the mesh. And `Lost` has no
        // reachable return site at all: `MatVec::apply` returns `()`, so an
        // adapter that loses its device mid-solve can only panic. Both are
        // filed under "pex quasistatic/gpu.rs".
        //
        // Upgrade path, in order: add the two `vulkano` crates to this crate's
        // manifest; AOT-compile the P2P Laplace shader, the only kernel
        // `docs/GPU.md` found GPU-suitable and already written — it is the
        // inner loop of `matvec::CpuMatVec::apply_observed`; the probe above;
        // then benchmark the crossover on the scale corpus and return it from
        // `crossover` below. One constraint that inner loop carries into the
        // port: its `j` fold is strictly left-to-right because the matrix is
        // byte-gated by `a_field_solve_is_byte_identical_across_runs`, so the
        // device kernel needs a *fixed* reduction order — a tree reduction
        // qualifies, an atomic accumulation does not. Neither agrees
        // bit-for-bit with the host fold, which is why item 5 asks for a
        // tolerance and why [`Backend`] exists to attribute the difference. No
        // signature above this line changes.
        Ok(None)
    }

    /// Panel count above which this device beat the host, measured on the scale
    /// corpus.
    ///
    /// A property of the device, not a constant: the crossover on a laptop
    /// integrated part and on a discrete card are not the same number.
    pub fn crossover(&self) -> usize {
        // No device has ever been measured, so there is no panel count above
        // which one was seen to win. `usize::MAX` is that statement in the
        // return type: `select` compares `panels >= crossover`, so the host
        // runs at every representable size.
        //
        // This is the fail-*closed* direction for a sentinel. Falling back to
        // the reference adapter costs throughput; the fail-open mistake would
        // be a small crossover, which would route a signoff number onto an
        // `f32` path nothing has ever validated. `> 0` also still holds, so the
        // measured-crossover assertion in
        // `pex/tests/quasistatic.rs::the_device_is_selected_only_above_its_own_measured_crossover`
        // does not weaken if a device ever does appear here.
        usize::MAX
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
    // Never read, and it cannot be: `upload` is the only constructor and it
    // always refuses, so no value of this type exists to read a field of. The
    // field stays because it is what gives `'d` something to bind — deleting it
    // makes the frozen `GpuMatVec<'d>` an unused-lifetime error, not a smaller
    // struct — and because `apply` needs the queue it names the moment a device
    // is real.
    #[expect(dead_code, reason = "Device::find yields no device; see upload")]
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
        debug_assert_eq!(
            mesh.panel.len(),
            mesh.epsilon.len(),
            "one permittivity per panel"
        );
        // [`Device::find`] is the only constructor and it never yields a
        // device, so nothing can reach this with a real `device` to upload to.
        // The typed error is the fail-closed answer: a caller that somehow
        // holds a `Device` gets a refusal it has to handle, never a `GpuMatVec`
        // whose buffers were never allocated.
        //
        // `_ = (device, mesh)` — both are the upload's inputs and both are
        // named in the signature; the panel columns, the tree and the two
        // vectors are allocated here once `find` can return a device.
        let _ = (device, mesh);
        Err(DeviceError::NoDevice)
    }
}

impl MatVec for GpuMatVec<'_> {
    fn dim(&self) -> usize {
        // [`GpuMatVec::upload`] is the only constructor and it always refuses,
        // so no value of this type exists to ask. Returning a number instead
        // would be a lie a solver would size its Krylov basis from.
        unreachable!("no GpuMatVec can be constructed: Device::find yields no device")
    }

    /// `y := A x`, with `x` converted to `f32` on upload and `y` widened back
    /// on readback.
    ///
    /// One fence, at the end, where the result is genuinely needed.
    fn apply(&self, x: &[f64], y: &mut [f64]) {
        // Unreachable for the same reason as `dim`. Stated as a panic rather
        // than as a quiet return: `y` is fully overwritten by contract, so a
        // body that returned without writing would hand GMRES the previous
        // iteration's vector and let a solve "converge" on nothing.
        let _ = (x, y);
        unreachable!("no GpuMatVec can be constructed: Device::find yields no device")
    }

    fn backend(&self) -> Backend {
        // Answerable without a device: this adapter is the `f32` device path,
        // whatever it is or is not able to do today. `Accuracy::backend` is how
        // a run's numbers are attributed, and an adapter that misnames itself
        // makes every attribution downstream a lie.
        Backend::GpuF32
    }
}
