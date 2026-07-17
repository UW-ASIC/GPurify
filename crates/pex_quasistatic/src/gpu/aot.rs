//! GPU kernel target/precision *contract* — the specification surface for
//! which kernels exist and at what precisions.
//!
//! The primary GPU path uses Vulkano with AOT SPIR-V shaders (see
//! [`crate::gpu::vulkano_backend`]): GLSL compute shaders compiled to SPIR-V at
//! build time by `vulkano-shaders`. No JIT, ~1ms startup.
//!
//! This module captures the kernel/precision/target matrix as executable metadata:
//!
//!  1. Enumerate the **finite** set of kernel specializations the solver needs
//!     (kernel type × precision × a few tile/block configs) — see [`hot_kernels`].
//!  2. Shaders are compiled AOT at build time by vulkano-shaders.
//!  3. The CPU backend is always available as the CI/no-hardware fallback.
//!
//! No GPU toolchain is invoked here — this is the specification surface so the
//! kernel set, precisions, and target matrix are testable in CI without hardware.

use crate::gpu::backend::Precision;

/// A GPU code-generation target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// SPIR-V via Vulkano (Vulkan). Default GPU path.
    SpirV,
    /// CPU fallback — always available for CI.
    Cpu,
}

/// The dominant kernels from the design report §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelKind {
    /// Near-field direct MVP; batched over leaf-box pairs (dense diagonal blocks).
    P2P,
    /// Multipole-to-local translation; dense matrix products → batched GEMM.
    M2L,
    /// Tree M2M / L2L; small kernels, can stay on CPU.
    M2mL2l,
    /// Dense BLAS inside GMRES (gemv + Arnoldi orthogonalization).
    GmresBlas,
    /// Block-local preconditioner apply → batched small dense solves.
    PrecondApply,
}

/// A single kernel specialization to emit at build time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelSpec {
    pub kind: KernelKind,
    pub precision: Precision,
    /// Thread-block / tile size hint (the only "config" axis that matters for
    /// the dense kernels here).
    pub tile: u32,
}

/// The finite specialization set an AOT build enumerates. Deliberately small —
/// this is the whole point of AOT over shipping a gigabyte of every shape.
pub fn hot_kernels() -> Vec<KernelSpec> {
    use KernelKind::*;
    let mut v = Vec::new();
    for &kind in &[P2P, M2L, M2mL2l, GmresBlas, PrecondApply] {
        for &precision in &[Precision::F64, Precision::F32] {
            v.push(KernelSpec { kind, precision, tile: 128 });
        }
    }
    v
}

/// A build-time emitted artifact (bytes + which target produced it).
#[derive(Debug, Clone)]
pub struct KernelArtifact {
    pub spec: KernelSpec,
    pub target: Target,
    /// The emitted module text/bytes. For `Cpu` this is a human-readable
    /// pseudo-listing; for real targets a `build.rs` would replace this with the
    /// output of the respective codegen backend.
    pub module: String,
}

/// Emit a placeholder artifact describing one kernel/target pair. A real driver
/// swaps the body for the codegen backend's output; the *contract* (which specs,
/// which targets) is what this module pins down and CI checks.
pub fn emit(spec: &KernelSpec, target: Target) -> KernelArtifact {
    let module = format!(
        "; AOT stub for {:?} @ {:?} tile={} target={:?}\n; replace with {} codegen output in build.rs",
        spec.kind,
        spec.precision,
        spec.tile,
        target,
        match target {
            Target::SpirV => "vulkano (SPIR-V)",
            Target::Cpu => "CPU fallback",
        }
    );
    KernelArtifact { spec: *spec, target, module }
}

/// Emit the full matrix (every hot kernel × every requested target) — what a
/// `build.rs` would loop over.
pub fn emit_all(targets: &[Target]) -> Vec<KernelArtifact> {
    let mut out = Vec::new();
    for spec in hot_kernels() {
        for &t in targets {
            out.push(emit(&spec, t));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_set_is_finite_and_covered() {
        let specs = hot_kernels();
        assert_eq!(specs.len(), 10); // 5 kinds × 2 precisions
        let arts = emit_all(&[Target::SpirV, Target::Cpu]);
        assert_eq!(arts.len(), 20);
        assert!(arts.iter().all(|a| !a.module.is_empty()));
    }
}
