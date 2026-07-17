//! Execution backend selection and the shared GPU context.
//!
//! Two backends: [`Backend::Cpu`] (always available, plain Rust) and
//! [`Backend::Gpu`] (Vulkano, AOT SPIR-V compute — see [`gpu`]). Unlike the
//! previous CubeCL/JIT design, GPU kernels are hand-written GLSL compiled to
//! SPIR-V at build time; there is no Rust-to-GPU transpilation. Each engine
//! owns its own shaders and drives them through the [`gpu`] context.

#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "gpu")]
pub mod gpu;
pub mod rule;

/// Where the per-element kernels run.
///
/// This enum is deliberately closed: there are exactly two execution targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Backend {
    /// Plain Rust on the host. Always available.
    Cpu,
    /// Vulkano compute (AOT SPIR-V). Requires the `gpu` feature and a device;
    /// callers fall back to [`Backend::Cpu`] when unavailable.
    Gpu,
}

impl Backend {
    /// Lowercase stable name, for telemetry and report fields.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Cpu => "cpu",
            Backend::Gpu => "gpu",
        }
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Is a Vulkan compute device actually usable right now?
///
/// Returns `false` without the `gpu` feature, or when no driver/device is
/// present. Device probing is panic-contained: a broken driver reads as "no
/// GPU", never a crash.
#[must_use]
pub fn gpu_ready() -> bool {
    #[cfg(feature = "gpu")]
    {
        gpu::ready()
    }
    #[cfg(not(feature = "gpu"))]
    {
        false
    }
}

/// Backends usable in this build on this machine. Always contains
/// [`Backend::Cpu`]; contains [`Backend::Gpu`] iff [`gpu_ready`].
#[must_use]
pub fn available_backends() -> Vec<Backend> {
    let mut v = vec![Backend::Cpu];
    if gpu_ready() {
        v.push(Backend::Gpu);
    }
    v
}

/// Telemetry captured during one engine run.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct BackendTelemetry {
    pub requested: String,
    pub actual: String,
    pub gpu_device: Option<String>,
    pub kernel_launches: u32,
    pub fallback_count: u32,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
}

impl BackendTelemetry {
    /// Start a telemetry record for a run that requested `requested` and is
    /// actually running on `actual` (they differ on a GPU→CPU fallback).
    #[must_use]
    pub fn new(requested: Backend, actual: Backend) -> Self {
        Self {
            requested: requested.as_str().to_owned(),
            actual: actual.as_str().to_owned(),
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_is_always_available() {
        assert!(available_backends().contains(&Backend::Cpu));
    }

    #[test]
    fn backend_names_are_stable() {
        assert_eq!(Backend::Cpu.as_str(), "cpu");
        assert_eq!(Backend::Gpu.to_string(), "gpu");
    }

    #[test]
    fn telemetry_records_requested_and_actual() {
        let t = BackendTelemetry::new(Backend::Gpu, Backend::Cpu);
        assert_eq!(t.requested, "gpu");
        assert_eq!(t.actual, "cpu");
        assert_eq!(t.kernel_launches, 0);
    }

    #[cfg(not(feature = "gpu"))]
    #[test]
    fn gpu_absent_without_feature() {
        assert!(!gpu_ready());
        assert_eq!(available_backends(), vec![Backend::Cpu]);
    }
}
