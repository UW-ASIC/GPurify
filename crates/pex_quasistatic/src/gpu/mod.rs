//! # quasiss-gpu
//!
//! Backend-agnostic compute abstraction for offloading the throughput-bound
//! kernels (P2P near-field, batched-GEMM M2L, dense GMRES BLAS) to a GPU. The
//! interface mirrors a `ComputeClient`/`ComputeServer` split: a
//! [`ComputeBackend`] trait with device buffers and a small set of compute
//! entry points, with a working **CPU backend** that is bit-comparable to the
//! dense reference and runs in CI without hardware.
//!
//! ## GPU strategy: AOT SPIR-V via Vulkano
//! The [`vulkano_backend`] module (feature `gpu`, off by default) uses
//! [Vulkano](https://docs.rs/vulkano) with GLSL shaders compiled to SPIR-V at
//! build time by `vulkano-shaders`. No JIT, ~1ms startup vs ~550ms with the
//! previous CubeCL backend.
//!
//! The backend trait is the seam: dense today, Vulkano/FMM tomorrow, with no
//! change to the numerics crates.

pub mod aot;
pub mod backend;
pub mod kernels;

#[cfg(feature = "gpu")]
pub mod op;
#[cfg(feature = "gpu")]
pub mod vulkano_backend;

pub use backend::{ComputeBackend, CpuBackend, DeviceMatrix, GpuMatrixHandle, Precision};

#[cfg(feature = "gpu")]
pub use vulkano_backend::VulkanoBackend;

/// Start Vulkan instance/device/pipeline creation on a background thread so
/// the ~hundreds of ms of driver init overlap with parsing + matrix assembly.
/// `join()` the handle at first use.
#[cfg(feature = "gpu")]
pub fn spawn_backend() -> std::thread::JoinHandle<std::sync::Arc<VulkanoBackend>> {
    std::thread::spawn(|| std::sync::Arc::new(VulkanoBackend::new()))
}

/// CLI helper: spawn the backend if `--gpu` was requested. Without the `gpu`
/// feature this prints the fallback warning instead (and the caller's
/// GPU branch is compiled out).
#[cfg(feature = "gpu")]
pub fn cli_spawn(use_gpu: bool) -> Option<std::thread::JoinHandle<std::sync::Arc<VulkanoBackend>>> {
    use_gpu.then(spawn_backend)
}
#[cfg(not(feature = "gpu"))]
pub fn cli_spawn(use_gpu: bool) {
    if use_gpu {
        eprintln!("warning: --gpu requested but gpu feature not enabled, using CPU");
    }
}
