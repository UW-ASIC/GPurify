//! # quasiss
//!
//! Unified quasistatic field solver: FastHenry-class inductance and
//! FastCap-class capacitance extraction on one shared engine. Both tools are
//! *the same machine underneath*: a discretization of a first-kind integral
//! equation with the free-space Laplace Green's function G(x,x') = 1/‖x−x'‖,
//! a dense matrix apply, and a preconditioned Krylov solve. This crate builds
//! that machine once; [`cap`] and [`henry`] are thin front ends differing only
//! in physics, and [`gpu`] (feature `gpu`) offloads the throughput-bound
//! kernels to Vulkan via AOT-compiled SPIR-V.
//!
//! What lives here:
//!  * [`geometry`] — 3-D vector / frame primitives (SoA-friendly, no external deps).
//!  * [`constants`] — µ₀, ε₀ and the derived kernel constants.
//!  * [`kernel`] — the Laplace kernel and the [`kernel::LinearOperator`] matvec trait.
//!  * [`integrals`] — analytic near-field element integrals (Grover/Hoer filament
//!    inductance; Wilton polygon potentials) — the accuracy foundation.
//!  * [`linalg`] — dense FP64 matrices + LU (real and complex fields).
//!  * [`operator`] — dense operator and block-Jacobi preconditioner.
//!  * [`krylov`] — restarted GMRES(m) over the `LinearOperator` trait.
//!
//! Everything is FP64 to match the originals' accuracy. The accelerated matvec
//! (FMM / H²-matrix / GPU) is a future implementation of `LinearOperator` and
//! drops in without touching the front ends or the solver.

pub mod cap;
pub mod constants;
pub mod fmm;
pub mod geometry;
pub mod gpu;
pub mod henry;
pub mod integrals;
pub mod kernel;
pub mod krylov;
pub mod linalg;
pub mod operator;
pub mod p2p;
pub mod refine;
pub mod simd;

pub use geometry::{Frame, Vec3};
pub use kernel::{apply_vec, ComplexOperator, LinearOperator};
pub use krylov::{gmres, gmres_complex, gmres_complex_batched, GmresOptions, GmresResult, GmresResultMeta};
pub use linalg::{DenseMatrix, Field, LuDecomposition};
pub use operator::{
    BlockJacobi, BlockJacobiComplex, DenseComplexOperator, DenseOperator,
};
