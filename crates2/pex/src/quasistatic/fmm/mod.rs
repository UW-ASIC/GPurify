//! Kernel-independent (black-box) fast multipole method for the Laplace kernel.
pub mod bbfmm;
pub mod chebyshev;
pub mod tree;

pub use bbfmm::LaplaceFmm;
