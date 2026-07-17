//! The free-space Laplace Green's function G(x,x') = 1/‖x−x'‖ and the abstract
//! `LinearOperator` interface that every matvec (dense, FMM, H²-matrix, or GPU)
//! implements. GMRES/GCR only ever see this trait — never the explicit matrix —
//! which is exactly how FastHenry and FastCap are structured.

use crate::quasistatic::geometry::Vec3;

/// The scalar Laplace kernel 1/r. Returns 0 for coincident points (the singular
/// self-interaction is always handled by an analytic element integral, never by
/// this point kernel).
#[inline]
pub fn laplace(x: Vec3, xp: Vec3) -> f64 {
    let r = x.dist(xp);
    if r == 0.0 {
        0.0
    } else {
        1.0 / r
    }
}

/// Gradient of the Laplace kernel with respect to the observation point `x`:
/// ∇ₓ (1/r) = −(x−x')/r³.
#[inline]
pub fn laplace_grad(x: Vec3, xp: Vec3) -> Vec3 {
    let d = x - xp;
    let r2 = d.norm2();
    if r2 == 0.0 {
        Vec3::ZERO
    } else {
        let r = r2.sqrt();
        d * (-1.0 / (r2 * r))
    }
}

/// A generic linear operator y = A·x over `f64` (real systems). The whole point
/// of the integral-equation formulation is that A is available only through this
/// apply; the accelerator (dense today, FMM/H²/GPU later) is swapped behind it
/// without the Krylov solver noticing.
pub trait LinearOperator {
    /// Dimension n of the (square) operator.
    fn dim(&self) -> usize;
    /// Compute y = A·x. `x.len() == y.len() == dim()`.
    fn apply(&self, x: &[f64], y: &mut [f64]);
}

/// Blanket helper: allocate and return A·x.
pub fn apply_vec(op: &dyn LinearOperator, x: &[f64]) -> Vec<f64> {
    let mut y = vec![0.0; op.dim()];
    op.apply(x, &mut y);
    y
}

use num_complex::Complex64;

/// The complex analogue of [`LinearOperator`], for the frequency-domain
/// impedance operator Z(ω) = R + jωL that FastHenry solves. Same contract: the
/// solver only ever sees this apply, never the explicit dense matrix.
pub trait ComplexOperator {
    fn dim(&self) -> usize;
    fn apply(&self, x: &[Complex64], y: &mut [Complex64]);
}
