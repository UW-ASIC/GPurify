//! GPU-backed implementations of the solver operator traits, shared by the
//! capacitance ([`crate::cap`]) and inductance ([`crate::henry`]) front ends.
//!
//! The matrix lives device-resident (f32, uploaded once); only vectors cross
//! the PCIe bus per GMRES iteration.

use std::sync::Arc;

use crate::gpu::backend::{ComputeBackend, GpuMatrixHandle};
use crate::gpu::vulkano_backend::VulkanoBackend;
use crate::kernel::{ComplexOperator, LinearOperator};
use num_complex::Complex64;

/// Dense real operator: y = A·x with A resident on the GPU.
pub struct GpuDenseOp {
    pub gpu: Arc<VulkanoBackend>,
    pub handle: GpuMatrixHandle,
}

impl LinearOperator for GpuDenseOp {
    fn dim(&self) -> usize {
        self.handle.rows
    }
    fn apply(&self, x: &[f64], y: &mut [f64]) {
        self.gpu.gemv_with_handle(&self.handle, x, y);
    }
}

/// Branch-impedance operator Zb = R + jωL with the real L **resident on the
/// GPU** (uploaded once per sweep, f32) and the diagonal R part applied on the
/// CPU in f64:
///   (R + jωL)(xᵣ + jxᵢ) = (R∘xᵣ − ω·L·xᵢ) + j(R∘xᵢ + ω·L·xᵣ)
/// Two real GEMVs per apply; only vectors cross the PCIe bus.
pub struct GpuZbOp<'a> {
    pub gpu: &'a VulkanoBackend,
    pub l_handle: &'a GpuMatrixHandle,
    pub r: &'a [f64],
    pub omega: f64,
}

impl GpuZbOp<'_> {
    /// Batched apply: Y = Zb·X for `ncols` columns stored concatenated
    /// (column c occupies `[c*n, (c+1)*n)` of `x` and `y`). All columns'
    /// re/im planes are packed into ONE row-major `n × 2·ncols` matrix
    /// `[Xre | Xim]`, so the device does a single GEMM dispatch per GMRES
    /// iteration instead of `2·ncols` GEMV round trips.
    pub fn apply_batch(&self, x: &[Complex64], y: &mut [Complex64], ncols: usize) {
        let n = self.r.len();
        assert_eq!(x.len(), n * ncols);
        assert_eq!(y.len(), n * ncols);
        let width = 2 * ncols;
        // B[j, c] = Re(x_c[j]), B[j, ncols + c] = Im(x_c[j]) — row-major.
        let mut bmat = vec![0.0f64; n * width];
        for c in 0..ncols {
            let xc = &x[c * n..(c + 1) * n];
            for j in 0..n {
                bmat[j * width + c] = xc[j].re;
                bmat[j * width + ncols + c] = xc[j].im;
            }
        }
        let lb = self.gpu.gemm_with_handle(self.l_handle, &bmat, width);
        // (R + jωL)(xᵣ + jxᵢ) = (R∘xᵣ − ω·L·xᵢ) + j(R∘xᵢ + ω·L·xᵣ)
        for c in 0..ncols {
            let xc = &x[c * n..(c + 1) * n];
            let yc = &mut y[c * n..(c + 1) * n];
            for j in 0..n {
                let lre = lb[j * width + c];
                let lim = lb[j * width + ncols + c];
                yc[j] = Complex64::new(
                    self.r[j] * xc[j].re - self.omega * lim,
                    self.r[j] * xc[j].im + self.omega * lre,
                );
            }
        }
    }
}

impl ComplexOperator for GpuZbOp<'_> {
    fn dim(&self) -> usize {
        self.r.len()
    }
    fn apply(&self, x: &[Complex64], y: &mut [Complex64]) {
        let n = self.r.len();
        let xre: Vec<f64> = x.iter().map(|c| c.re).collect();
        let xim: Vec<f64> = x.iter().map(|c| c.im).collect();
        let mut lre = vec![0.0; n];
        let mut lim = vec![0.0; n];
        self.gpu.gemv_with_handle(self.l_handle, &xre, &mut lre);
        self.gpu.gemv_with_handle(self.l_handle, &xim, &mut lim);
        for j in 0..n {
            y[j] = Complex64::new(
                self.r[j] * x[j].re - self.omega * lim[j],
                self.r[j] * x[j].im + self.omega * lre[j],
            );
        }
    }
}
