//! CPU data-parallel kernels for the parts of the pipeline the ExaFMM
//! literature vectorizes: the **P2P near-field direct interactions**
//! (embarrassingly data-parallel, compute-bound) and bulk Laplace kernel
//! evaluation. The inner kernel is explicit SIMD ([`crate::simd::p2p_accum`],
//! `wide::f64x4` with a masked self-interaction lane) over the
//! structure-of-arrays layout; `rayon` parallelizes across targets. The scalar
//! reference below stays as the accuracy gate.

use rayon::prelude::*;

/// Structure-of-arrays set of source points with scalar strengths.
pub struct Sources<'a> {
    pub x: &'a [f64],
    pub y: &'a [f64],
    pub z: &'a [f64],
    pub q: &'a [f64],
}

/// Direct (P2P) evaluation of the Laplace potential
///   φ(tᵢ) = Σ_j q_j / ‖tᵢ − s_j‖
/// at every target point, self-interaction (r == 0) skipped. This is the O(N²)
/// exact apply the FMM accelerates; it is also the exact near-field block in an
/// H²/HODLR representation.
///
/// The inner loop is explicit 4-lane SIMD (contiguous SoA reads, blended
/// r²>0 mask); `rayon` parallelizes across targets.
///
/// # Precision (measured)
/// This f64 path is the reference. The **near-field** use of this kernel MUST
/// stay f64: evaluating `1/r` in f32 for near-singular pairs (small `r`, heavy
/// cancellation) loses up to ~1.2e-4 relative — verified numerically. f32 is
/// only safe for the well-separated far-field block (~1e-7 relative there),
/// which is what the GPU runs; see `crate::gpu::Precision`.
pub fn p2p_laplace(
    tx: &[f64],
    ty: &[f64],
    tz: &[f64],
    src: &Sources,
    out: &mut [f64],
) {
    let n_t = tx.len();
    assert_eq!(ty.len(), n_t);
    assert_eq!(tz.len(), n_t);
    assert_eq!(out.len(), n_t);

    out.par_iter_mut().enumerate().for_each(|(i, oi)| {
        *oi = crate::simd::p2p_accum(tx[i], ty[i], tz[i], src.x, src.y, src.z, src.q);
    });
}

/// Single-threaded scalar reference (used to validate the parallel path bit-for-bit
/// up to reduction order).
pub fn p2p_laplace_scalar(
    tx: &[f64],
    ty: &[f64],
    tz: &[f64],
    src: &Sources,
    out: &mut [f64],
) {
    for i in 0..tx.len() {
        let (xi, yi, zi) = (tx[i], ty[i], tz[i]);
        let mut acc = 0.0;
        for j in 0..src.x.len() {
            let dx = xi - src.x[j];
            let dy = yi - src.y[j];
            let dz = zi - src.z[j];
            let r2 = dx * dx + dy * dy + dz * dz;
            if r2 > 0.0 {
                acc += src.q[j] / r2.sqrt();
            }
        }
        out[i] = acc;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parallel_matches_scalar() {
        let n = 200;
        let mk = |o: f64| (0..n).map(|i| (i as f64) * 0.01 + o).collect::<Vec<_>>();
        let (x, y, z) = (mk(0.0), mk(0.3), mk(0.7));
        let q: Vec<f64> = (0..n).map(|i| ((i % 7) as f64) - 3.0).collect();
        let src = Sources { x: &x, y: &y, z: &z, q: &q };
        let mut a = vec![0.0; n];
        let mut b = vec![0.0; n];
        p2p_laplace(&x, &y, &z, &src, &mut a);
        p2p_laplace_scalar(&x, &y, &z, &src, &mut b);
        for i in 0..n {
            assert!((a[i] - b[i]).abs() < 1e-9);
        }
    }
}
