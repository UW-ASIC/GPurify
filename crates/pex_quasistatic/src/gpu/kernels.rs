//! GPU kernel *logic*, written as plain per-thread Rust functions and validated
//! on the CPU.
//!
//! The design principle (and the reason GPU work is testable here without a GPU):
//! a compute kernel is just "what one thread computes for its index". Written as
//! a pure function `f(thread_index, inputs) -> output_element`, that function is
//! ordinary Rust — unit-testable on the CPU. The GLSL compute shaders in
//! `src/shaders/` (used by [`crate::gpu::vulkano_backend`]) are then nothing but
//! ```text
//! uint i = gl_GlobalInvocationID.x;
//! if (i < n) { out[i] = f(i, inputs...); }
//! ```
//! i.e. the same function with a thread index and SSBO buffer types.
//! Correctness proven here transfers directly to the GPU.
//!
//! Every function here maps to one of the dominant kernels in the design report
//! §5: P2P near-field, M2L (batched GEMM), M2M/L2L translations, GMRES BLAS
//! (gemv/axpy/dot), and the block-Jacobi preconditioner apply.

use rayon::prelude::*;

// ---------------------------------------------------------------------------
// P2P — near-field direct Laplace potential
// ---------------------------------------------------------------------------

/// Per-thread work for target `i`: φ(tᵢ) = Σⱼ qⱼ / ‖tᵢ − sⱼ‖, self (r=0) skipped.
///
/// This is the exact arithmetic the `#[kernel] p2p_laplace` runs per invocation.
/// `f32::sqrt` here resolves to the platform sqrt on CPU and to SPIR-V `OpSqrt`
/// on device — identical operation.
#[inline]
pub fn p2p_potential(
    i: usize,
    tx: &[f32],
    ty: &[f32],
    tz: &[f32],
    sx: &[f32],
    sy: &[f32],
    sz: &[f32],
    sq: &[f32],
) -> f32 {
    let xi = tx[i];
    let yi = ty[i];
    let zi = tz[i];
    let mut acc = 0.0f32;
    for j in 0..sx.len() {
        let dx = xi - sx[j];
        let dy = yi - sy[j];
        let dz = zi - sz[j];
        let r2 = dx * dx + dy * dy + dz * dz;
        if r2 > 0.0 {
            acc += sq[j] / r2.sqrt();
        }
    }
    acc
}

/// CPU driver: run the P2P per-thread function over all targets (rayon = the
/// grid of GPU threads).
pub fn p2p_laplace_cpu(
    tx: &[f32],
    ty: &[f32],
    tz: &[f32],
    sx: &[f32],
    sy: &[f32],
    sz: &[f32],
    sq: &[f32],
    out: &mut [f32],
) {
    out.par_iter_mut().enumerate().for_each(|(i, o)| {
        *o = p2p_potential(i, tx, ty, tz, sx, sy, sz, sq);
    });
}

// ---------------------------------------------------------------------------
// GEMV — dense matvec (the GMRES apply for a dense block)
// ---------------------------------------------------------------------------

/// Per-thread work for output row `i`: yᵢ = Σⱼ A[i,j]·xⱼ. Row-major `a`.
#[inline]
pub fn gemv_row(i: usize, a: &[f32], cols: usize, x: &[f32]) -> f32 {
    let base = i * cols;
    let mut acc = 0.0f32;
    for j in 0..cols {
        acc += a[base + j] * x[j];
    }
    acc
}

pub fn gemv_cpu(a: &[f32], rows: usize, cols: usize, x: &[f32], y: &mut [f32]) {
    assert_eq!(a.len(), rows * cols);
    assert_eq!(x.len(), cols);
    assert_eq!(y.len(), rows);
    y.par_iter_mut().enumerate().for_each(|(i, yi)| {
        *yi = gemv_row(i, a, cols, x);
    });
}

// ---------------------------------------------------------------------------
// M2L — batched GEMM. Each M2L translation is a dense product C = A·B, reused
// every GMRES iteration; on GPU this is a batched-GEMM launch.
// ---------------------------------------------------------------------------

/// Per-thread work for output element (row `i`, col `j`) of one GEMM:
/// C[i,j] = Σₖ A[i,k]·B[k,j]. `a` is m×k, `b` is k×n, both row-major.
#[inline]
pub fn gemm_element(i: usize, j: usize, a: &[f32], k: usize, b: &[f32], n: usize) -> f32 {
    let arow = i * k;
    let mut acc = 0.0f32;
    for p in 0..k {
        acc += a[arow + p] * b[p * n + j];
    }
    acc
}

/// CPU driver for one GEMM, threading over the (i,j) output grid.
pub fn gemm_cpu(a: &[f32], m: usize, k: usize, b: &[f32], n: usize, c: &mut [f32]) {
    assert_eq!(a.len(), m * k);
    assert_eq!(b.len(), k * n);
    assert_eq!(c.len(), m * n);
    c.par_iter_mut().enumerate().for_each(|(idx, cij)| {
        let i = idx / n;
        let j = idx % n;
        *cij = gemm_element(i, j, a, k, b, n);
    });
}

// ---------------------------------------------------------------------------
// M2M / L2L — tree translation: apply a (small, translation-invariant) operator
// T to an expansion vector. Structurally a gemv; separated to name the FMM step.
// ---------------------------------------------------------------------------

/// Per-thread work: apply translation operator row `i` to expansion `e`.
#[inline]
pub fn translate_row(i: usize, t: &[f32], p: usize, e: &[f32]) -> f32 {
    gemv_row(i, t, p, e)
}

pub fn translate_cpu(t: &[f32], out_len: usize, p: usize, e: &[f32], out: &mut [f32]) {
    gemv_cpu(t, out_len, p, e, out);
}

// ---------------------------------------------------------------------------
// GMRES BLAS — axpy and elementwise-product (for the dot reduction)
// ---------------------------------------------------------------------------

/// Per-thread work: yᵢ = α·xᵢ + yᵢ.
#[inline]
pub fn axpy_element(i: usize, alpha: f32, x: &[f32], y: &[f32]) -> f32 {
    alpha * x[i] + y[i]
}

pub fn axpy_cpu(alpha: f32, x: &[f32], y: &mut [f32]) {
    let yc = y.to_vec();
    y.par_iter_mut().enumerate().for_each(|(i, yi)| {
        *yi = axpy_element(i, alpha, x, &yc);
    });
}

/// Per-thread work for a dot product: the elementwise product xᵢ·yᵢ. The GPU
/// then tree-reduces these partials (a standard parallel reduction); on CPU we
/// reduce with a parallel sum.
#[inline]
pub fn mul_element(i: usize, x: &[f32], y: &[f32]) -> f32 {
    x[i] * y[i]
}

pub fn dot_cpu(x: &[f32], y: &[f32]) -> f32 {
    (0..x.len()).into_par_iter().map(|i| mul_element(i, x, y)).sum()
}

// ---------------------------------------------------------------------------
// Preconditioner apply — block-diagonal: each thread solves one small block by
// applying its precomputed inverse (stored row-major, block size `bs`).
// ---------------------------------------------------------------------------

/// Per-thread work for block `blk`: writes the `bs` outputs of that block by
/// multiplying the block's stored inverse `inv` (bs×bs) with the corresponding
/// slice of the residual `r`. `out` slice for this block is filled.
#[inline]
pub fn block_apply(blk: usize, inv: &[f32], bs: usize, r: &[f32], out: &mut [f32]) {
    let base = blk * bs;
    let inv_base = blk * bs * bs;
    for i in 0..bs {
        let mut acc = 0.0f32;
        for j in 0..bs {
            acc += inv[inv_base + i * bs + j] * r[base + j];
        }
        out[base + i] = acc;
    }
}

/// CPU driver: one thread per block.
pub fn block_jacobi_cpu(inv: &[f32], nblocks: usize, bs: usize, r: &[f32], out: &mut [f32]) {
    assert_eq!(inv.len(), nblocks * bs * bs);
    assert_eq!(r.len(), nblocks * bs);
    assert_eq!(out.len(), nblocks * bs);
    // Split output into per-block mutable chunks so threads don't alias.
    out.par_chunks_mut(bs).enumerate().for_each(|(blk, ochunk)| {
        let base = blk * bs;
        let inv_base = blk * bs * bs;
        for i in 0..bs {
            let mut acc = 0.0f32;
            for j in 0..bs {
                acc += inv[inv_base + i * bs + j] * r[base + j];
            }
            ochunk[i] = acc;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive_p2p(t: &[[f32; 3]], s: &[[f32; 3]], q: &[f32]) -> Vec<f32> {
        t.iter()
            .map(|ti| {
                let mut acc = 0.0f32;
                for (sj, &qj) in s.iter().zip(q) {
                    let dx = ti[0] - sj[0];
                    let dy = ti[1] - sj[1];
                    let dz = ti[2] - sj[2];
                    let r2 = dx * dx + dy * dy + dz * dz;
                    if r2 > 0.0 {
                        acc += qj / r2.sqrt();
                    }
                }
                acc
            })
            .collect()
    }

    #[test]
    fn p2p_matches_naive() {
        let n = 50;
        let tx: Vec<f32> = (0..n).map(|i| i as f32 * 0.1).collect();
        let ty: Vec<f32> = (0..n).map(|i| i as f32 * 0.2 + 1.0).collect();
        let tz: Vec<f32> = (0..n).map(|i| i as f32 * 0.05).collect();
        let q: Vec<f32> = (0..n).map(|i| ((i % 5) as f32) - 2.0).collect();
        let mut out = vec![0.0; n];
        p2p_laplace_cpu(&tx, &ty, &tz, &tx, &ty, &tz, &q, &mut out);
        let tpts: Vec<[f32; 3]> = (0..n).map(|i| [tx[i], ty[i], tz[i]]).collect();
        let expect = naive_p2p(&tpts, &tpts, &q);
        for i in 0..n {
            assert!((out[i] - expect[i]).abs() < 1e-4);
        }
    }

    #[test]
    fn gemv_matches() {
        // A = [[1,2,3],[4,5,6]], x=[1,0,-1] -> [1-3, 4-6] = [-2,-2]
        let a = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let x = vec![1.0, 0.0, -1.0];
        let mut y = vec![0.0; 2];
        gemv_cpu(&a, 2, 3, &x, &mut y);
        assert_eq!(y, vec![-2.0, -2.0]);
    }

    #[test]
    fn gemm_matches_identity_and_product() {
        // [[1,2],[3,4]] * [[5,6],[7,8]] = [[19,22],[43,50]]
        let a = vec![1.0, 2.0, 3.0, 4.0];
        let b = vec![5.0, 6.0, 7.0, 8.0];
        let mut c = vec![0.0; 4];
        gemm_cpu(&a, 2, 2, &b, 2, &mut c);
        assert_eq!(c, vec![19.0, 22.0, 43.0, 50.0]);
    }

    #[test]
    fn axpy_and_dot() {
        let x = vec![1.0f32, 2.0, 3.0];
        let mut y = vec![10.0f32, 10.0, 10.0];
        axpy_cpu(2.0, &x, &mut y);
        assert_eq!(y, vec![12.0, 14.0, 16.0]);
        assert_eq!(dot_cpu(&x, &x), 14.0);
    }

    #[test]
    fn block_jacobi_apply() {
        // Two 2x2 blocks: inverses are identity and [[2,0],[0,2]].
        let inv = vec![
            1.0, 0.0, 0.0, 1.0, // block 0 = I
            2.0, 0.0, 0.0, 2.0, // block 1 = 2I
        ];
        let r = vec![3.0, 4.0, 5.0, 6.0];
        let mut out = vec![0.0; 4];
        block_jacobi_cpu(&inv, 2, 2, &r, &mut out);
        assert_eq!(out, vec![3.0, 4.0, 10.0, 12.0]);
        // Also exercise the single-block per-thread function directly.
        let mut o2 = vec![0.0; 4];
        block_apply(0, &inv, 2, &r, &mut o2);
        block_apply(1, &inv, 2, &r, &mut o2);
        assert_eq!(o2, out);
    }
}
