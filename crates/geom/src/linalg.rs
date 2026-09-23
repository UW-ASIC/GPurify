//! `f64` vector kernels for ERC power's CG and extract's GMRES.
//!
//! Every fold is a strict left fold in ascending index order; that order is interface
//! (it decides CG `alpha` and the convergence verdict), so do not reassociate.
//! `axpy`/`xpay` are element-wise, so they run on `f64x4` lanes bit-identically.

use fearless_simd::{dispatch, f64x4, prelude::*, Level};

/// Σ aᵢ·bᵢ.
#[inline]
pub fn dot(a: &[f64], b: &[f64]) -> f64 {
    let mut s = 0.0;
    for (x, y) in a.iter().zip(b) {
        s += x * y;
    }
    s
}

/// ‖a‖₂.
#[inline]
pub fn nrm2(a: &[f64]) -> f64 {
    dot(a, a).sqrt()
}

/// y += α·x, element-wise, no FMA.
pub fn axpy(alpha: f64, x: &[f64], y: &mut [f64]) {
    dispatch!(Level::new(), s => axpy_simd(s, alpha, x, y));
}

#[inline(always)]
fn axpy_simd<S: Simd>(s: S, alpha: f64, x: &[f64], y: &mut [f64]) {
    let n = x.len().min(y.len());
    let (x, y) = (&x[..n], &mut y[..n]);
    let a = f64x4::splat(s, alpha);
    let (xc, xt) = x.as_chunks::<4>();
    let (yc, yt) = y.as_chunks_mut::<4>();
    for (xv, yv) in xc.iter().zip(yc) {
        (f64x4::from_slice(s, yv) + a * f64x4::from_slice(s, xv)).store_slice(yv);
    }
    axpy_scalar(alpha, xt, yt);
}

fn axpy_scalar(alpha: f64, x: &[f64], y: &mut [f64]) {
    for (yj, xj) in y.iter_mut().zip(x) {
        *yj += alpha * xj;
    }
}

/// p = z + β·p, element-wise, no FMA: CG's search-direction update.
pub fn xpay(z: &[f64], beta: f64, p: &mut [f64]) {
    dispatch!(Level::new(), s => xpay_simd(s, z, beta, p));
}

#[inline(always)]
fn xpay_simd<S: Simd>(s: S, z: &[f64], beta: f64, p: &mut [f64]) {
    let n = z.len().min(p.len());
    let (z, p) = (&z[..n], &mut p[..n]);
    let b = f64x4::splat(s, beta);
    let (zc, zt) = z.as_chunks::<4>();
    let (pc, pt) = p.as_chunks_mut::<4>();
    for (zv, pv) in zc.iter().zip(pc) {
        (f64x4::from_slice(s, zv) + b * f64x4::from_slice(s, pv)).store_slice(pv);
    }
    xpay_scalar(zt, beta, pt);
}

fn xpay_scalar(z: &[f64], beta: f64, p: &mut [f64]) {
    for (pj, zj) in p.iter_mut().zip(z) {
        *pj = zj + beta * *pj;
    }
}

/// One sparse mat-vec: `out[i]` is row `i` of a CSR matrix times `v`.
pub fn spmv(row_start: &[u32], col: &[u32], value: &[f64], v: &[f64], out: &mut [f64]) {
    for (i, row) in out.iter_mut().enumerate() {
        let (from, to) = (row_start[i] as usize, row_start[i + 1] as usize);
        let mut acc = 0.0f64;
        for k in from..to {
            acc += value[k] * v[col[k] as usize];
        }
        *row = acc;
    }
}

#[cfg(test)]
#[expect(
    clippy::float_cmp,
    reason = "the fold order is interface, so these assert bits, not closeness"
)]
mod tests {
    use super::{axpy, axpy_scalar, dot, nrm2, spmv, xpay, xpay_scalar};

    /// Deterministic values mixing ordinary floats with the edge cases
    /// (signed zero, subnormal, infinities, NaN).
    fn column(seed: u64, n: usize) -> Vec<f64> {
        const EDGE: [f64; 6] = [
            0.0,
            -0.0,
            5e-324,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
        ];
        (0..n as u64)
            .map(|i| {
                let h = (seed ^ i)
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .rotate_left(29);
                if h.is_multiple_of(11) {
                    EDGE[(h >> 8) as usize % EDGE.len()]
                } else {
                    f64::from_bits(h >> 2) % 1e6 - 5e5
                }
            })
            .collect()
    }

    fn bits(v: &[f64]) -> Vec<u64> {
        v.iter().map(|x| x.to_bits()).collect()
    }

    #[test]
    fn the_lane_kernels_match_their_scalar_loops_bit_for_bit() {
        for n in 0..=13 {
            for seed in 0..8 {
                let (x, y) = (column(seed, n), column(seed + 100, n));
                let k = column(seed + 200, 1)[0];
                let (mut got, mut want) = (y.clone(), y.clone());
                axpy(k, &x, &mut got);
                axpy_scalar(k, &x, &mut want);
                assert_eq!(bits(&got), bits(&want), "axpy n={n} seed={seed}");
                let (mut got, mut want) = (y.clone(), y);
                xpay(&x, k, &mut got);
                xpay_scalar(&x, k, &mut want);
                assert_eq!(bits(&got), bits(&want), "xpay n={n} seed={seed}");
            }
        }
    }

    /// `cargo test -p gpurify-geom --release -- --ignored --nocapture bench_`
    #[test]
    #[ignore = "timing, not a check"]
    fn bench_axpy_xpay() {
        use std::hint::black_box;
        use std::time::Instant;
        type Kernel = fn(&[f64], &mut [f64]);
        let kernels: [(&str, Kernel); 4] = [
            ("axpy simd", |x, y| axpy(1e-3, x, y)),
            ("axpy scalar", |x, y| axpy_scalar(1e-3, x, y)),
            ("xpay simd", |x, y| xpay(x, 0.5, y)),
            ("xpay scalar", |x, y| xpay_scalar(x, 0.5, y)),
        ];
        for n in [1_000usize, 10_000, 100_000] {
            let x: Vec<f64> = (0..u32::try_from(n).unwrap())
                .map(|i| f64::from(i) * 0.37 + 1.0)
                .collect();
            let mut y = x.clone();
            let reps = 20_000_000 / n;
            for (name, f) in kernels {
                let best = (0..9)
                    .map(|_| {
                        let t = Instant::now();
                        for _ in 0..reps {
                            f(black_box(&x), black_box(&mut y));
                        }
                        t.elapsed() / u32::try_from(reps).unwrap()
                    })
                    .min()
                    .unwrap();
                println!("n={n} {name}: {best:?} (best of 9)");
            }
        }
    }

    /// `[[2, 0, 1], [0, 3, 0], [1, 0, 4]]` against `[1, 2, 3]`.
    #[test]
    fn spmv_reads_the_csr_it_is_given() {
        let row_start = [0u32, 2, 3, 5];
        let col = [0u32, 2, 1, 0, 2];
        let value = [2.0, 1.0, 3.0, 1.0, 4.0];
        let mut out = [0.0; 3];
        spmv(&row_start, &col, &value, &[1.0, 2.0, 3.0], &mut out);
        assert_eq!(out, [5.0, 6.0, 13.0]);
    }

    #[test]
    fn the_empty_case_is_zero_and_not_a_panic() {
        assert_eq!(dot(&[], &[]), 0.0);
        assert_eq!(nrm2(&[]), 0.0);
        let mut out: [f64; 0] = [];
        spmv(&[0], &[], &[], &[1.0], &mut out);
    }
}
