//! Explicit SIMD kernels (`wide::f64x4`, stable Rust — lowers to AVX/SSE/NEON
//! per target, scalar per lane where SIMD is absent) for the hot inner loops:
//! GMRES modified-Gram–Schmidt dot/axpy (real and split-plane complex), dense
//! GEMV rows, and the P2P Laplace kernel.
//!
//! Results differ from the scalar loops only by reassociation of the four
//! partial sums — bounded by the solver tolerances; the analytic integrals and
//! LU stay scalar f64.

use wide::{f64x4, CmpGt};

#[inline]
fn load(s: &[f64], j: usize) -> f64x4 {
    f64x4::from([s[j], s[j + 1], s[j + 2], s[j + 3]])
}

/// Σ aᵢ·bᵢ with 16 partial sums (4 vector accumulators × 4 lanes) so the
/// FMA chains stay throughput-bound, not latency-bound.
#[inline]
pub fn dot(a: &[f64], b: &[f64]) -> f64 {
    debug_assert_eq!(a.len(), b.len());
    let n = a.len();
    let n16 = n & !15;
    let (mut a0, mut a1, mut a2, mut a3) =
        (f64x4::ZERO, f64x4::ZERO, f64x4::ZERO, f64x4::ZERO);
    let mut j = 0;
    while j < n16 {
        a0 = load(a, j).mul_add(load(b, j), a0);
        a1 = load(a, j + 4).mul_add(load(b, j + 4), a1);
        a2 = load(a, j + 8).mul_add(load(b, j + 8), a2);
        a3 = load(a, j + 12).mul_add(load(b, j + 12), a3);
        j += 16;
    }
    let n4 = n & !3;
    while j < n4 {
        a0 = load(a, j).mul_add(load(b, j), a0);
        j += 4;
    }
    let mut s = ((a0 + a1) + (a2 + a3)).reduce_add();
    while j < n {
        s += a[j] * b[j];
        j += 1;
    }
    s
}

/// ‖a‖₂.
#[inline]
pub fn nrm2(a: &[f64]) -> f64 {
    dot(a, a).sqrt()
}

/// y += α·x (call with −α for the MGS update w −= h·v).
#[inline]
pub fn axpy(alpha: f64, x: &[f64], y: &mut [f64]) {
    debug_assert_eq!(x.len(), y.len());
    let n = x.len();
    let n4 = n & !3;
    let av = f64x4::splat(alpha);
    let mut j = 0;
    while j < n4 {
        let r = av.mul_add(load(x, j), load(y, j));
        y[j..j + 4].copy_from_slice(&r.to_array());
        j += 4;
    }
    while j < n {
        y[j] += alpha * x[j];
        j += 1;
    }
}

/// Split-plane complex (unconjugated) dot Σ (ar+i·ai)(xr+i·xi):
/// returns (Σ ar·xr − ai·xi, Σ ar·xi + ai·xr). One pass over all four lanes —
/// this is the GEMV row kernel; memory traffic equals the interleaved loop.
#[inline]
pub fn cdot(ar: &[f64], ai: &[f64], xr: &[f64], xi: &[f64]) -> (f64, f64) {
    let n = ar.len();
    let n4 = n & !3;
    let (mut are, mut aim) = (f64x4::ZERO, f64x4::ZERO);
    let mut j = 0;
    while j < n4 {
        let (arj, aij) = (load(ar, j), load(ai, j));
        let (xrj, xij) = (load(xr, j), load(xi, j));
        are = arj.mul_add(xrj, are) - aij * xij;
        aim = arj.mul_add(xij, aij.mul_add(xrj, aim));
        j += 4;
    }
    let (mut re, mut im) = (are.reduce_add(), aim.reduce_add());
    while j < n {
        re += ar[j] * xr[j] - ai[j] * xi[j];
        im += ar[j] * xi[j] + ai[j] * xr[j];
        j += 1;
    }
    (re, im)
}

/// Split-plane complex conjugated dot ⟨v, w⟩ = Σ (vr−i·vi)(wr+i·wi):
/// returns (Σ vr·wr + vi·wi, Σ vr·wi − vi·wr).
#[inline]
pub fn cdot_conj(vr: &[f64], vi: &[f64], wr: &[f64], wi: &[f64]) -> (f64, f64) {
    let n = vr.len();
    let n4 = n & !3;
    let (mut are, mut aim) = (f64x4::ZERO, f64x4::ZERO);
    let mut j = 0;
    while j < n4 {
        let (vrj, vij) = (load(vr, j), load(vi, j));
        let (wrj, wij) = (load(wr, j), load(wi, j));
        are = vrj.mul_add(wrj, vij.mul_add(wij, are));
        aim = vrj.mul_add(wij, aim) - vij * wrj;
        j += 4;
    }
    let (mut hre, mut him) = (are.reduce_add(), aim.reduce_add());
    while j < n {
        hre += vr[j] * wr[j] + vi[j] * wi[j];
        him += vr[j] * wi[j] - vi[j] * wr[j];
        j += 1;
    }
    (hre, him)
}

/// Split-plane complex MGS update w −= h·v:
///   wr −= hre·vr − him·vi,  wi −= hre·vi + him·vr.
#[inline]
pub fn caxpy(hre: f64, him: f64, vr: &[f64], vi: &[f64], wr: &mut [f64], wi: &mut [f64]) {
    let n = vr.len();
    let n4 = n & !3;
    let (hrev, himv) = (f64x4::splat(hre), f64x4::splat(him));
    let mut j = 0;
    while j < n4 {
        let (vrj, vij) = (load(vr, j), load(vi, j));
        let rr = load(wr, j) - (hrev * vrj - himv * vij);
        let ri = load(wi, j) - (hrev * vij + himv * vrj);
        wr[j..j + 4].copy_from_slice(&rr.to_array());
        wi[j..j + 4].copy_from_slice(&ri.to_array());
        j += 4;
    }
    while j < n {
        wr[j] -= hre * vr[j] - him * vi[j];
        wi[j] -= hre * vi[j] + him * vr[j];
        j += 1;
    }
}

/// P2P Laplace inner loop for one target: Σ_j q_j/‖t − s_j‖ with the r²=0
/// self-interaction masked out.
#[inline]
pub fn p2p_accum(
    xi: f64,
    yi: f64,
    zi: f64,
    sx: &[f64],
    sy: &[f64],
    sz: &[f64],
    sq: &[f64],
) -> f64 {
    let n = sx.len();
    let (xv, yv, zv) = (f64x4::splat(xi), f64x4::splat(yi), f64x4::splat(zi));
    #[inline(always)]
    fn body(
        j: usize,
        xv: f64x4,
        yv: f64x4,
        zv: f64x4,
        sx: &[f64],
        sy: &[f64],
        sz: &[f64],
        sq: &[f64],
    ) -> f64x4 {
        let dx = xv - load(sx, j);
        let dy = yv - load(sy, j);
        let dz = zv - load(sz, j);
        let r2 = dx.mul_add(dx, dy.mul_add(dy, dz * dz));
        let mask = r2.cmp_gt(f64x4::ZERO);
        let contrib = load(sq, j) / r2.sqrt(); // inf/NaN in masked-out lanes
        mask.blend(contrib, f64x4::ZERO)
    }
    // Two independent accumulators: the divide/sqrt pipe is the bottleneck,
    // and two chains keep it fed.
    let n8 = n & !7;
    let (mut acc0, mut acc1) = (f64x4::ZERO, f64x4::ZERO);
    let mut j = 0;
    while j < n8 {
        acc0 += body(j, xv, yv, zv, sx, sy, sz, sq);
        acc1 += body(j + 4, xv, yv, zv, sx, sy, sz, sq);
        j += 8;
    }
    let n4 = n & !3;
    while j < n4 {
        acc0 += body(j, xv, yv, zv, sx, sy, sz, sq);
        j += 4;
    }
    let mut s = (acc0 + acc1).reduce_add();
    while j < n {
        let dx = xi - sx[j];
        let dy = yi - sy[j];
        let dz = zi - sz[j];
        let r2 = dx * dx + dy * dy + dz * dz;
        if r2 > 0.0 {
            s += sq[j] / r2.sqrt();
        }
        j += 1;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(n: usize, k: f64) -> Vec<f64> {
        (0..n).map(|i| ((i * 37 % 101) as f64 - 50.0) * k).collect()
    }

    #[test]
    fn dot_matches_scalar() {
        for n in [0, 1, 3, 4, 7, 1000, 10_003] {
            let a = seq(n, 0.013);
            let b = seq(n, -0.007);
            let simd = dot(&a, &b);
            let scalar: f64 = a.iter().zip(&b).map(|(x, y)| x * y).sum();
            let denom = scalar.abs().max(1.0);
            assert!(
                (simd - scalar).abs() / denom < 1e-13,
                "n={n}: {simd} vs {scalar}"
            );
        }
    }

    #[test]
    fn axpy_matches_scalar() {
        let x = seq(1003, 0.011);
        let mut y = seq(1003, 0.023);
        let mut yref = y.clone();
        axpy(-1.7, &x, &mut y);
        for (yr, xv) in yref.iter_mut().zip(&x) {
            *yr += -1.7 * xv;
        }
        for (a, b) in y.iter().zip(&yref) {
            assert!((a - b).abs() < 1e-12);
        }
    }

    #[test]
    fn complex_kernels_match_scalar() {
        let n = 517;
        let (vr, vi) = (seq(n, 0.01), seq(n, 0.02));
        let (mut wr, mut wi) = (seq(n, 0.03), seq(n, -0.015));
        let (hre_s, him_s) = {
            let (mut hre, mut him) = (0.0, 0.0);
            for j in 0..n {
                hre += vr[j] * wr[j] + vi[j] * wi[j];
                him += vr[j] * wi[j] - vi[j] * wr[j];
            }
            (hre, him)
        };
        let (hre, him) = cdot_conj(&vr, &vi, &wr, &wi);
        assert!((hre - hre_s).abs() / hre_s.abs().max(1.0) < 1e-13);
        assert!((him - him_s).abs() / him_s.abs().max(1.0) < 1e-13);

        let (cre_s, cim_s) = {
            let (mut re, mut im) = (0.0, 0.0);
            for j in 0..n {
                re += vr[j] * wr[j] - vi[j] * wi[j];
                im += vr[j] * wi[j] + vi[j] * wr[j];
            }
            (re, im)
        };
        let (cre, cim) = cdot(&vr, &vi, &wr, &wi);
        assert!((cre - cre_s).abs() / cre_s.abs().max(1.0) < 1e-13);
        assert!((cim - cim_s).abs() / cim_s.abs().max(1.0) < 1e-13);

        let (mut wr_ref, mut wi_ref) = (wr.clone(), wi.clone());
        caxpy(hre, him, &vr, &vi, &mut wr, &mut wi);
        for j in 0..n {
            wr_ref[j] -= hre * vr[j] - him * vi[j];
            wi_ref[j] -= hre * vi[j] + him * vr[j];
        }
        for j in 0..n {
            assert!((wr[j] - wr_ref[j]).abs() < 1e-12);
            assert!((wi[j] - wi_ref[j]).abs() < 1e-12);
        }
    }
}
