//! Restarted GMRES(m) for the real, nonsymmetric dense operators produced by the
//! integral-equation discretization. This is the iterative path (FastHenry uses
//! GMRES, FastCap uses GCR — both minimal-residual methods needing only a
//! matvec); it operates purely through the [`LinearOperator`] trait so the
//! underlying apply can be dense (today) or FMM/H²/GPU (later) with no change.
//!
//! A right preconditioner M⁻¹ is supported via the same trait, matching the
//! physically-local (block-Jacobi) preconditioner both original tools use.

use crate::kernel::LinearOperator;

/// Convergence / iteration controls.
#[derive(Debug, Clone, Copy)]
pub struct GmresOptions {
    /// Relative residual tolerance ‖b − Ax‖/‖b‖ (FastHenry default 1e-3,
    /// FastCap 1e-2; tighten as needed to match the originals).
    pub tol: f64,
    /// Restart length m.
    pub restart: usize,
    /// Maximum outer restart cycles.
    pub max_restarts: usize,
}

impl Default for GmresOptions {
    fn default() -> Self {
        GmresOptions {
            tol: 1e-3,
            restart: 50,
            max_restarts: 40,
        }
    }
}

/// Result of a GMRES solve.
#[derive(Debug, Clone)]
pub struct GmresResult {
    pub x: Vec<f64>,
    pub iterations: usize,
    pub residual: f64,
    pub converged: bool,
}

use crate::simd::{dot, nrm2};

/// Restarted GMRES(m) with an optional right preconditioner.
///
/// Solves A·x = b. If `precond` is `Some(M)`, solves A·M⁻¹·(M·x) = b using the
/// operator `M` as an *approximate inverse* apply (i.e. `precond.apply` computes
/// z = M⁻¹·r directly).
pub fn gmres(
    a: &dyn LinearOperator,
    b: &[f64],
    precond: Option<&dyn LinearOperator>,
    opts: GmresOptions,
) -> GmresResult {
    let n = a.dim();
    assert_eq!(b.len(), n);
    let bnorm = nrm2(b).max(f64::MIN_POSITIVE);

    let mut x = vec![0.0; n];
    let mut total_iters = 0;

    // ponytail: workspace buffers reused across all iterations/restarts —
    // the only per-iteration alloc left is the Krylov basis vector itself.
    let mut z = vec![0.0; n];
    let mut ax = vec![0.0; n];

    for _cycle in 0..opts.max_restarts {
        // r = b - A x
        a.apply(&x, &mut ax);
        let mut r: Vec<f64> = b.iter().zip(&ax).map(|(bi, axi)| bi - axi).collect();
        let beta = nrm2(&r);
        if beta / bnorm <= opts.tol {
            return GmresResult { x, iterations: total_iters, residual: beta / bnorm, converged: true };
        }

        let m = opts.restart;
        let mut v: Vec<Vec<f64>> = Vec::with_capacity(m + 1);
        for vi in r.iter_mut() {
            *vi /= beta;
        }
        v.push(r);

        // Hessenberg matrix H (m+1 x m), Givens rotations, and the residual RHS g.
        let mut h = vec![vec![0.0f64; m]; m + 1];
        let mut cs = vec![0.0f64; m];
        let mut sn = vec![0.0f64; m];
        let mut g = vec![0.0f64; m + 1];
        g[0] = beta;

        let mut k_used = 0;
        for k in 0..m {
            // Arnoldi with right preconditioning: w = A M⁻¹ v_k
            let zk: &[f64] = match precond {
                Some(mp) => {
                    mp.apply(&v[k], &mut z);
                    &z
                }
                None => &v[k],
            };
            let mut w = vec![0.0; n];
            a.apply(zk, &mut w);

            // Modified Gram–Schmidt (SIMD dot/axpy).
            for i in 0..=k {
                h[i][k] = dot(&w, &v[i]);
                crate::simd::axpy(-h[i][k], &v[i], &mut w);
            }
            h[k + 1][k] = nrm2(&w);

            // Happy breakdown or new basis vector.
            if h[k + 1][k] > 1e-14 {
                for wj in w.iter_mut() {
                    *wj /= h[k + 1][k];
                }
            }
            v.push(w);

            // Apply previous Givens rotations to the new column of H.
            for i in 0..k {
                let temp = cs[i] * h[i][k] + sn[i] * h[i + 1][k];
                h[i + 1][k] = -sn[i] * h[i][k] + cs[i] * h[i + 1][k];
                h[i][k] = temp;
            }
            // Compute and apply the new rotation to eliminate h[k+1][k].
            let (c, s) = givens(h[k][k], h[k + 1][k]);
            cs[k] = c;
            sn[k] = s;
            h[k][k] = c * h[k][k] + s * h[k + 1][k];
            h[k + 1][k] = 0.0;
            let temp = c * g[k] + s * g[k + 1];
            g[k + 1] = -s * g[k] + c * g[k + 1];
            g[k] = temp;

            total_iters += 1;
            k_used = k + 1;

            let resid = g[k + 1].abs() / bnorm;
            if resid <= opts.tol {
                break;
            }
        }

        // Solve the upper-triangular system H y = g (size k_used).
        let mut y = vec![0.0; k_used];
        for i in (0..k_used).rev() {
            let mut sum = g[i];
            for j in (i + 1)..k_used {
                sum -= h[i][j] * y[j];
            }
            y[i] = sum / h[i][i];
        }

        // Update solution: x += M⁻¹ (Σ y_i v_i).
        let mut dx = vec![0.0; n];
        for i in 0..k_used {
            for j in 0..n {
                dx[j] += y[i] * v[i][j];
            }
        }
        let dz: &[f64] = match precond {
            Some(mp) => {
                mp.apply(&dx, &mut z);
                &z
            }
            None => &dx,
        };
        for j in 0..n {
            x[j] += dz[j];
        }

        // ponytail: skip extra matvec for true residual unless estimated residual
        // is within 10× of tolerance (Givens residual is exact in exact arithmetic)
        let est_resid = g[k_used].abs() / bnorm;
        if est_resid <= opts.tol * 10.0 {
            a.apply(&x, &mut ax);
            let r2: Vec<f64> = b.iter().zip(&ax).map(|(bi, axi)| bi - axi).collect();
            let resid = nrm2(&r2) / bnorm;
            if resid <= opts.tol {
                return GmresResult { x, iterations: total_iters, residual: resid, converged: true };
            }
        }
    }

    // Not converged within max_restarts; return best iterate.
    let mut ax = vec![0.0; n];
    a.apply(&x, &mut ax);
    let r: Vec<f64> = b.iter().zip(&ax).map(|(bi, axi)| bi - axi).collect();
    let resid = nrm2(&r) / bnorm;
    GmresResult { x, iterations: total_iters, residual: resid, converged: false }
}

/// Stable Givens rotation coefficients eliminating `b` against `a`.
#[inline]
fn givens(a: f64, b: f64) -> (f64, f64) {
    if b == 0.0 {
        (1.0, 0.0)
    } else if b.abs() > a.abs() {
        let t = a / b;
        let s = 1.0 / (1.0 + t * t).sqrt();
        (t * s, s)
    } else {
        let t = b / a;
        let c = 1.0 / (1.0 + t * t).sqrt();
        (c, t * c)
    }
}

// ===========================================================================
// Complex restarted GMRES(m) for the frequency-domain impedance operator.
// ===========================================================================

use crate::kernel::ComplexOperator;
use num_complex::Complex64;

#[inline]
fn cnrm2(a: &[Complex64]) -> f64 {
    a.iter().map(|z| z.norm_sqr()).sum::<f64>().sqrt()
}

/// Complex Givens rotation zeroing `b` against `a` (LAPACK zlartg-style):
/// returns real `c` and complex `s` with c² + |s|² = 1 such that
/// [c, s; −conj(s), c]·[a; b] = [r; 0].
fn givens_c(a: Complex64, b: Complex64) -> (f64, Complex64) {
    if b == Complex64::new(0.0, 0.0) {
        return (1.0, Complex64::new(0.0, 0.0));
    }
    let fa = a.norm();
    if fa == 0.0 {
        return (0.0, Complex64::new(1.0, 0.0));
    }
    let den = (fa * fa + b.norm_sqr()).sqrt();
    let c = fa / den;
    let s = (a / fa) * b.conj() / den;
    (c, s)
}

/// Restarted GMRES(m) for a complex operator, with an optional complex right
/// preconditioner (`precond.apply` computes z = M⁻¹·r). Solves A·x = b.
pub fn gmres_complex(
    a: &dyn ComplexOperator,
    b: &[Complex64],
    precond: Option<&dyn ComplexOperator>,
    opts: GmresOptions,
) -> (Vec<Complex64>, GmresResultMeta) {
    let n = a.dim();
    assert_eq!(b.len(), n);
    let zero = Complex64::new(0.0, 0.0);
    let bnorm = cnrm2(b).max(f64::MIN_POSITIVE);
    let mut x = vec![zero; n];
    let mut total_iters = 0;

    // ponytail: workspace buffers reused across all iterations/restarts
    let mut z = vec![zero; n];
    let mut ax = vec![zero; n];

    // ponytail: the Krylov basis is stored as split re/im planes so the MGS
    // orthogonalization (the memory-bound hot loop) runs on contiguous f64
    // slices the compiler vectorizes; Complex64 appears only at the operator
    // boundary.
    let mut vk_c = vec![zero; n]; // interleaved copy of v[k] for the operator

    for _cycle in 0..opts.max_restarts {
        a.apply(&x, &mut ax);
        let r: Vec<Complex64> = b.iter().zip(&ax).map(|(bi, axi)| bi - axi).collect();
        let beta = cnrm2(&r);
        if beta / bnorm <= opts.tol {
            return (x, GmresResultMeta { iterations: total_iters, residual: beta / bnorm, converged: true });
        }

        let m = opts.restart;
        let mut vre: Vec<Vec<f64>> = Vec::with_capacity(m + 1);
        let mut vim: Vec<Vec<f64>> = Vec::with_capacity(m + 1);
        let inv_beta = 1.0 / beta;
        vre.push(r.iter().map(|c| c.re * inv_beta).collect());
        vim.push(r.iter().map(|c| c.im * inv_beta).collect());

        let mut h = vec![vec![zero; m]; m + 1];
        let mut cs = vec![0.0f64; m];
        let mut sn = vec![zero; m];
        let mut g = vec![zero; m + 1];
        g[0] = Complex64::new(beta, 0.0);

        let mut k_used = 0;
        for k in 0..m {
            for j in 0..n {
                vk_c[j] = Complex64::new(vre[k][j], vim[k][j]);
            }
            let zk: &[Complex64] = match precond {
                Some(mp) => {
                    mp.apply(&vk_c, &mut z);
                    &z
                }
                None => &vk_c,
            };
            let mut w = vec![zero; n];
            a.apply(zk, &mut w);
            let mut wre: Vec<f64> = w.iter().map(|c| c.re).collect();
            let mut wim: Vec<f64> = w.iter().map(|c| c.im).collect();

            // Modified Gram–Schmidt on split planes (SIMD):
            //   h = <v_i, w> = Σ (vre−i·vim)(wre+i·wim)
            for i in 0..=k {
                let (vr, vi) = (&vre[i], &vim[i]);
                let (hre, him) = crate::simd::cdot_conj(vr, vi, &wre, &wim);
                h[i][k] = Complex64::new(hre, him);
                // w -= h·v_i  (complex product in split form)
                crate::simd::caxpy(hre, him, vr, vi, &mut wre, &mut wim);
            }
            let hk1 = (dot(&wre, &wre) + dot(&wim, &wim)).sqrt();
            h[k + 1][k] = Complex64::new(hk1, 0.0);
            if hk1 > 1e-14 {
                let inv = 1.0 / hk1;
                for j in 0..n {
                    wre[j] *= inv;
                    wim[j] *= inv;
                }
            }
            vre.push(wre);
            vim.push(wim);

            // Apply previous rotations.
            for i in 0..k {
                let temp = Complex64::new(cs[i], 0.0) * h[i][k] + sn[i] * h[i + 1][k];
                h[i + 1][k] = -sn[i].conj() * h[i][k] + Complex64::new(cs[i], 0.0) * h[i + 1][k];
                h[i][k] = temp;
            }
            let (c, s) = givens_c(h[k][k], h[k + 1][k]);
            cs[k] = c;
            sn[k] = s;
            h[k][k] = Complex64::new(c, 0.0) * h[k][k] + s * h[k + 1][k];
            h[k + 1][k] = zero;
            let temp = Complex64::new(c, 0.0) * g[k] + s * g[k + 1];
            g[k + 1] = -s.conj() * g[k] + Complex64::new(c, 0.0) * g[k + 1];
            g[k] = temp;

            total_iters += 1;
            k_used = k + 1;
            if g[k + 1].norm() / bnorm <= opts.tol {
                break;
            }
        }

        // Back-substitute H y = g.
        let mut y = vec![zero; k_used];
        for i in (0..k_used).rev() {
            let mut sum = g[i];
            for j in (i + 1)..k_used {
                sum -= h[i][j] * y[j];
            }
            y[i] = sum / h[i][i];
        }
        let mut dx = vec![zero; n];
        for i in 0..k_used {
            let (yi, vr, vi) = (y[i], &vre[i], &vim[i]);
            for j in 0..n {
                dx[j] += yi * Complex64::new(vr[j], vi[j]);
            }
        }
        let dz: &[Complex64] = match precond {
            Some(mp) => {
                mp.apply(&dx, &mut z);
                &z
            }
            None => &dx,
        };
        for j in 0..n {
            x[j] += dz[j];
        }

        a.apply(&x, &mut ax);
        let r2: Vec<Complex64> = b.iter().zip(&ax).map(|(bi, axi)| bi - axi).collect();
        let resid = cnrm2(&r2) / bnorm;
        if resid <= opts.tol {
            return (x, GmresResultMeta { iterations: total_iters, residual: resid, converged: true });
        }
    }

    let mut ax = vec![zero; n];
    a.apply(&x, &mut ax);
    let r: Vec<Complex64> = b.iter().zip(&ax).map(|(bi, axi)| bi - axi).collect();
    let resid = cnrm2(&r) / bnorm;
    (x, GmresResultMeta { iterations: total_iters, residual: resid, converged: false })
}

/// Convergence metadata returned by [`gmres_complex`].
#[derive(Debug, Clone, Copy)]
pub struct GmresResultMeta {
    pub iterations: usize,
    pub residual: f64,
    pub converged: bool,
}

// ===========================================================================
// Batched complex GMRES — many RHS of the SAME operator advanced in lockstep
// so each iteration is ONE block apply (one GPU dispatch) instead of
// ncols independent matvecs.
// ===========================================================================

/// Per-column solve state for [`gmres_complex_batched`].
struct BatchCol<'a> {
    b: &'a [Complex64],
    bnorm: f64,
    x: Vec<Complex64>,
    // Krylov basis in split re/im planes (same layout as gmres_complex).
    vre: Vec<Vec<f64>>,
    vim: Vec<Vec<f64>>,
    h: Vec<Vec<Complex64>>,
    cs: Vec<f64>,
    sn: Vec<Complex64>,
    g: Vec<Complex64>,
    k: usize,
    cycle: usize,
    /// true → next apply is A·x for a residual check; false → Arnoldi step.
    residual_phase: bool,
    done: bool,
    converged: bool,
    residual: f64,
}

/// Batched restarted GMRES(m) for one complex operator applied to many
/// right-hand sides. `apply_block(x, y, ncols)` must compute yᶜ = A·xᶜ for
/// `ncols` columns stored concatenated (column c occupies `[c*n, (c+1)*n)`).
/// The point: all active columns share ONE block apply per iteration, so a GPU
/// backend does a single GEMM dispatch instead of ncols GEMVs.
///
/// Per-column tolerance/restart/max_restarts semantics match [`gmres_complex`];
/// converged columns drop out of the batch (compaction). Results satisfy the
/// same residual tolerance but are not bit-identical to the per-column path
/// (the redundant end-of-cycle/start-of-cycle residual apply is deduplicated).
pub fn gmres_complex_batched<F>(
    apply_block: F,
    rhs: &[Vec<Complex64>],
    precond: Option<&(dyn ComplexOperator + Sync)>,
    opts: GmresOptions,
) -> Vec<(Vec<Complex64>, GmresResultMeta)>
where
    F: Fn(&[Complex64], &mut [Complex64], usize),
{
    use rayon::prelude::*;
    let zero = Complex64::new(0.0, 0.0);
    if rhs.is_empty() {
        return Vec::new();
    }
    let n = rhs[0].len();
    let m = opts.restart;

    let mut cols: Vec<BatchCol> = rhs
        .iter()
        .map(|b| {
            assert_eq!(b.len(), n);
            BatchCol {
                b,
                bnorm: cnrm2(b).max(f64::MIN_POSITIVE),
                x: vec![zero; n],
                vre: Vec::new(),
                vim: Vec::new(),
                h: Vec::new(),
                cs: Vec::new(),
                sn: Vec::new(),
                g: Vec::new(),
                k: 0,
                cycle: 0,
                residual_phase: true,
                done: false,
                converged: false,
                residual: f64::INFINITY,
            }
        })
        .collect();

    let mut xbuf: Vec<Complex64> = Vec::new();
    let mut ybuf: Vec<Complex64> = Vec::new();

    loop {
        let mut active: Vec<&mut BatchCol> =
            cols.iter_mut().filter(|c| !c.done).collect();
        if active.is_empty() {
            break;
        }
        let ncols = active.len();
        xbuf.resize(ncols * n, zero);
        ybuf.resize(ncols * n, zero);

        // Build phase: each active column contributes the vector to apply —
        // its iterate x (residual check) or M⁻¹·v_k (Arnoldi step).
        active
            .par_iter()
            .zip(xbuf.par_chunks_mut(n))
            .for_each(|(col, chunk)| {
                if col.residual_phase {
                    chunk.copy_from_slice(&col.x);
                } else {
                    let k = col.k;
                    for j in 0..n {
                        chunk[j] = Complex64::new(col.vre[k][j], col.vim[k][j]);
                    }
                    if let Some(mp) = precond {
                        let mut z = vec![zero; n];
                        mp.apply(chunk, &mut z);
                        chunk.copy_from_slice(&z);
                    }
                }
            });

        // ONE block apply for the whole batch.
        apply_block(&xbuf, &mut ybuf, ncols);

        // Consume phase: per-column CPU work (MGS / Givens / restart logic).
        active
            .par_iter_mut()
            .zip(ybuf.par_chunks(n))
            .for_each(|(col, y)| {
                if col.residual_phase {
                    consume_residual(col, y, m, opts, zero);
                } else {
                    consume_arnoldi(col, y, n, m, opts, precond, zero);
                }
            });
    }

    cols.into_iter()
        .map(|c| {
            (
                c.x,
                GmresResultMeta {
                    iterations: 0, // per-column count not tracked in the batch
                    residual: c.residual,
                    converged: c.converged,
                },
            )
        })
        .collect()
}

/// Residual-check phase: y = A·x. Decide converged / give up / start a cycle.
fn consume_residual(
    col: &mut BatchCol,
    y: &[Complex64],
    m: usize,
    opts: GmresOptions,
    zero: Complex64,
) {
    let r: Vec<Complex64> = col.b.iter().zip(y).map(|(bi, yi)| bi - yi).collect();
    let beta = cnrm2(&r);
    col.residual = beta / col.bnorm;
    if col.residual <= opts.tol {
        col.done = true;
        col.converged = true;
        return;
    }
    if col.cycle >= opts.max_restarts {
        col.done = true;
        return;
    }
    col.cycle += 1;
    // Initialize a fresh Krylov cycle (same as gmres_complex's cycle start).
    let inv_beta = 1.0 / beta;
    col.vre = Vec::with_capacity(m + 1);
    col.vim = Vec::with_capacity(m + 1);
    col.vre.push(r.iter().map(|c| c.re * inv_beta).collect());
    col.vim.push(r.iter().map(|c| c.im * inv_beta).collect());
    col.h = vec![vec![zero; m]; m + 1];
    col.cs = vec![0.0; m];
    col.sn = vec![zero; m];
    col.g = vec![zero; m + 1];
    col.g[0] = Complex64::new(beta, 0.0);
    col.k = 0;
    col.residual_phase = false;
}

/// Arnoldi phase: y = A·M⁻¹·v_k. MGS + Givens; on (estimated) convergence or
/// basis full, update x and switch back to the residual check.
fn consume_arnoldi(
    col: &mut BatchCol,
    y: &[Complex64],
    n: usize,
    m: usize,
    opts: GmresOptions,
    precond: Option<&(dyn ComplexOperator + Sync)>,
    zero: Complex64,
) {
    let k = col.k;
    let mut wre: Vec<f64> = y.iter().map(|c| c.re).collect();
    let mut wim: Vec<f64> = y.iter().map(|c| c.im).collect();

    // Modified Gram–Schmidt on split planes (same arithmetic as gmres_complex).
    for i in 0..=k {
        let (vr, vi) = (&col.vre[i], &col.vim[i]);
        let (hre, him) = crate::simd::cdot_conj(vr, vi, &wre, &wim);
        col.h[i][k] = Complex64::new(hre, him);
        crate::simd::caxpy(hre, him, vr, vi, &mut wre, &mut wim);
    }
    let hk1 = (dot(&wre, &wre) + dot(&wim, &wim)).sqrt();
    col.h[k + 1][k] = Complex64::new(hk1, 0.0);
    if hk1 > 1e-14 {
        let inv = 1.0 / hk1;
        for j in 0..n {
            wre[j] *= inv;
            wim[j] *= inv;
        }
    }
    col.vre.push(wre);
    col.vim.push(wim);

    for i in 0..k {
        let temp = Complex64::new(col.cs[i], 0.0) * col.h[i][k] + col.sn[i] * col.h[i + 1][k];
        col.h[i + 1][k] =
            -col.sn[i].conj() * col.h[i][k] + Complex64::new(col.cs[i], 0.0) * col.h[i + 1][k];
        col.h[i][k] = temp;
    }
    let (c, s) = givens_c(col.h[k][k], col.h[k + 1][k]);
    col.cs[k] = c;
    col.sn[k] = s;
    col.h[k][k] = Complex64::new(c, 0.0) * col.h[k][k] + s * col.h[k + 1][k];
    col.h[k + 1][k] = zero;
    let temp = Complex64::new(c, 0.0) * col.g[k] + s * col.g[k + 1];
    col.g[k + 1] = -s.conj() * col.g[k] + Complex64::new(c, 0.0) * col.g[k + 1];
    col.g[k] = temp;

    let k_used = k + 1;
    if col.g[k_used].norm() / col.bnorm > opts.tol && k_used < m {
        col.k = k_used;
        return;
    }

    // Back-substitute H y = g and update x (then verify via a residual apply).
    let mut yv = vec![zero; k_used];
    for i in (0..k_used).rev() {
        let mut sum = col.g[i];
        for j in (i + 1)..k_used {
            sum -= col.h[i][j] * yv[j];
        }
        yv[i] = sum / col.h[i][i];
    }
    let mut dx = vec![zero; n];
    for i in 0..k_used {
        let (yi, vr, vi) = (yv[i], &col.vre[i], &col.vim[i]);
        for j in 0..n {
            dx[j] += yi * Complex64::new(vr[j], vi[j]);
        }
    }
    if let Some(mp) = precond {
        let mut dz = vec![zero; n];
        mp.apply(&dx, &mut dz);
        dx = dz;
    }
    for j in 0..n {
        col.x[j] += dx[j];
    }
    // Free the basis before the residual phase (memory: ncols × m × n planes).
    col.vre = Vec::new();
    col.vim = Vec::new();
    col.residual_phase = true;
}

#[cfg(test)]
mod batched_tests {
    use super::*;
    use crate::operator::{BlockJacobiComplex, DenseComplexOperator};
    use crate::linalg::DenseMatrix;

    #[test]
    fn batched_matches_per_column_gmres() {
        // Diagonally dominant complex system, several RHS.
        let n = 40;
        let mut a = DenseMatrix::<Complex64>::zeros(n, n);
        for i in 0..n {
            for j in 0..n {
                let v = if i == j {
                    Complex64::new(10.0 + i as f64, 3.0)
                } else {
                    Complex64::new(
                        1.0 / (1.0 + (i as f64 - j as f64).abs()),
                        0.3 / (1.0 + (i + j) as f64),
                    )
                };
                a[(i, j)] = v;
            }
        }
        let op = DenseComplexOperator::new(a.clone());
        let precond = BlockJacobiComplex::contiguous(&a, 8);
        let opts = GmresOptions { tol: 1e-8, restart: 20, max_restarts: 10 };

        let rhs: Vec<Vec<Complex64>> = (0..5)
            .map(|c| {
                (0..n)
                    .map(|i| Complex64::new(((i * (c + 2)) % 7) as f64 - 3.0, (i % 3) as f64))
                    .collect()
            })
            .collect();

        // Block apply = per-column applies through the same operator.
        let apply_block = |x: &[Complex64], y: &mut [Complex64], ncols: usize| {
            for c in 0..ncols {
                let (xc, yc) = (&x[c * n..(c + 1) * n], &mut y[c * n..(c + 1) * n]);
                op.apply(xc, yc);
            }
        };
        let batched = gmres_complex_batched(apply_block, &rhs, Some(&precond), opts);

        for (b, (xb, meta)) in rhs.iter().zip(&batched) {
            assert!(meta.converged, "batched column failed to converge");
            let (xs, ms) = gmres_complex(&op, b, Some(&precond), opts);
            assert!(ms.converged);
            let diff: f64 = xb.iter().zip(&xs).map(|(p, q)| (p - q).norm()).sum();
            let norm: f64 = xs.iter().map(|q| q.norm()).sum();
            assert!(diff / norm < 1e-6, "batched vs per-column mismatch: {}", diff / norm);
        }
    }
}
