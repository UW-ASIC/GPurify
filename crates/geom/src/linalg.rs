//! `f64` vector kernels for ERC power's CG and extract's GMRES.
//!
//! Every fold is a strict left fold in ascending index order; that order is interface
//! (it decides CG `alpha` and the convergence verdict), so do not reassociate.

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
#[inline]
pub fn axpy(alpha: f64, x: &[f64], y: &mut [f64]) {
    for (yj, xj) in y.iter_mut().zip(x) {
        *yj += alpha * xj;
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
    use super::{axpy, dot, nrm2, spmv};

    /// The fold order is interface, so the check is against the literal
    /// left-to-right sum, not against an approximation of it.
    #[test]
    fn the_kernels_agree_with_the_loops_they_replace() {
        let a: Vec<f64> = (0..37).map(|i| f64::from(i) * 0.37 - 3.0).collect();
        let b: Vec<f64> = (0..37).map(|i| 1.0 / (f64::from(i) + 1.5)).collect();

        let mut expect = 0.0;
        for i in 0..a.len() {
            expect += a[i] * b[i];
        }
        assert_eq!(dot(&a, &b), expect, "dot reassociated the sum");
        assert_eq!(nrm2(&a), dot(&a, &a).sqrt());

        let mut y = b.clone();
        axpy(-2.5, &a, &mut y);
        for i in 0..a.len() {
            assert_eq!(y[i], b[i] - 2.5 * a[i], "axpy is not the subtracting form");
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
