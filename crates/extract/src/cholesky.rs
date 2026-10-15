//! Dense Cholesky factorisation and solve, for the symmetric positive
//! definite systems of [`crate::compare`] (a net's conductance matrix) and
//! [`crate::fill`] (a floating cluster's capacitance matrix).
//!
//! Every sum is a strict fold in index order, so a result's bits are a
//! function of the matrix alone.

/// The lower Cholesky factor of a symmetric positive definite `m × m`
/// matrix, row-major; `None` at a pivot that is not positive.
#[allow(
    clippy::needless_range_loop,
    reason = "the fold order is the index order"
)]
pub(crate) fn factor(mut a: Vec<f64>, m: usize) -> Option<Vec<f64>> {
    for j in 0..m {
        let mut pivot = a[j * m + j];
        for k in 0..j {
            pivot -= a[j * m + k] * a[j * m + k];
        }
        if !(pivot > 0.0) {
            return None;
        }
        let pivot = pivot.sqrt();
        a[j * m + j] = pivot;
        for i in j + 1..m {
            let mut value = a[i * m + j];
            for k in 0..j {
                value -= a[i * m + k] * a[j * m + k];
            }
            a[i * m + j] = value / pivot;
        }
    }
    Some(a)
}

/// `x` with `L Lᵀ x = b`, `L` from [`factor`].
#[allow(
    clippy::needless_range_loop,
    reason = "the fold order is the index order"
)]
pub(crate) fn solve(l: &[f64], m: usize, b: &[f64]) -> Vec<f64> {
    let mut y = b.to_vec();
    for i in 0..m {
        for k in 0..i {
            y[i] -= l[i * m + k] * y[k];
        }
        y[i] /= l[i * m + i];
    }
    for i in (0..m).rev() {
        for k in i + 1..m {
            y[i] -= l[k * m + i] * y[k];
        }
        y[i] /= l[i * m + i];
    }
    y
}
