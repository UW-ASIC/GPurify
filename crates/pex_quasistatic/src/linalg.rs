//! Compact dense linear algebra in FP64: a row-major matrix type plus LU
//! factorization with partial pivoting, generic over a real (`f64`) or complex
//! (`Complex<f64>`) field.
//!
//! This is the "small-problem" direct path from the design report: for a few
//! hundred to a few thousand unknowns a dense FP64 solve *exactly* reproduces
//! the original tools (no FMM approximation), and it is the reference the
//! iterative/accelerated paths are validated against.

use num_complex::Complex64;
use std::ops::{Add, Div, Mul, Sub};

/// The scalar field a dense system is solved over. Implemented for `f64`
/// (electrostatics / capacitance, and DC inductance) and `Complex64`
/// (frequency-domain impedance Z = R + jωL).
pub trait Field:
    Copy
    + Send
    + Sync
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Div<Output = Self>
    + PartialEq
{
    fn zero() -> Self;
    fn one() -> Self;
    /// Magnitude, used to choose the pivot row.
    fn magnitude(self) -> f64;
    fn conj(self) -> Self;
}

impl Field for f64 {
    #[inline]
    fn zero() -> Self {
        0.0
    }
    #[inline]
    fn one() -> Self {
        1.0
    }
    #[inline]
    fn magnitude(self) -> f64 {
        self.abs()
    }
    #[inline]
    fn conj(self) -> Self {
        self
    }
}

impl Field for f32 {
    #[inline]
    fn zero() -> Self {
        0.0
    }
    #[inline]
    fn one() -> Self {
        1.0
    }
    #[inline]
    fn magnitude(self) -> f64 {
        self.abs() as f64
    }
    #[inline]
    fn conj(self) -> Self {
        self
    }
}

impl Field for Complex64 {
    #[inline]
    fn zero() -> Self {
        Complex64::new(0.0, 0.0)
    }
    #[inline]
    fn one() -> Self {
        Complex64::new(1.0, 0.0)
    }
    #[inline]
    fn magnitude(self) -> f64 {
        self.norm()
    }
    #[inline]
    fn conj(self) -> Self {
        Complex64::conj(&self)
    }
}

/// A dense, row-major matrix.
#[derive(Debug, Clone)]
pub struct DenseMatrix<T> {
    pub rows: usize,
    pub cols: usize,
    pub data: Vec<T>,
}

impl<T: Field> DenseMatrix<T> {
    pub fn zeros(rows: usize, cols: usize) -> Self {
        DenseMatrix {
            rows,
            cols,
            data: vec![T::zero(); rows * cols],
        }
    }

    pub fn identity(n: usize) -> Self {
        let mut m = Self::zeros(n, n);
        for i in 0..n {
            m[(i, i)] = T::one();
        }
        m
    }

    #[inline]
    pub fn get(&self, i: usize, j: usize) -> T {
        self.data[i * self.cols + j]
    }

    #[inline]
    pub fn set(&mut self, i: usize, j: usize, v: T) {
        self.data[i * self.cols + j] = v;
    }

    /// Matrix-vector product y = A·x.
    pub fn matvec(&self, x: &[T]) -> Vec<T> {
        assert_eq!(x.len(), self.cols);
        let mut y = vec![T::zero(); self.rows];
        for i in 0..self.rows {
            let base = i * self.cols;
            let mut acc = T::zero();
            for j in 0..self.cols {
                acc = acc + self.data[base + j] * x[j];
            }
            y[i] = acc;
        }
        y
    }
}

impl<T> std::ops::Index<(usize, usize)> for DenseMatrix<T> {
    type Output = T;
    #[inline]
    fn index(&self, (i, j): (usize, usize)) -> &T {
        &self.data[i * self.cols + j]
    }
}
impl<T> std::ops::IndexMut<(usize, usize)> for DenseMatrix<T> {
    #[inline]
    fn index_mut(&mut self, (i, j): (usize, usize)) -> &mut T {
        &mut self.data[i * self.cols + j]
    }
}

/// An in-place LU factorization with partial pivoting (Doolittle, PA = LU).
pub struct LuDecomposition<T> {
    lu: DenseMatrix<T>,
    piv: Vec<usize>,
    n: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum LinalgError {
    #[error("matrix is singular at column {0}")]
    Singular(usize),
    #[error("matrix must be square, got {0}x{1}")]
    NotSquare(usize, usize),
}

impl<T: Field> LuDecomposition<T> {
    /// Factor a square matrix. Consumes a copy so the original is untouched.
    pub fn factor(a: &DenseMatrix<T>) -> Result<Self, LinalgError> {
        if a.rows != a.cols {
            return Err(LinalgError::NotSquare(a.rows, a.cols));
        }
        let n = a.rows;
        let mut lu = a.clone();
        let mut piv: Vec<usize> = (0..n).collect();

        for k in 0..n {
            // Partial pivot: find row with largest magnitude in column k.
            let mut p = k;
            let mut max = lu[(k, k)].magnitude();
            for i in (k + 1)..n {
                let m = lu[(i, k)].magnitude();
                if m > max {
                    max = m;
                    p = i;
                }
            }
            if max == 0.0 {
                return Err(LinalgError::Singular(k));
            }
            if p != k {
                for j in 0..n {
                    lu.data.swap(k * n + j, p * n + j);
                }
                piv.swap(k, p);
            }

            // Trailing-submatrix rank-1 update: rows are independent, inner
            // loop is contiguous (autovectorizes); rayon over rows when the
            // remaining work is large enough to amortize the fork.
            let pivot = lu[(k, k)];
            let (top, tail) = lu.data.split_at_mut((k + 1) * n);
            let pivot_row = &top[k * n..(k + 1) * n];
            let update = |row: &mut [T]| {
                let factor = row[k] / pivot;
                row[k] = factor;
                for j in (k + 1)..n {
                    row[j] = row[j] - factor * pivot_row[j];
                }
            };
            let rows_left = n - k - 1;
            if rows_left * (n - k) > 64 * 64 {
                use rayon::prelude::*;
                tail.par_chunks_mut(n).for_each(update);
            } else {
                tail.chunks_mut(n).for_each(update);
            }
        }

        Ok(LuDecomposition { lu, piv, n })
    }

    /// Solve A·x = b for a single right-hand side.
    pub fn solve(&self, b: &[T]) -> Vec<T> {
        assert_eq!(b.len(), self.n);
        let n = self.n;
        // Apply row permutation.
        let mut x = vec![T::zero(); n];
        for i in 0..n {
            x[i] = b[self.piv[i]];
        }
        // Forward substitution (L has unit diagonal).
        for i in 0..n {
            let mut sum = x[i];
            for j in 0..i {
                sum = sum - self.lu[(i, j)] * x[j];
            }
            x[i] = sum;
        }
        // Back substitution.
        for i in (0..n).rev() {
            let mut sum = x[i];
            for j in (i + 1)..n {
                sum = sum - self.lu[(i, j)] * x[j];
            }
            x[i] = sum / self.lu[(i, i)];
        }
        x
    }

    /// Solve for many right-hand sides (columns of B), returning the columns of X.
    /// Used to extract a full capacitance / impedance matrix in one factorization.
    pub fn solve_many(&self, rhs_columns: &[Vec<T>]) -> Vec<Vec<T>> {
        rhs_columns.iter().map(|b| self.solve(b)).collect()
    }
}

/// ponytail: truncated low-rank approximation of a dense f64 matrix via
/// column-pivoted QR.  A ≈ U * V^T where U is m×k, V^T is k×n, k = effective rank.
/// Used to compress M2L operators in the FMM.
pub struct LowRankApprox {
    /// U factor (m × k), stored row-major as flat vec of length m*k.
    pub u: Vec<f64>,
    /// V^T factor (k × n), stored row-major as flat vec of length k*n.
    pub vt: Vec<f64>,
    pub m: usize,
    pub n: usize,
    pub k: usize,
}

impl LowRankApprox {
    /// Compute a truncated low-rank approximation of `a` (m×n, flat row-major)
    /// keeping singular-value-like magnitudes above `eps * max_magnitude`.
    pub fn compress(a: &[f64], m: usize, n: usize, eps: f64) -> Self {
        // Column-pivoted QR via modified Gram-Schmidt with column norms.
        let mut q = vec![0.0f64; m * n]; // Q factor columns
        let mut r = vec![0.0f64; n * n]; // R factor
        let mut perm: Vec<usize> = (0..n).collect();

        // Copy A into working buffer (will be modified in-place as we extract columns)
        q.copy_from_slice(&a[..m * n]);

        // Column norms for pivoting
        let mut col_norms: Vec<f64> = (0..n)
            .map(|j| (0..m).map(|i| a[i * n + j].powi(2)).sum::<f64>())
            .collect();

        let max_k = m.min(n);
        let mut k = 0;
        let norm_threshold = eps * col_norms.iter().cloned().fold(0.0f64, f64::max);

        for step in 0..max_k {
            // Find pivot: column with largest remaining norm
            let mut best = step;
            for j in (step + 1)..n {
                if col_norms[j] > col_norms[best] {
                    best = j;
                }
            }

            // Check if remaining columns are negligible
            if col_norms[best] < norm_threshold {
                break;
            }

            // Swap columns step <-> best in Q, R, perm, col_norms
            if best != step {
                perm.swap(step, best);
                col_norms.swap(step, best);
                for i in 0..m {
                    q.swap(i * n + step, i * n + best);
                }
                // Swap already-computed R rows for previous steps
                for row in 0..step {
                    r.swap(row * n + step, row * n + best);
                }
            }

            // Compute column norm (R diagonal)
            let mut norm = 0.0f64;
            for i in 0..m {
                norm += q[i * n + step].powi(2);
            }
            norm = norm.sqrt();
            if norm < 1e-15 {
                break;
            }
            r[step * n + step] = norm;

            // Normalize the column
            let inv_norm = 1.0 / norm;
            for i in 0..m {
                q[i * n + step] *= inv_norm;
            }

            // Orthogonalize remaining columns against this one
            for j in (step + 1)..n {
                let mut dot = 0.0;
                for i in 0..m {
                    dot += q[i * n + step] * q[i * n + j];
                }
                r[step * n + j] = dot;
                for i in 0..m {
                    q[i * n + j] -= dot * q[i * n + step];
                }
                col_norms[j] -= dot * dot;
                if col_norms[j] < 0.0 { col_norms[j] = 0.0; }
            }

            k = step + 1;
        }

        if k == 0 {
            return LowRankApprox { u: Vec::new(), vt: Vec::new(), m, n, k: 0 };
        }

        // Extract U = Q[:, :k] (m × k)
        let mut u = vec![0.0; m * k];
        for i in 0..m {
            for j in 0..k {
                u[i * k + j] = q[i * n + j];
            }
        }

        // Extract R_trunc = R[:k, :] (k × n) with column permutation applied
        // V^T = R[:k, P^{-1}] so that A ≈ U * V^T
        // R is currently in pivoted order: A * P ≈ Q * R
        // So A ≈ Q[:,:k] * R[:k,:] * P^T
        // V^T[i, perm[j]] = R[i, j] for j < n
        let mut vt = vec![0.0; k * n];
        for i in 0..k {
            for j in 0..n {
                vt[i * n + perm[j]] = r[i * n + j];
            }
        }

        LowRankApprox { u, vt, m, n, k }
    }

    /// Apply y += scale * (U * V^T) * x. `scratch` must be at least `k` long
    /// (caller-provided so the hot M2L loop does not allocate per pair).
    #[inline]
    pub fn apply_add(&self, x: &[f64], y: &mut [f64], scale: f64, scratch: &mut [f64]) {
        if self.k == 0 { return; }
        // t = V^T * x  (k elements)
        let t = &mut scratch[..self.k];
        for i in 0..self.k {
            let row = &self.vt[i * self.n..(i + 1) * self.n];
            t[i] = row.iter().zip(x).map(|(&a, &b)| a * b).sum();
        }
        // y += scale * U * t
        for i in 0..self.m {
            let row = &self.u[i * self.k..(i + 1) * self.k];
            let val: f64 = row.iter().zip(t.iter()).map(|(&a, &b)| a * b).sum();
            y[i] += scale * val;
        }
    }
}
