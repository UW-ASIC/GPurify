//! Mixed-precision iterative refinement and matrix equilibration.
//!
//! Iterative refinement is the report's accuracy-recovery scheme for FP64-poor
//! GPUs: factor the matrix once in **f32** (cheap, GPU-friendly), then recover
//! full **f64** accuracy by repeatedly computing the residual in f64 and
//! correcting with the f32 factorization:
//!   x₀ = 0;  rₖ = b − A·xₖ (f64);  A·dₖ = rₖ (solved via the f32 LU);  xₖ₊₁ = xₖ + dₖ.
//! A handful of steps drive the f64 residual to machine precision even though the
//! factorization is single precision — the classic Wilkinson result.
//!
//! Equilibration rescales rows/columns so the LU pivoting sees a well-balanced
//! matrix, improving accuracy for badly-scaled systems.

use crate::linalg::{DenseMatrix, LuDecomposition};

/// Controls for [`solve_iterative_refinement`].
#[derive(Debug, Clone, Copy)]
pub struct RefineOptions {
    pub tol: f64,
    pub max_steps: usize,
}
impl Default for RefineOptions {
    fn default() -> Self {
        RefineOptions { tol: 1e-13, max_steps: 30 }
    }
}

/// Outcome of a refined solve.
#[derive(Debug, Clone)]
pub struct RefineResult {
    pub x: Vec<f64>,
    pub steps: usize,
    pub residual: f64,
    pub converged: bool,
}

#[inline]
fn nrm2(v: &[f64]) -> f64 {
    v.iter().map(|x| x * x).sum::<f64>().sqrt()
}

/// Solve A·x = b to f64 accuracy using an **f32** LU factorization plus f64
/// iterative refinement. Demonstrates and implements the report's
/// "FP32 factorization + FP64 iterative refinement" precision-recovery path.
pub fn solve_iterative_refinement(
    a: &DenseMatrix<f64>,
    b: &[f64],
    opts: RefineOptions,
) -> Result<RefineResult, crate::linalg::LinalgError> {
    let n = a.rows;
    assert_eq!(a.cols, n);
    assert_eq!(b.len(), n);

    // Factor a single-precision copy of A once.
    let mut a32 = DenseMatrix::<f32>::zeros(n, n);
    for k in 0..n * n {
        a32.data[k] = a.data[k] as f32;
    }
    let lu32 = LuDecomposition::factor(&a32)?;

    let bnorm = nrm2(b).max(f64::MIN_POSITIVE);
    let mut x = vec![0.0f64; n];

    let mut residual = 1.0;
    let mut converged = false;
    let mut steps = 0;
    for step in 0..opts.max_steps {
        // r = b - A x, accumulated in f64.
        let ax = a.matvec(&x);
        let r: Vec<f64> = b.iter().zip(&ax).map(|(bi, axi)| bi - axi).collect();
        residual = nrm2(&r) / bnorm;
        steps = step;
        if residual <= opts.tol {
            converged = true;
            break;
        }
        // Correction via the f32 factorization: A·dx = r.
        let r32: Vec<f32> = r.iter().map(|&v| v as f32).collect();
        let dx32 = lu32.solve(&r32);
        // Guard against stagnation (f32 factorization limits achievable residual).
        let mut moved = false;
        for i in 0..n {
            let d = dx32[i] as f64;
            if d != 0.0 {
                moved = true;
            }
            x[i] += d;
        }
        if !moved {
            break;
        }
    }

    Ok(RefineResult { x, steps, residual, converged })
}

/// Row/column equilibration scales: returns `(row_scale, col_scale)` such that
/// the scaled matrix diag(row)·A·diag(col) has rows and columns of comparable
/// magnitude. A simple, robust variant: scale each row by 1/max|aᵢⱼ|, then each
/// column by 1/max|scaled aᵢⱼ|.
pub fn equilibration(a: &DenseMatrix<f64>) -> (Vec<f64>, Vec<f64>) {
    let n = a.rows;
    let mut row = vec![1.0; n];
    for i in 0..n {
        let mut m = 0.0f64;
        for j in 0..a.cols {
            m = m.max(a[(i, j)].abs());
        }
        if m > 0.0 {
            row[i] = 1.0 / m;
        }
    }
    let mut col = vec![1.0; a.cols];
    for j in 0..a.cols {
        let mut m = 0.0f64;
        for i in 0..n {
            m = m.max((row[i] * a[(i, j)]).abs());
        }
        if m > 0.0 {
            col[j] = 1.0 / m;
        }
    }
    (row, col)
}

/// Solve A·x = b with equilibration: solve (Dr·A·Dc)·y = Dr·b, then x = Dc·y.
/// More robust than a raw LU on badly-scaled systems.
pub fn solve_equilibrated(
    a: &DenseMatrix<f64>,
    b: &[f64],
) -> Result<Vec<f64>, crate::linalg::LinalgError> {
    let n = a.rows;
    let (row, col) = equilibration(a);
    let mut scaled = DenseMatrix::<f64>::zeros(n, n);
    for i in 0..n {
        for j in 0..n {
            scaled[(i, j)] = row[i] * a[(i, j)] * col[j];
        }
    }
    let rhs: Vec<f64> = (0..n).map(|i| row[i] * b[i]).collect();
    let lu = LuDecomposition::factor(&scaled)?;
    let y = lu.solve(&rhs);
    Ok((0..n).map(|j| col[j] * y[j]).collect())
}
