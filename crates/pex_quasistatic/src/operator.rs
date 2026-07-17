//! Concrete [`LinearOperator`] implementations: a dense operator (the exact
//! reference apply) and a block-Jacobi preconditioner (the "physically-local"
//! preconditioner both original tools use, generalized to algebraic diagonal
//! blocks). The FMM/H²/GPU accelerators from the design plug in here by
//! implementing the same trait.

use crate::kernel::{ComplexOperator, LinearOperator};
use crate::linalg::{DenseMatrix, LuDecomposition};
use num_complex::Complex64;

/// A dense real operator y = A·x. This is the small-problem reference path that
/// reproduces the original tools exactly (no acceleration error).
pub struct DenseOperator {
    pub a: DenseMatrix<f64>,
}

impl DenseOperator {
    pub fn new(a: DenseMatrix<f64>) -> Self {
        assert_eq!(a.rows, a.cols, "operator must be square");
        DenseOperator { a }
    }
}

impl LinearOperator for DenseOperator {
    fn dim(&self) -> usize {
        self.a.rows
    }
    fn apply(&self, x: &[f64], y: &mut [f64]) {
        let n = self.a.rows;
        let data = &self.a.data;
        for i in 0..n {
            y[i] = crate::simd::dot(&data[i * n..(i + 1) * n], x);
        }
    }
}

/// A dense complex operator y = A·x for the frequency-domain impedance system.
pub struct DenseComplexOperator {
    n: usize,
    /// Matrix stored as split re/im planes so the row products run through the
    /// SIMD f64 dot kernel (same split-plane trick as the complex GMRES basis).
    are: Vec<f64>,
    aim: Vec<f64>,
}

impl DenseComplexOperator {
    pub fn new(a: DenseMatrix<Complex64>) -> Self {
        assert_eq!(a.rows, a.cols, "operator must be square");
        DenseComplexOperator {
            n: a.rows,
            are: a.data.iter().map(|c| c.re).collect(),
            aim: a.data.iter().map(|c| c.im).collect(),
        }
    }
}

impl ComplexOperator for DenseComplexOperator {
    fn dim(&self) -> usize {
        self.n
    }
    fn apply(&self, x: &[Complex64], y: &mut [Complex64]) {
        let n = self.n;
        // Split x once per apply (allocation is noise next to the O(n²) row
        // products; no RefCell scratch — apply is called from rayon contexts).
        let xre: Vec<f64> = x.iter().map(|c| c.re).collect();
        let xim: Vec<f64> = x.iter().map(|c| c.im).collect();
        for i in 0..n {
            let (ar, ai) = (&self.are[i * n..(i + 1) * n], &self.aim[i * n..(i + 1) * n]);
            let (re, im) = crate::simd::cdot(ar, ai, &xre, &xim);
            y[i] = Complex64::new(re, im);
        }
    }
}

/// Complex block-Jacobi preconditioner (the physically-local preconditioner for
/// the impedance system): invert diagonal blocks once, apply as approximate
/// inverse.
pub struct BlockJacobiComplex {
    n: usize,
    blocks: Vec<BlockInvC>,
}

struct BlockInvC {
    indices: Vec<usize>,
    lu: LuDecomposition<Complex64>,
}

impl BlockJacobiComplex {
    pub fn new(a: &DenseMatrix<Complex64>, partition: &[Vec<usize>]) -> Self {
        let n = a.rows;
        let mut blocks = Vec::with_capacity(partition.len());
        for idx in partition {
            let bsz = idx.len();
            let mut sub = DenseMatrix::<Complex64>::zeros(bsz, bsz);
            for (li, &gi) in idx.iter().enumerate() {
                for (lj, &gj) in idx.iter().enumerate() {
                    sub[(li, lj)] = a[(gi, gj)];
                }
            }
            let lu = LuDecomposition::factor(&sub)
                .unwrap_or_else(|_| LuDecomposition::factor(&DenseMatrix::identity(bsz)).unwrap());
            blocks.push(BlockInvC { indices: idx.clone(), lu });
        }
        BlockJacobiComplex { n, blocks }
    }

    pub fn contiguous(a: &DenseMatrix<Complex64>, block_size: usize) -> Self {
        let n = a.rows;
        let mut partition = Vec::new();
        let mut i = 0;
        while i < n {
            let end = (i + block_size).min(n);
            partition.push((i..end).collect());
            i = end;
        }
        Self::new(a, &partition)
    }
}

impl ComplexOperator for BlockJacobiComplex {
    fn dim(&self) -> usize {
        self.n
    }
    fn apply(&self, x: &[Complex64], y: &mut [Complex64]) {
        for yi in y.iter_mut() {
            *yi = Complex64::new(0.0, 0.0);
        }
        for block in &self.blocks {
            let local_rhs: Vec<Complex64> = block.indices.iter().map(|&g| x[g]).collect();
            let local_sol = block.lu.solve(&local_rhs);
            for (li, &gi) in block.indices.iter().enumerate() {
                y[gi] = local_sol[li];
            }
        }
    }
}

/// Block-Jacobi preconditioner: the domain is partitioned into blocks of nearby
/// unknowns; each diagonal block is inverted (LU) once and applied as an
/// approximate inverse. With one block of size n it is an exact direct solve;
/// with many small blocks it is the cheap local preconditioner GMRES wants.
pub struct BlockJacobi {
    n: usize,
    blocks: Vec<BlockInv>,
}

struct BlockInv {
    indices: Vec<usize>,
    lu: LuDecomposition<f64>,
}

impl BlockJacobi {
    /// Build from the dense matrix and a partition of the index set into blocks.
    pub fn new(a: &DenseMatrix<f64>, partition: &[Vec<usize>]) -> Self {
        let n = a.rows;
        let mut blocks = Vec::with_capacity(partition.len());
        for idx in partition {
            let bsz = idx.len();
            let mut sub = DenseMatrix::<f64>::zeros(bsz, bsz);
            for (li, &gi) in idx.iter().enumerate() {
                for (lj, &gj) in idx.iter().enumerate() {
                    sub[(li, lj)] = a[(gi, gj)];
                }
            }
            // If a block is singular (rare), fall back to identity for that block.
            let lu = LuDecomposition::factor(&sub)
                .unwrap_or_else(|_| LuDecomposition::factor(&DenseMatrix::identity(bsz)).unwrap());
            blocks.push(BlockInv { indices: idx.clone(), lu });
        }
        BlockJacobi { n, blocks }
    }

    /// Convenience: contiguous blocks of size `block_size` (last may be smaller).
    pub fn contiguous(a: &DenseMatrix<f64>, block_size: usize) -> Self {
        let n = a.rows;
        let mut partition = Vec::new();
        let mut i = 0;
        while i < n {
            let end = (i + block_size).min(n);
            partition.push((i..end).collect());
            i = end;
        }
        Self::new(a, &partition)
    }
}

impl LinearOperator for BlockJacobi {
    fn dim(&self) -> usize {
        self.n
    }
    fn apply(&self, x: &[f64], y: &mut [f64]) {
        for yi in y.iter_mut() {
            *yi = 0.0;
        }
        for block in &self.blocks {
            let local_rhs: Vec<f64> = block.indices.iter().map(|&g| x[g]).collect();
            let local_sol = block.lu.solve(&local_rhs);
            for (li, &gi) in block.indices.iter().enumerate() {
                y[gi] = local_sol[li];
            }
        }
    }
}
