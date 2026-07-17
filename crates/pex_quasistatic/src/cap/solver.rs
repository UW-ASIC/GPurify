//! Electrostatic capacitance extraction.
//!
//! First-kind Laplace integral equation with piecewise-constant surface charge
//! and first-order collocation (FastCap's scheme):
//!   φ(r_k) = Σ_l P_kl σ_l,   P_kl = 1/(4πε₀) ∫_{panel l} da'/‖r_k − r'‖.
//! Every entry (self, near, far) uses the exact Wilton polygon integral, so no
//! quadrature error enters the coefficient matrix. Setting each conductor in
//! turn to 1 V (others 0 V), solving for σ, and summing panel charges per
//! conductor yields the Maxwell capacitance matrix C.

use crate::cap::geometry::Geometry;
use crate::constants::ONE_OVER_4PI_EPS0;
use crate::integrals::panel::{potential_integral, PanelSet};
use crate::linalg::{DenseMatrix, LuDecomposition};
use crate::operator::DenseOperator;
use crate::krylov::{gmres, GmresOptions};

/// The extracted capacitance data.
#[derive(Debug, Clone)]
pub struct CapResult {
    pub conductor_names: Vec<String>,
    /// Maxwell capacitance matrix [F]. `c[(i,j)]` = charge on conductor i per
    /// volt on conductor j (others grounded). Diagonal = self-capacitance
    /// (sum of the row for the mutual/short-circuit convention is the physical
    /// capacitance to infinity).
    pub c: DenseMatrix<f64>,
}

impl CapResult {
    pub fn num_conductors(&self) -> usize {
        self.conductor_names.len()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SolveError {
    #[error("no panels in geometry")]
    Empty,
    #[error("potential-coefficient matrix is singular")]
    Singular,
}

/// Which linear solver to use for the dense P system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Dense LU factorization (exact reference; factor once, solve per conductor).
    Direct,
    /// Iterative GMRES through the `LinearOperator` trait (exercises the
    /// accelerated matvec path; converges to the same answer within tolerance).
    Iterative,
}

/// RHS for conductor `j`: φ = 1 on that conductor's panels, 0 elsewhere.
/// Shared by the dense, GPU and FMM solve paths.
pub(crate) fn rhs_unit_conductor(set: &PanelSet, j: usize) -> Vec<f64> {
    let mut b = vec![0.0; set.len()];
    for (k, &c) in set.conductor.iter().enumerate() {
        if c as usize == j {
            b[k] = 1.0;
        }
    }
    b
}

/// Accumulate column j of the Maxwell matrix from a charge solution:
/// C[i][j] += Σ_{panels k on conductor i} σ[k] · area_k.
pub(crate) fn accumulate_c(set: &PanelSet, sigma: &[f64], j: usize, c: &mut DenseMatrix<f64>) {
    for (k, &cond) in set.conductor.iter().enumerate() {
        c[(cond as usize, j)] += sigma[k] * set.area[k];
    }
}

/// Assemble the dense potential-coefficient matrix P [m/F... actually V per unit
/// σ]. Row k = collocation at panel k's centroid; column l = charge density on
/// panel l.
pub fn assemble_p(geo: &Geometry) -> DenseMatrix<f64> {
    assemble_p_set(&PanelSet::build(&geo.panels))
}

/// SoA-set variant of [`assemble_p`] — the actual assembly loop.
pub fn assemble_p_set(set: &PanelSet) -> DenseMatrix<f64> {
    use rayon::prelude::*;
    let n = set.len();
    let mut p = DenseMatrix::<f64>::zeros(n, n);
    // Exact Wilton integral for every pair: this is the *reference* path, the
    // FMM operator is the fast one. Rows are independent -> rayon.
    p.data
        .par_chunks_mut(n)
        .enumerate()
        .for_each(|(k, row)| {
            let rk = set.centroid(k);
            for l in 0..n {
                row[l] = ONE_OVER_4PI_EPS0 * potential_integral(set.verts_of(l), rk);
            }
        });
    p
}

/// Solve for the capacitance matrix.
pub fn solve(geo: &Geometry, method: Method) -> Result<CapResult, SolveError> {
    if geo.panels.is_empty() {
        return Err(SolveError::Empty);
    }
    let set = PanelSet::build(&geo.panels);
    let ncond = geo.num_conductors();

    let p = assemble_p_set(&set);

    // Build one RHS per conductor: φ = 1 on that conductor's panels, 0 elsewhere.
    let rhs_cols: Vec<Vec<f64>> = (0..ncond).map(|j| rhs_unit_conductor(&set, j)).collect();

    // Solve P σ = φ for each conductor.
    let sigma_cols: Vec<Vec<f64>> = match method {
        Method::Direct => {
            let lu = LuDecomposition::factor(&p).map_err(|_| SolveError::Singular)?;
            lu.solve_many(&rhs_cols)
        }
        Method::Iterative => {
            let op = DenseOperator::new(p.clone());
            let opts = GmresOptions { tol: 1e-8, restart: 100, max_restarts: 50 };
            rhs_cols
                .iter()
                .map(|b| gmres(&op, b, None, opts).x)
                .collect()
        }
    };

    let mut c = DenseMatrix::<f64>::zeros(ncond, ncond);
    for (j, sigma) in sigma_cols.iter().enumerate() {
        accumulate_c(&set, sigma, j, &mut c);
    }

    Ok(CapResult { conductor_names: geo.conductor_names.clone(), c })
}

/// GPU-accelerated dense iterative solve: P is assembled on CPU (exact Wilton),
/// uploaded once (f32, device-resident), and every GMRES matvec runs on the
/// GPU. f32 is verified lossless for the dense matvec on these well-conditioned
/// BEM systems (see `crate::gpu::Precision`), so tol is set to 1e-4 — well
/// above the f32 residual floor and far below engineering accuracy.
#[cfg(feature = "gpu")]
pub fn solve_gpu(
    geo: &Geometry,
    gpu: std::sync::Arc<crate::gpu::VulkanoBackend>,
) -> Result<CapResult, SolveError> {
    use crate::gpu::{op::GpuDenseOp, ComputeBackend, DeviceMatrix as GpuDm};

    if geo.panels.is_empty() {
        return Err(SolveError::Empty);
    }
    let set = PanelSet::build(&geo.panels);
    let n = set.len();
    let ncond = geo.num_conductors();

    let p = assemble_p_set(&set);
    let handle = gpu.upload_matrix(&GpuDm::from_rows(n, n, p.data));
    let op = GpuDenseOp { gpu, handle };

    let opts = GmresOptions { tol: 1e-4, restart: 100, max_restarts: 50 };
    let mut c = DenseMatrix::<f64>::zeros(ncond, ncond);
    for j in 0..ncond {
        let b = rhs_unit_conductor(&set, j);
        let sigma = gmres(&op, &b, None, opts).x;
        accumulate_c(&set, &sigma, j, &mut c);
    }
    Ok(CapResult { conductor_names: geo.conductor_names.clone(), c })
}
