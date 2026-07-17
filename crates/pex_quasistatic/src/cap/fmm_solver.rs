//! FMM-accelerated capacitance extraction.
//!
//! The dense potential operator `P σ` is applied in near-linear time by a
//! precorrected split:
//!   * **far field** — well-separated panel pairs use the black-box FMM with
//!     each panel's charge lumped to a point at its centroid;
//!   * **near field** — the leaf-and-neighbour pairs the FMM leaves out are
//!     filled with the *exact* Wilton panel integral, so no accuracy is lost
//!     where the point approximation would be poor.
//! The result is a [`LinearOperator`] that GMRES uses exactly like the dense one
//! and that converges to the same capacitance.

use crate::cap::geometry::Geometry;
use crate::cap::solver::{accumulate_c, rhs_unit_conductor, CapResult};
use crate::constants::ONE_OVER_4PI_EPS0;
use crate::fmm::LaplaceFmm;
use crate::integrals::panel::{potential_integral, PanelSet};
use crate::kernel::LinearOperator;
use crate::krylov::{gmres, GmresOptions};
use crate::linalg::DenseMatrix;

/// A precorrected FMM operator for the potential-coefficient matrix P.
pub struct FmmCapOperator {
    fmm: LaplaceFmm,
    areas: Vec<f64>,
    /// Near-field exact coefficients in CSR layout (flat index + value planes,
    /// contiguous per row — cache-friendly sparse apply).
    near_off: Vec<usize>,
    near_idx: Vec<u32>,
    near_val: Vec<f64>,
    n: usize,
    // ponytail: pre-allocated centroid-charge buffer, avoids alloc per matvec
    q_buf: std::cell::RefCell<Vec<f64>>,
}

impl FmmCapOperator {
    /// Build from a geometry, Chebyshev order `n` and tree depth `max_level`.
    pub fn new(geo: &Geometry, order: usize, max_level: usize) -> Self {
        Self::from_set(&PanelSet::build(&geo.panels), order, max_level)
    }

    /// Build from a pre-built SoA [`PanelSet`] (no recomputation of
    /// centroids/areas when the caller already has one).
    pub fn from_set(set: &PanelSet, order: usize, max_level: usize) -> Self {
        use rayon::prelude::*;
        let n = set.len();
        let areas = set.area.clone();
        // LaplaceFmm takes points AoS; gather once from the lanes (cold, per solve).
        let pts: Vec<crate::geometry::Vec3> = (0..n).map(|i| set.centroid(i)).collect();
        let fmm = LaplaceFmm::new(&pts, order, max_level);

        // Near-field exact Wilton coefficients over the FMM's near blocks.
        // Each target lives in exactly one leaf, so rows are disjoint: compute
        // them in parallel, then flatten to CSR.
        let blocks = fmm.near_blocks();
        let rows: Vec<(usize, Vec<(u32, f64)>)> = blocks
            .par_iter()
            .flat_map_iter(|(targets, sources)| {
                targets.iter().map(move |&i| {
                    let ri = set.centroid(i);
                    let row = sources
                        .iter()
                        .map(|&j| {
                            let pij = ONE_OVER_4PI_EPS0
                                * potential_integral(set.verts_of(j), ri);
                            (j as u32, pij)
                        })
                        .collect();
                    (i, row)
                })
            })
            .collect();
        let mut per_row: Vec<Vec<(u32, f64)>> = vec![Vec::new(); n];
        for (i, row) in rows {
            per_row[i] = row;
        }
        let mut near_off = Vec::with_capacity(n + 1);
        let mut near_idx = Vec::new();
        let mut near_val = Vec::new();
        near_off.push(0);
        for row in &per_row {
            for &(j, v) in row {
                near_idx.push(j);
                near_val.push(v);
            }
            near_off.push(near_idx.len());
        }
        FmmCapOperator {
            fmm, areas, near_off, near_idx, near_val,
            q_buf: std::cell::RefCell::new(vec![0.0; n]), n,
        }
    }

    /// Exact near-field diagonal P_ii (Wilton self-term), for preconditioning.
    fn diagonal(&self, i: usize) -> Option<f64> {
        let (s, e) = (self.near_off[i], self.near_off[i + 1]);
        self.near_idx[s..e]
            .iter()
            .position(|&j| j as usize == i)
            .map(|p| self.near_val[s + p])
    }

}

impl LinearOperator for FmmCapOperator {
    fn dim(&self) -> usize {
        self.n
    }
    fn apply(&self, sigma: &[f64], y: &mut [f64]) {
        use rayon::prelude::*;
        // Far field: lump panel charges to centroid points q_j = area_j σ_j.
        let mut q = self.q_buf.borrow_mut();
        for j in 0..self.n { q[j] = self.areas[j] * sigma[j]; }
        let far = self.fmm.matvec_farfield(&q);
        drop(q); // release RefCell before par_iter
        // Near field: CSR sparse matvec, rows independent.
        // ponytail: borrow fields individually so RefCell is not captured.
        let near_off = &self.near_off;
        let near_idx = &self.near_idx;
        let near_val = &self.near_val;
        y.par_iter_mut().enumerate().for_each(|(i, yi)| {
            let mut acc = ONE_OVER_4PI_EPS0 * far[i];
            let (s, e) = (near_off[i], near_off[i + 1]);
            for (&j, &pij) in near_idx[s..e].iter().zip(&near_val[s..e]) {
                acc += pij * sigma[j as usize];
            }
            *yi = acc;
        });
    }
}

/// ponytail: diagonal Jacobi preconditioner from near-field self-interactions
struct DiagJacobi {
    inv_diag: Vec<f64>,
}

impl LinearOperator for DiagJacobi {
    fn dim(&self) -> usize { self.inv_diag.len() }
    fn apply(&self, x: &[f64], y: &mut [f64]) {
        for i in 0..self.inv_diag.len() {
            y[i] = x[i] * self.inv_diag[i];
        }
    }
}

/// Solve for the Maxwell capacitance matrix using the FMM operator + GMRES.
pub fn solve(geo: &Geometry, order: usize, max_level: usize, tol: f64) -> CapResult {
    let set = PanelSet::build(&geo.panels);
    let op = FmmCapOperator::from_set(&set, order, max_level);
    let n = set.len();
    let ncond = geo.num_conductors();

    // Build diagonal Jacobi preconditioner from near-field self-interactions
    let mut diag = vec![1.0f64; n];
    for i in 0..n {
        if let Some(d) = op.diagonal(i) {
            diag[i] = d;
        }
    }
    let precond = DiagJacobi {
        inv_diag: diag.iter().map(|&d| if d.abs() > 1e-30 { 1.0 / d } else { 1.0 }).collect(),
    };

    let opts = GmresOptions { tol, restart: 200, max_restarts: 50 };
    let mut c = DenseMatrix::<f64>::zeros(ncond, ncond);
    for j in 0..ncond {
        let rhs = rhs_unit_conductor(&set, j);
        let sigma = gmres(&op, &rhs, Some(&precond), opts).x;
        accumulate_c(&set, &sigma, j, &mut c);
    }
    CapResult { conductor_names: geo.conductor_names.clone(), c }
}
