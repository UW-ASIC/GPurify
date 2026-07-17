//! Multi-dielectric capacitance extraction (FastCap's conductor + dielectric
//! formulation).
//!
//! Equivalent free-space single-layer charge `σ` on every panel reproduces the
//! true potential. Two equation types:
//!  * **Conductor panel k** (surrounding permittivity εₖ): the true potential is
//!    the known conductor voltage,   Σ_l P_kl σ_l = V_k,   P_kl = (1/4πε₀)∫₁/R.
//!  * **Dielectric interface panel k** (outer εo / inner εi): continuity of the
//!    normal displacement D gives
//!      σ_k/(2ε₀)·(εo+εi)/(εo−εi) + Σ_l E_kl σ_l = 0,
//!    with E_kl = (1/4πε₀)∫ (r'−r_k)·n̂_k /R³ da'  (the normal field; self PV = 0).
//!
//! Free charge on conductor i: Q_i = εᵢ · Σ_{panels of i} σ_l a_l  (Gauss' law
//! on the equivalent charges times the surrounding permittivity). Setting each
//! conductor to 1 V in turn gives the Maxwell capacitance matrix.

use crate::cap::solver::CapResult;
use crate::constants::{EPS0, ONE_OVER_4PI_EPS0};
use crate::geometry::Vec3;
use crate::integrals::panel::{field_integral, potential_integral, Panel};
use crate::linalg::{DenseMatrix, LuDecomposition};

/// The role of a panel in a dielectric problem.
#[derive(Debug, Clone)]
pub enum PanelRole {
    /// Conductor surface of conductor `id`, sitting in a medium of relative
    /// permittivity `eps_surrounding`.
    Conductor { id: usize, eps_surrounding: f64 },
    /// Dielectric interface: `eps_out` on the outer side (direction the oriented
    /// normal points), `eps_in` on the inner side where `reference` lies. The
    /// panel normal is oriented to point *away* from `reference` (from the inner
    /// εi region toward the outer εo region). For a closed interface (e.g. a
    /// sphere) `reference` is any interior point (the centre); this gives a
    /// correct radially-outward normal on every panel, unlike a single exterior
    /// reference which would flip far-side panels.
    Dielectric { eps_out: f64, eps_in: f64, reference: Vec3 },
}

/// A capacitance problem with conductors and dielectric interfaces.
#[derive(Debug, Clone, Default)]
pub struct Problem {
    pub panels: Vec<Panel>,
    pub roles: Vec<PanelRole>,
    pub conductor_names: Vec<String>,
}

impl Problem {
    pub fn num_conductors(&self) -> usize {
        self.conductor_names.len()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DielectricError {
    #[error("empty problem")]
    Empty,
    #[error("panels/roles length mismatch")]
    Mismatch,
    #[error("singular system")]
    Singular,
}

/// Oriented outward normal for a dielectric panel: points *away* from the inner
/// reference point (from εi toward εo).
fn oriented_normal(panel: &Panel, reference: Vec3) -> Vec3 {
    let n = panel.normal();
    let c = panel.centroid();
    if n.dot(c - reference) < 0.0 {
        -n
    } else {
        n
    }
}

/// Solve a dielectric capacitance problem for the Maxwell capacitance matrix.
pub fn solve(problem: &Problem) -> Result<CapResult, DielectricError> {
    let n = problem.panels.len();
    if n == 0 {
        return Err(DielectricError::Empty);
    }
    if problem.roles.len() != n {
        return Err(DielectricError::Mismatch);
    }
    let ncond = problem.num_conductors();
    let centroids: Vec<Vec3> = problem.panels.iter().map(|p| p.centroid()).collect();
    let areas: Vec<f64> = problem.panels.iter().map(|p| p.area()).collect();

    // Precompute oriented normals for dielectric panels.
    let normals: Vec<Vec3> = problem
        .panels
        .iter()
        .zip(&problem.roles)
        .map(|(p, role)| match role {
            PanelRole::Dielectric { reference, .. } => oriented_normal(p, *reference),
            PanelRole::Conductor { .. } => p.normal(),
        })
        .collect();

    // Assemble the mixed system matrix A (n×n).
    let mut a = DenseMatrix::<f64>::zeros(n, n);
    for k in 0..n {
        match &problem.roles[k] {
            PanelRole::Conductor { .. } => {
                // Potential row.
                for l in 0..n {
                    a[(k, l)] = ONE_OVER_4PI_EPS0 * potential_integral(&problem.panels[l].vertices, centroids[k]);
                }
            }
            PanelRole::Dielectric { eps_out, eps_in, .. } => {
                let nk = normals[k];
                // PV normal field from source l is E·n̂ = -(1/4πε₀)∫(r'-r_k)·n̂/R³,
                // so the off-diagonal term is -E_kl (see derivation in module docs).
                for l in 0..n {
                    if l == k {
                        continue; // self field PV = 0; diagonal set below.
                    }
                    a[(k, l)] = -ONE_OVER_4PI_EPS0 * field_integral(&problem.panels[l].vertices, centroids[k], nk);
                }
                // Diagonal jump term: (εo+εi)/(2ε₀(εo−εi)).
                let diag = (eps_out + eps_in) / (2.0 * EPS0 * (eps_out - eps_in));
                a[(k, k)] = diag;
            }
        }
    }

    let lu = LuDecomposition::factor(&a).map_err(|_| DielectricError::Singular)?;

    // One RHS per conductor: V=1 on that conductor's panels, 0 on other
    // conductor panels, 0 on dielectric rows.
    let mut c = DenseMatrix::<f64>::zeros(ncond, ncond);
    for j in 0..ncond {
        let mut rhs = vec![0.0; n];
        for (k, role) in problem.roles.iter().enumerate() {
            if let PanelRole::Conductor { id, .. } = role {
                if *id == j {
                    rhs[k] = 1.0;
                }
            }
        }
        let sigma = lu.solve(&rhs);
        // Free charge on each conductor i: Q_i = eps_i * Σ σ_l a_l.
        for (k, role) in problem.roles.iter().enumerate() {
            if let PanelRole::Conductor { id, eps_surrounding } = role {
                c[(*id, j)] += eps_surrounding * sigma[k] * areas[k];
            }
        }
    }

    Ok(CapResult { conductor_names: problem.conductor_names.clone(), c })
}
