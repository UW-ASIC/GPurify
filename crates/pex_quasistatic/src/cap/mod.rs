//! # fastcap
//!
//! Capacitance (electrostatic) front end, built on `quasiss-core`. Parses
//! FastCap surface-panel geometry, assembles the potential-coefficient matrix
//! with exact Wilton analytic entries, and solves per conductor for the Maxwell
//! capacitance matrix.
//!
//! ```no_run
//! let geo = quasiss::cap::parse(&std::fs::read_to_string("bus.qui").unwrap(), 1.0).unwrap();
//! let cap = quasiss::cap::solve(&geo, quasiss::cap::Method::Direct).unwrap();
//! println!("C[0,0] = {} F", cap.c[(0, 0)]);
//! ```

pub mod dielectric;
pub mod fmm_solver;
pub mod geometry;
pub mod listfile;
pub mod mesh;
pub mod solver;

pub use dielectric::{PanelRole, Problem};
pub use listfile::{parse_file as parse_list_file, parse_str as parse_list_str};
pub use geometry::{parse, Geometry};
pub use solver::{assemble_p, solve, CapResult, Method};
#[cfg(feature = "gpu")]
pub use solver::solve_gpu;

/// Solve a multi-dielectric problem (conductors + dielectric interfaces).
pub fn solve_dielectric(problem: &Problem) -> Result<CapResult, dielectric::DielectricError> {
    dielectric::solve(problem)
}

/// Build a [`Geometry`] directly from a set of panels (bypassing the file
/// parser) — used by the mesh generators and tests.
pub fn from_panels(
    panels: Vec<crate::integrals::panel::Panel>,
    conductor_names: Vec<String>,
) -> Geometry {
    let mut geo = Geometry::default();
    geo.panels = panels;
    geo.conductor_names = conductor_names;
    geo
}

// ---------------------------------------------------------------------------
// Auto-selection logic: pick the best solver backend based on problem size
// ---------------------------------------------------------------------------

/// ponytail: solver strategy selected by auto_select; --gpu routes to the
/// GPU dense-iterative solve ([`solve_gpu`]) explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolverStrategy {
    /// Dense CPU (LU or iterative) — fastest for small problems
    DenseCpu,
    /// FMM CPU — pays off above ~500 panels
    FmmCpu,
}

/// Pick the best solver strategy based on panel count:
/// N < 500 dense (no FMM overhead), otherwise FMM.
pub fn auto_select(n_panels: usize) -> SolverStrategy {
    if n_panels < 500 {
        SolverStrategy::DenseCpu
    } else {
        SolverStrategy::FmmCpu
    }
}
