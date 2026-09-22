//! Dense P2P Laplace matvec: multiply the panel potential-coefficient matrix
//! by a charge vector without forming the matrix.
//!
//! Data in: a [`super::mesh::Mesh`]. Data out: `y = P x`, one potential per panel.

/// Vacuum permittivity, F/m. CODATA 2018.
const VACUUM_PERMITTIVITY: f64 = 8.854_187_812_8e-12;

/// `4πε₀`, the denominator of the free-space Green's function.
const FOUR_PI_EPS0: f64 = 4.0 * std::f64::consts::PI * VACUUM_PERMITTIVITY;

/// `4 ln(1 + √2)`: `√A` over this is a square panel's effective self-potential radius.
const SELF_POTENTIAL_SHAPE: f64 = 3.525_494_348_078_172;

/// `y := A x`, with `y` fully overwritten.
pub trait MatVec {
    /// Panel count; `x` and `y` are both this long.
    fn dim(&self) -> usize;
    fn apply(&self, x: &[f64], y: &mut [f64]);
}

/// Which adapter performed the matvec. Only the host `f64` one exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Cpu,
}

/// Host matvec in `f64`, direct O(n²): every pair is evaluated.
#[derive(Debug, Default)]
pub struct CpuMatVec {
    panel: Vec<Collocation>,
}

/// One panel, reduced to what the kernel reads.
#[derive(Debug, Clone, Copy, Default)]
struct Collocation {
    /// Centroid, metres.
    centre: [f64; 3],
    /// Effective radius `√A / SELF_POTENTIAL_SHAPE`; also the softening
    /// (`|Δc|² + ρ_i ρ_j`) that makes the diagonal the exact self-potential.
    radius: f64,
    /// `1 / (4π ε₀ ε_r)` for the dielectric above this panel.
    coefficient: f64,
}

impl CpuMatVec {
    pub fn build(mesh: &super::mesh::Mesh) -> Self {
        let panel = mesh
            .panel
            .iter()
            .zip(&mesh.epsilon)
            .map(|(row, &epsilon)| Collocation {
                centre: row.centre,
                // ponytail: square-panel shape factor on a rectangle; under-reports C
                // on slivers by 3.5% (2:1) up to 64% (100:1). Fix: closed-form rectangle.
                radius: row.area.sqrt() / SELF_POTENTIAL_SHAPE,
                coefficient: 1.0 / (FOUR_PI_EPS0 * epsilon),
            })
            .collect();
        Self { panel }
    }
}

impl MatVec for CpuMatVec {
    fn dim(&self) -> usize {
        self.panel.len()
    }

    /// `P_ij = 2 k_i k_j / (k_i + k_j) / √(|c_i − c_j|² + ρ_i ρ_j)`, `x` = total
    /// panel charge, so `P` is exactly symmetric.
    ///
    /// ponytail: harmonic-mean `k` is the two-medium transmitted image only; no
    /// reflected images, so same-layer coupling is under-predicted 14–159%.
    /// Fix: layered Green's function from the `ProcessStack`.
    fn apply(&self, x: &[f64], y: &mut [f64]) {
        let n = self.panel.len();
        let table = &self.panel[..];
        // Release-mode length check: a short vector panics, never solves a prefix.
        let x = &x[..n];
        let y = &mut y[..n];

        for i in 0..n {
            let row = table[i];
            // Strict ascending-j fold, no FMA: the output bytes depend on it.
            let mut potential = 0.0_f64;
            for j in 0..n {
                let col = table[j];
                let dx = row.centre[0] - col.centre[0];
                let dy = row.centre[1] - col.centre[1];
                let dz = row.centre[2] - col.centre[2];
                let r2 = dx * dx + dy * dy + dz * dz + row.radius * col.radius;
                potential += 2.0 * row.coefficient * col.coefficient * x[j]
                    / ((row.coefficient + col.coefficient) * r2.sqrt());
            }
            y[i] = potential;
        }
    }
}
