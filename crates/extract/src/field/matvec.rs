//! Dense P2P Laplace matvec: multiply the panel potential-coefficient matrix
//! by a charge vector without forming the matrix.
//!
//! Data in: a [`super::mesh::Mesh`]. Data out: `y = P x`, one potential per panel.

use fearless_simd::{dispatch, f64x4, Level, Simd, SimdBase, SimdFloat};
use rayon::prelude::*;

/// Vacuum permittivity, F/m. CODATA 2018.
const VACUUM_PERMITTIVITY: f64 = 8.854_187_812_8e-12;

/// `4πε₀`, the denominator of the free-space Green's function.
const FOUR_PI_EPS0: f64 = 4.0 * std::f64::consts::PI * VACUUM_PERMITTIVITY;

/// `4 ln(1 + √2)`: `√A` over this is a square panel's effective self-potential radius.
const SELF_POTENTIAL_SHAPE: f64 = 3.525_494_348_078_172;

/// Rows per rayon task; a multiple of the tile.
const BLOCK: usize = 64;

/// Target rows evaluated together against one broadcast source.
const TILE: usize = 8;

/// The panels as `SoA` columns, reduced to what the kernel reads.
#[derive(Debug, Default)]
pub struct CpuMatVec {
    /// Centroids, metres.
    cx: Vec<f64>,
    cy: Vec<f64>,
    cz: Vec<f64>,
    /// Effective radius `√A / SELF_POTENTIAL_SHAPE`; also the softening
    /// (`|Δc|² + ρ_i ρ_j`) that makes the diagonal the exact self-potential.
    radius: Vec<f64>,
    /// `1 / (4π ε₀ ε_r)` for the dielectric above each panel.
    coefficient: Vec<f64>,
}

impl CpuMatVec {
    pub fn build(mesh: &super::mesh::Mesh) -> Self {
        let mut out = Self::default();
        for (panel, &epsilon) in mesh.panel.iter().zip(&mesh.epsilon) {
            out.cx.push(panel.centre[0]);
            out.cy.push(panel.centre[1]);
            out.cz.push(panel.centre[2]);
            // ponytail: square-panel shape factor on a rectangle; under-reports C
            // on slivers by 3.5% (2:1) up to 64% (100:1). Fix: closed-form rectangle.
            out.radius.push(panel.area.sqrt() / SELF_POTENTIAL_SHAPE);
            out.coefficient.push(1.0 / (FOUR_PI_EPS0 * epsilon));
        }
        out
    }

    /// `y := P x`, `P_ij = 2 k_i k_j / (k_i + k_j) / √(|c_i − c_j|² + ρ_i ρ_j)`,
    /// `x` = total panel charge, so `P` is exactly symmetric.
    ///
    /// Each row is a strict ascending-j fold with separate multiply and add; the
    /// output bits depend on it. Rows run in parallel, 4 per SIMD lane group.
    ///
    /// ponytail: harmonic-mean `k` is the two-medium transmitted image only; no
    /// reflected images, so same-layer coupling is under-predicted 14–159%.
    /// Fix: layered Green's function from the `ProcessStack`.
    pub fn apply(&self, x: &[f64], y: &mut [f64]) {
        let n = self.cx.len();
        // Release-mode length check: a short vector panics, never solves a prefix.
        let (x, y) = (&x[..n], &mut y[..n]);
        let level = Level::new();
        y.par_chunks_mut(BLOCK)
            .enumerate()
            .for_each(|(block, out)| {
                dispatch!(level, s => self.rows_simd(s, block * BLOCK, x, out));
            });
    }

    /// Rows `first ..` into `out`, [`TILE`] at a time; the remainder is scalar.
    #[inline(always)]
    fn rows_simd<S: Simd>(&self, s: S, first: usize, x: &[f64], out: &mut [f64]) {
        const VECTORS: usize = TILE / 4;
        let (tiles, tail) = out.as_chunks_mut::<TILE>();
        for (t, tile) in tiles.iter_mut().enumerate() {
            let i = first + t * TILE;
            let lanes = |column: &[f64], v: usize| f64x4::from_slice(s, &column[i + 4 * v..][..4]);
            let cx: [_; VECTORS] = std::array::from_fn(|v| lanes(&self.cx, v));
            let cy: [_; VECTORS] = std::array::from_fn(|v| lanes(&self.cy, v));
            let cz: [_; VECTORS] = std::array::from_fn(|v| lanes(&self.cz, v));
            let radius: [_; VECTORS] = std::array::from_fn(|v| lanes(&self.radius, v));
            let k: [_; VECTORS] = std::array::from_fn(|v| lanes(&self.coefficient, v));
            let two_k: [_; VECTORS] = std::array::from_fn(|v| f64x4::splat(s, 2.0) * k[v]);
            let mut acc = [f64x4::splat(s, 0.0); VECTORS];
            for (j, &xj) in x.iter().enumerate() {
                let (jx, jy, jz) = (self.cx[j], self.cy[j], self.cz[j]);
                let (jr, jk) = (self.radius[j], self.coefficient[j]);
                for v in 0..VECTORS {
                    let dx = cx[v] - jx;
                    let dy = cy[v] - jy;
                    let dz = cz[v] - jz;
                    let r2 = dx * dx + dy * dy + dz * dz + radius[v] * jr;
                    acc[v] += two_k[v] * jk * xj / ((k[v] + jk) * r2.sqrt());
                }
            }
            for v in 0..VECTORS {
                acc[v].store_slice(&mut tile[4 * v..][..4]);
            }
        }
        let done = first + tiles.len() * TILE;
        for (offset, value) in tail.iter_mut().enumerate() {
            *value = self.row_scalar(done + offset, x);
        }
    }

    /// Row `i` of `P x`: the reference the SIMD tile must match bit for bit.
    fn row_scalar(&self, i: usize, x: &[f64]) -> f64 {
        let (ix, iy, iz, ir, ik) = (
            self.cx[i],
            self.cy[i],
            self.cz[i],
            self.radius[i],
            self.coefficient[i],
        );
        let mut potential = 0.0_f64;
        for (j, &xj) in x.iter().enumerate() {
            let dx = ix - self.cx[j];
            let dy = iy - self.cy[j];
            let dz = iz - self.cz[j];
            let r2 = dx * dx + dy * dy + dz * dz + ir * self.radius[j];
            let jk = self.coefficient[j];
            potential += 2.0 * ik * jk * xj / ((ik + jk) * r2.sqrt());
        }
        potential
    }
}

#[cfg(test)]
mod tests {
    use super::CpuMatVec;
    use gpurify_testgen::Rng;

    fn random(rng: &mut Rng, n: usize) -> (CpuMatVec, Vec<f64>) {
        let mut m = CpuMatVec::default();
        let mut x = Vec::with_capacity(n);
        for i in 0..n {
            // Every fourth panel coincides with its predecessor: r2 is the softening alone.
            let repeat = i % 4 == 3;
            let coord = |rng: &mut Rng, column: &[f64]| {
                if repeat {
                    column[i - 1]
                } else {
                    rng.unit() * 2e-5 - 1e-5
                }
            };
            let (cx, cy, cz) = (coord(rng, &m.cx), coord(rng, &m.cy), coord(rng, &m.cz));
            m.cx.push(cx);
            m.cy.push(cy);
            m.cz.push(cz);
            m.radius.push(1e-9 + rng.unit() * 1e-7);
            m.coefficient.push(1e10 * (1.0 + rng.unit() * 11.0));
            x.push(match i % 5 {
                0 => 0.0,
                1 => -1e-18,
                _ => rng.unit() * 2e-15 - 1e-15,
            });
        }
        (m, x)
    }

    /// Oracle: the scalar row fold. Lengths cover every tile/block remainder.
    #[test]
    fn the_simd_matvec_matches_the_scalar_fold_bit_for_bit() {
        let mut rng = Rng::new(11);
        let lengths = (0..=3 * super::TILE + 1).chain([63, 64, 65, 129, 300]);
        for n in lengths {
            let (m, x) = random(&mut rng, n);
            let mut y = vec![f64::NAN; n];
            m.apply(&x, &mut y);
            for (i, &got) in y.iter().enumerate() {
                let want = m.row_scalar(i, &x);
                assert_eq!(got.to_bits(), want.to_bits(), "n {n}, row {i}");
            }
        }
    }

    /// `cargo test -p gpurify-extract --release -- --ignored --nocapture matvec_timing`
    #[test]
    #[ignore = "timing, run by hand in --release"]
    fn matvec_timing() {
        let mut rng = Rng::new(5);
        for n in [256, 2_048, 8_192] {
            let (m, x) = random(&mut rng, n);
            let mut y = vec![0.0; n];
            let reps = (8_192 * 8_192 / (n * n)).clamp(1, 200);
            let start = std::time::Instant::now();
            for _ in 0..reps {
                for (i, value) in y.iter_mut().enumerate() {
                    *value = m.row_scalar(i, std::hint::black_box(&x));
                }
            }
            let scalar = start.elapsed() / u32::try_from(reps).expect("small");
            let start = std::time::Instant::now();
            for _ in 0..reps {
                m.apply(std::hint::black_box(&x), &mut y);
            }
            let simd = start.elapsed() / u32::try_from(reps).expect("small");
            std::hint::black_box(&y);
            println!(
                "n {n}: scalar 1-thread {scalar:?}, simd+rayon {simd:?}, {:.1}x",
                scalar.as_secs_f64() / simd.as_secs_f64()
            );
        }
    }
}
