//! Dense P2P Laplace matvec: multiply the panel potential-coefficient matrix
//! by a charge vector without forming the matrix.
//!
//! Data in: a [`super::mesh::Mesh`]. Data out: `y = P x`, one potential per panel.
//!
//! The substrate is a grounded plane at `z = 0`, by the method of images:
//! each panel's charge `q` at height `z` is paired with `−q` at `−z`, so the
//! potential vanishes on the plane and a conductor's charge is its
//! capacitance to the substrate (Jackson, *Classical Electrodynamics*, 3e,
//! §2.1). Every panel sits above the plane; the mesh leaves a shape on it
//! out (a junction, closed form).
//!
//! Far pairs interact centroid to centroid. A near pair, and each panel with
//! itself, is integrated over both rectangles, the Galerkin coefficient of
//! potential (Ruehli & Brennan, 1973): the potential of a uniformly charged
//! rectangle has a closed form ([`rectangle_potential`]), averaged over the
//! other panel by Gauss–Legendre quadrature, and a panel with itself has a
//! closed form too ([`self_integral`]). Centroid to centroid through a
//! softened distance, the near field made refining a mesh overshoot and
//! fall back (testing-plan F77); integrated, a cube's capacitance rises
//! monotonically toward its published value as the panels shrink.

use super::mesh::Panel;
use fearless_simd::{dispatch, f64x4, Level, Simd, SimdBase, SimdFloat};
use rayon::prelude::*;

/// Vacuum permittivity, F/m. CODATA 2018.
const VACUUM_PERMITTIVITY: f64 = 8.854_187_812_8e-12;

/// `4πε₀`, the denominator of the free-space Green's function.
const FOUR_PI_EPS0: f64 = 4.0 * std::f64::consts::PI * VACUUM_PERMITTIVITY;

/// `4 ln(1 + √2)`: `√A` over this is a square panel's effective self-potential radius.
const SELF_POTENTIAL_SHAPE: f64 = 3.525_494_348_078_172;

/// A pair is near, and integrated over both rectangles, when its centroids
/// are closer than this many times the sum of the two panels' half-diagonals.
/// At 3.05 a 1 µm cube's capacitance rises monotonically under refinement (2
/// to 63 panels a side); at 2.1 the softened far field beyond it still
/// overshoots, by 0.02% at 32 panels a side. The limit is kept off a lattice
/// distance: every squared centroid distance between equal squares of side
/// `a` is a multiple of `a²/4`, and were the limit one (at 2, `8a²`),
/// round-off in the absolute centroids would decide the pair, so moving a
/// layout would change its capacitance (the F46 class). `2 · 3.05² a² =
/// 18.605 a²` is `0.105 a²` from the nearest.
const NEAR: f64 = 3.05;

/// Gauss–Legendre nodes and weights on `[−1, 1]`, four points: exact for a
/// polynomial of degree 7, and the potential of a near rectangle is smooth
/// over the panel it is averaged on but for a logarithmic edge.
const GAUSS: [(f64, f64); 4] = [
    (-0.861_136_311_594_052_6, 0.347_854_845_137_453_9),
    (-0.339_981_043_584_856_3, 0.652_145_154_862_546_1),
    (0.339_981_043_584_856_3, 0.652_145_154_862_546_1),
    (0.861_136_311_594_052_6, 0.347_854_845_137_453_9),
];

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
    /// Effective radius `√A / SELF_POTENTIAL_SHAPE`: the softening
    /// (`|Δc|² + ρ_i ρ_j`) of the dense far-field kernel, which keeps it
    /// finite on the diagonal; near pairs replace what it gives there.
    radius: Vec<f64>,
    /// `1 / (4π ε₀ ε_r)` for the dielectric above each panel.
    coefficient: Vec<f64>,
    /// Near pairs, by row: row `i`'s are `near_start[i] .. near_start[i + 1]`
    /// of the two columns below, ascending by column. Empty: no near pairs.
    near_start: Vec<u32>,
    /// The column of each near pair.
    near_column: Vec<u32>,
    /// Exact minus dense entry of each near pair, added after the dense row.
    near_value: Vec<f64>,
}

impl CpuMatVec {
    /// The kernel's columns for `mesh`, and its near pairs.
    ///
    /// # Time complexity
    ///
    /// *O*(P²) distance tests, one dense product's worth, then a closed form
    /// for each near pair: a bounded number per panel at a uniform edge.
    // ponytail: every pair is tested for nearness; a spatial index when the
    // dense product itself is replaced.
    pub fn build(mesh: &super::mesh::Mesh) -> Self {
        let mut out = Self::default();
        for (panel, &epsilon) in mesh.panel.iter().zip(&mesh.epsilon) {
            out.cx.push(panel.centre[0]);
            out.cy.push(panel.centre[1]);
            out.cz.push(panel.centre[2]);
            out.radius.push(panel.area.sqrt() / SELF_POTENTIAL_SHAPE);
            out.coefficient.push(1.0 / (FOUR_PI_EPS0 * epsilon));
        }
        let rows: Vec<Vec<(u32, f64)>> = (0..mesh.panel.len())
            .into_par_iter()
            .map(|i| out.near_row(&mesh.panel, i))
            .collect();
        out.near_start.push(0);
        for row in rows {
            for (column, value) in row {
                out.near_column.push(column);
                out.near_value.push(value);
            }
            out.near_start
                .push(u32::try_from(out.near_column.len()).expect("the near pairs fit a u32"));
        }
        out
    }

    /// Row `i`'s near pairs, ascending by column: each the integrated entry
    /// less the dense kernel's.
    ///
    /// The integrated entry is `w_ij` times the mean of the two quadratures,
    /// panel `j`'s potential averaged over `i` and `i`'s over `j`, equal but
    /// for the quadrature's error, so the matrix stays symmetric and the
    /// solve reciprocal.
    fn near_row(&self, panel: &[Panel], i: usize) -> Vec<(u32, f64)> {
        let reach = |p: &Panel| p.half[0].hypot(p.half[1]);
        let mut row = Vec::new();
        for (j, other) in panel.iter().enumerate() {
            let d2 = (0..3)
                .map(|axis| (panel[i].centre[axis] - other.centre[axis]).powi(2))
                .sum::<f64>();
            let limit = NEAR * (reach(&panel[i]) + reach(other));
            if j != i && !(d2 < limit * limit) {
                continue;
            }
            let (ik, jk) = (self.coefficient[i], self.coefficient[j]);
            let weight = 2.0 * ik * jk / (ik + jk);
            let exact = if j == i {
                weight * galerkin(other, other, true)
            } else {
                weight
                    * 0.5
                    * (galerkin(&panel[i], other, false) + galerkin(other, &panel[i], false))
            };
            let column = u32::try_from(j).expect("a panel index is a u32");
            row.push((column, exact - self.dense(i, j)));
        }
        row
    }

    /// The dense kernel's entry `P_ij`, as [`Self::row_scalar`] forms it.
    fn dense(&self, i: usize, j: usize) -> f64 {
        let dx = self.cx[i] - self.cx[j];
        let dy = self.cy[i] - self.cy[j];
        let dz = self.cz[i] - self.cz[j];
        let image_z = self.cz[i] + self.cz[j];
        let plane = dx * dx + dy * dy;
        let soft = self.radius[i] * self.radius[j];
        let (ik, jk) = (self.coefficient[i], self.coefficient[j]);
        let weight = 2.0 * ik * jk / (ik + jk);
        weight / (plane + dz * dz + soft).sqrt()
            - weight / (plane + image_z * image_z + soft).sqrt()
    }

    /// Adds the near pairs of rows `first ..` to `out`, each row's in
    /// ascending column order after its dense sum.
    fn add_near(&self, first: usize, x: &[f64], out: &mut [f64]) {
        if self.near_start.is_empty() {
            return;
        }
        for (offset, value) in out.iter_mut().enumerate() {
            let i = first + offset;
            let pairs = self.near_start[i] as usize..self.near_start[i + 1] as usize;
            for (&column, &entry) in self.near_column[pairs.clone()]
                .iter()
                .zip(&self.near_value[pairs])
            {
                *value += entry * x[column as usize];
            }
        }
    }

    /// `y := P x`, `P_ij = w_ij (1/√(|c_i − c_j|² + ρ_i ρ_j) − 1/√(|c_i − c̄_j|² + ρ_i ρ_j))`
    /// for a far pair, with `w_ij = 2 k_i k_j / (k_i + k_j)` and `c̄_j` panel
    /// `j`'s image in the substrate plane `z = 0`; `x` = total panel charge.
    /// A near pair (closer than [`NEAR`] times the half-diagonals summed) and
    /// the diagonal are `w_ij` times the potential each panel's charge,
    /// spread over its rectangle, makes averaged over the other (less its
    /// image's), the mean of the two ways round. Every entry is symmetric in
    /// `i` and `j`, so `P` is too.
    ///
    /// Each row is a strict ascending-j fold of the dense kernel with separate
    /// multiply and add, then the near pairs' corrections in ascending column
    /// order; the output bits depend on it. Rows run in parallel, 4 per SIMD
    /// lane group.
    ///
    /// ponytail: harmonic-mean `k` is the two-medium transmitted image only; no
    /// reflected images at dielectric interfaces, so same-layer coupling is
    /// under-predicted 14–159%. Fix: layered Green's function from the
    /// `ProcessStack`.
    pub fn apply(&self, x: &[f64], y: &mut [f64]) {
        let n = self.cx.len();
        // Release-mode length check: a short vector panics, never solves a prefix.
        let (x, y) = (&x[..n], &mut y[..n]);
        let level = Level::new();
        y.par_chunks_mut(BLOCK)
            .enumerate()
            .for_each(|(block, out)| {
                dispatch!(level, s => self.rows_simd(s, block * BLOCK, x, out));
                self.add_near(block * BLOCK, x, out);
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
                    // Panel j's image sits at -jz.
                    let iz = cz[v] + jz;
                    let plane = dx * dx + dy * dy;
                    let soft = radius[v] * jr;
                    let r2 = plane + dz * dz + soft;
                    let image2 = plane + iz * iz + soft;
                    let weight = two_k[v] * jk * xj / (k[v] + jk);
                    acc[v] += weight / r2.sqrt() - weight / image2.sqrt();
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
            let image_z = iz + self.cz[j];
            let plane = dx * dx + dy * dy;
            let soft = ir * self.radius[j];
            let r2 = plane + dz * dz + soft;
            let image2 = plane + image_z * image_z + soft;
            let jk = self.coefficient[j];
            let weight = 2.0 * ik * jk * xj / (ik + jk);
            potential += weight / r2.sqrt() - weight / image2.sqrt();
        }
        potential
    }
}

/// The potential, in units of `1/(4πε)`, of a unit charge spread evenly
/// over `source`, less its image in the substrate, averaged over `target`:
/// 4 × 4 Gauss–Legendre points of [`rectangle_potential`]. When the two are
/// one panel (`same`), its own term is [`self_integral`] instead, and only
/// the image is a quadrature.
fn galerkin(target: &Panel, source: &Panel, same: bool) -> f64 {
    let normal = usize::from(target.normal);
    let (u, v) = ((normal + 1) % 3, (normal + 2) % 3);
    let mut sum = 0.0;
    for &(a, wa) in &GAUSS {
        for &(b, wb) in &GAUSS {
            let mut point = target.centre;
            point[u] += a * target.half[0];
            point[v] += b * target.half[1];
            let image = [point[0], point[1], -point[2]];
            let direct = if same {
                0.0
            } else {
                rectangle_potential(point, source)
            };
            sum += wa * wb * (direct - rectangle_potential(image, source));
        }
    }
    // The weights sum to 2 on each axis.
    let mut entry = sum / 4.0 / source.area;
    if same {
        let (a, b) = (2.0 * source.half[0], 2.0 * source.half[1]);
        entry += self_integral(a, b) / (source.area * source.area);
    }
    entry
}

/// `∫∫ ∫∫ dA dA' / |r − r'|` over one `a × b` rectangle, twice:
/// `(2/3)(a³ + b³ − d³) + 2a²b asinh(b/a) + 2ab² asinh(a/b)`, `d = √(a² + b²)`.
/// For a unit square, `4 ln(1 + √2) − (4/3)(√2 − 1)`.
fn self_integral(a: f64, b: f64) -> f64 {
    let d = a.hypot(b);
    2.0 / 3.0 * (a * a * a + b * b * b - d * d * d)
        + 2.0 * a * a * b * (b / a).asinh()
        + 2.0 * a * b * b * (a / b).asinh()
}

/// `∫∫ dA / |p − r|` over `panel`, at `point`: the potential of a unit
/// surface density, in units of `1/(4πε)`, in metres.
///
/// With `u`, `v` the panel's coordinates less the point's and `z` the
/// point's height off its plane, the antiderivative of `1/R`,
/// `R = √(u² + v² + z²)`, is
/// `u asinh(v/√(u² + z²)) + v asinh(u/√(v² + z²)) − z atan(uv/(zR))`,
/// taken between the panel's corners. (This form of `u ln(v + R)` drops
/// `u ln √(u² + z²)`, which cancels between corners of one `u`, and so has no
/// logarithm of zero on the panel's own edges.) At a square's centre it is
/// `4a ln(1 + √2)` for a side `a`.
fn rectangle_potential(point: [f64; 3], panel: &Panel) -> f64 {
    let normal = usize::from(panel.normal);
    let (u, v) = ((normal + 1) % 3, (normal + 2) % 3);
    let z = point[normal] - panel.centre[normal];
    let du = panel.centre[u] - point[u];
    let dv = panel.centre[v] - point[v];
    let (hu, hv) = (panel.half[0], panel.half[1]);
    let corner = |u: f64, v: f64| {
        let mut sum = 0.0;
        if u != 0.0 {
            sum += u * (v / u.hypot(z)).asinh();
        }
        if v != 0.0 {
            sum += v * (u / v.hypot(z)).asinh();
        }
        if z != 0.0 {
            let r = (u * u + v * v + z * z).sqrt();
            sum -= z * (u * v / (z * r)).atan();
        }
        sum
    };
    corner(du + hu, dv + hv) - corner(du - hu, dv + hv) - corner(du + hu, dv - hv)
        + corner(du - hu, dv - hv)
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

    /// A panel centred on the origin, normal to axis `normal`, `2 half[0]` by
    /// `2 half[1]`.
    fn plate(normal: u8, half: [f64; 2]) -> super::Panel {
        super::Panel {
            centre: [0.0; 3],
            area: 4.0 * half[0] * half[1],
            conductor: 0,
            normal,
            half,
        }
    }

    /// Oracle: closed forms. A uniformly charged square of side `a` has the
    /// potential `4a ln(1 + √2)` at its centre and half that at a corner (the
    /// square is four quarter-squares seen from their shared corner); a
    /// rectangle `a × b`, `2 (a asinh(b/a) + b asinh(a/b))` at its centre. A
    /// panel normal to x or y gives the same as one normal to z.
    #[test]
    fn a_charged_rectangle_has_its_closed_form_potential_on_its_own_plane() {
        let square = 4.0 * 2.0_f64.sqrt().ln_1p();
        for normal in 0..3_u8 {
            let p = plate(normal, [0.5, 0.5]);
            let centre = super::rectangle_potential([0.0; 3], &p);
            assert!(
                (centre - square).abs() <= 1e-15 * square,
                "{normal}: {centre}"
            );
            let mut corner = [0.0; 3];
            corner[usize::from((normal + 1) % 3)] = 0.5;
            corner[usize::from((normal + 2) % 3)] = -0.5;
            let at_corner = super::rectangle_potential(corner, &p);
            assert!(
                (2.0 * at_corner - square).abs() <= 1e-15 * square,
                "{at_corner}"
            );
        }
        let (a, b) = (3.0_f64, 1.0_f64);
        let want = 2.0 * (a * (b / a).asinh() + b * (a / b).asinh());
        let got = super::rectangle_potential([0.0; 3], &plate(2, [a / 2.0, b / 2.0]));
        assert!((got - want).abs() <= 1e-14 * want, "{got} against {want}");
    }

    /// Oracle: numerical quadrature, and the point-charge limit. Off the
    /// plane, the closed form matches a 1000 × 1000 midpoint sum of `1/R` over
    /// the panel to 1e-6 (the rule's error at that point is about 1e-7); far
    /// away it is the total charge over the distance, to the next multipole's
    /// `(a/d)²` share, 1e-4 at a hundred sides off.
    #[test]
    fn a_charged_rectangle_matches_quadrature_and_its_far_field() {
        let panel = plate(2, [0.5, 0.25]);
        let point = [0.3, -0.1, 0.4_f64];
        let n = 1000;
        let (du, dv) = (1.0 / f64::from(n), 0.5 / f64::from(n));
        let mut sum = 0.0;
        for i in 0..n {
            for j in 0..n {
                let u = -0.5 + (f64::from(i) + 0.5) * du;
                let v = -0.25 + (f64::from(j) + 0.5) * dv;
                let r =
                    ((point[0] - u).powi(2) + (point[1] - v).powi(2) + point[2] * point[2]).sqrt();
                sum += du * dv / r;
            }
        }
        let exact = super::rectangle_potential(point, &panel);
        assert!((exact - sum).abs() <= 1e-6 * sum, "{exact} against {sum}");

        for far in [[0.0, 0.0, 100.0_f64], [100.0, 0.0, 0.0], [-60.0, 80.0, 0.0]] {
            let monopole =
                panel.area / (far[0] * far[0] + far[1] * far[1] + far[2] * far[2]).sqrt();
            let got = super::rectangle_potential(far, &panel);
            assert!((got - monopole).abs() <= 1e-4 * monopole, "{far:?}: {got}");
        }
    }

    /// Oracle: a published value and quadrature. The double integral of
    /// `1/R` over a unit square is `4 ln(1 + √2) − (4/3)(√2 − 1)`, the mean
    /// inverse distance between two points of the square; over a 2 × 1
    /// rectangle it is the closed-form potential averaged over the rectangle,
    /// here by a 400 × 400 midpoint sum, good to 1e-5.
    #[test]
    fn a_rectangle_with_itself_has_its_closed_form_double_integral() {
        let square = 4.0 * 2.0_f64.sqrt().ln_1p() - 4.0 / 3.0 * (2.0_f64.sqrt() - 1.0);
        let got = super::self_integral(1.0, 1.0);
        assert!(
            (got - square).abs() <= 1e-15 * square,
            "{got} against {square}"
        );

        let panel = plate(2, [1.0, 0.5]);
        let n = 400;
        let (du, dv) = (2.0 / f64::from(n), 1.0 / f64::from(n));
        let mut sum = 0.0;
        for i in 0..n {
            for j in 0..n {
                let point = [
                    -1.0 + (f64::from(i) + 0.5) * du,
                    -0.5 + (f64::from(j) + 0.5) * dv,
                    0.0,
                ];
                sum += du * dv * super::rectangle_potential(point, &panel);
            }
        }
        let got = super::self_integral(2.0, 1.0);
        assert!((got - sum).abs() <= 1e-5 * sum, "{got} against {sum}");
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
}
