//! Dielectric interfaces: a stratified stack in the field solve.
//!
//! Data in: the stack's `pex` rows (each a layer's height and the dielectric
//! around it) and the meshed conductors. Data out: the [`Profile`] of the
//! permittivity with height, the panels of each interface between two
//! permittivities ([`interface_panels_into`]), and the operator rows that
//! make those panels' charge the polarisation the interface carries
//! ([`FieldRows`]).
//!
//! # The stack
//!
//! The dielectric is horizontally stratified: each `pex` row that states a
//! dielectric fills the stack from its height up to the next row's height
//! with its permittivity, the lowest row's reaching down to the substrate and
//! the highest row's up without end. A row's dielectric is "the dielectric
//! around it" (deck.md); the band from its height up is the inter-layer
//! dielectric it sits in. Two rows at one height must agree. An interface is
//! each height above the substrate where the permittivity changes.
//!
//! # The formulation
//!
//! FastCap's for several dielectrics (Nabors & White, "Multipole-accelerated
//! capacitance extraction algorithms for 3-D structures with multiple
//! dielectrics", *IEEE Trans. Circuits Syst. I* 39(11), 1992): every surface
//! carries its total charge (free and polarisation) in vacuum, still over the
//! grounded substrate by images. A conductor panel's row holds its potential;
//! an interface panel's row holds the continuity of the normal displacement,
//! `ε_a E⁻ = ε_b E⁺` with `ε_a` below and `ε_b` above, which with the
//! panel's own sheet field `±σ/2ε₀` is
//!
//! `σ = 2ε₀ λ E_z`, `λ = (ε_a − ε_b)/(ε_a + ε_b)`,
//!
//! `E_z` the field at the panel's centroid from every other charge and every
//! image. A conductor's capacitance is its free charge: each panel's total
//! charge times the permittivity outside that face.
//!
//! An interface is meshed over a window: the selection's footprint grown by
//! [`MARGIN`] times the height of the interface or of the highest conductor,
//! whichever is more; its polarisation charge falls with the cube of the
//! distance from the conductors, so what lies beyond reaches a conductor's
//! potential with the window's inverse square. The window is cut on a tensor
//! grid through every conductor edge, at the mesh's panel edge over the
//! conductors and growing by [`GROWTH`] beyond them; a conductor touching or
//! crossing the interface cuts its footprint out.

use super::mesh::Panel;
use gpurify_ingest::deck::ProcessStack;
use rayon::prelude::*;

/// How far an interface's window reaches past the selection's footprint, in
/// multiples of the interface's height or of the highest conductor's top,
/// whichever is more.
pub const MARGIN: f64 = 8.0;

/// How much each grid step beyond the conductors grows over the last.
pub const GROWTH: f64 = 1.5;

/// Two heights closer than this, in metres (a picometre), are one: a layer
/// whose top lands on the next layer's height reads the interface there.
const SAME_HEIGHT: f64 = 1e-12;

/// A pair is near, and integrated exactly, when its centroids are closer
/// than this many times the sum of the two panels' half-diagonals. Twice the
/// potential kernel's (`matvec`): a field falls one power of distance
/// faster than a potential, and its centroid approximation errs more at
/// one distance.
const NEAR: f64 = 6.0;

/// The permittivity as a function of height: band `i` holds `epsilon[i]`
/// from `start[i]` (metres) up to `start[i + 1]`. The first band starts at
/// minus infinity; neighbouring bands differ.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    /// Each band's lower edge, ascending; `start[0]` is `-inf`.
    pub start: Vec<f64>,
    /// Each band's relative permittivity.
    pub epsilon: Vec<f64>,
}

/// Why a stack has no profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Conflict {
    /// The row whose dielectric disagrees with another row's at its height:
    /// the higher layer id of the two.
    pub layer: u16,
}

impl Profile {
    /// The stack's profile, from every row that states a dielectric.
    ///
    /// # Errors
    ///
    /// [`Conflict`] when two rows at one height state different dielectrics.
    pub fn of(stack: &ProcessStack) -> Result<Self, Conflict> {
        let rows = stack.height_nm.len().min(stack.dielectric_k.len());
        // (height in metres, permittivity, layer), sorted by height then layer.
        let mut stated: Vec<(f64, f64, u16)> = (0..rows)
            .filter(|&row| stack.dielectric_k[row] > 0.0 && stack.height_nm[row].is_finite())
            .map(|row| {
                let layer = u16::try_from(row).expect("a stack row is a layer id");
                (stack.height_nm[row] * 1e-9, stack.dielectric_k[row], layer)
            })
            .collect();
        stated.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.2.cmp(&b.2)));
        let mut out = Profile {
            start: Vec::new(),
            epsilon: Vec::new(),
        };
        let mut last: Option<(f64, f64)> = None;
        for &(height, epsilon, layer) in &stated {
            if let Some((at, was)) = last {
                if (height - at).abs() <= SAME_HEIGHT && epsilon.to_bits() != was.to_bits() {
                    return Err(Conflict { layer });
                }
            }
            last = Some((height, epsilon));
            // The substrate is ground; a band starting on or under it starts
            // the profile.
            let from = if out.start.is_empty() || height <= 0.0 {
                f64::NEG_INFINITY
            } else {
                height
            };
            match out.epsilon.last() {
                Some(&previous) if previous.to_bits() == epsilon.to_bits() => {}
                Some(_) if from.is_infinite() => {
                    // A later row on the substrate: its band replaces the first.
                    *out.epsilon.last_mut().expect("a band") = epsilon;
                }
                _ => {
                    out.start.push(from);
                    out.epsilon.push(epsilon);
                }
            }
        }
        Ok(out)
    }

    /// Whether the permittivity changes with height: some interface exists.
    pub fn is_layered(&self) -> bool {
        self.epsilon.len() > 1
    }

    /// The permittivity just above height `z`: at an interface, the upper
    /// band's.
    pub fn above(&self, z: f64) -> f64 {
        let band = self.start.partition_point(|&s| s <= z + SAME_HEIGHT);
        self.epsilon[band.saturating_sub(1)]
    }

    /// The permittivity just below height `z`: at an interface, the lower
    /// band's.
    pub fn below(&self, z: f64) -> f64 {
        let band = self.start.partition_point(|&s| s < z - SAME_HEIGHT);
        self.epsilon[band.saturating_sub(1)]
    }

    /// Each interface: its height in metres, and the permittivity below and
    /// above it.
    pub fn interfaces(&self) -> impl Iterator<Item = (f64, f64, f64)> + '_ {
        (1..self.start.len())
            .map(|band| (self.start[band], self.epsilon[band - 1], self.epsilon[band]))
    }
}

/// One conductor box the interfaces see: its footprint and height, metres.
#[derive(Debug, Clone, Copy)]
pub struct Footprint {
    /// `[xlo, ylo]`.
    pub lo: [f64; 2],
    /// `[xhi, yhi]`.
    pub hi: [f64; 2],
    /// `[bottom, top]`.
    pub z: [f64; 2],
}

/// Grid lines across `[lo, hi]`: every edge in `edges`, at most `step`
/// apart between the first and last of them, and growing by [`GROWTH`]
/// from them out to `lo` and `hi`. Ascending, distinct.
fn grid_lines(edges: &[f64], lo: f64, hi: f64, step: f64) -> Vec<f64> {
    let mut sorted = edges.to_vec();
    sorted.sort_by(f64::total_cmp);
    sorted.dedup_by(|a, b| (*a - *b).abs() <= SAME_HEIGHT);
    let (Some(&first), Some(&last)) = (sorted.first(), sorted.last()) else {
        return vec![lo, hi];
    };
    let mut out = Vec::new();
    // Outward from the first edge, down to `lo`.
    let mut below = Vec::new();
    let (mut at, mut gap) = (first, step);
    while at - gap > lo + SAME_HEIGHT {
        at -= gap;
        below.push(at);
        gap *= GROWTH;
    }
    below.push(lo);
    below.reverse();
    out.extend(below);
    // Across the conductors, each span cut into equal steps of at most `step`.
    for pair in sorted.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a positive span over a positive step, bounded by the panel budget"
        )]
        let pieces = ((b - a) / step - 1e-6).ceil().max(1.0) as u32;
        for k in 0..pieces {
            out.push(a + (b - a) * f64::from(k) / f64::from(pieces));
        }
    }
    out.push(last);
    // Outward from the last edge, up to `hi`.
    let (mut at, mut gap) = (last, step);
    while at + gap < hi - SAME_HEIGHT {
        at += gap;
        out.push(at);
        gap *= GROWTH;
    }
    out.push(hi);
    out.dedup_by(|a, b| (*a - *b).abs() <= SAME_HEIGHT);
    out
}

/// Appends every interface's panels to `out`, interface by interface, each
/// as `(panel, λ)`, `λ = (ε_below − ε_above)/(ε_below + ε_above)`; its
/// conductor is `conductor`, the one past the last real one. A cell inside
/// the footprint of a box that touches or crosses the interface is metal,
/// not an interface, and is left out. Returns the panels appended.
///
/// # Errors
///
/// `Err(())` when the panels would exceed `remaining`, which is charged.
pub fn interface_panels_into(
    profile: &Profile,
    boxes: &[Footprint],
    step: f64,
    conductor: u32,
    remaining: &mut u32,
    out: &mut Vec<(Panel, f64)>,
) -> Result<usize, ()> {
    let before = out.len();
    if boxes.is_empty() {
        return Ok(0);
    }
    let reach = |axis: usize| {
        let lo = boxes
            .iter()
            .map(|b| b.lo[axis])
            .fold(f64::INFINITY, f64::min);
        let hi = boxes
            .iter()
            .map(|b| b.hi[axis])
            .fold(f64::NEG_INFINITY, f64::max);
        (lo, hi)
    };
    let top = boxes.iter().map(|b| b.z[1]).fold(0.0_f64, f64::max);
    let edges = |axis: usize| -> Vec<f64> {
        boxes
            .iter()
            .flat_map(|b| [b.lo[axis], b.hi[axis]])
            .collect()
    };
    let (xs, ys) = (edges(0), edges(1));
    for (z, below, above) in profile.interfaces() {
        let margin = MARGIN * z.max(top);
        let ((xlo, xhi), (ylo, yhi)) = (reach(0), reach(1));
        let gx = grid_lines(&xs, xlo - margin, xhi + margin, step);
        let gy = grid_lines(&ys, ylo - margin, yhi + margin, step);
        let metal: Vec<&Footprint> = boxes
            .iter()
            .filter(|b| b.z[0] <= z + SAME_HEIGHT && b.z[1] >= z - SAME_HEIGHT)
            .collect();
        let lambda = (below - above) / (below + above);
        let cells = (gx.len() - 1) * (gy.len() - 1);
        *remaining = remaining
            .checked_sub(u32::try_from(cells).map_err(|_| ())?)
            .ok_or(())?;
        for x in gx.windows(2) {
            for y in gy.windows(2) {
                let centre = [(x[0] + x[1]) / 2.0, (y[0] + y[1]) / 2.0];
                let inside = metal.iter().any(|b| {
                    b.lo[0] < centre[0]
                        && centre[0] < b.hi[0]
                        && b.lo[1] < centre[1]
                        && centre[1] < b.hi[1]
                });
                if inside {
                    continue;
                }
                let half = [(x[1] - x[0]) / 2.0, (y[1] - y[0]) / 2.0];
                out.push((
                    Panel {
                        centre: [centre[0], centre[1], z],
                        area: 4.0 * half[0] * half[1],
                        conductor,
                        normal: 2,
                        half,
                    },
                    lambda,
                ));
            }
        }
    }
    Ok(out.len() - before)
}

/// `∫∫ (p_z − z') / R³ dA'` over `panel` at `point`: the vertical field of a
/// unit surface density spread over the panel, in units of `1/(4πε₀)`. A
/// horizontal panel in the point's own plane gives 0 (outside it, the field
/// is in the plane; on it, the principal value).
fn vertical_field(point: [f64; 3], panel: &Panel) -> f64 {
    if panel.normal == 2 {
        let w = point[2] - panel.centre[2];
        if w == 0.0 {
            return 0.0;
        }
        let (x1, x2) = (
            panel.centre[0] - panel.half[0] - point[0],
            panel.centre[0] + panel.half[0] - point[0],
        );
        let (y1, y2) = (
            panel.centre[1] - panel.half[1] - point[1],
            panel.centre[1] + panel.half[1] - point[1],
        );
        // The solid-angle antiderivative of w / R³.
        let corner = |u: f64, v: f64| (u * v / (w * (u * u + v * v + w * w).sqrt())).atan();
        return corner(x2, y2) - corner(x1, y2) - corner(x2, y1) + corner(x1, y1);
    }
    // A vertical panel: its horizontal axis and half-widths; the panel's axes
    // are `normal + 1` and `normal + 2` (mod 3), so z is the second for a
    // panel normal to x and the first for one normal to y.
    let normal = usize::from(panel.normal);
    let (across, half_across, half_z) = if normal == 0 {
        (1, panel.half[0], panel.half[1])
    } else {
        (0, panel.half[1], panel.half[0])
    };
    let a = point[normal] - panel.centre[normal];
    let (o1, o2) = (
        panel.centre[across] - half_across - point[across],
        panel.centre[across] + half_across - point[across],
    );
    // ∫ (z − z')/R³ dz' = 1/R at the far end less at the near end, then
    // ∫ do / √(b² + o²) = asinh(o / b).
    let end = |z_end: f64| {
        let b = a.hypot(point[2] - z_end).max(f64::MIN_POSITIVE);
        (o2 / b).asinh() - (o1 / b).asinh()
    };
    end(panel.centre[2] + half_z) - end(panel.centre[2] - half_z)
}

/// `panel` mirrored in the substrate plane `z = 0`.
fn mirrored(panel: &Panel) -> Panel {
    Panel {
        centre: [panel.centre[0], panel.centre[1], -panel.centre[2]],
        ..*panel
    }
}

/// The exact vertical field at `target`'s centroid per unit charge on
/// `source`, less its image's: `(F(source) − F(image)) / A`, in units of
/// `1/(4πε₀)`. With `same`, the source's own direct part is the principal
/// value, 0, and only its image counts.
fn exact(target: &Panel, source: &Panel, same: bool) -> f64 {
    let direct = if same {
        0.0
    } else {
        vertical_field(target.centre, source)
    };
    (direct - vertical_field(target.centre, &mirrored(source))) / source.area
}

/// The far kernel: a unit point charge at `source`'s centroid and its image.
fn far(target: [f64; 3], source: [f64; 3]) -> f64 {
    let (dx, dy) = (target[0] - source[0], target[1] - source[1]);
    let (dz, image) = (target[2] - source[2], target[2] + source[2]);
    let plane = dx * dx + dy * dy;
    let r2 = plane + dz * dz;
    let i2 = plane + image * image;
    dz / (r2 * r2.sqrt()) - image / (i2 * i2.sqrt())
}

/// The rows of the interface panels: for row `g`, panel `first + g`,
/// `y_g = (√A_g/ε₀) (x_g/A_g − (λ_g / 2π) Σ_p x_p h_gp)`, `h_gp` the vertical
/// field at its centroid per unit charge on panel `p`, image included: zero
/// exactly when the interface's displacement is continuous. The scale makes
/// the rows volts, as the conductors' potential rows are.
#[derive(Debug, Default)]
pub struct FieldRows {
    /// The first interface panel; the rows are `first ..` of the system.
    first: usize,
    /// `λ / 2π` per row.
    weight: Vec<f64>,
    /// `√A / ε₀` per row.
    scale: Vec<f64>,
    /// `1 / A` per row.
    inverse_area: Vec<f64>,
    /// Near pairs by row, as `matvec`'s: row `g`'s are
    /// `near_start[g] .. near_start[g + 1]`, each the exact entry less the
    /// far kernel's (all of the exact entry on the diagonal, where the far
    /// kernel is not summed).
    near_start: Vec<u32>,
    near_column: Vec<u32>,
    near_value: Vec<f64>,
}

/// Vacuum permittivity, F/m. CODATA 2018.
const VACUUM_PERMITTIVITY: f64 = 8.854_187_812_8e-12;

impl FieldRows {
    /// The rows of `panel[first ..]`, the interface panels, whose `λ` is
    /// `lambda` in order.
    ///
    /// # Time complexity
    ///
    /// *O*(I · P) distance tests for I interface panels among P, and a
    /// closed form per near pair.
    pub fn build(panel: &[Panel], first: usize, lambda: &[f64]) -> Self {
        let reach = |p: &Panel| p.half[0].hypot(p.half[1]);
        let rows: Vec<Vec<(u32, f64)>> = (first..panel.len())
            .into_par_iter()
            .map(|g| {
                let target = &panel[g];
                let mut row = Vec::new();
                for (p, source) in panel.iter().enumerate() {
                    let d2 = (0..3)
                        .map(|axis| (target.centre[axis] - source.centre[axis]).powi(2))
                        .sum::<f64>();
                    let limit = NEAR * (reach(target) + reach(source));
                    if p != g && !(d2 < limit * limit) {
                        continue;
                    }
                    let value = if p == g {
                        exact(target, source, true)
                    } else {
                        exact(target, source, false) - far(target.centre, source.centre)
                    };
                    row.push((u32::try_from(p).expect("a panel index is a u32"), value));
                }
                row
            })
            .collect();
        let mut out = FieldRows {
            first,
            ..FieldRows::default()
        };
        out.near_start.push(0);
        for row in rows {
            for (column, value) in row {
                out.near_column.push(column);
                out.near_value.push(value);
            }
            out.near_start
                .push(u32::try_from(out.near_column.len()).expect("the near pairs fit a u32"));
        }
        for (g, &l) in lambda.iter().enumerate() {
            let area = panel[first + g].area;
            out.weight.push(l / (2.0 * std::f64::consts::PI));
            out.scale.push(area.sqrt() / VACUUM_PERMITTIVITY);
            out.inverse_area.push(1.0 / area);
        }
        out
    }

    /// Overwrites `y[first ..]` with the interface rows of `x`. Each row is a
    /// strict ascending fold of the far kernel over every other panel, then
    /// its near corrections in column order.
    pub fn apply(&self, panel: &[Panel], x: &[f64], y: &mut [f64]) {
        let first = self.first;
        y[first..].par_iter_mut().enumerate().for_each(|(g, out)| {
            let row = first + g;
            let target = panel[row].centre;
            let mut field = 0.0_f64;
            for (p, (&q, source)) in x.iter().zip(panel).enumerate() {
                if p != row {
                    field += q * far(target, source.centre);
                }
            }
            let pairs = self.near_start[g] as usize..self.near_start[g + 1] as usize;
            for (&column, &value) in self.near_column[pairs.clone()]
                .iter()
                .zip(&self.near_value[pairs])
            {
                field += value * x[column as usize];
            }
            *out = self.scale[g] * (x[row] * self.inverse_area[g] - self.weight[g] * field);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{grid_lines, vertical_field, Panel, Profile};
    use gpurify_ingest::deck::ProcessStack;

    fn plate(normal: u8, centre: [f64; 3], half: [f64; 2]) -> Panel {
        Panel {
            centre,
            area: 4.0 * half[0] * half[1],
            conductor: 0,
            normal,
            half,
        }
    }

    /// Oracle: quadrature and the point-charge limit. Over and beside
    /// horizontal and vertical panels, the closed form matches a 400 × 400
    /// midpoint sum of `(z − z')/R³` to 1e-5; in the panel's own plane a
    /// horizontal panel gives nothing; far away a panel is its charge over
    /// the distance squared, times the cosine to the vertical.
    #[test]
    fn the_vertical_field_of_a_rectangle_matches_quadrature() {
        let quadrature = |point: [f64; 3], panel: &Panel| {
            let n = 400;
            let normal = usize::from(panel.normal);
            let (u, v) = ((normal + 1) % 3, (normal + 2) % 3);
            let (du, dv) = (
                2.0 * panel.half[0] / f64::from(n),
                2.0 * panel.half[1] / f64::from(n),
            );
            let mut sum = 0.0;
            for i in 0..n {
                for j in 0..n {
                    let mut q = panel.centre;
                    q[u] += -panel.half[0] + (f64::from(i) + 0.5) * du;
                    q[v] += -panel.half[1] + (f64::from(j) + 0.5) * dv;
                    let d = [point[0] - q[0], point[1] - q[1], point[2] - q[2]];
                    let r = (d[0] * d[0] + d[1] * d[1] + d[2] * d[2]).sqrt();
                    sum += du * dv * d[2] / (r * r * r);
                }
            }
            sum
        };
        let cases = [
            (plate(2, [0.0, 0.0, 0.0], [0.5, 0.5]), [0.0, 0.0, 0.7]),
            (plate(2, [0.3, -0.2, 0.1], [1.0, 0.25]), [1.9, 0.4, -0.6]),
            (plate(0, [0.0, 0.0, 0.0], [0.5, 0.3]), [0.8, 0.1, 0.9]),
            (plate(1, [0.0, 0.0, 0.0], [0.4, 0.6]), [0.2, -0.7, -0.5]),
        ];
        for (panel, point) in cases {
            let exact = vertical_field(point, &panel);
            let sum = quadrature(point, &panel);
            assert!(
                (exact - sum).abs() <= 1e-5 * sum.abs().max(1e-3),
                "{panel:?} at {point:?}: {exact} against {sum}"
            );
        }
        let square = plate(2, [0.0; 3], [0.5, 0.5]);
        assert!(vertical_field([3.0, 0.0, 0.0], &square).abs() < 1e-15);
        let far = [0.0, 30.0, 40.0];
        let monopole = square.area * 40.0 / 50.0_f64.powi(3);
        let got = vertical_field(far, &square);
        assert!(
            (got - monopole).abs() <= 1e-3 * monopole,
            "{got} against {monopole}"
        );
    }

    /// Oracle: hand-derived from the definition. Rows at 0, 1 and 3 um
    /// stating 3.9, 3.9 and 7 make one interface at 3 um, 3.9 below and 7
    /// above; a row with no dielectric changes nothing; two rows at one
    /// height that disagree are a conflict naming the higher layer.
    #[test]
    fn the_profile_fills_each_band_from_its_row_up() {
        let stack = |rows: &[(f64, f64)]| ProcessStack {
            thickness_nm: vec![100.0; rows.len()],
            height_nm: rows.iter().map(|r| r.0).collect(),
            sheet_res_ohm_sq: vec![0.1; rows.len()],
            area_cap_af_um2: vec![0.0; rows.len()],
            fringe_cap_af_um: vec![0.0; rows.len()],
            dielectric_k: rows.iter().map(|r| r.1).collect(),
        };
        let profile = Profile::of(&stack(&[
            (0.0, 3.9),
            (1_000.0, 3.9),
            (2_000.0, 0.0),
            (3_000.0, 7.0),
        ]))
        .expect("a profile");
        assert!(profile.is_layered());
        let interfaces: Vec<_> = profile.interfaces().collect();
        assert_eq!(interfaces.len(), 1);
        let (z, below, above) = interfaces[0];
        let same = |a: f64, b: f64| a.to_bits() == b.to_bits();
        assert!((z - 3e-6).abs() < 1e-15 && same(below, 3.9) && same(above, 7.0));
        assert!(same(profile.above(3e-6), 7.0));
        assert!(same(profile.below(3e-6), 3.9));
        assert!(same(profile.above(2.5e-6), 3.9));
        assert!(same(profile.below(9e-6), 7.0));
        let uniform = Profile::of(&stack(&[(0.0, 3.9), (500.0, 3.9)])).expect("a profile");
        assert!(!uniform.is_layered());
        let conflict = Profile::of(&stack(&[(500.0, 3.9), (500.0, 4.2)]));
        assert_eq!(conflict, Err(super::Conflict { layer: 1 }));
    }

    /// Oracle: construct-from-answer. The lines pass through every edge,
    /// are at most a step apart between the edges, grow by `GROWTH` outside
    /// them, and end on the window.
    #[test]
    fn grid_lines_pass_through_every_edge_and_grow_outside() {
        let lines = grid_lines(&[0.0, 1.0, 0.25], -10.0, 11.0, 0.3);
        for edge in [0.0, 1.0, 0.25] {
            assert!(
                lines.iter().any(|&l| (l - edge).abs() < 1e-12),
                "{edge}: {lines:?}"
            );
        }
        assert_eq!(lines.first(), Some(&-10.0));
        assert_eq!(lines.last(), Some(&11.0));
        for pair in lines.windows(2) {
            assert!(pair[1] > pair[0], "{lines:?}");
            if pair[0] >= 0.0 && pair[1] <= 1.0 {
                assert!(pair[1] - pair[0] <= 0.3 + 1e-12, "{lines:?}");
            }
        }
        let gaps: Vec<f64> = lines
            .windows(2)
            .filter(|p| p[0] >= 1.0 && p[1] < 11.0)
            .map(|p| p[1] - p[0])
            .collect();
        for g in gaps.windows(2) {
            assert!((g[1] / g[0] - super::GROWTH).abs() < 1e-9, "{gaps:?}");
        }
    }
}
