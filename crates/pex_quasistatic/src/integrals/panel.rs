//! Analytic potential integrals over flat polygonal panels (Wilton et al.,
//! IEEE-TAP 1984) — the "single most important detail for agreement with the
//! originals" per the design report: the near/self Laplace integral
//!   I(r) = ∫_S 1/‖r − r'‖ da'
//! over a flat polygon S (triangle or quad), evaluated in closed form at an
//! arbitrary observation point r (including r on the panel, i.e. the self term).
//!
//! Uniform (piecewise-constant) source density, as in FastCap's first-order
//! collocation. The formula sums an edge contribution around the polygon.

use crate::geometry::Vec3;

/// A flat polygonal panel (3 or 4 vertices, assumed planar and convex, ordered
/// consistently so the normal is right-handed).
#[derive(Debug, Clone)]
pub struct Panel {
    pub vertices: Vec<Vec3>,
    /// Which conductor this panel belongs to (0-based).
    pub conductor: usize,
}

impl Panel {
    pub fn new(vertices: Vec<Vec3>, conductor: usize) -> Self {
        assert!(vertices.len() >= 3, "panel needs >= 3 vertices");
        Panel { vertices, conductor }
    }

    /// Area-weighted centroid (collocation point).
    pub fn centroid(&self) -> Vec3 {
        // Fan triangulation from vertex 0; area-weighted centroid.
        let v0 = self.vertices[0];
        let mut area_sum = 0.0;
        let mut c = Vec3::ZERO;
        for i in 1..self.vertices.len() - 1 {
            let v1 = self.vertices[i];
            let v2 = self.vertices[i + 1];
            let a = (v1 - v0).cross(v2 - v0).norm() * 0.5;
            let tri_c = (v0 + v1 + v2) * (1.0 / 3.0);
            c = c + tri_c * a;
            area_sum += a;
        }
        if area_sum == 0.0 {
            v0
        } else {
            c * (1.0 / area_sum)
        }
    }

    /// Outward unit normal (right-handed w.r.t. vertex ordering).
    pub fn normal(&self) -> Vec3 {
        let v0 = self.vertices[0];
        let v1 = self.vertices[1];
        let v2 = self.vertices[2];
        (v1 - v0).cross(v2 - v0).normalized()
    }

    /// Panel area (fan triangulation; correct for planar convex polygons).
    pub fn area(&self) -> f64 {
        let v0 = self.vertices[0];
        let mut a = 0.0;
        for i in 1..self.vertices.len() - 1 {
            let v1 = self.vertices[i];
            let v2 = self.vertices[i + 1];
            a += (v1 - v0).cross(v2 - v0).norm() * 0.5;
        }
        a
    }
}

/// Solve-time view of a panel collection, data-oriented hot/cold split: the
/// parse-time `Vec<Panel>` (one heap `Vec<Vec3>` per panel) stays the cold,
/// ergonomic representation; `PanelSet` is built **once** at solve entry and
/// holds the hot per-panel lanes (centroid, area, conductor) plus all vertices
/// flattened into one allocation with CSR offsets, so assembly loops stream
/// contiguous memory and centroids/areas are never recomputed.
///
#[derive(Debug, Clone)]
pub struct PanelSet {
    /// Centroid lanes (SoA).
    pub cx: Vec<f64>,
    pub cy: Vec<f64>,
    pub cz: Vec<f64>,
    pub area: Vec<f64>,
    /// Conductor index per panel (u32 lane; conductor counts are tiny).
    pub conductor: Vec<u32>,
    /// All panel vertices, flattened (3 or 4 per panel).
    verts: Vec<Vec3>,
    /// CSR offsets into `verts`, length `len() + 1`.
    vert_off: Vec<u32>,
}

impl PanelSet {
    /// Build from parsed panels. Uses the existing `centroid()`/`area()`
    /// methods so values are bit-identical to per-panel computation.
    pub fn build(panels: &[Panel]) -> Self {
        let n = panels.len();
        let mut set = PanelSet {
            cx: Vec::with_capacity(n),
            cy: Vec::with_capacity(n),
            cz: Vec::with_capacity(n),
            area: Vec::with_capacity(n),
            conductor: Vec::with_capacity(n),
            verts: Vec::with_capacity(n * 4),
            vert_off: Vec::with_capacity(n + 1),
        };
        set.vert_off.push(0);
        for p in panels {
            let c = p.centroid();
            set.cx.push(c.x);
            set.cy.push(c.y);
            set.cz.push(c.z);
            set.area.push(p.area());
            set.conductor.push(p.conductor as u32);
            set.verts.extend_from_slice(&p.vertices);
            set.vert_off.push(set.verts.len() as u32);
        }
        set
    }

    /// Centroid of panel `i`, gathered from the lanes.
    #[inline]
    pub fn centroid(&self, i: usize) -> Vec3 {
        Vec3::new(self.cx[i], self.cy[i], self.cz[i])
    }

    /// Vertices of panel `i` — same slice contents as `panels[i].vertices`.
    #[inline]
    pub fn verts_of(&self, i: usize) -> &[Vec3] {
        &self.verts[self.vert_off[i] as usize..self.vert_off[i + 1] as usize]
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.area.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.area.is_empty()
    }
}

/// Closed-form ∫_S 1/‖p − r'‖ da' over the flat polygon `vertices` (Wilton
/// 1984). Works for the self term (p in-plane) and all near/far points.
///
/// Returns the integral with units of length (da'/R has dimension length).
pub fn potential_integral(vertices: &[Vec3], p: Vec3) -> f64 {
    let n = polygon_normal(vertices);
    let v0 = vertices[0];
    // Signed normal distance of p from the panel plane.
    let d = (p - v0).dot(n);
    // Foot of the perpendicular: projection of p onto the plane.
    let p0 = p - n * d;
    let absd = d.abs();

    let nv = vertices.len();
    let mut total = 0.0;
    for i in 0..nv {
        let a = vertices[i];
        let b = vertices[(i + 1) % nv];
        let edge = b - a;
        let edge_len = edge.norm();
        if edge_len == 0.0 {
            continue;
        }
        let lhat = edge / edge_len; // unit tangent along edge a->b
        // In-plane outward normal to the edge: û = l̂ × n̂.
        let uhat = lhat.cross(n);

        // Signed perpendicular distance from p0 to the edge line (in plane).
        // Positive when p0 is on the interior side for CCW ordering.
        let p0_perp = (a - p0).dot(uhat);

        // Signed positions of the two endpoints along the edge, measured from
        // the foot of the perpendicular dropped from p0 to the edge line.
        let s_minus = (a - p0).dot(lhat);
        let s_plus = (b - p0).dot(lhat);

        let r0_sq = p0_perp * p0_perp + d * d;
        let r_plus = (s_plus * s_plus + r0_sq).sqrt();
        let r_minus = (s_minus * s_minus + r0_sq).sqrt();

        // log term; guard against log(0) when the observation point lies on the
        // edge line extension.
        let num = r_plus + s_plus;
        let den = r_minus + s_minus;
        let log_term = if num > 0.0 && den > 0.0 {
            p0_perp * (num / den).ln()
        } else if den.abs() > 0.0 {
            // Fall back to the numerically-stable difference-of-asinh form.
            p0_perp * (s_plus.asinh_over(r0_sq) - s_minus.asinh_over(r0_sq))
        } else {
            0.0
        };

        // arctangent (solid-angle) term, only nonzero off-plane.
        let atan_term = if absd > 0.0 && p0_perp != 0.0 {
            let t_plus = (p0_perp * s_plus) / (r0_sq + absd * r_plus);
            let t_minus = (p0_perp * s_minus) / (r0_sq + absd * r_minus);
            absd * (t_plus.atan() - t_minus.atan())
        } else {
            0.0
        };

        total += log_term - atan_term;
    }
    total
}

/// Symmetric 7-point degree-5 triangle quadrature (barycentric coords + weights,
/// weights sum to 1). Used for the normal-field coefficient where no simple exact
/// self form is needed (the self term vanishes by symmetry).
const TRI7: [(f64, f64, f64, f64); 7] = [
    (0.333_333_333_333_333_3, 0.333_333_333_333_333_3, 0.333_333_333_333_333_3, 0.225),
    (0.059_715_871_789_770, 0.470_142_064_105_115, 0.470_142_064_105_115, 0.132_394_152_788_506),
    (0.470_142_064_105_115, 0.059_715_871_789_770, 0.470_142_064_105_115, 0.132_394_152_788_506),
    (0.470_142_064_105_115, 0.470_142_064_105_115, 0.059_715_871_789_770, 0.132_394_152_788_506),
    (0.797_426_985_353_087, 0.101_286_507_323_456, 0.101_286_507_323_456, 0.125_939_180_544_827),
    (0.101_286_507_323_456, 0.797_426_985_353_087, 0.101_286_507_323_456, 0.125_939_180_544_827),
    (0.101_286_507_323_456, 0.101_286_507_323_456, 0.797_426_985_353_087, 0.125_939_180_544_827),
];

/// Normal-field coefficient: ∫_S (r' − p)·n̂_obs / ‖r' − p‖³ da' over the flat
/// polygon `vertices`, with `n_obs` the observation-surface normal. This is
/// 4πε₀ times the coefficient E_kl in the dielectric-interface equation
/// (the normal electric field at `p` due to unit charge density on the panel).
///
/// Computed by degree-5 triangle quadrature over a fan triangulation. The
/// singular self term (p on the panel, n_obs the panel normal) is 0 in the
/// principal-value sense and must be handled by the caller (the ±σ/2ε₀ jump is
/// separated out of this integral).
pub fn field_integral(vertices: &[Vec3], p: Vec3, n_obs: Vec3) -> f64 {
    let v0 = vertices[0];
    let mut acc = 0.0;
    for i in 1..vertices.len() - 1 {
        let v1 = vertices[i];
        let v2 = vertices[i + 1];
        let area = (v1 - v0).cross(v2 - v0).norm() * 0.5;
        if area == 0.0 {
            continue;
        }
        for &(b0, b1, b2, w) in TRI7.iter() {
            let rp = v0 * b0 + v1 * b1 + v2 * b2;
            let d = rp - p;
            let r2 = d.norm2();
            if r2 > 0.0 {
                let r = r2.sqrt();
                acc += w * area * d.dot(n_obs) / (r2 * r);
            }
        }
    }
    acc
}

/// Robust polygon normal via Newell's method (handles slightly non-planar quads).
fn polygon_normal(vertices: &[Vec3]) -> Vec3 {
    let nv = vertices.len();
    let mut nx = 0.0;
    let mut ny = 0.0;
    let mut nz = 0.0;
    for i in 0..nv {
        let c = vertices[i];
        let d = vertices[(i + 1) % nv];
        nx += (c.y - d.y) * (c.z + d.z);
        ny += (c.z - d.z) * (c.x + d.x);
        nz += (c.x - d.x) * (c.y + d.y);
    }
    Vec3::new(nx, ny, nz).normalized()
}

/// Helper for the stable log-term fallback: asinh(s/√r0²) = ln(s + √(s²+r0²)) − ln(√r0²).
trait AsinhOver {
    fn asinh_over(self, r0_sq: f64) -> f64;
}
impl AsinhOver for f64 {
    #[inline]
    fn asinh_over(self, r0_sq: f64) -> f64 {
        let r0 = r0_sq.sqrt();
        if r0 == 0.0 {
            // Degenerate; the log term is multiplied by p0_perp=0 in that case.
            0.0
        } else {
            (self / r0).asinh()
        }
    }
}
