//! Analytic and semi-analytic partial-inductance integrals for straight current
//! filaments — the near-field formulas FastHenry relies on for accuracy.
//!
//! Two regimes, matching the design report's "analytic for the near list,
//! quadrature for the well-separated smooth part":
//!
//!  * **Parallel filaments** (including the exact Grover closed form used for
//!    validation): a closed-form double integral of the Neumann formula.
//!  * **Arbitrarily oriented filaments**: Gauss–Legendre cubature of the Neumann
//!    double line integral (exact in the limit; used only when filaments are not
//!    parallel and not touching).
//!  * **Self partial inductance of a rectangular bar**: the classical
//!    Grover/Rosa closed form.
//!
//! Partial inductance between two filaments carrying uniform axial current is
//!   M = (µ₀/4π) (û₁·û₂) ∫₀^{l₁}∫₀^{l₂} ds dt / |r₁(s) − r₂(t)|.

use crate::quasistatic::constants::MU0_OVER_4PI;
use crate::quasistatic::geometry::Vec3;

/// A straight current filament of finite rectangular cross-section.
#[derive(Debug, Clone, Copy)]
pub struct Filament {
    /// Start point of the filament centre line.
    pub a: Vec3,
    /// End point of the filament centre line.
    pub b: Vec3,
    /// Cross-section width [m] (in-plane, perpendicular to axis).
    pub w: f64,
    /// Cross-section height/thickness [m].
    pub t: f64,
    /// Unit direction of the width side of the cross-section (⊥ axis).
    /// Needed by the exact brick–brick (Hoer–Love) mutual; a canonical
    /// default is chosen when the caller doesn't care.
    pub wdir: Vec3,
}

/// Canonical width direction ⊥ `axis` (same convention as the segment frame).
pub(crate) fn default_wdir(axis: Vec3) -> Vec3 {
    let helper = if axis.z.abs() < 0.99 {
        Vec3::new(0.0, 0.0, 1.0)
    } else {
        Vec3::new(1.0, 0.0, 0.0)
    };
    helper.cross(axis).normalized()
}

impl Filament {
    pub fn new(a: Vec3, b: Vec3, w: f64, t: f64) -> Self {
        let axis = (b - a).normalized();
        Filament { a, b, w, t, wdir: default_wdir(axis) }
    }

    /// Construct with an explicit cross-section frame (width direction).
    pub fn with_frame(a: Vec3, b: Vec3, w: f64, t: f64, wdir: Vec3) -> Self {
        Filament { a, b, w, t, wdir }
    }
    #[inline]
    pub fn length(&self) -> f64 {
        (self.b - self.a).norm()
    }
    #[inline]
    pub fn dir(&self) -> Vec3 {
        (self.b - self.a).normalized()
    }
    #[inline]
    pub fn area(&self) -> f64 {
        self.w * self.t
    }
    #[inline]
    pub fn midpoint(&self) -> Vec3 {
        (self.a + self.b) * 0.5
    }
}

/// Antiderivative used by the parallel-filament closed form:
/// P(u) = u·asinh(u/ρ) − √(u²+ρ²).
#[inline]
fn parallel_primitive(u: f64, rho: f64) -> f64 {
    // asinh(u/rho) = ln(u/rho + sqrt((u/rho)^2 + 1)); use the stable f64 asinh.
    u * (u / rho).asinh() - (u * u + rho * rho).sqrt()
}

/// Exact mutual partial inductance [H] between two **parallel** filaments,
/// computed from the Neumann double integral in closed form.
///
/// Geometry is reduced to: perpendicular separation `rho` between the two lines,
/// and the signed axial coordinates of each filament's endpoints along the
/// common axis (`x1..x2` for filament 1, `y1..y2` for filament 2). `sign` is
/// û₁·û₂ (+1 parallel, −1 antiparallel).
fn mutual_parallel_reduced(rho: f64, x1: f64, x2: f64, y1: f64, y2: f64, sign: f64) -> f64 {
    // Floor rho to avoid the log singularity of exactly-collinear filaments,
    // which do not occur for physically distinct laterally-offset conductors.
    let rho = rho.max(1e-30);
    let p = |u: f64| parallel_primitive(u, rho);
    let integral = p(y2 - x1) - p(y2 - x2) - p(y1 - x1) + p(y1 - x2);
    sign * MU0_OVER_4PI * integral
}

/// Mutual partial inductance [H] between two parallel filaments given as 3-D
/// segments. Panics-free: falls back through the reduced closed form.
pub fn mutual_parallel(f1: &Filament, f2: &Filament) -> f64 {
    let u1 = f1.dir();
    let u2 = f2.dir();
    let sign = u1.dot(u2).signum();
    // Common axis = direction of filament 1.
    let axis = u1;
    // Axial coordinates of endpoints projected on the axis, origin at f1.a.
    let x1 = 0.0;
    let x2 = (f1.b - f1.a).dot(axis);
    let y1 = (f2.a - f1.a).dot(axis);
    let y2 = (f2.b - f1.a).dot(axis);
    // Perpendicular separation: distance between the two parallel infinite lines.
    let d = f2.a - f1.a;
    let along = d.dot(axis);
    let perp = d - axis * along;
    let rho = perp.norm();
    mutual_parallel_reduced(rho, x1, x2, y1.min(y2), y1.max(y2), sign)
}

/// The classical **Grover closed form** for two equal, exactly-aligned parallel
/// filaments of length `l` separated by `d`:
///   M = (µ₀/2π)[ l·asinh(l/d) − √(l²+d²) + d ].
/// Provided as an independent reference for the validation suite.
pub fn mutual_parallel_equal_grover(l: f64, d: f64) -> f64 {
    2.0 * MU0_OVER_4PI * (l * (l / d).asinh() - (l * l + d * d).sqrt() + d)
}

/// Gauss–Legendre nodes/weights on [-1, 1] (n = 8), enough for well-separated
/// smooth filament pairs.
const GL8_X: [f64; 8] = [
    -0.960_289_856_497_536_2,
    -0.796_666_477_413_626_7,
    -0.525_532_409_916_329_0,
    -0.183_434_642_495_649_8,
    0.183_434_642_495_649_8,
    0.525_532_409_916_329_0,
    0.796_666_477_413_626_7,
    0.960_289_856_497_536_2,
];
const GL8_W: [f64; 8] = [
    0.101_228_536_290_376_3,
    0.222_381_034_453_374_5,
    0.313_706_645_877_887_3,
    0.362_683_783_378_362_0,
    0.362_683_783_378_362_0,
    0.313_706_645_877_887_3,
    0.222_381_034_453_374_5,
    0.101_228_536_290_376_3,
];

/// General mutual partial inductance [H] between two filaments of arbitrary
/// orientation, by Gauss–Legendre cubature of the Neumann double integral.
/// Accurate for non-touching pairs; the parallel closed form is preferred when
/// applicable.
pub fn mutual_quadrature(f1: &Filament, f2: &Filament) -> f64 {
    let l1 = f1.length();
    let l2 = f2.length();
    let u1 = f1.dir();
    let u2 = f2.dir();
    let dot = u1.dot(u2);
    let half1 = l1 * 0.5;
    let half2 = l2 * 0.5;
    let mut acc = 0.0;
    for i in 0..8 {
        let s = (GL8_X[i] + 1.0) * half1; // s in [0, l1]
        let p1 = f1.a + u1 * s;
        for j in 0..8 {
            let tpar = (GL8_X[j] + 1.0) * half2; // t in [0, l2]
            let p2 = f2.a + u2 * tpar;
            let r = p1.dist(p2);
            if r > 0.0 {
                acc += GL8_W[i] * GL8_W[j] / r;
            }
        }
    }
    // Jacobians half1, half2 from the [-1,1] -> [0,l] maps.
    MU0_OVER_4PI * dot * acc * half1 * half2
}

// ---------------------------------------------------------------------------
// Exact brick–brick mutual (Hoer & Love 1965), ported from FastHenry
// joelself.c `exact_mutual`/`brick_to_brick`/`eval_eq`. Accounts for the finite
// rectangular cross-sections — the centreline formulas err by O((w/ρ)²) for
// closely packed sub-filaments (skin-effect bundles).
// ---------------------------------------------------------------------------

/// joelself.c EPS: relative magnitude below which a coordinate is treated as
/// zero inside `eval_eq` (guards the log/atan singular terms).
const BRICK_EPS: f64 = 1e-13;
/// joelself.c DEG_TOL: cross-section dimension / length ratio below which the
/// filament is degenerate (tape/line) and the brick formula is skipped.
const DEG_TOL: f64 = 1.1e-4;

#[inline]
fn fill4(e: f64, a: f64, d: f64) -> [f64; 4] {
    [e - a, e + d - a, e + d, e]
}

#[inline]
fn log_term(x: f64, xsq: f64, ysq: f64, zsq: f64, len: f64) -> f64 {
    let _ = xsq;
    ((6.0 * zsq - ysq) * ysq - zsq * zsq) * x * ((x + len) / (ysq + zsq).sqrt()).ln()
}

#[inline]
fn tan_term(x: f64, y: f64, z: f64, zsq: f64, len: f64) -> f64 {
    x * y * z * zsq * (x * y / (z * len)).atan()
}

/// joelself.c `eval_eq`: the Hoer–Love primitive at one corner combination.
fn eval_eq(x: f64, y: f64, z: f64, ref_len: f64) -> f64 {
    let one_over_ref = 1.0 / ref_len.max(x.abs() + y.abs() + z.abs());
    let one_over_ref_sq = one_over_ref * one_over_ref;
    let (xsq, ysq, zsq) = (x * x, y * y, z * z);
    let len = (xsq + ysq + zsq).sqrt();

    let mut ret = (1.0 / 60.0)
        * len
        * (xsq * (xsq - 3.0 * ysq) + ysq * (ysq - 3.0 * zsq) + zsq * (zsq - 3.0 * xsq));

    let nz = |v: f64| (v.abs() < BRICK_EPS) as usize;
    let num_nearzero = nz(x * one_over_ref) + nz(y * one_over_ref) + nz(z * one_over_ref);
    let num_nearzero_sq =
        nz(xsq * one_over_ref_sq) + nz(ysq * one_over_ref_sq) + nz(zsq * one_over_ref_sq);

    if num_nearzero_sq < 2 {
        ret += (1.0 / 24.0)
            * (log_term(x, xsq, ysq, zsq, len)
                + log_term(y, ysq, xsq, zsq, len)
                + log_term(z, zsq, xsq, ysq, len));
    }
    if num_nearzero < 1 {
        ret -= (1.0 / 6.0)
            * (tan_term(x, y, z, zsq, len)
                + tan_term(x, z, y, ysq, len)
                + tan_term(z, y, x, xsq, len));
    }
    ret
}

/// joelself.c `brick_to_brick`: 4×4×4 corner-combination sum.
fn brick_to_brick(
    e: f64, a: f64, d: f64, p: f64, b: f64, c: f64, l3: f64, l1: f64, l2: f64,
) -> f64 {
    let q = fill4(e, a, d);
    let r = fill4(p, b, c);
    let s = fill4(l3, l1, l2);
    let mut total = 0.0;
    for (i, &qi) in q.iter().enumerate() {
        for (j, &rj) in r.iter().enumerate() {
            for (k, &sk) in s.iter().enumerate() {
                let sign = if (i + j + k) % 2 == 0 { 1.0 } else { -1.0 };
                total += sign * eval_eq(qi, rj, sk, a);
            }
        }
    }
    total
}

/// Exact mutual partial inductance [H] between two **parallel** rectangular
/// bricks with aligned (or 90°-rotated) cross-section frames. Returns `None`
/// when the geometry is outside the formula's domain (non-parallel axes,
/// skewed cross-sections, degenerate tape/line cross-sections) — callers fall
/// back to the centreline formulas, which are the correct limits there.
pub fn mutual_brick(fj: &Filament, fm: &Filament) -> Option<f64> {
    let zj = fj.dir();
    if zj.dot(fm.dir()).abs() < 1.0 - 1e-9 {
        return None;
    }
    let xj = fj.wdir;
    let yj = zj.cross(xj).normalized();

    // m's cross-section relative to j's frame: aligned or perpendicular only.
    let wm_along_x = fm.wdir.dot(xj).abs();
    let whperp = if wm_along_x > 1.0 - 1e-6 {
        false
    } else if wm_along_x < 1e-6 {
        true
    } else {
        return None; // skewed cross-section
    };

    let (a, b) = (fj.w, fj.t);
    let (c, d) = if whperp { (fm.w, fm.t) } else { (fm.t, fm.w) };
    let (l1, l2) = (fj.length(), fm.length());

    // Degenerate cross-sections: tape/line formulas (centreline path) apply.
    if a / l1.max(b) < DEG_TOL
        || b / l1.max(a) < DEG_TOL
        || c / l2.max(d) < DEG_TOL
        || d / l2.max(c) < DEG_TOL
    {
        return None;
    }

    // Corner-origin offsets (numerically-fixed form from joelself.c: subtract
    // the big endpoints first, then add the small corner vector).
    let vo = xj * (a * 0.5) + yj * (b * 0.5);
    let end = (fm.a - fj.a) + vo;
    let e = xj.dot(end) - d * 0.5;
    let p = yj.dot(end) - c * 0.5;
    let mut l3 = zj.dot(end);
    let l3_1 = zj.dot((fm.b - fj.a) + vo);
    let mut sign = 1.0;
    if l3 > l3_1 {
        sign = -1.0; // m runs antiparallel to j
        l3 = l3_1;
    }

    let total = brick_to_brick(e, a, d, p, b, c, l3, l1, l2) / (a * b * c * d);
    Some(sign * MU0_OVER_4PI * total)
}

/// Dispatch: exact brick–brick (Hoer–Love) for close parallel filaments where
/// the finite cross-section matters, centreline closed form for parallel
/// filaments that are far (or degenerate), quadrature otherwise.
pub fn mutual(f1: &Filament, f2: &Filament) -> f64 {
    let c = f1.dir().dot(f2.dir()).abs();
    if c > 1.0 - 1e-9 {
        // Perpendicular separation of the centre lines: the centreline formula
        // errs by O((w/ρ)²), so switch to the exact brick formula when close.
        let axis = f1.dir();
        let dv = f2.a - f1.a;
        let rho = (dv - axis * dv.dot(axis)).norm();
        let scale = f1.w.max(f1.t).max(f2.w).max(f2.t);
        if rho < 10.0 * scale {
            if let Some(m) = mutual_brick(f1, f2) {
                return m;
            }
        }
        mutual_parallel(f1, f2)
    } else {
        mutual_quadrature(f1, f2)
    }
}

/// Self partial inductance [H] of a straight rectangular bar of length `l`,
/// width `w`, thickness `t` — the classical Grover/Rosa closed form:
///   L = (µ₀/2π) l [ ln(2l/(w+t)) + 1/2 + 0.2235 (w+t)/l ].
/// Valid for l ≳ (w+t); accurate to a fraction of a percent for wire-like
/// aspect ratios and the standard reference for straight-conductor inductance.
pub fn self_inductance_bar(l: f64, w: f64, t: f64) -> f64 {
    let wt = w + t;
    2.0 * MU0_OVER_4PI * l * ((2.0 * l / wt).ln() + 0.5 + 0.223_5 * wt / l)
}

/// Self partial inductance [H] of a [`Filament`].
pub fn self_inductance(f: &Filament) -> f64 {
    self_inductance_bar(f.length(), f.w, f.t)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ponytail: 1e-9 cross-section = degenerate per DEG_TOL, so these exercise
    // the thin-filament (centreline) paths; brick tests below use fat sections.
    fn fil(a: [f64; 3], b: [f64; 3]) -> Filament {
        Filament::new(Vec3::new(a[0], a[1], a[2]), Vec3::new(b[0], b[1], b[2]), 1e-9, 1e-9)
    }

    /// Touching collinear filaments (every adjacent segment pair in a path).
    /// Exact: M = (µ₀/4π)[(l+m)ln(l+m) − l·ln l − m·ln m].
    #[test]
    fn collinear_touching_matches_closed_form() {
        let (l, m) = (1e-3, 2e-3);
        let f1 = fil([0.0, 0.0, 0.0], [l, 0.0, 0.0]);
        let f2 = fil([l, 0.0, 0.0], [l + m, 0.0, 0.0]);
        let exact = MU0_OVER_4PI * ((l + m) * (l + m).ln() - l * l.ln() - m * m.ln());
        let got = mutual(&f1, &f2);
        assert!(
            ((got - exact) / exact).abs() < 1e-9,
            "collinear touching: got {got:e}, exact {exact:e}"
        );
    }

    /// Perpendicular filaments: û₁·û₂ = 0 ⇒ M = 0 exactly.
    #[test]
    fn perpendicular_mutual_is_zero() {
        let f1 = fil([0.0, 0.0, 0.0], [1e-3, 0.0, 0.0]);
        let f2 = fil([2e-3, 1e-4, 0.0], [2e-3, 1.1e-3, 0.0]);
        assert_eq!(mutual(&f1, &f2), 0.0);
    }

    /// Touching non-parallel pair (45° elbow): GL8 cubature vs a subdivided
    /// reference (split each filament 16× and sum GL8 over sub-pairs — the
    /// singular corner contribution converges under subdivision).
    #[test]
    fn touching_elbow_quadrature_accuracy() {
        let l = 1e-3;
        let c = std::f64::consts::FRAC_1_SQRT_2;
        let f1 = fil([-l, 0.0, 0.0], [0.0, 0.0, 0.0]);
        let f2 = fil([0.0, 0.0, 0.0], [l * c, l * c, 0.0]);

        // Subdivided reference.
        let nsub = 16;
        let mut refv = 0.0;
        let (d1, d2) = (f1.b - f1.a, f2.b - f2.a);
        for i in 0..nsub {
            let a1 = f1.a + d1 * (i as f64 / nsub as f64);
            let b1 = f1.a + d1 * ((i + 1) as f64 / nsub as f64);
            for j in 0..nsub {
                let a2 = f2.a + d2 * (j as f64 / nsub as f64);
                let b2 = f2.a + d2 * ((j + 1) as f64 / nsub as f64);
                refv += mutual_quadrature(
                    &Filament::new(a1, b1, f1.w, f1.t),
                    &Filament::new(a2, b2, f2.w, f2.t),
                );
            }
        }

        let got = mutual(&f1, &f2);
        assert!(
            ((got - refv) / refv).abs() < 0.02,
            "45° elbow: GL8 {got:e} vs subdivided {refv:e}"
        );
    }

    /// Brick formula must reduce to the centreline formula when separation is
    /// large relative to the cross-section.
    #[test]
    fn brick_matches_centerline_when_far() {
        let (l, w, t) = (1e-3, 2e-5, 1e-5);
        let f1 = Filament::new(Vec3::new(0.0, 0.0, 0.0), Vec3::new(l, 0.0, 0.0), w, t);
        let f2 = Filament::new(Vec3::new(0.0, 5e-3, 0.0), Vec3::new(l, 5e-3, 0.0), w, t);
        let brick = mutual_brick(&f1, &f2).unwrap();
        let line = mutual_parallel(&f1, &f2);
        assert!(
            ((brick - line) / line).abs() < 1e-5,
            "far bricks: brick {brick:e} vs centreline {line:e}"
        );
    }

    /// Touching side-by-side bricks (adjacent sub-filaments of a skin-effect
    /// bundle — the case the centreline formula gets a few % wrong). Reference:
    /// subdivide each cross-section 16×16 into thin filaments and average the
    /// pairwise centreline mutuals (uniform-current definition of M).
    #[test]
    fn brick_matches_cross_section_subdivision() {
        let (l, w, t) = (1e-3, 2e-5, 1e-5);
        let f1 = Filament::new(Vec3::new(0.0, 0.0, 0.0), Vec3::new(l, 0.0, 0.0), w, t);
        let (wd, hd) = (f1.wdir, f1.dir().cross(f1.wdir).normalized());
        // Side-by-side touching: centre-to-centre = w along the width direction.
        let f2 = Filament::with_frame(f1.a + wd * w, f1.b + wd * w, w, t, wd);

        let nsub = 16;
        let mut refv = 0.0;
        for i1 in 0..nsub {
            for j1 in 0..nsub {
                let o1 = wd * ((i1 as f64 + 0.5) / nsub as f64 - 0.5) * w
                    + hd * ((j1 as f64 + 0.5) / nsub as f64 - 0.5) * t;
                for i2 in 0..nsub {
                    for j2 in 0..nsub {
                        let o2 = wd * ((i2 as f64 + 0.5) / nsub as f64 - 0.5) * w
                            + hd * ((j2 as f64 + 0.5) / nsub as f64 - 0.5) * t;
                        let t1 = Filament::new(f1.a + o1, f1.b + o1, 1e-12, 1e-12);
                        let t2 = Filament::new(f2.a + o2, f2.b + o2, 1e-12, 1e-12);
                        refv += mutual_parallel(&t1, &t2);
                    }
                }
            }
        }
        refv /= (nsub * nsub * nsub * nsub) as f64;

        let brick = mutual_brick(&f1, &f2).unwrap();
        let line = mutual_parallel(&f1, &f2);
        assert!(
            ((brick - refv) / refv).abs() < 2e-3,
            "touching bricks: brick {brick:e} vs subdivided {refv:e} (centreline {line:e})"
        );
        // and the centreline formula must actually be worse than the brick one
        assert!((brick - refv).abs() < (line - refv).abs());
    }
}
