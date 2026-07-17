//! Minimal 3-D vector geometry used throughout the discretization and kernels.
//!
//! Deliberately dependency-free (no `nalgebra`) so the core stays small and the
//! data layout is transparent — important for the SoA/SIMD and GPU offload paths
//! described in the design (structure-of-arrays particle/panel data).

use std::ops::{Add, Div, Mul, Neg, Sub};

/// A point or vector in 3-D space (f64, double precision — matching the
/// FastHenry/FastCap accuracy requirement).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Vec3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Vec3 {
    pub const ZERO: Vec3 = Vec3 { x: 0.0, y: 0.0, z: 0.0 };

    #[inline]
    pub const fn new(x: f64, y: f64, z: f64) -> Self {
        Vec3 { x, y, z }
    }

    #[inline]
    pub fn dot(self, o: Vec3) -> f64 {
        self.x * o.x + self.y * o.y + self.z * o.z
    }

    #[inline]
    pub fn cross(self, o: Vec3) -> Vec3 {
        Vec3::new(
            self.y * o.z - self.z * o.y,
            self.z * o.x - self.x * o.z,
            self.x * o.y - self.y * o.x,
        )
    }

    #[inline]
    pub fn norm2(self) -> f64 {
        self.dot(self)
    }

    #[inline]
    pub fn norm(self) -> f64 {
        self.norm2().sqrt()
    }

    /// Euclidean distance to another point.
    #[inline]
    pub fn dist(self, o: Vec3) -> f64 {
        (self - o).norm()
    }

    /// Unit vector; returns [`Vec3::ZERO`] for a zero-length input.
    #[inline]
    pub fn normalized(self) -> Vec3 {
        let n = self.norm();
        if n == 0.0 {
            Vec3::ZERO
        } else {
            self / n
        }
    }

    #[inline]
    pub fn scale(self, s: f64) -> Vec3 {
        Vec3::new(self.x * s, self.y * s, self.z * s)
    }
}

impl Add for Vec3 {
    type Output = Vec3;
    #[inline]
    fn add(self, o: Vec3) -> Vec3 {
        Vec3::new(self.x + o.x, self.y + o.y, self.z + o.z)
    }
}
impl Sub for Vec3 {
    type Output = Vec3;
    #[inline]
    fn sub(self, o: Vec3) -> Vec3 {
        Vec3::new(self.x - o.x, self.y - o.y, self.z - o.z)
    }
}
impl Neg for Vec3 {
    type Output = Vec3;
    #[inline]
    fn neg(self) -> Vec3 {
        Vec3::new(-self.x, -self.y, -self.z)
    }
}
impl Mul<f64> for Vec3 {
    type Output = Vec3;
    #[inline]
    fn mul(self, s: f64) -> Vec3 {
        self.scale(s)
    }
}
impl Div<f64> for Vec3 {
    type Output = Vec3;
    #[inline]
    fn div(self, s: f64) -> Vec3 {
        Vec3::new(self.x / s, self.y / s, self.z / s)
    }
}

/// An orthonormal frame (local coordinate system) for a flat element: `u` and
/// `v` span the element plane, `n` is the outward normal. Used to reduce panel
/// integrals to a 2-D local frame where the analytic formulas apply.
#[derive(Debug, Clone, Copy)]
pub struct Frame {
    pub origin: Vec3,
    pub u: Vec3,
    pub v: Vec3,
    pub n: Vec3,
}

impl Frame {
    /// World coordinates of a point given its local (u,v) coordinates in the plane.
    #[inline]
    pub fn to_world(&self, lu: f64, lv: f64) -> Vec3 {
        self.origin + self.u * lu + self.v * lv
    }

    /// Project a world point into local (u, v, n) coordinates relative to `origin`.
    #[inline]
    pub fn to_local(&self, p: Vec3) -> Vec3 {
        let d = p - self.origin;
        Vec3::new(d.dot(self.u), d.dot(self.v), d.dot(self.n))
    }
}
