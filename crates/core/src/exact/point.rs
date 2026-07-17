//! Exact point primitive and orientation predicates.

/// A point in layout database units.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

impl Point {
    #[must_use]
    pub const fn new(x: i32, y: i32) -> Self {
        Self { x, y }
    }
}

impl From<(i32, i32)> for Point {
    fn from((x, y): (i32, i32)) -> Self {
        Self { x, y }
    }
}

/// Orientation of an ordered point triple, or winding of a non-degenerate ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Orientation {
    Clockwise,
    Collinear,
    CounterClockwise,
}

/// Exact orientation over the complete `i32` coordinate range.
#[must_use]
pub fn orientation(a: Point, b: Point, c: Point) -> Orientation {
    match cross(a, b, c).cmp(&0) {
        std::cmp::Ordering::Less => Orientation::Clockwise,
        std::cmp::Ordering::Equal => Orientation::Collinear,
        std::cmp::Ordering::Greater => Orientation::CounterClockwise,
    }
}

#[inline]
pub(super) fn cross(a: Point, b: Point, c: Point) -> i128 {
    let abx = b.x as i128 - a.x as i128;
    let aby = b.y as i128 - a.y as i128;
    let acx = c.x as i128 - a.x as i128;
    let acy = c.y as i128 - a.y as i128;
    abx * acy - aby * acx
}

/// True when `p` lies on the closed segment `ab`.
#[must_use]
pub fn on_segment(a: Point, b: Point, p: Point) -> bool {
    cross(a, b, p) == 0
        && p.x >= a.x.min(b.x)
        && p.x <= a.x.max(b.x)
        && p.y >= a.y.min(b.y)
        && p.y <= a.y.max(b.y)
}

/// Exact rational point for sweep-line intersection representation.
/// Each coordinate is `num / den` with `den > 0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RationalPoint {
    pub x_num: i128,
    pub x_den: i128,
    pub y_num: i128,
    pub y_den: i128,
}

impl RationalPoint {
    /// Snap to the nearest integer point. Returns `None` if either coordinate
    /// overflows `i32`.
    ///
    /// ponytail: uses Euclidean rounding (round-half-away-from-zero) so that
    /// non-integer intersection points still produce a valid arrangement vertex.
    /// The arrangement is already approximate at non-integer intersections; the
    /// alternative is full rational arithmetic throughout, add if needed.
    #[must_use]
    pub fn try_snap(&self) -> Option<Point> {
        let snap = |num: i128, den: i128| -> Option<i32> {
            if den == 0 {
                return None;
            }
            // Normalize so denominator is positive.
            let (n, d) = if den < 0 { (-num, -den) } else { (num, den) };
            // Euclidean rounding: (n + d/2) / d for positive n,
            // (n - d/2) / d for negative n.
            let v = if n >= 0 {
                (n + d / 2) / d
            } else {
                (n - d / 2) / d
            };
            i32::try_from(v).ok()
        };
        Some(Point::new(
            snap(self.x_num, self.x_den)?,
            snap(self.y_num, self.y_den)?,
        ))
    }
}

/// Compute the exact rational intersection of two closed segments, if they
/// cross at a single interior point (proper intersection). Returns `None` for
/// disjoint, touching, collinear, or degenerate configurations — those are
/// handled by `classify_segment_intersection`.
///
/// Uses the standard parametric formula with i128 arithmetic. The cross
/// products involved are at most ~2×(2^31)^2 ≈ 2^63 per factor, so the final
/// products fit comfortably in i128.
#[must_use]
pub fn segment_intersection_rational(
    a0: Point,
    a1: Point,
    b0: Point,
    b1: Point,
) -> Option<RationalPoint> {
    // Direction vectors.
    let dax = a1.x as i128 - a0.x as i128;
    let day = a1.y as i128 - a0.y as i128;
    let dbx = b1.x as i128 - b0.x as i128;
    let dby = b1.y as i128 - b0.y as i128;

    // Denominator = da × db.
    let denom = dax * dby - day * dbx;
    if denom == 0 {
        return None; // parallel or collinear
    }

    // t = ((b0 - a0) × db) / denom
    let dx = b0.x as i128 - a0.x as i128;
    let dy = b0.y as i128 - a0.y as i128;
    let t_num = dx * dby - dy * dbx;

    // u = ((b0 - a0) × da) / denom
    let u_num = dx * day - dy * dax;

    // Check that 0 < t < 1 and 0 < u < 1 (strictly interior).
    // With denom possibly negative, normalize the sign check.
    let (t_num, u_num, denom) = if denom < 0 {
        (-t_num, -u_num, -denom)
    } else {
        (t_num, u_num, denom)
    };

    if t_num <= 0 || t_num >= denom || u_num <= 0 || u_num >= denom {
        return None; // not a proper interior crossing
    }

    // Intersection = a0 + t * da, expressed as rational with denominator `denom`.
    // x = (a0.x * denom + t_num * dax) / denom
    // ponytail: checked_mul would need i256 for pathological i32 inputs;
    // the actual products are ≤ ~2^95 which fits i128 for realistic layout coords.
    let x_num = (a0.x as i128) * denom + t_num * dax;
    let y_num = (a0.y as i128) * denom + t_num * day;

    Some(RationalPoint {
        x_num,
        x_den: denom,
        y_num,
        y_den: denom,
    })
}
