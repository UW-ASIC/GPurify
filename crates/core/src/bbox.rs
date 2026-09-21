//! Axis-aligned bounding boxes, and the proximity predicates that prune every
//! pairwise scan in the tree.

use gpurify_units::{Dbu, DbuArea};

/// Branchless `min`, spelled out because `Ord` is not a const trait on stable
/// (rust#143874) and every predicate below is `const fn`.
#[inline]
const fn min(a: i64, b: i64) -> i64 {
    if a < b {
        a
    } else {
        b
    }
}

/// The other half of [`min`].
#[inline]
const fn max(a: i64, b: i64) -> i64 {
    if a > b {
        a
    } else {
        b
    }
}

/// An axis-aligned box, inclusive on both bounds: a zero-area box is a point,
/// and `lo == hi` on one axis is a segment. Both are legal derived shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bbox {
    pub xlo: Dbu,
    pub ylo: Dbu,
    pub xhi: Dbu,
    pub yhi: Dbu,
}

/// [`Bbox::EMPTY`], the identity of [`Bbox::union`] and the correct fold seed.
impl Default for Bbox {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Bbox {
    /// The empty box: a sentinel that loses to every real point under
    /// [`Bbox::include`]. The bounds are exactly `±MAX_ABS_DBU`, so a point on
    /// the domain edge still folds correctly; anything inside it is a bug.
    pub const EMPTY: Self = Self {
        xlo: Dbu::new_unchecked(gpurify_units::MAX_ABS_DBU),
        ylo: Dbu::new_unchecked(gpurify_units::MAX_ABS_DBU),
        xhi: Dbu::new_unchecked(-gpurify_units::MAX_ABS_DBU),
        yhi: Dbu::new_unchecked(-gpurify_units::MAX_ABS_DBU),
    };

    /// The box containing exactly one point.
    pub const fn point(x: Dbu, y: Dbu) -> Self {
        Self {
            xlo: x,
            ylo: y,
            xhi: x,
            yhi: y,
        }
    }

    /// Grow to contain a point.
    #[must_use]
    pub const fn include(self, x: Dbu, y: Dbu) -> Self {
        // `new_unchecked` is sound here: every bound out is one of its own
        // inputs, so a fold seeded with `EMPTY` over in-domain points stays in
        // domain, `±MAX_ABS_DBU` included.
        Self {
            xlo: Dbu::new_unchecked(min(self.xlo.raw(), x.raw())),
            ylo: Dbu::new_unchecked(min(self.ylo.raw(), y.raw())),
            xhi: Dbu::new_unchecked(max(self.xhi.raw(), x.raw())),
            yhi: Dbu::new_unchecked(max(self.yhi.raw(), y.raw())),
        }
    }

    /// Grow to contain another box.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            xlo: Dbu::new_unchecked(min(self.xlo.raw(), other.xlo.raw())),
            ylo: Dbu::new_unchecked(min(self.ylo.raw(), other.ylo.raw())),
            xhi: Dbu::new_unchecked(max(self.xhi.raw(), other.xhi.raw())),
            yhi: Dbu::new_unchecked(max(self.yhi.raw(), other.yhi.raw())),
        }
    }

    /// True when the box contains no points — `lo > hi` on either axis.
    ///
    /// Distinct from a zero-area box, which contains exactly one point and is
    /// *not* empty. Conflating the two drops legitimately degenerate derived
    /// shapes.
    pub const fn is_empty(self) -> bool {
        self.xlo.raw() > self.xhi.raw() || self.ylo.raw() > self.yhi.raw()
    }

    /// True when the two boxes share at least one point.
    ///
    /// Inclusive: touching counts. That is the fail-closed direction — a
    /// touching pair is kept and exactly re-checked, where `<` would drop it
    /// silently, and every caller reads `false` as "cannot interact".
    pub const fn overlaps(self, other: Self) -> bool {
        self.xlo.raw() <= other.xhi.raw()
            && other.xlo.raw() <= self.xhi.raw()
            && self.ylo.raw() <= other.yhi.raw()
            && other.ylo.raw() <= self.yhi.raw()
    }

    /// True when `other` lies entirely inside `self`, inclusive of the boundary.
    pub const fn contains(self, other: Self) -> bool {
        self.xlo.raw() <= other.xlo.raw()
            && other.xhi.raw() <= self.xhi.raw()
            && self.ylo.raw() <= other.ylo.raw()
            && other.yhi.raw() <= self.yhi.raw()
    }

    /// True when the two boxes are within `distance` of each other on both
    /// axes, inclusive.
    ///
    /// The spacing-rule prune; same inclusivity as [`Bbox::overlaps`].
    pub const fn within(self, other: Self, distance: Dbu) -> bool {
        // A negative distance would make this *stricter* than `overlaps` and
        // silently drop pairs a spacing rule must measure.
        debug_assert!(distance.raw() >= 0, "a spacing distance is non-negative");

        // `overlaps` with each far edge pushed out by `distance`, so
        // `within(_, 0)` is `overlaps` by construction. Both operands are
        // bounded by `MAX_ABS_DBU`, so the sum cannot overflow `i64`.
        self.xlo.raw() <= other.xhi.raw() + distance.raw()
            && other.xlo.raw() <= self.xhi.raw() + distance.raw()
            && self.ylo.raw() <= other.yhi.raw() + distance.raw()
            && other.ylo.raw() <= self.yhi.raw() + distance.raw()
    }

    /// The overlapping region, or `None` when they do not overlap.
    pub const fn intersection(self, other: Self) -> Option<Self> {
        // The meet comes out empty on exactly the pairs `overlaps` rejects,
        // which is what keeps the two predicates from drifting apart.
        let meet = Self {
            xlo: Dbu::new_unchecked(max(self.xlo.raw(), other.xlo.raw())),
            ylo: Dbu::new_unchecked(max(self.ylo.raw(), other.ylo.raw())),
            xhi: Dbu::new_unchecked(min(self.xhi.raw(), other.xhi.raw())),
            yhi: Dbu::new_unchecked(min(self.yhi.raw(), other.yhi.raw())),
        };

        if meet.is_empty() {
            None
        } else {
            Some(meet)
        }
    }

    /// Width, height, and area of the box.
    ///
    /// Area is [`DbuArea`] rather than [`Dbu`] because the product of two
    /// coordinates does not fit `i64`.
    ///
    /// ponytail: a box spanning the *whole* coordinate domain has a width of
    /// `2^41`, one bit past what [`Dbu::new_unchecked`] will assert to in a
    /// debug build. `Dbu`'s `Sub` documents that difference as legal and does
    /// not check, but `Sub` is not a const impl and this signature is `const`,
    /// so `new_unchecked` is the only constructor reachable from here. The
    /// ceiling is a layout 1.1 km on a side, and `Bbox::EMPTY.width()` is
    /// already past it; upgrade path is a const `Dbu::sub` in `gpurify-units`,
    /// which is that crate's change to make, not this one's.
    pub const fn width(self) -> Dbu {
        Dbu::new_unchecked(self.xhi.raw() - self.xlo.raw())
    }
    pub const fn height(self) -> Dbu {
        Dbu::new_unchecked(self.yhi.raw() - self.ylo.raw())
    }
    /// Area of the box; an empty box measures zero.
    ///
    /// Not [`Dbu::mul_wide`]: that asserts both operands are in the coordinate
    /// domain, and a span is a difference of two coordinates so it legally
    /// reaches `2^41`. A zero here is not the same claim as [`Bbox::is_empty`]
    /// — a point and a segment measure zero and contain points.
    pub const fn area(self) -> DbuArea {
        // Each span clamped at zero *before* the product. Unclamped, `EMPTY`
        // inverts both axes and the two negative spans multiply back to
        // `+2^82`, the largest real answer there is, so a `min_area` rule would
        // read the sentinel as an enormous shape and pass; a box empty on one
        // axis only comes out negative and subtracts from any summed density.
        let w = max(self.xhi.raw() - self.xlo.raw(), 0);
        let h = max(self.yhi.raw() - self.ylo.raw(), 0);
        // `i128::from` is not a const impl, so the widening is spelled `as`.
        // Both spans are clamped at zero and bounded by `2^41`, so it is exact.
        let area = w as i128 * h as i128;
        debug_assert!(area >= 0, "a clamped area cannot be negative");
        debug_assert!(
            area.unsigned_abs() <= 1u128 << 82,
            "area past the 2^82 ceiling"
        );
        debug_assert!(!self.is_empty() || area == 0, "an empty box covers no area");
        DbuArea::new(area)
    }

    /// Bounding box of a run of coordinates.
    ///
    /// # Panics
    ///
    /// If the two columns disagree in length, in **every** profile: `zip` would
    /// otherwise fold over the shorter one and return a box that does not cover
    /// every vertex, and an under-sized box prunes real neighbours out of the
    /// spatial index — a missed violation.
    pub fn of_points(xs: &[Dbu], ys: &[Dbu]) -> Self {
        assert_eq!(xs.len(), ys.len(), "one y per x");

        let mut folded = Self::EMPTY;
        for (&x, &y) in xs.iter().zip(ys) {
            folded = folded.include(x, y);
        }

        debug_assert_eq!(
            folded.is_empty(),
            xs.is_empty(),
            "a run of points folds to a non-empty box, and only an empty run does not"
        );
        folded
    }

    /// Bounding box of every polygon in a store, one row of `out` per polygon;
    /// `out` is cleared and refilled.
    pub fn of_polys_into(
        xs: &[Dbu],
        ys: &[Dbu],
        starts: &[u32],
        lens: &[u32],
        out: &mut Vec<Self>,
    ) {
        debug_assert_eq!(xs.len(), ys.len(), "one y per x");
        debug_assert_eq!(starts.len(), lens.len(), "one vertex count per polygon");

        out.clear();
        out.reserve(starts.len());

        for (&start, &len) in starts.iter().zip(lens) {
            let from = start as usize;
            let to = from + len as usize;
            // Fail closed: a range escaping the columns panics on the slice
            // below in every profile.
            debug_assert!(
                to <= xs.len(),
                "a polygon's vertex range escapes the columns"
            );
            out.push(Self::of_points(&xs[from..to], &ys[from..to]));
        }

        debug_assert_eq!(
            out.len(),
            starts.len(),
            "one row per polygon, buffer cleared"
        );
    }
}
