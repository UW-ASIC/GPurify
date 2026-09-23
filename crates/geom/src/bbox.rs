//! Axis-aligned bounding boxes and the inclusive proximity predicates that prune
//! every pairwise scan.

use crate::{Dbu, DbuArea};

// `Ord::min`/`max` are not const; downstream `const fn`s call these methods.
const fn min(a: Dbu, b: Dbu) -> Dbu {
    if a.raw() < b.raw() {
        a
    } else {
        b
    }
}

const fn max(a: Dbu, b: Dbu) -> Dbu {
    if a.raw() > b.raw() {
        a
    } else {
        b
    }
}

/// An axis-aligned box, inclusive on both bounds: a zero-area box is a point or
/// a segment, both legal derived shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bbox {
    pub xlo: Dbu,
    pub ylo: Dbu,
    pub xhi: Dbu,
    pub yhi: Dbu,
}

/// [`Bbox::EMPTY`], the identity of [`Bbox::union`].
impl Default for Bbox {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Bbox {
    /// Inverted sentinel at exactly `±MAX_ABS_DBU`, so domain-edge points still fold.
    pub const EMPTY: Self = Self {
        xlo: Dbu::new_unchecked(crate::MAX_ABS_DBU),
        ylo: Dbu::new_unchecked(crate::MAX_ABS_DBU),
        xhi: Dbu::new_unchecked(-crate::MAX_ABS_DBU),
        yhi: Dbu::new_unchecked(-crate::MAX_ABS_DBU),
    };

    pub const fn point(x: Dbu, y: Dbu) -> Self {
        Self {
            xlo: x,
            ylo: y,
            xhi: x,
            yhi: y,
        }
    }

    #[must_use]
    pub const fn include(self, x: Dbu, y: Dbu) -> Self {
        Self {
            xlo: min(self.xlo, x),
            ylo: min(self.ylo, y),
            xhi: max(self.xhi, x),
            yhi: max(self.yhi, y),
        }
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            xlo: min(self.xlo, other.xlo),
            ylo: min(self.ylo, other.ylo),
            xhi: max(self.xhi, other.xhi),
            yhi: max(self.yhi, other.yhi),
        }
    }

    /// `lo > hi` on either axis. A zero-area box is *not* empty.
    pub const fn is_empty(self) -> bool {
        self.xlo.raw() > self.xhi.raw() || self.ylo.raw() > self.yhi.raw()
    }

    /// Share at least one point; touching counts (the fail-closed direction).
    pub const fn overlaps(self, other: Self) -> bool {
        self.xlo.raw() <= other.xhi.raw()
            && other.xlo.raw() <= self.xhi.raw()
            && self.ylo.raw() <= other.yhi.raw()
            && other.ylo.raw() <= self.yhi.raw()
    }

    /// `other` lies entirely inside `self`, boundary inclusive.
    pub const fn contains(self, other: Self) -> bool {
        self.xlo.raw() <= other.xlo.raw()
            && other.xhi.raw() <= self.xhi.raw()
            && self.ylo.raw() <= other.ylo.raw()
            && other.yhi.raw() <= self.yhi.raw()
    }

    /// Within `distance` on both axes, inclusive; `within(_, 0) == overlaps`.
    pub const fn within(self, other: Self, distance: Dbu) -> bool {
        debug_assert!(distance.raw() >= 0, "a spacing distance is non-negative");
        let d = distance.raw();
        self.xlo.raw() <= other.xhi.raw() + d
            && other.xlo.raw() <= self.xhi.raw() + d
            && self.ylo.raw() <= other.yhi.raw() + d
            && other.ylo.raw() <= self.yhi.raw() + d
    }

    /// The overlapping region, `None` exactly when `overlaps` is false.
    pub const fn intersection(self, other: Self) -> Option<Self> {
        let meet = Self {
            xlo: max(self.xlo, other.xlo),
            ylo: max(self.ylo, other.ylo),
            xhi: min(self.xhi, other.xhi),
            yhi: min(self.yhi, other.yhi),
        };
        if meet.is_empty() {
            None
        } else {
            Some(meet)
        }
    }

    /// A whole-domain box's width is `2^41`, past what `new_unchecked` debug-asserts.
    pub const fn width(self) -> Dbu {
        Dbu::new_unchecked(self.xhi.raw() - self.xlo.raw())
    }

    pub const fn height(self) -> Dbu {
        Dbu::new_unchecked(self.yhi.raw() - self.ylo.raw())
    }

    /// Each span clamped at zero before the product, so `EMPTY` measures 0, not `2^82`.
    pub const fn area(self) -> DbuArea {
        let (w, h) = (
            self.xhi.raw() - self.xlo.raw(),
            self.yhi.raw() - self.ylo.raw(),
        );
        let w = if w > 0 { w } else { 0 };
        let h = if h > 0 { h } else { 0 };
        DbuArea::new(w as i128 * h as i128)
    }

    /// Bounding box of a run of coordinates. Asserts equal lengths in release: a
    /// short `zip` would under-size the box and prune real neighbours.
    pub fn of_points(xs: &[Dbu], ys: &[Dbu]) -> Self {
        assert_eq!(xs.len(), ys.len(), "one y per x");
        let mut folded = Self::EMPTY;
        for (&x, &y) in xs.iter().zip(ys) {
            folded = folded.include(x, y);
        }
        folded
    }
}
