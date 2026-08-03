//! Axis-aligned bounding boxes, and the proximity predicates that prune every
//! pairwise scan in the tree.
//!
//! # This file is the one with the history
//!
//! In the previous implementation, making [`Bbox::overlaps`] strict on one axis
//! — turning "touch or overlap" into "strictly overlap", shifting every spacing
//! prune by one database unit — produced **zero test failures across the whole
//! suite**.
//!
//! It is invisible because every consumer re-verifies exactly afterwards. A
//! wrong prune therefore does not produce a wrong answer on the shapes it keeps;
//! it silently drops shapes that should have been checked. That is fail-**open**
//! on a spacing rule, and it is why [`crate::candidate_pairs_into`] carries a
//! test adapter: the property that matters is *the prune never rejects a pair
//! the exact predicate would have accepted*, and that property is not
//! observable in the return value.

use gpurify_units::{Dbu, DbuArea};

/// An inclusive axis-aligned box.
///
/// Inclusive on both bounds, so a zero-area box is a point and a box with
/// `lo == hi` on one axis is a segment. Both occur: a zero-width polygon is
/// rejected at ingest, but a *derived* layer can legitimately produce one.
///
/// **Five questions.** In/out: four `Dbu`. How many: one per polygon, and one
/// per index tile — millions. Access pattern: all four fields are read together
/// by every predicate, so this is the one place `AoS` is right; a `Vec<Bbox>` is
/// 32 contiguous bytes per row and a proximity scan reads all of it.
/// Lifetime: lives as long as the store. Parallelisable: fully.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bbox {
    pub xlo: Dbu,
    pub ylo: Dbu,
    pub xhi: Dbu,
    pub yhi: Dbu,
}

/// [`Bbox::EMPTY`]. The default is the identity of [`Bbox::union`] and the
/// correct seed for any fold, so defaulting to anything else would be a trap.
impl Default for Bbox {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Bbox {
    /// The empty box: a sentinel that loses to every real point under
    /// [`Bbox::include`].
    ///
    /// Built from `±MAX_ABS_DBU`, which dominates the whole legal coordinate
    /// domain *with equality* — a point at exactly `±MAX_ABS_DBU` folds
    /// correctly. Using a value beyond the domain would be margin, not
    /// correctness; using one inside it would be a bug.
    pub const EMPTY: Self = Self {
        xlo: Dbu::new_unchecked(gpurify_units::MAX_ABS_DBU),
        ylo: Dbu::new_unchecked(gpurify_units::MAX_ABS_DBU),
        xhi: Dbu::new_unchecked(-gpurify_units::MAX_ABS_DBU),
        yhi: Dbu::new_unchecked(-gpurify_units::MAX_ABS_DBU),
    };

    /// The box containing exactly one point.
    pub const fn point(x: Dbu, y: Dbu) -> Self {
        todo!()
    }

    /// Grow to contain a point. The fold step of [`Bbox::of_points_into`].
    ///
    /// **Decision** — pure, small in, one value out, and the test plan names it:
    /// a table of (box, point) cases including both domain edges.
    #[must_use]
    pub const fn include(self, x: Dbu, y: Dbu) -> Self {
        todo!()
    }

    /// Grow to contain another box.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        todo!()
    }

    /// True when the box contains no points — i.e. `lo > hi` on either axis.
    ///
    /// Distinct from a zero-area box, which contains exactly one point and is
    /// *not* empty. Conflating the two is how a legitimately degenerate derived
    /// shape gets dropped.
    pub const fn is_empty(self) -> bool {
        todo!()
    }

    /// True when the two boxes share at least one point.
    ///
    /// **Inclusive: touching counts.** Two boxes that share only an edge
    /// overlap. This is deliberate and it is the direction that fails *closed* —
    /// a touching pair is kept and then exactly re-checked, costing time. The
    /// strict version drops it and costs correctness.
    ///
    /// Every caller in the tree treats a `false` here as "these two shapes
    /// cannot interact", so this returning `false` wrongly is unrecoverable
    /// downstream.
    pub const fn overlaps(self, other: Self) -> bool {
        todo!()
    }

    /// True when `other` lies entirely inside `self`, inclusive of the boundary.
    pub const fn contains(self, other: Self) -> bool {
        todo!()
    }

    /// True when the two boxes are within `distance` of each other on both
    /// axes, inclusive.
    ///
    /// The spacing-rule prune. Same inclusivity argument as [`Bbox::overlaps`],
    /// and the same consequence for getting it wrong.
    pub const fn within(self, other: Self, distance: Dbu) -> bool {
        todo!()
    }

    /// The overlapping region, or `None` when they do not overlap.
    pub const fn intersection(self, other: Self) -> Option<Self> {
        todo!()
    }

    /// Width, height, and area of the box.
    ///
    /// Area is [`DbuArea`] because the product of two coordinates does not fit
    /// `i64`. This is the bound [`gpurify_units::MAX_ABS_DBU`] exists to
    /// guarantee.
    pub const fn width(self) -> Dbu {
        todo!()
    }
    pub const fn height(self) -> Dbu {
        todo!()
    }
    pub const fn area(self) -> DbuArea {
        todo!()
    }

    /// Bounding box of a run of coordinates.
    ///
    /// **Transform** — the `_into` form is absent because the output is one
    /// value, not a buffer. Reads the two coordinate columns in lockstep, so it
    /// is the shape a SIMD reduction wants: two independent min/max
    /// accumulators over contiguous `i64`, no loop-carried dependency beyond
    /// the accumulator.
    pub fn of_points(xs: &[Dbu], ys: &[Dbu]) -> Self {
        todo!()
    }

    /// Bounding box of every polygon in a store, one row of `out` per polygon.
    ///
    /// **Transform, A-to-B** — caller owns `out`, which is cleared and refilled
    /// to `starts.len()` rows. Each output row is a function of its own input
    /// range only, so any row order is legal and this parallelises by
    /// partitioning the range list.
    pub fn of_polys_into(
        xs: &[Dbu],
        ys: &[Dbu],
        starts: &[u32],
        lens: &[u32],
        out: &mut Vec<Self>,
    ) {
        todo!()
    }
}
