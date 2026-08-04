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
//! on a spacing rule, and it is why [`crate::index::candidate_pairs_into`] carries a
//! test adapter: the property that matters is *the prune never rejects a pair
//! the exact predicate would have accepted*, and that property is not
//! observable in the return value.

use gpurify_units::{Dbu, DbuArea};

/// The `min`/`max` branchless idiom, spelled the only way a `const fn` can spell
/// it: `Ord` is not a const trait on stable (rust#143874), so `a.min(b)` does
/// not compile inside any of the predicates below.
///
/// The `if` is the *source form of the builtin*, not a data-dependent branch —
/// it is row one of the branchless catalogue (`if c { a } else { b }` → a `min`
/// builtin), both arms are one already-loaded register, and LLVM lowers it to
/// `cmp`+`cmov` scalar and to `pminsq`/`pmaxsq` once [`Bbox::of_points`]'s fold
/// vectorises. There is no branch in the object code to name an escape valve
/// for.
#[inline]
const fn min(a: i64, b: i64) -> i64 {
    if a < b {
        a
    } else {
        b
    }
}

/// The other half of [`min`]; same argument.
#[inline]
const fn max(a: i64, b: i64) -> i64 {
    if a > b {
        a
    } else {
        b
    }
}

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
        Self {
            xlo: x,
            ylo: y,
            xhi: x,
            yhi: y,
        }
    }

    /// Grow to contain a point. The fold step of [`Bbox::of_points`].
    ///
    /// **Decision** — pure, small in, one value out, and the test plan names it:
    /// a table of (box, point) cases including both domain edges.
    #[must_use]
    pub const fn include(self, x: Dbu, y: Dbu) -> Self {
        // `new_unchecked` is honest here: every bound out is one of its own
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

    /// True when the box contains no points — i.e. `lo > hi` on either axis.
    ///
    /// Distinct from a zero-area box, which contains exactly one point and is
    /// *not* empty. Conflating the two is how a legitimately degenerate derived
    /// shape gets dropped.
    pub const fn is_empty(self) -> bool {
        // A disjunction: empty on one axis is empty, because the box is the
        // product of its two intervals and one empty factor empties the product.
        self.xlo.raw() > self.xhi.raw() || self.ylo.raw() > self.yhi.raw()
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
        // `<=`, four times, and the inclusivity is entirely in those four
        // characters — `<` on any one of them is the mutation this file's
        // module comment is about.
        //
        // `&&` rather than `&`: `BitAnd for bool` is not a const impl, so a
        // `const fn` cannot spell the non-short-circuiting form. It costs
        // nothing — all four operands are already-loaded registers with no side
        // effect, and LLVM if-converts the chain into `setle`/`and` rather than
        // four jumps.
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
    /// The spacing-rule prune. Same inclusivity argument as [`Bbox::overlaps`],
    /// and the same consequence for getting it wrong.
    pub const fn within(self, other: Self, distance: Dbu) -> bool {
        // A negative distance would make this *stricter* than `overlaps` and
        // drop pairs a spacing rule must measure — fail-open, and silent. The
        // limit reaching here has already been through `Grid::to_dbu`, which
        // refuses anything it cannot represent exactly, so this is a caller bug
        // and not an input class.
        debug_assert!(distance.raw() >= 0, "a spacing distance is non-negative");

        // `overlaps` with each far edge pushed out by `distance`, which is why
        // `within(_, 0)` is `overlaps` by construction rather than by a special
        // case. Both operands are bounded by `MAX_ABS_DBU`, so the sum is at
        // most `2^41` and cannot overflow `i64`.
        self.xlo.raw() <= other.xhi.raw() + distance.raw()
            && other.xlo.raw() <= self.xhi.raw() + distance.raw()
            && self.ylo.raw() <= other.yhi.raw() + distance.raw()
            && other.ylo.raw() <= self.yhi.raw() + distance.raw()
    }

    /// The overlapping region, or `None` when they do not overlap.
    pub const fn intersection(self, other: Self) -> Option<Self> {
        // The meet of two boxes under the same lattice `union` is the join of:
        // `max` on the low bounds, `min` on the high ones. It comes out empty
        // on exactly the pairs `overlaps` rejects, which is what keeps the two
        // predicates from drifting apart.
        let meet = Self {
            xlo: Dbu::new_unchecked(max(self.xlo.raw(), other.xlo.raw())),
            ylo: Dbu::new_unchecked(max(self.ylo.raw(), other.ylo.raw())),
            xhi: Dbu::new_unchecked(min(self.xhi.raw(), other.xhi.raw())),
            yhi: Dbu::new_unchecked(min(self.yhi.raw(), other.yhi.raw())),
        };

        // Surviving `if`: not a loop body, and not a select either — the two
        // arms are different `Option` variants, so there is nothing to blend.
        // LLVM builds it as a `cmov` on the discriminant.
        if meet.is_empty() {
            None
        } else {
            Some(meet)
        }
    }

    /// Width, height, and area of the box.
    ///
    /// Area is [`DbuArea`] because the product of two coordinates does not fit
    /// `i64`. This is the bound [`gpurify_units::MAX_ABS_DBU`] exists to
    /// guarantee.
    /// ponytail: a box spanning the *whole* coordinate domain has a width of
    /// `2^41`, one bit past what [`Dbu::new_unchecked`] will assert to in a
    /// debug build. `Dbu`'s `Sub` documents that difference as legal and does
    /// not check, but `Sub` is not a const impl and this signature is `const`,
    /// so `new_unchecked` is the only constructor reachable from here. The
    /// ceiling is a layout 1.1 km on a side, and `Bbox::EMPTY.width()` is
    /// already past it; upgrade path is a const `Dbu::sub` in `gpurify-units`,
    /// which is that crate's change to make, not this one's.
    ///
    /// **Not a wrong answer, and not a fail-open.** `2^41` sits 22 bits inside
    /// `i64`, so the subtraction is exact and a release build returns the true
    /// width; the failure is the `debug_assert` inside `new_unchecked`, which
    /// is loud and fail-closed. What is *not* representable is the claim
    /// `Dbu` makes about its own range — a width is a span, not a coordinate,
    /// and this signature returns the coordinate type. Filed under
    /// `## core/bbox.rs` in `docs/SIGNATURE_DEFECTS.md`; three spend-down
    /// passes have now confirmed no in-file route exists.
    pub const fn width(self) -> Dbu {
        Dbu::new_unchecked(self.xhi.raw() - self.xlo.raw())
    }
    pub const fn height(self) -> Dbu {
        Dbu::new_unchecked(self.yhi.raw() - self.ylo.raw())
    }
    /// Widened before the multiply, not after, and deliberately not via
    /// [`Dbu::mul_wide`]: that asserts both *operands* are in the coordinate
    /// domain, and a width is a difference of two coordinates, so it legally
    /// reaches `2^41`. The product is bounded by `2^82`, which is what
    /// [`gpurify_units::MAX_ABS_DBU`] buys and what `i128` holds with room.
    ///
    /// **An empty box measures zero**, never a negative area and never the
    /// `2^82` its inverted sentinel bounds would otherwise multiply back to.
    /// Unlike [`Bbox::width`], nothing about that is blocked: the clamp lives
    /// in the body. A zero here is still not the same claim as
    /// [`Bbox::is_empty`] — a point and a segment measure zero and contain
    /// points — so read emptiness from the predicate, not from the area.
    pub const fn area(self) -> DbuArea {
        // Each span clamped at zero *before* the product — the same arithmetic
        // `crate::rects::clipped_area` already spells out per rectangle, and for
        // the same reason: an empty box holds no points, so it covers no area.
        //
        // Unclamped, the two answers this returns on an empty box are both
        // worse than useless. `EMPTY` inverts *both* axes, and the two negative
        // spans multiply back to `+2^82` — bit-identical to the area of a box
        // spanning the whole coordinate domain, so the sentinel comes back
        // wearing the largest real answer there is, and a `min_area` rule reads
        // it as an enormous shape and passes. A box empty on one axis only
        // inverts one span and comes out *negative*, which subtracts real area
        // from any density that sums these.
        //
        // Two call sites already defended themselves against this by hand —
        // `pex::quasistatic` clamps `width()`/`height()` at zero before
        // widening, and `rects::clipped_area` carries the `.max(0)` per axis —
        // which is the tell that the guard belonged here, once, where every
        // caller routes through.
        //
        // `max` is the branchless helper above, so this is two selects and not
        // two branches.
        let w = max(self.xhi.raw() - self.xlo.raw(), 0);
        let h = max(self.yhi.raw() - self.ylo.raw(), 0);
        // `i128::from` is not a const impl, so the widening is spelled `as`.
        // Both spans are clamped at zero and bounded by `2^41`, so it is exact.
        let area = w as i128 * h as i128;
        debug_assert!(area >= 0, "a clamped area cannot be negative");
        debug_assert!(area.unsigned_abs() <= 1u128 << 82, "area past the 2^82 ceiling");
        // The shape that separates the two zero-area cases the file's own doc
        // comment insists are different: a point and a segment are non-empty and
        // measure zero, an empty box measures zero because it is empty.
        debug_assert!(!self.is_empty() || area == 0, "an empty box covers no area");
        DbuArea::new(area)
    }

    /// Bounding box of a run of coordinates.
    ///
    /// **Transform** — the `_into` form is absent because the output is one
    /// value, not a buffer. Reads the two coordinate columns in lockstep, so it
    /// is the shape a SIMD reduction wants: two independent min/max
    /// accumulators over contiguous `i64`, no loop-carried dependency beyond
    /// the accumulator.
    ///
    /// # Panics
    ///
    /// If the two columns disagree in length, in **every** profile. `zip` would
    /// otherwise fold over the shorter one and return a box that does not cover
    /// every vertex it was handed — an under-sized box prunes real neighbours
    /// out of the spatial index, which is a missed violation, the fail-open
    /// direction `docs/VOCABULARY.md` §3 names. The check is one compare
    /// hoisted above the loop as a uniform, amortised over the whole run.
    pub fn of_points(xs: &[Dbu], ys: &[Dbu]) -> Self {
        assert_eq!(xs.len(), ys.len(), "one y per x");

        // A strict left fold. `zip` rather than an index: it carries no bounds
        // check and no panic edge, so the body is the pure min/max accumulator
        // LLVM needs to turn into `pminsq`/`pmaxsq`. The `if`s inside `include`
        // are the source form of those builtins, not data-dependent branches —
        // see `min` above.
        let mut folded = Self::EMPTY;
        for (&x, &y) in xs.iter().zip(ys) {
            folded = folded.include(x, y);
        }

        // The shape of the result: a fold over at least one point has grown the
        // sentinel on every axis, and a fold over none has not moved it. This is
        // the assert that catches a seed or a min/max swap, which the value
        // itself does not advertise.
        debug_assert_eq!(
            folded.is_empty(),
            xs.is_empty(),
            "a run of points folds to a non-empty box, and only an empty run does not"
        );
        folded
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
        debug_assert_eq!(xs.len(), ys.len(), "one y per x");
        debug_assert_eq!(starts.len(), lens.len(), "one vertex count per polygon");

        out.clear();
        out.reserve(starts.len());

        // One row per polygon, each a fold over its own vertex range and
        // nothing else, so any row order is legal and this partitions by range.
        for (&start, &len) in starts.iter().zip(lens) {
            let from = start as usize;
            let to = from + len as usize;
            // Fail closed: a range escaping the columns panics on the slice
            // below in every profile. The assert is here to name it.
            debug_assert!(to <= xs.len(), "a polygon's vertex range escapes the columns");
            out.push(Self::of_points(&xs[from..to], &ys[from..to]));
        }

        debug_assert_eq!(out.len(), starts.len(), "one row per polygon, buffer cleared");
    }
}
