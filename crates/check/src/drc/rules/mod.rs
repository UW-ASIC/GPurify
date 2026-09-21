//! The twenty-four rule kinds, grouped by what they measure.
//!
//! Every transform appends to `out` and `runs` — never clears them — pushes
//! exactly one [`RuleRun`] per table row through `record_run`, counts
//! `examined` in the primitive named in its own doc, and allocates nothing per
//! row.
//!
//! `Violation::at` is the midpoint of the thing being measured, matching
//! `gpurify_testgen::violation`. Two rules name a vertex instead because the
//! defect *is* a vertex: [`grid::check_off_grid`] and [`grid::check_angle`].
//!
//! A rule whose layer fails to validate records [`Outcome::Refused`] for that
//! row and the run continues — never `Ran` with zero violations.
//!
//! [`Outcome::Refused`]: crate::report::Outcome::Refused
//! [`RuleRun`]: crate::report::RuleRun

pub mod area;
pub mod grid;
pub mod overlay;
pub mod patterning;
pub mod spacing;
pub mod via;
pub mod width;

use gpurify_geom::ops::{seg_seg_dist2, Point, Seg};
use gpurify_geom::{Bbox, GeometryStore, PolyId};
use gpurify_geom::{Dbu, DbuArea};

/// The message every rule table's column-length assert carries.
pub(crate) const COLUMNS_DIVERGED: &str = "a rule table's columns hold different row counts";

/// Gives a rule table the `len`/`is_empty` pair the dispatcher branches on.
///
/// List only columns that hold one entry per rule row — [`grid::AngleTable`]'s
/// `allowed` is a CSR payload whose length is a sum over rows, not a row count,
/// so asserting it here would fire on a correctly built table.
macro_rules! row_columns {
    ($($table:ident { $first:ident $(, $rest:ident)* }),+ $(,)?) => {$(
        impl $table {
            pub fn len(&self) -> usize {
                $(debug_assert_eq!(self.$first.len(), self.$rest.len(), "{COLUMNS_DIVERGED}");)*
                self.$first.len()
            }
            pub fn is_empty(&self) -> bool {
                self.len() == 0
            }
        }
    )+};
}
pub(crate) use row_columns;

/// Midpoint of two coordinates.
///
/// `div_euclid` rather than `/`: it floors on both sides of the origin, so the
/// midpoint of an odd span is the same coordinate whether the shape sits at
/// `x = 10` or at `x = -10`.
///
/// Both operands are in-domain, so the sum is inside `+/-2^41` and the halved
/// result is back inside the domain `new_unchecked` asserts.
pub(crate) const fn mid(a: Dbu, b: Dbu) -> Dbu {
    Dbu::new_unchecked((a.raw() + b.raw()).div_euclid(2))
}

/// The middle of the interval two boxes share, or of the gap between them when
/// they share none — the crate's reported coordinate for a pairwise violation.
pub(crate) const fn gap_midpoint(a: Bbox, b: Bbox) -> Point {
    Point {
        x: span_mid(a.xlo, a.xhi, b.xlo, b.xhi),
        y: span_mid(a.ylo, a.yhi, b.ylo, b.yhi),
    }
}

/// [`gap_midpoint`] on one axis: the middle of what two spans share, or of the
/// gap between them when they share none.
const fn span_mid(alo: Dbu, ahi: Dbu, blo: Dbu, bhi: Dbu) -> Dbu {
    debug_assert!(
        alo.raw() <= ahi.raw() && blo.raw() <= bhi.raw(),
        "a span runs low to high"
    );
    // `max` of the low ends and `min` of the high ends cross over exactly when
    // the spans separate, and the midpoint of `[lo, hi]` reversed is the
    // midpoint of the gap. Raw `i64` because `Ord::max` is not `const`.
    let lo = if alo.raw() >= blo.raw() { alo } else { blo };
    let hi = if ahi.raw() <= bhi.raw() { ahi } else { bhi };
    mid(lo, hi)
}

/// The centre of one box — where a rule that measures a shape reports.
pub(crate) const fn centre(b: Bbox) -> Point {
    gap_midpoint(b, b)
}

/// One closed ring's edges, in vertex order, closing edge included.
///
/// The wrap is branchless: `i + 1` on every edge but the last, where the
/// multiply by a false predicate lands it back on vertex zero.
pub(crate) fn ring_segs<'a>(xs: &'a [Dbu], ys: &'a [Dbu]) -> impl Iterator<Item = Seg> + 'a {
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    let n = xs.len();
    (0..n).map(move |i| {
        let j = (i + 1) * usize::from(i + 1 < n);
        Seg {
            a: Point { x: xs[i], y: ys[i] },
            b: Point { x: xs[j], y: ys[j] },
        }
    })
}

/// The box a segment occupies.
///
/// For rectilinear geometry the segment *is* its box, which is why
/// [`bbox_gap2`] is exact there and merely a lower bound in general.
pub(crate) const fn seg_bbox(s: Seg) -> Bbox {
    Bbox::point(s.a.x, s.a.y).include(s.b.x, s.b.y)
}

/// Squared distance between two boxes, zero where they touch or overlap.
///
/// A lower bound on the distance between anything the boxes contain, so it
/// prunes a pairwise measurement without ever changing the answer.
const fn bbox_gap2(a: Bbox, b: Bbox) -> DbuArea {
    let dx = axis_gap(a.xlo, a.xhi, b.xlo, b.xhi);
    let dy = axis_gap(a.ylo, a.yhi, b.ylo, b.yhi);
    // Each gap is at most `2^41`, so each square is at most `2^82` and the sum
    // at most `2^83` — the headroom `MAX_ABS_DBU` exists to buy.
    DbuArea::new(dx * dx + dy * dy)
}

/// [`bbox_gap2`] on one axis: `max(0, max(lo) - min(hi))`, as raw `i128`.
///
/// Raw rather than [`Dbu`] because the difference of two in-domain coordinates
/// reaches `2^41`, one bit past what `Dbu::new_unchecked` asserts to.
const fn axis_gap(alo: Dbu, ahi: Dbu, blo: Dbu, bhi: Dbu) -> i128 {
    let lo = if alo.raw() >= blo.raw() {
        alo.raw()
    } else {
        blo.raw()
    };
    let hi = if ahi.raw() <= bhi.raw() {
        ahi.raw()
    } else {
        bhi.raw()
    };
    let d = lo - hi;
    if d > 0 {
        d as i128
    } else {
        0
    }
}

/// Exact squared distance between two store polygons' *boundaries*.
///
/// Boundary distance, so a shape lying strictly *inside* another reads as its
/// edge separation rather than as zero; every caller has already merged or
/// excluded the nesting case. Zero exactly when the two boundaries touch or
/// cross. Squared because the true distance is irrational in general.
///
/// Quadratic in the two ring sizes. Going sub-quadratic needs an index over one
/// ring's edges and so a caller-owned scratch buffer.
pub(crate) fn poly_dist2(store: &GeometryStore, a: PolyId, b: PolyId) -> DbuArea {
    let (axs, ays) = store.poly_verts(a);
    let (bxs, bys) = store.poly_verts(b);
    debug_assert_eq!(axs.len(), ays.len(), "a ring's columns are parallel");
    debug_assert_eq!(bxs.len(), bys.len(), "a ring's columns are parallel");
    debug_assert!(axs.len() >= 3, "a stored ring has at least three vertices");
    debug_assert!(bxs.len() >= 3, "a stored ring has at least three vertices");

    let box_b = Bbox::of_points(bxs, bys);
    debug_assert!(
        !box_b.is_empty(),
        "a ring with vertices has a non-empty box"
    );

    // The sentinel is always replaced: both rings are non-empty and no real gap
    // comes close to `i128::MAX`. The assert below is what says so.
    let mut best = DbuArea::new(i128::MAX);
    for sa in ring_segs(axs, ays) {
        let box_a = seg_bbox(sa);

        // A true lower bound, so skipping the whole of `b`'s ring here cannot
        // change the answer.
        if bbox_gap2(box_a, box_b) >= best {
            continue;
        }

        for sb in ring_segs(bxs, bys) {
            let bound = bbox_gap2(box_a, seg_bbox(sb));

            if bound >= best {
                continue;
            }

            let exact = seg_seg_dist2(sa, sb);
            debug_assert!(
                bound <= exact,
                "the box gap is a lower bound on the distance between the boxes' contents"
            );
            best = best.min(exact);
        }
    }

    debug_assert!(
        best < DbuArea::new(i128::MAX),
        "every ring has an edge, so the sentinel is always replaced"
    );
    debug_assert!(best.raw() >= 0, "a squared distance is non-negative");
    best
}
