//! The twenty-four rule kinds, grouped by what they measure.
//!
//! One file per family, because a family shares its geometry primitive: the
//! width rules all scan inside one polygon, the spacing rules all start from a
//! candidate-pair prune, the overlay rules all relate an inner shape to an
//! outer one. Grouping by primitive is what lets the four width rules be four
//! reductions over one scan instead of four scans.
//!
//! # Every table has the same shape
//!
//! **Five questions**, answered once for all twenty-four. In: [`RuleSpec`] rows
//! from the deck, already layer-resolved and grid-converted by `ingest`. Out:
//! one `SoA` table of exactly the parameters that kind takes, nothing widened
//! to a common shape. How many: tens of rows per table, hundreds per deck —
//! *cold*, read once each at the top of a transform and hoisted as uniforms
//! over a loop with millions of iterations. Access pattern: a single forward
//! scan, all columns of a row read together at the top of that row's work.
//! Lifetime: the whole run, built once from the deck and never mutated.
//! Parallelisable: rows of one table are independent of each other; see the
//! ponytail note on [`Scratch`](crate::Scratch) for why they are not run that
//! way yet.
//!
//! Rows are `SoA` rather than `AoS` for one reason that is not performance:
//! [`RuleSet::rule_count`](crate::RuleSet::rule_count) and the dispatcher want
//! to ask "is this table empty" without knowing the row type, and the columns
//! keep the limit types honest — a `Vec<Dbu>` beside a `Vec<DbuArea>` cannot be
//! transposed by accident the way two `i64` struct fields can.
//!
//! # Every transform has the same shape
//!
//! ```ignore
//! pub fn check_<kind>(
//!     design: Design<'_>,
//!     table: &<Kind>Table,
//!     scratch: &mut Scratch,
//!     out: &mut Violations,
//!     runs: &mut Vec<RuleRun>,
//! )
//! ```
//!
//! - **`out` and `runs` are appended to, not cleared.** They are the gatherer's
//!   containers, shared by all twenty-four transforms;
//!   [`RuleSet::run`](crate::RuleSet::run) clears them once at the top of a run.
//!   Every *scratch* buffer is cleared and refilled, which is the `_into`
//!   discipline the conventions ask for — the outputs are the one place it
//!   would be wrong.
//! - **One [`RuleRun`] per table row, always**, pushed through
//!   `record_run`. Not per violation, not per layer, and
//!   never omitted because nothing was found.
//! - **`examined` counts the primitive the rule actually looked at**, named in
//!   each transform's doc: polygons for the shape rules, candidate pairs for
//!   the spacing rules, vertices for [`grid::check_off_grid`], windows for
//!   [`area::check_density`]. It is a claim a test can check, so it has to mean
//!   something specific.
//! - **Nothing allocates per row.** Every buffer a row needs lives in
//!   [`Scratch`](crate::Scratch) and is cleared, not reallocated.
//!
//! # Where a violation is reported
//!
//! **`Violation::at` is the midpoint of the thing being measured**: the middle
//! of a gap, the centre of an area, the midpoint of an edge, the middle of an
//! overlap. Every rule below either restates that in its own terms or inherits
//! it, and a rule reporting a different point is wrong rather than merely
//! surprising. The same sentence is written down on
//! `gpurify_testgen::violation`, which is where the suite's expected coordinates
//! come from; the two documents say one thing on purpose.
//!
//! Two rules name a vertex instead, because the defect *is* a vertex and a
//! midpoint would point at nothing: [`grid::check_off_grid`] reports the
//! offending vertex, and [`grid::check_angle`] reports the vertex the offending
//! edge leaves from.
//!
//! # Refusal is a result
//!
//! Validation of a layer can fail — [`ValidityError::NotRectilinear`] is the
//! common one, since this tool represents rectilinear geometry exactly and
//! refuses to approximate anything else. A rule whose layer fails to validate
//! records [`Outcome::Refused`] for that row and the run continues to the next
//! rule. It never records `Ran` with zero violations, and it never aborts the
//! whole run: one bad polygon on one layer must not suppress the verdict of
//! every other rule in the deck.
//!
//! [`RuleSpec`]: gpurify_ingest::deck::RuleSpec
//! [`ValidityError::NotRectilinear`]: gpurify_core::view::ValidityError::NotRectilinear
//! [`Outcome::Refused`]: gpurify_report::Outcome::Refused
//! [`RuleRun`]: gpurify_report::RuleRun

pub mod area;
pub mod grid;
pub mod overlay;
pub mod patterning;
pub mod spacing;
pub mod via;
pub mod width;

use gpurify_core::ops::{Point, Seg, seg_seg_dist2};
use gpurify_core::{Bbox, GeometryStore, PolyId};
use gpurify_units::{Dbu, DbuArea};

/// The message every rule table's column-length assert carries.
///
/// One row per rule across parallel columns is the shape stated at the top of
/// this module, so a length disagreement is a table built wrong rather than an
/// input that is merely unusual. Every family asserted it in its own words
/// until the wording was folded here; the panic location already names which
/// table it was.
pub(crate) const COLUMNS_DIVERGED: &str = "a rule table's columns hold different row counts";

/// Gives a rule table the `len`/`is_empty` pair the dispatcher branches on.
///
/// `len` is the first column's length; every other column listed must agree,
/// checked in debug builds against [`COLUMNS_DIVERGED`]. List only columns that
/// hold one entry per rule row — [`grid::AngleTable`]'s `allowed` is a CSR
/// payload whose length is a sum over rows, not a row count, so asserting it
/// here would fire on a correctly built table.
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
/// `x = 10` or at `x = -10`. Truncation toward zero is not, and a coordinate
/// that depends on which side of the origin a cell was placed is a determinism
/// bug waiting for a hierarchical run.
///
/// Both operands are in-domain, so the sum is inside `+/-2^41` and the halved
/// result is back inside the domain `new_unchecked` asserts.
pub(crate) const fn mid(a: Dbu, b: Dbu) -> Dbu {
    Dbu::new_unchecked((a.raw() + b.raw()).div_euclid(2))
}

/// The middle of the interval two boxes share, or of the gap between them when
/// they share none — the crate's reported coordinate for a pairwise violation.
///
/// **Decision** — two boxes in, one point out, pure and table-testable. Per axis
/// the answer is `mid(max(lo), min(hi))`, and that one expression is both cases:
/// where the projections are disjoint `max(lo)` and `min(hi)` are the two facing
/// edges and the midpoint is the middle of the gap; where they overlap they are
/// the shared span's ends and the midpoint is the middle of that. No branch, and
/// no way for the two cases to drift apart.
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
    // midpoint of the gap. Written on the raw `i64` because `Ord::max` is not
    // `const`.
    let lo = if alo.raw() >= blo.raw() { alo } else { blo };
    let hi = if ahi.raw() <= bhi.raw() { ahi } else { bhi };
    mid(lo, hi)
}

/// The centre of one box — its gap with itself, which is the whole box.
///
/// Where a rule that measures a *shape* rather than a gap reports: the centre of
/// an area, of a cut, of a window, of a gate marker.
pub(crate) const fn centre(b: Bbox) -> Point {
    gap_midpoint(b, b)
}

/// One closed ring's edges, in vertex order, closing edge included.
///
/// The wrap is branchless: `i + 1` on every edge but the last, where the
/// multiply by a false predicate lands it back on vertex zero. A `%` by a
/// runtime length would be a division in the innermost loop of every measured
/// pair.
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

/// The box a segment occupies. For rectilinear geometry — everything this tree
/// admits — the segment *is* its box, which is why [`bbox_gap2`] below is an
/// exact distance there and merely a lower bound in general.
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
/// reaches `2^41`, one bit past what `Dbu::new_unchecked` asserts to. The three
/// `if`s are the source form of `min`/`max`/`clamp`, not data-dependent
/// branches — same argument as `gpurify_core::bbox`'s own const `min`.
const fn axis_gap(alo: Dbu, ahi: Dbu, blo: Dbu, bhi: Dbu) -> i128 {
    let lo = if alo.raw() >= blo.raw() { alo.raw() } else { blo.raw() };
    let hi = if ahi.raw() <= bhi.raw() { ahi.raw() } else { bhi.raw() };
    let d = lo - hi;
    if d > 0 { d as i128 } else { 0 }
}

/// Exact squared distance between two store polygons' *boundaries*.
///
/// **Decision** — two rows in, one squared length out, pure. Zero exactly when
/// the two boundaries touch or cross, which is the equivalence the merged-figure
/// labelling keys on. Squared because the true distance is irrational in general
/// and every caller compares against a squared limit.
///
/// Boundary distance, so a shape lying strictly *inside* another reads as its
/// edge separation rather than as zero. Every caller here — spacing pairs,
/// multi-patterning conflicts, via neighbourhoods — has already merged or
/// excluded the nesting case.
///
/// # How the cross product is priced
///
/// A double loop over the *cross product* of two rings. A ring is tens of edges,
/// not bulk data — the bulk dimension is the candidate-pair list this is called
/// from, one level up.
///
/// The double loop does not *measure* every pair. Each edge pair is first
/// bounded by [`bbox_gap2`], which is six compares and two multiplies, and only
/// pairs that could beat the running best reach [`seg_seg_dist2`] — an
/// intersection test plus four `i128` point drops. On rectilinear input the
/// bound is exact, so a pair reaches the expensive call only when it strictly
/// improves the answer: `n * m` cheap bounds and `O(n + m)` measurements in
/// practice rather than `n * m` of them. The outer loop bounds each edge of `a`
/// against the whole of `b` first, so a far edge skips the inner scan entirely.
///
/// Ceiling that remains: still quadratic in the bounds, since pruning does not
/// change the number of pairs enumerated. Going sub-quadratic needs an index
/// over one ring's edges, which needs a caller-owned scratch buffer, which is a
/// signature this phase may not widen — recorded under `## drc/rules/mod.rs` in
/// `docs/SIGNATURE_DEFECTS.md`.
pub(crate) fn poly_dist2(store: &GeometryStore, a: PolyId, b: PolyId) -> DbuArea {
    let (axs, ays) = store.poly_verts(a);
    let (bxs, bys) = store.poly_verts(b);
    debug_assert_eq!(axs.len(), ays.len(), "a ring's columns are parallel");
    debug_assert_eq!(bxs.len(), bys.len(), "a ring's columns are parallel");
    debug_assert!(axs.len() >= 3, "a stored ring has at least three vertices");
    debug_assert!(bxs.len() >= 3, "a stored ring has at least three vertices");

    let box_b = Bbox::of_points(bxs, bys);
    debug_assert!(!box_b.is_empty(), "a ring with vertices has a non-empty box");

    // `min` carries no branch, and the sentinel is not a saturating distance
    // that could reach a comparison: both rings are non-empty and no gap comes
    // close to `i128::MAX`, so the first pair always measures and replaces it.
    // The assert below is what says so.
    let mut best = DbuArea::new(i128::MAX);
    for sa in ring_segs(axs, ays) {
        let box_a = seg_bbox(sa);

        // Escape valve: the taken side is a whole scan of `b`'s ring. Skipping
        // it is exactly what a branch is for, and the bound is a true lower
        // bound so the skip cannot change the answer.
        if bbox_gap2(box_a, box_b) >= best {
            continue;
        }

        for sb in ring_segs(bxs, bys) {
            let bound = bbox_gap2(box_a, seg_bbox(sb));

            // Escape valve: the taken side is expensive — `seg_seg_dist2` is an
            // orientation-based intersection test plus four `i128` drops, next
            // to six compares here.
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
