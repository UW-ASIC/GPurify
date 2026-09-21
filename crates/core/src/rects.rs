//! Rectilinear decomposition: polygons to disjoint rectangles, so areas sum
//! without an inclusion–exclusion correction.

use crate::ids::PolyId;
use crate::view::{RingRef, ValidatedLayer};
use gpurify_units::{Dbu, DbuArea};

/// One edge, as the x-range it spans and the y it sits at.
///
/// `y` is meaningless for a vertical edge: `lo == hi` makes the slab predicate
/// `lo <= x0 && hi >= x1` (with `x0 < x1`) unsatisfiable, so it is never read.
/// That is what lets the table hold *every* edge rather than only the crossing
/// ones.
type Span = (Dbu, Dbu, Dbu);

/// Normalise one edge into a [`Span`]. Branchless: `min`/`max` on `i64`.
fn span((x0, x1, y): Span) -> Span {
    (x0.min(x1), x0.max(x1), y)
}

/// Append one ring's edges to `edges` and its vertex x-coordinates to `slabs`.
fn collect_ring(ring: RingRef<'_>, edges: &mut Vec<Span>, slabs: &mut Vec<Dbu>) {
    let (xs, ys) = ring.coords();
    let n = xs.len();
    debug_assert_eq!(n, ys.len(), "a ring's coordinate columns are parallel");
    debug_assert!(n >= 3, "a validated ring has at least three vertices");

    slabs.extend_from_slice(xs);
    let before = edges.len();
    edges.reserve(n);

    // Adjacent-pair scan over offset views, plus the ring's wrap edge as a
    // scalar fixup.
    edges.extend(
        xs[..n - 1]
            .iter()
            .zip(&xs[1..])
            .zip(&ys[..n - 1])
            .map(|((&x0, &x1), &y)| span((x0, x1, y))),
    );
    edges.push(span((xs[n - 1], xs[0], ys[n - 1])));

    debug_assert_eq!(edges.len() - before, n, "one edge per vertex");
}

/// One axis-aligned rectangle of a decomposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub xlo: Dbu,
    pub ylo: Dbu,
    pub xhi: Dbu,
    pub yhi: Dbu,
}

impl Rect {
    /// Area of the rectangle.
    pub const fn area(self) -> DbuArea {
        debug_assert!(self.xlo.raw() <= self.xhi.raw() && self.ylo.raw() <= self.yhi.raw());
        debug_assert!(
            Dbu::new(self.xlo.raw()).is_some()
                && Dbu::new(self.ylo.raw()).is_some()
                && Dbu::new(self.xhi.raw()).is_some()
                && Dbu::new(self.yhi.raw()).is_some()
        );
        // Widths, not coordinates: `xhi - xlo` reaches `2 * MAX_ABS_DBU`, which
        // is outside the `Dbu` domain, so this cannot route through
        // `Dbu::mul_wide` — its precondition is on the *operands*.
        let w = (self.xhi.raw() - self.xlo.raw()) as i128;
        let h = (self.yhi.raw() - self.ylo.raw()) as i128;
        DbuArea::new(w * h)
    }
}

/// Decompose every polygon on a validated layer into disjoint rectangles.
///
/// `rects` holds every polygon's rectangles concatenated; `poly_start` is a CSR
/// offset array of length `layer.len() + 1`, so polygon `i`'s rectangles are
/// `rects[poly_start[i] .. poly_start[i + 1]]`.
///
/// Vertical-slab decomposition: canonical, so the same polygon always
/// decomposes the same way, which the determinism gate needs.
pub fn decompose_into(
    layer: &ValidatedLayer,
    store: &crate::store::GeometryStore,
    rects: &mut Vec<Rect>,
    poly_start: &mut Vec<u32>,
) {
    rects.clear();
    poly_start.clear();
    poly_start.push(0);

    // Per-polygon scratch, hoisted above the loop and cleared per use.
    let mut edges: Vec<Span> = Vec::new();
    let mut slabs: Vec<Dbu> = Vec::new();
    let mut active: Vec<Span> = Vec::new();
    let mut retained: Vec<Span> = Vec::new();
    let mut cuts: Vec<Dbu> = Vec::new();

    for idx in 0..layer.len() {
        let row = u32::try_from(idx).expect("a layer's polygon count fits a u32");
        let poly = layer.get(store, row);

        edges.clear();
        slabs.clear();
        collect_ring(poly.outer(), &mut edges, &mut slabs);
        for hole in poly.holes() {
            collect_ring(hole, &mut edges, &mut slabs);
        }

        slabs.sort_unstable();
        slabs.dedup();
        // Sorted by span start, so one forward cursor feeds the sweep's active
        // list. `Span` is a tuple of `Dbu`, so the order is total and the
        // unstable sort is still deterministic.
        edges.sort_unstable();
        debug_assert!(
            slabs.len() >= 2,
            "a validated polygon spans at least one slab"
        );
        debug_assert!(
            edges.len() >= 3,
            "a validated polygon has at least three edges"
        );

        // Both slab bounds ascend with `cut`, so each half of the crossing
        // predicate is monotone in it: an edge enters the active list once and
        // leaves once. That is what makes the cursor below a single pass.
        active.clear();
        let mut started = 0usize;

        for cut in 0..slabs.len() - 1 {
            let (x0, x1) = (slabs[cut], slabs[cut + 1]);
            debug_assert!(x0 < x1, "the slab list is sorted and deduplicated");

            // Admit every edge that has started by `x0`.
            while started < edges.len() && edges[started].0 <= x0 {
                active.push(edges[started]);
                started += 1;
            }

            // Retire every edge that ends before this slab. What survives is
            // exactly `lo <= x0 && hi >= x1`: the cursor above supplies the
            // first half, and an edge dropped at an earlier slab had
            // `hi < x1_prev <= x1`.
            //
            // Branchless compact: the store is unconditional and the write
            // cursor carries the predicate, which is why the reserve is for the
            // whole input rather than the survivors.
            let n = active.len();
            retained.clear();
            retained.reserve(n);
            debug_assert!(
                retained.capacity() >= n,
                "the compact reserves for the input, not the survivors"
            );
            let out = &mut retained.spare_capacity_mut()[..n];

            let mut w = 0usize;
            for (i, &e) in active.iter().enumerate() {
                let p = e.1 >= x1;
                // `w <= i` by induction: `w == 0 == i` on entry, and `bool` is
                // 0 or 1 so `w` advances by at most one per iteration while `i`
                // advances by exactly one. Rejected slots stay uninit and are
                // never read — `set_len(w)` truncates them away, and `Span` is
                // three `Dbu`, so there is no `Drop` to run.
                debug_assert!(w <= i);
                // SAFETY: `w <= i < n == out.len()`, from the induction above.
                // Unchecked because `w`'s step is data-dependent: LLVM gets no
                // affine recurrence for it, cannot prove `w <= i`, and would
                // leave a live `cmp/jae` to a panic edge in the loop, which is
                // both a data-dependent branch and a serialising one. Measured
                // 1.19x at 8k / 1.18x at 200k / 1.06x at 4M — the one place in
                // this shape where the `unsafe` pays.
                unsafe { out.get_unchecked_mut(w) }.write(e);
                w += usize::from(p);
            }

            // SAFETY: slots `0..w` were each written when `w` held that value,
            // and `w <= n <= capacity`.
            unsafe { retained.set_len(w) };
            debug_assert!(retained.len() <= n, "a compact cannot grow its input");

            core::mem::swap(&mut active, &mut retained);
            debug_assert!(
                active.iter().all(|&(lo, hi, _)| (lo <= x0) & (hi >= x1)),
                "the active list holds only edges crossing this slab side to side"
            );
            debug_assert_eq!(
                active.len(),
                edges
                    .iter()
                    .filter(|&&(lo, hi, _)| (lo <= x0) & (hi >= x1))
                    .count(),
                "the sweep must find every crossing the full rescan would"
            );

            cuts.clear();
            cuts.reserve(active.len());
            cuts.extend(active.iter().map(|&(_, _, y)| y));
            cuts.sort_unstable();

            // Even-odd fill: the slab's interior is between the first and
            // second crossing, the third and fourth, and so on. A validated
            // ring set never crosses itself, so the crossings are distinct and
            // the count is even — both of which the pairing relies on.
            debug_assert!(
                cuts.len().is_multiple_of(2),
                "a closed boundary crosses a slab an even number of times"
            );
            debug_assert!(
                cuts.windows(2).all(|pair| pair[0] < pair[1]),
                "two boundary crossings of one slab coincide"
            );

            rects.extend(cuts.chunks_exact(2).map(|pair| Rect {
                xlo: x0,
                ylo: pair[0],
                xhi: x1,
                yhi: pair[1],
            }));
        }

        poly_start.push(u32::try_from(rects.len()).expect("a decomposition fits a u32"));
    }

    debug_assert_eq!(
        poly_start.len(),
        layer.len() + 1,
        "CSR offsets are one longer"
    );
    debug_assert_eq!(poly_start[0], 0);
    debug_assert_eq!(
        poly_start[poly_start.len() - 1] as usize,
        rects.len(),
        "the trailing offset is the rectangle count"
    );
}

/// Total area covered by a polygon's rectangles; exact, because they are
/// disjoint.
pub fn covered_area(rects: &[Rect]) -> DbuArea {
    let mut total = DbuArea::new(0);
    for r in rects {
        total = total + r.area();
    }
    total
}

/// Area of a polygon's rectangles clipped to a window.
pub fn clipped_area(rects: &[Rect], window: crate::bbox::Bbox) -> DbuArea {
    debug_assert!(
        Dbu::new(window.xlo.raw()).is_some()
            && Dbu::new(window.ylo.raw()).is_some()
            && Dbu::new(window.xhi.raw()).is_some()
            && Dbu::new(window.yhi.raw()).is_some(),
        "the window is outside the coordinate domain the i128 product is bounded by"
    );
    let (wxlo, wylo) = (window.xlo.raw(), window.ylo.raw());
    let (wxhi, wyhi) = (window.xhi.raw(), window.yhi.raw());

    // The clip is `max(0, min(hi) - max(lo))` per axis, so a rectangle outside
    // the window contributes a zero factor and `Bbox::EMPTY` lands on zero by
    // the same arithmetic.
    let mut total = DbuArea::new(0);
    for r in rects {
        let w = i128::from((r.xhi.raw().min(wxhi) - r.xlo.raw().max(wxlo)).max(0));
        let h = i128::from((r.yhi.raw().min(wyhi) - r.ylo.raw().max(wylo)).max(0));
        total = total + DbuArea::new(w * h);
    }

    debug_assert!(
        total >= DbuArea::new(0),
        "a clipped area cannot be negative"
    );
    total
}

/// Which polygon a rectangle came from, derived from the CSR offsets.
pub fn owner_of(poly_start: &[u32], rect_index: u32) -> PolyId {
    debug_assert!(
        poly_start.len() >= 2,
        "CSR offsets describe at least one polygon"
    );
    debug_assert_eq!(poly_start[0], 0, "CSR offsets start at zero");
    debug_assert!(
        rect_index < poly_start[poly_start.len() - 1],
        "no polygon owns a rectangle past the end of the decomposition"
    );

    // The last offset still at or below the index: taking the *last* of a run
    // of equal offsets skips polygons that decomposed into nothing and names
    // the one that actually owns the row. `poly_start[0] == 0 <= rect_index`
    // makes the result at least one, so the `- 1` cannot underflow.
    let slot = poly_start.partition_point(|&start| start <= rect_index) - 1;

    debug_assert!(
        slot + 1 < poly_start.len(),
        "the owner is a polygon, not the trailing offset"
    );
    debug_assert!(
        poly_start[slot] <= rect_index && rect_index < poly_start[slot + 1],
        "the owner's CSR range must bracket the index"
    );
    PolyId(u32::try_from(slot).expect("a polygon count fits a u32"))
}
