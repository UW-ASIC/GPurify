//! Rectilinear decomposition into disjoint rectangles, so areas sum exactly.
//!
//! Data in: a [`ValidatedLayer`].
//! Data out: `Vec<Rect>` plus CSR `poly_start`, canonical vertical slabs.

use crate::view::{RingRef, ValidatedLayer};
use crate::{Dbu, DbuArea};

/// One edge as `(xlo, xhi, y)`. A vertical edge has `xlo == xhi`, so it never
/// satisfies the slab predicate and its `y` is never read.
type Span = (Dbu, Dbu, Dbu);

/// Append one ring's edges to `edges` and its vertex x-coordinates to `slabs`.
fn collect_ring(ring: RingRef<'_>, edges: &mut Vec<Span>, slabs: &mut Vec<Dbu>) {
    let (xs, ys) = ring.coords();
    let n = xs.len();
    slabs.extend_from_slice(xs);
    edges.extend(
        xs[..n - 1]
            .iter()
            .zip(&xs[1..])
            .zip(&ys[..n - 1])
            .map(|((&x0, &x1), &y)| (x0.min(x1), x0.max(x1), y)),
    );
    let (x0, x1) = (xs[n - 1], xs[0]);
    edges.push((x0.min(x1), x0.max(x1), ys[n - 1]));
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
    /// Widths reach `2^41`, so this multiplies spans in `i128`, not via `mul_wide`.
    pub const fn area(self) -> DbuArea {
        let w = (self.xhi.raw() - self.xlo.raw()) as i128;
        let h = (self.yhi.raw() - self.ylo.raw()) as i128;
        DbuArea::new(w * h)
    }
}

/// Decompose every polygon on a validated layer into disjoint rectangles by
/// vertical slabs (canonical). Polygon `i` owns `rects[poly_start[i] ..
/// poly_start[i + 1]]`; each slab's rectangles ascend in y.
pub fn decompose_into(
    layer: &ValidatedLayer,
    store: &crate::store::GeometryStore,
    rects: &mut Vec<Rect>,
    poly_start: &mut Vec<u32>,
) {
    rects.clear();
    poly_start.clear();
    poly_start.push(0);

    let mut edges: Vec<Span> = Vec::new();
    let mut slabs: Vec<Dbu> = Vec::new();
    let mut active: Vec<Span> = Vec::new();
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
        edges.sort_unstable();

        // Both slab bounds ascend, so an edge enters `active` once and leaves once.
        active.clear();
        let mut started = 0usize;

        for cut in 0..slabs.len() - 1 {
            let (x0, x1) = (slabs[cut], slabs[cut + 1]);

            while started < edges.len() && edges[started].0 <= x0 {
                active.push(edges[started]);
                started += 1;
            }
            // Survivors are exactly the edges with `lo <= x0 && hi >= x1`.
            active.retain(|e| e.1 >= x1);

            cuts.clear();
            cuts.extend(active.iter().map(|&(_, _, y)| y));
            cuts.sort_unstable();

            // Even-odd fill: interior between crossings 1-2, 3-4, ...
            rects.extend(cuts.chunks_exact(2).map(|pair| Rect {
                xlo: x0,
                ylo: pair[0],
                xhi: x1,
                yhi: pair[1],
            }));
        }

        poly_start.push(u32::try_from(rects.len()).expect("a decomposition fits a u32"));
    }
}

/// Total area of disjoint rectangles.
pub fn covered_area(rects: &[Rect]) -> DbuArea {
    let mut total = DbuArea::new(0);
    for r in rects {
        total = total + r.area();
    }
    total
}

/// Area of rectangles clipped to a window, per axis `max(0, min(hi) - max(lo))`.
pub fn clipped_area(rects: &[Rect], window: crate::bbox::Bbox) -> DbuArea {
    let (wxlo, wylo) = (window.xlo.raw(), window.ylo.raw());
    let (wxhi, wyhi) = (window.xhi.raw(), window.yhi.raw());
    let mut total = DbuArea::new(0);
    for r in rects {
        let w = i128::from((r.xhi.raw().min(wxhi) - r.xlo.raw().max(wxlo)).max(0));
        let h = i128::from((r.yhi.raw().min(wyhi) - r.ylo.raw().max(wylo)).max(0));
        total = total + DbuArea::new(w * h);
    }
    total
}
