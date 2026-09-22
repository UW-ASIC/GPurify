//! The twenty-four rule kinds, one function per kind, grouped by what they measure.
//!
//! Data in: one rule row's parameters, the store and a `Scratch`.
//! Data out: violations appended to `out`, and the row's [`Verdict`].
//! `Violation::at` is the midpoint of the thing measured (a vertex for off-grid
//! and angle). A layer that fails to validate is `Refused`, never a clean `Ran`.

pub mod area;
pub mod grid;
pub mod overlay;
pub mod patterning;
pub mod spacing;
pub mod via;
pub mod width;

use crate::report::Outcome;
use gpurify_geom::connectivity::{components_into, ComponentLabel};
use gpurify_geom::ops::{seg_seg_dist2, Point, Seg};
use gpurify_geom::{Bbox, GeometryStore, PolyId};
use gpurify_geom::{Dbu, DbuArea};

/// How one rule row ended, and how many of its primitives it examined.
pub(crate) type Verdict = (Outcome, u64);

pub(crate) const REFUSED: Verdict = (Outcome::Refused, 0);

/// Midpoint of two coordinates, floored (`div_euclid`) on both sides of the origin.
pub(crate) const fn mid(a: Dbu, b: Dbu) -> Dbu {
    Dbu::new_unchecked((a.raw() + b.raw()).div_euclid(2))
}

/// The middle of the interval two boxes share, or of the gap between them when
/// they share none — the report point for a pairwise violation.
pub(crate) const fn gap_midpoint(a: Bbox, b: Bbox) -> Point {
    Point {
        x: span_mid(a.xlo, a.xhi, b.xlo, b.xhi),
        y: span_mid(a.ylo, a.yhi, b.ylo, b.yhi),
    }
}

const fn span_mid(alo: Dbu, ahi: Dbu, blo: Dbu, bhi: Dbu) -> Dbu {
    let lo = if alo.raw() >= blo.raw() { alo } else { blo };
    let hi = if ahi.raw() <= bhi.raw() { ahi } else { bhi };
    mid(lo, hi)
}

pub(crate) const fn centre(b: Bbox) -> Point {
    gap_midpoint(b, b)
}

/// One closed ring's edges, in vertex order, closing edge last.
pub(crate) fn ring_segs<'a>(xs: &'a [Dbu], ys: &'a [Dbu]) -> impl Iterator<Item = Seg> + 'a {
    let n = xs.len();
    (0..n).map(move |i| {
        let j = if i + 1 < n { i + 1 } else { 0 };
        Seg {
            a: Point { x: xs[i], y: ys[i] },
            b: Point { x: xs[j], y: ys[j] },
        }
    })
}

pub(crate) const fn seg_bbox(s: Seg) -> Bbox {
    Bbox::point(s.a.x, s.a.y).include(s.b.x, s.b.y)
}

/// Squared distance between two boxes, zero where they touch or overlap; a
/// lower bound on the distance between anything they contain.
const fn bbox_gap2(a: Bbox, b: Bbox) -> DbuArea {
    let dx = axis_gap(a.xlo, a.xhi, b.xlo, b.xhi);
    let dy = axis_gap(a.ylo, a.yhi, b.ylo, b.yhi);
    DbuArea::new(dx * dx + dy * dy)
}

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

/// Exact squared distance between two store polygons' *boundaries*; zero exactly
/// when they touch or cross. Quadratic in the two ring sizes.
pub(crate) fn poly_dist2(store: &GeometryStore, a: PolyId, b: PolyId) -> DbuArea {
    let (axs, ays) = store.poly_verts(a);
    let (bxs, bys) = store.poly_verts(b);
    let box_b = Bbox::of_points(bxs, bys);

    let mut best = DbuArea::new(i128::MAX);
    for sa in ring_segs(axs, ays) {
        let box_a = seg_bbox(sa);
        if bbox_gap2(box_a, box_b) >= best {
            continue;
        }
        for sb in ring_segs(bxs, bys) {
            if bbox_gap2(box_a, seg_bbox(sb)) < best {
                best = best.min(seg_seg_dist2(sa, sb));
            }
        }
    }
    best
}

/// Exact squared distance for every pair, into `dists`.
pub(crate) fn pair_distances_into(
    store: &GeometryStore,
    pairs: &[(PolyId, PolyId)],
    dists: &mut Vec<DbuArea>,
) {
    dists.clear();
    dists.extend(pairs.iter().map(|&(a, b)| poly_dist2(store, a, b)));
}

/// Label the rows `first_row ..` of one layer by the components of the pairs
/// whose distance `join` accepts. A label is its component's minimum row offset.
pub(crate) fn label_pairs_into(
    first_row: u32,
    node_count: u32,
    pairs: &[(PolyId, PolyId)],
    dists: &[DbuArea],
    join: impl Fn(DbuArea) -> bool,
    edges: &mut Vec<(u32, u32)>,
    labels: &mut Vec<ComponentLabel>,
) {
    edges.clear();
    edges.extend(
        pairs
            .iter()
            .zip(dists)
            .filter(|&(_, &d2)| join(d2))
            .map(|(&(a, b), _)| (a.0 - first_row, b.0 - first_row)),
    );
    components_into(node_count, edges, labels);
}
