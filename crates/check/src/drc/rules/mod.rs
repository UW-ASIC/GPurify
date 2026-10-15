//! The rule kinds, one function per kind, grouped by what they measure.
//!
//! Data in: one rule row's parameters, the store and a `Scratch`.
//! Data out: violations appended to `out`, and the row's `Verdict`. Where each
//! kind places [`Violation::at`](crate::report::Violation::at), and what it
//! counts as examined, is documented on its [`Rule`](crate::drc::Rule)
//! variant. Input a kind cannot represent exactly (a layer that fails to
//! validate, a failed boolean, a non-axis-aligned edge) is `Refused`, never a
//! clean `Ran`. The via and grid kinds read raw rows and never refuse.

pub mod area;
pub mod edge;
pub mod facing;
pub mod grid;
pub mod overlay;
pub mod pattern;
pub mod patterning;
pub mod presence;
pub mod spacing;
pub mod via;
pub mod width;

use crate::report::Outcome;
use crate::topology::net::{in_material, Holes};
use fearless_simd::{dispatch, f64x4, Level, Simd, SimdBase};
use gpurify_geom::boolean::union_into;
use gpurify_geom::connectivity::{components_into, ComponentLabel};
use gpurify_geom::derive::{contains_scaled, interior_point8};
use gpurify_geom::ops::{seg_seg_dist2, seg_seg_near2, seg_seg_twice2, Point, Seg};
use gpurify_geom::rects::decompose_into;
use gpurify_geom::{Bbox, GeometryStore, LayerId, PolyId, PolygonRef, ValidatedLayer};
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

/// A validated layer cut into disjoint rectangles, CSR by polygon, so region
/// questions (containment, overlap area) are exact sums.
#[derive(Debug, Default)]
pub(crate) struct LayerRects {
    rects: Vec<Bbox>,
    start: Vec<u32>,
    /// Store row offset on the layer to the polygon holding it, holes included.
    pub(crate) poly_of_row: Vec<u32>,
    /// Each polygon's outer store row.
    pub(crate) row: Vec<PolyId>,
}

impl LayerRects {
    /// Refill from one layer validated straight from the store.
    pub(crate) fn build(&mut self, store: &GeometryStore, layer: LayerId, drawn: &ValidatedLayer) {
        decompose_into(drawn, &mut self.rects, &mut self.start);
        let first = store.polys_on_layer(layer).start;
        self.poly_of_row.clear();
        self.poly_of_row
            .resize(store.polys_on_layer(layer).len(), u32::MAX);
        self.row.clear();
        for poly in 0..u32::try_from(drawn.len()).expect("a layer indexes polygons with a u32") {
            let rows = drawn.get(poly).rows();
            for row in rows {
                self.poly_of_row[(row.0 - first) as usize] = poly;
            }
            self.row.push(drawn.get(poly).provenance());
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.row.len()
    }

    /// Every rectangle labelled with its polygon's outer row.
    pub(crate) fn labelled(&self) -> Vec<(Bbox, PolyId)> {
        (0..self.len())
            .flat_map(|poly| {
                let row = self.row[poly];
                self.of(u32::try_from(poly).expect("a layer indexes polygons with a u32"))
                    .iter()
                    .map(move |&r| (r, row))
            })
            .collect()
    }

    /// Polygon `poly`'s rectangles.
    pub(crate) fn of(&self, poly: u32) -> &[Bbox] {
        let i = poly as usize;
        &self.rects[self.start[i] as usize..self.start[i + 1] as usize]
    }
}

/// Labelled rectangles sorted by `xlo`, for "which of these overlap that" with
/// positive area.
pub(crate) struct SortedRects<T> {
    by_xlo: Vec<(Bbox, T)>,
    /// The widest rectangle: how far left of a query a hit can start.
    reach: i64,
}

impl<T: Copy> SortedRects<T> {
    pub(crate) fn new(mut by_xlo: Vec<(Bbox, T)>) -> Self {
        by_xlo.sort_unstable_by_key(|&(r, _)| r.xlo);
        let reach = by_xlo
            .iter()
            .map(|(r, _)| (r.xhi - r.xlo).raw())
            .max()
            .unwrap_or(0);
        Self { by_xlo, reach }
    }

    /// Each rectangle overlapping `q` with positive area, clipped to `q`.
    pub(crate) fn overlapping(&self, q: Bbox) -> impl Iterator<Item = (Bbox, T)> + '_ {
        let lo = self
            .by_xlo
            .partition_point(|(r, _)| r.xlo.raw() < q.xlo.raw() - self.reach);
        let hi = self.by_xlo.partition_point(|(r, _)| r.xlo < q.xhi);
        self.by_xlo[lo..hi.max(lo)]
            .iter()
            .filter_map(move |&(r, label)| {
                let c = r.intersection(q)?;
                (c.xlo < c.xhi && c.ylo < c.yhi).then_some((c, label))
            })
    }
}

/// The lowest drawn row under each figure of `figures`, a boolean result whose
/// own `provenance` is a row of the boolean's scratch store, not of the
/// layout; `PolyId(u32::MAX)` for a figure over nothing drawn.
pub(crate) fn owners_of(figures: &ValidatedLayer, drawn: &LayerRects) -> Vec<PolyId> {
    let under = SortedRects::new(drawn.labelled());
    let (mut rects, mut start) = (Vec::new(), Vec::new());
    decompose_into(figures, &mut rects, &mut start);
    start
        .windows(2)
        .map(|span| {
            rects[span[0] as usize..span[1] as usize]
                .iter()
                .flat_map(|&r| under.overlapping(r))
                .map(|(_, row)| row)
                .min()
                .unwrap_or(PolyId(u32::MAX))
        })
        .collect()
}

/// The lowest drawn row inside each figure of `figures`, the merge of
/// `drawn`, where either may hold edges at 45 degrees: each drawn polygon
/// lies in exactly one figure, found by a point inside it. `PolyId(u32::MAX)`
/// for a figure no drawn polygon lies in. The octilinear twin of
/// [`owners_of`], which cuts into rectangles.
pub(crate) fn owners_by_point(figures: &ValidatedLayer, drawn: &ValidatedLayer) -> Vec<PolyId> {
    let mut owner = vec![PolyId(u32::MAX); figures.len()];
    for (poly, home) in figures_holding(figures, drawn).into_iter().enumerate() {
        if let Some(figure) = home {
            let slot = &mut owner[figure as usize];
            *slot = (*slot).min(
                drawn
                    .get(u32::try_from(poly).expect("a u32 index"))
                    .provenance(),
            );
        }
    }
    owner
}

/// Per polygon of `drawn`: the figure of `figures` holding a point just
/// inside it, near its lowest convex corner, or `None`. Where `figures` is
/// the merge of a layer `drawn` lies in, that is the figure it lies in; for
/// any other `drawn` it is the figure a covered polygon lies in.
pub(crate) fn figures_holding(
    figures: &ValidatedLayer,
    drawn: &ValidatedLayer,
) -> Vec<Option<u32>> {
    if !(figures.is_octilinear() && drawn.is_octilinear()) {
        // At any angle no point near a corner is safely inside at a small
        // scale, and rounding moves boundaries: the figure sharing area.
        return gpurify_geom::derive::holding_figures(figures, drawn);
    }
    let mut by_xlo: Vec<(Bbox, u32)> = figures.bboxes().iter().copied().zip(0..).collect();
    by_xlo.sort_unstable_by_key(|&(b, _)| b.xlo);
    let widest = by_xlo
        .iter()
        .map(|(b, _)| (b.xhi - b.xlo).raw())
        .max()
        .unwrap_or(0);
    (0..u32::try_from(drawn.len()).expect("a layer indexes polygons with a u32"))
        .map(|poly| {
            let shape = drawn.get(poly);
            let (x8, y8) = interior_point8(shape);
            let b = shape.bbox();
            // A figure holding the shape starts at or left of it and reaches past it.
            let lo = by_xlo.partition_point(|&(f, _)| f.xlo.raw() < b.xhi.raw() - widest);
            let hi = by_xlo.partition_point(|&(f, _)| f.xlo <= b.xlo);
            by_xlo[lo..hi.max(lo)]
                .iter()
                .find(|&&(f, figure)| {
                    f.contains(b) && contains_scaled(figures.get(figure), x8, y8, 8)
                })
                .map(|&(_, figure)| figure)
        })
        .collect()
}

/// A point of a figure's material for its marker: one step inside it from
/// its lowest convex corner, floored to the grid; for a figure with an edge
/// at an angle other than a multiple of 45 degrees, that corner itself (on
/// its boundary, so within the figure, closed).
pub(crate) fn figure_point(poly: PolygonRef<'_>) -> Point {
    let (xs, ys) = poly.outer().coords();
    let skew = ring_segs(xs, ys).any(|e| {
        let (dx, dy) = ((e.b.x - e.a.x).raw(), (e.b.y - e.a.y).raw());
        dx != 0 && dy != 0 && dx.abs() != dy.abs()
    });
    if skew {
        let v = (0..xs.len())
            .min_by_key(|&i| (ys[i], xs[i]))
            .expect("a ring has vertices");
        return Point { x: xs[v], y: ys[v] };
    }
    let (x8, y8) = interior_point8(poly);
    Point {
        x: Dbu::new_unchecked(x8.div_euclid(8)),
        y: Dbu::new_unchecked(y8.div_euclid(8)),
    }
}

/// A layer validated and merged; `None` when it does not validate.
pub(crate) fn merged(
    store: &GeometryStore,
    layer: LayerId,
    s: &mut crate::drc::Scratch,
) -> Option<ValidatedLayer> {
    let drawn = s.validated.get(store, layer)?;
    let mut figures = ValidatedLayer::default();
    union_into(drawn, &ValidatedLayer::default(), &mut figures).ok()?;
    Some(figures)
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

/// Squared distance from a set of rectangles' sides to one ring's edges.
pub(crate) fn rects_ring_dist2(rects: &[Bbox], xs: &[Dbu], ys: &[Dbu]) -> i128 {
    let mut best = i128::MAX;
    for e in ring_segs(xs, ys) {
        for r in rects {
            let (rx, ry) = ([r.xlo, r.xhi, r.xhi, r.xlo], [r.ylo, r.ylo, r.yhi, r.yhi]);
            for side in ring_segs(&rx, &ry) {
                best = best.min(seg_seg_dist2(side, e).raw());
            }
        }
    }
    best
}

pub(crate) const fn seg_bbox(s: Seg) -> Bbox {
    Bbox::point(s.a.x, s.a.y).include(s.b.x, s.b.y)
}

/// Squared distance between two boxes, zero where they touch or overlap; a
/// lower bound on the distance between anything they contain.
pub(crate) const fn bbox_gap2(a: Bbox, b: Bbox) -> DbuArea {
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

/// Squared distance between two store polygons' *boundaries*, as [`seg_dist2`]
/// reads each pair of edges; zero exactly when they touch or cross. Quadratic
/// in the two ring sizes.
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
                best = best.min(seg_dist2(sa, sb));
            }
        }
    }
    best
}

/// Squared distance between two segments as the spacing family compares it.
/// Exact for axis-parallel segments. Between segments at 45 degrees it can be
/// a half unit (`7/√2` is `√24.5`); it is then floored, which compares
/// against any whole squared limit exactly as the true value does (`24.5 <
/// 25` and `24 < 25`), and a gap of `1/√2` reads 1, so only touching reads
/// 0. At any other angle, a fraction, floored the same way
/// ([`seg_seg_twice2`]), with the same exact comparison.
pub(crate) fn seg_dist2(p: Seg, q: Seg) -> DbuArea {
    let delta = |s: Seg| (s.b.x.raw() - s.a.x.raw(), s.b.y.raw() - s.a.y.raw());
    let axis = |(dx, dy): (i64, i64)| dx == 0 || dy == 0;
    let octilinear = |(dx, dy): (i64, i64)| dx == 0 || dy == 0 || dx.abs() == dy.abs();
    let (dp, dq) = (delta(p), delta(q));
    if axis(dp) && axis(dq) {
        return seg_seg_dist2(p, q);
    }
    let (twice, inexact) = if octilinear(dp) && octilinear(dq) {
        (seg_seg_near2(p, q).0, false)
    } else {
        seg_seg_twice2(p, q)
    };
    DbuArea::new(if twice == 0 && !inexact {
        0
    } else {
        (twice / 2).max(1)
    })
}

/// Squared boundary distance for every pair, into `dists`: exact wherever it is
/// below `limit²`, and never below `limit²` where the exact value is not.
/// Rectilinear pairs under a limit below `GAP_CAP` take the capped f64 kernel.
pub(crate) fn pair_distances_into(
    store: &GeometryStore,
    pairs: &[(PolyId, PolyId)],
    limit: Dbu,
    dists: &mut Vec<DbuArea>,
) {
    dists.clear();
    if limit.raw() >= GAP_CAP {
        dists.extend(pairs.iter().map(|&(a, b)| poly_dist2(store, a, b)));
        return;
    }
    dispatch!(Level::new(), simd => capped_distances(simd, store, pairs, dists));
}

/// Zero the distance of every pair that overlaps without its boundaries
/// meeting: a shape nested in another's material, or an outer and its own
/// hole. Boundary distance alone reads either as a gap. A shape inside a hole
/// keeps its distance to that hole, which is a real gap.
pub(crate) fn join_nested(
    store: &GeometryStore,
    holes: &Holes,
    pairs: &[(PolyId, PolyId)],
    dists: &mut [DbuArea],
) {
    let vertex = |p: PolyId| {
        let (xs, ys) = store.poly_verts(p);
        Point { x: xs[0], y: ys[0] }
    };
    for (&(a, b), d2) in pairs.iter().zip(dists) {
        if d2.raw() == 0 {
            continue;
        }
        let own_hole = holes.of(a).any(|h| h == b) || holes.of(b).any(|h| h == a);
        let nested = !holes.is_hole(a)
            && !holes.is_hole(b)
            && (in_material(store, holes, a, vertex(b)) || in_material(store, holes, b, vertex(a)));
        if own_hole || nested {
            *d2 = DbuArea::new(0);
        }
    }
}

/// Gaps are capped here so `gx² + gy²` is exact in f64 (at most 2^53).
const GAP_CAP: i64 = 1 << 26;

/// Squared distance per pair, exact below `GAP_CAP²` and at least `GAP_CAP²`
/// otherwise. Callers compare only against `limit²` with `limit < GAP_CAP`,
/// and report `isqrt` only below it, so this is as good as exact for them.
#[allow(
    clippy::inline_always,
    reason = "a fearless_simd kernel inlines into its dispatch"
)]
#[inline(always)]
fn capped_distances<S: Simd>(
    s: S,
    store: &GeometryStore,
    pairs: &[(PolyId, PolyId)],
    dists: &mut Vec<DbuArea>,
) {
    let mut far = EdgeBoxes::default();
    for &(a, b) in pairs {
        let (axs, ays) = store.poly_verts(a);
        let (bxs, bys) = store.poly_verts(b);
        let d2 = if rectilinear(axs, ays) && rectilinear(bxs, bys) {
            far.fill(bxs, bys);
            DbuArea::new(capped_dist2_simd(s, axs, ays, &far))
        } else {
            poly_dist2(store, a, b)
        };
        dists.push(d2);
    }
}

/// Every edge axis-aligned (or zero-length).
fn rectilinear(xs: &[Dbu], ys: &[Dbu]) -> bool {
    ring_segs(xs, ys).all(|e| e.a.x == e.b.x || e.a.y == e.b.y)
}

/// One ring's edge boxes as f64 columns (exact: |coordinate| <= 2^40).
#[derive(Debug, Default)]
struct EdgeBoxes {
    xlo: Vec<f64>,
    xhi: Vec<f64>,
    ylo: Vec<f64>,
    yhi: Vec<f64>,
}

impl EdgeBoxes {
    fn fill(&mut self, xs: &[Dbu], ys: &[Dbu]) {
        self.xlo.clear();
        self.xhi.clear();
        self.ylo.clear();
        self.yhi.clear();
        for e in ring_segs(xs, ys) {
            let b = seg_bbox(e);
            self.xlo.push(to_f64(b.xlo));
            self.xhi.push(to_f64(b.xhi));
            self.ylo.push(to_f64(b.ylo));
            self.yhi.push(to_f64(b.yhi));
        }
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "|coordinate| <= 2^40, exact in f64"
)]
fn to_f64(d: Dbu) -> f64 {
    d.raw() as f64
}

/// An axis-aligned segment is its own box, so two such segments are
/// `gx² + gy²` apart, with `g` the per-axis box gap (capped at `GAP_CAP`).
fn capped_gap2(a: Bbox, far: &EdgeBoxes, j: usize) -> f64 {
    let cap = to_f64(Dbu::new_unchecked(GAP_CAP));
    let gx = (to_f64(a.xlo).max(far.xlo[j]) - to_f64(a.xhi).min(far.xhi[j])).clamp(0.0, cap);
    let gy = (to_f64(a.ylo).max(far.ylo[j]) - to_f64(a.yhi).min(far.yhi[j])).clamp(0.0, cap);
    gx * gx + gy * gy
}

/// The scalar kernel: tail and oracle of [`capped_dist2_simd`].
fn capped_dist2_scalar(xs: &[Dbu], ys: &[Dbu], far: &EdgeBoxes, from: usize) -> f64 {
    let mut best = f64::INFINITY;
    for e in ring_segs(xs, ys) {
        let a = seg_bbox(e);
        for j in from..far.xlo.len() {
            best = best.min(capped_gap2(a, far, j));
        }
    }
    best
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::inline_always,
    reason = "an integer at most 2^53; a fearless_simd kernel inlines into its dispatch"
)]
#[inline(always)]
fn capped_dist2_simd<S: Simd>(s: S, xs: &[Dbu], ys: &[Dbu], far: &EdgeBoxes) -> i128 {
    let chunks = far.xlo.len() / 4 * 4;
    let (zero, cap) = (
        f64x4::splat(s, 0.0),
        f64x4::splat(s, to_f64(Dbu::new_unchecked(GAP_CAP))),
    );
    let mut best = f64x4::splat(s, f64::INFINITY);
    for e in ring_segs(xs, ys) {
        let a = seg_bbox(e);
        let (axlo, axhi) = (
            f64x4::splat(s, to_f64(a.xlo)),
            f64x4::splat(s, to_f64(a.xhi)),
        );
        let (aylo, ayhi) = (
            f64x4::splat(s, to_f64(a.ylo)),
            f64x4::splat(s, to_f64(a.yhi)),
        );
        for j in (0..chunks).step_by(4) {
            let load = |col: &[f64]| f64x4::from_slice(s, &col[j..j + 4]);
            let gx = (axlo.max(load(&far.xlo)) - axhi.min(load(&far.xhi)))
                .max(zero)
                .min(cap);
            let gy = (aylo.max(load(&far.ylo)) - ayhi.min(load(&far.yhi)))
                .max(zero)
                .min(cap);
            best = best.min(gx * gx + gy * gy);
        }
    }
    let best = best
        .reduce_min()
        .min(capped_dist2_scalar(xs, ys, far, chunks));
    i128::from(best as i64)
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

#[cfg(test)]
mod tests {
    use super::*;
    use gpurify_geom::store::GeometryStoreBuilder;
    use gpurify_geom::{LayerId, MAX_ABS_DBU};

    struct Rng(u64);
    impl Rng {
        fn below(&mut self, n: i64) -> i64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            i64::try_from(self.0 % n.unsigned_abs()).unwrap()
        }
        fn coord(&mut self, centre: i64, spread: i64) -> Dbu {
            let raw = centre + self.below(2 * spread + 1) - spread;
            Dbu::new_unchecked(raw.clamp(-MAX_ABS_DBU, MAX_ABS_DBU))
        }
    }

    /// A closed ring of `2k` vertices, every edge axis-aligned (may self-cross).
    fn staircase(r: &mut Rng, k: usize, c: (i64, i64), spread: i64) -> (Vec<Dbu>, Vec<Dbu>) {
        let px: Vec<Dbu> = (0..k).map(|_| r.coord(c.0, spread)).collect();
        let py: Vec<Dbu> = (0..k).map(|_| r.coord(c.1, spread)).collect();
        let (mut xs, mut ys) = (Vec::new(), Vec::new());
        for i in 0..k {
            xs.extend([px[i], px[(i + 1) % k]]);
            ys.extend([py[i], py[i]]);
        }
        (xs, ys)
    }

    fn free_ring(r: &mut Rng, n: usize, c: (i64, i64), spread: i64) -> (Vec<Dbu>, Vec<Dbu>) {
        (0..n)
            .map(|_| (r.coord(c.0, spread), r.coord(c.1, spread)))
            .unzip()
    }

    /// Differential: the capped path equals the exact i128 one below the cap,
    /// never reads under it above, and non-rectilinear pairs fall back.
    ///
    /// Oracle: differential against the exact i128 path (`GAP_CAP` itself as
    /// the cap): equal below the cap, never under it above, over random
    /// staircases and free rings.
    #[test]
    fn capped_distances_agree_with_poly_dist2() {
        let mut r = Rng(0x2545_f491_4f6c_dd1d);
        let cap2 = i128::from(GAP_CAP) * i128::from(GAP_CAP);
        for round in 0..400 {
            let spread = [10, 1_000, GAP_CAP, MAX_ABS_DBU][round % 4];
            let centre = if round % 7 == 0 { MAX_ABS_DBU - 5 } else { 0 };
            let mut b = GeometryStoreBuilder::default();
            for _ in 0..6 {
                let c = (r.coord(centre, spread).raw(), r.coord(0, spread).raw());
                let (xs, ys) = if r.below(3) == 0 {
                    let n = 3 + usize::try_from(r.below(5)).unwrap();
                    free_ring(&mut r, n, c, spread / 4 + 1)
                } else {
                    let k = 1 + usize::try_from(r.below(7)).unwrap();
                    staircase(&mut r, k, c, spread / 4 + 1)
                };
                b.push(LayerId(0), &xs, &ys);
            }
            let (store, _) = b.finish(1);
            let pairs: Vec<(PolyId, PolyId)> = (0..6)
                .flat_map(|a| (a + 1..6).map(move |b| (PolyId(a), PolyId(b))))
                .collect();
            let (mut exact, mut capped) = (Vec::new(), Vec::new());
            pair_distances_into(&store, &pairs, Dbu::new_unchecked(GAP_CAP), &mut exact);
            pair_distances_into(&store, &pairs, Dbu::new_unchecked(GAP_CAP - 1), &mut capped);
            for ((e, c), p) in exact.iter().zip(&capped).zip(&pairs) {
                if e.raw() < cap2 {
                    assert_eq!(e, c, "{p:?}");
                } else {
                    assert!(c.raw() >= cap2, "{p:?}: {c:?} under the cap for {e:?}");
                }
            }
        }
    }

    fn seg(ax: i64, ay: i64, bx: i64, by: i64) -> Seg {
        let p = |x, y| Point {
            x: Dbu::new_unchecked(x),
            y: Dbu::new_unchecked(y),
        };
        Seg {
            a: p(ax, ay),
            b: p(bx, by),
        }
    }

    /// Oracle: `seg_dist2`'s contract, hand values. Two 45-degree lines `y =
    /// x` and `y = x + 7` are `7/√2` apart, squared 24.5, floored to 24 (a
    /// rounding up would read 25); `y = x + 1` is squared 0.5, read 1;
    /// touching reads 0; axis-aligned segments 3 along and 4 across read 16.
    /// Segments of slope 1/2 on `y = x/2` and `y = x/2 + 3` are `3/√1.25`
    /// apart, squared 7.2: any other angle takes `seg_seg_dist2`, rounded up
    /// to 8.
    #[test]
    fn seg_dist2_floors_45_degree_half_units_and_rounds_other_angles_up() {
        let diagonal = seg(0, 0, 10, 10);
        let at = |p, q| seg_dist2(p, q).raw();
        assert_eq!(at(diagonal, seg(0, 7, 10, 17)), 24);
        assert_eq!(at(diagonal, seg(0, 1, 10, 11)), 1);
        assert_eq!(at(diagonal, seg(10, 10, 20, 0)), 0);
        assert_eq!(at(seg(0, 0, 10, 0), seg(13, 4, 23, 4)), 16 + 9);
        assert_eq!(at(seg(0, 0, 10, 0), seg(3, 4, 13, 4)), 16);
        let (p, q) = (seg(0, 0, 20, 10), seg(0, 3, 20, 13));
        assert_eq!(at(p, q), 8);
        assert_eq!(seg_dist2(p, q), seg_seg_dist2(p, q));
    }

    /// Differential: the SIMD kernel equals its scalar oracle for every edge
    /// count `0 ..= 3 * 4 + 1` on either side.
    ///
    /// Oracle: differential against `capped_dist2_scalar`, at every edge count
    /// 0 to 13 on either side.
    #[test]
    fn capped_dist2_simd_matches_scalar() {
        let mut r = Rng(0x9e37_79b9_7f4a_7c15);
        let mut far = EdgeBoxes::default();
        for n in 0..=13 {
            for m in 0..=13 {
                for spread in [3, GAP_CAP, MAX_ABS_DBU] {
                    let (xs, ys) = free_ring(&mut r, n, (0, 0), spread);
                    let (bx, by) = free_ring(&mut r, m, (0, 0), spread);
                    far.fill(&bx, &by);
                    let simd = dispatch!(Level::new(), s => capped_dist2_simd(s, &xs, &ys, &far));
                    #[allow(clippy::cast_possible_truncation, reason = "at most 2^53, or inf")]
                    let scalar = i128::from(capped_dist2_scalar(&xs, &ys, &far, 0) as i64);
                    assert_eq!(simd, scalar, "n={n} m={m}");
                }
            }
        }
    }
}
