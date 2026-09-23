//! Validated geometry: simple rectilinear rings, canonical winding, holes bound to
//! their innermost containing outer.
//!
//! Data in: one layer of a [`GeometryStore`].
//! Data out: [`ValidatedLayer`], one outer-plus-holes polygon per CCW ring.

use crate::bbox::Bbox;
use crate::ids::{LayerId, PolyId};
use crate::index::{candidate_pairs_into, SpatialIndex};
use crate::ops::{point_in_coords, self_intersects_with, winding_of, Point, SweptEdge, Winding};
use crate::store::GeometryStore;
use crate::{Dbu, DbuArea};
use fearless_simd::{dispatch, i64x4, mask64x4, prelude::*, Level};

/// Why a polygon could not be validated; never a silently skipped row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ValidityError {
    #[error("polygon {0:?} has fewer than three distinct vertices")]
    Degenerate(PolyId),
    #[error("polygon {0:?} has self-intersecting boundary")]
    SelfIntersecting(PolyId),
    #[error("polygon {0:?} is a hole with no containing outer ring")]
    OrphanHole(PolyId),
    #[error("polygon {0:?} is not rectilinear")]
    NotRectilinear(PolyId),
}

/// One layer's geometry, validated and grouped into outer-plus-holes polygons.
/// [`PartialEq`] is structural (same rings in the same order), not region equality.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ValidatedLayer {
    /// Owned: a boolean produces vertices no store row holds.
    verts_x: Vec<Dbu>,
    verts_y: Vec<Dbu>,
    ring_vert_start: Vec<u32>,
    ring_vert_len: Vec<u32>,
    /// Provenance; for a boolean result, the lowest contributing [`PolyId`].
    ring_poly: Vec<PolyId>,
    /// Ring 0 of each span is the outer (CCW); the rest are holes (CW).
    poly_ring_start: Vec<u32>,
    poly_ring_len: Vec<u32>,
    poly_bbox: Vec<Bbox>,
}

impl ValidatedLayer {
    pub fn len(&self) -> usize {
        self.poly_ring_start.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Borrow one validated polygon.
    pub fn get(&self, idx: u32) -> PolygonRef<'_> {
        PolygonRef { layer: self, idx }
    }

    /// One row per polygon, in `get` index order.
    pub fn bboxes(&self) -> &[Bbox] {
        &self.poly_bbox
    }

    /// Every ring of one polygon, outer first.
    pub(crate) fn poly_rings(&self, idx: u32) -> impl Iterator<Item = RingRef<'_>> + '_ {
        let start = self.poly_ring_start[idx as usize];
        let len = self.poly_ring_len[idx as usize];
        (start..start + len).map(move |ring| self.ring(ring))
    }

    fn ring(&self, ring: u32) -> RingRef<'_> {
        let start = self.ring_vert_start[ring as usize] as usize;
        let len = self.ring_vert_len[ring as usize] as usize;
        RingRef {
            xs: &self.verts_x[start..start + len],
            ys: &self.verts_y[start..start + len],
        }
    }
}

/// A polygon that is known valid: simple rings, canonical winding, holes
/// contained by their outer boundary.
#[derive(Debug, Clone, Copy)]
pub struct PolygonRef<'a> {
    layer: &'a ValidatedLayer,
    idx: u32,
}

impl<'a> PolygonRef<'a> {
    /// The outer boundary, wound CCW.
    pub fn outer(self) -> RingRef<'a> {
        self.layer
            .ring(self.layer.poly_ring_start[self.idx as usize])
    }

    /// The holes, wound CW, ascending by store row.
    pub fn holes(self) -> impl Iterator<Item = RingRef<'a>> + 'a {
        let layer = self.layer;
        let start = layer.poly_ring_start[self.idx as usize];
        let len = layer.poly_ring_len[self.idx as usize];
        (start + 1..start + len).map(move |ring| layer.ring(ring))
    }

    pub fn bbox(self) -> Bbox {
        self.layer.poly_bbox[self.idx as usize]
    }

    /// The store row of the outer, then of each hole. Meaningful only for a
    /// layer validated straight from the store, not for a boolean result.
    pub fn rows(self) -> impl Iterator<Item = PolyId> + 'a {
        let layer = self.layer;
        let start = layer.poly_ring_start[self.idx as usize] as usize;
        let len = layer.poly_ring_len[self.idx as usize] as usize;
        layer.ring_poly[start..start + len].iter().copied()
    }

    /// The store row to blame a finding on; for a boolean result, the lowest
    /// contributing [`PolyId`].
    pub fn provenance(self) -> PolyId {
        let ring = self.layer.poly_ring_start[self.idx as usize] as usize;
        self.layer.ring_poly[ring]
    }
}

/// One validated closed ring.
#[derive(Debug, Clone, Copy)]
pub struct RingRef<'a> {
    xs: &'a [Dbu],
    ys: &'a [Dbu],
}

impl<'a> RingRef<'a> {
    pub fn coords(self) -> (&'a [Dbu], &'a [Dbu]) {
        (self.xs, self.ys)
    }

    /// Twice the signed area; positive for CCW.
    pub fn area2(self) -> DbuArea {
        crate::ops::area2(self.xs, self.ys)
    }
}

/// `outer_slot` marker for a hole row.
const NOT_OUTER: u32 = u32::MAX;

/// Validate every polygon on one layer into `out` (cleared and refilled).
/// Fails on the first invalid polygon; arbitrary-angle input is
/// [`ValidityError::NotRectilinear`], not an approximation.
pub fn validate_layer_into(
    store: &GeometryStore,
    layer: LayerId,
    out: &mut ValidatedLayer,
) -> Result<(), ValidityError> {
    let rows = store.polys_on_layer(layer);
    out.reset();

    // Pass one: shape validation, splitting the layer's rows by winding.
    let rows_len = (rows.end - rows.start) as usize;
    let first = rows.start as usize;
    let mut outers: Vec<PolyId> = Vec::with_capacity(rows_len);
    let mut holes: Vec<PolyId> = Vec::with_capacity(rows_len);
    // Per layer row: its slot in `outers`, or `NOT_OUTER`.
    let mut outer_slot: Vec<u32> = Vec::with_capacity(rows_len);
    let mut edges = Vec::new();
    dispatch!(Level::new(), s => {
        for row in rows.clone() {
            let poly = PolyId(row);
            let (xs, ys) = store.poly_verts(poly);
            match classify_ring(s, xs, ys, poly, &mut edges)? {
                Winding::CounterClockwise => {
                    outer_slot.push(u32::try_from(outers.len()).expect("outers fit a u32"));
                    outers.push(poly);
                }
                Winding::Clockwise => {
                    outer_slot.push(NOT_OUTER);
                    holes.push(poly);
                }
            }
        }
        Ok::<(), ValidityError>(())
    })?;

    // Pass two: bind each hole to the innermost outer containing it. Distance-zero
    // candidates are every touching pair, and containment implies touching.
    let mut owned: Vec<(usize, PolyId)> = Vec::with_capacity(holes.len());
    if !holes.is_empty() {
        let mut index = SpatialIndex::default();
        SpatialIndex::build_into(store, layer, &mut index);
        let mut pairs: Vec<(PolyId, PolyId)> = Vec::new();
        candidate_pairs_into(store, &index, Dbu::new_unchecked(0), &mut pairs);

        // Keep only (outer, hole) pairs whose outer box encloses the hole's.
        let nested: Vec<(PolyId, PolyId)> = pairs
            .iter()
            .copied()
            .filter(|&(a, b)| {
                let a_outer = outer_slot[a.idx() - first] != NOT_OUTER;
                let b_outer = outer_slot[b.idx() - first] != NOT_OUTER;
                let a_in_b = store.poly_bbox(b).contains(store.poly_bbox(a));
                let b_in_a = store.poly_bbox(a).contains(store.poly_bbox(b));
                (a_outer != b_outer) & ((a_outer & b_in_a) | (b_outer & a_in_b))
            })
            .collect();

        // Starts above any real box area (<= 2^82).
        let mut best_area = vec![DbuArea::new(i128::MAX); rows_len];
        let mut best_slot = vec![NOT_OUTER; rows_len];
        for &(a, b) in &nested {
            let a_slot = outer_slot[a.idx() - first];
            let b_slot = outer_slot[b.idx() - first];
            let a_is_hole = a_slot == NOT_OUTER;
            let (outer, hole, slot) = if a_is_hole {
                (b, a, b_slot)
            } else {
                (a, b, a_slot)
            };

            let (hole_xs, hole_ys) = store.poly_verts(hole);
            let (outer_xs, outer_ys) = store.poly_verts(outer);
            let probe = Point {
                x: hole_xs[0],
                y: hole_ys[0],
            };
            if !point_in_coords(outer_xs, outer_ys, probe) {
                continue;
            }
            // Innermost = smallest containing box. Strict `<` over ascending pairs:
            // a tie keeps the lower store row.
            let area = store.poly_bbox(outer).area();
            let row = hole.idx() - first;
            if area < best_area[row] {
                best_area[row] = area;
                best_slot[row] = slot;
            }
        }

        for &hole in &holes {
            let slot = best_slot[hole.idx() - first];
            if slot == NOT_OUTER {
                return Err(ValidityError::OrphanHole(hole));
            }
            owned.push((slot as usize, hole));
        }
    }
    // Holes follow their outer, ascending by store row.
    owned.sort_unstable();

    // Pass three: emit, one contiguous ring span per polygon, outer first.
    let mut cursor = 0usize;
    for (slot, &outer) in outers.iter().enumerate() {
        let span_start = u32::try_from(out.ring_vert_start.len()).expect("rings fit a u32");
        let (outer_xs, outer_ys) = store.poly_verts(outer);
        out.push_ring(outer_xs, outer_ys, outer);
        while cursor < owned.len() && owned[cursor].0 == slot {
            let hole = owned[cursor].1;
            let (hole_xs, hole_ys) = store.poly_verts(hole);
            out.push_ring(hole_xs, hole_ys, hole);
            cursor += 1;
        }
        let span_len = u32::try_from(out.ring_vert_start.len()).expect("rings fit a u32");
        out.poly_ring_start.push(span_start);
        out.poly_ring_len.push(span_len - span_start);
        out.poly_bbox.push(store.poly_bbox(outer));
    }

    Ok(())
}

impl ValidatedLayer {
    /// Empty the buffer for reuse, keeping capacity.
    fn reset(&mut self) {
        self.verts_x.clear();
        self.verts_y.clear();
        self.ring_vert_start.clear();
        self.ring_vert_len.clear();
        self.ring_poly.clear();
        self.poly_ring_start.clear();
        self.poly_ring_len.clear();
        self.poly_bbox.clear();
    }

    /// Copy one ring's coordinates in and append its ring row.
    fn push_ring(&mut self, xs: &[Dbu], ys: &[Dbu], poly: PolyId) {
        let start = u32::try_from(self.verts_x.len()).expect("a layer's vertices fit a u32");
        let len = u32::try_from(xs.len()).expect("a ring's vertices fit a u32");
        self.verts_x.extend_from_slice(xs);
        self.verts_y.extend_from_slice(ys);
        self.ring_vert_start.push(start);
        self.ring_vert_len.push(len);
        self.ring_poly.push(poly);
    }
}

/// Validate one coordinate run and report its winding. Check order is part of the
/// answer: a bowtie is reported as self-intersecting, not non-rectilinear.
#[inline(always)]
fn classify_ring<S: Simd>(
    s: S,
    xs: &[Dbu],
    ys: &[Dbu],
    poly: PolyId,
    edges: &mut Vec<SweptEdge>,
) -> Result<Winding, ValidityError> {
    if xs.len() < 3 {
        return Err(ValidityError::Degenerate(poly));
    }
    let (distinct, rectilinear) = edge_flags(s, xs, ys);
    if !distinct {
        return Err(ValidityError::Degenerate(poly));
    }
    if !is_rectangle(xs, ys) && self_intersects_with(xs, ys, edges) {
        return Err(ValidityError::SelfIntersecting(poly));
    }
    if !rectilinear {
        return Err(ValidityError::NotRectilinear(poly));
    }
    // A run doubling back on itself has zero area: degenerate.
    winding_of(xs, ys).ok_or(ValidityError::Degenerate(poly))
}

/// Four distinct vertices alternating vertical and horizontal edges: an axis
/// box, whose opposite sides never meet, so the self-intersection sweep is moot.
fn is_rectangle(xs: &[Dbu], ys: &[Dbu]) -> bool {
    let [x0, x1, x2, x3] = xs else { return false };
    let [y0, y1, y2, y3] = ys else { return false };
    (x0 == x1 && y1 == y2 && x2 == x3 && y3 == y0) || (y0 == y1 && x1 == x2 && y2 == y3 && x3 == x0)
}

/// `(distinct, rectilinear)` over every edge of a closed run of `n >= 1` vertices:
/// no edge has both ends equal, and every edge keeps x or y.
#[inline(always)]
fn edge_flags<S: Simd>(s: S, xs: &[Dbu], ys: &[Dbu]) -> (bool, bool) {
    let n = xs.len();
    if n <= 4 {
        return edge_flags_scalar(xs, ys, xs[0], ys[0]);
    }
    let (ax, bx) = (&xs[..n - 1], &xs[1..]);
    let (ay, by) = (&ys[..n - 1], &ys[1..]);
    let (axc, _) = ax.as_chunks::<4>();
    let (bxc, _) = bx.as_chunks::<4>();
    let (ayc, _) = ay.as_chunks::<4>();
    let (byc, _) = by.as_chunks::<4>();
    let lanes = |c: &[Dbu; 4]| i64x4::from_slice(s, &c.map(Dbu::raw));
    let mut dup = mask64x4::splat(s, false);
    let mut skew = mask64x4::splat(s, false);
    for (((ax, bx), ay), by) in axc.iter().zip(bxc).zip(ayc).zip(byc) {
        let same_x = lanes(ax).simd_eq(lanes(bx));
        let same_y = lanes(ay).simd_eq(lanes(by));
        dup |= same_x & same_y;
        skew |= !(same_x | same_y);
    }
    // The tail edges plus the closing edge `n - 1 -> 0`.
    let done = 4 * axc.len();
    let (td, tr) = edge_flags_scalar(&xs[done..], &ys[done..], xs[0], ys[0]);
    (!dup.any_true() & td, !skew.any_true() & tr)
}

/// Scalar [`edge_flags`] over the open run `xs`, closed back to `(x0, y0)`: the
/// kernel's tail and its test oracle (`edge_flags_scalar(xs, ys, xs[0], ys[0])`).
fn edge_flags_scalar(xs: &[Dbu], ys: &[Dbu], x0: Dbu, y0: Dbu) -> (bool, bool) {
    let (mut distinct, mut rectilinear) = (true, true);
    let next_x = xs[1..].iter().chain([&x0]);
    let next_y = ys[1..].iter().chain([&y0]);
    for (((x, y), nx), ny) in xs.iter().zip(ys).zip(next_x).zip(next_y) {
        let (same_x, same_y) = (x == nx, y == ny);
        distinct &= !(same_x & same_y);
        rectilinear &= same_x | same_y;
    }
    (distinct, rectilinear)
}

#[cfg(test)]
mod tests {
    use super::{edge_flags, edge_flags_scalar, is_rectangle};
    use crate::ops::self_intersects;

    /// Every distinct 4-ring over a 3x3 grid: the shortcut claims no ring the
    /// sweep would call self-intersecting.
    #[test]
    fn a_rectangle_never_self_intersects() {
        let mut rects = 0;
        for code in 0..9u32.pow(4) {
            let v: Vec<(i64, i64)> = (0..4)
                .map(|k| {
                    let c = i64::from(code / 9u32.pow(k) % 9);
                    (c % 3, c / 3)
                })
                .collect();
            let xs: Vec<Dbu> = v.iter().map(|p| Dbu::new_unchecked(p.0)).collect();
            let ys: Vec<Dbu> = v.iter().map(|p| Dbu::new_unchecked(p.1)).collect();
            if edge_flags_scalar(&xs, &ys, xs[0], ys[0]).0 && is_rectangle(&xs, &ys) {
                rects += 1;
                assert!(!self_intersects(&xs, &ys), "{v:?}");
            }
        }
        assert!(rects > 0);
    }
    use crate::Dbu;
    use fearless_simd::{dispatch, Level};

    /// Rings over a three-value alphabet, so equal neighbours (duplicates, axis
    /// edges) and skew edges all turn up, at every length `1 ..= 13`.
    #[test]
    fn edge_flags_match_the_scalar_loop() {
        for n in 1..=13usize {
            for seed in 0..512u64 {
                let draw = |k: u64| {
                    (0..n as u64)
                        .map(|i| {
                            let h = (seed * 31 + i * 7 + k).wrapping_mul(0x9E37_79B9_7F4A_7C15);
                            let v = [0, crate::MAX_ABS_DBU, -crate::MAX_ABS_DBU]
                                [(h >> 40) as usize % 3];
                            Dbu::new_unchecked(v)
                        })
                        .collect::<Vec<_>>()
                };
                let (xs, ys) = (draw(0), draw(1));
                let got = dispatch!(Level::new(), s => edge_flags(s, &xs, &ys));
                assert_eq!(
                    got,
                    edge_flags_scalar(&xs, &ys, xs[0], ys[0]),
                    "n={n} seed={seed}"
                );
            }
        }
    }

    /// `cargo test -p gpurify-geom --release -- --ignored --nocapture bench_`
    #[test]
    #[ignore = "timing, not a check"]
    fn bench_edge_flags() {
        use std::hint::black_box;
        use std::time::Instant;
        for ring in [4i64, 8, 32, 200] {
            let rings = 400_000 / ring;
            // A staircase: rectilinear, distinct, so neither loop exits early.
            let (xs, ys): (Vec<Dbu>, Vec<Dbu>) = (0..ring)
                .map(|i| (Dbu::new_unchecked((i + 1) / 2), Dbu::new_unchecked(i / 2)))
                .unzip();
            let simd = (0..9)
                .map(|_| {
                    let t = Instant::now();
                    dispatch!(Level::new(), s => for _ in 0..rings {
                        black_box(edge_flags(s, black_box(&xs), black_box(&ys)));
                    });
                    t.elapsed()
                })
                .min()
                .unwrap();
            let scalar = (0..9)
                .map(|_| {
                    let t = Instant::now();
                    for _ in 0..rings {
                        let (xs, ys) = (black_box(&xs), black_box(&ys));
                        black_box(edge_flags_scalar(xs, ys, xs[0], ys[0]));
                    }
                    t.elapsed()
                })
                .min()
                .unwrap();
            println!("ring={ring}: simd {simd:?} scalar {scalar:?} (400k verts, best of 9)");
        }
    }
}
