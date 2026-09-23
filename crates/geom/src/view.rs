//! Validated geometry: simple rectilinear rings, canonical winding, holes bound to
//! their innermost containing outer.
//!
//! Data in: one layer of a [`GeometryStore`].
//! Data out: [`ValidatedLayer`], one outer-plus-holes polygon per CCW ring.

use crate::bbox::Bbox;
use crate::ids::{LayerId, PolyId};
use crate::index::{candidate_pairs_into, SpatialIndex};
use crate::ops::{point_in_coords, self_intersects, winding_of, Point, Winding};
use crate::store::GeometryStore;
use crate::{Dbu, DbuArea};

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
    for row in rows.clone() {
        let poly = PolyId(row);
        let (xs, ys) = store.poly_verts(poly);
        match classify_ring(xs, ys, poly)? {
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
fn classify_ring(xs: &[Dbu], ys: &[Dbu], poly: PolyId) -> Result<Winding, ValidityError> {
    let n = xs.len();
    if n < 3 {
        return Err(ValidityError::Degenerate(poly));
    }

    // Seeded with the last vertex so the closing edge is in the same pass.
    let (mut px, mut py) = (xs[n - 1], ys[n - 1]);
    let (mut distinct, mut rectilinear) = (true, true);
    for i in 0..n {
        let (x, y) = (xs[i], ys[i]);
        let same_x = px == x;
        let same_y = py == y;
        distinct &= !(same_x & same_y);
        rectilinear &= same_x | same_y;
        px = x;
        py = y;
    }

    if !distinct {
        return Err(ValidityError::Degenerate(poly));
    }
    if self_intersects(xs, ys) {
        return Err(ValidityError::SelfIntersecting(poly));
    }
    if !rectilinear {
        return Err(ValidityError::NotRectilinear(poly));
    }
    // A run doubling back on itself has zero area: degenerate.
    winding_of(xs, ys).ok_or(ValidityError::Degenerate(poly))
}
