//! The one place a polygon lives.

use crate::bbox::Bbox;
use crate::ids::{LayerId, PolyId};
use crate::ops::Point;
use gpurify_units::Dbu;
use std::ops::Range;

/// Flat layout geometry, grouped by layer.
///
/// Rows are ordered by [`LayerId`] and `layer_start` is a CSR offset array of
/// length `layer_count + 1`, so one layer's polygons are contiguous in every
/// column. [`PolyId`] order is therefore not insertion order: `ingest` must
/// permute its provenance columns by the permutation
/// [`GeometryStoreBuilder::finish`] returns, an invariant with no compiler
/// behind it.
#[derive(Debug, Default)]
pub struct GeometryStore {
    /// Vertex X, indexed by [`crate::VertId`].
    verts_x: Vec<Dbu>,
    verts_y: Vec<Dbu>,

    poly_layer: Vec<LayerId>,
    /// First vertex of each polygon, into `verts_x` / `verts_y`.
    poly_vert_start: Vec<u32>,
    poly_vert_len: Vec<u32>,
    poly_bbox: Vec<Bbox>,

    /// `layer_start[l] .. layer_start[l + 1]` are the rows on layer `l`.
    layer_start: Vec<u32>,
}

impl GeometryStore {
    pub fn poly_count(&self) -> usize {
        self.poly_layer.len()
    }

    pub fn layer_count(&self) -> usize {
        // `saturating_sub`, not `- 1`: a `Default` store has no offsets at all,
        // and zero layers is the honest answer for it.
        self.layer_start.len().saturating_sub(1)
    }

    /// The polygons on one layer, as a contiguous row range; empty for a layer
    /// with no geometry.
    pub fn polys_on_layer(&self, layer: LayerId) -> Range<u32> {
        // Fail closed: a layer beyond the deck's table indexes out of bounds and
        // panics in every profile. An empty range would make "this layer holds
        // nothing" and "this layer does not exist" indistinguishable, and the
        // second must never read as clean.
        self.layer_start[layer.idx()]..self.layer_start[layer.idx() + 1]
    }

    /// The coordinates of one polygon, as two parallel slices.
    pub fn poly_verts(&self, poly: PolyId) -> (&[Dbu], &[Dbu]) {
        let start = self.poly_vert_start[poly.idx()] as usize;
        let end = start + self.poly_vert_len[poly.idx()] as usize;
        debug_assert!(end <= self.verts_x.len(), "vertex run leaves the column");
        (&self.verts_x[start..end], &self.verts_y[start..end])
    }

    pub fn poly_bbox(&self, poly: PolyId) -> Bbox {
        self.poly_bbox[poly.idx()]
    }

    pub fn poly_layer(&self, poly: PolyId) -> LayerId {
        self.poly_layer[poly.idx()]
    }

    /// The bounding-box column for one layer.
    pub fn layer_bboxes(&self, layer: LayerId) -> &[Bbox] {
        let rows = self.polys_on_layer(layer);
        &self.poly_bbox[rows.start as usize..rows.end as usize]
    }

    /// Whether a point lies inside one polygon, the boundary counting as
    /// inside.
    ///
    /// On-edge is inside because a via landing exactly on a conductor's edge is
    /// connected, and because net labels are routinely written on a rectangle's
    /// corner or edge midpoint; a strict-interior test drops them silently.
    /// Not expressible via `ops::point_seg_dist2`, which rounds a slanted
    /// segment's distance away from zero and so never reports zero for a point
    /// genuinely on such an edge.
    pub fn poly_contains_point(&self, poly: PolyId, p: Point) -> bool {
        let (xs, ys) = self.poly_verts(poly);
        point_in_verts(xs, ys, p)
    }

    /// Append one whole layer's rings to the tail of the store, as the same
    /// four columns [`crate::Bbox::of_polys_into`] takes.
    ///
    /// Layer grouping survives an append only when `layer` is at or after every
    /// layer that already holds rows — `layer_start[layer] == poly_count`.
    /// Otherwise the rows land inside another layer's range and
    /// [`Self::polys_on_layer`] hands a rule some other layer's geometry:
    /// wrong, plausible, and checked clean. Hence `assert`, not `debug_assert`.
    pub fn append_layer(
        &mut self,
        layer: LayerId,
        xs: &[Dbu],
        ys: &[Dbu],
        vert_start: &[u32],
        vert_len: &[u32],
    ) {
        assert_eq!(xs.len(), ys.len(), "coordinate columns disagree in length");
        assert_eq!(
            vert_start.len(),
            vert_len.len(),
            "one vertex run per appended ring"
        );
        assert!(layer.idx() < self.layer_count(), "layer id past the table");
        assert_eq!(
            self.layer_start[layer.idx()] as usize,
            self.poly_count(),
            "a layer with rows after it cannot be appended to without moving them"
        );

        let base = u32::try_from(self.verts_x.len()).expect("vertex count fits a u32");
        // The end of the run, checked before anything is written:
        // `poly_vert_start` is a `u32` and a wrapped cursor hands `poly_verts`
        // another polygon's coordinates.
        base.checked_add(u32::try_from(xs.len()).expect("vertex count fits a u32"))
            .expect("total vertex count fits a u32");
        self.verts_x.extend_from_slice(xs);
        self.verts_y.extend_from_slice(ys);

        let rings = vert_start.len();
        self.poly_layer.resize(self.poly_layer.len() + rings, layer);
        for (&start, &len) in vert_start.iter().zip(vert_len) {
            let from = start as usize;
            let to = from + len as usize;
            debug_assert!(to <= xs.len(), "an appended run escapes the columns");
            self.poly_vert_start.push(base + start);
            self.poly_vert_len.push(len);
            self.poly_bbox
                .push(Bbox::of_points(&xs[from..to], &ys[from..to]));
        }

        // Every layer at or after this one was empty, so all their offsets sat
        // at the old row count and move by the same amount.
        let grown = u32::try_from(rings).expect("appended ring count fits a u32");
        for offset in &mut self.layer_start[layer.idx() + 1..] {
            *offset += grown;
        }

        debug_assert_eq!(
            self.poly_layer.len(),
            self.poly_vert_start.len(),
            "the appended rows left the columns ragged"
        );
        debug_assert_eq!(self.poly_layer.len(), self.poly_bbox.len());
        debug_assert_eq!(
            self.layer_start[self.layer_count()] as usize,
            self.poly_count(),
            "the layer offsets no longer cover every row"
        );
        debug_assert_eq!(
            self.polys_on_layer(layer).len(),
            rings,
            "the appended rows are not the ones this layer reports"
        );
    }
}

/// [`GeometryStore::poly_contains_point`] over a ring's two coordinate columns.
fn point_in_verts(xs: &[Dbu], ys: &[Dbu], p: Point) -> bool {
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    let n = xs.len();
    // Under three vertices there is no interior and no edge that bounds
    // anything.
    if n < 3 {
        return false;
    }

    // Seeded with the last vertex so the ring's closing edge is the first term
    // and needs no fixup after the loop.
    let mut crossings = 0u32;
    let mut on_edge = false;
    let (mut ax, mut ay) = (xs[n - 1], ys[n - 1]);
    for i in 0..n {
        let (bx, by) = (xs[i], ys[i]);
        // `(b - a) × (p - a)`, positive when `p` is left of the directed edge.
        // Widened before the multiply: the operands reach `2^41` and the
        // product `2^82`, where `i64` would silently wrap.
        let side = i128::from(bx.raw() - ax.raw()) * i128::from(p.y.raw() - ay.raw())
            - i128::from(by.raw() - ay.raw()) * i128::from(p.x.raw() - ax.raw());

        // Half-open crossing convention: a vertex is counted by exactly one of
        // the two edges meeting at it, so a ray grazing one is not counted
        // twice.
        let up = by.raw() > ay.raw();
        let straddles = (ay.raw() > p.y.raw()) != (by.raw() > p.y.raw());
        crossings += u32::from(straddles & ((side > 0) == up));

        // The boundary half: collinear with the edge *and* within the edge's
        // own span, which is what separates a point on the segment from one on
        // the infinite line through it.
        let within = (p.x.raw() >= ax.raw().min(bx.raw()))
            & (p.x.raw() <= ax.raw().max(bx.raw()))
            & (p.y.raw() >= ay.raw().min(by.raw()))
            & (p.y.raw() <= ay.raw().max(by.raw()));
        on_edge |= (side == 0) & within;

        (ax, ay) = (bx, by);
    }

    (crossings & 1 == 1) | on_edge
}

/// Accumulates polygons in arrival order, then sorts them by layer.
#[derive(Debug, Default)]
pub struct GeometryStoreBuilder {
    verts_x: Vec<Dbu>,
    verts_y: Vec<Dbu>,
    poly_layer: Vec<LayerId>,
    poly_vert_start: Vec<u32>,
    poly_vert_len: Vec<u32>,
}

impl GeometryStoreBuilder {
    /// Pre-size for a known polygon and vertex count.
    pub fn with_capacity(polys: usize, verts: usize) -> Self {
        Self {
            verts_x: Vec::with_capacity(verts),
            verts_y: Vec::with_capacity(verts),
            poly_layer: Vec::with_capacity(polys),
            poly_vert_start: Vec::with_capacity(polys),
            poly_vert_len: Vec::with_capacity(polys),
        }
    }

    /// Append one polygon, returning its pre-sort row index.
    pub fn push(&mut self, layer: LayerId, xs: &[Dbu], ys: &[Dbu]) -> u32 {
        // Every profile, not `debug_assert`: unequal columns would store one
        // polygon's X against the next one's Y and every geometric assertion
        // downstream would still pass.
        assert_eq!(xs.len(), ys.len(), "coordinate columns disagree in length");
        debug_assert!(
            {
                let mut in_range = true;
                for (x, y) in xs.iter().zip(ys) {
                    in_range &= Dbu::new(x.raw()).is_some() & Dbu::new(y.raw()).is_some();
                }
                in_range
            },
            "a coordinate is outside +/-MAX_ABS_DBU, on which every downstream \
             i128 area product depends"
        );

        let row = u32::try_from(self.poly_layer.len()).expect("polygon count fits a u32");
        let start = u32::try_from(self.verts_x.len()).expect("vertex count fits a u32");
        let len = u32::try_from(xs.len()).expect("polygon vertex count fits a u32");
        // The *end* of the run, not just its start: without this the columns
        // can finish one polygon past `u32::MAX` and `finish`'s `u32` vertex
        // cursor wraps silently in release, handing `poly_verts` some other
        // polygon's coordinates — wrong, plausible, and checked clean.
        start
            .checked_add(len)
            .expect("total vertex count fits a u32");

        self.verts_x.extend_from_slice(xs);
        self.verts_y.extend_from_slice(ys);
        self.poly_layer.push(layer);
        self.poly_vert_start.push(start);
        self.poly_vert_len.push(len);

        debug_assert_eq!(self.verts_x.len(), self.verts_y.len());
        row
    }

    /// Sort by layer, compute bounding boxes, and produce the store.
    ///
    /// Returns the permutation alongside the store: `permutation[new_row] ==
    /// old_row`. `ingest` must apply it to every provenance column, or the two
    /// tables desynchronise and a violation is reported against the wrong cell.
    /// The sort is stable, so `permutation` restricted to a layer's range is
    /// strictly ascending.
    ///
    /// `layer_count` comes from the deck, not from the geometry: a layer with
    /// no shapes still needs an empty range, so a rule referencing it returns
    /// "no violations" rather than "no such layer".
    pub fn finish(self, layer_count: usize) -> (GeometryStore, Vec<u32>) {
        let rows = self.poly_layer.len();
        debug_assert_eq!(self.poly_vert_start.len(), rows);
        debug_assert_eq!(self.poly_vert_len.len(), rows);
        debug_assert_eq!(self.verts_x.len(), self.verts_y.len());
        debug_assert!(layer_count <= usize::from(u16::MAX) + 1, "no such LayerId");

        // Counting sort by layer. Pass one is the histogram, offset by one so
        // pass two turns it into the CSR offsets in place.
        let mut layer_start = vec![0u32; layer_count + 1];
        for &layer in &self.poly_layer {
            // Fail closed: a polygon on a layer the deck never declared panics
            // here. Silently dropping it is a clean report for geometry nobody
            // checked.
            layer_start[layer.idx() + 1] += 1;
        }
        for l in 0..layer_count {
            layer_start[l + 1] += layer_start[l];
        }

        // Pass three walks arrivals in ascending order and appends each to its
        // layer's cursor, which is what makes the sort stable.
        let mut cursor = layer_start[..layer_count].to_vec();
        let mut permutation = vec![0u32; rows];
        for (old, &layer) in (0u32..).zip(self.poly_layer.iter()) {
            let slot = &mut cursor[layer.idx()];
            permutation[*slot as usize] = old;
            *slot += 1;
        }
        debug_assert_eq!(cursor.as_slice(), &layer_start[1..], "sort lost a row");

        debug_assert_eq!(permutation.len(), rows);
        let mut poly_layer = Vec::with_capacity(rows);
        let mut poly_vert_len = Vec::with_capacity(rows);
        for &old in &permutation {
            poly_layer.push(self.poly_layer[old as usize]);
            poly_vert_len.push(self.poly_vert_len[old as usize]);
        }
        debug_assert_eq!(poly_layer.len(), rows, "a gather lost a row");
        debug_assert_eq!(poly_vert_len.len(), rows, "a gather lost a row");

        // Coordinates are permuted too, not just the offsets, so one layer's
        // runs stay contiguous.
        let mut verts_x = Vec::with_capacity(self.verts_x.len());
        let mut verts_y = Vec::with_capacity(self.verts_y.len());
        let mut poly_vert_start = Vec::with_capacity(rows);
        // `at` cannot wrap: `push` refuses a polygon whose run would end past
        // `u32::MAX`.
        let mut at = 0u32;
        for (new, &old) in permutation.iter().enumerate() {
            let from = self.poly_vert_start[old as usize] as usize;
            let to = from + poly_vert_len[new] as usize;
            poly_vert_start.push(at);
            at += poly_vert_len[new];
            verts_x.extend_from_slice(&self.verts_x[from..to]);
            verts_y.extend_from_slice(&self.verts_y[from..to]);
        }

        let mut poly_bbox = Vec::new();
        Bbox::of_polys_into(
            &verts_x,
            &verts_y,
            &poly_vert_start,
            &poly_vert_len,
            &mut poly_bbox,
        );

        debug_assert_eq!(verts_x.len(), self.verts_x.len(), "a vertex run was lost");
        debug_assert_eq!(verts_y.len(), self.verts_y.len());
        debug_assert_eq!(at as usize, verts_x.len());
        debug_assert_eq!(poly_bbox.len(), rows);
        debug_assert_eq!(layer_start[layer_count] as usize, rows);
        debug_assert!(
            (0..layer_count).all(|l| {
                let range = layer_start[l] as usize..layer_start[l + 1] as usize;
                permutation[range].windows(2).all(|w| w[0] < w[1])
            }),
            "the sort is not stable within a layer"
        );

        let store = GeometryStore {
            verts_x,
            verts_y,
            poly_layer,
            poly_vert_start,
            poly_vert_len,
            poly_bbox,
            layer_start,
        };
        (store, permutation)
    }
}
