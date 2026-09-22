//! The one place a polygon lives.
//!
//! Data in: rings as `(LayerId, xs, ys)` in arrival order, via [`GeometryStoreBuilder::push`].
//! Data out: [`GeometryStore`], SoA columns grouped by layer, plus the arrival permutation.

use crate::bbox::Bbox;
use crate::ids::{LayerId, PolyId};
use crate::ops::{point_in_coords, Point};
use crate::Dbu;
use std::ops::Range;

/// Flat layout geometry, rows ordered by [`LayerId`] (`layer_start` is CSR,
/// `layer_count + 1` long). `ingest` must permute its provenance columns by the
/// permutation [`GeometryStoreBuilder::finish`] returns.
#[derive(Debug, Default)]
pub struct GeometryStore {
    verts_x: Vec<Dbu>,
    verts_y: Vec<Dbu>,

    poly_layer: Vec<LayerId>,
    poly_vert_start: Vec<u32>,
    poly_vert_len: Vec<u32>,
    poly_bbox: Vec<Bbox>,

    layer_start: Vec<u32>,
}

impl GeometryStore {
    pub fn poly_count(&self) -> usize {
        self.poly_layer.len()
    }

    pub fn layer_count(&self) -> usize {
        // A `Default` store has no offsets at all.
        self.layer_start.len().saturating_sub(1)
    }

    /// The polygons on one layer. Panics on a layer past the table, so "no such
    /// layer" never reads as "empty layer".
    pub fn polys_on_layer(&self, layer: LayerId) -> Range<u32> {
        self.layer_start[layer.idx()]..self.layer_start[layer.idx() + 1]
    }

    /// The coordinates of one polygon, as two parallel slices.
    pub fn poly_verts(&self, poly: PolyId) -> (&[Dbu], &[Dbu]) {
        let start = self.poly_vert_start[poly.idx()] as usize;
        let end = start + self.poly_vert_len[poly.idx()] as usize;
        (&self.verts_x[start..end], &self.verts_y[start..end])
    }

    pub fn poly_bbox(&self, poly: PolyId) -> Bbox {
        self.poly_bbox[poly.idx()]
    }

    pub fn poly_layer(&self, poly: PolyId) -> LayerId {
        self.poly_layer[poly.idx()]
    }

    pub fn layer_bboxes(&self, layer: LayerId) -> &[Bbox] {
        let rows = self.polys_on_layer(layer);
        &self.poly_bbox[rows.start as usize..rows.end as usize]
    }

    /// Whether a point lies inside one polygon, the boundary counting as inside
    /// (labels sit on corners and edges).
    pub fn poly_contains_point(&self, poly: PolyId, p: Point) -> bool {
        let (xs, ys) = self.poly_verts(poly);
        point_in_coords(xs, ys, p)
    }

    /// Append one whole layer's rings (`vert_start`/`vert_len` index `xs`/`ys`)
    /// to the tail. Asserts `layer` holds the last rows, or the rows would land in
    /// another layer's range.
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
        // A wrapped cursor would hand `poly_verts` another polygon's coordinates.
        base.checked_add(u32::try_from(xs.len()).expect("vertex count fits a u32"))
            .expect("total vertex count fits a u32");
        self.verts_x.extend_from_slice(xs);
        self.verts_y.extend_from_slice(ys);

        let rings = vert_start.len();
        self.poly_layer.resize(self.poly_layer.len() + rings, layer);
        for (&start, &len) in vert_start.iter().zip(vert_len) {
            let from = start as usize;
            let to = from + len as usize;
            self.poly_vert_start.push(base + start);
            self.poly_vert_len.push(len);
            self.poly_bbox
                .push(Bbox::of_points(&xs[from..to], &ys[from..to]));
        }

        // Every later layer was empty, so its offset moves by the same amount.
        let grown = u32::try_from(rings).expect("appended ring count fits a u32");
        for offset in &mut self.layer_start[layer.idx() + 1..] {
            *offset += grown;
        }
    }
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
        // Release assert: unequal columns would pair one polygon's X with the next's Y.
        assert_eq!(xs.len(), ys.len(), "coordinate columns disagree in length");

        let row = u32::try_from(self.poly_layer.len()).expect("polygon count fits a u32");
        let start = u32::try_from(self.verts_x.len()).expect("vertex count fits a u32");
        let len = u32::try_from(xs.len()).expect("polygon vertex count fits a u32");
        // The run's *end* must fit too, or `finish`'s u32 cursor wraps.
        start
            .checked_add(len)
            .expect("total vertex count fits a u32");

        self.verts_x.extend_from_slice(xs);
        self.verts_y.extend_from_slice(ys);
        self.poly_layer.push(layer);
        self.poly_vert_start.push(start);
        self.poly_vert_len.push(len);
        row
    }

    /// Append an axis-aligned rectangle (corner plus extents), wound CCW.
    pub fn push_rect(&mut self, layer: LayerId, x: Dbu, y: Dbu, w: Dbu, h: Dbu) -> u32 {
        let (x2, y2) = (x + w, y + h);
        self.push(layer, &[x, x2, x2, x], &[y, y, y2, y2])
    }

    /// Stable counting sort by layer, then bounding boxes.
    ///
    /// Returns `permutation[new_row] == old_row`. `layer_count` comes from the
    /// deck, so a layer with no shapes still gets an empty range; a polygon on a
    /// layer past it panics.
    pub fn finish(self, layer_count: usize) -> (GeometryStore, Vec<u32>) {
        let rows = self.poly_layer.len();

        // Histogram offset by one, then prefix-summed into CSR offsets in place.
        let mut layer_start = vec![0u32; layer_count + 1];
        for &layer in &self.poly_layer {
            layer_start[layer.idx() + 1] += 1;
        }
        for l in 0..layer_count {
            layer_start[l + 1] += layer_start[l];
        }

        // Arrivals in ascending order to per-layer cursors: stable.
        let mut cursor = layer_start[..layer_count].to_vec();
        let mut permutation = vec![0u32; rows];
        for (old, &layer) in (0u32..).zip(self.poly_layer.iter()) {
            let slot = &mut cursor[layer.idx()];
            permutation[*slot as usize] = old;
            *slot += 1;
        }

        let mut poly_layer = Vec::with_capacity(rows);
        let mut poly_vert_len = Vec::with_capacity(rows);
        for &old in &permutation {
            poly_layer.push(self.poly_layer[old as usize]);
            poly_vert_len.push(self.poly_vert_len[old as usize]);
        }

        // Coordinates are permuted too, so one layer's runs stay contiguous.
        let mut verts_x = Vec::with_capacity(self.verts_x.len());
        let mut verts_y = Vec::with_capacity(self.verts_y.len());
        let mut poly_vert_start = Vec::with_capacity(rows);
        let mut poly_bbox = Vec::with_capacity(rows);
        let mut at = 0u32;
        for (new, &old) in permutation.iter().enumerate() {
            let from = self.poly_vert_start[old as usize] as usize;
            let to = from + poly_vert_len[new] as usize;
            poly_vert_start.push(at);
            at += poly_vert_len[new];
            let (xs, ys) = (&self.verts_x[from..to], &self.verts_y[from..to]);
            poly_bbox.push(Bbox::of_points(xs, ys));
            verts_x.extend_from_slice(xs);
            verts_y.extend_from_slice(ys);
        }

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
