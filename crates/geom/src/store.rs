//! The one place a polygon lives.
//!
//! Data in: rings as `(LayerId, xs, ys)` in arrival order, via [`GeometryStoreBuilder::push`].
//! Data out: [`GeometryStore`], one column per field, rows grouped by layer, plus the arrival permutation.

use crate::bbox::Bbox;
use crate::ids::{LayerId, PolyId};
use crate::ops::{point_in_coords, Point, Seg};
use crate::Dbu;
use std::ops::Range;

/// Flat layout geometry: one row per ring, columns per field, rows grouped by
/// [`LayerId`] so a layer is one contiguous range ([`Self::polys_on_layer`]).
///
/// A row is one stored ring, not yet a polygon: a hole is its own clockwise
/// row on the same layer, bound to its outer only by
/// [`crate::view::validate_layer_into`]. Edge layers hold directed segments
/// instead ([`Self::edges_on_layer`]). Rows are immutable once stored; layers
/// are only ever appended, so a [`PolyId`] stays valid for the store's life.
///
/// `ingest` must permute its provenance columns by the permutation
/// [`GeometryStoreBuilder::finish`] returns.
#[derive(Debug, Default)]
pub struct GeometryStore {
    verts_x: Vec<Dbu>,
    verts_y: Vec<Dbu>,

    poly_layer: Vec<LayerId>,
    poly_vert_start: Vec<u32>,
    poly_vert_len: Vec<u32>,
    poly_bbox: Vec<Bbox>,

    layer_start: Vec<u32>,

    /// Edge layers' segments, directed with the material on the left of travel,
    /// grouped by layer; `edge_layer_start` is CSR like `layer_start`.
    edges: Vec<Seg>,
    edge_layer_start: Vec<u32>,

    /// Derived layers that could not be computed, ascending; each is empty.
    uncomputed: Vec<LayerId>,
}

impl GeometryStore {
    /// Returns the number of polygon rows, over every layer.
    pub fn poly_count(&self) -> usize {
        self.poly_layer.len()
    }

    /// Returns the number of layers the store was built for, empty ones
    /// included: the `layer_count` given to [`GeometryStoreBuilder::finish`].
    pub fn layer_count(&self) -> usize {
        // A `Default` store has no offsets at all.
        self.layer_start.len().saturating_sub(1)
    }

    /// Returns the rows of one layer's polygons, as a range of [`PolyId`] values.
    ///
    /// # Panics
    ///
    /// On a layer past [`Self::layer_count`], so "no such layer" never reads
    /// as "empty layer".
    pub fn polys_on_layer(&self, layer: LayerId) -> Range<u32> {
        self.layer_start[layer.idx()]..self.layer_start[layer.idx() + 1]
    }

    /// Returns one polygon's ring as parallel x and y slices, open: the last
    /// vertex joins the first and is not repeated.
    ///
    /// # Panics
    ///
    /// On a row past [`Self::poly_count`].
    pub fn poly_verts(&self, poly: PolyId) -> (&[Dbu], &[Dbu]) {
        let start = self.poly_vert_start[poly.idx()] as usize;
        let end = start + self.poly_vert_len[poly.idx()] as usize;
        (&self.verts_x[start..end], &self.verts_y[start..end])
    }

    /// Returns one polygon's bounding box. Panics on a row past [`Self::poly_count`].
    pub fn poly_bbox(&self, poly: PolyId) -> Bbox {
        self.poly_bbox[poly.idx()]
    }

    /// Returns the layer a polygon row is on. Panics on a row past [`Self::poly_count`].
    pub fn poly_layer(&self, poly: PolyId) -> LayerId {
        self.poly_layer[poly.idx()]
    }

    /// Returns the bounding boxes of one layer's polygons, in row order:
    /// element `i` belongs to row `polys_on_layer(layer).start + i`.
    ///
    /// # Panics
    ///
    /// On a layer past [`Self::layer_count`].
    pub fn layer_bboxes(&self, layer: LayerId) -> &[Bbox] {
        let rows = self.polys_on_layer(layer);
        &self.poly_bbox[rows.start as usize..rows.end as usize]
    }

    /// Whether a point lies inside one polygon's ring, the boundary counting as
    /// inside (labels sit on corners and edges). Reads the one ring only: a point
    /// in a hole is inside its outer row.
    pub fn poly_contains_point(&self, poly: PolyId, p: Point) -> bool {
        let (xs, ys) = self.poly_verts(poly);
        point_in_coords(xs, ys, p)
    }

    /// Marks a derived layer that could not be computed (an operand it cannot
    /// read, a coordinate past the domain). It stays empty, and validating it
    /// is [`crate::view::ValidityError::Uncomputed`], so every rule that reads
    /// it refuses and nothing else is touched.
    pub fn mark_uncomputed(&mut self, layer: LayerId) {
        if let Err(at) = self.uncomputed.binary_search(&layer) {
            self.uncomputed.insert(at, layer);
        }
    }

    /// Whether [`Self::mark_uncomputed`] marked `layer`.
    pub fn is_uncomputed(&self, layer: LayerId) -> bool {
        self.uncomputed.binary_search(&layer).is_ok()
    }

    /// Returns the segments of one edge layer, each directed with the material
    /// on its left; empty on a polygon layer.
    ///
    /// # Panics
    ///
    /// On a layer past [`Self::layer_count`].
    pub fn edges_on_layer(&self, layer: LayerId) -> &[Seg] {
        let (lo, hi) = (
            self.edge_layer_start[layer.idx()],
            self.edge_layer_start[layer.idx() + 1],
        );
        &self.edges[lo as usize..hi as usize]
    }

    /// Appends one whole edge layer's segments, as [`Self::append_layer`] does
    /// rings.
    ///
    /// # Panics
    ///
    /// When `layer` is past [`Self::layer_count`], when a later layer already
    /// holds segments, or past `u32::MAX` segments in total.
    pub fn append_edges(&mut self, layer: LayerId, edges: &[Seg]) {
        assert!(layer.idx() < self.layer_count(), "layer id past the table");
        assert_eq!(
            self.edge_layer_start[layer.idx()] as usize,
            self.edges.len(),
            "a layer with edges after it cannot be appended to without moving them"
        );
        self.edges.extend_from_slice(edges);
        let grown = u32::try_from(edges.len()).expect("edge count fits a u32");
        for offset in &mut self.edge_layer_start[layer.idx() + 1..] {
            *offset += grown;
        }
    }

    /// Appends one whole layer's rings to the end of the store: ring `i` is
    /// `xs[vert_start[i]..][..vert_len[i]]` and the same run of `ys`. This is how
    /// derived layers are added, in ascending id order, after
    /// [`GeometryStoreBuilder::finish`]. The rings are stored as given, not
    /// validated.
    ///
    /// # Panics
    ///
    /// When the column lengths disagree, when a ring's run
    /// `vert_start[i]..vert_start[i] + vert_len[i]` reaches past `xs`, when
    /// `layer` is past [`Self::layer_count`], when any later layer already
    /// holds rows (they would land in another layer's range), or past
    /// `u32::MAX` vertices in total.
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
            assert!(
                to <= xs.len(),
                "an appended ring's vertex run {from}..{to} lies inside the {} vertices given",
                xs.len()
            );
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

/// Accumulates rings in arrival order, then sorts them by layer into a
/// [`GeometryStore`].
#[derive(Debug, Default)]
pub struct GeometryStoreBuilder {
    verts_x: Vec<Dbu>,
    verts_y: Vec<Dbu>,
    poly_layer: Vec<LayerId>,
    poly_vert_start: Vec<u32>,
    poly_vert_len: Vec<u32>,
}

impl GeometryStoreBuilder {
    /// Returns an empty builder with room for `polys` rings of `verts` vertices
    /// in total, so a reader that knows its counts allocates once.
    pub fn with_capacity(polys: usize, verts: usize) -> Self {
        Self {
            verts_x: Vec::with_capacity(verts),
            verts_y: Vec::with_capacity(verts),
            poly_layer: Vec::with_capacity(polys),
            poly_vert_start: Vec::with_capacity(polys),
            poly_vert_len: Vec::with_capacity(polys),
        }
    }

    /// Appends one ring, open (no repeated closing vertex), returning its
    /// arrival row: the value [`Self::finish`]'s permutation maps back to.
    /// Counter-clockwise is an outer boundary and clockwise a hole; nothing is
    /// checked until [`crate::view::validate_layer_into`].
    ///
    /// # Panics
    ///
    /// When `xs` and `ys` differ in length, or past `u32::MAX` rings or
    /// vertices in total.
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

    /// Sorts the rings by layer, stably, and computes their bounding boxes.
    /// `O(rings + vertices + layer_count)`.
    ///
    /// Returns the store and `permutation`, with `permutation[new_row] ==
    /// old_row`: a reader keeping per-ring columns of its own permutes them by it.
    /// `layer_count` comes from the deck, so a layer with no shapes still gets an
    /// empty range, and derived layers can be appended later.
    ///
    /// # Panics
    ///
    /// When a ring was pushed on a layer `>= layer_count`.
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

        // CSR: the layer offsets end at the row count, and the vertex runs
        // tile the columns end to end.
        debug_assert_eq!(
            layer_start[layer_count] as usize, rows,
            "the last layer offset is the row count"
        );
        debug_assert_eq!(
            at as usize,
            verts_x.len(),
            "the permuted vertex runs cover every vertex once"
        );

        let store = GeometryStore {
            verts_x,
            verts_y,
            poly_layer,
            poly_vert_start,
            poly_vert_len,
            poly_bbox,
            layer_start,
            edges: Vec::new(),
            edge_layer_start: vec![0; layer_count + 1],
            uncomputed: Vec::new(),
        };
        (store, permutation)
    }
}
