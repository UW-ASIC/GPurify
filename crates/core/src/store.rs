//! The one place a polygon lives.

use crate::bbox::Bbox;
use crate::ids::{LayerId, PolyId};
use gpurify_units::Dbu;
use std::ops::Range;

/// Flat layout geometry, grouped by layer.
///
/// **Five questions.** In: coordinate runs from `ingest`. Out: the same,
/// sorted. How many: one store per run, tens of millions of vertices.
/// Access pattern: a rule reads one layer's coordinates and bounding boxes and
/// nothing else — so coordinates are two separate columns (a spacing scan
/// touches `verts_x` alone when pruning on X), and polygons are **stored
/// contiguously per layer**. Lifetime: the whole run, built once, never
/// mutated. Parallelisable: every consumer partitions by polygon range.
///
/// # Layer grouping
///
/// Rows are ordered by [`LayerId`], and `layer_start` is a CSR-style offset
/// array of length `layer_count + 1`. So [`GeometryStore::polys_on_layer`] is a
/// range, not a lookup, and one layer's polygons are contiguous in every
/// column. The old implementation kept a `Vec<Vec<u32>>` bucket per layer for
/// this; a sort at build time replaces it with arithmetic.
///
/// The cost is that [`PolyId`] order is not insertion order. `ingest` must
/// permute its provenance columns by the same permutation
/// [`GeometryStoreBuilder::finish`] returns — that is the invariant holding the
/// two tables together, and it has no compiler behind it.
#[derive(Debug, Default)]
pub struct GeometryStore {
    /// Vertex X, indexed by [`crate::VertId`]. Separate columns because
    /// proximity pruning reads one axis at a time.
    verts_x: Vec<Dbu>,
    verts_y: Vec<Dbu>,

    poly_layer: Vec<LayerId>,
    /// First vertex of each polygon, into `verts_x` / `verts_y`.
    poly_vert_start: Vec<u32>,
    poly_vert_len: Vec<u32>,
    /// Precomputed per polygon: every consumer needs it, and recomputing it in
    /// a pairwise scan is the O(n²)-with-a-large-constant mistake.
    poly_bbox: Vec<Bbox>,

    /// `layer_start[l] .. layer_start[l + 1]` are the rows on layer `l`.
    layer_start: Vec<u32>,
}

impl GeometryStore {
    pub fn poly_count(&self) -> usize {
        todo!()
    }

    pub fn layer_count(&self) -> usize {
        todo!()
    }

    /// The polygons on one layer, as a contiguous row range.
    ///
    /// O(1). Empty for a layer with no geometry, which is the common case for
    /// most of a PDK's layer table and must not be an error.
    pub fn polys_on_layer(&self, layer: LayerId) -> Range<u32> {
        todo!()
    }

    /// The coordinates of one polygon, as two parallel slices.
    ///
    /// Returned as slices rather than an iterator of points so a caller can
    /// hand them straight to a vectorised reduction.
    pub fn poly_verts(&self, poly: PolyId) -> (&[Dbu], &[Dbu]) {
        todo!()
    }

    pub fn poly_bbox(&self, poly: PolyId) -> Bbox {
        todo!()
    }

    pub fn poly_layer(&self, poly: PolyId) -> LayerId {
        todo!()
    }

    /// The bounding-box column for one layer.
    ///
    /// The slice a pairwise prune actually scans — handing out the whole column
    /// and a range would make every caller re-derive the offset.
    pub fn layer_bboxes(&self, layer: LayerId) -> &[Bbox] {
        todo!()
    }
}

/// Accumulates polygons in arrival order, then sorts them by layer.
///
/// Separate from [`GeometryStore`] because the store's layer-contiguity
/// invariant cannot hold during construction: a GDS reader emits polygons in
/// stream order, interleaved across layers. Making that a distinct type means
/// the invariant is true of every `GeometryStore` that exists, rather than true
/// after someone remembers to call `sort`.
#[derive(Debug, Default)]
pub struct GeometryStoreBuilder {
    verts_x: Vec<Dbu>,
    verts_y: Vec<Dbu>,
    poly_layer: Vec<LayerId>,
    poly_vert_start: Vec<u32>,
    poly_vert_len: Vec<u32>,
}

impl GeometryStoreBuilder {
    /// Pre-size for a known polygon and vertex count. `ingest` can estimate
    /// both from a GDS record count before parsing bodies.
    pub fn with_capacity(polys: usize, verts: usize) -> Self {
        todo!()
    }

    /// Append one polygon. Coordinates are copied into the flat columns; the
    /// caller's buffer is reusable immediately.
    ///
    /// Returns the pre-sort row index, which is what `ingest` records against
    /// its provenance columns so the permutation can be applied later.
    pub fn push(&mut self, layer: LayerId, xs: &[Dbu], ys: &[Dbu]) -> u32 {
        todo!()
    }

    /// Sort by layer, compute bounding boxes, and produce the store.
    ///
    /// **Transform, A-to-B.** Returns the permutation alongside the store:
    /// `permutation[new_row] == old_row`. `ingest` must apply it to every
    /// provenance column, or the two tables desynchronise and a violation is
    /// reported against the wrong cell.
    ///
    /// `layer_count` comes from the deck, not from the geometry: a layer with
    /// no shapes still needs a (empty) range, because a rule referencing it
    /// must return "no violations", not "no such layer".
    pub fn finish(self, layer_count: usize) -> (GeometryStore, Vec<u32>) {
        todo!()
    }
}
