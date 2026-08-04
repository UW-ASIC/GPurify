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
        self.poly_layer.len()
    }

    pub fn layer_count(&self) -> usize {
        // `saturating_sub`, not `- 1`: a `Default` store has no offsets at all,
        // and zero layers is the honest answer for it.
        self.layer_start.len().saturating_sub(1)
    }

    /// The polygons on one layer, as a contiguous row range.
    ///
    /// O(1). Empty for a layer with no geometry, which is the common case for
    /// most of a PDK's layer table and must not be an error.
    pub fn polys_on_layer(&self, layer: LayerId) -> Range<u32> {
        // Fail closed: a layer beyond the deck's table indexes out of bounds and
        // panics in every profile. Returning an empty range for it would make
        // "this layer holds nothing" and "this layer does not exist"
        // indistinguishable, and the second one must never read as clean.
        self.layer_start[layer.idx()]..self.layer_start[layer.idx() + 1]
    }

    /// The coordinates of one polygon, as two parallel slices.
    ///
    /// Returned as slices rather than an iterator of points so a caller can
    /// hand them straight to a vectorised reduction.
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
    ///
    /// The slice a pairwise prune actually scans — handing out the whole column
    /// and a range would make every caller re-derive the offset.
    pub fn layer_bboxes(&self, layer: LayerId) -> &[Bbox] {
        let rows = self.polys_on_layer(layer);
        &self.poly_bbox[rows.start as usize..rows.end as usize]
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
        Self {
            verts_x: Vec::with_capacity(verts),
            verts_y: Vec::with_capacity(verts),
            poly_layer: Vec::with_capacity(polys),
            poly_vert_start: Vec::with_capacity(polys),
            poly_vert_len: Vec::with_capacity(polys),
        }
    }

    /// Append one polygon. Coordinates are copied into the flat columns; the
    /// caller's buffer is reusable immediately.
    ///
    /// Returns the pre-sort row index, which is what `ingest` records against
    /// its provenance columns so the permutation can be applied later.
    pub fn push(&mut self, layer: LayerId, xs: &[Dbu], ys: &[Dbu]) -> u32 {
        // Every profile, not `debug_assert`: unequal columns would store one
        // polygon's X against the next one's Y and every geometric assertion
        // downstream would still pass. One compare amortised over a memcpy.
        assert_eq!(xs.len(), ys.len(), "coordinate columns disagree in length");
        debug_assert!(
            {
                // A strict left fold, `&` rather than `&&`: no data-dependent
                // branch, and short-circuiting an in-range check that is
                // overwhelmingly all-true would only cost a mispredict. The
                // columns were asserted equal length one line above, in every
                // profile, so `zip` cannot silently truncate the longer one.
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
        // The *end* of the run, not just its start. `start` alone is checked
        // before the extend, so without this the columns can finish one polygon
        // past `u32::MAX`, and `finish`'s vertex cursor — a `u32` — wraps
        // silently in release. A wrapped cursor hands `poly_verts` a run that
        // indexes some other polygon's coordinates: geometry that is wrong but
        // entirely plausible, checked clean, with no error anywhere. Fail closed
        // at the boundary the vertices enter through.
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
    /// **Transform, A-to-B.** Returns the permutation alongside the store:
    /// `permutation[new_row] == old_row`. `ingest` must apply it to every
    /// provenance column, or the two tables desynchronise and a violation is
    /// reported against the wrong cell.
    ///
    /// **The sort is stable.** Rows on one layer keep the order they were
    /// pushed in, so `permutation` restricted to any layer's range is strictly
    /// ascending. Stability is promised rather than left open because a
    /// construct-from-answer test names a shape by the position it was pushed
    /// at, and because a GDS reader's stream order is the only order a human
    /// reading a report can reconstruct.
    ///
    /// `layer_count` comes from the deck, not from the geometry: a layer with
    /// no shapes still needs a (empty) range, because a rule referencing it
    /// must return "no violations", not "no such layer".
    pub fn finish(self, layer_count: usize) -> (GeometryStore, Vec<u32>) {
        let rows = self.poly_layer.len();
        debug_assert_eq!(self.poly_vert_start.len(), rows);
        debug_assert_eq!(self.poly_vert_len.len(), rows);
        debug_assert_eq!(self.verts_x.len(), self.verts_y.len());
        debug_assert!(layer_count <= usize::from(u16::MAX) + 1, "no such LayerId");

        // Counting sort by layer. Pass one is the histogram, offset by one so
        // pass two turns it into the CSR offsets in place.
        //
        // All three passes are scalar because of what a counting sort is, not
        // to save effort. Passes one and three scatter: the destination index
        // is `layer.idx()`, read from the row, so two lanes of one vector can
        // target the same slot and the write is only correct with conflict
        // detection the stable ordering would then have to be re-imposed on
        // anyway. Pass two is a prefix scan — row `l + 1` reads what row `l`
        // wrote — which is a loop-carried chain, and it runs over `LayerId`
        // space, tens of entries for a real deck and 65_536 at the `u16`
        // ceiling: once per run, below any threshold where a scan rework pays.
        // That is the `/simd-loops` triage answer for each, and it is the
        // complete one.
        let mut layer_start = vec![0u32; layer_count + 1];
        for &layer in &self.poly_layer {
            // Fail closed: a polygon on a layer the deck never declared indexes
            // out of bounds and panics, in every profile. Silently dropping it
            // is a clean report for geometry nobody checked.
            layer_start[layer.idx() + 1] += 1;
        }
        for l in 0..layer_count {
            layer_start[l + 1] += layer_start[l];
        }

        // Pass three walks arrivals in ascending order and appends each to its
        // layer's cursor, which is what makes the sort stable: within a layer,
        // `permutation` comes out strictly ascending.
        let mut cursor = layer_start[..layer_count].to_vec();
        let mut permutation = vec![0u32; rows];
        // The row index counts in `u32` rather than `usize` because `push`
        // already refused a row that would not fit one.
        for (old, &layer) in (0u32..).zip(self.poly_layer.iter()) {
            let slot = &mut cursor[layer.idx()];
            permutation[*slot as usize] = old;
            *slot += 1;
        }
        debug_assert_eq!(cursor.as_slice(), &layer_start[1..], "sort lost a row");

        // Two gathers driven by the same permutation, fused into one pass: both
        // read `permutation[new]` and each output row is a function of its own
        // input row, so the two loops share a trip count and a cache line's
        // worth of source. `permutation` is `vec![0u32; rows]`, so `rows` is the
        // trip count for both columns and the two cannot come out ragged.
        debug_assert_eq!(permutation.len(), rows);
        let mut poly_layer = Vec::with_capacity(rows);
        let mut poly_vert_len = Vec::with_capacity(rows);
        for &old in &permutation {
            poly_layer.push(self.poly_layer[old as usize]);
            poly_vert_len.push(self.poly_vert_len[old as usize]);
        }
        debug_assert_eq!(poly_layer.len(), rows, "a gather lost a row");
        debug_assert_eq!(poly_vert_len.len(), rows, "a gather lost a row");

        // Coordinates are permuted too, not just the offsets: the access
        // pattern in the type's doc comment is one layer's coordinate runs read
        // end to end, and leaving the runs in arrival order would scatter them.
        let mut verts_x = Vec::with_capacity(self.verts_x.len());
        let mut verts_y = Vec::with_capacity(self.verts_y.len());
        let mut poly_vert_start = Vec::with_capacity(rows);
        // `at` cannot wrap: `push` refuses a polygon whose run would end past
        // `u32::MAX`, so the total it accumulates to is a count `push` already
        // admitted.
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
