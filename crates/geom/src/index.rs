//! Spatial index and candidate-pair generation.
//!
//! Data in: one layer's bounding boxes from a [`GeometryStore`].
//! Data out: candidate `(PolyId, PolyId)` pairs within a distance, sorted and
//! deduplicated; a superset of the true pairs, never missing one.

use crate::bbox::Bbox;
use crate::ids::{LayerId, PolyId};
use crate::store::GeometryStore;
use crate::Dbu;

/// A two-level uniform grid over one layer's bounding boxes.
///
/// A box is filed under every cell it overlaps, and each level's cell is at
/// least as wide as its widest box, so a box spans at most 2x2 cells (`<= 4n`
/// filings) whatever the mix of scales.
#[derive(Debug, Default)]
pub struct SpatialIndex {
    layer: Option<LayerId>,
    /// Boxes no wider than the fine cell. Non-empty whenever the layer is.
    fine: Level,
    /// Boxes wider than the fine cell; empty when there are none.
    coarse: Level,
}

/// One level: a CSR bucket table over the subset of a layer that belongs to it.
#[derive(Debug, Default)]
struct Level {
    cell: i64,
    /// The union of the *layer's* boxes, so both levels share one origin.
    extent: Bbox,
    nx: u32,
    ny: u32,
    /// `bucket_start[b] .. bucket_start[b + 1]` indexes `rows`.
    bucket_start: Vec<u32>,
    /// Store row ids, grouped by bucket, ascending inside each bucket.
    rows: Vec<u32>,
}

/// The longer side of a box; decides which level holds it.
fn box_extent(b: Bbox) -> i64 {
    (b.xhi.raw() - b.xlo.raw()).max(b.yhi.raw() - b.ylo.raw())
}

/// Cells along one axis, given the axis's inclusive unit count.
fn axis_cells(span: i64, cell: i64) -> u32 {
    let cells = (span + cell - 1) / cell;
    // Release check: `nx` is the bucket stride, a wrap would misfile rows.
    u32::try_from(cells).expect("more grid cells on one axis than a u32 holds")
}

/// The cell indices a coordinate range touches, clamped to the grid (cells past
/// the edge hold nothing, so folding them onto the border loses no row).
fn cell_span(lo: i64, hi: i64, origin: i64, cell: i64, cells: u32) -> (u32, u32) {
    let last = i64::from(cells - 1);
    let first_cell = ((lo - origin).max(0) / cell).min(last);
    let final_cell = ((hi - origin).max(0) / cell).min(last);
    (
        u32::try_from(first_cell).expect("the clamp bounds this by `cells - 1`"),
        u32::try_from(final_cell).expect("the clamp bounds this by `cells - 1`"),
    )
}

impl SpatialIndex {
    /// Build over one layer into `out` (cleared and refilled). Each row goes to
    /// exactly one level, dispatched on box extent.
    pub fn build_into(store: &GeometryStore, layer: LayerId, out: &mut Self) {
        let bboxes = store.layer_bboxes(layer);
        let rows = store.polys_on_layer(layer);

        out.layer = Some(layer);
        out.fine.clear();
        out.coarse.clear();

        let n = bboxes.len();
        if n == 0 {
            return;
        }

        let mut extent = Bbox::EMPTY;
        for &b in bboxes {
            extent = Bbox::union(extent, b);
        }
        let span_x = extent.xhi.raw() - extent.xlo.raw() + 1;
        let span_y = extent.yhi.raw() - extent.ylo.raw() + 1;

        // The median extent, widened until the bucket table is O(rows) whatever
        // the aspect ratio.
        let mut extents: Vec<i64> = bboxes.iter().map(|&b| box_extent(b)).collect();
        let widest = extents.iter().copied().fold(0i64, i64::max);

        let mid = n / 2;
        extents.select_nth_unstable(mid);
        let rows_i64 = i64::try_from(n).expect("a layer's row count fits an i64");
        let side = (4 * rows_i64 + 64).isqrt().max(1);
        let fine_cell = extents[mid]
            .max(1)
            .max((span_x + side - 1) / side)
            .max((span_y + side - 1) / side);

        out.fine
            .build_into(bboxes, rows.start, extent, fine_cell, 0);
        if widest > fine_cell {
            out.coarse
                .build_into(bboxes, rows.start, extent, widest, fine_cell + 1);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.fine.rows.is_empty() && self.coarse.rows.is_empty()
    }
}

impl Level {
    /// Back to the `default()` state, keeping the allocations.
    fn clear(&mut self) {
        self.cell = 1;
        self.extent = Bbox::EMPTY;
        self.nx = 0;
        self.ny = 0;
        self.bucket_start.clear();
        self.rows.clear();
    }

    /// The inclusive cell rectangle `(c0, c1, r0, r1)` `b` occupies, or `None`
    /// when its extent is outside `min_ext ..= cell` (the other level's).
    fn footprint(&self, b: Bbox, min_ext: i64) -> Option<(u32, u32, u32, u32)> {
        let ext = box_extent(b);
        if ext < min_ext || ext > self.cell {
            return None;
        }
        let (ox, oy) = (self.extent.xlo.raw(), self.extent.ylo.raw());
        let (c0, c1) = cell_span(b.xlo.raw(), b.xhi.raw(), ox, self.cell, self.nx);
        let (r0, r1) = cell_span(b.ylo.raw(), b.yhi.raw(), oy, self.cell, self.ny);
        Some((c0, c1, r0, r1))
    }

    /// File every box whose extent lies in `min_ext ..= cell` under every cell it
    /// overlaps, as a CSR bucket table over `extent`.
    fn build_into(
        &mut self,
        bboxes: &[Bbox],
        first_row: u32,
        extent: Bbox,
        cell: i64,
        min_ext: i64,
    ) {
        self.clear();
        self.cell = cell;
        self.extent = extent;
        self.nx = axis_cells(extent.xhi.raw() - extent.xlo.raw() + 1, cell);
        self.ny = axis_cells(extent.yhi.raw() - extent.ylo.raw() + 1, cell);
        let nx = self.nx as usize;
        let buckets = nx * self.ny as usize;
        let mut bucket_start = std::mem::take(&mut self.bucket_start);
        bucket_start.resize(buckets + 1, 0);

        let mut members = 0usize;
        for &b in bboxes {
            let Some((c0, c1, r0, r1)) = self.footprint(b, min_ext) else {
                continue;
            };
            members += 1;
            for r in r0..=r1 {
                for c in c0..=c1 {
                    bucket_start[r as usize * nx + c as usize + 1] += 1;
                }
            }
        }

        // No members: an absence, not an empty grid.
        if members == 0 {
            self.clear();
            return;
        }

        for b in 1..=buckets {
            bucket_start[b] += bucket_start[b - 1];
        }
        let mut rows = std::mem::take(&mut self.rows);
        rows.resize(bucket_start[buckets] as usize, 0);

        // `bucket_start[b]` doubles as bucket `b`'s write cursor. Rows are filed
        // ascending, which `gather_level`'s `b > a` binary search relies on.
        for (poly, &b) in (first_row..).zip(bboxes) {
            let Some((c0, c1, r0, r1)) = self.footprint(b, min_ext) else {
                continue;
            };
            for r in r0..=r1 {
                for c in c0..=c1 {
                    let bucket = r as usize * nx + c as usize;
                    let w = bucket_start[bucket];
                    rows[w as usize] = poly;
                    bucket_start[bucket] = w + 1;
                }
            }
        }

        // Each cursor now holds its bucket's end: shift right to restore offsets.
        bucket_start.copy_within(0..buckets, 1);
        bucket_start[0] = 0;
        self.bucket_start = bucket_start;
        self.rows = rows;
    }

    /// The region one bucket covers, clipped to the extent.
    fn cell_bbox(&self, col: u32, row: u32) -> Bbox {
        let x = self.extent.xlo.raw() + i64::from(col) * self.cell;
        let y = self.extent.ylo.raw() + i64::from(row) * self.cell;
        Bbox {
            xlo: Dbu::new_unchecked(x),
            ylo: Dbu::new_unchecked(y),
            xhi: Dbu::new_unchecked((x + self.cell - 1).min(self.extent.xhi.raw())),
            yhi: Dbu::new_unchecked((y + self.cell - 1).min(self.extent.yhi.raw())),
        }
    }
}

/// Panics on an index never built: an empty pair list would read as a check
/// that ran and found nothing.
fn built(index: &SpatialIndex) -> LayerId {
    index.layer.expect(
        "an index that was never built cannot answer a query: an empty pair \
         list would read as a check that ran and found nothing",
    )
}

/// Every pair of polygons on one layer whose boxes are within `distance`, with
/// `a < b`, ascending and deduplicated.
pub fn candidate_pairs_into(
    store: &GeometryStore,
    index: &SpatialIndex,
    distance: Dbu,
    out: &mut Vec<(PolyId, PolyId)>,
) {
    out.clear();
    let layer = built(index);
    if index.is_empty() {
        return;
    }
    prune_pairs::<true>(store, index, layer, distance, out);
}

/// Every pair between two *different* layers within `distance`, `a` from `a_index`.
pub fn cross_layer_pairs_into(
    store: &GeometryStore,
    a_index: &SpatialIndex,
    b_index: &SpatialIndex,
    distance: Dbu,
    out: &mut Vec<(PolyId, PolyId)>,
) {
    out.clear();
    let a_layer = built(a_index);
    built(b_index);
    if a_index.is_empty() || b_index.is_empty() {
        return;
    }
    prune_pairs::<false>(store, b_index, a_layer, distance, out);
}

/// Gather every row `index` can reach from each row of `layer`, keep the pairs
/// whose boxes are `within` distance, then sort and dedup. `SAME` means `index`
/// holds `layer` itself, so only `a < b` is emitted. Filtering before the sort is
/// the fast order: the gathered superset is ~100x what survives.
fn prune_pairs<const SAME: bool>(
    store: &GeometryStore,
    index: &SpatialIndex,
    layer: LayerId,
    distance: Dbu,
    out: &mut Vec<(PolyId, PolyId)>,
) {
    out.clear();
    for row in store.polys_on_layer(layer) {
        let a = PolyId(row);
        let a_box = store.poly_bbox(a);
        // A row lives in exactly one level, so the two gathers never overlap.
        gather_level::<SAME>(&index.fine, distance, a, a_box, out);
        gather_level::<SAME>(&index.coarse, distance, a, a_box, out);
    }
    out.retain(|&(a, b)| store.poly_bbox(a).within(store.poly_bbox(b), distance));
    // A box filed under several cells is gathered several times.
    out.sort_unstable();
    out.dedup();
}

/// Every row of one level that `a_box` grown by `distance` can reach, appended
/// paired with `a`.
fn gather_level<const SAME: bool>(
    grid: &Level,
    distance: Dbu,
    a: PolyId,
    a_box: Bbox,
    out: &mut Vec<(PolyId, PolyId)>,
) {
    if grid.rows.is_empty() {
        return;
    }

    let cell = grid.cell;
    let (ox, oy) = (grid.extent.xlo.raw(), grid.extent.ylo.raw());
    // Whole cells with `pad > distance`: rounds up (fail closed); the bucket
    // test below takes the slop back out.
    let pad = (distance.raw() / cell + 1) * cell;
    let (c0, c1) = cell_span(
        a_box.xlo.raw() - pad,
        a_box.xhi.raw() + pad,
        ox,
        cell,
        grid.nx,
    );
    let (r0, r1) = cell_span(
        a_box.ylo.raw() - pad,
        a_box.yhi.raw() + pad,
        oy,
        cell,
        grid.ny,
    );

    for r in r0..=r1 {
        let base = r as usize * grid.nx as usize;
        for c in c0..=c1 {
            if !grid.cell_bbox(c, r).within(a_box, distance) {
                continue;
            }
            let bucket = base + c as usize;
            let seg = &grid.rows
                [grid.bucket_start[bucket] as usize..grid.bucket_start[bucket + 1] as usize];
            // Ascending rows: `b > a` is a suffix, which also drops the self-pair.
            let from = if SAME {
                seg.partition_point(|&row| row <= a.0)
            } else {
                0
            };
            out.extend(seg[from..].iter().map(|&row| (a, PolyId(row))));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{candidate_pairs_into, cross_layer_pairs_into, SpatialIndex};
    use crate::ids::{LayerId, PolyId};
    use crate::store::{GeometryStore, GeometryStoreBuilder};
    use crate::Dbu;

    const A: LayerId = LayerId(0);
    const B: LayerId = LayerId(1);

    fn hash(mut value: u64) -> u64 {
        value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    /// Two sizes of square jittered over a lattice of 400-unit cells, two
    /// interleaved layers.
    fn corpus(seed: u64, cells: u64) -> GeometryStore {
        let mut builder = GeometryStoreBuilder::default();
        for (layer, (ox, oy)) in [(A, (0i64, 0i64)), (B, (170, 90))] {
            for row in 0..cells {
                for col in 0..cells {
                    let draw = hash(seed ^ (row << 20) ^ col);
                    if draw & 1 == 0 {
                        continue;
                    }
                    let side: u64 = if draw & 2 == 0 { 80 } else { 200 };
                    let room = 400 - side;
                    let x = ox + i64::try_from(col * 400 + (draw >> 8) % room).unwrap();
                    let y = oy + i64::try_from(row * 400 + (draw >> 30) % room).unwrap();
                    let s = i64::try_from(side).unwrap();
                    let xs = [x, x + s, x + s, x].map(Dbu::new_unchecked);
                    let ys = [y, y, y + s, y + s].map(Dbu::new_unchecked);
                    builder.push(layer, &xs, &ys);
                }
            }
        }
        builder.finish(2).0
    }

    fn indexed(store: &GeometryStore, layer: LayerId) -> SpatialIndex {
        let mut index = SpatialIndex::default();
        SpatialIndex::build_into(store, layer, &mut index);
        index
    }

    /// Oracle: the O(n^2) scan of the exact box predicate, same layer.
    #[test]
    fn same_layer_pairs_equal_the_all_pairs_scan() {
        let store = corpus(92, 12);
        let index = indexed(&store, A);
        let rows: Vec<u32> = store.polys_on_layer(A).collect();
        let mut out = Vec::new();
        for distance in [0i64, 25, 250, 2_000] {
            let d = Dbu::new_unchecked(distance);
            candidate_pairs_into(&store, &index, d, &mut out);
            let mut want = Vec::new();
            for (i, &a) in rows.iter().enumerate() {
                for &b in &rows[i + 1..] {
                    let (a, b) = (PolyId(a), PolyId(b));
                    if store.poly_bbox(a).within(store.poly_bbox(b), d) {
                        want.push((a, b));
                    }
                }
            }
            assert_eq!(out, want, "at a distance of {distance}");
        }
    }

    /// Oracle: the O(n^2) scan of the exact box predicate, cross layer.
    #[test]
    fn cross_layer_pairs_equal_the_all_pairs_scan() {
        let store = corpus(93, 10);
        let (a_index, b_index) = (indexed(&store, A), indexed(&store, B));
        let mut out = Vec::new();
        for distance in [0i64, 30, 400] {
            let d = Dbu::new_unchecked(distance);
            cross_layer_pairs_into(&store, &a_index, &b_index, d, &mut out);
            let mut want = Vec::new();
            for a in store.polys_on_layer(A) {
                for b in store.polys_on_layer(B) {
                    let (a, b) = (PolyId(a), PolyId(b));
                    if store.poly_bbox(a).within(store.poly_bbox(b), d) {
                        want.push((a, b));
                    }
                }
            }
            assert!(!want.is_empty());
            assert_eq!(out, want, "at a distance of {distance}");
        }
    }
}
