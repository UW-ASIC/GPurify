//! Spatial index and candidate-pair generation.
//!
//! This is the module that stops every pairwise rule being O(n²), and it is the
//! module whose mistakes are invisible. It carries a test adapter for that
//! reason — see [`crate::observe`] for why "cheap" is not the standard.

use crate::bbox::Bbox;
use crate::ids::{LayerId, PolyId};
use crate::observe::{NoObserve, Observer};
use crate::store::GeometryStore;
use gpurify_units::{Dbu, MAX_ABS_DBU};

/// A two-level uniform grid over one layer's bounding boxes.
///
/// **Five questions.** In: a bounding-box column. Out: bucket offsets and a
/// row-id list, one pair per level. How many: one per layer per run. Access
/// pattern: built once, scanned many times, always in bucket order — so it is
/// CSR, not a map of vectors. Lifetime: phase; cleared and rebuilt per layer
/// from one reusable allocation. Parallelisable: bucket counting is a
/// histogram, and the scan over buckets partitions cleanly.
///
/// A grid rather than a tree because layout geometry is close to uniformly
/// dense at the scale that matters, and a grid's build is a counting sort with
/// no pointer chasing.
///
/// **Two levels rather than one.** A box is filed under every cell it overlaps,
/// so a single grid sized to the median box files one reticle-sized shape under
/// `(span / cell)²` buckets — memory quadratic in the ratio of the largest
/// shape to the median, and a layer mixing a few huge shapes with a million
/// contacts is an ordinary layer, not a pathological one. Each level's cell is
/// therefore at least as wide as the widest box that level holds, which caps a
/// box at two cells per axis and the whole index at `4n` filings whatever the
/// mix of scales. The fine level takes everything up to the median extent
/// widened for aspect ratio; the coarse level takes the rest at a cell of the
/// maximum extent, and is not built at all when nothing is that large — which
/// is the common case, and why the single-scale layer pays nothing for this.
#[derive(Debug, Default)]
pub struct SpatialIndex {
    layer: Option<LayerId>,
    /// Boxes no wider than the fine cell. Non-empty whenever the layer is.
    fine: Grid,
    /// Boxes wider than the fine cell, at a cell wide enough to hold them.
    /// Empty — and never queried — when the layer has no such box.
    coarse: Grid,
}

/// One level: a CSR bucket table over the subset of a layer that belongs to it.
///
/// The two levels share an `extent`, so a query window means the same region in
/// both and only the cell size differs.
#[derive(Debug, Default)]
struct Grid {
    cell_size: Dbu,
    /// The region the grid covers: the union of the *layer's* bounding boxes,
    /// not just this level's, so both levels share one origin.
    extent: Bbox,
    /// `bucket_start[b] .. bucket_start[b + 1]` indexes `rows`.
    bucket_start: Vec<u32>,
    /// Store row ids, grouped by bucket, ascending inside each bucket.
    rows: Vec<u32>,
}

/// The longer side of a box — the quantity that decides which level holds it.
fn box_extent(b: Bbox) -> i64 {
    (b.xhi.raw() - b.xlo.raw()).max(b.yhi.raw() - b.ylo.raw())
}

/// Cells along one axis, given the axis's inclusive unit count.
fn axis_cells(span: i64, cell: i64) -> u32 {
    debug_assert!(span >= 1, "an inclusive span covers at least one unit");
    debug_assert!(cell >= 1, "a cell is at least one database unit wide");
    // `i64::div_ceil` is still unstable; both operands are positive here.
    let cells = (span + cell - 1) / cell;
    debug_assert!(cells >= 1, "grid axis {cells}");
    // Checked in every profile, not just debug. The bound is not local — the
    // caller picks `cell` no smaller than `span / side`, so `cells <= side + 1`
    // and `side` is `isqrt(4 * rows + 64)` — and a truncation here would not
    // fail loudly: `nx` is the stride of the bucket table, so a wrapped axis
    // count silently misfiles rows and loses pairs, which is the fail-open
    // direction. One divide already costs more than the compare.
    u32::try_from(cells).expect("more grid cells on one axis than a u32 holds")
}

/// The cell indices a coordinate range touches, clamped to the grid.
///
/// Clamping is what lets a query box grown by `distance` hang off the edge of
/// the extent: the cells beyond the edge hold nothing, so folding them onto the
/// border cell loses no row.
fn cell_span(lo: i64, hi: i64, origin: i64, cell: i64, cells: u32) -> (u32, u32) {
    debug_assert!(lo <= hi, "a coordinate range runs low to high");
    debug_assert!(cell >= 1 && cells >= 1);
    let last = i64::from(cells - 1);
    let first_cell = ((lo - origin).max(0) / cell).min(last);
    let final_cell = ((hi - origin).max(0) / cell).min(last);
    debug_assert!(first_cell <= final_cell);
    // Both are clamped into `0 ..= last` two lines up and `last` came from a
    // `u32`, so neither conversion can fail; `try_from` is how that clamp is
    // said out loud rather than asserted somewhere else.
    (
        u32::try_from(first_cell).expect("the clamp bounds this by `cells - 1`"),
        u32::try_from(final_cell).expect("the clamp bounds this by `cells - 1`"),
    )
}

/// The uniforms one level's two filing passes share, hoisted above both.
///
/// One struct rather than six loose locals because the two passes have to agree
/// *exactly*: a row counted by one and skipped by the other corrupts the write
/// cursors, and the only way to guarantee that is for both to ask the same
/// function.
struct Level {
    ox: i64,
    oy: i64,
    cell: i64,
    min_ext: i64,
    nx: u32,
    ny: u32,
}

impl Level {
    /// The inclusive cell rectangle `b` occupies — `(c0, c1, r0, r1)` — or
    /// `None` when `b`'s extent belongs to the other level.
    fn footprint(&self, b: Bbox) -> Option<(u32, u32, u32, u32)> {
        let ext = box_extent(b);
        // Not a bulk branch: the taken side runs a nested cell loop and a
        // scatter, which is the expensive-taken-side escape valve, and the
        // predicate is a box's size against a constant so it predicts with
        // whatever grain the layer's size distribution has.
        if ext < self.min_ext || ext > self.cell {
            return None;
        }
        let (c0, c1) = cell_span(b.xlo.raw(), b.xhi.raw(), self.ox, self.cell, self.nx);
        let (r0, r1) = cell_span(b.ylo.raw(), b.yhi.raw(), self.oy, self.cell, self.ny);
        debug_assert!(
            c1 - c0 <= 1 && r1 - r0 <= 1,
            "a box no wider than the cell touches at most two cells per axis"
        );
        Some((c0, c1, r0, r1))
    }
}

impl SpatialIndex {
    /// Build over one layer.
    ///
    /// **Transform, dispatcher.** Caller owns the index and it is cleared and
    /// refilled, so a loop over layers reuses one allocation. The dispatch is
    /// on box extent: each row goes to exactly one level, and each level is a
    /// uniform transform over the rows it kept.
    pub fn build_into(store: &GeometryStore, layer: LayerId, out: &mut Self) {
        let bboxes = store.layer_bboxes(layer);
        let rows = store.polys_on_layer(layer);
        debug_assert_eq!(
            bboxes.len(),
            rows.len(),
            "the bounding-box column and the row range are the same layer"
        );

        out.layer = Some(layer);
        out.fine.clear();
        out.coarse.clear();

        let n = bboxes.len();
        // Most of a PDK's layer table is empty, so this is the common case and
        // it is an answer, not an error: no rows, no buckets, no pairs.
        if n == 0 {
            return;
        }

        // A strict left fold in ascending row order. `union` is a per-coordinate
        // min/max, so the body carries no data-dependent branch and the whole
        // accumulator is one vectorisable chain.
        let mut extent = Bbox::EMPTY;
        for &b in bboxes {
            extent = Bbox::union(extent, b);
        }
        debug_assert_eq!(bboxes.len(), n, "the fold saw every row of the column");

        let (ox, oy) = (extent.xlo.raw(), extent.ylo.raw());
        let span_x = extent.xhi.raw() - ox + 1;
        let span_y = extent.yhi.raw() - oy + 1;
        debug_assert!(span_x >= 1 && span_y >= 1, "a real box is not the EMPTY sentinel");
        debug_assert!(
            ox.unsigned_abs() <= MAX_ABS_DBU.unsigned_abs()
                && extent.xhi.raw().unsigned_abs() <= MAX_ABS_DBU.unsigned_abs(),
            "the extent is a union of in-domain coordinates"
        );

        // The median bounding-box extent, then widened until the bucket table
        // is O(rows) whatever the aspect ratio — a 1 nm-tall, 1 mm-wide layer
        // must not ask for a million buckets per row.
        let mut extents: Vec<i64> = Vec::with_capacity(n);
        for &b in bboxes {
            extents.push(box_extent(b));
        }
        debug_assert_eq!(extents.len(), n, "one extent per bounding box");

        // Read before `select_nth_unstable` below reorders the column. `max` is
        // a `cmov`, not a branch, so the fold is flat whatever the size mix.
        let mut widest = 0i64;
        for &e in &extents {
            widest = widest.max(e);
        }

        let mid = n / 2;
        extents.select_nth_unstable(mid);
        // `n` is a layer's row count and rows are addressed by `u32` ids, so
        // the conversion is total; spelling it `try_from` is what says so.
        let rows_i64 = i64::try_from(n).expect("a layer's row count fits an i64");
        let side = (4 * rows_i64 + 64).isqrt().max(1);
        let fine_cell = extents[mid]
            .max(1)
            .max((span_x + side - 1) / side)
            .max((span_y + side - 1) / side);
        debug_assert!(widest >= extents[mid], "the maximum is not below the median");

        Grid::build_into(bboxes, rows.start, extent, fine_cell, 0, &mut out.fine);
        // Not a bulk branch: one test per layer, and the taken side is a whole
        // second build. Skipping it is the common case — a layer whose widest
        // box already fits the fine cell needs no second level at all.
        if widest > fine_cell {
            Grid::build_into(
                bboxes,
                rows.start,
                extent,
                widest,
                fine_cell + 1,
                &mut out.coarse,
            );
        }

        debug_assert!(!out.fine.rows.is_empty(), "the median box is always fine");
        let filed = out.fine.rows.len() + out.coarse.rows.len();
        debug_assert!(filed >= n, "every row is filed under at least one cell");
        // The whole point of the second level: a box never spans more than two
        // cells per axis of the level that holds it, so filing is linear in the
        // row count and independent of the ratio of largest box to median.
        debug_assert!(
            filed <= 4 * n,
            "{filed} filings for {n} rows, so some box spans more than 2x2 cells"
        );
        debug_assert!(
            out.fine
                .rows
                .iter()
                .chain(&out.coarse.rows)
                .all(|&r| r >= rows.start && r < rows.end),
            "every filed row belongs to the indexed layer"
        );
    }

    pub fn is_empty(&self) -> bool {
        self.fine.rows.is_empty() && self.coarse.rows.is_empty()
    }
}

impl Grid {
    /// Back to the state a `default()` grid is in, keeping the allocations.
    fn clear(&mut self) {
        self.cell_size = Dbu::new_unchecked(1);
        self.extent = Bbox::EMPTY;
        self.bucket_start.clear();
        self.rows.clear();
    }

    /// File every box whose extent lies in `min_ext ..= cell` into a CSR bucket
    /// table over `extent` at that cell size.
    ///
    /// **Transform.** `out` is caller-owned, cleared and refilled. The caller
    /// picks `cell` so that no member box is wider than it, which is what bounds
    /// a box to a 2x2 cell footprint; the assertion in the counting loop is that
    /// contract, checked.
    fn build_into(
        bboxes: &[Bbox],
        first_row: u32,
        extent: Bbox,
        cell: i64,
        min_ext: i64,
        out: &mut Self,
    ) {
        debug_assert!(cell >= 1, "a cell is at least one database unit wide");
        debug_assert!(min_ext >= 0 && min_ext <= cell, "the level's extent band is empty");

        out.clear();
        out.cell_size = Dbu::new_unchecked(cell);
        out.extent = extent;

        let (ox, oy) = (extent.xlo.raw(), extent.ylo.raw());
        let nx = axis_cells(extent.xhi.raw() - ox + 1, cell);
        let ny = axis_cells(extent.yhi.raw() - oy + 1, cell);
        let buckets = nx as usize * ny as usize;
        out.bucket_start.resize(buckets + 1, 0);
        let level = Level {
            ox,
            oy,
            cell,
            min_ext,
            nx,
            ny,
        };

        // Both loops are scatter-accumulate: the output index is a function of
        // the row's coordinates, so neither vectorises without lane-conflict
        // detection.
        //
        // The histogram is single-threaded, and not because nobody got to it.
        // The parallel form — per-thread counts merged before the prefix sum —
        // needs `rayon`, and `gpurify-core` sits at the base of the module graph
        // with exactly two dependencies, `gpurify-units` and `thiserror`. Adding
        // a third there is a manifest decision above a body, and it is filed in
        // `docs/SIGNATURE_DEFECTS.md` with the same blocker in `lvs::graph` and
        // `erc::Scratch`.
        //
        // A box is filed under *every* cell it overlaps, not just the one
        // holding a corner. That is what makes the bucket test in `gather_level`
        // sound — the alternative, one cell per box plus a global
        // maximum-extent margin, is fail-open the moment one reticle-sized
        // shape widens the margin past anything useful. The level split is what
        // keeps "every cell it overlaps" bounded at four.
        let mut members = 0usize;
        for &b in bboxes {
            let Some((c0, c1, r0, r1)) = level.footprint(b) else {
                continue;
            };
            members += 1;
            for r in r0..=r1 {
                let base = r as usize * nx as usize;
                for c in c0..=c1 {
                    out.bucket_start[base + c as usize + 1] += 1;
                }
            }
        }

        // A level with no members is an absence, not an empty grid: leaving the
        // bucket table behind would make `dims` disagree with `rows`, and
        // `gather_level` reads emptiness as "nothing to query".
        if members == 0 {
            out.clear();
            return;
        }

        // A prefix sum is a chain — row `b` reads what row `b - 1` wrote — so
        // it is loop-carried by construction and does not vectorise.
        for b in 1..=buckets {
            out.bucket_start[b] += out.bucket_start[b - 1];
        }
        let filed = out.bucket_start[buckets] as usize;
        debug_assert!(filed >= members, "every member is filed under at least one cell");
        debug_assert!(filed <= 4 * members, "a member spans more than 2x2 cells");
        out.rows.resize(filed, 0);

        // `bucket_start[b]` doubles as bucket `b`'s write cursor, so no second
        // offset array is allocated. Rows are filed in ascending order, which
        // is what lets `gather_level` find the `b > a` suffix by binary search.
        // Counting up in the id domain rather than `enumerate` + a narrowing
        // cast: `first_row .. first_row + bboxes.len()` is the layer's own row
        // range, so the id is exact by construction and no cast appears in the
        // body of a scatter.
        for (poly, &b) in (first_row..).zip(bboxes) {
            // The same `footprint` call as the counting loop, which is the
            // point of the shared function: a row counted there and skipped
            // here, or the reverse, corrupts the cursors.
            let Some((c0, c1, r0, r1)) = level.footprint(b) else {
                continue;
            };
            for r in r0..=r1 {
                let base = r as usize * nx as usize;
                for c in c0..=c1 {
                    let bucket = base + c as usize;
                    let w = out.bucket_start[bucket];
                    out.rows[w as usize] = poly;
                    out.bucket_start[bucket] = w + 1;
                }
            }
        }

        // Every cursor now holds the *end* of its bucket, which is the start of
        // the next one: shifting right restores the offsets.
        out.bucket_start.copy_within(0..buckets, 1);
        out.bucket_start[0] = 0;

        debug_assert_eq!(out.bucket_start[buckets] as usize, out.rows.len());
        debug_assert!(
            out.bucket_start.windows(2).all(|w| w[0] <= w[1]),
            "bucket offsets are non-decreasing"
        );
    }

    /// How many buckets the table holds. Zero for a level that was never built.
    fn bucket_count(&self) -> usize {
        self.bucket_start.len().saturating_sub(1)
    }

    /// Grid shape, derived rather than stored: `extent` and `cell_size` already
    /// fix it, and a second copy is a second thing to keep in step.
    fn dims(&self) -> (u32, u32) {
        let cell = self.cell_size.raw();
        let nx = axis_cells(self.extent.xhi.raw() - self.extent.xlo.raw() + 1, cell);
        let ny = axis_cells(self.extent.yhi.raw() - self.extent.ylo.raw() + 1, cell);
        debug_assert_eq!(self.bucket_start.len(), nx as usize * ny as usize + 1);
        (nx, ny)
    }

    /// The region one bucket covers, clipped to the extent so no coordinate
    /// leaves the legal domain.
    fn cell_bbox(&self, col: u32, row: u32) -> Bbox {
        let cell = self.cell_size.raw();
        let x = self.extent.xlo.raw() + i64::from(col) * cell;
        let y = self.extent.ylo.raw() + i64::from(row) * cell;
        Bbox {
            xlo: Dbu::new_unchecked(x),
            ylo: Dbu::new_unchecked(y),
            xhi: Dbu::new_unchecked((x + cell - 1).min(self.extent.xhi.raw())),
            yhi: Dbu::new_unchecked((y + cell - 1).min(self.extent.yhi.raw())),
        }
    }
}

/// What crossing the prune seam did.
///
/// Not derivable from the output: a prune that wrongly rejects a pair returns a
/// shorter list that is still perfectly well-formed. The property worth testing
/// is *no rejected pair would have passed the exact predicate*, and it is only
/// expressible with this.
pub trait ObservePairs: Observer {
    /// A pair was emitted as a candidate.
    fn emitted(&mut self, a: PolyId, b: PolyId);
    /// A pair was rejected by the prune. The argument of the whole seam.
    fn rejected(&mut self, a: PolyId, b: PolyId);
    /// A whole bucket was skipped without examining its rows.
    fn bucket_skipped(&mut self, bucket: u32, rows: u32);
}

/// The null adapter. Empty bodies on a zero-sized type, so the whole seam folds
/// away behind `ENABLED == false`; the parameters are named out because there is
/// nothing to name them for.
impl ObservePairs for NoObserve {
    fn emitted(&mut self, _a: PolyId, _b: PolyId) {}
    fn rejected(&mut self, _a: PolyId, _b: PolyId) {}
    fn bucket_skipped(&mut self, _bucket: u32, _rows: u32) {}
}

/// Every pair of polygons on one layer within `distance` of each other.
///
/// **Transform, gatherer.** Caller owns `out`, cleared and refilled. Pairs are
/// emitted with `a < b` and in ascending order, so the result is deterministic
/// regardless of how the index was built — a requirement, not a nicety, since
/// output ordering is gated.
///
/// The result is a *superset*: a pair here may still fail the exact check. A
/// pair absent from here is never checked again by anyone, which is the whole
/// risk this module carries.
pub fn candidate_pairs_into(
    store: &GeometryStore,
    index: &SpatialIndex,
    distance: Dbu,
    out: &mut Vec<(PolyId, PolyId)>,
) {
    candidate_pairs_observed(store, index, distance, out, &mut NoObserve);
}

/// [`candidate_pairs_into`] with the seam exposed.
///
/// Private: the observer is a test concern and does not belong in this module's
/// interface. Adapter tests are therefore unit tests in this crate — the
/// deliberate trade recorded in [`crate::observe`].
fn candidate_pairs_observed<O: ObservePairs>(
    store: &GeometryStore,
    index: &SpatialIndex,
    distance: Dbu,
    out: &mut Vec<(PolyId, PolyId)>,
    observer: &mut O,
) {
    out.clear();
    // An index that was never built is not an empty layer: `build_into` always
    // names the layer it indexed, so `None` here means a caller queried a
    // `default()`. Returning an empty list for it would report a clean check
    // that never ran — the fail-open shape `docs/VOCABULARY.md` §3 names — so
    // this is an `expect` and not a `debug_assert`: the signature has no error
    // channel, and a release build that answers the query anyway is the exact
    // defect the comment above describes. One predictable test per query call,
    // not per pair.
    let layer = index.layer.expect(
        "an index that was never built cannot answer a query: an empty pair \
         list would read as a spacing check that ran and found nothing",
    );
    if index.is_empty() {
        return;
    }
    debug_assert!(distance.raw() >= 0, "a spacing distance is never negative");
    debug_assert!(
        distance.raw() <= MAX_ABS_DBU,
        "a distance past the coordinate domain is a deck error, not a query"
    );

    prune_pairs::<true, O>(store, index, layer, distance, out, observer);
}

/// Gather every row `index` can reach from each row of `layer`, then prune the
/// result with the exact box predicate.
///
/// **Transform, gatherer.** The one implementation both pair queries are
/// spellings of; `SAME` is [`gather_near`]'s const parameter and says `index`
/// holds `layer`'s own rows, so a pair is emitted once with `a < b`.
///
/// No scratch buffer. The gather writes the raw superset straight into `out`
/// and the compact runs over it in place: the write cursor `w` never outruns
/// the read cursor `i`, so a row is only ever overwritten after it has been
/// read. `out` is the caller's, reused across calls, and it was already sized
/// for the whole input rather than the survivors — the memory-for-branches
/// trade the compact needs — so the second allocation bought nothing.
///
/// The gather appends a data-dependent number of pairs per row; the elementwise
/// part of the transform is the branchless compact below, and that is where the
/// exact predicate lives.
fn prune_pairs<const SAME: bool, O: ObservePairs>(
    store: &GeometryStore,
    index: &SpatialIndex,
    layer: LayerId,
    distance: Dbu,
    out: &mut Vec<(PolyId, PolyId)>,
    observer: &mut O,
) {
    out.clear();
    for row in store.polys_on_layer(layer) {
        let a = PolyId(row);
        gather_near::<SAME, O>(index, distance, a, store.poly_bbox(a), out, observer);
    }
    out.sort_unstable();
    out.dedup();
    debug_assert!(
        !SAME || out.iter().all(|&(a, b)| a < b),
        "the same-layer form emits `a < b` only"
    );
    let examined = out.len();

    // Replayed before the compact rather than after, because the compact is now
    // what destroys the examined list. The observer reads it as a shared slice,
    // so it still cannot reach the answer.
    if O::ENABLED {
        report_prune(store, out, distance, observer);
    }

    // The branchless compact, in place over the examined pairs. Survivors move
    // down into slots already read this pass, so no second buffer is needed and
    // no store is conditional; the predicate lives in the *index* `w`.
    let kept = {
        let pairs = out.as_mut_slice();
        debug_assert_eq!(pairs.len(), examined, "the compact reads what the gather wrote");
        let mut w = 0usize;
        for i in 0..examined {
            let (a, b) = pairs[i];
            let p = store.poly_bbox(a).within(store.poly_bbox(b), distance);
            // `w <= i` by induction: `w == i == 0` on entry, and each iteration
            // advances `w` by `usize::from(p)`, which Rust guarantees is 0 or 1
            // because `bool` is 0 or 1. So `w` never outruns `i` — which is also
            // why reading `pairs[i]` before the store is sound: slot `i` is
            // still its own until some later iteration lands on it.
            debug_assert!(w <= i);
            // The store is unchecked because `w`'s step is data-dependent: LLVM
            // gets no affine recurrence for it, cannot prove `w <= i`, and emits
            // a live `cmp/jae` to a panic edge that pins the loop to one element
            // per iteration. Unchecked over checked measures 1.19x at 8k, 1.18x
            // at 200k, 1.06x at 4M — `docs/BULK_MEASUREMENTS.md` §4.
            //
            // SAFETY: `w <= i < examined == pairs.len()`, from the induction.
            unsafe { *pairs.get_unchecked_mut(w) = (a, b) };
            w += usize::from(p);
        }
        w
    };

    out.truncate(kept);
    debug_assert_eq!(kept, out.len());
    debug_assert!(kept <= examined, "a compact cannot grow its input");
    debug_assert!(
        out.windows(2).all(|w| w[0] < w[1]),
        "candidate pairs come back strictly ascending and deduplicated"
    );
}

/// Replay the exact predicate over the examined pairs, for the observer only.
///
/// A separate pass rather than the observer threaded into the compact loop. The
/// whole call sits behind `O::ENABLED`, so a production build never codegens it,
/// and the compact keeps its unconditional store — an `observer.emitted(..)`
/// inside it would be the data-dependent branch that store exists to avoid.
/// Running it beside the compact rather than inside it is also what makes the
/// observed and unobserved answers identical by construction: it takes the
/// examined pairs as a shared slice, so the compact is the same loop either way
/// and neither pass can see the other's decisions.
fn report_prune<O: ObservePairs>(
    store: &GeometryStore,
    raw: &[(PolyId, PolyId)],
    distance: Dbu,
    observer: &mut O,
) {
    debug_assert!(O::ENABLED, "the null adapter must never reach this loop");
    for &(a, b) in raw {
        if store.poly_bbox(a).within(store.poly_bbox(b), distance) {
            observer.emitted(a, b);
        } else {
            observer.rejected(a, b);
        }
    }
}

/// Every row of `index` that a box grown by `distance` can reach, appended to
/// `out` paired with `a`.
///
/// `SAME` says the index holds `a`'s own layer, so a pair is emitted once with
/// `a < b`; it is a const parameter rather than a flag because it decides a test
/// inside the innermost loop and must vanish at monomorphisation.
///
/// Both levels are walked. A row lives in exactly one of them, so no pair is
/// produced twice by the split, and the bucket ids handed to the observer are
/// offset so the two levels' buckets stay distinguishable.
fn gather_near<const SAME: bool, O: ObservePairs>(
    index: &SpatialIndex,
    distance: Dbu,
    a: PolyId,
    a_box: Bbox,
    out: &mut Vec<(PolyId, PolyId)>,
    observer: &mut O,
) {
    gather_level::<SAME, O>(&index.fine, 0, distance, a, a_box, out, observer);
    // The offset exists only so the two levels' bucket ids stay distinguishable
    // *to the observer*, and `gather_level` reads it only under `O::ENABLED` —
    // so a production build folds this to a constant zero and pays neither the
    // conversion nor its panic edge. The checked form is what keeps a level
    // with more buckets than a `u32` holds from silently aliasing its ids onto
    // the fine level's.
    let coarse_base = if O::ENABLED {
        u32::try_from(index.fine.bucket_count()).expect("a level's bucket ids fit a u32")
    } else {
        0
    };
    gather_level::<SAME, O>(&index.coarse, coarse_base, distance, a, a_box, out, observer);
}

/// [`gather_near`] against one level.
///
/// The bucket walk is single-threaded, and the level that could change that is
/// not this one: the parallel axis is [`prune_pairs`]'s outer row loop, where
/// each `a` writes only its own pairs and the transform is already a gatherer.
/// Same blocker as the build histogram — `gpurify-core` depends on
/// `gpurify-units` and `thiserror` and nothing else, so there is no `rayon` here
/// to write it against, and the manifest change is filed in
/// `docs/SIGNATURE_DEFECTS.md` rather than made from inside a body.
///
/// Nothing else in this walk is left on the table. The duplicate filings a box
/// gets from spanning up to 2x2 cells cannot be collapsed by emitting from one
/// "home" cell only: the home cell can fall outside the query window while
/// another filed cell falls inside it, so the dedup in [`prune_pairs`] is the
/// cheap end of that trade and not a shortcut.
fn gather_level<const SAME: bool, O: ObservePairs>(
    grid: &Grid,
    bucket_base: u32,
    distance: Dbu,
    a: PolyId,
    a_box: Bbox,
    out: &mut Vec<(PolyId, PolyId)>,
    observer: &mut O,
) {
    // Not a bulk branch: a level is empty or not for the whole run, so this
    // predicts perfectly, and `dims` on an unbuilt level would read the EMPTY
    // sentinel as a span.
    if grid.rows.is_empty() {
        return;
    }

    let cell = grid.cell_size.raw();
    let (nx, ny) = grid.dims();
    let (ox, oy) = (grid.extent.xlo.raw(), grid.extent.ylo.raw());
    // `reach * cell > distance`, so widening the query by whole cells covers
    // every cell the box grown by `distance` can touch. Rounding up is the
    // direction that fails closed; the per-bucket test below takes the slop
    // back out.
    let pad = (distance.raw() / cell + 1) * cell;
    debug_assert!(pad > distance.raw(), "the cell window must cover the distance");

    let (c0, c1) = cell_span(a_box.xlo.raw() - pad, a_box.xhi.raw() + pad, ox, cell, nx);
    let (r0, r1) = cell_span(a_box.ylo.raw() - pad, a_box.yhi.raw() + pad, oy, cell, ny);

    for r in r0..=r1 {
        let base = r as usize * nx as usize;
        for c in c0..=c1 {
            let bucket = base + c as usize;
            let start = grid.bucket_start[bucket] as usize;
            let end = grid.bucket_start[bucket + 1] as usize;
            debug_assert!(start <= end && end <= grid.rows.len());

            // Not a bulk branch — one test per bucket, and the taken side scans
            // every row in it, which is the escape valve the branchless rubric
            // names. `pad` is a whole-cell bound, so this is what narrows the
            // window back to the cells `a_box` grown by `distance` really
            // reaches. Rejecting a bucket wrongly loses every pair inside it
            // silently, which is exactly what `bucket_skipped` exists to expose.
            if !grid.cell_bbox(c, r).within(a_box, distance) {
                if O::ENABLED {
                    // Both conversions are inside the seam, so a production
                    // build folds them away with the call. `end - start` is a
                    // difference of two `bucket_start` entries, which are
                    // already `u32`; `bucket` is a bucket index, bounded by the
                    // same `u32` the offset above is checked against.
                    let id =
                        bucket_base + u32::try_from(bucket).expect("a bucket id fits a u32");
                    let rows =
                        u32::try_from(end - start).expect("a bucket's row count fits a u32");
                    observer.bucket_skipped(id, rows);
                }
                continue;
            }

            let seg = &grid.rows[start..end];
            // Rows inside a bucket are ascending, so `b > a` is a suffix: one
            // branchless binary search for the boundary instead of a
            // data-dependent test per row. `a` files itself under this bucket
            // too, and the same bound is what drops the self-pair. Const-folded
            // away entirely for the cross-layer form, where every row counts.
            let from = if SAME {
                seg.partition_point(|&row| row <= a.0)
            } else {
                0
            };
            out.extend(seg[from..].iter().map(|&row| (a, PolyId(row))));
        }
    }
}

/// Every pair between two *different* layers within `distance`.
///
/// Separate from the same-layer form because the same-layer form can emit only
/// `a < b` and skip half the work, and folding both into one function would
/// mean a branch on layer equality inside the innermost loop.
pub fn cross_layer_pairs_into(
    store: &GeometryStore,
    a_index: &SpatialIndex,
    b_index: &SpatialIndex,
    distance: Dbu,
    out: &mut Vec<(PolyId, PolyId)>,
) {
    cross_layer_pairs_observed(store, a_index, b_index, distance, out, &mut NoObserve);
}

fn cross_layer_pairs_observed<O: ObservePairs>(
    store: &GeometryStore,
    a_index: &SpatialIndex,
    b_index: &SpatialIndex,
    distance: Dbu,
    out: &mut Vec<(PolyId, PolyId)>,
    observer: &mut O,
) {
    out.clear();
    // Same fail-open shape as the same-layer form, closed the same way: `None`
    // is an index nobody built, and an empty pair list for one reads as a clean
    // cross-layer check. Both are unwrapped in release, not just in debug.
    let a_layer = a_index.layer.expect(
        "an index that was never built cannot answer a query: an empty pair \
         list would read as a cross-layer check that ran and found nothing",
    );
    let b_layer = b_index.layer.expect(
        "an index that was never built cannot answer a query: an empty pair \
         list would read as a cross-layer check that ran and found nothing",
    );
    if a_index.is_empty() || b_index.is_empty() {
        return;
    }
    debug_assert_ne!(
        a_layer, b_layer,
        "the cross-layer form pairs two different layers"
    );
    debug_assert!(distance.raw() >= 0, "a spacing distance is never negative");
    debug_assert!(distance.raw() <= MAX_ABS_DBU);

    // `a_layer`'s rows queried against `b`'s index — the one asymmetry between
    // the two forms, and the reason `prune_pairs` takes the layer and the index
    // separately rather than deriving one from the other.
    prune_pairs::<false, O>(store, b_index, a_layer, distance, out, observer);
}

// The adapter tests. They live here, inside the crate, because
// `candidate_pairs_observed` is private — the observer is a test concern and
// widening the module's interface to reach it from `tests/` would defeat the
// point of the seam. That trade is recorded in [`crate::observe`].
//
// They also build their own geometry rather than using `gpurify-testgen`.
// `testgen` depends on this crate, so the copy of `gpurify-core` it links
// against is a *different* crate instance from the one under test here, and its
// `LayerId` is a different type. That is a property of the dev-dependency
// cycle, not a choice: the integration tests in `tests/` use the generator
// normally, and only this file, on the private side of the seam, cannot.
#[cfg(test)]
mod tests {
    use super::{candidate_pairs_observed, cross_layer_pairs_observed, ObservePairs, SpatialIndex};
    use crate::ids::{LayerId, PolyId};
    use crate::observe::Observer;
    use crate::store::{GeometryStore, GeometryStoreBuilder};
    use gpurify_units::Dbu;

    const A: LayerId = LayerId(0);
    const B: LayerId = LayerId(1);

    /// Records every decision the prune made. `ENABLED` is `true`, which is the
    /// whole difference between this adapter and [`crate::NoObserve`]: the
    /// bodies below are reachable only because the gate constant folds the
    /// other way.
    #[derive(Debug, Default)]
    struct Recorder {
        emitted: Vec<(PolyId, PolyId)>,
        rejected: Vec<(PolyId, PolyId)>,
        skipped_buckets: u32,
        skipped_rows: u32,
    }

    impl Observer for Recorder {
        const ENABLED: bool = true;
    }

    impl ObservePairs for Recorder {
        fn emitted(&mut self, a: PolyId, b: PolyId) {
            self.emitted.push((a, b));
        }
        fn rejected(&mut self, a: PolyId, b: PolyId) {
            self.rejected.push((a, b));
        }
        fn bucket_skipped(&mut self, _bucket: u32, rows: u32) {
            self.skipped_buckets += 1;
            self.skipped_rows += rows;
        }
    }

    /// A deterministic scatter over a lattice: cell `n` is occupied when the
    /// hash's low bit says so, and the shape inside it is offset by the rest of
    /// the hash. No generator and no state — the same corpus every run, on every
    /// platform, derived arithmetically from the seed.
    fn hash(mut value: u64) -> u64 {
        value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    /// Squares scattered over a `cells`-by-`cells` lattice of 400-unit cells,
    /// clear of one another but close enough that a prune has both accepting and
    /// rejecting work to do. Two layers, offset so their shapes interleave.
    fn corpus(seed: u64, cells: u64) -> GeometryStore {
        let mut builder = GeometryStoreBuilder::default();
        let mut push = |layer: LayerId, x: i64, y: i64, side: i64| {
            let xs = [x, x + side, x + side, x].map(Dbu::new_unchecked);
            let ys = [y, y, y + side, y + side].map(Dbu::new_unchecked);
            builder.push(layer, &xs, &ys);
        };

        for (layer, origin) in [(A, (0i64, 0i64)), (B, (170, 90))] {
            for row in 0..cells {
                for col in 0..cells {
                    let draw = hash(seed ^ (row << 20) ^ col);
                    if draw & 1 == 0 {
                        continue;
                    }
                    // Two sizes, so the layer has more than one spatial scale
                    // and the grid's median-extent cell sizing has something to
                    // decide.
                    let side = if draw & 2 == 0 { 80 } else { 200 };
                    let room = 400 - side;
                    let jitter_x = i64::try_from((draw >> 8) % room).expect("below room");
                    let jitter_y = i64::try_from((draw >> 30) % room).expect("below room");
                    let x = i64::try_from(col * 400).expect("the lattice fits an i64");
                    let y = i64::try_from(row * 400).expect("the lattice fits an i64");
                    push(
                        layer,
                        origin.0 + x + jitter_x,
                        origin.1 + y + jitter_y,
                        i64::try_from(side).expect("a side under four hundred"),
                    );
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

    fn dbu(value: i64) -> Dbu {
        Dbu::new_unchecked(value)
    }

    /// The exact predicate the prune is approximating, over one layer, by an
    /// `O(n^2)` scan. Obviously right, and independent of the index.
    fn exact_same_layer(
        store: &GeometryStore,
        layer: LayerId,
        distance: Dbu,
    ) -> Vec<(PolyId, PolyId)> {
        let rows: Vec<u32> = store.polys_on_layer(layer).collect();
        let mut out = Vec::new();
        for (offset, &a) in rows.iter().enumerate() {
            for &b in &rows[offset + 1..] {
                let (a, b) = (PolyId(a), PolyId(b));
                if store.poly_bbox(a).within(store.poly_bbox(b), distance) {
                    out.push((a, b));
                }
            }
        }
        out
    }

    /// Oracle: adapter. **The property the seam exists for.** A prune that
    /// wrongly rejects a pair returns a shorter list that is still perfectly
    /// well-formed, so no assertion on the return value can see the mistake.
    /// Here every rejection is recorded and re-run through the exact predicate:
    /// if the predicate would have accepted it, the prune failed open, and a
    /// spacing rule downstream silently passes a shape the foundry rejects.
    #[test]
    fn no_rejected_pair_would_have_passed_the_exact_predicate() {
        let store = corpus(91, 12);
        let index = indexed(&store, A);
        let mut out = Vec::new();

        for distance in [0i64, 1, 40, 300, 1_200] {
            let mut recorder = Recorder::default();
            candidate_pairs_observed(&store, &index, dbu(distance), &mut out, &mut recorder);

            for &(a, b) in &recorder.rejected {
                assert!(
                    !store.poly_bbox(a).within(store.poly_bbox(b), dbu(distance)),
                    "the prune rejected {a:?} and {b:?} at a distance of {distance}, \
                     but their bounding boxes are within it"
                );
            }
            assert!(
                !recorder.rejected.is_empty(),
                "nothing was rejected at a distance of {distance}, so the prune was \
                 never exercised on the side that can lose a pair"
            );
        }
    }

    /// Oracle: adapter, plus an `O(n^2)` scan. Rejections account for only part
    /// of the work: whole buckets are skipped without their rows ever reaching
    /// the pair predicate, and a bucket skipped wrongly is invisible in both the
    /// output and the rejection log. So completeness is asserted end to end —
    /// every pair the exact predicate accepts is emitted — and the emitted log
    /// is tied to the returned list, which is what callers actually see.
    #[test]
    fn the_prune_emits_every_pair_the_exact_predicate_accepts() {
        let store = corpus(92, 12);
        let index = indexed(&store, A);
        let mut out = Vec::new();

        for distance in [0i64, 25, 250, 2_000] {
            let mut recorder = Recorder::default();
            candidate_pairs_observed(&store, &index, dbu(distance), &mut out, &mut recorder);

            for pair in exact_same_layer(&store, A, dbu(distance)) {
                assert!(
                    out.contains(&pair),
                    "{pair:?} is within {distance} but was never emitted; \
                     {} buckets holding {} rows were skipped",
                    recorder.skipped_buckets,
                    recorder.skipped_rows
                );
            }

            let mut emitted = recorder.emitted.clone();
            emitted.sort_unstable();
            let mut returned = out.clone();
            returned.sort_unstable();
            assert_eq!(
                emitted, returned,
                "the seam and the returned list disagree at a distance of {distance}"
            );
        }
    }

    /// Oracle: adapter. The cross-layer form is a separate function with a
    /// separate loop, so it is a separate chance to reject a pair that should
    /// have survived. The same two claims, over the pairing that cannot halve
    /// its work with `a < b`.
    #[test]
    fn the_cross_layer_prune_rejects_nothing_the_exact_predicate_accepts() {
        let store = corpus(93, 10);
        let a_index = indexed(&store, A);
        let b_index = indexed(&store, B);
        let mut out = Vec::new();

        for distance in [0i64, 30, 400] {
            let mut recorder = Recorder::default();
            cross_layer_pairs_observed(
                &store,
                &a_index,
                &b_index,
                dbu(distance),
                &mut out,
                &mut recorder,
            );

            for &(a, b) in &recorder.rejected {
                assert!(
                    !store.poly_bbox(a).within(store.poly_bbox(b), dbu(distance)),
                    "the cross-layer prune rejected {a:?} and {b:?} at {distance}"
                );
            }

            for a in store.polys_on_layer(A) {
                for b in store.polys_on_layer(B) {
                    let (a, b) = (PolyId(a), PolyId(b));
                    if store.poly_bbox(a).within(store.poly_bbox(b), dbu(distance)) {
                        assert!(
                            out.contains(&(a, b)),
                            "{a:?} and {b:?} are within {distance} but were not emitted"
                        );
                    }
                }
            }
        }
        assert!(!out.is_empty(), "no cross-layer pair was ever emitted");
    }

    /// Oracle: law. The observer changes what is recorded, never what is
    /// returned. If installing an adapter altered the answer, every assertion
    /// made through one would be about a different function from the one that
    /// ships — the failure a seam has to rule out before it is worth anything.
    #[test]
    fn installing_an_observer_does_not_change_the_pairs_that_come_back() {
        let store = corpus(94, 10);
        let index = indexed(&store, A);

        let mut observed = Vec::new();
        let mut plain = Vec::new();
        for distance in [0i64, 60, 700] {
            candidate_pairs_observed(
                &store,
                &index,
                dbu(distance),
                &mut observed,
                &mut Recorder::default(),
            );
            super::candidate_pairs_into(&store, &index, dbu(distance), &mut plain);
            assert_eq!(observed, plain, "the observer changed the answer");
        }
        assert!(!plain.is_empty(), "the comparison would be vacuous");
    }
}
