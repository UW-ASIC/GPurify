//! Bounding-box prefiltering for boolean operands.
//!
//! Structurally identical to the candidate-pair prune in `core::index`: reject
//! cheaply, then compute exactly. And it has the same silent failure mode — a
//! wrongly rejected pair produces a shorter, perfectly well-formed operand list
//! and a quietly wrong answer, because nothing downstream ever looks at the
//! pair again.
//!
//! So it carries the same kind of test adapter, for the same reason: the
//! property that matters is *no rejected pair would have contributed to the
//! result*, and that is not observable in the output.
//!
//! This code is new. It has no history of being right, which is the argument
//! for instrumenting it from the start rather than after it burns someone.

use gpurify_core::observe::{NoObserve, Observer};
use gpurify_core::{Bbox, GeometryStore, LayerId, PolyId, ValidatedLayer};
use gpurify_units::Dbu;

/// What crossing the prefilter seam did.
pub trait ObservePrefilter: Observer {
    /// A pair was kept for exact evaluation.
    fn kept(&mut self, a: PolyId, b: PolyId);
    /// A pair was rejected on bounding boxes alone. The one that matters.
    fn rejected(&mut self, a: PolyId, b: PolyId);
}

/// The null adapter. Empty bodies on a zero-sized type, so the whole seam folds
/// away behind `ENABLED == false`; the parameters are named out because there is
/// nothing to name them for.
impl ObservePrefilter for NoObserve {
    fn kept(&mut self, _a: PolyId, _b: PolyId) {}
    fn rejected(&mut self, _a: PolyId, _b: PolyId) {}
}

/// Which operand pairs can possibly interact.
///
/// **Transform, gatherer.** Caller owns `out`, cleared and refilled, emitted in
/// ascending order so the result is deterministic regardless of index layout.
///
/// A superset: a surviving pair may still contribute nothing. A pair absent
/// from here is never evaluated by anyone.
pub fn candidates_into(
    store: &GeometryStore,
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut Vec<(PolyId, PolyId)>,
) {
    candidates_observed(store, a, b, out, &mut NoObserve);
}

/// [`candidates_into`] with the seam exposed.
///
/// Private, so the observer does not widen this module's interface and adapter
/// tests are unit tests here. Same trade as `core::observe` records.
fn candidates_observed<O: ObservePrefilter>(
    store: &GeometryStore,
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut Vec<(PolyId, PolyId)>,
    observer: &mut O,
) {
    out.clear();
    let a_box = a.bboxes();
    let b_box = b.bboxes();
    debug_assert_eq!(
        a_box.len(),
        a.len(),
        "one bounding box per validated polygon"
    );
    debug_assert_eq!(
        b_box.len(),
        b.len(),
        "one bounding box per validated polygon"
    );

    // An empty operand is an answer, not a refusal: nothing can interact with
    // nothing, and most of a deck's layer table is empty. It is also what keeps
    // `provenance_into` off the degenerate case where every layer matches.
    if a_box.is_empty() || b_box.is_empty() {
        return;
    }

    // Scratch is allocated per call: the frozen signature has nowhere to hang a
    // reusable buffer, and adding one is a signature change rather than a body.
    // `core::index` records the same trade. Filed in `docs/SIGNATURE_DEFECTS.md`.
    let mut a_row = Vec::new();
    let mut b_row = Vec::new();
    provenance_into(store, a_box, &mut a_row);
    provenance_into(store, b_box, &mut b_row);
    debug_assert_eq!(
        a_row.len(),
        a_box.len(),
        "one store row per operand polygon"
    );
    debug_assert_eq!(
        b_row.len(),
        b_box.len(),
        "one store row per operand polygon"
    );
    debug_assert!(
        a_row.windows(2).all(|w| w[0] < w[1]) && b_row.windows(2).all(|w| w[0] < w[1]),
        "operand rows are strictly ascending, which is what makes the pair order below ascending"
    );

    let mut index = OperandIndex::default();
    build_index(&b_row, b_box, &mut index);

    let mut near: Vec<(PolyId, Bbox)> = Vec::new();

    // Each polygon of `a` appends a data-dependent *number* of pairs, so the
    // outer loop is a scatter. The elementwise half of the transform is the
    // compact inside it.
    for (&left, &left_box) in a_row.iter().zip(a_box) {
        // Two binary searches replace the scan of `b`. Everything outside
        // `lo .. hi` is disjoint from `left_box` in x alone, so the exact test
        // below runs only over the x-overlapping window.
        let (lo, hi) = index.window(left_box);
        let win_row = &index.row[lo..hi];
        let win_bbox = &index.bbox[lo..hi];
        let width = win_row.len();
        debug_assert_eq!(
            width,
            win_bbox.len(),
            "the index's columns are parallel, so one window has one length"
        );

        // A branchless compact: the store is unconditional and the write cursor
        // carries the predicate. `near` is reserved for the whole window rather
        // than for the survivors, and that over-reservation is exactly what pays
        // for the unconditional store.
        near.clear();
        near.reserve(width);
        debug_assert!(
            near.capacity() >= width,
            "the compact reserves for the window, not the survivors"
        );
        let survivors = &mut near.spare_capacity_mut()[..width];
        let mut w = 0usize;
        for (i, (&right, &right_box)) in win_row.iter().zip(win_bbox).enumerate() {
            // `Bbox::overlaps` is four `<=` on already-loaded registers, which
            // LLVM if-converts to `setle`/`and`. No branch enters this body.
            let keep = left_box.overlaps(right_box);
            // `w <= i` by induction: `w` starts at 0 and `bool` is 0 or 1, so it
            // advances by at most one per iteration. `(PolyId, Bbox)` is `Copy`,
            // so the slots `w` skipped over hold nothing with a `Drop` and
            // `set_len(w)` truncates them away unread.
            debug_assert!(w <= i);
            // SAFETY: `w <= i < width == survivors.len()`, from the induction
            // just above. The store has to be unchecked: `w`'s step is
            // data-dependent, so LLVM gets no affine recurrence for it and
            // cannot prove the bound itself — it emits a live `cmp/jae` to a
            // panic edge instead, which is a branch in a body that otherwise has
            // none. Measured 1.19x at 8k / 1.18x at 200k / 1.06x at 4M in
            // `docs/BULK_MEASUREMENTS.md` §4.
            unsafe { survivors.get_unchecked_mut(w) }.write((right, right_box));
            w += usize::from(keep);
        }
        // SAFETY: slot `k` was written while `w == k`, for every `k < w`, and
        // `w <= width <= near.capacity()`.
        unsafe { near.set_len(w) };

        debug_assert!(
            near.len() <= b_box.len(),
            "a prune cannot invent an operand"
        );
        debug_assert!(
            index.bbox[..lo]
                .iter()
                .chain(&index.bbox[hi..])
                .all(|&outside| !left_box.overlaps(outside)),
            "the x-window dropped an operand the exact test would have kept"
        );

        // The window is in ascending-`xlo` order, so the survivors have to be
        // put back into store-row order; `b_row` is strictly ascending, so
        // sorting on the row is sorting on the operand's own index. Keys are
        // distinct, so the result does not depend on the sort being stable.
        near.sort_unstable_by_key(|&(right, _)| right.0);
        // A map straight into the caller's buffer: `left` is a uniform broadcast
        // across the survivors. The staging vector that used to sit between them
        // bought a second copy of every pair and nothing else.
        out.extend(near.iter().map(|&(right, _)| (left, right)));
    }

    debug_assert!(
        out.len() <= a_box.len() * b_box.len(),
        "the candidate list is a subset of the cross product"
    );
    debug_assert!(
        out.windows(2).all(|w| w[0] < w[1]),
        "candidates come back strictly ascending and without repeats"
    );

    if O::ENABLED {
        report_prune(&a_row, a_box, &b_row, b_box, observer);
    }
}

/// One operand's bounding boxes, ordered for interval queries.
///
/// **Five questions.** In: an operand's store-row and bounding-box columns.
/// Out: the same two columns reordered by `xlo`, plus the running maximum of
/// `xhi`. How many: one per call, over the tens to thousands of polygons a
/// derived-layer operand carries. Access pattern: built once, then two binary
/// searches and one contiguous scan per polygon of the other operand — so the
/// columns are parallel arrays, not a tree. Lifetime: the call. Parallelisable:
/// queries are independent reads of a finished index.
///
/// A sorted interval index rather than the uniform grid of
/// `core::index::SpatialIndex`: that one indexes a *store layer*, and a boolean
/// result has rows in no store, so it cannot be pointed at a `ValidatedLayer`
/// without widening `core`. This indexes the boxes themselves and so works on
/// either kind of operand.
#[derive(Debug, Default)]
struct OperandIndex {
    /// Store rows, in ascending `xlo` order.
    row: Vec<PolyId>,
    /// Bounding boxes, parallel to `row`.
    bbox: Vec<Bbox>,
    /// `max_xhi[k]` is the largest `xhi` in `bbox[..=k]`. Non-decreasing by
    /// construction, which is what makes it binary-searchable: below the first
    /// `k` whose running maximum reaches a query's `xlo`, *every* box ends
    /// before that query begins.
    max_xhi: Vec<Dbu>,
}

impl OperandIndex {
    /// The half-open range of index rows whose x-extent can meet `query`.
    ///
    /// Both ends are exact, not heuristic: at or above `hi` every box starts
    /// after the query ends, and below `lo` every box ends before it starts.
    /// Inclusive on both, because [`Bbox::overlaps`] counts a shared edge.
    fn window(&self, query: Bbox) -> (usize, usize) {
        let hi = self.bbox.partition_point(|b| b.xlo <= query.xhi);
        let lo = self.max_xhi[..hi].partition_point(|&reach| reach < query.xlo);
        debug_assert!(
            lo <= hi && hi <= self.bbox.len(),
            "a window is a range of the index"
        );
        (lo, hi)
    }
}

/// Order one operand's columns by `xlo` and accumulate the reach of each prefix.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled, so a loop
/// over operand pairs reuses one allocation.
fn build_index(row: &[PolyId], bbox: &[Bbox], out: &mut OperandIndex) {
    debug_assert_eq!(row.len(), bbox.len(), "an operand's columns are parallel");
    debug_assert!(
        !bbox.is_empty(),
        "the caller returns before an empty operand reaches here"
    );

    // `row` is one strictly-ascending `PolyId` per operand polygon, and `PolyId`
    // is a `u32`, so the column cannot be longer than the id space it indexes.
    // Checked rather than cast: this runs once per operand, not per row, and a
    // truncation here would silently shorten the permutation and drop polygons.
    let count = u32::try_from(row.len()).expect("one `PolyId` per row bounds the column by u32");
    let mut order: Vec<u32> = (0..count).collect();
    // Ties broken on the operand's own index, so the index is a function of the
    // input and not of the sort's internal choices.
    order.sort_unstable_by_key(|&i| (bbox[i as usize].xlo, i));

    let OperandIndex {
        row: out_row,
        bbox: out_bbox,
        max_xhi,
    } = out;
    // Two gathers over the same permutation, fused into one pass. A gather's
    // *address* is data-dependent, not its control flow, so there is no branch
    // in here to remove. The bounds check on `row[i]` stays: `order` being a
    // permutation of `0 .. row.len()` is true by construction but is not a fact
    // the compiler has, and buying it back with `unsafe` is not worth it in a
    // loop whose cost is the random-access load anyway. `push` after one
    // `reserve` for the same reason.
    out_row.clear();
    out_row.reserve(order.len());
    out_bbox.clear();
    out_bbox.reserve(order.len());
    for &i in &order {
        let i = i as usize;
        out_row.push(row[i]);
        out_bbox.push(bbox[i]);
    }

    // A prefix scan: row k reads what row k-1 wrote, so it is serial by shape —
    // an accumulator chain, not a map, and the same shape as `SpatialIndex`'s
    // prefix sum. The allocation is reserved once above the loop, not grown per
    // row.
    max_xhi.clear();
    max_xhi.reserve(out_bbox.len());
    let mut reach = out_bbox[0].xhi;
    for b in out_bbox.iter() {
        reach = reach.max(b.xhi);
        max_xhi.push(reach);
    }

    debug_assert_eq!(out_row.len(), row.len(), "an index loses no operand");
    debug_assert_eq!(max_xhi.len(), row.len(), "one reach per index row");
    debug_assert!(
        out_bbox.windows(2).all(|w| w[0].xlo <= w[1].xlo),
        "the index is ordered by xlo"
    );
    debug_assert!(
        max_xhi.windows(2).all(|w| w[0] <= w[1]),
        "a running maximum is non-decreasing, which is what the search assumes"
    );
}

/// Replay the box test over every pair, for the observer only.
///
/// A second pass rather than a call from inside the prune loop, and the whole
/// thing sits behind `O::ENABLED` so a production build never codegens it. The
/// prune loop only ever visits the x-window `lo .. hi`, so it never sees the
/// pairs the window itself dropped and could not report them rejected; running
/// the replay after the prune rather than during is also what makes the observed
/// and unobserved answers identical by construction, and walking the operands in
/// the same nesting is what makes `kept` come out in the order the caller was
/// handed. Same shape as `core::index::report_prune`, for the same reasons.
fn report_prune<O: ObservePrefilter>(
    a_row: &[PolyId],
    a_box: &[Bbox],
    b_row: &[PolyId],
    b_box: &[Bbox],
    observer: &mut O,
) {
    debug_assert!(O::ENABLED, "the null adapter must never reach this loop");
    debug_assert_eq!(a_row.len(), a_box.len(), "one store row per operand polygon");
    debug_assert_eq!(b_row.len(), b_box.len(), "one store row per operand polygon");
    // The `if` stays: both sides are one observer call, the split is the whole
    // point of the replay, and this loop exists only when a test adapter is
    // installed — there is nothing here to make fast.
    for (&left, &left_box) in a_row.iter().zip(a_box) {
        for (&right, &right_box) in b_row.iter().zip(b_box) {
            if left_box.overlaps(right_box) {
                observer.kept(left, right);
            } else {
                observer.rejected(left, right);
            }
        }
    }
}

/// The store row each polygon of a validated layer came from.
///
/// `ValidatedLayer` *records* this — its `ring_poly` column — and exposes it to
/// nobody: the column is private and `PolygonRef` has no accessor, so the only
/// route from a validated polygon back to a [`PolyId`] is the store itself. This
/// recovers it by matching the operand's bounding-box column against the store's:
/// `validate_layer_into` copies `store.poly_bbox(outer)` verbatim and emits outer
/// boundaries in ascending row order, so the operand's column is a subsequence of
/// the column of the layer it was validated from.
///
/// A subsequence can be embedded more than one way, and a layout is full of
/// repeated shapes — an array of vias makes a run of identical boxes, and a
/// drawn/pin layer pair makes two whole columns identical. Under an ambiguous
/// embedding a *greedy* match names a real store row that is not the row the
/// polygon came from, and nothing downstream can tell. So a layer is only
/// accepted here when its embedding is unique, checked by matching from both
/// ends: greedy-from-the-left is the smallest embedding and greedy-from-the-right
/// the largest, so the two agreeing means there is exactly one. Layers are tried
/// in order and the first unambiguous one wins; an ambiguous match is used only
/// if no layer offers an unambiguous one, because the alternative — the index
/// fallback below — is not more truthful, only less specific.
///
/// **Known correctness gap, and it needs a signature to close.** A layer a
/// boolean produced has rows in no store, so it has no preimage at all and falls
/// back to its own index: values in [`PolyId`]'s space that do not name store
/// rows and cannot be told apart from ones that do. `ValidatedLayer` holds the
/// answer in its private `ring_poly` column; reading it needs
/// `ValidatedLayer::provenance(&self) -> &[PolyId]` in `core`. That accessor also
/// closes the cost — this is O(store rows) per operand where reading a column is
/// O(operand). Filed in `docs/SIGNATURE_DEFECTS.md`.
fn provenance_into(store: &GeometryStore, want: &[Bbox], out: &mut Vec<PolyId>) {
    debug_assert!(
        !want.is_empty(),
        "the caller returns before an empty operand reaches here, or every layer would match"
    );
    out.clear();
    out.reserve(want.len());

    // A loop over the deck's layer table: tens of rows, not bulk data.
    let mut ambiguous: Option<LayerId> = None;
    for layer in 0..store.layer_count() {
        let layer = LayerId(u16::try_from(layer).expect("a layer table is indexed by a u16"));
        if !match_layer(store, layer, want, out) {
            continue;
        }
        if embedding_is_unique(store, layer, want, out) {
            check_recovered(store, layer, want, out);
            return;
        }
        ambiguous = ambiguous.or(Some(layer));
    }

    // Nothing identified the operand outright. A single ambiguous layer is still
    // the right layer; only which of its repeated boxes is which is unknown.
    if let Some(layer) = ambiguous {
        let matched = match_layer(store, layer, want, out);
        debug_assert!(
            matched,
            "the embedding found on the first pass is still there"
        );
        check_recovered(store, layer, want, out);
        return;
    }

    // No store preimage, so the operand is a boolean result. Its polygons are
    // still distinct and still ascending, which is everything the caller's
    // ordering guarantee rests on; the blame a report can assign is what is
    // lost, and the doc comment above says why closing that needs an accessor.
    out.clear();
    out.extend(
        (0..want.len()).map(|i| PolyId(u32::try_from(i).expect("a polygon count fits a u32"))),
    );
    debug_assert_eq!(out.len(), want.len());
}

/// Greedy left-to-right embedding of `want` in one layer's box column.
///
/// **Transform, gatherer.** `out` is cleared and refilled with the store rows
/// matched; true when every wanted box found one, which is what makes the layer
/// a candidate preimage.
///
/// The match cursor is `out.len()`, so row k reads what row k−1 wrote: a serial
/// chain, and nothing to vectorise. The `if` is the match itself — on the layer
/// the operand was validated from every row hits, so it predicts at ~100%, and
/// on a layer that is not it the scan is wasted rather than wrong.
fn match_layer(
    store: &GeometryStore,
    layer: LayerId,
    want: &[Bbox],
    out: &mut Vec<PolyId>,
) -> bool {
    let col = store.layer_bboxes(layer);
    out.clear();
    if col.len() < want.len() {
        return false;
    }
    let start = store.polys_on_layer(layer).start;
    for (offset, &bb) in col.iter().enumerate() {
        let at = out.len();
        if at < want.len() && bb == want[at] {
            let row = u32::try_from(offset).expect("a store row fits a u32");
            out.push(PolyId(start + row));
        }
    }
    out.len() == want.len()
}

/// Is `found` the only way `want` embeds in this layer's box column?
///
/// `found` is the greedy left-to-right embedding, which is the smallest one.
/// Matching from the right gives the largest. Equal at every position means
/// there is exactly one embedding, so the recovered rows are the rows the
/// operand was validated from rather than merely rows that look like them.
///
/// Same chain shape as [`match_layer`], walked the other way, and it exits early
/// on the first disagreement because one is enough.
fn embedding_is_unique(
    store: &GeometryStore,
    layer: LayerId,
    want: &[Bbox],
    found: &[PolyId],
) -> bool {
    debug_assert_eq!(
        found.len(),
        want.len(),
        "a full embedding was already found"
    );
    let col = store.layer_bboxes(layer);
    let start = store.polys_on_layer(layer).start;
    let mut at = want.len();
    for (offset, &bb) in col.iter().enumerate().rev() {
        if at > 0 && bb == want[at - 1] {
            at -= 1;
            let row = u32::try_from(offset).expect("a store row fits a u32");
            if found[at] != PolyId(start + row) {
                return false;
            }
        }
    }
    debug_assert_eq!(at, 0, "the left-to-right pass matched every wanted box");
    true
}

/// The shape a recovered preimage has to have, wherever it came from.
fn check_recovered(store: &GeometryStore, layer: LayerId, want: &[Bbox], out: &[PolyId]) {
    debug_assert_eq!(out.len(), want.len(), "one store row per operand polygon");
    debug_assert!(
        out.windows(2).all(|w| w[0] < w[1]),
        "a layer's rows are ascending, so a subsequence of them is too"
    );
    debug_assert!(
        out.iter()
            .zip(want)
            .all(|(&row, &bb)| store.poly_bbox(row) == bb),
        "a recovered row has the box of the polygon it was recovered for"
    );
    debug_assert!(
        out.last()
            .is_some_and(|&last| last.0 < store.polys_on_layer(layer).end),
        "a recovered row belongs to the layer it was recovered from"
    );
}

#[cfg(test)]
mod tests {
    //! The completeness property, asserted at the seam.
    //!
    //! `candidates_into` returns a superset, so keeping a pair that turns out
    //! to contribute nothing costs time and nothing else. Rejecting a pair that
    //! would have contributed costs a verdict, and produces a shorter, entirely
    //! well-formed operand list on the way out. Only the observer sees the
    //! difference.
    //!
    //! The oracle is exhaustive pairing on inputs small enough to pair
    //! exhaustively. The test builds the rectangles, so it knows every bounding
    //! box in plain `i64` before the store exists, and it computes the answer
    //! from those rather than from anything the crate under test provides.

    use super::{candidates_observed, ObservePrefilter};
    use gpurify_core::observe::Observer;
    use gpurify_core::view::validate_layer_into;
    use gpurify_core::{GeometryStore, LayerId, PolyId, ValidatedLayer};
    use gpurify_testgen::shapes::{Handle, Ids, LayoutBuilder};
    use gpurify_testgen::Rng;

    const OPERAND_A: LayerId = LayerId(0);
    const OPERAND_B: LayerId = LayerId(1);
    const LAYER_COUNT: usize = 2;

    /// An inclusive bounding box, as the test wrote it.
    type Extent = [i64; 4];

    /// Records both halves of the seam, in the order they were reported.
    #[derive(Debug, Default)]
    struct Record {
        kept: Vec<(PolyId, PolyId)>,
        rejected: Vec<(PolyId, PolyId)>,
    }

    impl Observer for Record {
        const ENABLED: bool = true;
    }

    impl ObservePrefilter for Record {
        fn kept(&mut self, a: PolyId, b: PolyId) {
            self.kept.push((a, b));
        }
        fn rejected(&mut self, a: PolyId, b: PolyId) {
            self.rejected.push((a, b));
        }
    }

    /// Do two boxes share at least one point?
    ///
    /// **Inclusive: touching counts.** That is `core::bbox::Bbox::overlaps`'s
    /// stated convention and this module is the same prune at a different seam.
    /// It is also the direction that fails closed — two shapes sharing an edge
    /// merge under a union, so a prune that dropped the pair would remove area
    /// from a derived layer.
    fn overlaps(p: Extent, q: Extent) -> bool {
        p[0] <= q[2] && q[0] <= p[2] && p[1] <= q[3] && q[1] <= p[3]
    }

    /// Rectangles with extents the caller keeps, so the expected answer is
    /// arithmetic on numbers the test chose rather than a second reading of the
    /// store.
    fn push_rects(layout: &mut LayoutBuilder, layer: LayerId, boxes: &[Extent]) -> Vec<Handle> {
        boxes
            .iter()
            .map(|&[xlo, ylo, xhi, yhi]| layout.rect(layer, xlo, ylo, xhi, yhi))
            .collect()
    }

    /// Pseudo-random rectangles in a window small enough that overlaps are
    /// common and disjoint pairs are common, which is what makes both halves of
    /// the property load-bearing.
    fn random_extents(rng: &mut Rng, count: usize, window: i64, max_side: i64) -> Vec<Extent> {
        (0..count)
            .map(|_| {
                let xlo = rng.range(-window, window);
                let ylo = rng.range(-window, window);
                [
                    xlo,
                    ylo,
                    xlo + rng.range(1, max_side + 1),
                    ylo + rng.range(1, max_side + 1),
                ]
            })
            .collect()
    }

    /// Extents indexed by the store row each rectangle became.
    fn by_poly_id(ids: &Ids, groups: &[(&[Handle], &[Extent])], total: usize) -> Vec<Extent> {
        let mut table = vec![[0i64; 4]; total];
        for (handles, boxes) in groups {
            for (&handle, &extent) in handles.iter().zip(*boxes) {
                table[ids.of(handle).idx()] = extent;
            }
        }
        table
    }

    /// Validate both layers of a store into fresh buffers.
    fn validated(store: &GeometryStore) -> (ValidatedLayer, ValidatedLayer) {
        let mut a = ValidatedLayer::default();
        let mut b = ValidatedLayer::default();
        validate_layer_into(store, OPERAND_A, &mut a).expect("rectangles are valid geometry");
        validate_layer_into(store, OPERAND_B, &mut b).expect("rectangles are valid geometry");
        (a, b)
    }

    /// Oracle: adapter. The property is stated over the rejected set, which is
    /// invisible in the return value, and checked against exhaustive pairing —
    /// eight rectangles against seven is fifty-six cross pairs, so "exhaustive"
    /// is a nested loop.
    ///
    /// Both directions are asserted, and both are needed. That no rejected pair
    /// overlaps is the correctness claim. That every overlapping pair survives
    /// is what stops a prune from satisfying the first claim by rejecting
    /// nothing and emitting nothing.
    #[test]
    fn no_rejected_pair_could_have_contributed_to_the_exact_result() {
        for seed in [1u64, 2, 3, 5, 8] {
            let mut rng = Rng::new(seed);
            let a_boxes = random_extents(&mut rng, 8, 300, 180);
            let b_boxes = random_extents(&mut rng, 7, 300, 180);

            let mut layout = LayoutBuilder::new(LAYER_COUNT);
            let a_handles = push_rects(&mut layout, OPERAND_A, &a_boxes);
            let b_handles = push_rects(&mut layout, OPERAND_B, &b_boxes);
            let total = layout.len() as usize;
            let (store, ids) = layout.finish();
            let extent = by_poly_id(
                &ids,
                &[(&a_handles, &a_boxes), (&b_handles, &b_boxes)],
                total,
            );

            let (a, b) = validated(&store);
            let mut out = Vec::new();
            let mut seam = Record::default();
            candidates_observed(&store, &a, &b, &mut out, &mut seam);

            for (&handle_a, &box_a) in a_handles.iter().zip(&a_boxes) {
                for (&handle_b, &box_b) in b_handles.iter().zip(&b_boxes) {
                    if !overlaps(box_a, box_b) {
                        continue;
                    }
                    let pair = (ids.of(handle_a), ids.of(handle_b));
                    assert!(
                        out.contains(&pair),
                        "seed {seed}: {pair:?} has overlapping boxes {box_a:?} and {box_b:?} \
                         but was not offered for exact evaluation"
                    );
                }
            }

            for &(left, right) in &seam.rejected {
                assert!(
                    !overlaps(extent[left.idx()], extent[right.idx()]),
                    "seed {seed}: ({left:?}, {right:?}) was rejected on boxes \
                     {:?} and {:?}, which do share a point",
                    extent[left.idx()],
                    extent[right.idx()]
                );
            }

            // The prune is only ever a superset, so "reject nothing" is a legal
            // reading of the interface and passes every assertion above while
            // doing no work at all. Counting the disjoint pairs the test built
            // itself is the check that it ran: on a window of 600 with sides of
            // at most 180, most of the fifty-six cross pairs miss each other.
            let disjoint = a_boxes
                .iter()
                .flat_map(|&box_a| b_boxes.iter().map(move |&box_b| (box_a, box_b)))
                .filter(|&(box_a, box_b)| !overlaps(box_a, box_b))
                .count();
            assert!(
                disjoint > 0 && !seam.rejected.is_empty(),
                "seed {seed}: {disjoint} of the cross pairs are disjoint and the \
                 prefilter rejected none of them, so it examined nothing"
            );
        }
    }

    /// Oracle: adapter. The kept half of the seam has to agree with what the
    /// caller is handed, or the rejected half proves nothing about the output:
    /// a prune could report every pair kept and then emit half of them.
    #[test]
    fn the_pairs_reported_kept_are_exactly_the_pairs_emitted() {
        let mut rng = Rng::new(13);
        let a_boxes = random_extents(&mut rng, 6, 240, 160);
        let b_boxes = random_extents(&mut rng, 6, 240, 160);

        let mut layout = LayoutBuilder::new(LAYER_COUNT);
        push_rects(&mut layout, OPERAND_A, &a_boxes);
        push_rects(&mut layout, OPERAND_B, &b_boxes);
        let (store, _) = layout.finish();

        let (a, b) = validated(&store);
        let mut out = vec![(PolyId(u32::MAX), PolyId(u32::MAX))];
        let mut seam = Record::default();
        candidates_observed(&store, &a, &b, &mut out, &mut seam);

        assert_eq!(
            out, seam.kept,
            "the pairs the caller receives and the pairs the seam reports kept differ"
        );
        assert!(
            out.windows(2).all(|pair| pair[0] < pair[1]),
            "candidates must be emitted in ascending order and without repeats: {out:?}"
        );
        for pair in &seam.rejected {
            assert!(
                !out.contains(pair),
                "{pair:?} was reported both kept and rejected"
            );
        }
    }

    /// Oracle: construct-from-answer, aimed at the one mistake this prune has a
    /// documented history of. Two rectangles sharing exactly one edge interact:
    /// their union is a single polygon. A strict overlap test rejects that pair
    /// and every downstream check re-verifies only what survives, so nothing
    /// else in the tree would notice.
    #[test]
    fn two_operands_touching_along_an_edge_are_kept() {
        let a_boxes: Vec<Extent> = vec![[0, 0, 100, 100]];
        let b_boxes: Vec<Extent> = vec![[100, 0, 200, 100], [500, 500, 600, 600]];

        let mut layout = LayoutBuilder::new(LAYER_COUNT);
        let a_handles = push_rects(&mut layout, OPERAND_A, &a_boxes);
        let b_handles = push_rects(&mut layout, OPERAND_B, &b_boxes);
        let (store, ids) = layout.finish();

        let (a, b) = validated(&store);
        let mut out = Vec::new();
        let mut seam = Record::default();
        candidates_observed(&store, &a, &b, &mut out, &mut seam);

        let touching = (ids.of(a_handles[0]), ids.of(b_handles[0]));
        assert!(
            out.contains(&touching),
            "{touching:?} share the line x = 100 and merge under a union, but the \
             prune dropped the pair; emitted {out:?}"
        );
        assert!(
            seam.kept.contains(&touching),
            "{touching:?} reached the caller without being reported at the seam, \
             so the seam does not describe what the prune did"
        );
        assert!(
            !seam.rejected.contains(&touching),
            "{touching:?} was reported rejected as well as kept"
        );

        // The other half of the fixture, and the reason a prune that keeps
        // everything does not pass this test: these two boxes are four hundred
        // units apart in both axes. Keeping the pair is legal under the
        // superset clause and would mean the bounding-box comparison never ran.
        let distant = (ids.of(a_handles[0]), ids.of(b_handles[1]));
        assert!(
            seam.rejected.contains(&distant) && !out.contains(&distant),
            "{distant:?} span [0, 100] and [500, 600] in both axes and cannot \
             interact, but the prune offered the pair for exact evaluation"
        );
    }

    /// Oracle: determinism. The doc comment states pairs come out in ascending
    /// order *regardless of index layout*, which is a claim about repeat runs:
    /// the same operands must produce the same list, and a reused output buffer
    /// must be cleared rather than appended to.
    #[test]
    fn the_same_operands_produce_the_same_candidate_list_twice() {
        let mut rng = Rng::new(21);
        let a_boxes = random_extents(&mut rng, 9, 260, 150);
        let b_boxes = random_extents(&mut rng, 9, 260, 150);

        let mut layout = LayoutBuilder::new(LAYER_COUNT);
        push_rects(&mut layout, OPERAND_A, &a_boxes);
        push_rects(&mut layout, OPERAND_B, &b_boxes);
        let (store, _) = layout.finish();

        let (a, b) = validated(&store);
        let mut first = Vec::new();
        super::candidates_into(&store, &a, &b, &mut first);
        let mut second = first.clone();
        super::candidates_into(&store, &a, &b, &mut second);

        assert_eq!(
            first, second,
            "two runs over the same operands disagreed, or the output buffer was \
             appended to rather than cleared"
        );
    }
}
