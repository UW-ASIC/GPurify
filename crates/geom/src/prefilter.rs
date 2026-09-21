//! Bounding-box prefiltering for boolean operands.

use crate::observe::{NoObserve, Observer};
use crate::{Bbox, GeometryStore, LayerId, PolyId, ValidatedLayer};
use crate::Dbu;

/// What crossing the prefilter seam did.
pub trait ObservePrefilter: Observer {
    /// A pair was kept for exact evaluation.
    fn kept(&mut self, a: PolyId, b: PolyId);
    /// A pair was rejected on bounding boxes alone — silently wrong if the
    /// pair would have contributed, so this is the half that matters.
    fn rejected(&mut self, a: PolyId, b: PolyId);
}

/// The null adapter: the seam folds away behind `ENABLED == false`.
impl ObservePrefilter for NoObserve {
    fn kept(&mut self, _a: PolyId, _b: PolyId) {}
    fn rejected(&mut self, _a: PolyId, _b: PolyId) {}
}

/// Which operand pairs can possibly interact, ascending and without repeats.
///
/// A superset: a surviving pair may still contribute nothing, but a pair absent
/// from here is never evaluated by anyone.
pub fn candidates_into(
    store: &GeometryStore,
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut Vec<(PolyId, PolyId)>,
) {
    candidates_observed(store, a, b, out, &mut NoObserve);
}

/// [`candidates_into`] with the observer seam exposed.
pub fn candidates_observed<O: ObservePrefilter>(
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

    // An empty operand is an answer, not a refusal, and it keeps
    // `provenance_into` off the case where every layer matches.
    if a_box.is_empty() || b_box.is_empty() {
        return;
    }

    // Scratch is allocated per call: the frozen signature has nowhere to hang a
    // reusable buffer.
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

    for (&left, &left_box) in a_row.iter().zip(a_box) {
        // Everything outside `lo .. hi` is disjoint from `left_box` in x alone,
        // so the exact test below runs only over the x-overlapping window.
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
        // carries the predicate, so `near` is reserved for the whole window.
        near.clear();
        near.reserve(width);
        debug_assert!(
            near.capacity() >= width,
            "the compact reserves for the window, not the survivors"
        );
        let survivors = &mut near.spare_capacity_mut()[..width];
        let mut w = 0usize;
        for (i, (&right, &right_box)) in win_row.iter().zip(win_bbox).enumerate() {
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
            // none. Measured 1.19x at 8k / 1.18x at 200k / 1.06x at 4M.
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

        // The window is in ascending-`xlo` order, so the survivors go back into
        // store-row order for the caller's ascending guarantee.
        near.sort_unstable_by_key(|&(right, _)| right.0);
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

/// One operand's bounding boxes, ordered for interval queries. Indexes the
/// boxes themselves, so it works on a boolean result with rows in no store.
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
    /// The half-open range of index rows whose x-extent can meet `query`. Both
    /// bounds compare inclusively, because [`Bbox::overlaps`] counts a shared
    /// edge.
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
fn build_index(row: &[PolyId], bbox: &[Bbox], out: &mut OperandIndex) {
    debug_assert_eq!(row.len(), bbox.len(), "an operand's columns are parallel");
    debug_assert!(
        !bbox.is_empty(),
        "the caller returns before an empty operand reaches here"
    );

    // Checked rather than cast: a truncation here would silently shorten the
    // permutation and drop polygons.
    let count = u32::try_from(row.len()).expect("one `PolyId` per row bounds the column by u32");
    let mut order: Vec<u32> = (0..count).collect();
    // Ties broken on the operand's own index, so the order is a function of the
    // input and not of the sort's internal choices.
    order.sort_unstable_by_key(|&i| (bbox[i as usize].xlo, i));

    let OperandIndex {
        row: out_row,
        bbox: out_bbox,
        max_xhi,
    } = out;
    // Two gathers over the same permutation, fused into one pass.
    out_row.clear();
    out_row.reserve(order.len());
    out_bbox.clear();
    out_bbox.reserve(order.len());
    for &i in &order {
        let i = i as usize;
        out_row.push(row[i]);
        out_bbox.push(bbox[i]);
    }

    // A prefix scan: row k reads what row k-1 wrote, so it is serial by shape.
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
/// A second pass, not a call from inside the prune loop: the prune only visits
/// the x-window, so it never sees the pairs the window itself dropped.
fn report_prune<O: ObservePrefilter>(
    a_row: &[PolyId],
    a_box: &[Bbox],
    b_row: &[PolyId],
    b_box: &[Bbox],
    observer: &mut O,
) {
    debug_assert!(O::ENABLED, "the null adapter must never reach this loop");
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
/// `ValidatedLayer` records this in a private column with no accessor, so the
/// rows are recovered by matching bounding-box columns: `validate_layer_into`
/// copies boxes verbatim in ascending row order, so an operand's column is a
/// subsequence of the layer it came from.
///
/// A subsequence can embed more than one way — an array of vias is a run of
/// identical boxes — and under an ambiguous embedding a greedy match names a
/// real store row that is not the right one. So a layer is accepted only when
/// its embedding is unique: greedy-from-the-left is the smallest embedding and
/// greedy-from-the-right the largest, so the two agreeing means there is exactly
/// one. An ambiguous match is used only if no layer offers an unambiguous one.
///
/// **Known correctness gap.** A layer a boolean produced has rows in no store,
/// so it falls back to its own index: values in [`PolyId`]'s space that do not
/// name store rows and cannot be told apart from ones that do. Closing it needs
/// `ValidatedLayer::provenance(&self) -> &[PolyId]` in `core`.
fn provenance_into(store: &GeometryStore, want: &[Bbox], out: &mut Vec<PolyId>) {
    debug_assert!(
        !want.is_empty(),
        "the caller returns before an empty operand reaches here, or every layer would match"
    );
    out.clear();
    out.reserve(want.len());

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

    // A single ambiguous layer is still the right layer; only which of its
    // repeated boxes is which is unknown.
    if let Some(layer) = ambiguous {
        let matched = match_layer(store, layer, want, out);
        debug_assert!(
            matched,
            "the embedding found on the first pass is still there"
        );
        check_recovered(store, layer, want, out);
        return;
    }

    // No store preimage, so the operand is a boolean result. The indices are
    // still distinct and ascending, which is all the caller's ordering
    // guarantee needs; what is lost is the blame a report can assign.
    out.clear();
    out.extend(
        (0..want.len()).map(|i| PolyId(u32::try_from(i).expect("a polygon count fits a u32"))),
    );
    debug_assert_eq!(out.len(), want.len());
}

/// Greedy left-to-right embedding of `want` in one layer's box column: fills
/// `out` with the rows matched, true when every wanted box found one.
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
/// `found` is the greedy left-to-right embedding, the smallest one; matching
/// from the right gives the largest. Equal at every position means there is
/// exactly one, so the recovered rows are the rows the operand came from.
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
