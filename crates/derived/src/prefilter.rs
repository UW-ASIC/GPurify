//! Bounding-box prefiltering for boolean operands.

use gpurify_core::observe::{NoObserve, Observer};
use gpurify_core::{Bbox, GeometryStore, LayerId, PolyId, ValidatedLayer};
use gpurify_units::Dbu;

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

#[cfg(test)]
mod tests {
    //! The completeness property, asserted at the observer seam against
    //! exhaustive pairing of extents the test itself chose.

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

    /// Do two boxes share at least one point? Inclusive: touching counts, which
    /// is the direction that fails closed — a shared edge merges under a union.
    fn overlaps(p: Extent, q: Extent) -> bool {
        p[0] <= q[2] && q[0] <= p[2] && p[1] <= q[3] && q[1] <= p[3]
    }

    /// Rectangles whose extents the caller keeps, so the expected answer never
    /// comes from a second reading of the store.
    fn push_rects(layout: &mut LayoutBuilder, layer: LayerId, boxes: &[Extent]) -> Vec<Handle> {
        boxes
            .iter()
            .map(|&[xlo, ylo, xhi, yhi]| layout.rect(layer, xlo, ylo, xhi, yhi))
            .collect()
    }

    /// Pseudo-random rectangles in a window small enough that both overlapping
    /// and disjoint pairs are common.
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

    /// No rejected pair overlaps is the correctness claim; every overlapping
    /// pair surviving stops a prune from emitting nothing.
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

            // "Reject nothing" is a legal superset and passes every assertion
            // above, so count the disjoint pairs the test built itself.
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

    /// The kept half of the seam must agree with what the caller is handed, or
    /// the rejected half proves nothing about the output.
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

    /// Two rectangles sharing exactly one edge interact — their union is a
    /// single polygon — and a strict overlap test would drop the pair with
    /// nothing downstream to notice.
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

        // The other half of the fixture: keep-everything is legal under the
        // superset clause, so a pair four hundred units apart must be rejected.
        let distant = (ids.of(a_handles[0]), ids.of(b_handles[1]));
        assert!(
            seam.rejected.contains(&distant) && !out.contains(&distant),
            "{distant:?} span [0, 100] and [500, 600] in both axes and cannot \
             interact, but the prune offered the pair for exact evaluation"
        );
    }

    /// The same operands produce the same list, and a reused output buffer is
    /// cleared rather than appended to.
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
