//! Spatial index and candidate-pair generation.
//!
//! This is the module that stops every pairwise rule being O(n²), and it is the
//! module whose mistakes are invisible. It carries a test adapter for that
//! reason — see [`crate::observe`] for why "cheap" is not the standard.

use crate::bbox::Bbox;
use crate::ids::{LayerId, PolyId};
use crate::observe::{NoObserve, Observer};
use crate::store::GeometryStore;
use gpurify_units::Dbu;

/// A uniform grid over one layer's bounding boxes.
///
/// **Five questions.** In: a bounding-box column. Out: bucket offsets and a
/// row-id list. How many: one per layer per run. Access pattern: built once,
/// scanned many times, always in bucket order — so it is CSR, not a map of
/// vectors. Lifetime: phase; cleared and rebuilt per layer from one reusable
/// allocation. Parallelisable: bucket counting is a histogram, and the scan
/// over buckets partitions cleanly.
///
/// A uniform grid rather than a tree because layout geometry is close to
/// uniformly dense at the scale that matters, and a grid's build is a counting
/// sort with no pointer chasing.
///
/// ponytail: uniform grid, cell size derived from the median bounding-box
/// extent. Degrades on a layer mixing one reticle-sized shape with a million
/// contacts. Upgrade to a two-level grid if the scale corpus shows it; the
/// interface does not change.
#[derive(Debug, Default)]
pub struct SpatialIndex {
    layer: Option<LayerId>,
    cell_size: Dbu,
    /// The region the grid covers: the union of the layer's bounding boxes.
    extent: Bbox,
    /// `bucket_start[b] .. bucket_start[b + 1]` indexes `rows`.
    bucket_start: Vec<u32>,
    /// Store row ids, grouped by bucket.
    rows: Vec<u32>,
}

impl SpatialIndex {
    /// Build over one layer.
    ///
    /// **Transform.** Caller owns the index and it is cleared and refilled, so
    /// a loop over layers reuses one allocation.
    pub fn build_into(store: &GeometryStore, layer: LayerId, out: &mut Self) {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        todo!()
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

impl ObservePairs for NoObserve {
    fn emitted(&mut self, a: PolyId, b: PolyId) {}
    fn rejected(&mut self, a: PolyId, b: PolyId) {}
    fn bucket_skipped(&mut self, bucket: u32, rows: u32) {}
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
    todo!()
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
    todo!()
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
