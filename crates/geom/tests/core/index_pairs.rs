//! Candidate-pair generation, from outside the crate.
//!
//! Everything here is a statement about the *returned* list: it is a superset
//! of the exact predicate, it is ascending and free of duplicates, and it is
//! the same list twice. The property that is not visible in a return value —
//! that no rejected pair would have passed the exact predicate — cannot be
//! asserted from out here, and its test lives beside the seam in
//! `src/index.rs`.
//!
//! The superset direction is the one that costs correctness. A pair absent from
//! this list is never checked again by anyone, so an over-eager prune is a
//! spacing rule silently passing shapes the foundry would reject. A pair
//! wrongly present costs one exact re-check and nothing else, which is why the
//! comparison below is one-sided.

use gpurify_geom::index::{candidate_pairs_into, cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::{GeometryStore, LayerId, PolyId};
use gpurify_testgen::shapes::{
    dbu, random_rectilinear_layer, spaced_pair, LayoutBuilder, RandomLayerSpec,
};
use gpurify_testgen::Rng;
use gpurify_geom::Dbu;

const A: LayerId = LayerId(0);
const B: LayerId = LayerId(1);

/// The exact predicate the prune is allowed to approximate: two bounding boxes
/// within `distance` on both axes, inclusive. An `O(n²)` scan over it is the
/// oracle — slow, obviously right, and independent of the index.
fn all_pairs_within(store: &GeometryStore, layer: LayerId, distance: Dbu) -> Vec<(PolyId, PolyId)> {
    let rows: Vec<u32> = store.polys_on_layer(layer).collect();
    let mut out = Vec::new();
    for (offset, &a) in rows.iter().enumerate() {
        for &b in &rows[offset + 1..] {
            if store
                .poly_bbox(PolyId(a))
                .within(store.poly_bbox(PolyId(b)), distance)
            {
                out.push((PolyId(a), PolyId(b)));
            }
        }
    }
    out
}

fn all_cross_pairs_within(
    store: &GeometryStore,
    a_layer: LayerId,
    b_layer: LayerId,
    distance: Dbu,
) -> Vec<(PolyId, PolyId)> {
    let mut out = Vec::new();
    for a in store.polys_on_layer(a_layer) {
        for b in store.polys_on_layer(b_layer) {
            if store
                .poly_bbox(PolyId(a))
                .within(store.poly_bbox(PolyId(b)), distance)
            {
                out.push((PolyId(a), PolyId(b)));
            }
        }
    }
    out
}

fn indexed(store: &GeometryStore, layer: LayerId) -> SpatialIndex {
    let mut index = SpatialIndex::default();
    SpatialIndex::build_into(store, layer, &mut index);
    index
}

/// A layer of squares at a known density, plus a second layer offset from it so
/// the cross-layer pairs are non-trivial.
fn two_layers(seed: u64) -> GeometryStore {
    let mut rng = Rng::new(seed);
    let mut layout = LayoutBuilder::new(2);
    let spec = RandomLayerSpec {
        cells: 16,
        cell: 400,
        density: 0.4,
    };
    random_rectilinear_layer(&mut layout, &mut rng, A, (0, 0), spec);
    random_rectilinear_layer(&mut layout, &mut rng, B, (150, 150), spec);
    layout.finish().0
}

/// Oracle: law, against an `O(n²)` scan of the exact predicate. The prune may
/// return extra pairs; it may not lose one. Run across several distances,
/// because the cell size is derived from the geometry and a distance far larger
/// than a cell is where a one-cell search radius stops being enough.
#[test]
fn every_pair_within_the_distance_survives_the_prune() {
    let store = two_layers(81);
    let index = indexed(&store, A);
    assert!(!index.is_empty(), "the corpus produced an empty index");

    let mut out = Vec::new();
    for distance in [0i64, 1, 5, 60, 400, 1_500] {
        candidate_pairs_into(&store, &index, dbu(distance), &mut out);
        let exact = all_pairs_within(&store, A, dbu(distance));
        for pair in &exact {
            assert!(
                out.contains(pair),
                "the prune dropped {pair:?} at a distance of {distance}, \
                 which the exact predicate accepts"
            );
        }
        assert!(
            out.len() >= exact.len(),
            "a superset cannot be shorter than the set it contains"
        );
        if distance >= 60 {
            assert!(!exact.is_empty(), "distance {distance} found no true pair");
        }
    }
}

/// Oracle: law. Pairs come out with `a < b` and in ascending order with no
/// duplicates. That is part of the interface, not a detail: output ordering is
/// gated, and a rule that reported one violation per candidate would report it
/// twice for a duplicated pair.
#[test]
fn pairs_are_ascending_deduplicated_and_ordered_the_same_way_twice() {
    let store = two_layers(82);
    let index = indexed(&store, A);

    let mut out = Vec::new();
    candidate_pairs_into(&store, &index, dbu(250), &mut out);
    assert!(!out.is_empty(), "the comparison would be vacuous");

    for &(a, b) in &out {
        assert!(a < b, "{a:?} and {b:?} are not in ascending order");
        assert_eq!(store.poly_layer(a), A, "{a:?} is not on the queried layer");
        assert_eq!(store.poly_layer(b), A, "{b:?} is not on the queried layer");
    }
    assert!(
        out.windows(2).all(|w| w[0] < w[1]),
        "the pair list is not strictly ascending, so it holds a duplicate"
    );

    // The same call into a buffer that already holds a longer answer: cleared
    // and refilled, not appended to.
    let first = out.clone();
    candidate_pairs_into(&store, &index, dbu(250), &mut out);
    assert_eq!(out, first, "candidate pairs are not reproducible");

    // Rebuilding the index into a reused allocation must not change the answer
    // either — that is the other half of the determinism gate here.
    let mut reused = indexed(&store, B);
    SpatialIndex::build_into(&store, A, &mut reused);
    candidate_pairs_into(&store, &reused, dbu(250), &mut out);
    assert_eq!(out, first, "rebuilding the index changed the pair list");
}

/// Oracle: construct-from-answer. Two squares placed an exact gap apart are a
/// candidate at that gap and, since the prune is a superset, still a candidate
/// at anything larger. The generator fixes the geometry, so the answer is known
/// before the index is built.
#[test]
fn a_pair_at_exactly_the_distance_is_a_candidate() {
    let mut layout = LayoutBuilder::new(1);
    let (left, right) = spaced_pair(&mut layout, A, (0, 0), 40, 100);
    // A third shape far away, so the index has more than one occupied cell and
    // the answer is not "everything, trivially".
    let lonely = layout.rect(A, 100_000, 100_000, 100_100, 100_100);
    let (store, ids) = layout.finish();

    let (a, b) = (ids.of(left), ids.of(right));
    let expected = (a.min(b), a.max(b));
    let far = ids.of(lonely);

    let index = indexed(&store, A);
    let mut out = Vec::new();

    for distance in [40i64, 41, 100] {
        candidate_pairs_into(&store, &index, dbu(distance), &mut out);
        assert!(
            out.contains(&expected),
            "the pair forty units apart is not a candidate at {distance}"
        );
        assert!(
            !out.contains(&(expected.0.min(far), expected.0.max(far))),
            "a shape a hundred thousand units away is a candidate at {distance}"
        );
    }

    // One unit short of the gap the generator placed: the exact predicate says
    // no, so the prune is allowed to say no, and the scan below is what decides
    // whether it did.
    candidate_pairs_into(&store, &index, dbu(39), &mut out);
    for pair in all_pairs_within(&store, A, dbu(39)) {
        assert!(
            out.contains(&pair),
            "{pair:?} was dropped at a distance of 39"
        );
    }
}

/// Oracle: law, again against an `O(n²)` scan. Cross-layer pairing is a
/// separate function because it cannot use `a < b` to halve its work, so it is
/// a separate chance to drop a pair — and the pairs it emits must name one
/// polygon from each layer, in that order.
#[test]
fn every_cross_layer_pair_within_the_distance_survives_the_prune() {
    let store = two_layers(83);
    let a_index = indexed(&store, A);
    let b_index = indexed(&store, B);

    let mut out = Vec::new();
    for distance in [0i64, 10, 200, 900] {
        cross_layer_pairs_into(&store, &a_index, &b_index, dbu(distance), &mut out);
        let exact = all_cross_pairs_within(&store, A, B, dbu(distance));
        for pair in &exact {
            assert!(
                out.contains(pair),
                "the cross-layer prune dropped {pair:?} at a distance of {distance}"
            );
        }
        for &(a, b) in &out {
            assert_eq!(store.poly_layer(a), A, "{a:?} is on the wrong layer");
            assert_eq!(store.poly_layer(b), B, "{b:?} is on the wrong layer");
        }
        assert!(
            out.windows(2).all(|w| w[0] < w[1]),
            "the cross-layer list is not strictly ascending at {distance}"
        );
    }
    assert!(!out.is_empty(), "no cross-layer pair was ever found");

    // Determinism, including a rebuild of both indices into reused buffers.
    let first = out.clone();
    cross_layer_pairs_into(&store, &a_index, &b_index, dbu(900), &mut out);
    assert_eq!(out, first, "cross-layer pairs are not reproducible");
}

/// Oracle: construct-from-answer. A layer with no geometry indexes to an empty
/// index and yields no pairs, and a layer with one polygon yields none either —
/// there is no pair to make. Both must be answers rather than errors, because a
/// PDK's layer table is mostly empty layers.
#[test]
fn an_empty_or_single_polygon_layer_yields_no_pairs() {
    let mut layout = LayoutBuilder::new(3);
    let low = layout.rect(A, 0, 0, 10, 10);
    let high = layout.rect(A, 5, 5, 15, 15);
    layout.rect(B, 0, 0, 10, 10);
    let (store, ids) = layout.finish();

    let empty = indexed(&store, LayerId(2));
    assert!(
        empty.is_empty(),
        "a layer with no geometry indexes to nothing"
    );

    let mut out = vec![(PolyId(9), PolyId(9))];
    candidate_pairs_into(&store, &empty, dbu(1_000), &mut out);
    assert!(out.is_empty(), "an empty index produced pairs");

    let single = indexed(&store, B);
    assert!(!single.is_empty(), "one polygon is still an index");
    candidate_pairs_into(&store, &single, dbu(1_000), &mut out);
    assert!(out.is_empty(), "one polygon cannot make a pair");

    // The occupied layer does produce its one pair, so the assertions above are
    // measuring emptiness rather than a function that never emits anything. The
    // pair is named, not counted: a prune emitting one pair of the wrong two
    // polygons satisfies a count and satisfies nothing else.
    let occupied = indexed(&store, A);
    candidate_pairs_into(&store, &occupied, dbu(0), &mut out);
    let (a, b) = (ids.of(low), ids.of(high));
    assert_eq!(
        out,
        vec![(a.min(b), a.max(b))],
        "two overlapping squares are one candidate pair, and it names those two"
    );

    // And a cross-layer query against the empty index is empty from either side.
    cross_layer_pairs_into(&store, &occupied, &empty, dbu(1_000), &mut out);
    assert!(out.is_empty());
    cross_layer_pairs_into(&store, &empty, &occupied, dbu(1_000), &mut out);
    assert!(out.is_empty());
}

/// Oracle: law. Candidate pairing is a statement about relative positions, so
/// translating every shape translates nothing about which pairs are candidates.
/// The pair list must come back identical up to the row renumbering, and since
/// a uniform translation preserves the store's row order it comes back
/// identical outright.
#[test]
fn the_candidate_list_is_invariant_under_translation_of_every_shape() {
    let mut rng = Rng::new(84);
    let spec = RandomLayerSpec {
        cells: 12,
        cell: 300,
        density: 0.5,
    };

    let mut base_layout = LayoutBuilder::new(1);
    random_rectilinear_layer(&mut base_layout, &mut Rng::new(84), A, (0, 0), spec);
    let base_store = base_layout.finish().0;
    let mut base_pairs = Vec::new();
    candidate_pairs_into(
        &base_store,
        &indexed(&base_store, A),
        dbu(150),
        &mut base_pairs,
    );
    assert!(!base_pairs.is_empty(), "the comparison would be vacuous");

    for _ in 0..6 {
        let origin = (rng.range(-400_000, 400_000), rng.range(-400_000, 400_000));
        let mut layout = LayoutBuilder::new(1);
        random_rectilinear_layer(&mut layout, &mut Rng::new(84), A, origin, spec);
        let store = layout.finish().0;

        let mut pairs = Vec::new();
        candidate_pairs_into(&store, &indexed(&store, A), dbu(150), &mut pairs);
        assert_eq!(
            pairs, base_pairs,
            "moving the whole layer to {origin:?} changed the candidate pairs"
        );
    }
}

/// Oracle: law. The prune is allowed to be generous but not arbitrary. Every
/// pair it emits names two *distinct* rows of the *queried* layer, and since the
/// list is ascending with `a < b` it cannot be longer than the layer's complete
/// pair count — a list that exceeds that bound is emitting something twice or
/// naming a row it was never given.
///
/// Layer membership is the assertion that carries this test. Checking instead
/// that each box lies inside the union of the layer's boxes would be true of
/// every row on the layer by construction, and would therefore fail for nothing.
#[test]
fn no_candidate_pair_names_one_polygon_twice_or_a_row_of_another_layer() {
    let store = two_layers(85);
    let index = indexed(&store, A);
    let mut out = Vec::new();
    candidate_pairs_into(&store, &index, dbu(100), &mut out);
    assert!(!out.is_empty());

    let rows = store.polys_on_layer(A).len();
    assert!(rows >= 2, "the corpus cannot make a pair");
    assert!(
        out.len() <= rows * (rows - 1) / 2,
        "{} pairs is more than the {rows} rows of layer A can make",
        out.len()
    );

    for &(a, b) in &out {
        assert_ne!(a, b, "a polygon was paired with itself");
        assert_eq!(store.poly_layer(a), A, "{a:?} is not on the queried layer");
        assert_eq!(store.poly_layer(b), A, "{b:?} is not on the queried layer");
    }
}
