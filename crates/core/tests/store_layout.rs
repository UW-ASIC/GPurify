//! The store's one structural invariant: rows are grouped by layer, and the
//! permutation `finish` returns is the map back to the order they arrived in.
//!
//! `ingest` permutes its provenance columns by that permutation. Nothing in the
//! type system holds the two tables together, so if the permutation is wrong a
//! violation is reported against the wrong cell of the wrong instance and every
//! geometric assertion in the tree still passes. That is the whole reason this
//! file exists.

use gpurify_core::{Bbox, GeometryStore, GeometryStoreBuilder, LayerId, PolyId};
use gpurify_testgen::shapes::{dbu, l_shape, rect, u_shape, LayoutBuilder};
use gpurify_testgen::Rng;
use gpurify_units::Dbu;

const LAYERS: usize = 5;

/// A coordinate run as the generator hands it over: parallel `i64` columns.
type Shape = (Vec<i64>, Vec<i64>);

/// The two columns as the store stores them, for comparing against what came
/// back out of it.
fn columns(shape: &Shape) -> (Vec<Dbu>, Vec<Dbu>) {
    (
        shape.0.iter().copied().map(dbu).collect(),
        shape.1.iter().copied().map(dbu).collect(),
    )
}

/// The shapes every test in this file builds from, in arrival order: layers
/// interleaved, one layer left with no geometry at all, and a shape on the last
/// layer so the trailing offset is not the easy case.
fn arrival_order() -> Vec<(LayerId, Shape)> {
    vec![
        (LayerId(3), rect(0, 0, 10, 10)),
        (LayerId(0), rect(100, 100, 140, 130)),
        (LayerId(3), l_shape(50, 50, 40, 12)),
        (LayerId(0), u_shape(-200, -200, 60, 10, 20)),
        (LayerId(4), rect(-10, -10, -5, -5)),
        (LayerId(0), rect(7, -300, 27, -280)),
        (LayerId(3), rect(1_000, 1_000, 1_010, 1_040)),
        (LayerId(1), rect(-1_000, 500, -900, 600)),
    ]
}

fn build() -> (GeometryStore, Vec<u32>) {
    let mut builder = GeometryStoreBuilder::default();
    for (row, (layer, shape)) in arrival_order().into_iter().enumerate() {
        let stored = columns(&shape);
        let assigned = builder.push(layer, &stored.0, &stored.1);
        assert_eq!(
            assigned as usize, row,
            "push must return the pre-sort row index"
        );
    }
    builder.finish(LAYERS)
}

/// Oracle: construct-from-answer. The test knows which layer each shape was
/// pushed onto and in what order, so it knows what the permutation must say.
/// `permutation[new_row] == old_row` is the contract `ingest` relies on, and it
/// is checked here against the arrival list rather than against the store.
#[test]
fn the_permutation_maps_every_sorted_row_back_to_the_row_it_arrived_as() {
    let arrivals = arrival_order();
    let (store, permutation) = build();

    assert_eq!(store.poly_count(), arrivals.len());
    assert_eq!(store.layer_count(), LAYERS);
    assert_eq!(permutation.len(), arrivals.len());

    // A permutation, not merely a map: every arrival row appears exactly once.
    let mut seen = permutation.clone();
    seen.sort_unstable();
    let expected: Vec<u32> =
        (0..u32::try_from(arrivals.len()).expect("eight rows fit a u32")).collect();
    assert_eq!(seen, expected, "the permutation is not a bijection");

    for (new_row, &old_row) in permutation.iter().enumerate() {
        let id = PolyId(u32::try_from(new_row).expect("eight rows fit a u32"));
        let (layer, shape) = &arrivals[old_row as usize];
        assert_eq!(store.poly_layer(id), *layer, "row {new_row} changed layer");

        let stored = columns(shape);
        assert_eq!(
            store.poly_verts(id),
            (stored.0.as_slice(), stored.1.as_slice()),
            "row {new_row} lost its coordinates"
        );
    }
}

/// Oracle: law. The layer offsets are CSR, so the ranges must be consecutive,
/// must cover every row exactly once, and must agree row for row with
/// `poly_layer`. A layer with no geometry is an empty range in the middle of
/// that chain, not a gap and not an error.
#[test]
fn layer_ranges_partition_every_row_and_an_empty_layer_is_an_empty_range() {
    let (store, _) = build();

    let mut boundary = 0u32;
    for l in 0..LAYERS {
        let layer = LayerId(u16::try_from(l).expect("five layers fit a u16"));
        let range = store.polys_on_layer(layer);
        assert_eq!(
            range.start,
            boundary,
            "layer {l} does not start where {} ended",
            l.saturating_sub(1)
        );
        assert!(range.end >= range.start, "layer {l} has an inverted range");
        for row in range.clone() {
            assert_eq!(
                store.poly_layer(PolyId(row)),
                layer,
                "row {row} is misfiled"
            );
        }
        boundary = range.end;
    }
    assert_eq!(
        boundary as usize,
        store.poly_count(),
        "the layer ranges do not cover the store"
    );

    // Layer 2 was never pushed onto. It has to answer with an empty range so a
    // rule naming it reports no violations rather than failing to find it.
    assert!(store.polys_on_layer(LayerId(2)).is_empty());
    assert!(store.layer_bboxes(LayerId(2)).is_empty());

    // Counts by layer, from the arrival list.
    for (layer, count) in [(0u16, 3usize), (1, 1), (2, 0), (3, 3), (4, 1)] {
        assert_eq!(
            store.polys_on_layer(LayerId(layer)).len(),
            count,
            "layer {layer}"
        );
    }
}

/// Oracle: law. A polygon's precomputed bounding box is by definition the fold
/// of `include` over that polygon's own vertices and nothing else, and
/// `layer_bboxes` is exactly the column slice covered by the layer's range. Two
/// derived views of one column agreeing is what stops the offset arithmetic
/// drifting.
#[test]
fn every_bounding_box_is_the_box_of_that_polygons_own_vertices() {
    let (store, _) = build();

    for row in 0..u32::try_from(store.poly_count()).expect("eight rows fit a u32") {
        let id = PolyId(row);
        let (xs, ys) = store.poly_verts(id);
        assert_eq!(store.poly_bbox(id), Bbox::of_points(xs, ys), "row {row}");
    }

    for l in 0..LAYERS {
        let layer = LayerId(u16::try_from(l).expect("five layers fit a u16"));
        let range = store.polys_on_layer(layer);
        let column = store.layer_bboxes(layer);
        assert_eq!(column.len(), range.len(), "layer {l} column length");
        for (offset, row) in range.enumerate() {
            assert_eq!(column[offset], store.poly_bbox(PolyId(row)), "layer {l}");
        }
    }
}

/// Oracle: determinism. The store is the input to every downstream verdict, so
/// two builds of the same pushes must agree on the permutation, the layer
/// column, the coordinate columns and the bounding boxes. Pre-sizing is an
/// allocation decision and must not be a semantic one, so the second build uses
/// `with_capacity` and the third the default.
#[test]
fn two_builds_of_the_same_pushes_agree_on_every_column() {
    let arrivals = arrival_order();
    let vertices: usize = arrivals.iter().map(|(_, shape)| shape.0.len()).sum();

    let mut sized = GeometryStoreBuilder::with_capacity(arrivals.len(), vertices);
    for (layer, shape) in &arrivals {
        let stored = columns(shape);
        sized.push(*layer, &stored.0, &stored.1);
    }
    let (sized_store, sized_permutation) = sized.finish(LAYERS);

    let (first_store, first_permutation) = build();
    let (second_store, second_permutation) = build();

    assert_eq!(first_permutation, second_permutation);
    assert_eq!(
        first_permutation, sized_permutation,
        "capacity changed order"
    );

    for store in [&second_store, &sized_store] {
        assert_eq!(store.poly_count(), first_store.poly_count());
        assert_eq!(store.layer_count(), first_store.layer_count());
        for row in 0..u32::try_from(first_store.poly_count()).expect("eight rows fit a u32") {
            let id = PolyId(row);
            assert_eq!(store.poly_layer(id), first_store.poly_layer(id));
            assert_eq!(store.poly_bbox(id), first_store.poly_bbox(id));
            assert_eq!(store.poly_verts(id), first_store.poly_verts(id));
        }
    }
}

/// Oracle: law. Sorting by layer regroups rows and must not lose, duplicate or
/// relabel one: the arrival rows a layer's range names are exactly the arrivals
/// that were pushed onto that layer. Over four hundred generated shapes, so it
/// is a property of the sort rather than of the eight-row fixture above.
///
/// The *order* within a layer is not asserted here, only the membership. The
/// interface promises more than that as of the Testing-Phase — `finish`'s sort
/// is stable, so a layer's permutation slice is strictly ascending — and this
/// assertion is therefore weaker than the contract rather than at odds with it.
/// Stability itself is a claim about one column, and the determinism test is
/// what reads it.
#[test]
fn regrouping_by_layer_loses_no_row_and_invents_none() {
    let mut rng = Rng::new(31);
    let mut builder = GeometryStoreBuilder::default();
    let mut arrivals_of_layer: Vec<Vec<u32>> = vec![Vec::new(); LAYERS];
    for arrival in 0..400u32 {
        let layer = u16::try_from(rng.below(5)).expect("a draw below five fits a u16");
        let x = rng.range(-50_000, 50_000);
        let y = rng.range(-50_000, 50_000);
        let stored = columns(&rect(x, y, x + rng.range(1, 500), y + rng.range(1, 500)));
        builder.push(LayerId(layer), &stored.0, &stored.1);
        arrivals_of_layer[usize::from(layer)].push(arrival);
    }
    let (store, permutation) = builder.finish(LAYERS);

    for (l, expected) in arrivals_of_layer.iter().enumerate() {
        let layer = LayerId(u16::try_from(l).expect("five layers fit a u16"));
        let mut found: Vec<u32> = store
            .polys_on_layer(layer)
            .map(|row| permutation[row as usize])
            .collect();
        found.sort_unstable();
        assert_eq!(&found, expected, "layer {l} holds the wrong arrivals");
    }
}

/// Oracle: construct-from-answer. `LayoutBuilder` is how every other test in
/// the suite names a shape it deliberately made wrong, and it names it by
/// inverting this permutation. If the two disagree, every construct-from-answer
/// test in the workspace is asserting against the wrong polygon.
#[test]
fn handles_resolve_to_the_rows_holding_the_geometry_they_were_pushed_with() {
    let mut layout = LayoutBuilder::new(LAYERS);
    let mut handles = Vec::new();
    for (layer, shape) in arrival_order() {
        handles.push((layout.shape(layer, &shape), layer, shape));
    }
    assert_eq!(layout.len(), 8);
    let (store, ids) = layout.finish();

    for (handle, layer, shape) in handles {
        let id = ids.of(handle);
        assert_eq!(store.poly_layer(id), layer);
        let stored = columns(&shape);
        assert_eq!(
            store.poly_verts(id),
            (stored.0.as_slice(), stored.1.as_slice())
        );
    }
}
