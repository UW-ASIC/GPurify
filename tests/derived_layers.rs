//! Deck-declared derived layers, materialised into the store the reader hands
//! back.
//!
//! Oracle throughout: construct-from-answer. Each layout below is drawn so the
//! result of the boolean is a set of rectangles stated before anything runs,
//! and the assertion is on the coordinates, not on a count.
//!
//! # Why this goes through the file
//!
//! A derived layer only earns its keep if it has real [`gpurify_geom::PolyId`]s
//! in the [`gpurify_geom::GeometryStore`] — that is what lets `topology` extract
//! nets over it, bind a label to it and recognise a device terminal on it
//! without any of those learning a second way to address geometry. So the claim
//! under test is about the *store the reader produces*, and the cheapest honest
//! way to make that claim is to write a base-layer-only layout out as GDSII and
//! read it back through the same entry point a run uses.

use gpurify_geom::Grid;
use gpurify_geom::{GeometryStore, LayerId, PolyId};
use gpurify_ingest::deck::{parse_deck, Deck};
use gpurify_ingest::layout::{gds, UnknownLayers};
use gpurify_ingest::StrTable;
use gpurify_testgen::gds::write_store;
use gpurify_testgen::shapes::LayoutBuilder;

/// One nanometre per database unit, which is what every fixture in this file is
/// drawn on.
fn grid() -> Grid {
    Grid::new(1_000).expect("1000 database units per micrometre is a legal grid")
}

/// Parse a deck, failing with the parser's own message.
fn deck(source: &str) -> Deck {
    parse_deck(source, grid(), &mut StrTable::default()).expect("the deck fixture parses")
}

/// The bounding box of every polygon on one layer, ascending by row.
fn boxes_on(store: &GeometryStore, layer: LayerId) -> Vec<(i64, i64, i64, i64)> {
    store
        .polys_on_layer(layer)
        .map(|row| {
            let bbox = store.poly_bbox(PolyId(row));
            (
                bbox.xlo.raw(),
                bbox.ylo.raw(),
                bbox.xhi.raw(),
                bbox.yhi.raw(),
            )
        })
        .collect()
}

/// Write a store out as GDSII and read it back through the reader.
fn round_trip(store: &GeometryStore, deck: &Deck) -> GeometryStore {
    let mut bytes = Vec::new();
    write_store(store, &deck.layers, "TOP", &mut bytes).expect("base geometry is writable");
    gds::read(&bytes, deck, UnknownLayers::Reject)
        .expect("a layout the deck describes reads back")
        .store
}

/// A deck declaring `diff_active = diff NOT poly` over two base layers.
const SUBTRACTION_DECK: &str = r#"{
  "layers": { "diff": [2, 0], "poly": [3, 0] },
  "derived": [
    { "name": "diff_active", "op": "not", "layers": ["diff", "poly"] }
  ]
}"#;

const DIFF: LayerId = LayerId(0);
const POLY: LayerId = LayerId(1);
const DIFF_ACTIVE: LayerId = LayerId(2);

/// Oracle: construct-from-answer. One diffusion rectangle crossed by one gate
/// is two source/drain regions, and their coordinates are decided by the
/// drawing: `(0,0)-(500,200)` minus `(200,-50)-(250,750)` is `(0,0)-(200,200)`
/// and `(250,0)-(500,200)`.
#[test]
fn a_deck_declared_subtraction_lands_in_the_store_as_real_polygons() {
    let deck = deck(SUBTRACTION_DECK);
    assert_eq!(
        deck.layers.len(),
        3,
        "a derived layer is a layer: two base plus one derived"
    );
    assert!(
        deck.layers.is_derived(DIFF_ACTIVE),
        "the derived layer took the id after every base one"
    );
    assert!(
        !deck.layers.is_derived(DIFF) && !deck.layers.is_derived(POLY),
        "a base layer is not derived"
    );

    let mut layout = LayoutBuilder::new(deck.layers.len());
    layout.rect(DIFF, 0, 0, 500, 200);
    layout.rect(POLY, 200, -50, 250, 750);
    let (base, _ids) = layout.finish();
    assert!(
        base.polys_on_layer(DIFF_ACTIVE).is_empty(),
        "the fixture writes no derived geometry, so whatever comes back on that \
         layer was computed by the read"
    );

    let store = round_trip(&base, &deck);
    assert_eq!(
        boxes_on(&store, DIFF),
        [(0, 0, 500, 200)],
        "the base layers must survive unchanged"
    );
    assert_eq!(boxes_on(&store, POLY), [(200, -50, 250, 750)]);
    assert_eq!(
        boxes_on(&store, DIFF_ACTIVE),
        [(0, 0, 200, 200), (250, 0, 500, 200)],
        "diff NOT poly is the two source/drain regions either side of the gate"
    );
}

/// Oracle: construct-from-answer. A derived layer may be built on a derived
/// layer, and the deck says so by naming it — which is only spellable because a
/// derived layer has a real `LayerId` like any other.
#[test]
fn a_derived_layer_may_be_built_on_an_earlier_derived_layer() {
    // Base layers ascending by name: diff 0, poly 1, window 2. Derived in
    // declaration order after them: diff_active 3, sd_in_window 4.
    const WINDOW: LayerId = LayerId(2);
    const ACTIVE: LayerId = LayerId(3);
    const IN_WINDOW: LayerId = LayerId(4);

    let deck = deck(
        r#"{
  "layers": { "diff": [2, 0], "poly": [3, 0], "window": [4, 0] },
  "derived": [
    { "name": "diff_active", "op": "not", "layers": ["diff", "poly"] },
    { "name": "sd_in_window", "op": "and", "layers": ["diff_active", "window"] }
  ]
}"#,
    );

    let mut layout = LayoutBuilder::new(deck.layers.len());
    layout.rect(LayerId(0), 0, 0, 500, 200);
    layout.rect(LayerId(1), 200, -50, 250, 750);
    layout.rect(WINDOW, 100, 0, 400, 200);
    let (base, _ids) = layout.finish();

    let store = round_trip(&base, &deck);
    assert_eq!(
        boxes_on(&store, ACTIVE),
        [(0, 0, 200, 200), (250, 0, 500, 200)],
        "the first derived layer is unchanged by the second one existing"
    );
    assert_eq!(
        boxes_on(&store, IN_WINDOW),
        [(100, 0, 200, 200), (250, 0, 400, 200)],
        "the second derived layer read the first one, not the base layer it \
         was built from"
    );
}

/// Oracle: construct-from-answer. A derived layer over a layer the layout does
/// not draw is empty, and an empty derived layer is a layer with no polygons —
/// never a missing layer, and never a panic.
#[test]
fn a_derived_layer_with_nothing_under_it_is_empty_rather_than_absent() {
    let deck = deck(SUBTRACTION_DECK);
    let mut layout = LayoutBuilder::new(deck.layers.len());
    layout.rect(POLY, 200, -50, 250, 750);
    let (base, _ids) = layout.finish();

    let store = round_trip(&base, &deck);
    assert_eq!(
        boxes_on(&store, POLY),
        [(200, -50, 250, 750)],
        "the gate is still there, so the read did happen"
    );
    assert!(
        boxes_on(&store, DIFF).is_empty(),
        "nothing was drawn on diff"
    );
    assert!(
        boxes_on(&store, DIFF_ACTIVE).is_empty(),
        "nothing minus something is nothing"
    );
}

/// Oracle: construct-from-answer. A derived layer has no GDS stream pair, so no
/// record in a layout file may ever map onto one.
#[test]
fn no_gds_stream_pair_maps_onto_a_derived_layer() {
    let deck = deck(SUBTRACTION_DECK);
    assert_eq!(
        deck.layers.of_stream(2, 0),
        Some(DIFF),
        "the base layers still map from their own stream pairs"
    );
    assert_eq!(deck.layers.of_stream(3, 0), Some(POLY));
    // The whole small-integer corner of the stream space, plus the pair a
    // derived row's placeholder is written with — the one value that could map
    // by accident rather than by design.
    for layer in 0..=8u16 {
        for datatype in 0..=8u16 {
            assert_ne!(
                deck.layers.of_stream(layer, datatype),
                Some(DIFF_ACTIVE),
                "stream {layer}/{datatype} mapped onto a derived layer"
            );
        }
    }
    assert_eq!(
        deck.layers.of_stream(u16::MAX, u16::MAX),
        None,
        "a derived layer's placeholder stream pair is not a stream pair"
    );
}
