//! The permutation invariant, and the two column shapes that hang off it.
//!
//! `GeometryStoreBuilder::finish` sorts rows by layer, so the id a polygon ends
//! up with is not the order it was pushed in. `Provenance` accumulates in
//! arrival order and is permuted afterwards. Nothing in the type system holds
//! those two tables together, and nothing downstream notices when they come
//! apart: a report against the wrong cell is plausible output.

use gpurify_core::{LayerId, PolyId};
use gpurify_ingest::intern::{StrId, StrTable};
use gpurify_ingest::provenance::PathTable;
use gpurify_ingest::Provenance;
use gpurify_testgen::LayoutBuilder;

/// Layers to interleave over. Three is enough for the layer sort to move rows
/// past each other in both directions.
const LAYERS: usize = 3;
/// Shapes to push. Small enough to read in a failure message, large enough that
/// an off-by-one in the permutation cannot land on the right answer by luck.
const SHAPES: usize = 12;

/// Oracle: construct-from-answer. Every polygon is pushed with provenance that
/// names it, so after the permutation each polygon's provenance is checkable
/// against the one thing it was built from. Shapes go down on interleaved
/// layers precisely so the permutation is not the identity — a fact the test
/// asserts before it relies on it, because against an identity permutation a
/// `permute` that does nothing at all would pass.
#[test]
fn provenance_follows_its_own_polygon_through_the_layer_sort() {
    let mut strings = StrTable::default();
    let mut layout = LayoutBuilder::new(LAYERS);
    let mut provenance = Provenance::default();
    let mut handles = Vec::with_capacity(SHAPES);
    let mut pushed: Vec<Vec<(i16, StrId)>> = Vec::with_capacity(SHAPES);

    for i in 0..SHAPES {
        let layer = LayerId(u16::try_from(i % LAYERS).expect("LAYERS is tiny"));
        let x = i64::try_from(i).expect("SHAPES is tiny") * 1_000;
        handles.push(layout.rect(layer, x, 0, x + 400, 400));

        let tag = strings.intern(&format!("cell_of_shape_{i}"));
        let props = vec![(i16::try_from(i).expect("SHAPES is tiny"), tag)];
        provenance.push(PathTable::ROOT, &props);
        pushed.push(props);
    }

    let (store, ids) = layout.finish();

    // `permutation[new] == old`, the form `GeometryStoreBuilder::finish` states
    // it in. `Ids` holds the inverse, so this inverts it back.
    let mut permutation = vec![0u32; SHAPES];
    for (old, &handle) in handles.iter().enumerate() {
        permutation[ids.of(handle).idx()] = u32::try_from(old).expect("SHAPES is tiny");
    }
    assert!(
        permutation
            .iter()
            .enumerate()
            .any(|(new, &old)| u32::try_from(new).expect("SHAPES is tiny") != old),
        "the layer sort left every row where it was, so this test could not \
         tell a correct permute from one that does nothing"
    );

    provenance.permute(&permutation);

    for (old, &handle) in handles.iter().enumerate() {
        let poly = ids.of(handle);
        assert_eq!(
            provenance.props_of(poly),
            pushed[old].as_slice(),
            "shape pushed at arrival row {old} became {poly:?}, whose provenance \
             belongs to another polygon"
        );
    }
    assert_eq!(
        store.poly_count(),
        SHAPES,
        "the store and the provenance table must have the same number of rows"
    );
}

/// Oracle: construct-from-answer. The property column is CSR, and the case a
/// CSR layout gets wrong is the empty one: a polygon with no properties costs a
/// single offset and must read back as an empty slice, not as its neighbour's
/// properties. Rows are read in push order with no permutation applied, so this
/// isolates the column shape from the permutation above.
#[test]
fn a_polygon_with_no_properties_reads_back_empty_rather_than_its_neighbours() {
    let mut strings = StrTable::default();
    let a = strings.intern("a");
    let b = strings.intern("b");
    let c = strings.intern("c");

    let rows: [Vec<(i16, StrId)>; 5] = [
        vec![],
        vec![(1, a)],
        vec![],
        vec![(2, b), (3, c), (4, a)],
        vec![],
    ];
    let mut provenance = Provenance::default();
    for row in &rows {
        provenance.push(PathTable::ROOT, row);
    }

    for (index, row) in rows.iter().enumerate() {
        let poly = PolyId(u32::try_from(index).expect("five rows"));
        assert_eq!(
            provenance.props_of(poly),
            row.as_slice(),
            "row {index} read back the wrong property range"
        );
        assert_eq!(
            provenance.path_of(poly),
            PathTable::ROOT,
            "row {index} was pushed at the root path"
        );
    }
}

/// Oracle: law. `labels` is documented as ascending by `PolyId`, which is what
/// lets `topology` bind labels deterministically without sorting. That ordering
/// must be a property of the table rather than of the order labels happened to
/// be attached in, so they go on in scrambled order here.
#[test]
fn labels_come_back_ascending_by_polygon_whatever_order_they_were_attached_in() {
    let mut strings = StrTable::default();
    let mut provenance = Provenance::default();
    for _ in 0..8 {
        provenance.push(PathTable::ROOT, &[]);
    }

    let attached = [
        (PolyId(5), strings.intern("vdd")),
        (PolyId(1), strings.intern("clk")),
        (PolyId(7), strings.intern("vss")),
        (PolyId(2), strings.intern("dout")),
    ];
    for &(poly, name) in &attached {
        provenance.label(poly, name);
    }

    let mut expected = attached;
    expected.sort_unstable_by_key(|&(poly, _)| poly);
    assert_eq!(
        provenance.labels(),
        expected.as_slice(),
        "labels are not in ascending polygon order, so label binding depends on \
         the order the reader happened to encounter the text records in"
    );
}

/// Oracle: law. Most polygons carry no label, and the label column is sparse
/// for exactly that reason. A layout where nothing was labelled must produce an
/// empty list rather than one row per polygon.
#[test]
fn an_unlabelled_layout_has_no_label_rows_at_all() {
    let mut provenance = Provenance::default();
    for _ in 0..16 {
        provenance.push(PathTable::ROOT, &[]);
    }
    assert!(
        provenance.labels().is_empty(),
        "pushing polygons created label rows for polygons that have no label"
    );
}

// ---------------------------------------------------------------------------
// Label resolution over a split diffusion: a pin binds to the piece under it,
// and a pin on the channel binds to nothing and refuses the load.
// ---------------------------------------------------------------------------

/// Oracle: construct-from-answer. The conductor arrives as the split
/// source/drain layer — two rectangles flanking a channel gap at
/// `(200,0)-(250,200)` — so where each label lands decides its polygon before
/// anything runs.
///
/// The pin on the channel is a **refusal**, not a binding: the channel is the
/// MOS body, it carries no extracted net, and quietly attaching the label to
/// the nearest flank would name a net the designer did not pin. That is
/// [`gpurify_ingest::LabelError::Unplaced`], aborting the load.
#[test]
fn a_label_binds_to_its_split_flank_and_one_on_the_channel_refuses_the_load() {
    use gpurify_core::ops::Point;
    use gpurify_ingest::deck::Connectivity;
    use gpurify_ingest::LabelError;
    use gpurify_units::Dbu;

    const ACTIVE: LayerId = LayerId(0);
    const TEXT: LayerId = LayerId(1);

    let at = |x: i64, y: i64| Point {
        x: Dbu::new(x).expect("fixture coordinates are in range"),
        y: Dbu::new(y).expect("fixture coordinates are in range"),
    };
    let connectivity = Connectivity {
        conductors: vec![ACTIVE],
        intra_layer_touch: true,
        label_layer: vec![TEXT],
        label_names: vec![ACTIVE],
        ..Connectivity::default()
    };

    let mut layout = LayoutBuilder::new(2);
    let source = layout.rect(ACTIVE, 0, 0, 200, 200);
    let drain = layout.rect(ACTIVE, 250, 0, 500, 200);
    let (store, ids) = layout.finish();

    let mut strings = StrTable::default();
    let (s_name, d_name) = (strings.intern("VSS"), strings.intern("Y"));

    // The two flank pins bind, each to its own piece.
    let mut provenance = Provenance::default();
    for _ in 0..store.poly_count() {
        provenance.push(PathTable::ROOT, &[]);
    }
    provenance.place_label(at(100, 100), TEXT, s_name);
    provenance.place_label(at(300, 100), TEXT, d_name);
    provenance
        .resolve_labels(&store, &connectivity)
        .expect("both pins sit on a source/drain piece");
    assert_eq!(
        provenance.labels(),
        &[(ids.of(source), s_name), (ids.of(drain), d_name)],
        "each pin bound to the split piece under it, not to the other flank"
    );

    // A third pin over the channel gap sits on no conductor shape at all.
    let mut provenance = Provenance::default();
    for _ in 0..store.poly_count() {
        provenance.push(PathTable::ROOT, &[]);
    }
    provenance.place_label(at(225, 100), TEXT, strings.intern("pin_on_channel"));
    let refused = provenance
        .resolve_labels(&store, &connectivity)
        .expect_err("a pin on the MOS channel names no extracted conductor");
    assert_eq!(
        refused,
        LabelError::Unplaced {
            layer: TEXT,
            x: 225,
            y: 100
        },
        "the refusal names the label's layer and point"
    );
}
