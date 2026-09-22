//! Net labels: their ordering contract and their binding to polygons.

use gpurify_geom::{LayerId, PolyId};
use gpurify_geom::StrTable;
use gpurify_ingest::Provenance;
use gpurify_testgen::LayoutBuilder;

/// Oracle: law. `labels` is documented as ascending by `PolyId`, which is what
/// lets `topology` bind labels deterministically without sorting. That ordering
/// must be a property of the table rather than of the order labels happened to
/// be attached in, so they go on in scrambled order here.
#[test]
fn labels_come_back_ascending_by_polygon_whatever_order_they_were_attached_in() {
    let mut strings = StrTable::default();
    let mut provenance = Provenance::default();

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
    use gpurify_geom::ops::Point;
    use gpurify_geom::Dbu;
    use gpurify_ingest::deck::Connectivity;
    use gpurify_ingest::LabelError;

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
