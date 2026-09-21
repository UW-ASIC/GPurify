//! The two edge builders, on geometry small enough to state the answer for.
//!
//! Oracle throughout: construct-from-answer. Every configuration below is
//! placed by hand at coordinates chosen so the correct edge list is decidable
//! by reading the numbers, and each test contains both a pair that must produce
//! an edge and a pair that must not. Pairing them is deliberate: an edge
//! builder that returned nothing at all would satisfy any test that only
//! checked the non-touching case, which is the shape of half the failures the
//! previous suite shipped.

use gpurify_geom::LayerId;
use gpurify_testgen::shapes::{Handle, Ids, LayoutBuilder};
use gpurify_topology::net::{intra_layer_edges_into, via_edges_into};

/// The edge set, as unordered pairs sorted for comparison.
///
/// An edge list feeds a union-find, where orientation and repetition are both
/// no-ops, so the interface's claim is about the set and the test asserts on
/// the set rather than on an ordering nothing promised.
fn edge_set(edges: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut normalised: Vec<(u32, u32)> = edges
        .iter()
        .map(|&(a, b)| if a <= b { (a, b) } else { (b, a) })
        .collect();
    normalised.sort_unstable();
    normalised.dedup();
    normalised
}

/// One expected edge, in the same form.
fn pair(ids: &Ids, a: Handle, b: Handle) -> (u32, u32) {
    let (a, b) = (ids.of(a).0, ids.of(b).0);
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// Oracle: construct-from-answer. Three configurations on one layer with one
/// call over all of them: an overlapping pair and an abutting pair are each one
/// edge, and an isolated square is none. Abutment is the case worth naming —
/// two shapes sharing an edge and no area are one conductor, and an
/// implementation testing for positive-area overlap silently splits every
/// abutted metal run in a real layout.
#[test]
fn shapes_that_overlap_or_abut_are_one_edge_and_an_isolated_shape_is_none() {
    let layer = LayerId(0);
    let mut layout = LayoutBuilder::new(1);
    let overlapping_a = layout.rect(layer, 0, 0, 100, 100);
    let overlapping_b = layout.rect(layer, 50, 0, 150, 100);
    let abutting_a = layout.rect(layer, 300, 0, 400, 100);
    let abutting_b = layout.rect(layer, 400, 0, 500, 100);
    let isolated = layout.rect(layer, 700, 0, 800, 100);
    let (store, ids) = layout.finish();

    let mut edges = Vec::new();
    intra_layer_edges_into(&store, layer, &mut edges);

    let mut expected = vec![
        pair(&ids, overlapping_a, overlapping_b),
        pair(&ids, abutting_a, abutting_b),
    ];
    expected.sort_unstable();
    assert_eq!(
        edge_set(&edges),
        expected,
        "the isolated square at x=700 clears both others by 200 dbu, so it joins nothing"
    );
    assert!(
        !edge_set(&edges)
            .iter()
            .any(|&edge| edge.0 == ids.of(isolated).0 || edge.1 == ids.of(isolated).0),
        "the isolated square was joined to something"
    );
}

/// Oracle: construct-from-answer. A cut lands in the overlap of the two layers
/// it connects, so the edge it contributes is exactly the pair of shapes it sits
/// on. A second cut in the same call sits on the lower layer only — a stacked
/// via array produces those legitimately — and contributes nothing without
/// being an error. The two are in one call so the absence is evidence: the
/// builder demonstrably ran and produced the edge it should have.
#[test]
fn a_cut_over_both_layers_joins_them_and_a_cut_over_one_is_no_edge_and_no_error() {
    let lower = LayerId(0);
    let upper = LayerId(1);
    let cut = LayerId(2);

    let mut layout = LayoutBuilder::new(3);
    let lower_shape = layout.rect(lower, 0, 0, 1_000, 1_000);
    // Overlaps the lower shape over the square (500, 500) .. (1000, 1000).
    let upper_shape = layout.rect(upper, 500, 500, 1_500, 1_500);
    // Inside that overlap: material on both sides, so this is a real via.
    layout.rect(cut, 600, 600, 700, 700);
    // Inside the lower shape and nowhere near the upper one.
    layout.rect(cut, 100, 100, 200, 200);
    let (store, ids) = layout.finish();

    let mut edges = Vec::new();
    via_edges_into(&store, cut, (lower, upper), &mut edges);

    assert_eq!(
        edge_set(&edges),
        vec![pair(&ids, lower_shape, upper_shape)],
        "the cut at (600, 600) joins the two shapes; the cut at (100, 100) touches only the lower one"
    );
}

/// Oracle: construct-from-answer. A cut sitting over neither layer joins
/// nothing, and a cut over two shapes on the *same* layer is not the pair this
/// transform reports either — it is asked for edges between `connects.0` and
/// `connects.1`, and the shapes it names must be one from each. The layout
/// holds one legal via so the empty answer for the rest is checked against a
/// builder that ran.
#[test]
fn a_cut_reports_only_pairs_spanning_the_two_layers_it_was_asked_about() {
    let lower = LayerId(0);
    let upper = LayerId(1);
    let cut = LayerId(2);

    let mut layout = LayoutBuilder::new(3);
    // Two lower shapes abutting at x = 1000, both under the same cut.
    let lower_left = layout.rect(lower, 0, 0, 1_000, 1_000);
    layout.rect(lower, 1_000, 0, 2_000, 1_000);
    let upper_shape = layout.rect(upper, 0, 0, 500, 500);
    // Over both lower shapes and no upper shape.
    layout.rect(cut, 900, 700, 1_100, 800);
    // Over the lower left shape and the upper shape.
    layout.rect(cut, 100, 100, 200, 200);
    // Over nothing at all.
    layout.rect(cut, 5_000, 5_000, 5_100, 5_100);
    let (store, ids) = layout.finish();

    let mut edges = Vec::new();
    via_edges_into(&store, cut, (lower, upper), &mut edges);

    assert_eq!(
        edge_set(&edges),
        vec![pair(&ids, lower_left, upper_shape)],
        "only the cut at (100, 100) has material on both of the layers asked about"
    );
}
