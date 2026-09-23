//! Rectilinear decomposition: the rectangles have to tile the polygon and
//! nothing else.
//!
//! Two claims carry everything downstream. The rectangles are **exact**, so
//! their areas sum to the polygon's area with no inclusion-exclusion
//! correction; and they are **disjoint**, so the sum is a sum rather than an
//! over-count. `min_area`, density and occupancy all measure through them, and
//! a decomposition that overlapped by one column of database units would
//! inflate every density number in a run without failing anything that only
//! counted rectangles.

use gpurify_geom::rects::{clipped_area, covered_area, decompose_into};
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::DbuArea;
use gpurify_geom::{Bbox, GeometryStore, LayerId};
use gpurify_testgen::shapes::{
    dbu, l_shape, l_shape_area, plus_shape, plus_shape_area, random_rectilinear_layer, rect,
    u_shape, u_shape_area, LayoutBuilder, RandomLayerSpec,
};
use gpurify_testgen::Rng;

const LAYER: LayerId = LayerId(0);

/// A coordinate run as the generator hands it over: parallel `i64` columns.
type Shape = (Vec<i64>, Vec<i64>);

fn bbox(xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> Bbox {
    Bbox {
        xlo: dbu(xlo),
        ylo: dbu(ylo),
        xhi: dbu(xhi),
        yhi: dbu(yhi),
    }
}

/// Do two rectangles share interior area? Computed here from the bounds, so it
/// does not go through [`Bbox`] and cannot agree with a broken decomposition
/// for the same reason a broken `overlaps` would.
fn interiors_meet(a: Bbox, b: Bbox) -> bool {
    a.xlo < b.xhi && b.xlo < a.xhi && a.ylo < b.yhi && b.ylo < a.yhi
}

fn validated(store: &GeometryStore, layer: LayerId) -> ValidatedLayer {
    let mut out = ValidatedLayer::default();
    validate_layer_into(store, layer, &mut out).expect("generated geometry is valid");
    out
}

/// Oracle: closed form. Each shape's area is stated by the generator as a
/// formula in its parameters, and an exact decomposition must reproduce it
/// exactly. The L, plus and U are here because their bounding boxes overstate
/// them, so a slab sweep that lost or duplicated a slab fails on them and
/// passes on the rectangle.
#[test]
fn a_decomposition_covers_exactly_the_area_of_the_polygon_it_came_from() {
    let cases: Vec<(Shape, i128)> = vec![
        (rect(0, 0, 40, 25), 1_000),
        (l_shape(0, 0, 100, 30), l_shape_area(100, 30)),
        (plus_shape(0, 0, 60, 8), plus_shape_area(60, 8)),
        (u_shape(0, 0, 100, 20, 40), u_shape_area(100, 20, 40)),
    ];

    // Each shape on its own layer so the polygon under test is polygon zero of
    // its layer whatever order the store sorted the rows into.
    let mut layout = LayoutBuilder::new(cases.len());
    for (index, (shape, _)) in cases.iter().enumerate() {
        let layer = LayerId(u16::try_from(index).expect("four layers fit a u16"));
        layout.shape(layer, shape);
    }
    let (store, _ids) = layout.finish();

    let (mut rects, mut poly_start) = (Vec::new(), Vec::new());
    for (index, (shape, area)) in cases.iter().enumerate() {
        let layer = validated(&store, LayerId(u16::try_from(index).expect("fits a u16")));
        decompose_into(&layer, &mut rects, &mut poly_start);

        assert_eq!(poly_start.len(), 2, "one polygon means two CSR offsets");
        assert_eq!(poly_start[0], 0);
        assert_eq!(
            poly_start[1] as usize,
            rects.len(),
            "the trailing offset must be the rectangle count"
        );
        assert!(!rects.is_empty(), "{shape:?} decomposed into nothing");
        assert_eq!(covered_area(&rects), DbuArea::new(*area), "{shape:?}");
        assert_eq!(
            covered_area(&rects),
            rects
                .iter()
                .map(|r| r.area())
                .fold(DbuArea::new(0), |total, area| total + area),
            "covered_area is not the sum of the rectangle areas"
        );
    }
}

/// Oracle: law. Disjointness is what makes the sum a sum. Asserted pairwise
/// over a generated layer, and asserted *per polygon*: rectangles of different
/// polygons may legitimately abut, but two rectangles of one polygon sharing
/// interior area is a double count.
#[test]
fn the_rectangles_of_one_polygon_are_pairwise_disjoint() {
    let mut rng = Rng::new(61);
    let mut layout = LayoutBuilder::new(1);
    let mut expected = Vec::new();
    for _ in 0..80 {
        let (x, y) = (rng.range(-100_000, 100_000), rng.range(-100_000, 100_000));
        let arm = rng.range(4, 600);
        let thickness = rng.range(1, arm);
        if rng.unit() < 0.5 {
            layout.shape(LAYER, &l_shape(x, y, arm, thickness));
            expected.push(l_shape_area(arm, thickness));
        } else {
            let gap = rng.range(1, 300);
            layout.shape(LAYER, &u_shape(x, y, arm, thickness, gap));
            expected.push(u_shape_area(arm, thickness, gap));
        }
    }
    let (store, _ids) = layout.finish();
    let layer = validated(&store, LAYER);

    let (mut rects, mut poly_start) = (Vec::new(), Vec::new());
    decompose_into(&layer, &mut rects, &mut poly_start);
    assert_eq!(poly_start.len(), layer.len() + 1);

    let mut total = DbuArea::new(0);
    for index in 0..layer.len() {
        let (from, to) = (poly_start[index] as usize, poly_start[index + 1] as usize);
        assert!(from <= to, "polygon {index} has an inverted CSR range");
        let own = &rects[from..to];
        assert!(!own.is_empty(), "polygon {index} decomposed into nothing");

        for (offset, &a) in own.iter().enumerate() {
            assert!(
                a.xlo < a.xhi && a.ylo < a.yhi,
                "polygon {index} rectangle {offset} is degenerate: {a:?}"
            );
            for &b in &own[offset + 1..] {
                assert!(
                    !interiors_meet(a, b),
                    "polygon {index} double-counts the region shared by {a:?} and {b:?}"
                );
            }
        }

        let index32 = u32::try_from(index).expect("eighty polygons fit a u32");
        assert_eq!(
            covered_area(own),
            layer.get(index32).area(),
            "polygon {index} is not covered exactly"
        );
        total = total + covered_area(own);
    }

    let stated: i128 = expected.iter().sum();
    assert_eq!(total, DbuArea::new(stated), "the layer's total area");
}

/// Oracle: closed form. Clipping to a window that contains everything is the
/// covered area; clipping to a window that touches nothing is zero; and
/// clipping a rectangle to a window that halves it is half. The last is the
/// only one of the three that can distinguish a real clip from a containment
/// test, which is why the window is placed to cut through the shapes rather
/// than around them.
#[test]
fn clipped_area_is_the_covered_area_inside_the_window_and_nothing_outside_it() {
    let mut layout = LayoutBuilder::new(1);
    // Two rectangles, both straddling x = 100.
    layout.rect(LAYER, 0, 0, 200, 50);
    layout.rect(LAYER, 50, 100, 150, 200);
    let (store, _ids) = layout.finish();
    let layer = validated(&store, LAYER);

    let (mut rects, mut poly_start) = (Vec::new(), Vec::new());
    decompose_into(&layer, &mut rects, &mut poly_start);
    let covered = covered_area(&rects);
    assert_eq!(covered, DbuArea::new(200 * 50 + 100 * 100));

    // A window swallowing everything.
    assert_eq!(clipped_area(&rects, bbox(-10, -10, 400, 400)), covered);
    // A window exactly the shapes' extent.
    assert_eq!(clipped_area(&rects, bbox(0, 0, 200, 200)), covered);
    // A window nowhere near them.
    assert_eq!(
        clipped_area(&rects, bbox(10_000, 10_000, 20_000, 20_000)),
        DbuArea::new(0)
    );
    // The left half of the extent: 100 x 50 of the low rectangle and 50 x 100
    // of the high one.
    assert_eq!(
        clipped_area(&rects, bbox(0, 0, 100, 200)),
        DbuArea::new(100 * 50 + 50 * 100)
    );
    // The right half is the complement, so the two halves sum to the whole.
    assert_eq!(
        clipped_area(&rects, bbox(0, 0, 100, 200)) + clipped_area(&rects, bbox(100, 0, 200, 200)),
        covered,
        "two halves of a window must partition the covered area"
    );
    // A horizontal band that catches only the low rectangle.
    assert_eq!(
        clipped_area(&rects, bbox(0, 0, 200, 50)),
        DbuArea::new(200 * 50)
    );
}

/// Oracle: law. A window's clipped area is bounded by the covered area and by
/// the window's own area, is monotone as the window grows, and is exactly the
/// covered area once the window contains the shapes' bounding box. Checked over
/// arbitrary windows against a generated layer, where no closed form is
/// available.
#[test]
fn clipped_area_is_monotone_and_bounded_by_the_window_and_the_shapes() {
    let mut rng = Rng::new(62);
    let mut layout = LayoutBuilder::new(1);
    let placed = random_rectilinear_layer(
        &mut layout,
        &mut rng,
        LAYER,
        (0, 0),
        RandomLayerSpec {
            cells: 24,
            cell: 500,
            density: 0.35,
        },
    );
    let (store, _ids) = layout.finish();
    let layer = validated(&store, LAYER);
    assert_eq!(
        u32::try_from(layer.len()).expect("a generated layer fits a u32"),
        placed.shapes,
        "the generator states how many shapes it placed"
    );

    let (mut rects, mut poly_start) = (Vec::new(), Vec::new());
    decompose_into(&layer, &mut rects, &mut poly_start);
    let covered = covered_area(&rects);
    assert_eq!(
        covered,
        DbuArea::new(placed.covered),
        "the generator states the covered area exactly: the squares do not touch"
    );

    // A window containing the whole region gives everything back.
    let all = bbox(-1, -1, placed.extent + 1, placed.extent + 1);
    assert_eq!(clipped_area(&rects, all), covered);

    for _ in 0..64 {
        let x = rng.range(-1_000, placed.extent);
        let y = rng.range(-1_000, placed.extent);
        let (w, h) = (rng.range(1, 6_000), rng.range(1, 6_000));
        let window = bbox(x, y, x + w, y + h);
        let inside = clipped_area(&rects, window);

        assert!(inside <= covered, "{window:?} claims more than exists");
        assert!(inside <= window.area(), "{window:?} claims more than it is");
        assert!(inside >= DbuArea::new(0), "{window:?} claims negative area");

        // Monotone: grow the window on every side and it cannot shrink.
        let bigger = bbox(x - 250, y - 250, x + w + 250, y + h + 250);
        assert!(
            clipped_area(&rects, bigger) >= inside,
            "growing {window:?} lost area"
        );
    }
}

/// Oracle: determinism. The doc comment names the decomposition canonical — the
/// same polygon always decomposes the same way — because the determinism gate
/// needs it. Run it twice into buffers that already hold a different result,
/// which is how a caller reusing one buffer across layers actually calls it.
#[test]
fn two_decompositions_of_one_layer_produce_the_same_rectangles_in_the_same_order() {
    let mut layout = LayoutBuilder::new(2);
    layout.shape(LAYER, &plus_shape(0, 0, 60, 8));
    layout.shape(LAYER, &u_shape(500, 0, 90, 15, 30));
    layout.shape(LAYER, &l_shape(0, 500, 100, 30));
    layout.rect(LayerId(1), 0, 0, 10, 10);
    let (store, _ids) = layout.finish();
    let layer = validated(&store, LAYER);
    let other = validated(&store, LayerId(1));

    let (mut rects, mut poly_start) = (Vec::new(), Vec::new());
    decompose_into(&layer, &mut rects, &mut poly_start);
    let (first_rects, first_start) = (rects.clone(), poly_start.clone());

    // Reuse the buffers for a different layer, then come back. Stale rows from
    // the wider layer must not survive into the narrower one or back again.
    decompose_into(&other, &mut rects, &mut poly_start);
    assert_eq!(
        poly_start.len(),
        2,
        "the offsets were appended to, not cleared"
    );
    assert_eq!(
        rects.len(),
        1,
        "one rectangle decomposes into one rectangle"
    );
    assert_eq!(covered_area(&rects), DbuArea::new(100));

    decompose_into(&layer, &mut rects, &mut poly_start);
    assert_eq!(rects, first_rects, "the decomposition is not reproducible");
    assert_eq!(poly_start, first_start, "the offsets are not reproducible");
    assert!(
        first_rects.len() >= 3,
        "the comparison would be near-vacuous"
    );
}
