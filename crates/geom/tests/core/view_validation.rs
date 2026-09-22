//! Validation: what a [`PolygonRef`] is allowed to promise, and what gets
//! refused before one can exist.
//!
//! The refusals matter as much as the acceptances. `validate_layer_into` fails
//! closed, so every rejected input below is checked for the *specific* error and
//! the *specific* polygon, not merely for `Err`. The previous implementation
//! dropped a hole with no containing outer ring without a word, which removes
//! area from a verification result, and an `is_err()` assertion would not have
//! told the two failures apart.

use gpurify_geom::ops::{self_intersects, winding_of, Winding};
use gpurify_geom::view::{validate_layer_into, RingRef, ValidatedLayer, ValidityError};
use gpurify_geom::DbuArea;
use gpurify_geom::{Bbox, GeometryStore, GeometryStoreBuilder, LayerId, PolyId};
use gpurify_testgen::shapes::{
    dbu, hole, l_shape, l_shape_area, plus_shape, plus_shape_area, rect, u_shape, u_shape_area,
    LayoutBuilder,
};
use gpurify_testgen::Rng;

const LAYER: LayerId = LayerId(0);
const OTHER: LayerId = LayerId(1);

/// A coordinate run as the generator hands it over: parallel `i64` columns.
type Shape = (Vec<i64>, Vec<i64>);

fn wind(ring: RingRef<'_>) -> Option<Winding> {
    let (xs, ys) = ring.coords();
    winding_of(xs, ys)
}

/// Push raw coordinate runs, bypassing `LayoutBuilder`'s own preconditions.
/// The rejection cases need runs that builder refuses to make.
fn store_of(runs: &[(LayerId, Vec<i64>, Vec<i64>)]) -> GeometryStore {
    let mut builder = GeometryStoreBuilder::default();
    for (layer, xs, ys) in runs {
        let xs: Vec<_> = xs.iter().copied().map(dbu).collect();
        let ys: Vec<_> = ys.iter().copied().map(dbu).collect();
        builder.push(*layer, &xs, &ys);
    }
    builder.finish(2).0
}

fn validate(store: &GeometryStore, layer: LayerId) -> Result<ValidatedLayer, ValidityError> {
    let mut out = ValidatedLayer::default();
    validate_layer_into(store, layer, &mut out).map(|()| out)
}

/// Sum of every polygon's area. Order-independent, which matters: the store
/// promises rows are grouped by layer, not the order rows take within one.
fn total_area(store: &GeometryStore, layer: &ValidatedLayer) -> DbuArea {
    (0..u32::try_from(layer.len()).expect("a test layer fits a u32"))
        .map(|index| layer.get(store, index).area())
        .fold(DbuArea::new(0), |total, area| total + area)
}

/// Oracle: closed form. The generator states each shape's area as a formula in
/// its own parameters, and `PolygonRef::area` must agree exactly. The L, plus
/// and U are here because their bounding boxes overstate them: an
/// implementation measuring the box passes on the rectangle and fails on the
/// other three.
#[test]
fn a_validated_polygon_has_the_area_its_generator_states() {
    let cases: Vec<(Shape, i128)> = vec![
        (rect(0, 0, 40, 25), 1_000),
        (l_shape(0, 0, 100, 30), l_shape_area(100, 30)),
        (plus_shape(500, 500, 60, 8), plus_shape_area(60, 8)),
        (u_shape(-300, -300, 100, 20, 40), u_shape_area(100, 20, 40)),
    ];

    let mut layout = LayoutBuilder::new(2);
    let handles: Vec<_> = cases
        .iter()
        .map(|(shape, _)| layout.shape(LAYER, shape))
        .collect();
    let (store, ids) = layout.finish();
    let layer = validate(&store, LAYER).expect("generated rectilinear shapes are valid");
    assert_eq!(layer.len(), cases.len());
    assert!(!layer.is_empty());

    // None of these shapes has a hole, so validation pairs nothing and the
    // layer's polygons sit in store-row order. The handle resolves the store
    // row; subtracting the layer's first row gives the index into the layer.
    let first_row = store.polys_on_layer(LAYER).start;
    for ((shape, area), handle) in cases.iter().zip(handles) {
        let id = ids.of(handle);
        let poly = layer.get(&store, id.0 - first_row);
        assert_eq!(poly.area(), DbuArea::new(*area), "{shape:?}");
        assert_eq!(poly.bbox(), store.poly_bbox(id));
        assert_eq!(poly.holes().count(), 0, "none of these have holes");
    }
}

/// Oracle: law. Validation's whole output is a promise about the rings it
/// produced: the outer boundary winds counter-clockwise, its doubled signed
/// area is therefore positive, and the run does not cross itself. Asserted over
/// a generated layer so it is a property of the pass rather than of a fixture.
#[test]
fn every_validated_outer_ring_winds_counter_clockwise_and_is_simple() {
    let mut rng = Rng::new(41);
    let mut layout = LayoutBuilder::new(2);
    for _ in 0..120 {
        let (x, y) = (rng.range(-200_000, 200_000), rng.range(-200_000, 200_000));
        match rng.below(3) {
            0 => layout.rect(LAYER, x, y, x + rng.range(1, 900), y + rng.range(1, 900)),
            1 => {
                let arm = rng.range(4, 800);
                layout.shape(LAYER, &l_shape(x, y, arm, rng.range(1, arm)))
            }
            _ => {
                let arm = rng.range(4, 800);
                layout.shape(
                    LAYER,
                    &u_shape(x, y, arm, rng.range(1, arm), rng.range(1, 400)),
                )
            }
        };
    }
    let (store, _ids) = layout.finish();
    let layer = validate(&store, LAYER).expect("generated rectilinear shapes are valid");
    assert_eq!(layer.len(), 120);

    for index in 0..120u32 {
        let poly = layer.get(&store, index);
        let outer = poly.outer();
        assert_eq!(
            wind(outer),
            Some(Winding::CounterClockwise),
            "polygon {index}"
        );
        assert!(
            outer.area2() > DbuArea::new(0),
            "polygon {index} winds counter-clockwise but reports a non-positive area"
        );
        let (xs, ys) = outer.coords();
        assert!(
            !self_intersects(xs, ys),
            "polygon {index} was validated but its boundary crosses itself"
        );
        assert_eq!(xs.len(), ys.len(), "the coordinate columns are parallel");
        assert!(
            xs.len() >= 4,
            "a rectilinear ring has at least four vertices"
        );
        assert_eq!(poly.bbox(), Bbox::of_points(xs, ys), "polygon {index} bbox");
        // With no holes, the polygon's area is half its outer ring's doubled
        // signed area — the only place the halving happens.
        assert_eq!(
            poly.area() + poly.area(),
            outer.area2(),
            "polygon {index} area is not half its outer ring"
        );
    }
}

/// Oracle: closed form. A hole is subtracted, so the polygon's area is the
/// outer rectangle less the inner one, and the hole's ring winds clockwise
/// while the outer winds counter-clockwise.
#[test]
fn a_hole_winds_clockwise_and_its_area_is_subtracted_from_its_container() {
    let mut layout = LayoutBuilder::new(2);
    layout.rect(LAYER, 0, 0, 100, 100);
    layout.shape(LAYER, &hole(20, 20, 60, 50));
    let (store, _ids) = layout.finish();
    let layer = validate(&store, LAYER).expect("a rectangle with a hole in it is valid");

    assert_eq!(layer.len(), 1, "an outer and its hole are one polygon");
    let poly = layer.get(&store, 0);

    let outer_area = 100 * 100i128;
    let hole_area = 40 * 30i128;
    assert_eq!(poly.area(), DbuArea::new(outer_area - hole_area));

    let outer = poly.outer();
    assert_eq!(wind(outer), Some(Winding::CounterClockwise));
    assert_eq!(outer.area2(), DbuArea::new(2 * outer_area));

    let holes: Vec<_> = poly.holes().collect();
    assert_eq!(holes.len(), 1);
    assert_eq!(wind(holes[0]), Some(Winding::Clockwise));
    assert_eq!(
        holes[0].area2(),
        DbuArea::new(-2 * hole_area),
        "a clockwise ring has negative doubled area"
    );

    // The polygon's bounding box is the outer boundary's; a hole cannot grow it.
    assert_eq!(
        poly.bbox(),
        Bbox {
            xlo: dbu(0),
            ylo: dbu(0),
            xhi: dbu(100),
            yhi: dbu(100)
        }
    );
}

/// Oracle: construct-from-answer. Each run below is invalid for exactly one
/// stated reason, so the error and the polygon it names are both known before
/// the pass runs. Fail closed: a shape the tool cannot represent is an error,
/// never a silently skipped row.
#[test]
fn each_kind_of_invalid_geometry_is_refused_by_name() {
    // Three coincident vertices: no distinct points, so no boundary.
    let degenerate = store_of(&[(LAYER, vec![5, 5, 5], vec![5, 5, 5])]);
    assert_eq!(
        validate(&degenerate, LAYER).map(|_| ()),
        Err(ValidityError::Degenerate(PolyId(0)))
    );

    // A bowtie: four distinct vertices whose boundary crosses itself.
    let bowtie = store_of(&[(LAYER, vec![0, 10, 10, 0], vec![0, 10, 0, 10])]);
    assert_eq!(
        validate(&bowtie, LAYER).map(|_| ()),
        Err(ValidityError::SelfIntersecting(PolyId(0)))
    );

    // A clockwise ring with nothing containing it.
    let orphan = {
        let h = hole(0, 0, 10, 10);
        store_of(&[(LAYER, h.0, h.1)])
    };
    assert_eq!(
        validate(&orphan, LAYER).map(|_| ()),
        Err(ValidityError::OrphanHole(PolyId(0)))
    );

    // A triangle: simple, non-degenerate, and not rectilinear. Refused rather
    // than approximated, because the previous general-angle path failed open in
    // three places and silently dropped area.
    let triangle = store_of(&[(LAYER, vec![0, 10, 5], vec![0, 0, 9])]);
    assert_eq!(
        validate(&triangle, LAYER).map(|_| ()),
        Err(ValidityError::NotRectilinear(PolyId(0)))
    );
}

/// Oracle: construct-from-answer. The error names a [`PolyId`], which is a
/// *store* row and not an index into the layer being validated. Three rectangles
/// occupy layer zero, so the bowtie on layer one cannot be row zero however the
/// sort arranges the rest — and an implementation reporting the within-layer
/// index would say `PolyId(0)` here.
#[test]
fn an_invalid_polygon_is_named_by_the_store_row_it_occupies() {
    let mut layout = LayoutBuilder::new(2);
    layout.rect(LAYER, 0, 0, 40, 40);
    layout.rect(LAYER, 100, 0, 140, 40);
    layout.rect(LAYER, 300, 0, 340, 40);
    let bowtie = layout.push(OTHER, &[200, 210, 210, 200], &[0, 10, 0, 10]);
    let (store, ids) = layout.finish();

    assert!(
        ids.of(bowtie) >= PolyId(3),
        "layer one starts after layer zero"
    );
    assert_eq!(
        validate(&store, OTHER).map(|_| ()),
        Err(ValidityError::SelfIntersecting(ids.of(bowtie)))
    );
    // The layer that holds only good geometry still validates.
    assert_eq!(validate(&store, LAYER).map(|l| l.len()), Ok(3));
}

/// Oracle: law. `validate_layer_into` reads one layer and only that layer, and
/// the buffer it fills is cleared first — both are what let a caller hoist one
/// `ValidatedLayer` above a loop over layers. A pass that appended instead of
/// clearing would still produce a plausible result on the first call.
#[test]
fn validation_reads_one_layer_and_clears_the_buffer_it_is_given() {
    let mut layout = LayoutBuilder::new(2);
    for i in 0..6 {
        layout.rect(LAYER, i * 100, 0, i * 100 + 50, 50);
    }
    for i in 0..2 {
        layout.rect(OTHER, i * 100, 500, i * 100 + 20, 520);
    }
    let (store, _ids) = layout.finish();

    let mut buffer = ValidatedLayer::default();
    validate_layer_into(&store, LAYER, &mut buffer).expect("six rectangles are valid");
    assert_eq!(buffer.len(), 6);
    assert_eq!(total_area(&store, &buffer), DbuArea::new(6 * 50 * 50));

    // The same buffer, reused. Six stale rows must not survive into a
    // two-polygon layer, and the areas must be the narrow layer's.
    validate_layer_into(&store, OTHER, &mut buffer).expect("two rectangles are valid");
    assert_eq!(buffer.len(), 2, "the buffer was appended to, not cleared");
    assert_eq!(total_area(&store, &buffer), DbuArea::new(2 * 20 * 20));

    // And back again: reuse is symmetric, not a one-way shrink.
    validate_layer_into(&store, LAYER, &mut buffer).expect("six rectangles are still valid");
    assert_eq!(buffer.len(), 6);
}

/// Oracle: determinism. Validation is the input to every boolean and every
/// rule, so two passes over one store must produce the same rings in the same
/// order with the same windings. Ring order is part of the interface — holes
/// follow their outer — so a reordering is a defect and not a detail.
#[test]
fn two_validations_of_one_store_agree_ring_for_ring() {
    let mut layout = LayoutBuilder::new(2);
    layout.rect(LAYER, 0, 0, 200, 200);
    layout.shape(LAYER, &hole(20, 20, 60, 60));
    layout.shape(LAYER, &hole(100, 100, 180, 150));
    layout.shape(LAYER, &l_shape(400, 400, 90, 25));
    layout.shape(LAYER, &u_shape(-500, -500, 80, 15, 30));
    let (store, _ids) = layout.finish();

    let first = validate(&store, LAYER).expect("valid");
    let second = validate(&store, LAYER).expect("valid");
    assert_eq!(first.len(), second.len());

    for index in 0..u32::try_from(first.len()).expect("a handful of polygons fit a u32") {
        let (a, b) = (first.get(&store, index), second.get(&store, index));
        assert_eq!(a.area(), b.area(), "polygon {index}");
        assert_eq!(a.bbox(), b.bbox(), "polygon {index}");
        assert_eq!(a.outer().coords(), b.outer().coords(), "polygon {index}");
        assert_eq!(wind(a.outer()), wind(b.outer()));

        let a_holes: Vec<_> = a.holes().map(|r| (r.coords(), wind(r))).collect();
        let b_holes: Vec<_> = b.holes().map(|r| (r.coords(), wind(r))).collect();
        assert_eq!(a_holes.len(), b_holes.len(), "polygon {index} hole count");
        for (left, right) in a_holes.iter().zip(&b_holes) {
            assert_eq!(left.0, right.0, "polygon {index} hole coordinates");
            assert_eq!(left.1, right.1, "polygon {index} hole winding");
        }
    }

    // The two-hole rectangle: area is the outer less *both* holes, which is
    // what fixes that holes accumulate rather than the last one winning. Found
    // by hole count, because the order rows take within a layer is not part of
    // the store's interface.
    let perforated = (0..3)
        .map(|index| first.get(&store, index))
        .find(|poly| poly.holes().count() == 2)
        .expect("one polygon has two holes");
    assert_eq!(
        perforated.area(),
        DbuArea::new(200 * 200 - 40 * 40 - 80 * 50),
        "both holes must be subtracted"
    );
    assert_eq!(
        first.len(),
        3,
        "five rows, two of them holes, is three polygons"
    );
}
