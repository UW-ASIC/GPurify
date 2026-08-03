//! Laws for the exact rectilinear booleans.
//!
//! # What is and is not reachable from outside the crate
//!
//! Every law in `boolean`'s own doc comment is stated over arbitrary operands.
//! Most of them are asserted here over *particular* configurations instead —
//! identical layers, disjoint layers, and one layer nested inside another —
//! and that restriction is not a choice about coverage.
//!
//! [`ValidatedLayer`] holds ring spans and polygon spans, indices into a
//! [`GeometryStore`]. It holds no coordinates, and [`ValidatedLayer::get`] takes
//! the store as a parameter. So a result whose geometry is *new* — the L that
//! two partially overlapping rectangles union into — has nowhere to live, and a
//! test cannot read one back. The configurations below are the ones whose
//! results are expressible as spans over the input store: a union that is one
//! operand, an intersection that is one operand, a difference that is empty, and
//! a union of disjoint operands that is the concatenation. This is recorded in
//! `docs/NEED_TESTING.md` as a Definition-Phase defect; it is not fixed here,
//! because signatures are frozen.
//!
//! Region equality is asserted as "each difference is empty and the areas
//! agree", which needs only the *empty* result to be expressible. That is what
//! lets the identity and commutativity laws below run at all.

use gpurify_core::boolean::{intersection_into, offset_into, subtraction_into, union_into};
use gpurify_core::view::{validate_layer_into, ValidatedLayer};
use gpurify_core::{GeometryStore, LayerId};
use gpurify_testgen::shapes::{
    dbu, l_shape, l_shape_area, rect, u_shape, u_shape_area, LayoutBuilder,
};
use gpurify_testgen::Rng;
use gpurify_units::DbuArea;

const A: LayerId = LayerId(0);
const B: LayerId = LayerId(1);

fn zero() -> DbuArea {
    DbuArea::new(0)
}

fn total_area(store: &GeometryStore, layer: &ValidatedLayer) -> DbuArea {
    (0..u32::try_from(layer.len()).expect("a test layer fits a u32"))
        .map(|index| layer.get(store, index).area())
        .fold(zero(), |total, area| total + area)
}

fn validated(store: &GeometryStore, layer: LayerId) -> ValidatedLayer {
    let mut out = ValidatedLayer::default();
    validate_layer_into(store, layer, &mut out).expect("generated geometry is valid");
    out
}

/// Region equality, expressed so that only an empty result has to be
/// representable: two regions are equal when neither has area the other lacks
/// and their areas agree.
fn assert_same_region(
    store: &GeometryStore,
    left: &ValidatedLayer,
    right: &ValidatedLayer,
    what: &str,
) {
    let mut scratch = ValidatedLayer::default();

    subtraction_into(left, right, &mut scratch).expect("rectilinear operands");
    assert_eq!(
        total_area(store, &scratch),
        zero(),
        "{what}: the left region has area the right one does not"
    );

    subtraction_into(right, left, &mut scratch).expect("rectilinear operands");
    assert_eq!(
        total_area(store, &scratch),
        zero(),
        "{what}: the right region has area the left one does not"
    );

    assert_eq!(
        total_area(store, left),
        total_area(store, right),
        "{what}: the two regions differ in area"
    );
}

/// Two layers whose shapes never meet: `A` on the left, `B` well to the right.
/// Areas are stated by the generator's closed forms.
fn disjoint_layers() -> (GeometryStore, DbuArea, DbuArea) {
    let mut layout = LayoutBuilder::new(2);
    layout.rect(A, 0, 0, 100, 50);
    layout.shape(A, &l_shape(0, 200, 90, 20));
    layout.shape(A, &u_shape(0, 500, 80, 15, 25));
    layout.rect(B, 10_000, 0, 10_060, 60);
    layout.shape(B, &l_shape(10_000, 200, 70, 30));
    let (store, _ids) = layout.finish();
    (
        store,
        DbuArea::new(100 * 50 + l_shape_area(90, 20) + u_shape_area(80, 15, 25)),
        DbuArea::new(60 * 60 + l_shape_area(70, 30)),
    )
}

/// Oracle: law. Self-union and self-intersection are idempotent, and a layer
/// minus itself is nothing at all. These hold for arbitrary operands, and the
/// operands here are three non-convex shapes whose bounding boxes overstate
/// them, so an implementation working on boxes fails.
#[test]
fn a_layer_unioned_intersected_and_subtracted_with_itself_behaves() {
    let (store, area_a, _) = disjoint_layers();
    let a = validated(&store, A);
    assert_eq!(total_area(&store, &a), area_a, "the operand's own area");

    let mut out = ValidatedLayer::default();

    union_into(&a, &a, &mut out).expect("rectilinear operands");
    assert_same_region(&store, &out, &a, "self-union is not idempotent");

    intersection_into(&a, &a, &mut out).expect("rectilinear operands");
    assert_same_region(&store, &out, &a, "self-intersection is not idempotent");

    subtraction_into(&a, &a, &mut out).expect("rectilinear operands");
    assert_eq!(total_area(&store, &out), zero(), "a minus a has area");
    assert!(out.is_empty(), "a minus a should hold no polygons at all");
    assert_eq!(out.len(), 0);
}

/// Oracle: law. `area(a ∪ b) + area(a ∩ b) == area(a) + area(b)` — inclusion
/// and exclusion, which holds for every pair of regions. On disjoint operands
/// the intersection contributes nothing, so the union has to account for both
/// operands exactly: an implementation that dropped or double-counted a polygon
/// fails on the left-hand side.
#[test]
fn area_is_conserved_under_union_and_intersection() {
    let (store, area_a, area_b) = disjoint_layers();
    let (a, b) = (validated(&store, A), validated(&store, B));

    let mut union = ValidatedLayer::default();
    let mut meet = ValidatedLayer::default();
    union_into(&a, &b, &mut union).expect("rectilinear operands");
    intersection_into(&a, &b, &mut meet).expect("rectilinear operands");

    assert_eq!(
        total_area(&store, &union) + total_area(&store, &meet),
        area_a + area_b,
        "inclusion-exclusion does not hold"
    );
    assert_eq!(
        total_area(&store, &meet),
        zero(),
        "disjoint layers cannot intersect"
    );
    assert_eq!(total_area(&store, &union), area_a + area_b);
    assert_eq!(
        union.len(),
        a.len() + b.len(),
        "no shape merged or vanished"
    );
}

/// Oracle: law. `a ∩ b ⊆ a` and `a ∪ b ⊇ a`, for any operands. Expressed the
/// only way a subset is expressible here: the part of the smaller region that
/// escapes the larger one has no area.
///
/// Four assertions that a difference is empty would all hold of a subtraction
/// that returned nothing whatever it was given, so the last assertion is the
/// one that makes the other four mean something: on these disjoint operands
/// `a − b` is the whole of `a`, which no vacuous implementation produces.
#[test]
fn the_intersection_is_a_subset_and_the_union_a_superset_of_each_operand() {
    let (store, area_a, _) = disjoint_layers();
    let (a, b) = (validated(&store, A), validated(&store, B));

    let mut meet = ValidatedLayer::default();
    let mut join = ValidatedLayer::default();
    let mut escaped = ValidatedLayer::default();
    intersection_into(&a, &b, &mut meet).expect("rectilinear operands");
    union_into(&a, &b, &mut join).expect("rectilinear operands");

    for (smaller, larger, what) in [
        (&meet, &a, "a intersect b escapes a"),
        (&meet, &b, "a intersect b escapes b"),
        (&a, &join, "a escapes a union b"),
        (&b, &join, "b escapes a union b"),
    ] {
        subtraction_into(smaller, larger, &mut escaped).expect("rectilinear operands");
        assert_eq!(total_area(&store, &escaped), zero(), "{what}");
    }

    subtraction_into(&a, &b, &mut escaped).expect("rectilinear operands");
    assert_eq!(
        total_area(&store, &escaped),
        area_a,
        "b takes nothing from a when the two are disjoint, so the four empty \
         differences above are a result and not a subtraction that never fires"
    );
    assert_eq!(escaped.len(), a.len(), "and it keeps every polygon of a");
}

/// Oracle: law. Union and intersection commute. Operand order changes nothing
/// about a region, so the two orderings must describe the same one — and the
/// generated corpus is asymmetric enough that an implementation reading only
/// its first operand fails.
#[test]
fn union_and_intersection_commute() {
    let (store, _, _) = disjoint_layers();
    let (a, b) = (validated(&store, A), validated(&store, B));

    let mut forward = ValidatedLayer::default();
    let mut backward = ValidatedLayer::default();

    union_into(&a, &b, &mut forward).expect("rectilinear operands");
    union_into(&b, &a, &mut backward).expect("rectilinear operands");
    assert_same_region(&store, &forward, &backward, "union does not commute");

    intersection_into(&a, &b, &mut forward).expect("rectilinear operands");
    intersection_into(&b, &a, &mut backward).expect("rectilinear operands");
    assert_same_region(&store, &forward, &backward, "intersection does not commute");
}

/// Oracle: law. `(a − b) ∪ (a ∩ b) == a`: difference and intersection partition
/// the first operand, so putting them back together recovers it. This is the
/// law that fails if a subtraction quietly drops a sliver, which is one of the
/// three fail-open defects the previous implementation carried.
#[test]
fn difference_and_intersection_partition_the_first_operand() {
    let (store, _, _) = disjoint_layers();
    let (a, b) = (validated(&store, A), validated(&store, B));

    let mut difference = ValidatedLayer::default();
    let mut meet = ValidatedLayer::default();
    let mut rebuilt = ValidatedLayer::default();

    subtraction_into(&a, &b, &mut difference).expect("rectilinear operands");
    intersection_into(&a, &b, &mut meet).expect("rectilinear operands");
    union_into(&difference, &meet, &mut rebuilt).expect("rectilinear operands");

    assert_same_region(&store, &rebuilt, &a, "the operand was not recovered");
    assert_eq!(
        total_area(&store, &difference) + total_area(&store, &meet),
        total_area(&store, &a),
        "the two parts do not sum to the whole"
    );
}

/// Oracle: construct-from-answer. Two layers holding identical geometry are the
/// same region, so the union is that region, the intersection is that region,
/// and the difference is empty. This is the fully-overlapping case, which the
/// disjoint corpus above cannot reach.
#[test]
fn identical_layers_union_and_intersect_to_themselves_and_subtract_to_nothing() {
    let shapes = [
        rect(0, 0, 120, 80),
        l_shape(300, 0, 100, 40),
        u_shape(0, 300, 90, 20, 30),
    ];
    let mut layout = LayoutBuilder::new(2);
    for shape in &shapes {
        layout.shape(A, shape);
        layout.shape(B, shape);
    }
    let (store, _ids) = layout.finish();
    let (a, b) = (validated(&store, A), validated(&store, B));

    let expected = DbuArea::new(120 * 80 + l_shape_area(100, 40) + u_shape_area(90, 20, 30));
    assert_eq!(total_area(&store, &a), expected);
    assert_eq!(total_area(&store, &b), expected);

    let mut out = ValidatedLayer::default();

    union_into(&a, &b, &mut out).expect("rectilinear operands");
    assert_eq!(
        total_area(&store, &out),
        expected,
        "the union double-counted"
    );
    assert_same_region(&store, &out, &a, "union of a region with itself");

    intersection_into(&a, &b, &mut out).expect("rectilinear operands");
    assert_eq!(
        total_area(&store, &out),
        expected,
        "the intersection lost area"
    );
    assert_same_region(&store, &out, &a, "intersection of a region with itself");

    subtraction_into(&a, &b, &mut out).expect("rectilinear operands");
    assert!(out.is_empty(), "identical layers leave nothing behind");
    subtraction_into(&b, &a, &mut out).expect("rectilinear operands");
    assert!(out.is_empty(), "and the same the other way round");
}

/// Oracle: construct-from-answer. When every shape of `b` lies strictly inside a
/// shape of `a`, the union is `a` and the intersection is `b`. Partial overlap
/// is the case this cannot reach, for the representation reason in this file's
/// header.
#[test]
fn a_contained_layer_unions_to_its_container_and_intersects_to_itself() {
    let mut layout = LayoutBuilder::new(2);
    layout.rect(A, 0, 0, 1_000, 1_000);
    layout.rect(A, 2_000, 0, 3_000, 1_000);
    layout.rect(B, 100, 100, 400, 400);
    layout.rect(B, 500, 600, 900, 900);
    layout.rect(B, 2_100, 100, 2_900, 900);
    let (store, _ids) = layout.finish();
    let (a, b) = (validated(&store, A), validated(&store, B));

    let area_a = DbuArea::new(2 * 1_000 * 1_000);
    let area_b = DbuArea::new(300 * 300 + 400 * 300 + 800 * 800);
    assert_eq!(total_area(&store, &a), area_a);
    assert_eq!(total_area(&store, &b), area_b);

    let mut out = ValidatedLayer::default();
    union_into(&a, &b, &mut out).expect("rectilinear operands");
    assert_same_region(&store, &out, &a, "the container swallowed the contained");
    assert_eq!(total_area(&store, &out), area_a);

    intersection_into(&a, &b, &mut out).expect("rectilinear operands");
    assert_same_region(&store, &out, &b, "the contained survived intact");
    assert_eq!(total_area(&store, &out), area_b);

    // Inclusion-exclusion again, now with a non-empty intersection.
    let mut meet = ValidatedLayer::default();
    let mut join = ValidatedLayer::default();
    intersection_into(&a, &b, &mut meet).expect("rectilinear operands");
    union_into(&a, &b, &mut join).expect("rectilinear operands");
    assert_eq!(
        total_area(&store, &join) + total_area(&store, &meet),
        area_a + area_b
    );
}

/// Oracle: law. A boolean is a statement about regions, so translating every
/// input translates the result and changes no area. Coordinate-independence is
/// the law an implementation cannot dodge by special-casing a fixture's
/// coordinates.
#[test]
fn a_boolean_result_is_invariant_under_translation_of_every_input() {
    let mut rng = Rng::new(51);
    let (base_store, area_a, area_b) = disjoint_layers();
    let base_union = {
        let (a, b) = (validated(&base_store, A), validated(&base_store, B));
        let mut out = ValidatedLayer::default();
        union_into(&a, &b, &mut out).expect("rectilinear operands");
        (total_area(&base_store, &out), out.len())
    };

    for _ in 0..8 {
        let (dx, dy) = (rng.range(-400_000, 400_000), rng.range(-400_000, 400_000));
        let mut layout = LayoutBuilder::new(2);
        layout.rect(A, dx, dy, dx + 100, dy + 50);
        layout.shape(A, &l_shape(dx, dy + 200, 90, 20));
        layout.shape(A, &u_shape(dx, dy + 500, 80, 15, 25));
        layout.rect(B, dx + 10_000, dy, dx + 10_060, dy + 60);
        layout.shape(B, &l_shape(dx + 10_000, dy + 200, 70, 30));
        let (store, _ids) = layout.finish();

        let (a, b) = (validated(&store, A), validated(&store, B));
        assert_eq!(total_area(&store, &a), area_a, "shifted by ({dx}, {dy})");
        assert_eq!(total_area(&store, &b), area_b, "shifted by ({dx}, {dy})");

        let mut out = ValidatedLayer::default();
        union_into(&a, &b, &mut out).expect("rectilinear operands");
        assert_eq!(
            (total_area(&store, &out), out.len()),
            base_union,
            "the union changed when every input moved by ({dx}, {dy})"
        );
    }
}

/// Oracle: law. Growing by nothing is the identity, and it is the one offset
/// whose result is expressible as spans over the input store. A non-zero offset
/// produces coordinates that exist in no store, so it cannot be read back — the
/// same representation defect the header records.
#[test]
fn an_offset_of_zero_is_the_identity() {
    let (store, area_a, _) = disjoint_layers();
    let a = validated(&store, A);

    let mut out = ValidatedLayer::default();
    offset_into(&a, dbu(0), &mut out).expect("rectilinear operand");
    assert_eq!(
        total_area(&store, &out),
        area_a,
        "a zero offset changed area"
    );
    assert_eq!(
        out.len(),
        a.len(),
        "a zero offset changed the polygon count"
    );
    assert_same_region(&store, &out, &a, "a zero offset moved the region");
}

/// Oracle: determinism. A derived-layer expression tree chains these, so a
/// boolean that produced its polygons in a different order on a second run
/// would make every downstream report non-reproducible. Run the same union
/// twice into a buffer that already holds a different result, which is exactly
/// how a caller reuses one.
#[test]
fn two_runs_of_one_boolean_produce_the_same_polygons_in_the_same_order() {
    let (store, _, _) = disjoint_layers();
    let (a, b) = (validated(&store, A), validated(&store, B));

    let mut buffer = ValidatedLayer::default();
    intersection_into(&a, &b, &mut buffer).expect("rectilinear operands");

    union_into(&a, &b, &mut buffer).expect("rectilinear operands");
    let first: Vec<_> = (0..u32::try_from(buffer.len()).expect("a small layer fits a u32"))
        .map(|index| {
            let poly = buffer.get(&store, index);
            (poly.bbox(), poly.area(), poly.holes().count())
        })
        .collect();

    union_into(&a, &b, &mut buffer).expect("rectilinear operands");
    let second: Vec<_> = (0..u32::try_from(buffer.len()).expect("a small layer fits a u32"))
        .map(|index| {
            let poly = buffer.get(&store, index);
            (poly.bbox(), poly.area(), poly.holes().count())
        })
        .collect();

    assert_eq!(first, second, "the union is not reproducible");
    assert!(!first.is_empty(), "the comparison would be vacuous");
}
