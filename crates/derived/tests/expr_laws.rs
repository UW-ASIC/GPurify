//! The boolean laws, lifted from one operation to a whole layer and run
//! through the evaluator.
//!
//! `core::boolean` states the laws and owns them for a single call. This file
//! asserts they survive the trip through a `DerivedExpr` tree, which is a
//! different claim: an evaluator that swaps its two scratch buffers one node
//! too late, or hands a cached result to the wrong name, breaks every law here
//! without breaking a single boolean.
//!
//! # The geometry
//!
//! Everything below runs on an L, a plus and a U as well as rectangles. That is
//! deliberate. The evaluator this crate replaces approximated `And` on bounding
//! boxes on the argument that boxes are sufficient for manhattan geometry, and
//! **every law in this file holds for that approximation on rectangles alone.**
//! The non-convex shapes are what make the tests able to fail.

use gpurify_core::view::validate_layer_into;
use gpurify_core::{GeometryStore, LayerId, ValidatedLayer};
use gpurify_derived::{DerivedError, DerivedExpr, Evaluator, LayerRef};
use gpurify_ingest::StrId;
use gpurify_testgen::{assert_bytes_identical, dbu, shapes, LayoutBuilder};
use gpurify_units::{Dbu, DbuArea};

const OPERAND_A: LayerId = LayerId(0);
const OPERAND_B: LayerId = LayerId(1);
const UNIVERSE: LayerId = LayerId(2);
const LAYER_COUNT: usize = 3;

// ---------------------------------------------------------------------------
// Expression constructors, so a law reads as the law and not as boxing.
// ---------------------------------------------------------------------------

fn base(layer: LayerId) -> DerivedExpr {
    DerivedExpr::Layer(LayerRef::Base(layer))
}

fn named(name: StrId) -> DerivedExpr {
    DerivedExpr::Layer(LayerRef::Named(name))
}

fn union(lhs: DerivedExpr, rhs: DerivedExpr) -> DerivedExpr {
    DerivedExpr::Union(Box::new(lhs), Box::new(rhs))
}

fn intersection(lhs: DerivedExpr, rhs: DerivedExpr) -> DerivedExpr {
    DerivedExpr::Intersection(Box::new(lhs), Box::new(rhs))
}

fn subtraction(lhs: DerivedExpr, rhs: DerivedExpr) -> DerivedExpr {
    DerivedExpr::Subtraction(Box::new(lhs), Box::new(rhs))
}

fn offset(operand: DerivedExpr, amount: i64) -> DerivedExpr {
    DerivedExpr::Offset(Box::new(operand), dbu(amount))
}

fn inside(operand: DerivedExpr, region: DerivedExpr) -> DerivedExpr {
    DerivedExpr::Inside {
        operand: Box::new(operand),
        region: Box::new(region),
    }
}

fn outside(operand: DerivedExpr, region: DerivedExpr, universe: DerivedExpr) -> DerivedExpr {
    DerivedExpr::Outside {
        operand: Box::new(operand),
        region: Box::new(region),
        universe: Box::new(universe),
    }
}

// ---------------------------------------------------------------------------
// Comparing two evaluated layers.
// ---------------------------------------------------------------------------

/// One layer as a sorted, comparable list of (bounding box, area) per polygon.
///
/// Two layers holding the same shapes have the same signature whatever order
/// their rows came out in, and two layers holding different shapes do not:
/// bounding box alone would not separate an L from its box, and area alone
/// would not separate a shape from the same shape somewhere else. Together they
/// separate everything these tests build.
type Signature = Vec<(Dbu, Dbu, Dbu, Dbu, DbuArea)>;

fn signature(store: &GeometryStore, layer: &ValidatedLayer) -> Signature {
    let mut rows: Signature = (0..layer.len())
        .map(|index| {
            let polygon = layer.get(
                store,
                u32::try_from(index).expect("a polygon count fits a u32"),
            );
            let bbox = polygon.bbox();
            (bbox.xlo, bbox.ylo, bbox.xhi, bbox.yhi, polygon.area())
        })
        .collect();
    rows.sort_unstable();
    rows
}

/// Total area of a layer. The one quantity every conservation law below is
/// stated in, and exact: `DbuArea` is an `i128` and nothing here divides.
fn total_area(signature: &Signature) -> DbuArea {
    signature
        .iter()
        .fold(DbuArea::new(0), |sum, row| sum + row.4)
}

/// Plan and evaluate a list of definitions, in the form a deck states them.
fn evaluate(store: &GeometryStore, definitions: &[(StrId, DerivedExpr)]) -> Evaluator {
    let names: Vec<StrId> = definitions.iter().map(|(name, _)| *name).collect();
    let exprs: Vec<DerivedExpr> = definitions.iter().map(|(_, expr)| expr.clone()).collect();
    let mut evaluator = Evaluator::plan(&names, &exprs).expect("the definitions form a DAG");
    evaluator
        .evaluate(store)
        .expect("every reference resolves against this store");
    evaluator
}

fn layer_of(store: &GeometryStore, evaluator: &Evaluator, name: StrId) -> Signature {
    let layer = evaluator
        .get(name)
        .unwrap_or_else(|| panic!("{name:?} was defined, so it must have been evaluated"));
    signature(store, layer)
}

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

fn shifted(shape: &(Vec<i64>, Vec<i64>), dx: i64, dy: i64) -> (Vec<i64>, Vec<i64>) {
    (
        shape.0.iter().map(|x| x + dx).collect(),
        shape.1.iter().map(|y| y + dy).collect(),
    )
}

/// Two layers of partly overlapping non-convex geometry, plus a universe box
/// with room to spare around both.
///
/// `dx`/`dy` translate the whole thing, which is what makes translation
/// invariance checkable without a second fixture.
fn overlapping_store(dx: i64, dy: i64) -> GeometryStore {
    let mut layout = LayoutBuilder::new(LAYER_COUNT);

    // An L whose bounding box is 400 square but whose area is not, a plus with
    // four reflex corners, and a rectangle far enough away that no operand on
    // the other layer reaches it.
    layout.shape(
        OPERAND_A,
        &shifted(&shapes::l_shape(0, 0, 400, 120), dx, dy),
    );
    layout.shape(
        OPERAND_A,
        &shifted(&shapes::plus_shape(900, 300, 200, 80), dx, dy),
    );
    layout.rect(OPERAND_A, dx + 1400, dy, dx + 1600, dy + 200);

    // A rectangle cutting across the L's inner corner, and a U straddling the
    // plus. Neither reaches the third shape on layer A.
    layout.rect(OPERAND_B, dx + 200, dy - 100, dx + 600, dy + 300);
    layout.shape(
        OPERAND_B,
        &shifted(&shapes::u_shape(700, 100, 300, 60, 140), dx, dy),
    );

    layout.rect(UNIVERSE, dx - 4000, dy - 4000, dx + 4000, dy + 4000);

    let (store, _) = layout.finish();
    store
}

/// Shapes far enough apart that growing them by 40 cannot merge any two, and
/// thick enough that shrinking by 40 cannot break any one in half.
///
/// Both conditions are what make grow-then-shrink an identity rather than an
/// approximation, and both are properties of these coordinates: the closest
/// approach between shapes is 600 and the narrowest feature is 120.
fn well_separated_store() -> GeometryStore {
    let mut layout = LayoutBuilder::new(LAYER_COUNT);
    layout.shape(OPERAND_A, &shapes::l_shape(0, 0, 400, 120));
    layout.rect(OPERAND_A, 1200, 0, 1600, 400);
    layout.shape(OPERAND_A, &shapes::u_shape(0, 1200, 400, 120, 200));
    layout.rect(UNIVERSE, -4000, -4000, 4000, 4000);
    let (store, _) = layout.finish();
    store
}

/// Three operand shapes, each of them wholly inside the region or wholly clear
/// of it, and a universe containing everything.
///
/// The "wholly" matters: it is the one configuration where selecting shapes and
/// clipping area agree, so the partition law below holds under either reading
/// of what `Inside` and `Outside` return.
fn cleanly_split_store() -> GeometryStore {
    let mut layout = LayoutBuilder::new(LAYER_COUNT);
    layout.rect(OPERAND_A, 100, 100, 300, 300);
    layout.shape(OPERAND_A, &shapes::l_shape(400, 100, 200, 60));
    layout.rect(OPERAND_A, 2000, 2000, 2200, 2200);
    layout.rect(OPERAND_B, 0, 0, 800, 800);
    layout.rect(UNIVERSE, -4000, -4000, 4000, 4000);
    let (store, _) = layout.finish();
    store
}

// ---------------------------------------------------------------------------
// The laws.
// ---------------------------------------------------------------------------

/// Oracle: law. Union and intersection are commutative for any two sets, so
/// this needs no constructed answer and holds on whatever geometry it is
/// handed. Swapping operands is also the cheapest way to catch an evaluator
/// that reads one scratch buffer while writing the other.
#[test]
fn union_and_intersection_commute_over_whole_layers() {
    let store = overlapping_store(0, 0);
    let (ab, ba, ab_cut, ba_cut) = (StrId(1), StrId(2), StrId(3), StrId(4));
    let evaluator = evaluate(
        &store,
        &[
            (ab, union(base(OPERAND_A), base(OPERAND_B))),
            (ba, union(base(OPERAND_B), base(OPERAND_A))),
            (ab_cut, intersection(base(OPERAND_A), base(OPERAND_B))),
            (ba_cut, intersection(base(OPERAND_B), base(OPERAND_A))),
        ],
    );

    let (joined, common) = (
        layer_of(&store, &evaluator, ab),
        layer_of(&store, &evaluator, ab_cut),
    );
    assert!(
        !joined.is_empty() && !common.is_empty(),
        "the fixture puts area in both operands and area in both at once, so an \
         empty union or an empty intersection is a wrong answer rather than a \
         degenerate case, and commutativity holds trivially between two of them"
    );
    assert_eq!(
        joined,
        layer_of(&store, &evaluator, ba),
        "a union changed when its operands were swapped"
    );
    assert_eq!(
        common,
        layer_of(&store, &evaluator, ba_cut),
        "an intersection changed when its operands were swapped"
    );
}

/// Oracle: law. Subtraction is the one operator where operand order is a silent
/// wrong answer rather than a compile error, so the asymmetry has to be
/// asserted rather than assumed. Both operands hold area the other does not, so
/// the two differences are genuinely different sets.
#[test]
fn subtracting_in_the_other_order_gives_a_different_layer() {
    let store = overlapping_store(0, 0);
    let (a_less_b, b_less_a) = (StrId(1), StrId(2));
    let evaluator = evaluate(
        &store,
        &[
            (a_less_b, subtraction(base(OPERAND_A), base(OPERAND_B))),
            (b_less_a, subtraction(base(OPERAND_B), base(OPERAND_A))),
        ],
    );

    let left = layer_of(&store, &evaluator, a_less_b);
    let right = layer_of(&store, &evaluator, b_less_a);
    assert!(
        !left.is_empty() && !right.is_empty(),
        "both differences are non-empty on this geometry, so an empty one is a \
         wrong answer, not a degenerate case: {left:?} against {right:?}"
    );
    assert_ne!(
        left, right,
        "subtraction commuted, which it must not: each operand covers area the \
         other does not"
    );
}

/// Oracle: law. `(a − b) ∪ (a ∩ b) == a` for any two sets. It is the strongest
/// single statement about subtraction available without a constructed answer,
/// because it fails in both directions: a subtraction that removes too much
/// loses area the intersection does not restore, and one that removes too
/// little leaves area the intersection double-counts.
#[test]
fn subtraction_and_intersection_partition_the_left_operand() {
    let store = overlapping_store(0, 0);
    let (difference, common, rejoined) = (StrId(1), StrId(2), StrId(3));
    let evaluator = evaluate(
        &store,
        &[
            (difference, subtraction(base(OPERAND_A), base(OPERAND_B))),
            (common, intersection(base(OPERAND_A), base(OPERAND_B))),
            (rejoined, union(named(difference), named(common))),
        ],
    );

    let mut expected = ValidatedLayer::default();
    validate_layer_into(&store, OPERAND_A, &mut expected)
        .expect("the fixture is valid rectilinear geometry");
    assert_eq!(
        layer_of(&store, &evaluator, rejoined),
        signature(&store, &expected),
        "(a - b) union (a intersect b) is not a"
    );
}

/// Total area of the shapes `overlapping_store` puts on each operand layer.
///
/// Closed form, and worth stating rather than measuring: no two shapes on one
/// layer of that fixture touch, so a layer's area is the sum of the shape areas
/// `testgen` states analytically. It is the anchor that stops the
/// inclusion-exclusion law below from holding trivially between two empty
/// layers.
fn operand_areas() -> (DbuArea, DbuArea) {
    let a = shapes::l_shape_area(400, 120) + shapes::plus_shape_area(200, 80) + 200 * 200;
    let b = 400 * 400 + shapes::u_shape_area(300, 60, 140);
    (DbuArea::new(a), DbuArea::new(b))
}

/// Oracle: law, anchored on a closed form. `area(a ∪ b) + area(a ∩ b) ==
/// area(a) + area(b)`, by inclusion-exclusion, for any two sets — and the two
/// right-hand terms are known analytically for this fixture, so the identity
/// cannot be satisfied by an evaluator that produces nothing.
///
/// Independent of the signature comparison used everywhere else here: it would
/// still catch a boolean that produced the right shapes with the wrong winding,
/// because winding is what signed area is made of.
#[test]
fn area_is_conserved_under_union_and_intersection() {
    let store = overlapping_store(0, 0);
    let (joined, common, left, right) = (StrId(1), StrId(2), StrId(3), StrId(4));
    let evaluator = evaluate(
        &store,
        &[
            (joined, union(base(OPERAND_A), base(OPERAND_B))),
            (common, intersection(base(OPERAND_A), base(OPERAND_B))),
            (left, base(OPERAND_A)),
            (right, base(OPERAND_B)),
        ],
    );

    let (a_area, b_area) = operand_areas();
    assert_eq!(
        total_area(&layer_of(&store, &evaluator, left)),
        a_area,
        "layer A is an L, a plus and a rectangle, none of them touching, so its \
         area is the sum of the three closed forms"
    );
    assert_eq!(
        total_area(&layer_of(&store, &evaluator, right)),
        b_area,
        "layer B is a rectangle and a U, not touching, so its area is the sum of \
         the two closed forms"
    );

    let combined = total_area(&layer_of(&store, &evaluator, joined))
        + total_area(&layer_of(&store, &evaluator, common));
    assert_eq!(
        combined,
        a_area + b_area,
        "area(a or b) + area(a and b) must equal area(a) + area(b)"
    );
}

/// Oracle: law. Idempotence and absorption: `a ∪ a == a` and
/// `a ∪ (a ∩ b) == a`. Both are cheap and both catch the same class of defect,
/// a union that appends rows instead of merging overlapping ones — which
/// produces a layer with twice the area and no error.
#[test]
fn union_is_idempotent_and_absorbs_an_intersection_it_contains() {
    let store = overlapping_store(0, 0);
    let (doubled, absorbed, common) = (StrId(1), StrId(2), StrId(3));
    let evaluator = evaluate(
        &store,
        &[
            (doubled, union(base(OPERAND_A), base(OPERAND_A))),
            (common, intersection(base(OPERAND_A), base(OPERAND_B))),
            (absorbed, union(base(OPERAND_A), named(common))),
        ],
    );

    let mut expected = ValidatedLayer::default();
    validate_layer_into(&store, OPERAND_A, &mut expected)
        .expect("the fixture is valid rectilinear geometry");
    let original = signature(&store, &expected);
    assert_eq!(
        layer_of(&store, &evaluator, doubled),
        original,
        "a union with itself is not itself"
    );
    assert_eq!(
        layer_of(&store, &evaluator, absorbed),
        original,
        "a union with something it already contains is not itself"
    );
}

/// Oracle: law. De Morgan, against the explicit finite universe the enum
/// requires: `U − (a ∪ b) == (U − a) ∩ (U − b)` and
/// `U − (a ∩ b) == (U − a) ∪ (U − b)`.
///
/// The universe here contains both operands with four thousand units of margin
/// on every side, which is what makes complementation well defined. Over an
/// unbounded plane neither side of either identity is a set of polygons at all,
/// and that is the reason `Outside` takes a universe rather than assuming one.
#[test]
fn de_morgan_holds_against_an_explicit_universe() {
    let store = overlapping_store(0, 0);
    let (not_a, not_b) = (StrId(1), StrId(2));
    let (not_either, both_nots) = (StrId(3), StrId(4));
    let (not_both, either_not) = (StrId(5), StrId(6));
    let joined = StrId(7);
    let evaluator = evaluate(
        &store,
        &[
            (not_a, subtraction(base(UNIVERSE), base(OPERAND_A))),
            (not_b, subtraction(base(UNIVERSE), base(OPERAND_B))),
            (joined, union(base(OPERAND_A), base(OPERAND_B))),
            (
                not_either,
                subtraction(base(UNIVERSE), union(base(OPERAND_A), base(OPERAND_B))),
            ),
            (both_nots, intersection(named(not_a), named(not_b))),
            (
                not_both,
                subtraction(
                    base(UNIVERSE),
                    intersection(base(OPERAND_A), base(OPERAND_B)),
                ),
            ),
            (either_not, union(named(not_a), named(not_b))),
        ],
    );

    // Closed form, and the reason this test cannot hold trivially: the universe
    // is an 8000-square box containing both operands with room to spare, so a
    // complement and the thing it complements must tile it exactly. Two empty
    // layers satisfy both De Morgan identities below and fail this.
    assert_eq!(
        total_area(&layer_of(&store, &evaluator, not_either))
            + total_area(&layer_of(&store, &evaluator, joined)),
        DbuArea::new(8_000 * 8_000),
        "the complement of a union and the union itself must tile the universe"
    );

    assert_eq!(
        layer_of(&store, &evaluator, not_either),
        layer_of(&store, &evaluator, both_nots),
        "the complement of a union is not the intersection of the complements"
    );
    assert_eq!(
        layer_of(&store, &evaluator, not_both),
        layer_of(&store, &evaluator, either_not),
        "the complement of an intersection is not the union of the complements"
    );
}

/// Oracle: law. `Inside` and `Outside` partition the operand they select from:
/// together they are all of it, and they share nothing.
///
/// Every operand shape in this fixture lies wholly within the region or wholly
/// clear of it, which is what lets the law be stated without first settling
/// whether the two operators select whole shapes or clip area. Under either
/// reading the answer is the same here, so the test measures the partition and
/// not the interpretation.
#[test]
fn inside_and_outside_partition_the_operand_they_select_from() {
    let store = cleanly_split_store();
    let (selected, rejected, rejoined, shared) = (StrId(1), StrId(2), StrId(3), StrId(4));
    let evaluator = evaluate(
        &store,
        &[
            (selected, inside(base(OPERAND_A), base(OPERAND_B))),
            (
                rejected,
                outside(base(OPERAND_A), base(OPERAND_B), base(UNIVERSE)),
            ),
            (rejoined, union(named(selected), named(rejected))),
            (shared, intersection(named(selected), named(rejected))),
        ],
    );

    let mut expected = ValidatedLayer::default();
    validate_layer_into(&store, OPERAND_A, &mut expected)
        .expect("the fixture is valid rectilinear geometry");
    assert_eq!(
        layer_of(&store, &evaluator, rejoined),
        signature(&store, &expected),
        "inside and outside do not cover the operand between them"
    );
    assert!(
        layer_of(&store, &evaluator, shared).is_empty(),
        "inside and outside overlap, so they are not a partition"
    );
    assert!(
        !layer_of(&store, &evaluator, selected).is_empty()
            && !layer_of(&store, &evaluator, rejected).is_empty(),
        "this fixture puts two shapes in the region and one outside it, so an \
         empty half means the selection did not run"
    );
}

/// Oracle: closed form. An L-infinity grow by `d` moves every edge of an
/// axis-aligned rectangle out by `d`, so the answer for a single rectangle is
/// arithmetic: the box is `[60, 540] x [160, 940]` and the area is
/// `480 * 780`. A Euclidean kernel, a per-vertex offset, or a grow applied to
/// only one axis all fail this, and none of them fails the conservation laws
/// above.
#[test]
fn growing_and_shrinking_one_rectangle_matches_the_closed_form() {
    let mut layout = LayoutBuilder::new(LAYER_COUNT);
    layout.rect(OPERAND_A, 100, 200, 500, 900);
    let (store, _) = layout.finish();

    let (grown, shrunk) = (StrId(1), StrId(2));
    let evaluator = evaluate(
        &store,
        &[
            (grown, offset(base(OPERAND_A), 40)),
            (shrunk, offset(base(OPERAND_A), -40)),
        ],
    );

    assert_eq!(
        layer_of(&store, &evaluator, grown),
        vec![(
            dbu(60),
            dbu(160),
            dbu(540),
            dbu(940),
            DbuArea::new(480 * 780)
        )],
        "growing [100, 500] x [200, 900] by 40 must give [60, 540] x [160, 940]"
    );
    assert_eq!(
        layer_of(&store, &evaluator, shrunk),
        vec![(
            dbu(140),
            dbu(240),
            dbu(460),
            dbu(860),
            DbuArea::new(320 * 620)
        )],
        "shrinking [100, 500] x [200, 900] by 40 must give [140, 460] x [240, 860]"
    );
}

/// Oracle: law. Grow by `d` then shrink by `d` is the identity on any shape
/// whose features are all wider than `2d` and whose separations all exceed
/// `2d`. The fixture guarantees both — narrowest feature 120, closest approach
/// 600, `d` of 40 — so the round trip must return the layer unchanged.
///
/// The L and the U are why this is worth running. Their reflex corners are
/// exactly where a grow-then-shrink that treats each polygon as its bounding
/// box, or that rounds a corner, loses the notch and returns something larger.
#[test]
fn growing_then_shrinking_by_the_same_amount_restores_the_layer() {
    let store = well_separated_store();
    let round_trip = StrId(1);
    let evaluator = evaluate(
        &store,
        &[(round_trip, offset(offset(base(OPERAND_A), 40), -40))],
    );

    let mut expected = ValidatedLayer::default();
    validate_layer_into(&store, OPERAND_A, &mut expected)
        .expect("the fixture is valid rectilinear geometry");
    assert_eq!(
        layer_of(&store, &evaluator, round_trip),
        signature(&store, &expected),
        "a grow of 40 followed by a shrink of 40 changed a layer whose narrowest \
         feature is 120 and whose closest approach is 600"
    );
}

/// Oracle: law. Every operation in the enum is defined by set membership, and
/// membership does not depend on where the origin is. So translating every
/// input by the same vector leaves every derived area untouched.
///
/// Areas rather than signatures, because the coordinates are exactly what the
/// translation changes. What must not change is the measurement, and a
/// coordinate-dependent shortcut — a comparison against zero, a sign test that
/// assumes positive quadrant — moves it.
#[test]
fn translating_every_input_leaves_every_derived_area_unchanged() {
    let definitions = |joined: StrId, common: StrId, difference: StrId| {
        vec![
            (joined, union(base(OPERAND_A), base(OPERAND_B))),
            (common, intersection(base(OPERAND_A), base(OPERAND_B))),
            (difference, subtraction(base(OPERAND_A), base(OPERAND_B))),
        ]
    };
    let (joined, common, difference) = (StrId(1), StrId(2), StrId(3));

    let origin = overlapping_store(0, 0);
    let moved = overlapping_store(-7_000, 3_500);
    let at_origin = evaluate(&origin, &definitions(joined, common, difference));
    let translated = evaluate(&moved, &definitions(joined, common, difference));

    for (name, what) in [
        (joined, "union"),
        (common, "intersection"),
        (difference, "subtraction"),
    ] {
        let before = layer_of(&origin, &at_origin, name);
        let after = layer_of(&moved, &translated, name);
        assert!(
            !before.is_empty(),
            "the {what} of this fixture is not empty, so an empty one is a wrong \
             answer and makes the comparison below vacuous"
        );
        assert_eq!(
            before.len(),
            after.len(),
            "the {what} produced a different polygon count after translation"
        );
        assert_eq!(
            before.iter().map(|row| row.4).collect::<Vec<DbuArea>>(),
            after.iter().map(|row| row.4).collect::<Vec<DbuArea>>(),
            "the {what} changed area when every input moved by the same vector"
        );
    }
}

/// Oracle: determinism. Anything producing output is run twice and compared
/// byte for byte. Two runs are done two ways on purpose: two fresh evaluators
/// prove the result does not depend on allocation history, and a second
/// `evaluate` on an evaluator that already has results proves the scratch
/// buffers the doc comment describes are cleared rather than accumulated.
#[test]
fn evaluating_the_same_definitions_twice_produces_identical_layers() {
    let store = overlapping_store(0, 0);
    let (joined, common, complement) = (StrId(1), StrId(2), StrId(3));
    let definitions = [
        (joined, union(base(OPERAND_A), base(OPERAND_B))),
        (common, intersection(base(OPERAND_A), base(OPERAND_B))),
        (
            complement,
            outside(base(OPERAND_A), base(OPERAND_B), base(UNIVERSE)),
        ),
    ];
    let names = [joined, common, complement];

    let render = |store: &GeometryStore, evaluator: &Evaluator| {
        let rows: Vec<Signature> = names
            .iter()
            .map(|&name| layer_of(store, evaluator, name))
            .collect();
        format!("{rows:?}").into_bytes()
    };

    let first = evaluate(&store, &definitions);
    let second = evaluate(&store, &definitions);
    for &name in &names {
        assert!(
            !layer_of(&store, &first, name).is_empty(),
            "{name:?} came out empty, and two empty renderings agree byte for byte \
             without anything having been produced"
        );
    }
    assert_bytes_identical(
        "a second evaluator",
        &render(&store, &first),
        &render(&store, &second),
    );

    let mut reused = evaluate(&store, &definitions);
    let once = render(&store, &reused);
    reused
        .evaluate(&store)
        .expect("re-evaluating the same plan against the same store still resolves");
    assert_bytes_identical("a re-run evaluator", &once, &render(&store, &reused));
}

/// Oracle: law. `Layer(Base(l))` is the identity, so its result must be the
/// layer `core` validates directly. This is the join between the two crates: if
/// it does not hold, every other law in this file could hold over the wrong
/// geometry and still pass.
#[test]
fn an_expression_naming_only_a_base_layer_is_that_validated_layer() {
    let store = overlapping_store(0, 0);
    let plain = StrId(1);
    let evaluator = evaluate(&store, &[(plain, base(OPERAND_A))]);

    let mut expected = ValidatedLayer::default();
    validate_layer_into(&store, OPERAND_A, &mut expected)
        .expect("the fixture is valid rectilinear geometry");
    assert_eq!(
        layer_of(&store, &evaluator, plain),
        signature(&store, &expected),
        "the identity expression did not return the layer it names"
    );
}

/// Oracle: construct-from-answer. Fail closed: a deck naming a layer the store
/// does not have is a typed error, never an empty result. An empty derived
/// layer would flow into every rule downstream as "nothing to check here",
/// which is the false-clean failure mode this workspace is built against.
#[test]
fn naming_a_layer_the_store_does_not_have_is_an_error_and_not_an_empty_layer() {
    let store = overlapping_store(0, 0);
    let absent = StrId(1);
    let names = [absent];
    let exprs = [base(LayerId(9))];

    let mut evaluator =
        Evaluator::plan(&names, &exprs).expect("a base-layer reference cannot form a cycle");
    let error = evaluator
        .evaluate(&store)
        .expect_err("layer 9 does not exist in a three-layer store");
    assert!(
        matches!(error, DerivedError::UnknownLayer),
        "an out-of-range base layer must be UnknownLayer, got {error:?}"
    );
}

/// Oracle: construct-from-answer. A lookup miss is `None`, not a panic and not
/// an empty layer. The distinction is what lets a caller tell "the deck does
/// not define this" from "the deck defines it and it came out empty".
#[test]
fn asking_for_a_name_the_deck_never_defined_returns_none() {
    let store = overlapping_store(0, 0);
    let defined = StrId(1);
    let evaluator = evaluate(&store, &[(defined, base(OPERAND_A))]);

    assert!(
        evaluator.get(StrId(2)).is_none(),
        "an undefined name resolved to a layer"
    );
    assert!(
        evaluator.get(defined).is_some(),
        "a defined name did not resolve, so the None above proves nothing"
    );
}
