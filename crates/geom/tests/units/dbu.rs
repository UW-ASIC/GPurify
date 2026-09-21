//! The coordinate domain and the widening product that rests on it.
//!
//! `MAX_ABS_DBU` is load-bearing for the whole tree: every `i128` area product
//! downstream is safe only because no coordinate exceeds `2^40`. So the domain
//! edge is tested as a closed form (the corner product is exactly `2^80`, a
//! number written out here rather than computed by the code under test), and
//! the arithmetic around it is tested as law, since "adding then subtracting
//! restores the original" holds for every pair and a hand-picked one proves
//! much less.

use gpurify_testgen::Rng;
use gpurify_geom::{Dbu, DbuArea, MAX_ABS_DBU};

/// Unwrap a coordinate the test asserts is inside the domain.
fn coord(raw: i64) -> Dbu {
    Dbu::new(raw).unwrap_or_else(|| panic!("{raw} should be inside +/-{MAX_ABS_DBU}"))
}

/// Oracle: closed form. The domain is stated in the doc comment as
/// `±MAX_ABS_DBU`, so the table is that statement: the endpoints are legal and
/// round-trip through `raw`, and one unit past either endpoint is `None`.
/// Rejecting is the whole job of the checked constructor, and a constructor
/// that clamped instead would pass a test that only looked at the accepted
/// half.
#[test]
fn the_coordinate_domain_is_closed_at_max_abs_dbu() {
    for raw in [
        0_i64,
        1,
        -1,
        4_096,
        -4_096,
        MAX_ABS_DBU - 1,
        MAX_ABS_DBU,
        -MAX_ABS_DBU,
    ] {
        assert_eq!(
            coord(raw).raw(),
            raw,
            "{raw} is inside the domain and must survive the round trip"
        );
    }

    for raw in [
        MAX_ABS_DBU + 1,
        -(MAX_ABS_DBU + 1),
        MAX_ABS_DBU * 2,
        i64::MAX,
        i64::MIN + 1,
        i64::MIN,
    ] {
        assert_eq!(
            Dbu::new(raw),
            None,
            "{raw} is outside +/-{MAX_ABS_DBU} and must be refused, not clamped"
        );
    }
}

/// Oracle: closed form. The doc comment justifies `MAX_ABS_DBU` by saying the
/// product of two coordinates is at most `2^80`. That is a number, so it is
/// asserted as a number: the four sign combinations of the corner case land on
/// `±2^80` exactly, in `i128`, with no wrap.
#[test]
fn the_widening_product_at_the_domain_corner_is_exactly_two_to_the_eighty() {
    let corner: i128 = 1 << 80;
    let max = coord(MAX_ABS_DBU);
    let min = coord(-MAX_ABS_DBU);

    assert_eq!(max.mul_wide(max).raw(), corner);
    assert_eq!(min.mul_wide(min).raw(), corner);
    assert_eq!(max.mul_wide(min).raw(), -corner);
    assert_eq!(min.mul_wide(max).raw(), -corner);
}

/// Oracle: law. The widening multiply is `i128` multiplication of the two
/// coordinates, for every pair in the domain — including the mixed-sign and
/// near-edge pairs a hand-written table would not think to include. The
/// comparison is against `i128::from(a) * i128::from(b)`, which is the
/// operation itself, not a reimplementation of it.
#[test]
fn the_widening_product_agrees_with_i128_multiplication_over_the_whole_domain() {
    let mut rng = Rng::new(41);
    for _ in 0..2_048 {
        let a = rng.range(-MAX_ABS_DBU, MAX_ABS_DBU + 1);
        let b = rng.range(-MAX_ABS_DBU, MAX_ABS_DBU + 1);
        assert_eq!(
            coord(a).mul_wide(coord(b)).raw(),
            i128::from(a) * i128::from(b),
            "seed 41: {a} * {b}"
        );
    }
}

/// Oracle: law. Multiplication commutes and negation distributes over it. Both
/// hold for every pair, and together they catch the argument transposition and
/// the dropped sign that the corner-case test above cannot see, because at the
/// corner both operands have the same magnitude.
#[test]
fn the_widening_product_commutes_and_composes_signs() {
    let mut rng = Rng::new(97);
    for _ in 0..1_024 {
        let a = coord(rng.range(-MAX_ABS_DBU, MAX_ABS_DBU + 1));
        let b = coord(rng.range(-MAX_ABS_DBU, MAX_ABS_DBU + 1));

        assert_eq!(a.mul_wide(b), b.mul_wide(a));
        assert_eq!((-a).mul_wide(b).raw(), -a.mul_wide(b).raw());
        assert_eq!((-a).mul_wide(-b), a.mul_wide(b));
    }
}

/// Oracle: law. Coordinates form a group under addition: subtracting what was
/// added restores the original, a value minus itself is zero, and double
/// negation is the identity. Holds for every pair, which is what makes it worth
/// more than three worked examples.
#[test]
fn coordinate_addition_and_subtraction_invert_each_other() {
    let zero = coord(0);
    let mut rng = Rng::new(13);
    for _ in 0..1_024 {
        // Half the domain each, so the sum stays inside `i64` with room to
        // spare, which is the unchecked-addition contract in the doc comment.
        let a = coord(rng.range(-MAX_ABS_DBU / 2, MAX_ABS_DBU / 2));
        let b = coord(rng.range(-MAX_ABS_DBU / 2, MAX_ABS_DBU / 2));

        assert_eq!((a + b) - b, a);
        assert_eq!((a - b) + b, a);
        assert_eq!(a + (-b), a - b);
        assert_eq!(a - a, zero);
        assert_eq!(-(-a), a);
        assert_eq!(a + zero, a);
    }
}

/// Oracle: law. Absolute value is idempotent, sign-blind, and never leaves the
/// domain — the last part is the claim the doc comment makes when it says the
/// operation cannot overflow, and the endpoints are where it would.
#[test]
fn absolute_value_is_the_magnitude_and_stays_inside_the_domain() {
    assert_eq!(coord(MAX_ABS_DBU).abs(), coord(MAX_ABS_DBU));
    assert_eq!(coord(-MAX_ABS_DBU).abs(), coord(MAX_ABS_DBU));
    assert_eq!(coord(0).abs(), coord(0));

    let mut rng = Rng::new(23);
    for _ in 0..1_024 {
        let raw = rng.range(-MAX_ABS_DBU, MAX_ABS_DBU + 1);
        let value = coord(raw);
        assert_eq!(value.abs().raw(), raw.abs());
        assert_eq!(value.abs(), (-value).abs());
        assert_eq!(value.abs().abs(), value.abs());
        assert!(value.abs().raw() <= MAX_ABS_DBU);
    }
}

/// Oracle: law. An area is a plain `i128` behind a newtype, so `new` and `raw`
/// are inverse and addition and subtraction cancel. Stated over the corner
/// values as well as arbitrary ones, because `±2^80` is the magnitude every
/// real area sum reaches.
#[test]
fn area_addition_and_subtraction_invert_each_other() {
    let corner: i128 = 1 << 80;
    for raw in [0_i128, 1, -1, corner, -corner] {
        assert_eq!(DbuArea::new(raw).raw(), raw);
    }

    // Drawn as full-domain products rather than as small numbers, so the
    // operands reach the `±2^80` the paragraph above is about. A `DbuArea`
    // that had quietly become an `i64` somewhere passes at layout scale and
    // wraps here.
    let mut rng = Rng::new(59);
    let draw = |rng: &mut Rng| {
        let lhs = i128::from(rng.range(-MAX_ABS_DBU, MAX_ABS_DBU + 1));
        let rhs = i128::from(rng.range(-MAX_ABS_DBU, MAX_ABS_DBU + 1));
        DbuArea::new(lhs * rhs)
    };
    for _ in 0..1_024 {
        let a = draw(&mut rng);
        let b = draw(&mut rng);

        assert_eq!((a + b) - b, a);
        assert_eq!((a - b) + b, a);
        assert_eq!(a + DbuArea::new(0), a);
        assert_eq!((a - a).raw(), 0);
    }
}

/// Oracle: law. The product of two coordinates and their sum-of-areas agree
/// with the distributive law, `a*(b+c) == a*b + a*c`, which ties `mul_wide` to
/// `DbuArea`'s addition. Neither operation can be wrong on its own and still
/// satisfy this over arbitrary inputs.
#[test]
fn the_widening_product_distributes_over_area_addition() {
    let mut rng = Rng::new(71);
    for _ in 0..1_024 {
        let a = coord(rng.range(-MAX_ABS_DBU, MAX_ABS_DBU + 1));
        let b = coord(rng.range(-MAX_ABS_DBU / 2, MAX_ABS_DBU / 2));
        let c = coord(rng.range(-MAX_ABS_DBU / 2, MAX_ABS_DBU / 2));

        assert_eq!(a.mul_wide(b + c), a.mul_wide(b) + a.mul_wide(c));
    }
}
