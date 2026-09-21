//! Which side of a limit is a violation, and what stops a `NaN` passing every
//! rule.
//!
//! The oracle is **closed form**: a comparison against a limit has an analytic
//! answer for every dimension, so the tests are a table of below, equal and
//! above against both senses, stated once and walked over every variant. There
//! is nothing to construct and no geometry to generate.
//!
//! The equality row is the one that matters most. `Minimum` with `<` where
//! `<=` was meant flags every shape drawn exactly at its limit, which is most
//! of a real layout, and a suite built from strictly-below and strictly-above
//! cases never notices.

use gpurify_check::report::{LimitSense, Measurement};
use gpurify_testgen::dbu;
use gpurify_testgen::shapes::area;
use gpurify_geom::Qty;

/// One dimension's worth of ordered values: below the limit, at it, above it.
///
/// Every variant of [`Measurement`] appears exactly once. A new variant that
/// forgets to add a row here is invisible, which is the one gap this shape has
/// — the enum's own doc comment says the compiler catches it in the
/// formatters, and it does not catch it in a test.
fn ordered_triples() -> Vec<(&'static str, Measurement, Measurement, Measurement)> {
    vec![
        (
            "a spacing",
            Measurement::Length(dbu(90)),
            Measurement::Length(dbu(100)),
            Measurement::Length(dbu(110)),
        ),
        (
            "a minimum area",
            Measurement::Area(area(9_000)),
            Measurement::Area(area(10_000)),
            Measurement::Area(area(11_000)),
        ),
        (
            "an antenna ratio",
            Measurement::Ratio(49.5),
            Measurement::Ratio(50.0),
            Measurement::Ratio(50.5),
        ),
        (
            "a via count",
            Measurement::Count(1),
            Measurement::Count(2),
            Measurement::Count(3),
        ),
        (
            "a supply voltage",
            Measurement::Voltage(Qty::new(1_700.0)),
            Measurement::Voltage(Qty::new(1_800.0)),
            Measurement::Voltage(Qty::new(1_900.0)),
        ),
        (
            "a branch current",
            Measurement::Current(Qty::new(90.0)),
            Measurement::Current(Qty::new(100.0)),
            Measurement::Current(Qty::new(110.0)),
        ),
        (
            "a point-to-point resistance",
            Measurement::Resistance(Qty::new(9.0)),
            Measurement::Resistance(Qty::new(10.0)),
            Measurement::Resistance(Qty::new(11.0)),
        ),
    ]
}

/// Oracle: closed form. `Minimum` is violated below its limit and by nothing
/// else; `Maximum` above it and by nothing else. Both senses are checked
/// against all three positions for every dimension, so a comparison written the
/// right way round for lengths and the wrong way round for resistances — the
/// defect `LimitSense` exists to prevent — fails here rather than in a signoff
/// run.
#[test]
fn minimum_is_violated_below_its_limit_and_maximum_above_it() {
    for (what, below, at, above) in ordered_triples() {
        assert!(
            below.violates(at, LimitSense::Minimum),
            "{what}: a value below a Minimum limit is a violation"
        );
        assert!(
            !above.violates(at, LimitSense::Minimum),
            "{what}: a value above a Minimum limit is not a violation"
        );
        assert!(
            above.violates(at, LimitSense::Maximum),
            "{what}: a value above a Maximum limit is a violation"
        );
        assert!(
            !below.violates(at, LimitSense::Maximum),
            "{what}: a value below a Maximum limit is not a violation"
        );
    }
}

/// Oracle: closed form. A shape drawn exactly at its limit is legal under both
/// senses — that is what "minimum" and "maximum" mean — and it is the boundary
/// an off-by-one comparison lands on. Stated separately from the table above
/// because it is the row that fails alone.
#[test]
fn a_measurement_exactly_at_its_limit_violates_neither_sense() {
    for (what, _, at, _) in ordered_triples() {
        assert!(
            !at.violates(at, LimitSense::Minimum),
            "{what}: a value at its Minimum limit was reported as a violation"
        );
        assert!(
            !at.violates(at, LimitSense::Maximum),
            "{what}: a value at its Maximum limit was reported as a violation"
        );
    }
}

/// Oracle: law. `violates` is antisymmetric across the two senses on unequal
/// values: whichever way round two distinct measurements sit, exactly one of
/// the two senses calls it a violation. That holds for any pair and any
/// dimension, so it catches a sense that answers the same way to both.
#[test]
fn exactly_one_sense_fires_on_any_two_unequal_measurements() {
    for (what, below, _, above) in ordered_triples() {
        for (low, high) in [(below, above), (above, below)] {
            let minimum = low.violates(high, LimitSense::Minimum);
            let maximum = low.violates(high, LimitSense::Maximum);
            assert!(
                minimum != maximum,
                "{what}: both senses answered {minimum} for two unequal values"
            );
        }
    }
}

/// Oracle: law. `NaN` compares false against everything, so a `NaN` limit
/// reports no violation for any measurement under either sense and a rule
/// carrying one is silently clean forever. `is_finite` is the guard that stops
/// such a value entering a report, so it has to reject every non-finite `f64`
/// in every variant that can hold one, infinities included: an infinite
/// `Maximum` limit passes everything just as quietly.
///
/// The exact variants are the other half. `Length`, `Area` and `Count` are
/// integers and cannot be non-finite, so `is_finite` must accept every one of
/// them rather than being a blanket refusal.
#[test]
fn is_finite_rejects_every_non_finite_value_and_accepts_every_exact_one() {
    let rejected = [
        Measurement::Ratio(f64::NAN),
        Measurement::Ratio(f64::INFINITY),
        Measurement::Ratio(f64::NEG_INFINITY),
        Measurement::Voltage(Qty::new(f64::NAN)),
        Measurement::Voltage(Qty::new(f64::INFINITY)),
        Measurement::Current(Qty::new(f64::NAN)),
        Measurement::Current(Qty::new(f64::NEG_INFINITY)),
        Measurement::Resistance(Qty::new(f64::NAN)),
        Measurement::Resistance(Qty::new(f64::INFINITY)),
    ];
    for (index, value) in rejected.into_iter().enumerate() {
        assert!(
            !value.is_finite(),
            "rejected[{index}] is not finite and was accepted, which is how a \
             rule passes without checking anything"
        );
    }

    let accepted = [
        Measurement::Length(dbu(0)),
        Measurement::Length(dbu(-1)),
        Measurement::Area(area(0)),
        Measurement::Area(area(i128::from(u64::MAX))),
        Measurement::Count(0),
        Measurement::Count(u32::MAX),
        Measurement::Ratio(0.0),
        Measurement::Ratio(f64::MAX),
        Measurement::Voltage(Qty::new(-1_800.0)),
        Measurement::Current(Qty::new(0.0)),
        Measurement::Resistance(Qty::new(1e12)),
    ];
    for (index, value) in accepted.into_iter().enumerate() {
        assert!(
            value.is_finite(),
            "accepted[{index}] is a representable measurement and was rejected"
        );
    }
}

/// Oracle: construct-from-answer, against the documented behaviour. `violates`
/// says mismatched dimensions "are asserted, not silently answered", so
/// comparing a length against a count must panic rather than return a bool
/// nobody can interpret.
///
/// In the Testing-Phase this passes for the wrong reason: the body is `todo!()`
/// and every call panics. It is written for the Implementation-Phase, where the
/// only way to keep it green is the assert the doc promises.
#[test]
fn comparing_two_dimensions_is_a_programming_error_rather_than_an_answer() {
    let length = Measurement::Length(dbu(200));
    let count = Measurement::Count(200);
    let ratio = Measurement::Ratio(200.0);
    for (left, right) in [(length, count), (count, ratio), (ratio, length)] {
        let answered = std::panic::catch_unwind(move || left.violates(right, LimitSense::Minimum));
        assert!(
            answered.is_err(),
            "{left:?} against {right:?} answered instead of asserting"
        );
    }
}

/// Oracle: law. Two measurements are equal exactly when they carry the same
/// dimension and the same value, which is what makes a violation row
/// assertable: `assert_only_violation` compares the measurement column, and a
/// `PartialEq` that ignored the variant would let a resistance match a length.
#[test]
fn measurements_of_different_dimensions_are_never_equal() {
    assert_ne!(Measurement::Length(dbu(200)), Measurement::Count(200));
    assert_ne!(Measurement::Ratio(200.0), Measurement::Count(200));
    assert_ne!(Measurement::Length(dbu(200)), Measurement::Length(dbu(201)));
    assert_eq!(Measurement::Length(dbu(200)), Measurement::Length(dbu(200)));
    assert_eq!(Measurement::Count(7), Measurement::Count(7));
    // A `NaN` is not equal to itself, so a row carrying one cannot be asserted
    // on at all. That is a second reason `is_finite` guards the push.
    assert_ne!(Measurement::Ratio(f64::NAN), Measurement::Ratio(f64::NAN));
}
