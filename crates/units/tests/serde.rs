//! The wire form of a quantity.
//!
//! `Qty`'s two `serde` impls make one claim: a quantity is a bare number, and
//! its dimension and prefix are schema rather than data. That is checkable
//! three ways without inventing a specification. The bare-number half is
//! structural — the serialised value is a JSON number, not an object, and two
//! quantities of different dimension and different prefix holding the same
//! count produce the same text, which is what "the prefix is not data" means.
//! The count half is a law: writing and reading back is the identity. And the
//! reading half is construct-from-answer: the text `3` at `10^-18` is three
//! attofarads, not three farads, because `raw` is a count of `10^P` base units.
//!
//! `serde_json` is the format here only because a format is needed at all;
//! nothing below asserts anything about JSON's spelling of a number beyond it
//! being one.

use gpurify_testgen::{assert_bytes_identical, Rng};
use gpurify_units::{prefix, Capacitance, Length, Qty, Resistance, Voltage};

/// Oracle: closed form. The doc comment says the dimension and prefix are
/// schema, so the only thing on the wire is the count. Stated two ways: the
/// serialised value is a JSON number rather than a struct — an impl that
/// derived `Serialize` would emit an object here — and four quantities that
/// disagree about both dimension and prefix, but agree about the count,
/// serialise to identical text.
#[test]
fn a_quantity_serialises_as_a_bare_number_carrying_neither_dimension_nor_prefix() {
    let value =
        serde_json::to_value(Qty::<Capacitance, { prefix::ATTO }>::new(3.0)).expect("3 aF");
    assert!(
        value.is_number(),
        "a quantity is a bare number on the wire, not {value}"
    );
    assert_eq!(value.as_f64(), Some(3.0), "the number is the count of 10^P");

    let same_count = [
        serde_json::to_string(&Qty::<Capacitance, { prefix::ATTO }>::new(-2.5)).expect("aF"),
        serde_json::to_string(&Qty::<Voltage, { prefix::BASE }>::new(-2.5)).expect("V"),
        serde_json::to_string(&Qty::<Resistance, { prefix::MEGA }>::new(-2.5)).expect("Mohm"),
        serde_json::to_string(&Qty::<Length, { prefix::NANO }>::new(-2.5)).expect("nm"),
    ];
    for text in &same_count {
        assert_eq!(
            *text, same_count[0],
            "the dimension and prefix are schema, so they cost no bytes per row"
        );
    }
}

/// Oracle: construct-from-answer. `raw` is a count of `10^P` base units, so the
/// bare number `3` read as a `Qty<Capacitance, -18>` is three attofarads —
/// count `3.0` and base value `3e-18`. An impl that treated the wire number as
/// a value in base units would come back as `3 F` written at the attofarad
/// prefix, and the two differ by `10^18`.
#[test]
#[allow(
    clippy::float_cmp,
    reason = "a bare f64 written by ryu and read back is the same f64, exactly"
)]
fn a_bare_number_reads_back_as_that_count_at_the_declared_prefix() {
    let attofarads: Qty<Capacitance, { prefix::ATTO }> =
        serde_json::from_str("3.0").expect("3.0 is a number");
    assert_eq!(attofarads.raw(), 3.0);
    assert_eq!(attofarads, Qty::<Capacitance, { prefix::ATTO }>::new(3.0));

    // An integer literal is the same number, and a report column of whole
    // millivolts is written without a fractional part by every JSON writer.
    let millivolts: Qty<Voltage, { prefix::MILLI }> =
        serde_json::from_str("1800").expect("1800 is a number");
    assert_eq!(millivolts.raw(), 1800.0);

    // Fail closed: a quantity is a number, and text that is not one is a typed
    // error rather than a default.
    assert!(
        serde_json::from_str::<Qty<Voltage, { prefix::BASE }>>("\"1.8\"").is_err(),
        "a quoted string is not a measurement"
    );
    assert!(
        serde_json::from_str::<Qty<Voltage, { prefix::BASE }>>("{\"raw\":1.8}").is_err(),
        "the derived struct form is not this type's wire form"
    );
}

/// Oracle: law. Writing and reading back is the identity on the value, for
/// every count and every dimension-prefix pair, which is the property a report
/// round trip depends on. Asserted with no tolerance: `f64` has a shortest
/// round-trip decimal form and both directions are exact, so anything less than
/// bit equality is a defect rather than rounding.
#[test]
#[allow(
    clippy::float_cmp,
    reason = "the decimal round trip of a finite f64 is exact; drift here is a bug"
)]
fn writing_a_quantity_and_reading_it_back_returns_the_same_count() {
    fn round_trip<D: gpurify_units::Dimension, const P: i8>(raw: f64) {
        let original = Qty::<D, P>::new(raw);
        let text = serde_json::to_string(&original).expect("a finite quantity");
        let parsed: Qty<D, P> = serde_json::from_str(&text).expect("what we just wrote");
        assert_eq!(parsed.raw(), raw, "{text} did not read back as {raw}");
    }

    for raw in [0.0_f64, -0.0, 1.8, -3.5, 1e-18, 1e18, 123.456_789, f64::MIN_POSITIVE] {
        round_trip::<Capacitance, { prefix::ATTO }>(raw);
        round_trip::<Voltage, { prefix::BASE }>(raw);
        round_trip::<Resistance, { prefix::MILLI }>(raw);
        round_trip::<Length, { prefix::GIGA }>(raw);
    }

    let mut rng = Rng::new(107);
    for _ in 0..512 {
        round_trip::<Voltage, { prefix::MILLI }>(rng.unit() * 2_000.0 - 1_000.0);
        round_trip::<Capacitance, { prefix::FEMTO }>(rng.unit() * 100.0);
    }
}

/// Oracle: determinism. Serialising is the crate's one path to bytes, so it is
/// subject to the determinism gate: a column of measurements written twice must
/// be byte-identical, because a report that differs between two runs of the same
/// binary is the defect that gate exists to catch.
#[test]
fn serialising_a_column_of_measurements_is_byte_identical_across_two_runs() {
    let mut rng = Rng::new(109);
    let column: Vec<Qty<Capacitance, { prefix::ATTO }>> = (0..1_024)
        .map(|_| Qty::new(rng.unit() * 200.0 - 100.0))
        .collect();

    let first = serde_json::to_vec(&column).expect("finite capacitances");
    let second = serde_json::to_vec(&column).expect("finite capacitances");
    assert_bytes_identical("a column of attofarads", &first, &second);
}
