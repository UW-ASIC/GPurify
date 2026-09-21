//! Physical quantities: prefix arithmetic, the Celsius boundary, and the
//! same-dimension operators.
//!
//! Dimension safety is a compile-time property here — adding volts to amps does
//! not typecheck, so there is nothing to run — and everything below is about
//! the numbers instead. Two oracles do all the work. Prefix scaling is a law:
//! restating a value at another prefix and back must return it, whatever the
//! value and whichever pair of prefixes, and the value in base units must not
//! depend on the prefix at all. The Celsius offset is a closed form, because
//! 273.15 is a constant and the three readings that matter are stated in the
//! function's own doc comment.

use gpurify_testgen::{assert_close, assert_close_relative, Rng};
use gpurify_geom::{celsius, prefix, Capacitance, Dimension, Length, Qty, Resistance, Voltage};

/// Restate at prefix `Q` and back at `P`.
///
/// Written once and instantiated at several prefix pairs, because the pair is a
/// compile-time parameter and a table cannot vary it.
fn assert_round_trips<D: Dimension, const P: i8, const Q: i8>(raw: f64) {
    let original = Qty::<D, P>::new(raw);
    let there_and_back = original.to::<Q>().to::<P>();
    assert_close_relative(
        &format!("{raw} restated at 10^{Q} and back at 10^{P}"),
        there_and_back.raw(),
        raw,
        1e-12,
    );
}

/// Render one quantity both ways and check it against its expected suffix.
///
/// The numeric head is parsed back rather than matched against a literal. The
/// doc comment's own examples disagree about trailing zeros — `3.0 aF` beside
/// `200 mohm`, which no single format string produces — so the value's spelling
/// is a choice the Implementation-Phase makes and this test has no standing to
/// pin. The prefix letter is a different matter: it is a function of the
/// exponent alone, and this impl is where the SI table is written down.
fn assert_renders_as<D: Dimension, const P: i8>(raw: f64, suffix: &str) {
    let quantity = Qty::<D, P>::new(raw);
    let shown = format!("{quantity}");
    let debugged = format!("{quantity:?}");
    assert_eq!(
        debugged, shown,
        "Debug is documented as the same text as Display"
    );

    let head = shown
        .strip_suffix(suffix)
        .unwrap_or_else(|| panic!("{shown:?} does not end in {suffix:?}"));
    let value: f64 = head
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("the head of {shown:?} is not a number: {e}"));
    assert_close(&format!("the value in {shown:?}"), value, raw, 1e-12);
}

/// Oracle: closed form. The SI prefix table is the oracle, and this impl is
/// where it is written down once, so each row is a letter anyone can look up:
/// `10^-18` is `a`, `10^-15` is `f`, `10^-3` is `m`, `10^0` is nothing at all,
/// `10^3` is `k`, `10^6` is `M`. The dimension contributes its base symbol
/// unprefixed, which is the part that goes wrong when a `Resistance` at
/// `10^-3` prints `mohm` as `ohm` and a report reads a thousand times low.
///
/// Micro is left out on purpose: `u` and the micro sign are both defensible and
/// the doc comment does not choose, so a test asserting either would be
/// inventing the specification rather than checking it.
#[test]
fn a_quantity_prints_its_value_followed_by_its_prefixed_symbol() {
    assert_renders_as::<Voltage, { prefix::BASE }>(1.8, "V");
    assert_renders_as::<Voltage, { prefix::MILLI }>(-250.0, "mV");
    assert_renders_as::<Voltage, { prefix::KILO }>(1.2, "kV");
    assert_renders_as::<Capacitance, { prefix::ATTO }>(3.0, "aF");
    assert_renders_as::<Capacitance, { prefix::FEMTO }>(-0.25, "fF");
    assert_renders_as::<Capacitance, { prefix::PICO }>(12.5, "pF");
    assert_renders_as::<Resistance, { prefix::MILLI }>(200.0, "mohm");
    assert_renders_as::<Resistance, { prefix::BASE }>(50.0, "ohm");
    assert_renders_as::<Resistance, { prefix::MEGA }>(1.0, "Mohm");
    assert_renders_as::<Length, { prefix::NANO }>(45.0, "nm");
    assert_renders_as::<Length, { prefix::GIGA }>(0.5, "Gm");
}

/// Oracle: closed form. `raw` is documented as the inverse of `new`, and a
/// wrapper that stores what it was handed has exactly one correct answer, so
/// this is asserted with no tolerance at all.
#[test]
#[allow(
    clippy::float_cmp,
    reason = "a newtype must return the bits it was handed, not a value near them"
)]
fn the_raw_count_is_exactly_what_was_wrapped() {
    for raw in [0.0_f64, 1.8, -3.5, 1e-18, 1e18, f64::MIN_POSITIVE] {
        assert_eq!(Qty::<Voltage, { prefix::BASE }>::new(raw).raw(), raw);
        assert_eq!(Qty::<Capacitance, { prefix::ATTO }>::new(raw).raw(), raw);
    }
}

/// Oracle: closed form. Restating at the prefix a quantity already carries
/// scales it by `10^0`, which is multiplication by one, so the result is the
/// original bit for bit. The test plan calls for exactness here specifically:
/// an implementation routing every conversion through `powi` and a division
/// would drift, and this is the one case where the drift has no excuse.
#[test]
#[allow(
    clippy::float_cmp,
    reason = "scaling by 10^0 is multiplication by one, which is exact for every finite f64"
)]
fn restating_at_the_same_prefix_is_exactly_the_identity() {
    for raw in [0.0_f64, 1.8, -3.5, 1e-18, 1e18, 123.456_789] {
        let base = Qty::<Voltage, { prefix::BASE }>::new(raw);
        assert_eq!(base.to::<{ prefix::BASE }>().raw(), raw);

        let atto = Qty::<Capacitance, { prefix::ATTO }>::new(raw);
        assert_eq!(atto.to::<{ prefix::ATTO }>().raw(), raw);

        let kilo = Qty::<Voltage, { prefix::KILO }>::new(raw);
        assert_eq!(kilo.to::<{ prefix::KILO }>().raw(), raw);
    }
}

/// Oracle: law. Restating a quantity at another prefix and back is the
/// identity, for every value and every pair of prefixes. The tolerance is
/// relative and stated: two `f64` multiplications by exact-ish powers of ten
/// lose at most a couple of units in the last place, so `1e-12` is many orders
/// of magnitude above the noise and still far below any scale error, which
/// would be a factor of ten.
#[test]
fn restating_a_prefix_and_restating_it_back_returns_the_original() {
    for raw in [1.8_f64, -3.5, 1e-6, 4.2e7, 6.022e23] {
        assert_round_trips::<Capacitance, { prefix::ATTO }, { prefix::FEMTO }>(raw);
        assert_round_trips::<Capacitance, { prefix::ATTO }, { prefix::BASE }>(raw);
        assert_round_trips::<Capacitance, { prefix::FEMTO }, { prefix::PICO }>(raw);
        assert_round_trips::<Voltage, { prefix::BASE }, { prefix::MICRO }>(raw);
        assert_round_trips::<Voltage, { prefix::MILLI }, { prefix::KILO }>(raw);
        assert_round_trips::<Voltage, { prefix::GIGA }, { prefix::NANO }>(raw);
        assert_round_trips::<Voltage, { prefix::PICO }, { prefix::MEGA }>(raw);
    }
}

/// Oracle: closed form, then law. `3 aF` is `3e-18 F` — the worked example in
/// the doc comment — and after that the law does the harder half: the value in
/// base units is what a quantity *is*, so restating its prefix cannot change
/// it. A `to` that scaled the wrong way passes the round-trip law above,
/// because two opposite errors cancel, and fails here.
#[test]
fn the_value_in_base_units_does_not_depend_on_the_prefix() {
    assert_close_relative(
        "3 aF in farads",
        Qty::<Capacitance, { prefix::ATTO }>::new(3.0).base(),
        3e-18,
        1e-15,
    );
    // `FEMTO` and `PICO` appear below only in the restatement loop, which
    // compares a quantity against itself and so cancels a sign error in the
    // constant the same way the round-trip law does. Stated absolutely here,
    // they are pinned: mutation testing found both surviving a deleted minus.
    assert_close_relative(
        "12.5 fF in farads",
        Qty::<Capacitance, { prefix::FEMTO }>::new(12.5).base(),
        12.5e-15,
        1e-15,
    );
    assert_close_relative(
        "12.5 pF in farads",
        Qty::<Capacitance, { prefix::PICO }>::new(12.5).base(),
        12.5e-12,
        1e-15,
    );
    assert_close_relative(
        "1.8 V in volts",
        Qty::<Voltage, { prefix::BASE }>::new(1.8).base(),
        1.8,
        1e-15,
    );
    assert_close_relative(
        "200 mV in volts",
        Qty::<Voltage, { prefix::MILLI }>::new(200.0).base(),
        0.2,
        1e-15,
    );

    let farads = Qty::<Capacitance, { prefix::FEMTO }>::new(12.5);
    for restated in [
        farads.to::<{ prefix::ATTO }>().base(),
        farads.to::<{ prefix::PICO }>().base(),
        farads.to::<{ prefix::BASE }>().base(),
        farads.to::<{ prefix::MEGA }>().base(),
    ] {
        assert_close_relative("12.5 fF restated", restated, farads.base(), 1e-12);
    }
}

/// Oracle: closed form. The offset is 273.15 and the three readings the doc
/// comment names are stated outright: absolute zero at 0 K, the freezing point
/// at 273.15 K, and a negative reading that must come back positive. The last
/// is why the function exists — `Temperature` is kelvin always because an
/// Arrhenius factor needs `1/T`, and a Celsius value let through unconverted
/// divides by zero at freezing and changes sign below it.
#[test]
fn celsius_puts_absolute_zero_at_zero_kelvin() {
    // (degrees Celsius, kelvin)
    const READINGS: &[(f64, f64)] = &[
        (-273.15, 0.0),
        (0.0, 273.15),
        (25.0, 298.15),
        (100.0, 373.15),
        (-40.0, 233.15),
        (-273.0, 0.15),
        (125.0, 398.15),
    ];
    for &(degrees, kelvin) in READINGS {
        assert_close(
            &format!("{degrees} C in kelvin"),
            celsius(degrees).raw(),
            kelvin,
            1e-9,
        );
    }
}

/// Oracle: law. Every reading at or above absolute zero is a positive kelvin
/// with a finite, positive reciprocal. That reciprocal is the thing an
/// Arrhenius factor computes, so this is the failure the conversion exists to
/// prevent, stated directly: at 0 C an unconverted reading divides by zero, and
/// below it the exponent changes sign and the model runs backwards.
#[test]
fn a_negative_celsius_reading_is_a_positive_kelvin_with_a_finite_reciprocal() {
    for degrees in [-273.0, -272.0, -40.0, -10.0, -0.001, 0.0, 25.0, 125.0] {
        let kelvin = celsius(degrees).raw();
        assert!(
            kelvin > 0.0,
            "{degrees} C came back as {kelvin} K, which 1/T cannot use"
        );
        let arrhenius = 1.0 / kelvin;
        assert!(
            arrhenius.is_finite() && arrhenius > 0.0,
            "1/{kelvin} K is {arrhenius}, so the Arrhenius factor is unusable"
        );
    }
}

/// Oracle: law. An offset conversion has unit slope, so a difference of two
/// readings survives it unchanged, for every pair. This is what separates the
/// intended `T + 273.15` from a scaling mistake such as `T * 273.15`, which
/// satisfies neither this nor absolute zero but would satisfy a test written
/// against only one reading.
#[test]
fn celsius_preserves_differences() {
    let mut rng = Rng::new(53);
    for _ in 0..512 {
        let a = rng.unit() * 400.0 - 273.15;
        let b = rng.unit() * 400.0 - 273.15;
        assert_close(
            "a temperature difference",
            celsius(b).raw() - celsius(a).raw(),
            b - a,
            1e-9,
        );
    }
}

/// Oracle: law. Quantities of one dimension and prefix form a group under
/// addition: subtracting what was added restores the original, a value minus
/// itself is zero, and double negation is the identity. The tolerance is
/// absolute because the values straddle zero, where a relative tolerance means
/// nothing, and the draws are bounded by ten so `1e-12` is far above `f64`
/// rounding at that scale.
#[test]
fn adding_a_quantity_and_subtracting_it_restores_the_original() {
    let zero = Qty::<Voltage, { prefix::MILLI }>::new(0.0);
    let mut rng = Rng::new(67);
    for _ in 0..512 {
        let a = Qty::<Voltage, { prefix::MILLI }>::new(rng.unit() * 20.0 - 10.0);
        let b = Qty::<Voltage, { prefix::MILLI }>::new(rng.unit() * 20.0 - 10.0);

        assert_close("(a + b) - b", ((a + b) - b).raw(), a.raw(), 1e-12);
        assert_close("(a - b) + b", ((a - b) + b).raw(), a.raw(), 1e-12);
        assert_close("a + (-b)", (a + (-b)).raw(), (a - b).raw(), 1e-12);
        assert_close("a + (-a)", (a + (-a)).raw(), 0.0, 1e-12);
        assert_close("-(-a)", (-(-a)).raw(), a.raw(), 1e-12);
        assert_close("a + 0", (a + zero).raw(), a.raw(), 1e-12);
    }
}

/// Oracle: law. Scaling by a dimensionless factor and dividing the same factor
/// out is the identity, and scaling by one is exact. The factors are drawn away
/// from zero because dividing by a factor near zero is a numerical question,
/// not a question about this operator.
#[test]
#[allow(
    clippy::float_cmp,
    reason = "multiplication and division by one are exact for every finite f64"
)]
fn scaling_by_a_factor_and_dividing_it_out_restores_the_original() {
    let one = Qty::<Voltage, { prefix::BASE }>::new(1.8);
    assert_eq!((one * 1.0).raw(), one.raw());
    assert_eq!((one / 1.0).raw(), one.raw());

    let mut rng = Rng::new(89);
    for _ in 0..512 {
        let value = Qty::<Voltage, { prefix::BASE }>::new(rng.unit() * 20.0 - 10.0);
        let factor = rng.unit() * 8.0 + 0.5;

        assert_close(
            "(v * k) / k",
            ((value * factor) / factor).raw(),
            value.raw(),
            1e-12,
        );
        assert_close(
            "(v / k) * k",
            ((value / factor) * factor).raw(),
            value.raw(),
            1e-12,
        );
        assert_close(
            "v * 2 - v",
            ((value * 2.0) - value).raw(),
            value.raw(),
            1e-12,
        );
    }
}

/// Oracle: closed form, then law. Dividing two quantities of one dimension is
/// dimensionless — this is what an antenna ratio is, which is why antenna
/// limits are bare `f64` — so `3 aF / 1.5 aF` is 2, exactly, both operands
/// being exact in binary. The law then says the ratio is prefix-free: restating
/// both operands cannot move it, because the prefix cancels.
#[test]
fn the_ratio_of_two_quantities_of_one_dimension_is_their_bare_ratio() {
    let numerator = Qty::<Capacitance, { prefix::ATTO }>::new(3.0);
    let denominator = Qty::<Capacitance, { prefix::ATTO }>::new(1.5);
    let ratio: f64 = numerator / denominator;
    assert_close("3 aF over 1.5 aF", ratio, 2.0, 1e-15);

    for restated in [
        numerator.to::<{ prefix::FEMTO }>() / denominator.to::<{ prefix::FEMTO }>(),
        numerator.to::<{ prefix::BASE }>() / denominator.to::<{ prefix::BASE }>(),
        numerator.to::<{ prefix::MEGA }>() / denominator.to::<{ prefix::MEGA }>(),
    ] {
        assert_close_relative("the same ratio at another prefix", restated, ratio, 1e-12);
    }

    let mut rng = Rng::new(101);
    for _ in 0..512 {
        let a = Qty::<Capacitance, { prefix::FEMTO }>::new(rng.unit() * 9.0 + 1.0);
        let b = Qty::<Capacitance, { prefix::FEMTO }>::new(rng.unit() * 9.0 + 1.0);
        assert_close_relative("a / b", a / b, a.raw() / b.raw(), 1e-12);
        assert_close_relative("(a / b) * (b / a)", (a / b) * (b / a), 1.0, 1e-12);
    }
}

/// Oracle: law. `is_finite` separates the values a report may carry from the
/// three that must never reach one. The `NaN` case is the whole point: it
/// compares false against every limit, so a rule handed one passes silently,
/// which is the fail-open mode this project treats as a defect. A predicate
/// that returned `true` unconditionally would satisfy a test that only checked
/// the ordinary values.
#[test]
fn only_finite_values_are_finite() {
    for raw in [
        0.0_f64,
        -0.0,
        1.8,
        -1e30,
        f64::MIN_POSITIVE,
        f64::MAX,
        f64::MIN,
    ] {
        assert!(
            Qty::<Voltage, { prefix::BASE }>::new(raw).is_finite(),
            "{raw} V is a finite measurement"
        );
    }
    for raw in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert!(
            !Qty::<Capacitance, { prefix::ATTO }>::new(raw).is_finite(),
            "{raw} aF must not pass as a finite measurement"
        );
    }
}
