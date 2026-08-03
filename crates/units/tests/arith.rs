//! Cross-dimension arithmetic: Ohm's law, area, and current density.
//!
//! Two oracles. The closed form is the school arithmetic — 1.8 V across 3 ohms
//! is 0.6 A, and there is no room for opinion about it — and the law is that
//! the three Ohm's-law operators are three views of one triple, so they must
//! agree with each other on every triple, not just the round one.
//!
//! The second half of every test here is the prefix claim. Operands may carry
//! any prefix and results are canonical, so `mV / uA` and the same physical
//! quantities as `V / A` must produce the identical number of ohms. That
//! `10^(P-Q)` factor is applied at runtime and is the single most likely place
//! for a sign slip in the whole crate: an implementation that got its direction
//! backwards is off by a factor of a million here and correct everywhere both
//! operands share a prefix.

use gpurify_testgen::{assert_close_relative, Rng};
use gpurify_units::{prefix, Area, Current, CurrentDensity, Length, Qty, Resistance, Voltage};

/// Oracle: closed form. 1.8 V, 0.6 A and 3 ohms are one triple, and each
/// operator recovers the member it is missing. The type annotations are half
/// the test: they assert at compile time that a quotient of prefixed operands
/// comes back canonical, at `10^0`, which is what stops prefixes propagating
/// into every downstream signature.
#[test]
fn the_three_ohms_law_operators_agree_on_one_triple() {
    let volts = Qty::<Voltage, { prefix::BASE }>::new(1.8);
    let amps = Qty::<Current, { prefix::BASE }>::new(0.6);
    let ohms = Qty::<Resistance, { prefix::BASE }>::new(3.0);

    let resistance: Qty<Resistance, { prefix::BASE }> = volts / amps;
    let voltage: Qty<Voltage, { prefix::BASE }> = amps * ohms;
    let current: Qty<Current, { prefix::BASE }> = volts / ohms;

    assert_close_relative("V / I", resistance.raw(), 3.0, 1e-12);
    assert_close_relative("I * R", voltage.raw(), 1.8, 1e-12);
    assert_close_relative("V / R", current.raw(), 0.6, 1e-12);
}

/// Oracle: closed form. The same triple written with mixed prefixes: 1.8 V is
/// 1800 mV, 0.6 A is 600000 uA, 3 ohms is 0.003 kohm. Every operator must land
/// on the same canonical answer as the base-prefix form, which is the claim the
/// module's doc comment makes and the one a same-prefix test cannot reach.
#[test]
fn cross_prefix_operands_give_the_same_canonical_answer_as_base_prefix_ones() {
    let millivolts = Qty::<Voltage, { prefix::MILLI }>::new(1_800.0);
    let microamps = Qty::<Current, { prefix::MICRO }>::new(600_000.0);
    let kilohms = Qty::<Resistance, { prefix::KILO }>::new(0.003);
    let milliamps = Qty::<Current, { prefix::MILLI }>::new(600.0);
    let milliohms = Qty::<Resistance, { prefix::MILLI }>::new(3_000.0);

    assert_close_relative("mV / uA in ohms", (millivolts / microamps).raw(), 3.0, 1e-12);
    assert_close_relative("mV / mohm in amps", (millivolts / milliohms).raw(), 0.6, 1e-12);
    assert_close_relative("mA * kohm in volts", (milliamps * kilohms).raw(), 1.8, 1e-12);

    // The direction of the scale factor, stated where it is largest. A
    // conversion applied the wrong way round is out by 10^18 here.
    let gigavolts = Qty::<Voltage, { prefix::GIGA }>::new(1.8e-9);
    let nanoamps = Qty::<Current, { prefix::NANO }>::new(6e8);
    assert_close_relative("GV / nA in ohms", (gigavolts / nanoamps).raw(), 3.0, 1e-12);
}

/// Oracle: law. For any current and any resistance, the voltage they produce
/// divides back to both of them. This holds for every triple rather than the
/// one above, so it catches an operator that is right at unity and wrong
/// elsewhere — the shape a transposed division takes when the test values
/// happen to be reciprocals.
#[test]
fn ohms_law_closes_over_arbitrary_triples() {
    let mut rng = Rng::new(37);
    for _ in 0..512 {
        // Away from zero in both directions: a resistance of zero is a short
        // and a current of zero has no drop, and neither is a statement about
        // these operators.
        let amps = Qty::<Current, { prefix::BASE }>::new(rng.unit() * 2.0 + 0.01);
        let ohms = Qty::<Resistance, { prefix::BASE }>::new(rng.unit() * 1_000.0 + 0.1);

        let volts = amps * ohms;
        assert_close_relative("V / R recovers I", (volts / ohms).raw(), amps.raw(), 1e-12);
        assert_close_relative("V / I recovers R", (volts / amps).raw(), ohms.raw(), 1e-12);
    }
}

/// Oracle: law. Ohm's law is prefix-blind: the physical answer does not depend
/// on how the operands were written down. Restating both operands and comparing
/// the canonical results is the general form of the worked example above, over
/// arbitrary values.
#[test]
fn ohms_law_is_indifferent_to_the_prefix_its_operands_carry() {
    let mut rng = Rng::new(43);
    for _ in 0..512 {
        let volts = Qty::<Voltage, { prefix::BASE }>::new(rng.unit() * 3.0 + 0.1);
        let amps = Qty::<Current, { prefix::BASE }>::new(rng.unit() * 2.0 + 0.01);
        let expected = (volts / amps).raw();

        let restated = volts.to::<{ prefix::MILLI }>() / amps.to::<{ prefix::MICRO }>();
        assert_close_relative("mV / uA", restated.raw(), expected, 1e-12);

        let other_way = volts.to::<{ prefix::KILO }>() / amps.to::<{ prefix::MILLI }>();
        assert_close_relative("kV / mA", other_way.raw(), expected, 1e-12);
    }
}

/// Oracle: closed form. Two metres by three metres is six square metres, and
/// the cross-prefix form of the same rectangle — 2000 mm by 3000000 um — is the
/// same six. Area is where a prefix slip is largest, because the two factors
/// compound.
#[test]
fn a_length_times_a_length_is_an_area_in_base_units() {
    let two_metres = Qty::<Length, { prefix::BASE }>::new(2.0);
    let three_metres = Qty::<Length, { prefix::BASE }>::new(3.0);
    let area: Qty<Area, { prefix::BASE }> = two_metres * three_metres;
    assert_close_relative("2 m by 3 m", area.raw(), 6.0, 1e-12);

    let two_in_millimetres = Qty::<Length, { prefix::MILLI }>::new(2_000.0);
    let three_in_micrometres = Qty::<Length, { prefix::MICRO }>::new(3_000_000.0);
    assert_close_relative(
        "2000 mm by 3000000 um",
        (two_in_millimetres * three_in_micrometres).raw(),
        6.0,
        1e-12,
    );

    // A rectangle at layout scale, where both operands are small: 500 nm by
    // 200 nm is 1e-13 square metres.
    let width = Qty::<Length, { prefix::NANO }>::new(500.0);
    let height = Qty::<Length, { prefix::NANO }>::new(200.0);
    assert_close_relative("500 nm by 200 nm", (width * height).raw(), 1e-13, 1e-12);
}

/// Oracle: law. Area is symmetric in its factors and linear in each, which is
/// what "this is a product" means. Both hold for every pair, and together they
/// rule out an implementation that squares one operand or drops the other.
#[test]
fn area_is_symmetric_in_its_factors_and_linear_in_each() {
    let mut rng = Rng::new(61);
    for _ in 0..512 {
        let a = Qty::<Length, { prefix::MICRO }>::new(rng.unit() * 100.0 + 1.0);
        let b = Qty::<Length, { prefix::NANO }>::new(rng.unit() * 1_000.0 + 1.0);

        assert_close_relative("a * b against b * a", (a * b).raw(), (b * a).raw(), 1e-12);
        assert_close_relative(
            "doubling one side doubles the area",
            ((a * 2.0) * b).raw(),
            (a * b).raw() * 2.0,
            1e-12,
        );
    }
}

/// Oracle: closed form. Electromigration limits are stated as current per unit
/// conductor width, so 1.2 A through a 0.4 m conductor is 3 A/m. The layout
/// form of the same quantity — 1.2 mA through a 400 nm wire is 3000 A/m — is
/// the one a real deck carries, and it is where the compounding of a small
/// prefix and a large one shows up.
#[test]
fn a_current_over_a_length_is_a_current_density() {
    let amps = Qty::<Current, { prefix::BASE }>::new(1.2);
    let metres = Qty::<Length, { prefix::BASE }>::new(0.4);
    let density: Qty<CurrentDensity, { prefix::BASE }> = amps / metres;
    assert_close_relative("1.2 A over 0.4 m", density.raw(), 3.0, 1e-12);

    let milliamps = Qty::<Current, { prefix::MILLI }>::new(1.2);
    let nanometres = Qty::<Length, { prefix::NANO }>::new(400.0);
    assert_close_relative(
        "1.2 mA over 400 nm",
        (milliamps / nanometres).raw(),
        3_000.0,
        1e-12,
    );
}

/// Oracle: law. Current density is linear in the current and inverse in the
/// width, for every pair. A conductor twice as wide carries half the density at
/// the same current, which is the property an electromigration rule actually
/// leans on, and it fails against a division written the wrong way round even
/// where the worked example happens to come out right.
#[test]
fn current_density_scales_with_current_and_inversely_with_width() {
    let mut rng = Rng::new(79);
    for _ in 0..512 {
        let amps = Qty::<Current, { prefix::MILLI }>::new(rng.unit() * 10.0 + 0.1);
        let width = Qty::<Length, { prefix::NANO }>::new(rng.unit() * 900.0 + 100.0);
        let reference = (amps / width).raw();

        assert_close_relative(
            "twice the current, twice the density",
            ((amps * 2.0) / width).raw(),
            reference * 2.0,
            1e-12,
        );
        assert_close_relative(
            "twice the width, half the density",
            (amps / (width * 2.0)).raw(),
            reference / 2.0,
            1e-12,
        );
    }
}
