//! The single float-to-bytes site in this crate.
//!
//! Every writer routes an `f64` through `json::format_f64`, so a difference
//! here is a difference in every file a run produces. The properties below are
//! the ones a byte-comparison gate actually rests on: one value maps to one
//! string, that string reads back as a number, and the mapping does not reorder
//! two values or conflate two a report has to tell apart.
//!
//! # What is not asserted, and why
//!
//! The function's doc comment says floats are written "with a fixed precision"
//! without saying how many digits, so no test here names the expected text of a
//! value. What they pin instead is the *consequence*: six significant digits
//! survive, which is what a capacitance in femtofarads needs. See
//! `docs/NEED_TESTING.md`.

use gpurify::export::json::format_f64;
use gpurify_testgen::{assert_close, assert_close_relative};

fn formatted(value: f64) -> String {
    let mut out = String::new();
    format_f64(value, &mut out);
    out
}

/// Every value a writer in this crate can hand the formatter: the ordinary
/// scale of a resistance or a ratio, both signs of zero, the halfway values two
/// rounding conventions disagree about, and the magnitudes at either end of the
/// representable range.
const TABLE: &[f64] = &[
    0.0,
    -0.0,
    1.0,
    -1.0,
    0.5,
    1.5,
    2.5,
    0.125,
    12.5,
    2.675,
    98_765.432_1,
    -42.0,
    1e-30,
    1e30,
    f64::MIN_POSITIVE,
    f64::MAX,
    f64::MIN,
];

/// Oracle: determinism. This is the property the whole crate's gate reduces to
/// — if one `f64` could format two ways, no output in this workspace would be
/// comparable against yesterday's.
#[test]
fn every_value_formats_to_the_same_string_every_time() {
    for &value in TABLE {
        let first = formatted(value);
        assert!(
            !first.is_empty(),
            "{value} formatted to nothing, which no reader can parse"
        );
        assert_eq!(first, formatted(value), "{value} formatted two ways");
    }
}

/// Oracle: determinism. A formatter holding a thread-local scratch buffer, or
/// reaching for anything a thread owns, agrees with itself on one thread and
/// nowhere else — which is the failure mode the two-thread half of the gate
/// exists for.
#[test]
fn the_formatter_holds_no_per_thread_state() {
    let here: Vec<String> = TABLE.iter().map(|&v| formatted(v)).collect();
    let there = std::thread::spawn(|| TABLE.iter().map(|&v| formatted(v)).collect::<Vec<_>>())
        .join()
        .expect("the formatter panicked on another thread");
    assert_eq!(here, there);
}

/// Oracle: law. The output is a number in text, so it parses as one. A
/// formatter that emitted a locale decimal comma, an empty string for a
/// subnormal, or `inf` for a finite input fails here, and each of those makes a
/// report unreadable by the tool that consumes it.
#[test]
fn every_formatted_value_parses_back_as_a_finite_number() {
    for &value in TABLE {
        let text = formatted(value);
        let parsed: f64 = text.trim().parse().unwrap_or_else(|error| {
            panic!("{value} formatted to {text:?}, which is not a number: {error}")
        });
        assert!(
            parsed.is_finite(),
            "{value} formatted to {text:?}, which reads back as {parsed}"
        );
    }
}

/// Oracle: closed form. A parasitic capacitance is reported in femtofarads and
/// a resistance in ohms; six significant digits is the floor at which those
/// numbers still mean what the extractor computed. The tolerance is stated
/// rather than felt, and every value below is exactly representable at six
/// digits, so a formatter that meets the floor passes and one that rounds to
/// two decimal places does not.
#[test]
fn six_significant_digits_survive_the_round_trip() {
    for &value in &[1.0, 12.5, 0.125, 1_234.5, 98_765.432_1, -42.0] {
        let text = formatted(value);
        let parsed: f64 = text
            .trim()
            .parse()
            .unwrap_or_else(|error| panic!("{value} formatted to {text:?}: {error}"));
        assert_close_relative("format_f64 round trip", parsed, value, 1e-6);
    }
}

/// Oracle: law. Negative zero is a distinct bit pattern that compares equal to
/// positive zero, so it is exactly the kind of value a byte gate trips over.
/// What must hold is that it formats one way and reads back as zero; whether it
/// keeps its sign in the text is a choice the interface does not make, and a
/// test asserting one would be asserting a preference.
#[test]
fn negative_zero_formats_deterministically_and_reads_back_as_zero() {
    let text = formatted(-0.0);
    assert_eq!(text, formatted(-0.0), "negative zero formatted two ways");
    let parsed: f64 = text
        .trim()
        .parse()
        .unwrap_or_else(|error| panic!("negative zero formatted to {text:?}: {error}"));
    assert_close("negative zero", parsed, 0.0, 0.0);
}

/// Oracle: law. Formatting is a function of the bits, not of how they were
/// arrived at. `0.1 + 0.2` is bit-identical to the literal below, so a
/// formatter that consulted anything else — an accumulated error term, a
/// remembered previous call — separates them.
#[test]
fn one_bit_pattern_formats_one_way_however_it_was_computed() {
    let computed = 0.1_f64 + 0.2_f64;
    let literal = 0.300_000_000_000_000_04_f64;
    assert_eq!(
        computed.to_bits(),
        literal.to_bits(),
        "the premise of this test is that these two are the same f64"
    );
    assert_eq!(formatted(computed), formatted(literal));
}

/// Oracle: law. Formatting is monotone: it may lose precision but it may not
/// reorder. A report whose numbers sorted differently from the values behind
/// them would be worse than one with fewer digits.
#[test]
fn formatting_never_reorders_two_values() {
    let ascending = [
        -1e6, -42.0, -1.5, -1.0, -0.5, 0.0, 0.5, 1.0, 1.5, 2.5, 12.5, 1e6,
    ];
    for pair in ascending.windows(2) {
        let lower: f64 = formatted(pair[0]).trim().parse().expect("a number");
        let upper: f64 = formatted(pair[1]).trim().parse().expect("a number");
        assert!(
            lower <= upper,
            "{} and {} formatted to {lower} and {upper}, which are the wrong way round",
            pair[0],
            pair[1]
        );
    }
}

/// Oracle: law. Two values a report has to distinguish must not collapse into
/// one string. Both pairs differ in the second decimal place, so any precision
/// a parasitic report could reasonably use separates them — a formatter that
/// did not would merge two parasitics into one number.
#[test]
fn two_values_a_report_must_distinguish_do_not_format_alike() {
    assert_ne!(formatted(12.5), formatted(12.25));
    assert_ne!(formatted(1.0), formatted(-1.0));
    assert_ne!(formatted(0.75), formatted(0.5));
}
