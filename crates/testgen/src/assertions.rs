//! Assertions over violation tables, rule runs and float comparisons.
//!
//! Each one panics with a message naming what differed, so a failing test
//! reads as a diagnosis. Violation rows compare by exact equality in every
//! field, floating-point measurements included; build the expected row with
//! [`crate::violation`] so its values are the exact ones.

use gpurify_check::report::{Outcome, RuleRun, Violation, Violations};
use gpurify_check::topology::{NetId, NetTable, PortTable};
use gpurify_geom::PolyId;
use gpurify_ingest::StrId;

/// The net partition as comparable data: each net's polygons, by `NetId`,
/// in the order the table holds them. Compare it with a generator's
/// `expected_net_polys`.
#[must_use]
pub fn net_partition(nets: &NetTable) -> Vec<Vec<PolyId>> {
    (0..nets.net_count())
        .map(|n| {
            nets.polys_of(NetId(u32::try_from(n).expect("a NetId is u32")))
                .to_vec()
        })
        .collect()
}

/// The port bindings as comparable data: each net's name, by `NetId`.
#[must_use]
pub fn port_names(ports: &PortTable, nets: &NetTable) -> Vec<Option<StrId>> {
    (0..nets.net_count())
        .map(|n| ports.name_of(NetId(u32::try_from(n).expect("a NetId is u32"))))
        .collect()
}

/// Asserts two `f64` agree to an absolute tolerance, inclusive.
///
/// # Panics
///
/// Panics if either value is not finite, or they differ by more than
/// `tolerance`; the message names `what`, both values and the error.
pub fn assert_close(what: &str, actual: f64, expected: f64, tolerance: f64) {
    assert!(
        actual.is_finite() && expected.is_finite(),
        "{what}: {actual} and {expected} must both be finite"
    );
    let error = (actual - expected).abs();
    assert!(
        error <= tolerance,
        "{what}: {actual} is not within {tolerance} of {expected} (off by {error})"
    );
}

/// Asserts two `f64` agree to a tolerance relative to the expected magnitude:
/// `|actual - expected| / |expected| <= tolerance`.
///
/// # Panics
///
/// Panics if either value is not finite, if `expected` is zero (use
/// [`assert_close`]), or if the relative error exceeds `tolerance`.
pub fn assert_close_relative(what: &str, actual: f64, expected: f64, tolerance: f64) {
    assert!(
        actual.is_finite() && expected.is_finite(),
        "{what}: {actual} and {expected} must both be finite"
    );
    assert!(
        expected != 0.0,
        "{what}: a relative tolerance around zero admits every value; use assert_close"
    );
    let error = ((actual - expected) / expected).abs();
    assert!(
        error <= tolerance,
        "{what}: {actual} differs from {expected} by {error} relative, over the \
         stated tolerance of {tolerance}"
    );
}

/// Asserts a rule ran and looked at something, returning its record.
///
/// # Panics
///
/// Panics unless exactly one [`RuleRun`] names `rule`, its outcome is
/// [`Outcome::Ran`], and it examined at least one shape: a rule that ran on
/// nothing exercised none of its logic.
#[must_use]
pub fn assert_rule_ran(runs: &[RuleRun], rule: StrId) -> RuleRun {
    let matching: Vec<&RuleRun> = runs.iter().filter(|r| r.rule == rule).collect();
    assert!(
        !matching.is_empty(),
        "no RuleRun for rule {rule:?}; the run recorded {:?}",
        runs.iter().map(|r| r.rule).collect::<Vec<_>>()
    );
    assert!(
        matching.len() == 1,
        "rule {rule:?} has {} RuleRun rows; a run row must be attributable to one rule",
        matching.len()
    );
    let run = *matching[0];
    assert!(
        run.outcome == Outcome::Ran,
        "rule {rule:?} did not run: {:?}",
        run.outcome
    );
    assert!(
        run.examined > 0,
        "rule {rule:?} ran but examined nothing, so nothing about its logic was exercised"
    );
    run
}

/// Asserts a rule ran, examined shapes, and found nothing.
///
/// # Panics
///
/// Panics as [`assert_rule_ran`] does, or if its record counts violations,
/// or if any row of `violations` names `rule`; the message lists those rows.
pub fn assert_clean(runs: &[RuleRun], violations: &Violations, rule: StrId) {
    let run = assert_rule_ran(runs, rule);
    assert!(
        run.violations == 0,
        "rule {rule:?} reports {} violations in its RuleRun",
        run.violations
    );
    let found: Vec<usize> = violations
        .rule
        .iter()
        .enumerate()
        .filter(|(_, &r)| r == rule)
        .map(|(i, _)| i)
        .collect();
    assert!(
        found.is_empty(),
        "rule {rule:?} was expected clean but rows {found:?} name it:\n{}",
        describe(violations, found.iter().copied())
    );
}

/// Asserts a violation table holds exactly one row, and that it is this one.
///
/// # Panics
///
/// Panics listing the table if it does not hold exactly one row, or naming
/// the first field (rule, layer, severity, `at`, measured, limit, shapes)
/// that differs from `expected`.
pub fn assert_only_violation(violations: &Violations, expected: &Violation) {
    assert!(
        violations.len() == 1,
        "expected exactly one violation, found {}:\n{}",
        violations.len(),
        describe(violations, 0..violations.len())
    );
    assert_violation_row(violations, 0, expected);
}

/// Asserts a table contains this violation, and returns the first row that
/// matches it in every field.
///
/// # Panics
///
/// Panics listing the whole table when no row matches.
#[must_use]
pub fn assert_has_violation(violations: &Violations, expected: &Violation) -> usize {
    let found = (0..violations.len()).find(|&i| violations.get(i) == *expected);
    match found {
        Some(index) => index,
        None => panic!(
            "no row matches {expected:?}; the table holds:\n{}",
            describe(violations, 0..violations.len())
        ),
    }
}

/// Asserts two violation tables are equal row for row, in order.
///
/// # Panics
///
/// Panics listing both tables if their lengths differ, or naming the first
/// row and field that differ.
pub fn assert_violations_eq(actual: &Violations, expected: &Violations) {
    assert!(
        actual.len() == expected.len(),
        "violation tables differ in length: {} against {}\nactual:\n{}\nexpected:\n{}",
        actual.len(),
        expected.len(),
        describe(actual, 0..actual.len()),
        describe(expected, 0..expected.len())
    );
    for index in 0..actual.len() {
        assert_violation_row(actual, index, &expected.get(index));
    }
}

/// Asserts a run produced byte-identical output twice.
///
/// # Panics
///
/// Panics if the bytes differ, naming `what`, both lengths, the offset of the
/// first difference, and up to 24 bytes either side of it from each, decoded
/// lossily as UTF-8.
pub fn assert_bytes_identical(what: &str, first: &[u8], second: &[u8]) {
    if first == second {
        return;
    }
    let at = first
        .iter()
        .zip(second)
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| first.len().min(second.len()));
    let from = at.saturating_sub(24);
    let to_first = (at + 24).min(first.len());
    let to_second = (at + 24).min(second.len());
    panic!(
        "{what} is not deterministic: {} and {} bytes, first difference at {at}\n\
         first:  {:?}\nsecond: {:?}",
        first.len(),
        second.len(),
        String::from_utf8_lossy(&first[from..to_first]),
        String::from_utf8_lossy(&second[from..to_second])
    );
}

/// Compare one row field by field, so the failure names the field.
fn assert_violation_row(violations: &Violations, index: usize, expected: &Violation) {
    let actual = violations.get(index);
    assert!(
        actual.rule == expected.rule,
        "row {index}: rule {:?}, expected {:?}",
        actual.rule,
        expected.rule
    );
    assert!(
        actual.layer == expected.layer,
        "row {index}: layer {:?}, expected {:?}",
        actual.layer,
        expected.layer
    );
    assert!(
        actual.severity == expected.severity,
        "row {index}: severity {:?}, expected {:?}",
        actual.severity,
        expected.severity
    );
    assert!(
        actual.at == expected.at,
        "row {index}: reported at {:?}, expected {:?}",
        actual.at,
        expected.at
    );
    assert!(
        actual.measured == expected.measured,
        "row {index}: measured {:?}, expected {:?}",
        actual.measured,
        expected.measured
    );
    assert!(
        actual.limit == expected.limit,
        "row {index}: limit {:?}, expected {:?}",
        actual.limit,
        expected.limit
    );
    assert!(
        actual.shapes == expected.shapes,
        "row {index}: shapes {:?}, expected {:?}",
        actual.shapes,
        expected.shapes
    );
}

/// Render the named rows for a failure message.
fn describe(violations: &Violations, rows: impl IntoIterator<Item = usize>) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for index in rows {
        let _ = writeln!(out, "  [{index}] {:?}", violations.get(index));
    }
    if out.is_empty() {
        out.push_str("  (no rows)\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{assert_bytes_identical, assert_close, assert_close_relative};

    /// Inside the tolerance passes, outside fails.
    ///
    /// Oracle: hand-derived. |1.0005 - 1| = 5e-4 is inside 1e-3 and |1.01 - 1|
    /// = 1e-2 outside; a NaN is outside any tolerance.
    #[test]
    fn absolute_tolerance_is_the_boundary_it_says_it_is() {
        assert_close("a length", 1.000_5, 1.0, 1e-3);
        assert!(std::panic::catch_unwind(|| assert_close("a length", 1.01, 1.0, 1e-3)).is_err());
        assert!(
            std::panic::catch_unwind(|| assert_close("a length", f64::NAN, 1.0, 1e-3)).is_err()
        );
    }

    /// A relative tolerance scales, and refuses zero.
    ///
    /// Oracle: hand-derived, against the documented contract. 0.5 / 1000 =
    /// 5e-4 is inside 1e-3 and 5e-4 outside 1e-6, and the doc says an expected
    /// zero panics ("use `assert_close`").
    #[test]
    fn relative_tolerance_scales_with_magnitude_and_refuses_zero() {
        assert_close_relative("a resistance", 1_000.5, 1_000.0, 1e-3);
        assert!(std::panic::catch_unwind(|| {
            assert_close_relative("a resistance", 1.000_5, 1.0, 1e-6);
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| {
            assert_close_relative("a resistance", 0.0, 0.0, 1e-3);
        })
        .is_err());
    }

    /// A single differing byte fails.
    ///
    /// Oracle: construct-from-answer. Byte 137 has one bit flipped, so the two
    /// buffers differ in exactly one byte.
    #[test]
    fn byte_comparison_catches_a_single_differing_byte() {
        let base: Vec<u8> = (0..200u32).map(|b| (b % 251) as u8).collect();
        assert_bytes_identical("a report", &base, &base.clone());
        let mut altered = base.clone();
        altered[137] ^= 1;
        assert!(std::panic::catch_unwind(move || {
            assert_bytes_identical("a report", &base, &altered);
        })
        .is_err());
    }
}
