//! Assertions over violation tables, rule runs and float comparisons.

use gpurify_ingest::StrId;
use gpurify_report::{Outcome, RuleRun, Violation, Violations};

/// Assert two `f64` agree to an absolute tolerance.
///
/// Both must be finite: a `NaN` compares false against everything, so an
/// unguarded comparison against one passes silently.
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

/// Assert two `f64` agree to a tolerance relative to the expected magnitude.
///
/// `expected` must not be zero: a relative tolerance around zero admits every
/// value. Use [`assert_close`] there.
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

/// Assert a rule ran and looked at something, returning its record.
///
/// The `examined > 0` floor is load-bearing: `Outcome::Ran` over an empty layer
/// is not evidence the rule's logic executed.
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

/// Assert a rule ran, examined shapes, and found nothing.
///
/// The only acceptable form of a clean assertion: an empty violation table on
/// its own is also satisfied by a rule that never executed.
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
        describe(violations, &found)
    );
}

/// Assert a violation table holds exactly one row, and that it is this one.
///
/// Every field is compared, coordinate and measurement included.
pub fn assert_only_violation(violations: &Violations, expected: &Violation) {
    assert!(
        violations.rule.len() == 1,
        "expected exactly one violation, found {}:\n{}",
        violations.rule.len(),
        describe(violations, &(0..violations.rule.len()).collect::<Vec<_>>())
    );
    assert_violation_row(violations, 0, expected);
}

/// Assert a table contains this violation, and return which row it is.
#[must_use]
pub fn assert_has_violation(violations: &Violations, expected: &Violation) -> usize {
    let found = (0..violations.rule.len()).find(|&i| row_matches(violations, i, expected));
    match found {
        Some(index) => index,
        None => panic!(
            "no row matches {expected:?}; the table holds:\n{}",
            describe(violations, &(0..violations.rule.len()).collect::<Vec<_>>())
        ),
    }
}

/// Assert two violation tables are equal row for row, in order.
///
/// Order is part of the interface: `Violations::sort_canonical` makes two
/// tables with the same rows in a different order a determinism failure.
pub fn assert_violations_eq(actual: &Violations, expected: &Violations) {
    assert!(
        actual.rule.len() == expected.rule.len(),
        "violation tables differ in length: {} against {}\nactual:\n{}\nexpected:\n{}",
        actual.rule.len(),
        expected.rule.len(),
        describe(actual, &(0..actual.rule.len()).collect::<Vec<_>>()),
        describe(expected, &(0..expected.rule.len()).collect::<Vec<_>>())
    );
    for index in 0..actual.rule.len() {
        assert_violation_row(actual, index, &row(expected, index));
    }
}

/// Assert a run produced byte-identical output twice.
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

/// Read one row back out of a table.
///
/// Reads the public columns rather than `Violations::get`, whose body is still
/// `todo!()` — an assertion helper must not panic before it can report.
fn row(violations: &Violations, index: usize) -> Violation {
    Violation {
        rule: violations.rule[index],
        layer: violations.layer[index],
        severity: violations.severity[index],
        at: violations.at[index],
        measured: violations.measured[index],
        limit: violations.limit[index],
        shapes: (violations.shape_a[index], violations.shape_b[index]),
    }
}

fn row_matches(violations: &Violations, index: usize, expected: &Violation) -> bool {
    let actual = row(violations, index);
    actual.rule == expected.rule
        && actual.layer == expected.layer
        && actual.severity == expected.severity
        && actual.at == expected.at
        && actual.measured == expected.measured
        && actual.limit == expected.limit
        && actual.shapes == expected.shapes
}

/// Compare one row field by field, so the failure names the field.
fn assert_violation_row(violations: &Violations, index: usize, expected: &Violation) {
    let actual = row(violations, index);
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
fn describe(violations: &Violations, rows: &[usize]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for &index in rows {
        let _ = writeln!(out, "  [{index}] {:?}", row(violations, index));
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
    #[test]
    fn absolute_tolerance_is_the_boundary_it_says_it_is() {
        assert_close("a length", 1.000_5, 1.0, 1e-3);
        assert!(std::panic::catch_unwind(|| assert_close("a length", 1.01, 1.0, 1e-3)).is_err());
        assert!(
            std::panic::catch_unwind(|| assert_close("a length", f64::NAN, 1.0, 1e-3)).is_err()
        );
    }

    /// A relative tolerance scales, and refuses zero.
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
