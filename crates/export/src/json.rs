//! JSON reports. The machine-readable form, and the one the determinism gate
//! compares.

use crate::{Header, WriteError};
use gpurify_ingest::StrTable;
use gpurify_report::{RuleRun, Violations};
use gpurify_units::Grid;

/// A complete verification report.
///
/// Both halves matter and neither is optional. `violations` is what was found;
/// `runs` is what was *checked*, and without it an empty violation list is
/// ambiguous between "clean" and "nothing ran". The old suite could not tell
/// those apart, which is how 45 of 94 DRC cases passed by asserting absence.
#[derive(Debug)]
pub struct Report<'a> {
    pub header: &'a Header,
    pub violations: &'a Violations,
    pub runs: &'a [RuleRun],
    /// Needed to turn `StrId` back into text — the one place in the pipeline
    /// where names become readable again.
    pub strings: &'a StrTable,
    /// Needed to print database units as nanometres.
    pub grid: Grid,
}

/// Write a report as JSON.
///
/// **Transform.** Caller owns `out`, which is appended to — so a caller can
/// write several reports into one buffer, and the buffer can be reused.
///
/// Iterates `violations` in the order the table already holds; it does not
/// sort. If the order is wrong, `Violations::sort_canonical` was not called and
/// that is the bug, not this.
///
/// Floats are written with a fixed precision. `serde_json`'s default shortest
/// round-trip representation is stable in practice, but "in practice" is not
/// what a byte-comparison gate wants.
pub fn write_report(report: &Report<'_>, out: &mut String) -> Result<(), WriteError> {
    todo!()
}

/// Write only the rule-run summary.
///
/// The answer to "did this run actually check anything", which is the first
/// question to ask of a clean report and the cheapest to answer.
pub fn write_summary(
    runs: &[RuleRun],
    strings: &StrTable,
    out: &mut String,
) -> Result<(), WriteError> {
    todo!()
}

/// Format one `f64` the same way on every platform, always.
///
/// **Decision** — pure, one value in, one string out, and the single place a
/// float becomes bytes in this crate. Every writer calls it. Centralised
/// because "the same number produces the same text" is exactly the kind of
/// property that holds until one writer formats it slightly differently.
pub fn format_f64(value: f64, out: &mut String) {
    todo!()
}
