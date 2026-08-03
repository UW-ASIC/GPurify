//! Rendering a run for a human.
//!
//! The JSON and GDS forms are `export`'s; this file is only the text one, and
//! it is here rather than there because it is a presentation choice rather than
//! an interchange format — no other tool consumes it, so it may change freely.

use gpurify_engine::{Outputs, Summary};
use gpurify_ingest::StrTable;
use gpurify_units::Grid;

/// Render the findings.
///
/// **Transform.** Caller owns `out`. Grouped by rule and ordered by the
/// canonical sort the table already carries, so two runs print identically and
/// a human diffing two logs sees only real changes.
pub fn write_violations(
    outputs: &Outputs,
    strings: &StrTable,
    grid: Grid,
    out: &mut String,
) {
    todo!()
}

/// Render the summary.
///
/// **Skipped rules are printed before the violation count, not after.** A
/// summary that leads with `0 violations` and mentions three skipped rules in a
/// footnote is technically complete and practically a lie, and this is the last
/// place in the pipeline where that can be got wrong.
pub fn write_summary(summary: &Summary, out: &mut String) {
    todo!()
}

/// Render an error a user can act on.
///
/// Every error type in this workspace carries what failed and where. This
/// prints that, and does not print a backtrace: a deck with an off-grid limit
/// is a user error, and a stack trace tells the user nothing about it.
pub fn write_error(error: &dyn std::error::Error, out: &mut String) {
    todo!()
}
