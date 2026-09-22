//! The text rendering of a run, for a human.

use gpurify::engine::{Outputs, StageStatus, Summary};
use gpurify_check::report::{Measurement, Outcome, Severity, SkipReason};
use gpurify_geom::{Dbu, Grid};
use gpurify_ingest::StrTable;
use std::fmt::Write as _;

/// Append the rule records (even when clean: they separate "ran, found nothing"
/// from "never ran"), the violation rows and the LVS verdict to `out`.
pub fn write_violations(outputs: &Outputs, strings: &StrTable, grid: Grid, out: &mut String) {
    out.push_str("rules:\n");
    if outputs.runs.is_empty() {
        out.push_str("  none recorded — nothing was checked\n");
    }
    for run in &outputs.runs {
        let _ = write!(out, "  {}: ", strings.resolve(run.rule));
        match run.outcome {
            Outcome::Ran => out.push_str("ran"),
            Outcome::Skipped(reason) => {
                let _ = write!(out, "skipped, {}", skip_reason(reason));
            }
            Outcome::Refused => out.push_str("refused"),
        }
        let _ = writeln!(
            out,
            ", examined {} shapes, found {} violations",
            run.examined, run.violations
        );
    }

    let rows = outputs.violations.len();
    let _ = writeln!(out, "violations: {rows}");
    for row in 0..rows {
        let violation = outputs.violations.get(row);
        let _ = write!(
            out,
            "  {} {} layer {} at ({}, {}) measured ",
            strings.resolve(violation.rule),
            match violation.severity {
                Severity::Warning => "warning",
                Severity::Error => "error",
            },
            violation.layer.0,
            grid.to_length(violation.at.x),
            grid.to_length(violation.at.y),
        );
        write_measurement(out, grid, violation.measured);
        out.push_str(" against limit ");
        write_measurement(out, grid, violation.limit);
        let _ = write!(out, " on shape {}", violation.shapes.0 .0);
        if let Some(other) = violation.shapes.1 {
            let _ = write!(out, " and shape {}", other.0);
        }
        out.push('\n');
    }

    // Debug-printed; every discrepancy of a mismatch is already an error row above.
    if let Some(verdict) = &outputs.lvs {
        let _ = writeln!(out, "lvs: {verdict:?}");
    }
}

/// One measurement through the run's grid: lengths in `nm`, areas in `nm^2`.
fn write_measurement(out: &mut String, grid: Grid, measurement: Measurement) {
    match measurement {
        Measurement::Length(value) => {
            let _ = write!(out, "{}", grid.to_length(value));
        }
        Measurement::Area(value) => {
            let per_dbu = grid.to_length(Dbu::new_unchecked(1)).raw();
            #[expect(
                clippy::cast_precision_loss,
                reason = "an area past 2^53 dbu^2 is reported to a reader, not accumulated"
            )]
            let square_nm = value.raw() as f64 * per_dbu * per_dbu;
            let _ = write!(out, "{square_nm} nm^2");
        }
        other => {
            let _ = write!(out, "{other}");
        }
    }
}

/// Why a rule did not run, phrased as the thing the reader can supply.
fn skip_reason(reason: SkipReason) -> &'static str {
    match reason {
        SkipReason::NoDesignIntent => "no design intent was supplied",
        SkipReason::NotInDeck => "the deck does not configure this rule",
        SkipReason::EmptyLayer => "the layer it names holds no geometry",
    }
}

/// Append the run summary: stage lines, then skipped before clean before the count.
pub fn write_summary(summary: &Summary, out: &mut String) {
    out.push_str("summary:\n");
    for (stage, status) in [
        ("drc", &summary.drc),
        ("erc", &summary.erc),
        ("lvs", &summary.lvs),
        ("pex", &summary.pex),
    ] {
        let _ = write!(out, "  {stage}: ");
        match status {
            StageStatus::Ran => out.push_str("ran\n"),
            StageStatus::NotSelected => out.push_str("not selected\n"),
            StageStatus::Skipped(why) => {
                let _ = writeln!(out, "skipped, {why}");
            }
            StageStatus::Refused(why) => {
                let _ = writeln!(out, "refused, {why}");
            }
        }
    }
    let _ = writeln!(out, "  {} rules skipped", summary.rules_skipped);
    let _ = writeln!(out, "  {} rules clean", summary.rules_clean);
    let _ = writeln!(
        out,
        "  {} violations: {} errors, {} warnings",
        summary.violations, summary.errors, summary.warnings
    );
}

/// Append an error and its cause chain to `out`. No backtrace: these are user errors.
pub fn write_error(error: &dyn std::error::Error, out: &mut String) {
    let _ = writeln!(out, "error: {error}");
    let mut cause = error.source();
    while let Some(link) = cause {
        let _ = writeln!(out, "  caused by: {link}");
        cause = link.source();
    }
}

#[cfg(test)]
mod tests {
    use super::{write_summary, write_violations};
    use gpurify::engine::{Outputs, StageStatus, Summary};
    use gpurify_check::report::{Measurement, Outcome, RuleRun, Severity, SkipReason, Violation};
    use gpurify_geom::{DbuArea, Grid, LayerId, PolyId};
    use gpurify_ingest::StrTable;
    use gpurify_testgen::{dbu, point};

    /// The whole text report for one small run, byte for byte. On a 2000 dbu/um
    /// grid one dbu is 0.5 nm, so 48 dbu^2 is 12 nm^2.
    #[test]
    fn a_run_renders_to_this_exact_text() {
        let mut strings = StrTable::default();
        let width = strings.intern("m1_min_width");
        let antenna = strings.intern("antenna_ratio");
        let mut outputs = Outputs::default();
        outputs.runs.push(RuleRun {
            rule: width,
            outcome: Outcome::Ran,
            examined: 4_231,
            violations: 1,
        });
        outputs.runs.push(RuleRun {
            rule: antenna,
            outcome: Outcome::Skipped(SkipReason::NoDesignIntent),
            examined: 0,
            violations: 0,
        });
        outputs.violations.push(Violation {
            rule: width,
            layer: LayerId(3),
            severity: Severity::Error,
            at: point(4_200, 8_600),
            measured: Measurement::Length(dbu(4)),
            limit: Measurement::Area(DbuArea::new(48)),
            shapes: (PolyId(7), Some(PolyId(9))),
        });
        let summary = Summary {
            drc: StageStatus::Ran,
            erc: StageStatus::Refused("bad grid".to_string()),
            lvs: StageStatus::Skipped("no reference netlist was supplied"),
            pex: StageStatus::NotSelected,
            violations: 1,
            errors: 1,
            warnings: 0,
            rules_clean: 0,
            rules_skipped: 1,
        };

        let grid = Grid::new(2_000).expect("a legal resolution");
        let mut out = String::new();
        write_violations(&outputs, &strings, grid, &mut out);
        write_summary(&summary, &mut out);
        assert_eq!(
            out,
            "rules:\n\
             \x20 m1_min_width: ran, examined 4231 shapes, found 1 violations\n\
             \x20 antenna_ratio: skipped, no design intent was supplied, examined 0 shapes, found 0 violations\n\
             violations: 1\n\
             \x20 m1_min_width error layer 3 at (2100 nm, 4300 nm) measured 2 nm against limit 12 nm^2 on shape 7 and shape 9\n\
             summary:\n\
             \x20 drc: ran\n\
             \x20 erc: refused, bad grid\n\
             \x20 lvs: skipped, no reference netlist was supplied\n\
             \x20 pex: not selected\n\
             \x20 1 rules skipped\n\
             \x20 0 rules clean\n\
             \x20 1 violations: 1 errors, 0 warnings\n"
        );
    }
}
