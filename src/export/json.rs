//! JSON reports: the machine-readable form.
//!
//! Data in: a [`Report`] (violations, rule records, strings, grid, header). Data
//! out: one JSON object appended to a `String`, lengths in nanometres.

use std::fmt::Write as _;

use crate::export::{Header, WriteError};
use gpurify_check::report::{Measurement, Outcome, RuleRun, Severity, SkipReason, Violations};
use gpurify_geom::{Dbu, Grid};
use gpurify_ingest::{StrId, StrTable};

/// A complete verification report. `runs` is what makes an empty violation list
/// mean "clean" rather than "nothing ran".
#[derive(Debug)]
pub struct Report<'a> {
    pub header: &'a Header,
    pub violations: &'a Violations,
    pub runs: &'a [RuleRun],
    pub strings: &'a StrTable,
    pub grid: Grid,
}

/// Write a report as JSON, appended to `out`, in the table's own order. A
/// non-finite measurement is refused before a byte is written.
pub fn write_report(report: &Report<'_>, out: &mut String) -> Result<(), WriteError> {
    let v = report.violations;
    let all_finite = v
        .measured
        .iter()
        .zip(&v.limit)
        .all(|(measured, limit)| measured.is_finite() && limit.is_finite());
    if !all_finite {
        return Err(WriteError::Unrepresentable("a non-finite measurement"));
    }

    out.push_str("{\"header\":");
    write_header(report.header, out);

    out.push_str(",\"violations\":[");
    for row in 0..v.rule.len() {
        if row > 0 {
            out.push(',');
        }
        out.push_str("{\"rule\":");
        write_name(report.strings, v.rule[row], out);
        let _ = write!(out, ",\"layer\":{}", v.layer[row].0);
        out.push_str(",\"severity\":\"");
        out.push_str(match v.severity[row] {
            Severity::Warning => "warning",
            Severity::Error => "error",
        });
        out.push_str("\",\"at\":{\"unit\":\"nm\",\"x\":");
        write_nm(v.at[row].x, report.grid, out);
        out.push_str(",\"y\":");
        write_nm(v.at[row].y, report.grid, out);
        out.push_str("},\"measured\":");
        write_measurement(v.measured[row], report.grid, out);
        out.push_str(",\"limit\":");
        write_measurement(v.limit[row], report.grid, out);
        let _ = write!(out, ",\"shapes\":[{}", v.shape_a[row].0);
        match v.shape_b[row] {
            Some(shape) => {
                let _ = write!(out, ",{}", shape.0);
            }
            None => out.push_str(",null"),
        }
        out.push_str("]}");
    }

    out.push_str("],\"runs\":[");
    for (index, run) in report.runs.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("{\"rule\":");
        write_name(report.strings, run.rule, out);
        out.push_str(",\"outcome\":\"");
        out.push_str(outcome_name(run.outcome));
        let _ = write!(
            out,
            "\",\"examined\":{},\"violations\":{}}}",
            run.examined, run.violations
        );
    }
    out.push_str("]}");
    Ok(())
}

fn write_header(header: &Header, out: &mut String) {
    out.push_str("{\"tool_version\":");
    write_json_str(header.tool_version, out);
    out.push_str(",\"deck_path\":");
    write_json_str(&header.deck_path, out);
    out.push_str(",\"layout_path\":");
    write_json_str(&header.layout_path, out);
    out.push_str(",\"timestamp\":");
    match &header.timestamp {
        Some(stamp) => write_json_str(stamp, out),
        None => out.push_str("null"),
    }
    out.push('}');
}

/// One measurement, tagged with its dimension and unit. Lengths become nm, areas nm^2.
fn write_measurement(measurement: Measurement, grid: Grid, out: &mut String) {
    let (kind, unit) = match measurement {
        Measurement::Length(_) => ("length", "nm"),
        Measurement::Area(_) => ("area", "nm^2"),
        Measurement::Ratio(_) => ("ratio", ""),
        Measurement::Count(_) => ("count", ""),
        Measurement::Voltage(_) => ("voltage", "mV"),
        Measurement::Current(_) => ("current", "uA"),
        Measurement::Resistance(_) => ("resistance", "ohm"),
    };
    let _ = write!(out, "{{\"kind\":\"{kind}\",\"unit\":\"{unit}\",\"value\":");
    match measurement {
        Measurement::Length(value) => write_nm(value, grid, out),
        Measurement::Area(value) => {
            #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
            let per_dbu = 1_000.0 / grid.dbu_per_um() as f64;
            #[expect(
                clippy::cast_precision_loss,
                reason = "an area past 2^53 dbu^2 is reported to six decimals, not summed"
            )]
            let square_nm = value.raw() as f64 * per_dbu * per_dbu;
            format_f64(square_nm, out);
        }
        Measurement::Ratio(value) => format_f64(value, out),
        Measurement::Count(value) => {
            let _ = write!(out, "{value}");
        }
        Measurement::Voltage(value) => format_f64(value.raw(), out),
        Measurement::Current(value) => format_f64(value.raw(), out),
        Measurement::Resistance(value) => format_f64(value.raw(), out),
    }
    out.push('}');
}

fn write_nm(coord: Dbu, grid: Grid, out: &mut String) {
    format_f64(grid.to_length(coord).raw(), out);
}

fn write_name(strings: &StrTable, id: StrId, out: &mut String) {
    write_json_str(strings.resolve(id), out);
}

/// What a rule did, as one token; a skip carries its reason.
fn outcome_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Ran => "ran",
        Outcome::Skipped(SkipReason::NoDesignIntent) => "skipped:no_design_intent",
        Outcome::Skipped(SkipReason::NotInDeck) => "skipped:not_in_deck",
        Outcome::Skipped(SkipReason::EmptyLayer) => "skipped:empty_layer",
        Outcome::Refused => "refused",
    }
}

fn write_json_str(text: &str, out: &mut String) {
    out.push_str(&serde_json::to_string(text).expect("a str always serialises"));
}

/// The one place a float becomes bytes: `{:.6}`, six decimal places, never an
/// exponent (so anything below `5e-7` prints as `0.000000`).
pub fn format_f64(value: f64, out: &mut String) {
    let _ = write!(out, "{value:.6}");
}
