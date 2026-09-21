//! JSON reports: the machine-readable form, and the one the determinism gate
//! compares.

use std::fmt::Write as _;

use crate::export::{Header, WriteError, INFALLIBLE};
use gpurify_ingest::{StrId, StrTable};
use gpurify_check::report::{Measurement, Outcome, RuleRun, Severity, SkipReason, Violations};
use gpurify_geom::{Dbu, Grid};

/// A complete verification report.
///
/// `runs` is not optional: without it an empty violation list is ambiguous
/// between "clean" and "nothing ran".
#[derive(Debug)]
pub struct Report<'a> {
    pub header: &'a Header,
    pub violations: &'a Violations,
    pub runs: &'a [RuleRun],
    /// Turns `StrId` back into text.
    pub strings: &'a StrTable,
    /// Turns database units into nanometres.
    pub grid: Grid,
}

/// Write a report as JSON, appended to `out`.
///
/// Iterates `violations` in the order the table already holds; it does not sort.
pub fn write_report(report: &Report<'_>, out: &mut String) -> Result<(), WriteError> {
    let rows = report.violations.rule.len();
    debug_assert!(
        columns_agree(report.violations, rows),
        "the violation table's columns hold different row counts"
    );

    // A `NaN` formats as `NaN`, which no JSON reader accepts. Folded before a
    // byte is written, so the failing path leaves `out` untouched. Slicing both
    // columns to one trip count is the release-profile half of `columns_agree`.
    debug_assert_eq!(
        report.violations.measured.len(),
        report.violations.limit.len(),
        "SoA columns must agree"
    );
    let n = report.violations.measured.len();
    let measured_col = &report.violations.measured[..n];
    let limit_col = &report.violations.limit[..n];
    let mut all_finite = true;
    for i in 0..n {
        all_finite &= measured_col[i].is_finite() & limit_col[i].is_finite();
    }
    if !all_finite {
        return Err(WriteError::Unrepresentable("a non-finite measurement"));
    }

    let start = out.len();
    out.reserve(256 + 160 * rows + 96 * report.runs.len());

    out.push_str("{\"header\":");
    write_header(report.header, out);

    out.push_str(",\"violations\":[");
    for row in 0..rows {
        let measured = report.violations.measured[row];
        let limit = report.violations.limit[row];

        out.push_str(SEPARATOR[usize::from(row > 0)]);
        out.push_str("{\"rule\":");
        write_name(report.strings, report.violations.rule[row], out);
        out.push_str(",\"layer\":");
        write_int(out, i128::from(report.violations.layer[row].0));
        out.push_str(",\"severity\":\"");
        out.push_str(severity_name(report.violations.severity[row]));
        out.push_str("\",\"at\":{\"unit\":\"nm\",\"x\":");
        write_nm(report.violations.at[row].x, report.grid, out);
        out.push_str(",\"y\":");
        write_nm(report.violations.at[row].y, report.grid, out);
        out.push_str("},\"measured\":");
        write_measurement(measured, report.grid, out);
        out.push_str(",\"limit\":");
        write_measurement(limit, report.grid, out);
        out.push_str(",\"shapes\":[");
        write_int(out, i128::from(report.violations.shape_a[row].0));
        match report.violations.shape_b[row] {
            Some(shape) => {
                out.push(',');
                write_int(out, i128::from(shape.0));
            }
            None => out.push_str(",null"),
        }
        out.push_str("]}");
    }

    out.push_str("],\"runs\":");
    write_runs(report.runs, report.strings, out);
    out.push('}');

    debug_assert!(out.len() > start, "the report wrote no bytes");
    Ok(())
}

/// `""` before the first row of an array, `","` before every later one.
const SEPARATOR: [&str; 2] = ["", ","];

/// Write only the rule-run summary: what was checked, without the findings.
pub fn write_summary(
    runs: &[RuleRun],
    strings: &StrTable,
    out: &mut String,
) -> Result<(), WriteError> {
    let start = out.len();
    out.reserve(16 + 96 * runs.len());

    out.push_str("{\"runs\":");
    write_runs(runs, strings, out);
    out.push('}');

    debug_assert!(out.len() > start, "the summary wrote no bytes");
    Ok(())
}

/// The rule-run array, shared by the report and the summary.
fn write_runs(runs: &[RuleRun], strings: &StrTable, out: &mut String) {
    let start = out.len();
    out.push('[');
    for (index, run) in runs.iter().enumerate() {
        out.push_str(SEPARATOR[usize::from(index > 0)]);
        out.push_str("{\"rule\":");
        write_name(strings, run.rule, out);
        out.push_str(",\"outcome\":\"");
        out.push_str(outcome_name(run.outcome));
        out.push_str("\",\"examined\":");
        write_int(out, i128::from(run.examined));
        out.push_str(",\"violations\":");
        write_int(out, i128::from(run.violations));
        out.push('}');
    }
    out.push(']');
    debug_assert!(out.len() > start, "an array is at least two bytes");
}

/// The run metadata: the only part of a report two runs may differ in.
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
        // `null` rather than an absent key, so a reader can tell "this run
        // carried no timestamp" from "this writer forgot the field".
        None => out.push_str("null"),
    }
    out.push('}');
}

/// One measurement, tagged with its dimension and unit so a reader cannot
/// compare a resistance against a spacing. Layout units become nanometres here.
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
    out.push_str("{\"kind\":\"");
    out.push_str(kind);
    out.push_str("\",\"unit\":\"");
    out.push_str(unit);
    out.push_str("\",\"value\":");
    match measurement {
        Measurement::Length(value) => write_nm(value, grid, out),
        Measurement::Area(value) => {
            // `|raw| <= MAX_ABS_DBU^2 == 2^80`, so the cast rounds, not wraps.
            let per_dbu = nm_per_dbu(grid);
            #[expect(
                clippy::cast_precision_loss,
                reason = "an area past 2^53 dbu^2 is reported to six decimals, not summed"
            )]
            let square_nm = value.raw() as f64 * per_dbu * per_dbu;
            format_f64(square_nm, out);
        }
        Measurement::Ratio(value) => format_f64(value, out),
        Measurement::Count(value) => write_int(out, i128::from(value)),
        Measurement::Voltage(value) => format_f64(value.raw(), out),
        Measurement::Current(value) => format_f64(value.raw(), out),
        Measurement::Resistance(value) => format_f64(value.raw(), out),
    }
    out.push('}');
}

/// One coordinate as nanometres, through the run's grid.
fn write_nm(coord: Dbu, grid: Grid, out: &mut String) {
    format_f64(grid.to_length(coord).raw(), out);
}

/// Nanometres per database unit. One micrometre is a thousand of them.
fn nm_per_dbu(grid: Grid) -> f64 {
    debug_assert!(grid.dbu_per_um() > 0, "a Grid is positive by construction");
    #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
    let per_um = grid.dbu_per_um() as f64;
    1_000.0 / per_um
}

/// A `StrId` resolved back to text, as a JSON string.
fn write_name(strings: &StrTable, id: StrId, out: &mut String) {
    write_json_str(strings.resolve(id), out);
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

/// What a rule did, as one token — a skip carries its reason in the same string.
fn outcome_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Ran => "ran",
        Outcome::Skipped(SkipReason::NoDesignIntent) => "skipped:no_design_intent",
        Outcome::Skipped(SkipReason::NotInDeck) => "skipped:not_in_deck",
        Outcome::Skipped(SkipReason::EmptyLayer) => "skipped:empty_layer",
        Outcome::Refused => "refused",
    }
}

/// An integer, widened once so there is one integer path rather than five.
fn write_int(out: &mut String, value: i128) {
    write!(out, "{value}").expect(INFALLIBLE);
}

/// One JSON string literal, escaped, with no allocation.
///
/// RFC 8259 requires escaping exactly the quote, the backslash and the C0
/// controls. Slicing by byte index is sound because every byte [`ESCAPE`] names
/// is ASCII, so a run boundary is a character boundary.
fn write_json_str(text: &str, out: &mut String) {
    let start = out.len();
    out.push('"');

    let mut run = 0;
    for (index, &byte) in text.as_bytes().iter().enumerate() {
        let escape = ESCAPE[byte as usize];
        if !escape.is_empty() {
            debug_assert!(
                text.is_char_boundary(index),
                "every escaped byte is ASCII, so it cannot sit inside a character"
            );
            out.push_str(&text[run..index]);
            out.push_str(escape);
            run = index + 1;
        }
    }
    out.push_str(&text[run..]);

    out.push('"');
    debug_assert!(
        out.len() - start >= text.len() + 2,
        "every input byte reaches the output, escaped or verbatim, inside quotes"
    );
}

/// The JSON escape for each byte value, `""` for a byte that needs none.
const ESCAPE: [&str; 256] = {
    let mut table = [""; 256];
    // Every C0 control has a `\u00xx` form; the five with a shorter spelling
    // overwrite theirs below. JSON accepts either, so the choice is pinned here.
    let mut byte = 0;
    while byte < CONTROL.len() {
        table[byte] = CONTROL[byte];
        byte += 1;
    }
    table[0x08] = "\\b";
    table[0x09] = "\\t";
    table[0x0a] = "\\n";
    table[0x0c] = "\\f";
    table[0x0d] = "\\r";
    table[b'"' as usize] = "\\\"";
    table[b'\\' as usize] = "\\\\";
    table
};

/// `\u00xx` for each C0 control, lowercase hex.
const CONTROL: [&str; 32] = [
    "\\u0000", "\\u0001", "\\u0002", "\\u0003", "\\u0004", "\\u0005", "\\u0006", "\\u0007",
    "\\u0008", "\\u0009", "\\u000a", "\\u000b", "\\u000c", "\\u000d", "\\u000e", "\\u000f",
    "\\u0010", "\\u0011", "\\u0012", "\\u0013", "\\u0014", "\\u0015", "\\u0016", "\\u0017",
    "\\u0018", "\\u0019", "\\u001a", "\\u001b", "\\u001c", "\\u001d", "\\u001e", "\\u001f",
];

/// Every column of the violation table holds the same number of rows. Restated
/// here because `Violations` keeps its own `columns_agree` private.
fn columns_agree(violations: &Violations, rows: usize) -> bool {
    violations.layer.len() == rows
        && violations.severity.len() == rows
        && violations.at.len() == rows
        && violations.measured.len() == rows
        && violations.limit.len() == rows
        && violations.shape_a.len() == rows
        && violations.shape_b.len() == rows
}

/// Format one `f64` the same way on every platform: the single place a float
/// becomes bytes in this crate.
///
/// Six digits after the decimal point, never an exponent — `{:.6}`. Decimal
/// places, not significant figures, so a nanometre count of 7654321 appears as
/// `7654321.000000` and is searchable; the cost is that anything below `5e-7`
/// prints as `0.000000`.
pub fn format_f64(value: f64, out: &mut String) {
    // Finiteness is a precondition: `write_report` refuses a non-finite row
    // before it reaches here, but the netlist and parasitic writers hand over a
    // `Qty` nothing has checked, and a `NaN` capacitance in a DSPF still parses.
    debug_assert!(
        value.is_finite(),
        "{value} cannot be written: no reader of any format this crate emits accepts it"
    );
    write!(out, "{value:.6}").expect(INFALLIBLE);
}
