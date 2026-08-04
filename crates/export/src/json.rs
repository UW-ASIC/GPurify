//! JSON reports. The machine-readable form, and the one the determinism gate
//! compares.

use std::fmt::Write as _;

use crate::{Header, WriteError, INFALLIBLE};
use gpurify_ingest::{StrId, StrTable};
use gpurify_report::{Measurement, Outcome, RuleRun, Severity, SkipReason, Violations};
use gpurify_units::{Dbu, Grid};

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
/// Floats are written through [`format_f64`], which pins the precision.
/// `serde_json`'s default shortest round-trip representation is stable in
/// practice, but "in practice" is not what a byte-comparison gate wants.
pub fn write_report(report: &Report<'_>, out: &mut String) -> Result<(), WriteError> {
    let rows = report.violations.rule.len();
    debug_assert!(
        columns_agree(report.violations, rows),
        "the violation table's columns hold different row counts"
    );

    // A `NaN` formats as `NaN`, which no JSON reader accepts, so a single bad
    // row loses the whole report. Both float columns are folded before a byte
    // is written, so the failing path leaves `out` untouched rather than
    // writing rows and rolling them back — an error return and a caller's
    // buffer no longer have to agree about how far the write got.
    //
    // `&`, not `&&`: both operands are one variant test, so short-circuiting
    // would buy a branch and save nothing. `Measurement::is_finite`'s `match`
    // is a jump table over a three-bit tag, and a rule's rows all carry one
    // dimension, so it predicts.
    //
    // Both columns are sliced to one trip count before the loop, which is what
    // deletes the per-row bounds check and is also the fail-closed half of
    // `columns_agree`: unlike the `debug_assert` above, a short `limit` column
    // panics here in release too rather than folding over the rows it happens
    // to have.
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

    // `violations` is written before `runs` so the order of the table is the
    // order of the text. A reader looking for the first mention of a rule finds
    // the violation, not the run record.
    let start = out.len();
    out.reserve(256 + 160 * rows + 96 * report.runs.len());

    out.push_str("{\"header\":");
    write_header(report.header, out);

    out.push_str(",\"violations\":[");
    for row in 0..rows {
        let measured = report.violations.measured[row];
        let limit = report.violations.limit[row];

        // A comma before every row but the first, without a branch: the byte is
        // written unconditionally into a two-element table indexed by the row.
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
        // Two arms of different widths, so no table indexed by the niche would
        // serve. It sits in a loop already excused above — text is variable
        // width, nothing here vectorises — and a spacing rule fills the slot for
        // every row while a width rule fills it for none, so it predicts.
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
///
/// A table rather than an `if`: the index is `row > 0` widened, so the write is
/// unconditional and the decision rides in the address.
const SEPARATOR: [&str; 2] = ["", ","];

/// Write only the rule-run summary.
///
/// The answer to "did this run actually check anything", which is the first
/// question to ask of a clean report and the cheapest to answer.
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
///
/// **Transform.** One JSON object per row of `runs`, in the order handed in.
/// Carries no measurement: a summary that quoted one would be the report under
/// a smaller name.
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

/// The run metadata, and the only part of a report two runs may differ in.
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
        // `null` rather than an absent key: a reader can then tell "this run
        // carried no timestamp" from "this writer forgot the field".
        None => out.push_str("null"),
    }
    out.push('}');
}

/// One measurement, tagged with the dimension and the unit it is written in.
///
/// The tag is what stops a reader comparing a resistance against a spacing —
/// the thing `Measurement` exists to prevent, carried through into the text.
/// Layout units become nanometres here, which is the conversion
/// `docs/SIGNATURE_DEFECTS.md` makes this writer responsible for.
///
/// The `match` is a jump table over a three-bit variant tag, not a
/// data-dependent branch over bulk data: one arm per dimension, all seven
/// bodies the same handful of pushes.
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
            // The square of `Grid::to_length`'s factor, applied to a product of
            // two coordinates. `|raw| <= MAX_ABS_DBU^2 == 2^80`, so the cast
            // rounds rather than overflows.
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

/// A `StrId` resolved back to text, as a JSON string. The one place in a report
/// where an interned name becomes readable again.
fn write_name(strings: &StrTable, id: StrId, out: &mut String) {
    write_json_str(strings.resolve(id), out);
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

/// What a rule did, as one token.
///
/// A skip carries its reason in the same string rather than a sibling field, so
/// "was this rule actually checked" is answerable by reading one value — which
/// is the question `RuleRun` exists for.
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
///
/// Every count in a report — a layer number, a polygon id, a shape count —
/// fits in `i128` with room to spare, and `{}` on an integer is exact at every
/// width, so nothing here needs [`format_f64`]'s precision decision.
fn write_int(out: &mut String, value: i128) {
    write!(out, "{value}").expect(INFALLIBLE);
}

/// One JSON string literal, escaped, with no allocation.
///
/// Rule ids and paths are ASCII in every deck this tool has seen, but "seen" is
/// not a guarantee and one stray quote in a deck would produce a report no
/// reader can parse. RFC 8259 requires escaping exactly the quote, the
/// backslash and the C0 controls; everything else is passed through as UTF-8.
///
/// Copied in runs, not character by character. The scan is over bytes against
/// [`ESCAPE`], and the stretch between two escapes leaves as one `push_str`, so
/// a name with nothing to escape — every name in a real deck, and one per
/// violation row — costs a single `memcpy` rather than a UTF-8 decode, a
/// `match` and a `push` per character. Slicing `text` by byte index is sound
/// because every byte [`ESCAPE`] names is ASCII, so a run boundary is always a
/// character boundary.
fn write_json_str(text: &str, out: &mut String) {
    let start = out.len();
    out.push('"');

    let mut run = 0;
    for (index, &byte) in text.as_bytes().iter().enumerate() {
        let escape = ESCAPE[byte as usize];
        // Not taken for any byte of a name, path or version string this writer
        // has been handed, so it predicts; and the taken side is a slice and
        // two appends, expensive enough that executing it unconditionally would
        // cost more than the occasional miss.
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
///
/// A table rather than a chain of arms: the common answer is "no escape", which
/// becomes one load and one test, and the escapes sit in one place where they
/// can be read against RFC 8259 §7 instead of being spread over a `match`.
const ESCAPE: [&str; 256] = {
    let mut table = [""; 256];
    // Every C0 control has a `\u00xx` form. The five with a shorter spelling
    // overwrite theirs below; JSON accepts either, but the shorter one is what
    // this writer emitted before the table existed and a report's bytes are a
    // comparison gate.
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

/// `\u00xx` for each C0 control, lowercase hex — byte for byte what the
/// `"\\u{:04x}"` this replaced produced.
const CONTROL: [&str; 32] = [
    "\\u0000", "\\u0001", "\\u0002", "\\u0003", "\\u0004", "\\u0005", "\\u0006", "\\u0007",
    "\\u0008", "\\u0009", "\\u000a", "\\u000b", "\\u000c", "\\u000d", "\\u000e", "\\u000f",
    "\\u0010", "\\u0011", "\\u0012", "\\u0013", "\\u0014", "\\u0015", "\\u0016", "\\u0017",
    "\\u0018", "\\u0019", "\\u001a", "\\u001b", "\\u001c", "\\u001d", "\\u001e", "\\u001f",
];

/// Every column of the violation table holds the same number of rows.
///
/// `Violations` keeps its own `columns_agree` private, and the columns are what
/// this writer indexes — a table short one column would panic here on a row the
/// others still have.
fn columns_agree(violations: &Violations, rows: usize) -> bool {
    violations.layer.len() == rows
        && violations.severity.len() == rows
        && violations.at.len() == rows
        && violations.measured.len() == rows
        && violations.limit.len() == rows
        && violations.shape_a.len() == rows
        && violations.shape_b.len() == rows
}

/// Format one `f64` the same way on every platform, always.
///
/// **Decision** — pure, one value in, one string out, and the single place a
/// float becomes bytes in this crate. Every writer calls it. Centralised
/// because "the same number produces the same text" is exactly the kind of
/// property that holds until one writer formats it slightly differently.
///
/// The precision is **six digits after the decimal point, never an exponent** —
/// `{:.6}`. Decimal places rather than significant figures, so the digits of a
/// value are the digits of its text: a nanometre count of 7654321 appears as
/// `7654321.000000` and can be found in a report by searching for it, which a
/// six-significant-figure form would have rounded away. The cost is the other
/// end of the range: anything below `5e-7` prints as `0.000000`. Every quantity
/// this crate writes is orders of magnitude above that — capacitance in
/// femtofarads, resistance in ohms, length in nanometres — and a writer holding
/// a capacitance in farads is the bug, not this.
pub fn format_f64(value: f64, out: &mut String) {
    // `{:.6}` is the whole decision, and it is stated above rather than here so
    // there is one place to read it.
    //
    // The precondition is finiteness: a `NaN` formats as `NaN` and an infinity
    // as `inf`, neither of which is JSON and neither of which a SPICE reader
    // accepts as a magnitude. `docs/SIGNATURE_DEFECTS.md` left the resolution
    // open between a `debug_assert` here and a `Result` return; this is the
    // former, which is the whole of what the frozen signature allows.
    // `write_report` refuses a non-finite row before it reaches here, but the
    // netlist and parasitic writers hand over a `Qty` nothing has checked, and a
    // `NaN` capacitance written into a DSPF is a file that parses.
    debug_assert!(
        value.is_finite(),
        "{value} cannot be written: no reader of any format this crate emits accepts it"
    );
    write!(out, "{value:.6}").expect(INFALLIBLE);
}
