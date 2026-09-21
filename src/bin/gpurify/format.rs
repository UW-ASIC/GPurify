//! The text rendering of a run, for a human.

use gpurify::engine::{Outputs, StageStatus, Summary};
use gpurify_check::report::{Measurement, Outcome, Severity, SkipReason};
use gpurify_geom::{Dbu, Grid};
use gpurify_ingest::StrTable;
use std::fmt::Write as _;

/// Append the rule records, the violation rows and the LVS verdict to `out`.
///
/// The rule records are printed even when clean: an empty violation table is
/// ambiguous between a rule that ran and found nothing and a rule that never
/// ran. `parasitics` is not rendered here — `export`'s SPEF and DSPF writers
/// take it.
pub fn write_violations(outputs: &Outputs, strings: &StrTable, grid: Grid, out: &mut String) {
    // `Violations::len` debug-asserts that the eight columns agree, which is
    // this function's one precondition: it reads them row-wise.
    let rows = outputs.violations.len();

    // The record of what executed comes first, so a reader meets it before the
    // findings rather than after them.
    out.push_str("rules:\n");
    if outputs.runs.is_empty() {
        // Fail closed in prose: no rule record at all is not a clean run.
        out.push_str("  none recorded — nothing was checked\n");
    }
    let mut recorded = 0usize;
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
        recorded += 1;
    }
    // A rule record that never reached the text is a rule the reader will read
    // as never having existed.
    debug_assert_eq!(
        recorded,
        outputs.runs.len(),
        "the rule-record renderer dropped rules"
    );

    let _ = writeln!(out, "violations: {rows}");
    let mut written = 0usize;
    for row in 0..rows {
        let violation = outputs.violations.get(row);
        // The report is the last place a `NaN` can be caught before a human
        // reads it as a measurement.
        debug_assert!(
            violation.measured.is_finite(),
            "row {row} measured {:?}, which is not finite",
            violation.measured
        );
        debug_assert!(
            violation.limit.is_finite(),
            "row {row} has limit {:?}, which is not finite",
            violation.limit
        );

        let _ = write!(
            out,
            "  {} {} layer {} at ({}, {}) measured ",
            strings.resolve(violation.rule),
            severity(violation.severity),
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
        written += 1;
    }
    // A formatter that collapsed rows sharing a rule would report fewer
    // violations than were found.
    debug_assert_eq!(written, rows, "the violation renderer dropped rows");

    // Printed through `Debug` because `gpurify_check::lvs::Verdict` is not nameable
    // here: `gpurify-lvs` is not a dependency and `gpurify_engine` re-exports
    // `Outputs` without it, so no `match` is writable. Names therefore print as
    // interned `StrId`s. Not a lost finding — every discrepancy of a `Mismatch`
    // is already an error row above.
    if let Some(verdict) = &outputs.lvs {
        let _ = writeln!(out, "lvs: {verdict:?}");
    }
}

/// One measurement, with the run's grid applied.
///
/// [`Measurement`]'s own `Display` prints raw database units, because
/// `std::fmt` has nowhere to carry a [`Grid`]. Lengths land in `nm` and areas
/// in `nm^2`, matching the JSON report. The other five variants are already
/// physical and fall through to `Display`.
fn write_measurement(out: &mut String, grid: Grid, measurement: Measurement) {
    match measurement {
        Measurement::Length(value) => {
            let _ = write!(out, "{}", grid.to_length(value));
        }
        Measurement::Area(value) => {
            // Nanometres per database unit, asked of the conversion rather than
            // recomputed from `dbu_per_um`: an area is a product of two
            // coordinates, so its factor is the length factor squared, and
            // taking it from `to_length` is what stops the two arms drifting.
            let per_dbu = grid.to_length(Dbu::new_unchecked(1)).raw();
            debug_assert!(
                per_dbu.is_finite() && per_dbu > 0.0,
                "a positive grid gives a positive length to one database unit, not {per_dbu}"
            );

            // `|raw| <= MAX_ABS_DBU^2 == 2^80`, so the cast rounds and cannot
            // overflow. Rounding is acceptable here and nowhere upstream: this
            // value is printed once and never summed.
            #[expect(
                clippy::cast_precision_loss,
                reason = "an area past 2^53 dbu^2 is reported to a reader, not accumulated"
            )]
            let square_nm = value.raw() as f64 * per_dbu * per_dbu;
            debug_assert!(
                square_nm.is_finite(),
                "a bounded area over a positive grid rendered as {square_nm}"
            );
            let _ = write!(out, "{square_nm} nm^2");
        }
        other => {
            let _ = write!(out, "{other}");
        }
    }
}

/// The one spelling of each severity, so a reader greps for a fixed word.
fn severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Warning => "warning",
        Severity::Error => "error",
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

/// Append the run summary to `out`, skipped rules before the violation count.
pub fn write_summary(summary: &Summary, out: &mut String) {
    // Not equality: `errors + warnings == violations` is stronger than anything
    // `engine` promises.
    debug_assert!(
        summary.errors <= summary.violations && summary.warnings <= summary.violations,
        "a severity count larger than the table it counts: {summary:?}"
    );

    out.push_str("summary:\n");
    write_stage(out, "drc", &summary.drc);
    write_stage(out, "erc", &summary.erc);
    write_stage(out, "lvs", &summary.lvs);
    write_stage(out, "pex", &summary.pex);

    // Skipped before clean, clean before the count, and all three printed even
    // when zero: a summary that leads with a count and footnotes what did not
    // run is complete and still a lie.
    let _ = writeln!(out, "  {} rules skipped", summary.rules_skipped);
    let _ = writeln!(out, "  {} rules clean", summary.rules_clean);
    let _ = writeln!(
        out,
        "  {} violations: {} errors, {} warnings",
        summary.violations, summary.errors, summary.warnings
    );

    debug_assert!(out.ends_with('\n'), "the summary ends mid-line");
}

/// One stage's status line.
fn write_stage(out: &mut String, stage: &str, status: &StageStatus) {
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

/// Append an error and its cause chain to `out`.
///
/// No backtrace: a deck with an off-grid limit is a user error, and a stack
/// trace tells the user nothing about it.
pub fn write_error(error: &dyn std::error::Error, out: &mut String) {
    let _ = writeln!(out, "error: {error}");
    let mut cause = error.source();
    while let Some(link) = cause {
        let _ = writeln!(out, "  caused by: {link}");
        cause = link.source();
    }
    debug_assert!(out.ends_with('\n'), "the error ends mid-line");
}

/// The text renderer, against answers built before it runs.
///
/// `LayerId` and `PolyId` are not nameable here — `gpurify-core` is not a
/// dependency — so ids come from the seeded scale generator rather than from
/// literals.
#[cfg(test)]
mod tests {
    use super::{write_error, write_measurement, write_summary, write_violations};
    use gpurify::engine::{Outputs, StageStatus, Summary};
    use gpurify_check::report::{Measurement, Outcome, RuleRun, Severity, SkipReason, Violations};
    use gpurify_geom::{DbuArea, Grid};
    use gpurify_ingest::StrTable;
    use gpurify_testgen::{
        assert_bytes_identical, dbu, point, scale_corpus, ScaleCorpus, ScaleSpec,
    };

    /// Append one row to the violation columns directly.
    ///
    /// A macro because `LayerId` and `PolyId` cannot appear in a signature
    /// here.
    macro_rules! push_row {
        ($violations:expr, $rule:expr, $layer:expr, $at:expr, $measured:expr, $limit:expr, $shape:expr) => {{
            let violations: &mut Violations = $violations;
            let (x, y): (i64, i64) = $at;
            violations.rule.push($rule);
            violations.layer.push($layer);
            violations.severity.push(Severity::Error);
            violations.at.push(point(x, y));
            violations
                .measured
                .push(Measurement::Length(dbu($measured)));
            violations.limit.push(Measurement::Length(dbu($limit)));
            violations.shape_a.push($shape);
            violations.shape_b.push(None);
        }};
    }

    /// One database unit is one nanometre here, so a coordinate prints with the
    /// same digits whether or not the grid was applied.
    const DBU_PER_UM: i64 = 1_000;

    fn grid() -> Grid {
        Grid::new(DBU_PER_UM).expect("1000 database units per micrometre is a legal resolution")
    }

    /// Three distinct layers and two nets of conductors, by construction.
    fn corpus() -> ScaleCorpus {
        scale_corpus(ScaleSpec {
            seed: 4,
            polygons: 12,
            nets: 2,
            hierarchy_depth: 1,
        })
    }

    /// Counts that share no digit run, so a `contains` check is evidence.
    fn summary_with_skips() -> Summary {
        Summary {
            drc: StageStatus::Ran,
            erc: StageStatus::Ran,
            lvs: StageStatus::Skipped("no reference netlist was supplied"),
            pex: StageStatus::NotSelected,
            violations: 137,
            errors: 101,
            warnings: 36,
            rules_clean: 209,
            rules_skipped: 43,
        }
    }

    /// The first line whose text contains `needle`, lowercased.
    fn line_containing(text: &str, needle: &str) -> usize {
        let lowered = text.to_lowercase();
        lowered
            .lines()
            .position(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("no line mentions {needle:?} in:\n{text}"))
    }

    /// The skip line comes before the violation count, whatever the wording.
    #[test]
    fn skipped_rules_are_printed_before_the_violation_count() {
        let mut out = String::new();
        write_summary(&summary_with_skips(), &mut out);
        let skipped = line_containing(&out, "skip");
        let violations = line_containing(&out, "violation");
        assert!(
            skipped < violations,
            "the skip line is at {skipped} and the violation count at \
             {violations}; skips come first:\n{out}"
        );
    }

    /// Every count handed in is a count that must appear.
    #[test]
    fn the_summary_reports_every_count_it_was_given() {
        let summary = summary_with_skips();
        let mut out = String::new();
        write_summary(&summary, &mut out);
        for (what, count) in [
            ("violations", summary.violations),
            ("errors", summary.errors),
            ("warnings", summary.warnings),
            ("clean rules", summary.rules_clean),
            ("skipped rules", summary.rules_skipped),
        ] {
            assert!(
                out.contains(&count.to_string()),
                "the summary never states the {what} count of {count}:\n{out}"
            );
        }
    }

    /// A skipped stage carries the reason it was skipped, which is the only
    /// thing telling a reader whether the missing input was theirs to supply.
    #[test]
    fn a_skipped_stage_is_reported_with_the_reason_it_carries() {
        let mut out = String::new();
        write_summary(&summary_with_skips(), &mut out);
        assert!(
            out.contains("no reference netlist was supplied"),
            "the summary drops the skip reason:\n{out}"
        );
    }

    /// The determinism gate compares two runs, so this is a function of its
    /// input alone.
    #[test]
    fn the_summary_renders_identically_twice() {
        let summary = summary_with_skips();
        let mut first = String::new();
        let mut second = String::new();
        write_summary(&summary, &mut first);
        write_summary(&summary, &mut second);
        assert_bytes_identical("the run summary", first.as_bytes(), second.as_bytes());
    }

    /// The table is built in canonical order by hand, so the assertion is about
    /// this function and not about `sort_canonical`.
    #[test]
    fn violations_are_rendered_in_the_canonical_order_of_the_table() {
        let corpus = corpus();
        let mut strings = StrTable::default();
        let one = strings.intern("m1_min_width");
        let two = strings.intern("m1_min_spacing");
        let (first, second) = if one.0 <= two.0 {
            ((one, "m1_min_width"), (two, "m1_min_spacing"))
        } else {
            ((two, "m1_min_spacing"), (one, "m1_min_width"))
        };

        let mut outputs = Outputs::default();
        for (rule, _) in [first, second] {
            push_row!(
                &mut outputs.violations,
                rule,
                corpus.layers.lower,
                (4_200, 8_600),
                350,
                500,
                corpus.expected_net_polys[0][0]
            );
        }

        let mut out = String::new();
        write_violations(&outputs, &strings, grid(), &mut out);
        let at_first = out
            .find(first.1)
            .unwrap_or_else(|| panic!("{} is missing from:\n{out}", first.1));
        let at_second = out
            .find(second.1)
            .unwrap_or_else(|| panic!("{} is missing from:\n{out}", second.1));
        assert!(
            at_first < at_second,
            "rule {} sorts before {} but is printed after it:\n{out}",
            first.1,
            second.1
        );
    }

    /// All four rows must survive to the text: a formatter that collapses rows
    /// sharing a rule reports fewer violations than were found.
    #[test]
    fn every_row_names_its_own_coordinate_and_what_it_measured() {
        let corpus = corpus();
        let mut strings = StrTable::default();
        let rule = strings.intern("m1_min_width");
        let poly = corpus.expected_net_polys[0][0];

        // Distinct digit runs, none a substring of another, so `contains` is
        // evidence for that row rather than an accidental match on a neighbour.
        let rows = [
            (4_200_i64, 8_600_i64, 350_i64),
            (7_100, 9_300, 410_i64),
            (2_700, 6_400, 380),
            (5_900, 3_100, 470),
        ];
        let mut outputs = Outputs::default();
        for (x, y, measured) in rows {
            push_row!(
                &mut outputs.violations,
                rule,
                corpus.layers.upper,
                (x, y),
                measured,
                850,
                poly
            );
        }

        let mut out = String::new();
        write_violations(&outputs, &strings, grid(), &mut out);
        for (x, y, measured) in rows {
            for value in [x, y, measured] {
                assert!(
                    out.contains(&value.to_string()),
                    "the row at ({x}, {y}) measuring {measured} lost {value}:\n{out}"
                );
            }
        }
        assert!(
            out.contains("850"),
            "no row states the limit it was compared against:\n{out}"
        );
    }

    /// "Clean" is only interpretable beside the record of what executed, and
    /// this function is the only place a clean run can name the rules that ran.
    #[test]
    fn a_clean_run_still_names_the_rules_that_ran_and_the_shapes_they_examined() {
        let mut strings = StrTable::default();
        let ran = strings.intern("m1_min_width");
        let skipped = strings.intern("antenna_ratio");

        let mut outputs = Outputs::default();
        outputs.runs.push(RuleRun {
            rule: ran,
            outcome: Outcome::Ran,
            examined: 4_231,
            violations: 0,
        });
        outputs.runs.push(RuleRun {
            rule: skipped,
            outcome: Outcome::Skipped(SkipReason::NoDesignIntent),
            examined: 0,
            violations: 0,
        });
        assert!(
            outputs.violations.rule.is_empty(),
            "the fixture is a clean run: no violation may be pushed"
        );

        let mut out = String::new();
        write_violations(&outputs, &strings, grid(), &mut out);

        let lowered = out.to_lowercase();
        let line_for = |rule: &str| {
            lowered
                .lines()
                .find(|line| line.contains(rule))
                .unwrap_or_else(|| panic!("a clean run never mentions {rule}:\n{out}"))
        };
        let clean = line_for("m1_min_width");
        assert!(
            clean.contains("4231"),
            "the clean rule is named without the 4231 shapes it examined, which \
             is the claim that separates it from a rule that never ran:\n{out}"
        );
        assert!(
            !clean.contains("skip"),
            "a rule that ran is reported as skipped:\n{out}"
        );
        assert!(
            line_for("antenna_ratio").contains("skip"),
            "the rule that did not run is printed as though it had:\n{out}"
        );
    }

    /// An area's conversion is the length conversion squared: on a 2000-unit
    /// micrometre one unit is 0.5 nm, so 4 dbu is 2 nm and 48 dbu^2 is 12 nm^2.
    #[test]
    fn an_area_is_converted_through_the_same_grid_factor_a_length_is() {
        let grid =
            Grid::new(2_000).expect("2000 database units per micrometre is a legal resolution");
        let mut out = String::new();
        write_measurement(&mut out, grid, Measurement::Length(dbu(4)));
        out.push(' ');
        write_measurement(&mut out, grid, Measurement::Area(DbuArea::new(48)));

        assert!(
            out.contains("2 nm"),
            "4 database units on a 0.5 nm grid is 2 nm:\n{out}"
        );
        assert!(
            out.contains("12 nm^2"),
            "48 dbu^2 on a 0.5 nm grid is 12 nm^2, and a raw 48 would be the \
             text report disagreeing with the JSON one:\n{out}"
        );
    }

    /// Two renderings of one table must not differ.
    #[test]
    fn the_violation_text_renders_identically_twice() {
        let corpus = corpus();
        let mut strings = StrTable::default();
        let rule = strings.intern("m1_min_spacing");
        let mut outputs = Outputs::default();
        push_row!(
            &mut outputs.violations,
            rule,
            corpus.layers.cut,
            (1_400, 2_800),
            90,
            120,
            corpus.expected_net_polys[1][0]
        );

        let mut first = String::new();
        let mut second = String::new();
        write_violations(&outputs, &strings, grid(), &mut first);
        write_violations(&outputs, &strings, grid(), &mut second);
        assert_bytes_identical("the violation text", first.as_bytes(), second.as_bytes());
    }

    /// The error's own message survives rendering, including through a
    /// transparent wrapper, and no backtrace comes with it.
    #[test]
    fn an_error_is_rendered_as_its_own_message_and_nothing_else() {
        let inner = gpurify::engine::pipeline::LoadError::NoGrid;
        let wrapped = gpurify::engine::EngineError::Load(inner.clone());
        for error in [
            &inner as &dyn std::error::Error,
            &wrapped as &dyn std::error::Error,
        ] {
            let expected = error.to_string();
            let mut out = String::new();
            write_error(error, &mut out);
            assert!(
                out.contains(&expected),
                "the rendered error drops its own message {expected:?}:\n{out}"
            );
            for noise in ["stack backtrace", "panicked at", "RUST_BACKTRACE"] {
                assert!(
                    !out.contains(noise),
                    "a user-facing error must not carry {noise:?}:\n{out}"
                );
            }
        }
    }
}
