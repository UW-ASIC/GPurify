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

/// The text renderer, against answers built before it runs.
///
/// These are unit tests rather than integration tests because the binary has no
/// library target: `mod format` is private to `main.rs` and nothing in
/// `tests/` can name it.
///
/// # Where the ids come from
///
/// `LayerId` and `PolyId` live in `gpurify-core`, which is not a dependency of
/// this crate, so a violation row cannot be written out by hand here. The
/// scale generator supplies real ones — a two-net corpus is the cheapest source
/// of two distinct layers and a handful of polygons, and it is deterministic
/// from its seed, so the rows below are as fixed as literals would have been.
#[cfg(test)]
mod tests {
    use super::{write_error, write_summary, write_violations};
    use gpurify_engine::{Outputs, StageStatus, Summary};
    use gpurify_ingest::StrTable;
    use gpurify_report::{Measurement, Outcome, RuleRun, Severity, SkipReason, Violations};
    use gpurify_testgen::{assert_bytes_identical, dbu, point, scale_corpus, ScaleCorpus, ScaleSpec};
    use gpurify_units::Grid;

    /// Append one row to the violation columns directly.
    ///
    /// A macro rather than a function because `LayerId` and `PolyId` cannot be
    /// named here, so they cannot appear in a signature — the macro passes the
    /// corpus's values straight through to the columns that already have the
    /// types. It also sidesteps `Violations::push`, which is a frozen signature
    /// over a `todo!()` body: a fixture that panicked before the formatter ran
    /// would say nothing about the formatter.
    macro_rules! push_row {
        ($violations:expr, $rule:expr, $layer:expr, $at:expr, $measured:expr, $limit:expr, $shape:expr) => {{
            let violations: &mut Violations = $violations;
            let (x, y): (i64, i64) = $at;
            violations.rule.push($rule);
            violations.layer.push($layer);
            violations.severity.push(Severity::Error);
            violations.at.push(point(x, y));
            violations.measured.push(Measurement::Length(dbu($measured)));
            violations.limit.push(Measurement::Length(dbu($limit)));
            violations.shape_a.push($shape);
            violations.shape_b.push(None);
        }};
    }

    /// One database unit is one nanometre at this resolution, so a coordinate
    /// prints with the same digits whether the formatter renders the raw unit
    /// or converts to nanometres as `Measurement`'s docs say it does. That is
    /// what lets these tests assert on a coordinate without fixing a rendering
    /// convention the frozen signatures never stated.
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

    /// Counts that are consistent with each other and share no digit run, so
    /// finding one in the rendered text is evidence for that count rather than
    /// an accidental match against another.
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

    /// Oracle: construct-from-answer. The ordering is the whole point of this
    /// function's doc comment, and it is checkable without fixing any wording:
    /// whichever line mentions skipping must come before whichever line
    /// mentions the violation count. A summary that leads with a count and
    /// footnotes the skips passes every count assertion and still misleads.
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

    /// Oracle: construct-from-answer. Every count handed in is a count that
    /// must appear. The five values are chosen so none is a digit substring of
    /// another, which is what makes a `contains` check evidence.
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

    /// Oracle: construct-from-answer. A skipped stage carries the reason it
    /// was skipped, and that reason is the only thing that tells a reader
    /// whether the missing input was theirs to supply. Losing it turns a
    /// diagnosis into a shrug.
    #[test]
    fn a_skipped_stage_is_reported_with_the_reason_it_carries() {
        let mut out = String::new();
        write_summary(&summary_with_skips(), &mut out);
        assert!(
            out.contains("no reference netlist was supplied"),
            "the summary drops the skip reason:\n{out}"
        );
    }

    /// Oracle: determinism. The summary is compared between two runs by the
    /// determinism gate, so it must be a function of its input alone.
    #[test]
    fn the_summary_renders_identically_twice() {
        let summary = summary_with_skips();
        let mut first = String::new();
        let mut second = String::new();
        write_summary(&summary, &mut first);
        write_summary(&summary, &mut second);
        assert_bytes_identical("the run summary", first.as_bytes(), second.as_bytes());
    }

    /// Oracle: construct-from-answer. The table is built already in the
    /// canonical order `Violations::sort_canonical` defines — rule id first —
    /// so the order the two rules must appear in is known before the formatter
    /// runs. Built by hand rather than sorted, so the assertion is about this
    /// function and not about the sort.
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

    /// Oracle: construct-from-answer. Every row's coordinate and measurement
    /// were chosen before the run, and all four rows must survive to the text:
    /// a formatter that collapses rows sharing a rule reports fewer violations
    /// than were found, which is the count-only failure moved one stage later.
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

    /// Oracle: construct-from-answer. The assertion the rest of the workspace
    /// is built around, at the last stage where it can be lost. `RuleRun`'s own
    /// doc states the claim: an empty violation table is produced both by a
    /// rule that ran and found nothing and by a rule that never ran, so "clean"
    /// is only interpretable beside the record of what executed. `write_summary`
    /// is handed counts and no rule identities, which leaves this function as
    /// the only place a clean run can name them — and is why the frozen
    /// signature takes `&Outputs` rather than `&Violations`. `Format::Text`
    /// says the same thing from the other side: "grouped by rule, counts first,
    /// skipped rules called out".
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

    /// Oracle: determinism. The violation text is what a human diffs between
    /// two logs, so two renderings of one table must not differ.
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

    /// Oracle: construct-from-answer. The error's own message is the answer,
    /// and it must survive being rendered — including through a wrapper, where
    /// `#[error(transparent)]` means the inner message is the whole message.
    /// The second half is the documented refusal to print a backtrace: a deck
    /// with a missing grid is a user error and a stack trace says nothing
    /// about it.
    #[test]
    fn an_error_is_rendered_as_its_own_message_and_nothing_else() {
        let inner = gpurify_engine::pipeline::LoadError::NoGrid;
        let wrapped = gpurify_engine::EngineError::Load(inner.clone());
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
