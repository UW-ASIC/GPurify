//! Design rule checking: one table per rule kind, one transform per table.
//!
//! A rule that cannot run says so — [`Outcome::Skipped`] when a required input
//! is absent, [`Outcome::Refused`] when the geometry is outside what this tool
//! represents exactly. Neither is ever collapsed into a clean result, and an
//! empty [`Violations`] alone cannot tell a clean design from a rule that never
//! ran; `record_run` is the one place the two are separated.

pub mod rules;
pub mod ruleset;

pub use ruleset::RuleSet;

use gpurify_core::connectivity::ComponentLabel;
use gpurify_core::index::SpatialIndex;
use gpurify_core::rects::Rect;
use gpurify_core::{GeometryStore, PolyId, ValidatedLayer};
use gpurify_derived::Evaluator;
use gpurify_ingest::StrId;
use gpurify_report::{Outcome, RuleRun, Violations};
use gpurify_topology::{DeviceTable, NetTable};
use gpurify_units::DbuArea;

/// Why a deck could not be turned into a [`RuleSet`].
///
/// Construction-time only: a rule that meets geometry it cannot handle records
/// [`Outcome::Refused`] against itself and the run continues, because one
/// unrepresentable polygon must not suppress every other rule's verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DrcError {
    /// The deck names a rule kind this crate does not implement.
    ///
    /// Fail closed: skipping it would leave a deck that looks fully checked and
    /// is not.
    #[error("rule {rule}: unknown rule kind {kind}")]
    UnknownKind { rule: String, kind: String },
    #[error("rule {rule}: missing required parameter {param}")]
    MissingParam { rule: String, param: &'static str },
    #[error("rule {rule}: parameter {param} is not the kind of value this rule takes")]
    WrongParamType { rule: String, param: &'static str },
    #[error("rule {rule}: takes {expected} layers, the deck names {found}")]
    WrongLayerCount {
        rule: String,
        expected: u32,
        found: u32,
    },
    /// A limit that is zero or negative — a `0` spacing limit passes everything
    /// silently.
    #[error("rule {rule}: limit {limit} is not positive")]
    NonPositiveLimit { rule: String, limit: i64 },
    /// An angle no integer edge vector expresses exactly; only multiples of 45
    /// degrees do.
    #[error("rule {rule}: {degrees} degrees is not exactly representable")]
    UnrepresentableAngle { rule: String, degrees: i32 },
    /// The deck defines the same rule id twice; two [`RuleRun`] rows sharing an
    /// id are attributable to nothing.
    #[error("duplicate rule id {0}")]
    DuplicateRule(String),
}

/// Everything a rule reads, borrowed for the length of one run.
///
/// `nets` and `devices` are deliberately not `Option`: an absent topology and
/// an empty one are indistinguishable once inside a rule, and reading "no nets
/// extracted" as "nothing to report" is fail-open.
#[derive(Debug, Clone, Copy)]
pub struct Design<'a> {
    pub store: &'a GeometryStore,
    /// Pre-evaluated named derived layers.
    pub derived: &'a Evaluator,
    pub nets: &'a NetTable,
    pub devices: &'a DeviceTable,
}

/// The buffer set every rule transform borrows and refills.
///
/// ponytail: one scratch means rules run sequentially — one `&mut Scratch` is
/// one exclusive borrow, so the dispatcher hands it to one transform at a time.
/// Splitting it into worker slots is private, but a parallel dispatcher needs a
/// worker count and there is no route for one to arrive: [`RuleSet::run`] takes
/// no thread budget and `gpurify_engine::run::run_drc` does not receive
/// `&RunOptions`, so `RunOptions::threads` cannot reach this crate. Filed in
/// `docs/SIGNATURE_DEFECTS.md` under "drc, from the `ponytail:` spend-down
/// pass".
#[derive(Debug, Default)]
pub struct Scratch {
    /// Validated geometry of the rule's primary layer.
    layer_a: ValidatedLayer,
    /// The second operand, for two-layer rules. Never aliases `layer_a`.
    layer_b: ValidatedLayer,
    /// Boolean result — a merged layer, an intersection, an enclosure region.
    layer_out: ValidatedLayer,
    index_a: SpatialIndex,
    index_b: SpatialIndex,
    /// Candidate pairs from the proximity prune — a superset, still checked
    /// exactly.
    pairs: Vec<(PolyId, PolyId)>,
    /// Rectilinear decomposition of `layer_a`, CSR by polygon: polygon `i`'s
    /// rectangles are `rects[rect_start[i] .. rect_start[i + 1]]`.
    rects: Vec<Rect>,
    rect_start: Vec<u32>,
    /// Edge list for the rules that group shapes before measuring them.
    edges: Vec<(u32, u32)>,
    labels: Vec<ComponentLabel>,
    /// Per-group area accumulator.
    areas: Vec<DbuArea>,
    /// Per-node scratch for the colouring search.
    colors: Vec<u8>,
}

impl Scratch {
    /// Drop every buffer's capacity.
    pub fn shrink(&mut self) {
        // Reassignment rather than per-field `shrink_to_fit`: `ValidatedLayer`
        // and `SpatialIndex` own their columns privately and expose no way to
        // release them.
        *self = Self::default();
    }
}

/// Close out one rule row: append its [`RuleRun`], with the violation count
/// derived rather than counted by the caller.
///
/// `violations_before` is `out.len()` read before the row's work started, so a
/// rule cannot report a violation it did not push or push one it did not
/// report.
pub(crate) fn record_run(
    runs: &mut Vec<RuleRun>,
    out: &Violations,
    violations_before: usize,
    rule: StrId,
    outcome: Outcome,
    examined: u64,
) {
    let after = out.len();
    debug_assert!(
        violations_before <= after,
        "a rule row started at {violations_before} of a table that now holds {after}: \
         the shared violation table was truncated under a running rule"
    );
    let pushed = after - violations_before;
    debug_assert!(
        u32::try_from(pushed).is_ok(),
        "{pushed} violations from one rule row overflow the run's count column"
    );

    let before_rows = runs.len();
    runs.push(RuleRun {
        rule,
        outcome,
        examined,
        // Saturating rather than wrapping: past 4 billion violations from one
        // rule the exact count is noise, but wrapping it to a small number
        // would read as a nearly-clean rule, which is fail-open.
        violations: u32::try_from(pushed).unwrap_or(u32::MAX),
    });
    debug_assert_eq!(
        runs.len(),
        before_rows + 1,
        "one rule row produces exactly one run row"
    );
}

/// Adapter tests for the one seam every rule row crosses; `record_run` is
/// `pub(crate)`, so these cannot live in `tests/`.
#[cfg(test)]
mod tests {
    use super::record_run;
    use gpurify_core::ops::Point;
    use gpurify_core::{LayerId, PolyId};
    use gpurify_ingest::StrId;
    use gpurify_report::{Measurement, Outcome, RuleRun, Severity, SkipReason, Violations};
    use gpurify_units::Dbu;

    /// Push `count` placeholder rows onto a violation table.
    fn fill(out: &mut Violations, count: usize) {
        for _ in 0..count {
            out.rule.push(StrId(9));
            out.layer.push(LayerId(0));
            out.severity.push(Severity::Error);
            out.at.push(Point {
                x: Dbu::new_unchecked(0),
                y: Dbu::new_unchecked(0),
            });
            out.measured.push(Measurement::Count(0));
            out.limit.push(Measurement::Count(1));
            out.shape_a.push(PolyId(0));
            out.shape_b.push(None);
        }
    }

    #[test]
    fn the_recorded_violation_count_is_what_the_row_actually_pushed() {
        let mut out = Violations::default();
        fill(&mut out, 5);

        let mut runs = Vec::new();
        record_run(&mut runs, &out, 2, StrId(4), Outcome::Ran, 77);

        assert_eq!(
            runs,
            vec![RuleRun {
                rule: StrId(4),
                outcome: Outcome::Ran,
                examined: 77,
                violations: 3,
            }]
        );
    }

    #[test]
    fn a_row_that_pushed_nothing_reports_zero_however_full_the_shared_table_is() {
        let mut out = Violations::default();
        fill(&mut out, 40);

        let mut runs = Vec::new();
        record_run(&mut runs, &out, 40, StrId(1), Outcome::Ran, 0);

        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].violations, 0);
        assert_eq!(runs[0].examined, 0);
    }

    #[test]
    fn every_outcome_appends_exactly_one_row_and_none_replaces_another() {
        let out = Violations::default();
        let mut runs = Vec::new();

        record_run(&mut runs, &out, 0, StrId(0), Outcome::Ran, 12);
        record_run(&mut runs, &out, 0, StrId(1), Outcome::Refused, 12);
        record_run(
            &mut runs,
            &out,
            0,
            StrId(2),
            Outcome::Skipped(SkipReason::EmptyLayer),
            0,
        );

        assert_eq!(runs.len(), 3);
        assert_eq!(
            runs.iter().map(|r| r.rule).collect::<Vec<_>>(),
            vec![StrId(0), StrId(1), StrId(2)],
            "rows are appended in call order, which is what makes a run reproducible"
        );
        assert_eq!(runs[1].outcome, Outcome::Refused);
        assert_eq!(runs[2].outcome, Outcome::Skipped(SkipReason::EmptyLayer));
        assert!(runs.iter().all(|r| r.violations == 0));
    }
}
