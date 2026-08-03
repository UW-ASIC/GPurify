//! Design rule checking: one table per rule kind, one transform per table.
//!
//! # What replaced the trait object
//!
//! The old tree held rules as `Box<dyn Rule>` in a `Vec`, each carrying a
//! `String` id and `i32` limits, and ran them by virtual call. That shape cost
//! three things at once: a vtable jump per rule, a heap string compared per
//! violation pushed, and a coordinate type too narrow for the domain.
//!
//! What is here instead is the dispatcher pattern from `docs/CONVENTIONS.md`
//! §2. Every rule kind owns a `SoA` table of its own parameters, and every
//! table has exactly one uniform transform over its rows. A run is one call per
//! non-empty table — [`RuleSet::run`] — so the branch on rule kind happens once
//! per *kind*, at deck-load time, rather than once per shape.
//!
//! There is no `dyn` anywhere in this crate and no `match` on a rule kind
//! inside any loop. Adding a rule kind means adding a table, a transform and a
//! line in the dispatcher, and the compiler names all three.
//!
//! # Clean is a claim, not a silence
//!
//! Every rule row emits a [`RuleRun`] saying it executed and how many things it
//! looked at. An empty [`Violations`] is what a rule that never ran produces
//! *and* what a clean design produces, so the violation table alone cannot tell
//! them apart — half the old DRC suite passed for exactly that reason. See
//! `record_run`, which is the one place the two are separated.
//!
//! A rule that cannot run says so: [`Outcome::Skipped`] when a required input
//! is absent, [`Outcome::Refused`] when the geometry is outside what this tool
//! represents exactly. Neither is ever collapsed into a clean result.

// Definition-Phase; see CLAUDE.md
#![allow(unused_variables, dead_code)]

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
/// Construction-time only. Nothing here is returned from a check: a rule that
/// meets geometry it cannot handle records [`Outcome::Refused`] against itself
/// and the run continues, because one unrepresentable polygon on one layer must
/// not suppress every other rule's verdict.
///
/// Stringly on purpose — these are read once, by a human, out of a deck that is
/// already wrong. The hot structures below carry [`StrId`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DrcError {
    /// The deck names a rule kind this crate does not implement.
    ///
    /// Fail closed. Skipping the rule would leave a deck that looks fully
    /// checked and is not, which is the exact failure this project is built
    /// against.
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
    /// A limit that is zero or negative. Every limit in this crate is a
    /// distance, an area or a count, and none of them has a meaningful
    /// non-positive value — a `0` spacing limit passes everything silently.
    #[error("rule {rule}: limit {limit} is not positive")]
    NonPositiveLimit { rule: String, limit: i64 },
    /// An angle no integer edge vector expresses exactly. Only multiples of 45
    /// degrees do — see [`rules::grid::Direction`].
    #[error("rule {rule}: {degrees} degrees is not exactly representable")]
    UnrepresentableAngle { rule: String, degrees: i32 },
    /// The deck defines the same rule id twice. Two [`RuleRun`] rows sharing an
    /// id are attributable to nothing.
    #[error("duplicate rule id {0}")]
    DuplicateRule(String),
}

/// Everything a rule reads, borrowed for the length of one run.
///
/// A bundle of shared references, `Copy` and with public fields, so all data
/// flow is still visible in every signature that takes one — this is not a
/// context object hiding state, it is four `&` that would otherwise be four
/// parameters on twenty-six functions.
///
/// `nets` and `devices` are here even though only the antenna family reads
/// them, and they are **not** `Option`. An absent topology and an empty one are
/// indistinguishable once inside the rule, and "no nets extracted" reported as
/// "no antenna violations" is fail-open. The engine extracts topology before
/// DRC regardless, because `lvs` and `erc` need it too.
#[derive(Debug, Clone, Copy)]
pub struct Design<'a> {
    pub store: &'a GeometryStore,
    /// Pre-evaluated named derived layers. A rule whose deck layer is derived
    /// looks it up here rather than recomputing the boolean per rule.
    pub derived: &'a Evaluator,
    pub nets: &'a NetTable,
    pub devices: &'a DeviceTable,
}

/// The buffer set every rule transform borrows and refills.
///
/// **Five questions.** In: nothing — it is storage. Out: nothing that outlives
/// a rule. How many: exactly one per run, threaded through all twenty-six
/// transforms. Access pattern: each transform clears the buffers it wants and
/// fills them; no transform reads what another left behind. Lifetime: phase —
/// this is the allocation that would otherwise be twenty-six independent
/// spatial indexes and pair lists per run. Parallelisable: no, and that is the
/// stated cost of one shared scratch — see the ponytail note below.
///
/// The fields are private. They are storage, not interface: which buffers exist
/// is an implementation question the Implementation-Phase gets to answer
/// without touching a frozen signature. Rules reach them directly because they
/// are descendants of this module.
///
/// ponytail: one scratch means rules run sequentially. That is right at this
/// scale — a real deck's twenty-six tables are dominated by two or three
/// spacing rules, so per-rule parallelism buys little next to parallelism
/// *inside* a rule. Upgrade to one `Scratch` per worker plus the gatherer merge
/// `Violations::extend` already provides, if a profile on the scale corpus says
/// otherwise. No signature changes.
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
    /// Candidate pairs from the proximity prune. A superset; every pair here is
    /// still checked exactly.
    pairs: Vec<(PolyId, PolyId)>,
    /// Rectilinear decomposition of `layer_a`, CSR by polygon: polygon `i`'s
    /// rectangles are `rects[rect_start[i] .. rect_start[i + 1]]`.
    rects: Vec<Rect>,
    rect_start: Vec<u32>,
    /// Edge list for the rules that group shapes before measuring them —
    /// merged figures, via arrays, multi-patterning conflicts, per-stage
    /// antenna connectivity.
    edges: Vec<(u32, u32)>,
    labels: Vec<ComponentLabel>,
    /// Per-group area accumulator: antenna collecting area, merged-figure area,
    /// windowed density numerator.
    areas: Vec<DbuArea>,
    /// Per-node scratch for the colouring search.
    colors: Vec<u8>,
}

impl Scratch {
    /// Drop every buffer's capacity.
    ///
    /// The only reason this exists is a long-lived process running many decks:
    /// the scratch grows to the largest layer it ever saw and never shrinks,
    /// which is exactly what a single run wants and exactly what a server does
    /// not.
    pub fn shrink(&mut self) {
        todo!()
    }
}

/// Close out one rule row: append its [`RuleRun`], with the violation count
/// derived rather than counted by the caller.
///
/// **Decision, and the invariant lives here.** Every one of the twenty-six
/// transforms ends each row through this function, so "a rule row always
/// produces exactly one run row, and its `violations` always equals what that
/// row actually pushed" is one line of code rather than twenty-six chances to
/// forget.
///
/// `violations_before` is `out.len()` read before the row's work started. That
/// is what makes the count derived: a rule cannot report a violation it did not
/// push, or push one it did not report.
pub(crate) fn record_run(
    runs: &mut Vec<RuleRun>,
    out: &Violations,
    violations_before: usize,
    rule: StrId,
    outcome: Outcome,
    examined: u64,
) {
    todo!()
}

/// Adapter tests for the one seam every rule row crosses.
///
/// `record_run` is `pub(crate)`, so these cannot live in `tests/`. That is the
/// deliberate trade recorded in `crates/core/src/observe.rs`: the invariant is
/// worth stating in one private function rather than widening the crate's
/// interface so a test can reach it.
#[cfg(test)]
mod tests {
    use super::record_run;
    use gpurify_core::ops::Point;
    use gpurify_core::{LayerId, PolyId};
    use gpurify_ingest::StrId;
    use gpurify_report::{Measurement, Outcome, RuleRun, Severity, SkipReason, Violations};
    use gpurify_units::Dbu;

    /// Push `count` placeholder rows onto a violation table.
    ///
    /// Column by column rather than through `Violations::push`, which is a
    /// frozen signature with a `todo!()` body: an arrangement helper that panics
    /// before the function under test runs would test nothing.
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

    /// Oracle: construct-from-answer. The count is *derived* from the table, so
    /// stating a table of five rows and a mark of two fixes the answer at three
    /// before the call. A transform cannot report a violation it did not push,
    /// or push one it did not report, and this is the one place that holds.
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

    /// Oracle: construct-from-answer. A rule that pushed nothing has a count of
    /// zero even though the shared table is far from empty — the mark is where
    /// *this* row started, not where the table did. Getting this wrong would
    /// credit every rule with every earlier rule's findings.
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

    /// Oracle: construct-from-answer. Exactly one run row per call, appended,
    /// whatever the outcome — a `Skipped` or `Refused` row is as much a record
    /// as a `Ran` one, and omitting it is how a rule that did not execute comes
    /// to look like a rule that found nothing.
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
