//! The violation table, and the record of which rules ran.

use crate::measure::Measurement;
use gpurify_core::ops::Point;
use gpurify_core::{LayerId, PolyId};
use gpurify_ingest::StrId;

/// How bad a finding is.
///
/// `Warning` exists so a rule can report something it is unsure about without
/// either failing the run or staying silent. It is never used to downgrade a
/// genuine violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Warning,
    Error,
}

/// One violation.
///
/// Written as a struct for readability at push sites; stored column-wise in
/// [`Violations`]. Every field here is something a physics test asserts on,
/// which is the reason each one exists.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Violation {
    /// The deck's id for the rule, interned. What a human greps for.
    pub rule: StrId,
    pub layer: LayerId,
    pub severity: Severity,
    /// Where. For a spacing violation, a point on the gap; for an area
    /// violation, a point inside the shape. Always inside or on the geometry
    /// the marker names, so a viewer can navigate to it.
    pub at: Point,
    pub measured: Measurement,
    pub limit: Measurement,
    /// The shapes involved. One for a width or area rule, two for spacing.
    /// `None` in the second slot rather than a repeat of the first.
    pub shapes: (PolyId, Option<PolyId>),
}

/// Every violation from a run, `SoA`.
///
/// **Five questions.** In: pushes from rules. Out: a canonically ordered table.
/// How many: zero on a clean run, tens of thousands on a bad one — so it is
/// pre-reserved but not per-rule. Access pattern: written once, sorted once,
/// then scanned in order by the writers and by every test assertion. Lifetime:
/// whole run. Parallelisable: rules producing into per-rule tables that are
/// concatenated is the gatherer pattern, and the concatenation order does not
/// matter because of the canonical sort.
#[derive(Debug, Default)]
pub struct Violations {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    pub severity: Vec<Severity>,
    pub at: Vec<Point>,
    pub measured: Vec<Measurement>,
    pub limit: Vec<Measurement>,
    pub shape_a: Vec<PolyId>,
    pub shape_b: Vec<Option<PolyId>>,
}

impl Violations {
    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        todo!()
    }

    pub fn push(&mut self, violation: Violation) {
        todo!()
    }

    /// Append another table's rows. The gatherer step after parallel rules.
    pub fn extend(&mut self, other: &Self) {
        todo!()
    }

    pub fn get(&self, index: usize) -> Violation {
        todo!()
    }

    /// Establish the canonical order.
    ///
    /// **Part of the interface, not an implementation detail.** Every consumer
    /// — writers, tests, the determinism gate — relies on it, so it is stated
    /// here: sort by rule id, then layer, then `at.y`, then `at.x`, then
    /// `shape_a`, then `shape_b`. That tuple is total over any set of rows this
    /// tool can produce, so the order does not depend on the input order and
    /// therefore does not depend on thread count.
    ///
    /// A stable sort would be enough given a total key, but the key is total
    /// precisely so stability is not load-bearing.
    pub fn sort_canonical(&mut self) {
        todo!()
    }
}

/// What a rule did, whether or not it found anything.
///
/// This is the answer to the failure the old suite had: half its DRC cases
/// asserted only that nothing was found, so a rule that never ran passed all of
/// them. "Clean" has to mean *this rule executed, examined N shapes, and found
/// nothing* — and that claim needs a record separate from the violation table,
/// because an empty table is exactly what both cases produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleRun {
    pub rule: StrId,
    pub outcome: Outcome,
    /// How many shapes the rule actually examined. Zero with `Outcome::Ran` is
    /// legitimate — an empty layer — but it is a different claim from not
    /// having run, and a test can tell them apart.
    pub examined: u64,
    pub violations: u32,
}

/// Why a rule produced the result it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Executed to completion.
    Ran,
    /// Did not run because a required input was absent — most often a design
    /// intent file for an ERC rule that needs one. Reported loudly; never
    /// collapsed into a clean result.
    Skipped(SkipReason),
    /// Refused because the input was outside what the tool represents
    /// exactly — non-rectilinear geometry, an off-grid limit. Fail closed.
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The rule needs design intent and none was supplied.
    NoDesignIntent,
    /// The deck does not configure this rule.
    NotInDeck,
    /// The layer the rule names holds no geometry.
    EmptyLayer,
}
