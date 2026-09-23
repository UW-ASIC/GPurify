//! The violation table, and the record of which rules ran.

use crate::report::measure::Measurement;
use gpurify_geom::ops::Point;
use gpurify_geom::Dbu;
use gpurify_geom::{LayerId, PolyId};
use gpurify_ingest::StrId;

/// How bad a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Something a rule is unsure about. Never used to downgrade a genuine
    /// violation.
    Warning,
    Error,
}

/// One violation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Violation {
    /// The deck's id for the rule, interned.
    pub rule: StrId,
    pub layer: LayerId,
    pub severity: Severity,
    /// Where. Always inside or on the geometry the marker names.
    pub at: Point,
    pub measured: Measurement,
    pub limit: Measurement,
    /// One shape for a width or area rule, two for spacing.
    pub shapes: (PolyId, Option<PolyId>),
}

/// Every violation from a run, `SoA`; all columns hold the same row count.
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
        self.rule.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rule.is_empty()
    }

    pub fn push(&mut self, violation: Violation) {
        // A `NaN` compares false against every limit and reads as clean.
        debug_assert!(violation.measured.is_finite(), "{violation:?}");
        debug_assert!(violation.limit.is_finite(), "{violation:?}");
        self.rule.push(violation.rule);
        self.layer.push(violation.layer);
        self.severity.push(violation.severity);
        self.at.push(violation.at);
        self.measured.push(violation.measured);
        self.limit.push(violation.limit);
        self.shape_a.push(violation.shapes.0);
        self.shape_b.push(violation.shapes.1);
    }

    /// Append another table's rows.
    pub fn extend(&mut self, other: &Self) {
        self.rule.extend_from_slice(&other.rule);
        self.layer.extend_from_slice(&other.layer);
        self.severity.extend_from_slice(&other.severity);
        self.at.extend_from_slice(&other.at);
        self.measured.extend_from_slice(&other.measured);
        self.limit.extend_from_slice(&other.limit);
        self.shape_a.extend_from_slice(&other.shape_a);
        self.shape_b.extend_from_slice(&other.shape_b);
    }

    /// The row at `index`.
    pub fn get(&self, index: usize) -> Violation {
        Violation {
            rule: self.rule[index],
            layer: self.layer[index],
            severity: self.severity[index],
            at: self.at[index],
            measured: self.measured[index],
            limit: self.limit[index],
            shapes: (self.shape_a[index], self.shape_b[index]),
        }
    }

    /// Establish the canonical order: rule id, layer, `at.y`, `at.x`,
    /// `shape_a`, `shape_b`, then every remaining field. The key is total, so
    /// the order depends only on the set of rows, not on input or thread count.
    pub fn sort_canonical(&mut self) {
        let rows =
            u32::try_from(self.rule.len()).expect("a violation table indexes rows with a u32");
        let mut perm: Vec<u32> = (0..rows).collect();
        perm.sort_by_cached_key(|&row| self.row_key(row as usize));

        permute_column(&perm, &mut self.rule);
        permute_column(&perm, &mut self.layer);
        permute_column(&perm, &mut self.severity);
        permute_column(&perm, &mut self.at);
        permute_column(&perm, &mut self.measured);
        permute_column(&perm, &mut self.limit);
        permute_column(&perm, &mut self.shape_a);
        permute_column(&perm, &mut self.shape_b);
    }

    fn row_key(&self, row: usize) -> RowKey {
        (
            self.rule[row],
            self.layer[row],
            self.at[row].y,
            self.at[row].x,
            self.shape_a[row],
            self.shape_b[row],
            self.severity[row],
            measurement_key(self.measured[row]),
            measurement_key(self.limit[row]),
        )
    }
}

type RowKey = (
    StrId,
    LayerId,
    Dbu,
    Dbu,
    PolyId,
    Option<PolyId>,
    Severity,
    (u8, i128, u64),
    (u8, i128, u64),
);

/// A total order over a [`Measurement`]'s encoding (deliberately not `Ord`:
/// a length against a voltage is meaningless).
fn measurement_key(measurement: Measurement) -> (u8, i128, u64) {
    match measurement {
        Measurement::Length(value) => (0, i128::from(value.raw()), 0),
        Measurement::Area(value) => (1, value.raw(), 0),
        Measurement::Ratio(value) => (2, 0, f64_key(value)),
        Measurement::Count(value) => (3, i128::from(value), 0),
        Measurement::Voltage(value) => (4, 0, f64_key(value.raw())),
        Measurement::Current(value) => (5, 0, f64_key(value.raw())),
        Measurement::Resistance(value) => (6, 0, f64_key(value.raw())),
    }
}

/// An `f64` as a `u64` that sorts in IEEE-754 total order.
fn f64_key(value: f64) -> u64 {
    let bits = value.to_bits();
    let sign_smear = 0u64.wrapping_sub(bits >> 63);
    bits ^ (sign_smear | (1 << 63))
}

/// Rewrite one column as `new[i] = old[perm[i]]`.
fn permute_column<T: Copy>(perm: &[u32], column: &mut Vec<T>) {
    *column = perm.iter().map(|&old| column[old as usize]).collect();
}

/// What a rule did, whether or not it found anything: "clean" means this rule
/// executed and found nothing, which an empty table alone does not say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleRun {
    pub rule: StrId,
    pub outcome: Outcome,
    /// How many shapes the rule examined. Zero with `Outcome::Ran` means an
    /// empty layer, not "did not run".
    pub examined: u64,
    pub violations: u32,
}

/// Why a rule produced the result it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Executed to completion.
    Ran,
    /// A required input was absent. Never collapsed into a clean result.
    Skipped(SkipReason),
    /// The input was outside what the tool represents exactly. Fail closed.
    Refused,
}

/// Why a rule was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The rule needs design intent and none was supplied.
    NoDesignIntent,
    /// The deck does not configure this rule.
    NotInDeck,
    /// The layer the rule names holds no geometry.
    EmptyLayer,
}

/// Close out one rule row: append its [`RuleRun`] with the violation count
/// derived as `out.len() - violations_before` (saturating at `u32::MAX`).
pub fn record_run(
    runs: &mut Vec<RuleRun>,
    out: &Violations,
    violations_before: usize,
    rule: StrId,
    outcome: Outcome,
    examined: u64,
) {
    let pushed = out.len() - violations_before;
    runs.push(RuleRun {
        rule,
        outcome,
        examined,
        violations: u32::try_from(pushed).unwrap_or(u32::MAX),
    });
}
