//! The violation table, and the record of which rules ran.

use crate::measure::Measurement;
use gpurify_core::ops::Point;
use gpurify_core::{LayerId, PolyId};
use gpurify_ingest::StrId;
use gpurify_units::Dbu;

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

/// Every violation from a run, `SoA`.
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
        debug_assert!(self.columns_agree(), "len: {COLUMNS_DIVERGED}");
        self.rule.len()
    }

    pub fn is_empty(&self) -> bool {
        debug_assert!(self.columns_agree(), "is_empty: {COLUMNS_DIVERGED}");
        self.rule.is_empty()
    }

    pub fn push(&mut self, violation: Violation) {
        debug_assert!(self.columns_agree(), "push: {COLUMNS_DIVERGED}");
        // A `NaN` past here compares false against every limit downstream and
        // reads as a clean rule.
        debug_assert!(
            violation.measured.is_finite(),
            "push: {:?} is not a finite measurement",
            violation.measured
        );
        debug_assert!(
            violation.limit.is_finite(),
            "push: {:?} is not a finite limit",
            violation.limit
        );
        let grown = self.rule.len() + 1;

        self.rule.push(violation.rule);
        self.layer.push(violation.layer);
        self.severity.push(violation.severity);
        self.at.push(violation.at);
        self.measured.push(violation.measured);
        self.limit.push(violation.limit);
        self.shape_a.push(violation.shapes.0);
        self.shape_b.push(violation.shapes.1);

        debug_assert!(self.columns_agree(), "push: {COLUMNS_DIVERGED}");
        debug_assert_eq!(self.rule.len(), grown, "push added other than one row");
    }

    /// Append another table's rows.
    pub fn extend(&mut self, other: &Self) {
        debug_assert!(self.columns_agree(), "extend, self: {COLUMNS_DIVERGED}");
        debug_assert!(other.columns_agree(), "extend, other: {COLUMNS_DIVERGED}");
        let grown = self.rule.len() + other.rule.len();

        self.rule.extend_from_slice(&other.rule);
        self.layer.extend_from_slice(&other.layer);
        self.severity.extend_from_slice(&other.severity);
        self.at.extend_from_slice(&other.at);
        self.measured.extend_from_slice(&other.measured);
        self.limit.extend_from_slice(&other.limit);
        self.shape_a.extend_from_slice(&other.shape_a);
        self.shape_b.extend_from_slice(&other.shape_b);

        debug_assert!(self.columns_agree(), "extend: {COLUMNS_DIVERGED}");
        debug_assert_eq!(self.rule.len(), grown, "extend appended the wrong count");
    }

    /// The row at `index`.
    pub fn get(&self, index: usize) -> Violation {
        debug_assert!(self.columns_agree(), "get: {COLUMNS_DIVERGED}");
        debug_assert!(
            index < self.rule.len(),
            "get({index}) on a table of {} rows",
            self.rule.len()
        );
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
    /// `shape_a`, `shape_b`.
    ///
    /// Part of the interface: the key is total, so the order is a function of
    /// the set of rows and not of the input order or the thread count.
    pub fn sort_canonical(&mut self) {
        debug_assert!(self.columns_agree(), "sort_canonical: {COLUMNS_DIVERGED}");
        let rows = self.rule.len();

        // Sort a permutation, then gather each column through it: sorting the
        // columns independently would let them disagree row for row. A table
        // wider than a `u32` fails closed rather than truncating.
        let rows_u32 =
            u32::try_from(rows).expect("a violation table indexes rows with a u32; see CONVENTIONS");
        let mut perm: Vec<u32> = (0..rows_u32).collect();
        // Cached: `sort_unstable_by_key` calls its extractor on every compare.
        perm.sort_by_cached_key(|&row| self.row_key(row as usize));
        debug_assert_eq!(perm.len(), rows, "the permutation lost rows");
        #[cfg(debug_assertions)]
        {
            let mut ascending = true;
            for pair in perm.windows(2) {
                ascending &= self.row_key(pair[0] as usize) <= self.row_key(pair[1] as usize);
            }
            debug_assert!(ascending, "sort_canonical: the permutation is not in key order");
        }

        permute_column(&perm, &mut self.rule);
        permute_column(&perm, &mut self.layer);
        permute_column(&perm, &mut self.severity);
        permute_column(&perm, &mut self.at);
        permute_column(&perm, &mut self.measured);
        permute_column(&perm, &mut self.limit);
        permute_column(&perm, &mut self.shape_a);
        permute_column(&perm, &mut self.shape_b);

        debug_assert!(self.columns_agree(), "sort_canonical: {COLUMNS_DIVERGED}");
        debug_assert_eq!(self.rule.len(), rows, "sort_canonical changed the row count");
    }

    /// The canonical sort key of one row: the six documented fields, then
    /// every remaining field. The six alone are not total — two rows can share
    /// a rule, layer, point and shape with `None` in both second slots — and a
    /// tie left open is where thread count leaks into the output order.
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

    /// Every column holds the same number of rows. A push or sort that touches
    /// seven of the eight leaves a table that still answers
    /// [`Violations::len`] correctly and is wrong everywhere else.
    fn columns_agree(&self) -> bool {
        let rows = self.rule.len();
        self.layer.len() == rows
            && self.severity.len() == rows
            && self.at.len() == rows
            && self.measured.len() == rows
            && self.limit.len() == rows
            && self.shape_a.len() == rows
            && self.shape_b.len() == rows
    }
}

const COLUMNS_DIVERGED: &str = "the violation table's columns hold different row counts";

/// What [`Violations::row_key`] returns.
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

/// A total order over a [`Measurement`]'s *encoding*. Deliberately not an `Ord`
/// impl: comparing a length against a voltage is meaningless as a measurement,
/// and offering it would invite a rule to do it.
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

/// An `f64` as a `u64` that sorts in IEEE-754 total order: the smeared sign bit
/// flips every bit of a negative (reversing its magnitude order) and the sign
/// bit alone of a positive (lifting it above every negative). `NaN` lands at
/// one end rather than comparing false against everything.
fn f64_key(value: f64) -> u64 {
    let bits = value.to_bits();
    let sign_smear = 0u64.wrapping_sub(bits >> 63);
    bits ^ (sign_smear | (1 << 63))
}

/// Rewrite one column as `new[i] = old[perm[i]]`. The bounds check stays:
/// `perm` carries arbitrary `u32`s, so a wrong index must panic rather than
/// read a neighbouring row.
fn permute_column<T: Copy>(perm: &[u32], column: &mut Vec<T>) {
    debug_assert_eq!(perm.len(), column.len(), "{COLUMNS_DIVERGED}");

    // Out of place: cycle-chasing in place makes row N read what row N-1 wrote.
    let mut gathered = Vec::with_capacity(perm.len());
    for &old in perm {
        gathered.push(column[old as usize]);
    }

    debug_assert_eq!(gathered.len(), perm.len(), "the gather lost rows");
    *column = gathered;
}

/// What a rule did, whether or not it found anything. Separate from the
/// violation table because "clean" must mean *this rule executed and found
/// nothing*, which an empty table alone does not say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleRun {
    pub rule: StrId,
    pub outcome: Outcome,
    /// How many shapes the rule examined. Zero with `Outcome::Ran` is
    /// legitimate — an empty layer — and differs from not having run.
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
