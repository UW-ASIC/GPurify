//! The violation table, and the record of which rules ran.

use crate::report::measure::Measurement;
use gpurify_geom::ops::Point;
use gpurify_geom::Dbu;
use gpurify_geom::{LayerId, PolyId};
use gpurify_ingest::StrId;

/// How bad a finding is. Ordered, `Warning < Error`, so the `max` over a run
/// is its worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// A finding that does not fail the run: a violation of an ERC row the
    /// deck marks `warning`. DRC and LVS never report one.
    Warning,
    /// A finding that fails the run.
    Error,
}

/// One violation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Violation {
    /// The deck's id for the rule, or the LVS report id (`lvs.*`), interned.
    pub rule: StrId,
    /// The layer the finding is reported on; each DRC
    /// [`Rule`](crate::drc::Rule) variant says which of its layers.
    /// `LayerId(u16::MAX)` for an LVS finding, which has none.
    pub layer: LayerId,
    /// Whether the finding fails the run.
    pub severity: Severity,
    /// Where to look, in grid units. Each rule kind picks its own point (each
    /// DRC [`Rule`](crate::drc::Rule) variant says which): a pair's point is
    /// the middle of the gap between the two shapes' bounding boxes and need
    /// not lie on either shape. An LVS finding has no place and reports the
    /// origin.
    pub at: Point,
    /// What the rule measured; the same variant as `limit`.
    pub measured: Measurement,
    /// The limit `measured` was held to: for a table rule, the cell that
    /// applied.
    pub limit: Measurement,
    /// The store rows the finding names: the offending shape, and the other
    /// shape of a pair (spacing, enclosure host, extension reference). The
    /// first is `PolyId(u32::MAX)` when no shape can be named: an edge-layer
    /// finding, an LVS finding, a density window on an empty layer.
    pub shapes: (PolyId, Option<PolyId>),
}

/// Every violation from a run, `SoA`; all columns hold the same row count, and
/// row `i` of each column is a field of [`Violations::get`]`(i)`.
#[derive(Debug, Default)]
pub struct Violations {
    /// [`Violation::rule`] per row.
    pub rule: Vec<StrId>,
    /// [`Violation::layer`] per row.
    pub layer: Vec<LayerId>,
    /// [`Violation::severity`] per row.
    pub severity: Vec<Severity>,
    /// [`Violation::at`] per row.
    pub at: Vec<Point>,
    /// [`Violation::measured`] per row.
    pub measured: Vec<Measurement>,
    /// [`Violation::limit`] per row.
    pub limit: Vec<Measurement>,
    /// The first of [`Violation::shapes`] per row.
    pub shape_a: Vec<PolyId>,
    /// The second of [`Violation::shapes`] per row.
    pub shape_b: Vec<Option<PolyId>>,
}

impl Violations {
    /// The row count, read from the `rule` column; a table whose columns
    /// differ in length was edited by hand and breaks every other method.
    pub fn len(&self) -> usize {
        self.rule.len()
    }

    /// Whether the table has no rows. Alone it does not mean the design is
    /// clean: a rule that did not run also adds no row (see [`RuleRun`]).
    pub fn is_empty(&self) -> bool {
        self.rule.is_empty()
    }

    /// Appends one row.
    ///
    /// # Panics
    ///
    /// In a debug build, when `measured` or `limit` is not finite: a `NaN`
    /// compares false against every limit and would read as clean.
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

    /// Appends another table's rows after this one's, in their order. The
    /// result is not in canonical order even when both inputs were.
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

    /// The row at `index`, gathered from every column.
    ///
    /// # Panics
    ///
    /// When `index` is not below [`Self::len`].
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

    /// Establishes the canonical order: rule id, layer, `at.y`, `at.x`,
    /// `shape_a`, `shape_b`, then every remaining field. The key is total, so
    /// the order depends only on the set of rows, not on input or thread count.
    /// Rule ids compare as interned ids, not as text, so the order also
    /// depends on the string table the ids came from.
    ///
    /// Takes *O*(*n* log *n*) time and rebuilds every column.
    ///
    /// # Panics
    ///
    /// When the table holds more than `u32::MAX` rows.
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
    /// The deck's id for the rule, or the LVS report id, interned.
    pub rule: StrId,
    /// Whether the rule ran; anything but [`Outcome::Ran`] fails the run.
    pub outcome: Outcome,
    /// How many items the rule examined. What an item is depends on the kind:
    /// polygons, merged figures, pairs, edges, vertices, windows or wells, as
    /// each DRC [`Rule`](crate::drc::Rule) variant states. Zero with
    /// `Outcome::Ran` means there was nothing to measure (an empty layer, no
    /// pair within reach), not "did not run".
    pub examined: u64,
    /// How many rows this rule added to the violation table, saturating at
    /// `u32::MAX`.
    pub violations: u32,
}

/// Why a rule produced the result it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Executed to completion.
    Ran,
    /// A required input was absent. Never collapsed into a clean result: a run
    /// with any rule skipped does not pass.
    Skipped(SkipReason),
    /// The input was outside what the tool represents exactly. Fail closed.
    Refused,
}

/// Why a rule was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The rule needs design intent and none was supplied.
    NoDesignIntent,
    /// The deck carries no limits for this check (the LVS device-count and
    /// parametric rows).
    NotInDeck,
    /// A layer the rule needs holds no geometry, so there is nothing to
    /// measure against: for DRC, a density rule's die, a tap-distance rule's
    /// wells, or a multi-patterning layer.
    EmptyLayer,
}

/// Close out one rule row: append its [`RuleRun`] with the violation count
/// derived as `out.len() - violations_before` (saturating at `u32::MAX`).
pub(crate) fn record_run(
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
