//! The violation table, and the record of which rules ran.

use crate::measure::Measurement;
use gpurify_core::ops::Point;
use gpurify_core::{LayerId, PolyId};
use gpurify_ingest::StrId;
use gpurify_units::Dbu;

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
        debug_assert!(self.columns_agree(), "len: {COLUMNS_DIVERGED}");
        self.rule.len()
    }

    pub fn is_empty(&self) -> bool {
        debug_assert!(self.columns_agree(), "is_empty: {COLUMNS_DIVERGED}");
        self.rule.is_empty()
    }

    pub fn push(&mut self, violation: Violation) {
        debug_assert!(self.columns_agree(), "push: {COLUMNS_DIVERGED}");
        // The table *is* the report, so this is the entry point
        // `Measurement::is_finite` names: a `NaN` past here compares false
        // against every limit downstream and reads as a clean rule.
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

    /// Append another table's rows. The gatherer step after parallel rules.
    pub fn extend(&mut self, other: &Self) {
        debug_assert!(self.columns_agree(), "extend, self: {COLUMNS_DIVERGED}");
        debug_assert!(other.columns_agree(), "extend, other: {COLUMNS_DIVERGED}");
        let grown = self.rule.len() + other.rule.len();

        // Eight bulk copies, not eight loops: `extend_from_slice` is a
        // `memcpy` for `Copy` columns.
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

    /// Establish the canonical order.
    ///
    /// **Part of the interface, not an implementation detail.** Every consumer
    /// — writers, tests, the determinism gate — relies on it, so it is stated
    /// here: sort by rule id, then layer, then `at.y`, then `at.x`, then
    /// `shape_a`, then `shape_b`. That tuple is total over any set of rows this
    /// tool can produce, so the order does not depend on the input order and
    /// therefore does not depend on thread count.
    ///
    /// `shape_b` is an `Option`, and `None` sorts before `Some` — Rust's
    /// derived `Option` order, so `sort_unstable_by_key` on the tuple gives it
    /// for free. A one-shape row therefore precedes the two-shape row it
    /// otherwise agrees with.
    ///
    /// A stable sort would be enough given a total key, but the key is total
    /// precisely so stability is not load-bearing.
    pub fn sort_canonical(&mut self) {
        debug_assert!(self.columns_agree(), "sort_canonical: {COLUMNS_DIVERGED}");
        let rows = self.rule.len();

        // Sort a permutation, then gather each column through it. Sorting the
        // columns in place would be eight independent sorts of eight columns
        // that must agree row for row — the `SoA` defect the multiset test
        // names. `u32` is the workspace's index width; a table this large is a
        // different problem, so it fails closed rather than truncating.
        let rows_u32 =
            u32::try_from(rows).expect("a violation table indexes rows with a u32; see CONVENTIONS");
        let mut perm: Vec<u32> = (0..rows_u32).collect();
        // Cached, not `sort_unstable_by_key`: that one is defined to call its
        // extractor on every comparison, and `row_key` is nine gathers across
        // nine columns plus two `Measurement` matches — rebuilt 2·n·log n times
        // for a table the doc comment sizes at tens of thousands of rows.
        // `sort_by_cached_key` runs it once per row and sorts the decorated
        // pairs, which is the same decorate-sort-undecorate the twin in
        // `pex::network` writes out by hand.
        //
        // Stable, which costs nothing here and buys nothing either:
        // `measurement_key` is injective on every variant, so two rows with
        // equal `RowKey`s agree in all eight columns and their relative order is
        // unobservable. That is what keeps the order a function of the *set* of
        // rows, which is the claim the doc comment above makes.
        perm.sort_by_cached_key(|&row| self.row_key(row as usize));
        debug_assert_eq!(perm.len(), rows, "the permutation lost rows");
        #[cfg(debug_assertions)]
        {
            // The sort's postcondition, read back off the permutation: adjacent
            // keys ascend. `&=` rather than an early `break`, so the scan has no
            // data-dependent exit; it runs only under `debug_assertions`, where
            // rebuilding `row_key` is affordable.
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

    /// The canonical sort key of one row.
    ///
    /// The documented six fields first, in the documented order. Then the
    /// three the doc does not name, because the six are *not* total over the
    /// rows this tool produces: two rows can share a rule, a layer, a point
    /// and one shape and still differ — a `None` second slot collides with
    /// every other `None` second slot on the same shape. The stated contract
    /// is that the order is a function of the *set* of rows and therefore not
    /// of thread count, and a tie left open is exactly where thread count
    /// leaks back in. So every remaining field extends the key, and the six
    /// stay the prefix that decides every comparison a reader cares about.
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

    /// Every column holds the same number of rows.
    ///
    /// The `SoA` invariant with nothing but this behind it: a push or a sort
    /// that touches seven of the eight columns leaves a table that still
    /// answers [`Violations::len`] correctly and is wrong everywhere else.
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

/// What [`Violations::row_key`] returns: the six documented key fields, then
/// the three that only exist to make the order total.
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

/// A total order over a [`Measurement`]'s *encoding*.
///
/// Not an `Ord` impl on `Measurement`: comparing a length against a voltage is
/// meaningless as a measurement, and offering it would invite a rule to do it.
/// A deterministic sort needs only that two encodings order the same way every
/// run, which the variant tag plus the payload gives.
///
/// The `match` is a jump table over a three-bit tag, not a data-dependent
/// branch in a bulk loop: it runs inside a comparator, which the sort calls
/// rather than a loop body.
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
///
/// Branchless: the sign bit smeared to a mask flips every bit of a negative
/// (reversing its magnitude order) and the sign bit alone of a positive
/// (lifting it above every negative). `NaN` lands at one end rather than
/// comparing false against everything, which is the fail-open mode
/// [`Measurement::is_finite`] exists to catch upstream of here.
fn f64_key(value: f64) -> u64 {
    let bits = value.to_bits();
    let sign_smear = 0u64.wrapping_sub(bits >> 63);
    bits ^ (sign_smear | (1 << 63))
}

/// Rewrite one column as `new[i] = old[perm[i]]`.
///
/// **Transform, A-to-B.** A gather: the load address is data-dependent, the
/// control flow is not, so the loop body carries no branch. The load's own
/// bounds check stays — `perm` carries arbitrary `u32`s, so there is no
/// induction argument that would earn an unchecked read, and a wrong index must
/// panic rather than read a neighbouring row.
fn permute_column<T: Copy>(perm: &[u32], column: &mut Vec<T>) {
    debug_assert_eq!(perm.len(), column.len(), "{COLUMNS_DIVERGED}");

    // One allocation per column per sort, and it stays one: `sort_canonical` is
    // `(&mut self)`, so there is no parameter a reused buffer could arrive in,
    // and the eight columns hold eight different element types, so a single
    // buffer could not serve them even if there were. Recorded in
    // `docs/SIGNATURE_DEFECTS.md`. Permuting in place instead is not the way
    // out: cycle-chasing makes row N read what row N-1 wrote, which is the
    // kernel rule's failure mode, and trades a branch-free gather for a
    // loop-carried chain with a data-dependent exit.
    let mut gathered = Vec::with_capacity(perm.len());
    for &old in perm {
        gathered.push(column[old as usize]);
    }

    debug_assert_eq!(gathered.len(), perm.len(), "the gather lost rows");
    *column = gathered;
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
