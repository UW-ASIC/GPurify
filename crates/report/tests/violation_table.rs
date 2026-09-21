//! The violation table: pushing rows, concatenating tables, and the canonical
//! order every consumer relies on.
//!
//! Oracles here are **law** and **determinism**. A sort permutes its input and
//! does nothing else; concatenation order is invisible once the canonical sort
//! has run; sorting an ordered table again changes nothing. Those hold for any
//! set of rows, so no geometry is needed and the tables are built directly.
//!
//! The claim under test in [`Violations::sort_canonical`]'s doc comment is that
//! the key is *total*, which is why stability is not load-bearing. A test that
//! sorted one arrangement and checked the result would not touch that claim, so
//! every ordering test here shuffles first, with a printed seed.

use gpurify_geom::{LayerId, PolyId};
use gpurify_ingest::StrId;
use gpurify_report::{Measurement, Severity, Violation, Violations};
use gpurify_testgen::{assert_bytes_identical, assert_violations_eq, point, Rng};

/// The corpus whose canonical order is known before anything is sorted.
///
/// Two values in each of the six key fields, walked in exactly the order the
/// doc states — rule, layer, `at.y`, `at.x`, `shape_a`, `shape_b` — so the
/// nested loops enumerate the answer.
///
/// Every field outside the key is a distinct function of the row's position, so
/// that all eight columns vary independently of one another. `measured` carries
/// the position itself, so a sorted table reads `Count(0), Count(1), ...` and a
/// column permuted out of step with the rest produces a tag sequence naming
/// exactly which. `limit` counts down and `severity` cycles on a period coprime
/// with the key, for the same reason: a column held constant across the corpus
/// can be shuffled, dropped or duplicated by a broken sort without a single
/// assertion noticing.
///
/// `at.y` before `at.x` is the part worth pinning. It is the one ordering a
/// reader would guess wrong, and a raster order is not what the interface
/// promises.
fn ordered_corpus() -> Vec<Violation> {
    let mut rows = Vec::with_capacity(64);
    for rule in [2u32, 5] {
        for layer in [1u16, 8] {
            for y in [-40i64, 40] {
                for x in [-40i64, 40] {
                    for shape_a in [3u32, 7] {
                        for shape_b in [11u32, 13] {
                            let tag = u32::try_from(rows.len()).expect("64 rows fit a u32");
                            rows.push(Violation {
                                rule: StrId(rule),
                                layer: LayerId(layer),
                                severity: severity_for(tag),
                                at: point(x, y),
                                measured: Measurement::Count(tag),
                                limit: Measurement::Count(1_000 - tag),
                                shapes: (PolyId(shape_a), Some(PolyId(shape_b))),
                            });
                        }
                    }
                }
            }
        }
    }
    rows
}

/// A severity that cycles with the row's position rather than being constant.
///
/// Period three against a corpus whose every key field has period a power of
/// two: no key boundary lines up with the cycle, so a sort that carried the
/// severity column along by its own index rather than by the row's lands on a
/// different value almost everywhere.
fn severity_for(tag: u32) -> Severity {
    if tag.is_multiple_of(3) {
        Severity::Warning
    } else {
        Severity::Error
    }
}

/// The ordered corpus plus a single-shape twin of every row.
///
/// Where a row is `Some(shape_b)`, its twin is `None`. That is the one key
/// field whose ordering the doc does not state, so nothing here asserts where
/// the twins land — only that they land in the same place under every input
/// order, which is the totality claim and all of it that is promised.
fn totality_corpus() -> Vec<Violation> {
    let mut rows = ordered_corpus();
    let paired = rows.len();
    for index in 0..paired {
        let mut twin = rows[index];
        twin.shapes.1 = None;
        let tag = u32::try_from(paired + index).expect("128 rows fit a u32");
        twin.measured = Measurement::Count(tag);
        twin.limit = Measurement::Count(1_000 - tag);
        twin.severity = severity_for(tag);
        rows.push(twin);
    }
    rows
}

/// Build a table by writing the columns directly.
///
/// Deliberately not `Violations::push`: the ordering tests would otherwise fail
/// for two unrelated reasons, and `push` has its own test below that compares
/// it against this.
fn table_of(rows: &[Violation]) -> Violations {
    let mut table = Violations::default();
    for row in rows {
        table.rule.push(row.rule);
        table.layer.push(row.layer);
        table.severity.push(row.severity);
        table.at.push(row.at);
        table.measured.push(row.measured);
        table.limit.push(row.limit);
        table.shape_a.push(row.shapes.0);
        table.shape_b.push(row.shapes.1);
    }
    table
}

/// Read one row back out of the public columns.
fn row_at(table: &Violations, index: usize) -> Violation {
    Violation {
        rule: table.rule[index],
        layer: table.layer[index],
        severity: table.severity[index],
        at: table.at[index],
        measured: table.measured[index],
        limit: table.limit[index],
        shapes: (table.shape_a[index], table.shape_b[index]),
    }
}

/// Render the table to bytes, one row per line, for the determinism gate.
fn render(table: &Violations) -> Vec<u8> {
    use std::fmt::Write as _;
    let mut out = String::new();
    for index in 0..table.rule.len() {
        let _ = writeln!(out, "{:?}", row_at(table, index));
    }
    out.into_bytes()
}

/// Every column is a column of the same table.
///
/// The `SoA` invariant with no compiler behind it. A push or a sort that
/// touches seven of the eight columns leaves a table that still answers
/// `len()` correctly and is wrong everywhere else.
fn assert_columns_are_parallel(table: &Violations, what: &str) {
    let rows = table.rule.len();
    for (name, length) in [
        ("layer", table.layer.len()),
        ("severity", table.severity.len()),
        ("at", table.at.len()),
        ("measured", table.measured.len()),
        ("limit", table.limit.len()),
        ("shape_a", table.shape_a.len()),
        ("shape_b", table.shape_b.len()),
    ] {
        assert!(
            length == rows,
            "{what}: column {name} holds {length} rows, column rule holds {rows}"
        );
    }
}

/// Shuffle a copy of `rows` under `seed`, load it, and sort it.
fn sorted_from_shuffle(rows: &[Violation], seed: u64) -> Violations {
    let mut shuffled = rows.to_vec();
    Rng::new(seed).shuffle(&mut shuffled);
    let mut table = table_of(&shuffled);
    table.sort_canonical();
    assert_columns_are_parallel(&table, &format!("sort_canonical at seed {seed}"));
    table
}

/// Oracle: construct-from-answer. The corpus is the cartesian product of two
/// values in each key field, enumerated in the order the interface promises, so
/// its sorted form is known before any sorting happens. Shuffling first is what
/// makes the input arbitrary; the answer was fixed by the nested loops.
#[test]
fn sort_canonical_orders_by_rule_then_layer_then_y_then_x_then_shapes() {
    let expected = table_of(&ordered_corpus());
    for seed in 0..16u64 {
        let actual = sorted_from_shuffle(&ordered_corpus(), seed);
        assert_violations_eq(&actual, &expected);
    }
}

/// Oracle: law, and the determinism gate. If the key is total then the sorted
/// table is a function of the *set* of rows and not of the order they arrived
/// in. Input order stands in for thread count here: rules run in parallel and
/// concatenate, so the arrival order is the only thing a thread count changes.
#[test]
fn sort_canonical_gives_one_byte_sequence_whatever_order_the_rows_arrived_in() {
    let rows = totality_corpus();
    let first = render(&sorted_from_shuffle(&rows, 0));
    for seed in 1..32u64 {
        let again = render(&sorted_from_shuffle(&rows, seed));
        assert_bytes_identical(&format!("sort_canonical at seed {seed}"), &first, &again);
    }
}

/// Oracle: law. Sorting is idempotent for any comparison that is a total order,
/// and a second pass that moves a row is evidence the key is not one.
///
/// The two degenerate tables are here as well, because they are what a clean
/// run actually produces: nothing to order, and one row already in order.
#[test]
fn sorting_an_already_canonical_table_moves_nothing() {
    let mut table = sorted_from_shuffle(&totality_corpus(), 101);
    let once = render(&table);
    table.sort_canonical();
    assert_bytes_identical("a second sort_canonical", &once, &render(&table));

    let mut empty = Violations::default();
    empty.sort_canonical();
    assert_violations_eq(&empty, &Violations::default());

    let single = &ordered_corpus()[..1];
    let mut one_row = table_of(single);
    one_row.sort_canonical();
    assert_violations_eq(&one_row, &table_of(single));
}

/// Oracle: law. A sort permutes; it may not drop, duplicate or corrupt a row.
/// Comparing the two multisets is what catches the classic `SoA` defect of
/// sorting one column independently of the seven beside it, which leaves a
/// correctly ordered table full of rows that were never pushed.
#[test]
fn sort_canonical_preserves_the_multiset_of_rows() {
    let rows = totality_corpus();
    let before = table_of(&rows);
    let after = sorted_from_shuffle(&rows, 77);

    let mut before_rows: Vec<String> = (0..before.rule.len())
        .map(|i| format!("{:?}", row_at(&before, i)))
        .collect();
    let mut after_rows: Vec<String> = (0..after.rule.len())
        .map(|i| format!("{:?}", row_at(&after, i)))
        .collect();
    before_rows.sort();
    after_rows.sort();
    assert_eq!(
        before_rows, after_rows,
        "sort_canonical changed which rows the table holds, not just their order"
    );
}

/// Oracle: law. `push` is the inverse of reading the columns back, so a row in
/// is the same row out, column for column. `len` counts what was pushed and
/// `is_empty` agrees with it at every step, including the empty table where the
/// two disagree most often.
#[test]
fn a_pushed_row_reads_back_out_of_the_columns_unchanged() {
    let rows = ordered_corpus();
    let mut table = Violations::default();
    assert!(table.is_empty(), "a fresh table is not empty");
    assert_eq!(table.len(), 0, "a fresh table reports rows");

    for (count, row) in rows.iter().enumerate() {
        table.push(*row);
        assert!(
            !table.is_empty(),
            "a table with {} rows reports empty",
            count + 1
        );
        assert!(
            table.len() == count + 1,
            "after {} pushes the table reports {} rows",
            count + 1,
            table.len()
        );
    }
    assert_columns_are_parallel(&table, "push");
    assert_violations_eq(&table, &table_of(&rows));
}

/// Oracle: law. `get` and `push` are two halves of one round trip, and `get` is
/// the only reader that is not the raw columns — so it is the one that can
/// disagree with them.
#[test]
fn get_returns_the_row_that_was_pushed_at_that_index() {
    let rows = ordered_corpus();
    let mut table = Violations::default();
    for row in &rows {
        table.push(*row);
    }
    for (index, expected) in rows.iter().enumerate() {
        assert_eq!(
            table.get(index),
            *expected,
            "row {index} did not survive push then get"
        );
    }
}

/// Oracle: law. The gatherer property the table's doc comment claims outright:
/// rules produce into per-rule tables that are concatenated, and the
/// concatenation order does not matter *because* of the canonical sort. So the
/// same rows split at an arbitrary point, extended in either order, must sort
/// to the same table as a single run — and to the known answer.
#[test]
fn concatenation_order_is_invisible_after_the_canonical_sort() {
    let rows = ordered_corpus();
    let expected = table_of(&rows);

    for seed in 0..8u64 {
        let mut rng = Rng::new(seed);
        let mut shuffled = rows.clone();
        rng.shuffle(&mut shuffled);
        let count = u64::try_from(shuffled.len()).expect("64 rows fit a u64");
        let split = usize::try_from(rng.below(count)).expect("a bounded index fits a usize");
        let (head, tail) = shuffled.split_at(split);

        let mut forwards = table_of(head);
        forwards.extend(&table_of(tail));
        assert_columns_are_parallel(&forwards, "extend");
        assert!(
            forwards.len() == rows.len(),
            "extend produced {} rows from {} and {}",
            forwards.len(),
            head.len(),
            tail.len()
        );
        // Before the sort, because the sort is what makes the order stop
        // mattering: `extend` is documented to *append*, and a version that
        // prepended, or that appended one column and prepended another, would
        // be invisible from here on.
        assert_violations_eq(&forwards, &table_of(&shuffled));
        forwards.sort_canonical();

        let mut backwards = table_of(tail);
        backwards.extend(&table_of(head));
        backwards.sort_canonical();

        assert_violations_eq(&forwards, &expected);
        assert_violations_eq(&backwards, &expected);
    }
}

/// Oracle: law. Extending by an empty table is the identity, which is the case
/// a gatherer hits on every rule that found nothing — that is most of them on a
/// clean run.
#[test]
fn extending_by_an_empty_table_changes_nothing() {
    let rows = ordered_corpus();
    let mut table = table_of(&rows);
    table.extend(&Violations::default());
    assert_columns_are_parallel(&table, "extend by empty");
    assert_violations_eq(&table, &table_of(&rows));
}

/// Oracle: law. `Warning` is defined as never downgrading a genuine violation,
/// which is a statement about the derived order: a writer reducing a set of
/// findings to their worst must land on `Error`. The variant order is the only
/// thing carrying that, and swapping the two variants is a silent change.
#[test]
fn a_warning_never_outranks_an_error() {
    assert!(Severity::Warning < Severity::Error);
    assert_eq!(
        [Severity::Error, Severity::Warning].into_iter().max(),
        Some(Severity::Error)
    );
}
