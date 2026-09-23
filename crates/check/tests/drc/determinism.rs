//! The determinism gate: two runs agree row for row; translating the design
//! translates only the report.

use crate::common;

use common::{A, B, OTHER_RULE, RULE};
use gpurify_check::drc::{Rule, RuleSet};
use gpurify_check::report::{RuleRun, Violations};
use gpurify_testgen::shapes::LayoutBuilder;
use gpurify_testgen::{assert_violations_eq, dbu};

/// A layout with several rules' worth of findings in it, so the comparison has
/// rows to disagree about.
fn busy_layout() -> gpurify_geom::GeometryStore {
    let mut layout = LayoutBuilder::new(2);
    for column in 0..12i64 {
        for row in 0..12i64 {
            let x = column * 250;
            let y = row * 250;
            layout.rect(A, x, y, x + 150, y + 150);
        }
    }
    layout.rect(B, -100, -100, 3_100, 3_100);
    let (store, _ids) = layout.finish();
    store
}

/// Two rules that both fire on the layout above, so the run has work to do in
/// more than one table.
fn two_rules() -> RuleSet {
    RuleSet {
        rules: vec![
            (
                RULE,
                Rule::MinSpacing {
                    layer: A,
                    limit: dbu(200),
                },
            ),
            (
                OTHER_RULE,
                Rule::MinWidth {
                    layer: A,
                    limit: dbu(200),
                },
            ),
        ],
    }
}

fn run_once(set: &RuleSet, store: &gpurify_geom::GeometryStore) -> (Violations, Vec<RuleRun>) {
    let mut out = Violations::default();
    let mut runs = Vec::new();
    set.run(store, &mut out, &mut runs);
    out.sort_canonical();
    (out, runs)
}

/// Oracle: determinism. The same rule set over the same geometry produces the
/// same rows in the same order, twice. The canonical sort is what makes the
/// order part of the interface, so comparing the tables row for row is a
/// stronger claim than comparing them as sets — and it is the claim every writer
/// downstream depends on.
#[test]
fn two_runs_of_one_design_produce_identical_violations_and_identical_run_rows() {
    let store = busy_layout();
    let set = two_rules();

    let (first, first_runs) = run_once(&set, &store);
    let (second, second_runs) = run_once(&set, &store);

    assert!(
        !first.rule.is_empty(),
        "a determinism comparison over two empty tables proves nothing"
    );
    assert_violations_eq(&first, &second);
    assert_eq!(first_runs, second_runs);
}

/// Oracle: law. Translating every input by the same vector translates every
/// reported coordinate by that vector and changes nothing else — the same rows,
/// the same measurements, the same `examined` counts. Layout geometry has no
/// privileged origin, so a rule whose answer depends on absolute position is
/// wrong for any input, not just this one.
#[test]
fn translating_the_whole_design_translates_the_report_and_changes_nothing_else() {
    const SHIFT: i64 = 1_000_000;
    let set = two_rules();

    let (origin, origin_runs) = run_once(&set, &busy_layout());
    assert!(
        !origin.rule.is_empty(),
        "a translation invariance that holds over no rows holds over nothing"
    );

    let mut moved_layout = LayoutBuilder::new(2);
    for column in 0..12i64 {
        for row in 0..12i64 {
            let x = column * 250 + SHIFT;
            let y = row * 250 + SHIFT;
            moved_layout.rect(A, x, y, x + 150, y + 150);
        }
    }
    moved_layout.rect(B, SHIFT - 100, SHIFT - 100, SHIFT + 3_100, SHIFT + 3_100);
    let (moved_store, _ids) = moved_layout.finish();
    let (moved, moved_runs) = run_once(&set, &moved_store);

    assert_eq!(
        origin_runs, moved_runs,
        "translation changed what was examined"
    );
    assert_eq!(origin.rule.len(), moved.rule.len());
    for row in 0..origin.rule.len() {
        assert_eq!(origin.rule[row], moved.rule[row]);
        assert_eq!(origin.layer[row], moved.layer[row]);
        assert_eq!(origin.measured[row], moved.measured[row]);
        assert_eq!(origin.limit[row], moved.limit[row]);
        assert_eq!(origin.shape_a[row], moved.shape_a[row]);
        assert_eq!(origin.shape_b[row], moved.shape_b[row]);
        assert_eq!(
            origin.at[row].x + dbu(SHIFT),
            moved.at[row].x,
            "row {row} moved by something other than the translation in x"
        );
        assert_eq!(
            origin.at[row].y + dbu(SHIFT),
            moved.at[row].y,
            "row {row} moved by something other than the translation in y"
        );
    }
}
