//! The determinism gate, and the two things about `Scratch` a caller relies on.
//!
//! Determinism is a gate rather than a test in this workspace, because the
//! defect it catches — eight of twenty-seven parasitic reports differing between
//! runs of the same binary — is invisible to every assertion about a single run.
//! There is no thread count to vary in `drc` yet (`Scratch` is shared, see its
//! ponytail note), so the two axes available are running twice and running with
//! a buffer set that has already been used.
//!
//! The second is the sharper one. Twenty-six transforms clear and refill one
//! buffer set in sequence, so a transform that read what the previous one left
//! behind would still be correct on a fresh `Scratch` and wrong on a reused one.
//! That is exactly the shape of a bug a single-run suite cannot see.

mod common;

use common::{Env, A, B, OTHER_RULE, RULE};
use gpurify_drc::{RuleSet, Scratch};
use gpurify_report::{RuleRun, Violations};
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
    let mut set = RuleSet::default();
    set.min_spacing.rule.push(RULE);
    set.min_spacing.layer.push(A);
    set.min_spacing.limit.push(dbu(200));

    set.min_width.rule.push(OTHER_RULE);
    set.min_width.layer.push(A);
    set.min_width.limit.push(dbu(200));
    set
}

fn run_once(
    set: &RuleSet,
    env: &Env,
    store: &gpurify_geom::GeometryStore,
    scratch: &mut Scratch,
) -> (Violations, Vec<RuleRun>) {
    let mut out = Violations::default();
    let mut runs = Vec::new();
    set.run(env.design(store), scratch, &mut out, &mut runs);
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
    let env = Env::default();
    let set = two_rules();

    let (first, first_runs) = run_once(&set, &env, &store, &mut Scratch::default());
    let (second, second_runs) = run_once(&set, &env, &store, &mut Scratch::default());

    assert!(
        !first.rule.is_empty(),
        "a determinism comparison over two empty tables proves nothing"
    );
    assert_violations_eq(&first, &second);
    assert_eq!(first_runs, second_runs);
}

/// Oracle: determinism. One `Scratch` is threaded through all twenty-four
/// transforms and through every run in a long-lived process, so a run against a
/// buffer set that has already been filled must reach the same verdict as one
/// against a fresh set. A transform reading what its predecessor left behind is
/// correct on the first run and wrong on every later one, which is a defect no
/// single-run assertion can see.
#[test]
fn a_reused_scratch_reaches_the_same_verdict_as_a_fresh_one() {
    let store = busy_layout();
    let env = Env::default();
    let set = two_rules();

    let (fresh, fresh_runs) = run_once(&set, &env, &store, &mut Scratch::default());
    assert!(
        !fresh.rule.is_empty(),
        "two empty tables agree about nothing"
    );

    let mut reused = Scratch::default();
    let (_warmup, _warmup_runs) = run_once(&set, &env, &store, &mut reused);
    let (again, again_runs) = run_once(&set, &env, &store, &mut reused);

    assert_violations_eq(&fresh, &again);
    assert_eq!(fresh_runs, again_runs);
}

/// Oracle: determinism. `Scratch::shrink` drops capacity and nothing else, so a
/// run after it must agree with a run before it. The buffers are storage; if
/// releasing them changed a verdict, they were carrying state.
#[test]
fn shrinking_the_scratch_between_runs_does_not_change_the_verdict() {
    let store = busy_layout();
    let env = Env::default();
    let set = two_rules();

    let mut scratch = Scratch::default();
    let (before, before_runs) = run_once(&set, &env, &store, &mut scratch);
    assert!(
        !before.rule.is_empty(),
        "two empty tables agree about nothing"
    );
    scratch.shrink();
    let (after, after_runs) = run_once(&set, &env, &store, &mut scratch);

    assert_violations_eq(&before, &after);
    assert_eq!(before_runs, after_runs);
}

/// Oracle: law. Translating every input by the same vector translates every
/// reported coordinate by that vector and changes nothing else — the same rows,
/// the same measurements, the same `examined` counts. Layout geometry has no
/// privileged origin, so a rule whose answer depends on absolute position is
/// wrong for any input, not just this one.
#[test]
fn translating_the_whole_design_translates_the_report_and_changes_nothing_else() {
    const SHIFT: i64 = 1_000_000;
    let env = Env::default();
    let set = two_rules();

    let (origin, origin_runs) = run_once(&set, &env, &busy_layout(), &mut Scratch::default());
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
    let (moved, moved_runs) = run_once(&set, &env, &moved_store, &mut Scratch::default());

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
