//! The custom-rule runner keeps the report's contract whatever the user's
//! function does (deck-library plan §4.4; testing-plan L9b "accounting
//! survives user code", "determinism survives user code", "a failing custom
//! rule fails the run", "findings are sane").

use gpurify_check::deck::{run_custom, CustomCheck, CustomCtx, CustomRule, Finding, Findings};
use gpurify_check::report::{Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use gpurify_geom::{GeometryStore, Grid, LayerId, PolyId, StrTable};
use gpurify_testgen::{dbu, point, LayoutBuilder};
use std::sync::atomic::{AtomicU32, Ordering};

const FULL: LayerId = LayerId(0);
const EMPTY: LayerId = LayerId(1);
const OTHER: LayerId = LayerId(2);

/// Three rectangles on layer 0, inside (0, 0)..(1000, 1000); layers 1 and 2
/// empty and holding one rectangle.
fn layout() -> GeometryStore {
    let mut layout = LayoutBuilder::new(3);
    layout.rect(FULL, 0, 0, 100, 100);
    layout.rect(FULL, 400, 400, 500, 500);
    layout.rect(FULL, 900, 900, 1000, 1000);
    layout.rect(OTHER, 200, 200, 300, 300);
    layout.finish().0
}

/// Runs `checks`, one rule each reading `inputs`, named `r0`, `r1`, ...
fn run(checks: &[(CustomCheck, &[LayerId])]) -> (Vec<Violation>, Vec<RuleRun>, StrTable) {
    let mut strings = StrTable::default();
    let rules: Vec<CustomRule> = checks
        .iter()
        .enumerate()
        .map(|(at, &(check, inputs))| CustomRule {
            id: strings.intern(&format!("r{at}")),
            inputs: inputs.to_vec(),
            severity: Severity::Error,
            check,
        })
        .collect();
    let store = layout();
    let grid = Grid::new(1000).expect("a 1 nm grid");
    let mut out = Violations::default();
    let mut runs = Vec::new();
    run_custom(&rules, &store, None, grid, &strings, &mut out, &mut runs);
    let rows = (0..out.len()).map(|row| out.get(row)).collect();
    (rows, runs, strings)
}

fn panics(_: &CustomCtx<'_>, _: &mut Findings) {
    panic!("a custom rule's bug");
}

fn finds_nothing(_: &CustomCtx<'_>, _: &mut Findings) {}

/// Flags every shape of input 0, in store order, once.
fn flags_each(ctx: &CustomCtx<'_>, out: &mut Findings) {
    for shape in ctx.shapes(ctx.input(0)) {
        out.flag(ctx, shape, Measurement::Length(dbu(1)));
    }
}

/// The same findings as [`flags_each`], last first and each three times.
fn flags_each_shuffled(ctx: &CustomCtx<'_>, out: &mut Findings) {
    let shapes: Vec<PolyId> = ctx.shapes(ctx.input(0)).collect();
    for _ in 0..3 {
        for &shape in shapes.iter().rev() {
            out.flag(ctx, shape, Measurement::Length(dbu(1)));
        }
    }
}

fn one(layer: LayerId, at: (i64, i64), measured: Measurement) -> Finding {
    Finding {
        layer,
        at: point(at.0, at.1),
        shapes: (PolyId(u32::MAX), None),
        measured,
        limit: measured,
    }
}

fn outside_the_extent(ctx: &CustomCtx<'_>, out: &mut Findings) {
    out.push(one(ctx.input(0), (5000, 0), Measurement::Length(dbu(1))));
}

fn on_an_undeclared_layer(_: &CustomCtx<'_>, out: &mut Findings) {
    out.push(one(OTHER, (250, 250), Measurement::Length(dbu(1))));
}

fn measures_nan(ctx: &CustomCtx<'_>, out: &mut Findings) {
    out.push(one(ctx.input(0), (50, 50), Measurement::Ratio(f64::NAN)));
}

/// A finding pushed, then a panic: nothing of it may reach the report.
fn finds_then_panics(ctx: &CustomCtx<'_>, out: &mut Findings) {
    flags_each(ctx, out);
    panic!("after a finding");
}

/// An empty input skips the rule without calling it; a populated one that
/// finds nothing ran, its `examined` counted by the runner; a rule reading
/// an empty layer and a populated one runs over both.
/// Oracle: construct-from-answer, L9b "accounting survives user code": the
/// layout holds 3 shapes on layer 0, 1 on layer 2, none on layer 1. The
/// skipped rule's function panics, so a call would make it `Refused`.
#[test]
fn an_empty_input_is_skipped_and_examined_comes_from_the_runner() {
    let (rows, runs, _) = run(&[
        (panics, &[EMPTY]),
        (finds_nothing, &[FULL]),
        (finds_nothing, &[EMPTY, OTHER]),
    ]);
    assert!(rows.is_empty());
    let got: Vec<(Outcome, u64)> = runs.iter().map(|r| (r.outcome, r.examined)).collect();
    assert_eq!(
        got,
        [
            (
                Outcome::Skipped(gpurify_check::report::SkipReason::EmptyLayer),
                0
            ),
            (Outcome::Ran, 3),
            (Outcome::Ran, 1),
        ]
    );
}

/// A panic makes the rule `Refused`, discards what it found, and the next
/// rule still runs.
/// Oracle: construct-from-answer, L9b "a failing custom rule fails the run":
/// tests unwind, so the rule is `Refused` and the report continues; the rule
/// after it flags its 3 shapes.
#[test]
fn a_panic_refuses_the_rule_and_the_run_goes_on() {
    let (rows, runs, strings) = run(&[(finds_then_panics, &[FULL]), (flags_each, &[FULL])]);
    assert_eq!(runs[0].outcome, Outcome::Refused);
    assert_eq!(runs[0].violations, 0);
    assert_eq!((runs[1].outcome, runs[1].violations), (Outcome::Ran, 3));
    assert!(rows.iter().all(|row| strings.resolve(row.rule) == "r1"));
}

/// Findings out of order and repeated give the same rows as the same
/// findings once each in order.
/// Oracle: law, L9b "determinism survives user code": the canonical order
/// and dedup depend only on the set of findings.
#[test]
fn unsorted_and_repeated_findings_are_canonical() {
    let (sorted, runs, _) = run(&[(flags_each, &[FULL])]);
    let (shuffled, shuffled_runs, _) = run(&[(flags_each_shuffled, &[FULL])]);
    assert_eq!(sorted.len(), 3);
    assert_eq!(shuffled, sorted);
    assert_eq!(shuffled_runs, runs);
}

/// A finding outside the layout, on a layer the rule did not declare, or
/// measured as no number refuses the rule, findings discarded.
/// Oracle: construct-from-answer, L9b "findings are sane": the layout's
/// extent is (0, 0)..(1000, 1000), so (5000, 0) is outside it; layer 2 is
/// not the rule's input; NaN is no measurement.
#[test]
fn an_insane_finding_refuses_the_rule() {
    let (rows, runs, _) = run(&[
        (outside_the_extent, &[FULL]),
        (on_an_undeclared_layer, &[FULL]),
        (measures_nan, &[FULL]),
    ]);
    assert!(rows.is_empty());
    assert!(runs
        .iter()
        .all(|run| run.outcome == Outcome::Refused && run.examined == 3));
}

static CALLS: AtomicU32 = AtomicU32::new(0);

/// A rule whose answer changes from call to call: it flags the first shape
/// on odd calls and the last on even ones (a call counter stands in for a
/// time seed, without the chance of two equal reads).
fn nondeterministic(ctx: &CustomCtx<'_>, out: &mut Findings) {
    let shapes: Vec<PolyId> = ctx.shapes(ctx.input(0)).collect();
    let pick = if CALLS.fetch_add(1, Ordering::Relaxed).is_multiple_of(2) {
        shapes[0]
    } else {
        shapes[shapes.len() - 1]
    };
    out.flag(ctx, pick, Measurement::Length(dbu(1)));
}

/// The run-twice comparison the determinism gate makes catches a
/// nondeterministic custom rule, and passes a deterministic one.
/// Oracle: determinism, L9b "determinism survives user code": two runs of
/// one deck over one layout must be row-identical.
#[test]
fn the_run_twice_comparison_catches_a_nondeterministic_rule() {
    let twice = |check: CustomCheck| run(&[(check, &[FULL])]).0 == run(&[(check, &[FULL])]).0;
    assert!(twice(flags_each));
    assert!(!twice(nondeterministic));
}

/// An equation-based spacing (Calibre eqDRC's form, a limit that is an
/// expression over measured values): two rectangles on input 0 must be at
/// least `50 + w / 2` apart, `w` the wider one's shorter side. Each pair
/// closer than its own limit is one finding measuring the gap.
fn width_dependent_space(ctx: &CustomCtx<'_>, out: &mut Findings) {
    let store = ctx.store();
    for (p, q) in ctx.pairs_within(0, 0, dbu(1000)) {
        let (a, b) = (store.poly_bbox(p), store.poly_bbox(q));
        let side = |r: gpurify_geom::Bbox| (r.xhi - r.xlo).min(r.yhi - r.ylo).raw();
        let need = 50 + side(a).max(side(b)) / 2;
        let gap = (b.xlo - a.xhi).max(a.xlo - b.xhi).raw();
        if gap < need {
            out.flag(ctx, p, Measurement::Length(dbu(gap)));
        }
    }
}

/// Catalog DRC-115, equation-based DRC: a limit computed from measured
/// values is a Rust custom rule, run and accounted as any other.
///
/// Oracle: the equation by hand: bars 100 and 200 wide, 1000 tall, side by
/// side, need `50 + 200 / 2 = 150`; gaps 149, 150, 151 give one finding of
/// 149 and none at or above 150.
#[test]
fn an_equation_based_limit_is_a_custom_rule() {
    for gap in [149, 150, 151] {
        let mut layout = LayoutBuilder::new(1);
        layout.rect(FULL, 0, 0, 100, 1000);
        layout.rect(FULL, 100 + gap, 0, 300 + gap, 1000);
        let store = layout.finish().0;
        let mut strings = StrTable::default();
        let rules = [CustomRule {
            id: strings.intern("eq.space"),
            inputs: vec![FULL],
            severity: Severity::Error,
            check: width_dependent_space,
        }];
        let mut out = Violations::default();
        let mut runs = Vec::new();
        let grid = Grid::new(1000).expect("a 1 nm grid");
        run_custom(&rules, &store, None, grid, &strings, &mut out, &mut runs);
        let found: Vec<Measurement> = (0..out.len()).map(|row| out.get(row).measured).collect();
        let want = if gap < 150 {
            vec![Measurement::Length(dbu(gap))]
        } else {
            Vec::new()
        };
        assert_eq!(found, want, "gap {gap}");
        assert_eq!(runs[0].outcome, Outcome::Ran);
    }
}
