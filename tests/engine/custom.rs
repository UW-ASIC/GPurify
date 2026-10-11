//! Custom rules through the whole run, and a deck a binary carries by name
//! (deck-library plan §4.4-4.5; catalog FLOW-006).

use super::{options, NONE};
use gpurify::deck::{
    compile, print, BuildError, CompiledDeck, CustomCtx, DeckBuilder, DeckFn, Findings,
};
use gpurify::engine::pipeline::{Inputs, LoadError};
use gpurify::engine::run::{run, run_with, Checks, EngineError};
use gpurify::export::{json, Header};
use gpurify_check::report::{Measurement, Outcome, Severity};
use gpurify_geom::{Grid, StrTable};
use std::sync::atomic::{AtomicU32, Ordering};

/// Flags every shape of its input.
fn flags_each(ctx: &CustomCtx<'_>, out: &mut Findings) {
    for shape in ctx.shapes(ctx.input(0)) {
        out.flag(ctx, shape, Measurement::Count(1));
    }
}

static CALLS: AtomicU32 = AtomicU32::new(0);

/// Flags a different shape on every call: a call counter in place of a time
/// seed, without the chance of two equal reads.
fn nondeterministic(ctx: &CustomCtx<'_>, out: &mut Findings) {
    let shapes: Vec<_> = ctx.shapes(ctx.input(0)).collect();
    let at = CALLS.fetch_add(1, Ordering::Relaxed) as usize % shapes.len();
    out.flag(ctx, shapes[at], Measurement::Count(1));
}

/// `tests/fixtures/params.deck` with one custom rule over `met1`.
fn with_check(
    grid: Grid,
    strings: &mut StrTable,
    check: gpurify::deck::CustomCheck,
) -> Result<CompiledDeck, BuildError> {
    let base = compile(include_str!("../fixtures/params.deck"), grid, strings)?;
    let mut d = DeckBuilder::from_deck(&base, strings);
    let met1 = d.get("met1");
    d.custom("met1.custom", &[met1], Severity::Error, check);
    d.finish()
}

fn params_flagging(grid: Grid, strings: &mut StrTable) -> Result<CompiledDeck, BuildError> {
    with_check(grid, strings, flags_each)
}

fn params_nondeterministic(grid: Grid, strings: &mut StrTable) -> Result<CompiledDeck, BuildError> {
    with_check(grid, strings, nondeterministic)
}

/// A coupling cell with two met1 shapes, under the deck named `deck`.
fn inputs(deck: &str) -> Inputs {
    Inputs {
        layout: crate::gen_fixtures::fixtures().join("pex/PEX_COUPLING_C.gds"),
        deck: deck.into(),
        ..Inputs::default()
    }
}

/// One DRC run's JSON report: the bytes the golden test compares twice.
fn report(decks: &[(&str, DeckFn)], deck: &str) -> String {
    let (loaded, _, outputs, _) =
        run_with(&inputs(deck), &options(Checks { drc: true, ..NONE }), decks)
            .expect("the run has a verdict");
    let header = Header {
        tool_version: "test",
        deck_path: deck.to_owned(),
        layout_path: String::new(),
        timestamp: None,
    };
    let mut text = String::new();
    json::write_report(
        &json::Report {
            header: &header,
            violations: &outputs.violations,
            runs: &outputs.runs,
            strings: &loaded.strings,
            grid: loaded.grid,
        },
        &mut text,
    )
    .expect("the report writes");
    text
}

/// A deck a binary carries runs by its name, its custom rule a row of the
/// report beside the deck's own rules, counted by the runner; without the
/// binary's decks the same name is a file that does not exist. FLOW-006.
/// Oracle: construct-from-answer: the cell holds two met1 shapes (its golden
/// `tests/golden/pex/PEX_COUPLING_C.all` reports `met1.min_width` examined
/// 2), and the rule flags each shape once.
#[test]
fn a_binary_s_own_deck_runs_its_custom_rules_by_name() {
    let decks: [(&str, DeckFn); 1] = [("params-custom", params_flagging)];
    let (loaded, _, outputs, summary) = run_with(
        &inputs("params-custom"),
        &options(Checks { drc: true, ..NONE }),
        &decks,
    )
    .expect("the named deck builds and runs");
    let row = outputs
        .runs
        .iter()
        .find(|run| loaded.strings.resolve(run.rule) == "met1.custom")
        .expect("the custom rule has a run row");
    assert_eq!(
        (row.outcome, row.examined, row.violations),
        (Outcome::Ran, 2, 2)
    );
    assert!(!summary.passed(), "its findings are errors");

    let error = run(
        &inputs("params-custom"),
        &options(Checks { drc: true, ..NONE }),
    )
    .expect_err("no file is named params-custom");
    assert!(
        matches!(error, EngineError::Load(LoadError::Deck(_))),
        "{error:?}"
    );
}

/// A deterministic custom rule gives the same report bytes twice; a
/// nondeterministic one does not, so the golden test's run-twice comparison
/// catches it.
/// Oracle: determinism, L9b "determinism survives user code".
#[test]
fn the_report_bytes_catch_a_nondeterministic_custom_rule() {
    let decks: [(&str, DeckFn); 2] = [
        ("flagging", params_flagging),
        ("nondeterministic", params_nondeterministic),
    ];
    assert_eq!(report(&decks, "flagging"), report(&decks, "flagging"));
    assert_ne!(
        report(&decks, "nondeterministic"),
        report(&decks, "nondeterministic")
    );
}

/// A deck with a custom rule is not written as text with the rule dropped:
/// the printer refuses it, naming the rule.
/// Oracle: construct-from-answer, L9b "printing a deck with custom rules
/// refuses or names them".
#[test]
fn a_deck_with_custom_rules_does_not_print() {
    let mut strings = StrTable::default();
    let deck =
        params_flagging(Grid::new(1000).expect("a grid"), &mut strings).expect("the deck builds");
    let error = print(&deck, &strings).expect_err("a custom rule has no text");
    assert!(error.to_string().contains("met1.custom"), "{error}");
}
