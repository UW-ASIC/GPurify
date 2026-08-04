//! End to end: a deck and a layout file in, a verification report out.
//!
//! Every other test in this workspace exercises one crate against inputs it
//! built itself. This one exercises the seams *between* them, which is where a
//! pipeline actually breaks: a `PolyId` that means one thing to `ingest` and
//! another to `report`, a `LayerId` resolved against the wrong table, a
//! permutation applied once too often. A per-crate test cannot catch any of
//! those, by construction — it never crosses the seam.
//!
//! # The oracle
//!
//! **Construct-from-answer, end to end.** The layout carries a single
//! deliberate violation at a coordinate this suite chose, is written to a real
//! GDS file, and is read back through the ordinary reader. The run must find
//! that violation, at that coordinate, with that measurement. No expected value
//! here was obtained by running anything.
//!
//! # Why the workspace root
//!
//! These link every crate at once, so they belong to none of them. It is also
//! the only place that links exactly one instance of `ingest` and one of
//! `export`: a dev-dependency cycle between those two builds *two* instances
//! whose `LayerTable` types are not the same type, which is why the
//! `parse -> write -> parse` law could not be written inside either crate.
//!
//! Every body outside `gpurify-testgen` is `todo!()`, so each test here panics
//! at its first call. That is the Testing-Phase's expected state. These are the
//! completion criterion for Phase 4 — not a suite to be turned green early by
//! writing an implementation underneath it.

use gpurify::drc::DrcError;
use gpurify::engine::pipeline::LoadError;
use gpurify::engine::run::{Checks, EngineError, StageStatus};
use gpurify::ingest::DeckError;
use gpurify::report::{Measurement, Outcome, Severity};

mod common;

/// Oracle: construct-from-answer. One min-width violation, placed at a
/// coordinate this test chose, carried through every stage.
///
/// The assertion is deliberately not "one violation was found". It is *this*
/// rule, on *this* layer, at *this* point, measuring *this* width against
/// *this* limit — because a rule flagging the wrong shape passes a count.
#[test]
fn a_deliberate_min_width_violation_survives_the_whole_pipeline() {
    let run = common::Run::with_min_width_violation();
    let outputs = run
        .execute()
        .expect("the pipeline completes on valid input");

    let found = common::only_violation(&outputs.violations);
    assert_eq!(run.strings.resolve(found.rule), "narrow_metal");
    assert_eq!(found.layer, run.met1);
    assert_eq!(found.at, run.violation_at);
    assert_eq!(found.measured, Measurement::Length(run.actual_width));
    assert_eq!(found.limit, Measurement::Length(run.limit));
    assert_eq!(found.severity, Severity::Error);
}

/// Oracle: construct-from-answer. A correct layout comes back clean *and says
/// what it checked*.
///
/// The second half is the point. An empty violation table is also what a run
/// that never executed produces, and the previous suite could not tell the two
/// apart — 45 of its 94 DRC cases passed on exactly that ambiguity.
#[test]
fn a_clean_layout_reports_clean_and_says_which_rules_examined_what() {
    let run = common::Run::clean();
    let outputs = run
        .execute()
        .expect("the pipeline completes on valid input");

    assert!(
        outputs.violations.is_empty(),
        "a correct layout has no violations"
    );

    let width = common::rule_run(&outputs.runs, &run.strings, "narrow_metal");
    assert_eq!(width.outcome, Outcome::Ran);
    assert!(
        width.examined > 0,
        "a clean result only means something if the rule looked at something; \
         examined == 0 with Outcome::Ran says the layer was empty, which is a \
         different claim from this layout being correct"
    );
}

/// Oracle: construct-from-answer, on statuses rather than geometry.
///
/// Every check is asked for while neither a reference netlist nor a design
/// intent file is supplied. LVS and the six intent-gated ERC rules cannot run,
/// the run must say so, and it must **not** pass.
///
/// This is the false-clean failure in its most dangerous form, because a CI job
/// reads the exit code and nothing else.
#[test]
fn a_run_missing_its_optional_inputs_reports_skipped_and_does_not_pass() {
    let run = common::Run::clean_with_gated_rule()
        .without_reference()
        .without_intent();
    let outputs = run
        .execute()
        .expect("missing optional inputs are not a failure to run");
    let summary = run.summary(&outputs);

    assert!(
        matches!(summary.lvs, StageStatus::Skipped(_)),
        "LVS was selected and had no reference netlist, so it is Skipped — not \
         Ran with a match, and not NotSelected"
    );
    assert!(
        summary.rules_skipped > 0,
        "the intent-gated ERC rules cannot have run"
    );
    assert!(
        !summary.passed(),
        "a run that could not check everything it was asked to check must not \
         pass; the exit code is the only place that distinction reaches a shell"
    );
}

/// Oracle: construct-from-answer. `NotSelected` and `Skipped` are different,
/// and only one of them blocks a pass.
///
/// The user who did not ask for LVS gets a pass. The user who asked and could
/// not have it does not. Conflating the two is a false clean in one direction
/// and a false alarm in the other.
#[test]
fn a_run_selecting_nothing_is_not_selected_everywhere_and_passes() {
    let run = common::Run::clean().selecting(Checks {
        drc: false,
        erc: false,
        lvs: false,
        pex: false,
    });
    let outputs = run.execute().expect("selecting nothing is a legal run");
    let summary = run.summary(&outputs);

    assert_eq!(summary.drc, StageStatus::NotSelected);
    assert_eq!(summary.lvs, StageStatus::NotSelected);
    assert_eq!(
        summary.rules_skipped, 0,
        "nothing was skipped; nothing was asked for"
    );
    assert!(
        summary.passed(),
        "declining a check is not a failure to run it"
    );
}

/// Oracle: determinism — a gate rather than an oracle.
///
/// The same inputs at two thread counts must serialise to identical bytes. This
/// is what would have caught the defect where 8 of 27 parasitic reports
/// differed between runs of the same binary on the same input: the numbers were
/// right and the file was not reproducible, so it could not be diffed against
/// yesterday's.
#[test]
fn two_runs_at_two_thread_counts_serialise_to_identical_bytes() {
    let run = common::Run::with_min_width_violation();
    let first = run.execute_with_threads(1).expect("single-threaded run");
    let second = run.execute_with_threads(4).expect("four-threaded run");

    let mut left = String::new();
    let mut right = String::new();
    run.serialise(&first, &mut left)
        .expect("a completed run serialises");
    run.serialise(&second, &mut right)
        .expect("a completed run serialises");

    assert_eq!(
        left, right,
        "output must not depend on thread count; a signoff report that differs \
         from itself cannot be diffed"
    );
}

/// Oracle: law — `parse -> write -> parse` is the identity on the store.
///
/// Stated precisely, because the loose version is false: the *store* round
/// trips, not the file. Hierarchy is flattened during the read, so writing a
/// flattened store and reading it back returns the flattened store, never the
/// original file's cell structure.
#[test]
fn a_layout_written_and_read_back_yields_the_same_store() {
    let run = common::Run::with_min_width_violation();
    let original = run.load().expect("the fixture is a valid layout");

    let mut bytes = Vec::new();
    gpurify::export::gds::write_store(&original.store, &original.deck.layers, "TOP", &mut bytes)
        .expect("a store read from GDS can be written back to GDS");

    let round_tripped = common::load_bytes(&bytes, &original.deck).expect("re-read");
    common::assert_stores_equal(&original.store, &round_tripped.store);
}

/// Oracle: construct-from-answer. Coordinates at the edge of the representable
/// domain survive the file round trip exactly.
///
/// `Dbu` is `i64` bounded by `MAX_ABS_DBU`; GDS stores coordinates in a
/// narrower field. A silent truncation moves geometry, and moving geometry
/// moves verdicts.
#[test]
fn coordinates_at_the_domain_edge_survive_the_file_round_trip() {
    let run = common::Run::at_domain_edge();
    let loaded = run
        .load()
        .expect("extreme but legal coordinates are still legal");
    common::assert_extremes_preserved(&loaded.store, run.extreme);
}

/// Oracle: construct-from-answer. A deck naming a rule kind that exists in
/// neither `drc::ruleset::KINDS` nor `erc::ruleset::KINDS` is refused.
///
/// Fail closed. Skipping an unrecognised rule produces a clean report for a
/// deck the tool did not understand, which is the worst output a signoff tool
/// can produce.
///
/// **The refusal is at `run_checks`, not at load**, and this test asserted the
/// wrong stage until the Implementation-Phase. `ingest::deck::parse_deck` is
/// documented not to interpret kinds at all — `drc::ruleset::KINDS` and
/// `erc::ruleset::KINDS` both live above `ingest` in the module graph, so the
/// parser cannot know the vocabulary and `LoadError` has no variant for it.
/// `RuleSet::from_deck` is where the vocabulary lives and where the refusal
/// belongs. The property under test is unchanged and is the one that matters:
/// refused, never skipped, and no check runs.
#[test]
fn a_deck_naming_an_unknown_rule_kind_is_refused_rather_than_skipped() {
    let run = common::Run::with_unknown_rule_kind();
    run.load()
        .expect("a kind is text to the parser, which does not read it");

    let error = run
        .execute()
        .expect_err("an unrecognised rule kind must not run");
    assert!(
        matches!(error, EngineError::Drc(DrcError::UnknownKind { .. })),
        "expected a rule-set error naming the unknown kind, got {error:?}"
    );
}

/// Oracle: construct-from-answer. A deck limit the grid cannot express is
/// refused, never rounded.
///
/// Rounding a spacing limit down passes shapes the foundry would reject. That
/// is why `Grid::to_dbu` is exact-or-rejected, and this is the test that the
/// decision survives all the way out to a user-visible error rather than being
/// quietly absorbed somewhere in between.
#[test]
fn an_off_grid_deck_limit_is_refused_rather_than_rounded() {
    let run = common::Run::with_off_grid_limit();
    let error = run
        .load()
        .expect_err("a limit off the manufacturing grid must not load");

    assert!(
        matches!(error, LoadError::Deck(DeckError::OffGrid(_, _))),
        "expected an off-grid rejection, got {error:?}"
    );
}

/// Oracle: law. Every rule the deck declares appears in the run record exactly
/// once, whatever it found.
///
/// Without this a rule can be dropped between `RuleSet::from_deck` and the
/// dispatcher, and the only symptom is a report quietly missing a check nobody
/// notices is absent.
#[test]
fn every_rule_in_the_deck_appears_in_the_run_record_exactly_once() {
    let run = common::Run::clean();
    let outputs = run.execute().expect("the pipeline completes");

    for rule in run.deck_rule_ids() {
        let seen = outputs.runs.iter().filter(|r| r.rule == rule).count();
        assert_eq!(
            seen,
            1,
            "rule {} appears {seen} times in the run record; every declared rule \
             must be accounted for exactly once",
            run.strings.resolve(rule)
        );
    }
}

/// Oracle: construct-from-answer. A reported length reaches the reader in
/// nanometres, not database units.
///
/// A report saying `200` with no unit is how two tools disagree silently.
#[test]
fn a_reported_length_prints_in_nanometres_against_the_runs_grid() {
    let run = common::Run::with_min_width_violation();
    let outputs = run.execute().expect("the pipeline completes");

    let found = common::only_violation(&outputs.violations);
    assert_eq!(
        common::render(found.measured, run.grid),
        format!("{} nm", run.actual_width_nm)
    );
}

// ---------------------------------------------------------------------------
// The fixture corpus.
//
// Eleven hand-written cases above, 160 corpus cases below. The eleven place a
// violation this file chose and follow it through every seam; the 160 read a
// layout somebody drew for a real PDK and ask whether the tool agrees with the
// shapes. Neither replaces the other: the eleven would still pass on a tool
// that got every real rule wrong, and the 160 would still pass on a tool whose
// JSON writer was not deterministic.
//
// Every expectation comes from `tests/fixtures/expectations.json`, whose numbers
// were derived from the geometry and the frozen doc comments. `manifest.json` —
// the deleted tree's own output — is not read by anything here.
// ---------------------------------------------------------------------------

/// Oracle: construct-from-answer, over 94 cells drawn with deliberate defects.
///
/// Each case asserts three things, and the second is why this layer exists at
/// all: the count, **that the rule ran and examined a non-empty jurisdiction**,
/// and for a positive case the measurement and the report coordinate. 45 of the
/// 94 expect zero violations, and in the old suite that was satisfied by a rule
/// that never executed — an empty violation table looks identical either way.
/// `RuleRun::outcome` and `RuleRun::examined` are what tell them apart.
#[test]
fn every_drc_case_in_the_corpus_agrees_with_its_geometry() {
    let corpus = common::load_corpus();
    let mut failed = Vec::new();
    for case in &corpus.drc.cases {
        failed.extend(common::check_geometry_case(case));
    }
    common::report_domain("DRC", corpus.drc.cases.len(), &failed);
}

/// Oracle: construct-from-answer, on connectivity rather than on shapes.
///
/// The same three assertions as DRC, plus the layer a finding is reported on:
/// an ERC violation names a net, and the layer is the cheapest evidence that
/// the net it named is the one the cell draws.
///
/// Four cases expect `Skipped(NoDesignIntent)` rather than a count. That is not
/// a weaker assertion, it is the one that matters most here — a clean count from
/// an intent-gated rule with no intent file is a false clean, and asserting the
/// skip is how this suite refuses to accept one.
#[test]
fn every_erc_case_in_the_corpus_agrees_with_its_geometry() {
    let corpus = common::load_corpus();
    let mut failed = Vec::new();
    for case in &corpus.erc.cases {
        failed.extend(common::check_geometry_case(case));
    }
    common::report_domain("ERC", corpus.erc.cases.len(), &failed);
}

/// Oracle: construct-from-answer. Each LVS cell draws a stated number of
/// devices and a stated number of nets.
///
/// **`expect_match` is not asserted, and the corpus is why.** The 16 reference
/// netlists exist only inside `manifest.json`, which is the deleted tree's
/// output and is not read by this suite; no netlist file ships in the corpus at
/// all. Findings F1–F6 in `expectations.json` add that the comparison could not
/// reach a verdict even given one — no cell draws a `licon`, so no strap ties
/// anything; `nwell` is not a conductor, so no pmos is recognised; and both
/// diffusion terminals bind to the same net, so every extracted MOS has
/// source == drain.
///
/// The device and net counts are where all three of those show themselves, one
/// stage earlier and with a clearer message than a graph mismatch would give.
#[test]
fn every_lvs_cell_in_the_corpus_extracts_the_devices_it_draws() {
    let corpus = common::load_corpus();
    let mut failed = Vec::new();
    for case in &corpus.lvs.cases {
        failed.extend(common::check_lvs_case(case));
    }
    common::report_domain("LVS", corpus.lvs.cases.len(), &failed);
}

/// Oracle: closed form. Sheet resistance of a known rectangle, parallel-plate
/// and fringe capacitance of a known area, vias in parallel.
///
/// Every number in these 27 cases is an analytic solution over the deck's own
/// coefficients — `1.0 Ω` is ten squares of 0.1 Ω/sq, `185 aF` is
/// 25 aF/µm² × 1 µm² plus 40 aF/µm × 4 µm. Nothing was read off a run.
///
/// Eight cases are negative: the cell is drawn wrong on purpose and the
/// extraction must *not* reproduce the correct number. Those assert the
/// mismatch, which is a weaker claim than a value and is stated as such in the
/// corpus.
#[test]
fn every_pex_case_in_the_corpus_agrees_with_its_closed_form() {
    let corpus = common::load_corpus();
    let mut failed = Vec::new();
    for case in &corpus.pex.cases {
        failed.extend(common::check_pex_case(case));
    }
    common::report_domain("PEX", corpus.pex.cases.len(), &failed);
}

/// Oracle: law. Lateral coupling goes as 1/S and does not depend on the axis.
///
/// The three cases these cover are marked `underivable` in the corpus and are
/// skipped by the test above, for a stated reason: `StackJson` has no lateral
/// coefficient column, so no absolute coupling value follows from the deck.
/// A *relation* between them still does, and it is exact — `PEX_S100`,
/// `PEX_CC` and `PEX_S400` are the same two bars at 100, 200 and 400 nm, and
/// `PEX_VERT` is `PEX_CC` rotated a quarter turn.
///
/// This is what keeps those three from being three cases that assert nothing.
#[test]
fn lateral_coupling_halves_when_the_gap_doubles_and_ignores_the_axis() {
    let failed = common::check_coupling_laws();
    assert!(
        failed.is_empty(),
        "the coupling cases in the corpus violate a law no extraction may \
         violate:\n\n{}\n",
        failed.join("\n\n")
    );
}
