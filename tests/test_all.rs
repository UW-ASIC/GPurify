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

use gpurify::check::drc::DrcError;
use gpurify::check::report::{Measurement, Outcome, Severity, SkipReason};
use gpurify::engine::pipeline::LoadError;
use gpurify::engine::run::{Checks, EngineError, StageStatus};
use gpurify::ingest::DeckError;

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
/// **The counts assert the split.** F1–F3 are closed: every cell draws its
/// `licon`s, the pfet recogniser is 3-terminal so every pmos is recognised,
/// and `diff_active = diff NOT poly` is the conductor, so a MOS channel
/// conducts nothing laterally and source and drain extract to distinct nets.
/// The `expect_nets` values below encode exactly that — `LVS_INV` is 4 nets,
/// where the pre-split extraction gave 3 with VSS shorted through the channel
/// to Y. `expect_match` stays unasserted in this loop because it runs the
/// layout side only; the full comparison against `lvs_inv.cdl` is the test
/// below this one.
#[test]
fn every_lvs_cell_in_the_corpus_extracts_the_devices_it_draws() {
    let corpus = common::load_corpus();
    let mut failed = Vec::new();
    for case in &corpus.lvs.cases {
        failed.extend(common::check_lvs_case(case));
    }
    common::report_domain("LVS", corpus.lvs.cases.len(), &failed);
}

/// Oracle: construct-from-answer. A real extraction and a real reference netlist
/// through the LVS stage, and the eight run rows that say which of its checks
/// executed.
///
/// **The first test in this workspace to run the LVS stage on geometry.**
/// `Inputs::reference` was the constant `None` in every fixture here, so
/// `run_lvs` returned `Skipped` on every run this project had ever done and
/// `lvs::graph::from_layout_into` was reached only by
/// `crates/engine/tests/checks.rs` on an `Extracted::default()` — an empty
/// extraction, which exercises none of its columns. This one hands it
/// `LVS_INV`'s four nets, four bound ports and two recognised MOS — source and
/// drain distinct, per the split `diff_active` conductor — read out of a real
/// GDS by the ordinary reader, against `lvs_inv.cdl` read by the ordinary
/// SPICE reader.
///
/// # The verdict is `Match`, and that is derived rather than observed
///
/// F1–F3 are closed: the layout side extracts the reference's own shape — two
/// MOS on four nets, source and drain distinct — and both sizes are asserted
/// below, off the parsed netlist and off the extraction, so a fixture that
/// loses a card weakens nothing silently. F4 is closed too, and its residual
/// cause was **not** the S/D asymmetry its name recorded —
/// `refine::role_code` had already collapsed `Source | Drain => 1` — but the
/// bulk terminal: a SPICE `M` card states four nets, the deck's MOS
/// recognisers bind three, so the reference carried a `Bulk` terminal the
/// layout can never extract and refinement unpaired everything over it.
/// `lvs::graph::drop_unextracted_bulk` now removes reference bulk terminals
/// exactly when the layout extracts no bulk at all, and the two graphs are
/// isomorphic: `Match`. Parameters stay uncompared here — `lvs_inv.cdl`
/// declares none, so `from_layout_into` emits none (its per-name gate), which
/// is the same comparison as before with the arity fixed.
///
/// # What is asserted independently of those findings
///
/// The run rows are. Six checks in `lvs::checks` file eight [`RuleRun`] rows
/// between them, and until this was wired up **not one of them reached
/// `Outputs::runs`** — `run_lvs` called `from_layout_into`, `from_reference_into`
/// and `compare`, and nothing else. So LVS contributed no row at all,
/// `Summary::rules_skipped` stayed `0` for a domain in which three rows cannot
/// be configured, and floating nets, label conflicts, merged net seeds and
/// dangling terminals went unchecked in every run. That is the false-clean shape
/// `Outputs::runs` documents itself as existing to prevent.
///
/// [`RuleRun`]: gpurify::check::report::RuleRun
#[test]
fn a_real_extraction_and_a_reference_netlist_reach_a_verdict_and_eight_run_rows() {
    let checks = Checks {
        drc: false,
        erc: false,
        lvs: true,
        pex: false,
    };
    let run = common::run_case_with_reference("lvs", "LVS_CLEAN_MATCH", checks, "lvs_inv.cdl")
        .expect("LVS_INV and the inverter netlist beside it both read");

    // The fixture, pinned. Everything below is derived from these two numbers,
    // so a `.cdl` that lost a card would otherwise weaken the test silently.
    let reference = run
        .loaded
        .reference
        .as_ref()
        .expect("a run given a reference netlist path holds the netlist it read");
    assert_eq!(
        reference.device_kind.len(),
        2,
        "lvs_inv.cdl declares two MOS cards; the reader produced {}",
        reference.device_kind.len()
    );
    assert_eq!(
        reference.net_name.len(),
        4,
        "lvs_inv.cdl names four nets — A, Y, VDD, VSS"
    );

    let verdict = run
        .outputs
        .lvs
        .as_ref()
        .expect("a stage that was given both netlists leaves its verdict behind");
    assert_eq!(
        *verdict,
        gpurify::check::lvs::Verdict::Match,
        "the layout extracts {} devices on {} nets against the reference's 2 on 4, \
         source and drain distinct and the unextracted bulk dropped, so the two \
         graphs are isomorphic and anything but Match reports a difference that \
         is not there",
        run.extracted.devices.len(),
        run.extracted.nets.net_count()
    );

    // A clean comparison contributes no violation rows; the six layout-only
    // checks on this clean cell contribute none either.
    assert_eq!(
        run.outputs.violations.len(),
        0,
        "a Match verdict must reach the report as zero discrepancy rows, \
         but the report carries {}",
        run.outputs.violations.len()
    );

    // The eight rows, by name, with `examined` tied to the extraction's own
    // counts rather than to a constant: the claim a `RuleRun` makes is *this
    // check looked at every one of them*, and a hardcoded number would still
    // pass on a check that examined half of a differently-sized cell.
    let nets = run.extracted.nets.net_count() as u64;
    let ports = run.extracted.ports.len() as u64;
    let devices = run.extracted.devices.len() as u64;
    let terminals = run.extracted.devices.terminal_net.len() as u64;
    let expected: [(&str, Outcome, u64); 8] = [
        ("lvs.floating_net", Outcome::Ran, nets),
        ("lvs.label_conflict", Outcome::Ran, nets),
        ("lvs.net_seed_conflict", Outcome::Ran, ports),
        // Both device-count families and the parametric check compare against a
        // limit that lives in the deck, and no signature in `lvs::checks` takes
        // one. They are recorded unrun rather than passing every layout, which
        // is the whole point of the variant — and the reason a run selecting
        // LVS cannot report a pass today.
        (
            "lvs.device_count_mos",
            Outcome::Skipped(SkipReason::NotInDeck),
            0,
        ),
        (
            "lvs.device_count_bjt",
            Outcome::Skipped(SkipReason::NotInDeck),
            0,
        ),
        ("lvs.parametric", Outcome::Skipped(SkipReason::NotInDeck), 0),
        ("lvs.terminal_net", Outcome::Ran, terminals),
        ("lvs.terminal_count", Outcome::Ran, devices),
    ];
    for (name, outcome, examined) in expected {
        let row = common::rule_run(&run.outputs.runs, &run.loaded.strings, name);
        assert_eq!(row.outcome, outcome, "{name} recorded the wrong outcome");
        assert_eq!(
            row.examined, examined,
            "{name} reports examining {} where the extraction holds {examined}",
            row.examined
        );
    }
    assert_eq!(
        run.outputs.runs.len(),
        expected.len(),
        "six checks file eight rows between them; the run recorded {:?}",
        run.outputs.runs
    );

    // The report a user is actually handed. `lvs::checks` files its rule ids as
    // sentinels counted down from `u32::MAX` precisely so that
    // `StrTable::resolve` panics on one rather than mislabelling a finding, and
    // `export::json::write_runs` resolves every row — so a stage that filed
    // those eight rows without mapping them back to interned names would crash
    // the CLI on every LVS run. This is the one check that the mapping happened.
    let mut json = String::new();
    gpurify::export::json::write_report(
        &gpurify::export::json::Report {
            header: &gpurify::export::Header {
                tool_version: "test",
                deck_path: "params.json".to_owned(),
                layout_path: "LVS_CLEAN_MATCH.gds".to_owned(),
                timestamp: None,
            },
            violations: &run.outputs.violations,
            runs: &run.outputs.runs,
            strings: &run.loaded.strings,
            grid: run
                .loaded
                .grid
                .expect("a successful load establishes the grid"),
        },
        &mut json,
    )
    .expect("every rule id an LVS run reports under resolves to a name");
    for (name, _, _) in expected {
        assert!(
            json.contains(&format!("\"{name}\"")),
            "the report does not name {name}, so a reader cannot tell that check \
             ran from a check that was never dispatched"
        );
    }
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

/// A decade tighter than the solve's own converged residual, and six orders
/// looser than the ULP-level disagreement two panel orderings actually produce.
/// See [`a_field_solve_obeys_the_coupling_laws_a_closed_form_cannot_state`].
const SAME_FIELD: f64 = 1e-9;

/// The deck's own numbers for the two bars the lateral-coupling cells draw:
/// both are 2000 nm long, met1 and met2 are each 400 nm thick, and the
/// dielectric is `k = 3.9`. `EPSILON_0_AF_PER_NM` is the vacuum permittivity in
/// the units this test works in, attofarads per nanometre.
const EPSILON_0_AF_PER_NM: f64 = 8.854_187_812_8e-3;
const K: f64 = 3.9;
const THICKNESS_NM: f64 = 400.0;
const LENGTH_NM: f64 = 2000.0;

/// Oracle: law, against the **field solve** rather than the closed form.
///
/// The other half of `pex`, and until the fixture cells carried net labels it
/// could not be reached at all: `engine::run::run_pex` selects nets by *name*,
/// through `ports.net_of`, and no reader produced a name — the GDS reader
/// skipped every `TEXT`, so `PortTable` was empty in every run this workspace
/// has ever done. This is the first test that executes `quasistatic::extract_into`
/// end to end through the engine, and with it `merge_field_solved_into` and the
/// `reciprocity_refusal` gate.
///
/// # Why these laws and not the 1/S one
///
/// `lateral_coupling_halves_when_the_gap_doubles_and_ignores_the_axis` asserts
/// that `C·S` is constant. That is right for the closed form — `analytical::
/// coupling_capacitance` is literally `coefficient × length / separation` — and
/// **wrong for a field solve**, which is the point of having one: a real
/// solution carries fringing, so coupling falls slower than `1/S` and `C·S`
/// grows with `S`. Asserting 1/S here would be asserting that the field solve
/// is the parallel-plate approximation.
///
/// What survives exactly, and is asserted below:
///
///  - **Rotation invariance.** `PEX_VERT` is `PEX_CC` turned a quarter turn.
///    Same geometry, so the same number.
///  - **Layer invariance.** `PEX_M2CC` is `PEX_CC` moved from met1 to met2, and
///    the deck gives both the same thickness and the same `dielectric_k`, so
///    the field is identical. This settles the corpus's open dispute against
///    the manifest, which asserts 200 aF for one and 160 for the other: no
///    physics over this stack produces that ratio, and the solve agrees with
///    the corpus.
///
/// # Why those two are a tolerance and not a bit compare
///
/// They were written as `to_bits()` equality first, and that was wrong: the two
/// runs agree to 29 ULPs — a relative `3e-15` — and not to the bit. Rotating
/// the geometry rotates the mesh, and a different panel *order* sums the same
/// contributions in a different order, which `f64` addition does not promise to
/// commute over. The bound below is `1e-9` relative: six orders looser than the
/// disagreement actually observed, and still a decade tighter than the `1e-10`
/// residual `solve::Options::default()` converges each column to — so it is
/// pinned by the solver's own stated accuracy rather than by a number picked to
/// make the assertion pass. A real axis or layer dependence would be a
/// percentage, not a ULP.
///  - **Monotonicity.** Coupling falls as the gap widens. Weaker than 1/S and
///    true of any correct solution.
///  - **The parallel-plate lower bound.** `ε₀·k·t·L/S` is the coupling two
///    facing plates would have with no fringing at all, and a real conductor
///    pair couples *more*. This is the assertion that would catch a solve
///    returning a plausible-looking but too-small number, which no relation
///    between the cases can catch.
#[test]
fn a_field_solve_obeys_the_coupling_laws_a_closed_form_cannot_state() {
    let coupling = |id: &str| -> f64 {
        common::field_solved_coupling_af("pex", id)
            .unwrap_or_else(|why| panic!("{id} did not field solve: {why}"))
    };

    let (s100, s200, s400) = (
        coupling("PEX_SPACING_100"),
        coupling("PEX_COUPLING_C"),
        coupling("PEX_SPACING_400"),
    );
    let vertical = coupling("PEX_VERT_COUPLING");
    let on_met2 = coupling("PEX_MET2_COUPLING");

    for (id, value) in [
        ("PEX_SPACING_100", s100),
        ("PEX_COUPLING_C", s200),
        ("PEX_SPACING_400", s400),
    ] {
        assert!(
            value > 0.0 && value.is_finite(),
            "{id} field solved to {value} aF; a coupling case that extracts \
             nothing passes every relation below on an absence"
        );
    }

    let agree = |a: f64, b: f64| (a - b).abs() <= SAME_FIELD * a.abs().max(b.abs());

    assert!(
        agree(vertical, s200),
        "PEX_VERT is PEX_CC rotated a quarter turn, so the field is the same \
         field: {vertical} aF against {s200} aF"
    );
    assert!(
        agree(on_met2, s200),
        "PEX_M2CC is PEX_CC on met2, which the deck gives the same thickness \
         and the same dielectric_k, so the field is the same field: {on_met2} \
         aF against {s200} aF. The manifest's 160-against-200 is what this \
         disagrees with, and the geometry is on this side"
    );

    assert!(
        s100 > s200 && s200 > s400,
        "coupling must fall as the gap widens: {s100} aF at 100 nm, {s200} at \
         200, {s400} at 400"
    );

    // ε₀·k·t·L/S, in attofarads, from the deck's own numbers: both bars are
    // 2000 nm long, met1 is 400 nm thick and the dielectric is k = 3.9. Two
    // facing plates with no fringe at all couple this much, and two real
    // conductors couple more — so this is a *lower* bound and a solve below it
    // is wrong however self-consistent it looks.
    let plate =
        |separation_nm: f64| EPSILON_0_AF_PER_NM * K * THICKNESS_NM * LENGTH_NM / separation_nm;

    for (id, value, separation) in [
        ("PEX_SPACING_100", s100, 100.0),
        ("PEX_COUPLING_C", s200, 200.0),
        ("PEX_SPACING_400", s400, 400.0),
    ] {
        let bound = plate(separation);
        assert!(
            value >= bound,
            "{id} field solved to {value} aF, below the {bound} aF two facing \
             plates would couple with no fringing at all. Fringing only adds, \
             so a solve under the parallel-plate value is wrong"
        );
    }
}

/// The design intent `a_corpus_case_with_design_intent_reaches_an_intent_gated_rule`
/// supplies, in the schema `ingest::intent::parse_intent` documents.
///
/// `ERC_HV_n0` is the one net `ERC_HV_CROSS` labels — a `TEXT` record on the
/// `li_label` layer at (200, 200) — so this declares a supply the extraction
/// actually produces, which is what `resolve_intent_into` needs before
/// `IntentMap::is_usable` can be true. 1800 mV is the deck's own
/// `hv_domain.max_domain_delta`, so nothing here invents a process number.
const HV_DOMAIN_INTENT: &str = r#"{
  "domains":  { "core": { "voltage_mv": 1800.0 } },
  "supplies": [{ "net": "ERC_HV_n0", "domain": "core", "role": "power" }]
}"#;

/// Oracle: construct-from-answer, on the harness rather than on geometry.
///
/// `docs/CORRECTNESS_MAP.md` §3: `tests/common/mod.rs` hardcoded `intent: None`
/// for every corpus case, so `IntentMap::declared` was false in every run this
/// corpus has ever done and all six intent-gated ERC rules recorded
/// `Skipped(NoDesignIntent)` whatever was on disk. F9 is filed as a missing
/// fixture and was really a harness constant — an intent file added to
/// `tests/fixtures/` would have changed nothing.
///
/// This test is the proof that the constant is gone: the *same* cell, through
/// the *same* pipeline, differing only in whether an intent file is passed.
///
/// # Both halves are load-bearing
///
/// The first half is the anti-vacuity guard, and it is not decoration. A test
/// that only asserted `Ran` with intent would also pass against a harness that
/// had deleted the gate entirely, which is the fail-open this whole suite is
/// written against — `check_hv_domain`'s own doc says that with no domains
/// declared every device spans a delta of zero and the design reads clean. So
/// the skip must still be there when intent is absent, and gone when it is not.
///
/// The port assertion is the second guard: `resolve_intent_into` re-keys
/// declared names through `PortTable`, so an intent naming a net this cell does
/// not label produces an empty `IntentMap`, `is_usable` stays false, and the
/// rule skips for a reason that has nothing to do with the harness.
///
/// # Why `hv_domain`
///
/// It is the cheapest of the six to reach: its gate is `intent.is_usable()` and
/// nothing else, where the four electrical rules also need a converged power
/// solve. What is proven here is that the gate is unhooked, not that any
/// particular rule is now covered — no corpus case for the four uncovered kinds
/// is written by this test.
#[test]
fn a_corpus_case_with_design_intent_reaches_an_intent_gated_rule() {
    let checks = Checks {
        drc: false,
        erc: true,
        lvs: false,
        pex: false,
    };

    let without = common::run_case("erc", "ERC_HV_CROSS", checks)
        .expect("ERC_HV_CROSS reaches the checks with no intent, as the corpus runs it");
    let skipped = common::rule_run(&without.outputs.runs, &without.loaded.strings, "hv_domain");
    assert_eq!(
        skipped.outcome,
        Outcome::Skipped(SkipReason::NoDesignIntent),
        "with no intent file the gate must still be closed; a hv_domain that \
         runs here reads every device as spanning zero volts and reports the \
         cell clean"
    );

    let with = common::run_case_with_intent("erc", "ERC_HV_CROSS", checks, HV_DOMAIN_INTENT)
        .expect("the same cell reaches the checks with an intent file beside it");

    let declared = with
        .loaded
        .strings
        .get("ERC_HV_n0")
        .expect("the intent file interned the net name it declares");
    assert!(
        with.extracted.ports.net_of(declared).is_some(),
        "the intent declares ERC_HV_n0 and the extraction bound no net to that \
         name, so IntentMap would be empty and the assertion below would be \
         satisfied by an accident rather than by the gate opening"
    );

    let ran = common::rule_run(&with.outputs.runs, &with.loaded.strings, "hv_domain");
    assert_eq!(
        ran.outcome,
        Outcome::Ran,
        "the same cell, the same deck, one design intent file: hv_domain must \
         reach a verdict. Anything else means the harness still gates it"
    );
}

// ---------------------------------------------------------------------------
// The four intent-gated ERC rules, on their *ran* path.
//
// `docs/CORRECTNESS_MAP.md` §3: `electromigration`, `esd_latchup`, `ir_drop`
// and `reliability` each have one corpus case, and every one of them asserts
// `Skipped(NoDesignIntent)`. Those cases are regression guards on the gate and
// stay exactly as they are — they run through `common::run_case`, which passes
// no intent. What follows runs the *same cells* through
// `common::run_case_with_intent`, which is the only way any of the four can
// reach a verdict.
// ---------------------------------------------------------------------------

/// Every violation one rule reported, ascending by report point.
///
/// `common::only_violation` cannot serve here: these runs enable the whole ERC
/// domain, so the table carries other rules' findings too. The sort is the
/// canonical one `Violations::sort_canonical` already establishes — `at.y` then
/// `at.x` — re-established after the filter so the pairing below is positional
/// rather than a search.
fn violations_of(run: &common::CaseRun, rule: &str) -> Vec<gpurify::check::report::Violation> {
    let id = run
        .loaded
        .strings
        .get(rule)
        .unwrap_or_else(|| panic!("the deck never interned a rule named {rule}"));
    let mut found: Vec<_> = (0..run.outputs.violations.len())
        .map(|row| run.outputs.violations.get(row))
        .filter(|violation| violation.rule == id)
        .collect();
    found.sort_by_key(|violation| (violation.at.y.raw(), violation.at.x.raw()));
    found
}

/// A reported point, as a plain pair, for the assertion messages below.
fn at_of(violation: &gpurify::check::report::Violation) -> (i64, i64) {
    (violation.at.x.raw(), violation.at.y.raw())
}

/// The layer a name resolves to in the run's own deck.
fn layer_of(run: &common::CaseRun, name: &str) -> gpurify::geom::LayerId {
    run.loaded
        .deck
        .layers
        .id(&run.loaded.strings, name)
        .unwrap_or_else(|| panic!("params.json declares no layer named {name}"))
}

/// A solved electrical measurement against its closed form, to a relative 1e-9.
///
/// The same tolerance `common::measurement_matches` uses, and for the same
/// reason: these numbers come out of a conjugate-gradient solve, so exact
/// equality would assert the iteration order rather than the physics.
fn assert_near(got: f64, want: f64, what: &str) {
    assert!(
        (got - want).abs() <= 1e-9 * want.abs().max(1.0),
        "{what}: solved {got}, the closed form says {want}"
    );
}

/// The design intent that puts `LVS_INV`'s poly rail under an IR-drop limit.
///
/// `LVS_INV_n5` is the `TEXT` record on `poly_label` at (200, -50) — the poly
/// stripe, and the one rail in the corpus whose *device* tap differs from its
/// *centre* tap, which is what makes the drop non-zero. 1800 mV is the deck's
/// own `nfet_01v8` domain. The budget is stated on the same net as the limit
/// because `power::extract_into` reads the two independently: a limit with no
/// budget injects no current, which is the second half of this test.
///
/// # 2000 µA, because the budget is shared per attach point
///
/// `power::extract_into` spreads the stated budget over the rail's attach
/// points — `attach.resize(attach.len() + here, ..)` at `erc/src/power.rs:1708`,
/// one share per terminal a device lands on the net. This was 1000 µA when the
/// cell yielded **one** recognised device, so the single gate carried all of it.
///
/// F2 and F3 closed: both transistors are recognised now and source no longer
/// collapses onto drain, so the poly rail carries **two** gates and 1000 µA
/// would be 500 µA each — 120.5 mV, under the limit, and the Ohm's-law bracket
/// this test exists for would be met by an absence.
///
/// 2000 µA restores the per-gate current to exactly what it was, so the closed
/// form below is unchanged at 241.0 mV and the test is *stronger*: two nodes
/// violate where one did. The physical claim is identical; only the number of
/// gates sharing the rail moved.
const IR_DROP_INTENT: &str = r#"{
  "domains":  { "core": { "voltage_mv": 1800.0 } },
  "supplies": [{ "net": "LVS_INV_n5", "domain": "core", "role": "power" }],
  "limits":   [{ "net": "LVS_INV_n5", "max_drop_mv": 200.0, "budget_current_ua": 2000.0 }]
}"#;

/// The same rail, the same limit, no current budget at all.
const IR_DROP_INTENT_NO_BUDGET: &str = r#"{
  "domains":  { "core": { "voltage_mv": 1800.0 } },
  "supplies": [{ "net": "LVS_INV_n5", "domain": "core", "role": "power" }],
  "limits":   [{ "net": "LVS_INV_n5", "max_drop_mv": 200.0 }]
}"#;

/// The same rail and the same 2000 µA, with the limit moved above the drop.
///
/// 241.0 mV against 300 mV rather than 200 mV is the *only* difference, so this
/// is the run that proves `max_drop_mv` participates in the compare at all.
/// Asserting the limit's value, as the first run does, does not: a rule that
/// ignored the number and fired whenever the drop exceeded zero would report the
/// stated limit faithfully and still be wrong.
const IR_DROP_INTENT_SLACK: &str = r#"{
  "domains":  { "core": { "voltage_mv": 1800.0 } },
  "supplies": [{ "net": "LVS_INV_n5", "domain": "core", "role": "power" }],
  "limits":   [{ "net": "LVS_INV_n5", "max_drop_mv": 300.0, "budget_current_ua": 2000.0 }]
}"#;

/// Oracle: closed form — `V = I·R` over the sheet resistance of a known
/// rectangle, plus the law that zero current through any resistance drops zero.
///
/// # Derivation
///
/// `LVS_INV`'s poly is one 50 × 800 stripe, `(200, -50)` to `(250, 750)`. The
/// only device the cell yields is the nfet: `recognise_into` drops a marker
/// whose terminal slots are not all bound, and the pfet recogniser names a
/// fourth terminal on `nwell`, which `params.json` does not list as a
/// conductor — so the psdm marker is skipped and the poly rail has exactly
/// **one** attach point. That is what keeps the whole 1000 µA budget on it
/// rather than half of it.
///
/// Two taps, therefore two nodes: the nfet marker taps the stripe at the centre
/// of the nsdm bbox, `y = 100`, and the rail's own centre tap is
/// `midpoint(-50, 750) = 350`. Both sit on the stripe's centre line,
/// `midpoint(200, 250) = 225`. The pad anchor is the centre tap, so the
/// unknown is the device node.
///
/// One edge between them: `ChainProfile` over a rectangle is a single slab of
/// width 50, the overlap is `350 − 100 = 250`, so `250 / 50 = 5.0` squares at
/// poly's `sheet_res_ohm_sq = 48.2` gives **241.0 Ω** exactly. 1000 µA through
/// it is **241.0 mV**, over a stated 200 mV limit, reported at `(225, 100)` on
/// poly. The pad node itself drops zero and is clean, so `examined` is 2 and
/// the violation count is 1.
///
/// # Why the second run is here
///
/// 241.0 mV is arithmetic on four numbers, and a rule that reported the *nominal*
/// supply instead of the drop would also produce a plausible millivolt figure.
/// Removing `budget_current_ua` leaves the geometry, the resistance and the
/// limit identical and makes the current zero; `V = I·R` then says the drop is
/// zero however large the resistance is. That half needs no arithmetic at all,
/// and it fails against any implementation that reports a voltage rather than a
/// drop.
///
/// # What this does not cover
///
/// The pad anchor is inferred — `Connectivity` has no pad-marker layer, so
/// `power.rs` takes the centre tap of the rail's widest shape. A real pad at an
/// end of the stripe would see 8 squares, not 5. This test is derived against
/// the inference, not against a pad.
#[test]
fn a_stated_current_budget_drops_ohms_law_across_a_known_poly_rail() {
    let checks = Checks {
        drc: false,
        erc: true,
        lvs: false,
        pex: false,
    };

    let run = common::run_case_with_intent("erc", "ERC_IR_DROP_GATE", checks, IR_DROP_INTENT)
        .expect("LVS_INV reaches the checks with an intent file beside it");

    let declared = run
        .loaded
        .strings
        .get("LVS_INV_n5")
        .expect("the intent file interned the net name it declares");
    assert!(
        run.extracted.ports.net_of(declared).is_some(),
        "the intent declares LVS_INV_n5 and the extraction bound no net to that \
         name, so IntentMap would be empty, ir_drop would skip, and every \
         assertion below would be satisfied by an accident"
    );

    let ran = common::rule_run(&run.outputs.runs, &run.loaded.strings, "ir_drop");
    assert_eq!(
        ran.outcome,
        Outcome::Ran,
        "one design intent file, and ir_drop must reach a verdict"
    );
    assert_eq!(
        ran.examined, 3,
        "examined is the number of nodes on nets carrying a stated limit, and \
         the poly rail has three: the nfet tap at y=100, the shape's own centre \
         tap at y=350, and the pfet tap at y=600. It was two while F2 left the \
         pfet unrecognised"
    );

    let found = violations_of(&run, "ir_drop");
    assert_eq!(
        found.len(),
        2,
        "each gate tap drops 241.0 mV over a 200 mV limit and the centre tap \
         drops nothing, so two of the three nodes are violations"
    );
    // Ascending, which `Violations::sort_canonical` guarantees, so the first is
    // the nfet tap at y=100 and the second the pfet tap at y=600.
    let violation = &found[0];

    let Measurement::Voltage(measured) = violation.measured else {
        panic!(
            "ir_drop reports a drop, which is a voltage: got {:?}",
            violation.measured
        );
    };
    // 1000 µA — half of the stated 2000 — through 5.0 squares of 48.2 Ω/sq.
    assert_near(measured.raw(), 241.0, "the IR drop at the nfet tap");

    let Measurement::Voltage(limit) = violation.limit else {
        panic!("the limit compared against a voltage is a voltage");
    };
    assert_near(limit.raw(), 200.0, "the stated max_drop_mv");

    assert_eq!(
        at_of(violation),
        (225, 100),
        "the drop is reported at the node it was solved at: the centre line of \
         the stripe, at the nfet's tap"
    );
    assert_eq!(violation.layer, layer_of(&run, "poly"));
    assert_eq!(violation.severity, Severity::Error);

    // The law: same rail, same 241 Ω, no current.
    let clean =
        common::run_case_with_intent("erc", "ERC_IR_DROP_GATE", checks, IR_DROP_INTENT_NO_BUDGET)
            .expect("the same cell reaches the checks with the budget removed");
    let ran = common::rule_run(&clean.outputs.runs, &clean.loaded.strings, "ir_drop");
    assert_eq!(
        ran.outcome,
        Outcome::Ran,
        "the limit is still stated, so the rule still has jurisdiction"
    );
    assert_eq!(
        ran.examined, 3,
        "the same three nodes are still under a stated limit"
    );
    assert!(
        violations_of(&clean, "ir_drop").is_empty(),
        "no current budget means no current, and zero current through 241 Ω \
         drops zero volts. A violation here is a rule reporting a supply \
         voltage rather than a drop"
    );

    // The limit varies, everything else is held. Without this run `max_drop_mv`
    // is only ever *asserted*, never *exercised*: the first run fires at 241
    // over 200 and the second is clean at zero current, and a rule that ignored
    // the stated number and fired whenever the drop exceeded zero satisfies
    // both. Here the drop is the same 241.0 mV and the limit is 300.
    let slack =
        common::run_case_with_intent("erc", "ERC_IR_DROP_GATE", checks, IR_DROP_INTENT_SLACK)
            .expect("the same cell reaches the checks with a looser limit");
    let ran = common::rule_run(&slack.outputs.runs, &slack.loaded.strings, "ir_drop");
    assert_eq!(
        ran.outcome,
        Outcome::Ran,
        "the limit is stated, so the rule has jurisdiction"
    );
    assert_eq!(ran.examined, 3, "the same three nodes carry a stated limit");
    assert!(
        violations_of(&slack, "ir_drop").is_empty(),
        "the same 241.0 mV drop is inside a 300 mV limit, so nothing fires. A \
         violation here is a rule that compares against something other than \
         the stated max_drop_mv"
    );
}

/// `ERC_HV`'s one labelled net at 3300 mV — 1.833× the `bti` row's
/// characterisation stress, which is what makes the inverse-power term bite.
///
/// [`HV_DOMAIN_INTENT`] is the 1800 mV half of the same declaration, and is
/// reused rather than repeated.
const HV_OVERSTRESS_INTENT: &str = r#"{
  "domains":  { "core": { "voltage_mv": 3300.0 } },
  "supplies": [{ "net": "ERC_HV_n0", "domain": "core", "role": "power" }]
}"#;

/// Oracle: closed form — the Arrhenius/inverse-power lifetime model, evaluated
/// against the deck's own `bti` row.
///
/// # Derivation
///
/// `ERC_HV` is one met1 bar, `(200, 200)` to `(800, 300)`, plus an nwell square
/// that is not a conductor. One conductor polygon on one labelled net gives a
/// grid of exactly **one node, zero edges**, held at the declared voltage — so
/// `conjugate_gradient` has no unknown to touch and the applied stress is the
/// declared supply exactly. The node sits at the bar's centre tap, `(500, 250)`,
/// on met1.
///
/// `reliability.rs` hoists three lines above the row loop:
///
/// ```text
/// thermal  = exp(Ea/k_B · (1/T_applied − 1/T_reference))
/// unit     = reference_lifetime_hours · thermal / duty_cycle
/// lifetime = unit · (reference_stress / |V|)^stress_exponent
/// ```
///
/// with `Ea = 0.5 eV`, `k_B = 8.617333262e-5 eV/K`, `T_reference = 398.15 K`
/// from the deck and `T_applied = 358.15 K` from
/// `engine::run::sign_off_temperature`. That is
/// `exp(5802.259060872792 × 2.8050997906361183e-4) = 5.09159717249751`, so
/// `unit = 5091.59717249751 h`.
///
/// **Sign check, and it is the half a wrong-signed exponent would fail:** the
/// part runs 40 K *cooler* than it was characterised at, so it must last
/// *longer* than its 1000 h reference point, not shorter.
///
/// At 1800 mV the stress ratio is exactly 1 and the prediction is the thermal
/// term alone — 5091.597 h against a 1000 h floor, clean, and clean against the
/// 3600 mV cap too. At 3300 mV it is `5091.59717249751 × (1800/3300)^4 =
/// 450.70076740364533 h`, which fires one violation and only one: 3300 mV is
/// still inside the cap.
///
/// The two halves are load-bearing together. 1800 mV alone cannot see
/// `stress_exponent` at all — any exponent gives 1.0 at the reference stress —
/// and 3300 mV alone cannot separate the thermal term from the power law.
///
/// # What this does not cover
///
/// `sign_off_temperature` is a hardcoded 85 °C with nothing in `RunOptions` able
/// to move it (filed, `crates/engine/src/run.rs:170`), so this test is also an
/// assertion about a constant. At 125 °C `thermal` would be exactly 1.0 and the
/// prediction exactly the 1000 h floor — the "never derates" collapse the rule's
/// own doc comment names.
#[test]
fn the_reliability_model_derates_a_cool_part_upward_and_an_overstressed_one_below_its_floor() {
    let checks = Checks {
        drc: false,
        erc: true,
        lvs: false,
        pex: false,
    };

    let nominal = common::run_case_with_intent("erc", "ERC_RELIABILITY", checks, HV_DOMAIN_INTENT)
        .expect("ERC_HV reaches the checks with an intent file beside it");

    let declared = nominal
        .loaded
        .strings
        .get("ERC_HV_n0")
        .expect("the intent file interned the net name it declares");
    assert!(
        nominal.extracted.ports.net_of(declared).is_some(),
        "the intent declares ERC_HV_n0 and the extraction bound no net to that \
         name, so reliability would skip and both halves below would pass \
         vacuously"
    );

    let ran = common::rule_run(&nominal.outputs.runs, &nominal.loaded.strings, "bti");
    assert_eq!(ran.outcome, Outcome::Ran, "one intent file opens the gate");
    assert_eq!(
        ran.examined, 1,
        "one conductor polygon on one net is one node, and examined is the \
         grid's node count"
    );
    assert!(
        violations_of(&nominal, "bti").is_empty(),
        "at exactly the characterisation stress the inverse-power term is 1.0, \
         and a part running 40 K cool predicts 5091.597 h against a 1000 h \
         floor. A violation here is an Arrhenius factor with the wrong sign"
    );

    let stressed =
        common::run_case_with_intent("erc", "ERC_RELIABILITY", checks, HV_OVERSTRESS_INTENT)
            .expect("the same cell reaches the checks at 3300 mV");

    let ran = common::rule_run(&stressed.outputs.runs, &stressed.loaded.strings, "bti");
    assert_eq!(ran.outcome, Outcome::Ran);
    assert_eq!(ran.examined, 1, "the same one-node grid");

    let found = violations_of(&stressed, "bti");
    assert_eq!(
        found.len(),
        1,
        "3300 mV is under the 3600 mV cap, so the overvoltage compare is clean \
         and only the lifetime compare fires"
    );
    let violation = &found[0];

    let Measurement::Ratio(hours) = violation.measured else {
        panic!(
            "a predicted lifetime is reported as a Ratio: got {:?}",
            violation.measured
        );
    };
    // 5091.59717249751 h × (1800/3300)^4.
    assert_near(
        hours,
        450.700_767_403_645_33,
        "the predicted lifetime at 3300 mV",
    );
    assert_eq!(violation.limit, Measurement::Ratio(1000.0));

    assert_eq!(
        at_of(violation),
        (500, 250),
        "the one node is the centre tap of the 600 x 100 met1 bar"
    );
    assert_eq!(violation.layer, layer_of(&stressed, "met1"));
    assert_eq!(violation.severity, Severity::Error);
}

/// Oracle: closed form on the geometry, for both halves of the rule.
///
/// # Derivation
///
/// The deck's `esd_latchup` row names `["met1", "nwell"]`, so met1 is the pad
/// layer and nwell the guard ring, and `examined` is "the number of pad nets
/// plus the number of guard rings" — one polygon on each layer, so **2**.
///
/// **Pad half.** `params.json` can state no `clamp_model` at all: `ParamValue`
/// carries no string, so `ruleset.rs` builds an empty clamp list. An empty clamp
/// list degrades the verdict rather than refusing the row — `ClampGraph::resolve`
/// on an empty edge list is `Ok`, and `lowest_resistance` returns `None` loudly.
/// The rule's own doc comment says a pad with *no* path is a violation with an
/// absent measurement rather than an infinite one, which is `Count(0)` against a
/// required `Count(1)`, reported at the pad's first vertex, `(200, 200)`.
///
/// **Ring half.** `ERC_HV`'s nwell is a solid 500 × 500 square, so its bbox min
/// span is `Length(500)` against a stated `min_guard_ring_width` of 1000 nm, at
/// its first vertex `(0, 0)`. The tap distance is clean and must stay clean:
/// the ring's bbox and the pad's bbox overlap, so `separation` is 0 against a
/// 3000 nm maximum, and a third violation here would mean the separation
/// arithmetic had inverted.
///
/// # The count of 2 is a ceiling, not a statement about `ERC_HV`
///
/// The first violation exists because the discharge-path half is *structurally
/// unable* to find a path, not because this cell lacks ESD protection. When
/// `ParamValue::Name(StrId)` lands and a clamp becomes spellable, the meaning of
/// that row changes and the count may drop to 1. This test is a regression guard
/// on that ceiling and says so here so that a future reader does not read it as
/// a physics claim.
///
/// The ring half is a real geometric finding, and it is also the one shape where
/// the rule's bbox-min-span measurement is *not* fail-open: for an actual
/// annulus that span is the outer diameter (`reliability.rs:722`, unfiled), and
/// `ERC_HV`'s solid square is the degenerate case where the two coincide. This
/// test therefore derives cleanly and covers nothing of that defect.
#[test]
fn an_unclamped_pad_and_an_undersized_guard_ring_are_both_found_on_the_same_cell() {
    let checks = Checks {
        drc: false,
        erc: true,
        lvs: false,
        pex: false,
    };

    let run = common::run_case_with_intent("erc", "ERC_ESD_LATCHUP", checks, HV_DOMAIN_INTENT)
        .expect("ERC_HV reaches the checks with an intent file beside it");

    let declared = run
        .loaded
        .strings
        .get("ERC_HV_n0")
        .expect("the intent file interned the net name it declares");
    assert!(
        run.extracted.ports.net_of(declared).is_some(),
        "ERC_HV_n0 is a corner-placed label, and binding is boundary-inclusive. \
         If it ever stopped binding, PortTable would empty, is_usable would go \
         false and this case would silently revert to Skipped"
    );

    let ran = common::rule_run(&run.outputs.runs, &run.loaded.strings, "esd_latchup");
    assert_eq!(ran.outcome, Outcome::Ran, "one intent file opens the gate");
    assert_eq!(
        ran.examined, 2,
        "one met1 pad net plus one nwell guard ring"
    );

    let found = violations_of(&run, "esd_latchup");
    assert_eq!(
        found.len(),
        2,
        "the pathless pad and the 500 nm ring, and nothing else: the pad and \
         the ring bboxes overlap, so the tap distance is 0 against a 3000 nm \
         maximum"
    );

    // Ascending by report point: the ring's first vertex is the origin, the
    // pad's is (200, 200).
    let (ring, pad) = (&found[0], &found[1]);

    assert_eq!(
        ring.measured,
        Measurement::Length(gpurify::geom::Dbu::new(500).expect("500 dbu is inside MAX_ABS_DBU"))
    );
    assert_eq!(
        ring.limit,
        Measurement::Length(gpurify::geom::Dbu::new(1000).expect("1000 dbu is inside MAX_ABS_DBU"))
    );
    assert_eq!(at_of(ring), (0, 0));
    assert_eq!(ring.layer, layer_of(&run, "nwell"));
    assert_eq!(ring.severity, Severity::Error);

    assert_eq!(
        pad.measured,
        Measurement::Count(0),
        "no clamp is spellable from a deck, so the pad has no discharge path at \
         all — and an absent path is Count(0), not an infinite resistance"
    );
    assert_eq!(pad.limit, Measurement::Count(1));
    assert_eq!(at_of(pad), (200, 200));
    assert_eq!(pad.layer, layer_of(&run, "met1"));
    assert_eq!(pad.severity, Severity::Error);
}

/// The one supply net in the corpus that carries met1 and can be named.
///
/// `ERC_EM_n2` is a `TEXT` record on `li_label` at (350, 50), the lower-left
/// corner of the second li rectangle, joined to the slender met1 stub through
/// `mcon`. `LVS_INV` draws no met1 at all, so this is the only cell where the
/// deck's `met1.electromigration` row has any jurisdiction to open.
const EM_INTENT: &str = r#"{
  "domains":  { "core": { "voltage_mv": 1800.0 } },
  "supplies": [{ "net": "ERC_EM_n2", "domain": "core", "role": "power" }],
  "limits":   [{ "net": "ERC_EM_n2", "budget_current_ua": 1000.0 }]
}"#;

/// The same rail and the same domain, with no current stated at all.
///
/// Declaring a supply without a budget is ordinary — a domain declaration is
/// what `hv_domain` and `reliability` read, and neither wants a current. The
/// `max_drop_mv` is here so `IntentMap::limit_net` is non-empty and the run is
/// usable for exactly the same reason [`EM_INTENT`]'s is: the *only* difference
/// between the two is `budget_current_ua`, which is the variable
/// [`a_terminal_less_rail_with_no_stated_budget_still_reaches_a_verdict`] holds
/// against [`a_discarded_current_budget_refuses_the_rules_that_read_a_branch_current`].
const EM_INTENT_NO_BUDGET: &str = r#"{
  "domains":  { "core": { "voltage_mv": 1800.0 } },
  "supplies": [{ "net": "ERC_EM_n2", "domain": "core", "role": "power" }],
  "limits":   [{ "net": "ERC_EM_n2", "max_drop_mv": 200.0 }]
}"#;

/// Oracle: law — a rule that cannot compute the quantity it compares must
/// refuse, because zero is *under* every limit it would compare against and a
/// clean row is indistinguishable from a checked one.
///
/// # The input, and why no number can be derived from it
///
/// `ERC_EM_n2` is `{li, met1}`. `params.json` binds device terminals to `poly`
/// and `diff`, so `DeviceTable::devices_on` — which is terminal-based — returns
/// nothing for it, and the 1000 µA [`EM_INTENT`] states has nowhere to be
/// placed. That is not an exotic input: it is the ordinary shape of a supply
/// rail fed from off-chip through a pad, where the current enters from outside
/// the extracted netlist.
///
/// No substitute number is available, and this is settled rather than
/// unexplored. Injecting at the inferred pad anchor is refuted by construction —
/// `power::solve_into` eliminates pad nodes from the unknowns and builds its
/// right-hand side over the unknowns only, so a pad node's `node_load` is never
/// read and the solve is all zeros either way. Spreading the budget over the
/// rail's own taps fabricates load positions, and a uniform spread reads *lower*
/// per edge than a concentrated distal draw on every edge but one — more
/// fail-open on exactly the distal segments an EM check exists for. So the
/// derived outcome is [`Outcome::Refused`], and `examined` is 0 because a row
/// that refused examined nothing.
///
/// # What this test used to assert, and why that was the defect
///
/// Until the guard landed this was
/// `electromigration_reaches_a_verdict_and_the_stated_budget_never_arrives`, and
/// it pinned `Ran` with `examined == 0` — deliberately, as a tripwire on
/// `power.rs`'s `if attach.is_empty() { continue; }`, which sat *above* the
/// first read of `budget_current_ua`. The history is the valuable part: `Ran` +
/// `examined 0` is not a verdict a reader can act on, and
/// `RuleRun::examined`'s frozen doc says "clean" has to mean *this rule
/// executed, examined N shapes, and found nothing*. With N zero, "your budget
/// never reached the solver" and "this rail is within its electromigration
/// limit" were the same row.
///
/// # Blast radius — three rules, and the third is the worst
///
/// All three readers of a branch current are asserted here, on one run, because
/// the gate is a property of the run and a fix that reached only the rule the
/// bug was found in would leave the other two silently clean:
///
/// - `met1.electromigration` — was `Ran` with `examined 0`.
/// - `ir_drop` — was `Ran` and clean: zero current leaves every node at its pad
///   voltage, so every drop is exactly 0.0 and no `max_drop_mv` can be exceeded.
/// - `em_current_density` — **the worst, and the case no test observed before
///   this one.** Its `LayerLimits::blech` is `&[]`, so `immortal` is always
///   false and `examined` counts *every* edge on a limited layer. It reported
///   `Ran` over the full in-scope population with no findings, which is
///   byte-identical to what a genuinely checked clean design reports.
///
/// `bti` is asserted `Ran` in the same breath, and that is the discrimination:
/// the guard must not be a blanket refusal of everything that touches the solve.
/// `check_reliability` deliberately keeps running, because zero current puts
/// every node at exactly its nominal — the *largest* stress its model can take —
/// so its verdict is pessimistic rather than wrong.
///
/// # This is not the coverage — [`black_and_blech_decide_a_met1_rail_that_carries_a_device_terminal`] is
///
/// `ERC_EM_DEV` draws the corpus's first `licon`, tying a recognised nfet's diff
/// through li and `mcon` onto a met1 rail, so `devices_on` is non-empty and the
/// budget survives. Black's derating and the Blech product are asserted against
/// real currents there. The two cells are a controlled pair: same deck row, same
/// intent shape, differing in exactly whether the limited rail carries a device
/// terminal.
#[test]
fn a_discarded_current_budget_refuses_the_rules_that_read_a_branch_current() {
    let checks = Checks {
        drc: false,
        erc: true,
        lvs: false,
        pex: false,
    };

    let run = common::run_case_with_intent("erc", "ERC_EMIG_MET1", checks, EM_INTENT)
        .expect("ERC_EM reaches the checks with an intent file beside it");

    let declared = run
        .loaded
        .strings
        .get("ERC_EM_n2")
        .expect("the intent file interned the net name it declares");
    let net = run.extracted.ports.net_of(declared).expect(
        "the intent declares ERC_EM_n2 and the extraction bound no net to that \
         name, so IntentMap would be empty, every rule below would record \
         Skipped(NoDesignIntent), and the Refused assertions would be satisfied \
         by nothing",
    );
    assert!(
        run.extracted.devices.devices_on(net).is_empty(),
        "the premise of this test is that the limited rail carries no device \
         terminal: with one, the budget lands, the solve carries current and \
         every row below is a verdict rather than a refusal"
    );

    // The three that read a branch current. One run, because the gate is a
    // property of the run: a fix reaching only the rule the defect was found in
    // leaves the other two silently clean.
    for rule in ["met1.electromigration", "ir_drop", "em_current_density"] {
        let ran = common::rule_run(&run.outputs.runs, &run.loaded.strings, rule);
        assert_eq!(
            ran.outcome,
            Outcome::Refused,
            "{rule} compares against a branch current, and the stated 1000 uA \
             never reached the solve. Ran here is a clean verdict over a grid \
             carrying no current at all"
        );
        assert_eq!(
            ran.examined, 0,
            "{rule} refused, and a row that refused examined nothing — a \
             refusal over a full population is a row claiming both"
        );
        assert!(
            violations_of(&run, rule).is_empty(),
            "{rule} refused, so any violation it reported was measured against \
             a zero current"
        );
    }

    // The discrimination: the guard is not a blanket refusal of everything
    // downstream of the solve. Zero current puts every node at its nominal,
    // which is the largest stress `check_reliability`'s model can take, so its
    // verdict errs closed and refusing would replace it with none.
    let ran = common::rule_run(&run.outputs.runs, &run.loaded.strings, "bti");
    assert_eq!(
        ran.outcome,
        Outcome::Ran,
        "reliability reads node_voltage, not branch_current, and a zero-current \
         grid hands it the maximum stress rather than none"
    );
}

/// Oracle: the gate's own contract — the refusal is conditioned on a *stated*
/// budget, so a run that states none must still reach a verdict.
///
/// # Why this leg exists
///
/// It is the false side of the guard, and without it the guard is untested
/// there: an implementation that refused whenever the solve carried no current —
/// or refused unconditionally the moment a supply is declared — passes
/// [`a_discarded_current_budget_refuses_the_rules_that_read_a_branch_current`]
/// and passes
/// [`black_and_blech_decide_a_met1_rail_that_carries_a_device_terminal`] too,
/// because that cell's budget does land.
///
/// Declaring a domain without a current is legitimate and common — it is what
/// `hv_domain` and `reliability` read — and `power::discarded_budget` is
/// `budget_current_ua.is_some_and(|b| b != 0.0) && sum == 0.0`, so `None` is
/// false on the first conjunct and the run proceeds.
///
/// # The derived outcomes
///
/// Same cell, same terminal-less rail, [`EM_INTENT_NO_BUDGET`] differing from
/// [`EM_INTENT`] in exactly the one field:
///
/// - `met1.electromigration` — `Ran`, `examined 0`, clean. No stated current is
///   no current, so the Blech product `|I|·(L/W)` is 0.0, at or under the deck
///   row's stated 10.0, and every in-scope edge is immortal. `examined` counts
///   non-exempt edges.
/// - `em_current_density` — `Ran`, `examined > 0`, clean. Its `blech` column is
///   `&[]`, so nothing is immortal and every edge on `li`/`met1`/`met2` counts;
///   `ERC_EM_n2` is drawn on li and met1, both limited by that row. The bound is
///   stated as `> 0` rather than as a count because the node and edge count of
///   the rail is a property of the tap inference, not of this rule's contract —
///   what this leg needs is that the population is *not* empty, which is what
///   separates "ran over the whole rail" from "refused" and from "ran over
///   nothing".
/// - Clean in both cases because zero is under every limit — which is precisely
///   why the run *with* a stated budget refuses instead. The pair is what makes
///   the refusal readable: the same clean row means "checked" here and would
///   have meant "unchecked" there.
#[test]
fn a_terminal_less_rail_with_no_stated_budget_still_reaches_a_verdict() {
    let checks = Checks {
        drc: false,
        erc: true,
        lvs: false,
        pex: false,
    };

    let run = common::run_case_with_intent("erc", "ERC_EMIG_MET1", checks, EM_INTENT_NO_BUDGET)
        .expect("ERC_EM reaches the checks with a budget-free intent beside it");

    let declared = run
        .loaded
        .strings
        .get("ERC_EM_n2")
        .expect("the intent file interned the net name it declares");
    assert!(
        run.extracted.ports.net_of(declared).is_some(),
        "the intent declares ERC_EM_n2 and the extraction bound no net to that \
         name, so every row below would be Skipped(NoDesignIntent) and the Ran \
         assertions would be satisfied by an accident"
    );

    let ran = common::rule_run(
        &run.outputs.runs,
        &run.loaded.strings,
        "met1.electromigration",
    );
    assert_eq!(
        ran.outcome,
        Outcome::Ran,
        "no budget is stated, so nothing was discarded and the rule has an \
         answer: a rail carrying no declared current violates no current limit"
    );
    assert_eq!(
        ran.examined, 0,
        "no stated current is a Blech product of 0.0, at or under the deck \
         row's 10.0, so the in-scope edges are immortal and examined counts \
         non-exempt edges only"
    );
    assert!(
        violations_of(&run, "met1.electromigration").is_empty(),
        "an immortal segment is exempted before the compare"
    );

    let ran = common::rule_run(&run.outputs.runs, &run.loaded.strings, "em_current_density");
    assert_eq!(
        ran.outcome,
        Outcome::Ran,
        "the same one field is the whole difference from the refusing run, so a \
         guard that fires here is keyed on the zero current rather than on the \
         discarded budget and refuses every unloaded design"
    );
    assert!(
        ran.examined > 0,
        "this row's blech column is empty, so nothing is immortal and every \
         edge on li/met1/met2 is examined — ERC_EM_n2 is drawn on li and met1. \
         An examined of 0 here is the rule running over nothing, which reads \
         the same as the refusal it is meant to be distinguished from"
    );
    assert!(
        violations_of(&run, "em_current_density").is_empty(),
        "no declared current is zero current, and zero density is under the \
         row's stated 1000 A/m"
    );
}

/// One intent for `ERC_EM_DEV`, at whatever current the caller wants to state.
///
/// `ERC_EM_DEV_n0` is the `TEXT` record on `met1_label` at (600, 50) — the met1
/// rail's lower-left corner, bound because `poly_contains_point` is
/// boundary-inclusive. Unlike `ERC_EM_n2` this net reaches a device terminal:
/// the `mcon` and the `licon` tie it down to the diff the nsdm marker recognises
/// an nfet on, which is the whole reason the cell was drawn.
fn em_dev_intent(budget_ua: f64) -> String {
    format!(
        r#"{{
  "domains":  {{ "core": {{ "voltage_mv": 1800.0 }} }},
  "supplies": [{{ "net": "ERC_EM_DEV_n0", "domain": "core", "role": "power" }}],
  "limits":   [{{ "net": "ERC_EM_DEV_n0", "budget_current_ua": {budget_ua:?} }}]
}}"#
    )
}

/// Oracle: closed form — Black's equation's Arrhenius derating against the
/// deck's own `met1.electromigration` row, and the Blech exemption against the
/// segment's own slenderness. Three currents on one geometry.
///
/// # The geometry, and why it exists
///
/// `ERC_EM_DEV` is the corpus's only cell whose electromigration-limited
/// conductor is on the same net as a device terminal. `ERC_EM_n2` is not — see
/// [`a_discarded_current_budget_refuses_the_rules_that_read_a_branch_current`],
/// which pins the refusal that shape now earns — so nothing before this cell
/// could put a stated budget on a met1 edge at all.
///
/// This test is the other half of that controlled pair, and it is the leg that
/// stops the refusal being drawn too wide: same deck row, same intent shape,
/// differing in exactly whether the limited rail carries a device terminal. If
/// the gate ever fires here, it is keyed on something other than a budget that
/// failed to reach the solve.
///
/// The net `ERC_EM_DEV_n0` is three conductor polygons joined by two drawn cuts:
///
/// ```text
/// diff  2/0  (0,   0) - (500,  200)     nsdm 10/0 (-50,-50)-(550,250)
/// licon 4/0  (380, 60) - (460,  140)    poly 3/0  (200,-50)-(250,250)
/// li    5/0  (350, 50) - (700,  150)
/// mcon  6/0  (610, 60) - (690,  140)
/// met1  7/0  (600, 50) - (700, 1950)    <- the rail under test
/// ```
///
/// The nfet is recognised on the derived `gate_n` channel marker with
/// `terminals: [poly, diff_active, diff_active]`; `diff_active = diff NOT
/// poly` splits the drawn diffusion at the gate, so source (left flank) and
/// drain (right flank) extract as **distinct** nets. The licon lands inside
/// the drain flank `(250, 0)-(500, 200)`, so `ERC_EM_DEV_n0` carries exactly
/// one device terminal — the drain — and `power::extract_into` puts the whole
/// declared budget on its tap. Same arriving current as the pre-split corpus,
/// where both S and D landed on one net, the budget was halved, and the two
/// shares scatter-accumulated back onto one node.
///
/// # The grid the solve builds
///
/// Taps land per shape on its long axis: the drain flank takes its own centre,
/// the licon tap and the device tap; li takes its centre plus the licon and
/// mcon taps; met1 (vertical, `100 >= 1900` fails `chain_is_horizontal`) takes
/// its centre `y = 1000` and the mcon tap `y = 100`. The graph is a tree, so
/// there is exactly one path from source to load and every edge on it carries
/// the whole current. The pad anchor is the centre tap of the rail's widest
/// shape on its **highest** layer — met1, `height_nm` 1300 — so the source is
/// met1's `y = 1000` node and the load is the diffusion node; the path runs
/// through every edge between them.
///
/// # The one in-scope edge
///
/// The deck row names `["met1"]` and a via edge's `edge_layer` is the **cut**
/// layer, so neither via is in scope and neither is any li or diff edge. The
/// met1 chain edge is the whole population: `edge_length = 1000 − 100 = 900`,
/// and `ChainProfile` over a rectangle is one slab of its short dimension, so
/// `edge_width = 100`.
///
/// # Black
///
/// ```text
/// scale   = 0.9 / (1.0 · 8.617333262e-5)      = 10444.066309571028
/// derate  = exp(scale · (1/358.15 − 1/383.15)) = 6.704133044734676
/// allowed = 1000 A/m · (100 dbu · 1000/1000) nm · 1e-9 · 1e6 · derate
///         = 100 µA · 6.704133044734676        = 670.4133044734676 µA
/// ```
///
/// `358.15 K` is `engine::run::sign_off_temperature`'s hardcoded 85 °C and
/// `383.15 K` is the deck's characterisation point, so the part runs 25 K
/// **cool** and the limit derates **up**. That is the direction a sign error
/// inverts. The `1e-9 · 1e6` is nanometres→metres against amps→microamps;
/// dropping it would read `100 000 µA` and pass everything.
///
/// # Blech
///
/// `blech_product = |I| · (L / W) = |I| · 9`, against the row's `10.0` µA, and
/// the exempt side is `<=`. So the segment is immortal below `10/9 = 1.111 µA`
/// and examined above it — and `examined += u64::from(!immortal)` is what makes
/// `examined` observable at all.
///
/// # The three runs
///
/// | budget | product | examined | verdict |
/// |---|---|---|---|
/// | 1.0 µA | 9.0 ≤ 10 | **0** | exempt, no compare |
/// | 500 µA | 4500 | **1** | 500 ≤ 670.41, clean |
/// | 1000 µA | 9000 | **1** | 1000 > 670.41, **one violation** |
///
/// Each pair separates a mechanism the others cannot. 1.0 against 500 is the
/// Blech exemption alone: both are far inside the derated limit, and only the
/// exemption moves `examined`. 500 against 1000 is the derated limit alone:
/// both are examined, and only the compare moves the violation count. And 1000
/// alone pins the arithmetic — a missing derating would fire at 500 too, an
/// inverted one would put the limit at 14.9 µA and fire on all three.
///
/// The violation is reported at `node_at[edge_from]` — the *lower* of the two
/// chain positions, `y = 100`, on met1's centre line `x = 650`, hence
/// `(650, 100)`. Not the shape centre, not a vertex.
///
/// # What this does not cover
///
/// The four magnitude fail-opens are untouched: this
/// asserts the closed form the code *states*, at a hardcoded 85 °C corner with
/// no self-heating and a budget spread uniformly over attach points. What it
/// adds over the tripwire is that the budget reaches the solve at all, and that
/// Black and Blech are both evaluated against a real current rather than
/// against zero.
///
/// `max_current_per_cut` stays dead here too: `power.rs` emits every via edge as
/// `EdgeKind::Via { cuts: 1 }` on the cut layer, and no deck row names `licon`
/// or `mcon`.
#[test]
fn black_and_blech_decide_a_met1_rail_that_carries_a_device_terminal() {
    let checks = Checks {
        drc: false,
        erc: true,
        lvs: false,
        pex: false,
    };

    // 1000 µA: examined, and over the derated limit.
    let hot = common::run_case_with_intent("erc", "ERC_EMIG_DEV", checks, &em_dev_intent(1000.0))
        .expect("ERC_EM_DEV reaches the checks with an intent file beside it");

    let declared = hot
        .loaded
        .strings
        .get("ERC_EM_DEV_n0")
        .expect("the intent file interned the net name it declares");
    let net = hot.extracted.ports.net_of(declared).expect(
        "the intent declares ERC_EM_DEV_n0 and the extraction bound no net \
             to that name, so IntentMap would be empty and every assertion below \
             would be satisfied by the gate rather than by the physics",
    );
    assert!(
        !hot.extracted.devices.devices_on(net).is_empty(),
        "the whole point of this cell is that the limited net carries a device \
         terminal: with none, power.rs:1612 discards the budget before reading \
         it and every current below is zero"
    );

    let ran = common::rule_run(
        &hot.outputs.runs,
        &hot.loaded.strings,
        "met1.electromigration",
    );
    assert_eq!(ran.outcome, Outcome::Ran, "one intent file opens the gate");
    assert_eq!(
        ran.examined, 1,
        "the deck row names met1 only, a via edge's layer is its cut layer, and \
         the rail's two taps give exactly one met1 chain edge — which at 9000 uA \
         of Blech product is nowhere near exempt"
    );

    let found = violations_of(&hot, "met1.electromigration");
    assert_eq!(
        found.len(),
        1,
        "one in-scope edge carrying 1000 uA against a 670.41 uA derated limit"
    );
    let violation = &found[0];

    let Measurement::Current(measured) = violation.measured else {
        panic!(
            "electromigration measures a branch current: got {:?}",
            violation.measured
        );
    };
    // The whole declared budget: two terminals on one net, halved and
    // scatter-accumulated back onto the one diff node, then carried down a
    // series path of six edges.
    assert_near(measured.raw(), 1000.0, "the current on the met1 rail");

    let Measurement::Current(limit) = violation.limit else {
        panic!("the limit compared against a current is a current");
    };
    // 1000 A/m x 100 nm = 100 uA, derated up by exp(0.9/8.617333262e-5 x
    // (1/358.15 - 1/383.15)) because 85 C is 25 K below the deck's 383.15 K
    // characterisation point.
    assert_near(limit.raw(), 670.413_304_473_467_6, "the derated met1 limit");

    assert_eq!(
        at_of(violation),
        (650, 100),
        "node_at of the edge's *from* endpoint: the mcon tap at y=100, on the \
         rail's centre line x=650"
    );
    assert_eq!(violation.layer, layer_of(&hot, "met1"));
    assert_eq!(violation.severity, Severity::Error);

    // 500 µA: the same edge, still examined, inside the same limit. Without
    // this run the derating is only ever asserted, never exercised — a rule
    // that ignored `allowed` and fired on any examined edge passes the run
    // above.
    let warm = common::run_case_with_intent("erc", "ERC_EMIG_DEV", checks, &em_dev_intent(500.0))
        .expect("the same cell reaches the checks at half the budget");
    let ran = common::rule_run(
        &warm.outputs.runs,
        &warm.loaded.strings,
        "met1.electromigration",
    );
    assert_eq!(ran.outcome, Outcome::Ran);
    assert_eq!(
        ran.examined, 1,
        "4500 uA of Blech product is still far above the 10 uA exemption, so \
         the same one edge is examined"
    );
    assert!(
        violations_of(&warm, "met1.electromigration").is_empty(),
        "500 uA is inside the 670.41 uA derated limit. A violation here is a \
         missing derating: undated, the limit is 100 uA and 500 exceeds it"
    );

    // 1.0 µA: Blech product 9.0 against a stated 10.0, non-strict, so the
    // segment is exempt and never reaches the compare at all. This is the only
    // run in which `examined` moves, and it moves for a reason that has nothing
    // to do with the limit.
    let cool = common::run_case_with_intent("erc", "ERC_EMIG_DEV", checks, &em_dev_intent(1.0))
        .expect("the same cell reaches the checks at 1 uA");
    let ran = common::rule_run(
        &cool.outputs.runs,
        &cool.loaded.strings,
        "met1.electromigration",
    );
    assert_eq!(
        ran.outcome,
        Outcome::Ran,
        "an exempt segment is a segment the mechanism does not apply to, not a \
         row that failed to run"
    );
    assert_eq!(
        ran.examined, 0,
        "1.0 uA over a slenderness of 900/100 is a Blech product of 9.0, at or \
         under the row's stated 10.0, so the one in-scope edge is immortal and \
         examined counts non-exempt edges only"
    );
    assert!(
        violations_of(&cool, "met1.electromigration").is_empty(),
        "an immortal segment is exempted before the compare"
    );
}

/// Oracle: law — determinism, on the split extraction path specifically.
///
/// `LVS_INV` is the corpus's gate-splitting cell: `diff_active = diff NOT
/// poly` is materialised by the boolean at load, the channel markers bind
/// source and drain to two of its pieces, and the four licon cuts merge eight
/// conductor polygons into four nets. Two independent runs over it must agree
/// bit-for-bit on every extracted table — net partition, device terminals,
/// port bindings — or every byte-comparison gate downstream of extraction is
/// comparing noise.
#[test]
fn extracting_the_split_corpus_twice_is_bit_identical() {
    let checks = Checks {
        drc: false,
        erc: false,
        lvs: false,
        pex: false,
    };
    let first = common::run_case("lvs", "LVS_CLEAN_MATCH", checks).expect("LVS_INV extracts");
    let second = common::run_case("lvs", "LVS_CLEAN_MATCH", checks).expect("LVS_INV extracts");

    assert_eq!(
        first.extracted.nets, second.extracted.nets,
        "two extractions of one layout disagree on the net partition"
    );
    assert_eq!(
        first.extracted.ports, second.extracted.ports,
        "two extractions of one layout disagree on the port bindings"
    );
    // `DeviceTable` carries no `PartialEq`; its public columns are the value.
    let devices = &first.extracted.devices;
    let again = &second.extracted.devices;
    assert_eq!(devices.kind, again.kind);
    assert_eq!(devices.marker, again.marker);
    assert_eq!(devices.model, again.model);
    assert_eq!(devices.terminal_start, again.terminal_start);
    assert_eq!(
        devices.terminal_net, again.terminal_net,
        "two extractions of one layout wire a device terminal to different nets"
    );
    assert_eq!(devices.terminal_role, again.terminal_role);
    assert_eq!(devices.param_start, again.param_start);
    assert_eq!(devices.param, again.param);

    // And the split really is in force: distinct source and drain on a device.
    let (terminal_nets, roles) = devices.terminals_of(gpurify::check::topology::DeviceId(0));
    let source = roles
        .iter()
        .position(|&r| r == gpurify::check::topology::TerminalRole::Source);
    let drain = roles
        .iter()
        .position(|&r| r == gpurify::check::topology::TerminalRole::Drain);
    let (source, drain) = (
        source.expect("a MOS has a source"),
        drain.expect("and a drain"),
    );
    assert_ne!(
        terminal_nets[source], terminal_nets[drain],
        "the determinism above would be vacuous if the split were not in force"
    );
}
