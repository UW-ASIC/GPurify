//! End to end: a deck and a layout file in, a verification report out.
//!
//! The hand-written cases place one violation at a chosen coordinate, write it
//! to a real GDS file and follow it through every seam. The corpus cases read
//! `tests/fixtures` and check each against its geometry-derived expectation.

use gpurify::check::report::{Measurement, Outcome, Severity, SkipReason};
use gpurify::engine::pipeline::LoadError;
use gpurify::engine::run::{Checks, StageStatus};
use gpurify::ingest::DeckError;

mod common;

/// Oracle: construct-from-answer. One min-width violation, placed at a
/// coordinate this test chose, carried through every stage.
#[test]
fn a_deliberate_min_width_violation_survives_the_whole_pipeline() {
    let run = common::Run::with_min_width_violation();
    let (outputs, _) = run
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
#[test]
fn a_clean_layout_reports_clean_and_says_which_rules_examined_what() {
    let run = common::Run::clean();
    let (outputs, _) = run
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
#[test]
fn a_run_missing_its_optional_inputs_reports_skipped_and_does_not_pass() {
    let run = common::Run::clean_with_gated_rule()
        .without_reference()
        .without_intent();
    let (_, summary) = run
        .execute()
        .expect("missing optional inputs are not a failure to run");

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

/// Oracle: law — `parse -> write -> parse` is the identity on the store.
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
#[test]
fn coordinates_at_the_domain_edge_survive_the_file_round_trip() {
    let run = common::Run::at_domain_edge();
    let loaded = run
        .load()
        .expect("extreme but legal coordinates are still legal");
    common::assert_extremes_preserved(&loaded.store, run.extreme);
}

/// Oracle: construct-from-answer. A deck limit the grid cannot express is
/// refused, never rounded.
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
#[test]
fn every_rule_in_the_deck_appears_in_the_run_record_exactly_once() {
    let run = common::Run::clean();
    let (outputs, _) = run.execute().expect("the pipeline completes");

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
#[test]
fn a_reported_length_prints_in_nanometres_against_the_runs_grid() {
    let run = common::Run::with_min_width_violation();
    let (outputs, _) = run.execute().expect("the pipeline completes");

    let found = common::only_violation(&outputs.violations);
    assert_eq!(
        common::render(found.measured, run.grid),
        format!("{} nm", run.actual_width_nm)
    );
}

// ---------------------------------------------------------------------------
// The fixture corpus: every expectation comes from `expectations.json`.
// ---------------------------------------------------------------------------

/// Oracle: construct-from-answer, over 94 cells drawn with deliberate defects.
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
            grid: run.loaded.grid,
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
const HV_DOMAIN_INTENT: &str = r#"{
  "domains":  { "core": { "voltage_mv": 1800.0 } },
  "supplies": [{ "net": "ERC_HV_n0", "domain": "core", "role": "power" }]
}"#;

/// Oracle: construct-from-answer, on the harness rather than on geometry.
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
fn assert_near(got: f64, want: f64, what: &str) {
    assert!(
        (got - want).abs() <= 1e-9 * want.abs().max(1.0),
        "{what}: solved {got}, the closed form says {want}"
    );
}

/// The design intent that puts `LVS_INV`'s poly rail under an IR-drop limit.
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
const IR_DROP_INTENT_SLACK: &str = r#"{
  "domains":  { "core": { "voltage_mv": 1800.0 } },
  "supplies": [{ "net": "LVS_INV_n5", "domain": "core", "role": "power" }],
  "limits":   [{ "net": "LVS_INV_n5", "max_drop_mv": 300.0, "budget_current_ua": 2000.0 }]
}"#;

/// Oracle: closed form — `V = I·R` over the sheet resistance of a known
/// rectangle, plus the law that zero current through any resistance drops zero.
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
const HV_OVERSTRESS_INTENT: &str = r#"{
  "domains":  { "core": { "voltage_mv": 3300.0 } },
  "supplies": [{ "net": "ERC_HV_n0", "domain": "core", "role": "power" }]
}"#;

/// Oracle: closed form — the Arrhenius/inverse-power lifetime model, evaluated
/// against the deck's own `bti` row.
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
const EM_INTENT: &str = r#"{
  "domains":  { "core": { "voltage_mv": 1800.0 } },
  "supplies": [{ "net": "ERC_EM_n2", "domain": "core", "role": "power" }],
  "limits":   [{ "net": "ERC_EM_n2", "budget_current_ua": 1000.0 }]
}"#;

/// The same rail and the same domain, with no current stated at all.
const EM_INTENT_NO_BUDGET: &str = r#"{
  "domains":  { "core": { "voltage_mv": 1800.0 } },
  "supplies": [{ "net": "ERC_EM_n2", "domain": "core", "role": "power" }],
  "limits":   [{ "net": "ERC_EM_n2", "max_drop_mv": 200.0 }]
}"#;

/// Oracle: law — a rule that cannot compute the quantity it compares must
/// refuse, because zero is *under* every limit it would compare against and a
/// clean row is indistinguishable from a checked one.
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
