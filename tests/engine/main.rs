//! `engine`: load errors, extraction, stage statuses, and the pass criterion.

#[path = "../common/gen_fixtures.rs"]
mod gen_fixtures;

mod custom;
mod def;
mod device_region;
mod edits;
mod incremental;

use gpurify::engine::pipeline::{extract, load, ExtractError, Inputs, LoadError, Loaded};
use gpurify::engine::run::{
    run, run_checks, Checks, EngineError, RunOptions, StageStatus, Summary,
};
use gpurify_check::deck::{CompileError, CompiledDeck};
use gpurify_check::drc::DrcError;
use gpurify_check::lvs::verdict::{Discrepancy, Side};
use gpurify_check::lvs::{CompareOptions, Verdict};
use gpurify_geom::{GeometryStore, GeometryStoreBuilder, Grid, LayerId};
use gpurify_ingest::deck::{parse_deck, Connectivity, Deck, DeviceKind};
use gpurify_ingest::netlist::{Netlist, RefNetId, SubcktId};
use gpurify_ingest::{Provenance, StrId, StrTable};
use gpurify_testgen::shapes::dbu;
use gpurify_testgen::LayoutBuilder;
use std::path::PathBuf;

const NONE: Checks = Checks {
    drc: false,
    erc: false,
    lvs: false,
    pex: false,
};

fn grid() -> Grid {
    Grid::new(1_000).expect("a 1 nm grid")
}

fn options(checks: Checks) -> RunOptions {
    RunOptions {
        checks,
        lvs: CompareOptions::default(),
        quasistatic_nets: Vec::new(),
    }
}

/// A run of `deck`, which states no rule, over `store`, with nothing else read.
fn empty_loaded(store: GeometryStore, deck: Deck) -> Loaded {
    let strings = StrTable::default();
    let deck =
        CompiledDeck::from_deck(deck, grid(), &strings).expect("a deck of no rules compiles");
    Loaded {
        strings,
        grid: grid(),
        deck,
        store,
        provenance: Provenance::default(),
        reference: None,
        intent: None,
        design: None,
    }
}

/// A missing deck or layout is reported as that input's error; a failed load
/// reaches no later stage.
///
/// Oracle: `load`'s `# Errors`, which names the variant for each input, and
/// construct-from-answer: each case pairs one missing file with a fixture pair
/// the engine loads (`a_quasistatic_net_is_solved_for_inductance_too`), so
/// only that input can be at fault. Which error wins when both are missing is
/// not a contract (`load`'s `# Errors`), so that case asserts only that `run`
/// returns the load failure rather than run a stage.
#[test]
fn a_load_reports_the_input_at_fault_and_reaches_no_stage() {
    let fixtures = gen_fixtures::fixtures();
    let missing = PathBuf::from("/nonexistent/missing");
    let inputs = |layout: PathBuf, deck: PathBuf| Inputs {
        layout,
        deck,
        ..Inputs::default()
    };
    let (layout, deck) = (
        fixtures.join("pex/PEX_COUPLING_C.gds"),
        fixtures.join("params.deck"),
    );
    assert!(matches!(
        load(&inputs(layout, missing.clone())),
        Err(LoadError::Deck(_))
    ));
    assert!(matches!(
        load(&inputs(missing.clone(), deck)),
        Err(LoadError::Layout(_))
    ));
    assert!(matches!(
        run(&inputs(missing.clone(), missing), &options(Checks::ALL)),
        Err(EngineError::Load(_))
    ));
}

/// Two overlapping rectangles are one net and a distant one another; an empty
/// design extracts to empty tables.
///
/// Oracle: construct-from-answer. The first two rectangles overlap at x
/// 90..100 and the third is 300 away: two nets. An empty design has no net,
/// device or port.
#[test]
fn extraction_partitions_by_touch_and_accepts_an_empty_design() {
    let metal = LayerId(0);
    let mut layout = LayoutBuilder::new(1);
    let left = layout.rect(metal, 0, 0, 100, 100);
    let right = layout.rect(metal, 90, 0, 200, 100);
    let apart = layout.rect(metal, 500, 0, 600, 100);
    let (store, ids) = layout.finish();
    let deck = Deck {
        connectivity: Connectivity {
            conductors: vec![metal],
            intra_layer_touch: true,
            ..Connectivity::default()
        },
        ..Deck::default()
    };

    let extracted = extract(&empty_loaded(store, deck)).expect("one conductor extracts");
    assert_eq!(extracted.nets.net_count(), 2);
    assert!(extracted.nets.same_net(ids.of(left), ids.of(right)));
    assert!(!extracted.nets.same_net(ids.of(left), ids.of(apart)));

    let empty = extract(&empty_loaded(GeometryStore::default(), Deck::default()))
        .expect("an empty design is extractable");
    assert_eq!(
        (
            empty.nets.net_count(),
            empty.devices.len(),
            empty.ports.len()
        ),
        (0, 0, 0)
    );
}

/// Raw diffusion that is both conductor and MOS source/drain under a marker
/// would merge source and drain into one net; extraction refuses it instead.
///
/// Oracle: `extract`'s documented `ExtractError::Channel` ("a transistor's
/// channel marker overlaps" live conductor): `diff` is a conductor and the
/// transistor's source and drain under the `nsdm` marker.
#[test]
fn a_deck_that_leaves_raw_diffusion_conducting_under_a_mos_marker_is_refused() {
    let mut strings = StrTable::default();
    let deck = parse_deck(
        "grid 1nm
layer diff = gds(65, 20)
layer poly = gds(66, 20)
layer nsdm = gds(93, 44)
connect conductors [diff, poly]
connect touch_within_layer
device mos nsdm model \"nfet\" terminals [poly, diff, diff]
",
        grid(),
        &mut strings,
    )
    .expect("the refusal is geometric, not schematic");
    let layer = |name| deck.layers.id(&strings, name).expect("declared");
    let (diff, poly, nsdm) = (layer("diff"), layer("poly"), layer("nsdm"));

    let mut builder = GeometryStoreBuilder::default();
    for (layer, [xlo, ylo, xhi, yhi]) in [
        (diff, [0, 0, 500, 200]),
        (poly, [200, -50, 250, 250]),
        (nsdm, [-50, -50, 550, 250]),
    ] {
        builder.push(
            layer,
            &[xlo, xhi, xhi, xlo].map(dbu),
            &[ylo, ylo, yhi, yhi].map(dbu),
        );
    }
    let (store, _) = builder.finish(deck.layers.len());

    let mut loaded = empty_loaded(store, deck);
    loaded.strings = strings;
    assert!(matches!(extract(&loaded), Err(ExtractError::Channel(_))));
}

/// One conductor deck, and a layout of two touching rectangles (one net) and
/// a third apart from them (another), labelled by `labels` as
/// `(rectangle, name)`.
fn labelled_rails(labels: &[(usize, &str)]) -> Loaded {
    let metal = LayerId(0);
    let mut layout = LayoutBuilder::new(1);
    let rects = [
        layout.rect(metal, 0, 0, 100, 100),
        layout.rect(metal, 90, 0, 200, 100),
        layout.rect(metal, 500, 0, 600, 100),
    ];
    let (store, ids) = layout.finish();
    let deck = Deck {
        connectivity: Connectivity {
            conductors: vec![metal],
            intra_layer_touch: true,
            ..Connectivity::default()
        },
        ..Deck::default()
    };
    let mut loaded = empty_loaded(store, deck);
    for &(rect, name) in labels {
        let name = loaded.strings.intern(name);
        loaded.provenance.label(ids.of(rects[rect]), name);
    }
    loaded
}

/// Testing-plan F14. Two labels on one net, a short between named nets, used
/// to abort extraction with no report row. It extracts, keeping both names
/// (LVS reports it as `lvs.net_seed_conflict`), and ERC refuses design intent
/// on it rather than resolve the net by one of its names, which would drop
/// the other's supply. The same intent on the unshorted layout runs.
///
/// Oracle: construct-from-answer, with `run_checks`' doc (a net with two labels
/// keeps both): rectangles 0 and 1 touch, so `VDD` and `VSS` on them are one
/// net and ERC refuses intent on it; on 0 and 2 they are two nets and ERC runs.
#[test]
fn a_short_between_labelled_nets_extracts_and_intent_on_it_is_refused() {
    let intent = r#"{"domains": {"core": {"voltage_mv": 1800}},
        "supplies": [{"net": "VDD", "domain": "core", "role": "power"},
                     {"net": "VSS", "domain": "core", "role": "ground"}]}"#;
    for (labels, shorted) in [
        (&[(0, "VDD"), (1, "VSS")][..], true),
        (&[(0, "VDD"), (2, "VSS")][..], false),
    ] {
        let mut loaded = labelled_rails(labels);
        let extracted = extract(&loaded).expect("a labelled short is not an extraction error");
        let vdd = loaded.strings.get("VDD").expect("labelled");
        let net = extracted.ports.net_of(vdd).expect("VDD is on one net");
        assert_eq!(
            extracted.ports.names_of(net).len(),
            if shorted { 2 } else { 1 }
        );

        loaded.intent = Some(
            gpurify_ingest::intent::parse_intent(intent, &mut loaded.strings)
                .expect("valid intent"),
        );
        let (_, summary) = run_checks(&loaded, &extracted, &options(Checks { erc: true, ..NONE }))
            .expect("the stage reports, it does not fail");
        match summary.erc {
            StageStatus::Refused(why) => {
                assert!(shorted && why.contains("VDD, VSS"), "{why}");
            }
            status => assert!(!shorted && status == StageStatus::Ran, "{status:?}"),
        }
    }
}

/// Testing-plan F14. A name on two disconnected nets is one net in two
/// pieces, an open; field-solving "the" net of that name would solve one
/// piece, so PEX refuses it by name (`a_quasistatic_net_is_solved_for_inductance_too`
/// is the name on one net).
///
/// Oracle: construct-from-answer. Rectangles 0 and 2 are apart, so `A` names
/// two nets, and the field solve refuses it by name rather than solve one
/// piece.
#[test]
fn a_quasistatic_name_on_two_nets_is_refused() {
    let loaded = labelled_rails(&[(0, "A"), (2, "A")]);
    let extracted = extract(&loaded).expect("an open is not an extraction error");
    let mut opts = options(Checks { pex: true, ..NONE });
    opts.quasistatic_nets = vec!["A".to_owned()];
    let (_, summary) = run_checks(&loaded, &extracted, &opts).expect("refused, not failed");
    assert!(
        matches!(&summary.pex, StageStatus::Refused(why) if why.contains("A labels 2 disconnected nets")),
        "{:?}",
        summary.pex
    );
}

/// Nothing selected: four declines, no output, and a pass.
///
/// Oracle: `Summary::passed`'s documented criterion (no errors, no skipped
/// rule, no selected stage skipped or refused): with nothing selected each
/// stage is `NotSelected`, nothing is produced, and the run passes.
#[test]
fn a_run_selecting_no_check_reports_four_declines_and_passes() {
    let loaded = empty_loaded(GeometryStore::default(), Deck::default());
    let extracted = extract(&loaded).expect("empty extracts");
    let (out, summary) = run_checks(&loaded, &extracted, &options(NONE)).expect("cannot fail");
    for status in [&summary.drc, &summary.erc, &summary.lvs, &summary.pex] {
        assert_eq!(status, &StageStatus::NotSelected);
    }
    assert!(out.runs.is_empty() && out.violations.is_empty());
    assert!(out.lvs.is_none() && out.parasitics.is_none());
    assert!(summary.passed());
}

/// One four-terminal transistor in one subcircuit, so `top` is unambiguous.
fn reference_with_one_transistor() -> Netlist {
    Netlist {
        subckt_name: vec![StrId(2)],
        subckt_port_start: vec![0, 0],
        port_net: Vec::new(),
        subckt_device_start: vec![0, 1],
        device_model: vec![StrId(1)],
        device_kind: vec![DeviceKind::Mos],
        device_terminal_start: vec![0, 4],
        terminal_net: vec![RefNetId(0), RefNetId(1), RefNetId(2), RefNetId(3)],
        device_param_start: vec![0, 0],
        param: Vec::new(),
        net_name: vec![StrId(4), StrId(5), StrId(6), StrId(7)],
        net_subckt: vec![SubcktId(0); 4],
        ..Netlist::default()
    }
}

/// Without a reference LVS is skipped (not a match) and blocks the pass. With
/// one against an empty layout it runs, files its five check rows, and every
/// discrepancy is an error.
///
/// Oracle: `docs/usage.md` ("a check whose input is missing is reported as
/// skipped, never as passed") and construct-from-answer: a one-transistor
/// reference against an empty layout leaves that device unpaired and nothing on
/// the layout side, each discrepancy an error.
#[test]
fn lvs_is_skipped_without_a_reference_and_a_mismatch_fails_the_run_with_one() {
    let lvs = Checks { lvs: true, ..NONE };
    let mut loaded = empty_loaded(GeometryStore::default(), Deck::default());
    let extracted = extract(&loaded).expect("empty extracts");

    let (out, summary) = run_checks(&loaded, &extracted, &options(lvs)).expect("a skip");
    assert!(matches!(summary.lvs, StageStatus::Skipped(_)));
    assert!(out.lvs.is_none());
    assert!(!summary.passed());

    loaded.reference = Some(reference_with_one_transistor());
    let (out, summary) = run_checks(&loaded, &extracted, &options(lvs)).expect("a comparison");
    assert_eq!(summary.lvs, StageStatus::Ran);
    // The five layout checks, every one run and clean: an unconfigurable
    // check records no row, so it cannot keep a clean comparison from passing.
    assert_eq!(out.runs.len(), 5);
    assert_eq!((summary.rules_clean, summary.rules_skipped), (5, 0));
    let Some(Verdict::Mismatch(found)) = &out.lvs else {
        panic!(
            "a one-device reference against an empty layout is a mismatch: {:?}",
            out.lvs
        );
    };
    assert!(found.contains(&Discrepancy::UnpairedDevice {
        side: Side::Reference,
        device: 0,
        model: StrId(1),
    }));
    assert!(!found.iter().any(|d| matches!(
        d,
        Discrepancy::UnpairedDevice {
            side: Side::Layout,
            ..
        }
    )));
    assert_eq!(out.violations.len(), found.len());
    assert_eq!(
        (summary.errors as usize, summary.warnings),
        (found.len(), 0)
    );
    assert!(!summary.passed());
}

/// One deck may hold both domains' kinds; a kind in neither is refused when
/// the deck compiles, before any check is selected, so a misspelling cannot
/// hide behind a DRC-only run. The parser refuses a spelling it does not
/// know, so the unknown kind is written into a parsed deck's table.
/// Oracle: construct-from-answer: `min_widht` is no kind; `width` and
/// `ir_drop` are one domain's each.
#[test]
fn a_kind_in_neither_domain_is_refused_when_the_deck_compiles() {
    const TEXT: &str = "grid 1nm
layer m = gds(1, 0)
rule a width(m) >= 10nm
rule b ir_drop()
";
    let mut strings = StrTable::default();
    let both = parse_deck(TEXT, grid(), &mut strings).expect("parses");
    let compiled = CompiledDeck::from_deck(both, grid(), &strings).expect("both kinds are known");
    assert_eq!((compiled.drc.rule_count(), compiled.erc.len()), (1, 1));

    let mut misspelled = parse_deck(TEXT, grid(), &mut strings).expect("parses");
    misspelled.rules.spec[0].kind = strings.intern("min_widht");
    let error = CompiledDeck::from_deck(misspelled, grid(), &strings)
        .expect_err("min_widht is nobody's rule kind");
    assert!(
        matches!(error, CompileError::Drc(DrcError::UnknownKind { ref kind, .. }) if kind == "min_widht"),
        "{error:?}"
    );
}

/// A field-solved net gains inductance and keeps its capacitive elements; the
/// analytical extraction alone carries none.
///
/// Oracle: `docs/usage.md`'s `--quasistatic` ("Field-solve this net's
/// capacitance and inductance"): the analytical run carries no inductance, the
/// field-solved one at least one, and no fewer capacitive elements.
#[test]
fn a_quasistatic_net_is_solved_for_inductance_too() {
    use gpurify_extract::Parasitic;

    let fixtures = gen_fixtures::fixtures();
    let inputs = Inputs {
        layout: fixtures.join("pex/PEX_COUPLING_C.gds"),
        deck: fixtures.join("params.deck"),
        ..Inputs::default()
    };
    let count = |quasistatic: bool, want_inductance: bool| -> usize {
        let mut opts = options(Checks { pex: true, ..NONE });
        if quasistatic {
            opts.quasistatic_nets = vec!["PEX_CC_n0".to_string(), "PEX_CC_n1".to_string()];
        }
        let (_, _, out, summary) = run(&inputs, &opts).expect("the coupling fixture field-solves");
        assert_eq!(summary.pex, StageStatus::Ran);
        out.parasitics.map_or(0, |network| {
            network
                .value
                .iter()
                .filter(|value| matches!(value, Parasitic::Inductance(_)) == want_inductance)
                .count()
        })
    };
    assert_eq!(count(false, true), 0);
    assert!(count(true, true) >= 1);
    assert!(count(true, false) >= count(false, false));
}

/// The pass criterion: errors, skipped rules, and skipped or refused stages
/// each block it; warnings and declined stages do not.
///
/// Oracle: `Summary::passed`'s documented criterion, one row per clause: an
/// error, a skipped rule and a skipped or refused stage each fail it; "Warnings
/// do not fail it", nor does a stage not selected.
#[test]
fn the_pass_criterion_table() {
    let clean = Summary {
        drc: StageStatus::Ran,
        erc: StageStatus::Ran,
        lvs: StageStatus::Ran,
        pex: StageStatus::Ran,
        violations: 0,
        errors: 0,
        warnings: 0,
        rules_clean: 17,
        rules_skipped: 0,
    };
    let skipped = || StageStatus::Skipped("a required input was absent");
    let refused = || StageStatus::Refused("not rectilinear".to_string());
    let cases = [
        ("clean", clean.clone(), true),
        (
            "a skipped rule",
            Summary {
                rules_skipped: 1,
                ..clean.clone()
            },
            false,
        ),
        (
            "an error",
            Summary {
                violations: 1,
                errors: 1,
                ..clean.clone()
            },
            false,
        ),
        (
            "a warning",
            Summary {
                violations: 1,
                warnings: 1,
                ..clean.clone()
            },
            true,
        ),
        (
            "drc skipped",
            Summary {
                drc: skipped(),
                ..clean.clone()
            },
            false,
        ),
        (
            "erc refused",
            Summary {
                erc: refused(),
                ..clean.clone()
            },
            false,
        ),
        (
            "lvs skipped",
            Summary {
                lvs: skipped(),
                ..clean.clone()
            },
            false,
        ),
        (
            "pex refused",
            Summary {
                pex: refused(),
                ..clean.clone()
            },
            false,
        ),
        (
            "nothing selected",
            Summary {
                drc: StageStatus::NotSelected,
                erc: StageStatus::NotSelected,
                lvs: StageStatus::NotSelected,
                pex: StageStatus::NotSelected,
                rules_clean: 0,
                ..clean.clone()
            },
            true,
        ),
    ];
    for (what, summary, passes) in cases {
        assert_eq!(summary.passed(), passes, "{what}: {summary:?}");
    }
}

/// LVS of `rects` on the shipped sky130 deck against the SPICE `reference`:
/// the verdict and the violations' rule ids.
fn sky130_lvs(rects: &[(&str, i64, i64, i64, i64)], reference: &str) -> (Verdict, Vec<String>) {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/pdks/sky130.deck"))
        .expect("the shipped deck is readable");
    let mut strings = StrTable::default();
    let deck = parse_deck(&source, grid(), &mut strings).expect("sky130.deck parses");
    let mut layout = LayoutBuilder::new(deck.layers.len());
    for &(name, xlo, ylo, xhi, yhi) in rects {
        let layer = deck.layers.id(&strings, name).expect("a sky130 layer");
        layout.rect(layer, xlo, ylo, xhi, yhi);
    }
    let (base, _) = layout.finish();

    let mut bytes = Vec::new();
    gpurify_testgen::gds::write_store(&base, &deck.layers, "TOP", &mut bytes).expect("writable");
    let (store, provenance) = gpurify_ingest::layout::gds::Library::parse(&bytes, &mut strings)
        .expect("parses")
        .flatten(
            &deck,
            &strings,
            gpurify_ingest::layout::UnknownLayers::Reject,
        )
        .expect("reads back");
    let reference = gpurify_ingest::netlist::spice::read(reference, &mut strings, &deck.devices)
        .expect("the reference parses");
    gpurify::engine::pipeline::intern_report_ids(&mut strings);
    let deck = CompiledDeck::from_deck(deck, grid(), &strings).expect("sky130.deck compiles");
    let loaded = Loaded {
        strings,
        grid: grid(),
        deck,
        store,
        provenance,
        reference: Some(reference),
        intent: None,
        design: None,
    };
    let extracted = extract(&loaded).expect("extracts");
    let (out, summary) =
        run_checks(&loaded, &extracted, &options(Checks { lvs: true, ..NONE })).expect("runs");
    assert_eq!(summary.lvs, StageStatus::Ran);
    let rules = out
        .violations
        .rule
        .iter()
        .map(|&rule| loaded.strings.resolve(rule).to_owned())
        .collect();
    (out.lvs.expect("a reference was given"), rules)
}

/// Oracle: construct-from-answer, on the shipped sky130 deck. One NMOS and no
/// p-tap: its bulk is the substrate under the diffusion (`connect global
/// psub`), a net with no tap and no label. The reference states the bulk on a
/// net of its own, so the NMOS matches and nothing floats. Reported by the
/// Philis session.
#[test]
fn an_nmos_bulk_on_the_untapped_substrate_does_not_fail_lvs() {
    let nmos = [
        ("diff", 0, 0, 1_000, 1_000),
        ("nsdm", -200, -200, 1_200, 1_200),
        ("poly", 450, -200, 600, 1_200),
    ];
    let reference = ".subckt top\nM1 d g s b sky130_fd_pr__nfet_01v8\n.ends\n";
    let (verdict, rules) = sky130_lvs(&nmos, reference);
    assert!(matches!(verdict, Verdict::Match), "{verdict:?}");
    assert!(rules.is_empty(), "no floating net: {rules:?}");
}

/// A PMOS in an n-well, its bulk tied to its source in the reference. With
/// no n-tap the well is a net of its own and LVS must not match (netgen
/// fails the same layout); an n-tap strapped to the source by li matches.
/// Oracle: the field report's floating-well strongarm, reduced to one device.
#[test]
fn a_pmos_in_an_untapped_well_fails_lvs_and_a_tapped_one_matches() {
    let pmos = [
        ("nwell", -1_500, -500, 1_500, 1_500),
        ("diff", 0, 0, 1_000, 1_000),
        ("psdm", -100, -200, 1_200, 1_200),
        ("poly", 450, -200, 600, 1_200),
        ("licon", 100, 400, 270, 570),
        ("li", 50, 350, 320, 620),
    ];
    let tap = [
        ("tap", -1_000, 0, -500, 1_000),
        ("nsdm", -1_125, -125, -375, 1_125),
        ("licon", -850, 400, -680, 570),
        ("li", -900, 350, 320, 620),
    ];
    let reference = ".subckt top\nM1 d g s s sky130_fd_pr__pfet_01v8\n.ends\n";

    let (verdict, _) = sky130_lvs(&pmos, reference);
    assert!(
        !matches!(verdict, Verdict::Match),
        "a floating well matched"
    );

    let tapped: Vec<_> = pmos.iter().chain(&tap).copied().collect();
    let (verdict, rules) = sky130_lvs(&tapped, reference);
    assert!(matches!(verdict, Verdict::Match), "{verdict:?} {rules:?}");
}

/// FLOW-005: live DRC from one shared deck. A consumer that edits a layout
/// (a router or an editor, as Philis is) parses the shipped deck once
/// through the library (`gpurify_ingest::deck::parse_deck`), compiles its
/// DRC rows once (`drc::RuleSet::from_deck`), and checks each edit of a
/// layout it holds in memory (`GeometryStoreBuilder`,
/// `gpurify_ingest::layout::derive_layers`, `RuleSet::run`): no file, no CLI.
///
/// Oracle: the foundry rule at the limit (FR), the sky130 periphery rules
/// m1.1 and m1.2, met1 width and spacing 0.14 um (`pdks/sky130.deck` [S1]):
/// two met1 wires 140 nm wide and 140 nm apart break neither; the first
/// narrowed by one 5 nm deck grid step is one m1.1 finding of 135 nm, and
/// the gap closed by one step one m1.2 finding of 135 nm. And a metamorphic
/// relation (MR): the shared deck gives each edit the whole report a deck
/// parsed afresh for that edit gives, and undoing an edit gives back the
/// report from before it, so checking leaves nothing behind in the deck. A
/// rule table that carries state from one check to the next, or a library
/// path that reads the deck otherwise than the run does, breaks it.
#[test]
fn a_consumer_checks_each_edit_against_one_shared_deck() {
    use gpurify_check::drc::RuleSet;
    use gpurify_check::report::{Measurement, Violations};

    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/pdks/sky130.deck"))
        .expect("the shipped deck is readable");
    let compile = || {
        let mut strings = StrTable::default();
        let deck = parse_deck(&source, grid(), &mut strings).expect("sky130.deck parses");
        let rules = RuleSet::from_deck(&deck, &strings).expect("its DRC rows compile");
        (strings, deck, rules)
    };
    // One edit: two met1 wires 2 um tall, the first `width` wide and the
    // second 140 nm, `gap` apart. Its report as sorted text, and its
    // findings as `(rule, measured)`.
    let check = |(strings, deck, rules): &(StrTable, Deck, RuleSet), (width, gap): (i64, i64)| {
        let met1 = deck.layers.id(strings, "met1").expect("a sky130 layer");
        let mut builder = GeometryStoreBuilder::default();
        for (xlo, xhi) in [(0, width), (width + gap, width + gap + 140)] {
            builder.push(
                met1,
                &[xlo, xhi, xhi, xlo].map(dbu),
                &[0, 0, 2_000, 2_000].map(dbu),
            );
        }
        let (mut store, _) = builder.finish(deck.layers.len());
        gpurify_ingest::layout::derive_layers(&mut store, deck, &Provenance::default(), strings)
            .expect("the derived layers compute");
        let (mut out, mut runs) = (Violations::default(), Vec::new());
        rules.run(&store, &mut out, &mut runs);
        let name = |id| strings.resolve(id).to_owned();
        let findings: Vec<(String, Measurement)> = (0..out.len())
            .map(|row| (name(out.get(row).rule), out.get(row).measured))
            .collect();
        let mut text: Vec<String> = runs
            .iter()
            .map(|run| format!("{} {:?} {}", name(run.rule), run.outcome, run.examined))
            .chain((0..out.len()).map(|row| {
                let v = out.get(row);
                format!("{} {:?} {:?}", name(v.rule), v.measured, v.at)
            }))
            .collect();
        text.sort();
        (text, findings)
    };

    let shared = compile();
    let edits = [(140, 140), (135, 140), (140, 140), (140, 135), (140, 140)];
    let reports: Vec<_> = edits.iter().map(|&edit| check(&shared, edit)).collect();
    for (&edit, report) in edits.iter().zip(&reports) {
        assert_eq!(
            report.0,
            check(&compile(), edit).0,
            "{edit:?}: the shared deck and a fresh one"
        );
    }
    assert_eq!(reports[0].0, reports[2].0, "the narrowing undone");
    assert_eq!(reports[0].0, reports[4].0, "the gap undone");
    for rule in ["m1.1", "m1.2"] {
        assert!(
            reports[0]
                .0
                .iter()
                .any(|line| line.starts_with(&format!("{rule} Ran "))),
            "{rule} runs: {:?}",
            reports[0].0
        );
    }
    let of = |k: usize, rule: &str| -> Vec<Measurement> {
        let found = reports[k].1.iter().filter(|(r, _)| r == rule);
        found.map(|&(_, measured)| measured).collect()
    };
    let nm = |n| vec![Measurement::Length(dbu(n))];
    assert_eq!(
        (of(0, "m1.1"), of(0, "m1.2")),
        (vec![], vec![]),
        "at the limit"
    );
    assert_eq!(
        (of(1, "m1.1"), of(1, "m1.2")),
        (nm(135), vec![]),
        "narrowed"
    );
    assert_eq!((of(3, "m1.1"), of(3, "m1.2")), (vec![], nm(135)), "closer");
}
