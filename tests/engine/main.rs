//! `engine`: load order, extraction, stage statuses, and the pass criterion.

#[path = "../common/gen_fixtures.rs"]
mod gen_fixtures;

use gpurify::engine::pipeline::{extract, load, ExtractError, Inputs, LoadError, Loaded};
use gpurify::engine::run::{
    run, run_checks, Checks, EngineError, RunOptions, StageStatus, Summary,
};
use gpurify_check::drc::DrcError;
use gpurify_check::lvs::verdict::{Discrepancy, Side};
use gpurify_check::lvs::{CompareOptions, Verdict};
use gpurify_geom::{GeometryStore, GeometryStoreBuilder, Grid, LayerId};
use gpurify_ingest::deck::{parse_deck, Connectivity, Deck, DeviceKind, RuleSpec};
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
        quasistatic_inductance: false,
        threads: Some(1),
    }
}

fn empty_loaded(store: GeometryStore, deck: Deck) -> Loaded {
    Loaded {
        strings: StrTable::default(),
        grid: grid(),
        deck,
        store,
        provenance: Provenance::default(),
        reference: None,
        intent: None,
    }
}

fn unreadable_inputs(grid: Option<Grid>) -> Inputs {
    Inputs {
        layout: PathBuf::from("/nonexistent/design.gds"),
        deck: PathBuf::from("/nonexistent/process.json"),
        grid,
        ..Inputs::default()
    }
}

/// The grid is checked before any file is opened, and the deck is read before
/// the layout; a failed load reaches no later stage.
#[test]
fn a_load_fails_on_the_grid_then_the_deck_before_the_layout() {
    assert!(matches!(
        load(&unreadable_inputs(None)),
        Err(LoadError::NoGrid)
    ));
    assert!(matches!(
        load(&unreadable_inputs(Some(grid()))),
        Err(LoadError::Deck(_))
    ));
    assert!(matches!(
        run(&unreadable_inputs(Some(grid())), &options(Checks::ALL)),
        Err(EngineError::Load(_))
    ));
}

/// Two overlapping rectangles are one net and a distant one another; an empty
/// design extracts to empty tables.
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
#[test]
fn a_deck_that_leaves_raw_diffusion_conducting_under_a_mos_marker_is_refused() {
    let mut strings = StrTable::default();
    let deck = parse_deck(
        r#"{
          "layers": { "diff": [65, 20], "poly": [66, 20], "nsdm": [93, 44] },
          "connectivity": { "conductors": ["diff", "poly"], "intra_layer_touch": true },
          "device_recognition": [
            { "kind": "mos", "marker": "nsdm", "model": "nfet",
              "terminals": ["poly", "diff", "diff"] }
          ]
        }"#,
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

/// Nothing selected: four declines, no output, and a pass.
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
        device_name: vec![StrId(3)],
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
/// one against an empty layout it runs, files its eight check rows (three
/// deliberately unconfigured, so skipped), and every discrepancy is an error.
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
    assert_eq!(out.runs.len(), 8);
    assert_eq!((summary.rules_clean, summary.rules_skipped), (5, 3));
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

fn loaded_with_rule_kinds(kinds: &[&str]) -> Loaded {
    let mut loaded = empty_loaded(GeometryStore::default(), Deck::default());
    for (at, kind) in kinds.iter().enumerate() {
        let id = loaded.strings.intern(&format!("rule.{at}"));
        let kind = loaded.strings.intern(kind);
        loaded.deck.rules.spec.push(RuleSpec {
            id,
            kind,
            layer_start: 0,
            layer_len: 0,
            param_start: 0,
            param_len: 0,
        });
    }
    loaded
}

/// One deck may hold both domains' kinds; a kind in neither is refused even
/// when no check is selected, so a misspelling cannot hide behind a DRC-only run.
#[test]
fn a_kind_in_neither_domain_is_refused_whatever_was_selected() {
    let both = loaded_with_rule_kinds(&["min_width", "antenna_electrical"]);
    let extracted = extract(&both).expect("empty extracts");
    run_checks(&both, &extracted, &options(NONE)).expect("both kinds are known");

    let misspelled = loaded_with_rule_kinds(&["min_width", "min_widht"]);
    let error = run_checks(&misspelled, &extracted, &options(NONE))
        .expect_err("min_widht is nobody's rule kind");
    assert!(
        matches!(error, EngineError::Drc(DrcError::UnknownKind { ref kind, .. }) if kind == "min_widht"),
        "{error:?}"
    );
}

/// Off, the network holds no inductance; on, the field-solved nets gain some
/// and keep their capacitive elements.
#[test]
fn the_inductance_flag_adds_elements_only_when_asked() {
    use gpurify_extract::Parasitic;

    let fixtures = gen_fixtures::fixtures();
    let inputs = Inputs {
        layout: fixtures.join("pex/PEX_COUPLING_C.gds"),
        deck: fixtures.join("params.json"),
        grid: Some(grid()),
        ..Inputs::default()
    };
    let count = |inductance: bool, want_inductance: bool| -> usize {
        let mut opts = options(Checks { pex: true, ..NONE });
        opts.quasistatic_nets = vec!["PEX_CC_n0".to_string(), "PEX_CC_n1".to_string()];
        opts.quasistatic_inductance = inductance;
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
