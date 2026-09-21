//! The shared stages: what `load_into` reads first, and what `extract_into`
//! leaves behind.
//!
//! Two oracles here.
//!
//! **Construct-from-answer** for extraction: a store holding one overlapping
//! pair and one shape well away from it, on a single conductor layer, is two
//! nets — decided when the rectangles were placed, before any code ran. That
//! answer is stated as a partition of polygons rather than as a count, so a
//! stage that found the right *number* of the wrong nets fails.
//!
//! **Law** for the load order. `load_into`'s doc comment states the ordering as
//! a constraint rather than an incident: the deck's grid must be established
//! before the layout is read, because layer mapping happens during the read.
//! That makes the reader consulted first observable on an input where both
//! files are unreadable, without a test having to know either file format.

use gpurify_geom::{GeometryStoreBuilder, LayerId};
use gpurify_engine::pipeline::{
    extract_into, intern_report_ids, load_into, Extracted, Inputs, LoadError, Loaded,
};
use gpurify_engine::run::{run, run_checks, Checks, EngineError, Outputs, RunOptions};
use gpurify_ingest::deck::{parse_deck, Connectivity, Deck};
use gpurify_ingest::StrTable;
use gpurify_lvs::refine::TieBreak;
use gpurify_lvs::CompareOptions;
use gpurify_testgen::LayoutBuilder;
use gpurify_geom::Grid;
use std::path::PathBuf;

/// The single conductor layer every extraction case below lives on.
const METAL: LayerId = LayerId(0);

/// Oracle: law, from the stated ordering. Neither file can be opened, so the
/// error names whichever reader ran first. It must be the deck's: the grid has
/// to exist before the layout can be mapped onto it, so a `LoadError::Layout`
/// here means the layout was read against a grid that had not been established.
///
/// The grid is supplied, which is what makes the law observable rather than
/// vacuous — `load_into` reads [`Inputs::grid`] before it opens either file, so
/// an absent one would stop at [`LoadError::NoGrid`] and this test would never
/// reach the two readers it is about.
#[test]
fn the_deck_is_consulted_before_the_layout_when_neither_can_be_read() {
    let inputs = Inputs {
        layout: PathBuf::from("/nonexistent/design.gds"),
        deck: PathBuf::from("/nonexistent/process.json"),
        grid: Some(Grid::new(1_000).expect("1000 database units per micrometre is a legal grid")),
        ..Inputs::default()
    };
    let mut loaded = Loaded::default();

    let error =
        load_into(&inputs, &mut loaded).expect_err("neither input exists, so this cannot succeed");

    assert!(
        matches!(error, LoadError::Deck(_)),
        "both inputs were unreadable and the failure reported was {error:?}; the \
         deck establishes the grid the layout is read against, so the deck is \
         what fails first"
    );
}

/// Oracle: law, from the same stated ordering, on its other side. A run with no
/// grid stops before either path is touched, so the two unreadable files below
/// cannot be what is blamed. Writable as of the Testing-Phase, when `Inputs`
/// gained the field that carries the condition; `NoGrid` had no reachable
/// input before it.
#[test]
fn a_load_with_no_grid_stops_before_either_file_is_opened() {
    let inputs = Inputs {
        layout: PathBuf::from("/nonexistent/design.gds"),
        deck: PathBuf::from("/nonexistent/process.json"),
        grid: None,
        ..Inputs::default()
    };
    let mut loaded = Loaded::default();

    let error =
        load_into(&inputs, &mut loaded).expect_err("no grid was supplied, so this cannot succeed");

    assert!(
        matches!(error, LoadError::NoGrid),
        "a run without a grid reported {error:?}; the grid is read before either \
         file, so no reader can be what failed"
    );
}

/// Oracle: law, from the stated ordering. `run` is documented as sequencing
/// load, extract and check and doing nothing else, so a load that fails is a
/// load error and extraction is never reached. An `EngineError::Extract` from
/// unreadable inputs would mean the stages ran out of order.
#[test]
fn a_run_whose_inputs_cannot_be_read_fails_at_the_load_and_goes_no_further() {
    let inputs = Inputs {
        layout: PathBuf::from("/nonexistent/design.gds"),
        deck: PathBuf::from("/nonexistent/process.json"),
        grid: Some(Grid::new(1_000).expect("1000 database units per micrometre is a legal grid")),
        ..Inputs::default()
    };
    let mut out = Outputs::default();

    let error = run(&inputs, &run_options(), &mut out)
        .expect_err("neither input exists, so this cannot succeed");

    assert!(
        matches!(error, EngineError::Load(_)),
        "unreadable inputs produced {error:?}; nothing downstream of the load can \
         have run, so nothing downstream may be blamed"
    );
    assert!(
        out.violations.rule.is_empty() && out.runs.is_empty(),
        "a run that failed to load reported findings it cannot have made"
    );
}

/// Oracle: construct-from-answer. Two overlapping rectangles and one apart from
/// them, on one conductor layer, are two nets. The assertion is on the
/// partition and not on the count: `same_net` is checked for the pair that
/// overlaps and for a pair that does not, so an extraction returning two nets
/// with the wrong shapes in them fails.
#[test]
fn overlapping_shapes_on_a_conductor_extract_as_one_net_and_a_distant_one_as_another() {
    let mut layout = LayoutBuilder::new(1);
    let left = layout.rect(METAL, 0, 0, 100, 100);
    let right = layout.rect(METAL, 90, 0, 200, 100);
    let apart = layout.rect(METAL, 500, 0, 600, 100);
    let (store, ids) = layout.finish();

    let loaded = Loaded {
        store,
        deck: Deck {
            connectivity: one_conductor(),
            ..Deck::default()
        },
        ..Loaded::default()
    };
    let mut extracted = Extracted::default();

    extract_into(&loaded, &mut extracted).expect("a single conductor layer needs no derivation");

    assert_eq!(
        extracted.nets.net_count(),
        2,
        "three shapes, two of which overlap, are two nets"
    );
    assert!(
        extracted.nets.same_net(ids.of(left), ids.of(right)),
        "the two overlapping rectangles were split across nets"
    );
    assert!(
        !extracted.nets.same_net(ids.of(left), ids.of(apart)),
        "a rectangle 400 units away was joined to one it does not touch, which is \
         a net merge and the failure a connectivity bug produces"
    );
}

/// Oracle: construct-from-answer, applied twice. `extract_into` takes a
/// caller-owned buffer, and the whole reason a caller holds one is to run a
/// second layout through it. A buffer that is appended to rather than refilled
/// doubles the net count on the second call, which is the specific bug this
/// catches — an empty design would not, because zero doubled is still zero.
#[test]
fn extracting_twice_into_one_buffer_gives_the_same_answer_as_extracting_once() {
    let mut layout = LayoutBuilder::new(1);
    let left = layout.rect(METAL, 0, 0, 100, 100);
    let right = layout.rect(METAL, 90, 0, 200, 100);
    layout.rect(METAL, 500, 0, 600, 100);
    let (store, ids) = layout.finish();

    let loaded = Loaded {
        store,
        deck: Deck {
            connectivity: one_conductor(),
            ..Deck::default()
        },
        ..Loaded::default()
    };
    let mut extracted = Extracted::default();

    extract_into(&loaded, &mut extracted).expect("a single conductor layer needs no derivation");
    let first = extracted.nets.net_count();
    extract_into(&loaded, &mut extracted).expect("a single conductor layer needs no derivation");

    assert_eq!(
        extracted.nets.net_count(),
        first,
        "the second extraction into the same buffer changed the net count, so the \
         buffer is being appended to rather than refilled"
    );
    assert_eq!(first, 2, "three shapes, two of which overlap, are two nets");
    assert!(
        extracted.nets.same_net(ids.of(left), ids.of(right)),
        "the partition did not survive being extracted into a reused buffer"
    );
}

/// Oracle: construct-from-answer. An empty design has nothing to derive, no
/// nets, no devices and no ports — and that is a successful extraction, not an
/// error. `ExtractError` names only a derivation failure and a port binding
/// failure, neither of which an empty store can reach.
#[test]
fn an_empty_design_extracts_to_empty_tables_without_failing() {
    let loaded = Loaded::default();
    let mut extracted = Extracted::default();

    extract_into(&loaded, &mut extracted).expect("an empty design is extractable, not an error");

    assert_eq!(extracted.nets.net_count(), 0, "no geometry, no nets");
    assert_eq!(extracted.devices.len(), 0, "no geometry, no devices");
    assert_eq!(extracted.ports.len(), 0, "no labels, no ports");
}

/// Oracle: construct-from-answer, on identity rather than on values.
/// `Extraction` exists so three tables cross a call together, and its doc
/// comment says the risk it removes is a silent transposition. The three
/// references must therefore be into the `Extracted` that produced them: a
/// borrow of anything else — a leaked default, a field of the wrong owner —
/// type-checks and would hand every downstream check the wrong tables.
#[test]
fn as_extraction_borrows_the_three_tables_of_the_extraction_it_was_called_on() {
    let extracted = Extracted::default();
    let view = extracted.as_extraction();

    assert!(
        std::ptr::eq(view.nets, &raw const extracted.nets),
        "the view's net table is not this extraction's net table"
    );
    assert!(
        std::ptr::eq(view.devices, &raw const extracted.devices),
        "the view's device table is not this extraction's device table"
    );
    assert!(
        std::ptr::eq(view.ports, &raw const extracted.ports),
        "the view's port table is not this extraction's port table"
    );
}

/// One conductor layer whose shapes connect by touching. The smallest
/// connectivity a net extraction can act on, and the one every case above uses.
fn one_conductor() -> Connectivity {
    Connectivity {
        conductors: vec![METAL],
        via_cut: Vec::new(),
        via_connects: Vec::new(),
        intra_layer_touch: true,
        ..Connectivity::default()
    }
}

/// Every field written out rather than `CompareOptions::default()`, whose body
/// is a `todo!()` until Phase 4 — a fixture that panics before the function
/// under test is reached turns every failure into the same failure.
fn run_options() -> RunOptions {
    RunOptions {
        checks: Checks::ALL,
        lvs: CompareOptions {
            max_rounds: 64,
            tie_break: TieBreak::LowestIndex,
            param_tolerance: 1e-3,
            match_names: false,
        },
        quasistatic_nets: Vec::new(),
        quasistatic_inductance: false,
        threads: Some(1),
    }
}

/// Oracle: law, from `intern_report_ids`'s doc comment. An embedder builds
/// `Loaded` by hand — deck from an in-memory string, geometry from the builder,
/// no file ever opened — and the seam must leave the string table exactly as
/// `load_into` would have: every LVS report id resolvable before a check runs.
#[test]
fn a_hand_built_loaded_runs_checks_once_its_report_ids_are_interned() {
    use gpurify_testgen::shapes::dbu;

    let grid = Grid::new(1_000).expect("1000 database units per micrometre is a legal grid");
    let mut strings = StrTable::default();
    let deck = parse_deck(r#"{"layers": {"met1": [68, 20]}}"#, grid, &mut strings)
        .expect("a one-layer deck parses");

    let mut builder = GeometryStoreBuilder::default();
    builder.push_rect(METAL, dbu(0), dbu(0), dbu(100), dbu(100));
    let (store, _) = builder.finish(deck.layers.len());

    let mut loaded = Loaded {
        strings,
        grid: Some(grid),
        deck,
        store,
        ..Loaded::default()
    };
    intern_report_ids(&mut loaded.strings);

    // The two ends of the id lists `load_into` interned through this same
    // seam: resolvable, and round-tripping to the constant they were made from.
    for id in ["lvs.unpaired_device", "lvs.terminal_count"] {
        let interned = loaded
            .strings
            .get(id)
            .unwrap_or_else(|| panic!("{id} did not intern, and a finding filed under it panics"));
        assert_eq!(loaded.strings.resolve(interned), id);
    }

    let mut extracted = Extracted::default();
    extract_into(&loaded, &mut extracted).expect("one undecorated layer extracts");

    let mut options = run_options();
    options.checks = Checks {
        drc: true,
        erc: false,
        lvs: false,
        pex: false,
    };
    let mut out = Outputs::default();
    run_checks(&loaded, &extracted, &options, &mut out)
        .expect("a drc-only run over a hand-built Loaded must not fail");
}

/// Oracle: law, from `refuse_conducting_channels`'s doc comment, at the seam
/// every caller routes through. A deck in the pre-split style — the raw
/// diffusion is both the conductor and the MOS source/drain terminal layer,
/// and the implant-shaped marker overlaps it with area — must fail extraction
/// with a channel refusal, not extract a transistor whose source and drain
/// share a net. Silence here is a short reported as clean, which is the
/// engine's old ceiling; the refusal is what removed it.
#[test]
fn a_deck_that_leaves_raw_diffusion_conducting_under_a_mos_marker_is_refused() {
    use gpurify_testgen::shapes::dbu;

    let grid = Grid::new(1_000).expect("1000 database units per micrometre is a legal grid");
    let mut strings = StrTable::default();
    let deck = parse_deck(
        r#"{
          "layers": { "diff": [65, 20], "poly": [66, 20], "nsdm": [93, 44] },
          "connectivity": {
            "conductors": ["diff", "poly"],
            "intra_layer_touch": true
          },
          "device_recognition": [
            { "kind": "mos", "marker": "nsdm", "model": "nfet",
              "terminals": ["poly", "diff", "diff"] }
          ]
        }"#,
        grid,
        &mut strings,
    )
    .expect("the pre-split deck still parses; the refusal is geometric, not schematic");

    let diff = deck.layers.id(&strings, "diff").expect("declared");
    let poly = deck.layers.id(&strings, "poly").expect("declared");
    let nsdm = deck.layers.id(&strings, "nsdm").expect("declared");

    // One transistor as the old corpus drew it: one diffusion rectangle
    // spanning the channel, a gate crossing it, the implant over the lot.
    let mut builder = GeometryStoreBuilder::default();
    builder.push_rect(diff, dbu(0), dbu(0), dbu(500), dbu(200));
    builder.push_rect(poly, dbu(200), dbu(-50), dbu(50), dbu(300));
    builder.push_rect(nsdm, dbu(-50), dbu(-50), dbu(600), dbu(300));
    let (store, _) = builder.finish(deck.layers.len());

    let mut loaded = Loaded {
        strings,
        grid: Some(grid),
        deck,
        store,
        ..Loaded::default()
    };
    intern_report_ids(&mut loaded.strings);

    let mut extracted = Extracted::default();
    let refused = extract_into(&loaded, &mut extracted)
        .expect_err("a conducting channel must refuse extraction, not merge S and D");
    assert!(
        matches!(refused, gpurify_engine::pipeline::ExtractError::Channel(_)),
        "the refusal must be the channel guard's, got {refused:?}"
    );
}
