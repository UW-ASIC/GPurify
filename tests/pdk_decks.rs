//! The decks in `pdks/` are inputs this repository ships, and nothing read one.
//!
//! Every other test in the workspace builds its own deck text, so the four
//! files a user actually points the tool at were never parsed by anything. That
//! is how all four came to sit in the *previous* tree's schema, two of them with
//! no `rules` section at all, without a single test going red: an absent section
//! is not a parse error, it is an empty [`RuleTable`], and an empty rule table
//! runs no checks and reports a clean pass. A PDK that configures no rules is
//! not a PDK, it is a deck-shaped file that certifies everything.
//!
//! # The oracle
//!
//! **Construct-from-answer**, with the answer stated as a property rather than
//! a number: whatever a deck says, if `drc` and `erc` cannot build a rule from
//! it, or a rule names a layer the deck never declared, or a conductor has no
//! sheet resistance, then the tool's verdict on that PDK is decided by what is
//! *missing* from the file. No expected value below was read off a run.
//!
//! # Why the workspace root
//!
//! Same reason as `tests/test_all.rs`: this needs `ingest`, `drc` and `erc` at
//! once and belongs to none of them.
//!
//! # Why the directory is read rather than listed
//!
//! A hard-coded list is a list someone has to remember to extend, and the fifth
//! PDK added the week after this lands is exactly the one nobody would. The
//! discovery is therefore the first thing asserted: an empty `pdks/` would make
//! every loop below pass vacuously, which is the same false clean in the test
//! suite that the tests themselves exist to prevent in the tool.

use gpurify::geom::Grid;
use gpurify::geom::LayerId;
use gpurify::ingest::deck::{Deck, DeviceKind, ParamValue};
use gpurify::ingest::StrTable;
use std::path::{Path, PathBuf};

/// The grid every deck in `pdks/` is authored against — `pdks/README.md` states
/// it, and a limit that is not an exact multiple of it is `DeckError::OffGrid`
/// rather than a rounded limit. Loading at this resolution is therefore itself
/// a check that the published numbers land on the pitch they claim.
const DBU_PER_UM: i64 = 1000;

/// Every `*.json` under `pdks/`, sorted, discovered by reading the directory.
fn deck_files() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("pdks");
    let mut found: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|why| panic!("pdks/ must be readable at {}: {why}", dir.display()))
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    found.sort();

    assert!(
        !found.is_empty(),
        "no deck was discovered in {}, so every assertion in this file would \
         pass without examining anything — which is the failure mode these \
         tests exist to close, reproduced inside the test suite",
        dir.display()
    );
    found
}

/// The deck's file name, for a message that names which of the four broke.
fn name_of(path: &Path) -> &str {
    path.file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("<unnameable deck>")
}

/// Parse one deck, or fail naming the file and the refusal.
fn load(path: &Path) -> (Deck, StrTable) {
    let source =
        std::fs::read_to_string(path).unwrap_or_else(|why| panic!("{}: {why}", path.display()));
    let grid = Grid::new(DBU_PER_UM).expect("a thousand database units per micrometre is a grid");
    let mut strings = StrTable::default();

    match gpurify::ingest::deck::parse_deck(&source, grid, &mut strings) {
        Ok(deck) => (deck, strings),
        Err(why) => panic!(
            "{} does not parse: {why}. A deck this tool ships is an input a user \
             points at directly, so a deck that cannot be read is a broken \
             release, not a broken test.",
            name_of(path)
        ),
    }
}

/// Oracle: construct-from-answer. Every shipped deck is a deck: it parses, and
/// both domains build a rule set from it.
#[test]
fn every_deck_in_pdks_parses_and_builds_both_rule_sets() {
    for path in deck_files() {
        let (deck, strings) = load(&path);

        gpurify::check::drc::RuleSet::from_deck(&deck, &strings).unwrap_or_else(|why| {
            panic!("{}: the DRC rule set does not build: {why}", name_of(&path))
        });
        gpurify::check::erc::RuleSet::from_deck(&deck, &strings).unwrap_or_else(|why| {
            panic!("{}: the ERC rule set does not build: {why}", name_of(&path))
        });
    }
}

/// Oracle: construct-from-answer. A deck configures at least one rule, and
/// every rule it configures is filed by exactly one domain.
#[test]
fn every_deck_configures_rules_and_every_rule_belongs_to_a_domain() {
    for path in deck_files() {
        let (deck, strings) = load(&path);
        let deck_name = name_of(&path);

        let drc =
            gpurify::check::drc::RuleSet::from_deck(&deck, &strings).expect("the DRC set builds");
        let erc =
            gpurify::check::erc::RuleSet::from_deck(&deck, &strings).expect("the ERC set builds");
        let filed = drc.rule_count() + erc.len();

        assert!(
            filed > 0,
            "{deck_name} configures no rule at all. It parses, it loads, and a \
             run over it finds nothing and exits zero — a clean report for a \
             design nothing examined."
        );
        assert_eq!(
            filed,
            deck.rules.spec.len(),
            "{deck_name} states {} rules and only {filed} are filed under a kind \
             either domain spells; the remainder are inert text in the file",
            deck.rules.spec.len()
        );
    }
}

/// Oracle: construct-from-answer. Every layer a rule names resolves back to the
/// same id through the layer table.
#[test]
fn every_layer_a_rule_names_resolves_in_the_layer_table() {
    for path in deck_files() {
        let (deck, strings) = load(&path);
        let deck_name = name_of(&path);

        for spec in &deck.rules.spec {
            let rule = strings.resolve(spec.id);
            let named = deck.rules.layers_of(spec).iter().copied().chain(
                deck.rules
                    .params_of(spec)
                    .iter()
                    .filter_map(|&(_, value)| match value {
                        ParamValue::Layer(layer) => Some(layer),
                        _ => None,
                    }),
            );

            for layer in named {
                assert!(
                    layer.idx() < deck.layers.len(),
                    "{deck_name}: rule {rule} names layer id {} and the table \
                     holds {} rows; a rule over a layer that is not there \
                     examines no geometry and reports clean",
                    layer.idx(),
                    deck.layers.len()
                );
                let name = strings.resolve(deck.layers.name(layer));
                assert_eq!(
                    deck.layers.id(&strings, name),
                    Some(layer),
                    "{deck_name}: rule {rule} names layer {name}, which does not \
                     resolve back to the id it was given; the name index and the \
                     name column disagree, so some lookups of this layer find it \
                     and others do not"
                );
            }
        }
    }
}

/// Oracle: construct-from-answer, against `erc::power`'s stated refusal.
#[test]
fn every_current_carrying_layer_has_a_sheet_resistance() {
    for path in deck_files() {
        let (deck, strings) = load(&path);
        let deck_name = name_of(&path);

        let carrying = deck
            .connectivity
            .conductors
            .iter()
            .chain(&deck.connectivity.via_cut);

        for &layer in carrying {
            let name = strings.resolve(deck.layers.name(layer));
            let ohms = deck
                .stack
                .sheet_res_ohm_sq
                .get(layer.idx())
                .copied()
                .unwrap_or(f64::NAN);

            assert!(
                ohms > 0.0 && ohms.is_finite(),
                "{deck_name}: {name} carries current and its pex stack gives it \
                 {ohms} ohms per square. erc::power refuses the entire stage on \
                 this, so the deck runs no IR-drop, no electromigration and no \
                 point-to-point resistance at all"
            );
        }

        assert!(
            !deck.connectivity.conductors.is_empty(),
            "{deck_name} declares no conductor, so every polygon extracts as its \
             own net and LVS reports a clean match for a chip that is not \
             connected"
        );
    }
}

/// Oracle: law — the stack is indexed by `LayerId`, so it is as long as the
/// layer table or it is empty.
#[test]
fn a_pex_stack_that_exists_has_one_row_per_declared_layer() {
    for path in deck_files() {
        let (deck, _strings) = load(&path);
        let deck_name = name_of(&path);
        let rows = deck.stack.sheet_res_ohm_sq.len();

        if rows == 0 {
            assert!(
                deck.connectivity.conductors.is_empty(),
                "{deck_name} declares conductors and no pex section at all; every \
                 parasitic it extracts would be zero"
            );
            continue;
        }

        for (column, len) in [
            ("thickness_nm", deck.stack.thickness_nm.len()),
            ("height_nm", deck.stack.height_nm.len()),
            ("sheet_res_ohm_sq", rows),
            ("area_cap_af_um2", deck.stack.area_cap_af_um2.len()),
            ("fringe_cap_af_um", deck.stack.fringe_cap_af_um.len()),
            ("dielectric_k", deck.stack.dielectric_k.len()),
        ] {
            assert_eq!(
                len,
                deck.layers.len(),
                "{deck_name}: the pex column {column} holds {len} rows for {} \
                 declared layers, and it is indexed by LayerId — the layers past \
                 the end read another layer's process parameters",
                deck.layers.len()
            );
        }
    }
}

/// Oracle: construct-from-answer. Every via row joins two layers the deck
/// declares as conductors.
#[test]
fn every_via_joins_two_declared_conductors() {
    for path in deck_files() {
        let (deck, strings) = load(&path);
        let deck_name = name_of(&path);

        let is_conductor = |layer: LayerId| deck.connectivity.conductors.contains(&layer);

        for (&cut, &(lower, upper)) in deck
            .connectivity
            .via_cut
            .iter()
            .zip(&deck.connectivity.via_connects)
        {
            let cut_name = strings.resolve(deck.layers.name(cut));
            for joined in [lower, upper] {
                let name = strings.resolve(deck.layers.name(joined));
                assert!(
                    is_conductor(joined),
                    "{deck_name}: via {cut_name} joins {name}, which the deck does \
                     not list as a conductor; the net stops at this via and LVS \
                     reads the two halves as an open"
                );
            }
        }
    }
}

/// Oracle: construct-from-answer. A deck pairs at least one text layer with a
/// conductor, so a port label has something to bind to.
#[test]
fn every_deck_pairs_a_text_layer_with_a_conductor() {
    for path in deck_files() {
        let (deck, strings) = load(&path);
        let deck_name = name_of(&path);

        assert!(
            !deck.connectivity.label_layer.is_empty(),
            "{deck_name}: connectivity.labels pairs no text layer with any \
             conductor, so every port label in a layout binds to nothing and \
             the extracted subcircuit comes out with no pins"
        );
        // `build_connectivity` refuses a pairing whose named layer is not a
        // conductor, so this only restates the column invariant the parse left.
        assert_eq!(
            deck.connectivity.label_layer.len(),
            deck.connectivity.label_names.len(),
            "{deck_name}: the label pairing columns are not parallel"
        );
        for &named in &deck.connectivity.label_names {
            let name = strings.resolve(deck.layers.name(named));
            assert!(
                deck.connectivity.conductors.contains(&named),
                "{deck_name}: a label row names {name}, which is not a conductor"
            );
        }
    }
}

/// Oracle: construct-from-answer, against `topology::device`'s stated rule —
/// "a marker whose positions are not all filled is skipped".
#[test]
fn every_mos_terminal_names_a_conductor() {
    for path in deck_files() {
        let (deck, strings) = load(&path);
        let deck_name = name_of(&path);
        let devices = &deck.devices;

        for row in 0..devices.kind.len() {
            if devices.kind[row] != DeviceKind::Mos {
                continue;
            }
            let model = strings.resolve(devices.model[row]);
            let span =
                devices.terminal_start[row] as usize..devices.terminal_start[row + 1] as usize;
            for &terminal in &devices.terminal[span] {
                let name = strings.resolve(deck.layers.name(terminal));
                assert!(
                    deck.connectivity.conductors.contains(&terminal),
                    "{deck_name}: the {model} recogniser puts a terminal on \
                     {name}, which the deck does not list as a conductor; that \
                     position can never be filled, so every {model} in a layout \
                     is silently dropped from the extraction"
                );
            }
        }
    }
}
