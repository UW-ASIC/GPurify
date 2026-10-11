//! The printer is the parser's inverse: a deck shared as text is the deck
//! (deck-library plan §4.7, testing-plan L9b "a shared deck survives
//! printing").
//!
//! Oracle: round trip. `compile(print(d))` in the same string table equals
//! `d`, typed rule by typed rule and layer by layer, and printing that again
//! gives the same text.

use super::{grid, twins, DECKS};
use gpurify_check::deck::{compile, print, BuildError, CompiledDeck, Origin};
use gpurify_geom::StrTable;

/// `deck` printed, compiled back into `strings`, equal to itself, and
/// printed again to the same text. Text states no provenance: every rule of
/// the deck read back is the base deck's own.
pub(crate) fn assert_round_trip(what: &str, deck: &CompiledDeck, strings: &mut StrTable) {
    let printed = print(deck, strings).unwrap_or_else(|why| panic!("{what}: {why}"));
    let again = compile(&printed, grid(), strings)
        .unwrap_or_else(|why| panic!("{what}: the printed deck does not compile: {why}"));
    let mut expected = deck.clone();
    for (_, origin) in &mut expected.provenance {
        *origin = Origin::Base;
    }
    super::builder::assert_same(what, &expected, &again, strings);
    let reprinted = print(&again, strings).unwrap_or_else(|why| panic!("{what}: {why}"));
    assert!(
        reprinted == printed,
        "{what}: printing the reprinted deck gave other text"
    );
}

/// Every shipped deck, compiled from its text, survives printing.
/// Oracle: round trip.
#[test]
fn every_shipped_deck_survives_printing() {
    for (name, text) in DECKS {
        let mut strings = StrTable::default();
        let deck = compile(text, grid(), &mut strings).expect("a shipped deck compiles");
        assert_round_trip(name, &deck, &mut strings);
    }
}

/// Every Rust twin, built with the builder, survives printing: a deck built
/// in Rust can be shared as text.
/// Oracle: round trip.
#[test]
fn every_rust_twin_survives_printing() {
    type Build = fn(&mut StrTable) -> Result<CompiledDeck, BuildError>;
    let builds: [(&str, Build); 4] = [
        ("generic_finfet", twins::generic_finfet::build),
        ("gf180mcu", twins::gf180mcu::build),
        ("ihp_sg13g2", twins::ihp_sg13g2::build),
        ("sky130", twins::sky130::build),
    ];
    for (name, build) in builds {
        let mut strings = StrTable::default();
        let deck = build(&mut strings).unwrap_or_else(|why| panic!("{name}: {why}"));
        assert_round_trip(name, &deck, &mut strings);
    }
}

/// A deck the printer cannot state is refused, not written wrong: a length
/// on a grid of thirds of a nanometre has no terminating decimal.
/// Oracle: hand-derived: 1 nm is 3 units of the grid, and one unit is 1/3 nm.
#[test]
fn a_length_no_decimal_states_is_refused() {
    let thirds = gpurify_geom::Grid::new(3000).expect("a third of a nanometre");
    let mut strings = StrTable::default();
    let deck = compile(
        "grid 1nm\nlayer m = gds(1, 0)\nrule w width(m) >= 1nm\n",
        thirds,
        &mut strings,
    )
    .expect("1 nm is 3 units of a 1/3 nm grid");
    assert!(print(&deck, &strings).is_err());
}

/// A deck with a `temperature` survives printing: it is written as stated,
/// each `pex` row's sheet at the nominal temperature with its `tc1` and
/// `tc2`, and the text says so.
/// Oracle: round trip.
#[test]
fn a_deck_with_a_temperature_survives_printing() {
    let text = "grid 1nm
layer met1 = gds(68, 20)
layer met2 = gds(69, 20)
temperature 358.15K nominal 303.15K
pex met1 thickness 360nm height 1376nm sheet 0.125ohm dielectric 3.9 area_cap 25.8aF/um2 fringe_cap 40.5aF/um tc1 3.179e-3/K tc2 3.094e-7/K2
pex met2 thickness 360nm height 2006nm sheet 0.125ohm area_cap 17.5aF/um2 fringe_cap 37.6aF/um tc1 3.161e-3/K tc2 -7.272e-7/K2
";
    let mut strings = StrTable::default();
    let deck = compile(text, grid(), &mut strings).expect("the deck compiles");
    assert!(deck.temperature.is_some());
    assert_round_trip("temperature", &deck, &mut strings);
    let printed = print(&deck, &strings).expect("the deck prints");
    assert!(
        printed.contains("temperature 3.5815e2K nominal 3.0315e2K"),
        "{printed}"
    );
    assert!(printed.contains("sheet 1.25e-1ohm"), "{printed}");
    assert!(
        printed.contains("tc1 3.179e-3/K tc2 3.094e-7/K2"),
        "{printed}"
    );
}
