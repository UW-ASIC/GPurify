//! Integration tests for `deck`: the compiled deck, its queries, the builder
//! and the printer, one module each.

mod builder;
mod custom;
mod errors;
mod esd_kinds;
mod kinds;
mod path_and_ac_kinds;
mod printer;
mod query;

/// The Rust twins of the shipped decks, translated from their text.
mod twins {
    pub mod generic_finfet;
    pub mod gf180mcu;
    pub mod ihp_sg13g2;
    pub mod sky130;
}

/// The shipped decks, as `gpurify::pdks` ships them.
const DECKS: [(&str, &str); 4] = [
    (
        "generic_finfet",
        include_str!("../../../../pdks/generic_finfet.deck"),
    ),
    ("gf180mcu", include_str!("../../../../pdks/gf180mcu.deck")),
    (
        "ihp_sg13g2",
        include_str!("../../../../pdks/ihp_sg13g2.deck"),
    ),
    ("sky130", include_str!("../../../../pdks/sky130.deck")),
];

/// The 1 nm grid every deck here is compiled on.
fn grid() -> gpurify_geom::Grid {
    gpurify_geom::Grid::new(1000).expect("a 1 nm grid")
}
