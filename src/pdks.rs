//! The decks GPurify ships, as text compiled into the library.
//!
//! A consumer that checks or routes against one of these processes reads the
//! deck from here instead of keeping a copy of `pdks/*.deck`, so its copy
//! cannot drift from the one the checker is tested with. Each constant is the
//! file's bytes, unchanged; each file names its sources in its header and
//! what it leaves out at its end.
//!
//! Every deck is authored on its own `grid` (5 nm, or 1 nm for
//! [`GENERIC_FINFET`]) and parses on any layout grid that grid divides.
//!
//! # Examples
//!
//! ```
//! use gpurify::geom::{Grid, StrTable};
//!
//! let mut strings = StrTable::default();
//! // A 1 nm layout grid: 1000 database units per micrometre.
//! let deck = gpurify::ingest::deck::parse_deck(gpurify::pdks::SKY130, Grid::new(1000)?, &mut strings)?;
//! assert!(deck.layers.id(&strings, "met1").is_some());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

/// SkyWater SKY130 (`sky130A`, five-metal aluminium back end), `pdks/sky130.deck`.
pub const SKY130: &str = include_str!("../pdks/sky130.deck");

/// GlobalFoundries GF180MCU (1P6M, MIM option B), `pdks/gf180mcu.deck`.
pub const GF180MCU: &str = include_str!("../pdks/gf180mcu.deck");

/// IHP SG13G2 (130 nm SiGe BiCMOS, five thin and two thick metals),
/// `pdks/ihp_sg13g2.deck`.
pub const IHP_SG13G2: &str = include_str!("../pdks/ihp_sg13g2.deck");

/// ASAP7, the predictive 7 nm FinFET PDK, standing in for a generic FinFET
/// process: `pdks/generic_finfet.deck`. No fab builds it.
pub const GENERIC_FINFET: &str = include_str!("../pdks/generic_finfet.deck");

/// Every shipped deck with its file stem, sorted by stem: one entry per file
/// of `pdks/`, which a test holds to the directory.
pub const ALL: [(&str, &str); 4] = [
    ("generic_finfet", GENERIC_FINFET),
    ("gf180mcu", GF180MCU),
    ("ihp_sg13g2", IHP_SG13G2),
    ("sky130", SKY130),
];
