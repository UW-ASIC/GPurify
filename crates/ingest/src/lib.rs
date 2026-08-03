//! Every reader. Layout, decks, netlists, design intent.
//!
//! This is where "parse, don't validate" happens: a malformed file, an
//! unrepresentable coordinate or an off-grid rule limit is rejected **here**,
//! once, and everything downstream takes the refined type and never rechecks.
//! Nothing in this module is on a hot path — it runs once per run — so it may
//! be as careful as it likes.
//!
//! # Fail closed
//!
//! Every reader implements a declared subset and errors on anything outside it.
//! It never guesses at a dialect and never returns a partial result: a deck
//! with one unrepresentable limit is not partially usable, and an empty clean
//! report is never allowed to mean "we could not read this".
//!
//! # The permutation invariant
//!
//! [`crate::layout`] builds a `GeometryStore` through `GeometryStoreBuilder`,
//! which sorts rows by layer and returns a permutation. Provenance columns are
//! accumulated in arrival order and **must** be permuted to match, or a
//! violation is reported against the wrong cell. [`Provenance::permute`] is the
//! one place that happens, and [`layout::read_layout`] is the one caller.

// Definition-Phase; see CLAUDE.md
#![allow(unused_variables, dead_code)]

pub mod deck;
pub mod intent;
pub mod intern;
pub mod layout;
pub mod netlist;
pub mod provenance;

pub use deck::{Deck, DeckError};
pub use intent::{DesignIntent, IntentError};
pub use intern::{StrId, StrTable};
pub use provenance::Provenance;
