//! Every reader: layout, deck, netlists, design intent.
//!
//! Readers fail closed: a malformed file, an unrepresentable coordinate or an
//! off-grid limit is an error, never a partial result.

pub mod deck;
pub mod intent;
pub mod layout;
pub mod netlist;
pub mod provenance;

/// A row count as the `u32` every table here is indexed by. Panics past `u32::MAX`.
pub(crate) fn narrow(rows: usize) -> u32 {
    u32::try_from(rows).expect("an ingest table is indexed by u32 and cannot hold 2^32 rows")
}

pub use deck::{Deck, DeckError};
pub use gpurify_geom::{StrId, StrTable};
pub use intent::{DesignIntent, IntentError};
pub use provenance::{LabelError, PlacedLabel, Provenance};
