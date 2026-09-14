//! Every reader. Layout, decks, netlists, design intent.
//!
//! Readers fail closed: a malformed file, an unrepresentable coordinate or an
//! off-grid limit is rejected here, once, and no partial result is returned.
//!
//! Invariant: `GeometryStoreBuilder` sorts rows by layer and returns a
//! permutation; provenance columns are accumulated in arrival order and must be
//! permuted to match, or a violation is reported against the wrong cell.
//! [`Provenance::permute`] is the one place that happens.

pub mod deck;
pub mod intent;
pub mod intern;
pub mod layout;
pub mod netlist;
pub mod provenance;

/// A row count or side-array offset as the `u32` every table in this crate is
/// indexed by. Fails closed rather than saturating.
pub(crate) fn narrow(rows: usize) -> u32 {
    u32::try_from(rows).expect("an ingest table is indexed by u32 and cannot hold 2^32 rows")
}

/// One row of a CSR table: `rows[start[row] .. start[row + 1]]`.
///
/// `start` carries one entry per row **plus a terminator**.
pub(crate) fn csr<'a, T>(start: &[u32], rows: &'a [T], row: usize) -> &'a [T] {
    debug_assert!(
        row + 1 < start.len(),
        "row {row} is past the end of a CSR offset column of {} entries",
        start.len()
    );
    let (first, last) = (start[row] as usize, start[row + 1] as usize);
    debug_assert!(
        first <= last && last <= rows.len(),
        "CSR offsets {first}..{last} are not an ascending range inside {} rows",
        rows.len()
    );
    &rows[first..last]
}

pub use deck::{Deck, DeckError};
pub use intent::{DesignIntent, IntentError};
pub use intern::{StrId, StrTable};
pub use provenance::{LabelError, PlacedLabel, Provenance};
