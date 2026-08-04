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

pub mod deck;
pub mod intent;
pub mod intern;
pub mod layout;
pub mod netlist;
pub mod provenance;

/// A row count or side-array offset as the `u32` every table in this crate is
/// indexed by.
///
/// One function rather than one per module: `deck`, `layout` and `netlist` each
/// grew their own copy of this line while the modules were being written apart,
/// and three `expect` messages for one impossibility is three places to get the
/// bound wrong. A file that really held 2^32 rows of anything is not a file this
/// tool can read, so this fails closed rather than saturating.
pub(crate) fn narrow(rows: usize) -> u32 {
    u32::try_from(rows).expect("an ingest table is indexed by u32 and cannot hold 2^32 rows")
}

/// One row of a CSR table: `rows[start[row] .. start[row + 1]]`.
///
/// The offset column carries one entry per row **plus a terminator**, which is
/// the convention `GeometryStore::layer_start`, `Netlist`'s four offset columns
/// and `Provenance::prop_start` all state. Every accessor over one of them
/// differs only in which pair of columns it names, so the range arithmetic and
/// the asserts that catch a desynchronised pair live here once.
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
pub use provenance::Provenance;
