//! Every reader: layout, deck, netlists, design intent.
//!
//! Readers fail closed: a malformed file, an unrepresentable coordinate or an
//! off-grid limit is an error, never a partial result. A construct a reader
//! does not support is refused with its location, never skipped or guessed at.
//!
//! | Input | Read with | Gives |
//! |---|---|---|
//! | GDSII layout, plain or gzip | [`layout::read_gds_bytes`], [`gds::Library::parse`](layout::gds::Library::parse) | a [`gds::Library`](layout::gds::Library), hierarchy intact |
//! | The process deck ([language](https://github.com/UW-ASIC/GPurify/blob/main/docs/deck.md)) | [`deck::parse_deck`] | a [`Deck`]: layers, rules, connectivity, devices, parasitic stack |
//! | The flattened layout | [`gds::Library::flatten`](layout::gds::Library::flatten) | a [`GeometryStore`](gpurify_geom::GeometryStore) with the deck's derived layers, and the placed labels in a [`Provenance`] |
//! | Reference netlist, SPICE/CDL or Spectre | [`netlist::spice::read`], [`netlist::spectre::read`] | a [`netlist::Netlist`], hierarchy intact |
//! | Design intent JSON ([schema](https://github.com/UW-ASIC/GPurify/blob/main/docs/usage.md#design-intent)) | [`intent::read_intent`] | a [`DesignIntent`] |
//! | System description JSON ([schema](https://github.com/UW-ASIC/GPurify/blob/main/docs/usage.md#multi-die-systems)) | [`system::read_system`] | a [`system::System`]: dies, placements, bonded faces |
//!
//! # Order matters
//!
//! The layout states its own grid in its `UNITS` record ([`gds::Library::grid`](layout::gds::Library::grid)),
//! and the deck is parsed against it: every deck length must be a whole number
//! of the layout's database units, or the deck is refused. Flattening maps each
//! GDS layer/datatype pair through the deck's [`LayerTable`](deck::LayerTable),
//! refusing a pair the deck neither declares nor lists with `ignore gds(L, D)`,
//! then computes the derived layers. Labels bind to shapes last, against the
//! deck's [`Connectivity`](deck::Connectivity).
//!
//! Every reader interns its names into one [`StrTable`]. Ids follow interning
//! order, so reading in the same order (layout, deck, netlist, intent) gives the
//! same [`StrId`]s, and the same report bytes, on every machine.
//!
//! # Examples
//!
//! ```no_run
//! use gpurify_ingest::deck::parse_deck;
//! use gpurify_ingest::layout::{gds, read_gds_bytes, UnknownLayers};
//! use gpurify_ingest::StrTable;
//! use std::path::Path;
//!
//! let mut strings = StrTable::default();
//! let bytes = read_gds_bytes(Path::new("my_layout.gds"))?;
//! let library = gds::Library::parse(&bytes, &mut strings)?;
//! let grid = library.grid()?;
//!
//! let source = std::fs::read_to_string("pdks/sky130.deck")?;
//! let deck = parse_deck(&source, grid, &mut strings).map_err(|e| e.in_file("pdks/sky130.deck"))?;
//!
//! let (store, mut provenance) = library.flatten(&deck, &strings, UnknownLayers::Reject)?;
//! provenance.resolve_labels(&store, &deck.connectivity)?;
//! println!("{} shapes on {} layers", store.poly_count(), store.layer_count());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod deck;
pub mod intent;
pub mod layout;
pub mod lefdef;
pub mod netlist;
pub mod provenance;
pub mod system;

/// A row count as the `u32` every table here is indexed by. Panics past `u32::MAX`.
pub(crate) fn narrow(rows: usize) -> u32 {
    u32::try_from(rows).expect("an ingest table is indexed by u32 and cannot hold 2^32 rows")
}

pub use deck::{Deck, DeckError};
pub use gpurify_geom::{StrId, StrTable};
pub use intent::{DesignIntent, IntentError};
pub use provenance::{BlackBox, LabelError, PlacedLabel, Provenance};
