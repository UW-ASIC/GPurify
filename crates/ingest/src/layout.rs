//! Layout readers: GDSII and OASIS.
//!
//! Both produce the same two outputs — a `GeometryStore` and a [`Provenance`] —
//! and share nothing else. They are different binary formats with different
//! record models, so there is no common reader trait: one implementation each,
//! and a single [`read_layout`] that dispatches on the file's magic.
//!
//! # Flattening
//!
//! Both formats are hierarchical; verification is flat. Flattening happens
//! here, during the read, so the store is built once rather than built and then
//! rewritten. Each emitted polygon records the instance path it came from, and
//! an unsupported transform (non-orthogonal rotation, non-integral
//! magnification) is an error, not an approximation.

use crate::deck::Deck;
use crate::intern::StrTable;
use crate::provenance::Provenance;
use gpurify_core::GeometryStore;

/// Everything a verification run needs from a layout file.
#[derive(Debug, Default)]
pub struct Layout {
    pub store: GeometryStore,
    pub provenance: Provenance,
    pub strings: StrTable,
}

/// Why a layout could not be read.
///
/// Every variant is a refusal, never a degradation. In particular
/// `UnsupportedTransform`: the old reader silently approximated some of these,
/// which moves geometry and therefore moves verdicts.
#[derive(Debug, Clone, thiserror::Error)]
pub enum LayoutError {
    #[error("unrecognised file format")]
    UnknownFormat,
    #[error("truncated record at byte {0}")]
    Truncated(u64),
    #[error("unsupported record type {0:#06x} at byte {1}")]
    UnsupportedRecord(u16, u64),
    #[error("coordinate {0} exceeds the representable range")]
    CoordinateOutOfRange(i64),
    #[error("instance transform is not representable exactly")]
    UnsupportedTransform,
    #[error("cell {0} is referenced but not defined")]
    MissingCell(String),
    #[error("cell hierarchy contains a cycle through {0}")]
    CyclicHierarchy(String),
    #[error("layer {0}/{1} is not in the deck's layer table")]
    UnknownLayer(u16, u16),
    #[error("io: {0}")]
    Io(String),
}

/// How strictly to treat geometry the deck does not describe.
///
/// Not a correctness switch: both settings verify identically. It decides
/// whether a layer absent from the deck is an error or is dropped, which is the
/// difference between running a partial deck deliberately and running one by
/// accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownLayers {
    /// Reject. The default, and what a signoff run uses.
    Reject,
    /// Drop, and report how many rows were dropped. Never silent.
    Drop,
}

/// Read a layout file, flatten it, and produce the store plus provenance.
///
/// **Transform, generative** — produces tables from a filename rather than from
/// a table. The deck is needed during the read, not after: layer mapping and
/// the grid resolution both affect what is emitted, and mapping afterwards
/// would mean holding raw layer numbers for every polygon.
///
/// This is the one function that applies the `GeometryStoreBuilder::finish`
/// permutation to the provenance columns.
pub fn read_layout(
    path: &std::path::Path,
    deck: &Deck,
    unknown: UnknownLayers,
) -> Result<Layout, LayoutError> {
    todo!()
}

/// GDSII.
///
/// A record stream of `(length, tag, payload)`. Record tags are a small dense
/// `u16` space known at compile time, so dispatch is an array index, not a map.
pub mod gds {
    use super::{Deck, Layout, LayoutError, UnknownLayers};

    /// True when the byte prefix is a GDSII header record.
    pub fn detect(prefix: &[u8]) -> bool {
        todo!()
    }

    pub fn read(
        bytes: &[u8],
        deck: &Deck,
        unknown: UnknownLayers,
    ) -> Result<Layout, LayoutError> {
        todo!()
    }
}

/// OASIS.
///
/// Variable-length integers, modal state carried between records, and optional
/// per-cell compression. The modal state is the part that makes this a separate
/// implementation rather than a variation of the GDS reader: a record's meaning
/// depends on records before it.
pub mod oasis {
    use super::{Deck, Layout, LayoutError, UnknownLayers};

    pub fn detect(prefix: &[u8]) -> bool {
        todo!()
    }

    pub fn read(
        bytes: &[u8],
        deck: &Deck,
        unknown: UnknownLayers,
    ) -> Result<Layout, LayoutError> {
        todo!()
    }
}
