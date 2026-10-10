//! Index newtypes, one per table, so a mix-up is a type error.

/// A polygon row of [`crate::GeometryStore`]; also indexes `ingest`'s provenance columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PolyId(pub u32);

impl PolyId {
    /// Returns the row as a `usize`, for indexing a column.
    pub const fn idx(self) -> usize {
        self.0 as usize
    }
}

/// A layer, as numbered by `ingest`: dense from 0, drawn layers before the
/// layers a deck derives from them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct LayerId(pub u16);

impl LayerId {
    /// Returns the id as a `usize`, for indexing a per-layer column.
    pub const fn idx(self) -> usize {
        self.0 as usize
    }
}
