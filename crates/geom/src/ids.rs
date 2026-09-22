//! Index newtypes, one per table, so a mix-up is a type error.

/// A polygon row of [`crate::GeometryStore`]; also indexes `ingest`'s provenance columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PolyId(pub u32);

impl PolyId {
    pub const fn idx(self) -> usize {
        self.0 as usize
    }
}

/// A layer, as numbered by `ingest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct LayerId(pub u16);

impl LayerId {
    pub const fn idx(self) -> usize {
        self.0 as usize
    }
}
