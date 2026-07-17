//! Newtype handles into the SoA store: indices, never pointers.

/// A layer identifier. Small integer, indexes the layer table. `u16` keeps references tiny.
pub type LayerId = u16;

/// Handle to a polygon: just an index into the SoA arrays. Copyable, pointer-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyId(pub u32);
