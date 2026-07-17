//! Newtype handles into the SoA store: indices, never pointers.

/// A layer identifier — a small integer indexing the layer table. `u16` keeps
/// per-polygon references tiny.
///
// ponytail: kept a type alias, not a newtype. A `struct LayerId(u16)` would
// prevent mixing with GDS datatype ints, but every consumer does `layer as
// usize` for bucket indexing; the newtype churn isn't worth it until the
// domain crates are ported. Revisit then.
pub type LayerId = u16;

/// Handle to a polygon: an index into the SoA arrays. Copyable, pointer-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PolyId(pub u32);

impl PolyId {
    /// The raw array index.
    #[must_use]
    #[inline]
    pub fn index(self) -> usize {
        self.0 as usize
    }
}
