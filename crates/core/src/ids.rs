//! Index newtypes.
//!
//! Every one of these is an index into a specific table. They are newtypes and
//! not aliases because the whole family is `u32`-shaped, and a `PolyId` used
//! where a `VertId` was meant is a bug that reads correctly and produces
//! plausible garbage.

macro_rules! ids {
    ($($(#[$doc:meta])* $name:ident($repr:ty) => $table:literal;)*) => {$(
        $(#[$doc])*
        #[doc = concat!("\n\nAn index into ", $table, ".")]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct $name(pub $repr);

        impl $name {
            /// The raw index, for use as a slice subscript.
            pub const fn idx(self) -> usize {
                self.0 as usize
            }
        }
    )*};
}

ids! {
    /// Identifies one polygon.
    ///
    /// The same value indexes `ingest`'s provenance columns. Keeping those two
    /// tables the same length and in the same order is an invariant with no
    /// compiler behind it — it is asserted at the one place that builds them.
    PolyId(u32) => "the per-polygon columns of [`crate::GeometryStore`]";

    /// Identifies one vertex.
    VertId(u32) => "the coordinate columns of [`crate::GeometryStore`]";

    /// Identifies one ring within a validated polygon: `0` is the outer
    /// boundary, `1..` are holes.
    RingId(u32) => "the ring table of a [`crate::PolygonRef`]";

    /// Identifies one layer.
    ///
    /// `u16` because a PDK has tens of layers and a deck's layer table is one
    /// of the few things small enough that the width visibly matters: it is a
    /// column in every polygon row.
    LayerId(u16) => "the layer table produced by `ingest`";
}
