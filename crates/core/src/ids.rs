//! Index newtypes: one per table, so a mix-up is a type error rather than
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
    /// Identifies one polygon; the same value indexes `ingest`'s provenance
    /// columns, which must stay the same length and order.
    PolyId(u32) => "the per-polygon columns of [`crate::GeometryStore`]";

    /// Identifies one vertex.
    VertId(u32) => "the coordinate columns of [`crate::GeometryStore`]";

    /// Identifies one ring within a validated polygon: `0` is the outer
    /// boundary, `1..` are holes.
    RingId(u32) => "the ring table of a [`crate::PolygonRef`]";

    /// Identifies one layer.
    LayerId(u16) => "the layer table produced by `ingest`";
}
