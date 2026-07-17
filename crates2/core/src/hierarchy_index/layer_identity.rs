//! GDS layer/datatype identity for indexed shapes.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GdsLayerIdentity {
    pub layer: i16,
    pub datatype: i16,
}
