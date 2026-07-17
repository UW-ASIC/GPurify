//! Source element kind of an indexed shape.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IndexedShapeKind {
    Boundary,
    Box,
    Path,
}
