//! Core data model for gdsverify: SoA geometry, connectivity, and (in progress)
//! exact predicates and layout I/O.
//!
//! Rewrite in progress (crates2). Ported and green so far:
//!   * [`geometry`] — the SoA store and its primitives (the shared vocabulary
//!     every engine builds on). The `exact`-predicate bridge
//!     (`GeometryStore::poly_as_exact`) is staged with the `exact` module.
//!   * [`connectivity`] — connected components (plain union-find on CPU; the
//!     GPU label-propagation kernels land in the `gpu` module in phase 2).

pub mod connectivity;
pub mod device_plane;
pub mod exact;
pub mod geometry;
pub mod hierarchy_index;
pub mod io;
pub mod sort_scan;

// Re-exports so `crate::params`, `crate::gds`, etc. resolve within this crate
// and downstream crates can use `gdsverify_core::params::Deck` etc.
pub use io::params;
pub use io::read;
pub use io::read::gds;
pub use io::read::oasis;
pub use io::schema;

pub use connectivity::{connected_components, host_union_find};
pub use device_plane::DevicePlane;
pub use exact::{
    BooleanOp, ExactGeometryError, OffsetKernel, Orientation, Point, PointClassification, Polygon,
    PolygonContact, PolygonSet, Ring, SegmentIntersection, Winding,
};
pub use geometry::{
    build_edges, candidate_pairs, Bbox, Edge, GeometryStore, LayerId, PolyId, Rect, RectSet,
};
