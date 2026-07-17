//! Shared geometry core: data-oriented store, exact predicates, I/O, schema.

pub mod connectivity;
pub mod device_plane;
pub mod exact;
pub mod geometry;
pub mod hierarchy_index;
pub mod io;
pub mod sort_scan;

pub use device_plane::DevicePlane;
pub use geometry::rects::{
    decompose_all, decompose_rectilinear, rect_overlap_area_pos, rect_touch, Rect, RectSet,
};
pub use geometry::{Bbox, Edge, GeometryStore, LayerId, PolyId};

// Re-exports so `crate::params`, `crate::gds`, etc. resolve within this crate
// and downstream crates can use `gdsverify_core::params::Deck` etc.
pub use io::params;
pub use io::read;
pub use io::read::gds;
pub use io::read::gds as gds_lossless;
pub use io::read::oasis;
pub use io::schema;

// Re-export backend types so `crate::session::` and `crate::backend::` paths work
pub use gdsverify_backend as backend;
pub use gdsverify_backend::session;
