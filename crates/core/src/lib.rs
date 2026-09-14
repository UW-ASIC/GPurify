//! Layout geometry: storage, exact predicates, exact rectilinear booleans, and
//! the spatial index that keeps them from being O(n²).

pub mod bbox;
pub mod boolean;
pub mod connectivity;
pub mod ids;
pub mod index;
pub mod observe;
pub mod ops;
pub mod rects;
pub mod store;
pub mod view;

pub use bbox::Bbox;
pub use ids::{LayerId, PolyId, RingId, VertId};
pub use observe::{NoObserve, Observer};
pub use store::{GeometryStore, GeometryStoreBuilder};
pub use view::{PolygonRef, RingRef, ValidatedLayer};
