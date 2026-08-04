//! Layout geometry: storage, exact predicates, exact rectilinear booleans, and
//! the spatial index that keeps them from being O(n²).
//!
//! **One representation.** [`GeometryStore`] is the only place a polygon lives:
//! flat `Dbu` coordinate columns plus a per-polygon index range. There is no
//! owned `Polygon` type. Validity — simple rings, holes bound to their outer,
//! canonical winding — is carried by the borrowed [`PolygonRef`], produced once
//! by [`view::validate_layer_into`] and thereafter assumed. Exact operations write
//! into caller-owned buffers, so nothing allocates per rule.
//!
//! **No text, no maps, no serde.** Hierarchy paths, GDS properties, net labels
//! and text annotations are provenance; they live in `ingest`, keyed by the
//! same [`PolyId`]. Nothing here reads them, so nothing here needs a string
//! table. That is what makes this module's benchmarks and mutation score mean
//! something.

// Modules are public: `core` is a geometry library, and its interface really is
// the set of predicates and transforms below. Curating it down to a handful of
// re-exports would hide `ops::segments_intersect` behind a longer path for no
// gain — a DRC rule needs it by name. The re-exports beneath are the types that
// appear in almost every signature, not a curated subset of the interface.
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
