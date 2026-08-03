//! Borrowed validated geometry.
//!
//! Exact boolean operations need guarantees the raw store does not make: rings
//! are simple, holes lie inside their outer boundary, winding is canonical.
//! Establishing those is a pass; re-establishing them per rule was 43% of a
//! signoff run in the old implementation.
//!
//! So validation happens once per layer into a [`ValidatedLayer`], and
//! [`PolygonRef`] is a *borrowed* handle into it. There is no owned polygon and
//! no copy of the coordinates.
//!
//! # The weakness, stated plainly
//!
//! An owned refined type cannot exist without having been validated. A borrowed
//! view can, if someone constructs one over rows that were never checked. The
//! only defence is that [`PolygonRef`]'s fields are private and the sole
//! constructor is [`validate_layer_into`]. That is weaker than "parse, don't
//! validate" normally gives, and it is the price of not copying the geometry.

use crate::ids::{LayerId, PolyId, RingId};
use crate::ops::Winding;
use crate::store::GeometryStore;

/// Why a polygon could not be validated.
///
/// Fail closed: an unvalidatable shape is an error, never a silently skipped
/// row. The old implementation dropped a hole with no containing outer ring
/// without a word, which removes area from a verification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ValidityError {
    #[error("polygon {0:?} has fewer than three distinct vertices")]
    Degenerate(PolyId),
    #[error("polygon {0:?} has self-intersecting boundary")]
    SelfIntersecting(PolyId),
    #[error("polygon {0:?} is a hole with no containing outer ring")]
    OrphanHole(PolyId),
    #[error("polygon {0:?} is not rectilinear")]
    NotRectilinear(PolyId),
}

/// One layer's geometry, validated and grouped into outer-plus-holes polygons.
///
/// **Five questions.** In: a [`GeometryStore`] and a [`LayerId`]. Out: ring
/// spans and polygon spans — indices only, no coordinates. How many: one per
/// layer per run, reused across every rule on that layer. Access pattern: `SoA`;
/// a boolean walks rings, a containment test walks polygons. Lifetime: phase —
/// this is a reusable buffer, cleared and refilled per layer, never
/// reallocated. Parallelisable: validation of distinct polygons is independent.
#[derive(Debug, Default)]
pub struct ValidatedLayer {
    /// Which layer this was built from, so a mismatched pairing is catchable.
    layer: Option<LayerId>,
    /// One row per ring: the store row it came from, and its winding.
    ring_poly: Vec<PolyId>,
    ring_winding: Vec<Winding>,
    /// One row per validated polygon: `ring_start .. ring_start + ring_len`
    /// into the ring columns. Ring 0 of every span is the outer boundary.
    poly_ring_start: Vec<u32>,
    poly_ring_len: Vec<u32>,
}

impl ValidatedLayer {
    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        todo!()
    }

    /// Borrow one validated polygon.
    ///
    /// Takes the store as a parameter rather than holding a reference, so
    /// `ValidatedLayer` stays a plain owned buffer the caller can keep across
    /// runs and refill. Pairing it with the wrong store is caught by the
    /// `layer` field.
    pub fn get<'a>(&'a self, store: &'a GeometryStore, idx: u32) -> PolygonRef<'a> {
        todo!()
    }
}

/// A polygon that is known valid: simple rings, canonical winding, holes
/// contained by their outer boundary.
///
/// Downstream takes this and never re-derives what it guarantees. Constructible
/// only through [`ValidatedLayer::get`].
#[derive(Debug, Clone, Copy)]
pub struct PolygonRef<'a> {
    store: &'a GeometryStore,
    layer: &'a ValidatedLayer,
    idx: u32,
}

impl<'a> PolygonRef<'a> {
    /// The outer boundary. Always present.
    pub fn outer(self) -> RingRef<'a> {
        todo!()
    }

    /// The holes. Empty for a simply-connected polygon, which is most of them.
    pub fn holes(self) -> impl Iterator<Item = RingRef<'a>> + 'a {
        todo!();
        #[allow(unreachable_code)]
        std::iter::empty()
    }

    pub fn bbox(self) -> crate::bbox::Bbox {
        todo!()
    }

    /// Signed area of the outer boundary minus the holes.
    ///
    /// `DbuArea` and exact: this feeds `min_area` and density, where a rounded
    /// answer changes a verdict.
    pub fn area(self) -> gpurify_units::DbuArea {
        todo!()
    }
}

/// One validated closed ring.
#[derive(Debug, Clone, Copy)]
pub struct RingRef<'a> {
    xs: &'a [gpurify_units::Dbu],
    ys: &'a [gpurify_units::Dbu],
    winding: Winding,
}

impl<'a> RingRef<'a> {
    /// The two coordinate columns, parallel and of equal length.
    ///
    /// Slices, not points, so an edge scan can vectorise.
    pub fn coords(self) -> (&'a [gpurify_units::Dbu], &'a [gpurify_units::Dbu]) {
        todo!()
    }

    pub fn winding(self) -> Winding {
        todo!()
    }

    /// Twice the signed area. Doubled to stay exact in integers — the halving
    /// is the only place a rounding could enter, so it does not happen here.
    pub fn area2(self) -> gpurify_units::DbuArea {
        todo!()
    }
}

/// Validate every polygon on one layer.
///
/// **Transform, A-to-B.** Caller owns `out`, which is cleared and refilled;
/// hoisting it above a per-layer loop is the point. All data flow is in the
/// signature.
///
/// Fails on the first invalid polygon rather than accumulating: a deck run
/// against geometry the tool cannot represent is not partially meaningful.
///
/// Rectilinear only. Arbitrary-angle input is [`ValidityError::NotRectilinear`],
/// not an approximation — the previous general-angle path failed open in three
/// places and silently dropped area.
pub fn validate_layer_into(
    store: &GeometryStore,
    layer: LayerId,
    out: &mut ValidatedLayer,
) -> Result<(), ValidityError> {
    todo!()
}

/// Which ring of a polygon a [`RingId`] refers to.
///
/// `RingId(0)` is always the outer boundary. Kept as a free function rather
/// than a method so it reads at the call site without borrowing anything.
pub const fn is_outer(ring: RingId) -> bool {
    todo!()
}
