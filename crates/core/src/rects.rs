//! Rectilinear decomposition: polygons to disjoint rectangles.
//!
//! Area, density and occupancy questions are trivial over rectangles and
//! awkward over polygons with holes, so several rules decompose first. The
//! decomposition is exact and the rectangles are disjoint, so areas sum without
//! an inclusion–exclusion correction.
//!
//! The previous implementation's `rectilinear_occupancy` was 43% of a signoff
//! run because a per-polygon transform scanned rows belonging to *other*
//! polygons — a violation of the kernel rule. Each output row here is a
//! function of its own input polygon only.

use crate::ids::PolyId;
use crate::view::ValidatedLayer;
use gpurify_units::{Dbu, DbuArea};

/// One axis-aligned rectangle of a decomposition.
///
/// `AoS`, unlike most of this crate: all four bounds are read together by every
/// consumer, and a rectangle is never scanned one field at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub xlo: Dbu,
    pub ylo: Dbu,
    pub xhi: Dbu,
    pub yhi: Dbu,
}

impl Rect {
    pub const fn area(self) -> DbuArea {
        todo!()
    }
}

/// Decompose every polygon on a validated layer into disjoint rectangles.
///
/// **Transform, A-to-B.** Caller owns both output buffers. `rects` holds the
/// rectangles of every polygon concatenated; `poly_start` is a CSR offset array
/// of length `layer.len() + 1`, so polygon `i`'s rectangles are
/// `rects[poly_start[i] .. poly_start[i + 1]]`.
///
/// Two buffers rather than a `Vec<Vec<Rect>>` for the reason given throughout
/// this crate: the nested form is one allocation per polygon and a pointer
/// chase per access, on a path that runs per rule per layer.
///
/// Vertical-slab decomposition, so the rectangle count is bounded by the vertex
/// count and the result is canonical — the same polygon always decomposes the
/// same way, which the determinism gate needs.
pub fn decompose_into(
    layer: &ValidatedLayer,
    store: &crate::store::GeometryStore,
    rects: &mut Vec<Rect>,
    poly_start: &mut Vec<u32>,
) {
    todo!()
}

/// Total area covered by a polygon's rectangles.
///
/// Exact, because the rectangles are disjoint. This is what `min_area` and the
/// density rules measure.
pub fn covered_area(rects: &[Rect]) -> DbuArea {
    todo!()
}

/// Area of a polygon's rectangles clipped to a window.
///
/// The density-window primitive. Takes the polygon's own rectangle slice, so
/// the caller has already done the CSR lookup and this function cannot read
/// another polygon's rows — which is the kernel-rule violation that made the
/// old version 43% of a run.
pub fn clipped_area(rects: &[Rect], window: crate::bbox::Bbox) -> DbuArea {
    todo!()
}

/// Which polygon each rectangle came from.
///
/// Derived from the CSR offsets rather than stored: a `Vec<PolyId>` parallel to
/// `rects` would be a second column that can desynchronise, for a lookup that
/// is a binary search over an array already in cache.
pub fn owner_of(poly_start: &[u32], rect_index: u32) -> PolyId {
    todo!()
}
