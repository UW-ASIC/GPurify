//! Width family: how narrow a single shape, or one feature of it, may be.
//!
//! All four rules measure *within* one polygon. None needs the spatial index,
//! none looks at a second shape, and all four fall out of the same scan over a
//! validated polygon's edges — the set of *facing* parallel edge pairs, meaning
//! two edges that are antiparallel and whose projections onto their shared axis
//! overlap. That scan is the whole family:
//!
//! - the gap between a facing pair whose interior is **inside** the polygon is
//!   a width, and [`check_min_width`] wants its minimum;
//! - the gap between a facing pair whose interior is **outside** the polygon is
//!   a notch, and [`check_notch`] wants its minimum;
//! - the same minimum width, compared the other way, is [`check_max_width`],
//!   which is a slotting trigger rather than a defect;
//! - and one edge's own length is [`check_min_edge_length`].
//!
//! The old tree measured width as `min(bbox.width, bbox.height)` with a note
//! that this is exact "for the conformance rectangles". It is not exact for an
//! L, a T or a comb, and every one of those is a real metal shape. The facing-
//! pair scan is exact for any rectilinear polygon, which is the whole input
//! domain, so there is no approximate path here at all.

use crate::{Design, Scratch};
use gpurify_core::{LayerId, PolygonRef};
use gpurify_ingest::StrId;
use gpurify_report::{RuleRun, Violations};
use gpurify_units::Dbu;

/// Minimum width: no part of a shape may be narrower than the limit.
#[derive(Debug, Default)]
pub struct MinWidthTable {
    /// The deck's id for the rule, interned. What a human greps a report for.
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// Violated *below*. Strictly positive; a zero limit is rejected at
    /// construction because it passes every shape while looking configured.
    pub limit: Vec<Dbu>,
}

/// Maximum width: a shape wider than the limit must be slotted.
///
/// The other sense of the same measurement. It is a separate table rather than
/// a `sense` column on [`MinWidthTable`] because a `sense` column is a branch
/// inside the loop, and because the old tree's `min_spacing` and `max_width`
/// shared a comparison that was correct for exactly one of them.
#[derive(Debug, Default)]
pub struct MaxWidthTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// Violated *above*.
    pub limit: Vec<Dbu>,
}

/// Minimum edge length: no single boundary edge shorter than the limit.
///
/// A jog too short to print, independent of how wide the shape is either side
/// of it.
#[derive(Debug, Default)]
pub struct MinEdgeLengthTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    pub limit: Vec<Dbu>,
}

/// Notch: two edges of the *same* polygon facing each other across a gap that
/// is outside the shape.
///
/// Distinct from spacing, which is the gap between two different polygons, and
/// distinct from width, which is the gap between two edges across material.
/// Same scan, opposite side.
#[derive(Debug, Default)]
pub struct NotchTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    pub limit: Vec<Dbu>,
}

impl MinWidthTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl MaxWidthTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl MinEdgeLengthTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl NotchTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

/// The narrowest place inside a polygon.
///
/// **Decision** — one borrowed polygon in, one distance out, pure and
/// table-testable, which is why it is not buried in the transform. A rectangle
/// gives `min(width, height)`; an L gives the narrower arm; a comb gives the
/// tooth. Exact for any rectilinear polygon.
///
/// Holes participate: the material between an outer edge and a hole edge facing
/// it is width, and ignoring it is how a ring with a thin wall passes.
pub fn narrowest_width(poly: PolygonRef<'_>) -> Dbu {
    todo!()
}

/// The narrowest notch in a polygon, or `None` when it has none.
///
/// **Decision** — the mirror of [`narrowest_width`], reducing over the facing
/// pairs whose gap lies *outside* the shape. `None` for a convex shape, which
/// has no such pair, and that is different from a notch of zero.
pub fn narrowest_notch(poly: PolygonRef<'_>) -> Option<Dbu> {
    todo!()
}

/// The shortest boundary edge of a polygon.
///
/// **Decision.** Zero-length edges — two identical consecutive vertices — are
/// not edges and do not participate; the validator has already rejected the
/// polygons where that mattered.
pub fn shortest_edge(poly: PolygonRef<'_>) -> Dbu {
    todo!()
}

/// Check every minimum-width rule in the table.
///
/// **Transform, and a kernel**: each polygon's verdict is a function of its own
/// coordinates and the row's uniforms only, so any polygon order is legal and
/// the loop partitions cleanly.
///
/// One violation per offending polygon, not per offending facing pair —
/// reported at the narrowest one, with [`narrowest_width`] as the measurement.
/// A shape with four thin arms is one thing to fix.
///
/// `examined` counts polygons on the layer. `Outcome::Refused` for that row if
/// the layer will not validate.
pub fn check_min_width(
    design: Design<'_>,
    table: &MinWidthTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every maximum-width rule in the table.
///
/// Same scan and same measurement as [`check_min_width`], compared with
/// `LimitSense::Maximum`. `examined` counts polygons.
pub fn check_max_width(
    design: Design<'_>,
    table: &MaxWidthTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every minimum-edge-length rule in the table.
///
/// One violation per offending *edge*, not per polygon: two short jogs on one
/// wire are two separate places a mask fails, and reporting them as one loses
/// the second coordinate. Reported at the edge's first vertex.
///
/// `examined` counts edges, which is the primitive this rule actually looks at
/// and is not derivable from the polygon count.
pub fn check_min_edge_length(
    design: Design<'_>,
    table: &MinEdgeLengthTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every notch rule in the table.
///
/// One violation per offending polygon, at its narrowest notch. `examined`
/// counts polygons.
pub fn check_notch(
    design: Design<'_>,
    table: &NotchTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}
