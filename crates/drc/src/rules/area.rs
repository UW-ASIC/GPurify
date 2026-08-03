//! Area family: how much material there is, and where.
//!
//! All four rules go through `core::rects::decompose_into`, because area over a
//! polygon with holes is awkward and area over disjoint rectangles is a sum.
//! The rectangles are disjoint by construction, so they add with no
//! inclusion–exclusion correction, and the decomposition is canonical — the
//! same polygon always decomposes the same way, which the determinism gate
//! needs.
//!
//! # Merged, not per-polygon
//!
//! [`check_min_area`] measures *connected figures*, not input polygons. Two
//! overlapping rectangles each below the limit are one shape that is above it,
//! and summing their fragment areas separately reports two violations that do
//! not exist while a genuinely thin figure split across three fragments reports
//! none. The union is exact (`core::boolean`), not a bounding-box
//! approximation.

use crate::{Design, Scratch};
use gpurify_core::LayerId;
use gpurify_ingest::StrId;
use gpurify_report::{LimitSense, RuleRun, Violations};
use gpurify_units::{Dbu, DbuArea};

/// Minimum area of a connected figure.
///
/// A shape too small to hold a printed feature. Measured after merging, which
/// is what makes it a rule about figures rather than about how the layout
/// happened to be fractured.
#[derive(Debug, Default)]
pub struct MinAreaTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// [`DbuArea`] rather than [`Dbu`]: an area limit is a squared coordinate
    /// and does not fit `i64` at the top of the domain. The old tree's `i64`
    /// limit was the same type as its coordinates, which is how an area and a
    /// distance ended up comparable.
    pub limit: Vec<DbuArea>,
}

/// Minimum enclosed area: a hole smaller than this cannot be etched open.
///
/// The complement of [`MinAreaTable`], and it measures the *hole*, not the
/// figure. Only real holes count — a ring of material around a void — not a
/// same-polarity shape nested inside another, which is material and encloses
/// nothing.
#[derive(Debug, Default)]
pub struct MinEnclosedAreaTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    pub limit: Vec<DbuArea>,
}

/// Cheesing: a plate above this area must carry slots or holes.
///
/// Large unbroken metal dishes during chemical-mechanical polish, so the
/// foundry requires it be perforated. The evidence has to be in the polygon's
/// own boundary: a smaller same-polarity shape drawn on top is more material,
/// not relief.
#[derive(Debug, Default)]
pub struct CheesingTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// The largest a figure may be while still unperforated. Violated above,
    /// and only when the figure has no hole.
    pub max_unslotted: Vec<DbuArea>,
}

/// Windowed density: the fraction of a moving window a layer covers.
///
/// Both senses live in one table, because unlike width-versus-max-width the two
/// share every step of the computation — the same window sweep and the same
/// coverage fraction, differing only in the final comparison. One `sense`
/// column read once per row as a uniform is not a branch in the loop.
#[derive(Debug, Default)]
pub struct DensityTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// Side of the square window. Density is meaningless without one: a layer
    /// that is 30% dense globally can be 0% dense over a millimetre and still
    /// dish.
    pub window: Vec<Dbu>,
    /// How far the window advances between evaluations. Usually half the
    /// window, so every point is covered by four overlapping windows. Stated
    /// rather than derived, because a deck that sweeps in whole-window steps
    /// misses exactly the straddling hot spot the rule is for.
    pub step: Vec<Dbu>,
    /// Covered fraction, in `0.0 ..= 1.0`. A ratio, so `f64` — this is one of
    /// the two dimensionless limits in the crate, alongside the antenna ratio.
    pub limit: Vec<f64>,
    /// Which side of `limit` is the violation. A minimum-density rule wants
    /// enough metal for planarisation; a maximum-density rule wants little
    /// enough for etch loading.
    pub sense: Vec<LimitSense>,
}

impl MinAreaTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl MinEnclosedAreaTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl CheesingTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl DensityTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

/// Check every minimum-area rule.
///
/// **Transform.** Merges the layer into connected figures, decomposes each into
/// disjoint rectangles, sums, compares. One violation per offending figure,
/// reported at a point inside it so a viewer can navigate there.
///
/// `examined` counts merged figures, not input polygons. That is the number a
/// test asserts on, and it differs from the polygon count exactly when merging
/// did something — which is the property worth being able to see.
///
/// `Outcome::Refused` if the union cannot be computed exactly. Never a clean
/// result: the old tree emitted a violation-shaped marker for a geometry error,
/// which put a fabrication defect and a tool failure in the same column.
pub fn check_min_area(
    design: Design<'_>,
    table: &MinAreaTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every minimum-enclosed-area rule.
///
/// One violation per offending hole, reported at a vertex of the hole ring.
/// `examined` counts holes, which is zero for a layer of simply-connected
/// shapes and is a legitimate clean result that a test can distinguish from not
/// having run.
pub fn check_min_enclosed_area(
    design: Design<'_>,
    table: &MinEnclosedAreaTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every cheesing rule.
///
/// A figure violates when its area is above the limit **and** it has no hole.
/// Both halves are needed: area alone flags every legitimate slotted plate, and
/// holes alone flags nothing.
///
/// `examined` counts merged figures.
pub fn check_cheesing(
    design: Design<'_>,
    table: &CheesingTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every density rule.
///
/// Sweeps a `window`-sided square across the layer's extent in `step`
/// increments and measures the covered fraction in each, via
/// `core::rects::clipped_area` over that polygon's own rectangle slice. The
/// slice is passed per polygon precisely so this cannot read another polygon's
/// rows — the kernel-rule violation that made the old `rectilinear_occupancy`
/// 43% of a signoff run.
///
/// One violation per offending window, reported at the window's lower-left
/// corner with the fraction as the measurement. Windows overlap, so one hot
/// spot produces several adjacent violations; that is honest, and merging them
/// would need a second pass that hides where the worst point is.
///
/// `examined` counts windows evaluated. `Outcome::Skipped(SkipReason::EmptyLayer)`
/// when the layer has no geometry, because a density fraction over an empty
/// extent is undefined rather than zero.
pub fn check_density(
    design: Design<'_>,
    table: &DensityTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}
