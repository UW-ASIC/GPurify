//! Overlay family: how two layers must sit relative to each other.
//!
//! Enclosure, extension and overlap are all the same question asked from
//! different sides — given a shape on layer A and a shape on layer B that
//! interact, is there enough of A around, past, or under B. They share a file
//! because they share the pairing step and the failure mode that goes with it.
//!
//! # Best host, not first host
//!
//! An inner shape may sit inside several outer shapes at once: a via under a
//! wide pad that a narrow wire also clips the corner of. The rule is satisfied
//! if the *best* host satisfies it, because after the layers are merged there
//! is only one host and it is the union. Taking the first host found, or the
//! worst, fails a via whose pad encloses it perfectly — and which host is
//! "first" depends on polygon order, so that variant is also nondeterministic.
//!
//! # An unhosted inner shape is zero enclosure, not skipped
//!
//! A via with no metal under it at all has an enclosure of zero and violates
//! every enclosure rule. Skipping it because no host was found is fail-open,
//! and it is the case that matters most.

use crate::{Design, Scratch};
use gpurify_core::{Bbox, LayerId};
use gpurify_ingest::StrId;
use gpurify_report::{RuleRun, Violations};
use gpurify_units::Dbu;

/// Minimum enclosure: the outer layer must surround the inner one by at least
/// the limit on **every** side.
#[derive(Debug, Default)]
pub struct MinEnclosureTable {
    pub rule: Vec<StrId>,
    /// The surrounding layer — metal under a via, implant around diffusion.
    pub outer: Vec<LayerId>,
    /// The surrounded layer.
    pub inner: Vec<LayerId>,
    pub limit: Vec<Dbu>,
}

/// Asymmetric enclosure: at least the limit on **one** side of each axis.
///
/// The relaxed form a foundry allows where lithographic overlay error is
/// directional: a via needs a landing pad on one side of each axis, not a
/// symmetric collar. Passes when
/// `max(left, right) >= limit && max(top, bottom) >= limit`.
#[derive(Debug, Default)]
pub struct AsymmetricEnclosureTable {
    pub rule: Vec<StrId>,
    pub outer: Vec<LayerId>,
    pub inner: Vec<LayerId>,
    /// Required on one side of each axis. Deliberately *not* named `limit`: the
    /// number means something weaker than the one in [`MinEnclosureTable`], and
    /// a reader who transposes the two rules should notice.
    pub min_one_side: Vec<Dbu>,
}

/// Minimum extension: one layer must run past another by at least the limit.
///
/// The poly endcap over diffusion is the canonical case — the gate must extend
/// beyond the channel or the transistor leaks around its end. Measured only
/// where the two shapes actually overlap, and on each side the layer protrudes.
#[derive(Debug, Default)]
pub struct MinExtensionTable {
    pub rule: Vec<StrId>,
    /// The layer that must stick out.
    pub layer: Vec<LayerId>,
    /// The layer it must stick out past.
    pub reference: Vec<LayerId>,
    pub limit: Vec<Dbu>,
}

/// Minimum overlap: two layers that meet must share at least this much.
///
/// Distinct from enclosure, which requires containment. Overlap only requires a
/// large enough intersection, so a wire crossing a strap satisfies it without
/// either shape containing the other. Measured on the exact boolean
/// intersection, not on bounding boxes — a bounding-box intersection
/// over-reports for any non-convex shape, and the old tree's `lvs` evaluator
/// did exactly that on the path feeding device recognition.
#[derive(Debug, Default)]
pub struct OverlapTable {
    pub rule: Vec<StrId>,
    pub a: Vec<LayerId>,
    pub b: Vec<LayerId>,
    /// The smaller side of the intersection rectangle must be at least this.
    /// A limit on *area* would pass a long thin sliver, which does not conduct.
    pub limit: Vec<Dbu>,
}

/// Maximum distance to a well tie: every point of a well must be within reach
/// of a tap.
///
/// A latch-up rule rather than a lithographic one. An untied well floats, its
/// junction forward-biases, and the parasitic thyristor fires — so the
/// constraint is on the *farthest* point of the well, not on the average.
#[derive(Debug, Default)]
pub struct MaxDistanceToTapTable {
    pub rule: Vec<StrId>,
    /// The region that needs tying — well or diffusion.
    pub well: Vec<LayerId>,
    /// The tie layer.
    pub tap: Vec<LayerId>,
    /// Violated above.
    pub limit: Vec<Dbu>,
}

impl MinEnclosureTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl AsymmetricEnclosureTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl MinExtensionTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl OverlapTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl MaxDistanceToTapTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

/// How far an outer shape extends past an inner one, per side.
///
/// **Decision** — two boxes in, four distances out, pure and table-testable,
/// and the one place the sign convention is written down: each field is
/// positive when the outer shape extends past the inner on that side, negative
/// when the inner sticks out. Negative is not an error here; it is what an
/// unhosted or overhanging shape measures, and clamping it to zero would hide
/// how badly the rule failed.
///
/// `AoS` because all four are read together by both enclosure rules and never
/// scanned one at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Margins {
    pub left: Dbu,
    pub right: Dbu,
    pub bottom: Dbu,
    pub top: Dbu,
}

impl Margins {
    /// The worst side. What [`check_min_enclosure`] compares.
    pub const fn worst(self) -> Dbu {
        todo!()
    }

    /// The better side of each axis, then the worse of those two. What
    /// [`check_asymmetric_enclosure`] compares:
    /// `min(max(left, right), max(bottom, top))`.
    pub const fn worst_axis_best_side(self) -> Dbu {
        todo!()
    }
}

/// Enclosure margins of `inner` within `outer`.
///
/// **Decision.** Bounding boxes, which is exact when the host is convex and
/// conservative otherwise — a non-convex host's box is larger than the host, so
/// this can *overstate* the enclosure. That direction fails open, so the
/// transforms below use it only as a prune and confirm containment exactly with
/// `ops::point_in_ring` before trusting a pass.
pub fn margins(inner: Bbox, outer: Bbox) -> Margins {
    todo!()
}

/// Check every minimum-enclosure rule.
///
/// **Transform.** For each inner shape, finds every containing outer shape,
/// takes the best [`Margins::worst`] among them, and compares. One violation
/// per offending inner shape, reported at its lower-left corner with the best
/// achievable margin as the measurement — so the number in the report is what
/// the layout actually has, not what the first candidate host happened to give.
///
/// `examined` counts inner shapes.
pub fn check_min_enclosure(
    design: Design<'_>,
    table: &MinEnclosureTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every asymmetric-enclosure rule.
///
/// Same pairing as [`check_min_enclosure`], reduced with
/// [`Margins::worst_axis_best_side`]. `examined` counts inner shapes.
pub fn check_asymmetric_enclosure(
    design: Design<'_>,
    table: &AsymmetricEnclosureTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every minimum-extension rule.
///
/// Only pairs that overlap are judged — a layer that does not meet the
/// reference at all is not failing to extend past it, it is somewhere else. The
/// measurement is the smallest protrusion across the sides where the layer does
/// protrude.
///
/// `examined` counts overlapping shape pairs.
pub fn check_min_extension(
    design: Design<'_>,
    table: &MinExtensionTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every overlap rule.
///
/// The exact intersection of the two merged layers, then the smaller dimension
/// of each resulting figure against the limit. One violation per insufficient
/// intersection, reported inside it.
///
/// `examined` counts intersection figures. `Outcome::Refused` if either
/// operand will not merge exactly.
pub fn check_overlap(
    design: Design<'_>,
    table: &OverlapTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every maximum-distance-to-tap rule.
///
/// Measures from the *corners* of each well shape, since the farthest point of
/// a rectilinear region from any finite point set is always a vertex. A well
/// violates if any of its corners is farther than the limit from every tap.
///
/// Distance is to the nearest point of the tap shape, not to its centre. The
/// old tree used the centre, which understates reach for a large tap strap and
/// therefore *over*-reports — a rare direction for a bug in this tree, but
/// still a wrong number in a report a human acts on.
///
/// `examined` counts well shapes. `Outcome::Skipped(SkipReason::EmptyLayer)`
/// when the well layer is empty; a well layer with no taps at all is **not**
/// skipped, it is a violation on every well shape.
pub fn check_max_distance_to_tap(
    design: Design<'_>,
    table: &MaxDistanceToTapTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}
