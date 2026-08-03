//! Via family: rules about vias as a *population* rather than as shapes.
//!
//! Both rules here are about how many cuts there are near each other, not about
//! how big any one of them is — a single via is a reliability risk whatever its
//! dimensions, and an array of them has to be pitched so the etch clears
//! between cuts. Every other property of a via is covered by the width,
//! spacing and enclosure families.
//!
//! # Counting is on the geometry, not on the net
//!
//! Two cuts count as redundant when they are physically adjacent, not when they
//! happen to be on the same net. A net can reach the same two conductors
//! through vias at opposite ends of a chip; those are not redundant, because
//! the failure being guarded against is one etch defect taking out one cut.

use crate::{Design, Scratch};
use gpurify_core::LayerId;
use gpurify_ingest::StrId;
use gpurify_report::{RuleRun, Violations};
use gpurify_units::Dbu;

/// Redundant via: an isolated cut is a single point of failure.
///
/// Every cut must have at least `min_count - 1` other cuts of the same layer
/// within `within` of it. A stated *count* rather than "must be doubled",
/// because triple-via requirements exist on the critical layers of some nodes.
#[derive(Debug, Default)]
pub struct RedundantViaTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// Cuts required in the neighbourhood, including the cut itself. Violated
    /// below. `u16`: a redundancy requirement is a small integer and a deck
    /// asking for 70 000 vias in one place is a typo, not a rule.
    pub min_count: Vec<u16>,
    /// The neighbourhood radius, and also the radius the candidate prune is
    /// built at.
    pub within: Vec<Dbu>,
}

/// Via array spacing: a dense group of cuts needs more pitch than a lone pair.
///
/// Etch loading rises with cut density, so once more than `array_threshold`
/// cuts form one cluster, every pair inside that cluster is held to
/// `limit` rather than to the layer's ordinary spacing.
///
/// A cluster is a connected component of the "within `limit` of each other"
/// graph, which is why this rule builds an edge list and calls
/// `core::connectivity` rather than scanning pairs alone.
#[derive(Debug, Default)]
pub struct ViaArraySpacingTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// A cluster larger than this is an array. Violated above, and only as a
    /// trigger — being in a big array is not itself a defect.
    pub array_threshold: Vec<u16>,
    /// The spacing every pair inside an array must have. Violated below.
    pub limit: Vec<Dbu>,
}

impl RedundantViaTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

impl ViaArraySpacingTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

/// Check every redundant-via rule.
///
/// **Transform.** Builds the index once per row, counts neighbours from the
/// candidate pairs in a single pass into the scratch, then judges each cut
/// against its count. Two passes rather than one: counting inside the judging
/// loop would mean row `n` reading what row `n - 1` wrote, which the kernel
/// rule forbids.
///
/// Neighbourhood distance is measured between the cuts' nearest points, not
/// their centres. Centres understate the distance for large cuts, so a
/// centre-based test *over*-counts neighbours and can call an isolated via
/// redundant — fail-open, and the old tree did it.
///
/// One violation per under-served cut, at the cut, measuring the count it had
/// against the count required. `examined` counts cuts.
pub fn check_redundant_via(
    design: Design<'_>,
    table: &RedundantViaTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Check every via-array-spacing rule.
///
/// Clusters first — edge list from the candidate pairs, then
/// `core::connectivity::components_into`, whose labels are the minimum member
/// index and therefore canonical. Then, for clusters above the threshold, every
/// pair inside is measured exactly.
///
/// One violation per offending pair inside a qualifying cluster, not one per
/// cluster: a 6×6 array with one bad column has a specific place to fix.
///
/// `examined` counts candidate pairs that fell inside a qualifying cluster.
pub fn check_via_array_spacing(
    design: Design<'_>,
    table: &ViaArraySpacingTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}
