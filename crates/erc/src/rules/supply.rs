//! Supply, substrate and pad integrity — topological, but geometry-aware.
//!
//! Five kinds. Like [`crate::rules::topology`] they need no design intent, but
//! unlike those four they read marker geometry as well as the net graph: a tie
//! is a distance, a pad is a marker layer, a soft connection is a path through
//! a layer the deck names as resistive.
//!
//! # Why none of these asks "is this net VDD"
//!
//! Because that is a design-intent question, and these rules always run. A
//! supply short here is *an n-type tie and a p-type tie on one conductor* —
//! true of any CMOS process, provable from the deck's tap markers, and correct
//! without anyone declaring a net name. The version that compares net names
//! against a supply list lives in [`crate::rules::reliability`], where it is
//! gated on intent and says so.

use crate::facts::NetFacts;
use crate::ruleset::RuleHead;
use crate::{Design, Scratch};
use gpurify_core::LayerId;
use gpurify_derived::LayerRef;
use gpurify_ingest::StrId;
use gpurify_report::{RuleRun, Violations};
use gpurify_units::Dbu;

/// One conductor carrying two ties of opposite type.
///
/// An n-well tie and a p-substrate tie on the same extracted net is a rail
/// short: the well sits at the substrate's potential, every device on it is
/// mis-biased, and on a real die it is a hole in the power plane. The deck
/// names the two tap markers and the rule needs nothing else — no net names, no
/// device polarity enum, no heuristic about which drain is an output. The old
/// implementation had all three, and its comment admitted it was tuned to one
/// conformance case.
#[derive(Debug, Default)]
pub struct SupplyShortTable {
    pub head: RuleHead,
    /// The two ties whose sharing one net is the short: `nwell_tap` and
    /// `psub_tap` on a standard CMOS deck. Named, not inferred.
    pub tap_a: Vec<LayerRef>,
    pub tap_b: Vec<LayerRef>,
}

/// Two parts of a net joined only through a resistive body.
///
/// A net that is one net in the extraction but two conductors in the silicon,
/// bridged by a well or the substrate. It passes LVS and it does not work: the
/// bridge is kilohms, so the two halves are at different potentials under any
/// load.
///
/// The test is a partition, not a distance: remove the soft layers' shapes from
/// the net's connectivity and ask whether it falls into more than one
/// component. That makes it exact and independent of how far apart the halves
/// are, where the old bounding-box pairwise version was neither.
#[derive(Debug, Default)]
pub struct SoftConnectionTable {
    pub head: RuleHead,
    /// `soft[soft_start[i] .. soft_start[i + 1]]` are row `i`'s resistive
    /// layers — well, substrate, unsilicided poly. CSR.
    pub soft_start: Vec<u32>,
    pub soft: Vec<LayerRef>,
}

/// A point in a tied region too far from the nearest tie.
///
/// Substrate and well resistance is distributed, so a tie at one corner does
/// not hold a large region at potential; foundries state a maximum distance
/// from any point to a tap. The measurement is a distance, exact in [`Dbu`],
/// and it is the one rule here whose limit a grid conversion has to make
/// representable.
#[derive(Debug, Default)]
pub struct MissingTieTable {
    pub head: RuleHead,
    /// The region that must be tied throughout: a well, an active area, a
    /// substrate region.
    pub region: Vec<LayerRef>,
    /// What counts as a tie.
    pub tap: Vec<LayerRef>,
    /// Furthest any point of the region may be from a tap.
    pub max_distance: Vec<Dbu>,
}

/// A gate held at a rail with nothing able to drive it.
///
/// The net carries a gate terminal and a source terminal but no drain, so
/// nothing in the design can change its state. Often deliberate — an unused
/// input tied off is correct practice — which is why the severity is a column:
/// a deck decides whether this is an error or a note.
#[derive(Debug, Default)]
pub struct TieHighLowTable {
    pub head: RuleHead,
}

/// A pad reaching no protection device.
///
/// Every net that reaches a bond pad must also reach a clamp, or the first
/// discharge into that pin goes through a gate oxide. The pad is a marker layer
/// the PDK provides; the clamps are model names the deck lists. The old
/// implementation had neither and guessed at "metal touching the cell boundary"
/// instead, which flags every abutted standard cell in a row.
#[derive(Debug, Default)]
pub struct EsdTopologicalTable {
    pub head: RuleHead,
    /// The marker layer whose polygons are bond pads or I/O.
    pub pad: Vec<LayerId>,
    /// `clamp_model[clamp_start[i] .. clamp_start[i + 1]]` are the interned
    /// model names that count as protection for row `i`. CSR.
    pub clamp_start: Vec<u32>,
    pub clamp_model: Vec<StrId>,
}

/// Flag every net carrying both taps.
///
/// **Transform.** Per rule row: evaluate the two tap layers, mark each tap's
/// net in a per-net slot of `scratch` with which tap it was, and report every
/// net marked with both. Two passes for the kernel rule's reason — the second
/// reads what the first wrote, so they cannot be one.
///
/// `examined` is the number of tap polygons across both layers.
pub fn check_supply_short(
    design: Design<'_>,
    table: &SupplyShortTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Flag every net that falls apart once the resistive layers are removed.
///
/// **Transform.** Per rule row: build the net's connectivity edge list from
/// hard conductors only, label components with `core::connectivity`, and report
/// any net whose polygons carry more than one label. The edge list and the
/// labels are `scratch` buffers, so a design with a hundred thousand nets
/// allocates twice, not two hundred thousand times.
///
/// The violation names the two shapes on either side of the bridge, so a viewer
/// lands on the gap rather than on the net as a whole.
///
/// `examined` is the number of nets touching at least one soft layer.
pub fn check_soft_connection(
    design: Design<'_>,
    table: &SoftConnectionTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Flag every point of a region further than `max_distance` from a tap.
///
/// **Transform.** Per rule row: index the taps once, then for each region
/// polygon find the furthest point of the region from every tap. The reported
/// point is that furthest point, and the measurement is its distance — not the
/// corner-sampling approximation the old implementation used, which missed a
/// long thin region entirely because all four of its corners were near a tap.
///
/// Distances are exact: `core::ops::point_seg_dist2` in [`DbuArea`], compared
/// against the squared limit, so no square root and no rounding enters a
/// verdict.
///
/// `examined` is the number of region polygons.
///
/// [`DbuArea`]: gpurify_units::DbuArea
pub fn check_missing_tie(
    design: Design<'_>,
    table: &MissingTieTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Flag every net that is a gate and a source and not a drain.
///
/// **Transform.** One pass over [`NetFacts::role`]: the mask contains
/// `GATE | SOURCE` and does not contain `DRAIN`. Three bit tests per net, no
/// branch, no lookup.
///
/// `examined` is the number of nets carrying at least one gate terminal.
pub fn check_tie_high_low(
    design: Design<'_>,
    facts: &NetFacts,
    table: &TieHighLowTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Flag every pad net reaching none of the listed clamp models.
///
/// **Transform.** Per rule row: collect the nets under the pad markers, then
/// walk each such net's devices and test their model against the row's clamp
/// list. The list is two or three interned ids, so the test is a linear scan
/// over `u32` and not a set.
///
/// `examined` is the number of distinct pad nets.
pub fn check_esd_topological(
    design: Design<'_>,
    table: &EsdTopologicalTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}
