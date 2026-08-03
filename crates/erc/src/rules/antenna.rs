//! Process-stage rules: antenna ratios and windowed density.
//!
//! Three kinds. They need exact geometry and deck limits, and nothing about
//! this particular design — a plasma-etch antenna ratio and a CMP density
//! target are properties of the process, so they are in the deck and these
//! rules always run.
//!
//! # Why these are here and not in `drc`
//!
//! Because both need connectivity. An antenna ratio accumulates the collecting
//! area of everything electrically joined to a gate *at the stage that layer is
//! etched*, which is a net question with a layer cut-off. Density is the
//! exception — it needs no nets — and it lives here because it shares the
//! windowed-area machinery and the CMP model with nothing in `drc`.
//!
//! # Areas are exact
//!
//! Every area in this module is a [`DbuArea`], summed in `i128`. A ratio is the
//! only `f64` and it is formed once, at the comparison. The old implementation
//! accumulated bounding-box areas in `i64` and compared floats it had already
//! rounded twice.
//!
//! [`DbuArea`]: gpurify_units::DbuArea

use crate::ruleset::RuleHead;
use crate::{Design, Scratch};
use gpurify_core::Bbox;
use gpurify_derived::LayerRef;
use gpurify_report::{RuleRun, Violations};
use gpurify_units::Dbu;

/// What an antenna rule counts as collecting area.
///
/// Closed, two variants, because the two are measured from different things:
/// horizontal area is the polygon's area, sidewall area is its union perimeter
/// times the layer's thickness. A deck that states one and means the other is
/// off by the aspect ratio of the wire, which at advanced nodes is most of the
/// answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntennaMeasure {
    /// Horizontal collecting area — the polygon's own area.
    Area,
    /// Vertical etched sidewall: union perimeter times the finished thickness
    /// of the layer.
    Sidewall { thickness: Dbu },
}

/// A calibrated first-order CMP thickness model for one layer.
///
/// Not a physical simulation: a linear response of finished thickness to local
/// density, with the coefficients coming from the foundry. It earns its place
/// because a density that passes its own limits can still produce a thickness
/// excursion, and that excursion is what a downstream layer's lithography sees.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CmpModel {
    /// Density the process is calibrated at.
    pub target_density: f64,
    pub nominal_thickness: Dbu,
    /// Thickness change for a density one full unit above target. Signed:
    /// dishing and erosion pull opposite ways.
    pub thickness_sensitivity: Dbu,
    /// Excursion from nominal that is a violation.
    pub max_abs_thickness_delta: Dbu,
}

/// Per-stage antenna ratio: one fabrication stage, one collecting set.
///
/// The collectors are a list rather than one layer because a stage etches
/// everything present at that stage — metal 3's etch sees metal 1, 2 and 3 and
/// every via below. The deck states that set per rule, which is what makes a
/// rule correspond to a real step in the process rather than to a layer.
#[derive(Debug, Default)]
pub struct AntennaTable {
    pub head: RuleHead,
    /// The gate whose area is the denominator — normally the derived
    /// `poly AND diff`, never the poly layer alone.
    pub gate: Vec<LayerRef>,
    /// `collector[collector_start[i] .. collector_start[i + 1]]` and the
    /// parallel `collector_measure` are row `i`'s collecting set. CSR.
    pub collector_start: Vec<u32>,
    pub collector: Vec<LayerRef>,
    pub collector_measure: Vec<AntennaMeasure>,
    /// Collecting area over gate area, above which the gate is at risk.
    /// Dimensionless: a ratio of two quantities of the same dimension, which is
    /// why the units crate makes that division produce a bare `f64`.
    pub max_ratio: Vec<f64>,
}

/// Cumulative antenna ratio, with diode credit.
///
/// The same accumulation summed across every metal layer on the net rather than
/// per stage, and reduced by any protection diode on the net:
///
/// ```text
/// ratio = collecting_area / gate_area - credit * diode_area - bonus
/// ```
///
/// Separate from [`AntennaTable`] rather than a flag on it, because the
/// accumulation is over a different set and the diode terms have no meaning in
/// the per-stage form. A `diode: Option<..>` on one shared table would be a
/// column that is `None` for every per-stage row.
#[derive(Debug, Default)]
pub struct AntennaElectricalTable {
    pub head: RuleHead,
    pub gate: Vec<LayerRef>,
    /// `collector[collector_start[i] .. collector_start[i + 1]]`, CSR. Every
    /// conductor on the net counts, so there is no per-collector measure here.
    pub collector_start: Vec<u32>,
    pub collector: Vec<LayerRef>,
    /// The protection diode layer, when the deck configures one.
    ///
    /// An `Option` in a table, deliberately: this is a handful of rows read
    /// once per run, not bulk data, and the existence-based alternative — a
    /// second table for rules with diodes — would duplicate five columns to
    /// avoid one branch executed twice per run.
    pub diode: Vec<Option<LayerRef>>,
    /// `credit` above: ratio credited per unit of diode area.
    pub diode_credit: Vec<f64>,
    /// `bonus` above: flat credit for the presence of any diode.
    pub diode_bonus: Vec<f64>,
    pub max_ratio: Vec<f64>,
}

/// Windowed density, and the thickness it implies.
///
/// A sliding window over the die, one density per position. Both bounds are
/// optional because a layer can have a floor, a ceiling, or both — but an
/// absent bound means *not checked*, and the [`RuleRun`] says so rather than
/// the report reading clean on a limit nobody stated.
#[derive(Debug, Default)]
pub struct DensityCmpTable {
    pub head: RuleHead,
    pub layer: Vec<LayerRef>,
    /// Window extent, and the step between window positions. A step smaller
    /// than the window overlaps deliberately: a violation straddling two
    /// non-overlapping windows appears in neither.
    pub window: Vec<(Dbu, Dbu)>,
    pub step: Vec<(Dbu, Dbu)>,
    pub min_density: Vec<Option<f64>>,
    pub max_density: Vec<Option<f64>>,
    /// Largest density difference permitted between adjacent windows. A steep
    /// gradient polishes unevenly even when every window is in range.
    pub max_neighbour_delta: Vec<Option<f64>>,
    pub cmp: Vec<Option<CmpModel>>,
    /// Whether a window clipped by the die edge is evaluated against its
    /// clipped area, or skipped.
    ///
    /// Skipping leaves a strip along the die edge unchecked, so a deck that
    /// sets this `false` must have steps that cover both edges exactly — and
    /// [`crate::RuleSet::from_deck`] rejects it when they do not. An unchecked
    /// strip nobody was told about is the failure mode; an explicit choice is
    /// not.
    pub include_partial_windows: Vec<bool>,
}

/// Per-stage antenna ratio, per gate net.
///
/// **Transform.** Per rule row and per stage: accumulate collecting area into a
/// per-net slot of `scratch`, accumulate gate area into another, then divide
/// once per net. Two passes over the geometry and one over the nets; no net is
/// touched twice and no area is recomputed.
///
/// The violation is reported at the gate, not at the wire, because the gate is
/// what fails and the gate is what a fix adds a diode to. `measured` is the
/// ratio, `limit` is `max_ratio`, sense [`Maximum`].
///
/// `examined` is the number of gate nets — nets carrying at least one gate
/// polygon under the row's gate layer.
///
/// [`Maximum`]: gpurify_report::LimitSense::Maximum
pub fn check_antenna(
    design: Design<'_>,
    table: &AntennaTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Cumulative antenna ratio, per gate net, with diode credit applied.
///
/// **Transform.** Same accumulation as [`check_antenna`] over the whole
/// collecting set at once, then the diode terms subtracted before the compare.
/// The subtraction happens on the ratio and not on the area, because that is
/// how a foundry states the credit and the two are not interchangeable.
///
/// A diode large enough to drive the ratio negative is not an error: it means
/// the net is protected, and the compare simply passes.
///
/// `examined` is the number of gate nets.
pub fn check_antenna_electrical(
    design: Design<'_>,
    table: &AntennaElectricalTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Density of every window, and the thickness the CMP model predicts.
///
/// **Transform.** Per rule row: rasterise the layer's area into the window grid
/// once, then read each window's numerator out of `scratch`. That is the whole
/// reason `die` is a parameter — the denominator is the window's area clipped
/// to the die, and a window's density is meaningless without it.
///
/// Each window is a function of its own accumulated area and the row's
/// uniforms, so the pass is a kernel and parallelises by window range. The
/// neighbour-delta check is a second pass over the finished density array, for
/// the kernel rule's reason: it reads what the first pass wrote.
///
/// `examined` is the number of windows evaluated, which is what distinguishes
/// a clean run from a step configuration that produced no windows at all.
pub fn check_density_cmp(
    design: Design<'_>,
    die: Bbox,
    table: &DensityCmpTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}
