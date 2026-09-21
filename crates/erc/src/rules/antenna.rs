//! Process-stage rules: antenna ratios and windowed density.
//!
//! A cumulative antenna check is one measurement per fabrication *stage* over
//! what exists at that stage, not one over the final stack — so it is spelled as
//! one rule row per stage, row `k` naming everything present when layer `k` is
//! etched. Measuring the final stack instead misses exactly the failure the rule
//! is for.
//!
//! Every area here is a [`DbuArea`] summed in `i128`; a ratio is the only `f64`
//! and it is formed once, at the comparison.
//!
//! [`DbuArea`]: gpurify_geom::DbuArea

use crate::ruleset::RuleHead;
use crate::{base_layer, centre, record_run, Design, Scratch};
use gpurify_geom::boolean::union_into;
use gpurify_geom::ops::area2;
use gpurify_geom::rects::{clipped_area, decompose_into, Rect};
use gpurify_geom::view::validate_layer_into;
use gpurify_geom::{Bbox, LayerId, PolyId};
use gpurify_geom::LayerRef;
use gpurify_ingest::StrId;
use gpurify_report::{LimitSense, Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use gpurify_topology::NetId;
use gpurify_geom::{Dbu, DbuArea, MAX_ABS_DBU};

/// What an antenna rule counts as collecting area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntennaMeasure {
    /// Horizontal collecting area — the polygon's own area.
    Area,
    /// Vertical etched sidewall: union perimeter times layer thickness.
    Sidewall { thickness: Dbu },
}

/// A calibrated first-order CMP thickness model for one layer: a linear
/// response of finished thickness to local density.
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
/// The collectors are a list because a stage etches everything present at that
/// stage — metal 3's etch sees metal 1, 2 and 3 and every via below.
#[derive(Debug, Default)]
pub struct AntennaTable {
    pub head: RuleHead,
    /// The gate whose area is the denominator.
    pub gate: Vec<LayerRef>,
    /// `collector[collector_start[i] .. collector_start[i + 1]]` and the
    /// parallel `collector_measure` are row `i`'s collecting set.
    pub collector_start: Vec<u32>,
    pub collector: Vec<LayerRef>,
    pub collector_measure: Vec<AntennaMeasure>,
    /// Collecting area over gate area, above which the gate is at risk.
    pub max_ratio: Vec<f64>,
}

/// Cumulative antenna ratio, with diode credit:
/// `ratio = collecting_area / gate_area - credit * diode_area - bonus`.
#[derive(Debug, Default)]
pub struct AntennaElectricalTable {
    pub head: RuleHead,
    pub gate: Vec<LayerRef>,
    /// `collector[collector_start[i] .. collector_start[i + 1]]`, CSR.
    pub collector_start: Vec<u32>,
    pub collector: Vec<LayerRef>,
    /// The protection diode layer, when the deck configures one.
    pub diode: Vec<Option<LayerRef>>,
    /// `credit` above: ratio credited per unit of diode area.
    pub diode_credit: Vec<f64>,
    /// `bonus` above: flat credit for the presence of any diode.
    pub diode_bonus: Vec<f64>,
    pub max_ratio: Vec<f64>,
}

/// Windowed density, and the thickness it implies.
///
/// An absent bound means *not checked*, never a bound that happens to pass.
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
    /// Largest density difference permitted between adjacent windows.
    pub max_neighbour_delta: Vec<Option<f64>>,
    pub cmp: Vec<Option<CmpModel>>,
    /// Whether a window clipped by the die edge is evaluated against its
    /// clipped area, or skipped.
    ///
    /// `false` leaves a strip along the die edge unchecked, so the deck's steps
    /// must cover both edges exactly; [`crate::RuleSet::from_deck`] rejects it
    /// when they do not.
    pub include_partial_windows: Vec<bool>,
}

/// Bit index in the per-layer role table: this layer's shapes are gates.
const GATE: u8 = 0;
/// Bit index: this layer's shapes collect plasma charge during the etch.
const COLLECTS: u8 = 1;
/// Bit index: this layer's shapes are protection diodes.
const DIODE: u8 = 2;

/// A rule row's collecting set as base layers, or `false` if any of it is
/// derived.
///
/// Fail closed on [`LayerRef::Named`]: a derived polygon has no map back to the
/// store rows a violation names, so running the rule over the base layers it
/// happens to mention would check different geometry than the deck asked for.
fn base_layers_into(refs: &[LayerRef], out: &mut Vec<LayerId>) -> bool {
    out.clear();
    out.reserve(refs.len());
    for &reference in refs {
        let Some(layer) = base_layer(reference) else {
            return false;
        };
        out.push(layer);
    }
    debug_assert!(out.len() <= refs.len(), "a resolve cannot grow its input");
    out.len() == refs.len()
}

/// Which part each of the store's layers plays in one antenna rule row:
/// `out[layer.idx()]` carries the [`GATE`], [`COLLECTS`] and [`DIODE`] bits.
///
/// # Panics
///
/// When a rule names a layer the store's layer table does not have. Fail
/// closed: skipping it would run the rule over less geometry than the deck
/// named and report the design clean.
fn roles_into(
    layer_count: usize,
    gate: LayerId,
    collectors: &[LayerId],
    diode: Option<LayerId>,
    out: &mut Vec<u8>,
) {
    out.clear();
    out.resize(layer_count, 0);
    out[gate.idx()] |= 1 << GATE;
    for &layer in collectors {
        out[layer.idx()] |= 1 << COLLECTS;
    }
    if let Some(layer) = diode {
        out[layer.idx()] |= 1 << DIODE;
    }
    debug_assert_eq!(out.len(), layer_count, "the role table is dense");
}

/// Doubled collecting, gate and diode area, per net.
///
/// `areas` is refilled to `3 * net_count` rows: net `n`'s collecting area is
/// `areas[n]`, its gate area `areas[net_count + n]`, its diode area
/// `areas[2 * net_count + n]`.
///
/// Every one is **doubled**: [`area2`] is exact in integers and the halving is
/// the one place a rounding could enter. The ratio divides one of these by
/// another and the factor of two cancels.
fn net_areas_into(design: Design<'_>, roles: &[u8], areas: &mut Vec<DbuArea>) {
    let count = design.nets.net_count();
    areas.clear();
    areas.resize(3 * count, DbuArea::new(0));

    for slot in 0..count {
        let net = NetId(u32::try_from(slot).expect("a net count fits a u32"));
        let mut collecting = 0i128;
        let mut gate = 0i128;
        let mut diode = 0i128;
        for &poly in design.nets.polys_of(net) {
            let role = roles[design.store.poly_layer(poly).idx()];
            let (xs, ys) = design.store.poly_verts(poly);
            let doubled = area2(xs, ys).raw();
            // The role bit is the multiplier, so a layer that is both a
            // collector and a diode lands in both.
            collecting += doubled * i128::from((role >> COLLECTS) & 1);
            gate += doubled * i128::from((role >> GATE) & 1);
            diode += doubled * i128::from((role >> DIODE) & 1);
        }
        areas[slot] = DbuArea::new(collecting);
        areas[count + slot] = DbuArea::new(gate);
        areas[2 * count + slot] = DbuArea::new(diode);
    }

    debug_assert_eq!(areas.len(), 3 * count, "three accumulators per net");
}

/// The lowest-numbered polygon on `net` that lies on a gate layer.
///
/// `polys_of` is ascending, so the first match is the lowest store row and two
/// runs report the same coordinate.
fn gate_poly(design: Design<'_>, roles: &[u8], net: NetId) -> Option<PolyId> {
    design
        .nets
        .polys_of(net)
        .iter()
        .copied()
        .find(|&poly| (roles[design.store.poly_layer(poly).idx()] >> GATE) & 1 == 1)
}

/// The four uniforms a ratio report reads, hoisted above the net loop.
#[derive(Debug, Clone, Copy)]
struct RatioRow {
    rule: StrId,
    severity: Severity,
    /// The gate layer: what the violation row names, because the gate fails.
    layer: LayerId,
    limit: f64,
}

/// Divide once per net, compare, and report at the gate.
///
/// Shared by both antenna rules, which differ only in `adjust`: the per-stage
/// form passes the ratio through, the cumulative form subtracts its diode terms.
///
/// Returns `examined`: the number of nets carrying gate area under this row's
/// gate layer.
#[allow(
    clippy::cast_precision_loss,
    reason = "a die's area in database units is far below 2^53, and the ratio is \
              an f64 by the time it reaches a report either way"
)]
fn report_ratios(
    design: Design<'_>,
    roles: &[u8],
    areas: &[DbuArea],
    row: RatioRow,
    adjust: impl Fn(f64, DbuArea) -> f64,
    out: &mut Violations,
) -> u64 {
    let count = design.nets.net_count();
    debug_assert_eq!(areas.len(), 3 * count, "three accumulators per net");
    debug_assert!(
        row.limit.is_finite(),
        "a non-finite antenna limit passes every ratio, which is fail-open"
    );
    let limit = Measurement::Ratio(row.limit);
    let mut examined = 0u64;

    for slot in 0..count {
        let collecting = areas[slot].raw();
        let gate = areas[count + slot].raw();
        let is_gate_net = gate > 0;
        examined += u64::from(is_gate_net);

        // `max(1)`: a net with no gate divides by one instead of by zero, so
        // the ratio stays finite and `violates`' finiteness assert holds.
        // `is_gate_net` keeps that meaningless number out of the report.
        let ratio = adjust(
            collecting as f64 / gate.max(1) as f64,
            // Halved back out of the doubled accumulator: a diode credit is
            // stated against a real area, not twice one.
            DbuArea::new(areas[2 * count + slot].raw() / 2),
        );
        debug_assert!(
            ratio.is_finite(),
            "a non-finite ratio compares false against every limit, which reads clean"
        );
        let violated = is_gate_net & Measurement::Ratio(ratio).violates(limit, LimitSense::Maximum);

        if violated {
            let net = NetId(u32::try_from(slot).expect("a net count fits a u32"));
            let poly = gate_poly(design, roles, net)
                .expect("a net with positive gate area carries a gate polygon");
            out.push(Violation {
                rule: row.rule,
                layer: row.layer,
                severity: row.severity,
                at: centre(design.store.poly_bbox(poly)),
                measured: Measurement::Ratio(ratio),
                limit,
                shapes: (poly, None),
            });
        }
    }

    debug_assert!(
        examined <= u64::try_from(count).expect("a net count fits a u64"),
        "a gate net is a net, so there cannot be more of them than there are nets"
    );
    examined
}

/// How many window positions a span holds at a given step.
///
/// The window at `origin + count * step` would start at or past the far edge of
/// the die and evaluate nothing, so the count stops one short of it.
fn positions(span: i64, step: i64) -> usize {
    debug_assert!(step > 0, "a non-positive step never advances");
    // A zero-width die must not report one window covering nothing.
    if span <= 0 {
        return 0;
    }
    usize::try_from((span - 1) / step + 1).expect("a window count fits a usize")
}

/// The half-open range of window positions one rectangle can contribute to.
///
/// Window `i` spans `[origin + i * step, origin + i * step + window]`, so it
/// meets `[lo, hi]` exactly when its far edge is past `lo` and its near edge is
/// before `hi`; solving both for `i` gives the range directly.
fn window_span(
    lo: i64,
    hi: i64,
    origin: i64,
    window: i64,
    step: i64,
    count: usize,
) -> (usize, usize) {
    debug_assert!(step > 0 && window > 0, "a window and a step are positive");
    debug_assert!(lo <= hi, "a rectangle's bounds run low to high");
    let count = i64::try_from(count).expect("a window count fits an i64");

    // `div_euclid`, not `/`: for a positive divisor it floors, which `/` does
    // not do for a negative numerator — and a rectangle left of the die's
    // origin makes the numerator negative.
    let first = (lo - window - origin).div_euclid(step) + 1;
    // `ceil((hi - origin) / step)`, spelled as a negated floor.
    let end = -((origin - hi).div_euclid(step));

    let first = first.clamp(0, count);
    let end = end.clamp(first, count);
    debug_assert!(
        first <= end && end <= count,
        "a window range is inside the grid"
    );
    let narrow = |edge: i64| usize::try_from(edge).expect("a clamped window index is not negative");
    (narrow(first), narrow(end))
}

/// Window `(i, j)` of one rule row's grid, and the same window clipped to the
/// die.
///
/// The clip is what makes a density a fraction: clipping the numerator and not
/// the denominator is how a density escapes `0.0 ..= 1.0`.
///
/// # Panics
///
/// Never, for `i < nx` and `j < ny`: [`positions`] stops one short of the
/// window that would start at or past the far edge, so every window this is
/// asked for has its low corner inside the die.
fn window_boxes(
    die: Bbox,
    at: (usize, usize),
    window: (Dbu, Dbu),
    step: (Dbu, Dbu),
) -> (Bbox, Bbox) {
    let index = |at: usize| i64::try_from(at).expect("a window index fits an i64");
    let xlo = die.xlo.raw() + index(at.0) * step.0.raw();
    let ylo = die.ylo.raw() + index(at.1) * step.1.raw();
    let (xhi, yhi) = (xlo + window.0.raw(), ylo + window.1.raw());
    debug_assert!(
        Dbu::new(xhi).is_some() && Dbu::new(yhi).is_some(),
        "a window running off the coordinate domain has no i128-bounded area"
    );
    let full = Bbox {
        xlo: Dbu::new_unchecked(xlo),
        ylo: Dbu::new_unchecked(ylo),
        xhi: Dbu::new_unchecked(xhi),
        yhi: Dbu::new_unchecked(yhi),
    };
    let clipped = full
        .intersection(die)
        .expect("a window position inside the grid meets the die");
    (full, clipped)
}

/// The half-open range of window positions whose *clipped* box one coordinate
/// interval touches, boundary included.
///
/// Distinct from [`window_span`], which wants the windows a rectangle
/// contributes *area* to and so excludes an edge-on touch. `far` is the die's
/// far edge on this axis: a window's clipped span never reaches past it, so an
/// interval starting beyond `far` touches no window at all.
fn window_touch_span(
    lo: i64,
    hi: i64,
    origin: i64,
    far: i64,
    window: i64,
    step: i64,
    count: usize,
) -> (usize, usize) {
    debug_assert!(step > 0 && window > 0, "a window and a step are positive");
    debug_assert!(lo <= hi, "a bounding box's bounds run low to high");
    let count = i64::try_from(count).expect("a window count fits an i64");

    // Window `i`'s clipped span is `[origin + i * step, min(origin + i * step +
    // window, far)]`; solving inclusive overlap with `[lo, hi]` for `i` gives
    // the range directly.
    //
    // `div_euclid`, not `/`: for a positive divisor it floors, which `/` does
    // not do for a negative numerator — and a box left of the die's origin makes
    // the numerator negative.
    let first = -((window + origin - lo).div_euclid(step));
    let end = (hi - origin).div_euclid(step) + 1;

    // `lo > far` drives `first` to `count` and the clamp collapses `end` onto
    // it, so the whole box drops out.
    let past = i64::from(lo > far) * count;
    let first = first.clamp(0, count).max(past);
    let end = end.clamp(first, count);
    debug_assert!(
        first <= end && end <= count,
        "a window range is inside the grid"
    );
    let narrow = |edge: i64| usize::try_from(edge).expect("a clamped window index is not negative");
    (narrow(first), narrow(end))
}

/// The store row every window of one rule row's grid is attributed to.
///
/// `out[j * nx + i]` is the lowest store row whose bounding box reaches window
/// `(i, j)` clipped to the die, or `u32::MAX` where the layer reaches that
/// window with nothing. `boxes[k]` is store row `first_row + k`, and the column
/// is ascending, so the lowest row is the lowest index.
fn window_owners_into(
    boxes: &[Bbox],
    first_row: u32,
    die: Bbox,
    window: (Dbu, Dbu),
    step: (Dbu, Dbu),
    grid: (usize, usize),
    out: &mut Vec<u32>,
) {
    let (nx, ny) = grid;
    let count = nx * ny;
    out.clear();
    out.resize(count, u32::MAX);

    for (offset, &bbox) in boxes.iter().enumerate() {
        let row = first_row + u32::try_from(offset).expect("a layer's row count fits a u32");
        let (i0, i1) = window_touch_span(
            bbox.xlo.raw(),
            bbox.xhi.raw(),
            die.xlo.raw(),
            die.xhi.raw(),
            window.0.raw(),
            step.0.raw(),
            nx,
        );
        let (j0, j1) = window_touch_span(
            bbox.ylo.raw(),
            bbox.yhi.raw(),
            die.ylo.raw(),
            die.yhi.raw(),
            window.1.raw(),
            step.1.raw(),
            ny,
        );
        for j in j0..j1 {
            for i in i0..i1 {
                let slot = j * nx + i;
                out[slot] = out[slot].min(row);
            }
        }
    }

    debug_assert_eq!(out.len(), count, "one owner slot per window");
    debug_assert!(
        out.iter().all(|&row| row == u32::MAX
            || (row >= first_row
                && usize::try_from(row - first_row).expect("a row offset fits a usize")
                    < boxes.len())),
        "an owner is a row of this layer, or the absent sentinel"
    );
}

/// The store row a window violation names, read out of the owner grid.
///
/// A window a minimum-density rule flags may hold no geometry at all, and
/// [`Violation`] has no spelling for "no shape", so the fallback is the layer's
/// own lowest row.
fn window_owner(owners: &[u32], slot: usize, fallback: u32) -> PolyId {
    debug_assert!(
        slot < owners.len(),
        "a window slot is inside the owner grid"
    );
    let best = owners[slot];
    let none = u32::from(best == u32::MAX).wrapping_neg();
    PolyId((best & !none) | (fallback & none))
}

/// Per-stage antenna ratio, per gate net.
///
/// The violation is reported at the gate, not at the wire: the gate is what
/// fails and what a fix adds a diode to.
pub fn check_antenna(
    design: Design<'_>,
    table: &AntennaTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.len();
    debug_assert_eq!(table.gate.len(), rows, "one gate layer per rule row");
    debug_assert_eq!(table.max_ratio.len(), rows, "one limit per rule row");
    debug_assert_eq!(
        table.collector_measure.len(),
        table.collector.len(),
        "one measure per collector"
    );
    debug_assert!(
        rows == 0 || table.collector_start.len() == rows + 1,
        "one CSR offset per rule row, plus the trailing one"
    );
    let runs_before = runs.len();

    let mut roles: Vec<u8> = Vec::new();
    let mut collectors: Vec<LayerId> = Vec::new();

    for row in 0..rows {
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        let violations_before = out.len();
        let span = table.collector_start[row] as usize..table.collector_start[row + 1] as usize;
        debug_assert!(
            span.end <= table.collector.len(),
            "a collecting set leaves its column"
        );

        // Fail closed, three ways, before any geometry is touched. `Sidewall`
        // is refused because the unit of perimeter-times-thickness against a
        // gate area is unstated, so any number produced here would settle an
        // open convention by implementation.
        let refused = !matches!(table.gate[row], LayerRef::Base(_))
            || !base_layers_into(&table.collector[span.clone()], &mut collectors)
            || table.collector_measure[span]
                .iter()
                .any(|measure| matches!(measure, AntennaMeasure::Sidewall { .. }));
        if refused {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        }
        let LayerRef::Base(gate) = table.gate[row] else {
            unreachable!("the refusal above rejected every derived gate layer")
        };

        roles_into(
            design.store.layer_count(),
            gate,
            &collectors,
            None,
            &mut roles,
        );
        net_areas_into(design, &roles, &mut scratch.areas);
        let examined = report_ratios(
            design,
            &roles,
            &scratch.areas,
            RatioRow {
                rule,
                severity,
                layer: gate,
                limit: table.max_ratio[row],
            },
            |ratio, _| ratio,
            out,
        );
        record_run(runs, out, violations_before, rule, Outcome::Ran, examined);
    }

    debug_assert_eq!(
        runs.len() - runs_before,
        rows,
        "one run row per rule row, whatever the outcome"
    );
}

/// Cumulative antenna ratio, per gate net, with diode credit applied.
///
/// The subtraction happens on the ratio and not on the area, because that is
/// how a foundry states the credit and the two are not interchangeable. A diode
/// large enough to drive the ratio negative means the net is protected and the
/// compare simply passes.
pub fn check_antenna_electrical(
    design: Design<'_>,
    table: &AntennaElectricalTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.len();
    debug_assert_eq!(table.gate.len(), rows, "one gate layer per rule row");
    debug_assert_eq!(table.diode.len(), rows, "one diode slot per rule row");
    debug_assert_eq!(table.diode_credit.len(), rows, "one credit per rule row");
    debug_assert_eq!(table.diode_bonus.len(), rows, "one bonus per rule row");
    debug_assert_eq!(table.max_ratio.len(), rows, "one limit per rule row");
    debug_assert!(
        rows == 0 || table.collector_start.len() == rows + 1,
        "one CSR offset per rule row, plus the trailing one"
    );
    let runs_before = runs.len();

    let mut roles: Vec<u8> = Vec::new();
    let mut collectors: Vec<LayerId> = Vec::new();

    for row in 0..rows {
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        let (credit, bonus) = (table.diode_credit[row], table.diode_bonus[row]);
        let violations_before = out.len();
        let span = table.collector_start[row] as usize..table.collector_start[row + 1] as usize;
        debug_assert!(
            span.end <= table.collector.len(),
            "a collecting set leaves its column"
        );

        let diode = match table.diode[row] {
            None => None,
            Some(LayerRef::Base(layer)) => Some(layer),
            Some(LayerRef::Named(_)) => {
                record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
                continue;
            }
        };

        // Fail closed. The third condition: the unit of the area `diode_credit`
        // multiplies is unstated, so a row whose verdict depends on that product
        // is refused. A row with no diode or a zero credit does not depend on it
        // — the product is zero under every candidate unit — so it runs.
        let refused = !matches!(table.gate[row], LayerRef::Base(_))
            || !base_layers_into(&table.collector[span], &mut collectors)
            || (diode.is_some() && credit != 0.0);
        if refused {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        }
        let LayerRef::Base(gate) = table.gate[row] else {
            unreachable!("the refusal above rejected every derived gate layer")
        };
        debug_assert!(
            credit.is_finite() && bonus.is_finite(),
            "a non-finite diode term makes every ratio non-finite, which reads clean"
        );

        roles_into(
            design.store.layer_count(),
            gate,
            &collectors,
            diode,
            &mut roles,
        );
        net_areas_into(design, &roles, &mut scratch.areas);
        let examined = report_ratios(
            design,
            &roles,
            &scratch.areas,
            RatioRow {
                rule,
                severity,
                layer: gate,
                limit: table.max_ratio[row],
            },
            #[allow(
                clippy::cast_precision_loss,
                reason = "a diode's area in database units is far below 2^53"
            )]
            |ratio, diode_area| ratio - credit * diode_area.raw() as f64 - bonus,
            out,
        );
        record_run(runs, out, violations_before, rule, Outcome::Ran, examined);
    }

    debug_assert_eq!(
        runs.len() - runs_before,
        rows,
        "one run row per rule row, whatever the outcome"
    );
}

/// Density of every window, and the thickness the CMP model predicts.
///
/// `die` is a parameter because the denominator is the window's area clipped to
/// the die, and a window's density is meaningless without it.
///
/// `examined` is the number of windows evaluated, which distinguishes a clean
/// run from a step configuration that produced no windows at all.
#[allow(
    clippy::cast_precision_loss,
    reason = "a die's area in database units is far below 2^53, and a density is \
              an f64 by the time it reaches a report either way"
)]
#[allow(
    clippy::too_many_lines,
    reason = "three passes over one window grid, each of which reads what the \
              previous one wrote; splitting them would hand the split functions \
              the same eleven uniforms this one already holds"
)]
pub fn check_density_cmp(
    design: Design<'_>,
    die: Bbox,
    table: &DensityCmpTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.len();
    debug_assert_eq!(table.layer.len(), rows, "one layer per rule row");
    debug_assert_eq!(table.window.len(), rows, "one window per rule row");
    debug_assert_eq!(table.step.len(), rows, "one step per rule row");
    debug_assert_eq!(table.min_density.len(), rows, "one floor per rule row");
    debug_assert_eq!(table.max_density.len(), rows, "one ceiling per rule row");
    debug_assert_eq!(table.max_neighbour_delta.len(), rows, "one delta per row");
    debug_assert_eq!(table.cmp.len(), rows, "one CMP model slot per rule row");
    debug_assert_eq!(
        table.include_partial_windows.len(),
        rows,
        "one edge policy per rule row"
    );
    debug_assert!(
        die.xlo.raw() <= die.xhi.raw() && die.ylo.raw() <= die.yhi.raw(),
        "the die box runs low to high"
    );
    let runs_before = runs.len();

    let mut rects: Vec<Rect> = Vec::new();
    let mut rect_start: Vec<u32> = Vec::new();
    let mut density: Vec<f64> = Vec::new();
    let mut owners: Vec<u32> = Vec::new();

    for row in 0..rows {
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        let (window, step) = (table.window[row], table.step[row]);
        let violations_before = out.len();

        // Fail closed: a derived layer has no map back to the store rows a
        // violation names, a non-positive window has no density to speak of, and
        // a non-positive step never advances.
        let refused = !matches!(table.layer[row], LayerRef::Base(_))
            || window.0.raw() <= 0
            || window.1.raw() <= 0
            || step.0.raw() <= 0
            || step.1.raw() <= 0;
        if refused {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        }
        let LayerRef::Base(layer) = table.layer[row] else {
            unreachable!("the refusal above rejected every derived layer")
        };

        let Scratch {
            layer_a,
            layer_b,
            areas,
            ..
        } = &mut *scratch;

        // Self-union is the merge: two overlapping input polygons trace as one
        // boundary, so the numerator is the region the layer covers rather than
        // a sum that double-counts every overlap. That is what keeps a density
        // inside `0.0 ..= 1.0` for a layer drawn with redundant shapes.
        if validate_layer_into(design.store, layer, layer_a).is_err() {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        }
        let operand: &_ = layer_a;
        if union_into(operand, operand, layer_b).is_err() {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        }
        decompose_into(layer_b, design.store, &mut rects, &mut rect_start);

        let nx = positions(die.xhi.raw() - die.xlo.raw(), step.0.raw());
        let ny = positions(die.yhi.raw() - die.ylo.raw(), step.1.raw());
        let count = nx * ny;
        areas.clear();
        areas.resize(count, DbuArea::new(0));

        // Rasterise the merged layer into the window grid.
        for rect in &rects {
            let (i0, i1) = window_span(
                rect.xlo.raw(),
                rect.xhi.raw(),
                die.xlo.raw(),
                window.0.raw(),
                step.0.raw(),
                nx,
            );
            let (j0, j1) = window_span(
                rect.ylo.raw(),
                rect.yhi.raw(),
                die.ylo.raw(),
                window.1.raw(),
                step.1.raw(),
                ny,
            );
            for j in j0..j1 {
                for i in i0..i1 {
                    let (_, clipped) = window_boxes(die, (i, j), window, step);
                    let slot = j * nx + i;
                    areas[slot] = areas[slot] + clipped_area(std::slice::from_ref(rect), clipped);
                }
            }
        }

        // The `is_some` and the value are split so the compare below is
        // unconditional and the flag is what admits its answer: an absent bound
        // is *not checked*, never a bound that happens to pass.
        let (min_on, min) = (
            table.min_density[row].is_some(),
            table.min_density[row].unwrap_or(0.0),
        );
        let (max_on, max) = (
            table.max_density[row].is_some(),
            table.max_density[row].unwrap_or(0.0),
        );
        let cmp = table.cmp[row];
        let partial = table.include_partial_windows[row];
        debug_assert!(
            min.is_finite() && max.is_finite(),
            "a non-finite density bound compares false against every window"
        );

        let boxes = design.store.layer_bboxes(layer);
        let store_rows = design.store.polys_on_layer(layer);
        debug_assert_eq!(
            boxes.len(),
            store_rows.len(),
            "the bounding-box column and the row range are the same layer"
        );
        // The layer's lowest row is what a window holding no geometry is
        // attributed to, because `Violation` has no spelling for "no shape".
        let fallback = if store_rows.start < store_rows.end {
            store_rows.start
        } else {
            0
        };
        window_owners_into(
            boxes,
            store_rows.start,
            die,
            window,
            step,
            (nx, ny),
            &mut owners,
        );

        // One density per window, row-major from the die's lower-left — the
        // neighbour-delta pass below depends on that order.
        density.clear();
        density.reserve(count);
        let mut examined = 0u64;
        for j in 0..ny {
            for i in 0..nx {
                let (full, clipped) = window_boxes(die, (i, j), window, step);
                // A window the die clips is evaluated when the deck says so and
                // contributes nothing when it does not.
                let counted = partial | die.contains(full);
                let numerator = areas[j * nx + i].raw();
                let denominator = clipped.area().raw();
                debug_assert!(denominator > 0, "a window meeting the die covers area");
                let value = numerator as f64 / denominator.max(1) as f64;
                density.push(value);
                debug_assert!(
                    (0.0..=1.0).contains(&value),
                    "window ({i}, {j}) covers {numerator} of {denominator}, which is not a fraction"
                );

                examined += u64::from(counted);
                let measured = Measurement::Ratio(value);
                let under = counted
                    & min_on
                    & measured.violates(Measurement::Ratio(min), LimitSense::Minimum);
                let over = counted
                    & max_on
                    & measured.violates(Measurement::Ratio(max), LimitSense::Maximum);

                if under {
                    out.push(Violation {
                        rule,
                        layer,
                        severity,
                        at: centre(clipped),
                        measured,
                        limit: Measurement::Ratio(min),
                        shapes: (window_owner(&owners, j * nx + i, fallback), None),
                    });
                }
                if over {
                    out.push(Violation {
                        rule,
                        layer,
                        severity,
                        at: centre(clipped),
                        measured,
                        limit: Measurement::Ratio(max),
                        shapes: (window_owner(&owners, j * nx + i, fallback), None),
                    });
                }

                // A first-order linear response: the excursion from nominal is
                // the sensitivity times the density's distance from the
                // calibration point.
                if let Some(model) = cmp {
                    let excursion =
                        model.thickness_sensitivity.raw() as f64 * (value - model.target_density);
                    debug_assert!(excursion.is_finite(), "a CMP model with no finite response");
                    // Saturating at the coordinate domain rather than wrapping:
                    // a saturated excursion violates every limit, which is the
                    // fail-closed side.
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "saturated to the coordinate domain on the line above, \
                                  so the truncation is of a value already in range"
                    )]
                    let magnitude =
                        Dbu::new_unchecked(excursion.abs().min(MAX_ABS_DBU as f64) as i64);
                    if counted
                        & Measurement::Length(magnitude).violates(
                            Measurement::Length(model.max_abs_thickness_delta),
                            LimitSense::Maximum,
                        )
                    {
                        out.push(Violation {
                            rule,
                            layer,
                            severity,
                            at: centre(clipped),
                            measured: Measurement::Length(magnitude),
                            limit: Measurement::Length(model.max_abs_thickness_delta),
                            shapes: (window_owner(&owners, j * nx + i, fallback), None),
                        });
                    }
                }
            }
        }
        debug_assert_eq!(density.len(), count, "one density per window");

        // The gradient between adjacent windows, a second pass because it reads
        // what the first wrote. Adjacency is the storage order above: `+1` along
        // x, `+nx` along y.
        if let Some(delta) = table.max_neighbour_delta[row] {
            debug_assert!(
                delta.is_finite(),
                "a non-finite gradient limit checks nothing"
            );
            let limit = Measurement::Ratio(delta);
            for j in 0..ny {
                for i in 0..nx {
                    let slot = j * nx + i;
                    // Two neighbours per window, the ones ahead of it, so each
                    // adjacent pair is examined once. `min` clamps the last row
                    // and column onto themselves, whose difference is zero and
                    // violates nothing.
                    let ahead = [j * nx + (i + 1).min(nx - 1), (j + 1).min(ny - 1) * nx + i];
                    for neighbour in ahead {
                        let gap = Measurement::Ratio((density[slot] - density[neighbour]).abs());
                        if gap.violates(limit, LimitSense::Maximum) {
                            let (_, clipped) = window_boxes(die, (i, j), window, step);
                            out.push(Violation {
                                rule,
                                layer,
                                severity,
                                at: centre(clipped),
                                measured: gap,
                                limit,
                                shapes: (window_owner(&owners, j * nx + i, fallback), None),
                            });
                        }
                    }
                }
            }
        }

        debug_assert!(
            examined <= u64::try_from(count).expect("a window count fits a u64"),
            "a rule cannot examine more windows than the grid holds"
        );
        record_run(runs, out, violations_before, rule, Outcome::Ran, examined);
    }

    debug_assert_eq!(
        runs.len() - runs_before,
        rows,
        "one run row per rule row, whatever the outcome"
    );
}

#[cfg(test)]
mod tests {
    use super::{positions, window_boxes, window_owners_into, Bbox, Dbu};

    fn bbox(xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> Bbox {
        Bbox {
            xlo: Dbu::new_unchecked(xlo),
            ylo: Dbu::new_unchecked(ylo),
            xhi: Dbu::new_unchecked(xhi),
            yhi: Dbu::new_unchecked(yhi),
        }
    }

    /// The linear scan [`window_owners_into`] replaced: the lowest row whose
    /// bounding box overlaps the window clipped to the die.
    fn owner_by_scan(
        boxes: &[Bbox],
        first_row: u32,
        die: Bbox,
        at: (usize, usize),
        window: (Dbu, Dbu),
        step: (Dbu, Dbu),
    ) -> u32 {
        let (_, clipped) = window_boxes(die, at, window, step);
        boxes
            .iter()
            .position(|b| b.overlaps(clipped))
            .map_or(u32::MAX, |k| {
                first_row + u32::try_from(k).expect("a test row count fits a u32")
            })
    }

    /// The owner grid answers exactly what the scan did, window for window.
    ///
    /// The cases that separate this span from the area span are the boundary
    /// ones: a box touching a window edge-on is an owner and contributes no
    /// area, and a box past the die's far edge is clipped away rather than
    /// folded onto the border window. Both are in the table, along with
    /// overlapping and non-overlapping steps.
    #[test]
    fn the_owner_grid_answers_what_the_linear_scan_did() {
        let die = bbox(0, 0, 300, 200);
        // Lowest row first, deliberately: the grid keeps the minimum, so a box
        // that must claim *no* window only proves it when nothing below it
        // would have claimed the same slot anyway.
        let boxes = [
            // Past the far edge on both axes, but near enough that an
            // *unclipped* window would still reach it. The one case the `far`
            // gate answers and the arithmetic alone does not.
            bbox(320, 250, 340, 260),
            bbox(400, 10, 500, 20),       // wholly past the die's far edge
            bbox(-500, -500, -400, -400), // wholly left of and below the die
            // Touches the edge shared by two windows exactly, on both axes.
            bbox(100, 0, 100, 200),
            bbox(10, 10, 40, 40),
            bbox(250, 150, 400, 400), // hangs off the far corner
            bbox(0, 0, 300, 200),     // the whole die
        ];
        let first_row = 7;

        let mut owners = Vec::new();
        for (wx, wy, sx, sy) in [
            (100, 100, 100, 100), // window == step, no overlap
            (100, 100, 50, 50),   // overlapping windows
            (150, 200, 100, 100), // window wider than the step
            (300, 200, 300, 200), // one window covering the whole die
            (7, 11, 13, 17),      // nothing divides anything
        ] {
            let window = (Dbu::new_unchecked(wx), Dbu::new_unchecked(wy));
            let step = (Dbu::new_unchecked(sx), Dbu::new_unchecked(sy));
            let nx = positions(die.xhi.raw() - die.xlo.raw(), sx);
            let ny = positions(die.yhi.raw() - die.ylo.raw(), sy);

            window_owners_into(&boxes, first_row, die, window, step, (nx, ny), &mut owners);
            assert_eq!(owners.len(), nx * ny, "one owner slot per window");

            for j in 0..ny {
                for i in 0..nx {
                    assert_eq!(
                        owners[j * nx + i],
                        owner_by_scan(&boxes, first_row, die, (i, j), window, step),
                        "window ({i}, {j}) of a {wx}x{wy} window stepped by {sx}x{sy}"
                    );
                }
            }
        }
    }
}
