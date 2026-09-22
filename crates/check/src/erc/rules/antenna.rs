//! Process-stage rules: antenna ratios and windowed density.
//!
//! A cumulative antenna check is one rule row per fabrication stage, row `k`
//! naming everything present when layer `k` is etched. Areas are doubled
//! [`DbuArea`]s summed in `i128`; a ratio is the only `f64`, formed at the
//! comparison.
//!
//! Data in: the store, nets, the die box. Data out: violations and one run
//! per row.

use crate::erc::ruleset::RuleHead;
use crate::erc::{centre, record_run, Design, Scratch};
use crate::report::{LimitSense, Measurement, Outcome, RuleRun, Violation, Violations};
use crate::topology::NetId;
use gpurify_geom::boolean::union_into;
use gpurify_geom::ops::area2;
use gpurify_geom::rects::{clipped_area, decompose_into, Rect};
use gpurify_geom::view::validate_layer_into;
use gpurify_geom::{Bbox, LayerId, PolyId};
use gpurify_geom::{Dbu, DbuArea, MAX_ABS_DBU};

/// What an antenna rule counts as collecting area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntennaMeasure {
    /// The polygon's own area.
    Area,
    /// Etched sidewall. Refused: the unit of perimeter-times-thickness against
    /// a gate area is unstated.
    Sidewall { thickness: Dbu },
}

/// A first-order CMP model: finished thickness linear in local density.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CmpModel {
    pub target_density: f64,
    pub nominal_thickness: Dbu,
    /// Thickness change per unit density above target; signed.
    pub thickness_sensitivity: Dbu,
    pub max_abs_thickness_delta: Dbu,
}

/// Per-stage antenna ratio: collecting area over gate area, per gate net.
#[derive(Debug, Default)]
pub struct AntennaTable {
    pub head: RuleHead,
    pub gate: Vec<LayerId>,
    /// `collector[collector_start[i] .. collector_start[i + 1]]` and the
    /// parallel `collector_measure` are row `i`'s collecting set.
    pub collector_start: Vec<u32>,
    pub collector: Vec<LayerId>,
    pub collector_measure: Vec<AntennaMeasure>,
    pub max_ratio: Vec<f64>,
}

/// Cumulative antenna ratio with diode credit:
/// `collecting / gate - credit * diode_area - bonus`.
#[derive(Debug, Default)]
pub struct AntennaElectricalTable {
    pub head: RuleHead,
    pub gate: Vec<LayerId>,
    /// `collector[collector_start[i] .. collector_start[i + 1]]`, CSR.
    pub collector_start: Vec<u32>,
    pub collector: Vec<LayerId>,
    pub diode: Vec<Option<LayerId>>,
    pub diode_credit: Vec<f64>,
    pub diode_bonus: Vec<f64>,
    pub max_ratio: Vec<f64>,
}

/// Windowed density, and the thickness it implies. An absent bound is *not
/// checked*.
#[derive(Debug, Default)]
pub struct DensityCmpTable {
    pub head: RuleHead,
    pub layer: Vec<LayerId>,
    /// Window extent and step; a step under the window overlaps on purpose.
    pub window: Vec<(Dbu, Dbu)>,
    pub step: Vec<(Dbu, Dbu)>,
    pub min_density: Vec<Option<f64>>,
    pub max_density: Vec<Option<f64>>,
    /// Largest density difference between adjacent windows.
    pub max_neighbour_delta: Vec<Option<f64>>,
    pub cmp: Vec<Option<CmpModel>>,
    /// Evaluate a die-clipped window against its clipped area, or skip it.
    pub include_partial_windows: Vec<bool>,
}

/// Role bits in the per-layer table.
const GATE: u8 = 0;
const COLLECTS: u8 = 1;
const DIODE: u8 = 2;

/// Doubled collecting, gate and diode area per net: `areas[n]`,
/// `areas[count + n]`, `areas[2 * count + n]`. Doubled so [`area2`] stays
/// exact; the ratio cancels the factor.
fn net_areas_into(design: Design<'_>, roles: &[u8], areas: &mut Vec<DbuArea>) {
    let count = design.nets.net_count();
    areas.clear();
    areas.resize(3 * count, DbuArea::new(0));
    for slot in 0..count {
        let net = NetId(u32::try_from(slot).expect("a net count fits a u32"));
        let (mut collecting, mut gate, mut diode) = (0i128, 0i128, 0i128);
        for &poly in design.nets.polys_of(net) {
            let role = roles[design.store.poly_layer(poly).idx()];
            let (xs, ys) = design.store.poly_verts(poly);
            let doubled = area2(xs, ys).raw();
            collecting += doubled * i128::from((role >> COLLECTS) & 1);
            gate += doubled * i128::from((role >> GATE) & 1);
            diode += doubled * i128::from((role >> DIODE) & 1);
        }
        areas[slot] = DbuArea::new(collecting);
        areas[count + slot] = DbuArea::new(gate);
        areas[2 * count + slot] = DbuArea::new(diode);
    }
}

/// One antenna row: area per net, the ratio per gate net (after `adjust`,
/// which receives the net's real diode area), reported at the net's lowest
/// gate polygon. Returns `examined`, the number of gate nets.
///
/// Panics when the row names a layer the store does not have.
#[allow(
    clippy::cast_precision_loss,
    reason = "a die's area in database units is far below 2^53"
)]
fn antenna_row(
    design: Design<'_>,
    head: (&RuleHead, usize),
    layers: (LayerId, &[LayerId], Option<LayerId>),
    limit: f64,
    adjust: impl Fn(f64, DbuArea) -> f64,
    scratch: &mut Scratch,
    out: &mut Violations,
) -> u64 {
    let (gate_layer, collectors, diode) = layers;
    let mut roles = vec![0u8; design.store.layer_count()];
    roles[gate_layer.idx()] |= 1 << GATE;
    for &layer in collectors {
        roles[layer.idx()] |= 1 << COLLECTS;
    }
    if let Some(layer) = diode {
        roles[layer.idx()] |= 1 << DIODE;
    }
    net_areas_into(design, &roles, &mut scratch.areas);
    let areas = &scratch.areas;

    let count = design.nets.net_count();
    let limit = Measurement::Ratio(limit);
    let mut examined = 0u64;
    for slot in 0..count {
        let gate = areas[count + slot].raw();
        if gate <= 0 {
            continue;
        }
        examined += 1;
        let ratio = adjust(
            areas[slot].raw() as f64 / gate as f64,
            DbuArea::new(areas[2 * count + slot].raw() / 2),
        );
        if !Measurement::Ratio(ratio).violates(limit, LimitSense::Maximum) {
            continue;
        }
        let poly = design
            .nets
            .polys_of(NetId(u32::try_from(slot).expect("a net count fits a u32")))
            .iter()
            .copied()
            .find(|&poly| (roles[design.store.poly_layer(poly).idx()] >> GATE) & 1 == 1)
            .expect("a net with positive gate area carries a gate polygon");
        out.push(Violation {
            rule: head.0.rule[head.1],
            layer: gate_layer,
            severity: head.0.severity[head.1],
            at: centre(design.store.poly_bbox(poly)),
            measured: Measurement::Ratio(ratio),
            limit,
            shapes: (poly, None),
        });
    }
    examined
}

/// Per-stage antenna ratio, reported at the gate. A row with a sidewall
/// collector is refused.
pub fn check_antenna(
    design: Design<'_>,
    table: &AntennaTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    for row in 0..table.head.len() {
        let rule = table.head.rule[row];
        let before = out.len();
        let span = table.collector_start[row] as usize..table.collector_start[row + 1] as usize;
        if table.collector_measure[span.clone()]
            .iter()
            .any(|measure| matches!(measure, AntennaMeasure::Sidewall { .. }))
        {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }
        let examined = antenna_row(
            design,
            (&table.head, row),
            (table.gate[row], &table.collector[span], None),
            table.max_ratio[row],
            |ratio, _| ratio,
            scratch,
            out,
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Cumulative antenna ratio with diode credit, subtracted from the ratio (as a
/// foundry states it). A row whose verdict depends on `credit * diode_area` is
/// refused: that area's unit is unstated.
pub fn check_antenna_electrical(
    design: Design<'_>,
    table: &AntennaElectricalTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    for row in 0..table.head.len() {
        let rule = table.head.rule[row];
        let (credit, bonus) = (table.diode_credit[row], table.diode_bonus[row]);
        let before = out.len();
        let span = table.collector_start[row] as usize..table.collector_start[row + 1] as usize;
        let diode = table.diode[row];
        if diode.is_some() && credit != 0.0 {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }
        let examined = antenna_row(
            design,
            (&table.head, row),
            (table.gate[row], &table.collector[span], diode),
            table.max_ratio[row],
            #[allow(
                clippy::cast_precision_loss,
                reason = "a diode's area in database units is far below 2^53"
            )]
            |ratio, diode_area| ratio - credit * diode_area.raw() as f64 - bonus,
            scratch,
            out,
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Window positions along a span: every window starts inside the die.
fn positions(span: i64, step: i64) -> usize {
    if span <= 0 {
        return 0;
    }
    usize::try_from((span - 1) / step + 1).expect("a window count fits a usize")
}

/// The half-open range of windows `[origin + i * step, + window]` that the
/// interval `[lo, hi]` contributes area to (an edge-on touch contributes none).
fn window_span(
    lo: i64,
    hi: i64,
    origin: i64,
    window: i64,
    step: i64,
    count: usize,
) -> (usize, usize) {
    let count = i64::try_from(count).expect("a window count fits an i64");

    // `div_euclid` floors a negative numerator; `/` would not.
    let first = (lo - window - origin).div_euclid(step) + 1;
    // `ceil((hi - origin) / step)`, spelled as a negated floor.
    let end = -((origin - hi).div_euclid(step));

    let first = first.clamp(0, count);
    let end = end.clamp(first, count);
    let narrow = |edge: i64| usize::try_from(edge).expect("a clamped window index is not negative");
    (narrow(first), narrow(end))
}

/// Window `(i, j)`, and the same window clipped to the die (the density
/// denominator). Every window from [`positions`] meets the die.
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

/// The half-open range of windows whose die-clipped box `[lo, hi]` touches,
/// boundary included (unlike [`window_span`]). `far` is the die's far edge: an
/// interval starting past it touches nothing.
fn window_touch_span(
    lo: i64,
    hi: i64,
    origin: i64,
    far: i64,
    window: i64,
    step: i64,
    count: usize,
) -> (usize, usize) {
    let count = i64::try_from(count).expect("a window count fits an i64");

    let first = -((window + origin - lo).div_euclid(step));
    let end = (hi - origin).div_euclid(step) + 1;

    let past = i64::from(lo > far) * count;
    let first = first.clamp(0, count).max(past);
    let end = end.clamp(first, count);
    let narrow = |edge: i64| usize::try_from(edge).expect("a clamped window index is not negative");
    (narrow(first), narrow(end))
}

/// `out[j * nx + i]`: the lowest store row whose box touches die-clipped window
/// `(i, j)`, or `u32::MAX`. `boxes[k]` is store row `first_row + k`.
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
}

/// The store row a window violation names; `fallback` for an empty window.
fn window_owner(owners: &[u32], slot: usize, fallback: u32) -> PolyId {
    let best = owners[slot];
    let none = u32::from(best == u32::MAX).wrapping_neg();
    PolyId((best & !none) | (fallback & none))
}

/// Density of every window (area clipped to `die`), neighbour deltas, and the
/// CMP thickness excursion. `examined` counts windows evaluated.
#[allow(
    clippy::cast_precision_loss,
    reason = "a die's area in database units is far below 2^53"
)]
pub fn check_density_cmp(
    design: Design<'_>,
    die: Bbox,
    table: &DensityCmpTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let mut rects: Vec<Rect> = Vec::new();
    let mut rect_start: Vec<u32> = Vec::new();
    let mut density: Vec<f64> = Vec::new();
    let mut owners: Vec<u32> = Vec::new();

    for row in 0..table.head.len() {
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        let (window, step) = (table.window[row], table.step[row]);
        let violations_before = out.len();

        // A non-positive window has no density; a non-positive step never advances.
        let layer = table.layer[row];
        if window.0.raw() <= 0 || window.1.raw() <= 0 || step.0.raw() <= 0 || step.1.raw() <= 0 {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        }

        let Scratch {
            layer_a,
            layer_b,
            areas,
            ..
        } = &mut *scratch;

        // Self-union merges overlaps, so a density stays inside `0.0 ..= 1.0`.
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

        // An absent bound is not checked: the flag admits the compare's answer.
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

        let boxes = design.store.layer_bboxes(layer);
        let store_rows = design.store.polys_on_layer(layer);
        // A window holding no geometry is attributed to the layer's lowest row.
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

        // Row-major from the die's lower-left; the delta pass relies on it.
        density.clear();
        density.reserve(count);
        let mut examined = 0u64;
        for j in 0..ny {
            for i in 0..nx {
                let (full, clipped) = window_boxes(die, (i, j), window, step);
                let counted = partial | die.contains(full);
                let numerator = areas[j * nx + i].raw();
                let denominator = clipped.area().raw();
                let value = numerator as f64 / denominator.max(1) as f64;
                density.push(value);

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

                if let Some(model) = cmp {
                    let excursion =
                        model.thickness_sensitivity.raw() as f64 * (value - model.target_density);
                    // Saturated at the coordinate domain: violates every limit.
                    #[allow(clippy::cast_possible_truncation, reason = "saturated first")]
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

        // Gradient to the two windows ahead (`+1`, `+nx`); `min` clamps the
        // last column and row onto themselves, a zero difference.
        if let Some(delta) = table.max_neighbour_delta[row] {
            let limit = Measurement::Ratio(delta);
            for j in 0..ny {
                for i in 0..nx {
                    let slot = j * nx + i;
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

        record_run(runs, out, violations_before, rule, Outcome::Ran, examined);
    }
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
