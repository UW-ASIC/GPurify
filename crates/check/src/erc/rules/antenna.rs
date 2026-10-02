//! Process-stage rules: antenna ratios and windowed density.
//!
//! A cumulative antenna check is one rule row per fabrication stage, row `k`
//! naming everything present when layer `k` is etched. Nets are built per row
//! from only the conductors that exist at that etch (SVRF `CONNECT` between
//! `NET AREA RATIO` stages), so a diode or a second gate reachable only
//! through a higher metal does not count yet. Areas are doubled [`DbuArea`]s
//! summed in `i128`; a ratio is the only `f64`, formed at the comparison.
//!
//! Data in: the store, nets, the die box. Data out: violations and one run
//! per row.

use crate::drc::rules::{owners_of, LayerRects, SortedRects};
use crate::erc::ruleset::RuleHead;
use crate::erc::{centre, record_run, Design, Scratch};
use crate::report::{LimitSense, Measurement, Outcome, RuleRun, Violation, Violations};
use crate::topology::{extract_nets_into, NetId, NetTable};
use gpurify_geom::boolean::union_into;
use gpurify_geom::ops::area2;
use gpurify_geom::rects::{clipped_area, decompose_into};
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::{Bbox, LayerId, PolyId};
use gpurify_geom::{Dbu, DbuArea, MAX_ABS_DBU};
use gpurify_ingest::deck::Connectivity;

/// What an antenna rule counts as collecting area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntennaMeasure {
    /// The polygon's own area.
    Area,
    /// Etched sidewall: the merged layer's perimeter times `thickness`, an
    /// area like the gate's (sky130 poly/li/met1-3, gf180 `perimeter_only`).
    Sidewall { thickness: Dbu },
}

/// The deck's conductors (bottom-up) and via rows, from which each antenna
/// row's etch-step connectivity is cut.
#[derive(Debug, Default)]
pub struct Stack {
    pub conductors: Vec<LayerId>,
    /// `(cut, lower, upper)`.
    pub vias: Vec<(LayerId, LayerId, LayerId)>,
    pub intra_layer_touch: bool,
}

impl Stack {
    /// The connectivity standing when the highest of `collectors` is etched:
    /// conductors up to it, and the vias joining two of them. A cut collector
    /// stands on its lower conductor. `None` when the deck names no conductors
    /// (the finished nets are used as given).
    fn stage(&self, collectors: &[LayerId]) -> Option<Connectivity> {
        if self.conductors.is_empty() {
            return None;
        }
        let pos = |layer: LayerId| self.conductors.iter().position(|&c| c == layer);
        let top = collectors
            .iter()
            .filter_map(|&c| {
                pos(c).or_else(|| {
                    self.vias
                        .iter()
                        .filter(|v| v.0 == c)
                        .filter_map(|&(_, a, b)| Some(pos(a)?.min(pos(b)?)))
                        .max()
                })
            })
            .max()
            .unwrap_or(self.conductors.len() - 1);
        let standing = |layer: LayerId| pos(layer).is_some_and(|at| at <= top);
        let (via_cut, via_connects) = self
            .vias
            .iter()
            .filter(|&&(_, a, b)| standing(a) && standing(b))
            .map(|&(cut, a, b)| (cut, (a, b)))
            .unzip();
        Some(Connectivity {
            conductors: self.conductors[..=top].to_vec(),
            via_cut,
            via_connects,
            intra_layer_touch: self.intra_layer_touch,
            ..Connectivity::default()
        })
    }
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
    pub stack: Stack,
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
    pub stack: Stack,
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

/// The net of every store row on `layer` that is not a conductor: that of the
/// topmost conductor (last in `conductors`, which is bottom-up) it overlaps
/// with positive area, the lowest net among that conductor's shapes. A
/// derived gate `poly and diff` sits on poly, not the well under it; a cut on
/// the metal under it. Touching alone does not join, so a gate is not put on
/// the diffusion beside it. `false` when a layer will not validate.
fn attach(
    design: Design<'_>,
    layer: LayerId,
    conductors: &[LayerId],
    nets: &NetTable,
    net_of: &mut [NetId],
    scratch: &mut Scratch,
) -> bool {
    let store = design.store;
    if store.polys_on_layer(layer).is_empty() {
        return true;
    }
    if validate_layer_into(store, layer, &mut scratch.layer_a).is_err() {
        return false;
    }
    let mut mine = LayerRects::default();
    mine.build(store, layer, &scratch.layer_a);
    let mut best = vec![NetId::NONE; mine.len()];
    let mut theirs = LayerRects::default();
    for &conductor in conductors {
        if validate_layer_into(store, conductor, &mut scratch.layer_b).is_err() {
            return false;
        }
        theirs.build(store, conductor, &scratch.layer_b);
        let under = SortedRects::new(theirs.labelled());
        for (poly, slot) in (0u32..).zip(best.iter_mut()) {
            let mut here = NetId::NONE;
            for &r in mine.of(poly) {
                for (_, row) in under.overlapping(r) {
                    here = here.min(nets.net_of(row));
                }
            }
            if here != NetId::NONE {
                *slot = here;
            }
        }
    }
    let first = store.polys_on_layer(layer).start;
    for (offset, &poly) in mine.poly_of_row.iter().enumerate() {
        net_of[first as usize + offset] = best[poly as usize];
    }
    true
}

/// Twice the perimeter of every merged figure on `layer`, with the store row
/// it is blamed on. `None` when the layer will not validate or merge.
fn merged_perimeters(
    design: Design<'_>,
    layer: LayerId,
    scratch: &mut Scratch,
) -> Option<Vec<(PolyId, i128)>> {
    validate_layer_into(design.store, layer, &mut scratch.layer_a).ok()?;
    let mut drawn = LayerRects::default();
    drawn.build(design.store, layer, &scratch.layer_a);
    union_into(
        &scratch.layer_a,
        &ValidatedLayer::default(),
        &mut scratch.layer_b,
    )
    .ok()?;
    let figures = &scratch.layer_b;
    Some(
        (0..)
            .zip(owners_of(figures, &drawn))
            .map(|(idx, owner)| {
                let poly = figures.get(idx);
                let perimeter: i128 = std::iter::once(poly.outer())
                    .chain(poly.holes())
                    .map(|ring| {
                        let (xs, ys) = ring.coords();
                        (0..xs.len())
                            .map(|i| {
                                let j = (i + 1) % xs.len();
                                i128::from(
                                    (xs[j] - xs[i]).raw().abs() + (ys[j] - ys[i]).raw().abs(),
                                )
                            })
                            .sum::<i128>()
                    })
                    .sum();
                (owner, 2 * perimeter)
            })
            .collect(),
    )
}

/// One antenna row: nets as they stand at this row's etch step, doubled
/// collecting, gate and diode area per net, the ratio per gate net (after
/// `adjust`, which receives the net's diode area), reported at the net's
/// lowest gate polygon. `examined` is the number of gate nets; `None` is
/// `Refused` (a layer that will not validate).
#[allow(
    clippy::cast_precision_loss,
    reason = "a die's area in database units is far below 2^53"
)]
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
fn antenna_row(
    design: Design<'_>,
    head: (&RuleHead, usize),
    (gate_layer, collectors, diode): (LayerId, &[LayerId], Option<LayerId>),
    measures: &[AntennaMeasure],
    stack: &Stack,
    limit: f64,
    adjust: impl Fn(f64, DbuArea) -> f64,
    scratch: &mut Scratch,
    out: &mut Violations,
) -> Option<u64> {
    let store = design.store;
    let stage = stack.stage(collectors);
    let mut staged = std::mem::take(&mut scratch.staged_nets);
    let nets: &NetTable = match &stage {
        Some(connectivity) => {
            extract_nets_into(store, connectivity, &mut staged);
            &staged
        }
        None => design.nets,
    };
    if nets.net_count() == 0 {
        scratch.staged_nets = staged;
        return Some(0);
    }
    // Conductors: the stage's, or (finished nets) every layer carrying a net.
    let conductors: Vec<LayerId> = match &stage {
        Some(connectivity) => connectivity.conductors.clone(),
        None => (0..store.layer_count())
            .map(|l| LayerId(u16::try_from(l).expect("a LayerId is a u16")))
            .filter(|&l| {
                store
                    .polys_on_layer(l)
                    .any(|row| nets.net_of(PolyId(row)) != NetId::NONE)
            })
            .collect(),
    };

    // A collector named twice collects once, with its first measure.
    let mut read: Vec<(LayerId, AntennaMeasure)> = Vec::new();
    for (&layer, &measure) in collectors.iter().zip(measures) {
        if !read.iter().any(|&(l, _)| l == layer) {
            read.push((layer, measure));
        }
    }
    let mut net_of = vec![NetId::NONE; store.poly_count()];
    let mut layers: Vec<LayerId> = read.iter().map(|&(l, _)| l).collect();
    layers.push(gate_layer);
    layers.extend(diode);
    layers.sort_unstable();
    layers.dedup();
    let mut ok = true;
    for &layer in &layers {
        if conductors.contains(&layer) {
            for row in store.polys_on_layer(layer) {
                net_of[row as usize] = nets.net_of(PolyId(row));
            }
        } else {
            ok &= attach(design, layer, &conductors, nets, &mut net_of, scratch);
        }
    }

    let count = nets.net_count();
    let mut areas = vec![0i128; 3 * count];
    let mut first_gate = vec![PolyId(u32::MAX); count];
    let add = |layer: LayerId, base: usize, areas: &mut Vec<i128>| {
        for row in store.polys_on_layer(layer) {
            let net = net_of[row as usize];
            if net != NetId::NONE {
                let (xs, ys) = store.poly_verts(PolyId(row));
                areas[base + net.idx()] += area2(xs, ys).raw();
            }
        }
    };
    add(gate_layer, count, &mut areas);
    if let Some(layer) = diode {
        add(layer, 2 * count, &mut areas);
    }
    for row in store.polys_on_layer(gate_layer) {
        let net = net_of[row as usize];
        if net != NetId::NONE {
            first_gate[net.idx()] = first_gate[net.idx()].min(PolyId(row));
        }
    }
    for &(layer, measure) in &read {
        let AntennaMeasure::Sidewall { thickness } = measure else {
            add(layer, 0, &mut areas);
            continue;
        };
        let Some(figures) = merged_perimeters(design, layer, scratch) else {
            ok = false;
            continue;
        };
        for (row, twice_perimeter) in figures {
            let net = net_of[row.idx()];
            if net != NetId::NONE {
                areas[net.idx()] += twice_perimeter * i128::from(thickness.raw());
            }
        }
    }
    scratch.staged_nets = staged;
    if !ok {
        return None;
    }

    let limit = Measurement::Ratio(limit);
    let mut examined = 0u64;
    for slot in 0..count {
        let gate = areas[count + slot];
        if gate <= 0 {
            continue;
        }
        examined += 1;
        let ratio = adjust(
            areas[slot] as f64 / gate as f64,
            DbuArea::new(areas[2 * count + slot] / 2),
        );
        if !Measurement::Ratio(ratio).violates(limit, LimitSense::Maximum) {
            continue;
        }
        let poly = first_gate[slot];
        out.push(Violation {
            rule: head.0.rule[head.1],
            layer: gate_layer,
            severity: head.0.severity[head.1],
            at: centre(store.poly_bbox(poly)),
            measured: Measurement::Ratio(ratio),
            limit,
            shapes: (poly, None),
        });
    }
    Some(examined)
}

/// Per-stage antenna ratio, reported at the gate.
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
        let examined = antenna_row(
            design,
            (&table.head, row),
            (table.gate[row], &table.collector[span.clone()], None),
            &table.collector_measure[span],
            &table.stack,
            table.max_ratio[row],
            |ratio, _| ratio,
            scratch,
            out,
        );
        let (outcome, examined) = examined.map_or((Outcome::Refused, 0), |n| (Outcome::Ran, n));
        record_run(runs, out, before, rule, outcome, examined);
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
        let collectors = &table.collector[span];
        let examined = antenna_row(
            design,
            (&table.head, row),
            (table.gate[row], collectors, diode),
            &vec![AntennaMeasure::Area; collectors.len()],
            &table.stack,
            table.max_ratio[row],
            #[allow(
                clippy::cast_precision_loss,
                reason = "a diode's area in database units is far below 2^53"
            )]
            |ratio, diode_area| ratio - credit * diode_area.raw() as f64 - bonus,
            scratch,
            out,
        );
        let (outcome, examined) = examined.map_or((Outcome::Refused, 0), |n| (Outcome::Ran, n));
        record_run(runs, out, before, rule, outcome, examined);
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
    let mut rects: Vec<Bbox> = Vec::new();
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
        decompose_into(layer_b, &mut rects, &mut rect_start);

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
    use super::{positions, window_boxes, window_owners_into, Bbox, Dbu, LayerId, Stack};

    /// At an etch step only the conductors up to it exist: metal2's via row is
    /// cut, so a diode or gate reachable only through metal2 is not on the net
    /// yet. A cut collector stands on its lower conductor.
    #[test]
    fn a_stage_holds_the_conductors_up_to_its_etch_and_the_vias_between_them() {
        let [diff, poly, li, met1, met2] = [0, 1, 2, 3, 4].map(LayerId);
        let [licon, mcon, via1] = [5, 6, 7].map(LayerId);
        let stack = Stack {
            conductors: vec![diff, poly, li, met1, met2],
            vias: vec![
                (licon, diff, li),
                (licon, poly, li),
                (mcon, li, met1),
                (via1, met1, met2),
            ],
            intra_layer_touch: true,
        };

        let at_met1 = stack.stage(&[met1]).expect("a deck with conductors");
        assert_eq!(at_met1.conductors, [diff, poly, li, met1]);
        assert_eq!(at_met1.via_cut, [licon, licon, mcon]);

        let at_via1 = stack.stage(&[via1]).expect("a deck with conductors");
        assert_eq!(at_via1.conductors, [diff, poly, li, met1]);

        let at_poly = stack.stage(&[poly]).expect("a deck with conductors");
        assert_eq!(at_poly.conductors, [diff, poly]);
        assert!(at_poly.via_cut.is_empty());

        assert!(Stack::default().stage(&[met1]).is_none());
    }

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
