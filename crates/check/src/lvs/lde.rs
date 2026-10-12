//! Layout-dependent effects of a transistor (catalog LVS-074): the STI
//! stress distances `SA` and `SB`, and the well-proximity integrals `SCA`,
//! `SCB` and `SCC`, BSIM4's instance parameters, measured from the drawn
//! active area and well and added to the layout's devices.
//!
//! Data in: the layout graph, the design, the deck's `lvs lde` rows. Data
//! out: the graph with `sa`, `sb`, `sca`, `scb` and `scc` on every
//! transistor of a row's model that the geometry lets be measured, each
//! only where its name is interned (so a reference can state it).
//!
//! # Definitions
//!
//! BSIM4 (BSIM4.6 manual, "Layout-Dependent Parasitics Model": the stress
//! effect and the well proximity effect) defines `SA` and `SB` as the
//! distances from the gate's two edges across the channel to the active
//! area's (OD) edges on either side, and, for an OD whose edge is not
//! straight, the effective `SA` by `1/(SA + L/2) = Σ wᵢ/W · 1/(saᵢ +
//! L/2)` over the strips `wᵢ` of the gate's width that see the distance
//! `saᵢ`. The stress model reads them only through `1/(SA + L/2) + 1/(SB +
//! L/2)`, so they are a pair: this module writes the smaller as `sa` and
//! the larger as `sb`, and the comparison sorts a card's the same way.
//!
//! `SCA`, `SCB` and `SCC` are integrals of the scattered well dopant over
//! the gate. Silvaco's public application note "Well Proximity and STI
//! Stress Effect Parameters Extraction in SmartDRC/LVS" (2022) writes them
//! in closed form from the four distances `SC1`..`SC4` between the gate's
//! edges and the well's edges, with `W`, `L` and the model's `SCREF`
//! ([`wpe`]), each distance the median over the gate edge of the distance
//! to the first well edge outward, and one past the maximum read as the
//! maximum. `SC1` and `SC3` face the gate's edges of length `W`, `SC2` and
//! `SC4` its edges of length `L`.
//!
//! # Limits
//!
//! The gate (the device's marker) must be one axis-aligned rectangle inside
//! one stretch of OD; otherwise nothing is measured, and a card stating the
//! parameter is `lvs.undeclared_param`. OD and well holes are read as solid.
//! `SD`, the spacing of fingers inside one instance, has no meaning for a
//! device of one channel and is not written. The candidate shapes come from
//! a scan of each layer sorted by left edge.

use crate::lvs::graph::{narrow, Graph};
use crate::Design;
use gpurify_geom::{Bbox, GeometryStore, Grid, LayerId, PolyId};
use gpurify_ingest::deck::{DeviceKind, LayerTable, LvsLde};
use gpurify_ingest::{StrId, StrTable};

/// `SCA`, `SCB` and `SCC` from the four distances `sc = [SC1, SC2, SC3,
/// SC4]`, the gate's `w` and `l` and the model's `scref`, all in one unit,
/// as Silvaco's application note writes them (its worked example: `SC1` to
/// `SC4` of 8.28, 1.351, 2.72 and 2 µm, `W` 3 µm, `L` 1 µm and `SCREF`
/// 0.95 µm give `SCA` 0.345, `SCB` 32.26n and `SCC` 10.41f, all three
/// dimensionless):
///
/// - `SCA = SCREF²/(W L) · (W (1/SC1 − 1/(SC1+L)) + L (1/SC2 − 1/(SC2+W)) +
///   W (1/SC3 − 1/(SC3+L)) + L (1/SC4 − 1/(SC4+W)))`;
/// - `SCB` the sum over the four edges of `1/(E·SCREF) · (SCREF/10 · s ·
///   e^(−10 s/SCREF) + SCREF²/100 · e^(−10 s/SCREF) − SCREF/10 · (s+E) ·
///   e^(−10 (s+E)/SCREF) − SCREF²/100 · e^(−10 (s+E)/SCREF))`, `E` being
///   `W` for `SC2` and `SC4` and `L` for `SC1` and `SC3`;
/// - `SCC` the same with 20 and 400 for 10 and 100.
#[must_use]
pub fn wpe(sc: [f64; 4], w: f64, l: f64, scref: f64) -> [f64; 3] {
    let [sc1, sc2, sc3, sc4] = sc;
    let inverse = |s: f64, depth: f64| 1.0 / s - 1.0 / (s + depth);
    let sca = scref * scref / (w * l)
        * (w * inverse(sc1, l) + l * inverse(sc2, w) + w * inverse(sc3, l) + l * inverse(sc4, w));
    let tail = |k: f64, s: f64, depth: f64| {
        let e = |x: f64| (-k * x / scref).exp();
        let term = |x: f64| scref / k * x * e(x) + scref * scref / (k * k) * e(x);
        (term(s) - term(s + depth)) / (depth * scref)
    };
    let sum = |k: f64| tail(k, sc2, w) + tail(k, sc4, w) + tail(k, sc1, l) + tail(k, sc3, l);
    [sca, sum(10.0), sum(20.0)]
}

/// One layer's polygons sorted by left edge, and the widest's width, so a
/// window's candidates are a slice.
struct Sorted {
    rows: Vec<(i64, PolyId)>,
    widest: i64,
}

impl Sorted {
    fn of(store: &GeometryStore, layer: LayerId) -> Self {
        let range = store.polys_on_layer(layer);
        let mut rows: Vec<(i64, PolyId)> = range
            .map(|poly| (store.poly_bbox(PolyId(poly)).xlo.raw(), PolyId(poly)))
            .collect();
        rows.sort_unstable();
        let widest = rows
            .iter()
            .map(|&(_, poly)| {
                let b = store.poly_bbox(poly);
                b.xhi.raw() - b.xlo.raw()
            })
            .max()
            .unwrap_or(0);
        Self { rows, widest }
    }

    /// The polygons whose bounding box meets `window`.
    ///
    /// ponytail: a scan from the first left edge a polygon as wide as the
    /// widest could start at; a layer of a few very wide polygons scans
    /// more, and a bucket grid is the upgrade.
    fn meeting(&self, store: &GeometryStore, window: Bbox) -> Vec<PolyId> {
        let from = self
            .rows
            .partition_point(|&(x, _)| x < window.xlo.raw() - self.widest);
        self.rows[from..]
            .iter()
            .take_while(|&&(x, _)| x <= window.xhi.raw())
            .map(|&(_, poly)| poly)
            .filter(|&poly| {
                let b = store.poly_bbox(poly);
                b.xhi >= window.xlo && b.ylo <= window.yhi && b.yhi >= window.ylo
            })
            .collect()
    }
}

/// The intervals of `along` (x when `horizontal`, else y) where the line at
/// `at` on the other axis lies inside some polygon of `polys`, merged and
/// ascending. `at` is never a vertex coordinate (a strip's middle), so no
/// edge lies along the line.
fn line_intervals(
    store: &GeometryStore,
    polys: &[PolyId],
    horizontal: bool,
    at: f64,
) -> Vec<(f64, f64)> {
    let mut spans = Vec::new();
    let mut crossings = Vec::new();
    for &poly in polys {
        let (xs, ys) = store.poly_verts(poly);
        let (along, across) = if horizontal { (xs, ys) } else { (ys, xs) };
        crossings.clear();
        for i in 0..along.len() {
            let j = (i + 1) % along.len();
            #[expect(clippy::cast_precision_loss, reason = "layout coordinates")]
            let (a0, c0, a1, c1) = (
                along[i].raw() as f64,
                across[i].raw() as f64,
                along[j].raw() as f64,
                across[j].raw() as f64,
            );
            if (c0 < at) != (c1 < at) {
                crossings.push(a0 + (at - c0) * (a1 - a0) / (c1 - c0));
            }
        }
        crossings.sort_unstable_by(f64::total_cmp);
        spans.extend(crossings.chunks_exact(2).map(|pair| (pair[0], pair[1])));
    }
    spans.sort_unstable_by(|a, b| a.0.total_cmp(&b.0));
    let mut merged: Vec<(f64, f64)> = Vec::with_capacity(spans.len());
    for (lo, hi) in spans {
        match merged.last_mut() {
            Some(last) if lo <= last.1 => last.1 = last.1.max(hi),
            _ => merged.push((lo, hi)),
        }
    }
    merged
}

/// The strips the span `lo..hi` of one axis falls into at every vertex
/// coordinate `polys` have inside it: `(middle, width)` each.
fn strips(
    store: &GeometryStore,
    polys: &[PolyId],
    horizontal: bool,
    (lo, hi): (i64, i64),
) -> Vec<(f64, f64)> {
    let mut cuts = vec![lo, hi];
    for &poly in polys {
        let (xs, ys) = store.poly_verts(poly);
        let coordinates = if horizontal { ys } else { xs };
        cuts.extend(
            coordinates
                .iter()
                .map(|c| c.raw())
                .filter(|&c| c > lo && c < hi),
        );
    }
    cuts.sort_unstable();
    cuts.dedup();
    #[expect(clippy::cast_precision_loss, reason = "layout coordinates")]
    cuts.windows(2)
        .map(|w| ((w[0] + w[1]) as f64 / 2.0, (w[1] - w[0]) as f64))
        .collect()
}

/// A gate's geometry: its box, whether the channel runs along x, and its
/// length and width.
struct Gate {
    bbox: Bbox,
    along_x: bool,
}

impl Gate {
    /// `(lo, hi)` of the box along the channel, then across it.
    fn spans(&self) -> ((i64, i64), (i64, i64)) {
        let x = (self.bbox.xlo.raw(), self.bbox.xhi.raw());
        let y = (self.bbox.ylo.raw(), self.bbox.yhi.raw());
        if self.along_x {
            (x, y)
        } else {
            (y, x)
        }
    }
}

/// `marker` as a rectangle, or `None` when it is not one axis-aligned
/// rectangle.
fn rectangle(store: &GeometryStore, marker: PolyId) -> Option<Bbox> {
    let (xs, ys) = store.poly_verts(marker);
    let b = store.poly_bbox(marker);
    let on_box = xs.iter().all(|&x| x == b.xlo || x == b.xhi)
        && ys.iter().all(|&y| y == b.ylo || y == b.yhi);
    (xs.len() == 4 && on_box && b.xlo < b.xhi && b.ylo < b.yhi).then_some(b)
}

/// The channel's direction: the axis along which the OD runs on past the
/// gate on both sides, and not the other. `None` when that is not one axis.
fn channel(store: &GeometryStore, od: &[PolyId], bbox: Bbox) -> Option<bool> {
    #[expect(clippy::cast_precision_loss, reason = "layout coordinates")]
    let (cx, cy) = (
        (bbox.xlo.raw() + bbox.xhi.raw()) as f64 / 2.0,
        (bbox.ylo.raw() + bbox.yhi.raw()) as f64 / 2.0,
    );
    #[expect(clippy::cast_precision_loss, reason = "layout coordinates")]
    let beyond = |horizontal: bool| {
        let (centre, along, lo, hi) = if horizontal {
            (cy, cx, bbox.xlo.raw() as f64, bbox.xhi.raw() as f64)
        } else {
            (cx, cy, bbox.ylo.raw() as f64, bbox.yhi.raw() as f64)
        };
        line_intervals(store, od, horizontal, centre)
            .iter()
            .any(|&(a, b)| a <= along && along <= b && a < lo && b > hi)
    };
    match (beyond(true), beyond(false)) {
        (true, false) => Some(true),
        (false, true) => Some(false),
        _ => None,
    }
}

/// `SA` and `SB`, smaller first, in database units: BSIM4's effective
/// distances over the gate's width from its two edges across the channel
/// to the OD's edges, each capped at `max`. `None` where a strip of the
/// gate is not inside the OD.
fn stress(store: &GeometryStore, od: &[PolyId], gate: &Gate, max: f64) -> Option<(f64, f64)> {
    let ((lo, hi), across) = gate.spans();
    #[expect(clippy::cast_precision_loss, reason = "layout coordinates")]
    let (lo, hi, length, width) = (
        lo as f64,
        hi as f64,
        (hi - lo) as f64,
        (across.1 - across.0) as f64,
    );
    let (mut inverse_low, mut inverse_high) = (0.0, 0.0);
    for (middle, strip) in strips(store, od, gate.along_x, across) {
        let (a, b) = line_intervals(store, od, gate.along_x, middle)
            .into_iter()
            .find(|&(a, b)| a <= lo && hi <= b)?;
        let (low, high) = ((lo - a).min(max), (b - hi).min(max));
        inverse_low += strip / width / (low + length / 2.0);
        inverse_high += strip / width / (high + length / 2.0);
    }
    let (low, high) = (
        1.0 / inverse_low - length / 2.0,
        1.0 / inverse_high - length / 2.0,
    );
    Some((low.min(high), low.max(high)))
}

/// The distance from the gate edge at `edge` outward (`toward` +1 or -1
/// along `horizontal`'s axis) to the first well edge, as the median over
/// the edge's strips weighted by their width, each capped at `max`.
fn well_distance(
    store: &GeometryStore,
    well: &[PolyId],
    (horizontal, edge, toward): (bool, f64, f64),
    span: (i64, i64),
    max: f64,
) -> f64 {
    let mut seen: Vec<(f64, f64)> = strips(store, well, horizontal, span)
        .into_iter()
        .map(|(middle, strip)| {
            let boundaries = line_intervals(store, well, horizontal, middle);
            let first = boundaries
                .iter()
                .flat_map(|&(a, b)| [a, b])
                .map(|end| (end - edge) * toward)
                .filter(|&d| d > 0.0)
                .fold(f64::INFINITY, f64::min);
            (first.min(max), strip)
        })
        .collect();
    seen.sort_unstable_by(|a, b| a.0.total_cmp(&b.0));
    let total: f64 = seen.iter().map(|s| s.1).sum();
    let mut covered = 0.0;
    for (distance, strip) in &seen {
        covered += strip;
        if covered * 2.0 >= total {
            return *distance;
        }
    }
    max
}

/// Adds `sa`, `sb` and, with a well, `sca`, `scb` and `scc` to every
/// transistor of `graph` whose model an `lvs lde` row names, each where its
/// name is interned, in metres or as BSIM4's dimensionless integrals, as
/// the [module docs](self) define them. `graph` must be
/// [`from_layout`](crate::lvs::graph::from_layout) of `design`, its device
/// rows the design's. A device whose gate is no rectangle inside one
/// stretch of OD, or whose layer was not computed, gets nothing.
pub fn add_lde_params(
    graph: &mut Graph,
    design: Design<'_>,
    (rows, layers): (&[LvsLde], &LayerTable),
    strings: &StrTable,
    grid: Grid,
) {
    let names = ["sa", "sb", "sca", "scb", "scc"].map(|name| strings.get(name));
    if rows.is_empty() || names.iter().all(Option::is_none) {
        return;
    }
    let store = design.store;
    let layer = |name: StrId| {
        layers
            .id(strings, strings.resolve(name))
            .filter(|&layer| !store.is_uncomputed(layer))
    };
    #[expect(clippy::cast_precision_loss, reason = "grid resolutions are small")]
    let metre = 1e-6 / grid.dbu_per_um() as f64;
    let mut added: Vec<Vec<(StrId, f64)>> = vec![Vec::new(); graph.device_count()];
    for row in rows {
        let Some(od_layer) = layer(row.od) else {
            continue;
        };
        let od_sorted = Sorted::of(store, od_layer);
        let well = row
            .well
            .and_then(|(well, scref)| Some((layer(well)?, scref)))
            .map(|(well, scref)| (Sorted::of(store, well), scref));
        #[expect(clippy::cast_precision_loss, reason = "layout coordinates")]
        let max = row.max.raw() as f64;
        for (device, out) in added.iter_mut().enumerate() {
            if graph.device_kind[device] != DeviceKind::Mos
                || graph.device_model[device] != row.model
            {
                continue;
            }
            let marker = design.devices.marker[device];
            let Some(bbox) = rectangle(store, marker) else {
                continue;
            };
            let window = Bbox {
                xlo: bbox.xlo - row.max,
                ylo: bbox.ylo - row.max,
                xhi: bbox.xhi + row.max,
                yhi: bbox.yhi + row.max,
            };
            let od = od_sorted.meeting(store, window);
            let Some(along_x) = channel(store, &od, bbox) else {
                continue;
            };
            let gate = Gate { bbox, along_x };
            let Some((sa, sb)) = stress(store, &od, &gate, max) else {
                continue;
            };
            for (name, value) in [(names[0], sa), (names[1], sb)] {
                if let Some(name) = name {
                    out.push((name, value * metre));
                }
            }
            let Some((well_sorted, scref)) = &well else {
                continue;
            };
            let near = well_sorted.meeting(store, window);
            let ((lo, hi), (across_lo, across_hi)) = gate.spans();
            #[expect(clippy::cast_precision_loss, reason = "layout coordinates")]
            let (lo_f, hi_f, alo, ahi) = (lo as f64, hi as f64, across_lo as f64, across_hi as f64);
            // SC1, SC3: the edges of length W, across the channel's ends;
            // SC2, SC4: the edges of length L, beside it.
            let h = along_x;
            let sc = [
                well_distance(store, &near, (h, lo_f, -1.0), (across_lo, across_hi), max),
                well_distance(store, &near, (!h, alo, -1.0), (lo, hi), max),
                well_distance(store, &near, (h, hi_f, 1.0), (across_lo, across_hi), max),
                well_distance(store, &near, (!h, ahi, 1.0), (lo, hi), max),
            ];
            #[expect(clippy::cast_precision_loss, reason = "layout coordinates")]
            let (w, l, scref) = (
                (across_hi - across_lo) as f64,
                (hi - lo) as f64,
                scref.raw() as f64,
            );
            let integrals = wpe(sc.map(|d| d * metre), w * metre, l * metre, scref * metre);
            for (name, value) in names[2..].iter().zip(integrals) {
                if let Some(name) = *name {
                    out.push((name, value));
                }
            }
        }
    }
    if added.iter().all(Vec::is_empty) {
        return;
    }
    let mut param =
        Vec::with_capacity(graph.param.len() + added.iter().map(Vec::len).sum::<usize>());
    let mut start = Vec::with_capacity(graph.device_count() + 1);
    start.push(0);
    for (device, extra) in added.iter().enumerate() {
        param.extend_from_slice(graph.params_of(narrow(device)));
        param.extend_from_slice(extra);
        start.push(narrow(param.len()));
    }
    graph.param = param;
    graph.device_param_start = start;
}

/// Sorts each reference device's `sa` and `sb`, smaller first, as
/// [`add_lde_params`] writes the layout's: the stress model reads the two
/// only as a pair. A device stating one of them alone keeps it.
pub(crate) fn sort_stress_pair(graph: &mut Graph, strings: (Option<StrId>, Option<StrId>)) {
    let (Some(sa), Some(sb)) = strings else {
        return;
    };
    for device in 0..graph.device_count() {
        let (from, to) = (
            graph.device_param_start[device] as usize,
            graph.device_param_start[device + 1] as usize,
        );
        let params = &mut graph.param[from..to];
        let a = params.iter().position(|p| p.0 == sa);
        let b = params.iter().position(|p| p.0 == sb);
        if let (Some(a), Some(b)) = (a, b) {
            if params[a].1 > params[b].1 {
                let (low, high) = (params[b].1, params[a].1);
                params[a].1 = low;
                params[b].1 = high;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::wpe;

    /// Oracle: the standard's worked example, Silvaco's application note
    /// "Well Proximity and STI Stress Effect Parameters Extraction in
    /// SmartDRC/LVS": `SC1` to `SC4` of 8.28, 1.351, 2.72 and 2 µm, `W`
    /// 3 µm, `L` 1 µm and `SCREF` 0.95 µm print as `SCA=0.345`,
    /// `SCB=32.260n` and `SCC=10.410f` (its `SCBW1=32.210n` the dominant
    /// term), in metres or in micrometres alike. `SCA` agrees to the note's
    /// three figures; `SCB` and `SCC` fall off as `e^(-10 SC2/SCREF)` and
    /// `e^(-20 SC2/SCREF)`, so the note's `SC2`, printed to the nanometre,
    /// carries ±0.53 % and ±1.05 % into them, and they are held to 0.6 %
    /// and 1.1 %. Breaks if an edge pairs with the wrong side length, or a
    /// coefficient of the exponentials is off.
    #[test]
    fn the_integrals_reproduce_the_note_s_worked_example() {
        for unit in [1e-6, 1.0] {
            let [sca, scb, scc] = wpe(
                [8.28 * unit, 1.351 * unit, 2.72 * unit, 2.0 * unit],
                3.0 * unit,
                1.0 * unit,
                0.95 * unit,
            );
            let near = |got: f64, want: f64, within: f64| (got - want).abs() <= within * want;
            assert!(near(sca, 0.345, 0.0015), "SCA {sca}");
            assert!(near(scb, 32.26e-9, 0.006), "SCB {scb}");
            assert!(near(scc, 10.41e-15, 0.011), "SCC {scc}");
        }
    }
}
