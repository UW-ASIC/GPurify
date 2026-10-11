//! Area family: min area, min enclosed (hole) area, cheesing, windowed and
//! whole-die density. Density windows tile the die (a boundary layer's extent,
//! or the drawn layers'), never just the measured layer's own extent.
//!
//! Data in: one layer, self-merged into connected figures (exact union) and
//! decomposed into disjoint rectangles (canonical). Data out: one violation per
//! offending figure, hole or window.

use super::{centre, owners_of, Verdict, REFUSED};
use crate::drc::Scratch;
use crate::report::{
    LimitSense, Measurement, Outcome, Severity, SkipReason, Violation, Violations,
};
use gpurify_geom::boolean::union_into;
use gpurify_geom::rects::{covered_area, decompose_into};
use gpurify_geom::{Bbox, GeometryStore, LayerId, PolyId, ValidatedLayer};
use gpurify_geom::{Dbu, DbuArea};
use gpurify_ingest::StrId;
use std::ops::Range;

/// Merge a layer into `s.layer_out` and decompose it into `s.rects`, CSR by figure.
/// `false` is `Refused`.
fn merge_layer(store: &GeometryStore, layer: LayerId, s: &mut Scratch) -> bool {
    let Some(drawn) = s.validated.get(store, layer) else {
        return false;
    };
    if union_into(drawn, drawn, &mut s.layer_out).is_err() {
        return false;
    }
    decompose_into(&s.layer_out, &mut s.rects, &mut s.rect_start);
    true
}

/// The lowest drawn row under each figure of `s.layer_out`, which
/// [`merge_layer`] filled: an outer row whose polygon covers part of the
/// figure, never an island in its hole.
fn figure_owners(store: &GeometryStore, layer: LayerId, s: &mut Scratch) -> Vec<PolyId> {
    let drawn = s
        .validated
        .get(store, layer)
        .expect("merge_layer validated the layer");
    s.rects_a.build(store, layer, drawn);
    owners_of(&s.layer_out, &s.rects_a)
}

/// The boxes of a validated layer's outer rows (never a hole row) sorted by
/// `xlo`, built on first use. A query scans only the boxes whose `xlo` lies
/// in the region's x span.
struct Owners<'a> {
    store: &'a GeometryStore,
    layer: &'a ValidatedLayer,
    by_xlo: Vec<(Bbox, u32)>,
}

impl<'a> Owners<'a> {
    fn new(store: &'a GeometryStore, layer: &'a ValidatedLayer) -> Self {
        Self {
            store,
            layer,
            by_xlo: Vec::new(),
        }
    }

    /// The lowest outer row whose box `region` contains, else the lowest
    /// outer row, else `u32::MAX` for an empty layer.
    fn owner(&mut self, region: Bbox) -> u32 {
        if self.by_xlo.is_empty() {
            let outers = (0..self.layer.len()).map(|poly| {
                let poly = u32::try_from(poly).expect("a layer indexes polygons with a u32");
                self.layer.get(poly).provenance()
            });
            let store = self.store;
            self.by_xlo
                .extend(outers.map(|row| (store.poly_bbox(row), row.0)));
            self.by_xlo.sort_unstable_by_key(|&(b, _)| b.xlo);
        }
        let lo = self.by_xlo.partition_point(|&(b, _)| b.xlo < region.xlo);
        let hi = self.by_xlo.partition_point(|&(b, _)| b.xlo <= region.xhi);
        self.by_xlo[lo..hi.max(lo)]
            .iter()
            .filter(|&&(b, _)| region.contains(b))
            .map(|&(_, row)| row)
            .min()
            .or_else(|| self.by_xlo.iter().map(|&(_, row)| row).min())
            .unwrap_or(u32::MAX)
    }
}

/// One violation per merged figure `violates(area, has_hole)` rejects, at the
/// centre of its first decomposed rectangle (always inside the figure).
/// Returns the figure count.
fn report_figures(
    store: &GeometryStore,
    layer: LayerId,
    rule: StrId,
    limit: DbuArea,
    s: &mut Scratch,
    out: &mut Violations,
    violates: impl Fn(DbuArea, bool) -> bool,
) -> u64 {
    let owners = figure_owners(store, layer, s);
    for (figure, owner) in owners.into_iter().enumerate() {
        let rects = &s.rects[s.rect_start[figure] as usize..s.rect_start[figure + 1] as usize];
        let area = covered_area(rects);
        let index = u32::try_from(figure).expect("a merged layer's figure count fits a u32");
        let has_hole = s.layer_out.get(index).holes().next().is_some();
        if !violates(area, has_hole) {
            continue;
        }
        out.push(Violation {
            rule,
            layer,
            severity: Severity::Error,
            at: centre(rects[0]),
            measured: Measurement::Area(area),
            limit: Measurement::Area(limit),
            shapes: (owner, None),
        });
    }
    s.layer_out.len() as u64
}

/// Minimum area of each merged figure. `examined` counts figures.
pub(crate) fn min_area(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    limit: DbuArea,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    if !merge_layer(store, layer, s) {
        return REFUSED;
    }
    let examined = report_figures(store, layer, rule, limit, s, out, |area, _| {
        Measurement::Area(area).violates(Measurement::Area(limit), LimitSense::Minimum)
    });
    (Outcome::Ran, examined)
}

/// Cheesing: a figure above `limit` with no hole. `examined` counts figures.
pub(crate) fn cheesing(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    limit: DbuArea,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    if !merge_layer(store, layer, s) {
        return REFUSED;
    }
    let examined = report_figures(store, layer, rule, limit, s, out, |area, has_hole| {
        Measurement::Area(area).violates(Measurement::Area(limit), LimitSense::Maximum) && !has_hole
    });
    (Outcome::Ran, examined)
}

/// Minimum hole area of the merged figures, reported at the hole's box centre.
/// `examined` counts holes.
pub(crate) fn min_enclosed_area(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    limit: DbuArea,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    if !merge_layer(store, layer, s) {
        return REFUSED;
    }
    let mut examined = 0u64;
    let owners = figure_owners(store, layer, s);
    for (index, owner) in (0..).zip(owners) {
        for hole in s.layer_out.get(index).holes() {
            examined += 1;
            // A hole winds clockwise; a rectilinear ring's doubled area is even.
            let area = DbuArea::new(-hole.area2().raw() / 2);
            if !Measurement::Area(area).violates(Measurement::Area(limit), LimitSense::Minimum) {
                continue;
            }
            let (xs, ys) = hole.coords();
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: centre(Bbox::of_points(xs, ys)),
                measured: Measurement::Area(area),
                limit: Measurement::Area(limit),
                shapes: (owner, None),
            });
        }
    }
    (Outcome::Ran, examined)
}

/// The die: the `boundary` layer's extent, or that of the drawn layers
/// `0..drawn`. A derived layer is not layout: grown past it, it would widen
/// the die.
fn die_of(store: &GeometryStore, boundary: Option<LayerId>, drawn: usize) -> Bbox {
    let extent = |layer: LayerId| {
        store
            .layer_bboxes(layer)
            .iter()
            .fold(Bbox::EMPTY, |acc, &b| acc.union(b))
    };
    match boundary {
        Some(layer) => extent(layer),
        None => (0..drawn).fold(Bbox::EMPTY, |die, layer| {
            die.union(extent(LayerId(
                u16::try_from(layer).expect("a LayerId is a u16"),
            )))
        }),
    }
}

/// The merged layer's rectangles clipped to the die, into `s.rects`.
/// `false` is `Refused`.
fn merge_within(store: &GeometryStore, layer: LayerId, die: Bbox, s: &mut Scratch) -> bool {
    if !merge_layer(store, layer, s) {
        return false;
    }
    s.rects.retain_mut(|r| match r.intersection(die) {
        Some(c) if c.xlo < c.xhi && c.ylo < c.yhi => {
            *r = c;
            true
        }
        _ => false,
    });
    true
}

/// The layer's first row, or `u32::MAX` (no shape) for an empty layer.
fn first_row_or_none(store: &GeometryStore, layer: LayerId) -> u32 {
    let rows = store.polys_on_layer(layer);
    if rows.is_empty() {
        u32::MAX
    } else {
        rows.start
    }
}

/// Density: a `side`-square window swept over the die in `step`s, each window's
/// covered area inside the die over the whole window, so a window hanging past
/// the die counts the outside as empty (the `KLayout` default, `padding_zero`).
/// One violation per offending window, at its centre. An empty layer on a
/// non-empty die has density zero. `examined` counts windows; an empty die is
/// `Skipped(EmptyLayer)`.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn density(
    store: &GeometryStore,
    rule: StrId,
    (layer, boundary, drawn): (LayerId, Option<LayerId>, usize),
    (window, step): (Dbu, Dbu),
    limit: f64,
    sense: LimitSense,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let die = die_of(store, boundary, drawn);
    if die.is_empty() {
        return (Outcome::Skipped(SkipReason::EmptyLayer), 0);
    }
    if !merge_within(store, layer, die, s) {
        return REFUSED;
    }

    let (side, stride) = (window.raw(), step.raw());
    let (x0, y0) = (die.xlo.raw(), die.ylo.raw());
    let cols = positions(die.xhi.raw() - x0, side, stride);
    let ways = positions(die.yhi.raw() - y0, side, stride);
    // A sweep leaving the coordinate domain is refused: clamping the window would
    // shrink the numerator but not the denominator.
    let (xmax, ymax) = (
        x0 + (cols - 1) * stride + side,
        y0 + (ways - 1) * stride + side,
    );
    if Dbu::new(xmax).is_none() || Dbu::new(ymax).is_none() {
        return REFUSED;
    }
    let Some(sweep) = cols.checked_mul(ways).and_then(|n| u64::try_from(n).ok()) else {
        return REFUSED;
    };

    let denominator = to_f64(i128::from(side) * i128::from(side));
    let validated = s
        .validated
        .get(store, layer)
        .expect("merge_within validated the layer");
    let mut owners = Owners::new(store, validated);
    let grid = WindowGrid {
        x0,
        y0,
        side,
        stride,
        cols,
        ways,
    };
    window_areas(&s.rects, grid, |window, covered| {
        let fraction = to_f64(covered.raw()) / denominator;
        if !Measurement::Ratio(fraction).violates(Measurement::Ratio(limit), sense) {
            return;
        }
        let owner = owners.owner(window);
        out.push(Violation {
            rule,
            layer,
            severity: Severity::Error,
            at: centre(window),
            measured: Measurement::Ratio(fraction),
            limit: Measurement::Ratio(limit),
            shapes: (PolyId(owner), None),
        });
    });
    (Outcome::Ran, sweep)
}

/// Whole-die density (gf180 M1.4 "30 % over the entire die", IHP M1.j/k): the
/// merged layer's area inside the die over the die's area, one violation at the
/// die's centre. `examined` is one; an empty die is `Skipped(EmptyLayer)`.
pub(crate) fn global_density(
    store: &GeometryStore,
    rule: StrId,
    (layer, boundary, drawn): (LayerId, Option<LayerId>, usize),
    limit: f64,
    sense: LimitSense,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let die = die_of(store, boundary, drawn);
    if die.is_empty() {
        return (Outcome::Skipped(SkipReason::EmptyLayer), 0);
    }
    if !merge_within(store, layer, die, s) {
        return REFUSED;
    }
    let fraction = to_f64(covered_area(&s.rects).raw()) / to_f64(die.area().raw());
    if Measurement::Ratio(fraction).violates(Measurement::Ratio(limit), sense) {
        out.push(Violation {
            rule,
            layer,
            severity: Severity::Error,
            at: centre(die),
            measured: Measurement::Ratio(fraction),
            limit: Measurement::Ratio(limit),
            shapes: (PolyId(first_row_or_none(store, layer)), None),
        });
    }
    (Outcome::Ran, 1)
}

/// A density sweep: `cols x ways` windows of `side`, origins `stride` apart
/// from `(x0, y0)`.
#[derive(Debug, Clone, Copy)]
struct WindowGrid {
    x0: i64,
    y0: i64,
    side: i64,
    stride: i64,
    cols: i64,
    ways: i64,
}

impl WindowGrid {
    fn window(self, ix: i64, iy: i64) -> Bbox {
        let (x, y) = (self.x0 + ix * self.stride, self.y0 + iy * self.stride);
        Bbox {
            xlo: Dbu::new_unchecked(x),
            ylo: Dbu::new_unchecked(y),
            xhi: Dbu::new_unchecked(x + self.side),
            yhi: Dbu::new_unchecked(y + self.side),
        }
    }

    /// The window indices along one axis that `lo..hi` overlaps with positive length.
    fn hit(self, lo: Dbu, hi: Dbu, origin: i64, n: i64) -> Range<i64> {
        let first = ((lo.raw() - origin - self.side).div_euclid(self.stride) + 1).clamp(0, n);
        let last = (hi.raw() - origin - 1).div_euclid(self.stride).min(n - 1);
        first..(last + 1).max(first)
    }
}

/// The exact covered area of every window of `g`, in row order (`iy`, then
/// `ix`), for disjoint `rects`. Each rectangle is clipped only against the
/// windows it overlaps, so the cost is the overlap count, not windows x rects.
fn window_areas(rects: &[Bbox], g: WindowGrid, mut each: impl FnMut(Bbox, DbuArea)) {
    let rows_of = |r: Bbox| g.hit(r.ylo, r.yhi, g.y0, g.ways);
    // Integer sums are order-free, so the order rectangles join a row is not output.
    let mut pending = rects.to_vec();
    pending.sort_unstable_by_key(|&r| rows_of(r).start);
    let mut pending = pending.into_iter().peekable();
    let mut active: Vec<Bbox> = Vec::new();
    let mut row = vec![0i128; usize::try_from(g.cols).expect("a positive window count")];
    for iy in 0..g.ways {
        active.extend(std::iter::from_fn(|| {
            pending.next_if(|&r| rows_of(r).start <= iy)
        }));
        active.retain(|&r| rows_of(r).contains(&iy));
        row.fill(0);
        let band = g.window(0, iy);
        for r in &active {
            let h = i128::from((r.yhi.min(band.yhi) - r.ylo.max(band.ylo)).raw().max(0));
            let cols = g.hit(r.xlo, r.xhi, g.x0, g.cols);
            let slots = usize::try_from(cols.start).expect("clamped at zero")
                ..usize::try_from(cols.end).expect("clamped at zero");
            for (ix, sum) in cols.zip(&mut row[slots]) {
                let w = g.window(ix, iy);
                let w = i128::from((r.xhi.min(w.xhi) - r.xlo.max(w.xlo)).raw().max(0));
                // Exact: a window's sum is at most side², far inside i128.
                *sum += w * h;
            }
        }
        for (ix, &covered) in (0..).zip(&row) {
            each(g.window(ix, iy), DbuArea::new(covered));
        }
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "a density fraction is an f64 by the deck's limit"
)]
fn to_f64(area: i128) -> f64 {
    area as f64
}

/// Window origins a sweep of `span` takes, rounded **up** so the far edge is
/// covered; always at least one.
fn positions(span: i64, window: i64, step: i64) -> i64 {
    ((span - window).max(0) + step - 1) / step + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpurify_geom::rects::clipped_area;

    fn b(xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> Bbox {
        let d = Dbu::new_unchecked;
        Bbox {
            xlo: d(xlo),
            ylo: d(ylo),
            xhi: d(xhi),
            yhi: d(yhi),
        }
    }

    /// Differential: every window's sum equals clipping every rectangle to it.
    ///
    /// Oracle: differential against clipping every rectangle to every window
    /// (`clipped_area`), over 2000 random grids and disjoint rectangle sets.
    #[test]
    fn window_areas_match_clipping_every_rect() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut rand = move |n: i64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            i64::try_from(seed % n.unsigned_abs()).unwrap()
        };
        for _ in 0..2000 {
            // Disjoint: one rectangle per 40-high band, random x span.
            let rects: Vec<Bbox> = (0..rand(12))
                .map(|k| {
                    let (x, y) = (rand(200) - 50, k * 40 - 30 + rand(10));
                    b(x, y, x + 1 + rand(150), y + 1 + rand(29))
                })
                .collect();
            let g = WindowGrid {
                x0: rand(40) - 60,
                y0: rand(40) - 60,
                side: 1 + rand(120),
                stride: 1 + rand(90),
                cols: 1 + rand(8),
                ways: 1 + rand(8),
            };
            let mut seen = Vec::new();
            window_areas(&rects, g, |w, a| seen.push((w, a)));
            let mut want = Vec::new();
            for iy in 0..g.ways {
                for ix in 0..g.cols {
                    let w = g.window(ix, iy);
                    want.push((w, clipped_area(&rects, w)));
                }
            }
            assert_eq!(seen, want, "{rects:?} {g:?}");
        }
    }
}
