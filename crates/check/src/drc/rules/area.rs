//! Area family: min area, min enclosed (hole) area, cheesing, windowed density.
//!
//! Data in: one layer, self-merged into connected figures (exact union) and
//! decomposed into disjoint rectangles (canonical). Data out: one violation per
//! offending figure, hole or window.

use super::{centre, Verdict, REFUSED};
use crate::drc::Scratch;
use crate::report::{
    LimitSense, Measurement, Outcome, Severity, SkipReason, Violation, Violations,
};
use gpurify_geom::boolean::{union_into, BooleanError};
use gpurify_geom::rects::{clipped_area, covered_area, decompose_into};
use gpurify_geom::view::validate_layer_into;
use gpurify_geom::{Bbox, GeometryStore, LayerId, PolyId};
use gpurify_geom::{Dbu, DbuArea};
use gpurify_ingest::StrId;

/// Merge a layer into `s.layer_out` and decompose it into `s.rects`, CSR by figure.
fn merge_layer(store: &GeometryStore, layer: LayerId, s: &mut Scratch) -> Result<(), BooleanError> {
    validate_layer_into(store, layer, &mut s.layer_a)?;
    union_into(&s.layer_a, &s.layer_a, &mut s.layer_out)?;
    decompose_into(&s.layer_out, &mut s.rects, &mut s.rect_start);
    Ok(())
}

/// The lowest store row on `layer` whose box `region` contains, or `u32::MAX`.
fn lowest_row_within(store: &GeometryStore, layer: LayerId, region: Bbox) -> u32 {
    let first_row = store.polys_on_layer(layer).start;
    (first_row..)
        .zip(store.layer_bboxes(layer))
        .filter(|&(_, &input)| region.contains(input))
        .map(|(row, _)| row)
        .min()
        .unwrap_or(u32::MAX)
}

/// One violation per merged figure `violates(area, has_hole)` rejects, at the
/// centre of its first decomposed rectangle (always inside the figure).
/// Returns the figure count.
fn report_figures(
    store: &GeometryStore,
    layer: LayerId,
    rule: StrId,
    limit: DbuArea,
    s: &Scratch,
    out: &mut Violations,
    violates: impl Fn(DbuArea, bool) -> bool,
) -> u64 {
    let figures = s.layer_out.len();
    for figure in 0..figures {
        let rects = &s.rects[s.rect_start[figure] as usize..s.rect_start[figure + 1] as usize];
        let area = covered_area(rects);
        let index = u32::try_from(figure).expect("a merged layer's figure count fits a u32");
        let has_hole = s.layer_out.get(index).holes().next().is_some();
        if !violates(area, has_hole) {
            continue;
        }
        let first = rects[0];
        let owner = lowest_row_within(store, layer, s.layer_out.bboxes()[figure]);
        out.push(Violation {
            rule,
            layer,
            severity: Severity::Error,
            at: centre(Bbox {
                xlo: first.xlo,
                ylo: first.ylo,
                xhi: first.xhi,
                yhi: first.yhi,
            }),
            measured: Measurement::Area(area),
            limit: Measurement::Area(limit),
            shapes: (PolyId(owner), None),
        });
    }
    figures as u64
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
    if merge_layer(store, layer, s).is_err() {
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
    if merge_layer(store, layer, s).is_err() {
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
    if merge_layer(store, layer, s).is_err() {
        return REFUSED;
    }
    let mut examined = 0u64;
    for figure in 0..s.layer_out.len() {
        let index = u32::try_from(figure).expect("a merged layer's figure count fits a u32");
        for hole in s.layer_out.get(index).holes() {
            examined += 1;
            // A hole winds clockwise; a rectilinear ring's doubled area is even.
            let area = DbuArea::new(-hole.area2().raw() / 2);
            if !Measurement::Area(area).violates(Measurement::Area(limit), LimitSense::Minimum) {
                continue;
            }
            let (xs, ys) = hole.coords();
            let owner = lowest_row_within(store, layer, s.layer_out.bboxes()[figure]);
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: centre(Bbox::of_points(xs, ys)),
                measured: Measurement::Area(area),
                limit: Measurement::Area(limit),
                shapes: (PolyId(owner), None),
            });
        }
    }
    (Outcome::Ran, examined)
}

/// Density: a `side`-square window swept over the merged layer's extent in
/// `step`s; one violation per offending window, at its centre. `examined`
/// counts windows. An empty layer is `Skipped(EmptyLayer)`: its density is
/// undefined, not zero.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn density(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    window: Dbu,
    step: Dbu,
    limit: f64,
    sense: LimitSense,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    const EMPTY: Verdict = (Outcome::Skipped(SkipReason::EmptyLayer), 0);
    if store.polys_on_layer(layer).is_empty() {
        return EMPTY;
    }
    if merge_layer(store, layer, s).is_err() {
        return REFUSED;
    }
    let extent = s
        .layer_out
        .bboxes()
        .iter()
        .fold(Bbox::EMPTY, |acc, &b| acc.union(b));
    if extent.is_empty() {
        return EMPTY;
    }

    let (side, stride) = (window.raw(), step.raw());
    let (x0, y0) = (extent.xlo.raw(), extent.ylo.raw());
    let cols = positions(extent.xhi.raw() - x0, side, stride);
    let ways = positions(extent.yhi.raw() - y0, side, stride);
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
    for iy in 0..ways {
        for ix in 0..cols {
            let (wx, wy) = (x0 + ix * stride, y0 + iy * stride);
            let window = Bbox {
                xlo: Dbu::new_unchecked(wx),
                ylo: Dbu::new_unchecked(wy),
                xhi: Dbu::new_unchecked(wx + side),
                yhi: Dbu::new_unchecked(wy + side),
            };
            // The rectangles are disjoint (merged first), so one clip is the sum.
            let fraction = to_f64(clipped_area(&s.rects, window).raw()) / denominator;
            if !Measurement::Ratio(fraction).violates(Measurement::Ratio(limit), sense) {
                continue;
            }
            // A window enclosing no polygon is attributed to the layer's first row.
            let owner = match lowest_row_within(store, layer, window) {
                u32::MAX => store.polys_on_layer(layer).start,
                row => row,
            };
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: centre(window),
                measured: Measurement::Ratio(fraction),
                limit: Measurement::Ratio(limit),
                shapes: (PolyId(owner), None),
            });
        }
    }
    (Outcome::Ran, sweep)
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
