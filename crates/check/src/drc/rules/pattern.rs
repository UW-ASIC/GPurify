//! Pattern family: a deck-supplied window of shapes found wherever the layout
//! matches it exactly, in any of the eight orientations.
//!
//! Data in: one validated rectilinear layer and a [`Pattern`]. Data out: one
//! violation per distinct window placement that matches. Exact on the grid.

use super::width::rects_layer;
use super::{centre, Verdict, REFUSED};
use crate::drc::ruleset::Pattern;
use crate::drc::Scratch;
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use gpurify_geom::boolean::{intersection_into, subtraction_into, union_into, BooleanError};
use gpurify_geom::rects::{covered_area, decompose_into};
use gpurify_geom::view::ValidatedLayer;
use gpurify_geom::{Bbox, Dbu, DbuArea, GeometryStore, LayerId, PolyId};
use gpurify_ingest::StrId;

/// `(x, y)` under orientation `o` (0 to 7): mirrored in the y axis when `o
/// >= 4`, then turned `o % 4` quarter turns counter-clockwise.
fn orient(o: u8, (mut x, mut y): (i64, i64)) -> (i64, i64) {
    if o >= 4 {
        x = -x;
    }
    for _ in 0..o % 4 {
        (x, y) = (-y, x);
    }
    (x, y)
}

/// `b` under orientation `o`, then moved by `(dx, dy)`.
fn placed(o: u8, b: Bbox, (dx, dy): (i64, i64)) -> Bbox {
    let p = orient(o, (b.xlo.raw(), b.ylo.raw()));
    let q = orient(o, (b.xhi.raw(), b.yhi.raw()));
    let at = |v: i64| Dbu::new_unchecked(v);
    Bbox {
        xlo: at(p.0.min(q.0) + dx),
        ylo: at(p.1.min(q.1) + dy),
        xhi: at(p.0.max(q.0) + dx),
        yhi: at(p.1.max(q.1) + dy),
    }
}

/// The merged region of `rects`.
fn region(rects: &[Bbox]) -> Result<ValidatedLayer, BooleanError> {
    let mut out = ValidatedLayer::default();
    union_into(&rects_layer(rects)?, &ValidatedLayer::default(), &mut out)?;
    Ok(out)
}

/// The area of a merged region.
fn area_of(layer: &ValidatedLayer) -> DbuArea {
    let (mut rects, mut start) = (Vec::new(), Vec::new());
    decompose_into(layer, &mut rects, &mut start);
    covered_area(&rects)
}

/// The pattern's anchor: the least `(x, y)` corner of its merged shapes
/// strictly inside its window and in no don't-care box, the boxes' edges
/// included. A match puts a corner of the layout there, so only the
/// layout's corners need trying. `None` when the shapes have no such
/// corner, or do not merge.
pub(crate) fn anchor_of(pattern: &Pattern) -> Option<(i64, i64)> {
    let shapes = region(&pattern.shapes).ok()?;
    let (w, h) = (pattern.window.0.raw(), pattern.window.1.raw());
    let free = |(x, y): (i64, i64)| {
        x > 0
            && y > 0
            && x < w
            && y < h
            && !pattern.ignore.iter().any(|b| {
                b.xlo.raw() <= x && x <= b.xhi.raw() && b.ylo.raw() <= y && y <= b.yhi.raw()
            })
    };
    (0..u32::try_from(shapes.len()).ok()?)
        .flat_map(|idx| shapes.get(idx).rings())
        .flat_map(|ring| {
            let (xs, ys) = ring.coords();
            xs.iter()
                .zip(ys)
                .map(|(x, y)| (x.raw(), y.raw()))
                .collect::<Vec<_>>()
        })
        .filter(|&p| free(p))
        .min()
}

/// Every placement of `pattern` on `layer`: each of the eight orientations
/// with the pattern's anchor on a corner of the merged layer, where the layer
/// clipped to the placed window equals the placed shapes outside the placed
/// don't-care boxes. One violation per distinct window, at its centre,
/// measuring the shapes' area, naming no shape. `examined` counts the
/// placements tried.
// ponytail: every corner in every orientation, each verified by booleans
// over the whole layer; index the layer's rectangles by window if a large
// layout makes this slow.
pub(crate) fn pattern_match(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    pattern: &Pattern,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(drawn) = s.validated.get(store, layer) else {
        return REFUSED;
    };
    let mut figures = ValidatedLayer::default();
    if union_into(drawn, &ValidatedLayer::default(), &mut figures).is_err() {
        return REFUSED;
    }
    let Some(anchor) = anchor_of(pattern) else {
        return REFUSED;
    };
    let corners: Vec<(i64, i64)> = (0..u32::try_from(figures.len()).unwrap_or(u32::MAX))
        .flat_map(|idx| figures.get(idx).rings())
        .flat_map(|ring| {
            let (xs, ys) = ring.coords();
            xs.iter()
                .zip(ys)
                .map(|(x, y)| (x.raw(), y.raw()))
                .collect::<Vec<_>>()
        })
        .collect();
    let window = Bbox {
        xlo: Dbu::new_unchecked(0),
        ylo: Dbu::new_unchecked(0),
        xhi: pattern.window.0,
        yhi: pattern.window.1,
    };
    let shape_area = match region(&pattern.shapes) {
        Ok(shapes) => area_of(&shapes),
        Err(_) => return REFUSED,
    };
    let mut found: Vec<Bbox> = Vec::new();
    let mut examined = 0u64;
    for o in 0..8u8 {
        let a = orient(o, anchor);
        for &v in &corners {
            examined += 1;
            let shift = (v.0 - a.0, v.1 - a.1);
            let placed_window = placed(o, window, shift);
            if found.contains(&placed_window) {
                continue;
            }
            let place = |rects: &[Bbox]| -> Vec<Bbox> {
                rects.iter().map(|&b| placed(o, b, shift)).collect()
            };
            match matches(
                &figures,
                placed_window,
                &place(&pattern.shapes),
                &place(&pattern.ignore),
            ) {
                Ok(true) => found.push(placed_window),
                Ok(false) => {}
                Err(_) => return REFUSED,
            }
        }
    }
    found.sort_unstable_by_key(|b| (b.xlo, b.ylo, b.xhi, b.yhi));
    for b in found {
        out.push(Violation {
            rule,
            layer,
            severity: Severity::Error,
            at: centre(b),
            measured: Measurement::Area(shape_area),
            limit: Measurement::Area(DbuArea::new(0)),
            shapes: (PolyId(u32::MAX), None),
        });
    }
    (Outcome::Ran, examined)
}

/// Whether `figures` clipped to `window` equals `shapes`, both outside the
/// don't-care boxes `ignore`: their symmetric difference there has no area.
fn matches(
    figures: &ValidatedLayer,
    window: Bbox,
    shapes: &[Bbox],
    ignore: &[Bbox],
) -> Result<bool, BooleanError> {
    let mut clipped = ValidatedLayer::default();
    intersection_into(figures, &rects_layer(&[window])?, &mut clipped)?;
    let ignored = region(ignore)?;
    let care = |layer: &ValidatedLayer| -> Result<ValidatedLayer, BooleanError> {
        let mut out = ValidatedLayer::default();
        subtraction_into(layer, &ignored, &mut out)?;
        Ok(out)
    };
    let (have, want) = (care(&clipped)?, care(&region(shapes)?)?);
    let mut both = ValidatedLayer::default();
    intersection_into(&have, &want, &mut both)?;
    let common = area_of(&both).raw();
    Ok(area_of(&have).raw() == common && area_of(&want).raw() == common)
}
