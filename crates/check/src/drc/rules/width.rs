//! Width family: min/max width and notch (facing parallel edge pairs of one
//! polygon, found by a scanline sweep), and min edge length.
//!
//! Data in: one validated layer; `min_width`, `notch` and `min_edge_length`
//! take edges at 45 degrees, the others refuse them. Data out: one violation
//! per offending merged figure (per edge of one for min edge length). Exact
//! on the whole input domain.

use super::{centre, mid, owners_by_point, owners_of, Verdict, REFUSED};
use crate::drc::ruleset::StepKind;
use crate::drc::Scratch;
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use gpurify_geom::boolean::{subtraction_into, union_into, BooleanError};
use gpurify_geom::derive::interacting_into;
use gpurify_geom::ops::isqrt;
use gpurify_geom::ops::Point;
use gpurify_geom::rects::decompose_into;
use gpurify_geom::store::GeometryStoreBuilder;
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::width::{narrowest_facing, narrowest_neck, narrowest_pair2, narrowest_width2};
use gpurify_geom::{Bbox, Dbu, DbuArea, MAX_ABS_DBU};
use gpurify_geom::{GeometryStore, LayerId};
use gpurify_ingest::StrId;

/// Min width (Euclidean at concave corners) and notch (`material_between ==
/// false`, facing edges only). One violation per
/// offending figure of the self-merged layer: touching rectangles are one U,
/// and a rectangle drawn inside another adds no width of its own. `examined`
/// is the pre-merge polygon count.
///
/// A layer with edges at 45 degrees is measured by
/// [`narrowest_pair2`](gpurify_geom::width::narrowest_pair2): facing edges at
/// their perpendicular distance, necks corner to corner, an acute tip 0 wide
/// (DRC-038; IHP SG13G2 M1.g, Mn.g, Gat.g). The figure is named by the
/// lowest drawn row inside it.
pub(crate) fn facing(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    limit: Dbu,
    material_between: bool,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(drawn) = s.validated.get_octilinear(store, layer) else {
        return REFUSED;
    };
    let polys = drawn.len() as u64;
    if union_into(drawn, &ValidatedLayer::default(), &mut s.layer_out).is_err() {
        return REFUSED;
    }
    if !drawn.is_rectilinear() {
        let owners = owners_by_point(&s.layer_out, drawn);
        for (idx, owner) in (0..).zip(owners) {
            let poly = s.layer_out.get(idx);
            if let Some((twice, at)) = narrowest_pair2(poly, material_between, limit) {
                out.push(Violation {
                    rule,
                    layer,
                    severity: Severity::Error,
                    at,
                    // Floored: twice a square halved, then rooted.
                    measured: Measurement::Length(isqrt(DbuArea::new(twice / 2))),
                    limit: Measurement::Length(limit),
                    shapes: (owner, None),
                });
            }
        }
        return (Outcome::Ran, polys);
    }
    // A merged figure's own provenance is a row of the boolean's scratch store.
    s.rects_a.build(store, layer, drawn);
    let owners = owners_of(&s.layer_out, &s.rects_a);
    for (idx, owner) in (0..).zip(owners) {
        let poly = s.layer_out.get(idx);
        // A convex shape has no notch, and that is not a violation.
        let facing = narrowest_facing(poly, material_between, &mut s.facing);
        // Width is Euclidean: a diagonal neck between concave corners counts.
        let neck = material_between
            .then(|| narrowest_neck(poly, limit))
            .flatten();
        let Some((measured, at)) = facing.into_iter().chain(neck).min_by_key(|&(gap, _)| gap)
        else {
            continue;
        };
        if measured < limit {
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at,
                measured: Measurement::Length(measured),
                limit: Measurement::Length(limit),
                shapes: (owner, None),
            });
        }
    }
    (Outcome::Ran, polys)
}

/// Max width: one violation per region of the merged layer where a `limit + 1`
/// square fits, so a plate with a thin tab is as wide as the plate and two
/// abutting rectangles are as wide as their union. Reported at the region's
/// narrowest facing pair, on the lowest drawn row under it. `examined` counts
/// drawn polygons.
pub(crate) fn max_width(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(drawn) = s.validated.get(store, layer) else {
        return REFUSED;
    };
    let polys = drawn.len() as u64;
    let mut wide = Vec::new();
    if wide_rects_into(drawn, limit + Dbu::new_unchecked(1), &mut wide).is_err() {
        return REFUSED;
    }
    if wide.is_empty() {
        return (Outcome::Ran, polys);
    }
    s.rects_a.build(store, layer, drawn);
    let merged = rects_layer(&wide)
        .and_then(|regions| union_into(&regions, &ValidatedLayer::default(), &mut s.layer_out));
    if merged.is_err() {
        return REFUSED;
    }
    let owners = owners_of(&s.layer_out, &s.rects_a);
    for (idx, owner) in (0..).zip(owners) {
        let poly = s.layer_out.get(idx);
        let (measured, at) = narrowest_facing(poly, true, &mut s.facing)
            .expect("every validated polygon has a facing pair across its own material");
        out.push(Violation {
            rule,
            layer,
            severity: Severity::Error,
            at,
            measured: Measurement::Length(measured),
            limit: Measurement::Length(limit),
            shapes: (owner, None),
        });
    }
    (Outcome::Ran, polys)
}

/// Exact cut size: every merged figure must be a `width` x `height` rectangle,
/// either way round (sky130 licon.1 "min and max L and W", IHP Cnt.a). A wrong
/// side reports that side against its target; a non-rectangle with the right
/// box reports its area against `width * height`. `examined` counts figures.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn cut_size(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    width: Dbu,
    height: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(drawn) = s.validated.get(store, layer) else {
        return REFUSED;
    };
    if union_into(drawn, &ValidatedLayer::default(), &mut s.layer_out).is_err() {
        return REFUSED;
    }
    s.rects_a.build(store, layer, drawn);
    let (short, long) = (width.min(height), width.max(height));
    let figures = &s.layer_out;
    for (idx, owner) in (0..).zip(owners_of(figures, &s.rects_a)) {
        let poly = figures.get(idx);
        let b = poly.bbox();
        let (bs, bl) = (b.width().min(b.height()), b.width().max(b.height()));
        let rectangle = poly.outer().coords().0.len() == 4 && poly.holes().next().is_none();
        let (measured, limit) = if bs != short {
            (Measurement::Length(bs), Measurement::Length(short))
        } else if bl != long {
            (Measurement::Length(bl), Measurement::Length(long))
        } else if !rectangle {
            let area = std::iter::once(poly.outer())
                .chain(poly.holes())
                .fold(0i128, |sum, ring| sum + ring.area2().raw())
                / 2;
            (
                Measurement::Area(DbuArea::new(area)),
                Measurement::Area(short.mul_wide(long)),
            )
        } else {
            continue;
        };
        out.push(Violation {
            rule,
            layer,
            severity: Severity::Error,
            at: Point {
                x: mid(b.xlo, b.xhi),
                y: mid(b.ylo, b.yhi),
            },
            measured,
            limit,
            shapes: (owner, None),
        });
    }
    (Outcome::Ran, figures.len() as u64)
}

/// Cut classes (sky130 via.1b, LEF58 `CUTCLASS`): every merged figure must be
/// a rectangle with no hole whose `(short, long)` sides are one of `classes`.
/// One violation per figure in none, at its bounding box's centre, measuring
/// the classes it matches (0) against 1. `examined` counts figures.
pub(crate) fn cut_class(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    classes: &[(Dbu, Dbu)],
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(drawn) = s.validated.get(store, layer) else {
        return REFUSED;
    };
    if union_into(drawn, &ValidatedLayer::default(), &mut s.layer_out).is_err() {
        return REFUSED;
    }
    s.rects_a.build(store, layer, drawn);
    let figures = &s.layer_out;
    for (idx, owner) in (0..).zip(owners_of(figures, &s.rects_a)) {
        let poly = figures.get(idx);
        let b = poly.bbox();
        let sides = (b.width().min(b.height()), b.width().max(b.height()));
        let rectangle = poly.outer().coords().0.len() == 4 && poly.holes().next().is_none();
        if rectangle && classes.contains(&sides) {
            continue;
        }
        out.push(Violation {
            rule,
            layer,
            severity: Severity::Error,
            at: Point {
                x: mid(b.xlo, b.xhi),
                y: mid(b.ylo, b.yhi),
            },
            measured: Measurement::Count(0),
            limit: Measurement::Count(1),
            shapes: (owner, None),
        });
    }
    (Outcome::Ran, figures.len() as u64)
}

/// Allowed widths (sky130 rpm.1b-1f, LEF58 `WIDTHTABLE`'s exact widths): each
/// merged figure's narrowest width, as `width` measures it, must be one of
/// `allowed`, compared squared and so exactly. One violation per figure in
/// none, at the centre of its first rectangle, measuring the width (floored)
/// against the nearest allowed one. `examined` counts figures.
pub(crate) fn allowed_width(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    allowed: &[Dbu],
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(drawn) = s.validated.get(store, layer) else {
        return REFUSED;
    };
    if union_into(drawn, &ValidatedLayer::default(), &mut s.layer_out).is_err() {
        return REFUSED;
    }
    s.rects_a.build(store, layer, drawn);
    let owners = owners_of(&s.layer_out, &s.rects_a);
    decompose_into(&s.layer_out, &mut s.rects, &mut s.rect_start);
    for (idx, owner) in (0u32..).zip(owners) {
        let width2 = narrowest_width2(s.layer_out.get(idx), &mut s.facing);
        if allowed.iter().any(|&w| w.mul_wide(w) == width2) {
            continue;
        }
        let width = isqrt(width2);
        let nearest = allowed
            .iter()
            .copied()
            .min_by_key(|w| (w.raw() - width.raw()).abs())
            .expect("an allowed list is never empty");
        out.push(Violation {
            rule,
            layer,
            severity: Severity::Error,
            at: centre(s.rects[s.rect_start[idx as usize] as usize]),
            measured: Measurement::Length(width),
            limit: Measurement::Length(nearest),
            shapes: (owner, None),
        });
    }
    (Outcome::Ran, s.layer_out.len() as u64)
}

/// LEF `PROTRUSIONWIDTH width1 LENGTH 0 WIDTH width2` (`limit`, `wide`): each
/// narrow part of a merged figure (no `limit` square covers it) touching the
/// figure's wide part (a `wide` square fits there) is one violation,
/// measuring its narrowest width, at the centre of its box, on the lowest
/// drawn row under it. `examined` counts merged figures.
pub(crate) fn protrusion_width(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    wide: Dbu,
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(drawn) = s.validated.get(store, layer) else {
        return REFUSED;
    };
    if union_into(drawn, &ValidatedLayer::default(), &mut s.layer_out).is_err() {
        return REFUSED;
    }
    s.rects_a.build(store, layer, drawn);
    let figures = &s.layer_out;
    let protrusions = || -> Result<ValidatedLayer, BooleanError> {
        let mut rects = Vec::new();
        wide_rects_into(figures, limit, &mut rects)?;
        let mut narrow = ValidatedLayer::default();
        subtraction_into(figures, &rects_layer(&rects)?, &mut narrow)?;
        wide_rects_into(figures, wide, &mut rects)?;
        let mut attached = ValidatedLayer::default();
        interacting_into(&narrow, &rects_layer(&rects)?, true, &mut attached);
        Ok(attached)
    };
    let Ok(attached) = protrusions() else {
        return REFUSED;
    };
    let owners = owners_of(&attached, &s.rects_a);
    for (idx, owner) in (0u32..).zip(owners) {
        let part = attached.get(idx);
        out.push(Violation {
            rule,
            layer,
            severity: Severity::Error,
            at: centre(part.bbox()),
            measured: Measurement::Length(isqrt(narrowest_width2(part, &mut s.facing))),
            limit: Measurement::Length(limit),
            shapes: (owner, None),
        });
    }
    (Outcome::Ran, s.layer_out.len() as u64)
}

/// One violation per edge of the merged layer shorter than `limit`, at its
/// midpoint, on the lowest drawn row under its figure. `examined` counts the
/// merged figures' edges. A 45-degree edge `k` steps long is `k·√2` long,
/// compared exactly and reported floored.
pub(crate) fn min_edge_length(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(drawn) = s.validated.get_octilinear(store, layer) else {
        return REFUSED;
    };
    if union_into(drawn, &ValidatedLayer::default(), &mut s.layer_out).is_err() {
        return REFUSED;
    }
    let owners = if drawn.is_rectilinear() {
        s.rects_a.build(store, layer, drawn);
        owners_of(&s.layer_out, &s.rects_a)
    } else {
        owners_by_point(&s.layer_out, drawn)
    };
    let limit2 = limit.mul_wide(limit);
    let mut examined = 0u64;
    for (idx, owner) in (0..).zip(owners) {
        for (a, b) in straight_runs(s.layer_out.get(idx)) {
            examined += 1;
            let (dx, dy) = ((b.x - a.x).abs(), (b.y - a.y).abs());
            let length2 = dx.mul_wide(dx) + dy.mul_wide(dy);
            if length2 < limit2 {
                let length = isqrt(length2);
                out.push(Violation {
                    rule,
                    layer,
                    severity: Severity::Error,
                    at: Point {
                        x: mid(a.x, b.x),
                        y: mid(a.y, b.y),
                    },
                    measured: Measurement::Length(length),
                    limit: Measurement::Length(limit),
                    shapes: (owner, None),
                });
            }
        }
    }
    (Outcome::Ran, examined)
}

/// Every straight run of a polygon's boundary, holes included: consecutive
/// edges of a ring running one way are one run. A merged ring keeps a vertex
/// where it passes straight through a point it also turns at (a 45-degree
/// tip touching an edge, the connected corner model), and one that leaves an
/// edge at a point it touches and comes back to it there continues that edge;
/// either way the edge is still one edge, as `KLayout` reads it.
fn straight_runs(poly: gpurify_geom::view::PolygonRef<'_>) -> Vec<(Point, Point)> {
    let mut runs = Vec::new();
    for ring in std::iter::once(poly.outer()).chain(poly.holes()) {
        let (xs, ys) = ring.coords();
        let n = xs.len();
        let at = |i: usize| Point {
            x: xs[i % n],
            y: ys[i % n],
        };
        let way = |i: usize| heading(at(i), at(i + 1));
        // Start at a vertex where the ring turns; every ring turns somewhere.
        let Some(first) = (0..n).find(|&i| way(i + n - 1) != way(i)) else {
            continue;
        };
        let mut from = first;
        for step in 1..=n {
            let i = first + step;
            if step == n || way(i - 1) != way(i) {
                runs.push((at(from), at(i)));
                from = i;
            }
        }
    }
    // A ring that leaves a straight edge at a point it also touches (a tip on
    // the edge) comes back and goes on: the two pieces are one edge.
    let mut by_start: std::collections::BTreeMap<(Point, (i64, i64)), usize> = runs
        .iter()
        .enumerate()
        .map(|(k, &(a, b))| ((a, heading(a, b)), k))
        .collect();
    let mut merged: Vec<(Point, Point)> = Vec::with_capacity(runs.len());
    let mut taken = vec![false; runs.len()];
    // A piece some other piece ends at is reached from that one.
    let continues: std::collections::BTreeSet<(Point, (i64, i64))> =
        runs.iter().map(|&(a, b)| (b, heading(a, b))).collect();
    for k in 0..runs.len() {
        let (a, b) = runs[k];
        if taken[k] || continues.contains(&(a, heading(a, b))) {
            continue;
        }
        taken[k] = true;
        let (way, mut end) = (heading(a, b), b);
        while let Some(&next) = by_start.get(&(end, way)) {
            if taken[next] {
                break;
            }
            taken[next] = true;
            by_start.remove(&(end, way));
            end = runs[next].1;
        }
        merged.push((a, end));
    }
    // Pieces on a closed straight loop (impossible) or not reached stay as they are.
    merged.extend((0..runs.len()).filter(|&k| !taken[k]).map(|k| runs[k]));
    merged
}

/// The direction an axis-aligned edge runs, as signs along x and y.
fn heading(a: Point, b: Point) -> (i64, i64) {
    ((b.x - a.x).raw().signum(), (b.y - a.y).raw().signum())
}

/// LEF `MINSTEP` variants (DRC-020): runs of consecutive edges shorter than
/// `limit` along each ring of the merged layer, classified by the long edges
/// on either side, rejected by `kind` and `length_sum` as
/// [`Rule::MinStep`](crate::drc::Rule::MinStep) states. One violation per
/// run at the centre of its vertices' box. `examined` counts runs.
pub(crate) fn min_step(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    (limit, kind, length_sum): (Dbu, StepKind, Option<Dbu>),
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(drawn) = s.validated.get(store, layer) else {
        return REFUSED;
    };
    if union_into(drawn, &ValidatedLayer::default(), &mut s.layer_out).is_err() {
        return REFUSED;
    }
    s.rects_a.build(store, layer, drawn);
    let mut examined = 0u64;
    let (mut points, mut short) = (Vec::new(), Vec::new());
    for (idx, owner) in (0u32..).zip(owners_of(&s.layer_out, &s.rects_a)) {
        let poly = s.layer_out.get(idx);
        for ring in std::iter::once(poly.outer()).chain(poly.holes()) {
            let (xs, ys) = ring.coords();
            points.clear();
            points.extend(xs.iter().zip(ys).map(|(&x, &y)| Point { x, y }));
            let n = points.len();
            let length = |i: usize| {
                let (a, b) = (points[i], points[(i + 1) % n]);
                (b.x - a.x).abs() + (b.y - a.y).abs()
            };
            short.clear();
            short.extend((0..n).map(|i| length(i) < limit));
            // Each run starts after a long edge; a ring with none is one run.
            let first_long = (0..n).find(|&i| !short[i]);
            let start = first_long.map_or(0, |i| i + 1);
            let mut i = 0;
            while i < n {
                let at = (start + i) % n;
                if !short[at] {
                    i += 1;
                    continue;
                }
                let mut count = 0usize;
                let mut sum = Dbu::new_unchecked(0);
                let mut bbox = Bbox::point(points[at].x, points[at].y);
                while i < n && short[(start + i) % n] {
                    let edge = (start + i) % n;
                    let end = points[(edge + 1) % n];
                    bbox = bbox.include(end.x, end.y);
                    sum = sum + length(edge);
                    count += 1;
                    i += 1;
                }
                examined += 1;
                // The long edges on either side, when the ring has one.
                let corner = first_long.map(|_| {
                    let before = (at + n - 1) % n;
                    let after = (at + count) % n;
                    let d1 = heading(points[before], points[(before + 1) % n]);
                    let d2 = heading(points[after], points[(after + 1) % n]);
                    let cross = d1.0 * d2.1 - d1.1 * d2.0;
                    let dot = d1.0 * d2.0 + d1.1 * d2.1;
                    match (cross.signum(), dot.signum()) {
                        (1, _) => Some(StepKind::OutsideCorner),
                        (-1, _) => Some(StepKind::InsideCorner),
                        (_, 1) => Some(StepKind::Step),
                        _ => None,
                    }
                });
                let run = u32::try_from(count).expect("a ring's edges fit a u32");
                let (measured, limit) = match kind {
                    StepKind::MaxEdges(most) if run > u32::from(most) => {
                        (Measurement::Count(run), Measurement::Count(u32::from(most)))
                    }
                    StepKind::MaxEdges(_) => continue,
                    _ if corner.flatten() != Some(kind) => continue,
                    _ => {
                        let fewest = if kind == StepKind::Step { 1 } else { 2 };
                        match length_sum {
                            _ if run < fewest => continue,
                            Some(allowed) if sum <= allowed => continue,
                            Some(allowed) => {
                                (Measurement::Length(sum), Measurement::Length(allowed))
                            }
                            None => (Measurement::Count(run), Measurement::Count(fewest - 1)),
                        }
                    }
                };
                out.push(Violation {
                    rule,
                    layer,
                    severity: Severity::Error,
                    at: Point {
                        x: mid(bbox.xlo, bbox.xhi),
                        y: mid(bbox.ylo, bbox.yhi),
                    },
                    measured,
                    limit,
                    shapes: (owner, None),
                });
            }
        }
    }
    (Outcome::Ran, examined)
}

/// The parts of a layer at least `w` wide, as disjoint rectangles: the union of
/// every axis-aligned `w`-square inside the merged layer (`KLayout`
/// `sized(-w/2).sized(w/2)`). Eroding by a `w - 1` square leaves a
/// positive-area anchor exactly where a `w`-square fits on the integer grid,
/// so a shape exactly `w` wide counts as wide.
pub(crate) fn wide_rects_into(
    drawn: &ValidatedLayer,
    w: Dbu,
    out: &mut Vec<Bbox>,
) -> Result<(), BooleanError> {
    out.clear();
    let extent = drawn
        .bboxes()
        .iter()
        .fold(Bbox::EMPTY, |acc, &b| acc.union(b));
    if extent.is_empty() {
        return Ok(());
    }
    let k = w.raw() - 1;
    let shift =
        |v: Dbu, by: i64| Dbu::new_unchecked((v.raw() + by).clamp(-MAX_ABS_DBU, MAX_ABS_DBU));
    let mut start = Vec::new();
    let mut scratch = ValidatedLayer::default();
    if k == 0 {
        union_into(drawn, &ValidatedLayer::default(), &mut scratch)?;
        decompose_into(&scratch, out, &mut start);
        return Ok(());
    }
    // ponytail: a frame clamped at the coordinate domain's edge erodes shapes
    // touching it; layouts never reach 2^40.
    let frame = rects_layer(&[Bbox {
        xlo: shift(extent.xlo, -k),
        ylo: shift(extent.ylo, -k),
        xhi: shift(extent.xhi, k),
        yhi: shift(extent.yhi, k),
    }])?;
    // Anchors p where p + [0, k]² leaves the layer: the complement dragged
    // left and down by k.
    subtraction_into(&frame, drawn, &mut scratch)?;
    decompose_into(&scratch, out, &mut start);
    for r in out.iter_mut() {
        r.xlo = shift(r.xlo, -k);
        r.ylo = shift(r.ylo, -k);
    }
    let blocked = rects_layer(out)?;
    subtraction_into(&frame, &blocked, &mut scratch)?;
    decompose_into(&scratch, out, &mut start);
    for r in out.iter_mut() {
        r.xhi = shift(r.xhi, k);
        r.yhi = shift(r.yhi, k);
    }
    let grown = rects_layer(out)?;
    union_into(&grown, &ValidatedLayer::default(), &mut scratch)?;
    decompose_into(&scratch, out, &mut start);
    Ok(())
}

/// Rectangles, possibly overlapping, as one validated layer.
pub(super) fn rects_layer(rects: &[Bbox]) -> Result<ValidatedLayer, BooleanError> {
    let mut builder = GeometryStoreBuilder::with_capacity(rects.len(), 4 * rects.len());
    for r in rects {
        builder.push(
            LayerId(0),
            &[r.xlo, r.xhi, r.xhi, r.xlo],
            &[r.ylo, r.ylo, r.yhi, r.yhi],
        );
    }
    let (store, _) = builder.finish(1);
    let mut out = ValidatedLayer::default();
    validate_layer_into(&store, LayerId(0), &mut out)?;
    Ok(out)
}
