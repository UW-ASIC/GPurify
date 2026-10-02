//! Width family: min/max width and notch (facing parallel edge pairs of one
//! polygon, found by a scanline sweep), and min edge length.
//!
//! Data in: one validated rectilinear layer. Data out: one violation per offending
//! polygon (per edge for min edge length). Exact on the whole input domain.

use super::{mid, owners_of, Verdict, REFUSED};
use crate::drc::Scratch;
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use gpurify_geom::boolean::{subtraction_into, union_into, BooleanError};
use gpurify_geom::ops::{Point, Winding};
use gpurify_geom::rects::decompose_into;
use gpurify_geom::store::GeometryStoreBuilder;
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::width::{narrowest_facing, narrowest_neck, poly_edges};
use gpurify_geom::{Bbox, Dbu, DbuArea, MAX_ABS_DBU};
use gpurify_geom::{GeometryStore, LayerId, PolyId};
use gpurify_ingest::StrId;

/// The store rows of a layer's validated polygons, in validated order: one
/// polygon per counter-clockwise row, ascending.
fn outer_rows(store: &GeometryStore, layer: LayerId) -> impl Iterator<Item = PolyId> + '_ {
    store
        .polys_on_layer(layer)
        .map(PolyId)
        .filter(move |&poly| {
            let (xs, ys) = store.poly_verts(poly);
            ring_winding(xs, ys) == Winding::CounterClockwise
        })
}

/// Winding of a validated rectilinear ring, read off its bottom edge: that edge
/// travels +x exactly when the ring is counter-clockwise.
fn ring_winding(xs: &[Dbu], ys: &[Dbu]) -> Winding {
    let n = xs.len();
    let ys = &ys[..n];
    // `i64::MAX` doubles as "no horizontal edge yet"; iteration zero is the closing edge.
    let (mut px, mut py) = (xs[n - 1].raw(), ys[n - 1].raw());
    let mut best_y = i64::MAX;
    let mut best_dx = 0i64;
    for i in 0..n {
        let (x, y) = (xs[i].raw(), ys[i].raw());
        let cand_y = if py == y { py } else { i64::MAX };
        if cand_y < best_y {
            best_dx = x - px;
            best_y = cand_y;
        }
        px = x;
        py = y;
    }
    debug_assert_eq!(
        Some(if best_dx > 0 {
            Winding::CounterClockwise
        } else {
            Winding::Clockwise
        }),
        gpurify_geom::ops::winding_of(xs, ys),
        "the bottom edge disagrees with the shoelace"
    );
    if best_dx > 0 {
        Winding::CounterClockwise
    } else {
        Winding::Clockwise
    }
}

/// Min width (Euclidean at concave corners) and notch (`material_between ==
/// false`, facing edges only). One violation per
/// offending figure of the self-merged layer: touching rectangles are one U,
/// and a rectangle drawn inside another adds no width of its own. `examined`
/// is the pre-merge polygon count.
pub(crate) fn facing(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    limit: Dbu,
    material_between: bool,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(drawn) = s.validated.get(store, layer) else {
        return REFUSED;
    };
    let polys = drawn.len() as u64;
    if union_into(drawn, &ValidatedLayer::default(), &mut s.layer_out).is_err() {
        return REFUSED;
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

/// One violation per edge shorter than `limit`, at its midpoint. `examined`
/// counts edges.
pub(crate) fn min_edge_length(
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
    let polys = u32::try_from(drawn.len()).expect("a layer indexes polygons with a u32");
    let mut rows = outer_rows(store, layer);
    let mut examined = 0u64;
    for idx in 0..polys {
        let shape = rows.next().expect("one store row per validated polygon");
        for (a, b) in poly_edges(drawn.get(idx)) {
            examined += 1;
            // Rectilinear: one term is zero.
            let length = (b.x - a.x).abs() + (b.y - a.y).abs();
            if length < limit {
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
                    shapes: (shape, None),
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
fn rects_layer(rects: &[Bbox]) -> Result<ValidatedLayer, BooleanError> {
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
