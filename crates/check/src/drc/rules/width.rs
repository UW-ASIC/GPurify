//! Width family: min/max width and notch (facing parallel edge pairs of one
//! polygon, found by a scanline sweep), and min edge length.
//!
//! Data in: one validated rectilinear layer. Data out: one violation per offending
//! polygon (per edge for min edge length). Exact on the whole input domain.

use super::{mid, Verdict, REFUSED};
use crate::drc::Scratch;
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use gpurify_geom::boolean::union_into;
use gpurify_geom::ops::{Point, Winding};
use gpurify_geom::view::ValidatedLayer;
use gpurify_geom::width::{narrowest_facing, poly_edges};
use gpurify_geom::Dbu;
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

/// Min width, max width (`violated_below == false`) and notch
/// (`material_between == false`). One violation per offending figure.
///
/// A notch is measured on the self-merged layer (touching rectangles are one U);
/// a width on the rows as drawn. `examined` is the pre-merge polygon count.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn facing(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    limit: Dbu,
    material_between: bool,
    violated_below: bool,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(drawn) = s.validated.get(store, layer) else {
        return REFUSED;
    };
    let polys = drawn.len() as u64;
    if !material_between && union_into(drawn, &ValidatedLayer::default(), &mut s.layer_out).is_err()
    {
        return REFUSED;
    }
    let figures = if material_between {
        drawn
    } else {
        &s.layer_out
    };
    for idx in 0..u32::try_from(figures.len()).expect("a layer indexes polygons with a u32") {
        let poly = figures.get(idx);
        // A convex shape has no notch, and that is not a violation.
        let Some((measured, at)) = narrowest_facing(poly, material_between, &mut s.facing) else {
            continue;
        };
        let violated = if violated_below {
            measured < limit
        } else {
            measured > limit
        };
        if violated {
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at,
                measured: Measurement::Length(measured),
                limit: Measurement::Length(limit),
                shapes: (poly.provenance(), None),
            });
        }
    }
    (Outcome::Ran, polys)
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
