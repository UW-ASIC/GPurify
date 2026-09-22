//! Width family: min/max width and notch (facing parallel edge pairs of one
//! polygon, found by a scanline sweep), and min edge length.
//!
//! Data in: one validated rectilinear layer. Data out: one violation per offending
//! polygon (per edge for min edge length). Exact on the whole input domain.

use super::{mid, ring_segs, Verdict, REFUSED};
use crate::drc::Scratch;
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use gpurify_geom::boolean::union_into;
use gpurify_geom::ops::{Point, Winding};
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::Dbu;
use gpurify_geom::{GeometryStore, LayerId, PolyId, PolygonRef};
use gpurify_ingest::StrId;

/// One axis-aligned boundary edge.
#[derive(Debug, Clone, Copy)]
struct Edge {
    /// Coordinate on the axis the edge is perpendicular to.
    pos: Dbu,
    lo: Dbu,
    hi: Dbu,
    /// Material lies on the greater-`pos` side (canonical winding puts material
    /// on the left of travel for every ring, holes included).
    material_above: bool,
    vertical: bool,
}

fn edge_of(a: Point, b: Point) -> Edge {
    let vertical = a.x == b.x;
    let (pos, from, to) = if vertical {
        (a.x, a.y, b.y)
    } else {
        (a.y, a.x, b.x)
    };
    Edge {
        pos,
        lo: from.min(to),
        hi: from.max(to),
        // Travelling +y leaves material at -x; travelling +x leaves it at +y.
        material_above: (to > from) != vertical,
        vertical,
    }
}

/// Every boundary edge of one polygon, holes included, outer ring first.
fn poly_edges(poly: PolygonRef<'_>) -> impl Iterator<Item = (Point, Point)> + '_ {
    std::iter::once(poly.outer())
        .chain(poly.holes())
        .flat_map(|ring| {
            let (xs, ys) = ring.coords();
            ring_segs(xs, ys).map(|s| (s.a, s.b))
        })
}

/// The gap between two facing edges and its midpoint, or `None` when they do
/// not face each other across material (`material_between`) or across a void.
fn facing_pair(a: Edge, b: Edge, material_between: bool) -> Option<(Dbu, Point)> {
    if a.vertical != b.vertical {
        return None;
    }
    let (near, far) = if a.pos <= b.pos { (a, b) } else { (b, a) };
    if near.material_above != material_between || far.material_above == material_between {
        return None;
    }
    let lo = near.lo.max(far.lo);
    let hi = near.hi.min(far.hi);
    if hi <= lo {
        return None;
    }
    let (across, along) = (mid(near.pos, far.pos), mid(lo, hi));
    let at = if a.vertical {
        Point {
            x: across,
            y: along,
        }
    } else {
        Point {
            x: along,
            y: across,
        }
    };
    Some((far.pos - near.pos, at))
}

/// Buffers for one facing-pair sweep, refilled per polygon.
#[derive(Debug, Default)]
pub(crate) struct FacingScratch {
    edges: Vec<Edge>,
    /// `(coordinate, LEAVE|ENTER, edge)`, ascending: spans are half-open.
    events: Vec<(Dbu, u8, u32)>,
    /// Edges crossing the scanline, sorted by `(pos, index)`.
    active: Vec<u32>,
}

const LEAVE: u8 = 0;
const ENTER: u8 = 1;

fn slot_of(edges: &[Edge], active: &[u32], edge: u32) -> usize {
    let want = (edges[edge as usize].pos, edge);
    active.partition_point(|&j| (edges[j as usize].pos, j) < want)
}

/// Fold the active pair `(right - 1, right)` into `best`; out of range is a no-op.
fn consider(
    edges: &[Edge],
    active: &[u32],
    right: usize,
    material_between: bool,
    best: &mut Option<(Dbu, Point)>,
) {
    if right == 0 || right >= active.len() {
        return;
    }
    let near = edges[active[right - 1] as usize];
    let far = edges[active[right] as usize];
    if let Some(found) = facing_pair(near, far, material_between) {
        if best.is_none_or(|(gap, _)| found.0 < gap) {
            *best = Some(found);
        }
    }
}

/// The narrowest facing pair among one axis's edges. Only active-list
/// neighbours can be narrowest, so each event checks the pairs it disturbed.
fn sweep_axis(
    edges: &[Edge],
    vertical: bool,
    material_between: bool,
    events: &mut Vec<(Dbu, u8, u32)>,
    active: &mut Vec<u32>,
) -> Option<(Dbu, Point)> {
    events.clear();
    active.clear();
    events.extend(
        edges
            .iter()
            .enumerate()
            .filter(|(_, e)| e.vertical == vertical)
            .flat_map(|(i, e)| {
                let i = u32::try_from(i).expect("a polygon's edges are indexed by a u32");
                [(e.lo, ENTER, i), (e.hi, LEAVE, i)]
            }),
    );
    events.sort_unstable();

    let mut best: Option<(Dbu, Point)> = None;
    let mut ev = 0;
    while ev < events.len() {
        let at = events[ev].0;
        let group = ev;
        while ev < events.len() && events[ev].0 == at {
            let (_, kind, edge) = events[ev];
            let slot = slot_of(edges, active, edge);
            if kind == ENTER {
                active.insert(slot, edge);
            } else {
                active.remove(slot);
            }
            ev += 1;
        }
        for &(_, _, edge) in &events[group..ev] {
            let slot = slot_of(edges, active, edge);
            consider(edges, active, slot, material_between, &mut best);
            consider(edges, active, slot + 1, material_between, &mut best);
        }
    }
    best
}

/// The narrowest facing pair of one polygon; a tie keeps the vertical sweep's.
fn narrowest_facing(
    poly: PolygonRef<'_>,
    material_between: bool,
    scratch: &mut FacingScratch,
) -> Option<(Dbu, Point)> {
    let FacingScratch {
        edges,
        events,
        active,
    } = scratch;
    edges.clear();
    // A zero-length edge has no material side.
    edges.extend(
        poly_edges(poly)
            .map(|(a, b)| edge_of(a, b))
            .filter(|e| e.lo < e.hi),
    );
    let across = sweep_axis(edges, true, material_between, events, active);
    let along = sweep_axis(edges, false, material_between, events, active);
    [across, along]
        .into_iter()
        .flatten()
        .min_by_key(|&(gap, _)| gap)
}

/// The narrowest width of a validated polygon, holes included.
pub(crate) fn narrowest_width(poly: PolygonRef<'_>, scratch: &mut FacingScratch) -> Dbu {
    narrowest_facing(poly, true, scratch)
        .expect("every validated polygon has a facing pair across its own material")
        .0
}

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
    if validate_layer_into(store, layer, &mut s.layer_a).is_err() {
        return REFUSED;
    }
    let polys = s.layer_a.len() as u64;
    if !material_between
        && union_into(&s.layer_a, &ValidatedLayer::default(), &mut s.layer_out).is_err()
    {
        return REFUSED;
    }
    let figures = if material_between {
        &s.layer_a
    } else {
        &s.layer_out
    };
    for idx in 0..u32::try_from(figures.len()).expect("a layer indexes polygons with a u32") {
        let poly = figures.get(store, idx);
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
    if validate_layer_into(store, layer, &mut s.layer_a).is_err() {
        return REFUSED;
    }
    let polys = u32::try_from(s.layer_a.len()).expect("a layer indexes polygons with a u32");
    let mut rows = outer_rows(store, layer);
    let mut examined = 0u64;
    for idx in 0..polys {
        let shape = rows.next().expect("one store row per validated polygon");
        for (a, b) in poly_edges(s.layer_a.get(store, idx)) {
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
