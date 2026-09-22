//! Overlay family: how two layers must sit relative to each other.
//!
//! Data in: two validated layers and their cross-layer candidate pairs.
//! Data out: one violation per offending inner shape / pair / well.
//! Enclosure takes the *best* host (lowest row on a tie); an unhosted inner
//! shape measures zero, never skipped. Margins are on bounding boxes, which is
//! optimistic for a concave host (a known fail-open).

use super::{centre, mid, ring_segs, Verdict, REFUSED};
use crate::drc::Scratch;
use crate::report::{
    LimitSense, Measurement, Outcome, Severity, SkipReason, Violation, Violations,
};
use gpurify_geom::index::{cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::ops::{isqrt, Point};
use gpurify_geom::view::validate_layer_into;
use gpurify_geom::{Bbox, GeometryStore, LayerId, PolyId};
use gpurify_geom::{Dbu, DbuArea, MAX_ABS_DBU};
use gpurify_ingest::StrId;
use std::cmp::Reverse;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Left,
    Right,
    Bottom,
    Top,
}

/// Per-side margins of `inner` within `outer`: positive where outer extends
/// past inner. May legally reach `±2^41`.
fn margins(inner: Bbox, outer: Bbox) -> [(Dbu, Side); 4] {
    [
        (inner.xlo - outer.xlo, Side::Left),
        (outer.xhi - inner.xhi, Side::Right),
        (inner.ylo - outer.ylo, Side::Bottom),
        (outer.yhi - inner.yhi, Side::Top),
    ]
}

/// The smaller of two sides, the first on a tie.
fn lesser(a: (Dbu, Side), b: (Dbu, Side)) -> (Dbu, Side) {
    if a.0 <= b.0 {
        a
    } else {
        b
    }
}

/// The larger of two sides, the first on a tie.
fn greater(a: (Dbu, Side), b: (Dbu, Side)) -> (Dbu, Side) {
    if a.0 >= b.0 {
        a
    } else {
        b
    }
}

/// The side an enclosure rule compares: the worst side, or for the asymmetric
/// rule `min(max(left, right), max(bottom, top))`.
fn enclosure_of(inner: Bbox, outer: Bbox, asymmetric: bool) -> (Dbu, Side) {
    let [l, r, b, t] = margins(inner, outer);
    if asymmetric {
        lesser(greater(l, r), greater(b, t))
    } else {
        lesser(lesser(l, r), lesser(b, t))
    }
}

/// Midpoint of the strip between the two boxes on one side.
fn strip_midpoint(inner: Bbox, outer: Bbox, side: Side) -> Point {
    let cross_x = mid(inner.xlo.max(outer.xlo), inner.xhi.min(outer.xhi));
    let cross_y = mid(inner.ylo.max(outer.ylo), inner.yhi.min(outer.yhi));
    match side {
        Side::Left => Point {
            x: mid(outer.xlo, inner.xlo),
            y: cross_y,
        },
        Side::Right => Point {
            x: mid(inner.xhi, outer.xhi),
            y: cross_y,
        },
        Side::Bottom => Point {
            x: cross_x,
            y: mid(outer.ylo, inner.ylo),
        },
        Side::Top => Point {
            x: cross_x,
            y: mid(inner.yhi, outer.yhi),
        },
    }
}

/// Below the most negative real margin (`-2 * MAX_ABS_DBU`): seeds the host fold.
const UNHOSTED: i64 = -(1 << 42);

/// "No tap in reach": `MAX_ABS_DBU²`, a perfect square, so it reports as
/// `MAX_ABS_DBU` and over-reports (fails closed).
const OUT_OF_REACH: i128 = 1 << 80;

fn point_box_dist2(x: Dbu, y: Dbu, b: Bbox) -> i128 {
    let dx = i128::from((b.xlo.raw() - x.raw()).max(x.raw() - b.xhi.raw()).max(0));
    let dy = i128::from((b.ylo.raw() - y.raw()).max(y.raw() - b.yhi.raw()).max(0));
    dx * dx + dy * dy
}

/// `sqrt(d2)` rounded **up**, so an exceeded limit reads as exceeded.
fn ceil_sqrt(d2: i128) -> Dbu {
    let root = isqrt(DbuArea::new(d2));
    let exact = root.mul_wide(root).raw() == d2;
    Dbu::new_unchecked(root.raw() + i64::from(!exact))
}

/// The run of `pairs` (strictly ascending) whose first element is `a`; the
/// cursor only moves forward as `a` ascends.
fn run_of(pairs: &[(PolyId, PolyId)], cursor: &mut usize, a: PolyId) -> (usize, usize) {
    while *cursor < pairs.len() && pairs[*cursor].0 < a {
        *cursor += 1;
    }
    let lo = *cursor;
    while *cursor < pairs.len() && pairs[*cursor].0 == a {
        *cursor += 1;
    }
    (lo, *cursor)
}

/// Validate both layers and prune their cross-layer pairs at `distance` into
/// `s.pairs`, grouped by `a`. `false` is `Refused`.
fn pair_layers(
    store: &GeometryStore,
    a: LayerId,
    b: LayerId,
    distance: Dbu,
    s: &mut Scratch,
) -> bool {
    if validate_layer_into(store, a, &mut s.layer_a).is_err()
        || validate_layer_into(store, b, &mut s.layer_b).is_err()
    {
        return false;
    }
    SpatialIndex::build_into(store, a, &mut s.index_a);
    SpatialIndex::build_into(store, b, &mut s.index_b);
    cross_layer_pairs_into(store, &s.index_a, &s.index_b, distance, &mut s.pairs);
    true
}

/// Whether two axis-aligned segments properly cross (touching is not crossing).
fn segments_cross(a: (Point, Point), b: (Point, Point)) -> bool {
    crosses_hv(a, b) || crosses_hv(b, a)
}

fn crosses_hv(h: (Point, Point), v: (Point, Point)) -> bool {
    let (xlo, xhi) = (h.0.x.min(h.1.x), h.0.x.max(h.1.x));
    let (ylo, yhi) = (v.0.y.min(v.1.y), v.0.y.max(v.1.y));
    h.0.y == h.1.y && v.0.x == v.1.x && v.0.x > xlo && v.0.x < xhi && h.0.y > ylo && h.0.y < yhi
}

/// Whether ring `inner` lies within ring `host` (boundary-inclusive): one vertex
/// inside and no proper edge crossing. Does not see host holes (fail-open).
fn ring_contains_ring(store: &GeometryStore, host: PolyId, inner: PolyId) -> bool {
    let (xs, ys) = store.poly_verts(inner);
    if !store.poly_contains_point(host, Point { x: xs[0], y: ys[0] }) {
        return false;
    }
    let (hxs, hys) = store.poly_verts(host);
    !ring_segs(xs, ys)
        .any(|si| ring_segs(hxs, hys).any(|sh| segments_cross((si.a, si.b), (sh.a, sh.b))))
}

/// Min enclosure (every side) or asymmetric enclosure (one side per axis), on
/// the best containing host. `examined` counts inner shapes.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn enclosure(
    store: &GeometryStore,
    rule: StrId,
    outer: LayerId,
    inner_layer: LayerId,
    limit: Dbu,
    asymmetric: bool,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    if !pair_layers(store, inner_layer, outer, Dbu::new_unchecked(0), s) {
        return REFUSED;
    }
    let limit = Measurement::Length(limit);
    let shapes = store.polys_on_layer(inner_layer);
    let examined = u64::from(shapes.end - shapes.start);
    let mut cursor = 0usize;
    for shape in shapes {
        let inner = PolyId(shape);
        let inner_box = store.poly_bbox(inner);
        let (lo, hi) = run_of(&s.pairs, &mut cursor, inner);
        // Best host; `Reverse` breaks a tie toward the lowest row. A candidate
        // that does not contain the shape folds in as `UNHOSTED`.
        let mut acc = (UNHOSTED, Reverse(u32::MAX));
        for &(_, candidate) in &s.pairs[lo..hi] {
            let host_box = store.poly_bbox(candidate);
            let contained =
                host_box.contains(inner_box) && ring_contains_ring(store, candidate, inner);
            let value = if contained {
                enclosure_of(inner_box, host_box, asymmetric).0.raw()
            } else {
                UNHOSTED
            };
            acc = acc.max((value, Reverse(candidate.0)));
        }
        let (best, Reverse(host)) = acc;
        let measured = Measurement::Length(Dbu::new_unchecked(best.clamp(0, MAX_ABS_DBU)));
        if !measured.violates(limit, LimitSense::Minimum) {
            continue;
        }
        let hosted = best >= 0;
        let at = if hosted {
            let host_box = store.poly_bbox(PolyId(host));
            strip_midpoint(
                inner_box,
                host_box,
                enclosure_of(inner_box, host_box, asymmetric).1,
            )
        } else {
            centre(inner_box)
        };
        out.push(Violation {
            rule,
            layer: inner_layer,
            severity: Severity::Error,
            at,
            measured,
            limit,
            shapes: (inner, hosted.then_some(PolyId(host))),
        });
    }
    (Outcome::Ran, examined)
}

/// The smallest positive protrusion and its side (first on a tie); zero when
/// the layer protrudes nowhere.
fn smallest_protrusion(reference: Bbox, line: Bbox) -> (Dbu, Side) {
    margins(reference, line)
        .into_iter()
        .filter(|&(value, _)| value.raw() > 0)
        .min_by_key(|&(value, _)| value.raw())
        .unwrap_or((Dbu::new_unchecked(0), Side::Left))
}

/// Min extension of `layer` past `reference`, judged on overlapping pairs only.
/// `examined` counts overlapping pairs.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn min_extension(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    reference: LayerId,
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    if !pair_layers(store, layer, reference, Dbu::new_unchecked(0), s) {
        return REFUSED;
    }
    let limit = Measurement::Length(limit);
    // The prune at distance zero is exactly the overlapping pairs.
    for &(line, reference) in &s.pairs {
        let (line_box, ref_box) = (store.poly_bbox(line), store.poly_bbox(reference));
        let (protrusion, side) = smallest_protrusion(ref_box, line_box);
        let measured = Measurement::Length(protrusion);
        if measured.violates(limit, LimitSense::Minimum) {
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: strip_midpoint(ref_box, line_box, side),
                measured,
                limit,
                shapes: (line, Some(reference)),
            });
        }
    }
    (Outcome::Ran, s.pairs.len() as u64)
}

/// Min overlap: the smaller side of each pair's box intersection (a known
/// fail-open for non-convex shapes). `examined` counts overlapping pairs.
pub(crate) fn overlap(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    b: LayerId,
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    if !pair_layers(store, layer, b, Dbu::new_unchecked(0), s) {
        return REFUSED;
    }
    let limit = Measurement::Length(limit);
    for &(a, b) in &s.pairs {
        let figure = store
            .poly_bbox(a)
            .intersection(store.poly_bbox(b))
            .expect("the prune at distance zero keeps overlapping boxes only");
        let smaller = figure.width().raw().min(figure.height().raw());
        let measured = Measurement::Length(Dbu::new_unchecked(smaller.min(MAX_ABS_DBU)));
        if measured.violates(limit, LimitSense::Minimum) {
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: centre(figure),
                measured,
                limit,
                shapes: (a, Some(b)),
            });
        }
    }
    (Outcome::Ran, s.pairs.len() as u64)
}

/// Max distance from every well vertex to the nearest tap box, reported at the
/// farthest vertex (first on a tie). `examined` counts wells; an empty well layer
/// is `Skipped(EmptyLayer)`, a well layer with no taps is not.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn max_distance_to_tap(
    store: &GeometryStore,
    rule: StrId,
    well_layer: LayerId,
    tap: LayerId,
    reach: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let wells = store.polys_on_layer(well_layer);
    let examined = u64::from(wells.end - wells.start);
    if examined == 0 {
        return (Outcome::Skipped(SkipReason::EmptyLayer), 0);
    }
    if !pair_layers(store, well_layer, tap, reach, s) {
        return REFUSED;
    }
    let limit = Measurement::Length(reach);
    let mut cursor = 0usize;
    for well_row in wells {
        let well = PolyId(well_row);
        let (lo, hi) = run_of(&s.pairs, &mut cursor, well);
        let taps = &s.pairs[lo..hi];
        let (xs, ys) = store.poly_verts(well);
        let mut worst = (i128::MIN, 0usize);
        for (vertex, (&x, &y)) in xs.iter().zip(ys).enumerate() {
            let nearest = taps
                .iter()
                .map(|&(_, tap)| point_box_dist2(x, y, store.poly_bbox(tap)))
                .fold(OUT_OF_REACH, i128::min);
            if nearest > worst.0 {
                worst = (nearest, vertex);
            }
        }
        let measured = Measurement::Length(ceil_sqrt(worst.0));
        if measured.violates(limit, LimitSense::Maximum) {
            out.push(Violation {
                rule,
                layer: well_layer,
                severity: Severity::Error,
                at: Point {
                    x: xs[worst.1],
                    y: ys[worst.1],
                },
                measured,
                limit,
                shapes: (well, None),
            });
        }
    }
    (Outcome::Ran, examined)
}
