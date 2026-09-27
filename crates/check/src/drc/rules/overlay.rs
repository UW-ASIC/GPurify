//! Overlay family: how two layers must sit relative to each other.
//!
//! Data in: two validated layers and their cross-layer candidate pairs.
//! Data out: one violation per offending inner shape / pair / well.
//! Enclosure takes the *best* host polygon (lowest row on a tie) that covers
//! the inner shape's whole area; an unhosted inner shape measures zero, never
//! skipped. Extension and overlap still measure bounding boxes, which is
//! optimistic for a concave shape (a known fail-open).

use super::{centre, mid, rects_ring_dist2, ring_segs, Verdict, REFUSED};
use crate::drc::Scratch;
use crate::erc::rules::supply::untied_points;
use crate::report::{
    LimitSense, Measurement, Outcome, Severity, SkipReason, Violation, Violations,
};
use gpurify_geom::index::{cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::ops::{isqrt, Point};
use gpurify_geom::rects::{clipped_area, covered_area};
use gpurify_geom::{Bbox, GeometryStore, LayerId, PolyId, PolygonRef};
use gpurify_geom::{Dbu, DbuArea, MAX_ABS_DBU};
use gpurify_ingest::StrId;
use std::cmp::Reverse;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

/// How far the host reaches past a rectangular `inner` on each side, read
/// along the side's own strip (projection metric): the nearest host edge,
/// holes included, facing that side. Exact for any rectilinear host that
/// contains `inner`.
fn strips(inner: Bbox, host: PolygonRef<'_>) -> [(Dbu, Side); 4] {
    // The widest margin the domain holds, 2^41: no real one exceeds it. Built
    // by `Sub`, as every margin is, since `new_unchecked` asserts 2^40.
    let far = Dbu::new_unchecked(MAX_ABS_DBU) - Dbu::new_unchecked(-MAX_ABS_DBU);
    let [mut l, mut r, mut b, mut t] = [far; 4];
    for ring in std::iter::once(host.outer()).chain(host.holes()) {
        let (xs, ys) = ring.coords();
        for e in ring_segs(xs, ys) {
            if e.a.x == e.b.x {
                let (lo, hi) = (e.a.y.min(e.b.y), e.a.y.max(e.b.y));
                if lo < inner.yhi && hi > inner.ylo {
                    if e.a.x <= inner.xlo {
                        l = l.min(inner.xlo - e.a.x);
                    }
                    if e.a.x >= inner.xhi {
                        r = r.min(e.a.x - inner.xhi);
                    }
                }
            } else {
                let (lo, hi) = (e.a.x.min(e.b.x), e.a.x.max(e.b.x));
                if lo < inner.xhi && hi > inner.xlo {
                    if e.a.y <= inner.ylo {
                        b = b.min(inner.ylo - e.a.y);
                    }
                    if e.a.y >= inner.yhi {
                        t = t.min(e.a.y - inner.yhi);
                    }
                }
            }
        }
    }
    [
        (l, Side::Left),
        (r, Side::Right),
        (b, Side::Bottom),
        (t, Side::Top),
    ]
}

/// Squared distance from the inner region (its rectangles) to the host's
/// boundary: the euclidean enclosure once the host contains it.
fn boundary_dist2(inner: &[Bbox], host: PolygonRef<'_>) -> i128 {
    std::iter::once(host.outer())
        .chain(host.holes())
        .map(|ring| {
            let (xs, ys) = ring.coords();
            rects_ring_dist2(inner, xs, ys)
        })
        .fold(i128::MAX, i128::min)
}

/// A contained inner polygon's enclosure in `host` and the side to report.
/// All sides: the euclidean distance to the host's boundary. Asymmetric: the
/// better axis's worse side, `max(min(left, right), min(bottom, top))`, which
/// needs a rectangular inner; any other inner falls back to all sides (fails
/// closed). `None` for the side means "not a rectangle, report at the centre".
fn enclosure_of(
    inner: &[Bbox],
    inner_box: Bbox,
    host: PolygonRef<'_>,
    asymmetric: bool,
) -> (Dbu, Option<Side>) {
    let boxed = inner.len() == 1;
    if boxed && asymmetric {
        let [l, r, b, t] = strips(inner_box, host);
        let (value, side) = greater(lesser(l, r), lesser(b, t));
        return (value, Some(side));
    }
    let value = isqrt(DbuArea::new(saturate(boundary_dist2(inner, host))));
    let side = boxed.then(|| {
        let [l, r, b, t] = strips(inner_box, host);
        lesser(lesser(l, r), lesser(b, t)).1
    });
    (value, side)
}

/// `isqrt` takes at most `MAX_ABS_DBU²`; a larger distance saturates there.
fn saturate(d2: i128) -> i128 {
    d2.min(i128::from(MAX_ABS_DBU) * i128::from(MAX_ABS_DBU))
}

/// Midpoint of the strip of width `margin` on one side of `inner`.
fn side_midpoint(inner: Bbox, margin: Dbu, side: Side) -> Point {
    let (cx, cy) = (mid(inner.xlo, inner.xhi), mid(inner.ylo, inner.yhi));
    match side {
        Side::Left => Point {
            x: mid(inner.xlo - margin, inner.xlo),
            y: cy,
        },
        Side::Right => Point {
            x: mid(inner.xhi, inner.xhi + margin),
            y: cy,
        },
        Side::Bottom => Point {
            x: cx,
            y: mid(inner.ylo - margin, inner.ylo),
        },
        Side::Top => Point {
            x: cx,
            y: mid(inner.yhi, inner.yhi + margin),
        },
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

/// `sqrt(d2)` rounded **up**, so an exceeded limit reads as exceeded.
fn ceil_sqrt(d2: i128) -> Dbu {
    let root = isqrt(DbuArea::new(d2));
    let exact = root.mul_wide(root).raw() == d2;
    Dbu::new_unchecked(root.raw() + i64::from(!exact))
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
    if s.validated.get(store, a).is_none() || s.validated.get(store, b).is_none() {
        return false;
    }
    SpatialIndex::build_into(store, a, &mut s.index_a);
    SpatialIndex::build_into(store, b, &mut s.index_b);
    cross_layer_pairs_into(store, &s.index_a, &s.index_b, distance, &mut s.pairs);
    true
}

/// Min enclosure (every side) or asymmetric enclosure (two opposite sides),
/// per inner polygon on its best host polygon. A host holds the inner only if
/// it covers all of its area (holes and concave notches count). `examined`
/// counts inner polygons.
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
    let Scratch {
        validated,
        pairs,
        rects_a: inner_rects,
        rects_b: host_rects,
        ..
    } = s;
    let drawn = validated.get(store, inner_layer).expect("validated above");
    inner_rects.build(store, inner_layer, drawn);
    let inner_boxes = drawn.bboxes().to_vec();
    let hosts = validated.get(store, outer).expect("validated above");
    host_rects.build(store, outer, hosts);
    let host_first = store.polys_on_layer(outer).start;

    let limit = Measurement::Length(limit);
    for poly in 0..u32::try_from(inner_rects.len()).expect("a layer indexes polygons with a u32") {
        let inner = inner_rects.row[poly as usize];
        let inner_box = inner_boxes[poly as usize];
        let mine = inner_rects.of(poly);
        let area = covered_area(mine);
        let lo = pairs.partition_point(|&(a, _)| a < inner);
        let hi = pairs.partition_point(|&(a, _)| a <= inner);
        // Best host; `Reverse` breaks a tie toward the lowest row.
        let mut acc = (UNHOSTED, Reverse(u32::MAX), None);
        for &(_, candidate) in &pairs[lo..hi] {
            let h = host_rects.poly_of_row[(candidate.0 - host_first) as usize];
            let host = host_rects.row[h as usize];
            let theirs = host_rects.of(h);
            let covered = mine
                .iter()
                .fold(DbuArea::new(0), |sum, &r| sum + clipped_area(theirs, r));
            if covered != area {
                continue;
            }
            let (value, side) = enclosure_of(mine, inner_box, hosts.get(h), asymmetric);
            acc = acc.max((value.raw(), Reverse(host.0), side));
        }
        let (best, Reverse(host), side) = acc;
        let measured = Measurement::Length(Dbu::new_unchecked(best.clamp(0, MAX_ABS_DBU)));
        if !measured.violates(limit, LimitSense::Minimum) {
            continue;
        }
        let hosted = best >= 0;
        let at = match side {
            Some(side) if hosted => side_midpoint(
                inner_box,
                Dbu::new_unchecked(best.clamp(0, MAX_ABS_DBU)),
                side,
            ),
            _ => centre(inner_box),
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
    (Outcome::Ran, inner_rects.len() as u64)
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

/// Max distance from any point of a well to the nearest tap (IHP LU.a/b,
/// gf180 DF.13/14: "any portion .. within 20 um of a tie"), with the ERC
/// `missing_tie` search: exact furthest point over the whole polygon, distance
/// to the taps' edges. Reported at that point, rounded up. `examined` counts
/// wells; an empty well layer is `Skipped(EmptyLayer)`, a well layer with no
/// taps is not.
///
/// ponytail: a point inside a tap measures to the tap's edge, not zero, so a
/// well interior under a wide tap over-reports by up to half the tap's width
/// (fails closed); an inside test per probe fixes it if it ever matters.
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
    if store.polys_on_layer(well_layer).is_empty() {
        return (Outcome::Skipped(SkipReason::EmptyLayer), 0);
    }
    if s.validated.get(store, well_layer).is_none() {
        return REFUSED;
    }
    let limit = Measurement::Length(reach);
    let examined = untied_points(
        store,
        (well_layer, tap),
        reach,
        &mut s.layer_out,
        |well, at, worst| {
            out.push(Violation {
                rule,
                layer: well_layer,
                severity: Severity::Error,
                at,
                measured: Measurement::Length(ceil_sqrt(worst.raw())),
                limit,
                shapes: (well, None),
            });
        },
    );
    examined.map_or(REFUSED, |n| (Outcome::Ran, n))
}
