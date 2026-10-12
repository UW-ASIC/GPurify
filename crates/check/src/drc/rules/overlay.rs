//! Overlay family: how two layers must sit relative to each other.
//!
//! Data in: two validated layers and their cross-layer candidate pairs, or
//! their merged figures. Data out: one violation per offending inner shape /
//! gate / shared figure / well.
//! Enclosure takes the *best* host polygon (lowest row on a tie) that covers
//! the inner shape's whole area; an unhosted inner shape measures zero, never
//! skipped. Extension and overlap measure the figures of the area the merged
//! layers share, so shapes that only touch are never measured.

use super::presence::{hosts, inside_point, rects_of};
use super::width::{rects_layer, wide_rects_into};
use super::{
    centre, gap_midpoint, merged, mid, owners_of, rects_ring_dist2, ring_segs, SortedRects,
    Verdict, REFUSED,
};
use crate::drc::{Scratch, WireBand};
use crate::erc::rules::supply::untied_points;
use crate::report::{
    LimitSense, Measurement, Outcome, Severity, SkipReason, Violation, Violations,
};
use gpurify_geom::boolean::{intersection_into, subtraction_into, union_into, BooleanError};
use gpurify_geom::index::{cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::ops::{isqrt, seg_seg_dist2, Point, Seg};
use gpurify_geom::rects::{clipped_area, covered_area, decompose_into};
use gpurify_geom::width::{narrowest_facing, narrowest_neck, poly_edges};
use gpurify_geom::{Bbox, GeometryStore, LayerId, PolyId, PolygonRef, ValidatedLayer};
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

/// The smaller of two sides, the first on a tie.
fn lesser(a: (Dbu, Side), b: (Dbu, Side)) -> (Dbu, Side) {
    if a.0 <= b.0 {
        a
    } else {
        b
    }
}

/// The widest margin the domain holds, 2^41: no real one exceeds it. Built by
/// `Sub`, as every margin is, since `new_unchecked` asserts 2^40.
fn far() -> Dbu {
    Dbu::new_unchecked(MAX_ABS_DBU) - Dbu::new_unchecked(-MAX_ABS_DBU)
}

/// How far the host reaches past a rectangular `inner` on each side, read
/// along the side's own strip (projection metric): the nearest host edge,
/// holes included, facing that side. Exact for any rectilinear host that
/// contains `inner`.
fn strips(inner: Bbox, host: PolygonRef<'_>) -> [(Dbu, Side); 4] {
    let [mut l, mut r, mut b, mut t] = [far(); 4];
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

/// How far the host reaches past a box `inner` (an edge, as a degenerate
/// box) at each end of each side: `[left, right, bottom, top]`, each
/// `(low end, high end)`, read straight out from the side just inside that
/// end (projection metric). A host whose edge steps along a side reaches
/// different distances at the side's two ends; a host that does not step
/// reaches its [`strips`] value at both.
fn strip_ends(inner: Bbox, host: PolygonRef<'_>) -> [(Dbu, Dbu); 4] {
    let mut ends = [(far(), far()); 4];
    // An edge spanning `lo..hi` faces the end at `at` of a side `from..to`
    // when it covers the side's last unit before that end.
    let covers_low = |lo: Dbu, hi: Dbu, from: Dbu| lo <= from && hi > from;
    let covers_high = |lo: Dbu, hi: Dbu, to: Dbu| lo < to && hi >= to;
    let keep = |slot: &mut (Dbu, Dbu), low: bool, high: bool, d: Dbu| {
        if low {
            slot.0 = slot.0.min(d);
        }
        if high {
            slot.1 = slot.1.min(d);
        }
    };
    for ring in std::iter::once(host.outer()).chain(host.holes()) {
        let (xs, ys) = ring.coords();
        for e in ring_segs(xs, ys) {
            if e.a.x == e.b.x {
                let (lo, hi) = (e.a.y.min(e.b.y), e.a.y.max(e.b.y));
                let (low, high) = (
                    covers_low(lo, hi, inner.ylo),
                    covers_high(lo, hi, inner.yhi),
                );
                if e.a.x <= inner.xlo {
                    keep(&mut ends[0], low, high, inner.xlo - e.a.x);
                }
                if e.a.x >= inner.xhi {
                    keep(&mut ends[1], low, high, e.a.x - inner.xhi);
                }
            } else {
                let (lo, hi) = (e.a.x.min(e.b.x), e.a.x.max(e.b.x));
                let (low, high) = (
                    covers_low(lo, hi, inner.xlo),
                    covers_high(lo, hi, inner.xhi),
                );
                if e.a.y <= inner.ylo {
                    keep(&mut ends[2], low, high, inner.ylo - e.a.y);
                }
                if e.a.y >= inner.yhi {
                    keep(&mut ends[3], low, high, e.a.y - inner.yhi);
                }
            }
        }
    }
    ends
}

/// The enclosure of `inner` by one of the two sides at each convex corner:
/// the least, over its convex corners, of the better of the two edges
/// meeting there, each read straight out at that corner's end of the edge,
/// and where to report it (the strip past the better edge of the worst
/// corner). For a rectangle in a host that does not step along its sides
/// this is `max(min(left, right), min(bottom, top))`, the opposite-sides
/// value: `min` of the four corner `max`es distributes to it.
fn adjacent_enclosure(inner: PolygonRef<'_>, host: PolygonRef<'_>) -> (Dbu, Point) {
    // An edge's reading at its endpoint `p`, outward from the inner.
    let at_end = |a: Point, b: Point, p: Point| {
        let edge = Bbox::point(a.x, a.y).include(b.x, b.y);
        let side = outward(a, b);
        let (low, high) = strip_ends(edge, host)[side as usize];
        let at_low = if a.x == b.x {
            p.y == edge.ylo
        } else {
            p.x == edge.xlo
        };
        (if at_low { low } else { high }, side, edge)
    };
    let (xs, ys) = inner.outer().coords();
    let n = xs.len();
    let pt = |i: usize| Point {
        x: xs[i % n],
        y: ys[i % n],
    };
    let mut worst: Option<(Dbu, Side, Bbox)> = None;
    for i in 0..n {
        let (u, v, w) = (pt(i + n - 1), pt(i), pt(i + 1));
        // Counter-clockwise outer ring: a left turn is a convex corner.
        let turn = (v.x - u.x).raw() * (w.y - v.y).raw() - (v.y - u.y).raw() * (w.x - v.x).raw();
        if turn <= 0 {
            continue;
        }
        let (d1, s1, e1) = at_end(u, v, v);
        let (d2, s2, e2) = at_end(v, w, v);
        let better = if (d1, s2) >= (d2, s1) {
            (d1, s1, e1)
        } else {
            (d2, s2, e2)
        };
        if worst.is_none_or(|(d, s, _)| (better.0, better.1) < (d, s)) {
            worst = Some(better);
        }
    }
    let (d, side, edge) = worst.expect("a validated polygon has a convex corner");
    (d, side_midpoint(edge, d, side))
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

/// How an enclosure rule reads an inner polygon in its host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// The Euclidean distance to the host's boundary (`min_enclosure`).
    EverySide,
    /// The better axis of straight-out readings (`asymmetric_enclosure`).
    Opposite,
    /// Facing parallel edges, coincident ones exempt
    /// (`noncoincident_enclosure`).
    NonCoincident,
    /// The better axis's widest straight-out reading, which must be 0
    /// (`full_width`).
    FullWidth,
    /// One of the two edges at each convex corner, read at that corner
    /// (`adjacent_enclosure`).
    Adjacent,
}

/// The least Euclidean distance between an edge of `inner` and a parallel
/// edge of `host` facing the same way at or beyond it, over the pairs that
/// do not touch, and the middle of the gap between that pair's boxes; `None`
/// when every such pair touches (an inner polygon whose every edge lies on
/// its host's boundary).
fn apart_enclosure(inner: PolygonRef<'_>, host: PolygonRef<'_>) -> Option<(DbuArea, Point)> {
    let mut best: Option<(DbuArea, Point)> = None;
    for (a, b) in poly_edges(inner) {
        let (side, e) = (outward(a, b), Seg { a, b });
        for (c, d) in poly_edges(host) {
            if outward(c, d) != side {
                continue;
            }
            let beyond = match side {
                Side::Left => c.x <= a.x,
                Side::Right => c.x >= a.x,
                Side::Bottom => c.y <= a.y,
                Side::Top => c.y >= a.y,
            };
            let d2 = seg_seg_dist2(e, Seg { a: c, b: d });
            if !beyond || d2.raw() == 0 || best.is_some_and(|(least, _)| least <= d2) {
                continue;
            }
            let boxes = (
                Bbox::point(a.x, a.y).include(b.x, b.y),
                Bbox::point(c.x, c.y).include(d.x, d.y),
            );
            best = Some((d2, gap_midpoint(boxes.0, boxes.1)));
        }
    }
    best
}

/// A contained inner polygon's enclosure in `host` and where to report it
/// (`None`: at the centre of its box).
///
/// Non-coincident: [`apart_enclosure`], reported in the middle of the gap
/// of the pair that measured it; past every limit when every pair touches.
///
/// All sides: the euclidean distance to the host's boundary, reported in the
/// strip on the least enclosed side of a rectangle.
///
/// Opposite: each edge of the polygon, holes included, is read straight out
/// from its outside to the nearest host edge facing it ([`strips`]); the
/// vertical edges enclose it along x by the least of theirs, the horizontal
/// edges along y, and the polygon measures its better axis,
/// `max(min(vertical), min(horizontal))`, x on a tie. For a rectangle that
/// is `max(min(left, right), min(bottom, top))`. Reported in the strip past
/// the least enclosed edge of that axis: left before right and bottom
/// before top on a tie, then the first in ring order.
fn enclosure_of(
    inner: PolygonRef<'_>,
    rects: &[Bbox],
    host: PolygonRef<'_>,
    mode: Mode,
) -> (Dbu, Option<Point>) {
    if mode == Mode::NonCoincident {
        return apart_enclosure(inner, host).map_or_else(
            || (far(), None),
            |(d2, at)| (isqrt(DbuArea::new(saturate(d2.raw()))), Some(at)),
        );
    }
    if mode == Mode::Adjacent {
        let (value, at) = adjacent_enclosure(inner, host);
        return (value, Some(at));
    }
    if mode == Mode::FullWidth {
        // Per axis (vertical edges, horizontal edges): the most enclosed edge.
        let mut most: [Option<(Dbu, Side, Bbox)>; 2] = [None; 2];
        for (a, b) in poly_edges(inner) {
            let edge = Bbox::point(a.x, a.y).include(b.x, b.y);
            let side = outward(a, b);
            let (run, _) = strips(edge, host)[side as usize];
            let axis = &mut most[usize::from(a.y == b.y)];
            if axis.is_none_or(|(d, s, _)| (run, Reverse(side)) > (d, Reverse(s))) {
                *axis = Some((run, side, edge));
            }
        }
        let edges = "a validated polygon has edges along both axes";
        let (x, y) = (most[0].expect(edges), most[1].expect(edges));
        let (run, side, edge) = if x.0 <= y.0 { x } else { y };
        return (run, Some(side_midpoint(edge, run, side)));
    }
    if mode == Mode::Opposite {
        // Per axis (vertical edges, horizontal edges): the least enclosed edge.
        let mut least: [Option<(Dbu, Side, Bbox)>; 2] = [None; 2];
        for (a, b) in poly_edges(inner) {
            let edge = Bbox::point(a.x, a.y).include(b.x, b.y);
            let side = outward(a, b);
            let (run, _) = strips(edge, host)[side as usize];
            let axis = &mut least[usize::from(a.y == b.y)];
            if axis.is_none_or(|(d, s, _)| (run, side) < (d, s)) {
                *axis = Some((run, side, edge));
            }
        }
        let edges = "a validated polygon has edges along both axes";
        let (x, y) = (least[0].expect(edges), least[1].expect(edges));
        let (run, side, edge) = if x.0 >= y.0 { x } else { y };
        return (run, Some(side_midpoint(edge, run, side)));
    }
    let value = isqrt(DbuArea::new(saturate(boundary_dist2(rects, host))));
    let inner_box = inner.bbox();
    let at = (rects.len() == 1).then(|| {
        let [l, r, b, t] = strips(inner_box, host);
        side_midpoint(inner_box, value, lesser(lesser(l, r), lesser(b, t)).1)
    });
    (value, at)
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

/// The part of `drawn` at least `width` wide, indexed for coverage; `None`
/// for no width. `Err` is a failed boolean.
fn wide_part(
    drawn: &ValidatedLayer,
    width: Option<Dbu>,
) -> Result<Option<SortedRects<()>>, BooleanError> {
    let Some(width) = width else {
        return Ok(None);
    };
    let mut rects = Vec::new();
    wide_rects_into(drawn, width, &mut rects)?;
    Ok(Some(SortedRects::new(
        rects.into_iter().map(|r| (r, ())).collect(),
    )))
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

/// Min enclosure (every side, or apart from coincident edges) or asymmetric
/// enclosure (two opposite sides),
/// per inner polygon on its best host: a figure of the merged outer layer, so
/// a ring drawn as abutting bands hosts a ring inside it. A host holds the
/// inner only if it covers all of its area (holes and concave notches count).
/// Only the inner polygons `wire` selects are held. `examined` counts them.
pub(crate) fn enclosure(
    store: &GeometryStore,
    rule: StrId,
    (outer, inner_layer): (LayerId, LayerId),
    (limit, wire): (Dbu, WireBand),
    mode: Mode,
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
        layer_out: merged,
        rects: merged_rects,
        rect_start: merged_start,
        ..
    } = s;
    let hosts = validated.get(store, outer).expect("validated above");
    host_rects.build(store, outer, hosts);
    let host_first = store.polys_on_layer(outer).start;
    if union_into(hosts, &ValidatedLayer::default(), merged).is_err() {
        return REFUSED;
    }
    // The parts of the outer layer at least `from` and `below` wide.
    let (Ok(from), Ok(below)) = (
        wide_part(hosts, Some(wire.from).filter(|w| w.raw() > 0)),
        wide_part(hosts, wire.below),
    ) else {
        return REFUSED;
    };
    let drawn = validated.get(store, inner_layer).expect("validated above");
    inner_rects.build(store, inner_layer, drawn);
    let inner_boxes = drawn.bboxes();
    decompose_into(merged, merged_rects, merged_start);
    let figure_rects = |f: u32| {
        &merged_rects[merged_start[f as usize] as usize..merged_start[f as usize + 1] as usize]
    };
    // Each drawn host polygon lies in exactly one merged figure.
    let by_figure = SortedRects::new(
        (0..u32::try_from(merged.len()).expect("a layer indexes polygons with a u32"))
            .flat_map(|f| figure_rects(f).iter().map(move |&r| (r, f)))
            .collect(),
    );
    let figure_of: Vec<Option<u32>> = (0..u32::try_from(host_rects.len())
        .expect("a layer indexes polygons with a u32"))
        .map(|h| {
            let &first = host_rects.of(h).first()?;
            by_figure.overlapping(first).next().map(|(_, f)| f)
        })
        .collect();

    let limit = Measurement::Length(limit);
    let mut examined = 0u64;
    for poly in 0..u32::try_from(inner_rects.len()).expect("a layer indexes polygons with a u32") {
        let inner = inner_rects.row[poly as usize];
        let inner_box = inner_boxes[poly as usize];
        let mine = inner_rects.of(poly);
        let area = covered_area(mine);
        let on = |wide: &SortedRects<()>| {
            let covered = mine.iter().flat_map(|&r| wide.overlapping(r));
            covered.fold(DbuArea::new(0), |sum, (clip, ())| sum + clip.area()) == area
        };
        if from.as_ref().is_some_and(|wide| !on(wide)) || below.as_ref().is_some_and(on) {
            continue;
        }
        examined += 1;
        let lo = pairs.partition_point(|&(a, _)| a < inner);
        let hi = pairs.partition_point(|&(a, _)| a <= inner);
        // Best host; `Reverse` breaks a tie toward the lowest row.
        let mut acc = (UNHOSTED, Reverse(u32::MAX), None);
        for &(_, candidate) in &pairs[lo..hi] {
            let h = host_rects.poly_of_row[(candidate.0 - host_first) as usize];
            let Some(figure) = figure_of[h as usize] else {
                continue;
            };
            let host = host_rects.row[h as usize];
            let theirs = figure_rects(figure);
            let covered = mine
                .iter()
                .fold(DbuArea::new(0), |sum, &r| sum + clipped_area(theirs, r));
            if covered != area {
                continue;
            }
            let (value, at) = enclosure_of(drawn.get(poly), mine, merged.get(figure), mode);
            // A full-width reading is a maximum: the best host has the least.
            let score = if mode == Mode::FullWidth {
                -value.raw()
            } else {
                value.raw()
            };
            acc = acc.max((score, Reverse(host.0), at));
        }
        let (best, Reverse(host), at) = acc;
        let hosted = best > UNHOSTED;
        if mode == Mode::FullWidth {
            // An unhosted inner is `must_be_inside`'s; a host spanned is met.
            if !hosted || best == 0 {
                continue;
            }
            let measured = Measurement::Length(Dbu::new_unchecked((-best).min(MAX_ABS_DBU)));
            out.push(Violation {
                rule,
                layer: inner_layer,
                severity: Severity::Error,
                at: at.unwrap_or_else(|| centre(inner_box)),
                measured,
                limit: Measurement::Length(Dbu::new_unchecked(0)),
                shapes: (inner, Some(PolyId(host))),
            });
            continue;
        }
        let measured = Measurement::Length(Dbu::new_unchecked(best.clamp(0, MAX_ABS_DBU)));
        if !measured.violates(limit, LimitSense::Minimum) {
            continue;
        }
        let at = match at {
            Some(at) if hosted => at,
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
    (Outcome::Ran, examined)
}

/// The part of `host` (its rectangles) that `held` (rectangles) grown by
/// `by` with square corners does not cover, or `Err` for a failed boolean.
fn beyond(host: &[Bbox], held: &[Bbox], by: i64) -> Result<ValidatedLayer, BooleanError> {
    let grow = |v: Dbu, d: i64| Dbu::new_unchecked((v.raw() + d).clamp(-MAX_ABS_DBU, MAX_ABS_DBU));
    let grown: Vec<Bbox> = held
        .iter()
        .map(|r| Bbox {
            xlo: grow(r.xlo, -by),
            ylo: grow(r.ylo, -by),
            xhi: grow(r.xhi, by),
            yhi: grow(r.yhi, by),
        })
        .collect();
    let mut out = ValidatedLayer::default();
    subtraction_into(&rects_layer(host)?, &rects_layer(&grown)?, &mut out)?;
    Ok(out)
}

/// Max enclosure: each merged outer figure holding inner figures must lie
/// inside their union grown by `limit` (square corners). One violation per
/// offending figure, at its part beyond the limit, measuring the least whole
/// growth that covers it (a binary search over growths). `examined` counts
/// the outer figures that hold an inner one.
pub(crate) fn max_enclosure(
    store: &GeometryStore,
    rule: StrId,
    (outer, inner): (LayerId, LayerId),
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let (Some(inner_figures), Some(outer_figures)) =
        (merged(store, inner, s), merged(store, outer, s))
    else {
        return REFUSED;
    };
    let (inner_rects, outer_rects) = (rects_of(&inner_figures), rects_of(&outer_figures));
    let figure = |rects: &(Vec<Bbox>, Vec<u32>), f: usize| -> Vec<Bbox> {
        rects.0[rects.1[f] as usize..rects.1[f + 1] as usize].to_vec()
    };
    // Each outer figure's held inner rectangles.
    let mut held: Vec<Vec<Bbox>> = vec![Vec::new(); outer_figures.len()];
    for (i, host) in hosts(&inner_rects, &outer_rects).into_iter().enumerate() {
        if let Some(host) = host {
            held[host as usize].extend(figure(&inner_rects, i));
        }
    }
    let drawn = s.validated.get(store, outer).expect("merged above");
    s.rects_a.build(store, outer, drawn);
    let owners = owners_of(&outer_figures, &s.rects_a);
    let mut examined = 0u64;
    for (f, mine) in held.iter().enumerate().filter(|(_, mine)| !mine.is_empty()) {
        examined += 1;
        let host = figure(&outer_rects, f);
        let Ok(excess) = beyond(&host, mine, limit.raw()) else {
            return REFUSED;
        };
        if excess.is_empty() {
            continue;
        }
        // The least growth that covers the host: past `limit`, and at most
        // the host's own span, which covers it from any point inside it.
        let span = host.iter().fold(Bbox::EMPTY, |acc, &r| acc.union(r));
        let (mut lo, mut hi) = (
            limit.raw(),
            (span.xhi - span.xlo).raw().max((span.yhi - span.ylo).raw()),
        );
        while hi - lo > 1 {
            let at = lo + (hi - lo) / 2;
            match beyond(&host, mine, at) {
                Ok(left) if left.is_empty() => hi = at,
                Ok(_) => lo = at,
                Err(_) => return REFUSED,
            }
        }
        let (rects, start) = rects_of(&excess);
        out.push(Violation {
            rule,
            layer: outer,
            severity: Severity::Error,
            at: inside_point(&(rects, start), 0),
            measured: Measurement::Length(Dbu::new_unchecked(hi)),
            limit: Measurement::Length(limit),
            shapes: (owners[f], None),
        });
    }
    (Outcome::Ran, examined)
}

/// The side of a gate edge `a -> b` the gate does not lie on: material is on
/// the left of travel.
fn outward(a: Point, b: Point) -> Side {
    match (a.x == b.x, b.x > a.x, b.y > a.y) {
        (false, true, _) => Side::Bottom,
        (false, false, _) => Side::Top,
        (true, _, true) => Side::Right,
        (true, _, false) => Side::Left,
    }
}

/// The one-unit strip just past `edge` (a degenerate box) on `side`.
fn just_past(edge: Bbox, side: Side) -> Bbox {
    let one = Dbu::new_unchecked(1);
    match side {
        Side::Left => Bbox {
            xlo: edge.xlo - one,
            ..edge
        },
        Side::Right => Bbox {
            xhi: edge.xhi + one,
            ..edge
        },
        Side::Bottom => Bbox {
            ylo: edge.ylo - one,
            ..edge
        },
        Side::Top => Bbox {
            yhi: edge.yhi + one,
            ..edge
        },
    }
}

/// How far `line` runs past one figure of `line ∩ reference` (a gate), and
/// where to report it. The line crosses the reference along an axis when
/// every gate edge facing along it lies on the reference's boundary; each
/// such edge measures how far the line runs on past it (projection metric,
/// 0 where the line stops flush). The gate measures the least over its
/// crossed axes, the first side on a tie; crossed along neither axis, the
/// line ends inside the reference: 0, at the gate's centre.
fn gate_extension(
    gate: PolygonRef<'_>,
    line: PolygonRef<'_>,
    reference: &SortedRects<PolyId>,
) -> (Dbu, Point) {
    // Per axis (vertical edges, horizontal edges): still crossed, and the
    // shortest run past one of its edges.
    let mut crossed = [true; 2];
    let mut best: [Option<(Dbu, Side, Bbox)>; 2] = [None; 2];
    for (a, b) in poly_edges(gate) {
        let edge = Bbox::point(a.x, a.y).include(b.x, b.y);
        let side = outward(a, b);
        let axis = usize::from(a.y == b.y);
        if reference
            .overlapping(just_past(edge, side))
            .next()
            .is_some()
        {
            crossed[axis] = false;
            continue;
        }
        let (run, _) = strips(edge, line)[side as usize];
        if best[axis].is_none_or(|(d, s, _)| (run, side) < (d, s)) {
            best[axis] = Some((run, side, edge));
        }
    }
    (0..2)
        .filter(|&axis| crossed[axis])
        .filter_map(|axis| best[axis])
        .min_by_key(|&(run, side, _)| (run, side))
        .map_or(
            (Dbu::new_unchecked(0), centre(gate.bbox())),
            |(run, side, edge)| (run, side_midpoint(edge, run, side)),
        )
}

/// Min extension of `layer` past `reference`, per gate: each figure of the
/// area the merged layers share, measured by [`gate_extension`] and reported
/// on the lowest drawn row of each layer under it. Shapes that only touch make
/// no gate. `examined` counts gates.
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
    let Some(lines) = merged(store, layer, s) else {
        return REFUSED;
    };
    let Some(drawn_ref) = s.validated.get(store, reference) else {
        return REFUSED;
    };
    s.rects_b.build(store, reference, drawn_ref);
    if intersection_into(&lines, drawn_ref, &mut s.layer_out).is_err() {
        return REFUSED;
    }
    let drawn = s.validated.get(store, layer).expect("merged above");
    s.rects_a.build(store, layer, drawn);
    let Scratch {
        layer_out: gates,
        rects,
        rect_start,
        rects_a,
        rects_b,
        ..
    } = s;
    // Each gate lies in exactly one line figure.
    let (mut line_rects, mut line_start) = (Vec::new(), Vec::new());
    decompose_into(&lines, &mut line_rects, &mut line_start);
    let line_of = SortedRects::new(
        line_start
            .windows(2)
            .zip(0u32..)
            .flat_map(|(span, f)| {
                line_rects[span[0] as usize..span[1] as usize]
                    .iter()
                    .map(move |&r| (r, f))
            })
            .collect(),
    );
    let refs = SortedRects::new(rects_b.labelled());
    decompose_into(gates, rects, rect_start);
    let owners = owners_of(gates, rects_a)
        .into_iter()
        .zip(owners_of(gates, rects_b));
    for (g, (line_row, ref_row)) in (0..).zip(owners) {
        let inside = rects[rect_start[g as usize] as usize];
        let (_, f) = line_of
            .overlapping(inside)
            .next()
            .expect("a gate lies on its line");
        let (measured, at) = gate_extension(gates.get(g), lines.get(f), &refs);
        if measured < limit {
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at,
                measured: Measurement::Length(measured),
                limit: Measurement::Length(limit),
                shapes: (line_row, Some(ref_row)),
            });
        }
    }
    (Outcome::Ran, gates.len() as u64)
}

/// Every concave corner of `poly`, holes included, into `out`: a right turn
/// where the material lies on the left of travel. A corner a figure meets
/// itself at is two.
fn concave_corners(poly: PolygonRef<'_>, out: &mut Vec<Point>) {
    for ring in std::iter::once(poly.outer()).chain(poly.holes()) {
        let (xs, ys) = ring.coords();
        let n = xs.len();
        for i in 0..n {
            let at = |k: usize| (i128::from(xs[k].raw()), i128::from(ys[k].raw()));
            let ((px, py), (vx, vy), (nx, ny)) = (at((i + n - 1) % n), at(i), at((i + 1) % n));
            if (vx - px) * (ny - vy) - (vy - py) * (nx - vx) < 0 {
                out.push(Point { x: xs[i], y: ys[i] });
            }
        }
    }
}

/// A gate's shape (sky130 poly.10, poly.11): each concave corner of the area
/// the merged layers share that is a concave corner of `layer` (a bend) or,
/// with `of_reference`, of `reference` (an inner corner covered). Reported
/// at the corner on the lowest drawn rows under its gate. `examined` counts
/// gates.
pub(crate) fn gate_corner(
    store: &GeometryStore,
    rule: StrId,
    (layer, reference): (LayerId, LayerId),
    of_reference: bool,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let (Some(lines), Some(refs)) = (merged(store, layer, s), merged(store, reference, s)) else {
        return REFUSED;
    };
    let mut gates = ValidatedLayer::default();
    if intersection_into(&lines, &refs, &mut gates).is_err() {
        return REFUSED;
    }
    let mut corners = Vec::new();
    let of = if of_reference { &refs } else { &lines };
    for f in 0..u32::try_from(of.len()).expect("a layer indexes polygons with a u32") {
        concave_corners(of.get(f), &mut corners);
    }
    corners.sort_unstable();
    let drawn = s.validated.get(store, layer).expect("merged above");
    s.rects_a.build(store, layer, drawn);
    let drawn = s.validated.get(store, reference).expect("merged above");
    s.rects_b.build(store, reference, drawn);
    let owners = owners_of(&gates, &s.rects_a)
        .into_iter()
        .zip(owners_of(&gates, &s.rects_b));
    let mut own = Vec::new();
    for (g, (a_row, b_row)) in (0..).zip(owners) {
        own.clear();
        concave_corners(gates.get(g), &mut own);
        for &at in own.iter().filter(|p| corners.binary_search(p).is_ok()) {
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at,
                measured: Measurement::Count(1),
                limit: Measurement::Count(0),
                shapes: (a_row, Some(b_row)),
            });
        }
    }
    (Outcome::Ran, gates.len() as u64)
}

/// Min overlap: each figure of the area the merged layers share, measured as
/// `min_width` measures a figure (facing edges, and a diagonal neck under the
/// limit), on the lowest drawn row of each layer under it. `examined` counts
/// the figures.
pub(crate) fn overlap(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    b: LayerId,
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(merged_a) = merged(store, layer, s) else {
        return REFUSED;
    };
    let Some(drawn_b) = s.validated.get(store, b) else {
        return REFUSED;
    };
    s.rects_b.build(store, b, drawn_b);
    if intersection_into(&merged_a, drawn_b, &mut s.layer_out).is_err() {
        return REFUSED;
    }
    let drawn_a = s.validated.get(store, layer).expect("merged above");
    s.rects_a.build(store, layer, drawn_a);
    let owners = owners_of(&s.layer_out, &s.rects_a)
        .into_iter()
        .zip(owners_of(&s.layer_out, &s.rects_b));
    for (idx, (a_row, b_row)) in (0..).zip(owners) {
        let shared = s.layer_out.get(idx);
        let neck = narrowest_neck(shared, limit);
        let (measured, at) = narrowest_facing(shared, true, &mut s.facing)
            .into_iter()
            .chain(neck)
            .min_by_key(|&(gap, _)| gap)
            .expect("every validated polygon has a facing pair across its own material");
        if measured < limit {
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at,
                measured: Measurement::Length(measured),
                limit: Measurement::Length(limit),
                shapes: (a_row, Some(b_row)),
            });
        }
    }
    (Outcome::Ran, s.layer_out.len() as u64)
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
