//! Derived-layer operations past the three booleans: sizing, selection by
//! relation or measure, holes, extents, and edge layers.
//!
//! Data in: merged [`ValidatedLayer`]s (a boolean result, or a layer passed
//! through [`merge_into`]); edge layers as directed [`Seg`]s, material on the
//! left of travel. Data out: a merged layer (but [`extents_into`]: one box per
//! polygon, overlaps kept), or merged edges. Semantics follow `KLayout`'s
//! merged-polygon definitions. Exact on rectilinear and octilinear layers, but
//! where a boolean snaps a vertex that falls between grid points
//! ([`crate::boolean::union_into`]).

use crate::bbox::Bbox;
use crate::boolean::{subtraction_into, union_into, BooleanError};
use crate::ids::LayerId;
use crate::index::{cross_layer_pairs_into, SpatialIndex};
use crate::ops::{segments_intersect, Point, Seg};
use crate::rects::decompose_into;
use crate::store::GeometryStoreBuilder;
use crate::view::{validate_layer_into, validate_layer_with, Angles, PolygonRef, ValidatedLayer};
use crate::width::{narrowest_pair2, narrowest_width2, FacingScratch};
use crate::{narrow, Dbu};
use std::ops::RangeInclusive;

const ONLY: LayerId = LayerId(0);

/// `a` with overlapping and abutting polygons merged (`KLayout` merged semantics).
pub fn merge_into(a: &ValidatedLayer, out: &mut ValidatedLayer) -> Result<(), BooleanError> {
    union_into(a, &ValidatedLayer::default(), out)
}

/// Validate the builder's rings as one octilinear layer, then merge them.
fn merged(builder: GeometryStoreBuilder, out: &mut ValidatedLayer) -> Result<(), BooleanError> {
    let (store, _) = builder.finish(1);
    let mut raw = ValidatedLayer::default();
    validate_layer_with(&store, ONLY, Angles::Octilinear, &mut raw)?;
    merge_into(&raw, out)
}

fn push_rect(builder: &mut GeometryStoreBuilder, r: Bbox) {
    builder.push(
        ONLY,
        &[r.xlo, r.xhi, r.xhi, r.xlo],
        &[r.ylo, r.ylo, r.yhi, r.yhi],
    );
}

/// `r` grown by `dx` left and right and `dy` above and below, refused past
/// the coordinate domain.
fn grown(r: Bbox, dx: i64, dy: i64) -> Result<Bbox, BooleanError> {
    let at = |v: Dbu, by: i64| Dbu::new(v.raw() + by).ok_or(BooleanError::OutOfRange);
    Ok(Bbox {
        xlo: at(r.xlo, -dx)?,
        ylo: at(r.ylo, -dy)?,
        xhi: at(r.xhi, dx)?,
        yhi: at(r.yhi, dy)?,
    })
}

/// `KLayout` `sized(dx, dy)` (`sized(d)` is `(d, d)`): the Minkowski sum with
/// the box `[-dx, dx] x [-dy, dy]` when both are at least 0, the erosion by
/// `[dx, -dx] x [dy, -dy]` when both are at most 0. A part no wider than
/// `2|dx|` across x, or `2|dy|` across y, shrinks away.
///
/// # Panics
///
/// When `dx` and `dy` differ in sign: one axis grown and the other shrunk is
/// not one Minkowski operation, and the deck refuses it.
///
/// On a layer with edges at 45 degrees the box moves a diagonal edge `dx` in
/// x and `dy` in y, and keeps every edge octilinear and every vertex on the
/// grid (a crossing between grid points is snapped as
/// [`crate::boolean::union_into`] states). `KLayout`'s `sized` moves every
/// edge along its normal instead, so on a diagonal edge the two differ; this
/// is the definition `docs/deck.md` gives.
pub fn sized_into(
    a: &ValidatedLayer,
    dx: Dbu,
    dy: Dbu,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    let (dx, dy) = (dx.raw(), dy.raw());
    assert!(
        dx.signum() * dy.signum() >= 0,
        "sizing grows or shrinks both axes, never one of each"
    );
    if dx >= 0 && dy >= 0 {
        return grow_into(a, dx, dy, out);
    }
    // Erosion is the complement of growing the complement, within a frame far
    // enough out that its own border does not erode `a`.
    let Some(extent) = a.bboxes().iter().copied().reduce(Bbox::union) else {
        return merge_into(a, out);
    };
    let mut frame = GeometryStoreBuilder::with_capacity(1, 4);
    push_rect(&mut frame, grown(extent, -dx, -dy)?);
    let mut frame_layer = ValidatedLayer::default();
    merged(frame, &mut frame_layer)?;
    let mut outside = ValidatedLayer::default();
    subtraction_into(&frame_layer, a, &mut outside)?;
    let mut eaten = ValidatedLayer::default();
    grow_into(&outside, -dx, -dy, &mut eaten)?;
    subtraction_into(a, &eaten, out)
}

/// `a` grown by the box `[-dx, dx] x [-dy, dy]`, `dx, dy >= 0`: exact, since
/// the Minkowski sum distributes over union. A rectilinear layer is the union
/// of its rectangles grown; any other is itself together with each boundary
/// edge swept by the box, since a point the sum adds lies within the box of
/// some boundary point.
fn grow_into(
    a: &ValidatedLayer,
    dx: i64,
    dy: i64,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    if !a.is_rectilinear() {
        let mut builder = GeometryStoreBuilder::with_capacity(0, 0);
        for idx in 0..narrow(a.len()) {
            // Outer and holes as rows: every ring adds its winding to the union.
            for ring in a.poly_rings(idx) {
                let (xs, ys) = ring.coords();
                builder.push(ONLY, xs, ys);
            }
            if dx == 0 && dy == 0 {
                continue;
            }
            for (p, q) in crate::width::poly_edges(a.get(idx)) {
                let (xs, ys) = swept_box(p, q, dx, dy)?;
                builder.push(ONLY, &xs, &ys);
            }
        }
        return merged(builder, out);
    }
    let (mut rects, mut start) = (Vec::new(), Vec::new());
    decompose_into(a, &mut rects, &mut start);
    let mut builder = GeometryStoreBuilder::with_capacity(rects.len(), 4 * rects.len());
    for &r in &rects {
        push_rect(&mut builder, grown(r, dx, dy)?);
    }
    merged(builder, out)
}

/// The octilinear edge `p`-`q` swept by the box `[-dx, dx] x [-dy, dy]`, not
/// both 0: its convex hull, counter-clockwise; a box for an axis-parallel
/// edge, else a hexagon (a parallelogram when `dx` or `dy` is 0). Refused past
/// the coordinate domain.
fn swept_box(p: Point, q: Point, dx: i64, dy: i64) -> Result<(Vec<Dbu>, Vec<Dbu>), BooleanError> {
    let (l, r) = if (p.x, p.y) <= (q.x, q.y) {
        (p, q)
    } else {
        (q, p)
    };
    let (lx, ly, rx, ry) = (l.x.raw(), l.y.raw(), r.x.raw(), r.y.raw());
    let mut corners: Vec<(i64, i64)> = if lx == rx || ly == ry {
        let (x0, x1) = (lx.min(rx) - dx, lx.max(rx) + dx);
        let (y0, y1) = (ly.min(ry) - dy, ly.max(ry) + dy);
        vec![(x0, y0), (x1, y0), (x1, y1), (x0, y1)]
    } else if ry > ly {
        // Rising: `l` is the lower end.
        vec![
            (lx - dx, ly - dy),
            (lx + dx, ly - dy),
            (rx + dx, ry - dy),
            (rx + dx, ry + dy),
            (rx - dx, ry + dy),
            (lx - dx, ly + dy),
        ]
    } else {
        // Falling: `l` is the upper end.
        vec![
            (lx - dx, ly - dy),
            (rx - dx, ry - dy),
            (rx + dx, ry - dy),
            (rx + dx, ry + dy),
            (lx + dx, ly + dy),
            (lx - dx, ly + dy),
        ]
    };
    // A zero `dx` or `dy` folds two corners of the hexagon into one.
    corners.dedup();
    while corners.len() > 1 && corners.first() == corners.last() {
        corners.pop();
    }
    let at = |v: i64| Dbu::new(v).ok_or(BooleanError::OutOfRange);
    let xs = corners
        .iter()
        .map(|&(x, _)| at(x))
        .collect::<Result<_, _>>()?;
    let ys = corners
        .iter()
        .map(|&(_, y)| at(y))
        .collect::<Result<_, _>>()?;
    Ok((xs, ys))
}

/// `KLayout` `holes`: every hole of `a` as a filled polygon, merged, so a hole
/// holding an island covers the island too.
pub fn holes_into(a: &ValidatedLayer, out: &mut ValidatedLayer) -> Result<(), BooleanError> {
    let mut builder = GeometryStoreBuilder::with_capacity(0, 0);
    let (mut xs, mut ys) = (Vec::new(), Vec::new());
    for idx in 0..narrow(a.len()) {
        for hole in a.get(idx).holes() {
            let (hx, hy) = hole.coords();
            xs.clear();
            ys.clear();
            // Holes wind CW; reversed they are outers.
            xs.extend(hx.iter().rev());
            ys.extend(hy.iter().rev());
            builder.push(ONLY, &xs, &ys);
        }
    }
    merged(builder, out)
}

/// `KLayout` `extents`: the bounding box of each polygon of `a`, one polygon
/// per box. Boxes that overlap stay apart, as `KLayout`'s do ("The boxes will
/// not be merged"); a later operation merges them like any operand.
pub fn extents_into(a: &ValidatedLayer, out: &mut ValidatedLayer) -> Result<(), BooleanError> {
    let mut builder = GeometryStoreBuilder::with_capacity(a.len(), 4 * a.len());
    for &b in a.bboxes() {
        push_rect(&mut builder, b);
    }
    let (store, _) = builder.finish(1);
    validate_layer_into(&store, ONLY, out)?;
    Ok(())
}

/// `KLayout` `with_area`: polygons whose area in square grid units, holes
/// excluded, is in `range`. Exact for an octilinear polygon too, whose area
/// can be a half unit: it is compared doubled.
pub fn with_area_into(a: &ValidatedLayer, range: RangeInclusive<i128>, out: &mut ValidatedLayer) {
    let (lo, hi) = (
        range.start().saturating_mul(2),
        range.end().saturating_mul(2),
    );
    let keep: Vec<bool> = (0..narrow(a.len()))
        .map(|idx| {
            let twice: i128 = a.poly_rings(idx).map(|r| r.area2().raw()).sum();
            (lo..=hi).contains(&twice)
        })
        .collect();
    a.select_into(&keep, out);
}

/// Polygons whose narrowest width, as the `width` rule measures it (diagonal
/// necks count), has its square in `range`, in square grid units
/// ([`narrowest_width2`]). Squared, a neck is a whole number, so a strict
/// bound is exact as an inclusive one: `> 70` is `4901..` here, and a
/// `√5000` neck (70.7) is in it.
///
/// # Errors
///
/// On a layer with 45-degree edges the width is
/// [`crate::width::narrowest_pair2`]'s, whose square can be a half unit: it
/// is in the range when its floor is at least the lower bound and its
/// ceiling at most the upper, which is exact for inclusive bounds. A strict
/// bound the deck turned inclusive (`> n` as `>= n² + 1`) misses a width
/// whose square is exactly `n² + ½` (`99/√2` against `> 70nm`).
pub fn with_width_into(a: &ValidatedLayer, range: RangeInclusive<i128>, out: &mut ValidatedLayer) {
    let mut scratch = FacingScratch::default();
    let far = Dbu::new_unchecked(crate::MAX_ABS_DBU);
    let keep: Vec<bool> = (0..narrow(a.len()))
        .map(|idx| {
            let poly = a.get(idx);
            if a.is_rectilinear() {
                return range.contains(&narrowest_width2(poly, &mut scratch).raw());
            }
            narrowest_pair2(poly, true, far).is_some_and(|(twice, _)| {
                twice / 2 >= *range.start() && (twice + 1) / 2 <= *range.end()
            })
        })
        .collect();
    a.select_into(&keep, out);
}

/// `KLayout` `with_bbox_max` (`longer`) or `with_bbox_min`: polygons whose
/// bounding box's longer, or shorter, side in grid units lies in `range`
/// ("the maximum dimension of the bounding box … either the width or height,
/// whichever is larger"). For a straight feature, the longer side is its
/// length.
pub fn with_bbox_into(
    a: &ValidatedLayer,
    longer: bool,
    range: RangeInclusive<i128>,
    out: &mut ValidatedLayer,
) {
    let keep: Vec<bool> = (0..narrow(a.len()))
        .map(|idx| {
            let b = a.get(idx).bbox();
            let (w, h) = (b.width().raw(), b.height().raw());
            range.contains(&i128::from(if longer { w.max(h) } else { w.min(h) }))
        })
        .collect();
    a.select_into(&keep, out);
}

/// `KLayout` `rectangles` and `squares` (`keep`), or `non_rectangles` and
/// `non_squares`: the polygons of `a` that are, or are not, one axis-aligned
/// box with no hole, and with `square` a box with equal sides. `a` must be
/// merged: then a rectangle drawn as abutting pieces is one rectangle, and two
/// boxes meeting only at a corner are one polygon that is none.
pub fn rectangles_into(a: &ValidatedLayer, square: bool, keep: bool, out: &mut ValidatedLayer) {
    let keep: Vec<bool> = (0..narrow(a.len()))
        .map(|idx| {
            let poly = a.get(idx);
            let b = poly.bbox();
            // A merged ring has no collinear vertex: four corners, every edge
            // horizontal or vertical, are a box (a diamond has four too).
            let (xs, ys) = poly.outer().coords();
            let axis = (0..xs.len()).all(|i| {
                let j = (i + 1) % xs.len();
                xs[i] == xs[j] || ys[i] == ys[j]
            });
            let boxed = xs.len() == 4 && axis && poly.holes().next().is_none();
            (boxed && (!square || b.width() == b.height())) == keep
        })
        .collect();
    a.select_into(&keep, out);
}

/// Every `(i, j)` whose boxes share a point, `i` into `a`, `j` into `b`.
fn box_pairs(a: &[Bbox], b: &[Bbox], out: &mut Vec<(u32, u32)>) {
    out.clear();
    if a.is_empty() || b.is_empty() {
        return;
    }
    let mut builder = GeometryStoreBuilder::with_capacity(a.len() + b.len(), 0);
    for (layer, boxes) in [(LayerId(0), a), (LayerId(1), b)] {
        for r in boxes {
            builder.push(layer, &[r.xlo, r.xhi], &[r.ylo, r.yhi]);
        }
    }
    let (store, _) = builder.finish(2);
    let (mut ia, mut ib) = (SpatialIndex::default(), SpatialIndex::default());
    SpatialIndex::build_into(&store, LayerId(0), &mut ia);
    SpatialIndex::build_into(&store, LayerId(1), &mut ib);
    let mut pairs = Vec::new();
    cross_layer_pairs_into(&store, &ia, &ib, Dbu::new_unchecked(0), &mut pairs);
    let first_b = narrow(a.len());
    out.extend(pairs.iter().map(|&(p, q)| (p.0, q.0 - first_b)));
}

/// Every edge of a polygon, holes included, as segments.
fn poly_segs(poly: PolygonRef<'_>) -> impl Iterator<Item = Seg> + '_ {
    crate::width::poly_edges(poly).map(|(a, b)| Seg { a, b })
}

/// Even-odd inside test for the point `(px / scale, py / scale)`, which must
/// lie on no ring: counts the edges a `+x` ray crosses, half-open in y, exactly
/// at any angle.
fn inside_scaled<'a>(
    polys: impl Iterator<Item = PolygonRef<'a>>,
    px: i64,
    py: i64,
    scale: i64,
) -> bool {
    let (k, px, py) = (i128::from(scale), i128::from(px), i128::from(py));
    let mut inside = false;
    for poly in polys {
        for seg in poly_segs(poly) {
            let (ax, ay) = (i128::from(seg.a.x.raw()) * k, i128::from(seg.a.y.raw()) * k);
            let (bx, by) = (i128::from(seg.b.x.raw()) * k, i128::from(seg.b.y.raw()) * k);
            if (ay > py) != (by > py) {
                // The point's side of the edge: left of an upward edge, or
                // right of a downward one, is where the ray crosses it.
                let side = (bx - ax) * (py - ay) - (by - ay) * (px - ax);
                if (side > 0) == (by > ay) {
                    inside = !inside;
                }
            }
        }
    }
    inside
}

/// A point strictly inside a polygon's material, at eight times scale: one
/// step into the material from a convex corner of its outer ring, along the
/// bisector of the corner, trying the corners lowest first. On the octilinear
/// grid no edge but those through a vertex passes within `1/√2` of it, so a
/// step of at most `√8 / 8` stays in the corner; the lowest, then leftmost,
/// corner is convex, and only a hole touching it there can make it try the
/// next.
///
/// # Panics
///
/// On a polygon with no such corner, which validation rules out.
pub fn interior_point8(poly: PolygonRef<'_>) -> (i64, i64) {
    let (xs, ys) = poly.outer().coords();
    let n = xs.len();
    let mut corners: Vec<usize> = (0..n).collect();
    corners.sort_unstable_by_key(|&i| (ys[i], xs[i]));
    for v in corners {
        let toward = |to: usize| {
            (
                (xs[to] - xs[v]).raw().signum(),
                (ys[to] - ys[v]).raw().signum(),
            )
        };
        let (back, on) = (toward((v + n - 1) % n), toward((v + 1) % n));
        // Convex: turning left from the way in (`-back`) to the way out.
        if back.1 * on.0 - back.0 * on.1 <= 0 {
            continue;
        }
        let probe = (
            8 * xs[v].raw() + back.0 + on.0,
            8 * ys[v].raw() + back.1 + on.1,
        );
        if inside_scaled(std::iter::once(poly), probe.0, probe.1, 8) {
            return probe;
        }
    }
    panic!("a validated polygon has a convex corner with its material beside it")
}

/// Whether the point `(px / scale, py / scale)`, which must lie on none of
/// its rings, is in a polygon's material: inside its outer and no hole.
/// Exact at any angle.
pub fn contains_scaled(poly: PolygonRef<'_>, px: i64, py: i64, scale: i64) -> bool {
    inside_scaled(std::iter::once(poly), px, py, scale)
}

/// Whether two closed polygons share a point: their boundaries meet, or one
/// lies inside the other.
fn polys_meet(p: PolygonRef<'_>, q: PolygonRef<'_>) -> bool {
    if poly_segs(p).any(|s| poly_segs(q).any(|t| segments_intersect(s, t))) {
        return true;
    }
    // No boundary contact: a vertex of either is off the other's rings.
    let vertex = |poly: PolygonRef<'_>| {
        let (xs, ys) = poly.outer().coords();
        (2 * xs[0].raw(), 2 * ys[0].raw())
    };
    let (px, py) = vertex(p);
    let (qx, qy) = vertex(q);
    inside_scaled(std::iter::once(q), px, py, 2) || inside_scaled(std::iter::once(p), qx, qy, 2)
}

/// `KLayout` `interacting` (`keep`) / `not_interacting` (`!keep`): polygons of
/// `a` that touch or overlap `b`; a shared corner counts.
// ponytail: pairwise edge test, O(edges(p) * edges(q)) per candidate pair; a
// per-pair sweep if huge merged polygons make this slow.
pub fn interacting_into(
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    keep: bool,
    out: &mut ValidatedLayer,
) {
    let mut pairs = Vec::new();
    box_pairs(a.bboxes(), b.bboxes(), &mut pairs);
    let mut hit = vec![!keep; a.len()];
    for &(i, j) in &pairs {
        if polys_meet(a.get(i), b.get(j)) {
            hit[i as usize] = keep;
        }
    }
    a.select_into(&hit, out);
}

/// Per polygon of `a`: `false` when it holds part of `parts` (a subset of `a`
/// by area), else `true`.
fn free_of(a: &ValidatedLayer, parts: &ValidatedLayer) -> Vec<bool> {
    let mut free = vec![true; a.len()];
    // One point inside each part: it lies inside exactly one polygon of `a`.
    let probes: Vec<(i64, i64)> = (0..narrow(parts.len()))
        .map(|i| interior_point8(parts.get(i)))
        .collect();
    let mut pairs = Vec::new();
    box_pairs(parts.bboxes(), a.bboxes(), &mut pairs);
    for &(r, p) in &pairs {
        let (x8, y8) = probes[r as usize];
        if inside_scaled(std::iter::once(a.get(p)), x8, y8, 8) {
            free[p as usize] = false;
        }
    }
    free
}

/// `KLayout` `inside`: polygons of `a` covered by `b`; touching `b`'s boundary
/// from inside is covered.
pub fn inside_into(
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    let mut rest = ValidatedLayer::default();
    subtraction_into(a, b, &mut rest)?;
    a.select_into(&free_of(a, &rest), out);
    Ok(())
}

/// `KLayout` `outside`: polygons of `a` sharing no area with `b`; touching is outside.
pub fn outside_into(
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    overlapping_into(a, b, false, out)
}

/// `KLayout` `overlapping` (`keep`): polygons of `a` sharing area with `b`;
/// touching is not overlapping. `!keep` is [`outside_into`].
pub fn overlapping_into(
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    keep: bool,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    let flags: Vec<bool> = overlapping_flags(a, b)?
        .into_iter()
        .map(|hit| hit == keep)
        .collect();
    a.select_into(&flags, out);
    Ok(())
}

/// Per polygon of `a`, in order: whether it shares area with `b`, as
/// [`overlapping_into`] selects. Touching is not sharing.
pub fn overlapping_flags(
    a: &ValidatedLayer,
    b: &ValidatedLayer,
) -> Result<Vec<bool>, BooleanError> {
    let mut common = ValidatedLayer::default();
    crate::boolean::intersection_into(a, b, &mut common)?;
    Ok(free_of(a, &common).into_iter().map(|free| !free).collect())
}

/// `KLayout` `covering` (`keep`) / `not_covering` (`!keep`): polygons of `a`
/// that hold a whole polygon of `b`, which may touch `a`'s boundary from
/// inside ([`inside_into`] with the operands swapped).
pub fn covering_into(
    a: &ValidatedLayer,
    b: &ValidatedLayer,
    keep: bool,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    let mut held = ValidatedLayer::default();
    inside_into(b, a, &mut held)?;
    // Each held polygon is connected and inside `a`, so it lies in one polygon of `a`.
    let flags: Vec<bool> = free_of(a, &held)
        .into_iter()
        .map(|free| free != keep)
        .collect();
    a.select_into(&flags, out);
    Ok(())
}

// ---- edge layers ----

/// One octilinear edge on its line. `dir` is the line's direction: 0
/// horizontal, 1 vertical, 2 rising at 45 degrees, 3 falling; `pos` its
/// intercept (`y`, `x`, `y - x`, `y + x`); `lo < hi` the span of the line's
/// parameter (`x`, `y`, `x`, `x`); `forward` whether it travels toward `hi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Run {
    dir: u8,
    pos: i64,
    lo: i64,
    hi: i64,
    forward: bool,
}

/// # Panics
///
/// On an edge at an angle other than a multiple of 45 degrees: an edge layer
/// is derived from validated octilinear polygons.
fn run_of(s: Seg) -> Run {
    let (ax, ay, bx, by) = (s.a.x.raw(), s.a.y.raw(), s.b.x.raw(), s.b.y.raw());
    let (dx, dy) = (bx - ax, by - ay);
    assert!(
        dx == 0 || dy == 0 || dx.abs() == dy.abs(),
        "an edge layer holds octilinear edges"
    );
    let (dir, pos, from, to) = if dy == 0 {
        (0, ay, ax, bx)
    } else if dx == 0 {
        (1, ax, ay, by)
    } else if dx == dy {
        (2, ay - ax, ax, bx)
    } else {
        (3, ay + ax, ax, bx)
    };
    Run {
        dir,
        pos,
        lo: from.min(to),
        hi: from.max(to),
        forward: to > from,
    }
}

/// The point at parameter `t` on the line `dir`/`pos`, all scaled by the
/// same factor.
const fn on_line(dir: u8, pos: i64, t: i64) -> (i64, i64) {
    match dir {
        0 => (t, pos),
        1 => (pos, t),
        2 => (t, t + pos),
        _ => (t, pos - t),
    }
}

fn seg_of(r: Run) -> Seg {
    let (from, to) = if r.forward {
        (r.lo, r.hi)
    } else {
        (r.hi, r.lo)
    };
    let point = |along: i64| {
        let (x, y) = on_line(r.dir, r.pos, along);
        Point {
            x: Dbu::new_unchecked(x),
            y: Dbu::new_unchecked(y),
        }
    };
    Seg {
        a: point(from),
        b: point(to),
    }
}

/// Where two runs' lines cross, as twice the parameter along each, or `None`
/// for parallel lines. Exact: twice a crossing of octilinear lines through
/// grid points is an integer.
fn crossing2(r: Run, t: Run) -> Option<(i64, i64)> {
    // Each line as `a·x + b·y = c`.
    let line = |run: Run| {
        let c = i128::from(run.pos);
        match run.dir {
            0 => (0, 1, c),
            1 => (1, 0, c),
            2 => (-1, 1, c),
            _ => (1, 1, c),
        }
    };
    let ((a1, b1, c1), (a2, b2, c2)) = (line(r), line(t));
    let det = a1 * b2 - a2 * b1;
    if det == 0 {
        return None;
    }
    // `det` is ±1 or ±2, so twice each coordinate divides exactly.
    let (x2, y2) = (2 * (c1 * b2 - c2 * b1) / det, 2 * (a1 * c2 - a2 * c1) / det);
    let along = |run: Run| {
        let v = if run.dir == 1 { y2 } else { x2 };
        i64::try_from(v).expect("a crossing of in-domain lines is in range")
    };
    Some((along(r), along(t)))
}

/// Runs to merged segments: collinear pieces of one direction that touch or
/// overlap become one, zero-length ones go.
fn emit_runs(runs: &mut Vec<Run>, out: &mut Vec<Seg>) {
    runs.retain(|r| r.lo < r.hi);
    runs.sort_unstable_by_key(|r| (r.dir, r.pos, r.forward, r.lo));
    out.clear();
    let mut at = 0;
    while at < runs.len() {
        let mut cur = runs[at];
        at += 1;
        while at < runs.len()
            && (runs[at].dir, runs[at].pos, runs[at].forward) == (cur.dir, cur.pos, cur.forward)
            && runs[at].lo <= cur.hi
        {
            cur.hi = cur.hi.max(runs[at].hi);
            at += 1;
        }
        out.push(seg_of(cur));
    }
}

/// `KLayout` `edges`: the boundary of every polygon of `a`, material on the left.
pub fn edges_into(a: &ValidatedLayer, out: &mut Vec<Seg>) {
    let mut runs: Vec<Run> = (0..narrow(a.len()))
        .flat_map(|idx| poly_segs(a.get(idx)))
        .map(run_of)
        .collect();
    emit_runs(&mut runs, out);
}

/// How an edge boolean combines its operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeOp {
    /// Parts of `a` coincident with `b`.
    And,
    /// Parts of `a` not coincident with `b`.
    Not,
    /// `a`, plus the parts of `b` not coincident with `a`.
    Or,
}

/// Parts of `a` that `b` covers (`covered`) or does not, direction ignored.
fn split_runs(a: &[Run], b: &[Run], covered: bool, out: &mut Vec<Run>) {
    // `b`'s coverage per line, undirected, merged and sorted.
    let mut cover: Vec<(u8, i64, i64, i64)> =
        b.iter().map(|r| (r.dir, r.pos, r.lo, r.hi)).collect();
    cover.sort_unstable();
    let mut merged: Vec<(u8, i64, i64, i64)> = Vec::with_capacity(cover.len());
    for c in cover {
        match merged.last_mut() {
            Some(m) if (m.0, m.1) == (c.0, c.1) && c.2 <= m.3 => m.3 = m.3.max(c.3),
            _ => merged.push(c),
        }
    }
    for &r in a {
        let first = merged.partition_point(|m| (m.0, m.1, m.3) <= (r.dir, r.pos, r.lo));
        let mut from = r.lo;
        for m in merged[first..]
            .iter()
            .take_while(|m| (m.0, m.1) == (r.dir, r.pos) && m.2 < r.hi)
        {
            let (lo, hi) = (m.2.max(r.lo), m.3.min(r.hi));
            if covered {
                out.push(Run { lo, hi, ..r });
            } else {
                out.push(Run {
                    lo: from,
                    hi: lo,
                    ..r
                });
            }
            from = hi;
        }
        if !covered {
            out.push(Run {
                lo: from,
                hi: r.hi,
                ..r
            });
        }
    }
}

/// `KLayout`'s edge booleans: coincidence ignores direction, and each result
/// piece keeps the direction of the operand it came from.
pub fn edge_boolean_into(a: &[Seg], b: &[Seg], op: EdgeOp, out: &mut Vec<Seg>) {
    let ra: Vec<Run> = a.iter().map(|&s| run_of(s)).collect();
    let rb: Vec<Run> = b.iter().map(|&s| run_of(s)).collect();
    let mut runs = Vec::new();
    match op {
        EdgeOp::And => split_runs(&ra, &rb, true, &mut runs),
        EdgeOp::Not => split_runs(&ra, &rb, false, &mut runs),
        EdgeOp::Or => {
            runs.extend_from_slice(&ra);
            split_runs(&rb, &ra, false, &mut runs);
        }
    }
    emit_runs(&mut runs, out);
}

fn seg_box(s: Seg) -> Bbox {
    Bbox::point(s.a.x, s.a.y).include(s.b.x, s.b.y)
}

/// Candidate polygons of `b` per edge of `a`, CSR: edge `i` owns
/// `cand[start[i] .. start[i + 1]]`.
fn edge_candidates(a: &[Seg], b: &ValidatedLayer, start: &mut Vec<u32>, cand: &mut Vec<u32>) {
    let boxes: Vec<Bbox> = a.iter().map(|&s| seg_box(s)).collect();
    let mut pairs = Vec::new();
    box_pairs(&boxes, b.bboxes(), &mut pairs);
    pairs.sort_unstable();
    start.clear();
    cand.clear();
    start.push(0);
    let mut at = 0;
    for i in 0..narrow(a.len()) {
        while at < pairs.len() && pairs[at].0 == i {
            cand.push(pairs[at].1);
            at += 1;
        }
        start.push(narrow(cand.len()));
    }
}

/// `KLayout` `inside_part` (`inside`) / `outside_part` (`!inside`): the parts of
/// each edge strictly inside / strictly outside `b`. Parts on `b`'s boundary
/// are in neither. Where a diagonal of `b` crosses a diagonal edge between
/// grid points, the part ends at the last grid point inside it.
pub fn edge_part_into(a: &[Seg], b: &ValidatedLayer, inside: bool, out: &mut Vec<Seg>) {
    let (mut start, mut cand) = (Vec::new(), Vec::new());
    edge_candidates(a, b, &mut start, &mut cand);
    let mut runs = Vec::new();
    // Cut points and on-line spans as twice the line's parameter.
    let mut cuts = Vec::new();
    let mut on_line = Vec::new();
    for (i, &s) in a.iter().enumerate() {
        let r = run_of(s);
        let polys = &cand[start[i] as usize..start[i + 1] as usize];
        // Every point where `b`'s boundary meets this edge's line cuts it.
        cuts.clear();
        cuts.extend([2 * r.lo, 2 * r.hi]);
        on_line.clear();
        for &p in polys {
            for t in poly_segs(b.get(p)).map(run_of) {
                if (t.dir, t.pos) == (r.dir, r.pos) {
                    cuts.extend([2 * t.lo, 2 * t.hi]);
                    on_line.push((2 * t.lo, 2 * t.hi));
                } else if let Some((on_r, on_t)) = crossing2(r, t) {
                    if (2 * t.lo..=2 * t.hi).contains(&on_t) {
                        cuts.push(on_r);
                    }
                }
            }
        }
        cuts.retain(|&c| (2 * r.lo..=2 * r.hi).contains(&c));
        cuts.sort_unstable();
        cuts.dedup();
        for w in cuts.windows(2) {
            let (lo, hi) = (w[0], w[1]);
            if on_line.iter().any(|&(l, h)| l <= lo && hi <= h) {
                continue;
            }
            // The piece's midpoint, at four times scale.
            let (x4, y4) = on_line_point(r, lo + hi);
            if inside_scaled(polys.iter().map(|&p| b.get(p)), x4, y4, 4) == inside {
                // Ends between grid points move inward onto the grid.
                let (lo, hi) = (lo.div_euclid(2) + lo.rem_euclid(2), hi.div_euclid(2));
                runs.push(Run { lo, hi, ..r });
            }
        }
    }
    emit_runs(&mut runs, out);
}

/// The point at parameter `t4 / 4` on a run's line, at four times scale.
const fn on_line_point(r: Run, t4: i64) -> (i64, i64) {
    on_line(r.dir, 4 * r.pos, t4)
}

/// `KLayout` edge `interacting` (`keep`) / `not_interacting` (`!keep`): whole
/// edges that touch or cross a polygon of `b`, or lie inside one.
pub fn edge_interacting_into(a: &[Seg], b: &ValidatedLayer, keep: bool, out: &mut Vec<Seg>) {
    let (mut start, mut cand) = (Vec::new(), Vec::new());
    edge_candidates(a, b, &mut start, &mut cand);
    out.clear();
    for (i, &s) in a.iter().enumerate() {
        let polys = &cand[start[i] as usize..start[i + 1] as usize];
        let meets = polys.iter().any(|&p| {
            let poly = b.get(p);
            poly_segs(poly).any(|t| segments_intersect(s, t))
                || inside_scaled(std::iter::once(poly), s.a.x.raw(), s.a.y.raw(), 1)
        });
        if meets == keep {
            out.push(s);
        }
    }
}

/// `KLayout` `extended(begin, end, out, in)` on edges, material on the left:
/// one box per edge of `a`, the edge lengthened by `begin` before its start
/// and `end` past its end, and widened by `outside` to its right (away from
/// its shape) and `inside` to its left. Boxes are not merged, as `KLayout`'s
/// are not. A box with no area (`outside + inside` of 0) is refused by
/// validation, and a 45-degree edge with [`BooleanError::NotRectilinear`].
pub fn extended_into(
    a: &[Seg],
    (begin, end, outside, inside): (Dbu, Dbu, Dbu, Dbu),
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    let mut builder = GeometryStoreBuilder::with_capacity(a.len(), 4 * a.len());
    for &s in a {
        let r = run_of(s);
        if r.dir > 1 {
            return Err(BooleanError::NotRectilinear);
        }
        let vertical = r.dir == 1;
        // Travelling toward `hi`, the material (left) is +y on a horizontal
        // edge and -x on a vertical one.
        let left_positive = r.forward != vertical;
        let (before, after) = if r.forward {
            (begin.raw(), end.raw())
        } else {
            (end.raw(), begin.raw())
        };
        let (below, above) = if left_positive {
            (outside.raw(), inside.raw())
        } else {
            (inside.raw(), outside.raw())
        };
        let (lo, hi, across_lo, across_hi) =
            (r.lo - before, r.hi + after, r.pos - below, r.pos + above);
        let at = |v: i64| Dbu::new(v).ok_or(BooleanError::OutOfRange);
        let b = if vertical {
            Bbox {
                xlo: at(across_lo)?,
                ylo: at(lo)?,
                xhi: at(across_hi)?,
                yhi: at(hi)?,
            }
        } else {
            Bbox {
                xlo: at(lo)?,
                ylo: at(across_lo)?,
                xhi: at(hi)?,
                yhi: at(across_hi)?,
            }
        };
        push_rect(&mut builder, b);
    }
    let (store, _) = builder.finish(1);
    validate_layer_into(&store, ONLY, out)?;
    Ok(())
}

/// `KLayout` `with_length`: edges whose length in grid units is in `range`.
/// A diagonal edge `k` steps long is `k·√2`, compared squared, exactly.
pub fn with_length_into(a: &[Seg], range: RangeInclusive<i128>, out: &mut Vec<Seg>) {
    let (lo, hi) = (*range.start(), *range.end());
    out.clear();
    out.extend(a.iter().filter(|s| {
        let r = run_of(**s);
        let k = i128::from(r.hi - r.lo);
        if r.dir < 2 {
            return range.contains(&k);
        }
        let length2 = 2 * k * k;
        let above = lo <= 0 || lo.checked_mul(lo).is_some_and(|l2| l2 <= length2);
        let below = hi >= 0 && hi.checked_mul(hi).is_none_or(|h2| length2 <= h2);
        above && below
    }));
}
