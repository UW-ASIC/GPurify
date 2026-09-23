//! Derived-layer operations past the three booleans: sizing, selection by
//! relation or measure, holes, extents, and edge layers.
//!
//! Data in: merged [`ValidatedLayer`]s (a boolean result, or a layer passed
//! through [`merge_into`]); edge layers as directed [`Seg`]s, material on the
//! left of travel. Data out: a merged layer, or merged edges. Semantics follow
//! `KLayout`'s merged-polygon definitions; exact on the rectilinear grid.

use crate::bbox::Bbox;
use crate::boolean::{subtraction_into, union_into, BooleanError};
use crate::ids::LayerId;
use crate::index::{cross_layer_pairs_into, SpatialIndex};
use crate::ops::{segments_intersect, Point, Seg};
use crate::rects::decompose_into;
use crate::store::GeometryStoreBuilder;
use crate::view::{validate_layer_into, PolygonRef, ValidatedLayer};
use crate::width::{narrowest_width, FacingScratch};
use crate::{narrow, Dbu, DbuArea};

const ONLY: LayerId = LayerId(0);

/// `a` with overlapping and abutting polygons merged (`KLayout` merged semantics).
pub fn merge_into(a: &ValidatedLayer, out: &mut ValidatedLayer) -> Result<(), BooleanError> {
    union_into(a, &ValidatedLayer::default(), out)
}

/// Validate the builder's CCW rings as one layer, then merge them.
fn merged(builder: GeometryStoreBuilder, out: &mut ValidatedLayer) -> Result<(), BooleanError> {
    let (store, _) = builder.finish(1);
    let mut raw = ValidatedLayer::default();
    validate_layer_into(&store, ONLY, &mut raw)?;
    merge_into(&raw, out)
}

fn push_rect(builder: &mut GeometryStoreBuilder, r: Bbox) {
    builder.push(
        ONLY,
        &[r.xlo, r.xhi, r.xhi, r.xlo],
        &[r.ylo, r.ylo, r.yhi, r.yhi],
    );
}

/// `r` grown by `d` on every side, refused past the coordinate domain.
fn grown(r: Bbox, d: i64) -> Result<Bbox, BooleanError> {
    let at = |v: Dbu, by: i64| Dbu::new(v.raw() + by).ok_or(BooleanError::OutOfRange);
    Ok(Bbox {
        xlo: at(r.xlo, -d)?,
        ylo: at(r.ylo, -d)?,
        xhi: at(r.xhi, d)?,
        yhi: at(r.yhi, d)?,
    })
}

/// `KLayout` `sized(d)`: the Minkowski sum with the square `[-d, d]²` for `d > 0`,
/// the erosion by it for `d < 0`. A part no wider than `2|d|` shrinks away.
pub fn sized_into(
    a: &ValidatedLayer,
    d: Dbu,
    out: &mut ValidatedLayer,
) -> Result<(), BooleanError> {
    let d = d.raw();
    if d >= 0 {
        return grow_into(a, d, out);
    }
    // Erosion is the complement of growing the complement, within a frame far
    // enough out that its own border does not erode `a`.
    let Some(extent) = a.bboxes().iter().copied().reduce(Bbox::union) else {
        return merge_into(a, out);
    };
    let mut frame = GeometryStoreBuilder::with_capacity(1, 4);
    push_rect(&mut frame, grown(extent, -d)?);
    let mut frame_layer = ValidatedLayer::default();
    merged(frame, &mut frame_layer)?;
    let mut outside = ValidatedLayer::default();
    subtraction_into(&frame_layer, a, &mut outside)?;
    let mut eaten = ValidatedLayer::default();
    grow_into(&outside, -d, &mut eaten)?;
    subtraction_into(a, &eaten, out)
}

/// Union of every rectangle of `a` grown by `d >= 0`: exact, since the
/// Minkowski sum distributes over union.
fn grow_into(a: &ValidatedLayer, d: i64, out: &mut ValidatedLayer) -> Result<(), BooleanError> {
    let (mut rects, mut start) = (Vec::new(), Vec::new());
    decompose_into(a, &mut rects, &mut start);
    let mut builder = GeometryStoreBuilder::with_capacity(rects.len(), 4 * rects.len());
    for &r in &rects {
        push_rect(&mut builder, grown(r, d)?);
    }
    merged(builder, out)
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

/// `KLayout` `extents`: the bounding box of every polygon of `a`, merged.
pub fn extents_into(a: &ValidatedLayer, out: &mut ValidatedLayer) -> Result<(), BooleanError> {
    let mut builder = GeometryStoreBuilder::with_capacity(a.len(), 4 * a.len());
    for &b in a.bboxes() {
        push_rect(&mut builder, b);
    }
    merged(builder, out)
}

/// `KLayout` `with_area(lo, hi)`, both bounds inclusive: polygons whose area,
/// holes excluded, is in `lo..=hi`.
pub fn with_area_into(a: &ValidatedLayer, lo: DbuArea, hi: DbuArea, out: &mut ValidatedLayer) {
    let keep: Vec<bool> = (0..narrow(a.len()))
        .map(|idx| {
            let twice: i128 = a.poly_rings(idx).map(|r| r.area2().raw()).sum();
            (lo.raw()..=hi.raw()).contains(&(twice / 2))
        })
        .collect();
    a.select_into(&keep, out);
}

/// Polygons whose narrowest width, as the `width` rule measures it, is in
/// `lo..=hi`.
pub fn with_width_into(a: &ValidatedLayer, lo: Dbu, hi: Dbu, out: &mut ValidatedLayer) {
    let mut scratch = FacingScratch::default();
    let keep: Vec<bool> = (0..narrow(a.len()))
        .map(|idx| (lo..=hi).contains(&narrowest_width(a.get(idx), &mut scratch)))
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

/// Even-odd inside test for the point `(x2 / 2, y2 / 2)`, which must lie on no
/// ring. Counts the vertical edges a `+x` ray crosses, half-open in y.
fn inside_doubled<'a>(polys: impl Iterator<Item = PolygonRef<'a>>, x2: i64, y2: i64) -> bool {
    let mut inside = false;
    for poly in polys {
        for seg in poly_segs(poly) {
            let (lo, hi) = (
                seg.a.y.raw().min(seg.b.y.raw()),
                seg.a.y.raw().max(seg.b.y.raw()),
            );
            if seg.a.x == seg.b.x && 2 * seg.a.x.raw() > x2 && 2 * lo <= y2 && y2 < 2 * hi {
                inside = !inside;
            }
        }
    }
    inside
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
    inside_doubled(std::iter::once(q), px, py) || inside_doubled(std::iter::once(p), qx, qy)
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
    let (mut rects, mut start) = (Vec::new(), Vec::new());
    decompose_into(parts, &mut rects, &mut start);
    // One rectangle per part: its open interior lies inside exactly one polygon of `a`.
    let probes: Vec<Bbox> = start[..start.len() - 1]
        .iter()
        .map(|&s| rects[s as usize])
        .collect();
    let mut pairs = Vec::new();
    box_pairs(&probes, a.bboxes(), &mut pairs);
    for &(r, p) in &pairs {
        let r = probes[r as usize];
        let (x2, y2) = (r.xlo.raw() + r.xhi.raw(), r.ylo.raw() + r.yhi.raw());
        if inside_doubled(std::iter::once(a.get(p)), x2, y2) {
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
    let mut common = ValidatedLayer::default();
    crate::boolean::intersection_into(a, b, &mut common)?;
    a.select_into(&free_of(a, &common), out);
    Ok(())
}

// ---- edge layers ----

/// One axis-parallel edge on its line: `pos` is the fixed coordinate, `lo < hi`
/// the span, `forward` whether it travels toward `hi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Run {
    vertical: bool,
    pos: i64,
    lo: i64,
    hi: i64,
    forward: bool,
}

fn run_of(s: Seg) -> Run {
    let vertical = s.a.x == s.b.x;
    let (pos, from, to) = if vertical {
        (s.a.x.raw(), s.a.y.raw(), s.b.y.raw())
    } else {
        (s.a.y.raw(), s.a.x.raw(), s.b.x.raw())
    };
    Run {
        vertical,
        pos,
        lo: from.min(to),
        hi: from.max(to),
        forward: to > from,
    }
}

fn seg_of(r: Run) -> Seg {
    let (from, to) = if r.forward {
        (r.lo, r.hi)
    } else {
        (r.hi, r.lo)
    };
    let point = |along: i64| {
        let (x, y) = if r.vertical {
            (r.pos, along)
        } else {
            (along, r.pos)
        };
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

/// Runs to merged segments: collinear pieces of one direction that touch or
/// overlap become one, zero-length ones go.
fn emit_runs(runs: &mut Vec<Run>, out: &mut Vec<Seg>) {
    runs.retain(|r| r.lo < r.hi);
    runs.sort_unstable_by_key(|r| (r.vertical, r.pos, r.forward, r.lo));
    out.clear();
    let mut at = 0;
    while at < runs.len() {
        let mut cur = runs[at];
        at += 1;
        while at < runs.len()
            && (runs[at].vertical, runs[at].pos, runs[at].forward)
                == (cur.vertical, cur.pos, cur.forward)
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
    let mut cover: Vec<(bool, i64, i64, i64)> =
        b.iter().map(|r| (r.vertical, r.pos, r.lo, r.hi)).collect();
    cover.sort_unstable();
    let mut merged: Vec<(bool, i64, i64, i64)> = Vec::with_capacity(cover.len());
    for c in cover {
        match merged.last_mut() {
            Some(m) if (m.0, m.1) == (c.0, c.1) && c.2 <= m.3 => m.3 = m.3.max(c.3),
            _ => merged.push(c),
        }
    }
    for &r in a {
        let first = merged.partition_point(|m| (m.0, m.1, m.3) <= (r.vertical, r.pos, r.lo));
        let mut from = r.lo;
        for m in merged[first..]
            .iter()
            .take_while(|m| (m.0, m.1) == (r.vertical, r.pos) && m.2 < r.hi)
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
/// are in neither.
pub fn edge_part_into(a: &[Seg], b: &ValidatedLayer, inside: bool, out: &mut Vec<Seg>) {
    let (mut start, mut cand) = (Vec::new(), Vec::new());
    edge_candidates(a, b, &mut start, &mut cand);
    let mut runs = Vec::new();
    let mut cuts = Vec::new();
    for (i, &s) in a.iter().enumerate() {
        let r = run_of(s);
        let polys = &cand[start[i] as usize..start[i + 1] as usize];
        // Every point where `b`'s boundary meets this edge's line cuts it.
        cuts.clear();
        cuts.extend([r.lo, r.hi]);
        let mut on_line = Vec::new();
        for &p in polys {
            for t in poly_segs(b.get(p)).map(run_of) {
                if t.vertical != r.vertical && (t.lo..=t.hi).contains(&r.pos) {
                    cuts.push(t.pos);
                } else if t.vertical == r.vertical && t.pos == r.pos {
                    cuts.extend([t.lo, t.hi]);
                    on_line.push((t.lo, t.hi));
                }
            }
        }
        cuts.retain(|&c| (r.lo..=r.hi).contains(&c));
        cuts.sort_unstable();
        cuts.dedup();
        for w in cuts.windows(2) {
            let (lo, hi) = (w[0], w[1]);
            if on_line.iter().any(|&(l, h)| l <= lo && hi <= h) {
                continue;
            }
            let (along, across) = (lo + hi, 2 * r.pos);
            let (x2, y2) = if r.vertical {
                (across, along)
            } else {
                (along, across)
            };
            if inside_doubled(polys.iter().map(|&p| b.get(p)), x2, y2) == inside {
                runs.push(Run { lo, hi, ..r });
            }
        }
    }
    emit_runs(&mut runs, out);
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
                || inside_doubled(std::iter::once(poly), 2 * s.a.x.raw(), 2 * s.a.y.raw())
        });
        if meets == keep {
            out.push(s);
        }
    }
}

/// `KLayout` `with_length(lo, hi)`, both bounds inclusive.
pub fn with_length_into(a: &[Seg], lo: Dbu, hi: Dbu, out: &mut Vec<Seg>) {
    out.clear();
    out.extend(a.iter().filter(|s| {
        let r = run_of(**s);
        (lo.raw()..=hi.raw()).contains(&(r.hi - r.lo))
    }));
}
