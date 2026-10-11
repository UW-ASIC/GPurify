//! Spacing family: how close two shapes may come.
//!
//! Data in: one layer (two for `min_spacing_diff`), indexed and pruned at the
//! rule's own limit — never narrower, or a dropped pair reports clean.
//! Data out: one violation per offending pair, at the midpoint of the pair of
//! points it measured (`nearest`). Pairs within one merged figure (touching
//! shapes) have no gap and are skipped.

use super::{
    gap_midpoint, join_nested, label_pairs_into, owners_of, pair_distances_into, rects_ring_dist2,
    ring_segs, seg_bbox, LayerRects, SortedRects, Verdict, REFUSED,
};
use crate::drc::rules::width::wide_rects_into;
use crate::drc::ruleset::SpacingTable;
use crate::drc::Scratch;
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use crate::topology::{NetId, NetTable};
use gpurify_geom::connectivity::ComponentLabel;
use gpurify_geom::derive::{edges_into, merge_into};
use gpurify_geom::index::{candidate_pairs_into, cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::ops::{isqrt, seg_seg_dist2, Point, Seg};
use gpurify_geom::{Bbox, GeometryStore, LayerId, PolyId};
use gpurify_geom::{Dbu, DbuArea, MAX_ABS_DBU};
use gpurify_ingest::StrId;
use std::cmp::Ordering;

/// The nearest approach among `pairs` of axis-parallel segments: its squared
/// distance and the midpoint of the two nearest points (floored). Where the
/// two nearest segments run alongside each other at that distance, the
/// nearest points are a stretch of pairs, and the midpoint is that stretch's
/// middle. A stretch is whole however its sides were cut: the nearest pairs'
/// stretches that lie on one line and touch or overlap are merged first, so
/// a side split by a collinear vertex, or by the rectangles a wide part is
/// cut into in one orientation, is marked at the middle of the whole run.
/// Among the merged stretches the longest wins (a facing run over a corner).
/// Stretches that tie on length are all kept: the point is the middle of the
/// box bounding their midpoints, floored once. That is between them: on
/// their line when they share one, and otherwise between the lines (on the
/// axis of a pair that is symmetric, such as a square tucked into an L's
/// corner, which can put it off the gap); it does not depend on the order of
/// the rings and maps with the layout under every symmetry of the square.
/// `None` when `pairs` is empty.
fn nearest(pairs: impl Iterator<Item = (Seg, Seg)>) -> Option<(DbuArea, Point)> {
    let mut best: Option<DbuArea> = None;
    // Each nearest pair's stretch, doubled: `(vertical, across, lo, hi)`, the
    // line's doubled middle across it and its extent along it. A pair that
    // faces over no run is a point, a horizontal stretch of length 0.
    let mut stretches: Vec<(bool, i64, i64, i64)> = Vec::new();
    for (p, q) in pairs {
        let d2 = seg_seg_dist2(p, q);
        match best.map(|b| d2.cmp(&b)) {
            Some(Ordering::Greater) => continue,
            Some(Ordering::Equal) => {}
            _ => {
                best = Some(d2);
                stretches.clear();
            }
        }
        // For axis-parallel segments, the boxes' overlap on each axis: a
        // positive one is the run they face each other over, and either
        // one's ends sum to twice the middle of the boxes' gap.
        let (pb, qb) = (seg_bbox(p), seg_bbox(q));
        let (xlo, xhi) = (pb.xlo.max(qb.xlo).raw(), pb.xhi.min(qb.xhi).raw());
        let (ylo, yhi) = (pb.ylo.max(qb.ylo).raw(), pb.yhi.min(qb.yhi).raw());
        stretches.push(if xhi > xlo {
            (false, ylo + yhi, 2 * xlo, 2 * xhi)
        } else if yhi > ylo {
            (true, xlo + xhi, 2 * ylo, 2 * yhi)
        } else {
            (false, ylo + yhi, xlo + xhi, xlo + xhi)
        });
    }
    // Merge each line's touching stretches; box the longest ones' doubled
    // midpoints: xlo, xhi, ylo, yhi.
    stretches.sort_unstable();
    let (mut longest, mut tied) = (-1, [0i64; 4]);
    let mut at = 0;
    while at < stretches.len() {
        let (vertical, across, lo, mut hi) = stretches[at];
        at += 1;
        while let Some(&(v, a, next_lo, next_hi)) = stretches.get(at) {
            if (v, a) != (vertical, across) || next_lo > hi {
                break;
            }
            hi = hi.max(next_hi);
            at += 1;
        }
        // Exact: a stretch's ends are both even, a point's equal.
        let along = i64::midpoint(lo, hi);
        let (x, y) = if vertical {
            (across, along)
        } else {
            (along, across)
        };
        match (hi - lo).cmp(&longest) {
            Ordering::Less => {}
            Ordering::Equal => {
                let [xlo, xhi, ylo, yhi] = tied;
                tied = [xlo.min(x), xhi.max(x), ylo.min(y), yhi.max(y)];
            }
            Ordering::Greater => (longest, tied) = (hi - lo, [x, x, y, y]),
        }
    }
    let quarter = |sum: i64| Dbu::new_unchecked(sum.div_euclid(4));
    let at = Point {
        x: quarter(tied[0] + tied[1]),
        y: quarter(tied[2] + tied[3]),
    };
    best.map(|d2| (d2, at))
}

/// Every edge of one ring paired with every edge of another.
fn ring_pairs<'a>(
    (axs, ays): (&'a [Dbu], &'a [Dbu]),
    (bxs, bys): (&'a [Dbu], &'a [Dbu]),
) -> impl Iterator<Item = (Seg, Seg)> + 'a {
    ring_segs(axs, ays).flat_map(move |p| ring_segs(bxs, bys).map(move |q| (p, q)))
}

/// Every side of each of `rects` paired with every edge of a ring.
fn rect_ring_pairs<'a>(
    rects: &'a [Bbox],
    ring: (&'a [Dbu], &'a [Dbu]),
) -> impl Iterator<Item = (Seg, Seg)> + 'a {
    rects.iter().flat_map(move |r| {
        let corner = |x, y| Point { x, y };
        let c = [
            corner(r.xlo, r.ylo),
            corner(r.xhi, r.ylo),
            corner(r.xhi, r.yhi),
            corner(r.xlo, r.yhi),
        ];
        (0..4)
            .map(move |i| Seg {
                a: c[i],
                b: c[(i + 1) % 4],
            })
            .flat_map(move |side| ring_segs(ring.0, ring.1).map(move |e| (side, e)))
    })
}

/// Where a pair measured `d2` apart is reported: the midpoint of `found`, its
/// nearest approach ([`nearest`]), when that measures `d2`; else (a pair
/// nested one in the other, measured 0 with its boundaries apart) the middle
/// of the overlap of the two rows' boxes.
fn marker(
    store: &GeometryStore,
    (a, b): (PolyId, PolyId),
    d2: DbuArea,
    found: Option<(DbuArea, Point)>,
) -> Point {
    found.filter(|&(near, _)| near == d2).map_or_else(
        || gap_midpoint(store.poly_bbox(a), store.poly_bbox(b)),
        |(_, at)| at,
    )
}

/// [`marker`] for a pair measured boundary to boundary, whole shape to whole
/// shape. Quadratic in the two ring sizes, as [`super::poly_dist2`]; only a
/// violation pays it.
pub(super) fn whole_at(store: &GeometryStore, (a, b): (PolyId, PolyId), d2: DbuArea) -> Point {
    let found = nearest(ring_pairs(store.poly_verts(a), store.poly_verts(b)));
    marker(store, (a, b), d2, found)
}

/// [`marker`] for a pair measured from the wide parts of either shape to the
/// other's ring.
fn wide_at(
    store: &GeometryStore,
    (a, b): (PolyId, PolyId),
    (wide_a, wide_b): (&[Bbox], &[Bbox]),
    d2: DbuArea,
) -> Point {
    let found = nearest(
        rect_ring_pairs(wide_a, store.poly_verts(b))
            .chain(rect_ring_pairs(wide_b, store.poly_verts(a))),
    );
    marker(store, (a, b), d2, found)
}

fn spacing_violation(
    rule: StrId,
    layer: LayerId,
    (a, b): (PolyId, PolyId),
    (dist2, at): (DbuArea, Point),
    limit: Dbu,
) -> Violation {
    Violation {
        rule,
        layer,
        severity: Severity::Error,
        at,
        // `isqrt` rounds toward zero: a report never overstates the gap.
        measured: Measurement::Length(isqrt(dist2)),
        limit: Measurement::Length(limit),
        shapes: (a, Some(b)),
    }
}

/// Validate, index, prune at `limit`, measure every candidate pair, and label
/// the layer's merged figures (pairs at distance zero). `false` is `Refused`.
fn prepare(store: &GeometryStore, layer: LayerId, limit: Dbu, s: &mut Scratch) -> bool {
    if s.validated.get(store, layer).is_none() {
        return false;
    }
    let rows = store.polys_on_layer(layer);
    SpatialIndex::build_into(store, layer, &mut s.index_a);
    candidate_pairs_into(store, &s.index_a, limit, &mut s.pairs);
    pair_distances_into(store, &s.pairs, limit, &mut s.dists);
    s.holes.build(store, [layer]);
    join_nested(store, &s.holes, &s.pairs, &mut s.dists);
    label_pairs_into(
        rows.start,
        rows.end - rows.start,
        &s.pairs,
        &s.dists,
        |d2| d2.raw() == 0,
        &mut s.edges,
        &mut s.labels,
    );
    true
}

/// [`prepare`], then the layer merged into `s.layer_out`. `false` is `Refused`.
fn prepare_merged(store: &GeometryStore, layer: LayerId, limit: Dbu, s: &mut Scratch) -> bool {
    if !prepare(store, layer, limit, s) {
        return false;
    }
    let drawn = s
        .validated
        .get(store, layer)
        .expect("`prepare` validated it");
    merge_into(drawn, &mut s.layer_out).is_ok()
}

/// The one same-layer kernel: every candidate pair in two different figures
/// that `measure` judges is examined, and reported when closer than `limit`,
/// at the point `at` gives. `measure` takes the pair and its distance and
/// returns the distance to judge, `None` for a pair the rule does not judge;
/// `at` takes the pair and the judged distance. Returns the examined count.
#[allow(clippy::too_many_arguments, reason = "the rule row, then two closures")]
fn judged_pairs(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    limit: Dbu,
    s: &Scratch,
    out: &mut Violations,
    measure: impl Fn(PolyId, PolyId, DbuArea) -> Option<DbuArea>,
    at: impl Fn(PolyId, PolyId, DbuArea) -> Point,
) -> u64 {
    let first_row = store.polys_on_layer(layer).start;
    let limit2 = limit.mul_wide(limit);
    let mut examined = 0u64;
    for (&(a, b), &whole) in s.pairs.iter().zip(&s.dists) {
        if s.labels[(a.0 - first_row) as usize] == s.labels[(b.0 - first_row) as usize] {
            continue;
        }
        if let Some(d2) = measure(a, b, whole) {
            examined += 1;
            if d2 < limit2 {
                let found = (d2, at(a, b, d2));
                out.push(spacing_violation(rule, layer, (a, b), found, limit));
            }
        }
    }
    examined
}

/// Same-layer minimum spacing. `examined` counts every candidate pair.
pub(crate) fn min_spacing(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    if !prepare(store, layer, limit, s) {
        return REFUSED;
    }
    judged_pairs(
        store,
        rule,
        layer,
        limit,
        s,
        out,
        |_, _, d2| Some(d2),
        |a, b, d2| whole_at(store, (a, b), d2),
    );
    (Outcome::Ran, s.pairs.len() as u64)
}

/// Cross-layer minimum spacing, reported on layer `a`. No merged-figure
/// exemption: overlap *is* the violation. `examined` counts candidate pairs.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn min_spacing_diff(
    store: &GeometryStore,
    rule: StrId,
    a_layer: LayerId,
    b_layer: LayerId,
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    if s.validated.get(store, a_layer).is_none() || s.validated.get(store, b_layer).is_none() {
        return REFUSED;
    }
    SpatialIndex::build_into(store, a_layer, &mut s.index_a);
    SpatialIndex::build_into(store, b_layer, &mut s.index_b);
    cross_layer_pairs_into(store, &s.index_a, &s.index_b, limit, &mut s.pairs);
    pair_distances_into(store, &s.pairs, limit, &mut s.dists);
    s.holes.build(store, [a_layer, b_layer]);
    join_nested(store, &s.holes, &s.pairs, &mut s.dists);
    let limit2 = limit.mul_wide(limit);
    for (&pair, &d2) in s.pairs.iter().zip(&s.dists) {
        if d2 < limit2 {
            let found = (d2, whole_at(store, pair, d2));
            out.push(spacing_violation(rule, a_layer, pair, found, limit));
        }
    }
    (Outcome::Ran, s.pairs.len() as u64)
}

/// End-of-line spacing, the ends read off the merged layer. `examined` counts
/// separate pairs where either shape lies on an end of line facing the other.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn eol_spacing(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    eol_width: Dbu,
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    if !prepare_merged(store, layer, limit, s) {
        return REFUSED;
    }
    let mut edges = Vec::new();
    edges_into(&s.layer_out, &mut edges);
    let mut ends: Vec<(Line, Seg)> = edges
        .into_iter()
        .map(|edge| (line_of(edge), edge))
        .filter(|&((.., lo, hi), _)| hi - lo < eol_width.raw())
        .collect();
    ends.sort_unstable_by_key(|&(line, _)| line);
    // The nearest approach of either shape to an end of line the other lies on.
    let approach = |a, b| {
        let mut hits = Vec::new();
        eol_hits(store, (a, b), &ends, (eol_width, limit), &mut hits);
        eol_hits(store, (b, a), &ends, (eol_width, limit), &mut hits);
        nearest(hits.into_iter())
    };
    let examined = judged_pairs(
        store,
        rule,
        layer,
        limit,
        s,
        out,
        |a, b, _| approach(a, b).map(|(d2, _)| d2),
        |a, b, d2| marker(store, (a, b), d2, approach(a, b)),
    );
    (Outcome::Ran, examined)
}

/// An axis-parallel edge on its line: whether it is vertical, its fixed
/// coordinate, whether it travels toward higher coordinates, and its span
/// `lo < hi`.
type Line = (bool, i64, bool, i64, i64);

fn line_of(edge: Seg) -> Line {
    let vertical = edge.a.x == edge.b.x;
    let (pos, from, to) = if vertical {
        (edge.a.x.raw(), edge.a.y.raw(), edge.b.y.raw())
    } else {
        (edge.a.y.raw(), edge.a.x.raw(), edge.b.x.raw())
    };
    (vertical, pos, to > from, from.min(to), from.max(to))
}

/// The keep-out an end of line projects: its span pushed `depth` out of its
/// material (to the right of travel, the material being on the left), clamped
/// to the coordinate domain.
fn eol_zone(edge: Seg, depth: Dbu) -> Bbox {
    let (dx, dy) = (
        edge.b.x.raw() - edge.a.x.raw(),
        edge.b.y.raw() - edge.a.y.raw(),
    );
    // Out of the material: the direction of travel turned clockwise.
    let (nx, ny) = (dy.signum(), -dx.signum());
    let d = depth.raw();
    let span = seg_bbox(edge);
    let grow =
        |coord: i64, by: i64| Dbu::new_unchecked((coord + by * d).clamp(-MAX_ABS_DBU, MAX_ABS_DBU));
    Bbox {
        xlo: grow(span.xlo.raw(), nx.min(0)),
        ylo: grow(span.ylo.raw(), ny.min(0)),
        xhi: grow(span.xhi.raw(), nx.max(0)),
        yhi: grow(span.yhi.raw(), ny.max(0)),
    }
}

/// The pairs of segments an end-of-line pair measures, into `out`: each part
/// of an end of line `eol` draws, with each edge of `other` reaching into that
/// end's keep-out. `ends` are the merged layer's ends of line (edges shorter
/// than `eol_width`), sorted by line; a drawn edge lies on one when they share
/// a line, a direction and a stretch of it. Nothing when no edge of `other`
/// reaches into such a keep-out.
fn eol_hits(
    store: &GeometryStore,
    (eol, other): (PolyId, PolyId),
    ends: &[(Line, Seg)],
    (eol_width, limit): (Dbu, Dbu),
    out: &mut Vec<(Seg, Seg)>,
) {
    let (xs, ys) = store.poly_verts(eol);
    let (oxs, oys) = store.poly_verts(other);
    for edge in ring_segs(xs, ys) {
        let (vertical, pos, forward, lo, hi) = line_of(edge);
        // An end overlapping `edge` is shorter than `eol_width`: it starts past this.
        let first = ends.partition_point(|&(line, _)| {
            line < (vertical, pos, forward, lo - eol_width.raw(), i64::MIN)
        });
        let on_edge = ends[first..]
            .iter()
            .take_while(|&&((v, p, f, start, _), _)| {
                (v, p, f) == (vertical, pos, forward) && start < hi
            })
            .filter(|&&((.., end), _)| end > lo);
        for &((.., start, end), end_of_line) in on_edge {
            let zone = eol_zone(end_of_line, limit);
            let piece = on_line(vertical, pos, start.max(lo), end.min(hi));
            out.extend(
                ring_segs(oxs, oys)
                    .filter(|&far| zone.overlaps(seg_bbox(far)))
                    .map(|far| (piece, far)),
            );
        }
    }
}

/// The segment from `from` to `to` along the line `pos`.
fn on_line(vertical: bool, pos: i64, from: i64, to: i64) -> Seg {
    let point = |along: i64| {
        let (x, y) = if vertical { (pos, along) } else { (along, pos) };
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

/// Two edges of different merged figures facing each other: the figures'
/// labels (lower first), the gap between the edges, and the run, the length
/// over which the edges project onto each other.
type Facing = (u32, u32, i64, i64);

/// Every two edges of the merged layer `s.layer_out`, in different figures,
/// that face each other across a gap of at most `within` and run alongside
/// each other for a positive length, sorted by figure pair. A
/// figure is labelled as [`prepare`] labelled the drawn rows under it
/// (`s.rects_a`, built from the layer). Facing: parallel, out of their
/// material toward each other, the one facing up below the one facing down.
fn facing_runs(store: &GeometryStore, layer: LayerId, within: Dbu, s: &Scratch) -> Vec<Facing> {
    let first_row = store.polys_on_layer(layer).start;
    let owners = owners_of(&s.layer_out, &s.rects_a);
    // Per orientation, the edges whose material lies below (facing up) and above.
    let (mut up, mut down) = (Vec::new(), Vec::new());
    for (figure, owner) in (0..).zip(owners) {
        let label = s.labels[(owner.0 - first_row) as usize].0;
        for ring in s.layer_out.poly_rings(figure) {
            let (xs, ys) = ring.coords();
            for (vertical, pos, forward, lo, hi) in ring_segs(xs, ys).map(line_of) {
                // Material on the left: up-travelling vertical, left-travelling horizontal.
                let side = if forward == vertical {
                    &mut up
                } else {
                    &mut down
                };
                side.push((vertical, pos, lo, hi, label));
            }
        }
    }
    down.sort_unstable();
    let mut runs = Vec::new();
    // ponytail: every down edge within `within` above each up edge; quadratic
    // only when many edges share one `within`-wide band.
    for &(vertical, pos, lo, hi, label) in &up {
        let first = down.partition_point(|&(v, p, ..)| (v, p) <= (vertical, pos));
        let facing = down[first..]
            .iter()
            .take_while(|&&(v, p, ..)| v == vertical && p - pos <= within.raw());
        for &(_, p, far_lo, far_hi, other) in facing {
            let run = hi.min(far_hi) - lo.max(far_lo);
            if run > 0 && other != label {
                runs.push((label.min(other), label.max(other), p - pos, run));
            }
        }
    }
    runs.sort_unstable();
    runs
}

/// The run of figures `a` and `b`: the longest their facing edges at most
/// `spacing` apart project onto each other, or 0. At most, not closer: a
/// pair exactly `spacing` apart runs alongside and is judged, and passes.
fn run_within(runs: &[Facing], a: ComponentLabel, b: ComponentLabel, spacing: Dbu) -> i64 {
    let pair = (a.0.min(b.0), a.0.max(b.0));
    let from = runs.partition_point(|&(p, q, ..)| (p, q) < pair);
    runs[from..]
        .iter()
        .take_while(|&&(p, q, ..)| (p, q) == pair)
        .filter(|&&(.., gap, _)| gap <= spacing.raw())
        .map(|&(.., run)| run)
        .max()
        .unwrap_or(0)
}

/// Each polygon's wide rectangles, CSR: every `wide` rectangle of the
/// polygon's own figure (component `labels`), grown by `attached`, clipped to
/// the polygon rectangle by rectangle.
fn wide_parts(
    polys: &LayerRects,
    labels: &[ComponentLabel],
    first_row: u32,
    wide: &[Bbox],
    attached: Dbu,
) -> (Vec<Bbox>, Vec<u32>) {
    // A wide rectangle lies in one figure: the one of any drawn rectangle it overlaps.
    let drawn = SortedRects::new(polys.labelled());
    let label_of = |row: PolyId| labels[(row.0 - first_row) as usize];
    let d = attached.raw();
    let grow =
        |v: Dbu, by: i64| Dbu::new_unchecked((v.raw() + by).clamp(-MAX_ABS_DBU, MAX_ABS_DBU));
    let grown = SortedRects::new(
        wide.iter()
            .filter_map(|&r| {
                let (_, row) = drawn.overlapping(r).next()?;
                let r = Bbox {
                    xlo: grow(r.xlo, -d),
                    ylo: grow(r.ylo, -d),
                    xhi: grow(r.xhi, d),
                    yhi: grow(r.yhi, d),
                };
                Some((r, label_of(row)))
            })
            .collect(),
    );
    let (mut parts, mut part_start) = (Vec::new(), vec![0u32]);
    for poly in 0..u32::try_from(polys.len()).expect("a layer indexes polygons with a u32") {
        let mine = label_of(polys.row[poly as usize]);
        for &r in polys.of(poly) {
            parts.extend(
                grown
                    .overlapping(r)
                    .filter(|&(_, label)| label == mine)
                    .map(|(clip, _)| clip),
            );
        }
        part_start.push(u32::try_from(parts.len()).expect("a layer's rectangles fit a u32"));
    }
    (parts, part_start)
}

/// Same-net or different-net spacing (gf180 NW.2a/2b), nets as extracted.
/// `Refused` when a shape on the layer carries no net. `examined` counts the
/// separate pairs of the asked relation.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn net_spacing(
    store: &GeometryStore,
    nets: &NetTable,
    rule: StrId,
    layer: LayerId,
    same_net: bool,
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let unnetted = store
        .polys_on_layer(layer)
        .any(|row| nets.net_of(PolyId(row)) == NetId::NONE);
    if unnetted || !prepare(store, layer, limit, s) {
        return REFUSED;
    }
    let examined = judged_pairs(
        store,
        rule,
        layer,
        limit,
        s,
        out,
        |a, b, d2| (nets.same_net(a, b) == same_net).then_some(d2),
        |a, b, d2| whole_at(store, (a, b), d2),
    );
    (Outcome::Ran, examined)
}

/// Spacing between shapes that their two nets decide. On one layer (`b` is
/// `None`) the pairs are shapes in different merged figures, as for
/// [`min_spacing`]; across two layers every pair, overlap included, as for
/// [`min_spacing_diff`], reported on `a`. `need` takes the pair's nets and
/// answers `None` for a pair the rule does not judge, `Some(None)` for one it
/// judges and requires nothing of, and `Some(Some(limit))` for the spacing it
/// requires, at most `widest`. One violation per pair closer than its limit,
/// at the midpoint of its measured points. `examined` counts judged pairs.
/// `Refused` when a layer will not validate or holds a shape on no net.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn net_pair_spacing(
    store: &GeometryStore,
    nets: &NetTable,
    rule: StrId,
    (a, b): (LayerId, Option<LayerId>),
    widest: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
    need: impl Fn(NetId, NetId) -> Option<Option<Dbu>>,
) -> Verdict {
    let unnetted = std::iter::once(a).chain(b).any(|layer| {
        store
            .polys_on_layer(layer)
            .any(|row| nets.net_of(PolyId(row)) == NetId::NONE)
    });
    if unnetted {
        return REFUSED;
    }
    let one_layer = match b {
        None => {
            if !prepare(store, a, widest, s) {
                return REFUSED;
            }
            true
        }
        Some(b) => {
            if s.validated.get(store, a).is_none() || s.validated.get(store, b).is_none() {
                return REFUSED;
            }
            SpatialIndex::build_into(store, a, &mut s.index_a);
            SpatialIndex::build_into(store, b, &mut s.index_b);
            cross_layer_pairs_into(store, &s.index_a, &s.index_b, widest, &mut s.pairs);
            pair_distances_into(store, &s.pairs, widest, &mut s.dists);
            s.holes.build(store, [a, b]);
            join_nested(store, &s.holes, &s.pairs, &mut s.dists);
            false
        }
    };
    let first_row = store.polys_on_layer(a).start;
    let label = |row: PolyId| s.labels[(row.0 - first_row) as usize];
    let mut examined = 0u64;
    for (&(p, q), &d2) in s.pairs.iter().zip(&s.dists) {
        if one_layer && label(p) == label(q) {
            continue;
        }
        let Some(limit) = need(nets.net_of(p), nets.net_of(q)) else {
            continue;
        };
        examined += 1;
        if let Some(limit) = limit.filter(|&limit| d2 < limit.mul_wide(limit)) {
            let found = (d2, whole_at(store, (p, q), d2));
            out.push(spacing_violation(rule, a, (p, q), found, limit));
        }
    }
    (Outcome::Ran, examined)
}

/// Spacing by table: each separate pair is held, in each width row either
/// shape reaches (measured from that shape's part at least as wide; row 0 from
/// the whole shape), to the cell of the last column whose run it exceeds, the
/// run read off the merged figures' edges facing each other at most that
/// cell apart ([`run_within`]). A pair reports once, at its highest failing row.
/// `examined` counts separate pairs.
pub(crate) fn spacing_table(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    table: &SpacingTable,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let widest = *table.space.last().expect("a valid table has a cell");
    if !prepare_merged(store, layer, widest, s) {
        return REFUSED;
    }
    let drawn = s
        .validated
        .get(store, layer)
        .expect("`prepare` validated it");
    s.rects_a.build(store, layer, drawn);
    let first_row = store.polys_on_layer(layer).start;
    // Per width row above the first: each polygon's parts wider than the row's width.
    let mut rows = Vec::with_capacity(table.width.len() - 1);
    let mut wide = Vec::new();
    for &width in &table.width[1..] {
        if wide_rects_into(drawn, width + Dbu::new_unchecked(1), &mut wide).is_err() {
            return REFUSED;
        }
        rows.push(wide_parts(
            &s.rects_a,
            &s.labels,
            first_row,
            &wide,
            Dbu::new_unchecked(0),
        ));
    }
    let runs = facing_runs(store, layer, widest, s);
    let polys = &s.rects_a;
    let poly_of = |row: PolyId| polys.poly_of_row[(row.0 - first_row) as usize] as usize;
    let label = |row: PolyId| s.labels[(row.0 - first_row) as usize];

    let mut examined = 0u64;
    for (&(a, b), &whole) in s.pairs.iter().zip(&s.dists) {
        let separate = label(a) != label(b) && poly_of(a) != poly_of(b);
        if !separate {
            continue;
        }
        examined += 1;
        // A row's column: the last whose run, within that row's cell, it exceeds.
        let column = |row: usize| {
            (1..table.prl.len())
                .rev()
                .find(|&c| {
                    table.prl[c].raw() < run_within(&runs, label(a), label(b), table.at(row, c))
                })
                .unwrap_or(0)
        };
        let (axs, ays) = store.poly_verts(a);
        let (bxs, bys) = store.poly_verts(b);
        let failed = (1..table.width.len()).rev().find_map(|row| {
            let (parts, start) = &rows[row - 1];
            let of = |poly: usize| &parts[start[poly] as usize..start[poly + 1] as usize];
            let (wide_a, wide_b) = (of(poly_of(a)), of(poly_of(b)));
            if wide_a.is_empty() && wide_b.is_empty() {
                return None;
            }
            let d2 = rects_ring_dist2(wide_a, bxs, bys).min(rects_ring_dist2(wide_b, axs, ays));
            let need = table.at(row, column(row));
            let d2 = DbuArea::new(d2);
            (d2 < need.mul_wide(need))
                .then(|| ((d2, wide_at(store, (a, b), (wide_a, wide_b), d2)), need))
        });
        let need = table.at(0, column(0));
        let failed = failed.or_else(|| {
            (whole < need.mul_wide(need)).then(|| ((whole, whole_at(store, (a, b), whole)), need))
        });
        if let Some((found, need)) = failed {
            out.push(spacing_violation(rule, layer, (a, b), found, need));
        }
    }
    (Outcome::Ran, examined)
}

/// Parallel-run-length spacing, the run that of the merged figures' facing
/// edges at most `limit` apart ([`run_within`]). `examined` counts separate
/// pairs whose run reaches `threshold`.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn prl_spacing(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    threshold: Dbu,
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    if !prepare_merged(store, layer, limit, s) {
        return REFUSED;
    }
    let drawn = s
        .validated
        .get(store, layer)
        .expect("`prepare` validated it");
    s.rects_a.build(store, layer, drawn);
    let runs = facing_runs(store, layer, limit, s);
    let first_row = store.polys_on_layer(layer).start;
    let label = |row: PolyId| s.labels[(row.0 - first_row) as usize];
    let examined = judged_pairs(
        store,
        rule,
        layer,
        limit,
        s,
        out,
        |a, b, d2| (run_within(&runs, label(a), label(b), limit) >= threshold.raw()).then_some(d2),
        |a, b, d2| whole_at(store, (a, b), d2),
    );
    (Outcome::Ran, examined)
}

/// Corner-to-corner spacing between convex corners of the merged layer that
/// face each other (pairs facing only across an edge are `min_spacing`'s).
/// `examined` counts separate pairs with facing corners.
pub(crate) fn corner_to_corner(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    if !prepare_merged(store, layer, limit, s) {
        return REFUSED;
    }
    let figures = &s.layer_out;
    let mut corners: Vec<Corner> = (0..u32::try_from(figures.len())
        .expect("a layer indexes polygons with a u32"))
        .flat_map(|idx| figures.poly_rings(idx))
        .flat_map(|ring| {
            let (xs, ys) = ring.coords();
            convex_corners(xs, ys)
        })
        .collect();
    corners.sort_unstable();
    let examined = judged_pairs(
        store,
        rule,
        layer,
        limit,
        s,
        out,
        |a, b, _| corner_gap(store, a, b, &corners).map(|(d2, _)| d2),
        |a, b, d2| marker(store, (a, b), d2, corner_gap(store, a, b, &corners)),
    );
    (Outcome::Ran, examined)
}

/// A convex corner: its vertex, then the diagonal it faces out along, each
/// component `±1`.
type Corner = (i64, i64, i64, i64);

/// The convex corners of a ring wound with its material on the left (a store
/// row or a merged ring): the vertices where it turns left.
fn convex_corners<'a>(xs: &'a [Dbu], ys: &'a [Dbu]) -> impl Iterator<Item = Corner> + 'a {
    let n = xs.len();
    (0..n).filter_map(move |i| {
        let (back, next) = ((i + n - 1) % n, (i + 1) % n);
        let (inx, iny) = (xs[i].raw() - xs[back].raw(), ys[i].raw() - ys[back].raw());
        let (outx, outy) = (xs[next].raw() - xs[i].raw(), ys[next].raw() - ys[i].raw());
        let left = i128::from(inx) * i128::from(outy) > i128::from(iny) * i128::from(outx);
        // Outward: along the edge coming in, against the one leaving.
        left.then_some((
            xs[i].raw(),
            ys[i].raw(),
            (inx - outx).signum(),
            (iny - outy).signum(),
        ))
    })
}

/// The nearest convex corners of the merged layer (`corners`, sorted) that
/// face each other, one at a vertex of `a` and one at a vertex of `b`: each
/// beyond the other on both axes, out along its own diagonal. Their squared
/// distance and midpoint ([`nearest`]), or `None` when there are none.
fn corner_gap(
    store: &GeometryStore,
    a: PolyId,
    b: PolyId,
    corners: &[Corner],
) -> Option<(DbuArea, Point)> {
    let merged = |row: PolyId| {
        let (xs, ys) = store.poly_verts(row);
        convex_corners(xs, ys).filter(move |corner| corners.binary_search(corner).is_ok())
    };
    let theirs: Vec<Corner> = merged(b).collect();
    let point = |x: i64, y: i64| {
        let p = Point {
            x: Dbu::new_unchecked(x),
            y: Dbu::new_unchecked(y),
        };
        Seg { a: p, b: p }
    };
    nearest(merged(a).flat_map(|(x, y, sx, sy)| {
        theirs.iter().filter_map(move |&(bx, by, bsx, bsy)| {
            let facing =
                (bx - x).signum() == sx && (by - y).signum() == sy && (bsx, bsy) == (-sx, -sy);
            facing.then(|| (point(x, y), point(bx, by)))
        })
    }))
}

/// Wide-metal spacing, measured from the wide part of a shape: the region
/// where a `threshold` square fits in the merged layer (sky130 `huge_met1 =
/// met1.sized(-1.5).sized(1.5)`), not the whole shape, grown by `attached`
/// (square corners) within the shape's own figure (sky130 m1.3a "attached to
/// or extending from `huge_met1` for a distance of up to 0.28 µm"). A plate with
/// a thin tab is still wide where the plate is. `examined` counts separate
/// pairs where either polygon has a wide part.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn wide_dependent(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    (threshold, attached): (Dbu, Dbu),
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    if !prepare(store, layer, limit, s) {
        return REFUSED;
    }
    let drawn = s
        .validated
        .get(store, layer)
        .expect("`prepare` validated it");
    let mut wide = Vec::new();
    if wide_rects_into(drawn, threshold, &mut wide).is_err() {
        return REFUSED;
    }
    s.rects_a.build(store, layer, drawn);
    let first_row = store.polys_on_layer(layer).start;
    let (parts, part_start) = wide_parts(&s.rects_a, &s.labels, first_row, &wide, attached);
    let polys = &s.rects_a;
    let wide_of = |row: PolyId| {
        let poly = polys.poly_of_row[(row.0 - first_row) as usize] as usize;
        &parts[part_start[poly] as usize..part_start[poly + 1] as usize]
    };

    let limit2 = limit.mul_wide(limit).raw();
    let mut examined = 0u64;
    for &(a, b) in &s.pairs {
        // A hole row and its own outer are one polygon, never a spacing pair.
        let poly_of = |row: PolyId| polys.poly_of_row[(row.0 - first_row) as usize];
        let separate = s.labels[(a.0 - first_row) as usize] != s.labels[(b.0 - first_row) as usize]
            && poly_of(a) != poly_of(b);
        let (wide_a, wide_b) = (wide_of(a), wide_of(b));
        if !separate || (wide_a.is_empty() && wide_b.is_empty()) {
            continue;
        }
        examined += 1;
        let ring = |row: PolyId| store.poly_verts(row);
        let (axs, ays) = ring(a);
        let (bxs, bys) = ring(b);
        let d2 = rects_ring_dist2(wide_a, bxs, bys).min(rects_ring_dist2(wide_b, axs, ays));
        if d2 < limit2 {
            let d2 = DbuArea::new(d2);
            let found = (d2, wide_at(store, (a, b), (wide_a, wide_b), d2));
            out.push(spacing_violation(rule, layer, (a, b), found, limit));
        }
    }
    (Outcome::Ran, examined)
}
