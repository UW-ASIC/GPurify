//! Spacing family: how close two shapes may come.
//!
//! Data in: one layer (two for `min_spacing_diff`), indexed and pruned at the
//! rule's own limit — never narrower, or a dropped pair reports clean.
//! Data out: one violation per offending pair, at the midpoint of the gap. Pairs
//! within one merged figure (touching shapes) have no gap and are skipped.

use super::{
    gap_midpoint, join_nested, label_pairs_into, pair_distances_into, rects_ring_dist2, ring_segs,
    seg_bbox, LayerRects, SortedRects, Verdict, REFUSED,
};
use crate::drc::rules::width::wide_rects_into;
use crate::drc::ruleset::SpacingTable;
use crate::drc::Scratch;
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use crate::topology::{NetId, NetTable};
use gpurify_geom::connectivity::ComponentLabel;
use gpurify_geom::index::{candidate_pairs_into, cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::ops::{isqrt, seg_seg_dist2, winding_of, Seg, Winding};
use gpurify_geom::{Bbox, GeometryStore, LayerId, PolyId};
use gpurify_geom::{Dbu, DbuArea, MAX_ABS_DBU};
use gpurify_ingest::StrId;

/// Signed overlap of two boxes' projections per axis; negative is a gap.
fn projection_overlaps(a: Bbox, b: Bbox) -> (i64, i64) {
    (
        a.xhi.raw().min(b.xhi.raw()) - a.xlo.raw().max(b.xlo.raw()),
        a.yhi.raw().min(b.yhi.raw()) - a.ylo.raw().max(b.ylo.raw()),
    )
}

fn spacing_violation(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    (a, b): (PolyId, PolyId),
    dist2: DbuArea,
    limit: Dbu,
) -> Violation {
    Violation {
        rule,
        layer,
        severity: Severity::Error,
        at: gap_midpoint(store.poly_bbox(a), store.poly_bbox(b)),
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

/// The one same-layer kernel: every candidate pair in two different figures that
/// `judge` accepts is examined, and reported when closer than `limit`. Returns
/// the examined count.
fn judged_pairs(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    limit: Dbu,
    s: &Scratch,
    out: &mut Violations,
    judge: impl Fn(PolyId, PolyId) -> bool,
) -> u64 {
    let first_row = store.polys_on_layer(layer).start;
    let limit2 = limit.mul_wide(limit);
    let mut examined = 0u64;
    for (&(a, b), &d2) in s.pairs.iter().zip(&s.dists) {
        let separate = s.labels[(a.0 - first_row) as usize] != s.labels[(b.0 - first_row) as usize];
        if separate && judge(a, b) {
            examined += 1;
            if d2 < limit2 {
                out.push(spacing_violation(store, rule, layer, (a, b), d2, limit));
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
    judged_pairs(store, rule, layer, limit, s, out, |_, _| true);
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
            out.push(spacing_violation(store, rule, a_layer, pair, d2, limit));
        }
    }
    (Outcome::Ran, s.pairs.len() as u64)
}

/// End-of-line spacing. `examined` counts separate pairs where either shape has
/// an end of line facing the other.
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
    if !prepare(store, layer, limit, s) {
        return REFUSED;
    }
    let first_row = store.polys_on_layer(layer).start;
    let limit2 = limit.mul_wide(limit);
    let mut examined = 0u64;
    for &(a, b) in &s.pairs {
        if s.labels[(a.0 - first_row) as usize] == s.labels[(b.0 - first_row) as usize] {
            continue;
        }
        let hit = eol_hit(store, a, b, eol_width, limit)
            .into_iter()
            .chain(eol_hit(store, b, a, eol_width, limit))
            .min();
        if let Some(d2) = hit {
            examined += 1;
            if d2 < limit2 {
                out.push(spacing_violation(store, rule, layer, (a, b), d2, limit));
            }
        }
    }
    (Outcome::Ran, examined)
}

/// The keep-out an end of line projects: its span pushed `depth` out along its
/// outward normal, clamped to the coordinate domain.
fn eol_zone(edge: Seg, normal_sign: i64, depth: Dbu) -> Bbox {
    let (dx, dy) = (
        edge.b.x.raw() - edge.a.x.raw(),
        edge.b.y.raw() - edge.a.y.raw(),
    );
    // Outward normal of a counter-clockwise boundary: direction turned clockwise.
    let (nx, ny) = (normal_sign * dy.signum(), -normal_sign * dx.signum());
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

/// Closest approach between an end of line of `eol` and `other` inside its
/// keep-out; `None` when `eol` has no end of line (an edge shorter than
/// `eol_width`, axis-aligned) reaching `other`.
fn eol_hit(
    store: &GeometryStore,
    eol: PolyId,
    other: PolyId,
    eol_width: Dbu,
    limit: Dbu,
) -> Option<DbuArea> {
    let (xs, ys) = store.poly_verts(eol);
    let (oxs, oys) = store.poly_verts(other);
    let normal_sign = match winding_of(xs, ys)? {
        Winding::CounterClockwise => 1,
        Winding::Clockwise => -1,
    };
    let width2 = eol_width.mul_wide(eol_width);

    let mut best: Option<DbuArea> = None;
    for edge in ring_segs(xs, ys) {
        let (dx, dy) = (
            edge.b.x.raw() - edge.a.x.raw(),
            edge.b.y.raw() - edge.a.y.raw(),
        );
        let len2 = DbuArea::new(i128::from(dx) * i128::from(dx) + i128::from(dy) * i128::from(dy));
        if len2 >= width2 || (dx != 0 && dy != 0) {
            continue;
        }
        let zone = eol_zone(edge, normal_sign, limit);
        for far in ring_segs(oxs, oys) {
            if zone.overlaps(seg_bbox(far)) {
                let dist2 = seg_seg_dist2(edge, far);
                best = Some(best.map_or(dist2, |seen| seen.min(dist2)));
            }
        }
    }
    best
}

/// How far two boxes run alongside each other: the larger projection overlap,
/// clamped to `0 ..= MAX_ABS_DBU`. Boxes over-report the run, which fails closed.
fn parallel_run_length(a: Bbox, b: Bbox) -> Dbu {
    let (along_x, along_y) = projection_overlaps(a, b);
    Dbu::new_unchecked(along_x.max(along_y).clamp(0, MAX_ABS_DBU))
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
    let examined = judged_pairs(store, rule, layer, limit, s, out, |a, b| {
        nets.same_net(a, b) == same_net
    });
    (Outcome::Ran, examined)
}

/// Spacing by table: each separate pair is held to the cell of its run length
/// and of each width row either shape reaches, measured from that shape's
/// part at least as wide (row 0 from the whole shape). A pair reports once,
/// at its highest failing row. `examined` counts separate pairs.
pub(crate) fn spacing_table(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    table: &SpacingTable,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let widest = *table.space.last().expect("a valid table has a cell");
    if !prepare(store, layer, widest, s) {
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
    let polys = &s.rects_a;
    let poly_of = |row: PolyId| polys.poly_of_row[(row.0 - first_row) as usize] as usize;

    let mut examined = 0u64;
    for (&(a, b), &whole) in s.pairs.iter().zip(&s.dists) {
        let separate = s.labels[(a.0 - first_row) as usize] != s.labels[(b.0 - first_row) as usize]
            && poly_of(a) != poly_of(b);
        if !separate {
            continue;
        }
        examined += 1;
        let run = parallel_run_length(store.poly_bbox(a), store.poly_bbox(b));
        let column = table.prl[1..].iter().filter(|&&prl| prl < run).count();
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
            let need = table.at(row, column);
            (d2 < need.mul_wide(need).raw()).then_some((DbuArea::new(d2), need))
        });
        let need = table.at(0, column);
        let failed = failed.or_else(|| (whole < need.mul_wide(need)).then_some((whole, need)));
        if let Some((d2, need)) = failed {
            out.push(spacing_violation(store, rule, layer, (a, b), d2, need));
        }
    }
    (Outcome::Ran, examined)
}

/// Parallel-run-length spacing. `examined` counts separate pairs whose run
/// reaches `threshold`.
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
    if !prepare(store, layer, limit, s) {
        return REFUSED;
    }
    let examined = judged_pairs(store, rule, layer, limit, s, out, |a, b| {
        parallel_run_length(store.poly_bbox(a), store.poly_bbox(b)) >= threshold
    });
    (Outcome::Ran, examined)
}

/// Corner-to-corner spacing: only pairs overlapping on neither axis (the rest
/// are `min_spacing`'s). `examined` counts those diagonal separate pairs.
pub(crate) fn corner_to_corner(
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
    let examined = judged_pairs(store, rule, layer, limit, s, out, |a, b| {
        let (along_x, along_y) = projection_overlaps(store.poly_bbox(a), store.poly_bbox(b));
        along_x < 0 && along_y < 0
    });
    (Outcome::Ran, examined)
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
            out.push(spacing_violation(
                store,
                rule,
                layer,
                (a, b),
                DbuArea::new(d2),
                limit,
            ));
        }
    }
    (Outcome::Ran, examined)
}
