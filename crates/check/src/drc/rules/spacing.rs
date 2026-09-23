//! Spacing family: how close two shapes may come.
//!
//! Data in: one layer (two for `min_spacing_diff`), indexed and pruned at the
//! rule's own limit — never narrower, or a dropped pair reports clean.
//! Data out: one violation per offending pair, at the midpoint of the gap. Pairs
//! within one merged figure (touching shapes) have no gap and are skipped.

use super::{
    gap_midpoint, label_pairs_into, pair_distances_into, ring_segs, seg_bbox, Verdict, REFUSED,
};
use crate::drc::rules::width::narrowest_width;
use crate::drc::Scratch;
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use gpurify_geom::index::{candidate_pairs_into, cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::ops::{isqrt, seg_seg_dist2, winding_of, Seg, Winding};
use gpurify_geom::view::validate_layer_into;
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
    if validate_layer_into(store, layer, &mut s.layer_a).is_err() {
        return false;
    }
    let rows = store.polys_on_layer(layer);
    SpatialIndex::build_into(store, layer, &mut s.index_a);
    candidate_pairs_into(store, &s.index_a, limit, &mut s.pairs);
    pair_distances_into(store, &s.pairs, &mut s.dists);
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
    if validate_layer_into(store, a_layer, &mut s.layer_a).is_err()
        || validate_layer_into(store, b_layer, &mut s.layer_b).is_err()
    {
        return REFUSED;
    }
    SpatialIndex::build_into(store, a_layer, &mut s.index_a);
    SpatialIndex::build_into(store, b_layer, &mut s.index_b);
    cross_layer_pairs_into(store, &s.index_a, &s.index_b, limit, &mut s.pairs);
    pair_distances_into(store, &s.pairs, &mut s.dists);
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

/// Wide-metal spacing. `examined` counts separate pairs with a wide member.
///
/// Known imprecision (fails closed): a hole row gets the *layer's* "any wide"
/// verdict, since `ValidatedLayer` has no hole-to-polygon provenance.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn wide_dependent(
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
    // One flag per store row; counter-clockwise rows are the validated polygons, in order.
    const HOLE: u8 = 2;
    let rows = store.polys_on_layer(layer);
    s.bytes.clear();
    let mut outers = 0u32;
    for row in rows.clone() {
        let (xs, ys) = store.poly_verts(PolyId(row));
        if matches!(winding_of(xs, ys), Some(Winding::CounterClockwise)) {
            let width = narrowest_width(s.layer_a.get(outers), &mut s.facing);
            s.bytes.push(u8::from(width >= threshold));
            outers += 1;
        } else {
            s.bytes.push(HOLE);
        }
    }
    let any_wide = s.bytes.iter().fold(0, |acc, &flag| acc | (flag & 1));
    for flag in &mut s.bytes {
        *flag = if *flag == HOLE { any_wide } else { *flag };
    }

    let first_row = rows.start;
    let wide = &s.bytes;
    let examined = judged_pairs(store, rule, layer, limit, s, out, |a, b| {
        (wide[(a.0 - first_row) as usize] | wide[(b.0 - first_row) as usize]) != 0
    });
    (Outcome::Ran, examined)
}
