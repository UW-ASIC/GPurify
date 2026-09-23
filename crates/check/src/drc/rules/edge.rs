//! Edge family: checks on an edge layer (`diff.edges() not tap.edges()`).
//!
//! Data in: the store's axis-aligned edges, each with its shape on the left.
//! Data out: one violation per offending edge or edge pair, at the edge's
//! midpoint or the gap's. An edge has no store row, so a finding names none
//! (`PolyId(u32::MAX)`). A non-axis-aligned edge is `Refused`.

use super::{centre, gap_midpoint, seg_bbox, SortedRects, Verdict, REFUSED};
use crate::drc::Scratch;
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use gpurify_geom::boolean::union_into;
use gpurify_geom::ops::{isqrt, seg_seg_dist2, Seg};
use gpurify_geom::rects::decompose_into;
use gpurify_geom::MAX_ABS_DBU;
use gpurify_geom::{Bbox, Dbu, DbuArea, GeometryStore, LayerId, PolyId, ValidatedLayer};
use gpurify_ingest::StrId;

const NO_SHAPE: PolyId = PolyId(u32::MAX);

fn axis_aligned(edges: &[Seg]) -> bool {
    edges.iter().all(|e| e.a.x == e.b.x || e.a.y == e.b.y)
}

fn length(e: Seg) -> Dbu {
    let b = seg_bbox(e);
    (b.xhi - b.xlo) + (b.yhi - b.ylo)
}

/// An edge shorter than `limit` (sky130 difftap.4 "min. tap bound by
/// diffusion", on the butting edges). `examined` counts edges.
pub(crate) fn min_length(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    limit: Dbu,
    out: &mut Violations,
) -> Verdict {
    let edges = store.edges_on_layer(layer);
    if !axis_aligned(edges) {
        return REFUSED;
    }
    for &e in edges {
        let measured = length(e);
        if measured < limit {
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: centre(seg_bbox(e)),
                measured: Measurement::Length(measured),
                limit: Measurement::Length(limit),
                shapes: (NO_SHAPE, None),
            });
        }
    }
    (Outcome::Ran, edges.len() as u64)
}

/// Edge pairs `(i into a, j into b)` whose boxes come within `limit` on both
/// axes; `i < j` when `b` is `a` itself.
fn near_pairs(a: &[Seg], b: &[Seg], same: bool, limit: Dbu) -> Vec<(usize, usize)> {
    let mut by_xlo: Vec<(Bbox, usize)> = b.iter().map(|&e| seg_bbox(e)).zip(0..).collect();
    by_xlo.sort_unstable_by_key(|&(r, _)| r.xlo);
    let reach = by_xlo
        .iter()
        .map(|(r, _)| (r.xhi - r.xlo).raw())
        .max()
        .unwrap_or(0);
    let mut pairs = Vec::new();
    for (i, &e) in a.iter().enumerate() {
        let r = seg_bbox(e);
        let lo = by_xlo.partition_point(|(q, _)| q.xlo.raw() < r.xlo.raw() - reach - limit.raw());
        let hi = by_xlo.partition_point(|(q, _)| q.xlo.raw() <= r.xhi.raw() + limit.raw());
        for &(q, j) in &by_xlo[lo..hi.max(lo)] {
            let near = q.xlo.raw() - r.xhi.raw() < limit.raw()
                && r.xlo.raw() - q.xhi.raw() < limit.raw()
                && q.ylo.raw() - r.yhi.raw() < limit.raw()
                && r.ylo.raw() - q.yhi.raw() < limit.raw();
            if near && (!same || i < j) {
                pairs.push((i, j));
            }
        }
    }
    pairs.sort_unstable();
    pairs
}

/// Two parallel edges closer than `limit`, measured edge to edge (euclidean,
/// so also end to end), whatever side their shapes are on. Edges that touch
/// are not a spacing, and perpendicular edges are not measured, as `KLayout`'s
/// default (sky130 difftap.5 and .7). `b` is `None` for pairs within `a`.
/// `examined` counts the parallel pairs measured.
pub(crate) fn spacing(
    store: &GeometryStore,
    rule: StrId,
    a: LayerId,
    b: Option<LayerId>,
    limit: Dbu,
    out: &mut Violations,
) -> Verdict {
    let first = store.edges_on_layer(a);
    let second = b.map_or(first, |b| store.edges_on_layer(b));
    if !axis_aligned(first) || !axis_aligned(second) {
        return REFUSED;
    }
    let limit2 = limit.mul_wide(limit);
    let horizontal = |e: Seg| e.a.y == e.b.y;
    let mut pairs = near_pairs(first, second, b.is_none(), limit);
    pairs.retain(|&(i, j)| horizontal(first[i]) == horizontal(second[j]));
    for &(i, j) in &pairs {
        let d2 = seg_seg_dist2(first[i], second[j]);
        if d2.raw() > 0 && d2 < limit2 {
            out.push(Violation {
                rule,
                layer: a,
                severity: Severity::Error,
                at: gap_midpoint(seg_bbox(first[i]), seg_bbox(second[j])),
                measured: Measurement::Length(isqrt(d2)),
                limit: Measurement::Length(limit),
                shapes: (NO_SHAPE, None),
            });
        }
    }
    (Outcome::Ran, pairs.len() as u64)
}

/// The strip `depth` deep on the outer side of an axis-aligned edge (its
/// shape is on the left), and the axis its depth runs along: `(strip, along_y,
/// sign)` with `sign` +1 when depth grows with the coordinate.
fn strip(e: Seg, depth: Dbu) -> (Bbox, bool, i64) {
    let clamp = |v: i64| Dbu::new_unchecked(v.clamp(-MAX_ABS_DBU, MAX_ABS_DBU));
    let b = seg_bbox(e);
    let d = depth.raw();
    if e.a.y == e.b.y {
        // Travelling +x the shape is above, so outside is below.
        let sign = if e.b.x > e.a.x { -1 } else { 1 };
        let y = e.a.y.raw();
        let (ylo, yhi) = if sign < 0 { (y - d, y) } else { (y, y + d) };
        let r = Bbox {
            ylo: clamp(ylo),
            yhi: clamp(yhi),
            ..b
        };
        (r, true, sign)
    } else {
        // Travelling +y the shape is to the left, so outside is to the right.
        let sign = if e.b.y > e.a.y { 1 } else { -1 };
        let x = e.a.x.raw();
        let (xlo, xhi) = if sign < 0 { (x - d, x) } else { (x, x + d) };
        let r = Bbox {
            xlo: clamp(xlo),
            xhi: clamp(xhi),
            ..b
        };
        (r, false, sign)
    }
}

/// How deep `outer` covers the strip outside `e` without a gap: the depth of
/// the first slice across the strip that `outer` does not cover, or `depth`.
fn covered_depth(e: Seg, depth: Dbu, outer: &SortedRects<()>) -> Dbu {
    let (band, along_y, sign) = strip(e, depth);
    let clips: Vec<Bbox> = outer.overlapping(band).map(|(clip, ())| clip).collect();
    let origin = if along_y { e.a.y.raw() } else { e.a.x.raw() };
    let depth_of = |v: Dbu| (v.raw() - origin) * sign;
    // Coverage across a slice changes only at a clip's near or far side.
    let mut cuts: Vec<i64> = vec![0, depth.raw()];
    for c in &clips {
        let (lo, hi) = if along_y {
            (c.ylo, c.yhi)
        } else {
            (c.xlo, c.xhi)
        };
        cuts.push(depth_of(lo));
        cuts.push(depth_of(hi));
    }
    cuts.sort_unstable();
    cuts.dedup();
    let at = |t: i64| Dbu::new_unchecked(origin + sign * t);
    for pair in cuts.windows(2) {
        let (near, far) = (at(pair[0]), at(pair[1]));
        let slice = if along_y {
            Bbox {
                ylo: near.min(far),
                yhi: near.max(far),
                ..band
            }
        } else {
            Bbox {
                xlo: near.min(far),
                xhi: near.max(far),
                ..band
            }
        };
        let covered = clips
            .iter()
            .filter_map(|&c| c.intersection(slice))
            .fold(DbuArea::new(0), |sum, c| sum + c.area());
        if covered != slice.area() {
            return Dbu::new_unchecked(pair[0]);
        }
    }
    depth
}

/// Each edge enclosed by `outer` by at least `limit`, measured straight out
/// from the edge across its own length (projection), on the side away from
/// its shape (sky130 n/psd.5a "enclosure of diff by nsdm, except for butting
/// edge"). `examined` counts edges.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn enclosure(
    store: &GeometryStore,
    rule: StrId,
    edges: LayerId,
    outer: LayerId,
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let list = store.edges_on_layer(edges);
    let Some(drawn) = s.validated.get(store, outer) else {
        return REFUSED;
    };
    if !axis_aligned(list) {
        return REFUSED;
    }
    let mut figures = ValidatedLayer::default();
    if union_into(drawn, &ValidatedLayer::default(), &mut figures).is_err() {
        return REFUSED;
    }
    let (mut rects, mut start) = (Vec::new(), Vec::new());
    decompose_into(&figures, &mut rects, &mut start);
    let outer_rects = SortedRects::new(rects.into_iter().map(|r| (r, ())).collect());
    for &e in list {
        if e.a == e.b {
            continue;
        }
        let measured = covered_depth(e, limit, &outer_rects);
        if measured < limit {
            out.push(Violation {
                rule,
                layer: edges,
                severity: Severity::Error,
                at: centre(seg_bbox(e)),
                measured: Measurement::Length(measured),
                limit: Measurement::Length(limit),
                shapes: (NO_SHAPE, None),
            });
        }
    }
    (Outcome::Ran, list.len() as u64)
}
