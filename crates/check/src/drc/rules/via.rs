//! Via family: vias as a population, counted on geometry (not nets).
//!
//! Data in: one cut layer (not validated) and its candidate pairs with exact
//! boundary distances. Data out: under-served cuts, or too-close pairs inside
//! an array cluster or around a cut with many neighbours.

use super::spacing::whole_at;
use super::width::wide_rects_into;
use super::{
    bbox_gap2, centre, join_nested, label_pairs_into, merged, pair_distances_into, SortedRects,
    Verdict, REFUSED,
};
use crate::drc::{CutClassTable, Scratch};
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use gpurify_geom::connectivity::components_into;
use gpurify_geom::index::{candidate_pairs_into, SpatialIndex};
use gpurify_geom::ops::{isqrt, Point};
use gpurify_geom::rects::decompose_into;
use gpurify_geom::{Bbox, Dbu, DbuArea, GeometryStore, LayerId, PolyId, ValidatedLayer};
use gpurify_ingest::StrId;

fn measured_pairs(store: &GeometryStore, layer: LayerId, radius: Dbu, s: &mut Scratch) {
    SpatialIndex::build_into(store, layer, &mut s.index_a);
    candidate_pairs_into(store, &s.index_a, radius, &mut s.pairs);
    pair_distances_into(store, &s.pairs, radius, &mut s.dists);
}

/// Every cut needs `min_count` cuts (itself included) within `within`, nearest
/// point to nearest point. One violation per under-served cut, at its centre.
/// `examined` counts cuts.
pub(crate) fn redundant_via(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    min_count: u16,
    within: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let cuts = store.polys_on_layer(layer);
    measured_pairs(store, layer, within, s);
    let within2 = within.mul_wide(within);
    // `rect_start` doubles as the per-cut neighbour counter.
    s.rect_start.clear();
    s.rect_start.resize((cuts.end - cuts.start) as usize, 0);
    for (&(a, b), &d2) in s.pairs.iter().zip(&s.dists) {
        if d2 <= within2 {
            s.rect_start[(a.0 - cuts.start) as usize] += 1;
            s.rect_start[(b.0 - cuts.start) as usize] += 1;
        }
    }
    let min_count = u32::from(min_count);
    for (row, &neighbours) in cuts.clone().zip(&s.rect_start) {
        let count = neighbours + 1;
        if count < min_count {
            let cut = PolyId(row);
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: centre(store.poly_bbox(cut)),
                measured: Measurement::Count(count),
                limit: Measurement::Count(min_count),
                shapes: (cut, None),
            });
        }
    }
    (Outcome::Ran, u64::from(cuts.end - cuts.start))
}

/// Clusters (components of "within `limit`") larger than `threshold` are arrays;
/// every pair inside one is held to `limit`. One violation per offending pair,
/// at the midpoint of the pair's nearest points, as the spacing family marks.
/// `examined` counts pairs inside a qualifying cluster.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn via_array_spacing(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    threshold: u16,
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let cuts = store.polys_on_layer(layer);
    let n = cuts.end - cuts.start;
    measured_pairs(store, layer, limit, s);
    let limit2 = limit.mul_wide(limit);
    let Scratch {
        pairs,
        dists,
        edges,
        labels,
        rect_start,
        ..
    } = s;
    label_pairs_into(
        cuts.start,
        n,
        pairs,
        dists,
        |d2| d2 <= limit2,
        edges,
        labels,
    );

    // Cluster populations, keyed by the label (the minimum member offset).
    rect_start.clear();
    rect_start.resize(n as usize, 0);
    for label in labels.iter() {
        rect_start[label.0 as usize] += 1;
    }

    let threshold = u32::from(threshold);
    let mut examined = 0u64;
    for (&(a, b), &d2) in pairs.iter().zip(dists.iter()) {
        let la = labels[(a.0 - cuts.start) as usize];
        let lb = labels[(b.0 - cuts.start) as usize];
        // Strictly larger: *at* the threshold is not yet an array.
        if la != lb || rect_start[la.0 as usize] <= threshold {
            continue;
        }
        examined += 1;
        if d2 < limit2 {
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: whole_at(store, (a, b), d2),
                measured: Measurement::Length(isqrt(d2)),
                limit: Measurement::Length(limit),
                shapes: (a, Some(b)),
            });
        }
    }
    (Outcome::Ran, examined)
}

/// Squared distance between two boxes' centres, at twice the scale, so a
/// centre on a half unit is whole: `4 d²`.
fn centres_dist2_x4(a: Bbox, b: Bbox) -> DbuArea {
    let twice = |lo: Dbu, hi: Dbu| i128::from(lo.raw()) + i128::from(hi.raw());
    let dx = twice(a.xlo, a.xhi) - twice(b.xlo, b.xhi);
    let dy = twice(a.ylo, a.yhi) - twice(b.ylo, b.yhi);
    DbuArea::new(dx * dx + dy * dy)
}

/// The midpoint of two boxes' centres, floored.
fn centres_mid(a: Bbox, b: Bbox) -> Point {
    let quarter = |p: Dbu, q: Dbu, r: Dbu, t: Dbu| {
        Dbu::new_unchecked((p.raw() + q.raw() + r.raw() + t.raw()).div_euclid(4))
    };
    Point {
        x: quarter(a.xlo, a.xhi, b.xlo, b.xhi),
        y: quarter(a.ylo, a.yhi, b.ylo, b.yhi),
    }
}

/// LEF cut spacing (`CENTERTOCENTER`, `ADJACENTCUTS n WITHIN w`): every pair
/// closer than `limit` where either cut has at least `adjacent` other cuts
/// strictly closer than `within` (every cut when `adjacent` is 0). Distances
/// are centre to centre with `center`, else boundary to boundary with nested
/// cuts at 0. One violation per offending pair. `examined` counts the cuts
/// held.
pub(crate) fn cut_spacing(
    store: &GeometryStore,
    rule: StrId,
    (layer, center): (LayerId, bool),
    (adjacent, within): (u16, Dbu),
    limit: Dbu,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let cuts = store.polys_on_layer(layer);
    let n = (cuts.end - cuts.start) as usize;
    // A centre lies in its box, so two boxes are never further apart than
    // their centres: pruning boxes at the reach keeps every pair.
    let reach = if adjacent == 0 {
        limit
    } else {
        limit.max(within)
    };
    measured_pairs(store, layer, reach, s);
    // Squared distances; at 2x for centres, so every one compares as `scale d²`.
    let scale: i128 = if center { 4 } else { 1 };
    if center {
        for (&(a, b), d2) in s.pairs.iter().zip(&mut s.dists) {
            *d2 = centres_dist2_x4(store.poly_bbox(a), store.poly_bbox(b));
        }
    } else {
        s.holes.build(store, [layer]);
        join_nested(store, &s.holes, &s.pairs, &mut s.dists);
    }
    // `rect_start` doubles as the per-cut neighbour counter.
    s.rect_start.clear();
    s.rect_start.resize(n, 0);
    let within2 = within.mul_wide(within).raw() * scale;
    if adjacent > 0 {
        for (&(a, b), d2) in s.pairs.iter().zip(&s.dists) {
            if d2.raw() < within2 {
                s.rect_start[(a.0 - cuts.start) as usize] += 1;
                s.rect_start[(b.0 - cuts.start) as usize] += 1;
            }
        }
    }
    let neighbours = &s.rect_start;
    let held = |cut: PolyId| neighbours[(cut.0 - cuts.start) as usize] >= u32::from(adjacent);
    let limit2 = limit.mul_wide(limit).raw() * scale;
    for (&(a, b), &d2) in s.pairs.iter().zip(&s.dists) {
        if d2.raw() >= limit2 || !(held(a) || held(b)) {
            continue;
        }
        let (measured, at) = if center {
            let (ba, bb) = (store.poly_bbox(a), store.poly_bbox(b));
            // floor(sqrt(4 d² / 4)) is floor(d): an integer k has k² ≤ x
            // exactly when k² ≤ floor(x).
            (isqrt(DbuArea::new(d2.raw() / 4)), centres_mid(ba, bb))
        } else {
            (isqrt(d2), whole_at(store, (a, b), d2))
        };
        out.push(Violation {
            rule,
            layer,
            severity: Severity::Error,
            at,
            measured: Measurement::Length(measured),
            limit: Measurement::Length(limit),
            shapes: (a, Some(b)),
        });
    }
    let examined = (0..n)
        .filter(|&i| neighbours[i] >= u32::from(adjacent))
        .count();
    (Outcome::Ran, examined as u64)
}

/// A cut-class spacing table (`LEF58_SPACINGTABLE` with `CUTCLASS` SIDE/END
/// entries): every pair of classed cuts closer than its cell, read as
/// [`Rule::CutClassSpacing`](crate::drc::Rule::CutClassSpacing) says.
/// `examined` counts the pairs of classed cuts within the largest cell.
pub(crate) fn cut_class_spacing(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    table: &CutClassTable,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let reach = *table.space.iter().max().expect("a valid table has cells");
    measured_pairs(store, layer, reach, s);
    s.holes.build(store, [layer]);
    join_nested(store, &s.holes, &s.pairs, &mut s.dists);
    let class = |b: Bbox| table.class_of(b.xhi - b.xlo, b.yhi - b.ylo);
    let wider = |b: Bbox| b.xhi - b.xlo > b.yhi - b.ylo;
    let taller = |b: Bbox| b.yhi - b.ylo > b.xhi - b.xlo;
    let mut examined = 0u64;
    for (&(a, b), &d2) in s.pairs.iter().zip(&s.dists) {
        let (ba, bb) = (store.poly_bbox(a), store.poly_bbox(b));
        let (Some(ca), Some(cb)) = (class(ba), class(bb)) else {
            continue;
        };
        examined += 1;
        // Row and column 2c are class c's END, 2c + 1 its SIDE.
        let cell = |side_a: bool, side_b: bool| {
            table.at(2 * ca + usize::from(side_a), 2 * cb + usize::from(side_b))
        };
        let apart_x = bb.xlo > ba.xhi || ba.xlo > bb.xhi;
        let apart_y = bb.ylo > ba.yhi || ba.ylo > bb.yhi;
        let need = if apart_x || apart_y {
            let across_y = apart_y.then(|| cell(wider(ba), wider(bb)));
            let across_x = apart_x.then(|| cell(taller(ba), taller(bb)));
            across_y.max(across_x).expect("apart along one axis")
        } else {
            [(false, false), (false, true), (true, false), (true, true)]
                .into_iter()
                .map(|(p, q)| cell(p, q))
                .max()
                .expect("four cells")
        };
        if d2 < need.mul_wide(need) {
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: whole_at(store, (a, b), d2),
                measured: Measurement::Length(isqrt(d2)),
                limit: Measurement::Length(need),
                shapes: (a, Some(b)),
            });
        }
    }
    (Outcome::Ran, examined)
}

/// A merged layer's rectangles, each labelled with its figure.
fn figure_rects(figures: &ValidatedLayer) -> SortedRects<u32> {
    let (mut rects, mut start) = (Vec::new(), Vec::new());
    decompose_into(figures, &mut rects, &mut start);
    SortedRects::new(
        start
            .windows(2)
            .zip(0u32..)
            .flat_map(|(span, f)| {
                rects[span[0] as usize..span[1] as usize]
                    .iter()
                    .map(move |&r| (r, f))
            })
            .collect(),
    )
}

/// LEF `MINIMUMCUT`: every via held by the wide part of `wide` (where a
/// `width + 1` square fits) needs `min_count` cuts, a via being the cuts that
/// join one `wide` figure to one `other` figure, split by `within` when given.
/// One violation per cut of a short via. `examined` counts held vias.
pub(crate) fn minimum_cut(
    store: &GeometryStore,
    rule: StrId,
    (cut, wide, other): (LayerId, LayerId, LayerId),
    (width, within): (Dbu, Option<Dbu>),
    min_count: u16,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let (Some(wide_figures), Some(other_figures)) =
        (merged(store, wide, s), merged(store, other, s))
    else {
        return REFUSED;
    };
    let drawn = s.validated.get(store, wide).expect("merged above");
    let mut part = Vec::new();
    if wide_rects_into(drawn, width + Dbu::new_unchecked(1), &mut part).is_err() {
        return REFUSED;
    }
    let part = SortedRects::new(part.into_iter().map(|r| (r, ())).collect());
    let (on_wide, on_other) = (figure_rects(&wide_figures), figure_rects(&other_figures));
    // Each cut on a wide figure, keyed by the figures it joins.
    let mut keyed: Vec<((u32, Option<u32>), PolyId)> = store
        .polys_on_layer(cut)
        .filter_map(|row| {
            let b = store.poly_bbox(PolyId(row));
            let w = on_wide.overlapping(b).map(|(_, f)| f).min()?;
            let o = on_other.overlapping(b).map(|(_, f)| f).min();
            Some(((w, o), PolyId(row)))
        })
        .collect();
    keyed.sort_unstable();
    let within2 = within.map(|d| d.mul_wide(d));
    let mut examined = 0u64;
    let (mut edges, mut labels) = (Vec::new(), Vec::new());
    for via in keyed.chunk_by(|p, q| p.0 == q.0) {
        // Groups of the via's cuts, by `within`.
        edges.clear();
        if let Some(within2) = within2 {
            for (i, &(_, a)) in (0u32..).zip(via) {
                for (j, &(_, b)) in (0u32..).zip(via).skip(i as usize + 1) {
                    if bbox_gap2(store.poly_bbox(a), store.poly_bbox(b)) < within2 {
                        edges.push((i, j));
                    }
                }
            }
        } else {
            edges.extend((1..via.len()).map(|j| (0, u32::try_from(j).expect("few cuts"))));
        }
        components_into(
            u32::try_from(via.len()).expect("a via has few cuts"),
            &edges,
            &mut labels,
        );
        let mut groups: Vec<(u32, PolyId)> = labels
            .iter()
            .zip(via)
            .map(|(label, &(_, row))| (label.0, row))
            .collect();
        groups.sort_unstable();
        for group in groups.chunk_by(|p, q| p.0 == q.0) {
            let held = group
                .iter()
                .any(|&(_, row)| part.overlapping(store.poly_bbox(row)).next().is_some());
            if !held {
                continue;
            }
            examined += 1;
            let cuts = u32::try_from(group.len()).expect("a via has few cuts");
            if cuts < u32::from(min_count) {
                for &(_, row) in group {
                    out.push(Violation {
                        rule,
                        layer: cut,
                        severity: Severity::Error,
                        at: centre(store.poly_bbox(row)),
                        measured: Measurement::Count(cuts),
                        limit: Measurement::Count(u32::from(min_count)),
                        shapes: (row, None),
                    });
                }
            }
        }
    }
    (Outcome::Ran, examined)
}

/// LEF `MAXVIASTACK`: the tallest chain of overlapping cuts, one per layer of
/// `stack` (bottom to top), through each cut; each cut at height
/// `max_height + 1` of a taller chain is reported once. `examined` counts
/// cuts.
pub(crate) fn via_stack(
    store: &GeometryStore,
    rule: StrId,
    stack: &[LayerId],
    max_height: u16,
    out: &mut Violations,
) -> Verdict {
    let cuts: Vec<Vec<(Bbox, PolyId)>> = stack
        .iter()
        .map(|&layer| {
            store
                .polys_on_layer(layer)
                .map(|row| (store.poly_bbox(PolyId(row)), PolyId(row)))
                .collect()
        })
        .collect();
    // Per layer and cut: the tallest chain ending at it from below (`down`)
    // and starting at it upward (`up`).
    let chain = |order: &mut dyn Iterator<Item = usize>, step: isize| {
        let mut heights: Vec<Vec<u32>> = cuts.iter().map(|c| vec![1; c.len()]).collect();
        for i in order {
            let Some(prev) = i.checked_add_signed(-step).filter(|&p| p < cuts.len()) else {
                continue;
            };
            let under = SortedRects::new(
                (0u32..)
                    .zip(&cuts[prev])
                    .map(|(k, &(b, _))| (b, k))
                    .collect(),
            );
            for (c, &(b, _)) in cuts[i].iter().enumerate() {
                let best = under
                    .overlapping(b)
                    .map(|(_, k)| heights[prev][k as usize])
                    .max();
                if let Some(best) = best {
                    heights[i][c] = best + 1;
                }
            }
        }
        heights
    };
    let down = chain(&mut (0..cuts.len()), 1);
    let up = chain(&mut (0..cuts.len()).rev(), -1);
    let over = u32::from(max_height) + 1;
    for (i, layer_cuts) in cuts.iter().enumerate() {
        for (c, &(b, row)) in layer_cuts.iter().enumerate() {
            let tallest = down[i][c] + up[i][c] - 1;
            if down[i][c] == over {
                out.push(Violation {
                    rule,
                    layer: stack[i],
                    severity: Severity::Error,
                    at: centre(b),
                    measured: Measurement::Count(tallest),
                    limit: Measurement::Count(u32::from(max_height)),
                    shapes: (row, None),
                });
            }
        }
    }
    (Outcome::Ran, cuts.iter().map(|c| c.len() as u64).sum())
}
