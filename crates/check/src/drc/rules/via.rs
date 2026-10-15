//! Via family: vias as a population, counted on geometry (not nets).
//!
//! Data in: one cut layer (not validated) and its candidate pairs with exact
//! boundary distances. Data out: under-served cuts, or too-close pairs inside
//! an array cluster or around a cut with many neighbours.

use super::spacing::whole_at;
use super::width::{rects_layer, wide_rects_into};
use super::{
    bbox_gap2, centre, figure_rects, join_nested, label_pairs_into, merged, pair_distances_into,
    SortedRects, Verdict, REFUSED,
};
use crate::drc::ruleset::CutAreaBands;
use crate::drc::{CutClassTable, Scratch};
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use gpurify_geom::boolean::{intersection_into, union_into, BooleanError};
use gpurify_geom::connectivity::components_into;
use gpurify_geom::index::{candidate_pairs_into, SpatialIndex};
use gpurify_geom::ops::{isqrt, Point};
use gpurify_geom::rects::decompose_into;
use gpurify_geom::{
    Bbox, Dbu, DbuArea, GeometryStore, LayerId, PolyId, ValidatedLayer, MAX_ABS_DBU,
};
use gpurify_ingest::StrId;

fn measured_pairs(store: &GeometryStore, layer: LayerId, radius: Dbu, s: &mut Scratch) {
    SpatialIndex::build_into(store, layer, &mut s.index_a);
    candidate_pairs_into(store, &s.index_a, radius, &mut s.pairs);
    pair_distances_into(store, &s.pairs, radius, &mut s.dists);
}

/// `LEF58_MAXSPACING` as `OpenROAD` reads it (DRC-034): every row of `cut`
/// needs another cut (a row of `others`, or of `cut` when `None`, with a
/// different box) whose box centre is at most `limit` from its own. One
/// violation per lonely cut, at its centre. `examined` counts cuts.
pub(crate) fn max_cut_spacing(
    store: &GeometryStore,
    rule: StrId,
    (cut, others): (LayerId, Option<LayerId>),
    limit: Dbu,
    out: &mut Violations,
) -> Verdict {
    // Centres doubled, so a half-unit centre stays exact.
    let doubled = |b: Bbox| ((b.xlo + b.xhi).raw(), (b.ylo + b.yhi).raw());
    let mut near: Vec<((i64, i64), Bbox)> = store
        .polys_on_layer(others.unwrap_or(cut))
        .map(|row| {
            let b = store.poly_bbox(PolyId(row));
            (doubled(b), b)
        })
        .collect();
    near.sort_unstable_by_key(|&((x, y), _)| (x, y));
    let reach = 2 * i128::from(limit.raw());
    let mut examined = 0u64;
    for row in store.polys_on_layer(cut) {
        examined += 1;
        let b = store.poly_bbox(PolyId(row));
        let (cx, cy) = doubled(b);
        // ponytail: a scan of the centres within `limit` along x; quadratic
        // only where many cuts share one column.
        let from = near.partition_point(|&((x, _), _)| i128::from(x) < i128::from(cx) - reach);
        let nearest2 = near[from..]
            .iter()
            .take_while(|&&((x, _), _)| i128::from(x) <= i128::from(cx) + reach)
            .filter(|&&(_, other)| other != b)
            .map(|&((x, y), _)| {
                let (dx, dy) = (i128::from(x - cx), i128::from(y - cy));
                dx * dx + dy * dy
            })
            .min();
        if nearest2.is_some_and(|d2| d2 <= reach * reach) {
            continue;
        }
        let nearest = near
            .iter()
            .filter(|&&(_, other)| other != b)
            .map(|&((x, y), _)| {
                let (dx, dy) = (i128::from(x - cx), i128::from(y - cy));
                dx * dx + dy * dy
            })
            .min();
        let (measured, limit) = match nearest {
            // The doubled distance halved, rounded up.
            Some(d2) => {
                let d = isqrt_up(d2);
                (
                    Measurement::Length(Dbu::new_unchecked(
                        i64::try_from((d + 1) / 2).expect("a distance inside the domain"),
                    )),
                    Measurement::Length(limit),
                )
            }
            None => (Measurement::Count(0), Measurement::Count(1)),
        };
        out.push(Violation {
            rule,
            layer: cut,
            severity: Severity::Error,
            at: centre(b),
            measured,
            limit,
            shapes: (PolyId(row), None),
        });
    }
    (Outcome::Ran, examined)
}

/// The least integer whose square is at least `n`, for `n >= 0`.
fn isqrt_up(n: i128) -> i128 {
    let r = n.isqrt();
    if r * r == n {
        r
    } else {
        r + 1
    }
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

/// LEF `MINIMUMCUT`: every via held by the wide part of `wide` (where a
/// `width + 1` square fits) needs `min_count` cuts, a via being the cuts that
/// join one `wide` figure to one `other` figure, split by `within` when given.
/// With `thin` (`LENGTH length WITHIN distance`), the vias held are instead
/// those on no wide part, on a wide wire's own figure, closer than
/// `distance` to that wire, whose wide region's longer box side exceeds
/// `length`. One violation per cut of a short via. `examined` counts held
/// vias.
pub(crate) fn minimum_cut(
    store: &GeometryStore,
    rule: StrId,
    (cut, wide, other): (LayerId, LayerId, LayerId),
    (width, thin, within): (Dbu, Option<(Dbu, Dbu)>, Option<Dbu>),
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
    let (on_wide, on_other) = (figure_rects(&wide_figures), figure_rects(&other_figures));
    // The wide wires LENGTH holds: regions of the wide part longer than
    // `length`, each rectangle labelled with its `wide` figure.
    let mut long = Vec::new();
    if let Some((length, _)) = thin {
        let mut regions = ValidatedLayer::default();
        let built = rects_layer(&part)
            .and_then(|r| union_into(&r, &ValidatedLayer::default(), &mut regions));
        if built.is_err() {
            return REFUSED;
        }
        let (mut rects, mut start) = (Vec::new(), Vec::new());
        decompose_into(&regions, &mut rects, &mut start);
        for (idx, span) in (0u32..).zip(start.windows(2)) {
            let b = regions.get(idx).bbox();
            if b.width().max(b.height()) <= length {
                continue;
            }
            let pieces = &rects[span[0] as usize..span[1] as usize];
            let Some((_, figure)) = on_wide.overlapping(pieces[0]).next() else {
                continue;
            };
            long.extend(pieces.iter().map(|&r| (r, figure)));
        }
    }
    let part = SortedRects::new(part.into_iter().map(|r| (r, ())).collect());
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
            let on_part =
                |&(_, row): &(u32, PolyId)| part.overlapping(store.poly_bbox(row)).next().is_some();
            let held = match thin {
                None => group.iter().any(on_part),
                // A thin wire's via: on no wide part, near a long wide wire
                // of its own figure.
                Some((_, distance)) => {
                    let figure = via[0].0 .0;
                    let reach = distance.mul_wide(distance);
                    !group.iter().any(on_part)
                        && group.iter().any(|&(_, row)| {
                            let b = store.poly_bbox(row);
                            long.iter()
                                .any(|&(r, f)| f == figure && bbox_gap2(b, r) < reach)
                        })
                }
            };
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

/// A drawn cut: its box and its row.
type Cut = (Bbox, PolyId);

/// The metal figures below and above a cut, `None` where it lands on none.
type Joins = (Option<u32>, Option<u32>);

/// LEF `MAXVIASTACK`: the tallest chain of overlapping cuts, one per layer of
/// `stack` (bottom to top), through each cut; each cut at height
/// `max_height + 1` of a taller chain is reported once. `examined` counts
/// cuts.
pub(crate) fn via_stack(
    store: &GeometryStore,
    rule: StrId,
    (layers, single): (&[LayerId], bool),
    max_height: u16,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let all = |layer: LayerId| -> Vec<(Bbox, PolyId)> {
        store
            .polys_on_layer(layer)
            .map(|row| (store.poly_bbox(PolyId(row)), PolyId(row)))
            .collect()
    };
    // With `single`, the cut layers sit between metals; a cut of a via of
    // two or more cuts (cuts joining the same two metal figures) stacks with
    // nothing.
    let (stack, cuts, examined): (Vec<LayerId>, Vec<Vec<Cut>>, u64) = if single {
        let mut metals = Vec::new();
        for &metal in layers.iter().step_by(2) {
            let Some(figures) = merged(store, metal, s) else {
                return REFUSED;
            };
            metals.push(figure_rects(&figures));
        }
        let stack: Vec<LayerId> = layers.iter().skip(1).step_by(2).copied().collect();
        let mut examined = 0u64;
        let cuts = stack
            .iter()
            .enumerate()
            .map(|(i, &layer)| {
                let on = |b: Bbox, k: usize| metals[k].overlapping(b).map(|(_, f)| f).min();
                let mut keyed: Vec<(Joins, Cut)> = all(layer)
                    .into_iter()
                    .map(|(b, row)| ((on(b, i), on(b, i + 1)), (b, row)))
                    .collect();
                examined += keyed.len() as u64;
                keyed.sort_unstable_by_key(|&(key, (_, row))| (key, row));
                keyed
                    .chunk_by(|p, q| p.0 == q.0)
                    .filter(|via| via.len() == 1)
                    .map(|via| via[0].1)
                    .collect()
            })
            .collect();
        (stack, cuts, examined)
    } else {
        let cuts: Vec<Vec<(Bbox, PolyId)>> = layers.iter().map(|&layer| all(layer)).collect();
        let examined = cuts.iter().map(|c| c.len() as u64).sum();
        (layers.to_vec(), cuts, examined)
    };
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
    (Outcome::Ran, examined)
}

/// Whether `b` is a cut of the class `(short, long)`: that size either way
/// round.
fn of_class(b: Bbox, (short, long): (Dbu, Dbu)) -> bool {
    let (w, h) = (b.xhi - b.xlo, b.yhi - b.ylo);
    w.min(h) == short && w.max(h) == long
}

/// LEF58 `KEEPOUTZONE` as `OpenROAD`'s detailed router checks it
/// (`checKeepOutZone_main`): round each cut of `class` (never square), a
/// side zone (the cut lengthened by `side.1` at each end, widened by
/// `side.0` each side) and an end zone (lengthened by `end.0`, widened by
/// `end.1`); every other cut, of class `to` when given, overlapping either
/// with a positive area is a finding measuring its area inside the two, at
/// the centre of that area's box. `examined` counts the class's cuts.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn keep_out_zone(
    store: &GeometryStore,
    rule: StrId,
    layer: LayerId,
    class: (Dbu, Dbu),
    to: Option<(Dbu, Dbu)>,
    end: (Dbu, Dbu),
    side: (Dbu, Dbu),
    out: &mut Violations,
) -> Verdict {
    let cuts: Vec<(Bbox, PolyId)> = store
        .polys_on_layer(layer)
        .map(|row| (store.poly_bbox(PolyId(row)), PolyId(row)))
        .collect();
    let others = SortedRects::new(
        cuts.iter()
            .copied()
            .filter(|&(b, _)| to.is_none_or(|to| of_class(b, to)))
            .collect(),
    );
    let at = |v: i64| Dbu::new_unchecked(v.clamp(-MAX_ABS_DBU, MAX_ABS_DBU));
    let mut examined = 0u64;
    let mut hits: Vec<(PolyId, Bbox, bool)> = Vec::new();
    for &(b, cut) in cuts.iter().filter(|&&(b, _)| of_class(b, class)) {
        examined += 1;
        let along_x = b.xhi - b.xlo > b.yhi - b.ylo;
        // Grown by `along` on the cut's long axis and `across` on its short one.
        let zone = |along: Dbu, across: Dbu| {
            let (dx, dy) = if along_x {
                (along.raw(), across.raw())
            } else {
                (across.raw(), along.raw())
            };
            Bbox {
                xlo: at(b.xlo.raw() - dx),
                ylo: at(b.ylo.raw() - dy),
                xhi: at(b.xhi.raw() + dx),
                yhi: at(b.yhi.raw() + dy),
            }
        };
        let (side_zone, end_zone) = (zone(side.1, side.0), zone(end.0, end.1));
        hits.clear();
        hits.extend(
            others
                .overlapping(side_zone)
                .map(|(part, o)| (o, part, true)),
        );
        hits.extend(
            others
                .overlapping(end_zone)
                .map(|(part, o)| (o, part, false)),
        );
        hits.retain(|&(o, ..)| o != cut);
        hits.sort_unstable_by_key(|&(o, _, in_side)| (o, !in_side));
        for other in hits.chunk_by(|p, q| p.0 == q.0) {
            // Inside one zone, or inside both less what the two share.
            let shared = match other {
                [(_, s, _), (_, e, _)] => s.intersection(*e).map_or(DbuArea::new(0), Bbox::area),
                _ => DbuArea::new(0),
            };
            let area = other
                .iter()
                .fold(DbuArea::new(0), |sum, &(_, part, _)| sum + part.area())
                - shared;
            let bounds = other
                .iter()
                .fold(Bbox::EMPTY, |sum, &(_, part, _)| sum.union(part));
            out.push(Violation {
                rule,
                layer,
                severity: Severity::Error,
                at: centre(bounds),
                measured: Measurement::Area(area),
                limit: Measurement::Area(DbuArea::new(0)),
                shapes: (cut, Some(other[0].0)),
            });
        }
    }
    (Outcome::Ran, examined)
}

/// The connectors of two merged layers: each pair of a `lower` and an `upper`
/// figure that overlap, its footprint their overlap.
struct Connectors {
    /// The footprint, merged.
    feet: ValidatedLayer,
    /// The footprint's rectangles, each labelled with its piece.
    pieces: SortedRects<u32>,
    /// Per footprint piece, its connector.
    of_piece: Vec<usize>,
    /// Per connector, the box of its footprint.
    bounds: Vec<Bbox>,
    /// Per connector, its `(lower, upper)` figures.
    figures: Vec<(u32, u32)>,
}

impl Connectors {
    fn new(under: &ValidatedLayer, over: &ValidatedLayer) -> Result<Self, BooleanError> {
        let mut feet = ValidatedLayer::default();
        intersection_into(under, over, &mut feet)?;
        let (under, over) = (figure_rects(under), figure_rects(over));
        let (mut rects, mut start) = (Vec::new(), Vec::new());
        decompose_into(&feet, &mut rects, &mut start);
        let pair: Vec<(u32, u32)> = start
            .windows(2)
            .map(|span| {
                let r = rects[span[0] as usize];
                (first_label(&under, r), first_label(&over, r))
            })
            .collect();
        let mut figures = pair.clone();
        figures.sort_unstable();
        figures.dedup();
        let of_piece: Vec<usize> = pair
            .iter()
            .map(|p| figures.binary_search(p).expect("every pair is listed"))
            .collect();
        let mut bounds = vec![Bbox::EMPTY; figures.len()];
        for (piece, &at) in (0u32..).zip(&of_piece) {
            bounds[at] = bounds[at].union(feet.get(piece).bbox());
        }
        Ok(Self {
            pieces: figure_rects(&feet),
            feet,
            of_piece,
            bounds,
            figures,
        })
    }

    /// Per connector, the merged figures of `cuts` overlapping its footprint,
    /// in figure order; a cut over two connectors is in each.
    fn cuts(&self, cuts: &ValidatedLayer) -> Vec<Vec<u32>> {
        let mut held = vec![Vec::new(); self.figures.len()];
        let (mut rects, mut start) = (Vec::new(), Vec::new());
        decompose_into(cuts, &mut rects, &mut start);
        let mut hit = Vec::new();
        for (cut, span) in (0u32..).zip(start.windows(2)) {
            hit.clear();
            for &r in &rects[span[0] as usize..span[1] as usize] {
                hit.extend(
                    self.pieces
                        .overlapping(r)
                        .map(|(_, piece)| self.of_piece[piece as usize]),
                );
            }
            hit.sort_unstable();
            hit.dedup();
            for &at in &hit {
                held[at].push(cut);
            }
        }
        held
    }

    /// Per connector, the area of `layer` inside its footprint.
    fn area_in(&self, layer: &ValidatedLayer) -> Result<Vec<DbuArea>, BooleanError> {
        let mut inside = ValidatedLayer::default();
        intersection_into(layer, &self.feet, &mut inside)?;
        let (mut rects, mut start) = (Vec::new(), Vec::new());
        decompose_into(&inside, &mut rects, &mut start);
        let mut sums = vec![DbuArea::new(0); self.figures.len()];
        for &r in &rects {
            let at = self.of_piece[first_label(&self.pieces, r) as usize];
            sums[at] = sums[at] + r.area();
        }
        Ok(sums)
    }
}

/// The label of the first rectangle of `sorted` overlapping `r`, which one
/// must.
fn first_label(sorted: &SortedRects<u32>, r: Bbox) -> u32 {
    sorted
        .overlapping(r)
        .map(|(_, label)| label)
        .next()
        .expect("a footprint lies on both layers")
}

/// sky130 ct.irdrop and via.irdrop as a deck states them: each connector (a
/// merged `lower` figure and a merged `upper` figure that overlap, its
/// footprint their overlap) is held, by the number of merged `pre` cuts
/// overlapping its footprint, to the band's limit on the change, either way,
/// between the `pre` and the `post` area inside the footprint. One violation
/// per failing connector, on `pre`, at the centre of its footprint's box.
/// `examined` counts connectors.
pub(crate) fn cut_area_change(
    store: &GeometryStore,
    rule: StrId,
    (pre, post, lower, upper): (LayerId, LayerId, LayerId, LayerId),
    bands: &CutAreaBands,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let (Some(under), Some(over), Some(before), Some(after)) = (
        merged(store, lower, s),
        merged(store, upper, s),
        merged(store, pre, s),
        merged(store, post, s),
    ) else {
        return REFUSED;
    };
    let Ok(connectors) = Connectors::new(&under, &over) else {
        return REFUSED;
    };
    let (Ok(was), Ok(is)) = (connectors.area_in(&before), connectors.area_in(&after)) else {
        return REFUSED;
    };
    for (at, cuts) in connectors.cuts(&before).iter().enumerate() {
        let Some(limit) = bands.limit(u32::try_from(cuts.len()).unwrap_or(u32::MAX)) else {
            continue;
        };
        let change = DbuArea::new((was[at].raw() - is[at].raw()).abs());
        if change > limit {
            out.push(Violation {
                rule,
                layer: pre,
                severity: Severity::Error,
                at: centre(connectors.bounds[at]),
                measured: Measurement::Area(change),
                limit: Measurement::Area(limit),
                shapes: (PolyId(u32::MAX), None),
            });
        }
    }
    (Outcome::Ran, connectors.figures.len() as u64)
}

/// A via's cuts, figures and footprints, as [`via_redundancy`] reads them.
struct Vias {
    connectors: Connectors,
    under: SortedRects<u32>,
    over: SortedRects<u32>,
    /// Every cut's box, by merged cut figure.
    boxes: Vec<Bbox>,
    /// Per connector, the cut figures on it.
    held: Vec<Vec<u32>>,
}

impl Vias {
    fn new(
        store: &GeometryStore,
        (cut, lower, upper): (LayerId, LayerId, LayerId),
        s: &mut Scratch,
    ) -> Option<Self> {
        let under = merged(store, lower, s)?;
        let over = merged(store, upper, s)?;
        let cuts = merged(store, cut, s)?;
        let connectors = Connectors::new(&under, &over).ok()?;
        let held = connectors.cuts(&cuts);
        Some(Self {
            under: figure_rects(&under),
            over: figure_rects(&over),
            boxes: cuts.bboxes().to_vec(),
            held,
            connectors,
        })
    }

    /// The first of a single-cut via's four neighbours ([`neighbours`])
    /// wholly on both of its figures and at least `space` from every box
    /// of `cuts`.
    fn second_cut(&self, at: usize, (pitch, space): (Dbu, Dbu), cuts: &[Bbox]) -> Option<Bbox> {
        let [only] = self.held[at][..] else {
            return None;
        };
        let (lo, hi) = self.connectors.figures[at];
        neighbours(self.boxes[only as usize], pitch).find(|&c| {
            covers(&self.under, lo, c) && covers(&self.over, hi, c) && clear(c, cuts, space)
        })
    }
}

/// A cut's four neighbours, its box `b` moved `pitch` right, left, up and
/// down, in that order.
fn neighbours(b: Bbox, pitch: Dbu) -> impl Iterator<Item = Bbox> {
    let p = pitch.raw();
    [(p, 0), (-p, 0), (0, p), (0, -p)]
        .into_iter()
        .map(move |(dx, dy)| {
            let shift = |v: Dbu, by: i64| Dbu::new_unchecked(v.raw() + by);
            Bbox {
                xlo: shift(b.xlo, dx),
                ylo: shift(b.ylo, dy),
                xhi: shift(b.xhi, dx),
                yhi: shift(b.yhi, dy),
            }
        })
}

/// Whether figure `figure` of `sorted` covers all of `b`.
fn covers(sorted: &SortedRects<u32>, figure: u32, b: Bbox) -> bool {
    sorted
        .overlapping(b)
        .filter(|&(_, label)| label == figure)
        .fold(DbuArea::new(0), |sum, (part, _)| sum + part.area())
        == b.area()
}

/// Whether `c` is at least `space` from every box of `cuts`.
fn clear(c: Bbox, cuts: &[Bbox], space: Dbu) -> bool {
    let space2 = space.mul_wide(space);
    cuts.iter().all(|&other| bbox_gap2(c, other) >= space2)
}

fn grown(b: Bbox, by: i64) -> Bbox {
    let d = |v: Dbu, by: i64| Dbu::new_unchecked(v.raw() + by);
    Bbox {
        xlo: d(b.xlo, -by),
        ylo: d(b.ylo, -by),
        xhi: d(b.xhi, by),
        yhi: d(b.yhi, by),
    }
}

/// How far figure `figure` of `sorted` reaches past `b` on its nearest
/// side: the largest margin, up to `cap`, by which `b` grown stays on it.
/// `None` when `b` is not wholly on it.
fn margin(sorted: &SortedRects<u32>, figure: u32, b: Bbox, cap: i64) -> Option<i64> {
    if !covers(sorted, figure, b) {
        return None;
    }
    let (mut lo, mut hi) = (0, cap);
    while lo < hi {
        let mid = lo + (hi - lo + 1) / 2;
        if covers(sorted, figure, grown(b, mid)) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Some(lo)
}

/// One redundant cut, and the metal it needs added below and above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insertion {
    /// The new cut.
    pub cut: Bbox,
    /// A patch of the lower metal under the via's two cuts, when the cut is
    /// not already wholly on it.
    pub lower: Option<Bbox>,
    /// The same for the upper metal.
    pub upper: Option<Bbox>,
}

/// Where a second cut goes beside each single-cut via, as `gpurify
/// enhance` adds them (catalog FLOW-009), in connector order: where
/// [`via_redundancy`] finds room, the first neighbour it finds; for a dead
/// via, the first neighbour at least `space` from every cut, with a patch
/// of each metal that does not hold it: the box round both cuts, grown by
/// the margin the metal already leaves round the via's cut (so the new cut
/// is enclosed as the old one is, and the patch overlaps the metal it
/// extends). Each cut is also `space` from every cut placed before it, so
/// the added cuts keep the rule's spacing among themselves; each joins the
/// two figures its via joins, and a patch touches its own figure. A dead
/// via made redundant is no longer dead, so the rule's rate rises. `None`
/// when a layer cannot be read (the rule's `Refused`).
pub fn redundant_cuts(
    store: &GeometryStore,
    layers: (LayerId, LayerId, LayerId),
    (pitch, space): (Dbu, Dbu),
) -> Option<Vec<Insertion>> {
    let vias = Vias::new(store, layers, &mut Scratch::default())?;
    let mut cuts = vias.boxes.clone();
    let mut added = Vec::new();
    for at in 0..vias.held.len() {
        let [only] = vias.held[at][..] else {
            continue;
        };
        let insertion = if let Some(cut) = vias.second_cut(at, (pitch, space), &cuts) {
            Insertion {
                cut,
                lower: None,
                upper: None,
            }
        } else {
            let b = vias.boxes[only as usize];
            let (lo, hi) = vias.connectors.figures[at];
            let (Some(below), Some(above)) = (
                margin(&vias.under, lo, b, pitch.raw()),
                margin(&vias.over, hi, b, pitch.raw()),
            ) else {
                continue;
            };
            let Some(cut) = neighbours(b, pitch).find(|&c| clear(c, &cuts, space)) else {
                continue;
            };
            let both = b.union(cut);
            Insertion {
                cut,
                lower: (!covers(&vias.under, lo, cut)).then(|| grown(both, below)),
                upper: (!covers(&vias.over, hi, cut)).then(|| grown(both, above)),
            }
        };
        cuts.push(insertion.cut);
        added.push(insertion);
    }
    Some(added)
}

/// The redundant-via rate of Xu et al. (ASP-DAC 2005), `1 - dead / vias`: a
/// via is a connector's cuts ([`Connectors`]); a single-cut via is dead when
/// none of its cut's four neighbours (its box moved `pitch` along x or y)
/// lies wholly on both of its figures at least `space` from every cut. One
/// violation when the rate is below `limit`, on `cut`, at the centre of the
/// first dead via's cut, measuring the rate. `examined` counts vias.
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
pub(crate) fn via_redundancy(
    store: &GeometryStore,
    rule: StrId,
    (cut, lower, upper): (LayerId, LayerId, LayerId),
    (pitch, space): (Dbu, Dbu),
    limit: f64,
    s: &mut Scratch,
    out: &mut Violations,
) -> Verdict {
    let Some(found) = Vias::new(store, (cut, lower, upper), s) else {
        return REFUSED;
    };
    let (held, boxes) = (&found.held, &found.boxes);
    let vias: Vec<usize> = (0..held.len()).filter(|&at| !held[at].is_empty()).collect();
    let dead: Vec<usize> = vias
        .iter()
        .copied()
        .filter(|&at| held[at].len() == 1 && found.second_cut(at, (pitch, space), boxes).is_none())
        .collect();
    #[allow(clippy::cast_precision_loss, reason = "via counts are far below 2^52")]
    let rate = if vias.is_empty() {
        1.0
    } else {
        1.0 - dead.len() as f64 / vias.len() as f64
    };
    if rate < limit {
        let first = held[dead[0]][0] as usize;
        out.push(Violation {
            rule,
            layer: cut,
            severity: Severity::Error,
            at: centre(boxes[first]),
            measured: Measurement::Ratio(rate),
            limit: Measurement::Ratio(limit),
            shapes: (PolyId(u32::MAX), None),
        });
    }
    (Outcome::Ran, vias.len() as u64)
}
