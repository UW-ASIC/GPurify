//! Via family: vias as a population, counted on geometry (not nets).
//!
//! Data in: one cut layer (not validated) and its candidate pairs with exact
//! boundary distances. Data out: under-served cuts, or too-close pairs inside
//! an array cluster.

use super::{centre, gap_midpoint, label_pairs_into, pair_distances_into, Verdict};
use crate::drc::Scratch;
use crate::report::{Measurement, Outcome, Severity, Violation, Violations};
use gpurify_geom::index::{candidate_pairs_into, SpatialIndex};
use gpurify_geom::ops::isqrt;
use gpurify_geom::{Dbu, GeometryStore, LayerId, PolyId};
use gpurify_ingest::StrId;

fn measured_pairs(store: &GeometryStore, layer: LayerId, radius: Dbu, s: &mut Scratch) {
    SpatialIndex::build_into(store, layer, &mut s.index_a);
    candidate_pairs_into(store, &s.index_a, radius, &mut s.pairs);
    pair_distances_into(store, &s.pairs, &mut s.dists);
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
/// every pair inside one is held to `limit`. One violation per offending pair.
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
                at: gap_midpoint(store.poly_bbox(a), store.poly_bbox(b)),
                measured: Measurement::Length(isqrt(d2)),
                limit: Measurement::Length(limit),
                shapes: (a, Some(b)),
            });
        }
    }
    (Outcome::Ran, examined)
}
