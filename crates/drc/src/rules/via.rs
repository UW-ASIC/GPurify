//! Via family: rules about vias as a *population* rather than as shapes.
//!
//! Counting is on the geometry, not on the net: two cuts count as redundant
//! when they are physically adjacent, because the failure guarded against is
//! one etch defect taking out one cut.

use super::{centre, gap_midpoint, poly_dist2, row_columns, COLUMNS_DIVERGED};
use crate::{record_run, Design, Scratch};
use gpurify_geom::connectivity::components_into;
use gpurify_geom::index::{candidate_pairs_into, SpatialIndex};
use gpurify_geom::ops::isqrt;
use gpurify_geom::{LayerId, PolyId};
use gpurify_ingest::StrId;
use gpurify_report::{Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use gpurify_geom::{Dbu, MAX_ABS_DBU};

/// Redundant via: every cut must have `min_count - 1` other cuts of the same
/// layer within `within` of it.
#[derive(Debug, Default)]
pub struct RedundantViaTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// Cuts required in the neighbourhood, *including the cut itself*.
    pub min_count: Vec<u16>,
    /// The neighbourhood radius, also the radius the candidate prune uses.
    pub within: Vec<Dbu>,
}

/// Via array spacing: once more than `array_threshold` cuts form one cluster —
/// a connected component of the "within `limit` of each other" graph — every
/// pair inside it is held to `limit`.
#[derive(Debug, Default)]
pub struct ViaArraySpacingTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// A cluster larger than this is an array — a trigger, not a defect.
    pub array_threshold: Vec<u16>,
    /// The spacing every pair inside an array must have.
    pub limit: Vec<Dbu>,
}

row_columns! {
    RedundantViaTable { rule, layer, min_count, within },
    ViaArraySpacingTable { rule, layer, array_threshold, limit },
}

/// Check every redundant-via rule.
///
/// Neighbourhood distance is between the cuts' nearest points, not their
/// centres: centres understate the distance for large cuts, so a centre-based
/// test over-counts neighbours and can call an isolated via redundant.
///
/// One violation per under-served cut, at the centre of that cut. `examined`
/// counts cuts.
pub fn check_redundant_via(
    design: Design<'_>,
    table: &RedundantViaTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let runs_before = runs.len();

    for row in 0..table.len() {
        let rule = table.rule[row];
        let layer = table.layer[row];
        let within = table.within[row];
        let min_count = u32::from(table.min_count[row]);
        debug_assert!(
            within.raw() >= 0 && within.raw() <= MAX_ABS_DBU,
            "a neighbourhood radius past the coordinate domain is a deck error"
        );

        let violations_before = out.len();
        let Scratch {
            index_a,
            pairs,
            areas,
            rect_start,
            ..
        } = &mut *scratch;

        let store = design.store;
        let cuts = store.polys_on_layer(layer);
        let n = (cuts.end - cuts.start) as usize;

        SpatialIndex::build_into(store, layer, index_a);
        candidate_pairs_into(store, index_a, within, pairs);
        debug_assert!(
            pairs.iter().all(|&(a, b)| a < b),
            "the same-layer prune emits ascending pairs"
        );
        debug_assert!(
            pairs
                .iter()
                .all(|&(a, b)| cuts.contains(&a.0) && cuts.contains(&b.0)),
            "a candidate pair left the layer its index was built over"
        );

        let within2 = within.mul_wide(within);

        // Pass one: measure every candidate pair exactly, once.
        areas.clear();
        areas.reserve(pairs.len());
        for &(a, b) in pairs.iter() {
            areas.push(poly_dist2(store, a, b));
        }
        debug_assert_eq!(areas.len(), pairs.len(), "one measurement per pair");

        // Pass two: how many *other* cuts each cut has in reach. `rect_start`
        // is this rule's per-cut counter column.
        rect_start.clear();
        rect_start.resize(n, 0u32);

        // Branchless: the count advances by the predicate rather than under it.
        for (&(a, b), &dist2) in pairs.iter().zip(areas.iter()) {
            let near = u32::from(dist2 <= within2);
            let ia = (a.0 - cuts.start) as usize;
            let ib = (b.0 - cuts.start) as usize;
            rect_start[ia] += near;
            rect_start[ib] += near;
        }
        debug_assert!(
            rect_start.iter().all(|&count| (count as usize) < n),
            "a cut counted more neighbours than there are other cuts on the layer"
        );
        debug_assert_eq!(
            rect_start
                .iter()
                .map(|&count| u64::from(count))
                .sum::<u64>(),
            2 * areas.iter().filter(|&&d2| d2 <= within2).count() as u64,
            "a pair in reach credits exactly two cuts, and a pair out of reach none"
        );

        // Pass three: judge. `zip` stops at the shorter side, so the length
        // agreement is asserted rather than assumed — a short counter column
        // would leave the tail of the layer unjudged and reported clean.
        assert_eq!(
            rect_start.len(),
            n,
            "one neighbour count per cut on the layer"
        );
        for (row, &neighbours) in cuts.clone().zip(rect_start.iter()) {
            // The cut is one of the cuts in its own neighbourhood.
            let count = neighbours + 1;
            let cut = PolyId(row);
            debug_assert!(
                count as usize <= n,
                "a cut has more neighbours than the layer holds"
            );

            if count < min_count {
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

        debug_assert!(
            out.len() - violations_before <= n,
            "a cut can be under-served at most once"
        );
        record_run(runs, out, violations_before, rule, Outcome::Ran, n as u64);
    }

    debug_assert_eq!(
        runs.len() - runs_before,
        table.len(),
        "one run row per rule row"
    );
}

/// Check every via-array-spacing rule.
///
/// One violation per offending pair, not one per cluster. `examined` counts
/// candidate pairs that fell inside a qualifying cluster.
pub fn check_via_array_spacing(
    design: Design<'_>,
    table: &ViaArraySpacingTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let runs_before = runs.len();

    for row in 0..table.len() {
        let rule = table.rule[row];
        let layer = table.layer[row];
        let threshold = u32::from(table.array_threshold[row]);
        let limit = table.limit[row];
        debug_assert!(
            limit.raw() >= 0 && limit.raw() <= MAX_ABS_DBU,
            "a spacing limit past the coordinate domain is a deck error"
        );

        let violations_before = out.len();
        let Scratch {
            index_a,
            pairs,
            edges,
            labels,
            areas,
            rect_start,
            ..
        } = &mut *scratch;

        let store = design.store;
        let cuts = store.polys_on_layer(layer);
        let n = cuts.end - cuts.start;

        SpatialIndex::build_into(store, layer, index_a);
        candidate_pairs_into(store, index_a, limit, pairs);
        debug_assert!(
            pairs
                .iter()
                .all(|&(a, b)| cuts.contains(&a.0) && cuts.contains(&b.0)),
            "a candidate pair left the layer its index was built over"
        );
        let limit2 = limit.mul_wide(limit);

        // Pass one: measure every candidate pair exactly, once. Every later
        // pass reads this column rather than re-walking the two cuts' edges.
        let n_pairs = pairs.len();
        areas.clear();
        areas.reserve(n_pairs);
        for &(a, b) in pairs.iter() {
            areas.push(poly_dist2(store, a, b));
        }
        debug_assert_eq!(areas.len(), n_pairs, "one measurement per pair");

        // Pass two: the cluster graph. A pair at or inside the limit joins one
        // cluster; a pair outside it becomes a self-loop, which merges nothing
        // — no branch, rather than a filtered push.
        let dists = &areas[..n_pairs];
        edges.clear();
        edges.reserve(n_pairs);
        for i in 0..n_pairs {
            let (a, b) = pairs[i];
            // Branchless: `joined` is all-ones for a pair inside the limit and
            // zero outside, so the far endpoint is blended in rather than
            // branched on.
            let joined = u32::from(dists[i] <= limit2).wrapping_neg();
            let ia = a.0 - cuts.start;
            let ib = b.0 - cuts.start;
            edges.push((ia, (ib & joined) | (ia & !joined)));
        }
        debug_assert_eq!(edges.len(), n_pairs, "one edge per pair");

        components_into(n, edges, labels);
        debug_assert_eq!(labels.len(), n as usize, "one label per cut");

        // Pass three: cluster populations, keyed by the label — which is the
        // minimum member index, so it indexes this column directly.
        rect_start.clear();
        rect_start.resize(n as usize, 0u32);
        for label in labels.iter() {
            rect_start[label.0 as usize] += 1;
        }
        debug_assert_eq!(
            rect_start.iter().sum::<u32>(),
            n,
            "every cut belongs to exactly one cluster"
        );

        // Pass four: judge the pairs inside a qualifying cluster.
        let mut examined = 0u64;
        for (slot, &(a, b)) in pairs.iter().enumerate() {
            let la = labels[(a.0 - cuts.start) as usize];
            let lb = labels[(b.0 - cuts.start) as usize];
            // Strictly larger: being *at* the threshold is not yet an array.
            let inside = (la == lb) & (rect_start[la.0 as usize] > threshold);
            examined += u64::from(inside);

            // Compared squared and exact; only the *reported* number is rooted,
            // and `isqrt` rounds toward zero so a report never overstates a gap.
            let short = areas[slot] < limit2;

            if inside & short {
                out.push(Violation {
                    rule,
                    layer,
                    severity: Severity::Error,
                    at: gap_midpoint(store.poly_bbox(a), store.poly_bbox(b)),
                    measured: Measurement::Length(isqrt(areas[slot])),
                    limit: Measurement::Length(limit),
                    shapes: (a, Some(b)),
                });
            }
        }

        debug_assert!(
            examined <= pairs.len() as u64,
            "a pair inside a cluster is still a candidate pair"
        );
        debug_assert!(
            (out.len() - violations_before) as u64 <= examined,
            "only a pair the rule judged can be a violation"
        );
        record_run(runs, out, violations_before, rule, Outcome::Ran, examined);
    }

    debug_assert_eq!(
        runs.len() - runs_before,
        table.len(),
        "one run row per rule row"
    );
}
