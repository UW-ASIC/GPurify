//! Via family: rules about vias as a *population* rather than as shapes.
//!
//! Both rules here are about how many cuts there are near each other, not about
//! how big any one of them is — a single via is a reliability risk whatever its
//! dimensions, and an array of them has to be pitched so the etch clears
//! between cuts. Every other property of a via is covered by the width,
//! spacing and enclosure families.
//!
//! # Counting is on the geometry, not on the net
//!
//! Two cuts count as redundant when they are physically adjacent, not when they
//! happen to be on the same net. A net can reach the same two conductors
//! through vias at opposite ends of a chip; those are not redundant, because
//! the failure being guarded against is one etch defect taking out one cut.

use super::{COLUMNS_DIVERGED, centre, gap_midpoint, poly_dist2, row_columns};
use crate::{record_run, Design, Scratch};
use gpurify_core::connectivity::components_into;
use gpurify_core::index::{candidate_pairs_into, SpatialIndex};
use gpurify_core::ops::isqrt;
use gpurify_core::{LayerId, PolyId};
use gpurify_ingest::StrId;
use gpurify_report::{Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use gpurify_units::{Dbu, MAX_ABS_DBU};

/// Redundant via: an isolated cut is a single point of failure.
///
/// Every cut must have at least `min_count - 1` other cuts of the same layer
/// within `within` of it. A stated *count* rather than "must be doubled",
/// because triple-via requirements exist on the critical layers of some nodes.
#[derive(Debug, Default)]
pub struct RedundantViaTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// Cuts required in the neighbourhood, including the cut itself. Violated
    /// below. `u16`: a redundancy requirement is a small integer and a deck
    /// asking for 70 000 vias in one place is a typo, not a rule.
    pub min_count: Vec<u16>,
    /// The neighbourhood radius, and also the radius the candidate prune is
    /// built at.
    pub within: Vec<Dbu>,
}

/// Via array spacing: a dense group of cuts needs more pitch than a lone pair.
///
/// Etch loading rises with cut density, so once more than `array_threshold`
/// cuts form one cluster, every pair inside that cluster is held to
/// `limit` rather than to the layer's ordinary spacing.
///
/// A cluster is a connected component of the "within `limit` of each other"
/// graph, which is why this rule builds an edge list and calls
/// `core::connectivity` rather than scanning pairs alone.
#[derive(Debug, Default)]
pub struct ViaArraySpacingTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// A cluster larger than this is an array. Violated above, and only as a
    /// trigger — being in a big array is not itself a defect.
    pub array_threshold: Vec<u16>,
    /// The spacing every pair inside an array must have. Violated below.
    pub limit: Vec<Dbu>,
}

row_columns! {
    RedundantViaTable { rule, layer, min_count, within },
    ViaArraySpacingTable { rule, layer, array_threshold, limit },
}

/// Check every redundant-via rule.
///
/// **Transform.** Builds the index once per row, measures every candidate pair
/// exactly, counts each cut's neighbours from those measurements, then judges
/// each cut against its count. Three passes rather than one: counting inside
/// the judging loop would mean row `n` reading what row `n - 1` wrote, which
/// the kernel rule forbids, and measuring inside the counting loop would
/// re-walk a cut's ring once per neighbour instead of once per pair.
///
/// Neighbourhood distance is measured between the cuts' nearest points, not
/// their centres. Centres understate the distance for large cuts, so a
/// centre-based test *over*-counts neighbours and can call an isolated via
/// redundant — fail-open, and the old tree did it.
///
/// One violation per under-served cut, at the centre of that cut, measuring the
/// count it had against the count required. `examined` counts cuts.
pub fn check_redundant_via(
    design: Design<'_>,
    table: &RedundantViaTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let runs_before = runs.len();

    // Not a bulk loop: a deck holds tens of rows per table, and every column of
    // the row is hoisted below as a uniform over a loop with millions of
    // iterations.
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

        // Pass one: measure every candidate pair exactly, once. This is the
        // call site `poly_dist2`'s own doc names — the ring cross-product
        // inside it is tens of edges and stays scalar, while the pair list
        // outside it is the bulk dimension. One measurement per pair, no
        // branch.
        //
        // No vector shape to reach for and none lost: the body is an opaque
        // call whose cost is two ring walks, so the loop is call-bound and the
        // store is the cheap part. `reserve` before the loop is what keeps the
        // push from carrying a realloc.
        areas.clear();
        areas.reserve(pairs.len());
        for &(a, b) in pairs.iter() {
            areas.push(poly_dist2(store, a, b));
        }
        debug_assert_eq!(areas.len(), pairs.len(), "one measurement per pair");

        // Pass two: how many *other* cuts each cut has in reach. `rect_start`
        // is this rule's per-cut counter column — `Scratch`'s fields are
        // storage, cleared and refilled by whichever transform wants them.
        rect_start.clear();
        rect_start.resize(n, 0u32);

        // Scatter-accumulate: each pair credits two output rows at
        // data-dependent indices, so this does not vectorise without
        // lane-conflict detection and is not asked to.
        //
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
            rect_start.iter().map(|&count| u64::from(count)).sum::<u64>(),
            2 * areas.iter().filter(|&&d2| d2 <= within2).count() as u64,
            "a pair in reach credits exactly two cuts, and a pair out of reach none"
        );

        // Pass three: judge. Separate from the counting because a cut's verdict
        // reads counts other pairs wrote, which the kernel rule forbids inside
        // one pass.
        //
        // The store row is zipped in rather than derived from a cast of the
        // slot: `cuts` is already a `u32` range, so no `usize` ever has to be
        // narrowed back to one. `zip` stops at the shorter side, so the length
        // agreement is asserted rather than assumed — a short counter column
        // would leave the tail of the layer unjudged and reported clean.
        assert_eq!(
            rect_start.len(),
            n,
            "one neighbour count per cut on the layer"
        );
        for (row, &neighbours) in cuts.clone().zip(rect_start.iter()) {
            // The cut is one of the cuts in its own neighbourhood, which is why
            // the requirement is a population and not a neighbour count.
            let count = neighbours + 1;
            let cut = PolyId(row);
            debug_assert!(count as usize <= n, "a cut has more neighbours than the layer holds");

            // Surviving `if`: the taken side builds and pushes an eight-column
            // row, which is the expensive-side escape valve, and on a layer that
            // meets its redundancy requirement it is never taken — so it also
            // predicts at ~100%.
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
/// Clusters first — edge list from the candidate pairs, then
/// `core::connectivity::components_into`, whose labels are the minimum member
/// index and therefore canonical. Then, for clusters above the threshold, every
/// pair inside is measured exactly.
///
/// One violation per offending pair inside a qualifying cluster, not one per
/// cluster: a 6×6 array with one bad column has a specific place to fix.
///
/// `examined` counts candidate pairs that fell inside a qualifying cluster.
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
        // One output row per input row and no branch. The ring cross-product
        // inside `poly_dist2` stays scalar; a ring is tens of edges, which is
        // not bulk, and the call is opaque, so there is no vector shape here to
        // reach for.
        let n_pairs = pairs.len();
        areas.clear();
        areas.reserve(n_pairs);
        for &(a, b) in pairs.iter() {
            areas.push(poly_dist2(store, a, b));
        }
        debug_assert_eq!(areas.len(), n_pairs, "one measurement per pair");

        // Pass two: the cluster graph. A pair at or inside the limit joins one
        // cluster; a pair outside it becomes a self-loop, which the union-find
        // finds redundant and which therefore merges nothing — one output row
        // per input row, no branch, rather than a filtered push.
        //
        // Slicing the measurement column to the pair count fails closed on a
        // short column in *every* profile, and hands LLVM one trip count that
        // covers both reads, so neither index carries a bounds check.
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
        // minimum member index, so it is itself a cut slot and indexes this
        // column directly.
        //
        // Scatter-accumulate: the output index is the label being read, so this
        // does not vectorise without lane-conflict detection.
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

        // Pass four: judge the pairs inside a qualifying cluster. `examined`
        // rides in the same pass because it counts the same population the
        // judgement does; folding it separately would walk the pair list twice.
        let mut examined = 0u64;
        for (slot, &(a, b)) in pairs.iter().enumerate() {
            let la = labels[(a.0 - cuts.start) as usize];
            let lb = labels[(b.0 - cuts.start) as usize];
            // Strictly larger: being *at* the threshold is not yet an array,
            // and being in a big group is a trigger rather than a defect.
            let inside = (la == lb) & (rect_start[la.0 as usize] > threshold);
            examined += u64::from(inside);

            // Compared squared and exact; only the *reported* number is rooted,
            // and `isqrt` rounds toward zero so a report never overstates a gap.
            let short = areas[slot] < limit2;

            // Surviving `if`: the taken side builds and pushes an eight-column
            // row. It is also false for every pair outside an array, which is
            // most of them on any layer with one via rule and no array.
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
