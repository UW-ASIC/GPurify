//! Supply, substrate and pad integrity — topological, but geometry-aware.
//!
//! Five kinds. None of these asks "is this net VDD": that is a design-intent
//! question and these rules always run. A supply short here is *an n-type tie
//! and a p-type tie on one conductor*, provable from the deck's tap markers.

use crate::facts::{NetFacts, RoleMask};
use crate::ruleset::RuleHead;
use crate::{ascending, base_layer, first_vertex, push_net_violations, record_run};
use crate::{Design, Scratch};
use gpurify_geom::connectivity::components_into;
use gpurify_geom::ops::{isqrt, point_seg_dist2, segments_intersect, Point, Seg};
use gpurify_geom::view::validate_layer_into;
use gpurify_geom::{Bbox, GeometryStore, LayerId, PolyId, RingRef, ValidatedLayer};
use gpurify_geom::{Evaluator, LayerRef};
use gpurify_ingest::StrId;
use gpurify_report::{Measurement, Outcome, RuleRun, Violation, Violations};
use gpurify_topology::NetId;
use gpurify_geom::{Dbu, DbuArea};

/// One conductor carrying two ties of opposite type.
#[derive(Debug, Default)]
pub struct SupplyShortTable {
    pub head: RuleHead,
    /// The two ties whose sharing one net is the short.
    pub tap_a: Vec<LayerRef>,
    pub tap_b: Vec<LayerRef>,
}

/// Two parts of a net joined only through a resistive body.
///
/// The test is a partition, not a distance: remove the soft layers' shapes from
/// the net's connectivity and ask whether it falls into more than one
/// component.
#[derive(Debug, Default)]
pub struct SoftConnectionTable {
    pub head: RuleHead,
    /// `soft[soft_start[i] .. soft_start[i + 1]]` are row `i`'s resistive
    /// layers.
    pub soft_start: Vec<u32>,
    pub soft: Vec<LayerRef>,
}

/// A point in a tied region too far from the nearest tie.
#[derive(Debug, Default)]
pub struct MissingTieTable {
    pub head: RuleHead,
    /// The region that must be tied throughout.
    pub region: Vec<LayerRef>,
    /// What counts as a tie.
    pub tap: Vec<LayerRef>,
    /// Furthest any point of the region may be from a tap.
    pub max_distance: Vec<Dbu>,
}

/// A gate held at a rail with nothing able to drive it: the net carries a gate
/// and a source terminal but no drain.
#[derive(Debug, Default)]
pub struct TieHighLowTable {
    pub head: RuleHead,
}

/// A pad reaching no protection device.
#[derive(Debug, Default)]
pub struct EsdTopologicalTable {
    pub head: RuleHead,
    /// The marker layer whose polygons are bond pads or I/O.
    pub pad: Vec<LayerId>,
    /// `clamp_model[clamp_start[i] .. clamp_start[i + 1]]` are the interned
    /// model names that count as protection for row `i`.
    pub clamp_start: Vec<u32>,
    pub clamp_model: Vec<StrId>,
}

/// Flag every net carrying both taps.
pub fn check_supply_short(
    design: Design<'_>,
    table: &SupplyShortTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.rule.len();
    debug_assert_eq!(table.head.severity.len(), rows, "one severity per rule row");
    debug_assert_eq!(table.tap_a.len(), rows, "one tap_a layer per rule row");
    debug_assert_eq!(table.tap_b.len(), rows, "one tap_b layer per rule row");

    let nets = design.nets.net_count();
    let extracted = nets != 0;
    let net_index = ascending(nets);
    let mut flagged: Vec<(u32, u32)> = Vec::new();

    for row in 0..rows {
        let before = out.len();
        let rule = table.head.rule[row];
        let (Some(tap_a), Some(tap_b)) =
            (base_layer(table.tap_a[row]), base_layer(table.tap_b[row]))
        else {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        };

        // One `u32` per net plus a trash slot past the end. Two bits, one per
        // tap layer, so "both taps on one conductor" is `marks == 3` and the
        // second pass needs no second column.
        scratch.net_marks.clear();
        scratch.net_marks.resize(nets + 1, 0);

        let (a_rows, b_rows) = (
            design.store.polys_on_layer(tap_a),
            design.store.polys_on_layer(tap_b),
        );
        let examined = u64::from(a_rows.end - a_rows.start) + u64::from(b_rows.end - b_rows.start);

        // `NetId::NONE` is `u32::MAX`, so `min` routes a tap drawn on a
        // non-conducting layer into the trash slot the second pass never reads.
        //
        // Guarded on `extracted`: `NetTable::net_of` fails closed by *panicking*
        // on a polygon its table never saw, and a run handed
        // `NetTable::default()` has seen none of them.
        if extracted {
            for row in a_rows {
                let slot = design.nets.net_of(PolyId(row)).idx().min(nets);
                scratch.net_marks[slot] |= 1;
            }
            for row in b_rows {
                let slot = design.nets.net_of(PolyId(row)).idx().min(nets);
                scratch.net_marks[slot] |= 2;
            }
        }

        let marks = &scratch.net_marks[..nets];
        debug_assert_eq!(net_index.len(), marks.len(), "SoA columns must agree");
        let n = net_index.len();

        // Reserved for the whole input, not the survivors: that over-allocation
        // is what lets the store below be unconditional.
        flagged.clear();
        flagged.reserve(n);
        let slots = &mut flagged.spare_capacity_mut()[..n];

        let mut w = 0usize;
        for i in 0..n {
            let row = (net_index[i], marks[i]);
            let p = marks[i] == 3;
            // `w <= i` by induction: `bool` is 0 or 1, so `w` advances by at
            // most one per iteration. Rejected slots stay uninit and are
            // truncated away by `set_len(w)`.
            debug_assert!(w <= i);
            // SAFETY: `w <= i < n == slots.len()`, from the induction above.
            unsafe { slots.get_unchecked_mut(w) }.write(row);
            w += usize::from(p);
        }
        // SAFETY: slots `0..w` were each written when `w` held that value, and
        // `w <= n <= capacity`.
        unsafe { flagged.set_len(w) };

        let shorted = w;
        debug_assert_eq!(shorted, flagged.len(), "the compact and its count disagree");
        debug_assert!(shorted <= nets, "more shorted nets than nets");

        push_net_violations(
            design,
            &flagged,
            rule,
            table.head.severity[row],
            Measurement::Count(2),
            Measurement::Count(1),
            out,
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every net that falls apart once the resistive layers are removed.
///
/// The violation names the two shapes on either side of the bridge, so a viewer
/// lands on the gap rather than on the net as a whole.
pub fn check_soft_connection(
    design: Design<'_>,
    table: &SoftConnectionTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.rule.len();
    debug_assert_eq!(table.head.severity.len(), rows, "one severity per rule row");
    debug_assert!(
        table.soft_start.len() == rows + 1 || table.soft_start.is_empty(),
        "the soft-layer CSR carries one offset per row plus a terminator"
    );

    let nets = design.nets.net_count();
    let extracted = nets != 0;
    let layers = design.store.layer_count();
    let net_index = ascending(nets);
    let mut soft_nets: Vec<(u32, u32)> = Vec::new();
    let mut is_soft: Vec<bool> = Vec::new();
    let mut soft_layers: Vec<LayerId> = Vec::new();
    let mut hard: Vec<PolyId> = Vec::new();
    let mut order: Vec<u32> = Vec::new();

    for row in 0..rows {
        let before = out.len();
        let rule = table.head.rule[row];
        let span = table.soft_start[row] as usize..table.soft_start[row + 1] as usize;

        is_soft.clear();
        is_soft.resize(layers, false);
        soft_layers.clear();
        let mut resolved = true;
        for &layer in &table.soft[span] {
            match base_layer(layer) {
                // Fail closed: a layer the store's table does not have indexes
                // out of bounds and panics here, in every profile.
                Some(base) => {
                    // `is_soft` is idempotent under a deck naming one layer
                    // twice; the row-range list is not.
                    let fresh = !is_soft[base.idx()];
                    is_soft[base.idx()] = true;
                    if fresh {
                        soft_layers.push(base);
                    }
                }
                None => resolved = false,
            }
        }
        if !resolved {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        }

        // Which nets touch a soft layer at all, walked through `polys_on_layer`
        // per soft layer so the layer test *is* the row range. Guarded on
        // `extracted` for the same reason as `check_supply_short`.
        scratch.net_marks.clear();
        scratch.net_marks.resize(nets + 1, 0);
        if extracted {
            for &layer in &soft_layers {
                for poly in design.store.polys_on_layer(layer) {
                    let slot = design.nets.net_of(PolyId(poly)).idx().min(nets);
                    scratch.net_marks[slot] |= 1;
                }
            }
        }

        let touched = &scratch.net_marks[..nets];
        debug_assert_eq!(net_index.len(), touched.len(), "SoA columns must agree");
        let n = net_index.len();

        soft_nets.clear();
        soft_nets.reserve(n);
        let slots = &mut soft_nets.spare_capacity_mut()[..n];

        let mut w = 0usize;
        for i in 0..n {
            let row = (net_index[i], touched[i]);
            let p = touched[i] == 1;
            // `w <= i` by induction: `bool` is 0 or 1, so `w` advances by at
            // most one per iteration. Rejected slots stay uninit and are
            // truncated away by `set_len(w)`.
            debug_assert!(w <= i);
            // SAFETY: `w <= i < n == slots.len()`, from the induction above.
            unsafe { slots.get_unchecked_mut(w) }.write(row);
            w += usize::from(p);
        }
        // SAFETY: slots `0..w` were each written when `w` held that value, and
        // `w <= n <= capacity`.
        unsafe { soft_nets.set_len(w) };

        let examined = w;
        debug_assert_eq!(
            examined,
            soft_nets.len(),
            "the compact and its count disagree"
        );

        for &(net, _) in &soft_nets {
            let net = NetId(net);
            // The net's conductors with the resistive body removed: what is
            // left is what the silicon actually holds at one potential.
            let polys = design.nets.polys_of(net);
            let n = polys.len();
            hard.clear();
            hard.reserve(n);
            let slots = &mut hard.spare_capacity_mut()[..n];

            let mut w = 0usize;
            for (i, &poly) in polys.iter().enumerate() {
                let p = !is_soft[design.store.poly_layer(poly).idx()];
                // `w <= i` by induction: `bool` is 0 or 1, so `w` advances by
                // at most one per iteration. Rejected slots stay uninit and are
                // truncated away by `set_len(w)`.
                debug_assert!(w <= i);
                // SAFETY: `w <= i < n == slots.len()`, from the induction above.
                unsafe { slots.get_unchecked_mut(w) }.write(poly);
                w += usize::from(p);
            }
            // SAFETY: slots `0..w` were each written when `w` held that value,
            // and `w <= n <= capacity`.
            unsafe { hard.set_len(w) };

            let conductors = w;
            debug_assert_eq!(conductors, hard.len(), "the compact and its count disagree");
            debug_assert!(
                conductors <= design.nets.polys_of(net).len(),
                "removing the soft layers cannot add a conductor"
            );
            let Some(&first_poly) = hard.first() else {
                continue;
            };

            scratch.boxes.clear();
            scratch.boxes.reserve(hard.len());
            scratch
                .boxes
                .extend(hard.iter().map(|&p| design.store.poly_bbox(p)));
            debug_assert_eq!(
                scratch.boxes.len(),
                hard.len(),
                "one box per hard conductor"
            );

            // The pair kept is the pair that shares a *point*, not the pair
            // whose boxes overlap: joining two conductors that only share a box
            // merges two components and *under*-reports the bridge. The box test
            // survives as the prune in front of the exact one, and an x-order
            // sweep keeps the scan off O(k²).
            let node_count = u32::try_from(hard.len()).expect("a net's polygons fit a u32");
            order.clear();
            order.extend(0..node_count);
            order.sort_unstable_by_key(|&i| scratch.boxes[i as usize].xlo);
            debug_assert!(
                order
                    .windows(2)
                    .all(|w| scratch.boxes[w[0] as usize].xlo <= scratch.boxes[w[1] as usize].xlo),
                "the sweep order is ascending in xlo"
            );

            scratch.edges.clear();
            for i in 0..order.len() {
                let a = order[i];
                let box_a = scratch.boxes[a as usize];
                for &b in &order[i + 1..] {
                    let box_b = scratch.boxes[b as usize];
                    if box_b.xlo > box_a.xhi {
                        break;
                    }
                    // `&&` rather than `&`: the exact test is two ring walks.
                    if box_a.overlaps(box_b)
                        && polys_meet(design.store, hard[a as usize], hard[b as usize])
                    {
                        scratch.edges.push((a, b));
                    }
                }
            }

            components_into(node_count, &scratch.edges, &mut scratch.labels);
            debug_assert_eq!(scratch.labels.len(), hard.len(), "one label per conductor");

            // The lowest-numbered conductor on the far side of the bridge, or
            // `u32::MAX` when there is no far side: a row agreeing with the
            // first label is smeared to `u32::MAX` and loses the `min`.
            let near = scratch.labels[0];
            let mut far = u32::MAX;
            for (idx, &label) in (0u32..).zip(&scratch.labels) {
                let same = u32::from(label == near).wrapping_neg();
                far = far.min(idx | same);
            }
            debug_assert!(
                far == u32::MAX || (far as usize) < hard.len(),
                "the far side of a bridge is one of this net's own conductors"
            );

            if far != u32::MAX {
                let far_poly = hard[far as usize];
                out.push(Violation {
                    rule,
                    layer: design.store.poly_layer(first_poly),
                    severity: table.head.severity[row],
                    at: first_vertex(design.store, first_poly),
                    measured: Measurement::Count(2),
                    limit: Measurement::Count(1),
                    shapes: (first_poly, Some(far_poly)),
                });
            }
        }

        let examined = u64::try_from(examined).expect("a net count fits a u64");
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every point of a region further than `max_distance` from a tap.
///
/// The reported point is *the* furthest point of the region, not a corner
/// sample. Distances are exact: `point_seg_dist2` in [`DbuArea`] against the
/// squared limit, so no square root enters a verdict.
///
/// [`DbuArea`]: gpurify_geom::DbuArea
pub fn check_missing_tie(
    design: Design<'_>,
    table: &MissingTieTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.rule.len();
    debug_assert_eq!(table.head.severity.len(), rows, "one severity per rule row");
    debug_assert_eq!(table.region.len(), rows, "one region layer per rule row");
    debug_assert_eq!(table.tap.len(), rows, "one tap layer per rule row");
    debug_assert_eq!(table.max_distance.len(), rows, "one limit per rule row");

    let mut taps: Vec<Seg> = Vec::new();
    let mut grid = TapGrid::default();
    let mut stack: Vec<Cell> = Vec::new();

    for row in 0..rows {
        let before = out.len();
        let rule = table.head.rule[row];
        // The region alone has to be a base layer: it is what the violation
        // names. The tap is only ever measured *to*, so it may be either.
        let Some(region) = base_layer(table.region[row]) else {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        };
        let Some(tap) = tap_geometry(
            design.store,
            design.derived,
            table.tap[row],
            &mut scratch.layer_b,
        ) else {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        };

        let limit = table.max_distance[row];
        debug_assert!(limit.raw() >= 0, "a tap distance is non-negative");
        // Squared, so no square root enters a verdict.
        let limit2 = limit.mul_wide(limit);

        // Holes are pushed too: a ring-shaped tap ties the region along its
        // inner boundary as much as its outer one.
        taps.clear();
        for idx in 0..tap.len() {
            let idx = u32::try_from(idx).expect("a validated layer's polygons fit a u32");
            let poly = tap.get(design.store, idx);
            push_ring_edges(poly.outer(), &mut taps);
            for hole in poly.holes() {
                push_ring_edges(hole, &mut taps);
            }
        }

        // Coincident edges measure the same distance, so keeping one of each is
        // exact and keeps a bucket shallow. Keyed on the endpoint pair in
        // ascending order, not on the segment as drawn: an edge two abutting
        // taps share is run in opposite directions by the two windings.
        taps.sort_unstable_by_key(undirected);
        taps.dedup_by_key(|s| undirected(s));

        TapGrid::build_into(&taps, &mut grid);

        // A region measured against no taps at all is untied everywhere, and
        // the sentinel is the whole answer.
        let tapped = !taps.is_empty();

        let region_rows = design.store.polys_on_layer(region);
        let examined = u64::from(region_rows.end - region_rows.start);

        for poly in region_rows {
            let poly = PolyId(poly);
            let (xs, ys) = design.store.poly_verts(poly);
            debug_assert_eq!(xs.len(), ys.len(), "the store's columns are parallel");
            let Some((&x0, &y0)) = xs.first().zip(ys.first()) else {
                continue;
            };

            // A region with no tap on the layer at all measures the sentinel,
            // whose root is `MAX_ABS_DBU`, so it is reported rather than passed.
            let (at, worst) = if tapped {
                // `limit2` goes in as the floor the search starts from, not as a
                // test applied to its answer: on a region that breaks the limit
                // nowhere the exact maximum is never read, and a search starting
                // at the limit proves that without descending.
                furthest_from_taps(
                    xs,
                    ys,
                    design.store.poly_bbox(poly),
                    limit2,
                    &grid,
                    &mut stack,
                )
            } else {
                (Point { x: x0, y: y0 }, NO_TAP_IN_RANGE)
            };
            debug_assert!(worst.raw() >= 0, "a squared distance is non-negative");

            if worst > limit2 {
                let measured = isqrt(worst);
                debug_assert!(
                    measured >= limit,
                    "a violation measures further than the limit it broke"
                );
                out.push(Violation {
                    rule,
                    layer: design.store.poly_layer(poly),
                    severity: table.head.severity[row],
                    at,
                    measured: Measurement::Length(measured),
                    limit: Measurement::Length(limit),
                    shapes: (poly, None),
                });
            }
        }

        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every net that is a gate and a source and not a drain.
pub fn check_tie_high_low(
    design: Design<'_>,
    facts: &NetFacts,
    table: &TieHighLowTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.rule.len();
    debug_assert_eq!(table.head.severity.len(), rows, "one severity per rule row");
    let nets = design.nets.net_count();
    debug_assert_eq!(facts.role.len(), nets, "one role mask per extracted net");

    let held = RoleMask::GATE.union(RoleMask::SOURCE);
    let driven = RoleMask::DRAIN;

    let net_index = ascending(nets);
    let mut flagged: Vec<(u32, RoleMask)> = Vec::new();

    for row in 0..rows {
        let before = out.len();
        let rule = table.head.rule[row];

        // The nets this rule could have flagged. Counting every net instead
        // would make a design with one transistor look thoroughly checked.
        let mut examined = 0u64;
        for i in 0..facts.role.len() {
            examined += u64::from(facts.role[i].contains(RoleMask::GATE));
        }
        debug_assert!(examined <= nets as u64, "more gate nets than nets");

        debug_assert_eq!(net_index.len(), facts.role.len(), "SoA columns must agree");
        let n = net_index.len();

        flagged.clear();
        flagged.reserve(n);
        let slots = &mut flagged.spare_capacity_mut()[..n];

        let mut w = 0usize;
        // Resliced, not zipped raw: a short role column is a panic here rather
        // than a silently-short pass.
        let roles = &facts.role[..n];
        for (i, (&mask, &net)) in roles.iter().zip(&net_index).enumerate() {
            let p = mask.contains(held) & !mask.intersects(driven);
            // `w <= i` by induction: `bool` is 0 or 1, so `w` advances by at
            // most one per iteration. Rejected slots stay uninit and are
            // truncated away by `set_len(w)`.
            debug_assert!(w <= i);
            // SAFETY: `w <= i < n == slots.len()`, from the induction above.
            unsafe { slots.get_unchecked_mut(w) }.write((net, mask));
            w += usize::from(p);
        }
        // SAFETY: slots `0..w` were each written when `w` held that value, and
        // `w <= n <= capacity`.
        unsafe { flagged.set_len(w) };

        let count = w;
        debug_assert_eq!(count, flagged.len(), "the compact and its count disagree");
        debug_assert!(count as u64 <= examined, "a tied-off net carries a gate");

        push_net_violations(
            design,
            &flagged,
            rule,
            table.head.severity[row],
            Measurement::Count(0),
            Measurement::Count(1),
            out,
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every pad net reaching none of the listed clamp models.
pub fn check_esd_topological(
    design: Design<'_>,
    table: &EsdTopologicalTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.rule.len();
    debug_assert_eq!(table.head.severity.len(), rows, "one severity per rule row");
    debug_assert_eq!(table.pad.len(), rows, "one pad layer per rule row");
    debug_assert!(
        table.clamp_start.len() == rows + 1 || table.clamp_start.is_empty(),
        "the clamp CSR carries one offset per row plus a terminator"
    );

    let nets = design.nets.net_count();
    let extracted = nets != 0;
    let net_index = ascending(nets);
    let mut on_a_pad: Vec<u32> = Vec::new();
    let mut pad_nets: Vec<(u32, u32)> = Vec::new();

    for row in 0..rows {
        let before = out.len();
        let rule = table.head.rule[row];
        let clamps = &table.clamp_model
            [table.clamp_start[row] as usize..table.clamp_start[row + 1] as usize];

        // Which nets a pad marker lands on, with `check_supply_short`'s trash
        // slot and its `extracted` guard, for the same reasons.
        on_a_pad.clear();
        on_a_pad.resize(nets + 1, 0);
        if extracted {
            for poly in design.store.polys_on_layer(table.pad[row]) {
                let slot = design.nets.net_of(PolyId(poly)).idx().min(nets);
                on_a_pad[slot] = 1;
            }
        }

        // The kept count is the number of *distinct* pad nets, which is what
        // `examined` claims.
        let on_pad = &on_a_pad[..nets];
        debug_assert_eq!(net_index.len(), on_pad.len(), "SoA columns must agree");
        let n = net_index.len();

        pad_nets.clear();
        pad_nets.reserve(n);
        let slots = &mut pad_nets.spare_capacity_mut()[..n];

        let mut w = 0usize;
        for i in 0..n {
            let row = (net_index[i], on_pad[i]);
            let p = on_pad[i] == 1;
            // `w <= i` by induction: `bool` is 0 or 1, so `w` advances by at
            // most one per iteration. Rejected slots stay uninit and are
            // truncated away by `set_len(w)`.
            debug_assert!(w <= i);
            // SAFETY: `w <= i < n == slots.len()`, from the induction above.
            unsafe { slots.get_unchecked_mut(w) }.write(row);
            w += usize::from(p);
        }
        // SAFETY: slots `0..w` were each written when `w` held that value, and
        // `w <= n <= capacity`.
        unsafe { pad_nets.set_len(w) };

        let examined = w;
        debug_assert_eq!(
            examined,
            pad_nets.len(),
            "the compact and its count disagree"
        );

        for &(net, _) in &pad_nets {
            let net = NetId(net);
            let protected = design
                .devices
                .devices_on(net)
                .iter()
                .any(|&device| clamps.contains(&design.devices.model[device.0 as usize]));

            if !protected {
                let Some(&poly) = design.nets.polys_of(net).first() else {
                    continue;
                };
                out.push(Violation {
                    rule,
                    layer: design.store.poly_layer(poly),
                    severity: table.head.severity[row],
                    at: first_vertex(design.store, poly),
                    measured: Measurement::Count(0),
                    limit: Measurement::Count(1),
                    shapes: (poly, None),
                });
            }
        }

        let examined = u64::try_from(examined).expect("a net count fits a u64");
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// One layer of tap geometry, however the deck named it.
///
/// A tap is only ever measured *to*, so it needs no [`PolyId`] and a derived tap
/// is usable here.
///
/// `None` is a refusal, never an empty layer: a rule that could not read its
/// taps must not report the region clean.
fn tap_geometry<'a>(
    store: &GeometryStore,
    derived: &'a Evaluator,
    layer: LayerRef,
    scratch: &'a mut ValidatedLayer,
) -> Option<&'a ValidatedLayer> {
    match layer {
        LayerRef::Base(base) => {
            validate_layer_into(store, base, scratch).ok()?;
            Some(scratch)
        }
        LayerRef::Named(name) => derived.get(name),
    }
}

/// One segment's endpoints in ascending order — its identity ignoring which way
/// round it was drawn.
fn undirected(s: &Seg) -> (i64, i64, i64, i64) {
    let (p, q) = ((s.a.x.raw(), s.a.y.raw()), (s.b.x.raw(), s.b.y.raw()));
    let (lo, hi) = (p.min(q), p.max(q));
    (lo.0, lo.1, hi.0, hi.1)
}

/// Append one ring's closed edges to a segment column.
fn push_ring_edges(ring: RingRef<'_>, out: &mut Vec<Seg>) {
    let (xs, ys) = ring.coords();
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    debug_assert!(
        xs.len() >= 3,
        "a validated ring has at least three vertices"
    );
    out.reserve(xs.len());
    for vertex in 0..xs.len() {
        out.push(ring_edge(xs, ys, vertex));
    }
}

/// The closed edge from vertex `i` of a ring to the next one, wrapping.
#[inline]
fn ring_edge(xs: &[Dbu], ys: &[Dbu], i: usize) -> Seg {
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    debug_assert!(
        i < xs.len(),
        "a ring edge starts at one of the ring's vertices"
    );
    // Branchless wrap: the subtraction is by zero for every vertex but the
    // last, which puts the ring's closing edge in the same pass.
    let next = (i + 1) - xs.len() * usize::from(i + 1 == xs.len());
    Seg {
        a: Point { x: xs[i], y: ys[i] },
        b: Point {
            x: xs[next],
            y: ys[next],
        },
    }
}

/// Whether two of the store's polygons share at least one point.
///
/// Every pair the upstream bounding-box prune keeps is re-tested exactly:
/// joining two conductors that share only a box merges two components into one,
/// which is fail-**open** for [`check_soft_connection`].
///
/// Two rings whose boundaries do not meet are either nested or disjoint, so one
/// vertex of each decides the rest.
fn polys_meet(store: &GeometryStore, a: PolyId, b: PolyId) -> bool {
    let (ax, ay) = store.poly_verts(a);
    let (bx, by) = store.poly_verts(b);
    debug_assert_eq!(ax.len(), ay.len(), "the store's columns are parallel");
    debug_assert_eq!(bx.len(), by.len(), "the store's columns are parallel");

    // A run with under three vertices bounds no area. Guarded rather than
    // asserted because the probes below read vertex zero, and `ingest` is
    // allowed to carry a degenerate run.
    if ax.len() < 3 || bx.len() < 3 {
        return false;
    }

    rings_meet(ax, ay, bx, by)
        || point_in_region(bx, by, Point { x: ax[0], y: ay[0] })
        || point_in_region(ax, ay, Point { x: bx[0], y: by[0] })
}

/// Whether any edge of one ring meets any edge of the other, touching included.
fn rings_meet(ax: &[Dbu], ay: &[Dbu], bx: &[Dbu], by: &[Dbu]) -> bool {
    for i in 0..ax.len() {
        let edge = ring_edge(ax, ay, i);
        for j in 0..bx.len() {
            if segments_intersect(edge, ring_edge(bx, by, j)) {
                return true;
            }
        }
    }
    false
}

/// Whether a point lies in a closed ring, boundary included.
///
/// An even-odd ray cast towards `+x`, exact in `i128`, with the boundary
/// answered first so a point on an edge is *in* the region:
/// [`check_missing_tie`]'s maximum is often attained exactly on a region edge.
///
/// Deliberately not folded with `topology::inside_ring`, whose boundary answer
/// is the opposite one for the opposite reason.
fn point_in_region(xs: &[Dbu], ys: &[Dbu], p: Point) -> bool {
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    // Under three vertices there is no region to be in.
    if xs.len() < 3 {
        return false;
    }

    let zero = DbuArea::new(0);
    let mut inside = false;
    for i in 0..xs.len() {
        let edge = ring_edge(xs, ys, i);
        if point_seg_dist2(p, edge) == zero {
            return true;
        }

        // The half-open crossing rule, then the side test: a vertex that does
        // not straddle the ray contributes `false` whatever the side test says,
        // and a zero `dy` makes the signed product zero, which is not negative.
        let dy = i128::from(edge.b.y.raw() - edge.a.y.raw());
        let dx = i128::from(edge.b.x.raw() - edge.a.x.raw());
        let lhs = i128::from(p.x.raw() - edge.a.x.raw()) * dy;
        let rhs = i128::from(p.y.raw() - edge.a.y.raw()) * dx;
        let straddles = (edge.a.y > p.y) != (edge.b.y > p.y);
        inside ^= straddles & ((lhs - rhs) * dy.signum() < 0);
    }
    inside
}

/// The smallest integer at least the square root of a non-negative area.
///
/// [`gpurify_geom::ops::isqrt`] rounds *toward zero*, which is the wrong
/// rounding for a bound: an upper bound rounded down prunes away the maximum it
/// was supposed to protect.
fn isqrt_ceil(area: i128) -> i64 {
    debug_assert!(area >= 0, "a negative area has no real square root");
    let root = area.isqrt();
    let root = root + i128::from(root * root != area);
    debug_assert!(
        root <= i128::from(i64::MAX),
        "the root of an area built from two in-domain coordinates is a length"
    );
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the assert above is the range check"
    )]
    let narrowed = root as i64;
    narrowed
}

/// Segments a [`TapGrid`] bucket should hold before another bucket is worth the
/// ring walk that reaching it costs. Tuned by measurement, not derived.
const BUCKET_TARGET: i64 = 16;

/// Whether no point of a cell can be further from a tap than the best found.
///
/// The bound is `sqrt(d2) + reach <= sqrt(worst)`, tested as
/// `sqrt(d2) <= worst_root - reach` squared. `worst_root` is `isqrt`'s floor, so
/// it loses under one database unit of slack and loses it on the safe side: the
/// test prunes slightly too rarely, never slightly too often.
///
/// The sign test is not optional — a negative slack squares to a positive number
/// that would pass the second test.
#[inline]
fn prunes(worst_root: i64, reach: i64, d2: DbuArea) -> bool {
    let slack = i128::from(worst_root - reach);
    (slack >= 0) & (d2.raw() <= slack * slack)
}

/// One axis-aligned block of integer points, closed on both ends: the unit of
/// work in [`furthest_from_taps`]'s search.
#[derive(Debug, Clone, Copy)]
struct Cell {
    xlo: i64,
    ylo: i64,
    xhi: i64,
    yhi: i64,
    /// The tap nearest this cell's parent probe, as an index into
    /// [`TapGrid::segs`], inherited by the children.
    hint: u32,
}

/// The nearest tap to some point: how far, and which one.
#[derive(Debug, Clone, Copy)]
struct Nearest {
    dist2: DbuArea,
    /// Index into [`TapGrid::segs`], or [`u32::MAX`] when nothing was scanned.
    tap: u32,
}

impl Nearest {
    /// Nothing scanned yet: the fold's identity.
    const NONE: Self = Self {
        dist2: NO_TAP_IN_RANGE,
        tap: u32::MAX,
    };

    /// Fold one candidate in, keeping whichever is nearer.
    #[inline]
    fn keep(&mut self, other: Self) {
        let mask = u32::from(other.dist2 < self.dist2).wrapping_neg();
        self.tap = (self.tap & !mask) | (other.tap & mask);
        self.dist2 = self.dist2.min(other.dist2);
    }
}

/// A uniform grid over one rule row's tap edges.
///
/// Not `core::index::SpatialIndex`: that builds over a store *layer* and this
/// rule's taps may be derived. Segments rather than boxes because the distance a
/// probe wants is to the tap's edge.
///
/// A segment is filed under *every* cell its bounding box overlaps, which is
/// what makes the ring search's stopping rule sound for a tap edge far longer
/// than a cell.
#[derive(Debug)]
struct TapGrid {
    origin: Point,
    cell: i64,
    nx: i64,
    ny: i64,
    /// `start[b] .. start[b + 1]` indexes `segs`.
    start: Vec<u32>,
    /// The segments themselves, duplicated into every bucket they touch.
    segs: Vec<Seg>,
    /// Build scratch: per-segment extents for the cell-size choice, and the
    /// per-bucket write cursor of the counting sort.
    extents: Vec<i64>,
    cursor: Vec<u32>,
}

/// The empty grid. Hand-written because [`Point`] carries no `Default`.
impl Default for TapGrid {
    fn default() -> Self {
        Self {
            origin: Point {
                x: Dbu::new_unchecked(0),
                y: Dbu::new_unchecked(0),
            },
            cell: 1,
            nx: 0,
            ny: 0,
            start: Vec::new(),
            segs: Vec::new(),
            extents: Vec::new(),
            cursor: Vec::new(),
        }
    }
}

impl TapGrid {
    /// Build over one row's tap edges.
    ///
    /// An empty tap column leaves an empty grid, which [`TapGrid::nybucket`]'s
    /// caller must not probe.
    fn build_into(taps: &[Seg], out: &mut Self) {
        out.start.clear();
        out.segs.clear();
        out.cursor.clear();
        out.cell = 1;
        out.nx = 0;
        out.ny = 0;
        out.origin = Point {
            x: Dbu::new_unchecked(0),
            y: Dbu::new_unchecked(0),
        };
        if taps.is_empty() {
            return;
        }

        let mut extent = Bbox::EMPTY;
        for s in taps {
            extent = extent.include(s.a.x, s.a.y).include(s.b.x, s.b.y);
        }
        let span_x = extent.xhi.raw() - extent.xlo.raw() + 1;
        let span_y = extent.yhi.raw() - extent.ylo.raw() + 1;
        debug_assert!(
            span_x >= 1 && span_y >= 1,
            "a real extent is not the EMPTY sentinel"
        );

        // Cell size by `core::index::SpatialIndex`'s recipe: the median segment
        // extent, widened until the bucket table is O(segments) whatever the
        // aspect ratio. The side count is taken over `taps.len() /
        // BUCKET_TARGET` rather than over `taps.len()`, because a nearest query
        // pays a ring walk and a one-segment bucket is not worth entering.
        out.extents.clear();
        out.extents.reserve(taps.len());
        out.extents.extend(taps.iter().map(|s| {
            (s.b.x.raw() - s.a.x.raw())
                .abs()
                .max((s.b.y.raw() - s.a.y.raw()).abs())
        }));
        debug_assert_eq!(out.extents.len(), taps.len(), "one extent per tap edge");
        let mid = out.extents.len() / 2;
        out.extents.select_nth_unstable(mid);
        let side = (i64::try_from(taps.len()).expect("a tap edge count fits an i64")
            / BUCKET_TARGET)
            .isqrt()
            .max(1);
        let cell = out.extents[mid]
            .max(1)
            .max((span_x + side - 1) / side)
            .max((span_y + side - 1) / side);

        out.cell = cell;
        out.origin = Point {
            x: extent.xlo,
            y: extent.ylo,
        };
        out.nx = (span_x + cell - 1) / cell;
        out.ny = (span_y + cell - 1) / cell;
        debug_assert!(out.nx >= 1 && out.ny >= 1, "a non-empty grid has a cell");
        debug_assert!(
            out.nx <= side && out.ny <= side,
            "the cell size was widened until the bucket table is O(segments)"
        );

        let buckets = usize::try_from(out.nx * out.ny).expect("a bucket count fits a usize");
        out.start.clear();
        out.start.resize(buckets + 1, 0);

        // A counting sort: scatter-accumulate, prefix sum, scatter.
        for seg in taps {
            let (x0, y0, x1, y1) = out.cells_of(*seg);
            for cy in y0..=y1 {
                for cx in x0..=x1 {
                    let b = out.bucket(cx, cy);
                    out.start[b + 1] += 1;
                }
            }
        }
        for b in 0..buckets {
            out.start[b + 1] += out.start[b];
        }
        let total =
            usize::try_from(out.start[buckets]).expect("a filed-segment count fits a usize");
        out.segs.clear();
        out.segs
            .resize(total, *taps.first().expect("the column is not empty"));
        out.cursor.clear();
        out.cursor.extend_from_slice(&out.start[..buckets]);
        for seg in taps {
            let (x0, y0, x1, y1) = out.cells_of(*seg);
            for cy in y0..=y1 {
                for cx in x0..=x1 {
                    let b = out.bucket(cx, cy);
                    let at = usize::try_from(out.cursor[b]).expect("a write cursor fits a usize");
                    out.segs[at] = *seg;
                    out.cursor[b] += 1;
                }
            }
        }
        debug_assert_eq!(
            out.cursor.last().copied(),
            Some(out.start[buckets]),
            "the counting sort filled exactly the space it counted"
        );
    }

    /// The flat bucket index of one in-range cell.
    #[inline]
    fn bucket(&self, cx: i64, cy: i64) -> usize {
        debug_assert!(
            (0..self.nx).contains(&cx) && (0..self.ny).contains(&cy),
            "cell off grid"
        );
        usize::try_from(cy * self.nx + cx).expect("a cell inside the grid has a non-negative index")
    }

    /// The inclusive cell range one segment's bounding box covers, clamped.
    #[inline]
    fn cells_of(&self, seg: Seg) -> (i64, i64, i64, i64) {
        let (x0, x1) = (
            seg.a.x.raw().min(seg.b.x.raw()),
            seg.a.x.raw().max(seg.b.x.raw()),
        );
        let (y0, y1) = (
            seg.a.y.raw().min(seg.b.y.raw()),
            seg.a.y.raw().max(seg.b.y.raw()),
        );
        (
            self.axis_x(x0).clamp(0, self.nx - 1),
            self.axis_y(y0).clamp(0, self.ny - 1),
            self.axis_x(x1).clamp(0, self.nx - 1),
            self.axis_y(y1).clamp(0, self.ny - 1),
        )
    }

    #[inline]
    fn axis_x(&self, x: i64) -> i64 {
        (x - self.origin.x.raw()).div_euclid(self.cell)
    }

    #[inline]
    fn axis_y(&self, y: i64) -> i64 {
        (y - self.origin.y.raw()).div_euclid(self.cell)
    }

    /// One filed tap edge.
    #[inline]
    fn tap(&self, at: u32) -> Seg {
        self.segs[usize::try_from(at).expect("a filed-segment index fits a usize")]
    }

    /// The nearest tap in one cell, or [`Nearest::NONE`] when it is empty.
    #[inline]
    fn nybucket(&self, cx: i64, cy: i64, p: Point) -> Nearest {
        let b = self.bucket(cx, cy);
        let (lo, hi) = (
            usize::try_from(self.start[b]).expect("a bucket offset fits a usize"),
            usize::try_from(self.start[b + 1]).expect("a bucket offset fits a usize"),
        );
        let bucket = &self.segs[lo..hi];
        let mut best = Nearest::NONE;
        for (tap, &seg) in (self.start[b]..).zip(bucket) {
            best.keep(Nearest {
                dist2: point_seg_dist2(p, seg),
                tap,
            });
        }
        best
    }

    /// The nearest tap edge to `p`, exactly.
    ///
    /// Rings of cells are scanned outward from `p`'s own cell, stopping once the
    /// best found is closer than the nearest point of any unscanned cell, which
    /// is `r × cell_size` away because a segment is filed under every cell it
    /// overlaps.
    fn nearest2(&self, p: Point) -> Nearest {
        debug_assert!(
            self.nx >= 1 && self.ny >= 1,
            "an empty grid has no nearest tap"
        );
        let (px, py) = (self.axis_x(p.x.raw()), self.axis_y(p.y.raw()));
        let rmax = px
            .abs()
            .max((px - (self.nx - 1)).abs())
            .max(py.abs())
            .max((py - (self.ny - 1)).abs());

        let mut best = Nearest::NONE;
        let mut r = 0;
        while r <= rmax {
            let (x0, x1) = (px - r, px + r);
            let (y0, y1) = (py - r, py + r);
            for cy in y0.max(0)..=y1.min(self.ny - 1) {
                // The ring's top and bottom rows are scanned whole; the rows
                // between contribute only their two ends.
                if (cy == y0) | (cy == y1) {
                    for cx in x0.max(0)..=x1.min(self.nx - 1) {
                        best.keep(self.nybucket(cx, cy, p));
                    }
                } else {
                    if (0..self.nx).contains(&x0) {
                        best.keep(self.nybucket(x0, cy, p));
                    }
                    if (0..self.nx).contains(&x1) && x1 != x0 {
                        best.keep(self.nybucket(x1, cy, p));
                    }
                }
            }

            // Every segment not yet scanned lies outside the block of cells at
            // Chebyshev radius `r`, so no point of it is nearer than `r × cell`.
            let gap = i128::from(r) * i128::from(self.cell);
            if best.dist2.raw() <= gap * gap {
                break;
            }
            r += 1;
        }

        debug_assert!(
            best.dist2 < NO_TAP_IN_RANGE,
            "a grid with a segment in it has a nearest segment"
        );
        debug_assert!(
            usize::try_from(best.tap).is_ok_and(|at| at < self.segs.len()),
            "the nearest segment is one of the filed ones"
        );
        best
    }
}

/// The point of one region polygon furthest from any tap, and that distance
/// squared — resolved only above `floor`.
///
/// The returned distance is the true maximum whenever that maximum exceeds
/// `floor`, and is `floor` itself otherwise. Pass `DbuArea::new(-1)` for the
/// unconditional maximum.
///
/// Branch and bound over the region's *integer points*, seeded from the
/// vertices. A search over the vertices alone is not enough: it misses the
/// maximum on a long thin region with a tap at each end, and on a wide region
/// tapped only at its corners, which is fail-**open** for a tie rule.
///
/// A cell is pruned when the furthest a point of it could be from a tap is no
/// further than the best already found — `nearest2` is 1-Lipschitz, so that
/// bound is the probe's own distance plus its reach into the cell, and both
/// terms round on the side that never makes the bound optimistic. Surviving
/// cells are quartered; single points cannot be, and dropping them terminates
/// the search at a resolution of one database unit.
///
/// Both uses of a probe's distance want only an *upper* bound on it, so each
/// cell inherits the tap nearest its parent and the exact query runs only on the
/// probes that bound cannot dismiss. Only the exact query ever writes `worst`,
/// so the reported measurement is unchanged.
fn furthest_from_taps(
    xs: &[Dbu],
    ys: &[Dbu],
    bbox: Bbox,
    floor: DbuArea,
    grid: &TapGrid,
    stack: &mut Vec<Cell>,
) -> (Point, DbuArea) {
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    debug_assert!(!xs.is_empty(), "the caller guarded the empty run");

    // Seeded from the region's own vertices, which are in the region by
    // definition and so need no containment test.
    let mut best = Nearest {
        dist2: DbuArea::new(-1),
        tap: 0,
    };
    let mut at = Point { x: xs[0], y: ys[0] };
    for vertex in 0..xs.len() {
        let here = Point {
            x: xs[vertex],
            y: ys[vertex],
        };
        let found = grid.nearest2(here);
        // Not `Nearest::keep`, which folds toward the *nearest* tap; this loop
        // wants the furthest vertex.
        if found.dist2 > best.dist2 {
            best = found;
            at = here;
        }
    }

    // The incumbent starts at the caller's floor when no vertex clears it: a
    // cell is pruned against the incumbent, so on a region whose maximum is
    // under the floor the first few cells prune and the descent never happens.
    // `at` still names the furthest *vertex*, a legal report point, and it is
    // read only when `worst` came back above the floor.
    let mut worst = best.dist2.max(floor);
    let mut worst_root = isqrt(worst).raw();

    stack.clear();
    stack.push(Cell {
        xlo: bbox.xlo.raw(),
        ylo: bbox.ylo.raw(),
        xhi: bbox.xhi.raw(),
        yhi: bbox.yhi.raw(),
        hint: best.tap,
    });
    while let Some(cell) = stack.pop() {
        debug_assert!(
            cell.xlo <= cell.xhi && cell.ylo <= cell.yhi,
            "a cell runs low to high"
        );
        let cx = cell.xlo + (cell.xhi - cell.xlo) / 2;
        let cy = cell.ylo + (cell.yhi - cell.ylo) / 2;
        let here = Point {
            x: Dbu::new_unchecked(cx),
            y: Dbu::new_unchecked(cy),
        };

        // The inherited tap is one real tap and so an upper bound on the
        // distance to the nearest.
        let mut probe = Nearest {
            dist2: point_seg_dist2(here, grid.tap(cell.hint)),
            tap: cell.hint,
        };

        // How far the probe can see into its own cell. Nothing in the cell is
        // further from a tap than the probe's own distance plus this.
        let rx = i128::from((cell.xhi - cx).max(cx - cell.xlo));
        let ry = i128::from((cell.yhi - cy).max(cy - cell.ylo));
        let reach = isqrt_ceil(rx * rx + ry * ry);

        // One test covers both reasons to want the exact query: a probe that
        // beats `worst` cannot prune, so that reason lies inside this one.
        if !prunes(worst_root, reach, probe.dist2) {
            let exact = grid.nearest2(here);
            debug_assert!(
                exact.dist2 <= probe.dist2,
                "the inherited tap is a real tap"
            );
            probe = exact;

            if exact.dist2 > worst && point_in_region(xs, ys, here) {
                worst = exact.dist2;
                worst_root = isqrt(worst).raw();
                at = here;
            }
        }

        // `probe` is the exact nearest whenever the test above failed, so which
        // cells survive here does not depend on the hint.
        if prunes(worst_root, reach, probe.dist2) {
            continue;
        }

        // A single integer point cannot be quartered and has already been
        // probed; dropping it terminates the search.
        let splits_x = cx < cell.xhi;
        let splits_y = cy < cell.yhi;
        if !splits_x && !splits_y {
            continue;
        }

        // A cell one unit wide or one unit tall quarters into two.
        stack.push(Cell {
            xlo: cell.xlo,
            ylo: cell.ylo,
            xhi: cx,
            yhi: cy,
            hint: probe.tap,
        });
        if splits_x {
            stack.push(Cell {
                xlo: cx + 1,
                ylo: cell.ylo,
                xhi: cell.xhi,
                yhi: cy,
                hint: probe.tap,
            });
        }
        if splits_y {
            stack.push(Cell {
                xlo: cell.xlo,
                ylo: cy + 1,
                xhi: cx,
                yhi: cell.yhi,
                hint: probe.tap,
            });
        }
        if splits_x && splits_y {
            stack.push(Cell {
                xlo: cx + 1,
                ylo: cy + 1,
                xhi: cell.xhi,
                yhi: cell.yhi,
                hint: probe.tap,
            });
        }
    }

    debug_assert!(worst.raw() >= 0, "a squared distance is non-negative");
    (at, worst)
}

/// The fold seed for "no tap is in range".
///
/// The largest area [`gpurify_geom::ops::isqrt`] accepts, so a region with no
/// taps at all measures `MAX_ABS_DBU` from one and is reported rather than
/// passed.
const NO_TAP_IN_RANGE: DbuArea = DbuArea::new(1i128 << 80);
