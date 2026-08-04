//! Supply, substrate and pad integrity — topological, but geometry-aware.
//!
//! Five kinds. Like [`crate::rules::topology`] they need no design intent, but
//! unlike those four they read marker geometry as well as the net graph: a tie
//! is a distance, a pad is a marker layer, a soft connection is a path through
//! a layer the deck names as resistive.
//!
//! # Why none of these asks "is this net VDD"
//!
//! Because that is a design-intent question, and these rules always run. A
//! supply short here is *an n-type tie and a p-type tie on one conductor* —
//! true of any CMOS process, provable from the deck's tap markers, and correct
//! without anyone declaring a net name. The version that compares net names
//! against a supply list lives in [`crate::rules::reliability`], where it is
//! gated on intent and says so.

use crate::facts::{NetFacts, RoleMask};
use crate::ruleset::RuleHead;
use crate::{ascending, base_layer, first_vertex, push_net_violations, record_run};
use crate::{Design, Scratch};
use gpurify_core::connectivity::components_into;
use gpurify_core::ops::{isqrt, point_seg_dist2, segments_intersect, Point, Seg};
use gpurify_core::view::validate_layer_into;
use gpurify_core::{Bbox, GeometryStore, LayerId, PolyId, RingRef, ValidatedLayer};
use gpurify_derived::{Evaluator, LayerRef};
use gpurify_ingest::StrId;
use gpurify_report::{Measurement, Outcome, RuleRun, Violation, Violations};
use gpurify_topology::NetId;
use gpurify_units::{Dbu, DbuArea};

/// One conductor carrying two ties of opposite type.
///
/// An n-well tie and a p-substrate tie on the same extracted net is a rail
/// short: the well sits at the substrate's potential, every device on it is
/// mis-biased, and on a real die it is a hole in the power plane. The deck
/// names the two tap markers and the rule needs nothing else — no net names, no
/// device polarity enum, no heuristic about which drain is an output. The old
/// implementation had all three, and its comment admitted it was tuned to one
/// conformance case.
#[derive(Debug, Default)]
pub struct SupplyShortTable {
    pub head: RuleHead,
    /// The two ties whose sharing one net is the short: `nwell_tap` and
    /// `psub_tap` on a standard CMOS deck. Named, not inferred.
    pub tap_a: Vec<LayerRef>,
    pub tap_b: Vec<LayerRef>,
}

/// Two parts of a net joined only through a resistive body.
///
/// A net that is one net in the extraction but two conductors in the silicon,
/// bridged by a well or the substrate. It passes LVS and it does not work: the
/// bridge is kilohms, so the two halves are at different potentials under any
/// load.
///
/// The test is a partition, not a distance: remove the soft layers' shapes from
/// the net's connectivity and ask whether it falls into more than one
/// component. That makes it exact and independent of how far apart the halves
/// are, where the old bounding-box pairwise version was neither.
#[derive(Debug, Default)]
pub struct SoftConnectionTable {
    pub head: RuleHead,
    /// `soft[soft_start[i] .. soft_start[i + 1]]` are row `i`'s resistive
    /// layers — well, substrate, unsilicided poly. CSR.
    pub soft_start: Vec<u32>,
    pub soft: Vec<LayerRef>,
}

/// A point in a tied region too far from the nearest tie.
///
/// Substrate and well resistance is distributed, so a tie at one corner does
/// not hold a large region at potential; foundries state a maximum distance
/// from any point to a tap. The measurement is a distance, exact in [`Dbu`],
/// and it is the one rule here whose limit a grid conversion has to make
/// representable.
#[derive(Debug, Default)]
pub struct MissingTieTable {
    pub head: RuleHead,
    /// The region that must be tied throughout: a well, an active area, a
    /// substrate region.
    pub region: Vec<LayerRef>,
    /// What counts as a tie.
    pub tap: Vec<LayerRef>,
    /// Furthest any point of the region may be from a tap.
    pub max_distance: Vec<Dbu>,
}

/// A gate held at a rail with nothing able to drive it.
///
/// The net carries a gate terminal and a source terminal but no drain, so
/// nothing in the design can change its state. Often deliberate — an unused
/// input tied off is correct practice — which is why the severity is a column:
/// a deck decides whether this is an error or a note.
#[derive(Debug, Default)]
pub struct TieHighLowTable {
    pub head: RuleHead,
}

/// A pad reaching no protection device.
///
/// Every net that reaches a bond pad must also reach a clamp, or the first
/// discharge into that pin goes through a gate oxide. The pad is a marker layer
/// the PDK provides; the clamps are model names the deck lists. The old
/// implementation had neither and guessed at "metal touching the cell boundary"
/// instead, which flags every abutted standard cell in a row.
#[derive(Debug, Default)]
pub struct EsdTopologicalTable {
    pub head: RuleHead,
    /// The marker layer whose polygons are bond pads or I/O.
    pub pad: Vec<LayerId>,
    /// `clamp_model[clamp_start[i] .. clamp_start[i + 1]]` are the interned
    /// model names that count as protection for row `i`. CSR.
    pub clamp_start: Vec<u32>,
    pub clamp_model: Vec<StrId>,
}

/// Flag every net carrying both taps.
///
/// **Transform.** Per rule row: evaluate the two tap layers, mark each tap's
/// net in a per-net slot of `scratch` with which tap it was, and report every
/// net marked with both. Two passes for the kernel rule's reason — the second
/// reads what the first wrote, so they cannot be one.
///
/// `examined` is the number of tap polygons across both layers.
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
        let (Some(tap_a), Some(tap_b)) = (base_layer(table.tap_a[row]), base_layer(table.tap_b[row]))
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

        // Branchless: `NetId::NONE` is `u32::MAX`, so `min` routes a tap drawn
        // on a non-conducting layer into the trash slot the second pass never
        // reads, rather than guarding the store with an `if`.
        //
        // Guarded on `extracted`, which is a hoisted uniform and not a per-row
        // test: `NetTable::net_of` fails closed by *panicking* on a polygon its
        // table never saw, and a run handed `NetTable::default()` has seen none
        // of them. No net means no net carrying both taps, so the marking pass
        // has nothing to write — and `examined` is still the tap polygons,
        // because they were looked at either way.
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

        // Pass two, and it is a separate pass for the kernel rule's reason: it
        // reads what pass one wrote.
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
            // most one per iteration and starts equal to `i` at zero. Rejected
            // slots stay uninit and are truncated away by `set_len(w)`;
            // `(u32, u32)` has no `Drop`.
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
/// **Transform.** Per rule row: build the net's connectivity edge list from
/// hard conductors only, label components with `core::connectivity`, and report
/// any net whose polygons carry more than one label. The edge list and the
/// labels are `scratch` buffers, so a design with a hundred thousand nets
/// allocates twice, not two hundred thousand times.
///
/// The violation names the two shapes on either side of the bridge, so a viewer
/// lands on the gap rather than on the net as a whole.
///
/// `examined` is the number of nets touching at least one soft layer.
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

        // Deck-sized: a row names a well, a substrate and an unsilicided poly,
        // so this is three layers and not bulk.
        is_soft.clear();
        is_soft.resize(layers, false);
        soft_layers.clear();
        let mut resolved = true;
        for &layer in &table.soft[span] {
            match base_layer(layer) {
                // Fail closed: a layer the store's table does not have indexes
                // out of bounds and panics here, in every profile.
                Some(base) => {
                    // `is_soft` is idempotent under a deck that names one layer
                    // twice; the row-range list is not, and a duplicate would
                    // make pass one walk the same polygons again for no mark it
                    // has not already set.
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

        // Pass one: which nets touch a soft layer at all. A scatter again, with
        // `check_supply_short`'s trash slot.
        //
        // Reached through `polys_on_layer` per soft layer, so it walks the three
        // rows ranges a deck row names — a well, a substrate, an unsilicided
        // poly — rather than every polygon in the store, and the layer test *is*
        // the row range rather than a gather into `is_soft` per polygon. The
        // outer loop is deck-sized and the mark is unconditional.
        //
        // Guarded on `extracted`, a hoisted uniform: `NetTable::net_of` fails
        // closed by *panicking* on a polygon its table never saw, and a run
        // handed `NetTable::default()` has seen none of them. With no nets,
        // nothing touches a soft layer *on a net*, which is the only sense this
        // rule has.
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

        // Pass two, separate for the kernel rule's reason.
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
            // truncated away by `set_len(w)`; `(u32, u32)` has no `Drop`.
            debug_assert!(w <= i);
            // SAFETY: `w <= i < n == slots.len()`, from the induction above.
            unsafe { slots.get_unchecked_mut(w) }.write(row);
            w += usize::from(p);
        }
        // SAFETY: slots `0..w` were each written when `w` held that value, and
        // `w <= n <= capacity`.
        unsafe { soft_nets.set_len(w) };

        let examined = w;
        debug_assert_eq!(examined, soft_nets.len(), "the compact and its count disagree");

        for &(net, _) in &soft_nets {
            let net = NetId(net);
            // The net's conductors with the resistive body removed. That
            // removal is the whole rule: what is left is what the silicon
            // actually holds at one potential.
            let polys = design.nets.polys_of(net);
            let n = polys.len();
            hard.clear();
            hard.reserve(n);
            let slots = &mut hard.spare_capacity_mut()[..n];

            let mut w = 0usize;
            for (i, &poly) in polys.iter().enumerate() {
                // The `is_soft` load is a gather — a data-dependent *address*,
                // not a branch.
                let p = !is_soft[design.store.poly_layer(poly).idx()];
                // `w <= i` by induction: `bool` is 0 or 1, so `w` advances by
                // at most one per iteration. Rejected slots stay uninit and are
                // truncated away by `set_len(w)`; `PolyId` has no `Drop`.
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
            debug_assert_eq!(scratch.boxes.len(), hard.len(), "one box per hard conductor");

            // Adjacency over one net's hard conductors, and the pair it keeps is
            // the pair that shares a *point*, not the pair whose boxes overlap:
            // a box is a superset of the shape inside it, so joining two
            // conductors that only share a box merges two components into one
            // and *under*-reports the bridge this rule exists to find. That is
            // fail-open, and it is the same discipline `topology` applies to
            // every pair its own bounding-box prune keeps.
            //
            // The box test survives as the prune in front of the exact one, and
            // an x-order sweep is what keeps the scan off O(k²): with the
            // conductors in ascending `xlo`, the first one starting past `a`'s
            // right edge ends `a`'s row, because so does every one after it.
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
                    // Surviving `if`: the sweep's exit, so it is not taken for
                    // any pair but the one that ends the row and predicts at
                    // ~100%, and the side it skips is the rest of the scan.
                    if box_b.xlo > box_a.xhi {
                        break;
                    }
                    // Surviving `if`, and `&&` rather than `&`: the exact test
                    // is two ring walks, which is the expensive side a branch
                    // exists to skip.
                    if box_a.overlaps(box_b) && polys_meet(design.store, hard[a as usize], hard[b as usize])
                    {
                        scratch.edges.push((a, b));
                    }
                }
            }

            components_into(node_count, &scratch.edges, &mut scratch.labels);
            debug_assert_eq!(scratch.labels.len(), hard.len(), "one label per conductor");

            // The lowest-numbered conductor on the far side of the bridge, or
            // `u32::MAX` when there is no far side. Branchless: a row that
            // agrees with the first label is smeared to `u32::MAX` and loses
            // the `min`, so no `if` decides the answer.
            let near = scratch.labels[0];
            let mut far = u32::MAX;
            // The counter rides in the iterator rather than beside it, so the
            // body stays three arithmetic ops with no bounds check and no cast.
            for (idx, &label) in (0u32..).zip(&scratch.labels) {
                let same = u32::from(label == near).wrapping_neg();
                far = far.min(idx | same);
            }
            debug_assert!(
                far == u32::MAX || (far as usize) < hard.len(),
                "the far side of a bridge is one of this net's own conductors"
            );

            // Surviving `if`: one test per net, and the taken side is a push.
            if far != u32::MAX {
                let far_poly = hard[far as usize];
                out.push(Violation {
                    rule,
                    layer: design.store.poly_layer(first_poly),
                    severity: table.head.severity[row],
                    at: first_vertex(design.store, first_poly),
                    // The net is one conductor in the extraction and two in the
                    // silicon; one is the limit.
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
/// **Transform.** Per rule row: index the taps once, then for each region
/// polygon find the furthest point of the region from every tap. The reported
/// point is that furthest point, and the measurement is its distance — not the
/// corner-sampling approximation the old implementation used, which missed a
/// long thin region entirely because all four of its corners were near a tap.
///
/// Distances are exact: `core::ops::point_seg_dist2` in [`DbuArea`], compared
/// against the squared limit, so no square root and no rounding enters a
/// verdict.
///
/// `examined` is the number of region polygons.
///
/// [`DbuArea`]: gpurify_units::DbuArea
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

    // The taps' edges, the grid over them and the search's cell stack: one flat
    // column per rule row, hoisted above the row loop so a deck configuring the
    // rule twice allocates once.
    let mut taps: Vec<Seg> = Vec::new();
    let mut grid = TapGrid::default();
    let mut stack: Vec<Cell> = Vec::new();

    for row in 0..rows {
        let before = out.len();
        let rule = table.head.rule[row];
        // The region alone has to be a base layer: it is what the violation
        // names, and a derived one hands out no `PolyId` to name. The tap is
        // only ever measured *to*, so it may be either.
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
        // Squared, so no square root enters a verdict. `mul_wide` is the only
        // route from coordinates to an area and it asserts both operands are
        // inside the domain `MAX_ABS_DBU` bounds the `i128` product with.
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

        // Index the taps once per rule row, which is what makes the search below
        // ask a bounded number of segments per probe rather than the whole
        // column.
        TapGrid::build_into(&taps, &mut grid);

        // A region measured against no taps at all is untied everywhere, and the
        // sentinel is the whole answer. Hoisted to one uniform rather than
        // carried through the search's arithmetic, where `MAX_ABS_DBU` would
        // defeat every bound it has.
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
            // whose root is `MAX_ABS_DBU` — the largest representable distance,
            // so an untied region is reported rather than passed. Fail closed.
            //
            // Surviving `if`: `tapped` is a uniform, hoisted above the row loop,
            // not a test on this row's data.
            let (at, worst) = if tapped {
                furthest_from_taps(xs, ys, design.store.poly_bbox(poly), &grid, &mut stack)
            } else {
                (Point { x: x0, y: y0 }, NO_TAP_IN_RANGE)
            };
            debug_assert!(worst.raw() >= 0, "a squared distance is non-negative");

            // Surviving `if`: one test per region polygon, and the taken side is
            // a push into eight columns.
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
///
/// **Transform.** One pass over [`NetFacts::role`]: the mask contains
/// `GATE | SOURCE` and does not contain `DRAIN`. Three bit tests per net, no
/// branch, no lookup.
///
/// `examined` is the number of nets carrying at least one gate terminal.
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

    // Hoisted uniforms, above the fold rather than rebuilt per net. Not `const`
    // items: `RoleMask::union` is a frozen `const fn` whose body this module
    // does not own, and a `const` would evaluate it at compile time.
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

        // Three bit tests per net and no branch: `&`, not `&&`, because both
        // operands are already-loaded bytes with no side effect.
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
            // truncated away by `set_len(w)`; `(u32, RoleMask)` has no `Drop`.
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
            // No drain reaches this net, and one is what it would take to drive
            // it.
            Measurement::Count(0),
            Measurement::Count(1),
            out,
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every pad net reaching none of the listed clamp models.
///
/// **Transform.** Per rule row: collect the nets under the pad markers, then
/// walk each such net's devices and test their model against the row's clamp
/// list. The list is two or three interned ids, so the test is a linear scan
/// over `u32` and not a set.
///
/// `examined` is the number of distinct pad nets.
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
    // No `Scratch` in this signature, so both buffers are local — hoisted above
    // the row loop, which is where the reuse is.
    let mut on_a_pad: Vec<u32> = Vec::new();
    let mut pad_nets: Vec<(u32, u32)> = Vec::new();

    for row in 0..rows {
        let before = out.len();
        let rule = table.head.rule[row];
        let clamps = &table.clamp_model[table.clamp_start[row] as usize
            ..table.clamp_start[row + 1] as usize];

        // Pass one: which nets a pad marker lands on. A scatter, with
        // `check_supply_short`'s trash slot for a marker on no conductor, and
        // its `extracted` guard for the same reason — `NetTable::net_of` fails
        // closed by *panicking* on a polygon its table never saw.
        on_a_pad.clear();
        on_a_pad.resize(nets + 1, 0);
        if extracted {
            for poly in design.store.polys_on_layer(table.pad[row]) {
                let slot = design.nets.net_of(PolyId(poly)).idx().min(nets);
                on_a_pad[slot] = 1;
            }
        }

        // Pass two, separate for the kernel rule's reason. The kept count is the
        // number of *distinct* pad nets, which is what `examined` claims.
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
            // truncated away by `set_len(w)`; `(u32, u32)` has no `Drop`.
            debug_assert!(w <= i);
            // SAFETY: `w <= i < n == slots.len()`, from the induction above.
            unsafe { slots.get_unchecked_mut(w) }.write(row);
            w += usize::from(p);
        }
        // SAFETY: slots `0..w` were each written when `w` held that value, and
        // `w <= n <= capacity`.
        unsafe { pad_nets.set_len(w) };

        let examined = w;
        debug_assert_eq!(examined, pad_nets.len(), "the compact and its count disagree");

        for &(net, _) in &pad_nets {
            let net = NetId(net);
            // A linear scan over two or three interned ids, as the rule's doc
            // comment states, over the handful of devices on one net. Neither
            // is bulk, and the search exits on the first clamp it reaches.
            let protected = design
                .devices
                .devices_on(net)
                .iter()
                .any(|&device| clamps.contains(&design.devices.model[device.0 as usize]));

            // Surviving `if`: one test per pad net, and the taken side is a push
            // into eight columns.
            if !protected {
                let Some(&poly) = design.nets.polys_of(net).first() else {
                    continue;
                };
                out.push(Violation {
                    rule,
                    layer: design.store.poly_layer(poly),
                    severity: table.head.severity[row],
                    at: first_vertex(design.store, poly),
                    // No listed clamp model reaches this pad, and one is what it
                    // takes to keep a discharge out of a gate oxide.
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
/// **Transform, dispatcher.** The two spellings of a layer reference reach
/// geometry by different routes and neither is the other's special case, so the
/// choice is made once, here, rather than inside the measurement loop.
///
/// A tap is only ever measured *to*, so unlike every other layer in this module
/// it needs no [`PolyId`]: a derived tap — `nsdm AND diff` on a standard CMOS
/// deck, which is how a real deck spells one — is usable, and this is the one
/// rule here that can take it. `scratch` is the caller's [`Scratch::layer_b`],
/// the buffer that field exists for, so a base layer is validated into an
/// allocation the run already owns.
///
/// `None` is a refusal, never an empty layer: a name the evaluator does not
/// hold, or geometry `core::view` will not represent, both mean the rule could
/// not read its taps — and a region measured against no taps at all is reported
/// clean by exactly the arithmetic that would report it correctly.
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

/// Append one ring's closed edges to a segment column.
///
/// **Transform, gatherer.** Caller owns `out` and this appends rather than
/// refilling, because one tap polygon contributes an outer boundary and every
/// hole it has.
fn push_ring_edges(ring: RingRef<'_>, out: &mut Vec<Seg>) {
    let (xs, ys) = ring.coords();
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    debug_assert!(xs.len() >= 3, "a validated ring has at least three vertices");
    out.reserve(xs.len());
    for vertex in 0..xs.len() {
        out.push(ring_edge(xs, ys, vertex));
    }
}

/// The closed edge from vertex `i` of a ring to the next one, wrapping.
///
/// **Decision** — a ring and an index in, one segment out.
#[inline]
fn ring_edge(xs: &[Dbu], ys: &[Dbu], i: usize) -> Seg {
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    debug_assert!(i < xs.len(), "a ring edge starts at one of the ring's vertices");
    // Branchless wrap, the catalogue's `i++; if i >= n { i = 0 }` row: the
    // subtraction is by zero for every vertex but the last, which is what puts
    // the ring's closing edge in the same pass with no fixup after it.
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
/// **Decision** — two rows in, one bool out. The bounding-box prune upstream
/// answers "these two boxes touch", and a box is a superset of the shape inside
/// it: joining two conductors that share only a bounding box merges two
/// components into one and is fail-**open** for
/// [`check_soft_connection`], whose whole verdict is the component count. So
/// every pair the prune keeps is re-tested exactly.
///
/// Two rings whose boundaries do not meet are either nested or disjoint, so one
/// vertex of each decides the rest.
///
/// This is [`gpurify_topology`]'s own `polys_intersect` predicate, which is
/// private to that crate. Restated rather than reached for, because widening
/// another crate's interface is a Definition-Phase change and this is not that
/// phase; the shared primitive underneath both is `core::ops`.
fn polys_meet(store: &GeometryStore, a: PolyId, b: PolyId) -> bool {
    let (ax, ay) = store.poly_verts(a);
    let (bx, by) = store.poly_verts(b);
    debug_assert_eq!(ax.len(), ay.len(), "the store's columns are parallel");
    debug_assert_eq!(bx.len(), by.len(), "the store's columns are parallel");

    // A run with under three vertices bounds no area and so shares no point
    // with anything. Guarded rather than asserted because the probes below read
    // vertex zero, and `ingest` is allowed to carry a degenerate run.
    if ax.len() < 3 || bx.len() < 3 {
        return false;
    }

    // `||`, not `|`: each containment walk is a full pass over a ring, which is
    // the "taken side is expensive" escape valve.
    rings_meet(ax, ay, bx, by)
        || point_in_region(bx, by, Point { x: ax[0], y: ay[0] })
        || point_in_region(ax, ay, Point { x: bx[0], y: by[0] })
}

/// Whether any edge of one ring meets any edge of the other, touching included.
///
/// **Decision** — two rings in, one bool out. O(n×m) over two rings' edges,
/// reached only after a bounding-box prune has rejected everything far apart,
/// and a layout polygon carries a handful of vertices.
fn rings_meet(ax: &[Dbu], ay: &[Dbu], bx: &[Dbu], by: &[Dbu]) -> bool {
    for i in 0..ax.len() {
        let edge = ring_edge(ax, ay, i);
        for j in 0..bx.len() {
            // Surviving `if`: the exit of a search. It is not taken for any edge
            // pair but the one that answers the question, so it predicts at
            // ~100%, and the side it skips is the rest of the scan.
            if segments_intersect(edge, ring_edge(bx, by, j)) {
                return true;
            }
        }
    }
    false
}

/// Whether a point lies in a closed ring, boundary included.
///
/// **Decision** — a ring and a point in, one bool out. An even-odd ray cast
/// towards `+x`, exact in `i128`, with the boundary answered first so a point on
/// an edge is *in* the region rather than in whichever half the crossing rule
/// happened to put it. That matters here because
/// [`check_missing_tie`]'s maximum is often attained exactly on a region edge.
///
/// Not a bulk loop: a layout polygon carries a handful of vertices.
///
/// Deliberately not folded with `topology::inside_ring`, whose boundary answer
/// is the opposite one for the opposite reason; the argument is written out
/// there.
fn point_in_region(xs: &[Dbu], ys: &[Dbu], p: Point) -> bool {
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    // Under three vertices there is no region to be in. One test per call,
    // hoisted above both folds.
    if xs.len() < 3 {
        return false;
    }

    let zero = DbuArea::new(0);
    let mut inside = false;
    for i in 0..xs.len() {
        let edge = ring_edge(xs, ys, i);
        // Surviving `if`: the exit of a search, not taken for any edge but the
        // one that answers the question, and the side it skips is the rest of
        // the walk.
        if point_seg_dist2(p, edge) == zero {
            return true;
        }

        // The half-open crossing rule, then the side test, both branchless. A
        // vertex that does not straddle the ray contributes `false` whatever
        // the side test says, and a zero `dy` makes the signed product zero,
        // which is not negative.
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
/// **Decision** — one area in, one length out. [`gpurify_core::ops::isqrt`]
/// rounds *toward zero*, which is the right rounding for a reported measurement
/// and the wrong one for a bound: an upper bound rounded down prunes away the
/// maximum it was supposed to protect.
fn isqrt_ceil(area: i128) -> i64 {
    debug_assert!(area >= 0, "a negative area has no real square root");
    let root = area.isqrt();
    // Branchless round-up, the catalogue's `if p { n += 1 }` row.
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

/// One axis-aligned block of integer points, closed on both ends.
///
/// The unit of work in [`furthest_from_taps`]'s search. `i64` rather than
/// [`Dbu`], because a cell is an interval over the coordinate domain rather than
/// a coordinate, and its midpoint arithmetic is not a coordinate operation.
#[derive(Debug, Clone, Copy)]
struct Cell {
    xlo: i64,
    ylo: i64,
    xhi: i64,
    yhi: i64,
}

/// A uniform grid over one rule row's tap edges.
///
/// **Five questions.** In: the tap segment column. Out: bucket offsets and the
/// segments grouped by bucket. How many: one per rule row, rebuilt from one
/// hoisted allocation. Access pattern: built once, probed many times, always
/// outward from the probe's own cell — so CSR, like
/// [`gpurify_core::index::SpatialIndex`]. Lifetime: phase. Parallelisable: the
/// probes are independent.
///
/// Not `core::index::SpatialIndex` itself: that one builds over a store *layer*
/// and indexes polygon rows, and this rule's taps may be a derived layer, which
/// has no rows in a store and hands out no [`PolyId`]. Segments rather than
/// boxes for the same reason the measurement is exact — the distance a probe
/// wants is to the tap's edge, not to a box around it.
///
/// A segment is filed under *every* cell its bounding box overlaps, not just the
/// one holding an endpoint. That is what makes the ring search's stopping rule
/// sound for a tap edge far longer than a cell — the alternative, one cell per
/// segment plus a global maximum-extent margin, is fail-open the moment one long
/// edge widens the margin past anything useful.
#[derive(Debug)]
struct TapGrid {
    origin: Point,
    cell: i64,
    nx: i64,
    ny: i64,
    /// `start[b] .. start[b + 1]` indexes `segs`.
    start: Vec<u32>,
    /// The segments themselves, duplicated into every bucket they touch. Stored
    /// rather than indexed: a bucket scan is then one contiguous fold with no
    /// gather.
    segs: Vec<Seg>,
    /// Build scratch: per-segment extents for the cell-size choice, and the
    /// per-bucket write cursor of the counting sort.
    extents: Vec<i64>,
    cursor: Vec<u32>,
}

/// The empty grid. Hand-written because [`Point`] carries no `Default` — a
/// coordinate has no neutral value, which is exactly the invariant that keeps a
/// zero from being mistaken for one.
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
    /// **Transform.** Caller owns the grid; it is cleared and refilled, so a
    /// deck configuring the rule twice allocates once. An empty tap column
    /// leaves an empty grid, which [`TapGrid::nybucket`]'s caller must not
    /// probe — [`check_missing_tie`] hoists that to one `tapped` uniform.
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
        debug_assert!(span_x >= 1 && span_y >= 1, "a real extent is not the EMPTY sentinel");

        // Cell size by `core::index::SpatialIndex`'s recipe and for its reasons:
        // the median segment extent, so half the column files into a single
        // cell, then widened until the bucket table is O(segments) whatever the
        // aspect ratio — a 1 nm-tall, 1 mm-wide tap must not ask for a million
        // buckets per edge.
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
        let side = i64::try_from(taps.len())
            .expect("a tap edge count fits an i64")
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

        // A counting sort: a scatter-accumulate, then a prefix sum, then a
        // scatter — the same shape `SpatialIndex::build_into` uses, one file
        // over.
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
        let total = usize::try_from(out.start[buckets]).expect("a filed-segment count fits a usize");
        out.segs.clear();
        out.segs.resize(total, *taps.first().expect("the column is not empty"));
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
        debug_assert!((0..self.nx).contains(&cx) && (0..self.ny).contains(&cy), "cell off grid");
        usize::try_from(cy * self.nx + cx).expect("a cell inside the grid has a non-negative index")
    }

    /// The inclusive cell range one segment's bounding box covers, clamped.
    #[inline]
    fn cells_of(&self, seg: Seg) -> (i64, i64, i64, i64) {
        let (x0, x1) = (seg.a.x.raw().min(seg.b.x.raw()), seg.a.x.raw().max(seg.b.x.raw()));
        let (y0, y1) = (seg.a.y.raw().min(seg.b.y.raw()), seg.a.y.raw().max(seg.b.y.raw()));
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

    /// The least squared distance from `p` to any bucket in one cell.
    #[inline]
    fn nybucket(&self, cx: i64, cy: i64, p: Point) -> DbuArea {
        let b = self.bucket(cx, cy);
        let (lo, hi) = (
            usize::try_from(self.start[b]).expect("a bucket offset fits a usize"),
            usize::try_from(self.start[b + 1]).expect("a bucket offset fits a usize"),
        );
        // `point_seg_dist2`'s domain preconditions are `debug_assert`s and are
        // the only panic edge in this loop; they cannot fire on geometry
        // `ingest` built, which checked every coordinate against the same bound
        // once.
        let bucket = &self.segs[lo..hi];
        let mut best = NO_TAP_IN_RANGE;
        for &seg in bucket {
            best = best.min(point_seg_dist2(p, seg));
        }
        best
    }

    /// The squared distance from `p` to the nearest tap edge.
    ///
    /// **Decision** — one point in, one squared distance out. Exact: rings of
    /// cells are scanned outward from `p`'s own cell and the scan stops only
    /// once the best found is closer than the nearest point of any cell not yet
    /// scanned, which is `r × cell_size` away because a segment is filed under
    /// every cell it overlaps.
    fn nearest2(&self, p: Point) -> DbuArea {
        debug_assert!(self.nx >= 1 && self.ny >= 1, "an empty grid has no nearest tap");
        let (px, py) = (self.axis_x(p.x.raw()), self.axis_y(p.y.raw()));
        let rmax = px
            .abs()
            .max((px - (self.nx - 1)).abs())
            .max(py.abs())
            .max((py - (self.ny - 1)).abs());

        let mut best = NO_TAP_IN_RANGE;
        let mut r = 0;
        while r <= rmax {
            let (x0, x1) = (px - r, px + r);
            let (y0, y1) = (py - r, py + r);
            for cy in y0.max(0)..=y1.min(self.ny - 1) {
                // Four `if`s per row of one ring, all on grid indices and none
                // on bulk data: the ring's top and bottom rows are scanned
                // whole, the rows between contribute only their two ends.
                if (cy == y0) | (cy == y1) {
                    for cx in x0.max(0)..=x1.min(self.nx - 1) {
                        best = best.min(self.nybucket(cx, cy, p));
                    }
                } else {
                    if (0..self.nx).contains(&x0) {
                        best = best.min(self.nybucket(x0, cy, p));
                    }
                    if (0..self.nx).contains(&x1) && x1 != x0 {
                        best = best.min(self.nybucket(x1, cy, p));
                    }
                }
            }

            // Every segment not yet scanned lies outside the block of cells at
            // Chebyshev radius `r`, so no point of it is nearer than `r × cell`.
            let gap = i128::from(r) * i128::from(self.cell);
            if best.raw() <= gap * gap {
                break;
            }
            r += 1;
        }

        debug_assert!(
            best < NO_TAP_IN_RANGE,
            "a grid with a segment in it has a nearest segment"
        );
        best
    }
}

/// The point of one region polygon furthest from any tap, and that distance
/// squared.
///
/// **Decision** — one ring, its bounding box and a tap grid in, one point and
/// one squared distance out. `stack` is caller-owned scratch, cleared on entry,
/// so a layer of a hundred thousand regions allocates once.
///
/// This is the rule's whole claim — [`check_missing_tie`]'s doc comment says
/// *the* furthest point — and a search over the region's vertices alone does not
/// make it. Vertices are exact where the maximum sits on a corner, which is the
/// rectangle, the L and the ring; they miss it on the two cases a real layout
/// actually fails on, a long thin region with a tap at each end and a wide
/// region tapped only at its corners. Missing a maximum is a missed violation,
/// which is fail-**open** for a tie rule.
///
/// So: branch and bound over the region's integer points, seeded from the
/// vertices. A cell is pruned when the furthest a point of it could possibly be
/// from a tap is no further than the best already found — `nearest2` is
/// 1-Lipschitz, so that bound is the probe's own distance plus the probe's reach
/// into its cell, and both terms round *up* so the bound is never optimistic. A
/// cell that survives is quartered. Single points cannot be quartered, and
/// dropping them is what terminates the search: `Dbu` is an integer, so the
/// resolution floor is one database unit and the answer is exact over every
/// point the report could name.
///
/// **Cost.** Set by the *shape* of the maximum, not by the region's size: an
/// isolated maximum — every shape a layout is mostly made of — prunes within a
/// few cells of the seed, and only a maximum spread along a ridge forces the
/// descent to the floor. The worst measured case is a region tapped along one
/// edge alone, 200 µm square at a nanometre grid, at 1.7 s release. A region
/// that size tapped anywhere sane is microseconds.
fn furthest_from_taps(
    xs: &[Dbu],
    ys: &[Dbu],
    bbox: Bbox,
    grid: &TapGrid,
    stack: &mut Vec<Cell>,
) -> (Point, DbuArea) {
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    debug_assert!(!xs.is_empty(), "the caller guarded the empty run");

    // Seeded from the region's own vertices, which are in the region by
    // definition and so need no containment test. On the shapes a layout is
    // mostly made of the answer is already here, and a strong seed is what makes
    // the search below prune at its first few cells instead of descending.
    //
    // Not a bulk loop: a layout polygon carries a handful of vertices, and it is
    // the fold inside `nearest2` that is bulk.
    let mut worst = DbuArea::new(-1);
    let mut at = Point { x: xs[0], y: ys[0] };
    for vertex in 0..xs.len() {
        let here = Point {
            x: xs[vertex],
            y: ys[vertex],
        };
        let d2 = grid.nearest2(here);
        // Surviving `if`: not a bulk loop, for the reason above, and the taken
        // side is two stores.
        if d2 > worst {
            worst = d2;
            at = here;
        }
    }

    stack.clear();
    stack.push(Cell {
        xlo: bbox.xlo.raw(),
        ylo: bbox.ylo.raw(),
        xhi: bbox.xhi.raw(),
        yhi: bbox.yhi.raw(),
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
        let d2 = grid.nearest2(here);

        // `&&`, not `&`: the containment walk is a pass over the region's ring
        // and is the expensive side a branch exists to skip. It is skipped for
        // every probe that could not have won anyway, which is nearly all of
        // them.
        if d2 > worst && point_in_region(xs, ys, here) {
            worst = d2;
            at = here;
        }

        // The bound. `reach` is how far the probe can see into its own cell, so
        // nothing in the cell is further from a tap than `d2`'s root plus it.
        let rx = i128::from((cell.xhi - cx).max(cx - cell.xlo));
        let ry = i128::from((cell.yhi - cy).max(cy - cell.ylo));
        let bound = i128::from(isqrt_ceil(d2.raw())) + i128::from(isqrt_ceil(rx * rx + ry * ry));
        // Surviving `if`: the prune, which is the whole point of the search and
        // is taken for the overwhelming majority of cells.
        if bound * bound <= worst.raw() {
            continue;
        }

        // A single integer point cannot be quartered and has already been
        // probed. Dropping it terminates the search; every other cell shrinks on
        // at least one axis per split.
        let splits_x = cx < cell.xhi;
        let splits_y = cy < cell.yhi;
        if !splits_x && !splits_y {
            continue;
        }

        // Four tests per surviving cell, on cell geometry rather than on bulk
        // data: a cell one unit wide or one unit tall quarters into two.
        stack.push(Cell {
            xlo: cell.xlo,
            ylo: cell.ylo,
            xhi: cx,
            yhi: cy,
        });
        if splits_x {
            stack.push(Cell {
                xlo: cx + 1,
                ylo: cell.ylo,
                xhi: cell.xhi,
                yhi: cy,
            });
        }
        if splits_y {
            stack.push(Cell {
                xlo: cell.xlo,
                ylo: cy + 1,
                xhi: cx,
                yhi: cell.yhi,
            });
        }
        if splits_x && splits_y {
            stack.push(Cell {
                xlo: cx + 1,
                ylo: cy + 1,
                xhi: cell.xhi,
                yhi: cell.yhi,
            });
        }
    }

    debug_assert!(worst.raw() >= 0, "a squared distance is non-negative");
    (at, worst)
}

/// The fold seed for "no tap is in range".
///
/// The largest area [`gpurify_core::ops::isqrt`] accepts, so a region with no
/// taps at all measures `MAX_ABS_DBU` away from one — the largest representable
/// distance — and is reported rather than passed. A saturating sentinel is
/// fail-*open* for a spacing rule; this is the same sentinel pointed the other
/// way, and it is why it is the seed of a `min` rather than of a `max`.
const NO_TAP_IN_RANGE: DbuArea = DbuArea::new(1i128 << 80);
