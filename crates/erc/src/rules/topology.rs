//! Rules that ask only what is connected to what.
//!
//! Nothing here re-derives connectivity: a gate is floating because `topology`
//! says the only terminal on its net is a gate.

use crate::facts::{NetFacts, RoleMask};
use crate::ruleset::RuleHead;
use crate::{
    ascending, base_layer, centre, first_vertex, push_net_violations, record_run, Design, Scratch,
};
use gpurify_core::ops::{winding_of, Winding};
use gpurify_core::{LayerId, PolyId};
use gpurify_derived::LayerRef;
use gpurify_report::{Measurement, Outcome, RuleRun, Violation, Violations};
use gpurify_topology::{DeviceId, NetId, TerminalRole};
use gpurify_units::Dbu;

/// A gate net with nothing driving it: the net's role mask is exactly
/// [`RoleMask::GATE`].
///
/// [`RoleMask::GATE`]: crate::RoleMask::GATE
#[derive(Debug, Default)]
pub struct FloatingGateTable {
    pub head: RuleHead,
}

/// A well with no tap tying it to a supply.
#[derive(Debug, Default)]
pub struct FloatingWellTable {
    pub head: RuleHead,
    /// The region that must be tied.
    pub well: Vec<LayerRef>,
    /// What counts as a tie inside it.
    pub tap: Vec<LayerRef>,
}

/// A net driven by more than one output.
///
/// The count is over distinct gate nets, not over drains: a parallel pair
/// sharing a gate is one driver built wide.
#[derive(Debug, Default)]
pub struct MultipleDriversTable {
    pub head: RuleHead,
    /// Distinct driving gate nets permitted on one net.
    pub max_drivers: Vec<u32>,
}

/// A conductor on a net no device terminal touches.
#[derive(Debug, Default)]
pub struct UnconnectedPinTable {
    pub head: RuleHead,
    /// `layer[layer_start[i] .. layer_start[i + 1]]` are row `i`'s layers.
    pub layer_start: Vec<u32>,
    pub layer: Vec<LayerId>,
}

/// Flag every net whose only terminals are gates.
///
/// `examined` is the number of nets carrying at least one gate terminal —
/// counting every net instead would make a design with one transistor look
/// thoroughly checked.
pub fn check_floating_gate(
    design: Design<'_>,
    facts: &NetFacts,
    table: &FloatingGateTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.len();
    debug_assert_eq!(
        table.head.severity.len(),
        rows,
        "a rule head's two columns arrive parallel"
    );
    debug_assert!(
        facts.len() <= design.nets.net_count(),
        "the role column names more nets than the extraction produced"
    );

    let roles = &facts.role[..];
    let nets = roles.len();
    let mut examined = 0u64;
    for role in roles {
        examined += u64::from(role.intersects(RoleMask::GATE));
    }
    debug_assert!(
        examined <= u64::try_from(facts.len()).unwrap_or(u64::MAX),
        "more gate nets than nets"
    );

    // The net column pairs with the mask column so the kept rows carry the net
    // that owns them.
    let net_index = ascending(facts.len());
    debug_assert_eq!(net_index.len(), nets, "SoA columns must agree");
    let net_index = &net_index[..nets];

    // Reserved for the whole input rather than for the survivors: that
    // over-reservation is what lets the store below be unconditional.
    let mut flagged: Vec<(u32, RoleMask)> = Vec::with_capacity(nets);
    let slots = &mut flagged.spare_capacity_mut()[..nets];
    let mut count = 0usize;
    for i in 0..nets {
        let row = (net_index[i], roles[i]);
        // Equality on the whole mask, not a bit test: a net whose *only*
        // terminals are gates.
        let keep = row.1 == RoleMask::GATE;
        // `count <= i` holds by induction: `bool` is 0 or 1, so the cursor
        // advances by at most one per iteration and starts equal to `i` at zero.
        debug_assert!(count <= i);
        // Unchecked because `count`'s step is data-dependent: LLVM cannot prove
        // `count <= i` and emits a panic edge that pins the loop to one element
        // per iteration.
        //
        // SAFETY: `count <= i < nets == slots.len()`, from the induction above.
        unsafe { slots.get_unchecked_mut(count) }.write(row);
        count += usize::from(keep);
    }
    // SAFETY: slots `0 .. count` were each written when the cursor held that
    // value, and `count <= nets <= capacity`.
    unsafe { flagged.set_len(count) };
    debug_assert_eq!(count, flagged.len(), "the compact and its count disagree");
    debug_assert!(
        count as u64 <= examined,
        "a floating gate net carries a gate"
    );

    for row in 0..rows {
        let before = out.len();
        push_net_violations(
            design,
            &flagged,
            table.head.rule[row],
            table.head.severity[row],
            Measurement::Count(0),
            Measurement::Count(1),
            out,
        );
        record_run(
            runs,
            out,
            before,
            table.head.rule[row],
            Outcome::Ran,
            examined,
        );
    }
}

/// Flag every well polygon containing no tap.
///
/// Exact containment, not bounding-box overlap: a tap whose box overlaps an
/// L-shaped well but sits in the notch is not inside it.
///
/// `examined` counts counter-clockwise rings only. A hole is neither examined
/// nor reported; it is what stops a tap drawn inside it from tying the well it
/// punctures.
pub fn check_floating_well(
    design: Design<'_>,
    table: &FloatingWellTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.len();
    debug_assert_eq!(
        table.head.severity.len(),
        rows,
        "a rule head's two columns arrive parallel"
    );
    debug_assert_eq!(table.well.len(), rows, "one well layer per rule row");
    debug_assert_eq!(table.tap.len(), rows, "one tap layer per rule row");

    // Row `k` of each is store row `polys_on_layer(well).start + k`, which is
    // why there is no `PolyId` column.
    let mut ring_well: Vec<bool> = Vec::new();
    let mut ring_order: Vec<u32> = Vec::new();
    let mut tied: Vec<bool> = Vec::new();

    for row in 0..rows {
        let before = out.len();
        let rule = table.head.rule[row];

        // Fail closed: a derived well has no `PolyId` to blame, and "we could
        // not check this" must never read as clean. The tap below is tested and
        // never reported at, so a derived tap is fine.
        let Some(well_layer) = base_layer(table.well[row]) else {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        };

        // Boxes are enough: a tap is tested for being inside a well, never
        // measured and never reported at.
        scratch.boxes.clear();
        match table.tap[row] {
            LayerRef::Base(layer) => {
                debug_assert!(
                    layer.idx() < design.store.layer_count(),
                    "a tap layer the store's layer table does not have"
                );
                scratch
                    .boxes
                    .extend_from_slice(design.store.layer_bboxes(layer));
            }
            LayerRef::Named(name) => {
                let Some(taps) = design.derived.get(name) else {
                    // Empty here would mean every well is untapped, which is
                    // loud but wrong; refusing says which it is.
                    record_run(runs, out, before, rule, Outcome::Refused, 0);
                    continue;
                };
                scratch.boxes.extend_from_slice(taps.bboxes());
            }
        }

        let polys = design.store.polys_on_layer(well_layer);
        let boxes = design.store.layer_bboxes(well_layer);
        let ring_count = polys.len();
        debug_assert_eq!(
            boxes.len(),
            ring_count,
            "the bounding-box column and the row range are the same layer"
        );

        // A well is wound counter-clockwise; a hole in one is its own store row
        // wound clockwise. A separate pass because the hole that punctures a
        // well may sit at a later store row than the well does.
        ring_well.clear();
        ring_well.reserve(ring_count);
        for id in polys.clone() {
            let (xs, ys) = design.store.poly_verts(PolyId(id));
            ring_well.push(winding_of(xs, ys) == Some(Winding::CounterClockwise));
        }
        debug_assert_eq!(ring_well.len(), ring_count, "one verdict per ring");

        // The stab order: rings ascending in low x, ties broken by row so the
        // order is total and the same on every run. A ring containing a point
        // has `xlo <= p.x <= xhi`, so the prefix with `xlo <= p.x` is a superset
        // of the answer and the far edge rejects the rest.
        ring_order.clear();
        ring_order.extend(0..u32::try_from(ring_count).expect("a store row is a u32"));
        ring_order.sort_unstable_by_key(|&k| (boxes[k as usize].xlo.raw(), k));
        debug_assert!(
            ring_order.is_sorted_by_key(|&k| boxes[k as usize].xlo.raw()),
            "the stab order is ascending in low x"
        );

        tied.clear();
        tied.resize(ring_count, false);

        // Each tap ties exactly one ring: the innermost holding its centre,
        // where innermost is the smallest containing bounding box. A tap drawn
        // in a hole ties the hole, so the well it punctures stays untied.
        for &tap in &scratch.boxes {
            let probe = centre(tap);
            let end = ring_order.partition_point(|&k| boxes[k as usize].xlo.raw() <= probe.x.raw());
            debug_assert!(
                end <= ring_order.len(),
                "a stab range leaves the ring order"
            );

            let mut best = u32::MAX;
            let mut best_area = 0i128;
            for &k in &ring_order[..end] {
                let box_ = boxes[k as usize];
                // Guards `inside_ring`, a pass over the ring's vertices. The
                // fourth edge is the stab range.
                if probe.x.raw() > box_.xhi.raw()
                    || probe.y.raw() < box_.ylo.raw()
                    || probe.y.raw() > box_.yhi.raw()
                {
                    continue;
                }
                // A ring no smaller than the best so far cannot be inner to it,
                // so the vertex pass is skipped without changing the answer.
                let area = box_.area().raw();
                if best != u32::MAX && area >= best_area {
                    continue;
                }
                let (xs, ys) = design.store.poly_verts(PolyId(polys.start + k));
                if !inside_ring(xs, ys, probe.x, probe.y) {
                    continue;
                }
                best = k;
                best_area = area;
            }

            if best == u32::MAX {
                continue;
            }
            debug_assert!(
                (best as usize) < ring_count,
                "the innermost ring is a row of this layer"
            );
            // Containment of the whole tap box, not of the probe alone, and a
            // hole winning the stab must tie nothing.
            tied[best as usize] |= ring_well[best as usize] && boxes[best as usize].contains(tap);
        }

        // Store order, so the violation table follows the layer rather than
        // the stab order.
        let mut examined = 0u64;
        for k in 0..ring_count {
            if !ring_well[k] {
                continue;
            }
            examined += 1;
            if tied[k] {
                continue;
            }
            let well = PolyId(polys.start + u32::try_from(k).expect("a store row is a u32"));
            out.push(Violation {
                rule,
                layer: well_layer,
                severity: table.head.severity[row],
                at: first_vertex(design.store, well),
                measured: Measurement::Count(0),
                limit: Measurement::Count(1),
                shapes: (well, None),
            });
        }

        debug_assert!(
            examined <= u64::try_from(ring_count).unwrap_or(u64::MAX),
            "more wells than rows on the well layer"
        );
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every net driven from more than `max_drivers` distinct gate nets.
///
/// The distinct count is over gate [`NetId`], so a four-finger output counts
/// once and two independent drivers count twice.
///
/// [`NetId`]: gpurify_topology::NetId
pub fn check_multiple_drivers(
    design: Design<'_>,
    table: &MultipleDriversTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.len();
    debug_assert_eq!(
        table.head.severity.len(),
        rows,
        "a rule head's two columns arrive parallel"
    );
    debug_assert_eq!(table.max_drivers.len(), rows, "one maximum per rule row");

    // Every `(driven net, driving gate net)` pair. A row only chooses the
    // threshold, so this is built once above the rows.
    scratch.edges.clear();
    for device in 0..design.devices.len() {
        let id = DeviceId(u32::try_from(device).expect("a device index is a u32"));
        let (nets, roles) = design.devices.terminals_of(id);
        debug_assert_eq!(
            nets.len(),
            roles.len(),
            "a device's terminal columns arrive parallel"
        );

        // The gate that switches this device, or `NO_GATE`. First wins.
        // `NetId::NONE` collapses onto the same value: a gate on no net cannot
        // drive anything either.
        let gate = roles
            .iter()
            .position(|role| matches!(role, TerminalRole::Gate))
            .map_or(NO_GATE, |slot| nets[slot].0);
        debug_assert!(
            gate != NO_GATE || !roles.contains(&TerminalRole::Gate),
            "a gate terminal on a real net must not read as ungated"
        );

        for (slot, role) in roles.iter().enumerate() {
            // A drain on no net has no polygon to be reported at.
            if matches!(role, TerminalRole::Drain) && nets[slot] != NetId::NONE {
                scratch.edges.push((nets[slot].0, gate));
            }
        }
    }

    // Sorted so the pairs of one net are one run, deduplicated so a four-finger
    // output counts its shared gate once. Together they make the answer a
    // function of the netlist rather than of device recognition order.
    scratch.edges.sort_unstable();
    scratch.edges.dedup();
    let pairs = scratch.edges.len();

    // Collapse each net's run of pairs to one `(net, distinct drivers)` row, in
    // place: the write cursor never overtakes the read cursor because a group
    // collapses at least one row to exactly one.
    let mut read = 0usize;
    let mut write = 0usize;
    while read < scratch.edges.len() {
        let net = scratch.edges[read].0;
        let end = read + scratch.edges[read..].partition_point(|&(driven, _)| driven == net);
        debug_assert!(end > read, "a group holds the row that named it");

        // The sentinel is `u32::MAX`, so an ungated drain sorts last within its
        // group and is present at most once after the dedup. It is not a driver,
        // but the net it lands on is still one this rule examined.
        let ungated = u32::from(scratch.edges[end - 1].1 == NO_GATE);
        let drivers = u32::try_from(end - read).expect("a group is shorter than the pair column");
        debug_assert!(
            drivers >= ungated,
            "the sentinel row is one of the group's own"
        );

        debug_assert!(
            write <= read,
            "the collapse write cursor overtook its read cursor"
        );
        scratch.edges[write] = (net, drivers - ungated);
        write += 1;
        read = end;
    }
    scratch.edges.truncate(write);
    debug_assert!(
        scratch.edges.len() <= pairs,
        "the collapse produced more nets than it read pairs"
    );

    let examined = u64::try_from(scratch.edges.len()).expect("a net count is a u64");

    for row in 0..rows {
        let before = out.len();
        let rule = table.head.rule[row];
        let max = table.max_drivers[row];

        for &(net, drivers) in &scratch.edges {
            if drivers > max {
                if let Some(&poly) = design.nets.polys_of(NetId(net)).first() {
                    out.push(Violation {
                        rule,
                        layer: design.store.poly_layer(poly),
                        severity: table.head.severity[row],
                        at: first_vertex(design.store, poly),
                        measured: Measurement::Count(drivers),
                        limit: Measurement::Count(max),
                        shapes: (poly, None),
                    });
                }
            }
        }

        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Flag every polygon on a listed layer whose net reaches no device.
///
/// The test is [`NetFacts::is_device_connected`], which counts every terminal
/// of every device family.
pub fn check_unconnected_pin(
    design: Design<'_>,
    facts: &NetFacts,
    table: &UnconnectedPinTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let rows = table.head.len();
    debug_assert_eq!(
        table.head.severity.len(),
        rows,
        "a rule head's two columns arrive parallel"
    );
    debug_assert!(
        table.layer_start.len() == rows + 1 || table.layer_start.is_empty(),
        "the layer CSR carries one offset per row plus a terminator"
    );

    // With no classified nets there is no forward column for `net_of` to read.
    let extracted = !facts.is_empty();

    for row in 0..rows {
        let before = out.len();
        let rule = table.head.rule[row];
        let from = usize::try_from(table.layer_start[row]).expect("a CSR offset is a usize");
        let to = usize::try_from(table.layer_start[row + 1]).expect("a CSR offset is a usize");
        debug_assert!(
            from <= to && to <= table.layer.len(),
            "a rule row's layer run leaves the column"
        );

        let mut examined = 0u64;
        for &layer in &table.layer[from..to] {
            let polys = design.store.polys_on_layer(layer);
            examined += u64::from(polys.end - polys.start);

            for id in polys {
                let poly = PolyId(id);
                // Guards a load that could fault: `net_of` indexes a column an
                // unextracted design never filled.
                let net = if extracted {
                    design.nets.net_of(poly)
                } else {
                    NetId::NONE
                };
                // One compare covers both absences: `NetId::NONE` is `u32::MAX`,
                // so a polygon on no net and a net past the classification both
                // fall short of the column. Fail closed in both directions.
                let connected = net.idx() < facts.len() && facts.is_device_connected(net);
                if connected {
                    continue;
                }
                out.push(Violation {
                    rule,
                    layer,
                    severity: table.head.severity[row],
                    at: first_vertex(design.store, poly),
                    measured: Measurement::Count(0),
                    limit: Measurement::Count(1),
                    shapes: (poly, None),
                });
            }
        }

        // `Ran` with `examined == 0` is the honest row for a rule naming no
        // layer: it executed and had nothing to look at.
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// The gate slot of a device that has none, and of one whose gate is on no net.
///
/// `u32::MAX`, which is [`NetId::NONE`]'s own value, so it sorts last and the
/// group scan in [`check_multiple_drivers`] subtracts it without a search.
const NO_GATE: u32 = u32::MAX;

/// Whether a point lies strictly inside a closed ring: an even-odd ray cast
/// towards `+x`, exact in `i128`.
///
/// Not folded with `supply::point_in_region`, the same ray cast: that one
/// answers *in* for a point exactly on an edge, this one leaves the boundary to
/// the half-open crossing rule, because a tap on a well's edge reading as
/// inside would tie the well and report it clean. Each rule's side is the
/// fail-closed one only for itself.
fn inside_ring(xs: &[Dbu], ys: &[Dbu], px: Dbu, py: Dbu) -> bool {
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    let n = xs.len();
    // Under three vertices there is no interior to be inside of.
    if n < 3 {
        return false;
    }

    // Seeding with the last vertex puts the ring's closing edge in the fold
    // rather than in a fixup outside it.
    let ys = &ys[..n];
    let mut crossings = 0u32;
    let mut ax = xs[n - 1];
    let mut ay = ys[n - 1];
    for i in 0..n {
        let (bx, by) = (xs[i], ys[i]);
        // `(b - a) x (p - a)`, positive when `p` is left of the edge. Widened
        // before the multiply: the operands reach `2^41` and the product
        // `2^82`, so an `i64` would silently wrap.
        let side = i128::from(bx.raw() - ax.raw()) * i128::from(py.raw() - ay.raw())
            - i128::from(by.raw() - ay.raw()) * i128::from(px.raw() - ax.raw());
        // Half-open: a vertex is counted by exactly one of the two edges meeting
        // at it, so a ray grazing one is not counted twice.
        let up = by.raw() > ay.raw();
        let straddles = (ay.raw() > py.raw()) != (by.raw() > py.raw());
        crossings += u32::from(straddles & ((side > 0) == up));
        ax = bx;
        ay = by;
    }

    crossings & 1 == 1
}
