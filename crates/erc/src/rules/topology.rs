//! Rules that ask only what is connected to what.
//!
//! Four kinds, no design intent, no solve. Each reduces to a question about a
//! net's [`RoleMask`] or its device list, which is why they cost one linear
//! pass over [`NetFacts`] between them and why they always run.
//!
//! # These are only as good as the extraction
//!
//! Nothing here re-derives connectivity. A gate is floating because
//! `topology` says the only terminal on its net is a gate — so an extraction
//! that missed a via reports a floating gate that is not floating, and one that
//! merged two nets reports nothing at all. That is the correct dependency
//! (`topology` is where connectivity is decided and tested), and it is stated
//! because these four rules are the ones a reader is tempted to make
//! independently clever.
//!
//! [`RoleMask`]: crate::RoleMask

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

/// A gate net with nothing driving it.
///
/// **Five questions.** In: rule rows from the deck. Out: nothing — the table is
/// the configuration. How many: normally exactly one row; a deck may configure
/// two at different severities. Access pattern: read once per row. Lifetime:
/// whole run. Parallelisable: read-only.
///
/// No parameters beyond the head, and that is the finding rather than an
/// omission. The old implementation carried a list of layers to treat as an
/// "external connection", because its net extraction stopped at the device and
/// it had to guess at the rest. Connectivity is `topology`'s job now, so the
/// whole rule is: the net's role mask is exactly [`RoleMask::GATE`].
///
/// [`RoleMask::GATE`]: crate::RoleMask::GATE
#[derive(Debug, Default)]
pub struct FloatingGateTable {
    pub head: RuleHead,
}

/// A well with no tap tying it to a supply.
///
/// The tap is a [`LayerRef`] because it is almost always derived — `nsdm AND
/// diff` inside `nwell` on a standard CMOS deck — and naming the derived layer
/// in the deck keeps the boolean in `derived`, where it is exact, rather than
/// re-approximating it here with bounding boxes as the old implementation did.
#[derive(Debug, Default)]
pub struct FloatingWellTable {
    pub head: RuleHead,
    /// The region that must be tied: `nwell`, a deep n-well, an isolated
    /// p-well.
    pub well: Vec<LayerRef>,
    /// What counts as a tie inside it.
    pub tap: Vec<LayerRef>,
}

/// A net driven by more than one output.
///
/// Two drains on one net is contention only when the drains belong to devices
/// with *different* gate nets — a parallel pair sharing a gate is one driver
/// built wide, and flagging it would make every multi-finger output a
/// violation. So the count is over distinct gate nets, not over drains.
#[derive(Debug, Default)]
pub struct MultipleDriversTable {
    pub head: RuleHead,
    /// Distinct driving gate nets permitted on one net. `1` for ordinary
    /// logic; a deck raises it for a net a design intends to share, such as a
    /// bus with a documented arbitration.
    pub max_drivers: Vec<u32>,
}

/// A conductor on a net no device terminal touches.
///
/// The layers are listed because the answer differs by layer: a top-metal
/// shape reaching no device is a routing stub, and a fill shape reaching no
/// device is fill. A deck that named no layers would flag both.
#[derive(Debug, Default)]
pub struct UnconnectedPinTable {
    pub head: RuleHead,
    /// `layer[layer_start[i] .. layer_start[i + 1]]` are row `i`'s layers.
    /// CSR, not a `Vec<Vec<LayerId>>`.
    pub layer_start: Vec<u32>,
    pub layer: Vec<LayerId>,
}

/// Flag every net whose only terminals are gates.
///
/// **Transform.** One pass over [`NetFacts::role`], per rule row. Each net's
/// verdict is a function of its own mask and the row's uniforms, so any net
/// order is legal and the pass parallelises by net range.
///
/// A gate net with no source, no drain and no passive terminal has no path to
/// a supply through anything: it charges to whatever the process left on it and
/// stays there. The violation is reported at the net's lowest-numbered polygon,
/// which is canonical because `NetTable::polys_of` is ascending.
///
/// `examined` is the number of nets carrying at least one gate terminal — the
/// nets this rule could have flagged. Counting every net instead would make a
/// design with one transistor look thoroughly checked.
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

    // The population this rule could flag, folded once above the rule rows
    // because it is a property of the design and not of any row's parameters.
    // Counting every net here instead would make a design with one transistor
    // look thoroughly checked.
    let roles = &facts.role[..];
    let nets = roles.len();
    let mut examined = 0u64;
    for role in roles {
        // Branchless: the bit test widens to 0 or 1 and is added unconditionally.
        examined += u64::from(role.intersects(RoleMask::GATE));
    }
    debug_assert!(
        examined <= u64::try_from(facts.len()).unwrap_or(u64::MAX),
        "more gate nets than nets"
    );

    // Which nets are flagged is a property of the design, not of a row's
    // parameters — this rule takes none — so the compact is hoisted above the
    // rows next to `examined`. The net column pairs with the mask column so the
    // kept rows carry the net that owns them; a compact over the masks alone
    // would come back holding masks and not the nets that own them.
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
        // terminals are gates. One compare per net, no branch.
        let keep = row.1 == RoleMask::GATE;
        // `count <= i` holds by induction: `bool` is 0 or 1, so the cursor
        // advances by at most one per iteration and starts equal to `i` at zero.
        // Rejected slots stay uninit and are never read — `set_len(count)`
        // truncates them away, and `(u32, RoleMask)` is `Copy`, so nothing has a
        // `Drop` to run.
        debug_assert!(count <= i);
        // Unchecked because `count`'s step is data-dependent: LLVM gets no
        // affine recurrence for it, cannot prove `count <= i`, and emits a live
        // panic edge that pins the loop to one element per iteration. Measured
        // at 1.19x / 1.18x / 1.06x for 8k / 200k / 4M rows —
        // `docs/BULK_MEASUREMENTS.md` §4.
        //
        // SAFETY: `count <= i < nets == slots.len()`, from the induction above.
        unsafe { slots.get_unchecked_mut(count) }.write(row);
        count += usize::from(keep);
    }
    // SAFETY: slots `0 .. count` were each written when the cursor held that
    // value, and `count <= nets <= capacity`.
    unsafe { flagged.set_len(count) };
    debug_assert_eq!(count, flagged.len(), "the compact and its count disagree");
    debug_assert!(count as u64 <= examined, "a floating gate net carries a gate");

    for row in 0..rows {
        let before = out.len();
        push_net_violations(
            design,
            &flagged,
            table.head.rule[row],
            table.head.severity[row],
            // What was found and what a driven net has: this net carries no
            // terminal that could drive it, against the one it needs.
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
/// **Transform.** Three passes per rule row. One classifies every ring on the
/// well layer by winding and orders the rings by low x. Two walks the taps and
/// ties each to the *innermost* ring holding its centre. Three reports every
/// counter-clockwise ring nothing tied. Exact containment, not bounding-box
/// overlap — a tap whose box overlaps an L-shaped well but sits in the notch is
/// not inside it, and the old implementation counted it.
///
/// Taps outer and rings inner, rather than the other way round, because the
/// question a tap answers — which ring am I in — has one answer, while the
/// question a well asks has as many answers as there are taps. The ring order
/// turns the inner scan into a stab of the rings whose low x has not yet passed
/// the probe.
///
/// A floating well is a latch-up path and a threshold shift at once, so it is
/// an error rather than a warning wherever a deck does not say otherwise.
///
/// `examined` is the number of well polygons — counter-clockwise rings. A hole
/// is neither examined nor reported; it is the thing that stops a tap drawn
/// inside it from tying the well it punctures.
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

    // The per-row ring tables. `Scratch` is frozen and holds no ring buffer —
    // `boxes` is spoken for by the taps — so these are locals, allocated above
    // the rule rows and cleared per row rather than per ring. Row `k` of each
    // is store row `polys_on_layer(well).start + k`, which is why there is no
    // `PolyId` column.
    let mut ring_well: Vec<bool> = Vec::new();
    let mut ring_order: Vec<u32> = Vec::new();
    let mut tied: Vec<bool> = Vec::new();

    for row in 0..rows {
        let before = out.len();
        let rule = table.head.rule[row];

        // Fail closed on a well this rule could not report against. A violation
        // names a `PolyId`; a derived layer keeps its provenance in a private
        // column of `ValidatedLayer` with no accessor, so a well evaluated from
        // an expression has no shape to blame. Refused, not skipped and not
        // dropped: "we could not check this" must never read as clean. The tap
        // below has no such restriction — it is tested, never reported at — and
        // a derived tap is the ordinary case.
        let Some(well_layer) = base_layer(table.well[row]) else {
            record_run(runs, out, before, rule, Outcome::Refused, 0);
            continue;
        };

        // The tap column, resolved once per row into the caller's buffer so the
        // scan below reads one contiguous slice whichever side of `LayerRef`
        // the deck named. Boxes are enough: a tap is tested for being inside a
        // well, never measured and never reported at. `extend_from_slice` is a
        // `memcpy` for a `Copy` column.
        scratch.boxes.clear();
        match table.tap[row] {
            LayerRef::Base(layer) => {
                debug_assert!(
                    layer.idx() < design.store.layer_count(),
                    "a tap layer the store's layer table does not have"
                );
                scratch.boxes.extend_from_slice(design.store.layer_bboxes(layer));
            }
            LayerRef::Named(name) => {
                let Some(taps) = design.derived.get(name) else {
                    // The deck named a derived layer the evaluator does not
                    // hold. Empty here would mean every well is untapped, which
                    // is loud but wrong; refusing says which it is.
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

        // Pass one: classify every ring on the well layer. A well is wound
        // counter-clockwise and a hole in one is its own store row wound
        // clockwise. Both are needed before any tap is tested, which is why
        // this is a pass of its own — the hole that punctures a well may sit at
        // a later store row than the well does.
        ring_well.clear();
        ring_well.reserve(ring_count);
        for id in polys.clone() {
            let (xs, ys) = design.store.poly_verts(PolyId(id));
            ring_well.push(winding_of(xs, ys) == Some(Winding::CounterClockwise));
        }
        debug_assert_eq!(ring_well.len(), ring_count, "one verdict per ring");

        // The stab order: rings ascending in low x, ties broken by row so the
        // order is total and the same on every run. A ring containing a point
        // has `xlo <= p.x <= xhi`, so the prefix with `xlo <= p.x` is a
        // superset of the answer and the far edge rejects the rest. This is
        // what replaces the O(wells x taps) pass the rule used to make.
        ring_order.clear();
        ring_order.extend(0..u32::try_from(ring_count).expect("a store row is a u32"));
        ring_order.sort_unstable_by_key(|&k| (boxes[k as usize].xlo.raw(), k));
        debug_assert!(
            ring_order.is_sorted_by_key(|&k| boxes[k as usize].xlo.raw()),
            "the stab order is ascending in low x"
        );

        tied.clear();
        tied.resize(ring_count, false);

        // Pass two: each tap ties exactly one ring — the innermost holding its
        // centre. Innermost is the smallest bounding box among the rings that
        // contain the probe, which is well defined because ring nesting is
        // strict containment. That is what binds a hole to the well it
        // punctures without needing the hierarchy `ValidatedLayer` keeps
        // private: a tap drawn in the hole ties the hole, so the well stays
        // untied, and a well island inside that hole is still tied by its own
        // taps rather than being shadowed by the ring around it.
        for &tap in &scratch.boxes {
            let probe = centre(tap);
            let end =
                ring_order.partition_point(|&k| boxes[k as usize].xlo.raw() <= probe.x.raw());
            debug_assert!(end <= ring_order.len(), "a stab range leaves the ring order");

            let mut best = u32::MAX;
            let mut best_area = 0i128;
            for &k in &ring_order[..end] {
                let box_ = boxes[k as usize];
                // Guards the expensive side: `inside_ring` is a pass over the
                // ring's vertices, and the three remaining box edges keep it
                // off nearly every pair. The fourth edge is the stab range.
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

            // Surviving `if`: a tap outside every ring on the well layer is
            // rare by construction, so this predicts at ~100%.
            if best == u32::MAX {
                continue;
            }
            debug_assert!(
                (best as usize) < ring_count,
                "the innermost ring is a row of this layer"
            );
            // Containment of the whole tap box, not of the probe alone: that is
            // the semantic the rule states, and a hole winning the stab is
            // exactly the case that must not tie anything.
            tied[best as usize] |= ring_well[best as usize] && boxes[best as usize].contains(tap);
        }

        // Pass three: report. Store order, so the violation table follows the
        // layer rather than the stab order.
        let mut examined = 0u64;
        for k in 0..ring_count {
            // Surviving `if`s: a layer is overwhelmingly wells rather than
            // holes, and a tied well is the ordinary case, so both predict at
            // ~100% and the side they skip is eight column pushes.
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
/// **Transform.** Two passes, because the kernel rule forbids one: the first
/// walks devices and writes a `(driven net, driving gate net)` pair into
/// `scratch` per drain, the second sorts, deduplicates and collapses each net's
/// run of pairs in place to one `(net, distinct drivers)` row. Fusing them
/// would have row N reading what row N−1 wrote.
///
/// Both passes sit above the rule rows. A row chooses the threshold and nothing
/// else, so the count it compares against is a property of the netlist; the
/// rows scan the collapsed table, which holds one row per driven net.
///
/// The distinct count is over gate [`NetId`], so a four-finger output counts
/// once and two independent drivers count twice.
///
/// `examined` is the number of nets carrying at least one drain terminal.
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

    // Pass one: every `(driven net, driving gate net)` pair. Independent of the
    // rule rows — a row only chooses the threshold — so it is built once above
    // them.
    scratch.edges.clear();
    for device in 0..design.devices.len() {
        let id = DeviceId(u32::try_from(device).expect("a device index is a u32"));
        let (nets, roles) = design.devices.terminals_of(id);
        debug_assert_eq!(
            nets.len(),
            roles.len(),
            "a device's terminal columns arrive parallel"
        );

        // The gate that switches this device, or `NO_GATE`. First wins, which
        // is deterministic; a MOS has exactly one, and a device with none — a
        // resistor, a capacitor — drives nothing and lands on the sentinel.
        // `NetId::NONE` collapses onto the same value, which is the right
        // answer: a gate on no net cannot drive anything either.
        let gate = roles
            .iter()
            .position(|role| matches!(role, TerminalRole::Gate))
            .map_or(NO_GATE, |slot| nets[slot].0);
        debug_assert!(
            gate != NO_GATE || !roles.contains(&TerminalRole::Gate),
            "a gate terminal on a real net must not read as ungated"
        );

        for (slot, role) in roles.iter().enumerate() {
            // Not a bulk loop — a device carries two to four terminals — and
            // the taken side appends a row. A drain on no net has no polygon to
            // be reported at, so it contributes nothing.
            if matches!(role, TerminalRole::Drain) && nets[slot] != NetId::NONE {
                scratch.edges.push((nets[slot].0, gate));
            }
        }
    }

    // Sorted so the pairs of one net are one run, deduplicated so a four-finger
    // output counts its shared gate once. Both are what make the answer a
    // function of the netlist rather than of the order devices were recognised
    // in, which is what the determinism gate asks.
    scratch.edges.sort_unstable();
    scratch.edges.dedup();
    let pairs = scratch.edges.len();

    // Pass two: collapse each net's run of pairs to one `(net, distinct
    // drivers)` row. Above the rule rows for the same reason pass one is — a
    // row chooses only the threshold, so counting per row rescanned every pair
    // once per row for an answer that could not differ between them.
    //
    // In place, which is what makes it free: the write cursor never overtakes
    // the read cursor, because a group collapses at least one row to exactly
    // one.
    let mut read = 0usize;
    let mut write = 0usize;
    while read < scratch.edges.len() {
        let net = scratch.edges[read].0;
        let end = read + scratch.edges[read..].partition_point(|&(driven, _)| driven == net);
        debug_assert!(end > read, "a group holds the row that named it");

        // The sentinel is `u32::MAX`, so an ungated drain sorts last within its
        // group and is present at most once after the dedup. Subtracted
        // branchlessly: it is not a driver, but the net it lands on is still a
        // net this rule examined.
        let ungated = u32::from(scratch.edges[end - 1].1 == NO_GATE);
        let drivers = u32::try_from(end - read).expect("a group is shorter than the pair column");
        debug_assert!(drivers >= ungated, "the sentinel row is one of the group's own");

        debug_assert!(write <= read, "the collapse write cursor overtook its read cursor");
        scratch.edges[write] = (net, drivers - ungated);
        write += 1;
        read = end;
    }
    scratch.edges.truncate(write);
    debug_assert!(
        scratch.edges.len() <= pairs,
        "the collapse produced more nets than it read pairs"
    );

    // One row per driven net now, so this is the population every rule row
    // examines and it no longer depends on the row.
    let examined = u64::try_from(scratch.edges.len()).expect("a net count is a u64");

    for row in 0..rows {
        let before = out.len();
        let rule = table.head.rule[row];
        let max = table.max_drivers[row];

        for &(net, drivers) in &scratch.edges {
            // Surviving `if`: contention is rare by construction, so this is not
            // taken for nearly every net and predicts at ~100%; the side it
            // skips is a CSR slice and eight column pushes.
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
/// **Transform.** One pass over the listed layers' polygon ranges; each
/// polygon's verdict is a load from [`NetFacts`] and a compare, with no
/// data-dependent branch beyond the push.
///
/// The test is [`NetFacts::is_device_connected`], which counts every terminal
/// of every device family. The old implementation consulted the MOS list alone,
/// so a block of BJTs or of resistors reported every one of its nets
/// unconnected — a whole-block false positive that trains a user to ignore the
/// rule, which is the same damage as a false negative.
///
/// `examined` is the number of polygons on the listed layers.
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

    // Hoisted uniform, not a per-polygon test: with no classified nets there is
    // no forward column for `NetTable::net_of` to read, and nothing on the
    // layout reaches a device anyway. Constant across the loop, so the
    // predictor memorises it and it costs nothing.
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
        // A deck names tens of layers per rule; the heavy work is the polygon
        // scan inside it.
        for &layer in &table.layer[from..to] {
            let polys = design.store.polys_on_layer(layer);
            examined += u64::from(polys.end - polys.start);

            for id in polys {
                let poly = PolyId(id);
                // The `if` guards a load that could fault, which is the one case
                // the branchless catalogue keeps a branch for: `net_of` indexes
                // a column an unextracted design never filled.
                let net = if extracted {
                    design.nets.net_of(poly)
                } else {
                    NetId::NONE
                };
                // One compare covers both absences. `NetId::NONE` is `u32::MAX`,
                // so a polygon on no net — a cut, a marker, a fill shape — and a
                // net past the classification both fall short of the column and
                // read as reaching no device. Fail closed in both directions.
                let connected = net.idx() < facts.len() && facts.is_device_connected(net);
                // Surviving `if`: a listed conductor layer is overwhelmingly
                // connected, so this predicts at ~100%, and the taken side is
                // eight column pushes.
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
        // layer: it executed and had nothing to look at, which a reader can
        // tell apart from a rule that never ran. Reporting it clean without the
        // count is the failure this crate is shaped against.
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// The gate slot of a device that has none, and of one whose gate is on no net.
///
/// `u32::MAX`, which is [`NetId::NONE`]'s own value — the two mean the same
/// thing here, and sorting last is what lets the group scan in
/// [`check_multiple_drivers`] subtract it without a search.
const NO_GATE: u32 = u32::MAX;

/// Whether a point lies strictly inside a closed ring.
///
/// **Decision** — a ring's two coordinate columns and a point in, one bool out.
/// An even-odd ray cast towards `+x`, exact in `i128`.
///
/// `core::ops::point_in_ring` is the same predicate and is not reachable from
/// here: it takes a `RingRef`, whose fields only `core` can fill, and the sole
/// route to one is `ValidatedLayer::get` — which hands back no [`PolyId`], so a
/// violation built through it could not name the shape it sits on. This is the
/// same argument `topology::net::point_inside` records at its own copy.
///
/// **Not folded with `supply::point_in_region`, which is the same ray cast over
/// the same columns.** That one answers *in* for a point exactly on an edge,
/// because `check_missing_tie`'s maximum is often attained there; this one
/// leaves the boundary to the half-open crossing rule, because a tap sitting on
/// a well's edge reading as inside would tie the well and report it clean. One
/// shared body would have to pick a side, and each rule's side is the
/// fail-closed one only for itself.
fn inside_ring(xs: &[Dbu], ys: &[Dbu], px: Dbu, py: Dbu) -> bool {
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    let n = xs.len();
    // Under three vertices there is no interior to be inside of. One test per
    // ring, hoisted above the fold, not a bulk branch.
    if n < 3 {
        return false;
    }

    // One strict left-to-right fold over both columns, carrying the previous
    // vertex between iterations. Seeding with the last vertex puts the ring's
    // closing edge in the fold rather than in a fixup outside it. The body is
    // branchless — the crossing is accumulated as a widened bool, not counted
    // under an `if`.
    //
    // Slicing `ys` to `n` up front is what deletes the per-element bounds check
    // on the second column; `xs` already carries `n` as its own length.
    let ys = &ys[..n];
    let mut crossings = 0u32;
    let mut ax = xs[n - 1];
    let mut ay = ys[n - 1];
    for i in 0..n {
        let (bx, by) = (xs[i], ys[i]);
        // `(b - a) x (p - a)`, positive when `p` is left of the edge. Widened
        // before the multiply: the operands are differences of coordinates
        // bounded by `MAX_ABS_DBU`, so they reach `2^41` and the product
        // `2^82` — an `i64` would silently wrap. Written out rather than
        // through `ops::orientation`, whose domain asserts would put a panic
        // edge in the loop.
        let side = i128::from(bx.raw() - ax.raw()) * i128::from(py.raw() - ay.raw())
            - i128::from(by.raw() - ay.raw()) * i128::from(px.raw() - ax.raw());
        // The half-open convention: a vertex is counted by exactly one of the
        // two edges meeting at it, so a ray grazing one is not counted twice.
        let up = by.raw() > ay.raw();
        let straddles = (ay.raw() > py.raw()) != (by.raw() > py.raw());
        crossings += u32::from(straddles & ((side > 0) == up));
        ax = bx;
        ay = by;
    }

    crossings & 1 == 1
}
