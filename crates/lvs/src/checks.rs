//! Standalone checks that need no reference netlist.
//!
//! These are the LVS findings that come from the layout alone — a floating net,
//! two labels on one net, a device count that cannot be right. They run before
//! comparison, because each of them makes a comparison meaningless, and a
//! mismatch caused by a label conflict is a confusing way to learn about the
//! label conflict.
//!
//! Same table-plus-transform shape as the DRC and ERC rules, and they report
//! into the same [`Violations`] table.
//!
//! # What these six cannot say, and why they say it loudly
//!
//! [`Violation`] needs a `rule: StrId`, a `layer`, an `at: Point` and a
//! `shape_a: PolyId`. Not one of the six signatures carries a [`StrTable`], a
//! rule table, a `GeometryStore` or a `LayerId`, so four of those seven columns
//! have no value derivable from the inputs. `docs/SIGNATURE_DEFECTS.md` records
//! the fix — a `rule: StrId` uniform plus `&DeviceTable` and `&GeometryStore` on
//! all six — as an open Definition-Phase decision, and the signatures are
//! frozen, so this module works around it rather than changing one:
//!
//! - the rule ids are sentinels counted down from `u32::MAX`, which
//!   [`StrTable::resolve`] panics on rather than resolving to whichever real
//!   name happens to sit at that index;
//! - `layer`, `at` and, where no net supplies one, `shape_a` are the
//!   out-of-range sentinels below, which index nothing.
//!
//! Two of the six — [`check_device_counts`] and [`check_parametric`] — compare
//! against limits that live in the deck, and no signature here takes a deck. So
//! they report [`Outcome::Skipped`] with [`SkipReason::NotInDeck`] rather than
//! inventing a limit everything passes. That is the whole point of the variant:
//! an unconfigurable rule is recorded as unrun, never as clean.
//!
//! [`StrTable`]: gpurify_ingest::StrTable
//! [`StrTable::resolve`]: gpurify_ingest::StrTable::resolve

use crate::graph::{narrow, LayoutGraph};
use gpurify_core::ops::Point;
use gpurify_core::{LayerId, PolyId};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrId;
use gpurify_report::{
    Measurement, Outcome, RuleRun, Severity, SkipReason, Violation, Violations,
};
use gpurify_topology::{DeviceTable, NetId, NetTable, PortTable};
use gpurify_units::Dbu;

/// Rule ids for the eight run rows the six checks produce.
///
/// Sentinels, for the reason the module comment gives. Counting down from
/// `u32::MAX` is what keeps them out of the range a run's [`StrTable`] issues,
/// which is what makes a report carrying one die instead of mislabelling itself.
///
/// [`StrTable`]: gpurify_ingest::StrTable
const FLOATING_NET: StrId = StrId(u32::MAX);
const LABEL_CONFLICT: StrId = StrId(u32::MAX - 1);
const NET_SEED_CONFLICT: StrId = StrId(u32::MAX - 2);
const DEVICE_COUNT_MOS: StrId = StrId(u32::MAX - 3);
const DEVICE_COUNT_BJT: StrId = StrId(u32::MAX - 4);
const PARAMETRIC: StrId = StrId(u32::MAX - 5);
const TERMINAL_NET: StrId = StrId(u32::MAX - 6);
const TERMINAL_COUNT: StrId = StrId(u32::MAX - 7);

/// The coordinate a graph-structure finding does not have.
///
/// A [`Violation`]'s `at` is documented as being inside the geometry the marker
/// names, so a viewer can navigate to it. A finding whose only input is a
/// terminal column names no geometry at all, and the origin is the one point
/// that claims nothing about where the fault is.
const NOWHERE: Point = Point {
    x: Dbu::new_unchecked(0),
    y: Dbu::new_unchecked(0),
};

/// The layer a netlist-level finding does not have. Past any layer table, so it
/// indexes nothing — the same fail-closed shape as [`NetId::NONE`].
const NO_LAYER: LayerId = LayerId(u16::MAX);

/// The polygon a graph-only finding does not have. Past any store.
const NO_SHAPE: PolyId = PolyId(u32::MAX);

/// Which terminal counts each device family admits, as a bitmask indexed by the
/// count.
///
/// The `TerminalRole` position table read as a predicate: a MOS names a gate, a
/// source and a drain, and optionally a bulk; a bipolar names exactly base,
/// emitter and collector; the two-terminal families name exactly two pins.
///
/// Indexed by the kind's tag rather than matched on, so a loop body carries a
/// load and a shift instead of a jump table — the `switch (state)` row of
/// `/branchless`. Eight entries and a mask of `7`, not five and a bounds check:
/// the mask makes the index provably in range, which is what keeps the panic
/// edge out of the loop. The three unreachable rows admit no width at all, so a
/// tag this table does not know fails closed.
const LEGAL_WIDTHS: [u32; 8] = [
    (1 << 3) | (1 << 4), // Mos: gate, source, drain, and optionally bulk
    1 << 3,              // Bjt: base, emitter, collector
    1 << 2,              // Resistor
    1 << 2,              // Capacitor
    1 << 2,              // Diode
    0,
    0,
    0,
];

/// The width each family is reported against when [`LEGAL_WIDTHS`] rejects one.
/// The full terminal set, which is what a reader compares the measurement to.
const FULL_WIDTHS: [u32; 8] = [4, 3, 2, 2, 2, 0, 0, 0];

/// Nets with no device terminal on them.
///
/// **Transform.** A net carrying geometry but no device is either dead metal or
/// a missing connection, and both are worth reporting. A net that is *only* a
/// port is not floating — it connects to something outside this cell — which is
/// why this needs the port table and not just the net table.
///
/// # Panics
///
/// When `devices` did not come from the same extraction as `nets`, in either
/// direction and in every profile. `recognise_into` sizes the device table's
/// reverse index to `nets.net_count()`, so one `devices_on` probe of the highest
/// net catches a table sized for fewer, and the scatter over `terminal_net`
/// catches a terminal naming a net this `nets` does not have. Fail closed, and
/// deliberately not guarded: a device table that cannot answer for a net would
/// otherwise read as a net with no devices, which is this check firing on every
/// net of a cell whose devices were merely looked up in the wrong table.
pub fn check_floating_nets(
    nets: &NetTable,
    devices: &DeviceTable,
    ports: &PortTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let before = out.len();
    let net_count = narrow(nets.net_count());

    // The fail-closed probe the `# Panics` section promises, hoisted out of the
    // scan and made once. A CSR run for row `k` reads offsets `k` and `k + 1`,
    // so a reverse index that can answer for the highest net can answer for
    // every lower one — which is the whole of what a `devices_on` call per net
    // was buying, and why the scan below makes none.
    if net_count > 0 {
        let top = devices.devices_on(NetId(net_count - 1));
        debug_assert!(
            top.len() <= devices.len(),
            "one net carries more devices than the table holds"
        );
    }

    // One column, carrying the predicate and the finding's payload in the same
    // `u32`: net `n` holds its lowest polygon while it is still a candidate and
    // [`NO_SHAPE`] once anything has ruled it out. All three reasons a net is
    // not floating collapse onto that one sentinel, so the compact below is a
    // single compare — no call, no slice, no branch.
    let mut lowest: Vec<PolyId> = Vec::with_capacity(net_count as usize);

    for row in 0..net_count {
        let net = NetId(row);
        // A named net leaves the cell, so it is not floating however little is
        // attached to it. Widened to an all-ones mask and OR-ed rather than
        // branched on: `NO_SHAPE` is `u32::MAX`, which *is* the mask.
        let named = u32::from(ports.name_of(net).is_some()).wrapping_neg();
        lowest.push(PolyId(first_poly(nets, net).0 | named));
    }
    debug_assert_eq!(lowest.len(), net_count as usize, "one column row per net");

    // The device half, scattered once over the terminals instead of probed once
    // per net. A net carries a device exactly when it appears in the terminal
    // column — `recognise_into` builds the reverse index from that column and
    // nothing else — so this is the same answer `devices_on(net).is_empty()`
    // gives, in `O(terminals)` rather than `O(nets)` CSR ranges.
    //
    // A scatter: the output index is data-dependent. A terminal naming a net
    // past this table indexes out of bounds and panics in every profile, which
    // is the other direction of the probe above.
    for &net in &devices.terminal_net {
        lowest[net.idx()] = NO_SHAPE;
    }

    // The compact, branchless: reserved for the whole input rather than for the
    // survivors, so the store is unconditional and the *index* carries the
    // decision.
    let rows = lowest.len();
    let mut floating: Vec<PolyId> = Vec::with_capacity(rows);
    let slots = &mut floating.spare_capacity_mut()[..rows];
    let mut w = 0usize;
    for (i, &poly) in lowest.iter().enumerate() {
        let keep = poly != NO_SHAPE;
        // `w <= i` by induction: `w` starts at zero and `bool` is 0 or 1, so it
        // advances by at most one per iteration.
        debug_assert!(w <= i);
        // SAFETY: `w <= i < rows == slots.len()`, from the induction above.
        // Rejected slots stay uninit and are never read — `set_len(w)`
        // truncates them away, and `PolyId: Copy` rules out a `Drop`.
        unsafe { slots.get_unchecked_mut(w) }.write(poly);
        w += usize::from(keep);
    }
    // SAFETY: every slot in `0..w` was written when `w` held that value, and
    // `w <= rows == capacity`.
    unsafe { floating.set_len(w) };
    debug_assert!(
        floating.len() <= nets.net_count(),
        "more floating nets than there are nets"
    );

    // Not a bulk loop: one iteration per finding, and a clean cell has none.
    for &poly in &floating {
        out.push(Violation {
            rule: FLOATING_NET,
            layer: NO_LAYER,
            severity: Severity::Error,
            at: NOWHERE,
            // The net's polygons are ascending, so the lowest one is canonical
            // and is the only geometry these inputs carry.
            shapes: (poly, None),
            measured: Measurement::Count(0),
            limit: Measurement::Count(1),
        });
    }

    debug_assert_eq!(
        out.len() - before,
        floating.len(),
        "the compact and the violations it wrote disagree"
    );
    record_run(runs, out, before, FLOATING_NET, Outcome::Ran, u64::from(net_count));
}

/// Two different labels resolving to one net, or one label to two nets.
///
/// Reported rather than resolved: choosing a winner produces a comparison that
/// is confidently wrong about which net is which.
pub fn check_label_conflicts(
    nets: &NetTable,
    ports: &PortTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let before = out.len();
    let net_count = narrow(nets.net_count());

    // One name to two nets is the half of the condition this table can state.
    // The other half — two names on one net — is unobservable through
    // [`PortTable`]'s interface, which is strictly ascending by net and offers
    // no iteration; it is [`check_net_seed_conflicts`]'s, counted rather than
    // named, for the same reason.
    //
    // `PortTable` publishes `name_of(net)` and nothing that iterates, so a
    // per-net binary search is the only enumeration its interface admits, and
    // the column has to exist before it can be sorted. The missing iterator is
    // filed in `docs/SIGNATURE_DEFECTS.md`.
    let mut named: Vec<(StrId, NetId)> = Vec::with_capacity(ports.len());
    for row in 0..net_count {
        let net = NetId(row);
        // Surviving `if`: the taken side appends, and most nets in a real cell
        // are anonymous, so this sits at the far end of the selectivity curve.
        if let Some(name) = ports.name_of(net) {
            named.push((name, net));
        }
    }
    debug_assert!(named.len() <= ports.len(), "a net named itself twice");

    // Sorting by `(name, net)` brings one name's nets adjacent, which turns the
    // question into a neighbour comparison over two offset views of the one
    // column; the empty and single-row cases collapse to two empty views rather
    // than to a length guard.
    named.sort_unstable();
    let (head, tail) = adjacent(&named);
    let pairs = head.len();
    debug_assert_eq!(pairs, tail.len(), "SoA columns must agree");

    // The compact, branchless, reserved for every pair rather than for the
    // clashing ones.
    let mut clashes: Vec<((StrId, NetId), (StrId, NetId))> = Vec::with_capacity(pairs);
    let slots = &mut clashes.spare_capacity_mut()[..pairs];
    let mut w = 0usize;
    for (i, (&this, &next)) in head.iter().zip(tail).enumerate() {
        let keep = this.0 == next.0;
        // `w <= i` by induction: `w` starts at zero and `bool` is 0 or 1, so it
        // advances by at most one per iteration.
        debug_assert!(w <= i);
        // SAFETY: `w <= i < pairs == slots.len()`, from the induction above.
        // Rejected slots stay uninit and are truncated away by `set_len(w)`;
        // `(StrId, NetId)` is `Copy`, so there is no `Drop` to skip.
        unsafe { slots.get_unchecked_mut(w) }.write((this, next));
        w += usize::from(keep);
    }
    // SAFETY: every slot in `0..w` was written when `w` held that value, and
    // `w <= pairs == capacity`.
    unsafe { clashes.set_len(w) };
    debug_assert!(clashes.len() <= pairs, "more clashing pairs than adjacent pairs");

    // Not a bulk loop: one iteration per finding, and a clean cell has none.
    for &((_, a), (_, b)) in &clashes {
        out.push(Violation {
            rule: LABEL_CONFLICT,
            layer: NO_LAYER,
            severity: Severity::Error,
            at: NOWHERE,
            shapes: (first_poly(nets, a), Some(first_poly(nets, b))),
            // One name, two nets, where a name names one net.
            measured: Measurement::Count(2),
            limit: Measurement::Count(1),
        });
    }

    record_run(runs, out, before, LABEL_CONFLICT, Outcome::Ran, u64::from(net_count));
}

/// Net seeds that disagree — two labelled shapes that extraction merged into
/// one net when the labels say they should be distinct.
///
/// Distinct from a label conflict: this is a connectivity finding wearing a
/// naming symptom, and the fix is in the layout, not the labels.
pub fn check_net_seed_conflicts(
    nets: &NetTable,
    ports: &PortTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let before = out.len();
    let net_count = narrow(nets.net_count());
    let seeds = narrow(ports.len());

    // Each seed is a labelled shape the binder bound to a net. Every *distinct*
    // net of this extraction that carries a name accounts for exactly one seed,
    // so a shortfall is seeds that landed somewhere a distinct net of this
    // extraction is not: two seeds merged onto one net, or a seed on a net this
    // table does not have. Both are the connectivity fault this check names,
    // and counting is as far as `PortTable`'s interface goes — it exposes
    // `name_of(net)` and nothing that iterates.
    //
    // `PortTable` exposes no column and no iterator, so a per-net binary search
    // is the only enumeration there is — the ceiling
    // [`check_label_conflicts`] names, with the same filed resolution. The body
    // is branchless: the bool is widened and added rather than counted under an
    // `if`.
    let mut resolved = 0u32;
    for row in 0..net_count {
        resolved += u32::from(ports.name_of(NetId(row)).is_some());
    }
    debug_assert!(
        resolved <= seeds,
        "{resolved} distinct named nets from {seeds} labels"
    );

    // Surviving `if`: one test per call, above the loop, not inside one.
    if resolved < seeds {
        out.push(Violation {
            rule: NET_SEED_CONFLICT,
            layer: NO_LAYER,
            severity: Severity::Error,
            at: NOWHERE,
            shapes: (NO_SHAPE, None),
            // Below its limit: the extraction resolved fewer distinct nets than
            // the layout placed seeds, and the shortfall is the merge.
            measured: Measurement::Count(resolved),
            limit: Measurement::Count(seeds),
        });
    }

    record_run(runs, out, before, NET_SEED_CONFLICT, Outcome::Ran, u64::from(seeds));
}

/// Device counts by family, against what the deck says is possible.
///
/// **Transform.** Separate MOS and BJT passes rather than one loop with a kind
/// branch, because the two families have different validity conditions — the
/// dispatcher pattern at its smallest.
pub fn check_device_counts(
    devices: &DeviceTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let before = out.len();
    debug_assert_eq!(
        devices.terminal_start.len(),
        devices.len() + usize::from(!devices.terminal_start.is_empty()),
        "the terminal CSR carries one offset per device plus a terminator"
    );

    // The two family passes, each closed out with its own run row so the
    // dispatcher's shape survives into the report. Neither can execute: "what
    // the deck says is possible" is a `Deck` this signature does not take, and
    // there is no other source for a per-family count limit. Inventing one
    // would be a limit every layout passes, which is the fail-open defect the
    // whole `RuleRun` mechanism exists to make impossible — so both rows are
    // recorded as unrun, loudly, and `examined` is zero because nothing was.
    //
    // Not a shortcut and not a body this phase can write: the whole check is a
    // count per family against a limit, and the limit has no source in these
    // three parameters. The missing `deck: &Deck` uniform is filed in
    // `docs/SIGNATURE_DEFECTS.md`.
    let unconfigured = Outcome::Skipped(SkipReason::NotInDeck);
    record_run(runs, out, before, DEVICE_COUNT_MOS, unconfigured, 0);
    record_run(runs, out, before, DEVICE_COUNT_BJT, unconfigured, 0);

    debug_assert_eq!(out.len(), before, "a skipped rule wrote a violation");
}

/// Devices whose measured parameters fall outside the deck's declared range for
/// their model.
///
/// A layout-only check: it needs no schematic, only the model's stated limits.
/// A device outside them will not simulate as intended regardless of whether
/// LVS matches.
pub fn check_parametric(
    devices: &DeviceTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let before = out.len();
    debug_assert_eq!(
        devices.param_start.len(),
        devices.len() + usize::from(!devices.param_start.is_empty()),
        "the param CSR carries one offset per device plus a terminator"
    );

    // Unrun for exactly one of the two reasons it used to have. There is now
    // something to compare: `topology::recognise_into` measures the marker
    // polygon's area as `DeviceParam::Area`, one row per device, so the param
    // column asserted above is populated rather than empty. What is still
    // missing is the other operand — "the model's stated limits" live in a
    // `Deck` this signature does not take, and with it the body is a compact
    // over that column and nothing else. Filed in
    // `docs/SIGNATURE_DEFECTS.md`; `Width`, `Length` and `Fingers` remain
    // unmeasurable for a separate reason filed under `topology`.
    record_run(
        runs,
        out,
        before,
        PARAMETRIC,
        Outcome::Skipped(SkipReason::NotInDeck),
        0,
    );

    debug_assert_eq!(out.len(), before, "a skipped rule wrote a violation");
}

/// Structural sanity of the extracted graph itself — a terminal on no net, a
/// device with the wrong terminal count for its family.
///
/// These indicate an extraction bug rather than a layout bug, and they are
/// checked because an extraction bug that reaches the comparator produces a
/// mismatch report blaming the layout.
pub fn check_topology(
    layout: &LayoutGraph,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let graph = &layout.0;
    let devices = graph.device_kind.len();
    let net_count = narrow(graph.net_name.len());

    debug_assert_eq!(graph.device_model.len(), devices, "one model per device");
    debug_assert_eq!(
        graph.terminal_net.len(),
        graph.terminal_role.len(),
        "a net column and a role column arrive parallel"
    );
    debug_assert!(
        graph.device_terminal_start.is_empty()
            || graph.device_terminal_start.len() == devices + 1,
        "the terminal CSR carries one offset per device plus a terminator"
    );
    debug_assert!(
        graph.net_terminal_start.is_empty()
            || graph.net_terminal_start.len() == graph.net_name.len() + 1,
        "the reverse CSR carries one offset per net plus a terminator"
    );
    debug_assert!(
        graph.device_terminal_start.windows(2).all(|w| w[0] <= w[1]),
        "a CSR run runs backwards"
    );

    // The forward direction only. `net_terminal` is the transpose of these same
    // terminals, so scanning it too would report every fault twice — and a
    // graph whose two directions disagree is a `from_layout_into` fault this
    // check has no second opinion to detect it with.
    let before = out.len();
    let terminals = graph.terminal_net.len();
    let mut dangling: Vec<u32> = Vec::with_capacity(terminals);
    let slots = &mut dangling.spare_capacity_mut()[..terminals];
    let mut w = 0usize;
    for (i, &net) in graph.terminal_net.iter().enumerate() {
        // `NetId::NONE` is `u32::MAX`, so "on no net" and "on a net past the
        // end of the table" are the same comparison, which is what lets the
        // body stay a single compare with no branch.
        let keep = net >= net_count;
        // `w <= i` by induction: `w` starts at zero and `bool` is 0 or 1, so it
        // advances by at most one per iteration.
        debug_assert!(w <= i);
        // SAFETY: `w <= i < terminals == slots.len()`, from the induction
        // above. Rejected slots stay uninit and are truncated away by
        // `set_len(w)`; `u32` is `Copy`, so there is no `Drop` to skip.
        unsafe { slots.get_unchecked_mut(w) }.write(net);
        w += usize::from(keep);
    }
    // SAFETY: every slot in `0..w` was written when `w` held that value, and
    // `w <= terminals == capacity`.
    unsafe { dangling.set_len(w) };
    debug_assert!(
        dangling.len() <= terminals,
        "more dangling terminals than terminals"
    );

    // Not a bulk loop: one iteration per finding, and a sound extraction has
    // none.
    for &net in &dangling {
        out.push(Violation {
            rule: TERMINAL_NET,
            layer: NO_LAYER,
            severity: Severity::Error,
            at: NOWHERE,
            shapes: (NO_SHAPE, None),
            // Read as "the graph has `net_count` nets and this terminal needs
            // at least `net + 1`", which is below its limit exactly when the
            // terminal dangles. `saturating_add` because `NetId::NONE` is
            // `u32::MAX` and would otherwise wrap to a limit of zero, which
            // every net count meets — fail-open, for the one input that is
            // certain to be a fault.
            measured: Measurement::Count(net_count),
            limit: Measurement::Count(net.saturating_add(1)),
        });
    }
    record_run(
        runs,
        out,
        before,
        TERMINAL_NET,
        Outcome::Ran,
        examined(terminals),
    );

    // A device's terminal count is its CSR run length: an adjacent-pair map
    // over two offset views. The empty case collapses to two empty views rather
    // than to a length guard.
    let before = out.len();
    let (from_col, to_col) = adjacent(&graph.device_terminal_start);
    debug_assert_eq!(from_col.len(), to_col.len(), "SoA columns must agree");
    let mut width: Vec<u32> = Vec::with_capacity(from_col.len());
    for (&from, &to) in from_col.iter().zip(to_col) {
        // Ascending by the CSR invariant asserted above, so this cannot wrap.
        width.push(to - from);
    }
    // Fail closed on a graph that cannot answer the question. The CSR shape
    // check above carries an `is_empty() ||` escape, so an absent
    // `device_terminal_start` beside a non-empty `device_kind` passes it; the
    // zip below then yields `min(devices, 0) == 0` iterations and the whole
    // check reports `Ran` having examined nothing. That is the empty clean
    // result `docs/VOCABULARY.md` names — indistinguishable, to a reader, from
    // a device table whose terminal counts are all legal.
    //
    // `debug_assert` alone is not enough here precisely because the release
    // build is where a false clean does damage. `Refused` rather than
    // `Skipped`: the graph is malformed, not merely missing an optional input,
    // and `Summary::passed` denies a pass on either.
    if width.len() != devices {
        record_run(runs, out, before, TERMINAL_COUNT, Outcome::Refused, 0);
        return;
    }

    debug_assert_eq!(graph.device_kind.len(), width.len(), "SoA columns must agree");
    let mut wrong: Vec<(DeviceKind, u32)> = Vec::with_capacity(devices);
    let slots = &mut wrong.spare_capacity_mut()[..devices];
    let mut w = 0usize;
    for (i, (&kind, &count)) in graph.device_kind.iter().zip(&width).enumerate() {
        // A count past 31 is clamped onto bit 31, which no family sets, so an
        // absurd terminal count is a finding rather than a shift overflow. The
        // `& 7` is what keeps the table load off a panic edge; see
        // `LEGAL_WIDTHS`.
        let keep = (LEGAL_WIDTHS[(kind as usize) & 7] >> count.min(31)) & 1 == 0;
        // `w <= i` by induction: `w` starts at zero and `bool` is 0 or 1, so it
        // advances by at most one per iteration.
        debug_assert!(w <= i);
        // SAFETY: `w <= i < devices == slots.len()`, from the induction above.
        // Rejected slots stay uninit and are truncated away by `set_len(w)`;
        // `(DeviceKind, u32)` is `Copy`, so there is no `Drop` to skip.
        unsafe { slots.get_unchecked_mut(w) }.write((kind, count));
        w += usize::from(keep);
    }
    // SAFETY: every slot in `0..w` was written when `w` held that value, and
    // `w <= devices == capacity`.
    unsafe { wrong.set_len(w) };
    debug_assert!(wrong.len() <= devices, "more malformed devices than devices");

    // Not a bulk loop: one iteration per finding, and a sound extraction has
    // none.
    for &(kind, measured) in &wrong {
        out.push(Violation {
            rule: TERMINAL_COUNT,
            layer: NO_LAYER,
            severity: Severity::Error,
            at: NOWHERE,
            shapes: (NO_SHAPE, None),
            measured: Measurement::Count(measured),
            limit: Measurement::Count(FULL_WIDTHS[(kind as usize) & 7]),
        });
    }
    record_run(runs, out, before, TERMINAL_COUNT, Outcome::Ran, examined(devices));
}

/// Close out one check: append its [`RuleRun`], with the violation count
/// derived rather than counted by the caller.
///
/// **Decision, and the invariant lives here.** The same argument `drc`'s
/// `record_run` makes, and deliberately a second copy of it rather than a
/// widening of `drc`'s interface: a check cannot report a violation it did not
/// push, or push one it did not report, because the count is `out.len()` before
/// and after and nothing else.
fn record_run(
    runs: &mut Vec<RuleRun>,
    out: &Violations,
    violations_before: usize,
    rule: StrId,
    outcome: Outcome,
    examined: u64,
) {
    let after = out.len();
    debug_assert!(
        violations_before <= after,
        "a check started at {violations_before} of a table that now holds {after}: \
         the shared violation table was truncated under a running check"
    );
    let pushed = after - violations_before;

    let before_rows = runs.len();
    runs.push(RuleRun {
        rule,
        outcome,
        examined,
        // Saturating rather than wrapping, for `drc::record_run`'s reason: past
        // four billion findings from one check the exact count is noise, but
        // wrapping it to a small number would read as a nearly-clean check.
        violations: u32::try_from(pushed).unwrap_or(u32::MAX),
    });
    debug_assert_eq!(
        runs.len(),
        before_rows + 1,
        "one check row produces exactly one run row"
    );
}

/// The two offset views an adjacent-pair scan runs over: rows `0 .. n-1`
/// against rows `1 .. n`.
///
/// The one copy. Both call sites wrote it out, and an empty or single-row column
/// is the case each had to get right on its own — `saturating_sub` and `min`
/// the wrong way round is an out-of-range slice, not an empty scan.
fn adjacent<T>(column: &[T]) -> (&[T], &[T]) {
    let head = column.len().saturating_sub(1);
    let tail = column.len().min(1);
    debug_assert_eq!(head, column.len() - tail, "the two views name a different pair count");
    (&column[..head], &column[tail..])
}

/// The lowest polygon of a net, or [`NO_SHAPE`] for a net carrying none.
///
/// `polys_of` is ascending, so the lowest one is canonical and does not depend
/// on how the extraction bucketed the layer.
fn first_poly(nets: &NetTable, net: NetId) -> PolyId {
    nets.polys_of(net).first().copied().unwrap_or(NO_SHAPE)
}

/// A row count as a [`RuleRun::examined`]. Widening, never truncating: a check
/// that under-reports what it looked at is how a summary comes back green.
fn examined(count: usize) -> u64 {
    u64::try_from(count).expect("a row count fits a u64")
}

