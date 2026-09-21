//! Standalone LVS checks that need no reference netlist.
//!
//! No signature here carries a `StrTable`, rule table, `GeometryStore` or
//! `LayerId`, so the rule ids and the `layer`/`at`/`shape` columns are
//! out-of-range sentinels that index nothing. Two checks compare against deck
//! limits no signature supplies and report [`Outcome::Skipped`] rather than
//! inventing a limit everything passes: an unconfigurable rule is recorded as
//! unrun, never as clean.

use crate::lvs::graph::{narrow, LayoutGraph};
use crate::report::{
    record_run, Measurement, Outcome, RuleRun, Severity, SkipReason, Violation, Violations,
};
use crate::topology::{DeviceTable, NetId, NetTable, PortTable};
use gpurify_geom::ops::Point;
use gpurify_geom::Dbu;
use gpurify_geom::{LayerId, PolyId};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrId;

/// Rule ids for the eight run rows the six checks produce. Counted down from
/// `u32::MAX` to stay out of the range a run's `StrTable` issues.
const FLOATING_NET: StrId = StrId(u32::MAX);
const LABEL_CONFLICT: StrId = StrId(u32::MAX - 1);
const NET_SEED_CONFLICT: StrId = StrId(u32::MAX - 2);
const DEVICE_COUNT_MOS: StrId = StrId(u32::MAX - 3);
const DEVICE_COUNT_BJT: StrId = StrId(u32::MAX - 4);
const PARAMETRIC: StrId = StrId(u32::MAX - 5);
const TERMINAL_NET: StrId = StrId(u32::MAX - 6);
const TERMINAL_COUNT: StrId = StrId(u32::MAX - 7);

/// The coordinate a graph-structure finding does not have.
const NOWHERE: Point = Point {
    x: Dbu::new_unchecked(0),
    y: Dbu::new_unchecked(0),
};

/// The layer a netlist-level finding does not have. Past any layer table.
const NO_LAYER: LayerId = LayerId(u16::MAX);

/// The polygon a graph-only finding does not have. Past any store.
const NO_SHAPE: PolyId = PolyId(u32::MAX);

/// Which terminal counts each device family admits, as a bitmask indexed by the
/// count.
///
/// Eight rows and a mask of `7`, not five and a bounds check. The three
/// unreachable rows admit no width at all, so an unknown tag fails closed.
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

/// The full terminal set each family is reported against when [`LEGAL_WIDTHS`]
/// rejects a width.
const FULL_WIDTHS: [u32; 8] = [4, 3, 2, 2, 2, 0, 0, 0];

/// Nets with no device terminal on them. A net that is *only* a port is not
/// floating.
///
/// # Panics
///
/// When `devices` did not come from the same extraction as `nets`, in either
/// direction and in every profile. Deliberately unguarded: a device table that
/// cannot answer for a net would otherwise read as a net with no devices.
pub fn check_floating_nets(
    nets: &NetTable,
    devices: &DeviceTable,
    ports: &PortTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let before = out.len();
    let net_count = narrow(nets.net_count());

    // The fail-closed probe the `# Panics` section promises, made once.
    if net_count > 0 {
        let top = devices.devices_on(NetId(net_count - 1));
        debug_assert!(
            top.len() <= devices.len(),
            "one net carries more devices than the table holds"
        );
    }

    // One column carrying both the predicate and the payload: net `n` holds its
    // lowest polygon while still a candidate, [`NO_SHAPE`] once ruled out.
    let mut lowest: Vec<PolyId> = Vec::with_capacity(net_count as usize);

    for row in 0..net_count {
        let net = NetId(row);
        // A named net leaves the cell, so it is not floating. `NO_SHAPE` is
        // `u32::MAX`, which *is* the all-ones mask.
        let named = u32::from(ports.name_of(net).is_some()).wrapping_neg();
        lowest.push(PolyId(first_poly(nets, net).0 | named));
    }
    debug_assert_eq!(lowest.len(), net_count as usize, "one column row per net");

    // A terminal naming a net past this table panics in every profile, which is
    // the other direction of the probe above.
    for &net in &devices.terminal_net {
        lowest[net.idx()] = NO_SHAPE;
    }

    // Branchless compact: reserved for the whole input.
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

    for &poly in &floating {
        out.push(Violation {
            rule: FLOATING_NET,
            layer: NO_LAYER,
            severity: Severity::Error,
            at: NOWHERE,
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
    record_run(
        runs,
        out,
        before,
        FLOATING_NET,
        Outcome::Ran,
        u64::from(net_count),
    );
}

/// Two different labels resolving to one net, or one label to two nets.
///
/// Reported rather than resolved: choosing a winner produces a comparison that is
/// confidently wrong about which net is which.
pub fn check_label_conflicts(
    nets: &NetTable,
    ports: &PortTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let before = out.len();
    let net_count = narrow(nets.net_count());

    // One name to two nets is the half this table can state; two names on one net
    // is unobservable through `PortTable` and is `check_net_seed_conflicts`'s.
    let mut named: Vec<(StrId, NetId)> = Vec::with_capacity(ports.len());
    for row in 0..net_count {
        let net = NetId(row);
        if let Some(name) = ports.name_of(net) {
            named.push((name, net));
        }
    }
    debug_assert!(named.len() <= ports.len(), "a net named itself twice");

    // Sorting by `(name, net)` brings one name's nets adjacent.
    named.sort_unstable();
    let (head, tail) = adjacent(&named);
    let pairs = head.len();
    debug_assert_eq!(pairs, tail.len(), "SoA columns must agree");

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
    debug_assert!(
        clashes.len() <= pairs,
        "more clashing pairs than adjacent pairs"
    );

    for &((_, a), (_, b)) in &clashes {
        out.push(Violation {
            rule: LABEL_CONFLICT,
            layer: NO_LAYER,
            severity: Severity::Error,
            at: NOWHERE,
            shapes: (first_poly(nets, a), Some(first_poly(nets, b))),
            measured: Measurement::Count(2),
            limit: Measurement::Count(1),
        });
    }

    record_run(
        runs,
        out,
        before,
        LABEL_CONFLICT,
        Outcome::Ran,
        u64::from(net_count),
    );
}

/// Net seeds that disagree: two labelled shapes extraction merged into one net
/// when the labels say they should be distinct.
pub fn check_net_seed_conflicts(
    nets: &NetTable,
    ports: &PortTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let before = out.len();
    let net_count = narrow(nets.net_count());
    let seeds = narrow(ports.len());

    // Every distinct named net accounts for exactly one seed, so a shortfall is
    // two seeds merged onto one net, or a seed on a net this table lacks.
    let mut resolved = 0u32;
    for row in 0..net_count {
        resolved += u32::from(ports.name_of(NetId(row)).is_some());
    }
    debug_assert!(
        resolved <= seeds,
        "{resolved} distinct named nets from {seeds} labels"
    );

    if resolved < seeds {
        out.push(Violation {
            rule: NET_SEED_CONFLICT,
            layer: NO_LAYER,
            severity: Severity::Error,
            at: NOWHERE,
            shapes: (NO_SHAPE, None),
            measured: Measurement::Count(resolved),
            limit: Measurement::Count(seeds),
        });
    }

    record_run(
        runs,
        out,
        before,
        NET_SEED_CONFLICT,
        Outcome::Ran,
        u64::from(seeds),
    );
}

/// Device counts by family, against what the deck says is possible.
pub fn check_device_counts(devices: &DeviceTable, out: &mut Violations, runs: &mut Vec<RuleRun>) {
    let before = out.len();
    debug_assert_eq!(
        devices.terminal_start.len(),
        devices.len() + usize::from(!devices.terminal_start.is_empty()),
        "the terminal CSR carries one offset per device plus a terminator"
    );

    // Neither family pass can execute: the per-family count limit lives in a
    // `Deck` this signature does not take, and inventing one would be a limit
    // every layout passes.
    let unconfigured = Outcome::Skipped(SkipReason::NotInDeck);
    record_run(runs, out, before, DEVICE_COUNT_MOS, unconfigured, 0);
    record_run(runs, out, before, DEVICE_COUNT_BJT, unconfigured, 0);

    debug_assert_eq!(out.len(), before, "a skipped rule wrote a violation");
}

/// Devices whose measured parameters fall outside the deck's declared range for
/// their model.
pub fn check_parametric(devices: &DeviceTable, out: &mut Violations, runs: &mut Vec<RuleRun>) {
    let before = out.len();
    debug_assert_eq!(
        devices.param_start.len(),
        devices.len() + usize::from(!devices.param_start.is_empty()),
        "the param CSR carries one offset per device plus a terminator"
    );

    // Unrun: the model's stated limits live in a `Deck` this signature does not
    // take, so there is no second operand to compare the param column against.
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

/// Structural sanity of the extracted graph itself: a terminal on no net, a
/// device with the wrong terminal count for its family.
pub fn check_topology(layout: &LayoutGraph, out: &mut Violations, runs: &mut Vec<RuleRun>) {
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
        graph.device_terminal_start.is_empty() || graph.device_terminal_start.len() == devices + 1,
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

    // Forward direction only: `net_terminal` is the transpose, so scanning it too
    // would report every fault twice.
    let before = out.len();
    let terminals = graph.terminal_net.len();
    let mut dangling: Vec<u32> = Vec::with_capacity(terminals);
    let slots = &mut dangling.spare_capacity_mut()[..terminals];
    let mut w = 0usize;
    for (i, &net) in graph.terminal_net.iter().enumerate() {
        // `NetId::NONE` is `u32::MAX`, so "on no net" and "on a net past the end
        // of the table" are the same comparison.
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

    for &net in &dangling {
        out.push(Violation {
            rule: TERMINAL_NET,
            layer: NO_LAYER,
            severity: Severity::Error,
            at: NOWHERE,
            shapes: (NO_SHAPE, None),
            // `saturating_add` because `NetId::NONE` is `u32::MAX` and would wrap
            // to a limit of zero, which every net count meets — fail-open, for
            // the one input certain to be a fault.
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

    let before = out.len();
    let (from_col, to_col) = adjacent(&graph.device_terminal_start);
    debug_assert_eq!(from_col.len(), to_col.len(), "SoA columns must agree");
    let mut width: Vec<u32> = Vec::with_capacity(from_col.len());
    for (&from, &to) in from_col.iter().zip(to_col) {
        // Ascending by the CSR invariant asserted above, so this cannot wrap.
        width.push(to - from);
    }
    // Fail closed: an absent `device_terminal_start` beside a non-empty
    // `device_kind` passes the `is_empty() ||` escape above, and the zip would
    // then examine nothing and report `Ran`. `Refused`, not `Skipped` — the graph
    // is malformed rather than missing an optional input.
    if width.len() != devices {
        record_run(runs, out, before, TERMINAL_COUNT, Outcome::Refused, 0);
        return;
    }

    debug_assert_eq!(
        graph.device_kind.len(),
        width.len(),
        "SoA columns must agree"
    );
    let mut wrong: Vec<(DeviceKind, u32)> = Vec::with_capacity(devices);
    let slots = &mut wrong.spare_capacity_mut()[..devices];
    let mut w = 0usize;
    for (i, (&kind, &count)) in graph.device_kind.iter().zip(&width).enumerate() {
        // A count past 31 is clamped onto bit 31, which no family sets, so an
        // absurd terminal count is a finding rather than a shift overflow. The
        // `& 7` keeps the table load off a panic edge; see `LEGAL_WIDTHS`.
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
    debug_assert!(
        wrong.len() <= devices,
        "more malformed devices than devices"
    );

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
    record_run(
        runs,
        out,
        before,
        TERMINAL_COUNT,
        Outcome::Ran,
        examined(devices),
    );
}

/// The two offset views an adjacent-pair scan runs over: rows `0 .. n-1` against
/// rows `1 .. n`.
fn adjacent<T>(column: &[T]) -> (&[T], &[T]) {
    let head = column.len().saturating_sub(1);
    let tail = column.len().min(1);
    debug_assert_eq!(
        head,
        column.len() - tail,
        "the two views name a different pair count"
    );
    (&column[..head], &column[tail..])
}

/// The lowest polygon of a net, or [`NO_SHAPE`] for a net carrying none.
fn first_poly(nets: &NetTable, net: NetId) -> PolyId {
    nets.polys_of(net).first().copied().unwrap_or(NO_SHAPE)
}

/// A row count as a [`RuleRun::examined`]. Widening, never truncating: a check
/// that under-reports what it looked at is how a summary comes back green.
fn examined(count: usize) -> u64 {
    u64::try_from(count).expect("a row count fits a u64")
}
