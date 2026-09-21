//! Series and parallel device reduction.
//!
//! [`reduce_into`] must run over the layout graph *and* the reference graph:
//! either may be written unreduced, and reducing only one side would make the
//! transform choose the answer rather than normalise the question.
//!
//! Under-reduction is safe and over-reduction is not. A merge that did not happen
//! leaves an extra device on one side, which [`compare`] reports as
//! [`Discrepancy::UnpairedDevice`]; a merge that should *not* have happened
//! deletes a device the design contains, and two netlists differing by exactly
//! that device then match. So every condition below is written as what must hold
//! before a merge, never as what must hold before a refusal.
//!
//! A parallel merge adds `W` and a series merge adds `L`, and this transform can
//! do neither: [`Graph::param`] keys on an interned name and nothing here is
//! handed a `StrTable`, so `W`, `L` and `M` are indistinguishable `u32`s. **A
//! device that declares any parameter therefore does not merge**, because
//! dropping the parameters would leave a merged reference declaring nothing
//! against a layout declaring nothing, which reports [`Verdict::Match`].
//!
//! ponytail: the upgrade path is one parameter and not a rewrite — a `&StrTable`
//! at this signature, or `DeviceParam` reaching [`Graph`] as a tag rather than as
//! a name, and then the additive column is identifiable and the sum is three
//! lines. `from_layout_into` measures `w`/`l` now, but the refusal still holds
//! the line correctly: a sized finger and a sized card each stay one device,
//! so the counts pair one to one and no sum is needed until a reference is
//! written pre-merged *with* sizes — that is the day to take this.
//!
//! [`compare`]: crate::lvs::compare::compare
//! [`Discrepancy::UnpairedDevice`]: crate::lvs::verdict::Discrepancy::UnpairedDevice
//! [`Verdict::Match`]: crate::lvs::verdict::Verdict::Match

use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrId;
use crate::topology::TerminalRole;

use crate::lvs::graph::{narrow, transpose_into, Graph};
use crate::lvs::refine::role_code;

/// The two ends of a MOS channel, which are what a merge exchanges, consumes and
/// counts. Every other role is fixed furniture.
const fn is_channel(role: TerminalRole) -> bool {
    matches!(role, TerminalRole::Source | TerminalRole::Drain)
}

/// The merge code the channel collapses onto. `8`, past every value
/// [`role_code`] returns, which is what puts a device's channel terminals at the
/// end of its sorted key and lets the non-channel half be read off as a prefix.
const CHANNEL: u64 = 8;

/// The lowest key a channel terminal can carry, and therefore the split point
/// between a device's non-channel prefix and its channel suffix.
const CHANNEL_BASE: u64 = CHANNEL << 32;

/// [`role_code`] with the channel collapsed onto one value: which end of a MOS
/// channel is the source is decided by bias, so two devices differing only in
/// that are one device.
const fn merge_code(role: TerminalRole) -> u64 {
    if is_channel(role) {
        CHANNEL
    } else {
        role_code(role)
    }
}

/// One terminal as a sortable `u64`: its merge code above its net. Injective, so
/// two keys are equal exactly when the role class and the net are.
fn terminal_key(role: TerminalRole, net: u32) -> u64 {
    (merge_code(role) << 32) | u64::from(net)
}

/// The net half of a [`terminal_key`].
fn key_net(key: u64) -> u32 {
    u32::try_from(key & 0xFFFF_FFFF).expect("the low half of a terminal key is a u32")
}

/// The kind tag the parallel sort keys on. A `match` and not an `as` cast, so a
/// new device family is a compile error here rather than a silent reordering.
const fn kind_tag(kind: DeviceKind) -> u8 {
    match kind {
        DeviceKind::Mos => 0,
        DeviceKind::Bjt => 1,
        DeviceKind::Resistor => 2,
        DeviceKind::Capacitor => 3,
        DeviceKind::Diode => 4,
    }
}

/// What one pass decided: which devices are one device, and which nets stopped
/// existing when they became one.
#[derive(Default)]
struct Plan {
    /// `root[device]` is the group's lowest device index. A device on its own is
    /// its own root.
    root: Vec<u32>,
    /// Device rows sorted by `(root, index)`, so a group is a contiguous run.
    order: Vec<u32>,
    /// Nets a series merge swallowed. Never a port and never named.
    consumed: Vec<bool>,
    /// `new_net[old]` is the surviving net's row, or `u32::MAX` for a consumed
    /// one. Ascending over the survivors, so their relative order is the input's.
    new_net: Vec<u32>,
    /// Devices that may merge at all: no declared parameter, and no terminal on
    /// no net. Both are refusals rather than oversights.
    mergeable: Vec<bool>,
    /// Each device's terminals as [`terminal_key`]s, ascending, CSR into `key`.
    key_start: Vec<u32>,
    key: Vec<u64>,
    /// Nets carrying a port, scattered from `port_net`.
    is_port: Vec<bool>,
    /// Candidate series nets and the two devices each joins, ascending by net.
    /// Kept because the consumed mask is rebuilt from it after a dissolution.
    series: Vec<(u32, u32, u32)>,
    /// Groups after dissolution — the device count the emission writes.
    groups: usize,
    /// Surviving nets — the net count the emission writes.
    nets: usize,
}

/// One device's terminal keys, ascending.
fn keys<'k>(key_start: &[u32], key: &'k [u64], device: u32) -> &'k [u64] {
    let from = key_start[device as usize] as usize;
    let to = key_start[device as usize + 1] as usize;
    debug_assert!(from <= to, "a key run runs backwards");
    &key[from..to]
}

/// The prefix of [`keys`] that is not the channel, and the suffix that is.
fn split_keys(run: &[u64]) -> (&[u64], &[u64]) {
    run.split_at(run.partition_point(|&key| key < CHANNEL_BASE))
}

/// Everything the parallel sort orders on: what the device is, and where every
/// terminal of it lands.
fn parallel_key<'k>(
    src: &Graph,
    key_start: &[u32],
    key: &'k [u64],
    device: u32,
) -> (u8, StrId, &'k [u64]) {
    (
        kind_tag(src.device_kind[device as usize]),
        src.device_model[device as usize],
        keys(key_start, key, device),
    )
}

/// The group root of `device`, with the path halved on the way.
///
/// The root is the set's **lowest** device index — [`join`] always points the
/// higher root at the lower — so the emission order is a function of the input.
fn find(root: &mut [u32], device: u32) -> u32 {
    let mut at = device as usize;
    while root[at] as usize != at {
        let grand = root[root[at] as usize];
        root[at] = grand;
        at = grand as usize;
    }
    narrow(at)
}

fn join(root: &mut [u32], a: u32, b: u32) {
    let (left, right) = (find(root, a), find(root, b));
    root[left.max(right) as usize] = left.min(right);
    debug_assert_eq!(find(root, a), find(root, b), "the join did not take");
}

/// Reduce a netlist to its series/parallel normal form, refilling `out`.
///
/// Devices are emitted one per group in ascending order of the group's lowest
/// source row; nets in ascending source order with the consumed ones removed, so
/// `port_net` keeps its declared order. A graph with nothing to merge comes
/// through byte-identical, which is what lets this sit unconditionally in front
/// of `compare`, and no hash container is used anywhere.
///
/// The pass count is bounded by `src.device_count()` because a pass that changes
/// anything drops the device count by at least one. Reaching the bound is a bug;
/// a release build that did hands back the partially reduced graph, which is
/// under-reduction and safe.
pub fn reduce_into(src: &Graph, out: &mut Graph) {
    let mut plan = Plan::default();

    if !plan_into(src, &mut plan) {
        copy_into(src, out);
        debug_assert_eq!(out, src, "the copy path is not a copy");
        return;
    }
    emit_into(src, &plan, out);

    let mut spare = Graph::default();
    let mut budget = src.device_count();
    while budget > 0 && plan_into(out, &mut plan) {
        emit_into(out, &plan, &mut spare);
        std::mem::swap(out, &mut spare);
        budget -= 1;
    }
    debug_assert!(
        budget > 0,
        "reduction did not reach a fixed point in {} passes",
        src.device_count()
    );
}

/// Every column of `src`, verbatim.
fn copy_into(src: &Graph, out: &mut Graph) {
    fn copy<T: Copy>(from: &[T], to: &mut Vec<T>) {
        to.clear();
        to.extend_from_slice(from);
    }
    copy(&src.device_kind, &mut out.device_kind);
    copy(&src.device_model, &mut out.device_model);
    copy(&src.device_terminal_start, &mut out.device_terminal_start);
    copy(&src.terminal_net, &mut out.terminal_net);
    copy(&src.terminal_role, &mut out.terminal_role);
    copy(&src.device_param_start, &mut out.device_param_start);
    copy(&src.param, &mut out.param);
    copy(&src.net_terminal_start, &mut out.net_terminal_start);
    copy(&src.net_terminal, &mut out.net_terminal);
    copy(&src.net_name, &mut out.net_name);
    copy(&src.port_net, &mut out.port_net);
}

/// Decide one pass: which devices are one device, and which nets die with them.
/// Returns whether anything merged, which is the fixed-point test.
fn plan_into(src: &Graph, plan: &mut Plan) -> bool {
    let devices = src.device_count();
    let nets = src.net_count();

    prepare(src, plan, devices, nets);
    join_parallel(src, plan, devices);
    join_series(src, plan, nets);

    // Groups, then validation, then the net renumbering: a group that does not
    // survive validation must not take its nets with it.
    order_by_group(plan, devices);
    dissolve_invalid(src, plan);
    order_by_group(plan, devices);
    mark_consumed(plan);
    rank_nets(plan, nets);

    plan.groups = count_groups(plan);
    debug_assert!(plan.groups <= devices, "reduction invented a device");
    // One direction only: a parallel merge consumes nothing, so the converse is
    // false.
    debug_assert!(
        (plan.nets == nets) || (plan.groups < devices),
        "a net was consumed without a merge"
    );
    plan.groups < devices
}

/// The per-row columns every later pass reads: the merge mask, the terminal keys
/// and the port mask.
fn prepare(src: &Graph, plan: &mut Plan, devices: usize, nets: usize) {
    plan.root.clear();
    plan.root.extend(0..narrow(devices));
    plan.consumed.clear();
    plan.consumed.resize(nets, false);
    plan.series.clear();

    plan.is_port.clear();
    plan.is_port.resize(nets, false);
    for &net in &src.port_net {
        debug_assert!((net as usize) < nets, "port names net {net} of {nets}");
        plan.is_port[net as usize] = true;
    }

    plan.key.clear();
    plan.key.reserve(src.terminal_net.len());
    plan.key_start.clear();
    plan.key_start.reserve(devices + 1);
    plan.key_start.push(0);
    plan.mergeable.clear();
    plan.mergeable.reserve(devices);
    for device in 0..narrow(devices) {
        let (terminal_nets, roles) = src.terminals_of(device);
        let from = plan.key.len();
        for slot in 0..roles.len() {
            plan.key
                .push(terminal_key(roles[slot], terminal_nets[slot]));
        }
        plan.key[from..].sort_unstable();
        plan.key_start.push(narrow(plan.key.len()));

        // Both refusals are stated in the module comment.
        let free = src.params_of(device).is_empty();
        let bound = !terminal_nets.contains(&u32::MAX);
        plan.mergeable.push(free & bound);
    }
    debug_assert_eq!(plan.key_start.len(), devices + 1);
    debug_assert_eq!(plan.mergeable.len(), devices);
}

/// Join every run of devices whose whole terminal map agrees.
///
/// Keyed on `(kind, model, terminal keys)` with the device row as final
/// tie-break, so the partition is independent of row order. An unmergeable device
/// is left out of every join rather than breaking the run it sits in.
fn join_parallel(src: &Graph, plan: &mut Plan, devices: usize) {
    let Plan {
        root,
        order,
        mergeable,
        key,
        key_start,
        ..
    } = plan;
    order.clear();
    order.extend(0..narrow(devices));
    order.sort_unstable_by(|&a, &b| {
        parallel_key(src, key_start, key, a)
            .cmp(&parallel_key(src, key_start, key, b))
            .then(a.cmp(&b))
    });

    // Walk the runs, joining each run's mergeable rows to the first of them.
    let mut at = 0usize;
    while at < order.len() {
        let head = parallel_key(src, key_start, key, order[at]);
        let mut end = at + 1;
        while end < order.len() && parallel_key(src, key_start, key, order[end]) == head {
            end += 1;
        }
        // The first mergeable row of the run anchors it, so an unmergeable row
        // anywhere in the run is skipped rather than splitting it.
        let mut anchor = u32::MAX;
        for &device in &order[at..end] {
            if !mergeable[device as usize] {
                continue;
            }
            if anchor == u32::MAX {
                anchor = device;
            } else {
                join(root, anchor, device);
            }
        }
        at = end;
    }
}

/// Join every pair of devices that meet at a node nothing else can reach.
///
/// Every condition is read off the graph as given, so all the joins are decided
/// before any is made, which is what folds a chain of three in one pass.
fn join_series(src: &Graph, plan: &mut Plan, nets: usize) {
    // Every guard is a *refusal* to merge, which is the direction the module
    // comment fixes.
    for net in 0..narrow(nets) {
        let on = src.terminals_on(net);
        if on.len() != 2 {
            continue;
        }
        let ((first, first_role), (second, second_role)) = (on[0], on[1]);
        // Merging across a named or probed node destroys the thing a human asked
        // about.
        if plan.is_port[net as usize] || src.net_name[net as usize].is_some() {
            continue;
        }
        // Two terminals of *one* device on a node is a shorted device, not a
        // series pair, and there is nothing to join it to.
        if first == second {
            continue;
        }
        if !(is_channel(first_role) & is_channel(second_role)) {
            continue;
        }
        if !(plan.mergeable[first as usize] & plan.mergeable[second as usize]) {
            continue;
        }
        if (src.device_kind[first as usize] != src.device_kind[second as usize])
            || (src.device_model[first as usize] != src.device_model[second as usize])
        {
            continue;
        }
        let (first_fixed, first_channel) = split_keys(keys(&plan.key_start, &plan.key, first));
        let (second_fixed, second_channel) = split_keys(keys(&plan.key_start, &plan.key, second));
        // Every terminal outside the channel has to agree, and there has to be
        // one: two channel ends and nothing else is a two-terminal element whose
        // series law is not `L` adding.
        if first_fixed.is_empty() || (first_fixed != second_fixed) {
            continue;
        }
        // Exactly two channel ends each, or "the other end" below is not one
        // thing.
        if (first_channel.len() != 2) || (second_channel.len() != 2) {
            continue;
        }
        // Without this, two devices in **parallel** read as in series through
        // either net they share, and the merge consumes a net both are still on.
        if other_end(first_channel, net) == other_end(second_channel, net) {
            continue;
        }
        join(&mut plan.root, first, second);
        plan.series.push((net, first, second));
    }
}

/// The net at the far end of a two-terminal channel from `net`. A device with
/// both ends on `net` answers `net`, which is what the parallel guard rejects on.
fn other_end(channel: &[u64], net: u32) -> u32 {
    debug_assert_eq!(channel.len(), 2, "a channel has two ends");
    let (low, high) = (key_net(channel[0]), key_net(channel[1]));
    if low == net {
        high
    } else {
        low
    }
}

/// Sort device rows into `(root, index)` order, so each group is a run.
fn order_by_group(plan: &mut Plan, devices: usize) {
    // Roots resolved into the column first, so the sort key is a plain load.
    for device in 0..narrow(devices) {
        let head = find(&mut plan.root, device);
        plan.root[device as usize] = head;
    }
    let Plan { root, order, .. } = plan;
    order.clear();
    order.extend(0..narrow(devices));
    order.sort_unstable_by_key(|&device| (root[device as usize], device));
}

/// Break up any group that would not produce a well-formed device.
///
/// The joins are pairwise and their transitive closure is not: three transistors
/// in a ring with tied gates are three legal series pairs whose group consumes
/// all three nodes and leaves a device with no channel. Dissolving a group cannot
/// affect another — a consumed net's two terminals are both inside one group.
fn dissolve_invalid(src: &Graph, plan: &mut Plan) {
    // `plan_into` rebuilds this from `series` afterwards.
    mark_consumed(plan);

    let mut at = 0usize;
    while at < plan.order.len() {
        let root = plan.root[plan.order[at] as usize];
        let mut end = at + 1;
        while end < plan.order.len() && plan.root[plan.order[end] as usize] == root {
            end += 1;
        }
        // A group of one is always well-formed: it is the device it started as.
        if end - at > 1 && !group_is_sound(src, plan, at, end) {
            for index in at..end {
                let device = plan.order[index];
                plan.root[device as usize] = device;
            }
        }
        at = end;
    }
}

/// Whether one group's members really are one device: same kind and model, same
/// non-channel terminals, and as many surviving channel ends as one member has.
fn group_is_sound(src: &Graph, plan: &Plan, from: usize, to: usize) -> bool {
    let head = plan.order[from];
    let (head_fixed, head_channel) = split_keys(keys(&plan.key_start, &plan.key, head));
    let head_kind = src.device_kind[head as usize];
    let head_model = src.device_model[head as usize];

    // A member carrying more than two channel ends is malformed, and that is a
    // refusal rather than an assert: `Graph`'s columns are public.
    let mut seen: [u32; 2] = [u32::MAX; 2];
    if head_channel.len() > seen.len() {
        return false;
    }

    let mut survivors = 0usize;
    for index in from..to {
        let device = plan.order[index];
        let (fixed, channel) = split_keys(keys(&plan.key_start, &plan.key, device));
        if (src.device_kind[device as usize] != head_kind)
            || (src.device_model[device as usize] != head_model)
        {
            return false;
        }
        if (fixed != head_fixed) || (channel.len() != head_channel.len()) {
            return false;
        }
        for &key in channel {
            let net = key_net(key);
            // A swallowed net, or one already standing for a surviving end, is
            // not a new end.
            if plan.consumed[net as usize] || seen.contains(&net) {
                continue;
            }
            if survivors == seen.len() {
                return false;
            }
            seen[survivors] = net;
            survivors += 1;
        }
    }
    survivors == head_channel.len()
}

/// Mark every candidate net whose two devices ended up in one group.
fn mark_consumed(plan: &mut Plan) {
    plan.consumed.iter_mut().for_each(|dead| *dead = false);
    for &(net, first, second) in &plan.series {
        plan.consumed[net as usize] |= plan.root[first as usize] == plan.root[second as usize];
    }
}

/// Rank the surviving nets, ascending, into `new_net`.
fn rank_nets(plan: &mut Plan, nets: usize) {
    plan.new_net.clear();
    plan.new_net.reserve(nets);
    let mut rank = 0u32;
    // Always store, conditionally advance.
    for net in 0..nets {
        let live = !plan.consumed[net];
        plan.new_net.push(if live { rank } else { u32::MAX });
        rank += u32::from(live);
    }
    plan.nets = rank as usize;
    debug_assert!(plan.nets <= nets, "reduction invented a net");
}

/// The number of distinct roots, read off the sorted order.
fn count_groups(plan: &Plan) -> usize {
    let mut groups = 0usize;
    let mut last = u32::MAX;
    for &device in &plan.order {
        let head = plan.root[device as usize];
        groups += usize::from(head != last);
        last = head;
    }
    groups
}

/// Write the planned graph into `out`, rebuilding the net-side incidence through
/// `graph::transpose_into` so the two directions cannot disagree.
fn emit_into(src: &Graph, plan: &Plan, out: &mut Graph) {
    let nets = src.net_count();
    debug_assert_eq!(
        plan.new_net.len(),
        nets,
        "the plan ranked another graph's nets"
    );

    out.net_name.clear();
    out.net_name.reserve(plan.nets);
    for net in 0..nets {
        // A consumed net is never named, so dropping the row loses no name.
        debug_assert!(
            !plan.consumed[net] || src.net_name[net].is_none(),
            "a named node was consumed"
        );
        if !plan.consumed[net] {
            out.net_name.push(src.net_name[net]);
        }
    }
    debug_assert_eq!(out.net_name.len(), plan.nets);

    out.port_net.clear();
    out.port_net.reserve(src.port_net.len());
    for &net in &src.port_net {
        debug_assert!(!plan.consumed[net as usize], "a port net was consumed");
        out.port_net.push(plan.new_net[net as usize]);
    }

    out.device_kind.clear();
    out.device_kind.reserve(plan.groups);
    out.device_model.clear();
    out.device_model.reserve(plan.groups);
    out.terminal_net.clear();
    out.terminal_role.clear();
    out.device_terminal_start.clear();
    out.device_terminal_start.reserve(plan.groups + 1);
    out.device_terminal_start.push(0);
    out.param.clear();
    out.device_param_start.clear();
    out.device_param_start.reserve(plan.groups + 1);
    out.device_param_start.push(0);

    let mut merged: Vec<(TerminalRole, u32)> = Vec::new();
    let mut at = 0usize;
    while at < plan.order.len() {
        let head = plan.order[at];
        let root = plan.root[head as usize];
        let mut end = at + 1;
        while end < plan.order.len() && plan.root[plan.order[end] as usize] == root {
            end += 1;
        }
        debug_assert_eq!(head, root, "a group's first row is not its root");

        out.device_kind.push(src.device_kind[head as usize]);
        out.device_model.push(src.device_model[head as usize]);
        if end - at == 1 {
            // A group of one is the device it started as, which is what makes an
            // unreducible graph come through byte-identical.
            let (terminal_nets, roles) = src.terminals_of(head);
            for slot in 0..roles.len() {
                out.terminal_net
                    .push(remap(&plan.new_net, terminal_nets[slot]));
                out.terminal_role.push(roles[slot]);
            }
            out.param.extend_from_slice(src.params_of(head));
        } else {
            merge_terminals(src, plan, at, end, &mut merged);
            for &(role, net) in &merged {
                out.terminal_net.push(plan.new_net[net as usize]);
                out.terminal_role.push(role);
            }
            // Every member is `mergeable`, and `mergeable` is `params_of` empty.
            debug_assert!(
                (at..end).all(|index| src.params_of(plan.order[index]).is_empty()),
                "a merged device carried a parameter it cannot have added"
            );
        }
        out.device_terminal_start
            .push(narrow(out.terminal_net.len()));
        out.device_param_start.push(narrow(out.param.len()));
        at = end;
    }
    debug_assert_eq!(
        out.device_kind.len(),
        plan.groups,
        "a group lost its device"
    );

    transpose_into(out, plan.nets);

    debug_assert_eq!(out.device_count(), plan.groups);
    debug_assert_eq!(out.net_count(), plan.nets);
    debug_assert_eq!(
        out.terminal_role.len(),
        out.terminal_net.len(),
        "a terminal lost its role"
    );
}

/// A net through the pass's renumbering, with a terminal on no net left alone:
/// dropping `u32::MAX` would hide the fault `checks::check_topology` reports, and
/// mapping it onto a real net would invent a connection.
fn remap(new_net: &[u32], net: u32) -> u32 {
    match new_net.get(net as usize) {
        Some(&mapped) => mapped,
        None => u32::MAX,
    }
}

/// One merged device's terminals, in `(role_code, net)` order: the
/// representative's non-channel terminals plus one per surviving channel net.
fn merge_terminals(
    src: &Graph,
    plan: &Plan,
    from: usize,
    to: usize,
    out: &mut Vec<(TerminalRole, u32)>,
) {
    out.clear();
    let head = plan.order[from];
    let (head_nets, head_roles) = src.terminals_of(head);
    for slot in 0..head_roles.len() {
        if !is_channel(head_roles[slot]) {
            out.push((head_roles[slot], head_nets[slot]));
        }
    }
    let fixed = out.len();

    for index in from..to {
        let device = plan.order[index];
        let (terminal_nets, roles) = src.terminals_of(device);
        for slot in 0..roles.len() {
            let net = terminal_nets[slot];
            let fresh = is_channel(roles[slot])
                && !plan.consumed[net as usize]
                && !out[fixed..].iter().any(|&(_, taken)| taken == net);
            if fresh {
                out.push((roles[slot], net));
            }
        }
    }

    out.sort_unstable_by_key(|&(role, net)| (role_code(role), net));
    debug_assert!(
        out.windows(2).all(|pair| pair[0] != pair[1]),
        "a merged device carries one terminal twice"
    );
}
