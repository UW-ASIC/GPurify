//! Series and parallel device reduction: the netlist transformation that sits on
//! top of a correct extraction.
//!
//! # Why this exists
//!
//! `topology` recognises one device per marker polygon, which is the only thing
//! geometry can say. A human draws two fingers of one transistor and a schematic
//! writes one card, and both are right; nothing between them reconciles the two.
//! That is finding F5, and `LVS_SERIES_MERGE` and `LVS_PARALLEL_MERGE` state it
//! twice — each extracts two devices where the reference declares one, with a
//! correct extraction on one side and a correct netlist on the other.
//!
//! # Both sides, or the reduction decides the verdict
//!
//! [`reduce_into`] runs over the layout graph *and* the reference graph, because
//! either may be written unreduced. Reducing only the layout would mean a
//! reference written as two parallel cards no longer matched a layout drawn as
//! two fingers — the transform would be choosing the answer rather than
//! normalising the question.
//!
//! # Under-reduction is safe and over-reduction is not
//!
//! Everything here fails towards *not* merging. A merge that should have happened
//! and did not leaves an extra device on one side, which [`compare`] reports as
//! [`Discrepancy::UnpairedDevice`] — a bad report, not a wrong one. A merge that
//! should not have happened deletes a device the design contains, and two
//! netlists differing by exactly that device then match. The crate's second doc
//! section forbids precisely that, so every condition below is written as what
//! must hold before a merge and never as what must hold before a refusal.
//!
//! # The merge conditions
//!
//! **Parallel.** Two devices of the same [`DeviceKind`] and model whose terminals
//! land on the same nets, with the channel read as a *set*: a MOS channel is
//! symmetric, so a device written source-first and one written drain-first are
//! the same device. `W` adds — see the parameter section below.
//!
//! **Series.** A net `N` joining two devices of the same kind and model, where
//! `N` carries exactly two terminals in total, one from each device, both of them
//! channel ends; `N` is neither a port nor named; every terminal *outside* the
//! channel agrees between the two devices, and there is at least one such
//! terminal — which is the tied gate, and the shared bulk with it; and the two
//! devices' other channel ends are on different nets, without which two devices
//! in **parallel** would read as being in series through either of the two nets
//! they share. `L` adds.
//!
//! The port-and-name condition is not optional. Merging across a node a human
//! named, probed or wired out of the cell destroys the thing they asked about,
//! and it is what makes `LVS_FINGERS` — `LVS_SERIES` minus the gate strap — stay
//! two devices.
//!
//! # Parameters are not carried, and that is deliberate
//!
//! A parallel merge adds `W` and a series merge adds `L`, and this transform can
//! do neither. [`Graph::param`] is `(StrId, f64)` — an *interned name* — and
//! nothing here is handed a `StrTable` to resolve one with, so `W`, `L` and `M`
//! are three indistinguishable `u32`s. `graph::from_layout_into` projects no
//! layout parameter at all (finding F8), so there is nothing to add on that side
//! either.
//!
//! **A device that declares any parameter therefore does not merge.** The
//! alternatives were both worse. Keeping one member's `W` writes a number into
//! the graph that is wrong by the finger count. Dropping the parameters makes a
//! merged reference declare nothing against a layout that declares nothing, which
//! is the zero-parameters-compared [`Verdict::Match`] that F8 exists to close.
//! Refusing fabricates nothing and is fail-closed in the direction above.
//!
//! ponytail: the upgrade path is one parameter and not a rewrite — a `&StrTable`
//! at this signature, or `DeviceParam` reaching [`Graph`] as a tag rather than as
//! a name, and then the additive column is identifiable and the sum is three
//! lines. It is worth taking the day `from_layout_into` measures `W`; today it
//! would only change which side of a mismatch the report blames.
//!
//! [`compare`]: crate::compare::compare
//! [`Discrepancy::UnpairedDevice`]: crate::verdict::Discrepancy::UnpairedDevice
//! [`Verdict::Match`]: crate::verdict::Verdict::Match

use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrId;
use gpurify_topology::TerminalRole;

use crate::graph::{narrow, transpose_into, Graph};
use crate::refine::role_code;

/// The two ends of a MOS channel, which are what a merge exchanges, consumes and
/// counts. Every other role is fixed furniture: a gate, a bulk, a bipolar's
/// emitter, either end of a symmetric two-terminal device.
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

/// [`role_code`] with the channel collapsed onto one value.
///
/// `role_code` keeps `Source` and `Drain` apart because `compare` must not treat
/// them as interchangeable while finding F4 is open. A *merge* is the one place
/// they genuinely are: which end of a channel is the source is decided by bias,
/// so two devices differing only in which end they call the source are one
/// device however the comparison later reads them.
const fn merge_code(role: TerminalRole) -> u64 {
    if is_channel(role) {
        CHANNEL
    } else {
        role_code(role)
    }
}

/// One terminal as a sortable `u64`: its merge code above its net.
///
/// Injective, so two keys are equal exactly when the role class and the net are.
/// A dangling terminal carries `u32::MAX` in the low half and is refused by
/// [`Plan::mergeable`] rather than here.
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
///
/// **Five questions.** In: a [`Graph`]. Out: a device-to-group map, a net
/// renumbering, and the merged device count. How many: one row per device and one
/// per net, so millions. Access pattern: built by three passes over the device
/// and net columns, then read once in emission order. Lifetime: one pass, and the
/// buffers are reused across the passes of one call. Parallelisable: the key
/// build is; the union-find is not, and does not need to be — it is
/// `O(devices · α)` against the emission's `O(terminals)`.
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
    /// no net. Both are refusals rather than oversights — see the module comment
    /// for the first, and `checks::check_topology` reports the second.
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
///
/// A free function over the two columns rather than a method on [`Plan`], so a
/// caller holding `&mut Plan` can read a key while writing a different column.
fn keys<'k>(key_start: &[u32], key: &'k [u64], device: u32) -> &'k [u64] {
    let from = key_start[device as usize] as usize;
    let to = key_start[device as usize + 1] as usize;
    debug_assert!(from <= to, "a key run runs backwards");
    &key[from..to]
}

/// The prefix of [`keys`] that is not the channel, and the suffix that is.
///
/// [`CHANNEL`] is the largest merge code, so the split is a `partition_point`
/// over a run of at most four and needs no second column.
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
/// The root of a set is its **lowest** device index: [`join`] always points the
/// higher root at the lower, so there is no rank column and the root doubles as
/// the group's canonical member. That is what makes the emission order below a
/// function of the input alone.
fn find(root: &mut [u32], device: u32) -> u32 {
    let mut at = device as usize;
    // Not a bulk loop: the trip count is the tree height, which path halving
    // keeps at a few even for a long chain of series merges.
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

/// Reduce a netlist to its series/parallel normal form.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled. `src` and
/// `out` are separate graphs, which is what lets the fixed-point loop below run a
/// pass over a graph the previous pass produced.
///
/// # What comes out
///
/// Devices are emitted one per group, in ascending order of the group's lowest
/// source row, so an unmerged device keeps its position relative to every other
/// unmerged device. Nets are emitted in ascending source order with the consumed
/// ones removed, so `port_net` stays in the order the reference declared it and
/// `net_name` keeps its rows. A group of one is copied terminal for terminal; a
/// merged group's terminals are sorted by `(role_code, net)`, which makes the
/// merged device independent of which member of its group was written first.
///
/// **A graph with nothing to merge comes through byte-identical**, column for
/// column: the plan is built first, and a plan that merges nothing takes the copy
/// path without reaching the emission code at all. That is what lets this sit
/// unconditionally in front of `compare`.
///
/// # Determinism
///
/// No hash container is used anywhere. Grouping is a union-find, whose partition
/// does not depend on the order the joins are made in, fed by a sort of device
/// rows with the row index as its final key and by a scan of nets in ascending
/// order. Every output order is stated above and is a function of the input's own
/// row order. Two runs over one graph are byte-identical, and exchanging two
/// devices of one group does not move the result.
///
/// # The iteration is bounded, and reaching the bound is a bug
///
/// A pass that changes anything merges at least two devices into one, so the
/// device count falls by at least one and `src.device_count()` passes cannot all
/// change something. The loop is bounded at exactly that, the bound is asserted
/// unreached, and a release build that somehow reached it hands back the
/// partially reduced graph — which is under-reduction, and safe in the direction
/// the module comment gives.
pub fn reduce_into(src: &Graph, out: &mut Graph) {
    let mut plan = Plan::default();

    if !plan_into(src, &mut plan) {
        copy_into(src, out);
        debug_assert_eq!(out, src, "the copy path is not a copy");
        return;
    }
    emit_into(src, &plan, out);

    // `Graph::default` allocates nothing, so the second buffer costs a stack
    // write on the common path, where one pass reaches the fixed point.
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
///
/// **Transform, A-to-B.** The identity path, and the reason "an unreducible graph
/// is passed through unchanged" is structural rather than argued.
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
///
/// **Transform.** Caller owns `plan`, cleared and refilled. Returns whether
/// anything merged at all, which is both the copy-path test and the fixed-point
/// test.
fn plan_into(src: &Graph, plan: &mut Plan) -> bool {
    let devices = src.device_count();
    let nets = src.net_count();

    prepare(src, plan, devices, nets);
    join_parallel(src, plan, devices);
    join_series(src, plan, nets);

    // Groups first, then validation, then the net renumbering — in that order,
    // because a group that does not survive validation must not take its nets
    // with it.
    order_by_group(plan, devices);
    dissolve_invalid(src, plan);
    order_by_group(plan, devices);
    mark_consumed(plan);
    rank_nets(plan, nets);

    plan.groups = count_groups(plan);
    debug_assert!(plan.groups <= devices, "reduction invented a device");
    // One direction only. A series merge consumes its node, so a consumed net
    // implies a merge; a *parallel* merge consumes nothing, so the converse does
    // not hold and asserting it would be asserting a falsehood.
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
    // A scatter, so the write address is the row's own value and the loop is
    // scalar by that fact about the data. `port_net` is hundreds of rows against
    // the millions the columns above are.
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
            plan.key.push(terminal_key(roles[slot], terminal_nets[slot]));
        }
        // One device's terminals, at most four (`checks::LEGAL_WIDTHS`), so this
        // is an insertion sort over a fixed tiny run and not a bulk sort.
        plan.key[from..].sort_unstable();
        plan.key_start.push(narrow(plan.key.len()));

        // Both refusals are stated in the module comment: a declared parameter
        // this transform cannot add, and a terminal on no net that
        // `check_topology` is already reporting. Neither is a bulk-loop branch —
        // `is_empty` and `contains` over a four-element run fold to a couple of
        // compares.
        let free = src.params_of(device).is_empty();
        let bound = !terminal_nets.contains(&u32::MAX);
        plan.mergeable.push(free & bound);
    }
    debug_assert_eq!(plan.key_start.len(), devices + 1);
    debug_assert_eq!(plan.mergeable.len(), devices);
}

/// Join every run of devices whose whole terminal map agrees.
///
/// The key is `(kind, model, terminal keys)`, and the terminal keys read the
/// channel as a set, so two devices across one pair of nets are one device
/// whichever end each calls its source. Sorting by that key with the device row
/// as the final tie-break is what makes the partition independent of row order:
/// the runs are the same sets whatever order the rows arrive in.
///
/// An unmergeable device is left out of every join rather than breaking the run
/// it sits in, so three identical devices of which the middle one declares a
/// parameter still merge the other two — and which two is not decided by where in
/// the run the parameter happened to sit.
fn join_parallel(src: &Graph, plan: &mut Plan, devices: usize) {
    let Plan { root, order, mergeable, key, key_start, .. } = plan;
    order.clear();
    order.extend(0..narrow(devices));
    // A comparator rather than a materialised key column: the key ends in a
    // slice of variable length, and sorting one `Vec<u32>` of row indices costs
    // a gather per compare against a second CSR column's construction.
    order.sort_unstable_by(|&a, &b| {
        parallel_key(src, key_start, key, a)
            .cmp(&parallel_key(src, key_start, key, b))
            .then(a.cmp(&b))
    });

    // Walk the runs, joining each run's mergeable rows to the first of them. Not
    // a bulk loop: the body branches on a run boundary, which is data-dependent
    // by construction, and a run of one — the common case in a real netlist —
    // takes neither side.
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
/// The scan is over nets in ascending order and every condition is read off the
/// graph as given, so all the joins are decided before any of them is made —
/// which is what lets a chain of three fall into one group in a single pass.
fn join_series(src: &Graph, plan: &mut Plan, nets: usize) {
    // Not a bulk loop: eight guards over a two-element run, and the taken side is
    // a union-find walk. Every guard is a *refusal* to merge, which is the
    // direction the module comment fixes.
    for net in 0..narrow(nets) {
        let on = src.terminals_on(net);
        if on.len() != 2 {
            continue;
        }
        let ((first, first_role), (second, second_role)) = (on[0], on[1]);
        // An internal node is one the design does not name and nothing outside
        // this cell can reach.
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
        // The tied gate, and the shared bulk with it: every terminal outside the
        // channel has to agree, and there has to be one. Two channel ends and
        // nothing else is a two-terminal element whose series law is not `L`
        // adding, so it is left alone.
        if first_fixed.is_empty() || (first_fixed != second_fixed) {
            continue;
        }
        // Exactly two channel ends each, or "the other end" below is not one
        // thing.
        if (first_channel.len() != 2) || (second_channel.len() != 2) {
            continue;
        }
        // Without this, two devices in **parallel** read as being in series
        // through either of the two nets they share: that net carries exactly two
        // channel terminals, one from each. The merge would then consume a net
        // both devices are still on, and hand back a transistor with one end.
        if other_end(first_channel, net) == other_end(second_channel, net) {
            continue;
        }
        join(&mut plan.root, first, second);
        plan.series.push((net, first, second));
    }
}

/// The net at the far end of a two-terminal channel from `net`.
///
/// A device with both channel ends on `net` answers `net`, which is what makes
/// the parallel guard above reject it rather than read past the run.
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
    // The roots are resolved into the column first: `find` needs `&mut` for the
    // path halving, and doing it here makes the sort key a plain load rather than
    // a tree walk per comparison.
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
/// # What can go wrong, and why a check rather than a ninth guard
///
/// The joins are pairwise and their transitive closure is not. Three transistors
/// wired in a ring with their gates tied are three legal series pairs whose group
/// consumes all three nodes and leaves a device with no channel at all, and the
/// same shape reachable through a mix of series and parallel joins is not
/// enumerable by staring at the pair conditions. So the group is built and then
/// *checked*, against the one thing a merged device has to be: the
/// representative's terminals, with the channel ends that survived standing in
/// for its own.
///
/// A group that fails is dissolved into its members, which is under-reduction and
/// safe. It cannot affect another group: a consumed net's two terminals are both
/// inside one group by construction, so groups are disjoint in nets as well as in
/// devices.
fn dissolve_invalid(src: &Graph, plan: &mut Plan) {
    // The mask this validation reads is the one the joins so far imply.
    // `plan_into` rebuilds it from `series` afterwards, against whatever roots
    // this leaves behind.
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

/// Whether one group's members really are one device.
///
/// Three claims, and all three are what the merge conditions were supposed to
/// have guaranteed: every member is the same kind of device with the same model,
/// every member carries the representative's non-channel terminals, and the
/// channel ends that were not consumed number exactly what one member's channel
/// does. Stated over the group rather than inferred from the pairs, which is the
/// whole point of checking rather than reasoning.
fn group_is_sound(src: &Graph, plan: &Plan, from: usize, to: usize) -> bool {
    let head = plan.order[from];
    let (head_fixed, head_channel) = split_keys(keys(&plan.key_start, &plan.key, head));
    let head_kind = src.device_kind[head as usize];
    let head_model = src.device_model[head as usize];

    // Two ends is what a channel has. A member carrying more is malformed, and a
    // malformed member is a refusal rather than an assert: `Graph`'s columns are
    // public and `checks::check_topology` is the thing that reports one.
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
            // A net the group swallowed, or one already standing for a surviving
            // end, is not a new end.
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
    // One iteration per candidate the series scan found, which is at most one per
    // net and in a real netlist far fewer.
    for &(net, first, second) in &plan.series {
        plan.consumed[net as usize] |=
            plan.root[first as usize] == plan.root[second as usize];
    }
}

/// Rank the surviving nets, ascending, into `new_net`.
fn rank_nets(plan: &mut Plan, nets: usize) {
    plan.new_net.clear();
    plan.new_net.reserve(nets);
    let mut rank = 0u32;
    // Always store, conditionally advance: the write is unconditional and the
    // rank carries the predicate, so the body holds no data-dependent branch.
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
    // A reduce over a sorted column: `groups += is_new`, no data-dependent branch
    // in the body.
    for &device in &plan.order {
        let head = plan.root[device as usize];
        groups += usize::from(head != last);
        last = head;
    }
    groups
}

/// Write the planned graph.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled. Reads `src`
/// and the plan; writes every column of `out`, and rebuilds the net-side
/// incidence through `graph::transpose_into` so the two directions cannot
/// disagree.
fn emit_into(src: &Graph, plan: &Plan, out: &mut Graph) {
    let nets = src.net_count();
    debug_assert_eq!(plan.new_net.len(), nets, "the plan ranked another graph's nets");

    out.net_name.clear();
    out.net_name.reserve(plan.nets);
    // A compact, and the payload is a cold side-table row rather than the
    // predicate's own value, so it stays scalar.
    for net in 0..nets {
        // A consumed net is never named — `join_series` refuses a named node — so
        // dropping the row loses no name.
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
            // A group of one is the device it started as, terminal for terminal
            // and parameter for parameter. That is what makes the byte-identity
            // of an unreducible graph structural rather than argued.
            let (terminal_nets, roles) = src.terminals_of(head);
            for slot in 0..roles.len() {
                out.terminal_net.push(remap(&plan.new_net, terminal_nets[slot]));
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
        out.device_terminal_start.push(narrow(out.terminal_net.len()));
        out.device_param_start.push(narrow(out.param.len()));
        at = end;
    }
    debug_assert_eq!(out.device_kind.len(), plan.groups, "a group lost its device");

    transpose_into(out, plan.nets);

    debug_assert_eq!(out.device_count(), plan.groups);
    debug_assert_eq!(out.net_count(), plan.nets);
    debug_assert_eq!(
        out.terminal_role.len(),
        out.terminal_net.len(),
        "a terminal lost its role"
    );
}

/// A net through the pass's renumbering, with a terminal on no net left alone.
///
/// `u32::MAX` is `NetId::NONE` projected. It indexes nothing, so it is passed
/// through rather than looked up — dropping it would hide the extraction fault
/// `checks::check_topology` reports, and mapping it onto a real net would invent
/// a connection.
fn remap(new_net: &[u32], net: u32) -> u32 {
    // The bounds test is the branch, and it predicts: a sound extraction takes
    // the hit side for every terminal in the design.
    match new_net.get(net as usize) {
        Some(&mapped) => mapped,
        None => u32::MAX,
    }
}

/// One merged device's terminals, in `(role_code, net)` order.
///
/// The representative's non-channel terminals verbatim — [`group_is_sound`] has
/// already established that every member carries the same ones — plus one
/// terminal per channel net that survived, taking its role from the first member
/// and slot that named it.
///
/// The sort is what makes a merged device independent of which member of its
/// group happened to be written first, and it keys on [`role_code`] rather than
/// [`merge_code`] so a source sorts ahead of a drain instead of tying with it. It
/// runs only for a merged group, so a group of one keeps the byte-identity above.
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
        // Four terminals at most per member and a handful of members, so the
        // linear scan over the ends already taken is the whole search structure
        // this needs.
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
