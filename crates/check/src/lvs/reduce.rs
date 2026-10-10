//! Series and parallel reduction to a fixed point, run on both sides.
//!
//! Data in/out: a [`Graph`]. Under-reduction is safe, over-reduction is not, so
//! every condition is what must hold before a merge.
//!
//! A merge keeps what it combines, by the device's law:
//!
//! | Kind | Parallel | Series | `m` |
//! |---|---|---|---|
//! | MOS | sums `W` and `nf`; every other parameter, `L` included, agrees | sums `L`; every other parameter agrees | folded into `W` |
//! | resistor, capacitor, diode, bipolar | sums the count `m` (1 when the card states none); every other parameter agrees | never | kept: that many in parallel |
//!
//! "Agrees" means the same parameter names with bit-identical values: the
//! comparison's tolerance plays no part here. A summed parameter must be
//! stated by every member or by none, so no member's share is dropped. A sized
//! MOS merges only when [`ParamNames`] says which parameter is `W` and which
//! is `L`, and any other device only when it names `m`, the parameter its
//! count is kept in. A passive's value is kept, not combined: two capacitors
//! of one `c` in parallel are one of that `c` with `m = 2`, as a card stating
//! `m = 2` is, and do not match one card of twice the `c`.
//!
//! - **Parallel** (catalog LVS-040, LVS-043, LVS-044; KLayout and Netgen both
//!   do it): devices of one kind and one model whose terminals land on the
//!   same nets role for role become one, with the first's terminals. MOS
//!   source and drain are interchangeable, and so are a resistor's ends; a
//!   diode's or capacitor's pins are not. A MOS whose source and drain share
//!   a net merges like any other. This applies to every device kind and
//!   consumes no net.
//! - **Series** (catalog LVS-041; on by default, which Netgen's is not): two
//!   devices of one kind and one model whose channels (`Source`/`Drain`) meet
//!   at a net carrying exactly those two terminals, with every other terminal
//!   on the same nets (gates strapped, one bulk; catalog LVS-045) and at least
//!   one such terminal, become one. The shared net must not be a port, and
//!   is consumed; a name alone does not protect it, since every reference
//!   net is named. [`compare`](crate::lvs::compare) makes a reference net a
//!   port when a layout label names it, so a labelled node stops the merge on
//!   both sides. In practice only MOS have a channel.
//! - **Multiplier** (catalog LVS-046): with both the `W` and `m` names given,
//!   each MOS's `W` is multiplied by its `m` and the `m` is dropped, before
//!   any merge. A MOS with no `W`, and every other device, keeps its `m`,
//!   except an `m` of 1, which is dropped as the count every card has.
//!
//! A device with a terminal on no net never merges. Each pass applies one law
//! to the whole graph, parallel first, so every sum within a pass is well
//! defined. Passes repeat until neither law merges anything, and a later pass
//! may merge a merged device again: a series stack, then two such stacks in
//! parallel. Resistors, capacitors and diodes are never merged in series
//! (catalog LVS-043, LVS-044).

use crate::topology::TerminalRole;
use gpurify_ingest::StrId;

/// Which interned parameter names mean width, length, fingers and multiplier.
/// A name absent from both netlists is `None`.
///
/// The default names nothing, and then a MOS that declares any parameter, and
/// every other device, never merges.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParamNames {
    /// `W`: summed by a parallel MOS merge, multiplied by `m`. With `length`,
    /// it lets sized MOS merge at all.
    pub width: Option<StrId>,
    /// `L`: summed by a series merge. With `width`, it lets sized MOS merge
    /// at all.
    pub length: Option<StrId>,
    /// `nf`: summed by a parallel MOS merge.
    pub fingers: Option<StrId>,
    /// `m`: a MOS's is folded into its `W`, when `width` is also named and
    /// the MOS states one. Any other device's is its count of identical
    /// devices in parallel, which a parallel merge sums; without this name
    /// they do not merge, since the count would have nowhere to go.
    pub multiplier: Option<StrId>,
}

/// Which law a merge applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeKind {
    /// Devices on the same nets became one: a MOS's `W` and `nf` were summed
    /// (and an unsized one's `m`), any other device's count `m`.
    Parallel,
    /// Devices stacked through an internal net became one; `L` was summed and
    /// the net was consumed.
    Series,
}

/// One merge, for the report: the input devices that became one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merge {
    /// The law applied.
    pub kind: MergeKind,
    /// The model of every device merged.
    pub model: StrId,
    /// Device rows of the graph `reduce` was given, ascending.
    ///
    /// Rows of the input, not of an intermediate pass, so a device merged
    /// twice lists every row it stands for in both merges.
    pub devices: Vec<u32>,
}

/// A parameter list as `(name, bits)` ascending: what must agree for a merge
/// that sums the `summed` names. A summed parameter keeps its name with its
/// value blanked, so it must be stated by both or neither; `ignored` is left
/// out, so it need not be.
fn signature(
    params: &[(StrId, f64)],
    summed: &[Option<StrId>],
    ignored: Option<StrId>,
) -> Vec<(StrId, u64)> {
    let mut out: Vec<(StrId, u64)> = params
        .iter()
        .filter(|(name, _)| Some(*name) != ignored)
        .map(|&(name, value)| {
            let bits = if summed.contains(&Some(name)) {
                0
            } else {
                value.to_bits()
            };
            (name, bits)
        })
        .collect();
    out.sort_unstable();
    out
}

use crate::lvs::graph::{narrow, transpose_into, Graph};
use crate::lvs::refine::{kind_code, role_code};
use gpurify_ingest::deck::DeviceKind;

/// The parameters a parallel merge of `kind` sums, each stated by every member
/// or by none: a MOS's `W`, `nf`, and the `m` only one with no `W` keeps.
/// Any other kind sums its count `m` instead, which [`count_of`] reads.
fn parallel_sums(kind: DeviceKind, names: ParamNames) -> [Option<StrId>; 3] {
    match kind {
        DeviceKind::Mos => [names.width, names.fingers, names.multiplier],
        _ => [None; 3],
    }
}

/// A device's count: its `m`, or 1 when it states none.
fn count_of(params: &[(StrId, f64)], multiplier: StrId) -> f64 {
    params
        .iter()
        .find(|(name, _)| *name == multiplier)
        .map_or(1.0, |&(_, m)| m)
}

/// The two ends of a MOS channel, which are what a merge exchanges, consumes and
/// counts. Every other role is fixed furniture.
const fn is_channel(role: TerminalRole) -> bool {
    matches!(role, TerminalRole::Source | TerminalRole::Drain)
}

/// The merge code the channel collapses onto, past every value [`role_code`]
/// returns (at most 16 + 255), which is what puts a device's channel terminals
/// at the end of its sorted key and lets the non-channel half be read off as a
/// prefix.
const CHANNEL: u64 = 1 << 16;

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
    /// Per device: the parameters a parallel merge needs equal (all but `W`,
    /// `nf`) and a series merge needs equal (all but `L`).
    parallel_sig: Vec<Vec<(StrId, u64)>>,
    series_sig: Vec<Vec<(StrId, u64)>>,
    /// Which law this pass applies.
    mode: Option<MergeKind>,
    /// Groups after dissolution — the device count the emission writes.
    groups: usize,
    /// Surviving nets — the net count the emission writes.
    nets: usize,
}

/// One device's terminal keys, ascending.
fn keys<'k>(key_start: &[u32], key: &'k [u64], device: u32) -> &'k [u64] {
    let from = key_start[device as usize] as usize;
    let to = key_start[device as usize + 1] as usize;
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
    signature: &'k [Vec<(StrId, u64)>],
    device: u32,
) -> (u64, StrId, &'k [u64], &'k [(StrId, u64)]) {
    (
        kind_code(src.device_kind[device as usize]),
        src.device_model[device as usize],
        keys(key_start, key, device),
        &signature[device as usize],
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
}

/// Reduce to series/parallel normal form, merging only MOS that state no
/// parameter: with no `m` name, no other kind has a count to keep.
/// Devices come out one per group ascending by the group's lowest row;
/// surviving nets keep their order. A graph with nothing to merge comes through
/// byte-identical.
///
/// Reducing a reduced graph changes nothing: the output is a fixed point.
///
/// # Panics
///
/// Panics, or reduces wrongly, when `src` breaks the [`Graph`] invariants.
pub fn reduce(src: &Graph) -> Graph {
    reduce_with(src, ParamNames::default()).0
}

/// [`reduce`], merging sized devices by `names`, and every merge it made, in
/// the order made.
///
/// With `names.multiplier` set, every MOS's `m` is folded into its `W` (when
/// `names.width` is set too) and every `m` of 1 is dropped, even when nothing
/// merges, so the output then differs from `src` in those parameters.
///
/// Each pass sorts every terminal, and each pass that merges anything removes
/// at least one device, so there are at most as many passes as devices.
///
/// # Panics
///
/// As [`reduce`].
pub fn reduce_with(src: &Graph, names: ParamNames) -> (Graph, Vec<Merge>) {
    let mut plan = Plan::default();
    let mut out = fold_multiplier(src, names);
    let mut spare = Graph::default();
    // `origin[d]`: the input rows output device `d` stands for, ascending.
    let mut origin: Vec<Vec<u32>> = (0..narrow(src.device_count())).map(|d| vec![d]).collect();
    let mut merges = Vec::new();
    // Each pass that changes anything drops a device, so this bound is never hit.
    for _ in 0..=2 * src.device_count() {
        let mode = if plan_into(&out, names, MergeKind::Parallel, &mut plan) {
            MergeKind::Parallel
        } else if plan_into(&out, names, MergeKind::Series, &mut plan) {
            MergeKind::Series
        } else {
            break;
        };
        let mut next = Vec::with_capacity(plan.groups);
        let mut at = 0usize;
        while at < plan.order.len() {
            let root = plan.root[plan.order[at] as usize];
            let mut end = at + 1;
            while end < plan.order.len() && plan.root[plan.order[end] as usize] == root {
                end += 1;
            }
            let mut rows: Vec<u32> = plan.order[at..end]
                .iter()
                .flat_map(|&d| origin[d as usize].iter().copied())
                .collect();
            rows.sort_unstable();
            if end - at > 1 {
                merges.push(Merge {
                    kind: mode,
                    model: out.device_model[plan.order[at] as usize],
                    devices: rows.clone(),
                });
            }
            next.push(rows);
            at = end;
        }
        origin = next;
        emit_into(&out, &plan, names, &mut spare);
        std::mem::swap(&mut out, &mut spare);
    }
    (out, merges)
}

/// Each MOS's `m` folded into its `W`: `m` devices in parallel are one of `m`
/// times the width. Every other `m` is kept as the device's count, except an
/// `m` of 1, which every card has and is dropped so that stating it or not is
/// one device. Untouched without the `m` name.
fn fold_multiplier(src: &Graph, names: ParamNames) -> Graph {
    let Some(multiplier) = names.multiplier else {
        return src.clone();
    };
    let mut out = src.clone();
    out.param.clear();
    out.device_param_start.clear();
    out.device_param_start.push(0);
    for device in 0..narrow(src.device_count()) {
        let params = src.params_of(device);
        let m = count_of(params, multiplier);
        let into = names.width.filter(|&width| {
            src.device_kind[device as usize] == DeviceKind::Mos
                && params.iter().any(|&(name, _)| name == width)
        });
        for &(name, value) in params {
            if name == multiplier {
                // Folded, or a count of one: nothing left to say.
                #[expect(clippy::float_cmp, reason = "1 is the count a card states exactly")]
                if into.is_none() && m != 1.0 {
                    out.param.push((name, value));
                }
            } else if Some(name) == into {
                out.param.push((name, value * m));
            } else {
                out.param.push((name, value));
            }
        }
        out.device_param_start.push(narrow(out.param.len()));
    }
    out
}

/// Decide one pass: which devices are one device, and which nets die with them.
/// Returns whether anything merged, which is the fixed-point test.
fn plan_into(src: &Graph, names: ParamNames, mode: MergeKind, plan: &mut Plan) -> bool {
    let devices = src.device_count();
    let nets = src.net_count();

    prepare(src, names, plan, devices, nets);
    plan.mode = Some(mode);
    match mode {
        MergeKind::Parallel => join_parallel(src, plan, devices),
        MergeKind::Series => join_series(src, plan, nets),
    }

    // Groups, then validation, then the net renumbering: a group that does not
    // survive validation must not take its nets with it. A parallel group needs
    // none: its members share the head's every terminal key, so it is the head,
    // even one whose source and drain share a net (testing-plan F57).
    order_by_group(plan, devices);
    if mode == MergeKind::Series {
        dissolve_invalid(src, plan);
        order_by_group(plan, devices);
    }
    mark_consumed(plan);
    rank_nets(plan, nets);

    plan.groups = count_groups(plan);
    // One direction only: a parallel merge consumes nothing, so the converse is
    // false.
    plan.groups < devices
}

/// The per-row columns every later pass reads: the merge mask, the terminal keys
/// and the port mask.
fn prepare(src: &Graph, names: ParamNames, plan: &mut Plan, devices: usize, nets: usize) {
    plan.root.clear();
    plan.root.extend(0..narrow(devices));
    plan.consumed.clear();
    plan.consumed.resize(nets, false);
    plan.series.clear();

    plan.is_port.clear();
    plan.is_port.resize(nets, false);
    for &net in &src.port_net {
        plan.is_port[net as usize] = true;
    }

    plan.key.clear();
    plan.key.reserve(src.terminal_net.len());
    plan.key_start.clear();
    plan.key_start.reserve(devices + 1);
    plan.key_start.push(0);
    plan.mergeable.clear();
    plan.mergeable.reserve(devices);
    plan.parallel_sig.clear();
    plan.series_sig.clear();
    for device in 0..narrow(devices) {
        let (terminal_nets, roles) = src.terminals_of(device);
        let from = plan.key.len();
        for slot in 0..roles.len() {
            plan.key
                .push(terminal_key(roles[slot], terminal_nets[slot]));
        }
        plan.key[from..].sort_unstable();
        plan.key_start.push(narrow(plan.key.len()));

        // Every refusal is stated in the module comment.
        let params = src.params_of(device);
        let kind = src.device_kind[device as usize];
        let sized = names.width.is_some() && names.length.is_some();
        let free = match kind {
            DeviceKind::Mos => params.is_empty() || sized,
            _ => names.multiplier.is_some(),
        };
        let bound = !terminal_nets.contains(&u32::MAX);
        plan.mergeable.push(free & bound);
        let counted = names.multiplier.filter(|_| kind != DeviceKind::Mos);
        plan.parallel_sig
            .push(signature(params, &parallel_sums(kind, names), counted));
        plan.series_sig
            .push(signature(params, &[names.length], None));
    }
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
        parallel_sig,
        ..
    } = plan;
    order.clear();
    order.extend(0..narrow(devices));
    order.sort_unstable_by(|&a, &b| {
        parallel_key(src, key_start, key, parallel_sig, a)
            .cmp(&parallel_key(src, key_start, key, parallel_sig, b))
            .then(a.cmp(&b))
    });

    // Walk the runs, joining each run's mergeable rows to the first of them.
    let mut at = 0usize;
    while at < order.len() {
        let head = parallel_key(src, key_start, key, parallel_sig, order[at]);
        let mut end = at + 1;
        while end < order.len()
            && parallel_key(src, key_start, key, parallel_sig, order[end]) == head
        {
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
        // A port is a node someone outside can reach, so it is not internal. A
        // name alone does not stop the merge: every reference net has one, and
        // the layout's would not (testing-plan F12).
        if plan.is_port[net as usize] {
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
            || (plan.series_sig[first as usize] != plan.series_sig[second as usize])
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

/// Break up any series group that would not produce a well-formed device.
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

/// Whether one series group's members really are one device: same kind and model, same
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
fn emit_into(src: &Graph, plan: &Plan, names: ParamNames, out: &mut Graph) {
    let nets = src.net_count();

    out.net_name.clear();
    out.net_name.reserve(plan.nets);
    for net in 0..nets {
        // A consumed net is never named, so dropping the row loses no name.
        if !plan.consumed[net] {
            out.net_name.push(src.net_name[net]);
        }
    }

    out.port_net.clear();
    out.port_net.reserve(src.port_net.len());
    for &net in &src.port_net {
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

        out.device_kind.push(src.device_kind[head as usize]);
        out.device_model.push(src.device_model[head as usize]);
        if end - at == 1 || plan.mode == Some(MergeKind::Parallel) {
            // A group of one is the device it started as, which is what makes an
            // unreducible graph come through byte-identical; a parallel group's
            // members all have the head's terminals.
            let (terminal_nets, roles) = src.terminals_of(head);
            for slot in 0..roles.len() {
                out.terminal_net.push(
                    plan.new_net
                        .get(terminal_nets[slot] as usize)
                        .copied()
                        .unwrap_or(u32::MAX),
                );
                out.terminal_role.push(roles[slot]);
            }
        } else {
            merge_terminals(src, plan, at, end, &mut merged);
            for &(role, net) in &merged {
                out.terminal_net.push(plan.new_net[net as usize]);
                out.terminal_role.push(role);
            }
        }
        if end - at == 1 {
            out.param.extend_from_slice(src.params_of(head));
        } else {
            // The head's parameters, the summed ones totalled over the group,
            // which states each of them on every member or on none.
            let kind = src.device_kind[head as usize];
            let group = &plan.order[at..end];
            let summed = match plan.mode {
                Some(MergeKind::Series) => [names.length, None, None],
                _ => parallel_sums(kind, names),
            };
            // Any kind but MOS keeps its count in `m`, which a card may leave
            // out: summed with a missing one read as 1, and written last.
            let counted = names
                .multiplier
                .filter(|_| plan.mode == Some(MergeKind::Parallel) && kind != DeviceKind::Mos);
            for &(name, value) in src.params_of(head) {
                if Some(name) == counted {
                    continue;
                }
                let total = if summed.contains(&Some(name)) {
                    group
                        .iter()
                        .flat_map(|&d| src.params_of(d))
                        .filter(|(other, _)| *other == name)
                        .map(|&(_, v)| v)
                        .sum()
                } else {
                    value
                };
                out.param.push((name, total));
            }
            if let Some(multiplier) = counted {
                let count = group
                    .iter()
                    .map(|&d| count_of(src.params_of(d), multiplier))
                    .sum();
                out.param.push((multiplier, count));
            }
        }
        out.device_terminal_start
            .push(narrow(out.terminal_net.len()));
        out.device_param_start.push(narrow(out.param.len()));
        at = end;
    }

    transpose_into(out, plan.nets);
}

/// One series-merged device's terminals, in `(role_code, net)` order: the
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
}
