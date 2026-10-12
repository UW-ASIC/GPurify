//! Series and parallel reduction to a fixed point, run on both sides.
//!
//! Data in/out: a [`Graph`]. Under-reduction is safe, over-reduction is not, so
//! every condition is what must hold before a merge.
//!
//! A merge keeps what it combines, by the device's law:
//!
//! | Kind | Parallel | Series | `m` |
//! |---|---|---|---|
//! | MOS stating `W` | sums `W`, `nf` and the diffusions `as`, `ad`, `ps`, `pd`, each to its channel end; every other parameter, `L` included, agrees | sums `L`, which both state; every other parameter agrees; never with a diffusion stated | folded into `W` and the diffusions |
//! | MOS stating no `W` | sums the count `m` (1 when the card states none); every other parameter agrees | as above | kept: that many in parallel |
//! | resistor, capacitor, diode, bipolar, inductor | sums the count `m`; every other parameter agrees | never | kept |
//! | the same, stating its value, under [`ParamNames::relaxed`] | combines the value by its law (a resistor's `r` and an inductor's `ind` harmonically, `1 / Σ 1/r`; a capacitor's `c`, a diode's `area`, a bipolar's `ae` by adding) and adds `w` (a resistor's), `area`, `perim` and `pe`; every other parameter agrees | a resistor, capacitor or inductor only: the value by the opposite law (`r` and `ind` adding, `c` harmonically), adding `area`, `perim` and a resistor's `l`; every other parameter, a resistor's `w` included, agrees | folded into the value and what adds |
//!
//! "Agrees" means the same parameter names with bit-identical values: the
//! comparison's tolerance plays no part here. A summed parameter must be
//! stated by every member or by none, so no member's share is dropped. Each
//! law needs only the name of what it sums (testing-plan F84): a parallel
//! merge of MOS stating `W` needs [`ParamNames`] to name `W`, and any other
//! parallel merge, a MOS with no `W` to sum included, the `m` its count is
//! kept in, so two unsized transistors in parallel are one with `m = 2`, not
//! one transistor (testing-plan F83). A series merge needs `L` stated on both
//! devices: with no length to sum, two transistors in series would read as
//! one and the stack count would be lost, so they stay two (testing-plan
//! F67). A MOS's diffusions belong to its channel ends, so a parallel merge
//! adds each member's to the head's end on the same net, and one that states
//! some of the four and not all never merges; a series merge would swallow
//! the shared diffusion, and is refused (testing-plan F16). Under the strict
//! policy, the default, a passive's value is kept, not combined: two
//! capacitors of one `c` in parallel are one of that `c` with `m = 2`, as a
//! card stating `m = 2` is, and do not match one card of twice the `c`.
//!
//! - **Parallel** (catalog LVS-040, LVS-043, LVS-044; `KLayout` and Netgen both
//!   do it): devices of one kind and one model whose terminals land on the
//!   same nets role for role become one, with the first's terminals. MOS
//!   source and drain are interchangeable, and so are a resistor's ends; a
//!   diode's or capacitor's pins are not. A MOS whose source and drain share
//!   a net merges like any other. This applies to every device kind and
//!   consumes no net.
//!   Netgen's `l critical` merges parallel MOS whose `L` agree within its
//!   tolerance; here they must be bit-identical, the conservative side.
//! - **Series** (catalog LVS-041; on by default, while Netgen 1.5.323 never
//!   merges MOS in series, `series enable` notwithstanding): two
//!   devices of one kind and one model whose channels (`Source`/`Drain`) meet
//!   at a net carrying exactly those two terminals, with every other terminal
//!   on the same nets (gates strapped, one bulk; catalog LVS-045) and at least
//!   one such terminal, become one, their `L`s summed; a device stating no
//!   `L` never merges in series. The shared net must not be a port, and
//!   is consumed; a name alone does not protect it, since every reference
//!   net is named. [`compare`](crate::lvs::compare) makes a reference net a
//!   port when a layout label names it, so a labelled node stops the merge on
//!   both sides. In practice only MOS have a channel.
//! - **Relaxed topology** (catalog LVS-043, LVS-044, LVS-049; Netgen's
//!   `property topology relaxed`, "two networks may have different topology
//!   as long as they are numerically the same after series and parallel
//!   combinations"): with [`ParamNames::relaxed`], a resistor, capacitor,
//!   diode or bipolar that states its value (`r`, `c`, `area`, `ae`) merges
//!   in parallel by the value's law, so two capacitors of `c` are one of
//!   `2c` and two resistors of `r` one of `r/2`, as Kirchhoff's laws make
//!   them; its `m` is folded in first, `r/m` and `m` times the rest. One that
//!   states no value has nothing to combine and keeps its count. A
//!   resistor or capacitor stating its value also merges in series, with
//!   another of its model whose terminal is the only other one on a net
//!   that is no port, their far ends on two other nets: `r` and a
//!   resistor's `l` add, `c` combines harmonically, and `area` and `perim`
//!   add, as `KLayout`'s `ResistorDeviceCombiner::serial` and
//!   `CapacitorDeviceCombiner::serial` combine them; a resistor's `w`
//!   must agree, as Netgen's sky130 setup states `series {w critical}`
//!   (`KLayout` instead averages it by resistance, which for equal widths
//!   is the same). A capacitor's ordered plates must chain plate to plate;
//!   plates `lvs permute` joins may meet either way. A ring of passives,
//!   or a chain closing on one net, stays as drawn. Diodes and bipolars
//!   never merge in series, as neither tool merges them.
//! - **Logic gates** (catalog LVS-047): with [`ParamNames::gates`], once
//!   neither law merges anything, plain identical transistors in parallel
//!   or in series on different gates of their own become one device whose
//!   gates are interchangeable (Silvaco Guardian's reduction; the rules are
//!   the `gates` module's), and the laws run again.
//! - **Multiplier** (catalog LVS-046): with both the `W` and `m` names given,
//!   each MOS's `W` is multiplied by its `m` and the `m` is dropped, before
//!   any merge. A MOS with no `W`, and every other device, keeps its `m`,
//!   except an `m` of 1, which is dropped as the count every card has;
//!   [`compare`](crate::lvs::compare) reads a missing count as that 1 again.
//!
//! A device with a terminal on no net never merges. Each pass applies one law
//! to the whole graph, parallel first, so every sum within a pass is well
//! defined. Passes repeat until neither law merges anything, and a later pass
//! may merge a merged device again: a series stack, then two such stacks in
//! parallel. Resistors and capacitors merge in series only under the
//! relaxed policy, diodes and bipolars never (catalog LVS-043, LVS-044).

use crate::topology::TerminalRole;
use gpurify_ingest::StrId;

/// Which interned parameter names mean width, length, fingers and multiplier.
/// A name absent from both netlists is `None`.
///
/// The default names nothing, and then nothing merges: no device has a `W` to
/// sum or a count to keep, and nothing merges in series.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParamNames {
    /// `W`: summed by a parallel merge of MOS that state it, multiplied by
    /// `m`. Without it, no MOS has a `W` to sum and each keeps its count.
    pub width: Option<StrId>,
    /// `L`: summed by a series merge, which needs it stated on both devices,
    /// so without this name nothing merges in series.
    pub length: Option<StrId>,
    /// `nf`: summed by a parallel merge of MOS stating `W`.
    pub fingers: Option<StrId>,
    /// `m`: a MOS's is folded into its `W`, when `width` is also named and
    /// the MOS states one. Any other device's, a MOS with no `W` included,
    /// is its count of identical devices in parallel, which a parallel merge
    /// sums; without this name they do not merge in parallel, since the count
    /// would have nowhere to go.
    pub multiplier: Option<StrId>,
    /// `as`, `ad`, `ps` and `pd`, in that order: a MOS's source and drain
    /// diffusion area and perimeter. Each belongs to one end of the channel,
    /// so where source and drain trade places, `as` trades with `ad` and `ps`
    /// with `pd`.
    pub diffusion: [Option<StrId>; 4],
    /// `r`, `c`, `area`, `perim`, `ae` and `pe`, in that order: a passive's
    /// or bipolar's value and what adds with it under [`Self::relaxed`].
    pub values: [Option<StrId>; 6],
    /// `ind`: an inductor's inductance, which combines under
    /// [`Self::relaxed`] as a resistance does, `KLayout`'s
    /// `InductorDeviceCombiner` (catalog LVS-065).
    pub inductance: Option<StrId>,
    /// Whether plain transistors stacked in series, or set in parallel, on
    /// different gates of their own merge into one device whose gates are
    /// interchangeable, the reduction logic-gate recognition rests on
    /// (Silvaco Guardian's series and parallel reduction "with different
    /// gate terminals"; the deck's `lvs recognize_gates`; catalog LVS-047).
    /// Off by default: an analog stack's order is part of the circuit.
    pub gates: bool,
    /// Whether a resistor, capacitor, diode or bipolar stating its value
    /// merges in parallel by the value's law, and a resistor or capacitor
    /// in series by the opposite one, rather than keeping a count
    /// (Netgen's `property topology relaxed`; the deck's `lvs topology
    /// relaxed`). Off by default: the strict policy, where two devices are
    /// never one of a combined value.
    pub relaxed: bool,
}

/// How a relaxed parallel merge combines a passive's or bipolar's
/// parameters ([`ParamNames::relaxed`]): the value, whether it combines
/// harmonically (a resistance) or adds, and the others that add.
#[derive(Debug, Clone, Copy)]
struct Law {
    value: StrId,
    harmonic: bool,
    adds: [Option<StrId>; 3],
}

impl Law {
    /// The law for a device of `kind` stating `params`: `None` under the
    /// strict policy, for a MOS, and for a device that states no value.
    fn of(kind: DeviceKind, params: &[(StrId, f64)], names: ParamNames) -> Option<Self> {
        if !names.relaxed {
            return None;
        }
        let [r, c, area, perim, ae, pe] = names.values;
        let (value, harmonic, adds) = match kind {
            DeviceKind::Resistor => (r?, true, [names.width, area, perim]),
            DeviceKind::Capacitor => (c?, false, [area, perim, None]),
            DeviceKind::Diode => (area?, false, [perim, None, None]),
            DeviceKind::Bjt => (ae?, false, [pe, area, perim]),
            DeviceKind::Inductor => (names.inductance?, true, [None, None, None]),
            DeviceKind::Mos => return None,
        };
        params
            .iter()
            .any(|&(name, _)| name == value)
            .then_some(Self {
                value,
                harmonic,
                adds,
            })
    }

    /// Whether the law combines `name`.
    fn combines(self, name: StrId) -> bool {
        name == self.value || self.adds.contains(&Some(name))
    }

    /// `name`'s value for `m` devices of `value` in parallel.
    fn times(self, name: StrId, value: f64, m: f64) -> f64 {
        if self.harmonic && name == self.value {
            value / m
        } else {
            value * m
        }
    }

    /// The names a parallel merge under this law combines, as
    /// [`parallel_sums`] lists them.
    fn sums(self) -> [Option<StrId>; 6] {
        let [a, b, c] = self.adds;
        [Some(self.value), a, b, c, None, None]
    }

    /// The names a series merge of `kind` under this law combines: the
    /// value, by the law opposite the parallel one (a resistance adds, a
    /// capacitance combines harmonically), and `area` and `perim` adding,
    /// with a resistor's `l` (`KLayout`'s `ResistorDeviceCombiner::serial`
    /// and `CapacitorDeviceCombiner::serial`). A resistor's `w` is not
    /// among them, so it must agree (Netgen's `series {w critical}` in the
    /// sky130 setup). `None` for a kind that never merges in series.
    fn series_sums(self, kind: DeviceKind, names: ParamNames) -> Option<[Option<StrId>; 6]> {
        let [_, _, area, perim, _, _] = names.values;
        match kind {
            DeviceKind::Resistor => Some([Some(self.value), names.length, area, perim, None, None]),
            DeviceKind::Capacitor => Some([Some(self.value), area, perim, None, None, None]),
            DeviceKind::Inductor => Some([Some(self.value), None, None, None, None, None]),
            _ => None,
        }
    }
}

/// Whether `kind` is a passive a relaxed series merge takes: a resistor, a
/// capacitor or an inductor, two pins each.
const fn series_passive(kind: DeviceKind) -> bool {
    matches!(
        kind,
        DeviceKind::Resistor | DeviceKind::Capacitor | DeviceKind::Inductor
    )
}

impl ParamNames {
    /// The name at the channel's other end: `ad` for `as`, `pd` for `ps` and
    /// back; any other name is itself. `None` where that name is no name of
    /// the run, so no device states it.
    pub(crate) fn across(self, name: StrId) -> Option<StrId> {
        match self.diffusion.iter().position(|&d| d == Some(name)) {
            Some(at) => self.diffusion[at ^ 1],
            None => Some(name),
        }
    }

    /// The run's relative tolerance for the parameter `name`: `tolerance`,
    /// except a count, `m` or `nf`, which is a whole number and agrees only
    /// exactly (testing-plan F99), so zero. A deck's `lvs tolerance` row on
    /// the parameter replaces either.
    pub(crate) fn tolerance(self, name: StrId, tolerance: f64) -> f64 {
        if Some(name) == self.multiplier || Some(name) == self.fingers {
            0.0
        } else {
            tolerance
        }
    }

    /// How many of the four diffusion names `params` states.
    fn diffusions_in(self, params: &[(StrId, f64)]) -> usize {
        self.diffusion
            .iter()
            .flatten()
            .filter(|&&name| params.iter().any(|&(stated, _)| stated == name))
            .count()
    }
}

/// Which law a merge applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeKind {
    /// Devices on the same nets became one: a MOS's `W` and `nf` were summed,
    /// or any other device's count `m`, a MOS with no `W` included.
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

use crate::lvs::graph::{channel_ends, narrow, transpose_into, Graph};
use crate::lvs::refine::{kind_code, role_code};
use gpurify_ingest::deck::DeviceKind;

/// Whether a parallel merge sums this device's `W`: a MOS stating one, whose
/// `m` was folded into it. Any other device, a MOS with no `W` included,
/// keeps its count in `m` instead (testing-plan F83).
fn sums_width(kind: DeviceKind, params: &[(StrId, f64)], names: ParamNames) -> bool {
    kind == DeviceKind::Mos
        && names
            .width
            .is_some_and(|width| params.iter().any(|&(name, _)| name == width))
}

/// The parameters a parallel merge sums, each stated by every member or by
/// none: a MOS's `W`, `nf` and diffusions when it [`sums_width`]. Any other
/// device sums its count `m` instead, which [`count_of`] reads.
fn parallel_sums(wide: bool, names: ParamNames) -> [Option<StrId>; 6] {
    if wide {
        let [area_s, area_d, perim_s, perim_d] = names.diffusion;
        [names.width, names.fingers, area_s, area_d, perim_s, perim_d]
    } else {
        [None; 6]
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
    /// Devices that may merge in parallel: no terminal on no net, and a `W`
    /// to sum or else the `m` name to count in.
    parallel_ok: Vec<bool>,
    /// Each device's terminals as [`terminal_key`]s, ascending, CSR into `key`.
    key_start: Vec<u32>,
    key: Vec<u64>,
    /// Nets carrying a port, scattered from `port_net`.
    is_port: Vec<bool>,
    /// Candidate series nets and the two devices each joins, ascending by net.
    /// Kept because the consumed mask is rebuilt from it after a dissolution.
    series: Vec<(u32, u32, u32)>,
    /// Per device: the parameters a parallel merge needs equal (all but `W`,
    /// `nf`) and a series merge needs equal (all but `L`). A device that
    /// states no `L`, or has a terminal on no net, has no series signature:
    /// it never merges in series (testing-plan F67).
    parallel_sig: Vec<Vec<(StrId, u64)>>,
    series_sig: Vec<Option<Vec<(StrId, u64)>>>,
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

/// [`reduce_with`] told no parameter names, which merges nothing: with no
/// `W` name no MOS has a width to sum, with no `m` name no device a count to
/// keep (testing-plan F83), and with no `L` name no series merge a length
/// (F67). The graph comes through byte-identical.
///
/// # Panics
///
/// As [`reduce_with`].
pub fn reduce(src: &Graph) -> Graph {
    reduce_with(src, ParamNames::default()).0
}

/// Reduce to parallel and series normal form by the laws of the module docs,
/// reading `W`, `L`, `nf` and `m` by `names`, and every merge made, in the
/// order made. Devices come out one per group ascending by the group's lowest
/// row; surviving nets keep their order. Reducing a reduced graph changes
/// nothing: the output is a fixed point.
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
/// Panics, or reduces wrongly, when `src` breaks the [`Graph`] invariants.
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
        } else if let Some((reduced, kind, groups)) = names
            .gates
            .then(|| crate::lvs::gates::pass(&out, names))
            .flatten()
        {
            // Logic-gate reduction, once nothing else merges; its groups
            // come ascending by lowest row, as a plan's do.
            let mut next = Vec::with_capacity(groups.len());
            for group in &groups {
                let mut rows: Vec<u32> = group
                    .iter()
                    .flat_map(|&d| origin[d as usize].iter().copied())
                    .collect();
                rows.sort_unstable();
                if group.len() > 1 {
                    merges.push(Merge {
                        kind,
                        model: out.device_model[group[0] as usize],
                        devices: rows.clone(),
                    });
                }
                next.push(rows);
            }
            origin = next;
            out = reduced;
            continue;
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

/// Each MOS's `m` folded into its `W` and its diffusions: `m` devices in
/// parallel are one of `m` times the width and the diffusion. Every other `m` is kept as the device's count, except an
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
        let kind = src.device_kind[device as usize];
        let into = names.width.filter(|_| sums_width(kind, params, names));
        let law = Law::of(kind, params, names);
        for &(name, value) in params {
            if name == multiplier {
                // Folded, or a count of one: nothing left to say.
                #[expect(clippy::float_cmp, reason = "1 is the count a card states exactly")]
                if into.is_none() && law.is_none() && m != 1.0 {
                    out.param.push((name, value));
                }
            } else if into.is_some()
                && (Some(name) == into || names.diffusion.contains(&Some(name)))
            {
                out.param.push((name, value * m));
            } else if let Some(law) = law.filter(|law| law.combines(name)) {
                out.param.push((name, law.times(name, value, m)));
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
    plan.parallel_ok.clear();
    plan.parallel_ok.reserve(devices);
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
        let bound = !terminal_nets.contains(&u32::MAX);
        // A merge with no `W` to sum keeps the count, which needs the `m`
        // name to be kept under (testing-plan F83); one with a `W` needs
        // nothing else (F84).
        let wide = sums_width(kind, params, names);
        // A relaxed passive combines its value instead of counting.
        let law = Law::of(kind, params, names);
        // Diffusions are summed end by end, which needs all four or none.
        let diffusions = names.diffusions_in(params);
        let whole = diffusions == 0 || diffusions == names.diffusion.len();
        let counts = !wide && law.is_none() && names.multiplier.is_some();
        plan.parallel_ok
            .push(bound & ((wide && whole) || law.is_some() || counts));
        let counted = names.multiplier.filter(|_| !wide && law.is_none());
        let sums = law.map_or_else(|| parallel_sums(wide, names), Law::sums);
        plan.parallel_sig.push(signature(params, &sums, counted));
        let states_length = names
            .length
            .is_some_and(|length| params.iter().any(|&(name, _)| name == length));
        // A relaxed resistor or capacitor stating its value merges in
        // series by its law; any other device by its `L`.
        let passive = law
            .and_then(|law| law.series_sums(kind, names))
            .filter(|_| roles.len() == 2);
        plan.series_sig.push(match passive {
            Some(sums) => bound.then(|| signature(params, &sums, None)),
            None => (states_length && bound && diffusions == 0 && !series_passive(kind))
                .then(|| signature(params, &[names.length], None)),
        });
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
        parallel_ok,
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
            if !parallel_ok[device as usize] {
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
        if series_passive(src.device_kind[first as usize]) {
            if passive_pair(src, plan, net, (first, first_role), (second, second_role)) {
                join(&mut plan.root, first, second);
                plan.series.push((net, first, second));
            }
            continue;
        }
        if !(is_channel(first_role) & is_channel(second_role)) {
            continue;
        }
        // Two stacked devices are one only as long as the two lengths: with
        // no `L` on either, the stack count would be lost (testing-plan F67).
        // A device with a terminal on no net has no signature either.
        if (src.device_kind[first as usize] != src.device_kind[second as usize])
            || (src.device_model[first as usize] != src.device_model[second as usize])
            || plan.series_sig[first as usize].is_none()
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

/// Whether two relaxed passives meet in series at `net`, which carries
/// exactly their two terminals and is no port: one kind and one model, a
/// series signature each and the same one (the value, and what adds with
/// it, stated by both or neither; every other parameter bit-identical),
/// and their far ends on two other nets, not the same one (that would be
/// a loop). A capacitor's plates are ordered, so its chain must run plate
/// to plate, one's second plate on the other's first, unless its two pins
/// compare under one role (a resistor's ends, or plates `lvs permute`
/// joined); tail to tail never merges.
fn passive_pair(
    src: &Graph,
    plan: &Plan,
    net: u32,
    (first, first_role): (u32, TerminalRole),
    (second, second_role): (u32, TerminalRole),
) -> bool {
    let (a, b) = (first as usize, second as usize);
    if src.device_kind[a] != src.device_kind[b]
        || src.device_model[a] != src.device_model[b]
        || plan.series_sig[a].is_none()
        || plan.series_sig[a] != plan.series_sig[b]
    {
        return false;
    }
    let far = |device: u32| {
        let (nets, roles) = src.terminals_of(device);
        let symmetric = roles[0] == roles[1];
        let other = if nets[0] == net { nets[1] } else { nets[0] };
        (other, symmetric)
    };
    let ((far_a, symmetric), (far_b, _)) = (far(first), far(second));
    far_a != net && far_b != net && far_a != far_b && (symmetric || first_role != second_role)
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
    debug_assert!(
        (0..devices).all(|device| {
            let head = plan.root[device] as usize;
            head <= device && plan.root[head] as usize == head
        }),
        "each group's root is its lowest device and its own root"
    );
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
    if series_passive(src.device_kind[head as usize]) {
        return passive_group_is_sound(src, plan, from, to);
    }
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

/// Whether a series group of passives is one passive: every member of the
/// head's kind and model, and exactly two terminals left on nets the group
/// did not consume, on two different nets. A ring consumes every net and
/// leaves none; a chain closing on itself leaves both ends on one net.
fn passive_group_is_sound(src: &Graph, plan: &Plan, from: usize, to: usize) -> bool {
    let head = plan.order[from] as usize;
    let mut ends = Vec::with_capacity(2);
    for index in from..to {
        let device = plan.order[index];
        if src.device_kind[device as usize] != src.device_kind[head]
            || src.device_model[device as usize] != src.device_model[head]
        {
            return false;
        }
        for &net in src.terminals_of(device).0 {
            if !plan.consumed[net as usize] {
                ends.push(net);
            }
        }
    }
    ends.len() == 2 && ends[0] != ends[1]
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
            let head_kind = src.device_kind[head as usize];
            let wide = sums_width(head_kind, src.params_of(head), names);
            let law = Law::of(head_kind, src.params_of(head), names)
                .filter(|_| plan.mode == Some(MergeKind::Parallel));
            let group = &plan.order[at..end];
            // A relaxed passive's series law, where this group is one.
            let series_law = Law::of(head_kind, src.params_of(head), names)
                .filter(|_| plan.mode == Some(MergeKind::Series))
                .and_then(|law| Some((law, law.series_sums(head_kind, names)?)));
            let summed = match (plan.mode, law, series_law) {
                (Some(MergeKind::Series), _, Some((_, sums))) => sums,
                (Some(MergeKind::Series), _, None) => [names.length, None, None, None, None, None],
                (_, Some(law), _) => law.sums(),
                _ => parallel_sums(wide, names),
            };
            // Combined harmonically: a resistance in parallel, a
            // capacitance in series.
            let harmonic = law
                .map(|law| (law.value, law.harmonic))
                .or_else(|| series_law.map(|(law, _)| (law.value, !law.harmonic)));
            // A member whose source is on the head's drain adds its `as` to
            // the head's `ad`, and so on: a diffusion is its net's.
            let (head_source, head_drain) = channel_ends(src, head);
            let crossed = |device: u32| {
                head_source != head_drain && channel_ends(src, device).0 == head_drain
            };
            // A device with no `W` to sum keeps its count in `m`, which a card
            // may leave out: summed with a missing one read as 1, and written
            // last.
            let counted = names
                .multiplier
                .filter(|_| plan.mode == Some(MergeKind::Parallel) && !wide && law.is_none());
            for &(name, value) in src.params_of(head) {
                if Some(name) == counted {
                    continue;
                }
                let total = if summed.contains(&Some(name)) {
                    let members = group.iter().flat_map(|&d| {
                        let read = if crossed(d) {
                            names.across(name)
                        } else {
                            Some(name)
                        };
                        src.params_of(d)
                            .iter()
                            .filter(move |&&(other, _)| Some(other) == read)
                            .map(|&(_, v)| v)
                    });
                    // A resistance in parallel, a capacitance in series,
                    // combines harmonically: `1 / Σ 1/x`.
                    if harmonic == Some((name, true)) {
                        1.0 / members.map(|v| 1.0 / v).sum::<f64>()
                    } else {
                        members.sum()
                    }
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
    if series_passive(src.device_kind[head as usize]) {
        // The chain's two surviving ends, each with the role it had.
        for &device in &plan.order[from..to] {
            let (nets, roles) = src.terminals_of(device);
            for (&net, &role) in nets.iter().zip(roles) {
                if !plan.consumed[net as usize] {
                    out.push((role, net));
                }
            }
        }
        out.sort_unstable_by_key(|&(role, net)| (role_code(role), net));
        return;
    }
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
