//! Logic-gate reduction: transistors of one model stacked in series, or set
//! in parallel, on *different* gates become one device whose gates are
//! interchangeable (catalog LVS-047).
//!
//! The definition is Silvaco Guardian LVS's, the one public vendor text on
//! it: its MOS "Series reduction option reduces the same type MOS ...
//! transistors to a single element if they are connected in series with
//! different gate terminals", the parallel option likewise, and "the
//! resulting device will have swappable gate terminals" (Guardian LVS
//! example 4, "Parallel/Series Merge and Reduction of Devices"). Its logic
//! gate recognition is built on the two (application note "Logic Gate
//! Recognition in Guardian LVS", 2020): a CMOS `NAND_N` is N n-channel
//! transistors in series and N p-channel in parallel on the same N inputs,
//! a `NOR_N` the other way round, and "all N input terminals are
//! swappable". Calibre's `LVS RECOGNIZE GATES` names the same idea; its
//! manual is not public.
//!
//! Data in: a reduced [`Graph`]. Data out: the graph with one law applied
//! once, and which input rows each output device stands for.
//!
//! What must hold before a merge, each a refusal otherwise (a false
//! mismatch, never a false match):
//!
//! - every member a plain transistor: one gate, one source, one drain, at
//!   most one bulk, every terminal on a net, no diffusion stated (a stack
//!   would swallow a shared diffusion, as a series merge would);
//! - every member of one model, with bit-identical parameters: a swap
//!   moves a transistor with its input, so members of different sizes
//!   would let a swap pass that changes the circuit;
//! - one bulk net for all, or none;
//! - every member on a gate net of its own;
//! - parallel: the same source and drain nets, either way round;
//! - series: a chain through nets that only its two neighbours touch and
//!   that are no port, ending on two distinct nets.
//!
//! The merged device keeps the members' parameters unchanged (they are
//! identical, and the count of its gates says how many it stands for), the
//! gates of every member in net order, the chain's two ends as its source
//! and drain, and the bulk. Members that already merged into a
//! multi-gate device are not plain, so nesting (an AOI's parallel groups in
//! series) is not reduced: a gate's stacks in another order still mismatch.

use crate::lvs::graph::{narrow, transpose_into, Graph};
use crate::lvs::reduce::{MergeKind, ParamNames};
use crate::topology::TerminalRole;
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrId;

/// A plain transistor's nets: gate, source, drain, bulk (`u32::MAX` when it
/// has none).
#[derive(Clone, Copy)]
struct Plain {
    gate: u32,
    source: u32,
    drain: u32,
    bulk: u32,
}

/// `device` read as a plain transistor, or `None` when it is not one.
fn plain(graph: &Graph, device: u32, names: ParamNames) -> Option<Plain> {
    if graph.device_kind[device as usize] != DeviceKind::Mos {
        return None;
    }
    let (nets, roles) = graph.terminals_of(device);
    let (mut gate, mut source, mut drain, mut bulk) = (None, None, None, None);
    for (&net, &role) in nets.iter().zip(roles) {
        if net == u32::MAX {
            return None;
        }
        let slot = match role {
            TerminalRole::Gate => &mut gate,
            TerminalRole::Source => &mut source,
            TerminalRole::Drain => &mut drain,
            TerminalRole::Bulk => &mut bulk,
            _ => return None,
        };
        if slot.replace(net).is_some() {
            return None;
        }
    }
    let diffusion = names
        .diffusion
        .iter()
        .chain(&names.stress)
        .flatten()
        .any(|&name| {
            graph
                .params_of(device)
                .iter()
                .any(|&(stated, _)| stated == name)
        });
    if diffusion {
        return None;
    }
    Some(Plain {
        gate: gate?,
        source: source?,
        drain: drain?,
        bulk: bulk.unwrap_or(u32::MAX),
    })
}

/// A device's parameters as sorted `(name, bits)`: equal exactly when the
/// two state the same names with bit-identical values.
fn bits(graph: &Graph, device: u32) -> Vec<(StrId, u64)> {
    let mut out: Vec<(StrId, u64)> = graph
        .params_of(device)
        .iter()
        .map(|&(name, value)| (name, value.to_bits()))
        .collect();
    out.sort_unstable();
    out
}

/// What a parallel group shares, then the member's gate and row: model,
/// the source/drain pair low end first, bulk, signature, gate, row.
type ParallelKey<'a> = (StrId, u32, u32, u32, &'a [(StrId, u64)], u32, u32);

fn find(root: &mut [u32], mut at: u32) -> u32 {
    while root[at as usize] != at {
        let up = root[root[at as usize] as usize];
        root[at as usize] = up;
        at = up;
    }
    at
}

fn join(root: &mut [u32], a: u32, b: u32) {
    let (a, b) = (find(root, a), find(root, b));
    root[a.max(b) as usize] = a.min(b);
}

/// One pass of logic-gate reduction over `graph`, parallel groups first
/// and, when there are none, series chains: `None` when nothing merges.
/// Otherwise the reduced graph, the law applied, and for each output device
/// the rows of `graph` it stands for, ascending, the devices ordered by
/// their lowest row, as [`reduce_with`](crate::lvs::reduce::reduce_with)
/// orders its own groups.
pub(crate) fn pass(graph: &Graph, names: ParamNames) -> Option<(Graph, MergeKind, Vec<Vec<u32>>)> {
    let devices = narrow(graph.device_count());
    let plains: Vec<Option<Plain>> = (0..devices).map(|d| plain(graph, d, names)).collect();
    let signature: Vec<Vec<(StrId, u64)>> = (0..devices).map(|d| bits(graph, d)).collect();
    let mut root: Vec<u32> = (0..devices).collect();
    let mut consumed = vec![false; graph.net_count()];

    // Parallel: plain transistors on one source/drain pair, either way
    // round, one bulk, one model and one signature, each on a gate of its
    // own.
    let mut keyed: Vec<ParallelKey<'_>> = (0..devices)
        .filter_map(|d| {
            let p = plains[d as usize]?;
            let (low, high) = (p.source.min(p.drain), p.source.max(p.drain));
            Some((
                graph.device_model[d as usize],
                low,
                high,
                p.bulk,
                signature[d as usize].as_slice(),
                p.gate,
                d,
            ))
        })
        .collect();
    keyed.sort_unstable();
    let mut parallel = false;
    for run in
        keyed.chunk_by(|a, b| a.0 == b.0 && a.1 == b.1 && a.2 == b.2 && a.3 == b.3 && a.4 == b.4)
    {
        // A gate shared within the run is a same-gate parallel merge's,
        // which reduction makes first; one left here keeps the run apart.
        if run.len() < 2 || run.windows(2).any(|w| w[0].5 == w[1].5) {
            continue;
        }
        for member in &run[1..] {
            join(&mut root, run[0].6, member.6);
        }
        parallel = true;
    }

    let kind = if parallel {
        MergeKind::Parallel
    } else {
        // Series: chain plain transistors through nets only the two touch.
        let is_port = {
            let mut is_port = vec![false; graph.net_count()];
            for &net in &graph.port_net {
                is_port[net as usize] = true;
            }
            is_port
        };
        let mut chained = false;
        for net in 0..narrow(graph.net_count()) {
            let on = graph.terminals_on(net);
            let [(a, role_a), (b, role_b)] = on else {
                continue;
            };
            let channel =
                |role: TerminalRole| matches!(role, TerminalRole::Source | TerminalRole::Drain);
            if is_port[net as usize] || a == b || !channel(*role_a) || !channel(*role_b) {
                continue;
            }
            let (Some(pa), Some(pb)) = (plains[*a as usize], plains[*b as usize]) else {
                continue;
            };
            let same = graph.device_model[*a as usize] == graph.device_model[*b as usize]
                && signature[*a as usize] == signature[*b as usize]
                && pa.bulk == pb.bulk
                && pa.gate != pb.gate;
            if same {
                join(&mut root, *a, *b);
                consumed[net as usize] = true;
                chained = true;
            }
        }
        if !chained {
            return None;
        }
        MergeKind::Series
    };

    // Groups, each checked; one that is not a sound chain falls apart.
    let mut groups: Vec<Vec<u32>> = Vec::new();
    let mut group_of = vec![u32::MAX; devices as usize];
    for d in 0..devices {
        let r = find(&mut root, d) as usize;
        if group_of[r] == u32::MAX {
            group_of[r] = narrow(groups.len());
            groups.push(Vec::new());
        }
        groups[group_of[r] as usize].push(d);
    }
    let mut out_groups: Vec<Vec<u32>> = Vec::new();
    let mut merged_any = false;
    for group in groups {
        if group.len() < 2 || sound(&group, &plains, &consumed) {
            merged_any |= group.len() >= 2;
            out_groups.push(group);
        } else {
            for &net in group.iter().flat_map(|&d| graph.terminals_of(d).0) {
                consumed[net as usize] = false;
            }
            out_groups.extend(group.into_iter().map(|d| vec![d]));
        }
    }
    if !merged_any {
        return None;
    }
    out_groups.sort_unstable_by_key(|group| group[0]);
    Some((
        emit(graph, &out_groups, &plains, &consumed),
        kind,
        out_groups,
    ))
}

/// Whether a group is one multi-gate transistor: every gate its own net,
/// and the terminals on nets the group did not consume are one source and
/// one drain on two distinct nets (a parallel group's are its shared ends),
/// so a ring or a branching chain stays as drawn.
fn sound(group: &[u32], plains: &[Option<Plain>], consumed: &[bool]) -> bool {
    let mut gates: Vec<u32> = group
        .iter()
        .filter_map(|&d| plains[d as usize].map(|p| p.gate))
        .collect();
    gates.sort_unstable();
    if gates.len() != group.len() || gates.windows(2).any(|w| w[0] == w[1]) {
        return false;
    }
    let ends: Vec<u32> = group
        .iter()
        .filter_map(|&d| plains[d as usize])
        .flat_map(|p| [p.source, p.drain])
        .filter(|&net| !consumed[net as usize])
        .collect();
    let parallel = ends.len() == 2 * group.len();
    if parallel {
        // Every member on the head's two ends.
        let head =
            plains[group[0] as usize].map(|p| (p.source.min(p.drain), p.source.max(p.drain)));
        return group.iter().all(|&d| {
            plains[d as usize].map(|p| (p.source.min(p.drain), p.source.max(p.drain))) == head
        }) && head.is_some_and(|(a, b)| a != b);
    }
    ends.len() == 2 && ends[0] != ends[1]
}

/// `graph` with each group one device, in group order, and the consumed
/// nets dropped, the survivors in their order.
fn emit(graph: &Graph, groups: &[Vec<u32>], plains: &[Option<Plain>], consumed: &[bool]) -> Graph {
    let nets = graph.net_count();
    let mut new_net = vec![u32::MAX; nets];
    let mut next = 0u32;
    for (net, slot) in new_net.iter_mut().enumerate() {
        if !consumed[net] {
            *slot = next;
            next += 1;
        }
    }
    let renamed = |net: u32| new_net.get(net as usize).copied().unwrap_or(u32::MAX);
    let mut out = Graph {
        net_name: (0..nets)
            .filter(|&net| !consumed[net])
            .map(|net| graph.net_name[net])
            .collect(),
        port_net: graph.port_net.iter().map(|&net| renamed(net)).collect(),
        ..Graph::default()
    };
    out.device_terminal_start.push(0);
    out.device_param_start.push(0);
    for group in groups {
        let head = group[0];
        out.device_kind.push(graph.device_kind[head as usize]);
        out.device_model.push(graph.device_model[head as usize]);
        out.param.extend_from_slice(graph.params_of(head));
        out.device_param_start.push(narrow(out.param.len()));
        if group.len() == 1 {
            let (terminal_nets, roles) = graph.terminals_of(head);
            out.terminal_net
                .extend(terminal_nets.iter().map(|&net| renamed(net)));
            out.terminal_role.extend_from_slice(roles);
        } else {
            let members: Vec<Plain> = group.iter().filter_map(|&d| plains[d as usize]).collect();
            let mut gates: Vec<u32> = members.iter().map(|p| p.gate).collect();
            gates.sort_unstable();
            for gate in gates {
                out.terminal_net.push(renamed(gate));
                out.terminal_role.push(TerminalRole::Gate);
            }
            let ends: Vec<u32> = members
                .iter()
                .flat_map(|p| [p.source, p.drain])
                .filter(|&net| !consumed[net as usize])
                .collect();
            // A parallel group's ends are each member's; its head's say it.
            let (source, drain) = if ends.len() == 2 {
                (ends[0], ends[1])
            } else {
                (members[0].source, members[0].drain)
            };
            out.terminal_net.push(renamed(source));
            out.terminal_role.push(TerminalRole::Source);
            out.terminal_net.push(renamed(drain));
            out.terminal_role.push(TerminalRole::Drain);
            if members[0].bulk != u32::MAX {
                out.terminal_net.push(renamed(members[0].bulk));
                out.terminal_role.push(TerminalRole::Bulk);
            }
        }
        out.device_terminal_start
            .push(narrow(out.terminal_net.len()));
    }
    transpose_into(&mut out, next as usize);
    out
}
