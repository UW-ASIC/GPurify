//! The comparison driver: refine, then read the partition as a verdict.
//!
//! Data in: reduced layout and reference graphs. Data out: a [`Verdict`] whose
//! discrepancy order is user-visible: class imbalances, then per-pair joins in
//! layout order, then unpaired layout nodes, then unpaired reference nodes.

use crate::lvs::graph::{narrow, Graph, LayoutGraph, RefGraph};
use crate::lvs::refine::{refine_into, role_code, Partition, TieBreak};
use crate::lvs::verdict::{Discrepancy, Inconclusive, Side, Verdict};
use crate::topology::TerminalRole;
use gpurify_ingest::StrId;
use std::cmp::Ordering;

/// How to run a comparison.
#[derive(Debug, Clone, Copy)]
pub struct CompareOptions {
    /// Bound on refinement rounds; exceeding it is [`Inconclusive::RoundLimit`].
    pub max_rounds: u32,
    pub tie_break: TieBreak,
    /// Relative parameter tolerance: `|a - b| <= tol * max(|a|, |b|)`.
    pub param_tolerance: f64,
    /// Also require paired nets to carry the same declared name.
    pub match_names: bool,
}

impl Default for CompareOptions {
    fn default() -> Self {
        Self {
            max_rounds: 1000,
            tie_break: TieBreak::LowestIndex,
            param_tolerance: 0.02,
            match_names: false,
        }
    }
}

/// Compare one cell; `scratch` is refinement state reused across cells.
pub fn compare(
    layout: &LayoutGraph,
    reference: &RefGraph,
    options: CompareOptions,
    scratch: &mut Partition,
) -> Verdict {
    if !refine_into(&layout.0, &reference.0, options.max_rounds, scratch) {
        return Verdict::Inconclusive(Inconclusive::RoundLimit);
    }
    interpret(&layout.0, &reference.0, scratch, options)
}

/// A node no class paired with anything.
const UNPAIRED: u32 = u32::MAX;

fn interpret(
    layout: &Graph,
    reference: &Graph,
    partition: &Partition,
    options: CompareOptions,
) -> Verdict {
    let layout_devices = narrow(layout.device_count());
    let ref_devices = narrow(reference.device_count());
    let mut found: Vec<Discrepancy> = Vec::new();

    let tallies = partition.layout_tally.iter().zip(&partition.ref_tally);
    // More than one node per side, so no single node can be blamed. Its members
    // are also reported unpaired below; the double report is deliberate.
    for (&layout_count, &ref_count) in tallies.clone() {
        if layout_count > 1 && ref_count > 1 {
            found.push(Discrepancy::ClassImbalance {
                layout_nodes: layout_count,
                ref_nodes: ref_count,
            });
        }
    }

    // Classes holding exactly one node per side, ascending by layout node.
    let resolved: Vec<bool> = tallies.map(|(&a, &b)| a == 1 && b == 1).collect();
    let pairs: Vec<(u32, u32)> = partition
        .layout_class
        .iter()
        .enumerate()
        .filter(|&(_, class)| resolved[class.0 as usize])
        .map(|(node, class)| (narrow(node), partition.ref_first[class.0 as usize]))
        .collect();

    let mut layout_mate = vec![UNPAIRED; layout.device_count() + layout.net_count()];
    let mut ref_mate = vec![UNPAIRED; reference.device_count() + reference.net_count()];
    for &(layout_node, ref_node) in &pairs {
        layout_mate[layout_node as usize] = ref_node;
        ref_mate[ref_node as usize] = layout_node;
    }

    // A proposed pairing is a candidate until terminals and parameters agree.
    let mut scratch = JoinScratch::default();
    for &(layout_node, ref_node) in &pairs {
        if layout_node < layout_devices {
            compare_identity(layout, reference, (layout_node, ref_node), &mut found);
            compare_terminals(
                layout,
                reference,
                (layout_node, ref_node),
                (layout_devices, ref_devices),
                &layout_mate,
                &mut scratch,
                &mut found,
            );
            compare_params(
                layout,
                reference,
                (layout_node, ref_node),
                options.param_tolerance,
                &mut scratch,
                &mut found,
            );
        } else if options.match_names {
            compare_net_name(
                layout,
                reference,
                (layout_node - layout_devices, ref_node - ref_devices),
                &mut found,
            );
        }
    }

    report_unpaired(layout, &layout_mate, Side::Layout, &mut found);
    report_unpaired(reference, &ref_mate, Side::Reference, &mut found);

    if found.is_empty() {
        Verdict::Match
    } else {
        Verdict::Mismatch(found)
    }
}

#[derive(Default)]
struct JoinScratch {
    /// `(role code, reference node, slot)` per terminal.
    layout_terminals: Vec<(u64, u32, u32)>,
    ref_terminals: Vec<(u64, u32, u32)>,
    layout_params: Vec<(StrId, f64)>,
    ref_params: Vec<(StrId, f64)>,
}

/// A paired device must also agree on kind and model (a hash agreeing is not a
/// comparison); if not, both sides are reported unpaired.
fn compare_identity(
    layout: &Graph,
    reference: &Graph,
    pair: (u32, u32),
    found: &mut Vec<Discrepancy>,
) {
    let (mine, theirs) = (pair.0 as usize, pair.1 as usize);
    let (layout_model, ref_model) = (layout.device_model[mine], reference.device_model[theirs]);
    if layout.device_kind[mine] == reference.device_kind[theirs] && layout_model == ref_model {
        return;
    }
    found.push(Discrepancy::UnpairedDevice {
        side: Side::Layout,
        device: pair.0,
        model: layout_model,
    });
    found.push(Discrepancy::UnpairedDevice {
        side: Side::Reference,
        device: pair.1,
        model: ref_model,
    });
}

const fn unmatched_terminal(pair: (u32, u32), role: TerminalRole) -> Discrepancy {
    Discrepancy::TerminalMismatch {
        layout_device: pair.0,
        ref_device: pair.1,
        role,
    }
}

/// Terminals matched by role code (never slot) onto counterpart nets, as a
/// sorted multiset merge; both tails are reported so the report is mirror-symmetric.
fn compare_terminals(
    layout: &Graph,
    reference: &Graph,
    pair: (u32, u32),
    devices: (u32, u32),
    layout_mate: &[u32],
    scratch: &mut JoinScratch,
    found: &mut Vec<Discrepancy>,
) {
    let (layout_device, ref_device) = pair;
    let (layout_devices, ref_devices) = devices;
    let (layout_nets, layout_roles) = layout.terminals_of(layout_device);
    let (ref_nets, ref_roles) = reference.terminals_of(ref_device);

    let (mine, theirs) = (&mut scratch.layout_terminals, &mut scratch.ref_terminals);
    mine.clear();
    theirs.clear();

    // Both sides in reference node space. A terminal on no net (`u32::MAX`)
    // overflows the add and agrees with nothing; so does one on an unpaired net.
    for slot in 0..layout_roles.len() {
        match layout_devices
            .checked_add(layout_nets[slot])
            .and_then(|node| layout_mate.get(node as usize).copied())
            .filter(|&mate| mate != UNPAIRED)
        {
            Some(mate) => mine.push((role_code(layout_roles[slot]), mate, narrow(slot))),
            None => found.push(unmatched_terminal(pair, layout_roles[slot])),
        }
    }
    for slot in 0..ref_roles.len() {
        match ref_devices.checked_add(ref_nets[slot]) {
            Some(node) => theirs.push((role_code(ref_roles[slot]), node, narrow(slot))),
            None => found.push(unmatched_terminal(pair, ref_roles[slot])),
        }
    }
    mine.sort_unstable();
    theirs.sort_unstable();

    let (mut at_mine, mut at_theirs) = (0usize, 0usize);
    while at_mine < mine.len() && at_theirs < theirs.len() {
        let (a, b) = (mine[at_mine], theirs[at_theirs]);
        match (a.0, a.1).cmp(&(b.0, b.1)) {
            Ordering::Equal => {
                at_mine += 1;
                at_theirs += 1;
            }
            Ordering::Less => {
                found.push(unmatched_terminal(pair, layout_roles[a.2 as usize]));
                at_mine += 1;
            }
            Ordering::Greater => {
                found.push(unmatched_terminal(pair, ref_roles[b.2 as usize]));
                at_theirs += 1;
            }
        }
    }

    for &(_, _, slot) in &mine[at_mine..] {
        found.push(unmatched_terminal(pair, layout_roles[slot as usize]));
    }
    for &(_, _, slot) in &theirs[at_theirs..] {
        found.push(unmatched_terminal(pair, ref_roles[slot as usize]));
    }
}

/// Parameters joined by name within relative tolerance (`NaN` fails); a name only
/// one side declares is [`Discrepancy::UndeclaredParam`], never a pass.
fn compare_params(
    layout: &Graph,
    reference: &Graph,
    pair: (u32, u32),
    tolerance: f64,
    scratch: &mut JoinScratch,
    found: &mut Vec<Discrepancy>,
) {
    let (mine, theirs) = (&mut scratch.layout_params, &mut scratch.ref_params);
    mine.clear();
    mine.extend_from_slice(layout.params_of(pair.0));
    theirs.clear();
    theirs.extend_from_slice(reference.params_of(pair.1));

    // Stable: rows sharing a name pair off in declaration order.
    mine.sort_by_key(|&(name, _)| name);
    theirs.sort_by_key(|&(name, _)| name);

    let (mut at_mine, mut at_theirs) = (0usize, 0usize);
    while at_mine < mine.len() && at_theirs < theirs.len() {
        let ((layout_param, layout_value), (ref_param, ref_value)) =
            (mine[at_mine], theirs[at_theirs]);
        if layout_param != ref_param {
            let mine_first = layout_param < ref_param;
            found.push(undeclared_param(
                pair,
                if mine_first {
                    Side::Layout
                } else {
                    Side::Reference
                },
                if mine_first { layout_param } else { ref_param },
            ));
            at_mine += usize::from(mine_first);
            at_theirs += usize::from(!mine_first);
            continue;
        }
        at_mine += 1;
        at_theirs += 1;

        let spread = (layout_value - ref_value).abs();
        let scale = layout_value.abs().max(ref_value.abs());
        let agree = spread <= tolerance * scale;
        if !agree {
            found.push(Discrepancy::ParameterMismatch {
                layout_device: pair.0,
                ref_device: pair.1,
                param: layout_param,
                layout_value,
                ref_value,
            });
        }
    }

    for &(param, _) in &mine[at_mine..] {
        found.push(undeclared_param(pair, Side::Layout, param));
    }
    for &(param, _) in &theirs[at_theirs..] {
        found.push(undeclared_param(pair, Side::Reference, param));
    }
}

/// One parameter of a paired device that only `side` declares.
const fn undeclared_param(pair: (u32, u32), side: Side, param: StrId) -> Discrepancy {
    Discrepancy::UndeclaredParam {
        side,
        layout_device: pair.0,
        ref_device: pair.1,
        param,
    }
}

/// One paired net's declared names, when the run asked for them to agree.
fn compare_net_name(
    layout: &Graph,
    reference: &Graph,
    nets: (u32, u32),
    found: &mut Vec<Discrepancy>,
) {
    let layout_name = layout.net_name[nets.0 as usize];
    let ref_name = reference.net_name[nets.1 as usize];
    if layout_name != ref_name {
        found.push(Discrepancy::UnpairedNet {
            side: Side::Layout,
            net: nets.0,
            name: layout_name,
        });
        found.push(Discrepancy::UnpairedNet {
            side: Side::Reference,
            net: nets.1,
            name: ref_name,
        });
    }
}

/// Every node of one side that no class paired, devices then nets.
fn report_unpaired(graph: &Graph, mate: &[u32], side: Side, found: &mut Vec<Discrepancy>) {
    let devices = graph.device_count();

    for (device, &partner) in mate[..devices].iter().enumerate() {
        if partner == UNPAIRED {
            found.push(Discrepancy::UnpairedDevice {
                side,
                device: narrow(device),
                model: graph.device_model[device],
            });
        }
    }
    for (net, &partner) in mate[devices..].iter().enumerate() {
        if partner == UNPAIRED {
            found.push(Discrepancy::UnpairedNet {
                side,
                net: narrow(net),
                name: graph.net_name[net],
            });
        }
    }
}
