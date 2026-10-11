//! The comparison driver: drop unextracted bulk, reduce, refine, then read the
//! partition as a verdict.
//!
//! Data in: the layout and reference graphs as projected. Data out: a [`Verdict`] whose
//! discrepancy order is user-visible: class imbalances, then per-pair joins in
//! layout order, then unpaired layout nodes, then unpaired reference nodes.

use crate::lvs::controls::{
    assign_roles, bound, drop_ignored_devices, drop_ignored_params, report_roles, restore_rows,
};
use crate::lvs::graph::{channel_ends, drop_unextracted_bulk, keep_declared_params, narrow, Graph};
use crate::lvs::reduce::{reduce_with, Merge, ParamNames};
use crate::lvs::refine::{refine_into, role_code, Partition};
use crate::lvs::verdict::{Discrepancy, Inconclusive, Side, Verdict};
use crate::topology::TerminalRole;
use gpurify_ingest::deck::LvsControls;
use gpurify_ingest::StrId;
use std::cmp::Ordering;

/// How to run a comparison.
///
/// The default is 1000 rounds, a 2% tolerance and no parameter names. The
/// `gpurify` binary keeps the first two and names `w`, `l`, `nf`, `m`, `as`,
/// `ad`, `ps` and `pd`.
#[derive(Debug, Clone, Copy)]
pub struct CompareOptions {
    /// The most refinement passes in a row that may split a class without the
    /// partition settling; one more is [`Inconclusive::RoundLimit`]. The count
    /// restarts at each symmetry tie-break, and at each pairing a tie-break
    /// tries, so the number of symmetries does not spend it.
    pub max_rounds: u32,
    /// Relative tolerance `tol` for every parameter of a paired device but
    /// its counts: values `a` and `b` agree when
    /// `|a - b| <= tol * max(|a|, |b|)`. `NaN` never agrees. A count, the
    /// parameter [`ParamNames`] names `m` or `nf`, is a whole number and
    /// agrees only exactly (testing-plan F99): `m = 50` against `m = 51`,
    /// 1.96 % apart, is a mismatch. A deck's `lvs tolerance` row replaces it
    /// for one parameter of one model, with a relative part, an absolute
    /// one, or both ([`compare_with`], catalog LVS-014), a count's too. It
    /// does not apply to reduction, whose merges need the other parameters
    /// bit-identical.
    ///
    /// Netgen's counterpart is `property ... tolerance`, `KLayout`'s `tolerance`.
    /// Netgen measures the difference against the mean of the two values, not
    /// the larger, so its `2 tol / (2 - tol)` is this `tol` exactly; the Netgen
    /// differential (testing-plan F3) sets it so.
    pub param_tolerance: f64,
    /// Which parameters are `W`, `L`, `nf`, `m` and the diffusions, so
    /// devices can be merged in parallel and series, and a diffusion read at
    /// its channel end. Default: none, and nothing merges.
    pub params: ParamNames,
}

impl Default for CompareOptions {
    fn default() -> Self {
        Self {
            max_rounds: 1000,
            param_tolerance: 0.02,
            params: ParamNames::default(),
        }
    }
}

/// Compares one cell: the extracted `layout` against one `reference`
/// subcircuit, as the [`lvs` module docs](crate::lvs) describe.
///
/// Reference `Bulk` terminals are dropped when no layout terminal is `Bulk`
/// (a three-terminal MOS recogniser), and a layout device keeps a parameter
/// through reduction only when the reference declares it on some device of
/// the same kind and model (a reference that sizes its diodes by `area` says
/// nothing about its transistors' areas, which must not block their merges).
/// Then both sides are reduced and refined together. A paired device's
/// parameters are compared per device: those its reference card states,
/// whatever other cards of the model state (testing-plan F68), and its count
/// `m`, 1 where a side states none, once the `m` name is given. A
/// symmetry pairs its lowest layout node with the reference node whose
/// parameters are closest, so a stall resolves by property value rather than
/// by row order, and a pairing that leaves a class short of layout nodes or
/// pairs devices that disagree is taken back for the next closest, so card
/// order does not decide a match either. Neither input is modified.
///
/// The verdict is deterministic: the same graphs and options give the same
/// verdict and the same discrepancy order on every run.
///
/// # Panics
///
/// Panics, or compares wrongly, when either graph breaks the [`Graph`]
/// invariants, or holds `u32::MAX` or more devices plus nets.
pub fn compare(layout: &Graph, reference: &Graph, options: CompareOptions) -> Verdict {
    compare_logged(layout, reference, options).0
}

/// Makes every reference net a layout label names a port of `reference`.
///
/// A label makes a layout port, and a series merge never crosses a port. The
/// reference's net of the same name must stop the merge too, or a stack with a
/// labelled internal node reduces on one side only (testing-plan F12).
fn protect_labelled(layout: &Graph, reference: &mut Graph) {
    let mut labels: Vec<StrId> = layout
        .port_net
        .iter()
        .filter_map(|&net| layout.net_name[net as usize])
        .collect();
    labels.sort_unstable();
    let mut is_port = vec![false; reference.net_count()];
    for &net in &reference.port_net {
        is_port[net as usize] = true;
    }
    for (net, &port) in is_port.iter().enumerate() {
        let named = reference.net_name[net].is_some_and(|name| labels.binary_search(&name).is_ok());
        if named && !port {
            reference.port_net.push(narrow(net));
        }
    }
}

/// [`compare`], and every series or parallel merge each side's reduction made,
/// layout's first.
///
/// A [`Merge`]'s device rows are rows of the graph that side was given (the
/// reference's rows are unchanged by the bulk drop). A device merged in two
/// passes, say series then parallel, appears in both merges. This is how a
/// [`Discrepancy`] row, which is a row of the reduced graph, is traced back
/// to what was drawn.
///
/// # Panics
///
/// As [`compare`].
pub fn compare_logged(
    layout: &Graph,
    reference: &Graph,
    options: CompareOptions,
) -> (Verdict, Vec<(Side, Merge)>) {
    compare_with(layout, reference, options, &LvsControls::default())
}

/// [`compare_logged`] under the deck's `lvs` statements, which the `gpurify`
/// binary passes from the deck it loaded. With no statement it is
/// [`compare_logged`].
///
/// - **`lvs tolerance`** (catalog LVS-014): a paired device's parameter
///   named by a row for its model agrees when `|a - b| <= absolute +
///   relative * max(|a|, |b|)`, the row's parts in place of
///   [`CompareOptions::param_tolerance`]; a part the row leaves out is zero.
///   The two parts add, as in `KLayout`'s `tolerance` ("absolute and
///   relative tolerances add"); Netgen's `property ... tolerance` is a
///   relative one, measured against the mean of the two values. A
///   symmetry's trial pairing is held to the same bound.
/// - **`lvs ignore_parameter`** (catalog LVS-014): the parameter is dropped
///   from every device of the model on both sides before reduction, so it
///   is neither compared nor read by a merge, as `KLayout`'s
///   `ignore_parameter` and Netgen's `property ... remove` leave it out.
/// - **`lvs asymmetric`** (catalog LVS-031): a transistor of the model has
///   a source and a drain that do not trade places, `KLayout`'s DMOS: its
///   source pairs only with a source and its drain with a drain, in
///   refinement, in the terminal comparison and in a parallel merge, and a
///   diffusion is compared at the end it is named for. Such transistors
///   never merge in series (`KLayout` merges no transistor in series, and
///   Netgen 1.5.323 none at all), so a stack of them does not match one
///   long card: a false mismatch, never a false match.
/// - **`lvs permute`** (catalog LVS-030): the two pins of every device of
///   the model are interchangeable, joined with its default classes (a
///   transistor's source and drain, unless asymmetric, and a resistor's
///   ends) as Netgen's `permute` and `KLayout`'s `equivalent_pins` declare
///   them. The pins of one class compare under one role, in refinement, the
///   terminal comparison and a parallel merge; a class other than a
///   transistor's channel is no channel, so no series merge takes it, and a
///   terminal mismatch on it is reported under its lowest pin's role.
/// - **`lvs ignore`** (catalog LVS-034): every device of the model is
///   dropped from both sides before reduction, as Netgen's `ignore class`
///   and `KLayout`'s `same_device_classes` with `nil` remove it, and so is
///   a net only those devices reached, unless it is a port of the reference
///   or a labelled layout net, which must still pair. A [`Merge`] still
///   lists rows of the graphs given.
/// - **`lvs ignore_shorted`** (catalog LVS-035): a device of the model with
///   every terminal it has on one net is dropped the same way, as Netgen's
///   `ignore shorted` removes dummies. Its terminals are those compared: a
///   reference bulk the layout does not extract is already gone, so a dummy
///   with gate, source and drain on one net is shorted on both sides.
///
/// # Panics
///
/// As [`compare`].
pub fn compare_with(
    layout: &Graph,
    reference: &Graph,
    options: CompareOptions,
    controls: &LvsControls,
) -> (Verdict, Vec<(Side, Merge)>) {
    let mut declared = reference.clone();
    drop_unextracted_bulk(layout, &mut declared);
    let reference_rows = drop_ignored_devices(&mut declared, controls);
    protect_labelled(layout, &mut declared);
    let mut measured = layout.clone();
    keep_declared_params(reference, &mut measured);
    let layout_rows = drop_ignored_devices(&mut measured, controls);
    drop_ignored_params(&mut measured, controls);
    drop_ignored_params(&mut declared, controls);
    assign_roles(&mut measured, controls);
    assign_roles(&mut declared, controls);
    let (mut layout, mut layout_merges) = reduce_with(&measured, options.params);
    let (mut reference, mut reference_merges) = reduce_with(&declared, options.params);
    restore_rows(&mut layout_merges, layout_rows.as_deref());
    restore_rows(&mut reference_merges, reference_rows.as_deref());
    if let Some(multiplier) = options.params.multiplier {
        state_count(&mut layout, multiplier);
        state_count(&mut reference, multiplier);
    }
    let merges = layout_merges
        .into_iter()
        .map(|m| (Side::Layout, m))
        .chain(reference_merges.into_iter().map(|m| (Side::Reference, m)))
        .collect();
    let mut partition = Partition::default();
    let budget = (options.max_rounds, options.param_tolerance);
    if !refine_into(
        (&layout, &reference),
        budget,
        (options.params, controls),
        &mut partition,
    ) {
        return (Verdict::Inconclusive(Inconclusive::RoundLimit), merges);
    }
    let mut verdict = interpret((&layout, &reference), &partition, (options, controls));
    if let Verdict::Mismatch(found) = &mut verdict {
        report_roles(found, &reference, controls);
    }
    (verdict, merges)
}

/// Writes the count every card has, `m = 1`, on each device that states
/// none. A card without `m` is one device whatever other cards state, so
/// its count is compared like any stated one: per-device presence
/// (testing-plan F68) is for measures, and a count is none. Without this, two
/// devices merged into `m = 2` matched a card stating no `m` once any card
/// named it.
fn state_count(graph: &mut Graph, multiplier: StrId) {
    let mut param = Vec::with_capacity(graph.param.len() + graph.device_count());
    let mut start = Vec::with_capacity(graph.device_count() + 1);
    start.push(0);
    for device in 0..narrow(graph.device_count()) {
        let params = graph.params_of(device);
        param.extend_from_slice(params);
        if !params.iter().any(|&(name, _)| name == multiplier) {
            param.push((multiplier, 1.0));
        }
        start.push(narrow(param.len()));
    }
    graph.param = param;
    graph.device_param_start = start;
}

/// A node no class paired with anything.
const UNPAIRED: u32 = u32::MAX;

fn interpret(
    (layout, reference): (&Graph, &Graph),
    partition: &Partition,
    (options, controls): (CompareOptions, &LvsControls),
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
    for &(layout_node, ref_node) in pairs.iter().filter(|pair| pair.0 < layout_devices) {
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
        let crossed = crossed(
            (layout, reference),
            (layout_node, ref_node),
            (layout_devices, ref_devices),
            &layout_mate,
        );
        compare_params(
            (layout, reference),
            (layout_node, ref_node),
            (options, controls, crossed),
            &mut scratch,
            &mut found,
        );
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

/// Whether a paired MOS's layout source is on its reference drain's net:
/// then the layout's `as` is the card's `ad`, and so on. A device whose
/// source and drain share a net, or that is no MOS, is never crossed.
fn crossed(
    (layout, reference): (&Graph, &Graph),
    pair: (u32, u32),
    (layout_devices, ref_devices): (u32, u32),
    layout_mate: &[u32],
) -> bool {
    let ((Some(source), Some(drain)), (_, Some(ref_drain))) = (
        channel_ends(layout, pair.0),
        channel_ends(reference, pair.1),
    ) else {
        return false;
    };
    let mate = |net: u32| {
        layout_devices
            .checked_add(net)
            .and_then(|node| layout_mate.get(node as usize).copied())
    };
    source != drain && mate(source) == ref_devices.checked_add(ref_drain)
}

/// The parameters the reference card states, each joined by name to the
/// layout's within its tolerance (`NaN` fails): the deck's row for the
/// reference model and that name, or the run's relative one, a count's
/// exactly ([`ParamNames::tolerance`]). The layout's
/// diffusions are read the other way round when the pair is `crossed`. One
/// the layout does not measure is [`Discrepancy::UndeclaredParam`], never a
/// pass. One only the layout measures is not compared: presence is per
/// device, and a card that omits a parameter states nothing about it
/// (testing-plan F68).
fn compare_params(
    (layout, reference): (&Graph, &Graph),
    pair: (u32, u32),
    (options, controls, crossed): (CompareOptions, &LvsControls, bool),
    scratch: &mut JoinScratch,
    found: &mut Vec<Discrepancy>,
) {
    let model = reference.device_model[pair.1 as usize];
    let (mine, theirs) = (&mut scratch.layout_params, &mut scratch.ref_params);
    mine.clear();
    mine.extend(
        layout
            .params_of(pair.0)
            .iter()
            .filter_map(|&(name, value)| {
                let name = if crossed {
                    options.params.across(name)?
                } else {
                    name
                };
                Some((name, value))
            }),
    );
    theirs.clear();
    theirs.extend_from_slice(reference.params_of(pair.1));

    // Stable: rows sharing a name pair off in declaration order.
    mine.sort_by_key(|&(name, _)| name);
    theirs.sort_by_key(|&(name, _)| name);

    let (mut at_mine, mut at_theirs) = (0usize, 0usize);
    while at_mine < mine.len() && at_theirs < theirs.len() {
        let ((layout_param, layout_value), (ref_param, ref_value)) =
            (mine[at_mine], theirs[at_theirs]);
        if layout_param < ref_param {
            // Measured, but this card says nothing about it.
            at_mine += 1;
            continue;
        }
        if layout_param > ref_param {
            found.push(undeclared_param(pair, ref_param));
            at_theirs += 1;
            continue;
        }
        at_mine += 1;
        at_theirs += 1;

        let within = bound(
            controls,
            options.params.tolerance(ref_param, options.param_tolerance),
            model,
            ref_param,
        );
        if !within.agree(layout_value, ref_value) {
            found.push(Discrepancy::ParameterMismatch {
                layout_device: pair.0,
                ref_device: pair.1,
                param: layout_param,
                layout_value,
                ref_value,
            });
        }
    }

    for &(param, _) in &theirs[at_theirs..] {
        found.push(undeclared_param(pair, param));
    }
}

/// One parameter the reference card of a paired device states and the layout
/// does not measure.
const fn undeclared_param(pair: (u32, u32), param: StrId) -> Discrepancy {
    Discrepancy::UndeclaredParam {
        side: Side::Reference,
        layout_device: pair.0,
        ref_device: pair.1,
        param,
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
        // No terminal and no name: no netlist can state such a net, so it has
        // nothing to pair with (`lvs.floating_net` reports it on the layout).
        let invisible = graph.terminals_on(narrow(net)).is_empty() && graph.net_name[net].is_none();
        if partner == UNPAIRED && !invisible {
            found.push(Discrepancy::UnpairedNet {
                side,
                net: narrow(net),
                name: graph.net_name[net],
            });
        }
    }
}
