//! The comparison driver: refine, then read the partition as a verdict.

use crate::lvs::graph::{narrow, Graph, LayoutGraph, RefGraph};
use crate::lvs::refine::{is_symmetric, refine_into, role_code, Partition, Refinement, TieBreak};
use crate::lvs::verdict::{Discrepancy, Inconclusive, Side, Verdict};
use crate::topology::TerminalRole;
use gpurify_ingest::StrId;
use std::cmp::Ordering;

/// How to run a comparison. Every field changes what a run concludes; none is a
/// performance knob.
#[derive(Debug, Clone, Copy)]
pub struct CompareOptions {
    /// Bound on refinement rounds. Exceeding it yields
    /// [`Verdict::Inconclusive`], never a mismatch.
    pub max_rounds: u32,
    /// What to do with a genuine symmetry.
    pub tie_break: TieBreak,
    /// Relative tolerance for parametric comparison, applied only here so that
    /// `topology` can measure devices in exact integers.
    pub param_tolerance: f64,
    /// Compare declared net names as well as structure. Off by default: a layout
    /// may legitimately name nets differently from its schematic.
    pub match_names: bool,
}

impl Default for CompareOptions {
    fn default() -> Self {
        Self {
            // Refinement propagates one hop per round, so the bound is a graph
            // diameter rather than a node count.
            max_rounds: 1000,
            // Refusing by default would make every differential pair, current
            // mirror and decap array inconclusive.
            tie_break: TieBreak::LowestIndex,
            // Two percent relative, the usual W/L tolerance.
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
    debug_assert!(
        options.param_tolerance >= 0.0,
        "a negative tolerance rejects every parameter"
    );

    match refine_into(
        layout,
        reference,
        options.tie_break,
        options.max_rounds,
        scratch,
    ) {
        // Neither outcome says anything about whether the netlists agree.
        Refinement::Exhausted => Verdict::Inconclusive(Inconclusive::RoundLimit),
        Refinement::Symmetric => Verdict::Inconclusive(Inconclusive::UnresolvedSymmetry),
        Refinement::Complete | Refinement::Discrepant => {
            interpret(layout, reference, scratch, options)
        }
    }
}

/// A node no class paired with anything. Unreachable as a node index.
const UNPAIRED: u32 = u32::MAX;

/// A node in an unresolved class holding the same count on both sides: unpaired
/// without being unpairable.
const HELD_BACK: u32 = u32::MAX - 1;

/// Turn a stable partition into discrepancies.
pub fn interpret(
    layout: &LayoutGraph,
    reference: &RefGraph,
    partition: &Partition,
    options: CompareOptions,
) -> Verdict {
    let layout = &layout.0;
    let reference = &reference.0;
    debug_assert!(
        options.param_tolerance >= 0.0,
        "a negative tolerance rejects every parameter"
    );

    let layout_devices = narrow(layout.device_count());
    let ref_devices = narrow(reference.device_count());
    let layout_nodes = layout.device_count() + layout.net_count();
    let ref_nodes = reference.device_count() + reference.net_count();

    let mut found: Vec<Discrepancy> = Vec::new();

    for (_class, layout_count, ref_count) in partition.unresolved() {
        debug_assert!(layout_count as usize <= layout_nodes);
        debug_assert!(ref_count as usize <= ref_nodes);

        // Equal counts are a symmetry, not a difference; the members are held
        // back below rather than blamed. Do not return early: a difference no
        // pairing can mend must survive a symmetry any pairing satisfies.
        if is_symmetric(layout_count, ref_count) {
            continue;
        }
        // More than one node per side, so no individual node can be blamed. These
        // members are *also* counted by the unpaired scan below; the double
        // report is deliberate, over-reporting being the fail-closed direction.
        if layout_count > 1 && ref_count > 1 {
            found.push(Discrepancy::ClassImbalance {
                layout_nodes: layout_count,
                ref_nodes: ref_count,
            });
        }
    }

    // Read before the scatter: the two are written into the same columns, and a
    // node is paired, or held back, or neither.
    let (layout_symmetric, ref_symmetric) = partition.symmetric_nodes();
    let symmetric = !layout_symmetric.is_empty();

    // `pairs()` retallies and reallocates on every call, so the two passes below
    // share one list.
    let pairs: Vec<(u32, u32)> = partition.pairs().collect();

    let mut layout_mate = vec![UNPAIRED; layout_nodes];
    let mut ref_mate = vec![UNPAIRED; ref_nodes];
    for &(layout_node, ref_node) in &pairs {
        debug_assert!((layout_node as usize) < layout_nodes, "pair names no node");
        debug_assert!((ref_node as usize) < ref_nodes, "pair names no node");
        debug_assert_eq!(
            layout_mate[layout_node as usize], UNPAIRED,
            "layout node {layout_node} paired twice"
        );
        debug_assert_eq!(
            ref_mate[ref_node as usize], UNPAIRED,
            "reference node {ref_node} paired twice"
        );
        layout_mate[layout_node as usize] = ref_node;
        ref_mate[ref_node as usize] = layout_node;
    }

    // The third state, over the same columns: both readers have to tell a
    // held-back node from an unpairable one.
    for (column, symmetric) in [
        (&mut layout_mate, &layout_symmetric),
        (&mut ref_mate, &ref_symmetric),
    ] {
        for &node in symmetric {
            debug_assert_eq!(
                column[node as usize], UNPAIRED,
                "node {node} is both paired and in an unresolved class"
            );
            column[node as usize] = HELD_BACK;
        }
    }

    // A proposed pairing is a candidate until the terminals and parameters agree
    // with it; accepting it unchecked is a false match.
    let mut scratch = JoinScratch::default();
    for &(layout_node, ref_node) in &pairs {
        let is_device = layout_node < layout_devices;
        debug_assert_eq!(
            is_device,
            ref_node < ref_devices,
            "refinement paired a device with a net"
        );
        if is_device {
            compare_identity(layout, reference, (layout_node, ref_node), &mut found);
            compare_terminals(
                layout,
                reference,
                (layout_node, ref_node),
                (layout_devices, ref_devices),
                (&layout_mate, &ref_mate),
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

    // A clean verdict is only clean when every node on both sides paired.
    let matched = found.is_empty() & !symmetric;
    debug_assert!(
        !matched
            || (layout_mate.iter().all(|&mate| mate < HELD_BACK)
                && ref_mate.iter().all(|&mate| mate < HELD_BACK)),
        "a match with unpaired nodes"
    );

    // Order matters: a difference beside an unbroken symmetry is still a
    // difference; an unbroken symmetry alone is a comparison that did not finish.
    if !found.is_empty() {
        Verdict::Mismatch(found)
    } else if symmetric {
        Verdict::Inconclusive(Inconclusive::UnresolvedSymmetry)
    } else {
        Verdict::Match
    }
}

/// The join buffers one paired device needs, owned by [`interpret`].
#[derive(Default)]
struct JoinScratch {
    /// `(role code, reference node, slot)` per terminal of the layout device.
    layout_terminals: Vec<(u64, u32, u32)>,
    /// The same for the reference device, already in reference node space.
    ref_terminals: Vec<(u64, u32, u32)>,
    /// One device's declared parameters, sorted by name.
    layout_params: Vec<(StrId, f64)>,
    ref_params: Vec<(StrId, f64)>,
}

/// One paired device's identity: the two columns that say *what it is*.
///
/// Structure is not identity — an nfet and a pfet wired identically have the same
/// neighbourhood, and [`interpret`] is `pub`, so a partition refinement did not
/// produce can be handed to it. Two devices that must not pair are reported as
/// two unpaired devices, one per side.
fn compare_identity(
    layout: &Graph,
    reference: &Graph,
    pair: (u32, u32),
    found: &mut Vec<Discrepancy>,
) {
    let (mine, theirs) = (pair.0 as usize, pair.1 as usize);
    debug_assert!(mine < layout.device_count(), "pair names no layout device");
    debug_assert!(
        theirs < reference.device_count(),
        "pair names no reference device"
    );

    let (layout_model, ref_model) = (layout.device_model[mine], reference.device_model[theirs]);
    let same =
        (layout.device_kind[mine] == reference.device_kind[theirs]) & (layout_model == ref_model);
    if same {
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

/// One terminal of a paired device the other side has no connection for. Both
/// sides report through it, so the report mirrors the reversed comparison.
const fn unmatched_terminal(pair: (u32, u32), role: TerminalRole) -> Discrepancy {
    Discrepancy::TerminalMismatch {
        layout_device: pair.0,
        ref_device: pair.1,
        role,
    }
}

/// One paired device's terminals: each role landing on nets that are each other's
/// counterpart.
///
/// Matched by role, never by slot — `topology::role_at` lists a MOS gate-first
/// and `graph::card_role` drain-first, and the two orders meet here. The sorted
/// merge leaves the multiset difference, so a device with two interchangeable
/// pins gets two counterparts rather than one counterpart twice.
///
/// A terminal on a [`HELD_BACK`] net is skipped rather than blamed. That is not
/// fail-open only because [`interpret`] cannot return `Match` while a held-back
/// node exists, and because both sides skip.
fn compare_terminals(
    layout: &Graph,
    reference: &Graph,
    pair: (u32, u32),
    devices: (u32, u32),
    mates: (&[u32], &[u32]),
    scratch: &mut JoinScratch,
    found: &mut Vec<Discrepancy>,
) {
    let (layout_device, ref_device) = pair;
    let (layout_devices, ref_devices) = devices;
    let (layout_mate, ref_mate) = mates;
    let (layout_nets, layout_roles) = layout.terminals_of(layout_device);
    let (ref_nets, ref_roles) = reference.terminals_of(ref_device);
    debug_assert_eq!(
        layout_nets.len(),
        layout_roles.len(),
        "a terminal without a role"
    );
    debug_assert_eq!(ref_nets.len(), ref_roles.len(), "a terminal without a role");

    let (mine, theirs) = (&mut scratch.layout_terminals, &mut scratch.ref_terminals);
    mine.clear();
    mine.reserve(layout_roles.len());
    theirs.clear();
    theirs.reserve(ref_roles.len());

    // Both sides' terminals in one index space — the reference one — so two keys
    // are equal exactly when they name the same connection, whatever slot.
    for slot in 0..layout_roles.len() {
        // Fail closed: a terminal on no net, or on a net nothing paired, agrees
        // with nothing, including another such terminal. `UNPAIRED` is
        // `NetId::NONE` projected, so the add overflows and is caught here.
        match layout_devices
            .checked_add(layout_nets[slot])
            .and_then(|node| layout_mate.get(node as usize).copied())
            .filter(|&mate| mate != UNPAIRED)
        {
            // A symmetric net: unpaired, and not a difference either.
            Some(HELD_BACK) => {}
            Some(mate) => mine.push((role_code(layout_roles[slot]), mate, narrow(slot))),
            None => found.push(unmatched_terminal(pair, layout_roles[slot])),
        }
    }
    for slot in 0..ref_roles.len() {
        match ref_devices
            .checked_add(ref_nets[slot])
            .map(|node| (node, ref_mate.get(node as usize).copied()))
        {
            Some((_, Some(HELD_BACK))) => {}
            Some((node, _)) => theirs.push((role_code(ref_roles[slot]), node, narrow(slot))),
            None => found.push(unmatched_terminal(pair, ref_roles[slot])),
        }
    }

    // The slot is the last key field, so two terminals carrying one connection
    // stay in declaration order.
    mine.sort_unstable();
    theirs.sort_unstable();
    debug_assert!(
        mine.windows(2).all(|run| run[0] < run[1]),
        "two layout terminals of one device claim the same slot"
    );
    debug_assert!(
        theirs.windows(2).all(|run| run[0] < run[1]),
        "two reference terminals of one device claim the same slot"
    );

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

    // Both tails, not just the layout one, so the report is the mirror image of
    // the reversed comparison.
    for &(_, _, slot) in &mine[at_mine..] {
        found.push(unmatched_terminal(pair, layout_roles[slot as usize]));
    }
    for &(_, _, slot) in &theirs[at_theirs..] {
        found.push(unmatched_terminal(pair, ref_roles[slot as usize]));
    }
}

/// One paired device's parameters, within the run's relative tolerance.
///
/// The spread is taken against the larger magnitude, so a value against zero
/// fails at every tolerance below one; a `NaN` compares false and is reported.
///
/// Keyed by name, not by position, and a name only one side declares is a
/// [`Discrepancy::UndeclaredParam`], not a pass: passing over the symmetric
/// difference would compare zero parameters and return [`Verdict::Match`].
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

    // Stable, so two rows sharing a name keep declaration order and pair off in
    // it. `f64` is not `Ord`, so the key is the name alone, not the whole row.
    mine.sort_by_key(|&(name, _)| name);
    theirs.sort_by_key(|&(name, _)| name);
    debug_assert!(
        mine.windows(2).all(|run| run[0].0 <= run[1].0),
        "the layout parameter join is walking an unsorted list"
    );
    debug_assert!(
        theirs.windows(2).all(|run| run[0].0 <= run[1].0),
        "the reference parameter join is walking an unsorted list"
    );

    let (mut at_mine, mut at_theirs) = (0usize, 0usize);
    while at_mine < mine.len() && at_theirs < theirs.len() {
        let ((layout_param, layout_value), (ref_param, ref_value)) =
            (mine[at_mine], theirs[at_theirs]);
        if layout_param != ref_param {
            // Whichever name sorts first is the one the other side never
            // declares, so it is reported and only its cursor advances.
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

    // Both tails, so the report is the mirror image of the reversed comparison.
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
    // There is no "renamed net" discrepancy: two nets that must not pair are two
    // unpaired nets, one per side.
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

/// Every node of one side that no class paired, named as a discrepancy.
///
/// `== UNPAIRED` and not `>= HELD_BACK`: a node in a balanced unresolved class is
/// unpaired without being unpairable, and skipping it is safe only because
/// [`interpret`] cannot return `Match` while one exists.
fn report_unpaired(graph: &Graph, mate: &[u32], side: Side, found: &mut Vec<Discrepancy>) {
    let devices = graph.device_count();
    debug_assert_eq!(mate.len(), devices + graph.net_count());
    debug_assert_eq!(graph.device_model.len(), devices);
    debug_assert_eq!(graph.net_name.len(), graph.net_count());

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
