//! The comparison driver: refine, then read the partition as a verdict.

use crate::graph::{narrow, Graph, LayoutGraph, RefGraph};
use crate::refine::{refine_into, role_code, Partition, Refinement, TieBreak};
use crate::verdict::{Discrepancy, Inconclusive, Side, Verdict};
use gpurify_ingest::StrId;
use gpurify_topology::TerminalRole;
use std::cmp::Ordering;

/// How to run a comparison.
///
/// Every field changes what a run *concludes*, so each has a documented reason
/// to exist. None of them is a performance knob.
#[derive(Debug, Clone, Copy)]
pub struct CompareOptions {
    /// Bound on refinement rounds. Exceeding it yields
    /// [`Verdict::Inconclusive`], never a mismatch.
    pub max_rounds: u32,
    /// What to do with a genuine symmetry.
    pub tie_break: TieBreak,
    /// Relative tolerance for parametric comparison. Applied deliberately here,
    /// which is why `topology` measures devices in exact integers rather than
    /// accumulating a tolerance by accident upstream.
    pub param_tolerance: f64,
    /// Compare declared net names as well as structure. Off by default: a
    /// layout is allowed to name nets differently from its schematic, and
    /// requiring agreement turns a naming convention into an LVS failure.
    pub match_names: bool,
}

impl Default for CompareOptions {
    fn default() -> Self {
        Self {
            // Refinement propagates one hop per round, so the bound is a graph
            // diameter rather than a node count. The retired tree capped its
            // refinement loop at the same thousand.
            max_rounds: 1000,
            // Refusing by default would make every differential pair, current
            // mirror and decap array in a real design inconclusive.
            tie_break: TieBreak::LowestIndex,
            // Two percent relative, the W/L tolerance the retired deck reader
            // defaulted to (`PropertyTolerance::rel_pct`).
            param_tolerance: 0.02,
            match_names: false,
        }
    }
}

/// Compare one cell.
///
/// **Transform.** `scratch` is the caller's refinement state, reused across
/// every cell of a hierarchical run — the allocation that would otherwise
/// dominate a large comparison.
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
        // Neither outcome says anything about whether the netlists agree, and
        // neither has a path from here to `Match`.
        Refinement::Exhausted => Verdict::Inconclusive(Inconclusive::RoundLimit),
        Refinement::Symmetric => Verdict::Inconclusive(Inconclusive::UnresolvedSymmetry),
        Refinement::Complete | Refinement::Discrepant => {
            interpret(layout, reference, scratch, options)
        }
    }
}

/// Turn a stable partition into discrepancies.
///
/// **Decision** — pure, a partition and two graphs in, a verdict out, with no
/// mutation anywhere. Separate from [`compare`] because it is the part worth a
/// table of cases: constructed partitions in, expected discrepancy lists out,
/// with no refinement involved.
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

    // Not a bulk loop: one iteration per class refinement failed to resolve,
    // and a completed run has none.
    for (_class, layout_count, ref_count) in partition.unresolved() {
        debug_assert!(layout_count as usize <= layout_nodes);
        debug_assert!(ref_count as usize <= ref_nodes);

        // Equal counts are a symmetry refinement could not break, not a
        // difference. Its members are unpaired without being unpairable, and
        // `Partition` publishes class membership nowhere, so they cannot be
        // held back from the unpaired scan below — the honest answer is that
        // the comparison did not finish.
        //
        // This masks any genuine discrepancy sharing the partition. Telling the
        // two apart needs a `members(ClassId)` accessor on `Partition`, which
        // is a frozen signature; it is filed under `## lvs` in
        // `docs/SIGNATURE_DEFECTS.md` and is not the Implementation-Phase's to
        // add. Inconclusive is the fail-closed reading in the meantime.
        if layout_count == ref_count && layout_count > 0 {
            return Verdict::Inconclusive(Inconclusive::UnresolvedSymmetry);
        }
        // More than one node on each side, so no individual node can be blamed
        // for the difference in counts.
        //
        // For the same missing accessor, this class's members are also counted
        // individually by the unpaired scan below, so the general form and the
        // specific one are both reported where `Discrepancy::ClassImbalance`
        // documents one. Suppressing the specific form needs the same
        // `members(ClassId)` accessor; same ledger entry.
        if layout_count > 1 && ref_count > 1 {
            found.push(Discrepancy::ClassImbalance {
                layout_nodes: layout_count,
                ref_nodes: ref_count,
            });
        }
    }

    // Read once. `pairs()` derives the class tallies and materialises the pair
    // list on every call, so the two passes below share one list rather than
    // paying two tally passes over every node and two allocations. The scatter
    // has to finish before the terminal pass starts anyway — a terminal is
    // described by the reference node its net was paired with, which is what
    // the scatter is building.
    let pairs: Vec<(u32, u32)> = partition.pairs().collect();

    // `u32::MAX` is "no counterpart"; a node index that large is unreachable
    // through columns the graph itself indexes with `u32`.
    //
    // A scatter: the write index is the row's own value, so the store is
    // random rather than contiguous and does not vectorise without
    // lane-conflict detection. Scalar by that fact about the data.
    let mut layout_mate = vec![u32::MAX; layout_nodes];
    let mut ref_mate = vec![u32::MAX; ref_nodes];
    for &(layout_node, ref_node) in &pairs {
        debug_assert!((layout_node as usize) < layout_nodes, "pair names no node");
        debug_assert!((ref_node as usize) < ref_nodes, "pair names no node");
        debug_assert_eq!(
            layout_mate[layout_node as usize],
            u32::MAX,
            "layout node {layout_node} paired twice"
        );
        debug_assert_eq!(
            ref_mate[ref_node as usize],
            u32::MAX,
            "reference node {ref_node} paired twice"
        );
        layout_mate[layout_node as usize] = ref_node;
        ref_mate[ref_node as usize] = layout_node;
    }

    // A pairing refinement proposed is a candidate until the terminals and the
    // parameters agree with it; accepting it unchecked is the false match the
    // crate's second doc section forbids.
    //
    // A dispatcher over the paired nodes, not a bulk transform: one iteration
    // appends a variable number of rows to `found` through one of two branches,
    // so neither the output index nor the trip count is affine in the input
    // index. `scratch` is hoisted above the loop so the two per-device joins
    // allocate once for the whole comparison and grow to the widest device the
    // run holds.
    let mut scratch = JoinScratch::default();
    for &(layout_node, ref_node) in &pairs {
        let is_device = layout_node < layout_devices;
        debug_assert_eq!(
            is_device,
            ref_node < ref_devices,
            "refinement paired a device with a net"
        );
        // `pairs()` is ascending by layout node and nodes are devices then
        // nets, so this flips at most once over the whole loop.
        if is_device {
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
            // `match_names` is a uniform, constant across the whole loop.
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

    // A clean verdict is only entitled to be clean when every node on both
    // sides paired. "Nothing to report" must not be reachable from "we did not
    // look".
    debug_assert!(
        !found.is_empty()
            || (layout_mate.iter().all(|&mate| mate != u32::MAX)
                && ref_mate.iter().all(|&mate| mate != u32::MAX)),
        "a match with unpaired nodes"
    );

    if found.is_empty() {
        Verdict::Match
    } else {
        Verdict::Mismatch(found)
    }
}

/// The join buffers one paired device needs, owned by [`interpret`].
///
/// **Five questions.** In: one device's terminal and parameter rows off two
/// graphs. Out: the same rows sorted, so the two sides can be walked in step.
/// How many: at most four terminals (`checks::LEGAL_WIDTHS`) and a handful of
/// parameters per device, but one device per paired row of the whole netlist.
/// Lifetime: the comparison — cleared and refilled per device, never resized
/// down, so the allocation is paid once and not once per device. Parallelisable:
/// per device, if the pairs loop ever is; each device reads only its own rows.
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

/// One terminal of a paired device the other side has no connection for.
///
/// **Decision.** Both sides report through it, so a finding about the reference
/// device names the same pair as one about the layout device and the report is
/// the mirror image of the reversed comparison.
const fn unmatched_terminal(pair: (u32, u32), role: TerminalRole) -> Discrepancy {
    Discrepancy::TerminalMismatch {
        layout_device: pair.0,
        ref_device: pair.1,
        role,
    }
}

/// One paired device's terminals: each role landing on nets that are each
/// other's counterpart.
///
/// # Matched by role, not by slot
///
/// The two sides list one device's terminals in different orders *on purpose*.
/// `topology::role_at` names the gate at position 0 because a recogniser's
/// terminal layers are listed geometry-first; `graph::card_role` names the drain
/// at position 0 because that is SPICE's `M` card order. Both are recorded as
/// resolved in `docs/SIGNATURE_DEFECTS.md`, which says in as many words that the
/// two orders *meet in `lvs`* — here.
///
/// So a slot-by-slot comparison reported a `TerminalMismatch` on every MOS and
/// every BJT the refiner had just paired correctly, and no test caught it
/// because every fixture builds both sides through one helper. The refiner folds
/// `(role, class)` commutatively for the same reason; this pass now agrees with
/// it.
///
/// # Sorted, then walked in step
///
/// Both sides' keys are sorted and merged, so what survives on either side is
/// the multiset difference: equal keys pair off one for one in slot order, which
/// is what a device with two interchangeable pins needs — two counterparts, not
/// one counterpart twice. `role_code` collapses `Pin(_)` to one code, which is
/// what `TerminalRole::Pin` documents and what the refiner already assumes.
///
/// The rank scan this replaced re-evaluated both key functions inside two nested
/// filters, so one four-terminal device cost tens of gathers into `layout_mate`
/// per direction and both directions ran. Each key is now computed once.
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
    debug_assert_eq!(layout_nets.len(), layout_roles.len(), "a terminal without a role");
    debug_assert_eq!(ref_nets.len(), ref_roles.len(), "a terminal without a role");

    let (mine, theirs) = (&mut scratch.layout_terminals, &mut scratch.ref_terminals);
    mine.clear();
    mine.reserve(layout_roles.len());
    theirs.clear();
    theirs.reserve(ref_roles.len());

    // Both sides' terminals in one index space — the reference one. A layout
    // terminal is described by the reference node its net was paired with, so
    // two terminals of a paired device name the same connection exactly when
    // their keys are equal, whatever slot each sits in.
    //
    // Neither of the two loops below is bulk: at most four terminals a side,
    // `checks::LEGAL_WIDTHS` carries the same bound, and the taken side of each
    // branch allocates a `Discrepancy` a sound device never reaches.
    for slot in 0..layout_roles.len() {
        // Fail closed. A terminal on no net, or on a net nothing paired, agrees
        // with nothing — including another such terminal. Letting two of them
        // cancel is how an unconnected gate reads as a matching one. `u32::MAX`
        // is `NetId::NONE` projected, so the add overflows and is caught here.
        match layout_devices
            .checked_add(layout_nets[slot])
            .and_then(|node| layout_mate.get(node as usize).copied())
            .filter(|&mate| mate != u32::MAX)
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

    // The slot is the last field, so the sort is a total order and two terminals
    // carrying one connection stay in declaration order — the merge below pairs
    // the earliest slots first, which is the rank rule stated as an ordering.
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
        // Not a bulk loop, same four-terminal bound as above, and two of the
        // three arms allocate.
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

    // Both tails are drained, not just the layout one, so the report is the
    // mirror image of the reversed comparison — the law
    // `swapping_the_two_sides_reverses_every_side_in_the_report` states.
    for &(_, _, slot) in &mine[at_mine..] {
        found.push(unmatched_terminal(pair, layout_roles[slot as usize]));
    }
    for &(_, _, slot) in &theirs[at_theirs..] {
        found.push(unmatched_terminal(pair, ref_roles[slot as usize]));
    }
}

/// One paired device's parameters, within the run's relative tolerance.
///
/// The spread is taken against the larger magnitude, which is the reading that
/// two equal values pass at any tolerance and that a value against zero fails
/// at every tolerance below one. A `NaN` on either side compares false and is
/// reported, which is the direction a tolerance test has to fail in.
///
/// # Keyed by name, not by position
///
/// Both sides are sorted by parameter name and walked in step. The position-wise
/// scan this replaced took `min` of the two lengths, so a reference device
/// declaring `W L M` against a layout device declaring `W L` compared two
/// parameters and dropped the third without saying so — a clean parametric
/// result for a parameter never looked at, which is the fail-open
/// `docs/VOCABULARY.md` §3 names. It also compared slot against slot, so two
/// sides declaring `W L` and `L W` reported both as beyond tolerance while
/// nothing was wrong.
///
/// A name only one side declares is passed over rather than reported, and that
/// is a deliberate reading, not the truncation coming back: the parameter sets
/// are the two sides' own, an extracted device carries what the recogniser could
/// measure and a card carries what its model needed, and a real deck states
/// which parameters a comparison covers. `Discrepancy` has no variant that can
/// say "declared on one side only" — `ParameterMismatch` needs two values — so
/// saying it at all is a frozen-signature question, filed under `## lvs` in
/// `docs/SIGNATURE_DEFECTS.md`.
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
    // it. `f64` is not `Ord`, which is why the key is the name alone rather than
    // the whole row.
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
        // Not a bulk loop: one device's declared parameters, single digits, and
        // the reporting arm allocates a `Discrepancy` a device within tolerance
        // never reaches.
        if layout_param != ref_param {
            at_mine += usize::from(layout_param < ref_param);
            at_theirs += usize::from(ref_param < layout_param);
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
    // There is no "renamed net" discrepancy, and inventing one would be a
    // signature change: two nets that must not pair are two unpaired nets, one
    // per side, which is also what keeps the report the mirror image of the
    // reversed comparison.
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
/// Two scalar loops, and they stay scalar: this is a compact carrying a payload
/// the predicate did not compute — the surviving row is a `Discrepancy` built
/// from the row index and a cold side-table column, not from the mate column
/// being scanned. The payload gather is random access off a cold table, so the
/// compact has nothing contiguous to widen.
fn report_unpaired(graph: &Graph, mate: &[u32], side: Side, found: &mut Vec<Discrepancy>) {
    let devices = graph.device_count();
    debug_assert_eq!(mate.len(), devices + graph.net_count());
    debug_assert_eq!(graph.device_model.len(), devices);
    debug_assert_eq!(graph.net_name.len(), graph.net_count());

    // Both loops: the taken side allocates a `Discrepancy`, and a matched run
    // takes it for no node at all, so selectivity sits at an end of its range
    // and the branch predicts.
    for (device, &partner) in mate[..devices].iter().enumerate() {
        if partner == u32::MAX {
            found.push(Discrepancy::UnpairedDevice {
                side,
                device: narrow(device),
                model: graph.device_model[device],
            });
        }
    }
    for (net, &partner) in mate[devices..].iter().enumerate() {
        if partner == u32::MAX {
            found.push(Discrepancy::UnpairedNet {
                side,
                net: narrow(net),
                name: graph.net_name[net],
            });
        }
    }
}
