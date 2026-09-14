//! The comparison driver: refine, then read the partition as a verdict.

use crate::graph::{narrow, Graph, LayoutGraph, RefGraph};
use crate::refine::{is_symmetric, refine_into, role_code, Partition, Refinement, TieBreak};
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

/// A node no class paired with anything.
///
/// Unreachable as a node index: both graphs index their own nodes with a `u32`,
/// so a column of them cannot be `u32::MAX` rows long.
const UNPAIRED: u32 = u32::MAX;

/// A node sitting in an unresolved class that holds the same count on both
/// sides — *unpaired without being unpairable*.
///
/// The second sentinel rather than a parallel `Vec<bool>`, because the two
/// passes that need it already carry the mate column, and a node is in exactly
/// one of the three states. Unreachable for the same reason [`UNPAIRED`] is.
const HELD_BACK: u32 = u32::MAX - 1;

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
        // difference: either pairing of the class's members is right, so
        // nothing in it is a discrepancy. Those members are held back below
        // rather than blamed, and the verdict cannot be `Match` while one
        // exists — `symmetric` carries that, and nothing here returns early.
        //
        // Returning on the first balanced class is what F4 had to fix. It
        // masked every genuine discrepancy sharing the partition: with a MOS
        // channel read as symmetric, a *deleted device* came back
        // `Inconclusive(UnresolvedSymmetry)` because the surviving
        // transistor's two channel nets were interchangeable. The two
        // conditions are independent, and a difference no pairing can mend
        // must survive a symmetry any pairing satisfies.
        if is_symmetric(layout_count, ref_count) {
            continue;
        }
        // More than one node on each side, so no individual node can be blamed
        // for the difference in counts.
        //
        // This class's members are *also* counted individually by the unpaired
        // scan below, where `Discrepancy::ClassImbalance` documents one form
        // per class. `Partition::symmetric_nodes` could hold them back the way
        // the balanced ones are held back, and that is deliberately not done:
        // `ClassImbalance` carries no node indices at all, so suppressing the
        // specific form would leave a reader with two counts and nothing to
        // open. Over-reporting is the fail-closed direction of the two. Filed
        // under `## lvs` in `docs/SIGNATURE_DEFECTS.md`.
        if layout_count > 1 && ref_count > 1 {
            found.push(Discrepancy::ClassImbalance {
                layout_nodes: layout_count,
                ref_nodes: ref_count,
            });
        }
    }

    // Read once, before the scatter, because the two are written into the same
    // columns: a node is paired, or held back, or neither.
    let (layout_symmetric, ref_symmetric) = partition.symmetric_nodes();
    let symmetric = !layout_symmetric.is_empty();

    // Read once. `pairs()` derives the class tallies and materialises the pair
    // list on every call, so the two passes below share one list rather than
    // paying two tally passes over every node and two allocations. The scatter
    // has to finish before the terminal pass starts anyway — a terminal is
    // described by the reference node its net was paired with, which is what
    // the scatter is building.
    let pairs: Vec<(u32, u32)> = partition.pairs().collect();

    // [`UNPAIRED`] is "no counterpart"; a node index that large is unreachable
    // through columns the graph itself indexes with `u32`.
    //
    // A scatter: the write index is the row's own value, so the store is
    // random rather than contiguous and does not vectorise without
    // lane-conflict detection. Scalar by that fact about the data.
    let mut layout_mate = vec![UNPAIRED; layout_nodes];
    let mut ref_mate = vec![UNPAIRED; ref_nodes];
    for &(layout_node, ref_node) in &pairs {
        debug_assert!((layout_node as usize) < layout_nodes, "pair names no node");
        debug_assert!((ref_node as usize) < ref_nodes, "pair names no node");
        debug_assert_eq!(
            layout_mate[layout_node as usize],
            UNPAIRED,
            "layout node {layout_node} paired twice"
        );
        debug_assert_eq!(
            ref_mate[ref_node as usize],
            UNPAIRED,
            "reference node {ref_node} paired twice"
        );
        layout_mate[layout_node as usize] = ref_node;
        ref_mate[ref_node as usize] = layout_node;
    }

    // The third state, written over the same columns. A symmetric class's
    // members are unpaired without being unpairable, so they carry neither a
    // mate nor the blame for not having one, and the two passes that read the
    // mate columns — the terminal join and `report_unpaired` — both have to
    // tell them from a node nothing could pair.
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
    // look", and a held-back node is exactly a node nobody looked at — the
    // compare is below both sentinels so neither state can reach `Match`.
    let matched = found.is_empty() & !symmetric;
    debug_assert!(
        !matched
            || (layout_mate.iter().all(|&mate| mate < HELD_BACK)
                && ref_mate.iter().all(|&mate| mate < HELD_BACK)),
        "a match with unpaired nodes"
    );

    // Order is the whole of finding F4. A difference found beside an unbroken
    // symmetry is still a difference — the symmetry says nothing about the
    // device that is missing — so it is reported rather than swallowed. An
    // unbroken symmetry with nothing else found is a comparison that did not
    // finish, and there is no path from that to `Match`.
    if !found.is_empty() {
        Verdict::Mismatch(found)
    } else if symmetric {
        Verdict::Inconclusive(Inconclusive::UnresolvedSymmetry)
    } else {
        Verdict::Match
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

/// One paired device's identity: the two columns that say *what it is*.
///
/// # Structure is not identity
///
/// [`compare_terminals`] proves the two devices sit in the same *place* in the
/// graph. It says nothing about what they *are*: an nfet and a pfet wired
/// identically have the same neighbourhood, and so do a resistor and a capacitor
/// across one pair of nets — [`role_code`] collapses `Pin(_)` on purpose, so not
/// even the roles separate those two.
///
/// Refinement folds [`Graph::device_kind`] and [`Graph::device_model`] into its
/// signature, so a pairing it *proposed* almost never crosses either column. But
/// that is a `wrapping_add` fold of neighbour hashes agreeing, not a comparison
/// happening, and [`interpret`] is `pub` precisely so a partition refinement did
/// not produce can be handed to it. Measured before this existed, in both
/// profiles: an identity pairing of a one-device `Mos`/`NCH` layout against a
/// one-device `Mos`/`PCH` reference, same terminals, returned
/// [`Verdict::Match`] — the one outcome this crate's documentation forbids.
///
/// # Two unpaired devices, not a new variant
///
/// The reading [`compare_net_name`] already takes for a renamed net, and for the
/// same reason it gives: two devices that must not pair are two unpaired
/// devices, one per side. [`Discrepancy::UnpairedDevice`] carries `model`
/// already, so the pair of rows names both models, and the report stays the
/// mirror image of the reversed comparison without a `side` field having to be
/// invented for a third shape.
///
/// The `if` is not a bulk-loop branch to remove: a sound netlist takes the
/// untaken side for every device, so selectivity sits at an end of its range and
/// the branch predicts, and the taken side allocates two `Discrepancy` rows.
fn compare_identity(
    layout: &Graph,
    reference: &Graph,
    pair: (u32, u32),
    found: &mut Vec<Discrepancy>,
) {
    let (mine, theirs) = (pair.0 as usize, pair.1 as usize);
    debug_assert!(mine < layout.device_count(), "pair names no layout device");
    debug_assert!(theirs < reference.device_count(), "pair names no reference device");

    let (layout_model, ref_model) = (layout.device_model[mine], reference.device_model[theirs]);
    let same = (layout.device_kind[mine] == reference.device_kind[theirs])
        & (layout_model == ref_model);
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
///
/// # A terminal on a held-back net is skipped, not blamed
///
/// [`HELD_BACK`] marks a net whose class refinement could not resolve and whose
/// two sides hold the same count — a symmetry, where either pairing is right.
/// Such a net has no counterpart *named*, but it is not a net the other side
/// lacks, so reporting the terminal on it as a [`Discrepancy::TerminalMismatch`]
/// invents a difference: it made every MOS in a comparison that refused a tie
/// report both channel terminals as unmatched, on a transistor with nothing
/// wrong with it.
///
/// Skipping is not fail-open, and only because [`interpret`] pairs it with a
/// verdict that cannot be `Match` while any held-back node exists. Both sides
/// are skipped — hence `ref_mate` — so the merge below still sees equal-length
/// lists and a genuine imbalance still drains a tail.
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
        // cancel is how an unconnected gate reads as a matching one. `UNPAIRED`
        // is `NetId::NONE` projected, so the add overflows and is caught here.
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
/// # A name only one side declares is a finding, not a pass
///
/// It used to be passed over, on the reading that the two parameter sets are the
/// two sides' own — an extracted device carries what the recogniser could
/// measure, a card carries what its model needed. That reading is wrong in the
/// one direction that matters. Passing over the symmetric difference means a
/// reference declaring `W L` against a layout declaring *nothing* compares zero
/// parameters, finds nothing, and returns [`Verdict::Match`]: a clean parametric
/// result for a comparison that never looked, which is the same fail-open shape
/// the position-wise scan above had, arriving by a different route. It is
/// finding F8, and it was reachable from every parametric run in the tree
/// because `graph::from_layout_into` projects no layout parameter at all.
///
/// [`Discrepancy::UndeclaredParam`] is the variant that says it. Both tails are
/// drained, so the report is the mirror image of the reversed comparison — the
/// law `swapping_the_two_sides_reverses_every_side_in_the_report` states for
/// terminals, and the reason the `side` field is on the variant.
///
/// A deck that genuinely wants a parameter uncompared says so by not declaring
/// it on *either* side, which this join reads as agreement because there is
/// nothing there to disagree about.
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
            // Whichever name sorts first is the one the other side never
            // declares, so it is reported and only its cursor advances.
            let mine_first = layout_param < ref_param;
            found.push(undeclared_param(
                pair,
                if mine_first { Side::Layout } else { Side::Reference },
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

    // Both tails, not just the layout one, for the reason the terminal join
    // above drains both: the report has to be the mirror image of the reversed
    // comparison. A tail is every name the shorter side ran out before reaching.
    for &(param, _) in &mine[at_mine..] {
        found.push(undeclared_param(pair, Side::Layout, param));
    }
    for &(param, _) in &theirs[at_theirs..] {
        found.push(undeclared_param(pair, Side::Reference, param));
    }
}

/// One parameter of a paired device that only `side` declares.
///
/// **Decision.** Both sides report through it, so a finding about the reference
/// card names the same pair as one about the layout device — the shape
/// [`unmatched_terminal`] has, and for the same reason.
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
/// [`HELD_BACK`] is the reason the test is `== UNPAIRED` rather than
/// `>= HELD_BACK`: a node in a balanced unresolved class is unpaired without
/// being unpairable, and blaming it reports a difference that is not there.
/// Skipping it is safe only because [`interpret`] cannot return `Match` while
/// one exists.
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
