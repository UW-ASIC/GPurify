//! Partition refinement: the matching algorithm.
//!
//! Both graphs' nodes start in one class each — all devices together, all nets
//! together — and are split repeatedly by a signature computed from their
//! neighbours' current classes. When no class splits further, classes
//! containing exactly one node from each side are a forced pairing.
//!
//! This is the standard netlist-comparison approach, and it is chosen here for
//! a specific reason: it is *deterministic*. It never picks a node arbitrarily,
//! so it produces the same partition regardless of iteration order or thread
//! count, which the determinism gate requires. Where it stalls — a symmetric
//! structure where several nodes are genuinely interchangeable — the tie is
//! broken by a rule stated in [`TieBreak`], never by whatever the hash order
//! happened to be.

use crate::graph::{narrow, Graph, LayoutGraph, RefGraph};
use gpurify_core::observe::{NoObserve, Observer};
use gpurify_ingest::deck::DeviceKind;
use gpurify_topology::TerminalRole;

/// A class of nodes not yet distinguished from each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ClassId(pub u32);

/// The refinement state for both graphs.
///
/// **Five questions.** In: two graphs. Out: a partition of both node sets into
/// shared classes. How many: one per comparison, sized by node count. Access
/// pattern: every round reads every node's neighbour classes and writes its own
/// new class — a textbook two-pass transform, never read-what-you-just-wrote.
/// Lifetime: one comparison; every buffer is reused across rounds. Parallelisable:
/// the signature pass is; the renumbering pass is a sort.
///
#[derive(Debug, Default)]
pub struct Partition {
    /// Class of each layout node, devices then nets.
    layout_class: Vec<ClassId>,
    ref_class: Vec<ClassId>,
    /// Scratch for the next round. Two buffers swapped, so a round never reads
    /// what it wrote — the kernel rule, applied to a graph algorithm.
    next_layout: Vec<ClassId>,
    next_ref: Vec<ClassId>,
    /// Per-node signature for the current round, sorted to renumber classes.
    signature: Vec<(u64, u32)>,
    class_count: u32,
}

/// Two partitions are equal when they assign the same classes to the same
/// nodes on both sides.
///
/// Hand-written rather than derived because the scratch columns are not part of
/// the value. A buffer reused from a previous comparison holds leftovers a
/// fresh one does not, and that those leftovers are unreadable is the whole
/// claim reuse rests on — a derive would make a correct implementation compare
/// unequal to itself across a reuse.
impl PartialEq for Partition {
    fn eq(&self, other: &Self) -> bool {
        self.class_count == other.class_count
            && self.layout_class == other.layout_class
            && self.ref_class == other.ref_class
    }
}

/// How to break a genuine symmetry.
///
/// Reached only when refinement stalls with classes holding more than one node
/// per side — a real symmetry, such as the two halves of a differential pair.
/// The choice must not depend on memory layout, so every option here is a total
/// order over something intrinsic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TieBreak {
    /// Lowest node index on each side. Deterministic and cheap, and correct
    /// whenever the symmetry is genuine — if the nodes really are
    /// interchangeable, either pairing is right.
    LowestIndex,
    /// Refuse. Report the symmetric group as a discrepancy instead of choosing.
    /// For a run that must not guess.
    Refuse,
}

/// What the refinement did, round by round.
///
/// Not derivable from the final partition: whether refinement converged in
/// three rounds or ninety, how many classes were split each round, and where it
/// stalled are the difference between a fast comparison and one that is about
/// to time out. This is the seam the work counters attach to.
pub trait ObserveRefine: Observer {
    fn round(&mut self, index: u32, classes: u32, split: u32);
    fn stalled(&mut self, class: ClassId, layout_nodes: u32, ref_nodes: u32);
    fn tie_broken(&mut self, class: ClassId);
}

impl ObserveRefine for NoObserve {
    fn round(&mut self, _index: u32, _classes: u32, _split: u32) {}
    fn stalled(&mut self, _class: ClassId, _layout_nodes: u32, _ref_nodes: u32) {}
    fn tie_broken(&mut self, _class: ClassId) {}
}

/// Refine until stable.
///
/// **Transform.** Caller owns `out`; its buffers are reused across rounds and
/// across comparisons, so a hierarchical run allocates once for the whole tree.
///
/// `max_rounds` bounds the work. Hitting it is not a mismatch and must not be
/// reported as one — it is [`Verdict::Inconclusive`](crate::Verdict), which is
/// the distinction the "never a false match" rule turns on.
pub fn refine_into(
    layout: &LayoutGraph,
    reference: &RefGraph,
    tie_break: TieBreak,
    max_rounds: u32,
    out: &mut Partition,
) -> Refinement {
    refine_observed(layout, reference, tie_break, max_rounds, out, &mut NoObserve)
}

/// How refinement ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refinement {
    /// No class split further and every class is a one-to-one pairing.
    Complete,
    /// Stable, but some class holds unequal counts from the two sides. That is
    /// a real structural difference and the classes involved name it.
    Discrepant,
    /// Stable with genuine symmetry remaining, and [`TieBreak::Refuse`] was in
    /// force.
    Symmetric,
    /// `max_rounds` was reached. Says nothing about whether the netlists match.
    Exhausted,
}

/// Splitmix64's finaliser. A signature is only ever compared with another
/// signature, never inverted and never resolved back to the neighbourhood that
/// produced it, so avalanche is the entire requirement.
const fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// A terminal's role as a number the signature can carry.
///
/// **Interchangeable roles share a code**, and that is the whole of what this
/// function decides. Two terminals compare equal exactly when their codes and
/// their paired nets agree — [`crate::compare`]'s terminal join keys its merge
/// on `(role_code, mate)` — so collapsing two roles here is precisely the
/// statement that a device written with those two exchanged is the same device.
///
/// `Pin(k)` collapses on purpose: [`TerminalRole::Pin`] asserts the two ends of
/// a symmetric two-terminal device are interchangeable, so letting the position
/// reach the signature would refuse to match a resistor written end-for-end. A
/// diode has no `Pin` for exactly the opposite reason.
///
/// `Emitter` and `Collector` do **not** collapse, and never will: a bipolar's
/// doping is asymmetric, so exchanging them makes a different — and much
/// worse — transistor.
/// `a_bipolars_emitter_and_collector_are_not_interchangeable` is the guard on
/// that, and it is what stops any future collapse being applied to everything.
///
/// # `Source` and `Drain` collapse, and that is finding F4
///
/// A MOS channel is symmetric; which end is the source is decided by *bias*,
/// not by layout, and an extractor reading geometry has nothing to decide it
/// with. `LVS_CLEAN_MATCH` and `LVS_SD_PERMUTE` are the same cell against
/// references that are exact S/D swaps and **both expect `Match`**, which no
/// S/D-distinguishing comparison can satisfy.
/// `a_mos_written_source_for_drain_is_the_same_transistor` is the unit-scale
/// statement of it, on a fixture whose two channel nets are anchored to
/// different degrees so that `Match` is not available to a relabelling.
///
/// # What the collapse costs, and where that is paid
///
/// It creates **genuine automorphisms** wherever a device's two channel nets
/// are otherwise indistinguishable — which is every isolated transistor and
/// most small fixtures. That is not a defect of the collapse; it is the
/// circuit being genuinely symmetric, and a comparison that claimed otherwise
/// was reading a distinction that physics does not make.
///
/// Two things had to be right before it could ship, and both are:
///
/// - `refine_observed` must break a balanced stall even when an *imbalanced*
///   class exists elsewhere in the same graph. Reading the two conditions as
///   one returned on the first imbalance, left the symmetry unbroken, and made
///   a deleted device read as an unfinished comparison. See the two
///   independent tests above `lowest == u32::MAX`.
/// - [`interpret`](crate::compare::interpret) must hold the members of a
///   balanced unresolved class back from the unpaired scan rather than blame
///   them, and must still report every class that is genuinely imbalanced.
///   [`Partition::symmetric_nodes`] is what tells the two apart, and
///   `an_unresolved_symmetry_does_not_mask_a_deleted_device` is the guard.
///
/// `TieBreak::LowestIndex` needed no change: it individualises one node per
/// stalled class per round, and a symmetric channel is one class, so one round
/// per device resolves it. Measured — every `LowestIndex` fixture in the suite
/// reaches `Refinement::Complete` or `Discrepant`, never `Exhausted`.
pub(crate) const fn role_code(role: TerminalRole) -> u64 {
    match role {
        TerminalRole::Gate => 0,
        TerminalRole::Source | TerminalRole::Drain => 1,
        TerminalRole::Bulk => 3,
        TerminalRole::Base => 4,
        TerminalRole::Emitter => 5,
        TerminalRole::Collector => 6,
        TerminalRole::Pin(_) => 7,
    }
}

const fn kind_code(kind: DeviceKind) -> u64 {
    match kind {
        DeviceKind::Mos => 0,
        DeviceKind::Bjt => 1,
        DeviceKind::Resistor => 2,
        DeviceKind::Capacitor => 3,
        DeviceKind::Diode => 4,
    }
}

/// Domain separators, so a device and a net with numerically equal
/// neighbourhoods cannot land on one signature.
const DEVICE_TAG: u64 = 0x01;
const NET_TAG: u64 = 0x11;
const NEIGHBOUR_TAG: u64 = 0x21;

/// One neighbour's contribution: its role and the class it currently sits in.
///
/// Folded into the node's signature with `wrapping_add`, which is commutative,
/// so the signature is a function of the *multiset* of neighbours and not of
/// the order a CSR row happens to store them in. That is what lets the layout
/// and the reference side disagree about terminal order without disagreeing
/// about structure.
const fn neighbour(role: TerminalRole, class: ClassId) -> u64 {
    mix(NEIGHBOUR_TAG ^ (role_code(role) << 8) ^ ((class.0 as u64) << 16))
}

/// A device's signature for one round: its own class, its intrinsic identity,
/// and the multiset of `(role, class)` over its terminals.
fn device_signature(graph: &Graph, device: u32, own: ClassId, net_class: &[ClassId]) -> u64 {
    let (nets, roles) = graph.terminals_of(device);
    debug_assert_eq!(nets.len(), roles.len(), "a terminal without a role");

    // `zip` rather than an index: the trip count is then one column's length and
    // neither load carries a bounds check. The `debug_assert_eq!` above is what
    // catches the columns disagreeing — a zip over unequal columns would fold the
    // shorter one and report a signature for a device it only half read.
    let mut neighbours = 0u64;
    for (&net, &role) in nets.iter().zip(roles) {
        neighbours = neighbours.wrapping_add(neighbour(role, net_class[net as usize]));
    }

    let head = mix(DEVICE_TAG ^ (u64::from(own.0) << 8));
    let head = mix(
        head ^ kind_code(graph.device_kind[device as usize])
            ^ (u64::from(graph.device_model[device as usize].0) << 8),
    );
    mix(head ^ neighbours)
}

/// A net's signature: its own class and the multiset of `(role, class)` over
/// the device terminals landing on it.
fn net_signature(graph: &Graph, net: u32, own: ClassId, device_class: &[ClassId]) -> u64 {
    // One column of `(device, role)` pairs, so there is no second length to
    // disagree with.
    let mut neighbours = 0u64;
    for &(device, role) in graph.terminals_on(net) {
        neighbours = neighbours.wrapping_add(neighbour(role, device_class[device as usize]));
    }
    mix(mix(NET_TAG ^ (u64::from(own.0) << 8)) ^ neighbours)
}

/// Append one graph's node signatures, tagged with their index in the combined
/// space `offset ..`.
fn push_signatures(graph: &Graph, class: &[ClassId], offset: u32, out: &mut Vec<(u64, u32)>) {
    let devices = graph.device_count();
    let nets = graph.net_count();
    debug_assert_eq!(class.len(), devices + nets, "a class column per node");
    debug_assert!(devices + nets <= u32::MAX as usize - offset as usize);
    let (device_class, net_class) = class.split_at(devices);

    // `enumerate` over the class column rather than a range indexing it: the
    // trip count is then the column's own length and the read carries no bounds
    // check. `narrow`, not `as`, on every index that becomes a node tag — a
    // truncation here renumbers one node onto another and the partition comes
    // back a confident wrong answer.
    for (device, &own) in device_class.iter().enumerate() {
        let index = narrow(device);
        out.push((device_signature(graph, index, own, net_class), offset + index));
    }
    for (net, &own) in net_class.iter().enumerate() {
        let signature = net_signature(graph, narrow(net), own, device_class);
        out.push((signature, offset + narrow(devices + net)));
    }
}

/// One refinement round over both graphs at once.
///
/// **Transform, A-to-B.** Signatures for every node of both sides go into one
/// buffer, are sorted, and their distinct runs become the next round's classes.
/// Sorting the union is what makes a class name the same structure on both
/// sides; sorting the two sides apart would number them independently and the
/// partitions would never be comparable.
///
/// `next` comes back holding the layout column followed by the reference one —
/// one combined scatter target, because splitting it inside the loop would put
/// an `if node >= layout_nodes` on a ~50/50 data-dependent branch. Returns the
/// number of classes.
fn signature_round(
    layout: &Graph,
    reference: &Graph,
    layout_class: &[ClassId],
    ref_class: &[ClassId],
    signature: &mut Vec<(u64, u32)>,
    next: &mut Vec<ClassId>,
) -> u32 {
    let total = layout_class.len() + ref_class.len();
    // `narrow`, not `as`: this is the offset the reference side's node indices
    // are tagged with, so a truncation here renumbers both sides onto each
    // other and the partition comes back a confident wrong answer.
    let split = narrow(layout_class.len());

    signature.clear();
    signature.reserve(total);
    push_signatures(layout, layout_class, 0, signature);
    push_signatures(reference, ref_class, split, signature);
    debug_assert_eq!(signature.len(), total, "a signature per node of both sides");

    // Ties on the hash break on the node index, so the ordering is total and
    // an unstable sort is still a deterministic one.
    signature.sort_unstable();

    next.clear();
    next.resize(total, ClassId(0));

    // A scatter: the write index is the row's own value, so this does not
    // vectorise without lane-conflict detection and is not meant to.
    let mut count = 0u32;
    let mut previous = 0u64;
    for (position, &(hash, node)) in signature.iter().enumerate() {
        // Branchless: `position == 0` opens the first run, and the run edge is
        // arithmetic rather than control flow.
        count += u32::from(hash != previous) | u32::from(position == 0);
        previous = hash;
        next[node as usize] = ClassId(count - 1);
    }

    debug_assert!(count as usize <= total, "more classes than nodes");
    count
}

/// A class refinement could not resolve: something lands in it on one side or
/// the other, and it did not come out holding exactly one node per side.
///
/// A class nothing lands in is absent, not unresolved — that is what `present`
/// buys, and it is why this cannot be written as `!resolved` alone.
const fn is_stalled(mine: u32, theirs: u32) -> bool {
    let present = (mine | theirs) != 0;
    let resolved = (mine == 1) & (theirs == 1);
    present & !resolved
}

/// A stalled class whose two sides hold the same number of nodes: a symmetry
/// refinement could not break, rather than a difference.
///
/// Either pairing of its members is right, so nothing in it is a discrepancy —
/// and equally, nothing in it is paired. That combination is what
/// [`interpret`](crate::compare::interpret) needs a name for: its members are
/// *unpaired without being unpairable*, and blaming them reports a difference
/// that is not there.
///
/// Equal counts and a stall together mean at least two nodes a side: a class
/// holding one each resolved, and a class holding none on either side is
/// absent. The `debug_assert` in [`Partition::symmetric_nodes`] pins that, so
/// the `> 1` here is a statement rather than a second guess.
pub(crate) const fn is_symmetric(mine: u32, theirs: u32) -> bool {
    (mine == theirs) & (mine > 1)
}

/// Nodes per class, and the lowest node index in each.
///
/// `first` is `u32::MAX` for a class holding nothing on this side, which is
/// unreachable as a node index because the combined index space is bounded by
/// the node count.
fn tally_into(class: &[ClassId], classes: u32, tally: &mut Vec<u32>, first: &mut Vec<u32>) {
    tally.clear();
    tally.resize(classes as usize, 0);
    first.clear();
    first.resize(classes as usize, u32::MAX);

    // Scatter-accumulate — a histogram, whose write index is the row's value.
    // Same unvectorisable shape as the renumbering above, so `narrow`'s compare
    // costs nothing this body was not already paying: both stores are indexed
    // by a value and are bounds-checked. It is not decoration either —
    // `u32::MAX` is `first`'s "this class holds nothing" sentinel, so a
    // truncating node index is a real node reading as absent.
    for (node, &ClassId(id)) in class.iter().enumerate() {
        debug_assert!(id < classes, "node {node} names class {id} of {classes}");
        let slot = id as usize;
        tally[slot] += 1;
        first[slot] = first[slot].min(narrow(node));
    }
}

fn refine_observed<O: ObserveRefine>(
    layout: &LayoutGraph,
    reference: &RefGraph,
    tie_break: TieBreak,
    max_rounds: u32,
    out: &mut Partition,
    observer: &mut O,
) -> Refinement {
    let (layout, reference) = (&layout.0, &reference.0);
    let layout_devices = layout.device_count();
    let ref_devices = reference.device_count();
    let layout_nodes = layout_devices + layout.net_count();
    let ref_nodes = ref_devices + reference.net_count();
    debug_assert!(u32::try_from(layout_nodes + ref_nodes).is_ok(), "node space fits a u32");

    // Devices in one class, nets in another — the coarsest partition that is
    // still sound, because a device can never pair with a net. A side with no
    // devices at all must not open an empty class, or the round count would
    // fall on the first round and "classes never decrease" would be a lie.
    let devices_exist = layout_devices + ref_devices > 0;
    let nets_exist = (layout_nodes - layout_devices) + (ref_nodes - ref_devices) > 0;
    let device_class = ClassId(0);
    let net_class = ClassId(u32::from(devices_exist));
    let mut class_count = u32::from(devices_exist) + u32::from(nets_exist);

    out.layout_class.clear();
    out.layout_class.resize(layout_devices, device_class);
    out.layout_class.resize(layout_nodes, net_class);
    out.ref_class.clear();
    out.ref_class.resize(ref_devices, device_class);
    out.ref_class.resize(ref_nodes, net_class);
    out.signature.clear();
    out.next_layout.clear();
    out.next_ref.clear();

    // Hoisted above the round loop: a stalled round re-tallies, and a tie-break
    // sends it round again.
    let (mut layout_tally, mut layout_first) = (Vec::new(), Vec::new());
    let (mut ref_tally, mut ref_first) = (Vec::new(), Vec::new());

    // Not a bulk loop: one iteration is a whole pass over both graphs, and the
    // count is a graph diameter — tens, against the thousands to millions of
    // rows each pass moves. It is also a chain by construction, each round
    // reading the classes the last one wrote.
    let mut round = 0u32;
    while round < max_rounds {
        let count = signature_round(
            layout,
            reference,
            &out.layout_class,
            &out.ref_class,
            &mut out.signature,
            &mut out.next_layout,
        );
        // Refinement only ever splits, so a class can never be lost.
        debug_assert!(count >= class_count, "{count} classes after {class_count}");

        // Split the combined scatter target back into two columns. `clear` then
        // `extend_from_slice` is one memcpy and keeps the capacity.
        out.next_ref.clear();
        out.next_ref.extend_from_slice(&out.next_layout[layout_nodes..]);
        out.next_layout.truncate(layout_nodes);
        std::mem::swap(&mut out.layout_class, &mut out.next_layout);
        std::mem::swap(&mut out.ref_class, &mut out.next_ref);
        debug_assert_eq!(out.layout_class.len(), layout_nodes);
        debug_assert_eq!(out.ref_class.len(), ref_nodes);

        if O::ENABLED {
            observer.round(round, count, count.saturating_sub(class_count));
        }
        round += 1;

        // Stability is tested on equality, not on a subtraction: a count that
        // somehow fell would wrap a `-` and read as stable, which is the
        // fail-open reading of "we could not check this".
        let stable = count == class_count;
        class_count = count;
        if !stable {
            continue;
        }

        tally_into(&out.layout_class, count, &mut layout_tally, &mut layout_first);
        tally_into(&out.ref_class, count, &mut ref_tally, &mut ref_first);

        // Three accumulators over the two tally columns, strictly left to right.
        // `tally_into` resized both to `count`, so the zip below folds every
        // class exactly once — asserted rather than assumed, because a zip over
        // unequal columns stops at the shorter one and would report a clean
        // partition for classes it never inspected.
        debug_assert_eq!(layout_tally.len(), ref_tally.len(), "a tally per side");
        debug_assert_eq!(layout_tally.len(), count as usize, "a tally row per class");

        let mut stalls = 0u32;
        let mut imbalance = 0u32;
        let mut lowest = u32::MAX;
        let mut class = 0u32;
        for (&mine, &theirs) in layout_tally.iter().zip(&ref_tally) {
            let present = u32::from((mine | theirs) != 0);
            let uneven = u32::from(mine != theirs);
            let stall = u32::from(is_stalled(mine, theirs));
            stalls += stall;
            imbalance |= present & uneven;
            // `class` when the class is a stall a tie-break may enter,
            // `u32::MAX` when not — a select, not a branch:
            // `(breakable ^ 1).wrapping_neg()` is all-ones on the rows to skip
            // and zero on the one to keep.
            //
            // Balanced, not merely stalled: an imbalanced class is a structural
            // difference, and individualising a node inside one would invent a
            // pairing between populations that cannot pair.
            let breakable = stall & (uneven ^ 1);
            lowest = lowest.min(class | (breakable ^ 1).wrapping_neg());
            class += 1;
        }
        debug_assert_eq!(class, count, "the fold saw one row per class");
        debug_assert!(stalls <= count, "more stalls than classes");
        debug_assert!(
            imbalance != 0 || stalls == 0 || lowest < count,
            "every class balanced, a stall, and no class to break it in"
        );

        // A separate pass, because a callback may not call out and may not
        // capture `&mut`. `O::ENABLED` is a `const`, so a production build
        // never codegens this loop at all and the fold above is the only one.
        if O::ENABLED {
            for class in 0..count {
                let here = class as usize;
                let (mine, theirs) = (layout_tally[here], ref_tally[here]);
                if is_stalled(mine, theirs) {
                    observer.stalled(ClassId(class), mine, theirs);
                }
            }
        }

        if stalls == 0 {
            out.class_count = count;
            return Refinement::Complete;
        }
        // A run told not to guess still gets told about a structural
        // difference: an imbalanced class is an answer, not a guess, and
        // reporting it as a symmetry would blame the run's configuration for a
        // difference between the netlists — a caller would then loosen the
        // tie-break and get the same answer.
        if tie_break == TieBreak::Refuse {
            out.class_count = count;
            return if imbalance == 0 {
                Refinement::Symmetric
            } else {
                Refinement::Discrepant
            };
        }
        // Every remaining stall is imbalanced, which no tie-break can mend.
        //
        // The two conditions are independent, and reading them as one is what
        // made a *deleted device* come back `Inconclusive(UnresolvedSymmetry)`
        // once `role_code` collapsed the MOS channel: the first imbalance
        // returned here immediately, so a balanced class elsewhere in the same
        // graph was left unbroken, and `compare::interpret` then read that
        // unbroken class as the whole comparison having failed to finish. A
        // symmetry is resolvable wherever it sits, and resolving it is what
        // lets the rest of the netlist be compared at all.
        if lowest == u32::MAX {
            out.class_count = count;
            return Refinement::Discrepant;
        }

        // The chosen class is balanced with more than one node per side, so the
        // symmetry is genuine and either pairing is right. Individualise one
        // class per round — the lowest, and within it the lowest node index on
        // each side — and let the next round propagate the consequence.
        debug_assert!(lowest < count, "a stall without a class");
        // Widened rather than narrowed: the node counts are `usize`, and a
        // narrowing compare would be the assert agreeing with the bug it exists
        // to catch.
        debug_assert!((layout_first[lowest as usize] as usize) < layout_nodes);
        debug_assert!((ref_first[lowest as usize] as usize) < ref_nodes);
        if O::ENABLED {
            observer.tie_broken(ClassId(lowest));
        }
        out.layout_class[layout_first[lowest as usize] as usize] = ClassId(count);
        out.ref_class[ref_first[lowest as usize] as usize] = ClassId(count);
        class_count = count + 1;
    }

    out.class_count = class_count;
    Refinement::Exhausted
}

impl Partition {
    /// A partition stated directly, rather than reached by refining.
    ///
    /// **Generative.** [`interpret`](crate::compare::interpret) is a decision —
    /// a partition and two graphs in, a verdict out — and its reason for
    /// existing apart from [`compare`](crate::compare::compare) is that it is
    /// worth a table of constructed cases. Without this it had no input it
    /// could be handed that `refine_into` had not just produced, so the table
    /// was unwritable and the separation bought nothing.
    ///
    /// Both columns index nodes the same way the refiner does: devices first,
    /// then nets. `class_count` is derived, one past the highest class named,
    /// so a caller cannot state a count that disagrees with the columns. The
    /// scratch columns are left empty; [`refine_into`] sizes them. The count
    /// saturates rather than wrapping on `ClassId(u32::MAX)`, which no
    /// refinement produces and no fixture has a reason to state.
    #[must_use]
    pub fn from_classes(layout_class: Vec<ClassId>, ref_class: Vec<ClassId>) -> Self {
        // Two folds rather than one over a chained iterator: the columns are
        // separate allocations, so a chain would be two loops anyway with a
        // switch between them.
        let mut highest = 0u32;
        for &ClassId(class) in &layout_class {
            highest = highest.max(class);
        }
        for &ClassId(class) in &ref_class {
            highest = highest.max(class);
        }
        // Not in a loop: `empty` is a uniform over both folds above.
        let empty = layout_class.is_empty() && ref_class.is_empty();
        let class_count = highest.saturating_add(1) * u32::from(!empty);

        Self {
            layout_class,
            ref_class,
            class_count,
            ..Self::default()
        }
    }

    /// The paired nodes, ascending by layout index.
    ///
    /// Only classes that resolved to exactly one node per side. Everything else
    /// is a discrepancy.
    pub fn pairs(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        debug_assert!(
            self.class_count as usize <= self.layout_class.len() + self.ref_class.len(),
            "more classes than nodes to fill them"
        );
        let (layout_tally, _, ref_tally, ref_first) = self.tallies();

        let mut paired = vec![(0u32, 0u32); self.layout_class.len()];
        let mut written = 0usize;
        // A branchless compact: store always, advance by the predicate. `paired`
        // is sized for the whole input rather than for the survivors, which is
        // the memory-for-branches trade that makes the store unconditional.
        for (node, &ClassId(class)) in self.layout_class.iter().enumerate() {
            let here = class as usize;
            let resolved = (layout_tally[here] == 1) & (ref_tally[here] == 1);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "`node` is `layout_class`'s own index, and `tallies()` \
                          on the line above just ran `narrow` over every row of \
                          that same column, so the length is known to fit a u32 \
                          in every profile — re-checking it here would put a \
                          panic edge in the body of a branchless compact"
            )]
            let row = (node as u32, ref_first[here]);
            paired[written] = row;
            written += usize::from(resolved);
        }
        paired.truncate(written);
        debug_assert!(written <= self.ref_class.len(), "more pairs than reference nodes");
        paired.into_iter()
    }

    /// Classes that did not resolve, with their membership on both sides.
    pub fn unresolved(&self) -> impl Iterator<Item = (ClassId, u32, u32)> + '_ {
        debug_assert!(
            self.class_count as usize <= self.layout_class.len() + self.ref_class.len(),
            "more classes than nodes to fill them"
        );
        let (layout_tally, _, ref_tally, _) = self.tallies();

        let mut open = vec![(ClassId(0), 0u32, 0u32); self.class_count as usize];
        let mut written = 0usize;
        // Same branchless commit as `pairs`, and the same stall predicate
        // `refine_observed` folds with — one `is_stalled`, so the two cannot
        // drift.
        for class in 0..self.class_count {
            let here = class as usize;
            let (mine, theirs) = (layout_tally[here], ref_tally[here]);
            open[written] = (ClassId(class), mine, theirs);
            written += usize::from(is_stalled(mine, theirs));
        }
        open.truncate(written);
        open.into_iter()
    }

    /// The nodes of every class that did not resolve but holds the same count
    /// on both sides, ascending by node index: the layout column, then the
    /// reference one.
    ///
    /// # Unpaired is not the same as unpairable
    ///
    /// A class holding the same count on both sides is a **symmetry**
    /// refinement could not break — the two halves of a differential pair, or
    /// the two ends of a MOS channel once [`role_code`] reads them as one role.
    /// Either pairing of its members is right, so nothing in it is a
    /// difference; and no pairing was chosen, so nothing in it is paired
    /// either. A class holding *different* counts is the opposite: a structural
    /// difference no pairing can mend.
    ///
    /// [`unresolved`](Self::unresolved) reports both kinds and
    /// [`pairs`](Self::pairs) reports neither, so from outside `Partition` the
    /// two were indistinguishable. `compare::interpret` therefore had to return
    /// [`Inconclusive::UnresolvedSymmetry`](crate::verdict::Inconclusive) for
    /// the whole comparison on the first balanced class it saw — which masked a
    /// **deleted device** sitting in another class, because a run that gave up
    /// says nothing about the device that is missing. That is finding F4's
    /// second half, and this is the accessor it was blocked on.
    ///
    /// # Two columns, not one
    ///
    /// The two sides hold the same *number* of symmetric nodes by definition
    /// but not the same *indices*, and `interpret` scatters into two separate
    /// mate columns, so returning one interleaved list would only make the
    /// caller split it again.
    ///
    /// Node indices are in the combined space the class columns use: devices
    /// first, then nets.
    #[must_use]
    pub fn symmetric_nodes(&self) -> (Vec<u32>, Vec<u32>) {
        let (layout_tally, _, ref_tally, _) = self.tallies();
        debug_assert_eq!(layout_tally.len(), ref_tally.len(), "a tally per side");

        // A uniform per class, hoisted out of the two compacts below so neither
        // re-derives it and the two cannot disagree about which classes are
        // symmetric.
        let mut symmetric = vec![false; self.class_count as usize];
        for (class, flag) in symmetric.iter_mut().enumerate() {
            let (mine, theirs) = (layout_tally[class], ref_tally[class]);
            debug_assert!(
                !is_symmetric(mine, theirs) || is_stalled(mine, theirs),
                "class {class} is balanced at {mine} a side and still resolved"
            );
            *flag = is_symmetric(mine, theirs);
        }

        // The same branchless compact `pairs` uses: store always, advance by the
        // predicate, and size the buffer for the whole input rather than for the
        // survivors.
        let mut columns = (
            vec![0u32; self.layout_class.len()],
            vec![0u32; self.ref_class.len()],
        );
        for (out, class) in [
            (&mut columns.0, &self.layout_class),
            (&mut columns.1, &self.ref_class),
        ] {
            let mut written = 0usize;
            for (node, &ClassId(id)) in class.iter().enumerate() {
                out[written] = narrow(node);
                written += usize::from(symmetric[id as usize]);
            }
            out.truncate(written);
        }

        debug_assert_eq!(
            columns.0.len(),
            columns.1.len(),
            "a balanced class holds the same count on both sides"
        );
        columns
    }

    /// Nodes per class on each side, plus the lowest node index in each.
    ///
    /// Derived rather than stored: it is read once per comparison, by
    /// [`pairs`](Self::pairs), [`unresolved`](Self::unresolved) and
    /// [`interpret`](crate::compare::interpret), and a stored copy would be a
    /// fourth thing the scratch buffers have to be kept honest about.
    fn tallies(&self) -> (Vec<u32>, Vec<u32>, Vec<u32>, Vec<u32>) {
        let (mut layout_tally, mut layout_first) = (Vec::new(), Vec::new());
        let (mut ref_tally, mut ref_first) = (Vec::new(), Vec::new());
        tally_into(
            &self.layout_class,
            self.class_count,
            &mut layout_tally,
            &mut layout_first,
        );
        tally_into(&self.ref_class, self.class_count, &mut ref_tally, &mut ref_first);
        (layout_tally, layout_first, ref_tally, ref_first)
    }
}

/// The one real body in this crate, and the only thing here that can be wrong
/// before the Implementation-Phase starts.
#[cfg(test)]
mod partition_tests {
    use super::{ClassId, Partition};

    #[test]
    fn a_stated_partition_derives_its_class_count_from_the_columns() {
        let stated = Partition::from_classes(
            vec![ClassId(0), ClassId(2), ClassId(0)],
            vec![ClassId(2), ClassId(1), ClassId(2)],
        );
        assert_eq!(stated.class_count, 3, "one past the highest class named");
        assert!(stated.next_layout.is_empty(), "scratch is the refiner's");
        assert_eq!(Partition::from_classes(vec![], vec![]).class_count, 0);
        assert_eq!(Partition::from_classes(vec![], vec![]), Partition::default());
    }

    /// Scratch is not part of the value: a reused buffer holds a previous
    /// comparison's leftovers, and that they are unreadable is the claim reuse
    /// rests on.
    #[test]
    fn two_partitions_agreeing_on_classes_are_equal_whatever_the_scratch_holds() {
        let fresh = Partition::from_classes(vec![ClassId(0)], vec![ClassId(0)]);
        let mut reused = Partition::from_classes(vec![ClassId(0)], vec![ClassId(0)]);
        reused.signature.push((7, 7));
        reused.next_ref.push(ClassId(9));
        assert_eq!(fresh, reused);
    }
}

/// Tests for the [`ObserveRefine`] seam.
///
/// These live inside the crate because [`refine_observed`] is private. That is
/// the deliberate trade `core::observe` records: the public interface takes no
/// observer, so the seam does not widen it, and the price is that its tests
/// cannot be integration tests.
///
/// Everything here is a property of the *round sequence*, which is the one thing
/// the final partition does not record. Whether a comparison converged in three
/// rounds or ninety, and whether it stalled on a symmetry before the tie-break
/// resolved it, are invisible in `pairs()` and are the difference between a fast
/// comparison and one about to time out.
#[cfg(test)]
mod tests {
    use super::{refine_observed, ClassId, ObserveRefine, Partition, Refinement, TieBreak};
    use crate::graph::{Graph, LayoutGraph, RefGraph};
    use gpurify_core::observe::Observer;
    use gpurify_ingest::deck::DeviceKind;
    use gpurify_ingest::StrId;
    use gpurify_topology::TerminalRole;

    const NCH: StrId = StrId(1);

    /// Records every callback in order. The gate is `true`, which is what makes
    /// it an adapter rather than a second null one.
    #[derive(Debug, Default)]
    struct Recorder {
        rounds: Vec<(u32, u32, u32)>,
        stalled: Vec<(ClassId, u32, u32)>,
        tie_broken: Vec<ClassId>,
    }

    impl Observer for Recorder {
        const ENABLED: bool = true;
    }

    impl ObserveRefine for Recorder {
        fn round(&mut self, index: u32, classes: u32, split: u32) {
            self.rounds.push((index, classes, split));
        }
        fn stalled(&mut self, class: ClassId, layout_nodes: u32, ref_nodes: u32) {
            self.stalled.push((class, layout_nodes, ref_nodes));
        }
        fn tie_broken(&mut self, class: ClassId) {
            self.tie_broken.push(class);
        }
    }

    /// A source-to-drain chain of `devices` transistors over `devices + 1` nets,
    /// **diode-connected at the low end**.
    ///
    /// Refinement propagates one hop per round along a chain, so the number of
    /// rounds this needs grows with its length. That is the whole reason the
    /// fixture is a chain: the seam's claim is about how much work happened, so
    /// the fixture has to make the amount of work predictable.
    ///
    /// # Why device 0 carries a gate
    ///
    /// A bare chain is *not* rigid once [`role_code`] reads a MOS channel as
    /// symmetric, and that is not a defect of either: reversing the chain end to
    /// end maps every source onto a drain, so with the two roles collapsed the
    /// reversal is a genuine automorphism and the fixture has a symmetry the
    /// tests below would be measuring instead of what they name. Without the
    /// gate, `a_rigid_graph_stalls_on_nothing_and_breaks_no_tie` reports
    /// `Symmetric` — correctly — and stops being about rigidity at all.
    ///
    /// Tying device 0's gate to one end of its own channel is the smallest
    /// anchor that distinguishes the two ends, and it is what a real stack is
    /// anchored by: a diode-connected transistor at the bottom of a mirror.
    /// A path graph with one distinguished endpoint has no automorphism but the
    /// identity, so the chain is rigid again.
    fn chain(devices: u32) -> Graph {
        let mut graph = Graph::default();
        graph.device_terminal_start.push(0);
        graph.device_param_start.push(0);
        for index in 0..devices {
            graph.device_kind.push(DeviceKind::Mos);
            graph.device_model.push(NCH);
            graph.terminal_net.push(index);
            graph.terminal_role.push(TerminalRole::Source);
            graph.terminal_net.push(index + 1);
            graph.terminal_role.push(TerminalRole::Drain);
            if index == 0 {
                graph.terminal_net.push(0);
                graph.terminal_role.push(TerminalRole::Gate);
            }
            let filled = u32::try_from(graph.terminal_net.len()).expect("a small fixture");
            graph.device_terminal_start.push(filled);
            graph.device_param_start.push(0);
        }
        graph.net_terminal_start.push(0);
        for net in 0..=devices {
            if net > 0 {
                graph.net_terminal.push((net - 1, TerminalRole::Drain));
            }
            if net < devices {
                graph.net_terminal.push((net, TerminalRole::Source));
            }
            if net == 0 {
                graph.net_terminal.push((0, TerminalRole::Gate));
            }
            let filled = u32::try_from(graph.net_terminal.len()).expect("a small fixture");
            graph.net_terminal_start.push(filled);
            graph.net_name.push(None);
        }
        graph
    }

    /// Two transistors sharing a tail and a bulk, gates and drains apart: a
    /// differential pair, whose two halves are interchangeable by an
    /// automorphism no signature can break.
    fn differential_pair() -> Graph {
        use TerminalRole::{Bulk, Drain, Gate, Source};
        let mut graph = Graph::default();
        graph.device_terminal_start.push(0);
        graph.device_param_start.push(0);
        for (gate, drain) in [(1u32, 3u32), (2, 4)] {
            graph.device_kind.push(DeviceKind::Mos);
            graph.device_model.push(NCH);
            for (role, net) in [(Gate, gate), (Source, 0), (Drain, drain), (Bulk, 5)] {
                graph.terminal_net.push(net);
                graph.terminal_role.push(role);
            }
            let filled = u32::try_from(graph.terminal_net.len()).expect("a small fixture");
            graph.device_terminal_start.push(filled);
            graph.device_param_start.push(0);
        }
        graph.net_terminal_start.push(0);
        let per_net: [&[(u32, TerminalRole)]; 6] = [
            &[(0, Source), (1, Source)],
            &[(0, Gate)],
            &[(1, Gate)],
            &[(0, Drain)],
            &[(1, Drain)],
            &[(0, Bulk), (1, Bulk)],
        ];
        for terminals in per_net {
            graph.net_terminal.extend_from_slice(terminals);
            let filled = u32::try_from(graph.net_terminal.len()).expect("a small fixture");
            graph.net_terminal_start.push(filled);
            graph.net_name.push(None);
        }
        graph
    }

    /// Oracle: law. Refinement only ever splits a class, so the class count is
    /// nondecreasing from round to round; rounds are announced consecutively
    /// from zero; and a round that split nothing is the last one, because that
    /// is what stability means. None of this is readable from the final
    /// partition, which is why the seam exists.
    #[test]
    fn rounds_are_announced_consecutively_and_never_lose_a_class() {
        let mut scratch = Partition::default();
        let mut observer = Recorder::default();
        let outcome = refine_observed(
            &LayoutGraph(chain(12)),
            &RefGraph(chain(12)),
            TieBreak::LowestIndex,
            256,
            &mut scratch,
            &mut observer,
        );
        assert_eq!(outcome, Refinement::Complete);

        assert!(
            observer.rounds.len() > 1,
            "a twelve-device chain converged in {} round(s), so the fixture is \
             not exercising propagation at all",
            observer.rounds.len()
        );
        for (position, &(index, classes, split)) in observer.rounds.iter().enumerate() {
            let position = u32::try_from(position).expect("a small round count");
            assert_eq!(index, position, "round indices are not consecutive from zero");
            if position > 0 {
                let previous = observer.rounds[position as usize - 1].1;
                assert!(
                    classes >= previous,
                    "round {index} reports {classes} classes after {previous}"
                );
            }
            if split == 0 {
                assert_eq!(
                    position as usize,
                    observer.rounds.len() - 1,
                    "round {index} split nothing but refinement continued"
                );
            }
        }
    }

    /// Oracle: construct-from-answer. The budget is three rounds and the chain
    /// needs more, so exactly three are announced and the run reports itself
    /// exhausted. A round counted but not announced, or announced past the
    /// budget, is work the seam is failing to account for.
    #[test]
    fn a_run_that_hits_its_budget_announces_exactly_that_many_rounds() {
        let mut scratch = Partition::default();
        let mut observer = Recorder::default();
        let outcome = refine_observed(
            &LayoutGraph(chain(24)),
            &RefGraph(chain(24)),
            TieBreak::LowestIndex,
            3,
            &mut scratch,
            &mut observer,
        );
        assert_eq!(outcome, Refinement::Exhausted);
        assert_eq!(observer.rounds.len(), 3);
    }

    /// Oracle: construct-from-answer. A differential pair stalls on a class
    /// holding both halves. Under [`TieBreak::Refuse`] the stall is reported and
    /// nothing is chosen, and because the graph is being compared with itself
    /// the class holds the same number of nodes on each side.
    #[test]
    fn a_refused_symmetry_is_announced_as_a_stall_and_nothing_is_chosen() {
        let mut scratch = Partition::default();
        let mut observer = Recorder::default();
        let outcome = refine_observed(
            &LayoutGraph(differential_pair()),
            &RefGraph(differential_pair()),
            TieBreak::Refuse,
            256,
            &mut scratch,
            &mut observer,
        );
        assert_eq!(outcome, Refinement::Symmetric);
        assert!(
            !observer.stalled.is_empty(),
            "refinement stalled without announcing which class"
        );
        assert!(
            observer.tie_broken.is_empty(),
            "a tie was broken under TieBreak::Refuse: {:?}",
            observer.tie_broken
        );
        for &(class, layout_nodes, ref_nodes) in &observer.stalled {
            assert_eq!(
                layout_nodes, ref_nodes,
                "class {class:?} is uneven in a comparison of a graph with itself"
            );
            assert!(layout_nodes > 1, "class {class:?} stalled with one node");
        }
    }

    /// Oracle: construct-from-answer. The same structure with the tie-break
    /// allowed to fire announces the classes it chose in, and every one of them
    /// is a class it first announced as stalled. A tie broken without a stall is
    /// a choice made where none was needed.
    #[test]
    fn a_broken_tie_is_announced_on_a_class_that_first_stalled() {
        let mut scratch = Partition::default();
        let mut observer = Recorder::default();
        let outcome = refine_observed(
            &LayoutGraph(differential_pair()),
            &RefGraph(differential_pair()),
            TieBreak::LowestIndex,
            256,
            &mut scratch,
            &mut observer,
        );
        assert_eq!(outcome, Refinement::Complete);
        assert!(
            !observer.tie_broken.is_empty(),
            "a symmetric structure completed without any tie being broken"
        );
        for class in &observer.tie_broken {
            assert!(
                observer.stalled.iter().any(|(stalled, ..)| stalled == class),
                "class {class:?} was tie-broken but never reported as stalled"
            );
        }
    }

    /// Oracle: law. A rigid graph — the chain, whose ends are distinguishable
    /// and whose interior is not symmetric — needs no tie-break at all. Without
    /// this, the two tests above are satisfied by an implementation that
    /// announces a stall on every class it ever looks at.
    #[test]
    fn a_rigid_graph_stalls_on_nothing_and_breaks_no_tie() {
        let mut scratch = Partition::default();
        let mut observer = Recorder::default();
        let outcome = refine_observed(
            &LayoutGraph(chain(7)),
            &RefGraph(chain(7)),
            TieBreak::Refuse,
            256,
            &mut scratch,
            &mut observer,
        );
        assert_eq!(outcome, Refinement::Complete);
        assert!(observer.stalled.is_empty(), "{:?}", observer.stalled);
        assert!(observer.tie_broken.is_empty(), "{:?}", observer.tie_broken);
    }
}
