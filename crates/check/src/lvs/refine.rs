//! Partition refinement: the matching algorithm.
//!
//! Nodes are split by a signature over their neighbours' current classes until no
//! class splits further; classes holding exactly one node per side are a forced
//! pairing, and a stall is resolved by [`TieBreak`] rather than by hash order.

use crate::lvs::graph::{narrow, Graph, LayoutGraph, RefGraph};
use gpurify_geom::observe::{NoObserve, Observer};
use gpurify_ingest::deck::DeviceKind;
use crate::topology::TerminalRole;

/// A class of nodes not yet distinguished from each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ClassId(pub u32);

/// The refinement state for both graphs.
#[derive(Debug, Default)]
pub struct Partition {
    /// Class of each layout node, devices then nets.
    layout_class: Vec<ClassId>,
    ref_class: Vec<ClassId>,
    /// Scratch for the next round. Two buffers swapped, so a round never reads
    /// what it wrote.
    next_layout: Vec<ClassId>,
    next_ref: Vec<ClassId>,
    /// Per-node signature for the current round, sorted to renumber classes.
    signature: Vec<(u64, u32)>,
    class_count: u32,
}

/// Two partitions are equal when they assign the same classes to the same nodes.
///
/// Hand-written, not derived: the scratch columns are not part of the value, and
/// a derive would make a reused buffer compare unequal to a fresh one.
impl PartialEq for Partition {
    fn eq(&self, other: &Self) -> bool {
        self.class_count == other.class_count
            && self.layout_class == other.layout_class
            && self.ref_class == other.ref_class
    }
}

/// How to break a genuine symmetry. Every option is a total order over something
/// intrinsic, never over memory layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TieBreak {
    /// Lowest node index on each side.
    LowestIndex,
    /// Refuse, and report the symmetric group as a discrepancy instead.
    Refuse,
}

/// What the refinement did, round by round — not derivable from the final
/// partition.
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

/// Refine until stable; `out`'s buffers are reused across rounds and comparisons.
///
/// Hitting `max_rounds` is not a mismatch and must not be reported as one — it is
/// [`Verdict::Inconclusive`](crate::lvs::Verdict).
pub fn refine_into(
    layout: &LayoutGraph,
    reference: &RefGraph,
    tie_break: TieBreak,
    max_rounds: u32,
    out: &mut Partition,
) -> Refinement {
    refine_observed(
        layout,
        reference,
        tie_break,
        max_rounds,
        out,
        &mut NoObserve,
    )
}

/// How refinement ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refinement {
    /// No class split further and every class is a one-to-one pairing.
    Complete,
    /// Stable, but some class holds unequal counts from the two sides.
    Discrepant,
    /// Stable with genuine symmetry remaining, and [`TieBreak::Refuse`] was in
    /// force.
    Symmetric,
    /// `max_rounds` was reached. Says nothing about whether the netlists match.
    Exhausted,
}

/// Splitmix64's finaliser. A signature is only ever compared with another, never
/// inverted, so avalanche is the entire requirement.
const fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// A terminal's role as a number the signature can carry.
///
/// **Interchangeable roles share a code**: collapsing two roles here states that
/// a device written with those two exchanged is the same device. `Pin(k)` and the
/// MOS `Source`/`Drain` pair collapse; `Emitter` and `Collector` do **not** and
/// never will, because a bipolar's doping is asymmetric.
///
/// The S/D collapse creates genuine automorphisms wherever a device's two channel
/// nets are otherwise indistinguishable, which is why `refine_observed` must
/// break a balanced stall even when an imbalanced class exists elsewhere.
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
/// Folded with `wrapping_add`, which is commutative, so the signature is a
/// function of the *multiset* of neighbours and not of CSR row order.
const fn neighbour(role: TerminalRole, class: ClassId) -> u64 {
    mix(NEIGHBOUR_TAG ^ (role_code(role) << 8) ^ ((class.0 as u64) << 16))
}

/// A device's signature for one round: its own class, its intrinsic identity,
/// and the multiset of `(role, class)` over its terminals.
fn device_signature(graph: &Graph, device: u32, own: ClassId, net_class: &[ClassId]) -> u64 {
    let (nets, roles) = graph.terminals_of(device);
    debug_assert_eq!(nets.len(), roles.len(), "a terminal without a role");

    // A zip over unequal columns folds the shorter one and would report a
    // signature for a device it only half read; the assert above catches that.
    let mut neighbours = 0u64;
    for (&net, &role) in nets.iter().zip(roles) {
        neighbours = neighbours.wrapping_add(neighbour(role, net_class[net as usize]));
    }

    let head = mix(DEVICE_TAG ^ (u64::from(own.0) << 8));
    let head = mix(head
        ^ kind_code(graph.device_kind[device as usize])
        ^ (u64::from(graph.device_model[device as usize].0) << 8));
    mix(head ^ neighbours)
}

/// A net's signature: its own class and the multiset of `(role, class)` over
/// the device terminals landing on it.
fn net_signature(graph: &Graph, net: u32, own: ClassId, device_class: &[ClassId]) -> u64 {
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

    // `narrow`, not `as`, on every index that becomes a node tag: a truncation
    // renumbers one node onto another.
    for (device, &own) in device_class.iter().enumerate() {
        let index = narrow(device);
        out.push((
            device_signature(graph, index, own, net_class),
            offset + index,
        ));
    }
    for (net, &own) in net_class.iter().enumerate() {
        let signature = net_signature(graph, narrow(net), own, device_class);
        out.push((signature, offset + narrow(devices + net)));
    }
}

/// One refinement round over both graphs at once, returning the class count.
///
/// Signatures for both sides go into ONE buffer and are sorted together, which is
/// what makes a class name the same structure on both sides. `next` comes back
/// holding the layout column followed by the reference one.
fn signature_round(
    layout: &Graph,
    reference: &Graph,
    layout_class: &[ClassId],
    ref_class: &[ClassId],
    signature: &mut Vec<(u64, u32)>,
    next: &mut Vec<ClassId>,
) -> u32 {
    let total = layout_class.len() + ref_class.len();
    // `narrow`, not `as`: a truncation renumbers both sides onto each other.
    let split = narrow(layout_class.len());

    signature.clear();
    signature.reserve(total);
    push_signatures(layout, layout_class, 0, signature);
    push_signatures(reference, ref_class, split, signature);
    debug_assert_eq!(signature.len(), total, "a signature per node of both sides");

    // Ties break on the node index, so an unstable sort is deterministic.
    signature.sort_unstable();

    next.clear();
    next.resize(total, ClassId(0));

    let mut count = 0u32;
    let mut previous = 0u64;
    for (position, &(hash, node)) in signature.iter().enumerate() {
        // `position == 0` opens the first run.
        count += u32::from(hash != previous) | u32::from(position == 0);
        previous = hash;
        next[node as usize] = ClassId(count - 1);
    }

    debug_assert!(count as usize <= total, "more classes than nodes");
    count
}

/// A class refinement could not resolve: something lands in it, and it did not
/// come out holding exactly one node per side.
///
/// A class nothing lands in is absent, not unresolved, which is why this cannot
/// be written as `!resolved` alone.
const fn is_stalled(mine: u32, theirs: u32) -> bool {
    let present = (mine | theirs) != 0;
    let resolved = (mine == 1) & (theirs == 1);
    present & !resolved
}

/// A stalled class whose two sides hold the same number of nodes: a symmetry
/// refinement could not break, rather than a difference.
///
/// Its members are unpaired without being unpairable, and blaming them reports a
/// difference that is not there.
pub(crate) const fn is_symmetric(mine: u32, theirs: u32) -> bool {
    (mine == theirs) & (mine > 1)
}

/// Nodes per class, and the lowest node index in each. `first` is `u32::MAX` for
/// a class holding nothing on this side.
fn tally_into(class: &[ClassId], classes: u32, tally: &mut Vec<u32>, first: &mut Vec<u32>) {
    tally.clear();
    tally.resize(classes as usize, 0);
    first.clear();
    first.resize(classes as usize, u32::MAX);

    // `narrow`, not `as`: `u32::MAX` is `first`'s "holds nothing" sentinel, so a
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
    debug_assert!(
        u32::try_from(layout_nodes + ref_nodes).is_ok(),
        "node space fits a u32"
    );

    // Devices in one class, nets in another. A side with no devices must not open
    // an empty class, or the class count would fall on the first round.
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

    let (mut layout_tally, mut layout_first) = (Vec::new(), Vec::new());
    let (mut ref_tally, mut ref_first) = (Vec::new(), Vec::new());

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

        // Split the combined scatter target back into two columns.
        out.next_ref.clear();
        out.next_ref
            .extend_from_slice(&out.next_layout[layout_nodes..]);
        out.next_layout.truncate(layout_nodes);
        std::mem::swap(&mut out.layout_class, &mut out.next_layout);
        std::mem::swap(&mut out.ref_class, &mut out.next_ref);
        debug_assert_eq!(out.layout_class.len(), layout_nodes);
        debug_assert_eq!(out.ref_class.len(), ref_nodes);

        if O::ENABLED {
            observer.round(round, count, count.saturating_sub(class_count));
        }
        round += 1;

        // Equality, not a subtraction: a count that fell would wrap a `-` and
        // read as stable, which is fail-open.
        let stable = count == class_count;
        class_count = count;
        if !stable {
            continue;
        }

        tally_into(
            &out.layout_class,
            count,
            &mut layout_tally,
            &mut layout_first,
        );
        tally_into(&out.ref_class, count, &mut ref_tally, &mut ref_first);

        // A zip over unequal columns stops at the shorter one and would report a
        // clean partition for classes it never inspected.
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
            // Balanced, not merely stalled: individualising a node inside an
            // imbalanced class would invent a pairing between populations that
            // cannot pair.
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

        // `O::ENABLED` is a `const`, so a production build never codegens this.
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
        // A run told not to guess still gets told about a structural difference:
        // reporting an imbalance as a symmetry would blame the configuration.
        if tie_break == TieBreak::Refuse {
            out.class_count = count;
            return if imbalance == 0 {
                Refinement::Symmetric
            } else {
                Refinement::Discrepant
            };
        }
        // Every remaining stall is imbalanced, which no tie-break can mend.
        // Independent of `imbalance` above: a balanced class elsewhere must still
        // be broken, or the rest of the netlist never gets compared.
        if lowest == u32::MAX {
            out.class_count = count;
            return Refinement::Discrepant;
        }

        // Balanced with more than one node per side, so the symmetry is genuine
        // and either pairing is right. One class per round.
        debug_assert!(lowest < count, "a stall without a class");
        // Widened, not narrowed: a narrowing compare would be the assert agreeing
        // with the bug it exists to catch.
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
    /// Both columns index nodes the way the refiner does: devices first, then
    /// nets. `class_count` is derived, one past the highest class named.
    #[must_use]
    pub fn from_classes(layout_class: Vec<ClassId>, ref_class: Vec<ClassId>) -> Self {
        let mut highest = 0u32;
        for &ClassId(class) in &layout_class {
            highest = highest.max(class);
        }
        for &ClassId(class) in &ref_class {
            highest = highest.max(class);
        }
        let empty = layout_class.is_empty() && ref_class.is_empty();
        let class_count = highest.saturating_add(1) * u32::from(!empty);

        Self {
            layout_class,
            ref_class,
            class_count,
            ..Self::default()
        }
    }

    /// The paired nodes, ascending by layout index: only classes that resolved to
    /// exactly one node per side.
    pub fn pairs(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        debug_assert!(
            self.class_count as usize <= self.layout_class.len() + self.ref_class.len(),
            "more classes than nodes to fill them"
        );
        let (layout_tally, _, ref_tally, ref_first) = self.tallies();

        let mut paired = vec![(0u32, 0u32); self.layout_class.len()];
        let mut written = 0usize;
        // Branchless compact: store always, advance by the predicate.
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
        debug_assert!(
            written <= self.ref_class.len(),
            "more pairs than reference nodes"
        );
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
        // The same `is_stalled` `refine_observed` folds with.
        for class in 0..self.class_count {
            let here = class as usize;
            let (mine, theirs) = (layout_tally[here], ref_tally[here]);
            open[written] = (ClassId(class), mine, theirs);
            written += usize::from(is_stalled(mine, theirs));
        }
        open.truncate(written);
        open.into_iter()
    }

    /// The nodes of every class that did not resolve but holds the same count on
    /// both sides: the layout column, then the reference one.
    ///
    /// Unpaired is not unpairable. [`unresolved`](Self::unresolved) reports both
    /// kinds and [`pairs`](Self::pairs) reports neither, so this is the only thing
    /// that tells a symmetry from a structural difference. Node indices are in the
    /// combined space the class columns use: devices first, then nets.
    #[must_use]
    pub fn symmetric_nodes(&self) -> (Vec<u32>, Vec<u32>) {
        let (layout_tally, _, ref_tally, _) = self.tallies();
        debug_assert_eq!(layout_tally.len(), ref_tally.len(), "a tally per side");

        let mut symmetric = vec![false; self.class_count as usize];
        for (class, flag) in symmetric.iter_mut().enumerate() {
            let (mine, theirs) = (layout_tally[class], ref_tally[class]);
            debug_assert!(
                !is_symmetric(mine, theirs) || is_stalled(mine, theirs),
                "class {class} is balanced at {mine} a side and still resolved"
            );
            *flag = is_symmetric(mine, theirs);
        }

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
    fn tallies(&self) -> (Vec<u32>, Vec<u32>, Vec<u32>, Vec<u32>) {
        let (mut layout_tally, mut layout_first) = (Vec::new(), Vec::new());
        let (mut ref_tally, mut ref_first) = (Vec::new(), Vec::new());
        tally_into(
            &self.layout_class,
            self.class_count,
            &mut layout_tally,
            &mut layout_first,
        );
        tally_into(
            &self.ref_class,
            self.class_count,
            &mut ref_tally,
            &mut ref_first,
        );
        (layout_tally, layout_first, ref_tally, ref_first)
    }
}

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
        assert_eq!(
            Partition::from_classes(vec![], vec![]),
            Partition::default()
        );
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

/// Tests for the [`ObserveRefine`] seam, in-crate because `refine_observed` is
/// private.
#[cfg(test)]
mod tests {
    use super::{refine_observed, ClassId, ObserveRefine, Partition, Refinement, TieBreak};
    use crate::lvs::graph::{Graph, LayoutGraph, RefGraph};
    use gpurify_geom::observe::Observer;
    use gpurify_ingest::deck::DeviceKind;
    use gpurify_ingest::StrId;
    use crate::topology::TerminalRole;

    const NCH: StrId = StrId(1);

    /// Records every callback in order.
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

    /// A source-to-drain chain of `devices` transistors, diode-connected at the
    /// low end. Device 0's gate is what makes the chain rigid: with the MOS
    /// channel collapsed, reversing a bare chain is a genuine automorphism.
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

    /// A differential pair, whose two halves are interchangeable by an
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

    /// Class counts are nondecreasing, rounds are announced consecutively from
    /// zero, and a round that split nothing is the last.
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
            assert_eq!(
                index, position,
                "round indices are not consecutive from zero"
            );
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

    /// The budget is three rounds and the chain needs more, so exactly three
    /// are announced.
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

    /// Under [`TieBreak::Refuse`] a differential pair's stall is reported and
    /// nothing is chosen.
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

    /// Every tie-broken class was first announced as stalled.
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
                observer
                    .stalled
                    .iter()
                    .any(|(stalled, ..)| stalled == class),
                "class {class:?} was tie-broken but never reported as stalled"
            );
        }
    }

    /// A rigid graph needs no tie-break at all, which is what stops the two
    /// tests above passing on an implementation that announces a stall on every
    /// class it looks at.
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
