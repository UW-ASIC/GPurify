//! Partition refinement: the matching algorithm.
//!
//! Data in: two graphs. Data out: a class per node on each side, plus per-class tallies.
//! Classes split by a hash of their neighbours' classes until stable; a pass re-signs
//! only the neighbours of nodes that changed class in the pass before. A balanced
//! stall is broken by pairing the lowest node index on each side of the stalled class
//! holding the lowest layout node, one class per stall.

use crate::lvs::graph::{narrow, Graph};
use crate::topology::TerminalRole;
use gpurify_ingest::deck::DeviceKind;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ClassId(pub(crate) u32);

/// Refinement state for both graphs. Node index is devices first, then nets;
/// internally layout nodes come first and reference nodes follow them.
#[derive(Debug, Default)]
pub(crate) struct Partition {
    /// Output, valid after a refinement that did not exhaust: each layout
    /// node's class, nodes per class on each side, and the lowest reference
    /// node in each class (`u32::MAX` when it has none).
    pub(crate) layout_class: Vec<ClassId>,
    pub(crate) layout_tally: Vec<u32>,
    pub(crate) ref_tally: Vec<u32>,
    pub(crate) ref_first: Vec<u32>,

    /// Class of every node.
    class: Vec<u32>,
    /// Nodes grouped by class: class `c` is `member[start[c] .. start[c] + size[c]]`.
    member: Vec<u32>,
    /// Where each node sits in `member`.
    slot: Vec<u32>,
    start: Vec<u32>,
    size: Vec<u32>,
    /// Layout nodes per class; the rest of `size` is reference nodes.
    layout_size: Vec<u32>,
    /// Nodes whose class changed since the last pass, and the next such set.
    dirty: Vec<u32>,
    next_dirty: Vec<u32>,
    /// `(class, signature, node)` for every node a pass re-signs.
    touched: Vec<(u32, u64, u32)>,
    /// Pass number that last touched each node.
    seen: Vec<u32>,
    /// `(offset, length)` of each part a class splits into.
    parts: Vec<(u32, u32)>,
}

/// Splitmix64's finaliser.
const fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// A terminal's role as a signature number. Interchangeable roles share a code:
/// MOS `Source`/`Drain` and every `Pin(_)`; `Emitter` and `Collector` never do.
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

pub(crate) const fn kind_code(kind: DeviceKind) -> u64 {
    match kind {
        DeviceKind::Mos => 0,
        DeviceKind::Bjt => 1,
        DeviceKind::Resistor => 2,
        DeviceKind::Capacitor => 3,
        DeviceKind::Diode => 4,
    }
}

/// One neighbour's contribution; summed with `wrapping_add`, so order-free.
const fn neighbour(role: TerminalRole, class: u32) -> u64 {
    mix(0x21 ^ (role_code(role) << 8) ^ ((class as u64) << 16))
}

/// Both graphs as one node space: layout nodes `0 .. split`, reference nodes after.
#[derive(Clone, Copy)]
struct Sides<'a> {
    layout: &'a Graph,
    reference: &'a Graph,
    split: u32,
}

impl Sides<'_> {
    /// Call `visit(role, neighbour)` for each edge of `node`. A terminal on no net has none.
    fn for_each_neighbour(self, node: u32, mut visit: impl FnMut(TerminalRole, u32)) {
        let (graph, offset) = if node < self.split {
            (self.layout, 0)
        } else {
            (self.reference, self.split)
        };
        let local = node - offset;
        let devices = narrow(graph.device_count());
        if local < devices {
            let (nets, roles) = graph.terminals_of(local);
            for (&net, &role) in nets.iter().zip(roles) {
                if net != u32::MAX {
                    visit(role, offset + devices + net);
                }
            }
        } else {
            for &(device, role) in graph.terminals_on(local - devices) {
                visit(role, offset + device);
            }
        }
    }
}

impl Partition {
    /// Devices one class per `(kind, model)`, nets one class; every node dirty.
    fn seed(&mut self, sides: Sides) {
        let mut key: Vec<(u64, u32)> = Vec::new();
        for (graph, offset) in [(sides.layout, 0), (sides.reference, sides.split)] {
            for device in 0..graph.device_count() {
                let identity = (kind_code(graph.device_kind[device]) << 32)
                    | u64::from(graph.device_model[device].0);
                key.push((identity, offset + narrow(device)));
            }
            let devices = graph.device_count();
            for net in 0..graph.net_count() {
                key.push((u64::MAX, offset + narrow(devices + net)));
            }
        }
        key.sort_unstable();

        let nodes = key.len();
        self.class.clear();
        self.class.resize(nodes, 0);
        self.slot.clear();
        self.slot.resize(nodes, 0);
        self.member.clear();
        self.start.clear();
        self.size.clear();
        self.layout_size.clear();
        for (at, &(identity, node)) in key.iter().enumerate() {
            if at == 0 || identity != key[at - 1].0 {
                self.start.push(narrow(at));
                self.size.push(0);
                self.layout_size.push(0);
            }
            let class = self.start.len() - 1;
            self.class[node as usize] = narrow(class);
            self.slot[node as usize] = narrow(at);
            self.member.push(node);
            self.size[class] += 1;
            self.layout_size[class] += u32::from(node < sides.split);
        }
        self.dirty.clear();
        self.dirty.extend(0..narrow(nodes));
        self.seen.clear();
        self.seen.resize(nodes, 0);
    }

    /// Move `node` to position `to` of `member`, swapping out what was there.
    fn place(&mut self, node: u32, to: u32) {
        let from = self.slot[node as usize];
        let other = self.member[to as usize];
        self.member.swap(from as usize, to as usize);
        self.slot[other as usize] = from;
        self.slot[node as usize] = to;
    }

    /// Carve `member[from .. from + count]` out of `parent` into a new class
    /// whose nodes become dirty. The caller re-points `parent`'s range.
    fn carve(&mut self, parent: u32, from: u32, count: u32, split: u32) {
        let class = narrow(self.start.len());
        let mut layout = 0;
        for at in from..from + count {
            let node = self.member[at as usize];
            self.class[node as usize] = class;
            self.next_dirty.push(node);
            layout += u32::from(node < split);
        }
        self.start.push(from);
        self.size.push(count);
        self.layout_size.push(layout);
        self.size[parent as usize] -= count;
        self.layout_size[parent as usize] -= layout;
    }

    /// Re-sign every neighbour of a dirty node and split its class by signature.
    /// Nodes of a class no dirty node touches keep their signature, so they stay
    /// together; the largest part keeps the class id. Returns whether anything split.
    fn pass(&mut self, sides: Sides, pass: u32) -> bool {
        self.touched.clear();
        for at in 0..self.dirty.len() {
            let (class, seen, touched) = (&self.class, &mut self.seen, &mut self.touched);
            sides.for_each_neighbour(self.dirty[at], |_, next| {
                if seen[next as usize] != pass {
                    seen[next as usize] = pass;
                    touched.push((class[next as usize], 0, next));
                }
            });
        }
        for entry in &mut self.touched {
            let class = &self.class;
            let mut signature = 0u64;
            sides.for_each_neighbour(entry.2, |role, next| {
                signature = signature.wrapping_add(neighbour(role, class[next as usize]));
            });
            entry.1 = signature;
        }
        self.touched.sort_unstable();

        self.next_dirty.clear();
        let touched = std::mem::take(&mut self.touched);
        let mut run_start = 0;
        while run_start < touched.len() {
            let parent = touched[run_start].0;
            let run_end = run_start + touched[run_start..].partition_point(|t| t.0 == parent);
            let run = &touched[run_start..run_end];
            run_start = run_end;

            let untouched = self.size[parent as usize] - narrow(run.len());
            if untouched == 0 && run[0].1 == run[run.len() - 1].1 {
                continue;
            }
            // Touched nodes to the tail, grouped by signature; untouched ones lead.
            let base = self.start[parent as usize] + untouched;
            for (at, &(_, _, node)) in run.iter().enumerate() {
                self.place(node, base + narrow(at));
            }
            // Parts as (offset, length): the untouched lead, then one per signature.
            let mut parts = std::mem::take(&mut self.parts);
            parts.clear();
            if untouched > 0 {
                parts.push((self.start[parent as usize], untouched));
            }
            let mut group = 0;
            for at in 1..=run.len() {
                if at == run.len() || run[at].1 != run[group].1 {
                    parts.push((base + narrow(group), narrow(at - group)));
                    group = at;
                }
            }
            let keep = parts
                .iter()
                .enumerate()
                .max_by_key(|&(at, &(_, length))| (length, std::cmp::Reverse(at)))
                .map_or(0, |(at, _)| at);
            self.start[parent as usize] = parts[keep].0;
            for (at, &(from, length)) in parts.iter().enumerate() {
                if at != keep {
                    self.carve(parent, from, length, sides.split);
                }
            }
            self.parts = parts;
        }
        self.touched = touched;
        std::mem::swap(&mut self.dirty, &mut self.next_dirty);
        !self.dirty.is_empty()
    }

    /// A layout node's class holds nodes on both sides, as many on each, and
    /// more than one: a symmetry only a tie-break can resolve.
    fn stalled(&self, node: u32) -> bool {
        let class = self.class[node as usize] as usize;
        let layout = self.layout_size[class];
        layout >= 2 && self.size[class] == 2 * layout
    }

    /// A layout node's class can never stall again: it is paired one to one,
    /// or holds no reference node, and splitting keeps it so.
    fn settled(&self, node: u32) -> bool {
        let class = self.class[node as usize] as usize;
        let layout = self.layout_size[class];
        self.size[class] == layout || (layout == 1 && self.size[class] == 2)
    }

    /// Pair `node` with the lowest reference node of its class, as a new class
    /// of their own.
    fn tie_break(&mut self, node: u32, split: u32) {
        let class = self.class[node as usize];
        let (from, end) = (
            self.start[class as usize],
            self.start[class as usize] + self.size[class as usize],
        );
        // ponytail: O(class size) per stall; keep members sorted per class if a
        // huge class of isolated nodes ever shows up in a profile.
        let mate = self.member[from as usize..end as usize]
            .iter()
            .copied()
            .filter(|&member| member >= split)
            .min()
            .expect("a stalled class holds reference nodes");
        self.place(node, end - 2);
        self.place(mate, end - 1);
        self.next_dirty.clear();
        self.carve(class, end - 2, 2, split);
        std::mem::swap(&mut self.dirty, &mut self.next_dirty);
    }

    /// Per-class tallies and the layout classes, as the verdict reads them.
    fn publish(&mut self, split: u32) {
        self.layout_tally.clone_from(&self.layout_size);
        self.ref_tally.clear();
        self.ref_tally.extend(
            self.size
                .iter()
                .zip(&self.layout_size)
                .map(|(&all, &layout)| all - layout),
        );
        self.ref_first.clear();
        self.ref_first.resize(self.start.len(), u32::MAX);
        for (node, &class) in self.class.iter().enumerate().skip(split as usize) {
            let first = &mut self.ref_first[class as usize];
            *first = (*first).min(narrow(node) - split);
        }
        self.layout_class.clear();
        self.layout_class.extend(
            self.class[..split as usize]
                .iter()
                .map(|&class| ClassId(class)),
        );
    }
}

/// Refine until stable, leaving classes and tallies in `out`. Returns `false`
/// when more than `max_rounds` passes in a row split a class without reaching a
/// stall, which says nothing about whether the graphs match. The count restarts
/// at each tie-break, so the number of symmetries does not spend it.
pub(crate) fn refine_into(
    layout: &Graph,
    reference: &Graph,
    max_rounds: u32,
    out: &mut Partition,
) -> bool {
    let split = narrow(layout.device_count() + layout.net_count());
    let sides = Sides {
        layout,
        reference,
        split,
    };
    out.seed(sides);

    let (mut rounds, mut pass, mut cursor) = (0u32, 0u32, 0u32);
    loop {
        if out.dirty.is_empty() {
            while cursor < split && out.settled(cursor) {
                cursor += 1;
            }
            let Some(node) = (cursor..split).find(|&node| out.stalled(node)) else {
                out.publish(split);
                return true;
            };
            out.tie_break(node, split);
            rounds = 0;
        }
        pass += 1;
        if out.pass(sides, pass) {
            if rounds == max_rounds {
                return false;
            }
            rounds += 1;
        }
    }
}
