//! Partition refinement: the matching algorithm, the iterative graph labelling
//! of C. Ebeling, "`GeminiII`: a second generation layout validation program",
//! ICCAD 1988, doi:10.1109/ICCAD.1988.122520.
//!
//! Data in: two graphs. Data out: a class per node on each side, plus per-class tallies.
//! Classes split by a hash of their neighbours' classes until stable; a pass re-signs
//! only the neighbours of nodes that changed class in the pass before. A balanced
//! stall is broken by pairing the lowest layout node of the stalled class holding
//! it with the reference node of that class whose parameters are closest (netgen's
//! "resolving symmetries by property value"), on a tie the net of the layout net's
//! label (`KLayout`'s `consider_net_names`), then the lowest, one class per stall.
//! A net has no parameters of its own: its closest is the one whose pairing puts
//! the diffusions of the transistors already paired closest at each channel end,
//! so symmetric channel nets pair the way the diffusions agree (testing-plan F98).
//!
//! Refinement cannot always split nodes that no relabelling exchanges, so the
//! closest node can be the wrong one (testing-plan F58). A pairing is a trial
//! while a match is still possible: refined until stable, it is kept when no
//! class holds more reference nodes than layout nodes and every device pair it
//! formed agrees on parameters; otherwise an undo log takes it back and the
//! next closest is tried, up to [`TRIES`]. When none fits, the closest is kept
//! and no later stall tries again, since a match is then out of reach.

use crate::lvs::controls::bound;
use crate::lvs::graph::{narrow, Graph};
use crate::lvs::reduce::ParamNames;
use crate::topology::TerminalRole;
use gpurify_ingest::deck::{DeviceKind, LvsControls};
use gpurify_ingest::StrId;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ClassId(pub(crate) u32);

/// The most reference nodes a stall tries its layout node against.
///
/// ponytail: depth one, eight wide. A wrong pairing that refinement exposes
/// only after a later tie-break is kept, and so is one whose right partner
/// ranks past the eighth; a search over several stalls fixes both if a
/// circuit ever needs it.
pub(crate) const TRIES: usize = 8;

/// One change a trial made, so a rejected trial can be taken back.
#[derive(Debug, Clone, Copy)]
enum Undo {
    /// [`Partition::place`] swapped these two `member` slots.
    Swap(u32, u32),
    /// [`Partition::carve`] made the last class out of this one.
    Carve(u32),
    /// A pass moved this class's start from this offset.
    Start(u32, u32),
}

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
    /// Classes holding more reference nodes than layout nodes. Splitting such a
    /// class leaves a part that still does, so once above zero no match is
    /// left to find.
    deficit: u32,
    /// Every change since the current trial began, while `trial` is set.
    log: Vec<Undo>,
    trial: bool,
    /// Set when a stall found no candidate that fits: a match is out of reach,
    /// and later stalls take their closest without trying others.
    hopeless: bool,
}

/// Splitmix64's finaliser.
const fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// A terminal's role as a signature number. Interchangeable roles share a code:
/// MOS `Source`/`Drain`, and a resistor's two ends (the graph builders write
/// both as `Pin(0)`). `Emitter` and `Collector` never share, and neither do a
/// diode's anode and cathode or a capacitor's plates, so a reversed diode is a
/// mismatch (testing-plan F15).
pub(crate) const fn role_code(role: TerminalRole) -> u64 {
    match role {
        TerminalRole::Gate => 0,
        TerminalRole::Source | TerminalRole::Drain => 1,
        TerminalRole::Bulk => 3,
        TerminalRole::Base => 4,
        TerminalRole::Emitter => 5,
        TerminalRole::Collector => 6,
        // Each pin position its own code: a diode's anode is not its cathode.
        // A resistor's ends are interchangeable, and the graph builders write
        // both as `Pin(0)` so they share this code.
        TerminalRole::Pin(position) => 16 + position as u64,
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
    mix(0x21 ^ (role_code(role) << 8) ^ ((class as u64) << 24))
}

/// Both graphs as one node space: layout nodes `0 .. split`, reference nodes after.
#[derive(Clone, Copy)]
struct Sides<'a> {
    layout: &'a Graph,
    reference: &'a Graph,
    split: u32,
    /// Which names trade places with source and drain.
    names: ParamNames,
    /// The deck's per-parameter tolerances.
    controls: &'a LvsControls,
    /// Each node's seed, layout nodes first: nodes of one seed start in a
    /// class of their own; `u32::MAX`, or a node past the end, has none.
    seeds: &'a [u32],
    /// Whether devices of one kind start in one class whatever their model.
    models_aside: bool,
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

/// `|a - b|` relative to the larger magnitude; zero when both are zero.
fn relative(a: f64, b: f64) -> f64 {
    let scale = a.abs().max(b.abs());
    if scale == 0.0 {
        0.0
    } else {
        (a - b).abs() / scale
    }
}

/// Which channel end a role is, as an index into [`ParamNames::diffusion`]:
/// 0 (`as`, `ps` at 2) for the source, 1 (`ad`, `pd` at 3) for the drain.
const fn channel_end(role: TerminalRole) -> Option<usize> {
    match role {
        TerminalRole::Source => Some(0),
        TerminalRole::Drain => Some(1),
        _ => None,
    }
}

impl Sides<'_> {
    /// How far apart the parameters of layout node `layout` and reference node
    /// `reference` are: per name the reference states, the relative difference
    /// when the layout states it too and one when it does not, summed. A name
    /// only the layout states is not compared (testing-plan F68). Zero for
    /// nets. Which channel end is which is not known yet, so diffusions are
    /// read both ways round and the closer taken.
    fn distance(self, layout: u32, reference: u32) -> f64 {
        let reference = reference - self.split;
        let (layout_devices, ref_devices) = (
            narrow(self.layout.device_count()),
            narrow(self.reference.device_count()),
        );
        if layout >= layout_devices || reference >= ref_devices {
            return 0.0;
        }
        let (mine, theirs) = (
            self.layout.params_of(layout),
            self.reference.params_of(reference),
        );
        let apart = |crossed: bool| -> f64 {
            theirs
                .iter()
                .map(|&(name, b)| {
                    let read = self.read(name, crossed);
                    mine.iter()
                        .find(|&&(n, _)| Some(n) == read)
                        .map_or(1.0, |&(_, a)| relative(a, b))
                })
                .sum()
        };
        apart(false).min(apart(true))
    }

    /// Whether layout node `layout` and reference node `reference` are other
    /// than two nets of one name, the layout net's label being the reference
    /// net's name. A symmetry between nets is broken toward the named one
    /// first, as `KLayout`'s `consider_net_names` "will employ net names
    /// to resolve ambiguities" (catalog LVS-032). Devices, and a layout net with
    /// no label, are always apart.
    fn named_apart(self, layout: u32, reference: u32) -> bool {
        let reference = reference - self.split;
        let (layout_devices, ref_devices) = (
            narrow(self.layout.device_count()),
            narrow(self.reference.device_count()),
        );
        if layout < layout_devices || reference < ref_devices {
            return true;
        }
        let label = self.layout.net_name[(layout - layout_devices) as usize];
        label.is_none() || label != self.reference.net_name[(reference - ref_devices) as usize]
    }

    /// The layout name a reference parameter `name` is read under: itself,
    /// or, `crossed`, its other channel end's.
    fn read(self, name: StrId, crossed: bool) -> Option<StrId> {
        if crossed {
            self.names.across(name)
        } else {
            Some(name)
        }
    }

    /// Whether layout node `layout` and reference node `reference` would pass
    /// the verdict's parameter comparison: every name the reference states
    /// stated by the layout too, each value within its bound of the other
    /// (the deck's row for the name, or `tolerance` relatively, a count
    /// exactly; `NaN` never is), diffusions either way round. Nets always do.
    fn agrees(self, layout: u32, reference: u32, tolerance: f64) -> bool {
        let reference = reference - self.split;
        if layout >= narrow(self.layout.device_count())
            || reference >= narrow(self.reference.device_count())
        {
            return true;
        }
        let model = self.reference.device_model[reference as usize];
        let (mine, theirs) = (
            self.layout.params_of(layout),
            self.reference.params_of(reference),
        );
        let agree = |crossed: bool| {
            theirs.iter().all(|&(name, b)| {
                let read = self.read(name, crossed);
                let within = bound(
                    self.controls,
                    self.names.tolerance(name, tolerance),
                    model,
                    name,
                );
                mine.iter()
                    .any(|&(other, a)| Some(other) == read && within.agree(a, b))
            })
        };
        agree(false) || agree(true)
    }
}

impl Partition {
    /// Devices one class per `(kind, model)`, nets one class; every node dirty.
    fn seed(&mut self, sides: Sides) {
        let mut key: Vec<(u64, u32)> = Vec::new();
        for (graph, offset) in [(sides.layout, 0), (sides.reference, sides.split)] {
            for device in 0..graph.device_count() {
                let model = if sides.models_aside {
                    0
                } else {
                    u64::from(graph.device_model[device].0)
                };
                let identity = (kind_code(graph.device_kind[device]) << 32) | model;
                key.push((identity, offset + narrow(device)));
            }
            let devices = graph.device_count();
            for net in 0..graph.net_count() {
                let node = offset + narrow(devices + net);
                // Below every unseeded net and above every device key.
                let seed = sides.seeds.get(node as usize).copied();
                let class = match seed {
                    Some(seed) if seed != u32::MAX => u64::MAX - 1 - u64::from(seed),
                    _ => u64::MAX,
                };
                key.push((class, node));
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
        self.deficit = narrow((0..self.start.len()).filter(|&c| self.short(c)).count());
        self.log.clear();
        self.trial = false;
        self.hopeless = false;
    }

    /// Whether `class` holds more reference nodes than layout nodes.
    fn short(&self, class: usize) -> bool {
        self.size[class] > 2 * self.layout_size[class]
    }

    /// Move `node` to position `to` of `member`, swapping out what was there.
    fn place(&mut self, node: u32, to: u32) {
        let from = self.slot[node as usize];
        let other = self.member[to as usize];
        self.member.swap(from as usize, to as usize);
        self.slot[other as usize] = from;
        self.slot[node as usize] = to;
        if self.trial {
            self.log.push(Undo::Swap(from, to));
        }
    }

    /// Carve `member[from .. from + count]` out of `parent` into a new class
    /// whose nodes become dirty. The caller re-points `parent`'s range.
    fn carve(&mut self, parent: u32, from: u32, count: u32, split: u32) {
        let class = narrow(self.start.len());
        let was_short = self.short(parent as usize);
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
        self.deficit = self.deficit - u32::from(was_short)
            + u32::from(self.short(parent as usize))
            + u32::from(self.short(class as usize));
        if self.trial {
            self.log.push(Undo::Carve(parent));
        }
    }

    /// Take back every change the log holds, newest first, leaving the
    /// partition as the trial found it but for `deficit`, which the caller
    /// restores.
    fn undo(&mut self) {
        while let Some(change) = self.log.pop() {
            match change {
                Undo::Swap(a, b) => {
                    self.member.swap(a as usize, b as usize);
                    self.slot[self.member[a as usize] as usize] = a;
                    self.slot[self.member[b as usize] as usize] = b;
                }
                Undo::Carve(parent) => {
                    let class = self.start.len() - 1;
                    let from = self.start[class] as usize;
                    for at in from..from + self.size[class] as usize {
                        self.class[self.member[at] as usize] = parent;
                    }
                    self.size[parent as usize] += self.size[class];
                    self.layout_size[parent as usize] += self.layout_size[class];
                    self.start.pop();
                    self.size.pop();
                    self.layout_size.pop();
                }
                Undo::Start(class, from) => self.start[class as usize] = from,
            }
        }
        self.dirty.clear();
        self.next_dirty.clear();
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
            if self.trial {
                self.log
                    .push(Undo::Start(parent, self.start[parent as usize]));
            }
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

    /// The reference nodes of `node`'s class.
    fn mates(&self, node: u32, split: u32) -> impl Iterator<Item = u32> + '_ {
        let class = self.class[node as usize] as usize;
        let from = self.start[class] as usize;
        self.member[from..from + self.size[class] as usize]
            .iter()
            .copied()
            .filter(move |&member| member >= split)
    }

    /// How far apart layout node `node` and reference node `mate` are:
    /// their parameters' [distance](Sides::distance) for devices, and for
    /// nets the diffusions pairing them would put at one channel end
    /// ([`Self::end_distance`]).
    fn apart(&self, node: u32, mate: u32, sides: Sides) -> f64 {
        if node < narrow(sides.layout.device_count()) {
            sides.distance(node, mate)
        } else {
            self.end_distance(node, mate, sides)
        }
    }

    /// How far apart the diffusions are that pairing layout net `net` with
    /// reference net `mate` puts at one channel end: for each source or
    /// drain on `net` whose transistor a class already pairs one to one, and
    /// whose mate has a source or drain on `mate`, each diffusion name the
    /// mate states at that end against the layout's at its own, as
    /// [`Sides::distance`] weighs them. Nothing else is told apart by a
    /// net's pairing, so it is zero where no such transistor is.
    fn end_distance(&self, net: u32, mate: u32, sides: Sides) -> f64 {
        let ref_devices = narrow(sides.reference.device_count());
        let ref_net = mate - sides.split - ref_devices;
        let names = sides.names.diffusion;
        let mut apart = 0.0;
        sides.for_each_neighbour(net, |role, device| {
            let class = self.class[device as usize] as usize;
            let Some(mine) = channel_end(role) else {
                return;
            };
            if self.size[class] != 2 || self.layout_size[class] != 1 {
                return;
            }
            let from = self.start[class] as usize;
            let other = self.member[from].max(self.member[from + 1]) - sides.split;
            let (nets, roles) = sides.reference.terminals_of(other);
            let Some(theirs) = nets
                .iter()
                .zip(roles)
                .find_map(|(&at, &role)| channel_end(role).filter(|_| at == ref_net))
            else {
                return;
            };
            let (layout, reference) = (
                sides.layout.params_of(device),
                sides.reference.params_of(other),
            );
            // Area, then perimeter.
            for k in [0, 2] {
                let (Some(read), Some(stated)) = (names[mine + k], names[theirs + k]) else {
                    continue;
                };
                if let Some(&(_, b)) = reference.iter().find(|&&(name, _)| name == stated) {
                    let a = layout.iter().find(|&&(name, _)| name == read);
                    apart += a.map_or(1.0, |&(_, a)| relative(a, b));
                }
            }
        });
        apart
    }

    /// The reference node of `node`'s class that is [closest](Self::apart);
    /// on a tie, a net of the name `node` carries ([`Sides::named_apart`]),
    /// then the lowest.
    ///
    /// ponytail: O(class size) per stall; keep members sorted per class if a
    /// huge class of isolated nodes ever shows up in a profile.
    fn closest(&self, node: u32, sides: Sides) -> u32 {
        self.mates(node, sides.split)
            .min_by(|&a, &b| {
                let (da, db) = (self.apart(node, a, sides), self.apart(node, b, sides));
                let (na, nb) = (sides.named_apart(node, a), sides.named_apart(node, b));
                da.total_cmp(&db).then(na.cmp(&nb)).then(a.cmp(&b))
            })
            .expect("a stalled class holds reference nodes")
    }

    /// The next [`TRIES`] − 1 reference nodes of `node`'s class after
    /// `closest`, in the same order: closest parameters first, then a net of
    /// `node`'s name, then the lowest.
    fn ranked(&self, node: u32, sides: Sides, closest: u32) -> Vec<u32> {
        let mut ranked: Vec<(f64, bool, u32)> = self
            .mates(node, sides.split)
            .filter(|&mate| mate != closest)
            .map(|mate| {
                (
                    self.apart(node, mate, sides),
                    sides.named_apart(node, mate),
                    mate,
                )
            })
            .collect();
        ranked.sort_unstable_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
        ranked.truncate(TRIES - 1);
        ranked.into_iter().map(|(_, _, mate)| mate).collect()
    }

    /// Pair `node` with `mate`, a reference node of its class, as a new class
    /// of their own whose two nodes are dirty.
    fn pair(&mut self, node: u32, mate: u32, split: u32) {
        let class = self.class[node as usize];
        let end = self.start[class as usize] + self.size[class as usize];
        self.place(node, end - 2);
        self.place(mate, end - 1);
        self.next_dirty.clear();
        self.carve(class, end - 2, 2, split);
        std::mem::swap(&mut self.dirty, &mut self.next_dirty);
    }

    /// Whether a settled trial can still be part of a match: no class short of
    /// layout nodes, and every one-to-one device class it made, the classes
    /// from `fresh` on and the ones they were carved from, agreeing on
    /// parameters.
    fn fits(&self, sides: Sides, tolerance: f64, fresh: usize) -> bool {
        let carved = self.log.iter().filter_map(|change| match *change {
            Undo::Carve(parent) => Some(parent as usize),
            _ => None,
        });
        self.deficit == 0
            && (fresh..self.start.len()).chain(carved).all(|class| {
                if self.size[class] != 2 || self.layout_size[class] != 1 {
                    return true;
                }
                let from = self.start[class] as usize;
                let (a, b) = (self.member[from], self.member[from + 1]);
                let (layout, reference) = (a.min(b), a.max(b));
                sides.agrees(layout, reference, tolerance)
            })
    }

    /// Pass until no class splits. Returns `false` when more than
    /// `max_rounds` passes in a row split one.
    fn settle(&mut self, sides: Sides, max_rounds: u32, pass: &mut u32) -> bool {
        let mut rounds = 0u32;
        while !self.dirty.is_empty() {
            *pass += 1;
            if self.pass(sides, *pass) {
                if rounds == max_rounds {
                    return false;
                }
                rounds += 1;
            }
        }
        true
    }

    /// Break the stall at layout node `node`: pair it with its closest
    /// reference node and settle, trying the next closest in turn while the
    /// result does not [fit](Self::fits) and a match is still possible.
    /// Returns `false` when a settle runs out of rounds.
    fn resolve(
        &mut self,
        node: u32,
        sides: Sides,
        (max_rounds, tolerance): (u32, f64),
        pass: &mut u32,
    ) -> bool {
        let closest = self.closest(node, sides);
        if self.hopeless || self.deficit > 0 {
            self.pair(node, closest, sides.split);
            return self.settle(sides, max_rounds, pass);
        }
        let (deficit, fresh) = (self.deficit, self.start.len());
        let mut ranked: Option<Vec<u32>> = None;
        let mut tried = 0;
        let mut mate = closest;
        loop {
            self.trial = true;
            self.log.clear();
            self.pair(node, mate, sides.split);
            let settled = self.settle(sides, max_rounds, pass);
            self.trial = false;
            if !settled {
                return false;
            }
            if self.fits(sides, tolerance, fresh) {
                return true;
            }
            self.undo();
            self.deficit = deficit;
            let others = ranked.get_or_insert_with(|| self.ranked(node, sides, closest));
            let Some(&next) = others.get(tried) else {
                break;
            };
            tried += 1;
            mate = next;
        }
        // Nothing tried fits, so no match is left to find: the closest, and
        // no more trials.
        self.hopeless = true;
        self.pair(node, closest, sides.split);
        self.settle(sides, max_rounds, pass)
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
/// at each tie-break and each trial of one, so the number of symmetries does
/// not spend it. `tolerance` and the deck's `controls` are the verdict's,
/// which a trial pairing's devices must meet. Nets sharing a `seeds` entry
/// (indexed by node, layout nodes first) start in a class of their own, and
/// with `models_aside` devices start one class per kind rather than per
/// kind and model.
pub(crate) fn refine_into(
    (layout, reference): (&Graph, &Graph),
    (max_rounds, tolerance): (u32, f64),
    (names, controls, seeds, models_aside): (ParamNames, &LvsControls, &[u32], bool),
    out: &mut Partition,
) -> bool {
    let split = narrow(layout.device_count() + layout.net_count());
    let sides = Sides {
        layout,
        reference,
        split,
        names,
        controls,
        seeds,
        models_aside,
    };
    out.seed(sides);

    let (mut pass, mut cursor) = (0u32, 0u32);
    if !out.settle(sides, max_rounds, &mut pass) {
        return false;
    }
    loop {
        while cursor < split && out.settled(cursor) {
            cursor += 1;
        }
        let Some(node) = (cursor..split).find(|&node| out.stalled(node)) else {
            out.publish(split);
            return true;
        };
        if !out.resolve(node, sides, (max_rounds, tolerance), &mut pass) {
            return false;
        }
    }
}
