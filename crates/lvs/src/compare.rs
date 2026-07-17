//! Netlist comparison via probabilistic partition refinement (netgen-style).
//!
//! Both extracted and reference graphs are loaded into a shared class space.
//! Each refinement round computes hash values for devices and nets using
//! XOR+SUM of random magic numbers, then fractures classes where hashes differ.
//! After convergence, automorphisms are broken by forcing unique IDs on one
//! ambiguous pair at a time.
//!
//! Two-terminal devices (R, C, diode) are full graph participants — not count-only.

use super::types::*;
use super::{BoxedRule, LvsCtx};
use crate::backend::Backend;
use crate::schema::PropertyTolerance;
use std::cell::RefCell;
use std::collections::HashMap;

// --- public helpers used by extract.rs reduce_netlist ---

pub fn kind_tag(k: &DeviceKind) -> u32 {
    match k {
        DeviceKind::Nmos => 0,
        DeviceKind::Pmos => 1,
        DeviceKind::Npn | DeviceKind::Pnp => 0,
    }
}
pub fn flavor_tag(f: &DeviceFlavor) -> u32 {
    match f {
        DeviceFlavor::Standard => 0,
        DeviceFlavor::Lvt => 1,
        DeviceFlavor::Hvt => 2,
    }
}
#[allow(dead_code)]
fn kind_name(tag: u32) -> &'static str {
    if tag == 0 {
        "Nmos"
    } else {
        "Pmos"
    }
}
#[allow(dead_code)]
fn flavor_name(tag: u32) -> &'static str {
    match tag {
        1 => "Lvt",
        2 => "Hvt",
        _ => "Std",
    }
}

fn bjt_kind_tag(k: &DeviceKind) -> u32 {
    match k {
        DeviceKind::Npn => 50,
        DeviceKind::Pnp => 51,
        _ => 50,
    }
}

fn two_term_kind_tag(k: &TwoTerminalKind) -> u32 {
    match k {
        TwoTerminalKind::Resistor => 0,
        TwoTerminalKind::Diode => 1,
        TwoTerminalKind::Capacitor => 2,
    }
}

#[allow(dead_code)]
fn two_term_kind_label(tag: u32) -> &'static str {
    match tag {
        0 => "Resistor",
        1 => "Diode",
        _ => "Capacitor",
    }
}

// --- PRNG (xorshift64, deterministic) ---

pub(super) struct Rng {
    state: u64,
}
impl Rng {
    pub(super) fn new(seed: u64) -> Self {
        Rng { state: seed }
    }
    pub(super) fn next(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }
}

// --- graph representation ---

pub(super) const MAX_PINS: usize = 4;

// Pin roles — permutable pins share the same role index so they get the
// same pin_magic value, making the hash invariant to their ordering.
const ROLE_GATE: u8 = 0;
const ROLE_SD: u8 = 1; // source+drain share this when non-strict
const ROLE_SOURCE: u8 = 1; // strict: source gets its own
const ROLE_DRAIN: u8 = 2; // strict: drain distinct from source
#[allow(dead_code)]
const ROLE_BODY: u8 = 3;
const ROLE_TERM: u8 = 4; // symmetric two-terminal (R, C): pins permutable
const ROLE_COLLECTOR: u8 = 5; // BJT collector
const ROLE_BASE: u8 = 6; // BJT base
const ROLE_EMITTER: u8 = 7; // BJT emitter
const ROLE_ANODE: u8 = 8; // diode: polarity is never permutable
const ROLE_CATHODE: u8 = 9;
pub(super) const NUM_ROLES: usize = 10;

/// Two-terminal pin roles: diodes are polar (terminal_a = anode by extraction
/// convention), resistors and capacitors are symmetric.
fn two_term_roles(k: &TwoTerminalKind) -> [u8; 2] {
    match k {
        TwoTerminalKind::Diode => [ROLE_ANODE, ROLE_CATHODE],
        _ => [ROLE_TERM, ROLE_TERM],
    }
}

pub(super) struct GraphDev {
    pub(super) seed: u32,
    pub(super) pin_count: u8,
    pub(super) nets: [u32; MAX_PINS],
    pub(super) roles: [u8; MAX_PINS],
    /// Index into original device arrays for parametric checks.
    /// For MOS: index into ext.devices / reference.devices.
    /// For two-terminal: u32::MAX (no parametric check on them yet).
    pub(super) orig_idx: u32,
    pub(super) is_mos: bool,
}

pub(super) struct TopoGraph {
    pub(super) devs: Vec<GraphDev>,
    pub(super) net_count: usize,
}

/// Resolve MOS pin roles from CompareOpts pin_swaps. If a swap group covers
/// both "source" and "drain", those pins share a role (like ROLE_SD).
/// Returns (source_role, drain_role).
// ponytail: only MOS S/D swap is meaningful today; generalize role mapping
// when multi-terminal device families (e.g. 4-input gates) appear.
fn mos_roles_from_swaps(strict: bool, pin_swaps: &[PinSwapGroup]) -> (u8, u8) {
    if strict {
        // In strict mode, only explicit pin swaps override the distinct roles.
        let has_sd_swap = pin_swaps.iter().any(|g| {
            g.terminals.iter().any(|t| t == "source" || t == "S")
                && g.terminals.iter().any(|t| t == "drain" || t == "D")
        });
        if has_sd_swap {
            (ROLE_SD, ROLE_SD)
        } else {
            (ROLE_SOURCE, ROLE_DRAIN)
        }
    } else {
        // Default non-strict: S/D are always permutable unless a swap group
        // explicitly separates them (not needed in practice).
        (ROLE_SD, ROLE_SD)
    }
}

pub(super) fn graph_from_extracted(
    ext: &ExtractedNetlist,
    strict: bool,
    pin_swaps: &[PinSwapGroup],
) -> TopoGraph {
    let mut remap: HashMap<u32, u32> = HashMap::new();
    let mut local = |n: u32| -> u32 {
        let next = remap.len() as u32;
        *remap.entry(n).or_insert(next)
    };
    let mut devs = Vec::new();

    let (sr, dr_r) = mos_roles_from_swaps(strict, pin_swaps);

    // ponytail: body pin omitted until Phase 3 implements well extraction.
    // body=0 placeholder would collide with real net IDs in the remap.
    for (i, d) in ext.devices.iter().enumerate() {
        let g = local(d.gate);
        let s = local(d.source);
        let dr = local(d.drain);
        let mut seed = kind_tag(&d.kind) * 3 + flavor_tag(&d.flavor);
        // DMOS gets a distinct seed offset from regular MOS
        if d.device_class.as_deref() == Some("dmos") {
            seed += 20;
        }
        devs.push(GraphDev {
            seed,
            pin_count: 3,
            nets: [g, s, dr, 0],
            roles: [ROLE_GATE, sr, dr_r, 0],
            orig_idx: i as u32,
            is_mos: true,
        });
    }

    // BJT devices (3-pin: collector, base, emitter)
    for d in &ext.bjt_devices {
        let c = local(d.collector);
        let b = local(d.base);
        let e = local(d.emitter);
        let seed = bjt_kind_tag(&d.kind);
        devs.push(GraphDev {
            seed,
            pin_count: 3,
            nets: [c, b, e, 0],
            roles: [ROLE_COLLECTOR, ROLE_BASE, ROLE_EMITTER, 0],
            orig_idx: u32::MAX,
            is_mos: false,
        });
    }

    for d in &ext.two_terminal {
        let a = local(d.terminal_a);
        let b = local(d.terminal_b);
        // seed by KIND only: matching is topology-driven, not name-driven —
        // auto-generated layout names must never have to line up with the schematic.
        let seed = 100 + two_term_kind_tag(&d.kind) * 10;
        let [ra, rb] = two_term_roles(&d.kind);
        devs.push(GraphDev {
            seed,
            pin_count: 2,
            nets: [a, b, 0, 0],
            roles: [ra, rb, 0, 0],
            orig_idx: u32::MAX,
            is_mos: false,
        });
    }

    TopoGraph {
        devs,
        net_count: remap.len(),
    }
}

pub(super) fn graph_from_reference(
    reference: &RefNetlist,
    strict: bool,
    pin_swaps: &[PinSwapGroup],
) -> (TopoGraph, HashMap<String, u32>) {
    let mut remap: HashMap<String, u32> = HashMap::new();
    let mut local = |n: &str| -> u32 {
        if let Some(&v) = remap.get(n) {
            return v;
        }
        let next = remap.len() as u32;
        remap.insert(n.to_string(), next);
        next
    };
    let mut devs = Vec::new();

    let (sr, dr_r) = mos_roles_from_swaps(strict, pin_swaps);

    for (i, d) in reference.devices.iter().enumerate() {
        let g = local(&d.gate);
        let s = local(&d.source);
        let dr = local(&d.drain);
        let seed = kind_tag(&d.kind) * 3 + flavor_tag(&d.flavor);
        devs.push(GraphDev {
            seed,
            pin_count: 3,
            nets: [g, s, dr, 0],
            roles: [ROLE_GATE, sr, dr_r, 0],
            orig_idx: i as u32,
            is_mos: true,
        });
    }

    // BJT devices (3-pin: collector, base, emitter)
    for d in &reference.ref_bjt {
        let c = local(&d.collector);
        let b = local(&d.base);
        let e = local(&d.emitter);
        let seed = bjt_kind_tag(&d.kind);
        devs.push(GraphDev {
            seed,
            pin_count: 3,
            nets: [c, b, e, 0],
            roles: [ROLE_COLLECTOR, ROLE_BASE, ROLE_EMITTER, 0],
            orig_idx: u32::MAX,
            is_mos: false,
        });
    }

    for d in &reference.ref_two_terminal {
        let a = local(&d.terminal_a);
        let b = local(&d.terminal_b);
        let seed = 100 + two_term_kind_tag(&d.kind) * 10;
        let [ra, rb] = two_term_roles(&d.kind);
        devs.push(GraphDev {
            seed,
            pin_count: 2,
            nets: [a, b, 0, 0],
            roles: [ra, rb, 0, 0],
            orig_idx: u32::MAX,
            is_mos: false,
        });
    }

    let net_count = remap.len();
    (TopoGraph { devs, net_count }, remap)
}

// --- probabilistic partition refinement ---

pub(super) fn build_pin_magic(rng: &mut Rng) -> [u64; NUM_ROLES] {
    let mut m = [0u64; NUM_ROLES];
    for i in 0..NUM_ROLES {
        m[i] = rng.next();
    }
    m
}

/// Compute hash for each device: SUM over pins of (pin_magic[role] XOR class_magic[net_class]).
fn compute_dev_hashes(
    g: &TopoGraph,
    net_class: &[u32],
    pin_magic: &[u64; NUM_ROLES],
    class_magic: &[u64],
) -> Vec<u64> {
    g.devs
        .iter()
        .map(|d| {
            let mut h: u64 = 0;
            for i in 0..d.pin_count as usize {
                let nc = net_class[d.nets[i] as usize];
                let cm = class_magic.get(nc as usize).copied().unwrap_or(0);
                h = h.wrapping_add(pin_magic[d.roles[i] as usize] ^ cm);
            }
            h
        })
        .collect()
}

/// Compute hash for each net: SUM over incident device terminals of (pin_magic[role] XOR class_magic[dev_class]).
fn compute_net_hashes(
    g: &TopoGraph,
    dev_class: &[u32],
    pin_magic: &[u64; NUM_ROLES],
    class_magic: &[u64],
    net_count: usize,
) -> Vec<u64> {
    let mut hashes = vec![0u64; net_count];
    let mut has_term = vec![false; net_count];
    for (di, d) in g.devs.iter().enumerate() {
        let dc = dev_class[di];
        let cm = class_magic.get(dc as usize).copied().unwrap_or(0);
        for i in 0..d.pin_count as usize {
            let net = d.nets[i] as usize;
            if net < net_count {
                hashes[net] = hashes[net].wrapping_add(pin_magic[d.roles[i] as usize] ^ cm);
                has_term[net] = true;
            }
        }
    }
    // Nets with no terminals get a sentinel hash
    for i in 0..net_count {
        if !has_term[i] {
            hashes[i] = u64::MAX;
        }
    }
    hashes
}

/// Fracture device classes: within each existing class, elements with different hashes
/// get split into new classes. Both graphs are fractured jointly (shared class space).
fn fracture_devs(
    cls_a: &mut [u32],
    hash_a: &[u64],
    cls_b: &mut [u32],
    hash_b: &[u64],
    class_magic: &mut Vec<u64>,
    rng: &mut Rng,
) -> bool {
    let mut groups: HashMap<u32, HashMap<u64, (Vec<usize>, Vec<usize>)>> = HashMap::new();
    for (i, (&c, &h)) in cls_a.iter().zip(hash_a).enumerate() {
        groups.entry(c).or_default().entry(h).or_default().0.push(i);
    }
    for (i, (&c, &h)) in cls_b.iter().zip(hash_b).enumerate() {
        groups.entry(c).or_default().entry(h).or_default().1.push(i);
    }
    let mut changed = false;
    for (_, hash_groups) in &groups {
        if hash_groups.len() <= 1 {
            continue;
        }
        changed = true;
        // First hash group keeps original class; others get new classes.
        let mut first = true;
        for (_, (ma, mb)) in hash_groups {
            if first {
                first = false;
                continue;
            }
            let new_cls = class_magic.len() as u32;
            class_magic.push(rng.next());
            for &m in ma {
                cls_a[m] = new_cls;
            }
            for &m in mb {
                cls_b[m] = new_cls;
            }
        }
    }
    changed
}

/// Fracture net classes — same algorithm as device fracturing.
fn fracture_nets(
    cls_a: &mut [u32],
    hash_a: &[u64],
    cls_b: &mut [u32],
    hash_b: &[u64],
    class_magic: &mut Vec<u64>,
    rng: &mut Rng,
) -> bool {
    fracture_devs(cls_a, hash_a, cls_b, hash_b, class_magic, rng)
}

/// Run refinement until no class splits occur.
fn iterate_to_fixpoint(
    ga: &TopoGraph,
    gb: &TopoGraph,
    dev_cls_a: &mut Vec<u32>,
    dev_cls_b: &mut Vec<u32>,
    net_cls_a: &mut Vec<u32>,
    net_cls_b: &mut Vec<u32>,
    class_magic: &mut Vec<u64>,
    pin_magic: &[u64; NUM_ROLES],
    rng: &mut Rng,
) {
    for _ in 0..1000 {
        let dh_a = compute_dev_hashes(ga, net_cls_a, pin_magic, class_magic);
        let dh_b = compute_dev_hashes(gb, net_cls_b, pin_magic, class_magic);
        let d_changed = fracture_devs(dev_cls_a, &dh_a, dev_cls_b, &dh_b, class_magic, rng);

        let nh_a = compute_net_hashes(ga, dev_cls_a, pin_magic, class_magic, ga.net_count);
        let nh_b = compute_net_hashes(gb, dev_cls_b, pin_magic, class_magic, gb.net_count);
        let n_changed = fracture_nets(net_cls_a, &nh_a, net_cls_b, &nh_b, class_magic, rng);

        if !d_changed && !n_changed {
            break;
        }
    }
}

/// Count ambiguous classes (>1 member in BOTH graphs).
/// Device and net classes are checked separately since their ID spaces may overlap
/// at initial seeds.
fn count_ambiguous(
    dev_cls_a: &[u32],
    dev_cls_b: &[u32],
    net_cls_a: &[u32],
    net_cls_b: &[u32],
) -> usize {
    let mut count = 0;
    // Device classes
    let mut da: HashMap<u32, usize> = HashMap::new();
    let mut db: HashMap<u32, usize> = HashMap::new();
    for &c in dev_cls_a {
        *da.entry(c).or_default() += 1;
    }
    for &c in dev_cls_b {
        *db.entry(c).or_default() += 1;
    }
    for (&c, &ca) in &da {
        if ca > 1 {
            if db.get(&c).copied().unwrap_or(0) > 1 {
                count += 1;
            }
        }
    }
    // Net classes
    let mut na: HashMap<u32, usize> = HashMap::new();
    let mut nb: HashMap<u32, usize> = HashMap::new();
    for &c in net_cls_a {
        if c != u32::MAX {
            *na.entry(c).or_default() += 1;
        }
    }
    for &c in net_cls_b {
        if c != u32::MAX {
            *nb.entry(c).or_default() += 1;
        }
    }
    for (&c, &ca) in &na {
        if ca > 1 {
            if nb.get(&c).copied().unwrap_or(0) > 1 {
                count += 1;
            }
        }
    }
    count
}

/// Break one automorphism: find smallest ambiguous class, force-assign unique classes
/// to one element from each graph. Returns true if an automorphism was broken.
fn resolve_one_automorphism(
    dev_cls_a: &mut [u32],
    dev_cls_b: &mut [u32],
    net_cls_a: &mut [u32],
    net_cls_b: &mut [u32],
    class_magic: &mut Vec<u64>,
    rng: &mut Rng,
) -> bool {
    // Check device classes for ambiguity
    let mut cls_members_a: HashMap<u32, Vec<usize>> = HashMap::new();
    let mut cls_members_b: HashMap<u32, Vec<usize>> = HashMap::new();
    for (i, &c) in dev_cls_a.iter().enumerate() {
        cls_members_a.entry(c).or_default().push(i);
    }
    for (i, &c) in dev_cls_b.iter().enumerate() {
        cls_members_b.entry(c).or_default().push(i);
    }

    // Find smallest ambiguous device class
    let mut best: Option<(usize, u32)> = None;
    for (&c, ma) in &cls_members_a {
        if ma.len() <= 1 {
            continue;
        }
        if let Some(mb) = cls_members_b.get(&c) {
            if mb.len() <= 1 {
                continue;
            }
            let size = ma.len() + mb.len();
            if best.map_or(true, |(s, _)| size < s) {
                best = Some((size, c));
            }
        }
    }

    // Also check net classes
    let mut net_ma: HashMap<u32, Vec<usize>> = HashMap::new();
    let mut net_mb: HashMap<u32, Vec<usize>> = HashMap::new();
    for (i, &c) in net_cls_a.iter().enumerate() {
        if c != u32::MAX {
            net_ma.entry(c).or_default().push(i);
        }
    }
    for (i, &c) in net_cls_b.iter().enumerate() {
        if c != u32::MAX {
            net_mb.entry(c).or_default().push(i);
        }
    }
    for (&c, ma) in &net_ma {
        if ma.len() <= 1 {
            continue;
        }
        if let Some(mb) = net_mb.get(&c) {
            if mb.len() <= 1 {
                continue;
            }
            let size = ma.len() + mb.len();
            if best.map_or(true, |(s, _)| size < s) {
                best = Some((size, c));
            }
        }
    }

    let Some((_, cls)) = best else {
        return false;
    };

    // Break it: assign unique class to one member from each graph
    if let (Some(ma), Some(mb)) = (cls_members_a.get(&cls), cls_members_b.get(&cls)) {
        if ma.len() > 1 && mb.len() > 1 {
            let new_cls = class_magic.len() as u32;
            class_magic.push(rng.next());
            dev_cls_a[ma[0]] = new_cls;
            dev_cls_b[mb[0]] = new_cls;
            return true;
        }
    }
    if let (Some(ma), Some(mb)) = (net_ma.get(&cls), net_mb.get(&cls)) {
        if ma.len() > 1 && mb.len() > 1 {
            let new_cls = class_magic.len() as u32;
            class_magic.push(rng.next());
            net_cls_a[ma[0]] = new_cls;
            net_cls_b[mb[0]] = new_cls;
            return true;
        }
    }
    false
}

// --- public API ---

/// A group of device terminals that are interchangeable (commutative).
/// For example, `["A", "B"]` means inputs A and B can be swapped without
/// changing the circuit function. During graph construction, all terminals
/// in a swap group receive the same role value.
#[derive(Debug, Clone)]
pub struct PinSwapGroup {
    pub terminals: Vec<String>,
}

pub struct CompareOpts {
    pub strict: bool,
    pub w_tolerance: PropertyTolerance,
    pub l_tolerance: PropertyTolerance,
    /// Generalized pin swap groups beyond the built-in S/D symmetry.
    /// Each group declares terminal names that are interchangeable.
    pub pin_swaps: Vec<PinSwapGroup>,
}

impl Default for CompareOpts {
    fn default() -> Self {
        CompareOpts {
            strict: false,
            w_tolerance: PropertyTolerance::default(),
            l_tolerance: PropertyTolerance::default(),
            pin_swaps: Vec::new(),
        }
    }
}

/// Refined class/graph state — the output of the partition-refinement stage,
/// read (never mutated) by the post-refinement check rules.
pub struct Refined {
    pub(crate) ga: TopoGraph,
    pub(crate) gb: TopoGraph,
    pub(crate) dev_cls_a: Vec<u32>,
    pub(crate) dev_cls_b: Vec<u32>,
    pub(crate) net_cls_a: Vec<u32>,
    pub(crate) net_cls_b: Vec<u32>,
    pub(crate) ref_net_remap: HashMap<String, u32>,
    pub(crate) ambiguous: usize,
}

/// Pipeline stages 1-3: graph build, iterative refinement, automorphism breaking.
fn refine(ext: &ExtractedNetlist, reference: &RefNetlist, opts: &CompareOpts) -> Refined {
    let ga = graph_from_extracted(ext, opts.strict, &opts.pin_swaps);
    let (gb, ref_net_remap) = graph_from_reference(reference, opts.strict, &opts.pin_swaps);

    // Initialize PRNG and magic tables
    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_1234);
    let pin_magic = build_pin_magic(&mut rng);

    // Initial class_magic: one entry per initial seed value
    let max_seed = ga
        .devs
        .iter()
        .chain(gb.devs.iter())
        .map(|d| d.seed)
        .max()
        .unwrap_or(0) as usize
        + 1;
    let mut class_magic: Vec<u64> = (0..max_seed).map(|_| rng.next()).collect();

    // Seed device classes from device kind
    let mut dev_cls_a: Vec<u32> = ga.devs.iter().map(|d| d.seed).collect();
    let mut dev_cls_b: Vec<u32> = gb.devs.iter().map(|d| d.seed).collect();

    // Ensure class_magic covers all seed values (name_seed can produce large values)
    let max_dev_cls = dev_cls_a
        .iter()
        .chain(dev_cls_b.iter())
        .copied()
        .max()
        .unwrap_or(0);
    while class_magic.len() <= max_dev_cls as usize {
        class_magic.push(rng.next());
    }

    // Seed net classes: all nets start in class 0 (already covered by class_magic)
    let mut net_cls_a = vec![0u32; ga.net_count];
    let mut net_cls_b = vec![0u32; gb.net_count];

    // L4.4: Named net seeds — force layout/reference net pairs into shared classes.
    // Build a reverse map from extracted graph net IDs to ext net IDs, then
    // match by name via ext.net_names and reference.net_seeds.
    {
        // ext_remap: ext net_id -> graph-local net_id (built during graph_from_extracted)
        // We rebuild it here since graph_from_extracted doesn't expose the map.
        // ponytail: rebuild remap; expose from graph_from_extracted if this is hot.
        let mut ext_remap: HashMap<u32, u32> = HashMap::new();
        let mut next_ext = 0u32;
        for d in &ext.devices {
            for &n in &[d.gate, d.source, d.drain] {
                ext_remap.entry(n).or_insert_with(|| {
                    let v = next_ext;
                    next_ext += 1;
                    v
                });
            }
        }
        for d in &ext.bjt_devices {
            for n in [d.collector, d.base, d.emitter] {
                ext_remap.entry(n).or_insert_with(|| {
                    let v = next_ext;
                    next_ext += 1;
                    v
                });
            }
        }
        for d in &ext.two_terminal {
            for &n in &[d.terminal_a, d.terminal_b] {
                ext_remap.entry(n).or_insert_with(|| {
                    let v = next_ext;
                    next_ext += 1;
                    v
                });
            }
        }
        // Build layout name -> graph-local net_id
        let mut ext_name_to_local: HashMap<&str, u32> = HashMap::new();
        for (net_id, name) in &ext.net_names {
            if let Some(&local) = ext_remap.get(net_id) {
                ext_name_to_local.insert(name.as_str(), local);
            }
        }
        // For each reference net seed, find matching layout net and force same class.
        for (ref_name, layout_name) in &reference.net_seeds {
            let ref_local = ref_net_remap.get(ref_name.as_str()).copied();
            let ext_local = ext_name_to_local.get(layout_name.as_str()).copied();
            if let (Some(r), Some(e)) = (ref_local, ext_local) {
                if (r as usize) < net_cls_b.len() && (e as usize) < net_cls_a.len() {
                    let new_cls = class_magic.len() as u32;
                    class_magic.push(rng.next());
                    net_cls_a[e as usize] = new_cls;
                    net_cls_b[r as usize] = new_cls;
                }
            }
        }
    }

    // --- Iterative refinement with automorphism breaking ---
    iterate_to_fixpoint(
        &ga,
        &gb,
        &mut dev_cls_a,
        &mut dev_cls_b,
        &mut net_cls_a,
        &mut net_cls_b,
        &mut class_magic,
        &pin_magic,
        &mut rng,
    );

    // Break automorphisms until fully resolved
    for _ in 0..1000 {
        if !resolve_one_automorphism(
            &mut dev_cls_a,
            &mut dev_cls_b,
            &mut net_cls_a,
            &mut net_cls_b,
            &mut class_magic,
            &mut rng,
        ) {
            break;
        }
        iterate_to_fixpoint(
            &ga,
            &gb,
            &mut dev_cls_a,
            &mut dev_cls_b,
            &mut net_cls_a,
            &mut net_cls_b,
            &mut class_magic,
            &pin_magic,
            &mut rng,
        );
    }

    let ambiguous = count_ambiguous(&dev_cls_a, &dev_cls_b, &net_cls_a, &net_cls_b);

    Refined {
        ga,
        gb,
        dev_cls_a,
        dev_cls_b,
        net_cls_a,
        net_cls_b,
        ref_net_remap,
        ambiguous,
    }
}

// --- check stage: rules from lvs/rules/, globbed at compile time ---

/// Pre-refinement rule order. Floating nets and label conflicts record
/// non-fatal findings first; the device count rules fast-fail before the
/// (expensive) refinement stage ever runs, exactly like the old inline code.
const PRE_REFINEMENT: &[&str] = &[
    "floating_net",
    "label_conflict",
    "device_count_mos",
    "device_count_bjt",
];

/// Post-refinement rule order — the old sequential check precedence.
const POST_REFINEMENT: &[&str] = &["topology", "net_seed_conflict", "parametric"];

pub fn compare(ext: &ExtractedNetlist, reference: &RefNetlist, opts: &CompareOpts) -> LvsResult {
    // GPU path for large netlists
    if super::gpu_compare::should_use_gpu(ext, reference) {
        let ga = graph_from_extracted(ext, opts.strict, &opts.pin_swaps);
        let (gb, ref_net_remap) = graph_from_reference(reference, opts.strict, &opts.pin_swaps);
        if let Some(result) =
            super::gpu_compare::gpu_compare(ext, reference, opts, &ga, &gb, &ref_net_remap)
        {
            return result;
        }
    }

    let ext_n = ext
        .devices
        .iter()
        .filter(|d| d.kind == DeviceKind::Nmos)
        .count();
    let ext_p = ext
        .devices
        .iter()
        .filter(|d| d.kind == DeviceKind::Pmos)
        .count();

    let floating_nets: Vec<FloatingNet> = ext.floating_nets.clone();
    let make_result =
        |matched, reason: String, ambiguous: usize, mismatches: Vec<Mismatch>| LvsResult {
            matched,
            reason,
            mismatches,
            extracted_devices: ext.devices.len(),
            nmos: ext_n,
            pmos: ext_p,
            ambiguous_classes: ambiguous,
            label_conflicts: ext.label_conflicts.clone(),
            floating_nets: floating_nets.clone(),
            device_mappings: Vec::new(),
            net_mappings: Vec::new(),
            witness: None,
        };

    let rules: Vec<BoxedRule> = super::rules::FACTORIES
        .iter()
        .filter_map(|f| f(opts))
        .collect();
    let by_id = |id: &str| rules.iter().find(|r| r.id() == id);
    let mut mismatches: Vec<Mismatch> = Vec::new();

    // Rules run sequentially; the first one to set the ctx fail reason ends
    // the comparison, so both the fast-fail perf shape and the reason-string
    // precedence of the old inline sequence are preserved. Rules that record
    // findings without a reason (floating nets, label conflicts) are non-fatal.
    let ctx = LvsCtx {
        extracted: ext,
        reference,
        opts,
        refined: None,
        fail_reason: RefCell::new(None),
    };
    for id in PRE_REFINEMENT {
        let Some(rule) = by_id(id) else { continue };
        mismatches.extend(rule.check(&ctx, Backend::Cpu));
        if let Some(reason) = ctx.fail_reason.borrow_mut().take() {
            return make_result(false, reason, 0, mismatches);
        }
    }

    let refined = refine(ext, reference, opts);
    let ctx = LvsCtx {
        extracted: ext,
        reference,
        opts,
        refined: Some(&refined),
        fail_reason: RefCell::new(None),
    };
    // Known post-refinement rules in precedence order, then any future
    // globbed rule not named in either phase list (FACTORIES order).
    let post = POST_REFINEMENT.iter().filter_map(|id| by_id(id)).chain(
        rules
            .iter()
            .filter(|r| !PRE_REFINEMENT.contains(&r.id()) && !POST_REFINEMENT.contains(&r.id())),
    );
    for rule in post {
        mismatches.extend(rule.check(&ctx, Backend::Cpu));
        if let Some(reason) = ctx.fail_reason.borrow_mut().take() {
            return make_result(false, reason, refined.ambiguous, mismatches);
        }
    }

    make_result(true, "match".into(), refined.ambiguous, mismatches)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_diode_ext(anti_parallel: bool) -> ExtractedNetlist {
        // nets 0 and 1; diode2 flips direction when anti_parallel
        let d1 = TwoTerminalDevice {
            kind: TwoTerminalKind::Diode,
            name: "d1".into(),
            terminal_a: 0,
            terminal_b: 1,
            value: 0.0,
        };
        let d2 = TwoTerminalDevice {
            kind: TwoTerminalKind::Diode,
            name: "d2".into(),
            terminal_a: if anti_parallel { 1 } else { 0 },
            terminal_b: if anti_parallel { 0 } else { 1 },
            value: 0.0,
        };
        ExtractedNetlist {
            devices: Vec::new(),
            bjt_devices: Vec::new(),
            net_count: 2,
            used_nets: 2,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: vec![d1, d2],
            floating_nets: Vec::new(),
            net_names: HashMap::new(),
        }
    }

    fn two_diode_ref() -> RefNetlist {
        let d = |a: &str, b: &str| RefTwoTerminal {
            kind: TwoTerminalKind::Diode,
            name: String::new(),
            terminal_a: a.into(),
            terminal_b: b.into(),
        };
        RefNetlist {
            devices: Vec::new(),
            net_seeds: std::collections::HashMap::new(),
            ref_two_terminal: vec![d("X", "Y"), d("X", "Y")],
            ref_bjt: Vec::new(),
        }
    }

    /// Diode polarity is topology, not a permutable label: parallel pair matches
    /// the parallel reference, the anti-parallel pair must NOT.
    #[test]
    fn diode_polarity_not_permutable() {
        let opts = CompareOpts::default();
        assert!(
            compare(&two_diode_ext(false), &two_diode_ref(), &opts).matched,
            "parallel diode pair should match"
        );
        assert!(
            !compare(&two_diode_ext(true), &two_diode_ref(), &opts).matched,
            "anti-parallel diode pair must mismatch a parallel reference"
        );
    }
}
