//! Partition refinement: the matching algorithm.
//!
//! Data in: two graphs. Data out: a class per node on each side, plus per-class tallies.
//! Nodes split by a hash of their neighbours' classes until stable; a balanced stall
//! is broken by pairing the lowest node index on each side, one class per round.

use crate::lvs::graph::{narrow, Graph};
use crate::topology::TerminalRole;
use gpurify_ingest::deck::DeviceKind;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ClassId(pub(crate) u32);

/// Refinement state for both graphs; node index is devices first, then nets.
#[derive(Debug, Default)]
pub(crate) struct Partition {
    pub(crate) layout_class: Vec<ClassId>,
    ref_class: Vec<ClassId>,
    next_layout: Vec<ClassId>,
    next_ref: Vec<ClassId>,
    signature: Vec<(u64, u32)>,
    spare: Vec<(u64, u32)>,
    /// Nodes per class on each side, and the lowest node index in each
    /// (`u32::MAX` when empty). Valid after a refinement that did not exhaust.
    pub(crate) layout_tally: Vec<u32>,
    pub(crate) ref_tally: Vec<u32>,
    layout_first: Vec<u32>,
    pub(crate) ref_first: Vec<u32>,
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

/// Domain separators, so a device and a net with equal neighbourhoods differ.
const DEVICE_TAG: u64 = 0x01;
const NET_TAG: u64 = 0x11;
const NEIGHBOUR_TAG: u64 = 0x21;

/// One neighbour's contribution; summed with `wrapping_add`, so order-free.
const fn neighbour(role: TerminalRole, class: ClassId) -> u64 {
    mix(NEIGHBOUR_TAG ^ (role_code(role) << 8) ^ ((class.0 as u64) << 16))
}

fn device_signature(graph: &Graph, device: u32, own: ClassId, net_class: &[ClassId]) -> u64 {
    let (nets, roles) = graph.terminals_of(device);
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

fn net_signature(graph: &Graph, net: u32, own: ClassId, device_class: &[ClassId]) -> u64 {
    let mut neighbours = 0u64;
    for &(device, role) in graph.terminals_on(net) {
        neighbours = neighbours.wrapping_add(neighbour(role, device_class[device as usize]));
    }
    mix(mix(NET_TAG ^ (u64::from(own.0) << 8)) ^ neighbours)
}

/// Append one graph's node signatures, tagged with their index `offset ..`.
fn push_signatures(graph: &Graph, class: &[ClassId], offset: u32, out: &mut Vec<(u64, u32)>) {
    let devices = graph.device_count();
    let (device_class, net_class) = class.split_at(devices);
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

/// One round over both graphs, sorted together so a class names the same
/// structure on both sides. `next` gets layout then reference; returns the class count.
fn signature_round(
    layout: &Graph,
    reference: &Graph,
    layout_class: &[ClassId],
    ref_class: &[ClassId],
    signature: &mut Vec<(u64, u32)>,
    spare: &mut Vec<(u64, u32)>,
    next: &mut Vec<ClassId>,
) -> u32 {
    let total = layout_class.len() + ref_class.len();
    let split = narrow(layout_class.len());

    signature.clear();
    signature.reserve(total);
    push_signatures(layout, layout_class, 0, signature);
    push_signatures(reference, ref_class, split, signature);

    sort_by_hash(signature, spare);

    next.clear();
    next.resize(total, ClassId(0));

    let mut count = 0u32;
    let mut previous = 0u64;
    for (position, &(hash, node)) in signature.iter().enumerate() {
        count += u32::from(hash != previous) | u32::from(position == 0);
        previous = hash;
        next[node as usize] = ClassId(count - 1);
    }
    count
}

/// Below this many signatures a plain comparison sort wins.
const RADIX_MIN: usize = 1 << 12;

/// Sort ascending by hash. Order among equal hashes is not fixed, and nothing
/// reads it: numbering only groups equal hashes. Above [`RADIX_MIN`], one
/// scatter on the top bits (about four hashes per bucket, as mixed hashes are
/// uniform) then a sort per bucket.
fn sort_by_hash(items: &mut Vec<(u64, u32)>, spare: &mut Vec<(u64, u32)>) {
    if items.len() < RADIX_MIN {
        items.sort_unstable_by_key(|&(hash, _)| hash);
        return;
    }
    let bits = (items.len() / 4).ilog2().min(20);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "at most 20 bits survive the shift"
    )]
    let bucket = |hash: u64| (hash >> (64 - bits)) as usize;
    let mut start = vec![0u32; (1 << bits) + 1];
    for &(hash, _) in items.iter() {
        start[bucket(hash) + 1] += 1;
    }
    for at in 1..start.len() {
        start[at] += start[at - 1];
    }
    spare.clear();
    spare.resize(items.len(), (0, 0));
    let mut cursor = start.clone();
    for &item in items.iter() {
        let slot = &mut cursor[bucket(item.0)];
        spare[*slot as usize] = item;
        *slot += 1;
    }
    for run in start.windows(2) {
        spare[run[0] as usize..run[1] as usize].sort_unstable_by_key(|&(hash, _)| hash);
    }
    std::mem::swap(items, spare);
}

/// Something lands in the class and it is not exactly one node per side.
const fn is_stalled(mine: u32, theirs: u32) -> bool {
    let present = (mine | theirs) != 0;
    let resolved = (mine == 1) & (theirs == 1);
    present & !resolved
}

fn tally_into(class: &[ClassId], classes: u32, tally: &mut Vec<u32>, first: &mut Vec<u32>) {
    tally.clear();
    tally.resize(classes as usize, 0);
    first.clear();
    first.resize(classes as usize, u32::MAX);
    for (node, &ClassId(id)) in class.iter().enumerate() {
        let slot = id as usize;
        tally[slot] += 1;
        first[slot] = first[slot].min(narrow(node));
    }
}

/// Refine until stable, leaving classes and tallies in `out`. Returns `false`
/// when `max_rounds` ran out, which says nothing about whether the graphs match.
pub(crate) fn refine_into(
    layout: &Graph,
    reference: &Graph,
    max_rounds: u32,
    out: &mut Partition,
) -> bool {
    let layout_devices = layout.device_count();
    let ref_devices = reference.device_count();
    let layout_nodes = layout_devices + layout.net_count();
    let ref_nodes = ref_devices + reference.net_count();

    // Devices in one class, nets in another; an absent kind opens no class.
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

    for _ in 0..max_rounds {
        let count = signature_round(
            layout,
            reference,
            &out.layout_class,
            &out.ref_class,
            &mut out.signature,
            &mut out.spare,
            &mut out.next_layout,
        );

        out.next_ref.clear();
        out.next_ref
            .extend_from_slice(&out.next_layout[layout_nodes..]);
        out.next_layout.truncate(layout_nodes);
        std::mem::swap(&mut out.layout_class, &mut out.next_layout);
        std::mem::swap(&mut out.ref_class, &mut out.next_ref);

        let stable = count == class_count;
        class_count = count;
        if !stable {
            continue;
        }

        tally_into(
            &out.layout_class,
            count,
            &mut out.layout_tally,
            &mut out.layout_first,
        );
        tally_into(
            &out.ref_class,
            count,
            &mut out.ref_tally,
            &mut out.ref_first,
        );

        // The lowest stalled class with equal counts is a genuine symmetry; an
        // imbalanced one no tie-break can mend. None left: done.
        let Some(lowest) = out
            .layout_tally
            .iter()
            .zip(&out.ref_tally)
            .position(|(&mine, &theirs)| is_stalled(mine, theirs) & (mine == theirs))
        else {
            return true;
        };

        out.layout_class[out.layout_first[lowest] as usize] = ClassId(count);
        out.ref_class[out.ref_first[lowest] as usize] = ClassId(count);
        class_count = count + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{sort_by_hash, RADIX_MIN};

    fn items(seed: u64, n: usize) -> Vec<(u64, u32)> {
        let mut z = seed;
        (0..n)
            .map(|i| {
                z = super::mix(z.wrapping_add(0x9e37_79b9_7f4a_7c15));
                // Few distinct values in odd seeds, so equal hashes are exercised.
                let hash = if seed.is_multiple_of(2) { z } else { z % 7 };
                (hash, u32::try_from(i).expect("small"))
            })
            .collect()
    }

    /// The radix path orders hashes as a comparison sort does.
    #[test]
    fn radix_sort_agrees_with_a_comparison_sort() {
        let mut spare = Vec::new();
        for seed in 0..6u64 {
            for n in [
                0,
                1,
                2,
                RADIX_MIN - 1,
                RADIX_MIN,
                RADIX_MIN + 1,
                3 * RADIX_MIN + 7,
            ] {
                let mut want = items(seed, n);
                let mut got = want.clone();
                want.sort_unstable();
                sort_by_hash(&mut got, &mut spare);
                assert!(got.is_sorted_by_key(|&(hash, _)| hash), "seed {seed} n {n}");
                got.sort_unstable();
                assert_eq!(got, want, "seed {seed} n {n}");
            }
        }
    }

    /// Thread CPU time in ns; a loaded machine distorts it far less than wall time.
    fn cpu_ns() -> u64 {
        let stat = std::fs::read_to_string("/proc/thread-self/schedstat").unwrap_or_default();
        stat.split_whitespace()
            .next()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    /// `cargo test --release -p gpurify-check --lib radix_bench -- --ignored --nocapture`
    #[test]
    #[ignore = "timing, run by hand"]
    fn radix_bench() {
        let mut spare = Vec::new();
        for n in [2_000usize, 20_000, 200_000, 2_000_000] {
            let source = items(2, n);
            let reps = (4_000_000 / n).max(3);
            let (mut a, mut b) = (0u64, 0u64);
            for _ in 0..reps {
                let mut v = source.clone();
                let t = cpu_ns();
                v.sort_unstable();
                a += cpu_ns() - t;
                std::hint::black_box(&v);
                let mut v = source.clone();
                let t = cpu_ns();
                sort_by_hash(&mut v, &mut spare);
                b += cpu_ns() - t;
                std::hint::black_box(&v);
            }
            let reps = reps as u64;
            println!(
                "n={n}: sort_unstable {} us, radix {} us",
                a / 1000 / reps,
                b / 1000 / reps
            );
        }
    }
}
