//! GPU-accelerated netlist comparer using hash-as-class Weisfeiler-Lehman refinement.
//!
//! Instead of fracturing classes via HashMaps, the 64-bit hash IS the class label.
//! dev_hash runs on GPU when available (one thread per device); net_hash stays on host
//! (nets << devices). Automorphism breaking is host-driven.
//!
//! Gated on: total device count >= 1M. Falls back to host on no-GPU builds.

use super::compare::{build_pin_magic, CompareOpts, Rng, TopoGraph, NUM_ROLES};
use super::types::*;
use std::collections::HashMap;

/// Minimum combined device count to activate GPU path.
const GPU_GATE_DEVICES: usize = 1_000_000;

/// ponytail: 50 rounds; typical circuits converge in ~10-20.
const MAX_ROUNDS: usize = 50;

// ---------------------------------------------------------------------------
// Hash-as-class helpers (host)
// ---------------------------------------------------------------------------

fn dev_hashes_host(g: &TopoGraph, net_class: &[u64], pin_magic: &[u64; NUM_ROLES]) -> Vec<u64> {
    g.devs
        .iter()
        .map(|d| {
            let mut h: u64 = d.seed as u64;
            for i in 0..d.pin_count as usize {
                let nc = net_class.get(d.nets[i] as usize).copied().unwrap_or(0);
                h = h.wrapping_add(pin_magic[d.roles[i] as usize] ^ nc);
            }
            h
        })
        .collect()
}

fn net_hashes_host(
    g: &TopoGraph,
    dev_class: &[u64],
    pin_magic: &[u64; NUM_ROLES],
    net_count: usize,
) -> Vec<u64> {
    let mut hashes = vec![0u64; net_count];
    let mut has_term = vec![false; net_count];
    for (di, d) in g.devs.iter().enumerate() {
        let dc = dev_class[di];
        for i in 0..d.pin_count as usize {
            let net = d.nets[i] as usize;
            if net < net_count {
                hashes[net] = hashes[net].wrapping_add(pin_magic[d.roles[i] as usize] ^ dc);
                has_term[net] = true;
            }
        }
    }
    for i in 0..net_count {
        if !has_term[i] {
            hashes[i] = u64::MAX;
        }
    }
    hashes
}

fn densify(
    dev_a: &[u64],
    dev_b: &[u64],
    net_a: &[u64],
    net_b: &[u64],
) -> (Vec<u32>, Vec<u32>, Vec<u32>, Vec<u32>) {
    let mut map: HashMap<u64, u32> = HashMap::new();
    let mut next_id = 0u32;
    let mut assign = |h: u64| -> u32 {
        *map.entry(h).or_insert_with(|| {
            let id = next_id;
            next_id += 1;
            id
        })
    };
    let da: Vec<u32> = dev_a.iter().map(|&h| assign(h)).collect();
    let db: Vec<u32> = dev_b.iter().map(|&h| assign(h)).collect();
    let na: Vec<u32> = net_a
        .iter()
        .map(|&h| if h == u64::MAX { u32::MAX } else { assign(h) })
        .collect();
    let nb: Vec<u32> = net_b
        .iter()
        .map(|&h| if h == u64::MAX { u32::MAX } else { assign(h) })
        .collect();
    (da, db, na, nb)
}

fn count_ambiguous_u64(dev_a: &[u64], dev_b: &[u64], net_a: &[u64], net_b: &[u64]) -> usize {
    let mut count = 0;
    let mut da: HashMap<u64, usize> = HashMap::new();
    let mut db: HashMap<u64, usize> = HashMap::new();
    for &c in dev_a {
        *da.entry(c).or_default() += 1;
    }
    for &c in dev_b {
        *db.entry(c).or_default() += 1;
    }
    for (&c, &ca) in &da {
        if ca > 1 {
            if db.get(&c).copied().unwrap_or(0) > 1 {
                count += 1;
            }
        }
    }
    let mut na: HashMap<u64, usize> = HashMap::new();
    let mut nb: HashMap<u64, usize> = HashMap::new();
    for &c in net_a {
        if c != u64::MAX {
            *na.entry(c).or_default() += 1;
        }
    }
    for &c in net_b {
        if c != u64::MAX {
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

fn resolve_one_automorphism_u64(
    dev_a: &mut [u64],
    dev_b: &mut [u64],
    net_a: &mut [u64],
    net_b: &mut [u64],
    rng: &mut Rng,
) -> bool {
    let mut cls_a: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut cls_b: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, &c) in dev_a.iter().enumerate() {
        cls_a.entry(c).or_default().push(i);
    }
    for (i, &c) in dev_b.iter().enumerate() {
        cls_b.entry(c).or_default().push(i);
    }

    let mut best: Option<(usize, u64, bool)> = None;
    for (&c, ma) in &cls_a {
        if ma.len() <= 1 {
            continue;
        }
        if let Some(mb) = cls_b.get(&c) {
            if mb.len() <= 1 {
                continue;
            }
            let size = ma.len() + mb.len();
            if best.map_or(true, |(s, _, _)| size < s) {
                best = Some((size, c, true));
            }
        }
    }

    let mut net_ma: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut net_mb: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, &c) in net_a.iter().enumerate() {
        if c != u64::MAX {
            net_ma.entry(c).or_default().push(i);
        }
    }
    for (i, &c) in net_b.iter().enumerate() {
        if c != u64::MAX {
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
            if best.map_or(true, |(s, _, _)| size < s) {
                best = Some((size, c, false));
            }
        }
    }

    let Some((_, cls, is_dev)) = best else {
        return false;
    };
    let new_label = rng.next();
    if is_dev {
        if let (Some(ma), Some(mb)) = (cls_a.get(&cls), cls_b.get(&cls)) {
            if ma.len() > 1 && mb.len() > 1 {
                dev_a[ma[0]] = new_label;
                dev_b[mb[0]] = new_label;
                return true;
            }
        }
    } else if let (Some(ma), Some(mb)) = (net_ma.get(&cls), net_mb.get(&cls)) {
        if ma.len() > 1 && mb.len() > 1 {
            net_a[ma[0]] = new_label;
            net_b[mb[0]] = new_label;
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// GPU kernel (CubeCL, feature = "gpu")
// ---------------------------------------------------------------------------

#[cfg(feature = "gpu")]
mod gpu_kernel {
    use cubecl::bytes::Bytes;
    use cubecl::cuda::{CudaDevice, CudaRuntime};
    use cubecl::prelude::*;
    use std::sync::OnceLock;

    const CUBE_DIM: u32 = 256;
    type Client = ComputeClient<CudaRuntime>;

    fn client() -> Option<&'static Client> {
        static C: OnceLock<Option<Client>> = OnceLock::new();
        C.get_or_init(|| std::panic::catch_unwind(|| CudaRuntime::client(&CudaDevice::new(0))).ok())
            .as_ref()
    }

    #[cube(launch_unchecked)]
    fn dev_hash_k(
        pin0: &Array<u32>,
        pin1: &Array<u32>,
        pin2: &Array<u32>,
        pin3: &Array<u32>,
        role0: &Array<u32>,
        role1: &Array<u32>,
        role2: &Array<u32>,
        role3: &Array<u32>,
        pin_count: &Array<u32>,
        seed: &Array<u32>,
        nc_lo: &Array<u32>,
        nc_hi: &Array<u32>,
        pm_lo: &Array<u32>,
        pm_hi: &Array<u32>,
        n_nets: u32,
        out_lo: &mut Array<u32>,
        out_hi: &mut Array<u32>,
    ) {
        if ABSOLUTE_POS < out_lo.len() {
            let pc = pin_count[ABSOLUTE_POS];
            let mut h_lo = seed[ABSOLUTE_POS];
            let mut h_hi = 0u32;

            if pc > 0 {
                let net = pin0[ABSOLUTE_POS];
                let r = role0[ABSOLUTE_POS] as usize;
                if net < n_nets {
                    let x_lo = pm_lo[r] ^ nc_lo[net as usize];
                    let x_hi = pm_hi[r] ^ nc_hi[net as usize];
                    let sum = h_lo as u64 + x_lo as u64;
                    h_lo = sum as u32;
                    h_hi = h_hi + x_hi + (sum >> 32) as u32;
                }
            }
            if pc > 1 {
                let net = pin1[ABSOLUTE_POS];
                let r = role1[ABSOLUTE_POS] as usize;
                if net < n_nets {
                    let x_lo = pm_lo[r] ^ nc_lo[net as usize];
                    let x_hi = pm_hi[r] ^ nc_hi[net as usize];
                    let sum = h_lo as u64 + x_lo as u64;
                    h_lo = sum as u32;
                    h_hi = h_hi + x_hi + (sum >> 32) as u32;
                }
            }
            if pc > 2 {
                let net = pin2[ABSOLUTE_POS];
                let r = role2[ABSOLUTE_POS] as usize;
                if net < n_nets {
                    let x_lo = pm_lo[r] ^ nc_lo[net as usize];
                    let x_hi = pm_hi[r] ^ nc_hi[net as usize];
                    let sum = h_lo as u64 + x_lo as u64;
                    h_lo = sum as u32;
                    h_hi = h_hi + x_hi + (sum >> 32) as u32;
                }
            }
            if pc > 3 {
                let net = pin3[ABSOLUTE_POS];
                let r = role3[ABSOLUTE_POS] as usize;
                if net < n_nets {
                    let x_lo = pm_lo[r] ^ nc_lo[net as usize];
                    let x_hi = pm_hi[r] ^ nc_hi[net as usize];
                    let sum = h_lo as u64 + x_lo as u64;
                    h_lo = sum as u32;
                    h_hi = h_hi + x_hi + (sum >> 32) as u32;
                }
            }

            out_lo[ABSOLUTE_POS] = h_lo;
            out_hi[ABSOLUTE_POS] = h_hi;
        }
    }

    fn to_u32(b: &[u8], n: usize) -> Vec<u32> {
        b.chunks_exact(4)
            .take(n)
            .map(|c| u32::from_ne_bytes(c.try_into().unwrap()))
            .collect()
    }

    fn split_u64(v: &[u64]) -> (Vec<u32>, Vec<u32>) {
        (
            v.iter().map(|&x| x as u32).collect(),
            v.iter().map(|&x| (x >> 32) as u32).collect(),
        )
    }

    fn merge_u64(lo: &[u32], hi: &[u32]) -> Vec<u64> {
        lo.iter()
            .zip(hi)
            .map(|(&l, &h)| (l as u64) | ((h as u64) << 32))
            .collect()
    }

    /// Compute dev_hash on GPU. Returns None if no CUDA or launch fails.
    pub fn gpu_dev_hashes(
        g: &super::TopoGraph,
        net_class: &[u64],
        pin_magic: &[u64; super::NUM_ROLES],
    ) -> Option<Vec<u64>> {
        let c = client()?;
        let n = g.devs.len();
        if n == 0 {
            return Some(Vec::new());
        }

        let run = || -> Option<Vec<u64>> {
            // Build SoA columns
            let mut p0 = vec![0u32; n];
            let mut p1 = vec![0u32; n];
            let mut p2 = vec![0u32; n];
            let mut p3 = vec![0u32; n];
            let mut r0 = vec![0u32; n];
            let mut r1 = vec![0u32; n];
            let mut r2 = vec![0u32; n];
            let mut r3 = vec![0u32; n];
            let mut pc = vec![0u32; n];
            let mut sd = vec![0u32; n];
            for (i, d) in g.devs.iter().enumerate() {
                p0[i] = d.nets[0];
                p1[i] = d.nets[1];
                p2[i] = d.nets[2];
                p3[i] = d.nets[3];
                r0[i] = d.roles[0] as u32;
                r1[i] = d.roles[1] as u32;
                r2[i] = d.roles[2] as u32;
                r3[i] = d.roles[3] as u32;
                pc[i] = d.pin_count as u32;
                sd[i] = d.seed;
            }

            let h_p0 = c.create(Bytes::from_elems(p0));
            let h_p1 = c.create(Bytes::from_elems(p1));
            let h_p2 = c.create(Bytes::from_elems(p2));
            let h_p3 = c.create(Bytes::from_elems(p3));
            let h_r0 = c.create(Bytes::from_elems(r0));
            let h_r1 = c.create(Bytes::from_elems(r1));
            let h_r2 = c.create(Bytes::from_elems(r2));
            let h_r3 = c.create(Bytes::from_elems(r3));
            let h_pc = c.create(Bytes::from_elems(pc));
            let h_sd = c.create(Bytes::from_elems(sd));

            let nc_padded = if net_class.is_empty() {
                &[0u64][..]
            } else {
                net_class
            };
            let (nc_lo, nc_hi) = split_u64(nc_padded);
            let (pm_lo, pm_hi) = split_u64(pin_magic);
            let h_nc_lo = c.create(Bytes::from_elems(nc_lo));
            let h_nc_hi = c.create(Bytes::from_elems(nc_hi));
            let h_pm_lo = c.create(Bytes::from_elems(pm_lo));
            let h_pm_hi = c.create(Bytes::from_elems(pm_hi));

            let out_lo = c.empty(n * 4);
            let out_hi = c.empty(n * 4);
            let nn = nc_padded.len();
            let nr = super::NUM_ROLES;

            unsafe {
                dev_hash_k::launch_unchecked::<CudaRuntime>(
                    c,
                    CubeCount::Static((n as u32).div_ceil(CUBE_DIM), 1, 1),
                    CubeDim::new_1d(CUBE_DIM),
                    ArrayArg::from_raw_parts(h_p0, n),
                    ArrayArg::from_raw_parts(h_p1, n),
                    ArrayArg::from_raw_parts(h_p2, n),
                    ArrayArg::from_raw_parts(h_p3, n),
                    ArrayArg::from_raw_parts(h_r0, n),
                    ArrayArg::from_raw_parts(h_r1, n),
                    ArrayArg::from_raw_parts(h_r2, n),
                    ArrayArg::from_raw_parts(h_r3, n),
                    ArrayArg::from_raw_parts(h_pc, n),
                    ArrayArg::from_raw_parts(h_sd, n),
                    ArrayArg::from_raw_parts(h_nc_lo, nn),
                    ArrayArg::from_raw_parts(h_nc_hi, nn),
                    ArrayArg::from_raw_parts(h_pm_lo, nr),
                    ArrayArg::from_raw_parts(h_pm_hi, nr),
                    g.net_count as u32,
                    ArrayArg::from_raw_parts(out_lo.clone(), n),
                    ArrayArg::from_raw_parts(out_hi.clone(), n),
                );
            }

            let lo = to_u32(&c.read_one(out_lo).ok()?, n);
            let hi = to_u32(&c.read_one(out_hi).ok()?, n);
            Some(merge_u64(&lo, &hi))
        };

        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
            Ok(v) => v,
            Err(_) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatch: GPU if available, else host
// ---------------------------------------------------------------------------

fn compute_dev_hashes(g: &TopoGraph, net_class: &[u64], pin_magic: &[u64; NUM_ROLES]) -> Vec<u64> {
    #[cfg(feature = "gpu")]
    {
        if let Some(v) = gpu_kernel::gpu_dev_hashes(g, net_class, pin_magic) {
            return v;
        }
    }
    dev_hashes_host(g, net_class, pin_magic)
}

// ---------------------------------------------------------------------------
// Hash-as-class refinement loop
// ---------------------------------------------------------------------------

fn hash_refine(
    ga: &TopoGraph,
    gb: &TopoGraph,
    pin_magic: &[u64; NUM_ROLES],
) -> (Vec<u64>, Vec<u64>, Vec<u64>, Vec<u64>) {
    let mut net_cls_a = vec![0u64; ga.net_count];
    let mut net_cls_b = vec![0u64; gb.net_count];
    let mut dev_cls_a = vec![0u64; ga.devs.len()];
    let mut dev_cls_b = vec![0u64; gb.devs.len()];

    for _ in 0..MAX_ROUNDS {
        dev_cls_a = compute_dev_hashes(ga, &net_cls_a, pin_magic);
        dev_cls_b = compute_dev_hashes(gb, &net_cls_b, pin_magic);

        let new_net_a = net_hashes_host(ga, &dev_cls_a, pin_magic, ga.net_count);
        let new_net_b = net_hashes_host(gb, &dev_cls_b, pin_magic, gb.net_count);

        if new_net_a == net_cls_a && new_net_b == net_cls_b {
            return (dev_cls_a, dev_cls_b, net_cls_a, net_cls_b);
        }
        net_cls_a = new_net_a;
        net_cls_b = new_net_b;
    }

    dev_cls_a = compute_dev_hashes(ga, &net_cls_a, pin_magic);
    dev_cls_b = compute_dev_hashes(gb, &net_cls_b, pin_magic);
    (dev_cls_a, dev_cls_b, net_cls_a, net_cls_b)
}

fn hash_refine_from(
    ga: &TopoGraph,
    gb: &TopoGraph,
    dev_a: &[u64],
    dev_b: &[u64],
    pin_magic: &[u64; NUM_ROLES],
) -> (Vec<u64>, Vec<u64>, Vec<u64>, Vec<u64>) {
    let mut net_cls_a = net_hashes_host(ga, dev_a, pin_magic, ga.net_count);
    let mut net_cls_b = net_hashes_host(gb, dev_b, pin_magic, gb.net_count);
    let mut dev_cls_a: Vec<u64>;
    let mut dev_cls_b: Vec<u64>;

    for _ in 0..MAX_ROUNDS {
        dev_cls_a = compute_dev_hashes(ga, &net_cls_a, pin_magic);
        dev_cls_b = compute_dev_hashes(gb, &net_cls_b, pin_magic);

        let new_net_a = net_hashes_host(ga, &dev_cls_a, pin_magic, ga.net_count);
        let new_net_b = net_hashes_host(gb, &dev_cls_b, pin_magic, gb.net_count);

        if new_net_a == net_cls_a && new_net_b == net_cls_b {
            return (dev_cls_a, dev_cls_b, net_cls_a, net_cls_b);
        }
        net_cls_a = new_net_a;
        net_cls_b = new_net_b;
    }

    dev_cls_a = compute_dev_hashes(ga, &net_cls_a, pin_magic);
    dev_cls_b = compute_dev_hashes(gb, &net_cls_b, pin_magic);
    (dev_cls_a, dev_cls_b, net_cls_a, net_cls_b)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Should the GPU path be attempted for this comparison?
pub fn should_use_gpu(ext: &ExtractedNetlist, reference: &RefNetlist) -> bool {
    let total = ext.devices.len()
        + ext.bjt_devices.len()
        + ext.two_terminal.len()
        + reference.devices.len()
        + reference.ref_bjt.len()
        + reference.ref_two_terminal.len();
    total >= GPU_GATE_DEVICES
}

/// Full GPU-accelerated compare. Returns the same LvsResult as the CPU path.
pub(super) fn gpu_compare(
    ext: &ExtractedNetlist,
    reference: &RefNetlist,
    opts: &CompareOpts,
    ga: &TopoGraph,
    gb: &TopoGraph,
    ref_net_remap: &HashMap<String, u32>,
) -> Option<LvsResult> {
    use std::collections::{BTreeMap, HashSet};

    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_1234);
    let pin_magic = build_pin_magic(&mut rng);

    let (mut dev_a, mut dev_b, mut net_a, mut net_b) = hash_refine(ga, gb, &pin_magic);

    // Automorphism breaking
    for _ in 0..1000 {
        if !resolve_one_automorphism_u64(&mut dev_a, &mut dev_b, &mut net_a, &mut net_b, &mut rng) {
            break;
        }
        let (da, db, na, nb) = hash_refine_from(ga, gb, &dev_a, &dev_b, &pin_magic);
        dev_a = da;
        dev_b = db;
        net_a = na;
        net_b = nb;
    }

    let ambiguous = count_ambiguous_u64(&dev_a, &dev_b, &net_a, &net_b);
    let (dev_cls_a, dev_cls_b, net_cls_a, net_cls_b) = densify(&dev_a, &dev_b, &net_a, &net_b);

    // --- Topology + parametric validation (same logic as CPU compare()) ---
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

    let mut mismatches: Vec<Mismatch> = Vec::new();
    for fnet in &floating_nets {
        mismatches.push(Mismatch::FloatingNet {
            net_id: fnet.net_id,
            label: fnet.label.clone(),
        });
    }
    for conflict in &ext.label_conflicts {
        mismatches.push(Mismatch::LabelConflict {
            net_id: 0,
            labels: vec![conflict.clone()],
        });
    }

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

    // Device class multiset
    let mut dev_buckets_a: HashMap<u32, usize> = HashMap::new();
    let mut dev_buckets_b: HashMap<u32, usize> = HashMap::new();
    for &c in &dev_cls_a {
        *dev_buckets_a.entry(c).or_default() += 1;
    }
    for &c in &dev_cls_b {
        *dev_buckets_b.entry(c).or_default() += 1;
    }
    let all_dev_cls: HashSet<u32> = dev_buckets_a
        .keys()
        .chain(dev_buckets_b.keys())
        .copied()
        .collect();
    for &c in &all_dev_cls {
        let ca = dev_buckets_a.get(&c).copied().unwrap_or(0);
        let cb = dev_buckets_b.get(&c).copied().unwrap_or(0);
        if ca != cb {
            let desc = format!(
                "device class {} has {} in layout vs {} in reference",
                c, ca, cb
            );
            mismatches.push(Mismatch::TopologyMismatch {
                description: desc.clone(),
            });
            return Some(make_result(
                false,
                format!("topology mismatch: {}", desc),
                ambiguous,
                mismatches,
            ));
        }
    }

    // Net class multiset
    let mut net_buckets_a: HashMap<u32, usize> = HashMap::new();
    let mut net_buckets_b: HashMap<u32, usize> = HashMap::new();
    for &c in &net_cls_a {
        if c != u32::MAX {
            *net_buckets_a.entry(c).or_default() += 1;
        }
    }
    for &c in &net_cls_b {
        if c != u32::MAX {
            *net_buckets_b.entry(c).or_default() += 1;
        }
    }
    let all_net_cls: HashSet<u32> = net_buckets_a
        .keys()
        .chain(net_buckets_b.keys())
        .copied()
        .collect();
    for &c in &all_net_cls {
        let ca = net_buckets_a.get(&c).copied().unwrap_or(0);
        let cb = net_buckets_b.get(&c).copied().unwrap_or(0);
        if ca != cb {
            let desc = format!(
                "net class {} has {} nets in layout vs {} in reference",
                c, ca, cb
            );
            mismatches.push(Mismatch::TopologyMismatch {
                description: desc.clone(),
            });
            return Some(make_result(
                false,
                format!("topology mismatch: {}", desc),
                ambiguous,
                mismatches,
            ));
        }
    }

    // Net seed conflict detection
    if !reference.net_seeds.is_empty() {
        let mut seed_class_to_names: HashMap<u32, Vec<&str>> = HashMap::new();
        for (net_name, _) in &reference.net_seeds {
            if let Some(&local_id) = ref_net_remap.get(net_name) {
                let c = net_cls_b[local_id as usize];
                if c != u32::MAX {
                    seed_class_to_names
                        .entry(c)
                        .or_default()
                        .push(net_name.as_str());
                }
            }
        }
        for (_, names) in &seed_class_to_names {
            if names.len() > 1 {
                let nets: Vec<String> = names.iter().map(|s| s.to_string()).collect();
                let reason = format!("net seed conflict: {} are isomorphic", names.join(" and "));
                mismatches.push(Mismatch::NetSeedConflict { nets });
                return Some(make_result(false, reason, ambiguous, mismatches));
            }
        }
    }

    // Parametric pass
    let enforce_parametric = reference.devices.iter().all(|d| d.w > 0 && d.l > 0);
    if enforce_parametric {
        let mut ext_wl: BTreeMap<u32, Vec<(i32, i32)>> = BTreeMap::new();
        let mut ref_wl: BTreeMap<u32, Vec<(i32, i32)>> = BTreeMap::new();
        for (i, d) in ga.devs.iter().enumerate() {
            if !d.is_mos {
                continue;
            }
            let oi = d.orig_idx as usize;
            ext_wl
                .entry(dev_cls_a[i])
                .or_default()
                .push((ext.devices[oi].w, ext.devices[oi].l));
        }
        for (i, d) in gb.devs.iter().enumerate() {
            if !d.is_mos {
                continue;
            }
            let oi = d.orig_idx as usize;
            ref_wl
                .entry(dev_cls_b[i])
                .or_default()
                .push((reference.devices[oi].w, reference.devices[oi].l));
        }

        let within_w = |got: i32, expect: i32| -> bool {
            ((got - expect).abs() as f64)
                <= (opts.w_tolerance.abs_nm as f64).max(opts.w_tolerance.rel_pct * expect as f64)
        };
        let within_l = |got: i32, expect: i32| -> bool {
            ((got - expect).abs() as f64)
                <= (opts.l_tolerance.abs_nm as f64).max(opts.l_tolerance.rel_pct * expect as f64)
        };
        for (cls, exts) in ext_wl.iter_mut() {
            if let Some(refs) = ref_wl.get_mut(cls) {
                exts.sort_unstable();
                refs.sort_unstable();
                for (&(gw, gl), &(rw, rl)) in exts.iter().zip(refs.iter()) {
                    if !within_w(gw, rw) || !within_l(gl, rl) {
                        let reason = format!(
                            "parametric mismatch: expected W/L {}/{} got {}/{}",
                            rw, rl, gw, gl
                        );
                        mismatches.push(Mismatch::ParametricMismatch {
                            property: "W/L".into(),
                            got: gw as f64,
                            expected: rw as f64,
                            tolerance: opts.w_tolerance.abs_nm as f64,
                        });
                        return Some(make_result(false, reason, ambiguous, mismatches));
                    }
                }
            }
        }
    }

    Some(make_result(true, "match".into(), ambiguous, mismatches))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::compare::{graph_from_extracted, graph_from_reference, CompareOpts};
    use super::*;

    fn inverter_extracted() -> ExtractedNetlist {
        ExtractedNetlist {
            devices: vec![
                Device {
                    kind: DeviceKind::Pmos,
                    gate: 0,
                    source: 1,
                    drain: 2,
                    body: 0,
                    flavor: DeviceFlavor::Standard,
                    w: 0,
                    l: 0,
                    device_class: None,
                    ..Default::default()
                },
                Device {
                    kind: DeviceKind::Nmos,
                    gate: 0,
                    source: 3,
                    drain: 2,
                    body: 0,
                    flavor: DeviceFlavor::Standard,
                    w: 0,
                    l: 0,
                    device_class: None,
                    ..Default::default()
                },
            ],
            net_count: 4,
            used_nets: 4,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: Vec::new(),
            bjt_devices: Vec::new(),
            floating_nets: Vec::new(),
            net_names: std::collections::HashMap::new(),
        }
    }

    fn inverter_reference() -> RefNetlist {
        RefNetlist {
            devices: vec![
                RefDevice {
                    kind: DeviceKind::Pmos,
                    gate: "A".into(),
                    source: "VDD".into(),
                    drain: "Y".into(),
                    w: 0,
                    l: 0,
                    flavor: DeviceFlavor::Standard,
                    ..Default::default()
                },
                RefDevice {
                    kind: DeviceKind::Nmos,
                    gate: "A".into(),
                    source: "VSS".into(),
                    drain: "Y".into(),
                    w: 0,
                    l: 0,
                    flavor: DeviceFlavor::Standard,
                    ..Default::default()
                },
            ],
            net_seeds: std::collections::HashMap::new(),
            ref_two_terminal: Vec::new(),
            ref_bjt: Vec::new(),
        }
    }

    #[test]
    fn gpu_inverter_matches_cpu() {
        let ext = inverter_extracted();
        let reference = inverter_reference();
        let opts = CompareOpts::default();

        let cpu_result = super::super::compare::compare(&ext, &reference, &opts);

        let ga = graph_from_extracted(&ext, opts.strict, &opts.pin_swaps);
        let (gb, ref_net_remap) = graph_from_reference(&reference, opts.strict, &opts.pin_swaps);
        let gpu_result = gpu_compare(&ext, &reference, &opts, &ga, &gb, &ref_net_remap).unwrap();

        assert_eq!(
            cpu_result.matched, gpu_result.matched,
            "CPU={} GPU={} (cpu: {}, gpu: {})",
            cpu_result.matched, gpu_result.matched, cpu_result.reason, gpu_result.reason
        );
        assert_eq!(cpu_result.ambiguous_classes, gpu_result.ambiguous_classes);
    }

    #[test]
    fn gpu_detects_swapped_gate() {
        let reference = inverter_reference();
        let opts = CompareOpts::default();

        let bad = ExtractedNetlist {
            devices: vec![
                Device {
                    kind: DeviceKind::Pmos,
                    gate: 0,
                    source: 1,
                    drain: 2,
                    body: 0,
                    flavor: DeviceFlavor::Standard,
                    w: 0,
                    l: 0,
                    device_class: None,
                    ..Default::default()
                },
                Device {
                    kind: DeviceKind::Nmos,
                    gate: 4,
                    source: 3,
                    drain: 2,
                    body: 0,
                    flavor: DeviceFlavor::Standard,
                    w: 0,
                    l: 0,
                    device_class: None,
                    ..Default::default()
                },
            ],
            net_count: 5,
            used_nets: 5,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: Vec::new(),
            bjt_devices: Vec::new(),
            floating_nets: Vec::new(),
            net_names: std::collections::HashMap::new(),
        };

        let cpu_result = super::super::compare::compare(&bad, &reference, &opts);
        let ga = graph_from_extracted(&bad, opts.strict, &opts.pin_swaps);
        let (gb, ref_net_remap) = graph_from_reference(&reference, opts.strict, &opts.pin_swaps);
        let gpu_result = gpu_compare(&bad, &reference, &opts, &ga, &gb, &ref_net_remap).unwrap();

        assert!(!cpu_result.matched);
        assert!(!gpu_result.matched);
    }

    #[test]
    fn gpu_automorphism_diff_pair() {
        let reference = RefNetlist {
            devices: vec![
                RefDevice {
                    kind: DeviceKind::Nmos,
                    gate: "INP".into(),
                    source: "TAIL".into(),
                    drain: "OUTN".into(),
                    w: 0,
                    l: 0,
                    flavor: DeviceFlavor::Standard,
                    ..Default::default()
                },
                RefDevice {
                    kind: DeviceKind::Nmos,
                    gate: "INN".into(),
                    source: "TAIL".into(),
                    drain: "OUTP".into(),
                    w: 0,
                    l: 0,
                    flavor: DeviceFlavor::Standard,
                    ..Default::default()
                },
            ],
            net_seeds: std::collections::HashMap::new(),
            ref_two_terminal: Vec::new(),
            ref_bjt: Vec::new(),
        };

        let ext = ExtractedNetlist {
            devices: vec![
                Device {
                    kind: DeviceKind::Nmos,
                    gate: 10,
                    source: 20,
                    drain: 30,
                    body: 0,
                    flavor: DeviceFlavor::Standard,
                    w: 0,
                    l: 0,
                    device_class: None,
                    ..Default::default()
                },
                Device {
                    kind: DeviceKind::Nmos,
                    gate: 11,
                    source: 20,
                    drain: 31,
                    body: 0,
                    flavor: DeviceFlavor::Standard,
                    w: 0,
                    l: 0,
                    device_class: None,
                    ..Default::default()
                },
            ],
            net_count: 5,
            used_nets: 5,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: Vec::new(),
            bjt_devices: Vec::new(),
            floating_nets: Vec::new(),
            net_names: std::collections::HashMap::new(),
        };

        let opts = CompareOpts::default();
        let cpu_result = super::super::compare::compare(&ext, &reference, &opts);
        let ga = graph_from_extracted(&ext, opts.strict, &opts.pin_swaps);
        let (gb, ref_net_remap) = graph_from_reference(&reference, opts.strict, &opts.pin_swaps);
        let gpu_result = gpu_compare(&ext, &reference, &opts, &ga, &gb, &ref_net_remap).unwrap();

        assert!(
            cpu_result.matched,
            "CPU should match: {}",
            cpu_result.reason
        );
        assert!(
            gpu_result.matched,
            "GPU should match: {}",
            gpu_result.reason
        );
        assert_eq!(cpu_result.ambiguous_classes, 0);
        assert_eq!(gpu_result.ambiguous_classes, 0);
    }

    #[test]
    fn gpu_two_terminal_wrong_net() {
        let reference = RefNetlist {
            devices: vec![RefDevice {
                kind: DeviceKind::Nmos,
                gate: "A".into(),
                source: "S".into(),
                drain: "D".into(),
                w: 0,
                l: 0,
                flavor: DeviceFlavor::Standard,
                ..Default::default()
            }],
            net_seeds: std::collections::HashMap::new(),
            ref_two_terminal: vec![RefTwoTerminal {
                kind: TwoTerminalKind::Resistor,
                name: "r1".into(),
                terminal_a: "D".into(),
                terminal_b: "VDD".into(),
            }],
            ref_bjt: Vec::new(),
        };

        let good = ExtractedNetlist {
            devices: vec![Device {
                kind: DeviceKind::Nmos,
                gate: 0,
                source: 1,
                drain: 2,
                body: 0,
                flavor: DeviceFlavor::Standard,
                w: 0,
                l: 0,
                device_class: None,
                ..Default::default()
            }],
            net_count: 4,
            used_nets: 4,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: vec![TwoTerminalDevice {
                kind: TwoTerminalKind::Resistor,
                name: "r1".into(),
                terminal_a: 2,
                terminal_b: 3,
                value: 100.0,
            }],
            bjt_devices: Vec::new(),
            floating_nets: Vec::new(),
            net_names: std::collections::HashMap::new(),
        };
        let opts = CompareOpts::default();
        let ga = graph_from_extracted(&good, opts.strict, &opts.pin_swaps);
        let (gb, rnr) = graph_from_reference(&reference, opts.strict, &opts.pin_swaps);
        let r = gpu_compare(&good, &reference, &opts, &ga, &gb, &rnr).unwrap();
        assert!(r.matched, "correct resistor should match: {}", r.reason);

        let bad = ExtractedNetlist {
            devices: vec![Device {
                kind: DeviceKind::Nmos,
                gate: 0,
                source: 1,
                drain: 2,
                body: 0,
                flavor: DeviceFlavor::Standard,
                w: 0,
                l: 0,
                device_class: None,
                ..Default::default()
            }],
            net_count: 4,
            used_nets: 4,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: vec![TwoTerminalDevice {
                kind: TwoTerminalKind::Resistor,
                name: "r1".into(),
                terminal_a: 0,
                terminal_b: 3,
                value: 100.0,
            }],
            bjt_devices: Vec::new(),
            floating_nets: Vec::new(),
            net_names: std::collections::HashMap::new(),
        };
        let ga = graph_from_extracted(&bad, opts.strict, &opts.pin_swaps);
        let (gb, rnr) = graph_from_reference(&reference, opts.strict, &opts.pin_swaps);
        let r = gpu_compare(&bad, &reference, &opts, &ga, &gb, &rnr).unwrap();
        assert!(!r.matched, "resistor on gate should mismatch");
    }
}
