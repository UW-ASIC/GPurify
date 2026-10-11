//! Two extractions of one layout, compared net by net: the netlist diff a
//! PEX flow is qualified with.
//!
//! Data in: a reference and a candidate [`ParasiticNetwork`] over the same
//! nets (the same layout and net table, so a [`NetId`] names one net in
//! both): a field solve against the closed forms, one deck against another,
//! one extraction type against another. Data out: a [`Comparison`], each
//! metric's value per net in both, and [`Metric::errors`], the statistics a
//! qualification reports.
//!
//! The metrics are those Silvaco's PEX Certify names (its public brief: "PEX
//! Diff: comparison of two or more extracted netlists in terms of pin-to-pin
//! resistances and RC delays, net to net capacitances"):
//!
//! - **total and ground capacitance** of each net, fF
//!   ([`ParasiticNetwork::capacitance_per_net`] and its ground part);
//! - **net-to-net capacitance**: the coupling between each pair of nets, fF;
//! - **pin-to-pin resistance**: from the net's first node (its driver) to
//!   the node farthest from it, the largest effective resistance
//!   `(G⁻¹)_jj` of the net's resistor network with the driver grounded, Ω;
//! - **RC delay**: the Elmore delay (Elmore, *J. Appl. Phys.* 19(1), 1948)
//!   from the driver to its slowest node, `max_j Σ_k (G⁻¹)_jk C_k`, each
//!   node's capacitance its ground and coupling capacitance together (the
//!   neighbours held still), in Ω·fF, which is femtoseconds.
//!
//! A node no resistance reaches from the driver has no defined resistance
//! or delay and is left out of both; a net of one node (lumped) has 0 of
//! each. Inductance plays no part. Nets are matched by [`NetId`], not by
//! name: this compares two extractions of one layout, not two tools'
//! netlists of two.

use crate::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_check::topology::NetId;
use std::collections::BTreeMap;

/// The largest net whose resistance and delay [`compare`] computes: its
/// conductance matrix is dense, 32 MiB at this size.
pub const MAX_DENSE_NODES: usize = 2048;

/// One quantity per net (or per pair of nets) in both extractions, as
/// parallel columns in ascending key order.
#[derive(Debug, Clone, PartialEq)]
pub struct Metric<K> {
    /// The net, or the pair of nets, each row is about.
    pub key: Vec<K>,
    /// The reference extraction's value.
    pub reference: Vec<f64>,
    /// The candidate extraction's value.
    pub candidate: Vec<f64>,
}

// By hand: a derive would ask `K: Default`, which a `NetId` is not.
impl<K> Default for Metric<K> {
    fn default() -> Self {
        Self {
            key: Vec::new(),
            reference: Vec::new(),
            candidate: Vec::new(),
        }
    }
}

/// Every metric of two extractions, over the nets both hold.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Comparison {
    /// Each net's total capacitance, ground and every coupling, fF.
    pub total_cap: Metric<NetId>,
    /// Each net's capacitance to ground, fF.
    pub ground_cap: Metric<NetId>,
    /// The coupling between two nets, fF, keyed `(lower, higher)`; a pair
    /// coupled in only one extraction reads 0 in the other.
    pub coupling: Metric<(NetId, NetId)>,
    /// Pin-to-pin resistance, driver to its farthest node, Ω.
    pub resistance: Metric<NetId>,
    /// Elmore delay, driver to its slowest node, fs (Ω·fF).
    pub delay: Metric<NetId>,
    /// Nets with nodes in the reference only.
    pub only_reference: Vec<NetId>,
    /// Nets with nodes in the candidate only.
    pub only_candidate: Vec<NetId>,
}

/// What a qualification reports of one metric: how far the candidate is
/// from the reference, relative to the reference.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Errors {
    /// Rows compared: those where either value reaches the floor.
    pub count: usize,
    /// Of those, the rows within the tolerance.
    pub within: usize,
    /// The largest relative error `|c − r| / |r|`, signed as `c − r`; 0
    /// when nothing is compared, infinite where the reference is 0.
    pub worst: f64,
    /// The row it is in, `None` when nothing is compared.
    pub worst_row: Option<usize>,
    /// The mean of `|c − r| / |r|`.
    pub mean: f64,
    /// The root mean square of the relative errors.
    pub rms: f64,
}

impl<K> Metric<K> {
    fn push(&mut self, key: K, reference: f64, candidate: f64) {
        self.key.push(key);
        self.reference.push(reference);
        self.candidate.push(candidate);
    }

    /// The relative error statistics over every row where the reference or
    /// the candidate reaches `floor` in magnitude (a coupling of a few
    /// attofarads is noise to a qualification); a row is within when its
    /// relative error is at most `tolerance`. Rows fold in key order, so the
    /// result is a function of the two networks alone.
    pub fn errors(&self, tolerance: f64, floor: f64) -> Errors {
        let mut out = Errors {
            count: 0,
            within: 0,
            worst: 0.0,
            worst_row: None,
            mean: 0.0,
            rms: 0.0,
        };
        let (mut sum, mut squares) = (0.0_f64, 0.0_f64);
        for (row, (&r, &c)) in self.reference.iter().zip(&self.candidate).enumerate() {
            if !(r.abs() >= floor || c.abs() >= floor) {
                continue;
            }
            // Equal values are no error, a zero reference among them.
            let error = if c - r == 0.0 { 0.0 } else { (c - r) / r.abs() };
            let size = error.abs();
            out.count += 1;
            out.within += usize::from(size <= tolerance);
            if out.worst_row.is_none() || size > out.worst.abs() {
                out.worst = error;
                out.worst_row = Some(row);
            }
            sum += size;
            squares += size * size;
        }
        if out.count > 0 {
            #[expect(clippy::cast_precision_loss, reason = "a row count")]
            let n = out.count as f64;
            out.mean = sum / n;
            out.rms = (squares / n).sqrt();
        }
        out
    }
}

/// Compares `candidate` against `reference`, net by net. Both must hold the
/// network invariant and be in canonical order
/// ([`ParasiticNetwork::sort_canonical`]), as every extraction leaves them.
/// A net of more than [`MAX_DENSE_NODES`] nodes reads NaN resistance and
/// delay: not computed, rather than a dense matrix of that size.
///
/// # Time complexity
///
/// *O*(e log e) for the elements, plus a dense Cholesky factorisation per
/// net, *O*(n³) for a net of n nodes.
///
/// ponytail: dense per net, capped; a sparse factorisation if a larger net
/// is ever qualified.
pub fn compare(reference: &ParasiticNetwork, candidate: &ParasiticNetwork) -> Comparison {
    let (r, c) = (Summary::of(reference), Summary::of(candidate));
    let mut out = Comparison::default();
    for net in r.nets.keys() {
        if !c.nets.contains_key(net) {
            out.only_reference.push(*net);
        }
    }
    for net in c.nets.keys() {
        if !r.nets.contains_key(net) {
            out.only_candidate.push(*net);
        }
    }
    for (&net, here) in &r.nets {
        let Some(there) = c.nets.get(&net) else {
            continue;
        };
        out.total_cap.push(net, here.total, there.total);
        out.ground_cap.push(net, here.ground, there.ground);
        out.resistance.push(net, here.resistance, there.resistance);
        out.delay.push(net, here.delay, there.delay);
    }
    let in_both = |net: &NetId| r.nets.contains_key(net) && c.nets.contains_key(net);
    let mut pairs: Vec<(NetId, NetId)> = r
        .pairs
        .keys()
        .chain(c.pairs.keys())
        .copied()
        .filter(|(a, b)| in_both(a) && in_both(b))
        .collect();
    pairs.sort_unstable();
    pairs.dedup();
    for pair in pairs {
        let value =
            |pairs: &BTreeMap<(NetId, NetId), f64>| pairs.get(&pair).copied().unwrap_or(0.0);
        out.coupling.push(pair, value(&r.pairs), value(&c.pairs));
    }
    out
}

/// One net's metrics.
#[derive(Debug, Clone, Copy)]
struct NetSummary {
    total: f64,
    ground: f64,
    resistance: f64,
    delay: f64,
}

/// Every net's metrics and every pair's coupling, of one network.
struct Summary {
    nets: BTreeMap<NetId, NetSummary>,
    pairs: BTreeMap<(NetId, NetId), f64>,
}

impl Summary {
    fn of(network: &ParasiticNetwork) -> Self {
        let total = network.capacitance_per_net();
        let net_of = |node: NodeId| network.node_net[node.0 as usize];
        // Each node's capacitance, ground and coupling alike, and each
        // net's ground part and each pair's coupling.
        let mut node_cap = vec![0.0_f64; network.node_count()];
        let mut ground: BTreeMap<NetId, f64> = BTreeMap::new();
        let mut pairs: BTreeMap<(NetId, NetId), f64> = BTreeMap::new();
        for row in 0..network.element_count() {
            let near = network.from[row];
            match (network.value[row], network.to[row]) {
                (Parasitic::GroundCap(q), _) => {
                    node_cap[near.0 as usize] += q.raw();
                    *ground.entry(net_of(near)).or_insert(0.0) += q.raw();
                }
                (Parasitic::CouplingCap(q), Some(far)) => {
                    node_cap[near.0 as usize] += q.raw();
                    node_cap[far.0 as usize] += q.raw();
                    let (a, b) = (net_of(near), net_of(far));
                    if a != b {
                        *pairs.entry((a.min(b), a.max(b))).or_insert(0.0) += q.raw();
                    }
                }
                _ => {}
            }
        }
        let mut nets = BTreeMap::new();
        let mut start = 0;
        while start < network.node_count() {
            let net = network.node_net[start];
            let end = start + network.node_net[start..].partition_point(|&other| other == net);
            let (resistance, delay) = resistance_and_delay(network, start..end, &node_cap);
            nets.insert(
                net,
                NetSummary {
                    total: total[net.0 as usize],
                    ground: ground.get(&net).copied().unwrap_or(0.0),
                    resistance,
                    delay,
                },
            );
            start = end;
        }
        Summary { nets, pairs }
    }
}

/// The pin-to-pin resistance and Elmore delay of the net on `nodes`, driven
/// at its first node: the largest `(G⁻¹)_jj` and `(G⁻¹ c)_j` over the nodes
/// a resistance reaches, `G` the conductance matrix with the driver
/// grounded. `(0, 0)` for a net of one reachable node.
fn resistance_and_delay(
    network: &ParasiticNetwork,
    nodes: std::ops::Range<usize>,
    node_cap: &[f64],
) -> (f64, f64) {
    let n = nodes.len();
    if n > MAX_DENSE_NODES {
        return (f64::NAN, f64::NAN);
    }
    // Which nodes a resistance reaches from the driver. A net's resistances
    // all start on its own nodes, one run of a canonical network.
    let mut reached = vec![false; n];
    reached[0] = true;
    let first = |end: usize| network.from.partition_point(|from| (from.0 as usize) < end);
    let resistors: Vec<(usize, usize, f64)> = (first(nodes.start)..first(nodes.end))
        .filter_map(|row| match (network.value[row], network.to[row]) {
            (Parasitic::Resistance(q), Some(far)) => {
                let (a, b) = (network.from[row].0 as usize, far.0 as usize);
                if nodes.contains(&a) && nodes.contains(&b) && q.raw() > 0.0 {
                    Some((a - nodes.start, b - nodes.start, q.raw()))
                } else {
                    None
                }
            }
            _ => None,
        })
        .collect();
    loop {
        let mut grew = false;
        for &(a, b, _) in &resistors {
            if reached[a] != reached[b] {
                reached[a] = true;
                reached[b] = true;
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    // The reached nodes but the driver, numbered from 0.
    let mut index = vec![usize::MAX; n];
    let mut m = 0;
    for (node, &here) in reached.iter().enumerate().skip(1) {
        if here {
            index[node] = m;
            m += 1;
        }
    }
    if m == 0 {
        return (0.0, 0.0);
    }
    let mut g = vec![0.0_f64; m * m];
    for &(a, b, ohm) in &resistors {
        let conductance = 1.0 / ohm;
        for (x, y) in [(a, b), (b, a)] {
            if x != 0 && reached[x] {
                g[index[x] * m + index[x]] += conductance;
                if y != 0 {
                    g[index[x] * m + index[y]] -= conductance;
                }
            }
        }
    }
    let Some(factor) = cholesky(g, m) else {
        return (f64::NAN, f64::NAN);
    };
    let mut caps = vec![0.0_f64; m];
    for (node, &here) in reached.iter().enumerate().skip(1) {
        if here {
            caps[index[node]] = node_cap[nodes.start + node];
        }
    }
    let delays = solve(&factor, m, &caps);
    let delay = delays.iter().copied().fold(0.0_f64, f64::max);
    let mut resistance = 0.0_f64;
    let mut unit = vec![0.0_f64; m];
    for j in 0..m {
        unit.fill(0.0);
        unit[j] = 1.0;
        resistance = resistance.max(solve(&factor, m, &unit)[j]);
    }
    (resistance, delay)
}

/// The lower Cholesky factor of a symmetric positive definite `m × m`
/// matrix, row-major; `None` at a pivot that is not positive.
#[allow(
    clippy::needless_range_loop,
    reason = "the fold order is the index order"
)]
fn cholesky(mut a: Vec<f64>, m: usize) -> Option<Vec<f64>> {
    for j in 0..m {
        let mut pivot = a[j * m + j];
        for k in 0..j {
            pivot -= a[j * m + k] * a[j * m + k];
        }
        if !(pivot > 0.0) {
            return None;
        }
        let pivot = pivot.sqrt();
        a[j * m + j] = pivot;
        for i in j + 1..m {
            let mut value = a[i * m + j];
            for k in 0..j {
                value -= a[i * m + k] * a[j * m + k];
            }
            a[i * m + j] = value / pivot;
        }
    }
    Some(a)
}

/// `x` with `L Lᵀ x = b`, `L` from [`cholesky`].
#[allow(
    clippy::needless_range_loop,
    reason = "the fold order is the index order"
)]
fn solve(factor: &[f64], m: usize, b: &[f64]) -> Vec<f64> {
    let mut y = b.to_vec();
    for i in 0..m {
        for k in 0..i {
            y[i] -= factor[i * m + k] * y[k];
        }
        y[i] /= factor[i * m + i];
    }
    for i in (0..m).rev() {
        for k in i + 1..m {
            y[i] -= factor[k * m + i] * y[k];
        }
        y[i] /= factor[i * m + i];
    }
    y
}
