//! Graphs built by hand, and the small vocabulary the LVS suite asserts in.
//!
//! Fixtures are construct-from-answer: the expected pairing is a fact about how
//! the graph was written. CSR ranges are `start[i] .. start[i + 1]`.

#![allow(
    dead_code,
    reason = "each test binary links only the fixtures it names"
)]

use gpurify_check::lvs::graph::Graph;
use gpurify_check::lvs::verdict::{Discrepancy, Side, Verdict};
use gpurify_check::topology::TerminalRole;
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrId;
use gpurify_testgen::Rng;

/// Interned names, stated as ids.
///
/// [`StrId`] is a transparent newtype over an index into the one string table a
/// run owns. Nothing in this suite resolves an id back to text, so the ids can
/// be written directly and `StrTable::intern` — a `todo!()` until the
/// Implementation-Phase — never has to be called.
pub const NCH: StrId = StrId(1);
pub const PCH: StrId = StrId(2);
pub const NPN: StrId = StrId(3);
pub const RES: StrId = StrId(4);
pub const WIDTH: StrId = StrId(5);
pub const LENGTH: StrId = StrId(6);
pub const VDD: StrId = StrId(7);
pub const VSS: StrId = StrId(8);

/// A width that a `usize` cannot exceed here without the fixture being wrong.
fn narrow(value: usize) -> u32 {
    u32::try_from(value).expect("a hand-written fixture is far below 2^32 rows")
}

/// Accumulates devices and nets, then lays them out as the parallel columns
/// [`Graph`] declares.
///
/// The reverse incidence is derived rather than supplied: `net_terminal` is by
/// definition the transpose of the device terminal columns, and a fixture that
/// stated both could state them inconsistently.
#[derive(Debug)]
pub struct GraphBuilder {
    nets: u32,
    kind: Vec<DeviceKind>,
    model: Vec<StrId>,
    terminals: Vec<Vec<(TerminalRole, u32)>>,
    params: Vec<Vec<(StrId, f64)>>,
    net_name: Vec<Option<StrId>>,
    port_net: Vec<u32>,
}

impl GraphBuilder {
    #[must_use]
    pub fn new(nets: u32) -> Self {
        Self {
            nets,
            kind: Vec::new(),
            model: Vec::new(),
            terminals: Vec::new(),
            params: Vec::new(),
            net_name: vec![None; nets as usize],
            port_net: Vec::new(),
        }
    }

    /// Add a device. Returns its index, which is also its node index.
    pub fn device(
        &mut self,
        kind: DeviceKind,
        model: StrId,
        terminals: &[(TerminalRole, u32)],
    ) -> u32 {
        self.device_with_params(kind, model, terminals, &[])
    }

    pub fn device_with_params(
        &mut self,
        kind: DeviceKind,
        model: StrId,
        terminals: &[(TerminalRole, u32)],
        params: &[(StrId, f64)],
    ) -> u32 {
        assert!(
            !terminals.is_empty(),
            "a device with no terminals is not one"
        );
        for &(_, net) in terminals {
            assert!(net < self.nets, "terminal names net {net} of {}", self.nets);
        }
        self.kind.push(kind);
        self.model.push(model);
        self.terminals.push(terminals.to_vec());
        self.params.push(params.to_vec());
        narrow(self.kind.len() - 1)
    }

    pub fn name_net(&mut self, net: u32, name: StrId) {
        self.net_name[net as usize] = Some(name);
    }

    pub fn port(&mut self, net: u32) {
        assert!(net < self.nets, "port names net {net} of {}", self.nets);
        self.port_net.push(net);
    }

    #[must_use]
    pub fn finish(self) -> Graph {
        let mut graph = Graph {
            net_name: self.net_name,
            port_net: self.port_net,
            ..Graph::default()
        };

        graph.device_terminal_start.push(0);
        graph.device_param_start.push(0);
        for index in 0..self.kind.len() {
            graph.device_kind.push(self.kind[index]);
            graph.device_model.push(self.model[index]);
            for &(role, net) in &self.terminals[index] {
                graph.terminal_net.push(net);
                graph.terminal_role.push(role);
            }
            graph
                .device_terminal_start
                .push(narrow(graph.terminal_net.len()));
            graph.param.extend_from_slice(&self.params[index]);
            graph.device_param_start.push(narrow(graph.param.len()));
        }

        // The transpose, ascending by device within each net.
        let mut per_net: Vec<Vec<(u32, TerminalRole)>> = vec![Vec::new(); self.nets as usize];
        for (index, terminals) in self.terminals.iter().enumerate() {
            for &(role, net) in terminals {
                per_net[net as usize].push((narrow(index), role));
            }
        }
        graph.net_terminal_start.push(0);
        for terminals in &per_net {
            graph.net_terminal.extend_from_slice(terminals);
            graph
                .net_terminal_start
                .push(narrow(graph.net_terminal.len()));
        }

        graph
    }
}

/// Two transistors stacked gate-to-drain, sharing a bulk.
///
/// Nets: 0 the lower gate, 1 the lower source, 2 the shared drain-gate node,
/// 3 the common bulk, 4 the upper source, 5 the upper drain.
///
/// # Not rigid, and the automorphism is named here on purpose
///
/// It used to be, and the claim is withdrawn. `refine::role_code` reads a MOS
/// channel as symmetric — finding F4 — so nets 4 and 5 are the upper device's
/// two channel ends, each carrying one terminal of one device under one role
/// code, and exchanging them is an automorphism no signature can break. The
/// automorphism group has order two and that is all of it: net 1 is the lower
/// device's only degree-one channel net, net 2 carries a gate as well, and the
/// two devices differ in what their gates land on.
///
/// So a test may still assert the *identity* pairing of this graph against
/// itself — the tie-break is lowest index on each side, and the two sides are
/// the same graph — but it may **not** assert a unique pairing against a
/// relabelling, because there are two. [`chain`] is the rigid fixture.
/// Neither the model name nor the port list is load-bearing, which keeps the
/// fixture independent of two semantics the frozen definitions leave open.
#[must_use]
pub fn stacked_pair() -> Graph {
    stacked_pair_with_params(&[], &[])
}

/// The same fixture with parameters on each device, for parametric comparison.
#[must_use]
pub fn stacked_pair_with_params(lower: &[(StrId, f64)], upper: &[(StrId, f64)]) -> Graph {
    use TerminalRole::{Bulk, Drain, Gate, Source};
    let mut builder = GraphBuilder::new(6);
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)],
        lower,
    );
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 2), (Source, 4), (Drain, 5), (Bulk, 3)],
        upper,
    );
    builder.finish()
}

/// A MOS and a bipolar, sharing nothing.
///
/// Two components, distinguishable from each other by terminal count and by
/// role, and each internally rigid because every net carries exactly one
/// terminal and no two of those terminals share a role. Deleting either device
/// therefore has an unambiguous consequence, which is what a
/// construct-from-answer perturbation needs.
///
/// Nets 0..=3 belong to the MOS in gate, source, drain, bulk order; nets 4..=6
/// to the bipolar in base, emitter, collector order.
#[must_use]
pub fn mos_and_bjt() -> Graph {
    let mut builder = GraphBuilder::new(7);
    add_mos(&mut builder, 0);
    add_bjt(&mut builder, 4);
    builder.finish()
}

/// The MOS alone: `mos_and_bjt` with the bipolar deleted, and nothing else
/// changed. The bipolar's three nets stay, so the perturbation is exactly one
/// device.
#[must_use]
pub fn mos_and_bjt_without_the_bjt() -> Graph {
    let mut builder = GraphBuilder::new(7);
    add_mos(&mut builder, 0);
    builder.finish()
}

fn add_mos(builder: &mut GraphBuilder, base: u32) {
    use TerminalRole::{Bulk, Drain, Gate, Source};
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[
            (Gate, base),
            (Source, base + 1),
            (Drain, base + 2),
            (Bulk, base + 3),
        ],
    );
}

fn add_bjt(builder: &mut GraphBuilder, base: u32) {
    use TerminalRole::{Base, Collector, Emitter};
    builder.device(
        DeviceKind::Bjt,
        NPN,
        &[(Base, base), (Emitter, base + 1), (Collector, base + 2)],
    );
}

/// A differential pair: two transistors sharing a tail and a bulk, with their
/// gates and drains on separate nets.
///
/// Genuinely symmetric. Exchanging the two devices along with their gate and
/// drain nets is an automorphism, so refinement cannot separate them and the
/// only honest outcomes are the tie-break rule or a refusal. No ports, because
/// a port list is an anchor and an anchored net would destroy the symmetry the
/// fixture exists to provide.
///
/// Nets: 0 the tail, 1 and 2 the gates, 3 and 4 the drains, 5 the bulk.
#[must_use]
pub fn differential_pair() -> Graph {
    use TerminalRole::{Bulk, Drain, Gate, Source};
    let mut builder = GraphBuilder::new(6);
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 1), (Source, 0), (Drain, 3), (Bulk, 5)],
    );
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 2), (Source, 0), (Drain, 4), (Bulk, 5)],
    );
    builder.finish()
}

/// A source-to-drain chain of `devices` transistors over `devices + 1` nets,
/// diode-connected at the low end.
///
/// Refinement propagates one hop per round along a chain, so a chain of length
/// n needs on the order of n rounds to become discrete. That makes it the
/// fixture for the round limit: the answer exists, and a run that stops early
/// has genuinely not found it yet.
///
/// # The anchor is what makes it rigid
///
/// Writing the source at the low end of every device and the drain at the high
/// end does **not** direct the chain, because `refine::role_code` reads a MOS
/// channel as symmetric — which is physics, not a shortcut: which end is the
/// source is set by bias, and an extractor reading geometry has nothing to
/// decide it with. With the two roles collapsed, reversing the chain end to end
/// maps every terminal onto one of the same code, so the reversal is a genuine
/// automorphism.
///
/// Device 0's gate ties to one end of its own channel, which is the smallest
/// thing that distinguishes the two ends of the path and is how a real stack is
/// anchored: a diode-connected transistor at the bottom of a mirror. A path
/// graph with one distinguished endpoint has no automorphism but the identity,
/// so the chain converges to one node per class and a test may assert the
/// pairing exactly.
///
/// # Panics
///
/// When `devices` is zero.
#[must_use]
pub fn chain(devices: u32) -> Graph {
    use TerminalRole::{Drain, Gate, Source};
    assert!(devices > 0, "a chain needs at least one device");
    let mut builder = GraphBuilder::new(devices + 1);
    builder.device(DeviceKind::Mos, NCH, &[(Source, 0), (Drain, 1), (Gate, 0)]);
    for index in 1..devices {
        builder.device(DeviceKind::Mos, NCH, &[(Source, index), (Drain, index + 1)]);
    }
    builder.finish()
}

/// An arbitrary well-formed graph, fixed by a seed.
///
/// For the laws — reflexivity above all — which hold for *any* input and so are
/// worth asserting on input nobody chose. Every device gets between two and
/// four terminals with distinct roles, on nets drawn uniformly, which produces
/// shared nets, floating nets and repeated structure without any of them being
/// arranged.
///
/// # Panics
///
/// When `devices` or `nets` is zero.
#[must_use]
pub fn random_graph(rng: &mut Rng, devices: u32, nets: u32) -> Graph {
    use TerminalRole::{Bulk, Drain, Gate, Source};
    const ROLES: [TerminalRole; 4] = [Gate, Source, Drain, Bulk];
    assert!(devices > 0 && nets > 0, "an empty graph is not a fixture");

    let mut builder = GraphBuilder::new(nets);
    for _ in 0..devices {
        let count = 2 + usize::try_from(rng.below(3)).expect("below(3) is under three");
        let terminals: Vec<(TerminalRole, u32)> = ROLES[..count]
            .iter()
            .map(|&role| {
                let net = u32::try_from(rng.below(u64::from(nets))).expect("below(nets) is a net");
                (role, net)
            })
            .collect();
        let model = if rng.unit() < 0.5 { NCH } else { PCH };
        builder.device(DeviceKind::Mos, model, &terminals);
    }
    builder.finish()
}

/// Relabel a graph's devices and nets.
///
/// `new_device[old]` and `new_net[old]` give each row its new index. The result
/// is isomorphic to `source` by construction, which is what makes it usable as
/// an oracle: the unique pairing of the two, wherever the source is rigid, is
/// exactly these two maps.
///
/// # Panics
///
/// When either map is not a permutation of its index space.
#[must_use]
pub fn permute(source: &Graph, new_device: &[u32], new_net: &[u32]) -> Graph {
    let device_count = source.device_kind.len();
    let net_count = source.net_name.len();
    assert_eq!(
        new_device.len(),
        device_count,
        "device map is the wrong size"
    );
    assert_eq!(new_net.len(), net_count, "net map is the wrong size");
    assert!(
        is_permutation(new_device),
        "device map is not a permutation"
    );
    assert!(is_permutation(new_net), "net map is not a permutation");

    // `order[new] = old`, so devices are emitted in their new index order.
    let mut order: Vec<usize> = (0..device_count).collect();
    order.sort_by_key(|&old| new_device[old]);

    let mut builder = GraphBuilder::new(narrow(net_count));
    for &old in &order {
        let terminals = source.device_terminal_start[old] as usize
            ..source.device_terminal_start[old + 1] as usize;
        let mapped: Vec<(TerminalRole, u32)> = terminals
            .map(|slot| {
                let net = source.terminal_net[slot] as usize;
                (source.terminal_role[slot], new_net[net])
            })
            .collect();
        let params =
            source.device_param_start[old] as usize..source.device_param_start[old + 1] as usize;
        builder.device_with_params(
            source.device_kind[old],
            source.device_model[old],
            &mapped,
            &source.param[params],
        );
    }
    for (old, name) in source.net_name.iter().enumerate() {
        if let Some(name) = *name {
            builder.name_net(new_net[old], name);
        }
    }
    for &net in &source.port_net {
        builder.port(new_net[net as usize]);
    }
    builder.finish()
}

fn is_permutation(map: &[u32]) -> bool {
    let mut seen = vec![false; map.len()];
    for &value in map {
        let Some(slot) = seen.get_mut(value as usize) else {
            return false;
        };
        if *slot {
            return false;
        }
        *slot = true;
    }
    true
}

/// The discrepancy list of a mismatch, or a failure naming what came back.
///
/// # Panics
///
/// When the verdict is not [`Verdict::Mismatch`].
#[must_use]
pub fn discrepancies(verdict: &Verdict) -> &[Discrepancy] {
    match verdict {
        Verdict::Mismatch(found) => found,
        other => panic!("expected a mismatch, got {other:?}"),
    }
}

/// Restate a discrepancy from the other side's point of view.
///
/// Comparing A to B and comparing B to A are the same question asked twice, so
/// their answers must be each other's image under this map. Every field that
/// names a side is exchanged.
#[must_use]
pub fn flip(discrepancy: &Discrepancy) -> Discrepancy {
    match *discrepancy {
        Discrepancy::UnpairedDevice {
            side,
            device,
            model,
        } => Discrepancy::UnpairedDevice {
            side: flip_side(side),
            device,
            model,
        },
        Discrepancy::UnpairedNet { side, net, name } => Discrepancy::UnpairedNet {
            side: flip_side(side),
            net,
            name,
        },
        Discrepancy::TerminalMismatch {
            layout_device,
            ref_device,
            role,
        } => Discrepancy::TerminalMismatch {
            layout_device: ref_device,
            ref_device: layout_device,
            role,
        },
        Discrepancy::ParameterMismatch {
            layout_device,
            ref_device,
            param,
            layout_value,
            ref_value,
        } => Discrepancy::ParameterMismatch {
            layout_device: ref_device,
            ref_device: layout_device,
            param,
            layout_value: ref_value,
            ref_value: layout_value,
        },
        // Both a side and a device pair, so both are exchanged: the reference
        // card declaring a lone `W` is, read backwards, the layout declaring it.
        Discrepancy::UndeclaredParam {
            side,
            layout_device,
            ref_device,
            param,
        } => Discrepancy::UndeclaredParam {
            side: flip_side(side),
            layout_device: ref_device,
            ref_device: layout_device,
            param,
        },
        Discrepancy::DuplicateName { side, name, nets } => Discrepancy::DuplicateName {
            side: flip_side(side),
            name,
            nets,
        },
        Discrepancy::ClassImbalance {
            layout_nodes,
            ref_nodes,
        } => Discrepancy::ClassImbalance {
            layout_nodes: ref_nodes,
            ref_nodes: layout_nodes,
        },
    }
}

#[must_use]
pub fn flip_side(side: Side) -> Side {
    match side {
        Side::Layout => Side::Reference,
        Side::Reference => Side::Layout,
    }
}

/// Assert two discrepancy lists hold the same findings.
///
/// A multiset comparison, not a sequence one: the order a comparator emits its
/// findings in is not part of what "the same difference" means, and the
/// determinism gate is asserted separately by rerunning the same comparison.
///
/// # Panics
///
/// When either list holds a finding the other does not.
pub fn assert_same_discrepancies(actual: &[Discrepancy], expected: &[Discrepancy]) {
    let mut taken = vec![false; actual.len()];
    for want in expected {
        let found = actual
            .iter()
            .enumerate()
            .position(|(index, have)| !taken[index] && have == want);
        let Some(index) = found else {
            panic!("no discrepancy matches {want:?}\nfound: {actual:#?}");
        };
        taken[index] = true;
    }
    let extra: Vec<&Discrepancy> = actual
        .iter()
        .enumerate()
        .filter(|(index, _)| !taken[*index])
        .map(|(_, found)| found)
        .collect();
    assert!(
        extra.is_empty(),
        "unexpected discrepancies {extra:#?}\nexpected: {expected:#?}"
    );
}

/// Whether a discrepancy blames a device on a given side.
#[must_use]
pub fn blames_device(discrepancy: &Discrepancy, side: Side, index: u32) -> bool {
    match *discrepancy {
        Discrepancy::UnpairedDevice {
            side: found,
            device,
            ..
        } => found == side && device == index,
        Discrepancy::TerminalMismatch {
            layout_device,
            ref_device,
            ..
        }
        | Discrepancy::ParameterMismatch {
            layout_device,
            ref_device,
            ..
        } => match side {
            Side::Layout => layout_device == index,
            Side::Reference => ref_device == index,
        },
        _ => false,
    }
}

/// Whether a discrepancy blames a net on a given side.
#[must_use]
pub fn blames_net(discrepancy: &Discrepancy, side: Side, index: u32) -> bool {
    match *discrepancy {
        Discrepancy::UnpairedNet {
            side: found, net, ..
        } => found == side && net == index,
        Discrepancy::DuplicateName { nets, .. } => nets.0 == index || nets.1 == index,
        _ => false,
    }
}
