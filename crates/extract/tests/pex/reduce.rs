//! PEX-008: the extraction type a deck asks for, applied to a network whose
//! every reduction is worked out by hand.

use gpurify_check::topology::NetId;
use gpurify_extract::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_extract::reduce::reduce;
use gpurify_geom::{LayerId, Qty};
use gpurify_ingest::deck::{Extraction, ExtractionKind};
use gpurify_testgen::assert_close;

/// Three nets: net 0 on nodes 0 and 1, net 1 on nodes 2 and 3, net 2 on
/// node 4. Ground: 1, 2, 3, 0.5 and 4 fF on nodes 0 to 4. Coupling: 0.25 fF
/// between nodes 0 and 2, 0.05 between 1 and 3, 0.75 between 1 and 4, 0.125
/// between 3 and 4. A field-solved look besides: 10 and 20 ohm along nets 0
/// and 1, a 5 pH inductance on net 0 and a 1 pH mutual to net 1.
///
/// Per net, every capacitance it touches: net 0 holds 1 + 2 + 0.25 + 0.05 +
/// 0.75 = 4.05 fF, net 1 3 + 0.5 + 0.25 + 0.05 + 0.125 = 3.925, net 2
/// 4 + 0.75 + 0.125 = 4.875.
fn network() -> ParasiticNetwork {
    let mut out = ParasiticNetwork {
        node_net: [0, 0, 1, 1, 2].map(NetId).to_vec(),
        node_layer: vec![LayerId(0); 5],
        ..ParasiticNetwork::default()
    };
    let ground = |ff: f64| Parasitic::GroundCap(Qty::new(ff));
    let coupling = |ff: f64| Parasitic::CouplingCap(Qty::new(ff));
    for (node, ff) in [(0, 1.0), (1, 2.0), (2, 3.0), (3, 0.5), (4, 4.0)] {
        out.push(NodeId(node), None, ground(ff));
    }
    for (a, b, ff) in [(0, 2, 0.25), (1, 3, 0.05), (1, 4, 0.75), (3, 4, 0.125)] {
        out.push(NodeId(a), Some(NodeId(b)), coupling(ff));
    }
    out.push(
        NodeId(0),
        Some(NodeId(1)),
        Parasitic::Resistance(Qty::new(10.0)),
    );
    out.push(
        NodeId(2),
        Some(NodeId(3)),
        Parasitic::Resistance(Qty::new(20.0)),
    );
    out.push(
        NodeId(0),
        Some(NodeId(1)),
        Parasitic::Inductance(Qty::new(5.0)),
    );
    out.push(
        NodeId(0),
        Some(NodeId(2)),
        Parasitic::MutualInductance(Qty::new(1.0)),
    );
    out.sort_canonical();
    out
}

/// Each net's total capacitance, worked out in [`network`].
const TOTALS: [f64; 3] = [4.05, 3.925, 4.875];

fn reduced(kind: ExtractionKind, coupling_threshold_ff: f64) -> ParasiticNetwork {
    let mut out = network();
    reduce(
        &mut out,
        Extraction {
            kind,
            coupling_threshold_af: coupling_threshold_ff * 1e3,
        },
    );
    out
}

/// Every element of one kind, as `(from, to, value)`.
fn of_kind(
    network: &ParasiticNetwork,
    keep: fn(Parasitic) -> Option<f64>,
) -> Vec<(u32, Option<u32>, f64)> {
    (0..network.element_count())
        .filter_map(|row| {
            keep(network.value[row])
                .map(|value| (network.from[row].0, network.to[row].map(|n| n.0), value))
        })
        .collect()
}

fn ground(value: Parasitic) -> Option<f64> {
    match value {
        Parasitic::GroundCap(q) => Some(q.raw()),
        _ => None,
    }
}

fn coupling(value: Parasitic) -> Option<f64> {
    match value {
        Parasitic::CouplingCap(q) => Some(q.raw()),
        _ => None,
    }
}

fn series(value: Parasitic) -> Option<f64> {
    match value {
        Parasitic::Resistance(q) => Some(q.raw()),
        Parasitic::Inductance(q) | Parasitic::MutualInductance(q) => Some(q.raw()),
        _ => None,
    }
}

/// Every net's total capacitance against [`TOTALS`]: grounding a coupling
/// moves it to ground on both of its nets, and lumping only adds.
fn holds_every_total(what: &str, network: &ParasiticNetwork) {
    let totals = network.capacitance_per_net();
    for (net, want) in TOTALS.into_iter().enumerate() {
        assert_close(&format!("{what}, net {net}"), totals[net], want, 1e-12);
    }
}

/// Oracle: law. `rcc` without a threshold is the whole network: the reduction
/// is the identity on a canonical one.
#[test]
fn rcc_keeps_the_whole_network() {
    assert_eq!(reduced(ExtractionKind::Rcc, 0.0), network());
}

/// Oracle: hand-derived (OpenRCX: "coupling below this threshold is
/// grounded", strictly below). At 0.125 fF the 0.05 fF coupling between
/// nodes 1 and 3 becomes 0.05 fF to ground on each, and the 0.125 fF one
/// stays; every total holds. Fails if the threshold is ignored, grounds at
/// or above it, or grounds on one end only.
#[test]
fn a_coupling_below_the_threshold_is_grounded_on_both_ends() {
    let out = reduced(ExtractionKind::Rcc, 0.125);
    assert_eq!(
        of_kind(&out, coupling),
        [(0, Some(2), 0.25), (1, Some(4), 0.75), (3, Some(4), 0.125)]
    );
    let grounds = of_kind(&out, ground);
    for node in [1, 3] {
        assert!(
            grounds.contains(&(node, None, 0.05)),
            "node {node}: {grounds:?}"
        );
    }
    assert_eq!(grounds.len(), 7, "five grounds and the grounded pair");
    assert_eq!(of_kind(&out, series), of_kind(&network(), series));
    holds_every_total("rcc at 0.125 fF", &out);
}

/// Oracle: hand-derived (Calibre's RC: resistance and capacitance to
/// ground). Every coupling is grounded at both ends, the totals hold, and
/// resistance and inductance stay.
#[test]
fn rc_grounds_every_coupling_and_keeps_the_series_elements() {
    let out = reduced(ExtractionKind::Rc, 0.0);
    assert_eq!(of_kind(&out, coupling), Vec::new());
    assert_eq!(of_kind(&out, ground).len(), 5 + 2 * 4);
    assert_eq!(of_kind(&out, series), of_kind(&network(), series));
    assert_eq!(out.node_net, network().node_net);
    holds_every_total("rc", &out);
}

/// Oracle: hand-derived (Calibre's R: parasitic resistance only). No
/// capacitance is left; resistance and inductance are.
#[test]
fn r_keeps_resistance_and_inductance_alone() {
    let out = reduced(ExtractionKind::R, 0.0);
    assert_eq!(of_kind(&out, ground), Vec::new());
    assert_eq!(of_kind(&out, coupling), Vec::new());
    assert_eq!(of_kind(&out, series), of_kind(&network(), series));
    assert!(out.capacitance_per_net().iter().all(|&c| c == 0.0));
}

/// Oracle: hand-derived (Calibre's C+CC, lumped). One node per net; each
/// net's grounds summed (3, 3.5 and 4 fF) and its couplings to each other
/// net summed (0.25 + 0.05 between nets 0 and 1, 0.75 and 0.125); no
/// resistance or inductance. Fails if nodes are not merged per net, or a
/// pair's two couplings stay apart.
#[test]
fn cc_lumps_each_net_and_sums_its_couplings_per_pair() {
    let out = reduced(ExtractionKind::Cc, 0.0);
    assert_eq!(out.node_net, [0, 1, 2].map(NetId));
    assert_eq!(
        of_kind(&out, ground),
        [(0, None, 3.0), (1, None, 3.5), (2, None, 4.0)]
    );
    let couplings = of_kind(&out, coupling);
    assert_eq!(couplings.len(), 3, "{couplings:?}");
    for ((from, to, got), (want_from, want_to, want)) in
        couplings
            .into_iter()
            .zip([(0, 1, 0.3), (0, 2, 0.75), (1, 2, 0.125)])
    {
        assert_eq!((from, to), (want_from, Some(want_to)));
        assert_close("a pair's coupling", got, want, 1e-12);
    }
    assert_eq!(of_kind(&out, series), Vec::new());
    holds_every_total("cc", &out);
}

/// Oracle: hand-derived (lumped C to ground). One node per net and one
/// element each, its total capacitance; a threshold changes nothing, since
/// no coupling is kept to compare with it.
#[test]
fn c_is_one_capacitance_to_ground_per_net() {
    for threshold in [0.0, 0.1] {
        let out = reduced(ExtractionKind::C, threshold);
        assert_eq!(out.node_net, [0, 1, 2].map(NetId));
        assert_eq!(out.element_count(), 3);
        for (net, (from, to, got)) in of_kind(&out, ground).into_iter().enumerate() {
            assert_eq!((from as usize, to), (net, None));
            assert_close("a lumped net", got, TOTALS[net], 1e-12);
        }
    }
}
