//! The extraction type: which parasitics the written network keeps.
//!
//! Data in: an extracted [`ParasiticNetwork`] holding its node invariant
//! (every net's nodes one contiguous run, ascending), and the deck's
//! [`Extraction`]. Data out: the same network, reduced in place and sorted
//! canonically.
//!
//! The types are Calibre's (Siemens, "How to use Calibre parasitic
//! extraction tools", Calibre blog, 2026-02-17: "R", "C+CC", "RC", "RCC";
//! the Calibre xRC-CB datasheet: "lumped C"):
//!
//! | Deck | Keeps | Coupling |
//! |---|---|---|
//! | `rcc` | everything | kept |
//! | `rc` | R, L, ground C | grounded |
//! | `r` | R, L | dropped, with ground C |
//! | `cc` | one node per net: ground C | kept, summed per pair of nets |
//! | `c` | one node per net: ground C | grounded |
//!
//! A field-solved net's series and mutual inductance sit with its
//! resistance: kept wherever R is.
//!
//! To ground a coupling capacitance is to replace it by a capacitance to
//! ground of the same value at each of its two nodes, which is what `OpenRCX`
//! does with coupling below its threshold (`OpenROAD` `extract_parasitics
//! -coupling_threshold`: "Coupling below this threshold is grounded"; its
//! log: "coupling capacitance less than … fF will be grounded"). Every
//! net keeps its total capacitance; what is lost is the other net's
//! switching seen through it. A coupling below
//! [`Extraction::coupling_threshold_af`] is grounded so in `cc` and `rcc`.
//!
//! To lump a net is to merge all its nodes into one, its first: its
//! resistance and inductance drop out, its ground capacitances sum into one
//! element and its couplings to each other net into one.

use crate::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_geom::Qty;
use gpurify_ingest::deck::{Extraction, ExtractionKind};
use std::collections::BTreeMap;

/// Reduces `network` in place to `extraction`'s type, then sorts it
/// canonically. `rcc` with no threshold changes nothing but the order.
///
/// Every net keeps its total capacitance
/// ([`ParasiticNetwork::capacitance_per_net`]), to round-off, except under
/// `r`, which drops it; `r`, `rc` and `rcc` keep every resistance and
/// inductance, and `c` and `cc` none. Each net keeps its nodes, but under
/// `c` and `cc` one per net, so every [`NodeId`] read before the call is
/// stale after it.
///
/// # Time complexity
///
/// *O*(e log e) for e elements: one pass, then the canonical sort.
pub fn reduce(network: &mut ParasiticNetwork, extraction: Extraction) {
    let kind = extraction.kind;
    let keeps_resistance = matches!(
        kind,
        ExtractionKind::R | ExtractionKind::Rc | ExtractionKind::Rcc
    );
    let keeps_capacitance = kind != ExtractionKind::R;
    // A coupling below this is grounded: every one where none is kept, and
    // none (not even a field solve's slightly negative one) without a
    // positive threshold.
    let threshold = match (kind.keeps_coupling(), extraction.coupling_threshold_af) {
        (false, _) => f64::INFINITY,
        (true, attofarads) if attofarads > 0.0 => attofarads / 1e3,
        (true, _) => f64::NEG_INFINITY,
    };

    let from = std::mem::take(&mut network.from);
    let to = std::mem::take(&mut network.to);
    let value = std::mem::take(&mut network.value);
    for ((near, far), element) in from.into_iter().zip(to).zip(value) {
        match element {
            Parasitic::Resistance(_)
            | Parasitic::Inductance(_)
            | Parasitic::MutualInductance(_) => {
                if keeps_resistance {
                    network.push(near, far, element);
                }
            }
            Parasitic::GroundCap(_) => {
                if keeps_capacitance {
                    network.push(near, far, element);
                }
            }
            Parasitic::CouplingCap(q) => {
                if !keeps_capacitance {
                    continue;
                }
                if q.raw() < threshold {
                    network.push(near, None, Parasitic::GroundCap(q));
                    if let Some(far) = far {
                        network.push(far, None, Parasitic::GroundCap(q));
                    }
                } else {
                    network.push(near, far, element);
                }
            }
        }
    }
    if matches!(kind, ExtractionKind::C | ExtractionKind::Cc) {
        lump(network);
    }
    network.sort_canonical();
}

/// Merges every net's nodes into one, the first of its run; sums its
/// ground capacitances into one element and its couplings to each other
/// net into one. Only capacitances are left by then. A coupling between two
/// nodes of one net, shorted by the merge, drops out.
fn lump(network: &mut ParasiticNetwork) {
    let mut node_net = Vec::new();
    let mut node_layer = Vec::new();
    let mut merged = Vec::with_capacity(network.node_count());
    for (row, &net) in network.node_net.iter().enumerate() {
        if node_net.last() != Some(&net) {
            node_net.push(net);
            node_layer.push(network.node_layer[row]);
        }
        merged.push(node(node_net.len() - 1));
    }
    // Summed in element order, a strict fold, keyed by (near, far or ground).
    let mut ground: BTreeMap<NodeId, f64> = BTreeMap::new();
    let mut coupling: BTreeMap<(NodeId, NodeId), f64> = BTreeMap::new();
    for row in 0..network.element_count() {
        let near = merged[network.from[row].0 as usize];
        match (network.value[row], network.to[row]) {
            (Parasitic::GroundCap(q), _) => *ground.entry(near).or_insert(0.0) += q.raw(),
            (Parasitic::CouplingCap(q), Some(far)) => {
                let far = merged[far.0 as usize];
                if far != near {
                    *coupling
                        .entry((near.min(far), near.max(far)))
                        .or_insert(0.0) += q.raw();
                }
            }
            _ => {}
        }
    }
    network.clear();
    network.node_net = node_net;
    network.node_layer = node_layer;
    for (near, femtofarads) in ground {
        network.push(near, None, Parasitic::GroundCap(Qty::new(femtofarads)));
    }
    for ((near, far), femtofarads) in coupling {
        network.push(
            near,
            Some(far),
            Parasitic::CouplingCap(Qty::new(femtofarads)),
        );
    }
}

fn node(index: usize) -> NodeId {
    NodeId(u32::try_from(index).expect("a node index is a u32"))
}
