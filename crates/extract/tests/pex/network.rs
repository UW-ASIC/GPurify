//! The parasitic network table: canonical element order and per-net
//! capacitance summed in that order.

use crate::common;

use common::serialise;
use gpurify_check::topology::NetId;
use gpurify_extract::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_geom::LayerId;
use gpurify_geom::{prefix, Capacitance, Qty, Resistance};
use gpurify_testgen::{assert_bytes_identical, assert_close, assert_close_relative, Rng};

fn ohms(value: f64) -> Parasitic {
    Parasitic::Resistance(Qty::<Resistance, { prefix::BASE }>::new(value))
}

fn ground(value: f64) -> Parasitic {
    Parasitic::GroundCap(Qty::<Capacitance, { prefix::FEMTO }>::new(value))
}

fn coupling(value: f64) -> Parasitic {
    Parasitic::CouplingCap(Qty::<Capacitance, { prefix::FEMTO }>::new(value))
}

/// A network whose nodes all sit on `net`, one per index.
fn nodes_on(net: NetId, count: u32) -> ParasiticNetwork {
    let count = usize::try_from(count).expect("node counts here are small");
    ParasiticNetwork {
        node_net: vec![net; count],
        node_layer: vec![LayerId(0); count],
        ..ParasiticNetwork::default()
    }
}

/// A network whose nodes sit on the listed nets, one node per entry.
fn nodes_across(nets: &[NetId]) -> ParasiticNetwork {
    ParasiticNetwork {
        node_net: nets.to_vec(),
        node_layer: vec![LayerId(0); nets.len()],
        ..ParasiticNetwork::default()
    }
}

/// Oracle: construct-from-answer. Pushing `n` elements leaves `n` elements and
/// leaves the node columns alone — nodes and elements are separate columns and
/// a push that touched both would misreport every count downstream.
#[test]
fn pushing_elements_grows_the_element_columns_and_not_the_node_columns() {
    let mut network = nodes_on(NetId(4), 3);
    assert_eq!(network.node_count(), 3);
    assert_eq!(network.element_count(), 0);

    network.push(NodeId(0), Some(NodeId(1)), ohms(12.0));
    network.push(NodeId(1), None, ground(0.5));
    network.push(NodeId(1), Some(NodeId(2)), ohms(8.0));

    assert_eq!(network.element_count(), 3);
    assert_eq!(network.node_count(), 3, "a push does not create a node");
    assert_eq!(network.from.len(), 3);
    assert_eq!(network.to.len(), 3);
    assert_eq!(network.value.len(), 3);
    assert_eq!(network.to[1], None, "a ground capacitance has no far node");
}

/// Oracle: closed form. A net carrying 1.5 fF and 2.25 fF to ground and 0.75 fF
/// of coupling to a neighbour holds 4.5 fF, which is addition. Resistance is
/// not capacitance and must not appear in the sum, which is why a resistor
/// large enough to be obvious sits in the same network.
#[test]
fn net_capacitance_is_the_sum_of_the_capacitive_elements_on_that_net() {
    let mut network = nodes_across(&[NetId(0), NetId(0), NetId(1)]);
    network.push(NodeId(0), None, ground(1.5));
    network.push(NodeId(1), None, ground(2.25));
    network.push(NodeId(0), Some(NodeId(2)), coupling(0.75));
    network.push(NodeId(2), None, ground(10.0));
    network.push(NodeId(0), Some(NodeId(1)), ohms(1_000.0));

    assert_close(
        "net 0, two grounds and a coupling",
        network.net_capacitance(NetId(0)).raw(),
        4.5,
        1e-12,
    );
    assert_close(
        "net 1, its own ground and the same coupling",
        network.net_capacitance(NetId(1)).raw(),
        10.75,
        1e-12,
    );
    assert_close(
        "a net with no elements",
        network.net_capacitance(NetId(2)).raw(),
        0.0,
        1e-12,
    );
}

/// Oracle: law. Capacitance to ground is additive, so a network with every
/// element pushed twice holds twice the capacitance on every net. The values
/// are drawn from a seeded generator so the law is stated over arbitrary
/// numbers rather than over three the author chose.
#[test]
fn net_capacitance_is_additive_over_the_elements_pushed() {
    let mut rng = Rng::new(31);
    let mut once = nodes_on(NetId(0), 8);
    let mut twice = nodes_on(NetId(0), 8);
    for index in 0..8_u32 {
        let value = ground(0.1 + rng.unit());
        once.push(NodeId(index), None, value);
        twice.push(NodeId(index), None, value);
        twice.push(NodeId(index), None, value);
    }

    let single = once.net_capacitance(NetId(0)).raw();
    assert!(
        single > 0.0,
        "eight positive capacitances summed to {single}"
    );
    assert_close_relative(
        "every element pushed twice",
        twice.net_capacitance(NetId(0)).raw(),
        2.0 * single,
        1e-12,
    );
}

/// Oracle: law. Canonical order is a function of the rows, so any permutation
/// of the same rows sorts to the same bytes. This is the determinism gate for
/// element order: the old tree's parasitic rows swapped between runs because a
/// hash map decided which came first, and permutation invariance is exactly the
/// property that would have caught it.
#[test]
fn sort_canonical_maps_every_permutation_of_the_same_rows_to_the_same_bytes() {
    let mut rng = Rng::new(37);
    let mut rows: Vec<(NodeId, Option<NodeId>, Parasitic)> = Vec::new();
    for index in 0..6_u32 {
        rows.push((NodeId(index), None, ground(0.5 + rng.unit())));
        rows.push((
            NodeId(index),
            Some(NodeId(index + 1)),
            ohms(1.0 + rng.unit()),
        ));
        rows.push((NodeId(index), Some(NodeId(index + 1)), coupling(rng.unit())));
    }

    let mut reference = nodes_on(NetId(0), 8);
    for &(from, to, value) in &rows {
        reference.push(from, to, value);
    }
    reference.sort_canonical();
    let canonical = serialise(&reference);

    for round in 0..8 {
        let mut shuffled = rows.clone();
        rng.shuffle(&mut shuffled);
        let mut network = nodes_on(NetId(0), 8);
        for (from, to, value) in shuffled {
            network.push(from, to, value);
        }
        network.sort_canonical();
        assert_bytes_identical(
            &format!("permutation {round} sorted canonically"),
            &canonical,
            &serialise(&network),
        );
    }
}

/// Oracle: law. Sorting an already sorted table is the identity, and sorting
/// never invents, drops or alters a row — the element count and the total
/// capacitance are the same either side of it.
#[test]
fn sort_canonical_is_idempotent_and_preserves_every_row() {
    let mut rng = Rng::new(41);
    let mut network = nodes_on(NetId(0), 5);
    for index in 0..4_u32 {
        network.push(NodeId(index + 1), None, ground(rng.unit() + 0.25));
        network.push(
            NodeId(index),
            Some(NodeId(index + 1)),
            ohms(rng.unit() + 1.0),
        );
    }
    let elements = network.element_count();
    let capacitance = network.net_capacitance(NetId(0)).raw();

    network.sort_canonical();
    let once = serialise(&network);
    assert_eq!(network.element_count(), elements, "sorting dropped a row");
    assert_close_relative(
        "capacitance either side of a sort",
        network.net_capacitance(NetId(0)).raw(),
        capacitance,
        1e-12,
    );

    network.sort_canonical();
    assert_bytes_identical("a second sort", &once, &serialise(&network));
}

/// Oracle: law. The stated order is by `from`, then by `to` with `None` first.
/// Asserting the predicate directly is what stops the permutation test above
/// from being satisfied by any order at all, so long as it is stable.
#[test]
fn sort_canonical_orders_by_from_then_by_to_with_ground_first() {
    let mut network = nodes_on(NetId(0), 5);
    network.push(NodeId(3), Some(NodeId(4)), ohms(2.0));
    network.push(NodeId(1), None, ground(1.0));
    network.push(NodeId(3), None, ground(3.0));
    network.push(NodeId(0), Some(NodeId(2)), ohms(4.0));
    network.push(NodeId(1), Some(NodeId(2)), coupling(5.0));
    network.sort_canonical();

    let key = |index: usize| {
        (
            network.from[index].0,
            network.to[index].map_or(0, |node| node.0 + 1),
        )
    };
    for index in 1..network.element_count() {
        assert!(
            key(index - 1) <= key(index),
            "rows {} and {index} are out of canonical order: {:?} then {:?}",
            index - 1,
            key(index - 1),
            key(index)
        );
    }
}

/// Oracle: law. The one-pass per-net totals are the per-net sums bit for bit,
/// coupling counts on both nets, and a node past the column counts nowhere.
#[test]
fn capacitance_per_net_matches_net_capacitance_bit_for_bit() {
    let mut rng = Rng::new(97);
    let nets = [NetId(0), NetId(0), NetId(2), NetId(3), NetId(3)];
    let mut network = nodes_across(&nets);
    let node = |rng: &mut Rng| NodeId(u32::try_from(rng.below(5)).expect("small"));
    for _ in 0..64 {
        let (from, to) = (node(&mut rng), node(&mut rng));
        match rng.below(3) {
            0 => network.push(from, None, ground(rng.unit())),
            1 => network.push(from, Some(to), coupling(rng.unit())),
            _ => network.push(from, Some(to), ohms(rng.unit())),
        }
    }
    network.push(NodeId(9), None, ground(100.0));
    network.sort_canonical();

    let all = network.capacitance_per_net();
    assert_eq!(all.len(), 4, "indexed up to the highest net present");
    for net in 0..5_u32 {
        assert_eq!(
            all.get(net as usize).copied().unwrap_or(0.0).to_bits(),
            network.net_capacitance(NetId(net)).raw().to_bits(),
            "net {net}"
        );
    }
    assert_eq!(all[1].to_bits(), 0.0_f64.to_bits(), "net 1 has no node");
    assert!(
        all.iter().all(|&c| c < 100.0),
        "the dangling element counted"
    );
}
