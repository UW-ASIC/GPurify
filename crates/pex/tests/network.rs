//! The parasitic network table, and the reduction that has to preserve it.
//!
//! Both modules state their own oracle. `network` claims a canonical element
//! order and a capacitance summed in that order; `reduce` claims total
//! capacitance and driving-point resistance are invariant, that series
//! resistance adds and that parallel conductance adds. All of those are laws or
//! closed forms, and none of them needs a reference implementation.

mod common;

use common::{capacitance_ff, resistance_ohm, serialise};
use gpurify_geom::LayerId;
use gpurify_pex::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_pex::reduce::{
    collapse_series_into, merge_parallel_into, reduce_into, total_capacitance, Order,
};
use gpurify_testgen::{assert_bytes_identical, assert_close, assert_close_relative, Rng};
use gpurify_topology::NetId;
use gpurify_geom::{prefix, Capacitance, Qty, Resistance};

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

/// A chain `0 -R- 1 -R- 2 ... -R- n`, every resistor `each` ohms.
///
/// Nothing but resistance: `collapse_series_into` refuses to remove a node that
/// carries capacitance, so a chain meant to collapse must not have any.
fn series_chain(stages: u32, each: f64) -> ParasiticNetwork {
    let mut network = nodes_on(NetId(0), stages + 1);
    for stage in 0..stages {
        network.push(NodeId(stage), Some(NodeId(stage + 1)), ohms(each));
    }
    network
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

/// Oracle: closed form. Total capacitance is the sum of every capacitive
/// element, counted once each whichever net it belongs to, and resistance is
/// not part of it.
#[test]
fn total_capacitance_counts_every_capacitive_element_exactly_once() {
    let mut network = nodes_across(&[NetId(0), NetId(1)]);
    network.push(NodeId(0), None, ground(2.0));
    network.push(NodeId(1), None, ground(3.0));
    network.push(NodeId(0), Some(NodeId(1)), coupling(0.5));
    network.push(NodeId(0), Some(NodeId(1)), ohms(75.0));

    assert_close(
        "two grounds and one coupling",
        total_capacitance(&network).raw(),
        5.5,
        1e-12,
    );
    assert_close(
        "an empty network",
        total_capacitance(&ParasiticNetwork::default()).raw(),
        0.0,
        1e-12,
    );
}

/// Oracle: law. `Order::Full` keeps every node, so reduction is the identity
/// and the reduced network is the unreduced one byte for byte. Every other
/// invariant test starts here, and if this one is wrong none of them mean
/// anything.
#[test]
fn reducing_to_full_order_is_the_identity_on_the_network() {
    let mut network = nodes_on(NetId(0), 5);
    let mut rng = Rng::new(43);
    for index in 0..4_u32 {
        network.push(
            NodeId(index),
            Some(NodeId(index + 1)),
            ohms(1.0 + rng.unit()),
        );
        network.push(NodeId(index + 1), None, ground(rng.unit() + 0.1));
    }
    network.sort_canonical();
    let before = serialise(&network);

    let mut out = ParasiticNetwork::default();
    reduce_into(&network, &[NodeId(0), NodeId(4)], Order::Full, &mut out);
    assert_bytes_identical("a full-order reduction", &before, &serialise(&out));
}

/// Oracle: law. Reduction preserves behaviour at the terminals, and total
/// capacitance is half of what that means. It holds at every order, so it is
/// asserted at all three — including `Full`, where it is the identity and would
/// be the first thing to break if reduction wrote into the wrong column.
#[test]
fn reduction_preserves_total_capacitance_at_every_order() {
    let mut rng = Rng::new(47);
    let mut network = nodes_on(NetId(0), 7);
    for index in 0..6_u32 {
        network.push(
            NodeId(index),
            Some(NodeId(index + 1)),
            ohms(2.0 + 4.0 * rng.unit()),
        );
        network.push(NodeId(index + 1), None, ground(0.2 + rng.unit()));
    }
    let before = total_capacitance(&network).raw();
    assert!(before > 0.0, "six capacitors summed to {before} fF");

    let terminals = [NodeId(0), NodeId(6)];
    for order in [Order::Full, Order::Reduced, Order::Lumped] {
        let mut out = ParasiticNetwork::default();
        reduce_into(&network, &terminals, order, &mut out);
        assert_close_relative(
            "total capacitance across a reduction",
            total_capacitance(&out).raw(),
            before,
            1e-9,
        );
    }
}

/// Oracle: closed form. Series resistance adds. A three ohm resistor and a
/// seven ohm resistor sharing an interior node that carries nothing else
/// collapse to one resistor of ten ohms, and that is the whole rule.
#[test]
fn two_resistors_sharing_a_bare_node_collapse_to_their_sum() {
    let mut network = nodes_on(NetId(0), 3);
    network.push(NodeId(0), Some(NodeId(1)), ohms(3.0));
    network.push(NodeId(1), Some(NodeId(2)), ohms(7.0));

    let mut out = ParasiticNetwork::default();
    collapse_series_into(&network, &mut out);
    assert_eq!(
        out.element_count(),
        1,
        "a two-resistor chain collapses to one resistor"
    );
    assert_close(
        "three ohms then seven",
        resistance_ohm(out.value[0]).expect("the surviving element is a resistor"),
        10.0,
        1e-12,
    );
    assert_ne!(
        out.from[0],
        out.to[0].expect("a resistor has two nodes"),
        "the collapsed resistor must still span two distinct nodes"
    );
}

/// Oracle: closed form. Series resistance adds over any chain length, so a
/// chain of eight identical resistors is one resistor of eight times the value,
/// spanning the two ends of the chain. The single-pair case above would pass
/// against an implementation that collapsed once and stopped, and a value
/// asserted without its endpoints would pass against one that collapsed the
/// chain onto the wrong pair of nodes.
#[test]
fn a_whole_chain_of_resistors_collapses_to_the_sum_of_the_chain() {
    let network = series_chain(8, 1.25);
    let mut out = ParasiticNetwork::default();
    collapse_series_into(&network, &mut out);

    assert_eq!(out.element_count(), 1, "the whole chain collapses");
    assert_close(
        "eight resistors of 1.25 ohms",
        resistance_ohm(out.value[0]).expect("the surviving element is a resistor"),
        10.0,
        1e-12,
    );
    assert_eq!(
        (out.from[0], out.to[0]),
        (NodeId(0), Some(NodeId(8))),
        "the collapsed resistor spans the two ends of the chain"
    );
}

/// Oracle: law. A node carrying capacitance is electrically observable, so
/// removing it changes the network's behaviour and the collapse must refuse.
/// Same chain as above with one capacitor on the interior node: nothing moves.
#[test]
fn a_node_carrying_capacitance_is_never_collapsed_away() {
    let mut network = nodes_on(NetId(0), 3);
    network.push(NodeId(0), Some(NodeId(1)), ohms(3.0));
    network.push(NodeId(1), Some(NodeId(2)), ohms(7.0));
    network.push(NodeId(1), None, ground(0.4));

    let mut out = ParasiticNetwork::default();
    collapse_series_into(&network, &mut out);
    assert_eq!(
        out.element_count(),
        3,
        "the interior node carries charge, so nothing may be collapsed"
    );

    let mut resistances: Vec<f64> = out
        .value
        .iter()
        .filter_map(|&v| resistance_ohm(v))
        .collect();
    resistances.sort_by(f64::total_cmp);
    assert_close("the lower resistor", resistances[0], 3.0, 1e-12);
    assert_close("the upper resistor", resistances[1], 7.0, 1e-12);
    assert_close(
        "the capacitance that blocked the collapse",
        total_capacitance(&out).raw(),
        0.4,
        1e-12,
    );
}

/// Oracle: closed form. Conductances add in parallel, so three ohms beside six
/// ohms is two ohms: `1/3 + 1/6 = 1/2`. The two values are deliberately unequal
/// — an implementation that averaged rather than summed conductance would give
/// four and a half and pass any test built from two identical resistors.
#[test]
fn resistors_between_the_same_pair_merge_by_adding_their_conductances() {
    let mut network = nodes_on(NetId(0), 2);
    network.push(NodeId(0), Some(NodeId(1)), ohms(3.0));
    network.push(NodeId(0), Some(NodeId(1)), ohms(6.0));

    let mut out = ParasiticNetwork::default();
    merge_parallel_into(&network, &mut out);
    assert_eq!(out.element_count(), 1, "one pair, one merged resistor");
    assert_close(
        "three ohms beside six",
        resistance_ohm(out.value[0]).expect("the merged element is a resistor"),
        2.0,
        1e-12,
    );
    assert_eq!(
        (out.from[0], out.to[0]),
        (NodeId(0), Some(NodeId(1))),
        "the merged resistor stands between the pair it was merged from"
    );
}

/// Oracle: law. Conductances add over any number of resistors, so `n` copies of
/// `R` between one pair merge to `R / n`. Stated over a range because two
/// resistors is the case an off-by-one in the merge loop still gets right.
#[test]
fn n_equal_resistors_in_parallel_merge_to_one_nth_of_the_value() {
    for count in 1_u32..=12 {
        let mut network = nodes_on(NetId(0), 2);
        for _ in 0..count {
            network.push(NodeId(0), Some(NodeId(1)), ohms(9.0));
        }
        let mut out = ParasiticNetwork::default();
        merge_parallel_into(&network, &mut out);

        assert_eq!(out.element_count(), 1, "{count} resistors between one pair");
        assert_close_relative(
            "n resistors of nine ohms in parallel",
            resistance_ohm(out.value[0]).expect("the merged element is a resistor"),
            9.0 / f64::from(count),
            1e-12,
        );
        assert_eq!(
            (out.from[0], out.to[0]),
            (NodeId(0), Some(NodeId(1))),
            "{count} merged resistors still stand between the same pair"
        );
    }
}

/// Oracle: law. Merging a network that has no parallel pair leaves it alone,
/// and merging twice is the same as merging once. Both are what "idempotent"
/// means for a reduction, and the second is what stops a merge from feeding on
/// its own output.
#[test]
fn merging_parallel_resistors_is_idempotent() {
    let network = series_chain(5, 2.5);
    let mut once = ParasiticNetwork::default();
    merge_parallel_into(&network, &mut once);
    once.sort_canonical();
    assert_eq!(
        once.element_count(),
        5,
        "a chain has no two resistors between one pair"
    );
    let first = serialise(&once);

    let mut twice = ParasiticNetwork::default();
    merge_parallel_into(&once, &mut twice);
    twice.sort_canonical();
    assert_bytes_identical("a second merge", &first, &serialise(&twice));
}

/// Oracle: closed form. Driving-point resistance between the terminals is the
/// other half of what reduction preserves. On a plain chain that number is the
/// sum of the chain, so reducing a twelve-stage chain of quarter-ohm resistors
/// between its two ends must give three ohms — and, there being no branch point
/// between them, exactly one element, standing between the two nodes that were
/// asked for. Terminals are what a simulator sees, so a resistance of the right
/// size between the wrong pair is not a near miss.
#[test]
fn reducing_a_chain_between_its_ends_preserves_its_driving_point_resistance() {
    let network = series_chain(12, 0.25);
    let terminals = [NodeId(0), NodeId(12)];
    let mut out = ParasiticNetwork::default();
    reduce_into(&network, &terminals, Order::Reduced, &mut out);

    assert_eq!(
        out.element_count(),
        1,
        "a chain with no branch point reduces to one resistor"
    );
    assert_close(
        "twelve quarter-ohm resistors end to end",
        resistance_ohm(out.value[0]).expect("the surviving element is a resistor"),
        3.0,
        1e-12,
    );

    // The surviving resistor spans the two terminals, whichever way round the
    // canonical order puts them.
    let mut spanned = [out.from[0], out.to[0].expect("a resistor has two nodes")];
    spanned.sort_unstable();
    assert_eq!(
        spanned, terminals,
        "the reduced resistor stands between {terminals:?}, which is what a \
         simulator will connect to"
    );
}

/// Oracle: determinism. Reduction is run on the output path, so it is under the
/// byte gate too: the same network reduced twice, and reduced again into a
/// buffer that already holds a result, must give the same bytes.
#[test]
fn reduction_is_byte_identical_across_runs_and_across_a_reused_buffer() {
    let mut rng = Rng::new(53);
    let mut network = nodes_on(NetId(0), 9);
    for index in 0..8_u32 {
        network.push(
            NodeId(index),
            Some(NodeId(index + 1)),
            ohms(0.5 + rng.unit()),
        );
        network.push(NodeId(index + 1), None, ground(0.05 + rng.unit()));
    }
    // A genuine multi-edge, so the merge has something to do.
    network.push(NodeId(2), Some(NodeId(3)), ohms(4.0));
    network.sort_canonical();

    let terminals = [NodeId(0), NodeId(8)];
    let mut first = ParasiticNetwork::default();
    reduce_into(&network, &terminals, Order::Reduced, &mut first);
    let bytes = serialise(&first);

    let mut second = ParasiticNetwork::default();
    reduce_into(&network, &terminals, Order::Reduced, &mut second);
    assert_bytes_identical("two reductions", &bytes, &serialise(&second));

    reduce_into(&network, &terminals, Order::Reduced, &mut second);
    assert_bytes_identical(
        "a reduction into a reused buffer",
        &bytes,
        &serialise(&second),
    );
}

/// Oracle: law. Nothing a reduction emits may be a non-finite or negative
/// value: a negative parasitic capacitance is not a small error, it is an
/// unstable simulation, and it is the shape a lost sign takes after a Kron
/// elimination.
#[test]
fn no_reduction_emits_a_negative_or_non_finite_value() {
    let mut rng = Rng::new(59);
    let mut network = nodes_on(NetId(0), 10);
    for index in 0..9_u32 {
        network.push(
            NodeId(index),
            Some(NodeId(index + 1)),
            ohms(0.1 + 3.0 * rng.unit()),
        );
        network.push(NodeId(index), None, ground(0.01 + rng.unit()));
    }

    for order in [Order::Full, Order::Reduced, Order::Lumped] {
        let mut out = ParasiticNetwork::default();
        reduce_into(&network, &[NodeId(0), NodeId(9)], order, &mut out);
        for (index, &value) in out.value.iter().enumerate() {
            let number = resistance_ohm(value)
                .or_else(|| capacitance_ff(value))
                .expect("a reduction emits only resistance and capacitance here");
            assert!(
                number.is_finite() && number > 0.0,
                "element {index} of a {order:?} reduction is {number}"
            );
        }
    }
}
