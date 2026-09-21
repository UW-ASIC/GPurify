//! SPEF and DSPF: the two writers with history.
//!
//! The old implementation's interlayer-capacitance rows carried their layer
//! pair in whichever order a hash map yielded, so eight of twenty-seven
//! parasitic outputs differed between runs of the same binary. The magnitudes
//! were right and the file was still unusable, because it could not be diffed.
//!
//! Reproducibility is checked in `determinism.rs`. What this file checks is the
//! other half: that the values and names handed in come back out, and that the
//! one case where a name is unavailable is refused rather than papered over
//! with a placeholder — a placeholder being, precisely, a name that changes
//! between runs.

mod fixture;

use fixture::{World, COUPLING_FF, GROUND_CAP_FF, SERIES_OHM};
use gpurify_export::json::format_f64;
use gpurify_export::parasitic::{node_name, write_dspf, write_spef};
use gpurify_export::WriteError;
use gpurify_extract::network::NodeId;

fn spef(world: &World) -> String {
    let mut out = String::new();
    write_spef(
        &world.parasitics,
        &world.ports,
        &world.strings,
        &world.header,
        &mut out,
    )
    .expect("every net in this world is named");
    out
}

fn dspf(world: &World) -> String {
    let mut out = String::new();
    write_dspf(
        &world.parasitics,
        &world.ports,
        &world.strings,
        &world.header,
        &mut out,
    )
    .expect("every net in this world is named");
    out
}

fn name_of(world: &World, node: NodeId) -> String {
    let mut out = String::new();
    node_name(
        &world.parasitics,
        node,
        &world.ports,
        &world.strings,
        &mut out,
    )
    .expect("every net in this world is named");
    out
}

fn formatted(value: f64) -> String {
    let mut out = String::new();
    format_f64(value, &mut out);
    out
}

/// Oracle: construct-from-answer. The fixture states three element values
/// before either writer runs, and every float in this crate becomes text
/// through one function — so the text that function produces for each value is
/// the text both files must contain. A writer that rounded a capacitance to its
/// own taste, or dropped an element, fails here.
#[test]
fn both_formats_carry_every_element_value_they_were_given() {
    let world = World::named();
    for (what, text) in [("SPEF", spef(&world)), ("DSPF", dspf(&world))] {
        for (element, value) in [
            ("the ground capacitance", GROUND_CAP_FF),
            ("the series resistance", SERIES_OHM),
            ("the coupling capacitance", COUPLING_FF),
        ] {
            let expected = formatted(value);
            assert!(
                text.contains(&expected),
                "{what} is missing {element}, {value}, which formats as {expected:?}:\n{text}"
            );
        }
    }
}

/// Oracle: construct-from-answer. Names are emitted through the port table, and
/// the port table was built from labels this test placed on known polygons.
#[test]
fn both_formats_name_the_nets_the_labels_named() {
    let world = World::named();
    for (what, text) in [("SPEF", spef(&world)), ("DSPF", dspf(&world))] {
        for name in ["VDD", "VSS"] {
            assert!(
                text.contains(name),
                "{what} does not name net {name}:\n{text}"
            );
        }
    }
}

/// Oracle: construct-from-answer. **The rule this file exists for.** An
/// anonymous net is an error, not a generated placeholder, because a
/// placeholder is a name that changes between runs — which is the determinism
/// defect wearing the costume of a feature. The error names the net by number,
/// so the reported id is asserted, not merely the variant.
#[test]
fn spef_refuses_an_anonymous_net_by_name_rather_than_inventing_one() {
    let world = World::half_named();
    let mut out = String::new();
    let result = write_spef(
        &world.parasitics,
        &world.ports,
        &world.strings,
        &world.header,
        &mut out,
    );
    match result {
        Err(WriteError::UnnamedNet(net)) => assert_eq!(
            net, world.upper_net.0,
            "the refusal names the wrong net; the anonymous one is {:?}",
            world.upper_net
        ),
        other => panic!("SPEF accepted an anonymous net and wrote {out:?}: {other:?}"),
    }
}

/// Oracle: construct-from-answer. Same rule, same reason, other format.
#[test]
fn dspf_refuses_an_anonymous_net_by_name_rather_than_inventing_one() {
    let world = World::half_named();
    let mut out = String::new();
    let result = write_dspf(
        &world.parasitics,
        &world.ports,
        &world.strings,
        &world.header,
        &mut out,
    );
    match result {
        Err(WriteError::UnnamedNet(net)) => assert_eq!(
            net, world.upper_net.0,
            "the refusal names the wrong net; the anonymous one is {:?}",
            world.upper_net
        ),
        other => panic!("DSPF accepted an anonymous net and wrote {out:?}: {other:?}"),
    }
}

/// Oracle: construct-from-answer. `node_name` shares the refusal, since it is
/// the function both writers reach it through. A node on an anonymous net has
/// no name, and saying so is the whole contract.
#[test]
fn a_node_on_an_anonymous_net_has_no_name() {
    let world = World::half_named();
    // Node 2 is the one the fixture placed on the upper net, which this world
    // deliberately left unlabelled.
    let mut out = String::new();
    let result = node_name(
        &world.parasitics,
        NodeId(2),
        &world.ports,
        &world.strings,
        &mut out,
    );
    match result {
        Err(WriteError::UnnamedNet(net)) => assert_eq!(net, world.upper_net.0),
        other => panic!("a node on an anonymous net was named {out:?}: {other:?}"),
    }
}

/// Oracle: law. Two nodes must not share a name. A simulator reading a file
/// that named two nodes alike would short them, and a shorted parasitic network
/// still solves — it just solves the wrong circuit.
#[test]
fn two_nodes_never_share_a_name() {
    let world = World::named();
    let names: Vec<String> = (0..3).map(|n| name_of(&world, NodeId(n))).collect();
    for name in &names {
        assert!(!name.is_empty(), "a node has no name: {names:?}");
    }
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        names.len(),
        "two of {names:?} are the same node name"
    );
}

/// Oracle: construct-from-answer. Nodes 0 and 1 are on the lower net and node 2
/// on the upper one, decided by the fixture before any writer ran. Sub-node
/// names are derived from the node's index within its net, so a node's name has
/// to place it on the right net — a name that did not would put a parasitic on
/// the wrong wire.
#[test]
fn a_node_is_named_on_the_net_it_belongs_to() {
    let world = World::named();
    for (node, expected) in [(NodeId(0), "VDD"), (NodeId(1), "VDD"), (NodeId(2), "VSS")] {
        let name = name_of(&world, node);
        assert!(
            name.contains(expected),
            "{node:?} is on the net labelled {expected} but is called {name:?}"
        );
    }
}

/// Oracle: determinism. `node_name` is a decision — pure, and shared by both
/// writers so the two formats agree about what a node is called. Calling it
/// twice is the cheapest statement of that.
#[test]
fn node_name_is_a_function_of_its_arguments_alone() {
    let world = World::named();
    for n in 0..3 {
        let first = name_of(&world, NodeId(n));
        assert_eq!(
            first,
            name_of(&world, NodeId(n)),
            "node {n} was named twice"
        );
    }
}

/// Oracle: construct-from-answer. Both files carry the run's header, and it is
/// the only place a timestamp may appear — so handing one in puts it there and
/// handing in `None` leaves it out, rather than substituting the clock.
#[test]
fn both_formats_carry_their_header_and_only_their_header() {
    let mut stamped = World::named();
    stamped.header = fixture::header(Some("2020-01-01T00:00:00Z"));
    let mut bare = World::named();
    bare.header = fixture::header(None);

    for (what, with_stamp, without) in [
        ("SPEF", spef(&stamped), spef(&bare)),
        ("DSPF", dspf(&stamped), dspf(&bare)),
    ] {
        assert!(
            with_stamp.contains("2020-01-01T00:00:00Z"),
            "{what} dropped the timestamp it was handed:\n{with_stamp}"
        );
        assert!(
            !without.contains("2020-01-01T00:00:00Z"),
            "{what} carries a timestamp nobody handed it:\n{without}"
        );
    }
}

/// Oracle: law. The two formats describe one network, so neither may be a
/// subset of the other by accident: SPEF and DSPF are different files. This is
/// the cheap guard against a writer that was implemented by delegating to the
/// other one and forgetting to change anything.
#[test]
fn spef_and_dspf_are_two_different_files() {
    let world = World::named();
    assert_ne!(
        spef(&world),
        dspf(&world),
        "the two parasitic writers produced the same bytes"
    );
}
