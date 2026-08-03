//! SPICE export: the extracted circuit, and the naming every other writer
//! shares with it.
//!
//! The fixture states a netlist — two transistors, two models, two nets — and
//! this file asks whether the writer reproduced it. It also pins the two claims
//! the module makes about itself in prose: that the parasitic *source* and the
//! parasitic *decision* are separate parameters, and that `net_name` is where a
//! net gets the one name it carries across every file a run produces.

mod fixture;

use fixture::World;
use gpurify_export::netlist::{net_name, write_spice, Detail};
use gpurify_export::{parasitic, WriteError};
use gpurify_testgen::dbu;
use gpurify_topology::device::{DeviceMeasure, DeviceParam};
use gpurify_topology::NetId;

fn spice(world: &World, parasitics: Option<&gpurify_pex::ParasiticNetwork>, detail: Detail) -> String {
    let mut out = String::new();
    write_spice(
        world.extraction(),
        parasitics,
        detail,
        &world.strings,
        &world.header,
        &mut out,
    )
    .expect("the netlist is writable");
    out
}

fn name_of(world: &World, net: NetId) -> String {
    let mut out = String::new();
    net_name(net, &world.ports, &world.strings, &mut out);
    out
}

/// Oracle: law, stated by the module's own doc comment. "The parameter is the
/// source, the mode is the decision, and they are separate so neither implies
/// the other." Handing over a network and asking for a schematic must therefore
/// produce exactly the schematic — byte for byte, not merely a file with the
/// same devices in it.
#[test]
fn a_parasitic_network_does_not_change_a_schematic_netlist() {
    let world = World::named();
    assert_eq!(
        spice(&world, Some(&world.parasitics), Detail::Schematic),
        spice(&world, None, Detail::Schematic),
        "passing a parasitic network changed the schematic, so the mode is not the decision"
    );
}

/// Oracle: construct-from-answer. The converse of the test above: asking for
/// parasitics with a network that has three elements in it must produce
/// something the schematic does not, or the mode is decorative.
#[test]
fn asking_for_parasitics_adds_them_to_the_netlist() {
    let world = World::named();
    let schematic = spice(&world, None, Detail::Schematic);
    let with_parasitics = spice(&world, Some(&world.parasitics), Detail::WithParasitics);

    assert_ne!(
        schematic, with_parasitics,
        "WithParasitics produced the schematic, so the parasitics were dropped"
    );
    assert!(
        with_parasitics.len() > schematic.len(),
        "the parasitic netlist is no longer than the schematic, so nothing was spliced in"
    );
}

/// Oracle: construct-from-answer. The fixture states two devices with two
/// distinct models before anything runs; a netlist a simulator can consume has
/// to name both, or one device silently becomes the other.
#[test]
fn the_netlist_names_every_device_model_it_was_given() {
    let world = World::named();
    let text = spice(&world, None, Detail::Schematic);
    for model in ["nfet_01v8", "pfet_01v8"] {
        assert!(
            text.contains(model),
            "the netlist does not name model {model}:\n{text}"
        );
    }
}

/// Oracle: construct-from-answer. A device is its model, its size and its
/// wiring, and the tests above cover only the first: a writer that emitted two
/// named transistors with no dimensions and no terminals would pass every one
/// of them, and the file would still be valid SPICE that simulates nothing.
///
/// What the sizes print as cannot be named here — `write_spice` takes no
/// `Grid`, so whether a `Dbu` width becomes a database unit or a micrometre is
/// the Implementation-Phase's to decide. What is derivable without that choice
/// is that both fields reach the file: change one and the file changes, and a
/// writer that dropped either produces the same bytes from both worlds.
#[test]
fn a_device_width_and_a_terminal_net_both_reach_the_netlist() {
    let world = World::named();
    let baseline = spice(&world, None, Detail::Schematic);

    let mut widened = World::named();
    widened.devices.param[0] = (DeviceParam::Width, DeviceMeasure::Length(dbu(900)));
    assert_ne!(
        baseline,
        spice(&widened, None, Detail::Schematic),
        "widening a device from 500 to 900 units changed nothing, so the netlist has no sizes"
    );

    // The gate of the first device, moved from the lower net to the upper one.
    let mut rewired = World::named();
    rewired.devices.terminal_net[0] = rewired.upper_net;
    assert_ne!(
        baseline,
        spice(&rewired, None, Detail::Schematic),
        "moving a gate to the other net changed nothing, so the netlist has no connectivity"
    );
}

/// Oracle: construct-from-answer. Both nets are named by labels the fixture
/// placed on known polygons, and every terminal in the device table sits on one
/// of them — so both names have to appear, and they have to be the names
/// `net_name` gives.
#[test]
fn the_netlist_names_its_nets_the_way_net_name_does() {
    let world = World::named();
    let text = spice(&world, None, Detail::Schematic);

    for net in [world.lower_net, world.upper_net] {
        let name = name_of(&world, net);
        assert!(
            text.contains(&name),
            "net {net:?} is called {name:?} by net_name but that does not appear:\n{text}"
        );
    }
    assert!(
        text.contains("VDD") && text.contains("VSS"),
        "the labelled net names are absent, so the netlist is anonymous:\n{text}"
    );
}

/// Oracle: construct-from-answer. A label placed on a polygon is that net's
/// name, so `net_name` has to return it. Anything else means an LVS run is
/// confidently wrong about which net is which.
#[test]
fn a_labelled_net_is_named_by_its_label() {
    let world = World::named();
    assert!(
        name_of(&world, world.lower_net).contains("VDD"),
        "the net labelled VDD is called {:?}",
        name_of(&world, world.lower_net)
    );
    assert!(
        name_of(&world, world.upper_net).contains("VSS"),
        "the net labelled VSS is called {:?}",
        name_of(&world, world.upper_net)
    );
}

/// Oracle: law. Two nets must not share a name. A netlist that gave them one
/// would short them, and the short would be invisible: the file is still valid
/// SPICE and still simulates, just not the circuit that was laid out.
///
/// The anonymous half of the world exercises the fallback naming, which is
/// where a collision is most likely — a `NetId` has to survive into the name.
#[test]
fn two_nets_never_share_a_name() {
    for world in [World::named(), World::half_named()] {
        let lower = name_of(&world, world.lower_net);
        let upper = name_of(&world, world.upper_net);
        assert!(!lower.is_empty() && !upper.is_empty(), "a net has no name");
        assert_ne!(
            lower, upper,
            "nets {:?} and {:?} share the name {lower:?}",
            world.lower_net, world.upper_net
        );
    }
}

/// Oracle: determinism. `net_name` is a decision — pure, small data in, one
/// value out — so it depends on its arguments and on nothing else, including
/// how many times it has been called.
#[test]
fn net_name_is_a_function_of_its_arguments_alone() {
    let world = World::named();
    for net in [world.lower_net, world.upper_net] {
        let first = name_of(&world, net);
        assert_eq!(first, name_of(&world, net), "net {net:?} was named twice");
    }
}

/// Oracle: law, and the reason `net_name` is shared rather than duplicated. A
/// net carries one name across every file a run produces; two tools handed the
/// SPICE and the DSPF of the same run have to agree about which net is which.
#[test]
fn a_net_is_called_the_same_thing_in_the_netlist_and_in_the_dspf() {
    let world = World::named();
    let spice_text = spice(&world, Some(&world.parasitics), Detail::WithParasitics);

    let mut dspf = String::new();
    parasitic::write_dspf(
        &world.parasitics,
        &world.ports,
        &world.strings,
        &world.header,
        &mut dspf,
    )
    .expect("every net in this world is named");

    for net in [world.lower_net, world.upper_net] {
        let name = name_of(&world, net);
        assert!(
            spice_text.contains(&name),
            "the netlist does not call net {net:?} {name:?}:\n{spice_text}"
        );
        assert!(
            dspf.contains(&name),
            "the DSPF does not call net {net:?} {name:?}:\n{dspf}"
        );
    }
}

/// Oracle: construct-from-answer. The header is written to the netlist too, and
/// it is the only place a run's metadata is allowed to be — so it is there, and
/// removing the timestamp removes it rather than substituting the clock.
#[test]
fn the_netlist_carries_its_header_and_only_its_header() {
    let mut stamped = World::named();
    stamped.header = fixture::header(Some("2020-01-01T00:00:00Z"));
    let mut bare = World::named();
    bare.header = fixture::header(None);

    let with_stamp = spice(&stamped, None, Detail::Schematic);
    let without = spice(&bare, None, Detail::Schematic);

    assert!(
        with_stamp.contains("2020-01-01T00:00:00Z"),
        "the timestamp handed in is not in the netlist:\n{with_stamp}"
    );
    assert!(
        !without.contains("2020-01-01T00:00:00Z"),
        "a netlist with no timestamp carries one anyway:\n{without}"
    );
}

/// Oracle: construct-from-answer. `WriteError` is the narrow set of things a
/// transcriber can fail at, and none of them apply to a world whose every net
/// is named and whose every device has a model. A writer that refused this
/// input would be making a decision, which is something else's job.
#[test]
fn a_complete_world_is_writable_without_error() {
    let world = World::named();
    let mut out = String::new();
    let result = write_spice(
        world.extraction(),
        Some(&world.parasitics),
        Detail::WithParasitics,
        &world.strings,
        &world.header,
        &mut out,
    );
    match result {
        Ok(()) => assert!(!out.is_empty(), "the netlist succeeded and wrote nothing"),
        Err(error) => panic!("a complete extraction was refused: {error}"),
    }
}

/// Oracle: construct-from-answer. SPICE names anonymous nets by number, so an
/// unnamed net is not an error there — unlike SPEF, where it is. Keeping the
/// two behaviours in one test states the contrast rather than leaving it to be
/// inferred from two files.
#[test]
fn spice_numbers_an_anonymous_net_where_spef_refuses_it() {
    let world = World::half_named();

    let mut netlist_out = String::new();
    write_spice(
        world.extraction(),
        None,
        Detail::Schematic,
        &world.strings,
        &world.header,
        &mut netlist_out,
    )
    .expect("SPICE names an anonymous net by its NetId");
    assert!(
        netlist_out.contains(&name_of(&world, world.upper_net)),
        "the anonymous net is missing from the netlist:\n{netlist_out}"
    );

    let mut spef_out = String::new();
    let refusal = parasitic::write_spef(
        &world.parasitics,
        &world.ports,
        &world.strings,
        &world.header,
        &mut spef_out,
    );
    match refusal {
        Err(WriteError::UnnamedNet(net)) => assert_eq!(
            net, world.upper_net.0,
            "SPEF refused the wrong net: the anonymous one is {:?}",
            world.upper_net
        ),
        other => panic!("SPEF accepted an anonymous net: {other:?}"),
    }
}
