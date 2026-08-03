//! Port binding: the names a layout declares, and the contradictions it can.
//!
//! Oracle throughout: construct-from-answer. The layout comes from
//! `gpurify_testgen::layout_from_netlist`, so which polygons share a net is
//! known before a label is placed, and therefore so is whether two labels land
//! on one net.

use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::{Provenance, StrTable};
use gpurify_testgen::netlist::NetlistCase;
use gpurify_testgen::{layout_from_netlist, DeviceSpec, Floorplan, NetlistSpec};
use gpurify_topology::port::PortError;
use gpurify_topology::{bind_ports_into, extract_nets_into, NetTable, PortTable, TerminalRole};

/// Three nets, one of which carries two polygons joined through a via.
///
/// That last one is what makes a conflict constructible: two labels on two
/// different shapes that extraction has already decided are one conductor.
fn two_pin_resistor() -> NetlistSpec {
    NetlistSpec {
        nets: 3,
        devices: vec![DeviceSpec {
            kind: DeviceKind::Resistor,
            model: "res".to_owned(),
            terminals: vec![(TerminalRole::Pin(0), 0), (TerminalRole::Pin(1), 1)],
        }],
    }
}

fn extract(case: &NetlistCase) -> NetTable {
    let mut nets = NetTable::default();
    extract_nets_into(&case.store, &case.connectivity, &mut nets);
    nets
}

/// Oracle: construct-from-answer. A label names the net of the shape it sits
/// on, the lookup goes both ways, and a net nobody labelled has no name. The
/// unnamed case is asserted next to two named ones from the same table, so it
/// is evidence about net 2 rather than about a binder that did nothing.
#[test]
fn a_label_names_the_net_of_the_shape_it_sits_on_and_nothing_else() {
    let mut strings = StrTable::default();
    let case = layout_from_netlist(&two_pin_resistor(), Floorplan::default(), &mut strings);
    let nets = extract(&case);

    let first = strings.intern("VIN");
    let second = strings.intern("VOUT");
    let mut provenance = Provenance::default();
    provenance.label(case.expected_net_polys[0][0], first);
    provenance.label(case.expected_net_polys[1][0], second);

    let mut ports = PortTable::default();
    bind_ports_into(&nets, &provenance, &mut ports)
        .expect("two labels on two nets is not ambiguous");

    let net_zero = nets.net_of(case.expected_net_polys[0][0]);
    let net_one = nets.net_of(case.expected_net_polys[1][0]);
    let net_two = nets.net_of(case.expected_net_polys[2][0]);

    assert_eq!(
        ports.len(),
        2,
        "two labels were placed, on two distinct nets"
    );
    assert_eq!(ports.name_of(net_zero), Some(first));
    assert_eq!(ports.name_of(net_one), Some(second));
    assert_eq!(
        ports.name_of(net_two),
        None,
        "net 2 is an unlabelled rail; LVS matches it by structure, not by name"
    );

    // The two directions are inverses of each other, which is the whole reason
    // both exist: LVS reads names to nets, a report reads nets to names.
    assert_eq!(ports.net_of(first), Some(net_zero));
    assert_eq!(ports.net_of(second), Some(net_one));
    assert!(!ports.is_empty());
}

/// Oracle: construct-from-answer. The two labelled shapes are a rail and the
/// stub joined to it by a via, so extraction has already established they are
/// one conductor — and one conductor cannot be both `VIN` and `VOUT`.
///
/// The result is an error, deliberately, and the error names the net. Picking a
/// winner and carrying on is the failure mode the module's doc comment refuses:
/// it produces an LVS result that is confidently wrong about which net is
/// which, and nothing downstream can tell that it happened.
#[test]
fn two_different_labels_on_one_net_is_a_conflict_and_not_a_silently_chosen_winner() {
    let mut strings = StrTable::default();
    let case = layout_from_netlist(&two_pin_resistor(), Floorplan::default(), &mut strings);
    let nets = extract(&case);

    let rail_and_stub = &case.expected_net_polys[0];
    assert!(
        rail_and_stub.len() >= 2,
        "net 0 must carry more than one polygon for this test to mean anything"
    );
    assert!(
        nets.same_net(rail_and_stub[0], rail_and_stub[1]),
        "the two shapes about to be labelled must already be one net"
    );

    let first = strings.intern("VIN");
    let second = strings.intern("VOUT");
    let mut provenance = Provenance::default();
    provenance.label(rail_and_stub[0], first);
    provenance.label(rail_and_stub[1], second);

    let mut ports = PortTable::default();
    let result = bind_ports_into(&nets, &provenance, &mut ports);
    assert_eq!(
        result,
        Err(PortError::ConflictingLabels(nets.net_of(rail_and_stub[0]))),
        "two labels on one net must be reported against that net"
    );
}

/// Oracle: construct-from-answer. The same name on two shapes of one net is
/// what a designer writes when they label both ends of a wire, and it is not a
/// contradiction — there is one name for one net. This is the boundary of the
/// rule above, and without it `ConflictingLabels` could be implemented as
/// "more than one label" and still pass.
#[test]
fn one_name_repeated_across_a_nets_shapes_binds_once_and_is_not_a_conflict() {
    let mut strings = StrTable::default();
    let case = layout_from_netlist(&two_pin_resistor(), Floorplan::default(), &mut strings);
    let nets = extract(&case);

    let rail_and_stub = &case.expected_net_polys[0];
    let name = strings.intern("VIN");
    let mut provenance = Provenance::default();
    provenance.label(rail_and_stub[0], name);
    provenance.label(rail_and_stub[1], name);

    let mut ports = PortTable::default();
    bind_ports_into(&nets, &provenance, &mut ports)
        .expect("one name on one net is not a contradiction");

    let net = nets.net_of(rail_and_stub[0]);
    assert_eq!(ports.len(), 1, "one net was named, so there is one port");
    assert_eq!(ports.name_of(net), Some(name));
    assert_eq!(ports.net_of(name), Some(net));
}

/// Oracle: determinism. `bind_ports_into` reads `Provenance::labels`, which is
/// already ascending by `PolyId`, so its result is claimed to be deterministic
/// without a sort. Binding twice into a reused table is where a claim like that
/// breaks first: the second call must clear what the first left behind rather
/// than append to it.
#[test]
fn binding_twice_into_one_table_gives_the_same_table() {
    let mut strings = StrTable::default();
    let case = layout_from_netlist(&two_pin_resistor(), Floorplan::default(), &mut strings);
    let nets = extract(&case);

    let first = strings.intern("VIN");
    let second = strings.intern("VOUT");
    let mut provenance = Provenance::default();
    provenance.label(case.expected_net_polys[0][0], first);
    provenance.label(case.expected_net_polys[1][0], second);

    let mut ports = PortTable::default();
    bind_ports_into(&nets, &provenance, &mut ports).expect("two labels on two nets");
    let after_one = (ports.len(), ports.net_of(first), ports.net_of(second));

    bind_ports_into(&nets, &provenance, &mut ports).expect("two labels on two nets");
    let after_two = (ports.len(), ports.net_of(first), ports.net_of(second));

    assert_eq!(
        after_one, after_two,
        "a reused PortTable accumulated rows instead of being refilled"
    );
}
