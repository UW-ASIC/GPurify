//! The shared graph shape: its CSR accessors, and the projection of a reference
//! netlist into it.
//!
//! Nothing here compares anything. These are the guarantees the matcher is
//! entitled to assume about its input, and a matcher reading the wrong device's
//! terminals produces a mismatch report that blames the layout.

mod common;

use common::{
    mos_and_bjt, random_graph, stacked_pair, stacked_pair_with_params, GraphBuilder, LENGTH, NCH,
    RES, VDD, VSS, WIDTH,
};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::netlist::{Netlist, RefNetId, SubcktId};
use gpurify_ingest::StrId;
use gpurify_lvs::graph::{from_reference_into, RefGraph};
use gpurify_testgen::Rng;
use gpurify_topology::TerminalRole;

/// Oracle: construct-from-answer. The fixture states each device's terminals
/// before the graph exists, so the accessor either hands back that list or it is
/// reading someone else's row. Devices of differing terminal counts sit next to
/// each other deliberately: an off-by-one in the CSR offsets is invisible when
/// every range is the same length.
#[test]
fn each_device_gets_back_the_terminals_it_was_built_with() {
    use TerminalRole::{Base, Bulk, Collector, Drain, Emitter, Gate, Source};
    let graph = mos_and_bjt();

    assert_eq!(graph.device_count(), 2);
    assert_eq!(graph.net_count(), 7);

    let (nets, roles) = graph.terminals_of(0);
    assert_eq!(nets, [0, 1, 2, 3]);
    assert_eq!(roles, [Gate, Source, Drain, Bulk]);

    let (nets, roles) = graph.terminals_of(1);
    assert_eq!(nets, [4, 5, 6]);
    assert_eq!(roles, [Base, Emitter, Collector]);
}

/// Oracle: law. The net-side incidence is the transpose of the device-side
/// incidence, for any graph whatsoever — every `(device, role)` on a net is a
/// terminal of that device landing there, and every terminal appears on exactly
/// one net. Asserted over generated graphs because the property is about the
/// pair of columns, not about any one arrangement of them.
#[test]
fn net_incidence_is_the_transpose_of_device_incidence() {
    let mut rng = Rng::new(19);
    for seed_round in 0..12 {
        let graph = random_graph(&mut rng, 6 + seed_round, 9);

        let mut from_devices: Vec<(u32, u32, TerminalRole)> = Vec::new();
        for device in 0..u32::try_from(graph.device_count()).expect("a small fixture") {
            let (nets, roles) = graph.terminals_of(device);
            assert_eq!(
                nets.len(),
                roles.len(),
                "device {device} has {} nets and {} roles",
                nets.len(),
                roles.len()
            );
            for (&net, &role) in nets.iter().zip(roles) {
                from_devices.push((device, net, role));
            }
        }

        let mut from_nets: Vec<(u32, u32, TerminalRole)> = Vec::new();
        for net in 0..u32::try_from(graph.net_count()).expect("a small fixture") {
            for &(device, role) in graph.terminals_on(net) {
                from_nets.push((device, net, role));
            }
        }

        assert_eq!(
            from_devices.len(),
            from_nets.len(),
            "round {seed_round}: {} terminals from devices, {} from nets",
            from_devices.len(),
            from_nets.len()
        );
        for terminal in &from_devices {
            let position = from_nets.iter().position(|other| other == terminal);
            let Some(position) = position else {
                panic!("round {seed_round}: {terminal:?} is on no net's list");
            };
            from_nets.swap_remove(position);
        }
        assert!(
            from_nets.is_empty(),
            "round {seed_round}: nets carry terminals no device owns: {from_nets:?}"
        );
    }
}

/// Oracle: construct-from-answer. Parameters are a second CSR over the same
/// device rows, and a device with none must get an empty slice rather than its
/// neighbour's. The lower transistor is given two parameters and the upper none
/// precisely so the empty case sits after a non-empty one.
#[test]
fn parameters_are_partitioned_across_the_devices_that_declared_them() {
    let graph = stacked_pair_with_params(&[(WIDTH, 0.5), (LENGTH, 0.03)], &[]);

    // Exact equality is right here: these values are stored and handed back,
    // never computed, so any difference at all is a wrong row rather than
    // rounding.
    assert_eq!(graph.params_of(0), [(WIDTH, 0.5), (LENGTH, 0.03)]);
    assert!(graph.params_of(1).is_empty());
    assert_eq!(
        graph.params_of(0).len() + graph.params_of(1).len(),
        graph.param.len(),
        "the two devices' parameter slices do not cover the parameter column"
    );
}

/// Oracle: law. Terminal ranges partition the terminal columns: they are
/// contiguous, they start at zero, they end at the column length, and no
/// terminal belongs to two devices. That is what "CSR" means, and it is the
/// invariant every other accessor in the crate is built on.
#[test]
fn terminal_ranges_tile_the_terminal_columns_without_gap_or_overlap() {
    let mut rng = Rng::new(101);
    let graph = random_graph(&mut rng, 11, 7);

    let mut covered = 0usize;
    for device in 0..u32::try_from(graph.device_count()).expect("a small fixture") {
        let (nets, _) = graph.terminals_of(device);
        covered += nets.len();
    }
    assert_eq!(
        covered,
        graph.terminal_net.len(),
        "the device ranges cover {covered} of {} terminals",
        graph.terminal_net.len()
    );
    assert_eq!(graph.terminal_net.len(), graph.terminal_role.len());
}

/// Oracle: construct-from-answer. A netlist is written out by hand, one
/// subcircuit holding every net, so the reference net numbering and the graph's
/// are the same space and the projection can be asserted row by row rather than
/// up to an unknown renumbering.
///
/// The MOS terminal roles are asserted as a set. SPICE orders a MOS card drain,
/// gate, source, bulk, but the frozen `Netlist` carries no roles at all, so the
/// mapping from card position to [`TerminalRole`] is a Definition-Phase
/// omission; what the projection may not do under any reading is invent a role
/// the family does not have, or use one twice.
///
/// The resistor's two roles are asserted as `Pin(_)` without pinning the index
/// for the same reason. [`TerminalRole::Pin`] is documented as "either end of a
/// symmetric two-terminal device, interchangeable by definition", which fixes
/// the variant and deliberately leaves the numbering open — so `Pin(0), Pin(1)`
/// and `Pin(1), Pin(2)` are both legal and a test may not choose between them.
#[test]
fn a_reference_subcircuit_projects_to_the_graph_it_describes() {
    let netlist = one_subcircuit();
    let mut graph = RefGraph::default();
    from_reference_into(&netlist, SubcktId(0), &gpurify_ingest::StrTable::default(), &mut graph);
    let graph = &graph.0;

    assert_eq!(graph.device_count(), 2);
    assert_eq!(graph.net_count(), 5);
    assert_eq!(graph.device_kind, [DeviceKind::Resistor, DeviceKind::Mos]);
    assert_eq!(graph.device_model, [RES, NCH]);

    let (nets, roles) = graph.terminals_of(0);
    assert_eq!(nets, [0, 1]);
    assert_eq!(roles.len(), 2, "a resistor has two terminals");
    for role in roles {
        assert!(
            matches!(role, TerminalRole::Pin(_)),
            "the resistor was given role {role:?}, and a symmetric two-terminal \
             device has pins"
        );
    }

    let (nets, roles) = graph.terminals_of(1);
    assert_eq!(nets, [1, 2, 3, 4]);
    let mut expected = vec![
        TerminalRole::Gate,
        TerminalRole::Source,
        TerminalRole::Drain,
        TerminalRole::Bulk,
    ];
    for role in roles {
        let position = expected.iter().position(|want| want == role);
        let Some(position) = position else {
            panic!("the MOS was given role {role:?}, which is not one of its four");
        };
        expected.swap_remove(position);
    }
    assert!(expected.is_empty(), "the MOS is missing roles {expected:?}");

    assert_eq!(graph.params_of(0), [(WIDTH, 2.5)]);
    assert!(graph.params_of(1).is_empty());
    assert_eq!(graph.port_net, [0, 1]);
    assert_eq!(
        graph.net_name,
        [Some(VDD), Some(VSS), Some(StrId(32)), Some(StrId(33)), Some(StrId(34))]
    );
}

/// Oracle: law. Projection is a function: the same subcircuit projected twice
/// gives the same columns, and projecting into a buffer that already holds a
/// graph must clear it rather than append to it. The reuse is the point of the
/// `_into` form, so it is the thing worth checking.
#[test]
fn projecting_twice_into_one_buffer_gives_the_same_graph_as_projecting_once() {
    let netlist = one_subcircuit();
    let strings = gpurify_ingest::StrTable::default();

    let mut once = RefGraph::default();
    from_reference_into(&netlist, SubcktId(0), &strings, &mut once);

    let mut twice = RefGraph::default();
    from_reference_into(&netlist, SubcktId(0), &strings, &mut twice);
    from_reference_into(&netlist, SubcktId(0), &strings, &mut twice);

    assert_eq!(format!("{once:?}"), format!("{twice:?}"));
}

/// A resistor and a transistor in one subcircuit over five nets.
///
/// Written as columns rather than parsed, because `spice::read` is a `todo!()`
/// until the Implementation-Phase and every field of [`Netlist`] is public
/// precisely so a test does not have to go through a parser to get one.
fn one_subcircuit() -> Netlist {
    Netlist {
        subckt_name: vec![StrId(30)],
        subckt_port_start: vec![0, 2],
        port_net: vec![RefNetId(0), RefNetId(1)],
        subckt_device_start: vec![0, 2],

        device_name: vec![StrId(40), StrId(41)],
        device_model: vec![RES, NCH],
        device_kind: vec![DeviceKind::Resistor, DeviceKind::Mos],
        device_terminal_start: vec![0, 2, 6],
        terminal_net: vec![
            RefNetId(0),
            RefNetId(1),
            RefNetId(1),
            RefNetId(2),
            RefNetId(3),
            RefNetId(4),
        ],
        device_param_start: vec![0, 1, 1],
        param: vec![(WIDTH, 2.5)],

        net_name: vec![VDD, VSS, StrId(32), StrId(33), StrId(34)],
        net_subckt: vec![SubcktId(0); 5],
        // Flat: the projection under test is per subcircuit, so an instance
        // here would be a row `from_reference_into` is defined to ignore.
        ..Netlist::default()
    }
}

/// Oracle: construct-from-answer. A net nothing attaches to still exists, has a
/// node index, and reports an empty terminal list. Dropping it is the bug that
/// makes a floating net invisible to LVS, and an empty CSR range at the end of
/// the column is exactly where an off-by-one hides.
#[test]
fn a_net_with_no_terminals_is_still_a_net_with_an_empty_terminal_list() {
    let mut builder = GraphBuilder::new(3);
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(TerminalRole::Source, 0), (TerminalRole::Drain, 1)],
    );
    let graph = builder.finish();

    assert_eq!(graph.net_count(), 3);
    assert!(graph.terminals_on(2).is_empty());
    assert_eq!(graph.terminals_on(0).len(), 1);
}

/// Oracle: construct-from-answer. The stacked pair shares net 2 between the
/// lower drain and the upper gate and net 3 between both bulks, so the reverse
/// incidence has to hold two entries for each and one for the rest. A
/// transposition that kept only the last writer would pass a total-count check
/// and fail this one.
#[test]
fn a_shared_net_lists_every_terminal_that_lands_on_it() {
    use TerminalRole::{Bulk, Drain, Gate, Source};
    let graph = stacked_pair();

    assert_eq!(graph.terminals_on(2), [(0, Drain), (1, Gate)]);
    assert_eq!(graph.terminals_on(3), [(0, Bulk), (1, Bulk)]);
    assert_eq!(graph.terminals_on(0), [(0, Gate)]);
    assert_eq!(graph.terminals_on(4), [(1, Source)]);
}

