//! Device recognition: one device per marker polygon, and the reverse index.
//!
//! Oracle throughout: construct-from-answer, over layouts
//! `gpurify_testgen::layout_from_netlist` emitted from a netlist stated first.
//! The marker polygons it produces are the answer for how many devices exist,
//! because that is the rule `topology::device` states: one polygon on the
//! recogniser's marker layer is exactly one device.

use gpurify_core::PolyId;
use gpurify_derived::Evaluator;
use gpurify_ingest::deck::{DeviceKind, DeviceRecognition};
use gpurify_ingest::StrTable;
use gpurify_testgen::netlist::{NetlistCase, NetlistLayers};
use gpurify_testgen::{layout_from_netlist, DeviceSpec, Floorplan, NetlistSpec};
use gpurify_topology::device::recognise_into;
use gpurify_topology::{extract_nets_into, DeviceId, DeviceTable, NetId, NetTable, TerminalRole};

const MOS_TERMINALS: [TerminalRole; 4] = [
    TerminalRole::Gate,
    TerminalRole::Source,
    TerminalRole::Drain,
    TerminalRole::Bulk,
];

/// A recogniser table holding exactly one row.
///
/// `layout_from_netlist` writes one recogniser per device, which is what a
/// layout of differently-shaped devices needs. The test below wants the
/// opposite: one recogniser and several marker polygons, so that what is being
/// counted is unambiguously the markers rather than the recogniser rows.
fn one_mos_recogniser(layers: &NetlistLayers, strings: &mut StrTable) -> DeviceRecognition {
    let terminal: Vec<_> = MOS_TERMINALS.iter().map(|&r| layers.layer_of(r)).collect();
    let terminal_len = u32::try_from(terminal.len()).expect("four terminals fit a u32");
    DeviceRecognition {
        kind: vec![DeviceKind::Mos],
        marker: vec![layers.marker],
        terminal_start: vec![0, terminal_len],
        terminal,
        model: vec![strings.intern("nch")],
    }
}

/// Two MOS devices wired to the same four nets in the same order.
///
/// Electrically indistinguishable, which is what makes a count over them a
/// claim about marker polygons rather than about wiring.
fn two_identical_mos() -> NetlistSpec {
    NetlistSpec {
        nets: 4,
        devices: (0..2)
            .map(|_| DeviceSpec {
                kind: DeviceKind::Mos,
                model: "nch".to_owned(),
                terminals: MOS_TERMINALS
                    .iter()
                    .enumerate()
                    .map(|(index, &role)| (role, u32::try_from(index).expect("four terminals")))
                    .collect(),
            })
            .collect(),
    }
}

/// Recognise every device in a case, with the nets it needs.
fn recognise(case: &NetlistCase, recognition: &DeviceRecognition) -> (NetTable, DeviceTable) {
    let mut nets = NetTable::default();
    extract_nets_into(&case.store, &case.connectivity, &mut nets);
    let mut devices = DeviceTable::default();
    recognise_into(
        &case.store,
        &Evaluator::default(),
        &nets,
        recognition,
        &mut devices,
    );
    (nets, devices)
}

/// Oracle: construct-from-answer. Two MOS devices wired to exactly the same
/// four nets, in the same terminal order, with the same model — electrically
/// indistinguishable, and two separate devices because there are two marker
/// polygons.
///
/// **This names a specific defect.** The old tree deduplicated recognised
/// devices on the tuple of nets they attached to, so a pair like this merged
/// into one and every downstream count, from LVS device matching to ERC's
/// device-connected test, was quietly short by one. Keying on the marker
/// polygon is the fix, and this is the test that holds it in place: the two
/// devices below agree on every field the old key looked at and differ only in
/// their marker.
#[test]
fn two_identical_devices_on_two_marker_polygons_are_two_devices_not_one() {
    let mut strings = StrTable::default();
    let case = layout_from_netlist(&two_identical_mos(), Floorplan::default(), &mut strings);
    let recognition = one_mos_recogniser(&case.layers, &mut strings);
    let (nets, devices) = recognise(&case, &recognition);

    assert_eq!(
        devices.len(),
        2,
        "the layout holds two marker polygons, so it holds two devices"
    );

    // The two markers are the two the generator placed, and they are distinct.
    let mut expected_markers: Vec<PolyId> =
        case.expected_devices.iter().map(|d| d.marker).collect();
    expected_markers.sort_unstable();
    assert_eq!(
        devices.marker, expected_markers,
        "devices are ordered by marker polygon, and these are the markers emitted"
    );

    // And they really are electrically identical, which is what makes the count
    // above a claim about markers rather than about wiring.
    let first = devices.terminals_of(DeviceId(0));
    let second = devices.terminals_of(DeviceId(1));
    assert_eq!(
        first.0, second.0,
        "the two devices were built on the same four nets"
    );
    assert_eq!(first.1, second.1, "the two devices have the same roles");
    assert_eq!(
        first.1,
        MOS_TERMINALS.as_slice(),
        "terminal roles follow the recogniser's terminal order"
    );

    let net_of_spec = |index: u32| nets.net_of(case.expected_net_polys[index as usize][0]);
    let want: Vec<NetId> = (0..4).map(net_of_spec).collect();
    assert_eq!(first.0, want.as_slice(), "device 0 is on the wrong nets");
}

/// Oracle: construct-from-answer. The reverse index is the question `erc` asks
/// constantly, and its answer is fixed by the spec: a net named by a terminal
/// carries that device, a net named by two carries both, and a net nothing
/// attaches to carries none. The last is an absence claim, so it is asserted
/// only alongside the two positives from the same table — a recogniser that
/// found nothing would fail the positives first.
#[test]
fn the_reverse_index_lists_exactly_the_devices_each_net_carries() {
    // Nets 0 and 1 carry one terminal each, nets 2 and 3 carry one from each
    // device, and net 4 carries nothing at all.
    let spec = NetlistSpec {
        nets: 5,
        devices: vec![
            DeviceSpec {
                kind: DeviceKind::Mos,
                model: "nch".to_owned(),
                terminals: vec![
                    (TerminalRole::Gate, 0),
                    (TerminalRole::Source, 1),
                    (TerminalRole::Drain, 2),
                    (TerminalRole::Bulk, 3),
                ],
            },
            DeviceSpec {
                kind: DeviceKind::Resistor,
                model: "res".to_owned(),
                terminals: vec![(TerminalRole::Pin(0), 2), (TerminalRole::Pin(1), 3)],
            },
        ],
    };

    let mut strings = StrTable::default();
    let case = layout_from_netlist(&spec, Floorplan::default(), &mut strings);
    let (nets, devices) = recognise(&case, &case.recognition);
    // Two recogniser rows, both naming the same marker layer, over two marker
    // polygons. Two is the answer because a recogniser can only fire where all
    // of its terminal layers have a shape under the marker — `terminal_net` is
    // a `Vec<NetId>` and cannot spell an absent terminal. See the longer note
    // in `extraction.rs` and the NEED_TESTING entry.
    assert_eq!(devices.len(), 2, "two marker polygons, two devices");

    // Device ids follow marker order, so the answer is read back through the
    // markers rather than assumed to be spec order.
    let device_of = |marker: PolyId| {
        let row = devices
            .marker
            .iter()
            .position(|&m| m == marker)
            .expect("every emitted marker was recognised");
        DeviceId(u32::try_from(row).expect("two devices fit a u32"))
    };
    let mos = device_of(case.expected_devices[0].marker);
    let resistor = device_of(case.expected_devices[1].marker);
    let net_of_spec = |index: usize| nets.net_of(case.expected_net_polys[index][0]);

    let mut shared = vec![mos, resistor];
    shared.sort_unstable();
    assert_eq!(
        devices.devices_on(net_of_spec(0)),
        [mos],
        "net 0 is the gate"
    );
    assert_eq!(
        devices.devices_on(net_of_spec(1)),
        [mos],
        "net 1 is the source"
    );
    assert_eq!(
        devices.devices_on(net_of_spec(2)),
        shared.as_slice(),
        "net 2 carries the drain and one resistor pin, ascending by DeviceId"
    );
    assert_eq!(
        devices.devices_on(net_of_spec(3)),
        shared.as_slice(),
        "net 3 carries the bulk and the other resistor pin"
    );
    assert!(
        devices.devices_on(net_of_spec(4)).is_empty(),
        "net 4 is a bare rail: nothing attaches to it, which is what a floating net is"
    );
}

/// Oracle: construct-from-answer. `recognise_into` takes `out` by `&mut` and
/// the caller owns it, so a table handed in twice must be refilled and not
/// appended to. The third call is the same claim from the other side: a deck
/// with no recognisers at all, into a table that already holds two devices,
/// must leave it empty.
///
/// The empty result is an absence claim and is asserted only after the same
/// table has demonstrably been filled twice from the same call, so it is
/// evidence about the deck rather than about a recogniser that never ran.
#[test]
fn a_reused_device_table_is_refilled_and_an_empty_deck_recognises_nothing() {
    let mut strings = StrTable::default();
    let case = layout_from_netlist(&two_identical_mos(), Floorplan::default(), &mut strings);
    let recognition = one_mos_recogniser(&case.layers, &mut strings);

    let mut nets = NetTable::default();
    extract_nets_into(&case.store, &case.connectivity, &mut nets);
    let evaluator = Evaluator::default();

    let mut devices = DeviceTable::default();
    recognise_into(&case.store, &evaluator, &nets, &recognition, &mut devices);
    let markers = devices.marker.clone();
    assert_eq!(markers.len(), 2, "the layout holds two marker polygons");
    assert!(!devices.is_empty());

    recognise_into(&case.store, &evaluator, &nets, &recognition, &mut devices);
    assert_eq!(
        devices.marker, markers,
        "a reused DeviceTable appended a second copy instead of being refilled"
    );
    assert_eq!(devices.len(), 2, "the same deck over the same layout, twice");

    recognise_into(
        &case.store,
        &evaluator,
        &nets,
        &DeviceRecognition::default(),
        &mut devices,
    );
    assert!(
        devices.is_empty(),
        "a deck naming no recognisers left the previous run's devices behind"
    );
    assert_eq!(devices.len(), 0);
    assert!(devices.marker.is_empty(), "the marker column was not cleared");
}
