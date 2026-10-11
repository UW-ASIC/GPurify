//! Device recognition: one device per marker polygon, and the reverse index.
//!
//! Oracle throughout: construct-from-answer, over layouts
//! `gpurify_testgen::layout_from_netlist` emitted from a netlist stated first.
//! The marker polygons it produces are the answer for how many devices exist,
//! because that is the rule `topology::device` states: one polygon on the
//! recogniser's marker layer is exactly one device.

use gpurify_check::topology::device::recognise_into;
use gpurify_check::topology::{
    extract_nets_into, DeviceId, DeviceTable, NetId, NetTable, TerminalRole,
};
use gpurify_geom::{LayerId, PolyId};
use gpurify_ingest::deck::{Connectivity, DeviceKind, DeviceRecognition};
use gpurify_ingest::StrTable;
use gpurify_testgen::netlist::{NetlistCase, NetlistLayers};
use gpurify_testgen::shapes::LayoutBuilder;
use gpurify_testgen::{layout_from_netlist, DeviceSpec, Floorplan, NetlistSpec};

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
        value: Vec::new(),
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
    recognise_into(&case.store, &nets, recognition, &mut devices);
    (nets, devices)
}

/// Oracle: construct-from-answer. Two MOS devices wired to exactly the same
/// four nets, in the same terminal order, with the same model — electrically
/// indistinguishable, and two separate devices because there are two marker
/// polygons.
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

    let mut devices = DeviceTable::default();
    recognise_into(&case.store, &nets, &recognition, &mut devices);
    let markers = devices.marker.clone();
    assert_eq!(markers.len(), 2, "the layout holds two marker polygons");
    assert!(!devices.is_empty());

    recognise_into(&case.store, &nets, &recognition, &mut devices);
    assert_eq!(
        devices.marker, markers,
        "a reused DeviceTable appended a second copy instead of being refilled"
    );
    assert_eq!(
        devices.len(),
        2,
        "the same deck over the same layout, twice"
    );

    recognise_into(
        &case.store,
        &nets,
        &DeviceRecognition::default(),
        &mut devices,
    );
    assert!(
        devices.is_empty(),
        "a deck naming no recognisers left the previous run's devices behind"
    );
    assert_eq!(devices.len(), 0);
    assert!(
        devices.marker.is_empty(),
        "the marker column was not cleared"
    );
}

/// Oracle: construct-from-answer. A MOS declares `[gate, sd, sd]` — two
/// terminal *positions* on one terminal *layer* — and the two must land on the
/// two source/drain regions, not twice on the same one.
///
/// The layout is drawn so the answer is fixed before anything runs: the
/// source/drain layer holds exactly two polygons under the marker, on opposite
/// sides of the gate, and they are far enough apart that no connectivity rule
/// can join them. So `Source` and `Drain` name two different nets, and any
/// binding that keeps one polygon per terminal *layer* reports them as one.
#[test]
fn two_terminal_positions_on_one_layer_bind_to_two_different_polygons() {
    const MARKER: LayerId = LayerId(0);
    const GATE: LayerId = LayerId(1);
    const SD: LayerId = LayerId(2);

    // Marker over the whole device; gate crossing it; the two source/drain
    // regions either side of the gate, disjoint and not touching.
    let mut layout = LayoutBuilder::new(3);
    let marker = layout.rect(MARKER, -50, -50, 550, 250);
    let gate = layout.rect(GATE, 200, -50, 250, 750);
    let source = layout.rect(SD, 0, 0, 200, 200);
    let drain = layout.rect(SD, 250, 0, 500, 200);
    let (store, ids) = layout.finish();
    let (marker, gate) = (ids.of(marker), ids.of(gate));
    let (source, drain) = (ids.of(source), ids.of(drain));

    let connectivity = Connectivity {
        conductors: vec![GATE, SD],
        intra_layer_touch: true,
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    extract_nets_into(&store, &connectivity, &mut nets);
    assert_ne!(
        nets.net_of(source),
        nets.net_of(drain),
        "the two source/drain regions are disjoint rectangles on the same \
         layer, so they are two nets before device recognition is asked anything"
    );

    let mut strings = StrTable::default();
    let recognition = DeviceRecognition {
        kind: vec![DeviceKind::Mos],
        marker: vec![MARKER],
        terminal_start: vec![0, 3],
        terminal: vec![GATE, SD, SD],
        model: vec![strings.intern("nch")],
        value: Vec::new(),
    };
    let mut devices = DeviceTable::default();
    recognise_into(&store, &nets, &recognition, &mut devices);

    assert_eq!(devices.len(), 1, "one marker polygon is one device");
    assert_eq!(devices.marker, [marker], "the device names its marker");
    let (bound, roles) = devices.terminals_of(DeviceId(0));
    assert_eq!(
        roles,
        [
            TerminalRole::Gate,
            TerminalRole::Source,
            TerminalRole::Drain
        ],
        "terminal roles follow the recogniser's terminal order"
    );
    assert_eq!(
        bound[0],
        nets.net_of(gate),
        "the gate is the gate layer's net"
    );
    assert_ne!(
        bound[1], bound[2],
        "source and drain bound to the same net, so the two terminal positions \
         took the same polygon: the channel is reported as a short"
    );
    // Which position takes which polygon is a convention, and it has to be one:
    // ascending `PolyId` is the only order that does not depend on how the
    // spatial index happened to bucket the layer.
    assert_eq!(
        [bound[1], bound[2]],
        [nets.net_of(source), nets.net_of(drain)],
        "repeated terminal positions take the layer's polygons under the \
         marker in ascending PolyId order"
    );
}

/// Two fingers under one implant, drawn to the dimensions of the corpus cell
/// `LVS_FINGERS`: one diffusion `(0, 0)–(1000, 200)`, two gates crossing it at
/// x 200 and x 600, and one implant rectangle covering the lot.
///
/// `diff_active` is `diff NOT poly`, so the three regions are what the deck's
/// derived layer materialises; `channel` is `poly AND diff`, the other derived
/// layer the same deck can state. Both are drawn here rather than computed,
/// because what is under test is what `recognise_into` does with a marker layer,
/// not what a boolean produces.
struct Fingers {
    store: gpurify_geom::GeometryStore,
    channel: [PolyId; 2],
    gate: [PolyId; 2],
    /// Source, shared middle, drain — ascending in x, and so in [`PolyId`].
    active: [PolyId; 3],
}

impl Fingers {
    const IMPLANT: LayerId = LayerId(0);
    const CHANNEL: LayerId = LayerId(1);
    const POLY: LayerId = LayerId(2);
    const ACTIVE: LayerId = LayerId(3);

    fn draw() -> Self {
        let mut layout = LayoutBuilder::new(4);
        layout.rect(Self::IMPLANT, -50, -50, 1050, 250);
        let channel = [
            layout.rect(Self::CHANNEL, 200, 0, 250, 200),
            layout.rect(Self::CHANNEL, 600, 0, 650, 200),
        ];
        let gate = [
            layout.rect(Self::POLY, 200, -50, 250, 250),
            layout.rect(Self::POLY, 600, -50, 650, 250),
        ];
        let active = [
            layout.rect(Self::ACTIVE, 0, 0, 200, 200),
            layout.rect(Self::ACTIVE, 250, 0, 600, 200),
            layout.rect(Self::ACTIVE, 650, 0, 1000, 200),
        ];
        let (store, ids) = layout.finish();
        Self {
            store,
            channel: channel.map(|h| ids.of(h)),
            gate: gate.map(|h| ids.of(h)),
            active: active.map(|h| ids.of(h)),
        }
    }

    /// The nets the layout carries. Gates and diffusion regions are conductors;
    /// neither the implant nor the channel is, so neither can join anything.
    fn nets(&self) -> NetTable {
        let connectivity = Connectivity {
            conductors: vec![Self::POLY, Self::ACTIVE],
            intra_layer_touch: true,
            ..Connectivity::default()
        };
        let mut nets = NetTable::default();
        extract_nets_into(&self.store, &connectivity, &mut nets);
        nets
    }

    /// A three-terminal MOS recogniser on `marker`, `[poly, active, active]` —
    /// the shape `tests/fixtures/params.deck` states.
    fn recogniser(marker: LayerId, strings: &mut StrTable) -> DeviceRecognition {
        DeviceRecognition {
            kind: vec![DeviceKind::Mos],
            marker: vec![marker],
            terminal_start: vec![0, 3],
            terminal: vec![Self::POLY, Self::ACTIVE, Self::ACTIVE],
            model: vec![strings.intern("nch")],
            value: Vec::new(),
        }
    }

    fn recognise(&self, marker: LayerId, nets: &NetTable) -> DeviceTable {
        let mut strings = StrTable::default();
        let recognition = Self::recogniser(marker, &mut strings);
        let mut devices = DeviceTable::default();
        recognise_into(&self.store, nets, &recognition, &mut devices);
        devices
    }
}

/// Oracle: construct-from-answer. Two transistors under one implant rectangle,
/// and the recogniser is told the implant is the marker.
///
/// A marker carrying more of a terminal layer's polygons than there are
/// positions is refused, not reported as its first finger.
#[test]
fn two_gates_under_one_implant_are_refused_rather_than_reported_as_one_device() {
    let drawn = Fingers::draw();
    let nets = drawn.nets();

    // The layout really does hold two transistors, and the three diffusion
    // regions really are three nets — so a count of one below is a dropped
    // device and not a merged one.
    assert_eq!(
        [
            nets.net_of(drawn.active[0]),
            nets.net_of(drawn.active[1]),
            nets.net_of(drawn.active[2])
        ]
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len(),
        3,
        "the three diffusion regions are disjoint, so they are three nets"
    );
    assert_ne!(
        nets.net_of(drawn.gate[0]),
        nets.net_of(drawn.gate[1]),
        "the two gates are separate poly rectangles, so they are two nets"
    );

    let devices = drawn.recognise(Fingers::IMPLANT, &nets);
    assert_eq!(
        devices.len(),
        0,
        "one implant rectangle over two transistors is not one device: the \
         recogniser reported {} of them",
        devices.len()
    );
    // Nor is it dropped in silence (testing-plan F32): two gate nets for one
    // gate position and three diffusion nets for two positions bind none of
    // the three terminals.
    let implant = PolyId(drawn.store.polys_on_layer(Fingers::IMPLANT).start);
    assert_eq!(devices.refused, [(implant, 0, 3)]);
}

/// One channel, its gate, and diffusion drawn as `active` (`xlo`, `xhi`
/// pairs, in drawing order), recognised as a three-terminal MOS: the
/// devices, and the nets of the gate and of each diffusion rectangle.
fn one_channel(active: &[(i64, i64)]) -> (DeviceTable, NetId, Vec<NetId>) {
    const CHANNEL: LayerId = LayerId(0);
    const POLY: LayerId = LayerId(1);
    const ACTIVE: LayerId = LayerId(2);
    let mut layout = LayoutBuilder::new(3);
    layout.rect(CHANNEL, 200, 0, 250, 200);
    let gate = layout.rect(POLY, 200, -50, 250, 250);
    let drawn: Vec<_> = active
        .iter()
        .map(|&(xlo, xhi)| layout.rect(ACTIVE, xlo, 0, xhi, 200))
        .collect();
    let (store, ids) = layout.finish();
    let connectivity = Connectivity {
        conductors: vec![POLY, ACTIVE],
        intra_layer_touch: true,
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    extract_nets_into(&store, &connectivity, &mut nets);
    let mut strings = StrTable::default();
    let recognition = DeviceRecognition {
        kind: vec![DeviceKind::Mos],
        marker: vec![CHANNEL],
        terminal_start: vec![0, 3],
        terminal: vec![POLY, ACTIVE, ACTIVE],
        model: vec![strings.intern("nch")],
        value: Vec::new(),
    };
    let mut devices = DeviceTable::default();
    recognise_into(&store, &nets, &recognition, &mut devices);
    let active = drawn.iter().map(|&h| nets.net_of(ids.of(h))).collect();
    (devices, nets.net_of(ids.of(gate)), active)
}

/// Oracle: construct-from-answer, testing-plan F33. A source or a drain drawn
/// twice is one terminal, so the channel is one device gated by its poly
/// between the source's net and the drain's, whichever of the two is drawn
/// twice and wherever its copy is numbered. It used to depend on numbering:
/// a copy numbered before the other terminal's polygon took that terminal's
/// position, and the marker was refused in silence.
#[test]
fn a_source_or_drain_drawn_twice_binds_wherever_its_copy_is_numbered() {
    let (source, drain) = ((0, 200), (250, 450));
    for active in [
        [source, source, drain],
        [source, drain, source],
        [drain, source, drain],
        [source, drain, drain],
    ] {
        let (devices, gate, nets) = one_channel(&active);
        let net_of = |rect| nets[active.iter().position(|&r| r == rect).expect("drawn")];
        let (s, d) = (net_of(source), net_of(drain));
        assert_ne!(s, d, "source and drain are two nets");
        assert_eq!(devices.len(), 1, "{active:?}: {:?}", devices.refused);
        let (bound, _) = devices.terminals_of(DeviceId(0));
        assert_eq!(bound[0], gate, "{active:?}");
        let mut channel = [bound[1], bound[2]];
        channel.sort_unstable();
        let mut want = [s, d];
        want.sort_unstable();
        assert_eq!(channel, want, "{active:?}");
        assert!(devices.refused.is_empty());
    }
}

/// Oracle: construct-from-answer, testing-plan F32. A channel with its drain
/// missing has one diffusion polygon for two positions: it is no device, and
/// it is listed as refused with the gate and source bound of three terminals,
/// so `lvs.terminal_net` can say where it is.
#[test]
fn a_channel_missing_its_drain_is_listed_as_refused() {
    let (devices, ..) = one_channel(&[(0, 200)]);
    assert_eq!(devices.len(), 0);
    assert_eq!(devices.refused, [(PolyId(0), 2, 3)]);
}

/// Oracle: construct-from-answer, testing-plan F69. A channel with its
/// source drawn twice and no drain: the copies overlap, so they are one
/// shape, and the drain's position has no polygon of its own. It is no
/// device, listed as refused with the gate and the source bound of three,
/// whether the copy coincides with the source or only overlaps it. It used
/// to bind both copies, on one net, as a transistor with its source and
/// drain shorted.
#[test]
fn a_source_drawn_twice_with_no_drain_is_refused_not_shorted() {
    for active in [[(0, 200), (0, 200)], [(0, 200), (100, 200)]] {
        let (devices, ..) = one_channel(&active);
        assert_eq!(devices.len(), 0, "{active:?} bound a shorted device");
        assert_eq!(devices.refused, [(PolyId(0), 2, 3)], "{active:?}");
    }
}

/// Oracle: construct-from-answer. One channel whose bulk layer is drawn
/// twice, two overlapping wells, as a top cell redrawing a tile's well does.
/// The two wells are one net, so the bulk is one terminal: one device.
#[test]
fn a_terminal_drawn_twice_on_one_net_still_binds() {
    const CHANNEL: LayerId = LayerId(0);
    const POLY: LayerId = LayerId(1);
    const ACTIVE: LayerId = LayerId(2);
    const WELL: LayerId = LayerId(3);
    let mut layout = LayoutBuilder::new(4);
    layout.rect(CHANNEL, 200, 0, 250, 200);
    layout.rect(POLY, 200, -50, 250, 250);
    layout.rect(ACTIVE, 0, 0, 200, 200);
    layout.rect(ACTIVE, 250, 0, 450, 200);
    layout.rect(WELL, -100, -100, 550, 300);
    layout.rect(WELL, -200, -200, 650, 400);
    let (store, _) = layout.finish();
    let connectivity = Connectivity {
        conductors: vec![POLY, ACTIVE, WELL],
        intra_layer_touch: true,
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    extract_nets_into(&store, &connectivity, &mut nets);
    let mut strings = StrTable::default();
    let recognition = DeviceRecognition {
        kind: vec![DeviceKind::Mos],
        marker: vec![CHANNEL],
        terminal_start: vec![0, 4],
        terminal: vec![POLY, ACTIVE, ACTIVE, WELL],
        model: vec![strings.intern("pch")],
        value: Vec::new(),
    };
    let mut devices = DeviceTable::default();
    recognise_into(&store, &nets, &recognition, &mut devices);
    assert_eq!(devices.len(), 1, "a redrawn well dropped the transistor");
}

/// Oracle: construct-from-answer. The same layout, recognised on a marker layer
/// drawn one polygon per channel — `poly AND diff`, which
/// `ingest::layout::derive_layers_into` materialises with a real `LayerId` and
/// which a deck states in its `derived` section.
///
/// This is the whole of the fix for F7, and it needs no code: the module's rule
/// is that a marker polygon *is* a device, so the deck has to name a layer that
/// is drawn that way. `nsdm` is not; `poly AND diff AND nsdm` is.
///
/// The answer is fixed by the geometry before anything runs. Two channel regions
/// means two transistors, each gated by the poly crossing it, each flanked by the
/// two diffusion regions its own channel touches — and the middle region is the
/// drain of the first and the source of the second, which is what makes this a
/// series pair rather than two isolated devices.
#[test]
fn a_marker_drawn_per_channel_recognises_one_device_per_finger() {
    use gpurify_check::topology::device::{DeviceMeasure, DeviceParam};

    let drawn = Fingers::draw();
    let nets = drawn.nets();
    let devices = drawn.recognise(Fingers::CHANNEL, &nets);

    assert_eq!(devices.len(), 2, "two channel regions are two transistors");
    assert_eq!(
        devices.marker, drawn.channel,
        "device ids are the rank of the marker polygon, ascending"
    );

    let (first, roles) = devices.terminals_of(DeviceId(0));
    assert_eq!(
        roles,
        [
            TerminalRole::Gate,
            TerminalRole::Source,
            TerminalRole::Drain
        ],
        "terminal roles follow the recogniser's terminal order"
    );
    assert_eq!(
        first,
        [
            nets.net_of(drawn.gate[0]),
            nets.net_of(drawn.active[0]),
            nets.net_of(drawn.active[1])
        ],
        "the left finger is gated by the poly at x 200 and flanked by the \
         first two diffusion regions"
    );

    let (second, _) = devices.terminals_of(DeviceId(1));
    assert_eq!(
        second,
        [
            nets.net_of(drawn.gate[1]),
            nets.net_of(drawn.active[1]),
            nets.net_of(drawn.active[2])
        ],
        "the right finger is gated by the poly at x 600 and flanked by the \
         last two diffusion regions"
    );
    assert_eq!(
        first[2], second[1],
        "the middle diffusion region is the first finger's drain and the \
         second's source, which is what makes them a series pair"
    );

    // The marker is the device's extent. Its area is W x L — on the implant it
    // was the whole active region, 33x too large, the measuring half of F8 —
    // and the flanking diffusion is offset in x, which names x the channel
    // axis: L = 50 along the current, W = 200 across it. One channel is one
    // finger, and the marker's perimeter is 2 (W + L).
    assert_eq!(
        devices.params_of(DeviceId(0)),
        [
            (
                DeviceParam::Width,
                DeviceMeasure::Length(gpurify_geom::Dbu::new_unchecked(200))
            ),
            (
                DeviceParam::Length,
                DeviceMeasure::Length(gpurify_geom::Dbu::new_unchecked(50))
            ),
            (DeviceParam::Fingers, DeviceMeasure::Count(1)),
            (
                DeviceParam::Area,
                DeviceMeasure::Area(gpurify_geom::DbuArea::new(50 * 200))
            ),
            (
                DeviceParam::Perimeter,
                DeviceMeasure::Length(gpurify_geom::Dbu::new_unchecked(2 * (50 + 200)))
            ),
        ],
        "a channel marker measures W, L, one finger, W x L and 2 (W + L)"
    );
}

/// Oracle: construct-from-answer. A BJT's three terminals are named, and the
/// names follow the recogniser's terminal order rather than the layout.
///
/// `role_at` gives `DeviceKind::Bjt` a table of `Base, Emitter, Collector`, so
/// a recogniser that lists its terminal layers in that order gets those roles
/// back. This is the whole of BJT support: recognition itself is kind-agnostic,
/// and the kind is read only to name the terminals.
#[test]
fn a_bjt_recogniser_names_its_three_terminals_base_emitter_collector() {
    const BJT_TERMINALS: [TerminalRole; 3] = [
        TerminalRole::Base,
        TerminalRole::Emitter,
        TerminalRole::Collector,
    ];

    let spec = NetlistSpec {
        nets: 3,
        devices: vec![DeviceSpec {
            kind: DeviceKind::Bjt,
            model: "npn".to_owned(),
            terminals: BJT_TERMINALS
                .iter()
                .enumerate()
                .map(|(index, &role)| (role, u32::try_from(index).expect("three terminals")))
                .collect(),
        }],
    };

    let mut strings = StrTable::default();
    let case = layout_from_netlist(&spec, Floorplan::default(), &mut strings);
    let (nets, devices) = recognise(&case, &case.recognition);

    assert_eq!(devices.len(), 1, "one marker polygon is one device");

    let (terminal_nets, roles) = devices.terminals_of(DeviceId(0));
    assert_eq!(
        roles,
        BJT_TERMINALS.as_slice(),
        "a BJT's terminals are named, not numbered — this is what distinguishes \
         it from the Pin fallback a kind with no role table receives"
    );

    let want: Vec<NetId> = (0..3)
        .map(|index: usize| nets.net_of(case.expected_net_polys[index][0]))
        .collect();
    assert_eq!(
        terminal_nets,
        want.as_slice(),
        "each named terminal landed on the net the spec wired it to"
    );
}

/// Oracle: construct-from-answer. A resistor's two terminals are `Pin`s, and
/// the variant is the claim — not the index.
///
/// `TerminalRole::Pin` is documented as either end of a symmetric two-terminal
/// device, interchangeable by definition, so the numbering is deliberately not
/// asserted: `Pin(0), Pin(1)` and `Pin(1), Pin(2)` are both legal answers and a
/// test that picked one would be pinning an unpromise. `crates/lvs/tests/graph.rs`
/// asserts the same shape on the reference side, which is what makes a layout
/// resistor and a netlist resistor comparable.
#[test]
fn a_resistor_recogniser_gives_its_two_terminals_interchangeable_pins() {
    let spec = NetlistSpec {
        nets: 2,
        devices: vec![DeviceSpec {
            kind: DeviceKind::Resistor,
            model: "res".to_owned(),
            terminals: vec![(TerminalRole::Pin(0), 0), (TerminalRole::Pin(1), 1)],
        }],
    };

    let mut strings = StrTable::default();
    let case = layout_from_netlist(&spec, Floorplan::default(), &mut strings);
    let (nets, devices) = recognise(&case, &case.recognition);

    assert_eq!(devices.len(), 1, "one marker polygon is one device");

    let (terminal_nets, roles) = devices.terminals_of(DeviceId(0));
    assert_eq!(roles.len(), 2, "a resistor has two terminals");
    for role in roles {
        assert!(
            matches!(role, TerminalRole::Pin(_)),
            "the resistor was given role {role:?}, and a symmetric two-terminal \
             device has pins"
        );
    }

    let want: Vec<NetId> = (0..2)
        .map(|index: usize| nets.net_of(case.expected_net_polys[index][0]))
        .collect();
    assert_eq!(
        terminal_nets,
        want.as_slice(),
        "the two pins landed on the two nets the spec wired them to"
    );
    assert_ne!(
        terminal_nets[0], terminal_nets[1],
        "a resistor across one net is a short, not a device"
    );
}

/// Oracle: construct-from-answer, testing-plan F16. A resistor body 1000 by
/// 200 with its two ends abutting it: its first end sits off the body's
/// centre along the body, so that is its axis, `L` = 1000 along it and `W` =
/// 200 across, whichever way round the body is drawn. Its area is 200 000
/// and its perimeter 2 (1000 + 200) = 2400, and the recogniser's `sheet` is
/// carried to the device for LVS to compute `r` from.
#[test]
fn a_resistor_body_measures_its_length_between_its_ends() {
    use gpurify_check::topology::device::{DeviceMeasure, DeviceParam};
    use gpurify_geom::{Dbu, DbuArea};
    use gpurify_ingest::deck::DeviceValue;
    const BODY: LayerId = LayerId(0);
    const END: LayerId = LayerId(1);
    let value = DeviceValue {
        sheet_ohm_sq: Some(100.0),
        ..DeviceValue::default()
    };
    let swap = |(a, b, c, d): (i64, i64, i64, i64)| (b, a, d, c);
    let along_x = [(0, 0, 1000, 200), (-300, 0, 0, 200), (1000, 0, 1300, 200)];
    for rects in [along_x, along_x.map(swap)] {
        let mut layout = LayoutBuilder::new(2);
        let (x0, y0, x1, y1) = rects[0];
        layout.rect(BODY, x0, y0, x1, y1);
        for &(x0, y0, x1, y1) in &rects[1..] {
            layout.rect(END, x0, y0, x1, y1);
        }
        let (store, _) = layout.finish();
        let connectivity = Connectivity {
            conductors: vec![END],
            intra_layer_touch: true,
            ..Connectivity::default()
        };
        let mut nets = NetTable::default();
        extract_nets_into(&store, &connectivity, &mut nets);
        let mut strings = StrTable::default();
        let recognition = DeviceRecognition {
            kind: vec![DeviceKind::Resistor],
            marker: vec![BODY],
            terminal_start: vec![0, 2],
            terminal: vec![END, END],
            model: vec![strings.intern("rpoly")],
            value: vec![value],
        };
        let mut devices = DeviceTable::default();
        recognise_into(&store, &nets, &recognition, &mut devices);
        assert_eq!(devices.len(), 1, "{rects:?}: {:?}", devices.refused);
        assert_eq!(
            devices.params_of(DeviceId(0)),
            [
                (
                    DeviceParam::Width,
                    DeviceMeasure::Length(Dbu::new_unchecked(200))
                ),
                (
                    DeviceParam::Length,
                    DeviceMeasure::Length(Dbu::new_unchecked(1000))
                ),
                (
                    DeviceParam::Area,
                    DeviceMeasure::Area(DbuArea::new(200_000))
                ),
                (
                    DeviceParam::Perimeter,
                    DeviceMeasure::Length(Dbu::new_unchecked(2400))
                ),
            ],
            "{rects:?}"
        );
        assert_eq!(devices.value, [value]);
    }
}

/// Oracle: construct-from-answer, testing-plan F85. A diode marker drawn as a
/// ring, 0..2000 square with a 200 wall, a pad on each side wall. The ring's
/// area is 2000² − 1600² = 1 440 000 and its edge both rings, 4 · 2000 +
/// 4 · 1600 = 14 400. The hole, a row of its own in the store, is part of
/// the ring and no second marker: it used to be measured as the outer square
/// alone (4 000 000 and 8000) and the hole refused as a marker binding
/// nothing.
#[test]
fn a_marker_with_a_hole_is_one_device_measured_without_the_hole() {
    use gpurify_check::topology::device::{DeviceMeasure, DeviceParam};
    use gpurify_geom::{Dbu, DbuArea};
    use gpurify_testgen::shapes::hole;
    const MARK: LayerId = LayerId(0);
    const ANODE: LayerId = LayerId(1);
    const CATHODE: LayerId = LayerId(2);
    let mut layout = LayoutBuilder::new(3);
    layout.rect(MARK, 0, 0, 2000, 2000);
    layout.shape(MARK, &hole(200, 200, 1800, 1800));
    layout.rect(ANODE, 0, 900, 200, 1100);
    layout.rect(CATHODE, 1800, 900, 2000, 1100);
    let (store, _) = layout.finish();
    let connectivity = Connectivity {
        conductors: vec![ANODE, CATHODE],
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    extract_nets_into(&store, &connectivity, &mut nets);
    let mut strings = StrTable::default();
    let recognition = DeviceRecognition {
        kind: vec![DeviceKind::Diode],
        marker: vec![MARK],
        terminal_start: vec![0, 2],
        terminal: vec![ANODE, CATHODE],
        model: vec![strings.intern("dpn")],
        value: Vec::new(),
    };
    let mut devices = DeviceTable::default();
    recognise_into(&store, &nets, &recognition, &mut devices);
    assert_eq!(devices.refused, [], "the hole was taken for a marker");
    assert_eq!(devices.len(), 1);
    assert_eq!(
        devices.params_of(DeviceId(0)),
        [
            (
                DeviceParam::Area,
                DeviceMeasure::Area(DbuArea::new(1_440_000))
            ),
            (
                DeviceParam::Perimeter,
                DeviceMeasure::Length(Dbu::new_unchecked(14_400))
            ),
        ]
    );
}

// ---------------------------------------------------------------------------
// The conduction guard: a MOS channel marker must not sit on live conductor
// area, or net extraction fuses source and drain into one net in silence.
// ---------------------------------------------------------------------------

use gpurify_check::topology::device::{refuse_conducting_channels, ChannelError};
use gpurify_geom::boolean::BooleanError;
use gpurify_geom::view::ValidityError;

/// Oracle: construct-from-answer. The [`Fingers`] layout is the *correct*
/// deck's world: the diffusion arrives split (`diff NOT poly`), so each channel
/// marker only *abuts* its two flanking regions along an edge and overlaps no
/// conductor area on the source/drain layer. Sharing an edge is how a terminal
/// is recognised at all, so the guard accepting it is not a tolerance — it is
/// the difference between area and contact that the whole split rests on.
///
/// The marker does overlap the poly gates with area; position 0 is the gate,
/// whose layer conducts *through* the channel on purpose, and the guard must
/// not read that as a short.
#[test]
fn a_channel_abutting_its_split_diffusion_passes_the_conduction_guard() {
    let drawn = Fingers::draw();
    let mut strings = StrTable::default();
    let recognition = Fingers::recogniser(Fingers::CHANNEL, &mut strings);
    let connectivity = Connectivity {
        conductors: vec![Fingers::POLY, Fingers::ACTIVE],
        intra_layer_touch: true,
        ..Connectivity::default()
    };

    assert_eq!(
        refuse_conducting_channels(&drawn.store, &connectivity, &recognition),
        Ok(()),
        "a channel that only touches the split source/drain regions is the \
         legal configuration, and refusing it would refuse every correct deck"
    );
}

/// Oracle: construct-from-answer. The pre-split deck's world: the raw
/// diffusion — one rectangle spanning the channel — is the conductor and the
/// source/drain terminal layer. `extract_nets_into` would hand both terminal
/// positions that one polygon's net and every extracted MOS would come back
/// with source shorted to drain, reported by nothing. The guard must refuse
/// this configuration naming the geometry, not extract it.
#[test]
fn a_channel_over_live_conductor_area_is_refused_naming_the_polygon() {
    const CHANNEL: LayerId = LayerId(0);
    const POLY: LayerId = LayerId(1);
    const DIFF: LayerId = LayerId(2);

    let mut layout = LayoutBuilder::new(3);
    // A marker over nothing, drawn first: row 0, outside the overlap.
    let stray = layout.rect(CHANNEL, 5_000, 0, 5_050, 200);
    let channel = layout.rect(CHANNEL, 200, 0, 250, 200);
    layout.rect(POLY, 200, -50, 250, 250);
    // One diffusion rectangle spanning the channel: the collapsing shape.
    let diff = layout.rect(DIFF, 0, 0, 500, 200);
    let (store, ids) = layout.finish();

    let mut strings = StrTable::default();
    let recognition = DeviceRecognition {
        kind: vec![DeviceKind::Mos],
        marker: vec![CHANNEL],
        terminal_start: vec![0, 3],
        terminal: vec![POLY, DIFF, DIFF],
        model: vec![strings.intern("nch")],
        value: Vec::new(),
    };
    let connectivity = Connectivity {
        conductors: vec![POLY, DIFF],
        intra_layer_touch: true,
        ..Connectivity::default()
    };

    let refused = refuse_conducting_channels(&store, &connectivity, &recognition)
        .expect_err("a channel over conducting diffusion is the silent S/D short");
    let ChannelError::ConductingChannel {
        marker,
        conductor,
        poly,
    } = refused
    else {
        panic!("the refusal must name the conducting channel, got {refused:?}");
    };
    assert_eq!(marker, CHANNEL, "the refusal names the marker layer");
    assert_eq!(conductor, DIFF, "the refusal names the source/drain layer");
    // The named polygon is the lowest store row contributing to the overlap,
    // the marker or the diffusion. The stray marker is the layer's row 0 and
    // the overlap's own first row number, but it is not under the overlap.
    assert_ne!(ids.of(stray), poly);
    assert_eq!(poly, ids.of(channel).min(ids.of(diff)));
}

/// Oracle: construct-from-answer. A non-rectilinear source/drain layer is a
/// channel overlap the rectilinear splitter cannot represent, so the guard
/// must refuse it naming the polygon rather than approximate or skip it.
#[test]
fn a_non_rectilinear_source_drain_layer_is_refused_not_split() {
    const CHANNEL: LayerId = LayerId(0);
    const POLY: LayerId = LayerId(1);
    const DIFF: LayerId = LayerId(2);

    let mut layout = LayoutBuilder::new(3);
    layout.rect(CHANNEL, 200, 0, 250, 200);
    layout.rect(POLY, 200, -50, 250, 250);
    // A triangle: every edge check the boolean runs on this layer refuses.
    let triangle = layout.push(DIFF, &[0, 500, 250], &[0, 0, 200]);
    let (store, ids) = layout.finish();

    let mut strings = StrTable::default();
    let recognition = DeviceRecognition {
        kind: vec![DeviceKind::Mos],
        marker: vec![CHANNEL],
        terminal_start: vec![0, 3],
        terminal: vec![POLY, DIFF, DIFF],
        model: vec![strings.intern("nch")],
        value: Vec::new(),
    };
    let connectivity = Connectivity {
        conductors: vec![POLY, DIFF],
        intra_layer_touch: true,
        ..Connectivity::default()
    };

    let refused = refuse_conducting_channels(&store, &connectivity, &recognition)
        .expect_err("a slanted diffusion cannot be split and must not be guessed at");
    assert_eq!(
        refused,
        ChannelError::Geometry(BooleanError::Validity(ValidityError::NotRectilinear(
            ids.of(triangle)
        ))),
        "the refusal names the polygon the splitter cannot represent"
    );
}
