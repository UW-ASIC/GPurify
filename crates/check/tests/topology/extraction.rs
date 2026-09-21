//! Net extraction against layouts emitted from a netlist that was known first.
//!
//! The oracle for almost everything here is construct-from-answer.
//! `gpurify_testgen::layout_from_netlist` is handed a netlist and emits a
//! rail-and-stub floorplan realising it, so the correct partition of polygons
//! into nets — and the correct device rows over it — are fixed before any code
//! under test runs. There is no closed form for "which shapes are the same
//! conductor", and a law alone cannot tell a correct partition from a
//! plausible one, so this is the strongest oracle available to this crate.

use std::collections::BTreeSet;

use gpurify_check::topology::device::recognise_into;
use gpurify_check::topology::{
    extract_nets_into, DeviceId, DeviceTable, NetId, NetTable, TerminalRole,
};
use gpurify_geom::Evaluator;
use gpurify_geom::{LayerId, PolyId};
use gpurify_ingest::deck::{Connectivity, DeviceKind};
use gpurify_ingest::StrTable;
use gpurify_testgen::netlist::{ExpectedDevice, NetlistCase};
use gpurify_testgen::shapes::{random_rectilinear_layer, LayoutBuilder, RandomLayerSpec};
use gpurify_testgen::{layout_from_netlist, DeviceSpec, Floorplan, NetlistSpec, Rng};

/// One four-terminal MOS and one two-terminal resistor sharing two nets.
///
/// Two of the four nets carry a single terminal, and two carry terminals from
/// both devices — so the spec exercises a net that merges across devices as
/// well as one that does not. Terminal order follows the recogniser's terminal
/// list, which is the order `DeviceRecognition` states its layers in.
fn mos_and_resistor() -> NetlistSpec {
    NetlistSpec {
        nets: 4,
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
    }
}

/// Assert an extracted table reproduces the netlist the layout was built from.
///
/// Every claim the answer makes is checked, not just the count: each spec net's
/// polygons are exactly the polygons the table lists for it, in the ascending
/// order `polys_of` promises, and no two spec nets collapsed into one. A count
/// comparison would pass against an extraction that shuffled polygons between
/// nets, which is the failure this whole file exists to catch.
fn assert_extracts_to_its_netlist(case: &NetlistCase, nets: &NetTable) {
    for (index, expected) in case.expected_net_polys.iter().enumerate() {
        assert!(
            !expected.is_empty(),
            "spec net {index} has no polygons; the generator is broken, not the extractor"
        );
        let net = nets.net_of(expected[0]);
        assert_eq!(
            nets.polys_of(net),
            expected.as_slice(),
            "spec net {index} extracted to the wrong polygon set"
        );
        for &poly in expected {
            assert_eq!(
                nets.net_of(poly),
                net,
                "polygon {poly:?} left spec net {index}"
            );
            assert!(
                nets.same_net(expected[0], poly),
                "polygon {poly:?} is not the same net as the rest of spec net {index}"
            );
        }
    }

    // Two spec nets landing on one NetId is a merge, and every rail in this
    // floorplan sits in its own y band precisely so that cannot happen legally.
    let ids: Vec<NetId> = case
        .expected_net_polys
        .iter()
        .map(|polys| nets.net_of(polys[0]))
        .collect();
    let distinct: BTreeSet<NetId> = ids.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        ids.len(),
        "two spec nets extracted to one net: {ids:?}"
    );

    for (a, first) in case.expected_net_polys.iter().enumerate() {
        for (b, second) in case.expected_net_polys.iter().enumerate().skip(a + 1) {
            assert!(
                !nets.same_net(first[0], second[0]),
                "spec nets {a} and {b} are separate rails but extracted as one net"
            );
        }
    }
}

/// The whole table, rendered as values, for comparing two runs.
fn snapshot(nets: &NetTable) -> Vec<Vec<PolyId>> {
    (0..nets.net_count())
        .map(|net| {
            nets.polys_of(NetId(u32::try_from(net).expect("net count fits a u32")))
                .to_vec()
        })
        .collect()
}

/// Oracle: construct-from-answer. The headline claim of the crate — a layout
/// emitted from a netlist extracts back to that netlist, nets and devices both.
#[test]
fn a_layout_emitted_from_a_netlist_extracts_back_to_that_netlist() {
    let mut strings = StrTable::default();
    let case = layout_from_netlist(&mos_and_resistor(), Floorplan::default(), &mut strings);

    let mut nets = NetTable::default();
    extract_nets_into(&case.store, &case.connectivity, &mut nets);
    assert_extracts_to_its_netlist(&case, &nets);

    let mut devices = DeviceTable::default();
    recognise_into(
        &case.store,
        &Evaluator::default(),
        &nets,
        &case.recognition,
        &mut devices,
    );

    // `case.recognition` holds one recogniser row per device and both name the
    // same marker layer, so the expected count of two rests on a recogniser
    // firing only where every one of its terminal layers has a shape under the
    // marker. That is not decoration and it is not a guess: `terminal_net` is a
    // `Vec<NetId>` with no way to spell "this terminal landed on nothing", so a
    // recogniser matching a marker whose terminal layers are absent has no row
    // it could legally write. The MOS column carries no `Pin` stubs and the
    // resistor column no gate, so under that reading the answer is two.
    // Recorded in NEED_TESTING because the convention is derived from the
    // signature rather than stated in `DeviceRecognition`'s doc comment.
    //
    // `recognise_into` orders devices by marker polygon, so the answer is put
    // in that order before it is compared rather than being matched up by
    // searching — a search would let a device recognised twice pass.
    let mut expected: Vec<ExpectedDevice> = case.expected_devices.clone();
    expected.sort_by_key(|device| device.marker);
    assert_eq!(
        devices.len(),
        expected.len(),
        "the layout holds {} marker polygons",
        expected.len()
    );

    for (row, want) in expected.iter().enumerate() {
        let id = DeviceId(u32::try_from(row).expect("a spec written by hand is small"));
        assert_eq!(devices.marker[row], want.marker, "device {row} marker");
        assert_eq!(devices.kind[row], want.kind, "device {row} kind");
        assert_eq!(devices.model[row], want.model, "device {row} model");

        let (terminal_nets, roles) = devices.terminals_of(id);
        let want_roles: Vec<TerminalRole> = want.terminals.iter().map(|&(r, _)| r).collect();
        assert_eq!(roles, want_roles.as_slice(), "device {row} terminal roles");

        let want_nets: Vec<NetId> = want
            .terminals
            .iter()
            .map(|&(_, net)| nets.net_of(case.expected_net_polys[net as usize][0]))
            .collect();
        assert_eq!(
            terminal_nets,
            want_nets.as_slice(),
            "device {row} terminal nets"
        );
    }
}

/// Oracle: construct-from-answer. The same netlist emitted with its devices in
/// a different order is a different layout with the same electrical structure,
/// and extraction must return that structure from either. This is the property
/// that makes an extractor usable on geometry whose stream order nobody
/// controls.
#[test]
fn extraction_does_not_depend_on_the_order_the_devices_were_emitted_in() {
    let base = mos_and_resistor();
    let mut rng = Rng::new(7);
    let mut shuffled = base.clone();
    for _ in 0..8 {
        rng.shuffle(&mut shuffled.devices);
        if shuffled.devices != base.devices {
            break;
        }
    }
    assert_ne!(
        shuffled.devices, base.devices,
        "eight shuffles left the order untouched, so this test compares a spec with itself"
    );

    let mut strings = StrTable::default();
    let case = layout_from_netlist(&shuffled, Floorplan::default(), &mut strings);
    let mut nets = NetTable::default();
    extract_nets_into(&case.store, &case.connectivity, &mut nets);
    assert_extracts_to_its_netlist(&case, &nets);
}

/// Oracle: law. `NetId` is derived from a `ComponentLabel`, which is the
/// minimum polygon index in the component, and net ids index a dense CSR — so
/// the only numbering consistent with both is ascending by each net's smallest
/// polygon. That is what makes an id canonical rather than an artefact of the
/// order the union-find happened to visit edges in, and every test comparing
/// nets by id rests on it.
#[test]
fn net_ids_ascend_with_the_smallest_polygon_on_each_net() {
    let mut strings = StrTable::default();
    let case = layout_from_netlist(&mos_and_resistor(), Floorplan::default(), &mut strings);
    let mut nets = NetTable::default();
    extract_nets_into(&case.store, &case.connectivity, &mut nets);

    assert!(nets.net_count() > 0, "the layout is not empty");
    let mut previous: Option<PolyId> = None;
    for index in 0..nets.net_count() {
        let net = NetId(u32::try_from(index).expect("net count fits a u32"));
        let polys = nets.polys_of(net);
        assert!(!polys.is_empty(), "net {index} lists no polygons");
        assert!(
            polys.windows(2).all(|pair| pair[0] < pair[1]),
            "net {index} is not ascending by PolyId: {polys:?}"
        );
        if let Some(smaller) = previous {
            assert!(
                smaller < polys[0],
                "net {index} starts at {:?}, which is not above the previous net's {smaller:?}",
                polys[0]
            );
        }
        previous = Some(polys[0]);
    }
}

/// Oracle: determinism. The gate, stated at this seam: the same store extracted
/// twice, into a fresh table and into one that has already been used, and from
/// two threads at once, gives one answer. Reusing a table is the case the
/// scratch buffers in `NetTable` create — an extraction that read stale edges
/// would differ only on the second call.
#[test]
fn extraction_is_identical_across_runs_reused_tables_and_threads() {
    let mut strings = StrTable::default();
    let case = layout_from_netlist(&mos_and_resistor(), Floorplan::default(), &mut strings);

    let mut nets = NetTable::default();
    extract_nets_into(&case.store, &case.connectivity, &mut nets);
    let first = snapshot(&nets);

    // Same table again: the scratch survives, the answer must not change.
    extract_nets_into(&case.store, &case.connectivity, &mut nets);
    assert_eq!(
        snapshot(&nets),
        first,
        "a reused NetTable changed its answer"
    );

    let mut fresh = NetTable::default();
    extract_nets_into(&case.store, &case.connectivity, &mut fresh);
    assert_eq!(
        snapshot(&fresh),
        first,
        "a fresh NetTable disagreed with a reused one"
    );

    // Two extractions running at once. `extract_nets_into` takes every input in
    // its signature, so there is nothing for two of them to share; a
    // disagreement here means there is.
    let concurrent: Vec<Vec<Vec<PolyId>>> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    let mut nets = NetTable::default();
                    extract_nets_into(&case.store, &case.connectivity, &mut nets);
                    snapshot(&nets)
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("extraction panicked on a worker"))
            .collect()
    });
    assert_eq!(concurrent[0], first, "thread 0 disagreed with the main run");
    assert_eq!(concurrent[1], first, "thread 1 disagreed with the main run");
}

/// Oracle: construct-from-answer. `Connectivity::intra_layer_touch` decides
/// whether two shapes on one conductor layer are the same conductor, and the
/// two rectangles abutting at x = 1000 below are the smallest layout where the
/// flag changes the answer: one net with it on, two with it off.
///
/// The pair of runs is the point. Every other layout in this crate either has
/// nothing touching on a conductor layer (`layout_from_netlist` joins
/// everything through vias, deliberately) or has the flag on with nothing
/// touching anyway — so an extractor that ignored the flag entirely, always
/// joining or never joining, satisfies all of them. That is the fail-open
/// shape: connectivity silently wider or narrower than the deck asked for,
/// which merges two nets or splits one and is invisible downstream.
#[test]
fn intra_layer_touch_decides_whether_two_abutting_shapes_are_one_net() {
    let layer = LayerId(0);
    let mut layout = LayoutBuilder::new(1);
    let left = layout.rect(layer, 0, 0, 1_000, 200);
    let right = layout.rect(layer, 1_000, 0, 2_000, 200);
    let (store, ids) = layout.finish();
    let (left, right) = (ids.of(left), ids.of(right));

    let joined = Connectivity {
        conductors: vec![layer],
        via_cut: Vec::new(),
        via_connects: Vec::new(),
        intra_layer_touch: true,
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    extract_nets_into(&store, &joined, &mut nets);
    assert_eq!(
        nets.net_count(),
        1,
        "two shapes sharing the edge at x = 1000 are one conductor when the deck says touching connects"
    );
    assert_eq!(
        nets.polys_of(nets.net_of(left)),
        [left, right],
        "the joined net holds both rectangles, ascending"
    );
    assert!(nets.same_net(left, right));

    let split = Connectivity {
        conductors: vec![layer],
        via_cut: Vec::new(),
        via_connects: Vec::new(),
        intra_layer_touch: false,
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    extract_nets_into(&store, &split, &mut nets);
    assert_eq!(
        nets.net_count(),
        2,
        "the same two shapes are two conductors when the deck says only vias connect"
    );
    assert!(
        !nets.same_net(left, right),
        "touching joined two shapes the deck did not ask to be joined"
    );
    assert_eq!(nets.polys_of(nets.net_of(left)), [left]);
    assert_eq!(nets.polys_of(nets.net_of(right)), [right]);
}

/// Oracle: construct-from-answer over arbitrary geometry, plus the partition
/// law. `random_rectilinear_layer` places squares with a clearance that
/// guarantees no two of them touch, so the answer on geometry nobody chose is
/// still known: one net per shape. On top of that the partition law holds for
/// any input at all — every polygon appears on exactly one net, and `net_of`
/// and `polys_of` are inverses.
#[test]
fn shapes_that_touch_nothing_each_form_their_own_net() {
    let layer = LayerId(0);
    let mut rng = Rng::new(19);
    let mut layout = LayoutBuilder::new(1);
    let placed = random_rectilinear_layer(
        &mut layout,
        &mut rng,
        layer,
        (0, 0),
        RandomLayerSpec {
            cells: 24,
            cell: 400,
            density: 0.5,
        },
    );
    assert!(placed.shapes > 0, "seed 19 placed no shapes at all");
    let (store, _ids) = layout.finish();

    let connectivity = Connectivity {
        conductors: vec![layer],
        via_cut: Vec::new(),
        via_connects: Vec::new(),
        intra_layer_touch: true,
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    extract_nets_into(&store, &connectivity, &mut nets);

    assert_eq!(
        nets.net_count(),
        placed.shapes as usize,
        "{} disjoint squares must be {} nets",
        placed.shapes,
        placed.shapes
    );

    let mut seen: BTreeSet<PolyId> = BTreeSet::new();
    for index in 0..nets.net_count() {
        let net = NetId(u32::try_from(index).expect("net count fits a u32"));
        let polys = nets.polys_of(net);
        assert_eq!(
            polys.len(),
            1,
            "net {index} merged shapes that do not touch"
        );
        for &poly in polys {
            assert_eq!(nets.net_of(poly), net, "polys_of and net_of disagree");
            assert!(seen.insert(poly), "polygon {poly:?} is listed on two nets");
        }
    }
    assert_eq!(
        seen.len(),
        placed.shapes as usize,
        "the nets do not cover every polygon exactly once"
    );

    // `same_net` is the question most rules ask, and here its answer is known
    // for every pair: reflexive, and false for any two distinct shapes.
    let all: Vec<PolyId> = seen.iter().copied().collect();
    for &poly in &all {
        assert!(
            nets.same_net(poly, poly),
            "{poly:?} is not the same net as itself"
        );
    }
    for window in all.windows(2) {
        assert!(
            !nets.same_net(window[0], window[1]),
            "{:?} and {:?} do not touch but extracted as one net",
            window[0],
            window[1]
        );
        assert_eq!(
            nets.same_net(window[0], window[1]),
            nets.same_net(window[1], window[0]),
            "same_net is not symmetric"
        );
    }
}
