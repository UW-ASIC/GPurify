//! The layout-only checks, and the `RuleRun` discipline they are the crate's
//! only carrier of.
//!
//! Why: half the DRC corpus of the suite this project
//! replaced asserted only that nothing was found, so a rule that never executed
//! passed every one of them. A clean result is therefore two claims, not one —
//! *this rule ran, it examined N things, and it found nothing* — and both are
//! asserted here every time.
//!
//! The extracted tables hold private fields and offer no constructor, so most
//! of these tests run [`check_layout`] over empty tables and a hand-built graph,
//! and read back the two structural rows (`lvs.terminal_net`,
//! `lvs.terminal_count`); the last two build the tables they need.

use crate::common;

use common::{mos_and_bjt, stacked_pair};
use gpurify_check::lvs::{check_layout, intern_rule_ids, Graph};
use gpurify_check::report::{Outcome, RuleRun, Violations};
use gpurify_check::topology::{DeviceTable, NetTable, PortTable};
use gpurify_check::Design;
use gpurify_geom::GeometryStore;
use gpurify_ingest::deck::LvsControls;
use gpurify_ingest::StrTable;

/// The structural rows `check_layout` writes for `graph`, and their violations.
fn check_topology(graph: &Graph, out: &mut Violations, runs: &mut Vec<RuleRun>) {
    let mut strings = StrTable::default();
    intern_rule_ids(&mut strings);
    let mut all = Vec::new();
    check_layout(
        graph,
        Design {
            store: &GeometryStore::default(),
            nets: &NetTable::default(),
            devices: &DeviceTable::default(),
        },
        &PortTable::default(),
        (&strings, &LvsControls::default()),
        out,
        &mut all,
    );
    let structural = [
        strings.get("lvs.terminal_net"),
        strings.get("lvs.terminal_count"),
    ];
    assert_eq!(all.len(), 5, "check_layout writes five rows");
    runs.extend(
        all.into_iter()
            .filter(|run| structural.contains(&Some(run.rule))),
    );
}

/// Assert a rule reported itself as having executed over a non-empty input, and
/// that the rows it wrote are the rows it says it wrote.
///
/// The second half is a law rather than a fixture fact: `RuleRun::violations`
/// counts what the run pushed into `out`, so for a single rule over an empty
/// table the two agree by definition however many rows there are. A rule that
/// under-reports its own findings is how a summary comes back green over a
/// violation table that is not.
fn assert_ran(runs: &[RuleRun], out: &Violations, expected_violations: usize) {
    assert!(!runs.is_empty(), "the rule did not record a run at all");
    let mut reported = 0u64;
    for run in runs {
        assert_eq!(
            run.outcome,
            Outcome::Ran,
            "the rule reported {:?} over an input that is present and non-empty",
            run.outcome
        );
        reported += u64::from(run.violations);
    }
    assert!(
        runs.iter().any(|run| run.examined > 0),
        "the rule ran and examined nothing, over an input holding devices"
    );
    assert_eq!(
        reported,
        out.len() as u64,
        "the runs claim {reported} violations against {} rows in the table",
        out.len()
    );
    assert_eq!(out.len(), expected_violations);
}

/// Oracle: construct-from-answer. Every device in `stacked_pair` and
/// `mos_and_bjt` has the full terminal set its family declares — gate, source,
/// drain and bulk for a MOS, base, emitter and collector for a bipolar — and
/// every terminal names a net that exists. There is nothing structurally wrong
/// to find, and the run has to say so *while also saying it looked*.
#[test]
fn a_well_formed_graph_is_structurally_clean_and_the_check_says_it_looked() {
    for (name, graph) in [
        ("stacked pair", stacked_pair()),
        ("a MOS and a bipolar", mos_and_bjt()),
    ] {
        let mut out = Violations::default();
        let mut runs = Vec::new();
        check_topology(&graph, &mut out, &mut runs);
        assert!(out.is_empty(), "{name}: a clean graph produced findings");
        assert_ran(&runs, &out, 0);
    }
}

/// Oracle: construct-from-answer. One terminal is repointed at net 6 of a graph
/// that has six nets, numbered 0 to 5. "A terminal on no net" is the first
/// condition `check_topology`'s own documentation names, and this is the only
/// way to state it in a [`Graph`](gpurify_check::lvs::Graph): the index is out of the
/// net table's range, so nothing can be on the other end of it.
///
/// Built by writing the column directly rather than through `GraphBuilder`,
/// which refuses a terminal naming a net that does not exist — the fixture
/// builder enforcing the invariant is exactly why the invariant needs a check
/// on the extractor's output, which has no such builder in front of it.
#[test]
fn a_terminal_naming_a_net_that_does_not_exist_is_found() {
    let mut graph = stacked_pair();
    let net_count = u32::try_from(graph.net_name.len()).expect("a small fixture");
    let dangling = graph.device_terminal_start[1] as usize;
    graph.terminal_net[dangling] = net_count;

    let mut out = Violations::default();
    let mut runs = Vec::new();
    check_topology(&graph, &mut out, &mut runs);

    assert_ran(&runs, &out, 1);
}

/// Oracle: construct-from-answer, on the reporting rather than on the finding.
///
/// A graph with devices but no terminal CSR cannot be asked what each device's
/// terminal count is — the column the question is about does not exist. The
/// terminal-count check must say it could not run, and must not report a clean
/// pass over a device table it never read.
///
/// This is the file's own thesis turned on the file: the shape check inside
/// `check_topology` carries an `is_empty() ||` escape, so this graph passes it,
/// and the compact underneath then iterates `min(devices, 0)` times. Before the
/// guard, the check recorded `Ran` with `examined` equal to the device count
/// while having examined nothing — a clean result that a reader cannot tell
/// from a device table whose terminal counts are all legal.
///
/// Stated as `Refused` rather than `Skipped` because the graph is malformed
/// rather than merely missing an optional input. Both deny a pass; only one is
/// true. And asserted in **both** profiles deliberately: the `debug_assert` that
/// guarded this before was absent from exactly the build where a false clean
/// does damage.
#[test]
fn a_graph_with_devices_but_no_terminal_csr_refuses_rather_than_reporting_clean() {
    let mut graph = stacked_pair();
    assert!(
        !graph.device_kind.is_empty(),
        "the fixture must hold devices for the question to be meaningful"
    );
    graph.device_terminal_start.clear();

    let mut out = Violations::default();
    let mut runs = Vec::new();
    check_topology(&graph, &mut out, &mut runs);

    let terminal_count = runs
        .iter()
        .find(|run| run.outcome != Outcome::Ran)
        .expect("no rule reported anything other than Ran over an unreadable graph");
    assert_eq!(
        terminal_count.outcome,
        Outcome::Refused,
        "a malformed graph is refused, not skipped and not run"
    );
    assert_eq!(
        terminal_count.examined, 0,
        "a check that read no column examined nothing, and must say so"
    );
}

/// Oracle: construct-from-answer. Two touching rectangles are one net, and
/// labelling them `VDD` (the right one) and `VSS` (the left) is a short
/// between two named nets (testing-plan F13, F14). It is one
/// `lvs.net_seed_conflict` row naming both labelled shapes, `VDD`'s first
/// since `VDD` is interned first, located at that shape's first vertex
/// (90, 0) on its layer: the row says which two labels and where. With one
/// of the labels removed, the same layout has no conflict.
#[test]
fn two_names_on_one_net_are_one_seed_conflict_row_at_the_first_label() {
    use gpurify_check::lvs::graph::from_layout;
    use gpurify_check::report::Measurement;
    use gpurify_check::topology::{bind_ports_into, extract_nets_into};
    use gpurify_geom::ops::Point;
    use gpurify_geom::{Dbu, LayerId};
    use gpurify_ingest::deck::Connectivity;
    use gpurify_ingest::Provenance;
    use gpurify_testgen::LayoutBuilder;

    let metal = LayerId(0);
    let mut layout = LayoutBuilder::new(1);
    let left = layout.rect(metal, 0, 0, 100, 100);
    let right = layout.rect(metal, 90, 0, 200, 100);
    let (store, ids) = layout.finish();
    let (left, right) = (ids.of(left), ids.of(right));
    let connectivity = Connectivity {
        conductors: vec![metal],
        intra_layer_touch: true,
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    extract_nets_into(&store, &connectivity, &mut nets);
    assert!(nets.same_net(left, right), "the fixture is one net");

    let mut strings = StrTable::default();
    intern_rule_ids(&mut strings);
    let (vdd, vss) = (strings.intern("VDD"), strings.intern("VSS"));
    let rule = strings.get("lvs.net_seed_conflict").expect("interned");
    let devices = DeviceTable::default();
    let design = Design {
        store: &store,
        nets: &nets,
        devices: &devices,
    };

    for (labels, rows) in [
        (&[(right, vdd), (left, vss)][..], 1),
        (&[(right, vdd)][..], 0),
    ] {
        let mut provenance = Provenance::default();
        for &(poly, name) in labels {
            provenance.label(poly, name);
        }
        let mut ports = PortTable::default();
        bind_ports_into(&nets, &provenance, &mut ports).expect("a short binds");
        let graph = from_layout(&nets, &devices, &ports, &strings, None);
        let (mut out, mut runs) = (Violations::default(), Vec::new());
        check_layout(
            &graph,
            design,
            &ports,
            (&strings, &LvsControls::default()),
            &mut out,
            &mut runs,
        );

        let run = runs.iter().find(|run| run.rule == rule).expect("a row");
        assert_eq!(run.outcome, Outcome::Ran);
        assert_eq!(run.examined, labels.len() as u64, "every binding");
        let found: Vec<_> = (0..out.len())
            .map(|row| out.get(row))
            .filter(|row| row.rule == rule)
            .collect();
        assert_eq!(found.len(), rows, "{found:?}");
        if let Some(row) = found.first() {
            assert_eq!(row.shapes, (right, Some(left)), "VDD's shape, then VSS's");
            let at = Point {
                x: Dbu::new_unchecked(90),
                y: Dbu::new_unchecked(0),
            };
            assert_eq!((row.at, row.layer), (at, metal));
            assert_eq!(
                (row.measured, row.limit),
                (Measurement::Count(2), Measurement::Count(1))
            );
        }
    }
}

/// Oracle: construct-from-answer, testing-plan F70. Three rectangles on one
/// conductor, apart: the first unlabelled and on no device, so a floating
/// net; the other two both labelled `VDD`, one name on two nets, an open.
/// Each row is located on the shape it names, at that shape's first vertex
/// on its layer: the floating net at its rectangle's (600, 0), the open at the
/// first labelled rectangle's (200, 0), naming both labelled rectangles. Both
/// used to report no layer and the origin.
#[test]
fn a_floating_net_and_a_split_label_are_located_on_their_shapes() {
    use gpurify_check::lvs::graph::from_layout;
    use gpurify_check::report::Measurement;
    use gpurify_check::topology::{bind_ports_into, extract_nets_into};
    use gpurify_geom::ops::Point;
    use gpurify_geom::{Dbu, LayerId};
    use gpurify_ingest::deck::Connectivity;
    use gpurify_ingest::Provenance;
    use gpurify_testgen::LayoutBuilder;

    let metal = LayerId(0);
    let mut layout = LayoutBuilder::new(1);
    let lone = layout.rect(metal, 600, 0, 700, 100);
    let left = layout.rect(metal, 200, 0, 300, 100);
    let right = layout.rect(metal, 400, 0, 500, 100);
    let (store, ids) = layout.finish();
    let (lone, left, right) = (ids.of(lone), ids.of(left), ids.of(right));
    let connectivity = Connectivity {
        conductors: vec![metal],
        intra_layer_touch: true,
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    extract_nets_into(&store, &connectivity, &mut nets);

    let mut strings = StrTable::default();
    intern_rule_ids(&mut strings);
    let vdd = strings.intern("VDD");
    let mut provenance = Provenance::default();
    provenance.label(left, vdd);
    provenance.label(right, vdd);
    let mut ports = PortTable::default();
    bind_ports_into(&nets, &provenance, &mut ports).expect("an open binds");
    let devices = DeviceTable::default();
    let design = Design {
        store: &store,
        nets: &nets,
        devices: &devices,
    };
    let graph = from_layout(&nets, &devices, &ports, &strings, None);
    let (mut out, mut runs) = (Violations::default(), Vec::new());
    check_layout(
        &graph,
        design,
        &ports,
        (&strings, &LvsControls::default()),
        &mut out,
        &mut runs,
    );

    let point = |x| Point {
        x: Dbu::new_unchecked(x),
        y: Dbu::new_unchecked(0),
    };
    for (name, shapes, at, counts) in [
        ("lvs.floating_net", (lone, None), point(600), (0, 1)),
        (
            "lvs.label_conflict",
            (left, Some(right)),
            point(200),
            (2, 1),
        ),
    ] {
        let rule = strings.get(name).expect("interned");
        let found: Vec<_> = (0..out.len())
            .map(|row| out.get(row))
            .filter(|row| row.rule == rule)
            .collect();
        assert_eq!(found.len(), 1, "{name}: {found:?}");
        let row = found[0];
        assert_eq!(row.shapes, shapes, "{name}");
        assert_eq!((row.at, row.layer), (at, metal), "{name}");
        assert_eq!(
            (row.measured, row.limit),
            (Measurement::Count(counts.0), Measurement::Count(counts.1)),
            "{name}"
        );
    }
}

/// Oracle: construct-from-answer, testing-plan F32. A marker recognition
/// refused, here with 2 of its 3 terminals bound, never reaches the graph,
/// so `lvs.terminal_net` reads it from the device table: one row on the
/// marker, at its first vertex (200, 0) on its layer, measuring the 2
/// terminals bound against the 3 listed. It examines the refused marker too.
#[test]
fn a_refused_marker_is_one_terminal_net_row_on_the_marker() {
    use gpurify_check::report::Measurement;
    use gpurify_geom::ops::Point;
    use gpurify_geom::{Dbu, LayerId};
    use gpurify_testgen::LayoutBuilder;

    let layer = LayerId(0);
    let mut layout = LayoutBuilder::new(1);
    let marker = layout.rect(layer, 200, 0, 250, 200);
    let (store, ids) = layout.finish();
    let marker = ids.of(marker);
    let mut devices = DeviceTable::default();
    devices.refused.push((marker, 2, 3));

    let mut strings = StrTable::default();
    intern_rule_ids(&mut strings);
    let rule = strings.get("lvs.terminal_net").expect("interned");
    let (mut out, mut runs) = (Violations::default(), Vec::new());
    check_layout(
        &Graph::default(),
        Design {
            store: &store,
            nets: &NetTable::default(),
            devices: &devices,
        },
        &PortTable::default(),
        (&strings, &LvsControls::default()),
        &mut out,
        &mut runs,
    );

    let run = runs.iter().find(|run| run.rule == rule).expect("a row");
    assert_eq!(
        (run.outcome, run.examined, run.violations),
        (Outcome::Ran, 1, 1)
    );
    let row = out.get(0);
    assert_eq!(row.rule, rule);
    assert_eq!(row.shapes, (marker, None));
    let at = Point {
        x: Dbu::new_unchecked(200),
        y: Dbu::new_unchecked(0),
    };
    assert_eq!((row.at, row.layer), (at, layer));
    assert_eq!(
        (row.measured, row.limit),
        (Measurement::Count(2), Measurement::Count(3))
    );
}

/// Oracle: the definition (`unpaired_instances`' rustdoc), by hand. Four
/// placements in flattening order: `X0` over rows 1..3, `X1` over 3..5
/// and `X1.X2` inside it over 4..5, and `X3` over 5..6, whose one row the
/// deck left out. Reduced device 1 stands for rows 1 and 2, merged. Rows 3
/// and 4 unpaired name `X1` alone, measured 2, not `X1.X2` again; row 4
/// alone names only `X1.X2`; device 1 unpaired names `X0` with both its
/// rows; row 0, placed by no instance, names nothing; `X3`, holding no row
/// the comparison kept, is never named, and nor is anything for an
/// unpaired layout device. Breaks if an inner placement is named under an
/// outer one, a partly paired one is named, or a merged device's rows are
/// not all read.
#[test]
fn an_instance_is_named_when_every_device_it_placed_is_unpaired() {
    use gpurify_check::lvs::verdict::{Discrepancy, Side};
    use gpurify_check::lvs::{unpaired_instances, UnpairedInstance};
    use gpurify_ingest::netlist::Placement;
    use gpurify_ingest::StrId;
    let placement = |devices: std::ops::Range<u32>| Placement {
        path: StrId(0),
        cell: StrId(0),
        devices,
    };
    let placements = [
        placement(1..3),
        placement(3..5),
        placement(4..5),
        placement(5..6),
    ];
    // Reduced device d stands for these rows; row 5 was left out.
    let rows = vec![vec![0], vec![1, 2], vec![3], vec![4]];
    let unpaired = |devices: &[u32]| -> Vec<Discrepancy> {
        devices
            .iter()
            .map(|&device| Discrepancy::UnpairedDevice {
                side: Side::Reference,
                device,
                model: StrId(0),
            })
            .collect()
    };
    let found = |devices: &[u32]| unpaired_instances(&unpaired(devices), &rows, &placements);
    let named = |placement, devices| UnpairedInstance { placement, devices };
    assert_eq!(found(&[2, 3]), [named(1, 2)]);
    assert_eq!(found(&[3]), [named(2, 1)]);
    assert_eq!(found(&[1]), [named(0, 2)]);
    assert!(found(&[0]).is_empty());
    let layout_side = [Discrepancy::UnpairedDevice {
        side: Side::Layout,
        device: 3,
        model: StrId(0),
    }];
    assert!(unpaired_instances(&layout_side, &rows, &placements).is_empty());
}
