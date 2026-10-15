//! Logic-gate reduction (`lvs recognize_gates`, catalog LVS-047): plain
//! transistors in series or in parallel on different gates become one device
//! with interchangeable gates, Silvaco Guardian's "series reduction ... with
//! different gate terminals" and its parallel twin. Each expected graph is
//! written out by hand from that definition and compared whole.

use crate::common;

use common::{GraphBuilder, NCH, PCH, RES, WIDTH};
use gpurify_check::lvs::graph::Graph;
use gpurify_check::lvs::reduce::{reduce_with, Merge, MergeKind, ParamNames};
use gpurify_check::topology::TerminalRole::{self, Bulk, Drain, Gate, Pin, Source};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrId;

/// `as`, `sa`: a diffusion and a stress name, either of which makes a
/// transistor not plain.
const AS: StrId = StrId(40);
const SA: StrId = StrId(41);

const GATES: ParamNames = ParamNames {
    width: None,
    length: None,
    fingers: None,
    multiplier: None,
    diffusion: [Some(AS), None, None, None],
    values: [None; 6],
    inductance: None,
    stress: [Some(SA), None],
    gates: true,
    relaxed: false,
};

fn mos(model: StrId, gate: u32, source: u32, drain: u32, bulk: u32) -> (StrId, Vec<(TerminalRole, u32)>) {
    (
        model,
        vec![(Gate, gate), (Source, source), (Drain, drain), (Bulk, bulk)],
    )
}

/// A graph of `nets` nets, MOS devices with parameters, and ports.
fn graph(nets: u32, devices: &[((StrId, Vec<(TerminalRole, u32)>), &[(StrId, f64)])], ports: &[u32]) -> Graph {
    let mut builder = GraphBuilder::new(nets);
    for ((model, terminals), params) in devices {
        builder.device_with_params(DeviceKind::Mos, *model, terminals, params);
    }
    for &port in ports {
        builder.port(port);
    }
    builder.finish()
}

fn gated(src: &Graph) -> (Graph, Vec<Merge>) {
    reduce_with(src, GATES)
}

const SIZE: &[(StrId, f64)] = &[(WIDTH, 1e-6)];

/// Oracle: the definition, NAND2's pull-down. nmos A (gate 0) from 2 to
/// the internal node 3, nmos B (gate 1) from 3 to 4, bulk 5. Net 3 is
/// touched by exactly the two channels and is no port, so the pair is one
/// device: gates 0 and 1 ascending, the chain's ends 2 and 4 as source and
/// drain, bulk 5; net 3 is consumed and nets above it shift down one (4 to
/// 3, 5 to 4). One series merge of rows 0 and 1.
#[test]
fn a_series_stack_on_two_gates_is_one_device_with_both_gates() {
    let src = graph(6, &[(mos(NCH, 0, 2, 3, 5), SIZE), (mos(NCH, 1, 3, 4, 5), SIZE)], &[2]);
    let (out, merges) = gated(&src);
    let mut want = GraphBuilder::new(5);
    want.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Gate, 1), (Source, 2), (Drain, 3), (Bulk, 4)],
        SIZE,
    );
    want.port(2);
    assert_eq!(out, want.finish());
    assert_eq!(
        merges,
        [Merge {
            kind: MergeKind::Series,
            model: NCH,
            devices: vec![0, 1],
        }]
    );
    // Without the control nothing merges: the gates are apart.
    let (plain, none) = reduce_with(&src, ParamNames { gates: false, ..GATES });
    assert_eq!((plain, none), (src, Vec::new()));
}

/// Oracle: the definition, NAND3's pull-down drawn out of order. Rows 0, 1
/// and 2 are the stack's top, bottom and middle, with gates 2, 0, 1, from
/// 7 through the internal nodes 3 and 4 to 5, bulk 6. One device: gates 0,
/// 1, 2 ascending, the unconsumed ends in member order (row 0's 5, then
/// row 1's 7) as source and drain; nets 3 and 4 dropped, 5, 6, 7 become 3,
/// 4, 5.
#[test]
fn a_three_stack_drawn_out_of_order_is_one_device() {
    let src = graph(
        8,
        &[
            (mos(NCH, 2, 4, 5, 6), &[]),
            (mos(NCH, 0, 7, 3, 6), &[]),
            (mos(NCH, 1, 3, 4, 6), &[]),
        ],
        &[],
    );
    let (out, merges) = gated(&src);
    // Members in row order: row 0 (4, 5), row 1 (7, 3), row 2 (3, 4); the
    // unconsumed ends in that order are 5 and 7. Nets 0, 1, 2, 5, 6, 7
    // survive as 0..=5.
    let mut want = GraphBuilder::new(6);
    want.device(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Gate, 1), (Gate, 2), (Source, 3), (Drain, 5), (Bulk, 4)],
    );
    assert_eq!(out, want.finish());
    assert_eq!(merges.len(), 1);
    assert_eq!(merges[0].devices, [0, 1, 2]);
    assert_eq!(merges[0].kind, MergeKind::Series);
}

/// Oracle: the definition, NAND2's pull-up. pmos A (gate 0) and B (gate 1)
/// both from 2 to 3, B the other way round, bulk 4: one parallel device,
/// gates ascending, the head's (row 0's) source and drain. A third pmos on
/// gate 0 too is a same-gate parallel pair, which ordinary reduction would
/// make first and this law leaves apart.
#[test]
fn a_parallel_pair_on_two_gates_is_one_device_and_a_shared_gate_is_not() {
    let src = graph(5, &[(mos(PCH, 0, 2, 3, 4), SIZE), (mos(PCH, 1, 3, 2, 4), SIZE)], &[]);
    let (out, merges) = gated(&src);
    let mut want = GraphBuilder::new(5);
    want.device_with_params(
        DeviceKind::Mos,
        PCH,
        &[(Gate, 0), (Gate, 1), (Source, 2), (Drain, 3), (Bulk, 4)],
        SIZE,
    );
    assert_eq!(out, want.finish());
    assert_eq!(
        merges,
        [Merge {
            kind: MergeKind::Parallel,
            model: PCH,
            devices: vec![0, 1],
        }]
    );

    // Same gate within the run: ordinary reduction has no W/m names here,
    // so it leaves them, and the gate law refuses a shared gate.
    let shared = graph(
        5,
        &[(mos(PCH, 0, 2, 3, 4), SIZE), (mos(PCH, 0, 3, 2, 4), SIZE)],
        &[],
    );
    assert_eq!(gated(&shared), (shared.clone(), Vec::new()));
}

/// Oracle: the module's refusals, each a pair that would be NAND2's
/// pull-down but for one thing, and so stays two devices untouched: another
/// model; a different size (a swap would move a transistor with its input);
/// a diffusion or stress parameter stated; bulks apart; the internal node a
/// port; a third terminal on the internal node; the same gate; a gate on no
/// net; a terminal of a fifth role; and a resistor in place of a
/// transistor.
#[test]
fn a_stack_breaking_any_precondition_stays_as_drawn() {
    let other = &[(WIDTH, 2e-6)][..];
    let stated = &[(WIDTH, 1e-6), (AS, 1e-12)][..];
    let stress = &[(WIDTH, 1e-6), (SA, 1e-7)][..];
    let cases: Vec<(&str, Graph)> = vec![
        (
            "model",
            graph(6, &[(mos(NCH, 0, 2, 3, 5), SIZE), (mos(PCH, 1, 3, 4, 5), SIZE)], &[]),
        ),
        (
            "size",
            graph(6, &[(mos(NCH, 0, 2, 3, 5), SIZE), (mos(NCH, 1, 3, 4, 5), other)], &[]),
        ),
        (
            "diffusion",
            graph(6, &[(mos(NCH, 0, 2, 3, 5), stated), (mos(NCH, 1, 3, 4, 5), stated)], &[]),
        ),
        (
            "stress",
            graph(6, &[(mos(NCH, 0, 2, 3, 5), stress), (mos(NCH, 1, 3, 4, 5), stress)], &[]),
        ),
        (
            "bulk",
            graph(7, &[(mos(NCH, 0, 2, 3, 5), SIZE), (mos(NCH, 1, 3, 4, 6), SIZE)], &[]),
        ),
        (
            "port",
            graph(6, &[(mos(NCH, 0, 2, 3, 5), SIZE), (mos(NCH, 1, 3, 4, 5), SIZE)], &[3]),
        ),
        (
            "same gate",
            graph(6, &[(mos(NCH, 0, 2, 3, 5), SIZE), (mos(NCH, 0, 3, 4, 5), SIZE)], &[]),
        ),
        ("third terminal", {
            let mut b = GraphBuilder::new(6);
            for (model, t) in [mos(NCH, 0, 2, 3, 5), mos(NCH, 1, 3, 4, 5)] {
                b.device_with_params(DeviceKind::Mos, model, &t, SIZE);
            }
            b.device(DeviceKind::Resistor, RES, &[(Pin(0), 3), (Pin(1), 5)]);
            b.finish()
        }),
        ("fifth role", {
            let mut b = GraphBuilder::new(7);
            b.device_with_params(
                DeviceKind::Mos,
                NCH,
                &[(Gate, 0), (Source, 2), (Drain, 3), (Bulk, 5), (Pin(0), 6)],
                SIZE,
            );
            b.device_with_params(DeviceKind::Mos, NCH, &mos(NCH, 1, 3, 4, 5).1, SIZE);
            b.finish()
        }),
        ("two gates on one", {
            let mut b = GraphBuilder::new(7);
            b.device_with_params(
                DeviceKind::Mos,
                NCH,
                &[(Gate, 0), (Gate, 6), (Source, 2), (Drain, 3), (Bulk, 5)],
                SIZE,
            );
            b.device_with_params(DeviceKind::Mos, NCH, &mos(NCH, 1, 3, 4, 5).1, SIZE);
            b.finish()
        }),
        ("not a transistor", {
            let mut b = GraphBuilder::new(6);
            b.device(DeviceKind::Resistor, NCH, &[(Gate, 0), (Source, 2), (Drain, 3), (Bulk, 5)]);
            b.device(DeviceKind::Resistor, NCH, &[(Gate, 1), (Source, 3), (Drain, 4), (Bulk, 5)]);
            b.finish()
        }),
    ];
    for (name, src) in cases {
        let (out, merges) = gated(&src);
        assert!(merges.is_empty(), "{name}: {merges:?}");
        assert_eq!(out.device_count(), src.device_count(), "{name}");
    }

    // A gate on no net: the builder cannot draw one, so detach it by hand.
    let mut floating = graph(6, &[(mos(NCH, 0, 2, 3, 5), SIZE), (mos(NCH, 1, 3, 4, 5), SIZE)], &[]);
    floating.terminal_net[0] = u32::MAX;
    // Net 0 loses its only terminal, the first of the transpose.
    floating.net_terminal.remove(0);
    for start in &mut floating.net_terminal_start[1..] {
        *start -= 1;
    }
    let (_, merges) = gated(&floating);
    assert!(merges.is_empty(), "a gate on no net: {merges:?}");
}

/// Oracle: the soundness rule. Three transistors on gates 0, 1, 2 chained
/// in a ring through nets 3, 4 and 5, each touched by exactly two channels:
/// every net joins, nothing is left as an end, so the group is no single
/// transistor and stays as drawn, its nets kept.
#[test]
fn a_ring_of_transistors_stays_as_drawn() {
    let src = graph(
        7,
        &[
            (mos(NCH, 0, 3, 4, 6), SIZE),
            (mos(NCH, 1, 4, 5, 6), SIZE),
            (mos(NCH, 2, 5, 3, 6), SIZE),
        ],
        &[],
    );
    assert_eq!(gated(&src), (src.clone(), Vec::new()));
}

/// Oracle: the definition, NAND3's pull-up: three pmos on gates 0, 1, 2,
/// all from 3 to 4, bulk 5, are one parallel device with the three gates
/// ascending and the head's ends.
#[test]
fn a_three_way_parallel_group_is_one_device() {
    let src = graph(
        6,
        &[
            (mos(PCH, 0, 3, 4, 5), SIZE),
            (mos(PCH, 1, 4, 3, 5), SIZE),
            (mos(PCH, 2, 3, 4, 5), SIZE),
        ],
        &[],
    );
    let (out, merges) = gated(&src);
    let mut want = GraphBuilder::new(6);
    want.device_with_params(
        DeviceKind::Mos,
        PCH,
        &[(Gate, 0), (Gate, 1), (Gate, 2), (Source, 3), (Drain, 4), (Bulk, 5)],
        SIZE,
    );
    assert_eq!(out, want.finish());
    assert_eq!(merges.len(), 1);
    assert_eq!(merges[0].devices, [0, 1, 2]);
}

/// Oracle: the soundness rule ("every gate its own net", "two distinct
/// nets"). A stack of three whose top and bottom share gate 0 joins pair by
/// pair (each neighbour's gate differs) but is no device with one net per
/// gate, so it stays as drawn; two transistors with source and drain both
/// on net 2, on two gates, are no device between two nets, and stay too.
#[test]
fn a_group_with_a_repeated_gate_or_one_end_stays_as_drawn() {
    let repeated = graph(
        7,
        &[
            (mos(NCH, 0, 2, 3, 6), SIZE),
            (mos(NCH, 1, 3, 4, 6), SIZE),
            (mos(NCH, 0, 4, 5, 6), SIZE),
        ],
        &[],
    );
    assert_eq!(gated(&repeated), (repeated.clone(), Vec::new()));
    let shorted = graph(
        4,
        &[(mos(PCH, 0, 2, 2, 3), SIZE), (mos(PCH, 1, 2, 2, 3), SIZE)],
        &[],
    );
    assert_eq!(gated(&shorted), (shorted.clone(), Vec::new()));
}

/// Oracle: the definition, through the comparison. A two-high stack whose
/// lower gate also drives a resistor, against a schematic of the same stack
/// with its two inputs the other way up: no renaming of nets maps one onto
/// the other (the resistor's input is next to ground in one and next to
/// the output in the other), so they differ, until the deck's `lvs
/// recognize_gates` makes each stack one device whose gates swap.
#[test]
fn the_deck_s_recognize_gates_lets_a_stack_s_inputs_swap() {
    use gpurify_check::lvs::verdict::Verdict;
    use gpurify_check::lvs::{compare_traced, CompareOptions};
    use gpurify_ingest::deck::LvsControls;
    // Nets: 0 A, 1 B, 2 out, 3 internal, 4 ground, 5 the resistor's far end.
    let stack = |lower: u32, upper: u32| {
        let mut b = GraphBuilder::new(6);
        b.device(DeviceKind::Mos, NCH, &mos(NCH, lower, 4, 3, 4).1);
        b.device(DeviceKind::Mos, NCH, &mos(NCH, upper, 3, 2, 4).1);
        b.device(DeviceKind::Resistor, RES, &[(Pin(0), 0), (Pin(0), 5)]);
        b.finish()
    };
    let (layout, reference) = (stack(0, 1), stack(1, 0));
    let options = CompareOptions::default();
    let plain = compare_traced(&layout, &reference, options, &LvsControls::default());
    assert_ne!(plain.verdict, Verdict::Match, "the inputs are not interchangeable");
    let controls = LvsControls {
        recognize_gates: true,
        ..LvsControls::default()
    };
    let gated = compare_traced(&layout, &reference, options, &controls);
    assert_eq!(gated.verdict, Verdict::Match, "{:?}", gated.verdict);
    assert_eq!(gated.reference_rows, [vec![0, 1], vec![2]]);
}

/// Oracle: the definition, a NAND2 whole. The pull-down stack and the
/// pull-up pair merge in turn, parallel first: the pull-up (rows 2, 3)
/// becomes one device, then the pull-down (rows 0, 1). The output devices
/// come ascending by their lowest row: the stack (0, 1) first.
#[test]
fn a_nand2_reduces_to_one_stack_and_one_parallel_pair() {
    // Nets: 0 A, 1 B, 2 out, 3 internal, 4 vss, 5 vdd.
    let src = graph(
        6,
        &[
            (mos(NCH, 0, 4, 3, 4), SIZE),
            (mos(NCH, 1, 3, 2, 4), SIZE),
            (mos(PCH, 0, 5, 2, 5), SIZE),
            (mos(PCH, 1, 2, 5, 5), SIZE),
        ],
        &[0, 1, 2, 4, 5],
    );
    let (out, merges) = gated(&src);
    assert_eq!(
        merges,
        [
            Merge {
                kind: MergeKind::Parallel,
                model: PCH,
                devices: vec![2, 3],
            },
            Merge {
                kind: MergeKind::Series,
                model: NCH,
                devices: vec![0, 1],
            },
        ]
    );
    // Net 3 consumed: 4 and 5 become 3 and 4.
    let mut want = GraphBuilder::new(5);
    want.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Gate, 1), (Source, 3), (Drain, 2), (Bulk, 3)],
        SIZE,
    );
    want.device_with_params(
        DeviceKind::Mos,
        PCH,
        &[(Gate, 0), (Gate, 1), (Source, 4), (Drain, 2), (Bulk, 4)],
        SIZE,
    );
    for port in [0, 1, 2, 3, 4] {
        want.port(port);
    }
    assert_eq!(out, want.finish());
}
