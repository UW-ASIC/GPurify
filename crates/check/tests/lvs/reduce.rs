//! Series and parallel reduction: what merges, what must not, and what comes
//! through untouched.
//!
//! The corpus sees reduction end to end: `LVS_SERIES_MERGE` and
//! `LVS_PARALLEL_MERGE` assert their verdict against their own reference
//! netlists (`tests/fixtures/lvs_refs/`). These tests pin what merges, and what
//! must not, on graphs built by hand.
//!
//! # The bracket the fixtures are built around
//!
//! `LVS_SERIES` is two nmos in series with their gates strapped together and must
//! become one device; `LVS_FINGERS` is the same cell **minus that strap** — same
//! diffusion, same two gates, same contacts — and must stay two. [`series_pair`]
//! is that bracket written as one function of one argument, so the two halves
//! differ in exactly one `u32` of one column and a test over them cannot be
//! passing for some other reason.

use crate::common;

use common::{mos_and_bjt, permute, GraphBuilder, LENGTH, NCH, PCH, VSS, WIDTH};
use gpurify_check::lvs::graph::Graph;
use gpurify_check::lvs::reduce::reduce;
use gpurify_check::lvs::verdict::Verdict;
use gpurify_check::lvs::{compare, CompareOptions};
use gpurify_check::topology::TerminalRole::{self, Bulk, Drain, Gate, Pin, Source};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrId;

/// Two nmos stacked source-to-drain, with `gate_b` deciding whether the upper
/// device's gate is strapped to the lower one's.
///
/// Nets: 0 the lower gate, 1 the outer source, 2 the internal node, 3 the outer
/// drain, 4 the shared bulk, and 5 a second gate net that only the split variant
/// puts a terminal on. Both variants declare six nets, so the two halves of the
/// bracket differ in exactly one value — device 1's gate net — and in nothing
/// else at all.
fn series_pair(gate_b: u32) -> Graph {
    let mut builder = GraphBuilder::new(6);
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 4)],
    );
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(Gate, gate_b), (Source, 2), (Drain, 3), (Bulk, 4)],
    );
    builder.finish()
}

/// [`series_pair`] without the spare gate net, so the reduced graph has no
/// floating net and can be compared against a reference somebody wrote by hand.
///
/// Nets: 0 gate, 1 outer source, 2 internal, 3 outer drain, 4 bulk.
fn series_pair_tight() -> Graph {
    let mut builder = GraphBuilder::new(5);
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 4)],
    );
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 2), (Drain, 3), (Bulk, 4)],
    );
    builder.finish()
}

/// Two transistors across one pair of nets. `model_b` and the upper device's
/// two channel nets are the knobs the negative cases turn.
///
/// Nets: 0 gate, 1 source, 2 drain, 3 bulk.
fn parallel_pair(model_b: StrId, source_b: u32, drain_b: u32) -> Graph {
    let mut builder = GraphBuilder::new(4);
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)],
    );
    builder.device(
        DeviceKind::Mos,
        model_b,
        &[(Gate, 0), (Source, source_b), (Drain, drain_b), (Bulk, 3)],
    );
    builder.finish()
}

/// The `(role, net)` pairs of one device, which is what every assertion below
/// is really about.
fn terminals(graph: &Graph, device: u32) -> Vec<(TerminalRole, u32)> {
    let (nets, roles) = graph.terminals_of(device);
    roles.iter().copied().zip(nets.iter().copied()).collect()
}

/// Oracle: construct-from-answer. The fixture is two transistors whose channel
/// meets at one internal node and whose gates are strapped, which is one
/// transistor of twice the length drawn as two fingers. The merged device's
/// terminals are decided before anything runs: the gate and the bulk both sides
/// share, and the two channel ends that are *not* the internal node.
#[test]
fn two_transistors_in_series_with_tied_gates_become_one() {
    let out = reduce(&series_pair(0));

    assert_eq!(out.device_count(), 1, "the strapped pair is one device");
    // Net 2 was the internal node and is consumed; 0, 1, 3, 4, 5 rank down to
    // 0, 1, 2, 3, 4.
    assert_eq!(out.net_count(), 5, "the internal node survived the merge");
    assert_eq!(
        terminals(&out, 0),
        [(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)]
    );
    assert_eq!(out.device_kind, [DeviceKind::Mos]);
    assert_eq!(out.device_model, [NCH]);
}

/// Oracle: construct-from-answer. `LVS_FINGERS` is `LVS_SERIES` minus the strap,
/// and no merge is legal: two gates on two nets are two transistors however
/// their diffusion is drawn. This is the single most important test in the file —
/// the merge condition is only worth anything if it can say no.
#[test]
fn the_same_pair_with_its_gates_on_two_nets_stays_two_devices() {
    let src = series_pair(5);
    let out = reduce(&src);

    assert_eq!(out.device_count(), 2, "two gate nets are two transistors");
    assert_eq!(out, src, "an unreducible graph is passed through unchanged");
}

/// Oracle: construct-from-answer. Two transistors between one pair of nets are
/// one transistor of twice the width. Nothing is consumed — a parallel merge
/// drops no net — so the reduced graph is the same four nets with one device on
/// them.
#[test]
fn two_transistors_in_parallel_become_one() {
    let out = reduce(&parallel_pair(NCH, 1, 2));

    assert_eq!(out.device_count(), 1);
    assert_eq!(out.net_count(), 4, "a parallel merge consumes no net");
    assert_eq!(
        terminals(&out, 0),
        [(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)]
    );
}

/// Oracle: construct-from-answer. A MOS channel is symmetric — which end is the
/// source is decided by bias and not by layout — so the same two transistors
/// with the upper one's source and drain exchanged are still one device.
#[test]
fn a_parallel_pair_merges_with_its_channel_ends_exchanged() {
    let out = reduce(&parallel_pair(NCH, 2, 1));

    assert_eq!(out.device_count(), 1);
    assert_eq!(
        terminals(&out, 0),
        [(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)]
    );
}

/// Oracle: construct-from-answer. An nfet and a pfet wired identically are two
/// devices, and merging them would report a circuit nobody drew. Same fixture,
/// same nets, same roles: the model name is the only difference.
#[test]
fn a_different_model_on_one_side_blocks_the_parallel_merge() {
    let src = parallel_pair(PCH, 1, 2);
    let out = reduce(&src);

    assert_eq!(out.device_count(), 2, "two models are two devices");
    assert_eq!(out, src);
}

/// Oracle: construct-from-answer. A port is where the rest of the design meets
/// this cell, so the node cannot be collapsed away — whatever the two devices on
/// it look like, something outside is entitled to reach it.
#[test]
fn a_shared_node_that_is_a_port_blocks_the_series_merge() {
    let mut builder = GraphBuilder::new(6);
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 4)],
    );
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 2), (Drain, 3), (Bulk, 4)],
    );
    builder.port(2);
    let src = builder.finish();

    assert_eq!(reduce(&src).device_count(), 2, "a port is not internal");
    assert_eq!(reduce(&src), src);
}

/// Oracle: construct-from-answer. A name alone does not make a node external:
/// every reference net is named, so if a name blocked the merge the reference
/// would never series-reduce while the layout did (testing-plan F12). Only a
/// port blocks it, and `compare` turns a reference net a layout label names
/// into one.
#[test]
fn a_name_alone_does_not_block_the_series_merge() {
    let mut builder = GraphBuilder::new(6);
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 4)],
    );
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 2), (Drain, 3), (Bulk, 4)],
    );
    builder.name_net(2, VSS);
    assert_eq!(
        reduce(&builder.finish()).device_count(),
        1,
        "a named node is internal"
    );
}

/// Oracle: construct-from-answer. A third terminal on the node means current can
/// leave it, so the two channels are not in series at all and the node is not
/// the pair's private business. The capacitor is the third terminal and is
/// itself unmergeable, so the reduced graph is the three devices it started
/// with.
#[test]
fn a_shared_node_with_a_third_terminal_blocks_the_series_merge() {
    let mut builder = GraphBuilder::new(6);
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 4)],
    );
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 2), (Drain, 3), (Bulk, 4)],
    );
    builder.device(DeviceKind::Capacitor, NCH, &[(Pin(0), 2), (Pin(1), 4)]);
    let src = builder.finish();

    assert_eq!(
        reduce(&src).device_count(),
        3,
        "the node has somewhere else to go"
    );
    assert_eq!(reduce(&src), src);
}

/// Oracle: construct-from-answer. Reduction is transitive: three fingers over two
/// internal nodes are one transistor of three times the length. Both internal
/// nodes qualify in the graph as given, so this is what the grouping has to get
/// right in one pass.
///
/// Nets: 0 gate, 1 outer source, 2 and 3 the internal nodes, 4 outer drain,
/// 5 bulk.
#[test]
fn three_in_series_reduce_to_one() {
    let mut builder = GraphBuilder::new(6);
    for (source, drain) in [(1, 2), (2, 3), (3, 4)] {
        builder.device(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, source), (Drain, drain), (Bulk, 5)],
        );
    }
    let out = reduce(&builder.finish());

    assert_eq!(out.device_count(), 1);
    assert_eq!(out.net_count(), 4, "both internal nodes are consumed");
    // 0, 1, 4, 5 rank down to 0, 1, 2, 3.
    assert_eq!(
        terminals(&out, 0),
        [(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)]
    );
}

/// Oracle: construct-from-answer. Two series pairs sharing both outer nodes are
/// two devices in parallel *after* the series merge and not before it, so this is
/// the fixture that needs the fixed-point loop rather than one pass. The outer
/// nodes are ports, which is what stops the four devices being one ring.
///
/// Nets: 0 gate, 1 outer source (port), 2 and 4 the internal nodes, 3 outer drain
/// (port), 5 bulk.
#[test]
fn a_series_merge_that_creates_a_parallel_pair_reduces_again() {
    let mut builder = GraphBuilder::new(6);
    for (source, drain) in [(1, 2), (2, 3), (1, 4), (4, 3)] {
        builder.device(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, source), (Drain, drain), (Bulk, 5)],
        );
    }
    builder.port(1);
    builder.port(3);
    let out = reduce(&builder.finish());

    assert_eq!(out.device_count(), 1, "two passes, not one");
    assert_eq!(out.net_count(), 4);
    assert_eq!(out.port_net, [1, 2], "a port net was renumbered wrongly");
}

/// Oracle: law. Reduction is idempotent — a graph with nothing left to merge is
/// its own reduction, for any input. Asserted on the two shapes that do reduce,
/// because the interesting way to break it is a second pass that keeps going.
#[test]
fn reducing_an_already_reduced_graph_changes_nothing() {
    for src in [
        series_pair(0),
        parallel_pair(NCH, 1, 2),
        series_pair_tight(),
    ] {
        let once = reduce(&src);
        let twice = reduce(&once);
        assert_eq!(twice, once, "reduction is not idempotent");
    }
}

/// Oracle: law. A graph holding no merge is passed through byte-identically, in
/// every column. This is the property that lets reduction sit unconditionally in
/// front of `compare`: a design with nothing to reduce must reach the matcher as
/// the graph the extractor produced.
///
/// The empty graph is in the list because it is the one input whose CSR columns
/// are *absent* rather than holding a lone terminator, and a rebuild would give
/// it one — so it is the case the copy path exists for.
#[test]
fn an_unreducible_graph_comes_through_byte_identical() {
    for src in [
        Graph::default(),
        mos_and_bjt(),
        series_pair(5),
        parallel_pair(PCH, 1, 2),
    ] {
        assert_eq!(reduce(&src), src);
    }
}

/// Oracle: construct-from-answer. `reduce` is handed no string table, so
/// nothing here can tell `W` from `L` from `M` — and the two are not
/// interchangeable, since a parallel merge adds widths and a series merge adds
/// lengths. A device that declares a parameter therefore does not merge. Since
/// `from_layout_into` began projecting measured `w`/`l`, this refusal is also
/// what keeps the finger counts comparable: neither a sized reference card nor
/// a sized extracted finger merges, so they pair one to one.
///
/// Fail-closed: an under-reduced netlist can only put an extra unpaired device in
/// a report, never remove one, so this can cost a `Match` and can never invent
/// one. The alternative — merging and keeping one member's `W` — writes a number
/// into the graph that is wrong by a factor of the finger count.
#[test]
fn a_declared_parameter_blocks_the_merge_rather_than_being_invented() {
    let mut builder = GraphBuilder::new(4);
    for _ in 0..2 {
        builder.device_with_params(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)],
            &[(WIDTH, 1.0), (LENGTH, 0.15)],
        );
    }
    let src = builder.finish();

    assert_eq!(reduce(&src).device_count(), 2, "W was invented");
    assert_eq!(reduce(&src), src);
}

/// Oracle: law. The two devices of a merge group are exchangeable, so exchanging
/// them in the input cannot move the output. Reduction may read device order for
/// its emission order and for nothing else.
#[test]
fn exchanging_two_devices_of_one_group_does_not_move_the_result() {
    for src in [series_pair(0), series_pair_tight()] {
        let nets: Vec<u32> = (0..u32::try_from(src.net_count()).expect("small")).collect();
        let swapped = permute(&src, &[1, 0], &nets);
        assert_ne!(swapped, src, "the permutation did nothing to permute");
        assert_eq!(reduce(&swapped), reduce(&src));
    }
}

/// Oracle: construct-from-answer. The whole point of the transform: a layout that
/// drew two fingers and a reference that wrote one card are the same circuit, and
/// after reduction the matcher says so.
///
/// The reference is written on its own net numbering and in SPICE's `M`-card
/// terminal order, so the two graphs are not each other's relabelling and the
/// pairing has to come from structure. Neither side declares a parameter, which
/// is what keeps F8's `UndeclaredParam` out of the way — a reference that
/// declares `W` against a layout that declares nothing is still not a `Match`,
/// and that is correct.
#[test]
fn a_reduced_layout_matches_an_already_reduced_reference() {
    assert_eq!(
        reduce(&series_pair_tight()).device_count(),
        1,
        "the layout side did not reduce"
    );

    let mut builder = GraphBuilder::new(4);
    builder.device(
        DeviceKind::Mos,
        NCH,
        &[(Drain, 3), (Gate, 1), (Source, 0), (Bulk, 2)],
    );
    let verdict = compare(
        &series_pair_tight(),
        &builder.finish(),
        CompareOptions::default(),
    );
    assert_eq!(verdict, Verdict::Match, "{verdict:?}");
}

/// The names the sized tests merge by; `nf` and `m` are two spare ids.
const NAMES: gpurify_check::lvs::ParamNames = gpurify_check::lvs::ParamNames {
    width: Some(WIDTH),
    length: Some(LENGTH),
    fingers: Some(StrId(90)),
    multiplier: Some(StrId(91)),
};

/// Two sized fingers across one pair of nets, the upper with source and drain
/// swapped (which end is which is bias, not structure).
/// Nets: 0 gate, 1 source, 2 drain, 3 bulk.
fn sized_fingers(upper: &[(StrId, f64)]) -> Graph {
    let mut builder = GraphBuilder::new(4);
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)],
        &[(WIDTH, 2e-6), (LENGTH, 1.5e-7)],
    );
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 2), (Drain, 1), (Bulk, 3)],
        upper,
    );
    builder.finish()
}

/// Oracle: netgen's parallel law. Two fingers of one length are one device of
/// their summed width; told nothing about names, sized devices stay apart.
#[test]
fn sized_fingers_merge_summing_width_when_told_which_parameter_is_width() {
    let fingers = sized_fingers(&[(WIDTH, 3e-6), (LENGTH, 1.5e-7)]);
    assert_eq!(reduce(&fingers).device_count(), 2, "merged without names");

    let (out, merges) = gpurify_check::lvs::reduce::reduce_with(&fingers, NAMES);
    assert_eq!(out.device_count(), 1);
    let mut params = out.params_of(0).to_vec();
    params.sort_by_key(|p| p.0);
    assert_eq!(params.len(), 2);
    assert!(
        (params[0].1 - 5e-6).abs() < 1e-12 && (params[1].1 - 1.5e-7).abs() < 1e-15,
        "{params:?}"
    );
    assert_eq!(merges.len(), 1);
    assert_eq!(merges[0].kind, gpurify_check::lvs::MergeKind::Parallel);
    assert_eq!(merges[0].devices, [0, 1]);
}

/// Different lengths are different transistors, however they are wired.
#[test]
fn fingers_of_different_length_do_not_merge() {
    let fingers = sized_fingers(&[(WIDTH, 2e-6), (LENGTH, 3e-7)]);
    let (out, merges) = gpurify_check::lvs::reduce::reduce_with(&fingers, NAMES);
    assert_eq!(out.device_count(), 2);
    assert!(merges.is_empty());
}

/// Oracle: the series law. Two equal-width devices stacked through an
/// internal node, gates strapped, are one device of their summed length.
#[test]
fn a_sized_stack_merges_summing_length() {
    let mut builder = GraphBuilder::new(5);
    for (source, drain) in [(1, 2), (2, 3)] {
        builder.device_with_params(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, source), (Drain, drain), (Bulk, 4)],
            &[(WIDTH, 1e-6), (LENGTH, 1.5e-7)],
        );
    }
    let (out, merges) = gpurify_check::lvs::reduce::reduce_with(&builder.finish(), NAMES);
    assert_eq!(out.device_count(), 1);
    let mut params = out.params_of(0).to_vec();
    params.sort_by_key(|p| p.0);
    assert!(
        (params[0].1 - 1e-6).abs() < 1e-15 && (params[1].1 - 3e-7).abs() < 1e-15,
        "{params:?}"
    );
    assert_eq!(merges[0].kind, gpurify_check::lvs::MergeKind::Series);
}

/// A reference card with `m = 2` is two fingers of its width: it pairs with a
/// layout that drew them.
#[test]
fn a_multiplier_card_matches_the_fingers_it_stands_for() {
    let layout = sized_fingers(&[(WIDTH, 2e-6), (LENGTH, 1.5e-7)]);
    let mut builder = GraphBuilder::new(4);
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Drain, 2), (Gate, 0), (Source, 1), (Bulk, 3)],
        &[(WIDTH, 2e-6), (LENGTH, 1.5e-7), (StrId(91), 2.0)],
    );
    let options = CompareOptions {
        params: NAMES,
        ..CompareOptions::default()
    };
    let verdict = compare(&layout, &builder.finish(), options);
    assert_eq!(verdict, Verdict::Match, "{verdict:?}");
}
