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
//! `LVS_SERIES` is two nmos in series with their gates strapped together, one
//! device of their summed length; `LVS_FINGERS` is the same cell **minus that
//! strap** — same diffusion, same two gates, same contacts — and must stay
//! two. [`series_pair`] is that bracket written as one function of one
//! argument, so the two halves differ in exactly one `u32` of one column and a
//! test over them cannot be passing for some other reason. Its devices state
//! `L`, since a series merge sums it and a stack with none stays two
//! (testing-plan F67); the corpus's `LVS_SERIES_MERGE` reference states none,
//! so that case is a mismatch. So is `LVS_PARALLEL_MERGE`: its two unsized
//! fingers keep their count, `m = 2`, and its card states none (F83).

use crate::common;

use common::{mos_and_bjt, permute, GraphBuilder, LENGTH, NCH, PCH, RES, VSS, WIDTH};
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
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 4)],
        SHORT,
    );
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, gate_b), (Source, 2), (Drain, 3), (Bulk, 4)],
        SHORT,
    );
    builder.finish()
}

/// [`series_pair`] without the spare gate net, so the reduced graph has no
/// floating net and can be compared against a reference somebody wrote by hand.
///
/// Nets: 0 gate, 1 outer source, 2 internal, 3 outer drain, 4 bulk.
fn series_pair_tight() -> Graph {
    let mut builder = GraphBuilder::new(5);
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 4)],
        SHORT,
    );
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 2), (Drain, 3), (Bulk, 4)],
        SHORT,
    );
    builder.finish()
}

/// The length every stacked device here states: a series merge sums `L`,
/// and a device that states none never merges in series (testing-plan F67).
const SHORT: &[(StrId, f64)] = &[(LENGTH, 1.5e-7)];

/// [`reduce`] told which parameters are `W`, `L`, `nf` and `m`, as the
/// `gpurify` binary is.
fn reduce_sized(src: &Graph) -> Graph {
    gpurify_check::lvs::reduce::reduce_with(src, NAMES).0
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
    let out = reduce_sized(&series_pair(0));

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
    assert_eq!(out.params_of(0), [(LENGTH, 3e-7)], "the lengths add");
}

/// Oracle: construct-from-answer. `LVS_FINGERS` is `LVS_SERIES` minus the strap,
/// and no merge is legal: two gates on two nets are two transistors however
/// their diffusion is drawn. This is the single most important test in the file —
/// the merge condition is only worth anything if it can say no.
#[test]
fn the_same_pair_with_its_gates_on_two_nets_stays_two_devices() {
    let src = series_pair(5);
    let out = reduce_sized(&src);

    assert_eq!(out.device_count(), 2, "two gate nets are two transistors");
    assert_eq!(out, src, "an unreducible graph is passed through unchanged");
}

/// Oracle: construct-from-answer. Two unsized transistors between one pair of
/// nets are one transistor counted twice, `m = 2`: with no `W` to sum, the
/// count is what keeps them two (testing-plan F83). Nothing is consumed — a
/// parallel merge drops no net — so the reduced graph is the same four nets
/// with one device on them.
#[test]
fn two_transistors_in_parallel_become_one() {
    let out = reduce_sized(&parallel_pair(NCH, 1, 2));

    assert_eq!(out.device_count(), 1);
    assert_eq!(out.net_count(), 4, "a parallel merge consumes no net");
    assert_eq!(
        terminals(&out, 0),
        [(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)]
    );
    assert_eq!(out.params_of(0), [(M, 2.0)], "the count was lost");
}

/// Oracle: construct-from-answer. A MOS channel is symmetric — which end is the
/// source is decided by bias and not by layout — so the same two transistors
/// with the upper one's source and drain exchanged are still one device.
#[test]
fn a_parallel_pair_merges_with_its_channel_ends_exchanged() {
    let out = reduce_sized(&parallel_pair(NCH, 2, 1));

    assert_eq!(out.device_count(), 1);
    assert_eq!(
        terminals(&out, 0),
        [(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)]
    );
}

/// Oracle: construct-from-answer, testing-plan F83. Two unsized transistors
/// in parallel are one card of `m = 2`, and not one card stating no count:
/// that card is one transistor, so the layout's count, 2, disagrees with its
/// 1. With no `m` name the count has nowhere to go and the two stay two.
#[test]
fn unsized_parallel_transistors_match_a_counted_card_and_not_a_bare_one() {
    let options = CompareOptions {
        params: NAMES,
        ..CompareOptions::default()
    };
    let card = |params: &[(StrId, f64)]| {
        let mut builder = GraphBuilder::new(4);
        builder.device_with_params(
            DeviceKind::Mos,
            NCH,
            &[(Drain, 2), (Gate, 0), (Source, 1), (Bulk, 3)],
            params,
        );
        builder.finish()
    };
    let layout = parallel_pair(NCH, 1, 2);
    assert_eq!(
        compare(&layout, &card(&[(M, 2.0)]), options),
        Verdict::Match
    );
    assert_eq!(
        compare(&layout, &card(&[]), options),
        Verdict::Mismatch(vec![gpurify_check::lvs::Discrepancy::ParameterMismatch {
            layout_device: 0,
            ref_device: 0,
            param: M,
            layout_value: 2.0,
            ref_value: 1.0,
        }])
    );
    let uncounted = gpurify_check::lvs::ParamNames {
        multiplier: None,
        ..NAMES
    };
    let (out, merges) = gpurify_check::lvs::reduce::reduce_with(&layout, uncounted);
    assert_eq!((out.device_count(), merges.len()), (2, 0));
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
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 4)],
        SHORT,
    );
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 2), (Drain, 3), (Bulk, 4)],
        SHORT,
    );
    builder.port(2);
    let src = builder.finish();

    assert_eq!(
        reduce_sized(&src).device_count(),
        2,
        "a port is not internal"
    );
    assert_eq!(reduce_sized(&src), src);
}

/// Oracle: construct-from-answer. A name alone does not make a node external:
/// every reference net is named, so if a name blocked the merge the reference
/// would never series-reduce while the layout did (testing-plan F12). Only a
/// port blocks it, and `compare` turns a reference net a layout label names
/// into one.
#[test]
fn a_name_alone_does_not_block_the_series_merge() {
    let mut builder = GraphBuilder::new(6);
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 4)],
        SHORT,
    );
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 2), (Drain, 3), (Bulk, 4)],
        SHORT,
    );
    builder.name_net(2, VSS);
    assert_eq!(
        reduce_sized(&builder.finish()).device_count(),
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
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 4)],
        SHORT,
    );
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 2), (Drain, 3), (Bulk, 4)],
        SHORT,
    );
    builder.device(DeviceKind::Capacitor, NCH, &[(Pin(0), 2), (Pin(1), 4)]);
    let src = builder.finish();

    assert_eq!(
        reduce_sized(&src).device_count(),
        3,
        "the node has somewhere else to go"
    );
    assert_eq!(reduce_sized(&src), src);
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
        builder.device_with_params(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, source), (Drain, drain), (Bulk, 5)],
            SHORT,
        );
    }
    let out = reduce_sized(&builder.finish());

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
        builder.device_with_params(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, source), (Drain, drain), (Bulk, 5)],
            SHORT,
        );
    }
    builder.port(1);
    builder.port(3);
    let out = reduce_sized(&builder.finish());

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
        let once = reduce_sized(&src);
        let twice = reduce_sized(&once);
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
/// it one — so it is the case the copy path exists for. A parallel pair of
/// two models is the same law's case in
/// `a_different_model_on_one_side_blocks_the_parallel_merge`.
#[test]
fn an_unreducible_graph_comes_through_byte_identical() {
    for src in [Graph::default(), mos_and_bjt(), series_pair(5)] {
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
        assert_eq!(reduce_sized(&swapped), reduce_sized(&src));
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
        reduce_sized(&series_pair_tight()).device_count(),
        1,
        "the layout side did not reduce"
    );

    let mut builder = GraphBuilder::new(4);
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Drain, 3), (Gate, 1), (Source, 0), (Bulk, 2)],
        &[(LENGTH, 3e-7)],
    );
    let options = CompareOptions {
        params: NAMES,
        ..CompareOptions::default()
    };
    let verdict = compare(&series_pair_tight(), &builder.finish(), options);
    assert_eq!(verdict, Verdict::Match, "{verdict:?}");
}

/// Oracle: the decision on testing-plan F67. A series merge sums `L`, and two
/// transistors stacked with no `L` on either have nothing to sum: merged, the
/// stack would be one transistor of no stated length, which pairs with one
/// unsized card and loses the stack count. So they stay two whether or not
/// the names are given, and so does a stack only one of whose devices states
/// `L`; the stack does not match one unsized card, and does match two.
#[test]
fn an_unsized_stack_stays_two_and_does_not_match_one_unsized_card() {
    let stack = |lower: &[(StrId, f64)]| {
        let mut builder = GraphBuilder::new(5);
        builder.device_with_params(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 4)],
            lower,
        );
        builder.device(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, 2), (Drain, 3), (Bulk, 4)],
        );
        builder.finish()
    };
    for src in [stack(&[]), stack(SHORT)] {
        assert_eq!(reduce(&src), src);
        assert_eq!(reduce_sized(&src), src, "a length came from nowhere");
    }

    let options = CompareOptions {
        params: NAMES,
        ..CompareOptions::default()
    };
    let mut one = GraphBuilder::new(4);
    one.device(
        DeviceKind::Mos,
        NCH,
        &[(Drain, 3), (Gate, 1), (Source, 0), (Bulk, 2)],
    );
    let verdict = compare(&stack(&[]), &one.finish(), options);
    assert_ne!(verdict, Verdict::Match, "a stack of two matched one card");
    assert_eq!(
        compare(&stack(&[]), &stack(&[]), options),
        Verdict::Match,
        "the stack is its own schematic"
    );
}

/// The names the sized tests merge by; `nf`, `m` and the diffusions are
/// spare ids.
const NAMES: gpurify_check::lvs::ParamNames = gpurify_check::lvs::ParamNames {
    width: Some(WIDTH),
    length: Some(LENGTH),
    fingers: Some(StrId(90)),
    multiplier: Some(StrId(91)),
    diffusion: [Some(AS), Some(AD), Some(PS), Some(PD)],
};

/// [`NAMES`]'s `as`, `ad`, `ps` and `pd`.
const AS: StrId = StrId(93);
const AD: StrId = StrId(94);
const PS: StrId = StrId(95);
const PD: StrId = StrId(96);

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

/// Oracle: construct-from-answer, testing-plan F84. Each law needs only the
/// name of what it sums. Told only which parameter is `L`, two 150 nm
/// channels stacked through an internal node are one of 300 nm; told only
/// which is `W`, two 2 µm fingers in parallel are one of 4 µm. They used to
/// need both names, so a reference stating only `L` (or only `W`) left both
/// sides unmerged.
#[test]
fn each_merge_needs_only_the_name_of_what_it_sums() {
    use gpurify_check::lvs::reduce::reduce_with;
    use gpurify_check::lvs::{MergeKind, ParamNames};
    let only = |width, length| ParamNames {
        width,
        length,
        ..ParamNames::default()
    };
    let (out, merges) = reduce_with(&series_pair_tight(), only(None, Some(LENGTH)));
    assert_eq!(out.device_count(), 1);
    assert_eq!(out.params_of(0), [(LENGTH, 3e-7)]);
    assert_eq!(merges[0].kind, MergeKind::Series);

    // Two fingers stating `W` alone, the upper with source and drain swapped.
    let mut fingers = GraphBuilder::new(4);
    for (source, drain) in [(1, 2), (2, 1)] {
        fingers.device_with_params(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, source), (Drain, drain), (Bulk, 3)],
            &[(WIDTH, 2e-6)],
        );
    }
    let (out, merges) = reduce_with(&fingers.finish(), only(Some(WIDTH), None));
    assert_eq!(out.device_count(), 1);
    assert_eq!(out.params_of(0), [(WIDTH, 4e-6)]);
    assert_eq!(merges[0].kind, MergeKind::Parallel);
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

/// A resistor's `r`, a spare id the passive tests state values under.
const R_VALUE: StrId = StrId(92);
/// [`NAMES`]'s `m`.
const M: StrId = StrId(91);

/// Passives of `kind` across nets 0 and 1, one per entry of `params`.
fn passives(kind: DeviceKind, params: &[&[(StrId, f64)]]) -> Graph {
    let mut builder = GraphBuilder::new(2);
    for &stated in params {
        builder.device_with_params(kind, RES, &[(Pin(0), 0), (Pin(1), 1)], stated);
    }
    builder.finish()
}

/// One device's parameters, sorted by name.
fn sorted_params(graph: &Graph, device: u32) -> Vec<(StrId, f64)> {
    let mut params = graph.params_of(device).to_vec();
    params.sort_by_key(|p| p.0);
    params
}

/// Oracle: the law of the device, testing-plan F20. Two 1 kΩ resistors in
/// parallel are not one 1 kΩ resistor, which is what summing only `W` made
/// of them: the merge keeps the value and counts the devices, so the merged
/// device is `r = 1k, m = 2`. A missing `m` counts 1, so a third with
/// `m = 2` beside them makes `m = 4`. Every kind but MOS keeps its count
/// this way.
#[test]
fn parallel_passives_keep_their_value_and_count_the_devices() {
    for kind in [
        DeviceKind::Resistor,
        DeviceKind::Capacitor,
        DeviceKind::Diode,
    ] {
        let k = [(R_VALUE, 1e3)];
        let (out, merges) =
            gpurify_check::lvs::reduce::reduce_with(&passives(kind, &[&k, &k]), NAMES);
        assert_eq!(out.device_count(), 1, "{kind:?}");
        assert_eq!(
            sorted_params(&out, 0),
            [(M, 2.0), (R_VALUE, 1e3)],
            "{kind:?}"
        );
        assert_eq!(merges[0].devices, [0, 1]);

        let k2 = [(R_VALUE, 1e3), (M, 2.0)];
        let out = gpurify_check::lvs::reduce::reduce_with(&passives(kind, &[&k, &k, &k2]), NAMES).0;
        assert_eq!(
            sorted_params(&out, 0),
            [(M, 4.0), (R_VALUE, 1e3)],
            "{kind:?}"
        );
    }
}

/// Oracle: construct-from-answer. Values that differ are not one device,
/// and with no `m` name the count has nowhere to go, so nothing merges and
/// both stay: under-reduction, never a count lost.
#[test]
fn parallel_passives_stay_apart_when_their_values_differ_or_there_is_no_count() {
    let differ = passives(
        DeviceKind::Capacitor,
        &[&[(R_VALUE, 1e3)], &[(R_VALUE, 2e3)]],
    );
    assert_eq!(
        gpurify_check::lvs::reduce::reduce_with(&differ, NAMES)
            .0
            .device_count(),
        2
    );
    let unsized_pair = passives(DeviceKind::Capacitor, &[&[], &[]]);
    assert_eq!(reduce(&unsized_pair), unsized_pair, "no m name, no merge");
}

/// Oracle: the multiplier's definition, testing-plan F21. `m = 2` on a card
/// with no `W` is two devices in parallel and stays, where it used to be
/// dropped; an `m` of 1 is every card's count and is dropped, so stating it
/// is the same device as not. A MOS with no `W` keeps its `m` too.
#[test]
fn a_multiplier_with_no_width_is_kept_as_the_count() {
    let out = gpurify_check::lvs::reduce::reduce_with(
        &passives(DeviceKind::Capacitor, &[&[(M, 2.0)]]),
        NAMES,
    )
    .0;
    assert_eq!(out.params_of(0), [(M, 2.0)]);
    let out = gpurify_check::lvs::reduce::reduce_with(
        &passives(DeviceKind::Capacitor, &[&[(M, 1.0)]]),
        NAMES,
    )
    .0;
    assert!(out.params_of(0).is_empty(), "{:?}", out.params_of(0));

    let mut builder = GraphBuilder::new(4);
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)],
        &[(M, 2.0)],
    );
    let out = gpurify_check::lvs::reduce::reduce_with(&builder.finish(), NAMES).0;
    assert_eq!(out.params_of(0), [(M, 2.0)]);
}

/// Oracle: construct-from-answer, through the comparison. A reference card
/// `m = 2` is the two capacitors a layout drew in parallel, and is not the
/// one capacitor of another layout: that one is short of the count the card
/// states.
#[test]
fn a_counted_card_matches_two_drawn_capacitors_and_not_one() {
    let options = CompareOptions {
        params: NAMES,
        ..CompareOptions::default()
    };
    let card = passives(DeviceKind::Capacitor, &[&[(M, 2.0)]]);
    let two = passives(DeviceKind::Capacitor, &[&[], &[]]);
    assert_eq!(compare(&two, &card, options), Verdict::Match);
    let one = passives(DeviceKind::Capacitor, &[&[]]);
    assert_eq!(
        compare(&one, &card, options),
        Verdict::Mismatch(vec![gpurify_check::lvs::Discrepancy::ParameterMismatch {
            layout_device: 0,
            ref_device: 0,
            param: M,
            layout_value: 1.0,
            ref_value: 2.0,
        }])
    );
}

/// Oracle: construct-from-answer. A card without `m` is one device, whatever
/// another card states. Four capacitors drawn as two parallel pairs, on nets
/// 0-1 and 2-3, against one card on 0-1 stating no count and one on 2-3
/// stating `m = 2`: three devices against four, a mismatch. The count used to
/// be compared only where the card stated it, so the bare card passed the
/// pair's `m = 2` and the two netlists matched.
#[test]
fn a_card_without_a_count_is_one_device_whatever_another_card_states() {
    let options = CompareOptions {
        params: NAMES,
        ..CompareOptions::default()
    };
    let caps = |counts: &[Option<f64>]| {
        let mut builder = GraphBuilder::new(4);
        for (pair, count) in counts.iter().enumerate() {
            let at = 2 * u32::try_from(pair).expect("two pairs");
            let stated: Vec<(StrId, f64)> = count.iter().map(|&m| (M, m)).collect();
            builder.device_with_params(
                DeviceKind::Capacitor,
                RES,
                &[(Pin(0), at), (Pin(1), at + 1)],
                &stated,
            );
        }
        builder.finish()
    };
    let mut drawn = GraphBuilder::new(4);
    for at in [0, 0, 2, 2] {
        drawn.device(
            DeviceKind::Capacitor,
            RES,
            &[(Pin(0), at), (Pin(1), at + 1)],
        );
    }
    let drawn = drawn.finish();
    assert_ne!(
        compare(&drawn, &caps(&[None, Some(2.0)]), options),
        Verdict::Match,
        "four capacitors matched three"
    );
    assert_eq!(
        compare(&drawn, &caps(&[Some(2.0), Some(2.0)]), options),
        Verdict::Match
    );
}

/// Oracle: the parallel law, testing-plan F57. Two transistors gated by net
/// 0 whose sources and drains all sit on net 1 are on the same nets role for
/// role, so they are one transistor of their summed width, with the head's
/// terminals: its source and drain both still on net 1. Counting the distinct
/// channel nets that survive (one, not two) used to dissolve the pair, so
/// the layout's two 1 µm fingers did not match the reference's 2 µm card.
#[test]
fn parallel_transistors_with_source_and_drain_shorted_merge() {
    let shorted = |widths: &[f64]| {
        let mut builder = GraphBuilder::new(3);
        for &w in widths {
            builder.device_with_params(
                DeviceKind::Mos,
                NCH,
                &[(Gate, 0), (Source, 1), (Drain, 1), (Bulk, 2)],
                &[(WIDTH, w), (LENGTH, 1.5e-7)],
            );
        }
        builder.finish()
    };
    let (out, merges) = gpurify_check::lvs::reduce::reduce_with(&shorted(&[1e-6, 1e-6]), NAMES);
    assert_eq!(out.device_count(), 1, "{merges:?}");
    assert_eq!(
        terminals(&out, 0),
        [(Gate, 0), (Source, 1), (Drain, 1), (Bulk, 2)]
    );
    assert_eq!(sorted_params(&out, 0), [(WIDTH, 2e-6), (LENGTH, 1.5e-7)]);

    let options = CompareOptions {
        params: NAMES,
        ..CompareOptions::default()
    };
    let verdict = compare(&shorted(&[1e-6, 1e-6]), &shorted(&[2e-6]), options);
    assert_eq!(verdict, Verdict::Match, "{verdict:?}");
}

/// Oracle: construct-from-answer, testing-plan F16. A diffusion belongs to
/// its channel end. Two 1 µm fingers between nets 1 and 2, the upper with
/// source and drain swapped: the lower's source is net 1 (`as` 1, `ps` 10)
/// and drain net 2 (`ad` 2, `pd` 20); the upper's source is net 2 (`as`
/// 30, `ps` 300) and drain net 1 (`ad` 4, `pd` 40). Merged with the lower's
/// terminals, net 1 holds 1 + 4 = 5 and 10 + 40 = 50, net 2 holds 2 + 30 =
/// 32 and 20 + 300 = 320; summing name by name would say 31 and 6. A card's
/// `m = 2` multiplies its diffusions as it does its `W`, and a stack stating
/// diffusions does not merge in series, the shared one having no law.
#[test]
fn diffusions_are_summed_at_their_channel_end_and_stop_a_series_merge() {
    use gpurify_check::lvs::reduce::reduce_with;
    let finger = |builder: &mut GraphBuilder, (source, drain): (u32, u32), sd: [f64; 4]| {
        builder.device_with_params(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, source), (Drain, drain), (Bulk, 3)],
            &[
                (WIDTH, 1e-6),
                (AS, sd[0]),
                (AD, sd[1]),
                (PS, sd[2]),
                (PD, sd[3]),
            ],
        );
    };
    let mut pair = GraphBuilder::new(4);
    finger(&mut pair, (1, 2), [1.0, 2.0, 10.0, 20.0]);
    finger(&mut pair, (2, 1), [30.0, 4.0, 300.0, 40.0]);
    let (out, merges) = reduce_with(&pair.finish(), NAMES);
    assert_eq!(merges.len(), 1);
    assert_eq!(
        sorted_params(&out, 0),
        [
            (WIDTH, 2e-6),
            (AS, 5.0),
            (AD, 32.0),
            (PS, 50.0),
            (PD, 320.0)
        ]
    );

    let mut card = GraphBuilder::new(4);
    card.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)],
        &[(WIDTH, 1e-6), (AS, 1.0), (PD, 20.0), (M, 2.0)],
    );
    let out = reduce_with(&card.finish(), NAMES).0;
    assert_eq!(
        sorted_params(&out, 0),
        [(WIDTH, 2e-6), (AS, 2.0), (PD, 40.0)]
    );

    let mut stack = GraphBuilder::new(5);
    for (source, drain) in [(1, 2), (2, 3)] {
        stack.device_with_params(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, source), (Drain, drain), (Bulk, 4)],
            &[(LENGTH, 1.5e-7), (AS, 1.0), (AD, 1.0), (PS, 1.0), (PD, 1.0)],
        );
    }
    let stack = stack.finish();
    assert_eq!(reduce_with(&stack, NAMES).0, stack);
}

/// Oracle: construct-from-answer, testing-plan F16. A transistor gated by
/// net 0, its source on net 1 and drain on net 2, with 1 of diffusion on net
/// 1 and 2 on net 2; a resistor from net 1 to net 0 tells net 1 from net 2.
/// A card that writes it drain first, `as` 2 on its source (net 2) and `ad`
/// 1, is the same transistor; one with `as` 1 on net 2 is not. Compared
/// name by name, the first used to mismatch and the second to match.
#[test]
fn a_diffusion_is_compared_at_its_channel_end() {
    let options = CompareOptions {
        params: NAMES,
        ..CompareOptions::default()
    };
    let circuit = |source: u32, drain: u32, sd: [f64; 2]| {
        let mut builder = GraphBuilder::new(4);
        builder.device_with_params(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, source), (Drain, drain), (Bulk, 3)],
            &[(AS, sd[0]), (AD, sd[1])],
        );
        builder.device(DeviceKind::Resistor, RES, &[(Pin(0), 1), (Pin(0), 0)]);
        builder.finish()
    };
    let layout = circuit(1, 2, [1e-12, 2e-12]);
    assert_eq!(
        compare(&layout, &circuit(2, 1, [2e-12, 1e-12]), options),
        Verdict::Match
    );
    assert_ne!(
        compare(&layout, &circuit(2, 1, [1e-12, 2e-12]), options),
        Verdict::Match,
        "the diffusions were read at the wrong ends"
    );
}
