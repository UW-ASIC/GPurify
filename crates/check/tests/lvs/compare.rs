//! Verdicts: what a comparison concluded, and whether it is entitled to.
//!
//! Two rules from the crate's own documentation are enforced here and are the
//! reason most of these tests exist. "Mismatch" is not a result, so a
//! perturbation made in one known place must be reported in that place. And
//! there is no path from "gave up" to "matched", so a run that could not finish
//! must say [`Verdict::Inconclusive`] and a run that finished must never say it.

use crate::common;

use common::{
    assert_same_discrepancies, blames_device, blames_net, chain, differential_pair, discrepancies,
    flip, mos_and_bjt, mos_and_bjt_without_the_bjt, permute, random_graph, stacked_pair,
    stacked_pair_with_params, GraphBuilder, NCH, NPN, VDD, VSS, WIDTH,
};
use gpurify_check::lvs::refine::{Partition, TieBreak};
use gpurify_check::lvs::verdict::{Discrepancy, Inconclusive, Side, Verdict};
use gpurify_check::lvs::{compare, CompareOptions, LayoutGraph, RefGraph};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrId;
use gpurify_testgen::Rng;

/// Options that resolve every tie and never run out of rounds, so a verdict is
/// about the graphs rather than about the budget.
fn decisive() -> CompareOptions {
    CompareOptions {
        max_rounds: 512,
        tie_break: TieBreak::LowestIndex,
        param_tolerance: 1e-6,
        match_names: false,
    }
}

/// Oracle: law. A netlist compared against itself matches. This needs no
/// constructed answer and no assumption about how the matcher works, and every
/// other test in this file is a perturbation away from it.
#[test]
fn a_netlist_compared_against_itself_matches() {
    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(stacked_pair()),
        &RefGraph(stacked_pair()),
        decisive(),
        &mut scratch,
    );
    assert_eq!(verdict, Verdict::Match);
}

/// Oracle: law. The same reflexivity over graphs nobody designed. A generated
/// graph is full of the structure a matcher can trip over — several devices with
/// identical wiring, nets carrying nothing, a net carrying four terminals — and
/// none of it makes a netlist differ from itself.
#[test]
fn reflexivity_holds_over_generated_graphs() {
    for seed in 0..16u64 {
        let devices = 3 + u32::try_from(seed).expect("a small seed");
        let layout = random_graph(&mut Rng::new(seed), devices, devices + 2);
        let reference = random_graph(&mut Rng::new(seed), devices, devices + 2);

        let mut scratch = Partition::default();
        let verdict = compare(
            &LayoutGraph(layout),
            &RefGraph(reference),
            decisive(),
            &mut scratch,
        );
        assert_eq!(verdict, Verdict::Match, "seed {seed} differs from itself");
    }
}

/// Oracle: law. A relabelling is not a difference. The layout is the same
/// circuit written with its rows in another order, which is exactly what an
/// extractor hands over, and a matcher that noticed would report a mismatch on
/// every real design.
#[test]
fn relabelling_the_rows_of_a_netlist_does_not_change_the_verdict() {
    let relabelled = permute(&stacked_pair(), &[1, 0], &[3, 5, 0, 4, 2, 1]);
    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(relabelled),
        &RefGraph(stacked_pair()),
        decisive(),
        &mut scratch,
    );
    assert_eq!(verdict, Verdict::Match);
}

/// Oracle: law. Comparing A to B and B to A ask the same question from the two
/// ends, so the answers are each other's image under exchanging the sides. A
/// report that came back with `Side::Layout` where it should have said
/// `Side::Reference` names the wrong netlist as the one holding the extra
/// device, which is a wrong answer that reads like a right one.
#[test]
fn swapping_the_two_sides_reverses_every_side_in_the_report() {
    let mut scratch = Partition::default();
    let forward = compare(
        &LayoutGraph(mos_and_bjt()),
        &RefGraph(mos_and_bjt_without_the_bjt()),
        decisive(),
        &mut scratch,
    );
    let backward = compare(
        &LayoutGraph(mos_and_bjt_without_the_bjt()),
        &RefGraph(mos_and_bjt()),
        decisive(),
        &mut scratch,
    );

    let flipped: Vec<Discrepancy> = discrepancies(&forward).iter().map(flip).collect();
    assert_same_discrepancies(discrepancies(&backward), &flipped);
}

/// Oracle: construct-from-answer. One device is deleted from the reference and
/// nothing else changes, so the layout holds exactly one device the reference
/// does not, and it is the bipolar. The assertion names the side, the device
/// index and the model, because a report that got any of the three wrong is
/// what sends an engineer to the wrong instance.
#[test]
fn a_deleted_device_is_reported_as_unpaired_on_the_side_that_still_has_it() {
    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(mos_and_bjt()),
        &RefGraph(mos_and_bjt_without_the_bjt()),
        decisive(),
        &mut scratch,
    );

    let found = discrepancies(&verdict);
    assert!(
        found.contains(&Discrepancy::UnpairedDevice {
            side: Side::Layout,
            device: 1,
            model: NPN,
        }),
        "the deleted bipolar is not reported as an unpaired layout device: {found:#?}"
    );
    assert!(
        !found.iter().any(|d| blames_device(d, Side::Layout, 0)),
        "the transistor, which was not touched, is implicated: {found:#?}"
    );
    assert!(
        !found.iter().any(|d| blames_device(d, Side::Reference, 0)),
        "the reference transistor is implicated: {found:#?}"
    );
}

/// Oracle: construct-from-answer. The bipolar's three nets survive the deletion
/// of the device on them, so on the layout side they carry a terminal and on the
/// reference side they carry nothing. They are therefore the nets the layout
/// holds and the reference cannot pair, and they are nets 4, 5 and 6 exactly —
/// a claim about which rows, not about how many.
#[test]
fn the_nets_orphaned_by_a_deleted_device_are_reported_by_index() {
    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(mos_and_bjt()),
        &RefGraph(mos_and_bjt_without_the_bjt()),
        decisive(),
        &mut scratch,
    );

    let found = discrepancies(&verdict);
    let unpaired: Vec<u32> = (0..7u32)
        .filter(|&net| found.iter().any(|d| blames_net(d, Side::Layout, net)))
        .collect();
    assert_eq!(
        unpaired,
        [4, 5, 6],
        "the layout-side nets the report blames are not the bipolar's: {found:#?}"
    );
}

/// Oracle: construct-from-answer. The upper transistor's gate and source are
/// exchanged in the reference and nothing else moves. That is not a relabelling:
/// the multiset of gate-net degrees is `{1, 2}` on one side and `{1, 1}` on the
/// other, so no renaming of nets makes the two netlists the same graph and the
/// answer is a mismatch naming the device whose terminal moved.
///
/// What this test may **not** claim is that the untouched device goes unblamed.
/// Refinement colours a node by its neighbours' classes, and the moved terminal
/// changes the class of net 2, which the lower transistor's drain also lands on;
/// so the lower transistor separates from its counterpart in the same round and
/// is reported too. That is correct behaviour, not a defect, and a test
/// asserting the perturbation stays local would fail against it.
#[test]
fn a_swapped_terminal_is_blamed_on_the_device_whose_terminal_moved() {
    use gpurify_check::topology::TerminalRole::{Bulk, Drain, Gate, Source};
    use gpurify_ingest::deck::DeviceKind;

    let mut builder = GraphBuilder::new(6);
    builder.device(
        DeviceKind::Mos,
        common::NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)],
    );
    // The upper device with gate and source exchanged against `stacked_pair`.
    builder.device(
        DeviceKind::Mos,
        common::NCH,
        &[(Gate, 4), (Source, 2), (Drain, 5), (Bulk, 3)],
    );
    let swapped = builder.finish();

    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(stacked_pair()),
        &RefGraph(swapped),
        decisive(),
        &mut scratch,
    );

    let found = discrepancies(&verdict);
    assert!(!found.is_empty(), "a mismatch with nothing to act on");
    assert!(
        found
            .iter()
            .any(|d| blames_device(d, Side::Layout, 1) || blames_device(d, Side::Reference, 1)),
        "the perturbed device is not named: {found:#?}"
    );
    // Neither fixture carries a parameter or a net name, so a finding of either
    // kind is a finding about something that is not in the input.
    for discrepancy in found {
        assert!(
            !matches!(
                discrepancy,
                Discrepancy::ParameterMismatch { .. } | Discrepancy::DuplicateName { .. }
            ),
            "{discrepancy:?} names a parameter or a name, and this fixture has neither"
        );
    }
}

/// Oracle: construct-from-answer. Two structurally identical netlists whose
/// widths differ by half. The tolerance is one percent, so the difference is
/// fifty times it, which is outside under either reading of "relative" — over
/// the layout value or over the reference one. The report must therefore name
/// the parameter, both device indices and both values.
#[test]
fn a_parameter_beyond_tolerance_is_reported_with_both_values() {
    let mut options = decisive();
    options.param_tolerance = 0.01;

    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(stacked_pair_with_params(&[(WIDTH, 1.0)], &[])),
        &RefGraph(stacked_pair_with_params(&[(WIDTH, 1.5)], &[])),
        options,
        &mut scratch,
    );

    assert_same_discrepancies(
        discrepancies(&verdict),
        &[Discrepancy::ParameterMismatch {
            layout_device: 0,
            ref_device: 0,
            param: WIDTH,
            layout_value: 1.0,
            ref_value: 1.5,
        }],
    );
}

/// Oracle: physics. Finding F4, stated as the thing that has to become true.
///
/// A MOS channel is symmetric: which end is the source is decided by *bias*, not
/// by layout, so a netlist written source-for-drain describes the same circuit.
/// `LVS_CLEAN_MATCH` and `LVS_SD_PERMUTE` are the same cell against references
/// that are exact S/D swaps, and both expect `Match`.
///
/// **The anchoring is the whole fixture, not decoration**, and it is the trap
/// this repo has fallen into three times. Net 1 carries one terminal; net 2
/// carries the bipolar's base as well. So the two channel nets have different
/// degrees, no relabelling of nets maps one graph onto the other, and `Match`
/// is available only to a comparison that reads the two roles as one. A fixture
/// whose halves differ by a relabelling would return `Match` whatever
/// [`gpurify_check::lvs::refine::role_code`] does, and would measure nothing.
///
/// The reference also keeps the *slots* in `Gate, Source, Drain, Bulk` order, so
/// the swap is in the roles rather than in the terminal order — which
/// `terminal_order.rs` already covers separately.
#[test]
fn a_mos_written_source_for_drain_is_the_same_transistor() {
    use gpurify_check::topology::TerminalRole::{
        Base, Bulk, Collector, Drain, Emitter, Gate, Source,
    };
    use gpurify_ingest::deck::DeviceKind;

    let anchored = |source: u32, drain: u32| {
        let mut builder = GraphBuilder::new(6);
        builder.device(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, source), (Drain, drain), (Bulk, 3)],
        );
        // The anchor: net 2 carries a second terminal, net 1 does not.
        builder.device(
            DeviceKind::Bjt,
            NPN,
            &[(Base, 2), (Emitter, 4), (Collector, 5)],
        );
        builder.finish()
    };

    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(anchored(1, 2)),
        &RefGraph(anchored(2, 1)),
        decisive(),
        &mut scratch,
    );
    assert_eq!(
        verdict,
        Verdict::Match,
        "a MOS channel is symmetric, so a reference that calls the other end \
         the source is the same transistor"
    );
}

/// Oracle: construct-from-answer, the corpus shape of F4's second half. A SPICE
/// `M` card states four nets, so a parsed reference always carries a `Bulk`
/// terminal; a deck whose MOS recogniser binds three terminals never extracts
/// one. `drop_unextracted_bulk` removes the reference's bulk exactly then, and
/// the comparison concludes on what both sides can state.
///
/// The reference is *also* written source-for-drain and both sides declare
/// `W`/`L`: the swap must not break the parameter pairing, because the channel
/// collapse acts on the terminal join and `compare_params` keys on names.
///
/// **The anchoring is the whole fixture**: the bipolar's base on net 2 gives
/// the drain's net a degree the source's net does not have, so `Match` is
/// available only to a comparison that is genuinely S/D-interchangeable, not
/// to any relabelling.
#[test]
fn a_reference_bulk_the_deck_cannot_extract_is_dropped_and_the_swap_still_pairs() {
    use gpurify_check::topology::TerminalRole::{
        Base, Bulk, Collector, Drain, Emitter, Gate, Source,
    };

    let sized: &[(StrId, f64)] = &[(WIDTH, 2e-6), (common::LENGTH, 5e-7)];
    let anchor = |builder: &mut GraphBuilder| {
        builder.device(
            DeviceKind::Bjt,
            NPN,
            &[(Base, 2), (Emitter, 4), (Collector, 5)],
        );
    };

    // Layout: 3-terminal MOS, no bulk anywhere, measured W/L.
    let mut builder = GraphBuilder::new(6);
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2)],
        sized,
    );
    anchor(&mut builder);
    let layout = LayoutGraph(builder.finish());

    // Reference: the card's four terminals, source and drain exchanged, the
    // same declared sizes.
    let mut builder = GraphBuilder::new(6);
    builder.device_with_params(
        DeviceKind::Mos,
        NCH,
        &[(Gate, 0), (Source, 2), (Drain, 1), (Bulk, 3)],
        sized,
    );
    anchor(&mut builder);
    let mut reference = RefGraph(builder.finish());

    // Before the drop the extra Bulk neighbour splits the device classes and
    // nothing pairs — the exact corpus failure.
    let mut scratch = Partition::default();
    assert_ne!(
        compare(&layout, &reference, decisive(), &mut scratch),
        Verdict::Match,
        "a reference bulk terminal with no layout counterpart cannot pair"
    );

    gpurify_check::lvs::graph::drop_unextracted_bulk(&layout, &mut reference);
    let verdict = compare(&layout, &reference, decisive(), &mut scratch);
    assert_eq!(
        verdict,
        Verdict::Match,
        "with the unextracted bulk dropped, an S/D-swapped reference with the \
         same W/L is the same transistor"
    );

    // Fail-closed boundary: a layout that *does* extract bulk keeps the
    // reference's, and a comparison across the arity difference still reports.
    let bulked = || {
        let mut builder = GraphBuilder::new(6);
        builder.device_with_params(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)],
            sized,
        );
        anchor(&mut builder);
        builder.finish()
    };
    let bulked_layout = LayoutGraph(bulked());
    let mut bulked_reference = RefGraph(bulked());
    gpurify_check::lvs::graph::drop_unextracted_bulk(&bulked_layout, &mut bulked_reference);
    assert_eq!(
        bulked_reference.0, bulked_layout.0,
        "a layout that extracts bulk must leave the reference's bulk alone"
    );
}

/// Oracle: physics, and the guard on finding F4's fix when it lands.
///
/// `refine::role_code` collapses interchangeable roles to one code — that is how
/// `TerminalRole::Pin` makes a resistor's two ends exchangeable, and it is the
/// mechanism F4 needs for a MOS channel. This is the boundary on it.
///
/// A bipolar's emitter and collector are **not** interchangeable: the doping is
/// asymmetric and exchanging them makes a different, much worse, transistor. So
/// `Emitter` and `Collector` keep distinct codes and the exchange is a mismatch.
///
/// **The anchoring is the whole fixture, not decoration.** The MOS on net 2
/// gives that net a degree the emitter's net does not have. Without it, swapping
/// the two is a *relabelling* and `Match` is the correct answer whatever the
/// roles do — which is what the first version of this test measured, and it
/// measured nothing.
#[test]
fn a_bipolars_emitter_and_collector_are_not_interchangeable() {
    use gpurify_check::topology::TerminalRole::{
        Base, Bulk, Collector, Drain, Emitter, Gate, Source,
    };
    use gpurify_ingest::deck::DeviceKind;

    let anchored = |emitter: u32, collector: u32| {
        let mut builder = GraphBuilder::new(6);
        builder.device(
            DeviceKind::Bjt,
            NPN,
            &[(Base, 0), (Emitter, emitter), (Collector, collector)],
        );
        builder.device(
            DeviceKind::Mos,
            NCH,
            &[(Gate, 4), (Source, 2), (Drain, 5), (Bulk, 3)],
        );
        builder.finish()
    };

    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(anchored(1, 2)),
        &RefGraph(anchored(2, 1)),
        decisive(),
        &mut scratch,
    );
    assert_ne!(
        verdict,
        Verdict::Match,
        "a bipolar's emitter and collector are asymmetric, so exchanging them \
         is a different device"
    );
}

/// Oracle: the crate's own prohibition. `lvs/src/lib.rs` forbids a false
/// [`Verdict::Match`], and a reference card declaring `W` against a layout
/// device declaring nothing used to produce exactly one: the name-keyed join
/// walked the *intersection*, so zero parameters were compared and the empty
/// discrepancy list read as agreement.
///
/// This was finding F8's fail-open half. Its corpus case is
/// `LVS_PARAM_MISMATCH`; `topology` now measures `Width`/`Length` for a MOS and
/// `graph::from_layout_into` projects them, so the one-sided shape below is no
/// longer every run's shape — but it remains reachable (a reference declaring a
/// name the layout cannot measure), and must never read as agreement.
///
/// A parameter one side declares and the other does not is not evidence of
/// agreement; it is a parameter that was never checked, which is the fail-open
/// shape `docs/VOCABULARY.md` §3 names. The verdict must not be `Match`, and the
/// report must name the side that declared it.
#[test]
fn a_parameter_only_one_side_declares_is_not_evidence_of_agreement() {
    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(stacked_pair_with_params(&[], &[])),
        &RefGraph(stacked_pair_with_params(&[(WIDTH, 1.0)], &[])),
        decisive(),
        &mut scratch,
    );

    assert_ne!(
        verdict,
        Verdict::Match,
        "a reference declaring W against a layout declaring nothing compared \
         zero parameters and called it a match"
    );
    assert_same_discrepancies(
        discrepancies(&verdict),
        &[Discrepancy::UndeclaredParam {
            side: Side::Reference,
            layout_device: 0,
            ref_device: 0,
            param: WIDTH,
        }],
    );
}

/// The mirror image, so the previous test is not satisfied by a comparator that
/// only ever blames the reference. Swapping the two sides must swap the `side`
/// field and nothing else — the same law
/// `swapping_the_two_sides_reverses_every_side_in_the_report` states for
/// terminals.
#[test]
fn the_side_that_declared_the_lone_parameter_is_the_side_the_report_names() {
    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(stacked_pair_with_params(&[(WIDTH, 1.0)], &[])),
        &RefGraph(stacked_pair_with_params(&[], &[])),
        decisive(),
        &mut scratch,
    );

    assert_same_discrepancies(
        discrepancies(&verdict),
        &[Discrepancy::UndeclaredParam {
            side: Side::Layout,
            layout_device: 0,
            ref_device: 0,
            param: WIDTH,
        }],
    );
}

/// Oracle: construct-from-answer, the other side of the same boundary. Half a
/// percent apart under a one percent tolerance is a match. Without this the
/// previous test is satisfied by a comparator that reports every parameter it
/// sees, and the tolerance would not be doing anything.
#[test]
fn a_parameter_inside_tolerance_is_not_a_difference() {
    let mut options = decisive();
    options.param_tolerance = 0.01;

    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(stacked_pair_with_params(&[(WIDTH, 1.0)], &[])),
        &RefGraph(stacked_pair_with_params(&[(WIDTH, 1.005)], &[])),
        options,
        &mut scratch,
    );
    assert_eq!(verdict, Verdict::Match);
}

/// Oracle: construct-from-answer. Names are off by default, which is stated in
/// [`CompareOptions::match_names`]'s own documentation and is a behavioural
/// choice rather than a formatting one: a layout may name its nets differently
/// from its schematic, and requiring agreement turns a naming convention into an
/// LVS failure. The two graphs here differ only in what net 0 is called.
#[test]
fn the_default_options_do_not_require_the_two_sides_to_agree_on_net_names() {
    assert!(
        !CompareOptions::default().match_names,
        "names must not be compared unless a run asks for it"
    );

    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(named_stack(VDD)),
        &RefGraph(named_stack(VSS)),
        CompareOptions::default(),
        &mut scratch,
    );
    assert_eq!(verdict, Verdict::Match);
}

/// Oracle: construct-from-answer. Turning name matching on makes the same pair
/// of graphs a mismatch, and it is net 0 — the only net whose name differs —
/// that the report names.
#[test]
fn asking_for_name_matching_makes_a_renamed_net_a_difference() {
    let mut options = decisive();
    options.match_names = true;

    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(named_stack(VDD)),
        &RefGraph(named_stack(VSS)),
        options,
        &mut scratch,
    );

    let found = discrepancies(&verdict);
    assert!(
        found
            .iter()
            .any(|d| blames_net(d, Side::Layout, 0) || blames_net(d, Side::Reference, 0)),
        "the renamed net is not named in the report: {found:#?}"
    );
}

/// The stacked pair with net 0 given a name and the rest anonymous.
fn named_stack(name: gpurify_ingest::StrId) -> gpurify_check::lvs::Graph {
    let mut graph = stacked_pair();
    graph.net_name[0] = Some(name);
    graph
}

/// Oracle: construct-from-answer. A chain of twenty-four devices needs about a
/// dozen rounds and is given one, so the comparison has not finished. The
/// crate's second documented rule is that this is not a mismatch and not a
/// match; it is the round limit, said out loud.
#[test]
fn a_round_limit_reached_is_inconclusive_and_never_a_mismatch() {
    let mut options = decisive();
    options.max_rounds = 1;

    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(chain(24)),
        &RefGraph(chain(24)),
        options,
        &mut scratch,
    );
    assert_eq!(verdict, Verdict::Inconclusive(Inconclusive::RoundLimit));
}

/// Oracle: construct-from-answer. The same two graphs with room to finish do
/// match, so the previous test's verdict came from the budget and not from the
/// chain. A pair of tests, because either alone is satisfied by an
/// implementation that always returns the answer the test wants.
#[test]
fn the_same_chain_matches_once_the_round_limit_is_generous() {
    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(chain(24)),
        &RefGraph(chain(24)),
        decisive(),
        &mut scratch,
    );
    assert_eq!(verdict, Verdict::Match);
}

/// Oracle: law. Whatever the budget, a netlist compared with itself is either
/// unfinished or matched. A mismatch would be a difference the round limit
/// invented, which is the failure the `Inconclusive` variant exists to prevent.
#[test]
fn no_round_budget_makes_a_netlist_differ_from_itself() {
    for budget in 1..=20u32 {
        let mut options = decisive();
        options.max_rounds = budget;

        let mut scratch = Partition::default();
        let verdict = compare(
            &LayoutGraph(chain(24)),
            &RefGraph(chain(24)),
            options,
            &mut scratch,
        );
        assert!(
            verdict == Verdict::Match || verdict == Verdict::Inconclusive(Inconclusive::RoundLimit),
            "budget {budget} produced {verdict:?} for a netlist against itself"
        );
    }
}

/// Oracle: construct-from-answer. The same structure with the tie-break allowed
/// to fire matches, so the refusal above is the configuration talking and not
/// the circuit.
#[test]
fn the_same_symmetric_structure_matches_when_the_tie_break_may_fire() {
    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(differential_pair()),
        &RefGraph(differential_pair()),
        decisive(),
        &mut scratch,
    );
    assert_eq!(verdict, Verdict::Match);
}

/// Oracle: law, the determinism gate. The same comparison run twice returns the
/// same verdict, and running an unrelated comparison in between through the same
/// scratch buffer does not change it. Verdicts are the crate's whole output, so
/// this is where "byte-identical across two runs" lands for `lvs`.
#[test]
fn a_comparison_gives_the_same_verdict_on_every_run() {
    let mut scratch = Partition::default();
    let first = compare(
        &LayoutGraph(mos_and_bjt()),
        &RefGraph(mos_and_bjt_without_the_bjt()),
        decisive(),
        &mut scratch,
    );

    compare(
        &LayoutGraph(chain(9)),
        &RefGraph(differential_pair()),
        decisive(),
        &mut scratch,
    );

    let second = compare(
        &LayoutGraph(mos_and_bjt()),
        &RefGraph(mos_and_bjt_without_the_bjt()),
        decisive(),
        &mut scratch,
    );

    // `Verdict` derives `PartialEq`, so the two reports are compared as values.
    // The `Debug` strings this replaced would have called two discrepancy lists
    // equal on a formatting coincidence and unequal on a formatting change, and
    // `graph.rs`'s doc comment on `Graph`'s derive argues against exactly that.
    assert_eq!(
        first, second,
        "the same comparison produced two different reports"
    );
}
