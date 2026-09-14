//! Verdicts: what a comparison concluded, and whether it is entitled to.
//!
//! Two rules from the crate's own documentation are enforced here and are the
//! reason most of these tests exist. "Mismatch" is not a result, so a
//! perturbation made in one known place must be reported in that place. And
//! there is no path from "gave up" to "matched", so a run that could not finish
//! must say [`Verdict::Inconclusive`] and a run that finished must never say it.

mod common;

use common::{
    assert_same_discrepancies, blames_device, blames_net, chain, differential_pair, discrepancies,
    flip, mos_and_bjt, mos_and_bjt_without_the_bjt, permute, random_graph, stacked_pair,
    stacked_pair_with_params, GraphBuilder, NCH, NPN, PCH, RES, VDD, VSS, WIDTH,
};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::StrId;
use gpurify_lvs::compare::interpret;
use gpurify_lvs::refine::{ClassId, Partition, TieBreak};
use gpurify_lvs::verdict::{Discrepancy, Inconclusive, Side, Verdict};
use gpurify_lvs::{compare, CompareOptions, Graph, LayoutGraph, RefGraph};
use gpurify_testgen::Rng;
use gpurify_topology::TerminalRole;

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
        !found
            .iter()
            .any(|d| blames_device(d, Side::Reference, 0)),
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
    use gpurify_ingest::deck::DeviceKind;
    use gpurify_topology::TerminalRole::{Bulk, Drain, Gate, Source};

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

/// One device, stated kind and model, on as many pins as `roles` names.
///
/// The minimum fixture for a device-identity check. Both sides get the same
/// terminal count, the same roles and the same nets, so *structure* cannot tell
/// them apart and the only thing left to disagree about is what the device is.
fn lone_device(kind: DeviceKind, model: StrId, roles: &[TerminalRole]) -> Graph {
    let nets = u32::try_from(roles.len()).expect("a handful of terminals");
    let terminals: Vec<(TerminalRole, u32)> =
        roles.iter().copied().zip(0..nets).collect();
    let mut builder = GraphBuilder::new(nets);
    builder.device(kind, model, &terminals);
    builder.finish()
}

/// The pairing that pairs node `n` with node `n`, stated rather than refined.
///
/// [`interpret`] is `pub` and documented as the part worth a table of
/// constructed cases, so this is the input that table is written in. Every node
/// lands in a class of its own, so every class resolves and every node pairs.
fn identity_partition(nodes: u32) -> Partition {
    let classes: Vec<ClassId> = (0..nodes).map(ClassId).collect();
    Partition::from_classes(classes.clone(), classes)
}

/// Oracle: the crate's own prohibition. `lvs/src/lib.rs` forbids a false
/// [`Verdict::Match`], and until [`interpret`] read the device columns it
/// produced one here: an nfet paired with a pfet, wired identically, came back
/// `Match`.
///
/// Refinement folds the model into its signature, so a pairing it *proposes*
/// almost never crosses two models — but `wrapping_add` over neighbour hashes is
/// a hash agreeing, not a comparison happening, and `interpret` is `pub`
/// precisely so a partition it did not produce can be handed to it. The terminal
/// join proves the two devices sit in the same *place*; nothing proved they are
/// the same *thing*.
///
/// Reported as two unpaired devices, one per side, which is the reading
/// `compare_net_name` already takes for a renamed net: the pair of rows carries
/// both model names, so the report says NCH against PCH.
#[test]
fn a_paired_device_whose_model_disagrees_is_not_a_match() {
    use TerminalRole::{Bulk, Drain, Gate, Source};
    const MOS: [TerminalRole; 4] = [Gate, Source, Drain, Bulk];

    let layout = LayoutGraph(lone_device(DeviceKind::Mos, NCH, &MOS));
    let reference = RefGraph(lone_device(DeviceKind::Mos, PCH, &MOS));
    // One device and four nets.
    let paired = identity_partition(5);

    let verdict = interpret(&layout, &reference, &paired, decisive());
    assert_ne!(
        verdict,
        Verdict::Match,
        "an nfet paired with a pfet, wired identically, came back matched"
    );
    assert_same_discrepancies(
        discrepancies(&verdict),
        &[
            Discrepancy::UnpairedDevice {
                side: Side::Layout,
                device: 0,
                model: NCH,
            },
            Discrepancy::UnpairedDevice {
                side: Side::Reference,
                device: 0,
                model: PCH,
            },
        ],
    );
}

/// Oracle: the same prohibition, on the other identity column. A resistor and a
/// capacitor across one pair of nets have the same neighbourhood, the same
/// terminal count and the same `Pin` roles — [`refine::role_code`] collapses
/// `Pin(_)` on purpose — so [`gpurify_lvs::Graph::device_kind`] is the only
/// thing that distinguishes them, and it was never read.
#[test]
fn a_paired_device_whose_kind_disagrees_is_not_a_match() {
    const PINS: [TerminalRole; 2] = [TerminalRole::Pin(0), TerminalRole::Pin(1)];

    let layout = LayoutGraph(lone_device(DeviceKind::Resistor, RES, &PINS));
    let reference = RefGraph(lone_device(DeviceKind::Capacitor, RES, &PINS));
    // One device and two nets.
    let paired = identity_partition(3);

    let verdict = interpret(&layout, &reference, &paired, decisive());
    assert_ne!(
        verdict,
        Verdict::Match,
        "a resistor paired with a capacitor came back matched"
    );
}

/// Oracle: construct-from-answer, and the discrimination guard on the two tests
/// above. The same stated pairing over two devices that *do* agree on kind and
/// model is a match, so neither test above is satisfied by a comparator that
/// reports every paired device it looks at.
#[test]
fn a_stated_pairing_of_two_agreeing_devices_is_still_a_match() {
    use TerminalRole::{Bulk, Drain, Gate, Source};
    const MOS: [TerminalRole; 4] = [Gate, Source, Drain, Bulk];

    let verdict = interpret(
        &LayoutGraph(lone_device(DeviceKind::Mos, NCH, &MOS)),
        &RefGraph(lone_device(DeviceKind::Mos, NCH, &MOS)),
        &identity_partition(5),
        decisive(),
    );
    assert_eq!(verdict, Verdict::Match);
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
/// [`gpurify_lvs::refine::role_code`] does, and would measure nothing.
///
/// The reference also keeps the *slots* in `Gate, Source, Drain, Bulk` order, so
/// the swap is in the roles rather than in the terminal order — which
/// `terminal_order.rs` already covers separately.
#[test]
fn a_mos_written_source_for_drain_is_the_same_transistor() {
    use gpurify_ingest::deck::DeviceKind;
    use gpurify_topology::TerminalRole::{Base, Bulk, Collector, Drain, Emitter, Gate, Source};

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
    use gpurify_ingest::deck::DeviceKind;
    use gpurify_topology::TerminalRole::{Base, Bulk, Collector, Drain, Emitter, Gate, Source};

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
/// This is finding F8. The corpus case is `LVS_PARAM_MISMATCH`, where
/// `topology` emits only `DeviceParam::Area` and `graph::from_layout_into`
/// projects no layout parameter at all — so every parametric LVS run in the
/// tree compared nothing and said `Match`.
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
fn named_stack(name: gpurify_ingest::StrId) -> gpurify_lvs::Graph {
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
            verdict == Verdict::Match
                || verdict == Verdict::Inconclusive(Inconclusive::RoundLimit),
            "budget {budget} produced {verdict:?} for a netlist against itself"
        );
    }
}

/// Oracle: construct-from-answer. The two halves of a differential pair are
/// interchangeable, so a run configured not to guess must say so rather than
/// pick one. `Mismatch` would be wrong — the netlists agree — and `Match` would
/// be a pairing the run was told not to make.
#[test]
fn refusing_a_tie_on_a_symmetric_structure_is_inconclusive_rather_than_a_guess() {
    let mut options = decisive();
    options.tie_break = TieBreak::Refuse;

    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(differential_pair()),
        &RefGraph(differential_pair()),
        options,
        &mut scratch,
    );
    assert_eq!(
        verdict,
        Verdict::Inconclusive(Inconclusive::UnresolvedSymmetry)
    );
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

/// Oracle: construct-from-answer, and the second half of finding F4.
///
/// The layout holds a bipolar the reference does not, *and* — once a MOS channel
/// reads as symmetric — the surviving transistor's two channel nets are
/// interchangeable. Under [`TieBreak::Refuse`] that symmetry stays unbroken, so
/// the partition handed to `interpret` carries a balanced unresolved class and an
/// imbalanced one at the same time.
///
/// An unbroken symmetry used to abort the whole reading: `interpret` returned
/// `Inconclusive(UnresolvedSymmetry)` on the first balanced class it saw and the
/// deleted bipolar went unreported. The two conditions are independent. A class
/// holding the same count on both sides is a symmetry — either pairing of its
/// members is right, so nothing in it is a difference. A class holding different
/// counts is a difference no pairing can mend. The second must survive the first.
///
/// The channel nets are held back rather than blamed, which is the other half of
/// the same statement: unpaired is not the same as unpairable.
#[test]
fn an_unresolved_symmetry_does_not_mask_a_deleted_device() {
    let mut options = decisive();
    options.tie_break = TieBreak::Refuse;

    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(mos_and_bjt()),
        &RefGraph(mos_and_bjt_without_the_bjt()),
        options,
        &mut scratch,
    );

    let found = discrepancies(&verdict);
    assert!(
        found.contains(&Discrepancy::UnpairedDevice {
            side: Side::Layout,
            device: 1,
            model: NPN,
        }),
        "an unbroken symmetry elsewhere in the graph swallowed the deleted \
         bipolar: {found:#?}"
    );
    let blamed: Vec<u32> = (0..7u32)
        .filter(|&net| found.iter().any(|d| blames_net(d, Side::Layout, net)))
        .collect();
    assert_eq!(
        blamed,
        [4, 5, 6],
        "the symmetric channel nets are unpaired without being unpairable, so \
         they are not a difference: {found:#?}"
    );
}

/// Oracle: law, and the discrimination guard on the test above.
///
/// A netlist does not differ from itself — that is
/// `a_netlist_compared_against_itself_matches`, extended to the one axis it does
/// not cover. `compare` never reaches `interpret` with an unbroken symmetry over
/// two identical graphs, because refinement calls that case
/// [`gpurify_lvs::refine::Refinement::Symmetric`] and answers it directly; so the
/// only way to hand `interpret` that partition is to state it, which is what
/// [`gpurify_lvs::refine::Partition::from_classes`] is for.
///
/// The partition is `mos_and_bjt` against itself with the MOS's two channel nets
/// — nodes 3 and 4, which are nets 1 and 2 — left sharing one class, exactly as
/// a refusal leaves them once `role_code` reads a MOS channel as symmetric.
/// Everything else is discrete.
///
/// **Holding those two nets back is not enough on its own.** The MOS *is*
/// paired, and two of its four terminals land on them, so the terminal join sees
/// a net with no counterpart named and used to report both as
/// `TerminalMismatch` — two invented differences on a transistor with nothing
/// wrong with it, and a `Mismatch` verdict for a netlist compared with itself.
/// A terminal on a held-back net is skipped on *both* sides instead, which is
/// safe only because a held-back node forbids `Match`: the answer here is
/// `Inconclusive`, which is what "we could not finish" is spelt.
#[test]
fn an_unbroken_symmetry_does_not_make_a_netlist_differ_from_itself() {
    // Nodes: 0 the MOS, 1 the bipolar, 2..=8 the seven nets. Nodes 3 and 4 are
    // the MOS's source and drain nets, and they share class 3.
    let classes: Vec<ClassId> = [0u32, 1, 2, 3, 3, 5, 6, 7, 8].map(ClassId).to_vec();
    let unbroken = Partition::from_classes(classes.clone(), classes);

    let verdict = interpret(
        &LayoutGraph(mos_and_bjt()),
        &RefGraph(mos_and_bjt()),
        &unbroken,
        decisive(),
    );
    assert_eq!(
        verdict,
        Verdict::Inconclusive(Inconclusive::UnresolvedSymmetry),
        "a netlist was reported as differing from itself because one of its \
         own symmetries went unbroken"
    );
}

/// Oracle: law. `interpret` is documented as pure: a partition and two graphs
/// in, a verdict out, nothing mutated. So reading the partition `compare` left
/// behind must give the verdict `compare` returned, and reading it again must
/// give the same one. If the two ever disagreed, the verdict would depend on
/// something outside the partition.
#[test]
fn interpreting_the_partition_compare_left_behind_reproduces_its_verdict() {
    for (name, layout, reference) in [
        ("a netlist against itself", stacked_pair(), stacked_pair()),
        (
            "a deleted device",
            mos_and_bjt(),
            mos_and_bjt_without_the_bjt(),
        ),
    ] {
        let layout = LayoutGraph(layout);
        let reference = RefGraph(reference);
        let mut scratch = Partition::default();
        let verdict = compare(&layout, &reference, decisive(), &mut scratch);

        let once = interpret(&layout, &reference, &scratch, decisive());
        let twice = interpret(&layout, &reference, &scratch, decisive());
        assert_eq!(once, twice, "{name}: interpret is not a function");
        assert_eq!(once, verdict, "{name}: interpret disagrees with compare");
    }
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
