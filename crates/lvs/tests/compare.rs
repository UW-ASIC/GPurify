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
    stacked_pair_with_params, NPN, VDD, VSS, WIDTH,
};
use gpurify_lvs::compare::interpret;
use gpurify_lvs::refine::{Partition, TieBreak};
use gpurify_lvs::verdict::{Discrepancy, Inconclusive, Side, Verdict};
use gpurify_lvs::{compare, CompareOptions, LayoutGraph, RefGraph};
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

    let mut builder = common::GraphBuilder::new(6);
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

    assert_eq!(
        format!("{first:?}"),
        format!("{second:?}"),
        "the same comparison produced two different reports"
    );
}
