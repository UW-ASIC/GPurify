//! Closed-form extraction.
//!
//! The easiest module in the tree to state an oracle for, and the tests say so:
//! sheet resistance times squares, a via divided by its cuts, and the
//! parallel-plate limit reached from a fringe term that has to fall away.
//!
//! `ground_capacitance` and `coupling_capacitance` take deck coefficients per
//! micrometre and geometry in database units, and the `Grid` that closes the
//! chain between them is a parameter as of the Testing-Phase, so both have an
//! absolute answer now. The laws are kept alongside the worked value —
//! superposition of the two terms, linearity in each coefficient, and the limit
//! the area term is the limit of — because each fails against a different wrong
//! implementation than a single number does: a formula that couples the two
//! terms can still hit one point exactly.

mod common;

use common::{extracted, grid, resistance_ohm, serialise, uniform_stack};
use gpurify_core::LayerId;
use gpurify_ingest::deck::ProcessStack;
use gpurify_pex::analytical::{
    coupling_capacitance, extract_into, extract_net_into, ground_capacitance, segment_resistance,
    stack_row, via_resistance,
};
use gpurify_pex::network::{Parasitic, ParasiticNetwork};
use gpurify_pex::reduce::total_capacitance;
use gpurify_testgen::{assert_bytes_identical, assert_close, assert_close_relative, dbu, Rng};
use gpurify_topology::DeviceTable;
use gpurify_units::DbuArea;

/// A node index as a subscript, refusing anything that is not one.
fn node(index: u32) -> usize {
    usize::try_from(index).expect("a node id is a u32 and usize is at least that wide")
}

/// Oracle: closed form. A ten-square run of a 100 milliohm per square layer is
/// one ohm, and the arithmetic is `0.1 * 10` written out in the assertion. No
/// implementation is consulted to know that.
#[test]
fn a_ten_square_run_of_a_hundred_milliohm_layer_is_one_ohm() {
    let r = segment_resistance(0.1, dbu(10_000), dbu(1_000));
    assert_close("ten squares of 0.1 ohm/sq", r.raw(), 1.0, 1e-12);
}

/// Oracle: closed form. Squares are dimensionless, so the same aspect ratio at
/// three wildly different absolute sizes is the same resistance. A formula that
/// leaked an absolute length — a stray grid factor, say — fails this and passes
/// the single worked example above.
#[test]
fn sheet_resistance_depends_on_aspect_ratio_and_not_on_absolute_size() {
    let reference = segment_resistance(2.5, dbu(400), dbu(100)).raw();
    assert_close("four squares of 2.5 ohm/sq", reference, 10.0, 1e-12);
    for scale in [1_i64, 97, 1_000_000] {
        let r = segment_resistance(2.5, dbu(400 * scale), dbu(100 * scale));
        assert_close_relative("four squares at any scale", r.raw(), reference, 1e-12);
    }
}

/// Oracle: law. Resistance in series adds, so one run of length `L` is two runs
/// of `L / 2` at the same width. True for any width and any sheet value, which
/// is why it is stated over three of each.
#[test]
fn segment_resistance_adds_when_a_run_is_cut_in_half() {
    for sheet in [0.05, 1.0, 42.0] {
        for width in [3_i64, 250, 90_000] {
            let whole = segment_resistance(sheet, dbu(15_000), dbu(width)).raw();
            let half = segment_resistance(sheet, dbu(7_500), dbu(width)).raw();
            assert_close_relative("a run cut in half", whole, 2.0 * half, 1e-12);
        }
    }
}

/// Oracle: law. Widening a conductor lowers its resistance in exact proportion,
/// because width is the denominator of the square count.
#[test]
fn doubling_conductor_width_halves_its_resistance() {
    let narrow = segment_resistance(0.7, dbu(5_000), dbu(250)).raw();
    let wide = segment_resistance(0.7, dbu(5_000), dbu(500)).raw();
    assert_close_relative("twice the width", wide, narrow / 2.0, 1e-12);
}

/// Oracle: closed form. A five ohm cut is five ohms on its own and one and a
/// quarter ohms in a four-cut array, because cuts are resistors in parallel.
/// That division is why a redundant via helps, and why the count has to come
/// from the geometry instead of being assumed to be one.
#[test]
fn via_resistance_divides_by_the_number_of_cuts() {
    assert_close("one cut", via_resistance(5.0, 1).raw(), 5.0, 1e-12);
    assert_close("a redundant pair", via_resistance(5.0, 2).raw(), 2.5, 1e-12);
    assert_close(
        "a two by two array",
        via_resistance(5.0, 4).raw(),
        1.25,
        1e-12,
    );
}

/// Oracle: law. Conductances add, so `n` cuts is `1 / n` of one cut for every
/// `n`. Stated over a range because the three worked cases above would all pass
/// against an implementation that special-cased the array sizes it had seen.
#[test]
fn via_conductance_adds_over_every_cut_count() {
    let one = via_resistance(3.3, 1).raw();
    for cuts in 1_u32..=64 {
        let many = via_resistance(3.3, cuts).raw();
        assert_close_relative("cuts in parallel", many * f64::from(cuts), one, 1e-12);
    }
}

/// Oracle: closed form. Writable as of the Testing-Phase, when
/// `ground_capacitance` gained the `Grid` that turns its two database-unit
/// arguments into the micrometres its two coefficients are stated per.
///
/// A 4 µm by 9 µm plate on a 1 nm grid is 36 µm² of area and 26 µm of
/// perimeter, so at 1.7 aF/µm² and 0.4 aF/µm the answer is
/// `1.7 × 36 + 0.4 × 26 = 71.6` attofarads — `0.0716` femtofarads, which is the
/// unit the return type names. The arithmetic is written out in the assertion
/// and no implementation is consulted to know it. This is the one case that
/// catches a formula off by the grid factor itself; every law below is blind to
/// a uniform scale.
#[test]
fn a_four_by_nine_micrometre_plate_is_seventy_one_point_six_attofarads() {
    let c = ground_capacitance(
        1.7,
        0.4,
        DbuArea::new(4_000 * 9_000),
        dbu(2 * (4_000 + 9_000)),
        grid(),
    );
    assert_close("36 um^2 at 1.7 aF/um^2 plus 26 um at 0.4 aF/um", c.raw(), 0.0716, 1e-12);
}

/// Oracle: law. The doc comment defines ground capacitance as an area term plus
/// a fringe term, so the two superpose: computing them together must equal
/// computing each alone and adding. This holds whatever the unit convention
/// turns out to be, and it fails against any implementation that couples them.
#[test]
fn ground_capacitance_superposes_its_area_and_fringe_terms() {
    let area = DbuArea::new(4_000 * 9_000);
    let perimeter = dbu(2 * (4_000 + 9_000));
    let both = ground_capacitance(1.7, 0.4, area, perimeter, grid()).raw();
    let area_only = ground_capacitance(1.7, 0.0, area, perimeter, grid()).raw();
    let fringe_only = ground_capacitance(0.0, 0.4, area, perimeter, grid()).raw();
    assert!(
        area_only > 0.0 && fringe_only > 0.0,
        "both terms must contribute: got {area_only} and {fringe_only}"
    );
    assert_close_relative("area plus fringe", both, area_only + fringe_only, 1e-12);
}

/// Oracle: law. Each term is its coefficient times a geometric quantity, so
/// each is linear in its own coefficient and independent of the other's. Two
/// scalings that must hold for any numbers at all.
#[test]
fn ground_capacitance_is_linear_in_each_deck_coefficient() {
    let area = DbuArea::new(2_500 * 2_500);
    let perimeter = dbu(4 * 2_500);
    let reference = ground_capacitance(1.0, 1.0, area, perimeter, grid()).raw();

    let area_share = ground_capacitance(1.0, 0.0, area, perimeter, grid()).raw();
    assert_close_relative(
        "three times the area coefficient",
        ground_capacitance(3.0, 1.0, area, perimeter, grid()).raw(),
        reference + 2.0 * area_share,
        1e-12,
    );

    let fringe_share = ground_capacitance(0.0, 1.0, area, perimeter, grid()).raw();
    assert_close_relative(
        "three times the fringe coefficient",
        ground_capacitance(1.0, 3.0, area, perimeter, grid()).raw(),
        reference + 2.0 * fringe_share,
        1e-12,
    );
}

/// Oracle: closed form, taken as a limit. The parallel-plate formula is what a
/// real capacitor approaches as the plate grows relative to its edge, and the
/// rate at which it approaches it is exact: for a square of side `s` the fringe
/// term goes as the perimeter `4s` and the area term as `s²`, so their ratio is
/// `4 / s` times whatever fixed factor the unit convention contributes. That
/// factor cancels between two sides, which is the whole reason this is stated
/// as a ratio of ratios rather than as an absolute bound — a thousandfold wider
/// plate has a thousandth the fringe share, whatever a database unit turns out
/// to be worth.
///
/// The two terms are taken apart with the coefficients rather than by
/// subtracting the total, so the share is computed at full precision instead of
/// as the difference of two nearly equal numbers. Superposition is what makes
/// that legitimate, and it is established on its own above.
#[test]
fn the_fringe_share_of_a_square_plate_falls_inversely_with_the_plate_side() {
    let share = |side: i64| {
        let area = DbuArea::new(i128::from(side) * i128::from(side));
        let perimeter = dbu(4 * side);
        let plate = ground_capacitance(1.0, 0.0, area, perimeter, grid()).raw();
        let fringe = ground_capacitance(0.0, 1.0, area, perimeter, grid()).raw();
        assert!(
            plate > 0.0 && fringe > 0.0,
            "a plate of side {side} has an area term of {plate} and a fringe term of {fringe}"
        );
        fringe / plate
    };

    let small = share(1_000);
    let large = share(1_000_000);
    let vast = share(1_000_000_000);
    assert!(
        small > large && large > vast,
        "the fringe share must fall with the plate side: {small}, {large}, {vast}"
    );
    assert_close_relative(
        "a thousandfold wider plate, from a thousand database units",
        small / large,
        1_000.0,
        1e-9,
    );
    assert_close_relative(
        "a thousandfold wider plate, from a million database units",
        large / vast,
        1_000.0,
        1e-9,
    );

    // And the limit itself: at a billion units on a side the total is the
    // parallel-plate value plus a correction of exactly `vast`, which the
    // ratios above have just pinned at four parts in a billion divided by
    // whatever a database unit is worth in the deck's length unit.
    let area = DbuArea::new(1_000_000_000_i128 * 1_000_000_000);
    let perimeter = dbu(4_000_000_000);
    let total = ground_capacitance(1.0, 1.0, area, perimeter, grid()).raw();
    let plate = ground_capacitance(1.0, 0.0, area, perimeter, grid()).raw();
    assert_close_relative("the parallel-plate limit", total / plate, 1.0 + vast, 1e-12);
}

/// Oracle: law. The coupling coefficient is stated per micrometre of facing
/// length, so the result is proportional to that length and to the coefficient,
/// and it falls with separation. Those three are the whole of what the doc
/// comment claims, and none of them needs the unit convention resolved.
#[test]
fn coupling_capacitance_scales_with_facing_length_and_falls_with_separation() {
    let reference = coupling_capacitance(2.0, dbu(6_000), dbu(300), grid()).raw();
    assert!(
        reference > 0.0,
        "two facing conductors couple: got {reference}"
    );

    assert_close_relative(
        "twice the facing length",
        coupling_capacitance(2.0, dbu(12_000), dbu(300), grid()).raw(),
        2.0 * reference,
        1e-12,
    );
    assert_close_relative(
        "twice the coefficient",
        coupling_capacitance(4.0, dbu(6_000), dbu(300), grid()).raw(),
        2.0 * reference,
        1e-12,
    );

    let mut previous = f64::INFINITY;
    for separation in [100_i64, 300, 900, 2_700, 8_100] {
        let value = coupling_capacitance(2.0, dbu(6_000), dbu(separation), grid()).raw();
        assert!(
            value > 0.0 && value < previous,
            "coupling must fall strictly with separation: {value} at {separation} \
             against {previous} one step closer"
        );
        previous = value;
    }
}

/// Oracle: construct-from-answer. The stack is dense and indexed directly by
/// layer, so a four-row stack answers for layers zero to three and refuses
/// everything above. The refusal is the half worth checking: the old
/// implementation reached this through a hash map, and a layer silently missing
/// is how one layer ends up extracted with another's coefficients.
#[test]
fn stack_row_is_the_layer_index_within_the_stack_and_nothing_outside_it() {
    let stack = uniform_stack(4, 1.0, 0.2);
    for layer in 0_u16..4 {
        assert_eq!(
            stack_row(&stack, LayerId(layer)),
            Some(usize::from(layer)),
            "layer {layer} of a four-row stack"
        );
    }
    for layer in [4_u16, 5, 63, u16::MAX] {
        assert_eq!(
            stack_row(&stack, LayerId(layer)),
            None,
            "layer {layer} is beyond a four-row stack"
        );
    }
    assert_eq!(
        stack_row(&ProcessStack::default(), LayerId(0)),
        None,
        "an empty stack describes no layer"
    );
}

/// Oracle: law. Capacitance is linear in the deck's capacitive coefficients, so
/// tripling both triples the extracted total. Run on a single-net corpus, where
/// there is no second net for a coupling term to appear between and the total
/// is ground capacitance alone.
///
/// The total is asserted positive first. Without that, linearity would be
/// satisfied by an extractor that emitted nothing at all.
#[test]
fn extracted_capacitance_is_linear_in_the_decks_capacitive_coefficients() {
    let case = extracted(7, 3, 1);
    let devices = DeviceTable::default();
    let mut single = ParasiticNetwork::default();
    let mut tripled = ParasiticNetwork::default();

    extract_into(
        case.store(),
        &case.nets,
        &devices,
        &uniform_stack(3, 1.0, 0.25),
        grid(),
        &mut single,
    );
    extract_into(
        case.store(),
        &case.nets,
        &devices,
        &uniform_stack(3, 3.0, 0.75),
        grid(),
        &mut tripled,
    );

    let base = total_capacitance(&single).raw();
    assert!(
        base > 0.0,
        "a conductor over a plane has capacitance; the extractor found {base} fF"
    );
    assert_close_relative(
        "three times the coefficients",
        total_capacitance(&tripled).raw(),
        3.0 * base,
        1e-12,
    );
}

/// Oracle: law. A conductor of nonzero length on a layer of nonzero sheet
/// resistance has nonzero series resistance, and every resistance in the
/// network is positive: a zero or negative parasitic resistor is not a
/// simplification, it is a short that changes the answer a simulator gives.
#[test]
fn every_extracted_resistance_is_positive_and_at_least_one_exists() {
    let case = extracted(11, 9, 2);
    let mut network = ParasiticNetwork::default();
    extract_into(
        case.store(),
        &case.nets,
        &DeviceTable::default(),
        &uniform_stack(3, 1.0, 0.25),
        grid(),
        &mut network,
    );

    let resistances: Vec<f64> = network
        .value
        .iter()
        .filter_map(|&value| resistance_ohm(value))
        .collect();
    assert!(
        !resistances.is_empty(),
        "a comb of rails and fingers on a resistive layer extracted no resistance"
    );
    for (index, &ohms) in resistances.iter().enumerate() {
        assert!(
            ohms > 0.0 && ohms.is_finite(),
            "resistance {index} is {ohms}, which is not a conductor"
        );
    }
}

/// Oracle: law. Every element names nodes that exist, none joins a node to
/// itself, and every coupling runs from the lower net to the higher. The last
/// is what the doc comment means by emitting a pair once, and its absence is
/// what let two layers swap places between runs of the old implementation.
#[test]
fn extracted_elements_name_real_nodes_and_order_every_coupling_by_net() {
    let case = extracted(13, 24, 2);
    let mut network = ParasiticNetwork::default();
    extract_into(
        case.store(),
        &case.nets,
        &DeviceTable::default(),
        &uniform_stack(3, 1.0, 0.25),
        grid(),
        &mut network,
    );

    let nodes = network.node_count();
    assert!(
        nodes > 0,
        "an extraction over real geometry produced no nodes"
    );
    assert!(
        network.element_count() > 0,
        "an extraction over real geometry produced no elements"
    );

    for index in 0..network.element_count() {
        let from = network.from[index];
        assert!(
            node(from.0) < nodes,
            "element {index} starts at node {} of {nodes}",
            from.0
        );
        let Some(to) = network.to[index] else {
            continue;
        };
        assert!(
            node(to.0) < nodes,
            "element {index} ends at node {} of {nodes}",
            to.0
        );
        assert_ne!(from, to, "element {index} joins node {} to itself", from.0);
        if matches!(network.value[index], Parasitic::CouplingCap(_)) {
            let a = network.node_net[node(from.0)];
            let b = network.node_net[node(to.0)];
            assert!(
                a < b,
                "coupling {index} runs from net {} to net {}; a pair is emitted \
                 once, by the lower net",
                a.0,
                b.0
            );
        }
    }
}

/// Oracle: law. Per-net capacitance counts a coupling on both of the nets it
/// joins; the network total counts it once. So summing `net_capacitance` over
/// every net must equal the total plus the coupling a second time — an identity
/// between two public decisions that is wrong the moment either one drops an
/// element kind or double-counts a ground term.
///
/// The nets summed over are read out of the network's own node column rather
/// than taken from the corpus. Every net the extraction touched is then in the
/// sum by construction, including one the corpus does not name — a cut polygon
/// landing on a net of its own would otherwise leave capacitance in the total
/// that no term of the sum could reach, and the identity would fail for a
/// reason that has nothing to do with the two functions under test.
#[test]
fn per_net_capacitance_sums_to_the_total_plus_the_coupling_counted_twice() {
    let case = extracted(29, 24, 3);
    let mut network = ParasiticNetwork::default();
    extract_into(
        case.store(),
        &case.nets,
        &DeviceTable::default(),
        &uniform_stack(3, 1.0, 0.25),
        grid(),
        &mut network,
    );

    let mut nets: Vec<_> = network.node_net.clone();
    nets.sort_unstable();
    nets.dedup();
    assert!(
        nets.len() >= case.selected.len(),
        "the extraction reached {} nets, fewer than the {} the corpus built",
        nets.len(),
        case.selected.len()
    );
    let per_net: f64 = nets
        .iter()
        .map(|&net| network.net_capacitance(net).raw())
        .sum();
    let coupling: f64 = network
        .value
        .iter()
        .filter_map(|value| match *value {
            Parasitic::CouplingCap(q) => Some(q.raw()),
            _ => None,
        })
        .sum();
    let total = total_capacitance(&network).raw();
    assert!(total > 0.0, "the corpus extracted no capacitance at all");
    assert_close_relative(
        "per-net capacitance against the network total",
        per_net,
        total + coupling,
        1e-9,
    );
}

/// Oracle: law. The doc comment says the output is canonical without a sort and
/// that `sort_canonical` exists as a guarantee rather than as the mechanism. So
/// sorting an extraction must not move a single byte. If it does, one of the
/// two is wrong, and the determinism gate rests on whichever it is.
#[test]
fn extraction_emits_the_order_sort_canonical_would_have_produced() {
    let case = extracted(17, 24, 2);
    let mut network = ParasiticNetwork::default();
    extract_into(
        case.store(),
        &case.nets,
        &DeviceTable::default(),
        &uniform_stack(3, 1.0, 0.25),
        grid(),
        &mut network,
    );

    let as_emitted = serialise(&network);
    network.sort_canonical();
    assert_bytes_identical(
        "an extraction against its own canonical order",
        &as_emitted,
        &serialise(&network),
    );
}

/// Oracle: determinism. The gate this crate exists under: eight of the old
/// tree's twenty-seven parasitic outputs differed between runs of the same
/// binary. Extracting twice must give the same bytes, and extracting into a
/// buffer that already holds a run must give the same bytes as extracting into
/// a fresh one. The second half is the "cleared and refilled" half of the
/// interface, and an append satisfies the first alone.
#[test]
fn extraction_is_byte_identical_across_runs_and_across_a_reused_buffer() {
    let case = extracted(19, 24, 2);
    let devices = DeviceTable::default();
    let stack = uniform_stack(3, 1.4, 0.35);

    let mut fresh = ParasiticNetwork::default();
    extract_into(case.store(), &case.nets, &devices, &stack, grid(), &mut fresh);
    let first = serialise(&fresh);

    let mut again = ParasiticNetwork::default();
    extract_into(case.store(), &case.nets, &devices, &stack, grid(), &mut again);
    assert_bytes_identical("two extractions of one corpus", &first, &serialise(&again));

    // The same buffer, a second time. Anything appended rather than replaced
    // shows up here and nowhere else.
    extract_into(case.store(), &case.nets, &devices, &stack, grid(), &mut again);
    assert_bytes_identical(
        "an extraction into a reused buffer",
        &first,
        &serialise(&again),
    );
}

/// Oracle: law. A net's elements depend only on its own geometry and its
/// neighbours' bounding boxes, never on another net's results, so extracting a
/// net cannot depend on which nets were extracted before it. The shuffle is
/// what makes the order arbitrary; the answer was fixed before it.
#[test]
fn extracting_one_net_does_not_depend_on_which_nets_came_before_it() {
    let case = extracted(23, 24, 4);
    let stack = uniform_stack(3, 1.0, 0.25);

    let alone: Vec<Vec<u8>> = case
        .selected
        .iter()
        .map(|&net| {
            let mut one = ParasiticNetwork::default();
            extract_net_into(case.store(), &case.nets, net, &stack, grid(), &mut one);
            assert!(
                one.element_count() > 0,
                "net {} extracted nothing at all",
                net.0
            );
            serialise(&one)
        })
        .collect();

    let mut order: Vec<usize> = (0..case.selected.len()).collect();
    Rng::new(23).shuffle(&mut order);
    for index in order {
        let mut one = ParasiticNetwork::default();
        extract_net_into(
            case.store(),
            &case.nets,
            case.selected[index],
            &stack,
            grid(),
            &mut one,
        );
        assert_bytes_identical(
            "one net extracted out of order",
            &alone[index],
            &serialise(&one),
        );
    }
}
