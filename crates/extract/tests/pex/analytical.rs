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

use crate::common;

use common::{extracted, grid, resistance_ohm, serialise, uniform_stack};
use gpurify_check::topology::net::extract_nets_into;
use gpurify_check::topology::NetTable;
use gpurify_extract::analytical::extract_into;
use gpurify_extract::network::{Parasitic, ParasiticNetwork};
use gpurify_geom::{GeometryStore, GeometryStoreBuilder, LayerId};
use gpurify_ingest::deck::Connectivity;
use gpurify_testgen::{assert_bytes_identical, assert_close, assert_close_relative, dbu};

/// Every capacitive element summed once, in element order.
fn total_capacitance(network: &ParasiticNetwork) -> f64 {
    let mut total = 0.0;
    for value in &network.value {
        if let Parasitic::GroundCap(q) | Parasitic::CouplingCap(q) = value {
            total += q.raw();
        }
    }
    total
}

/// A node index as a subscript, refusing anything that is not one.
fn node(index: u32) -> usize {
    usize::try_from(index).expect("a node id is a u32 and usize is at least that wide")
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
    let mut single = ParasiticNetwork::default();
    let mut tripled = ParasiticNetwork::default();

    extract_into(
        case.store(),
        &case.nets,
        &Connectivity::default(),
        &uniform_stack(3, 1.0, 0.25),
        grid(),
        &mut single,
    );
    extract_into(
        case.store(),
        &case.nets,
        &Connectivity::default(),
        &uniform_stack(3, 3.0, 0.75),
        grid(),
        &mut tripled,
    );

    let base = total_capacitance(&single);
    assert!(
        base > 0.0,
        "a conductor over a plane has capacitance; the extractor found {base} fF"
    );
    assert_close_relative(
        "three times the coefficients",
        total_capacitance(&tripled),
        3.0 * base,
        1e-12,
    );
}

/// Conductor rectangles on layer 0, one per `(width, height)`, in the order
/// given.
///
/// The order survives: `finish` counting-sorts by layer and every rectangle here
/// is on the same one, so `PolyId(i)` is `sides[i]` and the assignment below can
/// name them positionally.
/// Nets by extraction: layer 0 conducts, touching shapes join.
fn layer0_nets(store: &GeometryStore) -> NetTable {
    let connectivity = Connectivity {
        conductors: vec![LayerId(0)],
        intra_layer_touch: true,
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    extract_nets_into(store, &connectivity, &mut nets);
    nets
}

fn rects(sides: &[(i64, i64)]) -> GeometryStore {
    let mut builder = GeometryStoreBuilder::with_capacity(sides.len(), 4 * sides.len());
    for &(width, height) in sides {
        builder.push(
            LayerId(0),
            &[dbu(0), dbu(width), dbu(width), dbu(0)],
            &[dbu(0), dbu(0), dbu(height), dbu(height)],
        );
    }
    builder.finish(1).0
}

/// Oracle: closed form, and the one the whole resistive half of PEX rests on.
/// A 2000 by 200 nm rectangle on a 0.1 ohm per square layer is ten squares, so
/// it is one ohm — the same arithmetic
/// `a_ten_square_run_of_a_hundred_milliohm_layer_is_one_ohm` does against
/// `segment_resistance` directly, asked here of the network the extractor
/// actually emits.
///
/// This is finding F10. The chain model put a node at each polygon's centre and
/// joined *consecutive* centres, so the first node of a net never received a
/// resistor and a net of one polygon emitted none at all. Every resistance case
/// in `tests/fixtures/expectations.json` is a one-polygon net, so every
/// resistance this workspace had ever extracted was zero — and zero is also
/// what an extractor that never looked at the cell produces, so a zero
/// here would fail open.
///
/// A wire has resistance whether or not a second polygon happens to sit beside
/// it. No model gets to lose it.
#[test]
fn a_net_of_one_polygon_still_carries_that_polygons_resistance() {
    let store = rects(&[(2_000, 200)]);
    let nets = layer0_nets(&store);

    let mut network = ParasiticNetwork::default();
    extract_into(
        &store,
        &nets,
        &Connectivity::default(),
        &uniform_stack(1, 0.0, 0.0),
        grid(),
        &mut network,
    );

    let total: f64 = network
        .value
        .iter()
        .filter_map(|&v| resistance_ohm(v))
        .sum();
    assert_close(
        "ten squares of 0.1 ohm/sq, through the network",
        total,
        1.0,
        1e-12,
    );
}

/// Oracle: law — conservation. A net's emitted resistance is the sum of its
/// polygons' resistances, whatever the chain does with the distribution along
/// it. Three rectangles of deliberately different aspect ratios, so a model that
/// halved the two ends (the F10 shape, which is exact in the middle and short by
/// `(R_first + R_last) / 2`) fails by a different amount than one that dropped a
/// polygon, and neither can pass by cancellation.
///
/// The per-polygon terms are `sheet × long / short`, which the closed-form
/// tests in `analytical.rs` pin independently, so this asserts the *network*
/// against the *formula* rather than against itself.
#[test]
fn the_resistance_a_net_emits_is_the_sum_of_its_polygons_resistances() {
    const SIDES: [(i64, i64); 3] = [(2_000, 200), (5_000, 100), (300, 300)];

    let store = rects(&SIDES);
    let nets = layer0_nets(&store);

    let mut network = ParasiticNetwork::default();
    extract_into(
        &store,
        &nets,
        &Connectivity::default(),
        &uniform_stack(1, 0.0, 0.0),
        grid(),
        &mut network,
    );

    let want: f64 = SIDES
        .iter()
        .map(|&(width, height)| {
            let (long, short) = (width.max(height), width.min(height));
            #[expect(clippy::cast_precision_loss, reason = "small sides, exact in f64")]
            let squares = long as f64 / short as f64;
            0.1 * squares
        })
        .sum();
    let got: f64 = network
        .value
        .iter()
        .filter_map(|&v| resistance_ohm(v))
        .sum();
    assert_close(
        "a net's resistance is its polygons' resistances",
        got,
        want,
        1e-12,
    );
}

/// Two plates on layers 0 and 2 with `cuts` cut squares on layer 1 between
/// them, the two plates one net and the cuts on none.
///
/// The landing plates are the point: a bare cut carries no current, so a fixture
/// without them cannot say what a via array's resistance is. `PEX_VIA1` and
/// `PEX_VIA2` under `tests/fixtures/` are drawn without them, which their own
/// `note` fields record.
fn via_stack(cuts: i64) -> (GeometryStore, Connectivity, NetTable) {
    const LOWER: LayerId = LayerId(0);
    const CUT: LayerId = LayerId(1);
    const UPPER: LayerId = LayerId(2);

    let mut builder = GeometryStoreBuilder::default();
    let plate = |builder: &mut GeometryStoreBuilder, layer| {
        builder.push(
            layer,
            &[dbu(0), dbu(1_000), dbu(1_000), dbu(0)],
            &[dbu(0), dbu(0), dbu(200), dbu(200)],
        );
    };
    plate(&mut builder, LOWER);
    plate(&mut builder, UPPER);
    for i in 0..cuts {
        let x = 100 + 200 * i;
        builder.push(
            CUT,
            &[dbu(x), dbu(x + 100), dbu(x + 100), dbu(x)],
            &[dbu(50), dbu(50), dbu(150), dbu(150)],
        );
    }

    // `finish` counting-sorts by layer, so the rows come back lower plate, cuts,
    // upper plate — which is the order the net assignment below names.
    let store = builder.finish(3).0;
    let connectivity = Connectivity {
        conductors: vec![LOWER, UPPER],
        via_cut: vec![CUT],
        via_connects: vec![(LOWER, UPPER)],
        intra_layer_touch: true,
        ..Connectivity::default()
    };
    // One net for the two plates; the cuts are on none, which is what a cut
    // layer absent from `conductors` gets and the whole reason `vias_into`
    // exists.
    let mut nets = NetTable::default();
    extract_nets_into(&store, &connectivity, &mut nets);
    assert_eq!(nets.net_count(), 1, "the cuts join the two plates");
    (store, connectivity, nets)
}

/// One via stack extracted, with only the cut layer conducting.
fn via_resistance_of(cuts: i64) -> f64 {
    let (store, connectivity, nets) = via_stack(cuts);
    let mut stack = uniform_stack(3, 0.0, 0.0);
    stack.sheet_res_ohm_sq = vec![0.0, 5.0, 0.0];

    let mut network = ParasiticNetwork::default();
    extract_into(&store, &nets, &connectivity, &stack, grid(), &mut network);
    network
        .value
        .iter()
        .filter_map(|&v| resistance_ohm(v))
        .sum()
}

/// Oracle: closed form, asked of the extractor rather than of the formula. One
/// 5 ohm cut between two plates is 5 ohms, which is the first assertion
/// `via_resistance_divides_by_the_number_of_cuts` already makes of
/// `via_resistance` directly.
///
/// This is the second half of finding F11. A cut layer is in
/// `connectivity.via_cut` and not in `conductors`, so its polygons get
/// `NetId::NONE` and `extract_net_into` never saw them — which left
/// `via_resistance` with no caller anywhere in the tree and every via in every
/// design contributing nothing at all. `PEX_VIA1` extracted an empty network.
#[test]
fn one_cut_between_two_plates_contributes_its_own_resistance() {
    assert_close("one 5 ohm cut", via_resistance_of(1), 5.0, 1e-12);
}

/// Oracle: law — cuts of one array are in parallel, so `n` of them is `1 / n` of
/// one. That is the whole reason a redundant via helps, and it is the direction
/// an extractor emitting one resistor per cut gets exactly backwards: it would
/// put them in series and make the redundant via *worse* than a single one.
///
/// Stated over a range, because one or two worked cases pass against an
/// implementation that special-cased the array sizes it had seen.
#[test]
fn a_via_array_extracts_its_cuts_in_parallel_not_in_series() {
    let one = via_resistance_of(1);
    assert!(
        one > 0.0,
        "the single-cut case extracted nothing to compare against"
    );
    for cuts in 2..=5 {
        #[expect(
            clippy::cast_precision_loss,
            reason = "a cut count under ten is exact in f64"
        )]
        let n = cuts as f64;
        assert_close_relative(
            "cuts of one array conduct in parallel",
            via_resistance_of(cuts) * n,
            one,
            1e-12,
        );
    }
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
        &Connectivity::default(),
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
        &Connectivity::default(),
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
/// joins; the network total counts it once. So summing `capacitance_per_net` over
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
        &Connectivity::default(),
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
    let totals = network.capacitance_per_net();
    let per_net: f64 = nets.iter().map(|&net| totals[net.0 as usize]).sum();
    let coupling: f64 = network
        .value
        .iter()
        .filter_map(|value| match *value {
            Parasitic::CouplingCap(q) => Some(q.raw()),
            _ => None,
        })
        .sum();
    let total = total_capacitance(&network);
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
        &Connectivity::default(),
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
    let stack = uniform_stack(3, 1.4, 0.35);

    let mut fresh = ParasiticNetwork::default();
    extract_into(
        case.store(),
        &case.nets,
        &Connectivity::default(),
        &stack,
        grid(),
        &mut fresh,
    );
    let first = serialise(&fresh);

    let mut again = ParasiticNetwork::default();
    extract_into(
        case.store(),
        &case.nets,
        &Connectivity::default(),
        &stack,
        grid(),
        &mut again,
    );
    assert_bytes_identical("two extractions of one corpus", &first, &serialise(&again));

    // The same buffer, a second time. Anything appended rather than replaced
    // shows up here and nowhere else.
    extract_into(
        case.store(),
        &case.nets,
        &Connectivity::default(),
        &stack,
        grid(),
        &mut again,
    );
    assert_bytes_identical(
        "an extraction into a reused buffer",
        &first,
        &serialise(&again),
    );
}
