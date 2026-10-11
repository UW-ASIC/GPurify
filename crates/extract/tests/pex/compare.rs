//! PEX-009: two extractions compared net by net, on networks whose every
//! metric is worked out by hand.

use gpurify_check::topology::NetId;
use gpurify_extract::compare::{compare, Errors, Metric};
use gpurify_extract::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_geom::{LayerId, Qty};
use gpurify_testgen::assert_close;

/// Net 0: a ladder of four 10 ohm resistors from its driver (node 0) to node
/// 4, 2 fF to ground at nodes 1 to 4. Net 1: a 5 ohm resistor from node 5 to
/// node 6, 3 fF to ground at node 6, and 1 fF of coupling from node 6 to
/// net 0's node 2. Every resistance is scaled by `r` and every capacitance
/// by `c`.
fn ladder(r: f64, c: f64) -> ParasiticNetwork {
    let mut out = ParasiticNetwork {
        node_net: [0, 0, 0, 0, 0, 1, 1].map(NetId).to_vec(),
        node_layer: vec![LayerId(0); 7],
        ..ParasiticNetwork::default()
    };
    for k in 0..4 {
        out.push(
            NodeId(k),
            Some(NodeId(k + 1)),
            Parasitic::Resistance(Qty::new(10.0 * r)),
        );
        out.push(NodeId(k + 1), None, Parasitic::GroundCap(Qty::new(2.0 * c)));
    }
    out.push(
        NodeId(5),
        Some(NodeId(6)),
        Parasitic::Resistance(Qty::new(5.0 * r)),
    );
    out.push(NodeId(6), None, Parasitic::GroundCap(Qty::new(3.0 * c)));
    out.push(
        NodeId(2),
        Some(NodeId(6)),
        Parasitic::CouplingCap(Qty::new(c)),
    );
    out.sort_canonical();
    out
}

/// Oracle: closed form (Elmore 1948, a uniform RC ladder). Driven at node 0,
/// node `j` of the ladder sees `min(j, k)·R` shared with node `k`, so the far
/// end's delay is `R·C·N(N+1)/2 = 10·2·10 = 200` fs for N = 4, plus the
/// coupling's 1 fF at node 2 through 20 ohm: 220 fs; its pin-to-pin
/// resistance is `N·R = 40` ohm. Net 1 is one resistor: 5 ohm and
/// `5·(3 + 1) = 20` fs. Net 0 holds 8 + 1 fF, net 1 3 + 1. Fails if the
/// transfer resistance is the node's own and not the shared path, the
/// coupling is left off the delay, or the delay is read at the driver.
#[test]
fn a_ladder_s_resistance_and_delay_are_elmore_s() {
    let network = ladder(1.0, 1.0);
    let same = compare(&network, &network);
    assert_eq!(same.resistance.key, [NetId(0), NetId(1)]);
    for (net, (ohm, fs)) in [(40.0, 220.0), (5.0, 20.0)].into_iter().enumerate() {
        assert_close("pin-to-pin R", same.resistance.reference[net], ohm, 1e-9);
        assert_close("Elmore delay", same.delay.reference[net], fs, 1e-9);
    }
    assert_eq!(same.total_cap.reference, [9.0, 4.0]);
    assert_eq!(same.ground_cap.reference, [8.0, 3.0]);
    assert_eq!(same.coupling.key, [(NetId(0), NetId(1))]);
    assert_eq!(same.coupling.reference, [1.0]);
}

/// Oracle: law. Two equal resistors in parallel are half of one, so a net
/// whose one resistor is drawn twice reads half the pin-to-pin resistance
/// and half the delay.
#[test]
fn parallel_resistors_halve_the_resistance() {
    let mut twice = ladder(1.0, 1.0);
    twice.push(
        NodeId(5),
        Some(NodeId(6)),
        Parasitic::Resistance(Qty::new(5.0)),
    );
    twice.sort_canonical();
    let out = compare(&ladder(1.0, 1.0), &twice);
    assert_close(
        "half the resistance",
        out.resistance.candidate[1],
        2.5,
        1e-9,
    );
    assert_close("half the delay", out.delay.candidate[1], 10.0, 1e-9);
    assert_eq!(
        out.resistance.candidate[0].to_bits(),
        out.resistance.reference[0].to_bits()
    );
}

/// Oracle: metamorphic. Against itself every relative error is 0; with
/// every capacitance 10 % larger every capacitance metric is 10 % off and
/// the resistance not at all; with every resistance 20 % larger too, the
/// delay is `1.2 · 1.1 − 1 = 32 %` off.
#[test]
fn scaling_an_extraction_scales_its_errors() {
    let reference = ladder(1.0, 1.0);
    let same = compare(&reference, &reference);
    for errors in [
        same.total_cap.errors(0.0, 1e-9),
        same.resistance.errors(0.0, 1e-9),
        same.delay.errors(0.0, 1e-9),
        same.coupling.errors(0.0, 1e-9),
    ] {
        assert_eq!(errors.worst, 0.0);
        assert_eq!(errors.within, errors.count);
    }
    let scaled = compare(&reference, &ladder(1.2, 1.1));
    for (what, errors, want) in [
        ("total C", scaled.total_cap.errors(0.5, 1e-9), 0.1),
        ("ground C", scaled.ground_cap.errors(0.5, 1e-9), 0.1),
        ("coupling", scaled.coupling.errors(0.5, 1e-9), 0.1),
        ("resistance", scaled.resistance.errors(0.5, 1e-9), 0.2),
        ("delay", scaled.delay.errors(0.5, 1e-9), 0.32),
    ] {
        assert_close(what, errors.worst, want, 1e-12);
        assert_close(what, errors.mean, want, 1e-12);
        assert_close(what, errors.rms, want, 1e-12);
    }
}

/// Oracle: hand-derived. Rows 0 and 1 are 5 % and −10 % off; row 2 is
/// below the 0.01 floor on both sides and row 3 is zero on both, so neither
/// counts. At a 6 % tolerance one of two is within; the worst is row 1's
/// −10 %, the mean 7.5 %, the RMS `√((0.05² + 0.1²)/2)`.
#[test]
fn errors_count_only_rows_above_the_floor() {
    let metric = Metric {
        key: vec![0_u32, 1, 2, 3],
        reference: vec![1.0, 2.0, 0.001, 0.0],
        candidate: vec![1.05, 1.8, 0.002, 0.0],
    };
    let errors: Errors = metric.errors(0.06, 0.01);
    assert_eq!((errors.count, errors.within), (2, 1));
    assert_eq!(errors.worst_row, Some(1));
    assert_close("worst", errors.worst, -0.1, 1e-12);
    assert_close("mean", errors.mean, 0.075, 1e-12);
    assert_close(
        "rms",
        errors.rms,
        ((0.05_f64.powi(2) + 0.1_f64.powi(2)) / 2.0).sqrt(),
        1e-12,
    );
}

/// Oracle: construct-from-answer. A net only one extraction holds is named
/// as such and compared in no metric.
#[test]
fn a_net_in_one_extraction_only_is_named() {
    let mut fewer = ladder(1.0, 1.0);
    fewer.node_net.truncate(5);
    fewer.node_layer.truncate(5);
    let keep: Vec<usize> = (0..fewer.element_count())
        .filter(|&row| fewer.from[row].0 < 5 && fewer.to[row].is_none_or(|to| to.0 < 5))
        .collect();
    fewer.from = keep.iter().map(|&row| fewer.from[row]).collect();
    fewer.to = keep.iter().map(|&row| fewer.to[row]).collect();
    fewer.value = keep.iter().map(|&row| fewer.value[row]).collect();
    let out = compare(&ladder(1.0, 1.0), &fewer);
    assert_eq!(out.only_reference, [NetId(1)]);
    assert_eq!(out.only_candidate, Vec::new());
    assert_eq!(out.coupling.key, Vec::new());
    assert_eq!(out.total_cap.key, [NetId(0)]);
}
