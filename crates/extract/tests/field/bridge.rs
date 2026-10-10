//! The geometry bridge: drawn rectangles in, per-net inductance out.
//!
//! Oracle: **construct-from-answer**. A single drawn bar has a closed-form
//! self inductance (the Grover/Rosa formula `integrals::filament` states), so
//! the bridge's answer for that bar is checked against the formula it must
//! reproduce — same dimensions, independent code path through the solver.

use crate::common;

use common::{grid, uniform_stack};
use gpurify_check::topology::net::extract_nets_into;
use gpurify_check::topology::{NetId, NetTable};
use gpurify_extract::field::filament::self_inductance_bar;
use gpurify_extract::field::henry::{extract_inductance_into, InductMatrix, InductanceError};
use gpurify_geom::Dbu;
use gpurify_geom::{GeometryStoreBuilder, LayerId};
use gpurify_ingest::deck::Connectivity;

fn dbu(raw: i64) -> Dbu {
    Dbu::new(raw).expect("a test coordinate is in the coordinate domain")
}

/// One 10 µm × 1 µm bar on layer 0 of a 1 nm grid, assigned to net 0.
fn one_bar() -> (gpurify_geom::GeometryStore, NetTable) {
    let mut builder = GeometryStoreBuilder::default();
    builder.push(
        LayerId(0),
        &[dbu(0), dbu(10_000), dbu(10_000), dbu(0)],
        &[dbu(0), dbu(0), dbu(1_000), dbu(1_000)],
    );
    let (store, _) = builder.finish(1);
    let connectivity = Connectivity {
        conductors: vec![LayerId(0)],
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    extract_nets_into(&store, &connectivity, &mut nets);
    (store, nets)
}

/// Oracle: closed form. The bridge builds one filament for the bar, so the
/// port inductance is the Grover/Rosa self inductance of a 10 µm × 1 µm ×
/// 100 nm bar (`uniform_stack` states the thickness), within 5%.
#[test]
fn a_single_bar_matches_the_grover_closed_form() {
    let (store, nets) = one_bar();
    let stack = uniform_stack(1, 1.0, 0.25);
    let mut out = InductMatrix::default();
    extract_inductance_into(
        &store,
        &nets,
        &Connectivity::default(),
        &[NetId(0)],
        &stack,
        grid(),
        &mut out,
    )
    .expect("one bar over a stated stack solves");

    assert_eq!(out.net, vec![NetId(0)], "one row for the one selected net");
    let l = out.l_henry[0];
    let expected = self_inductance_bar(10e-6, 1e-6, 0.1e-6);
    let relative = ((l - expected) / expected).abs();
    assert!(
        relative < 0.05,
        "bridge {l:e} H vs Grover {expected:e} H, off by {relative:.6} relative"
    );

    // R = Rsq * L / W = 0.1 * 10 = 1 Ω at DC; at 1 MHz the resistive part is
    // still the DC value for a single filament (no skin subdivision).
    let r = out.r_ohm[0];
    assert!(
        ((r - 1.0) / 1.0).abs() < 1e-6,
        "one square-tenth bar reads {r} ohm, not the sheet-resistance 1 ohm"
    );
}

/// An L on layer 0 with legs of 20 µm along x and 16 µm up its right end,
/// 1 µm wide, drawn as `rects`, all on one net.
fn l_shape(
    rects: &[(i64, i64, i64, i64)],
    polygon: bool,
) -> (gpurify_geom::GeometryStore, NetTable) {
    let mut builder = GeometryStoreBuilder::default();
    if polygon {
        let (xs, ys): (Vec<Dbu>, Vec<Dbu>) = [
            (0, 0),
            (20_000, 0),
            (20_000, 16_000),
            (19_000, 16_000),
            (19_000, 1_000),
            (0, 1_000),
        ]
        .iter()
        .map(|&(x, y)| (dbu(x), dbu(y)))
        .unzip();
        builder.push(LayerId(0), &xs, &ys);
    }
    for &(xlo, ylo, xhi, yhi) in rects {
        builder.push(
            LayerId(0),
            &[dbu(xlo), dbu(xhi), dbu(xhi), dbu(xlo)],
            &[dbu(ylo), dbu(ylo), dbu(yhi), dbu(yhi)],
        );
    }
    let (store, _) = builder.finish(1);
    let connectivity = Connectivity {
        conductors: vec![LayerId(0)],
        intra_layer_touch: true,
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    extract_nets_into(&store, &connectivity, &mut nets);
    assert_eq!(nets.net_count(), 1, "the L is one net");
    (store, nets)
}

/// Oracle: closed form (F45, and the touching half of F23). A bend of width
/// `w` and centre-line length `Lc = a + b − w = 35 µm` is `Lc / w = 35`
/// squares, 3.5 ohm at 0.1 ohm/sq, its corner counted once, however it is
/// drawn: as one polygon, as two abutting rectangles, or as two full bars
/// overlapping at the corner. Its legs are perpendicular, so they have no
/// mutual partial inductance and `L` is Grover's self inductance of each leg
/// along the centre line, `a − w/2 = 19.5` and `b − w/2 = 15.5` µm, at
/// 100 nm thick.
///
/// R is `Re(Z)` of one series path, the sum of its pieces' resistances, so
/// it holds to round-off (`1e-9`). L holds to 1%, the accuracy of Grover's
/// formula at these aspect ratios: the corner is a 0.5 µm junction piece
/// whose self term is Grover's outside its range, carrying under 1% of the
/// total. One filament along the bounding box read 0.125 ohm (20 by 16, 1.25
/// squares), and two rectangles whose centre lines do not meet read zero.
#[test]
fn an_l_reads_its_centre_line_however_it_is_drawn() {
    let want_l =
        self_inductance_bar(19.5e-6, 1e-6, 0.1e-6) + self_inductance_bar(15.5e-6, 1e-6, 0.1e-6);
    let stack = uniform_stack(1, 1.0, 0.25);
    for (what, rects, polygon) in [
        ("one polygon", vec![], true),
        (
            "two abutting rectangles",
            vec![(0, 0, 20_000, 1_000), (19_000, 1_000, 20_000, 16_000)],
            false,
        ),
        (
            "two overlapping bars",
            vec![(0, 0, 20_000, 1_000), (19_000, 0, 20_000, 16_000)],
            false,
        ),
    ] {
        let (store, nets) = l_shape(&rects, polygon);
        let mut out = InductMatrix::default();
        extract_inductance_into(
            &store,
            &nets,
            &Connectivity::default(),
            &[NetId(0)],
            &stack,
            grid(),
            &mut out,
        )
        .expect("an L over a stated stack solves");
        let (r, l) = (out.r_ohm[0], out.l_henry[0]);
        assert!(
            ((r - 3.5) / 3.5).abs() < 1e-9,
            "{what}: {r} ohm, want 35 squares at 0.1 ohm/sq"
        );
        assert!(
            ((l - want_l) / want_l).abs() < 1e-2,
            "{what}: {l:e} H, want {want_l:e} H"
        );
    }
}

/// An `m1` bar `[0, 5] x [0, 1]` um on layer 0 and an `m2` bar
/// `[4, 9] x [0, 1]` on layer 2, joined by `cuts` (boxes, nm) on layer 1:
/// one net, with the stack that puts the three layers 100 nm apart.
fn via_pair(
    cuts: &[(i64, i64, i64, i64)],
) -> (gpurify_geom::GeometryStore, NetTable, Connectivity) {
    let mut builder = GeometryStoreBuilder::default();
    for (layer, xlo, xhi) in [(0, 0, 5_000), (2, 4_000, 9_000)] {
        builder.push(
            LayerId(layer),
            &[dbu(xlo), dbu(xhi), dbu(xhi), dbu(xlo)],
            &[dbu(0), dbu(0), dbu(1_000), dbu(1_000)],
        );
    }
    for &(xlo, ylo, xhi, yhi) in cuts {
        builder.push(
            LayerId(1),
            &[dbu(xlo), dbu(xhi), dbu(xhi), dbu(xlo)],
            &[dbu(ylo), dbu(ylo), dbu(yhi), dbu(yhi)],
        );
    }
    let (store, _) = builder.finish(3);
    let connectivity = Connectivity {
        conductors: vec![LayerId(0), LayerId(2)],
        via_cut: vec![LayerId(1)],
        via_connects: vec![(LayerId(0), LayerId(2))],
        intra_layer_touch: true,
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    extract_nets_into(&store, &connectivity, &mut nets);
    assert_eq!(nets.net_count(), 1, "the cuts join the bars");
    (store, nets, connectivity)
}

/// `m1` at 0.1 ohm/sq, cuts at 5 ohm each, `m2` at 0.08 ohm/sq, 100 nm
/// thick and 100 nm apart.
fn via_stack() -> gpurify_ingest::deck::ProcessStack {
    let mut stack = uniform_stack(3, 1.0, 0.25);
    stack.height_nm = vec![300.0, 400.0, 500.0];
    stack.sheet_res_ohm_sq = vec![0.1, 5.0, 0.08];
    stack
}

/// Oracle: definition (F23). A via joins the layers it connects, so an `m1`
/// bar and an `m2` bar joined by one cut are one circuit: the port runs from
/// `m1`'s far end at `x = 0` to `m2`'s at `x = 9` um, and the cut, centred
/// at `x = 4.2` um, lands both centre lines there. So the current crosses
/// 4.2 squares of `m1`, the cut, and 4.8 squares of `m2`:
/// `0.42 + 5 + 0.384 = 5.804` ohm. Two cuts side by side across the bar
/// land at the same points and conduct in parallel, `0.42 + 2.5 + 0.384`.
/// `Re(Z)` of one series path is its resistances' sum, so both hold to
/// round-off (`1e-9`). Before, vias joined nothing and the net read 0 ohm.
#[test]
fn a_via_joins_the_layers_it_connects() {
    for (what, cuts, ohm) in [
        (
            "one cut",
            vec![(4_100, 100, 4_300, 300)],
            0.42 + 5.0 + 0.384,
        ),
        (
            "two cuts across the bar",
            vec![(4_100, 100, 4_300, 300), (4_100, 600, 4_300, 800)],
            0.42 + 2.5 + 0.384,
        ),
    ] {
        let (store, nets, connectivity) = via_pair(&cuts);
        let mut out = InductMatrix::default();
        extract_inductance_into(
            &store,
            &nets,
            &connectivity,
            &[NetId(0)],
            &via_stack(),
            grid(),
            &mut out,
        )
        .expect("a via-joined pair over a stated stack solves");
        let r = out.r_ohm[0];
        assert!(
            ((r - ohm) / ohm).abs() < 1e-9,
            "{what}: {r} ohm, want {ohm}"
        );
        assert!(out.l_henry[0] > 0.0, "{what}: L = {}", out.l_henry[0]);
    }
}

/// Oracle: definition (F23). A net whose pieces do not join into one
/// circuit has no port impedance: two bars meeting only at a corner are one
/// net, but no current crosses a point, so the solve refuses the net rather
/// than read `L = 0`, `R = 0`. A via layer with no resistance per cut is
/// refused by name, as a conductor layer is.
#[test]
fn a_net_that_is_not_one_circuit_is_refused() {
    let mut builder = GeometryStoreBuilder::default();
    for (xlo, ylo) in [(0, 0), (5_000, 1_000)] {
        builder.push(
            LayerId(0),
            &[dbu(xlo), dbu(xlo + 5_000), dbu(xlo + 5_000), dbu(xlo)],
            &[dbu(ylo), dbu(ylo), dbu(ylo + 1_000), dbu(ylo + 1_000)],
        );
    }
    let (store, _) = builder.finish(1);
    let connectivity = Connectivity {
        conductors: vec![LayerId(0)],
        intra_layer_touch: true,
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    extract_nets_into(&store, &connectivity, &mut nets);
    assert_eq!(nets.net_count(), 1, "a corner touch joins the net");
    let mut out = InductMatrix::default();
    let stack = uniform_stack(1, 1.0, 0.25);
    match extract_inductance_into(
        &store,
        &nets,
        &connectivity,
        &[NetId(0)],
        &stack,
        grid(),
        &mut out,
    ) {
        Err(InductanceError::Disconnected(0)) => {}
        other => panic!("expected Disconnected(0), got {other:?}"),
    }

    let (store, nets, connectivity) = via_pair(&[(4_100, 100, 4_300, 300)]);
    let mut stack = via_stack();
    stack.sheet_res_ohm_sq[1] = 0.0;
    match extract_inductance_into(
        &store,
        &nets,
        &connectivity,
        &[NetId(0)],
        &stack,
        grid(),
        &mut out,
    ) {
        Err(InductanceError::NoSheetResistance(1)) => {}
        other => panic!("expected NoSheetResistance(1), got {other:?}"),
    }
}

/// Oracle: law. Two runs over the same geometry are the same bits — the
/// determinism gate for the inductance path.
#[test]
fn two_extractions_are_bit_identical() {
    let (store, nets) = one_bar();
    let stack = uniform_stack(1, 1.0, 0.25);
    let mut first = InductMatrix::default();
    let mut second = InductMatrix::default();
    for out in [&mut first, &mut second] {
        extract_inductance_into(
            &store,
            &nets,
            &Connectivity::default(),
            &[NetId(0)],
            &stack,
            grid(),
            out,
        )
        .expect("one bar over a stated stack solves");
    }

    assert_eq!(first.net, second.net);
    let bits = |values: &[f64]| -> Vec<u64> { values.iter().map(|v| v.to_bits()).collect() };
    assert_eq!(
        bits(&first.l_henry),
        bits(&second.l_henry),
        "L must be the same bits"
    );
    assert_eq!(
        bits(&first.r_ohm),
        bits(&second.r_ohm),
        "R must be the same bits"
    );
}

/// Oracle: construct-from-answer, on the refusal. A layer with no sheet
/// resistance has no conductivity, so a net touching it is refused by name —
/// not skipped, which would report an inductance that never saw the conductor.
#[test]
fn a_layer_with_no_sheet_resistance_is_refused_by_name() {
    let (store, nets) = one_bar();
    let mut stack = uniform_stack(1, 1.0, 0.25);
    stack.sheet_res_ohm_sq[0] = 0.0;
    let mut out = InductMatrix::default();
    let error = extract_inductance_into(
        &store,
        &nets,
        &Connectivity::default(),
        &[NetId(0)],
        &stack,
        grid(),
        &mut out,
    )
    .expect_err("a zero sheet resistance is a refusal, not a skip");

    match error {
        InductanceError::NoSheetResistance(layer) => assert_eq!(layer, 0),
        other => panic!("expected NoSheetResistance naming layer 0, got {other:?}"),
    }
}
