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

/// Oracle: closed form (Hall, *Thin Solid Films* 1(4), 1967: the corner
/// square of a right-angle bend counts 0.559 squares, by conformal map).
/// An L of legs 20 and 16 um, 1 um wide, is 19 + 15 squares of straight
/// leg and a corner square, however it is drawn: as one polygon, as two
/// abutting rectangles, or as two full bars overlapping at the corner (one
/// region, one grid: the same bits). The grid, four cells across, reads the
/// corner above Hall's value and below the centre line's one square (a
/// five-point grid converges to it from above: 0.71 at two cells, 0.62 at
/// four, 0.58 at eight, worked by hand on this grid); fails if the bend is
/// a centre line again (exactly one square) or loses its corner (none).
/// Its legs are perpendicular, so `L` is Grover's self inductance of each
/// leg along the centre line, `a − w/2 = 19.5` and `b − w/2 = 15.5` µm, at
/// 100 nm thick, to 1%: the strips of a leg carry its current evenly, and
/// the corner's cells carry under 1% of the total.
#[test]
fn an_l_reads_its_corner_crowded_however_it_is_drawn() {
    let want_l =
        self_inductance_bar(19.5e-6, 1e-6, 0.1e-6) + self_inductance_bar(15.5e-6, 1e-6, 0.1e-6);
    let stack = uniform_stack(1, 1.0, 0.25);
    let mut first: Option<f64> = None;
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
        let corner = r / 0.1 - 34.0;
        assert!(
            corner > 0.559 && corner < 0.66,
            "{what}: {r} ohm, a corner of {corner} squares"
        );
        let same = *first.get_or_insert(r);
        assert!(
            ((r - same) / same).abs() < 1e-9,
            "{what}: {r} ohm against {same}"
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

/// Two bars on layer 0, each its own net: `(xlo, ylo, xhi, yhi)` per bar.
fn two_nets(bars: [(i64, i64, i64, i64); 2]) -> (gpurify_geom::GeometryStore, NetTable) {
    let mut builder = GeometryStoreBuilder::default();
    for (xlo, ylo, xhi, yhi) in bars {
        builder.push(
            LayerId(0),
            &[dbu(xlo), dbu(xhi), dbu(xhi), dbu(xlo)],
            &[dbu(ylo), dbu(ylo), dbu(yhi), dbu(yhi)],
        );
    }
    let (store, _) = builder.finish(1);
    let connectivity = Connectivity {
        conductors: vec![LayerId(0)],
        ..Connectivity::default()
    };
    let mut nets = NetTable::default();
    extract_nets_into(&store, &connectivity, &mut nets);
    assert_eq!(nets.net_count(), 2, "two bars apart are two nets");
    (store, nets)
}

/// The inductance solve of both nets of [`two_nets`] together.
fn solve_both(bars: [(i64, i64, i64, i64); 2]) -> InductMatrix {
    let (store, nets) = two_nets(bars);
    let mut out = InductMatrix::default();
    extract_inductance_into(
        &store,
        &nets,
        &Connectivity::default(),
        &[NetId(0), NetId(1)],
        &uniform_stack(1, 1.0, 0.25),
        grid(),
        &mut out,
    )
    .expect("two bars over a stated stack solve");
    assert_eq!(out.net, [NetId(0), NetId(1)]);
    assert_eq!(out.m_henry.len(), 4, "a 2 x 2 inductance matrix");
    out
}

/// Two 20 µm × 1 µm bars along x, their centre lines `pitch` nm apart.
fn side_by_side(pitch: i64) -> [(i64, i64, i64, i64); 2] {
    [(0, 0, 20_000, 1_000), (0, pitch, 20_000, pitch + 1_000)]
}

/// Oracle: closed form (Grover, *Inductance Calculations*, 1946, ch. 6: two
/// equal parallel filaments `l` long, `d` apart, side by side,
/// `M = (µ₀/2π) l [asinh(l/d) − √(1 + d²/l²) + d/l]`). Bars 20 µm long, 1 µm
/// wide and 100 nm thick, their centre lines 12 µm apart: their geometric-mean
/// distance is `d` less `(w² − t²)/(12 d²)` of `ln d`, which moves `M` by
/// 5e-4, inside the 1e-3 allowed. Fails if the mutual is not computed (zero),
/// read off the wrong entry (the self inductance), or scaled wrongly.
#[test]
fn two_parallel_bars_have_grover_s_mutual_inductance() {
    let out = solve_both(side_by_side(12_000));
    let (l, d) = (20e-6_f64, 12e-6_f64);
    let want = 2e-7 * l * ((l / d).asinh() - (1.0 + (d / l).powi(2)).sqrt() + d / l);
    for got in [out.m_henry[1], out.m_henry[2]] {
        let relative = ((got - want) / want).abs();
        assert!(
            relative < 1e-3,
            "M = {got:e} H against Grover's {want:e} H, off by {relative:e}"
        );
    }
}

/// Oracle: laws. The port impedance matrix of a reciprocal network is
/// symmetric, so `M₀₁ = M₁₀` to round-off; its diagonal is each net's own
/// `L`; an open neighbour carries no current, so each bar's `L` and `R` are
/// what it reads solved alone, to round-off; and the pair's inductance
/// matrix is positive definite, `M² < L₀L₁`. Fails if a column is read for
/// a row, or the other port is driven while one is measured.
#[test]
fn the_inductance_matrix_is_reciprocal_and_an_open_neighbour_changes_nothing() {
    let pair = solve_both(side_by_side(2_000));
    let (m01, m10) = (pair.m_henry[1], pair.m_henry[2]);
    let scale = (pair.l_henry[0] * pair.l_henry[1]).sqrt();
    assert!(
        (m01 - m10).abs() <= 1e-9 * scale,
        "M01 {m01:e}, M10 {m10:e}"
    );
    assert!(m01 * m01 < pair.l_henry[0] * pair.l_henry[1], "M {m01:e}");
    assert_eq!(pair.m_henry[0].to_bits(), pair.l_henry[0].to_bits());
    assert_eq!(pair.m_henry[3].to_bits(), pair.l_henry[1].to_bits());

    let (store, nets) = two_nets(side_by_side(2_000));
    for net in 0..2_u32 {
        let mut alone = InductMatrix::default();
        extract_inductance_into(
            &store,
            &nets,
            &Connectivity::default(),
            &[NetId(net)],
            &uniform_stack(1, 1.0, 0.25),
            grid(),
            &mut alone,
        )
        .expect("one bar solves");
        let i = net as usize;
        for (what, got, want) in [
            ("L", pair.l_henry[i], alone.l_henry[0]),
            ("R", pair.r_ohm[i], alone.r_ohm[0]),
        ] {
            assert!(
                ((got - want) / want).abs() < 1e-9,
                "net {net}: {what} {got:e} with its neighbour, {want:e} alone"
            );
        }
    }
}

/// Oracle: laws. Parallel bars' mutual inductance is positive (both ports
/// run the same way along x) and falls as they move apart; perpendicular
/// bars have none, since the Neumann integrand carries `û₁ · û₂ = 0`.
#[test]
fn mutual_inductance_falls_with_distance_and_vanishes_across() {
    let mut last = f64::INFINITY;
    for pitch in [2_000, 3_000, 4_000, 8_000, 12_000, 16_000] {
        let m = solve_both(side_by_side(pitch)).m_henry[1];
        assert!(m > 0.0 && m < last, "pitch {pitch}: M {m:e} after {last:e}");
        last = m;
    }
    let across = solve_both([(0, 0, 20_000, 1_000), (25_000, -10_000, 26_000, 10_000)]);
    let scale = (across.l_henry[0] * across.l_henry[1]).sqrt();
    assert!(
        across.m_henry[1].abs() <= 1e-12 * scale,
        "perpendicular bars: M {:e}",
        across.m_henry[1]
    );
}
