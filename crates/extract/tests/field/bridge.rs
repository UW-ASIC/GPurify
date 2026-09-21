//! The geometry bridge: drawn rectangles in, per-net inductance out.
//!
//! Oracle: **construct-from-answer**. A single drawn bar has a closed-form
//! self inductance (the Grover/Rosa formula `integrals::filament` states), so
//! the bridge's answer for that bar is checked against the formula it must
//! reproduce — same dimensions, independent code path through the solver.

use crate::common;

use common::{grid, uniform_stack};
use gpurify_geom::{GeometryStoreBuilder, LayerId};
use gpurify_extract::field::henry::bridge::{
    extract_inductance_into, InductMatrix, InductanceError, InductanceOptions,
};
use gpurify_extract::field::integrals::filament::self_inductance_bar;
use gpurify_check::topology::{NetId, NetTable};
use gpurify_geom::Dbu;

fn dbu(raw: i64) -> Dbu {
    Dbu::new(raw).expect("a test coordinate is in the coordinate domain")
}

/// One 10 µm × 1 µm bar on layer 0 of a 1 nm grid, assigned to net 0.
fn one_bar() -> (gpurify_geom::GeometryStore, NetTable) {
    let mut builder = GeometryStoreBuilder::default();
    builder.push_rect(LayerId(0), dbu(0), dbu(0), dbu(10_000), dbu(1_000));
    let (store, _) = builder.finish(1);
    (store, NetTable::from_assignment(&[NetId(0)]))
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
        &[NetId(0)],
        &stack,
        grid(),
        &InductanceOptions::default(),
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

/// Oracle: law. Two runs over the same geometry are the same bits — the
/// determinism gate for the inductance path.
#[test]
fn two_extractions_are_bit_identical() {
    let (store, nets) = one_bar();
    let stack = uniform_stack(1, 1.0, 0.25);
    let options = InductanceOptions::default();
    let mut first = InductMatrix::default();
    let mut second = InductMatrix::default();
    for out in [&mut first, &mut second] {
        extract_inductance_into(&store, &nets, &[NetId(0)], &stack, grid(), &options, out)
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
        &[NetId(0)],
        &stack,
        grid(),
        &InductanceOptions::default(),
        &mut out,
    )
    .expect_err("a zero sheet resistance is a refusal, not a skip");

    match error {
        InductanceError::NoSheetResistance(layer) => assert_eq!(layer, 0),
        other => panic!("expected NoSheetResistance naming layer 0, got {other:?}"),
    }
}
