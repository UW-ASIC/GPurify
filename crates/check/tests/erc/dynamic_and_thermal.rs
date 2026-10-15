//! The worst switching cycle (`dynamic_ir_drop`, ERC-E11) and the
//! self-heated, statistical EM limit (`em_thermal`, ERC-E13), against closed
//! forms and the laws an RC grid stepped by backward Euler obeys.
//!
//! Every grid here is built column by column, so each closed form is worked
//! by hand: one RC node's backward-Euler recurrence and its continuous ramp
//! response, the static solve of every load at its peak, `ΔT = P θ`, Black's
//! equation at two temperatures, and the weakest link over lognormal wires.
//! The laws hold on random grids: `(G + C/h)⁻¹` is nonnegative, so more
//! current never lowers a drop and decap never raises one above the
//! decap-free value; a hotter run or more current never clears a wire.

use crate::common;

use common::{
    declared_supplies, head, limit_net, manufacturing_grid, microamps, millivolts, parallel_bundle,
    random_grid, rule, run_of, series_chain, solve, GridBuilder,
};
use gpurify_check::erc::facts::IntentMap;
use gpurify_check::erc::power::STEPS_PER_RISE;
use gpurify_check::erc::power::{self, EdgeKind, PowerError, PowerGrid, Solved, Stimulus};
use gpurify_check::erc::rules::electrical::{
    check_dynamic_ir_drop, check_electromigration, check_em_thermal, DynamicIrDropTable,
    ElectromigrationTable, EmThermalTable,
};
use gpurify_check::erc::Scratch;
use gpurify_check::report::{Measurement, Outcome, Violations};
use gpurify_check::topology::NetId;
use gpurify_geom::{prefix, CurrentDensity, LayerId, Qty, Temperature};
use gpurify_ingest::intent::{NetLimits, Switching};
use gpurify_testgen::{assert_close, assert_close_relative, Rng};

/// Boltzmann's constant in eV/K (CODATA 2018).
const K_EV: f64 = 8.617_333_262e-5;

fn kelvin(value: f64) -> Qty<Temperature, { prefix::BASE }> {
    Qty::new(value)
}

fn density(value: f64) -> Qty<CurrentDensity, { prefix::BASE }> {
    Qty::new(value)
}

/// One switching event: `peak` µA at each node, all `rise` ps wide, `cap` pF
/// at each node, followed for `window` ps.
fn stimulus(peak: &[f64], rise: f64, cap: &[f64], window: f64) -> Stimulus {
    Stimulus {
        node_peak: peak.iter().map(|&p| microamps(p)).collect(),
        node_rise_ps: vec![rise; peak.len()],
        node_cap_pf: cap.to_vec(),
        window_ps: window,
    }
}

/// The engine's response, mV per node.
fn respond(grid: &PowerGrid, stimulus: &Stimulus) -> Vec<f64> {
    let mut scratch = power::SolveScratch::default();
    let mut out = Vec::new();
    power::transient_into(grid, stimulus, &mut scratch, &mut out)
        .expect("this grid is anchored and its stimulus finite");
    out.iter().map(|v| v.raw()).collect()
}

/// The triangle at step `k` of a pulse `STEPS_PER_RISE` steps wide: 0 at the
/// ends, 1 in the middle.
fn triangle(k: u32) -> f64 {
    let fraction = f64::from(k) / f64::from(STEPS_PER_RISE);
    if fraction <= 1.0 {
        1.0 - (2.0 * fraction - 1.0).abs()
    } else {
        0.0
    }
}

/// The largest value of one RC node's backward-Euler recurrence,
/// `r[k+1] = (c r[k] + i[k+1]) / (c + g)` with `c = 1000 C / h` and
/// `g = 1000 / R` (µA per mV, from pF over ps and from Ω), `h` the rise over
/// `STEPS_PER_RISE`, over ten rises.
fn recurrence_peak(ohm: f64, cap_pf: f64, peak_ua: f64, rise_ps: f64) -> f64 {
    let h = rise_ps / f64::from(STEPS_PER_RISE);
    let (c, g) = (1000.0 * cap_pf / h, 1000.0 / ohm);
    let (mut r, mut best) = (0.0f64, 0.0f64);
    for k in 1..=10 * STEPS_PER_RISE {
        r = (c * r + peak_ua * triangle(k)) / (c + g);
        best = best.max(r);
    }
    best
}

/// Oracle: closed form of the documented discretization. One node behind `R`
/// with decap `C`, stepped by backward Euler at `STEPS_PER_RISE` steps per
/// rise, is the scalar recurrence [`recurrence_peak`] works by hand; the
/// engine's response there is that recurrence's peak, and its pad's is zero.
/// A wrong decap unit (the `1000` in `c`), a pulse sampled off its step, or a
/// state not carried between steps each move the peak.
#[test]
fn one_rc_node_follows_its_backward_euler_recurrence() {
    for (ohm, cap_pf, peak_ua, rise_ps) in [
        (1.0, 10.0, 1000.0, 100.0),
        (2.5, 0.3, 400.0, 50.0),
        (0.1, 200.0, 20_000.0, 20.0),
    ] {
        let grid = series_chain(1, ohm, 1_800.0, 0.0);
        let got = respond(
            &grid,
            &stimulus(&[0.0, peak_ua], rise_ps, &[0.0, cap_pf], 10.0 * rise_ps),
        );
        assert_close("the pad's response", got[0], 0.0, 0.0);
        assert_close_relative(
            "the node's peak",
            got[1],
            recurrence_peak(ohm, cap_pf, peak_ua, rise_ps),
            1e-12,
        );
    }
}

/// The continuous peak of one RC node's response to the triangle: `R k` times
/// `ρ(t) - 2 ρ(t - t_r/2) + ρ(t - t_r)`, `ρ(s) = s - τ (1 - e^{-s/τ})` the
/// ramp response (the integral of the step response `1 - e^{-t/τ}`), `k`
/// the ramp's slope. Unimodal: a scan, then golden section around its best.
fn closed_form_peak(ohm: f64, peak_ua: f64, rise_ps: f64, tau_ps: f64) -> f64 {
    let slope = 2.0 * peak_ua / rise_ps;
    let ramp = |s: f64| {
        if s > 0.0 {
            s - tau_ps * (1.0 - (-s / tau_ps).exp())
        } else {
            0.0
        }
    };
    let drop = |t: f64| {
        ohm / 1000.0 * slope * (ramp(t) - 2.0 * ramp(t - rise_ps / 2.0) + ramp(t - rise_ps))
    };
    let end = rise_ps + 10.0 * tau_ps;
    let samples = 20_000u32;
    let at = |i: u32| end * f64::from(i) / f64::from(samples);
    let best = (0..=samples)
        .max_by(|&a, &b| drop(at(a)).total_cmp(&drop(at(b))))
        .expect("samples");
    let (mut lo, mut hi) = (at(best.saturating_sub(1)), at((best + 1).min(samples)));
    for _ in 0..200 {
        let (a, b) = (lo + (hi - lo) / 3.0, hi - (hi - lo) / 3.0);
        if drop(a) < drop(b) {
            lo = a;
        } else {
            hi = b;
        }
    }
    drop(0.5 * (lo + hi))
}

/// Oracle: closed form. A ramp `k t` into `R` with decap `C` gives
/// `R k (t - τ (1 - e^{-t/τ}))` (`τ = R C`), and the triangle is three ramps
/// ([`closed_form_peak`]). Backward Euler damps, so the engine's peak is never
/// above the continuous one, and at 128 steps per rise it is at most 0.61 %
/// below it for any `τ` (worst near a tenth of the rise, 0.601 %), as the
/// constant's doc states. A step count halved, or a forward-Euler update,
/// leaves this band.
#[test]
fn an_rc_nodes_peak_is_its_closed_form_within_backward_eulers_error() {
    let (ohm, peak, rise) = (1.0, 1000.0, 100.0);
    for tau_over_rise in [0.001, 0.01, 0.03, 0.11, 0.3, 1.0, 3.0, 30.0] {
        let tau = tau_over_rise * rise;
        // τ = R C: one ohm times one picofarad is one picosecond.
        let cap = tau / ohm;
        let grid = series_chain(1, ohm, 1_800.0, 0.0);
        let got = respond(
            &grid,
            &stimulus(&[0.0, peak], rise, &[0.0, cap], 10.0 * rise),
        )[1];
        let exact = closed_form_peak(ohm, peak, rise, tau);
        assert!(
            got <= exact * (1.0 + 1e-9),
            "τ = {tau_over_rise} t_r: backward Euler peaks at {got} mV, above the closed form's {exact}"
        );
        assert!(
            got >= exact * (1.0 - 0.0061),
            "τ = {tau_over_rise} t_r: backward Euler peaks at {got} mV, more than 0.61 % under {exact}"
        );
    }
}

/// Oracle: closed form. Without decap a backward-Euler step is the static
/// solve of that step's loads, and every pulse peaks on step
/// `STEPS_PER_RISE / 2`, so each node's response is the static drop with
/// every load at its peak: `solve_into` on the same grid, a separate path
/// through Kirchhoff's law. A pulse that missed its peak step, or a state
/// leaking into a decap-free step, reads low.
#[test]
fn without_decap_a_grid_responds_with_the_static_drop_of_its_peaks() {
    for seed in 1..=6u64 {
        let mut grid = random_grid(seed, 30, 20);
        let n = grid.node_count();
        let peaks: Vec<f64> = grid.node_load.iter().map(|l| 3.0 * l.raw()).collect();
        let got = respond(&grid, &stimulus(&peaks, 50.0, &vec![0.0; n], 50.0));
        for (load, &peak) in grid.node_load.iter_mut().zip(&peaks) {
            *load = microamps(peak);
        }
        let reference = solve(&grid);
        let scale = reference
            .node_drop
            .iter()
            .fold(0.0f64, |acc, d| acc.max(d.raw().abs()));
        for (node, (&have, want)) in got.iter().zip(&reference.node_drop).enumerate() {
            assert_close(
                &format!("seed {seed}, node {node}"),
                have,
                want.raw(),
                1e-8 * scale,
            );
        }
    }
}

/// Random decap, 0 to 5 pF per node.
fn random_caps(rng: &mut Rng, n: usize) -> Vec<f64> {
    (0..n).map(|_| 5.0 * rng.unit()).collect()
}

/// Oracle: law. `(G + C/h)⁻¹` of an RC grid is nonnegative (a nonsingular
/// M-matrix's inverse) and so is `C/h`, so every step's response is a
/// nonnegative combination of the loads: doubling one load's peak lowers no
/// node's response at any step, nor its peak. A sign error in the decap term
/// or the right-hand side breaks it.
#[test]
fn more_current_never_lowers_a_nodes_response() {
    for seed in 1..=6u64 {
        let grid = random_grid(seed, 30, 20);
        let n = grid.node_count();
        let mut rng = Rng::new(seed);
        let caps = random_caps(&mut rng, n);
        let peaks: Vec<f64> = grid.node_load.iter().map(|l| l.raw()).collect();
        let base = respond(&grid, &stimulus(&peaks, 40.0, &caps, 400.0));
        let scale = base.iter().fold(0.0f64, |acc, r| acc.max(r.abs()));
        let mut more = peaks.clone();
        more[n / 2] *= 2.0;
        let raised = respond(&grid, &stimulus(&more, 40.0, &caps, 400.0));
        for node in 0..n {
            assert!(
                raised[node] >= base[node] - 1e-9 * scale,
                "seed {seed}, node {node}: {} mV with more current, {} mV before",
                raised[node],
                base[node]
            );
        }
    }
}

/// Oracle: law. With every load at most its peak, no drop exceeds the
/// decap-free `D = G⁻¹ I_peak`: from `r[k] <= D`,
/// `r[k+1] = (G + C/h)⁻¹ (C/h r[k] + i) <= (G + C/h)⁻¹ (C/h + G) D = D`.
/// So decap never raises a node above its decap-free response, on any grid.
/// On one RC node more decap strictly lowers the peak: a wider time constant's
/// kernel is the narrower one's convolved with a probability measure. Decap
/// that charged the wrong way, or added to the load, breaks both.
#[test]
fn decap_never_raises_a_drop_and_more_of_it_lowers_an_rc_nodes_peak() {
    for seed in 1..=6u64 {
        let grid = random_grid(seed, 30, 20);
        let n = grid.node_count();
        let mut rng = Rng::new(seed ^ 0xdec);
        let caps = random_caps(&mut rng, n);
        let peaks: Vec<f64> = grid.node_load.iter().map(|l| l.raw()).collect();
        let free = respond(&grid, &stimulus(&peaks, 40.0, &vec![0.0; n], 400.0));
        let scale = free.iter().fold(0.0f64, |acc, r| acc.max(r.abs()));
        let held = respond(&grid, &stimulus(&peaks, 40.0, &caps, 400.0));
        for node in 0..n {
            assert!(
                held[node] <= free[node] + 1e-9 * scale,
                "seed {seed}, node {node}: {} mV with decap, {} mV without",
                held[node],
                free[node]
            );
        }
    }
    let grid = series_chain(1, 1.0, 1_800.0, 0.0);
    let mut last = f64::INFINITY;
    for cap in [0.0, 1.0, 10.0, 100.0, 1000.0] {
        let peak = respond(&grid, &stimulus(&[0.0, 1000.0], 100.0, &[0.0, cap], 1000.0))[1];
        assert!(peak < last, "{cap} pF peaks at {peak} mV, not below {last}");
        last = peak;
    }
}

/// Oracle: construct-from-answer, against `transient_into`'s documented
/// errors: a negative or non-finite decap, a non-finite peak, and a switching
/// node with no rise are refused, naming the node; a grid where nothing
/// switches responds with zeros.
#[test]
fn a_stimulus_the_grid_cannot_take_is_refused() {
    let grid = series_chain(2, 1.0, 1_800.0, 0.0);
    let mut scratch = power::SolveScratch::default();
    let mut out = Vec::new();
    for (peak, rise, cap) in [
        ([0.0, 1.0, 0.0], 10.0, [0.0, -1.0, 0.0]),
        ([0.0, 1.0, 0.0], 10.0, [0.0, f64::NAN, 0.0]),
        ([0.0, f64::INFINITY, 0.0], 10.0, [0.0; 3]),
        ([0.0, 1.0, 0.0], 0.0, [0.0; 3]),
    ] {
        let result = power::transient_into(
            &grid,
            &stimulus(&peak, rise, &cap, 100.0),
            &mut scratch,
            &mut out,
        );
        assert_eq!(
            result,
            Err(PowerError::NotFinite(1)),
            "{peak:?} {rise} {cap:?}"
        );
    }
    power::transient_into(
        &grid,
        &stimulus(&[0.0; 3], 10.0, &[1.0; 3], 100.0),
        &mut scratch,
        &mut out,
    )
    .expect("nothing switches");
    assert!(out.iter().all(|v| v.raw() == 0.0), "{out:?}");
}

/// A net that switches `toggle_rate` of its cycles, `period` and `rise` ps,
/// with `decap` pF, its budget `budget` µA and its dynamic limit `limit` mV.
fn switching_intent(
    power_net: NetId,
    ground_net: NetId,
    budget: f64,
    decap: f64,
    limit: f64,
) -> IntentMap {
    let mut map = declared_supplies(power_net, ground_net, 1_800.0);
    limit_net(
        &mut map,
        NetId(0),
        NetLimits {
            budget_current_ua: Some(budget),
            dynamic: Some(Switching {
                max_drop: millivolts(limit),
                toggle_rate: 0.25,
                clock_period_ps: 1000.0,
                rise_time_ps: 100.0,
                decap_pf: decap,
            }),
            ..NetLimits::default()
        },
    );
    map
}

/// Oracle: closed form. One load of 1 mA behind 1 Ω: the static drop is
/// 1 mV; one switching event carries the charge of `1 / 0.25` cycles of
/// 1000 ps, `Q = 1000 µA × 4000 ps`, as a 100 ps triangle peaking at
/// `2 Q / 100 ps = 80 mA`. Without decap that is 80 mV, 81 mV in all; with
/// 10 pF it is the recurrence's peak plus 1 mV. On a ground rail the same
/// numbers are a rise. A limit a part in a million under flags the load's
/// node with that drop; one over passes. Every node of the net is examined.
#[test]
fn dynamic_ir_drop_is_the_static_drop_plus_the_worst_cycle() {
    let id = rule(40);
    let table = DynamicIrDropTable { head: head(id) };
    for (decap, dynamic) in [
        (0.0, 80.0),
        (10.0, recurrence_peak(1.0, 10.0, 80_000.0, 100.0)),
    ] {
        let total = 1.0 + dynamic;
        for ground in [false, true] {
            let (nominal, load) = if ground {
                (0.0, -1000.0)
            } else {
                (1_800.0, 1000.0)
            };
            let grid = series_chain(1, 1.0, nominal, load);
            let solution = solve(&grid);
            let nets = if ground {
                (NetId(1), NetId(0))
            } else {
                (NetId(0), NetId(1))
            };
            for (factor, flagged) in [(1.0 - 1e-6, true), (1.0 + 1e-6, false)] {
                let intent = switching_intent(nets.0, nets.1, 1000.0, decap, total * factor);
                let (mut out, mut runs) = (Violations::default(), Vec::new());
                check_dynamic_ir_drop(
                    Ok(Some(Solved {
                        grid: &grid,
                        solution: &solution,
                    })),
                    &intent,
                    &table,
                    &mut Scratch::default(),
                    &mut out,
                    &mut runs,
                );
                let run = run_of(&runs, id);
                assert_eq!(run.outcome, Outcome::Ran);
                assert_eq!(run.examined, 2, "the pad and the load");
                assert_eq!(
                    out.len(),
                    usize::from(flagged),
                    "decap {decap}, ground {ground}"
                );
                if flagged {
                    let Measurement::Voltage(mv) = out.get(0).measured else {
                        panic!("a drop is a voltage");
                    };
                    assert_close_relative("the dynamic drop", mv.raw(), total, 1e-9);
                    assert_eq!(out.get(0).shapes.0, grid.node_poly[1]);
                }
            }
        }
    }
}

/// An `em_thermal` row on `layers`, `density` A/m and `per_cut` µA at
/// 105 °C, Ea 0.9 eV, n 2, a Blech limit too small to exempt anything.
fn thermal_table(
    id: gpurify_ingest::StrId,
    layers: &[LayerId],
    density_am: f64,
    per_cut: f64,
) -> EmThermalTable {
    EmThermalTable {
        head: head(id),
        layer_start: vec![0, u32::try_from(layers.len()).expect("few layers")],
        layer: layers.to_vec(),
        max_density: vec![density(density_am); layers.len()],
        max_current_per_cut: vec![microamps(per_cut); layers.len()],
        blech_limit: vec![microamps(1e-6); layers.len()],
        reference_temperature: vec![kelvin(378.15)],
        activation_energy_ev: vec![0.9],
        current_exponent: vec![2.0],
        thermal_conductivity: vec![1.0],
        heat_spreading: vec![0.88],
        sigma: vec![0.5],
        limit_failure: vec![0.001],
        max_failure: vec![1.0],
        height_nm: Vec::new(),
    }
}

/// Black's derating from 105 °C to `t`: `exp(Ea / (n k) (1/t - 1/T_ref))`.
fn black(t: f64) -> f64 {
    (0.9 / (2.0 * K_EV) * (1.0 / t - 1.0 / 378.15)).exp()
}

/// Run one `em_thermal` table over a solved grid at `t` kelvin.
fn run_thermal(
    grid: &PowerGrid,
    table: &EmThermalTable,
    t: f64,
) -> (Violations, Vec<gpurify_check::report::RuleRun>) {
    let solution = solve(grid);
    let intent = declared_supplies(NetId(0), NetId(1), 1_800.0);
    let (mut out, mut runs) = (Violations::default(), Vec::new());
    check_em_thermal(
        Ok(Some(Solved {
            grid,
            solution: &solution,
        })),
        &intent,
        manufacturing_grid(),
        kelvin(t),
        table,
        &mut out,
        &mut runs,
    );
    (out, runs)
}

fn current_limit(m: Measurement) -> f64 {
    match m {
        Measurement::Current(c) => c.raw(),
        other => panic!("{other:?} is not a current"),
    }
}

/// Oracle: closed form, Banerjee et al. (DAC 1999) eqs. 8 and 10 with eq. 14's
/// spreading. A 1 µm × 1 µm metal segment of 1 Ω, 1 µm above the substrate,
/// carries 10 mA: `P = I² R = 1e-4 W`, `θ = t / (K L (W + φ t)) =
/// 1e-6 / (1 × 1e-6 × 1.88e-6) K/W`, so it runs `ΔT = P θ = 53.19 K` above
/// the 85 °C run, and its limit is 100 A/m × 1 µm derated by Black's equation
/// to that temperature. The cut beyond it, at the hotter metal of its two
/// ends, takes the same rise on its per-cut limit. Heating dropped, or the
/// cut left at the run temperature, changes both limits.
#[test]
fn self_heating_raises_a_wire_by_its_power_times_its_thermal_resistance() {
    let mut builder = GridBuilder::new();
    builder.node(0, 1_800.0, 0.0);
    builder.node(1_000, 1_800.0, 0.0);
    builder.node(2_000, 1_800.0, 10_000.0);
    builder.pad(0, 1_800.0);
    builder.edge(0, 1, 1.0);
    builder.edge_on(LayerId(1), 1, 2, 0.5);
    let mut grid = builder.finish();
    grid.edge_kind[1] = EdgeKind::Via;
    let id = rule(41);
    let mut table = thermal_table(id, &[LayerId(0), LayerId(1)], 100.0, 50.0);
    table.height_nm = vec![1_000.0];
    let (out, runs) = run_thermal(&grid, &table, 358.15);

    let rise = 1e-4 * 1e-6 / (1.0 * 1e-6 * (1e-6 + 0.88 * 1e-6));
    let hot = black(358.15 + rise);
    assert_eq!(run_of(&runs, id).examined, 2);
    assert_eq!(out.len(), 2, "the segment and the cut");
    assert_close_relative(
        "the segment's limit",
        current_limit(out.get(0).limit),
        100.0 * hot,
        1e-12,
    );
    assert_close_relative(
        "the cut's limit",
        current_limit(out.get(1).limit),
        50.0 * hot,
        1e-12,
    );
    assert_close_relative(
        "the current",
        current_limit(out.get(0).measured),
        10_000.0,
        1e-9,
    );
}

/// Oracle: closed form, Black's equation (Black 1969) held at equal lifetime:
/// with no self-heating (no layer height) the limit at temperature `T` is
/// `J W exp(Ea / (n k) (1/T - 1/T_ref))`, so the limits at 85 °C and 125 °C
/// stand in the ratio `exp(Ea / (n k) (1/358.15 - 1/398.15))`; and each is
/// `electromigration`'s limit for the same row (metamorphic: no heat makes
/// the kinds agree). A row with `sigma` 0 is refused, not run.
#[test]
fn blacks_equation_holds_between_two_temperatures() {
    let grid = series_chain(1, 1.0, 1_800.0, 5_000.0);
    let id = rule(42);
    let table = thermal_table(id, &[LayerId(0)], 100.0, 50.0);
    let mut limits = Vec::new();
    for t in [358.15, 398.15] {
        let (out, _) = run_thermal(&grid, &table, t);
        let limit = current_limit(out.get(0).limit);
        assert_close_relative("the derated limit", limit, 100.0 * black(t), 1e-12);
        let solution = solve(&grid);
        let em = ElectromigrationTable {
            head: head(id),
            layer_start: vec![0, 1],
            layer: vec![LayerId(0)],
            max_density: vec![density(100.0)],
            max_current_per_cut: vec![microamps(50.0)],
            blech_limit: vec![microamps(1e-6)],
            reference_temperature: vec![kelvin(378.15)],
            activation_energy_ev: vec![0.9],
            current_exponent: vec![2.0],
        };
        let (mut out, mut runs) = (Violations::default(), Vec::new());
        check_electromigration(
            Ok(Some(Solved {
                grid: &grid,
                solution: &solution,
            })),
            &declared_supplies(NetId(0), NetId(1), 1_800.0),
            manufacturing_grid(),
            kelvin(t),
            &em,
            &mut out,
            &mut runs,
        );
        assert_eq!(
            current_limit(out.get(0).limit).to_bits(),
            limit.to_bits(),
            "electromigration at {t} K"
        );
        limits.push(limit);
    }
    assert_close_relative(
        "the ratio of the limits",
        limits[0] / limits[1],
        (0.9 / (2.0 * K_EV) * (1.0 / 358.15 - 1.0 / 398.15)).exp(),
        1e-12,
    );
    let mut refused = thermal_table(id, &[LayerId(0)], 100.0, 50.0);
    refused.sigma = vec![0.0];
    let (out, runs) = run_thermal(&grid, &refused, 358.15);
    assert_eq!(run_of(&runs, id).outcome, Outcome::Refused);
    assert!(out.is_empty());
}

/// Oracle: standard tables and the weakest link. With the limit characterised
/// at 2.5 % failed (`z = -1.959963984540054`, the published normal quantile)
/// and `σ = 2 ln 0.5 / (z_0.1% - z_2.5%)`, a wire at half its limit sits at
/// `z_0.1% = -3.090232306167813`: it fails with probability 0.1 %. Three such
/// wires in parallel fail together with `1 - 0.999³ = 0.002997001`
/// (Kitchin's statistical EM budgeting): a budget a part in a million under
/// that flags the chip once, measured at that probability; one over passes.
/// A wrong quantile, a dropped `n / σ`, or a sum of probabilities in place of
/// the product moves the measure.
#[test]
fn the_chip_fails_when_any_lognormal_wire_does() {
    let (z_limit, z_wire) = (-1.959_963_984_540_054, -3.090_232_306_167_813);
    let grid = parallel_bundle(3, 1.0, 1_800.0, 3_000.0);
    let id = rule(43);
    // 2000 A/m over 1 µm is 2000 µA at the reference temperature: each wire
    // carries half of it.
    let mut table = thermal_table(id, &[LayerId(0)], 2_000.0, 50.0);
    table.sigma = vec![2.0 * 0.5f64.ln() / (z_wire - z_limit)];
    table.limit_failure = vec![0.025];
    let chip = 1.0 - 0.999f64.powi(3);
    for (factor, flagged) in [(1.0 - 1e-6, true), (1.0 + 1e-6, false)] {
        table.max_failure = vec![chip * factor];
        let (out, runs) = run_thermal(&grid, &table, 378.15);
        assert_eq!(run_of(&runs, id).examined, 3);
        assert_eq!(out.len(), usize::from(flagged), "budget {}", chip * factor);
        if flagged {
            let Measurement::Ratio(failed) = out.get(0).measured else {
                panic!("a failure probability is a ratio");
            };
            assert_close_relative("the chip's failure probability", failed, chip, 1e-9);
        }
    }
}

/// The current findings and the chip's probability of one run.
fn findings(out: &Violations) -> (Vec<(i64, u32)>, f64) {
    let mut wires = Vec::new();
    let mut chip = 0.0;
    for row in 0..out.len() {
        let v = out.get(row);
        match v.measured {
            Measurement::Current(_) => wires.push((v.at.x.raw(), v.shapes.1.map_or(0, |p| p.0))),
            Measurement::Ratio(f) => chip = f,
            other => panic!("{other:?}"),
        }
    }
    wires.sort_unstable();
    (wires, chip)
}

/// Oracle: law. A wire is flagged when `I > J W derate(T_run + a I²)`: the left
/// side grows with the current, the right falls with both the current and the
/// run temperature, and a wire's failure probability rises with its `I /
/// allowed`. So on random grids a hotter run, or every load half again, flags
/// every wire flagged before and leaves the chip no less likely to fail.
/// Self-heating that cooled a wire, or a derating the wrong way, breaks it.
#[test]
fn a_hotter_run_or_more_current_never_clears_a_wire() {
    let id = rule(44);
    let mut table = thermal_table(id, &[LayerId(0)], 300.0, 50.0);
    table.height_nm = vec![500.0];
    table.max_failure = vec![1e-300];
    for seed in 1..=6u64 {
        let grid = random_grid(seed, 20, 10);
        let (base, base_chip) = findings(&run_thermal(&grid, &table, 358.15).0);
        let (hot, hot_chip) = findings(&run_thermal(&grid, &table, 398.15).0);
        let mut heavy = random_grid(seed, 20, 10);
        for load in &mut heavy.node_load {
            *load = microamps(1.5 * load.raw());
        }
        let (more, more_chip) = findings(&run_thermal(&heavy, &table, 358.15).0);
        for wire in &base {
            assert!(
                hot.contains(wire),
                "seed {seed}: {wire:?} cleared by a hotter run"
            );
            assert!(
                more.contains(wire),
                "seed {seed}: {wire:?} cleared by more current"
            );
        }
        assert!(
            hot_chip >= base_chip && more_chip >= base_chip,
            "seed {seed}"
        );
    }
}

/// An `em_thermal` row runs only on a model with meaning, each bound
/// exactly where its documentation puts it: `sigma` and the thermal
/// conductivity finite and positive, the spreading finite and zero or more
/// (zero is a one-dimensional heat path), `limit_failure` strictly inside
/// `(0, 1)`, `max_failure` in `(0, 1]`, and a reference temperature above
/// absolute zero, an activation energy of zero or more and a finite
/// positive current exponent.
///
/// Oracle: the documented domains, construct-from-answer: each row differs
/// from the legal table in one value, one step either side of its bound.
#[test]
fn em_thermal_runs_exactly_on_the_documented_domain_of_each_parameter() {
    let grid = series_chain(2, 1.0, 1_800.0, 500.0);
    let id = rule(44);
    let cases: [(&str, fn(&mut EmThermalTable), Outcome); 19] = [
        ("legal", |_| {}, Outcome::Ran),
        ("sigma 0", |t| t.sigma[0] = 0.0, Outcome::Refused),
        ("sigma NaN", |t| t.sigma[0] = f64::NAN, Outcome::Refused),
        (
            "sigma inf",
            |t| t.sigma[0] = f64::INFINITY,
            Outcome::Refused,
        ),
        (
            "conductivity 0",
            |t| t.thermal_conductivity[0] = 0.0,
            Outcome::Refused,
        ),
        (
            "conductivity inf",
            |t| t.thermal_conductivity[0] = f64::INFINITY,
            Outcome::Refused,
        ),
        ("spreading 0", |t| t.heat_spreading[0] = 0.0, Outcome::Ran),
        (
            "spreading -0.01",
            |t| t.heat_spreading[0] = -0.01,
            Outcome::Refused,
        ),
        (
            "spreading inf",
            |t| t.heat_spreading[0] = f64::INFINITY,
            Outcome::Refused,
        ),
        (
            "limit_failure 0",
            |t| t.limit_failure[0] = 0.0,
            Outcome::Refused,
        ),
        (
            "limit_failure 1",
            |t| t.limit_failure[0] = 1.0,
            Outcome::Refused,
        ),
        (
            "max_failure 0",
            |t| t.max_failure[0] = 0.0,
            Outcome::Refused,
        ),
        ("max_failure 1", |t| t.max_failure[0] = 1.0, Outcome::Ran),
        (
            "max_failure 1.01",
            |t| t.max_failure[0] = 1.01,
            Outcome::Refused,
        ),
        (
            "reference 0 K",
            |t| t.reference_temperature[0] = kelvin(0.0),
            Outcome::Refused,
        ),
        (
            "current exponent 0",
            |t| t.current_exponent[0] = 0.0,
            Outcome::Refused,
        ),
        (
            "current exponent inf",
            |t| t.current_exponent[0] = f64::INFINITY,
            Outcome::Refused,
        ),
        (
            "activation 0 eV",
            |t| t.activation_energy_ev[0] = 0.0,
            Outcome::Ran,
        ),
        (
            "activation -0.01 eV",
            |t| t.activation_energy_ev[0] = -0.01,
            Outcome::Refused,
        ),
    ];
    for (why, edit, want) in cases {
        let mut table = thermal_table(id, &[LayerId(0)], 1e9, 1e9);
        table.max_failure = vec![0.5];
        edit(&mut table);
        let (out, runs) = run_thermal(&grid, &table, 358.15);
        assert_eq!(run_of(&runs, id).outcome, want, "{why}");
        if want == Outcome::Refused {
            assert!(out.is_empty(), "{why}: a refused row reports nothing");
        }
    }
}
