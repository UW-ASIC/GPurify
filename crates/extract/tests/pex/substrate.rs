//! The substrate network solve (catalog PEX-013) against closed forms and
//! the laws of a linear resistive network.

use gpurify_extract::substrate::{admittance, Admittance, Profile};

/// A rectangle `[x0, y0, x1, y1]`, µm.
type Rect = [f64; 4];

/// Solves `ports` (each a set of rectangles) under `domain`.
fn solve(profile: &Profile, domain: Rect, ports: &[Vec<Rect>], level: u32) -> Admittance {
    let xs: Vec<f64> = ports.iter().flatten().flat_map(|r| [r[0], r[2]]).collect();
    let ys: Vec<f64> = ports.iter().flatten().flat_map(|r| [r[1], r[3]]).collect();
    let port_at = |x: f64, y: f64| {
        ports.iter().position(|rects| {
            rects
                .iter()
                .any(|r| r[0] <= x && x <= r[2] && r[1] <= y && y <= r[3])
        })
    };
    admittance(profile, domain, &xs, &ys, port_at, ports.len(), level).expect("it solves")
}

/// ρ of 1 Ω·cm, in Ω·µm.
const OHM_CM: f64 = 1e4;

/// Read's capacitance of the unit square, in units of 4πε₀ (J. Comput.
/// Phys. 133, 1997: 0.3667874 ± 1e-7).
const SQUARE: f64 = 0.366_787_4;

/// A 1 µm square contact on a 20 µm slab of 1 Ω·cm over a grounded
/// backside, the die 80 µm across: its resistance at `level`.
fn square_on_slab(level: u32) -> f64 {
    let profile = Profile {
        layers: vec![(20.0, OHM_CM)],
        grounded: true,
    };
    let y = solve(
        &profile,
        [-40.0, -40.0, 40.0, 40.0],
        &[vec![[-0.5, -0.5, 0.5, 0.5]]],
        level,
    );
    1.0 / y.at(0, 0)
}

/// The closed form for [`square_on_slab`]: the half-space spreading of a
/// square, `ρ / (2π · 0.3667874 · s)` (an isolated plate's capacitance `C`
/// gives the half-space `G = σC / 2ε`), less the grounded backside's image
/// series for a source on a slab of depth `D`, `ρ ln 2 / (2πD)` (images at
/// `2nD` of alternating sign: `Σ (−1)^n / n = −ln 2`). The die's sides at
/// twice the depth change it by less than `e^-π` of the backside's term.
fn square_on_slab_closed_form() -> f64 {
    let (rho, s, depth) = (OHM_CM, 1.0, 20.0);
    rho / (2.0 * std::f64::consts::PI * SQUARE * s)
        - rho * std::f64::consts::LN_2 / (2.0 * std::f64::consts::PI * depth)
}

/// The relative error of each level from 0 to `top`, and of the Richardson
/// extrapolation of the last two (the error falls fourfold a level, the
/// edge cell shrinking fourfold).
fn errors_to(top: u32) -> (Vec<f64>, f64) {
    let exact = square_on_slab_closed_form();
    let r: Vec<f64> = (0..=top).map(square_on_slab).collect();
    let n = r.len();
    let extrapolated = r[n - 1] + (r[n - 1] - r[n - 2]) / 3.0;
    (
        r.iter().map(|v| (v - exact).abs() / exact).collect(),
        (extrapolated - exact).abs() / exact,
    )
}

/// A square contact on a slab: the grid converges on the closed form, each
/// level more than three times closer (21 %, 6.2 %, 1.4 %), and the two
/// finest extrapolate to within 0.5 %.
///
/// Oracle: closed form (Read's square-plate capacitance and the slab's
/// image series, [`square_on_slab_closed_form`]) and mesh-refinement
/// convergence. Breaks if the grading, the depth elimination or the modal
/// transform is wrong (the levels then stall or diverge).
#[test]
fn a_square_contact_spreads_as_the_closed_form_under_refinement() {
    let (errors, extrapolated) = errors_to(2);
    assert!(errors.windows(2).all(|w| w[1] < w[0] / 3.0), "{errors:?}");
    assert!(errors[2] < 0.02, "{errors:?}");
    assert!(extrapolated < 0.005, "{extrapolated}");
}

/// The same one level finer: within 0.5 %, and extrapolated within 0.05 %.
///
/// Oracle: as [`a_square_contact_spreads_as_the_closed_form_under_refinement`].
#[test]
#[ignore = "release tier: a two-minute solve"]
fn a_square_contact_converges_to_a_part_in_two_thousand() {
    let (errors, extrapolated) = errors_to(3);
    assert!(errors[3] < 0.005, "{errors:?}");
    assert!(extrapolated < 0.0005, "{extrapolated}");
}

/// A contact over a whole block's top, through two layers to a grounded
/// backside, is the layers in series: `(2 µm · 100 + 5 µm · 1000) Ω·µm /
/// 100 µm² = 52 Ω`, at every level.
///
/// Oracle: closed form (Ohm's law, `Σ ρᵢtᵢ / A`). Breaks if a layer's
/// resistivity lands on the wrong cells or a gap's conductance is wrong.
#[test]
fn a_full_contact_over_layers_is_their_series_resistance() {
    let profile = Profile {
        layers: vec![(2.0, 100.0), (5.0, 1000.0)],
        grounded: true,
    };
    for level in 0..3 {
        let y = solve(
            &profile,
            [0.0, 0.0, 10.0, 10.0],
            &[vec![[0.0, 0.0, 10.0, 10.0]]],
            level,
        );
        let r = 1.0 / y.at(0, 0);
        assert!((r - 52.0).abs() < 1e-9 * 52.0, "level {level}: {r}");
        assert!((1.0 / y.to_backside(0) - 52.0).abs() < 1e-9 * 52.0);
    }
}

/// Three contacts of unequal size at unequal spacing, one of them an L of
/// two rectangles.
fn three_ports(mirrored: bool) -> Vec<Vec<Rect>> {
    let ports = vec![
        vec![[0.0, 0.0, 2.0, 1.0]],
        vec![[5.0, 0.0, 6.0, 3.0], [6.0, 2.0, 8.0, 3.0]],
        vec![[-6.0, 4.0, -5.0, 5.0]],
    ];
    if !mirrored {
        return ports;
    }
    ports
        .into_iter()
        .map(|rects| {
            rects
                .into_iter()
                .map(|r| [-r[2], r[1], -r[0], r[3]])
                .collect()
        })
        .collect()
}

/// An epitaxial layer of 10 Ω·cm over a 0.01 Ω·cm bulk.
fn epi(grounded: bool) -> Profile {
    Profile {
        layers: vec![(3.0, 10.0 * OHM_CM), (30.0, 0.01 * OHM_CM)],
        grounded,
    }
}

/// The die of [`three_ports`].
const DIE: Rect = [-10.0, -4.0, 12.0, 9.0];

/// `Y` is symmetric whether the backside is grounded or floating, every
/// port couples to every other through a positive conductance, and with a
/// floating backside every row sums to zero: what leaves one port enters
/// the others.
///
/// Oracle: reciprocity (a passive resistive network's admittance matrix is
/// symmetric) and Kirchhoff's current law. Breaks if the modal transform
/// is not orthogonal in its weights or a port's current is mis-summed.
#[test]
fn the_port_admittance_is_reciprocal_and_conserves_current() {
    for grounded in [true, false] {
        let y = solve(&epi(grounded), DIE, &three_ports(false), 1);
        let scale = y.at(0, 0);
        for p in 0..3 {
            for q in 0..3 {
                assert!(
                    (y.at(p, q) - y.at(q, p)).abs() < 1e-8 * scale,
                    "Y[{p}][{q}] {} against {}",
                    y.at(p, q),
                    y.at(q, p)
                );
                if p != q {
                    assert!(y.between(p, q) > 0.0);
                }
            }
            if grounded {
                assert!(y.to_backside(p) > 0.0);
            } else {
                assert!(
                    y.to_backside(p).abs() < 1e-6 * scale,
                    "{}",
                    y.to_backside(p)
                );
            }
        }
    }
}

/// The layout mirrored left to right, its die with it, gives the same
/// admittances.
///
/// Oracle: symmetry (a mirror maps the boundary problem onto itself).
/// Breaks if the grid or the contacts depend on direction.
#[test]
fn a_mirrored_layout_has_the_same_network() {
    let mirrored = [-DIE[2], DIE[1], -DIE[0], DIE[3]];
    let (a, b) = (
        solve(&epi(true), DIE, &three_ports(false), 1),
        solve(&epi(true), mirrored, &three_ports(true), 1),
    );
    for (p, q) in a.y.iter().zip(&b.y) {
        assert!((p - q).abs() < 1e-8 * a.at(0, 0), "{p} against {q}");
    }
}

/// Two ports driven together are their columns summed: the merged port's
/// self-admittance is `Y00 + Y01 + Y10 + Y11`, and its coupling to the
/// third `Y20 + Y21`.
///
/// Oracle: superposition (the network is linear, so the response to both
/// at 1 V is the sum of the responses to each). Breaks if a solve depends
/// on more than the held voltages, such as a vector left from the last
/// port's solve.
#[test]
fn two_ports_driven_together_superpose() {
    let ports = three_ports(false);
    let y = solve(&epi(true), DIE, &ports, 1);
    let merged = vec![
        [ports[0].clone(), ports[1].clone()].concat(),
        ports[2].clone(),
    ];
    let m = solve(&epi(true), DIE, &merged, 1);
    let scale = y.at(0, 0);
    let both = y.at(0, 0) + y.at(0, 1) + y.at(1, 0) + y.at(1, 1);
    assert!(
        (m.at(0, 0) - both).abs() < 1e-8 * scale,
        "{} against {both}",
        m.at(0, 0)
    );
    let third = y.at(2, 0) + y.at(2, 1);
    assert!((m.at(1, 0) - third).abs() < 1e-8 * scale);
}
