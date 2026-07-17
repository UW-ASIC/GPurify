//! Capacitance validation against closed-form analytic references.

use gdsverify_pex::quasistatic::cap::{from_panels, mesh, solve, Method};
use gdsverify_pex::quasistatic::constants::EPS0;
use gdsverify_pex::quasistatic::geometry::Vec3;

const FOUR_PI_EPS0: f64 = 4.0 * std::f64::consts::PI * EPS0;

#[test]
fn isolated_sphere_self_capacitance() {
    // A conducting sphere of radius a has C = 4πε₀a exactly. BEM collocation on a
    // triangulated sphere converges to this; two icosahedron subdivisions
    // (320 panels) should land within a couple percent.
    let a = 1.0;
    let panels = mesh::icosphere(Vec3::ZERO, a, 2, 0);
    let n_panels = panels.len();
    let geo = from_panels(panels, vec!["sphere".into()]);
    let cap = solve(&geo, Method::Direct).unwrap();

    let c = cap.c[(0, 0)];
    let exact = FOUR_PI_EPS0 * a;
    let rel = (c - exact).abs() / exact;
    println!(
        "sphere: {n_panels} panels, C = {c:.6e} F, exact 4πε₀a = {exact:.6e} F, rel err {:.3}%",
        rel * 100.0
    );
    assert!(rel < 0.03, "sphere capacitance off by {:.2}%", rel * 100.0);
}

#[test]
fn sphere_converges_with_refinement() {
    // Refining the mesh must reduce the error monotonically toward 4πε₀a.
    let a = 1.0;
    let exact = FOUR_PI_EPS0 * a;
    let err = |subdiv| {
        let panels = mesh::icosphere(Vec3::ZERO, a, subdiv, 0);
        let geo = from_panels(panels, vec!["s".into()]);
        let c = solve(&geo, Method::Direct).unwrap().c[(0, 0)];
        (c - exact).abs() / exact
    };
    let e1 = err(1);
    let e2 = err(2);
    println!("sphere refinement: err(80 panels)={:.3}%, err(320 panels)={:.3}%", e1 * 100.0, e2 * 100.0);
    assert!(e2 < e1, "refinement did not improve accuracy: {e1} -> {e2}");
}

#[test]
fn parallel_plate_capacitor() {
    // Two coplanar-area plates, gap d ≪ plate size: the mutual capacitance
    // approaches the ideal ε₀A/d, with fringing adding a modest excess.
    let side = 0.2;
    let gap = 0.02;
    let area = side * side;
    let (nx, ny) = (10, 10);
    let mut panels = mesh::plate(0.0, 0.0, 0.0, side, side, nx, ny, 0);
    panels.extend(mesh::plate(0.0, 0.0, gap, side, side, nx, ny, 1));
    let geo = from_panels(panels, vec!["bottom".into(), "top".into()]);
    let cap = solve(&geo, Method::Direct).unwrap();

    let ideal = EPS0 * area / gap;
    // Mutual capacitance = magnitude of the off-diagonal Maxwell entry.
    let c_mutual = cap.c[(0, 1)].abs();
    let ratio = c_mutual / ideal;
    println!(
        "parallel plate: |C01| = {:.4e} F, ideal ε₀A/d = {:.4e} F, ratio {:.3}",
        c_mutual, ideal, ratio
    );
    // Physical parallel-plate + fringing: mutual C should exceed the ideal but
    // stay within ~30%.
    assert!(ratio > 0.95 && ratio < 1.35, "ratio {ratio} outside expected band");

    // Maxwell matrix symmetry.
    let asym = (cap.c[(0, 1)] - cap.c[(1, 0)]).abs() / cap.c[(0, 1)].abs();
    assert!(asym < 1e-6, "capacitance matrix not symmetric: {asym}");
    // Off-diagonal is negative (Maxwell convention), diagonal positive.
    assert!(cap.c[(0, 1)] < 0.0 && cap.c[(0, 0)] > 0.0);
}

#[test]
fn direct_and_iterative_agree() {
    // The dense LU path and the GMRES-through-LinearOperator path must produce
    // the same capacitance to the iterative tolerance.
    let panels = mesh::icosphere(Vec3::ZERO, 1.0, 1, 0);
    let geo = from_panels(panels, vec!["s".into()]);
    let cd = solve(&geo, Method::Direct).unwrap().c[(0, 0)];
    let ci = solve(&geo, Method::Iterative).unwrap().c[(0, 0)];
    let rel = (cd - ci).abs() / cd.abs();
    println!("direct {cd:.6e} vs iterative {ci:.6e}, rel {:.2e}", rel);
    assert!(rel < 1e-6, "direct vs iterative disagree: {rel}");
}
