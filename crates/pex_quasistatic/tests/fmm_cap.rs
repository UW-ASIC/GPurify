//! FMM-accelerated capacitance: matches the dense solver and the analytic sphere.

use quasiss::cap::{from_panels, mesh, solve, Method};
use quasiss::constants::EPS0;
use quasiss::geometry::Vec3;

#[test]
fn fmm_capacitance_matches_dense_and_analytic() {
    let a = 1.0;
    let panels = mesh::icosphere(Vec3::ZERO, a, 2, 0); // 320 panels
    let geo = from_panels(panels, vec!["sphere".into()]);

    let c_dense = solve(&geo, Method::Direct).unwrap().c[(0, 0)];
    let c_fmm = quasiss::cap::fmm_solver::solve(&geo, 4, 3, 1e-8).c[(0, 0)];
    let exact = 4.0 * std::f64::consts::PI * EPS0 * a;

    let rel_dense = (c_fmm - c_dense).abs() / c_dense;
    let rel_exact = (c_fmm - exact).abs() / exact;
    println!(
        "sphere C: dense={c_dense:.6e}, fmm={c_fmm:.6e}, exact={exact:.6e} | fmm-vs-dense {:.2e}, fmm-vs-exact {:.2}%",
        rel_dense, rel_exact * 100.0
    );
    // FMM must agree with the dense solve (both discretize the same operator).
    assert!(rel_dense < 5e-3, "FMM disagrees with dense: {rel_dense}");
    // And still converge to the analytic sphere capacitance.
    assert!(rel_exact < 0.03, "FMM sphere capacitance off: {rel_exact}");
}
