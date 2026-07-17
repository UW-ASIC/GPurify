//! Dielectric BEM validation against the dielectric-coated-sphere closed form.

use gdsverify_pex::quasistatic::cap::dielectric::{PanelRole, Problem};
use gdsverify_pex::quasistatic::cap::{mesh, solve_dielectric};
use gdsverify_pex::quasistatic::constants::EPS0;
use gdsverify_pex::quasistatic::geometry::Vec3;

#[test]
fn dielectric_coated_sphere() {
    // Conductor sphere radius a, dielectric shell (eps_r) out to radius b, vacuum
    // beyond. Closed form:  C = 4*pi*eps0 / [ (1/eps_r)(1/a - 1/b) + 1/b ].
    let a = 1.0;
    let b = 2.0;
    let eps_r = 4.0;

    // Conductor panels (radius a), sitting in the dielectric shell (eps_surrounding = eps_r).
    let cond = mesh::icosphere(Vec3::ZERO, a, 2, 0);
    // Dielectric interface at radius b: outer = vacuum (1), inner = eps_r.
    let dielec = mesh::icosphere(Vec3::ZERO, b, 2, 0);

    let mut problem = Problem::default();
    problem.conductor_names.push("sphere".into());
    for p in cond {
        problem.panels.push(p);
        problem.roles.push(PanelRole::Conductor { id: 0, eps_surrounding: eps_r });
    }
    // Reference point far outside b -> outer side is vacuum.
    let far = Vec3::ZERO; // inner reference (sphere centre)
    for p in dielec {
        problem.panels.push(p);
        problem.roles.push(PanelRole::Dielectric { eps_out: 1.0, eps_in: eps_r, reference: far });
    }

    let cap = solve_dielectric(&problem).unwrap();
    let c = cap.c[(0, 0)];
    let exact = 4.0 * std::f64::consts::PI * EPS0 / ((1.0 / eps_r) * (1.0 / a - 1.0 / b) + 1.0 / b);
    let rel = (c - exact).abs() / exact;
    println!("coated sphere: C = {c:.6e} F, exact = {exact:.6e} F, rel err {:.2}%", rel * 100.0);
    // Also show the bare-sphere and fully-immersed references for context.
    println!("  (bare sphere 4πε₀a = {:.4e}, exact coated = {:.4e})", 4.0*std::f64::consts::PI*EPS0*a, exact);
    assert!(rel < 0.05, "coated-sphere capacitance off by {:.2}%", rel * 100.0);
}

#[test]
fn dielectric_reduces_to_vacuum_when_eps_equal_one() {
    // With eps_r -> 1 the dielectric interface is invisible; C -> 4*pi*eps0*a.
    let a = 1.0;
    let cond = mesh::icosphere(Vec3::ZERO, a, 2, 0);
    let mut problem = Problem::default();
    problem.conductor_names.push("s".into());
    for p in cond {
        problem.panels.push(p);
        problem.roles.push(PanelRole::Conductor { id: 0, eps_surrounding: 1.0 });
    }
    let cap = solve_dielectric(&problem).unwrap();
    let exact = 4.0 * std::f64::consts::PI * EPS0 * a;
    let rel = (cap.c[(0, 0)] - exact).abs() / exact;
    assert!(rel < 0.03, "vacuum limit off: {rel}");
}
