//! Analytic validation of the near-field element integrals — the pieces that
//! must be exact for the whole solver to agree with the originals.

use gdsverify_pex::quasistatic::geometry::Vec3;
use gdsverify_pex::quasistatic::integrals::filament::{
    self, mutual_parallel, mutual_parallel_equal_grover, Filament,
};
use gdsverify_pex::quasistatic::integrals::panel::potential_integral;

fn approx(a: f64, b: f64, rel: f64) -> bool {
    (a - b).abs() <= rel * b.abs().max(1e-30)
}

#[test]
fn wilton_unit_square_self_integral() {
    // ∫∫ over the unit square of 1/r at its centre has the closed form
    //   4·asinh(1) = 4·ln(1+√2) = 3.525494…
    let verts = vec![
        Vec3::new(-0.5, -0.5, 0.0),
        Vec3::new(0.5, -0.5, 0.0),
        Vec3::new(0.5, 0.5, 0.0),
        Vec3::new(-0.5, 0.5, 0.0),
    ];
    let got = potential_integral(&verts, Vec3::ZERO);
    let exact = 4.0 * (1.0f64).asinh();
    assert!(approx(got, exact, 1e-12), "got {got}, exact {exact}");
}

#[test]
fn wilton_far_field_is_monopole() {
    // Far from a unit-area panel, ∫ da'/R → area / distance.
    let verts = vec![
        Vec3::new(-0.5, -0.5, 0.0),
        Vec3::new(0.5, -0.5, 0.0),
        Vec3::new(0.5, 0.5, 0.0),
        Vec3::new(-0.5, 0.5, 0.0),
    ];
    let z = 50.0;
    let got = potential_integral(&verts, Vec3::new(0.0, 0.0, z));
    let monopole = 1.0 / z;
    assert!(approx(got, monopole, 1e-3), "got {got}, monopole {monopole}");
}

#[test]
fn wilton_offplane_matches_quadrature() {
    // Compare the Wilton closed form against a fine Gauss product rule for a
    // generic near-but-not-singular observation point.
    let verts = vec![
        Vec3::new(0.0, 0.0, 0.0),
        Vec3::new(1.0, 0.0, 0.0),
        Vec3::new(1.0, 0.7, 0.0),
        Vec3::new(0.0, 0.7, 0.0),
    ];
    let p = Vec3::new(0.3, 0.2, 0.4);
    let got = potential_integral(&verts, p);

    // 40x40 midpoint quadrature over the rectangle.
    let (nx, ny) = (400usize, 280usize);
    let (lx, ly) = (1.0, 0.7);
    let (dx, dy) = (lx / nx as f64, ly / ny as f64);
    let mut q = 0.0;
    for i in 0..nx {
        for j in 0..ny {
            let x = (i as f64 + 0.5) * dx;
            let y = (j as f64 + 0.5) * dy;
            let r = p.dist(Vec3::new(x, y, 0.0));
            q += dx * dy / r;
        }
    }
    assert!(approx(got, q, 5e-4), "wilton {got}, quad {q}");
}

#[test]
fn grover_parallel_closed_form_consistency() {
    // The general parallel-filament routine must reproduce the classic Grover
    // closed form for two equal, aligned, laterally-separated filaments.
    let l = 0.05;
    let d = 0.003;
    let f1 = Filament::new(Vec3::new(0.0, 0.0, 0.0), Vec3::new(l, 0.0, 0.0), 1e-9, 1e-9);
    let f2 = Filament::new(Vec3::new(0.0, d, 0.0), Vec3::new(l, d, 0.0), 1e-9, 1e-9);
    let general = mutual_parallel(&f1, &f2);
    let grover = mutual_parallel_equal_grover(l, d);
    assert!(approx(general, grover, 1e-12), "general {general}, grover {grover}");
    assert!(general > 0.0);
}

#[test]
fn mutual_is_symmetric() {
    let f1 = Filament::new(Vec3::new(0.0, 0.0, 0.0), Vec3::new(0.04, 0.0, 0.0), 1e-4, 1e-4);
    let f2 = Filament::new(Vec3::new(0.01, 0.005, 0.002), Vec3::new(0.05, 0.005, 0.002), 1e-4, 1e-4);
    let m12 = filament::mutual(&f1, &f2);
    let m21 = filament::mutual(&f2, &f1);
    assert!(approx(m12, m21, 1e-10), "m12 {m12}, m21 {m21}");
}

#[test]
fn self_inductance_positive_and_scales() {
    // Longer bar -> larger self inductance (monotone), and roughly linear-log.
    let l1 = filament::self_inductance_bar(0.1, 1e-3, 1e-3);
    let l2 = filament::self_inductance_bar(0.2, 1e-3, 1e-3);
    assert!(l1 > 0.0 && l2 > l1);
}

// ---- complex GMRES validation ----
use gdsverify_pex::quasistatic::linalg::DenseMatrix;
use gdsverify_pex::quasistatic::operator::{BlockJacobiComplex, DenseComplexOperator};
use gdsverify_pex::quasistatic::krylov::{gmres_complex, GmresOptions};
use num_complex::Complex64;

#[test]
fn complex_gmres_matches_dense_lu() {
    // Random-ish diagonally-dominant complex system; GMRES must match LU solve.
    let n = 30;
    let mut a = DenseMatrix::<Complex64>::zeros(n, n);
    for i in 0..n {
        for j in 0..n {
            let re = ((i * 7 + j * 3) % 11) as f64 - 5.0;
            let im = ((i * 5 + j * 2) % 9) as f64 - 4.0;
            a[(i, j)] = Complex64::new(re, im) / (1.0 + (i as f64 - j as f64).abs());
        }
        a[(i, i)] += Complex64::new(50.0, 20.0); // diagonal dominance
    }
    let b: Vec<Complex64> = (0..n).map(|i| Complex64::new(i as f64, (n - i) as f64)).collect();

    let lu = gdsverify_pex::quasistatic::linalg::LuDecomposition::factor(&a).unwrap();
    let x_lu = lu.solve(&b);

    let op = DenseComplexOperator::new(a.clone());
    let precond = BlockJacobiComplex::contiguous(&a, 5);
    let opts = GmresOptions { tol: 1e-10, restart: 40, max_restarts: 20 };
    let (x_gmres, meta) = gmres_complex(&op, &b, Some(&precond), opts);
    assert!(meta.converged, "complex GMRES did not converge: {:?}", meta);

    let mut maxerr = 0.0f64;
    for i in 0..n {
        maxerr = maxerr.max((x_lu[i] - x_gmres[i]).norm());
    }
    println!("complex GMRES vs LU max err = {maxerr:.2e}, iters {}", meta.iterations);
    assert!(maxerr < 1e-8, "complex GMRES disagrees with LU: {maxerr}");
}

#[test]
fn iterative_refinement_recovers_f64_from_f32() {
    use gdsverify_pex::quasistatic::refine::{solve_iterative_refinement, solve_equilibrated, RefineOptions};
    // Well-conditioned f64 system; f32 factorization + f64 refinement must reach
    // f64 accuracy (far better than a pure-f32 solve ~1e-4).
    let n = 40;
    let mut a = DenseMatrix::<f64>::zeros(n, n);
    for i in 0..n {
        for j in 0..n {
            a[(i, j)] = 1.0 / (1.0 + (i as f64 - j as f64).abs());
        }
        a[(i, i)] += 10.0;
    }
    let x_true: Vec<f64> = (0..n).map(|i| (i as f64 * 0.37).sin()).collect();
    let b = a.matvec(&x_true);
    let res = solve_iterative_refinement(&a, &b, RefineOptions::default()).unwrap();
    let err: f64 = (0..n).map(|i| (res.x[i] - x_true[i]).abs()).fold(0.0, f64::max);
    println!("iterative refinement: {} steps, residual {:.2e}, max err {:.2e}", res.steps, res.residual, err);
    assert!(res.converged && err < 1e-10, "refinement failed: err {err}");

    // Equilibrated solve on a badly-scaled version must stay accurate.
    let mut a2 = a.clone();
    for i in 0..n { for j in 0..n { a2[(i,j)] *= 10f64.powi((i as i32 % 6) - 3); } }
    let b2 = a2.matvec(&x_true);
    let x2 = solve_equilibrated(&a2, &b2).unwrap();
    let err2: f64 = (0..n).map(|i| (x2[i]-x_true[i]).abs()).fold(0.0,f64::max);
    println!("equilibrated solve max err {:.2e}", err2);
    assert!(err2 < 1e-8, "equilibrated solve failed: {err2}");
}
