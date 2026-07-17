//! Validate the black-box FMM matvec against the dense O(N²) Laplace apply.

use quasiss::fmm::LaplaceFmm;
use quasiss::geometry::Vec3;

fn dense_matvec(pts: &[Vec3], q: &[f64]) -> Vec<f64> {
    let n = pts.len();
    let mut y = vec![0.0; n];
    for i in 0..n {
        let mut acc = 0.0;
        for j in 0..n {
            if i != j {
                acc += q[j] / pts[i].dist(pts[j]);
            }
        }
        y[i] = acc;
    }
    y
}

fn random_points(n: usize, seed: u64) -> Vec<Vec3> {
    // Simple LCG to avoid rand dependency.
    let mut s = seed;
    let mut nxt = || {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((s >> 33) as f64) / (1u64 << 31) as f64 - 1.0
    };
    (0..n).map(|_| Vec3::new(nxt(), nxt(), nxt())).collect()
}

fn rel_err(a: &[f64], b: &[f64]) -> f64 {
    let num: f64 = a.iter().zip(b).map(|(x, y)| (x - y).powi(2)).sum::<f64>().sqrt();
    let den: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    num / den.max(1e-300)
}

#[test]
fn fmm_matvec_matches_dense() {
    let pts = random_points(900, 12345);
    let q: Vec<f64> = (0..pts.len()).map(|i| ((i % 13) as f64) - 6.0).collect();
    let exact = dense_matvec(&pts, &q);

    let fmm = LaplaceFmm::new(&pts, 5, 3);
    let approx = fmm.matvec(&q);
    let e = rel_err(&approx, &exact);
    println!("FMM(n=5, L=3) vs dense: rel err = {e:.3e}");
    assert!(e < 1e-3, "FMM matvec too inaccurate: {e}");
}

#[test]
fn fmm_converges_with_chebyshev_order() {
    let pts = random_points(800, 999);
    let q: Vec<f64> = (0..pts.len()).map(|i| ((i * 7 % 11) as f64) - 5.0).collect();
    let exact = dense_matvec(&pts, &q);
    let e3 = rel_err(&LaplaceFmm::new(&pts, 3, 3).matvec(&q), &exact);
    let e6 = rel_err(&LaplaceFmm::new(&pts, 5, 3).matvec(&q), &exact);
    println!("FMM order convergence: n=3 -> {e3:.2e}, n=5 -> {e6:.2e}");
    assert!(e6 < e3, "higher order did not improve accuracy");
    assert!(e6 < 1e-4);
}
