//! One-off perf gate: SIMD kernels vs scalar/autovec equivalents.
use std::time::Instant;
fn main() {
    let n = 4096usize;
    let a: Vec<f64> = (0..n).map(|i| ((i*37%101) as f64 - 50.0)*0.013).collect();
    let b: Vec<f64> = (0..n).map(|i| ((i*53%97) as f64 - 48.0)*0.007).collect();
    let reps = 200_000;

    let t = Instant::now();
    let mut s = 0.0;
    for _ in 0..reps { s += quasiss::simd::dot(std::hint::black_box(&a), std::hint::black_box(&b)); }
    let simd_t = t.elapsed().as_secs_f64();

    let t = Instant::now();
    let mut s2 = 0.0;
    for _ in 0..reps {
        let (aa, bb) = (std::hint::black_box(&a), std::hint::black_box(&b));
        s2 += aa.iter().zip(bb).map(|(&x, &y)| x*y).sum::<f64>();
    }
    let auto_t = t.elapsed().as_secs_f64();
    println!("dot n={n}: simd {:.3}s  autovec {:.3}s  ratio {:.2}x   ({s:.3e} vs {s2:.3e})", simd_t, auto_t, auto_t/simd_t);

    // p2p: 4096 targets x 4096 sources
    let q: Vec<f64> = (0..n).map(|i| ((i%7) as f64)-3.0).collect();
    let src = quasiss::p2p::Sources { x: &a, y: &b, z: &q, q: &q };
    let mut out = vec![0.0; n];
    let t = Instant::now();
    quasiss::p2p::p2p_laplace(&a, &b, &q, &src, &mut out);
    let par_t = t.elapsed().as_secs_f64();
    let t = Instant::now();
    quasiss::p2p::p2p_laplace_scalar(&a, &b, &q, &src, &mut out);
    let scal_t = t.elapsed().as_secs_f64();
    // old autovec-scalar + rayon inner loop for an apples-to-apples compare
    use rayon::prelude::*;
    let t = Instant::now();
    out.par_iter_mut().enumerate().for_each(|(i, oi)| {
        let (xi, yi, zi) = (a[i], b[i], q[i]);
        let mut acc = 0.0;
        for j in 0..n {
            let dx = xi - src.x[j]; let dy = yi - src.y[j]; let dz = zi - src.z[j];
            let r2 = dx*dx + dy*dy + dz*dz;
            if r2 > 0.0 { acc += src.q[j] / r2.sqrt(); }
        }
        *oi = acc;
    });
    let old_t = t.elapsed().as_secs_f64();
    println!("p2p n={n}: simd+rayon {:.4}s  autovec+rayon {:.4}s ({:.2}x)  scalar-1thread {:.4}s", par_t, old_t, old_t/par_t, scal_t);
}
