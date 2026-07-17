use quasiss::fmm::LaplaceFmm;
use quasiss::geometry::Vec3;
use std::time::Instant;

fn dense(pts: &[Vec3], q: &[f64]) -> Vec<f64> {
    let n = pts.len();
    let mut y = vec![0.0; n];
    for i in 0..n {
        let mut a = 0.0;
        for j in 0..n { if i != j { a += q[j] / pts[i].dist(pts[j]); } }
        y[i] = a;
    }
    y
}

fn pts_on_sphere(n: usize) -> Vec<Vec3> {
    // Fibonacci sphere.
    let phi = std::f64::consts::PI * (3.0 - 5f64.sqrt());
    (0..n).map(|i| {
        let y = 1.0 - 2.0 * (i as f64 + 0.5) / n as f64;
        let r = (1.0 - y*y).sqrt();
        let t = phi * i as f64;
        Vec3::new(t.cos()*r, y, t.sin()*r)
    }).collect()
}

fn main() {
    println!("{:>7} {:>3} | {:>11} {:>11} {:>8} | {:>9}", "N","L","dense(ms)","fmm(ms)","speedup","rel_err");
    for &(n, lvl) in &[(2000usize,3usize),(5000,4),(10000,4),(20000,5),(40000,5)] {
        let pts = pts_on_sphere(n);
        let q: Vec<f64> = (0..n).map(|i| ((i%17) as f64)-8.0).collect();
        let t=Instant::now(); let yd=dense(&pts,&q); let td=t.elapsed().as_secs_f64()*1e3;
        let fmm=LaplaceFmm::new(&pts,4,lvl);
        // warm + time a matvec
        let t=Instant::now(); let yf=fmm.matvec(&q); let tf=t.elapsed().as_secs_f64()*1e3;
        let num:f64=yd.iter().zip(&yf).map(|(a,b)|(a-b).powi(2)).sum::<f64>().sqrt();
        let den:f64=yd.iter().map(|a|a*a).sum::<f64>().sqrt();
        println!("{:>7} {:>3} | {:>11.1} {:>11.1} {:>7.2}x | {:>9.2e}", n,lvl,td,tf,td/tf,num/den);
    }
}
