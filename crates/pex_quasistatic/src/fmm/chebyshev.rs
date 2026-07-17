//! Chebyshev interpolation for the black-box FMM (Fong & Darve 2009).
//!
//! The kernel-independent FMM approximates a smooth kernel on a box by
//! interpolating it at Chebyshev nodes:
//!   K(x, y) ≈ Σ_m Σ_l Sₙ(x, x̄_m) K(x̄_m, ȳ_l) Sₙ(y, ȳ_l)
//! where x̄_m are the n Chebyshev roots and Sₙ is the interpolation operator
//!   Sₙ(x, x̄_m) = 1/n + (2/n) Σ_{k=1}^{n-1} T_k(x̄_m) T_k(x).
//! Raising `n` gives spectral convergence for the 1/r Laplace kernel.

/// The `n` Chebyshev roots of Tₙ on [-1, 1]: x̄_m = cos((2m+1)π / 2n).
pub fn nodes(n: usize) -> Vec<f64> {
    (0..n)
        .map(|m| {
            let theta = (2.0 * m as f64 + 1.0) * std::f64::consts::PI / (2.0 * n as f64);
            theta.cos()
        })
        .collect()
}

/// Chebyshev polynomial T_k(x) for x ∈ [-1, 1] via the stable recurrence.
#[inline]
pub fn cheb_t(k: usize, x: f64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    if k == 1 {
        return x;
    }
    let mut tkm1 = 1.0;
    let mut tk = x;
    for _ in 2..=k {
        let tkp1 = 2.0 * x * tk - tkm1;
        tkm1 = tk;
        tk = tkp1;
    }
    tk
}

/// The 1-D interpolation weights `Sₙ(x, x̄_m)` for m = 0..n, for a point
/// `x ∈ [-1, 1]`. `Σ_m w[m] f(x̄_m)` reproduces any degree-<n polynomial at `x`.
pub fn interp_weights(x: f64, n: usize, nodes: &[f64]) -> Vec<f64> {
    // Precompute T_k(x) for k = 0..n-1.
    let mut tx = vec![0.0; n];
    tx[0] = 1.0;
    if n > 1 {
        tx[1] = x;
        for k in 2..n {
            tx[k] = 2.0 * x * tx[k - 1] - tx[k - 2];
        }
    }
    let inv_n = 1.0 / n as f64;
    (0..n)
        .map(|m| {
            let xm = nodes[m];
            // T_k(x̄_m) via recurrence too.
            let mut sum = 0.5; // corresponds to the 1/n term folded (see below)
            let mut tkm1 = 1.0;
            let mut tk = xm;
            // k = 1..n-1 : add T_k(x̄_m) T_k(x)
            for k in 1..n {
                let tkm = if k == 1 {
                    xm
                } else {
                    let t = 2.0 * xm * tk - tkm1;
                    tkm1 = tk;
                    tk = t;
                    t
                };
                sum += tkm * tx[k];
            }
            2.0 * inv_n * sum
        })
        .collect()
}

/// 3-D tensor-product interpolation. Returns weights over the `n³` Chebyshev
/// nodes (flattened m = m1·n² + m2·n + m3) for a point `p ∈ [-1,1]³`.
pub fn interp_weights_3d(p: [f64; 3], n: usize, nodes: &[f64]) -> Vec<f64> {
    let w1 = interp_weights(p[0], n, nodes);
    let w2 = interp_weights(p[1], n, nodes);
    let w3 = interp_weights(p[2], n, nodes);
    let mut w = vec![0.0; n * n * n];
    for a in 0..n {
        for b in 0..n {
            let wab = w1[a] * w2[b];
            let base = (a * n + b) * n;
            for c in 0..n {
                w[base + c] = wab * w3[c];
            }
        }
    }
    w
}

/// 3-D Chebyshev node coordinates in [-1,1]³ (same flattening as the weights).
pub fn nodes_3d(n: usize, nodes1d: &[f64]) -> Vec<[f64; 3]> {
    let mut pts = Vec::with_capacity(n * n * n);
    for a in 0..n {
        for b in 0..n {
            for c in 0..n {
                pts.push([nodes1d[a], nodes1d[b], nodes1d[c]]);
            }
        }
    }
    pts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpolation_is_exact_for_low_degree_polynomials() {
        let n = 6;
        let nd = nodes(n);
        // f(x) = 3 - 2x + x^2 - 0.5 x^3 (degree 3 < n); interpolation must be exact.
        let f = |x: f64| 3.0 - 2.0 * x + x * x - 0.5 * x * x * x;
        for &xt in &[-0.9, -0.3, 0.0, 0.42, 0.777] {
            let w = interp_weights(xt, n, &nd);
            let approx: f64 = (0..n).map(|m| w[m] * f(nd[m])).sum();
            assert!((approx - f(xt)).abs() < 1e-11, "x={xt}: {approx} vs {}", f(xt));
        }
    }

    #[test]
    fn interpolation_converges_for_smooth_function() {
        // exp(x) interpolation error shrinks fast with n.
        let f = |x: f64| x.exp();
        let err = |n: usize| {
            let nd = nodes(n);
            let mut e = 0.0f64;
            for i in 0..=20 {
                let xt = -1.0 + 2.0 * i as f64 / 20.0;
                let w = interp_weights(xt, n, &nd);
                let approx: f64 = (0..n).map(|m| w[m] * f(nd[m])).sum();
                e = e.max((approx - f(xt)).abs());
            }
            e
        };
        assert!(err(8) < err(4));
        assert!(err(8) < 1e-6);
    }

    #[test]
    fn tensor_weights_reproduce_trilinear() {
        let n = 5;
        let nd = nodes(n);
        let n3 = nodes_3d(n, &nd);
        let f = |p: [f64; 3]| 1.0 + p[0] - 2.0 * p[1] + p[2] + p[0] * p[1] * p[2];
        let pt = [0.3, -0.6, 0.1];
        let w = interp_weights_3d(pt, n, &nd);
        let approx: f64 = (0..n * n * n).map(|m| w[m] * f(n3[m])).sum();
        assert!((approx - f(pt)).abs() < 1e-10);
    }
}
