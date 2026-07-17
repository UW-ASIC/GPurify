//! Analytical wire inductance.

/// Free-space permeability μ₀ in nH/μm: 4π × 10⁻⁷ H/m = 4π × 10⁻¹ nH/μm.
const MU0_NH_PER_UM: f64 = 4.0 * std::f64::consts::PI * 1e-1;

/// Analytical self-inductance for a straight wire segment (Grover approximation).
///
/// `L = (μ₀ / 2π) × length × ln(2 × length / width)`
///
/// Returns nanohenries. Guard: returns 0 for degenerate geometry.
pub fn wire_inductance_nh(length_um: f64, width_um: f64) -> f64 {
    if length_um <= 0.0 || width_um <= 0.0 || length_um <= width_um {
        // ponytail: short/wide wires where l ≤ w have negligible inductance;
        // a proper partial-element model needed for accuracy below AR = 1.
        return 0.0;
    }
    let ratio = 2.0 * length_um / width_um;
    (MU0_NH_PER_UM / (2.0 * std::f64::consts::PI)) * length_um * ratio.ln()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn straight_wire() {
        let l = wire_inductance_nh(100.0, 1.0);
        // Sanity: positive, order-of-magnitude reasonable for 100 μm wire
        assert!(l > 0.0);
        // ln(200) ≈ 5.298 → L ≈ (0.2) * 100 * 5.298 / (2π) ≈ 16.86 nH
        assert!(
            (l - 100.0 * MU0_NH_PER_UM / (2.0 * std::f64::consts::PI) * (200.0_f64).ln()).abs()
                < 1e-9
        );
    }

    #[test]
    fn degenerate_returns_zero() {
        assert_eq!(wire_inductance_nh(0.0, 1.0), 0.0);
        assert_eq!(wire_inductance_nh(1.0, 0.0), 0.0);
        assert_eq!(wire_inductance_nh(1.0, 2.0), 0.0); // width > length
    }
}
