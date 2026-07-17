//! Analytical device-level parasitic models (gate R, junction C).

/// MOS gate resistance: Rgate = Rsh_poly × W / (3 × L × Nf²)
///
/// The 1/3 factor accounts for the distributed RC nature of the polysilicon gate.
/// `nf` is the number of fingers; multi-finger devices further divide R by Nf.
pub fn mos_gate_resistance(rsh_poly: f64, w_nm: i32, l_nm: i32, nf: u32) -> f64 {
    if l_nm <= 0 || nf == 0 {
        return 0.0;
    }
    let nf = nf as f64;
    rsh_poly * (w_nm as f64) / (3.0 * l_nm as f64 * nf * nf)
}

/// MOS junction capacitance: Cj = Cj0 × AD + Cjsw × PD
///
/// `cj0_af_um2`: zero-bias junction cap per unit area (aF/μm²).
/// `ad_um2`: drain/source area (μm²).
/// `cjsw_af_um`: sidewall cap per unit perimeter (aF/μm).
/// `pd_um`: drain/source perimeter (μm).
pub fn junction_capacitance(cj0_af_um2: f64, ad_um2: f64, cjsw_af_um: f64, pd_um: f64) -> f64 {
    cj0_af_um2 * ad_um2 + cjsw_af_um * pd_um
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_resistance_basic() {
        // 1 finger, 1000 nm W, 100 nm L, Rsh = 10 Ω/sq
        let r = mos_gate_resistance(10.0, 1000, 100, 1);
        // 10 * 1000 / (3 * 100 * 1) = 33.333...
        assert!((r - 100.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn gate_resistance_multi_finger() {
        let r1 = mos_gate_resistance(10.0, 1000, 100, 1);
        let r2 = mos_gate_resistance(10.0, 1000, 100, 2);
        // 2 fingers → R / 4
        assert!((r2 - r1 / 4.0).abs() < 1e-9);
    }

    #[test]
    fn gate_resistance_zero_guard() {
        assert_eq!(mos_gate_resistance(10.0, 1000, 0, 1), 0.0);
        assert_eq!(mos_gate_resistance(10.0, 1000, 100, 0), 0.0);
    }

    #[test]
    fn junction_cap_basic() {
        // Cj0 = 1000 aF/μm², AD = 0.5 μm², Cjsw = 200 aF/μm, PD = 3.0 μm
        let c = junction_capacitance(1000.0, 0.5, 200.0, 3.0);
        assert!((c - 1100.0).abs() < 1e-9);
    }
}
