//! Physical constants (SI units), CODATA-consistent values.

/// Vacuum permeability µ₀ [H/m].
///
/// Since the 2019 SI redefinition µ₀ is no longer exactly 4π×10⁻⁷, but the
/// difference is ~1e-10 relative and irrelevant here. We use the classical
/// value 4π×10⁻⁷ so that inductances match the textbook analytic formulas the
/// validation suite checks against (Rosa, Grover, Hoer), which are all derived
/// with µ₀ = 4π×10⁻⁷.
pub const MU0: f64 = 4.0 * std::f64::consts::PI * 1e-7;

/// Vacuum permittivity ε₀ [F/m].
pub const EPS0: f64 = 8.854_187_812_8e-12;

/// µ₀ / (4π) — the constant in front of the magnetic vector-potential / partial
/// inductance integral. Exactly 1e-7 with the classical µ₀.
pub const MU0_OVER_4PI: f64 = 1e-7;

/// 1 / (4π ε₀) — the Coulomb constant [m/F].
pub const ONE_OVER_4PI_EPS0: f64 = 1.0 / (4.0 * std::f64::consts::PI * EPS0);
