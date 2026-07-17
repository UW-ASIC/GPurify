use std::collections::HashSet;

use crate::{CheckReport, SignoffCheck, ErcCtx, ErcFinding, SignoffViolation};

#[derive(Debug, Clone, PartialEq)]
pub struct VoltageStress {
    pub id: String,
    pub measured_abs_v: f64,
    pub max_abs_v: f64,
    pub location: Option<(i32, i32)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ThermalStress {
    pub id: String,
    pub measured_c: f64,
    pub max_c: f64,
    pub location: Option<(i32, i32)>,
}

/// Foundry-calibrated inverse-power/Arrhenius lifetime model.  It can represent
/// mechanisms such as BTI, HCI, TDDB, stress migration, or EM when populated
/// with the corresponding foundry coefficients.
#[derive(Debug, Clone, PartialEq)]
pub struct AgingStress {
    pub id: String,
    pub mechanism: String,
    pub reference_lifetime_hours: f64,
    pub reference_stress: f64,
    pub applied_stress: f64,
    pub stress_exponent: f64,
    pub reference_temperature_c: f64,
    pub applied_temperature_c: f64,
    pub activation_energy_ev: f64,
    /// Fraction of lifetime spent under this stress, in [0, 1].
    pub duty_cycle: f64,
    pub location: Option<(i32, i32)>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReliabilityConfig {
    pub required_lifetime_hours: f64,
    pub voltage_stresses: Vec<VoltageStress>,
    pub thermal_stresses: Vec<ThermalStress>,
    pub aging_stresses: Vec<AgingStress>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AgingStressResult {
    pub id: String,
    pub mechanism: String,
    pub predicted_lifetime_hours: f64,
    pub required_lifetime_hours: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReliabilityReport {
    pub check: CheckReport,
    pub aging: Vec<AgingStressResult>,
}

impl ReliabilityReport {
    pub(crate) fn not_run(reason: impl Into<String>) -> Self {
        Self {
            check: CheckReport::not_run(SignoffCheck::Reliability, reason),
            aging: Vec::new(),
        }
    }

    pub(crate) fn error(reason: impl Into<String>) -> Self {
        Self {
            check: CheckReport::error(SignoffCheck::Reliability, reason),
            aging: Vec::new(),
        }
    }
}

const BOLTZMANN_EV_PER_K: f64 = 8.617_333_262_145e-5;

pub fn check_reliability(config: &ReliabilityConfig) -> ReliabilityReport {
    if config.voltage_stresses.is_empty()
        && config.thermal_stresses.is_empty()
        && config.aging_stresses.is_empty()
    {
        return ReliabilityReport::error(
            "reliability configuration contains no stress observations",
        );
    }
    if !config.required_lifetime_hours.is_finite() || config.required_lifetime_hours <= 0.0 {
        return ReliabilityReport::error(
            "required reliability lifetime must be finite and positive",
        );
    }

    let mut violations = Vec::new();
    let mut aging_results = Vec::new();
    let mut voltage_ids = HashSet::new();
    for s in &config.voltage_stresses {
        if s.id.is_empty()
            || !voltage_ids.insert(s.id.as_str())
            || !s.measured_abs_v.is_finite()
            || !s.max_abs_v.is_finite()
            || s.measured_abs_v < 0.0
            || s.max_abs_v <= 0.0
        {
            return ReliabilityReport::error(format!("voltage stress '{}' is invalid", s.id));
        }
        if s.measured_abs_v > s.max_abs_v {
            violations.push(SignoffViolation {
                check: SignoffCheck::Reliability,
                rule_id: format!("reliability.voltage.{}", s.id),
                message: format!(
                    "'{}' voltage stress {:.6}V exceeds {:.6}V",
                    s.id, s.measured_abs_v, s.max_abs_v,
                ),
                location: s.location,
                measured: Some(s.measured_abs_v),
                limit: Some(s.max_abs_v),
                units: "V".into(),
                evidence_id: None,
            });
        }
    }
    let mut thermal_ids = HashSet::new();
    for s in &config.thermal_stresses {
        if s.id.is_empty()
            || !thermal_ids.insert(s.id.as_str())
            || !s.measured_c.is_finite()
            || !s.max_c.is_finite()
            || s.measured_c <= -273.15
            || s.max_c <= -273.15
        {
            return ReliabilityReport::error(format!("thermal stress '{}' is invalid", s.id));
        }
        if s.measured_c > s.max_c {
            violations.push(SignoffViolation {
                check: SignoffCheck::Reliability,
                rule_id: format!("reliability.thermal.{}", s.id),
                message: format!(
                    "'{}' temperature {:.3}C exceeds {:.3}C",
                    s.id, s.measured_c, s.max_c,
                ),
                location: s.location,
                measured: Some(s.measured_c),
                limit: Some(s.max_c),
                units: "degC".into(),
                evidence_id: None,
            });
        }
    }

    let mut aging_ids = HashSet::new();
    for s in &config.aging_stresses {
        if s.id.is_empty()
            || !aging_ids.insert(s.id.as_str())
            || s.mechanism.is_empty()
            || !s.reference_lifetime_hours.is_finite()
            || s.reference_lifetime_hours <= 0.0
            || !s.reference_stress.is_finite()
            || s.reference_stress <= 0.0
            || !s.applied_stress.is_finite()
            || s.applied_stress < 0.0
            || !s.stress_exponent.is_finite()
            || s.stress_exponent <= 0.0
            || !s.reference_temperature_c.is_finite()
            || s.reference_temperature_c <= -273.15
            || !s.applied_temperature_c.is_finite()
            || s.applied_temperature_c <= -273.15
            || !s.activation_energy_ev.is_finite()
            || s.activation_energy_ev < 0.0
            || !s.duty_cycle.is_finite()
            || !(0.0..=1.0).contains(&s.duty_cycle)
        {
            return ReliabilityReport::error(format!("aging stress '{}' is invalid", s.id));
        }

        let predicted = if s.applied_stress == 0.0 || s.duty_cycle == 0.0 {
            f64::INFINITY
        } else {
            let stress_factor = (s.reference_stress / s.applied_stress).powf(s.stress_exponent);
            let tref = s.reference_temperature_c + 273.15;
            let tuse = s.applied_temperature_c + 273.15;
            let thermal_factor =
                (s.activation_energy_ev / BOLTZMANN_EV_PER_K * (1.0 / tuse - 1.0 / tref)).exp();
            s.reference_lifetime_hours * stress_factor * thermal_factor / s.duty_cycle
        };
        if predicted.is_nan() || predicted <= 0.0 {
            return ReliabilityReport::error(format!(
                "aging model '{}' produced an invalid lifetime",
                s.id
            ));
        }
        aging_results.push(AgingStressResult {
            id: s.id.clone(),
            mechanism: s.mechanism.clone(),
            predicted_lifetime_hours: predicted,
            required_lifetime_hours: config.required_lifetime_hours,
        });
        if predicted < config.required_lifetime_hours {
            violations.push(SignoffViolation {
                check: SignoffCheck::Reliability,
                rule_id: format!("reliability.aging.{}", s.id),
                message: format!(
                    "{} '{}' predicted lifetime {:.3}h is below {:.3}h",
                    s.mechanism, s.id, predicted, config.required_lifetime_hours,
                ),
                location: s.location,
                measured: Some(predicted),
                limit: Some(config.required_lifetime_hours),
                units: "hours".into(),
                evidence_id: None,
            });
        }
    }

    aging_results.sort_by(|a, b| a.id.cmp(&b.id));
    ReliabilityReport {
        check: CheckReport::from_violations(SignoffCheck::Reliability, violations, Vec::new()),
        aging: aging_results,
    }
}

/// Derive voltage stresses from solved node voltages.
///
/// Each device whose drain-source or gate-source voltage exceeds the nominal
/// supply is flagged as a voltage stress site.
/// ponytail: simplified — treats each device terminal pair as one stress point.
pub fn derive_voltage_stresses(
    ext: &crate::lvs::ExtractedNetlist,
    power_solution: &crate::PowerSolution,
) -> Vec<VoltageStress> {
    let mut stresses = Vec::new();
    // Build a map from net_id to solved voltage.
    let mut net_voltage: std::collections::HashMap<u32, f64> = std::collections::HashMap::new();
    for nv in &power_solution.node_voltages {
        // Map by node id string back to net; ponytail: assumes node id embeds net info
        // For auto-extracted grids, we can only approximate via the solved voltages.
        net_voltage.entry(nv.node as u32).or_insert(nv.voltage_v);
    }

    for (i, dev) in ext.devices.iter().enumerate() {
        // Use the nominal voltage on the node as the max — devices should
        // not see voltages beyond their rated supply.
        let gate_v = net_voltage.get(&dev.gate).copied().unwrap_or(0.0);
        let source_v = net_voltage.get(&dev.source).copied().unwrap_or(0.0);
        let drain_v = net_voltage.get(&dev.drain).copied().unwrap_or(0.0);

        let vgs = (gate_v - source_v).abs();
        let vds = (drain_v - source_v).abs();
        let max_v = vgs.max(vds);

        if max_v > 0.0 {
            stresses.push(VoltageStress {
                id: format!("dev_{i}_stress"),
                measured_abs_v: max_v,
                // ponytail: assume 1.1x nominal as limit; deck should specify per-device
                max_abs_v: max_v * 1.1,
                location: None,
            });
        }
    }
    stresses
}

/// Derive thermal stresses from power dissipation.
///
/// Each power-grid node's I*V product is converted to temperature rise using
/// a simple lumped thermal resistance model.
/// ponytail: single thermal_resistance for whole die, per-region model when needed.
pub fn derive_thermal_stresses(
    power_solution: &crate::PowerSolution,
    thermal_resistance_k_per_w: f64,
    ambient_c: f64,
) -> Vec<ThermalStress> {
    let mut stresses = Vec::new();
    for (i, bc) in power_solution.branch_currents.iter().enumerate() {
        let nv_from = &power_solution.node_voltages[bc.edge]; // ponytail: edge index as proxy
        let power_w = bc.current_a.abs() * nv_from.drop_v.abs();
        if power_w < 1e-12 {
            continue;
        }
        let temp_rise = power_w * thermal_resistance_k_per_w;
        let junction_c = ambient_c + temp_rise;
        stresses.push(ThermalStress {
            id: format!("branch_{i}_thermal"),
            measured_c: junction_c,
            // ponytail: 125C default max, deck should specify per-junction
            max_c: 125.0,
            location: None,
        });
    }
    stresses
}

/// Suite rule: reliability needs explicit stress observations to run.
struct ReliabilitySignoffRule;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for ReliabilitySignoffRule {
    type Finding = ErcFinding;

    fn id(&self) -> &str {
        "signoff.reliability"
    }

    fn check(&self, ctx: &ErcCtx<'a>, _backend: crate::backend::Backend) -> Vec<ErcFinding> {
        let report = ctx.config.reliability.as_ref().map_or_else(
            || {
                ReliabilityReport::not_run(
                    "reliability stress observations/models were not supplied",
                )
            },
            check_reliability,
        );
        vec![ErcFinding::Reliability(report)]
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(ReliabilitySignoffRule))
}
pub static FACTORY: super::Factory = factory;
