//! Electromigration analysis over a solved power grid.

use crate::{
    CheckReport, ElectromigrationConfig, PowerEdgeKind, PowerGrid, PowerSolution, SignoffCheck,
    ErcCtx, ErcFinding, SignoffViolation,
};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EmBranchResult {
    pub edge: usize,
    pub id: String,
    pub current_a: f64,
    pub current_density_a_per_um2: Option<f64>,
    pub allowed: f64,
    pub blech_exempt: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ElectromigrationReport {
    pub check: CheckReport,
    pub branches: Vec<EmBranchResult>,
}

impl ElectromigrationReport {
    pub(crate) fn not_run(reason: impl Into<String>) -> Self {
        Self {
            check: CheckReport::not_run(SignoffCheck::Electromigration, reason),
            branches: Vec::new(),
        }
    }
    pub(crate) fn error(reason: impl Into<String>) -> Self {
        Self {
            check: CheckReport::error(SignoffCheck::Electromigration, reason),
            branches: Vec::new(),
        }
    }
}

const BOLTZMANN_EV_PER_K: f64 = 8.617_333_262_145e-5;

pub fn analyze_electromigration(
    grid: &PowerGrid,
    solution: &PowerSolution,
    config: &ElectromigrationConfig,
) -> ElectromigrationReport {
    if solution.branch_currents.len() != grid.edges.len()
        || solution
            .branch_currents
            .iter()
            .enumerate()
            .any(|(i, b)| b.edge != i || !b.current_a.is_finite())
        || grid
            .edges
            .iter()
            .any(|e| e.from >= grid.nodes.len() || e.to >= grid.nodes.len())
    {
        return ElectromigrationReport::error("power solution does not correspond to this grid");
    }
    if !config.reference_temperature_c.is_finite()
        || config.reference_temperature_c <= -273.15
        || !config.activation_energy_ev.is_finite()
        || config.activation_energy_ev < 0.0
        || !config.current_exponent.is_finite()
        || config.current_exponent <= 0.0
        || config
            .max_temperature_c
            .is_some_and(|v| !v.is_finite() || v <= -273.15)
    {
        return ElectromigrationReport::error(
            "electromigration temperature/Arrhenius parameters are invalid",
        );
    }
    for (name, limit) in [
        (
            "default_max_current_density_a_per_um2",
            config.default_max_current_density_a_per_um2,
        ),
        (
            "default_max_current_per_cut_a",
            config.default_max_current_per_cut_a,
        ),
    ] {
        if limit.is_some_and(|v| !v.is_finite() || v <= 0.0) {
            return ElectromigrationReport::error(format!(
                "electromigration limit {name} is invalid"
            ));
        }
    }

    let tref = config.reference_temperature_c + 273.15;
    let mut results = Vec::new();
    let mut violations = Vec::new();
    for (i, edge) in grid.edges.iter().enumerate() {
        if edge.em_exempt {
            continue;
        }
        if !edge.temperature_c.is_finite() || edge.temperature_c <= -273.15 {
            return ElectromigrationReport::error(format!(
                "edge '{}' has an invalid temperature",
                edge.id
            ));
        }
        if edge
            .blech_product_limit_a_per_um
            .is_some_and(|v| !v.is_finite() || v < 0.0)
        {
            return ElectromigrationReport::error(format!(
                "edge '{}' has an invalid Blech-product limit",
                edge.id
            ));
        }
        let current = solution.branch_currents[i].current_a.abs();
        let temp_k = edge.temperature_c + 273.15;
        let exponent = config.activation_energy_ev / (config.current_exponent * BOLTZMANN_EV_PER_K)
            * (1.0 / temp_k - 1.0 / tref);
        let derating = exponent.exp();
        if !derating.is_finite() {
            return ElectromigrationReport::error(format!(
                "edge '{}' temperature derating overflowed",
                edge.id
            ));
        }

        if let Some(max_temp) = config.max_temperature_c {
            if edge.temperature_c > max_temp {
                violations.push(SignoffViolation {
                    check: SignoffCheck::Electromigration,
                    rule_id: "em.temperature".into(),
                    message: format!(
                        "edge '{}' temperature {:.2}C exceeds {:.2}C",
                        edge.id, edge.temperature_c, max_temp
                    ),
                    location: Some((grid.nodes[edge.from].x, grid.nodes[edge.from].y)),
                    measured: Some(edge.temperature_c),
                    limit: Some(max_temp),
                    units: "degC".into(),
                    evidence_id: None,
                });
            }
        }

        match edge.kind {
            PowerEdgeKind::Metal {
                width_um,
                thickness_um,
            } => {
                if !width_um.is_finite()
                    || width_um <= 0.0
                    || !thickness_um.is_finite()
                    || thickness_um <= 0.0
                {
                    return ElectromigrationReport::error(format!(
                        "edge '{}' has invalid metal dimensions",
                        edge.id
                    ));
                }
                if !edge.length_um.is_finite() || edge.length_um < 0.0 {
                    return ElectromigrationReport::error(format!(
                        "edge '{}' has an invalid metal length",
                        edge.id
                    ));
                }
                let Some(base_limit) = edge
                    .max_current_density_a_per_um2
                    .or(config.default_max_current_density_a_per_um2)
                else {
                    return ElectromigrationReport::error(format!(
                        "edge '{}' has no current-density limit",
                        edge.id
                    ));
                };
                if !base_limit.is_finite() || base_limit <= 0.0 {
                    return ElectromigrationReport::error(format!(
                        "edge '{}' has an invalid current-density limit",
                        edge.id
                    ));
                }
                let density = current / (width_um * thickness_um);
                let allowed = base_limit * derating;
                let blech_exempt = edge.blech_product_limit_a_per_um.is_some_and(|limit| {
                    limit.is_finite() && limit >= 0.0 && density * edge.length_um.max(0.0) <= limit
                });
                results.push(EmBranchResult {
                    edge: i,
                    id: edge.id.clone(),
                    current_a: current,
                    current_density_a_per_um2: Some(density),
                    allowed,
                    blech_exempt,
                });
                if !blech_exempt && density > allowed {
                    violations.push(SignoffViolation {
                        check: SignoffCheck::Electromigration,
                        rule_id: "em.metal_current_density".into(),
                        message: format!(
                            "edge '{}' current density {:.6} exceeds {:.6} A/um^2",
                            edge.id, density, allowed
                        ),
                        location: Some((grid.nodes[edge.from].x, grid.nodes[edge.from].y)),
                        measured: Some(density),
                        limit: Some(allowed),
                        units: "A/um^2".into(),
                        evidence_id: None,
                    });
                }
            }
            PowerEdgeKind::Via { cuts } => {
                if cuts == 0 {
                    return ElectromigrationReport::error(format!(
                        "edge '{}' has zero via cuts",
                        edge.id
                    ));
                }
                let Some(per_cut) = edge
                    .max_current_per_cut_a
                    .or(config.default_max_current_per_cut_a)
                else {
                    return ElectromigrationReport::error(format!(
                        "edge '{}' has no per-cut current limit",
                        edge.id
                    ));
                };
                if !per_cut.is_finite() || per_cut <= 0.0 {
                    return ElectromigrationReport::error(format!(
                        "edge '{}' has an invalid per-cut current limit",
                        edge.id
                    ));
                }
                let allowed = per_cut * f64::from(cuts) * derating;
                results.push(EmBranchResult {
                    edge: i,
                    id: edge.id.clone(),
                    current_a: current,
                    current_density_a_per_um2: None,
                    allowed,
                    blech_exempt: false,
                });
                if current > allowed {
                    violations.push(SignoffViolation {
                        check: SignoffCheck::Electromigration,
                        rule_id: "em.via_current".into(),
                        message: format!(
                            "via '{}' current {:.6}A exceeds {:.6}A",
                            edge.id, current, allowed
                        ),
                        location: Some((grid.nodes[edge.from].x, grid.nodes[edge.from].y)),
                        measured: Some(current),
                        limit: Some(allowed),
                        units: "A".into(),
                        evidence_id: None,
                    });
                }
            }
        }
    }
    results.sort_by_key(|r| r.edge);
    ElectromigrationReport {
        check: CheckReport::from_violations(SignoffCheck::Electromigration, violations, Vec::new()),
        branches: results,
    }
}

/// Suite rule: consumes the shared power-grid solution computed once by
/// `run_erc` so IR-drop and EM never solve the grid twice.
struct ElectromigrationSignoffRule;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for ElectromigrationSignoffRule {
    type Finding = ErcFinding;

    fn id(&self) -> &str {
        "signoff.electromigration"
    }

    fn check(&self, ctx: &ErcCtx<'a>, _backend: crate::backend::Backend) -> Vec<ErcFinding> {
        let report = match (&ctx.config.power, ctx.power) {
            (Some(p), Some(solve)) => match solve {
                Err(e) => ElectromigrationReport::error(format!("power-grid solve failed: {e}")),
                Ok(solution) => p.electromigration.as_ref().map_or_else(
                    || {
                        ElectromigrationReport::not_run(
                            "electromigration limits were not supplied",
                        )
                    },
                    |c| analyze_electromigration(&p.grid, solution, c),
                ),
            },
            _ => ElectromigrationReport::not_run(
                "power-grid topology and load currents were not supplied",
            ),
        };
        vec![ErcFinding::Electromigration(report)]
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(ElectromigrationSignoffRule))
}
pub static FACTORY: super::Factory = factory;
