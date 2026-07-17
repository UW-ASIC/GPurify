//! IR-drop analysis over a solved power grid.

use crate::{
    BranchCurrent, CheckReport, IrDropConfig, NodeVoltage, PowerGrid, PowerSolution, SignoffCheck,
    ErcCtx, ErcFinding, SignoffViolation,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IrDropReport {
    pub check: CheckReport,
    pub nodes: Vec<NodeVoltage>,
    pub branches: Vec<BranchCurrent>,
}

impl IrDropReport {
    pub(crate) fn not_run(reason: impl Into<String>) -> Self {
        Self {
            check: CheckReport::not_run(SignoffCheck::IrDrop, reason),
            nodes: Vec::new(),
            branches: Vec::new(),
        }
    }
    pub(crate) fn error(reason: impl Into<String>) -> Self {
        Self {
            check: CheckReport::error(SignoffCheck::IrDrop, reason),
            nodes: Vec::new(),
            branches: Vec::new(),
        }
    }
}

pub fn analyze_ir_drop(
    grid: &PowerGrid,
    solution: &PowerSolution,
    config: &IrDropConfig,
) -> IrDropReport {
    if solution.node_voltages.len() != grid.nodes.len()
        || solution.branch_currents.len() != grid.edges.len()
        || solution
            .node_voltages
            .iter()
            .enumerate()
            .any(|(i, n)| n.node != i || !n.voltage_v.is_finite() || !n.drop_v.is_finite())
        || solution
            .branch_currents
            .iter()
            .enumerate()
            .any(|(i, b)| b.edge != i || !b.current_a.is_finite())
    {
        return IrDropReport::error("power solution does not correspond to this grid");
    }
    if config.max_drop_v.is_none()
        && config.max_drop_pct.is_none()
        && config.max_overvoltage_v.is_none()
    {
        return IrDropReport::error("IR-drop configuration contains no limits");
    }
    if !grid.nodes.iter().any(|node| node.check_ir_drop) {
        return IrDropReport::error("IR-drop scope contains no nodes enabled for checking");
    }
    for (name, limit) in [
        ("max_drop_v", config.max_drop_v),
        ("max_drop_pct", config.max_drop_pct),
        ("max_overvoltage_v", config.max_overvoltage_v),
    ] {
        if limit.is_some_and(|v| !v.is_finite() || v < 0.0) {
            return IrDropReport::error(format!("IR-drop limit {name} is invalid"));
        }
    }

    let mut violations = Vec::new();
    for result in &solution.node_voltages {
        let node = &grid.nodes[result.node];
        if !node.check_ir_drop {
            continue;
        }
        if let Some(limit) = config.max_drop_v {
            if result.drop_v > limit {
                violations.push(SignoffViolation {
                    check: SignoffCheck::IrDrop,
                    rule_id: "ir_drop.absolute".into(),
                    message: format!(
                        "node '{}' drop {:.6}V exceeds {:.6}V",
                        node.id, result.drop_v, limit
                    ),
                    location: Some((node.x, node.y)),
                    measured: Some(result.drop_v),
                    limit: Some(limit),
                    units: "V".into(),
                    evidence_id: None,
                });
            }
        }
        if let Some(limit) = config.max_drop_pct {
            if node.nominal_voltage_v.abs() <= f64::EPSILON {
                return IrDropReport::error(format!(
                    "node '{}' has zero nominal voltage but a percentage limit is enabled",
                    node.id,
                ));
            }
            let pct = 100.0 * result.drop_v / node.nominal_voltage_v.abs();
            if pct > limit {
                violations.push(SignoffViolation {
                    check: SignoffCheck::IrDrop,
                    rule_id: "ir_drop.percent".into(),
                    message: format!("node '{}' drop {:.4}% exceeds {:.4}%", node.id, pct, limit),
                    location: Some((node.x, node.y)),
                    measured: Some(pct),
                    limit: Some(limit),
                    units: "%".into(),
                    evidence_id: None,
                });
            }
        }
        if let Some(limit) = config.max_overvoltage_v {
            let over = -result.drop_v;
            if over > limit {
                violations.push(SignoffViolation {
                    check: SignoffCheck::IrDrop,
                    rule_id: "ir_drop.overvoltage".into(),
                    message: format!(
                        "node '{}' overvoltage {:.6}V exceeds {:.6}V",
                        node.id, over, limit
                    ),
                    location: Some((node.x, node.y)),
                    measured: Some(over),
                    limit: Some(limit),
                    units: "V".into(),
                    evidence_id: None,
                });
            }
        }
    }
    IrDropReport {
        check: CheckReport::from_violations(
            SignoffCheck::IrDrop,
            violations,
            vec![format!(
                "solver iterations={}, relative residual={:.3e}",
                solution.iterations, solution.relative_residual,
            )],
        ),
        nodes: solution.node_voltages.clone(),
        branches: solution.branch_currents.clone(),
    }
}

/// Suite rule: consumes the shared power-grid solution computed once by
/// `run_erc` so IR-drop and EM never solve the grid twice.
struct IrDropSignoffRule;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for IrDropSignoffRule {
    type Finding = ErcFinding;

    fn id(&self) -> &str {
        "signoff.ir_drop"
    }

    fn check(&self, ctx: &ErcCtx<'a>, _backend: crate::backend::Backend) -> Vec<ErcFinding> {
        let report = match (&ctx.config.power, ctx.power) {
            (Some(p), Some(solve)) => match solve {
                Err(e) => IrDropReport::error(format!("power-grid solve failed: {e}")),
                Ok(solution) => p.ir_drop.as_ref().map_or_else(
                    || IrDropReport::not_run("IR-drop limits were not supplied"),
                    |c| analyze_ir_drop(&p.grid, solution, c),
                ),
            },
            _ => IrDropReport::not_run("power-grid topology and load currents were not supplied"),
        };
        vec![ErcFinding::IrDrop(report)]
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(IrDropSignoffRule))
}
pub static FACTORY: super::Factory = factory;
