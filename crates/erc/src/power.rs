//! Shared power-grid model and DC solve consumed by the IR-drop and
//! electromigration rules.

use std::collections::{HashSet, VecDeque};

#[derive(Debug, Clone, PartialEq)]
pub struct PowerNode {
    pub id: String,
    pub x: i32,
    pub y: i32,
    /// Expected rail voltage at this node before interconnect loss.
    pub nominal_voltage_v: f64,
    /// Some(v) makes this an ideal voltage source/boundary condition.
    pub fixed_voltage_v: Option<f64>,
    /// Positive values draw current from the grid; negative values inject it.
    pub load_current_a: f64,
    pub check_ir_drop: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PowerEdgeKind {
    Metal { width_um: f64, thickness_um: f64 },
    Via { cuts: u32 },
}

#[derive(Debug, Clone, PartialEq)]
pub struct PowerEdge {
    pub id: String,
    pub from: usize,
    pub to: usize,
    pub resistance_ohm: f64,
    pub length_um: f64,
    pub kind: PowerEdgeKind,
    pub temperature_c: f64,
    /// Per-edge foundry limit; falls back to the EM config default.
    pub max_current_density_a_per_um2: Option<f64>,
    /// Per-cut limit for vias; falls back to the EM config default.
    pub max_current_per_cut_a: Option<f64>,
    /// Optional Blech `J*L` immortality threshold in A/um.
    pub blech_product_limit_a_per_um: Option<f64>,
    pub em_exempt: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PowerGrid {
    pub nodes: Vec<PowerNode>,
    pub edges: Vec<PowerEdge>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PowerSolveConfig {
    pub relative_tolerance: f64,
    pub max_iterations: usize,
}

impl Default for PowerSolveConfig {
    fn default() -> Self {
        Self {
            relative_tolerance: 1e-10,
            max_iterations: 20_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IrDropConfig {
    pub max_drop_v: Option<f64>,
    /// Percent, e.g. `5.0` means five percent.
    pub max_drop_pct: Option<f64>,
    pub max_overvoltage_v: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ElectromigrationConfig {
    pub default_max_current_density_a_per_um2: Option<f64>,
    pub default_max_current_per_cut_a: Option<f64>,
    pub reference_temperature_c: f64,
    pub activation_energy_ev: f64,
    pub current_exponent: f64,
    pub max_temperature_c: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PowerSignoffConfig {
    pub grid: PowerGrid,
    pub solver: PowerSolveConfig,
    pub ir_drop: Option<IrDropConfig>,
    pub electromigration: Option<ElectromigrationConfig>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NodeVoltage {
    pub node: usize,
    pub id: String,
    pub voltage_v: f64,
    pub nominal_voltage_v: f64,
    pub drop_v: f64,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BranchCurrent {
    pub edge: usize,
    pub id: String,
    /// Positive is from `PowerEdge::from` to `PowerEdge::to`.
    pub current_a: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PowerSolution {
    pub node_voltages: Vec<NodeVoltage>,
    pub branch_currents: Vec<BranchCurrent>,
    pub iterations: usize,
    pub relative_residual: f64,
}

fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

/// Solve the resistor grid by conjugate gradients after eliminating fixed-voltage nodes.
pub fn solve_power_grid(
    grid: &PowerGrid,
    config: &PowerSolveConfig,
) -> Result<PowerSolution, String> {
    if grid.nodes.is_empty() {
        return Err("power grid contains no nodes".into());
    }
    if !config.relative_tolerance.is_finite()
        || config.relative_tolerance <= 0.0
        || config.max_iterations == 0
    {
        return Err("power solver tolerance/iteration limit is invalid".into());
    }
    let mut ids = HashSet::new();
    for (i, n) in grid.nodes.iter().enumerate() {
        if n.id.is_empty() || !ids.insert(n.id.as_str()) {
            return Err(format!("node {i} has an empty or duplicate id"));
        }
        if !n.nominal_voltage_v.is_finite()
            || !n.load_current_a.is_finite()
            || n.fixed_voltage_v.is_some_and(|v| !v.is_finite())
        {
            return Err(format!(
                "node '{}' contains a non-finite electrical value",
                n.id
            ));
        }
    }
    if !grid.nodes.iter().any(|n| n.fixed_voltage_v.is_some()) {
        return Err("power grid has no fixed-voltage supply/reference node".into());
    }

    let mut adjacency = vec![Vec::new(); grid.nodes.len()];
    let mut edge_ids = HashSet::new();
    for (i, e) in grid.edges.iter().enumerate() {
        if e.id.is_empty()
            || !edge_ids.insert(e.id.as_str())
            || e.from >= grid.nodes.len()
            || e.to >= grid.nodes.len()
            || e.from == e.to
            || !e.resistance_ohm.is_finite()
            || e.resistance_ohm <= 0.0
        {
            return Err(format!("edge {i} ('{}') is malformed or duplicated", e.id));
        }
        adjacency[e.from].push(e.to);
        adjacency[e.to].push(e.from);
    }

    // Every solved component must be anchored by at least one fixed-voltage node.
    let mut anchored = vec![false; grid.nodes.len()];
    let mut queue = VecDeque::new();
    for (i, n) in grid.nodes.iter().enumerate() {
        if n.fixed_voltage_v.is_some() {
            anchored[i] = true;
            queue.push_back(i);
        }
    }
    while let Some(i) = queue.pop_front() {
        for &j in &adjacency[i] {
            if !anchored[j] {
                anchored[j] = true;
                queue.push_back(j);
            }
        }
    }
    if let Some((i, _)) = grid
        .nodes
        .iter()
        .enumerate()
        .find(|(i, n)| n.fixed_voltage_v.is_none() && !anchored[*i])
    {
        return Err(format!(
            "node '{}' belongs to an unanchored power-grid island",
            grid.nodes[i].id
        ));
    }

    let mut unknown_of_node = vec![usize::MAX; grid.nodes.len()];
    let mut nodes_of_unknown = Vec::new();
    for (i, n) in grid.nodes.iter().enumerate() {
        if n.fixed_voltage_v.is_none() {
            unknown_of_node[i] = nodes_of_unknown.len();
            nodes_of_unknown.push(i);
        }
    }
    let m = nodes_of_unknown.len();
    let mut diag = vec![0.0; m];
    let mut off: Vec<Vec<(usize, f64)>> = vec![Vec::new(); m];
    let mut rhs = vec![0.0; m];
    for (ui, &ni) in nodes_of_unknown.iter().enumerate() {
        rhs[ui] = -grid.nodes[ni].load_current_a;
    }
    for e in &grid.edges {
        let g = 1.0 / e.resistance_ohm;
        let uf = unknown_of_node[e.from];
        let ut = unknown_of_node[e.to];
        match (uf != usize::MAX, ut != usize::MAX) {
            (true, true) => {
                diag[uf] += g;
                diag[ut] += g;
                off[uf].push((ut, g));
                off[ut].push((uf, g));
            }
            (true, false) => {
                diag[uf] += g;
                rhs[uf] += g * grid.nodes[e.to].fixed_voltage_v.unwrap();
            }
            (false, true) => {
                diag[ut] += g;
                rhs[ut] += g * grid.nodes[e.from].fixed_voltage_v.unwrap();
            }
            (false, false) => {}
        }
    }
    if let Some((ui, _)) = diag
        .iter()
        .enumerate()
        .find(|(_, d)| **d <= 0.0 || !d.is_finite())
    {
        return Err(format!(
            "node '{}' has no finite conductive path",
            grid.nodes[nodes_of_unknown[ui]].id
        ));
    }

    let matvec = |x: &[f64], y: &mut [f64]| {
        for i in 0..m {
            let mut v = diag[i] * x[i];
            for &(j, g) in &off[i] {
                v -= g * x[j];
            }
            y[i] = v;
        }
    };

    let mut x: Vec<f64> = nodes_of_unknown
        .iter()
        .map(|&i| grid.nodes[i].nominal_voltage_v)
        .collect();
    let mut ax = vec![0.0; m];
    matvec(&x, &mut ax);
    let mut r: Vec<f64> = rhs.iter().zip(&ax).map(|(b, a)| b - a).collect();
    let mut p = r.clone();
    let mut rr = dot(&r, &r);
    // Do not impose an implicit one-ampere absolute scale on convergence.
    // Small IC loads are routine; normalizing by max(1 A) could accept the
    // nominal-voltage initial guess without solving a micro/nanoamp network.
    let rhs_norm = dot(&rhs, &rhs).sqrt().max(f64::MIN_POSITIVE);
    let target = config.relative_tolerance * rhs_norm;
    let mut iterations = 0;
    let mut ap = vec![0.0; m];
    while rr.sqrt() > target && iterations < config.max_iterations {
        matvec(&p, &mut ap);
        let pap = dot(&p, &ap);
        // `pap` scales with both current and conductance and can legitimately
        // be far below machine epsilon in a high-resistance, low-current grid.
        // Positive definiteness is a sign test here, not an absolute cutoff.
        if !pap.is_finite() || pap <= 0.0 {
            return Err("power-grid matrix is singular or not positive definite".into());
        }
        let alpha = rr / pap;
        for i in 0..m {
            x[i] += alpha * p[i];
            r[i] -= alpha * ap[i];
        }
        let next_rr = dot(&r, &r);
        if !next_rr.is_finite() {
            return Err("power-grid solver diverged".into());
        }
        let beta = if rr > 0.0 { next_rr / rr } else { 0.0 };
        for i in 0..m {
            p[i] = r[i] + beta * p[i];
        }
        rr = next_rr;
        iterations += 1;
    }
    let relative_residual = rr.sqrt() / rhs_norm;
    if relative_residual > config.relative_tolerance {
        return Err(format!(
            "power-grid solver did not converge in {} iterations (relative residual {:.3e})",
            config.max_iterations, relative_residual,
        ));
    }

    let mut voltages = vec![0.0; grid.nodes.len()];
    for (i, n) in grid.nodes.iter().enumerate() {
        voltages[i] = n.fixed_voltage_v.unwrap_or_else(|| x[unknown_of_node[i]]);
    }
    let node_voltages = grid
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| {
            // Positive and negative rails both report degradation as a positive
            // drop.  On a nominal 0V rail, absolute ground bounce is the drop.
            let drop_v = if n.nominal_voltage_v.abs() <= f64::EPSILON {
                voltages[i].abs()
            } else {
                n.nominal_voltage_v.signum() * (n.nominal_voltage_v - voltages[i])
            };
            NodeVoltage {
                node: i,
                id: n.id.clone(),
                voltage_v: voltages[i],
                nominal_voltage_v: n.nominal_voltage_v,
                drop_v,
            }
        })
        .collect();
    let branch_currents = grid
        .edges
        .iter()
        .enumerate()
        .map(|(i, e)| BranchCurrent {
            edge: i,
            id: e.id.clone(),
            current_a: (voltages[e.from] - voltages[e.to]) / e.resistance_ohm,
        })
        .collect();
    Ok(PowerSolution {
        node_voltages,
        branch_currents,
        iterations,
        relative_residual,
    })
}
