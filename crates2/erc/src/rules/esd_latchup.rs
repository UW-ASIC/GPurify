use std::cmp::Ordering;
use std::collections::HashSet;

use crate::{CheckReport, SignoffCheck, ErcCtx, ErcFinding, SignoffViolation};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EsdNodeKind {
    IoPad,
    Power,
    Ground,
    Internal,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EsdNode {
    pub id: String,
    pub kind: EsdNodeKind,
    pub x: i32,
    pub y: i32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EsdEdge {
    pub id: String,
    pub from: usize,
    pub to: usize,
    pub bidirectional: bool,
    pub resistance_ohm: f64,
    pub current_capacity_a: f64,
    /// Maximum voltage imposed by this clamp element on the protected node.
    pub clamp_voltage_v: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EsdPathRequirement {
    pub id: String,
    pub source: usize,
    pub explicit_targets: Vec<usize>,
    pub target_kinds: Vec<EsdNodeKind>,
    pub required_current_a: f64,
    pub max_path_resistance_ohm: f64,
    pub max_clamp_voltage_v: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GuardRingEvidence {
    pub id: String,
    pub bias_node: usize,
    pub continuous: bool,
    pub width_um: f64,
    pub aggressor_distance_um: f64,
    pub victim_distance_um: f64,
    pub nearest_tap_distance_um: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LatchupSite {
    pub id: String,
    pub location: (i32, i32),
    pub guard_ring: Option<GuardRingEvidence>,
    pub allowed_bias_kinds: Vec<EsdNodeKind>,
    pub min_guard_ring_width_um: f64,
    pub max_aggressor_distance_um: f64,
    pub max_victim_distance_um: f64,
    pub max_tap_distance_um: f64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct EsdLatchupConfig {
    pub nodes: Vec<EsdNode>,
    pub edges: Vec<EsdEdge>,
    pub esd_paths: Vec<EsdPathRequirement>,
    pub latchup_sites: Vec<LatchupSite>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EsdPathResult {
    pub requirement_id: String,
    pub target: usize,
    pub edge_path: Vec<usize>,
    pub resistance_ohm: f64,
    pub min_current_capacity_a: f64,
    pub max_clamp_voltage_v: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EsdLatchupReport {
    pub check: CheckReport,
    pub paths: Vec<EsdPathResult>,
}

impl EsdLatchupReport {
    pub(crate) fn not_run(reason: impl Into<String>) -> Self {
        Self {
            check: CheckReport::not_run(SignoffCheck::EsdLatchup, reason),
            paths: Vec::new(),
        }
    }

    pub(crate) fn error(reason: impl Into<String>) -> Self {
        Self {
            check: CheckReport::error(SignoffCheck::EsdLatchup, reason),
            paths: Vec::new(),
        }
    }
}

fn shortest_qualified_path(
    config: &EsdLatchupConfig,
    req: &EsdPathRequirement,
    targets: &HashSet<usize>,
) -> Option<EsdPathResult> {
    let n = config.nodes.len();
    let mut dist = vec![f64::INFINITY; n];
    let mut prev: Vec<Option<(usize, usize)>> = vec![None; n]; // (previous node, edge)
    let mut done = vec![false; n];
    dist[req.source] = 0.0;

    let mut adjacency: Vec<Vec<(usize, usize)>> = vec![Vec::new(); n];
    for (ei, edge) in config.edges.iter().enumerate() {
        if edge.current_capacity_a + f64::EPSILON < req.required_current_a
            || edge.clamp_voltage_v > req.max_clamp_voltage_v
        {
            continue;
        }
        adjacency[edge.from].push((edge.to, ei));
        if edge.bidirectional {
            adjacency[edge.to].push((edge.from, ei));
        }
    }

    let mut found = None;
    for _ in 0..n {
        let next = (0..n)
            .filter(|&i| !done[i] && dist[i].is_finite())
            .min_by(|&a, &b| dist[a].partial_cmp(&dist[b]).unwrap_or(Ordering::Equal));
        let Some(u) = next else { break };
        done[u] = true;
        if targets.contains(&u) {
            found = Some(u);
            break;
        }
        for &(v, ei) in &adjacency[u] {
            if done[v] {
                continue;
            }
            let nd = dist[u] + config.edges[ei].resistance_ohm;
            if nd < dist[v] {
                dist[v] = nd;
                prev[v] = Some((u, ei));
            }
        }
    }

    let target = found?;
    let mut edges = Vec::new();
    let mut cursor = target;
    while cursor != req.source {
        let (p, edge) = prev[cursor]?;
        edges.push(edge);
        cursor = p;
    }
    edges.reverse();
    let min_capacity = edges
        .iter()
        .map(|&i| config.edges[i].current_capacity_a)
        .fold(f64::INFINITY, f64::min);
    let max_clamp = edges
        .iter()
        .map(|&i| config.edges[i].clamp_voltage_v)
        .fold(0.0, f64::max);
    Some(EsdPathResult {
        requirement_id: req.id.clone(),
        target,
        edge_path: edges,
        resistance_ohm: dist[target],
        min_current_capacity_a: min_capacity,
        max_clamp_voltage_v: max_clamp,
    })
}

pub fn check_esd_latchup(config: &EsdLatchupConfig) -> EsdLatchupReport {
    if config.esd_paths.is_empty() {
        return EsdLatchupReport::error(
            "ESD/latch-up configuration contains no ESD path requirements",
        );
    }
    if config.latchup_sites.is_empty() {
        return EsdLatchupReport::error("ESD/latch-up configuration contains no latch-up sites");
    }
    let mut node_ids = HashSet::new();
    for (i, node) in config.nodes.iter().enumerate() {
        if node.id.is_empty() || !node_ids.insert(node.id.as_str()) {
            return EsdLatchupReport::error(format!("ESD node {i} has an empty or duplicate id"));
        }
    }
    let mut edge_ids = HashSet::new();
    for (i, edge) in config.edges.iter().enumerate() {
        if edge.id.is_empty()
            || !edge_ids.insert(edge.id.as_str())
            || edge.from >= config.nodes.len()
            || edge.to >= config.nodes.len()
            || edge.from == edge.to
            || !edge.resistance_ohm.is_finite()
            || edge.resistance_ohm < 0.0
            || !edge.current_capacity_a.is_finite()
            || edge.current_capacity_a <= 0.0
            || !edge.clamp_voltage_v.is_finite()
            || edge.clamp_voltage_v < 0.0
        {
            return EsdLatchupReport::error(format!("ESD edge {i} ('{}') is malformed", edge.id));
        }
    }

    let mut violations = Vec::new();
    let mut paths = Vec::new();
    let mut requirement_ids = HashSet::new();
    for req in &config.esd_paths {
        if req.id.is_empty()
            || !requirement_ids.insert(req.id.as_str())
            || req.source >= config.nodes.len()
            || !req.required_current_a.is_finite()
            || req.required_current_a <= 0.0
            || !req.max_path_resistance_ohm.is_finite()
            || req.max_path_resistance_ohm < 0.0
            || !req.max_clamp_voltage_v.is_finite()
            || req.max_clamp_voltage_v < 0.0
        {
            return EsdLatchupReport::error(format!(
                "ESD path requirement '{}' is invalid",
                req.id
            ));
        }
        let mut targets: HashSet<usize> = req.explicit_targets.iter().copied().collect();
        if targets.iter().any(|&i| i >= config.nodes.len()) {
            return EsdLatchupReport::error(format!(
                "ESD path requirement '{}' references an unknown target",
                req.id
            ));
        }
        for (i, node) in config.nodes.iter().enumerate() {
            if req.target_kinds.contains(&node.kind) {
                targets.insert(i);
            }
        }
        targets.remove(&req.source);
        if targets.is_empty() {
            return EsdLatchupReport::error(format!(
                "ESD path requirement '{}' has no target nodes",
                req.id
            ));
        }
        match shortest_qualified_path(config, req, &targets) {
            None => violations.push(SignoffViolation {
                check: SignoffCheck::EsdLatchup,
                rule_id: format!("esd.path.{}", req.id),
                message: format!(
                    "no directed ESD path from '{}' meets {:.4}A and {:.4}V clamp requirements",
                    config.nodes[req.source].id, req.required_current_a, req.max_clamp_voltage_v,
                ),
                location: Some((config.nodes[req.source].x, config.nodes[req.source].y)),
                measured: None,
                limit: Some(req.required_current_a),
                units: "A".into(),
                evidence_id: None,
            }),
            Some(path) => {
                if path.resistance_ohm > req.max_path_resistance_ohm {
                    violations.push(SignoffViolation {
                        check: SignoffCheck::EsdLatchup,
                        rule_id: format!("esd.path_resistance.{}", req.id),
                        message: format!(
                            "ESD path '{}' resistance {:.6}ohm exceeds {:.6}ohm",
                            req.id, path.resistance_ohm, req.max_path_resistance_ohm,
                        ),
                        location: Some((config.nodes[req.source].x, config.nodes[req.source].y)),
                        measured: Some(path.resistance_ohm),
                        limit: Some(req.max_path_resistance_ohm),
                        units: "ohm".into(),
                        evidence_id: None,
                    });
                }
                paths.push(path);
            }
        }
    }

    let mut site_ids = HashSet::new();
    for site in &config.latchup_sites {
        if site.id.is_empty()
            || !site_ids.insert(site.id.as_str())
            || site.allowed_bias_kinds.is_empty()
            || !site.min_guard_ring_width_um.is_finite()
            || site.min_guard_ring_width_um <= 0.0
            || !site.max_aggressor_distance_um.is_finite()
            || site.max_aggressor_distance_um < 0.0
            || !site.max_victim_distance_um.is_finite()
            || site.max_victim_distance_um < 0.0
            || !site.max_tap_distance_um.is_finite()
            || site.max_tap_distance_um < 0.0
        {
            return EsdLatchupReport::error(format!("latch-up site '{}' is invalid", site.id));
        }
        let Some(ring) = &site.guard_ring else {
            violations.push(SignoffViolation {
                check: SignoffCheck::EsdLatchup,
                rule_id: format!("latchup.guard_ring.{}", site.id),
                message: format!("latch-up site '{}' has no guard ring", site.id),
                location: Some(site.location),
                measured: None,
                limit: Some(site.min_guard_ring_width_um),
                units: "um".into(),
                evidence_id: None,
            });
            continue;
        };
        if ring.bias_node >= config.nodes.len()
            || ring.id.is_empty()
            || !ring.width_um.is_finite()
            || ring.width_um <= 0.0
            || !ring.aggressor_distance_um.is_finite()
            || ring.aggressor_distance_um < 0.0
            || !ring.victim_distance_um.is_finite()
            || ring.victim_distance_um < 0.0
            || !ring.nearest_tap_distance_um.is_finite()
            || ring.nearest_tap_distance_um < 0.0
        {
            return EsdLatchupReport::error(format!(
                "guard-ring evidence for '{}' is invalid",
                site.id
            ));
        }
        let bias = &config.nodes[ring.bias_node];
        let checks = [
            (!ring.continuous, "continuity", 0.0, 1.0, "boolean"),
            (
                ring.width_um < site.min_guard_ring_width_um,
                "width",
                ring.width_um,
                site.min_guard_ring_width_um,
                "um",
            ),
            (
                ring.aggressor_distance_um > site.max_aggressor_distance_um,
                "aggressor_distance",
                ring.aggressor_distance_um,
                site.max_aggressor_distance_um,
                "um",
            ),
            (
                ring.victim_distance_um > site.max_victim_distance_um,
                "victim_distance",
                ring.victim_distance_um,
                site.max_victim_distance_um,
                "um",
            ),
            (
                ring.nearest_tap_distance_um > site.max_tap_distance_um,
                "tap_distance",
                ring.nearest_tap_distance_um,
                site.max_tap_distance_um,
                "um",
            ),
        ];
        for (bad, name, measured, limit, units) in checks {
            if bad {
                violations.push(SignoffViolation {
                    check: SignoffCheck::EsdLatchup,
                    rule_id: format!("latchup.{name}.{}", site.id),
                    message: format!(
                        "latch-up site '{}' guard-ring {name} is out of bounds",
                        site.id
                    ),
                    location: Some(site.location),
                    measured: Some(measured),
                    limit: Some(limit),
                    units: units.into(),
                    evidence_id: None,
                });
            }
        }
        if !site.allowed_bias_kinds.contains(&bias.kind) {
            violations.push(SignoffViolation {
                check: SignoffCheck::EsdLatchup,
                rule_id: format!("latchup.bias.{}", site.id),
                message: format!(
                    "guard ring '{}' is connected to invalid bias node '{}'",
                    ring.id, bias.id
                ),
                location: Some(site.location),
                measured: None,
                limit: None,
                units: String::new(),
                evidence_id: None,
            });
        }
    }

    paths.sort_by(|a, b| a.requirement_id.cmp(&b.requirement_id));
    EsdLatchupReport {
        check: CheckReport::from_violations(SignoffCheck::EsdLatchup, violations, Vec::new()),
        paths,
    }
}

/// Suite rule: ESD/latch-up needs an explicit network and evidence to run.
struct EsdLatchupSignoffRule;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for EsdLatchupSignoffRule {
    type Finding = ErcFinding;

    fn id(&self) -> &str {
        "signoff.esd_latchup"
    }

    fn check(&self, ctx: &ErcCtx<'a>, _backend: crate::backend::Backend) -> Vec<ErcFinding> {
        let report = ctx.config.esd_latchup.as_ref().map_or_else(
            || EsdLatchupReport::not_run("ESD network and latch-up evidence were not supplied"),
            check_esd_latchup,
        );
        vec![ErcFinding::EsdLatchup(report)]
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(EsdLatchupSignoffRule))
}
pub static FACTORY: super::Factory = factory;
