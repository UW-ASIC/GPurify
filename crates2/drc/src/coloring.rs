//! Deterministic complete bounded multi-pattern decomposition.
//!
//! The solver uses DSATUR variable ordering with exhaustive backtracking. Optional
//! stitch candidates are modeled as conflict edges that may be disabled at a stated
//! non-negative cost; branch-and-bound returns the minimum-cost legal solution. Search
//! and graph-size limits are explicit errors, never an uncolorable/clean result.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StitchCandidate {
    pub a: usize,
    pub b: usize,
    pub cost: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColoringProblem {
    pub node_count: usize,
    pub color_count: usize,
    pub conflicts: Vec<(usize, usize)>,
    pub precolors: BTreeMap<usize, usize>,
    pub allowed_colors: BTreeMap<usize, BTreeSet<usize>>,
    pub stitches: Vec<StitchCandidate>,
    pub max_nodes: usize,
    pub max_search_states: u64,
}

impl ColoringProblem {
    pub fn new(node_count: usize, color_count: usize, conflicts: Vec<(usize, usize)>) -> Self {
        Self {
            node_count,
            color_count,
            conflicts,
            precolors: BTreeMap::new(),
            allowed_colors: BTreeMap::new(),
            stitches: Vec::new(),
            max_nodes: 50_000,
            max_search_states: 10_000_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColoringSolution {
    pub colors: Vec<usize>,
    pub selected_stitches: Vec<StitchCandidate>,
    pub stitch_cost: u64,
    pub explored_states: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ColoringError {
    Invalid(String),
    CapacityExceeded { nodes: usize, limit: usize },
    SearchLimit { explored: u64, limit: u64 },
    Uncolorable { witness: Vec<usize> },
}

impl fmt::Display for ColoringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid coloring problem: {message}"),
            Self::CapacityExceeded { nodes, limit } => {
                write!(f, "coloring graph has {nodes} nodes (limit {limit})")
            }
            Self::SearchLimit { explored, limit } => {
                write!(
                    f,
                    "coloring search explored {explored} states (limit {limit})"
                )
            }
            Self::Uncolorable { witness } => {
                write!(f, "graph is uncolorable; witness nodes {witness:?}")
            }
        }
    }
}

impl std::error::Error for ColoringError {}

/// Reduce domains using arc consistency before search.
fn ac3_preprocess(
    adj: &[Vec<usize>],
    domains: &mut [BTreeSet<usize>],
) -> Result<(), ColoringError> {
    // Standard AC-3: maintain a worklist of arcs.
    // For each arc (i, j), remove values from domain[i] that have no support in domain[j].
    let mut worklist: VecDeque<(usize, usize)> = VecDeque::new();
    for (i, neighbors) in adj.iter().enumerate() {
        for &j in neighbors {
            worklist.push_back((i, j));
        }
    }
    while let Some((i, j)) = worklist.pop_front() {
        let mut changed = false;
        let supported: BTreeSet<usize> = domains[i]
            .iter()
            .copied()
            .filter(|&val| domains[j].iter().any(|&other| val != other))
            .collect();
        if supported.len() < domains[i].len() {
            domains[i] = supported;
            changed = true;
        }
        if domains[i].is_empty() {
            return Err(ColoringError::Uncolorable {
                witness: vec![i, j],
            });
        }
        if changed {
            for &k in &adj[i] {
                if k != j {
                    worklist.push_back((k, i));
                }
            }
        }
    }
    Ok(())
}

/// Extract a minimal uncolorable subgraph from the witness set.
fn minimal_unsat_core(witness: &[usize], adj: &[Vec<usize>], color_count: usize) -> Vec<usize> {
    // ponytail: greedy removal — try dropping each node, keep if still uncolorable.
    // O(n² * color_count) but witness sets are small in practice.
    let mut core: Vec<usize> = witness.to_vec();
    let mut i = 0;
    while i < core.len() {
        let removed = core.remove(i);
        if is_subgraph_uncolorable(&core, adj, color_count) {
            // removal kept it uncolorable, don't re-insert
        } else {
            core.insert(i, removed);
            i += 1;
        }
    }
    core
}

/// Quick greedy check: is the subgraph induced by `nodes` uncolorable with `color_count`?
fn is_subgraph_uncolorable(nodes: &[usize], adj: &[Vec<usize>], color_count: usize) -> bool {
    let node_set: BTreeSet<usize> = nodes.iter().copied().collect();
    // Build sub-problem and try to solve with a small search limit
    let index_map: BTreeMap<usize, usize> =
        nodes.iter().enumerate().map(|(i, &n)| (n, i)).collect();
    let mut sub_conflicts = Vec::new();
    for &n in nodes {
        for &neighbor in &adj[n] {
            if let Some(&ni) = index_map.get(&neighbor) {
                let a = index_map[&n];
                let b = ni;
                if a < b {
                    sub_conflicts.push((a, b));
                }
            }
        }
    }
    // For small subgraphs, clique check: if |nodes| > color_count and fully connected
    if node_set.len() > color_count {
        let fully_connected = nodes
            .iter()
            .all(|&n| nodes.iter().all(|&m| n == m || adj[n].contains(&m)));
        if fully_connected {
            return true;
        }
    }
    sub_conflicts.dedup();
    let mut sub_problem = ColoringProblem::new(nodes.len(), color_count, sub_conflicts);
    sub_problem.max_search_states = 10_000; // ponytail: small budget, enough for witness
    solve_coloring(&sub_problem).is_err()
}

/// Solve the complete finite problem or return a typed capacity/uncolorable result.
pub fn solve_coloring(problem: &ColoringProblem) -> Result<ColoringSolution, ColoringError> {
    validate(problem)?;
    if problem.node_count > problem.max_nodes {
        return Err(ColoringError::CapacityExceeded {
            nodes: problem.node_count,
            limit: problem.max_nodes,
        });
    }

    let mut stitch_by_edge = BTreeMap::<(usize, usize), StitchCandidate>::new();
    for stitch in &problem.stitches {
        stitch_by_edge.insert(edge(stitch.a, stitch.b), stitch.clone());
    }
    let mut conflicts: Vec<_> = problem
        .conflicts
        .iter()
        .copied()
        .map(|(a, b)| edge(a, b))
        .collect();
    conflicts.sort_unstable();
    conflicts.dedup();

    let mut solver = Solver {
        problem,
        conflicts,
        stitch_by_edge,
        colors: vec![None; problem.node_count],
        disabled: BTreeSet::new(),
        cost: 0,
        explored: 0,
        best: None,
        hit_limit: false,
    };
    for (&node, &color) in &problem.precolors {
        solver.colors[node] = Some(color);
    }
    // A same-color conflict fixed by precolors is not merely "permitted" by a
    // stitch candidate: that stitch is forced and must be selected and charged.
    for &(a, b) in &solver.conflicts {
        if solver.colors[a].is_some() && solver.colors[a] == solver.colors[b] {
            let pair = edge(a, b);
            let Some(stitch) = solver.stitch_by_edge.get(&pair) else {
                return Err(ColoringError::Uncolorable {
                    witness: vec![a, b],
                });
            };
            solver.disabled.insert(pair);
            solver.cost = solver
                .cost
                .checked_add(u64::from(stitch.cost))
                .ok_or_else(|| ColoringError::Invalid("forced stitch cost overflow".into()))?;
        }
    }
    if !solver.partial_consistent() {
        return Err(ColoringError::Uncolorable {
            witness: precolor_witness(problem),
        });
    }

    // AC-3 domain reduction before search
    {
        let stitch_edges: BTreeSet<_> = problem.stitches.iter().map(|s| edge(s.a, s.b)).collect();
        let mut adj = vec![Vec::new(); problem.node_count];
        for &(a, b) in &solver.conflicts {
            if !solver.disabled.contains(&(a, b)) && !stitch_edges.contains(&(a, b)) {
                adj[a].push(b);
                adj[b].push(a);
            }
        }
        let mut domains: Vec<BTreeSet<usize>> = (0..problem.node_count)
            .map(|n| {
                if let Some(&c) = problem.precolors.get(&n) {
                    BTreeSet::from([c])
                } else if let Some(allowed) = problem.allowed_colors.get(&n) {
                    allowed.clone()
                } else {
                    (0..problem.color_count).collect()
                }
            })
            .collect();
        if let Err(e) = ac3_preprocess(&adj, &mut domains) {
            return Err(e);
        }
        // ponytail: AC-3 result currently advisory; full domain integration
        // would thread reduced domains into the solver's allowed() method.
        // For now, early uncolorable detection is the win.
    }

    solver.search();
    // A provisional incumbent is not proof of optimality. If any branch was
    // truncated, return indeterminate even when a legal solution was found.
    if solver.hit_limit {
        return Err(ColoringError::SearchLimit {
            explored: solver.explored,
            limit: problem.max_search_states,
        });
    }
    if let Some(mut solution) = solver.best {
        solution.explored_states = solver.explored;
        return Ok(solution);
    }
    Err(ColoringError::Uncolorable {
        witness: minimal_witness(problem),
    })
}

struct Solver<'a> {
    problem: &'a ColoringProblem,
    conflicts: Vec<(usize, usize)>,
    stitch_by_edge: BTreeMap<(usize, usize), StitchCandidate>,
    colors: Vec<Option<usize>>,
    disabled: BTreeSet<(usize, usize)>,
    cost: u64,
    explored: u64,
    best: Option<ColoringSolution>,
    hit_limit: bool,
}

impl Solver<'_> {
    fn search(&mut self) {
        if self.hit_limit
            || self
                .best
                .as_ref()
                .is_some_and(|best| self.cost >= best.stitch_cost)
        {
            return;
        }
        self.explored += 1;
        if self.explored > self.problem.max_search_states {
            self.hit_limit = true;
            return;
        }

        let Some(node) = self.next_node() else {
            let selected_stitches = self
                .disabled
                .iter()
                .filter_map(|edge| self.stitch_by_edge.get(edge).cloned())
                .collect();
            self.best = Some(ColoringSolution {
                colors: self.colors.iter().map(|color| color.unwrap()).collect(),
                selected_stitches,
                stitch_cost: self.cost,
                explored_states: 0,
            });
            return;
        };

        let candidates = self.allowed(node);
        for color in candidates {
            let clashes: Vec<_> = self
                .neighbors(node)
                .filter(|&neighbor| self.colors[neighbor] == Some(color))
                .map(|neighbor| edge(node, neighbor))
                .collect();
            if clashes
                .iter()
                .any(|pair| !self.stitch_by_edge.contains_key(pair))
            {
                continue;
            }
            let newly_disabled: Vec<_> = clashes
                .into_iter()
                .filter(|pair| !self.disabled.contains(pair))
                .collect();
            let added_cost: u64 = newly_disabled
                .iter()
                .map(|pair| u64::from(self.stitch_by_edge[pair].cost))
                .sum();
            if self
                .best
                .as_ref()
                .is_some_and(|best| self.cost + added_cost >= best.stitch_cost)
            {
                continue;
            }
            self.colors[node] = Some(color);
            self.cost += added_cost;
            for pair in &newly_disabled {
                self.disabled.insert(*pair);
            }
            self.search();
            for pair in &newly_disabled {
                self.disabled.remove(pair);
            }
            self.cost -= added_cost;
            self.colors[node] = None;
        }
    }

    fn next_node(&self) -> Option<usize> {
        (0..self.problem.node_count)
            .filter(|&node| self.colors[node].is_none())
            .max_by_key(|&node| {
                let saturation = self
                    .neighbors(node)
                    .filter_map(|neighbor| self.colors[neighbor])
                    .collect::<BTreeSet<_>>()
                    .len();
                let degree = self.neighbors(node).count();
                (saturation, degree, std::cmp::Reverse(node))
            })
    }

    fn neighbors(&self, node: usize) -> impl Iterator<Item = usize> + '_ {
        self.conflicts.iter().filter_map(move |&(a, b)| {
            if self.disabled.contains(&(a, b)) {
                None
            } else if a == node {
                Some(b)
            } else if b == node {
                Some(a)
            } else {
                None
            }
        })
    }

    fn allowed(&self, node: usize) -> Vec<usize> {
        if let Some(&color) = self.problem.precolors.get(&node) {
            return vec![color];
        }
        let mut colors: Vec<_> = self.problem.allowed_colors.get(&node).map_or_else(
            || (0..self.problem.color_count).collect(),
            |set| set.iter().copied().collect(),
        );
        colors.sort_unstable();
        colors
    }

    fn partial_consistent(&self) -> bool {
        self.conflicts.iter().all(|&(a, b)| {
            self.colors[a].is_none()
                || self.colors[b].is_none()
                || self.colors[a] != self.colors[b]
                || self.disabled.contains(&(a, b))
        })
    }
}

fn validate(problem: &ColoringProblem) -> Result<(), ColoringError> {
    if problem.color_count == 0 {
        return Err(ColoringError::Invalid(
            "color_count must be positive".into(),
        ));
    }
    if problem.max_search_states == 0 {
        return Err(ColoringError::Invalid(
            "max_search_states must be positive".into(),
        ));
    }
    for &(a, b) in &problem.conflicts {
        if a >= problem.node_count || b >= problem.node_count || a == b {
            return Err(ColoringError::Invalid(format!(
                "invalid conflict ({a}, {b})"
            )));
        }
    }
    for (&node, &color) in &problem.precolors {
        if node >= problem.node_count || color >= problem.color_count {
            return Err(ColoringError::Invalid(format!(
                "invalid precolor {node}={color}"
            )));
        }
        if problem
            .allowed_colors
            .get(&node)
            .is_some_and(|allowed| !allowed.contains(&color))
        {
            return Err(ColoringError::Invalid(format!(
                "precolor {node}={color} is outside its allowed-color set"
            )));
        }
    }
    for (&node, allowed) in &problem.allowed_colors {
        if node >= problem.node_count
            || allowed.is_empty()
            || allowed.iter().any(|&c| c >= problem.color_count)
        {
            return Err(ColoringError::Invalid(format!(
                "invalid allowed colors for node {node}"
            )));
        }
    }
    let conflicts: BTreeSet<_> = problem
        .conflicts
        .iter()
        .copied()
        .map(|(a, b)| edge(a, b))
        .collect();
    let mut stitches = BTreeSet::new();
    for stitch in &problem.stitches {
        let pair = edge(stitch.a, stitch.b);
        if !conflicts.contains(&pair) || !stitches.insert(pair) {
            return Err(ColoringError::Invalid(format!(
                "stitch ({}, {}) is not a unique conflict edge",
                stitch.a, stitch.b
            )));
        }
    }
    Ok(())
}

fn edge(a: usize, b: usize) -> (usize, usize) {
    (a.min(b), a.max(b))
}

fn precolor_witness(problem: &ColoringProblem) -> Vec<usize> {
    for &(a, b) in &problem.conflicts {
        if problem.precolors.get(&a) == problem.precolors.get(&b)
            && problem.precolors.contains_key(&a)
        {
            return vec![a, b];
        }
    }
    problem.precolors.keys().copied().collect()
}

fn minimal_witness(problem: &ColoringProblem) -> Vec<usize> {
    if problem.color_count == 2 {
        if let Some(cycle) = odd_cycle(problem) {
            return cycle;
        }
    }
    // Build adjacency for unsat core extraction
    let stitch_edges: BTreeSet<_> = problem.stitches.iter().map(|s| edge(s.a, s.b)).collect();
    let mut adj = vec![Vec::new(); problem.node_count];
    for &(a, b) in &problem.conflicts {
        let pair = edge(a, b);
        if !stitch_edges.contains(&pair) {
            adj[a].push(b);
            adj[b].push(a);
        }
    }
    let full_set: Vec<usize> = problem
        .conflicts
        .iter()
        .flat_map(|&(a, b)| [a, b])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    minimal_unsat_core(&full_set, &adj, problem.color_count)
}

fn odd_cycle(problem: &ColoringProblem) -> Option<Vec<usize>> {
    let mut adjacency = vec![Vec::new(); problem.node_count];
    let stitch_edges: BTreeSet<_> = problem.stitches.iter().map(|s| edge(s.a, s.b)).collect();
    for &(a, b) in &problem.conflicts {
        if stitch_edges.contains(&edge(a, b)) {
            continue;
        }
        adjacency[a].push(b);
        adjacency[b].push(a);
    }
    for neighbors in &mut adjacency {
        neighbors.sort_unstable();
        neighbors.dedup();
    }
    let mut parity = vec![None; problem.node_count];
    let mut parent = vec![None; problem.node_count];
    for root in 0..problem.node_count {
        if parity[root].is_some() {
            continue;
        }
        parity[root] = Some(0_u8);
        let mut queue = VecDeque::from([root]);
        while let Some(node) = queue.pop_front() {
            for &neighbor in &adjacency[node] {
                if parity[neighbor].is_none() {
                    parity[neighbor] = Some(1 - parity[node].unwrap());
                    parent[neighbor] = Some(node);
                    queue.push_back(neighbor);
                } else if parity[neighbor] == parity[node] {
                    return Some(reconstruct_cycle(node, neighbor, &parent));
                }
            }
        }
    }
    None
}

fn reconstruct_cycle(mut a: usize, mut b: usize, parent: &[Option<usize>]) -> Vec<usize> {
    let mut path_a = vec![a];
    let mut path_b = vec![b];
    let ancestors_a: BTreeMap<_, _> = std::iter::successors(Some(a), |&node| parent[node])
        .enumerate()
        .map(|(depth, node)| (node, depth))
        .collect();
    while !ancestors_a.contains_key(&b) {
        b = parent[b].unwrap();
        path_b.push(b);
    }
    let lca = b;
    while a != lca {
        a = parent[a].unwrap();
        path_a.push(a);
    }
    path_b.pop();
    path_b.reverse();
    path_a.extend(path_b);
    path_a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crown_graph_defeats_sequential_greedy_but_solver_finds_two_colors() {
        // Crown graph K3,3 minus matching in adversarial a1,b1,a2,b2,a3,b3 order.
        let conflicts = vec![(0, 3), (0, 5), (2, 1), (2, 5), (4, 1), (4, 3)];
        let solution = solve_coloring(&ColoringProblem::new(6, 2, conflicts.clone())).unwrap();
        for (a, b) in conflicts {
            assert_ne!(solution.colors[a], solution.colors[b]);
        }
    }

    #[test]
    fn odd_cycle_has_a_constructive_witness() {
        let error =
            solve_coloring(&ColoringProblem::new(3, 2, vec![(0, 1), (1, 2), (2, 0)])).unwrap_err();
        let ColoringError::Uncolorable { witness } = error else {
            panic!("wrong error")
        };
        assert_eq!(witness.len(), 3);
    }

    #[test]
    fn precolors_allowed_sets_stitches_and_limits_are_enforced() {
        let mut problem = ColoringProblem::new(3, 2, vec![(0, 1), (1, 2), (2, 0)]);
        problem.precolors.insert(0, 0);
        problem.allowed_colors.insert(1, BTreeSet::from([1]));
        problem.stitches.push(StitchCandidate {
            a: 0,
            b: 2,
            cost: 7,
        });
        let solution = solve_coloring(&problem).unwrap();
        assert_eq!(solution.stitch_cost, 7);
        assert_eq!(solution.selected_stitches.len(), 1);

        problem.max_nodes = 2;
        assert!(matches!(
            solve_coloring(&problem),
            Err(ColoringError::CapacityExceeded { .. })
        ));
    }

    #[test]
    fn result_is_deterministic_under_edge_permutation() {
        let edges = vec![(0, 1), (1, 2), (2, 3), (3, 0)];
        let mut reversed = edges.clone();
        reversed.reverse();
        let a = solve_coloring(&ColoringProblem::new(4, 2, edges)).unwrap();
        let b = solve_coloring(&ColoringProblem::new(4, 2, reversed)).unwrap();
        assert_eq!(a.colors, b.colors);
    }

    #[test]
    fn same_color_precolors_force_and_charge_their_stitch() {
        let mut problem = ColoringProblem::new(2, 2, vec![(0, 1)]);
        problem.precolors.insert(0, 1);
        problem.precolors.insert(1, 1);
        problem.stitches.push(StitchCandidate {
            a: 0,
            b: 1,
            cost: 9,
        });
        let solution = solve_coloring(&problem).unwrap();
        assert_eq!(solution.stitch_cost, 9);
        assert_eq!(solution.selected_stitches, problem.stitches);
    }

    #[test]
    fn incumbent_before_search_limit_is_not_returned_as_optimal() {
        let mut problem = ColoringProblem::new(2, 2, vec![(0, 1)]);
        problem.precolors.insert(0, 0);
        problem.stitches.push(StitchCandidate {
            a: 0,
            b: 1,
            cost: 9,
        });
        problem.max_search_states = 2;
        assert!(matches!(
            solve_coloring(&problem),
            Err(ColoringError::SearchLimit { .. })
        ));
    }

    #[test]
    fn ac3_detects_domain_wipeout() {
        // Node 0 forced to color 0, node 1 forced to color 0, conflict (0,1)
        // AC-3 should detect this is uncolorable
        let mut adj = vec![vec![1], vec![0]];
        let mut domains = vec![BTreeSet::from([0]), BTreeSet::from([0])];
        assert!(ac3_preprocess(&adj, &mut domains).is_err());
    }

    #[test]
    fn ac3_reduces_domains() {
        // 3-node path: 0-1-2, 2 colors. Node 0 forced to {0}.
        // AC-3 should remove 0 from domain[1], then remove 1 from domain[2].
        let adj = vec![vec![1], vec![0, 2], vec![1]];
        let mut domains = vec![
            BTreeSet::from([0]),
            BTreeSet::from([0, 1]),
            BTreeSet::from([0, 1]),
        ];
        ac3_preprocess(&adj, &mut domains).unwrap();
        assert_eq!(domains[1], BTreeSet::from([1]));
        assert_eq!(domains[2], BTreeSet::from([0]));
    }

    #[test]
    fn minimal_unsat_core_extracts_small_witness() {
        // K4 with 3 colors is uncolorable. minimal_unsat_core should find
        // a 4-node clique (the whole thing, since K4 is the minimal uncolorable).
        let error = solve_coloring(&ColoringProblem::new(
            4,
            3,
            vec![(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)],
        ))
        .unwrap_err();
        let ColoringError::Uncolorable { witness } = error else {
            panic!("wrong error")
        };
        assert!(witness.len() <= 4);
    }
}
