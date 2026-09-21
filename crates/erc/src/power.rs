//! Resistive networks extracted from layout, and the DC solve over them.
//!
//! [`PowerGrid`] serves two questions with one type: the **supply grid** (every
//! polygon on a declared supply net, driven by pads and loaded by devices,
//! solved by [`solve_into`]) and a **per-net network** (one net's polygons
//! tapped at each device attach point, probed by [`effective_resistance_into`],
//! stored CSR-per-net in [`NetNetworks`]).
//!
//! A polygon becomes a chain of resistors along its long bounding-box axis,
//! tapped wherever something connects to it. Segment resistance is the layer's
//! sheet resistance times `∫ ds / w(s)` over [`ChainProfile`], where `w(s)` is
//! the metal a vertical cut at `s` actually finds — only the *axis* is a
//! bounding-box question, never the width. Every shape also carries a tap at its
//! own centre, so a shape nothing connects to still has a node and an
//! unreachable island is reported rather than silently absent. A shape's nodes
//! come out ascending along its chain, which is what makes the segment between
//! two taps one adjacent pair.
//!
//! The model is one-dimensional: current is taken to have spread across the
//! whole cross-section at every point along the chain, so transverse resistance
//! *within* a cut is not modelled. A 2-D mesh per polygon is the upgrade.

use crate::centre;
use crate::facts::IntentMap;
use gpurify_core::connectivity::{components_into, ComponentLabel};
use gpurify_core::ops::Point;
use gpurify_core::{Bbox, GeometryStore, LayerId, PolyId};
use gpurify_ingest::deck::{Connectivity, ProcessStack};
use gpurify_ingest::intent::SupplyRole;
use gpurify_topology::net::{intra_layer_edges_into, via_edges_into};
use gpurify_topology::{DeviceTable, NetId, NetTable};
use gpurify_units::{prefix, Current, Dbu, Grid, Qty, Resistance, Voltage, MAX_ABS_DBU};
use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// Microamps through one ohm per millivolt across it.
///
/// [`PowerGrid`] is millivolts, microamps and ohms, so the conductance a
/// Laplacian in those units wants is `1000 / R` and not `1 / R`. Getting it
/// wrong scales every drop by a million and still satisfies every law-shaped
/// test, because Kirchhoff and linearity are both scale-invariant.
const UA_PER_MV_OHM: f64 = 1_000.0;

/// A node held at a fixed potential has no unknown index.
///
/// A sentinel rather than `Option<u32>`: the assembly loop clamps on it instead
/// of branching.
const NOT_AN_UNKNOWN: u32 = u32::MAX;

/// Why a network could not be built or solved.
///
/// Fail closed, every variant: a grid that cannot be solved produces this, not
/// a zero-drop solution that reads as a clean IR-drop result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PowerError {
    /// No node is held at a fixed voltage, so the system is singular: any
    /// constant added to every node voltage is also a solution.
    #[error("the grid has no supply pad to anchor the solve")]
    Unanchored,
    /// A connected part of the grid that no pad reaches. Its voltages are
    /// undetermined for the same reason, and reporting the rest as clean would
    /// hide however much of the design sits in that island.
    #[error("node {0} is in an island no supply pad reaches")]
    UnanchoredIsland(u32),
    /// A zero, negative or non-finite resistance. Zero is the dangerous one: it
    /// short-circuits two nodes and silently removes a drop the design has.
    #[error("edge {0} does not have a positive finite resistance")]
    BadResistance(u32),
    /// The process stack has no sheet resistance for a layer carrying current.
    /// A default would be a guess, and a guessed conductor is a guessed verdict.
    #[error("layer {0:?} carries current but the process stack gives it no sheet resistance")]
    NoSheetResistance(LayerId),
    #[error("the solve did not reach the requested tolerance in {0} iterations")]
    NotConverged(u32),
    /// A load current, pad voltage or geometry produced a non-finite value.
    /// A `NaN` compares false against every limit and therefore passes it.
    #[error("node {0} carries a non-finite electrical value")]
    NotFinite(u32),
}

/// The process data an extraction needs, borrowed.
#[derive(Debug, Clone, Copy)]
pub struct Process<'a> {
    /// The layout's manufacturing grid. Needed only where a physical length
    /// leaves the model — current density is amps per metre, not amps per
    /// database unit.
    pub grid: Grid,
    pub stack: &'a ProcessStack,
    /// Which layers conduct, and which cuts join them. A via is an edge with a
    /// resistance, not a merge.
    pub connectivity: &'a Connectivity,
}

/// What kind of conductor an edge models.
///
/// The two differ in how their limit is stated: metal by current per unit
/// width, a via by current per cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    Metal,
    Via { cuts: u32 },
}

/// A resistive network over layout, `SoA`.
///
/// Fixed-voltage nodes are **not** an `Option` column: they are a separate
/// ascending list of node indices, so the solve iterates the pads that exist.
#[derive(Debug, Default)]
pub struct PowerGrid {
    /// The net each node belongs to. Several nodes share a net — that is the
    /// point, a net is not an equipotential once it has resistance.
    pub node_net: Vec<NetId>,
    /// Where the node is, for reporting a violation a viewer can navigate to.
    pub node_at: Vec<Point>,
    /// The polygon the node taps, and its layer. Reported as the violating
    /// shape; the layer is carried rather than looked up so a rule reading a
    /// solution needs no `GeometryStore` at all.
    pub node_poly: Vec<PolyId>,
    pub node_layer: Vec<LayerId>,
    /// The voltage this node would sit at with no interconnect loss — its
    /// domain's nominal. The reference every drop is measured from.
    pub node_nominal: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Current drawn at this node. Positive draws from the grid, negative
    /// injects — a ground node's load is negative by that convention.
    pub node_load: Vec<Qty<Current, { prefix::MICRO }>>,

    /// Nodes held at a fixed voltage: the supply pads. Ascending, so the
    /// elimination that removes them from the unknowns is a merge, not a
    /// search. Existence-based — a node absent here is an unknown.
    pub source_node: Vec<u32>,
    pub source_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,

    pub edge_from: Vec<u32>,
    pub edge_to: Vec<u32>,
    pub edge_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
    /// Conductor width and length of the segment, exact. Width is the
    /// denominator of a current density; length is the `L` of a Blech product.
    pub edge_width: Vec<Dbu>,
    pub edge_length: Vec<Dbu>,
    /// The layer the segment lies on, so a per-layer limit can be applied
    /// without re-deriving it from the endpoints.
    pub edge_layer: Vec<LayerId>,
    pub edge_kind: Vec<EdgeKind>,
}

impl PowerGrid {
    pub fn node_count(&self) -> usize {
        // The columns are public and pushed one at a time, so "six values in
        // step" is a caller invariant with no constructor to enforce it.
        debug_assert_eq!(
            self.node_at.len(),
            self.node_net.len(),
            "one point per node"
        );
        debug_assert_eq!(
            self.node_poly.len(),
            self.node_net.len(),
            "one polygon per node"
        );
        debug_assert_eq!(
            self.node_layer.len(),
            self.node_net.len(),
            "one layer per node"
        );
        debug_assert_eq!(
            self.node_nominal.len(),
            self.node_net.len(),
            "one nominal per node"
        );
        debug_assert_eq!(
            self.node_load.len(),
            self.node_net.len(),
            "one load per node"
        );
        self.node_net.len()
    }

    pub fn edge_count(&self) -> usize {
        debug_assert_eq!(self.edge_to.len(), self.edge_from.len(), "one end per edge");
        debug_assert_eq!(
            self.edge_resistance.len(),
            self.edge_from.len(),
            "one resistance per edge"
        );
        debug_assert_eq!(
            self.edge_width.len(),
            self.edge_from.len(),
            "one width per edge"
        );
        debug_assert_eq!(
            self.edge_length.len(),
            self.edge_from.len(),
            "one length per edge"
        );
        debug_assert_eq!(
            self.edge_layer.len(),
            self.edge_from.len(),
            "one layer per edge"
        );
        debug_assert_eq!(
            self.edge_kind.len(),
            self.edge_from.len(),
            "one kind per edge"
        );
        self.edge_from.len()
    }

    pub fn is_empty(&self) -> bool {
        self.node_count() == 0
    }

    /// The fixed voltage at a node, or `None` when it is an unknown.
    pub fn fixed_voltage(&self, node: u32) -> Option<Qty<Voltage, { prefix::MILLI }>> {
        debug_assert_eq!(
            self.source_voltage.len(),
            self.source_node.len(),
            "one voltage per pad"
        );
        // A binary search over an unsorted column silently reports a pad as an
        // unknown, which is a node the solve then moves off its boundary.
        debug_assert!(
            self.source_node.windows(2).all(|w| w[0] < w[1]),
            "the pad column is ascending and names each node once"
        );
        let row = self.source_node.binary_search(&node).ok()?;
        Some(self.source_voltage[row])
    }
}

/// One net's resistor network, per net, CSR.
///
/// Existence-based twice over: a net with fewer than two terminals has no row,
/// and a node that is not a terminal is simply absent from `terminal`.
#[derive(Debug, Default)]
pub struct NetNetworks {
    /// The net each row belongs to, ascending. Binary search for the reverse
    /// lookup.
    pub net: Vec<NetId>,

    /// `node_start[r] .. node_start[r + 1]` indexes the node columns.
    pub node_start: Vec<u32>,
    pub node_at: Vec<Point>,
    pub node_poly: Vec<PolyId>,

    /// `terminal_start[r] .. terminal_start[r + 1]` indexes `terminal`, whose
    /// values are node indices *within the row*. Effective resistance is
    /// reported between these and no others: a probe between two arbitrary
    /// interior taps is a number nothing in the design cares about.
    pub terminal_start: Vec<u32>,
    pub terminal: Vec<u32>,

    /// `edge_start[r] .. edge_start[r + 1]` indexes the edge columns. `from`
    /// and `to` are node indices within the row.
    pub edge_start: Vec<u32>,
    pub edge_from: Vec<u32>,
    pub edge_to: Vec<u32>,
    pub edge_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
}

impl NetNetworks {
    pub fn len(&self) -> usize {
        // `Default` has no offset columns at all, so the `rows + 1` shape is
        // asserted only once there is a row.
        debug_assert!(
            self.net.is_empty() || self.node_start.len() == self.net.len() + 1,
            "one node offset per row plus the end"
        );
        debug_assert!(
            self.net.is_empty() || self.terminal_start.len() == self.net.len() + 1,
            "one terminal offset per row plus the end"
        );
        debug_assert!(
            self.net.is_empty() || self.edge_start.len() == self.net.len() + 1,
            "one edge offset per row plus the end"
        );
        self.net.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The row index for a net, or `None` when the net has fewer than two
    /// terminals and therefore no network.
    pub fn row_of(&self, net: NetId) -> Option<u32> {
        debug_assert!(
            self.net.windows(2).all(|w| w[0] < w[1]),
            "the net column is ascending and names each net once"
        );
        let row = self.net.binary_search(&net).ok()?;
        Some(u32::try_from(row).expect("a row index is a u32"))
    }

    /// One row's nodes: position and tapped polygon, parallel.
    pub fn nodes_of(&self, row: u32) -> (&[Point], &[PolyId]) {
        debug_assert_eq!(
            self.node_poly.len(),
            self.node_at.len(),
            "a point column and a polygon column arrive parallel"
        );
        let (from, to) = csr_run(&self.node_start, row);
        (&self.node_at[from..to], &self.node_poly[from..to])
    }

    /// One row's terminal node indices, ascending.
    pub fn terminals_of(&self, row: u32) -> &[u32] {
        let (from, to) = csr_run(&self.terminal_start, row);
        &self.terminal[from..to]
    }

    /// One row's edges: endpoints and resistance, parallel.
    pub fn edges_of(&self, row: u32) -> (&[u32], &[u32], &[Qty<Resistance, { prefix::BASE }>]) {
        debug_assert_eq!(self.edge_to.len(), self.edge_from.len(), "one end per edge");
        debug_assert_eq!(
            self.edge_resistance.len(),
            self.edge_from.len(),
            "one resistance per edge"
        );
        let (from, to) = csr_run(&self.edge_start, row);
        (
            &self.edge_from[from..to],
            &self.edge_to[from..to],
            &self.edge_resistance[from..to],
        )
    }
}

/// One row's run in a CSR offset column.
///
/// Fail closed: a row past the table panics in **every** profile. Clamping would
/// make "carries nothing" and "does not exist" read the same, and a probe that
/// confuses them reports a net clean that it never measured.
fn csr_run(start: &[u32], row: u32) -> (usize, usize) {
    let (from, to) = (
        start[row as usize] as usize,
        start[row as usize + 1] as usize,
    );
    debug_assert!(from <= to, "a CSR run runs backwards");
    (from, to)
}

/// How hard the solver tries.
///
/// Both fields matter to a verdict, so neither is a hidden constant: a loose
/// tolerance under-reports drop, and a cap hit is [`PowerError::NotConverged`]
/// rather than a partial answer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SolveConfig {
    /// Stop when the residual falls to this fraction of the initial residual.
    pub relative_tolerance: f64,
    pub max_iterations: u32,
}

impl Default for SolveConfig {
    /// Tight enough that the tolerance is far below any limit a deck states, so
    /// a verdict never turns on it.
    fn default() -> Self {
        Self {
            relative_tolerance: 1e-10,
            max_iterations: 20_000,
        }
    }
}

/// The solved state of a [`PowerGrid`], `SoA` and parallel to it.
///
/// Row `i` of `node_voltage` is node `i` of the grid; row `i` of
/// `branch_current` is edge `i`. That correspondence is the interface.
#[derive(Debug, Default)]
pub struct PowerSolution {
    pub node_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Nominal minus solved, so a positive drop is a loss.
    pub node_drop: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Positive is from `edge_from` towards `edge_to`.
    pub branch_current: Vec<Qty<Current, { prefix::MICRO }>>,
    pub iterations: u32,
    pub relative_residual: f64,
}

impl PowerSolution {
    /// True when every value is finite and the columns match the grid.
    ///
    /// The precondition of every rule that reads a solution. A `NaN` voltage
    /// compares false against every limit and therefore passes it.
    pub fn is_consistent_with(&self, grid: &PowerGrid) -> bool {
        // Each loop runs over its own column's length, so a column shorter than
        // the grid cannot make one of them read past its own end.
        let mut finite = true;
        for i in 0..self.node_voltage.len() {
            finite &= self.node_voltage[i].is_finite();
        }
        for i in 0..self.node_drop.len() {
            finite &= self.node_drop[i].is_finite();
        }
        for i in 0..self.branch_current.len() {
            finite &= self.branch_current[i].is_finite();
        }

        (self.node_voltage.len() == grid.node_count())
            & (self.node_drop.len() == grid.node_count())
            & (self.branch_current.len() == grid.edge_count())
            & finite
            & self.relative_residual.is_finite()
    }
}

/// The linear-solve workspace.
///
/// [`solve_into`] uses conjugate gradients preconditioned by an **incomplete
/// Cholesky factorisation with zero fill**. Once the pads are eliminated the
/// matrix is a symmetric positive-definite M-matrix, which is the class IC(0)
/// is guaranteed to exist for — so a breakdown in [`factorise_into`] is a
/// rounding failure, and it falls back to the diagonal rather than to no
/// answer. Zero fill keeps the sparsity pattern of the matrix exactly, so the
/// solve's memory stays a function of the edge count.
#[derive(Debug, Default)]
pub struct SolveScratch {
    /// The reduced Laplacian in CSR: `row_start`, column indices, values.
    row_start: Vec<u32>,
    col: Vec<u32>,
    value: Vec<f64>,
    /// Right-hand side: injected current plus the pad contributions the
    /// elimination moved across.
    rhs: Vec<f64>,
    /// Conjugate-gradient state: solution, residual, search direction, and the
    /// mat-vec product. One `f64` column each, of the unknown count.
    x: Vec<f64>,
    r: Vec<f64>,
    p: Vec<f64>,
    ap: Vec<f64>,
    /// Diagonal preconditioner, as reciprocals so the inner loop multiplies.
    /// Used when the incomplete factorisation below breaks down, which on a
    /// grid Laplacian it should never do.
    inv_diag: Vec<f64>,
    /// The incomplete Cholesky factor, zero fill: the strictly lower triangle
    /// in CSR with each row's columns ascending and merged, plus the factor's
    /// own diagonal. Zero fill is the point — `l_col` holds the sparsity
    /// pattern of the matrix and nothing else, so the factor costs what the
    /// matrix costs and a long rail cannot fill it in.
    l_start: Vec<u32>,
    l_col: Vec<u32>,
    l_val: Vec<f64>,
    l_diag: Vec<f64>,
    /// One row's lower entries, staged for the sort that merges them.
    row_stage: Vec<(u32, f64)>,
    /// The preconditioned residual, `M⁻¹ r`. A separate column from `r`: the
    /// conjugate-gradient recurrence reads both in the same expression.
    z: Vec<f64>,
    /// Unknown index of each node, and its inverse. A pad has no unknown index.
    unknown_of_node: Vec<u32>,
    node_of_unknown: Vec<u32>,

    /// Assembly workspace: a per-row write cursor and a diagonal accumulator,
    /// both carrying one slot past the last row so a pad endpoint's share lands
    /// somewhere the fill loop can clamp to instead of branching around.
    cursor: Vec<u32>,
    diag: Vec<f64>,
    /// The edge list in *unknown* space, which is what [`assemble_into`] reads.
    branch: Vec<(u32, u32, f64)>,

    /// Connectivity workspace: the edge list as bare pairs, the component label
    /// of each node, and the two per-node boolean columns `solve_into` marks —
    /// which components a pad reaches, and which nodes are pads.
    pairs: Vec<(u32, u32)>,
    labels: Vec<ComponentLabel>,
    reached: Vec<bool>,
    is_pad: Vec<bool>,

    /// Probe workspace: the graph the Kron elimination edits, the reduced
    /// Laplacian it leaves over the terminals, and the dense solve over that.
    elim: ElimGraph,
    /// The reduced Laplacian, `k × k` row-major over the row's terminals.
    dense: Vec<f64>,
    /// One connected component of it, grounded, and that matrix's inverse.
    local: Vec<f64>,
    inverse: Vec<f64>,
    /// Effective resistance between terminal `i` and terminal `j` of the row,
    /// `k × k`. The pair loop reads it; `k` is the *terminal* count, which is
    /// what the Kron elimination buys — the tap count no longer enters.
    probe: Vec<f64>,
    /// Which terminal of the row a node is, or [`NONE`] for an interior tap.
    terminal_of_node: Vec<u32>,
    /// The terminals of one component, ascending.
    group: Vec<u32>,
}

impl SolveScratch {
    /// Drop every buffer's capacity.
    pub fn shrink(&mut self) {
        // Accepted equivalent-mutant site:
        // every field is private and neither length nor capacity is exposed, so
        // no test can tell this body from an empty one.
        *self = Self::default();
    }
}

/// The end of a linked list, and "this node is not a terminal".
///
/// Same value as [`NOT_AN_UNKNOWN`], deliberately a second name: that one is a
/// statement about the solve, this one about a list.
const NONE: u32 = u32::MAX;

/// The graph a Kron elimination edits in place.
///
/// A linked pool rather than CSR: a vertex's incidence list grows as its
/// neighbours are eliminated, so the run cannot be sized in advance. Half-edge
/// pool: edge `e` occupies slots `2e` and `2e + 1`, so a half-edge's twin is
/// `h ^ 1` and no back-pointer is stored. A killed half-edge keeps its link and
/// carries a zero conductance; [`ElimGraph::refresh`] unlinks it on the next
/// walk, so removal never searches a list backwards.
#[derive(Debug, Default)]
struct ElimGraph {
    /// Head half-edge of each vertex's list, or [`NONE`].
    head: Vec<u32>,
    alive: Vec<bool>,
    next: Vec<u32>,
    dst: Vec<u32>,
    /// Conductance of each half-edge. Zero means dead — a live conductance is
    /// positive by [`effective_resistance_into`]'s entry check, so zero is a
    /// value no live edge can take and needs no parallel flag column.
    g: Vec<f64>,
    /// Sparse accumulator over vertices: `slot[v]` is meaningful only where
    /// `stamp[v] == epoch`, so clearing it between walks is one increment.
    slot: Vec<u32>,
    stamp: Vec<u32>,
    epoch: u32,
    /// The neighbours of the vertex being eliminated, deduplicated: parallel
    /// strands are summed here, once, rather than spreading fill twice.
    fringe: Vec<(u32, f64)>,
    /// Minimum-degree queue, `(degree, vertex)`, lazily invalidated. Ordering by
    /// the pair rather than the degree alone is what makes the elimination order
    /// — and therefore every rounding in it — a function of the network.
    queue: BinaryHeap<Reverse<(u32, u32)>>,
}

impl ElimGraph {
    /// Empty the graph and size it for `vertices`, keeping every allocation.
    fn reset(&mut self, vertices: usize) {
        self.head.clear();
        self.head.resize(vertices, NONE);
        self.alive.clear();
        self.alive.resize(vertices, true);
        self.next.clear();
        self.dst.clear();
        self.g.clear();
        self.slot.clear();
        self.slot.resize(vertices, NONE);
        self.stamp.clear();
        self.stamp.resize(vertices, 0);
        self.epoch = 0;
        self.fringe.clear();
        self.queue.clear();
    }

    /// Add a conductance between two distinct live vertices.
    fn link(&mut self, a: u32, b: u32, g: f64) {
        debug_assert!(a != b, "a self loop carries no current and loads no node");
        debug_assert!(g > 0.0 && g.is_finite(), "a link is a positive conductance");
        let h = u32::try_from(self.next.len()).expect("a half-edge index is a u32");
        self.next.push(self.head[a as usize]);
        self.dst.push(b);
        self.g.push(g);
        self.head[a as usize] = h;
        self.next.push(self.head[b as usize]);
        self.dst.push(a);
        self.g.push(g);
        self.head[b as usize] = h + 1;
        debug_assert_eq!(h ^ 1, h + 1, "an edge opens on an even half-edge");
    }

    /// Unlink every dead half-edge of one vertex, and return its live degree.
    fn refresh(&mut self, v: u32) -> u32 {
        let mut live = 0u32;
        let mut prev = NONE;
        let mut h = self.head[v as usize];
        while h != NONE {
            let after = self.next[h as usize];
            let dead = !(self.g[h as usize] > 0.0)
                || !self.alive[self.dst[h as usize] as usize]
                || self.dst[h as usize] == v;
            if dead {
                if prev == NONE {
                    self.head[v as usize] = after;
                } else {
                    self.next[prev as usize] = after;
                }
            } else {
                live += 1;
                prev = h;
            }
            h = after;
        }
        live
    }

    /// Kron-eliminate one vertex: its neighbours inherit its conductance.
    ///
    /// Every pair of neighbours `(i, j)` gains `g_i g_j / d`, where `d` is the
    /// vertex's total conductance — the Schur complement of the Laplacian on
    /// that row, which leaves every effective resistance between the survivors
    /// exactly unchanged. Returns the changed neighbours in `self.fringe`.
    fn eliminate(&mut self, v: u32) {
        debug_assert!(self.alive[v as usize], "a vertex is eliminated once");
        self.epoch += 1;
        let epoch = self.epoch;
        self.fringe.clear();

        // Gather, deduplicate and unhook in one walk over the incidence list.
        let mut h = self.head[v as usize];
        while h != NONE {
            let u = self.dst[h as usize];
            let w = self.g[h as usize];
            if w > 0.0 && self.alive[u as usize] && u != v {
                if self.stamp[u as usize] == epoch {
                    self.fringe[self.slot[u as usize] as usize].1 += w;
                } else {
                    self.stamp[u as usize] = epoch;
                    self.slot[u as usize] =
                        u32::try_from(self.fringe.len()).expect("a fringe index is a u32");
                    self.fringe.push((u, w));
                }
            }
            // The vertex is leaving, so both halves of every incident edge do.
            self.g[h as usize] = 0.0;
            self.g[(h ^ 1) as usize] = 0.0;
            h = self.next[h as usize];
        }
        self.alive[v as usize] = false;
        self.head[v as usize] = NONE;

        // Folded left in ascending index order, so the total a vertex spreads is
        // the same bits on every run.
        let mut total = 0.0f64;
        for i in 0..self.fringe.len() {
            total += self.fringe[i].1;
        }
        // A vertex with no live neighbour spreads nothing, and dividing by its
        // zero total would be the `NaN` that reaches every probe after it.
        if !(total > 0.0 && total.is_finite()) {
            return;
        }

        for i in 0..self.fringe.len() {
            let (a, ga) = self.fringe[i];
            // Index `a`'s live neighbours, so the pair loop below adds into an
            // edge that already exists instead of growing a parallel strand per
            // elimination — which stops the pool growing quadratically.
            self.refresh(a);
            self.epoch += 1;
            let epoch = self.epoch;
            let mut h = self.head[a as usize];
            while h != NONE {
                let u = self.dst[h as usize];
                self.stamp[u as usize] = epoch;
                self.slot[u as usize] = h;
                h = self.next[h as usize];
            }
            for j in i + 1..self.fringe.len() {
                let (b, gb) = self.fringe[j];
                let delta = ga * gb / total;
                if self.stamp[b as usize] == epoch {
                    let e = self.slot[b as usize] as usize;
                    self.g[e] += delta;
                    self.g[e ^ 1] += delta;
                } else {
                    self.link(a, b, delta);
                }
            }
        }
    }
}

/// Invert a dense symmetric positive-definite matrix, by Cholesky.
///
/// `a` is `n × n` row-major and is consumed — the factor overwrites its lower
/// triangle. `out` is cleared and refilled with the `n × n` inverse.
///
/// `false` is the fail-closed exit: a grounded Laplacian of a connected
/// component is positive definite, so a pivot that is not positive and finite
/// means the numbers stopped being a network.
fn cholesky_inverse_into(a: &mut [f64], n: usize, out: &mut Vec<f64>) -> bool {
    debug_assert_eq!(a.len(), n * n, "a dense matrix is n by n");
    out.clear();
    out.resize(n * n, 0.0);

    for j in 0..n {
        let mut d = a[j * n + j];
        for k in 0..j {
            d -= a[j * n + k] * a[j * n + k];
        }
        if !(d > 0.0 && d.is_finite()) {
            return false;
        }
        let l = d.sqrt();
        a[j * n + j] = l;
        for i in j + 1..n {
            let mut s = a[i * n + j];
            for k in 0..j {
                s -= a[i * n + k] * a[j * n + k];
            }
            a[i * n + j] = s / l;
        }
    }

    // One forward and one back substitution per unit vector. The result is
    // symmetric, so writing it row-major and reading it either way agree.
    for c in 0..n {
        let row = &mut out[c * n..c * n + n];
        row[c] = 1.0;
        for i in 0..n {
            let mut y = row[i];
            for k in 0..i {
                y -= a[i * n + k] * row[k];
            }
            row[i] = y / a[i * n + i];
        }
        for i in (0..n).rev() {
            let mut x = row[i];
            for k in i + 1..n {
                x -= a[k * n + i] * row[k];
            }
            row[i] = x / a[i * n + i];
        }
    }
    true
}

/// One sparse mat-vec: `out[i]` is row `i` of the assembled matrix times `v`.
fn spmv(row_start: &[u32], col: &[u32], value: &[f64], v: &[f64], out: &mut [f64]) {
    debug_assert_eq!(
        row_start.len(),
        out.len() + 1,
        "one CSR offset per row plus the end"
    );
    debug_assert_eq!(col.len(), value.len(), "one column index per value");
    let used = row_start[out.len()] as usize;
    debug_assert!(used <= col.len(), "the CSR runs past its own columns");
    debug_assert!(
        col[..used].iter().all(|&c| (c as usize) < v.len()),
        "a CSR column names an unknown the vector does not have"
    );

    for (i, row) in out.iter_mut().enumerate() {
        let (from, to) = (row_start[i] as usize, row_start[i + 1] as usize);
        let mut acc = 0.0f64;
        for k in from..to {
            acc += value[k] * v[col[k] as usize];
        }
        *row = acc;
    }
}

/// The Euclidean norm of a residual, folded left in ascending index order.
///
/// The order is interface: it makes a converged-or-not verdict the same bits on
/// every run.
fn norm(v: &[f64]) -> f64 {
    let mut acc = 0.0f64;
    for &x in v {
        acc += x * x;
    }
    acc.sqrt()
}

/// Assemble a Laplacian into `scratch`'s CSR columns, and its inverse diagonal.
///
/// `scratch.branch` is `(unknown_a, unknown_b, conductance)` already in
/// *unknown* space, with [`NOT_AN_UNKNOWN`] naming an endpoint held at a fixed
/// potential. Such an endpoint still loads the diagonal — a pad is a
/// conductance to a boundary condition, not an open — but contributes no
/// off-diagonal, which is the elimination that leaves the system SPD.
///
/// Duplicate columns within a row are left duplicated: a multi-edge is two
/// conductances in parallel and a CSR mat-vec sums a row's entries, so merging
/// them by assignment is a bug.
fn assemble_into(scratch: &mut SolveScratch, unknowns: usize) {
    let width = u32::try_from(unknowns).expect("an unknown index is a u32");
    let SolveScratch {
        row_start,
        col,
        value,
        inv_diag,
        cursor,
        diag,
        branch,
        ..
    } = scratch;

    // Both carry one extra slot past the last row, which is where a pad
    // endpoint's contribution lands so the fill loop can clamp instead of
    // branch.
    cursor.clear();
    cursor.resize(unknowns + 1, 0);
    diag.clear();
    diag.resize(unknowns + 1, 0.0);

    // Pass one: how many off-diagonals each row carries. A pad endpoint clamps
    // into the bin past the last row and `both` is zero for it.
    for &(a, b, _) in branch.iter() {
        let both = u32::from((a != NOT_AN_UNKNOWN) & (b != NOT_AN_UNKNOWN));
        cursor[a.min(width) as usize] += both;
        cursor[b.min(width) as usize] += both;
    }

    // Pass two: offsets.
    row_start.clear();
    row_start.reserve(unknowns + 1);
    let mut running = 0u32;
    for count in &cursor[..unknowns] {
        row_start.push(running);
        // The diagonal is slot zero of every row, so the row is never empty and
        // `inv_diag` reads one stride.
        running += 1 + count;
    }
    row_start.push(running);

    let nnz = running as usize;
    col.clear();
    // One slot past the last row: the bin a pad-ended edge's off-diagonal is
    // written into and never advances past, so the fill loop's store stays
    // unconditional.
    col.resize(nnz + 1, 0);
    value.clear();
    value.resize(nnz + 1, 0.0);
    for i in 0..unknowns {
        col[row_start[i] as usize] = u32::try_from(i).expect("an unknown index is a u32");
        cursor[i] = row_start[i] + 1;
    }
    cursor[unknowns] = running;

    // Pass three: the fill.
    for &(a, b, g) in branch.iter() {
        let (a_row, b_row) = (a.min(width) as usize, b.min(width) as usize);
        // Every incident edge loads the diagonal of whichever end is an
        // unknown; a pad end's share lands in the bin and is thrown away.
        diag[a_row] += g;
        diag[b_row] += g;

        // The off-diagonal pair exists only when both ends are unknowns. Always
        // store, conditionally advance: the index carries the decision, and the
        // slot a pad-ended edge writes to is the bin past the last row.
        let paired = (a != NOT_AN_UNKNOWN) & (b != NOT_AN_UNKNOWN);
        let both = usize::from(paired);
        let ka = both * cursor[a_row] as usize + (1 - both) * nnz;
        col[ka] = b;
        value[ka] = -g;
        cursor[a_row] += u32::from(paired);
        let kb = both * cursor[b_row] as usize + (1 - both) * nnz;
        col[kb] = a;
        value[kb] = -g;
        cursor[b_row] += u32::from(paired);
    }

    inv_diag.clear();
    inv_diag.reserve(unknowns);
    for i in 0..unknowns {
        debug_assert!(
            diag[i] > 0.0 && diag[i].is_finite(),
            "unknown {i} has no positive conductance to anything, so the row is singular"
        );
        value[row_start[i] as usize] = diag[i];
        inv_diag.push(1.0 / diag[i]);
    }

    debug_assert_eq!(inv_diag.len(), unknowns, "one reciprocal per unknown");
    debug_assert_eq!(
        row_start.len(),
        unknowns + 1,
        "one CSR offset per row plus the end"
    );
    debug_assert!(
        (0..unknowns).all(|i| cursor[i] == row_start[i + 1]),
        "a row was filled short of its counted length"
    );
}

/// Factor the assembled matrix incompletely, with zero fill.
///
/// Writes `scratch`'s `l_*` columns: the strictly lower triangle, each row's
/// columns ascending and its duplicates merged, plus the factor's diagonal.
///
/// An **empty** factor is the fail-closed exit, and the caller's signal to
/// precondition with the diagonal alone. Empty rather than a flag, because a
/// half-built factor is *not* positive definite and preconditioning with one
/// makes conjugate gradients diverge.
///
/// Duplicate columns are merged here and nowhere else: [`assemble_into`] leaves
/// a multi-edge as two entries because a mat-vec sums a row, but a
/// factorisation *indexes* into the row and would skip one of them.
fn factorise_into(scratch: &mut SolveScratch, unknowns: usize) {
    let SolveScratch {
        row_start,
        col,
        value,
        l_start,
        l_col,
        l_val,
        l_diag,
        row_stage,
        ..
    } = scratch;
    debug_assert_eq!(
        row_start.len(),
        unknowns + 1,
        "one CSR offset per row plus the end"
    );

    // Pass one: the pattern. One row at a time, so the sort is over that row's
    // own degree and never over the matrix.
    l_start.clear();
    l_start.reserve(unknowns + 1);
    l_col.clear();
    l_val.clear();
    l_diag.clear();
    l_diag.resize(unknowns, 0.0);
    l_start.push(0);
    for i in 0..unknowns {
        row_stage.clear();
        for k in row_start[i] as usize..row_start[i + 1] as usize {
            let c = col[k];
            if (c as usize) < i {
                row_stage.push((c, value[k]));
            }
        }
        row_stage.sort_unstable_by_key(|&(c, _)| c);
        // Merge the run of each column into one entry.
        for &(c, v) in row_stage.iter() {
            let fresh =
                l_col.len() == l_start[i] as usize || *l_col.last().expect("non-empty") != c;
            l_col.resize(l_col.len() + usize::from(fresh), c);
            l_val.resize(l_val.len() + usize::from(fresh), 0.0);
            *l_val.last_mut().expect("the resize above left an entry") += v;
        }
        l_start.push(u32::try_from(l_col.len()).expect("a factor entry is a u32"));
    }
    debug_assert_eq!(l_col.len(), l_val.len(), "one value per factor column");
    debug_assert!(
        (0..unknowns).all(|i| {
            let (from, to) = (l_start[i] as usize, l_start[i + 1] as usize);
            l_col[from..to].windows(2).all(|w| w[0] < w[1])
                && l_col[from..to].iter().all(|&c| (c as usize) < i)
        }),
        "a factor row is ascending, deduplicated and strictly lower"
    );

    // Pass two: the factorisation. Row `i` needs rows `0 ..= i - 1` finished, so
    // no reordering is legal. Each inner sparse dot is a two-pointer merge of
    // two ascending column lists, which is what the pass above sorted for.
    for i in 0..unknowns {
        let (from, to) = (l_start[i] as usize, l_start[i + 1] as usize);
        let mut d = value[row_start[i] as usize];
        for t in from..to {
            let j = l_col[t] as usize;
            let mut s = l_val[t];
            let (mut p, mut q) = (from, l_start[j] as usize);
            let q_end = l_start[j + 1] as usize;
            while p < t && q < q_end {
                let (cp, cq) = (l_col[p], l_col[q]);
                let hit = f64::from(u8::from(cp == cq));
                s -= l_val[p] * l_val[q] * hit;
                p += usize::from(cp <= cq);
                q += usize::from(cq <= cp);
            }
            let v = s / l_diag[j];
            l_val[t] = v;
            d -= v * v;
        }
        // Fail closed: throw the whole factor away rather than leave a partial
        // one behind, and let the diagonal preconditioner take the solve.
        if !(d > 0.0 && d.is_finite()) {
            l_start.clear();
            l_col.clear();
            l_val.clear();
            l_diag.clear();
            return;
        }
        l_diag[i] = d.sqrt();
    }

    debug_assert!(
        l_diag.iter().all(|&d| d > 0.0 && d.is_finite()),
        "every pivot of a completed factorisation is positive and finite"
    );
}

/// Apply the preconditioner: `z = M⁻¹ r`.
///
/// One forward and one back substitution through the incomplete factor, or the
/// diagonal alone when [`factorise_into`] left the factor empty. Both run in a
/// fixed direction, so `z` is the same bits on every run of the same design.
fn precondition(
    factor: (&[u32], &[u32], &[f64], &[f64]),
    inv_diag: &[f64],
    r: &[f64],
    z: &mut [f64],
) {
    let (l_start, l_col, l_val, l_diag) = factor;
    let unknowns = z.len();
    debug_assert_eq!(r.len(), unknowns, "SoA columns must agree");
    debug_assert_eq!(inv_diag.len(), unknowns, "SoA columns must agree");

    // The fallback is an empty factor: `factorise_into` cleared the pattern and
    // never filled it.
    if l_diag.is_empty() {
        for i in 0..unknowns {
            z[i] = r[i] * inv_diag[i];
        }
        return;
    }

    debug_assert_eq!(l_diag.len(), unknowns, "one pivot per unknown");
    // Forward: `L y = r`, ascending, each row folding the entries left of its
    // diagonal.
    for i in 0..unknowns {
        let mut s = r[i];
        for t in l_start[i] as usize..l_start[i + 1] as usize {
            s -= l_val[t] * z[l_col[t] as usize];
        }
        z[i] = s / l_diag[i];
    }
    // Back: `Lᵀ z = y`, descending. Column-oriented: the transpose of a row-CSR
    // lower triangle is an upper triangle no column index reaches directly, so
    // row `i`'s value is scattered back over the rows above it.
    for i in (0..unknowns).rev() {
        let v = z[i] / l_diag[i];
        z[i] = v;
        for t in l_start[i] as usize..l_start[i + 1] as usize {
            z[l_col[t] as usize] -= l_val[t] * v;
        }
    }
}

/// Solve the assembled system for `scratch.x`, in place, from the guess it holds.
///
/// Conjugate gradients preconditioned by the incomplete Cholesky factor, or by
/// the diagonal alone when that breaks down. Returns the iteration count and the
/// residual as a fraction of the initial one.
fn conjugate_gradient(
    scratch: &mut SolveScratch,
    config: SolveConfig,
) -> Result<(u32, f64), PowerError> {
    let unknowns = scratch.x.len();
    debug_assert_eq!(
        scratch.rhs.len(),
        unknowns,
        "one right-hand side per unknown"
    );
    debug_assert_eq!(
        scratch.inv_diag.len(),
        unknowns,
        "one reciprocal per unknown"
    );
    debug_assert!(
        config.relative_tolerance > 0.0 && config.relative_tolerance.is_finite(),
        "a non-positive tolerance never stops the iteration"
    );

    // Once per solve: the factor is a function of the matrix, and nothing in the
    // loop below writes the matrix.
    factorise_into(scratch, unknowns);
    scratch.z.clear();
    scratch.z.resize(unknowns, 0.0);

    let SolveScratch {
        row_start,
        col,
        value,
        rhs,
        x,
        r,
        p,
        ap,
        inv_diag,
        l_start,
        l_col,
        l_val,
        l_diag,
        z,
        ..
    } = scratch;
    ap.clear();
    ap.resize(unknowns, 0.0);
    spmv(row_start, col, value, x, ap);
    r.clear();
    r.reserve(unknowns);
    for i in 0..unknowns {
        r.push(rhs[i] - ap[i]);
    }
    precondition((l_start, l_col, l_val, l_diag), inv_diag, r, z);
    p.clear();
    p.extend_from_slice(z);

    // Every vector below is `unknowns` long and stays that way, so the
    // column-agreement check goes here rather than inside the loop.
    debug_assert_eq!(x.len(), unknowns, "SoA columns must agree");
    debug_assert_eq!(r.len(), unknowns, "SoA columns must agree");
    debug_assert_eq!(p.len(), unknowns, "SoA columns must agree");
    debug_assert_eq!(ap.len(), unknowns, "SoA columns must agree");
    debug_assert_eq!(rhs.len(), unknowns, "SoA columns must agree");
    debug_assert_eq!(z.len(), unknowns, "SoA columns must agree");

    // Left fold, ascending: `rz` decides `alpha`, which decides the solution, so
    // reassociating it would make two runs of one design disagree.
    let mut rz = 0.0f64;
    for i in 0..unknowns {
        rz += r[i] * z[i];
    }

    let initial = norm(r);
    let goal = initial * config.relative_tolerance;
    let mut residual = initial;
    let mut iterations = 0u32;
    while residual > goal && iterations < config.max_iterations {
        spmv(row_start, col, value, p, ap);
        let mut pap = 0.0f64;
        for i in 0..unknowns {
            pap += p[i] * ap[i];
        }
        // The matrix is positive definite, so a non-positive `p·Ap` means the
        // iteration reached the floating-point floor; stopping here leaves the
        // convergence test below to decide whether that is good enough.
        if !(pap > 0.0) {
            break;
        }
        let alpha = rz / pap;
        for i in 0..unknowns {
            x[i] += alpha * p[i];
        }
        for i in 0..unknowns {
            r[i] -= alpha * ap[i];
        }
        precondition((l_start, l_col, l_val, l_diag), inv_diag, r, z);
        let mut next = 0.0f64;
        for i in 0..unknowns {
            next += r[i] * z[i];
        }
        let beta = next / rz;
        for i in 0..unknowns {
            p[i] = z[i] + beta * p[i];
        }
        rz = next;
        residual = norm(r);
        iterations += 1;
    }

    // Negated rather than `residual > goal`, so a `NaN` residual — from a
    // right-hand side that overflowed, or a breakdown — is a refusal and not a
    // silent pass. Fail closed.
    if !(residual <= goal) {
        return Err(PowerError::NotConverged(config.max_iterations));
    }
    debug_assert!(iterations <= config.max_iterations, "the cap was overrun");
    Ok((
        iterations,
        if initial > 0.0 {
            residual / initial
        } else {
            0.0
        },
    ))
}

/// A grid and its solution, borrowed together.
///
/// The four electrical rules read both or neither, so `Option<Solved>` says
/// "there is no solved grid" and the rules record themselves skipped.
#[derive(Debug, Clone, Copy)]
pub struct Solved<'a> {
    pub grid: &'a PowerGrid,
    pub solution: &'a PowerSolution,
}

/// Did a stated current budget fail to reach the solve?
///
/// True when some net declared as a supply states a non-zero
/// `budget_current_ua` and carries **no load at all** across its nodes. Exact,
/// not a heuristic: [`extract_into`] spreads `sign * budget_current_ua` over
/// the rail's attach points, so the net's `node_load` sums to the signed budget
/// whenever the budget was read and to exactly `0.0` whenever it was not.
/// `-0.0 == 0.0`, so a ground rail's negative shares use the same compare.
///
/// Attach points are **terminal** based, so a rail fed from off-chip through a
/// pad has none. No number can be substituted: the branch-current rules refuse
/// rather than report a verdict over a grid carrying no current, because a zero
/// current passes every density limit, Blech product and drop limit silently.
/// Closing it needs a per-terminal current column on `DeviceTable`.
pub(crate) fn discarded_budget(grid: &PowerGrid, intent: &IntentMap) -> bool {
    debug_assert_eq!(
        grid.node_load.len(),
        grid.node_count(),
        "one load per node, or the fold below reads another node's current"
    );

    // Walked over `limit_net` rather than `supply_net`: `parse_intent` does not
    // require a net carrying a `limits` entry to be a declared supply, and only
    // supplies are given grid nodes — so a budget stated on a non-supply net was
    // checked by nothing. The same compare catches it, its load being zero for
    // want of any node at all.
    intent
        .limit_net
        .iter()
        .zip(&intent.limit)
        .any(|(&net, limits)| {
            limits.budget_current_ua.is_some_and(|budget| budget != 0.0)
                && load_on(grid, net) == 0.0
        })
}

/// Total load on one net, over every node of the grid.
fn load_on(grid: &PowerGrid, net: NetId) -> f64 {
    // `-0.0` sums to `-0.0`, and `-0.0 == 0.0`, so a ground rail's negative
    // shares compare the same as a power rail's positive ones.
    (0..grid.node_count())
        .map(|node| f64::from(u8::from(grid.node_net[node] == net)) * grid.node_load[node].raw())
        .sum()
}

/// Build the supply grid from layout. Caller owns `out`, cleared and refilled.
///
/// Only nets [`IntentMap`] declares as supplies get nodes: a signal net has no
/// nominal voltage to measure a drop from. A run with no declared supplies
/// produces an empty grid and the caller passes `None` for [`Solved`], which is
/// how four rules report themselves skipped rather than clean.
///
/// `node_poly` names the same polygon once per tap; every consumer reads it
/// positionally, and none assumes a node and a polygon are the same thing.
///
/// The budget spreads **uniformly** over the rail's attach points, because
/// [`IntentMap`] carries one `budget_current_ua` per net and no per-instance
/// column. A hot spot therefore reads cooler than it is wherever the real draw
/// is concentrated; closing it needs a per-terminal current column on
/// [`DeviceTable`].
pub fn extract_into(
    store: &GeometryStore,
    nets: &NetTable,
    devices: &DeviceTable,
    intent: &IntentMap,
    process: Process<'_>,
    out: &mut PowerGrid,
) -> Result<(), PowerError> {
    debug_assert_eq!(
        intent.supply_role.len(),
        intent.supply_net.len(),
        "one role per declared supply"
    );
    debug_assert_eq!(
        intent.supply_voltage.len(),
        intent.supply_net.len(),
        "one nominal per declared supply"
    );

    out.node_net.clear();
    out.node_at.clear();
    out.node_poly.clear();
    out.node_layer.clear();
    out.node_nominal.clear();
    out.node_load.clear();
    out.source_node.clear();
    out.source_voltage.clear();
    out.edge_from.clear();
    out.edge_to.clear();
    out.edge_resistance.clear();
    out.edge_width.clear();
    out.edge_length.clear();
    out.edge_layer.clear();
    out.edge_kind.clear();

    // Fallible before a single row is written: a missing sheet resistance is a
    // refusal, never a default, and finding out mid-fill leaves a half-built
    // grid.
    let conductor = conductor_mask(process.connectivity, store.layer_count());
    let sheet = sheet_resistances(process, store.layer_count())?;

    // Pass one: which polygons carry a chain, and which declared supply each
    // belongs to. Only nets `intent` declares — a signal net has no nominal to
    // measure a drop from.
    let mut supply_of_shape: Vec<u32> = Vec::new();
    let mut shape: Vec<PolyId> = Vec::new();
    let mut supply_start: Vec<u32> = vec![0];
    let mut kept: Vec<PolyId> = Vec::new();
    for supply in 0..intent.supply_net.len() {
        // Branchless compact: reserve for the whole input, store
        // unconditionally, and let the write cursor carry the decision.
        let candidate = nets.polys_of(intent.supply_net[supply]);
        kept.clear();
        kept.reserve(candidate.len());
        let slots = &mut kept.spare_capacity_mut()[..candidate.len()];
        let mut w = 0usize;
        for (i, &poly) in candidate.iter().enumerate() {
            let keep = conductor[store.poly_layer(poly).idx()];
            // `w <= i` by induction: `w` is `0` when `i` is, and `bool` is 0 or
            // 1, so each iteration advances `w` by at most the one `i` advances
            // by.
            debug_assert!(w <= i);
            // SAFETY: `w <= i < candidate.len() == slots.len()` from the
            // induction above. Rejected slots stay uninit and are never read,
            // because `set_len(w)` truncates them away; `PolyId` is `Copy`, so
            // nothing here has a `Drop` to run on one.
            unsafe { slots.get_unchecked_mut(w) }.write(poly);
            w += usize::from(keep);
        }
        // SAFETY: slot `k` was written on the iteration where `w` held `k`, for
        // every `k` in `0..w`, and `w <= candidate.len() <= kept.capacity()`.
        unsafe { kept.set_len(w) };
        debug_assert!(
            kept.len() <= candidate.len(),
            "a compact cannot grow its input"
        );

        shape.extend_from_slice(&kept);
        supply_of_shape.resize(
            shape.len(),
            u32::try_from(supply).expect("a supply row is a u32"),
        );
        supply_start.push(u32::try_from(shape.len()).expect("a shape index is a u32"));
    }

    // Pass two: every connection between two shapes on the grid. Both lists are
    // needed before any node exists, because a connection is what says *where* a
    // shape is tapped and therefore where its chain is cut.
    let mut shape_of_poly = vec![NONE; store.poly_count()];
    for (index, &poly) in shape.iter().enumerate() {
        shape_of_poly[poly.idx()] = u32::try_from(index).expect("a shape index is a u32");
    }
    let mut links = Connections::default();
    connections_into(store, process.connectivity, &mut links);
    let both_noded = |(a, b, _): (u32, u32, LayerId)| {
        (shape_of_poly[a as usize] != NONE) & (shape_of_poly[b as usize] != NONE)
    };
    let mut metal: Vec<(u32, u32, LayerId)> = Vec::new();
    let mut via: Vec<(u32, u32, LayerId)> = Vec::new();
    // The same branchless compact twice, over the two connection lists.
    metal.reserve(links.metal.len());
    let slots = &mut metal.spare_capacity_mut()[..links.metal.len()];
    let mut w = 0usize;
    for i in 0..links.metal.len() {
        let link = links.metal[i];
        let keep = both_noded(link);
        // `w <= i` by induction: `w` starts at `0` with `i`, and `bool` is 0 or
        // 1, so `w` never outruns `i`.
        debug_assert!(w <= i);
        // SAFETY: `w <= i < links.metal.len() == slots.len()`. Rejected slots
        // stay uninit and `set_len(w)` truncates them away; the row is `Copy`,
        // so none of them has a `Drop`.
        unsafe { slots.get_unchecked_mut(w) }.write(link);
        w += usize::from(keep);
    }
    // SAFETY: slot `k` was written on the iteration where `w` held `k`, for
    // every `k` in `0..w`, and `w <= links.metal.len() <= metal.capacity()`.
    unsafe { metal.set_len(w) };

    via.reserve(links.via.len());
    let slots = &mut via.spare_capacity_mut()[..links.via.len()];
    let mut w = 0usize;
    for i in 0..links.via.len() {
        let link = links.via[i];
        let keep = both_noded(link);
        // `w <= i` by the same induction as the metal compact above.
        debug_assert!(w <= i);
        // SAFETY: `w <= i < links.via.len() == slots.len()`, and the rejected
        // slots are truncated away by `set_len(w)` without a `Drop` to run.
        unsafe { slots.get_unchecked_mut(w) }.write(link);
        w += usize::from(keep);
    }
    // SAFETY: slot `k` was written on the iteration where `w` held `k`, for
    // every `k` in `0..w`, and `w <= links.via.len() <= via.capacity()`.
    unsafe { via.set_len(w) };
    debug_assert!(
        metal.len() <= links.metal.len() && via.len() <= links.via.len(),
        "a compact cannot grow its input"
    );

    // Pass three: the taps. Every shape carries one at its own centre first, so
    // a shape nothing connects to still has a node — dropping it would delete a
    // disconnected island from the grid, and an island that is absent cannot be
    // told from one that was checked and found anchored.
    let mut taps = TapTable::default();
    taps.clear();
    // Three times: `push` appends to two tap columns at once.
    for (index, &poly) in shape.iter().enumerate() {
        let host = store.poly_bbox(poly);
        taps.push(
            u32::try_from(index).expect("a shape index is a u32"),
            tap_on(host, host),
        );
    }
    let metal_req = u32::try_from(taps.req_shape.len()).expect("a tap request is a u32");
    for &(a, b, _) in &metal {
        let (host_a, host_b) = (store.poly_bbox(PolyId(a)), store.poly_bbox(PolyId(b)));
        taps.push(shape_of_poly[a as usize], tap_on(host_a, host_b));
        taps.push(shape_of_poly[b as usize], tap_on(host_b, host_a));
    }
    let via_req = u32::try_from(taps.req_shape.len()).expect("a tap request is a u32");
    for &(a, b, _) in &via {
        let (host_a, host_b) = (store.poly_bbox(PolyId(a)), store.poly_bbox(PolyId(b)));
        taps.push(shape_of_poly[a as usize], tap_on(host_a, host_b));
        taps.push(shape_of_poly[b as usize], tap_on(host_b, host_a));
    }

    // Pass four: where the devices draw, as one more tap apiece. The share each
    // takes needs the count for its whole rail, so the requests are collected
    // here and scattered onto the node column once the nodes exist.
    let mut attach: Vec<u32> = Vec::new();
    let mut load: Vec<(u32, Qty<Current, { prefix::MICRO }>)> = Vec::new();
    let mut index = TapIndex::default();
    for (supply, &net) in intent.supply_net.iter().enumerate() {
        let (from, to) = (
            supply_start[supply] as usize,
            supply_start[supply + 1] as usize,
        );
        attach.clear();
        // A supply this block does not route has nothing to attach to.
        if to == from {
            continue;
        }
        TapIndex::build_into(store, &shape[from..to], &mut index);
        for &device in devices.devices_on(net) {
            let marker = centre(store.poly_bbox(devices.marker[device.0 as usize]));
            let host_index = from + index.nearest(marker) as usize;
            let host = store.poly_bbox(shape[host_index]);
            let request = taps.push(
                u32::try_from(host_index).expect("a shape index is a u32"),
                tap_on(host, Bbox::point(marker.x, marker.y)),
            );
            let (on, _) = devices.terminals_of(device);
            // One share per terminal the device lands on this net, so a device
            // with source and drain on the rail draws twice.
            let here = on.iter().filter(|&&n| n == net).count();
            attach.resize(attach.len() + here, request);
        }
        // No `attach.is_empty()` guard, deliberately: a rail with no device
        // terminal is the ordinary shape of a supply fed from off-chip, which
        // draws everything. `discarded_budget` reports that to the rules
        // instead, because an `Err` here would refuse the whole ERC stage.
        //
        // A ground node's load is negative by the column's own convention: it
        // injects into the rail rather than drawing from it.
        let sign = match intent.supply_role[supply] {
            SupplyRole::Power => 1.0,
            SupplyRole::Ground => -1.0,
        };
        #[allow(
            clippy::cast_precision_loss,
            reason = "an attach-point count is far inside an f64's exact integers"
        )]
        let share = Qty::new(
            sign * intent.limits_of(net).budget_current_ua.unwrap_or(0.0) / attach.len() as f64,
        );
        for &request in &attach {
            load.push((request, share));
        }
    }

    // Pass five: the nodes. One per distinct tap, ascending by shape and then
    // along that shape's chain.
    taps.finish(shape.len());
    let nodes = taps.node_shape.len();
    debug_assert_eq!(
        taps.node_along.len(),
        nodes,
        "SoA columns must agree: one chain position per node"
    );

    out.node_poly.reserve(nodes);
    for i in 0..nodes {
        out.node_poly.push(shape[taps.node_shape[i] as usize]);
    }
    out.node_net.reserve(nodes);
    for i in 0..nodes {
        let supply = supply_of_shape[taps.node_shape[i] as usize] as usize;
        out.node_net.push(intent.supply_net[supply]);
    }
    out.node_nominal.reserve(nodes);
    for i in 0..nodes {
        let supply = supply_of_shape[taps.node_shape[i] as usize] as usize;
        out.node_nominal.push(intent.supply_voltage[supply]);
    }
    out.node_layer.reserve(nodes);
    for i in 0..nodes {
        out.node_layer.push(store.poly_layer(out.node_poly[i]));
    }
    out.node_at.reserve(nodes);
    for i in 0..nodes {
        let host = store.poly_bbox(shape[taps.node_shape[i] as usize]);
        out.node_at.push(tap_point(host, taps.node_along[i]));
    }

    out.node_load.clear();
    out.node_load.resize(out.node_poly.len(), Qty::new(0.0));
    // Two rows can land on one node, so this accumulates rather than stores.
    for &(request, share) in &load {
        let node = taps.req_node[request as usize] as usize;
        out.node_load[node] = out.node_load[node] + share;
    }

    // Where the rail is anchored. No input carries a pad marker, so the anchor
    // is inferred from the stack: supply enters a die from the top, so it is the
    // centre tap of the rail's widest shape on its highest conducting layer.
    // The residual error is one anchor where a real rail has many, which
    // over-reports drop rather than under-reporting it. A pad-marker layer on
    // `Connectivity` closes it.
    for supply in 0..intent.supply_net.len() {
        let (from, to) = (
            supply_start[supply] as usize,
            supply_start[supply + 1] as usize,
        );
        // A rail with no shape has no node and therefore no pad.
        if to == from {
            continue;
        }
        // Keyed so every tie is broken by data rather than by order: highest
        // metal, then the widest piece of it, then the lowest shape index. A
        // missing `height_nm` reads as the substrate, which loses to every layer
        // the stack does name.
        let mut anchor = from;
        let mut best = (f64::NEG_INFINITY, i128::MIN);
        for (offset, &poly) in shape[from..to].iter().enumerate() {
            let host = store.poly_bbox(poly);
            let height = process
                .stack
                .height_nm
                .get(store.poly_layer(poly).idx())
                .copied()
                .unwrap_or(0.0);
            let key = (height, host.area().raw());
            if key > best {
                best = key;
                anchor = from + offset;
            }
        }

        // The centre tap: every shape carries one by construction (pass three
        // pushes it first), and the centre minimises the worst-case distance to
        // wherever the real pad sits. The chain is ascending in `node_along`.
        let host = store.poly_bbox(shape[anchor]);
        let middle = tap_on(host, host);
        let (lo, hi) = taps.chain_of(u32::try_from(anchor).expect("a shape index is a u32"));
        let at = lo
            + taps.node_along[lo..hi]
                .binary_search(&middle)
                .expect("every shape carries a tap at its own centre");
        out.source_node
            .push(u32::try_from(at).expect("a node index is a u32"));
        out.source_voltage.push(intent.supply_voltage[supply]);
    }

    // Pass six: the edges. A shape's own chain first, then one edge per
    // connection, whose two taps are the same physical point and whose length is
    // therefore the floor.
    let mut profile = ChainProfile::default();
    for (index, &poly) in shape.iter().enumerate() {
        let layer = store.poly_layer(poly);
        profile.build(store, poly);
        let (from, to) = taps.chain_of(u32::try_from(index).expect("a shape index is a u32"));
        for node in from..to.saturating_sub(1) {
            let (a, b) = (taps.node_along[node], taps.node_along[node + 1]);
            // The taps of one chain are strictly ascending, so the span is at
            // least one database unit and the floor is a restatement rather
            // than a correction. It is stated because a zero length makes the
            // Blech product zero, and a segment below the Blech limit is
            // *exempt* from electromigration.
            let length = Dbu::new_unchecked((b.raw() - a.raw()).max(1));
            // The metal the segment actually has, and the narrowest place in
            // it — not the shape's bounding box.
            let (squares, width) = profile.segment(a, b);
            out.edge_from
                .push(u32::try_from(node).expect("a node index is a u32"));
            out.edge_to
                .push(u32::try_from(node + 1).expect("a node index is a u32"));
            out.edge_resistance
                .push(Qty::new(sheet[layer.idx()] * squares));
            out.edge_width.push(width);
            out.edge_length.push(length);
            out.edge_layer.push(layer);
            out.edge_kind.push(EdgeKind::Metal);
        }
    }

    for (link, &(a, b, layer)) in metal.iter().enumerate() {
        let (host_a, host_b) = (store.poly_bbox(PolyId(a)), store.poly_bbox(PolyId(b)));
        let width = conductor_width(host_a, host_b);
        let (ra, rb) = (
            metal_req as usize + 2 * link,
            metal_req as usize + 2 * link + 1,
        );
        let (node_a, node_b) = (taps.req_node[ra], taps.req_node[rb]);
        // The two taps are the same physical point — the shapes touch — so this
        // is the floor; the metal between them is carried by the two chains.
        let length = run_length(out.node_at[node_a as usize], out.node_at[node_b as usize]);
        out.edge_from.push(node_a);
        out.edge_to.push(node_b);
        out.edge_resistance
            .push(Qty::new(sheet[layer.idx()] * squares(length, width)));
        out.edge_width.push(width);
        out.edge_length.push(length);
        out.edge_layer.push(layer);
        out.edge_kind.push(EdgeKind::Metal);
    }

    for (link, &(a, b, cut)) in via.iter().enumerate() {
        let (host_a, host_b) = (store.poly_bbox(PolyId(a)), store.poly_bbox(PolyId(b)));
        let width = conductor_width(host_a, host_b);
        let length = via_length(
            process,
            store.poly_layer(PolyId(a)),
            store.poly_layer(PolyId(b)),
        );
        let (ra, rb) = (via_req as usize + 2 * link, via_req as usize + 2 * link + 1);
        out.edge_from.push(taps.req_node[ra]);
        out.edge_to.push(taps.req_node[rb]);
        // One square of the cut layer, per cut. Each cut is its own parallel
        // edge, so a via array's conductance adds where it should and every cut
        // is checked against the per-cut limit the deck states.
        out.edge_resistance.push(Qty::new(sheet[cut.idx()]));
        out.edge_width.push(width);
        out.edge_length.push(length);
        out.edge_layer.push(cut);
        out.edge_kind.push(EdgeKind::Via { cuts: 1 });
    }

    debug_assert_eq!(
        out.source_node.len(),
        out.source_voltage.len(),
        "one voltage per pad"
    );
    // Two supplies' shape ranges are disjoint and ascending and nodes are
    // numbered by shape, so each rail's anchor lands below every node of the
    // rail after it. `PowerGrid::fixed_voltage` binary-searches on this.
    debug_assert!(
        out.source_node.windows(2).all(|w| w[0] < w[1]),
        "supplies were walked ascending, so their anchors are ascending"
    );
    debug_assert!(
        out.edge_from
            .iter()
            .chain(&out.edge_to)
            .all(|&n| (n as usize) < out.node_count()),
        "an edge names a node the grid does not have"
    );
    debug_assert!(
        out.edge_resistance
            .iter()
            .all(|r| r.raw() > 0.0 && r.is_finite()),
        "an extracted edge has no positive finite resistance"
    );
    Ok(())
}

/// A uniform grid over one net's tap points, for nearest-tap queries.
///
/// CSR by bucket, queried by expanding rings around the query cell. Distinct
/// from [`gpurify_core::index::SpatialIndex`] and from `rules::supply::TapGrid`:
/// this indexes one net's shapes *across* layers and answers a nearest-point
/// query, where those answer within-distance pair queries over segments.
#[derive(Debug, Default)]
struct TapIndex {
    /// Tap centre of each candidate, in candidate order.
    at: Vec<Point>,
    origin_x: Dbu,
    origin_y: Dbu,
    cell: i64,
    nx: u32,
    ny: u32,
    /// `bucket_start[b] .. bucket_start[b + 1]` indexes `rows`, whose values are
    /// indices into `at`.
    bucket_start: Vec<u32>,
    rows: Vec<u32>,
    /// Fill cursor of the counting sort, a `scratch` column so a loop over nets
    /// does not allocate one per build.
    cursor: Vec<u32>,
}

impl TapIndex {
    /// Build over one net's conducting shapes, clearing and refilling.
    fn build_into(store: &GeometryStore, candidate: &[PolyId], out: &mut Self) {
        debug_assert!(
            candidate.windows(2).all(|w| w[0] < w[1]),
            "the candidate list is ascending, which is what fixes the tie rule below"
        );
        out.at.clear();
        out.at.reserve(candidate.len());
        out.at
            .extend(candidate.iter().map(|&p| centre(store.poly_bbox(p))));
        out.grid();
    }

    /// Bucket the tap column this index already holds.
    ///
    /// Split from [`TapIndex::build_into`] so the ring search can be exercised
    /// against a brute-force scan without a [`GeometryStore`].
    fn grid(&mut self) {
        let out = self;
        out.bucket_start.clear();
        out.rows.clear();
        out.cell = 1;
        out.nx = 1;
        out.ny = 1;
        // A net with no conducting shape has no grid; `nearest` asserts against
        // being asked, and every caller already establishes the net has one.
        if out.at.is_empty() {
            out.bucket_start.push(0);
            return;
        }

        let mut bounds = Bbox::EMPTY;
        for i in 0..out.at.len() {
            let p = out.at[i];
            bounds = bounds.union(Bbox {
                xlo: p.x,
                ylo: p.y,
                xhi: p.x,
                yhi: p.y,
            });
        }
        let (ox, oy) = (bounds.xlo.raw(), bounds.ylo.raw());
        let (span_x, span_y) = (bounds.xhi.raw() - ox + 1, bounds.yhi.raw() - oy + 1);
        // One bucket per tap on average, whatever the aspect ratio: a rail one
        // track tall and a millimetre wide must not ask for a bucket per
        // database unit.
        let side = i64::try_from(out.at.len())
            .expect("a tap count is an i64")
            .isqrt()
            .max(1);
        let cell = ((span_x + side - 1) / side)
            .max((span_y + side - 1) / side)
            .max(1);
        out.origin_x = bounds.xlo;
        out.origin_y = bounds.ylo;
        out.cell = cell;
        out.nx = u32::try_from((span_x + cell - 1) / cell).expect("a grid axis is a u32");
        out.ny = u32::try_from((span_y + cell - 1) / cell).expect("a grid axis is a u32");
        debug_assert!(out.nx >= 1 && out.ny >= 1, "a real extent covers one cell");

        let buckets = out.nx as usize * out.ny as usize;
        out.bucket_start.resize(buckets + 1, 0);
        for index in 0..out.at.len() {
            let b = out.bucket_of(out.at[index]) as usize;
            out.bucket_start[b + 1] += 1;
        }
        for b in 0..buckets {
            out.bucket_start[b + 1] += out.bucket_start[b];
        }
        out.rows.resize(out.at.len(), 0);
        out.cursor.clear();
        out.cursor.extend_from_slice(&out.bucket_start);
        for index in 0..out.at.len() {
            let b = out.bucket_of(out.at[index]) as usize;
            out.rows[out.cursor[b] as usize] = u32::try_from(index).expect("a tap index is a u32");
            out.cursor[b] += 1;
        }

        debug_assert_eq!(
            out.bucket_start[buckets] as usize,
            out.at.len(),
            "every tap was filed in exactly one bucket"
        );
        debug_assert!(
            out.bucket_start.windows(2).all(|w| w[0] <= w[1]),
            "bucket offsets are non-decreasing"
        );
    }

    /// Which bucket a point inside the extent falls in.
    fn bucket_of(&self, p: Point) -> u32 {
        let col = (p.x.raw() - self.origin_x.raw()) / self.cell;
        let row = (p.y.raw() - self.origin_y.raw()) / self.cell;
        debug_assert!(
            col >= 0 && col < i64::from(self.nx) && row >= 0 && row < i64::from(self.ny),
            "a tap outside the extent it was measured from"
        );
        let (row, col) = (
            u32::try_from(row).expect("a tap row is inside the extent"),
            u32::try_from(col).expect("a tap column is inside the extent"),
        );
        row * self.nx + col
    }

    /// Which candidate a device attaches to: the one whose tap is nearest.
    ///
    /// Returns the index within the candidate list, and on a tie the lowest; the
    /// list is ascending by [`PolyId`], so the answer is a function of the layout
    /// and not of the order the rings were walked in.
    ///
    /// # Panics
    ///
    /// When the index is empty — a net with no shape has nothing to attach to,
    /// and every caller has already established it has one.
    fn nearest(&self, marker: Point) -> u32 {
        assert!(!self.at.is_empty(), "a net with no shape to attach to");

        // The query cell, clamped: a marker outside the extent searches from the
        // border cell outwards, and the slack test below is what keeps that
        // exact rather than merely close.
        let cx =
            ((marker.x.raw() - self.origin_x.raw()).max(0) / self.cell).min(i64::from(self.nx - 1));
        let cy =
            ((marker.y.raw() - self.origin_y.raw()).max(0) / self.cell).min(i64::from(self.ny - 1));

        let mut best = (i128::MAX, u32::MAX);
        let mut radius = 0i64;
        loop {
            let (lo_x, hi_x) = (cx - radius, cx + radius);
            let (lo_y, hi_y) = (cy - radius, cy + radius);
            let scan = |mut best: (i128, u32), row: i64, col: i64| {
                // Both are already clipped to the grid by every call site below.
                let b = (u32::try_from(row).expect("a scanned row is inside the grid") * self.nx
                    + u32::try_from(col).expect("a scanned column is inside the grid"))
                    as usize;
                let (from, to) = (
                    self.bucket_start[b] as usize,
                    self.bucket_start[b + 1] as usize,
                );
                for k in from..to {
                    let index = self.rows[k];
                    let here = self.at[index as usize];
                    let (dx, dy) = (
                        i128::from(here.x.raw() - marker.x.raw()),
                        i128::from(here.y.raw() - marker.y.raw()),
                    );
                    // Both differences are bounded by twice `MAX_ABS_DBU = 2^40`,
                    // so the squares and their sum sit far inside an `i128`.
                    // Exact, so a tie is a tie rather than a rounding.
                    let distance = dx * dx + dy * dy;
                    // The comparison is on the pair, so an equal distance is
                    // broken by the lower index and the ring order never decides
                    // one; a winning pair is never *further*, so `min` agrees
                    // with the blend.
                    let closer = u32::from((distance, index) < best).wrapping_neg();
                    best = (distance.min(best.0), (index & closer) | (best.1 & !closer));
                }
                best
            };

            // Everything at Chebyshev distance exactly `radius` from the query
            // cell. A row that is not itself part of the border contributes its
            // two end cells and nothing between them, named outright because a
            // row clipped by the grid edge has its ends less than a stride apart.
            let last_col = i64::from(self.nx - 1);
            for row in lo_y.max(0)..=hi_y.min(i64::from(self.ny - 1)) {
                if row == lo_y || row == hi_y {
                    for col in lo_x.max(0)..=hi_x.min(last_col) {
                        best = scan(best, row, col);
                    }
                } else {
                    // `radius` is non-zero here — a zero-radius block is one cell
                    // and that cell is a border row — so the two ends are
                    // distinct and neither is scanned twice.
                    for col in [lo_x, hi_x] {
                        if col >= 0 && col <= last_col {
                            best = scan(best, row, col);
                        }
                    }
                }
            }

            // Stop when nothing unscanned can be closer. The scanned block spans
            // these world coordinates, so an unscanned tap is at least `slack`
            // away — and a negative slack means the marker sits outside the
            // block, where nothing has been ruled out yet.
            let (blo_x, bhi_x) = (
                self.origin_x.raw() + lo_x * self.cell,
                self.origin_x.raw() + (hi_x + 1) * self.cell - 1,
            );
            let (blo_y, bhi_y) = (
                self.origin_y.raw() + lo_y * self.cell,
                self.origin_y.raw() + (hi_y + 1) * self.cell - 1,
            );
            let slack = (marker.x.raw() - blo_x)
                .min(bhi_x - marker.x.raw())
                .min(marker.y.raw() - blo_y)
                .min(bhi_y - marker.y.raw());
            let covered = lo_x <= 0
                && lo_y <= 0
                && hi_x >= i64::from(self.nx - 1)
                && hi_y >= i64::from(self.ny - 1);
            if covered || (slack >= 0 && best.0 <= i128::from(slack) * i128::from(slack)) {
                break;
            }
            radius += 1;
        }

        debug_assert!(
            (best.1 as usize) < self.at.len(),
            "the ring search covered the whole grid without finding a tap"
        );
        best.1
    }
}

/// Which layers carry current, as one byte per layer.
fn conductor_mask(connectivity: &Connectivity, layers: usize) -> Vec<bool> {
    let bound = connectivity
        .conductors
        .iter()
        .map(|l| l.idx() + 1)
        .max()
        .unwrap_or(0)
        .max(layers);
    let mut mask = vec![false; bound];
    for &layer in &connectivity.conductors {
        mask[layer.idx()] = true;
    }
    mask
}

/// Sheet resistance of every layer that will carry current, indexed by layer.
///
/// Fail closed: a missing, zero, negative or non-finite sheet resistance is
/// [`PowerError::NoSheetResistance`]. A zero in particular shorts a whole rail
/// and makes a bad grid read clean.
fn sheet_resistances(process: Process<'_>, layers: usize) -> Result<Vec<f64>, PowerError> {
    let carrying = process
        .connectivity
        .conductors
        .iter()
        .chain(&process.connectivity.via_cut);
    let bound = carrying
        .clone()
        .map(|l| l.idx() + 1)
        .max()
        .unwrap_or(0)
        .max(layers);
    let mut sheet = vec![0.0f64; bound];
    for &layer in carrying {
        let ohm_per_square = process
            .stack
            .sheet_res_ohm_sq
            .get(layer.idx())
            .copied()
            .unwrap_or(f64::NAN);
        if !(ohm_per_square > 0.0 && ohm_per_square.is_finite()) {
            return Err(PowerError::NoSheetResistance(layer));
        }
        sheet[layer.idx()] = ohm_per_square;
    }
    Ok(sheet)
}

/// Every connection between two conductor polygons, split by kind.
///
/// Two tables rather than one with a kind column: the resistance of the two is a
/// different formula, so a kind column would put a `match` inside the loop that
/// computes millions of them.
#[derive(Debug, Default)]
struct Connections {
    /// Touching pairs on one conductor layer, with that layer.
    metal: Vec<(u32, u32, LayerId)>,
    /// Cut-joined pairs, with the cut layer. One row per cut that lands on both
    /// conductors, so a via array of four cuts is four parallel edges.
    via: Vec<(u32, u32, LayerId)>,
}

fn connections_into(store: &GeometryStore, connectivity: &Connectivity, out: &mut Connections) {
    out.metal.clear();
    out.via.clear();
    debug_assert_eq!(
        connectivity.via_connects.len(),
        connectivity.via_cut.len(),
        "one pair of joined layers per via row"
    );

    let mut pairs: Vec<(u32, u32)> = Vec::new();

    // Whether touching shapes on one layer connect is a deck-wide fact, so it
    // selects the list to walk rather than guarding a row.
    let touching: &[LayerId] = if connectivity.intra_layer_touch {
        &connectivity.conductors
    } else {
        &[]
    };
    for &layer in touching {
        intra_layer_edges_into(store, layer, &mut pairs);
        out.metal.reserve(pairs.len());
        out.metal.extend(pairs.iter().map(|&(a, b)| (a, b, layer)));
    }
    for (row, &cut) in connectivity.via_cut.iter().enumerate() {
        via_edges_into(store, cut, connectivity.via_connects[row], &mut pairs);
        out.via.reserve(pairs.len());
        out.via.extend(pairs.iter().map(|&(a, b)| (a, b, cut)));
    }
}

/// Every shape's taps, sorted along its chain and deduplicated.
///
/// This is what makes a polygon a *chain* rather than a point: the metal between
/// two taps is modelled as the resistance it is. The request columns and the
/// node columns are separate groups joined by `req_node`.
#[derive(Debug, Default)]
struct TapTable {
    /// Request columns, in the order the caller pushed them: which shape, and
    /// where along that shape's chain.
    req_shape: Vec<u32>,
    req_along: Vec<Dbu>,
    /// The node each request resolved to. Filled by [`TapTable::finish`]; two
    /// requests at the same point on the same shape resolve to one node, which
    /// is what makes a via landing where a route already taps not split it.
    req_node: Vec<u32>,

    /// Node columns: which shape the node taps, and where on its chain.
    node_shape: Vec<u32>,
    node_along: Vec<Dbu>,
    /// `chain_start[s] .. chain_start[s + 1]` is shape `s`'s run of nodes,
    /// ascending along its chain — which is what makes the chain edges one pass
    /// over adjacent pairs.
    chain_start: Vec<u32>,

    /// Sort permutation, a column so the sort reuses one allocation.
    order: Vec<u32>,
}

impl TapTable {
    /// Empty the table, keeping every allocation.
    fn clear(&mut self) {
        self.req_shape.clear();
        self.req_along.clear();
        self.req_node.clear();
        self.node_shape.clear();
        self.node_along.clear();
        self.chain_start.clear();
        self.order.clear();
    }

    /// Ask for a tap on `shape` at `along`, and get the request's index back.
    fn push(&mut self, shape: u32, along: Dbu) -> u32 {
        let index = u32::try_from(self.req_shape.len()).expect("a tap request is a u32");
        self.req_shape.push(shape);
        self.req_along.push(along);
        index
    }

    /// Resolve every request to a node.
    ///
    /// Sorts by `(shape, along)` and gives one node to each distinct pair, so a
    /// shape's nodes come out ascending along its chain and `chain_start`
    /// carries `shapes + 1` offsets.
    fn finish(&mut self, shapes: usize) {
        debug_assert_eq!(
            self.req_along.len(),
            self.req_shape.len(),
            "one coordinate per tap request"
        );
        debug_assert!(
            self.req_shape.iter().all(|&s| (s as usize) < shapes),
            "a tap request names a shape the network does not have"
        );

        self.order.clear();
        self.order
            .extend(0..u32::try_from(self.req_shape.len()).expect("a tap request is a u32"));
        // The index is the last key, so the sort is total and the elimination
        // order cannot depend on which equal pair the sort left first.
        let (shape, along) = (&self.req_shape, &self.req_along);
        self.order
            .sort_unstable_by_key(|&i| (shape[i as usize], along[i as usize], i));

        self.req_node.clear();
        self.req_node.resize(self.req_shape.len(), NONE);
        self.node_shape.clear();
        self.node_along.clear();
        for &request in &self.order {
            let (s, a) = (
                self.req_shape[request as usize],
                self.req_along[request as usize],
            );
            let fresh = self.node_shape.last() != Some(&s) || self.node_along.last() != Some(&a);
            if fresh {
                self.node_shape.push(s);
                self.node_along.push(a);
            }
            self.req_node[request as usize] =
                u32::try_from(self.node_shape.len() - 1).expect("a node index is a u32");
        }

        self.chain_start.clear();
        self.chain_start.resize(shapes + 1, 0);
        for &s in &self.node_shape {
            self.chain_start[s as usize + 1] += 1;
        }
        for s in 0..shapes {
            self.chain_start[s + 1] += self.chain_start[s];
        }

        debug_assert_eq!(
            self.chain_start[shapes] as usize,
            self.node_shape.len(),
            "every node belongs to exactly one shape's chain"
        );
        debug_assert!(
            self.req_node
                .iter()
                .all(|&n| (n as usize) < self.node_shape.len()),
            "a tap request resolved to a node that does not exist"
        );
        debug_assert!(
            self.node_shape
                .windows(2)
                .zip(self.node_along.windows(2))
                .all(|(s, a)| (s[0], a[0]) < (s[1], a[1])),
            "the node columns run ascending by shape and then along the chain"
        );
    }

    /// One shape's run of nodes, ascending along its chain.
    fn chain_of(&self, shape: u32) -> (usize, usize) {
        let (from, to) = (
            self.chain_start[shape as usize] as usize,
            self.chain_start[shape as usize + 1] as usize,
        );
        debug_assert!(from < to, "every shape carries at least its own centre tap");
        (from, to)
    }
}

/// Which axis a polygon's resistor chain runs along: `true` for x.
///
/// The long bounding-box axis, because that is the direction current runs down a
/// route; a square shape ties and takes x.
fn chain_is_horizontal(host: Bbox) -> bool {
    host.width().raw() >= host.height().raw()
}

/// Where a connection to `other` lands on `host`, as a coordinate on `host`'s
/// long axis.
///
/// The centre of the two boxes' overlap. Boxes that only touch have no overlap,
/// and then the other box's centre clamped into `host` is the same point in the
/// limit.
fn tap_on(host: Bbox, other: Bbox) -> Dbu {
    let landed = match host.intersection(other) {
        Some(shared) => centre(shared),
        // Two boxes sharing only a corner have an empty intersection, and their
        // tap is still a real point on `host`.
        None => centre(other),
    };
    let (lo, hi, along) = if chain_is_horizontal(host) {
        (host.xlo, host.xhi, landed.x)
    } else {
        (host.ylo, host.yhi, landed.y)
    };
    Dbu::new_unchecked(along.raw().clamp(lo.raw(), hi.raw()))
}

/// The node position of a tap sitting at `along` on `host`'s long axis.
///
/// Across the chain the node sits at the conductor's centre line, which is what
/// makes the model one-dimensional: a polygon is a chain, not a sheet.
fn tap_point(host: Bbox, along: Dbu) -> Point {
    let middle = centre(host);
    if chain_is_horizontal(host) {
        Point {
            x: along,
            y: middle.y,
        }
    } else {
        Point {
            x: middle.x,
            y: along,
        }
    }
}

/// The conductor's cross-section along one shape's chain, exactly.
///
/// A piecewise-constant width profile: slab cuts ascending, and the covered
/// cross-section between each adjacent pair. This is what stops a bounding box
/// standing in for a route — an L of `100 × 100` on ten-wide arms profiles to
/// `9.1` squares and boxes to `1.0`, and under-reporting resistance by that
/// factor is fail-open for all four rules that read a solved grid. A rectangle
/// profiles to one slab of its own short dimension.
///
/// Still one-dimensional: transverse resistance within a slab is not modelled.
#[derive(Debug, Default)]
struct ChainProfile {
    /// Slab boundaries along the chain axis, ascending and deduplicated.
    /// `cut.len() == width.len() + 1` for a shape that spans anything at all.
    cut: Vec<Dbu>,
    /// Covered cross-section between `cut[k]` and `cut[k + 1]`, floored at one
    /// database unit so it is never a zero denominator.
    width: Vec<Dbu>,
    /// The ring's edges as `(lo, hi, across)` on the chain axis, sorted by
    /// `lo` — the sweep's input. A *perpendicular* edge has `lo == hi`, so the
    /// slab predicate `lo <= t0 && hi >= t1` with `t0 < t1` is unsatisfiable
    /// for it and its `across` is never read. Same trick, and the same reason,
    /// as [`gpurify_core::rects`]'s edge table.
    edge: Vec<(Dbu, Dbu, Dbu)>,
    /// The sweep's active-edge list, which after each slab's retirement *is*
    /// that slab's crossing set.
    active: Vec<(Dbu, Dbu, Dbu)>,
    crossing: Vec<Dbu>,
}

impl ChainProfile {
    /// Profile one shape, clearing and refilling.
    ///
    /// A vertical-slab sweep against an active-edge list: `O(V log V)` for the
    /// two sorts plus `O(V + C)` for the sweep.
    fn build(&mut self, store: &GeometryStore, poly: PolyId) {
        let host = store.poly_bbox(poly);
        let (xs, ys) = store.poly_verts(poly);
        debug_assert_eq!(
            xs.len(),
            ys.len(),
            "a ring's coordinate columns are parallel"
        );
        debug_assert!(
            xs.len() >= 3,
            "a validated ring has at least three vertices"
        );

        let (along, across) = if chain_is_horizontal(host) {
            (xs, ys)
        } else {
            (ys, xs)
        };
        let n = along.len();

        self.cut.clear();
        self.cut.extend_from_slice(along);
        self.cut.sort_unstable();
        self.cut.dedup();

        // One edge per vertex, the wrap edge as a fixup after the pair scan.
        self.edge.clear();
        self.edge.reserve(n);
        for k in 0..n - 1 {
            let (a, b) = (along[k], along[k + 1]);
            self.edge.push((a.min(b), a.max(b), across[k]));
        }
        let (a, b) = (along[n - 1], along[0]);
        self.edge.push((a.min(b), a.max(b), across[n - 1]));
        debug_assert_eq!(self.edge.len(), n, "one edge per vertex");
        self.edge.sort_unstable();

        self.width.clear();
        self.active.clear();
        let mut admitted = 0usize;
        for k in 0..self.cut.len().saturating_sub(1) {
            let (t0, t1) = (self.cut[k], self.cut[k + 1]);
            debug_assert!(t0 < t1, "the slab list is sorted and deduplicated");

            // Admit every edge that has started by this slab. The list is
            // sorted by `lo` and `t0` ascends, so each edge is admitted once
            // and the cursor never rewinds.
            while admitted < self.edge.len() && self.edge[admitted].0 <= t0 {
                self.active.push(self.edge[admitted]);
                admitted += 1;
            }
            // Retire every edge that ends before this slab: `t1` only grows, so
            // one that fails here fails at every slab after it. What survives
            // crosses this slab side to side, which is exactly its crossing set.
            self.active.retain(|&(_, hi, _)| hi >= t1);

            self.crossing.clear();
            self.crossing.extend(self.active.iter().map(|&(_, _, c)| c));
            self.crossing.sort_unstable();
            // A vertical line through the interior of a slab enters and leaves
            // the ring the same number of times, so the crossings pair up and
            // the metal is what lies between each pair.
            debug_assert!(
                self.crossing.len().is_multiple_of(2),
                "a closed ring is crossed an even number of times"
            );
            let mut covered = 0i64;
            for pair in self.crossing.chunks_exact(2) {
                covered += pair[1].raw() - pair[0].raw();
            }
            self.width.push(Dbu::new_unchecked(covered.max(1)));
        }

        debug_assert_eq!(
            self.cut.len(),
            self.width.len() + 1,
            "one slab between each adjacent pair of cuts"
        );
        debug_assert!(
            self.width.iter().all(|w| w.raw() > 0),
            "a zero width is a zero denominator"
        );
    }

    /// One chain segment: the squares of conductor between two taps, and the
    /// narrowest cross-section anywhere along it.
    ///
    /// The squares are `∫ ds / w(s)`, which reduces to `L / W` on the single slab
    /// a rectangle profiles to. The narrowest slab is what a current density
    /// divides by: the density peaks where the metal is thinnest, so taking the
    /// mean would report the peak as lower than it is.
    ///
    /// Folded left over ascending slabs, so the sum is the same bits every run.
    fn segment(&self, from: Dbu, to: Dbu) -> (f64, Dbu) {
        debug_assert!(from.raw() < to.raw(), "a chain segment runs forwards");
        debug_assert!(
            self.cut.first().is_some_and(|c| c.raw() <= from.raw())
                && self.cut.last().is_some_and(|c| c.raw() >= to.raw()),
            "a tap sits outside the shape it taps"
        );

        let mut squares = 0.0f64;
        let mut narrow = i64::MAX;
        for k in 0..self.width.len() {
            let lo = self.cut[k].raw().max(from.raw());
            let hi = self.cut[k + 1].raw().min(to.raw());
            let overlap = (hi - lo).max(0);
            let w = self.width[k].raw();
            #[allow(
                clippy::cast_precision_loss,
                reason = "both are bounded by MAX_ABS_DBU = 2^40, well inside an f64's exact integers"
            )]
            let ratio = overlap as f64 / w as f64;
            squares += ratio;
            // A slab this segment does not touch blends in as `i64::MAX`, which
            // loses every `min`.
            let mask = i64::from(overlap > 0).wrapping_neg();
            narrow = narrow.min((w & mask) | (i64::MAX & !mask));
        }

        debug_assert!(
            squares > 0.0 && squares.is_finite(),
            "a segment of positive length over a positive width has positive squares"
        );
        debug_assert!(
            narrow < i64::MAX,
            "a segment of positive length crossed no slab"
        );
        (squares, Dbu::new_unchecked(narrow))
    }
}

/// The conductor width a current density divides by: the narrower shape's
/// narrow dimension, floored so it is never a zero denominator.
fn conductor_width(a: Bbox, b: Bbox) -> Dbu {
    let narrow = |s: Bbox| s.width().raw().min(s.height().raw());
    Dbu::new_unchecked(narrow(a).min(narrow(b)).max(1))
}

/// The length of the segment between two taps.
///
/// Manhattan, because routing is. Floored at one database unit: a zero length
/// makes the Blech product zero, and a segment below the Blech limit is *exempt*
/// from electromigration, so a zero-length segment would exempt itself.
fn run_length(from: Point, to: Point) -> Dbu {
    let span = (from.x.raw() - to.x.raw()).abs() + (from.y.raw() - to.y.raw()).abs();
    Dbu::new_unchecked(span.max(1))
}

/// How long a via is: the height the process stack puts between its two
/// conductors, floored at one database unit.
///
/// The floor is the point: a zero length makes the Blech product zero, and a
/// segment below the Blech limit is *exempt* from electromigration.
fn via_length(process: Process<'_>, lower: LayerId, upper: LayerId) -> Dbu {
    let height = |layer: LayerId| {
        process
            .stack
            .height_nm
            .get(layer.idx())
            .copied()
            .unwrap_or(0.0)
    };
    #[allow(
        clippy::cast_precision_loss,
        reason = "a grid's database units per micrometre is a small positive integer"
    )]
    let per_um = process.grid.dbu_per_um() as f64;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "clamped into the Dbu range on the next line"
    )]
    let span = ((height(upper) - height(lower)).abs() * 1e-3 * per_um).round() as i64;
    Dbu::new_unchecked(span.clamp(1, MAX_ABS_DBU))
}

/// Squares of conductor in a segment: a ratio of two exact `Dbu`, so no grid
/// conversion enters and the result is exact ohms per exact squares.
fn squares(length: Dbu, width: Dbu) -> f64 {
    debug_assert!(width.raw() > 0, "a zero width is a zero denominator");
    #[allow(
        clippy::cast_precision_loss,
        reason = "both are bounded by MAX_ABS_DBU = 2^40, well inside an f64's exact integers"
    )]
    let ratio = length.raw() as f64 / width.raw() as f64;
    ratio
}

/// Build one resistor network per net that has at least two device terminals.
///
/// Caller owns `out`, cleared and refilled. Rows are emitted ascending by
/// [`NetId`], so the result does not depend on how the work was partitioned.
///
/// Independent of design intent: geometry and sheet resistance only, which is
/// why point-to-point resistance always runs.
pub fn extract_nets_into(
    store: &GeometryStore,
    nets: &NetTable,
    devices: &DeviceTable,
    process: Process<'_>,
    out: &mut NetNetworks,
) -> Result<(), PowerError> {
    debug_assert!(
        u32::try_from(nets.net_count()).is_ok() && u32::try_from(store.poly_count()).is_ok(),
        "both id spaces this walks are u32, so both counts must fit one"
    );
    out.net.clear();
    out.node_start.clear();
    out.node_at.clear();
    out.node_poly.clear();
    out.terminal_start.clear();
    out.terminal.clear();
    out.edge_start.clear();
    out.edge_from.clear();
    out.edge_to.clear();
    out.edge_resistance.clear();

    let conductor = conductor_mask(process.connectivity, store.layer_count());
    let sheet = sheet_resistances(process, store.layer_count())?;

    // Every net's conducting shapes, flat and grouped by net, plus each shape's
    // index *within its own net's row* — which is the space the chain below, and
    // therefore `NetNetworks`, states its endpoints in.
    let mut candidate: Vec<PolyId> = Vec::new();
    let mut candidate_start: Vec<u32> = Vec::with_capacity(nets.net_count() + 1);
    let mut shape_in_row = vec![NONE; store.poly_count()];
    let mut kept: Vec<PolyId> = Vec::new();
    candidate_start.push(0);
    for net in 0..nets.net_count() {
        let id = NetId(u32::try_from(net).expect("a net id is a u32"));
        // The same branchless compact `extract_into` runs over a supply's
        // polygons.
        let polys = nets.polys_of(id);
        kept.clear();
        kept.reserve(polys.len());
        let slots = &mut kept.spare_capacity_mut()[..polys.len()];
        let mut w = 0usize;
        for (i, &poly) in polys.iter().enumerate() {
            let keep = conductor[store.poly_layer(poly).idx()];
            // `w <= i` by induction: `w` is `0` when `i` is, and `bool` is 0 or
            // 1, so `w` advances by at most the one `i` advances by.
            debug_assert!(w <= i);
            // SAFETY: `w <= i < polys.len() == slots.len()` from the induction
            // above. Rejected slots stay uninit and `set_len(w)` truncates them
            // away; `PolyId` is `Copy`, so none of them has a `Drop`.
            unsafe { slots.get_unchecked_mut(w) }.write(poly);
            w += usize::from(keep);
        }
        // SAFETY: slot `k` was written on the iteration where `w` held `k`, for
        // every `k` in `0..w`, and `w <= polys.len() <= kept.capacity()`.
        unsafe { kept.set_len(w) };
        debug_assert!(kept.len() <= polys.len(), "a compact cannot grow its input");

        for (index, &poly) in kept.iter().enumerate() {
            shape_in_row[poly.idx()] = u32::try_from(index).expect("a shape index is a u32");
        }
        candidate.extend_from_slice(&kept);
        candidate_start.push(u32::try_from(candidate.len()).expect("a shape index is a u32"));
    }

    // Connections, bucketed by net. Sorting makes the emitted rows a function of
    // the layout rather than of the order the layer scans ran in; both endpoints
    // of a connection are the same net, so keying on one is enough.
    let mut links = Connections::default();
    connections_into(store, process.connectivity, &mut links);
    let by_net = |&(a, b, layer): &(u32, u32, LayerId)| (nets.net_of(PolyId(a)).0, a, b, layer.0);
    links.metal.sort_unstable_by_key(by_net);
    links.via.sort_unstable_by_key(by_net);

    let mut terminal: Vec<u32> = Vec::new();
    let mut index = TapIndex::default();
    let mut taps = TapTable::default();
    let mut profile = ChainProfile::default();
    for net in 0..nets.net_count() {
        let id = NetId(u32::try_from(net).expect("a net id is a u32"));
        let (from, to) = (
            candidate_start[net] as usize,
            candidate_start[net + 1] as usize,
        );
        let shapes = to - from;
        terminal.clear();
        taps.clear();
        // The net's own slice of each sorted connection list.
        let key = u32::try_from(net).expect("a net id is a u32");
        let metal = net_slice(&links.metal, key, nets);
        let via = net_slice(&links.via, key, nets);

        // Every shape carries a tap at its own centre first, so a shape nothing
        // connects to still has a node; then one per connection end, which cuts
        // each shape's chain where something actually lands on it.
        for local in 0..shapes {
            let host = store.poly_bbox(candidate[from + local]);
            taps.push(
                u32::try_from(local).expect("a shape index is a u32"),
                tap_on(host, host),
            );
        }
        let metal_req = u32::try_from(taps.req_shape.len()).expect("a tap request is a u32");
        for &(a, b, _) in metal {
            let (host_a, host_b) = (store.poly_bbox(PolyId(a)), store.poly_bbox(PolyId(b)));
            taps.push(shape_in_row[a as usize], tap_on(host_a, host_b));
            taps.push(shape_in_row[b as usize], tap_on(host_b, host_a));
        }
        let via_req = u32::try_from(taps.req_shape.len()).expect("a tap request is a u32");
        for &(a, b, _) in via {
            let (host_a, host_b) = (store.poly_bbox(PolyId(a)), store.poly_bbox(PolyId(b)));
            taps.push(shape_in_row[a as usize], tap_on(host_a, host_b));
            taps.push(shape_in_row[b as usize], tap_on(host_b, host_a));
        }

        // A net with no conducting shape has nothing to attach to.
        let mut attach: Vec<u32> = Vec::new();
        if shapes > 0 {
            TapIndex::build_into(store, &candidate[from..to], &mut index);
            for &device in devices.devices_on(id) {
                let marker = centre(store.poly_bbox(devices.marker[device.0 as usize]));
                let (on, _) = devices.terminals_of(device);
                // A device with two terminals on this net still taps it once, at
                // one place; the terminal list is node indices, and a node named
                // twice would make one probe appear twice.
                let attached = on.contains(&id);
                let local = index.nearest(marker);
                let host = store.poly_bbox(candidate[from + local as usize]);
                let request = taps.push(local, tap_on(host, Bbox::point(marker.x, marker.y)));
                attach.resize(attach.len() + usize::from(attached), request);
            }
        }
        taps.finish(shapes);

        for &request in &attach {
            terminal.push(taps.req_node[request as usize]);
        }
        terminal.sort_unstable();
        terminal.dedup();

        // A net with fewer than two attach points has no pair to measure, so it
        // has no row at all — reporting it clean would be a claim about nothing.
        if terminal.len() < 2 {
            continue;
        }

        let base = u32::try_from(out.node_poly.len()).expect("a node index is a u32");
        out.net.push(id);
        out.terminal.extend_from_slice(&terminal);
        for node in 0..taps.node_shape.len() {
            let poly = candidate[from + taps.node_shape[node] as usize];
            out.node_poly.push(poly);
            out.node_at
                .push(tap_point(store.poly_bbox(poly), taps.node_along[node]));
        }

        for local in 0..shapes {
            let poly = candidate[from + local];
            let layer = store.poly_layer(poly);
            profile.build(store, poly);
            let (lo, hi) = taps.chain_of(u32::try_from(local).expect("a shape index is a u32"));
            for node in lo..hi.saturating_sub(1) {
                // The metal the segment actually has, exactly as `extract_into`
                // spends it: the two networks are the same model.
                let (squares, _) =
                    profile.segment(taps.node_along[node], taps.node_along[node + 1]);
                out.edge_from
                    .push(u32::try_from(node).expect("a node index is a u32"));
                out.edge_to
                    .push(u32::try_from(node + 1).expect("a node index is a u32"));
                out.edge_resistance
                    .push(Qty::new(sheet[layer.idx()] * squares));
            }
        }

        for (link, &(a, b, layer)) in metal.iter().enumerate() {
            let (host_a, host_b) = (store.poly_bbox(PolyId(a)), store.poly_bbox(PolyId(b)));
            let (ra, rb) = (
                metal_req as usize + 2 * link,
                metal_req as usize + 2 * link + 1,
            );
            let (node_a, node_b) = (taps.req_node[ra], taps.req_node[rb]);
            // The two taps are the same physical point, so the length is the
            // floor; the metal between them is carried by the two chains above.
            let length = run_length(
                out.node_at[(base + node_a) as usize],
                out.node_at[(base + node_b) as usize],
            );
            out.edge_from.push(node_a);
            out.edge_to.push(node_b);
            out.edge_resistance.push(Qty::new(
                sheet[layer.idx()] * squares(length, conductor_width(host_a, host_b)),
            ));
        }
        for (link, &(_, _, cut)) in via.iter().enumerate() {
            let (ra, rb) = (via_req as usize + 2 * link, via_req as usize + 2 * link + 1);
            out.edge_from.push(taps.req_node[ra]);
            out.edge_to.push(taps.req_node[rb]);
            // One square of the cut layer, per cut, exactly as `extract_into`
            // spends it.
            out.edge_resistance.push(Qty::new(sheet[cut.idx()]));
        }

        out.node_start
            .push(u32::try_from(out.node_poly.len()).expect("a node index is a u32"));
        out.terminal_start
            .push(u32::try_from(out.terminal.len()).expect("a terminal index is a u32"));
        out.edge_start
            .push(u32::try_from(out.edge_from.len()).expect("an edge index is a u32"));
    }

    // The three offset columns carry `rows + 1` entries, so the leading zero
    // goes in only once there is a row — an empty result is every column empty,
    // which is what `Default` produces and what `len` asserts against.
    if !out.net.is_empty() {
        out.node_start.insert(0, 0);
        out.terminal_start.insert(0, 0);
        out.edge_start.insert(0, 0);
    }

    debug_assert!(
        out.net.windows(2).all(|w| w[0] < w[1]),
        "rows are emitted ascending by NetId, whatever partitioned the work"
    );
    debug_assert!(
        (0..u32::try_from(out.len()).expect("a row index is a u32")).all(|row| {
            let bound = u32::try_from(out.nodes_of(row).0.len()).expect("a node index is a u32");
            let (from, to, _) = out.edges_of(row);
            out.terminals_of(row).iter().all(|&t| t < bound)
                && from.iter().chain(to).all(|&n| n < bound)
        }),
        "a row names a node it does not have"
    );
    debug_assert!(
        out.edge_resistance
            .iter()
            .all(|r| r.raw() > 0.0 && r.is_finite()),
        "an extracted edge has no positive finite resistance"
    );
    Ok(())
}

/// One net's run of a connection list already sorted by net.
///
/// `partition_point` twice rather than a linear scan, which over millions of
/// rows once per net would be quadratic.
fn net_slice<'a>(
    links: &'a [(u32, u32, LayerId)],
    net: u32,
    nets: &NetTable,
) -> &'a [(u32, u32, LayerId)] {
    let of = |&(a, _, _): &(u32, u32, LayerId)| nets.net_of(PolyId(a)).0;
    let from = links.partition_point(|link| of(link) < net);
    let to = from + links[from..].partition_point(|link| of(link) == net);
    &links[from..to]
}

/// Solve the grid for node voltages and branch currents.
///
/// `out` is cleared and refilled to the grid's node and edge counts; `scratch`
/// survives the call so a loop over grids allocates once.
///
/// Fixed-voltage nodes are eliminated before the iteration rather than
/// constrained inside it, which leaves a symmetric positive-definite system.
/// Unanchored islands are rejected first, because CG on a singular system
/// converges to *a* solution whose drop is meaningless.
pub fn solve_into(
    grid: &PowerGrid,
    config: SolveConfig,
    scratch: &mut SolveScratch,
    out: &mut PowerSolution,
) -> Result<(), PowerError> {
    let nodes = grid.node_count();
    let edges = grid.edge_count();
    let node_width = u32::try_from(nodes).expect("a node index is a u32");
    debug_assert!(
        grid.edge_from
            .iter()
            .chain(&grid.edge_to)
            .all(|&n| n < node_width),
        "an edge names a node the grid does not have"
    );
    debug_assert!(
        grid.source_node.iter().all(|&n| n < node_width),
        "a pad names a node the grid does not have"
    );

    out.node_voltage.clear();
    out.node_drop.clear();
    out.branch_current.clear();
    out.iterations = 0;
    out.relative_residual = 0.0;

    // Non-finite inputs first: a `NaN` load reaches every column downstream and
    // makes every check after this one pass.
    debug_assert_eq!(
        grid.node_nominal.len(),
        grid.node_load.len(),
        "SoA columns must agree: one nominal and one load per node"
    );
    let mut finite = true;
    for i in 0..grid.node_nominal.len() {
        finite &= grid.node_nominal[i].is_finite() & grid.node_load[i].is_finite();
    }
    for i in 0..grid.source_voltage.len() {
        finite &= grid.source_voltage[i].is_finite();
    }
    if !finite {
        let node = grid
            .node_nominal
            .iter()
            .zip(&grid.node_load)
            .position(|(v, i)| !(v.is_finite() && i.is_finite()))
            .or_else(|| {
                grid.source_voltage
                    .iter()
                    .position(|v| !v.is_finite())
                    .map(|pad| grid.source_node[pad] as usize)
            })
            .expect("the fold found a non-finite value in one of these columns");
        return Err(PowerError::NotFinite(
            u32::try_from(node).expect("a node index is a u32"),
        ));
    }

    // A zero resistance is the dangerous one: it shorts two nodes and silently
    // removes a drop the design has.
    let mut sound = true;
    for i in 0..grid.edge_resistance.len() {
        let r = grid.edge_resistance[i];
        sound &= (r.raw() > 0.0) & r.is_finite();
    }
    if !sound {
        let edge = grid
            .edge_resistance
            .iter()
            .position(|r| !(r.raw() > 0.0 && r.is_finite()))
            .expect("the fold found an unusable resistance in this column");
        return Err(PowerError::BadResistance(
            u32::try_from(edge).expect("an edge index is a u32"),
        ));
    }

    // No pad at all, which includes the empty grid. Refusing here stops a caller
    // building a `Solved` over nothing and reporting four rules clean against it.
    if grid.source_node.is_empty() {
        return Err(PowerError::Unanchored);
    }

    let SolveScratch {
        pairs,
        labels,
        reached,
        ..
    } = &mut *scratch;
    debug_assert_eq!(
        grid.edge_from.len(),
        grid.edge_to.len(),
        "SoA columns must agree: one endpoint pair per edge"
    );
    pairs.clear();
    pairs.reserve(edges);
    for i in 0..grid.edge_from.len() {
        pairs.push((grid.edge_from[i], grid.edge_to[i]));
    }
    components_into(node_width, pairs, labels);
    debug_assert_eq!(labels.len(), nodes, "one component label per node");

    reached.clear();
    reached.resize(nodes, false);
    for &pad in &grid.source_node {
        reached[labels[pad as usize].0 as usize] = true;
    }
    let mut anchored = true;
    for i in 0..labels.len() {
        anchored &= reached[labels[i].0 as usize];
    }
    if !anchored {
        let node = labels
            .iter()
            .position(|l| !reached[l.0 as usize])
            .expect("the fold found a component no pad reaches");
        return Err(PowerError::UnanchoredIsland(
            u32::try_from(node).expect("a node index is a u32"),
        ));
    }

    // Eliminate the pads: every node that is not one gets an unknown index, and
    // the inverse map is what scatters the answer back afterwards.
    let is_pad = &mut scratch.is_pad;
    is_pad.clear();
    is_pad.resize(nodes, false);
    for &pad in &grid.source_node {
        is_pad[pad as usize] = true;
    }
    scratch.unknown_of_node.clear();
    scratch.unknown_of_node.resize(nodes, NOT_AN_UNKNOWN);
    scratch.node_of_unknown.clear();
    scratch.node_of_unknown.resize(nodes + 1, 0);
    let mut unknowns = 0u32;
    // `NOT_AN_UNKNOWN` is all ones, so a pad's index is the running one smeared
    // to the sentinel and only the cursor carries the decision.
    for (node, &pad) in is_pad.iter().enumerate() {
        scratch.unknown_of_node[node] = unknowns | u32::from(pad).wrapping_neg();
        scratch.node_of_unknown[unknowns as usize] =
            u32::try_from(node).expect("a node index is a u32");
        unknowns += u32::from(!pad);
    }
    let unknowns = unknowns as usize;
    scratch.node_of_unknown.truncate(unknowns);
    debug_assert_eq!(
        unknowns + grid.source_node.len(),
        nodes,
        "every node is either a pad or an unknown, exactly once"
    );

    // Node voltages start where every drop is measured from: pads at their fixed
    // voltage, unknowns at their domain's nominal. Not merely a warm start — the
    // residual then measures the interconnect loss alone, so
    // `relative_tolerance` is a fraction of the *drop* rather than of the supply.
    out.node_voltage.extend_from_slice(&grid.node_nominal);
    for (pad, &node) in grid.source_node.iter().enumerate() {
        out.node_voltage[node as usize] = grid.source_voltage[pad];
    }

    // Through the inverse map, so the solver's vectors are in unknown space and
    // the node space never enters the iteration.
    scratch.x.clear();
    scratch.x.reserve(unknowns);
    for i in 0..unknowns {
        let node = scratch.node_of_unknown[i] as usize;
        scratch.x.push(out.node_voltage[node].raw());
    }
    // Kirchhoff at an unknown: the branch currents into it sum to the current
    // drawn there, so the Laplacian row equals *minus* the load.
    scratch.rhs.clear();
    scratch.rhs.reserve(unknowns);
    for i in 0..unknowns {
        let node = scratch.node_of_unknown[i] as usize;
        scratch.rhs.push(-grid.node_load[node].raw());
    }

    // A conductance to a fixed potential moves `g * v` across to the right-hand
    // side. The slot past the last unknown absorbs whatever a pad-ended row
    // would have written.
    scratch.rhs.push(0.0);
    for edge in 0..edges {
        let (from, to) = (grid.edge_from[edge] as usize, grid.edge_to[edge] as usize);
        let g = UA_PER_MV_OHM / grid.edge_resistance[edge].raw();
        let (a, b) = (scratch.unknown_of_node[from], scratch.unknown_of_node[to]);
        let (a_unknown, b_unknown) = (a != NOT_AN_UNKNOWN, b != NOT_AN_UNKNOWN);
        let a_row = (a as usize).min(unknowns);
        let b_row = (b as usize).min(unknowns);
        scratch.rhs[a_row] +=
            g * out.node_voltage[to].raw() * f64::from(u8::from(a_unknown & !b_unknown));
        scratch.rhs[b_row] +=
            g * out.node_voltage[from].raw() * f64::from(u8::from(b_unknown & !a_unknown));
    }
    scratch.rhs.truncate(unknowns);

    let SolveScratch {
        branch,
        unknown_of_node,
        ..
    } = &mut *scratch;
    debug_assert_eq!(
        grid.edge_from.len(),
        grid.edge_to.len(),
        "SoA columns must agree: one endpoint pair per edge"
    );
    debug_assert_eq!(
        grid.edge_from.len(),
        grid.edge_resistance.len(),
        "SoA columns must agree: one resistance per edge"
    );
    branch.clear();
    branch.reserve(edges);
    for i in 0..grid.edge_from.len() {
        branch.push((
            unknown_of_node[grid.edge_from[i] as usize],
            unknown_of_node[grid.edge_to[i] as usize],
            UA_PER_MV_OHM / grid.edge_resistance[i].raw(),
        ));
    }
    assemble_into(scratch, unknowns);
    let (iterations, relative_residual) = conjugate_gradient(scratch, config)?;

    // The pads keep the exact voltage they were fixed at, which is the boundary
    // condition and not an approximation to it.
    for unknown in 0..unknowns {
        out.node_voltage[scratch.node_of_unknown[unknown] as usize] = Qty::new(scratch.x[unknown]);
    }

    let PowerSolution {
        node_voltage,
        node_drop,
        branch_current,
        ..
    } = &mut *out;
    debug_assert_eq!(
        grid.node_nominal.len(),
        node_voltage.len(),
        "SoA columns must agree: one nominal per solved node"
    );
    node_drop.clear();
    node_drop.reserve(nodes);
    // Resliced, not zipped raw: a short voltage column is a panic in every
    // profile rather than a silently-short drop column.
    let solved = &node_voltage[..grid.node_nominal.len()];
    node_drop.extend(
        grid.node_nominal
            .iter()
            .zip(solved)
            .map(|(&nominal, &v)| nominal - v),
    );
    branch_current.clear();
    branch_current.reserve(edges);
    for i in 0..grid.edge_from.len() {
        let across = node_voltage[grid.edge_from[i] as usize].raw()
            - node_voltage[grid.edge_to[i] as usize].raw();
        let g = UA_PER_MV_OHM / grid.edge_resistance[i].raw();
        branch_current.push(Qty::new(across * g));
    }
    out.iterations = iterations;
    out.relative_residual = relative_residual;

    if !out.is_consistent_with(grid) {
        // The three columns are the grid's lengths by construction above, so the
        // only way here is a value that stopped being finite during the solve.
        let node = out
            .node_voltage
            .iter()
            .zip(&out.node_drop)
            .position(|(v, d)| !(v.is_finite() && d.is_finite()))
            .or_else(|| {
                out.branch_current
                    .iter()
                    .position(|c| !c.is_finite())
                    .map(|edge| grid.edge_from[edge] as usize)
            })
            .unwrap_or(0);
        return Err(PowerError::NotFinite(
            u32::try_from(node).expect("a node index is a u32"),
        ));
    }
    Ok(())
}

/// Effective resistance between every terminal pair of one net's network.
///
/// `out` is cleared and refilled with `(terminal_a, terminal_b, resistance)` for
/// every pair with `a < b` in one connected component, ascending. A pair split
/// across components is absent rather than reported as infinite.
///
/// Non-terminal nodes are Kron-eliminated in minimum-degree order, leaving a
/// graph over the terminals alone; that is grounded per component and inverted
/// directly, so the probe carries no tolerance at all. Cost is the fill-in plus
/// a `k × k` inverse; upgrade to nested dissection if that ever dominates.
pub fn effective_resistance_into(
    networks: &NetNetworks,
    row: u32,
    scratch: &mut SolveScratch,
    out: &mut Vec<(u32, u32, Qty<Resistance, { prefix::BASE }>)>,
) -> Result<(), PowerError> {
    out.clear();
    debug_assert!(
        (row as usize) < networks.len(),
        "row {row} is not a row this table has"
    );

    let nodes = networks.nodes_of(row).0.len();
    let terminal = networks.terminals_of(row);
    let (edge_from, edge_to, edge_resistance) = networks.edges_of(row);
    let node_width = u32::try_from(nodes).expect("a node index is a u32");
    debug_assert!(
        terminal.windows(2).all(|w| w[0] < w[1]),
        "the terminal column is ascending and names each node once"
    );
    debug_assert!(
        terminal.iter().all(|&t| t < node_width),
        "a terminal names a node the row does not have"
    );
    debug_assert!(
        edge_from.iter().chain(edge_to).all(|&n| n < node_width),
        "an edge names a node the row does not have"
    );

    // Fail closed as `solve_into` does. The index named is the edge's index
    // *within the row*, which is what `edges_of` hands the caller.
    let mut sound = true;
    for &r in edge_resistance {
        sound &= (r.raw() > 0.0) & r.is_finite();
    }
    if !sound {
        let edge = edge_resistance
            .iter()
            .position(|r| !(r.raw() > 0.0 && r.is_finite()))
            .expect("the fold found an unusable resistance in this column");
        return Err(PowerError::BadResistance(
            u32::try_from(edge).expect("an edge index is a u32"),
        ));
    }

    let SolveScratch {
        pairs,
        labels,
        reached: done,
        elim,
        dense,
        local,
        inverse,
        probe,
        terminal_of_node,
        group,
        ..
    } = scratch;
    debug_assert_eq!(
        edge_from.len(),
        edge_to.len(),
        "SoA columns must agree: one endpoint pair per edge"
    );
    pairs.clear();
    pairs.reserve(edge_from.len());
    for i in 0..edge_from.len() {
        pairs.push((edge_from[i], edge_to[i]));
    }
    components_into(node_width, pairs, labels);
    debug_assert_eq!(labels.len(), nodes, "one component label per node");

    let terminals = terminal.len();
    terminal_of_node.clear();
    terminal_of_node.resize(nodes, NONE);
    for (index, &t) in terminal.iter().enumerate() {
        terminal_of_node[t as usize] = u32::try_from(index).expect("a terminal index is a u32");
    }

    // Kron-eliminate every interior tap. What is left is a graph over the
    // terminals alone, so everything after this is sized by the terminal count
    // and the tap count never enters again.
    elim.reset(nodes);
    for edge in 0..edge_from.len() {
        let (a, b) = (edge_from[edge], edge_to[edge]);
        // A self loop carries no current and loads no node.
        if a != b {
            elim.link(a, b, 1.0 / edge_resistance[edge].raw());
        }
    }
    for (node, &of_node) in terminal_of_node.iter().enumerate() {
        // Interior taps only; a terminal is what the elimination retains.
        if of_node == NONE {
            let v = u32::try_from(node).expect("a node index is a u32");
            let degree = elim.refresh(v);
            elim.queue.push(Reverse((degree, v)));
        }
    }
    // Minimum degree, cheapest first, queue lazily invalidated: a popped entry
    // whose degree no longer matches is re-queued at its current one.
    while let Some(Reverse((degree, v))) = elim.queue.pop() {
        if !elim.alive[v as usize] {
            continue;
        }
        let now = elim.refresh(v);
        if now != degree {
            elim.queue.push(Reverse((now, v)));
            continue;
        }
        elim.eliminate(v);
        // The fringe is what the elimination just made denser, and the only
        // degrees that can have changed.
        for i in 0..elim.fringe.len() {
            let u = elim.fringe[i].0;
            if terminal_of_node[u as usize] == NONE {
                let updated = elim.refresh(u);
                elim.queue.push(Reverse((updated, u)));
            }
        }
    }
    debug_assert!(
        (0..nodes).all(|n| !elim.alive[n] || terminal_of_node[n] != NONE),
        "an interior tap survived the elimination"
    );

    // Row-major, `k × k`, symmetric by construction — each edge is walked from
    // both ends.
    dense.clear();
    dense.resize(terminals * terminals, 0.0);
    for (i, &t) in terminal.iter().enumerate() {
        elim.refresh(t);
        let mut h = elim.head[t as usize];
        while h != NONE {
            let j = terminal_of_node[elim.dst[h as usize] as usize] as usize;
            debug_assert!(j < terminals, "the elimination left a non-terminal behind");
            let w = elim.g[h as usize];
            dense[i * terminals + j] -= w;
            dense[i * terminals + i] += w;
            h = elim.next[h as usize];
        }
    }

    // One dense solve per component: ground its lowest-numbered terminal and
    // invert what is left.
    probe.clear();
    probe.resize(terminals * terminals, 0.0);
    done.clear();
    done.resize(terminals, false);
    for start in 0..terminals {
        if done[start] {
            continue;
        }
        let component = labels[terminal[start] as usize];
        group.clear();
        for (i, &t) in terminal.iter().enumerate().skip(start) {
            if labels[t as usize] == component {
                done[i] = true;
                group.push(u32::try_from(i).expect("a terminal index is a u32"));
            }
        }
        // A component with one terminal has no pair to measure.
        let unknowns = group.len() - 1;
        if unknowns == 0 {
            continue;
        }

        // Ground `group[0]`, the lowest-numbered terminal of the component, and
        // keep the rest. Grounding is what turns a singular Laplacian into the
        // positive-definite matrix the Cholesky below wants.
        local.clear();
        local.resize(unknowns * unknowns, 0.0);
        for p in 0..unknowns {
            for q in 0..unknowns {
                let (a, b) = (group[p + 1] as usize, group[q + 1] as usize);
                local[p * unknowns + q] = dense[a * terminals + b];
            }
        }
        if !cholesky_inverse_into(local, unknowns, inverse) {
            return Err(PowerError::NotFinite(terminal[group[0] as usize]));
        }

        // `R(a, b) = X_aa + X_bb − 2 X_ab`, with the grounded terminal reading
        // as zero throughout — which is what makes `R(ground, b) = X_bb`.
        for p in 0..group.len() {
            for q in p + 1..group.len() {
                let keep = f64::from(u32::from(p != 0));
                let (pi, qi) = (p.max(1) - 1, q - 1);
                let xaa = inverse[pi * unknowns + pi] * keep;
                let xbb = inverse[qi * unknowns + qi];
                let xab = inverse[pi * unknowns + qi] * keep;
                probe[group[p] as usize * terminals + group[q] as usize] = xaa + xbb - 2.0 * xab;
            }
        }
    }

    // Every pair, `a < b`, ascending.
    for (i, &a) in terminal.iter().enumerate() {
        for (j, &b) in terminal.iter().enumerate().skip(i + 1) {
            // A pair split across components has no interconnect path, and the
            // interface says absent rather than infinite — an infinity compares
            // below every limit and reads as a pass.
            if labels[a as usize] != labels[b as usize] {
                continue;
            }
            let ohms = probe[i * terminals + j];
            debug_assert!(
                ohms > 0.0 && ohms.is_finite(),
                "R({a},{b}) came out as {ohms}, which is not a positive finite resistance"
            );
            out.push((a, b, Qty::new(ohms)));
        }
    }

    debug_assert!(
        out.windows(2).all(|w| (w[0].0, w[0].1) < (w[1].0, w[1].1)),
        "the probe list is ascending by terminal pair"
    );
    debug_assert!(
        out.len() <= terminal.len() * terminal.len(),
        "more probes than there are terminal pairs"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        assemble_into, factorise_into, ChainProfile, Point, SolveScratch, TapIndex, NOT_AN_UNKNOWN,
    };
    use gpurify_core::{GeometryStore, GeometryStoreBuilder, LayerId, PolyId};
    use gpurify_units::Dbu;

    /// One polygon on layer zero, from its rectilinear ring.
    fn shape(xs: &[i64], ys: &[i64]) -> GeometryStore {
        let mut builder = GeometryStoreBuilder::default();
        let xs: Vec<Dbu> = xs.iter().map(|&v| Dbu::new_unchecked(v)).collect();
        let ys: Vec<Dbu> = ys.iter().map(|&v| Dbu::new_unchecked(v)).collect();
        builder.push(LayerId(0), &xs, &ys);
        builder.finish(1).0
    }

    /// A rectangle is one slab of its own short dimension, so the whole-shape
    /// integral is the length-to-width ratio the model has always spent on it.
    /// That is what makes this change invisible to every closed-form test in
    /// the suite — and what makes those tests unable to see it go wrong, which
    /// is why this one is here.
    #[test]
    fn a_rectangle_profiles_to_its_own_length_over_its_own_width() {
        let store = shape(&[0, 400, 400, 0], &[0, 0, 10, 10]);
        let mut profile = ChainProfile::default();
        profile.build(&store, PolyId(0));

        assert_eq!(profile.width.len(), 1, "a rectangle spans one slab");
        let (squares, narrow) = profile.segment(Dbu::new_unchecked(0), Dbu::new_unchecked(400));
        assert!(
            (squares - 40.0).abs() < 1e-12,
            "400 by 10 is 40 squares, got {squares}"
        );
        assert_eq!(
            narrow.raw(),
            10,
            "the narrowest place in a rectangle is all of it"
        );
    }

    /// An L of `100 x 100` on ten-wide arms holds a hundred units of metal
    /// across the first ten of its span and ten across the remaining ninety, so
    /// `∫ ds / w(s)` is `10/100 + 90/10 = 9.1` squares. Its bounding box is
    /// square, so the model this replaced spent `100/100 = 1` — a resistance
    /// nine times low, which is a drop nine times low, which is fail-open for
    /// all four rules that read a solved grid.
    #[test]
    fn an_l_route_costs_the_squares_its_arms_have_and_not_its_bounding_box() {
        let store = shape(&[0, 100, 100, 10, 10, 0], &[0, 0, 10, 10, 100, 100]);
        let mut profile = ChainProfile::default();
        profile.build(&store, PolyId(0));

        let (squares, narrow) = profile.segment(Dbu::new_unchecked(0), Dbu::new_unchecked(100));
        assert!(
            (squares - 9.1).abs() < 1e-12,
            "the L integrates to 9.1 squares, got {squares}"
        );
        assert_eq!(narrow.raw(), 10, "the arm is the narrowest place on the L");
        assert!(
            squares > 9.0 * (100.0 / 100.0),
            "the bounding-box ratio is what this replaced"
        );
    }

    /// Rayleigh monotonicity, checked where it is produced rather than where it
    /// is observed: widening a polygon widens `w(s)` at every `s` it covers, so
    /// no segment of it can cost more squares than it did. The bounding-box
    /// model did **not** have this property — widening the short arm of an L
    /// past its long one flips the chain axis.
    #[test]
    fn widening_a_shape_can_only_lower_the_squares_a_segment_costs() {
        let narrow = shape(&[0, 100, 100, 10, 10, 0], &[0, 0, 10, 10, 100, 100]);
        let wide = shape(&[0, 100, 100, 10, 10, 0], &[0, 0, 20, 20, 100, 100]);
        let (mut thin, mut fat) = (ChainProfile::default(), ChainProfile::default());
        thin.build(&narrow, PolyId(0));
        fat.build(&wide, PolyId(0));

        for from in [0i64, 10, 40] {
            for to in [50i64, 80, 100] {
                let (before, _) = thin.segment(Dbu::new_unchecked(from), Dbu::new_unchecked(to));
                let (after, _) = fat.segment(Dbu::new_unchecked(from), Dbu::new_unchecked(to));
                assert!(
                    after <= before,
                    "widening {from}..{to} raised it from {before} to {after}"
                );
            }
        }
    }

    /// The defining property of an incomplete factorisation with zero fill: `L
    /// Lᵀ` agrees with the matrix **exactly** wherever the matrix is non-zero,
    /// and differs from it only where the pattern has a hole. A factor that
    /// fails this is not a preconditioner for this matrix, and conjugate
    /// gradients preconditioned by one is a recurrence with no reason to
    /// converge — which the suite would see as a tolerance failure on some
    /// design and not on the ones it has.
    ///
    /// A four-node cycle with one pad, which is the smallest network that has a
    /// hole to drop fill into: eliminating node 0 couples 1 and 3, and IC(0) is
    /// defined by refusing to store that coupling.
    #[test]
    fn an_incomplete_factor_reproduces_the_matrix_wherever_the_matrix_is_nonzero() {
        const N: usize = 4;
        let mut scratch = SolveScratch {
            branch: vec![
                (0, 1, 2.0),
                (1, 2, 4.0),
                (2, 3, 8.0),
                (3, 0, 16.0),
                (0, NOT_AN_UNKNOWN, 32.0),
            ],
            ..SolveScratch::default()
        };
        assemble_into(&mut scratch, N);
        factorise_into(&mut scratch, N);
        assert!(
            !scratch.l_diag.is_empty(),
            "an M-matrix factorises; an empty factor is the diagonal fallback"
        );

        // The matrix, densely, with each row's duplicate columns summed — which
        // is what a mat-vec over that row computes.
        let mut a = [[0.0f64; N]; N];
        for (i, row) in a.iter_mut().enumerate() {
            for t in scratch.row_start[i] as usize..scratch.row_start[i + 1] as usize {
                row[scratch.col[t] as usize] += scratch.value[t];
            }
        }
        // The factor, densely.
        let mut l = [[0.0f64; N]; N];
        for (i, row) in l.iter_mut().enumerate() {
            row[i] = scratch.l_diag[i];
            for t in scratch.l_start[i] as usize..scratch.l_start[i + 1] as usize {
                row[scratch.l_col[t] as usize] = scratch.l_val[t];
            }
        }

        let mut holes = 0;
        for i in 0..N {
            for j in 0..N {
                let mut llt = 0.0;
                for (&lik, &ljk) in l[i].iter().zip(&l[j]) {
                    llt += lik * ljk;
                }
                if a[i][j] == 0.0 {
                    holes += usize::from(llt.abs() > 1e-9);
                    continue;
                }
                assert!(
                    (llt - a[i][j]).abs() < 1e-9 * a[i][j].abs(),
                    "L Lt disagrees with A at ({i},{j}): {llt} against {}",
                    a[i][j]
                );
            }
        }
        assert!(
            holes > 0,
            "a cycle drops fill outside its own pattern, so a zero-fill factor \
             must differ from A somewhere — no difference means this case was \
             not exercising the incompleteness at all"
        );
    }

    /// The answer [`TapIndex::nearest`] has to agree with: every tap, compared
    /// exactly, ties broken by the lower index.
    fn brute_force(at: &[Point], marker: Point) -> u32 {
        let mut best = (i128::MAX, u32::MAX);
        for (index, here) in at.iter().enumerate() {
            let (dx, dy) = (
                i128::from(here.x.raw() - marker.x.raw()),
                i128::from(here.y.raw() - marker.y.raw()),
            );
            let candidate = (
                dx * dx + dy * dy,
                u32::try_from(index).expect("a tap index is a u32"),
            );
            best = best.min(candidate);
        }
        best.1
    }

    fn index_of(at: &[Point]) -> TapIndex {
        let mut index = TapIndex {
            at: at.to_vec(),
            ..TapIndex::default()
        };
        index.grid();
        index
    }

    /// The ring search must return what an exhaustive scan returns, for every
    /// query, or a device attaches to the wrong node and every drop measured
    /// through it is measured from the wrong place. Swept over degenerate
    /// aspect ratios and over markers well outside the extent, because those
    /// are what the clamped query cell and the slack test exist for.
    #[test]
    fn the_ring_search_agrees_with_an_exhaustive_scan() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // A uniform draw in `0 .. span`. Every span asked for below is a positive
        // literal, or three times one, and none exceeds 15000 — so the modulus
        // and its result both round-trip exactly.
        let mut draw = |span: i64| -> i64 {
            let modulus = u64::try_from(span).expect("a sweep span is positive");
            i64::try_from(next() % modulus).expect("a draw below the span fits an i64")
        };
        for taps in [1usize, 2, 3, 7, 40, 200] {
            for &(span_x, span_y) in &[(1i64, 1i64), (1, 5000), (5000, 1), (900, 900)] {
                let at: Vec<Point> = (0..taps)
                    .map(|_| Point {
                        x: Dbu::new_unchecked(draw(span_x) - span_x / 2),
                        y: Dbu::new_unchecked(draw(span_y) - span_y / 2),
                    })
                    .collect();
                let index = index_of(&at);
                for _ in 0..64 {
                    // Three times the extent, so most queries land outside it.
                    let marker = Point {
                        x: Dbu::new_unchecked(draw(3 * span_x) - 3 * span_x / 2),
                        y: Dbu::new_unchecked(draw(3 * span_y) - 3 * span_y / 2),
                    };
                    assert_eq!(
                        index.nearest(marker),
                        brute_force(&at, marker),
                        "{taps} taps over {span_x}x{span_y}, marker {marker:?}"
                    );
                }
            }
        }
    }
}
