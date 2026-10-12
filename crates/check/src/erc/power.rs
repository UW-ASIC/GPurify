//! Resistive networks extracted from layout, and the DC solve over them.
//!
//! Data in: the store, nets, devices, intent, the process stack.
//! Data out: the supply grid ([`PowerGrid`], solved by [`solve_into`] into a
//! [`PowerSolution`]), per-net networks ([`NetNetworks`], probed by
//! [`effective_resistance_into`]), and forced-current stress networks across
//! nets ([`StressGrid`], built by [`extract_stress_into`] and solved by
//! [`solve_into`]).
//!
//! A polygon is a chain of resistors along its long bounding-box axis, tapped
//! wherever something connects and once at its own centre (so an unconnected
//! shape is an island, not absent). Segment resistance is sheet resistance
//! times `∫ ds / w(s)` over the width a cut actually finds (`ChainProfile`).
//! One-dimensional: transverse resistance within a cut is not modelled.

use crate::erc::centre;
use crate::erc::facts::IntentMap;
use crate::topology::net::{intra_layer_edges_into, via_cuts_into};
use crate::topology::{csr_run, DeviceId, DeviceTable, NetId, NetTable};
use gpurify_geom::connectivity::{components_into, ComponentLabel};
use gpurify_geom::ops::Point;
use gpurify_geom::{prefix, Current, Dbu, Grid, Qty, Resistance, Voltage, MAX_ABS_DBU};
use gpurify_geom::{Bbox, GeometryStore, LayerId, PolyId};
use gpurify_ingest::deck::{Connectivity, ProcessStack};
use gpurify_ingest::intent::SupplyRole;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// Microamps per millivolt per ohm: the grid is mV, µA and Ω, so a conductance
/// is `1000 / R`. Wrong here scales every drop and still passes law tests.
const UA_PER_MV_OHM: f64 = 1_000.0;

/// The unknown index of a node held at a fixed potential.
const NOT_AN_UNKNOWN: u32 = u32::MAX;

/// Why a network could not be built or solved. Every variant fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PowerError {
    /// A grid with nodes but no pad held at a fixed voltage.
    /// [`extract_into`] anchors every supply that has a shape, so only a grid
    /// built by hand meets this.
    #[error("the grid has no supply pad to anchor the solve")]
    Unanchored,
    /// The node is in a piece of the grid no pad reaches, such as a supply
    /// shape joined to its net only through a global (substrate) layer, which
    /// carries no modelled current. Its voltage would be undefined.
    #[error("node {0} is in an island no supply pad reaches")]
    UnanchoredIsland(u32),
    /// The edge (within its network row, for a per-net network) has a zero,
    /// negative or non-finite resistance; zero would short two nodes and hide
    /// a drop.
    #[error("edge {0} does not have a positive finite resistance")]
    BadResistance(u32),
    /// A conductor, or a cut between two conductors, has no positive finite
    /// sheet resistance in the deck's `pex` rows: its resistance is unknown,
    /// never zero.
    #[error("layer {0:?} carries current but the process stack gives it no sheet resistance")]
    NoSheetResistance(LayerId),
    /// The conjugate-gradient solve did not bring the residual to `1e-10` of
    /// its starting value within this many iterations.
    #[error("the solve did not reach the requested tolerance in {0} iterations")]
    NotConverged(u32),
    /// The node carries a NaN or infinite value: an input nominal, load or pad
    /// voltage, a solved voltage or current, or a probe that would not invert.
    #[error("node {0} carries a non-finite electrical value")]
    NotFinite(u32),
}

/// The process data an extraction needs, borrowed.
#[derive(Debug, Clone, Copy)]
pub struct Process<'a> {
    /// The layout's grid: database units to metres.
    pub grid: Grid,
    /// The deck's parasitic stack: sheet resistance per layer (Ω per square;
    /// Ω per cut for a cut layer) and the layer heights that pick each
    /// supply's feed point and set a via's length.
    pub stack: &'a ProcessStack,
    /// The deck's `connect` statements: which layers conduct, which cuts join
    /// them, and which layers are global.
    pub connectivity: &'a Connectivity,
}

/// What an edge models: metal (limited per width), one via cut (limited per
/// cut), or a device conducting between two nets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    /// A run along one conductor, or the touch between two: limited per unit
    /// width.
    Metal,
    /// One cut of a via: limited per cut.
    Via,
    /// A device's on-resistance between two of its terminals' nets: an ESD
    /// clamp in a stress network ([`extract_stress_into`]), rated by its own
    /// size, never per width or per cut. The supply grid has none.
    Device,
}

/// The supply grid, `SoA`: node columns, the fixed-voltage pads, edge columns.
///
/// Every node column has [`PowerGrid::node_count`] entries and every edge
/// column [`PowerGrid::edge_count`]. Nodes are taps on the declared
/// supplies' conducting shapes; edges are resistors between them.
#[derive(Debug, Default)]
pub struct PowerGrid {
    /// The supply net each node is on.
    pub node_net: Vec<NetId>,
    /// Where to report a violation at this node.
    pub node_at: Vec<Point>,
    /// The tapped polygon.
    pub node_poly: Vec<PolyId>,
    /// The tapped polygon's layer.
    pub node_layer: Vec<LayerId>,
    /// The domain nominal every drop is measured from.
    pub node_nominal: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Current drawn here; negative injects (a ground rail's load).
    pub node_load: Vec<Qty<Current, { prefix::MICRO }>>,

    /// Pad nodes held at a fixed voltage, ascending.
    pub source_node: Vec<u32>,
    /// Parallel to `source_node`: the voltage each pad is held at, mV.
    pub source_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,

    /// Each resistor's first node; a branch current is positive from here
    /// toward `edge_to`.
    pub edge_from: Vec<u32>,
    /// Each resistor's second node.
    pub edge_to: Vec<u32>,
    /// Each resistor's value, Ω.
    pub edge_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
    /// Conductor width (density denominator) and length (Blech `L`), exact.
    pub edge_width: Vec<Dbu>,
    /// The run between the edge's two nodes, at least one database unit: the
    /// Blech `L`. For a via, the stack height between its conductors.
    pub edge_length: Vec<Dbu>,
    /// The conductor's layer, or the cut layer for a via.
    pub edge_layer: Vec<LayerId>,
    /// Which limit applies: per width or per cut.
    pub edge_kind: Vec<EdgeKind>,
}

impl PowerGrid {
    /// The number of nodes, the length of every node column.
    pub fn node_count(&self) -> usize {
        self.node_net.len()
    }

    /// The number of resistors, the length of every edge column.
    pub fn edge_count(&self) -> usize {
        self.edge_from.len()
    }

    /// True when no declared supply has a conducting shape: nothing to solve.
    pub fn is_empty(&self) -> bool {
        self.node_count() == 0
    }
}

/// One resistor network per net with at least two terminals, CSR by row.
///
/// Row `r` is net `net[r]`; its nodes, terminals and edges are the CSR runs
/// of their `*_start` columns, each of which has `len() + 1` entries once a
/// row exists and none before. Node indices in `terminal` and `edge_*` are
/// local to the row.
#[derive(Debug, Default)]
pub struct NetNetworks {
    /// The net of each row, ascending.
    pub net: Vec<NetId>,

    /// `node_start[r] .. node_start[r + 1]` indexes the node columns.
    pub node_start: Vec<u32>,
    /// Where each node sits: on its shape's centre line, at the tap.
    pub node_at: Vec<Point>,
    /// The polygon each node taps.
    pub node_poly: Vec<PolyId>,

    /// Row-local node indices between which resistance is probed.
    pub terminal_start: Vec<u32>,
    /// The attach-point nodes, row-local, ascending, at least two per row;
    /// CSR by `terminal_start`.
    pub terminal: Vec<u32>,

    /// Edges, endpoints row-local.
    pub edge_start: Vec<u32>,
    /// Each resistor's first node, row-local.
    pub edge_from: Vec<u32>,
    /// Each resistor's second node, row-local.
    pub edge_to: Vec<u32>,
    /// Each resistor's value, Ω.
    pub edge_resistance: Vec<Qty<Resistance, { prefix::BASE }>>,
}

impl NetNetworks {
    /// The number of rows: nets with at least two attach points.
    pub fn len(&self) -> usize {
        self.net.len()
    }

    /// True when no net has two attach points.
    pub fn is_empty(&self) -> bool {
        self.net.is_empty()
    }

    /// One row's nodes: position and tapped polygon.
    pub(crate) fn nodes_of(&self, row: u32) -> (&[Point], &[PolyId]) {
        let (from, to) = csr_run(&self.node_start, row as usize);
        (&self.node_at[from..to], &self.node_poly[from..to])
    }

    /// One row's terminal node indices, ascending.
    pub fn terminals_of(&self, row: u32) -> &[u32] {
        let (from, to) = csr_run(&self.terminal_start, row as usize);
        &self.terminal[from..to]
    }

    /// One row's edges: endpoints and resistance.
    pub(crate) fn edges_of(
        &self,
        row: u32,
    ) -> (&[u32], &[u32], &[Qty<Resistance, { prefix::BASE }>]) {
        let (from, to) = csr_run(&self.edge_start, row as usize);
        (
            &self.edge_from[from..to],
            &self.edge_to[from..to],
            &self.edge_resistance[from..to],
        )
    }
}

/// CG stops once the residual is this fraction of the initial one.
const RELATIVE_TOLERANCE: f64 = 1e-10;
/// CG refuses after this many iterations.
const MAX_ITERATIONS: u32 = 20_000;

/// The solved state of a [`PowerGrid`]: row `i` is node `i` (voltages) or edge
/// `i` (currents).
#[derive(Debug, Default)]
pub struct PowerSolution {
    /// Solved voltage at each node, mV; a pad sits exactly at its fixed
    /// voltage.
    pub node_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Nominal minus solved: positive is a loss.
    pub node_drop: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Positive from `edge_from` toward `edge_to`.
    pub branch_current: Vec<Qty<Current, { prefix::MICRO }>>,
}

impl PowerSolution {
    /// True when every value is finite and the columns match the grid.
    pub fn is_consistent_with(&self, grid: &PowerGrid) -> bool {
        self.node_voltage.len() == grid.node_count()
            && self.node_drop.len() == grid.node_count()
            && self.branch_current.len() == grid.edge_count()
            && self.node_voltage.iter().all(|v| v.is_finite())
            && self.node_drop.iter().all(|v| v.is_finite())
            && self.branch_current.iter().all(|c| c.is_finite())
    }
}

/// The linear-solve workspace: CG preconditioned by IC(0) (falling back to the
/// diagonal on breakdown), and the Kron-elimination probe.
#[derive(Debug, Default)]
pub struct SolveScratch {
    /// The reduced Laplacian, CSR.
    row_start: Vec<u32>,
    col: Vec<u32>,
    value: Vec<f64>,
    rhs: Vec<f64>,
    /// CG state.
    x: Vec<f64>,
    r: Vec<f64>,
    p: Vec<f64>,
    ap: Vec<f64>,
    z: Vec<f64>,
    /// Diagonal preconditioner, as reciprocals.
    inv_diag: Vec<f64>,
    /// IC(0) factor `L D Lᵀ`: the unit lower triangle's strict part, CSR,
    /// columns ascending and merged, plus the pivots `D`. Empty means "use the
    /// diagonal".
    l_start: Vec<u32>,
    l_col: Vec<u32>,
    l_val: Vec<f64>,
    l_diag: Vec<f64>,
    row_stage: Vec<(u32, f64)>,
    unknown_of_node: Vec<u32>,
    node_of_unknown: Vec<u32>,
    /// Assembly: row fill cursors and the diagonal.
    cursor: Vec<u32>,
    diag: Vec<f64>,
    /// Edges in unknown space.
    branch: Vec<(u32, u32, f64)>,
    pairs: Vec<(u32, u32)>,
    labels: Vec<ComponentLabel>,
    reached: Vec<bool>,
    is_pad: Vec<bool>,
    /// Probe workspace.
    elim: ElimGraph,
    /// The `k × k` reduced Laplacian over one row's terminals.
    dense: Vec<f64>,
    local: Vec<f64>,
    inverse: Vec<f64>,
    probe: Vec<f64>,
    /// Which terminal a node is, or [`NONE`].
    terminal_of_node: Vec<u32>,
    group: Vec<u32>,
}

/// End of a linked list, and "not a terminal".
const NONE: u32 = u32::MAX;

/// The graph a Kron elimination edits in place: a half-edge pool (edge `e` is
/// slots `2e`, `2e + 1`, twin `h ^ 1`) with linked incidence lists. A dead
/// half-edge carries zero conductance and is unlinked lazily by `refresh`.
#[derive(Debug, Default)]
struct ElimGraph {
    /// Head half-edge of each vertex's list, or [`NONE`].
    head: Vec<u32>,
    alive: Vec<bool>,
    next: Vec<u32>,
    dst: Vec<u32>,
    /// Conductance per half-edge; zero is dead.
    g: Vec<f64>,
    /// Sparse accumulator: `slot[v]` is valid only where `stamp[v] == epoch`.
    slot: Vec<u32>,
    stamp: Vec<u32>,
    epoch: u32,
    /// Deduplicated neighbours of the vertex being eliminated.
    fringe: Vec<(u32, f64)>,
    /// Min-degree queue keyed `(degree, vertex)`, lazily invalidated; the
    /// vertex tie-break fixes the elimination order and so every rounding.
    queue: BinaryHeap<Reverse<(u32, u32)>>,
}

impl ElimGraph {
    /// Empty the graph and size it for `vertices`.
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
        let h = u32::try_from(self.next.len()).expect("a half-edge index is a u32");
        self.next.push(self.head[a as usize]);
        self.dst.push(b);
        self.g.push(g);
        self.head[a as usize] = h;
        self.next.push(self.head[b as usize]);
        self.dst.push(a);
        self.g.push(g);
        self.head[b as usize] = h + 1;
    }

    /// Unlink every dead half-edge of one vertex; return its live degree.
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

    /// Kron-eliminate one vertex: each neighbour pair gains `g_i g_j / d` (the
    /// Schur complement), which leaves every survivor-to-survivor effective
    /// resistance unchanged. The touched neighbours are left in `fringe`.
    fn eliminate(&mut self, v: u32) {
        self.epoch += 1;
        let epoch = self.epoch;
        self.fringe.clear();

        // Gather, deduplicate and unhook in one walk.
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
            self.g[h as usize] = 0.0;
            self.g[(h ^ 1) as usize] = 0.0;
            h = self.next[h as usize];
        }
        self.alive[v as usize] = false;
        self.head[v as usize] = NONE;

        // Left fold in fringe order: the same bits every run.
        let mut total = 0.0f64;
        for i in 0..self.fringe.len() {
            total += self.fringe[i].1;
        }
        if !(total > 0.0 && total.is_finite()) {
            return;
        }

        for i in 0..self.fringe.len() {
            let (a, ga) = self.fringe[i];
            // Index `a`'s live neighbours so fill adds into an existing edge
            // instead of growing a parallel strand.
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

/// Invert a dense SPD `n × n` row-major matrix by Cholesky; `a` is consumed.
/// `false` when a pivot is not positive and finite.
fn cholesky_inverse_into(a: &mut [f64], n: usize, out: &mut Vec<f64>) -> bool {
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

    // One forward and one back substitution per unit vector.
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

/// Shared with the field solver; their fold order is part of the result.
use gpurify_geom::linalg::{axpy, dot, nrm2 as norm, spmv, xpay};

/// Assemble the reduced Laplacian (CSR, diagonal first in each row) and its
/// inverse diagonal from `scratch.branch`, which is in unknown space.
///
/// A [`NOT_AN_UNKNOWN`] endpoint (a pad) loads the other end's diagonal and
/// adds no off-diagonal. Duplicate columns stay duplicated: the mat-vec sums
/// them. Each diagonal accumulates in edge order.
fn assemble_into(scratch: &mut SolveScratch, unknowns: usize) {
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

    cursor.clear();
    cursor.resize(unknowns, 0);
    diag.clear();
    diag.resize(unknowns, 0.0);
    for &(a, b, _) in branch.iter() {
        if a != NOT_AN_UNKNOWN && b != NOT_AN_UNKNOWN {
            cursor[a as usize] += 1;
            cursor[b as usize] += 1;
        }
    }

    // Offsets; slot zero of every row is the diagonal.
    row_start.clear();
    row_start.push(0);
    let mut running = 0u32;
    for count in cursor.iter_mut() {
        let first = running;
        running += 1 + *count;
        row_start.push(running);
        *count = first + 1;
    }
    let nnz = running as usize;
    col.clear();
    col.resize(nnz, 0);
    value.clear();
    value.resize(nnz, 0.0);
    for i in 0..unknowns {
        col[row_start[i] as usize] = u32::try_from(i).expect("an unknown index is a u32");
    }

    for &(a, b, g) in branch.iter() {
        let (a_unknown, b_unknown) = (a != NOT_AN_UNKNOWN, b != NOT_AN_UNKNOWN);
        if a_unknown {
            diag[a as usize] += g;
        }
        if b_unknown {
            diag[b as usize] += g;
        }
        if a_unknown && b_unknown {
            for (row, other) in [(a, b), (b, a)] {
                let k = cursor[row as usize] as usize;
                col[k] = other;
                value[k] = -g;
                cursor[row as usize] += 1;
            }
        }
    }

    // Every unknown reaches a pad through branches of positive conductance.
    debug_assert!(
        diag.iter().all(|&d| d > 0.0),
        "the reduced Laplacian's diagonal is positive"
    );
    debug_assert!(
        cursor
            .iter()
            .zip(&row_start[1..])
            .all(|(&filled, &end)| filled == end),
        "every row's off-diagonal slots are filled exactly"
    );
    inv_diag.clear();
    inv_diag.reserve(unknowns);
    for i in 0..unknowns {
        value[row_start[i] as usize] = diag[i];
        inv_diag.push(1.0 / diag[i]);
    }
}

/// IC(0): factor the assembled matrix with zero fill into `l_*` as `L D Lᵀ`,
/// merging duplicate columns. Without square roots, a factor of a network
/// with exact binary values is exact: on a tree, where zero fill drops
/// nothing, CG then lands on the exact solution in one step, so a closed-form
/// drop is the same bits on a ground rail near 0 mV as on a power rail. On
/// breakdown the factor is left empty, which selects the diagonal
/// preconditioner (a partial factor would diverge).
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

    // The pattern: each row's strict lower entries, sorted and merged.
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
        for &(c, v) in row_stage.iter() {
            let fresh =
                l_col.len() == l_start[i] as usize || *l_col.last().expect("non-empty") != c;
            l_col.resize(l_col.len() + usize::from(fresh), c);
            l_val.resize(l_val.len() + usize::from(fresh), 0.0);
            *l_val.last_mut().expect("the resize above left an entry") += v;
        }
        l_start.push(u32::try_from(l_col.len()).expect("a factor entry is a u32"));
    }

    // The factorisation, in row order; each sparse dot is a two-pointer merge.
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
                s -= l_val[p] * l_val[q] * l_diag[cp as usize] * hit;
                p += usize::from(cp <= cq);
                q += usize::from(cq <= cp);
            }
            let v = s / l_diag[j];
            l_val[t] = v;
            d -= v * s;
        }
        if !(d > 0.0 && d.is_finite()) {
            l_start.clear();
            l_col.clear();
            l_val.clear();
            l_diag.clear();
            return;
        }
        l_diag[i] = d;
    }
}

/// `z = M⁻¹ r`: forward and back substitution through the IC(0) factor, or
/// the diagonal when the factor is empty.
fn precondition(
    factor: (&[u32], &[u32], &[f64], &[f64]),
    inv_diag: &[f64],
    r: &[f64],
    z: &mut [f64],
) {
    let (l_start, l_col, l_val, l_diag) = factor;
    let unknowns = z.len();
    if l_diag.is_empty() {
        // No bounds checks, so this autovectorises (one multiply per lane).
        for ((z, &r), &d) in z.iter_mut().zip(r).zip(inv_diag) {
            *z = r * d;
        }
        return;
    }
    // `L y = r`, ascending; `L` has a unit diagonal.
    for i in 0..unknowns {
        let mut s = r[i];
        for t in l_start[i] as usize..l_start[i + 1] as usize {
            s -= l_val[t] * z[l_col[t] as usize];
        }
        z[i] = s;
    }
    // `D w = y`.
    for (z, &d) in z.iter_mut().zip(l_diag) {
        *z /= d;
    }
    // `Lᵀ z = w`, descending, scattering each row back over the rows above.
    for i in (0..unknowns).rev() {
        let v = z[i];
        for t in l_start[i] as usize..l_start[i + 1] as usize {
            z[l_col[t] as usize] -= l_val[t] * v;
        }
    }
}

/// Preconditioned CG on the assembled and factorised system, from the guess
/// in `scratch.x`. A `NaN` residual refuses.
fn conjugate_gradient(scratch: &mut SolveScratch) -> Result<(), PowerError> {
    let unknowns = scratch.x.len();
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
    r.extend(rhs.iter().zip(ap.iter()).map(|(&b, &ax)| b - ax));
    precondition((l_start, l_col, l_val, l_diag), inv_diag, r, z);
    p.clear();
    p.extend_from_slice(z);

    let mut rz = dot(r, z);
    let initial = norm(r);
    let goal = initial * RELATIVE_TOLERANCE;
    let mut residual = initial;
    let mut iterations = 0u32;
    while residual > goal && iterations < MAX_ITERATIONS {
        spmv(row_start, col, value, p, ap);
        let pap = dot(p, ap);
        // Non-positive `p·Ap`: the floating-point floor; the test below decides.
        if !(pap > 0.0) {
            break;
        }
        let alpha = rz / pap;
        axpy(alpha, p, x);
        axpy(-alpha, ap, r);
        precondition((l_start, l_col, l_val, l_diag), inv_diag, r, z);
        let next = dot(r, z);
        let beta = next / rz;
        xpay(z, beta, p);
        rz = next;
        residual = norm(r);
        iterations += 1;
    }

    if !(residual <= goal) {
        return Err(PowerError::NotConverged(MAX_ITERATIONS));
    }
    Ok(())
}

/// A grid and its solution, borrowed together.
#[derive(Debug, Clone, Copy)]
pub struct Solved<'a> {
    /// The supply grid.
    pub grid: &'a PowerGrid,
    /// Its solution, row for row.
    pub solution: &'a PowerSolution,
}

/// What the grid rules read: the solve, `None` with no declared supply, or why
/// the solve failed (those rows are refused; every other rule still runs).
pub type Power<'a> = Result<Option<Solved<'a>>, PowerError>;

/// True when some net states a non-zero `budget_current_ua` and carries no
/// load on the grid (the budget never reached the solve, e.g. a rail with no
/// device terminal, or a limited net that is not a supply). Exact: the loads
/// sum to the signed budget or to `±0.0`.
pub(crate) fn discarded_budget(grid: &PowerGrid, intent: &IntentMap) -> bool {
    // One pass over the nodes; each limited net's loads summed in node order.
    let mut load = vec![0.0f64; intent.limit_net.len()];
    let mut last = (NetId::NONE, None);
    for (&net, &node_load) in grid.node_net.iter().zip(&grid.node_load) {
        if net != last.0 {
            last = (net, intent.limit_net.binary_search(&net).ok());
        }
        if let Some(row) = last.1 {
            load[row] += node_load.raw();
        }
    }
    intent.limit.iter().zip(&load).any(|(limits, &load)| {
        limits.budget_current_ua.is_some_and(|budget| budget != 0.0) && load == 0.0
    })
}

/// Build the supply grid; `out` is cleared and refilled. Only declared
/// supplies get nodes, so no supply means an empty grid (and `None` for
/// [`Solved`]).
///
/// Each rail's budget spreads uniformly over its device terminals: one number
/// per net is all [`IntentMap`] carries, so a hot spot reads cooler than it
/// is. The rail is anchored at one pad (see below), which over-reports drop.
///
/// # Errors
///
/// Returns [`PowerError::NoSheetResistance`] when a conductor, or a cut
/// between two non-global conductors, has no positive finite sheet
/// resistance, whether or not any supply is declared. `out` is left empty.
pub fn extract_into(
    store: &GeometryStore,
    nets: &NetTable,
    devices: &DeviceTable,
    intent: &IntentMap,
    process: Process<'_>,
    out: &mut PowerGrid,
) -> Result<(), PowerError> {
    *out = PowerGrid::default();
    // Fallible before anything is written: a missing sheet resistance refuses.
    let conductor = conductor_mask(process.connectivity, store.layer_count());
    let sheet = sheet_resistances(process, store.layer_count())?;

    // Every supply's conducting shapes, grouped by supply.
    let mut supply_of_shape: Vec<u32> = Vec::new();
    let mut shape: Vec<PolyId> = Vec::new();
    let mut supply_start: Vec<u32> = vec![0];
    for (supply, &net) in intent.supply_net.iter().enumerate() {
        // A hole row shares its outer's net but is no conductor: as a node,
        // nothing would link it and the solve would refuse it as an island.
        shape.extend(
            conducting(store, &conductor, nets.polys_of(net))
                .filter(|&poly| !nets.holes.is_hole(poly)),
        );
        supply_of_shape.resize(
            shape.len(),
            u32::try_from(supply).expect("a supply row is a u32"),
        );
        supply_start.push(u32::try_from(shape.len()).expect("a shape index is a u32"));
    }

    // Connections between two grid shapes: where each chain is cut.
    let mut shape_of_poly = vec![NONE; store.poly_count()];
    for (index, &poly) in shape.iter().enumerate() {
        shape_of_poly[poly.idx()] = u32::try_from(index).expect("a shape index is a u32");
    }
    let mut links = Connections::default();
    connections_into(store, process.connectivity, &mut links);
    let both_noded = |&(a, b, _, _): &Link| {
        shape_of_poly[a as usize] != NONE && shape_of_poly[b as usize] != NONE
    };
    links.metal.retain(both_noded);
    links.via.retain(both_noded);

    // Taps: every shape's centre first, then both ends of every connection.
    let mut taps = TapTable::default();
    for (index, &poly) in shape.iter().enumerate() {
        let host = store.poly_bbox(poly);
        taps.push(
            u32::try_from(index).expect("a shape index is a u32"),
            tap_on(host, host),
        );
    }
    let shape_of = |poly: u32| shape_of_poly[poly as usize];
    let metal_req = taps.push_links(store, &links.metal, shape_of);
    let via_req = taps.push_links(store, &links.via, shape_of);

    // One tap per device on the rail, on the nearest shape its marker touches
    // (else the nearest), and one load share per terminal it lands on the
    // rail (source and drain both draw).
    let mut attach: Vec<u32> = Vec::new();
    let mut load: Vec<(u32, Qty<Current, { prefix::MICRO }>)> = Vec::new();
    let mut index = TapIndex::default();
    for (supply, &net) in intent.supply_net.iter().enumerate() {
        let (from, to) = (
            supply_start[supply] as usize,
            supply_start[supply + 1] as usize,
        );
        attach.clear();
        if to == from {
            continue;
        }
        TapIndex::build_into(store, &shape[from..to], &mut index);
        for &device in devices.devices_on(net) {
            let marker_box = store.poly_bbox(devices.marker[device.0 as usize]);
            let marker = centre(marker_box);
            let host_index = from + index.host(marker_box) as usize;
            let host = store.poly_bbox(shape[host_index]);
            let request = taps.push(
                u32::try_from(host_index).expect("a shape index is a u32"),
                tap_on(host, Bbox::point(marker.x, marker.y)),
            );
            let (on, _) = devices.terminals_of(device);
            let here = on.iter().filter(|&&n| n == net).count();
            attach.resize(attach.len() + here, request);
        }
        // A rail with no terminal is left unloaded; `discarded_budget` reports
        // it to the rules rather than refusing the whole stage. Ground injects.
        let sign = match intent.supply_role[supply] {
            SupplyRole::Power => 1.0,
            SupplyRole::Ground => -1.0,
        };
        #[allow(clippy::cast_precision_loss, reason = "a small count")]
        let share = Qty::new(
            sign * intent.limits_of(net).budget_current_ua.unwrap_or(0.0) / attach.len() as f64,
        );
        load.extend(attach.iter().map(|&request| (request, share)));
    }

    // Nodes: one per distinct tap, ascending by shape then along its chain.
    taps.finish(shape.len());
    for i in 0..taps.node_shape.len() {
        let owner = taps.node_shape[i] as usize;
        let supply = supply_of_shape[owner] as usize;
        let poly = shape[owner];
        out.node_poly.push(poly);
        out.node_net.push(intent.supply_net[supply]);
        out.node_nominal.push(intent.held_at(supply));
        out.node_layer.push(store.poly_layer(poly));
        out.node_at
            .push(tap_point(store.poly_bbox(poly), taps.node_along[i]));
    }
    out.node_load.resize(out.node_poly.len(), Qty::new(0.0));
    for &(request, share) in &load {
        let node = taps.req_node[request as usize] as usize;
        out.node_load[node] = out.node_load[node] + share;
    }

    // The anchor: no input marks pads, and supply enters from the top.
    for supply in 0..intent.supply_net.len() {
        let (from, to) = (
            supply_start[supply] as usize,
            supply_start[supply + 1] as usize,
        );
        if to == from {
            continue;
        }
        let anchor = from + feed_shape(store, process, &shape[from..to]);
        let host = store.poly_bbox(shape[anchor]);
        let (lo, hi) = taps.chain_of(u32::try_from(anchor).expect("a shape index is a u32"));
        let at = lo
            + taps.node_along[lo..hi]
                .binary_search(&tap_on(host, host))
                .expect("every shape carries a tap at its own centre");
        out.source_node
            .push(u32::try_from(at).expect("a node index is a u32"));
        out.source_voltage.push(intent.held_at(supply));
    }

    push_edges(
        store,
        process,
        &sheet,
        &shape,
        &taps,
        [(&links.metal, metal_req), (&links.via, via_req)],
        &mut ChainProfile::default(),
        |edge| out.push_edge(edge),
    );
    Ok(())
}

/// The index in `shapes` of a supply's feed point: supply enters from the top,
/// so its highest-layer, then widest, then lowest-index shape. A missing
/// `height_nm` reads as the substrate. `shapes` is not empty.
fn feed_shape(store: &GeometryStore, process: Process<'_>, shapes: &[PolyId]) -> usize {
    let mut anchor = 0;
    let mut best = (f64::NEG_INFINITY, i128::MIN);
    for (offset, &poly) in shapes.iter().enumerate() {
        let height = process
            .stack
            .height_nm
            .get(store.poly_layer(poly).idx())
            .copied()
            .unwrap_or(0.0);
        let key = (height, store.poly_bbox(poly).area().raw());
        if key > best {
            best = key;
            anchor = offset;
        }
    }
    anchor
}

/// One forced-current stress for [`extract_stress_into`]: the nets a
/// discharge path spans, where a current is forced in and where it leaves,
/// and the devices that carry it from net to net.
#[derive(Debug, Clone, Copy)]
pub struct Stress<'a> {
    /// The nets the network spans, ascending, without repeats.
    pub nets: &'a [NetId],
    /// The polygon the current enters at; its net is one of `nets`. It taps
    /// its net's conducting shape nearest its box centre, at that centre.
    pub source: PolyId,
    /// The current forced in at `source`, µA.
    pub current: Qty<Current, { prefix::MICRO }>,
    /// The net the current leaves by, one of `nets`.
    pub sink: NetId,
    /// The sink's pins, each tapped as `source` is and held at 0 mV. Empty
    /// holds the sink's feed point instead, the centre of its highest, then
    /// widest, shape (as [`extract_into`] anchors a supply).
    pub pins: &'a [PolyId],
    /// The devices that conduct between nets. Each joins every pair of the
    /// distinct nets of `nets` its terminals touch, at its attach point on
    /// each (the shape nearest its marker's centre); one touching fewer than
    /// two adds nothing.
    pub devices: &'a [DeviceId],
    /// The resistance one device puts between two of its nets, Ω; positive.
    pub device_resistance: Qty<Resistance, { prefix::BASE }>,
}

/// A stress network built by [`extract_stress_into`] and solved by
/// [`solve_into`]: every node's voltage is its rise above the held pins.
#[derive(Debug, Default)]
pub struct StressGrid {
    /// The network. Its metal and via edges come first, as in the supply
    /// grid; its last `device.len()` edges are [`EdgeKind::Device`].
    pub grid: PowerGrid,
    /// The node the current enters at.
    pub entry: u32,
    /// The device each device edge models, in edge order.
    pub device: Vec<DeviceId>,
}

/// A tap request on the shape of `shapes` nearest `at`, at `at`; `None` when
/// `shapes` is empty.
// ponytail: rebuilds the nearest-shape index per query; a stress has a few
// pins and clamps.
fn tap_nearest(
    store: &GeometryStore,
    shapes: &[PolyId],
    offset: usize,
    at: Point,
    index: &mut TapIndex,
    taps: &mut TapTable,
) -> Option<u32> {
    if shapes.is_empty() {
        return None;
    }
    TapIndex::build_into(store, shapes, index);
    let local = index.nearest(at) as usize;
    let host = store.poly_bbox(shapes[local]);
    Some(taps.push(
        u32::try_from(offset + local).expect("a shape index is a u32"),
        tap_on(host, Bbox::point(at.x, at.y)),
    ))
}

/// Build the network a forced current flows through; `out` is cleared and
/// refilled. The nets are chains of resistors as in [`extract_into`]; each
/// device in `stress.devices` adds `device_resistance` between its attach
/// points on every two path nets it touches. The entry node draws
/// `-current` (an injection), the held nodes sit at 0 mV, and every node's
/// nominal is 0 mV, so after [`solve_into`] a node's voltage is the stress
/// voltage there.
///
/// # Errors
///
/// [`PowerError::NoSheetResistance`] as [`extract_into`] returns it, with
/// `out` left empty.
///
/// # Panics
///
/// Panics if `stress.source` is not on a net of `stress.nets`, or the source
/// net or the sink has no conducting shape.
pub fn extract_stress_into(
    store: &GeometryStore,
    nets: &NetTable,
    devices: &DeviceTable,
    process: Process<'_>,
    stress: Stress<'_>,
    out: &mut StressGrid,
) -> Result<(), PowerError> {
    out.grid = PowerGrid::default();
    out.device.clear();
    out.entry = 0;
    let conductor = conductor_mask(process.connectivity, store.layer_count());
    let sheet = sheet_resistances(process, store.layer_count())?;

    // Every path net's conducting shapes, grouped by net.
    let mut shape: Vec<PolyId> = Vec::new();
    let mut net_of_shape: Vec<NetId> = Vec::new();
    let mut net_start: Vec<usize> = vec![0];
    for &net in stress.nets {
        shape.extend(
            conducting(store, &conductor, nets.polys_of(net))
                .filter(|&poly| !nets.holes.is_hole(poly)),
        );
        net_of_shape.resize(shape.len(), net);
        net_start.push(shape.len());
    }
    let run_of = |net: NetId| {
        let row = stress
            .nets
            .binary_search(&net)
            .expect("a stressed polygon's net is a path net");
        (net_start[row], net_start[row + 1])
    };

    let mut shape_of_poly = vec![NONE; store.poly_count()];
    for (index, &poly) in shape.iter().enumerate() {
        shape_of_poly[poly.idx()] = u32::try_from(index).expect("a shape index is a u32");
    }
    let mut links = Connections::default();
    connections_into(store, process.connectivity, &mut links);
    let both_noded = |&(a, b, _, _): &Link| {
        shape_of_poly[a as usize] != NONE && shape_of_poly[b as usize] != NONE
    };
    links.metal.retain(both_noded);
    links.via.retain(both_noded);

    let mut taps = TapTable::default();
    for (index, &poly) in shape.iter().enumerate() {
        let host = store.poly_bbox(poly);
        taps.push(
            u32::try_from(index).expect("a shape index is a u32"),
            tap_on(host, host),
        );
    }
    let shape_of = |poly: u32| shape_of_poly[poly as usize];
    let metal_req = taps.push_links(store, &links.metal, shape_of);
    let via_req = taps.push_links(store, &links.via, shape_of);

    let mut index = TapIndex::default();
    let mut tap_at = |net: NetId, at: Point, taps: &mut TapTable| {
        let (from, to) = run_of(net);
        tap_nearest(store, &shape[from..to], from, at, &mut index, taps)
    };
    let source = store.poly_bbox(stress.source);
    let entry_req = tap_at(nets.net_of(stress.source), centre(source), &mut taps)
        .expect("the source net has a conducting shape");
    let mut held_req: Vec<u32> = Vec::new();
    for &pin in stress.pins {
        held_req.extend(tap_at(stress.sink, centre(store.poly_bbox(pin)), &mut taps));
    }
    if stress.pins.is_empty() {
        let (from, to) = run_of(stress.sink);
        assert!(to > from, "the sink net has a conducting shape");
        let anchor = from + feed_shape(store, process, &shape[from..to]);
        let host = store.poly_bbox(shape[anchor]);
        held_req.push(taps.push(
            u32::try_from(anchor).expect("a shape index is a u32"),
            tap_on(host, host),
        ));
    }
    // Per device: its attach request on each path net it touches.
    let mut attach: Vec<(DeviceId, Vec<u32>)> = Vec::new();
    let mut touched: Vec<NetId> = Vec::new();
    for &device in stress.devices {
        touched.clear();
        touched.extend(
            devices
                .terminals_of(device)
                .0
                .iter()
                .copied()
                .filter(|net| stress.nets.binary_search(net).is_ok()),
        );
        touched.sort_unstable();
        touched.dedup();
        if touched.len() < 2 {
            continue;
        }
        let marker = centre(store.poly_bbox(devices.marker[device.0 as usize]));
        let requests: Vec<u32> = touched
            .iter()
            .filter_map(|&net| tap_at(net, marker, &mut taps))
            .collect();
        attach.push((device, requests));
    }

    taps.finish(shape.len());
    let grid = &mut out.grid;
    for i in 0..taps.node_shape.len() {
        let owner = taps.node_shape[i] as usize;
        let poly = shape[owner];
        grid.node_poly.push(poly);
        grid.node_net.push(net_of_shape[owner]);
        grid.node_nominal.push(Qty::new(0.0));
        grid.node_load.push(Qty::new(0.0));
        grid.node_layer.push(store.poly_layer(poly));
        grid.node_at
            .push(tap_point(store.poly_bbox(poly), taps.node_along[i]));
    }
    out.entry = taps.req_node[entry_req as usize];
    // An injection is a negative load.
    grid.node_load[out.entry as usize] = Qty::new(-stress.current.raw());
    grid.source_node.extend(
        held_req
            .iter()
            .map(|&request| taps.req_node[request as usize]),
    );
    grid.source_node.sort_unstable();
    grid.source_node.dedup();
    grid.source_voltage
        .resize(grid.source_node.len(), Qty::new(0.0));

    push_edges(
        store,
        process,
        &sheet,
        &shape,
        &taps,
        [(&links.metal, metal_req), (&links.via, via_req)],
        &mut ChainProfile::default(),
        |edge| grid.push_edge(edge),
    );
    let one = Dbu::new_unchecked(1);
    for (device, requests) in &attach {
        let layer = store.poly_layer(devices.marker[device.0 as usize]);
        for (k, &a) in requests.iter().enumerate() {
            for &b in &requests[k + 1..] {
                grid.push_edge(Edge {
                    from: taps.req_node[a as usize],
                    to: taps.req_node[b as usize],
                    ohms: stress.device_resistance.raw(),
                    width: one,
                    length: one,
                    layer,
                    kind: EdgeKind::Device,
                });
                out.device.push(*device);
            }
        }
    }
    Ok(())
}

/// One resistor, before it is split into a network's columns.
#[derive(Clone, Copy)]
struct Edge {
    from: u32,
    to: u32,
    ohms: f64,
    width: Dbu,
    length: Dbu,
    layer: LayerId,
    kind: EdgeKind,
}

impl PowerGrid {
    fn push_edge(&mut self, edge: Edge) {
        self.edge_from.push(edge.from);
        self.edge_to.push(edge.to);
        self.edge_resistance.push(Qty::new(edge.ohms));
        self.edge_width.push(edge.width);
        self.edge_length.push(edge.length);
        self.edge_layer.push(edge.layer);
        self.edge_kind.push(edge.kind);
    }
}

/// Emit one network's edges in the solver's assembly order: every shape's
/// chain, then the metal links, then the vias. `links` pairs each link list
/// with its first tap request; node indices are `taps`' own.
fn push_edges(
    store: &GeometryStore,
    process: Process<'_>,
    sheet: &[f64],
    shape: &[PolyId],
    taps: &TapTable,
    links: [(&[Link], usize); 2],
    profile: &mut ChainProfile,
    mut push: impl FnMut(Edge),
) {
    let node = |n: usize| u32::try_from(n).expect("a node index is a u32");
    for (index, &poly) in shape.iter().enumerate() {
        let layer = store.poly_layer(poly);
        profile.build(store, poly);
        let (from, to) = taps.chain_of(u32::try_from(index).expect("a shape index is a u32"));
        for n in from..to.saturating_sub(1) {
            let (a, b) = (taps.node_along[n], taps.node_along[n + 1]);
            let (squares, width) = profile.segment(a, b);
            push(Edge {
                from: node(n),
                to: node(n + 1),
                ohms: sheet[layer.idx()] * squares,
                width,
                // Floored at one unit: a zero length would be Blech-immortal.
                length: Dbu::new_unchecked((b.raw() - a.raw()).max(1)),
                layer,
                kind: EdgeKind::Metal,
            });
        }
    }
    let at = |n: u32| {
        let n = n as usize;
        let host = store.poly_bbox(shape[taps.node_shape[n] as usize]);
        tap_point(host, taps.node_along[n])
    };
    let [(metal, metal_req), (via, via_req)] = links;
    for (link, &(a, b, layer, _)) in metal.iter().enumerate() {
        let (from, to) = (
            taps.req_node[metal_req + 2 * link],
            taps.req_node[metal_req + 2 * link + 1],
        );
        let width = conductor_width(store.poly_bbox(PolyId(a)), store.poly_bbox(PolyId(b)));
        // The shapes touch: the two taps coincide, so this is the floor.
        let length = run_length(at(from), at(to));
        push(Edge {
            from,
            to,
            ohms: sheet[layer.idx()] * squares(length, width),
            width,
            length,
            layer,
            kind: EdgeKind::Metal,
        });
    }
    for (link, &(a, b, cut, _)) in via.iter().enumerate() {
        // One square of the cut layer per cut; each cut is its own edge.
        push(Edge {
            from: taps.req_node[via_req + 2 * link],
            to: taps.req_node[via_req + 2 * link + 1],
            ohms: sheet[cut.idx()],
            width: conductor_width(store.poly_bbox(PolyId(a)), store.poly_bbox(PolyId(b))),
            length: via_length(
                process,
                store.poly_layer(PolyId(a)),
                store.poly_layer(PolyId(b)),
            ),
            layer: cut,
            kind: EdgeKind::Via,
        });
    }
}

/// The polygons of `polys` on conducting layers, in order.
fn conducting<'a>(
    store: &'a GeometryStore,
    conductor: &'a [bool],
    polys: &'a [PolyId],
) -> impl Iterator<Item = PolyId> + 'a {
    polys
        .iter()
        .copied()
        .filter(|&poly| conductor[store.poly_layer(poly).idx()])
}

/// The shapes of one net a device can draw its current from: their boxes,
/// for "which holds this point", and a uniform grid over their centres, for
/// exact nearest-point queries by expanding rings.
#[derive(Debug, Default)]
struct TapIndex {
    /// Box of each candidate, in candidate order.
    boxes: Vec<Bbox>,
    /// Candidate indices by ascending box `xlo`.
    by_xlo: Vec<u32>,
    /// The widest box: how far left of a point a box holding it can start.
    reach: i64,
    /// Centre of each candidate, in candidate order.
    at: Vec<Point>,
    origin_x: Dbu,
    origin_y: Dbu,
    cell: i64,
    nx: u32,
    ny: u32,
    /// `bucket_start[b] .. bucket_start[b + 1]` indexes `rows` (indices into `at`).
    bucket_start: Vec<u32>,
    rows: Vec<u32>,
    cursor: Vec<u32>,
}

impl TapIndex {
    /// Build over one net's conducting shapes.
    fn build_into(store: &GeometryStore, candidate: &[PolyId], out: &mut Self) {
        out.boxes.clear();
        out.boxes
            .extend(candidate.iter().map(|&p| store.poly_bbox(p)));
        out.at.clear();
        out.at.extend(out.boxes.iter().map(|&b| centre(b)));
        out.grid();
    }

    /// The candidate a device draws its current from: of those whose box
    /// touches or overlaps the device marker's box `marker` (shapes the
    /// device can be connected to), the one whose centre is nearest the
    /// marker's centre, the lower index winning a tie; with none touching,
    /// [`Self::nearest`] over every candidate. Panics on an empty index.
    fn host(&self, marker: Bbox) -> u32 {
        let at = centre(marker);
        let lo = self
            .by_xlo
            .partition_point(|&i| self.boxes[i as usize].xlo.raw() < marker.xlo.raw() - self.reach);
        self.by_xlo[lo..]
            .iter()
            .take_while(|&&i| self.boxes[i as usize].xlo <= marker.xhi)
            .filter(|&&i| {
                let b = self.boxes[i as usize];
                marker.xlo <= b.xhi && b.ylo <= marker.yhi && marker.ylo <= b.yhi
            })
            .map(|&i| {
                let c = self.at[i as usize];
                let (dx, dy) = (
                    i128::from(c.x.raw() - at.x.raw()),
                    i128::from(c.y.raw() - at.y.raw()),
                );
                (dx * dx + dy * dy, i)
            })
            .min()
            .map_or_else(|| self.nearest(at), |(_, i)| i)
    }

    /// Bucket the points already in `at` (split out so tests need no store).
    fn grid(&mut self) {
        let out = self;
        out.by_xlo.clear();
        out.by_xlo
            .extend(0..u32::try_from(out.boxes.len()).expect("a shape index is a u32"));
        let boxes = &out.boxes;
        out.by_xlo.sort_unstable_by_key(|&i| boxes[i as usize].xlo);
        out.reach = out
            .boxes
            .iter()
            .map(|b| (b.xhi - b.xlo).raw())
            .max()
            .unwrap_or(0);
        out.bucket_start.clear();
        out.rows.clear();
        out.cell = 1;
        out.nx = 1;
        out.ny = 1;
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
        // About one bucket per point, whatever the aspect ratio.
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
    }

    /// Which bucket a point inside the extent falls in.
    fn bucket_of(&self, p: Point) -> u32 {
        let col = (p.x.raw() - self.origin_x.raw()) / self.cell;
        let row = (p.y.raw() - self.origin_y.raw()) / self.cell;
        let (row, col) = (
            u32::try_from(row).expect("a tap row is inside the extent"),
            u32::try_from(col).expect("a tap column is inside the extent"),
        );
        row * self.nx + col
    }

    /// The candidate whose centre is nearest `marker` (exact in `i128`; the
    /// lowest index wins a tie). Panics on an empty index.
    fn nearest(&self, marker: Point) -> u32 {
        assert!(!self.at.is_empty(), "a net with no shape to attach to");

        // The query cell, clamped into the grid.
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
                    let distance = dx * dx + dy * dy;
                    // Compared as a pair: the lower index breaks a tie.
                    let closer = u32::from((distance, index) < best).wrapping_neg();
                    best = (distance.min(best.0), (index & closer) | (best.1 & !closer));
                }
                best
            };

            // The cells at Chebyshev distance `radius`: border rows whole, the
            // rows between only their two ends.
            let last_col = i64::from(self.nx - 1);
            for row in lo_y.max(0)..=hi_y.min(i64::from(self.ny - 1)) {
                if row == lo_y || row == hi_y {
                    for col in lo_x.max(0)..=hi_x.min(last_col) {
                        best = scan(best, row, col);
                    }
                } else {
                    for col in [lo_x, hi_x] {
                        if col >= 0 && col <= last_col {
                            best = scan(best, row, col);
                        }
                    }
                }
            }

            // Stop when nothing unscanned (at least `slack` away) can be closer.
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

        best.1
    }
}

/// Which layers carry current, indexed by layer.
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

/// Sheet resistance of every current-carrying layer, indexed by layer. A
/// missing, non-positive or non-finite value refuses (zero would short a rail).
/// A cut into a global layer carries nothing: the grid has no node there.
fn sheet_resistances(process: Process<'_>, layers: usize) -> Result<Vec<f64>, PowerError> {
    let connectivity = process.connectivity;
    let global = |layer: &LayerId| connectivity.global.contains(layer);
    let carrying = connectivity.conductors.iter().chain(
        connectivity
            .via_cut
            .iter()
            .zip(&connectivity.via_connects)
            .filter(move |(_, (a, b))| !global(a) && !global(b))
            .map(|(cut, _)| cut),
    );
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

/// Two connected polygons, the layer joining them, and the cut polygon both
/// ends are tapped under (`NONE` for a metal touch, tapped where they meet).
type Link = (u32, u32, LayerId, u32);

/// Every connection between two conductor polygons, by kind.
#[derive(Debug, Default)]
struct Connections {
    /// Touching pairs on one conductor layer, with that layer.
    metal: Vec<Link>,
    /// Pairs joined by one cut, with the cut layer and the cut (four cuts,
    /// four rows).
    via: Vec<Link>,
}

fn connections_into(store: &GeometryStore, connectivity: &Connectivity, out: &mut Connections) {
    out.metal.clear();
    out.via.clear();

    let mut pairs: Vec<(u32, u32)> = Vec::new();
    let mut cuts: Vec<(u32, u32, u32)> = Vec::new();
    let touching: &[LayerId] = if connectivity.intra_layer_touch {
        &connectivity.conductors
    } else {
        &[]
    };
    for &layer in touching {
        intra_layer_edges_into(store, layer, &mut pairs);
        out.metal.reserve(pairs.len());
        out.metal
            .extend(pairs.iter().map(|&(a, b)| (a, b, layer, NONE)));
    }
    for (row, &cut) in connectivity.via_cut.iter().enumerate() {
        via_cuts_into(store, cut, connectivity.via_connects[row], &mut cuts);
        out.via.reserve(cuts.len());
        out.via
            .extend(cuts.iter().map(|&(poly, a, b)| (a, b, cut, poly)));
    }
}

/// Tap requests on shapes, resolved to nodes: one per distinct
/// `(shape, along)`, ascending along each shape's chain.
#[derive(Debug, Default)]
struct TapTable {
    /// Requests in push order: which shape, where along its chain.
    req_shape: Vec<u32>,
    req_along: Vec<Dbu>,
    /// The node each request resolved to (set by [`TapTable::finish`]).
    req_node: Vec<u32>,
    node_shape: Vec<u32>,
    node_along: Vec<Dbu>,
    /// `chain_start[s] .. chain_start[s + 1]` is shape `s`'s run of nodes.
    chain_start: Vec<u32>,
    order: Vec<u32>,
}

impl TapTable {
    fn clear(&mut self) {
        self.req_shape.clear();
        self.req_along.clear();
        self.req_node.clear();
        self.node_shape.clear();
        self.node_along.clear();
        self.chain_start.clear();
        self.order.clear();
    }

    /// Ask for a tap on `shape` at `along`; returns the request index.
    fn push(&mut self, shape: u32, along: Dbu) -> u32 {
        let index = u32::try_from(self.req_shape.len()).expect("a tap request is a u32");
        self.req_shape.push(shape);
        self.req_along.push(along);
        index
    }

    /// Request both ends of every link (`a` then `b`): under the cut for a
    /// via, else where the other shape lands; returns the first request index.
    fn push_links(
        &mut self,
        store: &GeometryStore,
        links: &[Link],
        shape_of: impl Fn(u32) -> u32,
    ) -> usize {
        let first = self.req_shape.len();
        for &(a, b, _, cut) in links {
            let (host_a, host_b) = (store.poly_bbox(PolyId(a)), store.poly_bbox(PolyId(b)));
            let (at_a, at_b) = if cut == NONE {
                (host_b, host_a)
            } else {
                let under = store.poly_bbox(PolyId(cut));
                (under, under)
            };
            self.push(shape_of(a), tap_on(host_a, at_a));
            self.push(shape_of(b), tap_on(host_b, at_b));
        }
        first
    }

    /// Resolve every request to a node, sorting by `(shape, along, request)`.
    fn finish(&mut self, shapes: usize) {
        self.order.clear();
        self.order
            .extend(0..u32::try_from(self.req_shape.len()).expect("a tap request is a u32"));
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
    }

    /// One shape's run of nodes, ascending along its chain.
    fn chain_of(&self, shape: u32) -> (usize, usize) {
        (
            self.chain_start[shape as usize] as usize,
            self.chain_start[shape as usize + 1] as usize,
        )
    }
}

/// Whether a shape's chain runs along x: its long box axis (x on a tie).
fn chain_is_horizontal(host: Bbox) -> bool {
    host.width().raw() >= host.height().raw()
}

/// Where `other` lands on `host`'s chain axis: the centre of their overlap
/// (or of `other`, for a corner touch), clamped into `host`.
fn tap_on(host: Bbox, other: Bbox) -> Dbu {
    let landed = match host.intersection(other) {
        Some(shared) => centre(shared),
        None => centre(other),
    };
    let (lo, hi, along) = if chain_is_horizontal(host) {
        (host.xlo, host.xhi, landed.x)
    } else {
        (host.ylo, host.yhi, landed.y)
    };
    Dbu::new_unchecked(along.raw().clamp(lo.raw(), hi.raw()))
}

/// The node position of a tap at `along`, on `host`'s centre line.
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

/// A shape's exact cross-section along its chain: piecewise-constant widths
/// between slab cuts (an L of ten-wide arms is 9.1 squares, not its box's 1).
#[derive(Debug, Default)]
struct ChainProfile {
    /// Slab boundaries along the chain axis, ascending and deduplicated.
    cut: Vec<Dbu>,
    /// Covered cross-section per slab, floored at one unit.
    width: Vec<Dbu>,
    /// Ring edges as `(lo, hi, across)` on the chain axis, sorted by `lo`; a
    /// perpendicular edge (`lo == hi`) never spans a slab.
    edge: Vec<(Dbu, Dbu, Dbu)>,
    active: Vec<(Dbu, Dbu, Dbu)>,
    crossing: Vec<Dbu>,
}

impl ChainProfile {
    /// Profile one shape by a slab sweep over an active-edge list.
    fn build(&mut self, store: &GeometryStore, poly: PolyId) {
        let host = store.poly_bbox(poly);
        let (xs, ys) = store.poly_verts(poly);

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

        self.edge.clear();
        self.edge.reserve(n);
        for k in 0..n - 1 {
            let (a, b) = (along[k], along[k + 1]);
            self.edge.push((a.min(b), a.max(b), across[k]));
        }
        let (a, b) = (along[n - 1], along[0]);
        self.edge.push((a.min(b), a.max(b), across[n - 1]));
        self.edge.sort_unstable();

        self.width.clear();
        self.active.clear();
        let mut admitted = 0usize;
        for k in 0..self.cut.len().saturating_sub(1) {
            let (t0, t1) = (self.cut[k], self.cut[k + 1]);

            // Admit edges started by this slab; retire those ended before it.
            while admitted < self.edge.len() && self.edge[admitted].0 <= t0 {
                self.active.push(self.edge[admitted]);
                admitted += 1;
            }
            self.active.retain(|&(_, hi, _)| hi >= t1);

            self.crossing.clear();
            self.crossing.extend(self.active.iter().map(|&(_, _, c)| c));
            self.crossing.sort_unstable();
            // Crossings pair up; the metal lies between each pair.
            let mut covered = 0i64;
            for pair in self.crossing.chunks_exact(2) {
                covered += pair[1].raw() - pair[0].raw();
            }
            self.width.push(Dbu::new_unchecked(covered.max(1)));
        }
    }

    /// The squares `∫ ds / w(s)` between two taps (a left fold over slabs) and
    /// the narrowest width touched, which is where current density peaks.
    fn segment(&self, from: Dbu, to: Dbu) -> (f64, Dbu) {
        let mut squares = 0.0f64;
        let mut narrow = i64::MAX;
        for k in 0..self.width.len() {
            let lo = self.cut[k].raw().max(from.raw());
            let hi = self.cut[k + 1].raw().min(to.raw());
            let overlap = (hi - lo).max(0);
            let w = self.width[k].raw();
            #[allow(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
            let ratio = overlap as f64 / w as f64;
            squares += ratio;
            // An untouched slab blends in as `i64::MAX`.
            let mask = i64::from(overlap > 0).wrapping_neg();
            narrow = narrow.min((w & mask) | (i64::MAX & !mask));
        }

        (squares, Dbu::new_unchecked(narrow))
    }
}

/// The narrower shape's narrow dimension, floored at one unit.
fn conductor_width(a: Bbox, b: Bbox) -> Dbu {
    let narrow = |s: Bbox| s.width().raw().min(s.height().raw());
    Dbu::new_unchecked(narrow(a).min(narrow(b)).max(1))
}

/// Manhattan length between two taps, floored at one unit (a zero length
/// would be Blech-immortal).
fn run_length(from: Point, to: Point) -> Dbu {
    let span = (from.x.raw() - to.x.raw()).abs() + (from.y.raw() - to.y.raw()).abs();
    Dbu::new_unchecked(span.max(1))
}

/// A via's length: the stack height between its two conductors, floored at
/// one unit.
fn via_length(process: Process<'_>, lower: LayerId, upper: LayerId) -> Dbu {
    let height = |layer: LayerId| {
        process
            .stack
            .height_nm
            .get(layer.idx())
            .copied()
            .unwrap_or(0.0)
    };
    #[allow(clippy::cast_precision_loss, reason = "a small integer")]
    let per_um = process.grid.dbu_per_um() as f64;
    #[allow(clippy::cast_possible_truncation, reason = "clamped next")]
    let span = ((height(upper) - height(lower)).abs() * 1e-3 * per_um).round() as i64;
    Dbu::new_unchecked(span.clamp(1, MAX_ABS_DBU))
}

/// Squares of conductor: a ratio of two exact `Dbu`.
#[allow(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
fn squares(length: Dbu, width: Dbu) -> f64 {
    length.raw() as f64 / width.raw() as f64
}

/// Build one network per net with at least two device attach points; `out` is
/// cleared and refilled, rows ascending by [`NetId`]. Needs no design intent.
///
/// Same chain model as [`extract_into`], but each net's links are sorted by
/// `(net, a, b, layer)` and a device attaches once per net.
///
/// # Errors
///
/// Returns [`PowerError::NoSheetResistance`] as [`extract_into`] does, with
/// `out` left empty.
pub fn extract_nets_into(
    store: &GeometryStore,
    nets: &NetTable,
    devices: &DeviceTable,
    process: Process<'_>,
    out: &mut NetNetworks,
) -> Result<(), PowerError> {
    *out = NetNetworks::default();
    let conductor = conductor_mask(process.connectivity, store.layer_count());
    let sheet = sheet_resistances(process, store.layer_count())?;

    // Every net's conducting shapes, grouped by net, and each shape's index
    // within its own net (the row-local space the network is stated in).
    let mut candidate: Vec<PolyId> = Vec::new();
    let mut candidate_start: Vec<u32> = vec![0];
    let mut shape_in_row = vec![NONE; store.poly_count()];
    for net in 0..nets.net_count() {
        let id = NetId(u32::try_from(net).expect("a net id is a u32"));
        let first = candidate.len();
        // No node for a hole row, as in `extract_into`.
        candidate.extend(
            conducting(store, &conductor, nets.polys_of(id))
                .filter(|&poly| !nets.holes.is_hole(poly)),
        );
        for (index, &poly) in candidate[first..].iter().enumerate() {
            shape_in_row[poly.idx()] = u32::try_from(index).expect("a shape index is a u32");
        }
        candidate_start.push(u32::try_from(candidate.len()).expect("a shape index is a u32"));
    }

    // Links sorted by net (both ends share it) so each net's run is a slice.
    // Only links between two noded shapes: a cut into a global layer lands on
    // a shape the network has no node for.
    let mut links = Connections::default();
    connections_into(store, process.connectivity, &mut links);
    let both_noded =
        |&(a, b, _, _): &Link| shape_in_row[a as usize] != NONE && shape_in_row[b as usize] != NONE;
    links.metal.retain(both_noded);
    links.via.retain(both_noded);
    let by_net = |&(a, b, layer, cut): &Link| (nets.net_of(PolyId(a)).0, a, b, layer.0, cut);
    links.metal.sort_unstable_by_key(by_net);
    links.via.sort_unstable_by_key(by_net);

    let mut terminal: Vec<u32> = Vec::new();
    let mut index = TapIndex::default();
    let mut taps = TapTable::default();
    let mut profile = ChainProfile::default();
    let shape_of = |poly: u32| shape_in_row[poly as usize];
    for net in 0..nets.net_count() {
        let id = NetId(u32::try_from(net).expect("a net id is a u32"));
        let (from, to) = (
            candidate_start[net] as usize,
            candidate_start[net + 1] as usize,
        );
        let shapes = to - from;
        terminal.clear();
        taps.clear();
        let metal = net_slice(&links.metal, id.0, nets);
        let via = net_slice(&links.via, id.0, nets);

        for local in 0..shapes {
            let host = store.poly_bbox(candidate[from + local]);
            taps.push(
                u32::try_from(local).expect("a shape index is a u32"),
                tap_on(host, host),
            );
        }
        let metal_req = taps.push_links(store, metal, shape_of);
        let via_req = taps.push_links(store, via, shape_of);

        // Every device on the net taps the nearest shape its marker touches
        // (else the nearest); one with a terminal here is an attach point
        // (once, however many terminals).
        let mut attach: Vec<u32> = Vec::new();
        if shapes > 0 {
            TapIndex::build_into(store, &candidate[from..to], &mut index);
            for &device in devices.devices_on(id) {
                let marker_box = store.poly_bbox(devices.marker[device.0 as usize]);
                let marker = centre(marker_box);
                let (on, _) = devices.terminals_of(device);
                let local = index.host(marker_box);
                let host = store.poly_bbox(candidate[from + local as usize]);
                let request = taps.push(local, tap_on(host, Bbox::point(marker.x, marker.y)));
                if on.contains(&id) {
                    attach.push(request);
                }
            }
        }
        taps.finish(shapes);

        terminal.extend(
            attach
                .iter()
                .map(|&request| taps.req_node[request as usize]),
        );
        terminal.sort_unstable();
        terminal.dedup();
        // Under two attach points: no pair to measure, so no row.
        if terminal.len() < 2 {
            continue;
        }

        out.net.push(id);
        out.terminal.extend_from_slice(&terminal);
        for node in 0..taps.node_shape.len() {
            let poly = candidate[from + taps.node_shape[node] as usize];
            out.node_poly.push(poly);
            out.node_at
                .push(tap_point(store.poly_bbox(poly), taps.node_along[node]));
        }
        push_edges(
            store,
            process,
            &sheet,
            &candidate[from..to],
            &taps,
            [(metal, metal_req), (via, via_req)],
            &mut profile,
            |edge| {
                out.edge_from.push(edge.from);
                out.edge_to.push(edge.to);
                out.edge_resistance.push(Qty::new(edge.ohms));
            },
        );

        out.node_start
            .push(u32::try_from(out.node_poly.len()).expect("a node index is a u32"));
        out.terminal_start
            .push(u32::try_from(out.terminal.len()).expect("a terminal index is a u32"));
        out.edge_start
            .push(u32::try_from(out.edge_from.len()).expect("an edge index is a u32"));
    }

    // Offsets are `rows + 1` long once there is a row, and empty otherwise.
    if !out.net.is_empty() {
        out.node_start.insert(0, 0);
        out.terminal_start.insert(0, 0);
        out.edge_start.insert(0, 0);
    }
    Ok(())
}

/// One net's run of a link list sorted by net.
fn net_slice<'a>(links: &'a [Link], net: u32, nets: &NetTable) -> &'a [Link] {
    let of = |&(a, _, _, _): &Link| nets.net_of(PolyId(a)).0;
    let from = links.partition_point(|link| of(link) < net);
    let to = from + links[from..].partition_point(|link| of(link) == net);
    &links[from..to]
}

/// The first edge without a positive finite resistance (zero would short two
/// nodes and hide a drop).
fn bad_resistance(resistance: &[Qty<Resistance, { prefix::BASE }>]) -> Result<(), PowerError> {
    match resistance
        .iter()
        .position(|r| !(r.raw() > 0.0 && r.is_finite()))
    {
        Some(edge) => Err(PowerError::BadResistance(
            u32::try_from(edge).expect("an edge index is a u32"),
        )),
        None => Ok(()),
    }
}

/// Refuse a grid no solve can pose (an edge that is not positive and finite,
/// no pad, an island no pad reaches) and number its unknowns into `scratch`:
/// every node but a pad, ascending. Returns how many there are.
fn pose_into(grid: &PowerGrid, scratch: &mut SolveScratch) -> Result<usize, PowerError> {
    let nodes = grid.node_count();
    let node_width = u32::try_from(nodes).expect("a node index is a u32");
    bad_resistance(&grid.edge_resistance)?;
    if grid.source_node.is_empty() {
        return Err(PowerError::Unanchored);
    }

    let SolveScratch {
        pairs,
        labels,
        reached,
        ..
    } = &mut *scratch;
    pairs.clear();
    pairs.extend(
        grid.edge_from
            .iter()
            .copied()
            .zip(grid.edge_to.iter().copied()),
    );
    components_into(node_width, pairs, labels);
    reached.clear();
    reached.resize(nodes, false);
    for &pad in &grid.source_node {
        reached[labels[pad as usize].0 as usize] = true;
    }
    if let Some(node) = labels.iter().position(|l| !reached[l.0 as usize]) {
        return Err(PowerError::UnanchoredIsland(
            u32::try_from(node).expect("a node index is a u32"),
        ));
    }

    // Every non-pad node gets an unknown index; a pad's is `NOT_AN_UNKNOWN`.
    let is_pad = &mut scratch.is_pad;
    is_pad.clear();
    is_pad.resize(nodes, false);
    for &pad in &grid.source_node {
        is_pad[pad as usize] = true;
    }
    scratch.unknown_of_node.clear();
    scratch.unknown_of_node.resize(nodes, NOT_AN_UNKNOWN);
    scratch.node_of_unknown.clear();
    for (node, &pad) in is_pad.iter().enumerate() {
        if pad {
            continue;
        }
        scratch.unknown_of_node[node] =
            u32::try_from(scratch.node_of_unknown.len()).expect("an unknown index is a u32");
        scratch
            .node_of_unknown
            .push(u32::try_from(node).expect("a node index is a u32"));
    }
    Ok(scratch.node_of_unknown.len())
}

/// Assemble the grid's reduced Laplacian over the unknowns [`pose_into`]
/// numbered.
fn assemble_grid_into(grid: &PowerGrid, scratch: &mut SolveScratch, unknowns: usize) {
    let SolveScratch {
        branch,
        unknown_of_node,
        ..
    } = &mut *scratch;
    branch.clear();
    branch.extend((0..grid.edge_count()).map(|i| {
        (
            unknown_of_node[grid.edge_from[i] as usize],
            unknown_of_node[grid.edge_to[i] as usize],
            UA_PER_MV_OHM / grid.edge_resistance[i].raw(),
        )
    }));
    assemble_into(scratch, unknowns);
}

/// Solve the grid for node voltages and branch currents; `out` is refilled.
///
/// Pads are eliminated before the iteration (leaving an SPD system), and an
/// island no pad reaches is refused first: CG on a singular system converges
/// to a meaningless solution.
///
/// # Errors
///
/// [`PowerError::NotFinite`] for a non-finite nominal, load or pad voltage,
/// or a non-finite result; [`PowerError::BadResistance`] for an edge that is
/// not positive and finite; [`PowerError::Unanchored`] with no pad;
/// [`PowerError::UnanchoredIsland`] for a node no pad reaches;
/// [`PowerError::NotConverged`] when the iteration limit is hit. `out` is
/// not a solution after an error.
pub fn solve_into(
    grid: &PowerGrid,
    scratch: &mut SolveScratch,
    out: &mut PowerSolution,
) -> Result<(), PowerError> {
    let edges = grid.edge_count();
    *out = PowerSolution::default();

    // Non-finite inputs first: a `NaN` would pass every check downstream.
    let not_finite = grid
        .node_nominal
        .iter()
        .zip(&grid.node_load)
        .position(|(v, i)| !(v.is_finite() && i.is_finite()))
        .or_else(|| {
            grid.source_voltage
                .iter()
                .position(|v| !v.is_finite())
                .map(|pad| grid.source_node[pad] as usize)
        });
    if let Some(node) = not_finite {
        return Err(PowerError::NotFinite(
            u32::try_from(node).expect("a node index is a u32"),
        ));
    }
    let unknowns = pose_into(grid, scratch)?;

    // Start at nominal (pads at their fixed voltage), so the residual measures
    // interconnect loss and the tolerance is a fraction of the drop.
    out.node_voltage.extend_from_slice(&grid.node_nominal);
    for (pad, &node) in grid.source_node.iter().enumerate() {
        out.node_voltage[node as usize] = grid.source_voltage[pad];
    }
    scratch.x.clear();
    scratch.x.extend(
        scratch
            .node_of_unknown
            .iter()
            .map(|&node| out.node_voltage[node as usize].raw()),
    );
    // Kirchhoff: the Laplacian row is minus the load.
    scratch.rhs.clear();
    scratch.rhs.extend(
        scratch
            .node_of_unknown
            .iter()
            .map(|&node| -grid.node_load[node as usize].raw()),
    );

    // A conductance to a pad moves `g * v` to the right-hand side; the bin slot
    // past the end absorbs the other rows' zero terms.
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

    assemble_grid_into(grid, scratch, unknowns);
    factorise_into(scratch, unknowns);
    conjugate_gradient(scratch)?;

    // Pads keep their exact fixed voltage.
    for unknown in 0..unknowns {
        out.node_voltage[scratch.node_of_unknown[unknown] as usize] = Qty::new(scratch.x[unknown]);
    }
    out.node_drop.extend(
        grid.node_nominal
            .iter()
            .zip(&out.node_voltage)
            .map(|(&nominal, &v)| nominal - v),
    );
    for i in 0..edges {
        let across = out.node_voltage[grid.edge_from[i] as usize].raw()
            - out.node_voltage[grid.edge_to[i] as usize].raw();
        let g = UA_PER_MV_OHM / grid.edge_resistance[i].raw();
        out.branch_current.push(Qty::new(across * g));
    }

    if !out.is_consistent_with(grid) {
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

/// Backward-Euler steps per rise time of the fastest switching node in
/// [`transient_into`]. Even, so that node's peak falls on a step. At 128 the
/// peak of an RC node's response to its pulse reads low by at most 0.61 % of
/// the closed form, at a time constant near a tenth of the rise, and by less
/// at any other (`dynamic_and_thermal.rs` in this crate's tests).
pub const STEPS_PER_RISE: u32 = 128;

/// Microamps per millivolt from a capacitance in pF over a step in ps:
/// `pF · mV / ps = mA`. Wrong here scales every decap and still passes the
/// laws.
const UA_PER_MV_PER_PF_PS: f64 = 1_000.0;

/// One switching event per node of a [`PowerGrid`], for [`transient_into`].
/// Every node column has one entry per node of the grid.
#[derive(Debug, Default)]
pub struct Stimulus {
    /// The peak of the node's triangular current pulse, µA, signed as
    /// [`PowerGrid::node_load`] (a ground rail's injects); zero for a node
    /// that does not switch.
    pub node_peak: Vec<Qty<Current, { prefix::MICRO }>>,
    /// The pulse's base, ps: it rises for the first half and falls for the
    /// second. Read only where the peak is not zero.
    pub node_rise_ps: Vec<f64>,
    /// Capacitance from the node to an ideal reference, pF: its decap.
    pub node_cap_pf: Vec<f64>,
    /// How long after the pulses start the grid is followed, ps; never less
    /// than the longest pulse.
    pub window_ps: f64,
}

/// The grid's response to one switching event at every node, from rest:
/// `out` is refilled, node for node, with the drop of largest magnitude each
/// node reaches, signed as [`PowerSolution::node_drop`]; a pad's is zero.
///
/// Each node's decap ties it to an ideal reference, and each switching node
/// draws a triangle from zero at `t = 0` to its peak at half its rise and
/// back to zero at its rise. Pads hold their voltage, so by superposition the
/// static solution adds to this response unchanged. Backward Euler with a
/// fixed step `h`, the shortest rise over [`STEPS_PER_RISE`], solves
/// `(G + C/h) r[k+1] = (C/h) r[k] + i[k+1]` with the static solve's
/// preconditioned conjugate gradient, factorised once (Kouroussis and Najm,
/// DAC 2003, pose the same recurrence for an RC grid). Once every pulse has
/// ended, the walk stops at the first step in which no node's drop grew:
/// `(G + C/h)⁻¹ C/h` is nonnegative, so each node's change keeps its sign
/// from then on and none can grow again. Otherwise it stops at the window.
///
/// Cost: one conjugate-gradient solve per step, at most `window / h` steps.
///
/// # Errors
///
/// As [`solve_into`] for the grid itself: [`PowerError::BadResistance`],
/// [`PowerError::Unanchored`], [`PowerError::UnanchoredIsland`],
/// [`PowerError::NotConverged`]. [`PowerError::NotFinite`] for a node whose
/// peak or decap is not finite, whose decap is negative, or whose rise is not
/// positive and finite where it switches, and for a non-finite response. A
/// grid with no switching node responds with zeros, never an error.
///
/// # Panics
///
/// Panics if a node column of `stimulus` does not have one entry per node.
pub fn transient_into(
    grid: &PowerGrid,
    stimulus: &Stimulus,
    scratch: &mut SolveScratch,
    out: &mut Vec<Qty<Voltage, { prefix::MILLI }>>,
) -> Result<(), PowerError> {
    // ponytail: one fixed step for the whole window; a step that grows after
    // the pulses if long windows cost too many solves.
    let nodes = grid.node_count();
    assert!(
        stimulus.node_peak.len() == nodes
            && stimulus.node_rise_ps.len() == nodes
            && stimulus.node_cap_pf.len() == nodes,
        "one stimulus entry per node"
    );
    out.clear();
    out.resize(nodes, Qty::new(0.0));
    let node_index = |node: usize| u32::try_from(node).expect("a node index is a u32");
    let bad = (0..nodes).position(|node| {
        let peak = stimulus.node_peak[node].raw();
        let (rise, cap) = (stimulus.node_rise_ps[node], stimulus.node_cap_pf[node]);
        !(peak.is_finite()
            && cap.is_finite()
            && cap >= 0.0
            && (peak == 0.0 || (rise.is_finite() && rise > 0.0)))
    });
    if let Some(node) = bad {
        return Err(PowerError::NotFinite(node_index(node)));
    }
    let Some(shortest) = (0..nodes)
        .filter(|&node| stimulus.node_peak[node].raw() != 0.0)
        .map(|node| stimulus.node_rise_ps[node])
        .reduce(f64::min)
    else {
        return Ok(());
    };

    let unknowns = pose_into(grid, scratch)?;
    assemble_grid_into(grid, scratch, unknowns);
    let steps_per_rise = f64::from(STEPS_PER_RISE);
    let step_ps = shortest / steps_per_rise;
    // Each unknown's `C/h`, on its diagonal and in its right-hand side, and
    // its pulse's length in steps: exactly `STEPS_PER_RISE` for the fastest.
    let mut decap = Vec::with_capacity(unknowns);
    let mut span = Vec::with_capacity(unknowns);
    let mut pulses_end = 0.0f64;
    for unknown in 0..unknowns {
        let node = scratch.node_of_unknown[unknown] as usize;
        let c = UA_PER_MV_PER_PF_PS * stimulus.node_cap_pf[node] / step_ps;
        let slot = scratch.row_start[unknown] as usize;
        scratch.value[slot] += c;
        scratch.inv_diag[unknown] = 1.0 / scratch.value[slot];
        decap.push(c);
        span.push(steps_per_rise * (stimulus.node_rise_ps[node] / shortest));
        if stimulus.node_peak[node].raw() != 0.0 {
            pulses_end = pulses_end.max(span[unknown]);
        }
    }
    factorise_into(scratch, unknowns);
    let last = (stimulus.window_ps / step_ps)
        .max(pulses_end)
        .min(f64::from(u32::MAX));

    scratch.x.clear();
    scratch.x.resize(unknowns, 0.0);
    let mut previous = vec![0.0f64; unknowns];
    let mut step = 0u32;
    while f64::from(step) < last {
        step += 1;
        let at = f64::from(step);
        let SolveScratch {
            rhs,
            x,
            node_of_unknown,
            ..
        } = &mut *scratch;
        rhs.clear();
        rhs.extend((0..unknowns).map(|unknown| {
            let node = node_of_unknown[unknown] as usize;
            let fraction = at / span[unknown];
            let shape = if fraction <= 1.0 {
                1.0 - (2.0 * fraction - 1.0).abs()
            } else {
                0.0
            };
            decap[unknown] * x[unknown] + stimulus.node_peak[node].raw() * shape
        }));
        conjugate_gradient(scratch)?;

        let mut grew = false;
        for (unknown, before) in previous.iter_mut().enumerate() {
            let (drop, node) = (
                scratch.x[unknown],
                scratch.node_of_unknown[unknown] as usize,
            );
            if !drop.is_finite() {
                return Err(PowerError::NotFinite(node_index(node)));
            }
            grew |= drop.abs() > before.abs();
            *before = drop;
            if drop.abs() > out[node].raw().abs() {
                out[node] = Qty::new(drop);
            }
        }
        if at >= pulses_end && !grew {
            break;
        }
    }
    Ok(())
}

/// Effective resistance between every terminal pair of one network row: `out`
/// is refilled with `(a, b, ohms)`, `a < b`, ascending; a pair in different
/// components is absent (not infinite).
///
/// Interior nodes are Kron-eliminated in minimum-degree order, then each
/// component's `k × k` terminal Laplacian is grounded and inverted exactly.
///
/// # Errors
///
/// [`PowerError::BadResistance`] for an edge of the row that is not positive
/// and finite (its index within the row), and [`PowerError::NotFinite`] when
/// a component's terminal Laplacian will not invert.
///
/// # Panics
///
/// Panics if `row` is not below `networks.len()`.
pub fn effective_resistance_into(
    networks: &NetNetworks,
    row: u32,
    scratch: &mut SolveScratch,
    out: &mut Vec<(u32, u32, Qty<Resistance, { prefix::BASE }>)>,
) -> Result<(), PowerError> {
    out.clear();
    let nodes = networks.nodes_of(row).0.len();
    let terminal = networks.terminals_of(row);
    let (edge_from, edge_to, edge_resistance) = networks.edges_of(row);
    let node_width = u32::try_from(nodes).expect("a node index is a u32");
    // The index named is within the row.
    bad_resistance(edge_resistance)?;

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
    pairs.clear();
    pairs.extend(edge_from.iter().copied().zip(edge_to.iter().copied()));
    components_into(node_width, pairs, labels);

    let terminals = terminal.len();
    terminal_of_node.clear();
    terminal_of_node.resize(nodes, NONE);
    for (index, &t) in terminal.iter().enumerate() {
        terminal_of_node[t as usize] = u32::try_from(index).expect("a terminal index is a u32");
    }

    // Kron-eliminate every interior node.
    elim.reset(nodes);
    for edge in 0..edge_from.len() {
        let (a, b) = (edge_from[edge], edge_to[edge]);
        if a != b {
            elim.link(a, b, 1.0 / edge_resistance[edge].raw());
        }
    }
    for (node, &of_node) in terminal_of_node.iter().enumerate() {
        if of_node == NONE {
            let v = u32::try_from(node).expect("a node index is a u32");
            let degree = elim.refresh(v);
            elim.queue.push(Reverse((degree, v)));
        }
    }
    // A popped entry whose degree is stale is re-queued at its current one.
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
        for i in 0..elim.fringe.len() {
            let u = elim.fringe[i].0;
            if terminal_of_node[u as usize] == NONE {
                let updated = elim.refresh(u);
                elim.queue.push(Reverse((updated, u)));
            }
        }
    }

    // The terminal Laplacian, `k × k` row-major.
    dense.clear();
    dense.resize(terminals * terminals, 0.0);
    for (i, &t) in terminal.iter().enumerate() {
        elim.refresh(t);
        let mut h = elim.head[t as usize];
        while h != NONE {
            let j = terminal_of_node[elim.dst[h as usize] as usize] as usize;
            let w = elim.g[h as usize];
            dense[i * terminals + j] -= w;
            dense[i * terminals + i] += w;
            h = elim.next[h as usize];
        }
    }

    // Per component: ground its lowest terminal and invert the rest.
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
        let unknowns = group.len() - 1;
        if unknowns == 0 {
            continue;
        }
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
        // `R(a, b) = X_aa + X_bb - 2 X_ab`, the grounded terminal reading zero.
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

    for (i, &a) in terminal.iter().enumerate() {
        for (j, &b) in terminal.iter().enumerate().skip(i + 1) {
            if labels[a as usize] == labels[b as usize] {
                out.push((a, b, Qty::new(probe[i * terminals + j])));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        assemble_into, factorise_into, ChainProfile, Point, SolveScratch, TapIndex, NOT_AN_UNKNOWN,
    };
    use gpurify_geom::Dbu;
    use gpurify_geom::{Bbox, GeometryStore, GeometryStoreBuilder, LayerId, PolyId};

    /// One polygon on layer zero, from its rectilinear ring.
    fn shape(xs: &[i64], ys: &[i64]) -> GeometryStore {
        let mut builder = GeometryStoreBuilder::default();
        let xs: Vec<Dbu> = xs.iter().map(|&v| Dbu::new_unchecked(v)).collect();
        let ys: Vec<Dbu> = ys.iter().map(|&v| Dbu::new_unchecked(v)).collect();
        builder.push(LayerId(0), &xs, &ys);
        builder.finish(1).0
    }

    /// A rectangle is one slab of its short dimension: length over width.
    ///
    /// Oracle: closed form. A 400 x 10 bar is 400 / 10 = 40 squares, and its
    /// narrowest place is its width, 10.
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

    /// A `100 x 100` L on ten-wide arms is `10/100 + 90/10 = 9.1` squares, not
    /// its square bounding box's 1 (a drop nine times low).
    ///
    /// Oracle: closed form, as above: 10/100 + 90/10 = 9.1 squares along the L,
    /// its narrowest place the 10-wide arm.
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

    /// Rayleigh monotonicity: widening a polygon never raises a segment's squares.
    ///
    /// Oracle: law, Rayleigh monotonicity: resistance cannot rise when
    /// conductor is added, so the wider L costs no more squares on any segment.
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

    /// IC(0): `L D Lᵀ` equals the matrix wherever the matrix is non-zero. A
    /// four-node cycle with one pad is the smallest case with a fill hole.
    ///
    /// Oracle: the defining property of IC(0): `L D L^T` equals the matrix on
    /// its sparsity pattern, checked entry by entry on a four-node cycle with
    /// one pad.
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
        // The factor, densely: `L` with its unit diagonal, and `D`.
        let mut l = [[0.0f64; N]; N];
        for (i, row) in l.iter_mut().enumerate() {
            row[i] = 1.0;
            for t in scratch.l_start[i] as usize..scratch.l_start[i + 1] as usize {
                row[scratch.l_col[t] as usize] = scratch.l_val[t];
            }
        }
        let d = &scratch.l_diag;

        let mut holes = 0;
        for i in 0..N {
            for j in 0..N {
                let mut llt = 0.0;
                for k in 0..N {
                    llt += l[i][k] * d[k] * l[j][k];
                }
                if a[i][j] == 0.0 {
                    holes += usize::from(llt.abs() > 1e-9);
                    continue;
                }
                assert!(
                    (llt - a[i][j]).abs() < 1e-9 * a[i][j].abs(),
                    "L D Lt disagrees with A at ({i},{j}): {llt} against {}",
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

    /// The ring search agrees with an exhaustive scan, including degenerate
    /// aspect ratios and markers outside the extent.
    ///
    /// Oracle: differential against `brute_force`, the nearest tap by an
    /// exhaustive scan, over random taps, degenerate aspect ratios and markers
    /// outside the extent.
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

    /// A device draws its current from a shape its marker touches, not from
    /// the shape whose centre is nearest: a load whose marker sits on a 40 µm
    /// rail at x = 2.5 µm is 18.5 µm from the rail's centre but 5.0 µm from
    /// the centre of a strap crossing at x = 5 µm that it does not touch (O1,
    /// PDNSim). Of several it touches, the nearest centre decides (a MOS
    /// draws from the diffusion beside its channel rather than metal routed
    /// over it, as before); touching none, the nearest centre.
    ///
    /// Oracle: hand-derived from the boxes. Marker (2.4..2.6, 2.9..3.1) µm
    /// touches the rail (1..41 by 2.8..3.2) and not the strap (4.8..5.2 by
    /// 1.4..9.0); marker (4.9..5.1, 2.9..3.1) touches both, the strap's
    /// centre (5.0, 5.2) 2.2 µm away and the rail's (21, 3) 16 µm; marker
    /// (0.4..0.6, 8.9..9.1) touches neither.
    #[test]
    fn a_device_draws_from_a_shape_its_marker_touches() {
        let b = |xlo, ylo, xhi, yhi| Bbox {
            xlo: Dbu::new_unchecked(xlo),
            ylo: Dbu::new_unchecked(ylo),
            xhi: Dbu::new_unchecked(xhi),
            yhi: Dbu::new_unchecked(yhi),
        };
        let mut index = TapIndex {
            boxes: vec![b(4800, 1400, 5200, 9000), b(1000, 2800, 41_000, 3200)],
            ..TapIndex::default()
        };
        index.at = index.boxes.iter().map(|&x| super::centre(x)).collect();
        index.grid();
        let marker = b(2400, 2900, 2600, 3100);
        assert_eq!(
            index.nearest(super::centre(marker)),
            0,
            "the strap's centre is nearer"
        );
        assert_eq!(index.host(marker), 1, "the load touches only the rail");
        assert_eq!(
            index.host(b(4900, 2900, 5100, 3100)),
            0,
            "both: the nearer centre"
        );
        assert_eq!(
            index.host(b(400, 8900, 600, 9100)),
            0,
            "neither: the nearest centre"
        );
    }

    /// The bucketed pass agrees with a masked sum over every node per net.
    ///
    /// Oracle: differential against a naive masked sum over every node per net,
    /// over 500 random grids with zero and cancelling loads.
    #[test]
    fn discarded_budget_agrees_with_a_per_net_masked_sum() {
        use super::{discarded_budget, IntentMap, NetId, PowerGrid};
        use gpurify_geom::Qty;
        use gpurify_ingest::intent::NetLimits;
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move |m: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % m
        };
        for _ in 0..500 {
            let mut grid = PowerGrid::default();
            for _ in 0..next(12) {
                grid.node_net
                    .push(NetId(u32::try_from(next(4)).expect("small")));
                // Zeros and cancelling pairs are the interesting loads.
                let load = [0.0, -0.0, 1.5, -1.5, 2.0][usize::try_from(next(5)).expect("small")];
                grid.node_load.push(Qty::new(load));
            }
            let mut intent = IntentMap::default();
            for net in 0..5u32 {
                if next(2) == 0 {
                    intent.limit_net.push(NetId(net));
                    let budget =
                        [None, Some(0.0), Some(3.0)][usize::try_from(next(3)).expect("small")];
                    intent.limit.push(NetLimits {
                        budget_current_ua: budget,
                        ..NetLimits::default()
                    });
                }
            }
            let naive = intent
                .limit_net
                .iter()
                .zip(&intent.limit)
                .any(|(&net, limits)| {
                    let load: f64 = (0..grid.node_net.len())
                        .map(|n| {
                            f64::from(u8::from(grid.node_net[n] == net)) * grid.node_load[n].raw()
                        })
                        .sum();
                    limits.budget_current_ua.is_some_and(|b| b != 0.0) && load == 0.0
                });
            assert_eq!(discarded_budget(&grid, &intent), naive);
        }
    }
}
