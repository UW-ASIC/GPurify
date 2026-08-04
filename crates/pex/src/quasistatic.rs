//! Field-solved extraction, for nets the closed forms cannot describe.
//!
//! A boundary-element formulation: conductor surfaces are meshed into panels,
//! each panel carries an unknown charge density, and the potential each panel
//! sees from all the others gives a dense linear system. Solving it for one
//! conductor at unit potential and integrating the resulting charge gives one
//! column of the Maxwell capacitance matrix.
//!
//! The system is dense and large, so it is solved iteratively — GMRES — and the
//! matrix is never formed. The matvec is the entire cost, which is why the
//! matvec is the seam.
//!
//! # The oracles
//!
//! Stronger here than anywhere else in the tree, because electrostatics has
//! closed forms and conservation laws:
//!
//! - an isolated sphere of radius `r` has capacitance `4πε₀r`
//! - a parallel-plate pair approaches `εA/d` as the plate spacing shrinks
//! - the Maxwell capacitance matrix is **symmetric** — `C[i][j] == C[j][i]` —
//!   by reciprocity, for any geometry whatsoever
//! - it is diagonally dominant, and its off-diagonals are non-positive
//! - the electrostatic energy `½ VᵀCV` is non-negative for every `V`
//!
//! The symmetry law is the most useful of these: it holds for arbitrary meshes
//! and arbitrary conductors, so it catches errors on realistic geometry where
//! no closed form exists.

pub mod gpu;
pub mod matvec;
pub mod mesh;
pub mod solve;

use crate::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_core::{GeometryStore, LayerId};
use gpurify_ingest::deck::ProcessStack;
use gpurify_topology::{NetId, NetTable};
use gpurify_units::{prefix, Capacitance, Dbu, Grid, Qty, MAX_ABS_DBU};

/// Farads to the femtofarads [`Parasitic`] states capacitance in.
const FEMTOFARADS_PER_FARAD: f64 = 1e15;

/// The Maxwell capacitance matrix for a set of conductors.
///
/// Stored as the full square rather than a triangle: symmetry is a *result* to
/// be checked, not an assumption to be built in. Storing a triangle would make
/// the symmetry test vacuous.
#[derive(Debug, Default)]
pub struct CapMatrix {
    /// Which net each row and column belongs to.
    pub net: Vec<NetId>,
    /// Row-major, `n × n`, in farads.
    pub value: Vec<f64>,
}

impl CapMatrix {
    pub fn dim(&self) -> usize {
        let n = self.net.len();
        // The side is the net column, not a square root of the value column:
        // one net per row *and* column is what the type means. Asserting the
        // two agree is what makes `get`'s `i * n + j` an addressing fact rather
        // than an assumption.
        debug_assert_eq!(
            self.value.len(),
            n * n,
            "an {n} by {n} matrix holds {} entries",
            n * n
        );
        n
    }

    pub fn get(&self, i: usize, j: usize) -> f64 {
        let n = self.dim();
        debug_assert!(i < n, "row {i} is outside a {n} by {n} matrix");
        debug_assert!(j < n, "column {j} is outside a {n} by {n} matrix");
        self.value[i * n + j]
    }

    /// Largest relative asymmetry, `|C[i][j] − C[j][i]| / |C[i][j]|`.
    ///
    /// **Decision** — pure, and the headline check on any solve. Exposed
    /// because it is also worth *reporting*: an asymmetry above the solver's
    /// tolerance means the answer has not converged, whatever the residual says.
    pub fn asymmetry(&self) -> f64 {
        let n = self.dim();
        // A nested scan is the shape of the question, not a shortcut waiting to
        // be replaced: the mirror of a row-major entry is strided by `n`, and
        // `n` is the selected-conductor count of one quasi-static run — tens at
        // the outside.
        let mut worst = 0.0_f64;
        // Poison, carried beside the fold rather than in it. `f64::max` returns
        // the other operand on a NaN, which is what makes the `0 / 0` two
        // exactly-zero entries produce — no asymmetry — fold away. That same
        // property would swallow a NaN or infinite *entry* and report a
        // poisoned matrix as perfectly symmetric, which is a clean answer for a
        // matrix nothing could have checked. `x * 0.0` is a signed zero for
        // every finite `x` and NaN for a NaN or an infinity, so this separates
        // the two cases branchlessly and fails closed: the sum below is NaN,
        // and NaN is below no tolerance any caller compares against.
        //
        // `x * 0.0` and not the `x - x` this used to spell: the truth tables are
        // identical — both are the finite/non-finite indicator, `inf - inf`
        // being NaN just as `inf * 0.0` is — but `x - x` is `clippy::eq_op`,
        // which is deny-by-default and stopped `gpurify-pex` compiling under
        // clippy at all, taking `export`, `engine` and `cli` unlinted with it.
        // The signed zeros are harmless: `-0.0 + 0.0` is `+0.0`, and the fold
        // starts at `0.0`.
        let mut poison = 0.0_f64;
        for i in 0..n {
            for j in 0..n {
                let entry = self.value[i * n + j];
                let mirror = self.value[j * n + i];
                // An entry mirrored by an exact zero divides by zero to an
                // infinity, which survives the `max` — and infinitely
                // asymmetric is what it should report.
                worst = worst.max((entry - mirror).abs() / entry.abs());
                poison += entry * 0.0 + mirror * 0.0;
            }
        }
        debug_assert!(!worst.is_nan(), "the max fold kept a NaN it should drop");
        debug_assert!(worst >= 0.0, "a relative gap is non-negative");
        worst + poison
    }

    /// Electrostatic energy `½ VᵀCV`. Negative means the matrix is not a
    /// physical capacitance matrix.
    pub fn energy(&self, potentials: &[f64]) -> f64 {
        let n = self.dim();
        debug_assert_eq!(
            potentials.len(),
            n,
            "one potential per conductor of a {n} by {n} matrix"
        );
        // `V ᵀ C V` one row at a time. Both folds are strict left folds in
        // ascending index order — that is what keeps the sum bit-identical
        // across runs, and it is why neither may be reassociated.
        let mut total = 0.0_f64;
        for i in 0..n {
            let row = &self.value[i * n..(i + 1) * n];
            debug_assert_eq!(row.len(), potentials.len(), "SoA columns must agree");
            let mut flux = 0.0_f64;
            // `zip` rather than an index: it carries the trip count of the
            // shorter half, so there is no bounds check and no panic edge in
            // the body. The length check above is what makes "shorter half" a
            // non-question.
            for (c, v) in row.iter().zip(potentials) {
                flux += c * v;
            }
            total += potentials[i] * flux;
        }
        0.5 * total
    }
}

/// What a solve achieved, reported rather than assumed.
///
/// The old GPU path computed in `f32` and never checked, on a signoff tool.
/// Every number here exists so that cannot recur: the achieved residual is
/// measured in `f64` on the host and travels with the result.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Accuracy {
    /// Relative residual actually reached, in `f64`.
    pub residual: f64,
    /// Residual that was asked for.
    pub tolerance: f64,
    pub iterations: u32,
    /// Which adapter did the matvec. Recorded so a run's numbers can be
    /// attributed, and so a CI job with no device can assert the fallback was
    /// taken rather than silently passing.
    pub backend: matvec::Backend,
    /// [`CapMatrix::asymmetry`] of the result.
    pub asymmetry: f64,
}

/// Extract selected nets by field solve.
///
/// **Transform, A-to-B.** Caller owns both outputs. Nets are meshed in
/// ascending [`NetId`] order and the system assembled in that order, so the
/// matrix is a deterministic function of the geometry alone.
///
/// Returns the accuracy alongside the network. A caller that ignores it is
/// asserting the answer is good without having looked, which is exactly what
/// went wrong before.
///
/// `grid` is the run's grid, handed down to [`mesh::build_into`]: the solve
/// works in SI and the geometry is in grid units.
pub fn extract_into(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    stack: &ProcessStack,
    grid: gpurify_units::Grid,
    options: solve::Options,
    matrix: &mut CapMatrix,
    out: &mut ParasiticNetwork,
) -> Result<Accuracy, solve::SolveError> {
    debug_assert!(options.tolerance > 0.0, "a tolerance of zero is unreachable");
    debug_assert!(options.max_iterations > 0, "a solve with no iteration budget");

    matrix.net.clear();
    matrix.value.clear();
    // All five columns — see `ParasiticNetwork::clear`, which
    // `analytical::extract_into` opens with for the same reason.
    out.clear();

    // "Nets are meshed in ascending `NetId` order and the system assembled in
    // that order" — so the order is established here, once, and everything
    // below inherits it: the mesh's conductor bands, the matrix rows, and the
    // node column, whose invariant is that its net ranges ascend. Duplicates
    // are deliberately *not* dropped: two conductors over one net is a singular
    // system, which the solver refuses by name, where a silent dedup would
    // return a matrix one row smaller than the caller asked for.
    let mut order = selected.to_vec();
    order.sort_unstable();

    let mut mesh = mesh::Mesh::default();
    let meshing = mesh_options(store, nets, &order, stack, grid);
    mesh::build_into(store, nets, &order, stack, meshing, grid, &mut mesh)
        // The frozen return type is `solve::SolveError`, which has no variant
        // for a mesh that could not be built — see the note on `mesh_options`.
        // Fail closed anyway: a refusal at iteration zero is wrong about *why*,
        // and an empty clean matrix would be wrong about *whether*.
        .map_err(|_| solve::SolveError::Breakdown(0))?;

    let n = order.len();
    let panels = mesh.panel.len();
    debug_assert_eq!(mesh.conductor_net, order, "one conductor per selected net");
    debug_assert_eq!(mesh.conductor_start.len(), n + 1, "a CSR over {n} bands");
    debug_assert_eq!(mesh.epsilon.len(), panels, "one permittivity per panel");

    matrix.net.extend_from_slice(&order);
    matrix.value.resize(n * n, 0.0);

    // The adapter is selected, never assumed: probe for a device, ask
    // `matvec::select` whether this problem is above that device's own measured
    // crossover, and upload only if it is. Three fail-closed steps, all landing
    // on the host `f64` reference adapter — a probe that found a device it
    // could not use, a panel count below the crossover, and an upload that
    // refused. `Accuracy::backend` is read off the adapter that actually ran,
    // so the attribution is honest whichever arm was taken.
    //
    // `Device::find`'s `Err` is discarded rather than mapped: the frozen return
    // type is `solve::SolveError`, which has no variant for a device, and a
    // solve that ran correctly on the host is not a failure to report.
    let device = gpu::Device::find().ok().flatten();
    let accelerated = match matvec::select(panels, device.as_ref()) {
        matvec::Backend::GpuF32 => device
            .as_ref()
            .and_then(|device| gpu::GpuMatVec::upload(device, &mesh).ok()),
        matvec::Backend::Cpu => None,
    };

    let (residual, iterations, backend) = match accelerated {
        Some(operator) => columns_into(&operator, &mesh, options, matrix)?,
        None => columns_into(&matvec::CpuMatVec::build(&mesh), &mesh, options, matrix)?,
    };

    debug_assert_eq!(matrix.value.len(), n * n, "the matrix is square at {n}");

    // One node per net. A field solve is over whole conductors, so it has no
    // branch points to split at, and the net's lowest layer is the one a writer
    // anchors it to — a property of the geometry, so it is deterministic.
    out.node_net.extend_from_slice(&order);
    for &net in &order {
        let polys = nets.polys_of(net);
        debug_assert!(!polys.is_empty(), "net {net:?} was meshed with no geometry");
        let mut low = LayerId(u16::MAX);
        for &poly in polys {
            // A gather, not a branch: `min` is the branchless comparator and
            // the layer lookup is a data-dependent address.
            low = low.min(store.poly_layer(poly));
        }
        out.node_layer.push(low);
    }
    debug_assert_eq!(out.node_layer.len(), n, "one node per selected net");

    // The Maxwell matrix as a network. Row sum is the charge on a net when
    // every net is at one volt, which is its capacitance to ground; the
    // negated off-diagonal is the coupling, emitted once per pair by the lower
    // node. Pushed by ascending `from`, ground before coupling and coupling by
    // ascending `to`, which is canonical order already — `sort_canonical` is
    // the guarantee, not the mechanism.
    for row in 0..n {
        let from = NodeId(u32::try_from(row).expect("a node index is a u32"));
        // Strict left fold in ascending index order: the row sum is a reported
        // capacitance, so it has to be the same bits on every run.
        let mut ground = 0.0_f64;
        for &c in &matrix.value[row * n..(row + 1) * n] {
            ground += c;
        }
        out.push(from, None, Parasitic::GroundCap(femtofarads(ground)));
        for other in (row + 1)..n {
            let to = NodeId(u32::try_from(other).expect("a node index is a u32"));
            let coupling = -matrix.value[row * n + other];
            out.push(from, Some(to), Parasitic::CouplingCap(femtofarads(coupling)));
        }
    }
    debug_assert_eq!(
        out.element_count(),
        n * (n + 1) / 2,
        "one ground element per net and one coupling per pair"
    );

    Ok(Accuracy {
        residual,
        tolerance: options.tolerance,
        iterations,
        backend,
        asymmetry: matrix.asymmetry(),
    })
}

/// Solve one column per conductor into an already-sized [`CapMatrix`].
///
/// **Transform, A-to-B.** Caller owns `matrix`, whose `net` column is filled
/// and whose `value` column is already `n × n`. Returns the worst residual over
/// the columns, the total iteration count, and the backend read off the adapter
/// that ran — never a name chosen by the caller.
///
/// Generic over the seam, which is the point of the seam being where it is:
/// every decision above the multiply — the iteration strategy, the residual,
/// the refusal of a non-finite entry — happens once here, in `f64`, for both
/// adapters. An adapter multiplies, so that is all an adapter can get wrong.
fn columns_into<M: matvec::MatVec>(
    operator: &M,
    mesh: &mesh::Mesh,
    options: solve::Options,
    matrix: &mut CapMatrix,
) -> Result<(f64, u32, matvec::Backend), solve::SolveError> {
    let n = mesh.conductor_net.len();
    let panels = mesh.panel.len();
    debug_assert_eq!(
        operator.dim(),
        panels,
        "the operator is the mesh it was built from"
    );
    debug_assert_eq!(matrix.value.len(), n * n, "the matrix is square at {n}");
    debug_assert_eq!(matrix.net.len(), n, "one row per meshed conductor");

    let mut workspace = solve::Workspace::default();
    let mut potential = Vec::with_capacity(panels);
    let mut charge = vec![0.0_f64; panels];
    let mut residual = 0.0_f64;
    let mut iterations = 0_u32;

    // One solve per conductor: unit potential on it, ground on the rest, and
    // the charge that answer puts on conductor `row` is `C[row][column]`. The
    // loop is over conductors, not rows — the bulk work is inside it.
    for column in 0..n {
        let owner = u32::try_from(column).expect("a conductor index is a u32 in the mesh");
        // One collocation row per panel, refilled into the caller-owned buffer
        // rather than reallocated per column. `f64::from(bool)` is the
        // branchless form of "one volt on the driven conductor, ground on the
        // rest" — no `if`, and the body is a function of its own row.
        potential.clear();
        potential.reserve(panels);
        for panel in &mesh.panel {
            potential.push(f64::from(panel.conductor == owner));
        }
        debug_assert_eq!(potential.len(), panels, "one collocation row per panel");

        // A fixed zero initial guess, not the previous column's answer: the
        // matrix has to be a function of the geometry alone, and a warm start
        // would make column `c` depend on column `c - 1`'s round-off.
        charge.fill(0.0);
        let converged = solve::refine(operator, &potential, options, &mut charge, &mut workspace)?;
        debug_assert!(
            converged.residual <= options.tolerance,
            "a converged solve returned {} against a tolerance of {}",
            converged.residual,
            options.tolerance
        );
        residual = residual.max(converged.residual);
        iterations = iterations.saturating_add(converged.iterations);

        for row in 0..n {
            let start = subscript(mesh.conductor_start[row]);
            let end = subscript(mesh.conductor_start[row + 1]);
            debug_assert!(start <= end && end <= panels, "band {row} is {start}..{end}");
            // The solve's unknown is the panel's *total* charge, not its charge
            // density — see `matvec::CpuMatVec::apply_observed`, where that is
            // what makes `P` symmetric and the self-potential coefficient
            // `√A`-scaled. So the conductor's charge is the plain band sum; an
            // `area` weight here would reintroduce the `diag(A)` factor the
            // operator was built to keep out and cost reciprocity.
            let mut total = 0.0_f64;
            for &q in &charge[start..end] {
                total += q;
            }
            // Surviving `if`: false in every converged run, so it predicts
            // perfectly, and it is per conductor pair rather than per panel.
            // Fail closed — a non-finite entry reaching `CapMatrix` is a
            // capacitance a report would print.
            if !total.is_finite() {
                return Err(solve::SolveError::NonFinite(iterations));
            }
            matrix.value[row * n + column] = total;
        }
    }

    Ok((residual, iterations, operator.backend()))
}

/// Refuse rather than mesh beyond this many panels.
///
/// The matvec is dense, so an iteration costs `panels²`: a million of them is a
/// solve that runs for a week, and saying so is what
/// [`mesh::MeshOptions::max_panels`] is for. [`mesh_options`] coarsens the panel
/// edge to stay under this, so the limit is reached by a selection with more
/// faces than the budget allows rather than by the resolution chosen here.
const MAX_PANELS: u32 = 1 << 20;

/// What [`nm_to_dbu`] answers for a length the process stack does not state.
///
/// `i64::MAX` so it folds away under the `min` in [`finest_feature`] — an
/// undescribed layer must not be the smallest feature in the process.
const UNSTATED: i64 = i64::MAX;

/// How finely [`extract_into`] meshes.
///
/// **Decision** — pure: the process stack, the geometry about to be solved and
/// the run's grid in, one [`mesh::MeshOptions`] out.
///
/// The resolution is read off the process rather than off a constant. A
/// boundary element resolves a field across its own edge, so the length that
/// decides the edge is the smallest one the stack states — a layer's thickness,
/// which is how tall a conductor's side face is, or a dielectric gap, which is
/// the distance the field between two layers falls off over. Meshing at that
/// length puts at least one panel across every feature the process has, and the
/// number moves with the PDK: a 30 nm metal is meshed at 30 nm and a 5 µm
/// redistribution layer at 5 µm, where a fixed half-micrometre under-resolved
/// the first and charged the second for panels it did not need.
///
/// Two clamps sit on top, both in the fail-closed direction:
///
/// - the edge is coarsened until the *estimated* panel count fits
///   [`MAX_PANELS`], so a fine process over a large selection is answered
///   coarsely instead of refused. An estimate is not a guarantee — it is a
///   surface area over a panel area, and a face smaller than a panel still
///   costs one — so [`mesh::MeshError::TooManyPanels`] is still live above it,
///   and still refuses rather than truncating.
/// - the edge floors at one database unit. A zero edge cuts a face into no
///   panels, which is the fail-open direction for this knob.
///
/// Proximity refinement is set to the panel edge itself: a conductor nearer a
/// foreign conductor than one panel is wide sits in that conductor's near
/// field, where the centroid approximation in [`matvec`] is at its worst, and
/// halving the edge there is where the refinement buys the most. It costs the
/// O(n²) solid scan in [`mesh::build_into`], which is over the selection's
/// polygons and not over the layout.
///
/// The scan for the finest feature is over the whole stack rather than over the
/// layers the selection happens to occupy, so one thin barrier row meshes a
/// coarse selection at the barrier's scale. That is the direction to be wrong
/// in: an over-meshed run is slow and still bounded by the two clamps above,
/// where an under-meshed one is a capacitance a report prints. It is also why
/// the resolution is not clamped against `solve::Options` — a mesh too fine for
/// the iteration budget comes back as `solve::SolveError::NotConverged`, which
/// is a refusal and not a number.
///
/// The caller still cannot tune any of this: `extract_into` is frozen carrying
/// `solve::Options` and no [`mesh::MeshOptions`], so the accuracy knob is
/// reachable only by editing here. Filed in `docs/SIGNATURE_DEFECTS.md` under
/// "pex quasistatic".
fn mesh_options(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    stack: &ProcessStack,
    grid: Grid,
) -> mesh::MeshOptions {
    debug_assert!(grid.dbu_per_um() > 0, "a Grid is positive by construction");

    let feature = finest_feature(stack, grid);
    debug_assert!(feature >= 1, "a resolution of zero is an infinite refinement");

    let surface = surface_area(store, nets, selected, thickest_layer(stack, grid));
    debug_assert!(surface >= 0, "a surface area is non-negative");

    // The budget is a floor, not a target: it is the finest edge that still
    // fits, so the coarser of the two wins and a process finer than the budget
    // allows is meshed at the budget.
    let max_edge = feature.max(budget_edge(surface)).clamp(1, MAX_ABS_DBU);
    debug_assert!(
        (1..=MAX_ABS_DBU).contains(&max_edge),
        "a panel edge is a coordinate, so it lives in the coordinate domain"
    );

    mesh::MeshOptions {
        max_edge: Dbu::new_unchecked(max_edge),
        proximity_refine: Dbu::new_unchecked(max_edge),
        max_panels: MAX_PANELS,
    }
}

/// The smallest length the process stack states, in database units.
///
/// Every layer's thickness, and every positive gap between one layer's ceiling
/// and another's floor. A non-positive gap is two layers that coincide or
/// overlap — a stack stating one height for several layers has as many of those
/// as it has pairs — and is dropped by [`nm_to_dbu`] along with every unstated
/// row.
///
/// [`UNSTATED`] when the stack states nothing usable, which is a stack
/// [`mesh::build_into`] refuses by name for every polygon it is handed. Not a
/// bulk loop: a stack holds one row per layer of a PDK, so the pair scan is tens
/// against tens, and it is the same shape `mesh::extrusion_table` is written in.
fn finest_feature(stack: &ProcessStack, grid: Grid) -> i64 {
    // The rows both columns agree on: a gap needs a floor and a ceiling, and a
    // stack whose columns disagree states neither past the shorter of them.
    let rows = stack.thickness_nm.len().min(stack.height_nm.len());

    let mut finest = UNSTATED;
    for a in 0..rows {
        finest = finest.min(nm_to_dbu(stack.thickness_nm[a], grid));
        let ceiling = stack.height_nm[a] + stack.thickness_nm[a];
        // Ordered pairs, both ways round: of any two layers exactly one sits
        // above the other, and the reversed pair's gap is negative and dropped.
        // `b == a` is the layer's own negated thickness, dropped the same way.
        for b in 0..rows {
            finest = finest.min(nm_to_dbu(stack.height_nm[b] - ceiling, grid));
        }
    }
    finest
}

/// The largest thickness the stack states, in database units, or zero when it
/// states none.
///
/// Bounds the side-face term of [`surface_area`] only. An overestimate coarsens
/// the mesh, which is the direction a budget may safely be wrong in; an
/// underestimate would let the panel count past the limit and turn an answer
/// into a refusal.
fn thickest_layer(stack: &ProcessStack, grid: Grid) -> i64 {
    let mut thickest = 0;
    for &nm in &stack.thickness_nm {
        let stated = nm_to_dbu(nm, grid);
        // Not a bulk loop — one row per layer of a PDK — so the branch costs
        // nothing and says what it means: a layer the stack does not describe
        // has no thickness that could be the largest one.
        if stated != UNSTATED {
            thickest = thickest.max(stated);
        }
    }
    debug_assert!(
        (0..=MAX_ABS_DBU).contains(&thickest),
        "a layer thickness is a length in the coordinate domain"
    );
    thickest
}

/// The surface area of the selected conductors, in database units squared.
///
/// **Decision** — pure, and an estimate on purpose: a polygon is boxed and
/// extruded to `thickness`, so the answer is `2wh + 2(w + h)t` per polygon,
/// which is what [`mesh::build_into`] will actually panel if every polygon were
/// its own bounding box. It bounds a panel count, not a capacitance.
fn surface_area(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    thickness: i64,
) -> i128 {
    debug_assert!(thickness >= 0, "a layer thickness is non-negative");
    let t = i128::from(thickness);

    let mut surface = 0_i128;
    for &net in selected {
        // Bulk: one row per polygon of the selection, mapped to a face area and
        // summed. No data-dependent branch in the body — `max(0)` is the
        // branchless form of "an empty box contributes no area" — and the loop
        // bound is the net's polygon range rather than a predicate on the row.
        // `|w|, |h| <= 2^41` and a selection is far under `2^24` polygons, so
        // the accumulator cannot approach `i128`'s range.
        for &poly in nets.polys_of(net) {
            let bbox = store.poly_bbox(poly);
            let w = i128::from(bbox.width().raw().max(0));
            let h = i128::from(bbox.height().raw().max(0));
            surface += 2 * (w * h + (w + h) * t);
        }
    }
    debug_assert!(surface >= 0, "a sum of face areas is non-negative");
    surface
}

/// The finest panel edge whose estimated panel count still fits [`MAX_PANELS`].
///
/// **Decision** — pure. A panel of edge `e` covers `e²`, and proximity
/// refinement may quarter that, so a surface of `S` costs at most `4S / e²`
/// panels: the edge that fits the budget is `2 √(S / MAX_PANELS)`, rounded up.
fn budget_edge(surface: i128) -> i64 {
    debug_assert!(surface >= 0, "a surface area is non-negative");

    #[expect(
        clippy::cast_precision_loss,
        reason = "an area feeding a square root, where the rounding is far below one panel"
    )]
    let area = surface as f64;
    let edge = 2.0 * (area / f64::from(MAX_PANELS)).sqrt();
    debug_assert!(
        edge.is_finite() && edge >= 0.0,
        "a square root of a non-negative area is a non-negative number"
    );

    #[expect(
        clippy::cast_possible_truncation,
        reason = "saturating out of f64, then clamped into the coordinate domain"
    )]
    let units = edge.ceil() as i64;
    units.clamp(1, MAX_ABS_DBU)
}

/// A length the process stack states, in nanometres, as a count of database
/// units — or [`UNSTATED`] when the stack does not state it.
///
/// Rounded down rather than exact. [`Grid::to_dbu`] refuses a length that is not
/// a whole number of database units, which is right for a deck's spacing limit —
/// a rounded limit is a rule quietly relaxed — and wrong for a mesh resolution,
/// where the number is a target and refusing a 33.5 nm layer would refuse the
/// run. Down rather than to nearest, so the mesh is never coarser than the
/// feature it is resolving.
fn nm_to_dbu(nm: f64, grid: Grid) -> i64 {
    // Negated, so a `NaN` lands here rather than passing: a length the stack
    // does not state is not a length to mesh at, and neither is a gap between
    // two layers that overlap.
    if !(nm > 0.0) {
        return UNSTATED;
    }

    #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
    let per_um = grid.dbu_per_um() as f64;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "saturating out of f64, then clamped into the coordinate domain"
    )]
    let units = (nm * per_um / 1_000.0).floor() as i64;
    // Floored at one: a feature thinner than a database unit is still a
    // feature, and a panel edge of zero cuts a face into no panels at all.
    units.clamp(1, MAX_ABS_DBU)
}

/// A CSR boundary as a subscript.
fn subscript(boundary: u32) -> usize {
    usize::try_from(boundary).expect("a panel index is a u32 and usize is at least that wide")
}

/// Farads as the femtofarads [`Parasitic`] is stated in.
fn femtofarads(farads: f64) -> Qty<Capacitance, { prefix::FEMTO }> {
    Qty::new(farads * FEMTOFARADS_PER_FARAD)
}
