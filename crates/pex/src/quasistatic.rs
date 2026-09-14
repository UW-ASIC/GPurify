//! Field-solved extraction, for nets the closed forms cannot describe.
//!
//! A boundary-element formulation: conductor surfaces are meshed into panels,
//! and one GMRES solve per conductor at unit potential gives one column of the
//! Maxwell capacitance matrix. The system is dense and never formed, so the
//! matvec is the entire cost and the seam.

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
/// The full square, not a triangle: symmetry is a *result* to be checked, and
/// storing a triangle would make the check vacuous.
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
        // The side is the net column, not a square root of the value column;
        // asserting they agree is what makes `get`'s `i * n + j` sound.
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
    /// Above the solver's tolerance means the answer has not converged, whatever
    /// the residual says.
    pub fn asymmetry(&self) -> f64 {
        let n = self.dim();
        let mut worst = 0.0_f64;
        // Poison, carried beside the fold rather than in it. `f64::max` returns
        // the other operand on a NaN, which usefully folds away the `0 / 0` two
        // exactly-zero entries produce — but that same property would report a
        // NaN-poisoned matrix as perfectly symmetric. `x * 0.0` is a signed zero
        // for every finite `x` and NaN otherwise, so this separates the two
        // cases and fails closed: the sum is NaN, which is below no tolerance.
        // `x * 0.0` rather than `x - x`, which is `clippy::eq_op`.
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
        // Both folds are strict left folds in ascending index order, which is
        // what keeps the sum bit-identical across runs.
        let mut total = 0.0_f64;
        for i in 0..n {
            let row = &self.value[i * n..(i + 1) * n];
            debug_assert_eq!(row.len(), potentials.len(), "SoA columns must agree");
            let mut flux = 0.0_f64;
            for (c, v) in row.iter().zip(potentials) {
                flux += c * v;
            }
            total += potentials[i] * flux;
        }
        0.5 * total
    }
}

/// What a solve achieved, measured in `f64` on the host.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Accuracy {
    /// Relative residual actually reached, in `f64`.
    pub residual: f64,
    /// Residual that was asked for.
    pub tolerance: f64,
    pub iterations: u32,
    /// Which adapter actually did the matvec.
    pub backend: matvec::Backend,
    /// [`CapMatrix::asymmetry`] of the result.
    pub asymmetry: f64,
}

/// Extract selected nets by field solve.
///
/// Nets are meshed in ascending [`NetId`] order and the system assembled in that
/// order, so the matrix is a deterministic function of the geometry alone.
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
    out.clear();

    // The ascending order everything below inherits: the mesh's conductor bands,
    // the matrix rows, and the node column. Duplicates are deliberately *not*
    // dropped — two conductors over one net is a singular system, which the
    // solver refuses by name, where a silent dedup would return a matrix one row
    // smaller than the caller asked for.
    let mut order = selected.to_vec();
    order.sort_unstable();

    let mut mesh = mesh::Mesh::default();
    let meshing = mesh_options(store, nets, &order, stack, grid);
    mesh::build_into(store, nets, &order, stack, meshing, grid, &mut mesh)
        // `solve::SolveError` has no variant for a mesh that could not be built.
        // Fail closed anyway: a refusal at iteration zero is wrong about *why*,
        // where an empty clean matrix would be wrong about *whether*.
        .map_err(|_| solve::SolveError::Breakdown(0))?;

    let n = order.len();
    let panels = mesh.panel.len();
    debug_assert_eq!(mesh.conductor_net, order, "one conductor per selected net");
    debug_assert_eq!(mesh.conductor_start.len(), n + 1, "a CSR over {n} bands");
    debug_assert_eq!(mesh.epsilon.len(), panels, "one permittivity per panel");

    matrix.net.extend_from_slice(&order);
    matrix.value.resize(n * n, 0.0);

    // Three fail-closed steps, all landing on the host `f64` adapter: a probe
    // that found no usable device, a panel count below the crossover, and an
    // upload that refused. `Device::find`'s `Err` is discarded because a solve
    // that ran correctly on the host is not a failure to report.
    let device = gpu::Device::find().ok().flatten();
    let accelerated = match matvec::select(panels, device.as_ref()) {
        matvec::Backend::GpuF32 => device
            .as_ref()
            .and_then(|device| gpu::GpuMatVec::upload(device, &mesh).ok()),
        matvec::Backend::Cpu => None,
    };

    // The host adapter is built either way: it is the *accurate* operator
    // `solve::refine` forms its residual with, and without it a device solve's
    // residual would carry the device's own `f32` error.
    let host = matvec::CpuMatVec::build(&mesh);
    let (residual, iterations, backend) = match accelerated {
        Some(operator) => columns_into(&host, &operator, &mesh, options, matrix)?,
        None => columns_into(&host, &host, &mesh, options, matrix)?,
    };

    debug_assert_eq!(matrix.value.len(), n * n, "the matrix is square at {n}");

    // One node per net: a field solve is over whole conductors, so it has no
    // branch points to split at. The net's lowest layer is the anchor, which is
    // a property of the geometry and so deterministic.
    out.node_net.extend_from_slice(&order);
    for &net in &order {
        let polys = nets.polys_of(net);
        debug_assert!(!polys.is_empty(), "net {net:?} was meshed with no geometry");
        let mut low = LayerId(u16::MAX);
        for &poly in polys {
            low = low.min(store.poly_layer(poly));
        }
        out.node_layer.push(low);
    }
    debug_assert_eq!(out.node_layer.len(), n, "one node per selected net");

    // The Maxwell matrix as a network: the row sum is the net's capacitance to
    // ground, the negated off-diagonal is the coupling, emitted once per pair by
    // the lower node. The push order is canonical already.
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
/// Returns the worst residual, the total iteration count, and the backend read
/// off the adapter that ran. `accurate` is the `f64` host reference the residual
/// is formed with; `fast` solves the correction equation.
fn columns_into<A: matvec::MatVec, F: matvec::MatVec>(
    accurate: &A,
    fast: &F,
    mesh: &mesh::Mesh,
    options: solve::Options,
    matrix: &mut CapMatrix,
) -> Result<(f64, u32, matvec::Backend), solve::SolveError> {
    let n = mesh.conductor_net.len();
    let panels = mesh.panel.len();
    debug_assert_eq!(
        accurate.dim(),
        panels,
        "the residual operator is the mesh it was built from"
    );
    debug_assert_eq!(
        fast.dim(),
        panels,
        "both operators are the mesh they were built from"
    );
    debug_assert_eq!(matrix.value.len(), n * n, "the matrix is square at {n}");
    debug_assert_eq!(matrix.net.len(), n, "one row per meshed conductor");

    let mut workspace = solve::Workspace::default();
    let mut potential = Vec::with_capacity(panels);
    let mut charge = vec![0.0_f64; panels];
    let mut residual = 0.0_f64;
    let mut iterations = 0_u32;

    // One solve per conductor: unit potential on it, ground on the rest, and the
    // charge that answer puts on conductor `row` is `C[row][column]`.
    for column in 0..n {
        let owner = u32::try_from(column).expect("a conductor index is a u32 in the mesh");
        // One volt on the driven conductor, ground on the rest.
        potential.clear();
        potential.reserve(panels);
        for panel in &mesh.panel {
            potential.push(f64::from(panel.conductor == owner));
        }
        debug_assert_eq!(potential.len(), panels, "one collocation row per panel");

        // A fixed zero initial guess, not the previous column's answer: a warm
        // start would make column `c` depend on column `c - 1`'s round-off.
        charge.fill(0.0);
        let converged =
            solve::refine(accurate, fast, &potential, options, &mut charge, &mut workspace)?;
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
            // density, so the conductor's charge is the plain band sum. An
            // `area` weight here would reintroduce the `diag(A)` factor the
            // operator was built to keep out, and cost reciprocity.
            let mut total = 0.0_f64;
            for &q in &charge[start..end] {
                total += q;
            }
            // Fail closed: a non-finite entry reaching `CapMatrix` is a
            // capacitance a report would print.
            if !total.is_finite() {
                return Err(solve::SolveError::NonFinite(iterations));
            }
            matrix.value[row * n + column] = total;
        }
    }

    Ok((residual, iterations, fast.backend()))
}

/// Refuse rather than mesh beyond this many panels: the matvec is dense, so an
/// iteration costs `panels²`.
const MAX_PANELS: u32 = 1 << 20;

/// What [`nm_to_dbu`] answers for a length the process stack does not state.
///
/// `i64::MAX` so it folds away under the `min` in [`finest_feature`] — an
/// undescribed layer must not be the smallest feature in the process.
const UNSTATED: i64 = i64::MAX;

/// How finely [`extract_into`] meshes: the panel edge is the smallest length the
/// stack states, so the mesh moves with the PDK.
///
/// Two fail-closed clamps on top: the edge is coarsened until the *estimated*
/// panel count fits [`MAX_PANELS`] — an estimate, so
/// [`mesh::MeshError::TooManyPanels`] is still live above it — and it floors at
/// one database unit, a zero edge cutting a face into no panels.
///
/// The finest-feature scan covers the whole stack rather than the layers the
/// selection occupies, so one thin barrier row over-meshes a coarse selection.
/// An over-meshed run is slow and bounded; an under-meshed one is a capacitance
/// a report prints.
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

    // The budget is a floor, not a target: the coarser of the two wins.
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

/// The smallest length the process stack states, in database units: every
/// layer's thickness and every positive interlayer gap.
///
/// [`UNSTATED`] when the stack states nothing usable.
fn finest_feature(stack: &ProcessStack, grid: Grid) -> i64 {
    // The rows both columns agree on: a gap needs a floor and a ceiling.
    let rows = stack.thickness_nm.len().min(stack.height_nm.len());

    let mut finest = UNSTATED;
    for a in 0..rows {
        finest = finest.min(nm_to_dbu(stack.thickness_nm[a], grid));
        let ceiling = stack.height_nm[a] + stack.thickness_nm[a];
        // Ordered pairs, both ways round: the reversed pair's gap is negative
        // and dropped, as is `b == a`.
        for b in 0..rows {
            finest = finest.min(nm_to_dbu(stack.height_nm[b] - ceiling, grid));
        }
    }
    finest
}

/// The largest thickness the stack states, in database units, or zero.
fn thickest_layer(stack: &ProcessStack, grid: Grid) -> i64 {
    let mut thickest = 0;
    for &nm in &stack.thickness_nm {
        let stated = nm_to_dbu(nm, grid);
        // A layer the stack does not describe has no thickness that could be the
        // largest one.
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
/// An estimate — each polygon is boxed and extruded — because it bounds a panel
/// count, not a capacitance.
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
/// A panel of edge `e` covers `e²` and proximity refinement may quarter that, so
/// the edge that fits is `2 √(S / MAX_PANELS)`, rounded up.
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

/// A length the stack states, in nanometres, as a count of database units — or
/// [`UNSTATED`] when the stack does not state it.
///
/// Rounded down rather than refused as [`Grid::to_dbu`] would: this is a mesh
/// target, not a deck limit, and down keeps the mesh no coarser than the
/// feature.
fn nm_to_dbu(nm: f64, grid: Grid) -> i64 {
    // Negated, so a `NaN` lands here rather than passing.
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
    // Floored at one: a panel edge of zero cuts a face into no panels at all.
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
