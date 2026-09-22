//! Boundary-element capacitance solve, plus the inductance solve in [`henry`].
//!
//! Data in: selected nets' polygons and the process stack.
//! Data out: the Maxwell [`CapMatrix`] — one GMRES solve per conductor at unit
//! potential gives one column. The dense system is never formed; the matvec is the cost.

pub mod filament;
pub mod henry;
pub mod matvec;
pub mod mesh;
pub mod solve;

use gpurify_check::topology::{NetId, NetTable};
use gpurify_geom::GeometryStore;
use gpurify_geom::{Dbu, Grid, MAX_ABS_DBU};
use gpurify_ingest::deck::ProcessStack;

/// The Maxwell capacitance matrix, full square so symmetry is checkable.
#[derive(Debug, Default)]
pub struct CapMatrix {
    /// Which net each row and column belongs to.
    pub net: Vec<NetId>,
    /// Row-major, `n × n`, in farads.
    pub value: Vec<f64>,
}

impl CapMatrix {
    pub fn dim(&self) -> usize {
        self.net.len()
    }

    /// Largest relative asymmetry `|C[i][j] − C[j][i]| / |C[i][j]|`; NaN if any
    /// entry is non-finite, so a poisoned matrix fails every tolerance.
    pub fn asymmetry(&self) -> f64 {
        let n = self.dim();
        let mut worst = 0.0_f64;
        // `f64::max` drops NaN (folding away 0/0 from two exact zeros), so
        // poison is carried separately: `x * 0.0` is NaN only for non-finite `x`.
        let mut poison = 0.0_f64;
        for i in 0..n {
            for j in 0..n {
                let entry = self.value[i * n + j];
                let mirror = self.value[j * n + i];
                worst = worst.max((entry - mirror).abs() / entry.abs());
                poison += entry * 0.0 + mirror * 0.0;
            }
        }
        worst + poison
    }
}

/// What a solve achieved, measured in `f64`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Accuracy {
    /// Relative residual reached (worst column).
    pub residual: f64,
    /// Residual asked for.
    pub tolerance: f64,
    pub iterations: u32,
    pub backend: matvec::Backend,
    /// [`CapMatrix::asymmetry`] of the result.
    pub asymmetry: f64,
}

/// Field-solve `selected` into `matrix`, rows in ascending [`NetId`] order.
///
/// Duplicates are kept: two conductors on one net is a singular system the
/// solver refuses, rather than a silently smaller matrix.
pub fn extract_into(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    stack: &ProcessStack,
    grid: Grid,
    options: solve::Options,
    matrix: &mut CapMatrix,
) -> Result<Accuracy, solve::SolveError> {
    matrix.net.clear();
    matrix.value.clear();

    let mut order = selected.to_vec();
    order.sort_unstable();

    let mut mesh = mesh::Mesh::default();
    let meshing = mesh_options(store, nets, &order, stack, grid);
    // No `SolveError` variant for a mesh failure; refuse at iteration zero
    // rather than return an empty matrix.
    mesh::build_into(store, nets, &order, stack, meshing, grid, &mut mesh)
        .map_err(|_| solve::SolveError::Breakdown(0))?;

    let n = order.len();
    matrix.net.extend_from_slice(&order);
    matrix.value.resize(n * n, 0.0);

    let operator = matvec::CpuMatVec::build(&mesh);
    let (residual, iterations) = columns_into(&operator, &mesh, options, matrix)?;

    Ok(Accuracy {
        residual,
        tolerance: options.tolerance,
        iterations,
        backend: matvec::Backend::Cpu,
        asymmetry: matrix.asymmetry(),
    })
}

/// One solve per conductor into a sized [`CapMatrix`]; returns the worst
/// residual and the total iteration count.
fn columns_into(
    operator: &matvec::CpuMatVec,
    mesh: &mesh::Mesh,
    options: solve::Options,
    matrix: &mut CapMatrix,
) -> Result<(f64, u32), solve::SolveError> {
    let n = mesh.conductor_net.len();
    let panels = mesh.panel.len();
    let mut workspace = solve::Workspace::default();
    let mut potential = Vec::with_capacity(panels);
    let mut charge = vec![0.0_f64; panels];
    let mut residual = 0.0_f64;
    let mut iterations = 0_u32;

    for column in 0..n {
        let owner = u32::try_from(column).expect("a conductor index is a u32");
        // One volt on the driven conductor, ground on the rest.
        potential.clear();
        potential.extend(
            mesh.panel
                .iter()
                .map(|panel| f64::from(panel.conductor == owner)),
        );

        // Zero initial guess, never a warm start: columns stay independent.
        charge.fill(0.0);
        let converged = solve::refine(operator, &potential, options, &mut charge, &mut workspace)?;
        residual = residual.max(converged.residual);
        iterations = iterations.saturating_add(converged.iterations);

        for row in 0..n {
            let start = mesh.conductor_start[row] as usize;
            let end = mesh.conductor_start[row + 1] as usize;
            // The unknown is total panel charge, so a conductor's charge is the
            // plain band sum (an area weight would break reciprocity).
            let mut total = 0.0_f64;
            for &q in &charge[start..end] {
                total += q;
            }
            if !total.is_finite() {
                return Err(solve::SolveError::NonFinite(iterations));
            }
            matrix.value[row * n + column] = total;
        }
    }
    Ok((residual, iterations))
}

/// Refuse rather than mesh beyond this many panels: the matvec is dense.
const MAX_PANELS: u32 = 1 << 20;

/// [`nm_to_dbu`] for a length the stack does not state; folds away under `min`.
const UNSTATED: i64 = i64::MAX;

/// Panel edge = the smallest length the stack states, coarsened until the
/// estimated panel count fits [`MAX_PANELS`], floored at one database unit.
///
/// The scan covers the whole stack, so one thin layer over-meshes a coarse
/// selection: slow and bounded, never under-meshed.
fn mesh_options(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    stack: &ProcessStack,
    grid: Grid,
) -> mesh::MeshOptions {
    let feature = finest_feature(stack, grid);
    let surface = surface_area(store, nets, selected, thickest_layer(stack, grid));
    let max_edge = feature.max(budget_edge(surface)).clamp(1, MAX_ABS_DBU);
    mesh::MeshOptions {
        max_edge: Dbu::new_unchecked(max_edge),
        proximity_refine: Dbu::new_unchecked(max_edge),
        max_panels: MAX_PANELS,
    }
}

/// The smallest length the stack states, in database units: every layer's
/// thickness and every positive interlayer gap. [`UNSTATED`] if none.
fn finest_feature(stack: &ProcessStack, grid: Grid) -> i64 {
    let rows = stack.thickness_nm.len().min(stack.height_nm.len());
    let mut finest = UNSTATED;
    for a in 0..rows {
        finest = finest.min(nm_to_dbu(stack.thickness_nm[a], grid));
        let ceiling = stack.height_nm[a] + stack.thickness_nm[a];
        // Both orders: the reversed pair's negative gap is dropped by `nm_to_dbu`.
        for b in 0..rows {
            finest = finest.min(nm_to_dbu(stack.height_nm[b] - ceiling, grid));
        }
    }
    finest
}

/// The largest stated layer thickness, in database units, or zero.
fn thickest_layer(stack: &ProcessStack, grid: Grid) -> i64 {
    let mut thickest = 0;
    for &nm in &stack.thickness_nm {
        let stated = nm_to_dbu(nm, grid);
        if stated != UNSTATED {
            thickest = thickest.max(stated);
        }
    }
    thickest
}

/// Surface area of the selected conductors in dbu², each polygon boxed and
/// extruded — an estimate that bounds a panel count.
fn surface_area(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    thickness: i64,
) -> i128 {
    let t = i128::from(thickness);
    let mut surface = 0_i128;
    for &net in selected {
        for &poly in nets.polys_of(net) {
            let bbox = store.poly_bbox(poly);
            let w = i128::from(bbox.width().raw().max(0));
            let h = i128::from(bbox.height().raw().max(0));
            surface += 2 * (w * h + (w + h) * t);
        }
    }
    surface
}

/// The finest edge whose estimated panel count fits [`MAX_PANELS`]:
/// `2 √(S / MAX_PANELS)` rounded up (proximity refinement may quarter a panel).
fn budget_edge(surface: i128) -> i64 {
    #[expect(clippy::cast_precision_loss, reason = "an area feeding a square root")]
    let area = surface as f64;
    let edge = 2.0 * (area / f64::from(MAX_PANELS)).sqrt();
    #[expect(clippy::cast_possible_truncation, reason = "saturating, then clamped")]
    let units = edge.ceil() as i64;
    units.clamp(1, MAX_ABS_DBU)
}

/// A stated length in nm as database units, rounded down (a mesh target, not a
/// deck limit), floored at one; [`UNSTATED`] for a non-positive or NaN length.
fn nm_to_dbu(nm: f64, grid: Grid) -> i64 {
    if !(nm > 0.0) {
        return UNSTATED;
    }
    #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
    let per_um = grid.dbu_per_um() as f64;
    #[expect(clippy::cast_possible_truncation, reason = "saturating, then clamped")]
    let units = (nm * per_um / 1_000.0).floor() as i64;
    units.clamp(1, MAX_ABS_DBU)
}
