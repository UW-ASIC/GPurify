//! Boundary-element capacitance solve, plus the inductance solve in [`henry`].
//!
//! Data in: selected nets' polygons and the process stack.
//! Data out: the Maxwell [`CapMatrix`] — one GMRES solve per conductor at unit
//! potential gives one column. The dense system is never formed; the matvec is the cost.
//!
//! The pipeline is [`mesh::build_into`], then one [`solve::refine`] per
//! column. The free-space kernel has no images, so neither the substrate nor
//! a dielectric interface is in the field; see the
//! [crate docs](crate#accuracy-and-known-gaps).
//!
//! # Time complexity
//!
//! Each GMRES iteration is a dense product over every pair of panels,
//! *O*(P²) for P panels, and there is one solve per selected net. The panel
//! count is capped at 2²⁰: [`extract_into`] coarsens the panels until an
//! estimate of the count fits, and the mesh is refused with
//! [`mesh::MeshError::TooManyPanels`] if the real count still exceeds the cap.

pub mod filament;
pub mod henry;
mod matvec;
pub mod mesh;
pub mod solve;

use gpurify_check::topology::{NetId, NetTable};
use gpurify_geom::GeometryStore;
use gpurify_geom::{Dbu, Grid, MAX_ABS_DBU};
use gpurify_ingest::deck::ProcessStack;

/// The Maxwell capacitance matrix, full square so symmetry is checkable.
///
/// `C[i][i]` is positive, `C[i][j]` for `i ≠ j` is minus the coupling between
/// nets `i` and `j`, and a row sums to net `i`'s capacitance to infinity. A
/// converged solve is symmetric to about its tolerance (reciprocity), which is
/// what [`Self::asymmetry`] measures.
#[derive(Debug, Default)]
pub struct CapMatrix {
    /// Which net each row and column belongs to, in ascending [`NetId`] order.
    pub net: Vec<NetId>,
    /// Row-major, in farads. `n × n` from [`extract_into`]; `n` rows by one
    /// column per driven set from [`extract_columns_into`].
    pub value: Vec<f64>,
}

impl CapMatrix {
    /// Returns the number of rows, one per net.
    pub fn dim(&self) -> usize {
        self.net.len()
    }

    /// Largest relative asymmetry `|C[i][j] − C[j][i]| / |C[i][j]|`; NaN if any
    /// entry is non-finite, so a poisoned matrix fails every tolerance.
    ///
    /// Two exact zeros mirrored count as symmetric.
    ///
    /// # Panics
    ///
    /// Panics if `value` holds fewer than `n × n` entries, which a
    /// non-square matrix from [`extract_columns_into`] can.
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
    /// Relative residual every column was solved to.
    pub tolerance: f64,
    /// GMRES iterations summed over every column, saturating at `u32::MAX`.
    pub iterations: u32,
    /// [`CapMatrix::asymmetry`] of the result; `0.0` for a matrix that is
    /// not square, where it is undefined.
    pub asymmetry: f64,
}

/// Field-solves `selected` into `matrix`, rows in ascending [`NetId`] order.
///
/// Duplicates are kept: two conductors on one net is a singular system the
/// solver refuses, rather than a silently smaller matrix.
///
/// The panel edge is the smallest length the stack states (a layer
/// thickness or a gap between layers), coarsened until the estimated mesh
/// fits 2²⁰ panels. Every column is solved to [`solve::Options::default`].
///
/// # Errors
///
/// [`solve::SolveError::Mesh`] when the selection cannot be meshed: a net
/// with no polygons, a polygon on a layer the stack gives no thickness,
/// height or permittivity, a layer whose geometry does not validate as
/// rectilinear, or too many panels. The other variants when a column does
/// not converge, breaks down or goes non-finite.
pub fn extract_into(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    stack: &ProcessStack,
    grid: Grid,
    matrix: &mut CapMatrix,
) -> Result<Accuracy, solve::SolveError> {
    let mut order = selected.to_vec();
    order.sort_unstable();
    let meshing = mesh_options(store, nets, &order, stack, grid);
    extract_meshed_into(store, nets, &order, stack, grid, meshing, matrix)
}

/// [`extract_into`] at a caller's panel size rather than the stack-derived one.
///
/// # Errors
///
/// As [`extract_into`]. `meshing.max_panels` is the cap that
/// [`mesh::MeshError::TooManyPanels`] enforces.
pub fn extract_meshed_into(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    stack: &ProcessStack,
    grid: Grid,
    meshing: mesh::MeshOptions,
    matrix: &mut CapMatrix,
) -> Result<Accuracy, solve::SolveError> {
    let mut order = selected.to_vec();
    order.sort_unstable();
    let driven: Vec<Vec<usize>> = (0..order.len()).map(|i| vec![i]).collect();
    let options = solve::Options::default();
    columns_meshed_into(
        store, nets, &order, &driven, stack, grid, meshing, options, matrix,
    )
}

/// Columns of the Maxwell matrix with every selected conductor meshed: one
/// solve per entry of `driven`, each entry's conductors at one volt together
/// and the rest at ground. `matrix` is `selected.len()` rows by `driven.len()`
/// columns, row-major, rows in ascending [`NetId`] order (`matrix.net`). An
/// entry driving several conductors is the column of those conductors shorted,
/// the sum of their single columns, in one solve; a row is the charge induced
/// on that conductor, which is what a windowed extraction wants: a net's row
/// is its column, by reciprocity.
///
/// A driven net that is not in `selected` is ignored, so a set of only such
/// nets gives a zero column. Returns the GMRES iterations summed over every
/// column.
///
/// # Errors
///
/// As [`extract_into`], with `options` in place of the default tolerance and
/// budgets.
pub fn extract_columns_into(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    driven: &[Vec<NetId>],
    stack: &ProcessStack,
    grid: Grid,
    meshing: mesh::MeshOptions,
    options: solve::Options,
    matrix: &mut CapMatrix,
) -> Result<u32, solve::SolveError> {
    let mut order = selected.to_vec();
    order.sort_unstable();
    let columns: Vec<Vec<usize>> = driven
        .iter()
        .map(|set| {
            set.iter()
                .filter_map(|net| order.binary_search(net).ok())
                .collect()
        })
        .collect();
    columns_meshed_into(
        store, nets, &order, &columns, stack, grid, meshing, options, matrix,
    )
    .map(|accuracy| accuracy.iterations)
}

fn columns_meshed_into(
    store: &GeometryStore,
    nets: &NetTable,
    order: &[NetId],
    columns: &[Vec<usize>],
    stack: &ProcessStack,
    grid: Grid,
    meshing: mesh::MeshOptions,
    options: solve::Options,
    matrix: &mut CapMatrix,
) -> Result<Accuracy, solve::SolveError> {
    matrix.net.clear();
    matrix.value.clear();

    let mut mesh = mesh::Mesh::default();
    mesh::build_into(store, nets, order, stack, meshing, grid, &mut mesh)?;

    let n = order.len();
    matrix.net.extend_from_slice(order);
    matrix.value.resize(n * columns.len(), 0.0);

    let operator = matvec::CpuMatVec::build(&mesh);
    let iterations = columns_into(&operator, &mesh, options, columns, matrix)?;

    // Asymmetry is only defined on a square matrix.
    let asymmetry = if columns.len() == n {
        matrix.asymmetry()
    } else {
        0.0
    };
    Ok(Accuracy {
        tolerance: options.tolerance,
        iterations,
        asymmetry,
    })
}

/// One solve per conductor into a sized [`CapMatrix`]; returns the total
/// iteration count.
fn columns_into(
    operator: &matvec::CpuMatVec,
    mesh: &mesh::Mesh,
    options: solve::Options,
    columns: &[Vec<usize>],
    matrix: &mut CapMatrix,
) -> Result<u32, solve::SolveError> {
    let n = mesh.conductor_net.len();
    let width = columns.len();
    let panels = mesh.panel.len();
    let mut workspace = solve::Workspace::default();
    let mut potential = Vec::with_capacity(panels);
    let mut charge = vec![0.0_f64; panels];
    let mut iterations = 0_u32;

    let mut driven = vec![false; n];
    for (slot, column) in columns.iter().enumerate() {
        driven.fill(false);
        for &conductor in column {
            driven[conductor] = true;
        }
        // One volt on the driven conductors, ground on the rest.
        potential.clear();
        potential.extend(
            mesh.panel
                .iter()
                .map(|panel| f64::from(driven[panel.conductor as usize])),
        );

        // Zero initial guess, never a warm start: columns stay independent.
        charge.fill(0.0);
        let apply = |x: &[f64], y: &mut [f64]| operator.apply(x, y);
        let converged = solve::refine(apply, &potential, options, &mut charge, &mut workspace)?;
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
            matrix.value[row * width + slot] = total;
        }
    }
    Ok(iterations)
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
