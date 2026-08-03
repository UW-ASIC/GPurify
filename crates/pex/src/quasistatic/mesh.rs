//! Panel meshing: conductor surfaces to boundary elements.
//!
//! The mesh is the whole input to the solve, so its quality bounds the answer's
//! accuracy and its size bounds the cost. Both are decided here, and both are
//! reported rather than left implicit.

use gpurify_core::{GeometryStore, LayerId};
use gpurify_topology::{NetId, NetTable};
use gpurify_units::Dbu;

/// A flat rectangular boundary element.
///
/// `AoS`: the matvec reads every field of a panel together when evaluating an
/// influence, and panels are stored in spatial tree order so that read is
/// contiguous. This is one of the few places in the tree where `AoS` wins, and it
/// wins because of the access pattern, not by default.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Panel {
    /// Centroid, in metres. The solve works in SI, not in grid units — the
    /// conversion happens once, here, against the run's grid.
    pub centre: [f64; 3],
    /// Outward normal, unit length.
    pub normal: [f64; 3],
    pub area: f64,
    /// Which conductor this panel belongs to. Charge is integrated per
    /// conductor to give a matrix column.
    pub conductor: u32,
}

/// The meshed problem.
///
/// **Five questions.** In: geometry for the selected nets and the layer stack.
/// Out: panels in spatial order, plus the conductor each belongs to. How many:
/// thousands to hundreds of thousands. Access pattern: sequential in tree
/// order, every field together. Lifetime: one solve. Parallelisable: meshing
/// per conductor is; the spatial sort at the end is what makes panel order
/// canonical.
#[derive(Debug, Default)]
pub struct Mesh {
    pub panel: Vec<Panel>,
    /// `panel[conductor_start[c] .. conductor_start[c + 1]]` belongs to
    /// conductor `c`, after the canonical sort.
    pub conductor_start: Vec<u32>,
    pub conductor_net: Vec<NetId>,
    /// Relative permittivity above each panel. Layered dielectrics change the
    /// Green's function, so this travels with the mesh.
    pub epsilon: Vec<f64>,
}

/// How finely to mesh.
#[derive(Debug, Clone, Copy)]
pub struct MeshOptions {
    /// Largest panel edge, in database units. The accuracy knob.
    pub max_edge: Dbu,
    /// Refine panels within this distance of another conductor, where the field
    /// varies fastest and a uniform mesh is worst.
    pub proximity_refine: Dbu,
    /// Refuse rather than mesh beyond this many panels. A solve that would take
    /// a week should say so, not start.
    pub max_panels: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MeshError {
    #[error("mesh would exceed the panel limit")]
    TooManyPanels,
    #[error("layer {0:?} has no thickness in the process stack")]
    MissingThickness(LayerId),
    #[error("selected net has no geometry")]
    EmptyConductor,
}

/// Mesh the selected nets.
///
/// **Transform, A-to-B.** Caller owns `out`. Panels are emitted per conductor
/// in ascending [`NetId`] order and then sorted into spatial tree order by a
/// key derived only from position, so the mesh is a deterministic function of
/// the geometry — no thread count, no insertion order.
pub fn build_into(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    options: MeshOptions,
    out: &mut Mesh,
) -> Result<(), MeshError> {
    todo!()
}

/// Surface area of one conductor, summed from its panels.
///
/// **Decision** — pure, and the first thing a meshing test checks: the panels
/// must tile the conductor exactly, so their areas must sum to the analytic
/// surface area of the shape. A mesh that loses area loses charge, and a solve
/// on it is wrong in a way no residual reveals.
pub fn conductor_area(mesh: &Mesh, conductor: u32) -> f64 {
    todo!()
}
