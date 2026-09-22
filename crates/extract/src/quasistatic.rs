//! Field-solved extraction as a [`ParasiticNetwork`].
//!
//! Data in: the selected nets, solved by [`crate::field`].
//! Data out: one node per net carrying the Maxwell matrix (row sum to ground,
//! `-C_ij` coupling), plus a second node per net for series L and R when asked.

pub use crate::field::henry::{InductMatrix, InductanceError, InductanceOptions};
pub use crate::field::{matvec, mesh, solve, Accuracy, CapMatrix};

use crate::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_check::topology::{NetId, NetTable};
use gpurify_geom::{GeometryStore, Grid, LayerId, Qty};
use gpurify_ingest::deck::ProcessStack;

const FEMTOFARADS_PER_FARAD: f64 = 1e15;
const PICOHENRIES_PER_HENRY: f64 = 1e12;

/// Field-solve `selected` into `matrix`, then read it out into `out` (cleared).
pub fn extract_into(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    stack: &ProcessStack,
    grid: Grid,
    options: solve::Options,
    matrix: &mut CapMatrix,
    out: &mut ParasiticNetwork,
) -> Result<Accuracy, solve::SolveError> {
    out.clear();
    let accuracy = crate::field::extract_into(store, nets, selected, stack, grid, options, matrix)?;

    let n = matrix.net.len();
    push_anchors(store, nets, &matrix.net, out);
    for row in 0..n {
        let from = node(row);
        // Strict left fold in ascending index order: a reported capacitance.
        let mut ground = 0.0_f64;
        for &c in &matrix.value[row * n..(row + 1) * n] {
            ground += c;
        }
        out.push(
            from,
            None,
            Parasitic::GroundCap(Qty::new(ground * FEMTOFARADS_PER_FARAD)),
        );
        for other in (row + 1)..n {
            let coupling = -matrix.value[row * n + other] * FEMTOFARADS_PER_FARAD;
            out.push(
                from,
                Some(node(other)),
                Parasitic::CouplingCap(Qty::new(coupling)),
            );
        }
    }
    Ok(accuracy)
}

/// Solve per-net inductance and resistance for `selected` and append them to `out`.
///
/// `out` is empty or the one-node-per-net network [`extract_into`] built over the
/// same selection. Each net gains a far node beside its anchor (node `i` becomes
/// `2i`, its far node `2i + 1`), joined by the series L and R.
pub fn extract_inductance_into(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    stack: &ProcessStack,
    grid: Grid,
    options: &InductanceOptions,
    matrix: &mut InductMatrix,
    out: &mut ParasiticNetwork,
) -> Result<(), InductanceError> {
    crate::field::henry::extract_inductance_into(
        store, nets, selected, stack, grid, options, matrix,
    )?;

    if out.node_net.is_empty() {
        push_anchors(store, nets, &matrix.net, out);
    }
    debug_assert_eq!(out.node_net, matrix.net, "remapping the wrong nodes");

    let n = matrix.net.len();
    let mut node_net = Vec::with_capacity(2 * n);
    let mut node_layer = Vec::with_capacity(2 * n);
    for i in 0..n {
        node_net.extend([out.node_net[i]; 2]);
        node_layer.extend([out.node_layer[i]; 2]);
    }
    out.node_net = node_net;
    out.node_layer = node_layer;
    for from in &mut out.from {
        from.0 *= 2;
    }
    for to in out.to.iter_mut().flatten() {
        to.0 *= 2;
    }

    for row in 0..n {
        let anchor = node(2 * row);
        let far = Some(NodeId(anchor.0 + 1));
        let henry = matrix.l_henry[row] * PICOHENRIES_PER_HENRY;
        out.push(anchor, far, Parasitic::Inductance(Qty::new(henry)));
        out.push(
            anchor,
            far,
            Parasitic::Resistance(Qty::new(matrix.r_ohm[row])),
        );
    }
    Ok(())
}

/// One node per net, anchored on the net's lowest layer.
fn push_anchors(
    store: &GeometryStore,
    nets: &NetTable,
    order: &[NetId],
    out: &mut ParasiticNetwork,
) {
    out.node_net.extend_from_slice(order);
    for &net in order {
        let low = nets
            .polys_of(net)
            .iter()
            .map(|&p| store.poly_layer(p))
            .min();
        out.node_layer.push(low.unwrap_or(LayerId(u16::MAX)));
    }
}

fn node(index: usize) -> NodeId {
    NodeId(u32::try_from(index).expect("a node index is a u32"))
}
