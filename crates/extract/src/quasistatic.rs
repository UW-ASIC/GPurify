//! Field-solved extraction, driving [`crate::field`].
//!
//! The solver — mesh, matvec, GMRES, the capacitance matrix — lives in its own
//! crate; what stays here is the one thing that couples it to `pex`: reading
//! the Maxwell matrix out into a [`ParasiticNetwork`].

pub use crate::field::henry::bridge::{InductMatrix, InductanceError, InductanceOptions};
pub use crate::field::{matvec, mesh, solve, Accuracy, CapMatrix};

#[cfg(feature = "gpu")]
pub use crate::field::gpu;

use crate::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_check::topology::{NetId, NetTable};
use gpurify_geom::{prefix, Capacitance, Inductance, Qty, Resistance};
use gpurify_geom::{GeometryStore, LayerId};
use gpurify_ingest::deck::ProcessStack;

/// Farads to the femtofarads [`Parasitic`] states capacitance in.
const FEMTOFARADS_PER_FARAD: f64 = 1e15;

/// Henries to the picohenries [`Parasitic`] states inductance in.
const PICOHENRIES_PER_HENRY: f64 = 1e12;

/// Extract selected nets by field solve, then read the matrix out as a
/// [`ParasiticNetwork`].
///
/// The solve itself is [`crate::field::extract_into`]; this wrapper adds
/// the network assembly and nothing else, so the matrix and the network are two
/// views of one result.
pub fn extract_into(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    stack: &ProcessStack,
    grid: gpurify_geom::Grid,
    options: solve::Options,
    matrix: &mut CapMatrix,
    out: &mut ParasiticNetwork,
) -> Result<Accuracy, solve::SolveError> {
    out.clear();

    let accuracy = crate::field::extract_into(store, nets, selected, stack, grid, options, matrix)?;

    // The ascending net order the solve assembled the matrix in: `matrix.net`
    // is the sorted selection, one row per net.
    let order = &matrix.net;
    let n = order.len();
    debug_assert_eq!(matrix.value.len(), n * n, "the matrix is square at {n}");

    // One node per net: a field solve is over whole conductors, so it has no
    // branch points to split at. The net's lowest layer is the anchor, which is
    // a property of the geometry and so deterministic.
    out.node_net.extend_from_slice(order);
    for &net in order {
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
            out.push(
                from,
                Some(to),
                Parasitic::CouplingCap(femtofarads(coupling)),
            );
        }
    }
    debug_assert_eq!(
        out.element_count(),
        n * (n + 1) / 2,
        "one ground element per net and one coupling per pair"
    );

    Ok(accuracy)
}

/// Extract per-net inductance and resistance for `selected`, then push the
/// rows onto `out` as [`Parasitic::Inductance`] and [`Parasitic::Resistance`]
/// elements.
///
/// `out` must be either empty or the one-node-per-net network the capacitance
/// tail above lays down over the *same* selection. Both element kinds span two
/// nodes — the export writers refuse a resistance or inductance to ground, by
/// design — so each solved net gains a second sub-node beside its anchor and
/// the pair carries the series R and L the port measured. The capacitive
/// elements keep the anchor, so the two views stay one network.
pub fn extract_inductance_into(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    stack: &ProcessStack,
    grid: gpurify_geom::Grid,
    options: &InductanceOptions,
    matrix: &mut InductMatrix,
    out: &mut ParasiticNetwork,
) -> Result<(), InductanceError> {
    crate::field::henry::bridge::extract_inductance_into(
        store, nets, selected, stack, grid, options, matrix,
    )?;

    let n = matrix.net.len();
    debug_assert_eq!(matrix.l_henry.len(), n, "one inductance per selected net");
    debug_assert_eq!(matrix.r_ohm.len(), n, "one resistance per selected net");

    if out.node_net.is_empty() {
        // Standalone use: lay down the anchors the capacitance tail would
        // have — one node per net, on the net's lowest layer.
        out.node_net.extend_from_slice(&matrix.net);
        for &net in &matrix.net {
            let polys = nets.polys_of(net);
            debug_assert!(!polys.is_empty(), "net {net:?} was solved with no geometry");
            let mut low = LayerId(u16::MAX);
            for &poly in polys {
                low = low.min(store.poly_layer(poly));
            }
            out.node_layer.push(low);
        }
    }
    debug_assert_eq!(
        out.node_net, matrix.net,
        "the network is the capacitance tail's one-node-per-net column over \
         the same selection, or this remap renumbers the wrong nodes"
    );

    // Insert the far sub-node of each net beside its anchor: the node column
    // doubles, old node `i` becomes `2i`, and the far node of net `i` is
    // `2i + 1`. The per-net contiguity invariant survives because the pair is
    // adjacent and the net order is unchanged.
    let mut node_net = Vec::with_capacity(2 * n);
    let mut node_layer = Vec::with_capacity(2 * n);
    for i in 0..n {
        node_net.push(out.node_net[i]);
        node_net.push(out.node_net[i]);
        node_layer.push(out.node_layer[i]);
        node_layer.push(out.node_layer[i]);
    }
    out.node_net = node_net;
    out.node_layer = node_layer;
    let remap = |node: NodeId| NodeId(node.0 * 2);
    for from in &mut out.from {
        *from = remap(*from);
    }
    for to in &mut out.to {
        *to = to.map(remap);
    }

    for row in 0..n {
        let anchor = NodeId(u32::try_from(2 * row).expect("a node index is a u32"));
        let far = NodeId(anchor.0 + 1);
        out.push(
            anchor,
            Some(far),
            Parasitic::Inductance(picohenries(matrix.l_henry[row])),
        );
        out.push(
            anchor,
            Some(far),
            Parasitic::Resistance(ohms(matrix.r_ohm[row])),
        );
    }
    Ok(())
}

/// Farads as the femtofarads [`Parasitic`] is stated in.
fn femtofarads(farads: f64) -> Qty<Capacitance, { prefix::FEMTO }> {
    Qty::new(farads * FEMTOFARADS_PER_FARAD)
}

/// Henries as the picohenries [`Parasitic`] is stated in.
fn picohenries(henries: f64) -> Qty<Inductance, { prefix::PICO }> {
    Qty::new(henries * PICOHENRIES_PER_HENRY)
}

/// Ohms, already the base unit [`Parasitic`] states resistance in.
fn ohms(value: f64) -> Qty<Resistance, { prefix::BASE }> {
    Qty::new(value)
}
