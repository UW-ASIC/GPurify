//! Field-solved extraction as a [`ParasiticNetwork`].
//!
//! Data in: the selected nets, solved by [`crate::field`].
//! Data out: one node per net carrying the Maxwell matrix (row sum to ground,
//! `-C_ij` coupling), plus a second node per net for series L and R when asked,
//! and a mutual inductance between every pair of those nets.
//!
//! The engine's order is [`extract_into`], then [`extract_inductance_into`] on
//! the same network, then [`overlay`] onto the analytical network. What the
//! solves leave out is in the [crate docs](crate#accuracy-and-known-gaps).

pub use crate::field::henry::{InductMatrix, InductanceError};
pub use crate::field::{mesh, solve, Accuracy, CapMatrix};

use crate::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_check::topology::{NetId, NetTable};
use gpurify_geom::{GeometryStore, Grid, LayerId, Qty};
use gpurify_ingest::deck::{Connectivity, ProcessStack};

const FEMTOFARADS_PER_FARAD: f64 = 1e15;
const PICOHENRIES_PER_HENRY: f64 = 1e12;

/// Field-solves the capacitance of `selected` into `matrix`, then reads it out
/// into `out`, which is cleared first.
///
/// `out` gets one node per selected net, in ascending [`NetId`] order, on the
/// net's lowest layer that is not global. Each node carries its row sum as a
/// ground capacitance, and every pair `i < j` gets a coupling of `−C_ij`.
/// Every pair is written, even where the solve gives zero or a slightly
/// negative value; nothing is dropped, and a zero is `+0.0`, never `−0.0`.
/// Ground is the substrate, a grounded plane at height 0. A net's
/// shapes on a layer at height 0 (wells, diffusion) are junctions in that
/// plane: they are not in the field, and the ground capacitance includes
/// their closed form `Ca·A + Cf·P` from the layer's `pex` row. A net's
/// resistance through them is the inductance solve's, as for any shape. A
/// net's shapes on a global layer ([`Connectivity::global`], the substrate
/// as a net) carry no parasitics: they are not in the field and need no
/// `pex` row.
///
/// # Errors
///
/// Whatever [`crate::field::extract_into`] refuses: a mesh that cannot be
/// built ([`solve::SolveError::Mesh`]), or a column that does not converge
/// to the default tolerance. `out` is left cleared and `matrix` holds no
/// complete result.
pub fn extract_into(
    store: &GeometryStore,
    nets: &NetTable,
    connectivity: &Connectivity,
    selected: &[NetId],
    stack: &ProcessStack,
    grid: Grid,
    matrix: &mut CapMatrix,
    out: &mut ParasiticNetwork,
) -> Result<Accuracy, solve::SolveError> {
    out.clear();
    let accuracy =
        crate::field::extract_into(store, nets, connectivity, selected, stack, grid, matrix)?;

    let n = matrix.net.len();
    push_anchors(store, nets, connectivity, &matrix.net, out);
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
            // `0 − x`, not `−x`: a pair with no field between them (a net of
            // junctions only has no panels) reads +0, never −0 (F80).
            let coupling = 0.0 - matrix.value[row * n + other] * FEMTOFARADS_PER_FARAD;
            out.push(
                from,
                Some(node(other)),
                Parasitic::CouplingCap(Qty::new(coupling)),
            );
        }
    }
    Ok(accuracy)
}

/// Solves per-net inductance and resistance for `selected` and appends them to `out`.
///
/// `out` must be empty or the one-node-per-net network [`extract_into`] built
/// over the same selection; anything else is a wrong remapping that only
/// debug builds catch. Each net gains a far node beside its anchor (node `i`
/// becomes `2i`, its far node `2i + 1`), joined by the series L and R, so
/// every [`NodeId`] read from `out` before this call is stale after it. The
/// anchor is the end the net's port current enters. Every pair of nets
/// `i < j` gains a [`Parasitic::MutualInductance`] from `i`'s anchor to
/// `j`'s: the mean of `M_ij` and `M_ji`, which agree to round-off. The new
/// elements break canonical order until the network is sorted or
/// [`overlay`] sorts it.
///
/// # Errors
///
/// Every [`InductanceError`]: a selected net with no polygons off the global
/// layers, a polygon on a layer with no positive sheet resistance or
/// thickness, a net whose shapes do not join into one circuit through shared
/// edges and vias, or a singular system. `out` is unchanged then.
pub fn extract_inductance_into(
    store: &GeometryStore,
    nets: &NetTable,
    connectivity: &Connectivity,
    selected: &[NetId],
    stack: &ProcessStack,
    grid: Grid,
    matrix: &mut InductMatrix,
    out: &mut ParasiticNetwork,
) -> Result<(), InductanceError> {
    crate::field::henry::extract_inductance_into(
        store,
        nets,
        connectivity,
        selected,
        stack,
        grid,
        matrix,
    )?;

    if out.node_net.is_empty() {
        push_anchors(store, nets, connectivity, &matrix.net, out);
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
    for row in 0..n {
        for other in (row + 1)..n {
            let (there, back) = (
                matrix.m_henry[row * n + other],
                matrix.m_henry[other * n + row],
            );
            // `0 + x`, so no pair reads −0 (F80).
            let henry = 0.0 + there.midpoint(back) * PICOHENRIES_PER_HENRY;
            out.push(
                node(2 * row),
                Some(node(2 * other)),
                Parasitic::MutualInductance(Qty::new(henry)),
            );
        }
    }
    Ok(())
}

/// Replace the analytical rows of every net `solved` has nodes for with the
/// solved rows, then sort canonically.
///
/// The mesh never sees an unsolved neighbour, so an analytical element between a
/// solved net and an unsolved one is kept, moved onto the solved net's first
/// node. Elements within or between solved nets are dropped: the solve replaces them.
///
/// Both networks must hold the node invariant of [`ParasiticNetwork`].
/// Every node is renumbered, so a [`NodeId`] read from `network` before the
/// call is stale after it.
pub fn overlay(network: &mut ParasiticNetwork, solved: &ParasiticNetwork) {
    let analytical = std::mem::take(network);
    let highest = |nodes: &[NetId]| nodes.last().map_or(0, |net| net.0 as usize + 1);
    let nets = highest(&analytical.node_net).max(highest(&solved.node_net));
    let mut replaced = vec![false; nets];
    for net in &solved.node_net {
        replaced[net.0 as usize] = true;
    }

    // Two-way merge by net: both sides ascend and, with replaced rows skipped,
    // share no net, so the result keeps one contiguous ascending range per net.
    let mut coarse_map = vec![0_u32; analytical.node_count()];
    let mut fine_map = vec![0_u32; solved.node_count()];
    let mut anchor = vec![0_u32; nets];
    let (mut coarse, mut fine) = (0, 0);
    loop {
        while analytical
            .node_net
            .get(coarse)
            .is_some_and(|net| replaced[net.0 as usize])
        {
            coarse += 1;
        }
        let take_coarse = match (analytical.node_net.get(coarse), solved.node_net.get(fine)) {
            (None, None) => break,
            (Some(left), Some(right)) => left < right,
            (left, _) => left.is_some(),
        };
        let id = node(network.node_net.len()).0;
        let (source, row) = if take_coarse {
            coarse_map[coarse] = id;
            coarse += 1;
            (&analytical, coarse - 1)
        } else {
            let net = solved.node_net[fine].0 as usize;
            if fine == 0 || solved.node_net[fine - 1].0 as usize != net {
                anchor[net] = id;
            }
            fine_map[fine] = id;
            fine += 1;
            (solved, fine - 1)
        };
        network.node_net.push(source.node_net[row]);
        network.node_layer.push(source.node_layer[row]);
    }
    for (mapped, net) in coarse_map.iter_mut().zip(&analytical.node_net) {
        if replaced[net.0 as usize] {
            *mapped = anchor[net.0 as usize];
        }
    }

    let solved_node = |node: NodeId| replaced[analytical.node_net[node.0 as usize].0 as usize];
    for row in 0..analytical.element_count() {
        let (from, to) = (analytical.from[row], analytical.to[row]);
        if solved_node(from) && to.is_none_or(solved_node) {
            continue;
        }
        let remap = |node: NodeId| NodeId(coarse_map[node.0 as usize]);
        network.push(remap(from), to.map(remap), analytical.value[row]);
    }
    for row in 0..solved.element_count() {
        let remap = |node: NodeId| NodeId(fine_map[node.0 as usize]);
        network.push(
            remap(solved.from[row]),
            solved.to[row].map(remap),
            solved.value[row],
        );
    }
    network.sort_canonical();
    network.debug_check();
}

/// One node per net, anchored on the net's lowest layer that is not global:
/// a global layer carries nothing of the network.
fn push_anchors(
    store: &GeometryStore,
    nets: &NetTable,
    connectivity: &Connectivity,
    order: &[NetId],
    out: &mut ParasiticNetwork,
) {
    out.node_net.extend_from_slice(order);
    for &net in order {
        let low = nets
            .polys_of(net)
            .iter()
            .map(|&p| store.poly_layer(p))
            .filter(|layer| !connectivity.global.contains(layer))
            .min();
        out.node_layer.push(low.unwrap_or(LayerId(u16::MAX)));
    }
}

fn node(index: usize) -> NodeId {
    NodeId(u32::try_from(index).expect("a node index is a u32"))
}
