//! Field-solved extraction as a [`ParasiticNetwork`].
//!
//! Data in: the selected nets, solved by [`crate::field`].
//! Data out: one node per net carrying the Maxwell matrix (row sum to ground,
//! `-C_ij` coupling), plus a second node per net for series L and R when asked.

pub use crate::field::henry::{InductMatrix, InductanceError};
pub use crate::field::{mesh, solve, Accuracy, CapMatrix};

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
    matrix: &mut CapMatrix,
    out: &mut ParasiticNetwork,
) -> Result<Accuracy, solve::SolveError> {
    out.clear();
    let accuracy = crate::field::extract_into(store, nets, selected, stack, grid, matrix)?;

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
    matrix: &mut InductMatrix,
    out: &mut ParasiticNetwork,
) -> Result<(), InductanceError> {
    crate::field::henry::extract_inductance_into(store, nets, selected, stack, grid, matrix)?;

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

/// Replace the analytical rows of every net `solved` has nodes for with the
/// solved rows, then sort canonically.
///
/// The mesh never sees an unsolved neighbour, so an analytical element between a
/// solved net and an unsolved one is kept, moved onto the solved net's first
/// node. Elements within or between solved nets are dropped: the solve replaces them.
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
