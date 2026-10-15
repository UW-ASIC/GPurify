//! Metal fill in an extraction (catalog PEX-012): what the dummy metal a
//! foundry's density rules require does to the nets around it.
//!
//! Data in: a [`ParasiticNetwork`] in which every fill piece was extracted
//! as a net of its own (its shapes on a layer the deck marks as fill), and
//! how the deck treats each such net. Data out: the network with every fill
//! net's nodes and elements gone and their effect folded into the nets'
//! own elements.
//!
//! The treatments are the ones `StarRC` and Quantus offer (Synopsys'
//! `StarRC` and Cadence's Quantus datasheets, public material only):
//!
//! - [`Treatment::Grounded`]: fill tied to ground; a net's coupling to a
//!   piece becomes capacitance to ground.
//! - [`Treatment::Floating`]: fill left floating. Each piece is a conductor
//!   with no charge, so it is eliminated from the capacitive network: with
//!   `Y` the nodal capacitance matrix (ground the reference), the nets'
//!   matrix becomes `Y_aa − Y_af Y_ff⁻¹ Y_fa` (the Schur complement over the
//!   fill's nodes, a Kron reduction; Kron, *Tensor Analysis of Networks*,
//!   1939). A net coupled to a lone piece by `c₁`, another by `c₂`, the
//!   piece to ground by `c_g`, gets `c₁c₂ / (c₁ + c₂ + c_g)` to the other
//!   net and `c₁c_g / (c₁ + c₂ + c_g)` to ground: the series capacitors.
//!   Pieces coupled to each other are eliminated together.
//! - [`Treatment::Ignored`]: the fill is not there; every element touching
//!   it is dropped.
//!
//! A fill net is one conductor: its nodes are one node here, and its
//! resistance plays no part. "Virtual fill" (fill a tool would insert, not
//! drawn) is not modelled.

use crate::cholesky;
use crate::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_check::topology::NetId;
use gpurify_geom::Qty;
use std::collections::BTreeMap;

/// How the deck treats fill (`pex_fill <layer> floating|grounded|ignored`).
pub use gpurify_ingest::deck::FillTreatment as Treatment;

/// Folds every fill net of `fill` into the rest of `network` by its
/// treatment and removes its nodes; the other nets' nodes keep their order
/// (renumbered down) and the network ends canonical.
///
/// A cluster of floating pieces with no capacitance to anything is dropped:
/// it changes nothing.
///
/// # Errors
///
/// [`FillError::Cluster`] when floating pieces couple into a cluster too
/// large to reduce; the network is then unchanged.
pub fn treat(
    network: &mut ParasiticNetwork,
    fill: &BTreeMap<NetId, Treatment>,
) -> Result<(), FillError> {
    if fill.is_empty() {
        return Ok(());
    }
    let net_of = |node: NodeId| network.node_net[node.0 as usize];
    let treatment = |node: NodeId| fill.get(&net_of(node)).copied();
    let end = |node: Option<NodeId>| match node {
        None => End::Ground,
        Some(n) if treatment(n).is_some() => End::Fill(net_of(n)),
        Some(n) => End::Node(n),
    };
    let mut kept = ParasiticNetwork {
        node_net: network.node_net.clone(),
        node_layer: network.node_layer.clone(),
        ..ParasiticNetwork::default()
    };
    // Floating pieces: their capacitances to other ends, per piece.
    let mut floating: BTreeMap<NetId, Vec<(End, f64)>> = BTreeMap::new();
    for row in 0..network.element_count() {
        let (from, to, value) = (network.from[row], network.to[row], network.value[row]);
        let (a, b) = (end(Some(from)), end(to));
        let touches_fill = matches!(a, End::Fill(_)) || matches!(b, End::Fill(_));
        if !touches_fill {
            kept.push(from, to, value);
            continue;
        }
        let farads = match value {
            Parasitic::GroundCap(q) | Parasitic::CouplingCap(q) => q.raw(),
            // A fill piece's resistance and inductance carry no current.
            _ => continue,
        };
        for (here, there) in [(a, b), (b, a)] {
            let End::Fill(net) = here else { continue };
            if there == here {
                continue;
            }
            match fill[&net] {
                Treatment::Ignored => {}
                Treatment::Grounded => {
                    if let End::Node(node) = there {
                        kept.push(node, None, Parasitic::GroundCap(Qty::new(farads)));
                    }
                }
                Treatment::Floating => {
                    // A grounded piece is ground to a floating one; an
                    // ignored one is not there.
                    let there = match there {
                        End::Fill(other) => match fill[&other] {
                            Treatment::Floating => there,
                            Treatment::Grounded => End::Ground,
                            Treatment::Ignored => continue,
                        },
                        other => other,
                    };
                    floating.entry(net).or_default().push((there, farads));
                }
            }
        }
    }
    eliminate(&floating, &net_of, &mut kept)?;
    // Drop the fill nets' nodes, renumbering the rest in order.
    let mut new_id = vec![None; network.node_count()];
    let mut out = ParasiticNetwork::default();
    for (old, &net) in network.node_net.iter().enumerate() {
        if !fill.contains_key(&net) {
            new_id[old] = Some(NodeId::at(out.node_net.len()));
            out.node_net.push(net);
            out.node_layer.push(network.node_layer[old]);
        }
    }
    for row in 0..kept.element_count() {
        let from = new_id[kept.from[row].0 as usize].expect("a kept element's node is kept");
        let to = kept.to[row].map(|n| new_id[n.0 as usize].expect("kept"));
        out.push(from, to, kept.value[row]);
    }
    out.sort_canonical();
    *network = out;
    Ok(())
}

/// One end of a capacitance: a net's node, a fill piece (its net), or
/// ground.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum End {
    Node(NodeId),
    Fill(NetId),
    Ground,
}

/// The Kron reduction of every cluster of floating pieces (pieces joined by
/// capacitance), appending each new coupling and ground capacitance to
/// `kept`.
fn eliminate(
    floating: &BTreeMap<NetId, Vec<(End, f64)>>,
    net_of: &dyn Fn(NodeId) -> NetId,
    kept: &mut ParasiticNetwork,
) -> Result<(), FillError> {
    // Clusters: pieces joined by a capacitance, by union-find over the
    // pieces' positions in `floating`.
    let pieces: Vec<NetId> = floating.keys().copied().collect();
    let at = |net: NetId| pieces.binary_search(&net).ok();
    let mut parent: Vec<usize> = (0..pieces.len()).collect();
    for (k, entries) in floating.values().enumerate() {
        for &(there, _) in entries {
            if let End::Fill(other) = there {
                let (a, b) = (
                    root(&mut parent, k),
                    root(&mut parent, at(other).expect("floating")),
                );
                parent[a.max(b)] = a.min(b);
            }
        }
    }
    let mut clusters: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for k in 0..pieces.len() {
        let r = root(&mut parent, k);
        clusters.entry(r).or_default().push(k);
    }
    for members in clusters.values() {
        if members.len() > MAX_CLUSTER {
            return Err(FillError::Cluster(members.len()));
        }
        let place = |k: usize| members.binary_search(&k).expect("a member");
        let mut nodes: Vec<NodeId> = members
            .iter()
            .flat_map(|&k| floating[&pieces[k]].iter())
            .filter_map(|&(there, _)| match there {
                End::Node(n) => Some(n),
                _ => None,
            })
            .collect();
        nodes.sort_unstable();
        nodes.dedup();
        let (k, m) = (members.len(), nodes.len());
        // Y_ff (k × k) and Y_fa (k × m), row-major.
        let mut yff = vec![0.0_f64; k * k];
        let mut yfa = vec![0.0_f64; k * m];
        for (a, &piece) in members.iter().enumerate() {
            for &(there, c) in &floating[&pieces[piece]] {
                yff[a * k + a] += c;
                match there {
                    End::Ground => {}
                    End::Node(n) => {
                        let j = nodes.binary_search(&n).expect("collected");
                        yfa[a * m + j] -= c;
                    }
                    End::Fill(other) => {
                        let b = place(at(other).expect("floating"));
                        yff[a * k + b] -= c;
                    }
                }
            }
        }
        // X = Y_ff⁻¹ Y_fa, one column per node; a cluster with no
        // capacitance is singular and changes nothing.
        let Some(factor) = cholesky::factor(yff, k) else {
            continue;
        };
        let x: Vec<Vec<f64>> = (0..m)
            .map(|j| {
                let column: Vec<f64> = (0..k).map(|a| yfa[a * m + j]).collect();
                cholesky::solve(&factor, k, &column)
            })
            .collect();
        for i in 0..m {
            let to_cluster: f64 = (0..k).map(|a| -yfa[a * m + i]).sum();
            let mut through = 0.0_f64;
            for j in 0..m {
                // M_ij = (Y_faᵀ X)_ij, the capacitance i sees to j through
                // the cluster; positive.
                let mij: f64 = (0..k).map(|a| -yfa[a * m + i] * -x[j][a]).sum();
                through += mij;
                if j > i && mij > 0.0 && net_of(nodes[i]) != net_of(nodes[j]) {
                    kept.push(
                        nodes[i],
                        Some(nodes[j]),
                        Parasitic::CouplingCap(Qty::new(mij)),
                    );
                }
            }
            let ground = to_cluster - through;
            if ground > 0.0 {
                kept.push(nodes[i], None, Parasitic::GroundCap(Qty::new(ground)));
            }
        }
    }
    Ok(())
}

/// The union-find root of `k`, halving the path.
fn root(parent: &mut [usize], mut k: usize) -> usize {
    while parent[k] != k {
        parent[k] = parent[parent[k]];
        k = parent[k];
    }
    k
}

/// The most floating fill pieces one cluster may hold: its reduction is a
/// dense solve, 32 MiB at this size.
///
/// ponytail: dense per cluster; a sparse factorisation lifts it if a fill
/// array ever couples into one cluster this large.
pub const MAX_CLUSTER: usize = 2048;

/// Why fill could not be folded in.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FillError {
    /// A cluster of floating pieces coupled to each other is larger than
    /// [`MAX_CLUSTER`].
    #[error(
        "{0} floating fill pieces couple into one cluster, over the {MAX_CLUSTER} one dense \
         reduction holds"
    )]
    Cluster(usize),
}

#[cfg(test)]
mod tests {
    use super::{treat, Treatment};
    use crate::network::{NodeId, Parasitic, ParasiticNetwork};
    use gpurify_check::topology::NetId;
    use gpurify_geom::{LayerId, Qty};
    use std::collections::BTreeMap;

    /// Nets `0` (signal a), `1` and `2` (fill) and `3` (signal b), one
    /// node each; `caps` are `(near, far, fF)`, `None` for ground.
    fn network(caps: &[(u32, Option<u32>, f64)]) -> ParasiticNetwork {
        let mut n = ParasiticNetwork {
            node_net: (0..4).map(NetId).collect(),
            node_layer: vec![LayerId(0); 4],
            ..ParasiticNetwork::default()
        };
        for &(a, b, c) in caps {
            let value = if b.is_some() {
                Parasitic::CouplingCap(Qty::new(c))
            } else {
                Parasitic::GroundCap(Qty::new(c))
            };
            n.push(NodeId(a), b.map(NodeId), value);
        }
        n.sort_canonical();
        n
    }

    fn treated(caps: &[(u32, Option<u32>, f64)], fill: &[(u32, Treatment)]) -> ParasiticNetwork {
        let mut n = network(caps);
        let fill: BTreeMap<NetId, Treatment> = fill.iter().map(|&(k, t)| (NetId(k), t)).collect();
        treat(&mut n, &fill).expect("small clusters");
        n
    }

    /// The coupling between the two signal nets, and each one's ground C.
    fn read(n: &ParasiticNetwork) -> (f64, f64, f64) {
        let (mut cc, mut ga, mut gb) = (0.0, 0.0, 0.0);
        for row in 0..n.element_count() {
            let on_a = n.node_net[n.from[row].0 as usize] == NetId(0);
            match (n.value[row], n.to[row]) {
                (Parasitic::CouplingCap(q), Some(_)) => cc += q.raw(),
                (Parasitic::GroundCap(q), None) if on_a => ga += q.raw(),
                (Parasitic::GroundCap(q), None) => gb += q.raw(),
                _ => {}
            }
        }
        (cc, ga, gb)
    }

    /// Oracle: closed form, series capacitors: a coupled to a floating
    /// piece by 2 fF, the piece to b by 3 fF and to ground by 1 fF: a–b
    /// `2·3/6 = 1` fF, a to ground `2·1/6`, b to ground `3·1/6`; the
    /// fill's nodes are gone and a direct 0.5 fF a–b coupling stays.
    #[test]
    fn one_floating_piece_puts_its_couplings_in_series() {
        let n = treated(
            &[
                (0, Some(1), 2.0),
                (1, Some(3), 3.0),
                (1, None, 1.0),
                (0, Some(3), 0.5),
            ],
            &[(1, Treatment::Floating), (2, Treatment::Floating)],
        );
        assert_eq!(n.node_net, [NetId(0), NetId(3)]);
        let (cc, ga, gb) = read(&n);
        assert!((cc - 1.5).abs() < 1e-12, "{cc}");
        assert!(
            (ga - 2.0 / 6.0).abs() < 1e-12 && (gb - 0.5).abs() < 1e-12,
            "{ga} {gb}"
        );
    }

    /// Oracle: closed form: a, two floating pieces and b in a chain of
    /// three 3 fF capacitors is 1 fF from a to b, nothing to ground; the two
    /// pieces are eliminated together.
    #[test]
    fn a_chain_of_floating_pieces_is_eliminated_together() {
        let n = treated(
            &[(0, Some(1), 3.0), (1, Some(2), 3.0), (2, Some(3), 3.0)],
            &[(1, Treatment::Floating), (2, Treatment::Floating)],
        );
        let (cc, ga, gb) = read(&n);
        assert!((cc - 1.0).abs() < 1e-12 && ga.abs() < 1e-12 && gb.abs() < 1e-12);
    }

    /// Oracle: the treatments' definitions: grounded, a's 2 fF and b's
    /// 3 fF to the piece go to ground and no coupling appears; ignored,
    /// both are dropped; a grounded piece next to a floating one is ground
    /// to it, so a sees 2 fF in series with 2 fF, 1 fF to ground.
    #[test]
    fn grounded_fill_grounds_and_ignored_fill_drops() {
        let caps = [(0, Some(1), 2.0), (1, Some(3), 3.0), (1, None, 1.0)];
        assert_eq!(
            read(&treated(&caps, &[(1, Treatment::Grounded)])),
            (0.0, 2.0, 3.0)
        );
        assert_eq!(
            read(&treated(&caps, &[(1, Treatment::Ignored)])),
            (0.0, 0.0, 0.0)
        );
        let n = treated(
            &[(0, Some(1), 2.0), (1, Some(2), 2.0)],
            &[(1, Treatment::Floating), (2, Treatment::Grounded)],
        );
        assert_eq!(read(&n), (0.0, 1.0, 0.0));
    }
}
