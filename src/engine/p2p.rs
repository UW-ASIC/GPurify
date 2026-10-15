//! Point-to-point resistance and net-to-net coupling between nets a user
//! names (catalog PEX-016): what a PEX run's text report prints for the
//! deck's `report p2p` and `report coupling` lines.
//!
//! **Point to point.** Between two or more points on one net, the effective
//! resistance of the net's resistor network between each pair: every
//! conducting shape a chain of resistors along its long axis, `sheet · ∫
//! ds / w(s)`, each via cut its layer's resistance per cut, the points
//! tapped where they lie (the model of ERC's `p2p_resistance`,
//! [`gpurify_check::erc::power::extract_points_into`]). Calibre PERC's P2P
//! and Voltus report the same quantity (public material only); effective
//! resistance means a parallel strap can only lower it.
//!
//! **Net to net.** The total coupling capacitance between two named nets in
//! the extracted network, the sum of every coupling element between a node
//! of one and a node of the other.

use crate::engine::pipeline::{Extracted, Loaded};
use gpurify_check::erc::power::{
    effective_resistance_into, extract_points_into, NetNetworks, SolveScratch,
};
use gpurify_check::topology::NetId;
use gpurify_extract::{Parasitic, ParasiticNetwork};
use gpurify_geom::{ops::Point, Dbu};

/// The one net `name` labels, or why there is none.
fn net_named(loaded: &Loaded, extracted: &Extracted, name: &str) -> Result<NetId, String> {
    let pieces = loaded
        .strings
        .get(name)
        .map_or(&[][..], |id| extracted.ports.nets_of(id));
    match *pieces {
        [net] => Ok(net),
        [] => Err(format!("no net is named {name}")),
        _ => Err(format!(
            "{name} labels {} disconnected nets, an open",
            pieces.len()
        )),
    }
}

/// The resistance between every two of `points` (database units, as a
/// deck's `report p2p` line holds them) on the net `name`, as `(i, j,
/// ohms)` for `i < j` in the order given; a pair whose points the net does
/// not join is absent.
///
/// # Errors
///
/// No net or several of that name, a point on none of its conducting
/// shapes, or a conductor with no sheet resistance.
pub fn resistance(
    loaded: &Loaded,
    extracted: &Extracted,
    name: &str,
    points: &[(Dbu, Dbu)],
) -> Result<Vec<(usize, usize, f64)>, String> {
    let net = net_named(loaded, extracted, name)?;
    #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
    let per_um = loaded.grid.dbu_per_um() as f64;
    #[expect(clippy::cast_precision_loss, reason = "a coordinate, for a message")]
    let um = |d: Dbu| d.raw() as f64 / per_um;
    let at: Vec<Point> = points.iter().map(|&(x, y)| Point { x, y }).collect();
    let process = gpurify_check::erc::Process {
        grid: loaded.grid,
        stack: &loaded.deck.stack,
        connectivity: &loaded.deck.connectivity,
    };
    let mut networks = NetNetworks::default();
    let nodes = extract_points_into(
        &loaded.store,
        &extracted.nets,
        process,
        net,
        &at,
        &mut networks,
    )
    .map_err(|why| match why {
        gpurify_check::erc::PowerError::NotOnNet(k) => format!(
            "point ({}, {}) µm lies on no conducting shape of {name}",
            um(points[k].0),
            um(points[k].1)
        ),
        other => other.to_string(),
    })?;
    let mut pairs = Vec::new();
    effective_resistance_into(&networks, 0, &mut SolveScratch::default(), &mut pairs)
        .map_err(|why| why.to_string())?;
    let mut out = Vec::new();
    for i in 0..nodes.len() {
        for j in i + 1..nodes.len() {
            let (a, b) = (nodes[i].min(nodes[j]), nodes[i].max(nodes[j]));
            if a == b {
                out.push((i, j, 0.0));
            } else if let Some(&(_, _, ohms)) = pairs.iter().find(|&&(p, q, _)| (p, q) == (a, b)) {
                out.push((i, j, ohms.raw()));
            }
        }
    }
    Ok(out)
}

/// The total coupling capacitance in fF between the nets `a` and `b`.
///
/// # Errors
///
/// No net or several of either name.
pub fn coupling(
    loaded: &Loaded,
    extracted: &Extracted,
    network: &ParasiticNetwork,
    a: &str,
    b: &str,
) -> Result<f64, String> {
    let (a, b) = (
        net_named(loaded, extracted, a)?,
        net_named(loaded, extracted, b)?,
    );
    let net_of = |node: gpurify_extract::network::NodeId| network.node_net[node.0 as usize];
    Ok((0..network.element_count())
        .filter_map(|row| match (network.value[row], network.to[row]) {
            (Parasitic::CouplingCap(q), Some(far)) => {
                let pair = (net_of(network.from[row]), net_of(far));
                (pair == (a, b) || pair == (b, a)).then(|| q.raw())
            }
            _ => None,
        })
        .sum())
}
