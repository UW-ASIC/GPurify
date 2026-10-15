//! Through-silicon vias (catalog PEX-015, the TSV part of 3D-IC
//! extraction): each cut on a deck's `pex_tsv` layer is a copper cylinder
//! through the silicon inside an oxide liner, and adds the liner's
//! capacitance to its net.
//!
//! **The closed form.** A cylinder of radius `r` and length `L` inside a
//! liner of thickness `t` and permittivity `k` is a coaxial capacitor to
//! the silicon around it, held at ground:
//! `C = 2π ε₀ k L / ln((r + t) / r)` (Katti, Stucchi, De Meyer and Dehaene,
//! "Electrical Modeling and Characterization of Through Silicon Vias (TSVs)
//! for 3-D Integrated Circuits", *IEEE Trans. Electron Devices* 57(1),
//! 2010, eq. 2). The cut's radius is the one of the circle of its drawn
//! area, `r = √(A / π)`. The via's resistance is its `pex` row's per-cut
//! value, as any via's.
//!
//! Not modelled: the depletion capacitance in series with the liner (it
//! needs the silicon's doping and the bias), TSV-to-TSV coupling through
//! the silicon (it needs a substrate network, PEX-013), micro-bumps and
//! interposer wiring. Every value is the stack's, supplied by the deck: no
//! open PDK has a TSV.

use crate::network::{Parasitic, ParasiticNetwork};
use gpurify_check::topology::{NetId, NetTable};
use gpurify_geom::{GeometryStore, Grid, LayerId, PolyId, Qty};
use gpurify_ingest::deck::{Connectivity, TsvModel};

/// ε₀ in fF/µm.
const EPSILON0_FF_PER_UM: f64 = 8.854_187_812_8e-3;

/// A polygon's area in square database units, by the shoelace formula.
fn area(store: &GeometryStore, poly: PolyId) -> i128 {
    let (xs, ys) = store.poly_verts(poly);
    let n = xs.len();
    let twice: i128 = (0..n)
        .map(|k| {
            let j = (k + 1) % n;
            i128::from(xs[k].raw()) * i128::from(ys[j].raw())
                - i128::from(xs[j].raw()) * i128::from(ys[k].raw())
        })
        .sum();
    twice.abs() / 2
}

/// The liner capacitance in fF of one TSV of `area_um2` drawn area.
pub fn liner_capacitance_ff(model: &TsvModel, area_um2: f64) -> f64 {
    let r = (area_um2 / std::f64::consts::PI).sqrt();
    let (length, liner) = (model.length_nm / 1000.0, model.liner_nm / 1000.0);
    2.0 * std::f64::consts::PI * EPSILON0_FF_PER_UM * model.liner_k * length
        / ((r + liner) / r).ln()
}

/// Adds every TSV cut's liner capacitance to ground on its net's first
/// node, the net being that of a conductor shape the cut lands on, and
/// restores canonical order. A cut on no net's shape adds nothing.
pub fn add_into(
    network: &mut ParasiticNetwork,
    store: &GeometryStore,
    nets: &NetTable,
    connectivity: &Connectivity,
    tsvs: &[(LayerId, &TsvModel)],
    grid: Grid,
) {
    if tsvs.is_empty() {
        return;
    }
    #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
    let per_um = grid.dbu_per_um() as f64;
    let mut added = Vec::new();
    for &(layer, model) in tsvs {
        // The conductors the cut layer joins, where its cuts find their net.
        let landings: Vec<LayerId> = (0..connectivity.via_cut.len())
            .filter(|&row| connectivity.via_cut[row] == layer)
            .flat_map(|row| {
                let (a, b) = connectivity.via_connects[row];
                [a, b]
            })
            .collect();
        for cut in store.polys_on_layer(layer) {
            let cut = PolyId(cut);
            let b = store.poly_bbox(cut);
            let centre = gpurify_geom::ops::Point {
                x: gpurify_geom::Dbu::new_unchecked(i64::midpoint(b.xlo.raw(), b.xhi.raw())),
                y: gpurify_geom::Dbu::new_unchecked(i64::midpoint(b.ylo.raw(), b.yhi.raw())),
            };
            let net = landings.iter().find_map(|&on| {
                store
                    .polys_on_layer(on)
                    .map(PolyId)
                    .find(|&poly| store.poly_contains_point(poly, centre))
                    .map(|poly| nets.net_of(poly))
                    .filter(|&net| net != NetId::NONE)
            });
            let Some(node) = net.and_then(|net| network.first_node(net)) else {
                continue;
            };
            #[expect(clippy::cast_precision_loss, reason = "an area in database units")]
            let area_um2 = area(store, cut) as f64 / (per_um * per_um);
            added.push((node, liner_capacitance_ff(model, area_um2)));
        }
    }
    for (node, femtofarads) in added {
        network.push(node, None, Parasitic::GroundCap(Qty::new(femtofarads)));
    }
    network.sort_canonical();
}
