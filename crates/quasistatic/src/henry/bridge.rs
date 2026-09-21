//! Geometry bridge: [`GeometryStore`] polygons in, quasi-static inductance out.
//!
//! One [`henry::Netlist`](crate::henry::Netlist) is assembled for the whole
//! selection — one axis-aligned filament segment per polygon bounding box, one
//! port per net across its two most-distant nodes — and solved once at the
//! requested frequency. The port impedance diagonal is the answer:
//! `L = Im(Z)/ω`, `R = Re(Z)`.
//!
//! Determinism: nets are processed in ascending [`NetId`] order, node dedup is
//! a sorted vec of quantized endpoints (no map is iterated), and the solver's
//! own assembly is deck-order with order-preserving parallelism.

use crate::henry::netlist::{FreqSweep, Netlist, Node, Port, Segment};
use crate::henry::solver::{solve_with, Method, SolveError};
use gpurify_geom::GeometryStore;
use gpurify_ingest::deck::ProcessStack;
use gpurify_topology::{NetId, NetTable};
use gpurify_geom::Grid;

/// How the inductance solve is run.
#[derive(Debug, Clone, Copy)]
pub struct InductanceOptions {
    /// The single frequency the impedance is extracted at [Hz]. Must be
    /// positive: `L = Im(Z)/ω` is undefined at DC.
    pub frequency_hz: f64,
    /// Dense LU or preconditioned GMRES for the branch system.
    pub method: Method,
}

impl Default for InductanceOptions {
    /// 1 MHz — low enough that skin effect is negligible for on-chip
    /// cross-sections (quasi-static), high enough that ωL is well above
    /// round-off next to R — and the exact direct solve.
    fn default() -> Self {
        InductanceOptions {
            frequency_hz: 1e6,
            method: Method::Direct,
        }
    }
}

/// Per-net self inductance and resistance, one row per selected net in
/// ascending [`NetId`] order.
#[derive(Debug, Default)]
pub struct InductMatrix {
    pub net: Vec<NetId>,
    /// Self (loop) inductance seen at the net's port [H].
    pub l_henry: Vec<f64>,
    /// Series resistance seen at the net's port [Ω].
    pub r_ohm: Vec<f64>,
}

#[derive(Debug, thiserror::Error)]
pub enum InductanceError {
    /// A selected net touches a layer the stack states no usable sheet
    /// resistance for — refused by name, because a silent skip would report an
    /// inductance that never saw part of the conductor.
    #[error(
        "layer {0} has no positive sheet resistance in the process stack, so \
         its conductivity is undefined and net inductance cannot be solved"
    )]
    NoSheetResistance(u16),
    /// A selected net touches a layer with no positive thickness, so the
    /// filament cross-section (and σ = 1/(Rsq·t)) is undefined.
    #[error("layer {0} has no positive thickness in the process stack")]
    NoThickness(u16),
    /// A selected net owns no polygons at all.
    #[error("net {0} has no geometry to build a filament from")]
    EmptyNet(u32),
    #[error(transparent)]
    Solve(#[from] SolveError),
}

/// One database unit in metres.
fn metres_per_dbu(grid: Grid) -> f64 {
    #[expect(
        clippy::cast_precision_loss,
        reason = "a grid resolution is a small count"
    )]
    let per_um = grid.dbu_per_um() as f64;
    1e-6 / per_um
}

/// A quantized node key: endpoint coordinates in database units plus the layer
/// (which decides z). Lexicographic `Ord`, so a sorted vec is the dedup.
type NodeKey = (i64, i64, u16);

/// Extract per-net inductance and resistance for `selected` by a single
/// magnetoquasistatic solve over the whole selection.
///
/// Rectangles only: each polygon contributes one filament along its bounding
/// box's long axis, with the short side as width and the layer thickness as
/// height, centred at `height_nm + thickness_nm / 2`.
// ponytail: one filament bundle per poly bbox; centerline decomposition when L-shaped nets need it.
pub fn extract_inductance_into(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    stack: &ProcessStack,
    grid: Grid,
    options: &InductanceOptions,
    out: &mut InductMatrix,
) -> Result<(), InductanceError> {
    debug_assert!(
        options.frequency_hz > 0.0,
        "L = Im(Z)/omega is undefined at DC"
    );

    out.net.clear();
    out.l_henry.clear();
    out.r_ohm.clear();

    // Ascending net order, inherited by nodes, segments, ports and the rows of
    // the answer. Matches the electrostatic `extract_into`'s convention.
    let mut order = selected.to_vec();
    order.sort_unstable();

    let scale = metres_per_dbu(grid);
    let nm = 1e-9;
    let stack_rows = stack
        .sheet_res_ohm_sq
        .len()
        .min(stack.thickness_nm.len())
        .min(stack.height_nm.len());

    let mut nl = Netlist::default();
    for &net in &order {
        let polys = nets.polys_of(net);
        if polys.is_empty() {
            return Err(InductanceError::EmptyNet(net.0));
        }

        // Pass 1: quantized filament endpoints, deduplicated by sort. A sorted
        // vec rather than a map, per CONVENTIONS: the node order must be a
        // function of the geometry alone.
        let mut keys: Vec<NodeKey> = Vec::with_capacity(polys.len() * 2);
        for &poly in polys {
            let (a, b) = filament_endpoints(store.poly_bbox(poly));
            let layer = store.poly_layer(poly).0;
            keys.push((a.0, a.1, layer));
            keys.push((b.0, b.1, layer));
        }
        keys.sort_unstable();
        keys.dedup();

        // The net's nodes, appended to the combined netlist in sorted-key order.
        let base = nl.nodes.len();
        for (local, &(x, y, layer)) in keys.iter().enumerate() {
            let row = usize::from(layer);
            debug_assert!(row < stack_rows, "checked against the stack in pass 2");
            let z = (stack.height_nm.get(row).copied().unwrap_or(0.0)
                + stack.thickness_nm.get(row).copied().unwrap_or(0.0) / 2.0)
                * nm;
            #[expect(
                clippy::cast_precision_loss,
                reason = "coordinates are under 2^41 database units, within f64's exact range"
            )]
            let pos = [x as f64 * scale, y as f64 * scale, z];
            let name = format!("n{}", base + local);
            nl.node_index.insert(name.clone(), nl.nodes.len());
            nl.nodes.push(Node { name, pos });
        }

        // Pass 2: one segment per polygon, cross-section from the stack.
        for &poly in polys {
            let layer = store.poly_layer(poly);
            let row = usize::from(layer.0);
            let sheet = stack.sheet_res_ohm_sq.get(row).copied().unwrap_or(0.0);
            let thickness_m = stack.thickness_nm.get(row).copied().unwrap_or(0.0) * nm;
            if row >= stack_rows || !(sheet > 0.0) || !sheet.is_finite() {
                return Err(InductanceError::NoSheetResistance(layer.0));
            }
            if !(thickness_m > 0.0) {
                return Err(InductanceError::NoThickness(layer.0));
            }
            // σ = 1/(Rsq · t): the conductivity that reproduces the sheet
            // resistance through the drawn thickness.
            let sigma = 1.0 / (sheet * thickness_m);

            let bbox = store.poly_bbox(poly);
            let (a, b) = filament_endpoints(bbox);
            let short = bbox.width().raw().min(bbox.height().raw());
            #[expect(
                clippy::cast_precision_loss,
                reason = "a bbox side is under 2^41 database units, within f64's exact range"
            )]
            let w = short as f64 * scale;

            let n1 = node_name(base, &keys, (a.0, a.1, layer.0));
            let n2 = node_name(base, &keys, (b.0, b.1, layer.0));
            nl.segments.push(Segment {
                name: format!("s{}", nl.segments.len()),
                n1,
                n2,
                w,
                h: thickness_m,
                sigma,
                nhinc: 1,
                nwinc: 1,
                rw: 2.0,
                rh: 2.0,
                wdir: None,
            });
        }

        // One port per net, across its two most-distant nodes. The scan runs
        // in sorted-key order with a strict improvement test, so ties resolve
        // to the coordinate-lexicographically first pair.
        let (pa, pb) = most_distant_pair(&nl.nodes[base..]);
        nl.ports.push(Port {
            name: format!("net{}", net.0),
            n1: nl.nodes[base + pa].name.clone(),
            n2: nl.nodes[base + pb].name.clone(),
        });

        out.net.push(net);
    }

    nl.freq = Some(FreqSweep {
        fmin: options.frequency_hz,
        fmax: options.frequency_hz,
        ndec: 1.0,
    });

    let result = solve_with(&nl, options.method)?;
    debug_assert_eq!(result.frequencies.len(), 1, "a single-point sweep");
    let l = result.inductance(0);
    let r = result.resistance(0);
    let n = out.net.len();
    debug_assert_eq!(l.rows, n, "one port per selected net");
    for i in 0..n {
        out.l_henry.push(l[(i, i)]);
        out.r_ohm.push(r[(i, i)]);
    }
    Ok(())
}

/// The filament endpoints of one bounding box, in database units: the centre
/// line along the long axis. Ties (a square) run along x.
fn filament_endpoints(bbox: gpurify_geom::Bbox) -> ((i64, i64), (i64, i64)) {
    let (xlo, xhi) = (bbox.xlo.raw(), bbox.xhi.raw());
    let (ylo, yhi) = (bbox.ylo.raw(), bbox.yhi.raw());
    if xhi - xlo >= yhi - ylo {
        let yc = i64::midpoint(ylo, yhi);
        ((xlo, yc), (xhi, yc))
    } else {
        let xc = i64::midpoint(xlo, xhi);
        ((xc, ylo), (xc, yhi))
    }
}

/// The global node name of one quantized key, via binary search over the net's
/// sorted key vec.
fn node_name(base: usize, keys: &[NodeKey], key: NodeKey) -> String {
    let local = keys
        .binary_search(&key)
        .expect("every segment endpoint was pushed as a key in pass 1");
    format!("n{}", base + local)
}

/// The indices (into `nodes`) of the two most-distant nodes, by 3-D metric
/// distance, coordinate-lexicographic tie-break.
///
/// `nodes` is in sorted-key order, so scanning `i < j` with a strictly-greater
/// test keeps the lexicographically first pair on a tie.
// ponytail: O(n²) over one net's nodes; a rotating-calipers pass if a net ever
// carries enough polygons for this to show up.
fn most_distant_pair(nodes: &[Node]) -> (usize, usize) {
    debug_assert!(!nodes.is_empty(), "a net with no nodes has no port");
    let n = nodes.len();
    if n == 1 {
        return (0, 0);
    }
    let (mut best, mut pair) = (-1.0_f64, (0, 1));
    for i in 0..n {
        for j in (i + 1)..n {
            let (a, b) = (&nodes[i].pos, &nodes[j].pos);
            let d = (a[0] - b[0]).powi(2) + (a[1] - b[1]).powi(2) + (a[2] - b[2]).powi(2);
            if d > best {
                best = d;
                pair = (i, j);
            }
        }
    }
    pair
}
