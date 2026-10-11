//! Quasi-static inductance: `GeometryStore` polygons in, per-net series L and R out.
//!
//! Data in: selected nets. Each net's shapes are merged per layer and cut into
//! disjoint rectangles, as the closed forms read them; each rectangle is a
//! filament along its long axis (short side × layer thickness), and two
//! rectangles that share an edge are joined by a short filament through the
//! middle of that edge. One port per net runs across its two most distant
//! filament end points.
//! Data out: [`InductMatrix`] — the port impedance diagonal at one frequency,
//! `L = Im(Z)/ω`, `R = Re(Z)`, from a dense nodal solve of `Zb = R + jωL`.
//!
//! The frequency is 1 MHz: skin effect is negligible on chip there, and `ωL`
//! still stands well above round-off next to `R`. The filament integrals are
//! in [`crate::field::filament`].

#![expect(
    clippy::needless_range_loop,
    reason = "assembly kernels index several lanes in lockstep; ranged loops keep the fold order explicit"
)]

use crate::conductor::Regions;
use crate::field::filament::{self, default_wdir, Filament, Vec3};
use gpurify_check::topology::{NetId, NetTable};
use gpurify_geom::{Bbox, GeometryStore, Grid, LayerId, PolyId};
use gpurify_ingest::deck::{Connectivity, ProcessStack};
use num_complex::Complex64;
use rayon::prelude::*;
use std::cmp::Reverse;

/// The one frequency the impedance is extracted at: 1 MHz, where skin effect is
/// negligible on chip and ωL is still well above round-off next to R.
const FREQUENCY_HZ: f64 = 1e6;

/// Per-net self inductance (H) and series resistance (Ω), one row per selected
/// net in ascending [`NetId`] order.
///
/// Despite the name, only the diagonal is computed: each net's own port
/// impedance. Mutual inductance between nets is not reported.
#[derive(Debug, Default)]
pub struct InductMatrix {
    /// The net of each row.
    pub net: Vec<NetId>,
    /// Series inductance between the net's port terminals, henries.
    pub l_henry: Vec<f64>,
    /// Series resistance between the net's port terminals, ohms. At 1 MHz
    /// and one filament across each rectangle's width this is the DC
    /// resistance.
    pub r_ohm: Vec<f64>,
}

/// Why an inductance solve was refused. Each names what is missing rather
/// than solving without it.
#[derive(Debug, thiserror::Error)]
pub enum InductanceError {
    /// A selected polygon's layer has no stack row, or a sheet resistance
    /// that is not positive and finite, so its conductivity is unknown.
    /// Carries the layer id.
    #[error(
        "layer {0} has no positive sheet resistance in the process stack, so \
         its conductivity is undefined and net inductance cannot be solved"
    )]
    NoSheetResistance(u16),
    /// A selected polygon's layer has a thickness that is not positive.
    /// Carries the layer id.
    #[error("layer {0} has no positive thickness in the process stack")]
    NoThickness(u16),
    /// A selected net has no polygons off the global layers, which carry no
    /// parasitics. Carries the net id.
    #[error("net {0} has no geometry to build a filament from")]
    EmptyNet(u32),
    /// The branch impedance matrix or the reduced nodal admittance matrix
    /// has an exactly zero pivot column. Carries the frequency in Hz.
    #[error("singular system at frequency {0} Hz")]
    Singular(f64),
    /// A selected net's shapes on a layer do not validate as simple
    /// rectilinear rings, so they cannot be cut into filaments exactly.
    /// Carries the layer id.
    #[error("layer {0} is not valid rectilinear geometry, so it cannot be cut into filaments")]
    InvalidGeometry(u16),
    /// A selected net's filaments do not form one circuit: its pieces do
    /// not all join through shared edges and vias (two pieces meeting only
    /// at a corner, say), so its port impedance is undefined. Carries the
    /// net id.
    #[error(
        "net {0}'s shapes do not join into one circuit through shared edges and vias, \
         so its inductance is undefined"
    )]
    Disconnected(u32),
}

/// A filament node: coordinates in doubled database units, so every
/// rectangle's centre line lands on an integer, plus the layer. Sorted is
/// dedup order.
type NodeKey = (i64, i64, u16);

/// A rectangle's filament: its centre line along the long side (a square
/// runs along x), in doubled database units.
#[derive(Debug, Clone, Copy)]
struct Line {
    along_x: bool,
    /// The two ends, along the axis.
    lo: i64,
    hi: i64,
    /// The centre line's place across the axis.
    at: i64,
    /// The short side, in database units: the filament's width.
    width: i64,
}

impl Line {
    fn of(r: Bbox) -> Self {
        let (xlo, xhi, ylo, yhi) = (r.xlo.raw(), r.xhi.raw(), r.ylo.raw(), r.yhi.raw());
        if xhi - xlo >= yhi - ylo {
            Line {
                along_x: true,
                lo: 2 * xlo,
                hi: 2 * xhi,
                at: ylo + yhi,
                width: yhi - ylo,
            }
        } else {
            Line {
                along_x: false,
                lo: 2 * ylo,
                hi: 2 * yhi,
                at: xlo + xhi,
                width: xhi - xlo,
            }
        }
    }

    /// Where the point `(x, y)` (doubled units) projects onto the line,
    /// clamped to its ends, as a coordinate along the axis.
    fn project(self, x: i64, y: i64) -> i64 {
        (if self.along_x { x } else { y }).clamp(self.lo, self.hi)
    }

    fn key(self, along: i64, layer: u16) -> NodeKey {
        if self.along_x {
            (along, self.at, layer)
        } else {
            (self.at, along, layer)
        }
    }
}

/// The midpoint (doubled units) and length (database units) of the edge two
/// disjoint rectangles share, if they share one of positive length; `None`
/// for a corner touch or a gap.
fn shared_edge(a: Bbox, b: Bbox) -> Option<(i64, i64, i64)> {
    let (ax0, ax1, ay0, ay1) = (a.xlo.raw(), a.xhi.raw(), a.ylo.raw(), a.yhi.raw());
    let (bx0, bx1, by0, by1) = (b.xlo.raw(), b.xhi.raw(), b.ylo.raw(), b.yhi.raw());
    let (ylo, yhi) = (ay0.max(by0), ay1.min(by1));
    if (ax1 == bx0 || bx1 == ax0) && yhi > ylo {
        let x = if ax1 == bx0 { ax1 } else { ax0 };
        return Some((2 * x, ylo + yhi, yhi - ylo));
    }
    let (xlo, xhi) = (ax0.max(bx0), ax1.min(bx1));
    if (ay1 == by0 || by1 == ay0) && xhi > xlo {
        let y = if ay1 == by0 { ay1 } else { ay0 };
        return Some((xlo + xhi, 2 * y, xhi - xlo));
    }
    None
}

/// Solve per-net L and R for `selected` in one magnetoquasistatic solve.
///
/// `out` is cleared first and gets one row per selected net, in ascending
/// [`NetId`] order. All selected nets share one solve, and each net's value
/// is its port's self impedance with every other port open.
///
/// Each selected net's shapes are merged per layer and cut into disjoint
/// rectangles (vertical slabs), as the closed forms read them, so a wire is
/// the same conductor however it was drawn. Each rectangle is a filament
/// along its centre line, end to end along its long side (a square runs
/// along x), the short side wide and the layer thickness deep. Two
/// rectangles that share an edge are joined through the middle of it: a
/// filament from where that midpoint projects onto one centre line to where
/// it projects onto the other, as wide as the shared edge. A centre line is
/// split wherever a junction lands on it, and a stub past the last landing
/// carries no current. So a bend of constant width `w` and centre-line
/// length `Lc` reads `Lc / w` squares, its corner counted once. Pieces that
/// meet only at a corner are not joined.
///
/// Layers join through vias ([`Connectivity::via_cut`]): each cut whose box
/// shares a point with the net's rectangles on both of its plates lands on
/// the rectangle it overlaps most on each (the lowest on a tie), and is a
/// filament from where its centre projects onto one centre line to where it
/// projects onto the other, the cut wide and long, carrying the layer's
/// resistance per cut. Cuts of one array are so many filaments in parallel.
/// A net's port runs between its two most distant end points. Shapes on a
/// global layer ([`Connectivity::global`], the substrate as a net) carry no
/// modelled current: they are left out and need no stack row, so a net
/// whose pieces join only through one is not one circuit.
///
/// # Errors
///
/// [`InductanceError::EmptyNet`] for a selected net with no polygons off the
/// global layers,
/// [`InductanceError::InvalidGeometry`] for a net's shapes on a layer that
/// are not valid rectilinear rings, [`InductanceError::NoSheetResistance`]
/// or [`InductanceError::NoThickness`] for a shape on a layer the stack does
/// not describe (or a joining via layer with no resistance per cut),
/// [`InductanceError::Disconnected`] for a net whose pieces do not join into
/// one circuit (pieces meeting only at a corner, say), and
/// [`InductanceError::Singular`] if either factorisation meets a zero pivot.
/// Nets are checked in ascending order, each net's layers in ascending
/// order.
///
/// # Time complexity
///
/// A merge per net and layer; a check of every pair of one region's
/// rectangles for a shared edge; a scan of each via layer's cuts per net;
/// then *O*(B²) filament-pair integrals and an *O*(B³) complex factorisation
/// for B filament pieces, then an *O*(N³) one for N filament nodes.
pub fn extract_inductance_into(
    store: &GeometryStore,
    nets: &NetTable,
    connectivity: &Connectivity,
    selected: &[NetId],
    stack: &ProcessStack,
    grid: Grid,
    out: &mut InductMatrix,
) -> Result<(), InductanceError> {
    out.net.clear();
    out.l_henry.clear();
    out.r_ohm.clear();

    let mut order = selected.to_vec();
    order.sort_unstable();

    #[expect(
        clippy::cast_precision_loss,
        reason = "a grid resolution is a small count"
    )]
    let scale = 1e-6 / grid.dbu_per_um() as f64;
    let nm = 1e-9;
    let stack_rows = stack
        .sheet_res_ohm_sq
        .len()
        .min(stack.thickness_nm.len())
        .min(stack.height_nm.len());
    // Conductivity and thickness of a described layer; σ = 1/(Rsq · t)
    // reproduces the sheet resistance through the thickness.
    let conductor = |layer: u16| -> Result<(f64, f64), InductanceError> {
        let row = usize::from(layer);
        let sheet = stack.sheet_res_ohm_sq.get(row).copied().unwrap_or(0.0);
        let thickness_m = stack.thickness_nm.get(row).copied().unwrap_or(0.0) * nm;
        if row >= stack_rows || !(sheet > 0.0) || !sheet.is_finite() {
            return Err(InductanceError::NoSheetResistance(layer));
        }
        if !(thickness_m > 0.0) {
            return Err(InductanceError::NoThickness(layer));
        }
        Ok((1.0 / (sheet * thickness_m), thickness_m))
    };
    // A node's place, metres: half a database unit per doubled unit.
    let position = |(x, y, layer): NodeKey| {
        let row = usize::from(layer);
        let z = (stack.height_nm.get(row).copied().unwrap_or(0.0)
            + stack.thickness_nm.get(row).copied().unwrap_or(0.0) / 2.0)
            * nm;
        #[expect(
            clippy::cast_precision_loss,
            reason = "|coordinate| < 2^42, exact in f64"
        )]
        Vec3::new(x as f64 * scale / 2.0, y as f64 * scale / 2.0, z)
    };

    let mut nodes: Vec<Vec3> = Vec::new();
    let mut set = FilamentSet::default();
    let mut ports: Vec<(usize, usize)> = Vec::new();
    // Per net, reused: each rectangle's line and layer, the stops on each
    // line (`(rectangle, along)`), the junctions and the node keys.
    let mut lines: Vec<(Line, u16)> = Vec::new();
    let mut stops: Vec<(usize, i64)> = Vec::new();
    let mut junctions: Vec<(NodeKey, NodeKey, i64)> = Vec::new();
    let mut vias: Vec<(NodeKey, NodeKey, Bbox, f64)> = Vec::new();
    let mut keys: Vec<NodeKey> = Vec::new();
    // Each net's node range, for the one-circuit check.
    let mut spans: Vec<(NetId, usize, usize)> = Vec::new();
    for &net in &order {
        let mut regions = Regions::default();
        regions
            .push_net(store, nets, net, |layer| {
                !connectivity.global.contains(&layer)
            })
            .map_err(|layer| InductanceError::InvalidGeometry(layer.0))?;
        if regions.len() == 0 {
            return Err(InductanceError::EmptyNet(net.0));
        }
        for &layer in &regions.layer {
            conductor(layer.0)?;
        }

        lines.clear();
        stops.clear();
        junctions.clear();
        for region in 0..regions.len() {
            let layer = regions.layer[region].0;
            let range = regions.rect_range(region);
            for &rect in &regions.rects[range.clone()] {
                let line = Line::of(rect);
                stops.push((lines.len(), line.lo));
                stops.push((lines.len(), line.hi));
                lines.push((line, layer));
            }
            // ponytail: every pair of one region's rectangles; a sweep over
            // slab boundaries if regions grow to thousands of rectangles.
            for i in range.clone() {
                for j in i + 1..range.end {
                    let Some((x, y, edge)) = shared_edge(regions.rects[i], regions.rects[j]) else {
                        continue;
                    };
                    let (a, b) = (lines[i].0, lines[j].0);
                    let (at_a, at_b) = (a.project(x, y), b.project(x, y));
                    stops.push((i, at_a));
                    stops.push((j, at_b));
                    let (from, to) = (a.key(at_a, layer), b.key(at_b, layer));
                    if from != to {
                        junctions.push((from, to, edge));
                    }
                }
            }
        }
        // A line's index is its rectangle's index in `regions.rects`.
        vias.clear();
        for (&cut_layer, &(lower, upper)) in
            connectivity.via_cut.iter().zip(&connectivity.via_connects)
        {
            let plate = |layer: LayerId| -> Vec<usize> {
                (0..lines.len())
                    .filter(|&i| lines[i].1 == layer.0)
                    .collect()
            };
            let (below, above) = (plate(lower), plate(upper));
            let reach = |plate: &[usize]| {
                plate
                    .iter()
                    .fold(Bbox::EMPTY, |b, &i| b.union(regions.rects[i]))
            };
            let Some(window) = reach(&below).intersection(reach(&above)) else {
                continue;
            };
            // ponytail: scans every cut on the layer per net; a spatial
            // query if selections meet chip-scale via layers.
            for row in store.polys_on_layer(cut_layer) {
                let cut = store.poly_bbox(PolyId(row));
                if !cut.overlaps(window) {
                    continue;
                }
                let land = |plate: &[usize]| {
                    plate
                        .iter()
                        .copied()
                        .filter(|&i| cut.overlaps(regions.rects[i]))
                        .max_by_key(|&i| {
                            let shared = cut.intersection(regions.rects[i]);
                            (shared.map_or(0, |b| b.area().raw()), Reverse(i))
                        })
                };
                let (Some(a), Some(b)) = (land(&below), land(&above)) else {
                    continue;
                };
                let ohm = stack
                    .sheet_res_ohm_sq
                    .get(cut_layer.idx())
                    .copied()
                    .filter(|&ohm| ohm > 0.0 && ohm.is_finite())
                    .ok_or(InductanceError::NoSheetResistance(cut_layer.0))?;
                let (x, y) = (cut.xlo.raw() + cut.xhi.raw(), cut.ylo.raw() + cut.yhi.raw());
                let ((line_a, layer_a), (line_b, layer_b)) = (lines[a], lines[b]);
                let (at_a, at_b) = (line_a.project(x, y), line_b.project(x, y));
                stops.push((a, at_a));
                stops.push((b, at_b));
                vias.push((
                    line_a.key(at_a, layer_a),
                    line_b.key(at_b, layer_b),
                    cut,
                    ohm,
                ));
            }
        }
        stops.sort_unstable();
        stops.dedup();

        // Node order is the sorted key order: a function of the geometry alone.
        keys.clear();
        keys.extend(stops.iter().map(|&(i, along)| {
            let (line, layer) = lines[i];
            line.key(along, layer)
        }));
        keys.sort_unstable();
        keys.dedup();
        let base = nodes.len();
        nodes.extend(keys.iter().map(|&key| position(key)));
        let node_of = |key: NodeKey| {
            base + keys
                .binary_search(&key)
                .expect("every stop was pushed as a key")
        };

        #[expect(clippy::cast_precision_loss, reason = "|side| < 2^41, exact in f64")]
        let metres = |dbu: i64| dbu as f64 * scale;
        for run in stops.chunk_by(|a, b| a.0 == b.0) {
            let (line, layer) = lines[run[0].0];
            let (sigma, thickness_m) = conductor(layer)?;
            let w = metres(line.width);
            for pair in run.windows(2) {
                let n1 = node_of(line.key(pair[0].1, layer));
                let n2 = node_of(line.key(pair[1].1, layer));
                set.push(nodes[n1], nodes[n2], w, thickness_m, sigma, n1, n2);
            }
        }
        for &(from, to, edge) in &junctions {
            let (sigma, thickness_m) = conductor(from.2)?;
            let (n1, n2) = (node_of(from), node_of(to));
            set.push(
                nodes[n1],
                nodes[n2],
                metres(edge),
                thickness_m,
                sigma,
                n1,
                n2,
            );
        }
        for &(from, to, cut, ohm) in &vias {
            let (n1, n2) = (node_of(from), node_of(to));
            let (w, h) = (metres(cut.width().raw()), metres(cut.height().raw()));
            set.push_ohm(nodes[n1], nodes[n2], w, h, ohm, n1, n2);
        }

        let (pa, pb) = most_distant_pair(&nodes[base..]);
        ports.push((base + pa, base + pb));
        spans.push((net, base, nodes.len()));
        out.net.push(net);
    }

    let component = connected_components(&set, nodes.len());
    for &(net, from, to) in &spans {
        if component[from..to].iter().any(|&c| c != component[from]) {
            return Err(InductanceError::Disconnected(net.0));
        }
    }

    let f = FREQUENCY_HZ;
    let z = port_impedance_diagonal(&set, nodes.len(), &ports, f)?;
    let w = 2.0 * std::f64::consts::PI * f;
    for zp in z {
        out.l_henry.push(if w == 0.0 { 0.0 } else { zp.im / w });
        out.r_ohm.push(zp.re);
    }
    Ok(())
}

/// The two most distant nodes; ties keep the first pair in scan order.
// ponytail: O(n²) over one net's nodes; rotating calipers if nets grow large.
fn most_distant_pair(nodes: &[Vec3]) -> (usize, usize) {
    let n = nodes.len();
    if n == 1 {
        return (0, 0);
    }
    let (mut best, mut pair) = (-1.0_f64, (0, 1));
    for i in 0..n {
        for j in (i + 1)..n {
            let (a, b) = (nodes[i], nodes[j]);
            let d = (a.x - b.x).powi(2) + (a.y - b.y).powi(2) + (a.z - b.z).powi(2);
            if d > best {
                best = d;
                pair = (i, j);
            }
        }
    }
    pair
}

/// Branch filaments, `SoA`: geometry, DC resistance, and node pair.
#[derive(Default)]
struct FilamentSet {
    fils: Vec<Filament>,
    r: Vec<f64>,
    n1: Vec<usize>,
    n2: Vec<usize>,
}

impl FilamentSet {
    /// A conductor piece of conductivity `sigma`: `R = length / (σ w h)`.
    fn push(&mut self, p1: Vec3, p2: Vec3, w: f64, h: f64, sigma: f64, n1: usize, n2: usize) {
        let length = (p2 - p1).norm();
        self.push_ohm(p1, p2, w, h, length / (sigma * (w * h)), n1, n2);
    }

    /// A piece whose resistance is stated, not derived: a via cut.
    fn push_ohm(&mut self, p1: Vec3, p2: Vec3, w: f64, h: f64, ohm: f64, n1: usize, n2: usize) {
        // Normalized twice, as the width frame always was: the bits depend on it.
        let wdir = default_wdir((p2 - p1).normalized().normalized());
        self.fils.push(Filament::with_frame(p1, p2, w, h, wdir));
        self.r.push(ohm);
        self.n1.push(n1);
        self.n2.push(n2);
    }
}

/// `Z[p][p]` for every port at frequency `f`: nodal solve `A Zb⁻¹ Aᵀ V = I`
/// with one ground node per galvanically connected component.
fn port_impedance_diagonal(
    set: &FilamentSet,
    nn: usize,
    ports: &[(usize, usize)],
    f: f64,
) -> Result<Vec<Complex64>, InductanceError> {
    let fils = &set.fils;
    let nb = fils.len();

    // Partial inductance, upper triangle by rows (order-preserving collect).
    let rows: Vec<Vec<f64>> = (0..nb)
        .into_par_iter()
        .map(|i| {
            let mut row = vec![0.0; nb - i];
            row[0] = filament::self_inductance(&fils[i]);
            for j in (i + 1)..nb {
                row[j - i] = filament::mutual(&fils[i], &fils[j]);
            }
            row
        })
        .collect();

    // Ground: a port's negative terminal, else the component's lowest node.
    let comp = connected_components(set, nn);
    let ncomp = comp.iter().copied().max().map_or(0, |m| m + 1);
    let mut ground_of_comp = vec![usize::MAX; ncomp.max(1)];
    for &(_, c) in ports {
        let g = &mut ground_of_comp[comp[c]];
        if *g == usize::MAX {
            *g = c;
        }
    }
    for n in 0..nn {
        let g = &mut ground_of_comp[comp[n]];
        if *g == usize::MAX {
            *g = n;
        }
    }
    let mut is_ground = vec![false; nn];
    for &g in &ground_of_comp {
        if g != usize::MAX {
            is_ground[g] = true;
        }
    }
    let mut red_of = vec![usize::MAX; nn];
    let mut nred = 0;
    for n in 0..nn {
        if !is_ground[n] {
            red_of[n] = nred;
            nred += 1;
        }
    }

    // Zb = R (diagonal) + jωL.
    let w = 2.0 * std::f64::consts::PI * f;
    let mut zb = vec![Complex64::new(0.0, 0.0); nb * nb];
    for i in 0..nb {
        for j in 0..nb {
            let l = if j >= i {
                rows[i][j - i]
            } else {
                rows[j][i - j]
            };
            let mut val = Complex64::new(0.0, w * l);
            if i == j {
                val += Complex64::new(set.r[i], 0.0);
            }
            zb[i * nb + j] = val;
        }
    }
    let lu = Lu::factor(zb, nb).ok_or(InductanceError::Singular(f))?;

    // X[:, n] = Zb⁻¹ (Aᵀ column n) for every non-ground node.
    let xcols: Vec<Option<Vec<Complex64>>> = (0..nn)
        .into_par_iter()
        .map(|n| {
            if is_ground[n] {
                return None;
            }
            let mut rhs = vec![Complex64::new(0.0, 0.0); nb];
            for b in 0..nb {
                if set.n1[b] == n {
                    rhs[b] += Complex64::new(1.0, 0.0);
                }
                if set.n2[b] == n {
                    rhs[b] -= Complex64::new(1.0, 0.0);
                }
            }
            Some(lu.solve(&rhs))
        })
        .collect();

    // Reduced nodal admittance Yn = A X, scattered per branch.
    let mut yn = vec![Complex64::new(0.0, 0.0); nred * nred];
    for n in 0..nn {
        let Some(xc) = &xcols[n] else { continue };
        let rn = red_of[n];
        for b in 0..nb {
            let (b1, b2) = (set.n1[b], set.n2[b]);
            if !is_ground[b1] {
                yn[red_of[b1] * nred + rn] += xc[b];
            }
            if !is_ground[b2] {
                yn[red_of[b2] * nred + rn] -= xc[b];
            }
        }
    }
    let yn_lu = Lu::factor(yn, nred).ok_or(InductanceError::Singular(f))?;

    // Unit current into each port; its own voltage is Z[p][p].
    Ok(ports
        .iter()
        .map(|&(a, c)| {
            let mut iinj = vec![Complex64::new(0.0, 0.0); nred];
            if !is_ground[a] {
                iinj[red_of[a]] += Complex64::new(1.0, 0.0);
            }
            if !is_ground[c] {
                iinj[red_of[c]] -= Complex64::new(1.0, 0.0);
            }
            let v = yn_lu.solve(&iinj);
            let volt = |node: usize| {
                if is_ground[node] {
                    Complex64::new(0.0, 0.0)
                } else {
                    v[red_of[node]]
                }
            };
            volt(a) - volt(c)
        })
        .collect())
}

/// Component id per node (union-find over branches), numbered in ascending
/// order of each component's first node.
fn connected_components(set: &FilamentSet, nn: usize) -> Vec<usize> {
    fn find(parent: &mut [usize], x: usize) -> usize {
        let mut r = x;
        while parent[r] != r {
            r = parent[r];
        }
        let mut c = x;
        while parent[c] != r {
            let next = parent[c];
            parent[c] = r;
            c = next;
        }
        r
    }
    let mut parent: Vec<usize> = (0..nn).collect();
    for (&a, &b) in set.n1.iter().zip(&set.n2) {
        let ra = find(&mut parent, a);
        let rb = find(&mut parent, b);
        if ra != rb {
            parent[ra] = rb;
        }
    }
    let mut label = vec![usize::MAX; nn];
    let mut next = 0;
    let mut comp = vec![0usize; nn];
    for n in 0..nn {
        let r = find(&mut parent, n);
        if label[r] == usize::MAX {
            label[r] = next;
            next += 1;
        }
        comp[n] = label[r];
    }
    comp
}

/// Dense complex LU with partial pivoting (PA = LU), row-major `n × n`.
struct Lu {
    factors: Vec<Complex64>,
    piv: Vec<usize>,
    n: usize,
}

impl Lu {
    /// `None` when a pivot column is exactly zero.
    fn factor(mut lu: Vec<Complex64>, n: usize) -> Option<Self> {
        let mut piv: Vec<usize> = (0..n).collect();
        for k in 0..n {
            let mut p = k;
            let mut max = lu[k * n + k].norm();
            for i in (k + 1)..n {
                let m = lu[i * n + k].norm();
                if m > max {
                    max = m;
                    p = i;
                }
            }
            if max == 0.0 {
                return None;
            }
            if p != k {
                for j in 0..n {
                    lu.swap(k * n + j, p * n + j);
                }
                piv.swap(k, p);
            }

            // Rows are independent, so rayon is bit-identical to serial.
            let pivot = lu[k * n + k];
            let (top, tail) = lu.split_at_mut((k + 1) * n);
            let pivot_row = &top[k * n..(k + 1) * n];
            let update = |row: &mut [Complex64]| {
                let factor = row[k] / pivot;
                row[k] = factor;
                for j in (k + 1)..n {
                    row[j] -= factor * pivot_row[j];
                }
            };
            if (n - k - 1) * (n - k) > 64 * 64 {
                tail.par_chunks_mut(n).for_each(update);
            } else {
                tail.chunks_mut(n).for_each(update);
            }
        }
        Some(Lu {
            factors: lu,
            piv,
            n,
        })
    }

    fn solve(&self, b: &[Complex64]) -> Vec<Complex64> {
        let n = self.n;
        let mut x: Vec<Complex64> = self.piv.iter().map(|&p| b[p]).collect();
        for i in 0..n {
            let mut sum = x[i];
            for j in 0..i {
                sum -= self.factors[i * n + j] * x[j];
            }
            x[i] = sum;
        }
        for i in (0..n).rev() {
            let mut sum = x[i];
            for j in (i + 1)..n {
                sum -= self.factors[i * n + j] * x[j];
            }
            x[i] = sum / self.factors[i * n + i];
        }
        x
    }
}
