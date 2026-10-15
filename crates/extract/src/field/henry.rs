//! Quasi-static inductance: `GeometryStore` polygons in, per-net series L and R out.
//!
//! Data in: selected nets. Each net's shapes are merged per layer and cut into
//! disjoint rectangles, as the closed forms read them. A region of one
//! rectangle is a filament along its long axis (short side × layer
//! thickness), its current uniform; a region of several, where the wire
//! turns or changes width and the current crowds, is a grid of cells joined
//! face to face. One port per net runs across its two most
//! distant rectangle ends.
//! Data out: [`InductMatrix`] — the port impedance matrix at one frequency:
//! each net's `L = Im(Z_ii)/ω` and `R = Re(Z_ii)`, and the mutual inductance
//! `M_ij = Im(Z_ij)/ω` between every pair of nets, from a dense nodal solve
//! of `Zb = R + jωL`.
//!
//! The mutual inductance is the open-circuit one (Ruehli, *IBM J. Res. Dev.*
//! 16(5), 1972; Kamon, Tsuk & White, *IEEE Trans. MTT* 42(9), 1994, the
//! `FastHenry` port matrix): a unit current through net `j`'s port, every
//! other port open, induces `Z_ij` across net `i`'s. Its sign is the ports'
//! orientation: each port's current enters at the lower of its two end
//! points in node order (`x`, then `y`, then layer, as the layout states
//! them) and leaves at the other, so two parallel wires drawn side by side
//! read a positive `M`.
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
use gpurify_geom::{Bbox, Dbu, GeometryStore, Grid, LayerId, PolyId};
use gpurify_ingest::deck::{Connectivity, ProcessStack};
use num_complex::Complex64;
use rayon::prelude::*;
use std::cmp::Reverse;

/// The one frequency the impedance is extracted at: 1 MHz, where skin effect is
/// negligible on chip and ωL is still well above round-off next to R.
const FREQUENCY_HZ: f64 = 1e6;

/// Per-net self inductance (H) and series resistance (Ω), one row per selected
/// net in ascending [`NetId`] order, and the mutual inductance between every
/// pair of them.
#[derive(Debug, Default)]
pub struct InductMatrix {
    /// The net of each row.
    pub net: Vec<NetId>,
    /// Series inductance between the net's port terminals, henries.
    pub l_henry: Vec<f64>,
    /// The inductance matrix, henries, row-major `n × n`: `m_henry[i·n + j]`
    /// is `Im(Z_ij)/ω`, the voltage across net `i`'s port per unit current
    /// through net `j`'s, every other port open. The diagonal is
    /// [`Self::l_henry`]. Reciprocal (`Z` is symmetric, as `Zb` is) to
    /// round-off; signed by the ports' orientation (module docs).
    pub m_henry: Vec<f64>,
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

/// Solve per-net L and R, and the mutual inductance between every pair of
/// nets, for `selected` in one magnetoquasistatic solve.
///
/// `out` is cleared first and gets one row per selected net, in ascending
/// [`NetId`] order. All selected nets share one solve: each net's L and R are
/// its port's self impedance with every other port open, and
/// [`InductMatrix::m_henry`] holds the impedance between ports.
///
/// Each selected net's shapes are merged per layer and cut into disjoint
/// rectangles (vertical slabs), as the closed forms read them, so a wire is
/// the same conductor however it was drawn. A region of one rectangle is a
/// filament along its centre line, end to end along its long side (a square
/// runs along x), the short side wide and the layer thickness deep: a
/// straight run carries its current uniformly. A region of several
/// rectangles turns or changes width, and there the current crowds toward
/// the inner corner and the narrow side: it is a grid through every
/// rectangle edge, four cells across its narrowest rectangle, growing by
/// half again along straight runs away from them, each cell a node and each
/// two neighbouring cells a filament through their shared face (the
/// five-point discretisation of the plane's current, as `FastHenry`'s
/// uniform planes are meshed). So a right-angle bend's corner square reads
/// close to the 0.559 squares of Hall's conformal map (*Thin Solid Films*
/// 1(4), 1967), not the centre line's one. Pieces that meet only at a
/// corner are not joined.
///
/// Layers join through vias ([`Connectivity::via_cut`]): each cut whose box
/// shares a point with the net's rectangles on both of its plates lands on
/// the rectangle it overlaps most on each (the lowest on a tie), on a
/// filament where its centre projects onto the centre line, on a grid in
/// the cell under the middle of what the cut and the rectangle share, and
/// is a filament between its two landings, the cut wide and long, carrying
/// the layer's resistance per cut. Cuts of one array are so many filaments
/// in parallel. A net's port runs between its two most distant end points:
/// of a net of lines, its filaments' ends; of a net with a grid, its
/// rectangles' ends, a gridded rectangle's end a terminal joined to every
/// cell along that edge, an equipotential contact. Shapes on a
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
/// A merge per net and layer; a tensor grid per region of several
/// rectangles; a scan of each via layer's cuts per net;
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
    out.m_henry.clear();
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
    // line (`(rectangle, along)`) and the node keys.
    let mut lines: Vec<(Line, u16)> = Vec::new();
    let mut stops: Vec<(usize, i64)> = Vec::new();
    let mut vias: Vec<(Landing, Landing, Bbox, f64)> = Vec::new();
    let mut keys: Vec<NodeKey> = Vec::new();
    // Each net's node range, for the one-circuit check.
    let mut spans: Vec<(NetId, usize, usize)> = Vec::new();
    #[expect(clippy::cast_precision_loss, reason = "|side| < 2^41, exact in f64")]
    let metres = |dbu: i64| dbu as f64 * scale;
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

        // A region of several rectangles turns or changes width, where the
        // current crowds: it is gridded. One rectangle carries its current
        // uniformly, as one filament.
        let gridded: Vec<bool> = (0..regions.len())
            .map(|region| regions.rect_range(region).len() > 1)
            .collect();
        let mut region_of = vec![0_usize; regions.rects.len()];
        for region in 0..regions.len() {
            for rect in regions.rect_range(region) {
                region_of[rect] = region;
            }
        }

        lines.clear();
        stops.clear();
        for region in 0..regions.len() {
            let layer = regions.layer[region].0;
            for &rect in regions.rects_of(region) {
                let line = Line::of(rect);
                if !gridded[region] {
                    stops.push((lines.len(), line.lo));
                    stops.push((lines.len(), line.hi));
                }
                lines.push((line, layer));
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
                // On a gridded region, the cell under the middle of what the
                // cut and the rectangle share; on a line, its projection.
                let mut landing = |rect: usize| {
                    if gridded[region_of[rect]] {
                        let r = regions.rects[rect];
                        let shared = cut.intersection(r).unwrap_or(r);
                        // Half a unit inside the rectangle, so a cut that
                        // only touches its edge still lands on its own cell.
                        let inside = |at: i64, lo: Dbu, hi: Dbu| {
                            at.clamp(2 * lo.raw() + 1, 2 * hi.raw() - 1)
                        };
                        Landing::Cell(
                            rect,
                            inside(shared.xlo.raw() + shared.xhi.raw(), r.xlo, r.xhi),
                            inside(shared.ylo.raw() + shared.yhi.raw(), r.ylo, r.yhi),
                        )
                    } else {
                        let (line, layer) = lines[rect];
                        let along = line.project(x, y);
                        stops.push((rect, along));
                        Landing::Key(line.key(along, layer))
                    }
                };
                let (from, to) = (landing(a), landing(b));
                vias.push((from, to, cut, ohm));
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

        // Every gridded region's cells and the filaments between them.
        let mut grids: Vec<Option<CellGrid>> = Vec::with_capacity(regions.len());
        for region in 0..regions.len() {
            if !gridded[region] {
                grids.push(None);
                continue;
            }
            let layer = regions.layer[region].0;
            let (sigma, thickness_m) = conductor(layer)?;
            let z = position((0, 0, layer)).z;
            let grid = CellGrid::build(regions.rects_of(region), nodes.len());
            nodes.extend(
                grid.centres
                    .iter()
                    .map(|&(x, y)| Vec3::new(x * scale, y * scale, z)),
            );
            grid.filaments_into(scale, thickness_m, sigma, &nodes, &mut set);
            grids.push(Some(grid));
        }
        for &(from, to, cut, ohm) in &vias {
            let resolve = |landing: Landing| match landing {
                Landing::Key(key) => node_of(key),
                Landing::Cell(rect, x2, y2) => grids[region_of[rect]]
                    .as_ref()
                    .and_then(|grid| grid.cell_at(x2, y2))
                    .expect("a cut lands inside the rectangle it overlaps"),
            };
            let (n1, n2) = (resolve(from), resolve(to));
            let (w, h) = (metres(cut.width().raw()), metres(cut.height().raw()));
            set.push_ohm(nodes[n1], nodes[n2], w, h, ohm, n1, n2);
        }

        let (pa, pb) = if gridded.iter().any(|&g| g) {
            // The two most distant ends of any rectangle, lower key first; a
            // gridded rectangle's end is a terminal across its whole edge.
            let mut ends: Vec<(NodeKey, usize)> = Vec::with_capacity(2 * lines.len());
            for (rect, &(line, layer)) in lines.iter().enumerate() {
                ends.push((line.key(line.lo, layer), rect));
                ends.push((line.key(line.hi, layer), rect));
            }
            ends.sort_unstable();
            ends.dedup();
            let at: Vec<Vec3> = ends.iter().map(|&(key, _)| position(key)).collect();
            let (i, j) = most_distant_pair(&at);
            let mut terminal = |(key, rect): (NodeKey, usize)| -> Result<usize, InductanceError> {
                let region = region_of[rect];
                let Some(grid) = grids[region].as_ref() else {
                    return Ok(node_of(key));
                };
                let (sigma, thickness_m) = conductor(lines[rect].1)?;
                let node = nodes.len();
                nodes.push(position(key));
                grid.terminal_into(
                    regions.rects[rect],
                    key,
                    node,
                    scale,
                    thickness_m,
                    sigma,
                    &nodes,
                    &mut set,
                );
                Ok(node)
            };
            let first = terminal(ends[i])?;
            let second = if j == i { first } else { terminal(ends[j])? };
            (first - base, second - base)
        } else {
            most_distant_pair(&nodes[base..])
        };
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
    let z = port_impedance_matrix(&set, nodes.len(), &ports, f)?;
    let w = 2.0 * std::f64::consts::PI * f;
    let henry = |z: Complex64| if w == 0.0 { 0.0 } else { z.im / w };
    let n = ports.len();
    for p in 0..n {
        let zp = z[p * n + p];
        out.l_henry.push(henry(zp));
        out.r_ohm.push(zp.re);
    }
    out.m_henry.extend(z.iter().map(|&zqp| henry(zqp)));
    Ok(())
}

/// Where a via cut lands: a node key on a line, or a point (doubled
/// database units) on a gridded rectangle.
#[derive(Debug, Clone, Copy)]
enum Landing {
    /// A stop on a rectangle's centre line.
    Key(NodeKey),
    /// `(rectangle, x, y)`: the cell of a gridded region under the point.
    Cell(usize, i64, i64),
}

/// Cells across a gridded region's narrowest rectangle: the resolution of
/// the current's spread across a wire where it turns or changes width.
const CROWDING_CELLS: u32 = 4;

/// How much each cell grows over the last away from a region's edges and
/// corners, along a straight run where the current is uniform again.
const CELL_GROWTH: f64 = 1.5;

/// A gridded region: a tensor grid through every edge of its rectangles,
/// each cell inside them a node, each two neighbouring cells joined by a
/// filament through their shared face: the five-point discretisation of
/// the current's spread in the plane, as `FastHenry`'s uniform planes do
/// (Kamon, Tsuk & White, 1994). Coordinates in database units.
#[derive(Debug)]
struct CellGrid {
    /// The node of the first cell; the rest follow in `centres` order.
    first: usize,
    xs: Vec<f64>,
    ys: Vec<f64>,
    /// The node of cell `(i, j)` at `i · (ys.len() − 1) + j`, if inside.
    cell: Vec<Option<usize>>,
    /// Each node's cell centre, in node order.
    centres: Vec<(f64, f64)>,
}

/// Grid lines through every edge in `edges` (ascending, distinct): between
/// two neighbours `ceil(gap / step)` equal cells when that is at most twice
/// [`CROWDING_CELLS`], else cells growing by [`CELL_GROWTH`] from both ends
/// toward the middle.
fn cell_lines(edges: &[i64], step: f64) -> Vec<f64> {
    let mut out = Vec::new();
    for pair in edges.windows(2) {
        #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
        let (a, b) = (pair[0] as f64, pair[1] as f64);
        out.push(a);
        let gap = b - a;
        let pieces = (gap / step - 1e-9).ceil().max(1.0);
        if pieces <= 2.0 * f64::from(CROWDING_CELLS) {
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "at most twice CROWDING_CELLS"
            )]
            let pieces = pieces as u32;
            for k in 1..pieces {
                out.push(a + gap * f64::from(k) / f64::from(pieces));
            }
        } else {
            let (mut low, mut high, mut size) = (a, b, step);
            let mut upper = Vec::new();
            while high - low > 3.0 * size {
                low += size;
                high -= size;
                out.push(low);
                upper.push(high);
                size *= CELL_GROWTH;
            }
            out.extend(upper.into_iter().rev());
        }
    }
    #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
    let last = edges.last().map(|&e| e as f64);
    out.extend(last);
    out
}

impl CellGrid {
    /// The grid of the region of `rects` (disjoint, rectilinear), its nodes
    /// numbered from `first`. The cell size near every edge is the
    /// narrowest rectangle's short side over [`CROWDING_CELLS`].
    fn build(rects: &[Bbox], first: usize) -> Self {
        let edges = |lo: fn(&Bbox) -> i64, hi: fn(&Bbox) -> i64| {
            let mut out: Vec<i64> = rects.iter().flat_map(|r| [lo(r), hi(r)]).collect();
            out.sort_unstable();
            out.dedup();
            out
        };
        let narrowest = rects
            .iter()
            .map(|r| r.width().raw().min(r.height().raw()))
            .min()
            .unwrap_or(1)
            .max(1);
        #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
        let step = narrowest as f64 / f64::from(CROWDING_CELLS);
        let xs = cell_lines(&edges(|r| r.xlo.raw(), |r| r.xhi.raw()), step);
        let ys = cell_lines(&edges(|r| r.ylo.raw(), |r| r.yhi.raw()), step);
        let (nx, ny) = (xs.len() - 1, ys.len() - 1);
        let mut cell = vec![None; nx * ny];
        let mut centres = Vec::new();
        for i in 0..nx {
            for j in 0..ny {
                let (cx, cy) = ((xs[i] + xs[i + 1]) / 2.0, (ys[j] + ys[j + 1]) / 2.0);
                #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
                let inside = rects.iter().any(|r| {
                    (r.xlo.raw() as f64) < cx
                        && cx < r.xhi.raw() as f64
                        && (r.ylo.raw() as f64) < cy
                        && cy < r.yhi.raw() as f64
                });
                if inside {
                    cell[i * ny + j] = Some(first + centres.len());
                    centres.push((cx, cy));
                }
            }
        }
        CellGrid {
            first,
            xs,
            ys,
            cell,
            centres,
        }
    }

    /// The node of the cell under the point `(x2, y2)` in doubled database
    /// units, `None` when no cell of the region is there.
    fn cell_at(&self, x2: i64, y2: i64) -> Option<usize> {
        #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^41, exact in f64")]
        let (x, y) = (x2 as f64 / 2.0, y2 as f64 / 2.0);
        let i = self.xs.partition_point(|&l| l <= x).checked_sub(1)?;
        let j = self.ys.partition_point(|&l| l <= y).checked_sub(1)?;
        let ny = self.ys.len() - 1;
        if i >= self.xs.len() - 1 || j >= ny {
            return None;
        }
        self.cell[i * ny + j]
    }

    /// A filament between every two neighbouring cells, centre to centre,
    /// as wide as their shared face.
    fn filaments_into(
        &self,
        scale: f64,
        thickness: f64,
        sigma: f64,
        nodes: &[Vec3],
        set: &mut FilamentSet,
    ) {
        let (nx, ny) = (self.xs.len() - 1, self.ys.len() - 1);
        for i in 0..nx {
            for j in 0..ny {
                let Some(here) = self.cell[i * ny + j] else {
                    continue;
                };
                if let Some(right) = (i + 1 < nx).then(|| self.cell[(i + 1) * ny + j]).flatten() {
                    let width = (self.ys[j + 1] - self.ys[j]) * scale;
                    set.push(
                        nodes[here],
                        nodes[right],
                        width,
                        thickness,
                        sigma,
                        here,
                        right,
                    );
                }
                if let Some(up) = (j + 1 < ny).then(|| self.cell[i * ny + j + 1]).flatten() {
                    let width = (self.xs[i + 1] - self.xs[i]) * scale;
                    set.push(nodes[here], nodes[up], width, thickness, sigma, here, up);
                }
            }
        }
    }

    /// A port terminal: `node`, at the end `key` of rectangle `rect`'s
    /// centre line (doubled units), joined to every cell of the rectangle
    /// along that end's edge by a filament from the edge to the cell's
    /// centre, as wide as the cell: the edge is one equipotential contact,
    /// as a wire's end is.
    fn terminal_into(
        &self,
        rect: Bbox,
        key: NodeKey,
        node: usize,
        scale: f64,
        thickness: f64,
        sigma: f64,
        nodes: &[Vec3],
        set: &mut FilamentSet,
    ) {
        let line = Line::of(rect);
        let z = nodes[node].z;
        #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^41, exact in f64")]
        let edge = (if line.along_x { key.0 } else { key.1 }) as f64 / 2.0;
        #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
        let (xlo, xhi, ylo, yhi) = (
            rect.xlo.raw() as f64,
            rect.xhi.raw() as f64,
            rect.ylo.raw() as f64,
            rect.yhi.raw() as f64,
        );
        let ny = self.ys.len() - 1;
        for i in 0..self.xs.len() - 1 {
            for j in 0..ny {
                let Some(cell) = self.cell[i * ny + j] else {
                    continue;
                };
                let (cx, cy) = self.centres[cell - self.first];
                let in_rect = xlo < cx && cx < xhi && ylo < cy && cy < yhi;
                let (touches, width, from) = if line.along_x {
                    // Grid lines and edges are whole units: a quarter is equality.
                    let touches =
                        (self.xs[i] - edge).abs() < 0.25 || (self.xs[i + 1] - edge).abs() < 0.25;
                    (
                        touches,
                        self.ys[j + 1] - self.ys[j],
                        Vec3::new(edge * scale, cy * scale, z),
                    )
                } else {
                    let touches =
                        (self.ys[j] - edge).abs() < 0.25 || (self.ys[j + 1] - edge).abs() < 0.25;
                    (
                        touches,
                        self.xs[i + 1] - self.xs[i],
                        Vec3::new(cx * scale, edge * scale, z),
                    )
                };
                if in_rect && touches {
                    set.push(
                        from,
                        nodes[cell],
                        width * scale,
                        thickness,
                        sigma,
                        node,
                        cell,
                    );
                }
            }
        }
    }
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

/// The port impedance matrix at frequency `f`, row-major `n × n` for `n`
/// ports: `Z[q][p]` is the voltage across port `q` for a unit current into
/// port `p`, every other port open. Nodal solve `A Zb⁻¹ Aᵀ V = I` with one
/// ground node per galvanically connected component.
fn port_impedance_matrix(
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

    // Unit current into each port p; the voltage across every port q is Z[q][p].
    let n = ports.len();
    let mut z = vec![Complex64::new(0.0, 0.0); n * n];
    for (p, &(a, c)) in ports.iter().enumerate() {
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
        for (q, &(aq, cq)) in ports.iter().enumerate() {
            z[q * n + p] = volt(aq) - volt(cq);
        }
    }
    Ok(z)
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
