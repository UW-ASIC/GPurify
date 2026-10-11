//! Panel meshing: conductor surfaces to boundary elements.
//!
//! Data in: selected nets' polygons, cut into the disjoint rectangles
//! [`decompose_into`] gives and extruded through the stack. A rectangle's side
//! face is meshed only where no rectangle of the same conductor on the same
//! layer abuts it, so no panel sits inside metal.
//! Data out: a [`Mesh`] — panels banded by conductor, Morton-ordered within each
//! band. That order is the matvec's summation order, so it fixes output bits.

use gpurify_check::topology::{NetId, NetTable};
use gpurify_geom::rects::decompose_into;
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::{Bbox, GeometryStore, LayerId, PolyId};
use gpurify_geom::{Dbu, Grid};
use gpurify_ingest::deck::{Connectivity, ProcessStack};
use std::cmp::Ordering;
use std::collections::BTreeMap;

/// A flat rectangular boundary element.
///
/// Its face is axis-aligned: a top or bottom face of a layer's extrusion, or
/// a side face where no rectangle of the same conductor and layer abuts it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Panel {
    /// Centroid, in metres.
    pub centre: [f64; 3],
    /// Area, in square metres.
    pub area: f64,
    /// Which conductor this panel belongs to.
    pub conductor: u32,
}

/// The meshed problem: panels in spatial order, banded by conductor.
#[derive(Debug, Default)]
pub struct Mesh {
    /// Every panel, conductor by conductor, Morton-ordered within each band.
    /// The order is the matvec's summation order, so it fixes the output bits.
    pub panel: Vec<Panel>,
    /// `panel[conductor_start[c] .. conductor_start[c + 1]]` is conductor `c`.
    pub conductor_start: Vec<u32>,
    /// The net of each conductor, in the order it was selected.
    pub conductor_net: Vec<NetId>,
    /// Relative permittivity above each panel.
    pub epsilon: Vec<f64>,
}

/// How finely to mesh, and when to refuse.
#[derive(Debug, Clone, Copy)]
pub struct MeshOptions {
    /// Largest panel edge, in database units.
    pub max_edge: Dbu,
    /// Halve the edge on solids within this distance of another conductor (0 = off).
    pub proximity_refine: Dbu,
    /// Refuse rather than mesh beyond this many panels.
    pub max_panels: u32,
}

/// Why a selection could not be meshed. Each is a refusal, and the `out`
/// buffer holds no usable mesh after one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MeshError {
    /// The panels would exceed [`MeshOptions::max_panels`].
    #[error("mesh would exceed the panel limit")]
    TooManyPanels,
    /// A selected polygon is on a layer the stack does not describe: no row,
    /// or a row whose thickness or permittivity is not positive or whose
    /// height is not finite. The smallest such layer id is named.
    #[error(
        "no pex row gives this layer a positive thickness and permittivity, so it cannot be meshed"
    )]
    MissingThickness(LayerId),
    /// A selected net has no polygons.
    #[error("selected net has no geometry")]
    EmptyConductor,
    /// The layer's polygons fail validation as rectilinear geometry, so they
    /// cannot be cut into rectangles exactly.
    #[error("not valid rectilinear geometry, so it cannot be meshed exactly")]
    InvalidGeometry(LayerId),
}

impl MeshError {
    /// The layer the refusal names, which its message leaves to the caller
    /// to name as the deck does; `None` for a refusal about no one layer.
    pub fn layer(self) -> Option<LayerId> {
        match self {
            Self::MissingThickness(layer) | Self::InvalidGeometry(layer) => Some(layer),
            Self::TooManyPanels | Self::EmptyConductor => None,
        }
    }
}

/// Whether the stack puts `layer` on the substrate, at height 0 or below: a
/// well or a diffusion. Such a shape is a junction in the substrate, whose
/// capacitance to it is a depletion capacitance, not an electrostatic one,
/// so the mesh leaves it out and the solve adds its closed form
/// ([`super::extract_into`]).
pub(crate) fn on_substrate(stack: &ProcessStack, layer: LayerId) -> bool {
    stack
        .height_nm
        .get(layer.idx())
        .is_some_and(|&height| !(height > 0.0))
}

/// Whether `layer`'s shapes are conductors in the field: neither a junction
/// ([`on_substrate`]) nor a global layer ([`Connectivity::global`], the
/// substrate as a net, which carries no modelled parasitics and needs no
/// `pex` row).
pub(crate) fn in_field(stack: &ProcessStack, connectivity: &Connectivity, layer: LayerId) -> bool {
    !on_substrate(stack, layer) && !connectivity.global.contains(&layer)
}

/// Mesh the selected nets, one conductor per entry of `selected`, in that order.
///
/// `out` is cleared first. Each polygon is cut into disjoint rectangles,
/// extruded from its layer's height through its thickness, and each face is
/// cut into panels no longer than `options.max_edge` on a side (half that
/// near another conductor). A polygon on a layer the stack puts on the
/// substrate (height 0) is a junction and gets no panels, and so does one on
/// a global layer (`connectivity.global`), which needs no stack row; a
/// conductor made only of such polygons has an empty band.
///
/// # Errors
///
/// Every [`MeshError`]: checked net by net in selection order, and the panel
/// budget face by face, so an over-limit mesh is refused, never truncated.
///
/// # Time complexity
///
/// *O*(P log P) in the panels, for the sort, plus a check of every rectangle
/// against every other for proximity refinement, quadratic in the
/// selection's rectangles.
pub fn build_into(
    store: &GeometryStore,
    nets: &NetTable,
    connectivity: &Connectivity,
    selected: &[NetId],
    stack: &ProcessStack,
    options: MeshOptions,
    grid: Grid,
    out: &mut Mesh,
) -> Result<(), MeshError> {
    out.panel.clear();
    out.conductor_start.clear();
    out.conductor_net.clear();
    out.epsilon.clear();

    // One database unit, in metres.
    #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
    let metre = 1e-6 / grid.dbu_per_um() as f64;
    #[expect(
        clippy::cast_precision_loss,
        reason = "|max_edge| <= 2^40, exact in f64"
    )]
    let edge = options.max_edge.raw() as f64 * metre;

    let table = extrusion_table(stack);
    let sentinel = table.len() - 1;

    // Pass one: every selected polygon's rectangles as solids, so proximity
    // refinement can see every other conductor.
    let mut solid: Vec<Solid> = Vec::new();
    let mut rects = Rects::default();
    for (index, &net) in selected.iter().enumerate() {
        let conductor = u32::try_from(index).expect("a selection is indexed by a u32 conductor");
        let polys = nets.polys_of(net);
        if polys.is_empty() {
            return Err(MeshError::EmptyConductor);
        }
        // Refuse by the smallest layer id the stack does not describe (a layer
        // past the stack clamps onto the NaN sentinel row). A global layer
        // needs no row.
        let undescribed = polys
            .iter()
            .map(|&poly| store.poly_layer(poly))
            .filter(|layer| !connectivity.global.contains(layer))
            .filter(|layer| !(table[layer.idx().min(sentinel)].epsilon > 0.0))
            .min();
        if let Some(layer) = undescribed {
            return Err(MeshError::MissingThickness(layer));
        }
        for &poly in polys {
            let layer = store.poly_layer(poly);
            if !in_field(stack, connectivity, layer) {
                continue;
            }
            let row = table[layer.idx().min(sentinel)];
            for &bbox in rects.of(store, layer, poly)? {
                solid.push(Solid {
                    bbox,
                    z: row.z,
                    epsilon: row.epsilon,
                    conductor,
                    layer,
                });
            }
        }
    }

    // Every side face, by the plane it lies in, so an abutting rectangle of
    // the same conductor and layer can be cut out of its neighbour's face.
    let mut faces: BTreeMap<FaceKey, Vec<(i64, i64)>> = BTreeMap::new();
    for here in &solid {
        let b = here.bbox;
        for (axis, low, at, span) in side_faces(b) {
            faces
                .entry((here.conductor, here.layer, axis, low, at))
                .or_default()
                .push(span);
        }
    }

    // Pass two: each solid's six faces, cut at the edge limit.
    let mut scratch: Vec<(Panel, f64)> = Vec::new();
    let mut remaining = options.max_panels;
    out.conductor_start.push(0);
    out.conductor_net.extend_from_slice(selected);

    // Solids were pushed in conductor order, so each band is one run.
    let mut band_start = 0;
    for index in 0..selected.len() {
        let conductor = u32::try_from(index).expect("a selection is indexed by a u32 conductor");
        let band_end = band_start
            + solid[band_start..]
                .iter()
                .take_while(|s| s.conductor == conductor)
                .count();
        for &here in &solid[band_start..band_end] {
            #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
            let lo = [
                here.bbox.xlo.raw() as f64 * metre,
                here.bbox.ylo.raw() as f64 * metre,
                here.z[0],
            ];
            #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
            let hi = [
                here.bbox.xhi.raw() as f64 * metre,
                here.bbox.yhi.raw() as f64 * metre,
                here.z[1],
            ];
            let near = near_another_conductor(&solid, here, options.proximity_refine);
            let edge_here = edge / f64::from(1 + u8::from(near));
            for (axis, sign) in [(2, -1.0), (2, 1.0)] {
                let plane = if sign < 0.0 { lo[axis] } else { hi[axis] };
                mesh_face(
                    axis,
                    plane,
                    lo,
                    hi,
                    edge_here,
                    conductor,
                    here.epsilon,
                    &mut remaining,
                    &mut scratch,
                )?;
            }
            for (axis, low, at, span) in side_faces(here.bbox) {
                let covering = faces
                    .get(&(here.conductor, here.layer, axis, !low, at))
                    .map_or(&[][..], Vec::as_slice);
                // The face runs along the other planar axis.
                let along = 1 - axis;
                let plane = if low { lo[axis] } else { hi[axis] };
                for (from, to) in uncovered(span, covering) {
                    let (mut piece_lo, mut piece_hi) = (lo, hi);
                    #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
                    {
                        piece_lo[along] = from as f64 * metre;
                        piece_hi[along] = to as f64 * metre;
                    }
                    mesh_face(
                        axis,
                        plane,
                        piece_lo,
                        piece_hi,
                        edge_here,
                        conductor,
                        here.epsilon,
                        &mut remaining,
                        &mut scratch,
                    )?;
                }
            }
        }
        band_start = band_end;
        out.conductor_start
            .push(u32::try_from(scratch.len()).expect("the panel count is bounded by max_panels"));
    }

    // Morton order within each band (not across: bands stay contiguous), exact
    // centroid as the tiebreak.
    let key = morton_keys(&scratch);
    let mut order: Vec<u32> = (0..u32::try_from(scratch.len())
        .expect("the panel count is bounded by max_panels"))
        .collect();
    for band in out.conductor_start.windows(2) {
        let (from, to) = (band[0] as usize, band[1] as usize);
        order[from..to].sort_by(|&a, &b| {
            key[a as usize]
                .cmp(&key[b as usize])
                .then_with(|| spatial_cmp(scratch[a as usize].0, scratch[b as usize].0))
        });
    }

    for &row in &order {
        let (panel, epsilon) = scratch[row as usize];
        out.panel.push(panel);
        out.epsilon.push(epsilon);
    }
    Ok(())
}

/// One rectangle of a conductor polygon as a solid: grid-unit footprint, z
/// extent in metres.
#[derive(Debug, Clone, Copy)]
struct Solid {
    bbox: Bbox,
    z: [f64; 2],
    epsilon: f64,
    conductor: u32,
    layer: LayerId,
}

/// A side face's plane: conductor, layer, normal axis, low side, coordinate.
type FaceKey = (u32, LayerId, usize, bool, i64);

/// Each layer's polygons cut into rectangles, decomposed on first use.
#[derive(Default)]
struct Rects {
    /// By outer ring's row; a hole row maps to nothing (its outer carries it).
    of_poly: BTreeMap<PolyId, Vec<Bbox>>,
    done: Vec<LayerId>,
}

impl Rects {
    fn of(
        &mut self,
        store: &GeometryStore,
        layer: LayerId,
        poly: PolyId,
    ) -> Result<&[Bbox], MeshError> {
        if !self.done.contains(&layer) {
            self.done.push(layer);
            let mut valid = ValidatedLayer::default();
            validate_layer_into(store, layer, &mut valid)
                .map_err(|_| MeshError::InvalidGeometry(layer))?;
            let (mut rects, mut start) = (Vec::new(), Vec::new());
            decompose_into(&valid, &mut rects, &mut start);
            for i in 0..valid.len() {
                let polygon = valid.get(u32::try_from(i).expect("a polygon index is a u32"));
                let mut rows = polygon.rows();
                let outer = rows.next().expect("a polygon has an outer ring");
                self.of_poly.insert(
                    outer,
                    rects[start[i] as usize..start[i + 1] as usize].to_vec(),
                );
                for hole in rows {
                    self.of_poly.insert(hole, Vec::new());
                }
            }
        }
        Ok(self.of_poly.get(&poly).map_or(&[][..], Vec::as_slice))
    }
}

/// A rectangle's four side faces: `(normal axis, low side?, plane, span along
/// the other planar axis)`, in grid units.
fn side_faces(b: Bbox) -> [(usize, bool, i64, (i64, i64)); 4] {
    let (x, y) = ((b.xlo.raw(), b.xhi.raw()), (b.ylo.raw(), b.yhi.raw()));
    [
        (0, true, x.0, y),
        (0, false, x.1, y),
        (1, true, y.0, x),
        (1, false, y.1, x),
    ]
}

/// What of `span` no interval of `covering` covers, ascending.
fn uncovered(span: (i64, i64), covering: &[(i64, i64)]) -> Vec<(i64, i64)> {
    let mut cuts: Vec<(i64, i64)> = covering
        .iter()
        .map(|&(a, b)| (a.max(span.0), b.min(span.1)))
        .filter(|&(a, b)| a < b)
        .collect();
    cuts.sort_unstable();
    let mut out = Vec::new();
    let mut at = span.0;
    for (a, b) in cuts {
        if a > at {
            out.push((at, a));
        }
        at = at.max(b);
    }
    if at < span.1 {
        out.push((at, span.1));
    }
    out
}

/// One layer's z extent in metres and the permittivity above it.
#[derive(Debug, Clone, Copy)]
struct Extrusion {
    z: [f64; 2],
    /// Not positive exactly when the stack does not describe the layer.
    epsilon: f64,
}

/// An undescribed layer: NaN fails every `epsilon > 0.0` test.
const UNDESCRIBED: Extrusion = Extrusion {
    z: [f64::NAN; 2],
    epsilon: f64::NAN,
};

/// Every stack row as an [`Extrusion`], plus a trailing [`UNDESCRIBED`] sentinel
/// for any layer past the stack.
fn extrusion_table(stack: &ProcessStack) -> Vec<Extrusion> {
    let rows = stack
        .thickness_nm
        .len()
        .min(stack.height_nm.len())
        .min(stack.dielectric_k.len());
    let mut out: Vec<Extrusion> = (0..rows)
        .map(|row| {
            let thickness = stack.thickness_nm[row];
            let height = stack.height_nm[row];
            let epsilon = stack.dielectric_k[row];
            if !(thickness > 0.0) || !height.is_finite() || !(epsilon > 0.0) {
                return UNDESCRIBED;
            }
            Extrusion {
                z: [height * 1e-9, (height + thickness) * 1e-9],
                epsilon,
            }
        })
        .collect();
    out.push(UNDESCRIBED);
    out
}

/// Whether a solid sits within `distance` of a conductor other than its own.
// ponytail: O(n²) over the selection's polygons; a spatial index if selections grow large.
fn near_another_conductor(solid: &[Solid], of: Solid, distance: Dbu) -> bool {
    if distance.raw() == 0 {
        return false;
    }
    solid
        .iter()
        .any(|other| other.conductor != of.conductor && of.bbox.within(other.bbox, distance))
}

/// Panels along one face edge of `width` at a limit of `edge`; at least one.
///
/// A width within a millionth of an edge above a whole number of edges takes
/// that number. `width` is a difference of absolute coordinates in metres, so
/// an exact multiple can come out a few ulps over and gain a panel at one
/// position but not another: moving a layout changed its capacitance
/// (testing-plan F46).
fn cuts(width: f64, edge: f64) -> u32 {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "positive; a saturated count is refused as TooManyPanels"
    )]
    let n = (width / edge - 1e-6).ceil() as u32;
    n.max(1)
}

/// Panel one box into `out`. The budget is charged per face before emitting,
/// so an over-limit mesh is refused, never half-built.
fn mesh_face(
    axis: usize,
    plane: f64,
    lo: [f64; 3],
    hi: [f64; 3],
    edge: f64,
    conductor: u32,
    epsilon: f64,
    remaining: &mut u32,
    out: &mut Vec<(Panel, f64)>,
) -> Result<(), MeshError> {
    let (u, v) = ((axis + 1) % 3, (axis + 2) % 3);
    let (wu, wv) = (hi[u] - lo[u], hi[v] - lo[v]);
    // Degenerate (or NaN) faces carry no charge.
    if !(wu > 0.0 && wv > 0.0) {
        return Ok(());
    }

    let (nu, nv) = (cuts(wu, edge), cuts(wv, edge));
    let panels = nu.checked_mul(nv).ok_or(MeshError::TooManyPanels)?;
    *remaining = remaining
        .checked_sub(panels)
        .ok_or(MeshError::TooManyPanels)?;

    let (du, dv) = (wu / f64::from(nu), wv / f64::from(nv));
    let area = du * dv;
    for iu in 0..nu {
        for iv in 0..nv {
            let mut centre = [0.0; 3];
            centre[axis] = plane;
            centre[u] = (f64::from(iu) + 0.5).mul_add(du, lo[u]);
            centre[v] = (f64::from(iv) + 0.5).mul_add(dv, lo[v]);
            out.push((
                Panel {
                    centre,
                    area,
                    conductor,
                },
                epsilon,
            ));
        }
    }
    Ok(())
}

/// Bits per axis in a Morton key.
const MORTON_BITS: u32 = 21;
const MORTON_MAX: u64 = (1 << MORTON_BITS) - 1;
/// [`MORTON_MAX`] as `f64` (exact).
const MORTON_SPAN: f64 = 2_097_151.0;
const _: () = assert!(MORTON_MAX == 2_097_151, "MORTON_SPAN is not MORTON_MAX");

/// A Morton key per panel, quantised against the panels' own bounds.
fn morton_keys(panel: &[(Panel, f64)]) -> Vec<u64> {
    let mut lo = [f64::INFINITY; 3];
    let mut hi = [f64::NEG_INFINITY; 3];
    for &(p, _) in panel {
        for axis in 0..3 {
            lo[axis] = lo[axis].min(p.centre[axis]);
            hi[axis] = hi[axis].max(p.centre[axis]);
        }
    }
    // A degenerate axis collapses to one cell rather than dividing by zero.
    let scale: [f64; 3] = std::array::from_fn(|axis| {
        let span = hi[axis] - lo[axis];
        if span > 0.0 {
            MORTON_SPAN / span
        } else {
            0.0
        }
    });
    panel
        .iter()
        .map(|&(p, _)| {
            morton3(
                quantise(p.centre[0], lo[0], scale[0]),
                quantise(p.centre[1], lo[1], scale[1]),
                quantise(p.centre[2], lo[2], scale[2]),
            )
        })
        .collect()
}

/// One coordinate as a `MORTON_BITS`-wide integer; the cast saturates and maps
/// NaN to zero, so the key is total.
fn quantise(value: f64, lo: f64, scale: f64) -> u64 {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "saturating cast, NaN to zero"
    )]
    let raw = ((value - lo) * scale) as u64;
    raw.min(MORTON_MAX)
}

/// Interleave three `MORTON_BITS`-wide integers, `x` in the low bit of each triple.
const fn morton3(x: u64, y: u64, z: u64) -> u64 {
    spread3(x) | spread3(y) << 1 | spread3(z) << 2
}

/// Spread the low `MORTON_BITS` of `v` so bit `i` lands at bit `3 * i`.
const fn spread3(v: u64) -> u64 {
    let mut x = v & MORTON_MAX;
    x = (x | x << 32) & 0x001f_0000_0000_ffff;
    x = (x | x << 16) & 0x001f_0000_ff00_00ff;
    x = (x | x << 8) & 0x100f_00f0_0f00_f00f;
    x = (x | x << 4) & 0x10c3_0c30_c30c_30c3;
    x = (x | x << 2) & 0x1249_2492_4924_9249;
    x
}

/// Tiebreak under the Morton key: z, y, x by `total_cmp`.
fn spatial_cmp(a: Panel, b: Panel) -> Ordering {
    a.centre[2]
        .total_cmp(&b.centre[2])
        .then_with(|| a.centre[1].total_cmp(&b.centre[1]))
        .then_with(|| a.centre[0].total_cmp(&b.centre[0]))
}

#[cfg(test)]
mod tests {
    use super::{morton3, quantise, spread3, uncovered, MORTON_BITS, MORTON_MAX, MORTON_SPAN};

    #[test]
    fn uncovered_is_the_span_less_every_cover() {
        assert_eq!(uncovered((0, 10), &[]), [(0, 10)]);
        assert_eq!(
            uncovered((0, 10), &[(2, 4), (3, 6), (9, 20)]),
            [(0, 2), (6, 9)]
        );
        assert_eq!(uncovered((0, 10), &[(-5, 15)]), []);
    }

    /// An L whose bounding box swallows a second conductor in its notch: the
    /// L's panels must stay on the L, and its footprint must be its area,
    /// not its box's. Meshing boxes put the L's top face over the square.
    #[test]
    fn a_concave_conductor_is_meshed_as_drawn_not_as_its_box() {
        use gpurify_check::topology::{net::extract_nets_into, NetId, NetTable};
        use gpurify_geom::{Dbu, GeometryStoreBuilder, Grid, LayerId};
        use gpurify_ingest::deck::{Connectivity, ProcessStack};

        let d = Dbu::new_unchecked;
        let mut builder = GeometryStoreBuilder::default();
        let l = [
            (0, 0),
            (1000, 0),
            (1000, 400),
            (400, 400),
            (400, 1000),
            (0, 1000),
        ];
        let (xs, ys): (Vec<Dbu>, Vec<Dbu>) = l.iter().map(|&(x, y)| (d(x), d(y))).unzip();
        builder.push(LayerId(0), &xs, &ys);
        let square = [(600, 600), (900, 600), (900, 900), (600, 900)];
        let (xs, ys): (Vec<Dbu>, Vec<Dbu>) = square.iter().map(|&(x, y)| (d(x), d(y))).unzip();
        builder.push(LayerId(0), &xs, &ys);
        let (store, _) = builder.finish(1);
        let connectivity = Connectivity {
            conductors: vec![LayerId(0)],
            intra_layer_touch: true,
            ..Connectivity::default()
        };
        let mut nets = NetTable::default();
        extract_nets_into(&store, &connectivity, &mut nets);
        let stack = ProcessStack {
            thickness_nm: vec![100.0],
            height_nm: vec![1000.0],
            sheet_res_ohm_sq: vec![0.1],
            area_cap_af_um2: vec![1.0],
            fringe_cap_af_um: vec![1.0],
            dielectric_k: vec![4.0],
        };
        let options = super::MeshOptions {
            max_edge: d(50),
            proximity_refine: d(0),
            max_panels: 1_000_000,
        };
        let mut mesh = super::Mesh::default();
        let grid = Grid::new(1000).expect("a 1 nm grid");
        super::build_into(
            &store,
            &nets,
            &connectivity,
            &[NetId(0), NetId(1)],
            &stack,
            options,
            grid,
            &mut mesh,
        )
        .expect("meshable");
        let l_net = nets.net_of(gpurify_geom::PolyId(0));
        let l = u32::from(l_net != NetId(0));
        let (mut top, mut inside) = (0.0, 0);
        for p in mesh.panel.iter().filter(|p| p.conductor == l) {
            let (x, y) = (p.centre[0] * 1e9, p.centre[1] * 1e9);
            if x > 600.0 && x < 900.0 && y > 600.0 && y < 900.0 {
                inside += 1;
            }
            if (p.centre[2] - 1.1e-6).abs() < 1e-12 {
                top += p.area;
            }
        }
        assert_eq!(inside, 0, "the L has panels over the square");
        let l_area = 1000.0 * 400.0 + 400.0 * 600.0;
        assert!(
            (top * 1e18 - l_area).abs() < 1e-3,
            "top face {} nm², L {l_area} nm²",
            top * 1e18
        );
    }

    #[test]
    fn spreading_moves_bit_i_to_bit_three_i() {
        for i in 0..MORTON_BITS {
            assert_eq!(spread3(1 << i), 1 << (3 * i), "bit {i}");
        }
        assert_eq!(spread3(0), 0);
        assert_eq!(spread3(MORTON_MAX).count_ones(), MORTON_BITS);
        assert_eq!(
            spread3(MORTON_MAX | 1 << MORTON_BITS),
            spread3(MORTON_MAX),
            "a bit above the axis width is masked off"
        );
    }

    #[test]
    fn a_key_keeps_all_three_axes_in_disjoint_bits() {
        let (x, y, z) = (0b1011, 0b0110, 0b1101);
        let key = morton3(x, y, z);
        let gather = |shift: u32| {
            (0..MORTON_BITS).fold(0_u64, |bits, i| bits | (key >> (3 * i + shift) & 1) << i)
        };
        assert_eq!(gather(0), x);
        assert_eq!(gather(1), y);
        assert_eq!(gather(2), z);
        assert_eq!(morton3(0, 0, 0), 0);
        assert_eq!(
            morton3(MORTON_MAX, MORTON_MAX, MORTON_MAX).count_ones(),
            3 * MORTON_BITS
        );
    }

    #[test]
    fn quantising_is_monotone_and_total() {
        let scale = MORTON_SPAN / 4.0;
        assert_eq!(quantise(0.0, 0.0, scale), 0);
        assert_eq!(quantise(4.0, 0.0, scale), MORTON_MAX);
        assert_eq!(quantise(1.0, 0.0, scale), MORTON_MAX / 4);
        assert!(quantise(1.0, 0.0, scale) < quantise(2.0, 0.0, scale));
        assert_eq!(quantise(-1.0, 0.0, scale), 0);
        assert_eq!(quantise(9.0, 0.0, scale), MORTON_MAX);
        assert_eq!(quantise(f64::NAN, 0.0, scale), 0);
        assert_eq!(quantise(f64::INFINITY, 0.0, scale), MORTON_MAX);
        assert_eq!(quantise(7.0, 0.0, 0.0), 0);
    }
}
