//! Panel meshing: conductor surfaces to boundary elements.
//!
//! Data in: selected nets' polygons (as extruded bounding boxes) and the stack.
//! Data out: a [`Mesh`] — panels banded by conductor, Morton-ordered within each
//! band. That order is the matvec's summation order, so it fixes output bits.

use gpurify_check::topology::{NetId, NetTable};
use gpurify_geom::{Bbox, GeometryStore, LayerId};
use gpurify_geom::{Dbu, Grid};
use gpurify_ingest::deck::ProcessStack;
use std::cmp::Ordering;

/// A flat rectangular boundary element.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Panel {
    /// Centroid, in metres.
    pub centre: [f64; 3],
    pub area: f64,
    /// Which conductor this panel belongs to.
    pub conductor: u32,
}

/// The meshed problem: panels in spatial order, banded by conductor.
#[derive(Debug, Default)]
pub struct Mesh {
    pub panel: Vec<Panel>,
    /// `panel[conductor_start[c] .. conductor_start[c + 1]]` is conductor `c`.
    pub conductor_start: Vec<u32>,
    pub conductor_net: Vec<NetId>,
    /// Relative permittivity above each panel.
    pub epsilon: Vec<f64>,
}

#[derive(Debug, Clone, Copy)]
pub struct MeshOptions {
    /// Largest panel edge, in database units.
    pub max_edge: Dbu,
    /// Halve the edge on solids within this distance of another conductor (0 = off).
    pub proximity_refine: Dbu,
    /// Refuse rather than mesh beyond this many panels.
    pub max_panels: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MeshError {
    #[error("mesh would exceed the panel limit")]
    TooManyPanels,
    #[error("layer {0:?} has no thickness in the process stack")]
    MissingThickness(LayerId),
    #[error("selected net has no geometry")]
    EmptyConductor,
}

/// Mesh the selected nets, one conductor per entry of `selected`, in that order.
pub fn build_into(
    store: &GeometryStore,
    nets: &NetTable,
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

    // Pass one: every selected polygon as a solid, so proximity refinement can
    // see every other conductor.
    let mut solid: Vec<Solid> = Vec::new();
    for (index, &net) in selected.iter().enumerate() {
        let conductor = u32::try_from(index).expect("a selection is indexed by a u32 conductor");
        let polys = nets.polys_of(net);
        if polys.is_empty() {
            return Err(MeshError::EmptyConductor);
        }
        // Refuse by the smallest layer id the stack does not describe (a layer
        // past the stack clamps onto the NaN sentinel row).
        let undescribed = polys
            .iter()
            .map(|&poly| store.poly_layer(poly))
            .filter(|layer| !(table[layer.idx().min(sentinel)].epsilon > 0.0))
            .min();
        if let Some(layer) = undescribed {
            return Err(MeshError::MissingThickness(layer));
        }
        for &poly in polys {
            let row = table[store.poly_layer(poly).idx().min(sentinel)];
            solid.push(Solid {
                bbox: store.poly_bbox(poly),
                z: row.z,
                epsilon: row.epsilon,
                conductor,
            });
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
            mesh_box(
                lo,
                hi,
                edge_here,
                conductor,
                here.epsilon,
                &mut remaining,
                &mut scratch,
            )?;
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

/// One conductor polygon as a solid: grid-unit footprint, z extent in metres.
#[derive(Debug, Clone, Copy)]
struct Solid {
    bbox: Bbox,
    z: [f64; 2],
    epsilon: f64,
    conductor: u32,
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

/// The six faces of a box: the axis each is normal to, and which end it sits at.
const FACES: [(usize, f64); 6] = [
    (0, -1.0),
    (0, 1.0),
    (1, -1.0),
    (1, 1.0),
    (2, -1.0),
    (2, 1.0),
];

/// Panels along one face edge of `width` at a limit of `edge`; at least one.
fn cuts(width: f64, edge: f64) -> u32 {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "positive; a saturated count is refused as TooManyPanels"
    )]
    let n = (width / edge).ceil() as u32;
    n.max(1)
}

/// Panel one box into `out`. The budget is charged per face before emitting,
/// so an over-limit mesh is refused, never half-built.
fn mesh_box(
    lo: [f64; 3],
    hi: [f64; 3],
    edge: f64,
    conductor: u32,
    epsilon: f64,
    remaining: &mut u32,
    out: &mut Vec<(Panel, f64)>,
) -> Result<(), MeshError> {
    for (axis, sign) in FACES {
        let (u, v) = ((axis + 1) % 3, (axis + 2) % 3);
        let (wu, wv) = (hi[u] - lo[u], hi[v] - lo[v]);
        // Degenerate (or NaN) faces carry no charge.
        if !(wu > 0.0 && wv > 0.0) {
            continue;
        }

        let (nu, nv) = (cuts(wu, edge), cuts(wv, edge));
        let panels = nu.checked_mul(nv).ok_or(MeshError::TooManyPanels)?;
        *remaining = remaining
            .checked_sub(panels)
            .ok_or(MeshError::TooManyPanels)?;

        let (du, dv) = (wu / f64::from(nu), wv / f64::from(nv));
        let area = du * dv;
        let plane = (lo[axis] + hi[axis]).mul_add(0.5, sign * (hi[axis] - lo[axis]) * 0.5);

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
    use super::{morton3, quantise, spread3, MORTON_BITS, MORTON_MAX, MORTON_SPAN};

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
