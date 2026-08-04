//! Panel meshing: conductor surfaces to boundary elements.
//!
//! The mesh is the whole input to the solve, so its quality bounds the answer's
//! accuracy and its size bounds the cost. Both are decided here, and both are
//! reported rather than left implicit.

use gpurify_core::{Bbox, GeometryStore, LayerId};
use gpurify_ingest::deck::ProcessStack;
use gpurify_topology::{NetId, NetTable};
use gpurify_units::{Dbu, Grid};
use std::cmp::Ordering;

/// A flat rectangular boundary element.
///
/// `AoS`: the matvec reads every field of a panel together when evaluating an
/// influence, and panels are stored in spatial tree order so that read is
/// contiguous. This is one of the few places in the tree where `AoS` wins, and it
/// wins because of the access pattern, not by default.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Panel {
    /// Centroid, in metres. The solve works in SI, not in grid units — the
    /// conversion happens once, here, against the run's grid.
    pub centre: [f64; 3],
    /// Outward normal, unit length.
    pub normal: [f64; 3],
    pub area: f64,
    /// Which conductor this panel belongs to. Charge is integrated per
    /// conductor to give a matrix column.
    pub conductor: u32,
}

/// The meshed problem.
///
/// **Five questions.** In: geometry for the selected nets and the layer stack.
/// Out: panels in spatial order, plus the conductor each belongs to. How many:
/// thousands to hundreds of thousands. Access pattern: sequential in tree
/// order, every field together. Lifetime: one solve. Parallelisable: meshing
/// per conductor is; the spatial sort at the end is what makes panel order
/// canonical.
#[derive(Debug, Default)]
pub struct Mesh {
    pub panel: Vec<Panel>,
    /// `panel[conductor_start[c] .. conductor_start[c + 1]]` belongs to
    /// conductor `c`, after the canonical sort.
    pub conductor_start: Vec<u32>,
    pub conductor_net: Vec<NetId>,
    /// Relative permittivity above each panel. Layered dielectrics change the
    /// Green's function, so this travels with the mesh.
    pub epsilon: Vec<f64>,
}

/// How finely to mesh.
#[derive(Debug, Clone, Copy)]
pub struct MeshOptions {
    /// Largest panel edge, in database units. The accuracy knob.
    pub max_edge: Dbu,
    /// Refine panels within this distance of another conductor, where the field
    /// varies fastest and a uniform mesh is worst.
    pub proximity_refine: Dbu,
    /// Refuse rather than mesh beyond this many panels. A solve that would take
    /// a week should say so, not start.
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

/// Mesh the selected nets.
///
/// **Transform, A-to-B.** Caller owns `out`. Panels are emitted per conductor
/// in ascending [`NetId`] order and then sorted into spatial tree order by a
/// key derived only from position, so the mesh is a deterministic function of
/// the geometry — no thread count, no insertion order.
///
/// # The two inputs added in the Testing-Phase
///
/// As frozen this took neither `stack` nor `grid`, and so could produce neither
/// of the two things it promises. `stack` is where a layer's `thickness_nm` and
/// `height_nm` come from — a `GeometryStore` is two-dimensional, so without them
/// there is no z extent to panel and no way to raise
/// [`MeshError::MissingThickness`] — and it is the only source of the
/// `dielectric_k` that fills [`Mesh::epsilon`]. `grid` is what turns `Dbu` into
/// the metres [`Panel::centre`] and [`Panel::area`] are documented to be in.
pub fn build_into(
    store: &GeometryStore,
    nets: &NetTable,
    selected: &[NetId],
    stack: &ProcessStack,
    options: MeshOptions,
    grid: Grid,
    out: &mut Mesh,
) -> Result<(), MeshError> {
    debug_assert!(
        options.max_edge.raw() > 0,
        "a panel edge limit of zero cuts a face into no panels"
    );
    // Hoisted out of `near_another_conductor`'s inner loop: `Bbox::within`
    // debug-asserts this itself, and a panic edge inside an O(n^2) loop body is
    // both a branch and a barrier to vectorisation.
    debug_assert!(
        options.proximity_refine.raw() >= 0,
        "a refinement distance is non-negative"
    );
    debug_assert!(grid.dbu_per_um() > 0, "a Grid is positive by construction");

    out.panel.clear();
    out.conductor_start.clear();
    out.conductor_net.clear();
    out.epsilon.clear();

    // One database unit, in metres. `Grid::to_length` hands back nanometres and
    // the solve works in SI, so the scale is applied once, here.
    #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
    let metre = 1e-6 / grid.dbu_per_um() as f64;
    #[expect(
        clippy::cast_precision_loss,
        reason = "|max_edge| <= 2^40, exact in f64"
    )]
    let edge = options.max_edge.raw() as f64 * metre;

    // Extruding a layer is a function of the layer alone, so it is a uniform:
    // evaluated once per layer of the stack, above the polygon loops, rather
    // than once per polygon inside them. That is also what turns the per-polygon
    // step below from a fallible map into a plain gather plus one branchless
    // fold.
    let mut extrusion: Vec<Extrusion> = Vec::new();
    extrusion_table(stack, &mut extrusion);
    let table = &extrusion[..];
    let sentinel = table.len() - 1;
    debug_assert!(
        !(table[sentinel].epsilon > 0.0),
        "the sentinel row must fail the same test an undescribed layer does"
    );

    // Pass one: every selected conductor's polygons as solids. Separate from
    // the meshing pass because proximity refinement asks a solid about every
    // *other* conductor, which is not a question the first solid can answer.
    let mut solid: Vec<Solid> = Vec::new();
    for (index, &net) in selected.iter().enumerate() {
        let conductor = u32::try_from(index).expect("a selection is indexed by a u32 conductor");
        let polys = nets.polys_of(net);
        // Fail closed: a selected net with no geometry would otherwise leave an
        // empty band, and an empty band reads as "this conductor stores no
        // charge" rather than "this conductor was never meshed".
        if polys.is_empty() {
            return Err(MeshError::EmptyConductor);
        }

        // The smallest layer id in this conductor that the process stack does
        // not describe, or `u32::MAX` when it describes them all. Checked as its
        // own fold rather than inside the emit below, so the fault is named
        // before a single solid is written and the emit carries no branch.
        let mut undescribed = u32::MAX;
        for &poly in polys {
            let layer = store.poly_layer(poly);
            // Clamped gather, not a bounds branch — `/branchless`'s
            // `i = min(i, n - 1)`. A layer past the stack lands on the sentinel
            // row, which fails `epsilon > 0` exactly as a malformed row does.
            let described = table[layer.idx().min(sentinel)].epsilon > 0.0;
            // All ones when the layer is described, so `|` lifts it above every
            // real layer id and the fold stays a `min`.
            undescribed =
                undescribed.min(u32::from(layer.0) | 0u32.wrapping_sub(u32::from(described)));
        }
        // Fail closed: a `GeometryStore` is two-dimensional, so a layer the
        // stack does not describe has no z extent to panel and no permittivity
        // to carry, and a conductor meshed as a sheet holds charge on no side.
        if undescribed != u32::MAX {
            let layer = u16::try_from(undescribed).expect("the id came from a LayerId");
            return Err(MeshError::MissingThickness(LayerId(layer)));
        }

        // Appended straight to `solid`: the scratch band this used to map into
        // existed only because a map's destination is cleared before it is
        // filled. One reserve, one pass, no copy.
        let before = solid.len();
        solid.reserve(polys.len());
        for &poly in polys {
            let row = table[store.poly_layer(poly).idx().min(sentinel)];
            solid.push(Solid {
                bbox: store.poly_bbox(poly),
                z: row.z,
                epsilon: row.epsilon,
                conductor,
            });
        }
        debug_assert_eq!(solid.len(), before + polys.len(), "one solid per polygon");
    }
    debug_assert!(
        {
            // `&=` and not `iter().all`: `solid` is one row per polygon of the
            // selected nets, so this is a bulk loop like any other and `all`'s
            // early exit is the data-dependent branch the discipline removes.
            // Same shape as the entry assert in `matvec::CpuMatVec::build`.
            let mut ok = true;
            for s in &solid {
                ok &= s.epsilon > 0.0;
            }
            ok
        },
        "every solid carries a described layer's permittivity"
    );

    // Pass two: each solid's six faces, cut at the edge limit.
    let mut scratch: Vec<(Panel, f64)> = Vec::new();
    let mut remaining = options.max_panels;
    out.conductor_start.push(0);
    out.conductor_net.extend_from_slice(selected);

    let mut next = 0;
    for index in 0..selected.len() {
        let conductor = u32::try_from(index).expect("a selection is indexed by a u32 conductor");
        // The solids were pushed in conductor order, so one band is one run.
        // The compare is a loop bound, not a body branch: it fails once per
        // conductor, which is tens of times per run.
        while next < solid.len() && solid[next].conductor == conductor {
            let here = solid[next];
            let lo = [
                #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
                (here.bbox.xlo.raw() as f64 * metre),
                #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
                (here.bbox.ylo.raw() as f64 * metre),
                here.z[0],
            ];
            let hi = [
                #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
                (here.bbox.xhi.raw() as f64 * metre),
                #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
                (here.bbox.yhi.raw() as f64 * metre),
                here.z[1],
            ];
            // Halving is the refinement: the field varies fastest beside another
            // conductor, so a panel there gets half the edge and a quarter the
            // area. Branchless — the predicate is the divisor.
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
            next += 1;
        }
        out.conductor_start
            .push(u32::try_from(scratch.len()).expect("the panel count is bounded by max_panels"));
    }
    debug_assert_eq!(next, solid.len(), "a solid belongs to no conductor");

    // Spatial order, within each band and not across them: the CSR says a
    // conductor's panels are contiguous, so a global sort would be a different
    // interface. The key is a Morton code of the centroid against the mesh's own
    // centroid bounds, so the order is a function of the geometry — no thread
    // count, no insertion order — and panels adjacent in the column are adjacent
    // in all three axes at once, which is the locality the matvec's near-field
    // blocking reads.
    let mut key: Vec<u64> = Vec::new();
    morton_keys(&scratch, &mut key);
    debug_assert_eq!(key.len(), scratch.len(), "one sort key per panel");

    let mut order: Vec<u32> =
        (0..u32::try_from(scratch.len()).expect("the panel count is bounded by max_panels")).collect();
    for band in out.conductor_start.windows(2) {
        let (from, to) = (band[0] as usize, band[1] as usize);
        debug_assert!(from <= to && to <= scratch.len(), "a CSR band runs backwards");
        // The exact centroid is the tiebreak, so two panels quantised into the
        // same cell of the key still order by position and by nothing else.
        order[from..to].sort_by(|&a, &b| {
            key[a as usize]
                .cmp(&key[b as usize])
                .then_with(|| spatial_cmp(scratch[a as usize].0, scratch[b as usize].0))
        });
    }

    // Two gathers fused into one pass over `order`: each output row is the
    // permutation applied to its own input row, so the two columns are written
    // in lockstep from one indexed load. A data-dependent *address* is not a
    // branch. Both columns were cleared above and are refilled here.
    out.panel.reserve(order.len());
    out.epsilon.reserve(order.len());
    for &row in &order {
        let (panel, epsilon) = scratch[row as usize];
        out.panel.push(panel);
        out.epsilon.push(epsilon);
    }

    debug_assert_eq!(out.panel.len(), scratch.len(), "the sort lost a panel");
    debug_assert_eq!(
        out.epsilon.len(),
        out.panel.len(),
        "epsilon travels with the mesh, one entry per panel"
    );
    debug_assert_eq!(
        out.conductor_start.len(),
        selected.len() + 1,
        "a CSR over n conductors has n + 1 boundaries"
    );
    debug_assert_eq!(out.conductor_net.len(), selected.len());
    debug_assert_eq!(
        out.conductor_start.last().copied(),
        u32::try_from(out.panel.len()).ok(),
        "the last boundary is the end of the panel column"
    );
    Ok(())
}

/// One conductor polygon as a solid: its footprint in grid units, its z extent
/// in metres, and the permittivity above it.
///
/// `AoS`: meshing reads every field of one solid together and never scans a
/// single column, which is [`Panel`]'s argument exactly.
#[derive(Debug, Clone, Copy)]
struct Solid {
    bbox: Bbox,
    /// Bottom and top of the layer, in metres.
    z: [f64; 2],
    epsilon: f64,
    conductor: u32,
}

/// One layer's z extent, in metres, and the permittivity above it.
///
/// A named struct rather than a tuple because it is gathered per polygon and
/// the two fields read very differently: `epsilon` doubles as the row's
/// validity, and `.1 > 0.0` at that site would say nothing about why.
#[derive(Debug, Clone, Copy)]
struct Extrusion {
    /// Bottom and top of the layer, in metres.
    z: [f64; 2],
    /// Relative permittivity above the layer. Not positive exactly when the
    /// process stack does not describe this layer — see [`UNDESCRIBED`].
    epsilon: f64,
}

/// What a layer the process stack does not describe extrudes to.
///
/// `NaN` rather than zero: every reader of the table tests `epsilon > 0.0`,
/// which `NaN` fails, and a `NaN` that escapes the check poisons a panel rather
/// than quietly producing one of no thickness.
const UNDESCRIBED: Extrusion = Extrusion {
    z: [f64::NAN; 2],
    epsilon: f64::NAN,
};

/// Every layer the process stack describes, plus one sentinel row standing for
/// every layer it does not.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled. Not a bulk
/// loop: a stack has tens of rows, one per layer of a PDK. It exists so the
/// per-polygon lookup in [`build_into`] is a clamped gather with no branch and
/// no repeated `Vec::get`.
///
/// Fail closed on all three columns: a [`GeometryStore`] is two-dimensional, so
/// a layer with no thickness has no z extent to panel, and a conductor meshed
/// as a sheet carries charge on no side at all.
fn extrusion_table(stack: &ProcessStack, out: &mut Vec<Extrusion>) {
    // The rows all three columns agree on. A stack whose columns disagree
    // describes no layer past the shortest of them.
    let rows = stack
        .thickness_nm
        .len()
        .min(stack.height_nm.len())
        .min(stack.dielectric_k.len());

    out.clear();
    out.reserve(rows + 1);
    for row in 0..rows {
        out.push(extrude(stack, row));
    }
    // The sentinel, at index `rows`: a clamped gather lands here for any layer
    // id the stack is too short to describe.
    out.push(UNDESCRIBED);
    debug_assert_eq!(out.len(), rows + 1, "one row per layer, plus the sentinel");
}

/// One row of the process stack as a z extent and a permittivity.
///
/// **Decision** — pure, small data in, one value out.
fn extrude(stack: &ProcessStack, row: usize) -> Extrusion {
    debug_assert!(
        row < stack.thickness_nm.len()
            && row < stack.height_nm.len()
            && row < stack.dielectric_k.len(),
        "a row past a column of the stack"
    );
    let thickness = stack.thickness_nm[row];
    let height = stack.height_nm[row];
    let epsilon = stack.dielectric_k[row];

    // Negated, so a `NaN` is refused rather than accepted: a thickness that is
    // not a positive number is a deck that cannot state where this layer is.
    if !(thickness > 0.0) || !height.is_finite() || !(epsilon > 0.0) {
        return UNDESCRIBED;
    }
    Extrusion {
        z: [height * 1e-9, (height + thickness) * 1e-9],
        epsilon,
    }
}

/// Whether a solid sits within `distance` of a conductor other than its own.
fn near_another_conductor(solid: &[Solid], of: Solid, distance: Dbu) -> bool {
    // Surviving `if`: the knob is off or on for a whole run, so the predictor
    // sees one outcome, and the taken side is the O(n^2) scan below — row two of
    // the escape-valve list, twice over.
    if distance.raw() == 0 {
        return false;
    }
    // Every solid against every other, O(n^2) in the polygons of the selected
    // nets — tens to thousands, not the whole layout. The indexed version is
    // blocked, not deferred: `core::index::SpatialIndex::build_into` is frozen
    // at `(&GeometryStore, LayerId)`, and a solid column is neither — it spans
    // layers and its rows are not the store's. Recorded in
    // `docs/SIGNATURE_DEFECTS.md` as `index: no build-from-bbox-column seam`.
    // No early exit and no branch in the body: `|=` and `&`, not `||` and `&&`.
    let mut near = false;
    for other in solid {
        near |= (other.conductor != of.conductor) & of.bbox.within(other.bbox, distance);
    }
    near
}

/// The six faces of an axis-aligned box: the axis each is normal to, and which
/// end of that axis it sits at.
const FACES: [(usize, f64); 6] = [
    (0, -1.0),
    (0, 1.0),
    (1, -1.0),
    (1, 1.0),
    (2, -1.0),
    (2, 1.0),
];

/// How many panels one face edge of `width` is cut into at a limit of `edge`.
fn cuts(width: f64, edge: f64) -> u32 {
    debug_assert!(width > 0.0, "a face of no width is not meshed");
    debug_assert!(edge > 0.0, "a panel edge limit is positive");
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "positive, and a saturating cast is refused as TooManyPanels by the caller"
    )]
    let n = (width / edge).ceil() as u32;
    // At least one: a face narrower than the limit is still a face.
    n.max(1)
}

/// Panel one axis-aligned box into `out`, six faces cut at `edge`.
///
/// **Transform, A-to-B.** `remaining` is the caller's panel budget, decremented
/// per face *before* anything is emitted, so a mesh that would exceed the limit
/// is refused rather than half-built.
fn mesh_box(
    lo: [f64; 3],
    hi: [f64; 3],
    edge: f64,
    conductor: u32,
    epsilon: f64,
    remaining: &mut u32,
    out: &mut Vec<(Panel, f64)>,
) -> Result<(), MeshError> {
    debug_assert!(edge > 0.0, "a panel edge limit is positive");

    for (axis, sign) in FACES {
        let (u, v) = ((axis + 1) % 3, (axis + 2) % 3);
        let (wu, wv) = (hi[u] - lo[u], hi[v] - lo[v]);
        // Surviving `if`: six faces per box is not a bulk loop, and the taken
        // side is the whole nested emission below. A degenerate footprint — a
        // zero-width derived shape — has faces of no area, and a panel of no
        // area carries no charge and would fail `area > 0` downstream. Negated
        // so a `NaN` extent is skipped rather than meshed.
        if !(wu > 0.0 && wv > 0.0) {
            continue;
        }

        let (nu, nv) = (cuts(wu, edge), cuts(wv, edge));
        let panels = nu.checked_mul(nv).ok_or(MeshError::TooManyPanels)?;
        *remaining = remaining
            .checked_sub(panels)
            .ok_or(MeshError::TooManyPanels)?;
        out.reserve(panels as usize);

        let (du, dv) = (wu / f64::from(nu), wv / f64::from(nv));
        let area = du * dv;
        let mut normal = [0.0; 3];
        normal[axis] = sign;
        // The face plane: the box centre on this axis, pushed to whichever end
        // the sign names. Unit normal by construction — one component is +/-1
        // and the other two are zero.
        let plane = (lo[axis] + hi[axis]).mul_add(0.5, sign * (hi[axis] - lo[axis]) * 0.5);

        // No data-dependent branch in the body, and the whole face's allocation
        // is reserved above the loop, so nothing here grows element-wise.
        for iu in 0..nu {
            for iv in 0..nv {
                let mut centre = [0.0; 3];
                centre[axis] = plane;
                centre[u] = (f64::from(iu) + 0.5).mul_add(du, lo[u]);
                centre[v] = (f64::from(iv) + 0.5).mul_add(dv, lo[v]);
                out.push((
                    Panel {
                        centre,
                        normal,
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

/// Bits per axis in a Morton key. Three of them fit a `u64` with one to spare,
/// so a mesh is quantised to a 2M-cell grid per axis — finer than any panel
/// count this module will admit, and the tiebreak below covers what collides.
const MORTON_BITS: u32 = 21;

/// The largest value one axis of a Morton key can hold.
const MORTON_MAX: u64 = (1 << MORTON_BITS) - 1;

/// [`MORTON_MAX`] as the quantiser's multiplier, written out because `f64::from`
/// is not `const` and a cast would be. Exact: `2^21 - 1` needs 21 significant
/// bits and an `f64` carries 53.
const MORTON_SPAN: f64 = 2_097_151.0;

const _: () = assert!(MORTON_MAX == 2_097_151, "MORTON_SPAN is not MORTON_MAX");

/// A Morton (Z-order) sort key per panel.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled. The bounds
/// the key is quantised against are a reduction over the same panels, so the
/// key is a function of the geometry and nothing else — the property the sort's
/// determinism rests on.
///
/// Z-order rather than the lexicographic z-then-y-then-x this replaced: a
/// lexicographic order is contiguous along one axis and arbitrarily far apart
/// along the other two, so the matvec's near-field block for a panel straddles
/// the whole column. Interleaving the bits makes a run of the column a compact
/// box in space instead of a row of one.
fn morton_keys(panel: &[(Panel, f64)], out: &mut Vec<u64>) {
    // Ascending left fold over the centroids: the bounds decide the key, the key
    // decides the order, and two runs of one geometry must agree bit for bit.
    let mut bounds = [[f64::INFINITY; 3], [f64::NEG_INFINITY; 3]];
    for &(p, _) in panel {
        // Three axes, a fixed trip count the compiler unrolls. `min`/`max` are
        // the branchless form of the compare they replace.
        #[expect(
            clippy::needless_range_loop,
            reason = "`axis` addresses three arrays at once — both rows of `bounds` and \
                      `p.centre` — so there is no single slice to iterate. Clippy's \
                      suggestion walks `bounds`'s two rows, which is the wrong axis of \
                      the wrong array; the fixed trip count is 3"
        )]
        for axis in 0..3 {
            bounds[0][axis] = bounds[0][axis].min(p.centre[axis]);
            bounds[1][axis] = bounds[1][axis].max(p.centre[axis]);
        }
    }
    let lo = bounds[0];

    // Uniforms, hoisted above the map: three spans for the whole column.
    let scale: [f64; 3] = std::array::from_fn(|axis| {
        let span = bounds[1][axis] - lo[axis];
        // Not a bulk branch: three axes per mesh. A degenerate axis — one layer
        // of panels all at the same z, or an empty mesh — has no span to divide
        // by, and a scale of zero collapses that axis of the key rather than
        // handing the quantiser an infinity.
        if span > 0.0 {
            MORTON_SPAN / span
        } else {
            0.0
        }
    });

    // Caller-owned: cleared, reserved once, refilled to one key per panel.
    out.clear();
    out.reserve(panel.len());
    for &(p, _) in panel {
        out.push(morton3(
            quantise(p.centre[0], lo[0], scale[0]),
            quantise(p.centre[1], lo[1], scale[1]),
            quantise(p.centre[2], lo[2], scale[2]),
        ));
    }
    debug_assert_eq!(out.len(), panel.len(), "one key per panel");
}

/// One coordinate as a `MORTON_BITS`-wide integer.
///
/// The clamp *is* the cast: `f64 as u64` saturates at both ends and maps `NaN`
/// to zero, so no branch is needed. The panel column has no `NaN` centroid, but
/// a sort key has to be total whether or not that holds — an unordered key is a
/// non-deterministic mesh, and determinism here is interface.
fn quantise(value: f64, lo: f64, scale: f64) -> u64 {
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the cast saturates into [0, u64::MAX] and maps NaN to zero"
    )]
    let raw = ((value - lo) * scale) as u64;
    raw.min(MORTON_MAX)
}

/// Interleave three `MORTON_BITS`-wide integers, `x` in the low bit of each
/// triple.
const fn morton3(x: u64, y: u64, z: u64) -> u64 {
    spread3(x) | spread3(y) << 1 | spread3(z) << 2
}

/// Spread the low `MORTON_BITS` of `v` so bit `i` lands at bit `3 * i`.
///
/// Five shift-and-mask steps, each halving the distance a bit still has to
/// travel: branchless, constant time, and the reason the key costs nothing next
/// to the comparison sort that consumes it.
const fn spread3(v: u64) -> u64 {
    let mut x = v & MORTON_MAX;
    x = (x | x << 32) & 0x001f_0000_0000_ffff;
    x = (x | x << 16) & 0x001f_0000_ff00_00ff;
    x = (x | x << 8) & 0x100f_00f0_0f00_f00f;
    x = (x | x << 4) & 0x10c3_0c30_c30c_30c3;
    x = (x | x << 2) & 0x1249_2492_4924_9249;
    x
}

/// Spatial order over two panels, from their centroids and nothing else.
///
/// The tiebreak under [`morton_keys`], not the primary order: two panels whose
/// centroids quantise into one cell of the key are separated here, so the sort
/// stays a total order derived only from position. `total_cmp`, so two runs
/// cannot disagree about a signed zero.
fn spatial_cmp(a: Panel, b: Panel) -> Ordering {
    a.centre[2]
        .total_cmp(&b.centre[2])
        .then_with(|| a.centre[1].total_cmp(&b.centre[1]))
        .then_with(|| a.centre[0].total_cmp(&b.centre[0]))
}

/// Surface area of one conductor, summed from its panels.
///
/// **Decision** — pure, and the first thing a meshing test checks: the panels
/// must tile the conductor exactly, so their areas must sum to the analytic
/// surface area of the shape. A mesh that loses area loses charge, and a solve
/// on it is wrong in a way no residual reveals.
pub fn conductor_area(mesh: &Mesh, conductor: u32) -> f64 {
    let row = conductor as usize;
    // Fail closed: a conductor past the CSR indexes out of bounds and panics in
    // every profile. Returning zero for it would make "this conductor has no
    // surface" and "this conductor is not in this mesh" read the same, and a
    // zero area is a conductor that stores no charge.
    let (from, to) = (
        mesh.conductor_start[row] as usize,
        mesh.conductor_start[row + 1] as usize,
    );
    debug_assert!(from <= to, "a CSR band runs backwards");
    debug_assert!(to <= mesh.panel.len(), "a CSR band leaves the panel column");

    // Ascending left fold: the sum is the oracle a meshing test compares
    // against an analytic surface area, so it has to be the same sum on every
    // run.
    let mut area = 0.0_f64;
    for panel in &mesh.panel[from..to] {
        area += panel.area;
    }
    debug_assert!(area >= 0.0, "a surface area is non-negative");
    area
}

/// The Morton key is bit arithmetic with no coverage in `tests/quasistatic.rs`:
/// that suite gates on two runs agreeing byte for byte, which a wrong key
/// satisfies perfectly. These are the checks that do not.
#[cfg(test)]
mod tests {
    use super::{morton3, quantise, spread3, MORTON_BITS, MORTON_MAX, MORTON_SPAN};

    /// Spreading is the inverse of taking every third bit, and it puts bit `i`
    /// at bit `3 * i` — stated against a scan rather than against a second copy
    /// of the same five masks.
    #[test]
    fn spreading_moves_bit_i_to_bit_three_i() {
        for i in 0..MORTON_BITS {
            assert_eq!(
                spread3(1 << i),
                1 << (3 * i),
                "bit {i} did not land at bit {}",
                3 * i
            );
        }
        assert_eq!(spread3(0), 0);
        assert_eq!(
            spread3(MORTON_MAX).count_ones(),
            MORTON_BITS,
            "spreading is one-to-one, so it neither loses nor invents a bit"
        );
        assert_eq!(
            spread3(MORTON_MAX | 1 << MORTON_BITS),
            spread3(MORTON_MAX),
            "a bit above the axis width is masked off, not folded in"
        );
    }

    /// The three axes occupy disjoint bit positions, so a key can be taken apart
    /// again. A key that lost an axis would still sort deterministically, which
    /// is exactly why the determinism gate cannot see this.
    #[test]
    fn a_key_keeps_all_three_axes_in_disjoint_bits() {
        let (x, y, z) = (0b1011, 0b0110, 0b1101);
        let key = morton3(x, y, z);
        let gather = |shift: u32| {
            (0..MORTON_BITS).fold(0_u64, |bits, i| bits | (key >> (3 * i + shift) & 1) << i)
        };
        assert_eq!(gather(0), x, "x is the low bit of each triple");
        assert_eq!(gather(1), y);
        assert_eq!(gather(2), z);
        assert_eq!(morton3(0, 0, 0), 0);
        assert_eq!(
            morton3(
                MORTON_MAX,
                MORTON_MAX,
                MORTON_MAX
            )
            .count_ones(),
            3 * MORTON_BITS,
            "a full key is 63 bits wide"
        );
    }

    /// Quantising is monotone, saturates at both ends, and is total on the
    /// values a sort key must never be undefined for.
    #[test]
    fn quantising_is_monotone_and_total() {
        let scale = MORTON_SPAN / 4.0;
        assert_eq!(quantise(0.0, 0.0, scale), 0, "the low bound is cell zero");
        assert_eq!(
            quantise(4.0, 0.0, scale),
            MORTON_MAX,
            "the high bound is the last cell"
        );
        assert_eq!(quantise(1.0, 0.0, scale), MORTON_MAX / 4);
        assert!(quantise(1.0, 0.0, scale) < quantise(2.0, 0.0, scale));

        assert_eq!(quantise(-1.0, 0.0, scale), 0, "below the bound clamps down");
        assert_eq!(
            quantise(9.0, 0.0, scale),
            MORTON_MAX,
            "above the bound clamps up"
        );
        assert_eq!(quantise(f64::NAN, 0.0, scale), 0, "NaN is ordered, not UB");
        assert_eq!(quantise(f64::INFINITY, 0.0, scale), MORTON_MAX);
        assert_eq!(
            quantise(7.0, 0.0, 0.0),
            0,
            "a degenerate axis collapses to one cell rather than dividing"
        );
    }
}
