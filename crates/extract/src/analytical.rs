//! Closed-form extraction from the deck's process stack.
//!
//! Data in: every net's polygons, the conductor/via connectivity, the stack.
//! Data out: a canonical [`ParasiticNetwork`] — per conductor region a series
//! R and a ground C, lateral and interlayer coupling C, and via R. A region
//! is one edge-connected piece of a net's merged shapes on one layer, so a
//! wire reads the same however it was cut into polygons. The formulas and what
//! they leave out are in the
//! [crate docs](crate#the-closed-forms).

use crate::conductor::Regions;
use crate::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_check::topology::{NetId, NetTable};
use gpurify_geom::index::{candidate_pairs_into, cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::{ops, Bbox, GeometryStore, GeometryStoreBuilder, LayerId, PolyId};
use gpurify_geom::{prefix, Capacitance, Dbu, DbuArea, Grid, Qty, Resistance, MAX_ABS_DBU};
use gpurify_ingest::deck::{Connectivity, ProcessStack};

/// Divided by, never multiplied by `1e-3`, which is not exact in `f64`.
const AF_PER_FF: f64 = 1_000.0;

/// Vacuum permittivity, attofarads per micrometre (CODATA 2018).
const EPSILON0_AF_PER_UM: f64 = 8.854_187_812_8;

const NM_PER_UM: f64 = 1_000.0;

/// Lateral coupling reach, as a multiple of the conductor's thickness.
// ponytail: fixed because no deck states a halo; add `coupling_halo_nm` to the deck when one does.
const LATERAL_HALO_THICKNESSES: f64 = 10.0;

#[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
fn micrometres(value: Dbu, grid: Grid) -> f64 {
    value.raw() as f64 / grid.dbu_per_um() as f64
}

fn square_micrometres(value: DbuArea, grid: Grid) -> f64 {
    #[expect(clippy::cast_precision_loss, reason = "f64 is the output type")]
    let raw = value.raw() as f64;
    #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
    let per_um = grid.dbu_per_um() as f64;
    raw / (per_um * per_um)
}

/// Series resistance of a run: `sheet × length / width`. `width` must be positive.
fn segment_resistance(
    sheet_ohm_sq: f64,
    length: Dbu,
    width: Dbu,
) -> Qty<Resistance, { prefix::BASE }> {
    #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
    let squares = length.raw() as f64 / width.raw() as f64;
    Qty::new(sheet_ohm_sq * squares)
}

/// A via array's resistance: per-cut over the cut count (cuts are in parallel).
fn via_resistance(per_cut_ohm: f64, cuts: u32) -> Qty<Resistance, { prefix::BASE }> {
    Qty::new(per_cut_ohm / f64::from(cuts))
}

/// Capacitance to the plane beneath: `area × area_coeff + perimeter × fringe_coeff`.
///
/// Two separate products so `f(a, 0) + f(0, b) == f(a, b)` holds exactly.
fn ground_capacitance(
    area_af_um2: f64,
    fringe_af_um: f64,
    area: DbuArea,
    perimeter: Dbu,
    grid: Grid,
) -> Qty<Capacitance, { prefix::FEMTO }> {
    let plate = area_af_um2 * square_micrometres(area, grid);
    let fringe = fringe_af_um * micrometres(perimeter, grid);
    Qty::new((plate + fringe) / AF_PER_FF)
}

/// Capacitance between two neighbours: `k × L / S`, `k` in aF per µm at 1 µm.
/// `separation` must be positive.
fn coupling_capacitance(
    coefficient_af_um: f64,
    facing_length: Dbu,
    separation: Dbu,
    grid: Grid,
) -> Qty<Capacitance, { prefix::FEMTO }> {
    let ratio = micrometres(facing_length, grid) / micrometres(separation, grid);
    Qty::new(coefficient_af_um * ratio / AF_PER_FF)
}

/// Why the closed forms refused a design. Each names the layer whose
/// parasitics are unknown, rather than reading it as a perfect wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AnalyticalError {
    /// A conductor layer holds a net's shapes, but no `pex` row gives it a
    /// positive, finite sheet resistance: its resistance and capacitance are
    /// unknown, never zero.
    #[error("no pex row gives this conductor a positive sheet resistance")]
    Undescribed(LayerId),
    /// A via layer has a cut joining two conductor plates, but no `pex` row
    /// gives it a positive, finite resistance per cut.
    #[error("no pex row gives this via layer a positive resistance per cut")]
    UndescribedVia(LayerId),
    /// A conductor layer's shapes of one net do not validate as simple
    /// rectilinear rings, so they cannot be merged into a conductor exactly.
    #[error("not valid rectilinear geometry, so its conductors cannot be merged exactly")]
    InvalidGeometry(LayerId),
}

impl AnalyticalError {
    /// The layer the refusal names.
    pub fn layer(self) -> LayerId {
        match self {
            Self::Undescribed(layer)
            | Self::UndescribedVia(layer)
            | Self::InvalidGeometry(layer) => layer,
        }
    }
}

/// Region marker for a rectangle store row that is a via cut.
const CUT: u32 = u32::MAX;

/// Extracts every net of the design into `out`, which is cleared first and
/// left in canonical order.
///
/// `nets` must have been traced from `store` with `connectivity`, and `stack`
/// is indexed by [`LayerId`]. Each net's shapes on a non-global layer are
/// merged, and each piece of the merge whose parts share edges is one region
/// (two pieces that meet only at a corner are two, though the merge joins
/// them: a corner carries no current): a bar drawn as abutting or overlapping
/// polygons is one region with the outline's area and perimeter. Net `k`'s
/// nodes follow those of nets `0..k`; a net of `n` regions has `n + 1` nodes,
/// its regions ascending by layer. Region `i` contributes a ground
/// capacitance on node `i` and a resistor from node `i` to `i + 1`, and node
/// `i` is that region's node. A net with no region (shapes on global layers only) has no node.
/// Coupling is measured between the regions' rectangles and joins the
/// regions' nodes. A via array, the cuts that land on the same two regions
/// (the lowest region on each side, touching included), is one resistor
/// between their nodes.
///
/// Both coupling terms are parallel-plate (no fringing), so lateral coupling
/// is a lower bound, and neither is shielded by what lies between the plates.
/// An element that comes out zero is left out, and so is a cut that does not
/// land on both of its plates. Shapes on a global layer
/// ([`Connectivity::global`]) carry no parasitics and need no stack row, nor
/// do vias into them.
///
/// # Errors
///
/// [`AnalyticalError::Undescribed`] for the lowest conductor layer that holds
/// a net's shape and has no positive, finite sheet resistance; then
/// [`AnalyticalError::InvalidGeometry`] for the first net, in net order,
/// whose shapes on a layer are not valid rectilinear rings; then
/// [`AnalyticalError::UndescribedVia`] for the first via layer, in deck
/// order, with a cut on both of its conductor plates and no positive, finite
/// resistance per cut. `out` holds no usable network then.
///
/// # Panics
///
/// Panics if the nets or the nodes of the network outnumber a `u32`.
///
/// # Time complexity
///
/// A merge per net and layer, linear-logarithmic in that net's vertices, plus
/// the spatial joins: each conductor layer against itself within ten
/// thicknesses, each pair of conductor layers, and each via layer against
/// its two plates.
pub fn extract_into(
    store: &GeometryStore,
    nets: &NetTable,
    connectivity: &Connectivity,
    stack: &ProcessStack,
    grid: Grid,
    out: &mut ParasiticNetwork,
) -> Result<(), AnalyticalError> {
    out.clear();
    refuse_undescribed(store, nets, connectivity, stack)?;

    let regions = regions(store, nets, connectivity)?;
    let node_of = regions_into(&regions, stack, grid, out);
    let (rects, owner) = rect_store(store, connectivity, &regions);
    couple_into(
        &rects,
        &owner,
        &regions,
        connectivity,
        stack,
        grid,
        &node_of,
        out,
    );
    vias_into(&rects, &owner, connectivity, stack, &node_of, out)?;
    out.sort_canonical();
    out.debug_check();
    // A zero element is left out and every resistance is a positive sheet
    // or via value over a positive count.
    debug_assert!(
        out.value
            .iter()
            .all(|value| !matches!(*value, Parasitic::Resistance(r) if !(r.raw() > 0.0))),
        "every closed-form resistance is positive"
    );
    Ok(())
}

/// The conductor rectangles behind the nodes [`extract_into`] allocates for
/// the same `store`, `nets` and `connectivity`: each region's disjoint
/// rectangles, tagged with the region's node, ascending by node. A net's
/// closing node has none.
///
/// A node is a region, not a drawn polygon: a bar drawn as two abutting
/// polygons is one node, and two pieces that meet only at a corner are two,
/// whatever the polygon count. A caller that places the network's elements
/// on geometry of its own (the Liberty circuit's rectangles) reads each
/// node's place here.
///
/// # Errors
///
/// [`AnalyticalError::InvalidGeometry`], as [`extract_into`] gives for the
/// same inputs; where `extract_into` succeeded, this does too.
///
/// # Time complexity
///
/// The merge per net and layer that [`extract_into`] does, and no spatial
/// join.
pub fn node_rects(
    store: &GeometryStore,
    nets: &NetTable,
    connectivity: &Connectivity,
) -> Result<Vec<(NodeId, Bbox)>, AnalyticalError> {
    let regions = regions(store, nets, connectivity)?;
    let mut out = Vec::with_capacity(regions.rects.len());
    let mut node = 0u32;
    for region in 0..regions.len() {
        out.extend(regions.rects_of(region).iter().map(|&r| (NodeId(node), r)));
        node += 1;
        // A net's last region is followed by its closing node, as in
        // `regions_into`.
        if regions.net.get(region + 1) != Some(&regions.net[region]) {
            node += 1;
        }
    }
    Ok(out)
}

/// Every net's regions, in ascending [`NetId`], so the nodes `regions_into`
/// allocates are grouped by net and ascending. A global layer makes none.
fn regions(
    store: &GeometryStore,
    nets: &NetTable,
    connectivity: &Connectivity,
) -> Result<Regions, AnalyticalError> {
    let mut regions = Regions::default();
    let net_count = u32::try_from(nets.net_count()).expect("a NetId is a u32");
    for net in 0..net_count {
        regions
            .push_net(store, nets, NetId(net), |layer| {
                !connectivity.global.contains(&layer)
            })
            .map_err(AnalyticalError::InvalidGeometry)?;
    }
    Ok(regions)
}

/// Every region's rectangles on its layer and every via cut as drawn, in one
/// store, so the spatial joins measure conductors rather than drawn polygons.
/// `owner[row]` is a rectangle row's region, [`CUT`] for a cut.
fn rect_store(
    store: &GeometryStore,
    connectivity: &Connectivity,
    regions: &Regions,
) -> (GeometryStore, Vec<u32>) {
    let mut builder = GeometryStoreBuilder::with_capacity(regions.rects.len(), 0);
    let mut arrival = Vec::with_capacity(regions.rects.len());
    for region in 0..regions.len() {
        let index = u32::try_from(region).expect("a region index is a u32");
        for r in regions.rects_of(region) {
            builder.push(
                regions.layer[region],
                &[r.xlo, r.xhi, r.xhi, r.xlo],
                &[r.ylo, r.ylo, r.yhi, r.yhi],
            );
            arrival.push(index);
        }
    }
    let mut cut_layers = connectivity.via_cut.clone();
    cut_layers.sort_unstable();
    cut_layers.dedup();
    for layer in cut_layers {
        for row in store.polys_on_layer(layer) {
            let (xs, ys) = store.poly_verts(PolyId(row));
            builder.push(layer, xs, ys);
            arrival.push(CUT);
        }
    }
    let (rects, permutation) = builder.finish(store.layer_count());
    let owner = permutation
        .iter()
        .map(|&old| arrival[old as usize])
        .collect();
    (rects, owner)
}

/// The lowest non-global layer that holds a net's shape and is not
/// [`described`].
fn refuse_undescribed(
    store: &GeometryStore,
    nets: &NetTable,
    connectivity: &Connectivity,
    stack: &ProcessStack,
) -> Result<(), AnalyticalError> {
    for layer in 0..store.layer_count() {
        let layer = LayerId(u16::try_from(layer).expect("a LayerId is a u16"));
        if connectivity.global.contains(&layer) || described(stack, layer) {
            continue;
        }
        let on_a_net = store
            .polys_on_layer(layer)
            .any(|row| nets.net_of(PolyId(row)) != NetId::NONE);
        if on_a_net {
            return Err(AnalyticalError::Undescribed(layer));
        }
    }
    Ok(())
}

/// Whether the stack gives `layer` a positive, finite sheet resistance (Ω per
/// cut on a via layer): the one value every stated row has, and that a layer
/// with no row reads as zero.
fn described(stack: &ProcessStack, layer: LayerId) -> bool {
    stack_row(stack, layer)
        .map(|row| stack.sheet_res_ohm_sq[row])
        .is_some_and(|ohm| ohm > 0.0 && ohm.is_finite())
}

/// The run two same-layer boxes share and the gap across it; `None` for a
/// corner, an overlap, or touching boxes.
fn facing(a: Bbox, b: Bbox) -> Option<(Dbu, Dbu)> {
    let along_x = a.xhi.raw().min(b.xhi.raw()) - a.xlo.raw().max(b.xlo.raw());
    let along_y = a.yhi.raw().min(b.yhi.raw()) - a.ylo.raw().max(b.ylo.raw());
    let (run, gap) = match (along_x > 0, along_y > 0) {
        (true, false) => (along_x, -along_y),
        (false, true) => (along_y, -along_x),
        _ => return None,
    };
    (gap > 0).then(|| (Dbu::new_unchecked(run), Dbu::new_unchecked(gap)))
}

/// A stack row's lateral coupling coefficient `ε₀ · k · t`.
fn lateral_coefficient(stack: &ProcessStack, row: usize) -> f64 {
    let k = stack.dielectric_k.get(row).copied().unwrap_or(0.0);
    let thickness_um = stack.thickness_nm.get(row).copied().unwrap_or(0.0) / NM_PER_UM;
    EPSILON0_AF_PER_UM * k * thickness_um
}

/// Dielectric thickness in µm from the top of `lower` to the bottom of `upper`,
/// or `None` if they do not stack that way.
fn interlayer_gap_um(stack: &ProcessStack, lower: usize, upper: usize) -> Option<f64> {
    let top_of_lower = stack.height_nm.get(lower).copied().unwrap_or(0.0)
        + stack.thickness_nm.get(lower).copied().unwrap_or(0.0);
    let bottom_of_upper = stack.height_nm.get(upper).copied().unwrap_or(0.0);
    let gap_nm = bottom_of_upper - top_of_lower;
    (gap_nm > 0.0).then_some(gap_nm / NM_PER_UM)
}

/// One coupling element between regions on different nets, lower [`NetId`]
/// first. Non-positive or non-finite values are dropped.
fn push_coupling(
    regions: &Regions,
    node_of: &[NodeId],
    a: u32,
    b: u32,
    femtofarads: f64,
    out: &mut ParasiticNetwork,
) {
    if !(femtofarads > 0.0 && femtofarads.is_finite()) {
        return;
    }
    let (a, b) = (a as usize, b as usize);
    let (lo, hi) = if regions.net[a] < regions.net[b] {
        (a, b)
    } else {
        (b, a)
    };
    out.push(
        node_of[lo],
        Some(node_of[hi]),
        Parasitic::CouplingCap(Qty::new(femtofarads)),
    );
}

/// Lateral (same layer, within [`LATERAL_HALO_THICKNESSES`] × thickness) and
/// interlayer (overlapping) coupling between the regions' rectangles in
/// `rects` ([`rect_store`]). Appends.
fn couple_into(
    rects: &GeometryStore,
    owner: &[u32],
    regions: &Regions,
    connectivity: &Connectivity,
    stack: &ProcessStack,
    grid: Grid,
    node_of: &[NodeId],
    out: &mut ParasiticNetwork,
) {
    let store = rects;
    let region = |poly: PolyId| owner[poly.idx()];
    let same_net =
        |a: PolyId, b: PolyId| regions.net[region(a) as usize] == regions.net[region(b) as usize];
    let mut index_a = SpatialIndex::default();
    let mut index_b = SpatialIndex::default();
    let mut pairs = Vec::new();

    for (position, &layer) in connectivity.conductors.iter().enumerate() {
        let Some(row) = stack_row(stack, layer) else {
            continue;
        };
        let coefficient = lateral_coefficient(stack, row);
        #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
        let per_um = grid.dbu_per_um() as f64;
        let thickness_dbu =
            stack.thickness_nm.get(row).copied().unwrap_or(0.0) * per_um / NM_PER_UM;
        #[expect(clippy::cast_precision_loss, reason = "MAX_ABS_DBU is 2^40, exact")]
        let ceiling = MAX_ABS_DBU as f64;
        #[expect(clippy::cast_possible_truncation, reason = "clamped by the `min`")]
        let halo = (thickness_dbu * LATERAL_HALO_THICKNESSES).min(ceiling) as i64;

        if coefficient > 0.0 && halo > 0 {
            SpatialIndex::build_into(store, layer, &mut index_a);
            candidate_pairs_into(store, &index_a, Dbu::new_unchecked(halo), &mut pairs);
            for &(a, b) in &pairs {
                if same_net(a, b) {
                    continue;
                }
                let Some((run, gap)) = facing(store.poly_bbox(a), store.poly_bbox(b)) else {
                    continue;
                };
                let femtofarads = coupling_capacitance(coefficient, run, gap, grid).raw();
                push_coupling(regions, node_of, region(a), region(b), femtofarads, out);
            }
        }

        // Each layer pair once; lower/upper comes from the stack heights.
        for &above in &connectivity.conductors[position + 1..] {
            let Some(other) = stack_row(stack, above) else {
                continue;
            };
            let (lower, upper, lower_layer, upper_layer) =
                if stack.height_nm[row] <= stack.height_nm[other] {
                    (row, other, layer, above)
                } else {
                    (other, row, above, layer)
                };
            let Some(gap_um) = interlayer_gap_um(stack, lower, upper) else {
                continue;
            };
            // The dielectric between them is the one above the lower plate.
            let k = stack.dielectric_k.get(lower).copied().unwrap_or(0.0);
            if k <= 0.0 {
                continue;
            }
            let per_um2 = EPSILON0_AF_PER_UM * k / gap_um;

            SpatialIndex::build_into(store, lower_layer, &mut index_a);
            SpatialIndex::build_into(store, upper_layer, &mut index_b);
            cross_layer_pairs_into(store, &index_a, &index_b, Dbu::new_unchecked(0), &mut pairs);
            for &(a, b) in &pairs {
                if same_net(a, b) {
                    continue;
                }
                let (box_a, box_b) = (store.poly_bbox(a), store.poly_bbox(b));
                let wide =
                    box_a.xhi.raw().min(box_b.xhi.raw()) - box_a.xlo.raw().max(box_b.xlo.raw());
                let tall =
                    box_a.yhi.raw().min(box_b.yhi.raw()) - box_a.ylo.raw().max(box_b.ylo.raw());
                if wide <= 0 || tall <= 0 {
                    continue;
                }
                let overlap = DbuArea::new(i128::from(wide) * i128::from(tall));
                let femtofarads =
                    ground_capacitance(per_um2, 0.0, overlap, Dbu::new_unchecked(0), grid).raw();
                push_coupling(regions, node_of, region(a), region(b), femtofarads, out);
            }
        }
    }
}

/// Via resistance. Appends.
///
/// Cuts are grouped by the sorted `(lower, upper)` region pair they join; each
/// group is one resistor at per-cut / count (parallel, not series). A cut
/// lands on the lowest region whose rectangle shares a point with its box,
/// touching included, as net extraction joins. A via into a global layer is
/// skipped; any other via layer with a cut on both plates must be described.
fn vias_into(
    rects: &GeometryStore,
    owner: &[u32],
    connectivity: &Connectivity,
    stack: &ProcessStack,
    node_of: &[NodeId],
    out: &mut ParasiticNetwork,
) -> Result<(), AnalyticalError> {
    const NO_REGION: u32 = u32::MAX;
    let store = rects;

    let mut cut_index = SpatialIndex::default();
    let mut plate_index = SpatialIndex::default();
    let mut pairs = Vec::new();
    // Indexed by the cut's row; a cut missing a plate keeps the sentinel.
    let mut below = vec![NO_REGION; store.poly_count()];
    let mut above = vec![NO_REGION; store.poly_count()];
    let mut arrays: Vec<(u32, u32)> = Vec::new();

    for row in 0..connectivity.via_cut.len() {
        let cut_layer = connectivity.via_cut[row];
        let (lower, upper) = connectivity.via_connects[row];
        // A global layer has no regions, so a via into one joins nothing.
        if connectivity.global.contains(&lower) || connectivity.global.contains(&upper) {
            continue;
        }

        SpatialIndex::build_into(store, cut_layer, &mut cut_index);
        // Pairs come out `(cut, plate)`; the lowest plate wins, independent of
        // emission order.
        for (plate_layer, landing) in [(lower, &mut below), (upper, &mut above)] {
            SpatialIndex::build_into(store, plate_layer, &mut plate_index);
            cross_layer_pairs_into(
                store,
                &cut_index,
                &plate_index,
                Dbu::new_unchecked(0),
                &mut pairs,
            );
            for &(cut, plate) in &pairs {
                if store.poly_bbox(cut).overlaps(store.poly_bbox(plate)) {
                    let slot = &mut landing[cut.idx()];
                    *slot = (*slot).min(owner[plate.idx()]);
                }
            }
        }

        arrays.clear();
        for cut in store.polys_on_layer(cut_layer) {
            let (lo, hi) = (below[cut as usize], above[cut as usize]);
            if lo != NO_REGION && hi != NO_REGION {
                arrays.push((lo, hi));
            }
            below[cut as usize] = NO_REGION;
            above[cut as usize] = NO_REGION;
        }
        arrays.sort_unstable();
        if arrays.is_empty() {
            continue;
        }
        if !described(stack, cut_layer) {
            return Err(AnalyticalError::UndescribedVia(cut_layer));
        }
        let per_cut_ohm = stack.sheet_res_ohm_sq[cut_layer.idx()];

        for group in arrays.chunk_by(|a, b| a == b) {
            let key = group[0];
            let cuts = u32::try_from(group.len()).expect("a via array's cut count is a u32");
            let ohm = via_resistance(per_cut_ohm, cuts).raw();
            let (from, to) = (node_of[key.0 as usize], node_of[key.1 as usize]);
            out.push(from, Some(to), Parasitic::Resistance(Qty::new(ohm)));
        }
    }
    Ok(())
}

/// Every region's node, R and ground C, net by net; returns each region's
/// node. Appends.
///
/// A net of `n` regions gets `n + 1` boundary nodes; region `i` is a resistor
/// from node `i` to `i + 1` plus a ground C on node `i`, chained in region
/// order (a comb's fingers on two layers come out in series; the net total is
/// unchanged). Length and width are the sides of the rectangle with the
/// region's area and perimeter, the roots of `t² − (P/2)t + A`.
fn regions_into(
    regions: &Regions,
    stack: &ProcessStack,
    grid: Grid,
    out: &mut ParasiticNetwork,
) -> Vec<NodeId> {
    let mut node_of = Vec::with_capacity(regions.len());
    let mut first = 0;
    while first < regions.len() {
        let net = regions.net[first];
        let end = first + regions.net[first..].partition_point(|&other| other == net);
        for region in first..end {
            let node = NodeId::at(out.node_net.len());
            out.node_net.push(net);
            out.node_layer.push(regions.layer[region]);
            node_of.push(node);
            let next = NodeId(
                node.0
                    .checked_add(1)
                    .expect("the node columns fit a NodeId"),
            );
            region_into(regions, region, stack, grid, node, next, out);
        }
        // The closing boundary node.
        out.node_net.push(net);
        out.node_layer.push(regions.layer[end - 1]);
        first = end;
    }
    node_of
}

/// One region's ground C on `node` and R from `node` to `next`. Appends.
fn region_into(
    regions: &Regions,
    region: usize,
    stack: &ProcessStack,
    grid: Grid,
    node: NodeId,
    next: NodeId,
    out: &mut ParasiticNetwork,
) {
    // A region's layer is described: `refuse_undescribed` ran first.
    let sheet_ohm_sq = stack.sheet_res_ohm_sq[regions.layer[region].idx()];
    let (area, perimeter) = (regions.area[region], regions.perimeter[region]);

    {
        // A rectilinear outline is never too fat for a rectangle:
        // `(P/2)² ≥ 4A` holds for its bounding box and only grows from there.
        let half = perimeter.raw() / 2;
        let discriminant = i128::from(half) * i128::from(half) - 4 * area.raw();
        let spread = ops::isqrt(DbuArea::new(discriminant.max(0))).raw();
        let long = Dbu::new_unchecked(i64::midpoint(half, spread));
        let short = Dbu::new_unchecked((half - spread) / 2);

        let ohm = if short.raw() > 0 {
            segment_resistance(sheet_ohm_sq, long, short).raw()
        } else {
            0.0
        };
        let femtofarads = region_ground_ff(regions, region, stack, grid);

        // Ground first is canonical order. Zero values are dropped: a zero-ohm
        // resistor is a short.
        if femtofarads > 0.0 && femtofarads.is_finite() {
            out.push(node, None, Parasitic::GroundCap(Qty::new(femtofarads)));
        }
        if ohm > 0.0 && ohm.is_finite() {
            out.push(node, Some(next), Parasitic::Resistance(Qty::new(ohm)));
        }
    }
}

/// Region `region`'s capacitance to the substrate in fF, `Ca·A + Cf·P` from
/// its layer's row (zero past the stack).
pub(crate) fn region_ground_ff(
    regions: &Regions,
    region: usize,
    stack: &ProcessStack,
    grid: Grid,
) -> f64 {
    let row = regions.layer[region].idx();
    let area_af_um2 = stack.area_cap_af_um2.get(row).copied().unwrap_or(0.0);
    let fringe_af_um = stack.fringe_cap_af_um.get(row).copied().unwrap_or(0.0);
    let (area, perimeter) = (regions.area[region], regions.perimeter[region]);
    ground_capacitance(area_af_um2, fringe_af_um, area, perimeter, grid).raw()
}

/// A layer's process-stack row, or `None` past the stack.
fn stack_row(stack: &ProcessStack, layer: LayerId) -> Option<usize> {
    let row = layer.idx();
    (row < stack.sheet_res_ohm_sq.len()).then_some(row)
}

#[cfg(test)]
mod tests {
    //! The closed forms, against worked values and the laws each must obey.

    use super::{
        coupling_capacitance, ground_capacitance, segment_resistance, stack_row, via_resistance,
    };
    use gpurify_geom::{DbuArea, Grid, LayerId};
    use gpurify_ingest::deck::ProcessStack;
    use gpurify_testgen::{assert_close, assert_close_relative, dbu};

    fn grid() -> Grid {
        Grid::new(1_000).expect("a 1 nm grid")
    }

    /// Oracle: closed form. A ten-square run of a 100 milliohm per square layer is
    /// one ohm, and the arithmetic is `0.1 * 10` written out in the assertion. No
    /// implementation is consulted to know that.
    #[test]
    fn a_ten_square_run_of_a_hundred_milliohm_layer_is_one_ohm() {
        let r = segment_resistance(0.1, dbu(10_000), dbu(1_000));
        assert_close("ten squares of 0.1 ohm/sq", r.raw(), 1.0, 1e-12);
    }

    /// Oracle: closed form. Squares are dimensionless, so the same aspect ratio at
    /// three wildly different absolute sizes is the same resistance. A formula that
    /// leaked an absolute length — a stray grid factor, say — fails this and passes
    /// the single worked example above.
    #[test]
    fn sheet_resistance_depends_on_aspect_ratio_and_not_on_absolute_size() {
        let reference = segment_resistance(2.5, dbu(400), dbu(100)).raw();
        assert_close("four squares of 2.5 ohm/sq", reference, 10.0, 1e-12);
        for scale in [1_i64, 97, 1_000_000] {
            let r = segment_resistance(2.5, dbu(400 * scale), dbu(100 * scale));
            assert_close_relative("four squares at any scale", r.raw(), reference, 1e-12);
        }
    }

    /// Oracle: law. Resistance in series adds, so one run of length `L` is two runs
    /// of `L / 2` at the same width. True for any width and any sheet value, which
    /// is why it is stated over three of each.
    #[test]
    fn segment_resistance_adds_when_a_run_is_cut_in_half() {
        for sheet in [0.05, 1.0, 42.0] {
            for width in [3_i64, 250, 90_000] {
                let whole = segment_resistance(sheet, dbu(15_000), dbu(width)).raw();
                let half = segment_resistance(sheet, dbu(7_500), dbu(width)).raw();
                assert_close_relative("a run cut in half", whole, 2.0 * half, 1e-12);
            }
        }
    }

    /// Oracle: law. Widening a conductor lowers its resistance in exact proportion,
    /// because width is the denominator of the square count.
    #[test]
    fn doubling_conductor_width_halves_its_resistance() {
        let narrow = segment_resistance(0.7, dbu(5_000), dbu(250)).raw();
        let wide = segment_resistance(0.7, dbu(5_000), dbu(500)).raw();
        assert_close_relative("twice the width", wide, narrow / 2.0, 1e-12);
    }

    /// Oracle: closed form. A five ohm cut is five ohms on its own and one and a
    /// quarter ohms in a four-cut array, because cuts are resistors in parallel.
    /// That division is why a redundant via helps, and why the count has to come
    /// from the geometry instead of being assumed to be one.
    #[test]
    fn via_resistance_divides_by_the_number_of_cuts() {
        assert_close("one cut", via_resistance(5.0, 1).raw(), 5.0, 1e-12);
        assert_close("a redundant pair", via_resistance(5.0, 2).raw(), 2.5, 1e-12);
        assert_close(
            "a two by two array",
            via_resistance(5.0, 4).raw(),
            1.25,
            1e-12,
        );
    }

    /// Oracle: law. Conductances add, so `n` cuts is `1 / n` of one cut for every
    /// `n`. Stated over a range because the three worked cases above would all pass
    /// against an implementation that special-cased the array sizes it had seen.
    #[test]
    fn via_conductance_adds_over_every_cut_count() {
        let one = via_resistance(3.3, 1).raw();
        for cuts in 1_u32..=64 {
            let many = via_resistance(3.3, cuts).raw();
            assert_close_relative("cuts in parallel", many * f64::from(cuts), one, 1e-12);
        }
    }

    /// Oracle: closed form. Writable as of the Testing-Phase, when
    /// `ground_capacitance` gained the `Grid` that turns its two database-unit
    /// arguments into the micrometres its two coefficients are stated per.
    ///
    /// A 4 µm by 9 µm plate on a 1 nm grid is 36 µm² of area and 26 µm of
    /// perimeter, so at 1.7 aF/µm² and 0.4 aF/µm the answer is
    /// `1.7 × 36 + 0.4 × 26 = 71.6` attofarads — `0.0716` femtofarads, which is the
    /// unit the return type names. The arithmetic is written out in the assertion
    /// and no implementation is consulted to know it. This is the one case that
    /// catches a formula off by the grid factor itself; every law below is blind to
    /// a uniform scale.
    #[test]
    fn a_four_by_nine_micrometre_plate_is_seventy_one_point_six_attofarads() {
        let c = ground_capacitance(
            1.7,
            0.4,
            DbuArea::new(4_000 * 9_000),
            dbu(2 * (4_000 + 9_000)),
            grid(),
        );
        assert_close(
            "36 um^2 at 1.7 aF/um^2 plus 26 um at 0.4 aF/um",
            c.raw(),
            0.0716,
            1e-12,
        );
    }

    /// Oracle: law. The doc comment defines ground capacitance as an area term plus
    /// a fringe term, so the two superpose: computing them together must equal
    /// computing each alone and adding. This holds whatever the unit convention
    /// turns out to be, and it fails against any implementation that couples them.
    #[test]
    fn ground_capacitance_superposes_its_area_and_fringe_terms() {
        let area = DbuArea::new(4_000 * 9_000);
        let perimeter = dbu(2 * (4_000 + 9_000));
        let both = ground_capacitance(1.7, 0.4, area, perimeter, grid()).raw();
        let area_only = ground_capacitance(1.7, 0.0, area, perimeter, grid()).raw();
        let fringe_only = ground_capacitance(0.0, 0.4, area, perimeter, grid()).raw();
        assert!(
            area_only > 0.0 && fringe_only > 0.0,
            "both terms must contribute: got {area_only} and {fringe_only}"
        );
        assert_close_relative("area plus fringe", both, area_only + fringe_only, 1e-12);
    }

    /// Oracle: law. Each term is its coefficient times a geometric quantity, so
    /// each is linear in its own coefficient and independent of the other's. Two
    /// scalings that must hold for any numbers at all.
    #[test]
    fn ground_capacitance_is_linear_in_each_deck_coefficient() {
        let area = DbuArea::new(2_500 * 2_500);
        let perimeter = dbu(4 * 2_500);
        let reference = ground_capacitance(1.0, 1.0, area, perimeter, grid()).raw();

        let area_share = ground_capacitance(1.0, 0.0, area, perimeter, grid()).raw();
        assert_close_relative(
            "three times the area coefficient",
            ground_capacitance(3.0, 1.0, area, perimeter, grid()).raw(),
            reference + 2.0 * area_share,
            1e-12,
        );

        let fringe_share = ground_capacitance(0.0, 1.0, area, perimeter, grid()).raw();
        assert_close_relative(
            "three times the fringe coefficient",
            ground_capacitance(1.0, 3.0, area, perimeter, grid()).raw(),
            reference + 2.0 * fringe_share,
            1e-12,
        );
    }

    /// Oracle: closed form, taken as a limit. The parallel-plate formula is what a
    /// real capacitor approaches as the plate grows relative to its edge, and the
    /// rate at which it approaches it is exact: for a square of side `s` the fringe
    /// term goes as the perimeter `4s` and the area term as `s²`, so their ratio is
    /// `4 / s` times whatever fixed factor the unit convention contributes. That
    /// factor cancels between two sides, which is the whole reason this is stated
    /// as a ratio of ratios rather than as an absolute bound — a thousandfold wider
    /// plate has a thousandth the fringe share, whatever a database unit turns out
    /// to be worth.
    ///
    /// The two terms are taken apart with the coefficients rather than by
    /// subtracting the total, so the share is computed at full precision instead of
    /// as the difference of two nearly equal numbers. Superposition is what makes
    /// that legitimate, and it is established on its own above.
    #[test]
    fn the_fringe_share_of_a_square_plate_falls_inversely_with_the_plate_side() {
        let share = |side: i64| {
            let area = DbuArea::new(i128::from(side) * i128::from(side));
            let perimeter = dbu(4 * side);
            let plate = ground_capacitance(1.0, 0.0, area, perimeter, grid()).raw();
            let fringe = ground_capacitance(0.0, 1.0, area, perimeter, grid()).raw();
            assert!(
                plate > 0.0 && fringe > 0.0,
                "a plate of side {side} has an area term of {plate} and a fringe term of {fringe}"
            );
            fringe / plate
        };

        let small = share(1_000);
        let large = share(1_000_000);
        let vast = share(1_000_000_000);
        assert!(
            small > large && large > vast,
            "the fringe share must fall with the plate side: {small}, {large}, {vast}"
        );
        assert_close_relative(
            "a thousandfold wider plate, from a thousand database units",
            small / large,
            1_000.0,
            1e-9,
        );
        assert_close_relative(
            "a thousandfold wider plate, from a million database units",
            large / vast,
            1_000.0,
            1e-9,
        );

        // And the limit itself: at a billion units on a side the total is the
        // parallel-plate value plus a correction of exactly `vast`, which the
        // ratios above have just pinned at four parts in a billion divided by
        // whatever a database unit is worth in the deck's length unit.
        let area = DbuArea::new(1_000_000_000_i128 * 1_000_000_000);
        let perimeter = dbu(4_000_000_000);
        let total = ground_capacitance(1.0, 1.0, area, perimeter, grid()).raw();
        let plate = ground_capacitance(1.0, 0.0, area, perimeter, grid()).raw();
        assert_close_relative("the parallel-plate limit", total / plate, 1.0 + vast, 1e-12);
    }

    /// Oracle: law. The coupling coefficient is stated per micrometre of facing
    /// length, so the result is proportional to that length and to the coefficient,
    /// and it falls with separation. Those three are the whole of what the doc
    /// comment claims, and none of them needs the unit convention resolved.
    #[test]
    fn coupling_capacitance_scales_with_facing_length_and_falls_with_separation() {
        let reference = coupling_capacitance(2.0, dbu(6_000), dbu(300), grid()).raw();
        assert!(
            reference > 0.0,
            "two facing conductors couple: got {reference}"
        );

        assert_close_relative(
            "twice the facing length",
            coupling_capacitance(2.0, dbu(12_000), dbu(300), grid()).raw(),
            2.0 * reference,
            1e-12,
        );
        assert_close_relative(
            "twice the coefficient",
            coupling_capacitance(4.0, dbu(6_000), dbu(300), grid()).raw(),
            2.0 * reference,
            1e-12,
        );

        let mut previous = f64::INFINITY;
        for separation in [100_i64, 300, 900, 2_700, 8_100] {
            let value = coupling_capacitance(2.0, dbu(6_000), dbu(separation), grid()).raw();
            assert!(
                value > 0.0 && value < previous,
                "coupling must fall strictly with separation: {value} at {separation} \
                 against {previous} one step closer"
            );
            previous = value;
        }
    }

    /// Oracle: construct-from-answer. The stack is dense and indexed directly by
    /// layer, so a four-row stack answers for layers zero to three and refuses
    /// everything above. The refusal is the half worth checking: the old
    /// implementation reached this through a hash map, and a layer silently missing
    /// is how one layer ends up extracted with another's coefficients.
    #[test]
    fn stack_row_is_the_layer_index_within_the_stack_and_nothing_outside_it() {
        let stack = ProcessStack {
            sheet_res_ohm_sq: vec![0.1; 4],
            ..ProcessStack::default()
        };
        for layer in 0_u16..4 {
            assert_eq!(
                stack_row(&stack, LayerId(layer)),
                Some(usize::from(layer)),
                "layer {layer} of a four-row stack"
            );
        }
        for layer in [4_u16, 5, 63, u16::MAX] {
            assert_eq!(
                stack_row(&stack, LayerId(layer)),
                None,
                "layer {layer} is beyond a four-row stack"
            );
        }
        assert_eq!(
            stack_row(&ProcessStack::default(), LayerId(0)),
            None,
            "an empty stack describes no layer"
        );
    }

    /// Oracle: definition (testing-plan F93). Net `X` is a bar drawn as two
    /// abutting pieces, one region, and a piece meeting the bar only at a
    /// corner, a second region; so `X` has nodes 0 and 1 and closes on 2, and
    /// `Y`, one bar, is node 3 and closes on 4. `node_rects` names each
    /// region's rectangle by the node `extract_into` gave it, and no closing
    /// node; read as one node per drawn polygon, `X`'s three polygons would
    /// have put `Y`'s bar on node 4.
    #[test]
    fn node_rects_names_the_nodes_extract_into_allocates() {
        use super::{extract_into, node_rects};
        use crate::network::NodeId;
        use crate::ParasiticNetwork;
        use gpurify_check::topology::net::extract_nets_into;
        use gpurify_check::topology::NetTable;
        use gpurify_geom::{Bbox, GeometryStoreBuilder, PolyId};
        use gpurify_ingest::deck::Connectivity;

        let boxes = [(0, 0, 4, 1), (4, 0, 8, 1), (8, 1, 12, 2), (0, 3, 4, 4)];
        let mut builder = GeometryStoreBuilder::default();
        for (xlo, ylo, xhi, yhi) in boxes {
            builder.push(
                LayerId(0),
                &[dbu(xlo), dbu(xhi), dbu(xhi), dbu(xlo)],
                &[dbu(ylo), dbu(ylo), dbu(yhi), dbu(yhi)],
            );
        }
        let (store, _) = builder.finish(1);
        let connectivity = Connectivity {
            conductors: vec![LayerId(0)],
            intra_layer_touch: true,
            ..Connectivity::default()
        };
        let mut nets = NetTable::default();
        extract_nets_into(&store, &connectivity, &mut nets);
        let stack = ProcessStack {
            thickness_nm: vec![1.0],
            height_nm: vec![1.0],
            sheet_res_ohm_sq: vec![1.0],
            area_cap_af_um2: vec![1.0],
            fringe_cap_af_um: vec![1.0],
            dielectric_k: vec![0.0],
        };
        let mut network = ParasiticNetwork::default();
        extract_into(&store, &nets, &connectivity, &stack, grid(), &mut network)
            .expect("described and rectilinear");
        let (x, y) = (nets.net_of(PolyId(0)), nets.net_of(PolyId(3)));
        assert_eq!(network.node_net, [x, x, x, y, y]);

        let b = |xlo, ylo, xhi, yhi| Bbox {
            xlo: dbu(xlo),
            ylo: dbu(ylo),
            xhi: dbu(xhi),
            yhi: dbu(yhi),
        };
        assert_eq!(
            node_rects(&store, &nets, &connectivity).expect("rectilinear"),
            [
                (NodeId(0), b(0, 0, 8, 1)),
                (NodeId(1), b(8, 1, 12, 2)),
                (NodeId(3), b(0, 3, 4, 4)),
            ]
        );
    }
}
