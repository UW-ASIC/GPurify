//! Closed-form extraction from the deck's process stack.
//!
//! Data in: every net's polygons, the conductor/via connectivity, the stack.
//! Data out: a canonical [`ParasiticNetwork`] — per polygon a series R and a
//! ground C, lateral and interlayer coupling C, and via R.

use crate::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_check::topology::{DeviceTable, NetId, NetTable};
use gpurify_geom::index::{candidate_pairs_into, cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::{ops, Bbox, GeometryStore, LayerId, PolyId};
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
pub fn segment_resistance(
    sheet_ohm_sq: f64,
    length: Dbu,
    width: Dbu,
) -> Qty<Resistance, { prefix::BASE }> {
    #[expect(clippy::cast_precision_loss, reason = "|Dbu| <= 2^40, exact in f64")]
    let squares = length.raw() as f64 / width.raw() as f64;
    Qty::new(sheet_ohm_sq * squares)
}

/// A via array's resistance: per-cut over the cut count (cuts are in parallel).
pub fn via_resistance(per_cut_ohm: f64, cuts: u32) -> Qty<Resistance, { prefix::BASE }> {
    Qty::new(per_cut_ohm / f64::from(cuts))
}

/// Capacitance to the plane beneath: `area × area_coeff + perimeter × fringe_coeff`.
///
/// Two separate products so `f(a, 0) + f(0, b) == f(a, b)` holds exactly.
pub fn ground_capacitance(
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
pub fn coupling_capacitance(
    coefficient_af_um: f64,
    facing_length: Dbu,
    separation: Dbu,
    grid: Grid,
) -> Qty<Capacitance, { prefix::FEMTO }> {
    let ratio = micrometres(facing_length, grid) / micrometres(separation, grid);
    Qty::new(coefficient_af_um * ratio / AF_PER_FF)
}

/// Extract the whole design into `out` (cleared), in canonical order.
///
/// Both coupling terms are parallel-plate lower bounds (no fringing).
/// `devices` is unused: the stack carries no device parasitics.
pub fn extract_into(
    store: &GeometryStore,
    nets: &NetTable,
    devices: &DeviceTable,
    connectivity: &Connectivity,
    stack: &ProcessStack,
    grid: Grid,
    out: &mut ParasiticNetwork,
) {
    let _ = devices;
    out.clear();

    // Ascending nets make `node_net` grouped-and-ascending.
    let net_count = u32::try_from(nets.net_count()).expect("a NetId is a u32");
    for net in 0..net_count {
        extract_net_into(store, nets, NetId(net), stack, grid, out);
    }
    let node_of = nodes_by_poly(store, nets);
    couple_into(store, nets, connectivity, stack, grid, &node_of, out);
    vias_into(store, connectivity, stack, &node_of, out);
    out.sort_canonical();
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

/// One coupling element between polygons on different nets, lower [`NetId`]
/// first. Non-positive or non-finite values are dropped.
fn push_coupling(
    nets: &NetTable,
    node_of: &[NodeId],
    a: PolyId,
    b: PolyId,
    femtofarads: f64,
    out: &mut ParasiticNetwork,
) {
    if !(femtofarads > 0.0 && femtofarads.is_finite()) {
        return;
    }
    let (lo, hi) = if nets.net_of(a) < nets.net_of(b) {
        (a, b)
    } else {
        (b, a)
    };
    out.push(
        node_of[lo.idx()],
        Some(node_of[hi.idx()]),
        Parasitic::CouplingCap(Qty::new(femtofarads)),
    );
}

/// Every polygon's node, by [`PolyId`], mirroring [`extract_net_into`]'s
/// allocation. Polygons on no net get `u32::MAX`.
fn nodes_by_poly(store: &GeometryStore, nets: &NetTable) -> Vec<NodeId> {
    let mut node_of = vec![NodeId(u32::MAX); store.poly_count()];
    let net_count = u32::try_from(nets.net_count()).expect("a NetId is a u32");
    let mut next = 0u32;
    for net in 0..net_count {
        let polys = nets.polys_of(NetId(net));
        for (offset, &poly) in polys.iter().enumerate() {
            let node = next + u32::try_from(offset).expect("a net's polygon count is a u32");
            node_of[poly.idx()] = NodeId(node);
        }
        next += u32::try_from(polys.len()).expect("a net's polygon count is a u32")
            + u32::from(!polys.is_empty());
    }
    node_of
}

/// Lateral (same layer, within [`LATERAL_HALO_THICKNESSES`] × thickness) and
/// interlayer (overlapping) coupling. Appends.
fn couple_into(
    store: &GeometryStore,
    nets: &NetTable,
    connectivity: &Connectivity,
    stack: &ProcessStack,
    grid: Grid,
    node_of: &[NodeId],
    out: &mut ParasiticNetwork,
) {
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
                if nets.same_net(a, b) {
                    continue;
                }
                let Some((run, gap)) = facing(store.poly_bbox(a), store.poly_bbox(b)) else {
                    continue;
                };
                let femtofarads = coupling_capacitance(coefficient, run, gap, grid).raw();
                push_coupling(nets, node_of, a, b, femtofarads, out);
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
                if nets.same_net(a, b) {
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
                push_coupling(nets, node_of, a, b, femtofarads, out);
            }
        }
    }
}

/// Via resistance. Appends.
///
/// Cuts are grouped by the sorted `(lower, upper)` plate pair they join; each
/// group is one resistor at per-cut / count (parallel, not series).
fn vias_into(
    store: &GeometryStore,
    connectivity: &Connectivity,
    stack: &ProcessStack,
    node_of: &[NodeId],
    out: &mut ParasiticNetwork,
) {
    const NO_POLY: PolyId = PolyId(u32::MAX);

    let mut cut_index = SpatialIndex::default();
    let mut plate_index = SpatialIndex::default();
    let mut pairs = Vec::new();
    // Indexed by the cut's PolyId; a cut missing a plate keeps the sentinel.
    let mut below = vec![NO_POLY; store.poly_count()];
    let mut above = vec![NO_POLY; store.poly_count()];
    let mut arrays: Vec<(PolyId, PolyId)> = Vec::new();

    for row in 0..connectivity.via_cut.len() {
        let cut_layer = connectivity.via_cut[row];
        let (lower, upper) = connectivity.via_connects[row];
        let Some(cut_row) = stack_row(stack, cut_layer) else {
            continue;
        };
        let per_cut_ohm = stack.sheet_res_ohm_sq.get(cut_row).copied().unwrap_or(0.0);
        if !(per_cut_ohm > 0.0 && per_cut_ohm.is_finite()) {
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
                let slot = &mut landing[cut.idx()];
                *slot = PolyId(slot.0.min(plate.0));
            }
        }

        arrays.clear();
        for cut in store.polys_on_layer(cut_layer) {
            let (lo, hi) = (below[cut as usize], above[cut as usize]);
            if lo != NO_POLY && hi != NO_POLY {
                arrays.push((lo, hi));
            }
            below[cut as usize] = NO_POLY;
            above[cut as usize] = NO_POLY;
        }
        arrays.sort_unstable();

        for group in arrays.chunk_by(|a, b| a == b) {
            let key = group[0];
            let cuts = u32::try_from(group.len()).expect("a via array's cut count is a u32");
            let ohm = via_resistance(per_cut_ohm, cuts).raw();
            if ohm > 0.0 && ohm.is_finite() {
                let (from, to) = (node_of[key.0.idx()], node_of[key.1.idx()]);
                out.push(from, Some(to), Parasitic::Resistance(Qty::new(ohm)));
            }
        }
    }
}

/// One net's nodes and per-polygon R and ground C. Appends.
///
/// A net of `n` polygons gets `n + 1` boundary nodes; polygon `i` is a resistor
/// from node `i` to `i + 1` plus a ground C on node `i`, chained in [`PolyId`]
/// order (a comb's fingers come out in series; the net total is unchanged).
/// Length and width are the sides of the rectangle with the ring's area and
/// perimeter, the roots of `t² − (P/2)t + A`.
pub fn extract_net_into(
    store: &GeometryStore,
    nets: &NetTable,
    net: NetId,
    stack: &ProcessStack,
    grid: Grid,
    out: &mut ParasiticNetwork,
) {
    let polys = nets.polys_of(net);
    let base = u32::try_from(out.node_net.len()).expect("a NodeId is a u32");
    let count = u32::try_from(polys.len()).expect("a net's polygon count is a u32");
    // Release check: a wrapped NodeId would alias another net's node.
    base.checked_add(count + u32::from(!polys.is_empty()))
        .expect("the node columns of one network fit a NodeId");

    let mut node = NodeId(base);
    let mut last_layer = LayerId(0);
    for &poly in polys {
        let layer = store.poly_layer(poly);
        out.node_net.push(net);
        out.node_layer.push(layer);
        last_layer = layer;

        // An undescribed layer reads zero coefficients; the guards below drop them.
        let row = stack_row(stack, layer).unwrap_or(usize::MAX);
        let sheet_ohm_sq = stack.sheet_res_ohm_sq.get(row).copied().unwrap_or(0.0);
        let area_af_um2 = stack.area_cap_af_um2.get(row).copied().unwrap_or(0.0);
        let fringe_af_um = stack.fringe_cap_af_um.get(row).copied().unwrap_or(0.0);

        let (xs, ys) = store.poly_verts(poly);
        let area = DbuArea::new(ops::area2(xs, ys).raw().abs() / 2);

        // Seeded with the last vertex so the closing edge is counted.
        let mut previous = (
            xs.last().copied().unwrap_or(Dbu::new_unchecked(0)),
            ys.last().copied().unwrap_or(Dbu::new_unchecked(0)),
        );
        let mut perimeter = Dbu::new_unchecked(0);
        for (&x, &y) in xs.iter().zip(ys) {
            // Widened: two coordinates can differ by 2^41.
            let dx = i128::from(x.raw() - previous.0.raw());
            let dy = i128::from(y.raw() - previous.1.raw());
            perimeter = perimeter + ops::isqrt(DbuArea::new(dx * dx + dy * dy));
            previous = (x, y);
        }

        // A negative discriminant (too fat for a rectangle) lands on one square.
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
        let femtofarads =
            ground_capacitance(area_af_um2, fringe_af_um, area, perimeter, grid).raw();

        // Ground first is canonical order. Zero values are dropped: a zero-ohm
        // resistor is a short.
        if femtofarads > 0.0 && femtofarads.is_finite() {
            out.push(node, None, Parasitic::GroundCap(Qty::new(femtofarads)));
        }
        if ohm > 0.0 && ohm.is_finite() {
            out.push(
                node,
                Some(NodeId(node.0 + 1)),
                Parasitic::Resistance(Qty::new(ohm)),
            );
        }
        node = NodeId(node.0 + 1);
    }

    // The closing boundary node.
    if !polys.is_empty() {
        out.node_net.push(net);
        out.node_layer.push(last_layer);
    }
}

/// A layer's process-stack row, or `None` past the stack.
pub fn stack_row(stack: &ProcessStack, layer: LayerId) -> Option<usize> {
    let row = layer.idx();
    (row < stack.sheet_res_ohm_sq.len()).then_some(row)
}
