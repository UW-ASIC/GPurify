//! Closed-form extraction from the deck's process stack.

use crate::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_core::index::{candidate_pairs_into, cross_layer_pairs_into, SpatialIndex};
use gpurify_core::{ops, Bbox, GeometryStore, LayerId, PolyId};
use gpurify_ingest::deck::{Connectivity, ProcessStack};
use gpurify_topology::{DeviceTable, NetId, NetTable};
use gpurify_units::{prefix, Capacitance, Dbu, DbuArea, Grid, Qty, Resistance, MAX_ABS_DBU};

/// Attofarads in a femtofarad. Divided by, never multiplied by `1e-3`, which is
/// not exact in `f64`.
const AF_PER_FF: f64 = 1_000.0;

/// Vacuum permittivity, in attofarads per micrometre (CODATA 2018).
const EPSILON0_AF_PER_UM: f64 = 8.854_187_812_8;

/// Nanometres in a micrometre.
const NM_PER_UM: f64 = 1_000.0;

/// How far a conductor couples laterally, as a multiple of its own thickness.
///
/// ponytail: a fixed multiple, because no deck in this tree states a coupling
/// halo. Too large is quadratic on a dense layer, too small drops real coupling
/// (the fail-open direction). Upgrade path: a `coupling_halo_nm` in the deck's
/// `pex` section.
const LATERAL_HALO_THICKNESSES: f64 = 10.0;

/// A coordinate as micrometres, the unit every deck coefficient is stated per.
#[inline]
fn micrometres(value: Dbu, grid: Grid) -> f64 {
    debug_assert!(grid.dbu_per_um() > 0, "a Grid is positive by construction");
    debug_assert!(
        value.raw().unsigned_abs() <= MAX_ABS_DBU.unsigned_abs(),
        "a length past the coordinate domain: {}",
        value.raw()
    );

    #[expect(
        clippy::cast_precision_loss,
        reason = "|Dbu| <= 2^40 and a resolution is a small count; both exact in f64"
    )]
    let um = value.raw() as f64 / grid.dbu_per_um() as f64;
    debug_assert!(um.is_finite(), "a bounded coordinate over a positive grid");
    um
}

/// An area as square micrometres.
#[inline]
fn square_micrometres(value: gpurify_units::DbuArea, grid: Grid) -> f64 {
    debug_assert!(grid.dbu_per_um() > 0, "a Grid is positive by construction");
    // The bound `Bbox::area` states.
    debug_assert!(
        value.raw().unsigned_abs() <= 1u128 << 82,
        "an area past the 2^82 ceiling"
    );

    #[expect(
        clippy::cast_precision_loss,
        reason = "the caller's oracle is a coefficient times this area; f64 is the output type"
    )]
    let raw = value.raw() as f64;
    #[expect(
        clippy::cast_precision_loss,
        reason = "a resolution is a small count, exact in f64"
    )]
    let per_um = grid.dbu_per_um() as f64;
    let um2 = raw / (per_um * per_um);
    debug_assert!(um2.is_finite(), "a bounded area over a positive grid");
    um2
}

/// Series resistance of a conductor run: `sheet_resistance × length / width`.
pub fn segment_resistance(
    sheet_ohm_sq: f64,
    length: gpurify_units::Dbu,
    width: gpurify_units::Dbu,
) -> Qty<Resistance, { prefix::BASE }> {
    debug_assert!(
        sheet_ohm_sq.is_finite() && sheet_ohm_sq >= 0.0,
        "a sheet resistance is a finite non-negative number, not {sheet_ohm_sq}"
    );
    debug_assert!(
        length.raw() >= 0 && length.raw().unsigned_abs() <= MAX_ABS_DBU.unsigned_abs(),
        "a conductor run is a non-negative in-domain length, not {}",
        length.raw()
    );
    // Fail closed: a zero-width conductor is not a wire, and `f64` would hand
    // back an infinity plus every sum downstream of it.
    debug_assert!(
        length.raw() >= 0
            && width.raw() > 0
            && width.raw().unsigned_abs() <= MAX_ABS_DBU.unsigned_abs(),
        "a conductor has a positive in-domain width, not {}",
        width.raw()
    );

    #[expect(
        clippy::cast_precision_loss,
        reason = "|Dbu| <= 2^40 < 2^53, so both operands are exact in f64"
    )]
    let squares = length.raw() as f64 / width.raw() as f64;
    let ohm = sheet_ohm_sq * squares;

    debug_assert!(
        ohm.is_finite() && ohm >= 0.0,
        "{sheet_ohm_sq} ohm/sq over {squares} squares is {ohm}, which is not a conductor"
    );
    Qty::new(ohm)
}

/// Resistance of a via or contact cut: the per-cut constant over the number of
/// cuts in the array, because cuts conduct in parallel.
pub fn via_resistance(per_cut_ohm: f64, cuts: u32) -> Qty<Resistance, { prefix::BASE }> {
    debug_assert!(
        per_cut_ohm.is_finite() && per_cut_ohm >= 0.0,
        "a per-cut resistance is a finite non-negative number, not {per_cut_ohm}"
    );
    // A via array with no cuts is an open circuit, not a via.
    debug_assert!(cuts > 0, "a via array has at least one cut");

    let ohm = per_cut_ohm / f64::from(cuts);

    debug_assert!(
        ohm.is_finite() && ohm >= 0.0,
        "{per_cut_ohm} ohm over {cuts} cuts is {ohm}, which is not a via"
    );
    Qty::new(ohm)
}

/// Capacitance from a conductor to the plane beneath it: `area × area_coeff +
/// perimeter × fringe_coeff`.
///
/// The deck's coefficients are per micrometre while `area` and `perimeter` are
/// grid indices, so `grid` closes the unit chain.
pub fn ground_capacitance(
    area_af_um2: f64,
    fringe_af_um: f64,
    area: gpurify_units::DbuArea,
    perimeter: gpurify_units::Dbu,
    grid: Grid,
) -> Qty<Capacitance, { prefix::FEMTO }> {
    debug_assert!(
        area_af_um2.is_finite() && area_af_um2 >= 0.0,
        "an area coefficient is a finite non-negative number, not {area_af_um2}"
    );
    debug_assert!(
        fringe_af_um.is_finite() && fringe_af_um >= 0.0,
        "a fringe coefficient is a finite non-negative number, not {fringe_af_um}"
    );
    debug_assert!(area.raw() >= 0, "a conductor's area is non-negative");
    debug_assert!(
        perimeter.raw() >= 0,
        "a conductor's perimeter is non-negative"
    );

    // Superposition is an interface promise: `f(a, 0) + f(0, b) == f(a, b)`,
    // so the two terms stay separate products rather than one fused expression.
    let plate = area_af_um2 * square_micrometres(area, grid);
    let fringe = fringe_af_um * micrometres(perimeter, grid);
    let femtofarads = (plate + fringe) / AF_PER_FF;

    debug_assert!(
        femtofarads.is_finite() && femtofarads >= 0.0,
        "{plate} aF of plate plus {fringe} aF of fringe is {femtofarads} fF"
    );
    Qty::new(femtofarads)
}

/// Capacitance between two neighbouring conductors: `k × L / S`.
///
/// `coefficient_af_um` is per micrometre of facing length at one micrometre of
/// separation; `grid` converts both lengths to micrometres.
pub fn coupling_capacitance(
    coefficient_af_um: f64,
    facing_length: gpurify_units::Dbu,
    separation: gpurify_units::Dbu,
    grid: Grid,
) -> Qty<Capacitance, { prefix::FEMTO }> {
    debug_assert!(
        coefficient_af_um.is_finite() && coefficient_af_um >= 0.0,
        "a coupling coefficient is a finite non-negative number, not {coefficient_af_um}"
    );
    debug_assert!(
        facing_length.raw() >= 0,
        "a facing length is non-negative, not {}",
        facing_length.raw()
    );
    // Two conductors at zero separation are one conductor, and the reciprocal
    // says so with an infinity that would poison every net total it lands in.
    debug_assert!(
        separation.raw() > 0,
        "two distinct conductors are separated by at least one database unit"
    );

    let ratio = micrometres(facing_length, grid) / micrometres(separation, grid);
    let femtofarads = coefficient_af_um * ratio / AF_PER_FF;

    debug_assert!(
        femtofarads.is_finite() && femtofarads >= 0.0,
        "{coefficient_af_um} aF/um over a facing ratio of {ratio} is {femtofarads} fF"
    );
    Qty::new(femtofarads)
}

/// Extract the whole design analytically.
///
/// Caller owns `out`, cleared and refilled. Nets are processed in ascending
/// [`NetId`] order and coupling is emitted once per pair, by the lower one.
///
/// Both coupling terms are parallel-plate limits — `ε₀ · k · t · L / S`
/// laterally, `ε₀ · k · A / d` between layers — so they are a deliberate *lower*
/// bound: fringing adds to both, and `crate::quasistatic` carries it.
pub fn extract_into(
    store: &GeometryStore,
    nets: &NetTable,
    devices: &DeviceTable,
    connectivity: &Connectivity,
    stack: &ProcessStack,
    grid: Grid,
    out: &mut ParasiticNetwork,
) {
    // A ragged stack would hand one layer another layer's coefficients for the
    // columns that are long enough and zero for the rest — a wrong parasitic
    // rather than a missing one.
    debug_assert!(grid.dbu_per_um() > 0, "a Grid is positive by construction");
    let rows = stack.sheet_res_ohm_sq.len();
    debug_assert_eq!(
        stack.area_cap_af_um2.len(),
        rows,
        "one area coefficient per stack row"
    );
    debug_assert_eq!(
        stack.fringe_cap_af_um.len(),
        rows,
        "one fringe coefficient per stack row"
    );

    out.clear();

    let net_count = u32::try_from(nets.net_count()).expect("a NetId is a u32");

    // Ascending is load-bearing twice: it makes `node_net`
    // grouped-and-ascending as `ParasiticNetwork` documents, and makes the
    // emitted element order the one `sort_canonical` would have produced.
    for net in 0..net_count {
        extract_net_into(store, nets, NetId(net), stack, grid, out);
    }
    extract_devices_into(devices, stack, grid, out);
    // After every net has its nodes, so a pair's higher net has somewhere to land.
    let node_of = nodes_by_poly(store, nets, out);
    couple_into(store, nets, connectivity, stack, grid, &node_of, out);
    vias_into(store, connectivity, stack, &node_of, out);
    // `couple_into` appends by layer pair, not by `from`.
    out.sort_canonical();

    debug_assert_eq!(
        out.node_net.len(),
        out.node_layer.len(),
        "the node columns must stay parallel"
    );
    debug_assert_eq!(
        out.from.len(),
        out.to.len(),
        "the element columns must stay parallel"
    );
    debug_assert_eq!(
        out.from.len(),
        out.value.len(),
        "the element columns must stay parallel"
    );
    debug_assert!(
        out.node_net.len() <= store.poly_count() + nets.net_count(),
        "one node per conductor polygon plus one closing boundary per net at \
         most, {} against {} + {}",
        out.node_net.len(),
        store.poly_count(),
        nets.net_count()
    );
    debug_assert!(
        out.node_net.is_sorted(),
        "every net's nodes are one contiguous ascending range"
    );
    debug_assert!(
        out.from.is_sorted(),
        "elements are emitted in the `from`-ascending order `sort_canonical` produces"
    );
}

/// How two boxes on one layer face each other: the run they share, and the gap
/// they share it across. `None` for corner-to-corner and for an overlap.
///
/// Bounding boxes push capacitance up, the fail-closed direction for delay.
fn facing(a: Bbox, b: Bbox) -> Option<(Dbu, Dbu)> {
    let along_x = a.xhi.raw().min(b.xhi.raw()) - a.xlo.raw().max(b.xlo.raw());
    let along_y = a.yhi.raw().min(b.yhi.raw()) - a.ylo.raw().max(b.ylo.raw());

    // They face across the axis they are disjoint on, and run along the other.
    // Both positive is an overlap; neither positive is a corner.
    let (run, gap) = match (along_x > 0, along_y > 0) {
        (true, false) => (along_x, -along_y),
        (false, true) => (along_y, -along_x),
        _ => return None,
    };
    // Zero gap is two touching conductors, which is one conductor;
    // `coupling_capacitance` refuses the infinity it would produce.
    (gap > 0).then(|| (Dbu::new_unchecked(run), Dbu::new_unchecked(gap)))
}

/// One stack row's lateral coupling coefficient, `ε₀ · k · t`, in the units
/// [`coupling_capacitance`] reads.
fn lateral_coefficient(stack: &ProcessStack, row: usize) -> f64 {
    let k = stack.dielectric_k.get(row).copied().unwrap_or(0.0);
    let thickness_um = stack.thickness_nm.get(row).copied().unwrap_or(0.0) / NM_PER_UM;
    EPSILON0_AF_PER_UM * k * thickness_um
}

/// Dielectric thickness between the top of `lower` and the bottom of `upper`,
/// in micrometres, or `None` when they do not stack in that order.
///
/// `height_nm` is a layer's *bottom*, so the gap is
/// `height(upper) − (height(lower) + thickness(lower))`.
fn interlayer_gap_um(stack: &ProcessStack, lower: usize, upper: usize) -> Option<f64> {
    let top_of_lower = stack.height_nm.get(lower).copied().unwrap_or(0.0)
        + stack.thickness_nm.get(lower).copied().unwrap_or(0.0);
    let bottom_of_upper = stack.height_nm.get(upper).copied().unwrap_or(0.0);
    let gap_nm = bottom_of_upper - top_of_lower;
    (gap_nm > 0.0).then_some(gap_nm / NM_PER_UM)
}

/// Emit one coupling element between two polygons on different nets, the lower
/// [`NetId`]'s node first so no pair is counted twice.
fn push_coupling(
    nets: &NetTable,
    node_of: &[NodeId],
    a: PolyId,
    b: PolyId,
    femtofarads: f64,
    out: &mut ParasiticNetwork,
) {
    // A zero-farad row is one every reader downstream has to skip.
    if !(femtofarads > 0.0 && femtofarads.is_finite()) {
        return;
    }
    let (lo, hi) = if nets.net_of(a) < nets.net_of(b) {
        (a, b)
    } else {
        (b, a)
    };
    let (from, to) = (node_of[lo.idx()], node_of[hi.idx()]);
    debug_assert_ne!(from, to, "a coupling element joins a node to itself");
    out.push(
        from,
        Some(to),
        Parasitic::CouplingCap(Qty::new(femtofarads)),
    );
}

/// Every conductor polygon's node, indexed by [`PolyId`].
///
/// Mirrors the allocation [`extract_net_into`] performs and must stay in step
/// with it. Polygons on no net keep a `u32::MAX` sentinel, which indexes out of
/// bounds rather than aliasing node zero.
fn nodes_by_poly(store: &GeometryStore, nets: &NetTable, out: &ParasiticNetwork) -> Vec<NodeId> {
    const NO_NODE: NodeId = NodeId(u32::MAX);

    let mut node_of = vec![NO_NODE; store.poly_count()];
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

    debug_assert!(
        node_of.iter().enumerate().all(|(poly, &node)| {
            node == NO_NODE
                || out.node_net[node.0 as usize]
                    == nets.net_of(PolyId(u32::try_from(poly).expect("a PolyId is a u32")))
        }),
        "the node map disagrees with the node column `extract_net_into` wrote"
    );
    node_of
}

/// Lateral and interlayer coupling, appended to a network whose nodes exist.
///
/// Appends; does not clear. Two scans: same-layer at
/// [`LATERAL_HALO_THICKNESSES`] times the thickness, and cross-layer at zero
/// distance. A pair is only ever one of the two, so no term is counted twice.
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
            // Undescribed layer: no thickness, no `k`, no limit to state.
            continue;
        };
        let coefficient = lateral_coefficient(stack, row);
        #[expect(
            clippy::cast_precision_loss,
            reason = "a resolution is a small count, exact in f64"
        )]
        let per_um = grid.dbu_per_um() as f64;
        let thickness_dbu =
            stack.thickness_nm.get(row).copied().unwrap_or(0.0) * per_um / NM_PER_UM;
        #[expect(
            clippy::cast_precision_loss,
            reason = "MAX_ABS_DBU is 2^40, exactly representable in f64"
        )]
        let ceiling = MAX_ABS_DBU as f64;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "clamped to the coordinate domain by the `min` on the same line"
        )]
        let halo = (thickness_dbu * LATERAL_HALO_THICKNESSES).min(ceiling) as i64;

        if coefficient > 0.0 && halo > 0 {
            SpatialIndex::build_into(store, layer, &mut index_a);
            candidate_pairs_into(store, &index_a, Dbu::new_unchecked(halo), &mut pairs);
            for &(a, b) in &pairs {
                // Two polygons of one net are one conductor.
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

        // `position + 1..` visits a pair once; which is lower comes from the
        // stack's heights, not the deck's declaration order.
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
            // `ground_capacitance` with a zero fringe term is the parallel-plate
            // form, and it already carries the `Grid` conversion.
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

/// Via and contact resistance, appended to a network whose nodes exist.
///
/// A cut is an *element*, not a node: one resistor between the conductor below
/// it and the one above. Cuts are grouped by the sorted `(lower, upper)`
/// [`PolyId`] pair they join and each group emits one element carrying the
/// group's count — one resistor per cut would put them in series and make a
/// redundant via worse than a single one.
fn vias_into(
    store: &GeometryStore,
    connectivity: &Connectivity,
    stack: &ProcessStack,
    node_of: &[NodeId],
    out: &mut ParasiticNetwork,
) {
    /// Sentinel for a cut that landed on no plate on one side; the guard below
    /// drops it rather than joining it to polygon zero.
    const NO_POLY: PolyId = PolyId(u32::MAX);

    debug_assert_eq!(
        connectivity.via_cut.len(),
        connectivity.via_connects.len(),
        "one conductor pair per via row"
    );

    let mut cut_index = SpatialIndex::default();
    let mut plate_index = SpatialIndex::default();
    let mut pairs = Vec::new();
    // Indexed by the cut's own `PolyId`, so a cut that lands on neither plate
    // keeps its sentinel and is dropped rather than joined to node zero.
    let mut below = vec![NO_POLY; store.poly_count()];
    let mut above = vec![NO_POLY; store.poly_count()];
    let mut arrays: Vec<(PolyId, PolyId)> = Vec::new();

    for row in 0..connectivity.via_cut.len() {
        let cut_layer = connectivity.via_cut[row];
        let (lower, upper) = connectivity.via_connects[row];
        let Some(cut_row) = stack_row(stack, cut_layer) else {
            // Undescribed cut layer: no per-cut resistance to state.
            continue;
        };
        let per_cut_ohm = stack.sheet_res_ohm_sq.get(cut_row).copied().unwrap_or(0.0);
        if !(per_cut_ohm > 0.0 && per_cut_ohm.is_finite()) {
            continue;
        }

        SpatialIndex::build_into(store, cut_layer, &mut cut_index);
        // `cross_layer_pairs_into` emits `(a, b)` with `a` from the first index,
        // so the cut is always first and the plate second.
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
                // Lowest wins, so a cut straddling two plates picks the same one
                // whatever order the index emitted them in.
                let slot = &mut landing[cut.idx()];
                *slot = PolyId(slot.0.min(plate.0));
            }
        }

        // Sorted so the groups below are contiguous and ordered by geometry.
        arrays.clear();
        for cut in store.polys_on_layer(cut_layer) {
            let (lo, hi) = (below[cut as usize], above[cut as usize]);
            // A cut with no plate on one side carries no current.
            if lo != NO_POLY && hi != NO_POLY {
                arrays.push((lo, hi));
            }
            below[cut as usize] = NO_POLY;
            above[cut as usize] = NO_POLY;
        }
        arrays.sort_unstable();

        let mut at = 0usize;
        while at < arrays.len() {
            let key = arrays[at];
            let mut end = at;
            while end < arrays.len() && arrays[end] == key {
                end += 1;
            }
            let cuts = u32::try_from(end - at).expect("a via array's cut count is a u32");
            let ohm = via_resistance(per_cut_ohm, cuts).raw();
            let (from, to) = (node_of[key.0.idx()], node_of[key.1.idx()]);
            debug_assert_ne!(from, to, "a via joins two different conductor polygons");
            if ohm > 0.0 && ohm.is_finite() {
                out.push(from, Some(to), Parasitic::Resistance(Qty::new(ohm)));
            }
            at = end;
        }
    }
}

/// Extract one net's parasitics. **Appends. Does not clear `out`.**
///
/// Nodes sit at segment *boundaries*: a net of `n` polygons gets `n + 1` nodes,
/// and polygon `i` is one resistor from node `i` to node `i + 1` carrying its
/// whole series resistance, plus a ground capacitance on node `i`. So a net's
/// emitted resistance is exactly the sum of its polygons' resistances.
///
/// Dimensions come off the vertex ring, not the bounding box; the resistive
/// length and width are the sides of the rectangle with that area and perimeter,
/// the roots of `t² − (P/2)t + A`.
///
/// Nodes are chained in [`PolyId`] order rather than by which polygons touch, so
/// a comb's fingers come out in series where they are really parallel stubs.
/// Every polygon's resistance still appears exactly once, so a net's total is
/// unchanged; what moves is where along the net it sits.
pub fn extract_net_into(
    store: &GeometryStore,
    nets: &NetTable,
    net: NetId,
    stack: &ProcessStack,
    grid: Grid,
    out: &mut ParasiticNetwork,
) {
    debug_assert_eq!(
        out.node_net.len(),
        out.node_layer.len(),
        "the node columns arrive parallel"
    );
    debug_assert_eq!(
        out.from.len(),
        out.value.len(),
        "the element columns arrive parallel"
    );

    let polys = nets.polys_of(net);
    let base = u32::try_from(out.node_net.len()).expect("a NodeId is a u32");
    let count = u32::try_from(polys.len()).expect("a net's polygon count is a u32");
    // An empty net gets no node at all.
    let nodes = count + u32::from(!polys.is_empty());
    // Every profile, not `debug_assert`: a `NodeId` that wrapped would name an
    // existing node of another net, and every element written against it would
    // read as a legitimate parasitic on the wrong conductor.
    let end = base
        .checked_add(nodes)
        .expect("the node columns of one network fit a NodeId");

    out.node_net.reserve(nodes as usize);
    out.node_layer.reserve(nodes as usize);

    let mut node = NodeId(base);
    // The closing node inherits the last polygon's layer. The seed is only read
    // when `polys` is empty, and then the push it feeds does not happen.
    let mut last_layer = LayerId(0);
    for &poly in polys {
        let layer = store.poly_layer(poly);
        out.node_net.push(net);
        out.node_layer.push(layer);
        last_layer = layer;

        // An undescribed layer contributes zero coefficients, and the emission
        // guards below drop its elements rather than writing a zero parasitic.
        let row = stack_row(stack, layer).unwrap_or(usize::MAX);
        let sheet_ohm_sq = stack.sheet_res_ohm_sq.get(row).copied().unwrap_or(0.0);
        let area_af_um2 = stack.area_cap_af_um2.get(row).copied().unwrap_or(0.0);
        let fringe_af_um = stack.fringe_cap_af_um.get(row).copied().unwrap_or(0.0);

        // `area2` is the shoelace and returns twice the signed area; the halving
        // truncates by at most half a square database unit.
        let (xs, ys) = store.poly_verts(poly);
        let area = DbuArea::new(ops::area2(xs, ys).raw().abs() / 2);

        // Seeded with the *last* vertex so the ring's closing edge is the fold's
        // first term. Checked equal rather than zipped to the shorter: a short
        // ring would drop an edge and understate the perimeter, which reads
        // downstream as a smaller capacitance rather than as a fault.
        debug_assert_eq!(xs.len(), ys.len(), "a vertex ring's columns must agree");
        let mut previous = (
            xs.last().copied().unwrap_or(Dbu::new_unchecked(0)),
            ys.last().copied().unwrap_or(Dbu::new_unchecked(0)),
        );
        let mut perimeter = Dbu::new_unchecked(0);
        for (&x, &y) in xs.iter().zip(ys) {
            // Widened before squaring: two in-domain coordinates differ by up
            // to `2^41`, past `Dbu::mul_wide`'s operand precondition.
            let dx = i128::from(x.raw() - previous.0.raw());
            let dy = i128::from(y.raw() - previous.1.raw());
            perimeter = perimeter + ops::isqrt(DbuArea::new(dx * dx + dy * dy));
            previous = (x, y);
        }

        // `max(0)` on the discriminant is the shape too fat for a real root — a
        // disc — and lands on `long == short`, one square.
        let half = perimeter.raw() / 2;
        let discriminant = i128::from(half) * i128::from(half) - 4 * area.raw();
        let spread = ops::isqrt(DbuArea::new(discriminant.max(0))).raw();
        debug_assert!(
            spread <= half,
            "a non-negative area cannot spread the sides past their own sum"
        );
        let long = Dbu::new_unchecked(i64::midpoint(half, spread));
        let short = Dbu::new_unchecked((half - spread) / 2);
        debug_assert!(
            short.raw() >= 0 && short.raw() <= long.raw(),
            "the equivalent rectangle is {} by {}",
            long.raw(),
            short.raw()
        );

        // `segment_resistance` needs a positive width, and a degenerate figure —
        // which a derived layer can produce — is no conductor.
        let ohm = if short.raw() > 0 {
            segment_resistance(sheet_ohm_sq, long, short).raw()
        } else {
            0.0
        };
        let femtofarads =
            ground_capacitance(area_af_um2, fringe_af_um, area, perimeter, grid).raw();

        // Ground first *is* the canonical order: `canonical_key` maps
        // `to == None` to `0`, so emitting the capacitance second would need a
        // sort to undo. The guards keep zero-valued elements out — a zero-ohm
        // resistor is a short that changes the answer a simulator gives.
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

    // The closing boundary: the one node with no polygon of its own.
    if !polys.is_empty() {
        out.node_net.push(net);
        out.node_layer.push(last_layer);
    }

    debug_assert_eq!(
        out.node_net.len(),
        end as usize,
        "one node per polygon of the net, plus the closing boundary"
    );
    debug_assert_eq!(
        out.node_net.len(),
        out.node_layer.len(),
        "the node columns must stay parallel"
    );
    debug_assert_eq!(
        out.from.len(),
        out.value.len(),
        "the element columns must stay parallel"
    );
    debug_assert!(
        out.from.len() <= 2 * out.node_net.len(),
        "at most a ground capacitance and one series link per node"
    );
}

/// Parasitics intrinsic to a recognised device — gate capacitance, junction
/// capacitance, terminal resistance. **Appends. Does not clear `out`.**
///
/// Appends nothing, deliberately: the per-family constants are not in
/// [`ProcessStack`] and a device row names a marker [`PolyId`] rather than a
/// [`LayerId`], so not even the wrong coefficient is reachable. Inventing one
/// would put a number in a report that no deck stated. Upgrade path: a
/// `DeviceModel` table from the deck's device section, added to this signature.
pub fn extract_devices_into(
    devices: &DeviceTable,
    stack: &ProcessStack,
    grid: Grid,
    out: &mut ParasiticNetwork,
) {
    let rows = devices.len();
    debug_assert!(
        devices.terminal_start.len() == rows + 1 || devices.terminal_start.is_empty(),
        "the terminal CSR carries one offset per device plus a terminator"
    );
    debug_assert!(
        devices.param_start.len() == rows + 1 || devices.param_start.is_empty(),
        "the parameter CSR carries one offset per device plus a terminator"
    );
    debug_assert_eq!(
        devices.terminal_net.len(),
        devices.terminal_role.len(),
        "a net column and a role column arrive parallel"
    );
    debug_assert!(grid.dbu_per_um() > 0, "a Grid is positive by construction");
    debug_assert_eq!(
        stack.area_cap_af_um2.len(),
        stack.fringe_cap_af_um.len(),
        "the process stack's columns arrive parallel"
    );

    // `let _ = out` rather than `_out`: the name is part of the frozen
    // signature and of what a caller reads in the docs.
    let _ = out;
}

/// Which process-stack row a layer uses, indexed directly by [`LayerId`].
///
/// An array index and not a hash map, for determinism rather than speed.
pub fn stack_row(stack: &ProcessStack, layer: LayerId) -> Option<usize> {
    let rows = stack.sheet_res_ohm_sq.len();
    debug_assert_eq!(
        stack.thickness_nm.len(),
        rows,
        "one thickness per stack row"
    );
    debug_assert_eq!(stack.height_nm.len(), rows, "one height per stack row");
    debug_assert_eq!(
        stack.area_cap_af_um2.len(),
        rows,
        "one area coefficient per stack row"
    );
    debug_assert_eq!(
        stack.fringe_cap_af_um.len(),
        rows,
        "one fringe coefficient per stack row"
    );
    debug_assert_eq!(
        stack.dielectric_k.len(),
        rows,
        "one permittivity per stack row"
    );

    // Fail closed: a layer past the stack is `None`, never a wrapped or clamped
    // row holding another layer's coefficients.
    let row = layer.idx();
    (row < rows).then_some(row)
}
