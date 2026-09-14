//! Closed-form extraction from the deck's process stack.
//!
//! Each function here is a formula with a known analytic answer, which makes
//! this the easiest module in the tree to test: a rectangle of known dimensions
//! on a layer of known sheet resistance has exactly one right answer, and a
//! parallel-plate pair has another. No reference implementation is needed and
//! none is wanted.

use crate::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_core::index::{candidate_pairs_into, cross_layer_pairs_into, SpatialIndex};
use gpurify_core::{ops, Bbox, GeometryStore, LayerId, PolyId};
use gpurify_ingest::deck::{Connectivity, ProcessStack};
use gpurify_topology::{DeviceTable, NetId, NetTable};
use gpurify_units::{prefix, Capacitance, Dbu, DbuArea, Grid, Qty, Resistance, MAX_ABS_DBU};

/// Attofarads in a femtofarad.
///
/// The deck states its capacitive coefficients in attofarads and
/// [`Parasitic::GroundCap`] is fixed at femtofarads, so this factor appears
/// once per formula below and nowhere else. A division, not a multiply by
/// `1e-3`: `1e-3` is not exact in `f64` and `1000.0` is, so dividing is
/// correctly rounded from an exact operand.
const AF_PER_FF: f64 = 1_000.0;

/// Vacuum permittivity, in attofarads per micrometre.
///
/// CODATA 2018: `8.854 187 8128e-12` farads per metre, which is the same number
/// of attofarads per micrometre because both scalings are `1e-18` against
/// `1e-6`. Stated as the physical constant rather than as a fitted coefficient
/// because every coupling term below is a parallel-plate limit, and a limit
/// derived from a fitted number is not a limit.
const EPSILON0_AF_PER_UM: f64 = 8.854_187_812_8;

/// Nanometres in a micrometre. The stack states heights and thicknesses in
/// nanometres; every formula here wants micrometres.
const NM_PER_UM: f64 = 1_000.0;

/// How far a conductor couples laterally, as a multiple of its own thickness.
///
/// ponytail: a fixed multiple, because no deck in this tree states a coupling
/// halo. It bounds the candidate scan — coupling falls as `1 / S`, so a pair
/// beyond the halo contributes a term that rounds away, but *where* it rounds
/// away is a process question and this constant answers it with a guess.
///
/// The ceiling: on a dense layer the halo decides how many pairs are examined,
/// so a too-large value is quadratic and a too-small one drops real coupling —
/// and dropping it is the fail-open direction, since a missing coupling term
/// understates delay. Ten thicknesses is generous for the second: at ten
/// thicknesses of separation the parallel-plate term is a tenth of what it is at
/// one, and a real extractor's halo is the same order.
///
/// Upgrade path: a `coupling_halo_nm` in the deck's `pex` section, which is a
/// deck-schema change rather than a body. Filed in `docs/SIGNATURE_DEFECTS.md`.
const LATERAL_HALO_THICKNESSES: f64 = 10.0;

/// A coordinate as micrometres, which is what every deck coefficient is stated
/// per.
///
/// The one place a [`Grid`] is applied to a length in this module. Exact
/// whenever the coordinate divides the resolution, which is what lets the
/// closed forms above be asserted to a part in `1e-12` rather than to a
/// tolerance nobody can justify.
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

/// An area as square micrometres. [`micrometres`] squared, and squared *before*
/// the division so the two grid factors cancel in one operation instead of two.
#[inline]
fn square_micrometres(value: gpurify_units::DbuArea, grid: Grid) -> f64 {
    debug_assert!(grid.dbu_per_um() > 0, "a Grid is positive by construction");
    // The bound `Bbox::area` states, which is what `MAX_ABS_DBU` buys.
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

/// Series resistance of a conductor run.
///
/// `sheet_resistance × squares`, where squares is length over width. Exact for
/// a straight uniform-width segment, which is what the decomposition hands it —
/// the approximation is in the decomposition, not here.
///
/// **Decision** — pure, three values in, one out. Its oracle is the closed form
/// itself: a 10-square run of a 100 mΩ/□ layer is 1 Ω, and the test says so
/// without consulting any implementation.
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
    // Fail closed on the one input that has no answer: a zero-width conductor
    // is not a wire with a large resistance, it is not a wire. `f64` would hand
    // back an infinity and every sum downstream of it, so the precondition is
    // stated here rather than discovered as a `NaN` in a report.
    debug_assert!(
        length.raw() >= 0 && width.raw() > 0 && width.raw().unsigned_abs() <= MAX_ABS_DBU.unsigned_abs(),
        "a conductor has a positive in-domain width, not {}",
        width.raw()
    );

    // Squares first, then the coefficient. Squares are dimensionless — the
    // grid cancels between numerator and denominator and never appears — which
    // is exactly the property the scale-invariance law checks.
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

/// Resistance of a via or contact cut.
///
/// A per-cut constant from the deck, divided by the number of cuts in the
/// array — vias in parallel. The division is why a redundant via lowers
/// resistance, and why the count must come from the geometry rather than being
/// assumed to be one.
pub fn via_resistance(
    per_cut_ohm: f64,
    cuts: u32,
) -> Qty<Resistance, { prefix::BASE }> {
    debug_assert!(
        per_cut_ohm.is_finite() && per_cut_ohm >= 0.0,
        "a per-cut resistance is a finite non-negative number, not {per_cut_ohm}"
    );
    // A via array with no cuts is an open circuit, not a via. The count comes
    // from the geometry, so zero means the geometry named no cut and the
    // caller should not have reached a via formula at all.
    debug_assert!(cuts > 0, "a via array has at least one cut");

    // Conductances add, so `n` cuts in parallel is `1 / n` of one cut. `u32`
    // converts to `f64` losslessly, so no cut count can round.
    let ohm = per_cut_ohm / f64::from(cuts);

    debug_assert!(
        ohm.is_finite() && ohm >= 0.0,
        "{per_cut_ohm} ohm over {cuts} cuts is {ohm}, which is not a via"
    );
    Qty::new(ohm)
}

/// Capacitance from a conductor to the plane beneath it.
///
/// Area term plus fringe term: `area × area_coefficient + perimeter ×
/// fringe_coefficient`. The area term alone is the parallel-plate formula and
/// is exact for a wide plate; the fringe term is the deck's correction for
/// edges, and it dominates for a narrow wire.
///
/// The parallel-plate limit is the oracle: as width grows, the fringe term's
/// share must go to zero, and the total must approach `εA/d`.
///
/// # Units
///
/// Reopened in the Testing-Phase. The deck states its coefficients per square
/// micrometre and per micrometre; `area` and `perimeter` are grid indices. `grid`
/// is what closes the chain, and without it no absolute femtofarad value was
/// stateable — every closed form for this function had to be downgraded to a
/// scaling law. `area / grid.dbu_per_um()²` is square micrometres and
/// `perimeter / grid.dbu_per_um()` is micrometres, so the result is
/// `area_af_um2 × A_um2 + fringe_af_um × P_um` attofarads, reported in
/// femtofarads.
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
    debug_assert!(perimeter.raw() >= 0, "a conductor's perimeter is non-negative");

    // Two independent terms, summed once. Written this way rather than as a
    // single fused expression because superposition is an interface promise:
    // `f(a, 0) + f(0, b) == f(a, b)`, which holds here because each product
    // touches exactly one coefficient and a zero coefficient contributes an
    // exact `0.0`.
    let plate = area_af_um2 * square_micrometres(area, grid);
    let fringe = fringe_af_um * micrometres(perimeter, grid);
    let femtofarads = (plate + fringe) / AF_PER_FF;

    debug_assert!(
        femtofarads.is_finite() && femtofarads >= 0.0,
        "{plate} aF of plate plus {fringe} aF of fringe is {femtofarads} fF"
    );
    Qty::new(femtofarads)
}

/// Capacitance between two neighbouring conductors.
///
/// Falls off with separation and scales with facing length. Symmetric in its
/// two conductors by construction — which matters, because the old
/// implementation's asymmetric handling of the layer pair is what let a
/// `HashMap`'s iteration order change which layer was printed first.
///
/// # Units
///
/// Reopened in the Testing-Phase, same gap as [`ground_capacitance`]:
/// `coefficient_af_um` is per micrometre of facing length at unit separation,
/// and `facing_length` and `separation` are grid indices. `grid` converts both
/// to micrometres, so the result is attofarads reported in femtofarads.
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
    // says so with an infinity. Refused here rather than emitted: an infinite
    // coupling term poisons every net total it lands in.
    debug_assert!(
        separation.raw() > 0,
        "two distinct conductors are separated by at least one database unit"
    );

    // `C = k * L / S`, the parallel-run model at unit separation: linear in the
    // coefficient, linear in the facing length, and falling with separation.
    // The division is by the separation in micrometres, so the coefficient is
    // read exactly as the doc comment states it — per micrometre of facing
    // length at one micrometre of separation.
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
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled. Nets are
/// processed in ascending [`NetId`] order and elements appended in that order,
/// so the output is canonical without a sort — the sort exists as a guarantee,
/// not as the mechanism.
///
/// Parallelises by net: each net's elements depend only on its own geometry and
/// its neighbours' bounding boxes, never on another net's results. Coupling is
/// emitted once per pair, by the lower [`NetId`], so no pair is double-counted
/// and no ordering question arises.
///
/// `grid` is the run's grid, threaded through to the capacitance formulae —
/// see [`ground_capacitance`].
///
/// # Coupling, and the two objections that used to stand here
///
/// Both are withdrawn, and the second was simply wrong.
///
/// The first was an ordering objection: [`extract_net_into`] allocates one net's
/// nodes and writes that net's elements in one pass, so the higher net of a
/// coupling pair has no node yet when the lower one is written, and emitting the
/// pair later puts small `from` values behind large ones. True, and answered by
/// [`ParasiticNetwork::sort_canonical`], which is *defined* as the order this
/// function promises. [`couple_into`] runs after every net has its nodes and the
/// result is sorted; no signature moved.
///
/// The second claimed [`ProcessStack`] has no source for
/// [`coupling_capacitance`]'s `coefficient_af_um`, so synthesising one would put
/// a number in a report that no deck stated. That was a misreading of its own
/// columns. Both coupling terms here are **parallel-plate limits**, and a
/// parallel-plate limit is `ε₀ · k · geometry`:
///
/// - laterally, two conductors of thickness `t` facing over a length `L` across
///   a gap `S` — `ε₀ · k · t · L / S`;
/// - between layers, an overlap of area `A` across a dielectric of thickness
///   `d` — `ε₀ · k · A / d`.
///
/// `thickness_nm`, `height_nm` and `dielectric_k` are exactly `t`, `d` and `k`.
/// Nothing is fitted and nothing is invented: `ε₀` is a physical constant, and
/// the deck states the rest. On the corpus this reproduces the 138.1 aF that
/// `PEX_COUPLING_C` derives and the 4.604 aF that `PEX_CROSSOVER` derives, to
/// the digits each was written with.
///
/// It is a **lower bound**, deliberately. Fringing adds to both, which is why
/// `lateral_coupling_halves_when_the_gap_doubles_and_ignores_the_axis` holds
/// exactly here and does *not* hold of a field solve — see `crate::quasistatic`,
/// which is the path that carries fringing and the one a signoff run selects
/// per net.
pub fn extract_into(
    store: &GeometryStore,
    nets: &NetTable,
    devices: &DeviceTable,
    connectivity: &Connectivity,
    stack: &ProcessStack,
    grid: Grid,
    out: &mut ParasiticNetwork,
) {
    // Preconditions, over what the signature exposes. The stack's columns are
    // read by row in `extract_net_into` through three separate `get`s, so a
    // ragged stack would hand one layer another layer's coefficients for the
    // columns that are long enough and zero for the ones that are not — a wrong
    // parasitic rather than a missing one.
    debug_assert!(grid.dbu_per_um() > 0, "a Grid is positive by construction");
    let rows = stack.sheet_res_ohm_sq.len();
    debug_assert_eq!(stack.area_cap_af_um2.len(), rows, "one area coefficient per stack row");
    debug_assert_eq!(stack.fringe_cap_af_um.len(), rows, "one fringe coefficient per stack row");

    // Cleared and refilled, all five columns — see `ParasiticNetwork::clear`,
    // which `quasistatic::extract_into` opens with for the same reason.
    out.clear();

    let net_count = u32::try_from(nets.net_count()).expect("a NetId is a u32");

    // A dispatcher, not a row-wise transform: one iteration per net, each
    // running a whole sub-transform that appends a variable number of rows. The
    // rows are one level down, inside `extract_net_into`.
    //
    // Ascending is load-bearing twice over: it is what makes `node_net`
    // grouped-and-ascending as `ParasiticNetwork` documents, and what makes the
    // emitted element order the one `sort_canonical` would have produced.
    for net in 0..net_count {
        extract_net_into(store, nets, NetId(net), stack, grid, out);
    }
    extract_devices_into(devices, stack, grid, out);
    // After every net has its nodes, so a pair's higher net has somewhere to
    // land — which is the ordering objection this function's doc comment used to
    // record as a blocker.
    let node_of = nodes_by_poly(store, nets, out);
    couple_into(store, nets, connectivity, stack, grid, &node_of, out);
    vias_into(store, connectivity, stack, &node_of, out);
    // `couple_into` appends by layer pair, not by `from`, so the element columns
    // arrive out of order and are put back into the one this function promises.
    // `sort_canonical` *is* that order by definition, so this is the promise
    // rather than a repair of it.
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
    // The two order invariants this function's doc comment promises, asserted
    // over the columns the signature exposes. An adjacent-pair "is this column
    // ascending" scan is `slice::is_sorted` exactly — same comparison, same
    // ascending order, and the seed the fold needed is gone with it.
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
/// they share it across.
///
/// **Decision** — two boxes in, one optional pair out, pure and
/// table-testable. `None` when they do not face at all, which is the
/// corner-to-corner case (disjoint on both axes) and the overlapping case (two
/// shapes on one layer occupying the same ground, which is one conductor rather
/// than two).
///
/// Bounding boxes, and *conservatively*: a box's projection is a superset of its
/// polygon's, so the facing run is over-reported and the gap under-reported.
/// Both push the capacitance up, and an overstated coupling is the fail-closed
/// direction for delay. Exact for the rectangles this corpus is drawn from, and
/// `crate::quasistatic` is the path that is exact for the rest.
fn facing(a: Bbox, b: Bbox) -> Option<(Dbu, Dbu)> {
    let along_x = a.xhi.raw().min(b.xhi.raw()) - a.xlo.raw().max(b.xlo.raw());
    let along_y = a.yhi.raw().min(b.yhi.raw()) - a.ylo.raw().max(b.ylo.raw());

    // They face across the axis they are disjoint on, and run along the other.
    // Exactly one of the two may be positive; both positive is an overlap and
    // neither positive is a corner.
    let (run, gap) = match (along_x > 0, along_y > 0) {
        (true, false) => (along_x, -along_y),
        (false, true) => (along_y, -along_x),
        _ => return None,
    };
    // Zero gap is two touching conductors, which is one conductor. The
    // reciprocal would be an infinity, and `coupling_capacitance` refuses it.
    (gap > 0).then(|| (Dbu::new_unchecked(run), Dbu::new_unchecked(gap)))
}

/// One stack row's lateral coupling coefficient, in the units
/// [`coupling_capacitance`] reads.
///
/// `ε₀ · k · t`, the parallel-plate limit for two conductors of thickness `t`
/// facing each other. Every factor comes from the deck except `ε₀`, which is a
/// physical constant.
fn lateral_coefficient(stack: &ProcessStack, row: usize) -> f64 {
    let k = stack.dielectric_k.get(row).copied().unwrap_or(0.0);
    let thickness_um = stack.thickness_nm.get(row).copied().unwrap_or(0.0) / NM_PER_UM;
    EPSILON0_AF_PER_UM * k * thickness_um
}

/// Dielectric thickness between the top of `lower` and the bottom of `upper`,
/// in micrometres, or `None` when they do not stack in that order.
///
/// `height_nm` is a layer's *bottom*, so the gap is
/// `height(upper) − (height(lower) + thickness(lower))`. `None` for a
/// non-positive gap, which is either the same layer or two layers the stack
/// says intersect — neither is a parallel-plate pair.
fn interlayer_gap_um(stack: &ProcessStack, lower: usize, upper: usize) -> Option<f64> {
    let top_of_lower = stack.height_nm.get(lower).copied().unwrap_or(0.0)
        + stack.thickness_nm.get(lower).copied().unwrap_or(0.0);
    let bottom_of_upper = stack.height_nm.get(upper).copied().unwrap_or(0.0);
    let gap_nm = bottom_of_upper - top_of_lower;
    (gap_nm > 0.0).then_some(gap_nm / NM_PER_UM)
}

/// Emit one coupling element between two polygons on different nets.
///
/// **Decision plus one append.** Ordered by [`NetId`], the lower net's node
/// first, which is what
/// `extracted_elements_name_real_nodes_and_order_every_coupling_by_net` asserts
/// and what stops a pair being counted twice from two directions.
fn push_coupling(
    nets: &NetTable,
    node_of: &[NodeId],
    a: PolyId,
    b: PolyId,
    femtofarads: f64,
    out: &mut ParasiticNetwork,
) {
    // Surviving `if`: the value test keeps a zero or non-finite element out of
    // the network, for the reason `extract_net_into` gives — a zero-farad row is
    // one every reader downstream has to skip. Uniform across a run.
    if !(femtofarads > 0.0 && femtofarads.is_finite()) {
        return;
    }
    let (lo, hi) = if nets.net_of(a) < nets.net_of(b) { (a, b) } else { (b, a) };
    let (from, to) = (node_of[lo.idx()], node_of[hi.idx()]);
    debug_assert_ne!(from, to, "a coupling element joins a node to itself");
    out.push(from, Some(to), Parasitic::CouplingCap(Qty::new(femtofarads)));
}

/// Every conductor polygon's node, indexed by [`PolyId`].
///
/// **Transform, A-to-B.** Mirrors the allocation [`extract_net_into`] performs —
/// nets in ascending order, each contributing one node per polygon plus one
/// closing boundary — because the two have to agree and only one of them can
/// hold the map. The `debug_assert` at the end is what says they still do: every
/// entry is checked against the node column the first pass actually wrote.
///
/// [`NO_NODE`] fills the rows of polygons on no net, which is every polygon on a
/// non-conductor layer. Reading one is a bug, not a fallback, and it indexes out
/// of bounds in every profile rather than aliasing node zero.
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
/// **Transform, gatherer.** Appends; does not clear. Both terms are
/// parallel-plate limits off the deck's own columns — see [`extract_into`]'s doc
/// comment for the derivation and for why nothing here is fitted.
///
/// # Two scans, because they are two different questions
///
/// *Lateral* is a same-layer scan at [`LATERAL_HALO_THICKNESSES`] times the
/// layer's thickness: two conductors side by side on one layer, facing across a
/// gap. *Interlayer* is a cross-layer scan at zero distance: two conductors on
/// two layers, one above the other, coupling across the area they overlap. A
/// pair is only ever one of the two, so no term is counted twice.
///
/// Non-conductors are skipped on both, `connectivity.conductors` deciding which
/// those are. A via cut is in the stack and is not a plate.
fn couple_into(
    store: &GeometryStore,
    nets: &NetTable,
    connectivity: &Connectivity,
    stack: &ProcessStack,
    grid: Grid,
    node_of: &[NodeId],
    out: &mut ParasiticNetwork,
) {
    // Three buffers for the whole call. A rule-row loop's worth of allocation,
    // once per run rather than once per layer pair.
    let mut index_a = SpatialIndex::default();
    let mut index_b = SpatialIndex::default();
    let mut pairs = Vec::new();

    // Not a bulk loop: a deck names tens of conductors, and every value read
    // from a row here is a uniform over the pair loop below.
    for (position, &layer) in connectivity.conductors.iter().enumerate() {
        let Some(row) = stack_row(stack, layer) else {
            // A conductor the deck's `pex` section never described has no
            // thickness and no `k`, so it has no parallel-plate limit to state.
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
        // `MAX_ABS_DBU` is `1 << 40`, a power of two well inside the `f64`
        // mantissa, so the ceiling is exact and the clamp below it is the whole
        // of the truncation argument.
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
                // Two polygons of one net are one conductor and do not couple to
                // themselves. The test is a gather and a compare, not a branch
                // on data the loop could have hoisted.
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

        // Every conductor above this one. `position + 1..` rather than a second
        // full loop with an ordering test: a pair is visited once, and which of
        // the two is lower is decided by `interlayer_gap_um` from the stack's
        // own heights rather than by the deck's declaration order.
        for &above in &connectivity.conductors[position + 1..] {
            let Some(other) = stack_row(stack, above) else {
                continue;
            };
            let (lower, upper, lower_layer, upper_layer) = if stack.height_nm[row] <= stack.height_nm[other] {
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
            // `ground_capacitance` with a zero fringe term is `coefficient ×
            // area` exactly, which is the parallel-plate form — reused rather
            // than rewritten, and it already carries the `Grid` conversion.
            let per_um2 = EPSILON0_AF_PER_UM * k / gap_um;

            SpatialIndex::build_into(store, lower_layer, &mut index_a);
            SpatialIndex::build_into(store, upper_layer, &mut index_b);
            cross_layer_pairs_into(store, &index_a, &index_b, Dbu::new_unchecked(0), &mut pairs);
            for &(a, b) in &pairs {
                if nets.same_net(a, b) {
                    continue;
                }
                let (box_a, box_b) = (store.poly_bbox(a), store.poly_bbox(b));
                let wide = box_a.xhi.raw().min(box_b.xhi.raw()) - box_a.xlo.raw().max(box_b.xlo.raw());
                let tall = box_a.yhi.raw().min(box_b.yhi.raw()) - box_a.ylo.raw().max(box_b.ylo.raw());
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
/// **Transform, gatherer.** Appends; does not clear.
///
/// # A cut is not a node
///
/// A cut layer is in `connectivity.via_cut` and not in
/// `connectivity.conductors`, so `topology::extract_nets_into` gives its
/// polygons [`NetId::NONE`] and [`extract_net_into`] never sees them. That is
/// right — a cut is a resistor, not a conductor with a length and a ground
/// capacitance — and it is also why the whole via family used to extract
/// nothing: [`via_resistance`] had no caller in the tree and `PEX_VIA1` produced
/// an empty network. Finding F11.
///
/// So a cut contributes an *element* rather than a node: one resistor between
/// the node of the conductor below it and the node of the conductor above.
///
/// # Cuts in one array are one resistor
///
/// [`via_resistance`] divides by the cut count, because cuts in parallel conduct
/// in parallel — which is the whole reason a redundant via helps. Cuts are
/// therefore grouped by the *conductor pair they join* and each group emits one
/// element carrying the group's count. One resistor per cut would put them in
/// series and make a redundant via worse than a single one, which is backwards.
///
/// Grouping is by sorted `(lower, upper)` [`PolyId`] pair, so the emission order
/// is a function of the geometry rather than of the pair generator.
fn vias_into(
    store: &GeometryStore,
    connectivity: &Connectivity,
    stack: &ProcessStack,
    node_of: &[NodeId],
    out: &mut ParasiticNetwork,
) {
    /// A cut that landed on no plate on one side. Reading one is a bug, not a
    /// fallback: the guard below drops it rather than joining it to polygon zero.
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

    // Not a bulk loop: a deck names a handful of via layers, and everything read
    // from a row is a uniform over the cut loop below.
    for row in 0..connectivity.via_cut.len() {
        let cut_layer = connectivity.via_cut[row];
        let (lower, upper) = connectivity.via_connects[row];
        let Some(cut_row) = stack_row(stack, cut_layer) else {
            // A cut layer the deck's `pex` section never described has no
            // per-cut resistance to state.
            continue;
        };
        let per_cut_ohm = stack.sheet_res_ohm_sq.get(cut_row).copied().unwrap_or(0.0);
        if !(per_cut_ohm > 0.0 && per_cut_ohm.is_finite()) {
            continue;
        }

        SpatialIndex::build_into(store, cut_layer, &mut cut_index);
        // Zero distance: a cut lands on the plate it touches.
        // `cross_layer_pairs_into` emits `(a, b)` with `a` from the first index,
        // so the cut is always the first element and the plate the second.
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
                // whatever order the index emitted them in. `min` on the raw id
                // is a select, not a branch.
                let slot = &mut landing[cut.idx()];
                *slot = PolyId(slot.0.min(plate.0));
            }
        }

        // One row per cut that landed on both plates, keyed by the pair it
        // joins. Sorted so the groups below are contiguous and their order is
        // the geometry's rather than the index's.
        arrays.clear();
        for cut in store.polys_on_layer(cut_layer) {
            let (lo, hi) = (below[cut as usize], above[cut as usize]);
            // Surviving `if`: a cut with no plate on one side is a dangling cut,
            // which carries no current and has no resistance to report. Uniform
            // on real geometry — a via landing on nothing is a DRC violation,
            // and this is not the rule that reports it.
            if lo != NO_POLY && hi != NO_POLY {
                arrays.push((lo, hi));
            }
            // Reset for the next via row, which reuses the same two columns.
            below[cut as usize] = NO_POLY;
            above[cut as usize] = NO_POLY;
        }
        arrays.sort_unstable();

        // One element per run of equal pairs, carrying that run's length as the
        // cut count.
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

/// Extract one net's parasitics.
///
/// **Transform.** Public and separate because it is the unit a test can
/// construct by hand: one net of known geometry on a layer of known
/// coefficients, with an answer computed from the formulae above.
///
/// **Appends. Does not clear `out`.** Stated in the Testing-Phase, which could
/// not tell replace from append and so gave every call a fresh buffer. Append is
/// the only choice that composes: [`extract_into`] clears once and then calls
/// this per net, so a clear here would leave one net's worth of output.
///
/// # The model
///
/// Nodes at segment *boundaries*, not at segment centres: a net of `n` polygons
/// gets `n + 1` nodes, and polygon `i` is one resistor from node `i` to node
/// `i + 1` carrying its whole series resistance. Node `i` also carries polygon
/// `i`'s ground capacitance; the closing node `n` carries none, because there is
/// no polygon `n` to give it one.
///
/// A net's emitted resistance is therefore exactly the sum of its polygons'
/// resistances, which is the property
/// `the_resistance_a_net_emits_is_the_sum_of_its_polygons_resistances` states.
///
/// ## What this replaced, and why it was fail-open
///
/// The centre-to-centre form: one node per polygon at its centre, consecutive
/// centres joined by half of each polygon's resistance. That is a correct
/// statement of what a current crossing from one centre to the next sees, and it
/// loses `(R_first + R_last) / 2` — the two half-segments between the end
/// centres and the net's actual terminals, which had no nodes. On a net of *one*
/// polygon it loses the entire resistance and emits no resistive element at all.
///
/// Every resistance case in `tests/fixtures/expectations.json` is a one-polygon
/// net, so every resistance this workspace had ever extracted was `0`, and zero
/// is also what an extractor that never looked at the cell produces. Finding
/// F10.
///
/// The closing node is pushed for every non-empty net whether or not any element
/// names it — uniformly, so the node count is exactly `polys.len() + 1` and can
/// be asserted rather than reasoned about. A net whose layers are all
/// zero-resistance ends with a node nothing joins, which is the honest reading:
/// the net has two terminals and no resistance between them.
///
/// # Dimensions
///
/// Measured off the vertex ring, not the bounding box: [`gpurify_core::ops::area2`]
/// for the area and a fold of edge lengths for the perimeter, so an L-shape is
/// not inflated to its box and a serpentine is not flattened into one.
///
/// The resistive length and width come out of those same two numbers — the
/// sides of the rectangle with that area and that perimeter, which are the
/// roots of `t² − (P/2)t + A`. Exact for a rectangle, where the discriminant is
/// `(w − h)²` and the roots are `max` and `min`; for a serpentine it recovers
/// the run's real square count, which the bounding box reported as roughly one.
///
/// # Nodes are chained in `PolyId` order
///
/// Rather than by which polygons actually touch, so a comb's fingers come out
/// in series where they are really parallel stubs off the rail. Every polygon's
/// resistance still appears exactly once, so a net's total is unchanged; what
/// moves is where along the net it sits.
///
/// Not reachable from a body. A spanning tree needs the touch graph and, to
/// keep the emitted elements `from`-ascending, a buffer to merge its edges
/// against the ground terms — and this signature has nowhere to hang either, so
/// both would be allocated once per net by a function called once per net. That
/// is the scratch-parameter defect `topology::intra_layer_edges_into` already
/// records, and it is filed under `## pex` in `docs/SIGNATURE_DEFECTS.md`.
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
    // One boundary node per polygon plus the closing one. `u32::from(bool)` is
    // a select, not a branch, and an empty net gets no node at all — there is no
    // segment for a boundary to bound.
    let nodes = count + u32::from(!polys.is_empty());
    // Every profile, not `debug_assert`: a `NodeId` that wrapped would name an
    // existing node of another net, and every element written against it would
    // read as a legitimate parasitic on the wrong conductor.
    let end = base
        .checked_add(nodes)
        .expect("the node columns of one network fit a NodeId");

    out.node_net.reserve(nodes as usize);
    out.node_layer.reserve(nodes as usize);

    // Serial by construction: it appends a variable number of rows through the
    // frozen `ParasiticNetwork::push`. The bulk data is one level down — the
    // vertex ring of each polygon — and that is what the perimeter fold in the
    // body walks.
    let mut node = NodeId(base);
    // The closing node inherits the last polygon's layer, so `node_layer` says
    // something true about where the terminal sits. Seeded rather than made an
    // `Option`: the seed is only ever read when `polys` is empty, and then the
    // push it feeds does not happen.
    let mut last_layer = LayerId(0);
    for &poly in polys {
        let layer = store.poly_layer(poly);
        out.node_net.push(net);
        out.node_layer.push(layer);
        last_layer = layer;

        // One lookup, three loads. `unwrap_or` on an already-computed index is
        // a select, not a branch: the row decides a *value* here, never a
        // control path. A layer the deck's pex section never described
        // contributes zero coefficients, and the emission guards below then
        // drop its elements rather than writing a zero-valued parasitic.
        let row = stack_row(stack, layer).unwrap_or(usize::MAX);
        let sheet_ohm_sq = stack.sheet_res_ohm_sq.get(row).copied().unwrap_or(0.0);
        let area_af_um2 = stack.area_cap_af_um2.get(row).copied().unwrap_or(0.0);
        let fringe_af_um = stack.fringe_cap_af_um.get(row).copied().unwrap_or(0.0);

        // The polygon's own area and perimeter, both off the vertex ring.
        // `area2` is the shoelace and returns twice the signed
        // area, so the halved magnitude is the area; the halving
        // truncates by at most half a square database unit, and only for a ring
        // whose area is not an integer at all.
        let (xs, ys) = store.poly_verts(poly);
        let area = DbuArea::new(ops::area2(xs, ys).raw().abs() / 2);

        // The perimeter as a strict left fold carrying the previous vertex,
        // seeded with the *last* one so the ring's closing edge is the fold's
        // first term and needs no fixup outside. `unwrap_or` on `last` is a
        // select, not a guard: a row with no vertices folds zero times and
        // never reads the seed, so it decides a value and never a control path.
        //
        // The columns are checked equal rather than zipped to the shorter: a
        // ring one coordinate short would otherwise drop an edge and understate
        // the perimeter, which reads downstream as a smaller capacitance rather
        // than as a fault.
        debug_assert_eq!(xs.len(), ys.len(), "a vertex ring's columns must agree");
        let mut previous = (
            xs.last().copied().unwrap_or(Dbu::new_unchecked(0)),
            ys.last().copied().unwrap_or(Dbu::new_unchecked(0)),
        );
        let mut perimeter = Dbu::new_unchecked(0);
        for (&x, &y) in xs.iter().zip(ys) {
            // Widened before squaring, as `ops::point_seg_dist2` does: two
            // in-domain coordinates differ by up to `2^41`, which is past
            // `Dbu::mul_wide`'s operand precondition.
            let dx = i128::from(x.raw() - previous.0.raw());
            let dy = i128::from(y.raw() - previous.1.raw());
            perimeter = perimeter + ops::isqrt(DbuArea::new(dx * dx + dy * dy));
            previous = (x, y);
        }

        // The rectangle with this area and this perimeter: the roots of
        // `t² − (P/2)t + A`. `max(0)` on the discriminant is the shape too fat
        // for a real root — a disc, say — and it lands on `long == short`, one
        // square, which is what a square is. A `max`, so still a value and not
        // a branch.
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

        // Surviving `if`: `segment_resistance`'s precondition is a positive
        // width, and a degenerate figure — a derived layer can legitimately
        // produce one, see `Bbox`'s doc comment — has no conductor to state a
        // resistance for. Predicts perfectly: ingest rejects zero-width drawn
        // polygons, so the taken side is every row of a real store, and the
        // taken side is a call.
        let ohm = if short.raw() > 0 {
            segment_resistance(sheet_ohm_sq, long, short).raw()
        } else {
            0.0
        };
        let femtofarads =
            ground_capacitance(area_af_um2, fringe_af_um, area, perimeter, grid).raw();

        // Emission order is `sort_canonical`'s order by construction. Both rows
        // leave *this* node, and `canonical_key` maps `to == None` to `0` and a
        // present node to `node + 1`, so the ground capacitance sorts ahead of
        // the resistor beside it. Ground first is therefore the canonical order,
        // and emitting it second would need a sort to undo.
        //
        // Surviving `if`s, both the same escape valve: they keep a zero or
        // negative element out of the network. A zero-ohm resistor is not a
        // simplification, it is a short that changes the answer a simulator
        // gives, and a zero-farad capacitance is a row every reader downstream
        // has to skip. Both are uniform across a run — a layer either has
        // coefficients or it does not — so neither is the unpredictable branch
        // the rule is aimed at.
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

    // The closing boundary. Pushed after the loop rather than inside it because
    // it is the one node with no polygon of its own, and its layer is the last
    // polygon's — see the seed above.
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
/// capacitance, terminal resistance.
///
/// Separate from wire extraction because the formulae are per-family and come
/// from the device model, not the process stack.
///
/// **Appends. Does not clear `out`.** Same contract as [`extract_net_into`], and
/// for the same reason: [`extract_into`] runs the wire half and this half into
/// one network.
///
/// `grid` converts the device's `Dbu` geometry to micrometres, as in
/// [`ground_capacitance`].
///
/// # This appends nothing, and cannot
///
/// Reported rather than worked around. The doc comment above states where the
/// formulae come from — "the device model, not the process stack" — and there
/// is no device model in this signature. What is here is a [`DeviceTable`], a
/// [`ProcessStack`] and a [`Grid`], and neither of the first two closes the gap:
///
/// - [`ProcessStack`] is indexed by [`LayerId`], and a device row names a
///   marker [`gpurify_core::PolyId`], not a layer. Without a
///   [`GeometryStore`] there is no route from the one to the other, so not even
///   the wrong coefficient is reachable.
/// - The per-family constants a gate or junction capacitance needs — oxide
///   capacitance per unit area, sidewall capacitance per unit perimeter — are
///   not fields of [`ProcessStack`] at all. `dielectric_k` and `thickness_nm`
///   describe the interconnect dielectric, not a gate oxide.
///
/// Inventing a coefficient here would put a number in a report that no deck
/// stated, which is worse than the shortfall: a wrong parasitic is indefensible
/// where a missing one is at least visible against a reference netlist. So the
/// body asserts the table's shape and returns, and the ledger entry belongs in
/// `docs/NEED_TESTING.md`.
///
/// Upgrade path: a `DeviceModel` table from the deck's device section, keyed by
/// the same row [`gpurify_ingest::deck::DeviceRecognition`] is, added to this
/// signature. A Definition-Phase change.
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

    // Nothing is appended, and `out` is left exactly as it arrived — which is
    // what keeps `extract_into`'s `from`-ascending assertion true through this
    // call. See the doc comment for why there is no third formula to run.
    //
    // `let _ = out` rather than renaming the parameter `_out`: the name is part
    // of the frozen signature and of what a caller reads in the docs, and this
    // function grows a body the moment a `DeviceModel` reaches it. Same idiom as
    // `gpu::GpuMatVec::upload`.
    let _ = out;
}

/// Which process-stack row a layer uses.
///
/// Indexed directly by [`LayerId`]: the stack is dense, small and ordered
/// ascending. This is the lookup the old implementation did through a
/// `HashMap`, and the reason it is an array index now is determinism, not
/// speed.
pub fn stack_row(stack: &ProcessStack, layer: LayerId) -> Option<usize> {
    let rows = stack.sheet_res_ohm_sq.len();
    debug_assert_eq!(stack.thickness_nm.len(), rows, "one thickness per stack row");
    debug_assert_eq!(stack.height_nm.len(), rows, "one height per stack row");
    debug_assert_eq!(stack.area_cap_af_um2.len(), rows, "one area coefficient per stack row");
    debug_assert_eq!(stack.fringe_cap_af_um.len(), rows, "one fringe coefficient per stack row");
    debug_assert_eq!(stack.dielectric_k.len(), rows, "one permittivity per stack row");

    // Fail closed on the half that matters: a layer past the stack is `None`,
    // never a wrapped or clamped row. The old implementation reached this
    // through a hash map, where a missing layer and a layer holding another
    // layer's coefficients are one lookup apart.
    let row = layer.idx();
    (row < rows).then_some(row)
}
