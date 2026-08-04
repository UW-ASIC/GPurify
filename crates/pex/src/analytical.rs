//! Closed-form extraction from the deck's process stack.
//!
//! Each function here is a formula with a known analytic answer, which makes
//! this the easiest module in the tree to test: a rectangle of known dimensions
//! on a layer of known sheet resistance has exactly one right answer, and a
//! parallel-plate pair has another. No reference implementation is needed and
//! none is wanted.

use crate::network::{NodeId, Parasitic, ParasiticNetwork};
use gpurify_core::{ops, GeometryStore, LayerId};
use gpurify_ingest::deck::ProcessStack;
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
/// # Coupling is not emitted by this path
///
/// Not a shortcut and not reachable from a body: two frozen signatures are in
/// the way, and both are recorded under `## pex` in
/// `docs/SIGNATURE_DEFECTS.md`.
///
/// - [`extract_net_into`] allocates one net's nodes and writes that net's
///   elements in a single pass, so the *higher* net of a coupling pair has no
///   node yet when the lower one is being written. Emitting the pair in a later
///   pass puts small `from` values behind large ones, and `from`-ascending is
///   the order this function promises and the determinism gate rests on.
///   Closing it means splitting node allocation out of [`extract_net_into`],
///   which is a change to its signature.
/// - [`ProcessStack`] has no lateral column. `dielectric_k` and `thickness_nm`
///   describe the interconnect dielectric, not a per-layer coupling
///   coefficient, so [`coupling_capacitance`]'s `coefficient_af_um` has no
///   source in the deck. Synthesising one here would put a number in a report
///   that no deck stated — the objection [`extract_devices_into`] makes at
///   length, and the same answer.
///
/// The consequence is a total capacitance short by the lateral term, which
/// understates delay. That is a shortfall a reference netlist makes visible
/// rather than a wrong number, and `docs/NEED_TESTING.md` carries the ledger
/// entry for it.
pub fn extract_into(
    store: &GeometryStore,
    nets: &NetTable,
    devices: &DeviceTable,
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
        out.node_net.len() <= store.poly_count(),
        "one node per conductor polygon at most, {} against {}",
        out.node_net.len(),
        store.poly_count()
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
/// One node per conductor polygon, placed at the polygon's centre. Each node
/// carries its polygon's ground capacitance; consecutive nodes are joined by
/// half of each polygon's series resistance, which is what a current crossing
/// from one centre to the next sees.
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
    // Every profile, not `debug_assert`: a `NodeId` that wrapped would name an
    // existing node of another net, and every element written against it would
    // read as a legitimate parasitic on the wrong conductor.
    let end = base
        .checked_add(count)
        .expect("the node columns of one network fit a NodeId");

    out.node_net.reserve(polys.len());
    out.node_layer.reserve(polys.len());

    // Serial by construction, on two counts: it appends a variable number of
    // rows through the frozen `ParasiticNetwork::push`, and `previous_ohm` is a
    // loop-carried chain rather than a per-row function. The bulk data is one
    // level down — the vertex ring of each polygon — and that is what the
    // perimeter fold in the body walks.
    let mut node = NodeId(base);
    let mut previous_ohm = 0.0_f64;
    for &poly in polys {
        let layer = store.poly_layer(poly);
        out.node_net.push(net);
        out.node_layer.push(layer);

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
        let series = 0.5 * (previous_ohm + ohm);
        let femtofarads =
            ground_capacitance(area_af_um2, fringe_af_um, area, perimeter, grid).raw();

        // Emission order is `sort_canonical`'s order by construction: the link
        // arriving at this node carries the *previous* node's `from`, which is
        // one less than this one's, and a ground capacitance has `to == None`
        // and so sorts ahead of the link leaving the same node.
        //
        // Surviving `if`s, both the same escape valve. `node.0 > base` is a
        // loop-counter test the predictor memorises after one iteration. The
        // value tests are what keep a zero or negative element out of the
        // network: a zero-ohm resistor is not a simplification, it is a short
        // that changes the answer a simulator gives, and a zero-farad
        // capacitance is a row every reader downstream has to skip. Both are
        // uniform across a run — a layer either has coefficients or it does
        // not — so neither is the unpredictable branch the rule is aimed at.
        if node.0 > base && series > 0.0 && series.is_finite() {
            out.push(
                NodeId(node.0 - 1),
                Some(node),
                Parasitic::Resistance(Qty::new(series)),
            );
        }
        if femtofarads > 0.0 && femtofarads.is_finite() {
            out.push(node, None, Parasitic::GroundCap(Qty::new(femtofarads)));
        }

        previous_ohm = ohm;
        node = NodeId(node.0 + 1);
    }

    debug_assert_eq!(
        out.node_net.len(),
        end as usize,
        "one node appended per polygon of the net"
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
