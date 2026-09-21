//! Net extraction: which shapes are electrically the same conductor.
//!
//! Two shapes join if they are on the same conductor layer and touch, or if a
//! via cut on the right layer overlaps both.

use crate::topology::csr_run;
use gpurify_geom::connectivity::{components_into, ComponentLabel};
use gpurify_geom::index::{candidate_pairs_into, cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::ops::{segments_intersect, Point, Seg};
use gpurify_geom::Dbu;
use gpurify_geom::{GeometryStore, LayerId, PolyId};
use gpurify_ingest::deck::Connectivity;

/// Identifies one electrical net: a dense rank over `0 .. net_count`, ascending
/// by each net's smallest [`PolyId`], which is what makes ids canonical across
/// runs, machines and thread counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct NetId(pub u32);

impl NetId {
    /// The polygon is on no net at all: outside `0 .. net_count`, never listed
    /// by [`NetTable::polys_of`], and [`NetTable::same_net`] is false for it
    /// even against itself.
    pub const NONE: Self = Self(u32::MAX);

    /// The raw index, meaningless on [`NetId::NONE`].
    #[must_use]
    pub const fn idx(self) -> usize {
        self.0 as usize
    }
}

/// Which net each polygon belongs to, in both directions.
#[derive(Debug, Default)]
pub struct NetTable {
    /// Net of each polygon, indexed by [`PolyId`].
    poly_net: Vec<NetId>,
    /// `polys[net_start[n]..net_start[n + 1]]` is net `n`, ascending.
    net_start: Vec<u32>,
    polys: Vec<PolyId>,
    /// Scratch, kept so a second extraction reuses the allocations.
    edges: Vec<(u32, u32)>,
    labels: Vec<ComponentLabel>,
    scratch: EdgeScratch,
}

impl NetTable {
    /// How many nets there are; [`NetId::NONE`] is not one of them.
    pub fn net_count(&self) -> usize {
        // `saturating_sub`, not `- 1`: a `Default` table has no offsets at all.
        self.net_start.len().saturating_sub(1)
    }

    /// The net of a polygon, or [`NetId::NONE`] if it is on no conductor layer.
    pub fn net_of(&self, poly: PolyId) -> NetId {
        // Fail closed: a polygon this table never saw panics rather than
        // reading as "on no net".
        self.poly_net[poly.idx()]
    }

    /// The polygons on one net, ascending. Empty for [`NetId::NONE`].
    pub fn polys_of(&self, net: NetId) -> &[PolyId] {
        // `NONE`'s index is `u32::MAX`, so falling through would panic rather
        // than return the promised empty slice. Any other id past `net_count`
        // does panic, for `net_of`'s reason.
        if net == NetId::NONE {
            return &[];
        }
        let (from, to) = csr_run(&self.net_start, net.idx());
        &self.polys[from..to]
    }

    /// Whether two polygons are the same net. False when either is on no net,
    /// even for a polygon against itself: [`NetId::NONE`] is an absence, not a
    /// net two shapes can share.
    pub fn same_net(&self, a: PolyId, b: PolyId) -> bool {
        let (a, b) = (self.net_of(a), self.net_of(b));
        (a != NetId::NONE) & (a == b)
    }

    /// Build directly from a per-polygon net assignment.
    ///
    /// Does not re-canonicalise: the caller is trusted for [`NetId`]'s
    /// ordering, so an id the caller skipped becomes a net with no polygons,
    /// which extraction never produces.
    ///
    /// # Panics
    ///
    /// When `poly_net` holds more rows than a [`PolyId`] can name.
    #[must_use]
    pub fn from_assignment(poly_net: &[NetId]) -> Self {
        let mut net_start = Vec::new();
        let mut polys = Vec::new();
        rebuild_index(poly_net, &mut net_start, &mut polys);

        Self {
            poly_net: poly_net.to_vec(),
            net_start,
            polys,
            edges: Vec::new(),
            labels: Vec::new(),
            scratch: EdgeScratch::default(),
        }
    }
}

/// Rebuild the reverse CSR index from a per-polygon net assignment.
fn rebuild_index(poly_net: &[NetId], net_start: &mut Vec<u32>, polys: &mut Vec<PolyId>) {
    // `NetId::NONE`'s `idx() + 1` would win every max and size the CSR at four
    // billion nets, so the mask folds it to zero, `max`'s identity.
    let mut net_count = 0usize;
    for &net in poly_net {
        let live = usize::from(net != NetId::NONE).wrapping_neg();
        net_count = net_count.max((net.idx() + 1) & live);
    }

    net_start.clear();
    net_start.resize(net_count + 1, 0);
    // `NONE` must not be counted and its index is `u32::MAX`, so there is no
    // in-range slot to write it to harmlessly instead.
    for net in poly_net.iter().filter(|net| **net != NetId::NONE) {
        net_start[net.idx() + 1] += 1;
    }
    for index in 1..net_start.len() {
        net_start[index] += net_start[index - 1];
    }

    let mut cursor = net_start[..net_count].to_vec();
    polys.clear();
    polys.resize(net_start[net_count] as usize, PolyId(0));
    for (index, net) in poly_net.iter().enumerate() {
        if *net == NetId::NONE {
            continue;
        }
        let slot = &mut cursor[net.idx()];
        polys[*slot as usize] =
            PolyId(u32::try_from(index).expect("a polygon index fits a PolyId"));
        *slot += 1;
    }
    debug_assert_eq!(cursor, net_start[1..], "the counting sort under-filled");
}

/// Equal when the partition is equal; scratch is not part of the value.
impl PartialEq for NetTable {
    fn eq(&self, other: &Self) -> bool {
        self.poly_net == other.poly_net
            && self.net_start == other.net_start
            && self.polys == other.polys
    }
}

impl Eq for NetTable {}

/// Extract nets from geometry; caller owns `out`, cleared and refilled.
///
/// Only polygons on a layer in [`Connectivity::conductors`] get a net. A cut
/// *joins* the two conductors it overlaps but does not *belong* to that net,
/// which is what makes [`crate::topology::port::PortError::OrphanLabel`] reachable.
pub fn extract_nets_into(store: &GeometryStore, connectivity: &Connectivity, out: &mut NetTable) {
    let rows = store.poly_count();
    let node_count = u32::try_from(rows).expect("a polygon index fits a PolyId");
    debug_assert_eq!(
        connectivity.via_cut.len(),
        connectivity.via_connects.len(),
        "a via layer is a cut and the two layers it joins, in step"
    );

    // Pass one: the edge list, accumulated across every layer into `out.edges`.
    out.edges.clear();

    if connectivity.intra_layer_touch {
        for &layer in &connectivity.conductors {
            intra_layer_edges_append(store, layer, &mut out.scratch, &mut out.edges);
        }
    }
    for (&cut, &connects) in connectivity.via_cut.iter().zip(&connectivity.via_connects) {
        via_edges_append(store, cut, connects, &mut out.scratch, &mut out.edges);
    }
    debug_assert!(
        out.edges
            .iter()
            .all(|&(a, b)| a < node_count && b < node_count),
        "an edge names a polygon this store does not have"
    );

    // Pass two: the union-find, sequential, which is why it is its own pass.
    components_into(node_count, &out.edges, &mut out.labels);
    debug_assert_eq!(out.labels.len(), rows, "one label per polygon");

    // Fail closed: a conductor the store's layer table lacks panics rather
    // than being skipped, which would extract a netlist missing a whole layer
    // and report it as clean.
    let mut conducts = vec![false; store.layer_count()];
    for &layer in &connectivity.conductors {
        conducts[layer.idx()] = true;
    }

    // Pass three: labels to dense net ids. Walking ascending is what makes the
    // numbering canonical, a label being its component's minimum polygon index.
    out.poly_net.clear();
    out.poly_net.reserve(rows);
    let mut rank = vec![u32::MAX; rows];
    let mut next = 0u32;
    for row in 0..node_count {
        let poly = PolyId(row);
        let label = out.labels[poly.idx()].0 as usize;
        let conducting = conducts[store.poly_layer(poly).idx()];

        // Claim a rank the first time a conducting polygon names this label.
        let seen = rank[label];
        let fresh = (seen == u32::MAX) & conducting;
        let fresh_mask = u32::from(fresh).wrapping_neg();
        let id = (next & fresh_mask) | (seen & !fresh_mask);
        rank[label] = id;
        next += u32::from(fresh);

        // `!mask` is all ones for a non-conductor, which is `NetId::NONE`.
        let mask = u32::from(conducting).wrapping_neg();
        out.poly_net.push(NetId(id | !mask));
    }
    debug_assert_eq!(out.poly_net.len(), rows, "one net id per polygon");

    rebuild_index(&out.poly_net, &mut out.net_start, &mut out.polys);

    debug_assert_eq!(
        out.net_count(),
        next as usize,
        "the CSR must hold every rank the assignment handed out"
    );
    debug_assert!(
        out.net_start.windows(2).all(|w| w[0] < w[1]),
        "extraction numbers a net only when a polygon claims it, so no net is empty"
    );
    debug_assert!(
        out.polys.windows(2).all(|w| w[0] != w[1]),
        "a polygon is listed by exactly one net"
    );
}

/// Whether two of the store's polygons share at least one point.
///
/// The exact re-test behind every bounding-box prune in this crate: merging two
/// nets that share only a box is fail-**open** for every rule that exempts a
/// same-net pair.
fn polys_intersect(store: &GeometryStore, a: PolyId, b: PolyId) -> bool {
    let (ax, ay) = store.poly_verts(a);
    let (bx, by) = store.poly_verts(b);
    debug_assert_eq!(ax.len(), ay.len(), "the store's columns are parallel");
    debug_assert_eq!(bx.len(), by.len(), "the store's columns are parallel");

    // Guarded rather than asserted: the probe below reads vertex zero.
    if ax.is_empty() || bx.is_empty() {
        return false;
    }

    // `rings_meet` already answers boundary contact, so one vertex is enough:
    // rings whose boundaries do not meet are either nested or disjoint.
    rings_meet(ax, ay, bx, by)
        || point_inside(bx, by, ax[0], ay[0])
        || point_inside(ax, ay, bx[0], by[0])
}

/// The pairs of `pairs` whose polygons really intersect, in the same order, so
/// a prune that emitted ascending pairs still has ascending pairs on the way out.
pub(crate) fn retain_intersecting_into(
    store: &GeometryStore,
    pairs: &[(PolyId, PolyId)],
    out: &mut Vec<(PolyId, PolyId)>,
) {
    out.clear();
    out.reserve(pairs.len());
    debug_assert!(
        out.capacity() >= pairs.len(),
        "the compact reserves for the input, not the survivors"
    );
    let slots = &mut out.spare_capacity_mut()[..pairs.len()];

    let mut w = 0usize;
    for (i, &pair) in pairs.iter().enumerate() {
        let keep = polys_intersect(store, pair.0, pair.1);
        // `w <= i` by induction: `w` starts at zero and advances by
        // `usize::from(bool)`, which Rust guarantees is 0 or 1, so after `i`
        // iterations `w` is at most `i`.
        debug_assert!(w <= i);
        // Unchecked because `w`'s step is data-dependent, so LLVM cannot prove
        // `w < slots.len()` and emits a live panic edge in the loop body.
        // Measured 1.19x at 8k, 1.06x at 4M.
        //
        // SAFETY: `w <= i < pairs.len() == slots.len()`, from the induction
        // above. Rejected slots stay uninitialised and are never read, because
        // `set_len(w)` truncates them away, and `(PolyId, PolyId)` is `Copy`, so
        // nothing there needs dropping.
        unsafe { slots.get_unchecked_mut(w) }.write(pair);
        w += usize::from(keep);
    }

    // SAFETY: `out` was emptied on entry and slots `0 .. w` were each written
    // when `w` held that value, so every one of them is initialised. `w <=
    // pairs.len() <= capacity`.
    unsafe { out.set_len(w) };

    debug_assert!(out.len() <= pairs.len(), "an exact test cannot add a pair");
}

/// The closed segment from vertex `i` of a ring to the next one, wrapping.
#[inline]
fn ring_edge(xs: &[Dbu], ys: &[Dbu], i: usize) -> Seg {
    debug_assert!(
        i < xs.len(),
        "a ring edge starts at one of the ring's vertices"
    );
    // Branchless wrap: the multiply is by zero for every vertex but the last.
    let next = (i + 1) - xs.len() * usize::from(i + 1 == xs.len());
    Seg {
        a: Point { x: xs[i], y: ys[i] },
        b: Point {
            x: xs[next],
            y: ys[next],
        },
    }
}

/// Edge pairs the direct scan may examine before the sweep pays for itself. A
/// tuning constant, rounded rather than measured: the sweep's
/// `(n + m)·log2(n + m)` comparisons plus six allocations meet the quadratic
/// scan near `n·m ≈ 10³`.
const DIRECT_PAIR_BUDGET: usize = 1 << 10;

/// Whether any edge of one ring meets any edge of the other, touching included.
///
/// Two paths over one predicate, chosen against [`DIRECT_PAIR_BUDGET`]; they
/// agree because two segments that meet share a point whose x lies in both
/// extents, so the sweep can skip no pair that meets.
fn rings_meet(ax: &[Dbu], ay: &[Dbu], bx: &[Dbu], by: &[Dbu]) -> bool {
    // `saturating_mul`: a pair big enough to overflow must take the sweep.
    if ax.len().saturating_mul(bx.len()) <= DIRECT_PAIR_BUDGET {
        return rings_meet_direct(ax, ay, bx, by);
    }
    rings_meet_sweep(ax, ay, bx, by)
}

/// [`rings_meet`] by exhaustive pair scan; the reference implementation.
fn rings_meet_direct(ax: &[Dbu], ay: &[Dbu], bx: &[Dbu], by: &[Dbu]) -> bool {
    (0..ax.len()).any(|i| {
        let edge = ring_edge(ax, ay, i);
        (0..bx.len()).any(|j| segments_intersect(edge, ring_edge(bx, by, j)))
    })
}

/// The x-extent of every edge of a ring, in edge order; caller owns `out`.
fn edge_xspans_into(xs: &[Dbu], out: &mut Vec<(Dbu, Dbu)>) {
    let n = xs.len();
    debug_assert!(n > 0, "a ring with no vertices has no edges");

    // Zipping would silently take the shorter of the two offset views.
    let (from, to) = (&xs[..n - 1], &xs[1..]);
    debug_assert_eq!(from.len(), to.len(), "SoA columns must agree");

    // `n`, not `n - 1`: the closing edge below is the `n`th row.
    out.clear();
    out.reserve(n);
    for i in 0..from.len() {
        let (a, b) = (from[i], to[i]);
        out.push((a.min(b), a.max(b)));
    }
    out.push((xs[n - 1].min(xs[0]), xs[n - 1].max(xs[0])));
    debug_assert_eq!(out.len(), n, "one x-extent per edge, the closing edge last");
    debug_assert!(
        out.iter().all(|&(lo, hi)| lo <= hi),
        "an extent runs low to high"
    );
}

/// [`rings_meet`] by plane sweep: one event per edge, ascending by its left x.
/// An edge entering is tested against the *opposite* ring's live list and then
/// joins its own, so every cross pair that can meet is tested exactly once.
fn rings_meet_sweep(ax: &[Dbu], ay: &[Dbu], bx: &[Dbu], by: &[Dbu]) -> bool {
    let (n, m) = (ax.len(), bx.len());
    debug_assert!(
        n > 0 && m > 0,
        "an empty ring is polys_intersect's own answer"
    );

    let (mut span_a, mut span_b) = (Vec::new(), Vec::new());
    edge_xspans_into(ax, &mut span_a);
    edge_xspans_into(bx, &mut span_b);

    // Sort the numbering, not the extents: `ring_edge` takes an edge index.
    let edges_a = u32::try_from(n).expect("a ring has fewer than u32::MAX vertices");
    let edges_b = u32::try_from(m).expect("a ring has fewer than u32::MAX vertices");
    let mut order_a: Vec<u32> = (0..edges_a).collect();
    let mut order_b: Vec<u32> = (0..edges_b).collect();
    order_a.sort_unstable_by_key(|&i| span_a[i as usize]);
    order_b.sort_unstable_by_key(|&i| span_b[i as usize]);
    debug_assert!(
        order_a
            .windows(2)
            .all(|w| span_a[w[0] as usize].0 <= span_a[w[1] as usize].0)
            && order_b
                .windows(2)
                .all(|w| span_b[w[0] as usize].0 <= span_b[w[1] as usize].0),
        "the sweep visits edges in ascending left x"
    );

    let (mut live_a, mut live_b) = (Vec::new(), Vec::new());
    let (mut ia, mut ib) = (0usize, 0usize);

    while ia < n || ib < m {
        // The sentinel is far outside `MAX_ABS_DBU`, so a spent side never
        // wins the compare and the loop drains the other.
        let key_a = order_a
            .get(ia)
            .map_or(i64::MAX, |&i| span_a[i as usize].0.raw());
        let key_b = order_b
            .get(ib)
            .map_or(i64::MAX, |&i| span_b[i as usize].0.raw());
        let sweep_x = key_a.min(key_b);

        // Retire before admitting: an edge ending left of the sweep line can
        // share no point with anything still to come, which is what holds the
        // live lists at the local crossing depth and the sweep sub-quadratic.
        live_a.retain(|&i| span_a[i as usize].1.raw() >= sweep_x);
        live_b.retain(|&i| span_b[i as usize].1.raw() >= sweep_x);

        if key_a <= key_b {
            let edge = order_a[ia];
            ia += 1;
            if meets_any(ring_edge(ax, ay, edge as usize), bx, by, &live_b) {
                return true;
            }
            live_a.push(edge);
        } else {
            let edge = order_b[ib];
            ib += 1;
            if meets_any(ring_edge(bx, by, edge as usize), ax, ay, &live_a) {
                return true;
            }
            live_b.push(edge);
        }

        debug_assert!(
            live_a.len() <= ia && live_b.len() <= ib,
            "an edge is live only after its own event"
        );
    }

    false
}

/// Whether `edge` meets any of a ring's live edges.
fn meets_any(edge: Seg, xs: &[Dbu], ys: &[Dbu], live: &[u32]) -> bool {
    live.iter()
        .any(|&i| segments_intersect(edge, ring_edge(xs, ys, i as usize)))
}

/// Whether a point lies strictly inside a closed ring: an even-odd ray cast
/// towards +x, exact in `i128`. Boundary points are `rings_meet`'s answer, so
/// the rule here is half-open.
///
/// `core::ops::point_in_ring` is the same predicate and is unreachable: it
/// takes a `RingRef`, and building one means validating the layer — a fallible
/// pass whose error this signature has nowhere to report.
fn point_inside(xs: &[Dbu], ys: &[Dbu], px: Dbu, py: Dbu) -> bool {
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    let n = xs.len();
    // Under three vertices there is no interior to be inside of.
    if n < 3 {
        return false;
    }

    // Seeding with the last vertex puts the closing edge in the loop.
    let mut crossings = 0u32;
    let (mut ax, mut ay) = (xs[n - 1], ys[n - 1]);
    for i in 0..n {
        let (bx, by) = (xs[i], ys[i]);
        // `(b - a) × (p - a)`, positive when `p` is left of the edge. Widened
        // before the multiply: differences reach 2^41 and the product 2^82, so
        // `i64` would silently wrap.
        let side = i128::from(bx.raw() - ax.raw()) * i128::from(py.raw() - ay.raw())
            - i128::from(by.raw() - ay.raw()) * i128::from(px.raw() - ax.raw());
        // Half-open: a vertex is counted by exactly one of its two edges, so
        // a ray grazing one is not counted twice.
        let up = by.raw() > ay.raw();
        let straddles = (ay.raw() > py.raw()) != (by.raw() > py.raw());
        crossings += u32::from(straddles & ((side > 0) == up));
        (ax, ay) = (bx, by);
    }

    crossings & 1 == 1
}

/// The edge builders' working storage. Every column is dead between builder
/// calls, which is what makes one set safe to share across layers.
#[derive(Debug, Default)]
struct EdgeScratch {
    /// The conductor layer's index, rebuilt per layer and per side of a via.
    index: SpatialIndex,
    /// The cut layer's index, held apart because a via queries the two
    /// against each other.
    cut_index: SpatialIndex,
    /// Bounding-box candidates, before the exact intersection test.
    pairs: Vec<(PolyId, PolyId)>,
    /// The candidates that survived it.
    touching: Vec<(PolyId, PolyId)>,
    /// `(cut, conductor)` landings on the two layers of a via, held at once
    /// because [`via_edges_append`] merges them against each other.
    on_lower: Vec<(PolyId, PolyId)>,
    on_upper: Vec<(PolyId, PolyId)>,
}

/// Edges from shapes touching on one conductor layer.
pub fn intra_layer_edges_into(store: &GeometryStore, layer: LayerId, out: &mut Vec<(u32, u32)>) {
    out.clear();
    intra_layer_edges_append(store, layer, &mut EdgeScratch::default(), out);
}

/// [`intra_layer_edges_into`] appending to `out` through borrowed scratch.
fn intra_layer_edges_append(
    store: &GeometryStore,
    layer: LayerId,
    scratch: &mut EdgeScratch,
    out: &mut Vec<(u32, u32)>,
) {
    debug_assert!(
        layer.idx() < store.layer_count(),
        "a layer the store's layer table does not have"
    );
    let base = out.len();

    SpatialIndex::build_into(store, layer, &mut scratch.index);

    // Distance zero, because `Bbox::within(_, 0)` *is* `overlaps`, which counts
    // touching: two shapes sharing an edge and no area are one conductor.
    candidate_pairs_into(
        store,
        &scratch.index,
        Dbu::new_unchecked(0),
        &mut scratch.pairs,
    );

    // A wrongly merged net is fail-open, so every candidate is re-tested.
    retain_intersecting_into(store, &scratch.pairs, &mut scratch.touching);

    out.reserve(scratch.touching.len());
    for &(a, b) in &scratch.touching {
        out.push((a.0, b.0));
    }

    debug_assert_eq!(
        out.len() - base,
        scratch.touching.len(),
        "one edge per surviving pair"
    );
    debug_assert!(
        out[base..].iter().all(|&(a, b)| a < b),
        "the same-layer prune emits `a < b` only, and the exact test preserves it"
    );
}

/// Edges from a via cut overlapping shapes on the two layers it joins. A cut
/// overlapping only one of the two contributes no edge and is not an error.
pub fn via_edges_into(
    store: &GeometryStore,
    cut: LayerId,
    connects: (LayerId, LayerId),
    out: &mut Vec<(u32, u32)>,
) {
    out.clear();
    via_edges_append(store, cut, connects, &mut EdgeScratch::default(), out);
}

/// [`via_edges_into`] appending to `out` through borrowed scratch. The sort and
/// dedup below cover this call's rows only: `out` may already carry another
/// layer's edges, which must not be reshuffled into this run.
fn via_edges_append(
    store: &GeometryStore,
    cut: LayerId,
    connects: (LayerId, LayerId),
    scratch: &mut EdgeScratch,
    out: &mut Vec<(u32, u32)>,
) {
    let (lower, upper) = connects;
    debug_assert_ne!(lower, upper, "a via joins two different layers");
    debug_assert_ne!(cut, lower, "a cut layer is not one of the layers it joins");
    debug_assert_ne!(cut, upper, "a cut layer is not one of the layers it joins");
    debug_assert!(
        [cut, lower, upper]
            .iter()
            .all(|l| l.idx() < store.layer_count()),
        "a layer the store's layer table does not have"
    );

    let base = out.len();

    SpatialIndex::build_into(store, cut, &mut scratch.cut_index);
    // No cuts is an answer, not an error: most via layers are empty per cell.
    if scratch.cut_index.is_empty() {
        return;
    }

    // Destructured because the borrow checker splits fields of a `&mut` struct
    // but not fields reached through a call.
    let EdgeScratch {
        cut_index,
        index,
        pairs,
        on_lower,
        on_upper,
        ..
    } = scratch;
    cuts_landing_on(store, cut_index, lower, index, pairs, on_lower);
    cuts_landing_on(store, cut_index, upper, index, pairs, on_upper);

    // Both lists are ascending by `(cut, conductor)`, so the join is a merge on
    // the cut column and every edge it emits spans the two layers asked about.
    let mut lo = 0usize;
    let mut hi = 0usize;
    while lo < on_lower.len() && hi < on_upper.len() {
        // The merge advance skips a cut with material on only one layer: the
        // stacked-via-array case, legal and contributing no edge.
        let (a, b) = (on_lower[lo].0, on_upper[hi].0);
        if a < b {
            lo += 1;
            continue;
        }
        if b < a {
            hi += 1;
            continue;
        }

        let lo_end = lo + on_lower[lo..].partition_point(|&(c, _)| c == a);
        let hi_end = hi + on_upper[hi..].partition_point(|&(c, _)| c == a);
        for &(_, low_poly) in &on_lower[lo..lo_end] {
            for &(_, high_poly) in &on_upper[hi..hi_end] {
                out.push((low_poly.0, high_poly.0));
            }
        }
        lo = lo_end;
        hi = hi_end;
    }

    // A stack of cuts over one pair of shapes is a redundant edge, not a second
    // one; sorting first makes the answer a function of the geometry alone.
    sort_dedup_from(out, base);

    debug_assert!(
        out[base..].windows(2).all(|w| w[0] < w[1]),
        "via edges come back strictly ascending and deduplicated"
    );
}

/// Sort and deduplicate `out[base..]`, leaving everything before `base` alone:
/// those rows belong to an earlier layer and must not be shuffled into this
/// run. `w <= r` by induction — both start at 1 and `w` advances by
/// `usize::from(bool)` — so the branchless store never overwrites a row the
/// scan has yet to read.
fn sort_dedup_from(out: &mut Vec<(u32, u32)>, base: usize) {
    debug_assert!(base <= out.len(), "the run starts inside the buffer");

    let tail = &mut out[base..];
    tail.sort_unstable();

    let mut w = usize::from(!tail.is_empty());
    for r in 1..tail.len() {
        let row = tail[r];
        let keep = row != tail[w - 1];
        debug_assert!(w <= r, "the compact never outruns the scan");
        tail[w] = row;
        w += usize::from(keep);
    }
    out.truncate(base + w);

    debug_assert!(
        out[base..].windows(2).all(|w| w[0] < w[1]),
        "a deduplicated sorted run is strictly ascending"
    );
}

/// Every `(cut, conductor)` pair where the cut really lands, ascending, which
/// is what lets [`via_edges_append`] merge two of these instead of searching.
fn cuts_landing_on(
    store: &GeometryStore,
    cut_index: &SpatialIndex,
    layer: LayerId,
    index: &mut SpatialIndex,
    pairs: &mut Vec<(PolyId, PolyId)>,
    out: &mut Vec<(PolyId, PolyId)>,
) {
    SpatialIndex::build_into(store, layer, index);
    cross_layer_pairs_into(store, cut_index, index, Dbu::new_unchecked(0), pairs);

    // A cut whose box reaches a conductor it does not touch would merge two
    // nets. Also what the containment probe is for: a cut sits *inside* the
    // conductor it lands on, sharing no edge with it.
    retain_intersecting_into(store, pairs, out);

    debug_assert!(
        out.windows(2).all(|w| w[0] < w[1]),
        "the cross-layer prune is ascending and the exact test preserves it"
    );
}

#[cfg(test)]
mod tests {
    use super::{
        rings_meet_direct, rings_meet_sweep, sort_dedup_from, NetId, NetTable, DIRECT_PAIR_BUDGET,
    };
    use gpurify_geom::Dbu;
    use gpurify_geom::PolyId;

    /// Reads the private columns directly: every public accessor reads the CSR
    /// under test, so a matching pair of errors could cancel.
    #[test]
    fn a_stated_assignment_builds_the_reverse_index_it_implies() {
        let none = NetId::NONE;
        let table = NetTable::from_assignment(&[NetId(1), NetId(0), NetId(1), none, NetId(0)]);

        assert_eq!(table.net_start, [0, 2, 4], "two nets of two polygons each");
        assert_eq!(
            table.polys,
            [PolyId(1), PolyId(4), PolyId(0), PolyId(2)],
            "each net's polygons must come back ascending"
        );
        assert_eq!(
            table.poly_net,
            [NetId(1), NetId(0), NetId(1), none, NetId(0)],
            "the forward column is the caller's, unrenumbered"
        );

        // A store holding nothing but markers and cuts has no nets at all.
        let nothing = NetTable::from_assignment(&[none, none]);
        assert_eq!(nothing.net_start, [0]);
        assert!(nothing.polys.is_empty());

        assert_eq!(
            table,
            NetTable::from_assignment(&[NetId(1), NetId(0), NetId(1), none, NetId(0)])
        );
        assert_ne!(table, nothing);
    }

    /// Must leave `v[..base]` as it was and agree with `sort_unstable` +
    /// `dedup` on `v[base..]`.
    #[test]
    fn deduplicating_a_run_leaves_the_rows_before_it_untouched() {
        let head = [(9u32, 9u32), (0, 0), (9, 9)];
        for tail in [
            vec![],
            vec![(1u32, 2u32)],
            vec![(1, 2), (1, 2)],
            vec![(3, 4), (1, 2), (3, 4), (1, 2), (1, 2)],
            vec![(5, 5); 32],
            vec![(2, 1), (1, 2), (2, 2), (1, 1)],
        ] {
            let mut got: Vec<(u32, u32)> = head.iter().copied().chain(tail.clone()).collect();
            sort_dedup_from(&mut got, head.len());

            let mut want = tail.clone();
            want.sort_unstable();
            want.dedup();

            assert_eq!(&got[..head.len()], &head, "an earlier layer's rows moved");
            assert_eq!(&got[head.len()..], &want[..], "tail={tail:?}");
        }
    }

    /// A star of `n` vertices centred on `(cx, cy)`, alternating between two
    /// radii so edge x-extents overlap heavily.
    fn star(n: usize, cx: i64, cy: i64, near: i32, far: i32) -> (Vec<Dbu>, Vec<Dbu>) {
        let vertices = u32::try_from(n).expect("this fixture's rings are tens of vertices");
        let mut xs = Vec::with_capacity(n);
        let mut ys = Vec::with_capacity(n);
        for i in 0..vertices {
            let radius = if i % 2 == 0 { far } else { near };
            let theta = std::f64::consts::TAU * f64::from(i) / f64::from(vertices);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "|cos| and |sin| are at most 1 and `radius` is a call-site \
                          literal of at most 1000, so the product lands well inside i64"
            )]
            let (dx, dy) = (
                (theta.cos() * f64::from(radius)) as i64,
                (theta.sin() * f64::from(radius)) as i64,
            );
            xs.push(Dbu::new(cx + dx).expect("inside the coordinate domain"));
            ys.push(Dbu::new(cy + dy).expect("inside the coordinate domain"));
        }
        (xs, ys)
    }

    /// The sweep and the exhaustive scan compute one predicate, so they must
    /// agree on every input.
    #[test]
    fn the_sweep_and_the_exhaustive_scan_agree_on_every_ring_pair() {
        // The sizes below are chosen against the budget.
        const {
            assert!(
                8 * 8 <= DIRECT_PAIR_BUDGET,
                "the small pair takes the direct scan"
            );
            assert!(
                64 * 64 > DIRECT_PAIR_BUDGET,
                "the large pair takes the sweep"
            );
        }

        let mut saw_meeting = false;
        let mut saw_apart = false;
        for &n in &[3usize, 8, 33, 64, 129] {
            let (ax, ay) = star(n, 0, 0, 400, 1000);
            for &m in &[3usize, 8, 33, 64, 129] {
                for &offset in &[0i64, 300, 900, 1600, 4000] {
                    // Smaller than the other's inner radius: strictly nested.
                    let (bx, by) = star(m, offset, 0, 80, 200);
                    let direct = rings_meet_direct(&ax, &ay, &bx, &by);
                    let sweep = rings_meet_sweep(&ax, &ay, &bx, &by);
                    assert_eq!(
                        direct, sweep,
                        "n={n} m={m} offset={offset}: the sweep pruned a pair that meets"
                    );
                    // The predicate is symmetric.
                    assert_eq!(
                        direct,
                        rings_meet_sweep(&bx, &by, &ax, &ay),
                        "n={n} m={m} offset={offset}: the sweep is not symmetric"
                    );
                    saw_meeting |= direct;
                    saw_apart |= !direct;
                }
            }
        }
        assert!(
            saw_meeting,
            "a corpus where no pair ever meets proves nothing"
        );
        assert!(saw_apart, "nor one where every pair meets");
    }
}
