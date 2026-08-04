//! Net extraction: which shapes are electrically the same conductor.
//!
//! Two shapes join if they are on the same conductor layer and touch, or if a
//! via cut on the right layer overlaps both. That is the whole rule; everything
//! else is finding the pairs efficiently, which is `core::index`'s job, and
//! labelling the components, which is `core::connectivity`'s.

use crate::csr_run;
use gpurify_core::connectivity::{components_into, ComponentLabel};
use gpurify_core::index::{candidate_pairs_into, cross_layer_pairs_into, SpatialIndex};
use gpurify_core::ops::{segments_intersect, Point, Seg};
use gpurify_core::{GeometryStore, LayerId, PolyId};
use gpurify_ingest::deck::Connectivity;
use gpurify_units::Dbu;

/// Identifies one electrical net.
///
/// Derived from a [`ComponentLabel`], which is the minimum polygon index in the
/// component — so net ids are canonical: the same layout gives the same ids on
/// every run and every machine, regardless of thread count. The determinism
/// gate rests on that, and so does any test comparing extracted nets by id.
///
/// It is a *dense rank*, not the label itself: nets are numbered
/// `0 .. net_count` in ascending order of their smallest [`PolyId`]. Both
/// readings are canonical, and only the dense one indexes the CSR reverse index
/// below, so that is the one the tables use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct NetId(pub u32);

impl NetId {
    /// The polygon is on no net at all.
    ///
    /// A polygon whose layer is absent from [`Connectivity::conductors`] — a
    /// via cut, a device marker, any drawn-but-not-conducting shape — carries
    /// this. It is not a net: it is outside `0 .. net_count`, [`polys_of`]
    /// never lists it, and [`same_net`] is false for it against anything,
    /// itself included.
    ///
    /// A sentinel rather than an `Option` because [`net_of`] is asked per
    /// candidate pair by every spacing rule in `drc`, and the answer is a
    /// compare either way. Fail-closed both ways round: a marker never joins a
    /// conductor's net, and two markers never exempt each other from a spacing
    /// check by claiming to share one.
    ///
    /// [`polys_of`]: NetTable::polys_of
    /// [`same_net`]: NetTable::same_net
    /// [`net_of`]: NetTable::net_of
    pub const NONE: Self = Self(u32::MAX);

    /// The raw index, for use as a slice subscript. Matches `core::ids`.
    ///
    /// Meaningless on [`NetId::NONE`], which indexes nothing.
    #[must_use]
    pub const fn idx(self) -> usize {
        self.0 as usize
    }
}

/// Which net each polygon belongs to.
///
/// **Five questions.** In: a store and the deck's connectivity rules. Out: one
/// [`NetId`] per polygon, plus the reverse index. How many: one row per
/// polygon, millions. Access pattern: `poly_net` is read randomly by rules
/// asking "same net?"; `net_polys` is scanned per net by resistance and
/// antenna rules — so both directions exist, and the reverse one is CSR.
/// Lifetime: whole run. Parallelisable: pair-finding is; the union-find is not,
/// which is why it is a separate sequential pass over a precomputed edge list.
#[derive(Debug, Default)]
pub struct NetTable {
    /// Net of each polygon, indexed by [`PolyId`].
    poly_net: Vec<NetId>,
    /// `polys[net_start[n] .. net_start[n + 1]]` are net `n`'s polygons,
    /// ascending. CSR, not a `Vec<Vec<PolyId>>`.
    net_start: Vec<u32>,
    polys: Vec<PolyId>,
    /// Scratch, kept so a second extraction reuses the allocation.
    edges: Vec<(u32, u32)>,
    labels: Vec<ComponentLabel>,
    /// The edge builders' working storage, kept for the same reason. It is the
    /// whole per-layer allocation set, so holding it here is what turns "one
    /// allocation set per conductor layer" into "one per table, ever".
    scratch: EdgeScratch,
}

impl NetTable {
    /// How many nets there are. Ids run `0 .. net_count`; [`NetId::NONE`] is
    /// not one of them.
    pub fn net_count(&self) -> usize {
        // `saturating_sub`, not `- 1`: a `Default` table has no offsets at all,
        // and zero nets is the honest answer for it. Same argument as
        // `GeometryStore::layer_count`.
        self.net_start.len().saturating_sub(1)
    }

    /// The net of a polygon, or [`NetId::NONE`] if it is on no conductor layer.
    pub fn net_of(&self, poly: PolyId) -> NetId {
        // Fail closed: a polygon this table never saw indexes out of bounds and
        // panics in every profile. Returning `NONE` for it would make "on no
        // net" and "not in this extraction" indistinguishable, and a rule that
        // reads the second as the first exempts geometry nobody checked.
        self.poly_net[poly.idx()]
    }

    /// The polygons on one net, ascending by [`PolyId`]. Empty for
    /// [`NetId::NONE`].
    pub fn polys_of(&self, net: NetId) -> &[PolyId] {
        // Surviving `if`: not a bulk loop — this is asked once per net by a
        // resistance or antenna scan, and the taken side is a whole slice.
        // `NONE`'s index is `u32::MAX`, so falling through would panic rather
        // than return the empty slice the interface promises.
        if net == NetId::NONE {
            return &[];
        }
        // Any other id past `net_count` panics here, for `net_of`'s reason.
        let (from, to) = csr_run(&self.net_start, net.idx());
        &self.polys[from..to]
    }

    /// Whether two polygons are the same net. The question most rules ask.
    ///
    /// False when either is on no net, even for a polygon against itself:
    /// [`NetId::NONE`] is an absence, not a net two shapes can share.
    pub fn same_net(&self, a: PolyId, b: PolyId) -> bool {
        let (a, b) = (self.net_of(a), self.net_of(b));
        // `&`, not `&&`: both operands are two already-loaded `u32`s with no
        // side effect, so short-circuiting would buy a branch rather than save
        // work. The first conjunct is what makes `NONE` false against itself —
        // an absence is not a net two shapes can share.
        (a != NetId::NONE) & (a == b)
    }

    /// Build directly from a per-polygon net assignment.
    ///
    /// Reopened in the Testing-Phase. Every field here is private and
    /// [`extract_nets_into`] was the only producer, so a test could not state
    /// the net partition it expected. That blocked all of `lvs::checks`, both
    /// `erc` antenna rules and the `erc` ESD rules — none of which care how the
    /// partition was arrived at, only what it is.
    ///
    /// `poly_net[i]` is the net of `PolyId(i)`, or [`NetId::NONE`] for a
    /// polygon on no conductor layer. The reverse CSR index is rebuilt here, so
    /// the two directions cannot disagree.
    ///
    /// **Does not re-canonicalise.** [`NetId`] is documented as the rank of a
    /// net ordered by its smallest polygon, and this trusts the caller for that
    /// rather than silently renumbering — a test that wants a non-canonical
    /// assignment is usually testing whether canonicality is assumed, and
    /// repairing it here would hide the answer. An id the caller skipped
    /// therefore becomes a net with no polygons, which extraction never
    /// produces.
    ///
    /// # Panics
    ///
    /// When `poly_net` holds more than `u32::MAX` rows, which is more polygons
    /// than a [`PolyId`] can name.
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
///
/// **Transform, A-to-B.** Caller owns both outputs, cleared and refilled, so
/// [`extract_nets_into`] rebuilds a table's index without reallocating it.
/// Split out of [`NetTable::from_assignment`] because extraction wants the same
/// counting sort over buffers it already holds, and two copies of a counting
/// sort is two places for the two directions to disagree.
fn rebuild_index(poly_net: &[NetId], net_start: &mut Vec<u32>, polys: &mut Vec<PolyId>) {
    // How many nets the assignment names: a max over a column, folded strictly
    // left to right.
    //
    // Branchless, because `NetId::NONE` cannot be filtered out first: its
    // `idx() + 1` is `u32::MAX as usize + 1`, which would win every max and
    // size the CSR at four billion nets. The mask folds it to zero instead,
    // which is `max`'s identity.
    let mut net_count = 0usize;
    for &net in poly_net {
        let live = usize::from(net != NetId::NONE).wrapping_neg();
        net_count = net_count.max((net.idx() + 1) & live);
    }

    // A CSR build is a counting sort: the scatter's output index is
    // data-dependent and the prefix sum is carried from row to row, so neither
    // pass vectorises and neither is a candidate for it.
    //
    // `net_start[n + 1]` counts net `n`, then a prefix sum turns the counts
    // into offsets in place.
    net_start.clear();
    net_start.resize(net_count + 1, 0);
    // Surviving `if`, here and in the scatter below: a `NONE` row must not be
    // counted, and `NONE`'s index is `u32::MAX`, so there is no in-range slot to
    // write it to harmlessly instead. Both loops are unvectorisable scatters
    // regardless, so predicating the store would buy nothing.
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

/// Equal when the partition is equal.
///
/// The scratch columns are working storage that outlives a call, not part of
/// the value: a table extracted into twice must compare equal to a fresh one
/// holding the same nets, which is exactly what the determinism gate asks.
impl PartialEq for NetTable {
    fn eq(&self, other: &Self) -> bool {
        self.poly_net == other.poly_net
            && self.net_start == other.net_start
            && self.polys == other.polys
    }
}

impl Eq for NetTable {}

/// Extract nets from geometry.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled; its internal
/// scratch survives, so extracting twice allocates once.
///
/// Two passes, deliberately. The first builds the edge list — intra-layer
/// touching and via-mediated joins — and is a pure function of the geometry,
/// so it parallelises by layer. The second runs the union-find, which is
/// inherently sequential. Fusing them would make the whole thing sequential for
/// no gain; this is the "take two passes instead" case the kernel rule names.
///
/// # Which polygons get a net
///
/// Only those on a layer in [`Connectivity::conductors`]. Everything else — a
/// via cut, a device marker, a text or fill layer — gets [`NetId::NONE`] and is
/// counted by no net. A cut *joins* the two conductors it overlaps; it does not
/// *belong* to the net it joins, which is why `via_cut` and `conductors` are
/// separate columns of the deck.
///
/// Stating it is what makes [`crate::port::PortError::OrphanLabel`]
/// constructible: a label placed on a cut is attached to a shape on no net, and
/// that is the condition the variant names. The alternative — a singleton net
/// per non-conductor polygon — would leave every label bound to something and
/// the variant unreachable.
pub fn extract_nets_into(
    store: &GeometryStore,
    connectivity: &Connectivity,
    out: &mut NetTable,
) {
    let rows = store.poly_count();
    let node_count = u32::try_from(rows).expect("a polygon index fits a PolyId");
    debug_assert_eq!(
        connectivity.via_cut.len(),
        connectivity.via_connects.len(),
        "a via layer is a cut and the two layers it joins, in step"
    );

    // Pass one: the edge list, a pure function of the geometry.
    //
    // The two *appending* builders, not the public `_into` pair: `out.edges` is
    // the accumulator across every layer, and the builders' working storage is
    // one set held by the table rather than one set per layer. So a whole
    // extraction touches the allocator only where `edges` itself outgrows the
    // capacity a previous extraction left it, and there is no per-layer copy
    // out of a staging buffer.
    out.edges.clear();

    // Deck-sized loops, here and at the conductor scan below: tens of conductor
    // layers and tens of via layers, so neither is bulk. The bulk work is inside
    // the two builders they call.
    //
    // Hoisted uniform, not a per-row test: the deck either joins touching
    // shapes on a conductor layer or it does not.
    if connectivity.intra_layer_touch {
        for &layer in &connectivity.conductors {
            intra_layer_edges_append(store, layer, &mut out.scratch, &mut out.edges);
        }
    }
    for (&cut, &connects) in connectivity.via_cut.iter().zip(&connectivity.via_connects) {
        via_edges_append(store, cut, connects, &mut out.scratch, &mut out.edges);
    }
    debug_assert!(
        out.edges.iter().all(|&(a, b)| a < node_count && b < node_count),
        "an edge names a polygon this store does not have"
    );

    // Pass two: the union-find, which is inherently sequential.
    components_into(node_count, &out.edges, &mut out.labels);
    debug_assert_eq!(out.labels.len(), rows, "one label per polygon");

    // Which layers conduct. Dense over the store's layer table, so the test
    // below is an array read and not a scan of `conductors` per polygon.
    //
    // Fail closed: a conductor the store's layer table does not have indexes
    // out of bounds and panics, in every profile. Skipping it would extract a
    // netlist missing a whole layer and report it as clean.
    let mut conducts = vec![false; store.layer_count()];
    for &layer in &connectivity.conductors {
        conducts[layer.idx()] = true;
    }

    // Pass three: labels to dense net ids.
    //
    // `rank` is a scatter at a data-dependent index and `next` is carried from
    // row to row, so this is serial by shape. The body carries no branch.
    //
    // Walking ascending is what makes the numbering canonical: a label is the
    // minimum polygon index in its component, so the first row to claim a rank
    // is that component's smallest polygon, and ranks therefore come out
    // ascending by each net's smallest `PolyId` — exactly what `NetId`
    // documents.
    out.poly_net.clear();
    out.poly_net.reserve(rows);
    let mut rank = vec![u32::MAX; rows];
    let mut next = 0u32;
    for row in 0..node_count {
        let poly = PolyId(row);
        let label = out.labels[poly.idx()].0 as usize;
        let conducting = conducts[store.poly_layer(poly).idx()];

        // Claim a rank the first time a conducting polygon names this label.
        // The store is unconditional and rewrites the same value when the rank
        // was already claimed, so the decision rides in the value.
        let seen = rank[label];
        let fresh = (seen == u32::MAX) & conducting;
        let fresh_mask = u32::from(fresh).wrapping_neg();
        let id = (next & fresh_mask) | (seen & !fresh_mask);
        rank[label] = id;
        next += u32::from(fresh);

        // `!mask` is all ones for a non-conductor, which is `NetId::NONE` — a
        // via cut, a device marker, any drawn-but-not-conducting shape.
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
/// **Decision** — two rows in, one bool out. The bounding-box prune upstream
/// answers "these two boxes touch", and a box is a superset of the shape inside
/// it: joining two nets that share only a bounding box is fail-**open** for
/// every rule that exempts a same-net pair from a spacing check. So every pair
/// the prune keeps is re-tested exactly, which is the same discipline
/// `drc::rules::spacing` applies with `ops::seg_seg_dist2`.
///
/// Private, and reached from outside this module through
/// [`retain_intersecting_into`]. [`crate::device`] asks the same question of a
/// marker polygon and a terminal polygon and had re-derived this and its three
/// helpers verbatim. The predicate is what closes a fail-open in both places — a
/// box-only hit binding a terminal to a net it does not touch is the same defect
/// as a box-only hit merging two nets — so one copy is one place for that
/// argument to hold.
fn polys_intersect(store: &GeometryStore, a: PolyId, b: PolyId) -> bool {
    let (ax, ay) = store.poly_verts(a);
    let (bx, by) = store.poly_verts(b);
    debug_assert_eq!(ax.len(), ay.len(), "the store's columns are parallel");
    debug_assert_eq!(bx.len(), by.len(), "the store's columns are parallel");

    // A run with no vertices bounds no points and so shares none. Guarded
    // rather than asserted because the probe below reads vertex zero.
    if ax.is_empty() || bx.is_empty() {
        return false;
    }

    // `||`, not `|`: each of the two containment walks is a full pass over a
    // ring, which is the "taken side is expensive" escape valve. Boundary
    // contact is already answered by `rings_meet`, so the probes only have to
    // decide the strict interior — one vertex is enough, because two rings
    // whose boundaries do not meet are either nested or disjoint.
    rings_meet(ax, ay, bx, by)
        || point_inside(bx, by, ax[0], ay[0])
        || point_inside(ax, ay, bx[0], by[0])
}

/// The pairs of `pairs` whose polygons really intersect, in the same order.
///
/// **Transform, gatherer.** Caller owns `out`, cleared and refilled. Order is
/// preserved, so a prune that emitted ascending pairs still has ascending pairs
/// on the way out.
///
/// One copy because the unchecked store below is the sharpest thing in this
/// crate and three separate copies of its induction argument is three chances to
/// get one wrong. Every caller is the same shape: a bounding-box prune produced
/// candidates, and each has to be re-tested exactly before it is believed.
///
/// The compact is branchless — the store is unconditional and the write index
/// carries the predicate — because the exact test's selectivity is genuinely
/// per-pair and sits nowhere near either end, so it never reaches the branch
/// predictor. `out` is reserved for the whole input rather than for the
/// survivors; that over-reservation is the memory-for-branches trade.
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
        // Unchecked, and slicing to `[..pairs.len()]` is not enough to earn it:
        // `w`'s step is data-dependent, so LLVM gets no affine recurrence and
        // cannot prove `w < slots.len()`. It emits a live `cmp/jae` to a panic
        // edge instead, which is an implicit branch in the loop body. Measured
        // at `-C target-cpu=x86-64-v3`, unchecked over checked: 1.19x at 8k,
        // 1.18x at 200k, 1.06x at 4M — `docs/BULK_MEASUREMENTS.md` §4.
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
    debug_assert!(i < xs.len(), "a ring edge starts at one of the ring's vertices");
    // Branchless wrap, the catalogue's `i++; if i >= n { i = 0 }` row: the
    // multiply is by zero for every vertex but the last.
    let next = (i + 1) - xs.len() * usize::from(i + 1 == xs.len());
    Seg {
        a: Point { x: xs[i], y: ys[i] },
        b: Point {
            x: xs[next],
            y: ys[next],
        },
    }
}

/// Edge pairs the direct scan may examine before the sweep pays for itself.
///
/// `segments_intersect` is four cross products; a sort comparison is one `Dbu`
/// compare, call it a sixteenth of that. The sweep costs
/// `(n + m)·log2(n + m)` comparisons plus six `Vec` allocations, so the two
/// meet somewhere around `n·m ≈ 10³` — two 32-vertex rings, already an order of
/// magnitude past the four-vertex rectangle that dominates a real layer. Every
/// ring below the budget therefore stays on the allocation-free path it was
/// always on, and the sweep is reached only where the quadratic scan is the
/// larger cost by a wide margin, which is what makes a rounded constant
/// adequate here rather than a measured one.
const DIRECT_PAIR_BUDGET: usize = 1 << 10;

/// Whether any edge of one ring meets any edge of the other, touching included.
///
/// **Decision** — two rings in, one bool out, exact in `i128` throughout.
///
/// Two paths over the same predicate, chosen by edge count against
/// [`DIRECT_PAIR_BUDGET`]: [`rings_meet_direct`] scans every edge pair and
/// allocates nothing, [`rings_meet_sweep`] walks both edge lists in ascending
/// x and tests only the pairs whose x-extents overlap. They answer identically
/// by construction — two segments that meet share a point, and that point's x
/// lies in both extents, so no pair the sweep skips could have met — and the
/// inline differential test below pins that at sizes straddling the crossover.
///
/// Both inner scans are searches with an early exit, so both are `Iterator::any`
/// rather than a counted loop.
fn rings_meet(
    ax: &[Dbu],
    ay: &[Dbu],
    bx: &[Dbu],
    by: &[Dbu],
) -> bool {
    // Surviving `if`: one test per ring pair rather than one per edge pair, and
    // both sides compute the same predicate, so it is a cost choice and not a
    // decision about a row. `saturating_mul`, because a ring pair big enough to
    // overflow the product is precisely the one that must take the sweep.
    if ax.len().saturating_mul(bx.len()) <= DIRECT_PAIR_BUDGET {
        return rings_meet_direct(ax, ay, bx, by);
    }
    rings_meet_sweep(ax, ay, bx, by)
}

/// [`rings_meet`] by exhaustive pair scan. The reference implementation, and
/// the path every ordinary layout polygon takes.
fn rings_meet_direct(ax: &[Dbu], ay: &[Dbu], bx: &[Dbu], by: &[Dbu]) -> bool {
    (0..ax.len()).any(|i| {
        let edge = ring_edge(ax, ay, i);
        (0..bx.len()).any(|j| segments_intersect(edge, ring_edge(bx, by, j)))
    })
}

/// The x-extent of every edge of a ring, in edge order.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled to one row
/// per edge. Edge `i` runs from vertex `i` to vertex `i + 1` and the last wraps
/// to vertex 0, so this is a map over two offset views of the x column with the
/// closing edge as one fixup after the loop. `y` is not needed: the sweep orders
/// and prunes on x alone, and the exact test reads the vertices itself.
fn edge_xspans_into(xs: &[Dbu], out: &mut Vec<(Dbu, Dbu)>) {
    let n = xs.len();
    debug_assert!(n > 0, "a ring with no vertices has no edges");

    // Two offset views of the same column, read in lockstep. Zipping would
    // silently take the shorter of the two, which is the fail-open shape this
    // project fears, so the equal length is asserted rather than assumed.
    let (from, to) = (&xs[..n - 1], &xs[1..]);
    debug_assert_eq!(from.len(), to.len(), "SoA columns must agree");

    // Reserved for `n`, not `n - 1`: the closing edge below is the `n`th row,
    // and reserving for it here is what keeps this to one allocation.
    out.clear();
    out.reserve(n);
    for i in 0..from.len() {
        let (a, b) = (from[i], to[i]);
        out.push((a.min(b), a.max(b)));
    }
    out.push((xs[n - 1].min(xs[0]), xs[n - 1].max(xs[0])));
    debug_assert_eq!(out.len(), n, "one x-extent per edge, the closing edge last");
    debug_assert!(out.iter().all(|&(lo, hi)| lo <= hi), "an extent runs low to high");
}

/// [`rings_meet`] by plane sweep in ascending x.
///
/// One event per edge of either ring, in ascending order of the edge's left x.
/// An edge entering the sweep is tested against the *opposite* ring's live list
/// — the edges that started left of the sweep line and have not ended before it
/// — and then joins its own. That set is exactly the edges whose x-extent
/// overlaps the entering one, so every cross pair that can meet is tested, and
/// each is tested once: at the event of whichever of the two enters later.
///
/// Six per-call allocations, which is what the budget in [`rings_meet`] buys
/// back. Hoisting them is a scratch parameter and so a signature change; see
/// `docs/SIGNATURE_DEFECTS.md` under `topology`.
fn rings_meet_sweep(ax: &[Dbu], ay: &[Dbu], bx: &[Dbu], by: &[Dbu]) -> bool {
    let (n, m) = (ax.len(), bx.len());
    debug_assert!(n > 0 && m > 0, "an empty ring is polys_intersect's own answer");

    let (mut span_a, mut span_b) = (Vec::new(), Vec::new());
    edge_xspans_into(ax, &mut span_a);
    edge_xspans_into(bx, &mut span_b);

    // Sort the edge numbering, not the extents: `ring_edge` is addressed by
    // edge index, and a `u32` is a quarter of the move width of an extent.
    let edges_a = u32::try_from(n).expect("a ring has fewer than u32::MAX vertices");
    let edges_b = u32::try_from(m).expect("a ring has fewer than u32::MAX vertices");
    let mut order_a: Vec<u32> = (0..edges_a).collect();
    let mut order_b: Vec<u32> = (0..edges_b).collect();
    order_a.sort_unstable_by_key(|&i| span_a[i as usize]);
    order_b.sort_unstable_by_key(|&i| span_b[i as usize]);
    debug_assert!(
        order_a.windows(2).all(|w| span_a[w[0] as usize].0 <= span_a[w[1] as usize].0)
            && order_b.windows(2).all(|w| span_b[w[0] as usize].0 <= span_b[w[1] as usize].0),
        "the sweep visits edges in ascending left x"
    );

    let (mut live_a, mut live_b) = (Vec::new(), Vec::new());
    let (mut ia, mut ib) = (0usize, 0usize);

    while ia < n || ib < m {
        // Surviving `if`s, inside `map_or`: the exhausted-side test is false
        // for every event but the last few, so it predicts at ~100%. The
        // sentinel is far outside `MAX_ABS_DBU`, so a spent side never wins the
        // compare and the loop drains the other one.
        let key_a = order_a.get(ia).map_or(i64::MAX, |&i| span_a[i as usize].0.raw());
        let key_b = order_b.get(ib).map_or(i64::MAX, |&i| span_b[i as usize].0.raw());
        let sweep_x = key_a.min(key_b);

        // Retire before admitting: an edge ending left of the sweep line can
        // share no point with anything still to come. This is what holds the
        // live lists at the local crossing depth instead of at the whole edge
        // count, and so what makes the sweep sub-quadratic. `Vec::retain` is
        // stdlib's compact and compacts in place; a hand-written one would
        // write to a second buffer and cost a third and fourth allocation to
        // say the same thing.
        live_a.retain(|&i| span_a[i as usize].1.raw() >= sweep_x);
        live_b.retain(|&i| span_b[i as usize].1.raw() >= sweep_x);

        // Surviving `if`: which list the next event came from. One test per
        // event, over two sides that do the same work on mirrored arguments.
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

/// Whether `edge` meets any of a ring's live edges. The sweep's inner search.
fn meets_any(edge: Seg, xs: &[Dbu], ys: &[Dbu], live: &[u32]) -> bool {
    live.iter()
        .any(|&i| segments_intersect(edge, ring_edge(xs, ys, i as usize)))
}

/// Whether a point lies strictly inside a closed ring.
///
/// **Decision** — a ring and a point in, one bool out. An even-odd ray cast
/// towards +x, exact in `i128`. Boundary points are `rings_meet`'s answer, not
/// this one's, so the crossing rule here is the half-open one and needs no
/// on-edge case.
///
/// `core::ops::point_in_ring` is the same predicate and is not reachable: it
/// takes a `RingRef`, which only `core::view` and `core::boolean` can build,
/// and reaching one would mean validating the layer — a fallible pass whose
/// error this signature has nowhere to report.
fn point_inside(
    xs: &[Dbu],
    ys: &[Dbu],
    px: Dbu,
    py: Dbu,
) -> bool {
    debug_assert_eq!(xs.len(), ys.len(), "a ring's columns are parallel");
    let n = xs.len();
    // Under three vertices there is no interior to be inside of. Not a
    // data-dependent branch over bulk data: one test per ring, hoisted above
    // the loop.
    if n < 3 {
        return false;
    }

    // One pass over both columns, strictly ascending, carrying the previous
    // vertex in two locals. Seeding them with the last vertex puts the ring's
    // closing edge in the loop rather than in a fixup after it. The body is
    // branchless: the crossing is accumulated as a widened bool, not counted
    // under an `if`. The columns were asserted parallel on entry.
    let mut crossings = 0u32;
    let (mut ax, mut ay) = (xs[n - 1], ys[n - 1]);
    for i in 0..n {
        let (bx, by) = (xs[i], ys[i]);
        // `(b - a) × (p - a)`, positive when `p` is left of the edge. Widened
        // before the multiply: the operands are differences of coordinates
        // bounded by `MAX_ABS_DBU`, so they reach 2^41 and the product 2^82 —
        // `i64` would silently wrap. Written out rather than through
        // `ops::orientation`, whose domain asserts are a panic edge that would
        // pin the loop to one element per iteration.
        let side = i128::from(bx.raw() - ax.raw()) * i128::from(py.raw() - ay.raw())
            - i128::from(by.raw() - ay.raw()) * i128::from(px.raw() - ax.raw());
        // The half-open convention: a vertex is counted by exactly one of the
        // two edges meeting at it, so a ray grazing one is not counted twice. An
        // upward edge counts when the point is left of it, a downward edge when
        // it is right — which is the ray towards +x crossing it, either way.
        let up = by.raw() > ay.raw();
        let straddles = (ay.raw() > py.raw()) != (by.raw() > py.raw());
        crossings += u32::from(straddles & ((side > 0) == up));
        (ax, ay) = (bx, by);
    }

    crossings & 1 == 1
}

/// The edge builders' working storage, owned across the whole layer loop.
///
/// **Five questions.** In and out: nothing — this is allocation, not data. How
/// many: one set per [`NetTable`], not one per layer and not one per call.
/// Access pattern: every column is cleared and refilled inside one builder call
/// and is dead between calls, which is what makes one set safe to share across
/// layers. Lifetime: the whole run, held by the table extraction fills.
/// Parallelisable: one set per worker, which is why it is a parameter and not a
/// static — a per-layer split needs nothing but a scratch each.
///
/// Private, and threaded only through the appending builders. The public
/// `_into` pair cannot name it: their signatures are frozen, and a fresh
/// default per call is exactly what they used to do inline.
#[derive(Debug, Default)]
struct EdgeScratch {
    /// The conductor layer's index. Rebuilt per layer, and per *side* of a via.
    index: SpatialIndex,
    /// The cut layer's index, held apart from `index` because a via queries the
    /// two against each other, once for each layer the cut joins.
    cut_index: SpatialIndex,
    /// Bounding-box candidates, before the exact intersection test.
    pairs: Vec<(PolyId, PolyId)>,
    /// The candidates that survived it, for the same-layer builder.
    touching: Vec<(PolyId, PolyId)>,
    /// `(cut, conductor)` landings on the lower and upper layer of a via, held
    /// at once because [`via_edges_append`] merges the two against each other.
    on_lower: Vec<(PolyId, PolyId)>,
    on_upper: Vec<(PolyId, PolyId)>,
}

/// Edges from shapes touching on one conductor layer.
///
/// **Transform, gatherer.** Separate and public because it is independently
/// testable: a table of touching and non-touching configurations, with the
/// answer known by construction.
pub fn intra_layer_edges_into(
    store: &GeometryStore,
    layer: LayerId,
    out: &mut Vec<(u32, u32)>,
) {
    out.clear();
    intra_layer_edges_append(store, layer, &mut EdgeScratch::default(), out);
}

/// [`intra_layer_edges_into`] appending to `out` through borrowed scratch.
///
/// The form [`extract_nets_into`] calls, and where the body actually lives. It
/// neither clears `out` nor allocates working storage, so the conductor loop
/// accumulates every layer's edges into one list through one set of buffers.
/// The public wrapper is this with a `clear` and a fresh scratch, which is all
/// its frozen signature can say.
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

    // Distance zero, because `Bbox::within(_, 0)` *is* `overlaps` and overlaps
    // counts touching: two shapes sharing an edge and no area are one
    // conductor, and a prune that wanted positive-area overlap would split
    // every abutted metal run in a real layout.
    candidate_pairs_into(
        store,
        &scratch.index,
        Dbu::new_unchecked(0),
        &mut scratch.pairs,
    );

    // The box prune is a superset: a pair whose boxes meet may share no point,
    // and a wrongly merged net is fail-open for every rule that exempts a
    // same-net pair. So every candidate is re-tested exactly.
    retain_intersecting_into(store, &scratch.pairs, &mut scratch.touching);

    // Map, one row out per row in: a `(PolyId, PolyId)` is two `u32`s already,
    // so the body is the newtype coming off and nothing else. No branch, and
    // the reserve is what keeps the push from testing capacity per row.
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

/// Edges from a via cut overlapping shapes on the two layers it joins.
///
/// A cut overlapping only one of the two is not an error — a stacked via array
/// produces those — but it contributes no edge.
pub fn via_edges_into(
    store: &GeometryStore,
    cut: LayerId,
    connects: (LayerId, LayerId),
    out: &mut Vec<(u32, u32)>,
) {
    out.clear();
    via_edges_append(store, cut, connects, &mut EdgeScratch::default(), out);
}

/// [`via_edges_into`] appending to `out` through borrowed scratch.
///
/// [`intra_layer_edges_append`]'s counterpart, and where that body lives too.
/// The sort and the dedup below cover this call's rows only — `out` may already
/// carry another layer's edges, which are already sorted and deduplicated among
/// themselves and must not be reshuffled into this call's run.
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
        [cut, lower, upper].iter().all(|l| l.idx() < store.layer_count()),
        "a layer the store's layer table does not have"
    );

    let base = out.len();

    SpatialIndex::build_into(store, cut, &mut scratch.cut_index);
    // No cuts on this layer is an answer, not an error: most of a PDK's via
    // layers are empty in any given cell.
    if scratch.cut_index.is_empty() {
        return;
    }

    // Destructured because `cuts_landing_on` writes one of these columns while
    // reading two others, and the borrow checker splits fields of a `&mut`
    // struct but not fields reached through a call.
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

    // Both lists come back ascending by `(cut, conductor)`, so the join is a
    // merge on the cut column and every edge it emits spans the two layers
    // asked about — a cut over two shapes on the *same* layer contributes to
    // one list twice and to the product not at all.
    //
    // One cut emits the whole cross product of the shapes it lands on, so the
    // output row count is data-dependent, and the merge's two cursors are
    // carried between iterations. Serial by shape.
    let mut lo = 0usize;
    let mut hi = 0usize;
    while lo < on_lower.len() && hi < on_upper.len() {
        // Surviving `if`s: the advance of a merge join, which is the algorithm
        // rather than a decision about a row. The taken side skips a whole
        // cut's group, and a cut with material on only one of the two layers —
        // the stacked-via-array case, which is legal and contributes no edge —
        // is exactly what they skip.
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

    // A stack of cuts over one pair of shapes is a redundant edge, not a
    // second one. Sorting first is what makes the answer a function of the
    // geometry alone rather than of the order the cuts were filed in.
    sort_dedup_from(out, base);

    debug_assert!(
        out[base..].windows(2).all(|w| w[0] < w[1]),
        "via edges come back strictly ascending and deduplicated"
    );
}

/// Sort and deduplicate `out[base..]`, leaving everything before `base` alone.
///
/// **Transform, in-place.** `Vec::sort_unstable` + `Vec::dedup` is stdlib's
/// version and is not reachable here: it works on the whole vector, and an
/// appending builder owns only the rows it just wrote — the ones before `base`
/// belong to an earlier layer, are already sorted among themselves, and must
/// not be shuffled into this run.
///
/// The compact is branchless: the store is unconditional and the write index
/// carries the predicate, so the long run of duplicates a via array produces
/// costs no branch. `w <= r` by induction — both start at 1 and `w` advances by
/// `usize::from(bool)`, which is 0 or 1 — so the store never overwrites a row
/// the scan has yet to read, and `tail[w - 1]` is always the last row kept.
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

/// Every `(cut, conductor)` pair where the cut really lands on the conductor.
///
/// **Transform, gatherer.** Caller owns `out`, cleared and refilled, and owns
/// the two working columns as well: this is called once per layer a cut joins,
/// so building the index and the candidate list here would allocate per
/// iteration of the deck's via loop. Ascending by `(cut, conductor)`, which is
/// what lets [`via_edges_append`] merge two of these instead of searching one.
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

    // The exact test, for `polys_intersect`'s reason: a cut whose bounding box
    // reaches a conductor it does not touch would join two nets that are not
    // one conductor, and a wrongly merged net is fail-open for every rule that
    // exempts a same-net pair. It is also what the containment probe is for
    // here — a cut sits *inside* the conductor it lands on, sharing no edge
    // with it, which is the ordinary case rather than the exotic one.
    retain_intersecting_into(store, pairs, out);

    debug_assert!(
        out.windows(2).all(|w| w[0] < w[1]),
        "the cross-layer prune is ascending and the exact test preserves it"
    );
}

#[cfg(test)]
mod tests {
    use super::{
        rings_meet_direct, rings_meet_sweep, sort_dedup_from, NetId, NetTable,
        DIRECT_PAIR_BUDGET,
    };
    use gpurify_core::PolyId;
    use gpurify_units::Dbu;

    /// Reads the private columns directly, which is why it lives in the module
    /// rather than in `tests/`: `from_assignment` is only useful if the CSR it
    /// builds is right, and every public accessor reads that CSR, so checking
    /// it through them would let a matching pair of errors cancel.
    ///
    /// Oracle: construct-from-answer. The assignment is written down and the
    /// CSR it must produce with it — net 0 taking polygons 1 and 4, net 1
    /// taking 0 and 2, and polygon 3 taking neither because it is on no
    /// conductor.
    #[test]
    fn a_stated_assignment_builds_the_reverse_index_it_implies() {
        let none = NetId::NONE;
        let table =
            NetTable::from_assignment(&[NetId(1), NetId(0), NetId(1), none, NetId(0)]);

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

        // A store holding nothing but markers and cuts has no nets at all,
        // rather than one net holding everything.
        let nothing = NetTable::from_assignment(&[none, none]);
        assert_eq!(nothing.net_start, [0]);
        assert!(nothing.polys.is_empty());

        // The equality that lets a test state an expected partition.
        assert_eq!(
            table,
            NetTable::from_assignment(&[NetId(1), NetId(0), NetId(1), none, NetId(0)])
        );
        assert_ne!(table, nothing);
    }

    /// Oracle: law — `sort_dedup_from(v, base)` must leave `v[..base]` byte for
    /// byte as it was and agree with `sort_unstable` + `dedup` on `v[base..]`,
    /// because it exists only to be those two restricted to a suffix. A via
    /// array is a run of identical rows, so the duplicate-heavy case is the
    /// ordinary one and not the corner.
    ///
    /// In the module because `sort_dedup_from` is private: an appending builder
    /// must not reshuffle the layer before it, and that is invisible through
    /// `via_edges_into`, whose frozen signature clears `out` and so is only ever
    /// called with `base == 0`.
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

    /// A star-shaped ring of `n` vertices centred on `(cx, cy)`, alternating
    /// between two radii so the boundary is deeply notched and edge x-extents
    /// overlap heavily — the case that stresses the sweep's live lists.
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

    /// Oracle: law — the sweep and the exhaustive scan are two computations of
    /// one predicate, so they must agree on every input, and disagreement is the
    /// only way the sweep's pruning can be wrong. Swept across vertex counts
    /// straddling `DIRECT_PAIR_BUDGET` and across offsets that put the two rings
    /// disjoint, deeply interlocked, and nested without their boundaries
    /// meeting — the last being the case `polys_intersect`'s containment probes
    /// exist for, and the one a boundary sweep must answer `false` to.
    #[test]
    fn the_sweep_and_the_exhaustive_scan_agree_on_every_ring_pair() {
        // Both paths are reachable at the sizes swept below: the budget sits
        // between these two products, so `rings_meet` would route the small
        // pair to the direct scan and the large pair to the sweep. Nothing here
        // depends on the run, so it is checked when the test is compiled — if
        // the budget moves past either product this fails to build, which is
        // the point: the sizes below are chosen against the constant.
        const {
            assert!(8 * 8 <= DIRECT_PAIR_BUDGET, "the small pair takes the direct scan");
            assert!(64 * 64 > DIRECT_PAIR_BUDGET, "the large pair takes the sweep");
        }

        let mut saw_meeting = false;
        let mut saw_apart = false;
        for &n in &[3usize, 8, 33, 64, 129] {
            let (ax, ay) = star(n, 0, 0, 400, 1000);
            for &m in &[3usize, 8, 33, 64, 129] {
                for &offset in &[0i64, 300, 900, 1600, 4000] {
                    // A ring far smaller than the other's inner radius, placed
                    // at the centre, is strictly nested: no edge pair meets.
                    let (bx, by) = star(m, offset, 0, 80, 200);
                    let direct = rings_meet_direct(&ax, &ay, &bx, &by);
                    let sweep = rings_meet_sweep(&ax, &ay, &bx, &by);
                    assert_eq!(
                        direct, sweep,
                        "n={n} m={m} offset={offset}: the sweep pruned a pair that meets"
                    );
                    // Swapping the arguments swaps which ring drives the outer
                    // scan and which fills the live list; the predicate is
                    // symmetric and neither path may notice.
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
        assert!(saw_meeting, "a corpus where no pair ever meets proves nothing");
        assert!(saw_apart, "nor one where every pair meets");
    }
}
