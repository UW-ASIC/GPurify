//! Net extraction: which shapes are electrically the same conductor.
//!
//! Two shapes join if they are on the same conductor layer and touch (with
//! `connect touch_within_layer`), or if a via cut on the right layer overlaps
//! both. Every shape on a global layer is one net. Text labels join nothing:
//! two shapes with the same label and no drawn connection are two nets.
//! Data in: `GeometryStore` + `Connectivity`. Data out: `NetTable`.

use crate::topology::csr_run;
use gpurify_geom::connectivity::{components_into, ComponentLabel};
use gpurify_geom::index::{candidate_pairs_into, cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::ops::{segments_intersect, winding_of, Point, Seg, Winding};
use gpurify_geom::view::{validate_layer_with, Angles, ValidatedLayer};
use gpurify_geom::Dbu;
use gpurify_geom::{GeometryStore, LayerId, PolyId};
use gpurify_ingest::deck::Connectivity;

/// One electrical net: a dense rank over `0 .. net_count`, ascending by each
/// net's smallest [`PolyId`], so ids are canonical across runs and threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct NetId(pub u32);

impl NetId {
    /// The polygon is on no net. Never listed by [`NetTable::polys_of`], and
    /// [`NetTable::same_net`] is false for it even against itself.
    pub const NONE: Self = Self(u32::MAX);

    /// The raw index, meaningless on [`NetId::NONE`].
    #[must_use]
    pub const fn idx(self) -> usize {
        self.0 as usize
    }
}

/// Which net each polygon belongs to, in both directions.
///
/// Filled by [`extract_nets_into`]. Nets are `NetId(0) .. NetId(net_count)`,
/// numbered as [`NetId`] says; each net's polygons ascend. Only polygons on a
/// conductor or global layer have a net: a cut, a marker or a label shape is
/// on [`NetId::NONE`]. A polygon's hole, which the store keeps as a row of
/// its own, is on the polygon's net (on a layer that fails validation it is
/// left as drawn). The [`Default`] table has no nets and knows no polygon.
#[derive(Debug, Default)]
pub struct NetTable {
    /// Net of each polygon, indexed by [`PolyId`].
    poly_net: Vec<NetId>,
    /// `polys[net_start[n]..net_start[n + 1]]` is net `n`, ascending.
    net_start: Vec<u32>,
    polys: Vec<PolyId>,
    /// Every join the last extraction made, `(a, b)` polygon rows: touching
    /// shapes on one conductor, the two shapes a cut lands on, a global
    /// layer's shapes, a polygon and its holes. Kept, so a second extraction
    /// reuses the allocation and [`NetTable::path`] can walk them.
    edges: Vec<(u32, u32)>,
    labels: Vec<ComponentLabel>,
    scratch: EdgeScratch,
    /// Hole rows bound to their outers, over every layer of the store.
    pub(crate) holes: Holes,
    /// Per net: every shape is on a global layer (the substrate alone).
    global_only: Vec<bool>,
}

/// A store keeps a polygon's hole as its own clockwise row. This binds each
/// hole row to its outer, so nothing drawn inside a hole touches the ring.
#[derive(Debug, Default)]
pub(crate) struct Holes {
    /// Owning outer of each hole row; `NO_OWNER` for every other row.
    owner: Vec<u32>,
    /// `(outer, hole)`, ascending.
    of: Vec<(PolyId, PolyId)>,
    layer: ValidatedLayer,
}

const NO_OWNER: u32 = u32::MAX;

impl Holes {
    /// Rebind for `layers` of `store`. A layer that fails validation keeps its
    /// rows as drawn: DRC reports the invalid shape.
    pub(crate) fn build(
        &mut self,
        store: &GeometryStore,
        layers: impl IntoIterator<Item = LayerId>,
    ) {
        self.owner.clear();
        self.owner.resize(store.poly_count(), NO_OWNER);
        self.of.clear();
        for layer in layers {
            let clockwise = store.polys_on_layer(layer).any(|row| {
                let (xs, ys) = store.poly_verts(PolyId(row));
                winding_of(xs, ys) == Some(Winding::Clockwise)
            });
            if !clockwise
                || validate_layer_with(store, layer, Angles::Octilinear, &mut self.layer).is_err()
            {
                continue;
            }
            for polygon in 0..u32::try_from(self.layer.len()).expect("a layer's polygons fit a u32")
            {
                let mut rows = self.layer.get(polygon).rows();
                let outer = rows.next().expect("a polygon has an outer ring");
                for hole in rows {
                    self.owner[hole.idx()] = outer.0;
                    self.of.push((outer, hole));
                }
            }
        }
        self.of.sort_unstable();
    }

    pub(crate) fn is_hole(&self, poly: PolyId) -> bool {
        self.owner
            .get(poly.idx())
            .is_some_and(|&owner| owner != NO_OWNER)
    }

    pub(crate) fn of(&self, outer: PolyId) -> impl Iterator<Item = PolyId> + '_ {
        let from = self.of.partition_point(|&(o, _)| o < outer);
        self.of[from..]
            .iter()
            .take_while(move |&&(o, _)| o == outer)
            .map(|&(_, h)| h)
    }
}

impl NetTable {
    /// How many nets there are; [`NetId::NONE`] is not one of them.
    pub fn net_count(&self) -> usize {
        self.net_start.len().saturating_sub(1)
    }

    /// Whether a net holds only global-layer shapes: the substrate with nothing
    /// conducting drawn on it. Panics on a net past the table.
    pub fn is_global_only(&self, net: NetId) -> bool {
        self.global_only[net.idx()]
    }

    /// The net of a polygon, or [`NetId::NONE`]. Panics on a polygon this table never saw.
    pub fn net_of(&self, poly: PolyId) -> NetId {
        self.poly_net[poly.idx()]
    }

    /// The polygons on one net, ascending. Empty for [`NetId::NONE`].
    pub fn polys_of(&self, net: NetId) -> &[PolyId] {
        if net == NetId::NONE {
            return &[];
        }
        let (from, to) = csr_run(&self.net_start, net.idx());
        &self.polys[from..to]
    }

    /// Whether two polygons are the same net. False when either is on no net.
    pub fn same_net(&self, a: PolyId, b: PolyId) -> bool {
        let (a, b) = (self.net_of(a), self.net_of(b));
        a != NetId::NONE && a == b
    }

    /// The fewest polygons that join `from` to `to` through the joins the
    /// extraction made (shapes touching on one conductor, the two shapes a
    /// cut lands on, a global layer's shapes, a polygon and its holes; a cut
    /// itself is no step), `from` first and `to` last, `[from]` when they
    /// are one polygon. Of several such paths, the one a breadth-first walk
    /// from `from` taking each polygon's neighbours lowest first reaches
    /// `to` along, so the answer is the same on every run. `None` when the
    /// two are on different nets or
    /// on none, or the table holds no joins (a [`Default`] one). This is
    /// where a short between two labelled nets runs (catalog LVS-005).
    ///
    /// Breadth first over the net's joins: O(joins) time and O(polygons)
    /// memory per call. A polygon the table never saw has no path.
    pub fn path(&self, from: PolyId, to: PolyId) -> Option<Vec<PolyId>> {
        let (&net, &other) = (self.poly_net.get(from.idx())?, self.poly_net.get(to.idx())?);
        if net == NetId::NONE || net != other {
            return None;
        }
        if from == to {
            return Some(vec![from]);
        }
        let rows = self.poly_net.len();
        // The net's joins as CSR, each list ascending, so the walk is
        // deterministic.
        let on_net = |&&(a, b): &&(u32, u32)| {
            self.poly_net.get(a as usize) == Some(&net)
                && self.poly_net.get(b as usize) == Some(&net)
        };
        // Degrees, then their exclusive prefix sums: `start[row]` is where
        // row's neighbours begin, `start[rows]` how many there are.
        let mut start = vec![0u32; rows + 1];
        for &(a, b) in self.edges.iter().filter(on_net) {
            start[a as usize] += 1;
            start[b as usize] += 1;
        }
        let mut sum = 0u32;
        for slot in &mut start {
            let degree = *slot;
            *slot = sum;
            sum += degree;
        }
        let mut next_free = start.clone();
        let mut neighbour = vec![0u32; sum as usize];
        for &(a, b) in self.edges.iter().filter(on_net) {
            for (at, to) in [(a, b), (b, a)] {
                neighbour[next_free[at as usize] as usize] = to;
                next_free[at as usize] += 1;
            }
        }
        for run in start.windows(2) {
            neighbour[run[0] as usize..run[1] as usize].sort_unstable();
        }
        let mut parent = vec![u32::MAX; rows];
        parent[from.idx()] = from.0;
        let mut queue = std::collections::VecDeque::from([from.0]);
        while let Some(at) = queue.pop_front() {
            if at == to.0 {
                let mut path = vec![to];
                let mut step = at;
                while step != from.0 {
                    step = parent[step as usize];
                    path.push(PolyId(step));
                }
                path.reverse();
                return Some(path);
            }
            for &next in &neighbour[start[at as usize] as usize..start[at as usize + 1] as usize] {
                if parent[next as usize] == u32::MAX {
                    parent[next as usize] = at;
                    queue.push_back(next);
                }
            }
        }
        None
    }
}

/// Rebuild the reverse CSR index from a per-polygon net assignment.
fn rebuild_index(poly_net: &[NetId], net_start: &mut Vec<u32>, polys: &mut Vec<PolyId>) {
    let net_count = poly_net
        .iter()
        .filter(|&&net| net != NetId::NONE)
        .map(|net| net.idx() + 1)
        .max()
        .unwrap_or(0);

    net_start.clear();
    net_start.resize(net_count + 1, 0);
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
}

/// Extract nets from geometry; caller owns `out`, cleared and refilled.
///
/// Only polygons on a [`Connectivity::conductors`] or
/// [`Connectivity::global`] layer get a net. Polygons join when:
///
/// - they are on one conductor layer and share at least one point, touching
///   included, and [`Connectivity::intra_layer_touch`] is set;
/// - a cut on a [`Connectivity::via_cut`] layer shares at least one point with
///   both, one on each of the two layers that cut connects. The cut itself
///   belongs to no net;
/// - they are on one global layer, however far apart.
///
/// Bounding boxes only prune candidates; every join is an exact geometric
/// test. Labels are not read here: see [`bind_ports_into`](crate::topology::bind_ports_into).
///
/// # Panics
///
/// Panics if a layer `connectivity` names is not in the store's layer table,
/// or if the store holds `u32::MAX` or more polygons.
pub fn extract_nets_into(store: &GeometryStore, connectivity: &Connectivity, out: &mut NetTable) {
    let rows = store.poly_count();
    let node_count = u32::try_from(rows).expect("a polygon index fits a PolyId");

    out.holes.build(
        store,
        (0..store.layer_count()).map(|l| LayerId(u16::try_from(l).expect("a layer id fits a u16"))),
    );
    out.edges.clear();
    if connectivity.intra_layer_touch {
        for &layer in &connectivity.conductors {
            intra_layer_edges_append(store, &out.holes, layer, &mut out.scratch, &mut out.edges);
        }
    }
    for (&cut, &connects) in connectivity.via_cut.iter().zip(&connectivity.via_connects) {
        via_edges_append(
            store,
            &out.holes,
            cut,
            connects,
            &mut out.scratch,
            &mut out.edges,
        );
    }
    // A global layer is one net: chain its shapes, holes included, together.
    for &layer in &connectivity.global {
        let rows = store.polys_on_layer(layer);
        out.edges
            .extend(rows.clone().skip(1).map(|row| (rows.start, row)));
    }
    // A conductor the store's layer table lacks panics rather than being skipped.
    let mut conducts = vec![false; store.layer_count()];
    for &layer in connectivity.conductors.iter().chain(&connectivity.global) {
        conducts[layer.idx()] = true;
    }

    // A hole row is part of its outer's polygon, so it shares the outer's net.
    for &(outer, hole) in &out.holes.of {
        if conducts[store.poly_layer(outer).idx()] {
            out.edges.push((outer.0.min(hole.0), outer.0.max(hole.0)));
        }
    }

    components_into(node_count, &out.edges, &mut out.labels);

    // Labels to dense net ids. A label is its component's minimum polygon index,
    // so walking ascending makes the numbering canonical.
    out.poly_net.clear();
    out.poly_net.reserve(rows);
    let mut rank = vec![u32::MAX; rows];
    let mut next = 0u32;
    for row in 0..node_count {
        let poly = PolyId(row);
        if !conducts[store.poly_layer(poly).idx()] {
            out.poly_net.push(NetId::NONE);
            continue;
        }
        let slot = &mut rank[out.labels[poly.idx()].0 as usize];
        if *slot == u32::MAX {
            *slot = next;
            next += 1;
        }
        out.poly_net.push(NetId(*slot));
    }

    rebuild_index(&out.poly_net, &mut out.net_start, &mut out.polys);
    // Inside the assertion, so cargo-mutants does not count the check as code:
    // every polygon with a net is listed once, under that net.
    debug_assert!(
        {
            let mut listed = 0usize;
            let mut least = None;
            let nets_hold = (0..out.net_count()).all(|n| {
                let net = NetId(u32::try_from(n).expect("a net id is a u32"));
                let polys = out.polys_of(net);
                listed += polys.len();
                let first = polys.first().copied();
                let holds = first > least
                    && polys.windows(2).all(|w| w[0] < w[1])
                    && polys.iter().all(|&p| out.net_of(p) == net);
                least = first;
                holds
            });
            nets_hold && listed == out.poly_net.iter().filter(|&&n| n != NetId::NONE).count()
        },
        "the nets partition the conductor shapes: each shape on exactly one net, \
         each net's shapes ascending, nets numbered by their least shape"
    );
    out.global_only.clear();
    out.global_only.resize(next as usize, true);
    for (row, &net) in (0u32..).zip(&out.poly_net) {
        if net != NetId::NONE && !connectivity.global.contains(&store.poly_layer(PolyId(row))) {
            out.global_only[net.idx()] = false;
        }
    }
}

/// Whether two of the store's polygons share at least one point, holes
/// excluded. The exact re-test behind every bounding-box prune: merging on a
/// box alone is fail-open. A hole row is never a polygon of its own here.
pub(crate) fn polys_intersect(store: &GeometryStore, holes: &Holes, a: PolyId, b: PolyId) -> bool {
    if holes.is_hole(a) || holes.is_hole(b) {
        return false;
    }
    let (ax, ay) = store.poly_verts(a);
    let (bx, by) = store.poly_verts(b);
    if ax.is_empty() || bx.is_empty() {
        return false;
    }
    // A hole's edge is the polygon's boundary too.
    let meet = std::iter::once(a).chain(holes.of(a)).any(|ra| {
        let (rax, ray) = store.poly_verts(ra);
        std::iter::once(b).chain(holes.of(b)).any(|rb| {
            let (rbx, rby) = store.poly_verts(rb);
            rings_meet(rax, ray, rbx, rby)
        })
    });
    // Boundaries that do not meet are nested or disjoint, so one vertex decides;
    // it is off every boundary, so inclusive containment is strict here.
    meet || in_material(store, holes, b, Point { x: ax[0], y: ay[0] })
        || in_material(store, holes, a, Point { x: bx[0], y: by[0] })
}

/// Inside the outer ring and inside none of its holes.
pub(crate) fn in_material(store: &GeometryStore, holes: &Holes, outer: PolyId, p: Point) -> bool {
    store.poly_contains_point(outer, p) && !holes.of(outer).any(|h| store.poly_contains_point(h, p))
}

/// The pairs of `pairs` whose polygons really intersect, in input order.
pub(crate) fn retain_intersecting_into(
    store: &GeometryStore,
    holes: &Holes,
    pairs: &[(PolyId, PolyId)],
    out: &mut Vec<(PolyId, PolyId)>,
) {
    out.clear();
    out.extend(
        pairs
            .iter()
            .copied()
            .filter(|&(a, b)| polys_intersect(store, holes, a, b)),
    );
}

/// The closed segment from vertex `i` of a ring to the next one, wrapping.
#[inline]
fn ring_edge(xs: &[Dbu], ys: &[Dbu], i: usize) -> Seg {
    let next = if i + 1 == xs.len() { 0 } else { i + 1 };
    Seg {
        a: Point { x: xs[i], y: ys[i] },
        b: Point {
            x: xs[next],
            y: ys[next],
        },
    }
}

/// Edge pairs the direct scan may examine before the sweep pays for itself
/// (a rounded tuning constant, not measured).
const DIRECT_PAIR_BUDGET: usize = 1 << 10;

/// Whether any edge of one ring meets any edge of the other, touching included.
fn rings_meet(ax: &[Dbu], ay: &[Dbu], bx: &[Dbu], by: &[Dbu]) -> bool {
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

/// The x-extent `(lo, hi)` of every edge of a ring, in edge order.
fn edge_xspans(xs: &[Dbu]) -> Vec<(Dbu, Dbu)> {
    let n = xs.len();
    (0..n)
        .map(|i| {
            let (a, b) = (xs[i], xs[if i + 1 == n { 0 } else { i + 1 }]);
            (a.min(b), a.max(b))
        })
        .collect()
}

/// [`rings_meet`] by plane sweep over edges ascending by left x. An entering
/// edge is tested against the opposite ring's live edges, then joins its own.
fn rings_meet_sweep(ax: &[Dbu], ay: &[Dbu], bx: &[Dbu], by: &[Dbu]) -> bool {
    let (n, m) = (ax.len(), bx.len());
    let (span_a, span_b) = (edge_xspans(ax), edge_xspans(bx));

    let edges_a = u32::try_from(n).expect("a ring has fewer than u32::MAX vertices");
    let edges_b = u32::try_from(m).expect("a ring has fewer than u32::MAX vertices");
    let mut order_a: Vec<u32> = (0..edges_a).collect();
    let mut order_b: Vec<u32> = (0..edges_b).collect();
    order_a.sort_unstable_by_key(|&i| span_a[i as usize]);
    order_b.sort_unstable_by_key(|&i| span_b[i as usize]);

    let (mut live_a, mut live_b) = (Vec::new(), Vec::new());
    let (mut ia, mut ib) = (0usize, 0usize);
    while ia < n || ib < m {
        // `i64::MAX` is outside `MAX_ABS_DBU`, so a spent side never wins.
        let key_a = order_a
            .get(ia)
            .map_or(i64::MAX, |&i| span_a[i as usize].0.raw());
        let key_b = order_b
            .get(ib)
            .map_or(i64::MAX, |&i| span_b[i as usize].0.raw());
        let sweep_x = key_a.min(key_b);

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
    }
    false
}

/// Whether `edge` meets any of a ring's live edges.
fn meets_any(edge: Seg, xs: &[Dbu], ys: &[Dbu], live: &[u32]) -> bool {
    live.iter()
        .any(|&i| segments_intersect(edge, ring_edge(xs, ys, i as usize)))
}

/// The edge builders' working storage, dead between calls.
#[derive(Debug, Default)]
struct EdgeScratch {
    index: SpatialIndex,
    cut_index: SpatialIndex,
    pairs: Vec<(PolyId, PolyId)>,
    touching: Vec<(PolyId, PolyId)>,
    on_lower: Vec<(PolyId, PolyId)>,
    on_upper: Vec<(PolyId, PolyId)>,
}

/// Edges `a < b` from shapes touching on one conductor layer.
pub fn intra_layer_edges_into(store: &GeometryStore, layer: LayerId, out: &mut Vec<(u32, u32)>) {
    out.clear();
    let mut holes = Holes::default();
    holes.build(store, [layer]);
    intra_layer_edges_append(store, &holes, layer, &mut EdgeScratch::default(), out);
}

fn intra_layer_edges_append(
    store: &GeometryStore,
    holes: &Holes,
    layer: LayerId,
    scratch: &mut EdgeScratch,
    out: &mut Vec<(u32, u32)>,
) {
    SpatialIndex::build_into(store, layer, &mut scratch.index);
    // Distance zero counts touching: shapes sharing only an edge are one conductor.
    candidate_pairs_into(
        store,
        &scratch.index,
        Dbu::new_unchecked(0),
        &mut scratch.pairs,
    );
    retain_intersecting_into(store, holes, &scratch.pairs, &mut scratch.touching);
    out.extend(scratch.touching.iter().map(|&(a, b)| (a.0, b.0)));
}

/// Edges `(lower, upper)` from a via cut overlapping shapes on both layers it
/// joins, ascending and deduplicated. A cut over only one layer is no edge.
pub fn via_edges_into(
    store: &GeometryStore,
    cut: LayerId,
    connects: (LayerId, LayerId),
    out: &mut Vec<(u32, u32)>,
) {
    out.clear();
    let mut holes = Holes::default();
    holes.build(store, [cut, connects.0, connects.1]);
    via_edges_append(
        store,
        &holes,
        cut,
        connects,
        &mut EdgeScratch::default(),
        out,
    );
}

/// Every `(cut, lower, upper)` a via cut joins, one row per cut and pair,
/// ascending by cut. Unlike [`via_edges_into`], a stack of cuts is not merged.
pub fn via_cuts_into(
    store: &GeometryStore,
    cut: LayerId,
    connects: (LayerId, LayerId),
    out: &mut Vec<(u32, u32, u32)>,
) {
    out.clear();
    let mut holes = Holes::default();
    holes.build(store, [cut, connects.0, connects.1]);
    via_landings(
        store,
        &holes,
        cut,
        connects,
        &mut EdgeScratch::default(),
        |c, low, high| out.push((c.0, low.0, high.0)),
    );
}

/// Sorts and dedups only the rows it appends; earlier layers' rows stay put.
fn via_edges_append(
    store: &GeometryStore,
    holes: &Holes,
    cut: LayerId,
    connects: (LayerId, LayerId),
    scratch: &mut EdgeScratch,
    out: &mut Vec<(u32, u32)>,
) {
    let base = out.len();
    via_landings(store, holes, cut, connects, scratch, |_, low, high| {
        out.push((low.0, high.0));
    });

    // A stack of cuts over one pair of shapes is one edge.
    let mut tail = out.split_off(base);
    tail.sort_unstable();
    tail.dedup();
    out.append(&mut tail);
}

/// Call `emit(cut, lower, upper)` for every pair of conductors a cut lands on,
/// ascending by cut.
fn via_landings(
    store: &GeometryStore,
    holes: &Holes,
    cut: LayerId,
    (lower, upper): (LayerId, LayerId),
    scratch: &mut EdgeScratch,
    mut emit: impl FnMut(PolyId, PolyId, PolyId),
) {
    SpatialIndex::build_into(store, cut, &mut scratch.cut_index);
    if scratch.cut_index.is_empty() {
        return;
    }

    let EdgeScratch {
        cut_index,
        index,
        pairs,
        on_lower,
        on_upper,
        ..
    } = scratch;
    cuts_landing_on(store, holes, cut_index, lower, index, pairs, on_lower);
    cuts_landing_on(store, holes, cut_index, upper, index, pairs, on_upper);

    // Both lists ascend by `(cut, conductor)`: merge on the cut column.
    let (mut lo, mut hi) = (0usize, 0usize);
    while lo < on_lower.len() && hi < on_upper.len() {
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
                emit(a, low_poly, high_poly);
            }
        }
        lo = lo_end;
        hi = hi_end;
    }
}

/// Every `(cut, conductor)` pair where the cut really lands, ascending.
fn cuts_landing_on(
    store: &GeometryStore,
    holes: &Holes,
    cut_index: &SpatialIndex,
    layer: LayerId,
    index: &mut SpatialIndex,
    pairs: &mut Vec<(PolyId, PolyId)>,
    out: &mut Vec<(PolyId, PolyId)>,
) {
    SpatialIndex::build_into(store, layer, index);
    cross_layer_pairs_into(store, cut_index, index, Dbu::new_unchecked(0), pairs);
    retain_intersecting_into(store, holes, pairs, out);
}

#[cfg(test)]
mod tests {
    use super::{rebuild_index, rings_meet_direct, rings_meet_sweep, NetId, DIRECT_PAIR_BUDGET};
    use gpurify_geom::Dbu;
    use gpurify_geom::PolyId;

    /// Oracle: construct-from-answer. Polygons 1 and 4 are on net 0 and 0 and
    /// 2 on net 1, so the index is two nets of two, each ascending; markers
    /// alone give no net.
    #[test]
    fn a_stated_assignment_builds_the_reverse_index_it_implies() {
        let none = NetId::NONE;
        let (mut net_start, mut polys) = (Vec::new(), Vec::new());
        rebuild_index(
            &[NetId(1), NetId(0), NetId(1), none, NetId(0)],
            &mut net_start,
            &mut polys,
        );
        assert_eq!(net_start, [0, 2, 4], "two nets of two polygons each");
        assert_eq!(
            polys,
            [PolyId(1), PolyId(4), PolyId(0), PolyId(2)],
            "each net's polygons must come back ascending"
        );

        // A store holding nothing but markers and cuts has no nets at all.
        rebuild_index(&[none, none], &mut net_start, &mut polys);
        assert_eq!(net_start, [0]);
        assert!(polys.is_empty());
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
    ///
    /// Oracle: differential against `rings_meet_direct`, the exhaustive scan,
    /// on star pairs either side of the pair budget, meeting and apart; and the
    /// law that meeting is symmetric.
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
