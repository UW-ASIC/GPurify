//! Net extraction: which shapes are electrically the same conductor.
//!
//! Two shapes join if they are on the same conductor layer and touch, or if a
//! via cut on the right layer overlaps both.
//! Data in: `GeometryStore` + `Connectivity`. Data out: `NetTable`.

use crate::topology::csr_run;
use gpurify_geom::connectivity::{components_into, ComponentLabel};
use gpurify_geom::index::{candidate_pairs_into, cross_layer_pairs_into, SpatialIndex};
use gpurify_geom::ops::{segments_intersect, winding_of, Point, Seg, Winding};
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
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
    /// Hole rows bound to their outers, over every layer of the store.
    pub(crate) holes: Holes,
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
            if !clockwise || validate_layer_into(store, layer, &mut self.layer).is_err() {
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

    fn is_hole(&self, poly: PolyId) -> bool {
        self.owner
            .get(poly.idx())
            .is_some_and(|&owner| owner != NO_OWNER)
    }

    fn of(&self, outer: PolyId) -> impl Iterator<Item = PolyId> + '_ {
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
/// Only polygons on a [`Connectivity::conductors`] layer get a net. A cut joins
/// the two conductors it overlaps but does not belong to that net.
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
    // A hole row is part of its outer's polygon, so it shares the outer's net.
    for &layer in &connectivity.conductors {
        for (outer, hole) in out.holes.of.iter().copied() {
            if store.poly_layer(outer) == layer {
                out.edges.push((outer.0.min(hole.0), outer.0.max(hole.0)));
            }
        }
    }

    components_into(node_count, &out.edges, &mut out.labels);

    // A conductor the store's layer table lacks panics rather than being skipped.
    let mut conducts = vec![false; store.layer_count()];
    for &layer in &connectivity.conductors {
        conducts[layer.idx()] = true;
    }

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
}

/// Whether two of the store's polygons share at least one point, holes
/// excluded. The exact re-test behind every bounding-box prune: merging on a
/// box alone is fail-open. A hole row is never a polygon of its own here.
fn polys_intersect(store: &GeometryStore, holes: &Holes, a: PolyId, b: PolyId) -> bool {
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
fn in_material(store: &GeometryStore, holes: &Holes, outer: PolyId, p: Point) -> bool {
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

/// Sorts and dedups only the rows it appends; earlier layers' rows stay put.
fn via_edges_append(
    store: &GeometryStore,
    holes: &Holes,
    cut: LayerId,
    (lower, upper): (LayerId, LayerId),
    scratch: &mut EdgeScratch,
    out: &mut Vec<(u32, u32)>,
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
    let base = out.len();
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
                out.push((low_poly.0, high_poly.0));
            }
        }
        lo = lo_end;
        hi = hi_end;
    }

    // A stack of cuts over one pair of shapes is one edge.
    let mut tail = out.split_off(base);
    tail.sort_unstable();
    tail.dedup();
    out.append(&mut tail);
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
