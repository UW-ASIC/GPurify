//! Width family: how narrow a single shape, or one feature of it, may be.
//!
//! All four rules measure *within* one polygon. None needs the spatial index,
//! none looks at a second shape, and all four fall out of the same scan over a
//! validated polygon's edges — the set of *facing* parallel edge pairs, meaning
//! two edges that are antiparallel and whose projections onto their shared axis
//! overlap. That scan is the whole family:
//!
//! - the gap between a facing pair whose interior is **inside** the polygon is
//!   a width, and [`check_min_width`] wants its minimum;
//! - the gap between a facing pair whose interior is **outside** the polygon is
//!   a notch, and [`check_notch`] wants its minimum;
//! - the same minimum width, compared the other way, is [`check_max_width`],
//!   which is a slotting trigger rather than a defect;
//! - and one edge's own length is [`check_min_edge_length`].
//!
//! The old tree measured width as `min(bbox.width, bbox.height)` with a note
//! that this is exact "for the conformance rectangles". It is not exact for an
//! L, a T or a comb, and every one of those is a real metal shape. The facing-
//! pair scan is exact for any rectilinear polygon, which is the whole input
//! domain, so there is no approximate path here at all.

use super::{COLUMNS_DIVERGED, mid, ring_segs};
use crate::{record_run, Design, Scratch};
use gpurify_core::ops::{winding_of, Point, Winding};
use gpurify_core::view::validate_layer_into;
use gpurify_core::{GeometryStore, LayerId, PolyId, PolygonRef, RingRef};
use gpurify_ingest::StrId;
use gpurify_report::{Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use gpurify_units::Dbu;

/// Minimum width: no part of a shape may be narrower than the limit.
#[derive(Debug, Default)]
pub struct MinWidthTable {
    /// The deck's id for the rule, interned. What a human greps a report for.
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// Violated *below*. Strictly positive; a zero limit is rejected at
    /// construction because it passes every shape while looking configured.
    pub limit: Vec<Dbu>,
}

/// Maximum width: a shape wider than the limit must be slotted.
///
/// The other sense of the same measurement. It is a separate table rather than
/// a `sense` column on [`MinWidthTable`] because a `sense` column is a branch
/// inside the loop, and because the old tree's `min_spacing` and `max_width`
/// shared a comparison that was correct for exactly one of them.
#[derive(Debug, Default)]
pub struct MaxWidthTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// Violated *above*.
    pub limit: Vec<Dbu>,
}

/// Minimum edge length: no single boundary edge shorter than the limit.
///
/// A jog too short to print, independent of how wide the shape is either side
/// of it.
#[derive(Debug, Default)]
pub struct MinEdgeLengthTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    pub limit: Vec<Dbu>,
}

/// Notch: two edges of the *same* polygon facing each other across a gap that
/// is outside the shape.
///
/// Distinct from spacing, which is the gap between two different polygons, and
/// distinct from width, which is the gap between two edges across material.
/// Same scan, opposite side.
#[derive(Debug, Default)]
pub struct NotchTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    pub limit: Vec<Dbu>,
}

impl MinWidthTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.rule.len(), self.layer.len(), "{COLUMNS_DIVERGED}");
        debug_assert_eq!(self.rule.len(), self.limit.len(), "{COLUMNS_DIVERGED}");
        self.rule.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl MaxWidthTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.rule.len(), self.layer.len(), "{COLUMNS_DIVERGED}");
        debug_assert_eq!(self.rule.len(), self.limit.len(), "{COLUMNS_DIVERGED}");
        self.rule.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl MinEdgeLengthTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.rule.len(), self.layer.len(), "{COLUMNS_DIVERGED}");
        debug_assert_eq!(self.rule.len(), self.limit.len(), "{COLUMNS_DIVERGED}");
        self.rule.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl NotchTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.rule.len(), self.layer.len(), "{COLUMNS_DIVERGED}");
        debug_assert_eq!(self.rule.len(), self.limit.len(), "{COLUMNS_DIVERGED}");
        self.rule.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One boundary edge, reduced to the four facts a facing-pair test reads.
///
/// Materialised into [`FacingScratch::edges`] once per polygon. The sweep below
/// visits the same edge from two event coordinates and from an arbitrary number
/// of adjacency checks, so recomputing it from the coordinate columns each time
/// would put the ring walk back inside the inner loop — which is most of what
/// the pair scan used to cost.
#[derive(Debug, Clone, Copy)]
struct Edge {
    /// Coordinate on the axis the edge is *perpendicular* to: `x` for a
    /// vertical edge, `y` for a horizontal one.
    pos: Dbu,
    /// The edge's own extent on the other axis, ascending.
    lo: Dbu,
    hi: Dbu,
    /// The polygon's material lies on the greater-`pos` side of this edge.
    ///
    /// Canonical winding — counter-clockwise outer, clockwise hole — puts
    /// material on the *left* of travel for every ring of a validated polygon,
    /// hole included, so this is the direction of travel and nothing else.
    material_above: bool,
    /// Vertical edges pair only with vertical, horizontal only with
    /// horizontal: two rectilinear edges cannot be antiparallel across axes.
    vertical: bool,
}

/// Reduce one edge to its facing-pair facts.
///
/// **Decision** — two points in, one edge out, pure.
fn edge_of((a, b): (Point, Point)) -> Edge {
    let vertical = a.x == b.x;
    debug_assert!(
        vertical || a.y == b.y,
        "a validated polygon is rectilinear, so every edge is axis-aligned"
    );
    // Branchless: both arms are the same four assignments over swapped axes,
    // and the compiler folds them to a pair of `cmov` rather than a jump.
    let (pos, from, to) = if vertical { (a.x, a.y, b.y) } else { (a.y, a.x, b.x) };
    Edge {
        pos,
        lo: from.min(to),
        hi: from.max(to),
        // Travelling +y leaves material at -x; travelling +x leaves it at +y.
        // One expression covers both because `vertical` already picked the axis.
        material_above: (to > from) != vertical,
        vertical,
    }
}

/// Every ring of one polygon, outer boundary first.
fn poly_rings(poly: PolygonRef<'_>) -> impl Iterator<Item = RingRef<'_>> {
    std::iter::once(poly.outer()).chain(poly.holes())
}

/// One ring's edges as vertex pairs, the closing edge last.
///
/// The walk itself is [`ring_segs`], which every other family in this crate
/// already goes through; this only renames its [`Seg`] to the vertex pair the
/// facing scan reads.
///
/// [`Seg`]: gpurify_core::ops::Seg
fn ring_edges(ring: RingRef<'_>) -> impl Iterator<Item = (Point, Point)> + '_ {
    let (xs, ys) = ring.coords();
    debug_assert!(xs.len() >= 3, "a validated ring has at least three vertices");
    ring_segs(xs, ys).map(|s| (s.a, s.b))
}

/// Every boundary edge of one polygon, holes included.
fn poly_edges(poly: PolygonRef<'_>) -> impl Iterator<Item = (Point, Point)> + '_ {
    poly_rings(poly).flat_map(ring_edges)
}

/// Every boundary edge as an [`Edge`], with the zero-length ones dropped.
///
/// A validated ring has no zero-length edge, so the filter drops nothing on
/// real input — it is here because an edge of no extent has no direction, and
/// so no material side, and would make [`facing`] answer a question it was not
/// asked. [`sweep_axis`] leans on the same guarantee from the other end: an
/// edge whose `lo` equals its `hi` would leave the active list at the
/// coordinate it entered, and never be adjacent to anything.
fn edges(poly: PolygonRef<'_>) -> impl Iterator<Item = Edge> + '_ {
    poly_edges(poly).map(edge_of).filter(|e| e.lo < e.hi)
}

/// The gap between two edges that face each other, and the midpoint of it.
///
/// **Decision** — two edges and which side the material is on, one distance and
/// one report coordinate out, pure and table-testable.
///
/// `None` when they are not a facing pair at all: different axes, the same
/// direction of travel, projections that share no positive-length overlap, or
/// material on the side the caller did not ask for. `material_between` is what
/// separates a width from a notch, and it is the *only* thing that does.
fn facing(a: Edge, b: Edge, material_between: bool) -> Option<(Dbu, Point)> {
    if a.vertical != b.vertical {
        return None;
    }
    // Order by position, so the test below reads as "the near edge's material
    // points at the far edge, and the far edge's points back".
    let (near, far) = if a.pos <= b.pos { (a, b) } else { (b, a) };
    if near.material_above != material_between || far.material_above == material_between {
        return None;
    }
    let lo = near.lo.max(far.lo);
    let hi = near.hi.min(far.hi);
    if hi <= lo {
        return None;
    }
    let across = mid(near.pos, far.pos);
    let along = mid(lo, hi);
    let at = if a.vertical {
        Point { x: across, y: along }
    } else {
        Point { x: along, y: across }
    };
    Some((far.pos - near.pos, at))
}

/// Reusable buffers for one facing-pair sweep.
///
/// **Five questions.** In: one polygon's edges. Out: three columns cleared and
/// refilled per polygon — the edges themselves, the sweep's event stream, and
/// the active list. How many: one buffer set per polygon *loop*, not per
/// polygon; [`check_facing`] hoists one above its loop and every polygon on
/// every layer of every rule row reuses it. Lifetime: phase. Parallelisable:
/// one set per worker, since polygons are independent.
#[derive(Debug, Default)]
struct FacingScratch {
    /// The polygon's edges, both axes, in ring order. Indices into this column
    /// are what the other two carry.
    edges: Vec<Edge>,
    /// `(coordinate, kind, edge)`, ascending. `kind` orders [`LEAVE`] before
    /// [`ENTER`] at one coordinate, so an edge that ends where the next begins
    /// is never active alongside it — half-open `[lo, hi)` spans, which is what
    /// makes "adjacent in the active list" mean "adjacent over a *positive*
    /// stretch of the scanline".
    events: Vec<(Dbu, u8, u32)>,
    /// Indices into `edges` of the edges the scanline currently crosses, sorted
    /// by `(pos, index)` — the same order [`facing`] calls near-then-far.
    active: Vec<u32>,
}

/// An edge stops being active at its `hi`. Ordered before [`ENTER`].
const LEAVE: u8 = 0;
/// An edge becomes active at its `lo`.
const ENTER: u8 = 1;

/// Where an edge sits, or would sit, in the active list.
fn slot_of(edges: &[Edge], active: &[u32], edge: u32) -> usize {
    let want = (edges[edge as usize].pos, edge);
    active.partition_point(|&j| (edges[j as usize].pos, j) < want)
}

/// Fold the active list's pair `(right - 1, right)` into the running best.
///
/// Out-of-range is not an error and not a missing pair: the ends of the active
/// list have no outward neighbour, and a sweep that checks around every event
/// asks for one anyway.
fn consider(
    edges: &[Edge],
    active: &[u32],
    right: usize,
    material_between: bool,
    best: &mut Option<(Dbu, Point)>,
) {
    // Loop-shape guard, not a data-dependent branch: `right` comes from the
    // active list's length and the event's slot, never from a coordinate.
    if right == 0 || right >= active.len() {
        return;
    }
    let near = edges[active[right - 1] as usize];
    let far = edges[active[right] as usize];
    // Both `if`s guard the cheap side of an early reject: `facing` refuses most
    // adjacent pairs — they are the two sides of one wire, or a pair across the
    // wrong side — and refusing them without writing `best` is what a branch is
    // for.
    if let Some(found) = facing(near, far, material_between) {
        if best.is_none_or(|(gap, _)| found.0 < gap) {
            *best = Some(found);
        }
    }
}

/// The narrowest facing pair among the edges of one axis, by scanline sweep.
///
/// **Transform, reducer** — an edge column in, one pair out.
///
/// The sweep runs along the axis the edges *span*, so at any scanline the
/// active list is every edge of this axis the line crosses, ordered by
/// position. Only **adjacent** entries can be the narrowest pair: if an edge
/// `w` lies between an accepted pair, then whichever side of the material test
/// `w` answers, it forms an accepted pair with one of the two and a smaller
/// gap. So checking the pairs disturbed at each event coordinate is enough, and
/// that is `O(E log E)` against the `O(E²)` of testing every pair.
///
/// Completeness is the only thing that argument has to carry. It cannot
/// manufacture a violation: [`facing`] re-derives axis, direction and span
/// overlap for every candidate from the two edges alone, so a pair this sweep
/// offers on a bookkeeping mistake is still rejected unless it genuinely faces.
fn sweep_axis(
    edges: &[Edge],
    vertical: bool,
    material_between: bool,
    events: &mut Vec<(Dbu, u8, u32)>,
    active: &mut Vec<u32>,
) -> Option<(Dbu, Point)> {
    events.clear();
    active.clear();
    events.extend(
        edges
            .iter()
            .enumerate()
            .filter(|(_, e)| e.vertical == vertical)
            .flat_map(|(i, e)| {
                let i = u32::try_from(i).expect("a polygon's edges are indexed by a u32");
                [(e.lo, ENTER, i), (e.hi, LEAVE, i)]
            }),
    );
    events.sort_unstable();
    debug_assert!(
        events.len().is_multiple_of(2),
        "every edge contributes one enter and one leave"
    );

    let mut best: Option<(Dbu, Point)> = None;
    let mut ev = 0;
    // The active list is state threaded from one event to the next: a chain
    // dependency, the one class vectorisation cannot cross.
    while ev < events.len() {
        let at = events[ev].0;
        let group = ev;
        while ev < events.len() && events[ev].0 == at {
            let (_, kind, edge) = events[ev];
            let slot = slot_of(edges, active, edge);
            // Surviving `if`: the two arms are different memory moves, not two
            // values, so there is nothing to blend. It predicts at the ratio of
            // enters to leaves, which is one to one over a whole polygon and
            // long runs of each in ring order.
            if kind == ENTER {
                active.insert(slot, edge);
            } else {
                debug_assert_eq!(
                    active.get(slot).copied(),
                    Some(edge),
                    "an edge leaves the active list from the slot it entered"
                );
                active.remove(slot);
            }
            ev += 1;
        }
        // Every adjacency created at `at` holds until the next event
        // coordinate, which is strictly greater, so the pairs checked here
        // overlap over a positive stretch of the scanline.
        for &(_, _, edge) in &events[group..ev] {
            let slot = slot_of(edges, active, edge);
            consider(edges, active, slot, material_between, &mut best);
            consider(edges, active, slot + 1, material_between, &mut best);
        }
    }
    debug_assert!(active.is_empty(), "every edge that entered the sweep left it");

    best
}

/// The narrowest facing pair of one polygon, and where to report it.
///
/// **Decision.** `material_between` picks the side: `true` is a width, `false`
/// is a notch. One scan serves both, which is the whole reason the four rules
/// of this file are one file.
///
/// Two sweeps, because a vertical edge can only face a vertical one: the
/// vertical edges sweep along `y`, the horizontal along `x`.
///
/// **Which of several equally narrow places gets reported is arbitrary, and
/// this names the first the vertical sweep reached.** An L is as narrow in both
/// arms and a comb in every tooth, so the tie is the common case rather than
/// the corner — and the *measurement* is the same number whichever place is
/// named, which is what the limit is compared against. Arbitrary is not
/// unstable: the choice is a function of the coordinates alone, so two runs
/// over one layout name the same place.
fn narrowest_facing(
    poly: PolygonRef<'_>,
    material_between: bool,
    scratch: &mut FacingScratch,
) -> Option<(Dbu, Point)> {
    let FacingScratch {
        edges: edge_col,
        events,
        active,
    } = scratch;
    edge_col.clear();
    edge_col.extend(edges(poly));
    debug_assert!(
        edge_col.len() >= 4,
        "a simple rectilinear ring with an interior has at least four edges"
    );

    let across = sweep_axis(edge_col, true, material_between, events, active);
    let along = sweep_axis(edge_col, false, material_between, events, active);
    // Two candidates is not bulk data, and `min_by_key` keeps the first of a
    // tie, which is what fixes the axis order above.
    let best = [across, along].into_iter().flatten().min_by_key(|&(gap, _)| gap);

    debug_assert!(
        best.is_none_or(|(gap, _)| gap.raw() >= 0),
        "a facing pair is ordered by position, so its gap cannot be negative"
    );
    best
}

/// The narrowest width of one polygon, and where to report it.
///
/// Always present. Take any horizontal line through the interior that misses
/// every vertex: the material interval containing that point is bounded on the
/// left by an edge whose material is to its right and on the right by an edge
/// whose material is to its left, and both spans strictly contain the line — so
/// a facing pair across material exists for every validated polygon.
fn narrowest_width_at(poly: PolygonRef<'_>, scratch: &mut FacingScratch) -> (Dbu, Point) {
    narrowest_facing(poly, true, scratch)
        .expect("every validated polygon has a facing pair across its own material")
}

/// The store row each validated polygon of one layer came from, in
/// [`ValidatedLayer::get`](gpurify_core::ValidatedLayer::get) order.
///
/// [`ValidatedLayer`](gpurify_core::ValidatedLayer) keeps its `ring_poly`
/// provenance column private and exposes no accessor, so a rule that must name
/// the shape it flagged has no route to a [`PolyId`]. Rather than touch a
/// frozen signature, this replays the filter validation itself used: one
/// polygon is emitted per counter-clockwise row of the layer, in ascending row
/// order, so walking the layer's rows in the same order recovers the mapping
/// exactly.
///
/// The replay costs one pass over the layer's coordinates per rule row, and
/// [`ring_winding`] is what makes that pass cheap — two integer compares per
/// edge rather than the widening multiply a general shoelace cannot avoid.
/// Removing the pass outright is not a body: the mapping it recovers is
/// `ValidatedLayer::ring_poly`, a field of a frozen type with no reader, so the
/// fix is one accessor. Recorded in `docs/SIGNATURE_DEFECTS.md`.
struct OuterRows<'a> {
    store: &'a GeometryStore,
    next: u32,
    end: u32,
}

impl<'a> OuterRows<'a> {
    fn new(store: &'a GeometryStore, layer: LayerId) -> Self {
        let rows = store.polys_on_layer(layer);
        debug_assert!(rows.start <= rows.end, "a layer's row range runs forwards");
        Self {
            store,
            next: rows.start,
            end: rows.end,
        }
    }
}

impl Iterator for OuterRows<'_> {
    type Item = PolyId;

    fn next(&mut self) -> Option<PolyId> {
        while self.next < self.end {
            let poly = PolyId(self.next);
            self.next += 1;
            let (xs, ys) = self.store.poly_verts(poly);
            // The branch is the whole point of the iterator, and it predicts at
            // the layer's hole fraction, which is near zero on real geometry.
            if ring_winding(xs, ys) == Winding::CounterClockwise {
                return Some(poly);
            }
        }
        None
    }
}

/// Which way one already-validated rectilinear ring winds.
///
/// **Decision** — one ring's coordinate columns in, one winding out, pure and
/// table-testable.
///
/// [`winding_of`] answers the same question for a ring of any shape, and pays a
/// widening `i128` multiply per vertex to do it. Every ring [`OuterRows`] reads
/// has already been through
/// [`validate_layer_into`](gpurify_core::view::validate_layer_into), which
/// refuses non-simple, non-rectilinear and zero-area input, and on that domain
/// the answer is written on the bottom edge: the interior lies above every
/// horizontal edge at the ring's minimum `y`, so such an edge travels `+x`
/// exactly when the ring winds counter-clockwise. The unit square makes it
/// concrete — `(0,0) → (1,0) → (1,1) → (0,1)` is counter-clockwise and its
/// bottom edge travels `+x`; the same four vertices reversed do not.
///
/// A horizontal edge at the minimum `y` always exists. The vertex there cannot
/// carry two vertical edges, because both would leave it upwards from the same
/// `x` and overlap over a positive stretch — the self-intersection validation
/// has already refused.
///
/// The two `debug_assert`s at the end are the differential check: every debug
/// and test run compares this against the shoelace it replaces, on every ring
/// the width family reads.
fn ring_winding(xs: &[Dbu], ys: &[Dbu]) -> Winding {
    let n = xs.len();
    debug_assert_eq!(n, ys.len(), "a ring's coordinate columns must agree");
    debug_assert!(n >= 3, "a validated ring has at least three vertices");
    // Reslicing to the same `n` is what deletes the per-element bounds check on
    // the second column, exactly as in `ring_shortest_edge`.
    let ys = &ys[..n];

    // `prev` seeded with the last vertex, so iteration zero is the closing edge
    // and the wrap needs no fixup outside the loop. `i64::MAX` is above every
    // coordinate `MAX_ABS_DBU` admits, so "no horizontal edge yet" and "a
    // horizontal edge higher than the best" are one comparison and there is no
    // second sentinel in the body.
    let (mut px, mut py) = (xs[n - 1].raw(), ys[n - 1].raw());
    let mut best_y = i64::MAX;
    let mut best_dx = 0i64;
    for i in 0..n {
        let (x, y) = (xs[i].raw(), ys[i].raw());
        // Blends, not branches: a vertical edge is folded in at a `y` no minimum
        // can reach rather than skipped, and `x - px` is computed on every edge
        // whether or not it is kept. The body is straight-line integer work over
        // two contiguous columns, which is what lets it vectorise.
        let cand_y = if py == y { py } else { i64::MAX };
        let take = cand_y < best_y;
        best_dx = if take { x - px } else { best_dx };
        best_y = best_y.min(cand_y);
        px = x;
        py = y;
    }

    debug_assert_eq!(
        Some(best_y),
        ys.iter().map(|c| c.raw()).min(),
        "the bottom edge does not sit at the ring's minimum y"
    );
    debug_assert_ne!(
        best_dx, 0,
        "a validated ring has a horizontal edge of positive length at its minimum y"
    );
    let winding = if best_dx > 0 {
        Winding::CounterClockwise
    } else {
        Winding::Clockwise
    };
    debug_assert_eq!(
        Some(winding),
        winding_of(xs, ys),
        "the bottom edge disagrees with the shoelace"
    );
    winding
}

/// The narrowest place inside a polygon.
///
/// **Decision** — one borrowed polygon in, one distance out, pure and
/// table-testable, which is why it is not buried in the transform. A rectangle
/// gives `min(width, height)`; an L gives the narrower arm; a comb gives the
/// tooth. Exact for any rectilinear polygon.
///
/// Holes participate: the material between an outer edge and a hole edge facing
/// it is width, and ignoring it is how a ring with a thin wall passes.
///
/// The sweep's buffers are built here and dropped here, because the signature
/// has nowhere to put them. A caller with a polygon loop —
/// `spacing::wide_flags_into` is the one that exists — pays that per polygon.
/// `docs/SIGNATURE_DEFECTS.md` records the missing scratch parameter.
pub fn narrowest_width(poly: PolygonRef<'_>) -> Dbu {
    let (width, _) = narrowest_width_at(poly, &mut FacingScratch::default());
    debug_assert!(width.raw() > 0, "a polygon with a width of zero has no interior");
    debug_assert!(
        width <= poly.bbox().width().max(poly.bbox().height()),
        "a width is a gap between two coordinates of the polygon, so its own box bounds it"
    );
    width
}

/// The narrowest notch in a polygon, or `None` when it has none.
///
/// **Decision** — the mirror of [`narrowest_width`], reducing over the facing
/// pairs whose gap lies *outside* the shape. `None` for a convex shape, which
/// has no such pair, and that is different from a notch of zero.
pub fn narrowest_notch(poly: PolygonRef<'_>) -> Option<Dbu> {
    let notch =
        narrowest_facing(poly, false, &mut FacingScratch::default()).map(|(gap, _)| gap);
    debug_assert!(
        notch.is_none_or(|gap| gap.raw() > 0),
        "a notch of zero would mean two boundary edges touching, which is not simple"
    );
    notch
}

/// The shortest boundary edge of a polygon.
///
/// **Decision.** Zero-length edges — two identical consecutive vertices — are
/// not edges and do not participate; the validator has already rejected the
/// polygons where that mattered.
pub fn shortest_edge(poly: PolygonRef<'_>) -> Dbu {
    let shortest = poly_rings(poly)
        .map(ring_shortest_edge)
        .min()
        .expect("every validated polygon has an outer boundary");
    debug_assert!(
        shortest.raw() > 0,
        "the validator rejects a ring with two identical consecutive vertices"
    );
    shortest
}

/// The length of one rectilinear edge.
///
/// One of the two terms is always zero, so the sum is the distance and no
/// square root is involved.
fn edge_length(a: Point, b: Point) -> Dbu {
    (b.x - a.x).abs() + (b.y - a.y).abs()
}

/// The shortest edge of one ring.
///
/// **Transform, reducer.** Seeding the fold with the closing edge is what puts
/// the wrap in the same pass with no fixup outside the loop: iteration zero
/// recomputes exactly that edge, and `min` does not care.
fn ring_shortest_edge(ring: RingRef<'_>) -> Dbu {
    let (xs, ys) = ring.coords();
    let n = xs.len();
    debug_assert_eq!(n, ys.len(), "a ring's coordinate columns must agree");
    debug_assert!(n >= 3, "a validated ring has at least three vertices");
    // Reslicing to the same `n` is what deletes the per-element bounds check on
    // the second column: `ys.len() == n` becomes a fact LLVM carries into the
    // loop, where the index is the induction variable. It is also the release
    // profile's half of the length check above.
    let ys = &ys[..n];
    let last = Point { x: xs[n - 1], y: ys[n - 1] };
    let closing = edge_length(last, Point { x: xs[0], y: ys[0] });

    // Strict left-to-right fold, prev-point threaded through it. `min` is the
    // branchless form, so the body carries no data-dependent branch.
    let mut prev = last;
    let mut shortest = closing;
    for i in 0..n {
        let here = Point { x: xs[i], y: ys[i] };
        shortest = shortest.min(edge_length(prev, here));
        prev = here;
    }

    debug_assert!(shortest <= closing, "the seed is one of the edges folded over");
    shortest
}

/// Check every minimum-width rule in the table.
///
/// **Transform, and a kernel**: each polygon's verdict is a function of its own
/// coordinates and the row's uniforms only, so any polygon order is legal and
/// the loop partitions cleanly.
///
/// One violation per offending polygon, not per offending facing pair —
/// reported at the narrowest one, with [`narrowest_width`] as the measurement.
/// A shape with four thin arms is one thing to fix.
///
/// `examined` counts polygons on the layer. `Outcome::Refused` for that row if
/// the layer will not validate.
pub fn check_min_width(
    design: Design<'_>,
    table: &MinWidthTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    debug_assert_eq!(table.len(), table.rule.len(), "{COLUMNS_DIVERGED}");
    check_facing(
        design,
        &table.rule,
        &table.layer,
        &table.limit,
        Facing {
            material_between: true,
            violated_below: true,
        },
        scratch,
        out,
        runs,
    );
}

/// Which facing pair a rule measures, and which way its limit runs.
///
/// Two `bool` rather than two parameters so the call sites above read as their
/// own documentation, and a struct rather than a column because both are
/// **uniforms**: read once per rule row and hoisted above the polygon loop.
/// That is precisely the distinction [`MaxWidthTable`]'s doc draws — a `sense`
/// *column* is a branch inside the loop, a `sense` argument is a constant the
/// optimiser folds through it.
#[derive(Debug, Clone, Copy)]
struct Facing {
    /// `true` measures across material — a width. `false` measures across a
    /// void inside the shape — a notch.
    material_between: bool,
    /// `true` is violated below the limit, `false` above it.
    violated_below: bool,
}

/// The shared body of the three per-polygon rules in this family.
///
/// **Transform, and a kernel**: each polygon's verdict is a function of its own
/// coordinates and the row's uniforms, so any polygon order is legal.
fn check_facing(
    design: Design<'_>,
    rule: &[StrId],
    layer: &[LayerId],
    limit: &[Dbu],
    sense: Facing,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    debug_assert_eq!(rule.len(), layer.len(), "{COLUMNS_DIVERGED}");
    debug_assert_eq!(rule.len(), limit.len(), "{COLUMNS_DIVERGED}");

    // Hoisted above both loops: the sweep's three columns grow to the largest
    // polygon this rule set ever sees and are refilled, never reallocated.
    let mut sweep = FacingScratch::default();

    for row in 0..rule.len() {
        let (rule_id, layer_id, limit) = (rule[row], layer[row], limit[row]);
        debug_assert!(
            limit.raw() > 0,
            "a width-family limit is positive by construction; see DrcError::NonPositiveLimit"
        );
        let before = out.len();

        if validate_layer_into(design.store, layer_id, &mut scratch.layer_a).is_err() {
            // Fail closed. A refusal is recorded against this rule and the run
            // continues; it is never a clean result and never an abort of the
            // twenty-five other rules in the deck.
            record_run(runs, out, before, rule_id, Outcome::Refused, 0);
            continue;
        }

        let polys = u32::try_from(scratch.layer_a.len()).expect("a layer indexes polygons with a u32");
        let mut rows = OuterRows::new(design.store, layer_id);

        for idx in 0..polys {
            let poly = scratch.layer_a.get(design.store, idx);
            let shape = rows.next().expect("one store row per validated polygon");
            // A convex shape has no notch, and that is not a violation of
            // anything. A width is always present, which is what the assert
            // inside `narrowest_width_at` states.
            let Some((measured, at)) = narrowest_facing(poly, sense.material_between, &mut sweep)
            else {
                debug_assert!(
                    !sense.material_between,
                    "a validated polygon always has a facing pair across material"
                );
                continue;
            };

            // Branchless: `violated_below` is a uniform, so the sense costs one
            // `and` and one `or` rather than a jump, and both comparisons are
            // `cmp`/`setcc` the compiler already has in flight.
            let violated = ((measured < limit) & sense.violated_below)
                | ((measured > limit) & !sense.violated_below);

            // The `if` survives on the expensive-taken-side valve: the taken
            // side is eight column pushes with a possible realloc behind them,
            // and on real geometry it is taken for a handful of shapes in a
            // million.
            if violated {
                out.push(Violation {
                    rule: rule_id,
                    layer: layer_id,
                    severity: Severity::Error,
                    at,
                    measured: Measurement::Length(measured),
                    limit: Measurement::Length(limit),
                    shapes: (shape, None),
                });
            }
        }

        debug_assert!(
            rows.next().is_none(),
            "the layer holds more outer boundaries than it validated polygons"
        );
        debug_assert!(
            u64::try_from(out.len() - before).is_ok_and(|pushed| pushed <= u64::from(polys)),
            "one violation per offending polygon, and there are only so many polygons"
        );
        record_run(runs, out, before, rule_id, Outcome::Ran, u64::from(polys));
    }
}

/// Check every maximum-width rule in the table.
///
/// Same scan and same measurement as [`check_min_width`], compared with
/// `LimitSense::Maximum`. `examined` counts polygons.
pub fn check_max_width(
    design: Design<'_>,
    table: &MaxWidthTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    debug_assert_eq!(table.len(), table.rule.len(), "{COLUMNS_DIVERGED}");
    check_facing(
        design,
        &table.rule,
        &table.layer,
        &table.limit,
        Facing {
            material_between: true,
            violated_below: false,
        },
        scratch,
        out,
        runs,
    );
}

/// Check every minimum-edge-length rule in the table.
///
/// One violation per offending *edge*, not per polygon: two short jogs on one
/// wire are two separate places a mask fails, and reporting them as one loses
/// the second coordinate. Reported at the midpoint of that edge, which is the
/// crate's convention (module doc above) and what the suite asserts; an
/// endpoint is shared with the neighbouring edge and so names the finding
/// ambiguously.
///
/// `examined` counts edges, which is the primitive this rule actually looks at
/// and is not derivable from the polygon count.
pub fn check_min_edge_length(
    design: Design<'_>,
    table: &MinEdgeLengthTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    debug_assert_eq!(table.rule.len(), table.layer.len(), "{COLUMNS_DIVERGED}");
    debug_assert_eq!(table.rule.len(), table.limit.len(), "{COLUMNS_DIVERGED}");

    for row in 0..table.len() {
        let (rule_id, layer_id, limit) = (table.rule[row], table.layer[row], table.limit[row]);
        debug_assert!(limit.raw() > 0, "an edge-length limit is positive by construction");
        let before = out.len();

        if validate_layer_into(design.store, layer_id, &mut scratch.layer_a).is_err() {
            record_run(runs, out, before, rule_id, Outcome::Refused, 0);
            continue;
        }

        let polys = u32::try_from(scratch.layer_a.len()).expect("a layer indexes polygons with a u32");
        let mut rows = OuterRows::new(design.store, layer_id);
        let mut examined = 0u64;

        for idx in 0..polys {
            let poly = scratch.layer_a.get(design.store, idx);
            let shape = rows.next().expect("one store row per validated polygon");
            for (a, b) in poly_edges(poly) {
                examined += 1;
                let length = edge_length(a, b);
                // Expensive-taken-side valve, as in `check_facing`: eight column
                // pushes against one compare.
                if length < limit {
                    out.push(Violation {
                        rule: rule_id,
                        layer: layer_id,
                        severity: Severity::Error,
                        // The midpoint, not an endpoint: an endpoint is shared
                        // with the neighbouring edge and names the finding
                        // ambiguously.
                        at: Point {
                            x: mid(a.x, b.x),
                            y: mid(a.y, b.y),
                        },
                        measured: Measurement::Length(length),
                        limit: Measurement::Length(limit),
                        shapes: (shape, None),
                    });
                }
            }
        }

        debug_assert!(
            rows.next().is_none(),
            "the layer holds more outer boundaries than it validated polygons"
        );
        debug_assert!(
            examined >= u64::from(polys) * 3,
            "every validated polygon contributes at least a three-edge outer boundary"
        );
        debug_assert!(
            u64::try_from(out.len() - before).is_ok_and(|pushed| pushed <= examined),
            "one violation per offending edge, and there are only so many edges"
        );
        record_run(runs, out, before, rule_id, Outcome::Ran, examined);
    }
}

/// Check every notch rule in the table.
///
/// One violation per offending polygon, at its narrowest notch. `examined`
/// counts polygons.
pub fn check_notch(
    design: Design<'_>,
    table: &NotchTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    debug_assert_eq!(table.len(), table.rule.len(), "{COLUMNS_DIVERGED}");
    check_facing(
        design,
        &table.rule,
        &table.layer,
        &table.limit,
        Facing {
            material_between: false,
            violated_below: true,
        },
        scratch,
        out,
        runs,
    );
}
