//! Width family: how narrow a single shape, or one feature of it, may be.
//!
//! All four rules measure *within* one polygon and fall out of the same scan
//! over a validated polygon's edges — the set of *facing* parallel edge pairs,
//! meaning two antiparallel edges whose projections onto their shared axis
//! overlap. A facing pair whose interior is inside the polygon is a width,
//! outside it a notch; the same minimum compared the other way is
//! [`check_max_width`]; one edge's own length is [`check_min_edge_length`].
//!
//! The scan is exact for any rectilinear polygon, which is the whole input
//! domain, so there is no approximate path here.

use super::{COLUMNS_DIVERGED, mid, ring_segs, row_columns};
use crate::{record_run, Design, Scratch};
use gpurify_core::ops::{winding_of, Point, Winding};
use gpurify_core::boolean::union_into;
use gpurify_core::view::{validate_layer_into, ValidatedLayer};
use gpurify_core::{GeometryStore, LayerId, PolyId, PolygonRef, RingRef};
use gpurify_ingest::StrId;
use gpurify_report::{Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use gpurify_units::Dbu;

/// Minimum width: no part of a shape may be narrower than the limit.
#[derive(Debug, Default)]
pub struct MinWidthTable {
    /// The deck's id for the rule, interned.
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// Violated *below*.
    pub limit: Vec<Dbu>,
}

/// Maximum width: a shape wider than the limit must be slotted.
///
/// A separate table rather than a `sense` column on [`MinWidthTable`]: a
/// `sense` column would be a branch inside the loop.
#[derive(Debug, Default)]
pub struct MaxWidthTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    /// Violated *above*.
    pub limit: Vec<Dbu>,
}

/// Minimum edge length: no single boundary edge shorter than the limit.
#[derive(Debug, Default)]
pub struct MinEdgeLengthTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    pub limit: Vec<Dbu>,
}

/// Notch: two edges of the *same* polygon facing each other across a gap that
/// is outside the shape.
#[derive(Debug, Default)]
pub struct NotchTable {
    pub rule: Vec<StrId>,
    pub layer: Vec<LayerId>,
    pub limit: Vec<Dbu>,
}

row_columns! {
    MinWidthTable { rule, layer, limit },
    MaxWidthTable { rule, layer, limit },
    MinEdgeLengthTable { rule, layer, limit },
    NotchTable { rule, layer, limit },
}

/// One boundary edge, reduced to the four facts a facing-pair test reads.
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
fn edge_of((a, b): (Point, Point)) -> Edge {
    let vertical = a.x == b.x;
    debug_assert!(
        vertical || a.y == b.y,
        "a validated polygon is rectilinear, so every edge is axis-aligned"
    );
    let (pos, from, to) = if vertical { (a.x, a.y, b.y) } else { (a.y, a.x, b.x) };
    Edge {
        pos,
        lo: from.min(to),
        hi: from.max(to),
        // Travelling +y leaves material at -x; travelling +x leaves it at +y.
        material_above: (to > from) != vertical,
        vertical,
    }
}

/// Every ring of one polygon, outer boundary first.
fn poly_rings(poly: PolygonRef<'_>) -> impl Iterator<Item = RingRef<'_>> {
    std::iter::once(poly.outer()).chain(poly.holes())
}

/// One ring's edges as vertex pairs, the closing edge last.
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
/// An edge of no extent has no direction and so no material side; [`facing`]
/// and [`sweep_axis`] both rely on its absence.
fn edges(poly: PolygonRef<'_>) -> impl Iterator<Item = Edge> + '_ {
    poly_edges(poly).map(edge_of).filter(|e| e.lo < e.hi)
}

/// The gap between two edges that face each other, and the midpoint of it.
///
/// `None` when they are not a facing pair: different axes, the same direction
/// of travel, projections sharing no positive-length overlap, or material on
/// the side the caller did not ask for. `material_between` is the *only* thing
/// that separates a width from a notch.
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

/// Reusable buffers for one facing-pair sweep, cleared and refilled per
/// polygon.
#[derive(Debug, Default)]
struct FacingScratch {
    /// The polygon's edges, both axes, in ring order; the other two columns
    /// carry indices into it.
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
/// Out-of-range is not an error: the ends of the active list have no outward
/// neighbour, and a sweep that checks around every event asks for one anyway.
fn consider(
    edges: &[Edge],
    active: &[u32],
    right: usize,
    material_between: bool,
    best: &mut Option<(Dbu, Point)>,
) {
    if right == 0 || right >= active.len() {
        return;
    }
    let near = edges[active[right - 1] as usize];
    let far = edges[active[right] as usize];
    if let Some(found) = facing(near, far, material_between) {
        if best.is_none_or(|(gap, _)| found.0 < gap) {
            *best = Some(found);
        }
    }
}

/// The narrowest facing pair among the edges of one axis, by scanline sweep.
///
/// Only **adjacent** active-list entries can be the narrowest pair: an edge `w`
/// between an accepted pair forms an accepted pair with one of the two and a
/// smaller gap, whichever way the material test goes for `w`. So checking the
/// pairs disturbed at each event coordinate is enough.
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
    while ev < events.len() {
        let at = events[ev].0;
        let group = ev;
        while ev < events.len() && events[ev].0 == at {
            let (_, kind, edge) = events[ev];
            let slot = slot_of(edges, active, edge);
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

/// The narrowest facing pair of one polygon, and where to report it;
/// `material_between` picks the side — `true` a width, `false` a notch.
///
/// Ties are broken by naming the first place the vertical sweep reached, which
/// is a function of the coordinates alone.
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
    // `min_by_key` keeps the first of a tie, which is what fixes the axis order.
    let best = [across, along].into_iter().flatten().min_by_key(|&(gap, _)| gap);

    debug_assert!(
        best.is_none_or(|(gap, _)| gap.raw() >= 0),
        "a facing pair is ordered by position, so its gap cannot be negative"
    );
    best
}

/// The narrowest width of one polygon, and where to report it.
///
/// Always present: every validated polygon has a facing pair across its own
/// material.
fn narrowest_width_at(poly: PolygonRef<'_>, scratch: &mut FacingScratch) -> (Dbu, Point) {
    narrowest_facing(poly, true, scratch)
        .expect("every validated polygon has a facing pair across its own material")
}

/// The store row each validated polygon of one layer came from, in
/// [`ValidatedLayer::get`](gpurify_core::ValidatedLayer::get) order.
///
/// `ValidatedLayer::ring_poly` is private with no accessor, so this replays the
/// filter validation used: one polygon per counter-clockwise row, in ascending
/// row order. The missing accessor is recorded in `docs/SIGNATURE_DEFECTS.md`.
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
            if ring_winding(xs, ys) == Winding::CounterClockwise {
                return Some(poly);
            }
        }
        None
    }
}

/// Which way one already-validated rectilinear ring winds.
///
/// Only correct on the validated domain, where the answer is written on the
/// bottom edge: a horizontal edge at the ring's minimum `y` travels `+x`
/// exactly when the ring winds counter-clockwise. Such an edge always exists
/// there, because a vertex at the minimum `y` cannot carry two vertical edges
/// without the self-intersection validation having refused the ring. Use
/// [`winding_of`] for anything not so validated.
fn ring_winding(xs: &[Dbu], ys: &[Dbu]) -> Winding {
    let n = xs.len();
    debug_assert_eq!(n, ys.len(), "a ring's coordinate columns must agree");
    debug_assert!(n >= 3, "a validated ring has at least three vertices");
    // Reslicing to the same `n` deletes the per-element bounds check on the
    // second column.
    let ys = &ys[..n];

    // `prev` seeded with the last vertex, so iteration zero is the closing edge
    // and the wrap needs no fixup. `i64::MAX` is above every coordinate
    // `MAX_ABS_DBU` admits, so it doubles as "no horizontal edge yet".
    let (mut px, mut py) = (xs[n - 1].raw(), ys[n - 1].raw());
    let mut best_y = i64::MAX;
    let mut best_dx = 0i64;
    for i in 0..n {
        let (x, y) = (xs[i].raw(), ys[i].raw());
        // A vertical edge is folded in at a `y` no minimum can reach rather
        // than skipped, so the body stays branchless.
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

/// The narrowest place inside a polygon, exact for any rectilinear one.
///
/// Holes participate: the material between an outer edge and a hole edge facing
/// it is width, and ignoring it is how a ring with a thin wall passes.
/// Allocates the sweep's buffers per call because the signature has nowhere to
/// put them; recorded in `docs/SIGNATURE_DEFECTS.md`.
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
/// The mirror of [`narrowest_width`], over the facing pairs whose gap lies
/// *outside* the shape. `None` for a convex shape, which is not a notch of zero.
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

/// The length of one rectilinear edge — one term is always zero, so the sum is
/// the distance and no square root is involved.
fn edge_length(a: Point, b: Point) -> Dbu {
    (b.x - a.x).abs() + (b.y - a.y).abs()
}

/// The shortest edge of one ring.
///
/// Seeded with the closing edge, which puts the wrap in the same pass with no
/// fixup: iteration zero recomputes exactly that edge and `min` does not care.
fn ring_shortest_edge(ring: RingRef<'_>) -> Dbu {
    let (xs, ys) = ring.coords();
    let n = xs.len();
    debug_assert_eq!(n, ys.len(), "a ring's coordinate columns must agree");
    debug_assert!(n >= 3, "a validated ring has at least three vertices");
    // Reslicing to the same `n` deletes the per-element bounds check on the
    // second column, and is the release profile's half of the length check.
    let ys = &ys[..n];
    let last = Point { x: xs[n - 1], y: ys[n - 1] };
    let closing = edge_length(last, Point { x: xs[0], y: ys[0] });

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
/// One violation per offending polygon, at its narrowest facing pair.
/// `examined` counts polygons on the layer; `Outcome::Refused` for a row whose
/// layer will not validate.
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
/// **A notch is measured on the merged figure; a width is not.** Which
/// conductor a polygon belongs to is a property of the layer, not of the
/// polygon: three touching rectangles are one U with one notch, and each
/// rectangle alone is convex and has none. So the notch scan runs over the
/// layer's outers self-unioned. A width is a gap *inside* material and stays on
/// the store rows as drawn, which errs fail-closed.
///
/// `examined` stays the input polygon count for both senses, so the number
/// keeps meaning "shapes this rule looked at".
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

    // Hoisted above both loops: these grow to the largest polygon this rule set
    // ever sees and are refilled, never reallocated.
    let mut sweep = FacingScratch::default();
    let mut merged = ValidatedLayer::default();
    let nothing = ValidatedLayer::default();

    for row in 0..rule.len() {
        let (rule_id, layer_id, limit) = (rule[row], layer[row], limit[row]);
        debug_assert!(
            limit.raw() > 0,
            "a width-family limit is positive by construction; see DrcError::NonPositiveLimit"
        );
        let before = out.len();

        if validate_layer_into(design.store, layer_id, &mut scratch.layer_a).is_err() {
            // Fail closed: a refusal against this rule, never a clean result and
            // never an abort of the rest of the deck.
            record_run(runs, out, before, rule_id, Outcome::Refused, 0);
            continue;
        }

        // Read before the merge can change how many polygons there are.
        let polys = u32::try_from(scratch.layer_a.len()).expect("a layer indexes polygons with a u32");

        // The merge, for the notch sense only. A layer `union_into` cannot merge
        // is a layer the facing scan cannot measure either, so refusing the row
        // is the fail-closed answer.
        if !sense.material_between && union_into(&scratch.layer_a, &nothing, &mut merged).is_err() {
            record_run(runs, out, before, rule_id, Outcome::Refused, 0);
            continue;
        }
        let figures = if sense.material_between {
            &scratch.layer_a
        } else {
            &merged
        };
        let count = u32::try_from(figures.len()).expect("a layer indexes polygons with a u32");

        for idx in 0..count {
            let poly = figures.get(design.store, idx);
            // Provenance, not the store row order: a merged figure is not a row
            // of any layer, so `OuterRows` cannot name it.
            let shape = poly.provenance();
            // A convex shape has no notch, and that is not a violation.
            let Some((measured, at)) = narrowest_facing(poly, sense.material_between, &mut sweep)
            else {
                debug_assert!(
                    !sense.material_between,
                    "a validated polygon always has a facing pair across material"
                );
                continue;
            };

            let violated = ((measured < limit) & sense.violated_below)
                | ((measured > limit) & !sense.violated_below);

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
            count <= polys,
            "a union of a layer with nothing cannot produce more figures than \
             the layer has polygons, {count} against {polys}"
        );
        debug_assert!(
            u64::try_from(out.len() - before).is_ok_and(|pushed| pushed <= u64::from(count)),
            "one violation per offending figure, and there are only so many figures"
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
/// One violation per offending *edge*, not per polygon, at the midpoint of that
/// edge. `examined` counts edges.
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
                if length < limit {
                    out.push(Violation {
                        rule: rule_id,
                        layer: layer_id,
                        severity: Severity::Error,
                        // The midpoint: an endpoint is shared with the
                        // neighbouring edge and names the finding ambiguously.
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
