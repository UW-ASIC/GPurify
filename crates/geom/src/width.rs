//! Widths: the narrowest distance across (or between) a polygon's own parallel
//! edges, found by a scanline sweep per axis, and the diagonal necks between
//! its concave corners.
//!
//! Data in: one validated rectilinear polygon. Data out: the narrowest gap and
//! its midpoint. Exact on the whole input domain, but a neck's length, which
//! is floored to a whole unit ([`narrowest_width2`] keeps it exact, squared).

use crate::ops::{isqrt, seg_seg_near2, Point, Seg};
use crate::view::PolygonRef;
use crate::{Dbu, DbuArea};

/// Midpoint of two coordinates, floored on both sides of the origin.
const fn mid(a: Dbu, b: Dbu) -> Dbu {
    Dbu::new_unchecked((a.raw() + b.raw()).div_euclid(2))
}

/// One axis-aligned boundary edge.
#[derive(Debug, Clone, Copy)]
struct Edge {
    /// Coordinate on the axis the edge is perpendicular to.
    pos: Dbu,
    lo: Dbu,
    hi: Dbu,
    /// Material lies on the greater-`pos` side (canonical winding puts material
    /// on the left of travel for every ring, holes included).
    material_above: bool,
    vertical: bool,
}

fn edge_of(a: Point, b: Point) -> Edge {
    let vertical = a.x == b.x;
    let (pos, from, to) = if vertical {
        (a.x, a.y, b.y)
    } else {
        (a.y, a.x, b.x)
    };
    Edge {
        pos,
        lo: from.min(to),
        hi: from.max(to),
        // Travelling +y leaves material at -x; travelling +x leaves it at +y.
        material_above: (to > from) != vertical,
        vertical,
    }
}

/// Every boundary edge of one polygon, holes included, outer ring first.
pub fn poly_edges(poly: PolygonRef<'_>) -> impl Iterator<Item = (Point, Point)> + '_ {
    std::iter::once(poly.outer())
        .chain(poly.holes())
        .flat_map(|ring| {
            let (xs, ys) = ring.coords();
            let n = xs.len();
            (0..n).map(move |i| {
                let j = (i + 1) % n;
                (Point { x: xs[i], y: ys[i] }, Point { x: xs[j], y: ys[j] })
            })
        })
}

/// The gap between two facing edges and its midpoint, or `None` when they do
/// not face each other across material (`material_between`) or across a void.
fn facing_pair(a: Edge, b: Edge, material_between: bool) -> Option<(Dbu, Point)> {
    if a.vertical != b.vertical {
        return None;
    }
    let (near, far) = if a.pos <= b.pos { (a, b) } else { (b, a) };
    if near.material_above != material_between || far.material_above == material_between {
        return None;
    }
    let lo = near.lo.max(far.lo);
    let hi = near.hi.min(far.hi);
    if hi <= lo {
        return None;
    }
    let (across, along) = (mid(near.pos, far.pos), mid(lo, hi));
    let at = if a.vertical {
        Point {
            x: across,
            y: along,
        }
    } else {
        Point {
            x: along,
            y: across,
        }
    };
    Some((far.pos - near.pos, at))
}

/// Buffers for one facing-pair sweep, refilled per polygon.
#[derive(Debug, Default)]
pub struct FacingScratch {
    edges: Vec<Edge>,
    /// `(coordinate, LEAVE|ENTER, edge)`, ascending: spans are half-open.
    events: Vec<(Dbu, u8, u32)>,
    /// Edges crossing the scanline, sorted by `(pos, index)`.
    active: Vec<u32>,
}

const LEAVE: u8 = 0;
const ENTER: u8 = 1;

fn slot_of(edges: &[Edge], active: &[u32], edge: u32) -> usize {
    let want = (edges[edge as usize].pos, edge);
    active.partition_point(|&j| (edges[j as usize].pos, j) < want)
}

/// Fold the active pair `(right - 1, right)` into `best`; out of range is a no-op.
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
    if let Some(found) = facing_pair(near, far, material_between) {
        if best.is_none_or(|(gap, _)| found.0 < gap) {
            *best = Some(found);
        }
    }
}

/// The narrowest facing pair among one axis's edges. Only active-list
/// neighbours can be narrowest, so each event checks the pairs it disturbed.
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
                active.remove(slot);
            }
            ev += 1;
        }
        for &(_, _, edge) in &events[group..ev] {
            let slot = slot_of(edges, active, edge);
            consider(edges, active, slot, material_between, &mut best);
            consider(edges, active, slot + 1, material_between, &mut best);
        }
    }
    best
}

/// The narrowest facing pair of one polygon; a tie keeps the vertical sweep's.
pub fn narrowest_facing(
    poly: PolygonRef<'_>,
    material_between: bool,
    scratch: &mut FacingScratch,
) -> Option<(Dbu, Point)> {
    let FacingScratch {
        edges,
        events,
        active,
    } = scratch;
    edges.clear();
    // A zero-length edge has no material side.
    edges.extend(
        poly_edges(poly)
            .map(|(a, b)| edge_of(a, b))
            .filter(|e| e.lo < e.hi),
    );
    let across = sweep_axis(edges, true, material_between, events, active);
    let along = sweep_axis(edges, false, material_between, events, active);
    [across, along]
        .into_iter()
        .flatten()
        .min_by_key(|&(gap, _)| gap)
}

/// The narrowest width of a validated polygon, holes included, as the `width`
/// rule measures it: the least of the facing widths ([`narrowest_facing`]
/// across material) and the diagonal necks ([`narrowest_neck`]), a neck's
/// length floored to a whole unit.
pub fn narrowest_width(poly: PolygonRef<'_>, scratch: &mut FacingScratch) -> Dbu {
    isqrt(narrowest_width2(poly, scratch))
}

/// [`narrowest_width`] squared, exact: a diagonal neck of `√5000` is 5000,
/// so comparing it against a squared limit has no rounding.
pub fn narrowest_width2(poly: PolygonRef<'_>, scratch: &mut FacingScratch) -> DbuArea {
    let facing = narrowest_facing(poly, true, scratch)
        .expect("every validated polygon has a facing pair across its own material")
        .0;
    neck2(poly, facing).map_or(facing.mul_wide(facing), |(gap2, _)| DbuArea::new(gap2))
}

/// The narrowest diagonal neck of a polygon under `limit`: the Euclidean gap
/// between two concave corners facing each other across material, as at the
/// inner corners of two overlapping rectangles (`KLayout`'s euclidean width).
/// Facing edges whose projections overlap are [`narrowest_facing`]'s; this is
/// the corner-to-corner case it cannot see. The gap is the integer square
/// root of the exact squared gap, floored at any size; the comparison against
/// `limit` is exact. Returns the gap and its midpoint, or `None` when no such
/// neck is narrower than `limit`.
///
/// Over `k` concave corners, `O(k log k)` plus the pairs within `limit` in x:
/// `O(k²)` only when every corner sits in one `limit`-wide column.
pub fn narrowest_neck(poly: PolygonRef<'_>, limit: Dbu) -> Option<(Dbu, Point)> {
    neck2(poly, limit).map(|(gap2, at)| (isqrt(DbuArea::new(gap2)), at))
}

/// [`narrowest_neck`] with the gap squared, exact.
fn neck2(poly: PolygonRef<'_>, limit: Dbu) -> Option<(i128, Point)> {
    // ponytail: pairs within `limit` along x, O(k²) only when every concave
    // corner sits in one `limit`-wide column.
    // Each concave corner, with the diagonal its void quadrant points along.
    let mut corners: Vec<(i64, i64, i64, i64)> = Vec::new();
    for ring in std::iter::once(poly.outer()).chain(poly.holes()) {
        let (xs, ys) = ring.coords();
        let n = xs.len();
        for i in 0..n {
            let (p, c, q) = ((i + n - 1) % n, i, (i + 1) % n);
            let (ix, iy) = (xs[c].raw() - xs[p].raw(), ys[c].raw() - ys[p].raw());
            let (ox, oy) = (xs[q].raw() - xs[c].raw(), ys[q].raw() - ys[c].raw());
            // Material on the left of travel: a right turn is concave, and
            // the void lies back along the way in and on along the way out.
            if ix * oy - iy * ox < 0 {
                let (vx, vy) = ((ox - ix).signum(), (oy - iy).signum());
                corners.push((xs[c].raw(), ys[c].raw(), vx, vy));
            }
        }
    }
    corners.sort_unstable();
    let limit = limit.raw();
    let mut best: Option<(i128, Point)> = None;
    for (i, &(x, y, vx, vy)) in corners.iter().enumerate() {
        for &(x2, y2, vx2, vy2) in &corners[i + 1..] {
            if x2 - x >= limit {
                break;
            }
            let (dx, dy) = (x2 - x, y2 - y);
            // Opposite voids, and each corner on the other's material side.
            if (vx2, vy2) != (-vx, -vy) || dx * vx > 0 || dy * vy > 0 {
                continue;
            }
            let gap2 = i128::from(dx) * i128::from(dx) + i128::from(dy) * i128::from(dy);
            if gap2 < i128::from(limit) * i128::from(limit) && best.is_none_or(|(b, _)| gap2 < b) {
                let at = Point {
                    x: Dbu::new_unchecked((x + x2).div_euclid(2)),
                    y: Dbu::new_unchecked((y + y2).div_euclid(2)),
                };
                best = Some((gap2, at));
            }
        }
    }
    best
}

/// The narrowest width (`material_between`) or notch of a polygon whose
/// edges may lie at 45 degrees, as twice its square, exact, and where it is:
/// the midpoint of its two nearest points, floored. Only what is narrower
/// than `limit` is looked for; `None` when there is none.
///
/// The width is the rectilinear one ([`narrowest_width`]) read at every
/// octilinear angle, `KLayout`'s Euclidean `width` restricted to
/// antiparallel edge pairs, the least of:
/// - two antiparallel edges, each strictly on the other's material side, at
///   the distance between them: perpendicular where they face each other
///   (IHP SG13G2 M1.g/Mn.g, "45-degree bent width", which the PDK's
///   `KLayout` deck checks as a Euclidean `width` between the 45-degree
///   edges), end to end past each other (a neck, as at the inner corners of
///   two overlapping rectangles);
/// - two antiparallel edges on one line that touch, where the figure meets
///   itself across a point (the connected corner model): width 0; so too a
///   corner on an edge where one of its edges is at 135 degrees to it (below,
///   `KLayout`'s zero distance when touching);
/// - an acute tip, a corner of less than 90 degrees: width 0;
/// - two edges at 135 degrees to each other, an axis edge and a 45-degree one
///   (a chamfer and the side across from it, a 45-degree corner cut across an
///   L's inner corner), each with an end strictly on the other's material
///   side: the distance between the parts of each on the other's material
///   side, as `KLayout`'s Euclidean `width` at its default `angle_limit` of 90
///   pairs them. The foundry decks measure width so (gf180mcu's `fd_pv` unit
///   structures flag a chamfered `NW.1a` box whose side next to the chamfer
///   is under the limit).
///
/// A notch is two antiparallel edges facing across empty space over a
/// stretch of positive length, as [`narrowest_facing`] reads one.
///
/// Over `n` edges, the pairs within `limit` in x: `O(n²)` only when every
/// edge sits in one `limit`-wide column.
pub fn narrowest_pair2(
    poly: PolygonRef<'_>,
    material_between: bool,
    limit: Dbu,
) -> Option<(i128, Point)> {
    // ponytail: pairs within `limit` along x; a sweep by both axes if a figure
    // with thousands of edges in one column makes this slow.
    let mut best: Option<(i128, Point)> = None;
    let bound = 2 * limit.mul_wide(limit).raw();
    let mut keep = |d2: i128, at: Point| {
        if d2 < bound && best.is_none_or(|(b, _)| d2 < b) {
            best = Some((d2, at));
        }
    };
    let mid4 = |p: (i64, i64), q: (i64, i64)| Point {
        x: Dbu::new_unchecked((p.0 + q.0).div_euclid(4)),
        y: Dbu::new_unchecked((p.1 + q.1).div_euclid(4)),
    };

    let mut edges: Vec<Seg> = poly_edges(poly)
        .filter(|(a, b)| a != b)
        .map(|(a, b)| Seg { a, b })
        .collect();
    edges.sort_unstable_by_key(|e| e.a.x.min(e.b.x));
    for (i, &e) in edges.iter().enumerate() {
        let reach = e.a.x.max(e.b.x).raw() + limit.raw();
        for &f in &edges[i + 1..] {
            if f.a.x.min(f.b.x).raw() > reach {
                break;
            }
            if facing(e, f, material_between) {
                let (d2, p, q) = seg_seg_near2(e, f);
                keep(d2, mid4(p, q));
            } else if let Some((e, f)) = material_between.then(|| slanted(e, f)).flatten() {
                let (d2, p, q) = seg_seg_near2(e, f);
                keep(d2, mid4(p, q));
            }
        }
    }
    if !material_between {
        return best;
    }

    for ring in std::iter::once(poly.outer()).chain(poly.holes()) {
        let (xs, ys) = ring.coords();
        let n = xs.len();
        for i in 0..n {
            let (p, c, q) = ((i + n - 1) % n, i, (i + 1) % n);
            let (x, y) = (xs[c].raw(), ys[c].raw());
            let back = (xs[p].raw() - x, ys[p].raw() - y);
            let on = (xs[q].raw() - x, ys[q].raw() - y);
            // Turning from the way in, `-back`, to the way out.
            let turn =
                i128::from(back.1) * i128::from(on.0) - i128::from(back.0) * i128::from(on.1);
            let dot = i128::from(back.0) * i128::from(on.0) + i128::from(back.1) * i128::from(on.1);
            if turn > 0 && dot > 0 {
                // A left turn by more than 90 degrees: an acute tip.
                keep(0, Point { x: xs[c], y: ys[c] });
            }
        }
    }
    best
}

/// The parts of `e` and `f` a width measures when they are at 135 degrees to
/// each other and each has an end strictly on the other's material side
/// (`KLayout`'s `euclidian_near_part_of_edge`): each cut to the other's
/// material side, line included. `None` for any other pair.
fn slanted(e: Seg, f: Seg) -> Option<(Seg, Seg)> {
    let dir = |s: Seg| {
        (
            i128::from(s.b.x.raw() - s.a.x.raw()),
            i128::from(s.b.y.raw() - s.a.y.raw()),
        )
    };
    let ((ux, uy), (vx, vy)) = (dir(e), dir(f));
    if ux * vy == uy * vx || ux * vx + uy * vy >= 0 {
        return None;
    }
    // How far `of` is on `line`'s left, its material side, scaled.
    let side = |line: Seg, of: Point| {
        let (lx, ly) = dir(line);
        lx * i128::from(of.y.raw() - line.a.y.raw()) - ly * i128::from(of.x.raw() - line.a.x.raw())
    };
    // Two edges that touch and do not follow one another, as where a corner
    // lies on an edge (the connected corner model): `KLayout`'s zero distance
    // when touching counts the line itself as the material side, so the pair
    // is at 0 unless one lies wholly off the other's material side.
    if crate::ops::segments_intersect(e, f) && e.b != f.a && e.a != f.b {
        let off = |s: Seg, line: Seg| side(line, s.a) < 0 && side(line, s.b) < 0;
        return (!off(e, f) && !off(f, e)).then_some((e, f));
    }
    // `s` cut to `line`'s material side; it has an end strictly there.
    let cut = |s: Seg, line: Seg| {
        let (a, b) = (side(line, s.a), side(line, s.b));
        if a <= 0 && b <= 0 {
            return None;
        }
        if a >= 0 && b >= 0 {
            return Some(s);
        }
        // An axis edge meets a 45-degree line, and a 45-degree edge an axis
        // line, at a lattice point.
        let (dx, dy) = dir(s);
        let at = |n: i128, of: i64| {
            debug_assert_eq!(n % (a - b), 0, "an octilinear crossing is on the lattice");
            Dbu::new_unchecked(of + i64::try_from(n / (a - b)).expect("on the segment"))
        };
        let x = Point {
            x: at(dx * a, s.a.x.raw()),
            y: at(dy * a, s.a.y.raw()),
        };
        Some(if a > 0 {
            Seg { a: s.a, b: x }
        } else {
            Seg { a: x, b: s.b }
        })
    };
    Some((cut(e, f)?, cut(f, e)?))
}

/// Whether `(e, f)` face each other: antiparallel and each strictly on the
/// other's material side (`material_between`), or each on the other's empty
/// side over a stretch of positive length.
fn facing(e: Seg, f: Seg, material_between: bool) -> bool {
    let dir = |s: Seg| (s.b.x.raw() - s.a.x.raw(), s.b.y.raw() - s.a.y.raw());
    let ((ux, uy), (vx, vy)) = (dir(e), dir(f));
    let (ux, uy, vx, vy) = (
        i128::from(ux),
        i128::from(uy),
        i128::from(vx),
        i128::from(vy),
    );
    if ux * vy != uy * vx || ux * vx + uy * vy >= 0 {
        return false;
    }
    let want = if material_between { 1 } else { -1 };
    // The side of `of`'s first end against `line`: + is its left, its material.
    let side = |line: Seg, of: Point| {
        let (lx, ly) = dir(line);
        let (wx, wy) = (of.x.raw() - line.a.x.raw(), of.y.raw() - line.a.y.raw());
        (i128::from(lx) * i128::from(wy) - i128::from(ly) * i128::from(wx)).signum()
    };
    let (fe, ef) = (side(e, f.a), side(f, e.a));
    // Antiparallel on one line and touching: where the figure meets itself
    // across a point (the connected corner model), a width of 0.
    if material_between && fe == 0 && ef == 0 {
        return crate::ops::segments_intersect(e, f);
    }
    if fe != want || ef != want {
        return false;
    }
    if material_between {
        // A width pair need not overlap: past each other's ends the two
        // edges are as far apart as their nearest ends (a neck).
        return true;
    }
    let at = |p: Point| ux * i128::from(p.x.raw()) + uy * i128::from(p.y.raw());
    let (e0, e1) = (at(e.a).min(at(e.b)), at(e.a).max(at(e.b)));
    let (f0, f1) = (at(f.a).min(at(f.b)), at(f.a).max(at(f.b)));
    e0.max(f0) < e1.min(f1)
}

/// [`narrowest_pair2`] at any angle, exact: the narrowest width
/// (`material_between`) or notch under `limit`, twice its square as its floor
/// and whether the true value lies above it, and where it is (the midpoint
/// of its two nearest points, rounded). `None` when there is none.
///
/// The width is `KLayout`'s Euclidean `width` at its default `angle_limit`:
/// the least, over every ordered pair of the figure's edges at more than 90
/// degrees to each other, of the distance between the parts of each on the
/// other's material side
/// ([`crate::relation::pair_threshold_any`] under [`Relation::Width`]); so
/// facing edges, necks, a skew edge against one across from it, and an acute
/// tip (0). On octilinear figures it is [`narrowest_pair2`]. A notch is two
/// antiparallel edges facing across empty space over a stretch of positive
/// length, as [`narrowest_pair2`] reads one.
///
/// Over `n` edges, the pairs within `limit` in x: `O(n²)` only when every
/// edge sits in one `limit`-wide column.
pub fn narrowest_pair_any(
    poly: PolygonRef<'_>,
    material_between: bool,
    limit: Dbu,
) -> Option<((i128, bool), Point)> {
    use crate::relation::{pair_threshold_any, Relation, Zero};
    let mut best: Option<((i128, bool), Point)> = None;
    let bound = 2 * limit.mul_wide(limit).raw();
    let mut keep = |d2: (i128, bool), e: Seg, f: Seg| {
        if d2.0 < bound && best.is_none_or(|(b, _)| d2 < b) {
            let (_, p, q) = seg_seg_near2(e, f);
            let at = Point {
                x: Dbu::new_unchecked((p.0 + q.0).div_euclid(4)),
                y: Dbu::new_unchecked((p.1 + q.1).div_euclid(4)),
            };
            best = Some((d2, at));
        }
    };
    let rev = |s: Seg| Seg { a: s.b, b: s.a };
    let mut edges: Vec<Seg> = poly_edges(poly)
        .filter(|(a, b)| a != b)
        .map(|(a, b)| Seg { a, b })
        .collect();
    edges.sort_unstable_by_key(|e| e.a.x.min(e.b.x));
    for (i, &e) in edges.iter().enumerate() {
        let reach = e.a.x.max(e.b.x).raw() + limit.raw();
        let (ylo, yhi) = (e.a.y.min(e.b.y).raw(), e.a.y.max(e.b.y).raw());
        for &f in &edges[i + 1..] {
            if f.a.x.min(f.b.x).raw() > reach {
                break;
            }
            let (flo, fhi) = (f.a.y.min(f.b.y).raw(), f.a.y.max(f.b.y).raw());
            if flo > yhi + limit.raw() || ylo > fhi + limit.raw() {
                continue;
            }
            if material_between {
                for (p, q) in [(e, f), (f, e)] {
                    if let Some(d2) =
                        pair_threshold_any(Relation::Width, Zero::WhenTouching, rev(p), rev(q))
                    {
                        keep(d2, e, f);
                    }
                }
            } else if facing(e, f, false) {
                keep(crate::ops::seg_seg_twice2(e, f), e, f);
            }
        }
    }
    best
}
