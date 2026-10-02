//! Facing-edge widths: the narrowest distance across (or between) a polygon's
//! own parallel edges, found by a scanline sweep per axis.
//!
//! Data in: one validated rectilinear polygon. Data out: the narrowest gap and
//! its midpoint. Exact on the whole input domain.

use crate::ops::Point;
use crate::view::PolygonRef;
use crate::Dbu;

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

/// The narrowest width of a validated polygon, holes included.
pub fn narrowest_width(poly: PolygonRef<'_>, scratch: &mut FacingScratch) -> Dbu {
    narrowest_facing(poly, true, scratch)
        .expect("every validated polygon has a facing pair across its own material")
        .0
}

/// The narrowest diagonal neck of a polygon under `limit`: the Euclidean gap
/// between two concave corners facing each other across material, as at the
/// inner corners of two overlapping rectangles (`KLayout`'s euclidean width).
/// Facing edges whose projections overlap are [`narrowest_facing`]'s; this is
/// the corner-to-corner case it cannot see. The gap is floored to a whole
/// unit; the comparison against `limit` is exact.
///
/// ponytail: pairs within `limit` along x, O(k²) only when every concave
/// corner sits in one `limit`-wide column.
pub fn narrowest_neck(poly: PolygonRef<'_>, limit: Dbu) -> Option<(Dbu, Point)> {
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
    best.map(|(gap2, at)| {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_precision_loss,
            reason = "a gap under the limit"
        )]
        let gap = (gap2 as f64).sqrt() as i64;
        (Dbu::new_unchecked(gap), at)
    })
}
