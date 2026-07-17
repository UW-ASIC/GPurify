//! Free-function geometric primitives over the SoA store: segment distance,
//! intersection, window clipping, point-in-polygon, self-intersection, isqrt.
//!
//! The integer predicates here are correctness-critical (exact `i128` cross
//! products, fail-closed on overflow) and are ported verbatim.

use super::edge::Edge;
use super::ids::PolyId;
use super::store::GeometryStore;

/// Squared Euclidean distance between two segments' closest points (any angle:
/// for non-crossing segments the minimum is always at an endpoint). Returns 0
/// if they touch/cross. The primitive both spacing and corner checks use.
#[must_use]
pub fn seg_seg_dist2(a: &Edge, b: &Edge) -> i64 {
    if segments_intersect(a, b) {
        return 0;
    }
    let mut best = i64::MAX;
    for &(px, py) in &[(a.x0, a.y0), (a.x1, a.y1)] {
        best = best.min(point_seg_dist2(px, py, b));
    }
    for &(px, py) in &[(b.x0, b.y0), (b.x1, b.y1)] {
        best = best.min(point_seg_dist2(px, py, a));
    }
    best
}

#[inline]
fn point_seg_dist2(px: i32, py: i32, e: &Edge) -> i64 {
    let vx = i128::from(e.dx_i64());
    let vy = i128::from(e.dy_i64());
    let wx = i128::from(px) - i128::from(e.x0);
    let wy = i128::from(py) - i128::from(e.y0);
    let c1 = vx * wx + vy * wy;
    if c1 <= 0 {
        return i64::try_from(wx * wx + wy * wy).unwrap_or(i64::MAX);
    }
    let c2 = vx * vx + vy * vy;
    if c2 <= c1 {
        let dx = i128::from(px) - i128::from(e.x1);
        let dy = i128::from(py) - i128::from(e.y1);
        return i64::try_from(dx * dx + dy * dy).unwrap_or(i64::MAX);
    }
    // Projection falls on the segment: d² = |w|² − c1²/c2, exact in i128
    // (f64 here loses ulps on diagonal edges at large coordinates).
    let Some(num) = (wx * wx + wy * wy)
        .checked_mul(c2)
        .and_then(|lhs| c1.checked_mul(c1).and_then(|rhs| lhs.checked_sub(rhs)))
    else {
        // The legacy scalar-distance API cannot represent this intermediate;
        // DRC validation rejects such coordinate extents before rule execution.
        return i64::MAX;
    };
    i64::try_from(num / c2).unwrap_or(i64::MAX)
}

fn orient(ax: i64, ay: i64, bx: i64, by: i64, cx: i64, cy: i64) -> i128 {
    (i128::from(bx) - i128::from(ax)) * (i128::from(cy) - i128::from(ay))
        - (i128::from(by) - i128::from(ay)) * (i128::from(cx) - i128::from(ax))
}

fn on_seg(ax: i64, ay: i64, bx: i64, by: i64, cx: i64, cy: i64) -> bool {
    cx >= ax.min(bx) && cx <= ax.max(bx) && cy >= ay.min(by) && cy <= ay.max(by)
}

/// Do two segments intersect (proper crossing or collinear touch)?
#[must_use]
pub fn segments_intersect(a: &Edge, b: &Edge) -> bool {
    let (ax, ay, bx, by) = (
        i64::from(a.x0),
        i64::from(a.y0),
        i64::from(a.x1),
        i64::from(a.y1),
    );
    let (cx, cy, dx, dy) = (
        i64::from(b.x0),
        i64::from(b.y0),
        i64::from(b.x1),
        i64::from(b.y1),
    );
    let d1 = orient(cx, cy, dx, dy, ax, ay);
    let d2 = orient(cx, cy, dx, dy, bx, by);
    let d3 = orient(ax, ay, bx, by, cx, cy);
    let d4 = orient(ax, ay, bx, by, dx, dy);
    if ((d1 > 0) != (d2 > 0)) && ((d3 > 0) != (d4 > 0)) {
        return true;
    }
    (d1 == 0 && on_seg(cx, cy, dx, dy, ax, ay))
        || (d2 == 0 && on_seg(cx, cy, dx, dy, bx, by))
        || (d3 == 0 && on_seg(ax, ay, bx, by, cx, cy))
        || (d4 == 0 && on_seg(ax, ay, bx, by, dx, dy))
}

/// Area of a polygon clipped to an axis-aligned window (Sutherland–Hodgman +
/// shoelace). Exact for rectilinear geometry; `f64` for the fractional
/// intersection points diagonal edges can produce. Density checks need this —
/// a bbox-based coverage estimate wildly overstates non-convex shapes.
#[must_use]
pub fn clipped_area(
    store: &GeometryStore,
    p: PolyId,
    xmin: i32,
    ymin: i32,
    xmax: i32,
    ymax: i32,
) -> f64 {
    clipped_area_i64(
        store,
        p,
        i64::from(xmin),
        i64::from(ymin),
        i64::from(xmax),
        i64::from(ymax),
    )
}

/// Wide-coordinate density clip. Window edges may extend past the `i32` layout
/// domain even though every stored vertex is representable.
#[must_use]
pub fn clipped_area_i64(
    store: &GeometryStore,
    p: PolyId,
    xmin: i64,
    ymin: i64,
    xmax: i64,
    ymax: i64,
) -> f64 {
    let (s, e) = store.poly_range(p);
    // Work in window-relative coordinates. Shoelace on absolute coordinates
    // catastrophically cancels a 5x5 area translated near i32::MAX.
    let (origin_x, origin_y) = (i128::from(xmin), i128::from(ymin));
    let mut ring: Vec<(f64, f64)> = (s..e)
        .map(|i| {
            (
                (i128::from(store.verts_x[i]) - origin_x) as f64,
                (i128::from(store.verts_y[i]) - origin_y) as f64,
            )
        })
        .collect();
    let planes: [(f64, bool, bool); 4] = [
        (0.0, true, true),
        ((i128::from(xmax) - origin_x) as f64, true, false),
        (0.0, false, true),
        ((i128::from(ymax) - origin_y) as f64, false, false),
    ];
    for &(c, is_x, keep_ge) in &planes {
        if ring.is_empty() {
            return 0.0;
        }
        let val = |pt: (f64, f64)| if is_x { pt.0 } else { pt.1 };
        let inside = |pt: (f64, f64)| if keep_ge { val(pt) >= c } else { val(pt) <= c };
        let mut out: Vec<(f64, f64)> = Vec::with_capacity(ring.len() + 4);
        for i in 0..ring.len() {
            let a = ring[i];
            let b = ring[(i + 1) % ring.len()];
            let (ia, ib) = (inside(a), inside(b));
            let cross = |a: (f64, f64), b: (f64, f64)| -> (f64, f64) {
                let t = (c - val(a)) / (val(b) - val(a));
                (a.0 + t * (b.0 - a.0), a.1 + t * (b.1 - a.1))
            };
            if ia {
                out.push(a);
                if !ib {
                    out.push(cross(a, b));
                }
            } else if ib {
                out.push(cross(a, b));
            }
        }
        ring = out;
    }
    let mut a2 = 0.0;
    for i in 0..ring.len() {
        let (x0, y0) = ring[i];
        let (x1, y1) = ring[(i + 1) % ring.len()];
        a2 += x0 * y1 - x1 * y0;
    }
    (a2 / 2.0).abs()
}

/// Is a point strictly inside a polygon? Even-odd ray cast; points exactly on
/// the boundary return `false`. Integer-exact for the on-edge test.
#[must_use]
pub fn point_in_poly(store: &GeometryStore, p: PolyId, px: i32, py: i32) -> bool {
    let (s, e) = store.poly_range(p);
    let n = e - s;
    let (px, py) = (i64::from(px), i64::from(py));
    let mut inside = false;
    for i in 0..n {
        let (x0, y0) = store.poly_vertex(s, i);
        let (x1, y1) = store.poly_vertex(s, (i + 1) % n);
        let (x0, y0, x1, y1) = (i64::from(x0), i64::from(y0), i64::from(x1), i64::from(y1));
        if orient(x0, y0, x1, y1, px, py) == 0 && on_seg(x0, y0, x1, y1, px, py) {
            return false;
        }
        if (y0 > py) != (y1 > py) {
            let lhs = i128::from(x1 - x0) * i128::from(py - y0);
            let rhs = i128::from(px - x0) * i128::from(y1 - y0);
            let cross = if y1 > y0 { lhs > rhs } else { lhs < rhs };
            if cross {
                inside = !inside;
            }
        }
    }
    inside
}

/// Does the polygon's boundary properly cross itself (bow-tie / figure-8)?
///
/// Only PROPER crossings of non-adjacent edges count: collinear-overlap slits
/// (the GDS keyhole representation of holes) are legal and must not flag. A
/// sweep along the wider axis keeps the look-ahead window local instead of the
/// all-pairs O(n²) that melts on many-thousand-vertex comb polygons.
#[must_use]
pub fn poly_self_intersects(store: &GeometryStore, p: PolyId) -> bool {
    let (s, e) = store.poly_range(p);
    let n = e - s;
    if n < 4 {
        return false;
    }
    let edge = |i: usize| -> Edge {
        let (x0, y0) = store.poly_vertex(s, i);
        let (x1, y1) = store.poly_vertex(s, (i + 1) % n);
        Edge {
            x0,
            y0,
            x1,
            y1,
            poly: p.0,
        }
    };
    let bb = store.poly_bbox[p.index()];
    let sweep_x = bb.width_i64() >= bb.height_i64();
    let lo = |ed: &Edge| {
        if sweep_x {
            ed.x0.min(ed.x1)
        } else {
            ed.y0.min(ed.y1)
        }
    };
    let hi = |ed: &Edge| {
        if sweep_x {
            ed.x0.max(ed.x1)
        } else {
            ed.y0.max(ed.y1)
        }
    };
    let mut order: Vec<u32> = (0..n as u32).collect();
    order.sort_unstable_by_key(|&i| lo(&edge(i as usize)));
    for w in 0..n {
        let i = order[w] as usize;
        let a = edge(i);
        if a.len2_i128() == 0 {
            continue;
        }
        let a_hi = hi(&a);
        for &jj in &order[w + 1..] {
            let j = jj as usize;
            let b = edge(j);
            if lo(&b) > a_hi {
                break;
            }
            // Adjacent edges share a vertex; skip (incl. the ring wrap).
            if j == (i + 1) % n || i == (j + 1) % n {
                continue;
            }
            if b.len2_i128() == 0 {
                continue;
            }
            let (bx0, by0, bx1, by1) = (
                i64::from(b.x0),
                i64::from(b.y0),
                i64::from(b.x1),
                i64::from(b.y1),
            );
            let (ax0, ay0, ax1, ay1) = (
                i64::from(a.x0),
                i64::from(a.y0),
                i64::from(a.x1),
                i64::from(a.y1),
            );
            let d1 = orient(bx0, by0, bx1, by1, ax0, ay0);
            let d2 = orient(bx0, by0, bx1, by1, ax1, ay1);
            let d3 = orient(ax0, ay0, ax1, ay1, bx0, by0);
            let d4 = orient(ax0, ay0, ax1, ay1, bx1, by1);
            if ((d1 > 0) != (d2 > 0))
                && ((d3 > 0) != (d4 > 0))
                && d1 != 0
                && d2 != 0
                && d3 != 0
                && d4 != 0
            {
                return true;
            }
        }
    }
    false
}

/// Integer sqrt floor, for reporting measured distances from squared values.
#[must_use]
pub fn isqrt(n: i64) -> i64 {
    if n < 0 {
        return 0;
    }
    let mut x = (n as f64).sqrt() as i64;
    while i128::from(x + 1) * i128::from(x + 1) <= i128::from(n) {
        x += 1;
    }
    while i128::from(x) * i128::from(x) > i128::from(n) {
        x -= 1;
    }
    x
}
