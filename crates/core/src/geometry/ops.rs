//! Free-function geometric primitives over the SoA store: segment distance,
//! intersection, window clipping, point-in-polygon, self-intersection, isqrt.

use super::edge::Edge;
use super::ids::PolyId;
use super::store::GeometryStore;

/// Squared Euclidean distance between two segments' closest points (any angle:
/// for non-crossing segments the minimum is always at an endpoint).
/// Returns 0 if they touch/cross. This is the primitive both spacing and corner checks use.
pub fn seg_seg_dist2(a: &Edge, b: &Edge) -> i64 {
    // If bounding boxes overlap and the segments intersect, distance is 0.
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
    // projection falls on the segment: d² = |w|² − c1²/c2, exact in i128
    // (f64 here loses ulps on diagonal edges at large coordinates)
    let Some(num) = (wx * wx + wy * wy)
        .checked_mul(c2)
        .and_then(|lhs| c1.checked_mul(c1).and_then(|rhs| lhs.checked_sub(rhs)))
    else {
        // The legacy scalar-distance API cannot represent this intermediate.
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

pub fn segments_intersect(a: &Edge, b: &Edge) -> bool {
    let (ax, ay, bx, by) = (a.x0 as i64, a.y0 as i64, a.x1 as i64, a.y1 as i64);
    let (cx, cy, dx, dy) = (b.x0 as i64, b.y0 as i64, b.x1 as i64, b.y1 as i64);
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

/// Area of a polygon clipped to an axis-aligned window (Sutherland–Hodgman + shoelace).
/// Exact for rectilinear geometry; f64 for the fractional intersection points diagonal
/// edges can produce. This is what density checks need — a bbox-based coverage estimate
/// wildly overstates non-convex shapes like combs.
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

/// Wide-coordinate density clip. Window edges may extend past the i32 layout
/// domain even though every stored vertex is representable (for example a
/// 10-DBU window anchored five DBU below i32::MAX).
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
    // clip against each half-plane: keep(pt) true => inside
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

/// Is a point strictly inside a polygon? Even-odd ray cast; points exactly on the boundary
/// return false. Integer-exact for the on-edge test, half-open on crossing counts.
pub fn point_in_poly(store: &GeometryStore, p: PolyId, px: i32, py: i32) -> bool {
    let (s, e) = store.poly_range(p);
    let n = e - s;
    let (px, py) = (px as i64, py as i64);
    let mut inside = false;
    for i in 0..n {
        let (x0, y0) = store.poly_vertex(s, i);
        let (x1, y1) = store.poly_vertex(s, (i + 1) % n);
        let (x0, y0, x1, y1) = (x0 as i64, y0 as i64, x1 as i64, y1 as i64);
        // on-boundary => not strictly inside
        if orient(x0, y0, x1, y1, px, py) == 0 && on_seg(x0, y0, x1, y1, px, py) {
            return false;
        }
        if (y0 > py) != (y1 > py) {
            // exact crossing test: px < x-intersection of the edge with the horizontal ray
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
/// Only PROPER crossings of non-adjacent edges count: collinear-overlap slits
/// (the GDS keyhole representation of holes) are legal and must not flag.
/// O(n²) over the ring — polygons are small (rects dominate); revisit with a
/// sweep if fractured all-angle data shows up.
pub fn poly_self_intersects(store: &GeometryStore, p: PolyId) -> bool {
    let (s, e) = store.poly_range(p);
    let n = e - s;
    if n < 4 {
        return false;
    } // triangle can't self-cross
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
    // Sweep along the axis with more bbox-min spread: crossing edges must have
    // overlapping bboxes, so the look-ahead window stays local instead of the
    // all-pairs O(n²) that melts on many-thousand-vertex comb polygons.
    let bb = store.poly_bbox[p.0 as usize];
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
        for &jj in order[w + 1..].iter() {
            let j = jj as usize;
            let b = edge(j);
            if lo(&b) > a_hi {
                break;
            } // sweep window closed
              // adjacent edges share a vertex; skip (incl. the ring wrap)
            if j == (i + 1) % n || i == (j + 1) % n {
                continue;
            }
            if b.len2_i128() == 0 {
                continue;
            }
            let d1 = orient(
                b.x0 as i64,
                b.y0 as i64,
                b.x1 as i64,
                b.y1 as i64,
                a.x0 as i64,
                a.y0 as i64,
            );
            let d2 = orient(
                b.x0 as i64,
                b.y0 as i64,
                b.x1 as i64,
                b.y1 as i64,
                a.x1 as i64,
                a.y1 as i64,
            );
            let d3 = orient(
                a.x0 as i64,
                a.y0 as i64,
                a.x1 as i64,
                a.y1 as i64,
                b.x0 as i64,
                b.y0 as i64,
            );
            let d4 = orient(
                a.x0 as i64,
                a.y0 as i64,
                a.x1 as i64,
                a.y1 as i64,
                b.x1 as i64,
                b.y1 as i64,
            );
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
