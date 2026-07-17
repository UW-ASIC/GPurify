//! Rectilinear polygon → axis-aligned rectangle decomposition (vertical slab).
//!
//! Every rectilinear polygon is split into non-overlapping rectangles whose
//! union exactly equals the polygon. Non-rectilinear input (any edge that is
//! neither horizontal nor vertical) returns [`DecomposeError`].

use super::ids::PolyId;
use super::store::GeometryStore;

/// Why a rectilinear decomposition failed. (Was a `String`; a typed error lets
/// callers match on the cause and keeps messages consistent.)
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecomposeError {
    #[error("polygon {poly} has {verts} vertices, need >= 4 for rectilinear decomposition")]
    TooFewVertices { poly: u32, verts: usize },
    #[error("polygon {poly}: non-rectilinear edge ({x0},{y0}) -> ({x1},{y1})")]
    NonRectilinear {
        poly: u32,
        x0: i32,
        y0: i32,
        x1: i32,
        y1: i32,
    },
    #[error("polygon {poly}: odd crossing count {count} in slab [{x0}, {x1}] (self-intersecting?)")]
    OddCrossings {
        poly: u32,
        count: usize,
        x0: i32,
        x1: i32,
    },
}

/// An axis-aligned rectangle in database units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x0: i32,
    pub y0: i32,
    pub x1: i32,
    pub y1: i32,
}

impl Rect {
    #[must_use]
    #[inline]
    pub fn area(&self) -> i64 {
        i64::from(self.x1 - self.x0) * i64::from(self.y1 - self.y0)
    }
}

/// SoA rectangle set produced by [`decompose_all`]. Per-poly ranges let callers
/// iterate one polygon's rects without scanning the whole array.
#[derive(Clone, Debug, Default)]
pub struct RectSet {
    pub rect_x0: Vec<i32>,
    pub rect_y0: Vec<i32>,
    pub rect_x1: Vec<i32>,
    pub rect_y1: Vec<i32>,
    /// Which polygon each rect came from.
    pub rect_poly: Vec<u32>,
    /// Start index into the rect arrays for each input poly (parallel to `polys`).
    pub poly_rect_start: Vec<u32>,
    /// Number of rects for each input poly.
    pub poly_rect_len: Vec<u32>,
}

impl RectSet {
    #[must_use]
    #[inline]
    pub fn rect_count(&self) -> usize {
        self.rect_x0.len()
    }

    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.rect_x0.is_empty()
    }

    #[must_use]
    pub fn rect(&self, i: usize) -> Rect {
        Rect {
            x0: self.rect_x0[i],
            y0: self.rect_y0[i],
            x1: self.rect_x1[i],
            y1: self.rect_y1[i],
        }
    }
}

/// Decompose a single rectilinear polygon into axis-aligned rectangles via
/// vertical slab decomposition.
///
/// # Errors
/// [`DecomposeError`] if the polygon has fewer than four vertices, has a
/// non-rectilinear edge, or produces an odd slab crossing count.
pub fn decompose_rectilinear(
    store: &GeometryStore,
    poly: PolyId,
) -> Result<Vec<Rect>, DecomposeError> {
    let (s, e) = store.poly_range(poly);
    let n = e - s;
    if n < 4 {
        return Err(DecomposeError::TooFewVertices { poly: poly.0, verts: n });
    }

    // Collect vertices; validate all edges are axis-aligned.
    let mut verts: Vec<(i32, i32)> = Vec::with_capacity(n);
    for i in 0..n {
        let (x0, y0) = store.poly_vertex(s, i);
        let (x1, y1) = store.poly_vertex(s, (i + 1) % n);
        if x0 != x1 && y0 != y1 {
            return Err(DecomposeError::NonRectilinear {
                poly: poly.0,
                x0,
                y0,
                x1,
                y1,
            });
        }
        verts.push((x0, y0));
    }

    // Vertical slab decomposition: unique X coords are slab boundaries; for each
    // slab, horizontal edges spanning it give inside intervals (even-odd rule).
    let mut xs: Vec<i32> = verts.iter().map(|v| v.0).collect();
    xs.sort_unstable();
    xs.dedup();
    if xs.len() < 2 {
        return Ok(Vec::new());
    }

    // ponytail: O(V) scan per slab; total O(V * S). Fine for EDA polygons
    // (typically < 100 vertices). Sweep-line if a profile ever demands it.
    let mut rects = Vec::new();
    let mut crossings = Vec::new();
    for w in 0..xs.len() - 1 {
        let slab_x0 = xs[w];
        let slab_x1 = xs[w + 1];

        crossings.clear();
        for i in 0..n {
            let (x0, y0) = verts[i];
            let (x1, y1) = verts[(i + 1) % n];
            if y0 != y1 {
                continue; // vertical edge, skip
            }
            let ex_lo = x0.min(x1);
            let ex_hi = x0.max(x1);
            if ex_lo <= slab_x0 && ex_hi >= slab_x1 {
                crossings.push(y0);
            }
        }
        crossings.sort_unstable();
        if crossings.len() % 2 != 0 {
            return Err(DecomposeError::OddCrossings {
                poly: poly.0,
                count: crossings.len(),
                x0: slab_x0,
                x1: slab_x1,
            });
        }
        for pair in crossings.chunks_exact(2) {
            let (y_lo, y_hi) = (pair[0], pair[1]);
            if y_lo < y_hi {
                rects.push(Rect {
                    x0: slab_x0,
                    y0: y_lo,
                    x1: slab_x1,
                    y1: y_hi,
                });
            }
        }
    }

    Ok(rects)
}

/// Decompose multiple polygons into a single SoA [`RectSet`].
///
/// # Errors
/// Propagates the first [`DecomposeError`] from any input polygon.
pub fn decompose_all(store: &GeometryStore, polys: &[PolyId]) -> Result<RectSet, DecomposeError> {
    let mut set = RectSet {
        poly_rect_start: Vec::with_capacity(polys.len()),
        poly_rect_len: Vec::with_capacity(polys.len()),
        ..RectSet::default()
    };
    for &p in polys {
        let start = u32::try_from(set.rect_x0.len()).unwrap_or(u32::MAX);
        let rects = decompose_rectilinear(store, p)?;
        for r in &rects {
            set.rect_x0.push(r.x0);
            set.rect_y0.push(r.y0);
            set.rect_x1.push(r.x1);
            set.rect_y1.push(r.y1);
            set.rect_poly.push(p.0);
        }
        set.poly_rect_start.push(start);
        set.poly_rect_len
            .push(u32::try_from(rects.len()).unwrap_or(u32::MAX));
    }
    Ok(set)
}

// --- scalar predicates (GPU-portable: pure i32, no float branching) ----------

/// 1 iff two rectangles have positive-area overlap (open-interval intersection).
#[must_use]
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn rect_overlap_area_pos(
    ax0: i32,
    ay0: i32,
    ax1: i32,
    ay1: i32,
    bx0: i32,
    by0: i32,
    bx1: i32,
    by1: i32,
) -> u32 {
    let ix0 = ax0.max(bx0);
    let iy0 = ay0.max(by0);
    let ix1 = ax1.min(bx1);
    let iy1 = ay1.min(by1);
    u32::from(ix1 > ix0 && iy1 > iy0)
}

/// 1 iff two rectangles touch or overlap (closed-interval contact).
#[must_use]
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn rect_touch(
    ax0: i32,
    ay0: i32,
    ax1: i32,
    ay1: i32,
    bx0: i32,
    by0: i32,
    bx1: i32,
    by1: i32,
) -> u32 {
    u32::from(!(ax1 < bx0 || bx1 < ax0 || ay1 < by0 || by1 < ay0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> GeometryStore {
        GeometryStore::new()
    }

    #[test]
    fn decompose_rectangle() {
        let mut s = make_store();
        let p = s.add_rect(0, 0, 0, 100, 200);
        let rects = decompose_rectilinear(&s, p).unwrap();
        assert_eq!(rects.len(), 1);
        assert_eq!(rects[0], Rect { x0: 0, y0: 0, x1: 100, y1: 200 });
        assert_eq!(rects[0].area(), s.area(p));
    }

    #[test]
    fn decompose_l_shape() {
        let mut s = make_store();
        let p = s.add_polygon(
            0,
            &[(0, 0), (500, 0), (500, 200), (200, 200), (200, 500), (0, 500)],
        );
        let rects = decompose_rectilinear(&s, p).unwrap();
        let total_area: i64 = rects.iter().map(Rect::area).sum();
        assert_eq!(total_area, s.area(p));
        let bb = s.poly_bbox[p.index()];
        for r in &rects {
            assert!(r.x0 >= bb.xmin && r.x1 <= bb.xmax);
            assert!(r.y0 >= bb.ymin && r.y1 <= bb.ymax);
        }
        assert_pairwise_disjoint(&rects);
    }

    #[test]
    fn decompose_u_shape() {
        let mut s = make_store();
        let p = s.add_polygon(
            0,
            &[
                (0, 0),
                (400, 0),
                (400, 300),
                (300, 300),
                (300, 100),
                (100, 100),
                (100, 300),
                (0, 300),
            ],
        );
        let rects = decompose_rectilinear(&s, p).unwrap();
        let total_area: i64 = rects.iter().map(Rect::area).sum();
        assert_eq!(total_area, s.area(p));
        assert_pairwise_disjoint(&rects);
    }

    #[test]
    fn decompose_t_shape() {
        let mut s = make_store();
        let p = s.add_polygon(
            0,
            &[
                (150, 0),
                (250, 0),
                (250, 200),
                (400, 200),
                (400, 300),
                (0, 300),
                (0, 200),
                (150, 200),
            ],
        );
        let rects = decompose_rectilinear(&s, p).unwrap();
        let total_area: i64 = rects.iter().map(Rect::area).sum();
        assert_eq!(total_area, s.area(p));
        assert_pairwise_disjoint(&rects);
    }

    #[test]
    fn decompose_non_rectilinear_errors() {
        let mut s = make_store();
        let p = s.add_polygon(0, &[(0, 0), (100, 50), (100, 100), (0, 100)]);
        assert!(matches!(
            decompose_rectilinear(&s, p),
            Err(DecomposeError::NonRectilinear { .. })
        ));
    }

    #[test]
    fn decompose_all_batch() {
        let mut s = make_store();
        let p1 = s.add_rect(0, 0, 0, 100, 200);
        let p2 = s.add_polygon(
            0,
            &[(0, 0), (500, 0), (500, 200), (200, 200), (200, 500), (0, 500)],
        );
        let set = decompose_all(&s, &[p1, p2]).unwrap();
        assert_eq!(set.poly_rect_start.len(), 2);
        assert_eq!(set.poly_rect_len[0], 1);
        let total: i64 = (0..set.rect_count()).map(|i| set.rect(i).area()).sum();
        assert_eq!(total, s.area(p1) + s.area(p2));
    }

    #[test]
    fn overlap_predicates() {
        assert_eq!(rect_overlap_area_pos(0, 0, 10, 10, 20, 0, 30, 10), 0);
        assert_eq!(rect_overlap_area_pos(0, 0, 10, 10, 10, 0, 20, 10), 0); // touch, no area
        assert_eq!(rect_overlap_area_pos(0, 0, 10, 10, 5, 5, 15, 15), 1);
    }

    #[test]
    fn touch_predicates() {
        assert_eq!(rect_touch(0, 0, 10, 10, 20, 0, 30, 10), 0);
        assert_eq!(rect_touch(0, 0, 10, 10, 10, 0, 20, 10), 1); // edge contact
        assert_eq!(rect_touch(0, 0, 10, 10, 10, 10, 20, 20), 1); // corner contact
        assert_eq!(rect_touch(0, 0, 10, 10, 11, 0, 20, 10), 0); // gap
    }

    fn assert_pairwise_disjoint(rects: &[Rect]) {
        for i in 0..rects.len() {
            for j in (i + 1)..rects.len() {
                assert_eq!(
                    rect_overlap_area_pos(
                        rects[i].x0, rects[i].y0, rects[i].x1, rects[i].y1, rects[j].x0,
                        rects[j].y0, rects[j].x1, rects[j].y1,
                    ),
                    0,
                    "rects {:?} and {:?} overlap",
                    rects[i],
                    rects[j]
                );
            }
        }
    }
}
