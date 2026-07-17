//! Rectilinear polygon → axis-aligned rectangle decomposition (vertical slab).
//!
//! Every rectilinear polygon is split into non-overlapping rectangles whose union
//! exactly equals the polygon. Non-rectilinear input (any edge that is neither
//! horizontal nor vertical) returns `Err`.

use crate::geometry::{GeometryStore, PolyId};

/// An axis-aligned rectangle in database units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x0: i32,
    pub y0: i32,
    pub x1: i32,
    pub y1: i32,
}

impl Rect {
    #[inline]
    pub fn area(&self) -> i64 {
        (self.x1 - self.x0) as i64 * (self.y1 - self.y0) as i64
    }
}

/// SoA rectangle set produced by [`decompose_all`]. Per-poly ranges let callers
/// iterate one polygon's rects without scanning the whole array.
#[derive(Clone, Debug)]
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
    pub fn rect_count(&self) -> usize {
        self.rect_x0.len()
    }

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
/// vertical slab decomposition. Returns `Err` if any edge is non-rectilinear.
pub fn decompose_rectilinear(store: &GeometryStore, poly: PolyId) -> Result<Vec<Rect>, String> {
    let (s, e) = store.poly_range(poly);
    let n = e - s;
    if n < 4 {
        return Err(format!(
            "polygon {} has {} vertices, need >= 4 for rectilinear",
            poly.0, n
        ));
    }

    // Collect vertices; validate all edges are axis-aligned.
    let mut verts: Vec<(i32, i32)> = Vec::with_capacity(n);
    for i in 0..n {
        let (x0, y0) = store.poly_vertex(s, i);
        let (x1, y1) = store.poly_vertex(s, (i + 1) % n);
        if x0 != x1 && y0 != y1 {
            return Err(format!(
                "polygon {}: non-rectilinear edge ({},{}) -> ({},{})",
                poly.0, x0, y0, x1, y1
            ));
        }
        verts.push((x0, y0));
    }

    // Vertical slab decomposition:
    // 1. Collect unique X coordinates (slab boundaries).
    // 2. For each slab [x_i, x_{i+1}], find vertical intervals inside the polygon
    //    by scanning horizontal edges that span this slab.
    let mut xs: Vec<i32> = verts.iter().map(|v| v.0).collect();
    xs.sort_unstable();
    xs.dedup();
    if xs.len() < 2 {
        return Ok(Vec::new());
    }

    // ponytail: O(V) scan per slab; total O(V * S) where S = unique X count.
    // Fine for EDA polygons (typically < 100 vertices). Sweep-line if perf matters.
    let mut rects = Vec::new();
    let mut crossings = Vec::new();
    for w in 0..xs.len() - 1 {
        let slab_x0 = xs[w];
        let slab_x1 = xs[w + 1];

        // Collect y-coords of horizontal edges that fully span this slab. Sorted and
        // paired, they give the inside intervals (even-odd rule).
        crossings.clear();
        for i in 0..n {
            let (x0, y0) = verts[i];
            let (x1, y1) = verts[(i + 1) % n];
            if y0 != y1 {
                continue;
            } // vertical edge, skip
            let ex_lo = x0.min(x1);
            let ex_hi = x0.max(x1);
            if ex_lo <= slab_x0 && ex_hi >= slab_x1 {
                crossings.push(y0);
            }
        }
        crossings.sort_unstable();
        if crossings.len() % 2 != 0 {
            return Err(format!(
                "polygon {}: odd crossing count {} in slab [{}, {}]",
                poly.0,
                crossings.len(),
                slab_x0,
                slab_x1
            ));
        }
        for pair in crossings.chunks_exact(2) {
            let y_lo = pair[0];
            let y_hi = pair[1];
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
pub fn decompose_all(store: &GeometryStore, polys: &[PolyId]) -> Result<RectSet, String> {
    let mut set = RectSet {
        rect_x0: Vec::new(),
        rect_y0: Vec::new(),
        rect_x1: Vec::new(),
        rect_y1: Vec::new(),
        rect_poly: Vec::new(),
        poly_rect_start: Vec::with_capacity(polys.len()),
        poly_rect_len: Vec::with_capacity(polys.len()),
    };
    for &p in polys {
        let start = set.rect_x0.len() as u32;
        let rects = decompose_rectilinear(store, p)?;
        for r in &rects {
            set.rect_x0.push(r.x0);
            set.rect_y0.push(r.y0);
            set.rect_x1.push(r.x1);
            set.rect_y1.push(r.y1);
            set.rect_poly.push(p.0);
        }
        set.poly_rect_start.push(start);
        set.poly_rect_len.push(rects.len() as u32);
    }
    Ok(set)
}

// --- scalar predicates (GPU-portable: pure i32, no branching on floats) -------

/// 1 iff two rectangles have positive-area overlap (open-interval intersection).
#[inline]
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
    if ix1 > ix0 && iy1 > iy0 {
        1
    } else {
        0
    }
}

/// 1 iff two rectangles touch or overlap (closed-interval contact).
#[inline]
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
    if ax1 < bx0 || bx1 < ax0 || ay1 < by0 || by1 < ay0 {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::GeometryStore;

    fn make_store() -> GeometryStore {
        GeometryStore::new()
    }

    // --- decomposition tests ---

    #[test]
    fn decompose_rectangle() {
        let mut s = make_store();
        let p = s.add_rect(0, 0, 0, 100, 200);
        let rects = decompose_rectilinear(&s, p).unwrap();
        assert_eq!(rects.len(), 1);
        assert_eq!(
            rects[0],
            Rect {
                x0: 0,
                y0: 0,
                x1: 100,
                y1: 200
            }
        );
        assert_eq!(rects[0].area(), s.area(p));
    }

    #[test]
    fn decompose_l_shape() {
        // L-shape: bottom 500x200, left arm 200x500
        //   (0,0)-(500,0)-(500,200)-(200,200)-(200,500)-(0,500)
        let mut s = make_store();
        let p = s.add_polygon(
            0,
            &[
                (0, 0),
                (500, 0),
                (500, 200),
                (200, 200),
                (200, 500),
                (0, 500),
            ],
        );
        let rects = decompose_rectilinear(&s, p).unwrap();
        let total_area: i64 = rects.iter().map(|r| r.area()).sum();
        assert_eq!(total_area, s.area(p));
        // All rects inside poly bbox
        let bb = s.poly_bbox[p.0 as usize];
        for r in &rects {
            assert!(r.x0 >= bb.xmin && r.x1 <= bb.xmax);
            assert!(r.y0 >= bb.ymin && r.y1 <= bb.ymax);
        }
        // Rects pairwise interior-disjoint
        assert_pairwise_disjoint(&rects);
    }

    #[test]
    fn decompose_u_shape() {
        // U-shape: (0,0)-(400,0)-(400,300)-(300,300)-(300,100)-(100,100)-(100,300)-(0,300)
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
        let total_area: i64 = rects.iter().map(|r| r.area()).sum();
        assert_eq!(total_area, s.area(p));
        assert_pairwise_disjoint(&rects);
    }

    #[test]
    fn decompose_t_shape() {
        // T-shape: top bar 400x100, stem 100x200 centered
        // (150,0)-(250,0)-(250,200)-(400,200)-(400,300)-(0,300)-(0,200)-(150,200)
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
        let total_area: i64 = rects.iter().map(|r| r.area()).sum();
        assert_eq!(total_area, s.area(p));
        assert_pairwise_disjoint(&rects);
    }

    #[test]
    fn decompose_non_rectilinear_errors() {
        let mut s = make_store();
        let p = s.add_polygon(0, &[(0, 0), (100, 50), (100, 100), (0, 100)]);
        assert!(decompose_rectilinear(&s, p).is_err());
    }

    #[test]
    fn decompose_all_batch() {
        let mut s = make_store();
        let p1 = s.add_rect(0, 0, 0, 100, 200);
        let p2 = s.add_polygon(
            0,
            &[
                (0, 0),
                (500, 0),
                (500, 200),
                (200, 200),
                (200, 500),
                (0, 500),
            ],
        );
        let set = decompose_all(&s, &[p1, p2]).unwrap();
        assert_eq!(set.poly_rect_start.len(), 2);
        assert_eq!(set.poly_rect_len.len(), 2);
        // First poly is a rect -> 1 decomposed rect
        assert_eq!(set.poly_rect_len[0], 1);
        // Total area matches
        let total: i64 = (0..set.rect_count()).map(|i| set.rect(i).area()).sum();
        assert_eq!(total, s.area(p1) + s.area(p2));
    }

    // --- predicate tests ---

    #[test]
    fn overlap_area_pos_disjoint() {
        assert_eq!(rect_overlap_area_pos(0, 0, 10, 10, 20, 0, 30, 10), 0);
    }

    #[test]
    fn overlap_area_pos_touching() {
        // Touching at edge: no positive-area overlap
        assert_eq!(rect_overlap_area_pos(0, 0, 10, 10, 10, 0, 20, 10), 0);
    }

    #[test]
    fn overlap_area_pos_overlapping() {
        assert_eq!(rect_overlap_area_pos(0, 0, 10, 10, 5, 5, 15, 15), 1);
    }

    #[test]
    fn touch_disjoint() {
        assert_eq!(rect_touch(0, 0, 10, 10, 20, 0, 30, 10), 0);
    }

    #[test]
    fn touch_edge_contact() {
        assert_eq!(rect_touch(0, 0, 10, 10, 10, 0, 20, 10), 1);
    }

    #[test]
    fn touch_corner_contact() {
        assert_eq!(rect_touch(0, 0, 10, 10, 10, 10, 20, 20), 1);
    }

    #[test]
    fn touch_gap() {
        assert_eq!(rect_touch(0, 0, 10, 10, 11, 0, 20, 10), 0);
    }

    #[test]
    fn predicate_disjoint_l_shapes() {
        // Two L-shapes whose bboxes overlap but the actual rects don't
        // L1: bottom 0..100 x 0..50, left arm 0..50 x 0..100
        // L2: right part 60..100 x 60..100, bottom-right 60..100 x 60..110
        // Bboxes overlap at [60,100]x[60,100] but the Ls don't fill that region.
        // Decompose and check no rect pair has positive overlap.
        let mut s = GeometryStore::new();
        let l1 = s.add_polygon(
            0,
            &[(0, 0), (100, 0), (100, 50), (50, 50), (50, 100), (0, 100)],
        );
        let l2 = s.add_polygon(
            0,
            &[
                (60, 60),
                (110, 60),
                (110, 110),
                (70, 110),
                (70, 70),
                (60, 70),
            ],
        );
        // Their bboxes overlap
        assert!(s.poly_bbox[l1.0 as usize].overlaps(&s.poly_bbox[l2.0 as usize]));
        let r1 = decompose_rectilinear(&s, l1).unwrap();
        let r2 = decompose_rectilinear(&s, l2).unwrap();
        // No rect from l1 has positive-area overlap with any rect from l2
        for a in &r1 {
            for b in &r2 {
                assert_eq!(
                    rect_overlap_area_pos(a.x0, a.y0, a.x1, a.y1, b.x0, b.y0, b.x1, b.y1),
                    0,
                    "unexpected overlap between {:?} and {:?}",
                    a,
                    b
                );
            }
        }
    }

    fn assert_pairwise_disjoint(rects: &[Rect]) {
        for i in 0..rects.len() {
            for j in (i + 1)..rects.len() {
                assert_eq!(
                    rect_overlap_area_pos(
                        rects[i].x0,
                        rects[i].y0,
                        rects[i].x1,
                        rects[i].y1,
                        rects[j].x0,
                        rects[j].y0,
                        rects[j].x1,
                        rects[j].y1,
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
