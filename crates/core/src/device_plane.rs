//! Canonical device-resident geometry plane.
//!
//! [`DevicePlane`] decomposes every polygon in a [`GeometryStore`] into rectangles
//! (via [`decompose_all`]) and holds the result as flat SoA columns, mirroring the
//! layout GPU session kernels will consume. Built once, shared read-only by all
//! engines for the lifetime of the session.
//!
//! The "columns" are plain `Vec<T>` on CPU. When GPU support lands, these become
//! device buffers uploaded once at build time.

use crate::geometry::rects::{decompose_all, RectSet};
use crate::geometry::{GeometryStore, PolyId};

/// Immutable geometry plane: rectangles + per-poly bboxes, ready for GPU upload.
///
/// Contract: built once from a `GeometryStore`, never mutated. All engines share
/// a `&DevicePlane` for the duration of the verification session.
pub struct DevicePlane {
    /// Decomposed rectangles (SoA).
    pub rects: RectSet,
    /// Polygon bounding boxes (SoA, parallel to store's poly arrays).
    pub bbox_xmin: Vec<i32>,
    pub bbox_ymin: Vec<i32>,
    pub bbox_xmax: Vec<i32>,
    pub bbox_ymax: Vec<i32>,
    /// Which polygons were decomposed (in order).
    pub polys: Vec<PolyId>,
}

impl DevicePlane {
    /// Build from a geometry store, decomposing all polygons into rectangles.
    /// Non-rectilinear polygons are silently skipped (they keep their bbox entries
    /// but produce zero rects).
    // ponytail: skips non-rectilinear instead of erroring; mixed geometry layouts
    // exist. Upgrade to triangulation if non-rect coverage matters.
    pub fn build(store: &GeometryStore) -> DevicePlane {
        let all_polys: Vec<PolyId> = (0..store.poly_count() as u32).map(PolyId).collect();

        // Split into rectilinear / non-rectilinear and decompose the good ones.
        let mut rect_polys = Vec::new();
        for &p in &all_polys {
            let (s, e) = store.poly_range(p);
            let n = e - s;
            let mut ok = n >= 4;
            if ok {
                for i in 0..n {
                    let (x0, y0) = store.poly_vertex(s, i);
                    let (x1, y1) = store.poly_vertex(s, (i + 1) % n);
                    if x0 != x1 && y0 != y1 {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                rect_polys.push(p);
            }
        }

        let rects = decompose_all(store, &rect_polys).unwrap_or_else(|_| RectSet {
            rect_x0: Vec::new(),
            rect_y0: Vec::new(),
            rect_x1: Vec::new(),
            rect_y1: Vec::new(),
            rect_poly: Vec::new(),
            poly_rect_start: Vec::new(),
            poly_rect_len: Vec::new(),
        });

        let n = store.poly_count();
        let mut bbox_xmin = Vec::with_capacity(n);
        let mut bbox_ymin = Vec::with_capacity(n);
        let mut bbox_xmax = Vec::with_capacity(n);
        let mut bbox_ymax = Vec::with_capacity(n);
        for bb in &store.poly_bbox {
            bbox_xmin.push(bb.xmin);
            bbox_ymin.push(bb.ymin);
            bbox_xmax.push(bb.xmax);
            bbox_ymax.push(bb.ymax);
        }

        DevicePlane {
            rects,
            bbox_xmin,
            bbox_ymin,
            bbox_xmax,
            bbox_ymax,
            polys: rect_polys,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::GeometryStore;

    #[test]
    fn build_empty_store() {
        let s = GeometryStore::new();
        let dp = DevicePlane::build(&s);
        assert_eq!(dp.rects.rect_count(), 0);
        assert_eq!(dp.bbox_xmin.len(), 0);
    }

    #[test]
    fn build_single_rect() {
        let mut s = GeometryStore::new();
        s.add_rect(0, 10, 20, 100, 200);
        let dp = DevicePlane::build(&s);
        assert_eq!(dp.rects.rect_count(), 1);
        assert_eq!(dp.bbox_xmin.len(), 1);
        assert_eq!(dp.bbox_xmin[0], 10);
        assert_eq!(dp.bbox_ymin[0], 20);
        assert_eq!(dp.bbox_xmax[0], 110);
        assert_eq!(dp.bbox_ymax[0], 220);
        // Rect matches
        assert_eq!(dp.rects.rect_x0[0], 10);
        assert_eq!(dp.rects.rect_y0[0], 20);
        assert_eq!(dp.rects.rect_x1[0], 110);
        assert_eq!(dp.rects.rect_y1[0], 220);
        assert_eq!(dp.rects.rect_poly[0], 0);
    }

    #[test]
    fn build_mixed_geometry() {
        let mut s = GeometryStore::new();
        // Rect (rectilinear)
        s.add_rect(0, 0, 0, 100, 100);
        // Triangle (non-rectilinear, silently skipped)
        s.add_polygon(0, &[(0, 0), (100, 0), (50, 100)]);
        // L-shape (rectilinear)
        s.add_polygon(
            0,
            &[
                (0, 0),
                (200, 0),
                (200, 100),
                (100, 100),
                (100, 200),
                (0, 200),
            ],
        );
        let dp = DevicePlane::build(&s);
        // 3 polys total -> 3 bbox entries
        assert_eq!(dp.bbox_xmin.len(), 3);
        // Only 2 rectilinear polys decomposed
        assert_eq!(dp.polys.len(), 2);
        // Rect (1 rect) + L-shape (2+ rects)
        assert!(dp.rects.rect_count() >= 3);
        // Per-poly ranges consistent
        assert_eq!(dp.rects.poly_rect_start.len(), 2);
        assert_eq!(dp.rects.poly_rect_len.len(), 2);
        let total_from_ranges: u32 = dp.rects.poly_rect_len.iter().sum();
        assert_eq!(total_from_ranges as usize, dp.rects.rect_count());
    }

    #[test]
    fn column_lengths_consistent() {
        let mut s = GeometryStore::new();
        s.add_rect(0, 0, 0, 50, 50);
        s.add_polygon(
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
        let dp = DevicePlane::build(&s);
        let n = dp.rects.rect_count();
        assert_eq!(dp.rects.rect_x0.len(), n);
        assert_eq!(dp.rects.rect_y0.len(), n);
        assert_eq!(dp.rects.rect_x1.len(), n);
        assert_eq!(dp.rects.rect_y1.len(), n);
        assert_eq!(dp.rects.rect_poly.len(), n);
        // bbox columns all same length
        let nb = dp.bbox_xmin.len();
        assert_eq!(dp.bbox_ymin.len(), nb);
        assert_eq!(dp.bbox_xmax.len(), nb);
        assert_eq!(dp.bbox_ymax.len(), nb);
        assert_eq!(nb, s.poly_count());
    }

    #[test]
    fn readback_matches_host() {
        let mut s = GeometryStore::new();
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
        let dp = DevicePlane::build(&s);
        // Verify decomposed rects sum to polygon area
        let total_area: i64 = (0..dp.rects.rect_count())
            .map(|i| dp.rects.rect(i).area())
            .sum();
        assert_eq!(total_area, s.area(p));
        // Verify bbox matches store
        let bb = s.poly_bbox[p.0 as usize];
        assert_eq!(dp.bbox_xmin[0], bb.xmin);
        assert_eq!(dp.bbox_ymin[0], bb.ymin);
        assert_eq!(dp.bbox_xmax[0], bb.xmax);
        assert_eq!(dp.bbox_ymax[0], bb.ymax);
    }
}
