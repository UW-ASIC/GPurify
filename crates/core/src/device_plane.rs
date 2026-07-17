//! Canonical device-resident geometry plane.
//!
//! [`DevicePlane`] decomposes every polygon in a [`GeometryStore`] into
//! rectangles (via [`decompose_all`]) and holds the result as flat SoA columns,
//! mirroring the layout GPU kernels consume. Built once, shared read-only by all
//! engines for the lifetime of a verification session.
//!
//! The "columns" are plain `Vec<T>` on the CPU. With GPU support they become
//! device buffers uploaded once at build time.

use crate::geometry::rects::{decompose_all, RectSet};
use crate::geometry::{GeometryStore, PolyId};

/// Immutable geometry plane: rectangles + per-poly bboxes, ready for GPU upload.
///
/// Contract: built once from a [`GeometryStore`], never mutated. All engines
/// share a `&DevicePlane` for the duration of the verification session.
pub struct DevicePlane {
    /// Decomposed rectangles (SoA).
    pub rects: RectSet,
    /// Polygon bounding boxes (SoA, parallel to the store's poly arrays).
    pub bbox_xmin: Vec<i32>,
    pub bbox_ymin: Vec<i32>,
    pub bbox_xmax: Vec<i32>,
    pub bbox_ymax: Vec<i32>,
    /// Which polygons were decomposed (in order).
    pub polys: Vec<PolyId>,
}

impl DevicePlane {
    /// Build from a geometry store, decomposing all polygons into rectangles.
    ///
    /// Non-rectilinear polygons keep their bbox entry but produce zero rects.
    // ponytail: skips non-rectilinear instead of erroring; mixed geometry
    // layouts exist. Upgrade to triangulation if non-rect coverage matters.
    #[must_use]
    pub fn build(store: &GeometryStore) -> DevicePlane {
        let all_polys: Vec<PolyId> = (0..store.poly_count() as u32).map(PolyId).collect();

        // Keep only the rectilinear polygons (the ones decompose_all accepts).
        let mut rect_polys = Vec::new();
        for &p in &all_polys {
            let (s, e) = store.poly_range(p);
            let n = e - s;
            let rectilinear = n >= 4
                && (0..n).all(|i| {
                    let (x0, y0) = store.poly_vertex(s, i);
                    let (x1, y1) = store.poly_vertex(s, (i + 1) % n);
                    x0 == x1 || y0 == y1
                });
            if rectilinear {
                rect_polys.push(p);
            }
        }

        let rects = decompose_all(store, &rect_polys).unwrap_or_default();

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

    #[test]
    fn build_empty_store() {
        let dp = DevicePlane::build(&GeometryStore::new());
        assert_eq!(dp.rects.rect_count(), 0);
        assert_eq!(dp.bbox_xmin.len(), 0);
    }

    #[test]
    fn build_single_rect() {
        let mut s = GeometryStore::new();
        s.add_rect(0, 10, 20, 100, 200);
        let dp = DevicePlane::build(&s);
        assert_eq!(dp.rects.rect_count(), 1);
        assert_eq!(
            (dp.bbox_xmin[0], dp.bbox_ymin[0], dp.bbox_xmax[0], dp.bbox_ymax[0]),
            (10, 20, 110, 220)
        );
        assert_eq!(
            (
                dp.rects.rect_x0[0],
                dp.rects.rect_y0[0],
                dp.rects.rect_x1[0],
                dp.rects.rect_y1[0],
                dp.rects.rect_poly[0],
            ),
            (10, 20, 110, 220, 0)
        );
    }

    #[test]
    fn build_mixed_geometry_skips_non_rectilinear() {
        let mut s = GeometryStore::new();
        s.add_rect(0, 0, 0, 100, 100);
        s.add_polygon(0, &[(0, 0), (100, 0), (50, 100)]); // triangle, skipped
        s.add_polygon(
            0,
            &[(0, 0), (200, 0), (200, 100), (100, 100), (100, 200), (0, 200)],
        );
        let dp = DevicePlane::build(&s);
        assert_eq!(dp.bbox_xmin.len(), 3); // all polys get a bbox
        assert_eq!(dp.polys.len(), 2); // only rectilinear decomposed
        assert!(dp.rects.rect_count() >= 3);
        assert_eq!(dp.rects.poly_rect_start.len(), 2);
        let total: u32 = dp.rects.poly_rect_len.iter().sum();
        assert_eq!(total as usize, dp.rects.rect_count());
    }

    #[test]
    fn decomposed_rects_sum_to_polygon_area() {
        let mut s = GeometryStore::new();
        let p = s.add_polygon(
            0,
            &[(0, 0), (500, 0), (500, 200), (200, 200), (200, 500), (0, 500)],
        );
        let dp = DevicePlane::build(&s);
        let total_area: i64 = (0..dp.rects.rect_count()).map(|i| dp.rects.rect(i).area()).sum();
        assert_eq!(total_area, s.area(p));
        let bb = s.poly_bbox[p.index()];
        assert_eq!(
            (dp.bbox_xmin[0], dp.bbox_ymin[0], dp.bbox_xmax[0], dp.bbox_ymax[0]),
            (bb.xmin, bb.ymin, bb.xmax, bb.ymax)
        );
    }
}
