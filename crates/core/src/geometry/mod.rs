//! Data-oriented geometry core.
//!
//! Everything the checkers touch lives here in struct-of-arrays (SoA) form.
//! There are no per-polygon heap objects and no pointers between shapes —
//! references are `u32` indices into flat arrays. This is what makes the store
//! (a) cache-friendly for the CPU scanline passes and (b) trivially uploadable
//! to a GPU as flat buffers.
//!
//! Coordinates are `i32` database units (nm in the conformance suite).
//!
//! Layout, per the DOD skill:
//!   * `verts_x` / `verts_y`  — parallel arrays of every vertex (hot).
//!   * `poly_layer`           — layer id per polygon (warm; used to filter).
//!   * `poly_vert_start/len`  — index range into the vertex arrays (the handle).
//!
//! A polygon is an index range, not an object. Iterating all met1 edges never
//! loads a byte of any other layer's coordinates.

pub mod bbox;
pub mod edge;
pub mod ids;
pub mod ops;
pub mod rects;
pub mod store;

pub use bbox::Bbox;
pub use edge::{build_edges, Edge};
pub use ids::{LayerId, PolyId};
pub use ops::{
    clipped_area, clipped_area_i64, isqrt, point_in_poly, poly_self_intersects, seg_seg_dist2,
    segments_intersect,
};
pub use rects::{
    decompose_all, decompose_rectilinear, rect_overlap_area_pos, rect_touch, DecomposeError, Rect,
    RectSet,
};
pub use store::GeometryStore;

/// Sweep-line candidate pair generator: enumerate polygon pairs whose bboxes
/// come within `min` of each other. O(P log P + K).
///
/// `pb = None` => unordered pairs within `pa`. `pb = Some(..)` => cross pairs
/// only (one endpoint from each set), returned as `(a_side, b_side)`.
#[must_use]
pub fn candidate_pairs(
    store: &GeometryStore,
    pa: &[PolyId],
    pb: Option<&[PolyId]>,
    min: i32,
) -> Vec<(PolyId, PolyId)> {
    let mut xlo = i32::MAX;
    let mut xhi = i32::MIN;
    let mut ylo = i32::MAX;
    let mut yhi = i32::MIN;
    for &p in pa.iter().chain(pb.unwrap_or(&[])) {
        let b = store.poly_bbox[p.index()];
        xlo = xlo.min(b.xmin);
        xhi = xhi.max(b.xmin);
        ylo = ylo.min(b.ymin);
        yhi = yhi.max(b.ymin);
    }
    let sweep_x = i64::from(xhi) - i64::from(xlo) >= i64::from(yhi) - i64::from(ylo);
    let min = i64::from(min);
    let mut items: Vec<(i64, i64, PolyId, bool)> =
        Vec::with_capacity(pa.len() + pb.map_or(0, <[PolyId]>::len));
    let key = |b: &Bbox| {
        let (lo, hi) = if sweep_x {
            (b.xmin, b.xmax)
        } else {
            (b.ymin, b.ymax)
        };
        (i64::from(lo), i64::from(hi))
    };
    for &p in pa {
        let (lo, hi) = key(&store.poly_bbox[p.index()]);
        items.push((lo, hi, p, false));
    }
    for &p in pb.unwrap_or(&[]) {
        let (lo, hi) = key(&store.poly_bbox[p.index()]);
        items.push((lo, hi, p, true));
    }
    items.sort_unstable_by_key(|it| it.0);
    let mut out = Vec::new();
    for i in 0..items.len() {
        let (_, hi_i, pi, bi) = items[i];
        for &(_, _, pj, bj) in items[i + 1..].iter().take_while(|it| it.0 <= hi_i + min) {
            if pb.is_some() && bi == bj {
                continue;
            }
            let ba = store.poly_bbox[pi.index()];
            let bb = store.poly_bbox[pj.index()];
            let other_near = if sweep_x {
                i64::from(ba.ymin) - min <= i64::from(bb.ymax)
                    && i64::from(bb.ymin) - min <= i64::from(ba.ymax)
            } else {
                i64::from(ba.xmin) - min <= i64::from(bb.xmax)
                    && i64::from(bb.xmin) - min <= i64::from(ba.xmax)
            };
            if other_near {
                if bi {
                    out.push((pj, pi));
                } else {
                    out.push((pi, pj));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bbox_set_ops() {
        let a = Bbox { xmin: 0, ymin: 0, xmax: 10, ymax: 10 };
        let b = Bbox { xmin: 5, ymin: 5, xmax: 20, ymax: 20 };
        assert_eq!(a.union(&b), Bbox { xmin: 0, ymin: 0, xmax: 20, ymax: 20 });
        assert_eq!(
            a.intersection(&b),
            Some(Bbox { xmin: 5, ymin: 5, xmax: 10, ymax: 10 })
        );
        let far = Bbox { xmin: 100, ymin: 100, xmax: 110, ymax: 110 };
        assert_eq!(a.intersection(&far), None);
        assert_eq!(
            Bbox::from_points([(3, 4), (-1, 7)]),
            Bbox { xmin: -1, ymin: 4, xmax: 3, ymax: 7 }
        );
        assert_eq!(Bbox::from_points(std::iter::empty()), Bbox::empty());
    }

    #[test]
    fn iterators_match_manual_walk() {
        let mut store = GeometryStore::new();
        let p = store.add_rect(0, 0, 0, 10, 5);
        assert_eq!(
            store.vertices(p).collect::<Vec<_>>(),
            vec![(0, 0), (10, 0), (10, 5), (0, 5)]
        );
        let edges: Vec<Edge> = store.edges_of(p).collect();
        assert_eq!(edges.len(), 4);
        assert_eq!((edges[3].x1, edges[3].y1), (0, 0)); // ring closes
        assert!(edges.iter().all(|e| e.poly == p.0));
    }

    #[test]
    fn poly_as_exact_is_fail_closed() {
        let mut store = GeometryStore::new();
        let good = store.add_rect(0, 0, 0, 10, 5);
        assert!(store.poly_as_exact(good).is_ok());
        // bow-tie must be a typed error, never an empty/clean result
        let bad = store.add_polygon(0, &[(0, 0), (10, 10), (10, 0), (0, 10)]);
        assert!(store.poly_as_exact(bad).is_err());
        let degenerate = store.add_polygon(0, &[(0, 0), (1, 1)]);
        assert!(store.poly_as_exact(degenerate).is_err());
    }

    #[test]
    fn candidate_pairs_prunes_far_polys() {
        let mut s = GeometryStore::new();
        let a = s.add_rect(0, 0, 0, 10, 10);
        let b = s.add_rect(0, 15, 0, 10, 10); // 5 away from a
        let c = s.add_rect(0, 10_000, 0, 10, 10); // far
        let near = candidate_pairs(&s, &[a, b, c], None, 6);
        assert!(near.contains(&(a, b)) || near.contains(&(b, a)));
        assert!(!near.iter().any(|&(x, y)| x == c || y == c));
    }
}
