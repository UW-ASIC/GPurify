//! The one big flat SoA store all checkers read from.

use std::collections::HashMap;

use super::bbox::Bbox;
use super::edge::Edge;
use super::ids::{LayerId, PolyId};

/// The one big flat store. All checkers operate over borrowed slices of this —
/// never over owned per-shape objects. This is the primary public data
/// structure the library exposes: users can build one directly (immediate mode)
/// instead of going through GDS.
#[derive(Default, Clone)]
pub struct GeometryStore {
    // --- vertex arrays (hot) ---
    pub verts_x: Vec<i32>,
    pub verts_y: Vec<i32>,
    // --- per-polygon (warm) ---
    pub poly_layer: Vec<LayerId>,
    pub poly_vert_start: Vec<u32>,
    pub poly_vert_len: Vec<u32>,
    pub poly_bbox: Vec<Bbox>,
    /// Lossless stream annotations carried through checked hierarchy
    /// flattening. Directly constructed polygons receive empty entries.
    pub poly_properties: Vec<Vec<(i16, String)>>,
    /// Root-to-instance path for each polygon. Directly constructed polygons
    /// receive an empty path.
    pub poly_hierarchy_path: Vec<Vec<String>>,
    /// Per-layer polygon buckets (index = `LayerId`, insertion order
    /// preserved). Maintained by [`Self::add_polygon`] so [`Self::polys_on_layer`]
    /// is O(k), not an O(N) full-store scan — it has 30+ call sites in
    /// DRC/LVS/PEX, many in loops.
    layer_index: Vec<Vec<u32>>,
    // --- net label annotations (cold) ---
    /// Maps polygon index to a net name label. Callers assign labels; LVS
    /// extraction checks that polygons sharing a net carry consistent labels
    /// (or none). Empty by default — label-driven extraction is opt-in.
    pub net_labels: HashMap<u32, String>,
    // --- text annotations (cold) ---
    pub text_x: Vec<i32>,
    pub text_y: Vec<i32>,
    pub text_layer: Vec<i32>,
    pub text_datatype: Vec<i32>,
    pub text_string: Vec<String>,
    pub text_properties: Vec<Vec<(i16, String)>>,
    pub text_hierarchy_path: Vec<Vec<String>>,
}

impl GeometryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    #[inline]
    pub fn poly_count(&self) -> usize {
        self.poly_layer.len()
    }

    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.poly_layer.is_empty()
    }

    #[must_use]
    #[inline]
    pub fn text_count(&self) -> usize {
        self.text_string.len()
    }

    pub fn add_text(&mut self, layer: i32, datatype: i32, x: i32, y: i32, text: String) {
        self.add_text_annotated(layer, datatype, x, y, text, Vec::new(), Vec::new());
    }

    pub fn add_text_annotated(
        &mut self,
        layer: i32,
        datatype: i32,
        x: i32,
        y: i32,
        text: String,
        properties: Vec<(i16, String)>,
        hierarchy_path: Vec<String>,
    ) {
        self.text_x.push(x);
        self.text_y.push(y);
        self.text_layer.push(layer);
        self.text_datatype.push(datatype);
        self.text_string.push(text);
        self.text_properties.push(properties);
        self.text_hierarchy_path.push(hierarchy_path);
    }

    /// Append a polygon given as `(x, y)` vertex pairs. Returns its handle. The
    /// vertices are a closed ring given without repeating the first point.
    pub fn add_polygon(&mut self, layer: LayerId, pts: &[(i32, i32)]) -> PolyId {
        self.add_polygon_annotated(layer, pts, Vec::new(), Vec::new())
    }

    pub fn add_polygon_annotated(
        &mut self,
        layer: LayerId,
        pts: &[(i32, i32)],
        properties: Vec<(i16, String)>,
        hierarchy_path: Vec<String>,
    ) -> PolyId {
        let start = u32::try_from(self.verts_x.len()).unwrap_or(u32::MAX);
        let mut bb = Bbox::empty();
        for &(x, y) in pts {
            self.verts_x.push(x);
            self.verts_y.push(y);
            bb.include(x, y);
        }
        let id = PolyId(u32::try_from(self.poly_layer.len()).unwrap_or(u32::MAX));
        self.poly_layer.push(layer);
        self.poly_vert_start.push(start);
        self.poly_vert_len
            .push(u32::try_from(pts.len()).unwrap_or(u32::MAX));
        self.poly_bbox.push(bb);
        self.poly_properties.push(properties);
        self.poly_hierarchy_path.push(hierarchy_path);
        if self.layer_index.len() <= layer as usize {
            self.layer_index.resize_with(layer as usize + 1, Vec::new);
        }
        self.layer_index[layer as usize].push(id.0);
        id
    }

    /// Convenience: append an axis-aligned rectangle.
    pub fn add_rect(&mut self, layer: LayerId, x: i32, y: i32, w: i32, h: i32) -> PolyId {
        self.add_polygon(layer, &[(x, y), (x + w, y), (x + w, y + h), (x, y + h)])
    }

    /// Borrow a polygon's vertex slice range `[start, end)`. Zero-copy.
    #[must_use]
    #[inline]
    pub fn poly_range(&self, p: PolyId) -> (usize, usize) {
        let s = self.poly_vert_start[p.index()] as usize;
        let n = self.poly_vert_len[p.index()] as usize;
        (s, s + n)
    }

    #[must_use]
    #[inline]
    pub fn poly_vertex(&self, base: usize, i: usize) -> (i32, i32) {
        (self.verts_x[base + i], self.verts_y[base + i])
    }

    /// Iterate a polygon's vertices in ring order. Zero-copy view over the SoA
    /// arrays; the ring is given without repeating the first point.
    #[inline]
    pub fn vertices(&self, p: PolyId) -> impl Iterator<Item = (i32, i32)> + '_ {
        let (s, e) = self.poly_range(p);
        (s..e).map(move |i| (self.verts_x[i], self.verts_y[i]))
    }

    /// Iterate a polygon's directed edges, including the ring-closing wrap.
    #[inline]
    pub fn edges_of(&self, p: PolyId) -> impl Iterator<Item = Edge> + '_ {
        let (s, e) = self.poly_range(p);
        let n = e - s;
        (0..n).map(move |i| {
            let (x0, y0) = self.poly_vertex(s, i);
            let (x1, y1) = self.poly_vertex(s, (i + 1) % n);
            Edge {
                x0,
                y0,
                x1,
                y1,
                poly: p.0,
            }
        })
    }

    /// Validated exact polygon for `p`: one fail-closed gate bundling vertex
    /// count, capacity, degeneracy, and self-intersection checks. This is the
    /// supported bridge from the SoA store into [`exact`] semantics — callers
    /// must not re-implement per-site validity checks.
    pub fn poly_as_exact(
        &self,
        p: PolyId,
    ) -> Result<crate::exact::Polygon, crate::exact::ExactGeometryError> {
        let pts: Vec<crate::exact::Point> = self
            .vertices(p)
            .map(|(x, y)| crate::exact::Point { x, y })
            .collect();
        crate::exact::Polygon::from_boundary_walk(pts)
    }

    /// Iterate polygon indices on a given layer. Existence-based filtering:
    /// the caller loops only the polygons it cares about. Served from the
    /// per-layer bucket index — O(k) in the layer's polygon count, insertion
    /// order preserved. Borrowed, allocation-free.
    pub fn polys_on_layer(&self, layer: LayerId) -> impl Iterator<Item = PolyId> + '_ {
        self.layer_index
            .get(layer as usize)
            .into_iter()
            .flat_map(|v| v.iter().copied().map(PolyId))
    }

    /// Signed area × 2 (shoelace). Positive => CCW. `None` on overflow.
    #[must_use]
    pub fn signed_area2_exact(&self, p: PolyId) -> Option<i128> {
        let (s, e) = self.poly_range(p);
        let n = e - s;
        let mut area = 0_i128;
        for i in 0..n {
            let (x0, y0) = self.poly_vertex(s, i);
            let (x1, y1) = self.poly_vertex(s, (i + 1) % n);
            let term = i128::from(x0)
                .checked_mul(i128::from(y1))?
                .checked_sub(i128::from(x1).checked_mul(i128::from(y0))?)?;
            area = area.checked_add(term)?;
        }
        Some(area)
    }

    /// Compatibility measurement for legacy `i64` rule/report APIs. Exact
    /// validation uses [`Self::signed_area2_exact`]; out-of-range values are
    /// clamped only after that validation has emitted a capacity error.
    #[must_use]
    pub fn signed_area2(&self, p: PolyId) -> i64 {
        match self.signed_area2_exact(p) {
            Some(area) => i64::try_from(area).unwrap_or(if area < 0 { i64::MIN } else { i64::MAX }),
            None => i64::MAX,
        }
    }

    #[must_use]
    pub fn area_exact(&self, p: PolyId) -> Option<i128> {
        self.signed_area2_exact(p)?.checked_abs().map(|a| a / 2)
    }

    #[must_use]
    pub fn area(&self, p: PolyId) -> i64 {
        self.area_exact(p)
            .and_then(|area| i64::try_from(area).ok())
            .unwrap_or(i64::MAX)
    }
}
