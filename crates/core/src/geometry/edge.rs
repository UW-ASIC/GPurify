//! The dense edge stream consumed by scanline / edge-pair passes.

use super::ids::LayerId;
use super::store::GeometryStore;

/// A directed edge, materialized for scanline / edge-pair passes. This is the SoA "edge
/// stream" the DRC spacing/width algorithms consume. We build it on demand for a layer so
/// the hot loop iterates a dense array of edges with no polygon indirection.
#[derive(Clone, Copy, Debug)]
pub struct Edge {
    pub x0: i32,
    pub y0: i32,
    pub x1: i32,
    pub y1: i32,
    pub poly: u32, // which polygon this edge belongs to (for same-poly filtering)
}

impl Edge {
    #[inline]
    pub fn dx_i64(&self) -> i64 {
        i64::from(self.x1) - i64::from(self.x0)
    }
    #[inline]
    pub fn dy_i64(&self) -> i64 {
        i64::from(self.y1) - i64::from(self.y0)
    }
    #[inline]
    pub fn dx(&self) -> i32 {
        self.dx_i64()
            .clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
    }
    #[inline]
    pub fn dy(&self) -> i32 {
        self.dy_i64()
            .clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
    }
    #[inline]
    pub fn len2_i128(&self) -> i128 {
        let dx = i128::from(self.dx_i64());
        let dy = i128::from(self.dy_i64());
        dx * dx + dy * dy
    }
    #[inline]
    pub fn len2(&self) -> i64 {
        i64::try_from(self.len2_i128()).unwrap_or(i64::MAX)
    }
    #[inline]
    pub fn is_horizontal(&self) -> bool {
        self.y0 == self.y1
    }
    #[inline]
    pub fn is_vertical(&self) -> bool {
        self.x0 == self.x1
    }
}

/// Build the dense edge list for one layer. Output is a flat Vec<Edge> — SoA-adjacent and
/// GPU-uploadable. Edges are emitted in polygon order (CCW ring => interior on the left).
pub fn build_edges(store: &GeometryStore, layer: LayerId) -> Vec<Edge> {
    let mut edges = Vec::new();
    for p in store.polys_on_layer(layer) {
        edges.extend(store.edges_of(p));
    }
    edges
}
