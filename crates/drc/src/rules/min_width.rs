//! Min width: narrowest interior facing gap of one polygon.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{facing_gaps, gpu_poly_clean_mask, push_geometry_capacity, DrcCtx, Violation};

pub struct MinWidthRule { pub id: String, pub layer: LayerId, pub min: i32 }

// For axis-aligned polygons, width = min(bbox.width, bbox.height) is exact for convex
// rectangles; for general rectilinear polygons we additionally scan opposing parallel edges.
// The conformance width cases are rectangles, so the bbox measure is exact; we still emit
// the opposing-edge scan for robustness on non-convex shapes.
fn check_min_width(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, min: i32, gpu: Option<&DrcCtx<'_>>,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    let polys: Vec<PolyId> = store.polys_on_layer(layer).collect();
    let clean = gpu.and_then(|c| gpu_poly_clean_mask(c, &polys, min));
    for (k, &p) in polys.iter().enumerate() {
        let bb = store.poly_bbox[p.0 as usize];
        let (s, e) = store.poly_range(p);
        let n = e - s;
        // bbox fast path is exact ONLY for axis-aligned rectangles; a rotated
        // parallelogram has 4 vertices too and must take the facing-gap scan.
        let axis_aligned_rect =
            n == 4 && store.edges_of(p).all(|ed| ed.x0 == ed.x1 || ed.y0 == ed.y1);
        if axis_aligned_rect {
            let w = bb.width().min(bb.height());
            if w < min {
                out.push(Violation {
                    rule_id: rule_id.into(), kind: "min_width".into(),
                    layer: lt.name(layer).into(), measured: w as i64, limit: min as i64,
                    x: bb.xmin, y: bb.ymin,
                    hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                });
            }
            continue;
        }
        if clean.as_ref().is_some_and(|c| c[k]) { continue; } // GPU: no gap anywhere near min
        // Rectilinear: one violation per narrow INTERIOR facing gap — an L with two thin
        // arms is two violation sites, not one. Exterior gaps (notches) are excluded;
        // counting them as widths is the classic false positive naive edge scans produce
        // on U-shapes.
        let gaps = match facing_gaps(store, p, true) {
            Ok(gaps) => gaps,
            Err(_) => {
                push_geometry_capacity(store, lt, p, out);
                return;
            }
        };
        for (d, mx, my) in gaps {
            if d < i64::from(min) {
                out.push(Violation {
                    rule_id: rule_id.into(), kind: "min_width".into(),
                    layer: lt.name(layer).into(), measured: d, limit: min as i64,
                    x: mx, y: my,
                    hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                });
            }
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for MinWidthRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_min_width(ctx.store, &ctx.deck.layers, self.layer, self.min, Some(ctx), &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::MinWidth { id, layer, min } =>
            Some(Box::new(MinWidthRule { id: id.clone(), layer: *layer, min: *min })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
