//! Corner-to-corner spacing between diagonally offset shapes.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{candidate_pairs, merge_groups, DrcCtx, Violation};

pub struct CornerToCornerRule { pub id: String, pub layer: LayerId, pub min: i32 }

fn check_corner_to_corner(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, min: i32, gpu: Option<&DrcCtx<'_>>,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    let polys: Vec<PolyId> = store.polys_on_layer(layer).collect();
    let min2 = (min as i64) * (min as i64);
    let cands = candidate_pairs(store, &polys, None, min);
    // edge-pair distance lower-bounds corner distance, so the same GPU prefilter applies
    // ponytail: GPU prefilter staged for phase-2 vulkano; exact CPU path only.
    let _ = gpu;
    let far: Option<Vec<bool>> = None;
    let idx_of: std::collections::HashMap<u32, u32> =
        polys.iter().enumerate().map(|(i, p)| (p.0, i as u32)).collect();
    let group = merge_groups(store, &cands, far.as_ref(), polys.len(), &idx_of);
    for (k, &(pa, pb)) in cands.iter().enumerate() {
        if far.as_ref().is_some_and(|f| f[k]) { continue; }
        if group[idx_of[&pa.0] as usize] == group[idx_of[&pb.0] as usize] {
            continue; // parts of one merged shape (see merge_groups)
        }
        {
            let ba = store.poly_bbox[pa.0 as usize];
            let bb = store.poly_bbox[pb.0 as usize];
            if ba.overlaps(&bb) { continue; }
            // Only fire when the shapes are diagonally offset (no x or y span overlap),
            // otherwise it's an edge-spacing situation handled by min_spacing.
            let x_overlap = ba.xmax.min(bb.xmax) > ba.xmin.max(bb.xmin);
            let y_overlap = ba.ymax.min(bb.ymax) > ba.ymin.max(bb.ymin);
            if x_overlap || y_overlap { continue; }
            // nearest corners
            let mut best = i64::MAX;
            let mut bx = 0;
            let mut by = 0;
            for (ux, uy) in store.vertices(pa) {
                for (wx, wy) in store.vertices(pb) {
                    let dx = (ux - wx) as i64;
                    let dy = (uy - wy) as i64;
                    let d2 = dx * dx + dy * dy;
                    if d2 < best { best = d2; bx = ux; by = uy; }
                }
            }
            if best < min2 {
                out.push(Violation {
                    rule_id: rule_id.into(), kind: "corner_to_corner".into(),
                    layer: lt.name(layer).into(), measured: isqrt(best), limit: min as i64,
                    x: bx, y: by,
                    hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                });
            }
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for CornerToCornerRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_corner_to_corner(ctx.store, &ctx.deck.layers, self.layer, self.min, Some(ctx), &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::CornerToCorner { id, layer, min } =>
            Some(Box::new(CornerToCornerRule { id: id.clone(), layer: *layer, min: *min })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
