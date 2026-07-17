//! Redundant via (isolated via check): each polygon on the via layer must have
//! at least `min_count - 1` other same-layer polygons whose bbox center is
//! within `within` distance.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{candidate_pairs, DrcCtx, Violation};

pub struct RedundantViaRule { pub id: String, pub layer: LayerId, pub min_count: i32, pub within: i32 }

fn check_redundant_via(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, min_count: i32, within: i32,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    let polys: Vec<PolyId> = store.polys_on_layer(layer).collect();
    let within2 = (within as i64) * (within as i64);
    // centers sit inside their bboxes, so center-distance <= within implies the
    // bboxes come within `within`: the x-sweep candidate set is a superset.
    let center = |p: PolyId| -> (i64, i64) {
        let bb = store.poly_bbox[p.0 as usize];
        (((bb.xmin as i64) + (bb.xmax as i64)) / 2,
         ((bb.ymin as i64) + (bb.ymax as i64)) / 2)
    };
    let mut neighbors: std::collections::HashMap<u32, i32> =
        polys.iter().map(|p| (p.0, 0)).collect();
    for (pa, pb) in candidate_pairs(store, &polys, None, within) {
        let (ax, ay) = center(pa);
        let (bx, by) = center(pb);
        let (dx, dy) = (ax - bx, ay - by);
        if dx * dx + dy * dy <= within2 {
            *neighbors.get_mut(&pa.0).unwrap() += 1;
            *neighbors.get_mut(&pb.0).unwrap() += 1;
        }
    }
    for &p in &polys {
        let count = neighbors[&p.0];
        if count < min_count - 1 {
            let bb = store.poly_bbox[p.0 as usize];
            out.push(Violation {
                rule_id: rule_id.into(), kind: "redundant_via".into(),
                layer: lt.name(layer).into(), measured: (count + 1) as i64,
                limit: min_count as i64, x: bb.xmin, y: bb.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for RedundantViaRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_redundant_via(ctx.store, &ctx.deck.layers, self.layer, self.min_count, self.within, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::RedundantVia { id, layer, min_count, within } =>
            Some(Box::new(RedundantViaRule { id: id.clone(), layer: *layer, min_count: *min_count, within: *within })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
