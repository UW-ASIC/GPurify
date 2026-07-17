//! Cheesing (large unslotted plates): any over-limit polygon must carry actual
//! hole/keyhole evidence in its own boundary. Nested same-polarity polygons are
//! material and cannot waive it.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{keyhole_hole_rings, DrcCtx, Violation};

pub struct CheesingRule { pub id: String, pub layer: LayerId, pub max_area_no_slot: i64 }

pub(crate) fn check_cheesing(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, max_area_no_slot: i64,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    for p in store.polys_on_layer(layer) {
        let area = store.area(p);
        if area > max_area_no_slot && keyhole_hole_rings(store, p).is_empty() {
            let bb = store.poly_bbox[p.0 as usize];
            out.push(Violation {
                rule_id: rule_id.into(), kind: "cheesing".into(),
                layer: lt.name(layer).into(), measured: area,
                limit: max_area_no_slot, x: bb.xmin, y: bb.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for CheesingRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_cheesing(ctx.store, &ctx.deck.layers, self.layer, self.max_area_no_slot, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::Cheesing { id, layer, max_area_no_slot } =>
            Some(Box::new(CheesingRule { id: id.clone(), layer: *layer, max_area_no_slot: *max_area_no_slot })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
