//! Max width (slotting trigger).

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{DrcCtx, Violation};

pub struct MaxWidthRule { pub id: String, pub layer: LayerId, pub max: i32 }

fn check_max_width(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, max: i32,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    for p in store.polys_on_layer(layer) {
        let bb = store.poly_bbox[p.0 as usize];
        let w = bb.width().min(bb.height());
        if w > max {
            out.push(Violation {
                rule_id: rule_id.into(), kind: "max_width".into(),
                layer: lt.name(layer).into(), measured: w as i64, limit: max as i64,
                x: bb.xmin, y: bb.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for MaxWidthRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_max_width(ctx.store, &ctx.deck.layers, self.layer, self.max, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::MaxWidth { id, layer, max } =>
            Some(Box::new(MaxWidthRule { id: id.clone(), layer: *layer, max: *max })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
