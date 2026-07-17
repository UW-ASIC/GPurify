//! Asymmetric enclosure: each inner polygon must have enclosure >= min_one_side
//! on at least ONE side of each axis pair (left/right, top/bottom). Passes if
//! max(left,right) >= min AND max(top,bottom) >= min.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{poly_strictly_inside, DrcCtx, Violation};

pub struct AsymmetricEnclosureRule { pub id: String, pub outer: LayerId, pub inner: LayerId, pub min_one_side: i32 }

fn check_asymmetric_enclosure(
    store: &GeometryStore, lt: &LayerTable, outer: LayerId, inner: LayerId, min_one_side: i32,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    let outers: Vec<PolyId> = store.polys_on_layer(outer).collect();
    for pi in store.polys_on_layer(inner) {
        let ib = store.poly_bbox[pi.0 as usize];
        let mut best_ok = false;
        for &po in &outers {
            if !poly_strictly_inside(store, pi, po) { continue; }
            let ob = store.poly_bbox[po.0 as usize];
            let left_enc = ib.xmin - ob.xmin;
            let right_enc = ob.xmax - ib.xmax;
            let bottom_enc = ib.ymin - ob.ymin;
            let top_enc = ob.ymax - ib.ymax;
            let x_ok = left_enc.max(right_enc) >= min_one_side;
            let y_ok = bottom_enc.max(top_enc) >= min_one_side;
            if x_ok && y_ok {
                best_ok = true;
                break;
            }
        }
        if !best_ok {
            // find the best measured enclosure from any host for reporting
            let mut best_measured: i32 = 0;
            for &po in &outers {
                if !poly_strictly_inside(store, pi, po) { continue; }
                let ob = store.poly_bbox[po.0 as usize];
                let left_enc = ib.xmin - ob.xmin;
                let right_enc = ob.xmax - ib.xmax;
                let bottom_enc = ib.ymin - ob.ymin;
                let top_enc = ob.ymax - ib.ymax;
                let m = left_enc.max(right_enc).min(bottom_enc.max(top_enc));
                best_measured = best_measured.max(m);
            }
            out.push(Violation {
                rule_id: rule_id.into(), kind: "asymmetric_enclosure".into(),
                layer: lt.name(inner).into(), measured: best_measured as i64,
                limit: min_one_side as i64, x: ib.xmin, y: ib.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for AsymmetricEnclosureRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_asymmetric_enclosure(ctx.store, &ctx.deck.layers, self.outer, self.inner, self.min_one_side, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::AsymmetricEnclosure { id, outer, inner, min_one_side } =>
            Some(Box::new(AsymmetricEnclosureRule { id: id.clone(), outer: *outer, inner: *inner, min_one_side: *min_one_side })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
