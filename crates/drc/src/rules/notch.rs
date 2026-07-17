//! Notch: internal facing edges of the SAME polygon too close.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{facing_gaps, gpu_poly_clean_mask, push_geometry_capacity, DrcCtx, Violation};

pub struct NotchRule { pub id: String, pub layer: LayerId, pub min: i32 }

fn check_notch(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, min: i32, gpu: Option<&DrcCtx<'_>>,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    let polys: Vec<PolyId> = store.polys_on_layer(layer).collect();
    let clean = gpu.and_then(|c| gpu_poly_clean_mask(c, &polys, min));
    for (k, &p) in polys.iter().enumerate() {
        if clean.as_ref().is_some_and(|c| c[k]) { continue; }
        // a notch is a facing pair whose gap is OUTSIDE the polygon (see facing_gaps);
        // interior pairs are widths and belong to min_width, not here.
        let gaps = match facing_gaps(store, p, false) {
            Ok(gaps) => gaps,
            Err(_) => {
                push_geometry_capacity(store, lt, p, out);
                return;
            }
        };
        for (d, mx, my) in gaps {
            if d < i64::from(min) {
                out.push(Violation {
                    rule_id: rule_id.into(), kind: "notch".into(),
                    layer: lt.name(layer).into(), measured: d,
                    limit: min as i64, x: mx, y: my,
                    hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                });
            }
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for NotchRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_notch(ctx.store, &ctx.deck.layers, self.layer, self.min, Some(ctx), &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::Notch { id, layer, min } =>
            Some(Box::new(NotchRule { id: id.clone(), layer: *layer, min: *min })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
