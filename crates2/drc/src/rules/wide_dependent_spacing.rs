//! Wide-dependent spacing: when EITHER polygon in a pair is "wide" (min bbox
//! dimension >= width_threshold), the pair must satisfy a larger spacing
//! requirement (wide_spacing) instead of the normal min_spacing. This is the
//! standard foundry rule for wide-metal spacing.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{candidate_pairs, poly_poly_dist2_within, poly_strictly_inside, DrcCtx, Violation};

pub struct WideDependentSpacingRule { pub id: String, pub layer: LayerId, pub width_threshold: i32, pub wide_spacing: i32 }

fn check_wide_dependent_spacing(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, width_threshold: i32,
    wide_spacing: i32, rule_id: &str, out: &mut Vec<Violation>,
) {
    let polys: Vec<PolyId> = store.polys_on_layer(layer).collect();
    let ws2 = (wide_spacing as i64) * (wide_spacing as i64);
    let cands = candidate_pairs(store, &polys, None, wide_spacing);
    for &(pa, pb) in &cands {
        let ba = store.poly_bbox[pa.0 as usize];
        let bb = store.poly_bbox[pb.0 as usize];
        let wa = ba.width().min(ba.height());
        let wb = bb.width().min(bb.height());
        if wa < width_threshold && wb < width_threshold { continue; }
        let d2 = poly_poly_dist2_within(store, pa, pb, wide_spacing);
        if d2 == 0 { continue; } // overlapping/abutting, merged shape
        if poly_strictly_inside(store, pa, pb) || poly_strictly_inside(store, pb, pa) {
            continue;
        }
        if d2 < ws2 {
            out.push(Violation {
                rule_id: rule_id.into(), kind: "wide_dependent_spacing".into(),
                layer: lt.name(layer).into(), measured: isqrt(d2), limit: wide_spacing as i64,
                x: ba.xmax, y: ba.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for WideDependentSpacingRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_wide_dependent_spacing(ctx.store, &ctx.deck.layers, self.layer, self.width_threshold, self.wide_spacing, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::WideDependentSpacing { id, layer, width_threshold, wide_spacing } =>
            Some(Box::new(WideDependentSpacingRule { id: id.clone(), layer: *layer, width_threshold: *width_threshold, wide_spacing: *wide_spacing })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
