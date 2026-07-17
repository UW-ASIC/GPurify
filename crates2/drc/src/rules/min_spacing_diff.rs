//! Min spacing between two different layers.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{
    candidate_pairs, poly_poly_dist2_within, poly_strictly_inside, DrcCtx,
    Violation,
};

pub struct MinSpacingDiffRule { pub id: String, pub a: LayerId, pub b: LayerId, pub min: i32 }

fn check_spacing_diff(
    store: &GeometryStore, lt: &LayerTable, a: LayerId, b: LayerId, min: i32, gpu: Option<&DrcCtx<'_>>,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    let pas: Vec<PolyId> = store.polys_on_layer(a).collect();
    let pbs: Vec<PolyId> = store.polys_on_layer(b).collect();
    let min2 = (min as i64) * (min as i64);
    let cands = candidate_pairs(store, &pas, Some(&pbs), min);
    // ponytail: GPU prefilter staged for phase-2 vulkano; exact CPU path only.
    let _ = gpu;
    let far: Option<Vec<bool>> = None;
    for (k, &(pa, pb)) in cands.iter().enumerate() {
        if far.as_ref().is_some_and(|f| f[k]) { continue; }
        let ba = store.poly_bbox[pa.0 as usize];
        let d2 = poly_poly_dist2_within(store, pa, pb, min);
        if d2 == 0 { continue; } // touching/crossing layers: not a spacing pair
        if d2 < min2 {
            if poly_strictly_inside(store, pa, pb) || poly_strictly_inside(store, pb, pa) {
                continue;
            }
            out.push(Violation {
                rule_id: rule_id.into(), kind: "min_spacing_diff".into(),
                layer: format!("{}:{}", lt.name(a), lt.name(b)),
                measured: isqrt(d2), limit: min as i64, x: ba.xmax, y: ba.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for MinSpacingDiffRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_spacing_diff(ctx.store, &ctx.deck.layers, self.a, self.b, self.min, Some(ctx), &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::MinSpacingDiff { id, a, b, min } =>
            Some(Box::new(MinSpacingDiffRule { id: id.clone(), a: *a, b: *b, min: *min })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
