//! Min enclosure: outer layer must enclose inner by >= min on all sides.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{
    gpu_far_mask, poly_poly_dist2_within_wide, poly_strictly_inside, DrcCtx, Violation,
};

pub struct MinEnclosureRule { pub id: String, pub outer: LayerId, pub inner: LayerId, pub min: i32 }

fn check_enclosure(
    store: &GeometryStore, lt: &LayerTable, outer: LayerId, inner: LayerId, min: i32,
    gpu: Option<&DrcCtx<'_>>, rule_id: &str, out: &mut Vec<Violation>,
) {
    let outers: Vec<PolyId> = store.polys_on_layer(outer).collect();
    // phase 1: containment (CPU point-in-poly); unhosted inners are zero-enclosure.
    // Collect EVERY containing outer: the inner passes if its BEST host
    // encloses it — merged-metal semantics (a wire clipping the corner of a
    // via must not fail a via that its pad fully encloses).
    let mut hosted: Vec<(PolyId, PolyId)> = Vec::new();
    for pi in store.polys_on_layer(inner) {
        let ib = store.poly_bbox[pi.0 as usize];
        // containment truly, NOT by bbox: an L-shaped outer's bbox contains
        // points the polygon doesn't cover.
        let mut any = false;
        for &po in &outers {
            if poly_strictly_inside(store, pi, po) {
                hosted.push((pi, po));
                any = true;
            }
        }
        if !any {
            out.push(Violation {
                rule_id: rule_id.into(), kind: "min_enclosure".into(),
                layer: lt.name(inner).into(), measured: 0, limit: min as i64,
                x: ib.xmin, y: ib.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
    // phase 2: margin = min inner-boundary-to-outer-boundary distance, best
    // host wins. The GPU clears pairs whose margin is comfortably >= min
    // (clearing the inner entirely); the rest are measured exactly.
    let far = gpu.and_then(|c| gpu_far_mask(c, &hosted, min));
    let mut best: std::collections::HashMap<u32, i64> = std::collections::HashMap::new();
    let mut cleared: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for (k, &(pi, po)) in hosted.iter().enumerate() {
        if far.as_ref().is_some_and(|f| f[k]) {
            cleared.insert(pi.0);
            continue;
        }
        // exact for any polygon pair, equals the per-side margins on rectangles.
        let worst = isqrt(poly_poly_dist2_within_wide(
            store,
            pi,
            po,
            i64::from(min) + 1,
        ));
        let e = best.entry(pi.0).or_insert(i64::MIN);
        *e = (*e).max(worst);
    }
    for (pi, m) in best {
        if !cleared.contains(&pi) && m < i64::from(min) {
            let ib = store.poly_bbox[pi as usize];
            out.push(Violation {
                rule_id: rule_id.into(), kind: "min_enclosure".into(),
                layer: lt.name(inner).into(), measured: m, limit: min as i64,
                x: ib.xmin, y: ib.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for MinEnclosureRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_enclosure(ctx.store, &ctx.deck.layers, self.outer, self.inner, self.min, Some(ctx), &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::MinEnclosure { id, outer, inner, min } =>
            Some(Box::new(MinEnclosureRule { id: id.clone(), outer: *outer, inner: *inner, min: *min })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
