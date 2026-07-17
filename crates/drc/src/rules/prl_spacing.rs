//! PRL spacing (parallel run length dependent): when two same-layer polygons
//! have a parallel run length >= prl_threshold, their spacing must be
//! >= prl_spacing. PRL is the length of the overlapping projection along one
//! axis when shapes face each other.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{candidate_pairs, poly_poly_dist2_within, DrcCtx, Violation};

pub struct PrlSpacingRule { pub id: String, pub layer: LayerId, pub prl_threshold: i32, pub prl_spacing: i32 }

fn check_prl_spacing(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, prl_threshold: i32,
    prl_spacing: i32, rule_id: &str, out: &mut Vec<Violation>,
) {
    let polys: Vec<PolyId> = store.polys_on_layer(layer).collect();
    let ps2 = (prl_spacing as i64) * (prl_spacing as i64);
    let cands = candidate_pairs(store, &polys, None, prl_spacing);
    for &(pa, pb) in &cands {
        let ba = store.poly_bbox[pa.0 as usize];
        let bb = store.poly_bbox[pb.0 as usize];
        // compute PRL: overlapping projection along an axis where the shapes face each other
        let x_overlap = ba.xmax.min(bb.xmax) - ba.xmin.max(bb.xmin);
        let y_overlap = ba.ymax.min(bb.ymax) - ba.ymin.max(bb.ymin);
        // shapes face each other in y (gap in y) => PRL is x_overlap
        // shapes face each other in x (gap in x) => PRL is y_overlap
        let x_gap = ba.xmin.max(bb.xmin) - ba.xmax.min(bb.xmax); // positive if separated in x
        let y_gap = ba.ymin.max(bb.ymin) - ba.ymax.min(bb.ymax); // positive if separated in y
        let prl = if x_overlap > 0 && y_gap > 0 {
            x_overlap
        } else if y_overlap > 0 && x_gap > 0 {
            y_overlap
        } else {
            continue; // diagonal or overlapping, no parallel run
        };
        if prl < prl_threshold { continue; }
        let d2 = poly_poly_dist2_within(store, pa, pb, prl_spacing);
        if d2 == 0 { continue; } // abutting/overlapping
        if d2 < ps2 {
            out.push(Violation {
                rule_id: rule_id.into(), kind: "prl_spacing".into(),
                layer: lt.name(layer).into(), measured: isqrt(d2), limit: prl_spacing as i64,
                x: ba.xmax, y: ba.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for PrlSpacingRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_prl_spacing(ctx.store, &ctx.deck.layers, self.layer, self.prl_threshold, self.prl_spacing, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::PrlSpacing { id, layer, prl_threshold, prl_spacing } =>
            Some(Box::new(PrlSpacingRule { id: id.clone(), layer: *layer, prl_threshold: *prl_threshold, prl_spacing: *prl_spacing })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
