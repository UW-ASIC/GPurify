//! EOL spacing (end-of-line): an edge shorter than `eol_width` gets an enlarged
//! spacing zone of `eol_spacing`. If any other polygon's nearest edge is within
//! that zone, it's a violation.
//! ponytail: simplified to bbox-distance from short-edge endpoints to other polygons;
//! full EOL uses a rectangular extension zone, upgrade if measurement precision matters.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{
    candidate_pairs, gpu_far_mask, merge_groups, poly_edges, poly_poly_dist2_within, DrcCtx,
    Violation,
};

pub struct EolSpacingRule { pub id: String, pub layer: LayerId, pub eol_width: i32, pub eol_spacing: i32 }

fn check_eol_spacing(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, eol_width: i32,
    eol_spacing: i32, gpu: Option<&DrcCtx<'_>>, rule_id: &str, out: &mut Vec<Violation>,
) {
    let polys: Vec<PolyId> = store.polys_on_layer(layer).collect();
    let eol_sp2 = (eol_spacing as i64) * (eol_spacing as i64);
    let cands = candidate_pairs(store, &polys, None, eol_spacing);
    let far = gpu.and_then(|c| gpu_far_mask(c, &cands, eol_spacing));
    let idx_of: std::collections::HashMap<u32, u32> =
        polys.iter().enumerate().map(|(i, p)| (p.0, i as u32)).collect();
    let group = merge_groups(store, &cands, far.as_ref(), polys.len(), &idx_of);
    for (k, &(pa, pb)) in cands.iter().enumerate() {
        if far.as_ref().is_some_and(|f| f[k]) { continue; }
        if group[idx_of[&pa.0] as usize] == group[idx_of[&pb.0] as usize] { continue; }
        let d2 = poly_poly_dist2_within(store, pa, pb, eol_spacing);
        if d2 == 0 || d2 >= eol_sp2 { continue; }
        // A short edge projects a rectangular zone of depth eol_spacing along its
        // OUTWARD normal; only geometry entering that zone violates. A neighbor
        // beside the wire end is plain min_spacing territory, not EOL.
        let zone_hit = |p_eol: PolyId, p_other: PolyId| -> Option<(i64, i32, i32)> {
            let ccw = store.signed_area2(p_eol) > 0;
            let ea = poly_edges(store, p_eol);
            let eb = poly_edges(store, p_other);
            let mut best: Option<(i64, i32, i32)> = None;
            for a in &ea {
                let elen2 = a.len2_i128();
                if elen2 == 0
                    || elen2 >= i128::from(eol_width) * i128::from(eol_width)
                {
                    continue;
                }
                // manhattan outward normal (diagonal EOL edges: skip, no zone defined)
                let (udx, udy) = (a.dx().signum() as i32, a.dy().signum() as i32);
                if udx != 0 && udy != 0 { continue; }
                let (nx, ny) = if ccw { (udy, -udx) } else { (-udy, udx) };
                let zone = Bbox {
                    xmin: a.x0.min(a.x1).saturating_add(nx.min(0) * eol_spacing),
                    xmax: a.x0.max(a.x1).saturating_add(nx.max(0) * eol_spacing),
                    ymin: a.y0.min(a.y1).saturating_add(ny.min(0) * eol_spacing),
                    ymax: a.y0.max(a.y1).saturating_add(ny.max(0) * eol_spacing),
                };
                for b in &eb {
                    let eb_box = Bbox {
                        xmin: b.x0.min(b.x1), xmax: b.x0.max(b.x1),
                        ymin: b.y0.min(b.y1), ymax: b.y0.max(b.y1),
                    };
                    if !zone.overlaps(&eb_box) { continue; }
                    let sd = seg_seg_dist2(a, b);
                    if sd > 0 && sd < eol_sp2 && best.is_none_or(|(bd, _, _)| sd < bd) {
                        best = Some((sd, a.x0, a.y0));
                    }
                }
            }
            best
        };
        if let Some((sd, x, y)) = zone_hit(pa, pb).or_else(|| zone_hit(pb, pa)) {
            out.push(Violation {
                rule_id: rule_id.into(), kind: "eol_spacing".into(),
                layer: lt.name(layer).into(), measured: isqrt(sd), limit: eol_spacing as i64,
                x, y,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for EolSpacingRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_eol_spacing(ctx.store, &ctx.deck.layers, self.layer, self.eol_width, self.eol_spacing, Some(ctx), &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::EolSpacing { id, layer, eol_width, eol_spacing } =>
            Some(Box::new(EolSpacingRule { id: id.clone(), layer: *layer, eol_width: *eol_width, eol_spacing: *eol_spacing })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
