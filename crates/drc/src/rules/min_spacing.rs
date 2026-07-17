//! Min spacing: same-layer external spacing (merged-shape aware).

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{
    candidate_pairs, gap_region_covered, merge_groups, poly_poly_dist2_within,
    poly_strictly_inside, DrcCtx, Violation,
};

pub struct MinSpacingRule { pub id: String, pub layer: LayerId, pub min: i32, pub strict: bool }

pub(crate) fn check_spacing_same(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, min: i32, gpu: Option<&DrcCtx<'_>>,
    strict: bool, rule_id: &str, out: &mut Vec<Violation>,
) {
    let polys: Vec<PolyId> = store.polys_on_layer(layer).collect();
    let min2 = (min as i64) * (min as i64);
    let cands = candidate_pairs(store, &polys, None, min);
    // ponytail: GPU prefilter (gpu_far_mask) staged for phase-2 vulkano; every
    // candidate pair goes to the exact poly_poly_dist2_within path below.
    let _ = gpu;
    let far: Option<Vec<bool>> = None;
    let idx_of: std::collections::HashMap<u32, u32> =
        polys.iter().enumerate().map(|(i, p)| (p.0, i as u32)).collect();
    let group = merge_groups(store, &cands, far.as_ref(), polys.len(), &idx_of);
    for (k, &(pa, pb)) in cands.iter().enumerate() {
        if far.as_ref().is_some_and(|f| f[k]) { continue; } // GPU-cleared: clearly >= min
        let ba = store.poly_bbox[pa.0 as usize];
        // NOTE: overlapping *bboxes* do NOT mean the shapes touch (interlocking L
        // shapes). Only actual contact — direct or through a chain of touching
        // polygons (merge_groups) — makes the pair one merged shape.
        let d2 = poly_poly_dist2_within(store, pa, pb, min);
        if d2 == 0 { continue; } // abutting/crossing => merged shape
        if d2 < min2 {
            if poly_strictly_inside(store, pa, pb) || poly_strictly_inside(store, pb, pa) {
                continue; // hole/island of the same layer, merge semantics
            }
            // within one merged shape a sub-min gap is a notch of the
            // compound, not external spacing — and only if the gap region is
            // actually EXPOSED: a third polygon covering it makes the merged
            // shape solid there (bridge blocks over pad pairs).
            let same_shape = group[idx_of[&pa.0] as usize] == group[idx_of[&pb.0] as usize];
            if same_shape && gap_region_covered(store, &polys, pa, pb) {
                continue;
            }
            let d = isqrt(d2);
            // In STRICT mode, same-net gaps are spacing violations too
            let kind = if same_shape && !strict { "notch" } else { "min_spacing" };
            if std::env::var("PNR_DEBUG_NOTCH").is_ok() {
                let bb = store.poly_bbox[pb.0 as usize];
                let (sa, ea) = store.poly_range(pa);
                let (sb, eb) = store.poly_range(pb);
                eprintln!("[notch-dbg] {kind} d={d} pa=({},{},{},{})v{} pb=({},{},{},{})v{} same_shape={same_shape}",
                    ba.xmin, ba.ymin, ba.xmax, ba.ymax, ea - sa,
                    bb.xmin, bb.ymin, bb.xmax, bb.ymax, eb - sb);
            }
            out.push(Violation {
                rule_id: rule_id.into(),
                kind: kind.into(),
                layer: lt.name(layer).into(), measured: d, limit: min as i64,
                x: ba.xmax, y: ba.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for MinSpacingRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_spacing_same(ctx.store, &ctx.deck.layers, self.layer, self.min, Some(ctx), self.strict, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::MinSpacing { id, layer, min } =>
            Some(Box::new(MinSpacingRule { id: id.clone(), layer: *layer, min: *min, strict })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;

#[cfg(test)]
mod tests {
    use super::*;

    // Repro: via pad (A) and stub leg (C) 45nm apart, bridged by bar (B)
    // covering the gap — merged shape is solid there, no notch.
    #[test]
    fn bridged_same_net_gap_is_not_a_notch() {
        let mut store = GeometryStore::new();
        let met1: LayerId = 0;
        store.add_rect(met1, 8335, 7945, 290, 290); // A: pad
        store.add_rect(met1, 8335, 7945, 625, 290); // B: bar covering A..C gap
        store.add_rect(met1, 8670, 7945, 290, 585); // C: leg
        let mut defs = std::collections::HashMap::new();
        defs.insert("met1".to_string(), crate::params::LayerDef { layer: 68, datatype: 20 });
        let lt = LayerTable::from_defs(&defs);
        let mut out = Vec::new();
        check_spacing_same(&store, &lt, met1, 140, None, false, "min_spacing", &mut out);
        assert!(out.is_empty(), "bridged gap flagged: {out:?}");
    }
}
