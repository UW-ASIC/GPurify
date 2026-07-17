//! Via array spacing: when a group of > array_threshold polygons are clustered
//! (each within array_spacing of another), check that all pairs within the
//! group have spacing >= array_spacing. Build adjacency groups via union-find.
//! ponytail: simplified — just check if any pair in a large group violates.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{candidate_pairs, poly_poly_dist2_within_wide, DrcCtx, Violation};

pub struct ViaArraySpacingRule { pub id: String, pub layer: LayerId, pub array_threshold: i32, pub array_spacing: i32 }

fn check_via_array_spacing(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, array_threshold: i32,
    array_spacing: i32, rule_id: &str, out: &mut Vec<Violation>,
) {
    let polys: Vec<PolyId> = store.polys_on_layer(layer).collect();
    let n = polys.len();
    if n == 0 { return; }
    let as2 = (array_spacing as i64) * (array_spacing as i64);
    let cands = candidate_pairs(store, &polys, None, array_spacing);
    // union-find: two vias within array_spacing are in the same group
    let idx_of: std::collections::HashMap<u32, u32> =
        polys.iter().enumerate().map(|(i, p)| (p.0, i as u32)).collect();
    let mut parent: Vec<u32> = (0..n as u32).collect();
    fn find(parent: &mut [u32], x: u32) -> u32 {
        let mut r = x;
        while parent[r as usize] != r {
            parent[r as usize] = parent[parent[r as usize] as usize];
            r = parent[r as usize];
        }
        r
    }
    // track which candidate pairs are within array_spacing
    let mut close_pairs: Vec<(u32, u32)> = Vec::new();
    for &(pa, pb) in &cands {
        let d2 = poly_poly_dist2_within_wide(
            store,
            pa,
            pb,
            i64::from(array_spacing) + 1,
        );
        if d2 > 0 && d2 <= as2 {
            let ia = idx_of[&pa.0];
            let ib = idx_of[&pb.0];
            let (ra, rb) = (find(&mut parent, ia), find(&mut parent, ib));
            if ra != rb { parent[ra as usize] = rb; }
            close_pairs.push((ia, ib));
        }
    }
    // resolve all parents
    let groups: Vec<u32> = (0..n as u32).map(|i| find(&mut parent, i)).collect();
    // count group sizes
    let mut group_size: std::collections::HashMap<u32, i32> = std::collections::HashMap::new();
    for &g in &groups {
        *group_size.entry(g).or_insert(0) += 1;
    }
    // for groups larger than array_threshold, emit one violation per group
    let mut flagged_groups: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for &(ia, ib) in &close_pairs {
        let ga = find(&mut parent, ia);
        if *group_size.get(&ga).unwrap_or(&0) <= array_threshold { continue; }
        if !flagged_groups.insert(ga) { continue; }
        let pa = polys[ia as usize];
        let pb = polys[ib as usize];
        let d2 = poly_poly_dist2_within_wide(
            store,
            pa,
            pb,
            i64::from(array_spacing) + 1,
        );
        if d2 > 0 && d2 < as2 {
            let ba = store.poly_bbox[pa.0 as usize];
            out.push(Violation {
                rule_id: rule_id.into(), kind: "via_array_spacing".into(),
                layer: lt.name(layer).into(), measured: isqrt(d2), limit: array_spacing as i64,
                x: ba.xmin, y: ba.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for ViaArraySpacingRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_via_array_spacing(ctx.store, &ctx.deck.layers, self.layer, self.array_threshold, self.array_spacing, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::ViaArraySpacing { id, layer, array_threshold, array_spacing } =>
            Some(Box::new(ViaArraySpacingRule { id: id.clone(), layer: *layer, array_threshold: *array_threshold, array_spacing: *array_spacing })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
