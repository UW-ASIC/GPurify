//! Multi-patterning (complete bounded graph coloring): build a conflict graph —
//! two polygons within color_spacing are "conflicting" (can't share a color).
//! The shared DSATUR/backtracking solver is complete within its declared
//! node/search bounds. Capacity exhaustion is a fail-closed marker, never
//! treated as evidence that the graph is clean or uncolorable.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{candidate_pairs, coloring, poly_poly_dist2_within, DrcCtx, Violation};

pub struct MultiPatterningRule { pub id: String, pub layer: LayerId, pub num_colors: i32, pub color_spacing: i32 }

fn check_multi_patterning(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, num_colors: i32,
    color_spacing: i32, rule_id: &str, out: &mut Vec<Violation>,
) {
    let polys: Vec<PolyId> = store.polys_on_layer(layer).collect();
    let n = polys.len();
    if n == 0 { return; }
    let cs2 = (color_spacing as i64) * (color_spacing as i64);
    let cands = candidate_pairs(store, &polys, None, color_spacing);
    let idx_of: std::collections::HashMap<u32, usize> =
        polys.iter().enumerate().map(|(i, p)| (p.0, i)).collect();
    let mut conflicts = Vec::new();
    for &(pa, pb) in &cands {
        let d2 = poly_poly_dist2_within(store, pa, pb, color_spacing);
        if d2 > 0 && d2 < cs2 {
            let ia = idx_of[&pa.0];
            let ib = idx_of[&pb.0];
            conflicts.push((ia, ib));
        }
    }
    let problem = coloring::ColoringProblem::new(n, num_colors as usize, conflicts);
    match coloring::solve_coloring(&problem) {
        Ok(_) => {}
        Err(error) => {
            let (kind, witness) = match error {
                coloring::ColoringError::Uncolorable { witness } => {
                    ("multi_patterning", witness.first().copied().unwrap_or(0))
                }
                coloring::ColoringError::CapacityExceeded { .. }
                | coloring::ColoringError::SearchLimit { .. }
                | coloring::ColoringError::Invalid(_) => ("multi_patterning_error", 0),
            };
            let bb = store.poly_bbox[polys[witness.min(n - 1)].0 as usize];
            out.push(Violation {
                rule_id: rule_id.into(), kind: kind.into(),
                layer: lt.name(layer).into(), measured: num_colors as i64,
                limit: num_colors as i64, x: bb.xmin, y: bb.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for MultiPatterningRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_multi_patterning(ctx.store, &ctx.deck.layers, self.layer, self.num_colors, self.color_spacing, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::MultiPatterning { id, layer, num_colors, color_spacing } =>
            Some(Box::new(MultiPatterningRule { id: id.clone(), layer: *layer, num_colors: *num_colors, color_spacing: *color_spacing })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
