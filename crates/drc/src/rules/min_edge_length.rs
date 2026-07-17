//! Min edge length.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{DrcCtx, Violation};

pub struct MinEdgeLengthRule { pub id: String, pub layer: LayerId, pub min: i32 }

fn check_min_edge_length(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, min: i32, backend: Backend,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    let min2 = (min as i64) * (min as i64);
    let edges = build_edges(store, layer);
    // GPU advisory prefilter: f32 approx len2 with a slack threshold. Edges
    // clearly longer than min are skipped; borderline/short edges take the exact
    // i128 verdict below. thr chosen so no real hit is dropped (superset).
    #[cfg(feature = "gpu")]
    let approx: Option<Vec<f32>> =
        if backend == Backend::Gpu && edges.len() >= crate::gpu::GPU_MIN_LINEAR_WORK {
            let (x0, y0, x1, y1) = crate::gpu::edge_cols(&edges);
            crate::gpu::edge_len2_approx(&x0, &y0, &x1, &y1)
        } else {
            None
        };
    #[cfg(feature = "gpu")]
    let thr = (min as f32) * (min as f32) * 1.05 + 4.0;
    #[cfg(not(feature = "gpu"))]
    let _ = backend;
    for (_i, e) in edges.iter().enumerate() {
        #[cfg(feature = "gpu")]
        if approx.as_ref().is_some_and(|a| a[_i] >= thr) {
            continue;
        }
        let l2 = e.len2_i128();
        if l2 > 0 && l2 < i128::from(min2) {
            out.push(Violation {
                rule_id: rule_id.into(), kind: "min_edge_length".into(),
                layer: lt.name(layer).into(),
                measured: isqrt(i64::try_from(l2).unwrap_or(i64::MAX)), limit: min as i64,
                x: e.x0, y: e.y0,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for MinEdgeLengthRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_min_edge_length(ctx.store, &ctx.deck.layers, self.layer, self.min, backend, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::MinEdgeLength { id, layer, min } =>
            Some(Box::new(MinEdgeLengthRule { id: id.clone(), layer: *layer, min: *min })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
