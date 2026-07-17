//! Min edge length.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{edge_cols, DrcCtx, Violation, GPU_MIN_LINEAR_WORK};
use gdsverify_macros::verify_kernel;

pub struct MinEdgeLengthRule { pub id: String, pub layer: LayerId, pub min: i32 }

/// f32 squared edge length — advisory prefilter; the exact i128 length decides.
#[verify_kernel(shape = map)]
pub fn edge_len2_approx(x0: f32, y0: f32, x1: f32, y1: f32) -> f32 {
    let dx = x1 - x0;
    let dy = y1 - y0;
    dx * dx + dy * dy
}

fn check_min_edge_length(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, min: i32, backend: Backend,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    let min2 = (min as i64) * (min as i64);
    let edges = build_edges(store, layer);
    // GPU prefilter: edges with len2 clearly >= min2 need no exact check
    let approx = if backend == Backend::Gpu && edges.len() >= GPU_MIN_LINEAR_WORK {
        let (x0, y0, x1, y1) = edge_cols(&edges);
        edge_len2_approx_kernel::gpu(&x0, &y0, &x1, &y1)
    } else {
        None
    };
    let thr = (min as f32) * (min as f32) * 1.05 + 4.0;
    for (i, e) in edges.iter().enumerate() {
        if approx.as_ref().is_some_and(|a| a[i] >= thr) { continue; }
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
