//! Min edge length.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{DrcCtx, Violation};

pub struct MinEdgeLengthRule { pub id: String, pub layer: LayerId, pub min: i32 }

fn check_min_edge_length(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, min: i32, _backend: Backend,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    let min2 = (min as i64) * (min as i64);
    let edges = build_edges(store, layer);
    // ponytail: GPU prefilter (edge_len2_approx f32 kernel) staged for phase-2
    // vulkano; the exact i128 length below is the sole verdict path.
    for e in edges.iter() {
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
