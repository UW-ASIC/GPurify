//! Angle: edges must have an allowed orientation in degrees.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{poly_edges, DrcCtx, Violation};

pub struct AngleRule { pub id: String, pub allowed: Vec<i32> }

fn check_angle(
    store: &GeometryStore, lt: &LayerTable, allowed: &[i32], _backend: Backend,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    // ponytail: GPU prefilter (angle_dev f32 kernel) staged for phase-2 vulkano;
    // every edge takes the exact orientation check below.
    let mut all_edges: Vec<(Edge, LayerId)> = Vec::new();
    for p in 0..store.poly_count() as u32 {
        let layer = store.poly_layer[p as usize];
        all_edges.extend(poly_edges(store, PolyId(p)).into_iter().map(|e| (e, layer)));
    }
    for (e, layer) in all_edges.iter() {
        if e.dx() == 0 && e.dy() == 0 { continue; }
        let ang = edge_angle_deg(e);
        let ok = allowed.iter().any(|&a| ang_matches(ang, a));
        if !ok {
            out.push(Violation {
                rule_id: rule_id.into(), kind: "angle".into(),
                layer: lt.name(*layer).into(), measured: -1, limit: 0,
                x: e.x0, y: e.y0,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

fn edge_angle_deg(e: &Edge) -> f64 {
    let a = (e.dy() as f64).atan2(e.dx() as f64).to_degrees();
    // normalize to [0,180)
    let mut a = a % 180.0;
    if a < 0.0 { a += 180.0; }
    a
}
fn ang_matches(ang: f64, allowed: i32) -> bool {
    let target = (allowed as f64) % 180.0;
    (ang - target).abs() < 0.5 || (ang - target - 180.0).abs() < 0.5
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for AngleRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_angle(ctx.store, &ctx.deck.layers, &self.allowed, backend, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::Angle { id, allowed } =>
            Some(Box::new(AngleRule { id: id.clone(), allowed: allowed.clone() })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
