//! Angle: edges must have an allowed orientation in degrees.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{poly_edges, DrcCtx, Violation};

pub struct AngleRule { pub id: String, pub allowed: Vec<i32> }

fn check_angle(
    store: &GeometryStore, lt: &LayerTable, allowed: &[i32], backend: Backend,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    let mut all_edges: Vec<(Edge, LayerId)> = Vec::new();
    for p in 0..store.poly_count() as u32 {
        let layer = store.poly_layer[p as usize];
        all_edges.extend(poly_edges(store, PolyId(p)).into_iter().map(|e| (e, layer)));
    }
    // GPU advisory prefilter: |sin(edge - allowed)| < sin(0.4deg) is safely
    // inside the CPU's 0.5deg tolerance -> skip. Borderline/violating edges are
    // exact-checked below. Superset: no violating edge is dropped.
    #[cfg(feature = "gpu")]
    const SIN_04_DEG: f32 = 0.006_981_3;
    #[cfg(feature = "gpu")]
    let dev: Option<Vec<f32>> =
        if backend == Backend::Gpu && all_edges.len() >= crate::gpu::GPU_MIN_LINEAR_WORK {
            let flat: Vec<Edge> = all_edges.iter().map(|(e, _)| *e).collect();
            let (x0, y0, x1, y1) = crate::gpu::edge_cols(&flat);
            let sins: Vec<f32> = allowed.iter().map(|&a| (a as f32).to_radians().sin()).collect();
            let coss: Vec<f32> = allowed.iter().map(|&a| (a as f32).to_radians().cos()).collect();
            crate::gpu::angle_dev(&x0, &y0, &x1, &y1, &sins, &coss)
        } else {
            None
        };
    #[cfg(not(feature = "gpu"))]
    let _ = backend;
    for (_i, (e, layer)) in all_edges.iter().enumerate() {
        if e.dx() == 0 && e.dy() == 0 { continue; }
        #[cfg(feature = "gpu")]
        if dev.as_ref().is_some_and(|d| d[_i] < SIN_04_DEG) {
            continue;
        }
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
