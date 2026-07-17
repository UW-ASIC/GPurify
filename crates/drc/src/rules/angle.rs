//! Angle: edges must have an allowed orientation in degrees.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{edge_cols, poly_edges, DrcCtx, Violation, GPU_MIN_LINEAR_WORK};
use gdsverify_macros::verify_kernel;
// cube-dialect expansion of the kernel fn needs these operator traits in scope
#[cfg(feature = "gpu")]
use cubecl::frontend::{Abs, Sqrt};

pub struct AngleRule { pub id: String, pub allowed: Vec<i32> }

/// |sin(edge angle − allowed angle)| per (edge, allowed) pair; the driver takes
/// the min over allowed angles. Advisory f32 prefilter — exact verdicts below.
#[verify_kernel(shape = min_over)]
pub fn angle_dev(
    x0: f32, y0: f32, x1: f32, y1: f32, #[target] sin_a: f32, #[target] cos_a: f32,
) -> f32 {
    let dx = x1 - x0;
    let dy = y1 - y0;
    let len = f32::sqrt(dx * dx + dy * dy);
    let mut dev = 0.0f32;
    if len > 0.0 {
        dev = f32::abs(dx * sin_a - dy * cos_a) / len;
    }
    dev
}

fn check_angle(
    store: &GeometryStore, lt: &LayerTable, allowed: &[i32], backend: Backend,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    // GPU prefilter: |sin(edge - allowed)| < sin(0.4 deg) is clearly within the CPU's
    // 0.5 deg tolerance -> skip. Borderline and violating edges are exact-checked below.
    const SIN_04_DEG: f32 = 0.006_981_3;
    let mut all_edges: Vec<(Edge, LayerId)> = Vec::new();
    for p in 0..store.poly_count() as u32 {
        let layer = store.poly_layer[p as usize];
        all_edges.extend(poly_edges(store, PolyId(p)).into_iter().map(|e| (e, layer)));
    }
    let dev = if backend == Backend::Gpu && all_edges.len() >= GPU_MIN_LINEAR_WORK {
        let flat: Vec<Edge> = all_edges.iter().map(|(e, _)| *e).collect();
        let (x0, y0, x1, y1) = edge_cols(&flat);
        let sins: Vec<f32> = allowed.iter().map(|&a| (a as f32).to_radians().sin()).collect();
        let coss: Vec<f32> = allowed.iter().map(|&a| (a as f32).to_radians().cos()).collect();
        angle_dev_kernel::gpu(&x0, &y0, &x1, &y1, &sins, &coss)
    } else {
        None
    };
    for (i, (e, layer)) in all_edges.iter().enumerate() {
        if e.dx() == 0 && e.dy() == 0 { continue; }
        if dev.as_ref().is_some_and(|d| d[i] < SIN_04_DEG) { continue; }
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
