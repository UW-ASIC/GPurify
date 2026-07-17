//! Density (windowed coverage) — handles both MinDensity and MaxDensity params.
//! Tiles the layer's global bbox into `window`-sized windows and computes the covered
//! fraction of the layer polygons in each. Simplified but exact for axis-aligned rectangles
//! under our conformance geometry (single-window cases).

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{push_geometry_capacity, DrcCtx, Violation};

pub struct DensityRule { pub id: String, pub layer: LayerId, pub window: i32, pub frac_limit: f64, pub is_min: bool }

fn check_density(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, window: i32, frac_limit: f64,
    is_min: bool, rule_id: &str, out: &mut Vec<Violation>,
) {
    if window <= 0 { return; }
    let polys: Vec<PolyId> = store.polys_on_layer(layer).collect();
    if polys.is_empty() { return; }
    // global bbox
    let mut gb = Bbox::empty();
    for &p in &polys {
        let b = store.poly_bbox[p.0 as usize];
        gb.include(b.xmin, b.ymin);
        gb.include(b.xmax, b.ymax);
    }
    // Tile the field into window-sized tiles anchored at the field origin — a single
    // anchored window misses violations anywhere past the first window. Coverage is
    // accumulated per window in one pass over the polygons (O(P + windows), not O(P*W)),
    // clipping each polygon to the window exactly (bbox coverage overstates combs badly).
    // ponytail: assumes same-layer shapes don't overlap each other (true after merge;
    // overlapping input shapes would double-count).
    let window = i64::from(window);
    let win_area = (window as f64) * (window as f64);
    let Some(nx) = gb
        .width_i64()
        .checked_add(window - 1)
        .map(|span| span / window)
    else {
        push_geometry_capacity(store, lt, polys[0], out);
        return;
    };
    let Some(ny) = gb
        .height_i64()
        .checked_add(window - 1)
        .map(|span| span / window)
    else {
        push_geometry_capacity(store, lt, polys[0], out);
        return;
    };
    if nx <= 0 || ny <= 0 { return; }
    let Some(window_count) = nx.checked_mul(ny) else {
        push_geometry_capacity(store, lt, polys[0], out);
        return;
    };
    if window_count
        > i64::try_from(crate::geometry::exact::MAX_RECTILINEAR_BOOLEAN_CELLS)
            .unwrap_or(i64::MAX)
    {
        push_geometry_capacity(store, lt, polys[0], out);
        return;
    }
    let mut covered: std::collections::HashMap<(i64, i64), f64> = std::collections::HashMap::new();
    for &p in &polys {
        let b = store.poly_bbox[p.0 as usize];
        let wi0 = (i64::from(b.xmin) - i64::from(gb.xmin)) / window;
        let wi1 = (i64::from(b.xmax) - i64::from(gb.xmin) - 1) / window;
        let wj0 = (i64::from(b.ymin) - i64::from(gb.ymin)) / window;
        let wj1 = (i64::from(b.ymax) - i64::from(gb.ymin) - 1) / window;
        for wi in wi0..=wi1.min(nx - 1) {
            for wj in wj0..=wj1.min(ny - 1) {
                let Some((wx0, wy0, wx1, wy1)) =
                    density_window_bounds(gb, wi, wj, window)
                else {
                    push_geometry_capacity(store, lt, p, out);
                    return;
                };
                let a = clipped_area_i64(store, p, wx0, wy0, wx1, wy1);
                if a > 0.0 {
                    *covered.entry((wi, wj)).or_insert(0.0) += a;
                }
            }
        }
    }
    for wj in 0..ny {
        for wi in 0..nx {
            let frac = *covered.get(&(wi, wj)).unwrap_or(&0.0) / win_area;
            let bad = if is_min { frac < frac_limit } else { frac > frac_limit };
            if bad {
                let Some((wx0, wy0, _, _)) = density_window_bounds(gb, wi, wj, window)
                else {
                    push_geometry_capacity(store, lt, polys[0], out);
                    return;
                };
                let (Ok(x), Ok(y)) = (i32::try_from(wx0), i32::try_from(wy0)) else {
                    push_geometry_capacity(store, lt, polys[0], out);
                    return;
                };
                out.push(Violation {
                    rule_id: rule_id.into(),
                    kind: if is_min { "min_density".into() } else { "max_density".into() },
                    layer: lt.name(layer).into(),
                    measured: (frac * 1_000_000.0) as i64, // frac scaled to ppm to fit i64
                    limit: (frac_limit * 1_000_000.0) as i64,
                    x,
                    y,
                    hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                });
            }
        }
    }
}

fn density_window_bounds(
    global: Bbox, wi: i64, wj: i64, window: i64,
) -> Option<(i64, i64, i64, i64)> {
    let wx0 = wi.checked_mul(window)?.checked_add(i64::from(global.xmin))?;
    let wy0 = wj.checked_mul(window)?.checked_add(i64::from(global.ymin))?;
    Some((wx0, wy0, wx0.checked_add(window)?, wy0.checked_add(window)?))
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for DensityRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_density(ctx.store, &ctx.deck.layers, self.layer, self.window, self.frac_limit, self.is_min, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::MinDensity { id, layer, window, min_frac } =>
            Some(Box::new(DensityRule { id: id.clone(), layer: *layer, window: *window, frac_limit: *min_frac, is_min: true })),
        crate::params::DrcRuleParam::MaxDensity { id, layer, window, max_frac } =>
            Some(Box::new(DensityRule { id: id.clone(), layer: *layer, window: *window, frac_limit: *max_frac, is_min: false })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
