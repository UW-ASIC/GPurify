//! Off-grid vertices.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{DrcCtx, Violation};

pub struct OffGridRule { pub id: String, pub grid: i32 }

fn check_off_grid(
    store: &GeometryStore, lt: &LayerTable, grid: i32, backend: Backend,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    // GPU advisory prefilter: offgrid_flag is an EXACT integer remainder, so the
    // flag == the CPU verdict. Flagged vertices still take the exact check below
    // (emission stays in polygon order so output is identical either way).
    #[cfg(feature = "gpu")]
    let flags: Option<Vec<u32>> =
        if backend == Backend::Gpu && store.verts_x.len() >= crate::gpu::GPU_MIN_LINEAR_WORK {
            crate::gpu::offgrid_flag(&store.verts_x, &store.verts_y, grid)
        } else {
            None
        };
    #[cfg(not(feature = "gpu"))]
    let _ = backend;
    for p in 0..store.poly_count() as u32 {
        let pid = PolyId(p);
        let layer = store.poly_layer[p as usize];
        let (s, e) = store.poly_range(pid);
        for i in s..e {
            #[cfg(feature = "gpu")]
            if flags.as_ref().is_some_and(|f| f[i] == 0) {
                continue;
            }
            let x = store.verts_x[i];
            let y = store.verts_y[i];
            if x % grid != 0 || y % grid != 0 {
                let measured = if x % grid != 0 { x } else { y };
                out.push(Violation {
                    rule_id: rule_id.into(), kind: "off_grid".into(),
                    layer: lt.name(layer).into(), measured: measured as i64,
                    limit: grid as i64, x, y,
                    hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                });
            }
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for OffGridRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_off_grid(ctx.store, &ctx.deck.layers, self.grid, backend, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::OffGrid { id, grid } =>
            Some(Box::new(OffGridRule { id: id.clone(), grid: *grid })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
