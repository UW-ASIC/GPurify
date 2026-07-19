//! EM current density: flag narrow metal wires on nets that carry device current
//! (connected to device S/D terminals). A polygon on met1/met2 whose minimum
//! bbox dimension is below deck.erc.em_min_width_nm is flagged.
//! ponytail: min-width proxy for cross-section; add metal thickness + per-layer
//! current tables for a real J check.

use std::collections::HashSet;

use crate::backend::Backend;
use crate::{ErcCtx, ErcViolation};

pub struct EmCurrentDensityCheck;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for EmCurrentDensityCheck {
    type Finding = ErcViolation;
    fn id(&self) -> &str { "em_current_density" }
    fn check(&self, ctx: &ErcCtx<'a>, backend: Backend) -> Vec<ErcViolation> {
        let (store, lt, ext) = (ctx.store, &ctx.deck.layers, ctx.ext);
        let min_width_nm = ctx.deck.erc.em_min_width_nm;
        let mut out = Vec::new();
        let metal_layers: Vec<_> = ["met1", "met2"].iter()
            .filter_map(|n| lt.id(n)).collect();
        if metal_layers.is_empty() { return out; }

        // Collect device S/D nets
        let mut sd_nets: HashSet<u32> = HashSet::new();
        for d in &ext.devices {
            sd_nets.insert(d.source);
            sd_nets.insert(d.drain);
        }

        // Gather metal polys in emission order (net + bbox side by side). The
        // GPU width prefilter runs over this whole set; the exact per-poly
        // checks below stay in the same order, so output is identical.
        let mut nets: Vec<u32> = Vec::new();
        let mut bboxes: Vec<crate::geometry::Bbox> = Vec::new();
        for &ml in &metal_layers {
            for mp in store.polys_on_layer(ml) {
                nets.push(ext.net_of_poly[mp.0 as usize]);
                bboxes.push(store.poly_bbox[mp.0 as usize]);
            }
        }

        // GPU advisory prefilter: 1 iff min(width,height) < min_width (a superset
        // of the exact hits). `None` on CPU / small input / no device.
        #[cfg(feature = "gpu")]
        let flags: Option<Vec<u32>> =
            if backend == Backend::Gpu && bboxes.len() >= crate::gpu::GPU_MIN_LINEAR_WORK {
                let xmin: Vec<i32> = bboxes.iter().map(|b| b.xmin).collect();
                let ymin: Vec<i32> = bboxes.iter().map(|b| b.ymin).collect();
                let xmax: Vec<i32> = bboxes.iter().map(|b| b.xmax).collect();
                let ymax: Vec<i32> = bboxes.iter().map(|b| b.ymax).collect();
                crate::gpu::em_narrow_flags(&xmin, &ymin, &xmax, &ymax, min_width_nm)
            } else {
                None
            };
        #[cfg(not(feature = "gpu"))]
        let _ = backend;

        for (i, (&net, bb)) in nets.iter().zip(&bboxes).enumerate() {
            // Skip polys the GPU proved wide enough (flag is a superset).
            #[cfg(feature = "gpu")]
            if flags.as_ref().is_some_and(|f| f[i] == 0) {
                continue;
            }
            let _ = i;
            if net == u32::MAX { continue; }
            if !sd_nets.contains(&net) { continue; }
            let width = bb.width().min(bb.height());
            if width < min_width_nm {
                out.push(ErcViolation {
                    check: "em_current_density".into(),
                    detail: format!("narrow metal ({}nm) on current-carrying net", width),
                    x: bb.xmin, y: bb.ymin,
                });
            }
        }
        out
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(crate::Wrap(EmCurrentDensityCheck)))
}
pub static FACTORY: super::Factory = factory;
