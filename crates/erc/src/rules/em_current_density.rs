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
    fn check(&self, ctx: &ErcCtx<'a>, _backend: Backend) -> Vec<ErcViolation> {
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

        for &ml in &metal_layers {
            for mp in store.polys_on_layer(ml) {
                let net = ext.net_of_poly[mp.0 as usize];
                if net == u32::MAX { continue; }
                if !sd_nets.contains(&net) { continue; }
                let bb = store.poly_bbox[mp.0 as usize];
                let width = bb.width().min(bb.height());
                if width < min_width_nm {
                    out.push(ErcViolation {
                        check: "em_current_density".into(),
                        detail: format!("narrow metal ({}nm) on current-carrying net", width),
                        x: bb.xmin, y: bb.ymin,
                    });
                }
            }
        }
        out
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(crate::Wrap(EmCurrentDensityCheck)))
}
pub static FACTORY: super::Factory = factory;
