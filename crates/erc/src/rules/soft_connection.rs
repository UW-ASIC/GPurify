//! Soft connection: two conductors bridged only through a high-R well path.
//! Geometric check: non-overlapping li pads on the same nwell, no metal strap,
//! and not part of any device terminal (to avoid flagging normal inverter wiring).

use std::collections::HashSet;

use crate::backend::Backend;
use crate::{ErcCtx, ErcViolation};
use crate::geometry::PolyId;

pub struct SoftConnectionCheck;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for SoftConnectionCheck {
    type Finding = ErcViolation;
    fn id(&self) -> &str { "soft_connection" }
    fn check(&self, ctx: &ErcCtx<'a>, _backend: Backend) -> Vec<ErcViolation> {
        let (store, lt, ext) = (ctx.store, &ctx.deck.layers, ctx.ext);
        let mut out = Vec::new();
        let li_l = match lt.id("li") { Some(l) => l, None => return out };
        let nwell_l = match lt.id("nwell") { Some(l) => l, None => return out };

        let li_polys: Vec<PolyId> = store.polys_on_layer(li_l).collect();
        if li_polys.len() < 2 { return out; }

        let metal_layers: Vec<_> = ["met1", "met2"].iter()
            .filter_map(|n| lt.id(n)).collect();
        let mut device_nets: HashSet<u32> = HashSet::new();
        for d in &ext.devices {
            device_nets.insert(d.gate);
            device_nets.insert(d.source);
            device_nets.insert(d.drain);
        }

        for i in 0..li_polys.len() {
            for j in (i+1)..li_polys.len() {
                let a = store.poly_bbox[li_polys[i].0 as usize];
                let b = store.poly_bbox[li_polys[j].0 as usize];
                if a.overlaps(&b) { continue; }

                // Skip if either pad is part of a device net (normal wiring)
                let na = ext.net_of_poly[li_polys[i].0 as usize];
                let nb = ext.net_of_poly[li_polys[j].0 as usize];
                if device_nets.contains(&na) || device_nets.contains(&nb) { continue; }

                let nwell_bridges = store.polys_on_layer(nwell_l).any(|nw| {
                    let wb = store.poly_bbox[nw.0 as usize];
                    wb.overlaps(&a) && wb.overlaps(&b)
                });
                if !nwell_bridges { continue; }

                let has_metal = metal_layers.iter().any(|&ml| {
                    store.polys_on_layer(ml).any(|mp| {
                        let mb = store.poly_bbox[mp.0 as usize];
                        mb.overlaps(&a) && mb.overlaps(&b)
                    })
                });
                if !has_metal {
                    out.push(ErcViolation {
                        check: "soft_connection".into(),
                        detail: "conductors connected only through well (high-R)".into(),
                        x: a.xmin, y: a.ymin,
                    });
                    return out;
                }
            }
        }
        out
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(crate::Wrap(SoftConnectionCheck)))
}
pub static FACTORY: super::Factory = factory;
