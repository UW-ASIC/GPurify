//! Cumulative antenna ratio (CAR): total metal area across ALL metal layers
//! connected to a gate net, divided by the gate area. Unlike the single-layer
//! PAR in drc.rs, this sums metal area from every metal layer on the net.

use std::collections::HashMap;

use crate::backend::Backend;
use crate::{ErcCtx, ErcViolation};
use crate::geometry::Bbox;

pub struct AntennaElectricalCheck {
    pub ratio: f64,
}

impl<'a> crate::rule::Rule<ErcCtx<'a>> for AntennaElectricalCheck {
    type Finding = ErcViolation;
    fn id(&self) -> &str { "antenna_electrical" }
    fn check(&self, ctx: &ErcCtx<'a>, _backend: Backend) -> Vec<ErcViolation> {
        let (store, lt, ext, ratio) = (ctx.store, &ctx.deck.layers, ctx.ext, self.ratio);
        let mut out = Vec::new();
        let poly_l = match lt.id("poly") { Some(l) => l, None => return out };
        let diff_l = match lt.id("diff") { Some(l) => l, None => return out };

        // Gate area per gate net: poly-over-diff intersection area, keyed by net id
        let mut gate_area: HashMap<u32, i64> = HashMap::new();
        for p in store.polys_on_layer(poly_l) {
            let pb = store.poly_bbox[p.0 as usize];
            for d in store.polys_on_layer(diff_l) {
                let db = store.poly_bbox[d.0 as usize];
                let ix = pb.xmax.min(db.xmax) - pb.xmin.max(db.xmin);
                let iy = pb.ymax.min(db.ymax) - pb.ymin.max(db.ymin);
                if ix > 0 && iy > 0 {
                    let net = ext.net_of_poly[p.0 as usize];
                    if net != u32::MAX {
                        *gate_area.entry(net).or_insert(0) += (ix as i64) * (iy as i64);
                    }
                }
            }
        }
        if gate_area.is_empty() { return out; }

        // Sum metal area across ALL metal layers for each net
        let metal_names = ["met1", "met2"];
        let metal_layers: Vec<_> = metal_names.iter().filter_map(|n| lt.id(n)).collect();

        let mut total_metal: HashMap<u32, i64> = HashMap::new();
        for &ml in &metal_layers {
            for m in store.polys_on_layer(ml) {
                let net = ext.net_of_poly[m.0 as usize];
                if net != u32::MAX {
                    *total_metal.entry(net).or_insert(0) += store.area(m);
                }
            }
        }

        // Check each gate net: cumulative_ratio = total_metal_area / gate_area
        for (&net, &ga) in &gate_area {
            if ga == 0 { continue; }
            let ma = *total_metal.get(&net).unwrap_or(&0);
            let r = ma as f64 / ga as f64;
            if r > ratio {
                let pos = ext.net_of_poly.iter().enumerate()
                    .find(|(_, &n)| n == net)
                    .map(|(i, _)| store.poly_bbox[i])
                    .unwrap_or(Bbox::empty());
                out.push(ErcViolation {
                    check: "antenna_electrical".into(),
                    detail: format!(
                        "cumulative antenna ratio {:.1} exceeds limit {:.1} on gate net {}",
                        r, ratio, net,
                    ),
                    x: pos.xmin, y: pos.ymin,
                });
            }
        }
        out
    }
}

fn factory(deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(crate::Wrap(AntennaElectricalCheck { ratio: deck.erc.antenna_ratio })))
}
pub static FACTORY: super::Factory = factory;
