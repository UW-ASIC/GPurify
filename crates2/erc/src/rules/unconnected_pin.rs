//! Unconnected pin: metal polygon not connected to any device terminal.

use std::collections::HashSet;

use crate::backend::Backend;
use crate::{ErcCtx, ErcViolation};

pub struct UnconnectedPinCheck;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for UnconnectedPinCheck {
    type Finding = ErcViolation;
    fn id(&self) -> &str { "unconnected_pin" }
    fn check(&self, ctx: &ErcCtx<'a>, _backend: Backend) -> Vec<ErcViolation> {
        let (store, lt, ext) = (ctx.store, &ctx.deck.layers, ctx.ext);
        let mut out = Vec::new();
        let metal_layers: Vec<_> = ["met1", "met2"].iter()
            .filter_map(|n| lt.id(n)).collect();

        // Nets used by devices
        let mut device_nets: HashSet<u32> = HashSet::new();
        for d in &ext.devices {
            device_nets.insert(d.gate);
            device_nets.insert(d.source);
            device_nets.insert(d.drain);
        }

        for &ml in &metal_layers {
            for mp in store.polys_on_layer(ml) {
                let net = ext.net_of_poly[mp.0 as usize];
                if net == u32::MAX || !device_nets.contains(&net) {
                    let bb = store.poly_bbox[mp.0 as usize];
                    out.push(ErcViolation {
                        check: "unconnected_pin".into(),
                        detail: format!("metal on {} not connected to any device", lt.name(ml)),
                        x: bb.xmin, y: bb.ymin,
                    });
                }
            }
        }
        out
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(crate::Wrap(UnconnectedPinCheck)))
}
pub static FACTORY: super::Factory = factory;
