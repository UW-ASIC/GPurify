//! Multiple drivers: a non-gate net driven by drain terminals of devices with
//! DIFFERENT gate nets. Two outputs fighting the same wire → contention.

use std::collections::{HashMap, HashSet};

use crate::backend::Backend;
use crate::{ErcCtx, ErcViolation};
use crate::geometry::Bbox;

pub struct MultipleDriverCheck;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for MultipleDriverCheck {
    type Finding = ErcViolation;
    fn id(&self) -> &str { "multiple_drivers" }
    fn check(&self, ctx: &ErcCtx<'a>, _backend: Backend) -> Vec<ErcViolation> {
        let (store, ext) = (ctx.store, ctx.ext);
        let mut out = Vec::new();
        let gate_nets: HashSet<u32> = ext.devices.iter().map(|d| d.gate).collect();
        // per non-gate net: collect the gate nets of devices whose drain drives it
        let mut drivers: HashMap<u32, HashSet<u32>> = HashMap::new();
        for d in &ext.devices {
            if !gate_nets.contains(&d.drain) {
                drivers.entry(d.drain).or_default().insert(d.gate);
            }
        }
        for (&net, gates) in &drivers {
            if gates.len() > 1 {
                let pos = ext.net_of_poly.iter().enumerate()
                    .find(|(_, &n)| n == net)
                    .map(|(i, _)| store.poly_bbox[i])
                    .unwrap_or(Bbox::empty());
                out.push(ErcViolation {
                    check: "multiple_drivers".into(),
                    detail: format!("net {} driven by {} different gate signals", net, gates.len()),
                    x: pos.xmin, y: pos.ymin,
                });
            }
        }
        out
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(crate::Wrap(MultipleDriverCheck)))
}
pub static FACTORY: super::Factory = factory;
