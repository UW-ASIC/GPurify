//! Point-to-point resistance: for each net with device terminals, estimate total
//! wire resistance using PEX and flag if R exceeds a threshold.
//! Limit comes from deck.erc.p2p_r_limit_ohm; real signoff would use per-net targets.

use std::collections::HashSet;

use crate::backend::Backend;
use crate::{ErcCtx, ErcViolation};
use crate::geometry::Bbox;
use crate::pex::run_pex_by_net;

pub struct PointToPointResistanceCheck;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for PointToPointResistanceCheck {
    type Finding = ErcViolation;
    fn id(&self) -> &str { "p2p_resistance" }
    fn check(&self, ctx: &ErcCtx<'a>, _backend: Backend) -> Vec<ErcViolation> {
        let (store, deck, ext) = (ctx.store, ctx.deck, ctx.ext);
        let mut out = Vec::new();
        // Device terminal nets
        let mut device_nets: HashSet<u32> = HashSet::new();
        for d in &ext.devices {
            device_nets.insert(d.gate);
            device_nets.insert(d.source);
            device_nets.insert(d.drain);
        }

        let by_net = run_pex_by_net(store, deck, &ext.net_of_poly);

        for (&net, par) in &by_net {
            if !device_nets.contains(&net) { continue; }
            if par.r_ohm > deck.erc.p2p_r_limit_ohm {
                let pos = ext.net_of_poly.iter().enumerate()
                    .find(|(_, &n)| n == net)
                    .map(|(i, _)| store.poly_bbox[i])
                    .unwrap_or(Bbox::empty());
                out.push(ErcViolation {
                    check: "p2p_resistance".into(),
                    detail: format!("net {} R={:.1} ohm exceeds limit", net, par.r_ohm),
                    x: pos.xmin, y: pos.ymin,
                });
            }
        }
        out
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(crate::Wrap(PointToPointResistanceCheck)))
}
pub static FACTORY: super::Factory = factory;
