//! Tie-high / tie-low: a gate net shorted to a supply rail (a source-only net
//! with no signal driver). In correct designs, gates are driven by logic outputs;
//! when a gate is accidentally or intentionally tied to VDD/VSS, the gate net
//! appears as BOTH a gate terminal AND a source terminal, while NO device
//! drain drives it (supply rails have no drain output).

use std::collections::HashSet;

use crate::backend::Backend;
use crate::{ErcCtx, ErcViolation};
use crate::geometry::Bbox;

pub struct TieHighLowCheck;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for TieHighLowCheck {
    type Finding = ErcViolation;
    fn id(&self) -> &str { "tie_high_low" }
    fn check(&self, ctx: &ErcCtx<'a>, _backend: Backend) -> Vec<ErcViolation> {
        let (store, ext) = (ctx.store, ctx.ext);
        let mut out = Vec::new();
        let gate_nets: HashSet<u32> = ext.devices.iter().map(|d| d.gate).collect();
        let drain_nets: HashSet<u32> = ext.devices.iter().map(|d| d.drain).collect();
        let source_nets: HashSet<u32> = ext.devices.iter().map(|d| d.source).collect();

        for &gnet in &gate_nets {
            // Gate net is also a source net (tied to supply rail)
            if !source_nets.contains(&gnet) { continue; }
            // But no device drives this net from its drain (it's not a logic output)
            if drain_nets.contains(&gnet) { continue; }
            let pos = ext.net_of_poly.iter().enumerate()
                .find(|(_, &n)| n == gnet)
                .map(|(i, _)| store.poly_bbox[i])
                .unwrap_or(Bbox::empty());
            out.push(ErcViolation {
                check: "tie_high_low".into(),
                detail: format!("gate net {} tied to supply rail (no drain driver)", gnet),
                x: pos.xmin, y: pos.ymin,
            });
        }
        out
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(crate::Wrap(TieHighLowCheck)))
}
pub static FACTORY: super::Factory = factory;
