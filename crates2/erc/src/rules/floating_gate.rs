//! Floating gate: a gate net that connects ONLY to gate terminals (no driver/load).

use std::collections::HashSet;

use crate::backend::Backend;
use crate::{ErcCtx, ErcViolation};
use crate::geometry::Bbox;

pub struct FloatingGateCheck;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for FloatingGateCheck {
    type Finding = ErcViolation;
    fn id(&self) -> &str { "floating_gate" }
    fn check(&self, ctx: &ErcCtx<'a>, _backend: Backend) -> Vec<ErcViolation> {
        let (store, lt, ext) = (ctx.store, &ctx.deck.layers, ctx.ext);
        let mut out = Vec::new();
        let mut gate_nets: HashSet<u32> = HashSet::new();
        let mut driven_nets: HashSet<u32> = HashSet::new();
        for d in &ext.devices {
            gate_nets.insert(d.gate);
            driven_nets.insert(d.source);
            driven_nets.insert(d.drain);
        }
        // A gate net that also appears as S/D somewhere has a driver path.
        // A gate net that ONLY appears as gate is floating.
        // Also check: is the gate net connected to any non-device conductor (li/met)?
        // If yes, it's driven externally. We approximate: if the net connects to any
        // polygon that isn't poly-over-diff (the gate itself), it's driven.
        let poly_l = lt.id("poly");
        let diff_l = lt.id("diff");
        for &gnet in &gate_nets {
            if driven_nets.contains(&gnet) { continue; }
            // Check if any non-gate polygon is on this net
            let has_external = ext.net_of_poly.iter().enumerate().any(|(i, &n)| {
                if n != gnet { return false; }
                let layer = store.poly_layer[i];
                // poly over diff = gate, not an external connection
                if Some(layer) == poly_l { return false; }
                // diff segments are part of the device, not external
                if Some(layer) == diff_l { return false; }
                true
            });
            if has_external { continue; }
            // Find a representative gate poly for location
            let pos = ext.net_of_poly.iter().enumerate()
                .find(|(_, &n)| n == gnet)
                .map(|(i, _)| store.poly_bbox[i])
                .unwrap_or(Bbox::empty());
            out.push(ErcViolation {
                check: "floating_gate".into(),
                detail: format!("gate net {} has no driver", gnet),
                x: pos.xmin, y: pos.ymin,
            });
        }
        out
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(crate::Wrap(FloatingGateCheck)))
}
pub static FACTORY: super::Factory = factory;
