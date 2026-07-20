//! HV domain crossing: no conductor should cross from inside an nwell to outside
//! without proper isolation. A net that has conductive polygons both inside and
//! outside nwell AND is not a device terminal net is flagged.
//! ponytail: simplified — real HV checks use voltage-aware extraction; this
//! catches geometric domain violations.

use std::collections::HashSet;

use crate::backend::Backend;
use crate::{ErcCtx, ErcViolation};
use crate::geometry::{Bbox, PolyId};

pub struct HvDomainCheck;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for HvDomainCheck {
    type Finding = ErcViolation;
    fn id(&self) -> &str { "hv_domain_crossing" }
    fn check(&self, ctx: &ErcCtx<'a>, _backend: Backend) -> Vec<ErcViolation> {
        let (store, lt, ext) = (ctx.store, &ctx.deck.layers, ctx.ext);
        let mut out = Vec::new();
        let nwell_l = match lt.id("nwell") { Some(l) => l, None => return out };
        let conductor_names = ["li", "met1", "met2"];
        let conductor_layers: Vec<_> = conductor_names.iter()
            .filter_map(|n| lt.id(n)).collect();
        if conductor_layers.is_empty() { return out; }

        let nwell_polys: Vec<PolyId> = store.polys_on_layer(nwell_l).collect();
        if nwell_polys.is_empty() { return out; }

        // Device terminal nets (MOS/BJT/passive)
        let device_nets = crate::device_connected_nets(ext);

        // Build net -> {inside_nwell, outside_nwell}
        let mut inside: HashSet<u32> = HashSet::new();
        let mut outside: HashSet<u32> = HashSet::new();

        for &cl in &conductor_layers {
            for cp in store.polys_on_layer(cl) {
                let net = ext.net_of_poly[cp.0 as usize];
                if net == u32::MAX { continue; }
                let cb = store.poly_bbox[cp.0 as usize];
                let mut any_inside = false;
                let mut fully_covered = false;
                for &nw in &nwell_polys {
                    let nb = store.poly_bbox[nw.0 as usize];
                    if nb.overlaps(&cb) {
                        any_inside = true;
                        if nb.xmin <= cb.xmin && nb.ymin <= cb.ymin
                            && nb.xmax >= cb.xmax && nb.ymax >= cb.ymax {
                            fully_covered = true;
                        }
                    }
                }
                if any_inside { inside.insert(net); }
                if !fully_covered { outside.insert(net); }
            }
        }

        // Flag nets that span both domains and are not device terminals
        let mut flagged: HashSet<u32> = HashSet::new();
        for &net in &inside {
            if !outside.contains(&net) { continue; }
            if device_nets.contains(&net) { continue; }
            if !flagged.insert(net) { continue; }
            let pos = ext.net_of_poly.iter().enumerate()
                .find(|(_, &n)| n == net)
                .map(|(i, _)| store.poly_bbox[i])
                .unwrap_or(Bbox::empty());
            out.push(ErcViolation {
                check: "hv_domain_crossing".into(),
                detail: format!("net {} crosses nwell boundary without isolation", net),
                x: pos.xmin, y: pos.ymin,
            });
        }
        out
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(crate::Wrap(HvDomainCheck)))
}
pub static FACTORY: super::Factory = factory;
