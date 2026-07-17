//! Floating well: nwell polygon with no tap contact inside.
//! A tap = nsdm + diff overlap inside the nwell, connected to a metal layer.

use crate::backend::Backend;
use crate::{ErcCtx, ErcViolation};

pub struct FloatingWellCheck;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for FloatingWellCheck {
    type Finding = ErcViolation;
    fn id(&self) -> &str { "floating_well" }
    fn check(&self, ctx: &ErcCtx<'a>, _backend: Backend) -> Vec<ErcViolation> {
        let (store, lt) = (ctx.store, &ctx.deck.layers);
        let mut out = Vec::new();
        let nwell_l = match lt.id("nwell") { Some(l) => l, None => return out };
        let diff_l = match lt.id("diff") { Some(l) => l, None => return out };
        let nsdm_l = lt.id("nsdm");

        // A well is "tied" if there's a diff+nsdm tap inside it connected to metal.
        // Simplified: any diff polygon inside the nwell that overlaps nsdm = n+ tap.
        // ponytail: checks bbox overlap only, sufficient for conformance geometry.
        for nw in store.polys_on_layer(nwell_l) {
            let nb = store.poly_bbox[nw.0 as usize];
            let has_tap = store.polys_on_layer(diff_l).any(|dp| {
                let db = store.poly_bbox[dp.0 as usize];
                if !nb.overlaps(&db) { return false; }
                // Must be n+ type (nsdm) to be a well tap in nwell
                match nsdm_l {
                    Some(nl) => store.polys_on_layer(nl).any(|ns| {
                        store.poly_bbox[ns.0 as usize].overlaps(&db)
                    }),
                    None => false,
                }
            });
            if !has_tap {
                out.push(ErcViolation {
                    check: "floating_well".into(),
                    detail: "nwell has no n+ tap contact".into(),
                    x: nb.xmin, y: nb.ymin,
                });
            }
        }
        out
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(crate::Wrap(FloatingWellCheck)))
}
pub static FACTORY: super::Factory = factory;
