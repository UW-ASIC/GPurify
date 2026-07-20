//! ESD topological check: every net connected to a boundary metal (met1/met2
//! polygon touching the cell bbox edge) must also connect to at least one device
//! terminal. If a boundary-touching metal net has no device connection, it is an
//! unprotected I/O pad.
//! ponytail: simplified — real ESD checks verify specific clamp topologies;
//! this just checks connectivity.

use std::collections::HashSet;

use crate::backend::Backend;
use crate::{ErcCtx, ErcViolation};
use crate::geometry::Bbox;

pub struct EsdTopologicalCheck;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for EsdTopologicalCheck {
    type Finding = ErcViolation;
    fn id(&self) -> &str { "esd_missing" }
    fn check(&self, ctx: &ErcCtx<'a>, _backend: Backend) -> Vec<ErcViolation> {
        let (store, lt, ext) = (ctx.store, &ctx.deck.layers, ctx.ext);
        let mut out = Vec::new();
        let metal_layers: Vec<_> = ["met1", "met2"].iter()
            .filter_map(|n| lt.id(n)).collect();
        if metal_layers.is_empty() { return out; }

        // Compute cell bbox = union of all polygon bboxes
        let mut cell_bb = Bbox::empty();
        for bb in &store.poly_bbox {
            cell_bb.include(bb.xmin, bb.ymin);
            cell_bb.include(bb.xmax, bb.ymax);
        }
        if cell_bb.xmin == i32::MAX { return out; } // no polygons

        // Device nets: any net used by a device terminal (MOS/BJT/passive)
        let device_nets = crate::device_connected_nets(ext);

        // Find met1/met2 polygons touching the cell bbox edge (within 1 dbu)
        let mut flagged_nets: HashSet<u32> = HashSet::new();
        for &ml in &metal_layers {
            for mp in store.polys_on_layer(ml) {
                let bb = store.poly_bbox[mp.0 as usize];
                let touches_edge = (bb.xmin - cell_bb.xmin).abs() <= 1
                    || (bb.xmax - cell_bb.xmax).abs() <= 1
                    || (bb.ymin - cell_bb.ymin).abs() <= 1
                    || (bb.ymax - cell_bb.ymax).abs() <= 1;
                if !touches_edge { continue; }
                let net = ext.net_of_poly[mp.0 as usize];
                if net == u32::MAX { continue; }
                if device_nets.contains(&net) { continue; }
                if flagged_nets.insert(net) {
                    out.push(ErcViolation {
                        check: "esd_missing".into(),
                        detail: format!("I/O pad net {} has no ESD device", net),
                        x: bb.xmin, y: bb.ymin,
                    });
                }
            }
        }
        out
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(crate::Wrap(EsdTopologicalCheck)))
}
pub static FACTORY: super::Factory = factory;
