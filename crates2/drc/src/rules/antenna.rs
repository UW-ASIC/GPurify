//! Antenna (PAR: metal area / gate area).
//! For each gate (poly-over-diff crossing), sum connected metal area on `layer`
//! and compare to the gate area. ratio = metal_area / gate_area; violation if > limit.
//! ponytail: simplified single-layer antenna. Multi-layer cumulative (CAR) and
//! diode relief need the full connectivity graph; add when needed.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::Deck;
use super::super::{DrcCtx, Violation};

pub struct AntennaRule { pub id: String, pub layer: LayerId, pub ratio: f64 }

fn check_antenna(
    store: &GeometryStore, deck: &Deck, layer: LayerId, ratio: f64,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    use crate::lvs::extract_netlist;

    let lt = &deck.layers;
    let ext = match extract_netlist(store, deck) {
        Ok(e) => e,
        Err(_) => return,
    };
    let poly_l = match lt.id("poly") { Some(l) => l, None => return };
    let diff_l = match lt.id("diff") { Some(l) => l, None => return };

    // Gate area per gate net: sum poly-over-diff intersection areas
    let mut gate_area: std::collections::HashMap<u32, i64> = std::collections::HashMap::new();
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

    // Metal area per net on the antenna layer
    let mut metal_area: std::collections::HashMap<u32, i64> = std::collections::HashMap::new();
    for m in store.polys_on_layer(layer) {
        let net = ext.net_of_poly[m.0 as usize];
        if net != u32::MAX {
            *metal_area.entry(net).or_insert(0) += store.area(m);
        }
    }

    // Check each gate net
    for (&net, &ga) in &gate_area {
        if ga == 0 { continue; }
        let ma = *metal_area.get(&net).unwrap_or(&0);
        let r = ma as f64 / ga as f64;
        if r > ratio {
            let pos = ext.net_of_poly.iter().enumerate()
                .find(|(_, &n)| n == net)
                .map(|(i, _)| store.poly_bbox[i])
                .unwrap_or(Bbox::empty());
            out.push(Violation {
                rule_id: rule_id.into(), kind: "antenna".into(),
                layer: lt.name(layer).into(),
                measured: (r * 1000.0) as i64, // ratio × 1000 to fit i64
                limit: (ratio * 1000.0) as i64,
                x: pos.xmin, y: pos.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for AntennaRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_antenna(ctx.store, ctx.deck, self.layer, self.ratio, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::Antenna { id, layer, ratio } =>
            Some(Box::new(AntennaRule { id: id.clone(), layer: *layer, ratio: *ratio })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
