//! Fixed per-via resistance for each polygon on a via/contact layer.

use crate::backend::Backend;
use crate::geometry::LayerId;
use crate::params::PexLayerParams;
use crate::analytical::{Attributed, Parasitic, PexCtx};
use crate::rule::Rule;

pub struct ViaResistance {
    layer: LayerId,
    params: PexLayerParams,
}

impl<'a> Rule<PexCtx<'a>> for ViaResistance {
    type Finding = Attributed;
    fn id(&self) -> &str {
        "via_resistance"
    }
    fn check(&self, ctx: &PexCtx<'a>, _backend: Backend) -> Vec<Attributed> {
        let (store, lt, layer, p) = (ctx.store, ctx.layers, self.layer, &self.params);
        let mut out = Vec::new();
        for poly in store.polys_on_layer(layer) {
            out.push((
                Parasitic::ViaResistance {
                    layer: lt.name(layer).into(),
                    ohm: p.via_res_ohm,
                    source_polygon: None, corner: None,
                },
                [poly.0, u32::MAX],
            ));
        }
        out
    }
}

fn factory(layer: LayerId, params: &PexLayerParams) -> Option<crate::analytical::BoxedRule> {
    if params.via_res_ohm == 0.0 {
        return None;
    }
    Some(Box::new(ViaResistance {
        layer,
        params: params.clone(),
    }))
}
pub static FACTORY: crate::analytical::rules::Factory = factory;
