//! Area + fringe capacitance to substrate for every valid conductor polygon.
//!
//! Fill density and ground-plane shielding need explicit process-calibrated models. They are
//! deliberately not inferred from polygon size or hard-coded layer names here.

use crate::backend::Backend;
use crate::geometry::LayerId;
use crate::params::PexLayerParams;
use crate::{
    extraction_diagnostic, rectilinear_metrics, Attributed, Parasitic, PexCtx, NM_PER_UM,
};
use crate::rule::Rule;

pub struct AreaFringeCap {
    layer: LayerId,
    params: PexLayerParams,
}

impl<'a> Rule<PexCtx<'a>> for AreaFringeCap {
    type Finding = Attributed;
    fn id(&self) -> &str {
        "area_fringe_cap"
    }
    fn check(&self, ctx: &PexCtx<'a>, _backend: Backend) -> Vec<Attributed> {
        let (store, lt, layer, p) = (ctx.store, ctx.layers, self.layer, &self.params);
        let layer_name = lt.name(layer);
        let mut out = Vec::new();
        for poly in store.polys_on_layer(layer) {
            let metrics = match rectilinear_metrics(store, poly) {
                Ok(metrics) => metrics,
                Err(message) => {
                    out.push(extraction_diagnostic(
                        lt,
                        layer,
                        poly,
                        "ground_capacitance",
                        message,
                    ));
                    continue;
                }
            };
            let area_um2 = metrics.area_nm2 / (NM_PER_UM * NM_PER_UM);
            let perim_um = metrics.perimeter_nm / NM_PER_UM;
            let area_af = p.area_cap_af_um2 * area_um2;
            let fringe_af = p.fringe_cap_af_um * perim_um;
            let af = area_af + fringe_af;
            out.push((
                Parasitic::AreaCap {
                    layer: layer_name.into(),
                    af,
                    area_af,
                    fringe_af,
                    area_um2,
                    perimeter_um: perim_um,
                    source_polygon: None, corner: None,
                },
                [poly.0, u32::MAX],
            ));
        }
        out
    }
}

fn factory(layer: LayerId, params: &PexLayerParams) -> Option<crate::BoxedRule> {
    if params.area_cap_af_um2 == 0.0 && params.fringe_cap_af_um == 0.0 {
        return None;
    }
    Some(Box::new(AreaFringeCap {
        layer,
        params: params.clone(),
    }))
}
pub static FACTORY: crate::rules::Factory = factory;
