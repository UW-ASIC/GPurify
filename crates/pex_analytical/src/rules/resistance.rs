//! Sheet resistance of every valid conductor polygon.
//!
//! `R = Rs * Leq/Weq`, where the equivalent dimensions come from exact polygon area and
//! perimeter. The scalar remains a conservative analytical estimate: terminal-aware current
//! flow and distributed reduction require an RC network extractor or field solver.

use crate::backend::Backend;
use crate::geometry::LayerId;
use crate::params::PexLayerParams;
use crate::{
    extraction_diagnostic, rectilinear_metrics, report_dimension_nm, Attributed, Parasitic,
    PexCtx,
};
use crate::rule::Rule;

pub struct Resistance {
    layer: LayerId,
    params: PexLayerParams,
}

impl<'a> Rule<PexCtx<'a>> for Resistance {
    type Finding = Attributed;
    fn id(&self) -> &str {
        "resistance"
    }
    fn check(&self, ctx: &PexCtx<'a>, _backend: Backend) -> Vec<Attributed> {
        let (store, lt, layer, p) = (ctx.store, ctx.layers, self.layer, &self.params);
        let mut out = Vec::new();
        for poly in store.polys_on_layer(layer) {
            let metrics = match rectilinear_metrics(store, poly) {
                Ok(metrics) => metrics,
                Err(message) => {
                    out.push(extraction_diagnostic(
                        lt,
                        layer,
                        poly,
                        "sheet_resistance",
                        message,
                    ));
                    continue;
                }
            };
            let squares = metrics.equivalent_length_nm / metrics.equivalent_width_nm;
            let ohm = p.sheet_res_ohm_sq * squares;
            out.push((
                Parasitic::Resistance {
                    layer: lt.name(layer).into(),
                    ohm,
                    length_nm: report_dimension_nm(metrics.equivalent_length_nm),
                    width_nm: report_dimension_nm(metrics.equivalent_width_nm),
                    source_polygon: None, corner: None,
                },
                [poly.0, u32::MAX],
            ));
        }
        out
    }
}

fn factory(layer: LayerId, params: &PexLayerParams) -> Option<crate::BoxedRule> {
    if params.sheet_res_ohm_sq == 0.0 {
        return None;
    }
    Some(Box::new(Resistance {
        layer,
        params: params.clone(),
    }))
}
pub static FACTORY: crate::rules::Factory = factory;
