//! Min extension: layer extends past reference by >= min.
//! e.g. poly gate endcap over diff. We measure how far `layer` sticks out beyond `reference`
//! along the axis of the reference, on each protruding side, taking the minimum protrusion
//! where the two overlap.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{DrcCtx, Violation};

pub struct MinExtensionRule { pub id: String, pub layer: LayerId, pub reference: LayerId, pub min: i32 }

fn check_extension(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, reference: LayerId, min: i32,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    let refs: Vec<PolyId> = store.polys_on_layer(reference).collect();
    for pl in store.polys_on_layer(layer) {
        let lb = store.poly_bbox[pl.0 as usize];
        for &pr in &refs {
            let rb = store.poly_bbox[pr.0 as usize];
            if !lb.overlaps(&rb) { continue; }
            // Poly is a vertical bar crossing a horizontal diff: measure vertical protrusion.
            // Determine crossing orientation by which dimension of `layer` is longer.
            if lb.height() >= lb.width() {
                // vertical bar: extension is top and bottom past the reference
                let bottom_ext = rb.ymin - lb.ymin;
                let top_ext = lb.ymax - rb.ymax;
                for (ext, yy) in [(bottom_ext, rb.ymin), (top_ext, rb.ymax)] {
                    if ext < min {
                        out.push(Violation {
                            rule_id: rule_id.into(), kind: "min_extension".into(),
                            layer: lt.name(layer).into(), measured: ext as i64,
                            limit: min as i64, x: lb.xmin, y: yy,
                            hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                        });
                    }
                }
            } else {
                let left_ext = rb.xmin - lb.xmin;
                let right_ext = lb.xmax - rb.xmax;
                for (ext, xx) in [(left_ext, rb.xmin), (right_ext, rb.xmax)] {
                    if ext < min {
                        out.push(Violation {
                            rule_id: rule_id.into(), kind: "min_extension".into(),
                            layer: lt.name(layer).into(), measured: ext as i64,
                            limit: min as i64, x: xx, y: lb.ymin,
                            hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                        });
                    }
                }
            }
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for MinExtensionRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_extension(ctx.store, &ctx.deck.layers, self.layer, self.reference, self.min, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::MinExtension { id, layer, reference, min } =>
            Some(Box::new(MinExtensionRule { id: id.clone(), layer: *layer, reference: *reference, min: *min })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
