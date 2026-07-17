//! Max distance to tap (well tie proximity): for each polygon on diff_layer,
//! check that there exists at least one polygon on tap_layer whose bbox center
//! is within max_dist of every corner of the diff bbox. If any diff corner is
//! farther than max_dist from all taps, emit violation.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{DrcCtx, Violation};

pub struct MaxDistanceToTapRule { pub id: String, pub diff_layer: LayerId, pub tap_layer: LayerId, pub max_dist: i32 }

fn check_max_distance_to_tap(
    store: &GeometryStore, lt: &LayerTable, diff_layer: LayerId, tap_layer: LayerId,
    max_dist: i32, rule_id: &str, out: &mut Vec<Violation>,
) {
    let md2 = (max_dist as i64) * (max_dist as i64);
    // precompute tap bbox centers
    let tap_centers: Vec<(i64, i64)> = store.polys_on_layer(tap_layer).map(|t| {
        let tb = store.poly_bbox[t.0 as usize];
        (((tb.xmin as i64) + (tb.xmax as i64)) / 2,
         ((tb.ymin as i64) + (tb.ymax as i64)) / 2)
    }).collect();
    for dp in store.polys_on_layer(diff_layer) {
        let db = store.poly_bbox[dp.0 as usize];
        let corners = [
            (db.xmin as i64, db.ymin as i64),
            (db.xmax as i64, db.ymin as i64),
            (db.xmax as i64, db.ymax as i64),
            (db.xmin as i64, db.ymax as i64),
        ];
        for &(cx, cy) in &corners {
            let covered = tap_centers.iter().any(|&(tx, ty)| {
                let dx = cx - tx;
                let dy = cy - ty;
                dx * dx + dy * dy <= md2
            });
            if !covered {
                out.push(Violation {
                    rule_id: rule_id.into(), kind: "max_distance_to_tap".into(),
                    layer: lt.name(diff_layer).into(), measured: 0, limit: max_dist as i64,
                    x: cx as i32, y: cy as i32,
                    hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                });
                break; // one violation per diff polygon is enough
            }
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for MaxDistanceToTapRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_max_distance_to_tap(ctx.store, &ctx.deck.layers, self.diff_layer, self.tap_layer, self.max_dist, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::MaxDistanceToTap { id, diff_layer, tap_layer, max_dist } =>
            Some(Box::new(MaxDistanceToTapRule { id: id.clone(), diff_layer: *diff_layer, tap_layer: *tap_layer, max_dist: *max_dist })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;
