//! Overlap: two layers must overlap by >= min.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{derived, DrcCtx, Violation};

pub struct OverlapRule { pub id: String, pub a: LayerId, pub b: LayerId, pub min: i32 }

pub(crate) fn check_overlap(
    store: &GeometryStore, lt: &LayerTable, a: LayerId, b: LayerId, min: i32,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    let b_union = match derived::layer_polygon_set(store, b, Some(lt.id_to_name.len())) {
        Ok(set) => set,
        Err(_) => {
            out.push(Violation {
                rule_id: rule_id.into(), kind: "overlap_geometry_error".into(),
                layer: format!("{}:{}", lt.name(a), lt.name(b)),
                measured: -1, limit: min as i64, x: 0, y: 0,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
            return;
        }
    };
    for pa in store.polys_on_layer(a) {
        let polygon = gdsverify_core::exact::Polygon::from_outer(
            store.vertices(pa)
                .map(|(x, y)| gdsverify_core::exact::Point::new(x, y))
                .collect(),
        );
        let marker = store.poly_bbox[pa.0 as usize];
        let intersection = polygon
            .map(gdsverify_core::exact::PolygonSet::from_polygon)
            .map_err(derived::DerivedError::from)
            .and_then(|a_set| {
                gdsverify_core::exact::rectilinear_intersection(&a_set, &b_union)
                    .map_err(derived::DerivedError::from)
            });
        let Ok(intersection) = intersection else {
            out.push(Violation {
                rule_id: rule_id.into(), kind: "overlap_geometry_error".into(),
                layer: format!("{}:{}", lt.name(a), lt.name(b)),
                measured: -1, limit: min as i64, x: marker.xmin, y: marker.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
            continue;
        };
        let mut best = 0_i32;
        let mut unsupported = false;
        for component in intersection.polygons() {
            if !component.holes().is_empty() || component.outer().vertices().len() != 4 {
                unsupported = true;
                break;
            }
            let mut xs: Vec<_> = component.outer().vertices().iter().map(|p| p.x).collect();
            let mut ys: Vec<_> = component.outer().vertices().iter().map(|p| p.y).collect();
            xs.sort_unstable(); xs.dedup();
            ys.sort_unstable(); ys.dedup();
            if xs.len() != 2 || ys.len() != 2 {
                unsupported = true;
                break;
            }
            best = best.max((xs[1] - xs[0]).min(ys[1] - ys[0]));
        }
        if unsupported {
            out.push(Violation {
                rule_id: rule_id.into(), kind: "overlap_geometry_error".into(),
                layer: format!("{}:{}", lt.name(a), lt.name(b)),
                measured: -1, limit: min as i64, x: marker.xmin, y: marker.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        } else if best < min {
            out.push(Violation {
                rule_id: rule_id.into(), kind: "overlap".into(),
                layer: format!("{}:{}", lt.name(a), lt.name(b)),
                measured: best as i64, limit: min as i64,
                x: marker.xmin, y: marker.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for OverlapRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_overlap(ctx.store, &ctx.deck.layers, self.a, self.b, self.min, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::Overlap { id, a, b, min } =>
            Some(Box::new(OverlapRule { id: id.clone(), a: *a, b: *b, min: *min })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_uses_exact_contact_not_concave_bboxes() {
        let mut defs = std::collections::HashMap::new();
        defs.insert("a".to_string(), crate::params::LayerDef { layer: 1, datatype: 0 });
        defs.insert("b".to_string(), crate::params::LayerDef { layer: 2, datatype: 0 });
        let lt = LayerTable::from_defs(&defs);
        let (a, b) = (lt.id("a").unwrap(), lt.id("b").unwrap());
        let mut store = GeometryStore::new();
        store.add_polygon(a, &[
            (0, 0), (10, 0), (10, 2), (2, 2), (2, 10), (0, 10),
        ]);
        // This rectangle is inside the L-shape's bbox, but in its empty concavity.
        store.add_rect(b, 5, 5, 3, 3);
        let mut violations = Vec::new();
        check_overlap(&store, &lt, a, b, 2, "A.OVERLAP.B", &mut violations);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].measured, 0);
    }
}
