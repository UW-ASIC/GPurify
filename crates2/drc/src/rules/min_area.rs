//! Min area over merged (boolean-union) connected components.

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{derived, DrcCtx, Violation};

pub struct MinAreaRule { pub id: String, pub layer: LayerId, pub min: i64 }

// Real DRC measures connected union components. Summing fragment areas is
// a false-clean when fragments overlap, so use the shared exact boolean.
pub(crate) fn check_min_area(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, min: i64,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    let merged = match derived::layer_polygon_set(store, layer, Some(lt.id_to_name.len())) {
        Ok(merged) => merged,
        Err(_) => {
            let marker = store.polys_on_layer(layer).next()
                .map(|poly| store.poly_bbox[poly.0 as usize])
                .unwrap_or(Bbox { xmin: 0, ymin: 0, xmax: 0, ymax: 0 });
            out.push(Violation {
                rule_id: rule_id.into(), kind: "min_area_geometry_error".into(),
                layer: lt.name(layer).into(), measured: -1, limit: min,
                x: marker.xmin, y: marker.ymin,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
            return;
        }
    };
    for polygon in merged.polygons() {
        let area = polygon.area2() / 2;
        if area < i128::from(min) {
            let marker = polygon.outer().vertices()[0];
            out.push(Violation {
                rule_id: rule_id.into(), kind: "min_area".into(),
                layer: lt.name(layer).into(),
                measured: i64::try_from(area).unwrap_or(i64::MAX), limit: min,
                x: marker.x, y: marker.y,
                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
            });
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for MinAreaRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_min_area(ctx.store, &ctx.deck.layers, self.layer, self.min, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::MinArea { id, layer, min } =>
            Some(Box::new(MinAreaRule { id: id.clone(), layer: *layer, min: *min })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::overlap::check_overlap;

    #[test]
    fn min_area_uses_boolean_union_and_overlap_requires_a_counterpart() {
        let mut defs = std::collections::HashMap::new();
        defs.insert("a".to_string(), crate::params::LayerDef { layer: 1, datatype: 0 });
        defs.insert("b".to_string(), crate::params::LayerDef { layer: 2, datatype: 0 });
        let lt = LayerTable::from_defs(&defs);
        let (a, b) = (lt.id("a").unwrap(), lt.id("b").unwrap());
        let mut store = GeometryStore::new();
        store.add_rect(a, 0, 0, 10, 10);
        store.add_rect(a, 5, 0, 10, 10);

        let mut violations = Vec::new();
        check_min_area(&store, &lt, a, 175, "A.MIN", &mut violations);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].measured, 150);

        violations.clear();
        check_overlap(&store, &lt, a, b, 2, "A.OVERLAP.B", &mut violations);
        assert_eq!(violations.len(), 2);
        assert!(violations.iter().all(|violation| violation.measured == 0));
    }
}
