//! Min enclosed area (actual hole/keyhole area).

use crate::backend::Backend;
use crate::geometry::*;
use crate::params::LayerTable;
use super::super::{keyhole_hole_rings, DrcCtx, Violation};

pub struct MinEnclosedAreaRule { pub id: String, pub layer: LayerId, pub min_hole_area: i64 }

pub(crate) fn check_min_enclosed_area(
    store: &GeometryStore, lt: &LayerTable, layer: LayerId, min_hole_area: i64,
    rule_id: &str, out: &mut Vec<Violation>,
) {
    for polygon in store.polys_on_layer(layer) {
        for hole in keyhole_hole_rings(store, polygon) {
            let area = hole.signed_area2().abs() / 2;
            if area < i128::from(min_hole_area) {
                let marker = hole.vertices()[0];
                out.push(Violation {
                    rule_id: rule_id.into(), kind: "min_enclosed_area".into(),
                    layer: lt.name(layer).into(),
                    measured: i64::try_from(area).unwrap_or(i64::MAX),
                    limit: min_hole_area, x: marker.x, y: marker.y,
                    hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                });
            }
        }
    }
}

impl<'a> crate::rule::Rule<DrcCtx<'a>> for MinEnclosedAreaRule {
    type Finding = Violation;
    fn id(&self) -> &str { &self.id }
    fn check(&self, ctx: &DrcCtx<'a>, _backend: Backend) -> Vec<Violation> {
        let mut out = Vec::new();
        check_min_enclosed_area(ctx.store, &ctx.deck.layers, self.layer, self.min_hole_area, &self.id, &mut out);
        out
    }
}

fn factory(param: &crate::params::DrcRuleParam, _strict: bool) -> Option<super::BoxedRule> {
    match param {
        crate::params::DrcRuleParam::MinEnclosedArea { id, layer, min_hole_area } =>
            Some(Box::new(MinEnclosedAreaRule { id: id.clone(), layer: *layer, min_hole_area: *min_hole_area })),
        _ => None,
    }
}
pub static FACTORY: super::Factory = factory;

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::cheesing::check_cheesing;

    #[test]
    fn only_actual_keyhole_cycles_count_as_holes_or_slots() {
        let mut defs = std::collections::HashMap::new();
        defs.insert("m1".to_string(), crate::params::LayerDef { layer: 1, datatype: 0 });
        let lt = LayerTable::from_defs(&defs);
        let m1 = lt.id("m1").unwrap();

        let mut nested_material = GeometryStore::new();
        nested_material.add_rect(m1, 0, 0, 20, 20);
        nested_material.add_rect(m1, 8, 8, 4, 4);
        let mut violations = Vec::new();
        check_min_enclosed_area(&nested_material, &lt, m1, 40, "M1.HOLE", &mut violations);
        assert!(violations.is_empty(), "same-polarity material became a hole");
        check_cheesing(&nested_material, &lt, m1, 100, "M1.SLOT", &mut violations);
        assert_eq!(violations.len(), 1, "nested material waived cheesing");

        let mut keyhole = GeometryStore::new();
        keyhole.add_polygon(m1, &[
            (0, 0), (20, 0), (20, 20), (12, 20), (12, 16),
            (16, 16), (16, 12), (8, 12), (8, 16), (12, 16),
            (12, 20), (0, 20),
        ]);
        violations.clear();
        check_min_enclosed_area(&keyhole, &lt, m1, 40, "M1.HOLE", &mut violations);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].measured, 32);
        violations.clear();
        check_cheesing(&keyhole, &lt, m1, 100, "M1.SLOT", &mut violations);
        assert!(violations.is_empty());
    }
}
