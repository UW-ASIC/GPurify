//! Derived layer evaluation — boolean operations on polygon layers.
//!
//! Operates on bounding boxes (sufficient for manhattan geometry):
//!   - `And(layers)` → intersection of all named layers
//!   - `Subtract { base, minus }` → base regions not covered by minus
//!   - `Or(layers)` → union (concat polygon lists)

use crate::geometry::*;
use crate::params::LayerTable;
use crate::schema::{DerivedLayerOp, DerivedLayerSchema};
use std::collections::HashMap;

/// Evaluate all derived layers, adding new polygons to the store.
/// Returns a mapping from derived layer name → LayerId.
pub fn evaluate_derived_layers(
    store: &mut GeometryStore,
    lt: &LayerTable,
    derived: &[DerivedLayerSchema],
) -> HashMap<String, LayerId> {
    let mut derived_ids: HashMap<String, LayerId> = HashMap::new();
    // Allocate LayerIds for derived layers beyond the existing ones
    let mut next_id = lt.id_to_name.len() as LayerId;

    for dl in derived {
        let lid = next_id;
        next_id += 1;
        derived_ids.insert(dl.name.clone(), lid);

        match &dl.op {
            DerivedLayerOp::And(layer_names) => {
                let layers: Vec<LayerId> = layer_names
                    .iter()
                    .filter_map(|n| lt.id(n).or_else(|| derived_ids.get(n).copied()))
                    .collect();
                if layers.is_empty() {
                    continue;
                }
                // For each polygon on the first layer, check if ALL other layers overlap
                let base = layers[0];
                let rest = &layers[1..];
                let base_polys: Vec<Bbox> = store
                    .polys_on_layer(base)
                    .map(|p| store.poly_bbox[p.0 as usize])
                    .collect();
                for bp in &base_polys {
                    let mut isect = *bp;
                    let mut all_overlap = true;
                    for &rl in rest {
                        let overlaps = store
                            .polys_on_layer(rl)
                            .any(|p| store.poly_bbox[p.0 as usize].overlaps(&isect));
                        if !overlaps {
                            all_overlap = false;
                            break;
                        }
                        // Tighten intersection bbox
                        for p in store.polys_on_layer(rl) {
                            let ob = store.poly_bbox[p.0 as usize];
                            if ob.overlaps(&isect) {
                                isect = Bbox {
                                    xmin: isect.xmin.max(ob.xmin),
                                    ymin: isect.ymin.max(ob.ymin),
                                    xmax: isect.xmax.min(ob.xmax),
                                    ymax: isect.ymax.min(ob.ymax),
                                };
                                break;
                            }
                        }
                    }
                    if all_overlap && isect.width() > 0 && isect.height() > 0 {
                        store.add_rect(lid, isect.xmin, isect.ymin, isect.width(), isect.height());
                    }
                }
            }
            DerivedLayerOp::Subtract { base, minus } => {
                let base_lid = lt.id(base).or_else(|| derived_ids.get(base).copied());
                let minus_lid = lt.id(minus).or_else(|| derived_ids.get(minus).copied());
                let (Some(bl), Some(ml)) = (base_lid, minus_lid) else {
                    continue;
                };
                let minus_bboxes: Vec<Bbox> = store
                    .polys_on_layer(ml)
                    .map(|p| store.poly_bbox[p.0 as usize])
                    .collect();
                let base_bboxes: Vec<Bbox> = store
                    .polys_on_layer(bl)
                    .map(|p| store.poly_bbox[p.0 as usize])
                    .collect();
                for bp in &base_bboxes {
                    let remainders = subtract_bbox(*bp, &minus_bboxes);
                    for r in remainders {
                        if r.width() > 0 && r.height() > 0 {
                            store.add_rect(lid, r.xmin, r.ymin, r.width(), r.height());
                        }
                    }
                }
            }
            DerivedLayerOp::Or(layer_names) => {
                let layers: Vec<LayerId> = layer_names
                    .iter()
                    .filter_map(|n| lt.id(n).or_else(|| derived_ids.get(n).copied()))
                    .collect();
                let all_bboxes: Vec<Bbox> = layers
                    .iter()
                    .flat_map(|&l| {
                        store
                            .polys_on_layer(l)
                            .map(|p| store.poly_bbox[p.0 as usize])
                            .collect::<Vec<_>>()
                    })
                    .collect();
                for bb in all_bboxes {
                    store.add_rect(lid, bb.xmin, bb.ymin, bb.width(), bb.height());
                }
            }
        }
    }
    derived_ids
}

/// Subtract all `minus` bboxes from `base`, producing remaining rectangles.
/// For manhattan geometry, subtracting one rectangle from another produces at most 4.
fn subtract_bbox(base: Bbox, minus: &[Bbox]) -> Vec<Bbox> {
    let mut rects = vec![base];
    for m in minus {
        let mut next = Vec::new();
        for r in rects {
            // If no overlap, keep as-is
            let ox_min = r.xmin.max(m.xmin);
            let ox_max = r.xmax.min(m.xmax);
            let oy_min = r.ymin.max(m.ymin);
            let oy_max = r.ymax.min(m.ymax);
            if ox_min >= ox_max || oy_min >= oy_max {
                next.push(r);
                continue;
            }
            // Top strip
            if r.ymax > oy_max {
                next.push(Bbox {
                    xmin: r.xmin,
                    ymin: oy_max,
                    xmax: r.xmax,
                    ymax: r.ymax,
                });
            }
            // Bottom strip
            if r.ymin < oy_min {
                next.push(Bbox {
                    xmin: r.xmin,
                    ymin: r.ymin,
                    xmax: r.xmax,
                    ymax: oy_min,
                });
            }
            // Left strip (between top/bottom)
            if r.xmin < ox_min {
                next.push(Bbox {
                    xmin: r.xmin,
                    ymin: oy_min,
                    xmax: ox_min,
                    ymax: oy_max,
                });
            }
            // Right strip (between top/bottom)
            if r.xmax > ox_max {
                next.push(Bbox {
                    xmin: ox_max,
                    ymin: oy_min,
                    xmax: r.xmax,
                    ymax: oy_max,
                });
            }
        }
        rects = next;
    }
    rects
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn and_intersection() {
        let mut store = GeometryStore::new();
        let la: LayerId = 0;
        let lb: LayerId = 1;
        store.add_rect(la, 0, 0, 100, 100);
        store.add_rect(lb, 50, 50, 100, 100);

        let mut lt = crate::params::LayerTable::default();
        lt.name_to_id.insert("a".into(), la);
        lt.id_to_name.push("a".into());
        lt.id_to_gds.push((0, 0));
        lt.name_to_id.insert("b".into(), lb);
        lt.id_to_name.push("b".into());
        lt.id_to_gds.push((1, 0));

        let derived = vec![DerivedLayerSchema {
            name: "ab".into(),
            op: DerivedLayerOp::And(vec!["a".into(), "b".into()]),
        }];
        let ids = evaluate_derived_layers(&mut store, &lt, &derived);
        let ab_id = ids["ab"];
        let ab_polys: Vec<_> = store.polys_on_layer(ab_id).collect();
        assert_eq!(ab_polys.len(), 1);
        let bb = store.poly_bbox[ab_polys[0].0 as usize];
        assert_eq!((bb.xmin, bb.ymin, bb.xmax, bb.ymax), (50, 50, 100, 100));
    }

    #[test]
    fn subtract_removes_overlap() {
        let base = Bbox {
            xmin: 0,
            ymin: 0,
            xmax: 100,
            ymax: 100,
        };
        let minus = vec![Bbox {
            xmin: 25,
            ymin: 25,
            xmax: 75,
            ymax: 75,
        }];
        let r = subtract_bbox(base, &minus);
        assert_eq!(r.len(), 4); // top, bottom, left, right strips
        let total_area: i64 = r.iter().map(|b| b.width() as i64 * b.height() as i64).sum();
        assert_eq!(total_area, 100 * 100 - 50 * 50);
    }
}
