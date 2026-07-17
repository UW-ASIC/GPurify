//! Auto power-grid extraction from layout geometry + connectivity.
//!
//! Builds a [`PowerGrid`] without requiring the caller to construct one
//! by hand. One node per polygon centroid, one edge per via connection.
//! ponytail: simplified model — one node per polygon, not distributed RC mesh.

use std::collections::HashMap;

use crate::geometry::{GeometryStore, LayerId};
use crate::lvs::ExtractedNetlist;
use crate::params::Deck;

use super::power::{PowerEdge, PowerEdgeKind, PowerGrid, PowerNode};

/// Classification of nets into power, ground, or signal.
#[derive(Debug, Clone, Default)]
pub struct PowerNetClassification {
    /// (net_id, canonical_name, nominal_voltage_v)
    pub power_nets: Vec<(u32, String, f64)>,
    /// (net_id, canonical_name)
    pub ground_nets: Vec<(u32, String)>,
}

/// Common power rail patterns and their nominal voltages.
fn guess_voltage(name: &str) -> Option<f64> {
    let upper = name.to_uppercase();
    // ponytail: hardcoded heuristic, deck-driven overrides if precision matters
    match upper.as_str() {
        "VDD" | "VPWR" | "VCC" => Some(1.8),
        "VDDH" => Some(3.3),
        "VDDL" => Some(0.9),
        _ if upper.starts_with("VDD") => Some(1.8),
        _ => None,
    }
}

fn is_ground_name(name: &str) -> bool {
    let upper = name.to_uppercase();
    matches!(
        upper.as_str(),
        "VSS" | "GND" | "VGND" | "GROUND" | "DGND" | "AGND"
    ) || upper.starts_with("VSS")
}

/// Identify power/ground nets by name convention or deck `global_nets`.
pub fn identify_power_nets(
    deck: &Deck,
    net_names: &HashMap<u32, String>,
) -> PowerNetClassification {
    let mut cls = PowerNetClassification::default();
    let global_set: std::collections::HashSet<&str> =
        deck.global_nets.iter().map(|s| s.as_str()).collect();

    for (&net_id, name) in net_names {
        let is_global = global_set.contains(name.as_str());
        if is_ground_name(name) {
            cls.ground_nets.push((net_id, name.clone()));
        } else if let Some(v) = guess_voltage(name) {
            cls.power_nets.push((net_id, name.clone(), v));
        } else if is_global {
            // Global net but unrecognised name — treat as ground to be safe.
            cls.ground_nets.push((net_id, name.clone()));
        }
    }
    cls.power_nets.sort_by_key(|(id, _, _)| *id);
    cls.ground_nets.sort_by_key(|(id, _)| *id);
    cls
}

/// Extract a resistive power grid from layout polygons on power/ground nets.
///
/// Creates nodes at polygon centroids and edges from via connections.
/// Resistance from sheet resistance x L/W of conductor segments.
/// ponytail: O(polys * vias) brute force, spatial index if grids get large.
pub fn extract_power_grid(
    store: &GeometryStore,
    deck: &Deck,
    ext: &ExtractedNetlist,
    classification: &PowerNetClassification,
) -> PowerGrid {
    let dbu_um = deck.dbu_nm / 1000.0;

    // Build set of power/ground net ids and their voltages.
    let mut net_voltage: HashMap<u32, f64> = HashMap::new();
    let mut net_name_map: HashMap<u32, String> = HashMap::new();
    for (net_id, name, voltage) in &classification.power_nets {
        net_voltage.insert(*net_id, *voltage);
        net_name_map.insert(*net_id, name.clone());
    }
    for (net_id, name) in &classification.ground_nets {
        net_voltage.insert(*net_id, 0.0);
        net_name_map.insert(*net_id, name.clone());
    }

    if net_voltage.is_empty() {
        return PowerGrid::default();
    }

    // Sheet resistance lookup by layer.
    let sheet_res = |layer: LayerId| -> f64 {
        deck.pex
            .get(&layer)
            .map(|p| p.sheet_res_ohm_sq)
            .unwrap_or(0.1) // ponytail: fallback 0.1 ohm/sq, deck should specify
    };

    // Phase 1: create one node per polygon on a power/ground net.
    let mut nodes: Vec<PowerNode> = Vec::new();
    // Maps (polygon_index) -> node index in `nodes`.
    let mut poly_to_node: HashMap<u32, usize> = HashMap::new();

    for poly_idx in 0..store.poly_count() as u32 {
        let net = match ext.net_of_poly.get(poly_idx as usize) {
            Some(&n) if n != u32::MAX => n,
            _ => continue,
        };
        let nominal = match net_voltage.get(&net) {
            Some(&v) => v,
            None => continue,
        };
        let bb = store.poly_bbox[poly_idx as usize];
        let cx = (bb.xmin as i64 + bb.xmax as i64) / 2;
        let cy = (bb.ymin as i64 + bb.ymax as i64) / 2;
        let net_name = net_name_map
            .get(&net)
            .cloned()
            .unwrap_or_else(|| format!("net_{net}"));
        let is_fixed = classification
            .power_nets
            .iter()
            .any(|(id, _, _)| *id == net)
            || classification.ground_nets.iter().any(|(id, _)| *id == net);

        let node_idx = nodes.len();
        nodes.push(PowerNode {
            id: format!("{net_name}_p{poly_idx}"),
            x: cx as i32,
            y: cy as i32,
            nominal_voltage_v: nominal,
            // ponytail: first polygon on each net is the supply anchor;
            // more accurate: only pad/pin polygons should be fixed
            fixed_voltage_v: if is_fixed
                && poly_to_node.values().all(|&ni| {
                    nodes[ni].nominal_voltage_v != nominal || nodes[ni].fixed_voltage_v.is_none()
                }) {
                Some(nominal)
            } else {
                None
            },
            load_current_a: 0.0,
            check_ir_drop: true,
        });
        poly_to_node.insert(poly_idx, node_idx);
    }

    // Phase 2: create edges between polygons that share a net and overlap via bboxes.
    let mut edges = Vec::new();
    let mut edge_id = 0usize;

    // For each via layer, find polygon pairs it connects.
    for (via_layer, connected_layers) in &deck.connectivity.vias {
        let via_res = deck
            .pex
            .get(via_layer)
            .map(|p| p.via_res_ohm)
            .unwrap_or(1.0); // ponytail: fallback 1 ohm

        for via_poly in store.polys_on_layer(*via_layer) {
            let via_bb = store.poly_bbox[via_poly.0 as usize];
            // Find conductor polygons on connected layers that overlap the via.
            let mut touching_nodes: Vec<usize> = Vec::new();
            for &conn_layer in connected_layers {
                for cond_poly in store.polys_on_layer(conn_layer) {
                    if let Some(&node_idx) = poly_to_node.get(&cond_poly.0) {
                        let cond_bb = store.poly_bbox[cond_poly.0 as usize];
                        if via_bb.overlaps(&cond_bb) {
                            touching_nodes.push(node_idx);
                        }
                    }
                }
            }
            // Create edges between all pairs (ponytail: quadratic in touching count,
            // typically 2 layers per via so this is fine).
            touching_nodes.sort_unstable();
            touching_nodes.dedup();
            for i in 0..touching_nodes.len() {
                for j in (i + 1)..touching_nodes.len() {
                    let from = touching_nodes[i];
                    let to = touching_nodes[j];
                    edges.push(PowerEdge {
                        id: format!("via_e{edge_id}"),
                        from,
                        to,
                        resistance_ohm: via_res.max(1e-6),
                        length_um: 0.0,
                        kind: PowerEdgeKind::Via { cuts: 1 },
                        temperature_c: 25.0,
                        max_current_density_a_per_um2: None,
                        max_current_per_cut_a: None,
                        blech_product_limit_a_per_um: None,
                        em_exempt: false,
                    });
                    edge_id += 1;
                }
            }
        }
    }

    // Phase 3: connect same-net same-layer polygons that touch/overlap.
    let mut net_layer_polys: HashMap<(u32, LayerId), Vec<u32>> = HashMap::new();
    for (&poly_idx, &_node_idx) in &poly_to_node {
        let net = ext.net_of_poly[poly_idx as usize];
        let layer = store.poly_layer[poly_idx as usize];
        net_layer_polys
            .entry((net, layer))
            .or_default()
            .push(poly_idx);
    }
    for ((_, layer), polys) in &net_layer_polys {
        let r_sq = sheet_res(*layer);
        for i in 0..polys.len() {
            for j in (i + 1)..polys.len() {
                let bb_a = store.poly_bbox[polys[i] as usize];
                let bb_b = store.poly_bbox[polys[j] as usize];
                if !bb_a.overlaps(&bb_b) {
                    continue;
                }
                let from = poly_to_node[&polys[i]];
                let to = poly_to_node[&polys[j]];
                let dx = (bb_a.xmin + bb_a.xmax - bb_b.xmin - bb_b.xmax).unsigned_abs() as f64
                    * dbu_um
                    / 2.0;
                let dy = (bb_a.ymin + bb_a.ymax - bb_b.ymin - bb_b.ymax).unsigned_abs() as f64
                    * dbu_um
                    / 2.0;
                let length = (dx * dx + dy * dy).sqrt().max(dbu_um);
                // ponytail: approximate width as minimum bbox dimension
                let width = (bb_a.width().min(bb_b.width()) as f64 * dbu_um).max(dbu_um);
                let resistance = (r_sq * length / width).max(1e-6);
                edges.push(PowerEdge {
                    id: format!("seg_e{edge_id}"),
                    from,
                    to,
                    resistance_ohm: resistance,
                    length_um: length,
                    kind: PowerEdgeKind::Metal {
                        width_um: width,
                        thickness_um: 1.0,
                    },
                    temperature_c: 25.0,
                    max_current_density_a_per_um2: None,
                    max_current_per_cut_a: None,
                    blech_product_limit_a_per_um: None,
                    em_exempt: false,
                });
                edge_id += 1;
            }
        }
    }

    PowerGrid { nodes, edges }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_standard_power_names() {
        let deck = Deck::from_json(
            r#"{
            "layers": {"met1": {"layer": 1, "datatype": 0}},
            "drc": {},
            "pex": {}
        }"#,
        )
        .unwrap();
        let mut names = HashMap::new();
        names.insert(0, "VDD".to_string());
        names.insert(1, "VSS".to_string());
        names.insert(2, "SIG".to_string());
        let cls = identify_power_nets(&deck, &names);
        assert_eq!(cls.power_nets.len(), 1);
        assert_eq!(cls.power_nets[0].1, "VDD");
        assert_eq!(cls.ground_nets.len(), 1);
        assert_eq!(cls.ground_nets[0].1, "VSS");
    }

    #[test]
    fn empty_classification_yields_empty_grid() {
        let store = GeometryStore::new();
        let deck = Deck::from_json(
            r#"{
            "layers": {"met1": {"layer": 1, "datatype": 0}},
            "drc": {},
            "pex": {}
        }"#,
        )
        .unwrap();
        let ext = ExtractedNetlist {
            devices: Vec::new(),
            bjt_devices: Vec::new(),
            net_count: 0,
            used_nets: 0,
            net_of_poly: Vec::new(),
            label_conflicts: Vec::new(),
            two_terminal: Vec::new(),
            floating_nets: Vec::new(),
            net_names: HashMap::new(),
        };
        let cls = PowerNetClassification::default();
        let grid = extract_power_grid(&store, &deck, &ext, &cls);
        assert!(grid.nodes.is_empty());
        assert!(grid.edges.is_empty());
    }
}
