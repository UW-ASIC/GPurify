//! Device recognition for Wave 4 (L4.3).
//!
//! MOS recognition lives in extract.rs (pick_type_and_flavor + the gate-split
//! loop). BJT and two-terminal extraction also live there. This module holds
//! the resistor, capacitor, and diode extraction families that operate on
//! deck-driven rules after connectivity is established.

use super::extract::{full_region, poly_poly_overlap, rectilinear_intersection_area};
use crate::geometry::{GeometryStore, PolyId};
use crate::params::Deck;

// --- L4.3 device records ---

/// Extracted resistor with geometry-derived properties.
#[derive(Debug, Clone)]
pub struct ResistorDevice {
    pub terminal_a: u32,
    pub terminal_b: u32,
    pub body_polygon: PolyId,
    pub sheet_rho: f64,
    pub length: i32,
    pub width: i32,
    pub segments: u32,
}

/// Extracted capacitor with geometry-derived properties.
#[derive(Debug, Clone)]
pub struct CapacitorDevice {
    pub terminal_top: u32,
    pub terminal_bot: u32,
    pub area: i64,
    pub perimeter: i64,
}

/// Extracted diode.
#[derive(Debug, Clone)]
pub struct DiodeDevice {
    pub anode: u32,
    pub cathode: u32,
    pub area: i64,
    pub perimeter: i64,
}

// --- L4.3 extraction ---

/// Extract resistors from body/marker/terminal layer rules in the deck.
/// For each body polygon with marker overlap (and no gate crossing), finds
/// terminal overlaps and computes R = Rsh * L/W from bounding box geometry.
pub fn extract_resistors(
    store: &GeometryStore,
    deck: &Deck,
    net_of_poly: &[u32],
) -> Vec<ResistorDevice> {
    let mut out = Vec::new();
    let gate_layers: Vec<_> = deck
        .devices
        .mos_rules
        .iter()
        .map(|r| r.gate_layer)
        .collect();

    for rule in &deck.devices.resistor_rules {
        for body in store.polys_on_layer(rule.body_layer) {
            let bb = store.poly_bbox[body.0 as usize];
            // Must have marker overlap
            let has_marker = store
                .polys_on_layer(rule.marker_layer)
                .any(|m| poly_poly_overlap(store, m, body));
            if !has_marker {
                continue;
            }
            // Skip if this poly is used as a gate
            let is_gate = gate_layers.iter().any(|&gl| {
                store
                    .polys_on_layer(gl)
                    .any(|g| poly_poly_overlap(store, body, g))
            });
            if is_gate {
                continue;
            }

            // Find terminal overlaps sorted along long axis
            let long_axis_x = bb.width() >= bb.height();
            let mut terminals: Vec<(u32, i32)> = Vec::new();
            for tc in store.polys_on_layer(rule.terminal_layer) {
                if !poly_poly_overlap(store, tc, body) {
                    continue;
                }
                let net = net_of_poly[tc.0 as usize];
                if net == u32::MAX {
                    continue;
                }
                let tb = store.poly_bbox[tc.0 as usize];
                let pos = if long_axis_x {
                    (tb.xmin + tb.xmax) / 2
                } else {
                    (tb.ymin + tb.ymax) / 2
                };
                terminals.push((net, pos));
            }
            if terminals.len() < 2 {
                continue;
            }
            terminals.sort_by_key(|&(_, p)| p);

            let ta = terminals.first().unwrap().0;
            let tb_net = terminals.last().unwrap().0;
            let (length, width) = if long_axis_x {
                (bb.width(), bb.height())
            } else {
                (bb.height(), bb.width())
            };
            // ponytail: Rsh from PEX table; 0.0 if body layer has no PEX entry.
            let sheet_rho = deck
                .pex
                .get(&rule.body_layer)
                .map_or(0.0, |p| p.sheet_res_ohm_sq);

            out.push(ResistorDevice {
                terminal_a: ta,
                terminal_b: tb_net,
                body_polygon: body,
                sheet_rho,
                length,
                width,
                // ponytail: single segment from bbox; multi-segment when serpentine
                // detection is needed.
                segments: 1,
            });
        }
    }
    out
}

/// Extract capacitors from top/bottom plate overlap rules in the deck.
/// Computes overlap area as capacitance proxy.
pub fn extract_capacitors(
    store: &GeometryStore,
    deck: &Deck,
    net_of_poly: &[u32],
) -> Vec<CapacitorDevice> {
    let mut out = Vec::new();
    for rule in &deck.devices.cap_rules {
        for top in store.polys_on_layer(rule.top_layer) {
            let tb = store.poly_bbox[top.0 as usize];
            for bot in store.polys_on_layer(rule.bottom_layer) {
                let bb = store.poly_bbox[bot.0 as usize];
                if !tb.overlaps(&bb) {
                    continue;
                }
                let overlap = rectilinear_intersection_area(
                    store,
                    &[full_region(store, top), full_region(store, bot)],
                );
                if overlap <= 0 {
                    continue;
                }
                if let Some(marker_l) = rule.marker_layer {
                    let has_marker = store.polys_on_layer(marker_l).any(|m| {
                        rectilinear_intersection_area(
                            store,
                            &[
                                full_region(store, m),
                                full_region(store, top),
                                full_region(store, bot),
                            ],
                        ) > 0
                    });
                    if !has_marker {
                        continue;
                    }
                }
                let t_net = net_of_poly[top.0 as usize];
                let b_net = net_of_poly[bot.0 as usize];
                if t_net == u32::MAX || b_net == u32::MAX {
                    continue;
                }

                // ponytail: overlap bbox for perimeter; exact perimeter needs
                // intersection polygon outline, add if fringe capacitance matters.
                let ix0 = tb.xmin.max(bb.xmin);
                let iy0 = tb.ymin.max(bb.ymin);
                let ix1 = tb.xmax.min(bb.xmax);
                let iy1 = tb.ymax.min(bb.ymax);
                let perimeter = 2 * ((ix1 - ix0) as i64 + (iy1 - iy0) as i64);

                out.push(CapacitorDevice {
                    terminal_top: t_net,
                    terminal_bot: b_net,
                    area: overlap as i64,
                    perimeter,
                });
            }
        }
    }
    out
}

/// Extract diodes from anode/cathode layer junction with implant marker.
/// Computes area and perimeter from the intersection bounding box.
pub fn extract_diodes(store: &GeometryStore, deck: &Deck, net_of_poly: &[u32]) -> Vec<DiodeDevice> {
    let mut out = Vec::new();
    for rule in &deck.devices.diode_rules {
        for anode in store.polys_on_layer(rule.anode_layer) {
            let ab = store.poly_bbox[anode.0 as usize];
            for cathode in store.polys_on_layer(rule.cathode_layer) {
                let cb = store.poly_bbox[cathode.0 as usize];
                if !ab.overlaps(&cb) || !poly_poly_overlap(store, anode, cathode) {
                    continue;
                }
                let has_implant = store.polys_on_layer(rule.implant_layer).any(|imp| {
                    rectilinear_intersection_area(
                        store,
                        &[
                            full_region(store, imp),
                            full_region(store, anode),
                            full_region(store, cathode),
                        ],
                    ) > 0
                });
                if !has_implant {
                    continue;
                }
                let a_net = net_of_poly[anode.0 as usize];
                let c_net = net_of_poly[cathode.0 as usize];
                if a_net == u32::MAX || c_net == u32::MAX {
                    continue;
                }

                // ponytail: bbox intersection for area/perimeter; exact junction
                // area needs polygon clipping, add if mismatch rate matters.
                let ix0 = ab.xmin.max(cb.xmin);
                let iy0 = ab.ymin.max(cb.ymin);
                let ix1 = ab.xmax.min(cb.xmax);
                let iy1 = ab.ymax.min(cb.ymax);
                let w = (ix1 - ix0) as i64;
                let h = (iy1 - iy0) as i64;
                let area = w * h;
                let perimeter = 2 * (w + h);

                out.push(DiodeDevice {
                    anode: a_net,
                    cathode: c_net,
                    area,
                    perimeter,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geometry::GeometryStore;
    use crate::params::{
        CapRule, ConnectivityConfig, Deck, DeviceConfig, DiodeRule, ErcParams, LayerDef,
        LayerTable, ResistorRule,
    };
    use std::collections::HashMap;

    fn make_deck(
        layers_defs: &[(&str, i32, i32)],
        conductors: Vec<&str>,
        devices: DeviceConfig,
    ) -> Deck {
        let defs: HashMap<String, LayerDef> = layers_defs
            .iter()
            .map(|&(n, l, d)| {
                (
                    n.to_string(),
                    LayerDef {
                        layer: l,
                        datatype: d,
                    },
                )
            })
            .collect();
        let layers = LayerTable::from_defs(&defs);
        let conds = conductors.iter().filter_map(|n| layers.id(n)).collect();
        Deck {
            layers,
            drc_rules: Vec::new(),
            pex: HashMap::new(),
            dbu_nm: 1.0,
            lvs_cut_required: false,
            strict: false,
            connectivity: ConnectivityConfig {
                conductors: conds,
                vias: Vec::new(),
            },
            devices,
            w_tolerance: crate::schema::PropertyTolerance::default(),
            l_tolerance: crate::schema::PropertyTolerance::default(),
            fail_on_floating: false,
            erc: ErcParams::default(),
            intra_layer_touch: false,
            global_nets: Vec::new(),
            device_catalog: HashMap::new(),
            pex_method: Default::default(),
        }
    }

    #[test]
    fn extract_resistor_from_body_marker_terminal() {
        let layer_defs = [("body", 1, 0), ("marker", 2, 0), ("term", 3, 0)];
        let deck = make_deck(
            &layer_defs,
            vec!["body", "marker", "term"],
            DeviceConfig {
                resistor_rules: vec![ResistorRule {
                    name: "rpoly".into(),
                    body_layer: 0, // will be resolved below
                    marker_layer: 0,
                    terminal_layer: 0,
                }],
                ..Default::default()
            },
        );
        // Fix up layer IDs
        let body_l = deck.layers.id("body").unwrap();
        let marker_l = deck.layers.id("marker").unwrap();
        let term_l = deck.layers.id("term").unwrap();
        let mut deck = deck;
        deck.devices.resistor_rules[0].body_layer = body_l;
        deck.devices.resistor_rules[0].marker_layer = marker_l;
        deck.devices.resistor_rules[0].terminal_layer = term_l;

        let mut st = GeometryStore::new();
        // Body: 200 long, 50 wide
        st.add_rect(body_l, 0, 0, 200, 50);
        // Marker covers body
        st.add_rect(marker_l, -10, -10, 220, 70);
        // Two terminal contacts at ends
        st.add_rect(term_l, 0, 10, 20, 30); // left end
        st.add_rect(term_l, 180, 10, 20, 30); // right end

        // Fake net_of_poly: each poly gets its own net
        let net_of_poly: Vec<u32> = (0..st.poly_count() as u32).collect();

        let resistors = extract_resistors(&st, &deck, &net_of_poly);
        assert_eq!(resistors.len(), 1, "should find one resistor");
        let r = &resistors[0];
        assert_eq!(r.length, 200);
        assert_eq!(r.width, 50);
        assert_eq!(r.segments, 1);
    }

    #[test]
    fn extract_capacitor_from_overlap() {
        let layer_defs = [("top", 1, 0), ("bot", 2, 0)];
        let deck = make_deck(
            &layer_defs,
            vec!["top", "bot"],
            DeviceConfig {
                cap_rules: vec![CapRule {
                    name: "mimcap".into(),
                    top_layer: 0,
                    bottom_layer: 0,
                    marker_layer: None,
                }],
                ..Default::default()
            },
        );
        let top_l = deck.layers.id("top").unwrap();
        let bot_l = deck.layers.id("bot").unwrap();
        let mut deck = deck;
        deck.devices.cap_rules[0].top_layer = top_l;
        deck.devices.cap_rules[0].bottom_layer = bot_l;

        let mut st = GeometryStore::new();
        st.add_rect(top_l, 0, 0, 100, 100);
        st.add_rect(bot_l, 50, 50, 100, 100);

        let net_of_poly: Vec<u32> = (0..st.poly_count() as u32).collect();
        let caps = extract_capacitors(&st, &deck, &net_of_poly);
        assert_eq!(caps.len(), 1);
        assert!(caps[0].area > 0, "overlap area should be positive");
    }

    #[test]
    fn extract_diode_from_junction() {
        let layer_defs = [("anode", 1, 0), ("cathode", 2, 0), ("implant", 3, 0)];
        let deck = make_deck(
            &layer_defs,
            vec!["anode", "cathode"],
            DeviceConfig {
                diode_rules: vec![DiodeRule {
                    name: "pd".into(),
                    anode_layer: 0,
                    cathode_layer: 0,
                    implant_layer: 0,
                }],
                ..Default::default()
            },
        );
        let anode_l = deck.layers.id("anode").unwrap();
        let cathode_l = deck.layers.id("cathode").unwrap();
        let implant_l = deck.layers.id("implant").unwrap();
        let mut deck = deck;
        deck.devices.diode_rules[0].anode_layer = anode_l;
        deck.devices.diode_rules[0].cathode_layer = cathode_l;
        deck.devices.diode_rules[0].implant_layer = implant_l;

        let mut st = GeometryStore::new();
        st.add_rect(anode_l, 0, 0, 100, 100);
        st.add_rect(cathode_l, 50, 0, 100, 100);
        st.add_rect(implant_l, 0, 0, 200, 100);

        let net_of_poly: Vec<u32> = (0..st.poly_count() as u32).collect();
        let diodes = extract_diodes(&st, &deck, &net_of_poly);
        assert_eq!(diodes.len(), 1);
        assert!(diodes[0].area > 0);
        assert!(diodes[0].perimeter > 0);
    }
}
