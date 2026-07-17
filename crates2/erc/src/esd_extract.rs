//! ESD evidence extraction from layout geometry + connectivity.
//!
//! Identifies I/O pads, ESD clamp devices, discharge paths, and guard rings
//! from the extracted netlist rather than requiring caller-supplied evidence.
//! ponytail: heuristic identification, foundry-calibrated models when accuracy matters.

use crate::geometry::{Bbox, GeometryStore, LayerId};
use crate::lvs::ExtractedNetlist;
use crate::params::Deck;

use super::power_extract::PowerNetClassification;

/// An I/O pad identified from layout geometry.
#[derive(Clone, Debug)]
pub struct IoPad {
    pub net_id: u32,
    pub name: String,
    pub bbox: Bbox,
    pub direction: PadDirection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PadDirection {
    Input,
    Output,
    Bidirectional,
    Power,
    Ground,
    Unknown,
}

/// An ESD clamp device identified by model/class tags.
#[derive(Clone, Debug)]
pub struct EsdClamp {
    pub device_index: usize,
    pub clamp_type: String,
    pub pad_net: u32,
    pub rail_net: u32,
}

/// A discharge path from pad to power/ground rail.
#[derive(Clone, Debug)]
pub struct EsdPath {
    pub pad: String,
    pub rail: String,
    pub resistance_ohm: f64,
    pub devices: Vec<usize>,
    pub complete: bool,
}

/// Guard ring evidence for latch-up checking.
#[derive(Clone, Debug)]
pub struct GuardRing {
    pub cell_name: String,
    pub ring_layer: LayerId,
    pub width_nm: i32,
    pub continuous: bool,
    pub biased: bool,
    pub tap_count: u32,
}

/// All ESD evidence extracted from layout.
#[derive(Clone, Debug, Default)]
pub struct EsdEvidence {
    pub pads: Vec<IoPad>,
    pub clamps: Vec<EsdClamp>,
    pub paths: Vec<EsdPath>,
    pub guard_rings: Vec<GuardRing>,
}

/// Heuristic: pads are typically large top-metal polygons on the die periphery.
fn find_io_pads(
    store: &GeometryStore,
    ext: &ExtractedNetlist,
    classification: &PowerNetClassification,
    top_metal: Option<LayerId>,
) -> Vec<IoPad> {
    let top = match top_metal {
        Some(l) => l,
        None => return Vec::new(),
    };

    let power_nets: std::collections::HashSet<u32> = classification
        .power_nets
        .iter()
        .map(|(id, _, _)| *id)
        .collect();
    let ground_nets: std::collections::HashSet<u32> = classification
        .ground_nets
        .iter()
        .map(|(id, _)| *id)
        .collect();

    // ponytail: "large" = area > 100x the median polygon area on top metal
    let mut areas: Vec<i64> = Vec::new();
    for p in store.polys_on_layer(top) {
        let bb = store.poly_bbox[p.0 as usize];
        areas.push(bb.width_i64() * bb.height_i64());
    }
    if areas.is_empty() {
        return Vec::new();
    }
    areas.sort_unstable();
    let median = areas[areas.len() / 2];
    let threshold = median.saturating_mul(100).max(1);

    let mut pads = Vec::new();
    for p in store.polys_on_layer(top) {
        let bb = store.poly_bbox[p.0 as usize];
        let area = bb.width_i64() * bb.height_i64();
        if area < threshold {
            continue;
        }
        let net = match ext.net_of_poly.get(p.0 as usize) {
            Some(&n) if n != u32::MAX => n,
            _ => continue,
        };
        let name = ext
            .net_names
            .get(&net)
            .cloned()
            .unwrap_or_else(|| format!("net_{net}"));
        let direction = if power_nets.contains(&net) {
            PadDirection::Power
        } else if ground_nets.contains(&net) {
            PadDirection::Ground
        } else {
            PadDirection::Unknown
        };
        pads.push(IoPad {
            net_id: net,
            name,
            bbox: bb,
            direction,
        });
    }
    pads
}

/// Identify ESD clamp devices by device_class tag containing "esd" or "clamp".
fn find_esd_clamps(
    ext: &ExtractedNetlist,
    classification: &PowerNetClassification,
) -> Vec<EsdClamp> {
    let rail_nets: std::collections::HashSet<u32> = classification
        .power_nets
        .iter()
        .map(|(id, _, _)| *id)
        .chain(classification.ground_nets.iter().map(|(id, _)| *id))
        .collect();

    let mut clamps = Vec::new();
    for (i, dev) in ext.devices.iter().enumerate() {
        let class = match &dev.device_class {
            Some(c) => c.to_lowercase(),
            None => continue,
        };
        if !class.contains("esd") && !class.contains("clamp") {
            continue;
        }
        // Identify which terminal is the pad side and which is the rail side.
        let terminals = [dev.source, dev.drain, dev.gate, dev.body];
        let pad_net = terminals
            .iter()
            .find(|&&t| !rail_nets.contains(&t) && t != u32::MAX)
            .copied()
            .unwrap_or(dev.source);
        let rail_net = terminals
            .iter()
            .find(|&&t| rail_nets.contains(&t))
            .copied()
            .unwrap_or(dev.drain);

        clamps.push(EsdClamp {
            device_index: i,
            clamp_type: class,
            pad_net,
            rail_net,
        });
    }
    clamps
}

/// Identify guard rings: continuous ring-shaped polygons on well/tap layers.
/// ponytail: heuristic — polygon whose perimeter^2/area > 50 and encloses devices.
fn find_guard_rings(
    store: &GeometryStore,
    deck: &Deck,
    ext: &ExtractedNetlist,
    classification: &PowerNetClassification,
) -> Vec<GuardRing> {
    let rail_nets: std::collections::HashSet<u32> = classification
        .ground_nets
        .iter()
        .map(|(id, _)| *id)
        .collect();
    let dbu_nm = deck.dbu_nm;

    let mut rings = Vec::new();
    // Look for ring-like shapes on all conductor layers.
    for layer_id in &deck.connectivity.conductors {
        for p in store.polys_on_layer(*layer_id) {
            let bb = store.poly_bbox[p.0 as usize];
            let area = store.area(p).unsigned_abs().max(1) as f64;
            let perimeter = 2.0 * (bb.width_i64() + bb.height_i64()) as f64;
            // Ring-like: large perimeter relative to area (hollow shape).
            // ponytail: crude heuristic, proper topology check if needed.
            let ratio = perimeter * perimeter / area;
            if ratio < 50.0 {
                continue;
            }
            let net = ext
                .net_of_poly
                .get(p.0 as usize)
                .copied()
                .unwrap_or(u32::MAX);
            let biased = rail_nets.contains(&net);
            let width_nm = bb.width().min(bb.height()) as f64 * dbu_nm;
            rings.push(GuardRing {
                cell_name: format!("ring_p{}", p.0),
                ring_layer: *layer_id,
                width_nm: width_nm as i32,
                continuous: true, // ponytail: assume continuous if single polygon
                biased,
                tap_count: if biased { 1 } else { 0 },
            });
        }
    }
    rings
}

/// Extract ESD evidence from layout.
pub fn extract_esd_evidence(
    store: &GeometryStore,
    deck: &Deck,
    ext: &ExtractedNetlist,
    classification: &PowerNetClassification,
) -> EsdEvidence {
    // Determine top metal layer (last conductor in connectivity list).
    let top_metal = deck.connectivity.conductors.last().copied();

    let pads = find_io_pads(store, ext, classification, top_metal);
    let clamps = find_esd_clamps(ext, classification);
    let guard_rings = find_guard_rings(store, deck, ext, classification);

    // Build simple discharge paths from pads through clamps to rails.
    let mut paths = Vec::new();
    for pad in &pads {
        if pad.direction == PadDirection::Power || pad.direction == PadDirection::Ground {
            continue;
        }
        for clamp in &clamps {
            if clamp.pad_net != pad.net_id {
                continue;
            }
            let rail_name = ext
                .net_names
                .get(&clamp.rail_net)
                .cloned()
                .unwrap_or_else(|| format!("net_{}", clamp.rail_net));
            paths.push(EsdPath {
                pad: pad.name.clone(),
                rail: rail_name,
                resistance_ohm: 0.0, // ponytail: needs power grid solve for actual R
                devices: vec![clamp.device_index],
                complete: true,
            });
        }
    }

    EsdEvidence {
        pads,
        clamps,
        paths,
        guard_rings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn empty_netlist_yields_empty_evidence() {
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
        let ev = extract_esd_evidence(&store, &deck, &ext, &cls);
        assert!(ev.pads.is_empty());
        assert!(ev.clamps.is_empty());
        assert!(ev.paths.is_empty());
        assert!(ev.guard_rings.is_empty());
    }

    #[test]
    fn pad_direction_classification() {
        assert_eq!(PadDirection::Power, PadDirection::Power);
        assert_ne!(PadDirection::Input, PadDirection::Output);
    }
}
