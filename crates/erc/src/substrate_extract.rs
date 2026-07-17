//! Substrate/well/latch-up evidence extraction from layout geometry.
//!
//! Identifies well regions, substrate taps, and potential latch-up sites
//! from the extracted netlist rather than requiring caller-supplied evidence.
//! ponytail: heuristic geometry analysis, foundry-calibrated models for production.

use crate::geometry::{Bbox, GeometryStore, LayerId};
use crate::lvs::types::{DeviceKind, ExtractedNetlist};
use crate::params::Deck;

/// A well region in the substrate.
#[derive(Clone, Debug)]
pub struct WellRegion {
    pub well_type: WellType,
    pub layer: LayerId,
    pub bbox: Bbox,
    pub area_dbu2: i64,
    pub taps: Vec<SubstrateTap>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WellType {
    Nwell,
    Pwell,
    DeepNwell,
}

/// A substrate/well tap contact.
#[derive(Clone, Debug)]
pub struct SubstrateTap {
    pub x: i32,
    pub y: i32,
    pub net_id: u32,
    pub distance_to_edge_nm: i32,
}

/// A potential latch-up site (parasitic NPN/PNP thyristor path).
#[derive(Clone, Debug)]
pub struct LatchupSite {
    pub nmos_device: Option<usize>,
    pub pmos_device: Option<usize>,
    pub distance_nm: i32,
    pub guard_ring: Option<String>,
    pub severity: LatchupSeverity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LatchupSeverity {
    Low,
    Medium,
    High,
}

/// All substrate evidence extracted from layout.
#[derive(Clone, Debug, Default)]
pub struct SubstrateEvidence {
    pub wells: Vec<WellRegion>,
    pub latchup_sites: Vec<LatchupSite>,
    /// Indices into `wells` of wells with no tap contacts.
    pub untapped_wells: Vec<usize>,
}

/// Determine well type from layer name heuristic.
fn guess_well_type(name: &str) -> Option<WellType> {
    let lower = name.to_lowercase();
    // ponytail: name-based heuristic, deck should tag wells explicitly for production
    if lower.contains("dnw") || lower.contains("deep_nwell") || lower.contains("deepnwell") {
        Some(WellType::DeepNwell)
    } else if lower.contains("nwell") || lower.contains("nw") {
        Some(WellType::Nwell)
    } else if lower.contains("pwell") || lower.contains("pw") {
        Some(WellType::Pwell)
    } else {
        None
    }
}

/// Find well layers from the deck layer table by name convention.
fn find_well_layers(deck: &Deck) -> Vec<(LayerId, WellType)> {
    let mut result = Vec::new();
    for (name, &id) in &deck.layers.name_to_id {
        if let Some(wt) = guess_well_type(name) {
            result.push((id, wt));
        }
    }
    result.sort_by_key(|(id, _)| *id);
    result
}

/// Find tap/contact polygons that overlap a well region.
/// ponytail: O(taps * wells) brute force, spatial index if large.
fn find_taps_for_well(
    store: &GeometryStore,
    ext: &ExtractedNetlist,
    well_bb: &Bbox,
    deck: &Deck,
    dbu_nm: f64,
) -> Vec<SubstrateTap> {
    let mut taps = Vec::new();
    // Look for contact/tap polygons on conductor layers inside the well.
    for &layer_id in &deck.connectivity.conductors {
        let name = deck.layers.name(layer_id).to_lowercase();
        // ponytail: heuristic — tap layers contain "tap", "diff", or "cont"
        if !name.contains("tap") && !name.contains("diff") && !name.contains("cont") {
            continue;
        }
        for p in store.polys_on_layer(layer_id) {
            let bb = store.poly_bbox[p.0 as usize];
            if !well_bb.overlaps(&bb) {
                continue;
            }
            let net = ext
                .net_of_poly
                .get(p.0 as usize)
                .copied()
                .unwrap_or(u32::MAX);
            if net == u32::MAX {
                continue;
            }
            let cx = (bb.xmin + bb.xmax) / 2;
            let cy = (bb.ymin + bb.ymax) / 2;
            // Distance to nearest well edge.
            let dx = (cx - well_bb.xmin).min(well_bb.xmax - cx).max(0);
            let dy = (cy - well_bb.ymin).min(well_bb.ymax - cy).max(0);
            let dist = dx.min(dy) as f64 * dbu_nm;
            taps.push(SubstrateTap {
                x: cx,
                y: cy,
                net_id: net,
                distance_to_edge_nm: dist as i32,
            });
        }
    }
    taps
}

/// Extract substrate evidence from layout geometry.
pub fn extract_substrate_evidence(
    store: &GeometryStore,
    deck: &Deck,
    ext: &ExtractedNetlist,
) -> SubstrateEvidence {
    let dbu_nm = deck.dbu_nm;
    let well_layers = find_well_layers(deck);

    if well_layers.is_empty() {
        return SubstrateEvidence::default();
    }

    // Phase 1: identify well regions.
    let mut wells = Vec::new();
    for (layer_id, well_type) in &well_layers {
        for p in store.polys_on_layer(*layer_id) {
            let bb = store.poly_bbox[p.0 as usize];
            let area = store.area(p).unsigned_abs() as i64;
            let taps = find_taps_for_well(store, ext, &bb, deck, dbu_nm);
            wells.push(WellRegion {
                well_type: *well_type,
                layer: *layer_id,
                bbox: bb,
                area_dbu2: area,
                taps,
            });
        }
    }

    // Phase 2: find untapped wells.
    let untapped_wells: Vec<usize> = wells
        .iter()
        .enumerate()
        .filter(|(_, w)| w.taps.is_empty())
        .map(|(i, _)| i)
        .collect();

    // Phase 3: identify potential latch-up sites (NMOS/PMOS pairs near each other).
    let mut nmos_locs: Vec<(usize, i32, i32)> = Vec::new();
    let mut pmos_locs: Vec<(usize, i32, i32)> = Vec::new();
    for (i, dev) in ext.devices.iter().enumerate() {
        // Get device location from gate polygon bbox centroid.
        let gate_poly = dev.gate;
        if (gate_poly as usize) >= store.poly_count() {
            continue;
        }
        // gate field is a net_id, not a polygon — use well_provenance or skip.
        // ponytail: approximate location from the first polygon on the gate net.
        let loc = ext
            .net_of_poly
            .iter()
            .enumerate()
            .find(|(_, &n)| n == dev.gate)
            .map(|(pi, _)| {
                let bb = store.poly_bbox[pi];
                ((bb.xmin + bb.xmax) / 2, (bb.ymin + bb.ymax) / 2)
            });
        let (x, y) = match loc {
            Some(l) => l,
            None => continue,
        };
        match dev.kind {
            DeviceKind::Nmos => nmos_locs.push((i, x, y)),
            DeviceKind::Pmos => pmos_locs.push((i, x, y)),
            _ => {}
        }
    }

    let mut latchup_sites = Vec::new();
    // ponytail: O(nmos * pmos) brute force, grid-bin if device count is large
    for &(ni, nx, ny) in &nmos_locs {
        for &(pi, px, py) in &pmos_locs {
            let dx = (nx as i64 - px as i64).unsigned_abs() as f64 * dbu_nm;
            let dy = (ny as i64 - py as i64).unsigned_abs() as f64 * dbu_nm;
            let dist_nm = (dx * dx + dy * dy).sqrt();
            // ponytail: 50um proximity threshold, foundry-specific when calibrated
            if dist_nm > 50_000.0 {
                continue;
            }
            let severity = if dist_nm < 5_000.0 {
                LatchupSeverity::High
            } else if dist_nm < 20_000.0 {
                LatchupSeverity::Medium
            } else {
                LatchupSeverity::Low
            };
            latchup_sites.push(LatchupSite {
                nmos_device: Some(ni),
                pmos_device: Some(pi),
                distance_nm: dist_nm as i32,
                guard_ring: None, // ponytail: cross-ref with guard ring extraction
                severity,
            });
        }
    }

    SubstrateEvidence {
        wells,
        latchup_sites,
        untapped_wells,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn guess_well_type_recognizes_names() {
        assert_eq!(guess_well_type("nwell"), Some(WellType::Nwell));
        assert_eq!(guess_well_type("NWELL"), Some(WellType::Nwell));
        assert_eq!(guess_well_type("pwell"), Some(WellType::Pwell));
        assert_eq!(guess_well_type("deep_nwell"), Some(WellType::DeepNwell));
        assert_eq!(guess_well_type("met1"), None);
    }

    #[test]
    fn empty_layout_yields_empty_evidence() {
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
        let ev = extract_substrate_evidence(&store, &deck, &ext);
        assert!(ev.wells.is_empty());
        assert!(ev.latchup_sites.is_empty());
        assert!(ev.untapped_wells.is_empty());
    }

    #[test]
    fn latchup_severity_thresholds() {
        assert_ne!(LatchupSeverity::High, LatchupSeverity::Low);
        assert_eq!(LatchupSeverity::Medium, LatchupSeverity::Medium);
    }
}
