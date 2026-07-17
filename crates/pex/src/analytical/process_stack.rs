//! Process stack model and corner definitions for multi-corner PEX.

use crate::geometry::LayerId;
use crate::params::Deck;
use std::collections::HashMap;

/// A single metal/dielectric layer in the process stack.
#[derive(Clone, Debug)]
pub struct ProcessLayer {
    pub layer: LayerId,
    pub name: String,
    pub thickness_nm: f64,
    pub height_above_substrate_nm: f64,
    pub dielectric_constant: f64,
}

/// Ordered process stack, bottom to top.
#[derive(Clone, Debug)]
pub struct ProcessStack {
    pub layers: Vec<ProcessLayer>,
}

impl ProcessStack {
    /// Build a process stack from the deck's PEX layer entries.
    ///
    /// Per-layer `thickness_nm` / `height_nm` / `dielectric_k` from the deck JSON
    /// are used when set; layers that omit them fall back to the heuristic
    /// (uniform 200 nm thickness, 100 nm spacing, ε_r = 3.9). This is the real
    /// geometry the field-solver mesher extrudes, so populate it in the PDK for
    /// accurate C/L; the analytical path ignores it.
    pub fn from_deck(deck: &Deck) -> Self {
        const HEURISTIC_THICKNESS: f64 = 200.0;
        const HEURISTIC_SPACING: f64 = 100.0;

        let mut layer_ids: Vec<(LayerId, &str)> = deck
            .pex
            .keys()
            .map(|&lid| (lid, deck.layers.name(lid)))
            .collect();
        layer_ids.sort_by_key(|(lid, _)| *lid);

        // Running z for layers that don't pin their own `height_nm`.
        let mut next_heuristic_z = 0.0_f64;
        let layers = layer_ids
            .iter()
            .map(|(lid, name)| {
                let p = &deck.pex[lid];
                let thickness = if p.thickness_nm > 0.0 {
                    p.thickness_nm
                } else {
                    HEURISTIC_THICKNESS
                };
                // A layer that pins thickness or height opts fully into explicit
                // geometry (height defaults to 0 = on substrate). Otherwise it
                // stacks on the running heuristic height.
                let height = if p.height_nm > 0.0 || p.thickness_nm > 0.0 {
                    p.height_nm
                } else {
                    next_heuristic_z
                };
                next_heuristic_z = height + thickness + HEURISTIC_SPACING;
                ProcessLayer {
                    layer: *lid,
                    name: name.to_string(),
                    thickness_nm: thickness,
                    height_above_substrate_nm: height,
                    dielectric_constant: if p.dielectric_k > 0.0 {
                        p.dielectric_k
                    } else {
                        3.9
                    },
                }
            })
            .collect();
        ProcessStack { layers }
    }

    /// Layer IDs ordered bottom to top.
    pub fn layer_order(&self) -> Vec<LayerId> {
        self.layers.iter().map(|l| l.layer).collect()
    }

    pub fn layer_above(&self, layer: LayerId) -> Option<LayerId> {
        let idx = self.layers.iter().position(|l| l.layer == layer)?;
        self.layers.get(idx + 1).map(|l| l.layer)
    }

    pub fn layer_below(&self, layer: LayerId) -> Option<LayerId> {
        let idx = self.layers.iter().position(|l| l.layer == layer)?;
        idx.checked_sub(1).map(|i| self.layers[i].layer)
    }

    /// Vertical center-to-center distance between two layers in nm, `None` if either is
    /// absent.
    pub fn vertical_distance(&self, a: LayerId, b: LayerId) -> Option<f64> {
        let ha = self.layers.iter().find(|l| l.layer == a)?;
        let hb = self.layers.iter().find(|l| l.layer == b)?;
        let ca = ha.height_above_substrate_nm + ha.thickness_nm / 2.0;
        let cb = hb.height_above_substrate_nm + hb.thickness_nm / 2.0;
        Some((ca - cb).abs())
    }
}

/// Per-parameter overrides for a process corner.
#[derive(Clone, Debug, Default)]
pub struct PexCornerOverride {
    pub sheet_res_ohm_sq: Option<f64>,
    pub area_cap_af_um2: Option<f64>,
    pub fringe_cap_af_um: Option<f64>,
    pub coupling_cap_af_um: Option<f64>,
    pub tcr_ppm_per_c: Option<f64>,
}

/// Named set of PEX parameter overrides for a process corner.
#[derive(Clone, Debug)]
pub struct ProcessCorner {
    pub name: String,
    /// Keyed by layer name.
    pub overrides: HashMap<String, PexCornerOverride>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_from_deck_ordering() {
        let deck = crate::params::Deck::from_json(
            r#"{
            "layers": {
                "met1": { "layer": 68, "datatype": 20 },
                "met2": { "layer": 69, "datatype": 20 }
            },
            "drc": {},
            "pex": {
                "met1": { "sheet_res_ohm_sq": 0.1, "area_cap_af_um2": 25.0,
                    "fringe_cap_af_um": 40.0, "coupling_cap_af_um": 0.0,
                    "coupling_ref_spacing_nm": 200 },
                "met2": { "sheet_res_ohm_sq": 0.08, "area_cap_af_um2": 15.0,
                    "fringe_cap_af_um": 30.0, "coupling_cap_af_um": 0.0,
                    "coupling_ref_spacing_nm": 200 }
            }
        }"#,
        )
        .unwrap();
        let stack = ProcessStack::from_deck(&deck);
        assert_eq!(stack.layers.len(), 2);
        let order = stack.layer_order();
        assert_eq!(order.len(), 2);
        // First layer has height 0
        assert!((stack.layers[0].height_above_substrate_nm - 0.0).abs() < 1e-12);
        // layer_above / layer_below
        assert_eq!(stack.layer_above(order[0]), Some(order[1]));
        assert_eq!(stack.layer_below(order[1]), Some(order[0]));
        assert_eq!(stack.layer_above(order[1]), None);
        assert_eq!(stack.layer_below(order[0]), None);
        // Vertical distance
        let vd = stack.vertical_distance(order[0], order[1]).unwrap();
        assert!(vd > 0.0);
    }
}
