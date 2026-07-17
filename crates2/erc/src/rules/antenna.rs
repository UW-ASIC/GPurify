use std::collections::{BTreeMap, HashMap, HashSet};

use crate::geometry::{Bbox, GeometryStore, LayerId};
use crate::lvs::{extract_netlist_opts, ExtractOpts};
use crate::params::{Deck, DrcRuleParam};
use crate::backend::Backend;

use crate::{
    polygon_rect, rect_union_metrics, CheckReport, SignoffCheck, ErcCtx, ErcFinding,
    SignoffViolation,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AntennaMeasurement {
    /// Horizontal etched/contact area.
    Area,
    /// Vertical etched sidewall area: union perimeter times final layer thickness.
    Sidewall { thickness_um: f64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AntennaGate {
    pub gate_layer: LayerId,
    pub channel_layer: LayerId,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AntennaCollector {
    pub layer: LayerId,
    pub measurement: AntennaMeasurement,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AntennaDiode {
    pub layer: LayerId,
    /// `K` in EGAR = EA/A_gate - K*A_diode - bonus.
    pub area_credit_per_um2: f64,
    pub fixed_bonus: f64,
    /// Some simplified decks waive a net completely when a diode is present.
    pub full_waiver: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AntennaRule {
    pub id: String,
    pub gates: Vec<AntennaGate>,
    /// Include every listed collecting layer in this fabrication-stage check.
    pub collectors: Vec<AntennaCollector>,
    pub max_egar: f64,
    pub diode: Option<AntennaDiode>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct AntennaConfig {
    pub rules: Vec<AntennaRule>,
    /// None uses the deck setting.  A production run normally leaves this None.
    pub cut_required: Option<bool>,
}

impl AntennaConfig {
    /// Translate the legacy DRC antenna entries into the richer signoff form.
    /// Foundry decks should normally provide explicit sidewall/contact metrics.
    pub fn from_deck(deck: &Deck) -> Option<Self> {
        let mut gates: Vec<AntennaGate> = deck
            .devices
            .mos_rules
            .iter()
            .map(|r| AntennaGate {
                gate_layer: r.gate_layer,
                channel_layer: r.channel_layer,
            })
            .collect();
        gates.sort_by_key(|g| (g.gate_layer, g.channel_layer));
        gates.dedup();

        let mut rules = Vec::new();
        for rule in &deck.drc_rules {
            match rule {
                DrcRuleParam::Antenna { id, layer, ratio } => rules.push(AntennaRule {
                    id: id.clone(),
                    gates: gates.clone(),
                    collectors: vec![AntennaCollector {
                        layer: *layer,
                        measurement: AntennaMeasurement::Area,
                    }],
                    max_egar: *ratio,
                    diode: None,
                }),
                DrcRuleParam::AntennaCar {
                    id,
                    layers,
                    ratio,
                    diode,
                } => rules.push(AntennaRule {
                    id: id.clone(),
                    gates: gates.clone(),
                    collectors: layers
                        .iter()
                        .copied()
                        .map(|layer| AntennaCollector {
                            layer,
                            measurement: AntennaMeasurement::Area,
                        })
                        .collect(),
                    max_egar: *ratio,
                    diode: diode.map(|layer| AntennaDiode {
                        layer,
                        area_credit_per_um2: 0.0,
                        fixed_bonus: 0.0,
                        full_waiver: true,
                    }),
                }),
                _ => {}
            }
        }
        if rules.is_empty() {
            None
        } else {
            Some(Self {
                rules,
                cut_required: None,
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AntennaNetResult {
    pub rule_id: String,
    pub net: u32,
    pub gate_area_um2: f64,
    pub etched_area_um2: f64,
    pub diode_area_um2: f64,
    pub egar: f64,
    pub waived: bool,
    pub location: (i32, i32),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AntennaReport {
    pub check: CheckReport,
    pub nets: Vec<AntennaNetResult>,
}

impl AntennaReport {
    pub(crate) fn not_run(reason: impl Into<String>) -> Self {
        Self {
            check: CheckReport::not_run(SignoffCheck::Antenna, reason),
            nets: Vec::new(),
        }
    }

    pub(crate) fn error(reason: impl Into<String>) -> Self {
        Self {
            check: CheckReport::error(SignoffCheck::Antenna, reason),
            nets: Vec::new(),
        }
    }
}

pub fn check_antenna_from_deck(store: &GeometryStore, deck: &Deck) -> AntennaReport {
    match AntennaConfig::from_deck(deck) {
        Some(config) => check_antenna(store, deck, &config),
        None => AntennaReport::not_run(
            "no enabled antenna or antenna_car rules are present in the deck",
        ),
    }
}

pub fn check_antenna(store: &GeometryStore, deck: &Deck, config: &AntennaConfig) -> AntennaReport {
    if config.rules.is_empty() {
        return AntennaReport::error("antenna configuration contains no rules");
    }
    if !deck.dbu_nm.is_finite() || deck.dbu_nm <= 0.0 {
        return AntennaReport::error("deck.dbu_nm must be finite and positive");
    }
    let layer_count = deck.layers.id_to_name.len();
    let mut rule_ids = HashSet::new();
    for r in &config.rules {
        if r.id.is_empty()
            || !rule_ids.insert(r.id.as_str())
            || r.gates.is_empty()
            || r.collectors.is_empty()
        {
            return AntennaReport::error(format!(
                "antenna rule '{}' needs a unique id, at least one gate definition, and at least one collector",
                r.id,
            ));
        }
        if !r.max_egar.is_finite() || r.max_egar <= 0.0 {
            return AntennaReport::error(format!(
                "antenna rule '{}' has an invalid max_egar",
                r.id
            ));
        }
        for gate in &r.gates {
            if gate.gate_layer as usize >= layer_count
                || gate.channel_layer as usize >= layer_count
                || gate.gate_layer == gate.channel_layer
            {
                return AntennaReport::error(format!(
                    "antenna rule '{}' references an invalid gate/channel layer pair",
                    r.id,
                ));
            }
        }
        let mut collector_keys = HashSet::new();
        for c in &r.collectors {
            let key = match c.measurement {
                AntennaMeasurement::Area => (c.layer, 0_u8, 0_u64),
                AntennaMeasurement::Sidewall { thickness_um } => {
                    (c.layer, 1_u8, thickness_um.to_bits())
                }
            };
            if c.layer as usize >= layer_count || !collector_keys.insert(key) {
                return AntennaReport::error(format!(
                    "antenna rule '{}' has an unknown or duplicate collector",
                    r.id,
                ));
            }
            if let AntennaMeasurement::Sidewall { thickness_um } = c.measurement {
                if !thickness_um.is_finite() || thickness_um <= 0.0 {
                    return AntennaReport::error(format!(
                        "antenna rule '{}' has an invalid sidewall thickness",
                        r.id,
                    ));
                }
            }
        }
        if let Some(diode) = r.diode {
            if diode.layer as usize >= layer_count
                || !diode.area_credit_per_um2.is_finite()
                || diode.area_credit_per_um2 < 0.0
                || !diode.fixed_bonus.is_finite()
                || diode.fixed_bonus < 0.0
            {
                return AntennaReport::error(format!(
                    "antenna rule '{}' has invalid diode correction data",
                    r.id,
                ));
            }
        }
    }

    let opts = ExtractOpts {
        cut_required: config.cut_required.unwrap_or(deck.lvs_cut_required),
        ..Default::default()
    };
    let ext = match extract_netlist_opts(store, deck, &opts, Backend::Cpu) {
        Ok(ext) => ext,
        Err(e) => return AntennaReport::error(format!("connectivity extraction failed: {e}")),
    };

    let dbu_um = deck.dbu_nm / 1000.0;
    let mut all_results = Vec::new();
    let mut violations = Vec::new();
    let mut diagnostics = Vec::new();

    for rule in &config.rules {
        let mut gate_rects: HashMap<u32, Vec<Bbox>> = HashMap::new();
        let mut gate_location: HashMap<u32, (i32, i32)> = HashMap::new();
        for gate_def in &rule.gates {
            for gate in store.polys_on_layer(gate_def.gate_layer) {
                let Some(gb) = polygon_rect(store, gate) else {
                    return AntennaReport::error(format!(
                        "rule '{}': gate polygon {} is not an axis-aligned rectangle; exact boolean support is required",
                        rule.id, gate.0,
                    ));
                };
                let net = ext
                    .net_of_poly
                    .get(gate.0 as usize)
                    .copied()
                    .unwrap_or(u32::MAX);
                if net == u32::MAX {
                    continue;
                }
                for channel in store.polys_on_layer(gate_def.channel_layer) {
                    let Some(cb) = polygon_rect(store, channel) else {
                        return AntennaReport::error(format!(
                            "rule '{}': channel polygon {} is not an axis-aligned rectangle; exact boolean support is required",
                            rule.id, channel.0,
                        ));
                    };
                    let ix0 = gb.xmin.max(cb.xmin);
                    let iy0 = gb.ymin.max(cb.ymin);
                    let ix1 = gb.xmax.min(cb.xmax);
                    let iy1 = gb.ymax.min(cb.ymax);
                    if ix1 > ix0 && iy1 > iy0 {
                        gate_rects.entry(net).or_default().push(Bbox {
                            xmin: ix0,
                            ymin: iy0,
                            xmax: ix1,
                            ymax: iy1,
                        });
                        gate_location.entry(net).or_insert((ix0, iy0));
                    }
                }
            }
        }

        let mut etched_by_net: HashMap<u32, f64> = HashMap::new();
        for collector in &rule.collectors {
            let mut rects_by_net: HashMap<u32, Vec<Bbox>> = HashMap::new();
            for p in store.polys_on_layer(collector.layer) {
                let Some(bb) = polygon_rect(store, p) else {
                    return AntennaReport::error(format!(
                        "rule '{}': collecting polygon {} on '{}' is not an axis-aligned rectangle; exact boolean support is required",
                        rule.id,
                        p.0,
                        deck.layers.name(collector.layer),
                    ));
                };
                let net = ext
                    .net_of_poly
                    .get(p.0 as usize)
                    .copied()
                    .unwrap_or(u32::MAX);
                if net != u32::MAX {
                    rects_by_net.entry(net).or_default().push(bb);
                }
            }
            for (net, rects) in rects_by_net {
                let (area_dbu2, perimeter_dbu) = rect_union_metrics(&rects);
                let etched = match collector.measurement {
                    AntennaMeasurement::Area => area_dbu2 * dbu_um * dbu_um,
                    AntennaMeasurement::Sidewall { thickness_um } => {
                        perimeter_dbu * dbu_um * thickness_um
                    }
                };
                *etched_by_net.entry(net).or_default() += etched;
            }
        }

        let mut diode_area_by_net: HashMap<u32, f64> = HashMap::new();
        if let Some(diode) = rule.diode {
            let mut rects_by_net: HashMap<u32, Vec<Bbox>> = HashMap::new();
            for p in store.polys_on_layer(diode.layer) {
                let Some(bb) = polygon_rect(store, p) else {
                    return AntennaReport::error(format!(
                        "rule '{}': diode polygon {} is not an axis-aligned rectangle; exact boolean support is required",
                        rule.id, p.0,
                    ));
                };
                let direct_net = ext
                    .net_of_poly
                    .get(p.0 as usize)
                    .copied()
                    .unwrap_or(u32::MAX);
                let net = if direct_net != u32::MAX {
                    direct_net
                } else {
                    // Diode/junction layers are normally recognition markers,
                    // not conductors. Attribute the marker to the one extracted
                    // net whose real polygon geometry overlaps its rectangle.
                    let mut connected_nets = HashSet::new();
                    for q in 0..store.poly_count() as u32 {
                        let candidate =
                            ext.net_of_poly.get(q as usize).copied().unwrap_or(u32::MAX);
                        if candidate == u32::MAX {
                            continue;
                        }
                        if crate::geometry::clipped_area(
                            store,
                            crate::geometry::PolyId(q),
                            bb.xmin,
                            bb.ymin,
                            bb.xmax,
                            bb.ymax,
                        ) > 0.0
                        {
                            connected_nets.insert(candidate);
                        }
                    }
                    match connected_nets.len() {
                        1 => *connected_nets.iter().next().expect("one connected net"),
                        0 => {
                            return AntennaReport::error(format!(
                                "rule '{}': diode marker polygon {} is not connected to an extracted net",
                                rule.id, p.0,
                            ));
                        }
                        _ => {
                            return AntennaReport::error(format!(
                                "rule '{}': diode marker polygon {} ambiguously overlaps multiple extracted nets",
                                rule.id, p.0,
                            ));
                        }
                    }
                };
                rects_by_net.entry(net).or_default().push(bb);
            }
            for (net, rects) in rects_by_net {
                let (area, _) = rect_union_metrics(&rects);
                diode_area_by_net.insert(net, area * dbu_um * dbu_um);
            }
        }

        if gate_rects.is_empty() {
            diagnostics.push(format!(
                "rule '{}': no applicable gate area was present",
                rule.id
            ));
            continue;
        }

        let mut ordered: BTreeMap<u32, Vec<Bbox>> = BTreeMap::new();
        ordered.extend(gate_rects);
        for (net, rects) in ordered {
            let (gate_area_dbu2, _) = rect_union_metrics(&rects);
            let gate_area_um2 = gate_area_dbu2 * dbu_um * dbu_um;
            if gate_area_um2 <= 0.0 {
                continue;
            }
            let etched_area_um2 = etched_by_net.get(&net).copied().unwrap_or(0.0);
            let diode_area_um2 = diode_area_by_net.get(&net).copied().unwrap_or(0.0);
            let waived = rule
                .diode
                .is_some_and(|d| d.full_waiver && diode_area_um2 > 0.0);
            let mut egar = etched_area_um2 / gate_area_um2;
            if let Some(diode) = rule.diode {
                if diode_area_um2 > 0.0 && !diode.full_waiver {
                    egar -= diode.area_credit_per_um2 * diode_area_um2 + diode.fixed_bonus;
                }
            }
            egar = egar.max(0.0);
            let location = gate_location.get(&net).copied().unwrap_or((0, 0));
            all_results.push(AntennaNetResult {
                rule_id: rule.id.clone(),
                net,
                gate_area_um2,
                etched_area_um2,
                diode_area_um2,
                egar,
                waived,
                location,
            });
            if !waived && egar > rule.max_egar {
                violations.push(SignoffViolation {
                    check: SignoffCheck::Antenna,
                    rule_id: rule.id.clone(),
                    message: format!(
                        "net {net} etch-gate-area ratio {egar:.3} exceeds {:.3}",
                        rule.max_egar,
                    ),
                    location: Some(location),
                    measured: Some(egar),
                    limit: Some(rule.max_egar),
                    units: "ratio".into(),
                    evidence_id: None,
                });
            }
        }
    }

    all_results.sort_by(|a, b| (&a.rule_id, a.net).cmp(&(&b.rule_id, b.net)));
    AntennaReport {
        check: CheckReport::from_violations(SignoffCheck::Antenna, violations, diagnostics),
        nets: all_results,
    }
}

/// Analyze antenna ratios per fabrication stage (layer-by-layer accumulation).
///
/// For each gate net, accumulates collecting area stage by stage through the
/// fabrication layer order. Reports a violation when cumulative EGAR exceeds
/// the limit at any intermediate stage — not just at the final metal.
/// ponytail: reuses existing rect-based extraction, no new geometry engine needed.
pub fn check_fabrication_stage_antenna(
    store: &GeometryStore,
    deck: &Deck,
    ext: &crate::lvs::ExtractedNetlist,
    layer_order: &[LayerId],
    config: &AntennaConfig,
) -> Vec<SignoffViolation> {
    use std::collections::HashMap as Map;
    let dbu_um = deck.dbu_nm / 1000.0;
    let mut violations = Vec::new();

    for rule in &config.rules {
        // Collect gate areas per net (same logic as check_antenna).
        let mut gate_area_by_net: Map<u32, f64> = Map::new();
        for gate_def in &rule.gates {
            for gate in store.polys_on_layer(gate_def.gate_layer) {
                let Some(gb) = polygon_rect(store, gate) else {
                    continue;
                };
                let net = ext
                    .net_of_poly
                    .get(gate.0 as usize)
                    .copied()
                    .unwrap_or(u32::MAX);
                if net == u32::MAX {
                    continue;
                }
                for channel in store.polys_on_layer(gate_def.channel_layer) {
                    let Some(cb) = polygon_rect(store, channel) else {
                        continue;
                    };
                    let ix0 = gb.xmin.max(cb.xmin);
                    let iy0 = gb.ymin.max(cb.ymin);
                    let ix1 = gb.xmax.min(cb.xmax);
                    let iy1 = gb.ymax.min(cb.ymax);
                    if ix1 > ix0 && iy1 > iy0 {
                        let area = (ix1 - ix0) as f64 * (iy1 - iy0) as f64 * dbu_um * dbu_um;
                        *gate_area_by_net.entry(net).or_default() += area;
                    }
                }
            }
        }

        if gate_area_by_net.is_empty() {
            continue;
        }

        // Accumulate collecting area stage by stage.
        let mut cumulative_by_net: Map<u32, f64> = Map::new();

        for (stage_idx, &layer) in layer_order.iter().enumerate() {
            // Check if this layer is one of the rule's collectors.
            let collector = rule.collectors.iter().find(|c| c.layer == layer);
            if collector.is_none() {
                continue;
            }
            let collector = collector.unwrap();

            // Gather rectangles on this layer by net.
            let mut rects_by_net: Map<u32, Vec<Bbox>> = Map::new();
            for p in store.polys_on_layer(layer) {
                let Some(bb) = polygon_rect(store, p) else {
                    continue;
                };
                let net = ext
                    .net_of_poly
                    .get(p.0 as usize)
                    .copied()
                    .unwrap_or(u32::MAX);
                if net != u32::MAX {
                    rects_by_net.entry(net).or_default().push(bb);
                }
            }

            for (net, rects) in &rects_by_net {
                let (area_dbu2, perimeter_dbu) = rect_union_metrics(rects);
                let etched = match collector.measurement {
                    AntennaMeasurement::Area => area_dbu2 * dbu_um * dbu_um,
                    AntennaMeasurement::Sidewall { thickness_um } => {
                        perimeter_dbu * dbu_um * thickness_um
                    }
                };
                *cumulative_by_net.entry(*net).or_default() += etched;

                // Check cumulative EGAR at this stage.
                if let Some(&gate_area) = gate_area_by_net.get(net) {
                    if gate_area <= 0.0 {
                        continue;
                    }
                    let cumulative = cumulative_by_net[net];
                    let egar = cumulative / gate_area;
                    if egar > rule.max_egar {
                        violations.push(SignoffViolation {
                            check: SignoffCheck::Antenna,
                            rule_id: format!("{}.stage_{stage_idx}", rule.id),
                            message: format!(
                                "net {net} cumulative EGAR {egar:.3} exceeds {:.3} at fabrication stage {stage_idx} (layer {})",
                                rule.max_egar,
                                deck.layers.name(layer),
                            ),
                            location: None,
                            measured: Some(egar),
                            limit: Some(rule.max_egar),
                            units: "ratio".into(),
                            evidence_id: None,
                        });
                    }
                }
            }
        }
    }

    violations
}

/// Suite rule: run the antenna check from the explicit config, or derive one
/// from the deck's legacy antenna entries when none was supplied.
struct AntennaSignoffRule;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for AntennaSignoffRule {
    type Finding = ErcFinding;

    fn id(&self) -> &str {
        "signoff.antenna"
    }

    fn check(&self, ctx: &ErcCtx<'a>, _backend: Backend) -> Vec<ErcFinding> {
        let report = ctx.config.antenna.as_ref().map_or_else(
            || check_antenna_from_deck(ctx.store, ctx.deck),
            |c| check_antenna(ctx.store, ctx.deck, c),
        );
        vec![ErcFinding::Antenna(report)]
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(AntennaSignoffRule))
}
pub static FACTORY: super::Factory = factory;
