use std::collections::{HashMap, HashSet};

use crate::geometry::{Bbox, GeometryStore, LayerId};

use crate::{
    polygon_rect, rect_union_metrics, CheckReport, SignoffCheck, ErcCtx, ErcFinding,
    SignoffViolation,
};

/// Calibrated first-order CMP thickness model for one layer.
#[derive(Debug, Clone, PartialEq)]
pub struct CmpModel {
    pub target_density: f64,
    pub nominal_thickness_nm: f64,
    /// Predicted thickness change for a +1.0 change in local density.
    pub thickness_sensitivity_nm: f64,
    pub max_abs_thickness_delta_nm: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DensityCmpRule {
    pub id: String,
    pub layer: LayerId,
    pub window_width: i32,
    pub window_height: i32,
    pub step_x: i32,
    pub step_y: i32,
    pub min_density: Option<f64>,
    pub max_density: Option<f64>,
    /// Maximum absolute density delta between adjacent sampled windows.
    pub max_neighbor_delta: Option<f64>,
    pub cmp: Option<CmpModel>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DensityCmpConfig {
    /// Explicit chip/block boundary.  Empty space inside this box is checked.
    pub die: Bbox,
    pub rules: Vec<DensityCmpRule>,
    /// When true, edge windows are clipped to the die and normalized by their
    /// actual clipped area.  When false, only full windows are evaluated and
    /// their configured steps must cover both die edges exactly; a trailing
    /// unchecked strip is a configuration error.
    pub include_partial_windows: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DensityWindowResult {
    pub rule_id: String,
    pub layer: LayerId,
    pub window: Bbox,
    pub density: f64,
    pub predicted_thickness_nm: Option<f64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DensityCmpReport {
    pub check: CheckReport,
    pub windows: Vec<DensityWindowResult>,
}

impl DensityCmpReport {
    pub(crate) fn not_run(reason: impl Into<String>) -> Self {
        Self {
            check: CheckReport::not_run(SignoffCheck::DensityCmp, reason),
            windows: Vec::new(),
        }
    }

    pub(crate) fn error(reason: impl Into<String>) -> Self {
        Self {
            check: CheckReport::error(SignoffCheck::DensityCmp, reason),
            windows: Vec::new(),
        }
    }
}

fn valid_fraction(v: f64) -> bool {
    v.is_finite() && (0.0..=1.0).contains(&v)
}

fn anchors(lo: i32, hi: i32, window: i32, step: i32, partial: bool) -> Vec<(i32, i32)> {
    let mut out = Vec::new();
    let mut p = lo;
    if partial {
        while p < hi {
            out.push((p, p.saturating_add(window).min(hi)));
            let next = p.saturating_add(step);
            if next <= p {
                break;
            }
            p = next;
        }
    } else {
        while p.saturating_add(window) <= hi {
            out.push((p, p + window));
            let next = p.saturating_add(step);
            if next <= p {
                break;
            }
            p = next;
        }
    }
    out
}

pub fn check_density_cmp(store: &GeometryStore, config: &DensityCmpConfig) -> DensityCmpReport {
    if config.die.width() <= 0 || config.die.height() <= 0 {
        return DensityCmpReport::error("density/CMP die boundary must have positive area");
    }
    if config.rules.is_empty() {
        return DensityCmpReport::error("density/CMP configuration contains no rules");
    }

    let mut violations = Vec::new();
    let mut windows = Vec::new();
    let diagnostics = Vec::new();
    let mut rule_ids = HashSet::new();

    for rule in &config.rules {
        if rule.id.is_empty()
            || !rule_ids.insert(rule.id.as_str())
            || rule.window_width <= 0
            || rule.window_height <= 0
            || rule.step_x <= 0
            || rule.step_y <= 0
            || rule.step_x > rule.window_width
            || rule.step_y > rule.window_height
        {
            return DensityCmpReport::error(format!(
                "density/CMP rule '{}' has a duplicate/empty id or a non-covering window/step",
                rule.id,
            ));
        }
        if rule.min_density.is_some_and(|v| !valid_fraction(v))
            || rule.max_density.is_some_and(|v| !valid_fraction(v))
            || rule.max_neighbor_delta.is_some_and(|v| !valid_fraction(v))
        {
            return DensityCmpReport::error(format!(
                "density/CMP rule '{}' has a fraction outside [0, 1]",
                rule.id,
            ));
        }
        if let (Some(min), Some(max)) = (rule.min_density, rule.max_density) {
            if min > max {
                return DensityCmpReport::error(format!(
                    "density/CMP rule '{}' has min_density > max_density",
                    rule.id,
                ));
            }
        }
        if rule.min_density.is_none()
            && rule.max_density.is_none()
            && rule.max_neighbor_delta.is_none()
            && rule.cmp.is_none()
        {
            return DensityCmpReport::error(format!(
                "density/CMP rule '{}' has no enabled limit",
                rule.id,
            ));
        }
        if let Some(cmp) = &rule.cmp {
            if !valid_fraction(cmp.target_density)
                || !cmp.nominal_thickness_nm.is_finite()
                || cmp.nominal_thickness_nm <= 0.0
                || !cmp.thickness_sensitivity_nm.is_finite()
                || !cmp.max_abs_thickness_delta_nm.is_finite()
                || cmp.max_abs_thickness_delta_nm < 0.0
            {
                return DensityCmpReport::error(format!(
                    "density/CMP rule '{}' has an invalid CMP model",
                    rule.id,
                ));
            }
        }

        let mut layer_rects = Vec::new();
        for p in store.polys_on_layer(rule.layer) {
            let Some(bb) = polygon_rect(store, p) else {
                return DensityCmpReport::error(format!(
                    "rule '{}': polygon {} is not an axis-aligned rectangle; exact boolean support is required",
                    rule.id, p.0,
                ));
            };
            layer_rects.push(bb);
        }

        let xs = anchors(
            config.die.xmin,
            config.die.xmax,
            rule.window_width,
            rule.step_x,
            config.include_partial_windows,
        );
        let ys = anchors(
            config.die.ymin,
            config.die.ymax,
            rule.window_height,
            rule.step_y,
            config.include_partial_windows,
        );
        if xs.is_empty() || ys.is_empty() {
            return DensityCmpReport::error(format!(
                "density/CMP rule '{}' produces no windows inside the die boundary",
                rule.id,
            ));
        }
        if !config.include_partial_windows
            && (xs.last().is_none_or(|&(_, end)| end != config.die.xmax)
                || ys.last().is_none_or(|&(_, end)| end != config.die.ymax))
        {
            return DensityCmpReport::error(format!(
                "density/CMP rule '{}' leaves an unchecked die-edge strip; enable partial windows or choose a covering full-window step",
                rule.id,
            ));
        }

        let mut density_at: HashMap<(i32, i32), f64> = HashMap::new();
        for &(x0, x1) in &xs {
            for &(y0, y1) in &ys {
                let window = Bbox {
                    xmin: x0,
                    ymin: y0,
                    xmax: x1,
                    ymax: y1,
                };
                let clipped: Vec<Bbox> = layer_rects
                    .iter()
                    .filter_map(|r| {
                        let c = Bbox {
                            xmin: r.xmin.max(window.xmin),
                            ymin: r.ymin.max(window.ymin),
                            xmax: r.xmax.min(window.xmax),
                            ymax: r.ymax.min(window.ymax),
                        };
                        (c.width() > 0 && c.height() > 0).then_some(c)
                    })
                    .collect();
                let (covered, _) = rect_union_metrics(&clipped);
                let window_area = f64::from(window.width()) * f64::from(window.height());
                let density = if window_area > 0.0 {
                    covered / window_area
                } else {
                    0.0
                };
                let predicted = rule.cmp.as_ref().map(|cmp| {
                    cmp.nominal_thickness_nm
                        + cmp.thickness_sensitivity_nm * (density - cmp.target_density)
                });
                density_at.insert((x0, y0), density);
                windows.push(DensityWindowResult {
                    rule_id: rule.id.clone(),
                    layer: rule.layer,
                    window,
                    density,
                    predicted_thickness_nm: predicted,
                });

                if let Some(min) = rule.min_density {
                    if density < min {
                        violations.push(SignoffViolation {
                            check: SignoffCheck::DensityCmp,
                            rule_id: format!("{}.min_density", rule.id),
                            message: format!("local density {density:.5} is below {min:.5}"),
                            location: Some((x0, y0)),
                            measured: Some(density),
                            limit: Some(min),
                            units: "fraction".into(),
                            evidence_id: None,
                        });
                    }
                }
                if let Some(max) = rule.max_density {
                    if density > max {
                        violations.push(SignoffViolation {
                            check: SignoffCheck::DensityCmp,
                            rule_id: format!("{}.max_density", rule.id),
                            message: format!("local density {density:.5} exceeds {max:.5}"),
                            location: Some((x0, y0)),
                            measured: Some(density),
                            limit: Some(max),
                            units: "fraction".into(),
                            evidence_id: None,
                        });
                    }
                }
                if let (Some(cmp), Some(thickness)) = (&rule.cmp, predicted) {
                    let delta = (thickness - cmp.nominal_thickness_nm).abs();
                    if delta > cmp.max_abs_thickness_delta_nm {
                        violations.push(SignoffViolation {
                            check: SignoffCheck::DensityCmp,
                            rule_id: format!("{}.cmp_thickness", rule.id),
                            message: format!(
                                "predicted CMP thickness delta {delta:.3}nm exceeds {:.3}nm",
                                cmp.max_abs_thickness_delta_nm,
                            ),
                            location: Some((x0, y0)),
                            measured: Some(delta),
                            limit: Some(cmp.max_abs_thickness_delta_nm),
                            units: "nm".into(),
                            evidence_id: None,
                        });
                    }
                }
            }
        }

        if let Some(max_delta) = rule.max_neighbor_delta {
            for (&(x, y), &density) in &density_at {
                for neighbor in [
                    (x.saturating_add(rule.step_x), y),
                    (x, y.saturating_add(rule.step_y)),
                ] {
                    let Some(&other) = density_at.get(&neighbor) else {
                        continue;
                    };
                    let delta = (density - other).abs();
                    if delta > max_delta {
                        violations.push(SignoffViolation {
                            check: SignoffCheck::DensityCmp,
                            rule_id: format!("{}.density_gradient", rule.id),
                            message: format!(
                                "adjacent-window density delta {delta:.5} exceeds {max_delta:.5}",
                            ),
                            location: Some((x, y)),
                            measured: Some(delta),
                            limit: Some(max_delta),
                            units: "fraction".into(),
                            evidence_id: None,
                        });
                    }
                }
            }
        }
    }

    windows.sort_by(|a, b| {
        (&a.rule_id, a.window.xmin, a.window.ymin).cmp(&(&b.rule_id, b.window.xmin, b.window.ymin))
    });
    DensityCmpReport {
        check: CheckReport::from_violations(SignoffCheck::DensityCmp, violations, diagnostics),
        windows,
    }
}

/// Suite rule: validate rule layers against the deck, then run the check.
struct DensityCmpSignoffRule;

impl<'a> crate::rule::Rule<ErcCtx<'a>> for DensityCmpSignoffRule {
    type Finding = ErcFinding;

    fn id(&self) -> &str {
        "signoff.density_cmp"
    }

    fn check(&self, ctx: &ErcCtx<'a>, _backend: crate::backend::Backend) -> Vec<ErcFinding> {
        let report = ctx.config.density_cmp.as_ref().map_or_else(
            || DensityCmpReport::not_run("die boundary and density/CMP rules were not supplied"),
            |c| {
                if let Some(rule) = c
                    .rules
                    .iter()
                    .find(|rule| rule.layer as usize >= ctx.deck.layers.id_to_name.len())
                {
                    DensityCmpReport {
                        check: CheckReport::error(
                            SignoffCheck::DensityCmp,
                            format!(
                                "density/CMP rule '{}' references unknown layer id {}",
                                rule.id, rule.layer,
                            ),
                        ),
                        windows: Vec::new(),
                    }
                } else {
                    check_density_cmp(ctx.store, c)
                }
            },
        );
        vec![ErcFinding::DensityCmp(report)]
    }
}

fn factory(_deck: &crate::params::Deck) -> Option<super::BoxedRule> {
    Some(Box::new(DensityCmpSignoffRule))
}
pub static FACTORY: super::Factory = factory;
