//! The rule set: one [`Rule`] per deck row, the deck parser, and the driver.

use crate::drc::rules::{area, grid, overlay, patterning, spacing, via, width};
use crate::drc::{Design, DrcError, Scratch};
use crate::report::{record_run, LimitSense, RuleRun, Violations};
use gpurify_geom::{Dbu, DbuArea, LayerId};
use gpurify_ingest::deck::{Deck, ParamValue, RuleSpec};
use gpurify_ingest::{StrId, StrTable};

/// One configured DRC rule. Every limit is positive; area limits are squared.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Rule {
    MinWidth {
        layer: LayerId,
        limit: Dbu,
    },
    MaxWidth {
        layer: LayerId,
        limit: Dbu,
    },
    MinEdgeLength {
        layer: LayerId,
        limit: Dbu,
    },
    Notch {
        layer: LayerId,
        limit: Dbu,
    },
    MinSpacing {
        layer: LayerId,
        limit: Dbu,
    },
    MinSpacingDiff {
        a: LayerId,
        b: LayerId,
        limit: Dbu,
    },
    /// An edge shorter than `eol_width` is an end of line and needs `limit`.
    EolSpacing {
        layer: LayerId,
        eol_width: Dbu,
        limit: Dbu,
    },
    /// Pairs whose parallel run is at least `prl_threshold` need `limit`.
    PrlSpacing {
        layer: LayerId,
        prl_threshold: Dbu,
        limit: Dbu,
    },
    CornerToCorner {
        layer: LayerId,
        limit: Dbu,
    },
    /// Pairs with a shape whose narrowest width is at least `width_threshold`.
    WideDependentSpacing {
        layer: LayerId,
        width_threshold: Dbu,
        limit: Dbu,
    },
    MinArea {
        layer: LayerId,
        limit: DbuArea,
    },
    MinEnclosedArea {
        layer: LayerId,
        limit: DbuArea,
    },
    /// A figure above `max_unslotted` must carry a hole.
    Cheesing {
        layer: LayerId,
        max_unslotted: DbuArea,
    },
    /// Covered fraction of a `window`-sided square swept in `step`s.
    Density {
        layer: LayerId,
        window: Dbu,
        step: Dbu,
        limit: f64,
        sense: LimitSense,
    },
    MinEnclosure {
        outer: LayerId,
        inner: LayerId,
        limit: Dbu,
    },
    /// At least `min_one_side` on one side of each axis.
    AsymmetricEnclosure {
        outer: LayerId,
        inner: LayerId,
        min_one_side: Dbu,
    },
    MinExtension {
        layer: LayerId,
        reference: LayerId,
        limit: Dbu,
    },
    Overlap {
        a: LayerId,
        b: LayerId,
        limit: Dbu,
    },
    MaxDistanceToTap {
        well: LayerId,
        tap: LayerId,
        limit: Dbu,
    },
    OffGrid {
        pitch: Dbu,
    },
    /// Bit `i` allows the line at `45 * i` degrees (0, 45, 90, 135).
    Angle {
        allowed: u8,
    },
    /// Cuts required within `within` of each cut, the cut itself included.
    RedundantVia {
        layer: LayerId,
        min_count: u16,
        within: Dbu,
    },
    /// Clusters larger than `array_threshold` hold every pair to `limit`.
    ViaArraySpacing {
        layer: LayerId,
        array_threshold: u16,
        limit: Dbu,
    },
    MultiPatterning {
        layer: LayerId,
        colors: u8,
        color_spacing: Dbu,
    },
}

/// Every DRC rule the deck configures, in deck order.
#[derive(Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<(StrId, Rule)>,
}

impl RuleSet {
    /// Parse every deck row whose kind is in [`KINDS`]; other kinds belong to
    /// another domain and are stepped over (the engine refuses kinds no domain spells).
    ///
    /// Area limits are stated as the side of the equivalent square and squared here.
    pub fn from_deck(deck: &Deck, strings: &StrTable) -> Result<Self, DrcError> {
        let rules = &deck.rules;
        let name_of = |id: StrId| strings.resolve(id).to_owned();

        let mut ids: Vec<StrId> = rules.spec.iter().map(|spec| spec.id).collect();
        ids.sort_unstable();
        if let Some(pair) = ids.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(DrcError::DuplicateRule(name_of(pair[0])));
        }

        let wrong_type = |spec: &RuleSpec, param| DrcError::WrongParamType {
            rule: name_of(spec.id),
            param,
        };
        let value = |spec: &RuleSpec, param: &'static str| {
            strings
                .get(param)
                .and_then(|interned| rules.param(spec, interned))
                .ok_or_else(|| DrcError::MissingParam {
                    rule: name_of(spec.id),
                    param,
                })
        };
        let length = |spec: &RuleSpec, param| -> Result<Dbu, DrcError> {
            let ParamValue::Length(limit) = value(spec, param)? else {
                return Err(wrong_type(spec, param));
            };
            if limit.raw() <= 0 {
                return Err(DrcError::NonPositiveLimit {
                    rule: name_of(spec.id),
                    limit: limit.raw(),
                });
            }
            Ok(limit)
        };
        let square = |spec: &RuleSpec, param| length(spec, param).map(|side| side.mul_wide(side));
        let ratio = |spec: &RuleSpec, param| -> Result<f64, DrcError> {
            let ParamValue::Ratio(limit) = value(spec, param)? else {
                return Err(wrong_type(spec, param));
            };
            // `!(x > 0)` also rejects NaN, which would compare clean everywhere.
            if !(limit > 0.0) || !limit.is_finite() {
                #[allow(clippy::cast_possible_truncation, reason = "shown to a human only")]
                let shown = limit as i64;
                return Err(DrcError::NonPositiveLimit {
                    rule: name_of(spec.id),
                    limit: shown,
                });
            }
            Ok(limit)
        };
        let count = |spec: &RuleSpec, param, ceiling: u32| -> Result<u32, DrcError> {
            match value(spec, param)? {
                ParamValue::Count(found) if found <= ceiling => Ok(found),
                _ => Err(wrong_type(spec, param)),
            }
        };
        let positive = |spec: &RuleSpec, found: u32| {
            if found == 0 {
                return Err(DrcError::NonPositiveLimit {
                    rule: name_of(spec.id),
                    limit: 0,
                });
            }
            Ok(found)
        };
        let layers = |spec: &RuleSpec, expected: u32| {
            if spec.layer_len == expected {
                Ok(())
            } else {
                Err(DrcError::WrongLayerCount {
                    rule: name_of(spec.id),
                    expected,
                    found: spec.layer_len,
                })
            }
        };
        let layer = |spec: &RuleSpec, nth: usize| rules.layers_of(spec)[nth];
        // Layer count first, then each parameter in field order.
        let one = |spec: &RuleSpec| layers(spec, 1).map(|()| layer(spec, 0));
        let two = |spec: &RuleSpec| layers(spec, 2).map(|()| (layer(spec, 0), layer(spec, 1)));

        let mut set = Self::default();
        for spec in &rules.spec {
            let rule = match strings.resolve(spec.kind) {
                "min_width" => Rule::MinWidth {
                    layer: one(spec)?,
                    limit: length(spec, "limit")?,
                },
                "max_width" => Rule::MaxWidth {
                    layer: one(spec)?,
                    limit: length(spec, "limit")?,
                },
                "min_edge_length" => Rule::MinEdgeLength {
                    layer: one(spec)?,
                    limit: length(spec, "limit")?,
                },
                "notch" => Rule::Notch {
                    layer: one(spec)?,
                    limit: length(spec, "limit")?,
                },
                "min_spacing" => Rule::MinSpacing {
                    layer: one(spec)?,
                    limit: length(spec, "limit")?,
                },
                "min_spacing_diff" => {
                    let (a, b) = two(spec)?;
                    Rule::MinSpacingDiff {
                        a,
                        b,
                        limit: length(spec, "limit")?,
                    }
                }
                "eol_spacing" => Rule::EolSpacing {
                    layer: one(spec)?,
                    eol_width: length(spec, "eol_width")?,
                    limit: length(spec, "limit")?,
                },
                "prl_spacing" => Rule::PrlSpacing {
                    layer: one(spec)?,
                    prl_threshold: length(spec, "prl_threshold")?,
                    limit: length(spec, "limit")?,
                },
                "corner_to_corner" => Rule::CornerToCorner {
                    layer: one(spec)?,
                    limit: length(spec, "limit")?,
                },
                "wide_dependent_spacing" => Rule::WideDependentSpacing {
                    layer: one(spec)?,
                    width_threshold: length(spec, "width_threshold")?,
                    limit: length(spec, "limit")?,
                },
                "min_area" => Rule::MinArea {
                    layer: one(spec)?,
                    limit: square(spec, "limit")?,
                },
                "min_enclosed_area" => Rule::MinEnclosedArea {
                    layer: one(spec)?,
                    limit: square(spec, "limit")?,
                },
                "cheesing" => Rule::Cheesing {
                    layer: one(spec)?,
                    max_unslotted: square(spec, "max_unslotted")?,
                },
                "density" => {
                    let layer = one(spec)?;
                    let (window, step) = (length(spec, "window")?, length(spec, "step")?);
                    let limit = ratio(spec, "limit")?;
                    let ParamValue::Flag(maximum) = value(spec, "maximum")? else {
                        return Err(wrong_type(spec, "maximum"));
                    };
                    let sense = if maximum {
                        LimitSense::Maximum
                    } else {
                        LimitSense::Minimum
                    };
                    Rule::Density {
                        layer,
                        window,
                        step,
                        limit,
                        sense,
                    }
                }
                "min_enclosure" => {
                    let (outer, inner) = two(spec)?;
                    Rule::MinEnclosure {
                        outer,
                        inner,
                        limit: length(spec, "limit")?,
                    }
                }
                "asymmetric_enclosure" => {
                    let (outer, inner) = two(spec)?;
                    Rule::AsymmetricEnclosure {
                        outer,
                        inner,
                        min_one_side: length(spec, "min_one_side")?,
                    }
                }
                "min_extension" => {
                    let (layer, reference) = two(spec)?;
                    Rule::MinExtension {
                        layer,
                        reference,
                        limit: length(spec, "limit")?,
                    }
                }
                "overlap" => {
                    let (a, b) = two(spec)?;
                    Rule::Overlap {
                        a,
                        b,
                        limit: length(spec, "limit")?,
                    }
                }
                "max_distance_to_tap" => {
                    let (well, tap) = two(spec)?;
                    Rule::MaxDistanceToTap {
                        well,
                        tap,
                        limit: length(spec, "limit")?,
                    }
                }
                "off_grid" => {
                    layers(spec, 0)?;
                    Rule::OffGrid {
                        pitch: length(spec, "pitch")?,
                    }
                }
                "angle" => {
                    layers(spec, 0)?;
                    let wanted = strings.get("angle");
                    let mut allowed = 0u8;
                    for &(param, stated) in rules.params_of(spec) {
                        if Some(param) != wanted {
                            continue;
                        }
                        let ParamValue::Count(degrees) = stated else {
                            return Err(wrong_type(spec, "angle"));
                        };
                        let degrees = i32::try_from(degrees % 360).expect("under a full turn");
                        if degrees.rem_euclid(45) != 0 {
                            return Err(DrcError::UnrepresentableAngle {
                                rule: name_of(spec.id),
                                degrees,
                            });
                        }
                        allowed |= 1 << (degrees.rem_euclid(180) / 45);
                    }
                    if allowed == 0 {
                        return Err(DrcError::MissingParam {
                            rule: name_of(spec.id),
                            param: "angle",
                        });
                    }
                    Rule::Angle { allowed }
                }
                "redundant_via" => {
                    let layer = one(spec)?;
                    let min_count = positive(spec, count(spec, "min_count", u16::MAX.into())?)?;
                    Rule::RedundantVia {
                        layer,
                        min_count: u16::try_from(min_count).expect("checked against the ceiling"),
                        within: length(spec, "within")?,
                    }
                }
                "via_array_spacing" => {
                    let layer = one(spec)?;
                    // Zero is legal: it makes every cluster an array.
                    let threshold = count(spec, "array_threshold", u16::MAX.into())?;
                    Rule::ViaArraySpacing {
                        layer,
                        array_threshold: u16::try_from(threshold).expect("checked"),
                        limit: length(spec, "limit")?,
                    }
                }
                "multi_patterning" => {
                    let layer = one(spec)?;
                    let colors = positive(spec, count(spec, "colors", u8::MAX.into())?)?;
                    Rule::MultiPatterning {
                        layer,
                        colors: u8::try_from(colors).expect("checked against the ceiling"),
                        color_spacing: length(spec, "color_spacing")?,
                    }
                }
                other => {
                    assert!(
                        !KINDS.contains(&other),
                        "KINDS names {other} but it has no arm"
                    );
                    continue;
                }
            };
            set.rules.push((spec.id, rule));
        }
        Ok(set)
    }

    /// The number of `RuleRun` rows [`RuleSet::run`] produces.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Run every rule; `out` and `runs` are cleared first, then `runs` gains one
    /// row per rule, in rule order.
    pub fn run(
        &self,
        design: Design<'_>,
        s: &mut Scratch,
        out: &mut Violations,
        runs: &mut Vec<RuleRun>,
    ) {
        *out = Violations::default();
        runs.clear();
        let store = design.store;
        for &(id, rule) in &self.rules {
            let before = out.len();
            let (outcome, examined) = match rule {
                Rule::MinWidth { layer, limit } => {
                    width::facing(store, id, layer, limit, true, true, s, out)
                }
                Rule::MaxWidth { layer, limit } => {
                    width::facing(store, id, layer, limit, true, false, s, out)
                }
                Rule::Notch { layer, limit } => {
                    width::facing(store, id, layer, limit, false, true, s, out)
                }
                Rule::MinEdgeLength { layer, limit } => {
                    width::min_edge_length(store, id, layer, limit, s, out)
                }
                Rule::MinSpacing { layer, limit } => {
                    spacing::min_spacing(store, id, layer, limit, s, out)
                }
                Rule::MinSpacingDiff { a, b, limit } => {
                    spacing::min_spacing_diff(store, id, a, b, limit, s, out)
                }
                Rule::EolSpacing {
                    layer,
                    eol_width,
                    limit,
                } => spacing::eol_spacing(store, id, layer, eol_width, limit, s, out),
                Rule::PrlSpacing {
                    layer,
                    prl_threshold,
                    limit,
                } => spacing::prl_spacing(store, id, layer, prl_threshold, limit, s, out),
                Rule::CornerToCorner { layer, limit } => {
                    spacing::corner_to_corner(store, id, layer, limit, s, out)
                }
                Rule::WideDependentSpacing {
                    layer,
                    width_threshold,
                    limit,
                } => spacing::wide_dependent(store, id, layer, width_threshold, limit, s, out),
                Rule::MinArea { layer, limit } => area::min_area(store, id, layer, limit, s, out),
                Rule::MinEnclosedArea { layer, limit } => {
                    area::min_enclosed_area(store, id, layer, limit, s, out)
                }
                Rule::Cheesing {
                    layer,
                    max_unslotted,
                } => area::cheesing(store, id, layer, max_unslotted, s, out),
                Rule::Density {
                    layer,
                    window,
                    step,
                    limit,
                    sense,
                } => area::density(store, id, layer, window, step, limit, sense, s, out),
                Rule::MinEnclosure {
                    outer,
                    inner,
                    limit,
                } => overlay::enclosure(store, id, outer, inner, limit, false, s, out),
                Rule::AsymmetricEnclosure {
                    outer,
                    inner,
                    min_one_side,
                } => overlay::enclosure(store, id, outer, inner, min_one_side, true, s, out),
                Rule::MinExtension {
                    layer,
                    reference,
                    limit,
                } => overlay::min_extension(store, id, layer, reference, limit, s, out),
                Rule::Overlap { a, b, limit } => overlay::overlap(store, id, a, b, limit, s, out),
                Rule::MaxDistanceToTap { well, tap, limit } => {
                    overlay::max_distance_to_tap(store, id, well, tap, limit, s, out)
                }
                Rule::OffGrid { pitch } => grid::off_grid(store, id, pitch, out),
                Rule::Angle { allowed } => grid::angle(store, id, allowed, out),
                Rule::RedundantVia {
                    layer,
                    min_count,
                    within,
                } => via::redundant_via(store, id, layer, min_count, within, s, out),
                Rule::ViaArraySpacing {
                    layer,
                    array_threshold,
                    limit,
                } => via::via_array_spacing(store, id, layer, array_threshold, limit, s, out),
                Rule::MultiPatterning {
                    layer,
                    colors,
                    color_spacing,
                } => patterning::multi_patterning(store, id, layer, colors, color_spacing, s, out),
            };
            record_run(runs, out, before, id, outcome, examined);
        }
    }
}

/// Every rule kind this crate implements, as the deck spells it. Disjoint from
/// `crate::erc::ruleset::KINDS`.
pub const KINDS: [&str; 24] = [
    "min_width",
    "max_width",
    "min_edge_length",
    "notch",
    "min_spacing",
    "min_spacing_diff",
    "eol_spacing",
    "prl_spacing",
    "corner_to_corner",
    "wide_dependent_spacing",
    "min_area",
    "min_enclosed_area",
    "cheesing",
    "density",
    "min_enclosure",
    "asymmetric_enclosure",
    "min_extension",
    "overlap",
    "max_distance_to_tap",
    "off_grid",
    "angle",
    "redundant_via",
    "via_array_spacing",
    "multi_patterning",
];
