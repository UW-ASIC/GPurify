//! The rule set: one [`Rule`] per deck row, the deck parser, and the driver.

use crate::drc::rules::{area, edge, grid, overlay, patterning, presence, spacing, via, width};
use crate::drc::{DrcError, Scratch};
use crate::report::{record_run, LimitSense, Outcome, RuleRun, Violations};
use crate::topology::NetTable;
use gpurify_geom::{Dbu, DbuArea, GeometryStore, LayerId};
use gpurify_ingest::deck::{Deck, ParamValue, RuleSpec};
use gpurify_ingest::{StrId, StrTable};

/// One configured DRC rule. Every limit is positive; area limits are in square grid units.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Rule {
    MinWidth {
        layer: LayerId,
        limit: Dbu,
    },
    /// Wider than `limit` anywhere a `limit + 1` square fits.
    MaxWidth {
        layer: LayerId,
        limit: Dbu,
    },
    /// Every merged figure is a `width` x `height` rectangle, either way round.
    CutSize {
        layer: LayerId,
        width: Dbu,
        height: Dbu,
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
    /// Pairs near the part of a shape where a `width_threshold` square fits.
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
    /// Covered fraction of a `window`-sided square swept in `step`s over the
    /// die: the `boundary` layer's extent, or the whole layout's.
    Density {
        layer: LayerId,
        boundary: Option<LayerId>,
        window: Dbu,
        step: Dbu,
        limit: f64,
        sense: LimitSense,
    },
    /// Covered fraction of the whole die.
    GlobalDensity {
        layer: LayerId,
        boundary: Option<LayerId>,
        limit: f64,
        sense: LimitSense,
    },
    MinEnclosure {
        outer: LayerId,
        inner: LayerId,
        limit: Dbu,
    },
    /// At least `min_one_side` on both sides of at least one axis.
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
    /// Bit `i` allows the line at `45 * i` degrees (0, 45, 90, 135), on one
    /// layer or (`None`) on every layer.
    Angle {
        layer: Option<LayerId>,
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
    /// Every shape and every edge on the layer.
    Forbidden {
        layer: LayerId,
    },
    /// Each merged `outer` figure entirely holds at least `min_count` merged
    /// `inner` figures.
    MustContain {
        outer: LayerId,
        inner: LayerId,
        min_count: u32,
    },
    /// Each merged `inner` figure lies entirely inside `outer`.
    MustBeInside {
        inner: LayerId,
        outer: LayerId,
    },
    /// Pairs on the same net (`same_net`), or on different nets, closer than `limit`.
    NetSpacing {
        layer: LayerId,
        same_net: bool,
        limit: Dbu,
    },
    /// Spacing by width and parallel run length: `RuleSet::tables[table]`.
    SpacingTable {
        layer: LayerId,
        table: u32,
    },
    /// Wide-metal spacing measured from the wide part grown by `attached`
    /// within its own figure.
    AttachedWideSpacing {
        layer: LayerId,
        width_threshold: Dbu,
        attached: Dbu,
        limit: Dbu,
    },
    /// An edge shorter than `limit`.
    EdgeMinLength {
        layer: LayerId,
        limit: Dbu,
    },
    /// Two edges closer than `limit`, from `a` to `b` (or within `a`).
    EdgeSpacing {
        a: LayerId,
        b: Option<LayerId>,
        limit: Dbu,
    },
    /// The strip `limit` deep outside each edge not covered by `outer`.
    EdgeEnclosure {
        edges: LayerId,
        outer: LayerId,
        limit: Dbu,
    },
}

/// A spacing table, LEF `SPACINGTABLE PARALLELRUNLENGTH`: the required space
/// for a pair is `space[row][column]`, with `row` the last width exceeded by
/// the wider shape and `column` the last run length exceeded by the pair; the
/// first row and column always apply. Cells never fall along a row or column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpacingTable {
    pub prl: Vec<Dbu>,
    pub width: Vec<Dbu>,
    /// Row-major, `width.len()` rows of `prl.len()` cells.
    pub space: Vec<Dbu>,
}

impl SpacingTable {
    /// Whether the table is complete and monotone, as the struct states.
    pub fn is_valid(&self) -> bool {
        let starts_and_rises = |steps: &[Dbu]| {
            steps.first().is_some_and(|first| first.raw() == 0)
                && steps.windows(2).all(|pair| pair[0] < pair[1])
        };
        let columns = self.prl.len();
        starts_and_rises(&self.prl)
            && starts_and_rises(&self.width)
            && self.space.len() == columns * self.width.len()
            && self.space.iter().all(|cell| cell.raw() > 0)
            && self
                .space
                .chunks(columns)
                .all(|row| row.windows(2).all(|p| p[0] <= p[1]))
            && self.space.windows(columns + 1).all(|w| w[0] <= w[columns])
    }

    /// The cell at `row`, `column`.
    pub(crate) fn at(&self, row: usize, column: usize) -> Dbu {
        self.space[row * self.prl.len() + column]
    }
}

/// Every DRC rule the deck configures, in deck order.
#[derive(Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<(StrId, Rule)>,
    /// The tables [`Rule::SpacingTable`] names.
    pub tables: Vec<SpacingTable>,
}

impl RuleSet {
    /// Parse every deck row whose kind is in [`KINDS`]; other kinds belong to
    /// another domain and are stepped over (the engine refuses kinds no domain spells).
    ///
    /// Area limits arrive as areas (`ParamValue::Area`).
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
        let area_limit = |spec: &RuleSpec, param| match value(spec, param)? {
            ParamValue::Area(area) if area.raw() > 0 => Ok(area),
            ParamValue::Area(area) => Err(DrcError::NonPositiveLimit {
                rule: name_of(spec.id),
                limit: i64::try_from(area.raw()).unwrap_or(i64::MIN),
            }),
            _ => Err(wrong_type(spec, param)),
        };
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
        // A density layer, then an optional die boundary layer.
        let bounded = |spec: &RuleSpec| match spec.layer_len {
            1 => Ok((layer(spec, 0), None)),
            _ => two(spec).map(|(layer, boundary)| (layer, Some(boundary))),
        };
        let sense = |spec: &RuleSpec| -> Result<LimitSense, DrcError> {
            let ParamValue::Flag(maximum) = value(spec, "maximum")? else {
                return Err(wrong_type(spec, "maximum"));
            };
            Ok(if maximum {
                LimitSense::Maximum
            } else {
                LimitSense::Minimum
            })
        };

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
                "cut_size" => Rule::CutSize {
                    layer: one(spec)?,
                    width: length(spec, "width")?,
                    height: length(spec, "height")?,
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
                    limit: area_limit(spec, "limit")?,
                },
                "min_enclosed_area" => Rule::MinEnclosedArea {
                    layer: one(spec)?,
                    limit: area_limit(spec, "limit")?,
                },
                "cheesing" => Rule::Cheesing {
                    layer: one(spec)?,
                    max_unslotted: area_limit(spec, "max_unslotted")?,
                },
                "density" => {
                    let (layer, boundary) = bounded(spec)?;
                    let (window, step) = (length(spec, "window")?, length(spec, "step")?);
                    Rule::Density {
                        layer,
                        boundary,
                        window,
                        step,
                        limit: ratio(spec, "limit")?,
                        sense: sense(spec)?,
                    }
                }
                "global_density" => {
                    let (layer, boundary) = bounded(spec)?;
                    Rule::GlobalDensity {
                        layer,
                        boundary,
                        limit: ratio(spec, "limit")?,
                        sense: sense(spec)?,
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
                    let layer = match spec.layer_len {
                        0 => None,
                        _ => Some(one(spec)?),
                    };
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
                    Rule::Angle { layer, allowed }
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
                "forbidden" => Rule::Forbidden { layer: one(spec)? },
                "must_contain" => {
                    let (outer, inner) = two(spec)?;
                    Rule::MustContain {
                        outer,
                        inner,
                        min_count: positive(spec, count(spec, "min_count", u32::MAX)?)?,
                    }
                }
                "must_be_inside" => {
                    let (inner, outer) = two(spec)?;
                    Rule::MustBeInside { inner, outer }
                }
                "net_spacing" => {
                    let layer = one(spec)?;
                    let ParamValue::Flag(same_net) = value(spec, "same_net")? else {
                        return Err(wrong_type(spec, "same_net"));
                    };
                    Rule::NetSpacing {
                        layer,
                        same_net,
                        limit: length(spec, "limit")?,
                    }
                }
                "spacing_table" => {
                    let layer = one(spec)?;
                    let lengths = |param: &'static str| -> Result<Vec<Dbu>, DrcError> {
                        let wanted = strings.get(param);
                        rules
                            .params_of(spec)
                            .iter()
                            .filter(|&&(name, _)| Some(name) == wanted)
                            .map(|&(_, stated)| match stated {
                                ParamValue::Length(length) => Ok(length),
                                _ => Err(wrong_type(spec, param)),
                            })
                            .collect()
                    };
                    let table = SpacingTable {
                        prl: lengths("prl")?,
                        width: lengths("width")?,
                        space: lengths("space")?,
                    };
                    if !table.is_valid() {
                        return Err(DrcError::BadTable(name_of(spec.id)));
                    }
                    set.tables.push(table);
                    Rule::SpacingTable {
                        layer,
                        table: u32::try_from(set.tables.len() - 1).expect("a deck has few tables"),
                    }
                }
                "attached_wide_spacing" => Rule::AttachedWideSpacing {
                    layer: one(spec)?,
                    width_threshold: length(spec, "width_threshold")?,
                    attached: length(spec, "attached")?,
                    limit: length(spec, "limit")?,
                },
                "edge_min_length" => Rule::EdgeMinLength {
                    layer: one(spec)?,
                    limit: length(spec, "limit")?,
                },
                "edge_spacing" => {
                    let (a, b) = match spec.layer_len {
                        1 => (one(spec)?, None),
                        _ => two(spec).map(|(a, b)| (a, Some(b)))?,
                    };
                    Rule::EdgeSpacing {
                        a,
                        b,
                        limit: length(spec, "limit")?,
                    }
                }
                "edge_enclosure" => {
                    let (edges, outer) = two(spec)?;
                    Rule::EdgeEnclosure {
                        edges,
                        outer,
                        limit: length(spec, "limit")?,
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

    /// [`Self::run_with_nets`] without nets: a rule that reads them is `Refused`.
    pub fn run(&self, store: &GeometryStore, out: &mut Violations, runs: &mut Vec<RuleRun>) {
        self.run_with_nets(store, None, out, runs);
    }

    /// Run every rule; `out` and `runs` are cleared first, then `runs` gains one
    /// row per rule, in rule order. `nets` is the store's extraction.
    pub fn run_with_nets(
        &self,
        store: &GeometryStore,
        nets: Option<&NetTable>,
        out: &mut Violations,
        runs: &mut Vec<RuleRun>,
    ) {
        *out = Violations::default();
        runs.clear();
        let s = &mut Scratch::default();
        // The last rule reading each layer; its validation is dropped after that rule.
        let mut last_use: Vec<usize> = Vec::new();
        for (at, (_, rule)) in self.rules.iter().enumerate() {
            for layer in rule.layers().into_iter().flatten() {
                if last_use.len() <= layer.idx() {
                    last_use.resize(layer.idx() + 1, 0);
                }
                last_use[layer.idx()] = at;
            }
        }
        for (at, &(id, rule)) in self.rules.iter().enumerate() {
            let before = out.len();
            let (outcome, examined) = match rule {
                Rule::MinWidth { layer, limit } => {
                    width::facing(store, id, layer, limit, true, s, out)
                }
                Rule::MaxWidth { layer, limit } => {
                    width::max_width(store, id, layer, limit, s, out)
                }
                Rule::CutSize {
                    layer,
                    width,
                    height,
                } => width::cut_size(store, id, layer, width, height, s, out),
                Rule::Notch { layer, limit } => {
                    width::facing(store, id, layer, limit, false, s, out)
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
                } => spacing::wide_dependent(
                    store,
                    id,
                    layer,
                    (width_threshold, Dbu::new_unchecked(0)),
                    limit,
                    s,
                    out,
                ),
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
                    boundary,
                    window,
                    step,
                    limit,
                    sense,
                } => area::density(
                    store,
                    id,
                    (layer, boundary),
                    (window, step),
                    limit,
                    sense,
                    s,
                    out,
                ),
                Rule::GlobalDensity {
                    layer,
                    boundary,
                    limit,
                    sense,
                } => area::global_density(store, id, (layer, boundary), limit, sense, s, out),
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
                Rule::Angle { layer, allowed } => grid::angle(store, id, layer, allowed, out),
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
                Rule::Forbidden { layer } => presence::forbidden(store, id, layer, s, out),
                Rule::MustContain {
                    outer,
                    inner,
                    min_count,
                } => presence::must_contain(store, id, outer, inner, min_count, s, out),
                Rule::MustBeInside { inner, outer } => {
                    presence::must_be_inside(store, id, inner, outer, s, out)
                }
                Rule::NetSpacing {
                    layer,
                    same_net,
                    limit,
                } => match nets {
                    Some(nets) => {
                        spacing::net_spacing(store, nets, id, layer, same_net, limit, s, out)
                    }
                    None => (Outcome::Refused, 0),
                },
                Rule::SpacingTable { layer, table } => {
                    spacing::spacing_table(store, id, layer, &self.tables[table as usize], s, out)
                }
                Rule::AttachedWideSpacing {
                    layer,
                    width_threshold,
                    attached,
                    limit,
                } => spacing::wide_dependent(
                    store,
                    id,
                    layer,
                    (width_threshold, attached),
                    limit,
                    s,
                    out,
                ),
                Rule::EdgeMinLength { layer, limit } => {
                    edge::min_length(store, id, layer, limit, out)
                }
                Rule::EdgeSpacing { a, b, limit } => edge::spacing(store, id, a, b, limit, out),
                Rule::EdgeEnclosure {
                    edges,
                    outer,
                    limit,
                } => edge::enclosure(store, id, edges, outer, limit, s, out),
            };
            record_run(runs, out, before, id, outcome, examined);
            for layer in rule.layers().into_iter().flatten() {
                if last_use[layer.idx()] == at {
                    s.validated.forget(layer);
                }
            }
        }
    }
}

impl Rule {
    /// Every layer the rule reads.
    fn layers(&self) -> [Option<LayerId>; 2] {
        match *self {
            Rule::MinWidth { layer, .. }
            | Rule::MaxWidth { layer, .. }
            | Rule::CutSize { layer, .. }
            | Rule::MinEdgeLength { layer, .. }
            | Rule::Notch { layer, .. }
            | Rule::MinSpacing { layer, .. }
            | Rule::EolSpacing { layer, .. }
            | Rule::PrlSpacing { layer, .. }
            | Rule::CornerToCorner { layer, .. }
            | Rule::WideDependentSpacing { layer, .. }
            | Rule::MinArea { layer, .. }
            | Rule::MinEnclosedArea { layer, .. }
            | Rule::Cheesing { layer, .. }
            | Rule::RedundantVia { layer, .. }
            | Rule::ViaArraySpacing { layer, .. }
            | Rule::MultiPatterning { layer, .. }
            | Rule::Forbidden { layer }
            | Rule::NetSpacing { layer, .. }
            | Rule::SpacingTable { layer, .. }
            | Rule::AttachedWideSpacing { layer, .. }
            | Rule::EdgeMinLength { layer, .. } => [Some(layer), None],
            Rule::EdgeSpacing { a, b, .. } => [Some(a), b],
            Rule::Density {
                layer, boundary, ..
            }
            | Rule::GlobalDensity {
                layer, boundary, ..
            } => [Some(layer), boundary],
            Rule::MinSpacingDiff { a, b, .. }
            | Rule::Overlap { a, b, .. }
            | Rule::MinEnclosure {
                outer: a, inner: b, ..
            }
            | Rule::AsymmetricEnclosure {
                outer: a, inner: b, ..
            }
            | Rule::MinExtension {
                layer: a,
                reference: b,
                ..
            }
            | Rule::MaxDistanceToTap {
                well: a, tap: b, ..
            }
            | Rule::MustContain {
                outer: a, inner: b, ..
            }
            | Rule::MustBeInside { inner: a, outer: b }
            | Rule::EdgeEnclosure {
                edges: a, outer: b, ..
            } => [Some(a), Some(b)],
            Rule::Angle { layer, .. } => [layer, None],
            Rule::OffGrid { .. } => [None, None],
        }
    }
}

/// Every rule kind this crate implements, as the deck spells it. Disjoint from
/// `crate::erc::ruleset::KINDS`.
pub const KINDS: [&str; 35] = [
    "min_width",
    "max_width",
    "cut_size",
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
    "global_density",
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
    "forbidden",
    "must_contain",
    "must_be_inside",
    "net_spacing",
    "spacing_table",
    "attached_wide_spacing",
    "edge_min_length",
    "edge_spacing",
    "edge_enclosure",
];
