//! The rule set: every kind's table, the deck builder, and the dispatcher.
//!
//! A deck's rules arrive as a flat [`RuleTable`] of [`RuleSpec`] rows whose
//! kind is an interned string; [`RuleSet::from_deck`] matches that string once
//! per rule and files the row into the table for its kind. After that the kind
//! is encoded in *which table the row is in*, so no transform needs a tag.
//!
//! [`RuleTable`]: gpurify_ingest::deck::RuleTable
//! [`RuleSpec`]: gpurify_ingest::deck::RuleSpec

use crate::drc::rules::area::{CheesingTable, DensityTable, MinAreaTable, MinEnclosedAreaTable};
use crate::drc::rules::grid::{AngleTable, OffGridTable};
use crate::drc::rules::overlay::{
    AsymmetricEnclosureTable, MaxDistanceToTapTable, MinEnclosureTable, MinExtensionTable,
    OverlapTable,
};
use crate::drc::rules::patterning::MultiPatterningTable;
use crate::drc::rules::spacing::{
    CornerToCornerTable, EolSpacingTable, MinSpacingDiffTable, MinSpacingTable, PrlSpacingTable,
    WideDependentSpacingTable,
};
use crate::drc::rules::via::{RedundantViaTable, ViaArraySpacingTable};
use crate::drc::rules::width::{MaxWidthTable, MinEdgeLengthTable, MinWidthTable, NotchTable};
use crate::drc::rules::{area, grid, overlay, patterning, spacing, via, width};
use crate::drc::{Design, DrcError, Scratch};

/// Files a deck row into its table: check the layer count, parse the
/// parameters, then push one value into each column.
///
/// Each entry reads `<index> "<kind>" <table> [<layers>] { <column>: <value> }`.
/// Every value is parsed before any column is pushed: a row that fails parsing
/// must not leave one column longer than its siblings, which is the invariant
/// `row_columns!` asserts on every `len`. Kinds needing more than this are
/// written out after `@rest`.
macro_rules! deck_arms {
    ($set:ident, $spec:ident, $kind:ident, $layers:ident,
     $($n:literal $name:literal $table:ident [$count:literal] { $($col:ident : $val:expr),+ $(,)? })+
     @rest $($rest:tt)*) => {
        match $kind {
            $($n => {
                debug_assert_eq!(KINDS[$kind], $name);
                $layers($spec, $count)?;
                let ($($col,)+) = ($($val,)+);
                $($set.$table.$col.push($col);)+
            })+
            $($rest)*
        }
    };
}

/// Runs one transform per **non-empty** table, in the order written.
///
/// The emptiness guard is not an optimisation: a kind the deck does not
/// configure must produce no [`RuleRun`] at all, and that silence is a
/// different claim from a skip.
macro_rules! dispatch {
    ($self:ident, $design:ident, $scratch:ident, $out:ident, $runs:ident,
     $($table:ident => $check:path),+ $(,)?) => {$(
        if !$self.$table.is_empty() {
            $check($design, &$self.$table, $scratch, $out, $runs);
        }
    )+};
}
use crate::report::{LimitSense, RuleRun, Violations};
use gpurify_geom::Dbu;
use gpurify_ingest::deck::{Deck, ParamValue, RuleSpec};
use gpurify_ingest::{StrId, StrTable};

/// Every DRC rule the deck configures, filed by kind.
///
/// Twenty-four distinct field types rather than one `Vec<Rule>` with a kind
/// tag, so the dispatcher below cannot be wired up wrong in a way that still
/// compiles and reports the wrong rule id.
#[derive(Debug, Default)]
pub struct RuleSet {
    pub min_width: MinWidthTable,
    pub max_width: MaxWidthTable,
    pub min_edge_length: MinEdgeLengthTable,
    pub notch: NotchTable,

    pub min_spacing: MinSpacingTable,
    pub min_spacing_diff: MinSpacingDiffTable,
    pub eol_spacing: EolSpacingTable,
    pub prl_spacing: PrlSpacingTable,
    pub corner_to_corner: CornerToCornerTable,
    pub wide_dependent_spacing: WideDependentSpacingTable,

    pub min_area: MinAreaTable,
    pub min_enclosed_area: MinEnclosedAreaTable,
    pub cheesing: CheesingTable,
    pub density: DensityTable,

    pub min_enclosure: MinEnclosureTable,
    pub asymmetric_enclosure: AsymmetricEnclosureTable,
    pub min_extension: MinExtensionTable,
    pub overlap: OverlapTable,
    pub max_distance_to_tap: MaxDistanceToTapTable,

    pub off_grid: OffGridTable,
    pub angle: AngleTable,

    pub redundant_via: RedundantViaTable,
    pub via_array_spacing: ViaArraySpacingTable,

    pub multi_patterning: MultiPatterningTable,
}

impl RuleSet {
    /// File every rule in the deck into the table for its kind.
    ///
    /// Rejects rather than skips any row this crate's [`KINDS`] spells: a
    /// missing or mistyped parameter, the wrong number of layers, a
    /// non-positive limit, a duplicate rule id. A kind absent from [`KINDS`]
    /// belongs to another domain and is stepped over — the engine refuses a
    /// kind in neither this array nor `crate::erc::ruleset::KINDS` before
    /// either rule set is built, so that skip is not a silent drop.
    ///
    /// Layer resolution and grid conversion are already done by `ingest`;
    /// nothing here parses text or touches a grid.
    #[allow(
        clippy::too_many_lines,
        reason = "one arm per rule kind, in KINDS order; splitting it would put \
                  half the deck vocabulary out of sight of the other half, which \
                  is the one thing a reader checking this file needs to compare"
    )]
    pub fn from_deck(deck: &Deck, strings: &StrTable) -> Result<Self, DrcError> {
        // The three area limits — `min_area`, `min_enclosed_area`, `cheesing`
        // — are stated by the deck as the *side of the equivalent square*,
        // squared by `square` below, because `ParamValue` has no area variant.
        // A real PDK area has no integer square root, so the deck author
        // rounds: the rounding that reports nothing is *down* for the two
        // minima and *up* for `cheesing`.
        let rules = &deck.rules;

        // Every kind name resolved once, so the per-row match below is `u32`
        // equality and never a string compare. A kind the run's table has never
        // seen is `None`, which no `spec.kind` can equal.
        let kind_id: [Option<StrId>; KINDS.len()] =
            std::array::from_fn(|at| strings.get(KINDS[at]));

        let name_of = |id: StrId| strings.resolve(id).to_owned();

        // Duplicates first, before a single row is filed: two rows sharing an
        // id produce two `RuleRun` rows attributable to nothing.
        let mut ids: Vec<StrId> = rules.spec.iter().map(|spec| spec.id).collect();
        ids.sort_unstable();
        if let Some(pair) = ids.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(DrcError::DuplicateRule(name_of(pair[0])));
        }

        let value = |spec: &RuleSpec, param: &'static str| -> Result<ParamValue, DrcError> {
            // `get`, never `intern`: a parameter name the table has never seen
            // cannot be one the deck spelled, and interning here would hand
            // back an id that matches nothing.
            strings
                .get(param)
                .and_then(|interned| rules.param(spec, interned))
                .ok_or_else(|| DrcError::MissingParam {
                    rule: name_of(spec.id),
                    param,
                })
        };

        // A distance, area or count limit of zero passes every shape while
        // looking configured, so it is refused rather than believed.
        let length = |spec: &RuleSpec, param: &'static str| -> Result<Dbu, DrcError> {
            let ParamValue::Length(limit) = value(spec, param)? else {
                return Err(DrcError::WrongParamType {
                    rule: name_of(spec.id),
                    param,
                });
            };
            if limit.raw() <= 0 {
                return Err(DrcError::NonPositiveLimit {
                    rule: name_of(spec.id),
                    limit: limit.raw(),
                });
            }
            Ok(limit)
        };

        let square =
            |spec: &RuleSpec, param: &'static str| -> Result<gpurify_geom::DbuArea, DrcError> {
                let side = length(spec, param)?;
                debug_assert!(
                    side.raw() <= gpurify_geom::MAX_ABS_DBU,
                    "a side past the coordinate domain squares past the i128 ceiling"
                );
                Ok(side.mul_wide(side))
            };

        let ratio_of = |spec: &RuleSpec, param: &'static str| -> Result<f64, DrcError> {
            let ParamValue::Ratio(limit) = value(spec, param)? else {
                return Err(DrcError::WrongParamType {
                    rule: name_of(spec.id),
                    param,
                });
            };
            // `!(x > 0)` rather than `x <= 0`: a NaN limit compares false
            // against every measurement downstream and reads as a clean rule,
            // which is the fail-open shape this whole crate is built against.
            if !(limit > 0.0) || !limit.is_finite() {
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "the error reports a rejected limit to a human; the \
                              truncated form of a non-positive ratio is still \
                              non-positive"
                )]
                let shown = limit as i64;
                return Err(DrcError::NonPositiveLimit {
                    rule: name_of(spec.id),
                    limit: shown,
                });
            }
            Ok(limit)
        };

        // Counts are stored narrower than the deck may state them, so a value
        // past the column's width is a deck error rather than a wrap.
        let count = |spec: &RuleSpec, param: &'static str, ceiling: u32| -> Result<u32, DrcError> {
            let ParamValue::Count(found) = value(spec, param)? else {
                return Err(DrcError::WrongParamType {
                    rule: name_of(spec.id),
                    param,
                });
            };
            if found > ceiling {
                return Err(DrcError::WrongParamType {
                    rule: name_of(spec.id),
                    param,
                });
            }
            Ok(found)
        };

        let flag = |spec: &RuleSpec, param: &'static str| -> Result<bool, DrcError> {
            let ParamValue::Flag(set) = value(spec, param)? else {
                return Err(DrcError::WrongParamType {
                    rule: name_of(spec.id),
                    param,
                });
            };
            Ok(set)
        };

        let layers = |spec: &RuleSpec, expected: u32| -> Result<(), DrcError> {
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

        let mut set = Self::default();

        for spec in &rules.spec {
            // A kind this crate does not spell is another domain's row;
            // `engine::run::run_checks` is what refuses a kind no domain
            // spells, so this skip is not a silent drop.
            let Some(kind) = kind_id.iter().position(|&name| name == Some(spec.kind)) else {
                continue;
            };

            deck_arms! { set, spec, kind, layers,
                0 "min_width" min_width [1] { rule: spec.id, layer: layer(spec, 0), limit: length(spec, "limit")? }
                1 "max_width" max_width [1] { rule: spec.id, layer: layer(spec, 0), limit: length(spec, "limit")? }
                2 "min_edge_length" min_edge_length [1] { rule: spec.id, layer: layer(spec, 0), limit: length(spec, "limit")? }
                3 "notch" notch [1] { rule: spec.id, layer: layer(spec, 0), limit: length(spec, "limit")? }
                4 "min_spacing" min_spacing [1] { rule: spec.id, layer: layer(spec, 0), limit: length(spec, "limit")? }
                5 "min_spacing_diff" min_spacing_diff [2] { rule: spec.id, a: layer(spec, 0), b: layer(spec, 1), limit: length(spec, "limit")? }
                6 "eol_spacing" eol_spacing [1] { rule: spec.id, layer: layer(spec, 0), eol_width: length(spec, "eol_width")?, limit: length(spec, "limit")? }
                7 "prl_spacing" prl_spacing [1] { rule: spec.id, layer: layer(spec, 0), prl_threshold: length(spec, "prl_threshold")?, limit: length(spec, "limit")? }
                8 "corner_to_corner" corner_to_corner [1] { rule: spec.id, layer: layer(spec, 0), limit: length(spec, "limit")? }
                9 "wide_dependent_spacing" wide_dependent_spacing [1] { rule: spec.id, layer: layer(spec, 0), width_threshold: length(spec, "width_threshold")?, limit: length(spec, "limit")? }
                10 "min_area" min_area [1] { rule: spec.id, layer: layer(spec, 0), limit: square(spec, "limit")? }
                11 "min_enclosed_area" min_enclosed_area [1] { rule: spec.id, layer: layer(spec, 0), limit: square(spec, "limit")? }
                12 "cheesing" cheesing [1] { rule: spec.id, layer: layer(spec, 0), max_unslotted: square(spec, "max_unslotted")? }
                14 "min_enclosure" min_enclosure [2] { rule: spec.id, outer: layer(spec, 0), inner: layer(spec, 1), limit: length(spec, "limit")? }
                15 "asymmetric_enclosure" asymmetric_enclosure [2] { rule: spec.id, outer: layer(spec, 0), inner: layer(spec, 1), min_one_side: length(spec, "min_one_side")? }
                16 "min_extension" min_extension [2] { rule: spec.id, layer: layer(spec, 0), reference: layer(spec, 1), limit: length(spec, "limit")? }
                17 "overlap" overlap [2] { rule: spec.id, a: layer(spec, 0), b: layer(spec, 1), limit: length(spec, "limit")? }
                18 "max_distance_to_tap" max_distance_to_tap [2] { rule: spec.id, well: layer(spec, 0), tap: layer(spec, 1), limit: length(spec, "limit")? }
                19 "off_grid" off_grid [0] { rule: spec.id, pitch: length(spec, "pitch")? }

                @rest
                13 => {
                    debug_assert_eq!(KINDS[kind], "density");
                    layers(spec, 1)?;
                    let window = length(spec, "window")?;
                    let step = length(spec, "step")?;
                    let limit = ratio_of(spec, "limit")?;
                    // Stated, never defaulted: guessing the sense picks the
                    // reading that reports nothing.
                    let maximum = flag(spec, "maximum")?;
                    set.density.rule.push(spec.id);
                    set.density.layer.push(layer(spec, 0));
                    set.density.window.push(window);
                    set.density.step.push(step);
                    set.density.limit.push(limit);
                    set.density.sense.push(if maximum {
                        LimitSense::Maximum
                    } else {
                        LimitSense::Minimum
                    });
                }
                20 => {
                    debug_assert_eq!(KINDS[kind], "angle");
                    layers(spec, 0)?;
                    let start = u32::try_from(set.angle.allowed.len())
                        .expect("a deck's allowed directions number in the tens");
                    // One `angle` parameter per allowed direction, so the row's
                    // whole parameter list is scanned rather than one name
                    // looked up.
                    let wanted = strings.get("angle");
                    for &(param, stated) in rules.params_of(spec) {
                        if Some(param) != wanted {
                            continue;
                        }
                        let ParamValue::Count(degrees) = stated else {
                            return Err(DrcError::WrongParamType {
                                rule: name_of(spec.id),
                                param: "angle",
                            });
                        };
                        // A direction is periodic in a full turn, so the
                        // reduction is exact and keeps the `i32` cast faithful.
                        let degrees = i32::try_from(degrees % 360).expect("under a full turn");
                        let direction = grid::Direction::from_degrees(degrees).ok_or_else(|| {
                            DrcError::UnrepresentableAngle {
                                rule: name_of(spec.id),
                                degrees,
                            }
                        })?;
                        set.angle.allowed.push(direction);
                    }
                    let end = u32::try_from(set.angle.allowed.len())
                        .expect("a deck's allowed directions number in the tens");
                    if end == start {
                        // An empty allowed set rejects every edge in the
                        // design, which is not a configuration anyone means.
                        return Err(DrcError::MissingParam {
                            rule: name_of(spec.id),
                            param: "angle",
                        });
                    }
                    set.angle.rule.push(spec.id);
                    set.angle.allowed_start.push(start);
                    set.angle.allowed_len.push(end - start);
                }
                21 => {
                    debug_assert_eq!(KINDS[kind], "redundant_via");
                    layers(spec, 1)?;
                    let min_count = count(spec, "min_count", u32::from(u16::MAX))?;
                    if min_count == 0 {
                        return Err(DrcError::NonPositiveLimit {
                            rule: name_of(spec.id),
                            limit: 0,
                        });
                    }
                    let within = length(spec, "within")?;
                    set.redundant_via.rule.push(spec.id);
                    set.redundant_via.layer.push(layer(spec, 0));
                    set.redundant_via
                        .min_count
                        .push(u16::try_from(min_count).expect("checked against the ceiling"));
                    set.redundant_via.within.push(within);
                }
                22 => {
                    debug_assert_eq!(KINDS[kind], "via_array_spacing");
                    layers(spec, 1)?;
                    // Zero is a legal threshold — it makes every cluster an
                    // array — so this one is not checked for positivity.
                    let array_threshold = count(spec, "array_threshold", u32::from(u16::MAX))?;
                    let limit = length(spec, "limit")?;
                    set.via_array_spacing.rule.push(spec.id);
                    set.via_array_spacing.layer.push(layer(spec, 0));
                    set.via_array_spacing
                        .array_threshold
                        .push(u16::try_from(array_threshold).expect("checked against the ceiling"));
                    set.via_array_spacing.limit.push(limit);
                }
                23 => {
                    debug_assert_eq!(KINDS[kind], "multi_patterning");
                    layers(spec, 1)?;
                    let colors = count(spec, "colors", u32::from(u8::MAX))?;
                    if colors == 0 {
                        return Err(DrcError::NonPositiveLimit {
                            rule: name_of(spec.id),
                            limit: 0,
                        });
                    }
                    let color_spacing = length(spec, "color_spacing")?;
                    set.multi_patterning.rule.push(spec.id);
                    set.multi_patterning.layer.push(layer(spec, 0));
                    set.multi_patterning
                        .colors
                        .push(u8::try_from(colors).expect("checked against the ceiling"));
                    set.multi_patterning.color_spacing.push(color_spacing);
                }
                // Unreachable via `KINDS`, but fail closed rather than panic: a
                // twenty-fifth name with no arm here would otherwise be filed
                // nowhere and reported as checked.
                _ => {
                    return Err(DrcError::UnknownKind {
                        rule: name_of(spec.id),
                        kind: name_of(spec.kind),
                    })
                }
            }
        }

        // Every row this crate spells is filed; other domains' rows are skipped
        // above and excluded from the count.
        debug_assert_eq!(
            set.rule_count(),
            rules
                .spec
                .iter()
                .filter(|spec| kind_id.contains(&Some(spec.kind)))
                .count(),
            "a deck row was filed under no kind, so a configured rule would never run"
        );
        Ok(set)
    }

    /// How many rule rows the set holds, across every table.
    ///
    /// The number of [`RuleRun`] rows [`RuleSet::run`] will produce.
    pub fn rule_count(&self) -> usize {
        self.min_width.len()
            + self.max_width.len()
            + self.min_edge_length.len()
            + self.notch.len()
            + self.min_spacing.len()
            + self.min_spacing_diff.len()
            + self.eol_spacing.len()
            + self.prl_spacing.len()
            + self.corner_to_corner.len()
            + self.wide_dependent_spacing.len()
            + self.min_area.len()
            + self.min_enclosed_area.len()
            + self.cheesing.len()
            + self.density.len()
            + self.min_enclosure.len()
            + self.asymmetric_enclosure.len()
            + self.min_extension.len()
            + self.overlap.len()
            + self.max_distance_to_tap.len()
            + self.off_grid.len()
            + self.angle.len()
            + self.redundant_via.len()
            + self.via_array_spacing.len()
            + self.multi_patterning.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rule_count() == 0
    }

    /// Run every configured rule.
    ///
    /// `out` and `runs` are cleared here — the one place they are, since the
    /// transforms themselves append — and `runs` gains exactly
    /// [`RuleSet::rule_count`] rows, left in dispatch order.
    ///
    /// Infallible: geometry a rule cannot handle is that rule's
    /// [`Outcome::Refused`](crate::report::Outcome::Refused) row, not the
    /// run's failure. Everything that could fail the whole run already failed
    /// in [`RuleSet::from_deck`].
    pub fn run(
        &self,
        design: Design<'_>,
        scratch: &mut Scratch,
        out: &mut Violations,
        runs: &mut Vec<RuleRun>,
    ) {
        // The one place either container is cleared. Column by column because
        // the table is `SoA` and has no `clear`; capacity is kept.
        out.rule.clear();
        out.layer.clear();
        out.severity.clear();
        out.at.clear();
        out.measured.clear();
        out.limit.clear();
        out.shape_a.clear();
        out.shape_b.clear();
        runs.clear();
        debug_assert!(out.is_empty(), "run started over a table it did not clear");

        let expected = self.rule_count();

        dispatch! { self, design, scratch, out, runs,
            min_width => width::check_min_width,
            max_width => width::check_max_width,
            min_edge_length => width::check_min_edge_length,
            notch => width::check_notch,

            min_spacing => spacing::check_min_spacing,
            min_spacing_diff => spacing::check_min_spacing_diff,
            eol_spacing => spacing::check_eol_spacing,
            prl_spacing => spacing::check_prl_spacing,
            corner_to_corner => spacing::check_corner_to_corner,
            wide_dependent_spacing => spacing::check_wide_dependent_spacing,

            min_area => area::check_min_area,
            min_enclosed_area => area::check_min_enclosed_area,
            cheesing => area::check_cheesing,
            density => area::check_density,

            min_enclosure => overlay::check_min_enclosure,
            asymmetric_enclosure => overlay::check_asymmetric_enclosure,
            min_extension => overlay::check_min_extension,
            overlap => overlay::check_overlap,
            max_distance_to_tap => overlay::check_max_distance_to_tap,

            off_grid => grid::check_off_grid,
            angle => grid::check_angle,

            redundant_via => via::check_redundant_via,
            via_array_spacing => via::check_via_array_spacing,

            multi_patterning => patterning::check_multi_patterning,
        }

        // One run row per configured rule row. A missing line above is silent
        // in the violation table and is exactly what this catches.
        debug_assert_eq!(
            runs.len(),
            expected,
            "a configured rule produced no run row, which reads as a clean design"
        );
    }
}

/// Every rule kind this crate implements, as the deck spells it.
///
/// Order matches the field order of [`RuleSet`], so a failure naming index `i`
/// names `KINDS[i]`. Disjoint from `crate::erc::ruleset::KINDS`: one deck row
/// must be filed by exactly one domain.
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

/// The rule-dispatch adapter test: every table holding a row produces exactly
/// one run row attributable to it.
#[cfg(test)]
mod tests {
    use super::RuleSet;
    use crate::drc::rules::grid::Direction;
    use crate::drc::{Design, Scratch};
    use crate::report::{LimitSense, Outcome, RuleRun, Violations};
    use crate::topology::{DeviceTable, NetTable};
    use gpurify_geom::Evaluator;
    use gpurify_geom::{GeometryStore, LayerId};
    use gpurify_ingest::StrId;
    use gpurify_testgen::dbu;
    use gpurify_testgen::shapes::{area, hole, rect, LayoutBuilder};

    const A: LayerId = LayerId(0);
    const B: LayerId = LayerId(1);

    use super::KINDS;

    fn id(kind: &str) -> StrId {
        let index = KINDS
            .iter()
            .position(|&name| name == kind)
            .expect("every rule id in this module names a kind");
        StrId(u32::try_from(index).expect("twenty-four kinds"))
    }

    /// Geometry chosen so no rule has an empty population to look at.
    fn populated_design() -> GeometryStore {
        let mut layout = LayoutBuilder::new(2);
        layout.rect(A, 0, 0, 200, 1_000);
        layout.rect(A, 300, 0, 500, 1_000);
        layout.rect(A, 600, 0, 800, 200);
        layout.rect(A, 600, 300, 800, 500);
        layout.rect(A, 2_000, 2_000, 2_100, 2_100);
        layout.rect(A, 2_200, 2_200, 2_300, 2_300);
        layout.shape(A, &rect(5_000, 5_000, 5_400, 5_400));
        layout.shape(A, &hole(5_100, 5_100, 5_300, 5_300));
        layout.rect(B, -100, -100, 600, 1_100);
        layout.rect(B, 3_000, 3_000, 3_100, 3_100);
        let (store, _ids) = layout.finish();
        store
    }

    /// One row in every one of the twenty-four tables, each with a distinct id.
    #[allow(
        clippy::too_many_lines,
        reason = "one statement group per rule kind; splitting it would hide the \
                  fact that this fixture is an exhaustive inventory of RuleSet's \
                  fields, which is the only reason it exists"
    )]
    fn full_deck() -> RuleSet {
        let mut set = RuleSet::default();

        set.min_width.rule.push(id("min_width"));
        set.min_width.layer.push(A);
        set.min_width.limit.push(dbu(1));

        set.max_width.rule.push(id("max_width"));
        set.max_width.layer.push(A);
        set.max_width.limit.push(dbu(1_000_000));

        set.min_edge_length.rule.push(id("min_edge_length"));
        set.min_edge_length.layer.push(A);
        set.min_edge_length.limit.push(dbu(1));

        set.notch.rule.push(id("notch"));
        set.notch.layer.push(A);
        set.notch.limit.push(dbu(1));

        set.min_spacing.rule.push(id("min_spacing"));
        set.min_spacing.layer.push(A);
        set.min_spacing.limit.push(dbu(100));

        set.min_spacing_diff.rule.push(id("min_spacing_diff"));
        set.min_spacing_diff.a.push(A);
        set.min_spacing_diff.b.push(B);
        set.min_spacing_diff.limit.push(dbu(100));

        set.eol_spacing.rule.push(id("eol_spacing"));
        set.eol_spacing.layer.push(A);
        set.eol_spacing.eol_width.push(dbu(300));
        set.eol_spacing.limit.push(dbu(100));

        set.prl_spacing.rule.push(id("prl_spacing"));
        set.prl_spacing.layer.push(A);
        set.prl_spacing.prl_threshold.push(dbu(1));
        set.prl_spacing.limit.push(dbu(100));

        set.corner_to_corner.rule.push(id("corner_to_corner"));
        set.corner_to_corner.layer.push(A);
        set.corner_to_corner.limit.push(dbu(200));

        set.wide_dependent_spacing
            .rule
            .push(id("wide_dependent_spacing"));
        set.wide_dependent_spacing.layer.push(A);
        set.wide_dependent_spacing.width_threshold.push(dbu(1));
        set.wide_dependent_spacing.limit.push(dbu(100));

        set.min_area.rule.push(id("min_area"));
        set.min_area.layer.push(A);
        set.min_area.limit.push(area(1));

        set.min_enclosed_area.rule.push(id("min_enclosed_area"));
        set.min_enclosed_area.layer.push(A);
        set.min_enclosed_area.limit.push(area(1));

        set.cheesing.rule.push(id("cheesing"));
        set.cheesing.layer.push(A);
        set.cheesing.max_unslotted.push(area(1_000_000_000));

        set.density.rule.push(id("density"));
        set.density.layer.push(A);
        set.density.window.push(dbu(1_000));
        set.density.step.push(dbu(500));
        set.density.limit.push(1.0);
        set.density.sense.push(LimitSense::Maximum);

        set.min_enclosure.rule.push(id("min_enclosure"));
        set.min_enclosure.outer.push(B);
        set.min_enclosure.inner.push(A);
        set.min_enclosure.limit.push(dbu(1));

        set.asymmetric_enclosure
            .rule
            .push(id("asymmetric_enclosure"));
        set.asymmetric_enclosure.outer.push(B);
        set.asymmetric_enclosure.inner.push(A);
        set.asymmetric_enclosure.min_one_side.push(dbu(1));

        set.min_extension.rule.push(id("min_extension"));
        set.min_extension.layer.push(A);
        set.min_extension.reference.push(B);
        set.min_extension.limit.push(dbu(1));

        set.overlap.rule.push(id("overlap"));
        set.overlap.a.push(A);
        set.overlap.b.push(B);
        set.overlap.limit.push(dbu(1));

        set.max_distance_to_tap.rule.push(id("max_distance_to_tap"));
        set.max_distance_to_tap.well.push(A);
        set.max_distance_to_tap.tap.push(B);
        set.max_distance_to_tap.limit.push(dbu(1_000_000));

        set.off_grid.rule.push(id("off_grid"));
        set.off_grid.pitch.push(dbu(1));

        set.angle.rule.push(id("angle"));
        set.angle.allowed_start.push(0);
        set.angle.allowed_len.push(2);
        set.angle.allowed.push(Direction { dx: 1, dy: 0 });
        set.angle.allowed.push(Direction { dx: 0, dy: 1 });

        set.redundant_via.rule.push(id("redundant_via"));
        set.redundant_via.layer.push(A);
        set.redundant_via.min_count.push(1);
        set.redundant_via.within.push(dbu(200));

        set.via_array_spacing.rule.push(id("via_array_spacing"));
        set.via_array_spacing.layer.push(A);
        set.via_array_spacing.array_threshold.push(0);
        set.via_array_spacing.limit.push(dbu(200));

        set.multi_patterning.rule.push(id("multi_patterning"));
        set.multi_patterning.layer.push(A);
        set.multi_patterning.colors.push(3);
        set.multi_patterning.color_spacing.push(dbu(100));

        set
    }

    struct Fixture {
        store: GeometryStore,
        derived: Evaluator,
        nets: NetTable,
        devices: DeviceTable,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                store: populated_design(),
                derived: Evaluator::default(),
                nets: NetTable::default(),
                devices: DeviceTable::default(),
            }
        }

        fn design(&self) -> Design<'_> {
            Design {
                store: &self.store,
                derived: &self.derived,
                nets: &self.nets,
                devices: &self.devices,
            }
        }
    }

    #[test]
    fn every_configured_rule_produces_exactly_one_attributable_run_row() {
        let fixture = Fixture::new();
        let set = full_deck();
        let mut scratch = Scratch::default();
        let mut out = Violations::default();
        let mut runs: Vec<RuleRun> = Vec::new();

        set.run(fixture.design(), &mut scratch, &mut out, &mut runs);

        assert_eq!(set.rule_count(), KINDS.len());
        assert_eq!(
            runs.len(),
            set.rule_count(),
            "the run must account for every rule it loaded"
        );

        let mut seen: Vec<u32> = runs.iter().map(|run| run.rule.0).collect();
        seen.sort_unstable();
        let expected: Vec<u32> =
            (0..u32::try_from(KINDS.len()).expect("twenty-four kinds")).collect();
        assert_eq!(
            seen, expected,
            "every table with a row must be dispatched exactly once"
        );
    }

    #[test]
    fn every_geometric_rule_ran_over_a_population_it_could_measure() {
        let fixture = Fixture::new();
        let set = full_deck();
        let mut scratch = Scratch::default();
        let mut out = Violations::default();
        let mut runs: Vec<RuleRun> = Vec::new();

        set.run(fixture.design(), &mut scratch, &mut out, &mut runs);

        for (index, kind) in KINDS.iter().enumerate() {
            let wanted = StrId(u32::try_from(index).expect("twenty-four kinds"));
            let run = runs
                .iter()
                .find(|run| run.rule == wanted)
                .unwrap_or_else(|| panic!("{kind} produced no run row"));

            assert_eq!(run.outcome, Outcome::Ran, "{kind} did not run");
            assert!(
                run.examined > 0,
                "{kind} ran but examined nothing, so nothing about it was exercised"
            );
        }
    }

    #[test]
    fn a_run_clears_the_outputs_it_was_handed() {
        let fixture = Fixture::new();
        let set = full_deck();
        let mut scratch = Scratch::default();
        let mut out = Violations::default();
        let mut runs: Vec<RuleRun> = vec![RuleRun {
            rule: StrId(9_999),
            outcome: Outcome::Refused,
            examined: 5,
            violations: 3,
        }];
        out.rule.push(StrId(9_999));

        set.run(fixture.design(), &mut scratch, &mut out, &mut runs);

        assert_eq!(runs.len(), set.rule_count());
        assert!(
            runs.iter().all(|run| run.rule != StrId(9_999)),
            "a stale run row survived into a new run"
        );
        assert!(
            out.rule.iter().all(|&rule| rule != StrId(9_999)),
            "a stale violation survived into a new run"
        );
    }

    #[test]
    fn an_empty_rule_set_holds_nothing_and_dispatches_nothing() {
        let fixture = Fixture::new();
        let set = RuleSet::default();
        assert!(set.is_empty());
        assert_eq!(set.rule_count(), 0);

        let mut scratch = Scratch::default();
        let mut out = Violations::default();
        let mut runs: Vec<RuleRun> = Vec::new();
        set.run(fixture.design(), &mut scratch, &mut out, &mut runs);

        assert!(runs.is_empty());
        assert!(out.rule.is_empty());
    }

    #[test]
    fn the_rule_count_is_the_sum_across_every_table() {
        let mut set = RuleSet::default();
        assert!(set.is_empty());

        set.min_width.rule.push(StrId(0));
        set.min_width.layer.push(A);
        set.min_width.limit.push(dbu(10));
        assert!(!set.is_empty());
        assert_eq!(set.rule_count(), 1);

        set.off_grid.rule.push(StrId(1));
        set.off_grid.pitch.push(dbu(5));
        assert_eq!(set.rule_count(), 2);

        set.min_width.rule.push(StrId(2));
        set.min_width.layer.push(B);
        set.min_width.limit.push(dbu(20));
        assert_eq!(set.rule_count(), 3);
    }
}
