//! The rule set: every kind's table, the deck builder, and the dispatcher.
//!
//! This is the file the dispatcher pattern is *for*. A deck's rules arrive as a
//! flat [`RuleTable`] of [`RuleSpec`] rows whose kind is an interned string;
//! [`RuleSet::from_deck`] matches that string once per rule and files the row
//! into the table for its kind. After that the kind is gone — it is encoded in
//! *which table the row is in*, and the transform over that table needs no tag,
//! no vtable and no match.
//!
//! Everything downstream is therefore uniform: [`RuleSet::run`] is a fixed list
//! of calls, one per table, each a straight-line loop over rows that all take
//! the same parameters. The cost of a rule kind is paid once at load; the run
//! pays nothing for kinds the deck does not use, because their tables are
//! empty and their transforms are never called.
//!
//! [`RuleTable`]: gpurify_ingest::deck::RuleTable
//! [`RuleSpec`]: gpurify_ingest::deck::RuleSpec

use crate::rules::area::{CheesingTable, DensityTable, MinAreaTable, MinEnclosedAreaTable};
use crate::rules::grid::{AngleTable, OffGridTable};
use crate::rules::overlay::{
    AsymmetricEnclosureTable, MaxDistanceToTapTable, MinEnclosureTable, MinExtensionTable,
    OverlapTable,
};
use crate::rules::patterning::MultiPatterningTable;
use crate::rules::spacing::{
    CornerToCornerTable, EolSpacingTable, MinSpacingDiffTable, MinSpacingTable, PrlSpacingTable,
    WideDependentSpacingTable,
};
use crate::rules::via::{RedundantViaTable, ViaArraySpacingTable};
use crate::rules::width::{MaxWidthTable, MinEdgeLengthTable, MinWidthTable, NotchTable};
use crate::rules::{area, grid, overlay, patterning, spacing, via, width};
use crate::{Design, DrcError, Scratch};
use gpurify_ingest::deck::{Deck, ParamValue, RuleSpec};
use gpurify_ingest::{StrId, StrTable};
use gpurify_report::{LimitSense, RuleRun, Violations};
use gpurify_units::Dbu;

/// Every DRC rule the deck configures, filed by kind.
///
/// **Five questions.** In: a [`Deck`] and the run's [`StrTable`]. Out: itself,
/// twenty-four `SoA` tables. How many: exactly one per run. Access pattern: each
/// table is read once, front to back, by its own transform — so the twenty-four
/// fields are never read together and there is nothing to gain from packing
/// them. Lifetime: the whole run, built once, never mutated. Parallelisable:
/// the tables are independent of one another; see [`Scratch`]'s ponytail note
/// for why the dispatcher does not yet exploit that.
///
/// Twenty-four distinct field types rather than one `Vec<Rule>` with a kind tag.
/// That is the whole architecture in one struct: passing a [`MinWidthTable`] to
/// [`check_notch`](crate::rules::width::check_notch) does not compile, so the
/// dispatcher below cannot be wired up wrong in a way that produces plausible
/// output. A tag-and-match design would compile and would report the wrong
/// rule id on every violation.
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
    /// **Transform, dispatcher — and the only place in this crate that branches
    /// on a rule kind.** One match per
    /// [`RuleSpec`](gpurify_ingest::deck::RuleSpec), at load, over an interned
    /// [`StrId`](gpurify_ingest::StrId): the kind names are looked up in
    /// `strings` once each up front, so the match is on `u32` equality and not
    /// on text.
    ///
    /// The kind names it matches are [`KINDS`], which is this crate's whole
    /// vocabulary and is stated there rather than here so a deck author, a deck
    /// parser and a test read it from one place. A kind absent from that array
    /// belongs to another domain and is stepped over, because the deck's one
    /// rule table feeds every domain. It is *not* dropped silently: the engine
    /// refuses a kind that is in neither this array nor
    /// `gpurify_erc::ruleset::KINDS` before it builds either rule set, so the
    /// only rows reaching here are rows some domain implements.
    ///
    /// `strings` is borrowed, not mutated. A kind or parameter name the table
    /// does not already contain cannot name anything the deck defined, so
    /// `StrTable::get` is the right call and interning here would grow the
    /// table with names that are by definition unused.
    ///
    /// # Fail closed
    ///
    /// Rejects rather than skips, in every case a row is this crate's: a
    /// missing or mistyped parameter, the wrong number of layers, a
    /// non-positive limit, a duplicate rule id. A deck with one rule this
    /// crate silently ignored
    /// produces a report that looks complete and is not, which is the failure
    /// mode the whole tree is built against. Partial construction is not
    /// offered, because a partially-loaded deck has no meaningful verdict.
    ///
    /// The layer resolution and grid conversion are already done — `ingest`
    /// produced [`ParamValue::Length`](gpurify_ingest::deck::ParamValue::Length)
    /// in [`Dbu`](gpurify_units::Dbu) against the run's grid, or refused the
    /// deck. Nothing here parses text or touches a grid.
    #[allow(
        clippy::too_many_lines,
        reason = "one arm per rule kind, in KINDS order; splitting it would put \
                  half the deck vocabulary out of sight of the other half, which \
                  is the one thing a reader checking this file needs to compare"
    )]
    pub fn from_deck(deck: &Deck, strings: &StrTable) -> Result<Self, DrcError> {
        // The deck's *parameter* vocabulary, which the Definition-Phase left
        // open (docs/NEED_TESTING.md, "RuleSet::from_deck and the whole
        // DrcError family"). Chosen here, and named after the column each
        // value lands in so a deck author reading a table's fields has read the
        // deck schema:
        //
        //   kind                     layers            parameters
        //   min_width                [layer]           limit
        //   max_width                [layer]           limit
        //   min_edge_length          [layer]           limit
        //   notch                    [layer]           limit
        //   min_spacing              [layer]           limit
        //   min_spacing_diff         [a, b]            limit
        //   eol_spacing              [layer]           eol_width, limit
        //   prl_spacing              [layer]           prl_threshold, limit
        //   corner_to_corner         [layer]           limit
        //   wide_dependent_spacing   [layer]           width_threshold, limit
        //   min_area                 [layer]           limit
        //   min_enclosed_area        [layer]           limit
        //   cheesing                 [layer]           max_unslotted
        //   density                  [layer]           window, step, limit, maximum
        //   min_enclosure            [outer, inner]    limit
        //   asymmetric_enclosure     [outer, inner]    min_one_side
        //   min_extension            [layer, ref]      limit
        //   overlap                  [a, b]            limit
        //   max_distance_to_tap      [well, tap]       limit
        //   off_grid                 []                pitch
        //   angle                    []                angle (one per allowed direction)
        //   redundant_via            [layer]           min_count, within
        //   via_array_spacing        [layer]           array_threshold, limit
        //   multi_patterning         [layer]           colors, color_spacing
        //
        // The three area limits — `min_area`, `min_enclosed_area`, `cheesing`
        // — are stated as the **side of the equivalent square**, a
        // `ParamValue::Length` squared by `square` below, because
        // `gpurify_ingest::deck::ParamValue` has no area variant and lengths
        // are the only thing `ingest` converts against the grid.
        //
        // Not a shortcut this file can spend: the fix is a `ParamValue::Area`
        // carrying a `DbuArea`, converted in `ingest` against `grid²`, which is
        // a variant on a frozen enum in another crate. Filed under `## drc` in
        // `docs/SIGNATURE_DEFECTS.md`, together with the direction it errs —
        // a real PDK area (0.088 µm² of metal) has no integer square root, so
        // the deck author rounds, and the rounding that reports nothing is
        // *down* for the two minima and *up* for `cheesing`.
        let rules = &deck.rules;

        // Every kind name resolved once, so the per-row match below is `u32`
        // equality and never a string compare. A kind the run's table has never
        // seen is `None`, which no `spec.kind` can equal.
        let kind_id: [Option<StrId>; KINDS.len()] = std::array::from_fn(|at| strings.get(KINDS[at]));

        let name_of = |id: StrId| strings.resolve(id).to_owned();

        // Duplicates first, before a single row is filed: two rows sharing an
        // id produce two `RuleRun` rows attributable to nothing, which is what
        // makes every count this crate reports readable.
        let mut ids: Vec<StrId> = rules.spec.iter().map(|spec| spec.id).collect();
        ids.sort_unstable();
        if let Some(pair) = ids.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(DrcError::DuplicateRule(name_of(pair[0])));
        }

        let value = |spec: &RuleSpec, param: &'static str| -> Result<ParamValue, DrcError> {
            // `get`, never `intern`: a parameter name the table has never seen
            // cannot be one the deck spelled, and growing the caller's table on
            // a lookup would hand back an id that matches nothing.
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

        let square = |spec: &RuleSpec, param: &'static str| -> Result<gpurify_units::DbuArea, DrcError> {
            let side = length(spec, param)?;
            debug_assert!(
                side.raw() <= gpurify_units::MAX_ABS_DBU,
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

        // A deck has hundreds of rule rows read once each: cold, not bulk. The
        // `if`s below are all on one row's own parameters at load time, not on
        // anything a check iterates.
        for spec in &rules.spec {
            // One deck feeds every domain, so a kind this crate does not spell
            // is another domain's row — `erc`'s — and stepping over it is what
            // lets a deck hold both. That is only half of fail closed: the
            // other half is `engine::run::run_checks`, which refuses a kind
            // that is in neither [`KINDS`] nor `gpurify_erc::ruleset::KINDS`
            // before either rule set is built. A typo is still the run's
            // failure; it is refused at the one layer that holds both
            // vocabularies rather than at the first one to read the row.
            let Some(kind) = kind_id.iter().position(|&name| name == Some(spec.kind)) else {
                continue;
            };

            // Each arm asserts the name of the index it files under. Filing a
            // row one table over is the failure mode this dispatcher exists to
            // make impossible, and it is invisible in the output: the run would
            // report the wrong rule's id against a measurement it never took.
            match kind {
                0 => {
                    debug_assert_eq!(KINDS[kind], "min_width");
                    layers(spec, 1)?;
                    let limit = length(spec, "limit")?;
                    set.min_width.rule.push(spec.id);
                    set.min_width.layer.push(layer(spec, 0));
                    set.min_width.limit.push(limit);
                }
                1 => {
                    debug_assert_eq!(KINDS[kind], "max_width");
                    layers(spec, 1)?;
                    let limit = length(spec, "limit")?;
                    set.max_width.rule.push(spec.id);
                    set.max_width.layer.push(layer(spec, 0));
                    set.max_width.limit.push(limit);
                }
                2 => {
                    debug_assert_eq!(KINDS[kind], "min_edge_length");
                    layers(spec, 1)?;
                    let limit = length(spec, "limit")?;
                    set.min_edge_length.rule.push(spec.id);
                    set.min_edge_length.layer.push(layer(spec, 0));
                    set.min_edge_length.limit.push(limit);
                }
                3 => {
                    debug_assert_eq!(KINDS[kind], "notch");
                    layers(spec, 1)?;
                    let limit = length(spec, "limit")?;
                    set.notch.rule.push(spec.id);
                    set.notch.layer.push(layer(spec, 0));
                    set.notch.limit.push(limit);
                }
                4 => {
                    debug_assert_eq!(KINDS[kind], "min_spacing");
                    layers(spec, 1)?;
                    let limit = length(spec, "limit")?;
                    set.min_spacing.rule.push(spec.id);
                    set.min_spacing.layer.push(layer(spec, 0));
                    set.min_spacing.limit.push(limit);
                }
                5 => {
                    debug_assert_eq!(KINDS[kind], "min_spacing_diff");
                    layers(spec, 2)?;
                    let limit = length(spec, "limit")?;
                    set.min_spacing_diff.rule.push(spec.id);
                    set.min_spacing_diff.a.push(layer(spec, 0));
                    set.min_spacing_diff.b.push(layer(spec, 1));
                    set.min_spacing_diff.limit.push(limit);
                }
                6 => {
                    debug_assert_eq!(KINDS[kind], "eol_spacing");
                    layers(spec, 1)?;
                    let eol_width = length(spec, "eol_width")?;
                    let limit = length(spec, "limit")?;
                    set.eol_spacing.rule.push(spec.id);
                    set.eol_spacing.layer.push(layer(spec, 0));
                    set.eol_spacing.eol_width.push(eol_width);
                    set.eol_spacing.limit.push(limit);
                }
                7 => {
                    debug_assert_eq!(KINDS[kind], "prl_spacing");
                    layers(spec, 1)?;
                    let prl_threshold = length(spec, "prl_threshold")?;
                    let limit = length(spec, "limit")?;
                    set.prl_spacing.rule.push(spec.id);
                    set.prl_spacing.layer.push(layer(spec, 0));
                    set.prl_spacing.prl_threshold.push(prl_threshold);
                    set.prl_spacing.limit.push(limit);
                }
                8 => {
                    debug_assert_eq!(KINDS[kind], "corner_to_corner");
                    layers(spec, 1)?;
                    let limit = length(spec, "limit")?;
                    set.corner_to_corner.rule.push(spec.id);
                    set.corner_to_corner.layer.push(layer(spec, 0));
                    set.corner_to_corner.limit.push(limit);
                }
                9 => {
                    debug_assert_eq!(KINDS[kind], "wide_dependent_spacing");
                    layers(spec, 1)?;
                    let width_threshold = length(spec, "width_threshold")?;
                    let limit = length(spec, "limit")?;
                    set.wide_dependent_spacing.rule.push(spec.id);
                    set.wide_dependent_spacing.layer.push(layer(spec, 0));
                    set.wide_dependent_spacing
                        .width_threshold
                        .push(width_threshold);
                    set.wide_dependent_spacing.limit.push(limit);
                }
                10 => {
                    debug_assert_eq!(KINDS[kind], "min_area");
                    layers(spec, 1)?;
                    let limit = square(spec, "limit")?;
                    set.min_area.rule.push(spec.id);
                    set.min_area.layer.push(layer(spec, 0));
                    set.min_area.limit.push(limit);
                }
                11 => {
                    debug_assert_eq!(KINDS[kind], "min_enclosed_area");
                    layers(spec, 1)?;
                    let limit = square(spec, "limit")?;
                    set.min_enclosed_area.rule.push(spec.id);
                    set.min_enclosed_area.layer.push(layer(spec, 0));
                    set.min_enclosed_area.limit.push(limit);
                }
                12 => {
                    debug_assert_eq!(KINDS[kind], "cheesing");
                    layers(spec, 1)?;
                    let max_unslotted = square(spec, "max_unslotted")?;
                    set.cheesing.rule.push(spec.id);
                    set.cheesing.layer.push(layer(spec, 0));
                    set.cheesing.max_unslotted.push(max_unslotted);
                }
                13 => {
                    debug_assert_eq!(KINDS[kind], "density");
                    layers(spec, 1)?;
                    let window = length(spec, "window")?;
                    let step = length(spec, "step")?;
                    let limit = ratio_of(spec, "limit")?;
                    // Stated, never defaulted: a density rule whose sense the
                    // deck left out is two rules, and guessing picks the one
                    // that reports nothing.
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
                14 => {
                    debug_assert_eq!(KINDS[kind], "min_enclosure");
                    layers(spec, 2)?;
                    let limit = length(spec, "limit")?;
                    set.min_enclosure.rule.push(spec.id);
                    set.min_enclosure.outer.push(layer(spec, 0));
                    set.min_enclosure.inner.push(layer(spec, 1));
                    set.min_enclosure.limit.push(limit);
                }
                15 => {
                    debug_assert_eq!(KINDS[kind], "asymmetric_enclosure");
                    layers(spec, 2)?;
                    let min_one_side = length(spec, "min_one_side")?;
                    set.asymmetric_enclosure.rule.push(spec.id);
                    set.asymmetric_enclosure.outer.push(layer(spec, 0));
                    set.asymmetric_enclosure.inner.push(layer(spec, 1));
                    set.asymmetric_enclosure.min_one_side.push(min_one_side);
                }
                16 => {
                    debug_assert_eq!(KINDS[kind], "min_extension");
                    layers(spec, 2)?;
                    let limit = length(spec, "limit")?;
                    set.min_extension.rule.push(spec.id);
                    set.min_extension.layer.push(layer(spec, 0));
                    set.min_extension.reference.push(layer(spec, 1));
                    set.min_extension.limit.push(limit);
                }
                17 => {
                    debug_assert_eq!(KINDS[kind], "overlap");
                    layers(spec, 2)?;
                    let limit = length(spec, "limit")?;
                    set.overlap.rule.push(spec.id);
                    set.overlap.a.push(layer(spec, 0));
                    set.overlap.b.push(layer(spec, 1));
                    set.overlap.limit.push(limit);
                }
                18 => {
                    debug_assert_eq!(KINDS[kind], "max_distance_to_tap");
                    layers(spec, 2)?;
                    let limit = length(spec, "limit")?;
                    set.max_distance_to_tap.rule.push(spec.id);
                    set.max_distance_to_tap.well.push(layer(spec, 0));
                    set.max_distance_to_tap.tap.push(layer(spec, 1));
                    set.max_distance_to_tap.limit.push(limit);
                }
                19 => {
                    debug_assert_eq!(KINDS[kind], "off_grid");
                    // No layer: the mask lattice is a property of the process.
                    layers(spec, 0)?;
                    let pitch = length(spec, "pitch")?;
                    set.off_grid.rule.push(spec.id);
                    set.off_grid.pitch.push(pitch);
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
                        // reduction is exact and it is what keeps the cast to
                        // the error's `i32` faithful.
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
                // `kind_id` came from `KINDS`, so `position` cannot return an
                // index past it. Fail closed anyway rather than panic: a
                // twenty-fifth name added to `KINDS` with no arm here would
                // otherwise be filed nowhere and reported as checked.
                _ => {
                    return Err(DrcError::UnknownKind {
                        rule: name_of(spec.id),
                        kind: name_of(spec.kind),
                    })
                }
            }
        }

        // Every row this crate *spells* is filed. Rows belonging to another
        // domain are skipped above and so are excluded from the count, which is
        // the only thing that changed when one deck started feeding two
        // domains: a `KINDS` name with no arm below still trips this.
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
    /// The number [`RuleSet::run`] will produce [`RuleRun`] rows for, so a
    /// caller can assert the run accounted for every rule it loaded. That
    /// equality is the crate's top-level invariant and this is what makes it
    /// checkable without reaching into twenty-four fields.
    pub fn rule_count(&self) -> usize {
        // Twenty-four named fields, not a loop: there is no collection here to
        // iterate, and the compiler names this line when a twenty-fifth
        // table arrives.
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
    /// **Transform, dispatcher.** One call per non-empty table, in the fixed
    /// order the fields are declared in. `out` and `runs` are cleared here —
    /// the one place they are, since the transforms themselves append — and
    /// `runs` gains exactly [`RuleSet::rule_count`] rows.
    ///
    /// # Ordering
    ///
    /// The dispatch order is fixed but is *not* the output order. Violations
    /// are canonically sorted afterwards by
    /// [`Violations::sort_canonical`](gpurify_report::Violations::sort_canonical),
    /// which is what makes the report independent of this order and therefore
    /// of any future decision to run the tables in parallel. `runs` is left in
    /// dispatch order, which is deterministic for a given [`RuleSet`] because
    /// the tables are built in deck order.
    ///
    /// # Infallible on purpose
    ///
    /// There is no `Result`. Geometry a rule cannot handle is that rule's
    /// [`Outcome::Refused`](gpurify_report::Outcome::Refused) row, not the
    /// run's failure: one unrepresentable polygon on one layer must not
    /// suppress the verdict of the other twenty-three rules. Everything that
    /// *could* fail the whole run already failed in
    /// [`RuleSet::from_deck`].
    pub fn run(
        &self,
        design: Design<'_>,
        scratch: &mut Scratch,
        out: &mut Violations,
        runs: &mut Vec<RuleRun>,
    ) {
        // The one place either container is cleared. Column by column because
        // the table is `SoA` and has no `clear`; capacity is kept, which is the
        // point of the caller owning the buffers.
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

        // Twenty-four guards on twenty-four table lengths. Each is constant for
        // the whole run and not over bulk data at all — the branch predictor
        // memorises every one of them on the first deck — and the guard is what
        // makes the doc's claim true: a kind the deck does not use costs the
        // run nothing, not even its transform's prologue.
        if !self.min_width.is_empty() {
            width::check_min_width(design, &self.min_width, scratch, out, runs);
        }
        if !self.max_width.is_empty() {
            width::check_max_width(design, &self.max_width, scratch, out, runs);
        }
        if !self.min_edge_length.is_empty() {
            width::check_min_edge_length(design, &self.min_edge_length, scratch, out, runs);
        }
        if !self.notch.is_empty() {
            width::check_notch(design, &self.notch, scratch, out, runs);
        }

        if !self.min_spacing.is_empty() {
            spacing::check_min_spacing(design, &self.min_spacing, scratch, out, runs);
        }
        if !self.min_spacing_diff.is_empty() {
            spacing::check_min_spacing_diff(design, &self.min_spacing_diff, scratch, out, runs);
        }
        if !self.eol_spacing.is_empty() {
            spacing::check_eol_spacing(design, &self.eol_spacing, scratch, out, runs);
        }
        if !self.prl_spacing.is_empty() {
            spacing::check_prl_spacing(design, &self.prl_spacing, scratch, out, runs);
        }
        if !self.corner_to_corner.is_empty() {
            spacing::check_corner_to_corner(design, &self.corner_to_corner, scratch, out, runs);
        }
        if !self.wide_dependent_spacing.is_empty() {
            spacing::check_wide_dependent_spacing(
                design,
                &self.wide_dependent_spacing,
                scratch,
                out,
                runs,
            );
        }

        if !self.min_area.is_empty() {
            area::check_min_area(design, &self.min_area, scratch, out, runs);
        }
        if !self.min_enclosed_area.is_empty() {
            area::check_min_enclosed_area(design, &self.min_enclosed_area, scratch, out, runs);
        }
        if !self.cheesing.is_empty() {
            area::check_cheesing(design, &self.cheesing, scratch, out, runs);
        }
        if !self.density.is_empty() {
            area::check_density(design, &self.density, scratch, out, runs);
        }

        if !self.min_enclosure.is_empty() {
            overlay::check_min_enclosure(design, &self.min_enclosure, scratch, out, runs);
        }
        if !self.asymmetric_enclosure.is_empty() {
            overlay::check_asymmetric_enclosure(
                design,
                &self.asymmetric_enclosure,
                scratch,
                out,
                runs,
            );
        }
        if !self.min_extension.is_empty() {
            overlay::check_min_extension(design, &self.min_extension, scratch, out, runs);
        }
        if !self.overlap.is_empty() {
            overlay::check_overlap(design, &self.overlap, scratch, out, runs);
        }
        if !self.max_distance_to_tap.is_empty() {
            overlay::check_max_distance_to_tap(design, &self.max_distance_to_tap, scratch, out, runs);
        }

        if !self.off_grid.is_empty() {
            grid::check_off_grid(design, &self.off_grid, scratch, out, runs);
        }
        if !self.angle.is_empty() {
            grid::check_angle(design, &self.angle, scratch, out, runs);
        }

        if !self.redundant_via.is_empty() {
            via::check_redundant_via(design, &self.redundant_via, scratch, out, runs);
        }
        if !self.via_array_spacing.is_empty() {
            via::check_via_array_spacing(design, &self.via_array_spacing, scratch, out, runs);
        }

        if !self.multi_patterning.is_empty() {
            patterning::check_multi_patterning(design, &self.multi_patterning, scratch, out, runs);
        }

        // The crate's top-level invariant, asserted where it is produced: one
        // run row per configured rule row. A missing line above is silent in
        // the violation table and is exactly what this catches.
        debug_assert_eq!(
            runs.len(),
            expected,
            "a configured rule produced no run row, which reads as a clean design"
        );
    }
}

/// Every rule kind this crate implements, as the deck spells it.
///
/// **This is the deck's vocabulary and it is stated nowhere else.**
/// `RuleSet::from_deck` matches `RuleSpec::kind` against these names, so a
/// deck author, a deck parser and a test all need them, and until they were
/// public the only copy lived in this crate's test module. It is also half of
/// the engine's union check: a kind absent from this array *and* from
/// `gpurify_erc::ruleset::KINDS` is refused before any rule set is built —
/// never a silent skip.
///
/// Order matches the field order of [`RuleSet`], so a failure naming index `i`
/// names `KINDS[i]`.
///
/// The antenna family is **not** here. It was, and it was also in
/// `gpurify_erc::ruleset::KINDS`, so one deck row spelled `antenna` was filed by
/// both `from_deck`s and failed one of them. The family belongs to `erc`: an
/// antenna ratio accumulates the collecting area of everything electrically
/// joined to a gate at the stage that layer is etched, which is a net question
/// with a layer cut-off and not a geometry question. This crate stays pure
/// geometry, and the two `KINDS` arrays are now disjoint.
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

/// The rule-dispatch adapter test.
///
/// `docs/TESTING.md` names rule dispatch as a seam that needs one: "clean"
/// meaning *this rule ran and examined N shapes* is not observable in the
/// violation table, and in this crate the observation is the [`RuleRun`] row. So
/// the property under test is the one a missing line in the dispatcher breaks
/// and nothing else in the suite catches — **every table holding a row produces
/// exactly one run row attributable to it**. A rule kind wired up nowhere is
/// silent, and silence is what a clean design looks like.
///
/// These are unit tests rather than integration tests because the fixture below
/// is the dispatcher's own inventory: it has to name all twenty-four fields, and
/// it belongs beside the struct it enumerates so the compiler points here when a
/// twenty-fifth arrives.
#[cfg(test)]
mod tests {
    use super::RuleSet;
    use crate::rules::grid::Direction;
    use crate::{Design, Scratch};
    use gpurify_core::{GeometryStore, LayerId};
    use gpurify_derived::Evaluator;
    use gpurify_ingest::StrId;
    use gpurify_report::{LimitSense, Outcome, RuleRun, Violations};
    use gpurify_testgen::dbu;
    use gpurify_testgen::shapes::{area, hole, rect, LayoutBuilder};
    use gpurify_topology::{DeviceTable, NetTable};

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
    ///
    /// Two facing stripes give the spacing family its pairs and the overlay
    /// family its hosts; a short-ended pair gives the end-of-line rule an edge
    /// that qualifies; a diagonally offset pair gives corner-to-corner its only
    /// legal input; and the ring gives the enclosed-area rule a hole, which is
    /// the one population a layer of simple shapes does not contain.
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
    ///
    /// The limits are deliberately loose: what is under test here is dispatch,
    /// not measurement, and every measurement has its own test in `tests/`.
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

    /// Oracle: construct-from-answer. The deck was built with exactly one row in
    /// each of the twenty-four tables, so the run must produce twenty-four run
    /// rows, one per id, with nothing repeated and nothing missing. A rule kind
    /// the dispatcher forgets to call produces no row and no violation, which
    /// is indistinguishable from a clean design in every other test in this
    /// crate.
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

    /// Oracle: construct-from-answer. The geometry above was chosen so every
    /// geometric rule has a nonzero population — polygons, pairs, holes, edges,
    /// vertices, windows — so each must report `Ran` over a nonzero `examined`.
    /// A rule whose layer lookup returned the wrong range reports `Ran` with
    /// zero, which is the shape of a false-clean result and is what this
    /// assertion exists to reject.
    ///
    /// There is no exception left. There was one — the antenna family referred
    /// collected charge to a gate this fixture has no device for — and it went
    /// with the family, to `erc`.
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

    /// Oracle: construct-from-answer. `run` owns the clearing of both output
    /// containers — the transforms themselves only append — so rows left over
    /// from an earlier run must not survive into this one. A run that appended
    /// instead would report the previous design's violations against this
    /// design's rules.
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

    /// Oracle: construct-from-answer. An empty set holds no rules and produces
    /// no run rows — which is the one case where an empty `runs` is correct, and
    /// is why `rule_count` is the number every other assertion compares against
    /// rather than a constant.
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

    /// Oracle: construct-from-answer. `rule_count` sums across every table, so
    /// adding a second row to one table moves it by one and `is_empty` stops
    /// being true the moment any table holds anything.
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
