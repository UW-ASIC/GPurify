//! Everything that reads a design and reports on it: extraction ([`topology`]),
//! the rule engines ([`drc`], [`erc`], [`lvs`]) and the report they share
//! ([`report`]).
//!
//! Data in: the deck, compiled with its rules typed ([`deck::compile`]), and
//! the layout tables a load produced
//! ([`gpurify_geom::GeometryStore`], plus [`topology::NetTable`] and
//! [`topology::DeviceTable`] from extraction). Data out: the
//! [`report::Violations`] columns, and one [`report::RuleRun`] per configured
//! rule saying whether it ran and how many shapes it examined.
//!
//! # The guarantee every rule keeps
//!
//! A rule never passes by not looking. Each configured rule records exactly one
//! [`report::RuleRun`]: [`report::Outcome::Ran`] with the number of shapes it
//! examined, [`report::Outcome::Skipped`] with the reason (an empty layer, a
//! missing design-intent file), or [`report::Outcome::Refused`] when the input is
//! outside what the rule represents exactly. A run with any rule not `Ran` does
//! not pass.
//!
//! # Rule reference
//!
//! Every rule kind a deck can name, the Rust item that checks it, and the
//! [check catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv)
//! rows it covers. The catalog lists every check a signoff verifier is expected to
//! handle, and [check-sources.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md)
//! names the foundry manual, standard or tool that defines each one. The deck
//! language itself is in
//! [deck.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/deck.md). A
//! catalog row may be covered only in part; what is missing is in
//! [limitations.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/limitations.md).
//!
//! ## Design rules
//!
//! Each row of a deck's DRC section becomes one [`drc::Rule`] in a
//! [`drc::RuleSet`]. `L` is a layer or layer expression, `E` and `F` edge layers.
//!
//! | Deck | Kind | Checked by | Flags | Catalog |
//! |---|---|---|---|---|
//! | `width(L) >= len` | `min_width` | [`drc::Rule::MinWidth`] | a shape narrower than the limit anywhere | DRC-010, DRC-073, DRC-090, DRC-095, DRC-096, ERC-C11 |
//! | `width(L) <= len` | `max_width` | [`drc::Rule::MaxWidth`] | a part of a shape wider than the limit in every direction | DRC-012 |
//! | `size(L) == w x h` | `cut_size` | [`drc::Rule::CutSize`] | a cut that is not exactly that rectangle | DRC-013, DRC-014 |
//! | `edge_length(L) >= len` | `min_edge_length` | [`drc::Rule::MinEdgeLength`] | an edge shorter than the limit | DRC-020 |
//! | `notch(L) >= len` | `notch` | [`drc::Rule::Notch`] | a gap inside one shape narrower than the limit | DRC-024 |
//! | `space(L) >= len` | `min_spacing` | [`drc::Rule::MinSpacing`] | two shapes on one layer closer than the limit | DRC-023, DRC-060 |
//! | `space(A, B) >= len` | `min_spacing_diff` | [`drc::Rule::MinSpacingDiff`] | a shape on A closer than the limit to one on B | DRC-047, DRC-065, DRC-073, ERC-C11 |
//! | `eol_space(L; eol_width: len) >= len` | `eol_spacing` | [`drc::Rule::EolSpacing`] | too little space at an end of line | DRC-029, DRC-031 |
//! | `prl_space(L; prl: len) >= len` | `prl_spacing` | [`drc::Rule::PrlSpacing`] | shapes running side by side for `prl`, too close | DRC-026 |
//! | `corner_space(L) >= len` | `corner_to_corner` | [`drc::Rule::CornerToCorner`] | two shapes whose corners are too close | DRC-032 |
//! | `wide_space(L; width: len) >= len` | `wide_dependent_spacing` | [`drc::Rule::WideDependentSpacing`] | too little space from the wide part of a shape | DRC-025 |
//! | `wide_space(L; width: len, attached: len) >= len` | `attached_wide_spacing` | [`drc::Rule::AttachedWideSpacing`] | the same, also from what is attached to the wide part | DRC-028 |
//! | `space(L; nets: same \| different) >= len` | `net_spacing` | [`drc::Rule::NetSpacing`] | same-net or different-net shapes too close | DRC-080 |
//! | `space_table(L; prl: [..], width: [..], space: [[..]])` | `spacing_table` | [`drc::Rule::SpacingTable`] | two shapes closer than their table cell | DRC-025, DRC-026, DRC-027 |
//! | `area(L) >= area` | `min_area` | [`drc::Rule::MinArea`] | a shape smaller than the limit | DRC-017, ERC-A9 |
//! | `hole_area(L) >= area` | `min_enclosed_area` | [`drc::Rule::MinEnclosedArea`] | a hole smaller than the limit | DRC-019 |
//! | `cheesing(L) <= area` | `cheesing` | [`drc::Rule::Cheesing`] | a shape larger than the limit with no slot | DRC-075, ERC-E12 |
//! | `density(L[, boundary]; window: len, step: len) >= frac` | `density` | [`drc::Rule::Density`] | a window with coverage outside the limit | DRC-071 |
//! | `global_density(L[, boundary]) >= frac` | `global_density` | [`drc::Rule::GlobalDensity`] | coverage of the whole die outside the limit | DRC-070 |
//! | `enclosure(inner, outer) >= len` | `min_enclosure` | [`drc::Rule::MinEnclosure`] | an inner shape not surrounded by the limit on every side | DRC-040, DRC-090, DRC-096 |
//! | `enclosure(inner, outer, opposite) >= len` | `asymmetric_enclosure` | [`drc::Rule::AsymmetricEnclosure`] | an inner shape without the limit on two opposite sides | DRC-041, DRC-042 |
//! | `extension(A, B) >= len` | `min_extension` | [`drc::Rule::MinExtension`] | A not extending past B by the limit | DRC-045 |
//! | `overlap(A, B) >= len` | `overlap` | [`drc::Rule::Overlap`] | A and B overlapping by less than the limit | DRC-046 |
//! | `tap_distance(well, tap) <= len` | `max_distance_to_tap` | [`drc::Rule::MaxDistanceToTap`] | a point of a well too far from a tap | ERC-D1 |
//! | `off_grid(; pitch: len)` | `off_grid` | [`drc::Rule::OffGrid`] | a vertex off the manufacturing grid | DRC-001 |
//! | `angle([L]; allowed: [..])` | `angle` | [`drc::Rule::Angle`] | an edge at an angle not in the list | DRC-002, DRC-003, DRC-037 |
//! | `redundant_via(L; within: len) >= count` | `redundant_via` | [`drc::Rule::RedundantVia`] | a cut with too few neighbours | DRC-066, DRC-117 |
//! | `via_array_space(L; array: count) >= len` | `via_array_spacing` | [`drc::Rule::ViaArraySpacing`] | cuts in a large cluster too close | DRC-062 |
//! | `patterning(L; colors: count) >= len` | `multi_patterning` | [`drc::Rule::MultiPatterning`] | shapes that cannot be split onto that many masks | DRC-100, DRC-101 |
//! | `forbidden(L)` | `forbidden` | [`drc::Rule::Forbidden`] | every shape on `L` | DRC-005, DRC-006, DRC-018, DRC-050, DRC-074, DRC-090, DRC-095, DRC-097, ERC-A10 |
//! | `contains(outer, inner) >= count` | `must_contain` | [`drc::Rule::MustContain`] | an outer shape holding too few inner shapes | DRC-048, DRC-049, DRC-085 |
//! | `inside(inner, outer)` | `must_be_inside` | [`drc::Rule::MustBeInside`] | an inner shape not entirely inside outer | DRC-007, DRC-048 |
//! | `length(E) >= len` | `edge_min_length` | [`drc::Rule::EdgeMinLength`] | an edge on an edge layer shorter than the limit | DRC-021, DRC-051 |
//! | `space(E[, F]) >= len` | `edge_spacing` | [`drc::Rule::EdgeSpacing`] | parallel edges on edge layers too close | DRC-051 |
//! | `enclosure(E, L) >= len` | `edge_enclosure` | [`drc::Rule::EdgeEnclosure`] | an edge whose outside is not covered by L for the limit | DRC-051 |
//! | `count(L) >= n`, `count(L) <= n` | `count` | [`drc::Rule::Count`] | too few or too many shapes on `L` in the whole layout | DRC-091, DRC-095 |
//! | `size(L; allowed: [w x h, ..])` | `cut_class` | [`drc::Rule::CutClass`] | a cut whose size is none of the listed classes | DRC-014 |
//! | `min_step(L; max_edges: n \| corner: .., length_sum: ..) >= len` | `min_step` | [`drc::Rule::MinStep`] | a run of short edges LEF `MINSTEP` rejects: too many in a row, or at a corner or step | DRC-020 |
//! | `interior_angle([L]) >= deg` | `min_interior_angle` | [`drc::Rule::MinInteriorAngle`] | a drawn corner whose angle inside its shape is under the limit: an acute angle | DRC-003 |
//! | `valid([L])` | `polygon_validity` | [`drc::Rule::PolygonValidity`] | a drawn polygon that crosses itself or encloses no area | DRC-004 |
//! | `width(L; allowed: [w, ..])` | `allowed_width` | [`drc::Rule::AllowedWidth`] | a shape whose width is none of the listed widths | DRC-015, DRC-090 |
//! | `width(E) >= len` | `edge_width` | [`drc::Rule::EdgeWidth`] | two edges facing each other across their shapes closer than the limit: a channel length or width, a width in one direction | DRC-011, DRC-016, DRC-090 |
//! | `facing_space(E) >= len` | `edge_facing_space` | [`drc::Rule::EdgeFacingSpace`] | two edges whose outer sides face each other closer than the limit: a spacing in one direction | DRC-016 |
//! | `region_density(L, R) >= frac`, `<= frac` | `region_density` | [`drc::Rule::RegionDensity`] | a shape of `R` inside which `L` covers too little or too much | DRC-072, DRC-075 |
//! | `total_area(L) <= area` | `total_area` | [`drc::Rule::TotalArea`] | more area on `L` in the whole layout than the limit | DRC-091 |
//! | `aspect_ratio(L) <= r` | `aspect_ratio` | [`drc::Rule::AspectRatio`] | a shape whose bounding box is longer than `r` times its width | DRC-022 |
//! | `tip_space_table(L; length: [..], space: [[..]])` | `tip_spacing_table` | [`drc::Rule::TipSpacingTable`] | facing edges closer than the cell their two length classes select | DRC-031 |
//! | `forbidden_space(L; min: len, max: len, prl: len)` | `forbidden_spacing` | [`drc::Rule::ForbiddenSpacing`] | facing edges running alongside at a gap in a forbidden range | DRC-033 |
//! | `eol_space(L; eol_width: len, within: len, parallel: .., end_to_end: ..) >= len` | `eol_within_spacing` | [`drc::Rule::EolWithinSpacing`] | too little space in a LEF end-of-line keep-out, with parallel-edge and end-to-end qualifiers | DRC-029 |
//! | `eol_keep_out(L; eol_width: len, backward: len, side: len, forward: len)` | `eol_keep_out` | [`drc::Rule::EolKeepOut`] | another shape inside an end of line's keep-out box | DRC-030 |
//! | `two_width_table(L; width: [..], prl: [..], space: [[..]])` | `two_width_spacing_table` | [`drc::Rule::TwoWidthSpacingTable`] | two shapes closer than the cell both their widths select | DRC-027 |
//! | `span_length(L; x: [..], y: [..])` | `span_length` | [`drc::Rule::SpanLength`] | a span of a shape not on the list of legal spans | DRC-036 |
//!
//! ## Electrical rules
//!
//! Each ERC row becomes one row of the [`erc::RuleSet`] table for its kind. The
//! voltage rules read what each net can reach from the supplies in the
//! design-intent file.
//!
//! | Deck | Kind | Checked by | Flags | Catalog |
//! |---|---|---|---|---|
//! | `antenna(gate, collectors..; max_ratio, sidewall, diode)` | `antenna` | [`erc::RuleSet::antenna`] | collector area above `max_ratio` times the gate area, a gate on a `diode` net skipped | ERC-A1, ERC-A2, ERC-A3, ERC-A4, ERC-A8, ERC-A9, ERC-A11, ERC-A12, ERC-A13 |
//! | `antenna_electrical(gate, collectors..; ..)` | `antenna_electrical` | [`erc::RuleSet::antenna_electrical`] | the cumulative ratio, with diode credit | ERC-A4, ERC-A5, ERC-A6, ERC-A7, ERC-A8, ERC-A9, ERC-A12, ERC-A13 |
//! | `density_cmp(L; window, step, ..)` | `density_cmp` | [`erc::RuleSet::density_cmp`] | metal density, or CMP thickness, out of range | DRC-071, DRC-113, ERC-B1 |
//! | `electromigration(layers..; ..)` | `electromigration` | [`erc::RuleSet::electromigration`] | a wire or cut above its rated current at temperature | ERC-E4, ERC-E5, ERC-E6 |
//! | `em_current_density(layers..; ..)` | `em_current_density` | [`erc::RuleSet::em_current_density`] | a wire or cut above its instantaneous current limit | ERC-C7, ERC-D4, ERC-E1, ERC-E2, ERC-E3, ERC-E10 |
//! | `ir_drop()` | `ir_drop` | [`erc::RuleSet::ir_drop`] | a node whose drop exceeds its net's limit | ERC-E8 |
//! | `dynamic_ir_drop()` | `dynamic_ir_drop` | [`erc::RuleSet::dynamic_ir_drop`] | a node whose drop in the worst switching cycle exceeds its net's limit | ERC-E11 |
//! | `em_thermal(layers..; ..)` | `em_thermal` | [`erc::RuleSet::em_thermal`] | a wire or cut above its rated current at its self-heated temperature, or a chip too likely to fail by EM | ERC-E13 |
//! | `p2p_resistance(; max)` | `p2p_resistance` | [`erc::RuleSet::p2p_resistance`] | two points on one net too far apart in resistance | ERC-C6, ERC-D4 |
//! | `reliability(; ..)` | `reliability` | [`erc::RuleSet::reliability`] | a device whose predicted lifetime is too short | ERC-E5, ERC-F5 |
//! | `hv_domain(; max_delta, isolation)` | `hv_domain` | [`erc::RuleSet::hv_domain`] | a device spanning supply domains too far apart | DRC-083, ERC-F10 |
//! | `esd_latchup(pad, guard_ring; ..)` | `esd_latchup` | [`erc::RuleSet::esd_latchup`] | a narrow or untapped guard ring, or an unclamped pad | ERC-C1, ERC-D2 |
//! | `esd_topological(pad; clamps)` | `esd_topological` | [`erc::RuleSet::esd_topological`] | a pad with no clamp path to both supplies | ERC-C1 |
//! | `floating_gate(; labels_are_ports)` | `floating_gate` | [`erc::RuleSet::floating_gate`] | a net that only reaches gates | ERC-G1 |
//! | `floating_well(well, tap)` | `floating_well` | [`erc::RuleSet::floating_well`] | a well with no tap | DRC-085, ERC-G2 |
//! | `missing_tie(region, tap; max_distance)` | `missing_tie` | [`erc::RuleSet::missing_tie`] | a region too far from a tap | ERC-D1 |
//! | `multiple_drivers(; max)` | `multiple_drivers` | [`erc::RuleSet::multiple_drivers`] | a net with too many drivers | ERC-G3 |
//! | `soft_connection(layers..)` | `soft_connection` | [`erc::RuleSet::soft_connection`] | a net held together only through high-resistance layers | LVS-003, ERC-G5 |
//! | `supply_short(tap_a, tap_b[, within])` | `supply_short` | [`erc::RuleSet::supply_short`] | a net touching both kinds of tap | ERC-G4 |
//! | `tie_high_low()` | `tie_high_low` | [`erc::RuleSet::tie_high_low`] | a gate tied straight to a rail | ERC-G7 |
//! | `unconnected_pin(layers..)` | `unconnected_pin` | [`erc::RuleSet::unconnected_pin`] | a shape that reaches no device | DRC-084, ERC-E9, ERC-G6 |
//! | `gate_oxide(; models, max)` | `gate_oxide` | [`erc::RuleSet::gate_oxide`] | a gate that can differ from its channel by more than max | ERC-F2 |
//! | `drain_source(; models, max)` | `drain_source` | [`erc::RuleSet::drain_source`] | a drain that can differ from its source by more than max | ERC-F3 |
//! | `well_bias(; pmos, nmos)` | `well_bias` | [`erc::RuleSet::well_bias`] | a well that can forward-bias a junction | ERC-D3, ERC-F12 |
//! | `missing_level_shifter(; shifters)` | `missing_level_shifter` | [`erc::RuleSet::missing_level_shifter`] | a gate driven from another power domain | ERC-F6 |
//! | `domain_crossing()` | `domain_crossing` | [`erc::RuleSet::domain_crossing`] | a channel joining two power domains | ERC-F9 |
//!
//! ## Layout against schematic
//!
//! LVS compares the extracted layout with a reference netlist ([`lvs::compare`])
//! and reports under these ids. The first six are [`lvs::Discrepancy`] variants;
//! the rest are checks on the layout's own graph ([`lvs::check_layout`]).
//!
//! | Report id | Raised by | Flags | Catalog |
//! |---|---|---|---|
//! | `lvs.unpaired_device` | [`lvs::Discrepancy::UnpairedDevice`] | a device with no partner on the other side | LVS-011, LVS-012, LVS-013, LVS-049 |
//! | `lvs.unpaired_net` | [`lvs::Discrepancy::UnpairedNet`] | a net with no partner on the other side | LVS-015, LVS-016 |
//! | `lvs.terminal_mismatch` | [`lvs::Discrepancy::TerminalMismatch`] | paired devices whose terminals reach different nets | LVS-015 |
//! | `lvs.parameter_mismatch` | [`lvs::Discrepancy::ParameterMismatch`] | paired devices whose parameters differ beyond the tolerance | LVS-014 |
//! | `lvs.undeclared_param` | [`lvs::Discrepancy::UndeclaredParam`] | a parameter the reference card states that the layout does not measure | LVS-020 |
//! | `lvs.class_imbalance` | [`lvs::Discrepancy::ClassImbalance`] | a class with different member counts on the two sides | LVS-012, LVS-015, LVS-049 |
//! | `lvs.floating_net` | [`lvs::check_layout`] | a layout net that reaches no device | LVS-006 |
//! | `lvs.label_conflict` | [`lvs::check_layout`] | one label on several nets | LVS-001, LVS-002 |
//! | `lvs.net_seed_conflict` | [`lvs::check_layout`] | several labels on one net: a short between named nets | DRC-086, LVS-001, LVS-005 |
//! | `lvs.terminal_net` | [`lvs::check_layout`] | a device marker no recogniser could bind, or a terminal on no net | LVS-004 |
//! | `lvs.terminal_count` | [`lvs::check_layout`] | a device with the wrong number of terminals | LVS-004 |

pub mod deck;
pub mod drc;
pub mod erc;
pub mod lvs;
pub mod report;
pub mod topology;

use gpurify_geom::GeometryStore;
use topology::{DeviceTable, NetTable};

/// Everything an ERC rule reads about the layout, borrowed for one run.
///
/// The three must come from one load: the tables index `store`'s polygons by
/// [`PolyId`](gpurify_geom::PolyId), so a table built from another store
/// reads the wrong shapes or panics.
#[derive(Debug, Clone, Copy)]
pub struct Design<'a> {
    /// The layout's polygons.
    pub store: &'a GeometryStore,
    /// The nets extracted from `store` by [`topology::extract_nets_into`].
    pub nets: &'a NetTable,
    /// The devices recognised against `nets` by
    /// [`topology::device::recognise_into`].
    pub devices: &'a DeviceTable,
}
