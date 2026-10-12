//! Every rule kind, once: the kind lists both domains read and a typed
//! constructor per kind for a deck built in Rust ([`DeckBuilder`]).
//!
//! One `macro_rules!` table names each kind with its layer arguments and
//! parameters, and generates [`DRC_KINDS`], [`ERC_KINDS`] and the
//! constructors from it. A constructor's name is the kind's, so a misspelt
//! kind does not compile, and every parameter is an argument, so a missing
//! one does not compile either. A constructor makes a [`RuleRow`]: the rule
//! as the parser would read it, which [`DeckBuilder::finish`] types and
//! validates exactly as it does a deck read from text.
//!
//! Lengths are [`Dbu`] and areas [`DbuArea`] on the builder's grid; every
//! other quantity is an `f64` in the unit its parameter names (mV, µA, A/m,
//! ohms, kelvin, eV, hours), the units the parser converts to. Each
//! constructor links the rule variant or table that defines the kind, and
//! the [rule reference](crate#rule-reference) gives its deck spelling.
//!
//! # What does not compile
//!
//! Two refusals of the parser are type errors here. A length without its
//! unit, as the parser refuses `width(met1) >= 140`, is a bare number where a
//! [`Dbu`] goes:
//!
//! ```compile_fail
//! use gpurify_check::deck::{rules, DeckBuilder};
//! use gpurify_geom::{Grid, StrTable};
//!
//! let mut strings = StrTable::default();
//! let mut d = DeckBuilder::new(Grid::new(1000).expect("a grid"), &mut strings);
//! let met1 = d.layer("met1", (68, 20));
//! d.rule("m1.1", rules::min_width(met1, 140));
//! ```
//!
//! And `<=` on a minimum, as the parser refuses `area(met1) <= 83000nm2`, is
//! a kind no constructor makes:
//!
//! ```compile_fail
//! use gpurify_check::deck::{rules, DeckBuilder};
//! use gpurify_geom::{DbuArea, Grid, StrTable};
//!
//! let mut strings = StrTable::default();
//! let mut d = DeckBuilder::new(Grid::new(1000).expect("a grid"), &mut strings);
//! let met1 = d.layer("met1", (68, 20));
//! d.rule("m1.6", rules::max_area(met1, DbuArea::new(83_000)));
//! ```
//!
//! [`DeckBuilder`]: super::DeckBuilder
//! [`DeckBuilder::finish`]: super::DeckBuilder::finish

use super::builder::{LayerExpr, LayerRef};
use crate::drc::StepKind;
use gpurify_geom::{Dbu, DbuArea};
use gpurify_ingest::deck::ParamValue;

/// One rule as a constructor makes it, before it has an id: its kind, its
/// layer arguments in the order the deck writes them, and its parameters by
/// engine name. Give it to [`DeckBuilder::rule`](super::DeckBuilder::rule).
#[derive(Debug, Clone, PartialEq)]
pub struct RuleRow {
    pub(super) kind: &'static str,
    /// The layer arguments, in deck order.
    pub(super) args: Vec<LayerExpr>,
    /// Engine layer slot `i` takes `args[slots[i]]`; empty when the engine
    /// takes the deck's order.
    pub(super) slots: &'static [u8],
    pub(super) params: Vec<(&'static str, RowValue)>,
    pub(super) warning: bool,
}

/// A parameter value before its layer and model names are resolved.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum RowValue {
    Value(ParamValue),
    Layer(LayerRef),
    Model(String),
}

impl RuleRow {
    fn new(kind: &'static str, slots: &'static [u8]) -> Self {
        Self {
            kind,
            args: Vec::new(),
            slots,
            params: Vec::new(),
            warning: false,
        }
    }

    /// The kind's name, its entry of [`DRC_KINDS`] or [`ERC_KINDS`].
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    /// An ERC rule reported as a warning, not an error: the deck's
    /// `rule <id> warning ...`. A DRC rule refuses it when the deck is built,
    /// as the parser does.
    #[must_use]
    pub fn warning(mut self) -> Self {
        self.warning = true;
        self
    }
}

/// A value a constructor stores as one or more parameter rows.
trait Arg {
    fn put(self, name: &'static str, params: &mut Vec<(&'static str, RowValue)>);
}

impl Arg for Dbu {
    fn put(self, name: &'static str, params: &mut Vec<(&'static str, RowValue)>) {
        params.push((name, RowValue::Value(ParamValue::Length(self))));
    }
}

impl Arg for DbuArea {
    fn put(self, name: &'static str, params: &mut Vec<(&'static str, RowValue)>) {
        params.push((name, RowValue::Value(ParamValue::Area(self))));
    }
}

impl Arg for f64 {
    fn put(self, name: &'static str, params: &mut Vec<(&'static str, RowValue)>) {
        params.push((name, RowValue::Value(ParamValue::Ratio(self))));
    }
}

impl Arg for u32 {
    fn put(self, name: &'static str, params: &mut Vec<(&'static str, RowValue)>) {
        params.push((name, RowValue::Value(ParamValue::Count(self))));
    }
}

impl Arg for bool {
    fn put(self, name: &'static str, params: &mut Vec<(&'static str, RowValue)>) {
        params.push((name, RowValue::Value(ParamValue::Flag(self))));
    }
}

impl Arg for LayerRef {
    fn put(self, name: &'static str, params: &mut Vec<(&'static str, RowValue)>) {
        params.push((name, RowValue::Layer(self)));
    }
}

impl<T: Arg> Arg for Option<T> {
    fn put(self, name: &'static str, params: &mut Vec<(&'static str, RowValue)>) {
        if let Some(value) = self {
            value.put(name, params);
        }
    }
}

impl Arg for &[u32] {
    fn put(self, name: &'static str, params: &mut Vec<(&'static str, RowValue)>) {
        for &value in self {
            value.put(name, params);
        }
    }
}

impl Arg for &[f64] {
    fn put(self, name: &'static str, params: &mut Vec<(&'static str, RowValue)>) {
        for &value in self {
            value.put(name, params);
        }
    }
}

impl Arg for &[Dbu] {
    fn put(self, name: &'static str, params: &mut Vec<(&'static str, RowValue)>) {
        for &value in self {
            value.put(name, params);
        }
    }
}

/// A list of cut sizes, `width x height` each: the `height` rows follow
/// their `width` rows in the order given.
impl Arg for &[(Dbu, Dbu)] {
    fn put(self, name: &'static str, params: &mut Vec<(&'static str, RowValue)>) {
        for &(width, height) in self {
            width.put(name, params);
            height.put("height", params);
        }
    }
}

/// A piecewise-linear table of `(diode area, number)` points: each area
/// row under `<name>_area` before its number under `name`.
impl Arg for &[(DbuArea, f64)] {
    fn put(self, name: &'static str, params: &mut Vec<(&'static str, RowValue)>) {
        // ponytail: the two tables `antenna_electrical` has; a third adds its arm.
        let area = match name {
            "diode_reduce" => "diode_reduce_area",
            _ => "diode_max_ratio_area",
        };
        for &(at, value) in self {
            at.put(area, params);
            value.put(name, params);
        }
    }
}

/// LEF `MINSTEP`'s variant: `max_edges`, or a `corner` by its index.
impl Arg for StepKind {
    fn put(self, _: &'static str, params: &mut Vec<(&'static str, RowValue)>) {
        let (name, value) = match self {
            StepKind::MaxEdges(most) => ("max_edges", u32::from(most)),
            StepKind::OutsideCorner => ("corner", 0),
            StepKind::InsideCorner => ("corner", 1),
            StepKind::Step => ("corner", 2),
        };
        value.put(name, params);
    }
}

impl Arg for &[&str] {
    fn put(self, name: &'static str, params: &mut Vec<(&'static str, RowValue)>) {
        for &model in self {
            params.push((name, RowValue::Model(model.to_owned())));
        }
    }
}

/// A layer argument's type: `one` layer or expression, an `opt`ional one, or
/// `many` named layers.
macro_rules! layer_ty {
    (one) => { impl Into<LayerExpr> };
    (opt) => { Option<LayerExpr> };
    (many) => { &[LayerRef] };
}

/// Appends a layer argument to a row's arguments.
macro_rules! push_layer {
    (one, $value:expr, $args:expr) => {
        $args.push($value.into())
    };
    (opt, $value:expr, $args:expr) => {
        $args.extend($value)
    };
    (many, $value:expr, $args:expr) => {
        $args.extend($value.iter().map(|&layer| LayerExpr::from(layer)))
    };
}

/// The kind table: one row per kind, generating its entry of the kind list
/// and its constructor. A row is the kind's name, its layer arguments in deck
/// order, the engine's layer order where it differs (`[1, 0]`: the engine
/// takes the second argument first), and its parameters with the engine
/// names `from_deck` reads.
macro_rules! kinds {
    (
        $(#[$list_meta:meta])*
        $list:ident;
        $(
            $(#[$meta:meta])*
            $kind:ident($($arg:ident: $at:ident),*) [$($slot:literal),*]
                { $($param:ident: $ty:ty = $engine:literal),* $(,)? }
        )*
    ) => {
        $(#[$list_meta])*
        pub const $list: [&str; [$(stringify!($kind)),*].len()] = [$(stringify!($kind)),*];

        $(
            $(#[$meta])*
            pub fn $kind($($arg: layer_ty!($at),)* $($param: $ty),*) -> RuleRow {
                #[allow(unused_mut, reason = "a kind with no layer and no parameter")]
                let mut row = RuleRow::new(stringify!($kind), &[$($slot),*]);
                $(push_layer!($at, $arg, row.args);)*
                $(Arg::put($param, $engine, &mut row.params);)*
                row
            }
        )*
    };
}

kinds! {
    /// Every DRC rule kind, by the name a deck row resolves to (`min_width`
    /// for `width(L) >= len`), in [`Rule`](crate::drc::Rule) variant order:
    /// [`crate::drc::ruleset::KINDS`]. Disjoint from [`ERC_KINDS`].
    /// [`CompiledDeck::from_deck`](super::CompiledDeck::from_deck) refuses a
    /// deck row whose kind is in neither
    /// ([`DrcError::UnknownKind`](crate::drc::DrcError::UnknownKind)).
    DRC_KINDS;
    /// [`Rule::MinWidth`](crate::drc::Rule::MinWidth): `width(layer) >= limit`.
    min_width(layer: one) [] { limit: Dbu = "limit" }
    /// [`Rule::MaxWidth`](crate::drc::Rule::MaxWidth): `width(layer) <= limit`.
    max_width(layer: one) [] { limit: Dbu = "limit" }
    /// [`Rule::CutSize`](crate::drc::Rule::CutSize): `size(layer) == width x height`.
    cut_size(layer: one) [] { width: Dbu = "width", height: Dbu = "height" }
    /// [`Rule::MinEdgeLength`](crate::drc::Rule::MinEdgeLength): `edge_length(layer) >= limit`.
    min_edge_length(layer: one) [] { limit: Dbu = "limit" }
    /// [`Rule::Notch`](crate::drc::Rule::Notch): `notch(layer) >= limit`.
    notch(layer: one) [] { limit: Dbu = "limit" }
    /// [`Rule::MinSpacing`](crate::drc::Rule::MinSpacing): `space(layer) >= limit`.
    min_spacing(layer: one) [] { limit: Dbu = "limit" }
    /// [`Rule::MinSpacingDiff`](crate::drc::Rule::MinSpacingDiff): `space(a, b) >= limit`.
    min_spacing_diff(a: one, b: one) [] { limit: Dbu = "limit" }
    /// [`Rule::EolSpacing`](crate::drc::Rule::EolSpacing):
    /// `eol_space(layer; eol_width: eol_width) >= limit`.
    eol_spacing(layer: one) [] { eol_width: Dbu = "eol_width", limit: Dbu = "limit" }
    /// [`Rule::PrlSpacing`](crate::drc::Rule::PrlSpacing):
    /// `prl_space(layer; prl: prl_threshold) >= limit`.
    prl_spacing(layer: one) [] { prl_threshold: Dbu = "prl_threshold", limit: Dbu = "limit" }
    /// [`Rule::CornerToCorner`](crate::drc::Rule::CornerToCorner): `corner_space(layer) >= limit`.
    corner_to_corner(layer: one) [] { limit: Dbu = "limit" }
    /// [`Rule::WideDependentSpacing`](crate::drc::Rule::WideDependentSpacing):
    /// `wide_space(layer; width: width_threshold) >= limit`.
    wide_dependent_spacing(layer: one) [] {
        width_threshold: Dbu = "width_threshold",
        limit: Dbu = "limit",
    }
    /// [`Rule::MinArea`](crate::drc::Rule::MinArea): `area(layer) >= limit`.
    min_area(layer: one) [] { limit: DbuArea = "limit" }
    /// [`Rule::MinEnclosedArea`](crate::drc::Rule::MinEnclosedArea): `hole_area(layer) >= limit`.
    min_enclosed_area(layer: one) [] { limit: DbuArea = "limit" }
    /// [`Rule::Cheesing`](crate::drc::Rule::Cheesing): `cheesing(layer) <= max_unslotted`.
    cheesing(layer: one) [] { max_unslotted: DbuArea = "max_unslotted" }
    /// [`Rule::Density`](crate::drc::Rule::Density):
    /// `density(layer[, boundary]; window: window, step: step) >= limit`, or
    /// `<=` when `maximum`. `limit` is a fraction.
    density(layer: one, boundary: opt) [] {
        window: Dbu = "window",
        step: Dbu = "step",
        limit: f64 = "limit",
        maximum: bool = "maximum",
    }
    /// [`Rule::GlobalDensity`](crate::drc::Rule::GlobalDensity):
    /// `global_density(layer[, boundary]) >= limit`, or `<=` when `maximum`.
    global_density(layer: one, boundary: opt) [] { limit: f64 = "limit", maximum: bool = "maximum" }
    /// [`Rule::MinEnclosure`](crate::drc::Rule::MinEnclosure): `enclosure(inner, outer) >= limit`.
    min_enclosure(inner: one, outer: one) [1, 0] { limit: Dbu = "limit" }
    /// [`Rule::AsymmetricEnclosure`](crate::drc::Rule::AsymmetricEnclosure):
    /// `enclosure(inner, outer, opposite) >= min_one_side`.
    asymmetric_enclosure(inner: one, outer: one) [1, 0] { min_one_side: Dbu = "min_one_side" }
    /// [`Rule::MinExtension`](crate::drc::Rule::MinExtension): `extension(layer, reference) >= limit`.
    min_extension(layer: one, reference: one) [] { limit: Dbu = "limit" }
    /// [`Rule::Overlap`](crate::drc::Rule::Overlap): `overlap(a, b) >= limit`.
    overlap(a: one, b: one) [] { limit: Dbu = "limit" }
    /// [`Rule::MaxDistanceToTap`](crate::drc::Rule::MaxDistanceToTap):
    /// `tap_distance(well, tap) <= limit`.
    max_distance_to_tap(well: one, tap: one) [] { limit: Dbu = "limit" }
    /// [`Rule::OffGrid`](crate::drc::Rule::OffGrid): `off_grid(; pitch: pitch)`.
    off_grid() [] { pitch: Dbu = "pitch" }
    /// [`Rule::Angle`](crate::drc::Rule::Angle): `angle([layer]; allowed: [..])`,
    /// each allowed angle in whole degrees.
    angle(layer: opt) [] { allowed: &[u32] = "angle" }
    /// [`Rule::RedundantVia`](crate::drc::Rule::RedundantVia):
    /// `redundant_via(layer; within: within) >= min_count`.
    redundant_via(layer: one) [] { min_count: u32 = "min_count", within: Dbu = "within" }
    /// [`Rule::ViaArraySpacing`](crate::drc::Rule::ViaArraySpacing):
    /// `via_array_space(layer; array: array_threshold) >= limit`.
    via_array_spacing(layer: one) [] { array_threshold: u32 = "array_threshold", limit: Dbu = "limit" }
    /// [`Rule::MultiPatterning`](crate::drc::Rule::MultiPatterning):
    /// `patterning(layer; colors: colors) >= color_spacing`.
    multi_patterning(layer: one) [] { colors: u32 = "colors", color_spacing: Dbu = "color_spacing" }
    /// [`Rule::Forbidden`](crate::drc::Rule::Forbidden): `forbidden(layer)`.
    forbidden(layer: one) [] {}
    /// [`Rule::MustContain`](crate::drc::Rule::MustContain): `contains(outer, inner) >= min_count`.
    must_contain(outer: one, inner: one) [] { min_count: u32 = "min_count" }
    /// [`Rule::MustBeInside`](crate::drc::Rule::MustBeInside): `inside(inner, outer)`.
    must_be_inside(inner: one, outer: one) [] {}
    /// [`Rule::NetSpacing`](crate::drc::Rule::NetSpacing):
    /// `space(layer[, other]; nets: same | different) >= limit`, `same_net`
    /// for `same` (one layer only).
    net_spacing(layer: one, other: opt) [] { same_net: bool = "same_net", limit: Dbu = "limit" }
    /// [`Rule::SpacingTable`](crate::drc::Rule::SpacingTable):
    /// `space_table(layer; prl: [..], width: [..], space: [[..], ..])`, `space`
    /// row by row.
    spacing_table(layer: one) [] { prl: &[Dbu] = "prl", width: &[Dbu] = "width", space: &[Dbu] = "space" }
    /// [`Rule::AttachedWideSpacing`](crate::drc::Rule::AttachedWideSpacing):
    /// `wide_space(layer; width: width_threshold, attached: attached) >= limit`.
    attached_wide_spacing(layer: one) [] {
        width_threshold: Dbu = "width_threshold",
        attached: Dbu = "attached",
        limit: Dbu = "limit",
    }
    /// [`Rule::EdgeMinLength`](crate::drc::Rule::EdgeMinLength): `length(edges) >= limit`.
    edge_min_length(edges: one) [] { limit: Dbu = "limit" }
    /// [`Rule::EdgeSpacing`](crate::drc::Rule::EdgeSpacing): `space(a[, b]) >= limit`, on edge layers.
    edge_spacing(a: one, b: opt) [] { limit: Dbu = "limit" }
    /// [`Rule::EdgeEnclosure`](crate::drc::Rule::EdgeEnclosure): `enclosure(edges, outer) >= limit`.
    edge_enclosure(edges: one, outer: one) [] { limit: Dbu = "limit" }
    /// [`Rule::Count`](crate::drc::Rule::Count): `count(layer) >= limit`, or
    /// `<=` when `maximum`.
    count(layer: one) [] { limit: u32 = "limit", maximum: bool = "maximum" }
    /// [`Rule::AspectRatio`](crate::drc::Rule::AspectRatio): `aspect_ratio(layer) <= limit`.
    aspect_ratio(layer: one) [] { limit: f64 = "limit" }
    /// [`Rule::TotalArea`](crate::drc::Rule::TotalArea): `total_area(layer) <= limit`.
    total_area(layer: one) [] { limit: DbuArea = "limit" }
    /// [`Rule::CutClass`](crate::drc::Rule::CutClass):
    /// `size(layer; allowed: [w x h, ..])`.
    cut_class(layer: one) [] { allowed: &[(Dbu, Dbu)] = "width" }
    /// [`Rule::EdgeWidth`](crate::drc::Rule::EdgeWidth): `width(edges) >= limit`.
    edge_width(edges: one) [] { limit: Dbu = "limit" }
    /// [`Rule::EdgeFacingSpace`](crate::drc::Rule::EdgeFacingSpace):
    /// `facing_space(edges) >= limit`.
    edge_facing_space(edges: one) [] { limit: Dbu = "limit" }
    /// [`Rule::RegionDensity`](crate::drc::Rule::RegionDensity):
    /// `region_density(layer, region) >= limit`, or `<=` when `maximum`;
    /// `limit` a fraction.
    region_density(layer: one, region: one) [] { limit: f64 = "limit", maximum: bool = "maximum" }
    /// [`Rule::AllowedWidth`](crate::drc::Rule::AllowedWidth):
    /// `width(layer; allowed: [..])`.
    allowed_width(layer: one) [] { allowed: &[Dbu] = "width" }
    /// [`Rule::MinInteriorAngle`](crate::drc::Rule::MinInteriorAngle):
    /// `interior_angle([layer]) >= limit`, in degrees.
    min_interior_angle(layer: opt) [] { limit: f64 = "limit" }
    /// [`Rule::PolygonValidity`](crate::drc::Rule::PolygonValidity): `valid([layer])`.
    polygon_validity(layer: opt) [] {}
    /// [`Rule::MinStep`](crate::drc::Rule::MinStep):
    /// `min_step(layer; max_edges: n | corner: .., length_sum) >= limit`;
    /// `length_sum` only with a corner.
    min_step(layer: one) [] { limit: Dbu = "limit", kind: StepKind = "corner", length_sum: Option<Dbu> = "length_sum" }
}

kinds! {
    /// Every ERC rule kind, as the deck spells it, alphabetical: the
    /// [`erc::KINDS`](crate::erc::KINDS) each [`RuleSet`](crate::erc::RuleSet)
    /// field is named after. Disjoint from [`DRC_KINDS`].
    ERC_KINDS;
    /// [`AntennaTable`](crate::erc::rules::antenna::AntennaTable):
    /// `antenna(gate, collectors..; max_ratio, sidewall: thickness | none, diode: layer | none)`.
    antenna(gate: one, collectors: many) [] {
        max_ratio: f64 = "max_ratio",
        sidewall: Option<Dbu> = "sidewall_thickness",
        diode: Option<LayerRef> = "diode_layer",
    }
    /// [`AntennaElectricalTable`](crate::erc::rules::antenna::AntennaElectricalTable):
    /// `antenna_electrical(gate, collectors..; max_ratio, sidewall, cut_factor,
    /// diode, diode_credit, diode_bonus, area_minus_diode, gate_plus_diode,
    /// diode_reduce, diode_max_ratio, exempt)`; the two tables are
    /// `(diode area, number)` points, empty for `none`.
    antenna_electrical(gate: one, collectors: many) [] {
        max_ratio: f64 = "max_ratio",
        sidewall: Option<Dbu> = "sidewall_thickness",
        cut_factor: f64 = "cut_factor",
        diode: Option<LayerRef> = "diode_layer",
        diode_credit: f64 = "diode_credit",
        diode_bonus: f64 = "diode_bonus",
        area_minus_diode: f64 = "area_minus_diode",
        gate_plus_diode: f64 = "gate_plus_diode",
        diode_reduce: &[(DbuArea, f64)] = "diode_reduce",
        diode_max_ratio: &[(DbuArea, f64)] = "diode_max_ratio",
        exempt: Option<LayerRef> = "exempt_layer",
    }
    /// [`DensityCmpTable`](crate::erc::rules::antenna::DensityCmpTable):
    /// `density_cmp(layer; window: x x y, step: x x y, min, max, max_delta,
    /// partial_windows, cmp: (target, sensitivity, max_delta) | none)`, the
    /// bounds fractions and `cmp_*` the three coefficients of `cmp`, all or
    /// none.
    density_cmp(layer: one) [] {
        window_x: Dbu = "window_x",
        window_y: Dbu = "window_y",
        step_x: Dbu = "step_x",
        step_y: Dbu = "step_y",
        min_density: Option<f64> = "min_density",
        max_density: Option<f64> = "max_density",
        max_neighbour_delta: Option<f64> = "max_neighbour_delta",
        include_partial_windows: bool = "include_partial_windows",
        cmp_target_density: Option<f64> = "cmp_target_density",
        cmp_thickness_sensitivity: Option<Dbu> = "cmp_thickness_sensitivity",
        cmp_max_abs_thickness_delta: Option<Dbu> = "cmp_max_abs_thickness_delta",
    }
    /// [`DielectricFieldTable`](crate::erc::rules::domain::DielectricFieldTable):
    /// `dielectric_field(layer[, other]; max_field)`, in V/µm.
    dielectric_field(layer: one, other: opt) [] { max_field: f64 = "max_field" }
    /// [`DomainCrossingTable`](crate::erc::rules::domain::DomainCrossingTable): `domain_crossing()`.
    domain_crossing() [] {}
    /// [`ModelLimitTable`](crate::erc::rules::domain::ModelLimitTable):
    /// `drain_source(; models, max)`, `max_voltage` in mV.
    drain_source() [] { models: &[&str] = "model", max_voltage: f64 = "max_voltage" }
    /// [`DynamicIrDropTable`](crate::erc::rules::electrical::DynamicIrDropTable):
    /// `dynamic_ir_drop()`.
    dynamic_ir_drop() [] {}
    /// [`ElectromigrationTable`](crate::erc::rules::electrical::ElectromigrationTable):
    /// `electromigration(layers..; ..)`, densities in A/m, currents in µA,
    /// the temperature in kelvin, the energy in eV.
    electromigration(layers: many) [] {
        max_density: f64 = "max_density",
        max_current_per_cut: f64 = "max_current_per_cut",
        blech_limit: f64 = "blech_limit",
        reference_temperature: f64 = "reference_temperature",
        activation_energy_ev: f64 = "activation_energy_ev",
        current_exponent: f64 = "current_exponent",
    }
    /// [`EmCurrentDensityTable`](crate::erc::rules::electrical::EmCurrentDensityTable):
    /// `em_current_density(layers..; max_density, max_current_per_cut,
    /// narrow: (width, current) | none)`, in A/m and µA; the narrow band's
    /// two values are both stated or both `None`.
    em_current_density(layers: many) [] {
        max_density: f64 = "max_density",
        max_current_per_cut: f64 = "max_current_per_cut",
        narrow_width: Option<Dbu> = "narrow_width",
        narrow_current: Option<f64> = "narrow_current",
    }
    /// [`EmThermalTable`](crate::erc::rules::electrical::EmThermalTable):
    /// `em_thermal(layers..; ..)`, as `electromigration` plus the
    /// dielectric's thermal conductivity in W/(m·K), the heat-spreading
    /// factor, the lognormal sigma and the two failure fractions.
    em_thermal(layers: many) [] {
        max_density: f64 = "max_density",
        max_current_per_cut: f64 = "max_current_per_cut",
        blech_limit: f64 = "blech_limit",
        reference_temperature: f64 = "reference_temperature",
        activation_energy_ev: f64 = "activation_energy_ev",
        current_exponent: f64 = "current_exponent",
        thermal_conductivity: f64 = "thermal_conductivity",
        heat_spreading: f64 = "heat_spreading",
        sigma: f64 = "sigma",
        limit_failure: f64 = "limit_failure",
        max_failure: f64 = "max_failure",
    }
    /// [`EsdLatchupTable`](crate::erc::rules::reliability::EsdLatchupTable):
    /// `esd_latchup(pad, guard_ring; min_guard_ring_width, max_tap_distance, clamps)`.
    esd_latchup(pad: one, guard_ring: one) [] {
        min_guard_ring_width: Dbu = "min_guard_ring_width",
        max_tap_distance: Dbu = "max_tap_distance",
        clamps: &[&str] = "clamp",
    }
    /// [`EsdTopologicalTable`](crate::erc::rules::supply::EsdTopologicalTable):
    /// `esd_topological(pad; clamps)`.
    esd_topological(pad: one) [] { clamps: &[&str] = "clamp" }
    /// [`FanoutTable`](crate::erc::rules::topology::FanoutTable): `fanout(; max)`.
    fanout() [] { max_gates: u32 = "max_gates" }
    /// [`FloatingGateTable`](crate::erc::rules::topology::FloatingGateTable):
    /// `floating_gate(; labels_are_ports)`.
    floating_gate() [] { labels_are_ports: bool = "labels_are_ports" }
    /// [`FloatingWellTable`](crate::erc::rules::topology::FloatingWellTable): `floating_well(well, tap)`.
    floating_well(well: one, tap: one) [] {}
    /// [`ModelLimitTable`](crate::erc::rules::domain::ModelLimitTable):
    /// `gate_oxide(; models, max)`, `max_voltage` in mV.
    gate_oxide() [] { models: &[&str] = "model", max_voltage: f64 = "max_voltage" }
    /// [`HvDomainTable`](crate::erc::rules::reliability::HvDomainTable):
    /// `hv_domain(; max_delta, isolation: layer | none)`, in mV.
    hv_domain() [] { max_domain_delta: f64 = "max_domain_delta", isolation: Option<LayerRef> = "isolation" }
    /// [`HvTagTable`](crate::erc::rules::domain::HvTagTable):
    /// `hv_tag(layer, tag; voltage)`, in mV.
    hv_tag(layer: one, tag: one) [] { voltage: f64 = "voltage" }
    /// [`IrDropTable`](crate::erc::rules::electrical::IrDropTable): `ir_drop()`.
    ir_drop() [] {}
    /// [`MissingIsolationTable`](crate::erc::rules::domain::MissingIsolationTable):
    /// `missing_isolation(; isolation: models | none)`.
    missing_isolation() [] { isolation: &[&str] = "isolation" }
    /// [`MissingLevelShifterTable`](crate::erc::rules::domain::MissingLevelShifterTable):
    /// `missing_level_shifter(; shifters: models | none)`.
    missing_level_shifter() [] { shifters: &[&str] = "shifter" }
    /// [`MissingTieTable`](crate::erc::rules::supply::MissingTieTable):
    /// `missing_tie(region, tap; max_distance)`.
    missing_tie(region: one, tap: one) [] { max_distance: Dbu = "max_distance" }
    /// [`MixedTagTable`](crate::erc::rules::supply::MixedTagTable): `mixed_tag(layer, tag)`.
    mixed_tag(layer: one, tag: one) [] {}
    /// [`MultipleDriversTable`](crate::erc::rules::topology::MultipleDriversTable):
    /// `multiple_drivers(; max)`.
    multiple_drivers() [] { max_drivers: u32 = "max_drivers" }
    /// [`P2pResistanceTable`](crate::erc::rules::electrical::P2pResistanceTable):
    /// `p2p_resistance(; max)`, in ohms.
    p2p_resistance() [] { max_resistance: f64 = "max_resistance" }
    /// [`ReliabilityTable`](crate::erc::rules::reliability::ReliabilityTable):
    /// `reliability(; ..)`, lifetimes in hours, voltages in mV, the
    /// temperature in kelvin, the energy in eV, the duty cycle a fraction.
    reliability() [] {
        required_lifetime_hours: f64 = "required_lifetime_hours",
        reference_lifetime_hours: f64 = "reference_lifetime_hours",
        reference_stress: f64 = "reference_stress",
        stress_exponent: f64 = "stress_exponent",
        reference_temperature: f64 = "reference_temperature",
        activation_energy_ev: f64 = "activation_energy_ev",
        max_abs_voltage: f64 = "max_abs_voltage",
        duty_cycle: f64 = "duty_cycle",
    }
    /// [`SoftConnectionTable`](crate::erc::rules::supply::SoftConnectionTable):
    /// `soft_connection(layers..)`.
    soft_connection(layers: many) [] {}
    /// [`SupplyShortTable`](crate::erc::rules::supply::SupplyShortTable):
    /// `supply_short(tap_a, tap_b[, within])`.
    supply_short(tap_a: one, tap_b: one, within: opt) [] {}
    /// [`TieHighLowTable`](crate::erc::rules::supply::TieHighLowTable): `tie_high_low()`.
    tie_high_low() [] {}
    /// [`UnconnectedPinTable`](crate::erc::rules::topology::UnconnectedPinTable):
    /// `unconnected_pin(layers..)`.
    unconnected_pin(layers: many) [] {}
    /// [`UndrivenGateTable`](crate::erc::rules::domain::UndrivenGateTable): `undriven_gate()`.
    undriven_gate() [] {}
    /// [`VoltageSpacingTable`](crate::erc::rules::domain::VoltageSpacingTable):
    /// `voltage_space(layer[, other]; voltage: [..], space: [..])`, the
    /// voltages in mV.
    voltage_spacing(layer: one, other: opt) [] { voltage: &[f64] = "voltage", space: &[Dbu] = "space" }
    /// [`WellBiasTable`](crate::erc::rules::domain::WellBiasTable):
    /// `well_bias(; pmos: models | none, nmos: models | none)`.
    well_bias() [] { pmos: &[&str] = "pmos", nmos: &[&str] = "nmos" }
}
