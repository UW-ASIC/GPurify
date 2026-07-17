//! Additive production-deck schema and fail-closed checked execution.
//!
//! The original [`crate::params::Deck`] remains the explicitly named W1 legacy
//! adapter. This module does not reinterpret legacy JSON. New decks use a versioned,
//! strict schema with typed quantities, expressions, lookup tables, symbolic base or
//! derived layer references, and context selectors. A parsed rule is never silently
//! skipped: missing evidence is `Error`, an inapplicable declared context is `NotRun`,
//! and an implementation gap is `Unsupported`.

use super::derived::{DerivedError, DerivedEvaluator, DerivedExpr, DerivedValue, LayerExprRef};
use super::{run_drc, Violation};
use gdsverify_core::exact::{
    rectilinear_intersection, rectilinear_subtraction, Point, Polygon, PolygonSet,
};
use crate::geometry::{GeometryStore, LayerId};
use crate::params::{Deck, LayerTable};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    Dbu,
    Nanometer,
    SquareDbu,
    SquareNanometer,
    Ratio,
    Count,
    Volt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Dimension {
    Length,
    Area,
    Ratio,
    Count,
    Voltage,
}

impl Unit {
    pub fn dimension(self) -> Dimension {
        match self {
            Self::Dbu | Self::Nanometer => Dimension::Length,
            Self::SquareDbu | Self::SquareNanometer => Dimension::Area,
            Self::Ratio => Dimension::Ratio,
            Self::Count => Dimension::Count,
            Self::Volt => Dimension::Voltage,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Literal {
    pub value: f64,
    pub unit: Unit,
}

/// Quantity normalized to DBU, DBU², ratio, count, or volts.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Quantity {
    pub value: f64,
    pub dimension: Dimension,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScalarExpr {
    Literal {
        value: f64,
        unit: Unit,
    },
    Variable {
        name: String,
    },
    Add {
        lhs: Box<ScalarExpr>,
        rhs: Box<ScalarExpr>,
    },
    Subtract {
        lhs: Box<ScalarExpr>,
        rhs: Box<ScalarExpr>,
    },
    Multiply {
        lhs: Box<ScalarExpr>,
        rhs: Box<ScalarExpr>,
    },
    Divide {
        lhs: Box<ScalarExpr>,
        rhs: Box<ScalarExpr>,
    },
    Lookup {
        table: String,
        input: Box<ScalarExpr>,
    },
    /// Conditional expression for table-driven limits.
    Conditional {
        when: Box<ContextSelector>,
        then_expr: Box<ScalarExpr>,
        else_expr: Box<ScalarExpr>,
    },
    /// Minimum of two expressions.
    Min {
        lhs: Box<ScalarExpr>,
        rhs: Box<ScalarExpr>,
    },
    /// Maximum of two expressions.
    Max {
        lhs: Box<ScalarExpr>,
        rhs: Box<ScalarExpr>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TablePoint {
    pub input: f64,
    pub output: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupTable {
    pub input_unit: Unit,
    pub output_unit: Unit,
    pub points: Vec<TablePoint>,
    /// If false, use a lower-bound step table. If true, linearly interpolate.
    #[serde(default)]
    pub interpolate: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum LayerSourceSchema {
    Base { name: String },
    Derived { name: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedLayerSource {
    Base(LayerId),
    Derived(String),
}

/// Symbolic derived-layer AST used at the JSON boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum DerivedLayerSchema {
    Layer {
        source: LayerSourceSchema,
    },
    Union {
        operands: Vec<DerivedLayerSchema>,
    },
    Intersection {
        lhs: Box<DerivedLayerSchema>,
        rhs: Box<DerivedLayerSchema>,
    },
    Subtraction {
        lhs: Box<DerivedLayerSchema>,
        rhs: Box<DerivedLayerSchema>,
    },
    Xor {
        lhs: Box<DerivedLayerSchema>,
        rhs: Box<DerivedLayerSchema>,
    },
    NotWithin {
        region: Box<DerivedLayerSchema>,
        operand: Box<DerivedLayerSchema>,
    },
    Grow {
        operand: Box<DerivedLayerSchema>,
        distance: i32,
    },
    Shrink {
        operand: Box<DerivedLayerSchema>,
        distance: i32,
    },
    Inside {
        operand: Box<DerivedLayerSchema>,
        region: Box<DerivedLayerSchema>,
    },
    Outside {
        operand: Box<DerivedLayerSchema>,
        region: Box<DerivedLayerSchema>,
    },
    Interacting {
        operand: Box<DerivedLayerSchema>,
        other: Box<DerivedLayerSchema>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetRelation {
    SameNet,
    DifferentNet,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSelector {
    pub net_relation: Option<NetRelation>,
    pub min_voltage_difference: Option<ScalarExpr>,
    pub domains: Option<Vec<String>>,
    pub region: Option<String>,
    pub cells: Option<Vec<String>>,
    pub hierarchy_prefix: Option<String>,
    pub process: Option<String>,
    pub corner: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProductionRuleSchema {
    MinWidth {
        id: String,
        layer: LayerSourceSchema,
        limit: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    Spacing {
        id: String,
        layer: LayerSourceSchema,
        other: Option<LayerSourceSchema>,
        limit: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    PrlSpacing {
        id: String,
        layer: LayerSourceSchema,
        parallel_run_length: ScalarExpr,
        limit: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    EolSpacing {
        id: String,
        layer: LayerSourceSchema,
        eol_width: ScalarExpr,
        within: ScalarExpr,
        limit: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    Enclosure {
        id: String,
        outer: LayerSourceSchema,
        inner: LayerSourceSchema,
        limit: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    Extension {
        id: String,
        layer: LayerSourceSchema,
        reference: LayerSourceSchema,
        limit: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    MinArea {
        id: String,
        layer: LayerSourceSchema,
        limit: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    MinEnclosedArea {
        id: String,
        layer: LayerSourceSchema,
        limit: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    /// Large material components require an exact hole or explicit slot/keyhole
    /// evidence layer that touches or interacts with the component.
    Cheesing {
        id: String,
        layer: LayerSourceSchema,
        slots: LayerSourceSchema,
        max_area_without_slot: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    CutClass {
        id: String,
        cut: LayerSourceSchema,
        class: String,
        min_count: ScalarExpr,
        within: ScalarExpr,
        #[serde(default)]
        redundancy: Option<ScalarExpr>,
        #[serde(default)]
        when: ContextSelector,
    },
    Density {
        id: String,
        layer: LayerSourceSchema,
        region: LayerSourceSchema,
        exclusion: Option<LayerSourceSchema>,
        window: ScalarExpr,
        step: ScalarExpr,
        min: Option<ScalarExpr>,
        max: Option<ScalarExpr>,
        #[serde(default)]
        cmp_model: Option<String>,
        #[serde(default)]
        when: ContextSelector,
    },
    Antenna {
        id: String,
        conductor: LayerSourceSchema,
        gate: LayerSourceSchema,
        diode: Option<LayerSourceSchema>,
        fabrication_stage: u32,
        ratio_limit: ScalarExpr,
        #[serde(default)]
        equation: Option<String>,
        #[serde(default)]
        when: ContextSelector,
    },
    MultiPatterning {
        id: String,
        layer: LayerSourceSchema,
        colors: ScalarExpr,
        spacing: ScalarExpr,
        #[serde(default)]
        max_search_states: Option<u64>,
        #[serde(default)]
        when: ContextSelector,
    },
    // --- legacy parity variants below ---
    MaxWidth {
        id: String,
        layer: LayerSourceSchema,
        limit: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    Notch {
        id: String,
        layer: LayerSourceSchema,
        limit: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    MinEdgeLength {
        id: String,
        layer: LayerSourceSchema,
        limit: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    OffGrid {
        id: String,
        grid: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    Angle {
        id: String,
        allowed: Vec<i32>,
        #[serde(default)]
        when: ContextSelector,
    },
    Overlap {
        id: String,
        a: LayerSourceSchema,
        b: LayerSourceSchema,
        limit: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    CornerToCorner {
        id: String,
        layer: LayerSourceSchema,
        limit: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    WideDependentSpacing {
        id: String,
        layer: LayerSourceSchema,
        width_threshold: ScalarExpr,
        wide_spacing: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    AsymmetricEnclosure {
        id: String,
        outer: LayerSourceSchema,
        inner: LayerSourceSchema,
        min_one_side: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    RedundantVia {
        id: String,
        cut: LayerSourceSchema,
        min_count: ScalarExpr,
        within: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    ViaArraySpacing {
        id: String,
        layer: LayerSourceSchema,
        array_threshold: ScalarExpr,
        array_spacing: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    MaxDistanceToTap {
        id: String,
        diff_layer: LayerSourceSchema,
        tap_layer: LayerSourceSchema,
        max_dist: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
    AntennaCar {
        id: String,
        layers: Vec<LayerSourceSchema>,
        ratio_limit: ScalarExpr,
        diode: Option<LayerSourceSchema>,
        #[serde(default)]
        when: ContextSelector,
    },
    SpacingDiff {
        id: String,
        a: LayerSourceSchema,
        b: LayerSourceSchema,
        limit: ScalarExpr,
        #[serde(default)]
        when: ContextSelector,
    },
}

impl ProductionRuleSchema {
    pub fn id(&self) -> &str {
        match self {
            Self::MinWidth { id, .. }
            | Self::Spacing { id, .. }
            | Self::PrlSpacing { id, .. }
            | Self::EolSpacing { id, .. }
            | Self::Enclosure { id, .. }
            | Self::Extension { id, .. }
            | Self::MinArea { id, .. }
            | Self::MinEnclosedArea { id, .. }
            | Self::Cheesing { id, .. }
            | Self::CutClass { id, .. }
            | Self::Density { id, .. }
            | Self::Antenna { id, .. }
            | Self::MultiPatterning { id, .. }
            | Self::MaxWidth { id, .. }
            | Self::Notch { id, .. }
            | Self::MinEdgeLength { id, .. }
            | Self::OffGrid { id, .. }
            | Self::Angle { id, .. }
            | Self::Overlap { id, .. }
            | Self::CornerToCorner { id, .. }
            | Self::WideDependentSpacing { id, .. }
            | Self::AsymmetricEnclosure { id, .. }
            | Self::RedundantVia { id, .. }
            | Self::ViaArraySpacing { id, .. }
            | Self::MaxDistanceToTap { id, .. }
            | Self::AntennaCar { id, .. }
            | Self::SpacingDiff { id, .. } => id,
        }
    }

    fn selector(&self) -> &ContextSelector {
        match self {
            Self::MinWidth { when, .. }
            | Self::Spacing { when, .. }
            | Self::PrlSpacing { when, .. }
            | Self::EolSpacing { when, .. }
            | Self::Enclosure { when, .. }
            | Self::Extension { when, .. }
            | Self::MinArea { when, .. }
            | Self::MinEnclosedArea { when, .. }
            | Self::Cheesing { when, .. }
            | Self::CutClass { when, .. }
            | Self::Density { when, .. }
            | Self::Antenna { when, .. }
            | Self::MultiPatterning { when, .. }
            | Self::MaxWidth { when, .. }
            | Self::Notch { when, .. }
            | Self::MinEdgeLength { when, .. }
            | Self::OffGrid { when, .. }
            | Self::Angle { when, .. }
            | Self::Overlap { when, .. }
            | Self::CornerToCorner { when, .. }
            | Self::WideDependentSpacing { when, .. }
            | Self::AsymmetricEnclosure { when, .. }
            | Self::RedundantVia { when, .. }
            | Self::ViaArraySpacing { when, .. }
            | Self::MaxDistanceToTap { when, .. }
            | Self::AntennaCar { when, .. }
            | Self::SpacingDiff { when, .. } => when,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionDeckSchema {
    pub schema_version: u32,
    pub deck_id: String,
    pub model_revision: String,
    pub dbu_nm: f64,
    #[serde(default)]
    pub variables: BTreeMap<String, ScalarExpr>,
    #[serde(default)]
    pub tables: BTreeMap<String, LookupTable>,
    #[serde(default)]
    pub derived_layers: BTreeMap<String, DerivedLayerSchema>,
    pub rules: Vec<ProductionRuleSchema>,
}

#[derive(Clone, Debug)]
pub struct ProductionDeck {
    pub schema: ProductionDeckSchema,
    pub derived_layers: BTreeMap<String, DerivedExpr>,
}

impl ProductionDeck {
    /// Parse strict JSON and resolve all symbolic layers before any layout runs.
    pub fn from_json(value: &serde_json::Value, layers: &LayerTable) -> Result<Self, DeckError> {
        let schema: ProductionDeckSchema = serde_json::from_value(value.clone())
            .map_err(|error| DeckError::Schema(error.to_string()))?;
        Self::from_schema(schema, layers)
    }

    pub fn from_schema(
        schema: ProductionDeckSchema,
        layers: &LayerTable,
    ) -> Result<Self, DeckError> {
        if schema.schema_version != 1 {
            return Err(DeckError::Schema(format!(
                "unsupported production DRC schema version {}",
                schema.schema_version
            )));
        }
        if schema.deck_id.trim().is_empty() || schema.model_revision.trim().is_empty() {
            return Err(DeckError::Schema(
                "deck_id and model_revision must not be empty".into(),
            ));
        }
        if !schema.dbu_nm.is_finite() || schema.dbu_nm <= 0.0 {
            return Err(DeckError::Schema(
                "dbu_nm must be finite and positive".into(),
            ));
        }
        validate_tables(&schema.tables, schema.dbu_nm)?;
        validate_variables(&schema.variables, &schema.tables, schema.dbu_nm)?;

        let derived_layers = schema
            .derived_layers
            .iter()
            .map(|(name, expression)| {
                if name.trim().is_empty() {
                    return Err(DeckError::Schema(
                        "derived-layer name must not be empty".into(),
                    ));
                }
                Ok((
                    name.clone(),
                    resolve_derived(expression, layers, &schema.derived_layers)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let mut ids = BTreeSet::new();
        for rule in &schema.rules {
            if rule.id().trim().is_empty() || !ids.insert(rule.id().to_owned()) {
                return Err(DeckError::Schema(format!(
                    "rule ID `{}` is empty or duplicated",
                    rule.id()
                )));
            }
            validate_rule(rule, &schema, layers)?;
        }

        // Resolve every named derived layer now. Cycles and arbitrary-angle operations
        // that depend on actual geometry remain checked at run time, but references are
        // guaranteed to exist before execution.
        for expression in derived_layers.values() {
            validate_derived_references(expression, &derived_layers)?;
        }
        Ok(Self {
            schema,
            derived_layers,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct DrcContext {
    pub poly_nets: Option<BTreeMap<u32, String>>,
    pub net_voltages: Option<BTreeMap<String, f64>>,
    pub net_domains: Option<BTreeMap<String, String>>,
    pub poly_cells: Option<BTreeMap<u32, String>>,
    pub hierarchy_paths: Option<BTreeMap<u32, String>>,
    pub regions: BTreeMap<String, PolygonSet>,
    pub exclusion_regions: BTreeMap<String, PolygonSet>,
    pub process: Option<String>,
    pub corner: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleStatus {
    Clean,
    Violations,
    NotRun,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiagnosticCode {
    MissingContext,
    ContextNotApplicable,
    Unsupported,
    CapacityExceeded,
    InvalidGeometry,
    InvalidModel,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleDiagnostic {
    pub code: DiagnosticCode,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct CheckedRuleResult {
    pub rule_id: String,
    pub status: RuleStatus,
    pub violations: Vec<Violation>,
    pub diagnostics: Vec<RuleDiagnostic>,
}

#[derive(Clone, Debug)]
pub struct CheckedDrcReport {
    pub deck_id: String,
    pub model_revision: String,
    pub legacy_adapter: bool,
    pub rules: Vec<CheckedRuleResult>,
}

impl CheckedDrcReport {
    pub fn is_clean(&self) -> bool {
        !self.rules.is_empty()
            && self
                .rules
                .iter()
                .all(|rule| rule.status == RuleStatus::Clean)
    }
}

/// Explicit W1 compatibility adapter. It preserves all legacy results but does not
/// advertise production contextual semantics.
pub fn run_legacy_adapter(store: &GeometryStore, deck: &Deck) -> CheckedDrcReport {
    let report = run_drc(store, deck);
    let capacity_stop = report
        .violations
        .iter()
        .any(|violation| violation.kind == "geometry_capacity");
    let mut by_rule = BTreeMap::<String, Vec<Violation>>::new();
    for violation in report.violations {
        by_rule
            .entry(violation.rule_id.clone())
            .or_default()
            .push(violation);
    }
    let mut rules: Vec<_> = deck
        .drc_rules
        .iter()
        .map(|rule| {
            let violations = by_rule.remove(rule.id()).unwrap_or_default();
            CheckedRuleResult {
                rule_id: rule.id().to_owned(),
                status: if capacity_stop {
                    RuleStatus::NotRun
                } else if violations.is_empty() {
                    RuleStatus::Clean
                } else {
                    RuleStatus::Violations
                },
                violations,
                diagnostics: if capacity_stop {
                    vec![RuleDiagnostic {
                        code: DiagnosticCode::CapacityExceeded,
                        message: "rule was not run because input geometry exceeds legacy numeric capacity"
                            .into(),
                    }]
                } else {
                    Vec::new()
                },
            }
        })
        .collect();
    // Always-on geometry validation is deliberately outside the deck rule list.
    // Preserve those leftovers as errors; dropping them lets malformed layouts
    // become CLEAN through the compatibility adapter.
    for (rule_id, violations) in by_rule {
        let capacity = violations
            .iter()
            .any(|violation| violation.kind == "geometry_capacity");
        rules.push(CheckedRuleResult {
            rule_id,
            status: RuleStatus::Error,
            violations,
            diagnostics: vec![RuleDiagnostic {
                code: if capacity {
                    DiagnosticCode::CapacityExceeded
                } else {
                    DiagnosticCode::InvalidGeometry
                },
                message: if capacity {
                    "geometry exceeds the numeric capacity of the legacy DRC rule/report API".into()
                } else {
                    "always-on geometry validation failed".into()
                },
            }],
        });
    }
    CheckedDrcReport {
        deck_id: "legacy-w1".into(),
        model_revision: "legacy-w1".into(),
        legacy_adapter: true,
        rules,
    }
}

/// Run the strict production deck. Currently exact min-area and explicit-region
/// density are production-enabled. Other declared operations return `Unsupported`
/// until their private legacy bbox measurements have migrated to the exact kernel.
pub fn run_checked(
    store: &GeometryStore,
    deck: &ProductionDeck,
    layers: &LayerTable,
    context: &DrcContext,
) -> CheckedDrcReport {
    let mut evaluator =
        DerivedEvaluator::new_checked(store, &deck.derived_layers, layers.id_to_name.len());
    let rules = deck
        .schema
        .rules
        .iter()
        .map(|rule| {
            if let Some(result) = check_context(rule.id(), rule.selector(), context) {
                return result;
            }
            match run_rule(rule, deck, layers, &mut evaluator) {
                Ok(violations) => CheckedRuleResult {
                    rule_id: rule.id().to_owned(),
                    status: if violations.is_empty() {
                        RuleStatus::Clean
                    } else {
                        RuleStatus::Violations
                    },
                    violations,
                    diagnostics: Vec::new(),
                },
                Err(error) => CheckedRuleResult {
                    rule_id: rule.id().to_owned(),
                    status: RuleStatus::Error,
                    violations: Vec::new(),
                    diagnostics: vec![RuleDiagnostic {
                        code: match &error {
                            RunError::Unsupported(_) => DiagnosticCode::Unsupported,
                            RunError::Derived(DerivedError::CapacityExceeded { .. })
                            | RunError::Derived(DerivedError::Geometry(
                                gdsverify_core::exact::ExactGeometryError::CapacityExceeded {
                                    ..
                                }
                                | gdsverify_core::exact::ExactGeometryError::ArithmeticOverflow,
                            )) => DiagnosticCode::CapacityExceeded,
                            RunError::Derived(_) => DiagnosticCode::InvalidGeometry,
                            RunError::Expression(_) => DiagnosticCode::InvalidModel,
                        },
                        message: error.to_string(),
                    }],
                },
            }
        })
        .collect();
    CheckedDrcReport {
        deck_id: deck.schema.deck_id.clone(),
        model_revision: deck.schema.model_revision.clone(),
        legacy_adapter: false,
        rules,
    }
}

fn run_rule(
    rule: &ProductionRuleSchema,
    deck: &ProductionDeck,
    layers: &LayerTable,
    evaluator: &mut DerivedEvaluator<'_>,
) -> Result<Vec<Violation>, RunError> {
    match rule {
        ProductionRuleSchema::MinArea { id, layer, limit, .. } => {
            let set = evaluate_source(layer, layers, evaluator)?;
            let limit = evaluate_expression(limit, deck)?.value;
            let mut violations = Vec::new();
            for polygon in set.polygons() {
                let area = polygon.area2() as f64 / 2.0;
                if area < limit {
                    let point = polygon.outer().vertices()[0];
                    violations.push(Violation {
                        rule_id: id.clone(),
                        kind: "min_area".into(),
                        layer: source_name(layer),
                        measured: saturating_i64(area),
                        limit: saturating_i64(limit),
                        x: point.x,
                        y: point.y,
                        hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                    });
                }
            }
            Ok(violations)
        }
        ProductionRuleSchema::MinEnclosedArea { id, layer, limit, .. } => {
            let set = evaluate_source(layer, layers, evaluator)?;
            let limit = evaluate_expression(limit, deck)?.value;
            let mut violations = Vec::new();
            for polygon in set.polygons() {
                for hole in polygon.holes() {
                    let area = -(hole.signed_area2() as f64) / 2.0;
                    if area < limit {
                        let point = hole.vertices()[0];
                        violations.push(Violation {
                            rule_id: id.clone(), kind: "min_enclosed_area".into(),
                            layer: source_name(layer), measured: saturating_i64(area),
                            limit: saturating_i64(limit), x: point.x, y: point.y,
                            hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                        });
                    }
                }
            }
            Ok(violations)
        }
        ProductionRuleSchema::Cheesing {
            id, layer, slots, max_area_without_slot, ..
        } => {
            let set = evaluate_source(layer, layers, evaluator)?;
            let slots_set = evaluate_source(slots, layers, evaluator)?;
            let limit = evaluate_expression(max_area_without_slot, deck)?.value;
            let mut violations = Vec::new();
            for polygon in set.polygons() {
                let area = polygon.area2() as f64 / 2.0;
                if area <= limit || !polygon.holes().is_empty() { continue; }
                let has_explicit_slot = slots_set.polygons().iter().any(|slot| {
                    gdsverify_core::exact::classify_polygon_contact(
                        polygon.outer(), slot.outer(),
                    ) != gdsverify_core::exact::PolygonContact::Disjoint
                });
                if !has_explicit_slot {
                    let point = polygon.outer().vertices()[0];
                    violations.push(Violation {
                        rule_id: id.clone(), kind: "cheesing".into(),
                        layer: source_name(layer), measured: saturating_i64(area),
                        limit: saturating_i64(limit), x: point.x, y: point.y,
                        hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                    });
                }
            }
            Ok(violations)
        }
        ProductionRuleSchema::Density {
            id,
            layer,
            region,
            exclusion,
            window,
            step,
            min,
            max,
            cmp_model,
            ..
        } => {
            if cmp_model.is_some() {
                return Err(RunError::Unsupported(
                    "CMP model execution requires calibrated model inputs; the schema is retained but no coefficients are invented".into(),
                ));
            }
            let material = evaluate_source(layer, layers, evaluator)?;
            let mut region = evaluate_source(region, layers, evaluator)?;
            if let Some(exclusion) = exclusion {
                region = rectilinear_subtraction(&region, &evaluate_source(exclusion, layers, evaluator)?)?;
            }
            let window = positive_i32(evaluate_expression(window, deck)?.value, "window")?;
            let step = positive_i32(evaluate_expression(step, deck)?.value, "step")?;
            if step > window {
                return Err(RunError::Expression("density step cannot exceed window (unchecked gaps)".into()));
            }
            let min = min.as_ref().map(|expr| evaluate_expression(expr, deck)).transpose()?.map(|q| q.value);
            let max = max.as_ref().map(|expr| evaluate_expression(expr, deck)).transpose()?.map(|q| q.value);
            exact_density(id, layer, &material, &region, window, step, min, max)
        }
        ProductionRuleSchema::MinWidth { id, layer, limit, .. } => {
            let set = evaluate_source(layer, layers, evaluator)?;
            let limit_dbu = positive_i32(evaluate_expression(limit, deck)?.value, "limit")?;
            let mut violations = Vec::new();
            let store = polygonset_to_store(&set);
            for p in 0..store.poly_count() {
                let pid = crate::geometry::PolyId(p as u32);
                // ponytail: facing_gaps interior=true gives width measurements
                let gaps = super::facing_gaps(&store, pid, true)?;
                for (d, mx, my) in gaps {
                    if d < i64::from(limit_dbu) {
                        violations.push(Violation {
                            rule_id: id.clone(), kind: "min_width".into(),
                            layer: source_name(layer), measured: d,
                            limit: i64::from(limit_dbu), x: mx, y: my,
                            hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                        });
                    }
                }
            }
            Ok(violations)
        }
        ProductionRuleSchema::MaxWidth { id, layer, limit, .. } => {
            let set = evaluate_source(layer, layers, evaluator)?;
            let limit_dbu = positive_i32(evaluate_expression(limit, deck)?.value, "limit")?;
            let mut violations = Vec::new();
            let store = polygonset_to_store(&set);
            for p in 0..store.poly_count() {
                let pid = crate::geometry::PolyId(p as u32);
                let gaps = super::facing_gaps(&store, pid, true)?;
                for (d, mx, my) in gaps {
                    if d > i64::from(limit_dbu) {
                        violations.push(Violation {
                            rule_id: id.clone(), kind: "max_width".into(),
                            layer: source_name(layer), measured: d,
                            limit: i64::from(limit_dbu), x: mx, y: my,
                            hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                        });
                    }
                }
            }
            Ok(violations)
        }
        ProductionRuleSchema::Notch { id, layer, limit, .. } => {
            let set = evaluate_source(layer, layers, evaluator)?;
            let limit_dbu = positive_i32(evaluate_expression(limit, deck)?.value, "limit")?;
            let mut violations = Vec::new();
            let store = polygonset_to_store(&set);
            for p in 0..store.poly_count() {
                let pid = crate::geometry::PolyId(p as u32);
                // ponytail: facing_gaps interior=false gives notch (exterior gap) measurements
                let gaps = super::facing_gaps(&store, pid, false)?;
                for (d, mx, my) in gaps {
                    if d < i64::from(limit_dbu) {
                        violations.push(Violation {
                            rule_id: id.clone(), kind: "notch".into(),
                            layer: source_name(layer), measured: d,
                            limit: i64::from(limit_dbu), x: mx, y: my,
                            hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                        });
                    }
                }
            }
            Ok(violations)
        }
        ProductionRuleSchema::Spacing { id, layer, other, limit, .. } => {
            let set_a = evaluate_source(layer, layers, evaluator)?;
            let limit_dbu = positive_i32(evaluate_expression(limit, deck)?.value, "limit")?;
            let mut violations = Vec::new();
            if let Some(other_layer) = other {
                // Two-layer spacing
                let set_b = evaluate_source(other_layer, layers, evaluator)?;
                let mut store = GeometryStore::new();
                let mut pa = Vec::new();
                let mut pb = Vec::new();
                for polygon in set_a.polygons() {
                    let pts: Vec<(i32, i32)> = polygon.outer().vertices().iter()
                        .map(|v| (v.x, v.y)).collect();
                    pa.push(store.add_polygon(0, &pts));
                }
                for polygon in set_b.polygons() {
                    let pts: Vec<(i32, i32)> = polygon.outer().vertices().iter()
                        .map(|v| (v.x, v.y)).collect();
                    pb.push(store.add_polygon(1, &pts));
                }
                let limit2 = i64::from(limit_dbu) * i64::from(limit_dbu);
                let cands = super::candidate_pairs(&store, &pa, Some(&pb), limit_dbu);
                for (a, b) in cands {
                    let d2 = super::poly_poly_dist2_within(&store, a, b, limit_dbu);
                    if d2 > 0 && d2 < limit2 {
                        let ba = store.poly_bbox[a.0 as usize];
                        let bb = store.poly_bbox[b.0 as usize];
                        let mx = super::midpoint_i32(
                            ba.xmin.max(bb.xmin).min(ba.xmax),
                            bb.xmin.max(ba.xmin).min(bb.xmax),
                        )?;
                        let my = super::midpoint_i32(
                            ba.ymin.max(bb.ymin).min(ba.ymax),
                            bb.ymin.max(ba.ymin).min(bb.ymax),
                        )?;
                        violations.push(Violation {
                            rule_id: id.clone(), kind: "spacing".into(),
                            layer: source_name(layer),
                            measured: crate::geometry::isqrt(d2),
                            limit: i64::from(limit_dbu), x: mx, y: my,
                            hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                        });
                    }
                }
            } else {
                // Same-layer spacing
                let store = polygonset_to_store(&set_a);
                let polys: Vec<crate::geometry::PolyId> = (0..store.poly_count())
                    .map(|i| crate::geometry::PolyId(i as u32)).collect();
                let limit2 = i64::from(limit_dbu) * i64::from(limit_dbu);
                let cands = super::candidate_pairs(&store, &polys, None, limit_dbu);
                for (a, b) in cands {
                    let d2 = super::poly_poly_dist2_within(&store, a, b, limit_dbu);
                    if d2 > 0 && d2 < limit2 {
                        let ba = store.poly_bbox[a.0 as usize];
                        let bb = store.poly_bbox[b.0 as usize];
                        let mx = super::midpoint_i32(
                            ba.xmin.max(bb.xmin).min(ba.xmax),
                            bb.xmin.max(ba.xmin).min(bb.xmax),
                        )?;
                        let my = super::midpoint_i32(
                            ba.ymin.max(bb.ymin).min(ba.ymax),
                            bb.ymin.max(ba.ymin).min(bb.ymax),
                        )?;
                        violations.push(Violation {
                            rule_id: id.clone(), kind: "spacing".into(),
                            layer: source_name(layer),
                            measured: crate::geometry::isqrt(d2),
                            limit: i64::from(limit_dbu), x: mx, y: my,
                            hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                        });
                    }
                }
            }
            Ok(violations)
        }
        ProductionRuleSchema::Enclosure { id, outer, inner, limit, .. } => {
            let outer_set = evaluate_source(outer, layers, evaluator)?;
            let inner_set = evaluate_source(inner, layers, evaluator)?;
            let limit_dbu = positive_i32(evaluate_expression(limit, deck)?.value, "limit")?;
            let mut violations = Vec::new();
            // ponytail: bbox-based enclosure — measures min edge distance
            // from inner bbox edges to nearest outer bbox edges. Exact for
            // rectilinear; upgrade to edge-walk if 45° enclosure matters.
            for inner_poly in inner_set.polygons() {
                let ib = poly_bbox_exact(inner_poly);
                let mut best_enc = i64::MAX;
                let mut best_outer: Option<(i32, i32, i32, i32)> = None;
                for outer_poly in outer_set.polygons() {
                    let ob = poly_bbox_exact(outer_poly);
                    // inner must be inside outer's bbox
                    if ib.0 >= ob.0 && ib.1 >= ob.1 && ib.2 <= ob.2 && ib.3 <= ob.3 {
                        let enc = [
                            i64::from(ib.0) - i64::from(ob.0),
                            i64::from(ib.1) - i64::from(ob.1),
                            i64::from(ob.2) - i64::from(ib.2),
                            i64::from(ob.3) - i64::from(ib.3),
                        ].into_iter().min().unwrap();
                        if enc < best_enc {
                            best_enc = enc;
                            best_outer = Some(ob);
                        }
                    }
                }
                if best_enc < i64::from(limit_dbu) {
                    let point = inner_poly.outer().vertices()[0];
                    violations.push(Violation {
                        rule_id: id.clone(), kind: "enclosure".into(),
                        layer: source_name(inner),
                        measured: best_enc,
                        limit: i64::from(limit_dbu), x: point.x, y: point.y,
                        hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                    });
                } else if best_outer.is_none() && !inner_set.polygons().is_empty() {
                    // Inner not inside any outer — treat as zero enclosure
                    let point = inner_poly.outer().vertices()[0];
                    violations.push(Violation {
                        rule_id: id.clone(), kind: "enclosure".into(),
                        layer: source_name(inner),
                        measured: 0,
                        limit: i64::from(limit_dbu), x: point.x, y: point.y,
                        hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                    });
                }
            }
            Ok(violations)
        }
        ProductionRuleSchema::Extension { id, layer, reference, limit, .. } => {
            let layer_set = evaluate_source(layer, layers, evaluator)?;
            let ref_set = evaluate_source(reference, layers, evaluator)?;
            let limit_dbu = positive_i32(evaluate_expression(limit, deck)?.value, "limit")?;
            let mut violations = Vec::new();
            // ponytail: bbox-based extension — measures how far layer extends
            // beyond reference on each side. Exact for rectilinear; upgrade to
            // edge-walk for 45°.
            for layer_poly in layer_set.polygons() {
                let lb = poly_bbox_exact(layer_poly);
                for ref_poly in ref_set.polygons() {
                    let rb = poly_bbox_exact(ref_poly);
                    // Check overlap on at least one axis
                    let x_overlap = lb.2 > rb.0 && lb.0 < rb.2;
                    let y_overlap = lb.3 > rb.1 && lb.1 < rb.3;
                    if !x_overlap && !y_overlap { continue; }
                    // Measure extension on each side where layer extends beyond ref
                    let extensions = [
                        i64::from(rb.0) - i64::from(lb.0), // layer left of ref
                        i64::from(rb.1) - i64::from(lb.1), // layer below ref
                        i64::from(lb.2) - i64::from(rb.2), // layer right of ref
                        i64::from(lb.3) - i64::from(rb.3), // layer above ref
                    ];
                    for ext in extensions {
                        if ext > 0 && ext < i64::from(limit_dbu) {
                            let point = layer_poly.outer().vertices()[0];
                            violations.push(Violation {
                                rule_id: id.clone(), kind: "extension".into(),
                                layer: source_name(layer),
                                measured: ext,
                                limit: i64::from(limit_dbu), x: point.x, y: point.y,
                                hierarchy_path: None, source_polygons: Vec::new(), marker: None,
                            });
                        }
                    }
                }
            }
            Ok(violations)
        }
        // ponytail: remaining variants need specialized kernels (PRL, EOL,
        // coloring, antenna, etc.) not yet in the exact path. Unsupported
        // until migrated; upgrade path: one variant per PR.
        ProductionRuleSchema::PrlSpacing { .. }
        | ProductionRuleSchema::EolSpacing { .. }
        | ProductionRuleSchema::CutClass { .. }
        | ProductionRuleSchema::Antenna { .. }
        | ProductionRuleSchema::MultiPatterning { .. }
        | ProductionRuleSchema::MinEdgeLength { .. }
        | ProductionRuleSchema::OffGrid { .. }
        | ProductionRuleSchema::Angle { .. }
        | ProductionRuleSchema::Overlap { .. }
        | ProductionRuleSchema::CornerToCorner { .. }
        | ProductionRuleSchema::WideDependentSpacing { .. }
        | ProductionRuleSchema::AsymmetricEnclosure { .. }
        | ProductionRuleSchema::RedundantVia { .. }
        | ProductionRuleSchema::ViaArraySpacing { .. }
        | ProductionRuleSchema::MaxDistanceToTap { .. }
        | ProductionRuleSchema::AntennaCar { .. }
        | ProductionRuleSchema::SpacingDiff { .. } => Err(RunError::Unsupported(
            "rule is schema-valid but its legacy private geometry kernel has not yet migrated to exact production execution".into(),
        )),
    }
}

fn exact_density(
    id: &str,
    layer: &LayerSourceSchema,
    material: &PolygonSet,
    region: &PolygonSet,
    window: i32,
    step: i32,
    min: Option<f64>,
    max: Option<f64>,
) -> Result<Vec<Violation>, RunError> {
    let Some((xmin, ymin, xmax, ymax)) = set_bbox(region) else {
        return Err(RunError::Expression("density region is empty".into()));
    };
    super::density_window_work(xmin, ymin, xmax, ymax, window, step)?;
    let mut violations = Vec::new();
    let window = i64::from(window);
    let step = i64::from(step);
    let xmax = i64::from(xmax);
    let ymax = i64::from(ymax);
    let mut y = i64::from(ymin);
    loop {
        let mut x = i64::from(xmin);
        loop {
            let x1 = x
                .checked_add(window)
                .ok_or(gdsverify_core::exact::ExactGeometryError::ArithmeticOverflow)?
                .min(xmax);
            let y1 = y
                .checked_add(window)
                .ok_or(gdsverify_core::exact::ExactGeometryError::ArithmeticOverflow)?
                .min(ymax);
            let (x0, y0, x1, y1) = (
                i32::try_from(x).map_err(|_| RunError::Expression("window x overflow".into()))?,
                i32::try_from(y).map_err(|_| RunError::Expression("window y overflow".into()))?,
                i32::try_from(x1).map_err(|_| RunError::Expression("window x overflow".into()))?,
                i32::try_from(y1).map_err(|_| RunError::Expression("window y overflow".into()))?,
            );
            let window_set = rectangle(x0, y0, x1, y1)?;
            let scoped_window = rectilinear_intersection(region, &window_set)?;
            let denominator = scoped_window.area2() as f64 / 2.0;
            if denominator > 0.0 {
                let covered =
                    rectilinear_intersection(material, &scoped_window)?.area2() as f64 / 2.0;
                let fraction = covered / denominator;
                let bad_limit = min
                    .filter(|limit| fraction < *limit)
                    .map(|limit| ("min_density", limit))
                    .or_else(|| {
                        max.filter(|limit| fraction > *limit)
                            .map(|limit| ("max_density", limit))
                    });
                if let Some((kind, limit)) = bad_limit {
                    violations.push(Violation {
                        rule_id: id.into(),
                        kind: kind.into(),
                        layer: source_name(layer),
                        measured: saturating_i64(fraction * 1_000_000.0),
                        limit: saturating_i64(limit * 1_000_000.0),
                        x: x0,
                        y: y0,
                        hierarchy_path: None,
                        source_polygons: Vec::new(),
                        marker: None,
                    });
                }
            }
            if i64::from(x1) == xmax {
                break;
            }
            x = x
                .checked_add(step)
                .ok_or_else(|| RunError::Expression("density step overflow".into()))?;
            if x >= xmax {
                break;
            }
        }
        if y.checked_add(window)
            .ok_or(gdsverify_core::exact::ExactGeometryError::ArithmeticOverflow)?
            >= ymax
        {
            break;
        }
        y = y
            .checked_add(step)
            .ok_or_else(|| RunError::Expression("density step overflow".into()))?;
        if y >= ymax {
            break;
        }
    }
    Ok(violations)
}

fn evaluate_source(
    source: &LayerSourceSchema,
    layers: &LayerTable,
    evaluator: &mut DerivedEvaluator<'_>,
) -> Result<PolygonSet, RunError> {
    let value = match source {
        LayerSourceSchema::Base { name: layer } => {
            let layer = layers
                .id(layer)
                .ok_or_else(|| RunError::Expression(format!("unknown layer `{layer}`")))?;
            evaluator.evaluate(&DerivedExpr::Layer {
                layer: LayerExprRef::Base { layer },
            })?
        }
        LayerSourceSchema::Derived { name } => evaluator.evaluate_named(name)?,
    };
    match value {
        DerivedValue::Area(set) => Ok(set),
        DerivedValue::Edges(_) => Err(RunError::Unsupported(
            "area rule received an edge layer".into(),
        )),
    }
}

fn check_context(
    id: &str,
    selector: &ContextSelector,
    context: &DrcContext,
) -> Option<CheckedRuleResult> {
    let missing = if selector.net_relation.is_some() && context.poly_nets.is_none() {
        Some("polygon-to-net attribution")
    } else if selector.min_voltage_difference.is_some() && context.net_voltages.is_none() {
        Some("net voltage evidence")
    } else if selector.domains.is_some() && context.net_domains.is_none() {
        Some("net domain evidence")
    } else if selector.cells.is_some() && context.poly_cells.is_none() {
        Some("cell-name attribution")
    } else if selector.hierarchy_prefix.is_some() && context.hierarchy_paths.is_none() {
        Some("hierarchy paths")
    } else if selector.process.is_some() && context.process.is_none() {
        Some("process identity")
    } else if selector.corner.is_some() && context.corner.is_none() {
        Some("corner identity")
    } else if selector
        .region
        .as_ref()
        .is_some_and(|name| !context.regions.contains_key(name))
    {
        Some("named region geometry")
    } else {
        None
    };
    if let Some(evidence) = missing {
        return Some(CheckedRuleResult {
            rule_id: id.into(),
            status: RuleStatus::Error,
            violations: Vec::new(),
            diagnostics: vec![RuleDiagnostic {
                code: DiagnosticCode::MissingContext,
                message: format!("rule requires missing {evidence}"),
            }],
        });
    }
    if selector.net_relation.is_some()
        || selector.min_voltage_difference.is_some()
        || selector.domains.is_some()
        || selector.region.is_some()
        || selector.cells.is_some()
        || selector.hierarchy_prefix.is_some()
    {
        return Some(CheckedRuleResult {
            rule_id: id.into(),
            status: RuleStatus::Error,
            violations: Vec::new(),
            diagnostics: vec![RuleDiagnostic {
                code: DiagnosticCode::Unsupported,
                message: "required per-object context is present but contextual geometry filtering is not implemented".into(),
            }],
        });
    }
    let not_applicable = selector
        .process
        .as_ref()
        .is_some_and(|expected| context.process.as_ref() != Some(expected))
        || selector
            .corner
            .as_ref()
            .is_some_and(|expected| context.corner.as_ref() != Some(expected));
    not_applicable.then(|| CheckedRuleResult {
        rule_id: id.into(),
        status: RuleStatus::NotRun,
        violations: Vec::new(),
        diagnostics: vec![RuleDiagnostic {
            code: DiagnosticCode::ContextNotApplicable,
            message: "rule selector does not apply to the active process/corner".into(),
        }],
    })
}

fn evaluate_expression(
    expression: &ScalarExpr,
    deck: &ProductionDeck,
) -> Result<Quantity, RunError> {
    let mut stack = Vec::new();
    eval(
        expression,
        &deck.schema.variables,
        &deck.schema.tables,
        deck.schema.dbu_nm,
        &mut stack,
    )
    .map_err(RunError::Expression)
}

fn eval(
    expression: &ScalarExpr,
    variables: &BTreeMap<String, ScalarExpr>,
    tables: &BTreeMap<String, LookupTable>,
    dbu_nm: f64,
    stack: &mut Vec<String>,
) -> Result<Quantity, String> {
    use ScalarExpr::*;
    match expression {
        Literal { value, unit } => normalize(*value, *unit, dbu_nm),
        Variable { name } => {
            if stack.contains(name) {
                return Err(format!("variable cycle: {} -> {name}", stack.join(" -> ")));
            }
            let expression = variables
                .get(name)
                .ok_or_else(|| format!("unknown variable `{name}`"))?;
            stack.push(name.clone());
            let result = eval(expression, variables, tables, dbu_nm, stack);
            stack.pop();
            result
        }
        Add { lhs, rhs } | Subtract { lhs, rhs } => {
            let lhs = eval(lhs, variables, tables, dbu_nm, stack)?;
            let rhs = eval(rhs, variables, tables, dbu_nm, stack)?;
            if lhs.dimension != rhs.dimension {
                return Err("add/subtract operands have different dimensions".into());
            }
            let value = if matches!(expression, Add { .. }) {
                lhs.value + rhs.value
            } else {
                lhs.value - rhs.value
            };
            finite_quantity(value, lhs.dimension)
        }
        Multiply { lhs, rhs } => {
            let lhs = eval(lhs, variables, tables, dbu_nm, stack)?;
            let rhs = eval(rhs, variables, tables, dbu_nm, stack)?;
            let dimension = match (lhs.dimension, rhs.dimension) {
                (Dimension::Ratio, dimension) | (dimension, Dimension::Ratio) => dimension,
                (Dimension::Length, Dimension::Length) => Dimension::Area,
                _ => return Err("unsupported dimensional multiplication".into()),
            };
            finite_quantity(lhs.value * rhs.value, dimension)
        }
        Divide { lhs, rhs } => {
            let lhs = eval(lhs, variables, tables, dbu_nm, stack)?;
            let rhs = eval(rhs, variables, tables, dbu_nm, stack)?;
            if rhs.value == 0.0 {
                return Err("division by zero".into());
            }
            let dimension = if lhs.dimension == rhs.dimension {
                Dimension::Ratio
            } else if rhs.dimension == Dimension::Ratio {
                lhs.dimension
            } else {
                return Err("unsupported dimensional division".into());
            };
            finite_quantity(lhs.value / rhs.value, dimension)
        }
        Lookup { table, input } => {
            let table = tables
                .get(table)
                .ok_or_else(|| format!("unknown lookup table `{table}`"))?;
            let input = eval(input, variables, tables, dbu_nm, stack)?;
            if input.dimension != table.input_unit.dimension() {
                return Err("lookup input has wrong dimension".into());
            }
            let raw_input = denormalize(input.value, table.input_unit, dbu_nm)?;
            let output = table_lookup(table, raw_input)?;
            normalize(output, table.output_unit, dbu_nm)
        }
        // ponytail: Conditional eval always evaluates both branches at validation
        // time; runtime would short-circuit, but we have no runtime context here.
        Conditional {
            then_expr,
            else_expr,
            ..
        } => {
            let then_val = eval(then_expr, variables, tables, dbu_nm, stack)?;
            let else_val = eval(else_expr, variables, tables, dbu_nm, stack)?;
            if then_val.dimension != else_val.dimension {
                return Err("conditional branches have different dimensions".into());
            }
            // ponytail: without runtime context, return then_expr as default
            Ok(then_val)
        }
        Min { lhs, rhs } => {
            let lhs = eval(lhs, variables, tables, dbu_nm, stack)?;
            let rhs = eval(rhs, variables, tables, dbu_nm, stack)?;
            if lhs.dimension != rhs.dimension {
                return Err("min operands have different dimensions".into());
            }
            finite_quantity(lhs.value.min(rhs.value), lhs.dimension)
        }
        Max { lhs, rhs } => {
            let lhs = eval(lhs, variables, tables, dbu_nm, stack)?;
            let rhs = eval(rhs, variables, tables, dbu_nm, stack)?;
            if lhs.dimension != rhs.dimension {
                return Err("max operands have different dimensions".into());
            }
            finite_quantity(lhs.value.max(rhs.value), lhs.dimension)
        }
    }
}

fn validate_tables(tables: &BTreeMap<String, LookupTable>, dbu_nm: f64) -> Result<(), DeckError> {
    for (name, table) in tables {
        if name.trim().is_empty() || table.points.is_empty() {
            return Err(DeckError::Schema(format!("lookup table `{name}` is empty")));
        }
        let mut previous = f64::NEG_INFINITY;
        for point in &table.points {
            if !point.input.is_finite() || !point.output.is_finite() || point.input <= previous {
                return Err(DeckError::Schema(format!(
                    "lookup table `{name}` points must be finite with strictly increasing input"
                )));
            }
            previous = point.input;
        }
        normalize(table.points[0].input, table.input_unit, dbu_nm).map_err(DeckError::Schema)?;
        normalize(table.points[0].output, table.output_unit, dbu_nm).map_err(DeckError::Schema)?;
    }
    Ok(())
}

fn validate_variables(
    variables: &BTreeMap<String, ScalarExpr>,
    tables: &BTreeMap<String, LookupTable>,
    dbu_nm: f64,
) -> Result<(), DeckError> {
    for (name, expression) in variables {
        if name.trim().is_empty() {
            return Err(DeckError::Schema("variable name must not be empty".into()));
        }
        eval(
            expression,
            variables,
            tables,
            dbu_nm,
            &mut vec![name.clone()],
        )
        .map_err(DeckError::Schema)?;
    }
    Ok(())
}

fn validate_rule(
    rule: &ProductionRuleSchema,
    schema: &ProductionDeckSchema,
    layers: &LayerTable,
) -> Result<(), DeckError> {
    let expected: &[(ScalarExpr, Dimension)] = match rule {
        ProductionRuleSchema::MinWidth { limit, .. }
        | ProductionRuleSchema::Spacing { limit, .. }
        | ProductionRuleSchema::Enclosure { limit, .. }
        | ProductionRuleSchema::Extension { limit, .. } => &[(limit.clone(), Dimension::Length)],
        ProductionRuleSchema::PrlSpacing {
            parallel_run_length,
            limit,
            ..
        } => &[
            (parallel_run_length.clone(), Dimension::Length),
            (limit.clone(), Dimension::Length),
        ],
        ProductionRuleSchema::EolSpacing {
            eol_width,
            within,
            limit,
            ..
        } => &[
            (eol_width.clone(), Dimension::Length),
            (within.clone(), Dimension::Length),
            (limit.clone(), Dimension::Length),
        ],
        ProductionRuleSchema::MinArea { limit, .. }
        | ProductionRuleSchema::MinEnclosedArea { limit, .. } => {
            &[(limit.clone(), Dimension::Area)]
        }
        ProductionRuleSchema::Cheesing {
            max_area_without_slot,
            ..
        } => &[(max_area_without_slot.clone(), Dimension::Area)],
        ProductionRuleSchema::CutClass {
            min_count,
            within,
            redundancy,
            ..
        } => {
            let mut values = vec![
                (min_count.clone(), Dimension::Count),
                (within.clone(), Dimension::Length),
            ];
            if let Some(redundancy) = redundancy {
                values.push((redundancy.clone(), Dimension::Count));
            }
            validate_rule_values(rule, &values, schema, layers)?;
            for (field, expression) in std::iter::once(("min_count", min_count))
                .chain(redundancy.iter().map(|value| ("redundancy", value)))
            {
                let value = rule_quantity(rule.id(), expression, schema)?.value;
                if value.fract() != 0.0 {
                    return Err(DeckError::Rule {
                        id: rule.id().into(),
                        message: format!("{field} must resolve to an integer count"),
                    });
                }
            }
            return Ok(());
        }
        ProductionRuleSchema::Density {
            window,
            step,
            min,
            max,
            ..
        } => {
            if min.is_none() && max.is_none() {
                return Err(DeckError::Rule {
                    id: rule.id().into(),
                    message: "density needs min and/or max".into(),
                });
            }
            let values = vec![
                (window.clone(), Dimension::Length),
                (step.clone(), Dimension::Length),
            ];
            validate_rule_values(rule, &values, schema, layers)?;
            let window_value = rule_quantity(rule.id(), window, schema)?.value;
            let step_value = rule_quantity(rule.id(), step, schema)?.value;
            if window_value.fract() != 0.0 || step_value.fract() != 0.0 || step_value > window_value
            {
                return Err(DeckError::Rule {
                    id: rule.id().into(),
                    message: "density window/step must be integer DBU and step <= window".into(),
                });
            }
            let min_value = min
                .as_ref()
                .map(|value| rule_quantity(rule.id(), value, schema))
                .transpose()?;
            let max_value = max
                .as_ref()
                .map(|value| rule_quantity(rule.id(), value, schema))
                .transpose()?;
            for (field, value) in [("min", min_value), ("max", max_value)] {
                if let Some(value) = value {
                    if value.dimension != Dimension::Ratio || !(0.0..=1.0).contains(&value.value) {
                        return Err(DeckError::Rule {
                            id: rule.id().into(),
                            message: format!("{field} density must be a ratio in [0, 1]"),
                        });
                    }
                }
            }
            if min_value
                .zip(max_value)
                .is_some_and(|(min, max)| min.value > max.value)
            {
                return Err(DeckError::Rule {
                    id: rule.id().into(),
                    message: "density limits must satisfy min <= max".into(),
                });
            }
            return Ok(());
        }
        ProductionRuleSchema::Antenna {
            ratio_limit,
            fabrication_stage,
            ..
        } => {
            if *fabrication_stage == 0 {
                return Err(DeckError::Rule {
                    id: rule.id().into(),
                    message: "fabrication_stage must be positive".into(),
                });
            }
            &[(ratio_limit.clone(), Dimension::Ratio)]
        }
        ProductionRuleSchema::MultiPatterning {
            colors,
            spacing,
            max_search_states,
            ..
        } => {
            if max_search_states == &Some(0) {
                return Err(DeckError::Rule {
                    id: rule.id().into(),
                    message: "max_search_states must be positive".into(),
                });
            }
            let values = [
                (colors.clone(), Dimension::Count),
                (spacing.clone(), Dimension::Length),
            ];
            validate_rule_values(rule, &values, schema, layers)?;
            let colors = rule_quantity(rule.id(), colors, schema)?.value;
            if colors.fract() != 0.0 || !(2.0..=64.0).contains(&colors) {
                return Err(DeckError::Rule {
                    id: rule.id().into(),
                    message: "colors must resolve to an integer in [2, 64]".into(),
                });
            }
            return Ok(());
        }
        // ponytail: legacy-parity variants — validate expressions, defer execution
        ProductionRuleSchema::MaxWidth { limit, .. }
        | ProductionRuleSchema::Notch { limit, .. }
        | ProductionRuleSchema::MinEdgeLength { limit, .. }
        | ProductionRuleSchema::CornerToCorner { limit, .. } => {
            &[(limit.clone(), Dimension::Length)]
        }
        ProductionRuleSchema::OffGrid { grid, .. } => &[(grid.clone(), Dimension::Length)],
        ProductionRuleSchema::Angle { allowed, .. } => {
            if allowed.is_empty() {
                return Err(DeckError::Rule {
                    id: rule.id().into(),
                    message: "allowed angles must not be empty".into(),
                });
            }
            validate_rule_values(rule, &[], schema, layers)?;
            return Ok(());
        }
        ProductionRuleSchema::Overlap { limit, .. }
        | ProductionRuleSchema::SpacingDiff { limit, .. } => &[(limit.clone(), Dimension::Length)],
        ProductionRuleSchema::WideDependentSpacing {
            width_threshold,
            wide_spacing,
            ..
        } => &[
            (width_threshold.clone(), Dimension::Length),
            (wide_spacing.clone(), Dimension::Length),
        ],
        ProductionRuleSchema::AsymmetricEnclosure { min_one_side, .. } => {
            &[(min_one_side.clone(), Dimension::Length)]
        }
        ProductionRuleSchema::RedundantVia {
            min_count, within, ..
        } => {
            let values = vec![
                (min_count.clone(), Dimension::Count),
                (within.clone(), Dimension::Length),
            ];
            validate_rule_values(rule, &values, schema, layers)?;
            return Ok(());
        }
        ProductionRuleSchema::ViaArraySpacing {
            array_threshold,
            array_spacing,
            ..
        } => {
            let values = vec![
                (array_threshold.clone(), Dimension::Count),
                (array_spacing.clone(), Dimension::Length),
            ];
            validate_rule_values(rule, &values, schema, layers)?;
            return Ok(());
        }
        ProductionRuleSchema::MaxDistanceToTap { max_dist, .. } => {
            &[(max_dist.clone(), Dimension::Length)]
        }
        ProductionRuleSchema::AntennaCar { ratio_limit, .. } => {
            &[(ratio_limit.clone(), Dimension::Ratio)]
        }
    };
    validate_rule_values(rule, expected, schema, layers)
}

fn rule_quantity(
    id: &str,
    expression: &ScalarExpr,
    schema: &ProductionDeckSchema,
) -> Result<Quantity, DeckError> {
    eval(
        expression,
        &schema.variables,
        &schema.tables,
        schema.dbu_nm,
        &mut Vec::new(),
    )
    .map_err(|message| DeckError::Rule {
        id: id.into(),
        message,
    })
}

fn validate_rule_values(
    rule: &ProductionRuleSchema,
    expected: &[(ScalarExpr, Dimension)],
    schema: &ProductionDeckSchema,
    layers: &LayerTable,
) -> Result<(), DeckError> {
    for source in rule_sources(rule) {
        resolve_source(source, layers, &schema.derived_layers)?;
    }
    for (expression, dimension) in expected {
        let quantity = eval(
            expression,
            &schema.variables,
            &schema.tables,
            schema.dbu_nm,
            &mut Vec::new(),
        )
        .map_err(|message| DeckError::Rule {
            id: rule.id().into(),
            message,
        })?;
        if quantity.dimension != *dimension || !quantity.value.is_finite() || quantity.value <= 0.0
        {
            return Err(DeckError::Rule {
                id: rule.id().into(),
                message: format!("expected positive {dimension:?}, got {quantity:?}"),
            });
        }
    }
    if let Some(expr) = &rule.selector().min_voltage_difference {
        let value = eval(
            expr,
            &schema.variables,
            &schema.tables,
            schema.dbu_nm,
            &mut Vec::new(),
        )
        .map_err(|message| DeckError::Rule {
            id: rule.id().into(),
            message,
        })?;
        if value.dimension != Dimension::Voltage || value.value < 0.0 {
            return Err(DeckError::Rule {
                id: rule.id().into(),
                message: "min_voltage_difference must be non-negative volts".into(),
            });
        }
    }
    Ok(())
}

fn rule_sources(rule: &ProductionRuleSchema) -> Vec<&LayerSourceSchema> {
    match rule {
        ProductionRuleSchema::MinWidth { layer, .. }
        | ProductionRuleSchema::PrlSpacing { layer, .. }
        | ProductionRuleSchema::EolSpacing { layer, .. }
        | ProductionRuleSchema::MinArea { layer, .. }
        | ProductionRuleSchema::MinEnclosedArea { layer, .. }
        | ProductionRuleSchema::MultiPatterning { layer, .. }
        | ProductionRuleSchema::MaxWidth { layer, .. }
        | ProductionRuleSchema::Notch { layer, .. }
        | ProductionRuleSchema::MinEdgeLength { layer, .. }
        | ProductionRuleSchema::CornerToCorner { layer, .. }
        | ProductionRuleSchema::ViaArraySpacing { layer, .. } => vec![layer],
        ProductionRuleSchema::Spacing { layer, other, .. } => {
            std::iter::once(layer).chain(other.iter()).collect()
        }
        ProductionRuleSchema::Enclosure { outer, inner, .. }
        | ProductionRuleSchema::AsymmetricEnclosure { outer, inner, .. } => vec![outer, inner],
        ProductionRuleSchema::Cheesing { layer, slots, .. } => vec![layer, slots],
        ProductionRuleSchema::Extension {
            layer, reference, ..
        } => vec![layer, reference],
        ProductionRuleSchema::CutClass { cut, .. }
        | ProductionRuleSchema::RedundantVia { cut, .. } => vec![cut],
        ProductionRuleSchema::Density {
            layer,
            region,
            exclusion,
            ..
        } => std::iter::once(layer)
            .chain(std::iter::once(region))
            .chain(exclusion.iter())
            .collect(),
        ProductionRuleSchema::Antenna {
            conductor,
            gate,
            diode,
            ..
        } => std::iter::once(conductor)
            .chain(std::iter::once(gate))
            .chain(diode.iter())
            .collect(),
        ProductionRuleSchema::Overlap { a, b, .. }
        | ProductionRuleSchema::SpacingDiff { a, b, .. } => vec![a, b],
        ProductionRuleSchema::WideDependentSpacing { layer, .. } => vec![layer],
        ProductionRuleSchema::MaxDistanceToTap {
            diff_layer,
            tap_layer,
            ..
        } => vec![diff_layer, tap_layer],
        ProductionRuleSchema::AntennaCar { layers, diode, .. } => {
            layers.iter().chain(diode.iter()).collect()
        }
        // No layers to resolve
        ProductionRuleSchema::OffGrid { .. } | ProductionRuleSchema::Angle { .. } => vec![],
    }
}

fn resolve_source(
    source: &LayerSourceSchema,
    layers: &LayerTable,
    derived: &BTreeMap<String, DerivedLayerSchema>,
) -> Result<ResolvedLayerSource, DeckError> {
    match source {
        LayerSourceSchema::Base { name } => layers
            .id(name)
            .map(ResolvedLayerSource::Base)
            .ok_or_else(|| DeckError::Schema(format!("unknown base layer `{name}`"))),
        LayerSourceSchema::Derived { name } => derived
            .contains_key(name)
            .then(|| ResolvedLayerSource::Derived(name.clone()))
            .ok_or_else(|| DeckError::Schema(format!("unknown derived layer `{name}`"))),
    }
}

fn resolve_derived(
    expression: &DerivedLayerSchema,
    layers: &LayerTable,
    definitions: &BTreeMap<String, DerivedLayerSchema>,
) -> Result<DerivedExpr, DeckError> {
    use DerivedLayerSchema::*;
    let recur =
        |expr: &DerivedLayerSchema| resolve_derived(expr, layers, definitions).map(Box::new);
    Ok(match expression {
        Layer { source } => DerivedExpr::Layer {
            layer: match resolve_source(source, layers, definitions)? {
                ResolvedLayerSource::Base(layer) => LayerExprRef::Base { layer },
                ResolvedLayerSource::Derived(name) => LayerExprRef::Derived { name },
            },
        },
        Union { operands } => DerivedExpr::Union {
            operands: operands
                .iter()
                .map(|expr| resolve_derived(expr, layers, definitions))
                .collect::<Result<_, _>>()?,
        },
        Intersection { lhs, rhs } => DerivedExpr::Intersection {
            lhs: recur(lhs)?,
            rhs: recur(rhs)?,
        },
        Subtraction { lhs, rhs } => DerivedExpr::Subtraction {
            lhs: recur(lhs)?,
            rhs: recur(rhs)?,
        },
        Xor { lhs, rhs } => DerivedExpr::Xor {
            lhs: recur(lhs)?,
            rhs: recur(rhs)?,
        },
        NotWithin { region, operand } => DerivedExpr::NotWithin {
            region: recur(region)?,
            operand: recur(operand)?,
        },
        Grow { operand, distance } => DerivedExpr::Grow {
            operand: recur(operand)?,
            distance: *distance,
        },
        Shrink { operand, distance } => DerivedExpr::Shrink {
            operand: recur(operand)?,
            distance: *distance,
        },
        Inside { operand, region } => DerivedExpr::Inside {
            operand: recur(operand)?,
            region: recur(region)?,
        },
        Outside { operand, region } => DerivedExpr::Outside {
            operand: recur(operand)?,
            region: recur(region)?,
        },
        Interacting { operand, other } => DerivedExpr::Interacting {
            operand: recur(operand)?,
            other: recur(other)?,
        },
    })
}

fn validate_derived_references(
    expression: &DerivedExpr,
    definitions: &BTreeMap<String, DerivedExpr>,
) -> Result<(), DeckError> {
    fn visit(
        expression: &DerivedExpr,
        definitions: &BTreeMap<String, DerivedExpr>,
        visiting: &mut Vec<String>,
    ) -> Result<(), DeckError> {
        use DerivedExpr::*;
        match expression {
            Layer {
                layer: LayerExprRef::Derived { name },
            } => {
                if visiting.contains(name) {
                    return Err(DeckError::Schema(format!(
                        "derived-layer cycle: {} -> {name}",
                        visiting.join(" -> ")
                    )));
                }
                let target = definitions
                    .get(name)
                    .ok_or_else(|| DeckError::Schema(format!("unknown derived layer `{name}`")))?;
                visiting.push(name.clone());
                visit(target, definitions, visiting)?;
                visiting.pop();
            }
            Layer { .. } => {}
            Union { operands } => {
                for operand in operands {
                    visit(operand, definitions, visiting)?;
                }
            }
            Intersection { lhs, rhs } | Subtraction { lhs, rhs } | Xor { lhs, rhs } => {
                visit(lhs, definitions, visiting)?;
                visit(rhs, definitions, visiting)?;
            }
            NotWithin { region, operand }
            | Inside { operand, region }
            | Outside { operand, region } => {
                visit(region, definitions, visiting)?;
                visit(operand, definitions, visiting)?;
            }
            Grow { operand, .. }
            | Shrink { operand, .. }
            | Edges { operand, .. }
            | SizeByExpr { operand, .. } => visit(operand, definitions, visiting)?,
            Interacting { operand, other } => {
                visit(operand, definitions, visiting)?;
                visit(other, definitions, visiting)?;
            }
        }
        Ok(())
    }
    visit(expression, definitions, &mut Vec::new())
}

fn normalize(value: f64, unit: Unit, dbu_nm: f64) -> Result<Quantity, String> {
    if !value.is_finite() {
        return Err("quantity must be finite".into());
    }
    let value = match unit {
        Unit::Dbu | Unit::Ratio | Unit::Count | Unit::Volt => value,
        Unit::Nanometer => value / dbu_nm,
        Unit::SquareDbu => value,
        Unit::SquareNanometer => value / (dbu_nm * dbu_nm),
    };
    finite_quantity(value, unit.dimension())
}

fn denormalize(value: f64, unit: Unit, dbu_nm: f64) -> Result<f64, String> {
    let value = match unit {
        Unit::Dbu | Unit::Ratio | Unit::Count | Unit::Volt | Unit::SquareDbu => value,
        Unit::Nanometer => value * dbu_nm,
        Unit::SquareNanometer => value * dbu_nm * dbu_nm,
    };
    value
        .is_finite()
        .then_some(value)
        .ok_or_else(|| "quantity conversion overflow".into())
}

fn finite_quantity(value: f64, dimension: Dimension) -> Result<Quantity, String> {
    value
        .is_finite()
        .then_some(Quantity { value, dimension })
        .ok_or_else(|| "expression is not finite".into())
}

fn table_lookup(table: &LookupTable, input: f64) -> Result<f64, String> {
    if input <= table.points[0].input {
        return Ok(table.points[0].output);
    }
    for pair in table.points.windows(2) {
        if input <= pair[1].input {
            if !table.interpolate {
                return Ok(pair[0].output);
            }
            let fraction = (input - pair[0].input) / (pair[1].input - pair[0].input);
            return Ok(pair[0].output + fraction * (pair[1].output - pair[0].output));
        }
    }
    Ok(table.points.last().unwrap().output)
}

fn positive_i32(value: f64, field: &str) -> Result<i32, RunError> {
    if !value.is_finite() || value <= 0.0 || value.fract() != 0.0 || value > f64::from(i32::MAX) {
        return Err(RunError::Expression(format!(
            "{field} must resolve to a positive integer DBU value"
        )));
    }
    Ok(value as i32)
}

fn rectangle(x0: i32, y0: i32, x1: i32, y1: i32) -> Result<PolygonSet, RunError> {
    Ok(PolygonSet::from_polygon(Polygon::from_outer(vec![
        Point::new(x0, y0),
        Point::new(x1, y0),
        Point::new(x1, y1),
        Point::new(x0, y1),
    ])?))
}

fn set_bbox(set: &PolygonSet) -> Option<(i32, i32, i32, i32)> {
    let mut bbox = (i32::MAX, i32::MAX, i32::MIN, i32::MIN);
    let mut any = false;
    for polygon in set.polygons() {
        for point in polygon.outer().vertices() {
            any = true;
            bbox.0 = bbox.0.min(point.x);
            bbox.1 = bbox.1.min(point.y);
            bbox.2 = bbox.2.max(point.x);
            bbox.3 = bbox.3.max(point.y);
        }
    }
    any.then_some(bbox)
}

fn source_name(source: &LayerSourceSchema) -> String {
    match source {
        LayerSourceSchema::Base { name } => name.clone(),
        LayerSourceSchema::Derived { name } => format!("derived:{name}"),
    }
}

fn saturating_i64(value: f64) -> i64 {
    value.round().clamp(i64::MIN as f64, i64::MAX as f64) as i64
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeckError {
    Schema(String),
    Rule { id: String, message: String },
}

impl fmt::Display for DeckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(message) => write!(f, "production DRC deck: {message}"),
            Self::Rule { id, message } => write!(f, "production DRC rule `{id}`: {message}"),
        }
    }
}

impl std::error::Error for DeckError {}

#[derive(Clone, Debug)]
enum RunError {
    Unsupported(String),
    Derived(DerivedError),
    Expression(String),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(message) => write!(f, "unsupported: {message}"),
            Self::Derived(error) => write!(f, "derived geometry: {error}"),
            Self::Expression(message) => write!(f, "model expression: {message}"),
        }
    }
}

impl From<DerivedError> for RunError {
    fn from(value: DerivedError) -> Self {
        Self::Derived(value)
    }
}

impl From<gdsverify_core::exact::ExactGeometryError> for RunError {
    fn from(value: gdsverify_core::exact::ExactGeometryError) -> Self {
        Self::Derived(DerivedError::Geometry(value))
    }
}

/// Load a PolygonSet's outer rings into a throwaway GeometryStore so the
/// existing SoA-based helpers (facing_gaps, candidate_pairs, poly_poly_dist2)
/// can operate on derived-layer geometry.
// ponytail: holes are dropped — width/spacing operate on merged outer boundaries.
// If hole-aware measurements matter, upgrade to an edge-walk kernel.
fn polygonset_to_store(set: &PolygonSet) -> GeometryStore {
    let mut store = GeometryStore::new();
    for polygon in set.polygons() {
        let pts: Vec<(i32, i32)> = polygon
            .outer()
            .vertices()
            .iter()
            .map(|v| (v.x, v.y))
            .collect();
        store.add_polygon(0, &pts);
    }
    store
}

/// Bounding box of an exact polygon as (xmin, ymin, xmax, ymax).
fn poly_bbox_exact(polygon: &Polygon) -> (i32, i32, i32, i32) {
    let mut xmin = i32::MAX;
    let mut ymin = i32::MAX;
    let mut xmax = i32::MIN;
    let mut ymax = i32::MIN;
    for v in polygon.outer().vertices() {
        xmin = xmin.min(v.x);
        ymin = ymin.min(v.y);
        xmax = xmax.max(v.x);
        ymax = ymax.max(v.y);
    }
    (xmin, ymin, xmax, ymax)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::LayerDef;
    use serde_json::json;
    use std::collections::HashMap;

    fn layers() -> LayerTable {
        LayerTable::from_defs(&HashMap::from([
            (
                "m1".into(),
                LayerDef {
                    layer: 1,
                    datatype: 0,
                },
            ),
            (
                "die".into(),
                LayerDef {
                    layer: 2,
                    datatype: 0,
                },
            ),
            (
                "ko".into(),
                LayerDef {
                    layer: 3,
                    datatype: 0,
                },
            ),
        ]))
    }

    #[test]
    fn strict_schema_rejects_unknown_fields_units_layers_and_variable_cycles() {
        let layers = layers();
        let mut value = json!({
            "schema_version": 1, "deck_id": "D", "model_revision": "R", "dbu_nm": 1.0,
            "rules": [{"kind":"min_area", "id":"M1.A", "layer":{"source":"base","name":"m1"},
                "limit":{"op":"literal","value":10.0,"unit":"square_dbu"}, "typo": 4}]
        });
        assert!(ProductionDeck::from_json(&value, &layers)
            .unwrap_err()
            .to_string()
            .contains("unknown field"));
        value["rules"][0].as_object_mut().unwrap().remove("typo");
        value["rules"][0]["layer"]["name"] = json!("missing");
        assert!(ProductionDeck::from_json(&value, &layers)
            .unwrap_err()
            .to_string()
            .contains("unknown base layer"));

        value["rules"][0]["layer"]["name"] = json!("m1");
        value["variables"] = json!({
            "a":{"op":"variable","name":"b"}, "b":{"op":"variable","name":"a"}
        });
        assert!(ProductionDeck::from_json(&value, &layers)
            .unwrap_err()
            .to_string()
            .contains("cycle"));
    }

    #[test]
    fn tables_interpolate_with_dimensions_and_derived_layer_feeds_min_area() {
        let layers = layers();
        let value = json!({
            "schema_version":1, "deck_id":"D", "model_revision":"R", "dbu_nm":2.0,
            "tables":{"area_by_count":{"input_unit":"count","output_unit":"square_nanometer",
                "points":[{"input":1.0,"output":40.0},{"input":3.0,"output":80.0}],"interpolate":true}},
            "derived_layers":{"trimmed":{"op":"subtraction",
                "lhs":{"op":"layer","source":{"source":"base","name":"m1"}},
                "rhs":{"op":"layer","source":{"source":"base","name":"ko"}}}},
            "rules":[{"kind":"min_area","id":"M1.A","layer":{"source":"derived","name":"trimmed"},
                "limit":{"op":"lookup","table":"area_by_count",
                    "input":{"op":"literal","value":2.0,"unit":"count"}}}]
        });
        let deck = ProductionDeck::from_json(&value, &layers).unwrap();
        let mut store = GeometryStore::new();
        store.add_rect(layers.id("m1").unwrap(), 0, 0, 4, 4);
        store.add_rect(layers.id("ko").unwrap(), 2, 0, 2, 4);
        let report = run_checked(&store, &deck, &layers, &DrcContext::default());
        assert_eq!(report.rules[0].status, RuleStatus::Violations);
        assert_eq!(report.rules[0].violations[0].measured, 8);
        assert_eq!(report.rules[0].violations[0].limit, 15); // 60nm² / (2nm/DBU)²
    }

    #[test]
    fn missing_context_and_unsupported_rule_never_report_clean() {
        let layers = layers();
        let value = json!({
            "schema_version":1, "deck_id":"D", "model_revision":"R", "dbu_nm":1.0,
            "rules":[
                {"kind":"spacing","id":"M1.S","layer":{"source":"base","name":"m1"},"other":null,
                    "limit":{"op":"literal","value":2.0,"unit":"dbu"},
                    "when":{"net_relation":"different_net"}},
                {"kind":"min_width","id":"M1.W","layer":{"source":"base","name":"m1"},
                    "limit":{"op":"literal","value":2.0,"unit":"dbu"}}
            ]
        });
        let deck = ProductionDeck::from_json(&value, &layers).unwrap();
        let report = run_checked(
            &GeometryStore::new(),
            &deck,
            &layers,
            &DrcContext::default(),
        );
        assert_eq!(report.rules[0].status, RuleStatus::Error);
        assert_eq!(
            report.rules[0].diagnostics[0].code,
            DiagnosticCode::MissingContext
        );
        // min_width is now implemented; empty geometry → Clean
        assert_eq!(report.rules[1].status, RuleStatus::Clean);
        assert!(!report.is_clean());
    }

    #[test]
    fn density_uses_explicit_region_exclusion_and_union_area() {
        let layers = layers();
        let value = json!({
            "schema_version":1, "deck_id":"D", "model_revision":"R", "dbu_nm":1.0,
            "rules":[{"kind":"density","id":"M1.D","layer":{"source":"base","name":"m1"},
                "region":{"source":"base","name":"die"},"exclusion":{"source":"base","name":"ko"},
                "window":{"op":"literal","value":10.0,"unit":"dbu"},
                "step":{"op":"literal","value":10.0,"unit":"dbu"},
                "min":{"op":"literal","value":0.75,"unit":"ratio"},"max":null}]
        });
        let deck = ProductionDeck::from_json(&value, &layers).unwrap();
        let mut store = GeometryStore::new();
        let m1 = layers.id("m1").unwrap();
        store.add_rect(m1, 0, 0, 6, 10);
        store.add_rect(m1, 4, 0, 6, 10); // overlap must not double count
        store.add_rect(layers.id("die").unwrap(), 0, 0, 10, 10);
        store.add_rect(layers.id("ko").unwrap(), 8, 0, 2, 10);
        let report = run_checked(&store, &deck, &layers, &DrcContext::default());
        assert_eq!(report.rules[0].status, RuleStatus::Clean); // 80/80 after keepout
    }

    #[test]
    fn density_is_translation_safe_and_window_work_is_bounded() {
        let layers = layers();
        let value = json!({
            "schema_version":1, "deck_id":"D", "model_revision":"R", "dbu_nm":1.0,
            "rules":[{"kind":"density","id":"M1.D","layer":{"source":"base","name":"m1"},
                "region":{"source":"base","name":"die"},"exclusion":null,
                "window":{"op":"literal","value":10.0,"unit":"dbu"},
                "step":{"op":"literal","value":10.0,"unit":"dbu"},
                "min":{"op":"literal","value":1.0,"unit":"ratio"},"max":null}]
        });
        let deck = ProductionDeck::from_json(&value, &layers).unwrap();
        let run_at = |origin: i32| {
            let mut store = GeometryStore::new();
            store.add_rect(layers.id("m1").unwrap(), origin, origin, 5, 5);
            store.add_rect(layers.id("die").unwrap(), origin, origin, 5, 5);
            run_checked(&store, &deck, &layers, &DrcContext::default())
        };
        let at_origin = run_at(0);
        let at_max = run_at(i32::MAX - 5);
        assert_eq!(at_origin.rules[0].status, RuleStatus::Clean);
        assert_eq!(at_max.rules[0].status, at_origin.rules[0].status);

        let cap = super::super::MAX_DENSITY_WINDOW_WORK;
        assert_eq!(
            super::super::density_window_work(0, 0, cap as i32, 1, 1, 1).unwrap(),
            cap
        );
        assert!(matches!(
            super::super::density_window_work(0, 0, cap as i32 + 1, 1, 1, 1),
            Err(gdsverify_core::exact::ExactGeometryError::CapacityExceeded {
                cells,
                limit
            }) if cells == cap + 1 && limit == cap
        ));

        let mut over_cap_value = value;
        over_cap_value["rules"][0]["window"]["value"] = json!(1.0);
        over_cap_value["rules"][0]["step"]["value"] = json!(1.0);
        let over_cap_deck = ProductionDeck::from_json(&over_cap_value, &layers).unwrap();
        let mut over_cap_store = GeometryStore::new();
        over_cap_store.add_rect(layers.id("m1").unwrap(), 0, 0, cap as i32 + 1, 1);
        over_cap_store.add_rect(layers.id("die").unwrap(), 0, 0, cap as i32 + 1, 1);
        let over_cap = run_checked(
            &over_cap_store,
            &over_cap_deck,
            &layers,
            &DrcContext::default(),
        );
        assert_eq!(over_cap.rules[0].status, RuleStatus::Error);
        assert_eq!(
            over_cap.rules[0].diagnostics[0].code,
            DiagnosticCode::CapacityExceeded
        );
    }

    #[test]
    fn deck_rejects_invalid_density_and_discrete_ranges() {
        let layers = layers();
        let mut density = json!({
            "schema_version":1, "deck_id":"D", "model_revision":"R", "dbu_nm":1.0,
            "rules":[{"kind":"density","id":"M1.D",
                "layer":{"source":"base","name":"m1"},
                "region":{"source":"base","name":"die"},"exclusion":null,
                "window":{"op":"literal","value":10.0,"unit":"dbu"},
                "step":{"op":"literal","value":10.0,"unit":"dbu"},
                "min":{"op":"literal","value":0.0,"unit":"ratio"},
                "max":{"op":"literal","value":1.0,"unit":"ratio"}}]
        });
        ProductionDeck::from_json(&density, &layers).unwrap();

        density["rules"][0]["min"]["value"] = json!(1.1);
        assert!(ProductionDeck::from_json(&density, &layers)
            .unwrap_err()
            .to_string()
            .contains("[0, 1]"));
        density["rules"][0]["min"]["value"] = json!(0.8);
        density["rules"][0]["max"]["value"] = json!(0.2);
        assert!(ProductionDeck::from_json(&density, &layers)
            .unwrap_err()
            .to_string()
            .contains("min <= max"));
        density["rules"][0]["min"]["value"] = json!(0.0);
        density["rules"][0]["max"]["value"] = json!(1.0);
        density["rules"][0]["step"]["value"] = json!(11.0);
        assert!(ProductionDeck::from_json(&density, &layers)
            .unwrap_err()
            .to_string()
            .contains("step <= window"));

        let coloring = json!({
            "schema_version":1, "deck_id":"D", "model_revision":"R", "dbu_nm":1.0,
            "rules":[{"kind":"multi_patterning","id":"M1.MP",
                "layer":{"source":"base","name":"m1"},
                "colors":{"op":"literal","value":2.5,"unit":"count"},
                "spacing":{"op":"literal","value":10.0,"unit":"dbu"}}]
        });
        assert!(ProductionDeck::from_json(&coloring, &layers)
            .unwrap_err()
            .to_string()
            .contains("integer in [2, 64]"));
    }

    #[test]
    fn exact_holes_and_explicit_keyhole_slots_drive_plate_rules() {
        let layers = layers();
        let value = json!({
            "schema_version":1, "deck_id":"D", "model_revision":"R", "dbu_nm":1.0,
            "derived_layers":{"ring":{"op":"subtraction",
                "lhs":{"op":"layer","source":{"source":"base","name":"die"}},
                "rhs":{"op":"layer","source":{"source":"base","name":"ko"}}}},
            "rules":[
                {"kind":"min_enclosed_area","id":"HOLE.A",
                    "layer":{"source":"derived","name":"ring"},
                    "limit":{"op":"literal","value":10.0,"unit":"square_dbu"}},
                {"kind":"cheesing","id":"PLATE.SLOT",
                    "layer":{"source":"derived","name":"ring"},
                    "slots":{"source":"base","name":"ko"},
                    "max_area_without_slot":{"op":"literal","value":50.0,"unit":"square_dbu"}}
            ]
        });
        let deck = ProductionDeck::from_json(&value, &layers).unwrap();
        let mut store = GeometryStore::new();
        store.add_rect(layers.id("die").unwrap(), 0, 0, 10, 10);
        store.add_rect(layers.id("ko").unwrap(), 2, 2, 3, 3);
        let report = run_checked(&store, &deck, &layers, &DrcContext::default());
        assert_eq!(report.rules[0].status, RuleStatus::Violations);
        assert_eq!(report.rules[0].violations[0].measured, 9);
        assert_eq!(report.rules[1].status, RuleStatus::Clean);

        // A boundary-reaching slot reconstructs as a keyhole indentation, not a hole.
        let mut keyhole_store = GeometryStore::new();
        keyhole_store.add_rect(layers.id("die").unwrap(), 0, 0, 10, 10);
        keyhole_store.add_rect(layers.id("ko").unwrap(), 4, 4, 2, 6);
        let report = run_checked(&keyhole_store, &deck, &layers, &DrcContext::default());
        assert_eq!(report.rules[1].status, RuleStatus::Clean);
    }

    #[test]
    fn legacy_adapter_preserves_always_on_geometry_errors() {
        let deck =
            Deck::from_json(r#"{"layers":{"m1":{"layer":1,"datatype":0}},"drc":{}}"#).unwrap();
        let mut store = GeometryStore::new();
        store.add_polygon(
            deck.layers.id("m1").unwrap(),
            &[(0, 0), (10, 10), (10, 0), (0, 10)],
        );
        let report = run_legacy_adapter(&store, &deck);
        assert!(!report.is_clean());
        let geometry = report
            .rules
            .iter()
            .find(|rule| rule.rule_id == "__geometry__")
            .unwrap();
        assert_eq!(geometry.status, RuleStatus::Error);
        assert_eq!(geometry.violations[0].kind, "polygon_validity");
    }

    #[test]
    fn legacy_public_apis_reject_point_touch_lobes_but_accept_paired_keyholes() {
        let deck = Deck::from_json(
            r#"{"layers":{"m1":{"layer":1,"datatype":0}},
                "drc":{"GRID":{"kind":"off_grid","grid":1}}}"#,
        )
        .unwrap();
        let layer = deck.layers.id("m1").unwrap();
        let malformed_cases = vec![
            // Two opposite-winding lobes touch only at the repeated point.
            vec![
                (10, 0),
                (20, 0),
                (20, 20),
                (0, 20),
                (0, 0),
                (0, -5),
                (-5, -5),
                (-5, 0),
                (0, 0),
            ],
            // A vertex touches the interior of a non-adjacent edge.
            vec![(0, 0), (10, 0), (10, 10), (0, 10), (5, 0), (5, -5)],
            // A later edge partially retraces a non-adjacent edge.
            vec![
                (0, 0),
                (10, 0),
                (10, 10),
                (0, 10),
                (7, 0),
                (3, 0),
                (3, -5),
                (7, -5),
            ],
            // Full same-direction overlap is not a paired slit.
            vec![
                (0, 0),
                (10, 0),
                (10, 10),
                (0, 10),
                (0, 0),
                (10, 0),
                (10, -5),
                (0, -5),
            ],
            // Immediate reverse-edge backtracking is a spike, not a hole cycle.
            vec![(0, 0), (10, 0), (10, 10), (0, 10), (0, 0), (0, -5), (0, 0)],
            // Exact reviewer repro: the retrace connects a clockwise lobe
            // outside, rather than a contained hole.
            vec![
                (0, 0),
                (-5, 0),
                (-5, -5),
                (-10, -5),
                (-10, 0),
                (-5, 0),
                (0, 0),
                (10, 0),
                (10, 10),
                (0, 10),
            ],
            // Disjoint opposite-winding loops joined by a retraced edge are
            // lobes, not a containment-valid keyhole.
            vec![
                (10, 5),
                (20, 5),
                (20, 10),
                (30, 10),
                (30, 0),
                (20, 0),
                (20, 5),
                (10, 5),
                (10, 10),
                (0, 10),
                (0, 0),
                (10, 0),
            ],
            // Containment alone cannot turn a same-polarity nested lobe into a
            // hole; only absolute orientation is allowed to vary.
            vec![
                (0, 0),
                (10, 0),
                (10, 10),
                (5, 10),
                (5, 8),
                (3, 8),
                (3, 3),
                (8, 3),
                (8, 8),
                (5, 8),
                (5, 10),
                (0, 10),
            ],
        ];
        for points in malformed_cases {
            let mut malformed = GeometryStore::new();
            malformed.add_polygon(layer, &points);
            let raw = run_drc(&malformed, &deck);
            assert_eq!(
                raw.violations.len(),
                1,
                "missed malformed boundary {points:?}"
            );
            assert_eq!(raw.violations[0].rule_id, "__geometry__");
            assert_eq!(raw.violations[0].kind, "polygon_validity");
            let checked = run_legacy_adapter(&malformed, &deck);
            assert!(!checked.is_clean());
            assert_eq!(
                checked
                    .rules
                    .iter()
                    .find(|rule| rule.rule_id == "GRID")
                    .unwrap()
                    .status,
                RuleStatus::Clean,
            );
            let geometry = checked
                .rules
                .iter()
                .find(|rule| rule.rule_id == "__geometry__")
                .unwrap();
            assert_eq!(geometry.status, RuleStatus::Error);
            assert_eq!(
                geometry.diagnostics[0].code,
                DiagnosticCode::InvalidGeometry
            );
        }

        let valid_keyhole = [
            (0, 0),
            (1000, 0),
            (1000, 450),
            (600, 450),
            (600, 400),
            (900, 400),
            (900, 100),
            (100, 100),
            (100, 400),
            (600, 400),
            (600, 450),
            (0, 450),
        ];
        let mut reversed_keyhole = valid_keyhole;
        reversed_keyhole.reverse();
        let inverse_winding_keyhole = [
            (0, 0),
            (-10, 0),
            (-10, 10),
            (10, 10),
            (10, -10),
            (-10, -10),
            (-10, 0),
            (0, 0),
            (2, 0),
            (2, 2),
            (0, 2),
        ];
        let two_keyholes = [
            (0, 0),
            (100, 0),
            (100, 100),
            (70, 100),
            (70, 80),
            (90, 80),
            (90, 60),
            (60, 60),
            (60, 80),
            (70, 80),
            (70, 100),
            (40, 100),
            (40, 80),
            (50, 80),
            (50, 60),
            (20, 60),
            (20, 80),
            (40, 80),
            (40, 100),
            (0, 100),
        ];
        for points in [
            valid_keyhole.as_slice(),
            reversed_keyhole.as_slice(),
            inverse_winding_keyhole.as_slice(),
            two_keyholes.as_slice(),
        ] {
            let mut valid = GeometryStore::new();
            valid.add_polygon(layer, points);
            assert!(
                run_drc(&valid, &deck).violations.is_empty(),
                "rejected valid keyhole boundary {points:?}"
            );
            assert!(run_legacy_adapter(&valid, &deck).is_clean());
        }
    }

    #[test]
    fn legacy_api_reports_full_i32_geometry_capacity_without_panicking() {
        let deck = Deck::from_json(
            r#"{"layers":{"m1":{"layer":1,"datatype":0}},
                "drc":{"GRID":{"kind":"off_grid","grid":1}}}"#,
        )
        .unwrap();
        let layer = deck.layers.id("m1").unwrap();
        let mut full_range = GeometryStore::new();
        let polygon = full_range.add_polygon(
            layer,
            &[
                (i32::MIN, i32::MIN),
                (i32::MAX, i32::MIN),
                (i32::MAX, i32::MAX),
                (i32::MIN, i32::MAX),
            ],
        );

        let bbox = full_range.poly_bbox[polygon.0 as usize];
        assert_eq!(bbox.width_i64(), i64::from(u32::MAX));
        assert_eq!(bbox.height_i64(), i64::from(u32::MAX));
        assert_eq!(bbox.width(), i32::MAX);
        assert_eq!(bbox.height(), i32::MAX);
        assert!(!crate::geometry::poly_self_intersects(&full_range, polygon));
        assert!(full_range.area_exact(polygon).unwrap() > i128::from(i64::MAX));
        assert_eq!(full_range.signed_area2(polygon), i64::MAX);
        assert_eq!(full_range.area(polygon), i64::MAX);

        let raw = run_drc(&full_range, &deck);
        assert_eq!(raw.violations.len(), 1);
        assert_eq!(raw.violations[0].rule_id, "__geometry__");
        assert_eq!(raw.violations[0].kind, "geometry_capacity");

        let checked = run_legacy_adapter(&full_range, &deck);
        assert!(!checked.is_clean());
        let geometry = checked
            .rules
            .iter()
            .find(|rule| rule.rule_id == "__geometry__")
            .unwrap();
        assert_eq!(geometry.status, RuleStatus::Error);
        assert_eq!(
            geometry.diagnostics[0].code,
            DiagnosticCode::CapacityExceeded
        );
        assert_eq!(
            checked
                .rules
                .iter()
                .find(|rule| rule.rule_id == "GRID")
                .unwrap()
                .status,
            RuleStatus::NotRun
        );
        assert_eq!(deck.layers.name(layer), "m1");

        let mut reversed = GeometryStore::new();
        let polygon = reversed.add_polygon(
            layer,
            &[
                (i32::MIN, i32::MAX),
                (i32::MAX, i32::MAX),
                (i32::MAX, i32::MIN),
                (i32::MIN, i32::MIN),
            ],
        );
        assert_eq!(reversed.signed_area2(polygon), i64::MIN);
        assert_eq!(reversed.area(polygon), i64::MAX);
        assert!(!crate::geometry::poly_self_intersects(&reversed, polygon));
        assert_eq!(
            run_drc(&reversed, &deck).violations[0].kind,
            "geometry_capacity"
        );

        let mut oversized = GeometryStore::new();
        let oversized_points = vec![(0, 0); gdsverify_core::exact::MAX_BOUNDARY_WALK_VERTICES + 1];
        oversized.add_polygon(layer, &oversized_points);
        let checked = run_legacy_adapter(&oversized, &deck);
        let geometry = checked
            .rules
            .iter()
            .find(|rule| rule.rule_id == "__geometry__")
            .unwrap();
        assert_eq!(geometry.status, RuleStatus::Error);
        assert_eq!(
            geometry.diagnostics[0].code,
            DiagnosticCode::CapacityExceeded
        );
        assert_eq!(
            checked
                .rules
                .iter()
                .find(|rule| rule.rule_id == "GRID")
                .unwrap()
                .status,
            RuleStatus::NotRun
        );
    }

    #[test]
    fn legacy_rule_arithmetic_is_translation_safe_at_i32_extrema() {
        let deck = Deck::from_json(
            r#"{"layers":{"m1":{"layer":1,"datatype":0}},"drc":{
                "W":{"kind":"min_width","layer":"m1","min":7},
                "N":{"kind":"notch","layer":"m1","min":9},
                "S":{"kind":"min_spacing","layer":"m1","min":5}}}"#,
        )
        .unwrap();
        let layer = deck.layers.id("m1").unwrap();
        let shifted = |points: &[(i32, i32)], dx: i32, dy: i32| {
            points
                .iter()
                .map(|&(x, y)| {
                    (
                        i32::try_from(i64::from(x) + i64::from(dx)).unwrap(),
                        i32::try_from(i64::from(y) + i64::from(dy)).unwrap(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let signature = |store: &GeometryStore| {
            run_drc(store, &deck)
                .violations
                .into_iter()
                .map(|violation| (violation.rule_id, violation.kind, violation.measured))
                .collect::<Vec<_>>()
        };

        // A non-convex U exercises vertical/horizontal gap distances and
        // midpoints. Translation makes every old `a+b` midpoint overflow i32.
        let u_shape = [
            (0, 0),
            (20, 0),
            (20, 20),
            (14, 20),
            (14, 6),
            (6, 6),
            (6, 20),
            (0, 20),
        ];
        let mut origin = GeometryStore::new();
        origin.add_polygon(layer, &u_shape);
        let mut near_max = GeometryStore::new();
        near_max.add_polygon(layer, &shifted(&u_shape, i32::MAX - 20, i32::MAX - 20));
        let origin_signature = signature(&origin);
        assert!(origin_signature.iter().any(|(id, _, _)| id == "W"));
        assert!(origin_signature.iter().any(|(id, _, _)| id == "N"));
        assert_eq!(signature(&near_max), origin_signature);

        // Positive spacing used to subtract `min` from a bbox coordinate at
        // i32::MIN inside candidate pruning.
        let first = [(0, 0), (10, 0), (10, 10), (0, 10)];
        let second = [(13, 0), (23, 0), (23, 10), (13, 10)];
        let mut spacing_origin = GeometryStore::new();
        spacing_origin.add_polygon(layer, &first);
        spacing_origin.add_polygon(layer, &second);
        let offset = i32::MIN + 1;
        let mut near_min = GeometryStore::new();
        near_min.add_polygon(layer, &shifted(&first, offset, offset));
        near_min.add_polygon(layer, &shifted(&second, offset, offset));
        let spacing_signature = signature(&spacing_origin);
        assert!(spacing_signature
            .iter()
            .any(|(id, _, measured)| { id == "S" && *measured == 3 }));
        assert_eq!(signature(&near_min), spacing_signature);

        // Parallel diagonal edges have an 8e18 dot product and a cross² that
        // exceeds i64, while their true perpendicular width is only sqrt(32).
        let diagonal = [
            (-1_000_000_000, -1_000_000_000),
            (1_000_000_000, 1_000_000_000),
            (999_999_996, 1_000_000_004),
            (-1_000_000_004, -999_999_996),
        ];
        let mut diagonal_store = GeometryStore::new();
        let diagonal_polygon = diagonal_store.add_polygon(layer, &diagonal);
        let diagonal_gaps =
            super::super::facing_gaps(&diagonal_store, diagonal_polygon, true).unwrap();
        assert!(
            diagonal_gaps.iter().any(|(distance, _, _)| *distance == 5),
            "diagonal gaps: {diagonal_gaps:?}"
        );
        let diagonal_report = run_drc(&diagonal_store, &deck);
        assert!(
            diagonal_report
                .violations
                .iter()
                .any(|violation| { violation.rule_id == "W" && violation.measured == 5 }),
            "diagonal report: {:?}",
            diagonal_report.violations
        );
        assert!(diagonal_report
            .violations
            .iter()
            .all(|violation| violation.rule_id != "__geometry__"));

        let density_deck = Deck::from_json(
            r#"{"layers":{"m1":{"layer":1,"datatype":0}},"drc":{
                "D":{"kind":"min_density","layer":"m1","window":10,
                    "min_frac":0.5}}}"#,
        )
        .unwrap();
        let density_layer = density_deck.layers.id("m1").unwrap();
        let mut density_origin = GeometryStore::new();
        density_origin.add_rect(density_layer, 0, 0, 5, 5);
        let mut density_at_max = GeometryStore::new();
        density_at_max.add_polygon(
            density_layer,
            &[
                (i32::MAX - 5, i32::MAX - 5),
                (i32::MAX, i32::MAX - 5),
                (i32::MAX, i32::MAX),
                (i32::MAX - 5, i32::MAX),
            ],
        );
        let density_signature = |store: &GeometryStore| {
            run_drc(store, &density_deck)
                .violations
                .into_iter()
                .map(|violation| (violation.rule_id, violation.measured))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            density_signature(&density_origin),
            vec![("D".into(), 250_000)]
        );
        assert_eq!(
            density_signature(&density_at_max),
            density_signature(&density_origin)
        );

        let max_limit_deck = Deck::from_json(
            r#"{"layers":{"m1":{"layer":1,"datatype":0},
                "via":{"layer":2,"datatype":0}},"drc":{
                "A":{"kind":"via_array_spacing","layer":"via",
                    "array_threshold":2,"array_spacing":2147483647},
                "E":{"kind":"min_enclosure","outer":"m1","inner":"via",
                    "min":2147483647}}}"#,
        )
        .unwrap();
        let via = max_limit_deck.layers.id("via").unwrap();
        let m1 = max_limit_deck.layers.id("m1").unwrap();
        let mut via_array = GeometryStore::new();
        via_array.add_rect(via, 0, 0, 1, 1);
        via_array.add_rect(via, 2, 0, 1, 1);
        via_array.add_rect(via, 4, 0, 1, 1);
        let array_report = run_drc(&via_array, &max_limit_deck);
        assert!(array_report
            .violations
            .iter()
            .any(|violation| violation.rule_id == "A"));
        assert!(array_report
            .violations
            .iter()
            .all(|violation| violation.rule_id != "__geometry__"));

        let mut enclosure = GeometryStore::new();
        enclosure.add_rect(m1, 0, 0, 20, 20);
        enclosure.add_rect(via, 5, 5, 5, 5);
        let enclosure_report = run_drc(&enclosure, &max_limit_deck);
        assert!(enclosure_report
            .violations
            .iter()
            .any(|violation| violation.rule_id == "E"));
        assert!(enclosure_report
            .violations
            .iter()
            .all(|violation| violation.rule_id != "__geometry__"));
    }

    #[test]
    fn scalar_expr_min_selects_smaller_limit() {
        let layers = layers();
        let value = json!({
            "schema_version":1, "deck_id":"D", "model_revision":"R", "dbu_nm":1.0,
            "rules":[{"kind":"min_area","id":"M1.A","layer":{"source":"base","name":"m1"},
                "limit":{"op":"min",
                    "lhs":{"op":"literal","value":20.0,"unit":"square_dbu"},
                    "rhs":{"op":"literal","value":10.0,"unit":"square_dbu"}}}]
        });
        let deck = ProductionDeck::from_json(&value, &layers).unwrap();
        let mut store = GeometryStore::new();
        store.add_rect(layers.id("m1").unwrap(), 0, 0, 3, 3); // area = 9
        let report = run_checked(&store, &deck, &layers, &DrcContext::default());
        // min(20,10) = 10, area = 9 < 10 → violation
        assert_eq!(report.rules[0].status, RuleStatus::Violations);
        assert_eq!(report.rules[0].violations[0].limit, 10);
    }

    #[test]
    fn scalar_expr_max_selects_larger() {
        let layers = layers();
        let value = json!({
            "schema_version":1, "deck_id":"D", "model_revision":"R", "dbu_nm":1.0,
            "rules":[{"kind":"min_area","id":"M1.A","layer":{"source":"base","name":"m1"},
                "limit":{"op":"max",
                    "lhs":{"op":"literal","value":5.0,"unit":"square_dbu"},
                    "rhs":{"op":"literal","value":8.0,"unit":"square_dbu"}}}]
        });
        let deck = ProductionDeck::from_json(&value, &layers).unwrap();
        let mut store = GeometryStore::new();
        store.add_rect(layers.id("m1").unwrap(), 0, 0, 3, 3); // area = 9
        let report = run_checked(&store, &deck, &layers, &DrcContext::default());
        // max(5,8)=8, area=9 >= 8 → clean
        assert_eq!(report.rules[0].status, RuleStatus::Clean);
    }

    #[test]
    fn legacy_parity_variants_parse_as_unsupported() {
        let layers = layers();
        // max_width and notch are now implemented — they return Clean on empty
        // geometry. off_grid remains unsupported.
        let value = json!({
            "schema_version":1, "deck_id":"D", "model_revision":"R", "dbu_nm":1.0,
            "rules":[
                {"kind":"off_grid","id":"OG",
                    "grid":{"op":"literal","value":2.0,"unit":"dbu"}}
            ]
        });
        let deck = ProductionDeck::from_json(&value, &layers).unwrap();
        let report = run_checked(
            &GeometryStore::new(),
            &deck,
            &layers,
            &DrcContext::default(),
        );
        for rule in &report.rules {
            assert_eq!(rule.status, RuleStatus::Error);
            assert_eq!(rule.diagnostics[0].code, DiagnosticCode::Unsupported);
        }
    }

    #[test]
    fn production_min_width_detects_narrow_polygon() {
        let layers = layers();
        let value = json!({
            "schema_version":1, "deck_id":"D", "model_revision":"R", "dbu_nm":1.0,
            "rules":[{"kind":"min_width","id":"M1.W","layer":{"source":"base","name":"m1"},
                "limit":{"op":"literal","value":5.0,"unit":"dbu"}}]
        });
        let deck = ProductionDeck::from_json(&value, &layers).unwrap();
        // 3-wide rect violates min_width=5
        let mut store = GeometryStore::new();
        store.add_rect(layers.id("m1").unwrap(), 0, 0, 3, 10);
        let report = run_checked(&store, &deck, &layers, &DrcContext::default());
        assert_eq!(report.rules[0].status, RuleStatus::Violations);
        assert!(report.rules[0].violations.iter().any(|v| v.measured == 3));

        // 5-wide rect passes
        let mut clean_store = GeometryStore::new();
        clean_store.add_rect(layers.id("m1").unwrap(), 0, 0, 5, 10);
        let clean_report = run_checked(&clean_store, &deck, &layers, &DrcContext::default());
        assert_eq!(clean_report.rules[0].status, RuleStatus::Clean);
    }

    #[test]
    fn production_spacing_detects_close_polygons() {
        let layers = layers();
        let value = json!({
            "schema_version":1, "deck_id":"D", "model_revision":"R", "dbu_nm":1.0,
            "rules":[{"kind":"spacing","id":"M1.S","layer":{"source":"base","name":"m1"},
                "other":null,"limit":{"op":"literal","value":5.0,"unit":"dbu"}}]
        });
        let deck = ProductionDeck::from_json(&value, &layers).unwrap();
        let m1 = layers.id("m1").unwrap();
        // Two rects 3 apart — violates spacing=5
        let mut store = GeometryStore::new();
        store.add_rect(m1, 0, 0, 10, 10);
        store.add_rect(m1, 13, 0, 10, 10);
        let report = run_checked(&store, &deck, &layers, &DrcContext::default());
        assert_eq!(report.rules[0].status, RuleStatus::Violations);
        assert!(report.rules[0].violations.iter().any(|v| v.measured == 3));

        // Two rects 5 apart — passes
        let mut clean_store = GeometryStore::new();
        clean_store.add_rect(m1, 0, 0, 10, 10);
        clean_store.add_rect(m1, 15, 0, 10, 10);
        let clean_report = run_checked(&clean_store, &deck, &layers, &DrcContext::default());
        assert_eq!(clean_report.rules[0].status, RuleStatus::Clean);
    }

    #[test]
    fn production_enclosure_detects_insufficient_surround() {
        let layers = layers();
        let value = json!({
            "schema_version":1, "deck_id":"D", "model_revision":"R", "dbu_nm":1.0,
            "rules":[{"kind":"enclosure","id":"E","outer":{"source":"base","name":"die"},
                "inner":{"source":"base","name":"m1"},
                "limit":{"op":"literal","value":3.0,"unit":"dbu"}}]
        });
        let deck = ProductionDeck::from_json(&value, &layers).unwrap();
        let die = layers.id("die").unwrap();
        let m1 = layers.id("m1").unwrap();
        // inner at (2,2)-(8,8) inside outer at (0,0)-(10,10) -> enc = 2 < 3
        let mut store = GeometryStore::new();
        store.add_rect(die, 0, 0, 10, 10);
        store.add_rect(m1, 2, 2, 6, 6);
        let report = run_checked(&store, &deck, &layers, &DrcContext::default());
        assert_eq!(report.rules[0].status, RuleStatus::Violations);
        assert!(report.rules[0].violations.iter().any(|v| v.measured == 2));

        // inner at (3,3)-(7,7) -> enc = 3, passes
        let mut clean_store = GeometryStore::new();
        clean_store.add_rect(die, 0, 0, 10, 10);
        clean_store.add_rect(m1, 3, 3, 4, 4);
        let clean_report = run_checked(&clean_store, &deck, &layers, &DrcContext::default());
        assert_eq!(clean_report.rules[0].status, RuleStatus::Clean);
    }

    #[test]
    fn production_notch_detects_internal_gap() {
        let layers = layers();
        let value = json!({
            "schema_version":1, "deck_id":"D", "model_revision":"R", "dbu_nm":1.0,
            "rules":[{"kind":"notch","id":"N","layer":{"source":"base","name":"m1"},
                "limit":{"op":"literal","value":9.0,"unit":"dbu"}}]
        });
        let deck = ProductionDeck::from_json(&value, &layers).unwrap();
        let m1 = layers.id("m1").unwrap();
        // U-shape with 8-wide notch
        let mut store = GeometryStore::new();
        store.add_polygon(
            m1,
            &[
                (0, 0),
                (20, 0),
                (20, 20),
                (14, 20),
                (14, 6),
                (6, 6),
                (6, 20),
                (0, 20),
            ],
        );
        let report = run_checked(&store, &deck, &layers, &DrcContext::default());
        assert_eq!(report.rules[0].status, RuleStatus::Violations);
        assert!(report.rules[0].violations.iter().any(|v| v.measured == 8));
    }

    #[test]
    fn production_max_width_and_empty_geometry() {
        let layers = layers();
        let value = json!({
            "schema_version":1, "deck_id":"D", "model_revision":"R", "dbu_nm":1.0,
            "rules":[
                {"kind":"max_width","id":"MW","layer":{"source":"base","name":"m1"},
                    "limit":{"op":"literal","value":5.0,"unit":"dbu"}},
                {"kind":"notch","id":"N","layer":{"source":"base","name":"m1"},
                    "limit":{"op":"literal","value":5.0,"unit":"dbu"}}
            ]
        });
        let deck = ProductionDeck::from_json(&value, &layers).unwrap();
        // Empty geometry -> Clean (not Error)
        let report = run_checked(
            &GeometryStore::new(),
            &deck,
            &layers,
            &DrcContext::default(),
        );
        assert_eq!(report.rules[0].status, RuleStatus::Clean);
        assert_eq!(report.rules[1].status, RuleStatus::Clean);

        // 10-wide rect exceeds max_width=5
        let mut store = GeometryStore::new();
        store.add_rect(layers.id("m1").unwrap(), 0, 0, 10, 3);
        let report = run_checked(&store, &deck, &layers, &DrcContext::default());
        assert_eq!(report.rules[0].status, RuleStatus::Violations);
        assert!(report.rules[0].violations.iter().any(|v| v.measured == 10));
    }
}
