//! PDK rule schema and its resolved runtime form.
//!
//! One module, two stages of the same data:
//!  1. The serde-facing *schema* ([`VerifySchema`], [`DrcRuleSchema`],
//!     [`LvsSchema`], ...) — exactly what a PDK deck JSON contains.
//!  2. The resolved *deck* ([`Deck`], [`LayerTable`], [`DrcRuleParam`], ...) —
//!     validated, layer-name-resolved parameters the rule engines consume.
//!     Rules receive a reference to the deck through their engine context
//!     (e.g. `DrcCtx`), never the raw schema.
//!
//! Parse, don't validate: JSON is checked once at this boundary; downstream
//! code takes the resolved types and never re-checks.

use crate::geometry::LayerId;
use serde::Deserialize;
use std::collections::HashMap;

/// What the verify crate needs from a PDK.
pub struct VerifySchema {
    /// Layer definitions: name → (GDS layer, GDS datatype).
    pub layers: HashMap<String, (i32, i32)>,
    /// DRC rules.
    pub drc_rules: Vec<DrcRuleSchema>,
    /// PEX process constants keyed by layer name.
    pub pex: HashMap<String, PexLayerParams>,
    /// ERC thresholds (defaulted — see ErcParams).
    pub erc: ErcParams,
    /// LVS extraction options.
    pub lvs: LvsSchema,
    /// PDK-driven connectivity (conductors + vias). Empty → legacy hardcoded fallback.
    pub connectivity: ConnectivitySchema,
    /// PDK-driven device recognition. Empty → legacy hardcoded MOS-only fallback.
    pub devices: DeviceSchema,
}

/// One DRC rule as provided by the PDK. Flat bag of optional fields —
/// `Deck::from_schema` resolves layer names and builds typed `DrcRuleParam`s.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DrcRuleSchema {
    /// Stable rule identifier reported in violations. For legacy schemas that
    /// leave this empty, `Deck::from_schema` falls back to `kind`.
    pub id: String,
    /// Rule implementation selector (for example `min_width`). This is
    /// deliberately independent from `id`, allowing multiple instances of one
    /// rule kind on different layers or with different thresholds.
    pub kind: String,
    pub enabled: bool,
    #[serde(alias = "layer_a")]
    pub layer: Option<String>,
    pub layer_b: Option<String>,
    pub outer: Option<String>,
    pub inner: Option<String>,
    #[serde(rename = "ref", alias = "reference")]
    pub reference: Option<String>,
    pub min: Option<i64>,
    pub max: Option<i32>,
    pub grid: Option<i32>,
    pub window: Option<i32>,
    pub min_frac: Option<f64>,
    pub max_frac: Option<f64>,
    pub ratio: Option<f64>,
    pub eol_width: Option<i32>,
    pub eol_spacing: Option<i32>,
    pub allowed: Option<Vec<i32>>,
    pub width_threshold: Option<i32>,
    pub wide_spacing: Option<i32>,
    pub prl_threshold: Option<i32>,
    pub prl_spacing: Option<i32>,
    pub min_count: Option<i32>,
    pub within: Option<i32>,
    pub array_threshold: Option<i32>,
    pub array_spacing: Option<i32>,
    pub max_dist: Option<i32>,
    pub num_colors: Option<i32>,
    /// Ordered metal stack, bottom-up, for cumulative antenna (CAR).
    pub layers: Option<Vec<String>>,
    /// Diode/junction marker layer: connection waives the antenna check.
    pub diode_layer: Option<String>,
}

impl Default for DrcRuleSchema {
    fn default() -> Self {
        Self {
            id: String::new(),
            kind: String::new(),
            enabled: true,
            layer: None,
            layer_b: None,
            outer: None,
            inner: None,
            reference: None,
            min: None,
            max: None,
            grid: None,
            window: None,
            min_frac: None,
            max_frac: None,
            ratio: None,
            eol_width: None,
            eol_spacing: None,
            allowed: None,
            width_threshold: None,
            wide_spacing: None,
            prl_threshold: None,
            prl_spacing: None,
            min_count: None,
            within: None,
            array_threshold: None,
            array_spacing: None,
            max_dist: None,
            num_colors: None,
            layers: None,
            diode_layer: None,
        }
    }
}

/// Parse the JSON `drc` section into rule schemas.
///
/// Two encodings are accepted:
///
/// * Legacy/object form: `{ "min_width": { ... } }`. The object key is both
///   the ID and kind unless the body supplies an explicit `id` or `kind`.
/// * Explicit/list form: `[{ "id": "M1.W.1", "kind": "min_width", ... }]`.
///
/// The object form can also express repeated kinds by using distinct keys and
/// putting `"kind": "min_width"` in each body.
pub fn drc_rules_from_json(value: &serde_json::Value) -> Result<Vec<DrcRuleSchema>, String> {
    match value {
        serde_json::Value::Null => Ok(Vec::new()),
        serde_json::Value::Object(rules) => rules
            .iter()
            .map(|(key, body)| drc_rule_from_json(Some(key), body))
            .collect(),
        serde_json::Value::Array(rules) => rules
            .iter()
            .enumerate()
            .map(|(index, body)| {
                drc_rule_from_json(None, body)
                    .map_err(|e| format!("DRC rule at array index {index}: {e}"))
            })
            .collect(),
        _ => Err("`drc` must be an object map or an array of rule objects".into()),
    }
}

fn drc_rule_from_json(
    map_key: Option<&str>,
    value: &serde_json::Value,
) -> Result<DrcRuleSchema, String> {
    let object = value.as_object().ok_or_else(|| match map_key {
        Some(key) => format!("DRC rule `{key}` must be an object"),
        None => "DRC rule must be an object".into(),
    })?;
    let string = |field: &str| match object.get(field) {
        None => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value.as_str())),
        Some(_) => Err(format!("`{field}` must be a string")),
    };
    let id = string("id")?
        .map(str::to_owned)
        .or_else(|| map_key.map(str::to_owned))
        .ok_or_else(|| "missing required string field `id`".to_string())?;
    let kind = string("kind")?
        .map(str::to_owned)
        .or_else(|| map_key.map(str::to_owned))
        .ok_or_else(|| format!("DRC rule `{id}` is missing required string field `kind`"))?;
    let context = format!("DRC rule `{id}`");
    let mut body = object.clone();
    merge_alias(&mut body, "layer", "layer_a", &context)?;
    merge_alias(&mut body, "ref", "reference", &context)?;
    body.insert("id".into(), id.clone().into());
    body.insert("kind".into(), kind.into());

    // `Option<T>` normally accepts explicit nulls. Deck fields do not: null is
    // almost always a misspelled/omitted limit and must fail closed.
    if let Some(field) = body
        .iter()
        .find_map(|(field, value)| value.is_null().then_some(field))
    {
        return Err(format!("{context}: `{field}` must not be null"));
    }

    serde_json::from_value(serde_json::Value::Object(body)).map_err(|error| {
        let message = error.to_string();
        match message
            .strip_prefix("unknown field `")
            .and_then(|rest| rest.split('`').next())
        {
            Some(field) => format!("{context}: unknown property `{field}`"),
            None => format!("{context}: {message}"),
        }
    })
}

fn merge_alias(
    object: &mut serde_json::Map<String, serde_json::Value>,
    field: &str,
    alias: &str,
    context: &str,
) -> Result<(), String> {
    let Some(alias_value) = object.remove(alias) else {
        return Ok(());
    };
    match object.get(field) {
        Some(value) if value != &alias_value => {
            Err(format!("{context}: `{field}` and `{alias}` disagree"))
        }
        Some(_) => Ok(()),
        None => {
            object.insert(field.into(), alias_value);
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub struct PropertyTolerance {
    pub abs_nm: i32,
    pub rel_pct: f64,
}

impl Default for PropertyTolerance {
    fn default() -> Self {
        PropertyTolerance {
            abs_nm: 10,
            rel_pct: 0.02,
        }
    }
}

#[derive(Default)]
pub struct LvsSchema {
    pub cut_required: bool,
    pub w_tolerance: PropertyTolerance,
    pub l_tolerance: PropertyTolerance,
    pub fail_on_floating: bool,
    pub hierarchical: bool,
    pub equate_cells: Vec<(String, String)>,
}

/// PDK-driven connectivity: which layers conduct and which vias bridge them.
/// Replaces the hardcoded `connective_layers()` function.
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConnectivitySchema {
    pub conductors: Vec<String>,
    pub vias: Vec<ViaSchema>,
    /// Same-layer touching polygons connect (default true, matches KLayout).
    pub intra_layer_touch: bool,
    /// Global net names that connect across hierarchy boundaries.
    pub global_nets: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViaSchema {
    pub layer: String,
    pub connects: Vec<String>,
}

/// PDK-driven device recognition rules.
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeviceSchema {
    #[serde(rename = "mos")]
    pub mos_rules: Vec<MosRuleSchema>,
    #[serde(rename = "bjt")]
    pub bjt_rules: Vec<BjtRuleSchema>,
    #[serde(rename = "resistor")]
    pub resistor_rules: Vec<ResistorRuleSchema>,
    #[serde(rename = "diode")]
    pub diode_rules: Vec<DiodeRuleSchema>,
    #[serde(rename = "cap", alias = "capacitor")]
    pub cap_rules: Vec<CapRuleSchema>,
    #[serde(skip)]
    pub derived_layers: Vec<DerivedLayerSchema>,
}

/// Defines the serde and layer-resolved forms together so their field layouts
/// cannot drift apart.
macro_rules! device_rule_pair {
    ($(#[$meta:meta])* $schema:ident => $resolved:ident {
        $($(#[$field_meta:meta])* $field:ident: $schema_ty:ty => $resolved_ty:ty),* $(,)?
    }) => {
        $(#[$meta])*
        #[derive(Clone, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $schema {
            $($(#[$field_meta])* pub $field: $schema_ty),*
        }

        #[derive(Clone)]
        pub struct $resolved { $(pub $field: $resolved_ty),* }
    };
}

device_rule_pair! {
    /// MOS device: gate over channel, with type chosen by implant.
    MosRuleSchema => MosRule {
        name: String => String,
        gate_layer: String => LayerId,
        channel_layer: String => LayerId,
        type_implant: String => LayerId,
        device_type: String => String,
        #[serde(default)] flavor_markers: Vec<(String, String)> => Vec<(LayerId, String)>,
        #[serde(default)] well_layer: Option<String> => Option<LayerId>,
        #[serde(default)] device_class: Option<String> => Option<String>,
    }
}

device_rule_pair! {
    /// BJT: three-layer intersection with type marker.
    BjtRuleSchema => BjtRule {
        name: String => String,
        collector_layer: String => LayerId,
        base_layer: String => LayerId,
        emitter_layer: String => LayerId,
        type_marker: String => LayerId,
        device_type: String => String,
    }
}

/// Derived layer: boolean operation on existing layers.
#[derive(Clone)]
pub struct DerivedLayerSchema {
    pub name: String,
    pub op: DerivedLayerOp,
}

#[derive(Clone)]
pub enum DerivedLayerOp {
    And(Vec<String>),
    Subtract { base: String, minus: String },
    Or(Vec<String>),
}

/// Configurable property combination for series/parallel merging.
#[derive(Clone, Debug, PartialEq)]
pub enum CombineRule {
    Add,
    Par,
    Min,
    Max,
    Critical,
}

device_rule_pair! {
    /// Two-terminal resistor: body with marker, no gate crossing.
    ResistorRuleSchema => ResistorRule {
        name: String => String,
        body_layer: String => LayerId,
        marker_layer: String => LayerId,
        terminal_layer: String => LayerId,
    }
}

device_rule_pair! {
    /// Diode: junction of two layers with implant marker.
    DiodeRuleSchema => DiodeRule {
        name: String => String,
        anode_layer: String => LayerId,
        cathode_layer: String => LayerId,
        implant_layer: String => LayerId,
    }
}

device_rule_pair! {
    /// MIM/MOS capacitor: two plates with optional marker.
    CapRuleSchema => CapRule {
        name: String => String,
        top_layer: String => LayerId,
        bottom_layer: String => LayerId,
        #[serde(default)] marker_layer: Option<String> => Option<LayerId>,
    }
}

// --------------------------------------------------------------------
// Device catalog (the "devices" section — library of known device
// names with sizing constraints, distinct from device_recognition)
// --------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceCatalogEntry {
    #[serde(rename = "type")]
    pub device_type: String,
    pub cell: String,
    #[serde(default)]
    pub min_w: Option<i32>,
    #[serde(default)]
    pub min_l: Option<i32>,
    #[serde(default)]
    pub default_w: Option<i32>,
    #[serde(default)]
    pub default_l: Option<i32>,
}

/// Parse the `devices` section into a device catalog, expanding
/// `_prefixes` and `_aliases` to avoid redundant entries in the JSON.
///
/// Reserved keys (start with `_`):
/// * `_prefixes`: `["sky130_fd_pr__"]` — auto-creates `{prefix}{name}`
///   for every device entry.
/// * `_aliases`:  `{"n": "nfet"}` — explicit name→base mapping.
pub fn parse_device_catalog(
    value: &serde_json::Value,
) -> Result<HashMap<String, DeviceCatalogEntry>, String> {
    let obj = match value {
        serde_json::Value::Null => return Ok(HashMap::new()),
        serde_json::Value::Object(m) => m,
        _ => return Err("`devices` must be an object".into()),
    };

    let prefixes: Vec<String> = obj
        .get("_prefixes")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| format!("`_prefixes`: {e}"))?
        .unwrap_or_default();

    let aliases: HashMap<String, String> = obj
        .get("_aliases")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| format!("`_aliases`: {e}"))?
        .unwrap_or_default();

    let mut catalog = HashMap::new();
    for (key, val) in obj {
        if key.starts_with('_') {
            continue;
        }
        let entry: DeviceCatalogEntry =
            serde_json::from_value(val.clone()).map_err(|e| format!("device `{key}`: {e}"))?;
        catalog.insert(key.clone(), entry);
    }

    let base_keys: Vec<String> = catalog.keys().cloned().collect();
    for prefix in &prefixes {
        for name in &base_keys {
            let aliased = format!("{prefix}{name}");
            if !catalog.contains_key(&aliased) {
                catalog.insert(aliased, catalog[name].clone());
            }
        }
    }

    for (alias, base) in &aliases {
        let entry = catalog
            .get(base)
            .ok_or_else(|| format!("alias `{alias}` references unknown device `{base}`"))?
            .clone();
        catalog.insert(alias.clone(), entry);
    }

    Ok(catalog)
}

// --------------------------------------------------------------------
// Resolved parameter deck (formerly params.rs)
// --------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayerDef {
    pub layer: i32,
    pub datatype: i32,
}

/// Resolves symbolic layer names (e.g. "met1") to internal `LayerId`s and to GDS
/// (layer,datatype) pairs. Built once, then shared read-only by every checker.
#[derive(Debug, Default)]
pub struct LayerTable {
    pub name_to_id: HashMap<String, LayerId>,
    pub id_to_name: Vec<String>,
    pub id_to_gds: Vec<(i32, i32)>,
    pub gds_to_id: HashMap<(i32, i32), LayerId>,
}

impl LayerTable {
    pub fn from_defs(defs: &HashMap<String, LayerDef>) -> Self {
        // deterministic order: sort by (layer,datatype) so ids are stable across runs
        let mut items: Vec<(&String, &LayerDef)> = defs.iter().collect();
        items.sort_by_key(|(_, d)| (d.layer, d.datatype));
        let mut t = LayerTable::default();
        for (name, d) in items {
            let id = t.id_to_name.len() as LayerId;
            t.name_to_id.insert(name.clone(), id);
            t.id_to_name.push(name.clone());
            t.id_to_gds.push((d.layer, d.datatype));
            t.gds_to_id.insert((d.layer, d.datatype), id);
        }
        t
    }

    pub fn id(&self, name: &str) -> Option<LayerId> {
        self.name_to_id.get(name).copied()
    }
    pub fn name(&self, id: LayerId) -> &str {
        &self.id_to_name[id as usize]
    }
    pub fn from_gds(&self, layer: i32, datatype: i32) -> Option<LayerId> {
        self.gds_to_id.get(&(layer, datatype)).copied()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PexLayerParams {
    pub sheet_res_ohm_sq: f64,
    pub area_cap_af_um2: f64,
    pub fringe_cap_af_um: f64,
    pub coupling_cap_af_um: f64,
    pub coupling_ref_spacing_nm: f64,
    /// Fixed per-via resistance (ohm). When set, every polygon on this layer
    /// gets this R regardless of geometry. Used for via/contact layers.
    #[serde(default)]
    pub via_res_ohm: f64,
    #[serde(default)]
    pub interlayer_cap_af_um2: f64,
    // --- 3D process geometry, consumed only by the field-solver PEX path ---
    /// Metal thickness (nm). 0 → the field solver falls back to its stack
    /// heuristic for this layer.
    #[serde(default)]
    pub thickness_nm: f64,
    /// Bottom of the metal above substrate (nm). 0 (with thickness 0) → heuristic.
    #[serde(default)]
    pub height_nm: f64,
    /// Dielectric constant of the surrounding medium. 0 → 3.9 (SiO₂).
    #[serde(default)]
    pub dielectric_k: f64,
}

/// Selects how PEX derives per-net R/C: the fast analytical (pattern/2.5D)
/// models, or the quasi-static field solvers (FastCap2 for C, FastHenry2 for R).
/// Set in the deck JSON as `"pex_method": "analytical" | "field_solver"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PexMethod {
    #[default]
    Analytical,
    FieldSolver,
}

/// Resolved connectivity: LayerIds instead of strings.
#[derive(Clone, Default)]
pub struct ConnectivityConfig {
    pub conductors: Vec<LayerId>,
    pub vias: Vec<(LayerId, Vec<LayerId>)>,
}

/// Resolved device config.
#[derive(Clone, Default)]
pub struct DeviceConfig {
    pub mos_rules: Vec<MosRule>,
    pub bjt_rules: Vec<BjtRule>,
    pub resistor_rules: Vec<ResistorRule>,
    pub diode_rules: Vec<DiodeRule>,
    pub cap_rules: Vec<CapRule>,
}

/// ERC thresholds. Every field defaults to today's built-in value, so decks
/// without an "erc" section behave identically; override per PDK in params.json.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErcParams {
    /// antenna_electrical: cumulative metal area / gate area limit.
    #[serde(default = "d_erc_antenna")]
    pub antenna_ratio: f64,
    /// em_current_density: minimum metal width on current-carrying nets (nm).
    #[serde(default = "d_erc_em_w")]
    pub em_min_width_nm: i32,
    /// p2p_resistance: per-net total wire resistance limit (ohm).
    #[serde(default = "d_erc_p2p")]
    pub p2p_r_limit_ohm: f64,
    /// missing_tie: max distance from a diff corner to the nearest tap (nm).
    #[serde(default = "d_erc_tie")]
    pub tie_max_dist_nm: i32,
}
fn d_erc_antenna() -> f64 {
    200.0
}
fn d_erc_em_w() -> i32 {
    200
}
fn d_erc_p2p() -> f64 {
    10.0
}
fn d_erc_tie() -> i32 {
    2000
}
impl Default for ErcParams {
    fn default() -> Self {
        ErcParams {
            antenna_ratio: d_erc_antenna(),
            em_min_width_nm: d_erc_em_w(),
            p2p_r_limit_ohm: d_erc_p2p(),
            tie_max_dist_nm: d_erc_tie(),
        }
    }
}

/// The fully-resolved deck the checkers consume.
pub struct Deck {
    pub layers: LayerTable,
    pub drc_rules: Vec<DrcRuleParam>,
    pub pex: HashMap<LayerId, PexLayerParams>,
    /// Analytical (default) or field-solver PEX. Set via `"pex_method"` in JSON.
    pub pex_method: PexMethod,
    pub dbu_nm: f64,
    /// LVS extraction requires explicit cut (via) shapes to connect layers.
    pub lvs_cut_required: bool,
    /// STRICT mode: off-grid → hard error, acute angle → hard error,
    /// same-net spacing enforced. Default false (nominal mode).
    pub strict: bool,
    /// PDK-driven connectivity. Empty → legacy hardcoded fallback.
    pub connectivity: ConnectivityConfig,
    /// PDK-driven device recognition. Empty → legacy hardcoded MOS-only.
    pub devices: DeviceConfig,
    pub w_tolerance: PropertyTolerance,
    pub l_tolerance: PropertyTolerance,
    pub fail_on_floating: bool,
    pub intra_layer_touch: bool,
    pub global_nets: Vec<String>,
    /// ERC thresholds (all defaulted; see [`ErcParams`]).
    pub erc: ErcParams,
    /// Device catalog (expanded from the `devices` section, including
    /// prefix/alias expansions). Empty when loaded via `from_schema`.
    pub device_catalog: HashMap<String, DeviceCatalogEntry>,
}

/// Defines each tagged DRC parameter once while giving every variant the
/// stable rule ID used by reporting. Engines still match a concrete enum with
/// no virtual dispatch.
macro_rules! drc_rule_params {
    ($( $(#[$meta:meta])* $variant:ident { $($field:ident: $ty:ty),* $(,)? } ),* $(,)?) => {
        #[derive(Debug, Clone)]
        pub enum DrcRuleParam {
            $(
                $(#[$meta])*
                $variant { id: String, $($field: $ty),* }
            ),*
        }

        impl DrcRuleParam {
            pub fn id(&self) -> &str {
                match self { $(Self::$variant { id, .. } => id),* }
            }
        }
    };
}

drc_rule_params! {
    MinWidth { layer: LayerId, min: i32 },
    MinSpacing { layer: LayerId, min: i32 },
    MinSpacingDiff { a: LayerId, b: LayerId, min: i32 },
    MinEnclosure { outer: LayerId, inner: LayerId, min: i32 },
    MinExtension { layer: LayerId, reference: LayerId, min: i32 },
    MinArea { layer: LayerId, min: i64 },
    MaxWidth { layer: LayerId, max: i32 },
    Notch { layer: LayerId, min: i32 },
    MinEdgeLength { layer: LayerId, min: i32 },
    OffGrid { grid: i32 },
    Angle { allowed: Vec<i32> },
    MinDensity { layer: LayerId, window: i32, min_frac: f64 },
    MaxDensity { layer: LayerId, window: i32, max_frac: f64 },
    Overlap { a: LayerId, b: LayerId, min: i32 },
    CornerToCorner { layer: LayerId, min: i32 },
    Antenna { layer: LayerId, ratio: f64 },
    /// Cumulative antenna ratio through an ordered metal stack, optionally
    /// waived by a diode-layer connection.
    AntennaCar { layers: Vec<LayerId>, ratio: f64, diode: Option<LayerId> },
    EolSpacing { layer: LayerId, eol_width: i32, eol_spacing: i32 },
    WideDependentSpacing { layer: LayerId, width_threshold: i32, wide_spacing: i32 },
    PrlSpacing { layer: LayerId, prl_threshold: i32, prl_spacing: i32 },
    AsymmetricEnclosure { outer: LayerId, inner: LayerId, min_one_side: i32 },
    MinEnclosedArea { layer: LayerId, min_hole_area: i64 },
    Cheesing { layer: LayerId, max_area_no_slot: i64 },
    RedundantVia { layer: LayerId, min_count: i32, within: i32 },
    ViaArraySpacing { layer: LayerId, array_threshold: i32, array_spacing: i32 },
    MaxDistanceToTap { diff_layer: LayerId, tap_layer: LayerId, max_dist: i32 },
    MultiPatterning { layer: LayerId, num_colors: i32, color_spacing: i32 },
}

fn drc_rule_error(id: &str, kind: &str, message: impl std::fmt::Display) -> String {
    format!("DRC rule `{id}` ({kind}): {message}")
}

fn required_positive_i32_from_i64(
    id: &str,
    kind: &str,
    field: &str,
    value: Option<i64>,
) -> Result<i32, String> {
    let value = value
        .ok_or_else(|| drc_rule_error(id, kind, format!("missing required `{field}` parameter")))?;
    if value <= 0 {
        return Err(drc_rule_error(
            id,
            kind,
            format!("`{field}` must be positive, got {value}"),
        ));
    }
    i32::try_from(value).map_err(|_| {
        drc_rule_error(
            id,
            kind,
            format!("`{field}` value {value} is outside the i32 range"),
        )
    })
}

fn required_positive_i32(
    id: &str,
    kind: &str,
    field: &str,
    value: Option<i32>,
) -> Result<i32, String> {
    let value = value
        .ok_or_else(|| drc_rule_error(id, kind, format!("missing required `{field}` parameter")))?;
    if value <= 0 {
        return Err(drc_rule_error(
            id,
            kind,
            format!("`{field}` must be positive, got {value}"),
        ));
    }
    Ok(value)
}

fn required_positive_i64(
    id: &str,
    kind: &str,
    field: &str,
    value: Option<i64>,
) -> Result<i64, String> {
    let value = value
        .ok_or_else(|| drc_rule_error(id, kind, format!("missing required `{field}` parameter")))?;
    if value <= 0 {
        return Err(drc_rule_error(
            id,
            kind,
            format!("`{field}` must be positive, got {value}"),
        ));
    }
    Ok(value)
}

fn required_positive_f64(
    id: &str,
    kind: &str,
    field: &str,
    value: Option<f64>,
) -> Result<f64, String> {
    let value = value
        .ok_or_else(|| drc_rule_error(id, kind, format!("missing required `{field}` parameter")))?;
    if !value.is_finite() || value <= 0.0 {
        return Err(drc_rule_error(
            id,
            kind,
            format!("`{field}` must be finite and positive, got {value}"),
        ));
    }
    Ok(value)
}

fn required_fraction(id: &str, kind: &str, field: &str, value: Option<f64>) -> Result<f64, String> {
    let value = value
        .ok_or_else(|| drc_rule_error(id, kind, format!("missing required `{field}` parameter")))?;
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(drc_rule_error(
            id,
            kind,
            format!("`{field}` must be finite and in [0, 1], got {value}"),
        ));
    }
    Ok(value)
}

impl Deck {
    /// Build a `Deck` from a filled [`VerifySchema`].
    pub fn from_schema(schema: VerifySchema) -> Result<Deck, String> {
        let mut gds_pairs = std::collections::HashMap::new();
        for (name, &(layer, datatype)) in &schema.layers {
            if name.trim().is_empty() {
                return Err("layer name must not be empty".into());
            }
            if layer < 0
                || layer > i32::from(i16::MAX)
                || datatype < 0
                || datatype > i32::from(i16::MAX)
            {
                return Err(format!(
                    "layer `{name}` has GDS pair ({layer}, {datatype}) outside the supported non-negative i16 range"
                ));
            }
            if let Some(previous) = gds_pairs.insert((layer, datatype), name.as_str()) {
                return Err(format!(
                    "layers `{previous}` and `{name}` share duplicate GDS pair ({layer}, {datatype})"
                ));
            }
        }
        let layer_defs: HashMap<String, LayerDef> = schema
            .layers
            .into_iter()
            .map(|(name, (layer, datatype))| (name, LayerDef { layer, datatype }))
            .collect();
        let layers = LayerTable::from_defs(&layer_defs);
        let lid = |name: Option<&str>| -> Result<LayerId, String> {
            let n = name.ok_or_else(|| "missing layer name".to_string())?;
            layers.id(n).ok_or_else(|| format!("unknown layer '{}'", n))
        };

        let mut drc_rules = Vec::new();
        let mut rule_ids = std::collections::HashSet::new();
        for r in &schema.drc_rules {
            if r.kind.trim().is_empty() {
                return Err("DRC rule kind must not be empty".into());
            }
            let id = if r.id.trim().is_empty() {
                r.kind.clone()
            } else {
                r.id.clone()
            };
            if id.trim().is_empty() {
                return Err("DRC rule ID must not be empty".into());
            }
            if !rule_ids.insert(id.clone()) {
                return Err(format!("duplicate DRC rule ID `{id}`"));
            }
            let kind = r.kind.as_str();
            macro_rules! rule {
                ($variant:ident { $($field:ident: $value:expr),* $(,)? }) => {
                    DrcRuleParam::$variant { id: id.clone(), $($field: $value),* }
                };
            }
            macro_rules! positive {
                ($field:ident) => {
                    required_positive_i32(&id, kind, stringify!($field), r.$field)
                };
            }
            macro_rules! fraction {
                ($field:ident) => {
                    required_fraction(&id, kind, stringify!($field), r.$field)
                };
            }
            let min_i32 = || required_positive_i32_from_i64(&id, kind, "min", r.min);
            let layer = || lid(r.layer.as_deref()).map_err(|e| drc_rule_error(&id, kind, e));
            let layer_b = || lid(r.layer_b.as_deref()).map_err(|e| drc_rule_error(&id, kind, e));
            let outer = || lid(r.outer.as_deref()).map_err(|e| drc_rule_error(&id, kind, e));
            let inner = || lid(r.inner.as_deref()).map_err(|e| drc_rule_error(&id, kind, e));

            let rule = match kind {
                "min_width" => rule!(MinWidth {
                    layer: layer()?,
                    min: min_i32()?
                }),
                "min_spacing" => rule!(MinSpacing {
                    layer: layer()?,
                    min: min_i32()?
                }),
                "min_spacing_diff" => rule!(MinSpacingDiff {
                    a: layer()?,
                    b: layer_b()?,
                    min: min_i32()?
                }),
                "min_enclosure" | "well_enclosure" => rule!(MinEnclosure {
                    outer: outer()?,
                    inner: inner()?,
                    min: min_i32()?
                }),
                "min_extension" => rule!(MinExtension {
                    layer: layer()?,
                    reference: lid(r.reference.as_deref())
                        .map_err(|e| drc_rule_error(&id, kind, e))?,
                    min: min_i32()?
                }),
                "min_area" => rule!(MinArea {
                    layer: layer()?,
                    min: required_positive_i64(&id, kind, "min", r.min)?
                }),
                "max_width" => rule!(MaxWidth {
                    layer: layer()?,
                    max: positive!(max)?
                }),
                "notch" => rule!(Notch {
                    layer: layer()?,
                    min: min_i32()?
                }),
                "min_edge_length" => rule!(MinEdgeLength {
                    layer: layer()?,
                    min: min_i32()?
                }),
                "off_grid" => rule!(OffGrid {
                    grid: positive!(grid)?
                }),
                "angle" => {
                    let allowed = r.allowed.clone().ok_or_else(|| {
                        drc_rule_error(&id, kind, "missing required `allowed` parameter")
                    })?;
                    if allowed.is_empty() {
                        return Err(drc_rule_error(&id, kind, "`allowed` must not be empty"));
                    }
                    if let Some(angle) = allowed.iter().find(|&&angle| !(0..180).contains(&angle)) {
                        return Err(drc_rule_error(
                            &id,
                            kind,
                            format!("allowed angle {angle} is outside [0, 180)"),
                        ));
                    }
                    rule!(Angle { allowed: allowed })
                }
                "min_density" => rule!(MinDensity {
                    layer: layer()?,
                    window: positive!(window)?,
                    min_frac: fraction!(min_frac)?
                }),
                "max_density" => rule!(MaxDensity {
                    layer: layer()?,
                    window: positive!(window)?,
                    max_frac: fraction!(max_frac)?
                }),
                "overlap" => rule!(Overlap {
                    a: layer()?,
                    b: layer_b()?,
                    min: min_i32()?
                }),
                "corner_to_corner" => rule!(CornerToCorner {
                    layer: layer()?,
                    min: min_i32()?
                }),
                "antenna" => rule!(Antenna {
                    layer: layer()?,
                    ratio: required_positive_f64(&id, kind, "ratio", r.ratio)?
                }),
                "antenna_car" => {
                    let stack = r.layers.as_ref().ok_or_else(|| {
                        drc_rule_error(&id, kind, "missing required `layers` parameter")
                    })?;
                    if stack.is_empty() {
                        return Err(drc_rule_error(&id, kind, "`layers` must not be empty"));
                    }
                    let mut seen = std::collections::HashSet::new();
                    let mut stack_ids = Vec::with_capacity(stack.len());
                    for name in stack {
                        if !seen.insert(name) {
                            return Err(drc_rule_error(
                                &id,
                                kind,
                                format!("duplicate layer `{name}` in antenna stack"),
                            ));
                        }
                        stack_ids.push(lid(Some(name)).map_err(|e| drc_rule_error(&id, kind, e))?);
                    }
                    let diode = r
                        .diode_layer
                        .as_deref()
                        .map(|name| lid(Some(name)).map_err(|e| drc_rule_error(&id, kind, e)))
                        .transpose()?;
                    rule!(AntennaCar {
                        layers: stack_ids,
                        ratio: required_positive_f64(&id, kind, "ratio", r.ratio)?,
                        diode: diode
                    })
                }
                "eol_spacing" => rule!(EolSpacing {
                    layer: layer()?,
                    eol_width: positive!(eol_width)?,
                    eol_spacing: positive!(eol_spacing)?
                }),
                "wide_dependent_spacing" => rule!(WideDependentSpacing {
                    layer: layer()?,
                    width_threshold: positive!(width_threshold)?,
                    wide_spacing: positive!(wide_spacing)?
                }),
                "prl_spacing" => rule!(PrlSpacing {
                    layer: layer()?,
                    prl_threshold: positive!(prl_threshold)?,
                    prl_spacing: positive!(prl_spacing)?
                }),
                "asymmetric_enclosure" => rule!(AsymmetricEnclosure {
                    outer: outer()?,
                    inner: inner()?,
                    min_one_side: min_i32()?
                }),
                "min_enclosed_area" => rule!(MinEnclosedArea {
                    layer: layer()?,
                    min_hole_area: required_positive_i64(&id, kind, "min", r.min)?
                }),
                "cheesing" => rule!(Cheesing {
                    layer: layer()?,
                    max_area_no_slot: i64::from(positive!(max)?)
                }),
                "redundant_via" => {
                    let min_count = positive!(min_count)?;
                    if min_count < 2 {
                        return Err(drc_rule_error(
                            &id,
                            kind,
                            format!("`min_count` must be at least 2, got {min_count}"),
                        ));
                    }
                    rule!(RedundantVia {
                        layer: layer()?,
                        min_count: min_count,
                        within: positive!(within)?
                    })
                }
                "via_array_spacing" => {
                    let array_threshold = positive!(array_threshold)?;
                    if array_threshold < 2 {
                        return Err(drc_rule_error(
                            &id,
                            kind,
                            format!("`array_threshold` must be at least 2, got {array_threshold}"),
                        ));
                    }
                    rule!(ViaArraySpacing {
                        layer: layer()?,
                        array_threshold: array_threshold,
                        array_spacing: positive!(array_spacing)?
                    })
                }
                "max_distance_to_tap" => rule!(MaxDistanceToTap {
                    diff_layer: layer()?,
                    tap_layer: layer_b()?,
                    max_dist: positive!(max_dist)?
                }),
                "multi_patterning" => {
                    let num_colors = positive!(num_colors)?;
                    if !(2..=64).contains(&num_colors) {
                        return Err(drc_rule_error(
                            &id,
                            kind,
                            format!("`num_colors` must be in [2, 64], got {num_colors}"),
                        ));
                    }
                    rule!(MultiPatterning {
                        layer: layer()?,
                        num_colors: num_colors,
                        color_spacing: min_i32()?
                    })
                }
                other => return Err(drc_rule_error(&id, kind, format!("unknown kind `{other}`"))),
            };
            // Disabled entries are still fully parsed and validated.  This
            // catches unsupported kinds, misspelled layers and malformed units
            // in the declared deck inventory; `enabled` controls execution,
            // not whether the schema is understood.
            if r.enabled {
                drc_rules.push(rule);
            }
        }
        drc_rules.sort_by(|a, b| a.id().cmp(b.id()));

        let mut pex = HashMap::new();
        for (name, p) in schema.pex {
            let id = layers
                .id(&name)
                .ok_or_else(|| format!("PEX parameters reference unknown layer `{name}`"))?;
            for (field, value) in [
                ("sheet_res_ohm_sq", p.sheet_res_ohm_sq),
                ("area_cap_af_um2", p.area_cap_af_um2),
                ("fringe_cap_af_um", p.fringe_cap_af_um),
                ("coupling_cap_af_um", p.coupling_cap_af_um),
                ("coupling_ref_spacing_nm", p.coupling_ref_spacing_nm),
                ("via_res_ohm", p.via_res_ohm),
                ("interlayer_cap_af_um2", p.interlayer_cap_af_um2),
                ("thickness_nm", p.thickness_nm),
                ("height_nm", p.height_nm),
                ("dielectric_k", p.dielectric_k),
            ] {
                if !value.is_finite() || value < 0.0 {
                    return Err(format!(
                        "PEX layer `{name}`: `{field}` must be finite and non-negative, got {value}"
                    ));
                }
            }
            if p.coupling_cap_af_um > 0.0 && p.coupling_ref_spacing_nm <= 0.0 {
                return Err(format!(
                    "PEX layer `{name}`: `coupling_ref_spacing_nm` must be positive when \
                     `coupling_cap_af_um` is enabled"
                ));
            }
            pex.insert(id, p);
        }

        // Resolve connectivity schema → ConnectivityConfig
        let connectivity = {
            let cs = &schema.connectivity;
            if cs.conductors.is_empty() && cs.vias.is_empty() {
                ConnectivityConfig::default()
            } else {
                if cs.conductors.is_empty() {
                    return Err(
                        "connectivity schema declares vias but contains no conductors".into(),
                    );
                }
                let mut conductor_names = std::collections::HashSet::new();
                let conductors = cs
                    .conductors
                    .iter()
                    .map(|name| {
                        if !conductor_names.insert(name.as_str()) {
                            return Err(format!(
                                "connectivity conductor layer `{name}` is duplicated"
                            ));
                        }
                        layers.id(name).ok_or_else(|| {
                            format!("connectivity conductor references unknown layer `{name}`")
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let mut vias = Vec::with_capacity(cs.vias.len());
                let mut via_layers = std::collections::HashSet::new();
                for via in &cs.vias {
                    if !via_layers.insert(via.layer.as_str()) {
                        return Err(format!(
                            "connectivity cut layer `{}` has duplicate via declarations",
                            via.layer,
                        ));
                    }
                    let via_id = layers.id(&via.layer).ok_or_else(|| {
                        format!(
                            "connectivity via references unknown cut layer `{}`",
                            via.layer
                        )
                    })?;
                    if via.connects.is_empty() {
                        return Err(format!(
                            "connectivity via `{}` must connect at least one conductor layer",
                            via.layer,
                        ));
                    }
                    let mut connected_names = std::collections::HashSet::new();
                    let connects = via
                        .connects
                        .iter()
                        .map(|name| {
                            if !connected_names.insert(name.as_str()) {
                                return Err(format!(
                                    "connectivity via `{}` repeats conductor layer `{name}`",
                                    via.layer,
                                ));
                            }
                            if !conductor_names.contains(name.as_str()) {
                                return Err(format!(
                                    "connectivity via `{}` references layer `{name}` that is not declared as a conductor",
                                    via.layer,
                                ));
                            }
                            layers.id(name).ok_or_else(|| {
                                format!(
                                    "connectivity via `{}` references unknown conductor layer `{name}`",
                                    via.layer,
                                )
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    vias.push((via_id, connects));
                }
                ConnectivityConfig { conductors, vias }
            }
        };

        if !schema.erc.antenna_ratio.is_finite()
            || schema.erc.antenna_ratio <= 0.0
            || schema.erc.em_min_width_nm <= 0
            || !schema.erc.p2p_r_limit_ohm.is_finite()
            || schema.erc.p2p_r_limit_ohm <= 0.0
            || schema.erc.tie_max_dist_nm <= 0
        {
            return Err(
                "ERC thresholds must be finite and positive in their documented units".into(),
            );
        }

        // Resolve device schema → DeviceConfig
        let devices = {
            let ds = &schema.devices;
            let device_layer = |device_kind: &str,
                                rule_name: &str,
                                role: &str,
                                layer_name: &str|
             -> Result<LayerId, String> {
                layers.id(layer_name).ok_or_else(|| {
                    format!(
                        "device-recognition {device_kind} rule `{rule_name}` references unknown \
                         {role} layer `{layer_name}`"
                    )
                })
            };

            let mut mos_rules = Vec::with_capacity(ds.mos_rules.len());
            let mut mos_names = std::collections::HashSet::new();
            for rule in &ds.mos_rules {
                if rule.name.trim().is_empty() || !mos_names.insert(rule.name.as_str()) {
                    return Err(format!(
                        "device-recognition MOS rule has an empty or duplicate name `{}`",
                        rule.name
                    ));
                }
                if !matches!(rule.device_type.as_str(), "nmos" | "pmos") {
                    return Err(format!(
                        "device-recognition MOS rule `{}` has unsupported device type `{}`",
                        rule.name, rule.device_type
                    ));
                }
                if rule
                    .device_class
                    .as_ref()
                    .is_some_and(|class| class.trim().is_empty())
                {
                    return Err(format!(
                        "device-recognition MOS rule `{}` has an empty device class",
                        rule.name
                    ));
                }
                let mut flavor_layers = std::collections::HashSet::new();
                for (layer_name, flavor) in &rule.flavor_markers {
                    if !matches!(
                        flavor.as_str(),
                        "lvt" | "Lvt" | "LVT" | "hvt" | "Hvt" | "HVT"
                    ) {
                        return Err(format!(
                            "device-recognition MOS rule `{}` has unsupported flavor `{flavor}`",
                            rule.name
                        ));
                    }
                    if !flavor_layers.insert(layer_name.as_str()) {
                        return Err(format!(
                            "device-recognition MOS rule `{}` repeats flavor-marker layer `{layer_name}`",
                            rule.name
                        ));
                    }
                }
                let flavor_markers = rule
                    .flavor_markers
                    .iter()
                    .map(|(layer_name, flavor)| {
                        device_layer("MOS", &rule.name, "flavor marker", layer_name)
                            .map(|layer| (layer, flavor.clone()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let well_layer = rule
                    .well_layer
                    .as_deref()
                    .map(|name| device_layer("MOS", &rule.name, "well", name))
                    .transpose()?;
                mos_rules.push(MosRule {
                    name: rule.name.clone(),
                    gate_layer: device_layer("MOS", &rule.name, "gate", &rule.gate_layer)?,
                    channel_layer: device_layer("MOS", &rule.name, "channel", &rule.channel_layer)?,
                    type_implant: device_layer(
                        "MOS",
                        &rule.name,
                        "type implant",
                        &rule.type_implant,
                    )?,
                    device_type: rule.device_type.clone(),
                    flavor_markers,
                    well_layer,
                    device_class: rule.device_class.clone(),
                });
            }

            let mut bjt_rules = Vec::with_capacity(ds.bjt_rules.len());
            let mut bjt_names = std::collections::HashSet::new();
            for rule in &ds.bjt_rules {
                if rule.name.trim().is_empty() || !bjt_names.insert(rule.name.as_str()) {
                    return Err(format!(
                        "device-recognition BJT rule has an empty or duplicate name `{}`",
                        rule.name
                    ));
                }
                if !matches!(rule.device_type.as_str(), "npn" | "pnp") {
                    return Err(format!(
                        "device-recognition BJT rule `{}` has unsupported device type `{}`",
                        rule.name, rule.device_type
                    ));
                }
                bjt_rules.push(BjtRule {
                    name: rule.name.clone(),
                    collector_layer: device_layer(
                        "BJT",
                        &rule.name,
                        "collector",
                        &rule.collector_layer,
                    )?,
                    base_layer: device_layer("BJT", &rule.name, "base", &rule.base_layer)?,
                    emitter_layer: device_layer("BJT", &rule.name, "emitter", &rule.emitter_layer)?,
                    type_marker: device_layer("BJT", &rule.name, "type marker", &rule.type_marker)?,
                    device_type: rule.device_type.clone(),
                });
            }

            let mut resistor_rules = Vec::with_capacity(ds.resistor_rules.len());
            let mut resistor_names = std::collections::HashSet::new();
            for rule in &ds.resistor_rules {
                if rule.name.trim().is_empty() || !resistor_names.insert(rule.name.as_str()) {
                    return Err(format!(
                        "device-recognition resistor rule has an empty or duplicate name `{}`",
                        rule.name
                    ));
                }
                resistor_rules.push(ResistorRule {
                    name: rule.name.clone(),
                    body_layer: device_layer("resistor", &rule.name, "body", &rule.body_layer)?,
                    marker_layer: device_layer(
                        "resistor",
                        &rule.name,
                        "marker",
                        &rule.marker_layer,
                    )?,
                    terminal_layer: device_layer(
                        "resistor",
                        &rule.name,
                        "terminal",
                        &rule.terminal_layer,
                    )?,
                });
            }

            let mut diode_rules = Vec::with_capacity(ds.diode_rules.len());
            let mut diode_names = std::collections::HashSet::new();
            for rule in &ds.diode_rules {
                if rule.name.trim().is_empty() || !diode_names.insert(rule.name.as_str()) {
                    return Err(format!(
                        "device-recognition diode rule has an empty or duplicate name `{}`",
                        rule.name
                    ));
                }
                diode_rules.push(DiodeRule {
                    name: rule.name.clone(),
                    anode_layer: device_layer("diode", &rule.name, "anode", &rule.anode_layer)?,
                    cathode_layer: device_layer(
                        "diode",
                        &rule.name,
                        "cathode",
                        &rule.cathode_layer,
                    )?,
                    implant_layer: device_layer(
                        "diode",
                        &rule.name,
                        "implant",
                        &rule.implant_layer,
                    )?,
                });
            }

            let mut cap_rules = Vec::with_capacity(ds.cap_rules.len());
            let mut cap_names = std::collections::HashSet::new();
            for rule in &ds.cap_rules {
                if rule.name.trim().is_empty() || !cap_names.insert(rule.name.as_str()) {
                    return Err(format!(
                        "device-recognition capacitor rule has an empty or duplicate name `{}`",
                        rule.name
                    ));
                }
                let marker_layer = rule
                    .marker_layer
                    .as_deref()
                    .map(|name| device_layer("capacitor", &rule.name, "marker", name))
                    .transpose()?;
                cap_rules.push(CapRule {
                    name: rule.name.clone(),
                    top_layer: device_layer("capacitor", &rule.name, "top plate", &rule.top_layer)?,
                    bottom_layer: device_layer(
                        "capacitor",
                        &rule.name,
                        "bottom plate",
                        &rule.bottom_layer,
                    )?,
                    marker_layer,
                });
            }
            DeviceConfig {
                mos_rules,
                bjt_rules,
                resistor_rules,
                diode_rules,
                cap_rules,
            }
        };

        Ok(Deck {
            layers,
            drc_rules,
            pex,
            pex_method: PexMethod::default(),
            dbu_nm: 1.0,
            lvs_cut_required: schema.lvs.cut_required,
            strict: false,
            connectivity,
            devices,
            w_tolerance: schema.lvs.w_tolerance,
            l_tolerance: schema.lvs.l_tolerance,
            fail_on_floating: schema.lvs.fail_on_floating,
            intra_layer_touch: schema.connectivity.intra_layer_touch,
            global_nets: schema.connectivity.global_nets.clone(),
            erc: schema.erc,
            device_catalog: HashMap::new(),
        })
    }

    /// Parse a PDK deck from a JSON string. Delegates to `from_schema` internally.
    pub fn from_json(text: &str) -> Result<Self, String> {
        use crate::schema::{drc_rules_from_json, parse_device_catalog};

        #[derive(Deserialize)]
        struct Doc {
            #[serde(default)]
            layers: HashMap<String, LayerDef>,
            #[serde(default)]
            drc: serde_json::Value,
            #[serde(default)]
            pex: HashMap<String, PexLayerParams>,
            #[serde(default)]
            lvs: LvsRaw,
            #[serde(default)]
            connectivity: ConnectivitySchema,
            #[serde(default)]
            device_recognition: DeviceSchema,
            #[serde(default)]
            erc: ErcParams,
            #[serde(default)]
            devices: serde_json::Value,
            #[serde(default)]
            pex_method: PexMethod,
        }

        #[derive(Deserialize, Default)]
        #[serde(deny_unknown_fields)]
        struct LvsRaw {
            #[serde(default)]
            cut_required: bool,
        }

        let doc: Doc = serde_json::from_str(text).map_err(|e| e.to_string())?;

        let layers = doc
            .layers
            .into_iter()
            .map(|(name, def)| (name, (def.layer, def.datatype)))
            .collect();

        let connectivity =
            if doc.connectivity.conductors.is_empty() && doc.connectivity.vias.is_empty() {
                ConnectivitySchema::default()
            } else {
                ConnectivitySchema {
                    conductors: doc.connectivity.conductors,
                    vias: doc.connectivity.vias,
                    intra_layer_touch: doc.connectivity.intra_layer_touch,
                    global_nets: doc.connectivity.global_nets,
                }
            };

        let mut deck = Self::from_schema(VerifySchema {
            layers,
            drc_rules: drc_rules_from_json(&doc.drc)?,
            pex: doc.pex,
            erc: doc.erc,
            lvs: LvsSchema {
                cut_required: doc.lvs.cut_required,
                ..Default::default()
            },
            connectivity,
            devices: doc.device_recognition,
        })?;

        deck.device_catalog = parse_device_catalog(&doc.devices)?;
        deck.pex_method = doc.pex_method;
        Ok(deck)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{
        BjtRuleSchema, CapRuleSchema, ConnectivitySchema, DeviceSchema, DiodeRuleSchema,
        DrcRuleSchema, LvsSchema, MosRuleSchema, ResistorRuleSchema, VerifySchema, ViaSchema,
    };

    fn base_schema() -> VerifySchema {
        VerifySchema {
            layers: [
                ("known".to_string(), (1, 0)),
                ("met1".to_string(), (2, 0)),
                ("met2".to_string(), (3, 0)),
            ]
            .into_iter()
            .collect(),
            drc_rules: Vec::new(),
            pex: HashMap::new(),
            erc: ErcParams::default(),
            lvs: LvsSchema::default(),
            connectivity: ConnectivitySchema::default(),
            devices: DeviceSchema::default(),
        }
    }

    // ponytail: repeated_rule_kinds_run_with_distinct_ids moved to engine (needs DRC)

    #[test]
    fn explicit_array_and_legacy_map_encodings_are_supported() {
        let array = Deck::from_json(
            r#"{
                "layers": {"met1": {"layer": 1, "datatype": 0}},
                "drc": [
                    {"id": "M1.W.1", "kind": "min_width", "layer": "met1", "min": 100}
                ]
            }"#,
        )
        .expect("explicit DRC array");
        assert_eq!(array.drc_rules[0].id(), "M1.W.1");

        let legacy = Deck::from_json(
            r#"{
                "layers": {"met1": {"layer": 1, "datatype": 0}},
                "drc": {"min_width": {"layer": "met1", "min": 100}}
            }"#,
        )
        .expect("legacy DRC map");
        assert_eq!(legacy.drc_rules[0].id(), "min_width");

        let duplicate = Deck::from_json(
            r#"{
                "layers": {"met1": {"layer": 1, "datatype": 0}},
                "drc": [
                    {"id": "DUP", "kind": "min_width", "layer": "met1", "min": 100},
                    {"id": "DUP", "kind": "min_spacing", "layer": "met1", "min": 100}
                ]
            }"#,
        )
        .err()
        .expect("duplicate rule IDs must fail");
        assert!(
            duplicate.contains("duplicate DRC rule ID `DUP`"),
            "{duplicate}"
        );
    }

    #[test]
    fn rule_ids_are_independent_in_from_schema_too() {
        let mut schema = base_schema();
        schema.drc_rules = vec![
            DrcRuleSchema {
                id: "M1.W".into(),
                kind: "min_width".into(),
                layer: Some("met1".into()),
                min: Some(100),
                ..Default::default()
            },
            DrcRuleSchema {
                id: "M2.W".into(),
                kind: "min_width".into(),
                layer: Some("met2".into()),
                min: Some(200),
                ..Default::default()
            },
        ];
        let deck = Deck::from_schema(schema).expect("schema");
        assert_eq!(
            deck.drc_rules
                .iter()
                .map(DrcRuleParam::id)
                .collect::<Vec<_>>(),
            ["M1.W", "M2.W"],
        );
        // ponytail: run_drc assertion moved to engine (needs DRC crate)

        assert!(
            DrcRuleSchema::default().enabled,
            "programmatic schema omission must match JSON's enabled=true default"
        );
    }

    #[test]
    fn malformed_numeric_rules_fail_construction() {
        let cases = [
            (
                r#"{"kind":"min_width","layer":"met1","min":0}"#,
                "must be positive",
            ),
            (
                r#"{"kind":"min_width","layer":"met1","min":-1}"#,
                "must be positive",
            ),
            (
                r#"{"kind":"min_width","layer":"met1","min":2147483648}"#,
                "outside the i32 range",
            ),
            (
                r#"{"kind":"max_density","layer":"met1","window":100,"max_frac":1.1}"#,
                "in [0, 1]",
            ),
            (r#"{"kind":"angle","allowed":[]}"#, "must not be empty"),
            (
                r#"{"kind":"multi_patterning","layer":"met1","min":100,"num_colors":1}"#,
                "in [2, 64]",
            ),
        ];
        for (body, expected) in cases {
            let json = format!(
                r#"{{"layers":{{"met1":{{"layer":1,"datatype":0}}}},"drc":{{"R":{body}}}}}"#
            );
            let error = Deck::from_json(&json)
                .err()
                .expect("invalid rule must fail");
            assert!(
                error.contains(expected),
                "expected `{expected}` in error, got `{error}`"
            );
        }

        let mut schema = base_schema();
        schema.drc_rules.push(DrcRuleSchema {
            id: "DENS.NAN".into(),
            kind: "min_density".into(),
            enabled: true,
            layer: Some("met1".into()),
            window: Some(100),
            min_frac: Some(f64::NAN),
            ..Default::default()
        });
        let error = Deck::from_schema(schema)
            .err()
            .expect("NaN density must fail");
        assert!(error.contains("finite"), "unexpected error: {error}");
    }

    #[test]
    fn unknown_drc_properties_fail_construction() {
        let error = Deck::from_json(
            r#"{
                "layers": {"met1": {"layer": 1, "datatype": 0}},
                "drc": {
                    "M1.W.1": {
                        "kind": "min_width",
                        "layer": "met1",
                        "mni": 100,
                        "min": 100
                    }
                }
            }"#,
        )
        .err()
        .expect("an unknown DRC property must not be ignored");
        assert!(
            error.contains("M1.W.1") && error.contains("unknown property `mni`"),
            "unexpected error: {error}"
        );

        let error = Deck::from_json(
            r#"{
                "layers": {"met1": {"layer": 1, "datatype": 0}},
                "drc": {"UNKNOWN": {"kind": "min_wdith", "enabled": false}}
            }"#,
        )
        .err()
        .expect("disabled operations must still be understood by the engine");
        assert!(error.contains("unknown kind `min_wdith`"), "{error}");

        let error = Deck::from_json(
            r#"{
                "layers": {"met1": {"layer": 1, "datatype": 0}},
                "drc": {
                    "M2.W": {
                        "kind": "min_width",
                        "enabled": false,
                        "layer": "ghost",
                        "min": 100
                    }
                }
            }"#,
        )
        .err()
        .expect("disabled rules must not hide unknown layer references");
        assert!(error.contains("unknown layer 'ghost'"), "{error}");
    }

    #[test]
    fn unknown_pex_and_connectivity_layers_are_errors() {
        let mut schema = base_schema();
        schema.pex.insert(
            "ghost".into(),
            PexLayerParams {
                sheet_res_ohm_sq: 1.0,
                area_cap_af_um2: 1.0,
                fringe_cap_af_um: 1.0,
                coupling_cap_af_um: 1.0,
                coupling_ref_spacing_nm: 1.0,
                via_res_ohm: 0.0,
                interlayer_cap_af_um2: 0.0,
                thickness_nm: 0.0,
                height_nm: 0.0,
                dielectric_k: 0.0,
            },
        );
        let error = Deck::from_schema(schema)
            .err()
            .expect("unknown PEX layer must fail");
        assert!(error.contains("PEX") && error.contains("ghost"), "{error}");

        let mut schema = base_schema();
        schema.pex.insert(
            "met1".into(),
            PexLayerParams {
                sheet_res_ohm_sq: f64::NAN,
                area_cap_af_um2: 1.0,
                fringe_cap_af_um: 1.0,
                coupling_cap_af_um: 1.0,
                coupling_ref_spacing_nm: 1.0,
                via_res_ohm: 0.0,
                interlayer_cap_af_um2: 0.0,
                thickness_nm: 0.0,
                height_nm: 0.0,
                dielectric_k: 0.0,
            },
        );
        let error = Deck::from_schema(schema)
            .err()
            .expect("non-finite PEX coefficient must fail");
        assert!(
            error.contains("sheet_res_ohm_sq") && error.contains("finite"),
            "{error}"
        );

        let mut schema = base_schema();
        schema.pex.insert(
            "met1".into(),
            PexLayerParams {
                sheet_res_ohm_sq: 1.0,
                area_cap_af_um2: 1.0,
                fringe_cap_af_um: 1.0,
                coupling_cap_af_um: 1.0,
                coupling_ref_spacing_nm: 0.0,
                via_res_ohm: 0.0,
                interlayer_cap_af_um2: 0.0,
                thickness_nm: 0.0,
                height_nm: 0.0,
                dielectric_k: 0.0,
            },
        );
        let error = Deck::from_schema(schema)
            .err()
            .expect("enabled coupling needs positive reference spacing");
        assert!(
            error.contains("coupling_ref_spacing_nm") && error.contains("positive"),
            "{error}"
        );

        let mut schema = base_schema();
        schema.connectivity.conductors = vec!["ghost".into()];
        let error = Deck::from_schema(schema)
            .err()
            .expect("unknown conductor must fail");
        assert!(
            error.contains("connectivity conductor") && error.contains("ghost"),
            "{error}"
        );

        let mut schema = base_schema();
        schema.connectivity.conductors = vec!["known".into()];
        schema.connectivity.vias = vec![ViaSchema {
            layer: "ghost".into(),
            connects: vec!["known".into()],
        }];
        let error = Deck::from_schema(schema)
            .err()
            .expect("unknown via cut layer must fail");
        assert!(
            error.contains("connectivity via") && error.contains("ghost"),
            "{error}"
        );

        let mut schema = base_schema();
        schema.connectivity.conductors = vec!["known".into()];
        schema.connectivity.vias = vec![ViaSchema {
            layer: "met1".into(),
            connects: vec!["known".into(), "ghost".into()],
        }];
        let error = Deck::from_schema(schema)
            .err()
            .expect("unknown via conductor must fail");
        assert!(
            error.contains("connectivity via") && error.contains("ghost"),
            "{error}"
        );
    }

    #[test]
    fn every_device_class_rejects_unknown_layer_references() {
        let device_cases: Vec<(&str, DeviceSchema)> = vec![
            (
                "MOS",
                DeviceSchema {
                    mos_rules: vec![MosRuleSchema {
                        name: "nmos".into(),
                        gate_layer: "known".into(),
                        channel_layer: "known".into(),
                        type_implant: "known".into(),
                        device_type: "nmos".into(),
                        flavor_markers: vec![("ghost".into(), "lvt".into())],
                        well_layer: None,
                        device_class: None,
                    }],
                    ..Default::default()
                },
            ),
            (
                "BJT",
                DeviceSchema {
                    bjt_rules: vec![BjtRuleSchema {
                        name: "npn".into(),
                        collector_layer: "known".into(),
                        base_layer: "known".into(),
                        emitter_layer: "known".into(),
                        type_marker: "ghost".into(),
                        device_type: "npn".into(),
                    }],
                    ..Default::default()
                },
            ),
            (
                "resistor",
                DeviceSchema {
                    resistor_rules: vec![ResistorRuleSchema {
                        name: "res".into(),
                        body_layer: "known".into(),
                        marker_layer: "known".into(),
                        terminal_layer: "ghost".into(),
                    }],
                    ..Default::default()
                },
            ),
            (
                "diode",
                DeviceSchema {
                    diode_rules: vec![DiodeRuleSchema {
                        name: "dio".into(),
                        anode_layer: "known".into(),
                        cathode_layer: "known".into(),
                        implant_layer: "ghost".into(),
                    }],
                    ..Default::default()
                },
            ),
            (
                "capacitor",
                DeviceSchema {
                    cap_rules: vec![CapRuleSchema {
                        name: "cap".into(),
                        top_layer: "known".into(),
                        bottom_layer: "known".into(),
                        marker_layer: Some("ghost".into()),
                    }],
                    ..Default::default()
                },
            ),
        ];

        for (kind, devices) in device_cases {
            let mut schema = base_schema();
            schema.devices = devices;
            let error = Deck::from_schema(schema)
                .err()
                .unwrap_or_else(|| panic!("{kind} unknown layer unexpectedly accepted"));
            assert!(
                error.contains("device-recognition")
                    && error.contains(kind)
                    && error.contains("ghost"),
                "unexpected {kind} error: {error}"
            );
        }
    }

    #[test]
    fn unsupported_device_and_flavor_names_are_errors() {
        let mut schema = base_schema();
        schema.devices.mos_rules.push(MosRuleSchema {
            name: "mystery".into(),
            gate_layer: "known".into(),
            channel_layer: "known".into(),
            type_implant: "known".into(),
            device_type: "gaafet".into(),
            flavor_markers: Vec::new(),
            well_layer: None,
            device_class: None,
        });
        let error = Deck::from_schema(schema)
            .err()
            .expect("an unsupported MOS kind must not default to NMOS");
        assert!(
            error.contains("unsupported device type `gaafet`"),
            "{error}"
        );

        let mut schema = base_schema();
        schema.devices.mos_rules.push(MosRuleSchema {
            name: "nmos".into(),
            gate_layer: "known".into(),
            channel_layer: "known".into(),
            type_implant: "known".into(),
            device_type: "nmos".into(),
            flavor_markers: vec![("known".into(), "ulvt".into())],
            well_layer: None,
            device_class: None,
        });
        let error = Deck::from_schema(schema)
            .err()
            .expect("an unsupported flavor must not default to standard Vt");
        assert!(error.contains("unsupported flavor `ulvt`"), "{error}");

        let mut schema = base_schema();
        schema.devices.bjt_rules.push(BjtRuleSchema {
            name: "q".into(),
            collector_layer: "known".into(),
            base_layer: "known".into(),
            emitter_layer: "known".into(),
            type_marker: "known".into(),
            device_type: "phototransistor".into(),
        });
        let error = Deck::from_schema(schema)
            .err()
            .expect("an unsupported BJT kind must not default to NPN");
        assert!(
            error.contains("unsupported device type `phototransistor`"),
            "{error}"
        );
    }

    #[test]
    fn deck_metadata_and_nested_properties_fail_closed() {
        let mut schema = base_schema();
        schema.layers.insert("met1_alias".into(), (2, 0));
        let error = Deck::from_schema(schema)
            .err()
            .expect("duplicate GDS pairs make one symbolic layer unreachable");
        assert!(error.contains("duplicate GDS pair (2, 0)"), "{error}");

        let mut schema = base_schema();
        schema
            .layers
            .insert("invalid".into(), (i32::from(i16::MAX) + 1, 0));
        let error = Deck::from_schema(schema)
            .err()
            .expect("the reader stores GDS layer numbers as signed 16-bit values");
        assert!(error.contains("non-negative i16 range"), "{error}");

        let mut schema = base_schema();
        schema.erc.em_min_width_nm = 0;
        let error = Deck::from_schema(schema)
            .err()
            .expect("zero ERC limits must not disable a check implicitly");
        assert!(error.contains("ERC thresholds"), "{error}");

        let mut schema = base_schema();
        schema.connectivity.conductors = vec!["known".into(), "known".into()];
        let error = Deck::from_schema(schema)
            .err()
            .expect("duplicate conductor membership must be rejected");
        assert!(
            error.contains("conductor layer `known` is duplicated"),
            "{error}"
        );

        let error = Deck::from_json(
            r#"{
                "full_pdk_metadata": {"owner": "caller"},
                "layers": {"met1": {"layer": 1, "datatype": 0}},
                "pex": {"met1": {
                    "sheet_res_ohm_sq": 1.0,
                    "area_cap_af_um2": 1.0,
                    "fringe_cap_af_um": 1.0,
                    "coupling_cap_af_um": 0.0,
                    "coupling_ref_spacing_nm": 0.0,
                    "sheet_res_ohm_sqq": 2.0
                }}
            }"#,
        )
        .err()
        .expect("unknown properties inside a recognized PEX section must fail");
        assert!(
            error.contains("unknown field `sheet_res_ohm_sqq`"),
            "{error}"
        );

        // Unrelated top-level sections belong to the complete PDK facade and
        // remain accepted by the standalone verification subset adapter.
        Deck::from_json(
            r#"{
                "full_pdk_metadata": {"owner": "caller"},
                "layers": {"met1": {"layer": 1, "datatype": 0}}
            }"#,
        )
        .expect("unrelated top-level full-PDK sections remain compatible");
    }

    #[test]
    fn device_catalog_expands_prefixes_and_aliases() {
        let deck = Deck::from_json(
            r#"{
                "layers": {"met1": {"layer": 1, "datatype": 0}},
                "devices": {
                    "_prefixes": ["fab__"],
                    "_aliases": {"short": "nfet"},
                    "nfet": {"type": "nmos", "cell": "mosfet", "min_w": 420, "min_l": 150},
                    "pfet": {"type": "pmos", "cell": "mosfet"}
                }
            }"#,
        )
        .expect("device catalog");
        assert_eq!(deck.device_catalog.len(), 5);
        assert!(deck.device_catalog.contains_key("nfet"));
        assert!(deck.device_catalog.contains_key("fab__nfet"));
        assert!(deck.device_catalog.contains_key("fab__pfet"));
        assert!(deck.device_catalog.contains_key("short"));
        assert_eq!(deck.device_catalog["short"].device_type, "nmos");
    }
}
