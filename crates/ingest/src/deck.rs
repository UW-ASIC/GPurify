//! The PDK deck: process data, and nothing else. Per-chip facts are
//! [`crate::intent`].
//!
//! Limits are physical nanometres, converted against the layout's grid at load
//! exactly or not at all. Rule kinds are interned verbatim and never interpreted
//! here.

use gpurify_geom::{StrId, StrTable};
use crate::narrow;
use gpurify_geom::LayerId;
use gpurify_geom::{prefix::NANO, Dbu, Grid, GridError, Length, Qty};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

/// Why a deck was rejected.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DeckError {
    #[error("malformed deck: {0}")]
    Malformed(String),
    #[error("rule {0} refers to unknown layer {1}")]
    UnknownLayer(String, String),
    #[error("rule {0}: limit {1} nm is not an exact multiple of the grid")]
    OffGrid(String, i64),
    #[error("rule {0} is missing required parameter {1}")]
    MissingParam(String, String),
    #[error("duplicate rule id {0}")]
    DuplicateRule(String),
    #[error("io: {0}")]
    Io(String),
}

/// A parsed, validated, grid-resolved deck.
#[derive(Debug, Default)]
pub struct Deck {
    /// The grid every limit in [`Self::rules`] was converted against. `None`
    /// only on a default-constructed `Deck`, which holds no rules. A deck file
    /// does not declare its own resolution; the grid comes from the layout.
    pub grid: Option<Grid>,
    pub layers: LayerTable,
    pub rules: RuleTable,
    pub connectivity: Connectivity,
    pub devices: DeviceRecognition,
    pub stack: ProcessStack,
}

/// Layer names to ids, and back.
#[derive(Debug, Default)]
pub struct LayerTable {
    /// `LayerId(i)` is named `name[i]`.
    name: Vec<StrId>,
    /// GDS layer/datatype pair each id maps to.
    stream: Vec<(u16, u16)>,
    /// Ids sorted by their name's [`StrId`] — by the id, not the name's bytes.
    by_name: Vec<LayerId>,
    /// Ids sorted by their `(gds_layer, gds_datatype)` pair, then by id, for
    /// [`Self::of_stream`]. Ties broken by id so a deck pointing two names at
    /// one pair still has a total order starting at the lowest id.
    ///
    /// **Base layers only.** A derived layer is computed, not drawn, so no
    /// record in a layout file may map onto one.
    by_stream: Vec<LayerId>,
    /// The id of the first derived layer, and so the number of base ones. A
    /// `u16` and not a `LayerId`: it is a count, one past the last base layer.
    derived_start: u16,
    /// How each derived layer is computed, one row per id from `derived_start`
    /// up.
    derived: DerivedTable,
}

/// The placeholder stream pair recorded for a derived layer, which has none.
/// Not an identity: ask [`LayerTable::is_derived`].
const DERIVED_STREAM: (u16, u16) = (u16::MAX, u16::MAX);

impl LayerTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(
            self.name.len(),
            self.stream.len(),
            "one stream pair per layer"
        );
        debug_assert_eq!(
            self.name.len(),
            self.by_name.len(),
            "one name index entry per layer"
        );
        debug_assert_eq!(
            usize::from(self.derived_start),
            self.by_stream.len(),
            "one stream index entry per base layer, and none for a derived one"
        );
        self.name.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// `None` for a name the deck does not define.
    pub fn id(&self, strings: &StrTable, name: &str) -> Option<LayerId> {
        // `get`, never `intern`: growing the caller's table on a lookup would
        // hand back an id for a layer with no geometry, and a rule against it
        // reports clean.
        let wanted = strings.get(name)?;
        let at = self
            .by_name
            .binary_search_by_key(&wanted, |&LayerId(i)| self.name[usize::from(i)])
            .ok()?;
        let found = self.by_name[at];
        debug_assert_eq!(
            self.name[found.idx()],
            wanted,
            "the index named another layer"
        );
        Some(found)
    }
    pub fn name(&self, layer: LayerId) -> StrId {
        debug_assert!(layer.idx() < self.name.len(), "layer id past the table");
        self.name[layer.idx()]
    }
    /// Which id a GDS layer/datatype pair maps to.
    ///
    /// `partition_point`, not `binary_search_by_key`: it lands on the *first* id
    /// of a run, so two names on one pair answer with the lower id.
    pub fn of_stream(&self, layer: u16, datatype: u16) -> Option<LayerId> {
        let wanted = (layer, datatype);
        let at = self
            .by_stream
            .partition_point(|&LayerId(i)| self.stream[usize::from(i)] < wanted);
        let found = *self.by_stream.get(at)?;
        // A miss lands on the successor of `wanted`, or past the end; both mean
        // the deck does not declare this pair.
        (self.stream[found.idx()] == wanted).then_some(found)
    }

    /// The GDS stream pair a layer writes to. The inverse of [`Self::of_stream`].
    ///
    /// A derived layer answers with [`DERIVED_STREAM`]; a writer should ask
    /// [`Self::is_derived`] and skip those rows, which would duplicate area.
    pub fn stream_of(&self, layer: LayerId) -> (u16, u16) {
        debug_assert!(layer.idx() < self.stream.len(), "layer id past the table");
        self.stream[layer.idx()]
    }

    /// Is this layer computed by the deck rather than drawn in the layout?
    ///
    /// Derived layers take the ids after every base one, which is what lets
    /// `GeometryStore::append_layer` append them to a store grouped by layer.
    pub fn is_derived(&self, layer: LayerId) -> bool {
        debug_assert!(layer.idx() < self.name.len(), "layer id past the table");
        layer.0 >= self.derived_start
    }

    /// How the derived layers are computed, in id order.
    pub fn derived(&self) -> &DerivedTable {
        debug_assert_eq!(
            self.derived.len() + usize::from(self.derived_start),
            self.name.len(),
            "every layer is either base or derived, and no layer is both"
        );
        &self.derived
    }

    /// Add a derived layer, and hand back the id it took.
    ///
    /// Appended, not sorted in: an id above every base layer and every derived
    /// layer declared before it is also the order they can be materialised in.
    /// The name index is kept sorted; the stream index deliberately is not.
    ///
    /// # Panics
    ///
    /// On `u16::MAX + 1` layers, or when `operands` is empty or names a layer at
    /// or above the id being taken — all of which [`parse_deck`] refuses first.
    pub fn push_derived(&mut self, name: StrId, op: DerivedOp, operands: &[LayerId]) -> LayerId {
        let id = LayerId(
            u16::try_from(self.name.len())
                .expect("a deck has tens of layers, and LayerId is a u16"),
        );
        assert!(
            !operands.is_empty(),
            "a derived layer is computed from at least one layer"
        );
        assert!(
            operands.iter().all(|&operand| operand < id),
            "a derived layer names an operand at or above its own id, so \
             materialising it in id order would read a layer that does not exist yet"
        );

        let at = self
            .by_name
            .partition_point(|&LayerId(i)| self.name[usize::from(i)] < name);
        self.name.push(name);
        self.stream.push(DERIVED_STREAM);
        self.by_name.insert(at, id);

        // The CSR's leading zero goes down with the first row.
        if self.derived.operand_start.is_empty() {
            self.derived.operand_start.push(0);
        }
        self.derived.layer.push(id);
        self.derived.op.push(op);
        self.derived.operand.extend_from_slice(operands);
        self.derived
            .operand_start
            .push(narrow(self.derived.operand.len()));

        debug_assert!(
            self.by_name
                .windows(2)
                .all(|pair| self.name[pair[0].idx()] <= self.name[pair[1].idx()]),
            "the by-name index is not ascending, so `id` would miss declared layers"
        );
        debug_assert!(
            self.is_derived(id),
            "a derived layer took a base layer's id"
        );
        debug_assert!(
            self.derived.layer.windows(2).all(|pair| pair[0] < pair[1]),
            "derived ids come out ascending, which is the order they are materialised in"
        );
        id
    }

    /// Build a layer table from `(name, gds_layer, gds_datatype)` entries, where
    /// `LayerId(i)` is `entries[i]`. Both indexes tie-break by id, so a repeat
    /// still gives a total, deterministic order.
    pub fn build(entries: &[(StrId, u16, u16)]) -> Self {
        let count =
            u16::try_from(entries.len()).expect("a deck has tens of layers, and LayerId is a u16");

        let name: Vec<StrId> = entries.iter().map(|&(name, _, _)| name).collect();
        let stream: Vec<(u16, u16)> = entries
            .iter()
            .map(|&(_, layer, datatype)| (layer, datatype))
            .collect();

        let mut by_name: Vec<LayerId> = (0..count).map(LayerId).collect();
        by_name.sort_unstable_by_key(|&LayerId(i)| (name[usize::from(i)], i));

        let mut by_stream: Vec<LayerId> = (0..count).map(LayerId).collect();
        by_stream.sort_unstable_by_key(|&LayerId(i)| (stream[usize::from(i)], i));

        // A table built unsorted does not fail; it resolves some names and
        // misses others.
        debug_assert!(
            by_name
                .windows(2)
                .all(|pair| name[pair[0].idx()] <= name[pair[1].idx()]),
            "the by-name index is not ascending, so `id` would miss declared layers"
        );
        debug_assert!(
            by_stream
                .windows(2)
                .all(|pair| stream[pair[0].idx()] <= stream[pair[1].idx()]),
            "the by-stream index is not ascending, so `of_stream` would drop declared layers"
        );
        debug_assert_eq!(name.len(), entries.len(), "one row per declared layer");
        debug_assert_eq!(name.len(), stream.len(), "one stream pair per layer");
        debug_assert_eq!(name.len(), by_name.len(), "one name index entry per layer");
        debug_assert_eq!(
            name.len(),
            by_stream.len(),
            "one stream index entry per layer"
        );

        Self {
            name,
            stream,
            by_name,
            by_stream,
            // Every entry `build` is handed is a base layer; derived ones
            // arrive through `push_derived` afterwards.
            derived_start: count,
            derived: DerivedTable::default(),
        }
    }
}

/// The operators a deck may spell over layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivedOp {
    /// Intersection. `poly AND diff` is the gate.
    And,
    /// Union.
    Or,
    /// Subtraction. `diff NOT poly` is the source/drain regions.
    Not,
}

/// Layers the deck computes from other layers.
///
/// A row may only name layers with a lower id, so declaration order is
/// evaluation order and a cycle is unspellable. Operands fold left:
/// `{ "op": "not", "layers": ["a", "b", "c"] }` is `(a − b) − c`.
#[derive(Debug, Default)]
pub struct DerivedTable {
    /// The id this row produced. Ascending, and above every base layer.
    layer: Vec<LayerId>,
    op: Vec<DerivedOp>,
    /// `operand[operand_start[i] .. operand_start[i + 1]]` are row `i`'s
    /// operands. CSR, with the usual closing sentinel.
    operand_start: Vec<u32>,
    operand: Vec<LayerId>,
}

impl DerivedTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(
            self.layer.len(),
            self.op.len(),
            "one operator per derived layer"
        );
        debug_assert!(
            self.operand_start.len() == self.layer.len() + 1 || self.operand_start.is_empty(),
            "the operand CSR carries one offset per row plus a terminator"
        );
        self.layer.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// The id row `row` produced, and the operator it folds with.
    pub fn row(&self, row: usize) -> (LayerId, DerivedOp) {
        (self.layer[row], self.op[row])
    }
    /// The layers one row folds, in the order it folds them. Never empty.
    pub fn operands_of(&self, row: usize) -> &[LayerId] {
        let start = self.operand_start[row] as usize;
        let end = self.operand_start[row + 1] as usize;
        debug_assert!(
            start < end,
            "a derived layer is computed from at least one layer"
        );
        debug_assert!(
            end <= self.operand.len(),
            "an operand range runs off the table"
        );
        &self.operand[start..end]
    }
}

/// One rule as the deck states it, layers resolved and lengths already [`Dbu`].
#[derive(Debug, Clone, Copy)]
pub struct RuleSpec {
    /// The rule's id, for reporting. Interned.
    pub id: StrId,
    /// The rule kind, interned. `drc` matches this against its own kind list.
    pub kind: StrId,
    /// `layer_ref[layer_start .. layer_start + layer_len]` in [`RuleTable`].
    pub layer_start: u32,
    pub layer_len: u32,
    /// `param[param_start .. param_start + param_len]` in [`RuleTable`].
    pub param_start: u32,
    pub param_len: u32,
}

/// A rule parameter, already converted.
#[derive(Debug, Clone, Copy)]
pub enum ParamValue {
    /// A length, converted against the grid. The common case.
    Length(Dbu),
    /// A dimensionless ratio — an antenna limit, a density fraction.
    Ratio(f64),
    Count(u32),
    Flag(bool),
    /// A layer, for rules parameterised by one.
    Layer(LayerId),
}

/// Every rule in the deck, `SoA`.
#[derive(Debug, Default)]
pub struct RuleTable {
    pub spec: Vec<RuleSpec>,
    pub layer_ref: Vec<LayerId>,
    /// Parameter name and value, names interned.
    pub param: Vec<(StrId, ParamValue)>,
}

impl RuleTable {
    pub fn layers_of(&self, rule: &RuleSpec) -> &[LayerId] {
        let start = rule.layer_start as usize;
        let end = start + rule.layer_len as usize;
        debug_assert!(
            end <= self.layer_ref.len(),
            "a rule's layer range runs off the table"
        );
        &self.layer_ref[start..end]
    }
    pub fn params_of(&self, rule: &RuleSpec) -> &[(StrId, ParamValue)] {
        let start = rule.param_start as usize;
        let end = start + rule.param_len as usize;
        debug_assert!(
            end <= self.param.len(),
            "a rule's parameter range runs off the table"
        );
        &self.param[start..end]
    }
    /// Look up one parameter by interned name.
    pub fn param(&self, rule: &RuleSpec, name: StrId) -> Option<ParamValue> {
        self.params_of(rule)
            .iter()
            .find(|&&(declared, _)| declared == name)
            .map(|&(_, value)| value)
    }
}

/// What connects to what: conductors carry current, vias join two conductors.
#[derive(Debug, Default)]
pub struct Connectivity {
    pub conductors: Vec<LayerId>,
    /// One row per via layer: the cut layer and the two layers it joins.
    pub via_cut: Vec<LayerId>,
    pub via_connects: Vec<(LayerId, LayerId)>,
    /// Whether shapes on the same conductor layer connect by touching.
    pub intra_layer_touch: bool,
    /// One row per net-label layer: the layer a `TEXT` is drawn on, and the
    /// conductor layer whose shapes it names. GDSII states no such relationship,
    /// so the deck must. Each row names exactly one conductor, so a label can
    /// never join two conductor layers into one net.
    pub label_layer: Vec<LayerId>,
    /// The conductor each row of `label_layer` names. Parallel to it.
    pub label_names: Vec<LayerId>,
}

/// How to recognise a device from geometry.
///
/// A terminal's role is its **position**, fixed per family:
///
/// | [`DeviceKind`] | `terminal[k]`, in order from k = 0 |
/// |---|---|
/// | `Mos` | gate, source, drain, bulk |
/// | `Bjt` | base, emitter, collector, then bulk if a fourth is declared |
/// | `Resistor`, `Capacitor`, `Diode` | pin 0, pin 1 — symmetric, so the comparator may swap them |
///
/// A recogniser stating them in another order extracts a transistor with its
/// source and drain transposed, which LVS reports as a layout mismatch.
#[derive(Debug, Default)]
pub struct DeviceRecognition {
    /// One row per recogniser: the marker layer whose polygons each identify
    /// one device, and the layers forming its terminals.
    pub kind: Vec<DeviceKind>,
    pub marker: Vec<LayerId>,
    pub terminal_start: Vec<u32>,
    pub terminal: Vec<LayerId>,
    /// Interned model name, for netlist comparison.
    pub model: Vec<StrId>,
}

/// The device families this tool recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Mos,
    Bjt,
    Resistor,
    Capacitor,
    Diode,
}

/// Per-layer process parameters, for parasitic extraction, indexed by [`LayerId`].
#[derive(Debug, Default)]
pub struct ProcessStack {
    pub thickness_nm: Vec<f64>,
    pub height_nm: Vec<f64>,
    pub sheet_res_ohm_sq: Vec<f64>,
    pub area_cap_af_um2: Vec<f64>,
    pub fringe_cap_af_um: Vec<f64>,
    pub dielectric_k: Vec<f64>,
}

/// Parse and validate a deck from memory.
///
/// # Schema
///
/// ```json
/// {
///   "layers": { "<name>": [<gds_layer>, <gds_datatype>] },
///   "derived": [{ "name": "<name>", "op": "and"|"or"|"not",
///                 "layers": ["<name>", ..] }],
///   "rules":  { "<rule_id>": { "kind": "<kind>",
///                              "layers": ["<name>", ..],
///                              "params": { "<param>": <value> } } },
///   "connectivity":       { "conductors": ["<name>", ..],
///                           "intra_layer_touch": <bool>,
///                           "vias": [{ "layer": "<name>",
///                                      "connects": ["<name>", "<name>"] }],
///                           "labels": [{ "layer": "<name>",
///                                        "names": "<name>" }] },
///   "device_recognition": [{ "kind": "mos"|"bjt"|"resistor"|"capacitor"|"diode",
///                            "marker": "<name>", "model": "<string>",
///                            "terminals": ["<name>", ..] }],
///   "pex": { "<name>": { "thickness_nm": <n>, "height_nm": <n>,
///                        "sheet_res_ohm_sq": <n>, "area_cap_af_um2": <n>,
///                        "fringe_cap_af_um": <n>, "dielectric_k": <n> } }
/// }
/// ```
///
/// Every section is optional; an absent one leaves its table empty. Layers take
/// their [`LayerId`] ascending by name, so two runs over the same text agree on
/// every id downstream.
///
/// A `derived` row produces a real [`LayerId`] that anything naming a layer may
/// name. Those ids come after every base layer, in declaration order, and carry
/// no GDS stream pair.
///
/// A parameter value carries its own shape, since a bare `45` cannot be told
/// from a ratio of `45`:
///
/// | JSON | becomes |
/// |---|---|
/// | `{ "nm": 45 }` | [`ParamValue::Length`], converted against `grid` |
/// | `{ "ratio": 2.5 }` | [`ParamValue::Ratio`] |
/// | `{ "count": 4 }` | [`ParamValue::Count`] |
/// | `{ "layer": "met1" }` | [`ParamValue::Layer`], resolved |
/// | `true` / `false` | [`ParamValue::Flag`] |
///
/// Lengths are **physical nanometres** and convert exactly or not at all, so
/// `DeckError::OffGrid` is a property of the deck and the grid together rather
/// than of a rounding mode.
///
/// # Errors
///
/// `Malformed` for anything not this shape; `UnknownLayer` for any layer name
/// absent from `"layers"`; `MissingParam` for a rule with no `kind` or no
/// `layers`; `OffGrid` for a length off the grid; `DuplicateRule` for a rule id
/// stated twice. Never a skip.
///
/// `kind` is interned verbatim, so a deck may hold rules of both domains and
/// neither `from_deck` can refuse one it does not spell. The refusal that keeps
/// a misspelled rule from reading as a clean design is
/// `gpurify_engine::run::run_checks`, the only layer holding both vocabularies.
pub fn parse_deck(source: &str, grid: Grid, strings: &mut StrTable) -> Result<Deck, DeckError> {
    let doc: DeckJson =
        serde_json::from_str(source).map_err(|why| DeckError::Malformed(why.to_string()))?;

    let mut layers = build_layers(&doc.layers, strings)?;
    // Before every other section: any of them may name a derived layer, and
    // `build_stack`'s columns are one row per layer.
    build_derived(&doc.derived, &mut layers, strings)?;
    let rules = build_rules(&doc.rules, &layers, grid, strings)?;
    let connectivity = build_connectivity(&doc.connectivity, &layers, strings)?;
    let devices = build_devices(&doc.device_recognition, &layers, strings)?;
    let stack = build_stack(&doc.pex, &layers, strings)?;

    debug_assert_eq!(
        devices.kind.len(),
        devices.marker.len(),
        "one marker per recogniser"
    );
    debug_assert_eq!(
        devices.kind.len(),
        devices.model.len(),
        "one model per recogniser"
    );
    debug_assert_eq!(connectivity.via_cut.len(), connectivity.via_connects.len());
    debug_assert_eq!(
        layers.derived().len(),
        doc.derived.len(),
        "one row per derived layer"
    );

    Ok(Deck {
        grid: Some(grid),
        layers,
        rules,
        connectivity,
        devices,
        stack,
    })
}

/// The `"derived"` section, layers resolved and ids assigned in declaration
/// order. An operand the table does not hold yet — including the row's own
/// name — is [`DeckError::UnknownLayer`].
fn build_derived(
    declared: &[DerivedJson],
    layers: &mut LayerTable,
    strings: &mut StrTable,
) -> Result<(), DeckError> {
    // Operands are resolved before the id is taken, so a self-reference is an
    // unresolved name rather than a layer folding itself.
    let mut operands: Vec<LayerId> = Vec::new();
    for row in declared {
        if row.layers.is_empty() {
            return Err(DeckError::MissingParam(
                row.name.clone(),
                "layers".to_owned(),
            ));
        }
        operands.clear();
        for name in &row.layers {
            operands.push(layer_of(layers, strings, &row.name, name)?);
        }
        if layers.id(strings, &row.name).is_some() {
            return Err(DeckError::Malformed(format!(
                "layer {} is declared twice",
                row.name
            )));
        }
        let op = match row.op.as_str() {
            "and" => DerivedOp::And,
            "or" => DerivedOp::Or,
            "not" => DerivedOp::Not,
            other => {
                return Err(DeckError::Malformed(format!(
                    "derived: unknown operator {other} on layer {}",
                    row.name
                )))
            }
        };
        layers.push_derived(strings.intern(&row.name), op, &operands);
    }
    Ok(())
}

/// Resolve one layer name, naming what referred to it when it is not declared.
fn layer_of(
    layers: &LayerTable,
    strings: &StrTable,
    referrer: &str,
    name: &str,
) -> Result<LayerId, DeckError> {
    layers
        .id(strings, name)
        .ok_or_else(|| DeckError::UnknownLayer(referrer.to_owned(), name.to_owned()))
}

/// Layer names to a [`LayerTable`], ids ascending by the name's *bytes* — an
/// interning order would differ between runs.
fn build_layers(
    declared: &Pairs<(u16, u16)>,
    strings: &mut StrTable,
) -> Result<LayerTable, DeckError> {
    let mut sorted: Vec<&(String, (u16, u16))> = declared.0.iter().collect();
    sorted.sort_unstable_by(|left, right| left.0.cmp(&right.0));

    for pair in sorted.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(DeckError::Malformed(format!(
                "layer {} is declared twice",
                pair[0].0
            )));
        }
    }

    let entries: Vec<(StrId, u16, u16)> = sorted
        .iter()
        .map(|(name, (layer, datatype))| (strings.intern(name), *layer, *datatype))
        .collect();

    let table = LayerTable::build(&entries);
    debug_assert_eq!(table.len(), declared.0.len(), "one id per declared layer");
    Ok(table)
}

/// The `"rules"` section to a [`RuleTable`], layers resolved and lengths
/// converted. Rules keep the order the deck states them in.
fn build_rules(
    declared: &Pairs<RuleJson>,
    layers: &LayerTable,
    grid: Grid,
    strings: &mut StrTable,
) -> Result<RuleTable, DeckError> {
    let mut table = RuleTable {
        spec: Vec::with_capacity(declared.0.len()),
        ..RuleTable::default()
    };
    let mut seen: Vec<StrId> = Vec::with_capacity(declared.0.len());

    for (rule_id, rule) in &declared.0 {
        let id = strings.intern(rule_id);
        if seen.contains(&id) {
            return Err(DeckError::DuplicateRule(rule_id.clone()));
        }
        seen.push(id);

        let kind = rule
            .kind
            .as_deref()
            .ok_or_else(|| DeckError::MissingParam(rule_id.clone(), "kind".to_owned()))?;
        let rule_layers = rule
            .layers
            .as_deref()
            .ok_or_else(|| DeckError::MissingParam(rule_id.clone(), "layers".to_owned()))?;

        let layer_start = table.layer_ref.len();
        for name in rule_layers {
            table
                .layer_ref
                .push(layer_of(layers, strings, rule_id, name)?);
        }

        let param_start = table.param.len();
        for (name, stated) in &rule.params.0 {
            let value = param_value(stated, rule_id, layers, grid, strings)?;
            let name = strings.intern(name);
            table.param.push((name, value));
        }

        table.spec.push(RuleSpec {
            id,
            kind: strings.intern(kind),
            layer_start: narrow(layer_start),
            layer_len: narrow(table.layer_ref.len() - layer_start),
            param_start: narrow(param_start),
            param_len: narrow(table.param.len() - param_start),
        });
    }

    debug_assert_eq!(
        table.spec.len(),
        declared.0.len(),
        "one row per declared rule"
    );
    Ok(table)
}

/// One stated parameter to its converted [`ParamValue`].
fn param_value(
    stated: &ParamJson,
    rule_id: &str,
    layers: &LayerTable,
    grid: Grid,
    strings: &StrTable,
) -> Result<ParamValue, DeckError> {
    Ok(match *stated {
        ParamJson::Flag(flag) => ParamValue::Flag(flag),
        ParamJson::Ratio(ratio) => ParamValue::Ratio(ratio),
        ParamJson::Count(count) => ParamValue::Count(count),
        ParamJson::Nm(nm) => ParamValue::Length(to_limit(nm, grid, rule_id)?),
        ParamJson::Layer(ref name) => ParamValue::Layer(layer_of(layers, strings, rule_id, name)?),
    })
}

/// A physical nanometre limit to grid units, exactly or not at all. `NotFinite`
/// is separated out: a `NaN` is not off the grid, it is off everything.
fn to_limit(nm: f64, grid: Grid, rule_id: &str) -> Result<Dbu, DeckError> {
    grid.to_dbu(Qty::<Length, NANO>::new(nm)).map_err(|why| {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the message names the limit the deck stated; a limit too large to \
                      truncate is already refused, and the digits after the point are not \
                      what the reader needs to see"
        )]
        let stated = nm as i64;
        match why {
            GridError::NotFinite => {
                DeckError::Malformed(format!("rule {rule_id}: limit is not a finite number"))
            }
            _ => DeckError::OffGrid(rule_id.to_owned(), stated),
        }
    })
}

/// The `"connectivity"` section, layers resolved.
fn build_connectivity(
    declared: &ConnectivityJson,
    layers: &LayerTable,
    strings: &StrTable,
) -> Result<Connectivity, DeckError> {
    let mut connectivity = Connectivity {
        conductors: Vec::with_capacity(declared.conductors.len()),
        via_cut: Vec::with_capacity(declared.vias.len()),
        via_connects: Vec::with_capacity(declared.vias.len()),
        intra_layer_touch: declared.intra_layer_touch,
        label_layer: Vec::with_capacity(declared.labels.len()),
        label_names: Vec::with_capacity(declared.labels.len()),
    };

    for name in &declared.conductors {
        connectivity
            .conductors
            .push(layer_of(layers, strings, "connectivity", name)?);
    }
    for via in &declared.vias {
        connectivity
            .via_cut
            .push(layer_of(layers, strings, "connectivity", &via.layer)?);
        connectivity.via_connects.push((
            layer_of(layers, strings, "connectivity", &via.connects.0)?,
            layer_of(layers, strings, "connectivity", &via.connects.1)?,
        ));
    }
    for label in &declared.labels {
        let names = layer_of(layers, strings, "connectivity", &label.names)?;
        // Fail closed here rather than as `topology::port`'s `OrphanLabel`: at
        // run time nothing can say which deck row was wrong.
        if !connectivity.conductors.contains(&names) {
            return Err(DeckError::Malformed(format!(
                "connectivity: label layer {} names {}, which is not a conductor",
                label.layer, label.names
            )));
        }
        let text = layer_of(layers, strings, "connectivity", &label.layer)?;
        // A `TEXT` record carries a stream pair and a derived layer has none,
        // so such a pairing can never bind a label — silently, at run time.
        if layers.is_derived(text) {
            return Err(DeckError::Malformed(format!(
                "connectivity: label layer {} is a derived layer, which carries no \
                 text records",
                label.layer
            )));
        }
        connectivity.label_layer.push(text);
        connectivity.label_names.push(names);
    }

    debug_assert_eq!(
        connectivity.label_layer.len(),
        connectivity.label_names.len(),
        "the label pairing columns must stay parallel"
    );
    Ok(connectivity)
}

/// The `"device_recognition"` section, as the CSR [`DeviceRecognition`] holds.
/// Terminal order is the role, and this preserves the deck's order.
fn build_devices(
    declared: &[DeviceJson],
    layers: &LayerTable,
    strings: &mut StrTable,
) -> Result<DeviceRecognition, DeckError> {
    let mut devices = DeviceRecognition::default();
    if declared.is_empty() {
        // Sentinel included: a `terminal_start` of `[0]` would claim a
        // recogniser row the empty `kind` column does not have.
        return Ok(devices);
    }

    devices.terminal_start.push(0);
    for device in declared {
        devices.kind.push(match device.kind.as_str() {
            "mos" => DeviceKind::Mos,
            "bjt" => DeviceKind::Bjt,
            "resistor" => DeviceKind::Resistor,
            "capacitor" => DeviceKind::Capacitor,
            "diode" => DeviceKind::Diode,
            other => {
                return Err(DeckError::Malformed(format!(
                    "device_recognition: unknown device kind {other}"
                )))
            }
        });
        devices.marker.push(layer_of(
            layers,
            strings,
            "device_recognition",
            &device.marker,
        )?);
        devices.model.push(strings.intern(&device.model));
        for name in &device.terminals {
            devices
                .terminal
                .push(layer_of(layers, strings, "device_recognition", name)?);
        }
        devices.terminal_start.push(narrow(devices.terminal.len()));
    }

    debug_assert_eq!(
        devices.terminal_start.len(),
        devices.kind.len() + 1,
        "a CSR offset column carries one closing sentinel"
    );
    Ok(devices)
}

/// The `"pex"` section, as a column per parameter indexed by [`LayerId`].
///
/// Every column is `layers.len()` long once the section exists at all;
/// `pex::stack_row` indexes it directly. An omitted layer keeps its zero.
fn build_stack(
    declared: &Pairs<StackJson>,
    layers: &LayerTable,
    strings: &StrTable,
) -> Result<ProcessStack, DeckError> {
    if declared.0.is_empty() {
        return Ok(ProcessStack::default());
    }

    let rows = layers.len();
    let mut stack = ProcessStack {
        thickness_nm: vec![0.0; rows],
        height_nm: vec![0.0; rows],
        sheet_res_ohm_sq: vec![0.0; rows],
        area_cap_af_um2: vec![0.0; rows],
        fringe_cap_af_um: vec![0.0; rows],
        dielectric_k: vec![0.0; rows],
    };

    for (name, row) in &declared.0 {
        let at = layer_of(layers, strings, "pex", name)?.idx();
        stack.thickness_nm[at] = row.thickness_nm;
        stack.height_nm[at] = row.height_nm;
        stack.sheet_res_ohm_sq[at] = row.sheet_res_ohm_sq;
        stack.area_cap_af_um2[at] = row.area_cap_af_um2;
        stack.fringe_cap_af_um[at] = row.fringe_cap_af_um;
        stack.dielectric_k[at] = row.dielectric_k;
    }

    debug_assert_eq!(stack.dielectric_k.len(), rows, "one stack row per layer");
    Ok(stack)
}

/// The key/value pairs of a JSON object, in file order and with repeats kept:
/// `serde_json::Map` collapses a repeated key and would drop a duplicate rule.
struct Pairs<T>(Vec<(String, T)>);

impl<T> Default for Pairs<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Pairs<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PairVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for PairVisitor<T> {
            type Value = Pairs<T>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Pairs<T>, M::Error> {
                let mut pairs = Vec::with_capacity(map.size_hint().unwrap_or(0));
                while let Some(entry) = map.next_entry::<String, T>()? {
                    pairs.push(entry);
                }
                Ok(Pairs(pairs))
            }
        }

        deserializer.deserialize_map(PairVisitor(std::marker::PhantomData))
    }
}

/// The deck file, as JSON states it. The schema is on [`parse_deck`].
///
/// `deny_unknown_fields` on every struct here: a misspelled `"conectivity"` is
/// a deck with no connectivity, which reports a clean LVS for a broken chip.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct DeckJson {
    #[serde(default)]
    layers: Pairs<(u16, u16)>,
    /// An array, not an object: declaration order decides the ids rows take and
    /// therefore which may name which.
    #[serde(default)]
    derived: Vec<DerivedJson>,
    #[serde(default)]
    rules: Pairs<RuleJson>,
    #[serde(default)]
    connectivity: ConnectivityJson,
    #[serde(default)]
    device_recognition: Vec<DeviceJson>,
    #[serde(default)]
    pex: Pairs<StackJson>,
    /// Consumer-owned: a downstream tool keeps its layer roles and construction
    /// dimensions in the deck it hands us. Named so such a deck parses and the
    /// section is ignored — an anonymous escape hatch would also swallow the
    /// misspelled real sections `deny_unknown_fields` exists to catch.
    #[allow(dead_code)]
    #[serde(default)]
    cell: serde_json::Value,
}

/// `kind` and `layers` are `Option`, so their absence is `MissingParam` naming
/// the rule instead of a serde message naming a byte offset.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleJson {
    kind: Option<String>,
    layers: Option<Vec<String>>,
    #[serde(default)]
    params: Pairs<ParamJson>,
}

/// A parameter value carries its own shape — `45` alone cannot be told from a
/// ratio of `45`.
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ParamJson {
    Nm(f64),
    Ratio(f64),
    Count(u32),
    Layer(String),
    /// Untagged: `true` is a flag and no other variant is a bare boolean.
    #[serde(untagged)]
    Flag(bool),
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ConnectivityJson {
    #[serde(default)]
    conductors: Vec<String>,
    #[serde(default)]
    intra_layer_touch: bool,
    #[serde(default)]
    vias: Vec<ViaJson>,
    #[serde(default)]
    labels: Vec<LabelJson>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViaJson {
    layer: String,
    connects: (String, String),
}

/// One `connectivity.labels` row: a text layer and the conductor it names.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LabelJson {
    layer: String,
    names: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceJson {
    kind: String,
    marker: String,
    model: String,
    terminals: Vec<String>,
}

/// One `derived` row: the name the computed layer takes, the operator, and the
/// layers it folds.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivedJson {
    name: String,
    op: String,
    layers: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct StackJson {
    #[serde(default)]
    thickness_nm: f64,
    #[serde(default)]
    height_nm: f64,
    #[serde(default)]
    sheet_res_ohm_sq: f64,
    #[serde(default)]
    area_cap_af_um2: f64,
    #[serde(default)]
    fringe_cap_af_um: f64,
    #[serde(default)]
    dielectric_k: f64,
}

/// Read and validate a deck against a layout's grid, interning into the
/// caller's [`StrTable`] so deck and layout names share one id space.
pub fn read_deck(
    path: &std::path::Path,
    grid: Grid,
    strings: &mut StrTable,
) -> Result<Deck, DeckError> {
    // The path is in the message: a run loads four files.
    let source = std::fs::read_to_string(path)
        .map_err(|why| DeckError::Io(format!("{}: {why}", path.display())))?;
    parse_deck(&source, grid, strings)
}

/// Layer-table tests, and the fixture the layout tests borrow.
#[cfg(test)]
pub(crate) mod tests {
    use super::{parse_deck, DeckError, LayerTable, StrTable};
    use gpurify_geom::LayerId;
    use gpurify_geom::Grid;

    /// The `"cell"` key is the one consumer-owned name [`DeckJson`] admits; any
    /// other unknown key must still die in `deny_unknown_fields`, or a
    /// misspelled section is a deck missing that section and a clean report.
    #[test]
    fn a_cell_section_parses_ignored_while_a_misspelled_section_still_fails() {
        let grid = Grid::new(1_000).expect("a positive resolution is a legal grid");

        let carried = r#"{"layers": {"met1": [68, 20]}, "cell": {"roles": {"met1": "route"}}}"#;
        let deck = parse_deck(carried, grid, &mut StrTable::default())
            .expect("a deck carrying a consumer-owned cell section must parse");
        assert_eq!(deck.layers.len(), 1, "the cell section leaked into parsing");

        let misspelled = r#"{"layers": {"met1": [68, 20]}, "rulez": {}}"#;
        let error = parse_deck(misspelled, grid, &mut StrTable::default())
            .expect_err("an unknown key that is not `cell` must still fail closed");
        assert!(
            matches!(error, DeckError::Malformed(_)),
            "a misspelled section was {error:?}, not a malformed-deck refusal"
        );
    }

    /// Build a layer table from `(name, gds layer, gds datatype)` rows.
    pub(crate) fn layer_table(strings: &mut StrTable, rows: &[(&str, u16, u16)]) -> LayerTable {
        let entries: Vec<_> = rows
            .iter()
            .map(|&(name, layer, datatype)| (strings.intern(name), layer, datatype))
            .collect();
        LayerTable::build(&entries)
    }

    /// The rows every layout test in this crate is written against.
    pub(crate) const ROWS: [(&str, u16, u16); 3] =
        [("met1", 68, 20), ("via1", 67, 44), ("poly", 66, 20)];

    #[test]
    fn a_name_the_deck_does_not_declare_resolves_to_no_layer_at_all() {
        let mut strings = StrTable::default();
        let layers = layer_table(&mut strings, &ROWS);

        assert_eq!(layers.len(), ROWS.len());
        assert!(!layers.is_empty());

        for (index, &(name, _, _)) in ROWS.iter().enumerate() {
            let expected = LayerId(u16::try_from(index).expect("three rows"));
            assert_eq!(
                layers.id(&strings, name),
                Some(expected),
                "{name} did not resolve to the id it was declared at"
            );
            assert_eq!(
                strings.resolve(layers.name(expected)),
                name,
                "{expected:?} named the wrong layer"
            );
        }

        // Interned, so it exists as a string, but never declared as a layer.
        let stray = strings.intern("met9");
        assert!(
            layers.id(&strings, "met9").is_none(),
            "an interned name that the deck never declared resolved to a layer"
        );
        assert!(
            layers
                .id(&strings, "a name nothing ever interned")
                .is_none(),
            "an unknown name resolved to a layer"
        );
        assert_eq!(
            strings.resolve(stray),
            "met9",
            "the lookup mutated the string table it was handed"
        );
    }

    #[test]
    fn stream_pairs_map_only_where_the_deck_declares_them() {
        let mut strings = StrTable::default();
        let layers = layer_table(&mut strings, &ROWS);

        for (index, &(_, layer, datatype)) in ROWS.iter().enumerate() {
            assert_eq!(
                layers.of_stream(layer, datatype),
                Some(LayerId(u16::try_from(index).expect("three rows"))),
                "stream {layer}/{datatype} did not map to the id it was declared at"
            );
        }
        assert!(
            layers.of_stream(69, 20).is_none(),
            "an undeclared layer number mapped to a layer"
        );
        assert!(
            layers.of_stream(68, 21).is_none(),
            "an undeclared datatype on a declared layer number mapped to a layer, \
             so the datatype is being ignored"
        );
        assert!(
            layers.of_stream(66, 44).is_none(),
            "a layer number from one row and a datatype from another mapped to a \
             layer, so the pair is not being matched as a pair"
        );
    }
}
