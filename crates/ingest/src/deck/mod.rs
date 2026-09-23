//! The PDK deck: layers, derived layers, rules, connectivity, device recognisers, PEX stack.
//!
//! Data in: deck text (see `docs/deck.md`) and the layout's grid.
//! Data out: [`Deck`], limits converted from physical nanometres to grid units exactly or refused.
//! Rule kinds are interned verbatim and never interpreted here.

use crate::narrow;
use gpurify_geom::LayerId;
use gpurify_geom::{Dbu, DbuArea};
use gpurify_geom::{StrId, StrTable};

mod kinds;
mod lex;
mod parse;

pub use parse::{parse_deck, Diagnostic};

/// Why a deck was rejected.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DeckError {
    /// Two statements that parse alone but contradict each other.
    #[error("malformed deck: {0}")]
    Malformed(String),
    #[error("io: {0}")]
    Io(String),
    /// The deck text did not parse; each diagnostic points at its span.
    #[error("{}", parse::render(.file, .diagnostics))]
    Invalid {
        file: String,
        diagnostics: Vec<Diagnostic>,
    },
}

impl DeckError {
    /// Name the file the diagnostics point into.
    #[must_use]
    pub fn in_file(mut self, path: &str) -> Self {
        if let Self::Invalid { file, .. } = &mut self {
            path.clone_into(file);
        }
        self
    }
}

/// A parsed, validated, grid-resolved deck.
#[derive(Debug, Default)]
pub struct Deck {
    pub layers: LayerTable,
    pub rules: RuleTable,
    pub connectivity: Connectivity,
    pub devices: DeviceRecognition,
    pub stack: ProcessStack,
}

/// Layer names and stream pairs to ids, and back. Derived layers take the ids after every base layer.
#[derive(Debug, Default)]
pub struct LayerTable {
    /// `LayerId(i)` is named `name[i]`.
    name: Vec<StrId>,
    /// GDS layer/datatype pair per id; [`DERIVED_STREAM`] for a derived layer.
    stream: Vec<(u16, u16)>,
    /// Base-layer ids sorted by `(stream pair, id)`, so a shared pair answers with the lowest id.
    by_stream: Vec<LayerId>,
    /// The first derived id, and so the number of base layers.
    derived_start: u16,
    /// How each derived layer is computed, in id order. Operands fold left and only name lower ids.
    derived: Vec<(LayerId, DerivedOp, Vec<LayerId>)>,
}

/// The placeholder stream pair of a derived layer. Ask [`LayerTable::is_derived`].
const DERIVED_STREAM: (u16, u16) = (u16::MAX, u16::MAX);

impl LayerTable {
    pub fn len(&self) -> usize {
        self.name.len()
    }
    /// `None` for a name the deck does not define. Never interns.
    pub fn id(&self, strings: &StrTable, name: &str) -> Option<LayerId> {
        let wanted = strings.get(name)?;
        let at = self.name.iter().position(|&n| n == wanted)?;
        Some(LayerId(u16::try_from(at).expect("LayerId is a u16")))
    }
    /// The base layer a GDS layer/datatype pair maps to; the lowest id when two share it.
    pub fn of_stream(&self, layer: u16, datatype: u16) -> Option<LayerId> {
        let wanted = (layer, datatype);
        let at = self
            .by_stream
            .partition_point(|&LayerId(i)| self.stream[usize::from(i)] < wanted);
        let found = *self.by_stream.get(at)?;
        (self.stream[found.idx()] == wanted).then_some(found)
    }

    /// The GDS stream pair a layer writes to. A derived layer answers [`DERIVED_STREAM`];
    /// a writer should skip [`Self::is_derived`] rows, which would duplicate area.
    pub fn stream_of(&self, layer: LayerId) -> (u16, u16) {
        self.stream[layer.idx()]
    }

    /// Is this layer computed by the deck rather than drawn in the layout?
    pub fn is_derived(&self, layer: LayerId) -> bool {
        layer.0 >= self.derived_start
    }

    /// Is this an edge layer (directed segments, not polygons)? Only a check
    /// that says it takes edges accepts one.
    pub fn is_edges(&self, layer: LayerId) -> bool {
        let Some(row) = layer.idx().checked_sub(usize::from(self.derived_start)) else {
            return false;
        };
        let (_, op, operands) = &self.derived[row];
        op.makes_edges()
            .unwrap_or_else(|| self.is_edges(operands[0]))
    }

    /// How the derived layers are computed, in id order.
    pub(crate) fn derived(&self) -> &[(LayerId, DerivedOp, Vec<LayerId>)] {
        &self.derived
    }

    /// Add a derived layer above every existing id.
    fn push_derived(&mut self, name: StrId, op: DerivedOp, operands: Vec<LayerId>) {
        let id = LayerId(u16::try_from(self.name.len()).expect("LayerId is a u16"));
        assert!(
            !operands.is_empty() && operands.iter().all(|&operand| operand < id),
            "a derived layer folds at least one lower id"
        );
        self.name.push(name);
        self.stream.push(DERIVED_STREAM);
        self.derived.push((id, op, operands));
    }

    /// A table of base layers from `(name, gds_layer, gds_datatype)`; `LayerId(i)` is `entries[i]`.
    pub(crate) fn build(entries: &[(StrId, u16, u16)]) -> Self {
        let count = u16::try_from(entries.len()).expect("LayerId is a u16");
        let name = entries.iter().map(|&(name, _, _)| name).collect();
        let stream: Vec<(u16, u16)> = entries
            .iter()
            .map(|&(_, layer, datatype)| (layer, datatype))
            .collect();
        let mut by_stream: Vec<LayerId> = (0..count).map(LayerId).collect();
        by_stream.sort_unstable_by_key(|&LayerId(i)| (stream[usize::from(i)], i));
        Self {
            name,
            stream,
            by_stream,
            derived_start: count,
            derived: Vec::new(),
        }
    }
}

/// The operators a deck may spell over layers. `and`/`or`/`not` fold over
/// every operand; a method takes its receiver, then its layer argument if any.
/// Bounds are inclusive, in grid units (square grid units for an area).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DerivedOp {
    And,
    Or,
    Not,
    /// Grow, or shrink when negative.
    Sized(Dbu),
    /// `interacting` (`true`) or `not_interacting`.
    Interacting(bool),
    Inside,
    Outside,
    Holes,
    Extents,
    WithArea(i128, i128),
    WithWidth(i128, i128),
    /// Polygons to their boundary edges.
    Edges,
    /// `inside_part` (`true`) or `outside_part`, on edges.
    Part(bool),
    WithLength(i128, i128),
}

impl DerivedOp {
    /// Whether the result is edges: `Some` when the op decides, `None` when it
    /// keeps its receiver's kind.
    pub(crate) fn makes_edges(self) -> Option<bool> {
        match self {
            Self::Edges => Some(true),
            Self::Sized(_)
            | Self::Inside
            | Self::Outside
            | Self::Holes
            | Self::Extents
            | Self::WithArea(..)
            | Self::WithWidth(..) => Some(false),
            Self::And
            | Self::Or
            | Self::Not
            | Self::Interacting(_)
            | Self::Part(_)
            | Self::WithLength(..) => None,
        }
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
    /// An area, already in square grid units.
    Area(DbuArea),
    /// A layer, for rules parameterised by one.
    Layer(LayerId),
    /// A device model name a `device` statement declares, interned.
    Model(StrId),
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
        &self.layer_ref[start..start + rule.layer_len as usize]
    }
    pub fn params_of(&self, rule: &RuleSpec) -> &[(StrId, ParamValue)] {
        let start = rule.param_start as usize;
        &self.param[start..start + rule.param_len as usize]
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
    /// One row per net-label layer: the layer a `TEXT` is drawn on...
    pub label_layer: Vec<LayerId>,
    /// ...and the one conductor whose shapes it names.
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
#[derive(Debug, Default)]
pub struct DeviceRecognition {
    /// One row per recogniser: each marker polygon is one device. Terminals are CSR.
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

/// Lower a parsed deck to a [`Deck`]. Base layers take ids ascending by name
/// bytes; derived layers follow in declaration order. Strings are interned in
/// section order, so the same deck text always yields the same [`StrId`]s. The
/// parser has already checked every name and value; what fails here is a
/// relation between statements.
fn build(doc: &DeckSrc, strings: &mut StrTable) -> Result<Deck, DeckError> {
    let mut layers = build_layers(&doc.layers, strings);
    // First: any later section may name a derived layer.
    for row in &doc.derived {
        let operands = row
            .layers
            .iter()
            .map(|name| layer_of(&layers, strings, name))
            .collect();
        layers.push_derived(strings.intern(&row.name), row.op, operands);
    }
    // A misspelt model would match no device and silently check nothing.
    for rule in &doc.rules {
        for (_, stated) in &rule.params {
            if let ParamSrc::Model(model) = stated {
                if !doc.devices.iter().any(|device| device.model == *model) {
                    return Err(DeckError::Malformed(format!(
                        "rule {}: model \"{model}\" is not declared by any device statement",
                        rule.id
                    )));
                }
            }
        }
    }
    let rules = build_rules(&doc.rules, &layers, strings);
    let connectivity = build_connectivity(&doc.connectivity, &layers, strings)?;
    let devices = build_devices(&doc.devices, &layers, strings);
    let stack = build_stack(&doc.pex, &layers, strings);

    Ok(Deck {
        layers,
        rules,
        connectivity,
        devices,
        stack,
    })
}

/// A layer name the parser has already resolved.
fn layer_of(layers: &LayerTable, strings: &StrTable, name: &str) -> LayerId {
    layers
        .id(strings, name)
        .expect("the parser admits only declared layers")
}

/// Layer names to a [`LayerTable`], ids ascending by name *bytes*, not interning order.
fn build_layers(declared: &[(String, (u16, u16))], strings: &mut StrTable) -> LayerTable {
    let mut sorted: Vec<&(String, (u16, u16))> = declared.iter().collect();
    sorted.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let entries: Vec<(StrId, u16, u16)> = sorted
        .iter()
        .map(|(name, (layer, datatype))| (strings.intern(name), *layer, *datatype))
        .collect();
    LayerTable::build(&entries)
}

/// The rules to a [`RuleTable`], in deck order.
fn build_rules(declared: &[RuleSrc], layers: &LayerTable, strings: &mut StrTable) -> RuleTable {
    let mut table = RuleTable {
        spec: Vec::with_capacity(declared.len()),
        ..RuleTable::default()
    };
    for rule in declared {
        let id = strings.intern(&rule.id);
        let layer_start = table.layer_ref.len();
        for name in &rule.layers {
            table.layer_ref.push(layer_of(layers, strings, name));
        }
        let param_start = table.param.len();
        for (name, stated) in &rule.params {
            let value = match *stated {
                ParamSrc::Value(value) => value,
                ParamSrc::Layer(ref layer) => ParamValue::Layer(layer_of(layers, strings, layer)),
                ParamSrc::Model(ref model) => ParamValue::Model(strings.intern(model)),
            };
            table.param.push((strings.intern(name), value));
        }
        table.spec.push(RuleSpec {
            id,
            kind: strings.intern(rule.kind),
            layer_start: narrow(layer_start),
            layer_len: narrow(table.layer_ref.len() - layer_start),
            param_start: narrow(param_start),
            param_len: narrow(table.param.len() - param_start),
        });
    }
    table
}

/// Connectivity, layers resolved; a label row must name a drawn layer and a conductor.
fn build_connectivity(
    declared: &ConnectivitySrc,
    layers: &LayerTable,
    strings: &StrTable,
) -> Result<Connectivity, DeckError> {
    let layer = |name: &str| layer_of(layers, strings, name);
    let mut connectivity = Connectivity {
        conductors: declared.conductors.iter().map(|name| layer(name)).collect(),
        via_cut: declared.vias.iter().map(|via| layer(&via.layer)).collect(),
        via_connects: declared
            .vias
            .iter()
            .map(|via| (layer(&via.connects.0), layer(&via.connects.1)))
            .collect(),
        intra_layer_touch: declared.intra_layer_touch,
        label_layer: Vec::with_capacity(declared.labels.len()),
        label_names: Vec::with_capacity(declared.labels.len()),
    };
    for label in &declared.labels {
        let names = layer(&label.names);
        // Fail closed here rather than as `topology::port`'s `OrphanLabel`: at
        // run time nothing can say which deck row was wrong.
        if !connectivity.conductors.contains(&names) {
            return Err(DeckError::Malformed(format!(
                "connect label {} names {}, which is not a conductor",
                label.layer, label.names
            )));
        }
        let text = layer(&label.layer);
        // A `TEXT` record carries a stream pair and a derived layer has none,
        // so such a pairing can never bind a label — silently, at run time.
        if layers.is_derived(text) {
            return Err(DeckError::Malformed(format!(
                "connect label {}: a derived layer carries no text records",
                label.layer
            )));
        }
        connectivity.label_layer.push(text);
        connectivity.label_names.push(names);
    }
    Ok(connectivity)
}

/// Device recognisers, as the CSR [`DeviceRecognition`] holds. Terminal order
/// is the role, and this preserves the deck's order.
fn build_devices(
    declared: &[DeviceSrc],
    layers: &LayerTable,
    strings: &mut StrTable,
) -> DeviceRecognition {
    let mut devices = DeviceRecognition::default();
    if declared.is_empty() {
        // Sentinel included: a `terminal_start` of `[0]` would claim a
        // recogniser row the empty `kind` column does not have.
        return devices;
    }
    devices.terminal_start.push(0);
    for device in declared {
        devices.kind.push(device.kind);
        devices
            .marker
            .push(layer_of(layers, strings, &device.marker));
        devices.model.push(strings.intern(&device.model));
        for name in &device.terminals {
            devices.terminal.push(layer_of(layers, strings, name));
        }
        devices.terminal_start.push(narrow(devices.terminal.len()));
    }
    devices
}

/// The PEX stack, a column per parameter indexed by [`LayerId`].
///
/// Every column is `layers.len()` long once any `pex` row exists;
/// `pex::stack_row` indexes it directly. A layer with no row keeps its zero.
fn build_stack(
    declared: &[(String, StackSrc)],
    layers: &LayerTable,
    strings: &StrTable,
) -> ProcessStack {
    if declared.is_empty() {
        return ProcessStack::default();
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
    for (name, row) in declared {
        let at = layer_of(layers, strings, name).idx();
        stack.thickness_nm[at] = row.thickness_nm;
        stack.height_nm[at] = row.height_nm;
        stack.sheet_res_ohm_sq[at] = row.sheet_res_ohm_sq;
        stack.area_cap_af_um2[at] = row.area_cap_af_um2;
        stack.fringe_cap_af_um[at] = row.fringe_cap_af_um;
        stack.dielectric_k[at] = row.dielectric_k;
    }
    stack
}

/// The deck as the parser states it: names unresolved, values converted.
#[derive(Default)]
struct DeckSrc {
    /// Base layers in statement order, with their GDS pair.
    layers: Vec<(String, (u16, u16))>,
    /// In declaration order, which decides the ids they take.
    derived: Vec<DerivedSrc>,
    rules: Vec<RuleSrc>,
    connectivity: ConnectivitySrc,
    devices: Vec<DeviceSrc>,
    pex: Vec<(String, StackSrc)>,
}

struct RuleSrc {
    id: String,
    /// The engine kind name.
    kind: &'static str,
    layers: Vec<String>,
    params: Vec<(&'static str, ParamSrc)>,
}

/// A converted value, or a layer still to resolve.
enum ParamSrc {
    Value(ParamValue),
    Layer(String),
    Model(String),
}

#[derive(Default)]
struct ConnectivitySrc {
    conductors: Vec<String>,
    intra_layer_touch: bool,
    vias: Vec<ViaSrc>,
    labels: Vec<LabelSrc>,
}

struct ViaSrc {
    layer: String,
    connects: (String, String),
}

/// `connect label <layer> names <conductor>`.
struct LabelSrc {
    layer: String,
    names: String,
}

struct DeviceSrc {
    kind: DeviceKind,
    marker: String,
    model: String,
    terminals: Vec<String>,
}

/// `layer <name> = a op b op ..`, one operator folded left.
struct DerivedSrc {
    name: String,
    op: DerivedOp,
    layers: Vec<String>,
}

struct StackSrc {
    thickness_nm: f64,
    height_nm: f64,
    sheet_res_ohm_sq: f64,
    area_cap_af_um2: f64,
    fringe_cap_af_um: f64,
    dielectric_k: f64,
}

/// Layer-table tests, and the fixture the layout tests borrow.
#[cfg(test)]
pub(crate) mod tests {
    use super::{LayerTable, StrTable};
    use gpurify_geom::LayerId;

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

        for (index, &(name, _, _)) in ROWS.iter().enumerate() {
            let expected = LayerId(u16::try_from(index).expect("three rows"));
            assert_eq!(
                layers.id(&strings, name),
                Some(expected),
                "{name} did not resolve to the id it was declared at"
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
