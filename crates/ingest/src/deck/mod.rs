//! The PDK deck: layers, derived layers, rules, connectivity, device recognisers, PEX stack.
//!
//! Data in: deck text and the layout's grid. The language is
//! [deck.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/deck.md).
//! Data out: [`Deck`], every limit converted from physical units to grid units
//! exactly, or refused.
//!
//! Each rule's spelling (`space(met1) >= 140nm`) resolves to one engine kind
//! name (`min_spacing`) with every parameter named, typed and converted;
//! nothing here decides what a rule means. The DRC and ERC engines in
//! `gpurify-check` read [`RuleSpec::kind`] and the parameters by name.
//!
//! # Examples
//!
//! ```
//! use gpurify_geom::{Grid, StrTable};
//! use gpurify_ingest::deck::{parse_deck, ParamValue};
//!
//! let text = "grid 5nm
//! layer met1 = gds(68, 20)
//! rule m1.1 width(met1) >= 140nm
//! ";
//! let mut strings = StrTable::default();
//! // A 1 nm layout grid: 1000 database units per micrometre.
//! let deck = parse_deck(text, Grid::new(1000)?, &mut strings)?;
//!
//! let rule = &deck.rules.spec[0];
//! assert_eq!(strings.resolve(rule.kind), "min_width");
//! let limit = strings.get("limit").and_then(|name| deck.rules.param(rule, name));
//! assert!(matches!(limit, Some(ParamValue::Length(d)) if d.raw() == 140));
//!
//! // 142 nm is not on the deck's 5 nm grid: refused, never rounded.
//! let off_grid = text.replace("140nm", "142nm");
//! assert!(parse_deck(&off_grid, Grid::new(1000)?, &mut StrTable::default()).is_err());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

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
    /// Statements that parse alone but contradict each other: a rule naming a
    /// model no `device` declares, net spacing on a non-conductor, a global
    /// layer also listed as a conductor, or a label row whose text layer is
    /// derived or whose named layer is not a conductor.
    #[error("malformed deck: {0}")]
    Malformed(String),
    /// The deck file could not be read. [`parse_deck`] never returns it; a
    /// caller reading the file does.
    #[error("io: {0}")]
    Io(String),
    /// The deck text did not parse. Displays as `file:line:col: message`, the
    /// line, and a caret under the span, for each diagnostic.
    #[error("{}", parse::render(.file, .diagnostics))]
    Invalid {
        /// The path shown before each diagnostic; `<deck>` until
        /// [`DeckError::in_file`] names it.
        file: String,
        /// Every error found, at most 50: parsing continues past an error so
        /// one pass reports them all.
        diagnostics: Vec<Diagnostic>,
    },
}

impl DeckError {
    /// Names the file the diagnostics point into. Other variants pass through unchanged.
    #[must_use]
    pub fn in_file(mut self, path: &str) -> Self {
        if let Self::Invalid { file, .. } = &mut self {
            path.clone_into(file);
        }
        self
    }
}

/// A parsed, validated, grid-resolved deck, built by [`parse_deck`].
///
/// Every table refers to layers by [`LayerId`], and every name (layer, rule,
/// model, parameter) is a [`StrId`] in the [`StrTable`] the deck was parsed
/// with. Lengths are [`Dbu`] on the layout grid the deck was parsed against,
/// so a deck is only meaningful with a layout on that grid.
#[derive(Debug, Default)]
pub struct Deck {
    /// Drawn and derived layers, and the stream pairs the deck ignores.
    pub layers: LayerTable,
    /// Every `rule` statement, in deck order.
    pub rules: RuleTable,
    /// The `connect` statements: what carries a net, and how layers join.
    pub connectivity: Connectivity,
    /// The `device` statements.
    pub devices: DeviceRecognition,
    /// The `pex` statements: the parasitic stack, per layer.
    pub stack: ProcessStack,
}

/// Layer names and stream pairs to ids, and back.
///
/// Ids are dense from 0. Drawn layers (`layer x = gds(L, D)`) come first,
/// ascending by name bytes; derived layers follow in declaration order, each
/// computed only from lower ids. Each inner operation of a nested expression
/// such as `(a or b) not c` adds a hidden derived layer (`x#1`, `x#2`, …), and
/// a layer expression written inside a rule adds one named `<rule id>@k`. No
/// deck text can name a hidden layer.
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
    /// The text patterns [`DerivedOp::WithText`] names, `*` any run, `?` one character.
    texts: Vec<String>,
    /// Stream pairs the deck says to drop (`ignore gds(L, D)`), sorted; never a declared pair.
    ignored: Vec<(u16, u16)>,
}

/// The placeholder stream pair of a derived layer. Ask [`LayerTable::is_derived`].
const DERIVED_STREAM: (u16, u16) = (u16::MAX, u16::MAX);

impl LayerTable {
    /// Returns the number of layers, drawn, derived and hidden: the
    /// `layer_count` a [`GeometryStore`](gpurify_geom::GeometryStore) for this
    /// deck is built with.
    pub fn len(&self) -> usize {
        self.name.len()
    }
    /// Whether the deck declares no layer.
    pub fn is_empty(&self) -> bool {
        self.name.is_empty()
    }
    /// `None` for a name the deck does not define. Never interns.
    pub fn id(&self, strings: &StrTable, name: &str) -> Option<LayerId> {
        let wanted = strings.get(name)?;
        let at = self.name.iter().position(|&n| n == wanted)?;
        Some(LayerId(u16::try_from(at).expect("LayerId is a u16")))
    }
    /// The drawn layer a GDS layer/datatype pair maps to; the lowest id when
    /// two share it. `None` for a pair the deck does not declare, ignored or not.
    /// `O(log n)`.
    pub fn of_stream(&self, layer: u16, datatype: u16) -> Option<LayerId> {
        let wanted = (layer, datatype);
        let at = self
            .by_stream
            .partition_point(|&LayerId(i)| self.stream[usize::from(i)] < wanted);
        let found = *self.by_stream.get(at)?;
        (self.stream[found.idx()] == wanted).then_some(found)
    }

    /// The GDS stream pair a layer writes to. A derived layer answers `(65535, 65535)`;
    /// a writer should skip [`Self::is_derived`] rows, which would duplicate area.
    pub fn stream_of(&self, layer: LayerId) -> (u16, u16) {
        self.stream[layer.idx()]
    }

    /// Whether the deck drops geometry on this stream pair (`ignore gds(L, D)`)
    /// instead of refusing the layout for it. Never true of a declared pair.
    pub fn is_ignored(&self, layer: u16, datatype: u16) -> bool {
        self.ignored.binary_search(&(layer, datatype)).is_ok()
    }

    /// Is this layer computed by the deck rather than drawn in the layout?
    pub fn is_derived(&self, layer: LayerId) -> bool {
        layer.0 >= self.derived_start
    }

    /// Is this an edge layer (directed segments, not polygons)? Only a check
    /// that says it takes edges accepts one. Panics on an id past [`Self::len`].
    pub fn is_edges(&self, layer: LayerId) -> bool {
        let Some(row) = layer.idx().checked_sub(usize::from(self.derived_start)) else {
            return false;
        };
        let (_, op, operands) = &self.derived[row];
        op.makes_edges()
            .unwrap_or_else(|| self.is_edges(operands[0]))
    }

    /// Returns the layer's name as the deck wrote it, or its hidden name.
    /// Panics on an id past [`Self::len`].
    pub fn name(&self, layer: LayerId) -> StrId {
        self.name[layer.idx()]
    }

    /// How a derived layer is computed; `None` for a drawn layer.
    pub fn op(&self, layer: LayerId) -> Option<DerivedOp> {
        layer
            .idx()
            .checked_sub(usize::from(self.derived_start))
            .map(|row| self.derived[row].1)
    }

    /// The layers a derived layer is computed from, every one a lower id;
    /// empty for a drawn layer. [`DerivedOp`] says what each position means.
    pub fn operands(&self, layer: LayerId) -> &[LayerId] {
        layer
            .idx()
            .checked_sub(usize::from(self.derived_start))
            .map_or(&[], |row| &self.derived[row].2)
    }

    /// How the derived layers are computed, in id order.
    pub(crate) fn derived(&self) -> &[(LayerId, DerivedOp, Vec<LayerId>)] {
        &self.derived
    }

    /// Text pattern `text` of a [`DerivedOp::WithText`]: `*` matches any run of
    /// characters, `?` one, anything else itself, case included. Panics on an
    /// index no `WithText` holds.
    pub fn text(&self, text: u32) -> &str {
        &self.texts[text as usize]
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
            texts: Vec::new(),
            ignored: Vec::new(),
        }
    }
}

/// The operators a deck may spell over layers; the semantics are
/// [deck.md's layer operations](https://github.com/UW-ASIC/GPurify/blob/main/docs/deck.md#layers).
///
/// [`LayerTable::operands`] holds the inputs. `And`, `Or` and `Not` fold left
/// over every operand (`a not b not c` is one row of three). Every other
/// operation takes its receiver as operand 0 and its layer argument, if it
/// has one, as operand 1. Touching and overlapping shapes count as one shape
/// before an operation reads them.
///
/// Bounds `(lo, hi)` are inclusive, in grid units (square grid units for an
/// area); a strict `>` or `<` in the deck has already moved one unit, and an
/// absent side is `i128::MIN` or `i128::MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivedOp {
    /// The area every operand covers. On edge layers, the parts of operand 0
    /// that coincide with every other operand.
    And,
    /// The area any operand covers. On edge layers, every operand's edges,
    /// shared parts once.
    Or,
    /// Operand 0's area minus every other operand's. On edge layers, the parts
    /// of operand 0 that coincide with no other operand.
    Not,
    /// Every shape grown by the length on all sides, corners square; shrunk
    /// when negative, a part no wider than twice the shrink disappearing.
    Sized(Dbu),
    /// `interacting` (`true`): the shapes or edges of operand 0 that touch or
    /// overlap a shape of operand 1, a shared corner counting. `false` is
    /// `not_interacting`, the rest.
    Interacting(bool),
    /// The shapes of operand 0 entirely covered by operand 1, touching its
    /// boundary from inside allowed.
    Inside,
    /// The shapes of operand 0 sharing no area with operand 1; touching is outside.
    Outside,
    /// Each hole of each shape, filled; a hole holding an island covers it.
    Holes,
    /// The bounding box of each shape, one shape per box: boxes that overlap
    /// are not merged.
    Extents,
    /// The shapes whose area, holes excluded, lies in `lo..=hi` square grid units.
    WithArea(i128, i128),
    /// The shapes whose narrowest width, as the `width` rule measures it, lies
    /// in `lo..=hi` grid units; a diagonal neck counts, floored to a whole unit.
    WithWidth(i128, i128),
    /// Polygons to their boundary edges, each directed with the material on
    /// its left. The result is an edge layer.
    Edges,
    /// `inside_part` (`true`) or `outside_part`: the parts of each edge of
    /// operand 0 strictly inside, or strictly outside, operand 1's shapes.
    /// Parts on the boundary are in neither.
    Part(bool),
    /// The edges whose length lies in `lo..=hi` grid units.
    WithLength(i128, i128),
    /// `with_text` (`keep`) or `without_text`: the shapes of operand 0 that
    /// hold, on their material or boundary, a `TEXT` drawn on operand 1 (always
    /// a drawn layer) whose string matches [`LayerTable::text`] `text`.
    WithText {
        /// `true` keeps the shapes holding a match, `false` the others.
        keep: bool,
        /// Index of the pattern, for [`LayerTable::text`].
        text: u32,
    },
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
            | Self::WithWidth(..)
            | Self::WithText { .. } => Some(false),
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
///
/// Read its layers and parameters through [`RuleTable::layers_of`] and
/// [`RuleTable::params_of`] rather than slicing by hand.
#[derive(Debug, Clone, Copy)]
pub struct RuleSpec {
    /// The rule's id, for reporting: the deck's text with every `{name}`
    /// replaced. Interned; unique within a deck.
    pub id: StrId,
    /// The engine kind the deck's spelling resolved to (`width(L) >=` is
    /// `min_width`, `width(L) <=` is `max_width`), interned. `drc` and `erc`
    /// match this against their own kind lists.
    pub kind: StrId,
    /// First of this rule's rows in [`RuleTable::layer_ref`].
    pub layer_start: u32,
    /// Number of layer arguments.
    pub layer_len: u32,
    /// First of this rule's rows in [`RuleTable::param`].
    pub param_start: u32,
    /// Number of parameter rows.
    pub param_len: u32,
}

/// A rule parameter, already converted to the unit the engines store.
#[derive(Debug, Clone, Copy)]
pub enum ParamValue {
    /// A length in grid units, on the deck grid and exact on the layout grid.
    /// The common case: every comparison limit on a length.
    Length(Dbu),
    /// Any other real number, in its dimension's engine unit: a ratio,
    /// exponent or fraction (`0..=1`, `%` already divided) bare; a voltage in
    /// mV; a current in µA; a current per width in A/m (µA/µm); a resistance in
    /// ohms; a temperature in kelvin (`C` already converted); an energy in eV;
    /// a time in hours. The name says which.
    Ratio(f64),
    /// A whole count (cuts, colours, drivers), or an angle in whole degrees.
    Count(u32),
    /// `true`/`false`; `nets: same` (`true`) or `different`; `maximum`, which a
    /// density rule's `<=` sets; or `warning`, on an ERC rule written so.
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
    /// One row per `rule` statement, in deck order (a `for` loop's rules in
    /// iteration order).
    pub spec: Vec<RuleSpec>,
    /// Every rule's layer arguments, back to back; a [`RuleSpec`] owns a run.
    pub layer_ref: Vec<LayerId>,
    /// Parameter name and value, names interned; a [`RuleSpec`] owns a run.
    pub param: Vec<(StrId, ParamValue)>,
}

impl RuleTable {
    /// Returns a rule's layer arguments in the order its engine kind takes
    /// them, which can differ from the deck's: `enclosure(inner, outer)` is
    /// stored outer first.
    pub fn layers_of(&self, rule: &RuleSpec) -> &[LayerId] {
        let start = rule.layer_start as usize;
        &self.layer_ref[start..start + rule.layer_len as usize]
    }
    /// Returns a rule's parameters. A list parameter (`models`, `allowed`, a
    /// spacing table's cells) is one row per element under the same name, in
    /// list order; a parameter written `none` has no row at all.
    pub fn params_of(&self, rule: &RuleSpec) -> &[(StrId, ParamValue)] {
        let start = rule.param_start as usize;
        &self.param[start..start + rule.param_len as usize]
    }
    /// Looks up one parameter by interned name: the first row for a list,
    /// `None` when absent or written `none`.
    pub fn param(&self, rule: &RuleSpec, name: StrId) -> Option<ParamValue> {
        self.params_of(rule)
            .iter()
            .find(|&&(declared, _)| declared == name)
            .map(|&(_, value)| value)
    }
}

/// What connects to what: conductors carry current, vias join two conductors.
///
/// Rows of `via_cut` and `via_connects` pair by index, as do `label_layer`
/// and `label_names`.
#[derive(Debug, Default)]
pub struct Connectivity {
    /// The layers that carry a net (`connect conductors [..]`), in the order
    /// written. No global layer is among them.
    pub conductors: Vec<LayerId>,
    /// One row per `connect via` statement: the cut layer...
    pub via_cut: Vec<LayerId>,
    /// ...and the two layers it joins where it overlaps them.
    pub via_connects: Vec<(LayerId, LayerId)>,
    /// Whether shapes on the same conductor layer connect by touching
    /// (`connect touch_within_layer`).
    pub intra_layer_touch: bool,
    /// Net-only layers, each one net however many shapes it holds (the
    /// substrate). Not conductors: they carry no modelled current and no
    /// parasitics, so they need no sheet resistance, nor do vias into them.
    pub global: Vec<LayerId>,
    /// One row per `connect label` statement: the drawn layer a `TEXT` is on...
    pub label_layer: Vec<LayerId>,
    /// ...and the conductor whose shapes it names. When two rows share a text
    /// layer, a label binds through the first row that finds a shape under it.
    pub label_names: Vec<LayerId>,
}

/// How to recognise a device from geometry: one row per `device` statement,
/// in deck order.
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
    /// The device family of each recogniser.
    pub kind: Vec<DeviceKind>,
    /// The layer each of whose shapes is one device.
    pub marker: Vec<LayerId>,
    /// Recogniser `i`'s terminal layers are
    /// `terminal[terminal_start[i]..terminal_start[i + 1]]`: one longer than
    /// `kind`, or empty when the deck declares no device.
    pub terminal_start: Vec<u32>,
    /// Every recogniser's terminal layers, in role order (see above).
    pub terminal: Vec<LayerId>,
    /// Interned model name, for netlist comparison.
    pub model: Vec<StrId>,
}

/// The device families this tool recognises, in the deck as `mos`, `bjt`,
/// `resistor`, `capacitor` and `diode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    /// A MOS transistor; a SPICE `M` card.
    Mos,
    /// A bipolar transistor; a SPICE `Q` card.
    Bjt,
    /// A two-pin resistor; a SPICE `R` card.
    Resistor,
    /// A two-pin capacitor; a SPICE `C` card.
    Capacitor,
    /// A two-pin diode; a SPICE `D` card.
    Diode,
}

/// Per-layer process parameters, for parasitic extraction, indexed by [`LayerId`].
///
/// Every column is empty when the deck has no `pex` statement, and
/// [`LayerTable::len`] long otherwise. A layer with no `pex` row reads `0.0`
/// in every column, which means "not stated", not a measured zero.
#[derive(Debug, Default)]
pub struct ProcessStack {
    /// Conductor thickness, nm.
    pub thickness_nm: Vec<f64>,
    /// Height above the substrate, nm.
    pub height_nm: Vec<f64>,
    /// Sheet resistance, ohms per square.
    pub sheet_res_ohm_sq: Vec<f64>,
    /// Area capacitance to substrate, aF/µm².
    pub area_cap_af_um2: Vec<f64>,
    /// Fringe capacitance to substrate, aF/µm of edge.
    pub fringe_cap_af_um: Vec<f64>,
    /// Relative permittivity of the surrounding dielectric.
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
    layers.texts.clone_from(&doc.texts);
    layers.ignored.clone_from(&doc.ignored);
    layers.ignored.sort_unstable();
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
    // Only a conductor's shapes carry a net; any other layer would read as all
    // different nets, or none the same.
    for rule in doc.rules.iter().filter(|rule| rule.kind == "net_spacing") {
        let layer = &rule.layers[0];
        if !connectivity
            .conductors
            .contains(&layer_of(&layers, strings, layer))
        {
            return Err(DeckError::Malformed(format!(
                "rule {}: net spacing on {layer}, which is not a conductor",
                rule.id
            )));
        }
    }
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
        global: declared.global.iter().map(|name| layer(name)).collect(),
        label_layer: Vec::with_capacity(declared.labels.len()),
        label_names: Vec::with_capacity(declared.labels.len()),
    };
    if let Some(name) = declared
        .global
        .iter()
        .find(|name| connectivity.conductors.contains(&layer(name)))
    {
        return Err(DeckError::Malformed(format!(
            "connect global {name}: a global layer is net-only, not a conductor"
        )));
    }
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
    /// `ignore gds(L, D)` pairs, distinct, none of them a base layer's.
    ignored: Vec<(u16, u16)>,
    /// In declaration order, which decides the ids they take.
    derived: Vec<DerivedSrc>,
    /// Text patterns, indexed by [`DerivedOp::WithText`].
    texts: Vec<String>,
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
    global: Vec<String>,
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
