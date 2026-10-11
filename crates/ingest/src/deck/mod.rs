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

use gpurify_geom::LayerId;
use gpurify_geom::{prefix, Qty, Temperature};
use gpurify_geom::{Dbu, DbuArea};
use gpurify_geom::{StrId, StrTable};

mod kinds;
mod lex;
mod parse;
mod print;
mod source;

pub use parse::{parse_deck, parse_source, Diagnostic};
pub use print::{print, PrintError};
pub use source::{
    lower, ConnectivitySource, DeckSource, DerivedSource, DeviceSource, LabelSource, ParamSource,
    RuleSource, StackSource, ViaSource,
};

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

/// A parsed, validated, grid-resolved deck, built by [`parse_deck`] (or by
/// [`lower`] from a [`DeckSource`]).
///
/// Every table refers to layers by [`LayerId`], and every name (layer, rule,
/// model, parameter) is a [`StrId`] in the [`StrTable`] the deck was parsed
/// with. Lengths are [`Dbu`] on the layout grid the deck was parsed against,
/// so a deck is only meaningful with a layout on that grid.
#[derive(Debug, Default, Clone, PartialEq)]
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
    /// The `temperature` statement's operating temperature, absolute; `None`
    /// when the deck states none. [`ProcessStack::sheet_res_ohm_sq`] is
    /// already at it.
    pub temperature: Option<Qty<Temperature, { prefix::BASE }>>,
    /// The `temperature` statement and the `pex` rows' coefficients as
    /// written, which [`ProcessStack::sheet_res_ohm_sq`] was computed from;
    /// `None` when the deck states no temperature.
    pub temperature_law: Option<TemperatureLaw>,
    /// The `lvs` statements: how the comparison treats each device model.
    pub lvs: LvsControls,
}

/// A deck's `temperature T nominal T0` and, per `pex` row, its sheet
/// resistance at `T0` with its coefficients: the law the stack's sheet
/// resistances were moved to `T` by, kept so the deck can be written again
/// exactly.
#[derive(Debug, Clone, PartialEq)]
pub struct TemperatureLaw {
    /// `T`, the operating temperature, kelvin.
    pub operating_k: f64,
    /// `T0`, the temperature the `sheet` values are stated at, kelvin.
    pub nominal_k: f64,
    /// Per `pex` row, its layer, its sheet resistance at `T0` in ohms per
    /// square, and `(tc1, tc2)` per K and per K².
    pub rows: Vec<(LayerId, f64, (f64, f64))>,
}

/// The layer table, for a reader that needs only the layers
/// ([`flatten`](crate::layout::gds::Library::flatten)).
impl AsRef<LayerTable> for Deck {
    fn as_ref(&self) -> &LayerTable {
        &self.layers
    }
}

/// Itself, so a reader taking any holder of a layer table takes the table.
impl AsRef<LayerTable> for LayerTable {
    fn as_ref(&self) -> &LayerTable {
        self
    }
}

/// Layer names and stream pairs to ids, and back.
///
/// Ids are dense from 0. Drawn layers (`layer x = gds(L, D)`) come first,
/// ascending by name bytes; derived layers follow in declaration order, each
/// computed only from lower ids. Each inner operation of a nested expression
/// such as `(a or b) not c` adds a hidden derived layer (`x#1`, `x#2`, …), and
/// a layer expression written inside a rule adds one named `<rule id>@k`. No
/// deck text can name a hidden layer.
#[derive(Debug, Default, Clone, PartialEq)]
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
    ///
    /// Only a layer the table derives is: an id past the table, as a deck
    /// built by hand with no layer rows gives every layer, is drawn.
    pub fn is_derived(&self, layer: LayerId) -> bool {
        layer
            .idx()
            .checked_sub(usize::from(self.derived_start))
            .is_some_and(|row| row < self.derived.len())
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
    /// Every shape grown by `.0` left and right and `.1` above and below,
    /// corners square (`KLayout`'s `sized(dx, dy)`; `sized(d)` is `(d, d)`);
    /// shrunk when both are negative, a part no wider than twice the shrink
    /// across that axis disappearing. The two never differ in sign.
    Sized(Dbu, Dbu),
    /// `interacting` (`true`): the shapes or edges of operand 0 that touch or
    /// overlap a shape of operand 1, a shared corner counting. `false` is
    /// `not_interacting`, the rest.
    Interacting(bool),
    /// The shapes of operand 0 entirely covered by operand 1, touching its
    /// boundary from inside allowed.
    Inside,
    /// The shapes of operand 0 sharing no area with operand 1; touching is
    /// outside. `KLayout`'s `outside`, and its `not_overlapping`.
    Outside,
    /// `KLayout` `overlapping`: the shapes of operand 0 sharing area with
    /// operand 1. Touching is not overlapping; [`DerivedOp::Outside`] is the
    /// rest.
    Overlapping,
    /// `KLayout` `covering` (`true`): the shapes of operand 0 that hold a whole
    /// shape of operand 1, which may touch the holder's boundary from inside.
    /// `false` is `not_covering`, the rest.
    Covering(bool),
    /// Each hole of each shape, filled; a hole holding an island covers it.
    Holes,
    /// The bounding box of each shape, one shape per box: boxes that overlap
    /// are not merged.
    Extents,
    /// The shapes whose area, holes excluded, lies in `lo..=hi` square grid units.
    WithArea(i128, i128),
    /// The shapes whose narrowest width, as the `width` rule measures it (a
    /// diagonal neck counts), has its square in `lo..=hi` square grid units.
    /// A squared width is a whole number, so the deck's strict bounds are
    /// kept exactly: `with_width(> 70nm)` is `4901..` and holds a `√5000`
    /// neck, `with_width(<= 70nm)` is `..=4900` and does not.
    WithWidth(i128, i128),
    /// `with_bbox_max` (`longer`) or `with_bbox_min`: the shapes whose
    /// bounding box's longer, or shorter, side lies in `lo..=hi` grid units,
    /// as `KLayout`'s selections of those names. The longer side is a straight
    /// feature's length.
    WithBbox {
        /// The longer side (`with_bbox_max`), else the shorter.
        longer: bool,
        /// The least side kept, in grid units.
        lo: i128,
        /// The greatest side kept, in grid units.
        hi: i128,
    },
    /// `rectangles` (`keep`), `squares` (`keep` and `square`),
    /// `non_rectangles` or `non_squares`: the shapes that are, or are not, one
    /// axis-aligned box with no hole, a square having equal sides, as
    /// `KLayout`'s selections of those names and LEF58 `RECTONLY` define them.
    /// Shapes are read merged, so abutting pieces that make one box are a
    /// rectangle, and two boxes meeting only at a corner are one shape that is
    /// not.
    Rectangles {
        /// Squares only.
        square: bool,
        /// `true` keeps the matching shapes, `false` the others.
        keep: bool,
    },
    /// Polygons to their boundary edges, each directed with the material on
    /// its left. The result is an edge layer.
    Edges,
    /// `inside_part` (`true`) or `outside_part`: the parts of each edge of
    /// operand 0 strictly inside, or strictly outside, operand 1's shapes.
    /// Parts on the boundary are in neither.
    Part(bool),
    /// The edges whose length lies in `lo..=hi` grid units.
    WithLength(i128, i128),
    /// `vertical` (`true`) or `horizontal`: the edges of operand 0 running
    /// along that axis, as `KLayout`'s `with_angle(90)` and `with_angle(0)`
    /// select them. An edge layer is axis-aligned, so the two split it.
    Oriented(bool),
    /// `with_text` (`keep`) or `without_text`: the shapes of operand 0 that
    /// hold, on their material or boundary, a `TEXT` drawn on operand 1 (always
    /// a drawn layer) whose string matches [`LayerTable::text`] `text`.
    WithText {
        /// `true` keeps the shapes holding a match, `false` the others.
        keep: bool,
        /// Index of the pattern, for [`LayerTable::text`].
        text: u32,
    },
    /// `KLayout` `extended` on an edge layer: one box per edge, the edge
    /// lengthened by `begin` before its start and `end` past its end, and
    /// widened by `outside` away from its shape and `inside` into it. The
    /// edge runs with its shape on its left, so its start is the corner it
    /// leaves going counter-clockwise round an outer ring. Boxes are not
    /// merged, as `KLayout`'s are not; each length is 0 or more, and
    /// `outside + inside` is positive.
    Extended {
        /// Added before the edge's start.
        begin: Dbu,
        /// Added past the edge's end.
        end: Dbu,
        /// Away from the edge's shape (its right).
        outside: Dbu,
        /// Into the edge's shape (its left).
        inside: Dbu,
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
            | Self::Overlapping
            | Self::Covering(_)
            | Self::Holes
            | Self::Extents
            | Self::WithArea(..)
            | Self::WithWidth(..)
            | Self::Rectangles { .. }
            | Self::WithBbox { .. }
            | Self::WithText { .. }
            | Self::Extended { .. } => Some(false),
            Self::And
            | Self::Or
            | Self::Not
            | Self::Interacting(_)
            | Self::Part(_)
            | Self::WithLength(..)
            | Self::Oriented(_) => None,
        }
    }
}

/// One rule as the deck states it, layers resolved and lengths already [`Dbu`].
///
/// Read its layers and parameters through [`RuleTable::layers_of`] and
/// [`RuleTable::params_of`] rather than slicing by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq)]
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
    /// density rule's `<=` sets; or `warning`, on a rule written so.
    Flag(bool),
    /// An area, already in square grid units.
    Area(DbuArea),
    /// A layer, for rules parameterised by one.
    Layer(LayerId),
    /// A device model name a `device` statement declares, interned.
    Model(StrId),
}

/// Every rule in the deck, `SoA`.
#[derive(Debug, Default, Clone, PartialEq)]
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
#[derive(Debug, Default, Clone, PartialEq)]
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
#[derive(Debug, Default, Clone, PartialEq)]
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
    /// What each recogniser states for its kind's value law, one row per
    /// recogniser as the deck fills it. A table built by hand may leave it
    /// short, and a recogniser past its end states nothing.
    pub value: Vec<DeviceValue>,
}

/// The coefficients a `device` statement may give, from which LVS computes a
/// resistor's `r` and a capacitor's `c` from what is drawn. One left out is
/// `None`, and the value it would give is then not computed: never taken as
/// zero, so a reference that states it gets `lvs.undeclared_param`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct DeviceValue {
    /// `sheet`: a resistor body's resistance per square, in ohms. `r` is
    /// `sheet * l / w`.
    pub sheet_ohm_sq: Option<f64>,
    /// `area_cap`: a capacitor's capacitance per area of its marker, aF/µm².
    pub area_cap_af_um2: Option<f64>,
    /// `fringe_cap`: a capacitor's capacitance per length of its marker's
    /// perimeter, aF/µm. `c` is `area_cap * area + fringe_cap * perim`, of
    /// the terms the statement gives.
    pub fringe_cap_af_um: Option<f64>,
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

/// The `lvs` statements: what the layout-versus-schematic comparison does
/// with a device model beyond what its `device` statement says. Every column
/// is empty when the deck has no `lvs` statement, and LVS then compares as
/// `gpurify_check::lvs` documents.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct LvsControls {
    /// `lvs tolerance`, one row per statement in deck order, at most one per
    /// model and parameter (catalog LVS-014).
    pub tolerance: Vec<LvsTolerance>,
    /// `lvs ignore_parameter "model" param`: `(model, parameter)`, a
    /// parameter that is not compared on that model, nor read by its merges,
    /// as if no card stated it and the layout measured none (catalog
    /// LVS-014). Never `m`, and never one with a tolerance row.
    pub ignore_parameter: Vec<(StrId, StrId)>,
    /// `lvs asymmetric "model"`: MOS models whose source and drain are not
    /// interchangeable, `KLayout`'s DMOS (catalog LVS-031), each once.
    pub asymmetric: Vec<StrId>,
    /// `lvs permute "model" pin pin`: `(model, pin, pin)`, two pins of the
    /// model's devices that are interchangeable (catalog LVS-030), each a
    /// position in its `device` statement's terminal order (see
    /// [`DeviceRecognition`]), the two distinct.
    pub permute: Vec<(StrId, u8, u8)>,
    /// `lvs ignore "model"`: models whose devices are left out of the
    /// comparison on both sides, Netgen's `ignore class` (catalog LVS-034),
    /// each once. The model need not be a deck device: a schematic may hold
    /// devices no recogniser draws.
    pub ignore: Vec<StrId>,
    /// `lvs ignore_shorted "model"`: models whose devices with every
    /// terminal on one net are left out on both sides, Netgen's `ignore
    /// shorted` (catalog LVS-035), each once; any model name, as `ignore`.
    pub ignore_shorted: Vec<StrId>,
    /// `lvs ports_by_name`: each port of the reference's top cell pairs
    /// only with the layout net its label names, `KLayout`'s
    /// `flag_missing_ports` (catalog LVS-001, LVS-016).
    pub ports_by_name: bool,
    /// `lvs range "model" param >= min <= max`, one row per statement, at
    /// most one per model and parameter (catalog LVS-068).
    pub range: Vec<LvsRange>,
    /// `lvs topology relaxed`: a passive or bipolar stating its value merges
    /// in parallel by the value's law, Netgen's `property topology relaxed`
    /// (catalog LVS-043, LVS-044, LVS-049); `lvs topology strict`, the
    /// default, keeps a count instead.
    pub relaxed: bool,
    /// `lvs connect_implicit "pattern"`: label globs (`*` any run, `?` one
    /// character; [`glob_matches`](crate::layout::glob_matches)). Layout nets
    /// whose label matches one are joined for the comparison with every
    /// other net of that label, `KLayout`'s `connect_implicit` ("must
    /// connect" nets; catalog LVS-002).
    pub connect_implicit: Vec<String>,
    /// `lvs connect_explicit "a" "b" ...`: groups of labels, two or more
    /// each, whose layout nets are joined for the comparison, `KLayout`'s
    /// `connect_explicit` (catalog LVS-002).
    pub connect_explicit: Vec<Vec<StrId>>,
}

/// One `lvs range` statement: the bounds a parameter measured on every
/// layout device of a model must lie within, either or both, a value at a
/// bound being legal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LvsRange {
    /// The device model, which a `device` statement declares.
    pub model: StrId,
    /// The parameter, lowercase: a length (`w`, `l`, `perim`, `ps`, `pd`,
    /// `pe`), an area (`area`, `as`, `ad`, `ae`) or the count `nf`.
    pub param: StrId,
    /// The least legal value, when stated.
    pub min: Option<LvsLimit>,
    /// The greatest legal value, when stated.
    pub max: Option<LvsLimit>,
}

/// A bound of an `lvs range` row, on the layout's grid, of the kind its
/// parameter is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LvsLimit {
    /// A length, in database units.
    Length(Dbu),
    /// An area, in square database units.
    Area(DbuArea),
    /// A count.
    Count(u32),
}

/// The names `lvs permute` gives the pins of a device of `kind`, in its
/// `device` statement's terminal order: Netgen's pin names for the SPICE
/// primitives, `end_a` and `end_b`, `top` and `bottom`, `anode` and
/// `cathode`, and a transistor's `gate`, `source`, `drain` and `bulk` and a
/// bipolar's `base`, `emitter` and `collector`.
#[must_use]
pub const fn pin_names(kind: DeviceKind) -> &'static [&'static str] {
    match kind {
        DeviceKind::Mos => &["gate", "source", "drain", "bulk"],
        DeviceKind::Bjt => &["base", "emitter", "collector"],
        DeviceKind::Resistor => &["end_a", "end_b"],
        DeviceKind::Capacitor => &["top", "bottom"],
        DeviceKind::Diode => &["anode", "cathode"],
    }
}

/// One `lvs tolerance` statement: how far apart one parameter of one model
/// may be on the two sides and still agree. Two values `a` and `b` agree when
/// `|a - b| <= absolute + relative * max(|a|, |b|)`, the two parts adding as
/// `KLayout`'s `tolerance` does. The row replaces the run's tolerance for that
/// parameter of that model, so a part it leaves out is zero.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LvsTolerance {
    /// The device model, which a `device` statement declares.
    pub model: StrId,
    /// The parameter, lowercase, as LVS compares it (`w`, `l`, `r`, ...).
    pub param: StrId,
    /// The relative part, a fraction from 0 to 1 of the larger value.
    pub relative: f64,
    /// The absolute part, in the parameter's SI unit (metres, square
    /// metres, ohms, farads, or a count), zero or more.
    pub absolute: f64,
    /// The absolute part as the deck states it, in the deck's unit for the
    /// parameter ([`absolute_unit`]), so the deck prints back exactly.
    pub stated: f64,
}

/// The unit an absolute tolerance on `param` is written in, and the factor
/// from it to SI: a length in nm, an area in nm², a resistance in ohms, a
/// capacitance in aF, a count. A parameter not listed has no known unit, so
/// it takes a relative tolerance only.
#[must_use]
pub fn absolute_unit(param: &str) -> Option<(&'static str, f64)> {
    match param {
        "w" | "l" | "ps" | "pd" | "pe" | "perim" => Some(("nm", 1e-9)),
        "area" | "as" | "ad" | "ae" => Some(("nm2", 1e-18)),
        "r" => Some(("ohm", 1.0)),
        "c" => Some(("aF", 1e-18)),
        "m" | "nf" => Some(("", 1.0)),
        _ => None,
    }
}

/// Per-layer process parameters, for parasitic extraction, indexed by [`LayerId`].
///
/// Every column is empty when the deck has no `pex` statement, and
/// [`LayerTable::len`] long otherwise. A layer with no `pex` row reads `0.0`
/// in every column, which means "not stated", not a measured zero.
///
/// A parsed row is physical: its thickness is positive, its dielectric
/// positive when the row states one (a row may leave it out, and then reads
/// `0.0`, not stated), and every other value zero or more (a zero again reads
/// as "not stated"); the parser refuses anything else, naming the value. A
/// stack built in code is not checked.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ProcessStack {
    /// Conductor thickness, nm.
    pub thickness_nm: Vec<f64>,
    /// Height above the substrate, nm.
    pub height_nm: Vec<f64>,
    /// Sheet resistance, ohms per square (per cut on a via layer), at the
    /// deck's operating temperature ([`Deck::temperature`]): a row's `sheet`
    /// is stated at the `nominal` temperature `T₀` and read at `T` as
    /// `R(T) = R(T₀)·(1 + tc1·(T − T₀) + tc2·(T − T₀)²)`, the law of the
    /// ngspice resistor model (ngspice manual, "Resistors", temperature
    /// coefficients) and of the PDKs' published coefficients, such as
    /// sky130's `tc1rm1`/`tc2rm1` at `tnom = 30` (`sky130_fd_pr` model file
    /// `sky130_fd_pr__model__r+c.model.spice`). Catalog PEX-007.
    pub sheet_res_ohm_sq: Vec<f64>,
    /// Area capacitance to substrate, aF/µm².
    pub area_cap_af_um2: Vec<f64>,
    /// Fringe capacitance to substrate, aF/µm of edge.
    pub fringe_cap_af_um: Vec<f64>,
    /// Relative permittivity of the surrounding dielectric; `0.0` where the
    /// row leaves it out.
    pub dielectric_k: Vec<f64>,
}

/// The `lvs` statements, models interned. A control on a model no `device`
/// statement declares is refused: it would change nothing, silently.
fn build_lvs(
    declared: &LvsSrc,
    devices: &[DeviceSource],
    strings: &mut StrTable,
) -> Result<LvsControls, DeckError> {
    let known = |model: &str, control: &str| {
        if devices.iter().any(|device| device.model == model) {
            Ok(())
        } else {
            Err(DeckError::Malformed(format!(
                "lvs {control}: model \"{model}\" is not declared by any device statement"
            )))
        }
    };
    let mut lvs = LvsControls::default();
    for (model, a, b) in &declared.permute {
        known(model, "permute")?;
        let kind = devices
            .iter()
            .find(|device| device.model == *model)
            .map_or(DeviceKind::Mos, |device| device.kind);
        let names = pin_names(kind);
        let position = |pin: &str| {
            names
                .iter()
                .position(|&name| name == pin)
                .and_then(|at| u8::try_from(at).ok())
                .ok_or_else(|| {
                    DeckError::Malformed(format!(
                        "lvs permute: \"{model}\" has no pin `{pin}`; its pins are {}",
                        names.join(", ")
                    ))
                })
        };
        let (a, b) = (position(a)?, position(b)?);
        if a == b {
            return Err(DeckError::Malformed(format!(
                "lvs permute: \"{model}\" permutes `{}` with itself",
                names[usize::from(a)]
            )));
        }
        let channel = kind == DeviceKind::Mos && a.min(b) == 1 && a.max(b) == 2;
        if channel && declared.asymmetric.contains(model) {
            return Err(DeckError::Malformed(format!(
                "lvs permute: \"{model}\" is asymmetric, so its source and drain do not permute"
            )));
        }
        lvs.permute.push((strings.intern(model), a, b));
    }
    for model in &declared.ignore {
        lvs.ignore.push(strings.intern(model));
    }
    for model in &declared.ignore_shorted {
        lvs.ignore_shorted.push(strings.intern(model));
    }
    lvs.ports_by_name = declared.ports_by_name;
    lvs.relaxed = declared.topology == Some(true);
    lvs.connect_implicit.clone_from(&declared.connect_implicit);
    for group in &declared.connect_explicit {
        lvs.connect_explicit
            .push(group.iter().map(|name| strings.intern(name)).collect());
    }
    for (model, param, min, max) in &declared.range {
        known(model, "range")?;
        lvs.range.push(LvsRange {
            model: strings.intern(model),
            param: strings.intern(param),
            min: *min,
            max: *max,
        });
    }
    for model in &declared.asymmetric {
        known(model, "asymmetric")?;
        if devices
            .iter()
            .any(|device| device.model == *model && device.kind != DeviceKind::Mos)
        {
            return Err(DeckError::Malformed(format!(
                "lvs asymmetric: \"{model}\" is not a mos device; only a transistor has a source and a drain"
            )));
        }
        lvs.asymmetric.push(strings.intern(model));
    }
    for (model, param) in &declared.ignore_parameter {
        known(model, "ignore_parameter")?;
        if let Some(row) = declared
            .tolerance
            .iter()
            .find(|row| row.model == *model && row.param == *param)
        {
            return Err(DeckError::Malformed(format!(
                "lvs tolerance: `{}` of \"{}\" is ignored, so a tolerance on it means nothing",
                row.param, row.model
            )));
        }
        lvs.ignore_parameter
            .push((strings.intern(model), strings.intern(param)));
    }
    for row in &declared.tolerance {
        known(&row.model, "tolerance")?;
        lvs.tolerance.push(LvsTolerance {
            model: strings.intern(&row.model),
            param: strings.intern(&row.param),
            relative: row.relative,
            absolute: row.absolute * absolute_unit(&row.param).map_or(1.0, |(_, to_si)| to_si),
            stated: row.absolute,
        });
    }
    Ok(lvs)
}

/// The `lvs` statements as written, models unresolved: a deck source's
/// [`DeckSource::lvs`], which [`lower`] resolves to [`LvsControls`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LvsSrc {
    pub(crate) tolerance: Vec<ToleranceSrc>,
    /// `(model, parameter)`, the parameter lowercase.
    pub(crate) ignore_parameter: Vec<(String, String)>,
    pub(crate) asymmetric: Vec<String>,
    /// `(model, pin, pin)`, the pins as written.
    pub(crate) permute: Vec<(String, String, String)>,
    pub(crate) ignore: Vec<String>,
    pub(crate) ignore_shorted: Vec<String>,
    pub(crate) ports_by_name: bool,
    /// `(model, parameter, min, max)`, the parameter lowercase.
    pub(crate) range: Vec<(String, String, Option<LvsLimit>, Option<LvsLimit>)>,
    /// `lvs topology`, once: `Some(true)` relaxed, `Some(false)` strict.
    pub(crate) topology: Option<bool>,
    pub(crate) connect_implicit: Vec<String>,
    pub(crate) connect_explicit: Vec<Vec<String>>,
}

/// `lvs tolerance "model" param relative r absolute a`, the absolute part
/// in the deck's unit ([`absolute_unit`]).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ToleranceSrc {
    pub(crate) model: String,
    pub(crate) param: String,
    pub(crate) relative: f64,
    pub(crate) absolute: f64,
}

impl LvsSrc {
    /// The statements that [`lower`] resolves to `controls`, for a deck
    /// whose devices are `devices`: what a compiled deck decompiles to.
    #[must_use]
    pub fn from_controls(
        controls: &LvsControls,
        devices: &[DeviceSource],
        strings: &StrTable,
    ) -> Self {
        let name = |id: StrId| strings.resolve(id).to_owned();
        Self {
            tolerance: controls
                .tolerance
                .iter()
                .map(|row| ToleranceSrc {
                    model: name(row.model),
                    param: name(row.param),
                    relative: row.relative,
                    absolute: row.stated,
                })
                .collect(),
            ignore_parameter: controls
                .ignore_parameter
                .iter()
                .map(|&(model, param)| (name(model), name(param)))
                .collect(),
            asymmetric: controls.asymmetric.iter().map(|&id| name(id)).collect(),
            permute: controls
                .permute
                .iter()
                .map(|&(model, a, b)| {
                    let model = name(model);
                    let kind = devices
                        .iter()
                        .find(|device| device.model == model)
                        .map_or(DeviceKind::Mos, |device| device.kind);
                    let pin = |at: u8| pin_names(kind)[usize::from(at)].to_owned();
                    (model, pin(a), pin(b))
                })
                .collect(),
            ignore: controls.ignore.iter().map(|&id| name(id)).collect(),
            ignore_shorted: controls.ignore_shorted.iter().map(|&id| name(id)).collect(),
            ports_by_name: controls.ports_by_name,
            range: controls
                .range
                .iter()
                .map(|row| (name(row.model), name(row.param), row.min, row.max))
                .collect(),
            topology: controls.relaxed.then_some(true),
            connect_implicit: controls.connect_implicit.clone(),
            connect_explicit: controls
                .connect_explicit
                .iter()
                .map(|group| group.iter().map(|&id| name(id)).collect())
                .collect(),
        }
    }
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

    /// Oracle: construct-from-answer. The table is built from `ROWS`, so each
    /// name resolves to its row index, and `met9`, interned but never declared,
    /// and a name never interned resolve to nothing.
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

    /// Oracle: construct-from-answer. Each `ROWS` pair maps to its row index;
    /// 69/20 is undeclared, 68/21 shares only the layer number, and 66/44 mixes
    /// two rows' halves, so none maps.
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
