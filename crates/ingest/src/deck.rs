//! The PDK deck: process data, and nothing else.
//!
//! A deck describes a *process node*, so it is portable across every design on
//! that node. Anything that differs per chip — supply nets, voltages, current
//! budgets — is design intent and lives in [`crate::intent`]. Mixing the two
//! would mean forking `sky130.json` per chip.
//!
//! # Rule limits are physical
//!
//! Limits are written in the deck as physical nanometres and converted against
//! the layout's grid at load, **exactly or not at all**. That is what makes a
//! deck portable across grids, and why a 45 nm limit on a 5 nm grid is an error
//! rather than a silent 45-rounded-to-45 that is really 9 grid units.
//!
//! # Rule kinds are not interpreted here
//!
//! `ingest` does not know what `min_width` means. It produces [`RuleSpec`] rows
//! with an interned kind, resolved layers and converted parameters; `drc` and
//! `erc` build their own per-kind tables from those. That is what keeps this
//! module from depending on the domains it feeds.

use crate::intern::{StrId, StrTable};
use crate::narrow;
use gpurify_core::LayerId;
use gpurify_units::{prefix::NANO, Dbu, Grid, GridError, Length, Qty};
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
    /// The grid every limit in [`Self::rules`] was converted against — the one
    /// [`parse_deck`] was handed, echoed so a consumer of the deck can state a
    /// limit in nanometres again without being passed the grid a second time.
    ///
    /// `Some` for every deck a parse returns. `None` only on a
    /// default-constructed `Deck`, which holds no rules and so has nothing to
    /// convert. A deck file does **not** declare its own resolution: limits are
    /// physical nanometres and the grid comes from the layout.
    pub grid: Option<Grid>,
    pub layers: LayerTable,
    pub rules: RuleTable,
    pub connectivity: Connectivity,
    pub devices: DeviceRecognition,
    pub stack: ProcessStack,
}

/// Layer names to ids, and back.
///
/// Names arrive from JSON at runtime, so they are interned rather than matched:
/// the compile-time-table rule does not apply to keys the PDK chooses.
#[derive(Debug, Default)]
pub struct LayerTable {
    /// `LayerId(i)` is named `name[i]`.
    name: Vec<StrId>,
    /// GDS layer/datatype pair each id maps to.
    stream: Vec<(u16, u16)>,
    /// Ids sorted by their name's [`StrId`], for the reverse lookup. Sorted,
    /// not hashed — see [`crate::intern`].
    ///
    /// By the id and not by the name's bytes: a name is already a `u32` by the
    /// time it reaches here, so [`Self::id`] resolves the text to a `StrId`
    /// once through the string table and then binary-searches this column on
    /// `u32` comparisons. Ordering by bytes would mean a string compare at
    /// every probe and would make [`Self::build`] need the string table.
    by_name: Vec<LayerId>,
    /// Ids sorted by their `(gds_layer, gds_datatype)` pair, then by id, for
    /// [`Self::of_stream`]. The reverse index of [`Self::stream`] exactly as
    /// [`Self::by_name`] is of [`Self::name`].
    ///
    /// Ties broken by id so a deck that points two names at one stream pair
    /// still has a total, deterministic order, and so the run of equal pairs
    /// starts at the lowest id — which is the id `of_stream` answers with.
    ///
    /// **Base layers only.** A derived layer is computed, not drawn, so no
    /// record in a layout file may map onto one — see [`Self::push_derived`].
    by_stream: Vec<LayerId>,
    /// The id of the first derived layer, and so the number of base ones.
    ///
    /// A `u16` rather than a `LayerId` because a deck with no derived layers
    /// has no such id: the value is one past the last base layer, which is a
    /// count and not a row.
    derived_start: u16,
    /// How each derived layer is computed, one row per id from `derived_start`
    /// up. Here rather than beside `Deck::layers` because a derived layer's id
    /// and its recipe are the same fact: [`Self::push_derived`] is the only way
    /// to get either, so a layer cannot exist without the arithmetic that
    /// produces it.
    derived: DerivedTable,
}

/// The stream pair recorded for a derived layer.
///
/// A derived layer has none — it is computed from other layers, not read off a
/// record — but [`LayerTable::stream`] is a column indexed by [`LayerId`] and
/// every row needs a value. This one is excluded from [`LayerTable::by_stream`],
/// so [`LayerTable::of_stream`] can never answer with a derived layer whatever a
/// file contains. It is *not* an identity: ask [`LayerTable::is_derived`].
const DERIVED_STREAM: (u16, u16) = (u16::MAX, u16::MAX);

impl LayerTable {
    pub fn len(&self) -> usize {
        debug_assert_eq!(self.name.len(), self.stream.len(), "one stream pair per layer");
        debug_assert_eq!(self.name.len(), self.by_name.len(), "one name index entry per layer");
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
    /// `None` for a name the deck does not define. A rule referencing one is a
    /// deck error, not a new layer.
    ///
    /// Two steps, both fail-closed: `strings.get(name)` — never `intern`, this
    /// must not grow the caller's table — and then a binary search of the
    /// `by_name` index. A name the string table holds but the deck never
    /// declared misses the second step.
    pub fn id(&self, strings: &StrTable, name: &str) -> Option<LayerId> {
        // `get`, never `intern`: a name the string table has never seen is not a
        // layer, and growing the caller's table on a lookup would hand back an
        // id for a layer with no geometry — a rule that then reports clean.
        let wanted = strings.get(name)?;
        let at = self
            .by_name
            .binary_search_by_key(&wanted, |&LayerId(i)| self.name[usize::from(i)])
            .ok()?;
        let found = self.by_name[at];
        debug_assert_eq!(self.name[found.idx()], wanted, "the index named another layer");
        Some(found)
    }
    pub fn name(&self, layer: LayerId) -> StrId {
        debug_assert!(layer.idx() < self.name.len(), "layer id past the table");
        self.name[layer.idx()]
    }
    /// Which id a GDS layer/datatype pair maps to.
    ///
    /// A binary search of the [`Self::by_stream`] index, mirroring [`Self::id`].
    /// `layout::gds::Flatten::emit` calls this once per element, so the layer
    /// count is a constant factor on the per-polygon path; the index takes it
    /// from linear to `log2(layers)` probes and, unlike a hash, keeps the table
    /// build order-free and the lookup allocation-free.
    ///
    /// `partition_point` rather than `binary_search_by_key`: it lands on the
    /// *first* id of a run, so a deck pointing two names at one stream pair
    /// answers with the lower id — the answer the scan this replaced gave, and
    /// the only one that does not depend on where the search happened to bisect.
    pub fn of_stream(&self, layer: u16, datatype: u16) -> Option<LayerId> {
        let wanted = (layer, datatype);
        let at = self
            .by_stream
            .partition_point(|&LayerId(i)| self.stream[usize::from(i)] < wanted);
        let found = *self.by_stream.get(at)?;
        // A miss lands on the successor of `wanted`, or past the end. Both are
        // "the deck does not declare this pair", which is the fail-closed
        // answer: an undeclared stream carries no geometry into any rule.
        (self.stream[found.idx()] == wanted).then_some(found)
    }

    /// The GDS stream pair a layer writes to. The inverse of [`Self::of_stream`].
    ///
    /// Reopened in the Testing-Phase: `export::gds::write_store` has to map each
    /// store row's `LayerId` back to a stream pair, and only the forward
    /// direction existed. Without this the writer cannot be implemented as
    /// signed, which blocks the `parse -> write -> parse` law.
    ///
    /// A derived layer answers with [`DERIVED_STREAM`], which is a placeholder
    /// and not a pair the deck states. A writer emitting a store that holds
    /// derived rows should ask [`Self::is_derived`] and skip them: they are the
    /// deck's own arithmetic over layers the file already carries, so writing
    /// them out duplicates area, and reading such a file back maps the
    /// placeholder onto no layer at all.
    pub fn stream_of(&self, layer: LayerId) -> (u16, u16) {
        debug_assert!(layer.idx() < self.stream.len(), "layer id past the table");
        self.stream[layer.idx()]
    }

    /// Is this layer computed by the deck rather than drawn in the layout?
    ///
    /// Derived layers take the ids after every base one, so the test is one
    /// compare. That contiguity is not a convenience: it is what lets
    /// `GeometryStore::append_layer` put their polygons at the tail of a store
    /// that is grouped by layer.
    pub fn is_derived(&self, layer: LayerId) -> bool {
        debug_assert!(layer.idx() < self.name.len(), "layer id past the table");
        layer.0 >= self.derived_start
    }

    /// How the derived layers are computed, in id order.
    ///
    /// `ingest::layout::derive_layers_into` is the one consumer: it walks these
    /// rows in order and appends each result to the store.
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
    /// Appended rather than sorted in: a derived layer's id has to be above
    /// every base one *and* above every derived layer declared before it, which
    /// is also the order they can be materialised in — each one may be built
    /// from the ones already in the store. Ids therefore follow declaration
    /// order here, while base ids follow name order; both are functions of the
    /// deck text, so two runs agree.
    ///
    /// The recipe goes down with the id, in one call, because a derived layer
    /// with no arithmetic behind it is a layer that stays empty for ever — and
    /// an empty conductor reads downstream as geometry nobody connected rather
    /// than as a deck that was assembled wrong.
    ///
    /// The name index is kept sorted so [`Self::id`] still finds it. The stream
    /// index deliberately is not touched.
    ///
    /// # Panics
    ///
    /// When the table already holds `u16::MAX + 1` layers, which is every id
    /// [`LayerId`] can spell, or when `operands` is empty or names a layer at
    /// or above the id being taken — both of which [`parse_deck`] refuses
    /// first, with a message naming the deck row.
    pub fn push_derived(&mut self, name: StrId, op: DerivedOp, operands: &[LayerId]) -> LayerId {
        let id = LayerId(
            u16::try_from(self.name.len()).expect("a deck has tens of layers, and LayerId is a u16"),
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

        // The CSR's leading zero goes down with the first row, exactly as every
        // other segmented column in this module seeds itself.
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
        debug_assert!(self.is_derived(id), "a derived layer took a base layer's id");
        debug_assert!(
            self.derived.layer.windows(2).all(|pair| pair[0] < pair[1]),
            "derived ids come out ascending, which is the order they are materialised in"
        );
        id
    }

    /// Build a layer table from resolved entries.
    ///
    /// Reopened in the Testing-Phase. Every field here is private and
    /// [`read_deck`] was the only producer, so no `Deck` could be built in
    /// memory and nothing taking one was reachable from a test — including
    /// `drc::RuleSet::from_deck`, which is that crate's entire dispatcher.
    ///
    /// Entries are `(name, gds_layer, gds_datatype)`, and `LayerId(i)` is
    /// `entries[i]`. This maintains the sorted index itself, so the invariant
    /// holds for every table that exists rather than for every table someone
    /// remembered to sort.
    ///
    /// A name appearing twice is a malformed deck and [`parse_deck`] rejects it
    /// there; here the later entry simply sorts after the earlier one, so the
    /// index stays total and deterministic rather than depending on which of
    /// two equal keys the sort happened to move. A *stream pair* appearing
    /// twice is not rejected anywhere — nothing forbids two names on one GDS
    /// layer — so the same tie-break carries the by-stream index, and
    /// [`Self::of_stream`] answers with the lower id.
    ///
    /// Implemented rather than deferred to the Implementation-Phase: it is the
    /// fixture every `drc`, `export` and `engine` test needs before any body
    /// exists to test.
    pub fn build(entries: &[(StrId, u16, u16)]) -> Self {
        let count = u16::try_from(entries.len())
            .expect("a deck has tens of layers, and LayerId is a u16");

        let name: Vec<StrId> = entries.iter().map(|&(name, _, _)| name).collect();
        let stream: Vec<(u16, u16)> = entries
            .iter()
            .map(|&(_, layer, datatype)| (layer, datatype))
            .collect();

        let mut by_name: Vec<LayerId> = (0..count).map(LayerId).collect();
        by_name.sort_unstable_by_key(|&LayerId(i)| (name[usize::from(i)], i));

        let mut by_stream: Vec<LayerId> = (0..count).map(LayerId).collect();
        by_stream.sort_unstable_by_key(|&LayerId(i)| (stream[usize::from(i)], i));

        // The sorts are what `id` and `of_stream` binary-search, and a table
        // built unsorted would not fail — it would resolve some names and miss
        // others, which reads downstream as a rule against a layer with no
        // geometry, or as a GDS record on a layer the deck never declared.
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
        debug_assert_eq!(name.len(), by_stream.len(), "one stream index entry per layer");

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
///
/// Three, deliberately, and each is one of `core::boolean`'s: the set a PDK
/// actually writes for connectivity and device recognition. A closed enum, so
/// adding a fourth breaks the match that applies them rather than falling
/// through to a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivedOp {
    /// Intersection. `poly AND diff` is the gate.
    And,
    /// Union.
    Or,
    /// Subtraction. `diff NOT poly` is the source/drain regions, which is what
    /// makes them two conductors rather than one spanning the channel.
    Not,
}

/// Layers the deck computes from other layers.
///
/// Reached through [`LayerTable::derived`], and built only by
/// [`LayerTable::push_derived`], so a derived layer cannot have an id without a
/// recipe or a recipe without an id.
///
/// **Five questions.** In: the deck's `derived` section, names already resolved.
/// Out: one row per derived layer — the id it took, its operator, and the
/// operand layers in the order it folds them. How many: tens per deck, read
/// once per run when the store is built. Access pattern: one forward scan in id
/// order. Lifetime: the whole run, with the deck. Parallelisable: no, and it
/// must not be — a row may name a layer an earlier row produced.
///
/// # Why an operator and a list rather than an expression tree
///
/// Because a derived layer has a real [`LayerId`], every intermediate result
/// can be a named layer, and a nested expression is spelled as two rows. That
/// is how a PDK deck is written anyway — Calibre's SVRF layer statements and
/// `KLayout`'s DRC scripts both name each step — and it removes the two things
/// a tree would need here: name resolution separate from the layer table, and a
/// topological sort. A row may only name layers with a lower id, so declaration
/// order *is* evaluation order and a cycle is unspellable.
///
/// Operands fold left: `{ "op": "not", "layers": ["a", "b", "c"] }` is
/// `(a − b) − c`, and a single operand is a copy.
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
        debug_assert_eq!(self.layer.len(), self.op.len(), "one operator per derived layer");
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
        debug_assert!(start < end, "a derived layer is computed from at least one layer");
        debug_assert!(end <= self.operand.len(), "an operand range runs off the table");
        &self.operand[start..end]
    }
}

/// One rule as the deck states it, before any domain interprets it.
///
/// Layers are resolved and lengths are already converted to [`Dbu`], so a
/// domain building its tables does no parsing and no grid arithmetic.
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
///
/// A closed enum rather than a string: the set of shapes a limit can take is
/// fixed, and a domain matching on it exhaustively cannot silently ignore one.
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
///
/// Flat side arrays rather than a `Vec` per rule: a deck has hundreds of rules
/// with two or three parameters each, and the nested form is a thousand tiny
/// allocations for data read once.
#[derive(Debug, Default)]
pub struct RuleTable {
    pub spec: Vec<RuleSpec>,
    pub layer_ref: Vec<LayerId>,
    /// Parameter name and value. Names are interned; a domain looks a parameter
    /// up by linear scan over the two or three a rule has, once at load.
    pub param: Vec<(StrId, ParamValue)>,
}

impl RuleTable {
    pub fn layers_of(&self, rule: &RuleSpec) -> &[LayerId] {
        let start = rule.layer_start as usize;
        let end = start + rule.layer_len as usize;
        debug_assert!(end <= self.layer_ref.len(), "a rule's layer range runs off the table");
        &self.layer_ref[start..end]
    }
    pub fn params_of(&self, rule: &RuleSpec) -> &[(StrId, ParamValue)] {
        let start = rule.param_start as usize;
        let end = start + rule.param_len as usize;
        debug_assert!(end <= self.param.len(), "a rule's parameter range runs off the table");
        &self.param[start..end]
    }
    /// Look up one parameter by interned name.
    ///
    /// **Decision** — a linear scan over two or three entries, run once per
    /// rule at table-build time. A map here would be slower and would
    /// reintroduce iteration-order nondeterminism for nothing.
    pub fn param(&self, rule: &RuleSpec, name: StrId) -> Option<ParamValue> {
        self.params_of(rule)
            .iter()
            .find(|&&(declared, _)| declared == name)
            .map(|&(_, value)| value)
    }
}

/// What connects to what.
///
/// Consumed by `topology`. Conductors are layers that carry current; vias are
/// layers whose presence joins two conductors.
#[derive(Debug, Default)]
pub struct Connectivity {
    pub conductors: Vec<LayerId>,
    /// One row per via layer: the cut layer and the two layers it joins.
    pub via_cut: Vec<LayerId>,
    pub via_connects: Vec<(LayerId, LayerId)>,
    /// Whether shapes on the same conductor layer connect by touching.
    pub intra_layer_touch: bool,
    /// One row per net-label layer: the layer a `TEXT` is drawn on, and the
    /// conductor layer whose shapes it names.
    ///
    /// # Why this is a deck table and not a rule
    ///
    /// The GDSII Stream Format specification defines no relationship between a
    /// `TEXT` element and any other element. The words *net*, *netlist*,
    /// *connectivity*, *pin*, *port* and *terminal* do not appear in it at all;
    /// `LAYER` and `TEXTTYPE` are opaque integers. So "which text names which
    /// conductor" is not derivable from a layout file, and no rule this crate
    /// could hardcode would be portable — the PDKs disagree with each other:
    ///
    /// | PDK | met1 drawn | pin | label |
    /// |---|---|---|---|
    /// | sky130 | 68/20 | 68/16 | 68/5 |
    /// | GF180MCU | 34/0 | *(none)* | 34/10 |
    ///
    /// sky130 splits `.drawing` / `.pin` / `.label` / `.net` across datatypes
    /// 20/16/5/23 per metal; GF180MCU has one `_Label` datatype and no pin
    /// datatype. A reader that guessed same-layer would see sky130's
    /// drawing-layer text and none of the rest, and none of GF180MCU's.
    ///
    /// The pairing is therefore stated, once, here — the same shape `KLayout`'s
    /// `connect(metal1, metal1_labels)` takes, and the same thing Magic's
    /// `cifinput` `labels` statement is.
    ///
    /// # One conductor per label layer
    ///
    /// `label_layer` is *not* required to be unique across rows, but each row
    /// names exactly one conductor, so a label can never join two conductor
    /// layers into one net. A text layer paired with two conductors would be a
    /// short manufactured by the deck rather than drawn by the designer, which
    /// is why the column is a pair and not a set.
    pub label_layer: Vec<LayerId>,
    /// The conductor each row of `label_layer` names. Parallel to it.
    pub label_names: Vec<LayerId>,
}

/// How to recognise a device from geometry.
///
/// # Terminal order is the role
///
/// A terminal's *role* — gate, source, drain, bulk — is not a column here and
/// cannot be: `TerminalRole` is a `topology` type and `topology` sits above this
/// crate. The role is therefore the terminal's **position**, fixed per family:
///
/// | [`DeviceKind`] | `terminal[k]`, in order from k = 0 |
/// |---|---|
/// | `Mos` | gate, source, drain, bulk |
/// | `Bjt` | base, emitter, collector, then bulk if a fourth is declared |
/// | `Resistor`, `Capacitor`, `Diode` | pin 0, pin 1 — symmetric, so the comparator may swap them |
///
/// Written down in the Testing-Phase because it was written down nowhere: the
/// convention existed only in `gpurify-testgen`'s netlist builder and the tests
/// calibrated against it, and a deck author reading this type had no way to know
/// which order to state. A recogniser whose terminals are in a different order
/// extracts a transistor with its source and drain transposed, which LVS reports
/// as a mismatch in the layout.
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
///
/// Closed, because each is a different extraction and a different comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Mos,
    Bjt,
    Resistor,
    Capacitor,
    Diode,
}

/// Per-layer process parameters, for parasitic extraction.
///
/// Ordered ascending by [`LayerId`] and indexed by it directly — the layer
/// stack is dense and small, so this is an array lookup with no hashing. The
/// old implementation used a `HashMap` here, and its iteration order is what
/// made interlayer capacitance rows swap between runs.
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
/// Reopened in the Testing-Phase. [`read_deck`] took a `&Path` and was the only
/// producer, so `DeckError::OffGrid`, `UnknownLayer`, `MissingParam` and
/// `DuplicateRule` were all unreachable from a test — every fail-closed
/// guarantee this module makes was unverifiable.
///
/// # Schema
///
/// JSON, stated here because it was stated nowhere and a parser whose input
/// format is undocumented cannot be tested against anything:
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
/// ## Derived layers are layers
///
/// A `derived` row produces a real [`LayerId`], and everything that names a
/// layer — a rule, a conductor, a via's endpoints, the conductor a label layer
/// names, a device's marker or terminal — may name it. That is the point: net
/// extraction, label binding and device recognition all address geometry by
/// store row, so a computed layer only reaches them by having rows of its own.
/// `ingest::layout` materialises them during the read.
///
/// The ids come *after* every base layer, in declaration order, so a row may
/// fold only layers declared before it. That makes declaration order evaluation
/// order and a cycle unspellable, and it is what lets the polygons be appended
/// to a store that is grouped by layer. What a derived layer does not have is a
/// GDS stream pair: no record in a layout file ever maps onto one.
///
/// ## Parameter values are tagged
///
/// [`ParamValue`] is a closed enum and nothing in the deck says which variant a
/// kind expects, so the *value* carries its own shape rather than being guessed
/// from its JSON type — a bare `45` cannot be told from a ratio of `45`:
///
/// | JSON | becomes |
/// |---|---|
/// | `{ "nm": 45 }` | [`ParamValue::Length`], converted against `grid` |
/// | `{ "ratio": 2.5 }` | [`ParamValue::Ratio`] |
/// | `{ "count": 4 }` | [`ParamValue::Count`] |
/// | `{ "layer": "met1" }` | [`ParamValue::Layer`], resolved |
/// | `true` / `false` | [`ParamValue::Flag`] |
///
/// Lengths are **physical nanometres** and convert exactly or not at all, which
/// is what makes `DeckError::OffGrid` a property of the deck and the grid
/// together rather than of a rounding mode.
///
/// ## What each refusal is
///
/// Stated so each is constructible on purpose: `Malformed` for anything that is
/// not this shape — bad JSON, a value of the wrong type, an unrecognised
/// `device_recognition.kind`; `UnknownLayer` for any layer name, anywhere,
/// absent from `"layers"`; `MissingParam` for a rule with no `kind` or no
/// `layers`; `OffGrid` for a length that is not an exact multiple of the grid;
/// `DuplicateRule` for a rule id stated twice. Never a skip, in any case.
///
/// ## Kinds are not interpreted here
///
/// `kind` is interned verbatim. `ingest` does not know the vocabulary and must
/// not: `gpurify_drc::ruleset::KINDS` and `gpurify_erc::ruleset::KINDS` are the
/// two lists, and both live above this crate in the module graph.
///
/// A row still does not record which domain it belongs to, and both
/// `from_deck`s read the one [`RuleTable`] — so neither can refuse a kind, since
/// the other domain's rows are unrecognised to it. Each files the kinds it
/// spells and steps over the rest. The refusal that keeps a misspelled rule from
/// reading as a clean design moved up to `gpurify_engine::run::run_checks`,
/// which is the only layer holding both vocabularies. A deck may therefore hold
/// rules of both domains.
///
/// The two lists are disjoint, which is what makes "a row belongs to exactly one
/// domain" true. `"antenna"` was once in both, with two mutually exclusive
/// schemas, so a row spelled that way was filed by both and failed one of them.
/// The antenna family is `erc`'s and `drc`'s copy is deleted; see
/// `docs/SIGNATURE_DEFECTS.md` under `## erc`.
pub fn parse_deck(source: &str, grid: Grid, strings: &mut StrTable) -> Result<Deck, DeckError> {
    let doc: DeckJson =
        serde_json::from_str(source).map_err(|why| DeckError::Malformed(why.to_string()))?;

    let mut layers = build_layers(&doc.layers, strings)?;
    // Before every other section, because a rule, a conductor, a via, a label
    // pairing or a device terminal may name a derived layer, and none of them
    // can resolve a name the table does not hold yet. And before `build_stack`,
    // whose columns are one row per layer.
    build_derived(&doc.derived, &mut layers, strings)?;
    let rules = build_rules(&doc.rules, &layers, grid, strings)?;
    let connectivity = build_connectivity(&doc.connectivity, &layers, strings)?;
    let devices = build_devices(&doc.device_recognition, &layers, strings)?;
    let stack = build_stack(&doc.pex, &layers, strings)?;

    debug_assert_eq!(devices.kind.len(), devices.marker.len(), "one marker per recogniser");
    debug_assert_eq!(devices.kind.len(), devices.model.len(), "one model per recogniser");
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

/// The `"derived"` section, layers resolved and ids assigned.
///
/// **Transform, A-to-B.** Grows `layers` by one id per row, in declaration
/// order, which is what makes declaration order evaluation order.
///
/// Every refusal here is a deck error naming the row: an operand the table does
/// not hold yet — including the row's own name, and including a row declared
/// later — is [`DeckError::UnknownLayer`], because a forward reference has no
/// value at the point it would be read and an empty layer in its place is a
/// rule that reports clean. A row with no operands is
/// [`DeckError::MissingParam`], a name already taken is `Malformed`.
fn build_derived(
    declared: &[DerivedJson],
    layers: &mut LayerTable,
    strings: &mut StrTable,
) -> Result<(), DeckError> {
    // One buffer for the whole section: a row has a handful of operands, and
    // they have to be resolved before the id is taken so a self-reference is an
    // unresolved name rather than a layer folding itself.
    let mut operands: Vec<LayerId> = Vec::new();
    for row in declared {
        if row.layers.is_empty() {
            return Err(DeckError::MissingParam(row.name.clone(), "layers".to_owned()));
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
///
/// **Decision** — the one place a deck name becomes a [`LayerId`], so
/// `UnknownLayer` cannot be forgotten at one of the five sections that resolve
/// names.
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

/// Layer names to a [`LayerTable`], ids ascending by name.
///
/// Sorted by the name's *bytes* rather than by its [`StrId`]: an id is the
/// order the parser happened to intern in, and the doc promises the ids two
/// runs over the same text agree on. Sorting also puts a repeated name next to
/// itself, which is how the duplicate is found.
fn build_layers(declared: &Pairs<(u16, u16)>, strings: &mut StrTable) -> Result<LayerTable, DeckError> {
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
/// converted.
///
/// **Transform, A-to-B.** Rules keep the order the deck states them in, so a
/// report's rule order is the deck author's order.
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
            table.layer_ref.push(layer_of(layers, strings, rule_id, name)?);
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

    debug_assert_eq!(table.spec.len(), declared.0.len(), "one row per declared rule");
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
        ParamJson::Layer(ref name) => {
            ParamValue::Layer(layer_of(layers, strings, rule_id, name)?)
        }
    })
}

/// A physical nanometre limit to grid units, exactly or not at all.
///
/// A limit that rounds is a limit the foundry did not state, so both refusals
/// here are typed. `NotFinite` is separated from the rest because a `NaN` is
/// not "off the grid" — it is off everything, and reporting it as an off-grid
/// limit sends the deck author looking at their resolution.
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
        // Fail closed on a pairing that names a layer the deck does not call a
        // conductor. A label binds to a *net*, and a shape on a non-conductor
        // layer is on no net — `topology::port` would refuse it as
        // `OrphanLabel` at run time, one layout late and with no way to say
        // which deck row was wrong.
        if !connectivity.conductors.contains(&names) {
            return Err(DeckError::Malformed(format!(
                "connectivity: label layer {} names {}, which is not a conductor",
                label.layer, label.names
            )));
        }
        let text = layer_of(layers, strings, "connectivity", &label.layer)?;
        // A `TEXT` record carries a stream pair, and a derived layer has none,
        // so a pairing that puts the text on one can never bind a label. Left
        // to run time it is silence: no label placed, no net named, and
        // `export::parasitic` failing on the first unnamed net of a design that
        // labelled every one of them.
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
///
/// Terminal order is the role — see [`DeviceRecognition`]. The deck states the
/// terminals in that order and this preserves it; nothing here knows what the
/// positions mean.
fn build_devices(
    declared: &[DeviceJson],
    layers: &LayerTable,
    strings: &mut StrTable,
) -> Result<DeviceRecognition, DeckError> {
    let mut devices = DeviceRecognition::default();
    if declared.is_empty() {
        // An absent section leaves the table empty, sentinel included: a
        // `terminal_start` of `[0]` would claim a recogniser row that the empty
        // `kind` column does not have.
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
        devices
            .marker
            .push(layer_of(layers, strings, "device_recognition", &device.marker)?);
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
/// Every column is `layers.len()` long once the section exists at all, because
/// `pex::stack_row` indexes it directly. A declared layer the section omits
/// keeps its zero, which is a layer that contributes no capacitance and no
/// resistance rather than one that indexes a neighbour's.
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

/// The key/value pairs of a JSON object, in the order the file states them and
/// with repeats kept.
///
/// `serde_json::Map` is the obvious type and is the wrong one: it collapses a
/// repeated key to the last value, which would make `DeckError::DuplicateRule`
/// unreachable and would silently drop one of two rules with the same id.
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
/// a deck with no connectivity at all, which extracts every shape as its own
/// net and reports a clean LVS for a chip that is not connected.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct DeckJson {
    #[serde(default)]
    layers: Pairs<(u16, u16)>,
    /// An array, not an object: the order rows are declared in decides the ids
    /// they take and therefore which of them may name which, so it is part of
    /// the meaning rather than of the formatting.
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
}

/// `kind` and `layers` are `Option` rather than required, so their absence is
/// `DeckError::MissingParam` naming the rule instead of a serde message naming
/// a byte offset.
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
    /// Untagged, because a flag has nothing to disambiguate: `true` is a flag
    /// and no other variant is a bare boolean.
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
///
/// `names` rather than `connects`, because this is not a connection — a label
/// joins nothing to anything. It renames one net, and the pairing says which
/// layer's nets it may rename.
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
///
/// `layers` rather than `operands`, so the key reads the same as it does on a
/// rule — in both places it is the list of layer names the row is about.
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

/// Read and validate a deck against a layout's grid.
///
/// A thin wrapper over [`parse_deck`]: reads the file, and every decision after
/// that belongs to the parser. Keeping the file read out of the parser is what
/// makes the parser testable.
///
/// **Transform, generative.** The grid is a parameter because limit conversion
/// depends on it: the same deck loaded against two grids produces two
/// [`Deck`]s, or an error on the grid that cannot represent a limit.
///
/// Interns into the caller's [`StrTable`] so deck names and layout names share
/// one id space.
pub fn read_deck(
    path: &std::path::Path,
    grid: Grid,
    strings: &mut StrTable,
) -> Result<Deck, DeckError> {
    // The path is in the message: a run loads a deck, a layout, a netlist and
    // an intent file, and "No such file or directory" alone names none of them.
    let source = std::fs::read_to_string(path)
        .map_err(|why| DeckError::Io(format!("{}: {why}", path.display())))?;
    parse_deck(&source, grid, strings)
}

/// Layer-table tests, and the fixture the layout tests borrow.
///
/// These stay unit tests: the layout tests beside them need a populated [`Deck`]
/// and building one is cheapest from inside the module that owns the fields.
/// They no longer *have* to be — [`LayerTable::build`] was added in the
/// Testing-Phase and the fixture goes through it, so what these tests exercise
/// is the constructor every other crate now uses rather than a second one
/// written here.
#[cfg(test)]
pub(crate) mod tests {
    use super::{LayerTable, StrTable};
    use gpurify_core::LayerId;

    /// Build a layer table from `(name, gds layer, gds datatype)` rows.
    pub(crate) fn layer_table(strings: &mut StrTable, rows: &[(&str, u16, u16)]) -> LayerTable {
        let entries: Vec<_> = rows
            .iter()
            .map(|&(name, layer, datatype)| (strings.intern(name), layer, datatype))
            .collect();
        LayerTable::build(&entries)
    }

    /// The rows every layout test in this crate is written against.
    pub(crate) const ROWS: [(&str, u16, u16); 3] = [("met1", 68, 20), ("via1", 67, 44), ("poly", 66, 20)];

    /// Oracle: construct-from-answer. The table is built from three known rows,
    /// so every lookup has an answer decided before the lookup ran. The
    /// undeclared name is the load-bearing case: a rule naming a layer the deck
    /// does not define must be a deck error, and a table that interned the name
    /// on the way past would hand back an id for a layer with no geometry — a
    /// rule that then reports clean forever.
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
            layers.id(&strings, "a name nothing ever interned").is_none(),
            "an unknown name resolved to a layer"
        );
        assert_eq!(
            strings.resolve(stray),
            "met9",
            "the lookup mutated the string table it was handed"
        );
    }

    /// Oracle: construct-from-answer. Stream pairs are the reader's entry
    /// point: a GDSII record carries `(layer, datatype)` and nothing else, so
    /// this mapping decides which shapes exist. The datatype half is checked
    /// separately because a table keyed on the layer number alone answers every
    /// query in this test correctly except the last two.
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

