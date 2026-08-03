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
use gpurify_core::LayerId;
use gpurify_units::{Dbu, Grid};

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
    /// Ids sorted by name, for the reverse lookup. Sorted, not hashed — see
    /// [`crate::intern`].
    by_name: Vec<LayerId>,
}

impl LayerTable {
    pub fn len(&self) -> usize {
        todo!()
    }
    pub fn is_empty(&self) -> bool {
        todo!()
    }
    /// `None` for a name the deck does not define. A rule referencing one is a
    /// deck error, not a new layer.
    pub fn id(&self, strings: &StrTable, name: &str) -> Option<LayerId> {
        todo!()
    }
    pub fn name(&self, layer: LayerId) -> StrId {
        todo!()
    }
    /// Which id a GDS layer/datatype pair maps to.
    pub fn of_stream(&self, layer: u16, datatype: u16) -> Option<LayerId> {
        todo!()
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
        todo!()
    }
    pub fn params_of(&self, rule: &RuleSpec) -> &[(StrId, ParamValue)] {
        todo!()
    }
    /// Look up one parameter by interned name.
    ///
    /// **Decision** — a linear scan over two or three entries, run once per
    /// rule at table-build time. A map here would be slower and would
    /// reintroduce iteration-order nondeterminism for nothing.
    pub fn param(&self, rule: &RuleSpec, name: StrId) -> Option<ParamValue> {
        todo!()
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
}

/// How to recognise a device from geometry.
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

/// Read and validate a deck against a layout's grid.
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
    todo!()
}

/// Layer-table tests, and the fixture the layout tests borrow.
///
/// These are unit tests rather than integration tests for one reason:
/// [`LayerTable`] has private fields and no constructor, and [`read_deck`] —
/// its only producer — takes a path to a file whose schema is not stated
/// anywhere a test can write against. So a deck cannot be built in memory from
/// outside this crate, and nothing that takes one can be exercised. That is a
/// Definition-Phase defect, recorded in `docs/NEED_TESTING.md` rather than
/// fixed here; signatures are frozen. Building the table from its fields inside
/// the module that owns them is the workaround, and it costs the round-trip law
/// nothing.
#[cfg(test)]
pub(crate) mod tests {
    use super::{LayerTable, StrTable};
    use gpurify_core::LayerId;

    /// Build a layer table from `(name, gds layer, gds datatype)` rows.
    ///
    /// `by_name` is the reverse-lookup index and is ordered by the layer's
    /// *name bytes*, matching [`crate::intern::StrTable`]'s sorted index — the
    /// field's doc comment points at it for exactly this reason.
    pub(crate) fn layer_table(strings: &mut StrTable, rows: &[(&str, u16, u16)]) -> LayerTable {
        let name = rows.iter().map(|&(n, _, _)| strings.intern(n)).collect();
        let stream = rows.iter().map(|&(_, l, d)| (l, d)).collect();

        let mut order: Vec<usize> = (0..rows.len()).collect();
        order.sort_unstable_by_key(|&i| rows[i].0);
        let by_name = order
            .into_iter()
            .map(|i| LayerId(u16::try_from(i).expect("a deck has tens of layers")))
            .collect();

        LayerTable {
            name,
            stream,
            by_name,
        }
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
