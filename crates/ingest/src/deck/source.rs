//! A deck as names: what the parser reads, what a deck built in code holds,
//! and what the printer writes, before [`lower`] resolves it to a [`Deck`].
//!
//! Every value is already converted to the unit the engines store (lengths in
//! grid units of the layout grid the deck was read for), but layers, models
//! and rule ids are still names. [`lower`] resolves the names, assigns the
//! ids, and refuses what contradicts itself, so a source built by anyone
//! lowers to a deck the engines can trust as one parsed from text.

use super::kinds::EDGE_KINDS;
use super::{build_lvs, LvsSrc};
use super::{
    Connectivity, Deck, DeckError, DerivedOp, DeviceKind, DeviceRecognition, DeviceValue,
    Extraction, LayerTable, ParamValue, ProcessCorner, ProcessStack, RuleSpec, RuleTable, Stages,
    TemperatureLaw,
};
use crate::narrow;
use gpurify_geom::{LayerId, StrId, StrTable};

/// A whole deck by name, in statement order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DeckSource {
    /// Drawn layers, each with its GDS layer and datatype. Their ids are
    /// assigned ascending by name, so their order here does not matter.
    pub layers: Vec<(String, (u16, u16))>,
    /// `ignore gds(L, D)` pairs: distinct, none of them a drawn layer's.
    pub ignored: Vec<(u16, u16)>,
    /// Derived layers in declaration order, which is their id order. A
    /// nested expression is a row per operation: the inner ones named
    /// `<layer>#k`, numbered in post-order, and a layer expression written
    /// inside a rule `<rule id>@k`, numbered in argument order. No deck text
    /// can name either.
    pub derived: Vec<DerivedSource>,
    /// Text and cell-name patterns, indexed by [`DerivedOp::WithText`]'s `text`
    /// and [`DerivedOp::InCells`]'s `first..first + count`, in the
    /// order the derived rows name them.
    pub texts: Vec<String>,
    /// Every rule, in deck order (a `for` loop's in iteration order).
    pub rules: Vec<RuleSource>,
    /// The `connect` statements.
    pub connectivity: ConnectivitySource,
    /// The `device` statements, in order.
    pub devices: Vec<DeviceSource>,
    /// The `pex` rows, each a layer name and its values.
    pub pex: Vec<(String, StackSource)>,
    /// `temperature T nominal T0`: `(T, T0)`, kelvin, both positive.
    pub temperature: Option<(f64, f64)>,
    /// The `lvs` statements, as the parser reads them.
    pub lvs: LvsSrc,
    /// The `extraction` statement, if the deck has one.
    pub extraction: Option<Extraction>,
    /// The `corner` lines, in deck order.
    pub corners: Vec<CornerSource>,
    /// The `stage` lines, in deck order, each with the ids of the rules
    /// written after it. Empty: the deck is not staged.
    pub stages: Vec<(String, Vec<String>)>,
    /// The `waive` lines, each a rule id and a layer, in deck order.
    pub waivers: Vec<(String, String)>,
}

/// One `corner` line: `corner <corner> <layer> <key> <value> ..`.
#[derive(Debug, Clone, PartialEq)]
pub struct CornerSource {
    /// The corner's name.
    pub corner: String,
    /// The layer whose `pex` row it varies.
    pub layer: String,
    /// The values it states.
    pub values: CornerValues,
}

/// A `corner` line's values: one per `pex` key, in the order `thickness`
/// (nm), `height` (nm), `sheet` (ohms per square, at the nominal
/// temperature), `dielectric`, `area_cap` (aF/µm²), `fringe_cap` (aF/µm),
/// `tc1` (1/K) and `tc2` (1/K²); `None` where the line states none.
pub type CornerValues = [Option<f64>; 8];

/// One derived layer: `name = layers[0] op layers[1] ..`.
#[derive(Debug, Clone, PartialEq)]
pub struct DerivedSource {
    /// The layer's name.
    pub name: String,
    /// The operation; [`DerivedOp`] says what each operand position means.
    pub op: DerivedOp,
    /// The operands, each a layer declared before this one.
    pub layers: Vec<String>,
}

/// One rule: an engine kind with its layers and named parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleSource {
    /// The rule's id, unique in the deck.
    pub id: String,
    /// The engine kind name (`min_width`), one the DRC or ERC kind list
    /// spells.
    pub kind: &'static str,
    /// The layer arguments in the order the engine kind takes them, which
    /// can differ from the deck's: `enclosure(inner, outer)` is stored outer
    /// first.
    pub layers: Vec<String>,
    /// The parameters by engine name. A list is one row per element under
    /// one name; a parameter written `none` has no row.
    pub params: Vec<(&'static str, ParamSource)>,
}

/// A parameter value: converted, or a name still to resolve.
#[derive(Debug, Clone, PartialEq)]
pub enum ParamSource {
    /// A value in its engine unit. Never [`ParamValue::Layer`] or
    /// [`ParamValue::Model`], which are names here.
    Value(ParamValue),
    /// A layer, by name.
    Layer(String),
    /// A device model, by name; some `device` statement declares it.
    Model(String),
}

/// The `connect` statements.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConnectivitySource {
    /// `connect conductors [..]`, every list in order.
    pub conductors: Vec<String>,
    /// `connect touch_within_layer`.
    pub intra_layer_touch: bool,
    /// `connect global L`, in order.
    pub global: Vec<String>,
    /// `connect via L [a, b]`, in order.
    pub vias: Vec<ViaSource>,
    /// `connect label T names C`, in order.
    pub labels: Vec<LabelSource>,
}

/// `connect via <layer> [<a>, <b>]`.
#[derive(Debug, Clone, PartialEq)]
pub struct ViaSource {
    /// The cut layer.
    pub layer: String,
    /// The two layers it joins where it overlaps them.
    pub connects: (String, String),
}

/// `connect label <layer> names <conductor>`.
#[derive(Debug, Clone, PartialEq)]
pub struct LabelSource {
    /// The drawn layer the text is on.
    pub layer: String,
    /// The conductor whose shapes it names.
    pub names: String,
}

/// One `device` statement.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceSource {
    /// The family.
    pub kind: DeviceKind,
    /// The marker layer: each of its shapes is one device.
    pub marker: String,
    /// The model name LVS compares.
    pub model: String,
    /// The terminal layers, in role order ([`DeviceRecognition`]).
    pub terminals: Vec<String>,
    /// The value-law coefficients the statement gives.
    pub value: DeviceValue,
}

/// One `pex` row, in [`ProcessStack`]'s units; `0.0` is "not stated".
/// `sheet_res_ohm_sq` is at the deck's nominal temperature.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct StackSource {
    /// Conductor thickness, nm; positive.
    pub thickness_nm: f64,
    /// Height above the substrate, nm.
    pub height_nm: f64,
    /// Sheet resistance, ohms per square.
    pub sheet_res_ohm_sq: f64,
    /// Area capacitance to substrate, aF/µm².
    pub area_cap_af_um2: f64,
    /// Fringe capacitance to substrate, aF/µm.
    pub fringe_cap_af_um: f64,
    /// Relative permittivity; `0.0` when the row leaves it out.
    pub dielectric_k: f64,
    /// `(tc1 per K, tc2 per K²)`, given together or not at all; a deck
    /// with a temperature gives every row both.
    pub tc: Option<(f64, f64)>,
}

/// Resolves a source to a [`Deck`]. Drawn layers take ids ascending by name
/// bytes; derived layers follow in declaration order. Strings are interned
/// in section order (layers, derived layers, rules, connectivity, devices),
/// so the same source and table state always give the same [`StrId`]s.
///
/// # Errors
///
/// [`DeckError::Malformed`] for the first contradiction: a name declared
/// twice or used before it is declared, an edge layer where polygons are
/// wanted or polygons where edges are, a text layer that is not drawn, a
/// rule naming a model no device declares, net spacing on a non-conductor, a
/// global layer also listed as a conductor, or a label row whose text layer
/// is derived or whose named layer is not a conductor. The parser refuses
/// all of these with a line and column first; a source built in code meets
/// them here.
///
/// # Examples
///
/// ```
/// use gpurify_geom::StrTable;
/// use gpurify_ingest::deck::{lower, DeckSource, DerivedOp, DerivedSource};
///
/// let mut source = DeckSource::default();
/// source.layers.push(("met1".to_owned(), (68, 20)));
/// source.derived.push(DerivedSource {
///     name: "fat".to_owned(),
///     op: DerivedOp::Holes,
///     layers: vec!["met2".to_owned()],
/// });
/// assert!(lower(&source, &mut StrTable::default()).is_err(), "met2 is not declared");
/// source.derived[0].layers = vec!["met1".to_owned()];
/// let deck = lower(&source, &mut StrTable::default())?;
/// assert_eq!(deck.layers.len(), 2);
/// # Ok::<(), gpurify_ingest::deck::DeckError>(())
/// ```
pub fn lower(doc: &DeckSource, strings: &mut StrTable) -> Result<Deck, DeckError> {
    let malformed = |message: String| Err(DeckError::Malformed(message));
    let mut layers = build_layers(&doc.layers, strings)?;
    // First: any later section may name a derived layer.
    for row in &doc.derived {
        if layers.id(strings, &row.name).is_some() {
            return malformed(format!("layer {} is declared twice", row.name));
        }
        let operands = row
            .layers
            .iter()
            .map(|name| layer_of(&layers, strings, name, &row.name))
            .collect::<Result<Vec<_>, _>>()?;
        if operands.is_empty() {
            return malformed(format!("layer {}: an operation needs a layer", row.name));
        }
        check_operands(&layers, row, &operands)?;
        layers.push_derived(strings.intern(&row.name), row.op, operands);
    }
    layers.texts.clone_from(&doc.texts);
    let texts = u32::try_from(doc.texts.len()).unwrap_or(u32::MAX);
    if let Some(row) = doc
        .derived
        .iter()
        .find(|row| matches!(row.op, DerivedOp::WithText { text, .. } if text >= texts))
    {
        return malformed(format!("layer {}: its text pattern is missing", row.name));
    }
    // What the parser refuses, refused for a source built by hand too.
    let mut selections = 0;
    for row in &doc.derived {
        let DerivedOp::InCells { first, count, .. } = row.op else {
            continue;
        };
        selections += 1;
        let patterns = (first
            .checked_add(count)
            .filter(|&end| count > 0 && end <= texts))
        .map(|end| &doc.texts[first as usize..end as usize]);
        let Some(patterns) = patterns else {
            return malformed(format!(
                "layer {}: its cell-name patterns are missing",
                row.name
            ));
        };
        if patterns
            .iter()
            .any(|p| p.is_empty() || p.contains(['[', ']', '{', '}', '\\']))
        {
            return malformed(format!(
                "layer {}: a cell-name pattern is empty or holds `[`, `]`, `{{`, `}}` or `\\`",
                row.name
            ));
        }
    }
    if selections > super::MAX_CELL_SELECTIONS {
        return malformed(format!(
            "a deck holds at most {} cell selections",
            super::MAX_CELL_SELECTIONS
        ));
    }
    layers.ignored.clone_from(&doc.ignored);
    layers.ignored.sort_unstable();
    for rule in &doc.rules {
        for (_, stated) in &rule.params {
            // A misspelt model would match no device and silently check nothing.
            if let ParamSource::Model(model) = stated {
                if !doc.devices.iter().any(|device| device.model == *model) {
                    return malformed(format!(
                        "rule {}: model \"{model}\" is not declared by any device statement",
                        rule.id
                    ));
                }
            }
        }
    }
    let rules = build_rules(&doc.rules, &layers, strings)?;
    let connectivity = build_connectivity(&doc.connectivity, &layers, strings)?;
    // Only a conductor's shapes carry a net; any other layer would read as all
    // different nets, or none the same.
    for rule in &doc.rules {
        // Every layer of a spacing by net; the judged layer of a tag rule.
        let judged: &[String] = match rule.kind {
            "net_spacing" | "voltage_spacing" | "dielectric_field" => &rule.layers[..],
            "hv_tag" | "mixed_tag" => &rule.layers[..rule.layers.len().min(1)],
            _ => &[],
        };
        for layer in judged {
            if !connectivity
                .conductors
                .contains(&layer_of(&layers, strings, layer, &rule.id)?)
            {
                return malformed(format!(
                    "rule {}: judges nets on {layer}, which is not a conductor",
                    rule.id
                ));
            }
        }
    }
    let devices = build_devices(&doc.devices, &layers, strings)?;
    let stack = build_stack(&doc.pex, doc.temperature, &layers, strings)?;
    let corners = build_corners(
        &doc.corners,
        &doc.pex,
        doc.temperature,
        &stack,
        &layers,
        strings,
    )?;
    let stages = build_stages(&doc.stages, &doc.rules, strings)?;
    // A waiver for a rule the deck does not have would waive nothing, silently.
    let mut waivers = Vec::with_capacity(doc.waivers.len());
    for (rule, layer) in &doc.waivers {
        if !doc.rules.iter().any(|declared| declared.id == *rule) {
            return Err(DeckError::Malformed(format!(
                "waive {rule}: no rule of the deck has that id"
            )));
        }
        if waivers.contains(&(rule, layer)) {
            return Err(DeckError::Malformed(format!(
                "waive {rule}: {layer} is stated twice"
            )));
        }
        waivers.push((rule, layer));
    }
    let waivers = waivers
        .into_iter()
        .map(|(rule, layer)| {
            let layer = layer_of(&layers, strings, layer, &format!("waive {rule}"))?;
            Ok((strings.intern(rule), layer))
        })
        .collect::<Result<Vec<_>, DeckError>>()?;
    let lvs = build_lvs(&doc.lvs, &doc.devices, strings)?;
    let temperature_law = match doc.temperature {
        None => None,
        Some((operating_k, nominal_k)) => {
            let mut rows = Vec::with_capacity(doc.pex.len());
            for (name, row) in &doc.pex {
                // `build_stack` refused a row without coefficients.
                let tc = row.tc.unwrap_or_default();
                rows.push((
                    layer_of(&layers, strings, name, "pex")?,
                    row.sheet_res_ohm_sq,
                    tc,
                ));
            }
            Some(TemperatureLaw {
                operating_k,
                nominal_k,
                rows,
            })
        }
    };

    Ok(Deck {
        layers,
        rules,
        connectivity,
        devices,
        stack,
        temperature: doc
            .temperature
            .map(|(operating, _)| gpurify_geom::Qty::new(operating)),
        temperature_law,
        lvs,
        extraction: doc.extraction.unwrap_or_default(),
        corners,
        stages,
        waivers,
    })
}

/// The stages, each rule id resolved to its stage.
///
/// # Errors
///
/// [`DeckError::Malformed`] for a stage named twice, a rule listed in two
/// stages or in one twice, and an id no rule has.
fn build_stages(
    declared: &[(String, Vec<String>)],
    rules: &[RuleSource],
    strings: &mut StrTable,
) -> Result<Stages, DeckError> {
    let mut stages = Stages::default();
    let mut seen: Vec<&str> = Vec::new();
    for (at, (name, ids)) in declared.iter().enumerate() {
        if declared[..at].iter().any(|(earlier, _)| earlier == name) {
            return Err(DeckError::Malformed(format!(
                "stage {name} is stated twice"
            )));
        }
        let stage = u16::try_from(at)
            .map_err(|_| DeckError::Malformed("a deck has at most 65535 stages".to_owned()))?;
        stages.name.push(strings.intern(name));
        for id in ids {
            if seen.contains(&id.as_str()) {
                return Err(DeckError::Malformed(format!(
                    "stage {name}: rule {id} is already in a stage"
                )));
            }
            if !rules.iter().any(|rule| rule.id == *id) {
                return Err(DeckError::Malformed(format!("stage {name}: no rule {id}")));
            }
            seen.push(id);
            stages.of_rule.push((strings.intern(id), stage));
        }
    }
    Ok(stages)
}

/// A layer by name, or the error naming the statement that used it.
fn layer_of(
    layers: &LayerTable,
    strings: &StrTable,
    name: &str,
    user: &str,
) -> Result<LayerId, DeckError> {
    layers
        .id(strings, name)
        .ok_or_else(|| DeckError::Malformed(format!("{user}: unknown layer {name}")))
}

/// Whether a derived row's operands are of the kind its operation takes:
/// one kind throughout a fold, polygons into a polygon operation and as any
/// layer argument, edges into an edge operation, a drawn text layer.
fn check_operands(
    layers: &LayerTable,
    row: &DerivedSource,
    operands: &[LayerId],
) -> Result<(), DeckError> {
    let edges = layers.is_edges(operands[0]);
    let wrong = |what: &str| Err(DeckError::Malformed(format!("layer {}: {what}", row.name)));
    match row.op {
        DerivedOp::And | DerivedOp::Or | DerivedOp::Not
            if operands
                .iter()
                .any(|&layer| layers.is_edges(layer) != edges) =>
        {
            return wrong("cannot combine an edge layer with a polygon layer");
        }
        DerivedOp::Part(_)
        | DerivedOp::WithLength(..)
        | DerivedOp::Oriented(_)
        | DerivedOp::Extended { .. }
            if !edges =>
        {
            return wrong("the operation needs an edge layer, not polygons");
        }
        DerivedOp::Sized(..)
        | DerivedOp::Inside
        | DerivedOp::Outside
        | DerivedOp::Overlapping
        | DerivedOp::Covering(_)
        | DerivedOp::Holes
        | DerivedOp::Extents
        | DerivedOp::Rectangles { .. }
        | DerivedOp::WithBbox { .. }
        | DerivedOp::WithRect { .. }
        | DerivedOp::Edges
        | DerivedOp::WithArea(..)
        | DerivedOp::WithWidth(..)
        | DerivedOp::WithText { .. }
            if edges =>
        {
            return wrong("the operation needs a polygon layer, not edges");
        }
        _ => {}
    }
    let takes_argument = !matches!(row.op, DerivedOp::And | DerivedOp::Or | DerivedOp::Not);
    if takes_argument {
        if let Some(&argument) = operands.get(1) {
            if layers.is_edges(argument) {
                return wrong("a layer argument is a polygon layer");
            }
            if matches!(row.op, DerivedOp::WithText { .. }) && layers.is_derived(argument) {
                return wrong("text is drawn on a GDS layer, not a derived one");
            }
        }
    }
    if let DerivedOp::WithRect { w, h, .. } = row.op {
        if w.raw() <= 0 || h.raw() <= 0 {
            return wrong("a box has positive sides");
        }
    }
    // A cell tag belongs to a drawn ring; a derived layer has none.
    if matches!(row.op, DerivedOp::InCells { .. })
        && (operands.len() != 1 || layers.is_derived(operands[0]))
    {
        return wrong("a cell selection reads one drawn layer");
    }
    Ok(())
}

/// Layer names to a [`LayerTable`], ids ascending by name *bytes*, not
/// interning order.
fn build_layers(
    declared: &[(String, (u16, u16))],
    strings: &mut StrTable,
) -> Result<LayerTable, DeckError> {
    let mut sorted: Vec<&(String, (u16, u16))> = declared.iter().collect();
    sorted.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    if let Some(pair) = sorted.windows(2).find(|pair| pair[0].0 == pair[1].0) {
        return Err(DeckError::Malformed(format!(
            "layer {} is declared twice",
            pair[0].0
        )));
    }
    let entries: Vec<(StrId, u16, u16)> = sorted
        .iter()
        .map(|(name, (layer, datatype))| (strings.intern(name), *layer, *datatype))
        .collect();
    Ok(LayerTable::build(&entries))
}

/// The rules to a [`RuleTable`], in deck order.
fn build_rules(
    declared: &[RuleSource],
    layers: &LayerTable,
    strings: &mut StrTable,
) -> Result<RuleTable, DeckError> {
    let mut table = RuleTable {
        spec: Vec::with_capacity(declared.len()),
        ..RuleTable::default()
    };
    let mut seen: Vec<&str> = Vec::with_capacity(declared.len());
    for rule in declared {
        match seen.binary_search(&rule.id.as_str()) {
            Ok(_) => {
                return Err(DeckError::Malformed(format!(
                    "duplicate rule id `{}`",
                    rule.id
                )))
            }
            Err(at) => seen.insert(at, &rule.id),
        }
        let id = strings.intern(&rule.id);
        // Which slots take edges: a kind not listed takes polygons only.
        let slots = EDGE_KINDS
            .iter()
            .find(|(engine, _)| *engine == rule.kind)
            .map_or(&[][..], |&(_, slots)| slots);
        let layer_start = table.layer_ref.len();
        for (at, name) in rule.layers.iter().enumerate() {
            let layer = layer_of(layers, strings, name, &rule.id)?;
            let edges = layers.is_edges(layer);
            match slots.get(at).copied().unwrap_or(Some(false)) {
                Some(want) if want != edges => {
                    let (want, got) = if want {
                        ("an edge layer", "polygons")
                    } else {
                        ("a polygon layer", "edges")
                    };
                    return Err(DeckError::Malformed(format!(
                        "rule {}: {} here takes {want}; {name} is {got}",
                        rule.id, rule.kind
                    )));
                }
                _ => {}
            }
            table.layer_ref.push(layer);
        }
        let param_start = table.param.len();
        for (name, stated) in &rule.params {
            let value = match *stated {
                ParamSource::Value(value) => value,
                ParamSource::Layer(ref layer) => {
                    let layer = layer_of(layers, strings, layer, &rule.id)?;
                    if layers.is_edges(layer) {
                        return Err(DeckError::Malformed(format!(
                            "rule {}: parameter {name} takes a polygon layer",
                            rule.id
                        )));
                    }
                    ParamValue::Layer(layer)
                }
                ParamSource::Model(ref model) => ParamValue::Model(strings.intern(model)),
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
    Ok(table)
}

/// Connectivity, layers resolved; a label row must name a drawn layer and a
/// conductor.
fn build_connectivity(
    declared: &ConnectivitySource,
    layers: &LayerTable,
    strings: &StrTable,
) -> Result<Connectivity, DeckError> {
    let layer = |name: &str| -> Result<LayerId, DeckError> {
        let layer = layer_of(layers, strings, name, "connect")?;
        if layers.is_edges(layer) {
            return Err(DeckError::Malformed(format!(
                "connect: {name} is an edge layer, which carries no net"
            )));
        }
        Ok(layer)
    };
    let all = |names: &[String]| {
        names
            .iter()
            .map(|name| layer(name))
            .collect::<Result<Vec<_>, _>>()
    };
    let mut connectivity = Connectivity {
        conductors: all(&declared.conductors)?,
        via_cut: Vec::with_capacity(declared.vias.len()),
        via_connects: Vec::with_capacity(declared.vias.len()),
        intra_layer_touch: declared.intra_layer_touch,
        global: all(&declared.global)?,
        label_layer: Vec::with_capacity(declared.labels.len()),
        label_names: Vec::with_capacity(declared.labels.len()),
    };
    for via in &declared.vias {
        connectivity.via_cut.push(layer(&via.layer)?);
        connectivity
            .via_connects
            .push((layer(&via.connects.0)?, layer(&via.connects.1)?));
    }
    if let Some(name) = declared
        .global
        .iter()
        .zip(&connectivity.global)
        .find(|(_, global)| connectivity.conductors.contains(global))
        .map(|(name, _)| name)
    {
        return Err(DeckError::Malformed(format!(
            "connect global {name}: a global layer is net-only, not a conductor"
        )));
    }
    for label in &declared.labels {
        let names = layer(&label.names)?;
        // Fail closed here rather than as `topology::port`'s `OrphanLabel`: at
        // run time nothing can say which deck row was wrong.
        if !connectivity.conductors.contains(&names) {
            return Err(DeckError::Malformed(format!(
                "connect label {} names {}, which is not a conductor",
                label.layer, label.names
            )));
        }
        let text = layer(&label.layer)?;
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
    declared: &[DeviceSource],
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
        let user = format!("device {}", device.model);
        let polygons = |name: &str| -> Result<LayerId, DeckError> {
            let layer = layer_of(layers, strings, name, &user)?;
            if layers.is_edges(layer) {
                return Err(DeckError::Malformed(format!(
                    "{user}: {name} is an edge layer, not a device's shapes"
                )));
            }
            Ok(layer)
        };
        let marker = polygons(&device.marker)?;
        let terminals = device
            .terminals
            .iter()
            .map(|name| polygons(name))
            .collect::<Result<Vec<_>, _>>()?;
        devices.kind.push(device.kind);
        devices.marker.push(marker);
        devices.model.push(strings.intern(&device.model));
        devices.terminal.extend(terminals);
        devices.terminal_start.push(narrow(devices.terminal.len()));
        devices.value.push(device.value);
    }
    Ok(devices)
}

/// The PEX stack, a column per parameter indexed by [`LayerId`].
///
/// Every column is `layers.len()` long once any `pex` row exists;
/// `pex::stack_row` indexes it directly. A layer with no row keeps its zero.
/// Each row's sheet resistance is moved from `temperature`'s nominal to its
/// operating value ([`ProcessStack::sheet_res_ohm_sq`]).
///
/// A deck that states a temperature gives every row both coefficients, and
/// one that states none gives none: a coefficient left out would be a silent
/// zero, and one with no temperature would change nothing. The law must keep
/// the resistance positive.
fn build_stack(
    declared: &[(String, StackSource)],
    temperature: Option<(f64, f64)>,
    layers: &LayerTable,
    strings: &StrTable,
) -> Result<ProcessStack, DeckError> {
    if declared.is_empty() {
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
    for (name, row) in declared {
        let factor = temperature_factor(&format!("pex {name}"), temperature, row.tc)?;
        let at = layer_of(layers, strings, name, "pex")?.idx();
        stack.thickness_nm[at] = row.thickness_nm;
        stack.height_nm[at] = row.height_nm;
        stack.sheet_res_ohm_sq[at] = row.sheet_res_ohm_sq * factor;
        stack.area_cap_af_um2[at] = row.area_cap_af_um2;
        stack.fringe_cap_af_um[at] = row.fringe_cap_af_um;
        stack.dielectric_k[at] = row.dielectric_k;
    }
    Ok(stack)
}

/// The factor that moves a `sheet` stated at the deck's nominal temperature
/// to its operating one, `1 + tc1·ΔT + tc2·ΔT²` (the ngspice resistor law),
/// for the row or corner line `name`; 1 without a temperature.
///
/// # Errors
///
/// [`DeckError::Malformed`] for coefficients without a temperature, a
/// temperature without coefficients, or a factor that is not positive.
fn temperature_factor(
    name: &str,
    temperature: Option<(f64, f64)>,
    tc: Option<(f64, f64)>,
) -> Result<f64, DeckError> {
    match (temperature, tc) {
        (None, None) => Ok(1.0),
        (Some((operating, nominal)), Some((tc1, tc2))) => {
            let delta = operating - nominal;
            let factor = 1.0 + tc1 * delta + tc2 * delta * delta;
            if factor.is_finite() && factor > 0.0 {
                Ok(factor)
            } else {
                Err(DeckError::Malformed(format!(
                    "{name}: tc1 and tc2 scale its resistance by {factor} at the \
                     deck's temperature; a resistance stays positive"
                )))
            }
        }
        (None, Some(_)) => Err(DeckError::Malformed(format!(
            "{name}: tc1 and tc2 need a `temperature` statement to say how far \
             from nominal the run is"
        ))),
        (Some(_), None) => Err(DeckError::Malformed(format!(
            "{name}: the deck states a temperature, so the row needs tc1 and tc2 \
             (0/K and 0/K2 for a resistance that does not vary)"
        ))),
    }
}

/// Each corner's stack: the nominal one with the corner's stated values in
/// place, corners in the order the deck first names them.
///
/// A corner's `sheet`, like a row's, is stated at the nominal temperature,
/// and moves to the operating one by the corner line's `tc1` and `tc2` where
/// it gives both, else by the row's.
///
/// # Errors
///
/// [`DeckError::Malformed`] for a corner line on a layer with no `pex` row
/// (a corner varies a row, it does not add one), one that names a layer
/// twice for one corner or states nothing, one that gives one of `tc1` and
/// `tc2`, and one whose resistance [`temperature_factor`] refuses.
fn build_corners(
    declared: &[CornerSource],
    pex: &[(String, StackSource)],
    temperature: Option<(f64, f64)>,
    nominal: &ProcessStack,
    layers: &LayerTable,
    strings: &mut StrTable,
) -> Result<Vec<ProcessCorner>, DeckError> {
    let mut corners: Vec<ProcessCorner> = Vec::new();
    for line in declared {
        let name = format!("corner {} {}", line.corner, line.layer);
        let Some((_, base)) = pex.iter().find(|(layer, _)| *layer == line.layer) else {
            return Err(DeckError::Malformed(format!(
                "corner {}: layer {} has no pex row to vary",
                line.corner, line.layer
            )));
        };
        if line.values.iter().all(Option::is_none) {
            return Err(DeckError::Malformed(format!("{name}: states nothing")));
        }
        let at = if let Some(at) = corners
            .iter()
            .position(|corner| strings.resolve(corner.name) == line.corner)
        {
            at
        } else {
            corners.push(ProcessCorner {
                name: strings.intern(&line.corner),
                stack: nominal.clone(),
                stated: Vec::new(),
            });
            corners.len() - 1
        };
        let layer = layer_of(layers, strings, &line.layer, &name)?;
        let ProcessCorner { stack, stated, .. } = &mut corners[at];
        if stated.iter().any(|&(on, _)| on == layer) {
            return Err(DeckError::Malformed(format!(
                "{name}: the layer is stated twice"
            )));
        }
        stated.push((layer, line.values));
        let row = layer.idx();
        let columns = [
            &mut stack.thickness_nm,
            &mut stack.height_nm,
            &mut stack.sheet_res_ohm_sq,
            &mut stack.dielectric_k,
            &mut stack.area_cap_af_um2,
            &mut stack.fringe_cap_af_um,
        ];
        for (column, value) in columns.into_iter().zip(line.values) {
            if let Some(value) = value {
                column[row] = value;
            }
        }
        let [_, _, sheet, _, _, _, tc1, tc2] = line.values;
        let tc = match (tc1, tc2) {
            (Some(tc1), Some(tc2)) => Some((tc1, tc2)),
            (None, None) => base.tc,
            _ => {
                return Err(DeckError::Malformed(format!(
                    "{name}: gives one of tc1 and tc2; give both, or neither"
                )))
            }
        };
        stack.sheet_res_ohm_sq[row] =
            sheet.unwrap_or(base.sheet_res_ohm_sq) * temperature_factor(&name, temperature, tc)?;
    }
    Ok(corners)
}

impl DeckSource {
    /// The layers, connectivity, devices and parasitic stack of a lowered
    /// deck, back to names, and no rule: what [`lower`] would resolve to those
    /// tables again, in the same `strings`.
    ///
    /// A `pex` row is one whose thickness is stated (positive), as every
    /// parsed row's is. The stack's sheet resistances are already at
    /// `temperature`, so a deck with one is written at it: nominal equal to
    /// operating, and every row's coefficients zero, which lowers to the same
    /// stack.
    pub fn from_tables(
        layers: &LayerTable,
        connectivity: &Connectivity,
        devices: &DeviceRecognition,
        stack: &ProcessStack,
        temperature: Option<f64>,
        strings: &StrTable,
    ) -> Self {
        let name = |layer: LayerId| strings.resolve(layers.name(layer)).to_owned();
        let all_ids =
            (0..layers.len()).map(|at| LayerId(u16::try_from(at).expect("a LayerId is a u16")));
        let mut source = DeckSource {
            layers: all_ids
                .clone()
                .filter(|&layer| !layers.is_derived(layer))
                .map(|layer| (name(layer), layers.stream_of(layer)))
                .collect(),
            ignored: layers.ignored.clone(),
            derived: layers
                .derived()
                .iter()
                .map(|(layer, op, operands)| DerivedSource {
                    name: name(*layer),
                    op: *op,
                    layers: operands.iter().map(|&operand| name(operand)).collect(),
                })
                .collect(),
            texts: layers.texts.clone(),
            ..DeckSource::default()
        };
        let names = |ids: &[LayerId]| ids.iter().map(|&layer| name(layer)).collect::<Vec<_>>();
        source.connectivity = ConnectivitySource {
            conductors: names(&connectivity.conductors),
            intra_layer_touch: connectivity.intra_layer_touch,
            global: names(&connectivity.global),
            vias: connectivity
                .via_cut
                .iter()
                .zip(&connectivity.via_connects)
                .map(|(&cut, &(a, b))| ViaSource {
                    layer: name(cut),
                    connects: (name(a), name(b)),
                })
                .collect(),
            labels: connectivity
                .label_layer
                .iter()
                .zip(&connectivity.label_names)
                .map(|(&text, &names)| LabelSource {
                    layer: name(text),
                    names: name(names),
                })
                .collect(),
        };
        source.devices = (0..devices.kind.len())
            .map(|row| {
                let span =
                    devices.terminal_start[row] as usize..devices.terminal_start[row + 1] as usize;
                DeviceSource {
                    kind: devices.kind[row],
                    marker: name(devices.marker[row]),
                    model: strings.resolve(devices.model[row]).to_owned(),
                    terminals: names(&devices.terminal[span]),
                    value: devices.value.get(row).copied().unwrap_or_default(),
                }
            })
            .collect();
        source.pex = all_ids
            .filter(|layer| {
                stack
                    .thickness_nm
                    .get(layer.idx())
                    .is_some_and(|&t| t > 0.0)
            })
            .map(|layer| {
                let at = layer.idx();
                (
                    name(layer),
                    StackSource {
                        thickness_nm: stack.thickness_nm[at],
                        height_nm: stack.height_nm[at],
                        sheet_res_ohm_sq: stack.sheet_res_ohm_sq[at],
                        area_cap_af_um2: stack.area_cap_af_um2[at],
                        fringe_cap_af_um: stack.fringe_cap_af_um[at],
                        dielectric_k: stack.dielectric_k[at],
                        tc: temperature.map(|_| (0.0, 0.0)),
                    },
                )
            })
            .collect();
        source.temperature = temperature.map(|kelvin| (kelvin, kelvin));
        source
    }
}
