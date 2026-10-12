//! A deck back to text, the inverse of the parser: [`parse_source`] of
//! [`print`]'s text gives back an equivalent [`DeckSource`], one that
//! [`lower`]s to the same [`Deck`](super::Deck) in the same string table.
//!
//! Every value is written in the unit the engines store it in (lengths and
//! areas in nanometres from the layout grid, voltages in mV), as the shortest
//! decimal that reads back to the same number, so nothing is rounded. A
//! hidden layer is written back as the expression that made it, where it was
//! made, so every layer keeps its id.
//!
//! [`parse_source`]: super::parse_source
//! [`lower`]: super::lower

use super::kinds::{Cmp, Dim, Kind, Param, KINDS};
use super::{
    absolute_unit, DeckSource, DerivedOp, DerivedSource, DeviceKind, LvsLimit, ParamSource,
    ParamValue, RuleSource,
};
use gpurify_geom::{DbuArea, Grid};
use std::collections::HashMap;
use std::fmt::Write as _;

/// Why a deck could not be written as text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrintError {
    /// A value or name the deck language cannot state exactly: a length on a
    /// grid that is no terminating decimal of a nanometre, a number that is
    /// not finite, a range open on both sides, a text with a line break, a
    /// rule no kind spells, a layer written inside a rule that no rule owns,
    /// or a rule id no `rule` statement can write (a `for` loop can splice a
    /// unit such as `%` into one).
    #[error("cannot write the deck: {0}")]
    Unprintable(String),
}

/// Writes `source`, read for the layout grid `grid`, as deck text.
///
/// The text states `grid` as the deck's grid, its drawn layers, ignored
/// pairs, derived layers and rules in declaration order (each rule where its
/// first inline layer was made, every other after the layers), then its
/// connectivity, devices, `lvs` statements and parasitic stack. `for` loops
/// and `let` bindings are not reconstructed: a loop's rules are written
/// one by one.
///
/// # Errors
///
/// [`PrintError::Unprintable`] for what the language cannot state.
///
/// # Examples
///
/// ```
/// use gpurify_geom::Grid;
/// use gpurify_ingest::deck::{parse_source, print};
///
/// let text = "grid 5nm
/// layer met1 = gds(68, 20)
/// layer fat = met1.sized(-1.5um).sized(1.5um)
/// rule m1.1 width(met1) >= 0.14um
/// ";
/// let grid = Grid::new(1000)?;
/// let source = parse_source(text, grid)?;
/// let printed = print(&source, grid)?;
/// assert!(printed.contains("rule m1.1 width(met1) >= 140nm"));
/// assert_eq!(parse_source(&printed, grid)?, source);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn print(source: &DeckSource, grid: Grid) -> Result<String, PrintError> {
    let printer = Printer {
        source,
        grid,
        derived: source
            .derived
            .iter()
            .enumerate()
            .map(|(at, row)| (row.name.as_str(), at))
            .collect(),
    };
    printer.deck()
}

/// Whether a `rule` statement can write `id`: letters, digits, `_` and `.`,
/// as the lexer reads an id.
fn is_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.')
}

/// Whether a layer name is one the parser made for a nested or inline
/// expression, which no deck text can name.
fn hidden(name: &str) -> bool {
    name.contains('#') || name.contains('@')
}

struct Printer<'a> {
    source: &'a DeckSource,
    grid: Grid,
    /// Each derived row's index, by name.
    derived: HashMap<&'a str, usize>,
}

/// Exactly `numerator / denominator` as a decimal, or `None` when it does not
/// terminate within 30 places.
fn decimal(numerator: i128, denominator: i128) -> Option<String> {
    if denominator <= 0 {
        return None;
    }
    let negative = numerator < 0;
    let mut whole = numerator.unsigned_abs();
    let den = denominator.unsigned_abs();
    let mut places = 0u32;
    while !whole.is_multiple_of(den) {
        if places == 30 {
            return None;
        }
        whole = whole.checked_mul(10)?;
        places += 1;
    }
    let digits = (whole / den).to_string();
    let sign = if negative { "-" } else { "" };
    if places == 0 {
        return Some(format!("{sign}{digits}"));
    }
    let places = places as usize;
    let padded = format!("{digits:0>width$}", width = places + 1);
    let (int, frac) = padded.split_at(padded.len() - places);
    Some(format!("{sign}{int}.{frac}"))
}

/// A finite number as the shortest decimal that reads back to it.
fn number(value: f64) -> Result<String, PrintError> {
    if value.is_finite() {
        Ok(format!("{value:e}"))
    } else {
        Err(PrintError::Unprintable(format!(
            "{value} is not a number a deck can state"
        )))
    }
}

/// A string in quotes, `"` and `\` escaped.
fn quoted(text: &str) -> Result<String, PrintError> {
    if text.contains('\n') {
        return Err(PrintError::Unprintable(format!(
            "{text:?} holds a line break"
        )));
    }
    Ok(format!(
        "\"{}\"",
        text.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

/// `m` such that `m * |m|` is `squared`, as `with_width` stores a bound.
fn signed_root(squared: i128) -> Option<i64> {
    let magnitude = squared.unsigned_abs();
    // An integer square root by Newton's method, from above.
    let mut root = magnitude;
    if magnitude > 1 {
        let mut next = magnitude / 2 + 1;
        while next < root {
            root = next;
            next = root.midpoint(magnitude / root);
        }
    }
    if root.checked_mul(root)? != magnitude {
        return None;
    }
    let root = i64::try_from(root).ok()?;
    Some(if squared < 0 { -root } else { root })
}

impl Printer<'_> {
    /// A length in grid units, in nanometres.
    fn length(&self, raw: i128) -> Result<String, PrintError> {
        decimal(raw * 1000, i128::from(self.grid.dbu_per_um()))
            .map(|nm| format!("{nm}nm"))
            .ok_or_else(|| {
                PrintError::Unprintable(format!(
                    "{raw} grid units is no terminating decimal of a nanometre"
                ))
            })
    }

    /// An area in square grid units, in square nanometres.
    fn area(&self, area: DbuArea) -> Result<String, PrintError> {
        let per_um = i128::from(self.grid.dbu_per_um());
        decimal(area.raw() * 1_000_000, per_um * per_um)
            .map(|nm2| format!("{nm2}nm2"))
            .ok_or_else(|| {
                PrintError::Unprintable(format!(
                    "{} square grid units is no terminating decimal of a square nanometre",
                    area.raw()
                ))
            })
    }

    fn deck(&self) -> Result<String, PrintError> {
        let source = self.source;
        let mut out = String::new();
        let _ = writeln!(out, "grid {}", self.length(1)?);
        for (name, (layer, datatype)) in &source.layers {
            let _ = writeln!(out, "layer {name} = gds({layer}, {datatype})");
        }
        for (layer, datatype) in &source.ignored {
            let _ = writeln!(out, "ignore gds({layer}, {datatype})");
        }
        // Rules are written in order; one whose inline layers were made
        // between two derived layers is written there, with every rule
        // before it, so each layer keeps its id.
        let mut written = 0;
        for row in &source.derived {
            if row.name.contains('#') {
                continue;
            }
            let Some((owner, _)) = row.name.split_once('@') else {
                let _ = writeln!(out, "layer {} = {}", row.name, self.expr(row)?);
                continue;
            };
            if source.rules[..written].iter().any(|rule| rule.id == owner) {
                continue;
            }
            let Some(at) = source.rules[written..]
                .iter()
                .position(|rule| rule.id == owner)
            else {
                return Err(PrintError::Unprintable(format!(
                    "layer {} belongs to no rule",
                    row.name
                )));
            };
            for rule in &source.rules[written..=written + at] {
                let _ = writeln!(out, "{}", self.rule(rule)?);
            }
            written += at + 1;
        }
        for rule in &source.rules[written..] {
            let _ = writeln!(out, "{}", self.rule(rule)?);
        }
        if let Some((operating, nominal)) = source.temperature {
            let _ = writeln!(
                out,
                "temperature {}K nominal {}K",
                number(operating)?,
                number(nominal)?
            );
        }
        self.connectivity(&mut out);
        self.devices(&mut out)?;
        self.lvs(&mut out)?;
        for (layer, row) in &source.pex {
            let _ = write!(
                out,
                "pex {layer} thickness {}nm height {}nm sheet {}ohm area_cap {}aF/um2 fringe_cap {}aF/um",
                number(row.thickness_nm)?,
                number(row.height_nm)?,
                number(row.sheet_res_ohm_sq)?,
                number(row.area_cap_af_um2)?,
                number(row.fringe_cap_af_um)?,
            );
            if row.dielectric_k != 0.0 {
                let _ = write!(out, " dielectric {}", number(row.dielectric_k)?);
            }
            if let Some((tc1, tc2)) = row.tc {
                let _ = write!(out, " tc1 {}/K tc2 {}/K2", number(tc1)?, number(tc2)?);
            }
            out.push('\n');
        }
        Ok(out)
    }

    fn connectivity(&self, out: &mut String) {
        let connectivity = &self.source.connectivity;
        if !connectivity.conductors.is_empty() {
            let _ = writeln!(
                out,
                "connect conductors [{}]",
                connectivity.conductors.join(", ")
            );
        }
        if connectivity.intra_layer_touch {
            out.push_str("connect touch_within_layer\n");
        }
        for layer in &connectivity.global {
            let _ = writeln!(out, "connect global {layer}");
        }
        for via in &connectivity.vias {
            let _ = writeln!(
                out,
                "connect via {} [{}, {}]",
                via.layer, via.connects.0, via.connects.1
            );
        }
        for label in &connectivity.labels {
            let _ = writeln!(out, "connect label {} names {}", label.layer, label.names);
        }
    }

    fn devices(&self, out: &mut String) -> Result<(), PrintError> {
        for device in &self.source.devices {
            let kind = match device.kind {
                DeviceKind::Mos => "mos",
                DeviceKind::Bjt => "bjt",
                DeviceKind::Resistor => "resistor",
                DeviceKind::Capacitor => "capacitor",
                DeviceKind::Diode => "diode",
            };
            let _ = write!(
                out,
                "device {kind} {} model {} terminals [{}]",
                device.marker,
                quoted(&device.model)?,
                device.terminals.join(", ")
            );
            let value = device.value;
            for (key, stated, unit) in [
                ("sheet", value.sheet_ohm_sq, "ohm"),
                ("area_cap", value.area_cap_af_um2, "aF/um2"),
                ("fringe_cap", value.fringe_cap_af_um, "aF/um"),
            ] {
                if let Some(stated) = stated {
                    let _ = write!(out, " {key} {}{unit}", number(stated)?);
                }
            }
            out.push('\n');
        }
        Ok(())
    }

    /// The `lvs` statements, a kind at a time, each kind in deck order.
    fn lvs(&self, out: &mut String) -> Result<(), PrintError> {
        let lvs = &self.source.lvs;
        for row in &lvs.tolerance {
            let _ = write!(out, "lvs tolerance {} {}", quoted(&row.model)?, row.param);
            if row.relative > 0.0 || row.absolute == 0.0 {
                let _ = write!(out, " relative {}", number(row.relative)?);
            }
            if row.absolute > 0.0 {
                let (unit, _) = absolute_unit(&row.param).ok_or_else(|| {
                    PrintError::Unprintable(format!("`{}` takes no absolute tolerance", row.param))
                })?;
                let _ = write!(out, " absolute {}{unit}", number(row.absolute)?);
            }
            out.push('\n');
        }
        for (model, param) in &lvs.ignore_parameter {
            let _ = writeln!(out, "lvs ignore_parameter {} {param}", quoted(model)?);
        }
        for model in &lvs.asymmetric {
            let _ = writeln!(out, "lvs asymmetric {}", quoted(model)?);
        }
        for (model, a, b) in &lvs.permute {
            let _ = writeln!(out, "lvs permute {} {a} {b}", quoted(model)?);
        }
        for model in &lvs.ignore {
            let _ = writeln!(out, "lvs ignore {}", quoted(model)?);
        }
        for model in &lvs.ignore_shorted {
            let _ = writeln!(out, "lvs ignore_shorted {}", quoted(model)?);
        }
        if lvs.ports_by_name {
            out.push_str("lvs ports_by_name\n");
        }
        for (model, param, min, max) in &lvs.range {
            let _ = write!(out, "lvs range {} {param}", quoted(model)?);
            for (cmp, limit) in [(">=", min), ("<=", max)] {
                let Some(limit) = limit else { continue };
                let value = match *limit {
                    LvsLimit::Length(length) => self.length(i128::from(length.raw()))?,
                    LvsLimit::Area(area) => self.area(area)?,
                    LvsLimit::Count(count) => count.to_string(),
                };
                let _ = write!(out, " {cmp} {value}");
            }
            out.push('\n');
        }
        if let Some(relaxed) = lvs.topology {
            let policy = if relaxed { "relaxed" } else { "strict" };
            let _ = writeln!(out, "lvs topology {policy}");
        }
        for pattern in &lvs.connect_implicit {
            let _ = writeln!(out, "lvs connect_implicit {}", quoted(pattern)?);
        }
        for group in &lvs.connect_explicit {
            let names: Result<Vec<_>, _> = group.iter().map(|name| quoted(name)).collect();
            let _ = writeln!(out, "lvs connect_explicit {}", names?.join(" "));
        }
        Ok(())
    }

    /// A layer as an operand: its name, or a hidden layer's expression in
    /// parentheses.
    fn operand(&self, name: &str) -> Result<String, PrintError> {
        if hidden(name) {
            Ok(format!("({})", self.expr(self.row(name)?)?))
        } else {
            Ok(name.to_owned())
        }
    }

    fn row(&self, name: &str) -> Result<&DerivedSource, PrintError> {
        self.derived
            .get(name)
            .map(|&at| &self.source.derived[at])
            .ok_or_else(|| PrintError::Unprintable(format!("layer {name} is not declared")))
    }

    /// The expression a derived row computes.
    fn expr(&self, row: &DerivedSource) -> Result<String, PrintError> {
        let name = |at: usize| -> Result<&str, PrintError> {
            row.layers.get(at).map(String::as_str).ok_or_else(|| {
                PrintError::Unprintable(format!("layer {} misses an operand", row.name))
            })
        };
        let fold = |word: &str| -> Result<String, PrintError> {
            let operands = row
                .layers
                .iter()
                .map(|layer| self.operand(layer))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(operands.join(&format!(" {word} ")))
        };
        let call = |method: &str, argument: Option<String>| -> Result<String, PrintError> {
            Ok(format!(
                "{}.{method}({})",
                self.operand(name(0)?)?,
                argument.unwrap_or_default()
            ))
        };
        let layer_argument = || self.operand(name(1)?).map(Some);
        match row.op {
            DerivedOp::And => fold("and"),
            DerivedOp::Or => fold("or"),
            DerivedOp::Not => fold("not"),
            DerivedOp::Sized(dx, dy) if dx == dy => {
                call("sized", Some(self.length(i128::from(dx.raw()))?))
            }
            DerivedOp::Sized(dx, dy) => call(
                "sized",
                Some(format!(
                    "{}, {}",
                    self.length(i128::from(dx.raw()))?,
                    self.length(i128::from(dy.raw()))?
                )),
            ),
            DerivedOp::Overlapping => call("overlapping", layer_argument()?),
            DerivedOp::Covering(true) => call("covering", layer_argument()?),
            DerivedOp::Covering(false) => call("not_covering", layer_argument()?),
            DerivedOp::Extended {
                begin,
                end,
                outside,
                inside,
            } => call(
                "extended",
                Some(format!(
                    "begin: {}, end: {}, out: {}, in: {}",
                    self.length(i128::from(begin.raw()))?,
                    self.length(i128::from(end.raw()))?,
                    self.length(i128::from(outside.raw()))?,
                    self.length(i128::from(inside.raw()))?
                )),
            ),
            DerivedOp::Interacting(true) => call("interacting", layer_argument()?),
            DerivedOp::Interacting(false) => call("not_interacting", layer_argument()?),
            DerivedOp::Inside => call("inside", layer_argument()?),
            DerivedOp::Outside => call("outside", layer_argument()?),
            DerivedOp::Part(true) => call("inside_part", layer_argument()?),
            DerivedOp::Part(false) => call("outside_part", layer_argument()?),
            DerivedOp::Holes => call("holes", None),
            DerivedOp::Rectangles { square, keep } => call(
                match (keep, square) {
                    (true, false) => "rectangles",
                    (true, true) => "squares",
                    (false, false) => "non_rectangles",
                    (false, true) => "non_squares",
                },
                None,
            ),
            DerivedOp::Oriented(vertical) => {
                call(if vertical { "vertical" } else { "horizontal" }, None)
            }
            DerivedOp::WithBbox { longer, lo, hi } => {
                let bound = |value: i128| self.length(value);
                let method = if longer {
                    "with_bbox_max"
                } else {
                    "with_bbox_min"
                };
                call(method, Some(Self::bounds(&row.name, lo, hi, bound)?))
            }
            DerivedOp::Extents => call("extents", None),
            DerivedOp::Edges => call("edges", None),
            DerivedOp::WithArea(lo, hi) => {
                let bound = |value: i128| self.area(DbuArea::new(value));
                call("with_area", Some(Self::bounds(&row.name, lo, hi, bound)?))
            }
            DerivedOp::WithLength(lo, hi) => {
                let bound = |value: i128| self.length(value);
                call("with_length", Some(Self::bounds(&row.name, lo, hi, bound)?))
            }
            DerivedOp::WithWidth(lo, hi) => {
                let root = |squared: i128| {
                    signed_root(squared).ok_or_else(|| {
                        PrintError::Unprintable(format!("layer {}: a width bound", row.name))
                    })
                };
                // A strict bound moved the squared value one past the root.
                let low = |value: i128| -> Result<String, PrintError> {
                    match signed_root(value) {
                        Some(root) => self.length(i128::from(root)).map(|l| format!(">= {l}")),
                        None => Ok(format!("> {}", self.length(i128::from(root(value - 1)?))?)),
                    }
                };
                let high = |value: i128| -> Result<String, PrintError> {
                    match signed_root(value) {
                        Some(root) => self.length(i128::from(root)).map(|l| format!("<= {l}")),
                        None => Ok(format!("< {}", self.length(i128::from(root(value + 1)?))?)),
                    }
                };
                let mut bounds = Vec::new();
                if lo != i128::MIN {
                    bounds.push(low(lo)?);
                }
                if hi != i128::MAX {
                    bounds.push(high(hi)?);
                }
                if bounds.is_empty() {
                    return Err(PrintError::Unprintable(format!(
                        "layer {}: a range open on both sides",
                        row.name
                    )));
                }
                call("with_width", Some(bounds.join(", ")))
            }
            DerivedOp::WithText { keep, text } => {
                let pattern = self.source.texts.get(text as usize).ok_or_else(|| {
                    PrintError::Unprintable(format!("layer {}: no text pattern", row.name))
                })?;
                let method = if keep { "with_text" } else { "without_text" };
                call(method, Some(format!("{}, {}", name(1)?, quoted(pattern)?)))
            }
        }
    }

    /// Inclusive bounds as comparisons, each value written by `value`; an
    /// absent side is `i128::MIN` or `i128::MAX`.
    fn bounds(
        layer: &str,
        lo: i128,
        hi: i128,
        value: impl Fn(i128) -> Result<String, PrintError>,
    ) -> Result<String, PrintError> {
        let mut bounds = Vec::new();
        if lo != i128::MIN {
            bounds.push(format!(">= {}", value(lo)?));
        }
        if hi != i128::MAX {
            bounds.push(format!("<= {}", value(hi)?));
        }
        if bounds.is_empty() {
            return Err(PrintError::Unprintable(format!(
                "layer {layer}: a range open on both sides"
            )));
        }
        Ok(bounds.join(", "))
    }

    /// One rule statement.
    fn rule(&self, rule: &RuleSource) -> Result<String, PrintError> {
        if !is_rule_id(&rule.id) {
            return Err(PrintError::Unprintable(format!(
                "rule id `{}` holds a character no rule statement can write",
                rule.id
            )));
        }
        let kind = kind_of(rule)?;
        let fixed = kind.layers.len();
        // Deck argument `slot` is the engine's layer `at` where `layers[at] == slot`.
        let mut deck: Vec<&str> = vec![""; fixed];
        for (at, &slot) in kind.layers.iter().enumerate() {
            deck[usize::from(slot)] = rule.layers[at].as_str();
        }
        deck.extend(rule.layers[fixed..].iter().map(String::as_str));
        let mut positional = deck
            .iter()
            .map(|&layer| {
                if hidden(layer) {
                    self.expr(self.row(layer)?)
                } else {
                    Ok(layer.to_owned())
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        positional.extend(kind.modifier.map(str::to_owned));
        let named = kind
            .params
            .iter()
            .map(|&param| Ok(format!("{}: {}", param.name, self.value(rule, param)?)))
            .collect::<Result<Vec<_>, PrintError>>()?;
        let warning = rule.params.iter().any(|(name, value)| {
            *name == "warning" && *value == ParamSource::Value(ParamValue::Flag(true))
        });
        let mut text = format!(
            "rule {}{} {}({}",
            rule.id,
            if warning { " warning" } else { "" },
            kind.name,
            positional.join(", ")
        );
        if !named.is_empty() {
            let _ = write!(text, "; {}", named.join(", "));
        }
        text.push(')');
        if let Some(limit) = kind.limit {
            let cmp = match kind.cmp {
                Cmp::Ge => ">=",
                Cmp::Le => "<=",
                Cmp::Eq => "==",
                Cmp::Absent => "",
            };
            let value = self.value(
                rule,
                Param {
                    name: kind.name,
                    ..limit
                },
            )?;
            let _ = write!(text, " {cmp} {value}");
        }
        Ok(text)
    }

    /// One parameter's value as the deck writes it, `none` when an optional
    /// one is absent.
    fn value(&self, rule: &RuleSource, param: Param) -> Result<String, PrintError> {
        let stated = |engine: &str| -> Vec<&ParamSource> {
            rule.params
                .iter()
                .filter(|(name, _)| *name == engine)
                .map(|(_, value)| value)
                .collect()
        };
        let values = stated(param.engine);
        let missing = || {
            PrintError::Unprintable(format!(
                "rule {}: {} has no {}",
                rule.id, rule.kind, param.engine
            ))
        };
        if values.is_empty() && !matches!(param.dim, Dim::Group(_)) {
            if param.none {
                return Ok("none".to_owned());
            }
            if !matches!(
                param.dim,
                Dim::AngleList | Dim::Models | Dim::LengthList | Dim::LengthRows
            ) {
                return Err(missing());
            }
        }
        let wrong = || {
            PrintError::Unprintable(format!(
                "rule {}: {} is not a value of its kind",
                rule.id, param.engine
            ))
        };
        let one = |value: &ParamSource| -> Result<String, PrintError> {
            let ParamSource::Value(value) = value else {
                return Err(wrong());
            };
            match (param.dim, *value) {
                (
                    Dim::Length
                    | Dim::LengthPair(_)
                    | Dim::LengthPairList(_)
                    | Dim::LengthList
                    | Dim::OptLengthList
                    | Dim::LengthRows,
                    ParamValue::Length(length),
                ) => self.length(i128::from(length.raw())),
                (Dim::Area, ParamValue::Area(area)) => self.area(area),
                (Dim::Count, ParamValue::Count(count)) => Ok(count.to_string()),
                (Dim::Word(words), ParamValue::Count(at)) => words
                    .get(at as usize)
                    .map(|&word| word.to_owned())
                    .ok_or_else(wrong),
                (Dim::AngleList, ParamValue::Count(degrees)) => Ok(format!("{degrees}deg")),
                (Dim::Bool, ParamValue::Flag(flag)) => Ok(flag.to_string()),
                (Dim::OptLengthList, ParamValue::Flag(false)) => Ok("none".to_owned()),
                (Dim::Nets, ParamValue::Flag(same)) => {
                    Ok(if same { "same" } else { "different" }.to_owned())
                }
                (dim, ParamValue::Ratio(number_value)) => {
                    let unit = match dim {
                        Dim::Voltage => "mV",
                        Dim::Current => "uA",
                        Dim::CurrentPerWidth => "A/m",
                        Dim::Resistance => "ohm",
                        Dim::Temperature => "K",
                        Dim::Energy => "eV",
                        Dim::ThermalConductivity => "W/mK",
                        Dim::Time => "h",
                        Dim::CapPerArea => "aF/um2",
                        Dim::CapPerLength => "aF/um",
                        Dim::Angle => "deg",
                        Dim::Fraction | Dim::Scalar => "",
                        _ => return Err(wrong()),
                    };
                    Ok(format!("{}{unit}", number(number_value)?))
                }
                _ => Err(wrong()),
            }
        };
        let list = |values: &[&ParamSource]| -> Result<Vec<String>, PrintError> {
            values.iter().map(|value| one(value)).collect()
        };
        match param.dim {
            Dim::Layer => match values[0] {
                ParamSource::Layer(name) => Ok(name.clone()),
                _ => Err(wrong()),
            },
            Dim::Models => {
                if values.is_empty() {
                    return Ok(if param.none {
                        "none".to_owned()
                    } else {
                        "[]".to_owned()
                    });
                }
                let names = values
                    .iter()
                    .map(|value| match value {
                        ParamSource::Model(name) => quoted(name),
                        _ => Err(wrong()),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(format!("[{}]", names.join(", ")))
            }
            Dim::LengthPair(second) => {
                let other = stated(second);
                let other = other.first().ok_or_else(missing)?;
                Ok(format!("{} x {}", one(values[0])?, one(other)?))
            }
            Dim::AngleList | Dim::LengthList | Dim::OptLengthList => {
                Ok(format!("[{}]", list(&values)?.join(", ")))
            }
            Dim::LengthPairList(second) => {
                let others = stated(second);
                if values.len() != others.len() {
                    return Err(missing());
                }
                let pairs = values
                    .iter()
                    .zip(&others)
                    .map(|(a, b)| Ok(format!("{} x {}", one(a)?, one(b)?)))
                    .collect::<Result<Vec<_>, PrintError>>()?;
                Ok(format!("[{}]", pairs.join(", ")))
            }
            Dim::AreaTable(second) => {
                let numbers = stated(second);
                if values.len() != numbers.len() {
                    return Err(missing());
                }
                let points = values
                    .iter()
                    .zip(&numbers)
                    .map(|(area, value)| match (area, value) {
                        (
                            ParamSource::Value(ParamValue::Area(area)),
                            ParamSource::Value(ParamValue::Ratio(value)),
                        ) => Ok(format!("({}, {})", self.area(*area)?, number(*value)?)),
                        _ => Err(wrong()),
                    })
                    .collect::<Result<Vec<_>, PrintError>>()?;
                Ok(format!("[{}]", points.join(", ")))
            }
            Dim::LengthRows => {
                // A spacing table has a column per run; a table without runs
                // (a tip table) is square.
                let columns = match stated("prl").len() {
                    0 => (1..=values.len())
                        .find(|side| side * side >= values.len())
                        .unwrap_or(1),
                    runs => runs,
                };
                let cells = list(&values)?;
                let rows: Vec<String> = cells
                    .chunks(columns)
                    .map(|row| format!("[{}]", row.join(", ")))
                    .collect();
                Ok(format!("[{}]", rows.join(", ")))
            }
            Dim::Group(inner) => {
                let Some(first) = inner.first() else {
                    return Err(wrong());
                };
                if stated(first.engine).is_empty() {
                    return if param.none {
                        Ok("none".to_owned())
                    } else {
                        Err(missing())
                    };
                }
                let named = inner
                    .iter()
                    .map(|&inner| Ok(format!("{}: {}", inner.name, self.value(rule, inner)?)))
                    .collect::<Result<Vec<_>, PrintError>>()?;
                Ok(format!("({})", named.join(", ")))
            }
            _ => one(values[0]),
        }
    }
}

/// The kind-table row a rule is written with: its engine kind, its layer
/// count, and the flags the row fixes (a density rule's `maximum`).
fn kind_of(rule: &RuleSource) -> Result<&'static Kind, PrintError> {
    let layers = rule.layers.len();
    KINDS
        .iter()
        .filter(|kind| {
            kind.engine == rule.kind
                && (layers == kind.layers.len() || (kind.more && layers > kind.layers.len()))
                // A row's required values are stated (MINSTEP's two rows
                // differ only in which they require, `contains`' three only
                // in their limit's).
                && kind.limit.iter().chain(kind.params).all(|param| {
                    param.none
                        || matches!(
                            param.dim,
                            Dim::AngleList
                                | Dim::Models
                                | Dim::LengthList
                                | Dim::LengthRows
                                | Dim::Group(_)
                        )
                        || rule.params.iter().any(|(name, _)| *name == param.engine)
                })
                && kind.fixed.iter().all(|&(flag, on)| {
                    rule.params.iter().any(|(name, value)| {
                        *name == flag && *value == ParamSource::Value(ParamValue::Flag(on))
                    })
                })
        })
        // The row knowing the most stated values, the first on a tie, as the
        // parser picks among an enclosure's wire-band rows.
        .min_by_key(|kind| {
            std::cmp::Reverse(
                rule.params
                    .iter()
                    .filter(|(name, _)| {
                        kind.limit
                            .iter()
                            .chain(kind.params)
                            .any(|param| param.engine == *name)
                    })
                    .count(),
            )
        })
        .ok_or_else(|| {
            PrintError::Unprintable(format!(
                "rule {}: no deck spelling of {} with {layers} layers",
                rule.id, rule.kind
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::{decimal, signed_root};

    /// Oracle: hand-derived decimals and roots.
    #[test]
    fn decimals_and_roots_are_exact() {
        assert_eq!(decimal(140_000, 1000).as_deref(), Some("140"));
        assert_eq!(decimal(1000, 2000).as_deref(), Some("0.5"));
        assert_eq!(decimal(-3000, 10_000).as_deref(), Some("-0.3"));
        assert_eq!(decimal(7, 1000).as_deref(), Some("0.007"));
        assert_eq!(decimal(1000, 3000), None, "a third does not terminate");
        assert_eq!(signed_root(4900), Some(70));
        assert_eq!(signed_root(-4900), Some(-70));
        assert_eq!(signed_root(4901), None);
        assert_eq!(signed_root(0), Some(0));
        assert_eq!(signed_root(1), Some(1));
    }
}
