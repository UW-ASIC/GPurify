//! The JSON deck reader, kept until every deck is converted to deck text.

use super::{build, Deck, DeckError, DeckSrc, Pairs, ParamSrc};
use gpurify_geom::{Grid, StrTable};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

/// Parse and validate a JSON deck.
pub fn parse_deck(source: &str, grid: Grid, strings: &mut StrTable) -> Result<Deck, DeckError> {
    let doc: DeckSrc =
        serde_json::from_str(source).map_err(|why| DeckError::Malformed(why.to_string()))?;
    build(&doc, grid, strings)
}

/// Rewrite a JSON deck as deck text that lowers to the same rules. Values are
/// written in the engine's own units with Rust's shortest round-trip `f64`
/// text, so the text parses back to the identical bits.
pub fn to_deck_text(source: &str) -> Result<String, DeckError> {
    use super::kinds::{Cmp, Dim, Param, KINDS};
    use std::fmt::Write as _;

    let bad = |why: String| DeckError::Malformed(why);
    let doc: DeckSrc = serde_json::from_str(source).map_err(|why| bad(why.to_string()))?;
    let mut out = String::new();

    // The grid: 5 nm when every rule length is a multiple of it, else 1 nm.
    let on_five = doc.rules.0.iter().all(|(_, rule)| {
        rule.params.0.iter().all(|(_, value)| match *value {
            ParamSrc::Nm(nm) => nm % 5.0 == 0.0,
            _ => true,
        })
    });
    let _ = writeln!(out, "grid {}nm\n", if on_five { 5 } else { 1 });

    for (name, (layer, datatype)) in &doc.layers.0 {
        let _ = writeln!(out, "layer {name} = gds({layer}, {datatype})");
    }
    for row in &doc.derived {
        let _ = writeln!(
            out,
            "layer {} = {}",
            row.name,
            row.layers.join(&format!(" {} ", row.op))
        );
    }
    out.push('\n');

    for (id, rule) in &doc.rules.0 {
        let kind = rule.kind.as_deref().unwrap_or_default();
        let params = &rule.params.0;
        let find = |engine: &str| {
            params
                .iter()
                .find(|(name, _)| name == engine)
                .map(|(_, v)| v)
        };
        let maximum = matches!(find("maximum"), Some(ParamSrc::Flag(true)));
        let row = KINDS
            .iter()
            .find(|k| {
                k.engine == kind
                    && k.fixed
                        .iter()
                        .all(|&(flag, on)| flag != "maximum" || on == maximum)
            })
            .ok_or_else(|| bad(format!("{id}: no deck kind for {kind}")))?;
        let known = |name: &str| {
            row.params.iter().chain(row.limit.iter()).any(|p| {
                p.engine == name
                    || matches!(p.dim, Dim::LengthPair(second) if second == name)
                    || matches!(p.dim, Dim::Group(inner) if inner.iter().any(|q| q.engine == name))
            }) || row.fixed.iter().any(|&(flag, _)| flag == name)
                || name == "warning"
                // Validated by the engine but never read.
                || matches!(name, "required_current" | "max_path_resistance" | "max_clamp_voltage")
        };
        if let Some((name, _)) = params.iter().find(|(name, _)| !known(name)) {
            return Err(bad(format!("{id}: unknown param {name}")));
        }

        let value = |p: &Param| -> Result<String, DeckError> {
            let missing = || bad(format!("{id}: missing {}", p.engine));
            let default = match p.engine {
                "diode_credit" | "diode_bonus" => Some("0"),
                "include_partial_windows" => Some("true"),
                _ if p.none => Some("none"),
                _ => None,
            };
            let text = match (p.dim, find(p.engine)) {
                (Dim::AngleList, _) => {
                    let angles: Vec<String> = params
                        .iter()
                        .filter(|(name, _)| name == p.engine)
                        .map(|(_, v)| match v {
                            ParamSrc::Count(deg) => format!("{deg}deg"),
                            _ => String::new(),
                        })
                        .collect();
                    format!("[{}]", angles.join(", "))
                }
                (Dim::Group(inner), _) => match find(inner[0].engine) {
                    None => "none".to_owned(),
                    Some(_) => {
                        let parts: Result<Vec<String>, DeckError> = inner
                            .iter()
                            .map(|q| {
                                Ok(format!(
                                    "{}: {}",
                                    q.name,
                                    write(q, find(q.engine)).ok_or_else(missing)?
                                ))
                            })
                            .collect();
                        format!("({})", parts?.join(", "))
                    }
                },
                (Dim::LengthPair(second), Some(ParamSrc::Nm(a))) => match find(second) {
                    Some(ParamSrc::Nm(b)) => format!("{a}nm x {b}nm"),
                    _ => return Err(missing()),
                },
                (_, found) => match write(p, found) {
                    Some(text) => text,
                    None => default.ok_or_else(missing)?.to_owned(),
                },
            };
            Ok(text)
        };

        // Deck argument i is engine slot j where row.layers[j] == i.
        let engine_layers = rule.layers.as_deref().unwrap_or_default();
        let mut args: Vec<String> = (0..row.layers.len())
            .map(|i| {
                let slot = row
                    .layers
                    .iter()
                    .position(|&j| usize::from(j) == i)
                    .unwrap_or(i);
                engine_layers.get(slot).cloned().unwrap_or_default()
            })
            .collect();
        args.extend(engine_layers.iter().skip(row.layers.len()).cloned());
        args.extend(row.modifier.map(str::to_owned));
        let named: Result<Vec<String>, DeckError> = row
            .params
            .iter()
            .map(|p| Ok(format!("{}: {}", p.name, value(p)?)))
            .collect();
        let named = named?;
        let inside = match (args.is_empty(), named.is_empty()) {
            (_, true) => args.join(", "),
            (true, false) => format!("; {}", named.join(", ")),
            (false, false) => format!("{}; {}", args.join(", "), named.join(", ")),
        };
        let warning = if matches!(find("warning"), Some(ParamSrc::Flag(true))) {
            "warning "
        } else {
            ""
        };
        let _ = write!(out, "rule {id} {warning}{}({inside})", row.name);
        if let Some(limit) = row.limit {
            let cmp = match row.cmp {
                Cmp::Ge => ">=",
                Cmp::Le => "<=",
                Cmp::Eq => "==",
                Cmp::Absent => "",
            };
            let _ = write!(out, " {cmp} {}", value(&limit)?);
        }
        out.push('\n');
    }
    out.push('\n');

    let c = &doc.connectivity;
    if !c.conductors.is_empty() {
        let _ = writeln!(out, "connect conductors [{}]", c.conductors.join(", "));
    }
    if c.intra_layer_touch {
        out.push_str("connect touch_within_layer\n");
    }
    for via in &c.vias {
        let _ = writeln!(
            out,
            "connect via {} [{}, {}]",
            via.layer, via.connects.0, via.connects.1
        );
    }
    for label in &c.labels {
        let _ = writeln!(out, "connect label {} names {}", label.layer, label.names);
    }
    out.push('\n');
    for d in &doc.device_recognition {
        let model = d.model.replace('\\', "\\\\").replace('"', "\\\"");
        let _ = writeln!(
            out,
            "device {} {} model \"{model}\" terminals [{}]",
            d.kind,
            d.marker,
            d.terminals.join(", ")
        );
    }
    out.push('\n');
    for (name, s) in &doc.pex.0 {
        let _ = writeln!(
            out,
            "pex {name} thickness {}nm height {}nm sheet {}ohm dielectric {} area_cap {}aF/um2 fringe_cap {}aF/um",
            s.thickness_nm, s.height_nm, s.sheet_res_ohm_sq, s.dielectric_k, s.area_cap_af_um2, s.fringe_cap_af_um
        );
    }
    out.truncate(out.trim_end().len());
    out.push('\n');
    Ok(out)
}

/// One stated value as deck text in the engine's unit; `None` when absent.
fn write(p: &super::kinds::Param, found: Option<&ParamSrc>) -> Option<String> {
    use super::kinds::Dim;
    Some(match (p.dim, found?) {
        (Dim::Length, ParamSrc::Nm(nm)) => format!("{nm}nm"),
        (Dim::Area, ParamSrc::Nm(side)) => format!("{}nm2", side * side),
        (Dim::Count, ParamSrc::Count(n)) => format!("{n}"),
        (Dim::Bool, ParamSrc::Flag(b)) => format!("{b}"),
        (Dim::Layer, ParamSrc::Layer(name)) => name.clone(),
        (dim, ParamSrc::Ratio(r)) => {
            let unit = match dim {
                Dim::Voltage => "mV",
                Dim::Current => "uA",
                Dim::CurrentPerWidth => "A/m",
                Dim::Resistance => "ohm",
                Dim::Temperature => "K",
                Dim::Energy => "eV",
                Dim::Time => "h",
                _ => "",
            };
            format!("{r}{unit}")
        }
        _ => return None,
    })
}

/// `serde_json::Map` collapses a repeated key and would drop a duplicate rule.
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
