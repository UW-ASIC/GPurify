//! The LEF reader: technology layers, vias, sites, non-default widths and
//! cell abstracts, in DEF database units.

use super::lex::Lexer;
use super::{LefDefError, Pt, Shape, ViaRule};

/// A LEF layer's `TYPE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerKind {
    /// `ROUTING`: carries wires.
    Routing,
    /// `CUT`: via cuts between two routing or masterslice layers.
    Cut,
    /// `MASTERSLICE`: poly or diffusion, below the routing.
    Masterslice,
    /// `OVERLAP`: the outline of an irregular macro.
    Overlap,
    /// Any other type (`IMPLANT`, `TSV`, …), not a conductor here.
    Other,
}

/// One `LAYER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LefLayer {
    /// Its name, as DEF and the macros name it.
    pub name: String,
    /// Its type; `Other` until a `TYPE` statement says.
    pub kind: LayerKind,
    /// The default wire width, database units: what a regular DEF wire on
    /// it is drawn at.
    pub width: Option<i64>,
    /// `PITCH`, x and y (one value gives both), database units.
    pub pitch: Option<(i64, i64)>,
    /// `DIRECTION HORIZONTAL` (`Some(true)`) or `VERTICAL`.
    pub horizontal: Option<bool>,
}

/// One macro `PIN`: its ports' shapes and vias, unplaced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MacroPin {
    /// The pin's name, as DEF connects to it.
    pub name: String,
    /// Every `RECT` and `POLYGON` of every `PORT`.
    pub shapes: Vec<Shape>,
    /// Every `VIA pt name` of every `PORT`.
    pub vias: Vec<(String, Pt)>,
}

/// One `EDGETYPE` entry of a library's `LEF58_CELLEDGESPACINGTABLE`
/// property: the least spacing between a cell edge of one type and a cell
/// edge of another (ISPD 2014 placement contest, Benchmark Suite A, slides
/// 16 and 27; ICCAD 2017 Problem C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellEdgeSpacing {
    /// The first edge type.
    pub first: String,
    /// The second; the spacing is the same either way round.
    pub second: String,
    /// The spacing, database units.
    pub spacing: i64,
    /// `EXCEPTABUTTED`: two edges that touch (no gap) are exempt.
    pub except_abutted: bool,
    /// Options no public text defines (`EXCEPTNONFILLERINBETWEEN`,
    /// `OPTIONAL`, `SOFT`, `EXACT`), as written; an entry with any is not
    /// checked.
    pub undefined: Vec<String>,
}

/// The side of a cell an [`EdgeType`] types, in the macro's own frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeSide {
    /// `LEFT`: the edge at x = 0.
    Left,
    /// `RIGHT`: at x = the cell's width.
    Right,
    /// `TOP`: at y = its height.
    Top,
    /// `BOTTOM`: at y = 0.
    Bottom,
}

/// Which stretch of its side an [`EdgeType`] covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeSpan {
    /// The whole side.
    Whole,
    /// `CELLROW n`: the `n`-th row the cell spans, from 1 at the bottom.
    CellRow(u32),
    /// `HALFROW n`: the `n`-th half row.
    HalfRow(u32),
    /// `RANGE b e`: from `b` to `e` along the side, database units.
    Range(i64, i64),
}

/// One `EDGETYPE` statement of a macro's `LEF58_EDGETYPE` property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeType {
    /// The side it types.
    pub side: EdgeSide,
    /// The edge type's name.
    pub name: String,
    /// The stretch of the side.
    pub span: EdgeSpan,
}

/// One `MACRO`: a cell's abstract.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Macro {
    /// The cell name, as a DEF component's model names it.
    pub name: String,
    /// `CLASS`'s first word (`CORE`, `BLOCK`, `PAD`, …); empty when none.
    pub class: String,
    /// `CLASS CORE SPACER`: a filler cell.
    pub spacer: bool,
    /// The `LEF58_EDGETYPE` property's statements, in order.
    pub edge_types: Vec<EdgeType>,
    /// `ORIGIN`, added to every shape before placement.
    pub origin: Pt,
    /// `SIZE width BY height`.
    pub size: Pt,
    /// The pins, in order.
    pub pins: Vec<MacroPin>,
    /// The `OBS` shapes.
    pub obs: Vec<Shape>,
    /// The `OBS` vias.
    pub obs_vias: Vec<(String, Pt)>,
}

/// One or more LEF files, read into one library in DEF database units.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lef {
    /// `MANUFACTURINGGRID`, database units.
    pub manufacturing_grid: Option<i64>,
    /// The layers, in order.
    pub layers: Vec<LefLayer>,
    /// The vias, each its shapes about its origin.
    pub vias: Vec<(String, Vec<Shape>)>,
    /// `SITE` sizes.
    pub sites: Vec<(String, Pt)>,
    /// Each `NONDEFAULTRULE`'s wire width per layer.
    pub ndrs: Vec<(String, Vec<(String, i64)>)>,
    /// The cell abstracts.
    pub macros: Vec<Macro>,
    /// The library's `LEF58_CELLEDGESPACINGTABLE` entries, in order, from
    /// `PROPERTYDEFINITIONS` or a library `PROPERTY`.
    pub cell_edge_spacing: Vec<CellEdgeSpacing>,
}

/// Reads one LEF file into `lef`, every length converted to `dbu` units per
/// micrometre (the DEF's `UNITS DISTANCE MICRONS`). A technology LEF and
/// its cell LEFs are read one after the other into one [`Lef`]; a later
/// definition of a name is appended, and the first one found is used.
///
/// # Errors
///
/// A malformed statement; a `PATH` or `ITERATE`; a via `PATTERN` that
/// does not fit its `ROWCOL`; a length that is not a whole number of
/// database units. An unknown layer type is read as `Other`, never refused.
pub fn read_lef_into(text: &str, dbu: i64, lef: &mut Lef) -> Result<(), LefDefError> {
    let mut lx = Lexer::new(text, "LEF");
    while let Some(word) = lx.peek() {
        lx.next()?;
        match word {
            "END" => {
                // `END LIBRARY`, the last statement.
                lx.next()?;
            }
            "UNITS" | "SPACING" => skip_to_end(&mut lx, word)?,
            "PROPERTYDEFINITIONS" => loop {
                // `object name type [RANGE …] [value] ;`; a library string
                // property may carry its value here.
                let object = lx.next()?;
                if object == "END" {
                    lx.expect("PROPERTYDEFINITIONS")?;
                    break;
                }
                let name = lx.next()?;
                let mut value = None;
                loop {
                    let token = lx.next()?;
                    if token == ";" {
                        break;
                    }
                    if token.starts_with('"') {
                        value = Some(token);
                    }
                }
                if let (Some(value), "LIBRARY") = (value, object) {
                    library_property(&mut lx, dbu, lef, name, value)?;
                }
            },
            "PROPERTY" => loop {
                // `PROPERTY name value [name value …] ;`.
                let name = lx.next()?;
                if name == ";" {
                    break;
                }
                let value = lx.next()?;
                library_property(&mut lx, dbu, lef, name, value)?;
            },
            "MANUFACTURINGGRID" => {
                lef.manufacturing_grid = Some(lx.microns(dbu)?);
                lx.expect(";")?;
            }
            "LAYER" => lef.layers.push(layer(&mut lx, dbu)?),
            "VIA" => {
                let name = lx.next()?.to_owned();
                let shapes = via(&mut lx, dbu, &name)?;
                lef.vias.push((name, shapes));
            }
            "SITE" => {
                let name = lx.next()?.to_owned();
                let mut size = (0, 0);
                loop {
                    match lx.next()? {
                        "END" => {
                            lx.expect(&name)?;
                            break;
                        }
                        "SIZE" => {
                            size.0 = lx.microns(dbu)?;
                            lx.expect("BY")?;
                            size.1 = lx.microns(dbu)?;
                            lx.expect(";")?;
                        }
                        _ => lx.skip_statement()?,
                    }
                }
                lef.sites.push((name, size));
            }
            "NONDEFAULTRULE" => {
                let name = lx.next()?.to_owned();
                let mut widths = Vec::new();
                loop {
                    match lx.next()? {
                        "END" => {
                            lx.expect(&name)?;
                            break;
                        }
                        "LAYER" => {
                            let layer = lx.next()?.to_owned();
                            loop {
                                match lx.next()? {
                                    "END" => {
                                        lx.expect(&layer)?;
                                        break;
                                    }
                                    "WIDTH" => {
                                        widths.push((layer.clone(), lx.microns(dbu)?));
                                        lx.expect(";")?;
                                    }
                                    _ => lx.skip_statement()?,
                                }
                            }
                        }
                        "VIA" => {
                            let via_name = lx.next()?.to_owned();
                            let shapes = via(&mut lx, dbu, &via_name)?;
                            lef.vias.push((via_name, shapes));
                        }
                        "SPACING" => skip_to_end(&mut lx, "SPACING")?,
                        _ => lx.skip_statement()?,
                    }
                }
                lef.ndrs.push((name, widths));
            }
            "BEGINEXT" => while lx.next()? != "ENDEXT" {},
            "VIARULE" => {
                let name = lx.next()?.to_owned();
                skip_to_end(&mut lx, &name)?;
            }
            "MACRO" => lef.macros.push(macro_(&mut lx, dbu)?),
            _ => lx.skip_statement()?,
        }
    }
    Ok(())
}

/// The text of a quoted LEF string, quotes removed.
fn unquote(token: &str) -> &str {
    token.trim_start_matches('"').trim_end_matches('"')
}

/// Reads a library property the reader keeps: `LEF58_CELLEDGESPACINGTABLE`,
/// `CELLEDGESPACINGTABLE [NODEFAULT] { EDGETYPE type type [options]
/// spacing }… ;` (the options as OpenROAD's parser orders them). Any other
/// property is skipped.
fn library_property(
    lx: &mut Lexer<'_>,
    dbu: i64,
    lef: &mut Lef,
    name: &str,
    value: &str,
) -> Result<(), LefDefError> {
    if name != "LEF58_CELLEDGESPACINGTABLE" {
        return Ok(());
    }
    let mut words = unquote(value)
        .split(|c: char| c.is_whitespace() || c == ';')
        .filter(|w| !w.is_empty())
        .peekable();
    if words.next() != Some("CELLEDGESPACINGTABLE") {
        return Err(lx.err("LEF58_CELLEDGESPACINGTABLE does not start CELLEDGESPACINGTABLE"));
    }
    if words.peek() == Some(&"NODEFAULT") {
        words.next();
    }
    while let Some(word) = words.next() {
        if word != "EDGETYPE" {
            return Err(lx.err(format!(
                "LEF58_CELLEDGESPACINGTABLE: {word} where EDGETYPE belongs"
            )));
        }
        let mut field = || {
            words
                .next()
                .ok_or_else(|| lx.err("LEF58_CELLEDGESPACINGTABLE: an EDGETYPE entry ends early"))
        };
        let (first, second) = (field()?.to_owned(), field()?.to_owned());
        let mut entry = CellEdgeSpacing {
            first,
            second,
            spacing: 0,
            except_abutted: false,
            undefined: Vec::new(),
        };
        loop {
            let word = field()?;
            match word {
                "EXCEPTABUTTED" => entry.except_abutted = true,
                "EXCEPTNONFILLERINBETWEEN" | "OPTIONAL" | "SOFT" | "EXACT" => {
                    entry.undefined.push(word.to_owned());
                }
                _ => {
                    entry.spacing = super::lex::exact_units(word, dbu).ok_or_else(|| {
                        lx.err(format!(
                            "LEF58_CELLEDGESPACINGTABLE: spacing {word} is not a whole number of database units"
                        ))
                    })?;
                    break;
                }
            }
        }
        lef.cell_edge_spacing.push(entry);
    }
    Ok(())
}

/// Reads a macro's `LEF58_EDGETYPE` value: `EDGETYPE {RIGHT | LEFT | TOP |
/// BOTTOM} type [CELLROW n | HALFROW n | RANGE b e] ;`, one or more.
fn edge_types(lx: &Lexer<'_>, dbu: i64, value: &str) -> Result<Vec<EdgeType>, LefDefError> {
    let mut out = Vec::new();
    for statement in unquote(value).split(';') {
        let words: Vec<&str> = statement.split_whitespace().collect();
        if words.is_empty() {
            continue;
        }
        let bad = || {
            lx.err(format!(
                "LEF58_EDGETYPE: cannot read `{}`",
                statement.trim()
            ))
        };
        let side = match words.get(1).copied() {
            Some("LEFT") => EdgeSide::Left,
            Some("RIGHT") => EdgeSide::Right,
            Some("TOP") => EdgeSide::Top,
            Some("BOTTOM") => EdgeSide::Bottom,
            _ => return Err(bad()),
        };
        let (Some(&"EDGETYPE"), Some(name)) = (words.first(), words.get(2)) else {
            return Err(bad());
        };
        let row = |text: &str| text.parse::<u32>().ok().filter(|&n| n > 0);
        let span = match words[3..] {
            [] => EdgeSpan::Whole,
            ["CELLROW", n] => EdgeSpan::CellRow(row(n).ok_or_else(bad)?),
            ["HALFROW", n] => EdgeSpan::HalfRow(row(n).ok_or_else(bad)?),
            ["RANGE", b, e] => {
                let at = |t: &str| super::lex::exact_units(t, dbu).ok_or_else(bad);
                EdgeSpan::Range(at(b)?, at(e)?)
            }
            _ => return Err(bad()),
        };
        out.push(EdgeType {
            side,
            name: (*name).to_owned(),
            span,
        });
    }
    Ok(out)
}

/// Skips to just past `END name`.
fn skip_to_end(lx: &mut Lexer<'_>, name: &str) -> Result<(), LefDefError> {
    while !(lx.next()? == "END" && lx.eat(name)) {}
    Ok(())
}

fn layer(lx: &mut Lexer<'_>, dbu: i64) -> Result<LefLayer, LefDefError> {
    let name = lx.next()?.to_owned();
    let mut out = LefLayer {
        name: name.clone(),
        kind: LayerKind::Other,
        width: None,
        pitch: None,
        horizontal: None,
    };
    loop {
        match lx.next()? {
            "END" => {
                lx.expect(&name)?;
                return Ok(out);
            }
            "TYPE" => {
                out.kind = match lx.next()? {
                    "ROUTING" => LayerKind::Routing,
                    "CUT" => LayerKind::Cut,
                    "MASTERSLICE" => LayerKind::Masterslice,
                    "OVERLAP" => LayerKind::Overlap,
                    _ => LayerKind::Other,
                };
                lx.skip_statement()?;
            }
            "WIDTH" => {
                out.width = Some(lx.microns(dbu)?);
                lx.expect(";")?;
            }
            "PITCH" => {
                let x = lx.microns(dbu)?;
                let y = if lx.peek() == Some(";") {
                    x
                } else {
                    lx.microns(dbu)?
                };
                out.pitch = Some((x, y));
                lx.expect(";")?;
            }
            "DIRECTION" => {
                out.horizontal = match lx.next()? {
                    "HORIZONTAL" => Some(true),
                    "VERTICAL" => Some(false),
                    _ => None,
                };
                lx.skip_statement()?;
            }
            "ACCURRENTDENSITY" | "DCCURRENTDENSITY" => {
                // `… type value ;`, or `… type` and its own `FREQUENCY`,
                // `CUTAREA`, `WIDTH` statements through `TABLEENTRIES … ;`.
                lx.next()?;
                if lx.peek().is_some_and(|w| w.parse::<f64>().is_err()) {
                    while lx.next()? != "TABLEENTRIES" {}
                }
                lx.skip_statement()?;
            }
            ";" => {}
            _ => lx.skip_statement()?,
        }
    }
}

/// A `VIA` body after its name, through `END name`: fixed shapes, or a
/// generated via's rule.
fn via(lx: &mut Lexer<'_>, dbu: i64, name: &str) -> Result<Vec<Shape>, LefDefError> {
    lx.eat("DEFAULT");
    let mut shapes = Vec::new();
    let mut rule: Option<ViaRule> = None;
    let mut layer = String::new();
    loop {
        let word = lx.next()?;
        match word {
            "END" => {
                lx.expect(name)?;
                break;
            }
            "LAYER" => {
                layer = lx.next()?.to_owned();
                lx.skip_statement()?;
            }
            "RECT" | "POLYGON" => shapes.push(geometry(lx, dbu, &layer, word)?),
            "VIARULE" => {
                lx.next()?;
                lx.expect(";")?;
                rule = Some(ViaRule {
                    rowcol: (1, 1),
                    ..ViaRule::default()
                });
            }
            "CUTSIZE" | "CUTSPACING" | "ROWCOL" | "ORIGIN" => {
                let r = rule
                    .as_mut()
                    .ok_or_else(|| lx.err("via rule data without VIARULE"))?;
                let a = if word == "ROWCOL" {
                    lx.int()?
                } else {
                    lx.microns(dbu)?
                };
                let b = if word == "ROWCOL" {
                    lx.int()?
                } else {
                    lx.microns(dbu)?
                };
                match word {
                    "CUTSIZE" => r.cut = (a, b),
                    "CUTSPACING" => r.spacing = (a, b),
                    "ROWCOL" => r.rowcol = (a, b),
                    _ => r.origin = (a, b),
                }
                lx.expect(";")?;
            }
            "ENCLOSURE" | "OFFSET" => {
                let r = rule
                    .as_mut()
                    .ok_or_else(|| lx.err("via rule data without VIARULE"))?;
                let mut v = [0; 4];
                for slot in &mut v {
                    *slot = lx.microns(dbu)?;
                }
                if word == "ENCLOSURE" {
                    r.enclosure = v;
                } else {
                    r.offset = v;
                }
                lx.expect(";")?;
            }
            "LAYERS" => {
                let r = rule
                    .as_mut()
                    .ok_or_else(|| lx.err("via rule data without VIARULE"))?;
                for slot in &mut r.layers {
                    lx.next()?.clone_into(slot);
                }
                lx.expect(";")?;
            }
            "PATTERN" => {
                let r = rule
                    .as_mut()
                    .ok_or_else(|| lx.err("PATTERN without VIARULE"))?;
                lx.next()?.clone_into(&mut r.pattern);
                lx.eat(";");
            }
            _ => lx.skip_statement()?,
        }
    }
    if let Some(rule) = rule {
        check_rule(lx, &rule)?;
        shapes.extend(rule.shapes());
    }
    Ok(shapes)
}

pub(super) fn check_rule(lx: &Lexer<'_>, rule: &ViaRule) -> Result<(), LefDefError> {
    if rule.rowcol.0 < 1 || rule.rowcol.1 < 1 || rule.cut.0 <= 0 || rule.cut.1 <= 0 {
        return Err(lx.err("a generated via needs a positive CUTSIZE and ROWCOL"));
    }
    if rule.rowcol.0 > 1024 || rule.rowcol.1 > 1024 {
        return Err(lx.err("a generated via of more than 1024 cuts a side is not read"));
    }
    if rule.layers.iter().any(String::is_empty) {
        return Err(lx.err("a generated via needs its LAYERS"));
    }
    if rule.cuts().is_none() {
        return Err(lx.err(format!(
            "via cut PATTERN {} does not give the {} rows of {} cuts its ROWCOL states",
            rule.pattern, rule.rowcol.0, rule.rowcol.1
        )));
    }
    Ok(())
}

/// `RECT [MASK n] pt pt ;` or `POLYGON [MASK n] pt pt pt … ;` on `layer`.
fn geometry(lx: &mut Lexer<'_>, dbu: i64, layer: &str, word: &str) -> Result<Shape, LefDefError> {
    if layer.is_empty() {
        return Err(lx.err(format!("{word} before any LAYER")));
    }
    if lx.eat("MASK") {
        lx.next()?;
    }
    if lx.peek() == Some("ITERATE") {
        return Err(lx.err("ITERATE geometry is not read"));
    }
    let mut points = Vec::new();
    while lx.peek() != Some(";") {
        // LEF points may be bracketed: `( x y )`.
        let bracketed = lx.eat("(");
        let x = lx.microns(dbu)?;
        let y = lx.microns(dbu)?;
        if bracketed {
            lx.expect(")")?;
        }
        points.push((x, y));
    }
    lx.expect(";")?;
    if word == "RECT" {
        let [a, b] = points[..] else {
            return Err(lx.err("a RECT has two points"));
        };
        Ok(Shape::rect(layer, a, b))
    } else if points.len() < 3 {
        Err(lx.err("a POLYGON has at least three points"))
    } else {
        Ok(Shape {
            layer: layer.to_owned(),
            ring: points,
        })
    }
}

/// `LAYER`/`RECT`/`POLYGON`/`VIA` statements up to `END`, into shapes and
/// vias.
fn geometries(
    lx: &mut Lexer<'_>,
    dbu: i64,
    shapes: &mut Vec<Shape>,
    vias: &mut Vec<(String, Pt)>,
) -> Result<(), LefDefError> {
    let mut layer = String::new();
    loop {
        let word = lx.next()?;
        match word {
            "END" => return Ok(()),
            "LAYER" => {
                layer = lx.next()?.to_owned();
                lx.skip_statement()?;
            }
            "RECT" | "POLYGON" => shapes.push(geometry(lx, dbu, &layer, word)?),
            "VIA" => {
                if lx.eat("MASK") {
                    lx.next()?;
                }
                if lx.peek() == Some("ITERATE") {
                    return Err(lx.err("ITERATE geometry is not read"));
                }
                let bracketed = lx.eat("(");
                let x = lx.microns(dbu)?;
                let y = lx.microns(dbu)?;
                if bracketed {
                    lx.expect(")")?;
                }
                vias.push((lx.next()?.to_owned(), (x, y)));
                lx.expect(";")?;
            }
            "PATH" => return Err(lx.err("PATH geometry is not read")),
            ";" => {}
            _ => lx.skip_statement()?,
        }
    }
}

fn macro_(lx: &mut Lexer<'_>, dbu: i64) -> Result<Macro, LefDefError> {
    let name = lx.next()?.to_owned();
    let mut out = Macro {
        name: name.clone(),
        ..Macro::default()
    };
    loop {
        match lx.next()? {
            "END" => {
                lx.expect(&name)?;
                return Ok(out);
            }
            "CLASS" => {
                lx.next()?.clone_into(&mut out.class);
                out.spacer = out.class == "CORE" && lx.peek() == Some("SPACER");
                lx.skip_statement()?;
            }
            "PROPERTY" => loop {
                let name = lx.next()?;
                if name == ";" {
                    break;
                }
                let value = lx.next()?;
                if name == "LEF58_EDGETYPE" {
                    out.edge_types.extend(edge_types(lx, dbu, value)?);
                }
            },
            "ORIGIN" => {
                let bracketed = lx.eat("(");
                out.origin = (lx.microns(dbu)?, lx.microns(dbu)?);
                if bracketed {
                    lx.expect(")")?;
                }
                lx.expect(";")?;
            }
            "SIZE" => {
                let w = lx.microns(dbu)?;
                lx.expect("BY")?;
                out.size = (w, lx.microns(dbu)?);
                lx.expect(";")?;
            }
            "PIN" => {
                let pin_name = lx.next()?.to_owned();
                let mut pin = MacroPin {
                    name: pin_name.clone(),
                    ..MacroPin::default()
                };
                loop {
                    match lx.next()? {
                        "END" => {
                            lx.expect(&pin_name)?;
                            break;
                        }
                        "PORT" => geometries(lx, dbu, &mut pin.shapes, &mut pin.vias)?,
                        ";" => {}
                        _ => lx.skip_statement()?,
                    }
                }
                out.pins.push(pin);
            }
            "OBS" => geometries(lx, dbu, &mut out.obs, &mut out.obs_vias)?,
            "DENSITY" => {
                // `DENSITY LAYER l ; RECT … value ; … END`.
                while lx.next()? != "END" {}
            }
            ";" => {}
            _ => lx.skip_statement()?,
        }
    }
}
