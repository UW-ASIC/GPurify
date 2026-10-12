//! The DEF reader: a design's die, rows, tracks, vias, components, pins,
//! nets and fill, in its own database units.

use super::lef::{check_rule, LayerKind, Lef};
use super::lex::{Lexer, MAX_COORD};
use super::{fault, LefDefError, Orient, Pt, Shape, ViaRule};

/// One `ROW`: `num` sites of `site` from `origin`, `step` apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The row's name.
    pub name: String,
    /// The LEF `SITE` it is made of.
    pub site: String,
    /// The first site's placement point.
    pub origin: Pt,
    /// The sites' orientation.
    pub orient: Orient,
    /// `DO numX BY numY`; `(1, 1)` when absent.
    pub num: Pt,
    /// `STEP stepX stepY`; `(0, 0)` when absent.
    pub step: Pt,
}

/// One `TRACKS` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Track {
    /// `X`: tracks at x positions (vertical wires); `Y`: at y positions.
    pub x: bool,
    /// The first track's coordinate.
    pub start: i64,
    /// How many tracks.
    pub count: i64,
    /// Their pitch.
    pub step: i64,
    /// The layers they are for.
    pub layers: Vec<String>,
}

/// One `COMPONENTS` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    /// The instance name.
    pub name: String,
    /// The LEF macro it places.
    pub model: String,
    /// `PLACED`, `FIXED` or `COVER`: where and how; `None` when unplaced.
    pub placement: Option<(Pt, Orient)>,
}

/// A via placed in wiring, a pin or fill: its definition's shapes turned by
/// `orient` and moved to `at`, `array.0 × array.1` times `array.2, array.3`
/// apart (`DO … STEP …`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViaAt {
    /// The via's name, from the DEF `VIAS` or a LEF `VIA`.
    pub name: String,
    /// The via origin's placement.
    pub at: Pt,
    /// Its orientation.
    pub orient: Orient,
    /// `(numX, numY, stepX, stepY)`; `(1, 1, 0, 0)` for one via.
    pub array: (i64, i64, i64, i64),
}

/// One `PINS` entry, its shapes already placed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefPin {
    /// The pin's name.
    pub name: String,
    /// The net it is on.
    pub net: String,
    /// Every placed port's `LAYER` and `POLYGON` shapes. A port with no
    /// placement has no location and no shapes (5.8: "the PINS statement
    /// describes logical pins, without placement or physical information").
    pub shapes: Vec<Shape>,
    /// Every placed port's vias.
    pub vias: Vec<ViaAt>,
}

/// One wire segment of a net's routing, centre line and rule resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wire {
    /// The LEF routing layer.
    pub layer: String,
    /// Its width.
    pub width: i64,
    /// The segment's first routing point.
    pub from: Pt,
    /// Its second; the segment is horizontal or vertical.
    pub to: Pt,
    /// How far the wire runs past `from`.
    pub from_ext: i64,
    /// How far past `to`.
    pub to_ext: i64,
}

impl Wire {
    /// The rectangle the segment draws, as `(lower-left, upper-right)`.
    pub fn rect(&self) -> (Pt, Pt) {
        let ((ax, ay), (bx, by)) = (self.from, self.to);
        let half = self.width / 2;
        let (lo_ext, hi_ext) = if (ax, ay) <= (bx, by) {
            (self.from_ext, self.to_ext)
        } else {
            (self.to_ext, self.from_ext)
        };
        let (lo, hi) = ((ax.min(bx), ay.min(by)), (ax.max(bx), ay.max(by)));
        if ax == bx {
            (
                (lo.0 - half, lo.1 - lo_ext),
                (lo.0 + self.width - half, hi.1 + hi_ext),
            )
        } else {
            (
                (lo.0 - lo_ext, lo.1 - half),
                (hi.0 + hi_ext, lo.1 + self.width - half),
            )
        }
    }
}

/// One `NETS` or `SPECIALNETS` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Net {
    /// The net's name.
    pub name: String,
    /// From `SPECIALNETS`.
    pub special: bool,
    /// `( comp pin )` connections; `comp` is `*` for every component, and
    /// `PIN` for a DEF pin.
    pub connections: Vec<(String, String)>,
    /// The wire segments.
    pub wires: Vec<Wire>,
    /// The vias in its wiring, and a special net's `VIA` statements.
    pub vias: Vec<ViaAt>,
    /// A special net's `RECT` and `POLYGON` shapes, and every wiring `RECT`.
    pub shapes: Vec<Shape>,
}

/// One DEF file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Def {
    /// `DESIGN`.
    pub design: String,
    /// `UNITS DISTANCE MICRONS`: database units per micrometre.
    pub dbu: i64,
    /// `DIEAREA`, as a ring (two points become the rectangle's four).
    pub die_area: Vec<Pt>,
    /// The rows.
    pub rows: Vec<Row>,
    /// The routing tracks.
    pub tracks: Vec<Track>,
    /// The `VIAS` section's vias, each its shapes about its origin.
    pub vias: Vec<(String, Vec<Shape>)>,
    /// The components.
    pub components: Vec<Component>,
    /// The external pins.
    pub pins: Vec<DefPin>,
    /// Every net, special nets and regular nets in file order.
    pub nets: Vec<Net>,
    /// The `FILLS` shapes.
    pub fills: Vec<Shape>,
    /// The `FILLS` vias.
    pub fill_vias: Vec<ViaAt>,
}

/// The database units per micrometre a DEF states (`UNITS DISTANCE MICRONS
/// n`), which its LEFs are read at.
///
/// # Errors
///
/// No `UNITS` statement, or a value that is not a positive integer.
pub fn def_units(text: &str) -> Result<i64, LefDefError> {
    let mut lx = Lexer::new(text, "DEF");
    while let Some(word) = lx.peek() {
        lx.next()?;
        if word == "UNITS" {
            lx.expect("DISTANCE")?;
            lx.expect("MICRONS")?;
            let units = lx.int()?;
            if units <= 0 {
                return Err(lx.err("UNITS DISTANCE MICRONS must be positive"));
            }
            return Ok(units);
        }
    }
    Err(fault("DEF", 0, "no UNITS DISTANCE MICRONS statement"))
}

/// Reads a DEF against its LEF library, read at [`def_units`]: the LEF
/// gives a regular wire's width and the layers a via joins.
///
/// # Errors
///
/// A malformed statement, a construct the module docs list as refused, a
/// name used before it is defined, or a missing `UNITS`.
pub fn read_def(text: &str, lef: &Lef) -> Result<Def, LefDefError> {
    let mut lx = Lexer::new(text, "DEF");
    let mut def = Def::default();
    let mut ndrs: Vec<(String, Vec<(String, i64)>)> = Vec::new();
    while let Some(word) = lx.peek() {
        lx.next()?;
        match word {
            "DESIGN" => {
                lx.next()?.clone_into(&mut def.design);
                lx.expect(";")?;
            }
            "UNITS" => {
                lx.expect("DISTANCE")?;
                lx.expect("MICRONS")?;
                def.dbu = lx.int()?;
                lx.expect(";")?;
            }
            "DIEAREA" => {
                let mut prev = None;
                while lx.peek() == Some("(") {
                    let p = lx.point(prev)?;
                    def.die_area.push(p);
                    prev = Some(p);
                }
                lx.expect(";")?;
                if let [a, b] = def.die_area[..] {
                    def.die_area = Shape::rect("", a, b).ring;
                } else if def.die_area.len() < 3 {
                    return Err(lx.err("DIEAREA has two points or a polygon of three or more"));
                }
            }
            "ROW" => def.rows.push(row(&mut lx)?),
            "TRACKS" => def.tracks.push(track(&mut lx)?),
            "VIAS" => section(&mut lx, "VIAS", |lx| {
                let name = lx.next()?.to_owned();
                let shapes = def_via(lx)?;
                def.vias.push((name, shapes));
                Ok(())
            })?,
            "NONDEFAULTRULES" => section(&mut lx, "NONDEFAULTRULES", |lx| {
                let name = lx.next()?.to_owned();
                let mut widths = Vec::new();
                while lx.next()? != ";" {
                    if lx.eat("LAYER") {
                        let layer = lx.next()?.to_owned();
                        lx.expect("WIDTH")?;
                        widths.push((layer, lx.int()?));
                    }
                }
                ndrs.push((name, widths));
                Ok(())
            })?,
            "COMPONENTS" => section(&mut lx, "COMPONENTS", |lx| {
                let name = lx.next()?.to_owned();
                let model = lx.next()?.to_owned();
                let mut placement = None;
                options(lx, |lx, key| {
                    if matches!(key, "PLACED" | "FIXED" | "COVER") {
                        let at = lx.point(None)?;
                        placement = Some((at, orient(lx)?));
                    }
                    Ok(())
                })?;
                def.components.push(Component {
                    name,
                    model,
                    placement,
                });
                Ok(())
            })?,
            "PINS" => section(&mut lx, "PINS", |lx| {
                let pin = pin(lx, &def.vias, lef)?;
                def.pins.push(pin);
                Ok(())
            })?,
            "NETS" | "SPECIALNETS" => {
                let special = word == "SPECIALNETS";
                let mut nets = Vec::new();
                section(&mut lx, word, |lx| {
                    nets.push(net(lx, special, &def.vias, &ndrs, lef)?);
                    Ok(())
                })?;
                def.nets.extend(nets);
            }
            "FILLS" => section(&mut lx, "FILLS", |lx| {
                if lx.eat("VIA") {
                    let name = lx.next()?.to_owned();
                    plus_options(lx)?;
                    while lx.peek() == Some("(") {
                        let at = lx.point(None)?;
                        def.fill_vias.push(ViaAt {
                            name: name.clone(),
                            at,
                            orient: Orient::N,
                            array: (1, 1, 0, 0),
                        });
                    }
                    return lx.expect(";");
                }
                lx.expect("LAYER")?;
                let layer = lx.next()?.to_owned();
                plus_options(lx)?;
                loop {
                    match lx.next()? {
                        ";" => return Ok(()),
                        "RECT" => {
                            let a = lx.point(None)?;
                            let b = lx.point(Some(a))?;
                            def.fills.push(Shape::rect(&layer, a, b));
                        }
                        "POLYGON" => def.fills.push(polygon(lx, &layer)?),
                        other => return Err(lx.err(format!("unexpected {other} in a fill"))),
                    }
                }
            })?,
            "BEGINEXT" => while lx.next()? != "ENDEXT" {},
            "PROPERTYDEFINITIONS"
            | "REGIONS"
            | "GROUPS"
            | "SCANCHAINS"
            | "BLOCKAGES"
            | "PINPROPERTIES"
            | "SLOTS"
            | "STYLES"
            | "GCELLGRIDS" => while !(lx.next()? == "END" && lx.eat(word)) {},
            "END" => {
                lx.expect("DESIGN")?;
                break;
            }
            _ => lx.skip_statement()?,
        }
    }
    if def.dbu <= 0 {
        return Err(fault("DEF", 0, "no positive UNITS DISTANCE MICRONS"));
    }
    Ok(def)
}

/// `count ; - item ; … END name`: each item after its `-` through its `;`
/// is `item`'s to read.
fn section<'a>(
    lx: &mut Lexer<'a>,
    name: &str,
    mut item: impl FnMut(&mut Lexer<'a>) -> Result<(), LefDefError>,
) -> Result<(), LefDefError> {
    lx.int()?;
    lx.expect(";")?;
    loop {
        if lx.eat("END") {
            return lx.expect(name);
        }
        lx.expect("-")?;
        item(lx)?;
    }
}

/// `+ KEY …` options through the item's `;`; `read` takes the words after
/// `KEY` it knows, and the rest up to the next `+` or `;` is skipped.
fn options<'a>(
    lx: &mut Lexer<'a>,
    mut read: impl FnMut(&mut Lexer<'a>, &str) -> Result<(), LefDefError>,
) -> Result<(), LefDefError> {
    loop {
        match lx.next()? {
            ";" => return Ok(()),
            "+" => {
                let key = lx.next()?;
                read(lx, key)?;
                while !matches!(lx.peek(), Some("+" | ";") | None) {
                    lx.next()?;
                }
            }
            other => return Err(lx.err(format!("expected + or ;, found {other}"))),
        }
    }
}

/// Skips `+ MASK n` and `+ OPC` before a shape.
fn plus_options(lx: &mut Lexer<'_>) -> Result<(), LefDefError> {
    while lx.eat("+") {
        if lx.next()? == "MASK" {
            lx.next()?;
        }
    }
    Ok(())
}

fn orient(lx: &mut Lexer<'_>) -> Result<Orient, LefDefError> {
    let word = lx.next()?;
    Orient::parse(word).ok_or_else(|| lx.err(format!("{word} is not an orientation")))
}

fn polygon(lx: &mut Lexer<'_>, layer: &str) -> Result<Shape, LefDefError> {
    let mut ring = Vec::new();
    while lx.peek() == Some("(") {
        let p = lx.point(ring.last().copied())?;
        ring.push(p);
    }
    if ring.len() < 3 {
        return Err(lx.err("a POLYGON has at least three points"));
    }
    Ok(Shape {
        layer: layer.to_owned(),
        ring,
    })
}

fn row(lx: &mut Lexer<'_>) -> Result<Row, LefDefError> {
    let name = lx.next()?.to_owned();
    let site = lx.next()?.to_owned();
    let origin = (lx.int()?, lx.int()?);
    let orient = orient(lx)?;
    let (mut num, mut step) = ((1, 1), (0, 0));
    if lx.eat("DO") {
        num.0 = lx.int()?;
        lx.expect("BY")?;
        num.1 = lx.int()?;
        if lx.eat("STEP") {
            step = (lx.int()?, lx.int()?);
        }
    }
    while lx.next()? != ";" {}
    Ok(Row {
        name,
        site,
        origin,
        orient,
        num,
        step,
    })
}

fn track(lx: &mut Lexer<'_>) -> Result<Track, LefDefError> {
    let x = match lx.next()? {
        "X" => true,
        "Y" => false,
        other => return Err(lx.err(format!("TRACKS takes X or Y, not {other}"))),
    };
    let start = lx.int()?;
    lx.expect("DO")?;
    let count = lx.int()?;
    lx.expect("STEP")?;
    let step = lx.int()?;
    let mut layers = Vec::new();
    loop {
        match lx.next()? {
            ";" => break,
            "MASK" => {
                lx.next()?;
                lx.eat("SAMEMASK");
            }
            "LAYER" => {
                while lx.peek().is_some_and(|w| w != ";") {
                    layers.push(lx.next()?.to_owned());
                }
            }
            other => return Err(lx.err(format!("unexpected {other} in TRACKS"))),
        }
    }
    Ok(Track {
        x,
        start,
        count,
        step,
        layers,
    })
}

/// A `VIAS` item after its name: `+ RECT`/`+ POLYGON` shapes, or a
/// generated via's `+ VIARULE` parameters.
fn def_via(lx: &mut Lexer<'_>) -> Result<Vec<Shape>, LefDefError> {
    let mut shapes = Vec::new();
    let mut rule: Option<ViaRule> = None;
    loop {
        match lx.next()? {
            ";" => break,
            "+" => {}
            other => return Err(lx.err(format!("expected + or ;, found {other}"))),
        }
        let key = lx.next()?;
        match key {
            "RECT" | "POLYGON" => {
                let layer = lx.next()?;
                if lx.peek() == Some("+") {
                    lx.next()?;
                    lx.expect("MASK")?;
                    lx.next()?;
                }
                if key == "RECT" {
                    let a = lx.point(None)?;
                    let b = lx.point(Some(a))?;
                    shapes.push(Shape::rect(layer, a, b));
                } else {
                    shapes.push(polygon(lx, layer)?);
                }
            }
            "VIARULE" => {
                lx.next()?;
                rule = Some(ViaRule {
                    rowcol: (1, 1),
                    ..ViaRule::default()
                });
            }
            "PATTERN" => {
                let r = rule
                    .as_mut()
                    .ok_or_else(|| lx.err("PATTERN without VIARULE"))?;
                lx.next()?.clone_into(&mut r.pattern);
            }
            // The name of the pattern a fixed via was made from (5.6).
            "PATTERNNAME" => {
                lx.next()?;
            }
            _ => {
                let r = rule
                    .as_mut()
                    .ok_or_else(|| lx.err(format!("{key} without VIARULE")))?;
                match key {
                    "CUTSIZE" => r.cut = (lx.int()?, lx.int()?),
                    "CUTSPACING" => r.spacing = (lx.int()?, lx.int()?),
                    "ROWCOL" => r.rowcol = (lx.int()?, lx.int()?),
                    "ORIGIN" => r.origin = (lx.int()?, lx.int()?),
                    "LAYERS" => {
                        for slot in &mut r.layers {
                            lx.next()?.clone_into(slot);
                        }
                    }
                    "ENCLOSURE" | "OFFSET" => {
                        let mut v = [0; 4];
                        for slot in &mut v {
                            *slot = lx.int()?;
                        }
                        if key == "ENCLOSURE" {
                            r.enclosure = v;
                        } else {
                            r.offset = v;
                        }
                    }
                    other => return Err(lx.err(format!("unexpected {other} in a via"))),
                }
            }
        }
    }
    if let Some(rule) = rule {
        check_rule(lx, &rule)?;
        shapes.extend(rule.shapes());
    }
    Ok(shapes)
}

fn pin(
    lx: &mut Lexer<'_>,
    vias: &[(String, Vec<Shape>)],
    lef: &Lef,
) -> Result<DefPin, LefDefError> {
    let name = lx.next()?.to_owned();
    // One port at a time: its shapes and vias relative to its placement.
    let mut out = DefPin {
        name,
        net: String::new(),
        shapes: Vec::new(),
        vias: Vec::new(),
    };
    let mut port: (Vec<Shape>, Vec<ViaAt>) = (Vec::new(), Vec::new());
    let close =
        |port: &mut (Vec<Shape>, Vec<ViaAt>), placed: Option<(Pt, Orient)>, out: &mut DefPin| {
            let (shapes, vias) = std::mem::take(port);
            if let Some((at, orient)) = placed {
                out.shapes
                    .extend(shapes.iter().map(|shape| shape.moved(orient, at)));
                out.vias.extend(vias.into_iter().map(|via| {
                    let (x, y) = orient.apply(via.at);
                    ViaAt {
                        at: (x + at.0, y + at.1),
                        ..via
                    }
                }));
            }
        };
    let mut placed = None;
    options(lx, |lx, key| {
        match key {
            "NET" => lx.next()?.clone_into(&mut out.net),
            "PORT" => {
                close(&mut port, placed.take(), &mut out);
            }
            "LAYER" | "POLYGON" => {
                let layer = lx.next()?;
                while let Some("MASK" | "SPACING" | "DESIGNRULEWIDTH") = lx.peek() {
                    lx.next()?;
                    lx.next()?;
                }
                if key == "LAYER" {
                    let a = lx.point(None)?;
                    let b = lx.point(Some(a))?;
                    port.0.push(Shape::rect(layer, a, b));
                } else {
                    port.0.push(polygon(lx, layer)?);
                }
            }
            "VIA" => {
                let via = lx.next()?.to_owned();
                known_via(lx, &via, vias, lef)?;
                if lx.eat("MASK") {
                    lx.next()?;
                }
                let at = lx.point(None)?;
                port.1.push(ViaAt {
                    name: via,
                    at,
                    orient: Orient::N,
                    array: (1, 1, 0, 0),
                });
            }
            "PLACED" | "FIXED" | "COVER" => {
                let at = lx.point(None)?;
                placed = Some((at, orient(lx)?));
            }
            _ => {}
        }
        Ok(())
    })?;
    close(&mut port, placed, &mut out);
    if out.net.is_empty() {
        return Err(lx.err(format!("pin {} has no + NET", out.name)));
    }
    Ok(out)
}

fn known_via<'v>(
    lx: &Lexer<'_>,
    name: &str,
    vias: &'v [(String, Vec<Shape>)],
    lef: &'v Lef,
) -> Result<&'v [Shape], LefDefError> {
    vias.iter()
        .chain(&lef.vias)
        .find(|(n, _)| n == name)
        .map(|(_, shapes)| shapes.as_slice())
        .ok_or_else(|| lx.err(format!("via {name} is defined in no earlier VIAS or LEF")))
}

/// Which rule a regular wire is drawn at.
#[derive(Clone)]
enum Taper {
    /// The net's `NONDEFAULTRULE`, else the LEF width.
    Net,
    /// `TAPER`: the LEF width.
    Default,
    /// `TAPERRULE name`.
    Rule(String),
}

/// A wire before its rule is known: special wires carry their width.
struct RawWire {
    layer: String,
    width: Option<i64>,
    taper: Taper,
    from: Pt,
    to: Pt,
    from_ext: Option<i64>,
    to_ext: Option<i64>,
}

fn net(
    lx: &mut Lexer<'_>,
    special: bool,
    vias: &[(String, Vec<Shape>)],
    ndrs: &[(String, Vec<(String, i64)>)],
    lef: &Lef,
) -> Result<Net, LefDefError> {
    let name = lx.next()?.to_owned();
    let mut out = Net {
        name,
        special,
        connections: Vec::new(),
        wires: Vec::new(),
        vias: Vec::new(),
        shapes: Vec::new(),
    };
    while lx.eat("(") {
        let comp = lx.next()?.to_owned();
        let pin = lx.next()?.to_owned();
        while lx.next()? != ")" {}
        out.connections.push((comp, pin));
    }
    let mut raw: Vec<RawWire> = Vec::new();
    let mut ndr: Option<String> = None;
    let line = lx.line();
    options(lx, |lx, key| {
        match key {
            "ROUTED" | "FIXED" | "COVER" | "NOSHIELD" => {
                routing(lx, special, vias, lef, &mut raw, &mut out)?;
            }
            "SHIELD" => return Err(lx.err("SHIELD wiring is not read")),
            "SUBNET" => return Err(lx.err("a SUBNET is not read")),
            "NONDEFAULTRULE" => ndr = Some(lx.next()?.to_owned()),
            "RECT" | "POLYGON" if special => {
                let layer = lx.next()?.to_owned();
                plus_options(lx)?;
                if key == "RECT" {
                    let a = lx.point(None)?;
                    let b = lx.point(Some(a))?;
                    out.shapes.push(Shape::rect(&layer, a, b));
                } else {
                    out.shapes.push(polygon(lx, &layer)?);
                }
            }
            "VIA" if special => {
                let via = lx.next()?.to_owned();
                known_via(lx, &via, vias, lef)?;
                plus_options(lx)?;
                let orient = if lx.peek() == Some("(") {
                    Orient::N
                } else {
                    orient(lx)?
                };
                while lx.peek() == Some("(") {
                    let at = lx.point(None)?;
                    out.vias.push(ViaAt {
                        name: via.clone(),
                        at,
                        orient,
                        array: (1, 1, 0, 0),
                    });
                }
            }
            _ => {}
        }
        Ok(())
    })?;
    let rule_width = |rule: &str, layer: &str| {
        ndrs.iter()
            .chain(&lef.ndrs)
            .find(|(n, _)| n == rule)
            .and_then(|(_, widths)| widths.iter().find(|(l, _)| l == layer))
            .map(|w| w.1)
    };
    for wire in raw {
        let width = match (wire.width, &wire.taper, &ndr) {
            (Some(width), _, _) => Some(width),
            (None, Taper::Rule(rule), _) | (None, Taper::Net, Some(rule)) => {
                rule_width(rule, &wire.layer)
            }
            (None, _, _) => lef
                .layers
                .iter()
                .find(|l| l.name == wire.layer)
                .and_then(|l| l.width),
        }
        .ok_or_else(|| {
            fault(
                "DEF",
                line,
                format!(
                    "net {} routes on {}, which has no LEF WIDTH or rule width",
                    out.name, wire.layer
                ),
            )
        })?;
        // The default extension: half the width for a regular wire, none
        // for a special one (5.8 pp. 268, 321).
        let ext = if special { 0 } else { width / 2 };
        out.wires.push(Wire {
            layer: wire.layer,
            width,
            from: wire.from,
            to: wire.to,
            from_ext: wire.from_ext.unwrap_or(ext),
            to_ext: wire.to_ext.unwrap_or(ext),
        });
    }
    Ok(out)
}

/// A routing statement after `ROUTED`: paths separated by `NEW`, through
/// the next `+` or `;`.
fn routing(
    lx: &mut Lexer<'_>,
    special: bool,
    vias: &[(String, Vec<Shape>)],
    lef: &Lef,
    raw: &mut Vec<RawWire>,
    out: &mut Net,
) -> Result<(), LefDefError> {
    loop {
        let mut layer = lx.next()?.to_owned();
        let width = if special { Some(lx.int()?) } else { None };
        let mut taper = Taper::Net;
        loop {
            match lx.peek() {
                Some("TAPER") => {
                    lx.next()?;
                    taper = Taper::Default;
                }
                Some("TAPERRULE") => {
                    lx.next()?;
                    taper = Taper::Rule(lx.next()?.to_owned());
                }
                Some("STYLE") => return Err(lx.err("a wire STYLE is not read")),
                Some("+") if special => {
                    lx.next()?;
                    match lx.next()? {
                        "SHAPE" | "MASK" => {
                            lx.next()?;
                        }
                        "STYLE" => return Err(lx.err("a wire STYLE is not read")),
                        other => return Err(lx.err(format!("unexpected + {other} in wiring"))),
                    }
                }
                _ => break,
            }
        }
        // The last point: where the path is, and the extension it carries.
        let mut last: Option<(Pt, Option<i64>)> = None;
        loop {
            match lx.peek() {
                Some("(") => {
                    lx.next()?;
                    let prev = last.map(|l| l.0);
                    let x = lx.coord(prev.map(|p| p.0))?;
                    let y = lx.coord(prev.map(|p| p.1))?;
                    let ext = if lx.peek() == Some(")") {
                        None
                    } else {
                        let ext = lx.int()?;
                        if ext < 0 {
                            return Err(lx.err("a wire extension is at least 0"));
                        }
                        Some(ext)
                    };
                    lx.expect(")")?;
                    match last {
                        Some((p, p_ext)) if p != (x, y) => {
                            if p.0 != x && p.1 != y {
                                return Err(lx.err(
                                    "a wire segment that is neither horizontal nor vertical \
                                     is not read",
                                ));
                            }
                            raw.push(RawWire {
                                layer: layer.clone(),
                                width,
                                taper: taper.clone(),
                                from: p,
                                to: (x, y),
                                from_ext: p_ext,
                                to_ext: ext,
                            });
                        }
                        // The same point again: an extension at a via.
                        Some((_, p_ext)) => {
                            last = Some(((x, y), ext.or(p_ext)));
                            continue;
                        }
                        None => {}
                    }
                    last = Some(((x, y), ext));
                }
                Some("MASK") => {
                    lx.next()?;
                    lx.next()?;
                }
                Some("RECT") => {
                    lx.next()?;
                    let (px, py) = last
                        .ok_or_else(|| lx.err("a wiring RECT before any point"))?
                        .0;
                    lx.expect("(")?;
                    let d = [lx.int()?, lx.int()?, lx.int()?, lx.int()?];
                    lx.expect(")")?;
                    out.shapes.push(Shape::rect(
                        &layer,
                        (px + d[0], py + d[1]),
                        (px + d[2], py + d[3]),
                    ));
                }
                Some("VIRTUAL") => {
                    lx.next()?;
                    let p = lx.point(last.map(|l| l.0))?;
                    last = Some((p, None));
                }
                Some("NEW") => {
                    lx.next()?;
                    break;
                }
                Some("+" | ";") | None => return Ok(()),
                Some(_) => {
                    let name = lx.next()?.to_owned();
                    let shapes = known_via(lx, &name, vias, lef)?;
                    let at = last
                        .ok_or_else(|| lx.err(format!("via {name} before any point")))?
                        .0;
                    let orient = match lx.peek().and_then(Orient::parse) {
                        Some(o) => {
                            lx.next()?;
                            o
                        }
                        None => Orient::N,
                    };
                    let mut array = (1, 1, 0, 0);
                    if lx.eat("DO") {
                        array.0 = lx.int()?;
                        lx.expect("BY")?;
                        array.1 = lx.int()?;
                        lx.expect("STEP")?;
                        array.2 = lx.int()?;
                        array.3 = lx.int()?;
                        if array.0 < 1 || array.1 < 1 || array.0 * array.1 > 1 << 20 {
                            return Err(lx.err("a via array of 1 to 2^20 vias"));
                        }
                    }
                    layer = other_layer(lx, shapes, &layer, &name, lef)?;
                    out.vias.push(ViaAt {
                        name,
                        at,
                        orient,
                        array,
                    });
                    last = Some((at, None));
                }
            }
        }
    }
}

/// The layer a via takes a path to from `layer`: of the via's two
/// non-cut layers, the one it is not on.
fn other_layer(
    lx: &Lexer<'_>,
    shapes: &[Shape],
    layer: &str,
    via: &str,
    lef: &Lef,
) -> Result<String, LefDefError> {
    let is_cut = |name: &str| {
        lef.layers
            .iter()
            .any(|l| l.name == name && l.kind == LayerKind::Cut)
    };
    let mut metals: Vec<&str> = shapes
        .iter()
        .map(|s| s.layer.as_str())
        .filter(|l| !is_cut(l))
        .collect();
    metals.sort_unstable();
    metals.dedup();
    match metals[..] {
        [a, b] if a == layer => Ok(b.to_owned()),
        [a, b] if b == layer => Ok(a.to_owned()),
        _ => Err(lx.err(format!(
            "via {via} does not join {layer} to one other layer (its LEF cut layer must be TYPE CUT)"
        ))),
    }
}

// Coordinates past 2^31 are refused as read; the sums a placement makes
// stay within i64.
const _: () = assert!(MAX_COORD < (1 << 40));
