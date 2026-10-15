//! LEF and DEF: a placed-and-routed design as its library and its layout.
//!
//! Data in: LEF text (technology layers, vias, cell abstracts) and DEF text
//! (the design: die area, rows, tracks, components, pins, routed nets, fill).
//! Data out: [`Lef`] and [`Def`] as written, then [`flatten`]'s flat shapes
//! on LEF layer names, each with its net, and [`to_gds`]'s GDSII stream of
//! them on a deck's layers, which the GDS reader takes like any layout.
//!
//! The source is the *LEF/DEF 5.8 Language Reference* (Cadence, May 2017;
//! [lefdefref.pdf]). Only what a route-level extraction and an integration
//! check need is read; the rest of a statement or section is skipped by its
//! grammar, never guessed at:
//!
//! | File | Read | Skipped (no geometry, no connectivity) |
//! |---|---|---|
//! | LEF | `UNITS DATABASE MICRONS`, `MANUFACTURINGGRID`, `LAYER` (`TYPE`, `WIDTH`, `DIRECTION`, `PITCH`), `VIA` (fixed and `VIARULE`-generated), `SITE` (`SIZE`), `NONDEFAULTRULE` (`LAYER … WIDTH`), `MACRO` (`CLASS`, `ORIGIN`, `SIZE`, `PIN … PORT`, `OBS`: `LAYER`, `RECT`, `POLYGON`, `VIA`; the `LEF58_EDGETYPE` property), the library's `LEF58_CELLEDGESPACINGTABLE` property (in `PROPERTYDEFINITIONS` or a library `PROPERTY`) | every other statement: antenna, spacing, other properties, `VIARULE`, `SPACING` |
//! | DEF | `UNITS`, `DESIGN`, `DIEAREA`, `ROW`, `TRACKS`, `VIAS`, `NONDEFAULTRULES`, `COMPONENTS`, `PINS`, `NETS` and `SPECIALNETS` (connections, `ROUTED`/`FIXED`/`COVER`/`NOSHIELD` wiring, `RECT`, `POLYGON`, `VIA`, `NONDEFAULTRULE`), `FILLS` | `PROPERTYDEFINITIONS`, `REGIONS`, `GROUPS`, `SCANCHAINS`, `BLOCKAGES`, `GCELLGRID`, `HISTORY`, `BEGINEXT`, `PINPROPERTIES`, `SLOTS`, `STYLES`; per item: `SOURCE`, `WEIGHT`, `HALO`, `PROPERTY`, antenna data, `USE`, `DIRECTION` |
//!
//! Refused, with the line: a LEF `PATH` or `ITERATE` geometry, a wire
//! `STYLE` or a 45-degree segment, `SHIELD` wiring and a `SUBNET`, a
//! regular wire on a layer with no `WIDTH`, a name used before it is
//! defined, a length that is not a whole number of the DEF's database
//! units, and a coordinate past GDSII's 32-bit range. A layer's
//! `WIREEXTENSION` and a rule's `WIREEXT` are not read: a wire end takes
//! the DEF default below.
//!
//! # Geometry
//!
//! - A wire segment runs between two routing points, as wide as its rule
//!   (the LEF layer's `WIDTH`, the net's `NONDEFAULTRULE`, or a special
//!   wire's own width), each end extended past its point by the point's
//!   `extValue`, or by default half the width for a regular wire and 0 for
//!   a special wire (5.8 pp. 268, 321). A point's extension also starts the
//!   wire that leaves it on a via's other layer, as `OpenDB` reads it; each
//!   segment is its own rectangle, so a special wire turning a corner with
//!   no extension leaves the corner square undrawn (p. 321, and `OpenDB`;
//!   `KLayout` joins it).
//! - A component's macro is shifted by its `ORIGIN`, turned to its
//!   orientation, and placed so that the lower-left corner of its turned
//!   `SIZE` box lands on the placement point (pp. 244, 122). A pin's shapes,
//!   and a via in a wire, turn about their own placement point.
//! - Orientations are those of `OpenAccess`, as the reference maps them:
//!   `N` R0, `S` R180, `W` R90, `E` R270, `FN` MY, `FS` MX, `FW` MX then
//!   R90, `FE` MY then R90.
//! - A generated via's cut array is centred on the via origin; each metal
//!   is the array grown by its enclosure, moved by its `OFFSET`, and
//!   everything by `ORIGIN` (p. 341); a `PATTERN` leaves out the cuts it
//!   marks absent (pp. 349-351).
//!
//! [lefdefref.pdf]: https://coriolis.lip6.fr/doc/lefdef/lefdefref/lefdefref.pdf

mod def;
mod gds_out;
mod lef;
mod lex;

pub use def::{def_units, read_def, Component, Def, DefPin, Net, Row, Track, ViaAt, Wire};
pub use gds_out::to_gds;
pub use lef::{
    read_lef_into, CellEdgeSpacing, EdgeSide, EdgeSpan, EdgeType, LayerKind, Lef, LefLayer, Macro,
    MacroPin,
};

/// Why a LEF or DEF file could not be read, or its design not flattened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{file} line {line}: {message}")]
pub struct LefDefError {
    /// `"LEF"` or `"DEF"`, or `"design"` for a fault found while flattening.
    pub file: &'static str,
    /// The 1-based line of the token at fault; 0 when no line applies.
    pub line: u32,
    /// What is wrong.
    pub message: String,
}

/// A point in database units.
pub type Pt = (i64, i64);

/// A DEF and the LEF library it was read against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Design {
    /// The design.
    pub def: Def,
    /// Its technology and cell abstracts, in the DEF's units.
    pub lef: Lef,
}

/// A closed polygon on one layer, its ring without the repeated first
/// point, in database units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shape {
    /// The LEF layer name.
    pub layer: String,
    /// The vertices, in the order written (a rectangle counter-clockwise from
    /// its lower-left corner).
    pub ring: Vec<Pt>,
}

impl Shape {
    /// The rectangle with corners `a` and `b`, either order.
    pub fn rect(layer: &str, a: Pt, b: Pt) -> Self {
        let (x0, x1) = (a.0.min(b.0), a.0.max(b.0));
        let (y0, y1) = (a.1.min(b.1), a.1.max(b.1));
        Self {
            layer: layer.to_owned(),
            ring: vec![(x0, y0), (x1, y0), (x1, y1), (x0, y1)],
        }
    }

    /// The bounding box `(xlo, ylo, xhi, yhi)`.
    pub fn bbox(&self) -> (i64, i64, i64, i64) {
        self.ring.iter().fold(
            (i64::MAX, i64::MAX, i64::MIN, i64::MIN),
            |(a, b, c, d), &(x, y)| (a.min(x), b.min(y), c.max(x), d.max(y)),
        )
    }

    fn moved(&self, orient: Orient, at: Pt) -> Self {
        Self {
            layer: self.layer.clone(),
            ring: self
                .ring
                .iter()
                .map(|&p| {
                    let (x, y) = orient.apply(p);
                    (x + at.0, y + at.1)
                })
                .collect(),
        }
    }
}

/// A DEF orientation (5.8 p. 244).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Orient {
    /// North, R0.
    #[default]
    N,
    /// South, R180.
    S,
    /// West, R90.
    W,
    /// East, R270.
    E,
    /// Flipped north, MY.
    FN,
    /// Flipped south, MX.
    FS,
    /// Flipped west, MX then R90.
    FW,
    /// Flipped east, MY then R90.
    FE,
}

impl Orient {
    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "N" => Self::N,
            "S" => Self::S,
            "W" => Self::W,
            "E" => Self::E,
            "FN" => Self::FN,
            "FS" => Self::FS,
            "FW" => Self::FW,
            "FE" => Self::FE,
            _ => return None,
        })
    }

    /// The point turned about the origin, as `OpenAccess` (and `OpenDB`'s
    /// `dbTransform`) turns it: R90 takes `(x, y)` to `(−y, x)`.
    pub fn apply(self, (x, y): Pt) -> Pt {
        match self {
            Self::N => (x, y),
            Self::S => (-x, -y),
            Self::W => (-y, x),
            Self::E => (y, -x),
            Self::FN => (-x, y),
            Self::FS => (x, -y),
            Self::FW => (y, x),
            Self::FE => (-y, -x),
        }
    }
}

/// Where a flat shape came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A net's wiring: a wire, a via in it, or a net `RECT`/`POLYGON`.
    Route,
    /// A DEF pin's port, outside every component.
    Pin,
    /// A component's macro pin, by component index.
    MacroPin(u32),
    /// A component's macro obstruction, by component index.
    Obstruction(u32),
    /// A `FILLS` shape.
    Fill,
}

/// One shape of the flattened design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatShape {
    /// The shape, on a LEF layer.
    pub shape: Shape,
    /// The net it is on, by name; `None` for an obstruction, fill or an
    /// unconnected macro pin.
    pub net: Option<String>,
    /// What placed it.
    pub origin: Origin,
}

fn fault(file: &'static str, line: u32, message: impl Into<String>) -> LefDefError {
    LefDefError {
        file,
        line,
        message: message.into(),
    }
}

/// The geometry of the shapes a generated via (`VIARULE` form) makes, 5.8
/// p. 341: cut array centred on the origin, each metal the array grown by
/// its enclosure and moved by its offset, all moved by `origin`.
#[derive(Debug, Clone, Default)]
pub(crate) struct ViaRule {
    pub cut: (i64, i64),
    pub layers: [String; 3],
    pub spacing: (i64, i64),
    pub enclosure: [i64; 4],
    pub rowcol: (i64, i64),
    pub origin: Pt,
    pub offset: [i64; 4],
    /// `PATTERN`: which cuts of the array are drawn; empty for all.
    pub pattern: String,
}

impl ViaRule {
    /// Which cuts of the `rows × cols` array are drawn, row by row from the
    /// bottom, each left to right; `None` for a malformed `PATTERN`.
    ///
    /// 5.8 p. 342 and pp. 349-351: `numRows_rowDefinition` groups joined by
    /// `_`, from the bottom row up, `numRows` in hexadecimal; a row
    /// definition is hexadecimal digits of four cuts each, most significant
    /// bit leftmost, `R` then a repeat count then a digit standing for that
    /// digit repeated; bits past the row's cuts are ignored, and the rows
    /// must number `numCutRows`. A `_MR` or `_MC` suffix names a mask
    /// pattern only.
    pub(crate) fn cuts(&self) -> Option<Vec<bool>> {
        let (rows, cols) = (
            usize::try_from(self.rowcol.0).ok()?,
            usize::try_from(self.rowcol.1).ok()?,
        );
        if self.pattern.is_empty() {
            return Some(vec![true; rows * cols]);
        }
        let pattern = self
            .pattern
            .strip_suffix("_MR")
            .or_else(|| self.pattern.strip_suffix("_MC"))
            .unwrap_or(&self.pattern);
        let parts: Vec<&str> = pattern.split('_').collect();
        if !parts.len().is_multiple_of(2) {
            return None;
        }
        let mut out = Vec::with_capacity(rows * cols);
        for pair in parts.chunks(2) {
            let count = usize::from_str_radix(pair[0], 16).ok()?;
            let mut bits = Vec::new();
            let mut chars = pair[1].chars();
            while let Some(c) = chars.next() {
                let (times, digit) = if c == 'R' {
                    (chars.next()?.to_digit(16)?, chars.next()?.to_digit(16)?)
                } else {
                    (1, c.to_digit(16)?)
                };
                for _ in 0..times {
                    bits.extend((0..4).rev().map(|b| digit >> b & 1 == 1));
                }
            }
            if bits.len() < cols || out.len() + count.checked_mul(cols)? > rows * cols {
                return None;
            }
            for _ in 0..count {
                out.extend_from_slice(&bits[..cols]);
            }
        }
        (out.len() == rows * cols).then_some(out)
    }

    pub(crate) fn shapes(&self) -> Vec<Shape> {
        let (rows, cols) = self.rowcol;
        let width = cols * self.cut.0 + (cols - 1) * self.spacing.0;
        let height = rows * self.cut.1 + (rows - 1) * self.spacing.1;
        let (x0, y0) = (-width / 2, -height / 2);
        let (ox, oy) = self.origin;
        let [bx, by, tx, ty] = self.enclosure;
        let [bdx, bdy, tdx, tdy] = self.offset;
        let mut out = vec![
            Shape::rect(
                &self.layers[0],
                (x0 - bx + bdx + ox, y0 - by + bdy + oy),
                (x0 + width + bx + bdx + ox, y0 + height + by + bdy + oy),
            ),
            Shape::rect(
                &self.layers[2],
                (x0 - tx + tdx + ox, y0 - ty + tdy + oy),
                (x0 + width + tx + tdx + ox, y0 + height + ty + tdy + oy),
            ),
        ];
        let present = self.cuts().expect("a via rule is checked as read");
        for (k, &here) in present.iter().enumerate() {
            if !here {
                continue;
            }
            let k = i64::try_from(k).expect("at most 2^20 cuts");
            let (r, c) = (k / cols, k % cols);
            let x = x0 + c * (self.cut.0 + self.spacing.0) + ox;
            let y = y0 + r * (self.cut.1 + self.spacing.1) + oy;
            out.push(Shape::rect(
                &self.layers[1],
                (x, y),
                (x + self.cut.0, y + self.cut.1),
            ));
        }
        out
    }
}

/// The design flattened: every wire, via, pin, placed macro pin and
/// obstruction, and fill, on LEF layer names, in DEF order (pins, then
/// components, then nets, special nets first, then fills).
///
/// A component's macro pin takes the net a DEF net connects to it, `( comp
/// pin )` or `( * pin )`; an unplaced component has no shapes.
///
/// # Errors
///
/// A component of a macro no LEF defines, or a via no LEF or DEF defines.
pub fn flatten(def: &Def, lef: &Lef) -> Result<Vec<FlatShape>, LefDefError> {
    use std::collections::HashMap;
    let design = |message: String| fault("design", 0, message);
    let mut out = Vec::new();
    let via_shapes = |name: &str| -> Result<&[Shape], LefDefError> {
        def.vias
            .iter()
            .find(|(n, _)| n == name)
            .or_else(|| lef.vias.iter().find(|(n, _)| n == name))
            .map(|(_, shapes)| shapes.as_slice())
            .ok_or_else(|| design(format!("via {name} is defined in no LEF or DEF")))
    };
    let place_via = |via: &ViaAt, net: Option<&str>, origin, out: &mut Vec<FlatShape>| {
        let shapes = via_shapes(&via.name)?;
        for i in 0..via.array.0 {
            for j in 0..via.array.1 {
                let at = (via.at.0 + i * via.array.2, via.at.1 + j * via.array.3);
                for shape in shapes {
                    out.push(FlatShape {
                        shape: shape.moved(via.orient, at),
                        net: net.map(str::to_owned),
                        origin,
                    });
                }
            }
        }
        Ok::<(), LefDefError>(())
    };

    for pin in &def.pins {
        for shape in &pin.shapes {
            out.push(FlatShape {
                shape: shape.clone(),
                net: Some(pin.net.clone()),
                origin: Origin::Pin,
            });
        }
        for via in &pin.vias {
            place_via(via, Some(&pin.net), Origin::Pin, &mut out)?;
        }
    }

    // Which net each component pin is on; `( * pin )` binds every component.
    let mut pin_net: HashMap<(&str, &str), &str> = HashMap::new();
    let mut every_net: HashMap<&str, &str> = HashMap::new();
    for net in &def.nets {
        for (comp, pin) in &net.connections {
            if comp == "*" {
                every_net.insert(pin, &net.name);
            } else {
                pin_net.insert((comp, pin), &net.name);
            }
        }
    }
    for (index, comp) in def.components.iter().enumerate() {
        let Some((at, orient)) = comp.placement else {
            continue;
        };
        let index = u32::try_from(index).map_err(|_| design("too many components".into()))?;
        let model = lef
            .macros
            .iter()
            .find(|m| m.name == comp.model)
            .ok_or_else(|| {
                design(format!(
                    "component {} is a {}, which no LEF defines",
                    comp.name, comp.model
                ))
            })?;
        // Shifted by ORIGIN, turned, then moved so the turned SIZE box's
        // lower-left corner is the placement point.
        let (w, h) = model.size;
        let corners = [(0, 0), (w, h)].map(|p| orient.apply(p));
        let shift = (
            at.0 - corners[0].0.min(corners[1].0),
            at.1 - corners[0].1.min(corners[1].1),
        );
        let place = |shape: &Shape| {
            let shifted = shape.moved(Orient::N, model.origin);
            shifted.moved(orient, shift)
        };
        for pin in &model.pins {
            let net = pin_net
                .get(&(comp.name.as_str(), pin.name.as_str()))
                .or_else(|| every_net.get(pin.name.as_str()))
                .map(|n| (*n).to_owned());
            for shape in &pin.shapes {
                out.push(FlatShape {
                    shape: place(shape),
                    net: net.clone(),
                    origin: Origin::MacroPin(index),
                });
            }
            for (name, p) in &pin.vias {
                for shape in via_shapes(name)? {
                    out.push(FlatShape {
                        shape: place(&shape.moved(Orient::N, *p)),
                        net: net.clone(),
                        origin: Origin::MacroPin(index),
                    });
                }
            }
        }
        for shape in &model.obs {
            out.push(FlatShape {
                shape: place(shape),
                net: None,
                origin: Origin::Obstruction(index),
            });
        }
        for (name, p) in &model.obs_vias {
            for shape in via_shapes(name)? {
                out.push(FlatShape {
                    shape: place(&shape.moved(Orient::N, *p)),
                    net: None,
                    origin: Origin::Obstruction(index),
                });
            }
        }
    }

    let mut nets: Vec<&Net> = def.nets.iter().filter(|n| n.special).collect();
    nets.extend(def.nets.iter().filter(|n| !n.special));
    for net in nets {
        for wire in &net.wires {
            let (lo, hi) = wire.rect();
            // A special wire of width 0 carries only its vias.
            if lo.0 < hi.0 && lo.1 < hi.1 {
                out.push(FlatShape {
                    shape: Shape::rect(&wire.layer, lo, hi),
                    net: Some(net.name.clone()),
                    origin: Origin::Route,
                });
            }
        }
        for via in &net.vias {
            place_via(via, Some(&net.name), Origin::Route, &mut out)?;
        }
        for shape in &net.shapes {
            out.push(FlatShape {
                shape: shape.clone(),
                net: Some(net.name.clone()),
                origin: Origin::Route,
            });
        }
    }
    for shape in &def.fills {
        out.push(FlatShape {
            shape: shape.clone(),
            net: None,
            origin: Origin::Fill,
        });
    }
    for via in &def.fill_vias {
        place_via(via, None, Origin::Fill, &mut out)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
