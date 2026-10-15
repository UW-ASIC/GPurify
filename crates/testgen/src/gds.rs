//! GDSII writer: the other half of `parse -> write -> parse`, for test layouts.
//! An error names what the format cannot represent.
//!
//! Data in: a flattened [`GeometryStore`] and the deck's [`LayerTable`], or a
//! hierarchy of [`Structure`]s. Data out: a GDSII library (one cell for a
//! store) on a 1 nm grid: `UNITS` says 0.001 user units
//! (µm) and 1e-9 m per database unit, and every coordinate is written as the
//! integer it is. A store built on a coarser grid reads back as 1 nm, so
//! build test geometry in nanometres. Timestamps are zero, so the bytes are
//! reproducible.

use gpurify_geom::ops::area2;
use gpurify_geom::Dbu;
use gpurify_geom::{GeometryStore, LayerId, PolyId};
use gpurify_ingest::deck::LayerTable;

// Record tags as they appear on the wire — `(record type << 8) | data type`.
const HEADER: u16 = 0x0002;
const BGNLIB: u16 = 0x0102;
const LIBNAME: u16 = 0x0206;
const UNITS: u16 = 0x0305;
const ENDLIB: u16 = 0x0400;
const BGNSTR: u16 = 0x0502;
const STRNAME: u16 = 0x0606;
const ENDSTR: u16 = 0x0700;
const BOUNDARY: u16 = 0x0800;
const LAYER: u16 = 0x0D02;
const DATATYPE: u16 = 0x0E02;
const XY: u16 = 0x1003;
const ENDEL: u16 = 0x1100;
const TEXT: u16 = 0x0C00;
const TEXTTYPE: u16 = 0x1602;
const STRING: u16 = 0x1906;
const SREF: u16 = 0x0A00;
const AREF: u16 = 0x0B00;
const SNAME: u16 = 0x1206;
const COLROW: u16 = 0x1302;
const STRANS: u16 = 0x1A01;
const MAG: u16 = 0x1B05;
const ANGLE: u16 = 0x1C05;

/// `STRANS` bit 0 (MSB first): reflect about the x axis before rotating.
const STRANS_REFLECT: u16 = 0x8000;

/// Stream format 6.0, the version every reader since 1987 accepts.
const VERSION: u16 = 600;

/// Library and structure times: zero, never the clock, so output is reproducible.
const TIMESTAMPS: [u8; 24] = [0; 24];

/// A GDSII coordinate is a signed 32-bit database unit; a wider one is refused,
/// never truncated. `i32::MIN` is excluded with it.
const COORD_LIMIT: u64 = i32::MAX as u64;

/// User units (µm) per database unit, and metres per database unit.
///
/// Fixed at a 1 nm grid: the writer is handed no `Grid`.
const USER_UNITS_PER_DBU: f64 = 1e-3;
const METRES_PER_DBU: f64 = 1e-9;

/// Write a store as a flat GDSII library, appended to `out`.
///
/// One cell, named `cell_name`: the store was flattened at ingest, so a round
/// trip returns the flattened store and not the original file. Polygons go
/// out in store order, each as a `BOUNDARY` on its layer's stream pair from
/// `layers`; a clockwise row is a hole of the outer row before it, the order
/// the reader stores a keyhole in, and goes out inside that outer's keyhole.
/// Shapes on a derived layer are skipped: they are the deck's arithmetic over
/// geometry already in the file. On error, `out` holds a partial library and
/// must be discarded.
///
/// # Errors
///
/// A static message naming what GDSII cannot carry: `cell_name` outside
/// ASCII, a polygon with fewer than three vertices, a coordinate beyond
/// `i32::MAX` in magnitude, a polygon (a keyhole with its slits) too long for
/// one record (over 8190 vertices), a hole first on its layer, or a shape on
/// a layer `layers` does not declare.
pub fn write_store(
    store: &GeometryStore,
    layers: &LayerTable,
    cell_name: &str,
    out: &mut Vec<u8>,
) -> Result<(), &'static str> {
    write_store_labelled(store, layers, &[], cell_name, out)
}

/// One text label for [`write_store_labelled`]: a `TEXT` element on a base
/// layer's stream pair, at a point in database units.
#[derive(Debug, Clone, Copy)]
pub struct Label<'a> {
    /// The label layer; written on its stream pair as layer and texttype.
    pub layer: LayerId,
    /// Where the text sits, in database units.
    pub x: i64,
    /// Where the text sits, in database units.
    pub y: i64,
    /// The net name it states. ASCII only.
    pub text: &'a str,
}

/// [`write_store`], plus one `TEXT` element per label after the polygons, so a
/// test layout can name its nets the way a drawn one does and the labels go
/// through the reader like any layout's.
///
/// # Errors
///
/// As [`write_store`], and also a label on a derived or undeclared layer, a
/// label coordinate beyond `i32::MAX` in magnitude, or label text outside ASCII.
pub fn write_store_labelled(
    store: &GeometryStore,
    layers: &LayerTable,
    labels: &[Label<'_>],
    cell_name: &str,
    out: &mut Vec<u8>,
) -> Result<(), &'static str> {
    put_library_head(out, cell_name)?;
    put_record(out, BGNSTR, &TIMESTAMPS)?;
    put_ascii(out, STRNAME, cell_name)?;

    let mut payload = Vec::new();
    for layer in 0..store.layer_count() {
        let layer = LayerId(u16::try_from(layer).expect("LayerId is a u16, so is the layer count"));
        let range = store.polys_on_layer(layer);
        if range.is_empty() {
            continue;
        }
        // A derived layer is the deck's arithmetic over geometry already in
        // this file, and has no stream pair to be written or read back with.
        if layers.is_derived(layer) {
            continue;
        }
        // Fail closed: a row on a layer the deck never declared has no stream
        // pair, and inventing one puts geometry on a layer nobody is watching.
        if layer.idx() >= layers.len() {
            return Err("a layer the deck's table does not declare");
        }
        let (number, datatype) = layers.stream_of(layer);
        let mut row = range.start;
        while row < range.end {
            let (xs, ys) = store.poly_verts(PolyId(row));
            if area2(xs, ys).raw() < 0 {
                return Err("a hole with no outer row before it");
            }
            // A clockwise row is a hole of the outer before it, as the reader
            // stores a keyhole: written back as one keyhole with that outer.
            let holes = row + 1;
            row = holes;
            while row < range.end && {
                let (hx, hy) = store.poly_verts(PolyId(row));
                area2(hx, hy).raw() < 0
            } {
                row += 1;
            }
            if holes == row {
                put_boundary(out, &mut payload, number, datatype, xs, ys)?;
            } else {
                let (kx, ky) = keyhole(store, holes - 1..row);
                put_boundary(out, &mut payload, number, datatype, &kx, &ky)?;
            }
        }
    }
    for label in labels {
        if label.layer.idx() >= layers.len() || layers.is_derived(label.layer) {
            return Err("a label on a layer the deck's table does not declare as drawn");
        }
        let (number, texttype) = layers.stream_of(label.layer);
        let coordinate = |value: i64| {
            i32::try_from(value).map_err(|_| "a label coordinate beyond the GDSII range")
        };
        let at = (coordinate(label.x)?, coordinate(label.y)?);
        put_text(out, number, texttype, at, label.text)?;
    }
    put_record(out, ENDSTR, &[])?;
    put_record(out, ENDLIB, &[])
}

/// One structure for [`write_library`]: its rectangles, its placements,
/// then its texts.
#[derive(Debug, Clone, Default)]
pub struct Structure {
    /// The structure's name. ASCII only.
    pub name: String,
    /// `(layer, datatype, [xlo, ylo, xhi, yhi])`, each a counter-clockwise
    /// `BOUNDARY`.
    pub rects: Vec<(u16, u16, [i32; 4])>,
    /// Each an `SREF`, or an `AREF` when it is an array.
    pub refs: Vec<Placement>,
    /// `(layer, texttype, x, y, text)`, each a `TEXT` after the placements.
    /// ASCII only.
    pub texts: Vec<(u16, u16, i32, i32, String)>,
}

/// One `SREF` or `AREF` in a [`Structure`].
#[derive(Debug, Clone)]
pub struct Placement {
    /// The placed structure's name. ASCII only.
    pub cell: String,
    /// Reflect about the x axis before rotating (`STRANS` bit 0).
    pub reflect: bool,
    /// Counter-clockwise quarter turns, written as an `ANGLE` in degrees.
    pub quarter_turns: u8,
    /// Whole magnification; 1 writes no `MAG`.
    pub mag: u32,
    /// Where the child's origin lands; for an array, its first element's.
    pub at: (i32, i32),
    /// The lattice of an `AREF`; `None` for an `SREF`.
    pub array: Option<Array>,
}

/// An `AREF`'s lattice, in the parent's frame as the format states it.
#[derive(Debug, Clone, Copy)]
pub struct Array {
    /// Copies along the column step; positive.
    pub cols: u16,
    /// Copies along the row step; positive.
    pub rows: u16,
    /// From one column to the next.
    pub col_step: (i32, i32),
    /// From one row to the next.
    pub row_step: (i32, i32),
}

/// Write `cells` as one GDSII library, in order, on the 1 nm grid
/// [`write_store`] uses: the hierarchical half of a `write -> parse` test, for
/// the reader's placement, array and cycle handling. Nothing is checked
/// against the hierarchy: a placement may name any structure, defined or not,
/// itself included. On error, `out` holds a partial library.
///
/// # Errors
///
/// A name outside ASCII, an array with a zero count or whose far corner
/// leaves the 32-bit coordinate range, or a record over 64 KiB.
pub fn write_library(cells: &[Structure], out: &mut Vec<u8>) -> Result<(), &'static str> {
    put_library_head(out, "LIB")?;
    for cell in cells {
        put_record(out, BGNSTR, &TIMESTAMPS)?;
        put_ascii(out, STRNAME, &cell.name)?;
        for &(layer, datatype, [xlo, ylo, xhi, yhi]) in &cell.rects {
            let ring = [(xlo, ylo), (xhi, ylo), (xhi, yhi), (xlo, yhi), (xlo, ylo)];
            put_record(out, BOUNDARY, &[])?;
            put_record(out, LAYER, &layer.to_be_bytes())?;
            put_record(out, DATATYPE, &datatype.to_be_bytes())?;
            put_record(out, XY, &xy(&ring))?;
            put_record(out, ENDEL, &[])?;
        }
        for placement in &cell.refs {
            put_placement(out, placement)?;
        }
        for &(layer, texttype, x, y, ref text) in &cell.texts {
            put_text(out, layer, texttype, (x, y), text)?;
        }
        put_record(out, ENDSTR, &[])?;
    }
    put_record(out, ENDLIB, &[])
}

/// One `SREF` or `AREF`, in the format's record order.
fn put_placement(out: &mut Vec<u8>, placement: &Placement) -> Result<(), &'static str> {
    let mut points = vec![placement.at];
    if let Some(Array {
        cols,
        rows,
        col_step,
        row_step,
    }) = placement.array
    {
        if cols == 0 || rows == 0 {
            return Err("an array with a zero count");
        }
        let far = |n: u16, step: (i32, i32)| -> Result<(i32, i32), &'static str> {
            let reach = |origin: i32, step: i32| {
                i32::try_from(i64::from(origin) + i64::from(n) * i64::from(step))
                    .map_err(|_| "an array corner beyond the GDSII range")
            };
            Ok((
                reach(placement.at.0, step.0)?,
                reach(placement.at.1, step.1)?,
            ))
        };
        points.push(far(cols, col_step)?);
        points.push(far(rows, row_step)?);
    }
    let array = placement.array.is_some();
    put_record(out, if array { AREF } else { SREF }, &[])?;
    put_ascii(out, SNAME, &placement.cell)?;
    let turns = placement.quarter_turns % 4;
    if placement.reflect || placement.mag != 1 || turns != 0 {
        let flags = if placement.reflect { STRANS_REFLECT } else { 0 };
        put_record(out, STRANS, &flags.to_be_bytes())?;
        if placement.mag != 1 {
            put_record(out, MAG, &real8(f64::from(placement.mag)))?;
        }
        if turns != 0 {
            put_record(out, ANGLE, &real8(f64::from(turns) * 90.0))?;
        }
    }
    if let Some(Array { cols, rows, .. }) = placement.array {
        let mut colrow = [0u8; 4];
        colrow[..2].copy_from_slice(&cols.to_be_bytes());
        colrow[2..].copy_from_slice(&rows.to_be_bytes());
        put_record(out, COLROW, &colrow)?;
    }
    put_record(out, XY, &xy(&points))?;
    put_record(out, ENDEL, &[])
}

/// One `TEXT` element: the stream pair, the point, and the string.
fn put_text(
    out: &mut Vec<u8>,
    layer: u16,
    texttype: u16,
    at: (i32, i32),
    text: &str,
) -> Result<(), &'static str> {
    put_record(out, TEXT, &[])?;
    put_record(out, LAYER, &layer.to_be_bytes())?;
    put_record(out, TEXTTYPE, &texttype.to_be_bytes())?;
    put_record(out, XY, &xy(&[at]))?;
    put_ascii(out, STRING, text)?;
    put_record(out, ENDEL, &[])
}

/// An `XY` payload: each point as two big-endian 32-bit database units.
fn xy(points: &[(i32, i32)]) -> Vec<u8> {
    points
        .iter()
        .flat_map(|&(x, y)| x.to_be_bytes().into_iter().chain(y.to_be_bytes()))
        .collect()
}

// ----------------------------------------------------------------- the format

/// `HEADER`, `BGNLIB`, `LIBNAME` and `UNITS` — everything before the first cell.
fn put_library_head(out: &mut Vec<u8>, name: &str) -> Result<(), &'static str> {
    put_record(out, HEADER, &VERSION.to_be_bytes())?;
    put_record(out, BGNLIB, &TIMESTAMPS)?;
    put_ascii(out, LIBNAME, name)?;

    let mut units = [0u8; 16];
    units[..8].copy_from_slice(&real8(USER_UNITS_PER_DBU));
    units[8..].copy_from_slice(&real8(METRES_PER_DBU));
    put_record(out, UNITS, &units)
}

/// The rows `rows`, an outer then its clockwise holes, as one GDSII keyhole
/// ring: the outer, then from its first vertex an axis-aligned slit out to
/// each hole's first vertex, around the hole and back along the same slit.
/// Each slit is drawn both ways, so it encloses nothing, and the reader's
/// keyhole split (`geom::boolean::canonical_rings_into`) gives back the
/// outer and the holes, which is why the slits must be rectilinear.
fn keyhole(store: &GeometryStore, rows: std::ops::Range<u32>) -> (Vec<Dbu>, Vec<Dbu>) {
    let (mut kx, mut ky) = (Vec::new(), Vec::new());
    let mut go = |x: Dbu, y: Dbu| {
        if kx.last() != Some(&x) || ky.last() != Some(&y) {
            kx.push(x);
            ky.push(y);
        }
    };
    let (ox, oy) = store.poly_verts(PolyId(rows.start));
    for (&x, &y) in ox.iter().zip(oy) {
        go(x, y);
    }
    let (x0, y0) = (ox[0], oy[0]);
    for hole in rows.start + 1..rows.end {
        let (hx, hy) = store.poly_verts(PolyId(hole));
        go(x0, y0);
        go(hx[0], y0);
        for (&x, &y) in hx.iter().zip(hy) {
            go(x, y);
        }
        go(hx[0], hy[0]);
        go(hx[0], y0);
    }
    (kx, ky)
}

/// One `BOUNDARY` element — the stream pair, the closed outline, and `ENDEL`.
/// `payload` is caller-owned scratch, reused across polygons.
fn put_boundary(
    out: &mut Vec<u8>,
    payload: &mut Vec<[u8; 8]>,
    layer: u16,
    datatype: u16,
    xs: &[Dbu],
    ys: &[Dbu],
) -> Result<(), &'static str> {
    if xs.len() < 3 {
        return Err("a boundary with fewer than three vertices");
    }

    let mut worst = 0u64;
    for (x, y) in xs.iter().zip(ys) {
        worst = worst
            .max(x.raw().unsigned_abs())
            .max(y.raw().unsigned_abs());
    }
    if worst > COORD_LIMIT {
        return Err("a coordinate wider than a GDSII 32-bit database unit");
    }

    payload.clear();
    payload.reserve(xs.len() + 1);
    for (&x, &y) in xs.iter().zip(ys) {
        payload.push(pack((x, y)));
    }
    // GDSII repeats a boundary's first point as its last. The store holds no
    // such point and `ingest`'s reader drops it again, which is what keeps
    // `parse -> write -> parse` from growing a vertex per trip.
    let first = payload[0];
    payload.push(first);

    put_record(out, BOUNDARY, &[])?;
    put_record(out, LAYER, &layer.to_be_bytes())?;
    put_record(out, DATATYPE, &datatype.to_be_bytes())?;
    put_record(out, XY, payload.as_flattened())?;
    put_record(out, ENDEL, &[])
}

/// One `XY` point: two big-endian 32-bit database units.
#[allow(
    clippy::cast_possible_truncation,
    reason = "put_boundary bounds every coordinate to COORD_LIMIT before mapping"
)]
fn pack((x, y): (Dbu, Dbu)) -> [u8; 8] {
    let x = (x.raw() as i32).to_be_bytes();
    let y = (y.raw() as i32).to_be_bytes();
    [x[0], x[1], x[2], x[3], y[0], y[1], y[2], y[3]]
}

/// A record header: the total length including these four bytes, then the tag.
fn put_head(out: &mut Vec<u8>, tag: u16, payload_len: usize) -> Result<(), &'static str> {
    let len =
        u16::try_from(payload_len + 4).map_err(|_| "a GDSII record longer than 65535 bytes")?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&tag.to_be_bytes());
    Ok(())
}

fn put_record(out: &mut Vec<u8>, tag: u16, payload: &[u8]) -> Result<(), &'static str> {
    put_head(out, tag, payload.len())?;
    out.extend_from_slice(payload);
    Ok(())
}

/// A name record, padded to an even length with the NUL the format uses.
fn put_ascii(out: &mut Vec<u8>, tag: u16, text: &str) -> Result<(), &'static str> {
    // Refused rather than written as bytes no reader can resolve.
    if !text.is_ascii() {
        return Err("a name outside ASCII");
    }
    let padding = text.len() % 2;
    put_head(out, tag, text.len() + padding)?;
    out.extend_from_slice(text.as_bytes());
    out.resize(out.len() + padding, 0);
    Ok(())
}

/// An eight-byte GDSII real — sign, a seven-bit excess-64 base-sixteen exponent
/// and a fifty-six-bit fraction, so the value is
/// `± fraction / 2^56 · 16^(exponent − 64)`. The inverse of
/// `ingest::layout::gds::real`.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the fraction is bounded below 2^56 and the exponent to 0..=127 \
              by the normalisation above the casts"
)]
fn real8(value: f64) -> [u8; 8] {
    if value == 0.0 {
        return [0; 8];
    }
    let sign = u8::from(value < 0.0) << 7;
    let mut mantissa = value.abs();
    let mut exponent = 64i32;
    while mantissa >= 1.0 {
        mantissa /= 16.0;
        exponent += 1;
    }
    while mantissa < 1.0 / 16.0 {
        mantissa *= 16.0;
        exponent -= 1;
    }

    let fraction = (mantissa * 72_057_594_037_927_936.0).round();
    let mut out = (fraction as u64).to_be_bytes();
    out[0] = sign | exponent as u8;
    out
}
