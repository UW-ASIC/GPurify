//! GDSII writer: the other half of `parse -> write -> parse`, for test layouts.
//! An error names what the format cannot represent.
//!
//! Data in: a flattened [`GeometryStore`] and the deck's [`LayerTable`]. Data out:
//! a one-cell GDSII library on a 1 nm grid: `UNITS` says 0.001 user units
//! (µm) and 1e-9 m per database unit, and every coordinate is written as the
//! integer it is. A store built on a coarser grid reads back as 1 nm, so
//! build test geometry in nanometres. Timestamps are zero, so the bytes are
//! reproducible.

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
/// `layers`. Shapes on a derived layer are skipped: they are the deck's
/// arithmetic over geometry already in the file. On error, `out` holds a
/// partial library and must be discarded.
///
/// # Errors
///
/// A static message naming what GDSII cannot carry: `cell_name` outside
/// ASCII, a polygon with fewer than three vertices, a coordinate beyond
/// `i32::MAX` in magnitude, a polygon too long for one record (over 8190
/// vertices), or a shape on a layer `layers` does not declare.
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
        for row in range {
            let (xs, ys) = store.poly_verts(PolyId(row));
            put_boundary(out, &mut payload, number, datatype, xs, ys)?;
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
        let mut xy = [0u8; 8];
        xy[..4].copy_from_slice(&coordinate(label.x)?.to_be_bytes());
        xy[4..].copy_from_slice(&coordinate(label.y)?.to_be_bytes());
        put_record(out, TEXT, &[])?;
        put_record(out, LAYER, &number.to_be_bytes())?;
        put_record(out, TEXTTYPE, &texttype.to_be_bytes())?;
        put_record(out, XY, &xy)?;
        put_ascii(out, STRING, label.text)?;
        put_record(out, ENDEL, &[])?;
    }
    put_record(out, ENDSTR, &[])?;
    put_record(out, ENDLIB, &[])
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
