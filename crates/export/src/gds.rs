//! GDSII writer: marker layers, and the other half of `parse -> write -> parse`.

use crate::{narrow, WriteError};
use gpurify_geom::{GeometryStore, LayerId, PolyId};
use gpurify_ingest::deck::LayerTable;
use gpurify_report::Violations;
use gpurify_geom::Dbu;

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

/// Stream format 6.0, the version every reader since 1987 accepts.
const VERSION: u16 = 600;

/// The library and structure modification/access times, as twelve `i16` — zero,
/// never the clock, because a report that differs from itself cannot be diffed.
const TIMESTAMPS: [u8; 24] = [0; 24];

/// A GDSII coordinate is a signed 32-bit database unit.
///
/// `Dbu` is an `i64` bounded by `MAX_ABS_DBU = 2^40`, 256 times wider than this
/// field, and truncating one moves geometry, so the bound is checked and the
/// file refused. `i32::MIN` is excluded with it.
const COORD_LIMIT: u64 = i32::MAX as u64;

/// Database units per user unit, and metres per database unit.
///
/// Fixed at the workspace's 1 nm grid: no parameter of either writer carries a
/// `Grid`, and omitting `UNITS` would let every tool apply a default of its own.
const USER_UNITS_PER_DBU: f64 = 1e-3;
const METRES_PER_DBU: f64 = 1e-9;

/// The cell and library a marker file is written into.
const MARKER_CELL: &str = "MARKERS";

/// Write a store as a flat GDSII library, appended to `out`.
///
/// One cell: the store was flattened at ingest, so a round trip returns the
/// flattened store and not the original file. Polygons go out in store order.
pub fn write_store(
    store: &GeometryStore,
    layers: &LayerTable,
    cell_name: &str,
    out: &mut Vec<u8>,
) -> Result<(), WriteError> {
    debug_assert!(!cell_name.is_empty(), "a GDSII cell has a name");

    let start = out.len();
    put_library_head(out, cell_name)?;
    put_record(out, BGNSTR, &TIMESTAMPS)?;
    put_ascii(out, STRNAME, cell_name)?;

    let rows = narrow(store.poly_count());
    let mut payload = Vec::new();

    // Walked by layer range: the store is CSR-grouped, so layer order is row
    // order.
    let mut emitted = 0u32;
    // Skipped deliberately, so the assert below stays an equality.
    let mut skipped = 0u32;
    for layer in 0..store.layer_count() {
        let layer = LayerId(u16::try_from(layer).expect("LayerId is a u16, so is the layer count"));
        let range = store.polys_on_layer(layer);
        if range.is_empty() {
            continue;
        }
        // A derived layer is the deck's arithmetic over geometry already in
        // this file, and has no stream pair to be written or read back with.
        if layers.is_derived(layer) {
            skipped += range.end - range.start;
            continue;
        }
        // Fail closed: a row on a layer the deck never declared has no stream
        // pair, and inventing one puts geometry on a layer nobody is watching.
        // Guarded by the emptiness test above, so a store reserving more layers
        // than the deck declares is refused only when that loses geometry.
        if layer.idx() >= layers.len() {
            return Err(WriteError::Unrepresentable(
                "a layer the deck's table does not declare",
            ));
        }
        let (number, datatype) = layers.stream_of(layer);
        emitted += range.end - range.start;
        for row in range {
            let (xs, ys) = store.poly_verts(PolyId(row));
            put_boundary(out, &mut payload, number, datatype, xs, ys)?;
        }
    }
    debug_assert_eq!(
        emitted + skipped,
        rows,
        "the layer ranges do not cover the store, so a polygon was neither \
         written nor deliberately skipped"
    );

    put_record(out, ENDSTR, &[])?;
    put_record(out, ENDLIB, &[])?;
    debug_assert_eq!(
        (out.len() - start) % 2,
        0,
        "a GDSII record was emitted without its pad byte"
    );
    Ok(())
}

/// Write violation markers as geometry, one shape per violation.
///
/// The marker layer number comes from the caller; a caller wanting one layer per
/// rule calls once per rule.
pub fn write_markers(
    violations: &Violations,
    store: &GeometryStore,
    marker_layer: LayerId,
    out: &mut Vec<u8>,
) -> Result<(), WriteError> {
    debug_assert_eq!(
        violations.shape_a.len(),
        violations.len(),
        "the violation columns diverged"
    );

    let rows = narrow(store.poly_count());
    // Fail closed, above the first byte written: a violation naming a row the
    // store does not hold would produce a marker nobody can find.
    let mut out_of_range = false;
    for &poly in &violations.shape_a {
        out_of_range |= poly.0 >= rows;
    }
    if out_of_range {
        return Err(WriteError::Unrepresentable(
            "a violation naming a shape the store does not hold",
        ));
    }

    let start = out.len();
    put_library_head(out, MARKER_CELL)?;
    put_record(out, BGNSTR, &TIMESTAMPS)?;
    put_ascii(out, STRNAME, MARKER_CELL)?;

    let mut payload = Vec::new();
    for &poly in &violations.shape_a {
        debug_assert!(poly.0 < rows, "the bound check above let a stale row past");
        let (xs, ys) = store.poly_verts(poly);
        put_boundary(out, &mut payload, marker_layer.0, 0, xs, ys)?;
    }

    put_record(out, ENDSTR, &[])?;
    put_record(out, ENDLIB, &[])?;
    debug_assert_eq!(
        (out.len() - start) % 2,
        0,
        "a GDSII record was emitted without its pad byte"
    );
    Ok(())
}

// ----------------------------------------------------------------- the format

/// `HEADER`, `BGNLIB`, `LIBNAME` and `UNITS` — everything before the first cell.
fn put_library_head(out: &mut Vec<u8>, name: &str) -> Result<(), WriteError> {
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
) -> Result<(), WriteError> {
    debug_assert_eq!(xs.len(), ys.len(), "the coordinate columns diverged");
    if xs.len() < 3 {
        return Err(WriteError::Unrepresentable(
            "a boundary with fewer than three vertices",
        ));
    }

    let mut worst = 0u64;
    for (x, y) in xs.iter().zip(ys) {
        worst = worst
            .max(x.raw().unsigned_abs())
            .max(y.raw().unsigned_abs());
    }
    if worst > COORD_LIMIT {
        return Err(WriteError::Unrepresentable(
            "a coordinate wider than a GDSII 32-bit database unit",
        ));
    }

    payload.clear();
    payload.reserve(xs.len() + 1);
    for (&x, &y) in xs.iter().zip(ys) {
        payload.push(pack((x, y)));
    }
    debug_assert_eq!(
        payload.len(),
        xs.len(),
        "a vertex was dropped on the way out"
    );
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
fn put_head(out: &mut Vec<u8>, tag: u16, payload_len: usize) -> Result<(), WriteError> {
    let len = u16::try_from(payload_len + 4)
        .map_err(|_| WriteError::Unrepresentable("a GDSII record longer than 65535 bytes"))?;
    debug_assert_eq!(len % 2, 0, "a GDSII record is a whole number of words");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&tag.to_be_bytes());
    Ok(())
}

fn put_record(out: &mut Vec<u8>, tag: u16, payload: &[u8]) -> Result<(), WriteError> {
    put_head(out, tag, payload.len())?;
    out.extend_from_slice(payload);
    Ok(())
}

/// A name record, padded to an even length with the NUL the format uses.
fn put_ascii(out: &mut Vec<u8>, tag: u16, text: &str) -> Result<(), WriteError> {
    // Refused rather than written as bytes no reader can resolve.
    if !text.is_ascii() {
        return Err(WriteError::Unrepresentable("a name outside ASCII"));
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
    debug_assert!(value.is_finite(), "a GDSII real is a finite number");
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
    debug_assert!(
        (0..=127).contains(&exponent),
        "a GDSII real's exponent is seven bits excess sixty-four"
    );

    let fraction = (mantissa * 72_057_594_037_927_936.0).round();
    debug_assert!(
        (0.0..72_057_594_037_927_936.0).contains(&fraction),
        "a GDSII real's fraction is fifty-six bits"
    );
    let mut out = (fraction as u64).to_be_bytes();
    out[0] = sign | exponent as u8;
    out
}
