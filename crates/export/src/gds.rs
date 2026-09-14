//! GDSII writer.
//!
//! Two uses, and the second is why it matters more than it looks.
//!
//! The obvious one is writing marker layers: a violation's geometry as shapes a
//! layout viewer can display over the design.
//!
//! The other is that it closes the round trip. `parse → write → parse` being
//! the identity on the store is one of the strongest laws available to test
//! `ingest` with, and it needs a writer to state. That law does not depend on
//! either implementation being right in any absolute sense — which is exactly
//! the property this project's oracles are chosen for.

use crate::{narrow, WriteError};
use gpurify_core::{GeometryStore, LayerId, PolyId};
use gpurify_ingest::deck::LayerTable;
use gpurify_report::Violations;
use gpurify_units::Dbu;

// Record tags as they appear on the wire — `(record type << 8) | data type`.
// The same spelling as `ingest::layout::gds`, which is the reader for these
// bytes and the only consumer that has to agree with them exactly.
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

/// The library and structure modification/access times, as twelve `i16`.
///
/// Zero, and that is the point: neither `write_store` nor `write_markers` takes
/// a [`crate::Header`], so the header record is the one place in this crate
/// where the clock could leak in without a parameter to blame for it. A report
/// that differs from itself cannot be diffed against yesterday's.
const TIMESTAMPS: [u8; 24] = [0; 24];

/// A GDSII coordinate is a signed 32-bit database unit.
///
/// `Dbu` is an `i64` bounded by `MAX_ABS_DBU = 2^40`, so a perfectly legal
/// coordinate is up to 256 times wider than the field this format holds it in.
/// Truncating one moves geometry, and moving geometry moves verdicts, so the
/// bound is checked and the file refused. `i32::MIN` is excluded with it: a
/// domain symmetric about zero is one fewer edge case than a domain that is
/// not, and nothing needs the extra value.
const COORD_LIMIT: u64 = i32::MAX as u64;

/// Database units per user unit, and metres per database unit.
///
/// Fixed at a 1 nm grid, which is this workspace's own (`Grid::new(1000)`).
/// Not a shortcut and not upgradable from inside this file: no parameter of
/// either writer carries a `Grid`, and neither `GeometryStore` nor
/// `deck::LayerTable` holds one, so the physical scale simply is not reachable
/// here. Omitting `UNITS` is worse — the format requires it and every tool then
/// applies a default of its own choosing — so the workspace grid is written and
/// the mismatch is recorded rather than hidden.
///
/// Recorded in `docs/SIGNATURE_DEFECTS.md`, under `export::gds`.
/// `ingest`'s reader discards `UNITS`, so the
/// `parse -> write -> parse` law is unaffected; what a wrong grid costs is a
/// marker overlay that a viewer scales differently from the design it overlays.
const USER_UNITS_PER_DBU: f64 = 1e-3;
const METRES_PER_DBU: f64 = 1e-9;

/// The cell and library a marker file is written into.
const MARKER_CELL: &str = "MARKERS";

/// Write a store as a flat GDSII library.
///
/// **Transform.** Caller owns `out`, appended to.
///
/// Flat: the store has no hierarchy left, having been flattened at ingest, so
/// this writes one cell. Round-tripping therefore returns the flattened store,
/// not the original file — which is the identity the law actually claims, and
/// stating it precisely is what stops the test being wrong about what it proves.
///
/// Emits polygons in store order, which is grouped by layer and canonical.
pub fn write_store(
    store: &GeometryStore,
    layers: &LayerTable,
    cell_name: &str,
    out: &mut Vec<u8>,
) -> Result<(), WriteError> {
    // Both the library and the structure are named by this one string, so an
    // empty one produces a file whose only cell cannot be referenced. `put_ascii`
    // would write the zero-length record without complaint.
    debug_assert!(!cell_name.is_empty(), "a GDSII cell has a name");

    let start = out.len();
    put_library_head(out, cell_name)?;
    put_record(out, BGNSTR, &TIMESTAMPS)?;
    put_ascii(out, STRNAME, cell_name)?;

    let rows = narrow(store.poly_count());
    let mut payload = Vec::new();

    // Walked by layer range rather than by row. The store is CSR-grouped by
    // `LayerId` and `layer_start` runs monotonically from zero to the row
    // count, so walking the ranges in layer order walks the rows in store
    // order — the emitted byte sequence is unchanged. What changes is that the
    // stream pair is now a uniform hoisted above one layer's whole range
    // instead of a `stream_of` call per polygon, and the deck check below runs
    // once per layer instead of once per row.
    let mut emitted = 0u32;
    // Rows deliberately not written, so the coverage assert below can still say
    // "every row was accounted for" rather than being weakened to an
    // inequality that a genuinely dropped polygon would also satisfy.
    let mut skipped = 0u32;
    for layer in 0..store.layer_count() {
        let layer = LayerId(u16::try_from(layer).expect("LayerId is a u16, so is the layer count"));
        let range = store.polys_on_layer(layer);
        // Not a data-dependent branch on bulk data: this is the outer,
        // per-layer loop, and most of a PDK's layer table is empty in any given
        // run so it predicts on the common side.
        if range.is_empty() {
            continue;
        }
        // A derived layer is the deck's own arithmetic over geometry this file
        // already carries — `diff_active` is `diff NOT poly`, and both operands
        // are written above. Emitting it too would put the same area in the
        // file twice, and a reader that took it at face value would see a
        // conductor where the deck says there is none.
        //
        // It is also unrepresentable. `ingest::deck` keeps derived layers out of
        // `by_stream` precisely so `of_stream` can never map a GDS record onto
        // one, and `stream_of` has no pair to answer with — so a file written
        // with them cannot be read back, and would fail closed on
        // `UnknownLayer` rather than round-trip.
        //
        // Same outer-loop argument as the emptiness test above: per layer, not
        // per row, and uniform across a run.
        if layers.is_derived(layer) {
            skipped += range.end - range.start;
            continue;
        }
        // Fail closed. A store row on a layer the deck's table never declared
        // has no stream pair, and inventing one would put geometry on a layer
        // nobody is watching. Guarded by the emptiness test above so that a
        // store reserving more layers than the deck declares is refused only
        // when that actually loses geometry — the same row set the per-row form
        // rejected, and no more.
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

/// Write violation markers as geometry.
///
/// One shape per violation on a per-rule marker layer, so a viewer can toggle
/// rules independently. Marker layer numbers come from the caller rather than
/// being invented here, because they have to agree with whatever the viewer is
/// configured to show.
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
    // Fail closed, hoisted above the emission loop and above the first byte
    // written: a violation naming a row the store does not hold has no
    // geometry, and an empty marker for it would read as a violation nobody can
    // find. An OR-fold over the column rather than a test per row, so the bulk
    // pass carries no branch at all and the one that survives is over a scalar
    // — the same shape `put_boundary` uses for its coordinate bound. Folded as
    // a `bool` rather than as a maximum because a maximum cannot tell an empty
    // violation table from one naming row zero of an empty store.
    //
    // `|=`, never `||`: the short-circuit is a data-dependent branch on every
    // row, and both sides are one compare.
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
    // A whole library rather than a bare cell: a marker file is opened as an
    // overlay in its own right, and a caller writing markers into the same
    // buffer as a design would be concatenating two libraries whatever this
    // emitted, since a readable library has to close with ENDLIB.
    put_library_head(out, MARKER_CELL)?;
    put_record(out, BGNSTR, &TIMESTAMPS)?;
    put_ascii(out, STRNAME, MARKER_CELL)?;

    let mut payload = Vec::new();
    // Every branch that was over the violation column has been lifted into the
    // OR-fold above, so what is left here is a straight walk.
    //
    // Iterated in the order the table holds, never sorted: if the order is
    // wrong it is wrong at the source, and fixing it here would hide that.
    //
    // The per-rule split the doc comment names is the caller's: one layer
    // number reaches this call, so a caller wanting one layer per rule calls
    // once per rule. Datatype 0 for all of them.
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

/// One `BOUNDARY` element: the stream pair, the closed outline, and `ENDEL`.
///
/// `payload` is caller-owned scratch, so a store of a million polygons makes
/// one allocation rather than a million.
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

    // A max-magnitude reduction rather than a test per vertex, so the bound
    // check itself carries no branch and the one that survives is over a
    // scalar. Same shape as `ingest::layout::gds::Flatten::emit`, which is the
    // reader-side half of the same claim.
    //
    // Zipped rather than indexed by `0..xs.len()`: the column-length equality
    // is a `debug_assert` above, so in release LLVM has nothing to elide the
    // second column's bounds check with, and `zip` carries the shorter length
    // as the trip count for free. `max` on `u64` is a select, not a branch.
    let mut worst = 0u64;
    for (x, y) in xs.iter().zip(ys) {
        worst = worst.max(x.raw().unsigned_abs()).max(y.raw().unsigned_abs());
    }
    if worst > COORD_LIMIT {
        return Err(WriteError::Unrepresentable(
            "a coordinate wider than a GDSII 32-bit database unit",
        ));
    }

    // `+ 1` for the repeated first point pushed below, so a polygon of any size
    // costs this scratch buffer at most one growth on its first use and none
    // after.
    payload.clear();
    payload.reserve(xs.len() + 1);
    for (&x, &y) in xs.iter().zip(ys) {
        payload.push(pack((x, y)));
    }
    debug_assert_eq!(payload.len(), xs.len(), "a vertex was dropped on the way out");
    // GDSII repeats a boundary's first point as its last. The store does not
    // hold that point and `ingest`'s reader drops it again, which is what makes
    // `parse -> write -> parse` the identity rather than a slow growth of one
    // vertex per trip.
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
///
/// The padding is the case a writer gets wrong once and then every reader
/// misparses the file from that point on, which is why the odd-length cell name
/// is the one the test names.
fn put_ascii(out: &mut Vec<u8>, tag: u16, text: &str) -> Result<(), WriteError> {
    // Not a bulk loop: two names per library. `is_ascii` is where a UTF-8 cell
    // name is refused rather than written as bytes no reader can resolve.
    if !text.is_ascii() {
        return Err(WriteError::Unrepresentable("a name outside ASCII"));
    }
    let padding = text.len() % 2;
    put_head(out, tag, text.len() + padding)?;
    out.extend_from_slice(text.as_bytes());
    out.resize(out.len() + padding, 0);
    Ok(())
}

/// An eight-byte GDSII real: sign, a seven-bit excess-64 base-sixteen exponent,
/// and a fifty-six-bit fraction, so the value is
/// `± fraction / 2^56 · 16^(exponent − 64)`.
///
/// The inverse of `ingest::layout::gds::real`. Called twice per library, on two
/// constants, so the normalising loops walk the exponent rather than any data.
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
