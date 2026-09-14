//! Layout readers: GDSII and OASIS.
//!
//! Both produce the same two outputs — a `GeometryStore` and a [`Provenance`] —
//! and share nothing else. They are different binary formats with different
//! record models, so there is no common reader trait: one implementation each,
//! and a single [`read_layout`] that dispatches on the file's magic.
//!
//! # Flattening
//!
//! Both formats are hierarchical; verification is flat. Flattening happens
//! here, during the read, so the store is built once rather than built and then
//! rewritten. Each emitted polygon records the instance path it came from, and
//! an unsupported transform (non-orthogonal rotation, non-integral
//! magnification) is an error, not an approximation.

use crate::deck::{Deck, DerivedOp, DerivedTable};
use crate::intern::StrTable;
use crate::provenance::{PathTable, Provenance};
use gpurify_core::boolean::{intersection_into, subtraction_into, union_into, BooleanError};
use gpurify_core::view::{validate_layer_into, ValidatedLayer};
use gpurify_core::GeometryStore;
use gpurify_units::Dbu;

/// Everything a verification run needs from a layout file.
#[derive(Debug, Default)]
pub struct Layout {
    pub store: GeometryStore,
    pub provenance: Provenance,
    pub strings: StrTable,
    /// Polygons the reader dropped because their stream pair is absent from the
    /// deck's layer table. Zero under [`UnknownLayers::Reject`], which refuses
    /// the file instead.
    ///
    /// Added in the Testing-Phase: `Drop` is documented as "never silent" and
    /// nothing in the reader's signature carried the count that claim is about,
    /// so a run against the wrong deck produced a smaller store and said
    /// nothing. A caller reporting a non-zero value here is what makes the
    /// difference between running a partial deck on purpose and running one by
    /// accident.
    pub dropped: u32,
}

/// Why a layout could not be read.
///
/// Every variant is a refusal, never a degradation. In particular
/// `UnsupportedTransform`: the old reader silently approximated some of these,
/// which moves geometry and therefore moves verdicts.
#[derive(Debug, Clone, thiserror::Error)]
pub enum LayoutError {
    #[error("unrecognised file format")]
    UnknownFormat,
    #[error("truncated record at byte {0}")]
    Truncated(u64),
    #[error("unsupported record type {0:#06x} at byte {1}")]
    UnsupportedRecord(u16, u64),
    #[error("coordinate {0} exceeds the representable range")]
    CoordinateOutOfRange(i64),
    #[error("instance transform is not representable exactly")]
    UnsupportedTransform,
    #[error("cell {0} is referenced but not defined")]
    MissingCell(String),
    #[error("cell hierarchy contains a cycle through {0}")]
    CyclicHierarchy(String),
    #[error("layer {0}/{1} is not in the deck's layer table")]
    UnknownLayer(u16, u16),
    /// A layer the deck computes from other layers could not be computed.
    ///
    /// Fail closed, and this is the shape that matters: the geometry underneath
    /// a derived layer is real, so the alternative to refusing is a layer that
    /// silently comes back empty — every conductor on it unconnected, every
    /// device terminal on it unbound, and a clean report over all of it.
    #[error("derived layer {0:?} could not be computed: {1}")]
    Derived(gpurify_core::LayerId, BooleanError),
    #[error("io: {0}")]
    Io(String),
}

/// How strictly to treat geometry the deck does not describe.
///
/// Not a correctness switch: both settings verify identically. It decides
/// whether a layer absent from the deck is an error or is dropped, which is the
/// difference between running a partial deck deliberately and running one by
/// accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownLayers {
    /// Reject. The default, and what a signoff run uses.
    Reject,
    /// Drop, and report how many rows were dropped in [`Layout::dropped`].
    /// Never silent.
    Drop,
}

/// Read a layout file, flatten it, and produce the store plus provenance.
///
/// **Transform, generative** — produces tables from a filename rather than from
/// a table. The deck is needed during the read, not after: layer mapping and
/// the grid resolution both affect what is emitted, and mapping afterwards
/// would mean holding raw layer numbers for every polygon.
///
/// This is the one function that applies the `GeometryStoreBuilder::finish`
/// permutation to the provenance columns.
pub fn read_layout(
    path: &std::path::Path,
    deck: &Deck,
    unknown: UnknownLayers,
) -> Result<Layout, LayoutError> {
    use std::io::{Read, Seek};

    let mut file = std::fs::File::open(path).map_err(|e| LayoutError::Io(e.to_string()))?;

    // Peek the gzip magic rather than asking a decoder: `MultiGzDecoder::new`
    // parses the first header eagerly, cannot fail, and has already pulled up
    // to 32 KiB into a `BufReader` you cannot get back.
    let mut magic = [0u8; 2];
    let peeked = file
        .read(&mut magic)
        .map_err(|e| LayoutError::Io(e.to_string()))?;
    file.rewind().map_err(|e| LayoutError::Io(e.to_string()))?;

    let mut bytes = Vec::new();
    if peeked == 2 && magic == [0x1f, 0x8b] {
        // `MultiGzDecoder`, never `GzDecoder`. A gzip file is a *series* of
        // members — `bgzip` and several EDA writers emit many — and `GzDecoder`
        // stops after the first with a clean `Ok(0)`. That is a silently
        // partial layout and a clean report over the die area that never
        // decoded, which is exactly the fail-open case this tree refuses.
        flate2::read::MultiGzDecoder::new(file)
            .read_to_end(&mut bytes)
            .map_err(|e| LayoutError::Io(e.to_string()))?;
    } else {
        file.read_to_end(&mut bytes)
            .map_err(|e| LayoutError::Io(e.to_string()))?;
    }

    // Detection runs on the decompressed bytes, and a failed decompression
    // above returned rather than falling through to "try it as GDSII": reading
    // compressed noise as records produces a plausible short layout.
    if gds::detect(&bytes) {
        gds::read(&bytes, deck, unknown)
    } else if oasis::detect(&bytes) {
        oasis::read(&bytes, deck, unknown)
    } else {
        Err(LayoutError::UnknownFormat)
    }
}

/// Compute every layer the deck derives and append it to the store.
///
/// **Transform, in-place.** Caller owns both tables. One row per derived layer
/// in `derived`, folded left over its operands, appended to `store` as real
/// polygons and matched one for one by a `Provenance` row so the two tables stay
/// the same length.
///
/// # Why the polygons go in the store
///
/// So that nothing downstream needs a second way to address geometry.
/// `topology::net` partitions store rows, `topology::port` binds a label to a
/// store row, `topology::device` binds a terminal to a store row, and a rule
/// reports a store row. A derived layer that lived beside the store instead
/// would have to be taught to all four, and `NetTable` in particular indexes
/// `poly_net` by [`gpurify_core::PolyId`] — there is no id a
/// `ValidatedLayer` polygon could offer it.
///
/// # Order
///
/// `derived` is ascending by id and a row may only name lower ids, so one
/// forward scan is enough: by the time a row is reached, every layer it folds
/// is already in the store. That is the whole of the dependency handling, and
/// it is why the deck needs no expression tree.
///
/// # Provenance
///
/// A derived polygon came from no instance, so its path is [`PathTable::ROOT`]
/// and it carries no stream properties. What a report needs to name a real
/// shape is on the geometry side: `core::view::PolygonRef::provenance` carries
/// the lowest contributing store row through the boolean.
///
/// # Holes
///
/// Rings are appended as they come out of the boolean — outer counter-clockwise,
/// holes clockwise — which is exactly the encoding `core::view::validate_layer_into`
/// reads back, so validating the derived layer reproduces the polygons the
/// boolean produced. It is also the same encoding a layout file uses for a
/// donut, so a derived layer is no worse off here than a drawn one.
pub fn derive_layers_into(
    store: &mut GeometryStore,
    provenance: &mut Provenance,
    derived: &DerivedTable,
) -> Result<(), LayoutError> {
    // One buffer set for the whole call: an accumulator, the operand being
    // folded into it, and the result of the fold, rotated rather than
    // reallocated. Plus the four flat columns the store append takes.
    let mut folded = ValidatedLayer::default();
    let mut operand = ValidatedLayer::default();
    let mut combined = ValidatedLayer::default();
    let (mut xs, mut ys) = (Vec::<Dbu>::new(), Vec::<Dbu>::new());
    let (mut start, mut len) = (Vec::<u32>::new(), Vec::<u32>::new());

    // Tens of derived layers per deck, each a handful of operands, so neither
    // of the two loops here is bulk; the bulk work is inside the booleans.
    for row in 0..derived.len() {
        let (layer, op) = derived.row(row);
        let operands = derived.operands_of(row);
        let blame = |why: BooleanError| LayoutError::Derived(layer, why);

        validate_layer_into(store, operands[0], &mut folded).map_err(|why| blame(why.into()))?;
        for &next in &operands[1..] {
            validate_layer_into(store, next, &mut operand).map_err(|why| blame(why.into()))?;
            match op {
                DerivedOp::And => intersection_into(&folded, &operand, &mut combined),
                DerivedOp::Or => union_into(&folded, &operand, &mut combined),
                DerivedOp::Not => subtraction_into(&folded, &operand, &mut combined),
            }
            .map_err(blame)?;
            std::mem::swap(&mut folded, &mut combined);
        }

        xs.clear();
        ys.clear();
        start.clear();
        len.clear();
        for polygon in 0..u32::try_from(folded.len()).expect("a layer's polygons fit a u32") {
            let polygon = folded.get(store, polygon);
            // Outer first, then its holes — the ring order `validate_layer_into`
            // emits and the one it reads back.
            for ring in std::iter::once(polygon.outer()).chain(polygon.holes()) {
                let (ring_xs, ring_ys) = ring.coords();
                start.push(crate::narrow(xs.len()));
                len.push(crate::narrow(ring_xs.len()));
                xs.extend_from_slice(ring_xs);
                ys.extend_from_slice(ring_ys);
            }
        }

        store.append_layer(layer, &xs, &ys, &start, &len);
        for _ in 0..start.len() {
            provenance.push(PathTable::ROOT, &[]);
        }
        debug_assert_eq!(
            store.polys_on_layer(layer).len(),
            start.len(),
            "the appended rings are not the ones the layer reports"
        );
    }

    debug_assert!(
        provenance.is_empty() || provenance.len() == store.poly_count(),
        "provenance and the store disagree on how many polygons exist, so every \
         violation past the first derived row names another shape's cell"
    );
    Ok(())
}

/// GDSII.
///
/// A record stream of `(length, tag, payload)`. Record tags are a small dense
/// `u16` space known at compile time, so dispatch is an array index, not a map.
pub mod gds {
    use super::{Deck, Layout, LayoutError, UnknownLayers};
    use crate::intern::{StrId, StrTable};
    use crate::narrow;
    use crate::provenance::{PathId, PathTable, Provenance};
    use gpurify_core::{GeometryStore, GeometryStoreBuilder};
    use gpurify_units::{Dbu, MAX_ABS_DBU};

    /// Every GDSII library opens with a six-byte `HEADER` record, so the magic
    /// is the record framing itself: length 6, record type 0, data type 2.
    const MAGIC: [u8; 4] = [0x00, 0x06, 0x00, 0x02];

    // Record tags as they appear on the wire — `(record type << 8) | data type`
    // — which is also how `LayoutError::UnsupportedRecord` reports one.
    const HEADER: u16 = 0x0002;
    const BGNLIB: u16 = 0x0102;
    const LIBNAME: u16 = 0x0206;
    const UNITS: u16 = 0x0305;
    const ENDLIB: u16 = 0x0400;
    const BGNSTR: u16 = 0x0502;
    const STRNAME: u16 = 0x0606;
    const ENDSTR: u16 = 0x0700;
    const BOUNDARY: u16 = 0x0800;
    const PATH: u16 = 0x0900;
    const SREF: u16 = 0x0A00;
    const AREF: u16 = 0x0B00;
    const TEXT: u16 = 0x0C00;
    const LAYER: u16 = 0x0D02;
    const DATATYPE: u16 = 0x0E02;
    const WIDTH: u16 = 0x0F03;
    const XY: u16 = 0x1003;
    const ENDEL: u16 = 0x1100;
    const SNAME: u16 = 0x1206;
    const COLROW: u16 = 0x1302;
    const NODE: u16 = 0x1500;
    /// `TEXT`'s half of the stream pair. The spec requires it — the grammar is
    /// `<textbody> ::= TEXTTYPE [PRESENTATION] .. XY STRING`, with TEXTTYPE
    /// unbracketed — so a `TEXT` without one is refused rather than defaulted.
    const TEXTTYPE: u16 = 0x1602;
    /// Justification and font of the rendered glyph. Read and discarded: it
    /// moves where the *characters* are drawn relative to the `XY` point, and
    /// the point itself is what names a shape.
    const PRESENTATION: u16 = 0x1701;
    const STRING: u16 = 0x1906;
    const STRANS: u16 = 0x1A01;
    const MAG: u16 = 0x1B05;
    const ANGLE: u16 = 0x1C05;
    const REFLIBS: u16 = 0x1F06;
    const FONTS: u16 = 0x2006;
    const GENERATIONS: u16 = 0x2202;
    const ATTRTABLE: u16 = 0x2306;
    const PATHTYPE: u16 = 0x2102;
    const ELFLAGS: u16 = 0x2601;
    const PROPATTR: u16 = 0x2B02;
    const PROPVALUE: u16 = 0x2C06;
    const BOX: u16 = 0x2D00;
    const BOXTYPE: u16 = 0x2E02;
    const PLEX: u16 = 0x2F03;
    const BGNEXTN: u16 = 0x3003;
    const ENDEXTN: u16 = 0x3103;
    const FORMAT: u16 = 0x3602;
    const MASK: u16 = 0x3706;
    const ENDMASKS: u16 = 0x3800;
    const LIBDIRSIZE: u16 = 0x3902;
    const SRFNAME: u16 = 0x3A06;
    const LIBSECUR: u16 = 0x3B02;

    /// `STRANS` bit 0, counted from the most significant: reflect about the X
    /// axis before rotating.
    const STRANS_REFLECT: u16 = 0x8000;
    /// `STRANS` bits 13 and 14: magnification and angle are absolute, i.e. not
    /// composed with the parent's. Both break the fold in [`Xform::compose`],
    /// so both are refused rather than approximated.
    const STRANS_ABSOLUTE: u16 = 0x0006;

    /// A byte offset as [`LayoutError`] states it.
    ///
    /// One place so the cast is justified once: an offset is an index into a
    /// slice already in memory, so it is at most `usize::MAX` and this is
    /// lossless on every target this tree builds for.
    const fn offset(at: usize) -> u64 {
        at as u64
    }

    /// True when the byte prefix is a GDSII header record.
    pub fn detect(prefix: &[u8]) -> bool {
        prefix.starts_with(&MAGIC)
    }

    pub fn read(bytes: &[u8], deck: &Deck, unknown: UnknownLayers) -> Result<Layout, LayoutError> {
        let mut library = parse(bytes)?;
        let (mut store, mut provenance, dropped) = flatten(&library, deck, unknown)?;
        // Here rather than in `read_layout`, so that every path producing a
        // store from bytes produces a *complete* one — the round-trip law
        // compares a store read through `gds::read` against a store read
        // through `read_layout`, and a derived layer materialised in only one
        // of them would make the two differ by construction.
        super::derive_layers_into(&mut store, &mut provenance, deck.layers.derived())?;
        Ok(Layout {
            store,
            provenance,
            // The names the elements interned along the way. Taken rather than
            // borrowed: the library dies here and the ids in the store's
            // provenance only mean something against this table.
            strings: std::mem::take(&mut library.strings),
            dropped,
        })
    }

    // ---------------------------------------------------------------- parsing

    /// One geometry element as the file states it, before any transform.
    ///
    /// Ranges into [`Library`]'s flat columns rather than owned vectors: a
    /// library holds millions of these and a `Vec` per element is three words
    /// of header before a single coordinate exists.
    struct Elem {
        layer: u16,
        datatype: u16,
        vert_start: u32,
        vert_len: u32,
        prop_start: u32,
        prop_len: u32,
    }

    /// One `SREF` or `AREF`: a child cell, its placement, and the array step.
    ///
    /// An `SREF` is the one-by-one case with zero steps, so flattening has one
    /// path rather than two.
    struct Ref {
        cell: StrId,
        /// The child's own transform, whose translation is the array origin.
        place: Xform,
        col_step: (i64, i64),
        row_step: (i64, i64),
        cols: u32,
        rows: u32,
    }

    /// One `TEXT` as the file states it, before any transform.
    ///
    /// The coordinate is inline rather than a range into `xs`/`ys`: the spec
    /// says "a text or SREF element must have only one pair of coordinates", so
    /// the run is always length one and a `(start, len)` pair would be two
    /// words to describe one point.
    struct Text {
        layer: u16,
        texttype: u16,
        x: i64,
        y: i64,
        string: StrId,
    }

    /// One structure, as ranges into the library's element and reference lists.
    struct Cell {
        name: StrId,
        elem_start: u32,
        elem_end: u32,
        ref_start: u32,
        ref_end: u32,
        text_start: u32,
        text_end: u32,
    }

    /// An exactly representable instance transform.
    ///
    /// Integral magnification, an optional reflection about the X axis, a
    /// quarter turn, and a translation — the subset the module doc declares.
    /// It is closed under composition, which is what makes flattening a fold
    /// rather than a matrix stack: `F` and `R` do not commute, but
    /// `F·R_q = R_{-q}·F`, so every composite is still one scale, one
    /// reflection, one quarter turn and one translation.
    #[derive(Clone, Copy)]
    struct Xform {
        mag: i64,
        flip: bool,
        quadrant: u8,
        dx: i64,
        dy: i64,
    }

    impl Xform {
        const IDENTITY: Self = Self {
            mag: 1,
            flip: false,
            quadrant: 0,
            dx: 0,
            dy: 0,
        };

        /// The linear part as the row-major pair `(a, b, c, e)` of
        /// `x' = a·x + b·y`, `y' = c·x + e·y`.
        ///
        /// A uniform: computed once per instance and hoisted above the vertex
        /// loop, so the `match` and the `if` below are constant across every
        /// row that loop then walks.
        fn linear(self) -> (i64, i64, i64, i64) {
            let (a, b, c, e) = match self.quadrant & 3 {
                0 => (1, 0, 0, 1),
                1 => (0, -1, 1, 0),
                2 => (-1, 0, 0, -1),
                _ => (0, 1, -1, 0),
            };
            // The reflection is the second column negated, because it runs
            // before the rotation.
            let s = if self.flip { -1 } else { 1 };
            (self.mag * a, self.mag * b * s, self.mag * c, self.mag * e * s)
        }

        /// `self` applied after `child`.
        fn compose(self, child: Self) -> Self {
            let (a, b, c, e) = self.linear();
            Self {
                mag: self.mag * child.mag,
                flip: self.flip ^ child.flip,
                // `F·R_q = R_{-q}·F`, so a reflecting parent reverses the
                // child's turn as it commutes past it.
                quadrant: if self.flip {
                    (self.quadrant + 4 - (child.quadrant & 3)) & 3
                } else {
                    (self.quadrant + child.quadrant) & 3
                },
                dx: a * child.dx + b * child.dy + self.dx,
                dy: c * child.dx + e * child.dy + self.dy,
            }
        }
    }

    /// The library as parsed: hierarchy intact, nothing mapped to the deck yet.
    #[derive(Default)]
    struct Library {
        strings: StrTable,
        cells: Vec<Cell>,
        /// Cell indices ordered by name, for the `SNAME` lookup. Sorted and
        /// binary-searched, not hashed — see [`crate::intern`]; a map's
        /// iteration order is what made the old tree's reports differ between
        /// runs of the same binary.
        by_name: Vec<u32>,
        elems: Vec<Elem>,
        refs: Vec<Ref>,
        texts: Vec<Text>,
        xs: Vec<i64>,
        ys: Vec<i64>,
        props: Vec<(i16, StrId)>,
    }

    impl Library {
        /// The cell a name defines, or `None`.
        fn find(&self, name: StrId) -> Option<u32> {
            let at = self
                .by_name
                .binary_search_by_key(&name, |&i| self.cells[i as usize].name)
                .ok()?;
            Some(self.by_name[at])
        }
    }

    /// One `(tag, payload)` record and the offset just past it.
    ///
    /// Fail closed on both framing errors a stream can have: a header that runs
    /// off the end, and a length that cannot advance.
    fn record(bytes: &[u8], at: usize) -> Result<(u16, &[u8], usize), LayoutError> {
        let head = bytes
            .get(at..at + 4)
            .ok_or(LayoutError::Truncated(offset(at)))?;
        let len = usize::from(u16::from_be_bytes([head[0], head[1]]));
        let tag = u16::from_be_bytes([head[2], head[3]]);
        // A record shorter than its own header would leave `at` where it is and
        // loop forever; an odd length is not a GDSII record at all.
        if len < 4 || len % 2 != 0 {
            return Err(LayoutError::Truncated(offset(at)));
        }
        let payload = bytes
            .get(at + 4..at + len)
            .ok_or(LayoutError::Truncated(offset(at)))?;
        Ok((tag, payload, at + len))
    }

    /// A two-byte integer payload.
    fn word(payload: &[u8], at: usize) -> Result<u16, LayoutError> {
        let bytes: [u8; 2] = payload
            .get(..2)
            .and_then(|s| s.try_into().ok())
            .ok_or(LayoutError::Truncated(offset(at)))?;
        Ok(u16::from_be_bytes(bytes))
    }

    /// A four-byte signed integer payload, widened to the arithmetic width the
    /// rest of this module works in.
    fn long(payload: &[u8], at: usize) -> Result<i64, LayoutError> {
        let bytes: [u8; 4] = payload
            .get(..4)
            .and_then(|s| s.try_into().ok())
            .ok_or(LayoutError::Truncated(offset(at)))?;
        Ok(i64::from(i32::from_be_bytes(bytes)))
    }

    /// An ASCII payload, with the NUL the format pads odd names with removed.
    fn ascii(payload: &[u8]) -> std::borrow::Cow<'_, str> {
        let end = payload.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        String::from_utf8_lossy(&payload[..end])
    }

    /// An eight-byte GDSII real: sign, a seven-bit excess-64 base-sixteen
    /// exponent, and a fifty-six-bit fraction, so the value is
    /// `± fraction / 2^56 · 16^(exponent − 64)`.
    #[expect(
        clippy::cast_precision_loss,
        reason = "the fraction is 56 bits and f64 carries 53; every value this \
                  reader accepts is an integral magnification or a quarter turn, \
                  both exact in f64, and anything else is refused by its caller"
    )]
    fn real(payload: &[u8], at: usize) -> Result<f64, LayoutError> {
        /// `2^56`, the fraction's implied denominator.
        const SCALE: f64 = 72_057_594_037_927_936.0;
        let bytes: [u8; 8] = payload
            .get(..8)
            .and_then(|s| s.try_into().ok())
            .ok_or(LayoutError::Truncated(offset(at)))?;
        let sign = if bytes[0] & 0x80 == 0 { 1.0 } else { -1.0 };
        let exponent = i32::from(bytes[0] & 0x7f) - 64;
        let fraction = u64::from_be_bytes([
            0, bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        Ok(sign * (fraction as f64) / SCALE * 16f64.powi(exponent))
    }

    /// Append an `XY` payload to the coordinate columns.
    ///
    /// Two passes over the same bytes, and they stay two: reaching one would
    /// need a `Cols` impl reinterpreting a byte slice as eight-byte points, and
    /// `Cols` is sealed inside `gpurify-core`, plus a two-column `map_into`,
    /// which does not exist. Both are entries in `docs/SIGNATURE_DEFECTS.md`
    /// under *ingest*; neither is reachable from this crate. `chunks_exact`
    /// keeps both passes branchless and the second is served entirely from L1.
    fn points(xs: &mut Vec<i64>, ys: &mut Vec<i64>, payload: &[u8], at: usize) -> Result<(), LayoutError> {
        if !payload.len().is_multiple_of(8) {
            return Err(LayoutError::Truncated(offset(at)));
        }
        xs.extend(
            payload
                .chunks_exact(8)
                .map(|p| i64::from(i32::from_be_bytes([p[0], p[1], p[2], p[3]]))),
        );
        ys.extend(
            payload
                .chunks_exact(8)
                .map(|p| i64::from(i32::from_be_bytes([p[4], p[5], p[6], p[7]]))),
        );
        debug_assert_eq!(xs.len(), ys.len(), "the coordinate columns diverged");
        Ok(())
    }

    /// Read the record stream into a [`Library`].
    ///
    /// **Transform, generative.** One pass, no hierarchy resolution: every
    /// record is either consumed into a table, skipped as carrying no geometry,
    /// or refused. Nothing is approximated, so a construct this reader does not
    /// implement cannot reach the store as something else.
    fn parse(bytes: &[u8]) -> Result<Library, LayoutError> {
        let mut lib = Library::default();
        // One scratch set for every `PATH` in the library, hoisted above the
        // record scan so stroking a centreline allocates nothing per element.
        let mut stroke = Stroke::default();
        let mut open: Option<usize> = None;
        let mut at = 0usize;

        // The record scan is a chain — record N's offset is record N−1's offset
        // plus the length record N−1 declared — so it is not vectorisable, and
        // its `match` is a state machine, not a data-dependent branch inside a
        // kernel.
        loop {
            let (tag, payload, next) = record(bytes, at)?;
            match tag {
                ENDLIB => break,
                // Library metadata. `UNITS` is read and discarded on purpose:
                // coordinates are database units already and this reader never
                // rescales them, so the grid is the layout's, not the file's.
                HEADER | BGNLIB | LIBNAME | UNITS | REFLIBS | FONTS | GENERATIONS | ATTRTABLE
                | FORMAT | MASK | ENDMASKS | LIBDIRSIZE | SRFNAME | LIBSECUR => {}
                BGNSTR => {
                    if open.is_some() {
                        return Err(LayoutError::UnsupportedRecord(tag, offset(at)));
                    }
                    open = Some(lib.cells.len());
                    lib.cells.push(Cell {
                        // Overwritten by the STRNAME that follows; a structure
                        // that never states one is refused at ENDSTR.
                        name: StrId(u32::MAX),
                        elem_start: narrow(lib.elems.len()),
                        elem_end: narrow(lib.elems.len()),
                        ref_start: narrow(lib.refs.len()),
                        ref_end: narrow(lib.refs.len()),
                        text_start: narrow(lib.texts.len()),
                        text_end: narrow(lib.texts.len()),
                    });
                }
                STRNAME => {
                    let index = open.ok_or(LayoutError::UnsupportedRecord(tag, offset(at)))?;
                    let name = lib.strings.intern(&ascii(payload));
                    lib.cells[index].name = name;
                }
                ENDSTR => {
                    let index = open.take().ok_or(LayoutError::UnsupportedRecord(tag, offset(at)))?;
                    if lib.cells[index].name == StrId(u32::MAX) {
                        return Err(LayoutError::UnsupportedRecord(BGNSTR, offset(at)));
                    }
                    lib.cells[index].elem_end = narrow(lib.elems.len());
                    lib.cells[index].ref_end = narrow(lib.refs.len());
                    lib.cells[index].text_end = narrow(lib.texts.len());
                }
                BOUNDARY | BOX => {
                    if open.is_none() {
                        return Err(LayoutError::UnsupportedRecord(tag, offset(at)));
                    }
                    at = boundary(&mut lib, bytes, next, at, tag)?;
                    continue;
                }
                // A stroked centreline, and by the time `path` returns it is an
                // `Elem` like any other — the outline is exact or the element
                // was refused, so nothing downstream can tell a `PATH` from a
                // `BOUNDARY`.
                PATH => {
                    if open.is_none() {
                        return Err(LayoutError::UnsupportedRecord(tag, offset(at)));
                    }
                    at = path(&mut lib, &mut stroke, bytes, next, at)?;
                    continue;
                }
                SREF | AREF => {
                    if open.is_none() {
                        return Err(LayoutError::UnsupportedRecord(tag, offset(at)));
                    }
                    at = reference(&mut lib, bytes, next, at, tag == AREF)?;
                    continue;
                }
                // A TEXT carries no geometry, but it carries the net label, and
                // a run whose labels never arrive is a run whose `PortTable` is
                // empty — which makes every net unnamed, the SPEF and DSPF
                // writers refuse, and the engine's field-solve path
                // unreachable, because it selects nets by name.
                //
                // Read here and bound later: the point is in this cell's frame
                // and there are no `PolyId`s yet, so the binding waits for
                // `Provenance::resolve_labels`, after flattening and after the
                // store's layer sort.
                TEXT => {
                    if open.is_none() {
                        return Err(LayoutError::UnsupportedRecord(tag, offset(at)));
                    }
                    at = text(&mut lib, bytes, next, at)?;
                    continue;
                }
                // A NODE is an electrical annotation with no manufactured shape
                // and, unlike a TEXT, no name: the spec gives `NODETYPE` no
                // meaning and never says what a node *is*. There is nothing to
                // record that would not be a guess.
                NODE => {
                    at = skip_element(bytes, next)?;
                    continue;
                }
                _ => return Err(LayoutError::UnsupportedRecord(tag, offset(at))),
            }
            at = next;
        }

        if open.is_some() {
            return Err(LayoutError::Truncated(offset(at)));
        }

        lib.by_name = (0..narrow(lib.cells.len())).collect();
        lib.by_name
            .sort_unstable_by_key(|&i| (lib.cells[i as usize].name, i));

        debug_assert_eq!(lib.xs.len(), lib.ys.len());
        debug_assert_eq!(lib.by_name.len(), lib.cells.len());
        debug_assert!(
            lib.elems
                .iter()
                .all(|e| (e.vert_start + e.vert_len) as usize <= lib.xs.len()),
            "an element's vertex run leaves the coordinate columns"
        );
        Ok(lib)
    }

    /// The records an element carries whatever kind it is: its stream
    /// properties, the flags that carry no geometry, and its terminator.
    /// `Ok(Some(next))` is the `ENDEL`, `Ok(None)` "consumed, keep reading".
    ///
    /// One implementation because [`boundary`] and [`path`] state these
    /// identically — they held a verbatim copy each while the two readers were
    /// written apart, and a property arm added to one and not the other is a
    /// polygon whose provenance silently lands on its neighbour.
    ///
    /// [`reference`] deliberately does **not** route through this: an `SREF`
    /// has no `prop_start` range to own the pair, so a property record on one
    /// would leak into the next element's range. It stays a refusal there.
    fn element_record(
        lib: &mut Library,
        attribute: &mut i16,
        tag: u16,
        payload: &[u8],
        at: usize,
        next: usize,
    ) -> Result<Option<usize>, LayoutError> {
        match tag {
            PROPATTR => {
                #[expect(
                    clippy::cast_possible_wrap,
                    reason = "PROPATTR is a signed two-byte integer on the wire"
                )]
                {
                    *attribute = word(payload, at)? as i16;
                }
            }
            PROPVALUE => {
                let value = lib.strings.intern(&ascii(payload));
                lib.props.push((*attribute, value));
            }
            ELFLAGS | PLEX => {}
            ENDEL => return Ok(Some(next)),
            _ => return Err(LayoutError::UnsupportedRecord(tag, offset(at))),
        }
        Ok(None)
    }

    /// Consume a `TEXT` through its `ENDEL`. Returns the offset past it.
    ///
    /// The grammar, from the Feb-87 manual — bracketed is optional, and note
    /// that `TEXTTYPE`, `XY` and `STRING` are not:
    ///
    /// ```text
    /// <text>     ::= TEXT [ELFLAGS] [PLEX] LAYER <textbody>
    /// <textbody> ::= TEXTTYPE [PRESENTATION] [PATHTYPE] [WIDTH] [<strans>] XY STRING
    /// ```
    ///
    /// # What is read and what is dropped
    ///
    /// `LAYER` and `TEXTTYPE` are the stream pair, and they are what the deck's
    /// label pairing is stated against. `XY` is the one point the spec allows —
    /// *"a text or SREF element must have only one pair of coordinates"* — and
    /// it is what a later pass tests against the geometry. `STRING` is the
    /// name.
    ///
    /// `PRESENTATION`, `PATHTYPE` and `WIDTH` describe the rendered glyph: how
    /// the characters are justified around the point, how their strokes end,
    /// how thick they are. None of that moves the point, and the point is the
    /// whole of what names a shape, so all three are accepted and discarded.
    /// Reading them is not optional even so — an unknown record is
    /// `UnsupportedRecord`, so silently refusing a legal `TEXT` would be the
    /// alternative.
    ///
    /// `STRANS`/`MAG`/`ANGLE` are accepted for the same reason and discarded
    /// for a sharper one: they rotate and mirror the glyph about its own
    /// anchor, and the anchor is the `XY` point, which they leave where it is.
    /// The transform that *does* move a label is the instance transform, and
    /// that is applied in `Flatten::visit` alongside the geometry.
    fn text(
        lib: &mut Library,
        bytes: &[u8],
        mut at: usize,
        start: usize,
    ) -> Result<usize, LayoutError> {
        let mut layer: Option<u16> = None;
        let mut texttype: Option<u16> = None;
        let mut point: Option<(i64, i64)> = None;
        let mut string: Option<StrId> = None;
        let mut attribute = 0i16;
        // A TEXT's properties are parsed and dropped: `props` is a per-polygon
        // CSR column and this element becomes no polygon, so appending to it
        // would shift every later shape's property range.
        let props_before = lib.props.len();

        let end = loop {
            let (tag, payload, next) = record(bytes, at)?;
            match tag {
                LAYER => layer = Some(word(payload, at)?),
                TEXTTYPE => texttype = Some(word(payload, at)?),
                XY => {
                    // Into scratch at the end of the shared columns, then
                    // popped: `points` is the one checked reader of an XY
                    // payload, and duplicating its framing checks here to save
                    // two pushes would duplicate the thing most worth having
                    // exactly once.
                    let before = lib.xs.len();
                    points(&mut lib.xs, &mut lib.ys, payload, at)?;
                    // Fail closed on the one shape the spec forbids. A TEXT
                    // with two points is not a TEXT with an extra point to
                    // ignore; it is a file that means something this reader
                    // cannot know.
                    if lib.xs.len() != before + 1 {
                        lib.xs.truncate(before);
                        lib.ys.truncate(before);
                        return Err(LayoutError::UnsupportedRecord(TEXT, offset(start)));
                    }
                    point = Some((lib.xs[before], lib.ys[before]));
                    lib.xs.truncate(before);
                    lib.ys.truncate(before);
                }
                STRING => string = Some(lib.strings.intern(&ascii(payload))),
                // Glyph presentation, and the transform of the glyph about its
                // own anchor. Accepted, discarded — see this function's doc.
                PRESENTATION | PATHTYPE | WIDTH | STRANS | MAG | ANGLE => {}
                _ => {
                    if let Some(end) = element_record(lib, &mut attribute, tag, payload, at, next)? {
                        break end;
                    }
                }
            }
            at = next;
        };
        lib.props.truncate(props_before);

        // Fail closed on each of the three the grammar makes mandatory. A label
        // missing its stream pair cannot be paired with a conductor, one
        // missing its point cannot be placed, and one missing its string names
        // nothing — and none of the three has a defensible default.
        let (Some(layer), Some(texttype), Some((x, y)), Some(string)) =
            (layer, texttype, point, string)
        else {
            return Err(LayoutError::UnsupportedRecord(TEXT, offset(start)));
        };

        lib.texts.push(Text {
            layer,
            texttype,
            x,
            y,
            string,
        });
        Ok(end)
    }

    /// Consume a `BOUNDARY` or `BOX` through its `ENDEL`. Returns the offset
    /// past it.
    fn boundary(
        lib: &mut Library,
        bytes: &[u8],
        mut at: usize,
        start: usize,
        kind: u16,
    ) -> Result<usize, LayoutError> {
        let vert_start = narrow(lib.xs.len());
        let prop_start = narrow(lib.props.len());
        let mut layer: Option<u16> = None;
        let mut datatype: Option<u16> = None;
        let mut attribute = 0i16;
        let mut seen_xy = false;

        let end = loop {
            let (tag, payload, next) = record(bytes, at)?;
            match tag {
                LAYER => layer = Some(word(payload, at)?),
                // One arm for both because a BOX's type plays the datatype's
                // role exactly: it is the second half of the stream pair.
                DATATYPE | BOXTYPE => datatype = Some(word(payload, at)?),
                XY => {
                    points(&mut lib.xs, &mut lib.ys, payload, at)?;
                    seen_xy = true;
                }
                _ => {
                    if let Some(end) = element_record(lib, &mut attribute, tag, payload, at, next)? {
                        break end;
                    }
                }
            }
            at = next;
        };

        // The closing point a BOUNDARY repeats belongs to the file format, not
        // to the store. One compare per element, not per vertex.
        let last = lib.xs.len().wrapping_sub(1);
        let first = vert_start as usize;
        if lib.xs.len() - first >= 2 && lib.xs[first] == lib.xs[last] && lib.ys[first] == lib.ys[last] {
            lib.xs.pop();
            lib.ys.pop();
        }

        let vert_len = narrow(lib.xs.len()) - vert_start;
        // Fail closed. An element missing its stream pair or its geometry, or
        // one with no interior, is refused: there is no representation of it
        // that is not a guess, and a guess is a moved verdict.
        let (Some(layer), Some(datatype)) = (layer, datatype) else {
            return Err(LayoutError::UnsupportedRecord(kind, offset(start)));
        };
        if !seen_xy || vert_len < 3 {
            return Err(LayoutError::UnsupportedRecord(kind, offset(start)));
        }

        lib.elems.push(Elem {
            layer,
            datatype,
            vert_start,
            vert_len,
            prop_start,
            prop_len: narrow(lib.props.len()) - prop_start,
        });
        Ok(end)
    }

    /// Per-`PATH` scratch: the centreline and the two offset chains it strokes
    /// into.
    ///
    /// A column of `(i64, i64)` rather than two of `i64` because every one of
    /// these is read as a point — both coordinates in the same expression —
    /// which is the one case `CONVENTIONS.md` §1 keeps `AoS` for.
    #[derive(Default)]
    struct Stroke {
        /// The centreline as the file states it, with the two end caps applied.
        pts: Vec<(i64, i64)>,
        /// One unit direction per segment: `pts.len() - 1` rows.
        dirs: Vec<(i64, i64)>,
        /// `dirs` with both ends duplicated, so `ext[i]` is the segment
        /// arriving at vertex `i` and `ext[i + 1]` the one leaving it.
        ext: Vec<(i64, i64)>,
        left: Vec<(i64, i64)>,
        right: Vec<(i64, i64)>,
    }

    /// Consume a `PATH` through its `ENDEL`, stroking its centreline into the
    /// outline the rest of the pipeline sees. Returns the offset past it.
    ///
    /// **Transform, A-to-B.** An `n`-point centreline in, a `2n`-point ring
    /// out: one offset corner per vertex per side.
    ///
    /// # What is exact, and what is refused
    ///
    /// The outline is exact or the element is refused; there is no rounded
    /// case, because a rounded outline moves a spacing verdict exactly the way
    /// a rounded instance transform does. Exact means all four of:
    ///
    /// - **every segment axis-parallel and non-degenerate**, so both offset
    ///   lines are axis-parallel and their intersection is an integer point;
    /// - **an even width**, so the half-width the offset is by is still a whole
    ///   database unit;
    /// - **no vertex that reverses direction**, which has no miter at all — the
    ///   two offset lines coincide and the join is a cap, a different element;
    /// - **`PATHTYPE` 0, 2 or 4.** Type 1 is a semicircular cap and no polygon
    ///   is that shape.
    ///
    /// Everything else is a typed refusal, never a store row.
    fn path(
        lib: &mut Library,
        stroke: &mut Stroke,
        bytes: &[u8],
        mut at: usize,
        start: usize,
    ) -> Result<usize, LayoutError> {
        let vert_start = narrow(lib.xs.len());
        let prop_start = narrow(lib.props.len());
        let mut layer: Option<u16> = None;
        let mut datatype: Option<u16> = None;
        let mut attribute = 0i16;
        let mut seen_xy = false;
        // The format's defaults: a zero width, flush ends, no extensions.
        let mut width = 0i64;
        let mut pathtype = 0u16;
        let mut begin_ext = 0i64;
        let mut end_ext = 0i64;

        let end = loop {
            let (tag, payload, next) = record(bytes, at)?;
            match tag {
                LAYER => layer = Some(word(payload, at)?),
                DATATYPE => datatype = Some(word(payload, at)?),
                WIDTH => width = long(payload, at)?,
                PATHTYPE => pathtype = word(payload, at)?,
                BGNEXTN => begin_ext = long(payload, at)?,
                ENDEXTN => end_ext = long(payload, at)?,
                XY => {
                    points(&mut lib.xs, &mut lib.ys, payload, at)?;
                    seen_xy = true;
                }
                _ => {
                    if let Some(end) = element_record(lib, &mut attribute, tag, payload, at, next)? {
                        break end;
                    }
                }
            }
            at = next;
        };

        // The centreline moves out of the coordinate columns and the outline
        // takes its place: the columns hold what the store will, and a refusal
        // below leaves no half-written element behind it.
        let first = vert_start as usize;
        let (cx, cy) = (&lib.xs[first..], &lib.ys[first..]);
        let centre = cx.len();
        debug_assert_eq!(centre, cy.len(), "the coordinate columns diverged");
        stroke.pts.clear();
        stroke.pts.reserve(centre);
        for i in 0..centre {
            stroke.pts.push((cx[i], cy[i]));
        }
        lib.xs.truncate(first);
        lib.ys.truncate(first);

        let (Some(layer), Some(datatype)) = (layer, datatype) else {
            return Err(LayoutError::UnsupportedRecord(PATH, offset(start)));
        };
        let n = stroke.pts.len();
        if !seen_xy || n < 2 {
            return Err(LayoutError::UnsupportedRecord(PATH, offset(start)));
        }
        // A zero width has no area to verify. A negative one is GDSII's
        // "absolute width", which does not compose with an instance
        // magnification — the same objection `STRANS_ABSOLUTE` is refused for.
        // An odd width offsets by half a database unit, which is off the grid.
        if width <= 0 || width % 2 != 0 {
            return Err(LayoutError::UnsupportedRecord(WIDTH, offset(start)));
        }
        let half = width / 2;
        let (begin_ext, end_ext) = match pathtype {
            0 => (0, 0),
            2 => (half, half),
            4 => (begin_ext, end_ext),
            _ => return Err(LayoutError::UnsupportedRecord(PATHTYPE, offset(start))),
        };

        // The adjacent-pair scan, as two offset views of the same column: `tail`
        // is the segment's start vertex and `head` its end.
        let (tail, head) = (&stroke.pts[..n - 1], &stroke.pts[1..]);
        let segments = tail.len();
        debug_assert_eq!(segments, head.len(), "the offset views diverged");

        // Exactly one of the two deltas is zero on an axis-parallel,
        // non-degenerate segment. Folded to one flag over the whole centreline
        // rather than tested per vertex, so the scan carries no branch: `&=` on
        // `bool` is the non-short-circuiting operator, so the fold is one `and`
        // per row and no control flow.
        let mut axis_parallel = true;
        for i in 0..segments {
            let (a, b) = (tail[i], head[i]);
            axis_parallel &= (a.0 == b.0) ^ (a.1 == b.1);
        }
        if !axis_parallel {
            return Err(LayoutError::UnsupportedTransform);
        }

        stroke.dirs.clear();
        stroke.dirs.reserve(segments);
        for i in 0..segments {
            let (a, b) = (tail[i], head[i]);
            stroke.dirs.push(((b.0 - a.0).signum(), (b.1 - a.1).signum()));
        }
        debug_assert_eq!(stroke.dirs.len(), n - 1, "one direction per segment");

        // A reversal is the one join with no intersection to miter at. Same
        // shape of check as above — `|=` on `bool` does not short-circuit — and
        // empty for a two-point centreline.
        let (prev, curr) = (&stroke.dirs[..segments - 1], &stroke.dirs[1..]);
        debug_assert_eq!(prev.len(), curr.len(), "the offset views diverged");
        let mut reverses = false;
        for i in 0..prev.len() {
            let (p, c) = (prev[i], curr[i]);
            reverses |= p.0 * c.0 + p.1 * c.1 < 0;
        }
        if reverses {
            return Err(LayoutError::UnsupportedTransform);
        }

        // The end caps are the only term that depends on a vertex's *index*, so
        // they are folded into the centreline here and the corner map below
        // stays uniform over every row. Extending a segment along its own
        // direction leaves that direction unchanged, which is why `dirs` is
        // computed first and stays valid.
        let (front, back) = (stroke.dirs[0], stroke.dirs[segments - 1]);
        stroke.pts[0].0 -= begin_ext * front.0;
        stroke.pts[0].1 -= begin_ext * front.1;
        stroke.pts[n - 1].0 += end_ext * back.0;
        stroke.pts[n - 1].1 += end_ext * back.1;

        stroke.ext.clear();
        stroke.ext.reserve(segments + 2);
        stroke.ext.push(front);
        stroke.ext.extend_from_slice(&stroke.dirs);
        stroke.ext.push(back);
        debug_assert_eq!(
            stroke.ext.len(),
            n + 1,
            "one arriving and one leaving direction per vertex"
        );

        // The miter, exact and division-free. With `d` the dot product of the
        // two unit directions — `1` at a collinear join, `0` at a quarter turn,
        // and `-1` refused above — the offset corner is
        // `p + half * (n_in * (1 - d) + n_out)`, which is the intersection of
        // the two offset lines in both surviving cases: `n_in + n_out` at a
        // turn, and `n_out` alone where the two normals are the same vector.
        // `side` is `+1` for the left chain and `-1` for the right, and is a
        // uniform, so the body is six multiplies and no branch.
        let corner = |side: i64| {
            move |(p, pv, cv): ((i64, i64), (i64, i64), (i64, i64))| {
                let dot = pv.0 * cv.0 + pv.1 * cv.1;
                let (inx, iny) = (-pv.1 * side, pv.0 * side);
                let (outx, outy) = (-cv.1 * side, cv.0 * side);
                (
                    p.0 + half * (inx * (1 - dot) + outx),
                    p.1 + half * (iny * (1 - dot) + outy),
                )
            }
        };
        debug_assert_eq!(stroke.pts.len(), n, "one centreline vertex per corner");
        debug_assert_eq!(stroke.ext.len(), n + 1, "the offset views diverged");

        let left = corner(1);
        stroke.left.clear();
        stroke.left.reserve(n);
        for i in 0..n {
            stroke
                .left
                .push(left((stroke.pts[i], stroke.ext[i], stroke.ext[i + 1])));
        }

        let right = corner(-1);
        stroke.right.clear();
        stroke.right.reserve(n);
        for i in 0..n {
            stroke
                .right
                .push(right((stroke.pts[i], stroke.ext[i], stroke.ext[i + 1])));
        }

        // Right side forward, then left side back. That order is what makes the
        // ring counter-clockwise, and `core::view` reads a clockwise ring as a
        // hole — a stroked wire emitted the other way round would subtract
        // itself from its own layer.
        lib.xs.extend(stroke.right.iter().map(|p| p.0));
        lib.xs.extend(stroke.left.iter().rev().map(|p| p.0));
        lib.ys.extend(stroke.right.iter().map(|p| p.1));
        lib.ys.extend(stroke.left.iter().rev().map(|p| p.1));

        let vert_len = narrow(lib.xs.len()) - vert_start;
        debug_assert_eq!(lib.xs.len(), lib.ys.len(), "the coordinate columns diverged");
        debug_assert_eq!(
            vert_len as usize,
            2 * n,
            "an n-point centreline strokes to one corner per vertex per side"
        );

        lib.elems.push(Elem {
            layer,
            datatype,
            vert_start,
            vert_len,
            prop_start,
            prop_len: narrow(lib.props.len()) - prop_start,
        });
        Ok(end)
    }

    /// Consume an `SREF` or `AREF` through its `ENDEL`.
    fn reference(
        lib: &mut Library,
        bytes: &[u8],
        mut at: usize,
        start: usize,
        array: bool,
    ) -> Result<usize, LayoutError> {
        let mut name: Option<StrId> = None;
        let mut place = Xform::IDENTITY;
        let mut cols = 1u32;
        let mut rows = 1u32;
        // An SREF states one point, an AREF three. A fourth is not this format.
        let mut pt = [(0i64, 0i64); 3];
        let mut points_seen = 0usize;

        let end = loop {
            let (tag, payload, next) = record(bytes, at)?;
            match tag {
                SNAME => name = Some(lib.strings.intern(&ascii(payload))),
                STRANS => {
                    let flags = word(payload, at)?;
                    // An absolute magnification or angle does not compose with
                    // the parent's, so the fold in `Xform::compose` would be
                    // wrong for it. Refused, never approximated.
                    if flags & STRANS_ABSOLUTE != 0 {
                        return Err(LayoutError::UnsupportedTransform);
                    }
                    place.flip = flags & STRANS_REFLECT != 0;
                }
                MAG => {
                    let m = real(payload, at)?;
                    // Non-integral magnification would put a vertex off the
                    // manufacturing grid, which is a geometry change, not a
                    // rounding.
                    if !((1.0..=1e6).contains(&m) && m.fract() == 0.0) {
                        return Err(LayoutError::UnsupportedTransform);
                    }
                    #[expect(
                        clippy::cast_possible_truncation,
                        reason = "checked integral and inside 1..=1e6 on the line above"
                    )]
                    {
                        place.mag = m as i64;
                    }
                }
                ANGLE => {
                    let degrees = real(payload, at)?;
                    let quarters = degrees / 90.0;
                    // Non-orthogonal rotation cannot be represented on an
                    // integer grid at all.
                    if quarters.fract() != 0.0 || quarters.abs() > 1e6 {
                        return Err(LayoutError::UnsupportedTransform);
                    }
                    #[expect(
                        clippy::cast_possible_truncation,
                        reason = "checked integral and bounded on the line above"
                    )]
                    let quarters = quarters as i64;
                    #[expect(
                        clippy::cast_possible_truncation,
                        reason = "`rem_euclid(4)` is 0..=3, so neither the sign \
                                  nor the top 56 bits carry information"
                    )]
                    {
                        place.quadrant = (quarters.rem_euclid(4)) as u8;
                    }
                }
                COLROW => {
                    let payload: [u8; 4] = payload
                        .get(..4)
                        .and_then(|s| s.try_into().ok())
                        .ok_or(LayoutError::Truncated(offset(at)))?;
                    cols = u32::from(u16::from_be_bytes([payload[0], payload[1]]));
                    rows = u32::from(u16::from_be_bytes([payload[2], payload[3]]));
                }
                XY => {
                    if !payload.len().is_multiple_of(8) {
                        return Err(LayoutError::Truncated(offset(at)));
                    }
                    for (slot, p) in pt.iter_mut().zip(payload.chunks_exact(8)) {
                        *slot = (
                            i64::from(i32::from_be_bytes([p[0], p[1], p[2], p[3]])),
                            i64::from(i32::from_be_bytes([p[4], p[5], p[6], p[7]])),
                        );
                    }
                    points_seen = payload.len() / 8;
                }
                ELFLAGS | PLEX => {}
                ENDEL => break next,
                _ => return Err(LayoutError::UnsupportedRecord(tag, offset(at))),
            }
            at = next;
        };

        let Some(cell) = name else {
            return Err(LayoutError::UnsupportedRecord(SREF, offset(start)));
        };
        let wanted = if array { 3 } else { 1 };
        if points_seen != wanted {
            return Err(LayoutError::UnsupportedRecord(SREF, offset(start)));
        }
        place.dx = pt[0].0;
        place.dy = pt[0].1;

        // An AREF states the far corner of the array, not the step, so the step
        // is exact or the array is not representable — a rounded pitch moves
        // every instance after the first.
        let (col_step, row_step) = if array {
            if cols == 0 || rows == 0 {
                return Err(LayoutError::UnsupportedTransform);
            }
            let step = |far: (i64, i64), n: u32| -> Option<(i64, i64)> {
                let n = i64::from(n);
                let (dx, dy) = (far.0 - pt[0].0, far.1 - pt[0].1);
                (dx % n == 0 && dy % n == 0).then_some((dx / n, dy / n))
            };
            (
                step(pt[1], cols).ok_or(LayoutError::UnsupportedTransform)?,
                step(pt[2], rows).ok_or(LayoutError::UnsupportedTransform)?,
            )
        } else {
            ((0, 0), (0, 0))
        };

        lib.refs.push(Ref {
            cell,
            place,
            col_step,
            row_step,
            cols,
            rows,
        });
        Ok(end)
    }

    /// Consume an element whose records carry no geometry, through its `ENDEL`.
    fn skip_element(bytes: &[u8], mut at: usize) -> Result<usize, LayoutError> {
        loop {
            let (tag, _, next) = record(bytes, at)?;
            at = next;
            if tag == ENDEL {
                return Ok(at);
            }
        }
    }

    // -------------------------------------------------------------- flattening

    /// The hierarchy walk, and the tables it fills.
    struct Flatten<'a> {
        lib: &'a Library,
        deck: &'a Deck,
        unknown: UnknownLayers,
        builder: GeometryStoreBuilder,
        provenance: Provenance,
        dropped: u32,
        /// Which cells are on the current root-to-here chain, for the cycle
        /// check. A column of `bool`, not a set: cell ids are dense.
        on_chain: Vec<bool>,
        /// The instance chain, root first, as `Provenance` wants it.
        chain: Vec<StrId>,
        /// Per-polygon scratch, hoisted so nothing allocates per element.
        rx: Vec<i64>,
        ry: Vec<i64>,
        tx: Vec<Dbu>,
        ty: Vec<Dbu>,
    }

    /// Resolve the hierarchy into one flat store.
    ///
    /// **Transform, A-to-B.** Every top cell — one on a normal layout — is
    /// walked depth first, and each element it reaches is transformed into the
    /// root frame once. The store's own layer sort runs last, and its
    /// permutation is applied to the provenance columns here, which is the
    /// invariant `crate::ingest`'s module doc names.
    fn flatten(
        lib: &Library,
        deck: &Deck,
        unknown: UnknownLayers,
    ) -> Result<(GeometryStore, Provenance, u32), LayoutError> {
        // A scatter, and it fails closed on a name no cell defines.
        let mut referenced = vec![false; lib.cells.len()];
        for reference in &lib.refs {
            let target = lib.find(reference.cell).ok_or_else(|| {
                LayoutError::MissingCell(lib.strings.resolve(reference.cell).to_owned())
            })?;
            referenced[target as usize] = true;
        }

        let mut walk = Flatten {
            lib,
            deck,
            unknown,
            builder: GeometryStoreBuilder::with_capacity(lib.elems.len(), lib.xs.len()),
            provenance: Provenance::default(),
            dropped: 0,
            on_chain: vec![false; lib.cells.len()],
            chain: Vec::new(),
            rx: Vec::new(),
            ry: Vec::new(),
            tx: Vec::new(),
            ty: Vec::new(),
        };

        // Fail closed: a library whose every cell is referenced has no root to
        // walk from, which means a cycle. Reporting an empty store for it would
        // be a clean report over a layout nobody read.
        if !lib.cells.is_empty() && referenced.iter().all(|&r| r) {
            return Err(LayoutError::CyclicHierarchy(
                lib.strings.resolve(lib.cells[0].name).to_owned(),
            ));
        }
        for (index, &is_referenced) in referenced.iter().enumerate() {
            if !is_referenced {
                walk.visit(narrow(index), Xform::IDENTITY)?;
            }
        }

        let (store, permutation) = walk.builder.finish(deck.layers.len());
        debug_assert_eq!(
            permutation.len(),
            store.poly_count(),
            "the store returned a permutation of a different length than its rows"
        );
        // The invariant `crate::ingest`'s module doc names, and the one place
        // it happens: provenance is accumulated in file order and the store is
        // sorted by layer, so without this every violation names another
        // shape's cell.
        walk.provenance.permute(&permutation);
        Ok((store, walk.provenance, walk.dropped))
    }

    impl Flatten<'_> {
        /// Emit one cell's geometry under the accumulated transform, then
        /// recurse through its references.
        fn visit(&mut self, cell: u32, at: Xform) -> Result<(), LayoutError> {
            let lib = self.lib;
            let index = cell as usize;
            if self.on_chain[index] {
                return Err(LayoutError::CyclicHierarchy(
                    lib.strings.resolve(lib.cells[index].name).to_owned(),
                ));
            }
            self.on_chain[index] = true;

            // The root path is `PathId(0)` by definition, so the common case —
            // a flat library, where every shape is in the top cell — interns
            // nothing at all.
            let path = if self.chain.is_empty() {
                PathTable::ROOT
            } else {
                self.provenance.intern_path(&self.chain)
            };

            let entry = &lib.cells[index];
            for elem in &lib.elems[entry.elem_start as usize..entry.elem_end as usize] {
                self.emit(elem, at, path)?;
            }
            for label in &lib.texts[entry.text_start as usize..entry.text_end as usize] {
                self.place(label, at)?;
            }

            for reference in &lib.refs[entry.ref_start as usize..entry.ref_end as usize] {
                let child = lib.find(reference.cell).ok_or_else(|| {
                    LayoutError::MissingCell(lib.strings.resolve(reference.cell).to_owned())
                })?;
                self.chain.push(reference.cell);
                for r in 0..reference.rows {
                    for c in 0..reference.cols {
                        let placed = Xform {
                            dx: reference.place.dx
                                + i64::from(c) * reference.col_step.0
                                + i64::from(r) * reference.row_step.0,
                            dy: reference.place.dy
                                + i64::from(c) * reference.col_step.1
                                + i64::from(r) * reference.row_step.1,
                            ..reference.place
                        };
                        self.visit(child, at.compose(placed))?;
                    }
                }
                self.chain.pop();
            }

            self.on_chain[index] = false;
            Ok(())
        }

        /// Transform one label's point into the root frame and record it.
        ///
        /// The same transform the geometry takes, and it has to be: a label
        /// under a mirrored instance names the shape the mirror put under it,
        /// not the one that was there before. Unlike [`Self::emit`] there is no
        /// winding to fix up, because a point has none.
        ///
        /// A text on a stream pair the deck's layer table does not name is
        /// dropped under [`UnknownLayers::Drop`] and refused under `Reject`,
        /// exactly as geometry is — but it is *not* counted in `dropped`, which
        /// the `Layout` field's doc defines as polygons. What decides whether a
        /// mapped label is a net label at all is the deck's `connectivity`
        /// pairing, and that is read later, by
        /// [`Provenance::resolve_labels`](crate::provenance::Provenance::resolve_labels).
        fn place(&mut self, label: &Text, at: Xform) -> Result<(), LayoutError> {
            let Some(layer) = self.deck.layers.of_stream(label.layer, label.texttype) else {
                return match self.unknown {
                    UnknownLayers::Reject => {
                        Err(LayoutError::UnknownLayer(label.layer, label.texttype))
                    }
                    UnknownLayers::Drop => Ok(()),
                };
            };

            let (a, b, c, e) = at.linear();
            let x = a * label.x + b * label.y + at.dx;
            let y = c * label.x + e * label.y + at.dy;

            // The same `±MAX_ABS_DBU` bound `emit` enforces on every vertex,
            // and for the same reason: `Dbu::new_unchecked` below is only sound
            // inside it, and a label outside the domain would be compared
            // against geometry that cannot be.
            let bound = MAX_ABS_DBU.unsigned_abs();
            if x.unsigned_abs() > bound {
                return Err(LayoutError::CoordinateOutOfRange(x));
            }
            if y.unsigned_abs() > bound {
                return Err(LayoutError::CoordinateOutOfRange(y));
            }

            self.provenance.place_label(
                gpurify_core::ops::Point {
                    x: Dbu::new_unchecked(x),
                    y: Dbu::new_unchecked(y),
                },
                layer,
                label.string,
            );
            Ok(())
        }

        /// Transform one element into the root frame and push it.
        fn emit(&mut self, elem: &Elem, at: Xform, path: PathId) -> Result<(), LayoutError> {
            let lib = self.lib;
            let start = elem.vert_start as usize;
            let end = start + elem.vert_len as usize;
            debug_assert!(end <= lib.xs.len(), "vertex run leaves the column");
            debug_assert!(at.mag >= 1, "magnification was checked integral and positive");

            let Some(layer) = self.deck.layers.of_stream(elem.layer, elem.datatype) else {
                match self.unknown {
                    UnknownLayers::Reject => {
                        return Err(LayoutError::UnknownLayer(elem.layer, elem.datatype))
                    }
                    // Never silent: the count is what a caller reports to tell
                    // a partial deck run on purpose from one by accident.
                    UnknownLayers::Drop => {
                        self.dropped += 1;
                        return Ok(());
                    }
                }
            };

            let (xs, ys) = (&lib.xs[start..end], &lib.ys[start..end]);
            // Uniforms, hoisted: the whole transform is four multipliers and
            // two offsets, so the vertex loops below carry no branch at all.
            let (a, b, c, e) = at.linear();
            let (dx, dy) = (at.dx, at.dy);
            let verts = xs.len();
            debug_assert_eq!(verts, ys.len(), "the coordinate columns diverged");
            // A BOUNDARY/BOX is refused below 3 vertices and a PATH strokes to
            // 2n with n >= 2, so the `[1..]` reversal below cannot slice empty.
            debug_assert!(verts >= 3, "an element with no interior reached emit");

            self.rx.clear();
            self.rx.reserve(verts);
            for i in 0..verts {
                self.rx.push(a * xs[i] + b * ys[i] + dx);
            }
            self.ry.clear();
            self.ry.reserve(verts);
            for i in 0..verts {
                self.ry.push(c * xs[i] + e * ys[i] + dy);
            }
            debug_assert_eq!(self.rx.len(), verts);
            debug_assert_eq!(self.ry.len(), verts);

            // Parse, don't validate: the `±MAX_ABS_DBU` bound every downstream
            // i128 area product rests on is checked here, once, and never
            // rechecked. A max-magnitude reduction rather than a per-vertex
            // test, so the check itself carries no branch.
            let bound = MAX_ABS_DBU.unsigned_abs();
            let mut worst = 0u64;
            for i in 0..verts {
                worst = worst
                    .max(self.rx[i].unsigned_abs())
                    .max(self.ry[i].unsigned_abs());
            }
            if worst > bound {
                // Cold: the offending value is wanted once, on the path that
                // refuses the file, so the scan for it is not on any hot path.
                let out = self
                    .rx
                    .iter()
                    .chain(self.ry.iter())
                    .copied()
                    .find(|v| v.unsigned_abs() > bound)
                    .expect("the reduction above found one");
                return Err(LayoutError::CoordinateOutOfRange(out));
            }

            self.tx.clear();
            self.tx.reserve(verts);
            for i in 0..verts {
                self.tx.push(Dbu::new_unchecked(self.rx[i]));
            }
            self.ty.clear();
            self.ty.reserve(verts);
            for i in 0..verts {
                self.ty.push(Dbu::new_unchecked(self.ry[i]));
            }
            debug_assert_eq!(self.tx.len(), self.ty.len());

            // GDSII itself gives a BOUNDARY's vertex order no meaning — the
            // Feb-87 manual states no winding for it, and a boundary drawn
            // inside another is not a hole in this format. This store does
            // read a clockwise ring as a hole, so the order is meaning we add;
            // whether that is the right model is `docs/SIGNATURE_DEFECTS.md`,
            // not this line. What this line owes either model is the weaker,
            // spec-independent invariant the flattener was breaking: *a cell's
            // rings have the same orientation wherever the cell is placed.*
            //
            // `strans` bit 0 is `diag(1,-1)` applied before the rotation, so
            // `Xform::linear` composes to determinant −1 exactly when `flip` —
            // rotations are det +1 and `mag >= 1` — and the shoelace sum scales
            // by that determinant. A mirrored instance of a counter-clockwise
            // cell therefore arrives clockwise unless the vertex order follows,
            // and `validate_layer_into` reads it as an orphan hole.
            //
            // `[1..]`, not the whole run: `erc::first_vertex` documents vertex
            // 0 as a shape's canonical report point, so reversing it would move
            // every per-shape ERC coordinate under a mirror. Rings are stored
            // open here, so fixing vertex 0 and reversing the rest is the
            // reversal. `at.flip` is a per-instance uniform, hoisted with
            // `(a, b, c, e)` above the vertex loops — not a per-row branch.
            debug_assert_eq!(
                a * e - b * c < 0,
                at.flip,
                "det < 0 iff flip: rotations are det +1 and mag >= 1"
            );
            if at.flip {
                self.tx[1..].reverse();
                self.ty[1..].reverse();
            }

            self.builder.push(layer, &self.tx, &self.ty);
            // Immediately after the push, so the two tables cannot drift: the
            // permutation applied at the end is only meaningful if row N of one
            // is row N of the other.
            let props = elem.prop_start as usize..(elem.prop_start + elem.prop_len) as usize;
            self.provenance.push(path, &lib.props[props]);
            Ok(())
        }
    }
}

/// OASIS.
///
/// Variable-length integers, modal state carried between records, and optional
/// per-cell compression. The modal state is the part that makes this a separate
/// implementation rather than a variation of the GDS reader: a record's meaning
/// depends on records before it.
pub mod oasis {
    use super::{Deck, Layout, LayoutError, UnknownLayers};

    /// The magic string every OASIS file opens with, `%SEMI-OASIS\r\n`.
    const MAGIC: &[u8] = b"%SEMI-OASIS\r\n";

    pub fn detect(prefix: &[u8]) -> bool {
        prefix.starts_with(MAGIC)
    }

    /// # Not implemented, and refused rather than half-read
    ///
    /// OASIS is recognised and then declined. This is a format that has not
    /// been written yet, not a shortcut inside one that has: there is no
    /// ceiling here to raise and no faster version of the code below.
    ///
    /// What the format itself settles, and what makes the eventual reader
    /// safe to land incrementally: **an OASIS record carries no length.** A
    /// record id is one byte and its operands are self-delimiting, so a record
    /// the reader does not model cannot be skipped past — there is no way to
    /// find where the next one starts. Refusal is therefore forced by the
    /// encoding rather than chosen, and a reader implementing only `START`,
    /// `CELL`, `RECTANGLE`, `POLYGON` and `PLACEMENT` is not a partial reader
    /// that drops geometry; it is a total reader over a smaller subset, which
    /// is exactly the shape `gds` already has. The modal state is fully
    /// tracked for the records that *are* modelled, because every record before
    /// an unmodelled one was read.
    ///
    /// What still has to be built, in order: the unsigned and signed
    /// variable-length integer decoder and the seven real types; the modal
    /// variable block and its "unset is an error" rule; the five point-list
    /// encodings and the eleven repetition kinds; then `CBLOCK` (raw deflate,
    /// so its declared uncompressed byte count is the only integrity evidence
    /// there is and must be checked). Flattening is `gds`'s, which is private
    /// to that module and would move up to `layout` alongside `Xform` and
    /// `Library`.
    pub fn read(bytes: &[u8], deck: &Deck, unknown: UnknownLayers) -> Result<Layout, LayoutError> {
        // The signature is `gds::read`'s, frozen, and both of these are read by
        // the reader the upgrade path above describes. Discarded here rather
        // than renamed to `_deck`/`_unknown`, which would put the placeholder
        // spelling in the rendered docs of a function that will take them.
        let _ = (deck, unknown);
        if !detect(bytes) {
            return Err(LayoutError::UnknownFormat);
        }
        let at = u64::try_from(MAGIC.len()).expect("the magic is thirteen bytes");
        // The first record id after the magic, which is precisely the record
        // this reader does not support — as is every other one.
        let id = bytes
            .get(MAGIC.len())
            .copied()
            .ok_or(LayoutError::Truncated(at))?;
        Err(LayoutError::UnsupportedRecord(u16::from(id), at))
    }
}

/// Reader tests, and the GDSII round trip.
///
/// Unit tests rather than integration tests because every one of them needs a
/// populated [`Deck`], and `deck::LayerTable` has private fields, no
/// constructor and no in-memory producer. The fixture lives in `deck`'s own
/// test module; see the note there and `docs/NEED_TESTING.md`.
///
/// The input is assembled byte by byte from the Calma stream format, which is
/// an external specification and therefore an oracle: a record is
/// `(length, tag, payload)` with the length in bytes including the four-byte
/// header, coordinates are 32-bit big-endian, and a BOUNDARY's point list
/// repeats its first point last. Nothing here reads a value out of the code
/// under test.
#[cfg(test)]
mod tests {
    use super::{gds, Deck, Layout, LayoutError, UnknownLayers};
    use crate::deck::tests::{layer_table, ROWS};
    use crate::intern::StrTable;
    use crate::provenance::PathTable;
    use gpurify_core::{Bbox, GeometryStore, LayerId, PolyId};
    use gpurify_testgen::shapes::{Handle, Ids};
    use gpurify_testgen::{dbu, LayoutBuilder};

    const HEADER: u16 = 0x0002;
    const BGNLIB: u16 = 0x0102;
    const LIBNAME: u16 = 0x0206;
    const UNITS: u16 = 0x0305;
    const BGNSTR: u16 = 0x0502;
    const STRNAME: u16 = 0x0606;
    const BOUNDARY: u16 = 0x0800;
    const SREF: u16 = 0x0A00;
    const LAYER: u16 = 0x0D02;
    const DATATYPE: u16 = 0x0E02;
    const XY: u16 = 0x1003;
    const SNAME: u16 = 0x1206;
    const STRANS: u16 = 0x1A01;
    const MAG: u16 = 0x1B05;
    const ANGLE: u16 = 0x1C05;
    const PROPATTR: u16 = 0x2B02;
    const PROPVALUE: u16 = 0x2C06;
    const ENDEL: u16 = 0x1100;
    const ENDSTR: u16 = 0x0700;
    const ENDLIB: u16 = 0x0400;
    const TEXT: u16 = 0x0C00;
    const TEXTTYPE: u16 = 0x1602;
    const PRESENTATION: u16 = 0x1701;
    const STRING: u16 = 0x1906;

    /// `STRANS` bit 0, counting from the most significant as the Feb-87 manual
    /// does: reflect about the X axis before rotating. Spelled here from the
    /// specification rather than imported from the reader, which is the code
    /// under test.
    const REFLECT: u16 = 0x8000;

    /// One BOUNDARY element: a stream pair, an open point list closed by
    /// [`gds_library`] when it writes the XY record, and any property records
    /// that follow it.
    struct Boundary {
        layer: u16,
        datatype: u16,
        xs: Vec<i64>,
        ys: Vec<i64>,
        props: Vec<(i16, String)>,
    }

    fn boundary(layer: u16, datatype: u16, xs: &[i64], ys: &[i64]) -> Boundary {
        assert_eq!(xs.len(), ys.len(), "coordinate columns must be parallel");
        Boundary {
            layer,
            datatype,
            xs: xs.to_vec(),
            ys: ys.to_vec(),
            props: Vec::new(),
        }
    }

    impl Boundary {
        /// Attach one `PROPATTR` / `PROPVALUE` pair, which is what
        /// [`Provenance::props_of`] hands back for the polygon this element
        /// becomes.
        fn tagged(mut self, attribute: i16, value: &str) -> Self {
            self.props.push((attribute, value.to_owned()));
            self
        }
    }

    fn record(out: &mut Vec<u8>, tag: u16, payload: &[u8]) {
        let length = u16::try_from(payload.len() + 4).expect("a GDSII record is under 64 KiB");
        assert!(length % 2 == 0, "GDSII records have an even length");
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(payload);
    }

    /// A GDSII eight-byte real: sign, a seven-bit excess-64 base-sixteen
    /// exponent, and a fifty-six-bit fraction. Only positive values occur in a
    /// UNITS record, so the sign bit is always clear.
    fn gds_real(value: f64) -> [u8; 8] {
        const TWO_POW_56: f64 = 72_057_594_037_927_936.0;
        assert!(value > 0.0, "a GDSII unit is positive");
        let mut exponent = 64i32;
        let mut mantissa = value;
        while mantissa >= 1.0 {
            mantissa /= 16.0;
            exponent += 1;
        }
        while mantissa < 1.0 / 16.0 {
            mantissa *= 16.0;
            exponent -= 1;
        }
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "the mantissa is below one, so the product is below 2^56"
        )]
        let fraction = (mantissa * TWO_POW_56).round() as u64;
        assert!(fraction < 1 << 56, "the fraction overflowed its field");
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "the loops above leave the exponent inside 0..=127"
        )]
        let mut out = [exponent as u8, 0, 0, 0, 0, 0, 0, 0];
        out[1..8].copy_from_slice(&fraction.to_be_bytes()[1..8]);
        out
    }

    /// ASCII payload, NUL-padded to an even length as the format requires.
    fn ascii(text: &str) -> Vec<u8> {
        let mut bytes = text.as_bytes().to_vec();
        if bytes.len() % 2 == 1 {
            bytes.push(0);
        }
        bytes
    }

    /// One `SREF`: the cell placed, the `STRANS` flag word, the rotation in
    /// degrees, and where the child's origin lands in the parent.
    ///
    /// `angle` is stated in degrees because that is what the record holds; a
    /// zero writes no `ANGLE` record at all, which is how the format spells the
    /// default and keeps `gds_real`'s positive-value precondition honest.
    struct Ref {
        cell: &'static str,
        strans: u16,
        angle: f64,
        x: i64,
        y: i64,
        /// Integral, because the reader accepts only integral magnification and
        /// an `i64` cannot be compared against a default with `float_cmp`
        /// looking over your shoulder.
        mag: i64,
    }

    fn sref(cell: &'static str, strans: u16, angle: f64, x: i64, y: i64) -> Ref {
        Ref {
            cell,
            strans,
            angle,
            x,
            y,
            // One is the format's default and writes no MAG record, which keeps
            // `gds_real`'s positive-value precondition honest the same way a
            // zero angle does.
            mag: 1,
        }
    }

    impl Ref {
        /// Attach a `MAG` record. Integral and in `1..=1e6` or the reader
        /// refuses the instance, which is the subset the module doc declares.
        fn magnified(mut self, mag: i64) -> Self {
            self.mag = mag;
            self
        }
    }

    /// A one-cell GDSII library holding the given boundaries.
    ///
    /// The UNITS record states a one-micrometre user unit over a one-nanometre
    /// database unit, which is the thousand-database-units-per-micrometre grid
    /// every test in this module works on.
    fn gds_library(cell: &str, elements: &[Boundary]) -> Vec<u8> {
        gds_hierarchy(&[(cell, elements, &[])])
    }

    /// A GDSII library of several cells, each holding boundaries and `SREF`s.
    ///
    /// The reader takes every cell nothing references as a root, so the
    /// hierarchy is stated entirely by which names appear in which `SREF` list;
    /// a caller wanting one root gives exactly one cell no other cell places.
    fn gds_hierarchy(cells: &[(&str, &[Boundary], &[Ref])]) -> Vec<u8> {
        let mut out = Vec::new();
        record(&mut out, HEADER, &600u16.to_be_bytes());
        record(&mut out, BGNLIB, &[0u8; 24]);
        record(&mut out, LIBNAME, &ascii("GPURIFY.DB"));
        let mut units = Vec::with_capacity(16);
        units.extend_from_slice(&gds_real(1e-3));
        units.extend_from_slice(&gds_real(1e-9));
        record(&mut out, UNITS, &units);

        for (cell, elements, refs) in cells {
            record(&mut out, BGNSTR, &[0u8; 24]);
            record(&mut out, STRNAME, &ascii(cell));
            for element in *elements {
                record(&mut out, BOUNDARY, &[]);
                record(&mut out, LAYER, &element.layer.to_be_bytes());
                record(&mut out, DATATYPE, &element.datatype.to_be_bytes());
                let mut xy = Vec::with_capacity((element.xs.len() + 1) * 8);
                for (&x, &y) in element.xs.iter().zip(&element.ys) {
                    let x = i32::try_from(x).expect("test coordinates fit a GDSII coordinate");
                    let y = i32::try_from(y).expect("test coordinates fit a GDSII coordinate");
                    xy.extend_from_slice(&x.to_be_bytes());
                    xy.extend_from_slice(&y.to_be_bytes());
                }
                // A BOUNDARY's point list closes by repeating its first point.
                xy.extend_from_within(0..8);
                record(&mut out, XY, &xy);
                // Properties follow the geometry and precede ENDEL, one PROPATTR
                // and one PROPVALUE per pair.
                for (attribute, value) in &element.props {
                    record(&mut out, PROPATTR, &attribute.to_be_bytes());
                    record(&mut out, PROPVALUE, &ascii(value));
                }
                record(&mut out, ENDEL, &[]);
            }
            // The format's order inside an SREF: the name, then the optional
            // transform records, then the single point the origin lands on.
            for reference in *refs {
                record(&mut out, SREF, &[]);
                record(&mut out, SNAME, &ascii(reference.cell));
                if reference.strans != 0 {
                    record(&mut out, STRANS, &reference.strans.to_be_bytes());
                }
                // `<strans> ::= STRANS [MAG] [ANGLE]`, so MAG sits between the
                // flag word and the rotation.
                if reference.mag != 1 {
                    let mag = i32::try_from(reference.mag).expect("a test magnification fits an i32");
                    record(&mut out, MAG, &gds_real(f64::from(mag)));
                }
                if reference.angle != 0.0 {
                    record(&mut out, ANGLE, &gds_real(reference.angle));
                }
                let x = i32::try_from(reference.x).expect("test coordinates fit a GDSII coordinate");
                let y = i32::try_from(reference.y).expect("test coordinates fit a GDSII coordinate");
                let mut xy = Vec::with_capacity(8);
                xy.extend_from_slice(&x.to_be_bytes());
                xy.extend_from_slice(&y.to_be_bytes());
                record(&mut out, XY, &xy);
                record(&mut out, ENDEL, &[]);
            }
            record(&mut out, ENDSTR, &[]);
        }
        record(&mut out, ENDLIB, &[]);
        out
    }

    /// A deck holding nothing but the three layers in `ROWS`.
    fn three_layer_deck(strings: &mut StrTable) -> Deck {
        Deck {
            layers: layer_table(strings, &ROWS),
            ..Deck::default()
        }
    }

    /// One `TEXT` element: a stream pair, one point, and the name.
    struct Label {
        layer: u16,
        texttype: u16,
        x: i64,
        y: i64,
        string: &'static str,
    }

    fn label(layer: u16, texttype: u16, x: i64, y: i64, string: &'static str) -> Label {
        Label {
            layer,
            texttype,
            x,
            y,
            string,
        }
    }

    /// A one-cell library of boundaries and `TEXT`s.
    ///
    /// Written out here rather than folded into [`gds_hierarchy`] because the
    /// record order inside a `TEXT` is its own: the Feb-87 grammar is
    /// `TEXT [ELFLAGS] [PLEX] LAYER TEXTTYPE [PRESENTATION] [PATHTYPE] [WIDTH]
    /// [<strans>] XY STRING`, so `TEXTTYPE` follows `LAYER` where a `BOUNDARY`
    /// has `DATATYPE`, and `STRING` comes after the point rather than before
    /// it. Assembled from the specification, not from the reader.
    fn gds_labelled(cell: &str, elements: &[Boundary], labels: &[Label]) -> Vec<u8> {
        let mut out = gds_hierarchy(&[(cell, elements, &[])]);
        // `gds_hierarchy` closed the cell and the library; splice the texts in
        // before that ENDSTR by rebuilding the tail. Cheaper to state: the two
        // closing records are eight bytes, and re-emitting them after the text
        // block is the whole edit.
        let tail = out.len() - 8;
        let texts = text_records(labels);
        out.splice(tail..tail, texts);
        out
    }

    /// The `TEXT` element block for a run of labels, ready to splice in front of
    /// whichever cell's `ENDSTR` should own them.
    fn text_records(labels: &[Label]) -> Vec<u8> {
        let mut texts = Vec::new();
        for label in labels {
            record(&mut texts, TEXT, &[]);
            record(&mut texts, LAYER, &label.layer.to_be_bytes());
            record(&mut texts, TEXTTYPE, &label.texttype.to_be_bytes());
            // Middle-centre justification, font 0 — read and discarded by the
            // reader, present here because a real writer emits it.
            record(&mut texts, PRESENTATION, &0x0005u16.to_be_bytes());
            let x = i32::try_from(label.x).expect("test coordinates fit a GDSII coordinate");
            let y = i32::try_from(label.y).expect("test coordinates fit a GDSII coordinate");
            let mut xy = Vec::with_capacity(8);
            xy.extend_from_slice(&x.to_be_bytes());
            xy.extend_from_slice(&y.to_be_bytes());
            record(&mut texts, XY, &xy);
            record(&mut texts, STRING, &ascii(label.string));
            record(&mut texts, ENDEL, &[]);
        }
        texts
    }

    /// A square boundary of side 400 on the deck's first layer.
    fn first_layer_square() -> Boundary {
        boundary(ROWS[0].1, ROWS[0].2, &[0, 400, 400, 0], &[0, 0, 400, 400])
    }

    /// Its bounding box, stated rather than derived.
    fn first_square_bbox() -> Bbox {
        Bbox {
            xlo: dbu(0),
            ylo: dbu(0),
            xhi: dbu(400),
            yhi: dbu(400),
        }
    }

    /// Compare two stores row by row. `GeometryStore` does not derive
    /// `PartialEq` and should not — its columns are private — so identity is
    /// stated here as the conjunction of everything the store exposes.
    fn assert_same_store(what: &str, left: &GeometryStore, right: &GeometryStore) {
        assert_eq!(
            left.poly_count(),
            right.poly_count(),
            "{what}: polygon counts differ"
        );
        assert_eq!(
            left.layer_count(),
            right.layer_count(),
            "{what}: layer counts differ"
        );
        for layer in 0..u16::try_from(left.layer_count()).expect("a deck has tens of layers") {
            assert_eq!(
                left.polys_on_layer(LayerId(layer)),
                right.polys_on_layer(LayerId(layer)),
                "{what}: layer {layer} holds a different row range"
            );
        }
        for row in 0..u32::try_from(left.poly_count()).expect("test stores are small") {
            let poly = PolyId(row);
            assert_eq!(
                left.poly_layer(poly),
                right.poly_layer(poly),
                "{what}: {poly:?} is on a different layer"
            );
            assert_eq!(
                left.poly_bbox(poly),
                right.poly_bbox(poly),
                "{what}: {poly:?} has a different bounding box"
            );
            assert_eq!(
                left.poly_verts(poly),
                right.poly_verts(poly),
                "{what}: {poly:?} has different coordinates"
            );
        }
    }

    /// One layout, stated twice: as the store `core`'s builder makes of it, and
    /// as the GDSII library the format specification says holds it.
    ///
    /// Two rectangles, an L and a plus, on all three layers and pushed in an
    /// order that is not grouped by layer, so the store's layer sort has work
    /// to do. The non-convex shapes are there because a reader that emitted a
    /// bounding box instead of a point list would reproduce a rectangle
    /// perfectly.
    /// `Ids` and the handles come back alongside so a caller can ask which
    /// store row each element became — which is the whole of the permutation
    /// invariant and is not readable from the store.
    fn corpus() -> (GeometryStore, Ids, Vec<Handle>, Vec<Boundary>) {
        use gpurify_testgen::shapes::{l_shape, plus_shape, rect};
        let shapes = [
            (0usize, rect(0, 0, 400, 400)),
            (2, l_shape(1_000, 0, 600, 200)),
            (1, rect(2_000, 100, 2_180, 280)),
            (0, plus_shape(4_000, 4_000, 500, 120)),
        ];

        let mut layout = LayoutBuilder::new(ROWS.len());
        let mut elements = Vec::with_capacity(shapes.len());
        let mut handles = Vec::with_capacity(shapes.len());
        for (layer, shape) in &shapes {
            handles.push(layout.shape(
                LayerId(u16::try_from(*layer).expect("three layers")),
                shape,
            ));
            elements.push(boundary(ROWS[*layer].1, ROWS[*layer].2, &shape.0, &shape.1));
        }
        let (store, ids) = layout.finish();
        (store, ids, handles, elements)
    }

    /// Oracle: construct-from-answer. One rectangle is written into the file at
    /// coordinates the test chose, so the store the reader produces has a known
    /// answer down to the vertex. This is the assertion the old suite never
    /// made: not "one polygon was read" but "this polygon, on this layer, at
    /// these four points".
    #[test]
    fn a_boundary_reads_back_on_the_layer_and_at_the_coordinates_it_was_written_at() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_library("TOP", &[first_layer_square()]);

        let layout = gds::read(&bytes, &deck, UnknownLayers::Reject).expect("a well-formed library");

        assert_eq!(layout.store.poly_count(), 1);
        assert_eq!(
            layout.store.layer_count(),
            ROWS.len(),
            "the layer count comes from the deck, so a layer with no geometry \
             still has an empty range"
        );
        assert_eq!(layout.store.poly_layer(PolyId(0)), LayerId(0));
        assert_eq!(
            layout.store.poly_verts(PolyId(0)),
            (
                [dbu(0), dbu(400), dbu(400), dbu(0)].as_slice(),
                [dbu(0), dbu(0), dbu(400), dbu(400)].as_slice()
            ),
            "the closing point a BOUNDARY repeats belongs to the file format, \
             not to the store"
        );
        assert_eq!(layout.store.poly_bbox(PolyId(0)), first_square_bbox());
        assert_eq!(
            layout.provenance.path_of(PolyId(0)),
            PathTable::ROOT,
            "a shape in the top cell came from no instance"
        );
    }

    /// Oracle: construct-from-answer. The file declares one shape on a layer
    /// the deck knows and one on a layer it does not, so both settings have an
    /// answer stated in advance: `Reject` names the undeclared stream pair,
    /// `Drop` keeps exactly the shape that was declared. A reader that invented
    /// a layer for the stray pair would pass a count-only test and fail this.
    #[test]
    fn an_undeclared_layer_is_refused_under_reject_and_dropped_under_drop() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_library(
            "TOP",
            &[
                first_layer_square(),
                boundary(99, 7, &[900, 1_300, 1_300, 900], &[0, 0, 400, 400]),
            ],
        );

        match gds::read(&bytes, &deck, UnknownLayers::Reject) {
            Err(LayoutError::UnknownLayer(99, 7)) => {}
            other => panic!(
                "an undeclared stream pair under Reject produced {:?} rather than \
                 UnknownLayer(99, 7)",
                other.map(|l| l.store.poly_count())
            ),
        }

        let dropped = gds::read(&bytes, &deck, UnknownLayers::Drop).expect("Drop never refuses");
        assert_eq!(
            dropped.store.poly_count(),
            1,
            "Drop kept a shape on a layer the deck does not declare, or dropped \
             one it does"
        );
        assert_eq!(dropped.store.poly_layer(PolyId(0)), LayerId(0));
        assert_eq!(
            dropped.store.poly_bbox(PolyId(0)),
            first_square_bbox(),
            "the surviving shape is not the one that was on a declared layer"
        );
    }

    /// Oracle: law. `UnknownLayers` is documented as not being a correctness
    /// switch — both settings verify identically. Where every layer in the file
    /// is declared there is nothing to drop, so the two must produce the same
    /// store for any such input.
    #[test]
    fn the_two_unknown_layer_settings_agree_when_every_layer_is_declared() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_library(
            "TOP",
            &[
                first_layer_square(),
                boundary(
                    ROWS[1].1,
                    ROWS[1].2,
                    &[900, 1_300, 1_300, 900],
                    &[0, 0, 400, 400],
                ),
                boundary(
                    ROWS[2].1,
                    ROWS[2].2,
                    &[0, 200, 200, 0],
                    &[900, 900, 1_100, 1_100],
                ),
            ],
        );

        let rejecting = gds::read(&bytes, &deck, UnknownLayers::Reject).expect("all layers known");
        let dropping = gds::read(&bytes, &deck, UnknownLayers::Drop).expect("all layers known");
        assert_eq!(rejecting.store.poly_count(), 3);
        assert_same_store("Reject against Drop", &rejecting.store, &dropping.store);
    }

    /// Oracle: construct-from-answer. A record whose declared length runs past
    /// the end of the file is a truncation, and the reader is documented as
    /// saying where. Cutting the final byte off a valid library is the smallest
    /// input with that property, and the offset reported has to land inside the
    /// file the reader was given.
    #[test]
    fn a_record_running_past_the_end_of_the_file_is_a_truncation_not_a_short_read() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let mut bytes = gds_library("TOP", &[first_layer_square()]);
        bytes.pop().expect("the library is not empty");

        match gds::read(&bytes, &deck, UnknownLayers::Reject) {
            Err(LayoutError::Truncated(at)) => assert!(
                at <= bytes.len() as u64,
                "the truncation was reported at byte {at}, past the {} the file has",
                bytes.len()
            ),
            other => panic!(
                "a truncated library produced {:?} rather than Truncated",
                other.map(|l| l.store.poly_count())
            ),
        }
    }

    /// Oracle: construct-from-answer. The same four shapes are stated twice —
    /// once as the store `GeometryStoreBuilder` makes of them and once as the
    /// GDSII library the format specification says holds them — and the reader
    /// has to turn the second into the first, vertex by vertex.
    ///
    /// This is what survives of the round-trip law. `parse -> write -> parse`
    /// cannot be written: `export::gds::write_store` takes a `&LayerTable`, and
    /// a `LayerTable` can only be built inside this crate, where the
    /// dev-dependency cycle makes it a different type from the one `export`
    /// links against. Both halves of that are recorded in
    /// `docs/NEED_TESTING.md`. What is lost is the writer; what the law was
    /// really buying — that the reader reproduces a store stated independently
    /// of it — is what the assertion below makes, and it makes it against the
    /// format specification rather than against this workspace's own writer,
    /// which is the stronger oracle of the two.
    ///
    /// Asserting the whole store also pins the reader's *push* order: both
    /// paths interleave layers across the same `GeometryStoreBuilder::finish`,
    /// so the two agree row for row exactly when the reader pushes elements in
    /// file order. It does not pin the sort itself as stable — an unstable sort
    /// agrees with itself — and nothing here should be read as requiring one.
    #[test]
    fn a_library_holding_a_known_layout_reads_back_as_that_exact_store() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let (expected, _, _, elements) = corpus();
        let bytes = gds_library("TOP", &elements);

        let read = gds::read(&bytes, &deck, UnknownLayers::Reject)
            .expect("a library built to the format specification");
        assert_eq!(read.store.poly_count(), elements.len());
        assert_same_store("a known layout read from GDSII", &expected, &read.store);
    }

    /// Oracle: construct-from-answer, on the invariant `crate`'s module doc
    /// calls out by name: provenance is accumulated in file order and must be
    /// permuted into store order, or every violation is reported against the
    /// wrong cell.
    ///
    /// Each element carries a `PROPATTR` / `PROPVALUE` pair naming its position
    /// in the file, which is the only per-polygon annotation a flat library can
    /// carry — hierarchy paths need an SREF, and `Provenance::props` exists for
    /// exactly this stream data. `Ids` says which store row each element became,
    /// so the expected property of every row is known before the read. The
    /// corpus interleaves layers, so the permutation is not the identity and a
    /// reader that skipped `Provenance::permute` reads its neighbour's tag.
    #[test]
    fn each_polygons_stream_properties_follow_it_through_the_layer_sort() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let (_, ids, handles, elements) = corpus();
        let tagged: Vec<Boundary> = elements
            .into_iter()
            .enumerate()
            .map(|(file_row, element)| {
                let attribute = i16::try_from(file_row + 1).expect("four elements");
                element.tagged(attribute, &format!("element_{file_row}"))
            })
            .collect();
        let bytes = gds_library("TOP", &tagged);

        let rows: Vec<PolyId> = handles.iter().map(|&h| ids.of(h)).collect();
        assert!(
            rows.iter()
                .enumerate()
                .any(|(file_row, poly)| u32::try_from(file_row).expect("four elements") != poly.0),
            "the layer sort left every element where it was, so this test could \
             not tell a permuted provenance table from an unpermuted one"
        );

        let layout = gds::read(&bytes, &deck, UnknownLayers::Reject).expect("well formed");
        for (file_row, &poly) in rows.iter().enumerate() {
            let props = layout.provenance.props_of(poly);
            assert_eq!(
                props.len(),
                1,
                "{poly:?} carries {} properties; the element it came from stated \
                 one",
                props.len()
            );
            assert_eq!(
                props[0].0,
                i16::try_from(file_row + 1).expect("four elements"),
                "{poly:?} came from element {file_row} of the file and carries \
                 another element's property attribute"
            );
            assert_eq!(
                layout.strings.resolve(props[0].1),
                format!("element_{file_row}"),
                "{poly:?} resolves to another element's property value, which is \
                 the wrong cell printed beside every violation on it"
            );
        }
    }

    /// Oracle: construct-from-answer. The dispatcher is the only entry point a
    /// run actually uses, and everything above it tests `gds::read` on bytes,
    /// so what is unchecked is one `match`: a `read_layout` that opened the
    /// file, recognised it as GDSII and then returned `Layout::default()`
    /// satisfies both of its refusal tests. The answer is the store the corpus
    /// was built from, so the dispatch has to reach the reader and hand back
    /// what it produced.
    #[test]
    fn read_layout_dispatches_a_gdsii_file_onto_the_gdsii_reader() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let (expected, _, _, elements) = corpus();
        let path = std::env::temp_dir().join(format!(
            "gpurify-ingest-{}-dispatch.gds",
            std::process::id()
        ));
        std::fs::write(&path, gds_library("TOP", &elements)).expect("scratch write");

        let read = super::read_layout(&path, &deck, UnknownLayers::Reject);
        let _ = std::fs::remove_file(&path);

        let layout = read.expect("a library built to the format specification");
        assert_same_store("a known layout through read_layout", &expected, &layout.store);
    }

    /// Oracle: determinism, which is a gate rather than a test. The same bytes
    /// read twice must produce the same store. `ingest` takes no thread count,
    /// so there is one configuration to run this at rather than two.
    #[test]
    fn reading_the_same_library_twice_produces_the_same_store() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let (_, _, _, elements) = corpus();
        let bytes = gds_library("TOP", &elements);

        let once = gds::read(&bytes, &deck, UnknownLayers::Reject).expect("well formed");
        let twice = gds::read(&bytes, &deck, UnknownLayers::Reject).expect("well formed");
        assert_same_store("the GDSII reader run twice", &once.store, &twice.store);
    }

    /// Oracle: law. A `Layout` carries exactly one provenance row per store
    /// row. That is the invariant the permutation exists to preserve and the
    /// one nothing in the type system holds; reading a flat library puts every
    /// row at the root path, so the check is total over the store.
    #[test]
    fn every_polygon_read_has_a_provenance_row_of_its_own() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_library(
            "TOP",
            &[
                first_layer_square(),
                boundary(
                    ROWS[2].1,
                    ROWS[2].2,
                    &[900, 1_300, 1_300, 900],
                    &[0, 0, 400, 400],
                ),
                boundary(
                    ROWS[1].1,
                    ROWS[1].2,
                    &[0, 200, 200, 0],
                    &[900, 900, 1_100, 1_100],
                ),
            ],
        );

        let layout: Layout = gds::read(&bytes, &deck, UnknownLayers::Reject).expect("well formed");
        assert_eq!(layout.store.poly_count(), 3);
        for row in 0..u32::try_from(layout.store.poly_count()).expect("three shapes") {
            assert_eq!(
                layout.provenance.path_of(PolyId(row)),
                PathTable::ROOT,
                "row {row} has no provenance of its own, so the two tables are \
                 different lengths"
            );
            assert!(
                layout.provenance.props_of(PolyId(row)).is_empty(),
                "row {row} acquired stream properties the file never stated"
            );
        }
    }

    /// The cell every mirroring test below instantiates: a right triangle with
    /// legs 200 and 100 at the cell origin, wound counter-clockwise.
    ///
    /// Chirality is the point. A rectangle is its own mirror image about either
    /// axis, so a reader that dropped the reflection entirely would reproduce
    /// one exactly; a triangle with three distinct vertices and no symmetry
    /// cannot hide a wrong transform, and three vertices is short enough to
    /// state every expected coordinate in the test that wants it.
    fn ccw_triangle() -> Boundary {
        boundary(ROWS[0].1, ROWS[0].2, &[0, 200, 0], &[0, 0, 100])
    }

    /// The vertices of a store row, as a pair of owned columns, so a test can
    /// compare against a literal without borrowing the layout twice.
    fn verts(store: &GeometryStore, row: u32) -> (Vec<i64>, Vec<i64>) {
        let (xs, ys) = store.poly_verts(PolyId(row));
        (
            xs.iter().map(|d| d.raw()).collect(),
            ys.iter().map(|d| d.raw()).collect(),
        )
    }

    /// Oracle: construct-from-answer. `LEAF` is one counter-clockwise triangle;
    /// `TOP` places it twice, once plain and once under `STRANS 0x8000`. GDSII
    /// defines bit 0 as a reflection about the X axis applied *before* the
    /// rotation, so the mirrored copy's coordinates are `(x, −y)` shifted by the
    /// reference point — which is a determinant of −1 and therefore reverses the
    /// ring. Both rows' vertices are stated here in full; the winding equality
    /// is asserted alongside them because it is the property, and the literals
    /// are only one way of reaching it.
    #[test]
    fn a_mirrored_instance_keeps_the_orientation_the_cell_was_drawn_with() {
        use gpurify_core::ops::{winding_of, Winding};

        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_hierarchy(&[
            ("LEAF", &[ccw_triangle()], &[]),
            (
                "TOP",
                &[],
                &[
                    sref("LEAF", 0, 0.0, 0, 0),
                    sref("LEAF", REFLECT, 0.0, 1_000, 0),
                ],
            ),
        ]);

        let layout = gds::read(&bytes, &deck, UnknownLayers::Reject).expect("a well-formed library");
        assert_eq!(
            layout.store.poly_count(),
            2,
            "one row per placement of the leaf cell"
        );

        assert_eq!(
            verts(&layout.store, 0),
            (vec![0, 200, 0], vec![0, 0, 100]),
            "the unmirrored placement is the cell as drawn"
        );
        // (0,0), (200,0), (0,100) under (x, −y) + (1000, 0) is (1000,0),
        // (1200,0), (1000,−100), which is clockwise; the reversal that restores
        // the drawn orientation fixes vertex 0 and turns the rest around.
        assert_eq!(
            verts(&layout.store, 1),
            (vec![1_000, 1_000, 1_200], vec![0, -100, 0]),
            "the mirrored placement did not come back in the reversed order a \
             determinant of −1 requires"
        );

        let (xs, ys) = layout.store.poly_verts(PolyId(0));
        assert_eq!(winding_of(xs, ys), Some(Winding::CounterClockwise), "the cell as drawn");
        let (xs, ys) = layout.store.poly_verts(PolyId(1));
        assert_eq!(
            winding_of(xs, ys),
            Some(Winding::CounterClockwise),
            "a cell's rings must have the same orientation wherever the cell is \
             placed; clockwise here is read downstream as a hole"
        );
    }

    /// Oracle: construct-from-answer, and the answer is the identity. `TOP`
    /// places `MID` mirrored, `MID` places `LEAF` mirrored, and two reflections
    /// compose to a rotation — so the doubly nested copy must be the cell as
    /// drawn, vertex for vertex, including its order. `TOP` also places `LEAF`
    /// directly so the answer sits in the same store as the thing it answers.
    ///
    /// This is the parity path: `Xform::compose` xors the two `flip`s, and any
    /// fix that reversed per level rather than on the composed transform would
    /// reverse this ring twice and pass, or once and fail here.
    #[test]
    fn a_doubly_mirrored_instance_is_the_cell_as_drawn() {
        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_hierarchy(&[
            ("LEAF", &[ccw_triangle()], &[]),
            ("MID", &[], &[sref("LEAF", REFLECT, 0.0, 0, 0)]),
            (
                "TOP",
                &[],
                &[
                    sref("LEAF", 0, 0.0, 0, 0),
                    sref("MID", REFLECT, 0.0, 0, 0),
                ],
            ),
        ]);

        let layout = gds::read(&bytes, &deck, UnknownLayers::Reject).expect("a well-formed library");
        assert_eq!(layout.store.poly_count(), 2);
        assert_eq!(
            verts(&layout.store, 0),
            (vec![0, 200, 0], vec![0, 0, 100]),
            "the direct placement is the cell as drawn"
        );
        assert_eq!(
            verts(&layout.store, 1),
            (vec![0, 200, 0], vec![0, 0, 100]),
            "two reflections compose to the identity, so the nested copy must \
             be indistinguishable from the direct one — order included"
        );
    }

    /// Oracle: construct-from-answer. `TOP` places `LEAF` four times, each
    /// mirrored and rotated by one more quarter turn, at origins 2000 apart so
    /// no two overlap. GDSII applies the reflection first, so the composed
    /// linear part is `R_q · diag(1, −1)`: `(x, −y)`, `(y, x)`, `(−x, y)`,
    /// `(−y, −x)`. Every one of those has determinant −1, so every one of the
    /// four rings reverses — `F·R_q = R_{−q}·F` is where a transform fix most
    /// easily goes wrong, and a fix that keyed off the quadrant rather than the
    /// determinant would get two of these four right.
    ///
    /// The triangle's area is 10000 whichever way it is placed, and the
    /// signed area's sign is the winding, so the stated vertices and the
    /// counter-clockwise assertion are two readings of the same fact.
    #[test]
    fn a_mirror_composed_with_each_quarter_turn_still_flattens_counter_clockwise() {
        use gpurify_core::ops::{winding_of, Winding};

        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_hierarchy(&[
            ("LEAF", &[ccw_triangle()], &[]),
            (
                "TOP",
                &[],
                &[
                    sref("LEAF", REFLECT, 0.0, 0, 0),
                    sref("LEAF", REFLECT, 90.0, 2_000, 0),
                    sref("LEAF", REFLECT, 180.0, 4_000, 0),
                    sref("LEAF", REFLECT, 270.0, 6_000, 0),
                ],
            ),
        ]);

        let layout = gds::read(&bytes, &deck, UnknownLayers::Reject).expect("a well-formed library");
        assert_eq!(layout.store.poly_count(), 4);

        // Each row: the drawn triangle through `R_q · diag(1, −1)`, offset by
        // the reference point, then reversed from vertex 1 on.
        let expected = [
            (vec![0, 0, 200], vec![0, -100, 0]),
            (vec![2_000, 2_100, 2_000], vec![0, 0, 200]),
            (vec![4_000, 4_000, 3_800], vec![0, 100, 0]),
            (vec![6_000, 5_900, 6_000], vec![0, 0, -200]),
        ];
        for (row, want) in expected.into_iter().enumerate() {
            let row = u32::try_from(row).expect("four placements");
            assert_eq!(
                verts(&layout.store, row),
                want,
                "the mirrored placement at quarter turn {row} did not flatten to \
                 the reflected-then-rotated triangle in reversed order"
            );
            let (xs, ys) = layout.store.poly_verts(PolyId(row));
            assert_eq!(
                winding_of(xs, ys),
                Some(Winding::CounterClockwise),
                "quarter turn {row} came back clockwise, which is read \
                 downstream as a hole"
            );
        }
    }

    /// Oracle: construct-from-answer, derived from the GDSII composition rule
    /// rather than from a run. A mirror and a rotation split across *two*
    /// levels of hierarchy, in both orders — the case the corpus exercises only
    /// through `DRC_HIER_NEST`, inside a test that is red for unrelated reasons
    /// and therefore gates nothing.
    ///
    /// The two orders are **not** the same transform, and that is the point.
    /// GDSII applies a reference's reflection before its rotation, so composing
    /// parent over child gives:
    ///
    /// - mirrored parent over a child rotated a quarter turn:
    ///   `F · R₉₀ · p = F · (−y, x) = (−y, −x)`
    /// - a parent rotated a quarter turn over a mirrored child:
    ///   `R₉₀ · F · p = R₉₀ · (x, −y) = (y, x)`
    ///
    /// Those are negatives of each other, which is `F · R_q = R_{−q} · F` seen
    /// from outside: [`Xform::compose`] negates the child's quadrant when the
    /// parent flips, and a composition that instead *added* the quadrants would
    /// give both placements the same answer and pass a test that checked only
    /// one of them. Both determinants are −1 — exactly one flip survives either
    /// composition — so both rings reverse.
    ///
    /// The `assert_ne!` is the one carrying the asymmetry: it fails if the two
    /// orders are ever collapsed into one, whatever else stays right.
    #[test]
    fn a_mirror_and_a_rotation_split_across_two_levels_do_not_commute() {
        use gpurify_core::ops::{winding_of, Winding};

        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);
        let bytes = gds_hierarchy(&[
            ("LEAF", &[ccw_triangle()], &[]),
            // A rotated child, to sit under a mirrored parent.
            ("ROTATED", &[], &[sref("LEAF", 0, 90.0, 0, 0)]),
            // A mirrored child, to sit under a rotated parent.
            ("MIRRORED", &[], &[sref("LEAF", REFLECT, 0.0, 0, 0)]),
            (
                "TOP",
                &[],
                &[
                    sref("ROTATED", REFLECT, 0.0, 0, 0),
                    sref("MIRRORED", 0, 90.0, 5_000, 0),
                ],
            ),
        ]);

        let layout =
            gds::read(&bytes, &deck, UnknownLayers::Reject).expect("a well-formed library");
        assert_eq!(layout.store.poly_count(), 2, "one row per leaf placement");

        // (0,0), (200,0), (0,100) through `(−y, −x)` is (0,0), (0,−200),
        // (−100,0) — clockwise — so the reversal fixes vertex 0 and turns the
        // rest around.
        let mirrored_parent = verts(&layout.store, 0);
        assert_eq!(
            mirrored_parent,
            (vec![0, -100, 0], vec![0, 0, -200]),
            "a mirrored parent over a rotated child did not flatten to \
             `F · R₉₀` in reversed order"
        );

        // Through `(y, x)`, offset by (5000, 0): (5000,0), (5000,200),
        // (5100,0) — also clockwise, also reversed.
        let rotated_parent = verts(&layout.store, 1);
        assert_eq!(
            rotated_parent,
            (vec![5_000, 5_100, 5_000], vec![0, 0, 200]),
            "a rotated parent over a mirrored child did not flatten to \
             `R₉₀ · F` in reversed order"
        );

        // The asymmetry, stated independently of the literals above: translate
        // each to its own first vertex and the two shapes still differ, because
        // `(−y, −x)` and `(y, x)` are negatives rather than a translation apart.
        let relative = |(xs, ys): &(Vec<i64>, Vec<i64>)| -> Vec<(i64, i64)> {
            xs.iter()
                .zip(ys)
                .map(|(x, y)| (x - xs[0], y - ys[0]))
                .collect()
        };
        assert_ne!(
            relative(&mirrored_parent),
            relative(&rotated_parent),
            "`F · R_q` and `R_q · F` produced the same shape; the two orders \
             have been collapsed and one of them is now wrong"
        );

        for (row, order) in [(0u32, "mirrored parent"), (1, "rotated parent")] {
            let (xs, ys) = layout.store.poly_verts(PolyId(row));
            assert_eq!(
                winding_of(xs, ys),
                Some(Winding::CounterClockwise),
                "{order}: a cell's rings keep the orientation they were drawn \
                 with however deep the mirror sits; clockwise is read \
                 downstream as a hole"
            );
        }
    }

    /// The stream pairs sky130 actually uses, so the fixture is not a made-up
    /// numbering: `met1.drawing` is 68/20 and `met1.label` is 68/5.
    const LABEL_ROWS: [(&str, u16, u16); 2] = [("met1", 68, 20), ("met1_label", 68, 5)];

    /// A deck whose `met1_label` layer names `met1`, which is the pairing
    /// `connectivity.labels` carries and the only thing that makes a `TEXT` a
    /// net label rather than documentation.
    fn labelling_deck(strings: &mut StrTable) -> Deck {
        let layers = layer_table(strings, &LABEL_ROWS);
        let met1 = layers.of_stream(68, 20).expect("the fixture declares met1");
        let text = layers.of_stream(68, 5).expect("the fixture declares met1_label");
        Deck {
            connectivity: crate::deck::Connectivity {
                conductors: vec![met1],
                label_layer: vec![text],
                label_names: vec![met1],
                ..crate::deck::Connectivity::default()
            },
            layers,
            ..Deck::default()
        }
    }

    /// One 400-square of met1 at the origin, the shape every label test below
    /// aims at.
    fn met1_square() -> Boundary {
        boundary(68, 20, &[0, 400, 400, 0], &[0, 0, 400, 400])
    }

    /// Read a library and bind its labels, returning the resolved column.
    fn bound_labels(bytes: &[u8], deck: &Deck) -> Result<Vec<(PolyId, String)>, crate::LabelError> {
        let mut layout = gds::read(bytes, deck, UnknownLayers::Reject).expect("a well-formed library");
        layout
            .provenance
            .resolve_labels(&layout.store, &deck.connectivity)?;
        Ok(layout
            .provenance
            .labels()
            .iter()
            .map(|&(poly, name)| (poly, layout.strings.resolve(name).to_owned()))
            .collect())
    }

    /// Oracle: construct-from-answer. The label is written at a point the test
    /// chose, inside a square the test chose, so which polygon it must name is
    /// known before the reader runs.
    ///
    /// This is the path that did not exist: the reader skipped every `TEXT`, so
    /// `Provenance::label` had no production caller, `PortTable` was empty in
    /// every real run, and with it every net name — which made the SPEF and
    /// DSPF writers return `UnnamedNet` and the engine's field-solve path,
    /// which selects nets *by name*, unreachable.
    #[test]
    fn a_text_inside_a_shape_names_the_net_that_shape_is_on() {
        let mut strings = StrTable::default();
        let deck = labelling_deck(&mut strings);
        let bytes = gds_labelled("TOP", &[met1_square()], &[label(68, 5, 200, 200, "VDD")]);

        let bound = bound_labels(&bytes, &deck).expect("the label sits on the square");

        assert_eq!(
            bound,
            vec![(PolyId(0), "VDD".to_owned())],
            "the one text drawn inside the one square names it"
        );
    }

    /// Oracle: law. The boundary counts as inside.
    ///
    /// Not an edge case in this domain: GDSII fixes no relationship between a
    /// `TEXT` and a shape, so the convention is the tool's, and every
    /// established one treats an on-edge label as attached — `KLayout` states it
    /// as "inside or on the edge of". Pin labels are routinely written at a
    /// rectangle's corner or the midpoint of an edge, so a strict-interior test
    /// would silently drop them and leave the net unnamed.
    ///
    /// All four cases the half-open ray cast alone answers `false` for: a point
    /// on a horizontal edge, on a vertical edge, and on two of the corners.
    #[test]
    fn a_text_on_a_shapes_edge_or_corner_still_names_it() {
        let mut strings = StrTable::default();
        let deck = labelling_deck(&mut strings);

        for (x, y, where_it_is) in [
            (200, 0, "the midpoint of the bottom edge"),
            (0, 200, "the midpoint of the left edge"),
            (400, 200, "the midpoint of the right edge"),
            (0, 0, "the lower-left corner"),
            (400, 400, "the upper-right corner"),
        ] {
            let bytes = gds_labelled("TOP", &[met1_square()], &[label(68, 5, x, y, "VDD")]);
            let bound = bound_labels(&bytes, &deck).unwrap_or_else(|why| {
                panic!("a label at {where_it_is} must bind, not refuse: {why}")
            });
            assert_eq!(
                bound,
                vec![(PolyId(0), "VDD".to_owned())],
                "a label at {where_it_is} is on the conductor"
            );
        }
    }

    /// Oracle: law. A text on a layer no `connectivity.labels` row pairs is
    /// documentation, not a net label, and is passed over in silence.
    ///
    /// The distinction is the whole reason the pairing is a deck table: the
    /// GDSII specification contains no rule relating a `TEXT` to a shape — the
    /// words *net*, *pin*, *port* and *connectivity* do not appear in it — so
    /// nothing about the file itself says which texts are names.
    #[test]
    fn a_text_on_an_unpaired_layer_is_documentation_and_binds_nothing() {
        let mut strings = StrTable::default();
        // met1's own drawing layer is declared, and deliberately *not* paired.
        let deck = labelling_deck(&mut strings);
        let bytes = gds_labelled("TOP", &[met1_square()], &[label(68, 20, 200, 200, "a note")]);

        let bound = bound_labels(&bytes, &deck).expect("an unpaired text is not a fault");

        assert!(
            bound.is_empty(),
            "a text the deck does not pair names nothing, and must not be \
             guessed onto the shape it happens to sit on"
        );
    }

    /// Oracle: law. A label the deck *claims* that lands on no shape is
    /// refused, not dropped.
    ///
    /// Fail closed, and the direction matters: a dropped label leaves the net
    /// with its geometry and without its name, and an unnamed net reads
    /// downstream as a net nobody labelled rather than as a label nobody could
    /// place. Real flows agree — GF180MCU's layer table says its label layers
    /// are used "for any wrong placement of label check".
    #[test]
    fn a_claimed_label_on_no_shape_is_refused_rather_than_dropped() {
        let mut strings = StrTable::default();
        let deck = labelling_deck(&mut strings);
        // Well clear of the square, which spans 0..400 on both axes.
        let bytes = gds_labelled("TOP", &[met1_square()], &[label(68, 5, 9_000, 9_000, "VDD")]);

        match bound_labels(&bytes, &deck) {
            Err(crate::LabelError::Unplaced { x, y, .. }) => {
                assert_eq!((x, y), (9_000, 9_000), "the refusal names where the label was");
            }
            Ok(bound) => panic!("a misplaced label was accepted, binding {bound:?}"),
        }
    }

    /// Oracle: law. A label under a mirrored instance moves with the geometry
    /// it names.
    ///
    /// The regression this file already had for rings and did not have for
    /// points.
    ///
    /// **The translation is what gives the test its teeth.** The child draws
    /// its square at y 0..400 and labels the point (200, 200); the parent
    /// places the cell mirrored about X and shifted up by 1000, so `y ↦ 1000 −
    /// y` and the placed square spans y 600..1000 with the label at (200, 800).
    /// The *untransformed* point (200, 200) is nowhere near that square, so a
    /// reader that left the label in the child's frame refuses it as
    /// `Unplaced`. A shift of 400 would have been worthless: the square would
    /// land back on 0..400 and (200, 200) is a fixed point of `y ↦ 400 − y`, so
    /// the test would pass with the transform dropped entirely.
    #[test]
    fn a_label_under_a_mirrored_instance_moves_with_the_shape_it_names() {
        let mut strings = StrTable::default();
        let deck = labelling_deck(&mut strings);

        let mut bytes = gds_hierarchy(&[
            ("CHILD", &[met1_square()], &[]),
            ("TOP", &[], &[sref("CHILD", REFLECT, 0.0, 0, 1000)]),
        ]);
        // The label belongs to CHILD, so it is spliced into the first cell —
        // whose ENDSTR is the record before TOP's BGNSTR.
        let child_end = find_first_endstr(&bytes);
        let mut texts = Vec::new();
        record(&mut texts, TEXT, &[]);
        record(&mut texts, LAYER, &68u16.to_be_bytes());
        record(&mut texts, TEXTTYPE, &5u16.to_be_bytes());
        let mut xy = Vec::with_capacity(8);
        xy.extend_from_slice(&200i32.to_be_bytes());
        xy.extend_from_slice(&200i32.to_be_bytes());
        record(&mut texts, XY, &xy);
        record(&mut texts, STRING, &ascii("VDD"));
        record(&mut texts, ENDEL, &[]);
        bytes.splice(child_end..child_end, texts);

        let bound = bound_labels(&bytes, &deck)
            .expect("the label is mirrored onto the square exactly as the square is");

        assert_eq!(
            bound,
            vec![(PolyId(0), "VDD".to_owned())],
            "a point under a mirrored instance takes the instance transform, \
             the same as every vertex of the shape it names"
        );
    }

    /// The byte offset of the first `ENDSTR` record, which is where a label
    /// belonging to the first cell has to be spliced.
    fn find_first_endstr(bytes: &[u8]) -> usize {
        let mut at = 0;
        while at + 4 <= bytes.len() {
            let len = usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
            let tag = u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]);
            assert!(len >= 4, "a GDSII record carries its own header");
            if tag == ENDSTR {
                return at;
            }
            at += len;
        }
        panic!("the fixture library has no ENDSTR");
    }

    // ------------------------------------------ global transform equivariance

    /// One representable instance transform, `W(p) = mag · R_q · Fʳ · p + (dx, dy)`.
    ///
    /// A test-local restatement of what the format allows, deliberately *not*
    /// [`super::gds::Xform`]: the law below computes its expected answer with
    /// [`Warp::apply`], and an expected answer computed with the function under
    /// test asserts nothing.
    #[derive(Clone, Copy)]
    struct Warp {
        mag: i64,
        reflect: bool,
        quarters: u8,
        dx: i64,
        dy: i64,
    }

    impl Warp {
        /// Apply it, spelled from the Feb-87 manual in the order the manual
        /// states.
        ///
        /// `STRANS` bit 0 is a reflection about the X axis — `(x, y) ↦ (x, −y)`
        /// — and it runs **before** the `ANGLE` rotation, which is
        /// counter-clockwise: `R₉₀(x, y) = (−y, x)`. Magnification is a scalar
        /// and commutes with both, so it is folded into the last line.
        fn apply(self, x: i64, y: i64) -> (i64, i64) {
            let (x, y) = if self.reflect { (x, -y) } else { (x, y) };
            let (x, y) = match self.quarters {
                0 => (x, y),
                1 => (-y, x),
                2 => (-x, -y),
                3 => (y, -x),
                _ => unreachable!("a quarter turn is 0..=3"),
            };
            (self.mag * x + self.dx, self.mag * y + self.dy)
        }

        /// The `SREF` that carries it.
        fn sref_of(self, cell: &'static str) -> Ref {
            let strans = if self.reflect { REFLECT } else { 0 };
            sref(cell, strans, f64::from(self.quarters) * 90.0, self.dx, self.dy)
                .magnified(self.mag)
        }
    }

    /// The library the equivariance law is stated over, optionally wrapped.
    ///
    /// `LEAF` draws two counter-clockwise rings on two different layers and
    /// carries one `TEXT`. `MID` places `LEAF` **mirrored**. `TOP` draws a ring
    /// of its own, places `LEAF` directly, and places `MID` under a quarter
    /// turn — so the deepest ring arrives through a mirror composed with a
    /// rotation across *two* levels of hierarchy, which `CLAUDE.md` records as
    /// reached today only by a corpus test that is red for unrelated reasons.
    ///
    /// `TOP`'s own ring sits out at `x = 2·10⁶` so that one magnification in the
    /// table below is genuinely unrepresentable rather than merely large.
    ///
    /// Cell order is load-bearing twice: `LEAF` first, so the existing
    /// [`find_first_endstr`] splice point owns its labels, and `TOP` last, so
    /// appending `WRAP` leaves every other cell's bytes byte-identical. `WRAP`
    /// is then the library's only unreferenced cell, which is how the reader
    /// spells "the root".
    fn nested_mirror_library(wrap: Option<Warp>) -> Vec<u8> {
        let leaf = [
            ccw_triangle(),
            boundary(ROWS[1].1, ROWS[1].2, &[0, 120, 120, 0], &[0, 0, 60, 60]),
        ];
        let top = [boundary(
            ROWS[2].1,
            ROWS[2].2,
            &[2_000_000, 2_000_400, 2_000_400, 2_000_000],
            &[0, 0, 400, 400],
        )];
        let mid_refs = [sref("LEAF", REFLECT, 0.0, 300, 0)];
        let top_refs = [sref("LEAF", 0, 0.0, 0, 0), sref("MID", 0, 90.0, 1_000, 0)];
        let wrap_refs: Vec<Ref> = wrap.into_iter().map(|w| w.sref_of("TOP")).collect();

        let mut cells: Vec<(&str, &[Boundary], &[Ref])> = vec![
            ("LEAF", &leaf, &[]),
            ("MID", &[], &mid_refs),
            ("TOP", &top, &top_refs),
        ];
        if !wrap_refs.is_empty() {
            cells.push(("WRAP", &[], &wrap_refs));
        }

        let mut bytes = gds_hierarchy(&cells);
        let at = find_first_endstr(&bytes);
        let texts = text_records(&[label(ROWS[1].1, ROWS[1].2, 60, 20, "N1")]);
        bytes.splice(at..at, texts);
        bytes
    }

    /// The hierarchy path of a store row, resolved to text so two reads with
    /// two independent [`StrTable`]s can be compared.
    fn path_text(layout: &Layout, row: u32) -> Vec<String> {
        let id = layout.provenance.path_of(PolyId(row));
        layout
            .provenance
            .paths()
            .get(id)
            .iter()
            .map(|&component| layout.strings.resolve(component).to_owned())
            .collect()
    }

    /// Oracle: law — global transform equivariance of the whole reader.
    ///
    /// Wrap a library's single root cell in a new outermost cell holding one
    /// `SREF` of it under any representable `W`. Flattening is function
    /// composition, so the result must be the unwrapped result pushed through
    /// `W` and nothing else:
    ///
    /// - **(a)** the row count, each layer's row range and each row's layer are
    ///   untouched — `W` is a bijection of the plane and does not create,
    ///   destroy or re-label a shape. (`layer_count` is deliberately *not*
    ///   asserted: it is `deck.layers.len()`, identical by construction.)
    /// - **(b)** row `i`'s vertices are `W(v_j)` in order when `W` does not
    ///   reflect, and `[W(v₀), W(v_{n−1}), …, W(v₁)]` when it does — vertex 0
    ///   is the fixed point `erc::first_vertex` relies on, and `[1..]` reverses
    ///   because a determinant of −1 flips the winding.
    /// - **(c)** every `PlacedLabel` point becomes `W(p)`, in the same order, on
    ///   the same layer, with the same name.
    /// - **(d)** every row's hierarchy path gains exactly one leading
    ///   component, `TOP`, and nothing else — so the partition of rows by path
    ///   is preserved.
    ///
    /// **Why it holds at arbitrary depth, which is the whole point.** Write the
    /// base row as `v_j = A(u_{σ(j)})`, where `u` is the cell as drawn, `A` is
    /// the composed transform and `σ` is the identity when `A`'s flip parity is
    /// even and the `[1..]` reversal `ρ` when it is odd. Wrapped, the parity is
    /// `p ⊕ r`. When `r = 0` the two parities agree and `v′_j = W(v_j)`. When
    /// `r = 1` they differ, and *either* `σ = id, τ = ρ` *or* `σ = ρ, τ = id`;
    /// because `ρ` is an involution both give `v′_j = W(v_{ρ(j)})`. So the law
    /// is stated over the parity *difference*, never the absolute parity — which
    /// is why the fixture deliberately contains a cell already placed mirrored,
    /// under a rotation, two levels deep.
    ///
    /// A run that comes back `Err(LayoutError::CoordinateOutOfRange(_))` is a
    /// pass — `W` may leave the representable domain — but that is spelled as
    /// that one variant, and the table below asserts every other `W` is
    /// accepted. Otherwise a reader that refused every wrapped library would
    /// satisfy the law, which is exactly the fail-open shape this tree refuses.
    #[test]
    fn wrapping_the_root_in_one_transformed_instance_transforms_the_whole_store() {
        use gpurify_units::MAX_ABS_DBU;

        let mut strings = StrTable::default();
        let deck = three_layer_deck(&mut strings);

        let base = gds::read(&nested_mirror_library(None), &deck, UnknownLayers::Reject)
            .expect("the unwrapped library is well formed");

        // ---- anti-vacuity. Every clause is quantified over rows, layers and
        // labels, so a reader producing none of them satisfies all of them.
        assert_eq!(
            base.store.poly_count(),
            5,
            "the base fixture is one ring in TOP plus two rings under each of \
             the two LEAF placements"
        );
        for layer in 0..3u16 {
            assert!(
                !base.store.polys_on_layer(LayerId(layer)).is_empty(),
                "layer {layer} is empty, so clause (a) has nothing to compare \
                 on it"
            );
        }
        assert_eq!(
            base.provenance.placed_labels().len(),
            2,
            "one TEXT in LEAF and two placements of LEAF, so clause (c) needs \
             two points to move"
        );
        let base_paths: Vec<Vec<String>> = (0..5).map(|row| path_text(&base, row)).collect();
        assert!(
            base_paths.iter().any(Vec::is_empty)
                && base_paths.iter().any(|p| p.len() == 2)
                && base_paths.iter().collect::<std::collections::BTreeSet<_>>().len() == 3,
            "clause (d) is vacuous unless the base already partitions its rows \
             across a root path and a two-deep one: {base_paths:?}"
        );

        // Both rings on layer 0 are the same drawn triangle; they differ only
        // because one arrived through the mirror inside MID composed with TOP's
        // quarter turn. If they were congruent by translation the fixture would
        // no longer exercise the parity path the law's derivation rests on.
        let relative = |(xs, ys): &(Vec<i64>, Vec<i64>)| -> Vec<(i64, i64)> {
            xs.iter().zip(ys).map(|(x, y)| (x - xs[0], y - ys[0])).collect()
        };
        assert_ne!(
            relative(&verts(&base.store, 0)),
            relative(&verts(&base.store, 1)),
            "the two LEAF placements came out congruent by translation, so the \
             base library no longer contains a mirror and the depth half of \
             this law is untested"
        );

        // ---- the transforms. Every one is representable on this fixture, so
        // every one is asserted to be accepted.
        let warps = [
            Warp { mag: 1, reflect: false, quarters: 0, dx: 0, dy: 0 },
            Warp { mag: 1, reflect: false, quarters: 0, dx: -7_000, dy: 3_000 },
            Warp { mag: 1, reflect: true, quarters: 0, dx: 0, dy: 0 },
            Warp { mag: 1, reflect: false, quarters: 1, dx: 0, dy: 0 },
            Warp { mag: 1, reflect: true, quarters: 3, dx: 1_234, dy: -5_678 },
            Warp { mag: 3, reflect: true, quarters: 1, dx: -1_000, dy: 2_000 },
            Warp { mag: 3, reflect: false, quarters: 2, dx: 500, dy: -500 },
        ];
        assert!(
            warps.iter().any(|w| w.reflect)
                && warps.iter().any(|w| !w.reflect)
                && warps.iter().any(|w| w.quarters != 0)
                && warps.iter().any(|w| w.mag > 1),
            "the table has to reach both halves of clause (b), a rotation and a \
             magnification, or it tests translation only"
        );

        for (index, w) in warps.into_iter().enumerate() {
            let what = format!(
                "W#{index} (mag {}, reflect {}, q {}, d ({}, {}))",
                w.mag, w.reflect, w.quarters, w.dx, w.dy
            );
            let wrapped = gds::read(
                &nested_mirror_library(Some(w)),
                &deck,
                UnknownLayers::Reject,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "{what}: every coordinate it produces is inside \
                     ±MAX_ABS_DBU, so refusing it is a defect, not the \
                     out-of-range escape: {e}"
                )
            });

            // (a)
            assert_eq!(
                wrapped.store.poly_count(),
                base.store.poly_count(),
                "{what}: a rigid motion created or destroyed a row"
            );
            for layer in 0..3u16 {
                assert_eq!(
                    wrapped.store.polys_on_layer(LayerId(layer)),
                    base.store.polys_on_layer(LayerId(layer)),
                    "{what}: layer {layer} holds a different row range"
                );
            }

            for row in 0..5u32 {
                assert_eq!(
                    wrapped.store.poly_layer(PolyId(row)),
                    base.store.poly_layer(PolyId(row)),
                    "{what}: row {row} moved to another layer"
                );

                // (b)
                let (bxs, bys) = verts(&base.store, row);
                let n = bxs.len();
                let order: Vec<usize> = if w.reflect {
                    std::iter::once(0).chain((1..n).rev()).collect()
                } else {
                    (0..n).collect()
                };
                let want: (Vec<i64>, Vec<i64>) =
                    order.iter().map(|&j| w.apply(bxs[j], bys[j])).unzip();
                assert_eq!(
                    verts(&wrapped.store, row),
                    want,
                    "{what}: row {row} is not the base row through W; a \
                     reflecting W reverses [1..] and fixes vertex 0, and \
                     nothing else may move"
                );
            }

            // (c)
            let (before, after) = (
                base.provenance.placed_labels(),
                wrapped.provenance.placed_labels(),
            );
            assert_eq!(
                after.len(),
                before.len(),
                "{what}: the label count changed"
            );
            for (row, (b, a)) in before.iter().zip(after).enumerate() {
                let (x, y) = w.apply(b.at.x.raw(), b.at.y.raw());
                assert_eq!(
                    (a.at.x.raw(), a.at.y.raw()),
                    (x, y),
                    "{what}: label {row} did not take the same transform its \
                     geometry took"
                );
                assert_eq!(a.layer, b.layer, "{what}: label {row} changed layer");
                assert_eq!(
                    wrapped.strings.resolve(a.name),
                    base.strings.resolve(b.name),
                    "{what}: label {row} changed name"
                );
            }

            // (d)
            for row in 0..5u32 {
                let mut want = vec!["TOP".to_owned()];
                want.extend_from_slice(&base_paths[row as usize]);
                assert_eq!(
                    path_text(&wrapped, row),
                    want,
                    "{what}: row {row}'s path is not the base path with exactly \
                     one leading component"
                );
            }
        }

        // ---- and the escape is real, not a blanket. TOP draws a ring at
        // x = 2·10⁶, so a magnification of 10⁶ lands it at 2·10¹², past
        // MAX_ABS_DBU = 2⁴⁰ ≈ 1.0995·10¹². `CoordinateOutOfRange` specifically:
        // any other error would mean the reader refused for the wrong reason.
        let overflow = Warp { mag: 1_000_000, reflect: false, quarters: 0, dx: 0, dy: 0 };
        match gds::read(
            &nested_mirror_library(Some(overflow)),
            &deck,
            UnknownLayers::Reject,
        ) {
            Err(LayoutError::CoordinateOutOfRange(value)) => assert!(
                value.unsigned_abs() > MAX_ABS_DBU.unsigned_abs(),
                "the reported coordinate {value} is inside the domain it was \
                 refused for"
            ),
            other => panic!(
                "a magnification that leaves the representable domain must be \
                 refused as CoordinateOutOfRange, not as {other:?}"
            ),
        }
    }
}
