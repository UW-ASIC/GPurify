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

use crate::deck::Deck;
use crate::intern::StrTable;
use crate::provenance::Provenance;
use gpurify_core::GeometryStore;

/// Everything a verification run needs from a layout file.
#[derive(Debug, Default)]
pub struct Layout {
    pub store: GeometryStore,
    pub provenance: Provenance,
    pub strings: StrTable,
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
    /// Drop, and report how many rows were dropped. Never silent.
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
    todo!()
}

/// GDSII.
///
/// A record stream of `(length, tag, payload)`. Record tags are a small dense
/// `u16` space known at compile time, so dispatch is an array index, not a map.
pub mod gds {
    use super::{Deck, Layout, LayoutError, UnknownLayers};

    /// True when the byte prefix is a GDSII header record.
    pub fn detect(prefix: &[u8]) -> bool {
        todo!()
    }

    pub fn read(
        bytes: &[u8],
        deck: &Deck,
        unknown: UnknownLayers,
    ) -> Result<Layout, LayoutError> {
        todo!()
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

    pub fn detect(prefix: &[u8]) -> bool {
        todo!()
    }

    pub fn read(
        bytes: &[u8],
        deck: &Deck,
        unknown: UnknownLayers,
    ) -> Result<Layout, LayoutError> {
        todo!()
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
    const LAYER: u16 = 0x0D02;
    const DATATYPE: u16 = 0x0E02;
    const XY: u16 = 0x1003;
    const PROPATTR: u16 = 0x2B02;
    const PROPVALUE: u16 = 0x2C06;
    const ENDEL: u16 = 0x1100;
    const ENDSTR: u16 = 0x0700;
    const ENDLIB: u16 = 0x0400;

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
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "the mantissa is below one, so the product is below 2^56"
        )]
        let fraction = (mantissa * TWO_POW_56).round() as u64;
        assert!(fraction < 1 << 56, "the fraction overflowed its field");
        #[allow(
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

    /// A one-cell GDSII library holding the given boundaries.
    ///
    /// The UNITS record states a one-micrometre user unit over a one-nanometre
    /// database unit, which is the thousand-database-units-per-micrometre grid
    /// every test in this module works on.
    fn gds_library(cell: &str, elements: &[Boundary]) -> Vec<u8> {
        let mut out = Vec::new();
        record(&mut out, HEADER, &600u16.to_be_bytes());
        record(&mut out, BGNLIB, &[0u8; 24]);
        record(&mut out, LIBNAME, &ascii("GPURIFY.DB"));
        let mut units = Vec::with_capacity(16);
        units.extend_from_slice(&gds_real(1e-3));
        units.extend_from_slice(&gds_real(1e-9));
        record(&mut out, UNITS, &units);

        record(&mut out, BGNSTR, &[0u8; 24]);
        record(&mut out, STRNAME, &ascii(cell));
        for element in elements {
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
        record(&mut out, ENDSTR, &[]);
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
}
