//! GDSII output: the library, the marker layers, and the round trip.
//!
//! # What can be built here, and what cannot
//!
//! `gds::write_store` takes a `deck::LayerTable` to map a `LayerId` onto a GDS
//! layer and datatype. That type has private fields and no constructor, so
//! nothing outside `ingest` can populate one — recorded in
//! `docs/NEED_TESTING.md`. A store holding geometry therefore has no layer
//! table to be written against, and the library tests below work on an empty
//! store.
//!
//! That is less of a loss than it looks. The library skeleton is where a GDSII
//! writer would put a timestamp, where record padding goes wrong, and where the
//! round trip is stated; the marker writer takes its layer as a parameter
//! rather than through the table, so it is testable with real geometry.

mod fixture;

use fixture::World;
use gpurify_export::gds::{write_markers, write_store};
use gpurify_ingest::deck::{Deck, LayerTable};
use gpurify_ingest::layout::{gds as reader, UnknownLayers};

fn library(cell_name: &str) -> Vec<u8> {
    let store = fixture::empty_store();
    let layers = LayerTable::default();
    let mut out = Vec::new();
    write_store(&store, &layers, cell_name, &mut out).expect("an empty store is writable");
    out
}

fn markers(world: &World, violations: &gpurify_report::Violations, layer: u16) -> Vec<u8> {
    let mut out = Vec::new();
    write_markers(
        violations,
        &world.store,
        gpurify_core::LayerId(layer),
        &mut out,
    )
    .expect("the markers are writable");
    out
}

/// Oracle: law, from the GDSII format itself. Every record carries a 16-bit
/// length and is padded to an even number of bytes, so a well-formed stream has
/// an even length whatever it contains. `TOP` is three characters, which is
/// exactly the case a writer that forgot to pad a string record gets wrong —
/// and the file it produces is one every reader misparses from that point on.
#[test]
fn the_library_is_a_whole_number_of_gds_records_for_an_odd_length_cell_name() {
    for cell_name in ["TOP", "TOPCELL", "A"] {
        let bytes = library(cell_name);
        assert!(
            !bytes.is_empty(),
            "the library for {cell_name} has no bytes at all"
        );
        assert_eq!(
            bytes.len() % 2,
            0,
            "the library for {cell_name} is {} bytes, so a record was not padded",
            bytes.len()
        );
    }
}

/// Oracle: law. The reader's own format detection has to recognise what the
/// writer emits, or the two halves of this workspace do not speak the same
/// format. Neither side is an oracle for the other's correctness in any
/// absolute sense, which is exactly the property this project's oracles are
/// chosen for.
#[test]
fn the_reader_recognises_what_the_writer_emits_as_gds() {
    let bytes = library("TOP");
    assert!(
        reader::detect(&bytes),
        "the GDS reader does not recognise the GDS writer's output"
    );
}

/// Oracle: law. `parse -> write -> parse` is the identity on the store, and the
/// store here is flat and empty — so what comes back is a store with no
/// polygons, from a library that was nonetheless a real file with a real cell
/// in it. Stating the law over the empty store is stating it precisely: the
/// round trip returns the flattened store, never the original hierarchy.
#[test]
fn writing_an_empty_store_and_reading_it_back_gives_an_empty_store() {
    let bytes = library("TOP");
    let deck = Deck::default();
    let layout = reader::read(&bytes, &deck, UnknownLayers::Reject)
        .expect("a library the writer produced is one the reader accepts");
    assert_eq!(
        layout.store.poly_count(),
        0,
        "an empty store round-tripped into geometry that was never written"
    );
}

/// Oracle: construct-from-answer. The cell name is a parameter, so it reaches
/// the file: two names produce two libraries. A writer that ignored it would
/// produce one, and every downstream tool would open a cell called something
/// nobody asked for.
#[test]
fn the_cell_name_reaches_the_library() {
    assert_ne!(
        library("TOP"),
        library("BOTTOM"),
        "two cell names produced one library"
    );
}

/// Whether a byte stream contains a given record or coordinate.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// One GDSII LAYER record, from the Calma stream format: a four-byte header of
/// `(length, tag)` big-endian followed by the layer number as a big-endian
/// `u16`. Six bytes, tag `0x0D02`. The format is the oracle, not the writer.
fn layer_record(layer: u16) -> [u8; 6] {
    let [hi, lo] = layer.to_be_bytes();
    [0x00, 0x06, 0x0D, 0x02, hi, lo]
}

/// Oracle: construct-from-answer, against the Calma stream format. One shape
/// per violation, on the marker layer the caller named. The layer number comes
/// from the caller precisely because it has to agree with whatever the viewer
/// is configured to show, so a file on layer 7 has to carry a LAYER record
/// saying 7 — a writer that shifted it by one would show markers on a layer
/// nobody is watching, and would still pass a test that only compared two files
/// for difference.
#[test]
fn the_marker_layer_number_reaches_the_file() {
    let world = World::named();
    let on_one = markers(&world, &world.violations, 1);
    let on_seven = markers(&world, &world.violations, 7);
    assert!(!on_one.is_empty(), "the marker writer produced no bytes");
    assert_ne!(
        on_one, on_seven,
        "two marker layers produced one file, so the layer parameter is ignored"
    );
    for (layer, bytes) in [(1u16, &on_one), (7, &on_seven)] {
        let record = layer_record(layer);
        assert!(
            contains(bytes, &record),
            "the markers asked for on layer {layer} carry no LAYER record {record:02x?}"
        );
    }
}

/// Oracle: construct-from-answer, against the Calma stream format. A marker is
/// the geometry of the shape the violation names — which is the only thing
/// `write_markers` is given a `GeometryStore` for — so the coordinates of that
/// shape are in the file. GDSII holds an XY coordinate as a big-endian 32-bit
/// database unit, and the upper rectangle spans x = 400 to 500 while the lower
/// one spans 0 to 100, so a writer that emitted a fixed box, the bounding box
/// of everything, or the other shape cannot pass.
#[test]
fn a_marker_follows_the_shape_its_violation_names() {
    let world = World::named();

    let mut row = world.rows[0];
    row.shapes = (world.lower_poly, None);
    let on_lower = markers(&world, &fixture::table_of(&[row]), 1);
    row.shapes = (world.upper_poly, None);
    let on_upper = markers(&world, &fixture::table_of(&[row]), 1);

    assert_ne!(
        on_lower, on_upper,
        "markers for two shapes four hundred units apart are the same bytes"
    );
    // Zero is not among the coordinates checked: `0i32` big-endian is four zero
    // bytes, which a file of record headers contains whatever it drew.
    for (what, bytes, coordinates) in [
        ("lower", &on_lower, &[100i32][..]),
        ("upper", &on_upper, &[400, 500][..]),
    ] {
        for &x in coordinates {
            assert!(
                contains(bytes, &x.to_be_bytes()),
                "the marker for the {what} rectangle does not carry its x = {x}"
            );
        }
    }
}

/// Oracle: construct-from-answer. Writers here iterate the order the source
/// table guarantees and never sort — "if the order is wrong it is wrong at the
/// source, and fixing it here hides that." So reversing the table reverses the
/// markers, and a writer that sorted would produce the same file from both.
#[test]
fn the_markers_come_out_in_the_order_the_violation_table_holds() {
    let world = World::named();
    let mut reversed = world.rows;
    reversed.reverse();

    assert_ne!(
        markers(&world, &world.violations, 1),
        markers(&world, &fixture::table_of(&reversed), 1),
        "reversing the violation table changed nothing, so the writer sorted it"
    );
}

/// Oracle: law. Both writers append to a caller-owned buffer, so writing into a
/// buffer that already holds something leaves that something alone and adds
/// exactly what a fresh buffer would have received. A writer that indexed from
/// the start of the buffer, or cleared it, is the kind of defect that only
/// shows when two things are written into one file.
#[test]
fn both_gds_writers_append_to_the_buffer_they_are_given() {
    let world = World::named();
    let store = fixture::empty_store();
    let layers = LayerTable::default();

    let mut combined = Vec::new();
    write_store(&store, &layers, "TOP", &mut combined).expect("an empty store is writable");
    let after_library = combined.len();
    write_markers(
        &world.violations,
        &world.store,
        gpurify_core::LayerId(1),
        &mut combined,
    )
    .expect("the markers are writable");

    let expected_library = library("TOP");
    let expected_markers = markers(&world, &world.violations, 1);
    assert_eq!(
        &combined[..after_library],
        &expected_library[..],
        "the marker writer overwrote the library before it"
    );
    assert_eq!(
        &combined[after_library..],
        &expected_markers[..],
        "appending changed what the marker writer emitted"
    );
}
