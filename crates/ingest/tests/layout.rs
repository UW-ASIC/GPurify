//! `read_gds_bytes` on whole files: refusals, and gzip.

use gpurify_ingest::layout::{gds, read_gds_bytes, LayoutError};
use gpurify_ingest::StrTable;
use gpurify_testgen::gds::write_library;
use gpurify_testgen::oracle;
use std::io::Write;

/// Writes `bytes` to a fresh scratch file named `name` and reads it as a layout.
fn read(name: &str, bytes: &[u8]) -> Result<(), LayoutError> {
    let dir = oracle::scratch("ingest-layout");
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("scratch write");
    let result = read_gds_bytes(&path);
    let _ = std::fs::remove_dir_all(&dir);
    gds::Library::parse(&result?, &mut StrTable::default()).map(|_| ())
}

/// An empty GDSII library: no structure, only the library records.
fn empty_library() -> Vec<u8> {
    let mut out = Vec::new();
    write_library(&[], &mut out).expect("an empty library writes");
    out
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).expect("in-memory write");
    encoder.finish().expect("in-memory gzip")
}

/// Oracle: construct-from-answer. Bytes in no known format are refused, not
/// read as an empty layout, which would report clean.
#[test]
fn a_file_in_no_known_format_is_refused_rather_than_read_as_an_empty_layout() {
    match read(
        "not-a-layout.bin",
        b"this is not a layout file, it is a sentence",
    ) {
        Err(LayoutError::UnknownFormat) => {}
        other => panic!("a file in no known format produced {other:?}"),
    }
}

/// Oracle: construct-from-answer. An unopenable layout is an error, not an empty store.
#[test]
fn a_layout_that_cannot_be_opened_is_an_error_rather_than_an_empty_store() {
    let missing = std::path::Path::new("/nonexistent/gpurify/no-such-layout.gds");
    match read_gds_bytes(missing) {
        Err(LayoutError::Io(_)) => {}
        other => panic!("an unreadable layout produced {other:?} rather than LayoutError::Io"),
    }
}

/// Oracle: law. A gzip file reads as its contents, including one split into two
/// gzip members: stopping after the first would be a silently partial layout.
#[test]
fn a_gzip_layout_reads_as_its_contents_across_every_member() {
    let plain = empty_library();
    read("plain.gds", &plain).expect("an empty library is a valid layout");
    read("one-member.gds.gz", &gzip(&plain)).expect("gzip of a valid layout");

    let (head, tail) = plain.split_at(10);
    let mut two_members = gzip(head);
    two_members.extend(gzip(tail));
    read("two-members.gds.gz", &two_members)
        .expect("a two-member gzip must decode both members, or ENDLIB is never reached");
}
