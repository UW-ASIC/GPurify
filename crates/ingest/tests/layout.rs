//! Format dispatch, and what `read_layout` does with a file it cannot use.
//!
//! The reader tests that need a populated `LayerTable` live inside the crate:
//! the type has private fields and no constructor, so no caller outside
//! `ingest` can build one. That gap is recorded in `docs/NEED_TESTING.md`. What
//! is testable from out here is the part before any layer is resolved — which
//! format a byte stream is, and whether an unusable file is refused.

use gpurify_ingest::layout::{gds, oasis, LayoutError, UnknownLayers};
use gpurify_ingest::Deck;
use gpurify_testgen::Rng;

/// The first six bytes of every GDSII file: a HEADER record, four bytes of
/// `(length, tag)` and a two-byte version. Format constant, not a value read
/// out of the code under test.
const GDS_PREFIX: [u8; 6] = [0x00, 0x06, 0x00, 0x02, 0x00, 0x05];

/// OASIS begins with its magic string, `%SEMI-OASIS` and a CRLF.
const OASIS_MAGIC: &[u8] = b"%SEMI-OASIS\r\n";

/// Oracle: law. `read_layout` dispatches on the file's magic, which is only
/// well defined if at most one detector ever accepts a given prefix. That has
/// to hold for arbitrary bytes, not just for the two magics, so the input is
/// generated: 512 random prefixes, seeded, plus the empty one.
#[test]
fn at_most_one_format_detector_accepts_any_given_prefix() {
    let mut rng = Rng::new(11);
    let mut prefix = Vec::with_capacity(32);
    for _ in 0..512 {
        prefix.clear();
        #[allow(
            clippy::cast_possible_truncation,
            reason = "below(256) is in 0..256, which is exactly a u8"
        )]
        prefix.extend((0..32).map(|_| rng.below(256) as u8));
        assert!(
            !(gds::detect(&prefix) && oasis::detect(&prefix)),
            "both detectors accepted {prefix:?}, so which reader runs is a \
             matter of which was asked first"
        );
    }
    assert!(
        !gds::detect(&[]) && !oasis::detect(&[]),
        "a detector accepted an empty prefix, which is fail-open on a file \
         with no content at all"
    );
}

/// Oracle: construct-from-answer. Each format's own magic is the input and the
/// answer is the format it belongs to. The cross-rejections are the half that
/// matters: a detector that accepts on "not obviously the other format" passes
/// the positive case and fails here.
#[test]
fn each_detector_accepts_its_own_magic_and_refuses_the_others() {
    assert!(
        gds::detect(&GDS_PREFIX),
        "the GDSII HEADER record was not recognised as GDSII"
    );
    assert!(
        oasis::detect(OASIS_MAGIC),
        "the OASIS magic string was not recognised as OASIS"
    );
    assert!(
        !oasis::detect(&GDS_PREFIX),
        "the OASIS detector accepted a GDSII header"
    );
    assert!(
        !gds::detect(OASIS_MAGIC),
        "the GDSII detector accepted the OASIS magic string"
    );
    assert!(
        !gds::detect(b"PK\x03\x04nothing to do with layout"),
        "the GDSII detector accepted a zip archive"
    );
}

/// A scratch path unique to this process and this test.
fn scratch(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("gpurify-ingest-{}-{name}", std::process::id()))
}

/// Oracle: construct-from-answer. A file whose bytes are neither format is
/// rejected, not read as an empty layout. An empty store passes every geometric
/// rule, so "we could not read this" arriving as "there is nothing wrong with
/// this" is the false-clean failure the whole crate is built against.
#[test]
fn a_file_in_neither_format_is_refused_rather_than_read_as_an_empty_layout() {
    let path = scratch("not-a-layout.bin");
    std::fs::write(&path, b"this is not a layout file, it is a sentence").expect("scratch write");

    let result = gpurify_ingest::layout::read_layout(&path, &Deck::default(), UnknownLayers::Reject);
    let _ = std::fs::remove_file(&path);

    match result {
        Err(LayoutError::UnknownFormat) => {}
        other => panic!("a file in no known format produced {other:?}"),
    }
}

/// Oracle: construct-from-answer. A layout that cannot be opened is an error
/// for the same reason a deck that cannot be opened is: the alternative is a
/// clean report on a design nothing was read from.
#[test]
fn a_layout_that_cannot_be_opened_is_an_error_rather_than_an_empty_store() {
    let missing = std::path::Path::new("/nonexistent/gpurify/no-such-layout.gds");
    match gpurify_ingest::layout::read_layout(missing, &Deck::default(), UnknownLayers::Reject) {
        Err(LayoutError::Io(_)) => {}
        other => panic!("an unreadable layout produced {other:?} rather than LayoutError::Io"),
    }
}

/// Oracle: law. Format detection is a property of the bytes and nothing else,
/// so it is the same answer however many times it is asked and whatever the
/// prefix is followed by. Trailing content cannot change the verdict, which is
/// what lets `read_layout` dispatch on a short prefix rather than the file.
#[test]
fn detection_depends_on_the_prefix_alone_and_not_on_what_follows_it() {
    let mut rng = Rng::new(29);
    let mut file = GDS_PREFIX.to_vec();
    assert!(gds::detect(&file));
    for _ in 0..64 {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "below(256) is in 0..256, which is exactly a u8"
        )]
        file.push(rng.below(256) as u8);
        assert!(
            gds::detect(&file),
            "appending bytes after a GDSII header changed the format verdict"
        );
        assert!(!oasis::detect(&file));
    }
}
