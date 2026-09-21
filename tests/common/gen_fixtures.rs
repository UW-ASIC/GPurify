//! Split the 167 per-case GDSII fixtures out of one source file, on demand.
//!
//! # What goes in, what comes out
//!
//! In: `tests/fixtures/_source/conformance.gds` — 134 cells in one library —
//! and `tests/fixtures/manifest.json`, which says which cell each case id is
//! drawn on. Out: `tests/fixtures/<domain>/<case id>.gds`, one small library per
//! case holding that cell and everything it places.
//!
//! Both inputs stay in the repository; the 167 outputs do not, and are
//! `.gitignore`d. That is the whole reason this file exists: the per-case files
//! were byte-for-byte derivable from the source and were being carried anyway.
//!
//! # The manifest is a build input here, not an oracle
//!
//! Only `gds_file` and each case's `cell` are read. `expect_violations`,
//! `reference_netlist` and `expected` — the deleted tree's own answers — are
//! read by nothing in this workspace: the deleted tree is not an oracle, and
//! routing its answers back in would defeat that quietly. Every expected
//! number the corpus checks comes from `expectations.json`.
//!
//! # The reconstruction rule, in full
//!
//! Verified byte-identical on the first 160 files against the versions that were
//! tracked before this module existed, and re-verified by
//! [`the_generated_corpus_matches_what_the_generator_produces`] on every run.
//!
//! 1. `HEADER` and `BGNLIB` copied from the source, then a `LIBNAME` of
//!    `GPUVERIFY_<case id>` — NUL-padded to even length *only when odd*, which
//!    is what a GDSII record requires and is not the same as always padding —
//!    then `UNITS` copied from the source.
//! 2. Each cell's `BGNSTR..ENDSTR` copied byte for byte, in placement order:
//!    children before the cell that places them, so a reader meets a cell's
//!    definition before its `SREF`.
//! 3. A `STRANS` record whose flag word is zero is dropped. It carries no
//!    transform, and the writer that produced these files did not emit one.
//! 4. `ENDLIB`.
//!
//! # Concurrency
//!
//! Cargo runs each test binary as its own process and each `#[test]` on its own
//! thread, so both a thread race and a process race are live. The `Once` closes
//! the first. The second is closed by writing to a per-process temporary name
//! and `rename`ing it into place: `rename` within a directory is atomic on
//! POSIX and every writer produces identical bytes, so a reader sees the
//! complete old file or the complete new one and never a half-written one.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Once;

/// The GDSII record types this splitter has to recognise.
///
/// A record is `[u16 length][u8 type][u8 data type][payload]`, length inclusive
/// of the four-byte head. Everything not named here is copied verbatim.
const HEADER: u8 = 0x00;
const BGNLIB: u8 = 0x01;
const LIBNAME: u8 = 0x02;
const UNITS: u8 = 0x03;
const BGNSTR: u8 = 0x05;
const STRNAME: u8 = 0x06;
const ENDSTR: u8 = 0x07;
const SNAME: u8 = 0x12;
const STRANS: u8 = 0x1a;

/// `ENDLIB`, which has no payload and is therefore a constant.
const ENDLIB_RECORD: [u8; 4] = [0x00, 0x04, 0x04, 0x00];

/// The four directories the corpus is split into, and the field of the manifest
/// each comes from.
const DOMAINS: [&str; 4] = ["drc", "erc", "lvs", "pex"];

/// How many cases the manifest declares in total.
///
/// Asserted rather than trusted: a manifest that lost a domain would otherwise
/// generate a smaller corpus, and the corpus tests would report "cell did not
/// load" for cases that simply were not written.
///
/// One file per *case*, not per cell: several cases share a cell and each still
/// gets its own `<case id>.gds`, so this moves for a new case that reuses an
/// existing cell exactly as it does for one that adds geometry.
const CASE_COUNT: usize = 167;

// ---------------------------------------------------------------------------
// The manifest, reading only the two fields that are inputs.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Manifest {
    gds_file: String,
    drc: ManifestDomain,
    erc: ManifestDomain,
    lvs: ManifestDomain,
    pex: ManifestDomain,
}

#[derive(Deserialize)]
struct ManifestDomain {
    cases: Vec<ManifestCase>,
}

/// Every other field of a manifest case is one of the deleted tree's answers,
/// and `serde` drops what is not named here.
#[derive(Deserialize)]
struct ManifestCase {
    id: String,
    cell: String,
}

impl Manifest {
    fn domain(&self, name: &str) -> &[ManifestCase] {
        match name {
            "drc" => &self.drc.cases,
            "erc" => &self.erc.cases,
            "lvs" => &self.lvs.cases,
            "pex" => &self.pex.cases,
            other => panic!("no manifest domain named {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// The source library, indexed.
// ---------------------------------------------------------------------------

/// One GDSII record's byte range in the stream that holds it.
type Span = (usize, usize);

/// Every record's span, in stream order.
///
/// A chain, not a bulk loop: record N starts where record N-1 ended, and that
/// length is only known once N-1 has been read. `/simd-loops` triage stops
/// there — there is nothing to widen and no branch to predicate away, and the
/// input is 30 KB read once per process.
fn records(bytes: &[u8]) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut at = 0;
    while at + 4 <= bytes.len() {
        let len = usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
        assert!(
            len >= 4 && at + len <= bytes.len(),
            "conformance.gds is not a GDSII record stream: a record at byte {at} \
             claims a length of {len}"
        );
        spans.push((at, at + len));
        at += len;
    }
    assert_eq!(
        at,
        bytes.len(),
        "conformance.gds ends mid-record at byte {at}"
    );
    spans
}

/// A record's name payload, without the padding NUL a GDSII writer adds to make
/// the record length even.
fn name_of(bytes: &[u8], span: Span) -> &str {
    let payload = &bytes[span.0 + 4..span.1];
    let trimmed = payload.strip_suffix(b"\0").unwrap_or(payload);
    std::str::from_utf8(trimmed).expect("a GDSII cell name is ASCII")
}

/// The source library, split into the pieces a per-case file is assembled from.
struct Source<'a> {
    bytes: &'a [u8],
    /// `HEADER`, `BGNLIB` and `UNITS`, which every output copies verbatim.
    header: Span,
    bgnlib: Span,
    units: Span,
    /// Each cell's `BGNSTR..ENDSTR`, and the cells it places by `SREF`/`AREF`.
    block: BTreeMap<&'a str, Span>,
    children: BTreeMap<&'a str, Vec<&'a str>>,
}

impl<'a> Source<'a> {
    fn index(bytes: &'a [u8]) -> Self {
        let spans = records(bytes);
        let mut header = None;
        let mut bgnlib = None;
        let mut units = None;
        let mut block = BTreeMap::new();
        let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();

        // One pass, dispatching on the record tag. The `if` chain stays: it is
        // a dispatcher over a handful of tags where the taken side copies a
        // slice or inserts into a map, which is `/branchless`'s "taken side is
        // expensive" escape valve, and 2301 records is far too few to vectorise.
        let mut open: Option<usize> = None;
        let mut cell: Option<&str> = None;
        for span in spans {
            match bytes[span.0 + 2] {
                HEADER => header = Some(span),
                BGNLIB => bgnlib = Some(span),
                UNITS => units = Some(span),
                BGNSTR => {
                    open = Some(span.0);
                    cell = None;
                }
                STRNAME if open.is_some() && cell.is_none() => cell = Some(name_of(bytes, span)),
                SNAME => {
                    let placed = name_of(bytes, span);
                    let owner = cell.expect("an SREF outside a cell");
                    children.entry(owner).or_default().push(placed);
                }
                ENDSTR => {
                    let start = open.take().expect("an ENDSTR with no BGNSTR");
                    let name = cell.take().expect("a cell with no STRNAME");
                    block.insert(name, (start, span.1));
                }
                _ => {}
            }
        }

        Source {
            bytes,
            header: header.expect("conformance.gds has no HEADER"),
            bgnlib: bgnlib.expect("conformance.gds has no BGNLIB"),
            units: units.expect("conformance.gds has no UNITS"),
            block,
            children,
        }
    }

    fn slice(&self, span: Span) -> &'a [u8] {
        &self.bytes[span.0..span.1]
    }

    /// `cell` and everything it places, children first.
    ///
    /// Post-order so a reader meets a cell's definition before the `SREF` that
    /// places it, which is the order the source file itself is in.
    fn closure(&self, cell: &'a str) -> Vec<&'a str> {
        let mut order = Vec::new();
        let mut seen = Vec::new();
        self.visit(cell, &mut seen, &mut order);
        order
    }

    fn visit(&self, cell: &'a str, seen: &mut Vec<&'a str>, order: &mut Vec<&'a str>) {
        if seen.contains(&cell) {
            return;
        }
        seen.push(cell);
        for &child in self.children.get(cell).map_or(&[][..], Vec::as_slice) {
            self.visit(child, seen, order);
        }
        order.push(cell);
    }
}

/// Copy a cell block, dropping any `STRANS` that carries no transform.
///
/// The source's writer emitted `STRANS` only where the flag word is non-zero,
/// so a zero one is noise a later edit of the source added. Keeping it would
/// change nothing a reader does and would make these files differ from the ones
/// this generator replaced.
fn copy_cell(into: &mut Vec<u8>, block: &[u8]) {
    let mut at = 0;
    while at < block.len() {
        let len = usize::from(u16::from_be_bytes([block[at], block[at + 1]]));
        let zero_strans = block[at + 2] == STRANS && block[at + 4..at + 6] == [0x00, 0x00];
        if !zero_strans {
            into.extend_from_slice(&block[at..at + len]);
        }
        at += len;
    }
}

/// One case's library, as bytes.
fn case_gds(source: &Source, case_id: &str, cell: &str) -> Vec<u8> {
    assert!(
        source.block.contains_key(cell),
        "manifest names cell {cell} for case {case_id}, which conformance.gds \
         does not hold"
    );

    let mut name = format!("GPUVERIFY_{case_id}").into_bytes();
    // A GDSII record length is a `u16` over the whole record, and the format
    // requires it even. Padded only when the name makes it odd — always padding
    // would append a NUL to every even-length name and change 66 of the 160
    // files.
    if name.len() % 2 == 1 {
        name.push(0);
    }

    let mut out = Vec::with_capacity(4096);
    out.extend_from_slice(source.slice(source.header));
    out.extend_from_slice(source.slice(source.bgnlib));
    let record_len = u16::try_from(4 + name.len()).expect("a case id is short");
    out.extend_from_slice(&record_len.to_be_bytes());
    out.push(LIBNAME);
    out.push(0x06); // ASCII string.
    out.extend_from_slice(&name);
    out.extend_from_slice(source.slice(source.units));

    for placed in source.closure(cell) {
        let span = source.block[placed];
        copy_cell(&mut out, source.slice(span));
    }
    out.extend_from_slice(&ENDLIB_RECORD);

    debug_assert_eq!(
        out.len() % 2,
        0,
        "{case_id}: a GDSII stream has even length"
    );
    debug_assert!(
        out.ends_with(&ENDLIB_RECORD),
        "{case_id}: the stream does not end with ENDLIB"
    );
    debug_assert_eq!(
        records(&out)
            .iter()
            .filter(|&&span| out[span.0 + 2] == BGNSTR)
            .count(),
        source.closure(cell).len(),
        "{case_id}: the stream holds a different number of cells than the \
         closure of {cell} has"
    );
    out
}

// ---------------------------------------------------------------------------
// Writing them out.
// ---------------------------------------------------------------------------

/// Generate the per-case fixtures under `root`, once per process.
///
/// Idempotent across processes as well as across threads — see the module doc.
pub fn ensure(root: &Path) {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| generate(root));
}

fn generate(root: &Path) {
    let manifest_path = root.join("manifest.json");
    let text = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|why| panic!("{}: {why}", manifest_path.display()));
    let manifest: Manifest = serde_json::from_str(&text)
        .unwrap_or_else(|why| panic!("{}: {why}", manifest_path.display()));

    let source_path = root.join(&manifest.gds_file);
    let bytes = std::fs::read(&source_path)
        .unwrap_or_else(|why| panic!("{}: {why}", source_path.display()));
    let source = Source::index(&bytes);

    let mut written = 0;
    for domain in DOMAINS {
        let dir = root.join(domain);
        std::fs::create_dir_all(&dir).unwrap_or_else(|why| panic!("{}: {why}", dir.display()));
        for case in manifest.domain(domain) {
            let path = dir.join(format!("{}.gds", case.id));
            write_if_different(&path, &case_gds(&source, &case.id, &case.cell));
            written += 1;
        }
    }

    assert_eq!(
        written, CASE_COUNT,
        "the manifest declares {written} cases; the corpus is {CASE_COUNT}, and \
         a case that was never written reads downstream as a cell that would not \
         load rather than as a missing fixture"
    );
}

/// Write `bytes` to `path` unless it already holds exactly those bytes.
///
/// The compare is not an optimisation — it is what makes a stale or truncated
/// file repair itself. The temporary-plus-rename is what makes two test
/// binaries racing on the same path safe.
fn write_if_different(path: &Path, bytes: &[u8]) {
    if std::fs::read(path).is_ok_and(|held| held == bytes) {
        return;
    }
    let temp = path.with_extension(format!("gds.tmp.{}", std::process::id()));
    std::fs::write(&temp, bytes).unwrap_or_else(|why| panic!("{}: {why}", temp.display()));
    std::fs::rename(&temp, path).unwrap_or_else(|why| panic!("{}: {why}", path.display()));
}

/// Oracle: law — the corpus on disk is what this generator produces.
///
/// Written while the 160 files were still tracked, where it proved the
/// reconstruction byte for byte against hand-drawn originals. They are ignored
/// now, so what it proves today is narrower and worth stating plainly: that a
/// fixture tree left behind by an older revision of this file is not silently
/// reused. The corroboration it once carried lives in the two inputs, both of
/// which are still tracked.
#[test]
fn the_generated_corpus_matches_what_the_generator_produces() {
    let root = super::fixtures();
    let text =
        std::fs::read_to_string(root.join("manifest.json")).expect("the manifest is tracked");
    let manifest: Manifest = serde_json::from_str(&text).expect("the manifest parses");
    let bytes =
        std::fs::read(root.join(&manifest.gds_file)).expect("the source library is tracked");
    let source = Source::index(&bytes);

    let mut checked = 0;
    for domain in DOMAINS {
        for case in manifest.domain(domain) {
            let path = root.join(domain).join(format!("{}.gds", case.id));
            let on_disk =
                std::fs::read(&path).unwrap_or_else(|why| panic!("{}: {why}", path.display()));
            assert_eq!(
                on_disk,
                case_gds(&source, &case.id, &case.cell),
                "{}: the file on disk is not what this generator produces from \
                 {} — it is stale, and every case that reads it is checking \
                 geometry nobody derived",
                path.display(),
                manifest.gds_file
            );
            checked += 1;
        }
    }
    assert_eq!(checked, CASE_COUNT);
}
