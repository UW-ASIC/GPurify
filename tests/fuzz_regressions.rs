//! Every committed fuzz crasher, and every seed the fuzz targets start from,
//! through the same entry points and oracles as `cargo fuzz` (`fuzz/oracles.rs`),
//! on stable: the merge gate needs no nightly toolchain (docs/testing-plan.md L4).
//!
//! A crasher found by `cargo fuzz run <target>` is minimised
//! (`cargo fuzz tmin <target> <file>`) and committed as
//! `fuzz/regressions/<target>/<name>`, where the test for its target replays it
//! from then on. The seed directories listed here are the ones the nightly
//! workflow passes to `cargo fuzz run` (`.github/workflows/nightly.yml`).

#![allow(dead_code, reason = "the fuzz harness's shared modules, used in part")]

#[path = "exhaustive/harness.rs"]
mod harness;

#[path = "exhaustive/bitmap.rs"]
mod bitmap;

#[path = "../fuzz/oracles.rs"]
mod oracles;

use std::path::{Path, PathBuf};

/// The targets, as `fuzz/Cargo.toml` names them.
const TARGETS: [&str; 10] = [
    "gds",
    "gds_structured",
    "deck",
    "netlist_spice",
    "netlist_spectre",
    "intent",
    "liberty_spec",
    "drc_e2e",
    "lefdef",
    "spef",
];

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Every file under `dir`, recursively, sorted; none if it does not exist.
fn files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry.expect("a readable directory entry").path();
        if path.is_dir() {
            out.extend(files(&path));
        } else {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// Runs `oracle` on every crasher of `target` and every file of `seeds`, and
/// fails naming each input that broke it.
fn replay(target: &str, oracle: fn(&[u8]), seeds: &[&str]) {
    let mut inputs = files(&repo().join("fuzz/regressions").join(target));
    for dir in seeds {
        let found = files(&repo().join(dir));
        assert!(!found.is_empty(), "{target}: seed directory {dir} is empty");
        inputs.extend(found);
    }
    let broken: Vec<String> = inputs
        .iter()
        .filter(|path| {
            let bytes = std::fs::read(path).expect("a readable input");
            std::panic::catch_unwind(|| oracle(&bytes)).is_err()
        })
        .map(|path| path.display().to_string())
        .collect();
    assert!(broken.is_empty(), "{target} fails on {broken:#?}");
}

/// A directory under `fuzz/regressions` that names no target would be
/// replayed by nothing.
///
/// Oracle: `fuzz/Cargo.toml`'s target names, copied into `TARGETS`.
#[test]
fn every_regression_directory_names_a_target() {
    let Ok(entries) = std::fs::read_dir(repo().join("fuzz/regressions")) else {
        return;
    };
    for entry in entries {
        let name = entry.expect("a readable directory entry").file_name();
        let name = name.to_string_lossy();
        assert!(
            TARGETS.contains(&name.as_ref()),
            "fuzz/regressions/{name} is not a fuzz target"
        );
    }
}

/// Oracle: `oracles::gds`: a typed error, never a panic; flattening within
/// budget; a layout that can be written back reads back to the same store
/// (round trip).
#[test]
fn gds() {
    replay("gds", oracles::gds, &["tests/fixtures/_source"]);
}

/// Oracle: `oracles::gds_structured`: the flat count and area computed from
/// the decoded structures, and the hierarchy errors the limits define.
#[test]
fn gds_structured() {
    replay("gds_structured", oracles::gds_structured, &[]);
}

/// Oracle: `oracles::deck`: every diagnostic's span lies inside the input on
/// character boundaries, and every rule of an accepted deck gets a run row.
#[test]
fn deck() {
    replay("deck", oracles::deck, &["pdks", "fuzz/seeds/deck"]);
}

/// Oracle: `oracles::netlist_spice`: a typed error, never a panic; device
/// and instance counts counted from the card text; the flattening counted
/// from the subcircuit tables.
#[test]
fn netlist_spice() {
    replay(
        "netlist_spice",
        oracles::netlist_spice,
        &["tests/fixtures/lvs_refs", "fuzz/seeds/netlist_spice"],
    );
}

/// Oracle: `oracles::netlist_spectre`: a typed error, never a panic; device
/// and instance counts counted from the statements; the flattening counted
/// from the subcircuit tables.
#[test]
fn netlist_spectre() {
    replay(
        "netlist_spectre",
        oracles::netlist_spectre,
        &["fuzz/seeds/netlist_spectre"],
    );
}

/// Oracle: `oracles::intent`: a typed error, never a panic.
#[test]
fn intent() {
    replay("intent", oracles::intent, &["fuzz/seeds/intent"]);
}

/// Oracle: `oracles::liberty_spec`: a typed error, never a panic.
#[test]
fn liberty_spec() {
    replay(
        "liberty_spec",
        oracles::liberty_spec,
        &["fuzz/seeds/liberty_spec"],
    );
}

/// Oracle: `oracles::lefdef`: a typed error, never a panic, and the GDSII
/// the reader writes round-trips through the GDS reader on the DEF's grid.
#[test]
fn lefdef() {
    replay("lefdef", oracles::lefdef, &["fuzz/seeds/lefdef"]);
}

/// Oracle: `oracles::spef`: a typed error, never a panic, and an accepted
/// file is a well-formed canonical network; seeded with every SPEF and
/// DSPF golden the writers produce.
#[test]
fn spef() {
    replay(
        "spef",
        oracles::spef,
        &["fuzz/seeds/spef", "tests/golden/pex"],
    );
}

/// The target has no seed directory, so its regressions directory is the
/// replay hook: it must exist and hold an input, or this would pass on a
/// missing path. Its first input is a seed, not a crasher: a `min_spacing`
/// case (index `0x0001_0005`, two cells of one row) under symmetry 3, moved by
/// (`0x1234_5678`, `-0x1000_0000`).
///
/// Oracle: `oracles::drc_e2e`: the bitmap reference, written from each rule's
/// rustdoc.
#[test]
fn drc_e2e() {
    let hook = repo().join("fuzz/regressions/drc_e2e");
    assert!(
        !files(&hook).is_empty(),
        "{} holds no input to replay",
        hook.display()
    );
    replay("drc_e2e", oracles::drc_e2e, &[]);
}
