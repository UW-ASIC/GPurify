#![allow(dead_code)]

use gdsverify::{Deck, GeometryStore};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("engine crate must live at crates/engine")
        .to_path_buf()
}

pub fn fixture_root() -> PathBuf {
    repository_root().join("tests/fixtures")
}

pub fn manifest() -> Value {
    let path = fixture_root().join("manifest.json");
    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

pub fn deck() -> Deck {
    let path = fixture_root().join("params.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    Deck::from_json(&text).unwrap_or_else(|error| panic!("load {}: {error}", path.display()))
}

pub fn cases<'a>(manifest: &'a Value, suite: &str) -> &'a [Value] {
    manifest
        .get(suite)
        .and_then(|section| section.get("cases"))
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("manifest section `{suite}.cases` must be an array"))
}

pub fn case_string<'a>(case: &'a Value, field: &str) -> &'a str {
    case.get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("fixture case is missing string field `{field}`: {case}"))
}

pub fn load_case_store(suite: &str, case: &Value, deck: &Deck) -> GeometryStore {
    let id = case_string(case, "id");
    let cell = case_string(case, "cell");
    let path = fixture_root().join(suite).join(format!("{id}.gds"));
    let layout = gdsverify::load_gds(
        path.to_str().expect("fixture path must be valid UTF-8"),
        deck,
    )
    .unwrap_or_else(|error| panic!("load {}: {error}", path.display()));
    assert_eq!(
        layout.top_cells,
        vec![cell.to_string()],
        "{} must have one expected top cell",
        path.display()
    );
    layout
        .cells
        .get(cell)
        .unwrap_or_else(|| panic!("{} has no flattened cell `{cell}`", path.display()))
        .clone()
}

pub fn close(got: f64, expected: f64, tolerance: f64) -> bool {
    got.is_finite()
        && expected.is_finite()
        && (got - expected).abs() <= tolerance.max(expected.abs() * 1.0e-6 + 1.0e-9)
}
