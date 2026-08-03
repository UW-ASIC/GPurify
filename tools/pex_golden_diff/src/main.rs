//! Per-field numeric and shape diff of `crates_clean/pex` against
//! `tests/golden/pex/*.json`.
//!
//! in: 27 GDS fixtures + `tests/fixtures/manifest.json` + the deck; out: one
//! row per fixture on stdout (max absolute deviation, max relative deviation,
//! the field that carried it) plus a global worst line, plus every shape
//! mismatch. Exit 1 on any shape mismatch or any non-zero deviation.
//!
//! Why this exists next to `pex/tests/golden.rs`: the test asserts
//! `serde_json::Value` equality, which answers "did anything move?" with a
//! bool. This answers "by how much, and which field", which is the only form
//! in which a numeric regression can be triaged. It also catches the two cases
//! `Value` equality is blind to: `-0.0 == 0.0`, and an integer-vs-float type
//! swap is caught by `Value` but not reported as a *shape* fact.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use gdsverify_core::geometry::GeometryStore;
use gdsverify_core::io::read::{
    flatten_all, read_layout, FlattenOptions, GeometryPolicy, LayerMap, UnmappedPolicy,
};
use gdsverify_core::io::Deck;
use gdsverify_core::units::Grid;
use gdsverify_pex::{report, run_pex};
use serde_json::Value;

const DECK: &str = include_str!("../../../crates_clean/fixtures/params.json");

/// One numeric disagreement, keyed by its JSON path.
struct Dev {
    path: String,
    got: f64,
    want: f64,
    abs: f64,
    rel: f64,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn store_of(root: &Path, id: &str, cell: &str, deck: &Deck) -> GeometryStore {
    let path = root.join("tests/fixtures/pex").join(format!("{id}.gds"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let (cells, _units) = read_layout(&bytes, deck.grid).expect("fixture reads");
    let opts = FlattenOptions {
        geometry: GeometryPolicy::PreserveInvalid,
        unmapped: UnmappedPolicy::Count,
        ..FlattenOptions::default()
    };
    let layout = flatten_all(&cells, LayerMap(deck.layers.gds_to_id()), &opts).expect("flattens");
    layout
        .cell(cell)
        .unwrap_or_else(|| panic!("{id}.gds has no flattened cell `{cell}`"))
        .clone()
}

/// Name of the JSON value kind, so a type swap reads as a shape fact rather
/// than a mystery inequality.
fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(n) => {
            if n.is_f64() {
                "float"
            } else {
                "int"
            }
        }
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Lockstep walk. `shape` collects structural disagreements (missing key, extra
/// key, differing length, differing value kind); `devs` collects numeric ones.
///
/// Kernel rule holds: each visit reads its own two nodes and the uniform path
/// prefix, and appends. No node is revisited.
fn walk(path: &str, got: &Value, want: &Value, shape: &mut Vec<String>, devs: &mut Vec<Dev>) {
    if kind(got) != kind(want) {
        shape.push(format!(
            "{path}: kind {} != golden {}",
            kind(got),
            kind(want)
        ));
        return;
    }
    match (got, want) {
        (Value::Object(g), Value::Object(w)) => {
            let gk: BTreeSet<&str> = g.keys().map(String::as_str).collect();
            let wk: BTreeSet<&str> = w.keys().map(String::as_str).collect();
            for k in gk.difference(&wk) {
                shape.push(format!("{path}.{k}: present in rewrite, absent in golden"));
            }
            for k in wk.difference(&gk) {
                shape.push(format!("{path}.{k}: absent in rewrite, present in golden"));
            }
            for k in gk.intersection(&wk) {
                walk(&format!("{path}.{k}"), &g[*k], &w[*k], shape, devs);
            }
        }
        (Value::Array(g), Value::Array(w)) => {
            if g.len() != w.len() {
                shape.push(format!("{path}: len {} != golden {}", g.len(), w.len()));
                return;
            }
            for (i, (a, b)) in g.iter().zip(w).enumerate() {
                walk(&format!("{path}[{i}]"), a, b, shape, devs);
            }
        }
        (Value::String(g), Value::String(w)) => {
            if g != w {
                shape.push(format!("{path}: {g:?} != golden {w:?}"));
            }
        }
        (Value::Bool(g), Value::Bool(w)) => {
            if g != w {
                shape.push(format!("{path}: {g} != golden {w}"));
            }
        }
        (Value::Number(g), Value::Number(w)) => {
            // Compare the bits, not the values: this is the one place where
            // `==` lies (-0.0 == 0.0) and where a golden's exact ULP matters.
            let (gf, wf) = (
                g.as_f64().expect("finite golden-side number"),
                w.as_f64().expect("finite golden-side number"),
            );
            if gf.to_bits() != wf.to_bits() {
                let abs = (gf - wf).abs();
                let rel = if wf == 0.0 { f64::INFINITY } else { abs / wf.abs() };
                devs.push(Dev {
                    path: path.to_string(),
                    got: gf,
                    want: wf,
                    abs,
                    rel,
                });
            }
        }
        _ => {}
    }
}

fn main() {
    let root = repo_root();
    let deck = Deck::from_json(DECK, Grid::NANOMETRE).expect("fixture deck loads");
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(root.join("tests/fixtures/manifest.json")).expect("manifest"),
    )
    .expect("manifest parses");
    let cases = manifest["pex"]["cases"]
        .as_array()
        .expect("manifest has pex.cases");

    println!(
        "{:<20} {:>5} {:>7} {:>13} {:>13}  {}",
        "fixture", "rows", "fields", "max |abs|", "max |rel|", "worst field"
    );
    println!("{}", "-".repeat(96));

    let mut total_fields = 0usize;
    let mut total_rows = 0usize;
    let mut shape_problems = 0usize;
    let mut worst: Option<(String, Dev)> = None;

    for case in cases {
        let id = case["id"].as_str().expect("case id");
        let cell = case["cell"].as_str().expect("case cell");
        let store = store_of(&root, id, cell, &deck);

        let rows = run_pex(&store, &deck).expect("analytical deck");
        let got = serde_json::to_value(report(&rows, &deck)).expect("report serializes");
        let want: Value = serde_json::from_slice(
            &std::fs::read(root.join("tests/golden/pex").join(format!("{id}.json")))
                .expect("golden exists"),
        )
        .expect("golden parses");

        let mut shape = Vec::new();
        let mut devs = Vec::new();
        walk("", &got, &want, &mut shape, &mut devs);

        let nrows = want["parasitics"].as_array().map_or(0, Vec::len);
        let nfields = count_numbers(&want);
        total_rows += nrows;
        total_fields += nfields;
        shape_problems += shape.len();

        let max_abs = devs.iter().map(|d| d.abs).fold(0.0f64, f64::max);
        let max_rel = devs.iter().map(|d| d.rel).fold(0.0f64, f64::max);
        let worst_here = devs
            .iter()
            .max_by(|a, b| a.rel.total_cmp(&b.rel))
            .map_or_else(|| "-".to_string(), |d| {
                format!("{} got {} want {}", d.path, d.got, d.want)
            });
        println!("{id:<20} {nrows:>5} {nfields:>7} {max_abs:>13.3e} {max_rel:>13.3e}  {worst_here}");
        for s in &shape {
            println!("    SHAPE {s}");
        }

        if let Some(d) = devs.into_iter().max_by(|a, b| a.rel.total_cmp(&b.rel)) {
            if worst.as_ref().is_none_or(|(_, w)| d.rel > w.rel) {
                worst = Some((id.to_string(), d));
            }
        }
    }

    println!("{}", "-".repeat(96));
    println!(
        "27 fixtures, {total_rows} parasitic rows, {total_fields} numeric fields compared \
         bit-for-bit (f64 to_bits)"
    );
    println!("shape mismatches: {shape_problems}");
    match &worst {
        None => println!("worst field: NONE — every numeric field is bit-identical"),
        Some((id, d)) => println!(
            "worst field: {id}{} got {} want {} abs {:.6e} rel {:.6e}",
            d.path, d.got, d.want, d.abs, d.rel
        ),
    }
    if shape_problems > 0 || worst.is_some() {
        std::process::exit(1);
    }
}

/// Every numeric leaf, so the "fields compared" column is a real count and not
/// the row count wearing a hat.
fn count_numbers(v: &Value) -> usize {
    match v {
        Value::Number(_) => 1,
        Value::Array(a) => a.iter().map(count_numbers).sum(),
        Value::Object(o) => o.values().map(count_numbers).sum(),
        _ => 0,
    }
}

/// Negative control. A diff tool that reports zero on everything is
/// indistinguishable from a diff tool that reports zero on everything.
#[cfg(test)]
mod tests {
    use super::{walk, Value};
    use serde_json::json;

    fn run(a: &Value, b: &Value) -> (Vec<String>, Vec<(String, f64)>) {
        let (mut s, mut d) = (Vec::new(), Vec::new());
        walk("", a, b, &mut s, &mut d);
        (s, d.into_iter().map(|x| (x.path, x.rel)).collect())
    }

    #[test]
    fn one_ulp_is_not_zero() {
        let want = 0.202_499_999_999_999_99_f64;
        let got = f64::from_bits(want.to_bits() + 1);
        let (s, d) = run(&json!({ "af": got }), &json!({ "af": want }));
        assert!(s.is_empty());
        assert_eq!(d.len(), 1, "one ULP must be reported, not absorbed");
        assert!(d[0].1 > 0.0 && d[0].1 < 1e-15, "rel {}", d[0].1);
    }

    #[test]
    fn negative_zero_is_a_deviation() {
        let (_, d) = run(&json!({ "ohm": -0.0 }), &json!({ "ohm": 0.0 }));
        assert_eq!(d.len(), 1, "`==` says -0.0 == 0.0; to_bits must not");
    }

    #[test]
    fn shape_changes_are_named_not_counted_as_numbers() {
        let (s, d) = run(
            &json!({ "parasitics": [{ "AreaCap": { "af": 1.0, "extra": 2.0 } }] }),
            &json!({ "parasitics": [{ "AreaCap": { "af": 1.0, "layer": "met1" } }] }),
        );
        assert!(d.is_empty());
        assert_eq!(s.len(), 2, "{s:?}");
        assert!(s.iter().any(|m| m.contains(".extra")));
        assert!(s.iter().any(|m| m.contains(".layer")));
    }

    #[test]
    fn int_to_float_swap_is_a_shape_mismatch() {
        let (s, d) = run(&json!({ "spacing_nm": 400.0 }), &json!({ "spacing_nm": 400 }));
        assert!(d.is_empty());
        assert_eq!(s, vec![".spacing_nm: kind float != golden int".to_string()]);
    }

    #[test]
    fn row_count_and_variant_tag_are_checked() {
        let (s, _) = run(&json!([1.0]), &json!([1.0, 2.0]));
        assert_eq!(s, vec![": len 1 != golden 2".to_string()]);
        let (s, _) = run(&json!({ "Resistance": {} }), &json!({ "ViaResistance": {} }));
        assert_eq!(s.len(), 2, "a renamed variant tag is two key diffs: {s:?}");
    }
}
