//! Dump the original reader's view of every GDS fixture.
//!
//! Transformation: `(params.json, 161 x .gds)` -> one JSON file.
//! Shape: `{ "<relative path>": { "<cell>": [ [layer, x0, y0, x1, y1, ...], .. ] } }`
//! plus a parallel `"<path>#paths"` map of hierarchy paths, so a divergence in
//! instance naming shows up as well as one in geometry.
//!
//! Cells are flattened with the same options the original's `read_gds` picks,
//! because that is what every production caller got.

use gdsverify_core::io::read::gds;
use gdsverify_core::params::Deck;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tool lives at tools/reader_diff_ref")
        .to_path_buf()
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().is_some_and(|x| x == "gds") {
            out.push(p);
        }
    }
}

fn main() {
    let root = repo_root();
    let deck_text = std::fs::read_to_string(root.join("tests/fixtures/params.json"))
        .expect("tests/fixtures/params.json");
    let deck = Deck::from_json(&deck_text).expect("deck parses");

    let mut files = Vec::new();
    collect(&root.join("tests/fixtures"), &mut files);
    files.sort();

    let mut doc = Map::new();
    for path in &files {
        let rel = path
            .strip_prefix(&root)
            .expect("fixture under the repo root")
            .to_string_lossy()
            .into_owned();
        let bytes = std::fs::read(path).expect("readable fixture");
        let layout = match gds::read_gds(&bytes, &deck.layers) {
            Ok(l) => l,
            Err(e) => {
                doc.insert(rel, json!({ "__error": e }));
                continue;
            }
        };
        let mut cells = Map::new();
        let mut names: Vec<&String> = layout.cells.keys().collect();
        names.sort();
        for name in names {
            let store = &layout.cells[name];
            let mut polys = Vec::with_capacity(store.poly_count());
            let mut paths = Vec::with_capacity(store.poly_count());
            for p in 0..store.poly_count() {
                let start = store.poly_vert_start[p] as usize;
                let len = store.poly_vert_len[p] as usize;
                let mut row = vec![Value::from(store.poly_layer[p])];
                for i in start..start + len {
                    row.push(Value::from(store.verts_x[i]));
                    row.push(Value::from(store.verts_y[i]));
                }
                polys.push(Value::Array(row));
                paths.push(Value::from(store.poly_hierarchy_path[p].join("/")));
            }
            cells.insert(
                name.clone(),
                json!({ "polys": polys, "paths": paths, "texts": store.text_count() }),
            );
        }
        doc.insert(rel, Value::Object(cells));
    }

    let out = root.join("tools/reader_diff_ref/reader_reference.json");
    std::fs::write(&out, serde_json::to_vec(&Value::Object(doc)).expect("serialise"))
        .expect("write reference");
    eprintln!("wrote {} ({} files)", out.display(), files.len());
}
