//! Scratch probe: time analytical vs quasistatic PEX per fixture. Read-only w.r.t. crates/.
use gdsverify::{load_gds, run_pex, Deck};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf()
}

fn main() {
    let only = std::env::args().nth(1);
    let fx = root().join("tests/fixtures");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(fx.join("manifest.json")).unwrap()).unwrap();
    let deck =
        Deck::from_json(&std::fs::read_to_string(fx.join("params.json")).unwrap()).unwrap();
    println!("deck.pex_method = {:?}", deck.pex_method);
    let cases = manifest["pex"]["cases"].as_array().unwrap();
    for c in cases {
        let id = c["id"].as_str().unwrap();
        if let Some(o) = &only {
            if id != o {
                continue;
            }
        }
        let cell = c["cell"].as_str().unwrap();
        let layout =
            load_gds(fx.join("pex").join(format!("{id}.gds")).to_str().unwrap(), &deck).unwrap();
        let store = layout.cells.get(cell).unwrap().clone();
        let t = std::time::Instant::now();
        let r = run_pex(&store, &deck);
        let ana = t.elapsed().as_micros();

        let np = store.poly_count();
        let net_of_poly: Vec<u32> = (0..np as u32).collect();
        let t = std::time::Instant::now();
        let q = gdsverify_pex::bridge::extract_quasistatic(&store, &deck, &net_of_poly);
        let qs = t.elapsed().as_micros();
        let qres = match &q {
            Ok(m) => format!("ok nets={}", m.len()),
            Err(e) => format!("ERR {e}"),
        };
        println!(
            "{id:22} polys={np:5} ana={ana:>8}us  quasi={qs:>10}us  par={} {qres}",
            r.parasitics.len()
        );
    }
}
