//! LVS conformance binary.
//!
//! Usage: conformance-lvs [conformance_dir]   (default: ../../conformance)

use gdsverify::*;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

struct Totals {
    pass: usize,
    fail: usize,
    coverage: HashMap<String, (Vec<String>, Vec<String>)>,
}
impl Totals {
    fn new() -> Self {
        Totals {
            pass: 0,
            fail: 0,
            coverage: HashMap::new(),
        }
    }
    fn record(&mut self, ok: bool) {
        if ok {
            self.pass += 1
        } else {
            self.fail += 1
        }
    }
    fn track(&mut self, rule: &str, id: &str, is_pass: bool) {
        let e = self
            .coverage
            .entry(rule.into())
            .or_insert_with(|| (Vec::new(), Vec::new()));
        if is_pass {
            e.0.push(id.into());
        } else {
            e.1.push(id.into());
        }
    }
}

fn cell_store<'a>(layout: &'a GdsLayout, cell: &str) -> &'a GeometryStore {
    layout
        .cells
        .get(cell)
        .unwrap_or_else(|| panic!("cell {cell} missing from GDS"))
}

fn emit_coverage(t: &Totals, path: &str) {
    let mut csv = String::from("rule,pass_tests,fail_tests,status\n");
    let mut rules: Vec<&String> = t.coverage.keys().collect();
    rules.sort();
    let mut unproven = 0;
    for rule in &rules {
        let (pass, fail) = t.coverage.get(*rule).unwrap();
        let status = if fail.is_empty() {
            unproven += 1;
            "unproven"
        } else {
            "proven"
        };
        csv.push_str(&format!(
            "{},{},{},{}\n",
            rule,
            pass.join(";"),
            fail.join(";"),
            status
        ));
    }
    std::fs::write(path, &csv).expect("write coverage.csv");
    println!(
        "\ncoverage: {}/{} rules proven (have >=1 negative test), {} unproven -> {path}",
        rules.len() - unproven,
        rules.len(),
        unproven
    );
}

// --- JSON deck loader ---

#[derive(Deserialize)]
struct LayerDefRaw {
    layer: i32,
    datatype: i32,
}

#[derive(Deserialize, Default)]
struct LvsRaw {
    #[serde(default)]
    cut_required: bool,
}

#[derive(Deserialize)]
struct ParamsDoc {
    layers: HashMap<String, LayerDefRaw>,
    drc: Value,
    #[serde(default)]
    pex: HashMap<String, gdsverify::params::PexLayerParams>,
    #[serde(default)]
    lvs: LvsRaw,
    #[serde(default)]
    erc: gdsverify::params::ErcParams,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

fn load_deck_json(path: &str) -> Result<Deck, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let doc: ParamsDoc = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let layers = doc
        .layers
        .iter()
        .map(|(n, d)| (n.clone(), (d.layer, d.datatype)))
        .collect();
    let drc_rules = gdsverify::schema::drc_rules_from_json(&doc.drc)?;
    use gdsverify::schema::{ConnectivitySchema, DeviceSchema, MosRuleSchema, ViaSchema};

    let connectivity = if let Some(c) = doc.extra.get("connectivity") {
        ConnectivitySchema {
            conductors: c
                .get("conductors")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            vias: c
                .get("vias")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| {
                            let layer = v.get("layer")?.as_str()?.to_string();
                            let connects = v
                                .get("connects")?
                                .as_array()?
                                .iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect();
                            Some(ViaSchema { layer, connects })
                        })
                        .collect()
                })
                .unwrap_or_default(),
            intra_layer_touch: true,
            global_nets: Vec::new(),
        }
    } else {
        ConnectivitySchema::default()
    };

    let devices = if let Some(d) = doc.extra.get("devices") {
        let mos_rules = d
            .get("mos")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|r| {
                        Some(MosRuleSchema {
                            name: r.get("name")?.as_str()?.into(),
                            gate_layer: r.get("gate_layer")?.as_str()?.into(),
                            channel_layer: r.get("channel_layer")?.as_str()?.into(),
                            type_implant: r.get("type_implant")?.as_str()?.into(),
                            device_type: r.get("device_type")?.as_str()?.into(),
                            flavor_markers: r
                                .get("flavor_markers")
                                .and_then(|f| f.as_array())
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|p| {
                                            let arr = p.as_array()?;
                                            Some((
                                                arr.first()?.as_str()?.into(),
                                                arr.get(1)?.as_str()?.into(),
                                            ))
                                        })
                                        .collect()
                                })
                                .unwrap_or_default(),
                            well_layer: r
                                .get("well_layer")
                                .and_then(|w| w.as_str())
                                .map(String::from),
                            device_class: None,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        DeviceSchema {
            mos_rules,
            ..Default::default()
        }
    } else {
        DeviceSchema::default()
    };

    Deck::from_schema(VerifySchema {
        layers,
        drc_rules,
        pex: doc.pex,
        erc: doc.erc,
        lvs: LvsSchema {
            cut_required: doc.lvs.cut_required,
            ..Default::default()
        },
        connectivity,
        devices,
    })
}

// --- LVS helpers ---

fn build_reference(v: &Value) -> RefNetlist {
    let mut devices = Vec::new();
    for d in v["devices"].as_array().unwrap() {
        let kind = match d["type"].as_str().unwrap() {
            "nmos" => DeviceKind::Nmos,
            _ => DeviceKind::Pmos,
        };
        let flavor = match d.get("flavor").and_then(|v| v.as_str()) {
            Some("lvt") => DeviceFlavor::Lvt,
            Some("hvt") => DeviceFlavor::Hvt,
            _ => DeviceFlavor::Standard,
        };
        devices.push(RefDevice {
            kind,
            gate: d["g"].as_str().unwrap().to_string(),
            source: d["s"].as_str().unwrap().to_string(),
            drain: d["d"].as_str().unwrap().to_string(),
            w: d.get("w").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
            l: d.get("l").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
            flavor,
            body: None,
            ad: None,
            as_: None,
            pd: None,
            ps: None,
        });
    }
    RefNetlist {
        devices,
        net_seeds: std::collections::HashMap::new(),
        ref_two_terminal: Vec::new(),
        ref_bjt: Vec::new(),
    }
}

fn run_lvs_cases(manifest: &Value, deck: &Deck, layout: &GdsLayout, t: &mut Totals) {
    println!("--- LVS ---");
    let cases = manifest["lvs"]["cases"].as_array().unwrap();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let cell = case["cell"].as_str().unwrap();
        let expect_match = case["expect_match"].as_bool().unwrap();
        let reference = build_reference(&case["reference_netlist"]);

        let store = cell_store(layout, cell);
        let result = run_lvs(store, deck, &reference);

        let ok = result.matched == expect_match;
        t.record(ok);
        t.track("lvs", id, expect_match);
        let flag = if ok { "PASS" } else { "FAIL" };
        println!(
            "  [{flag}] {id:20} match={} exp={}  ({}N/{}P) {}",
            result.matched, expect_match, result.nmos, result.pmos, result.reason
        );
    }
}

#[test]
fn conformance() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "fixtures".to_string());
    let manifest_txt =
        std::fs::read_to_string(format!("{dir}/manifest.json")).expect("read manifest.json");
    let manifest: Value = serde_json::from_str(&manifest_txt).expect("parse manifest");

    let deck = load_deck_json(&format!("{dir}/params.json")).expect("load params.json");
    let gds_file = manifest["gds_file"].as_str().unwrap();
    let layout = load_gds(&format!("{dir}/{gds_file}"), &deck).expect("read gds");

    println!("== conformance-lvs ==");
    println!("cells loaded: {}", layout.cells.len());
    println!();

    let mut t = Totals::new();

    run_lvs_cases(&manifest, &deck, &layout, &mut t);

    println!();
    println!("== summary: {} passed, {} failed ==", t.pass, t.fail);

    let csv_path = format!("{dir}/coverage_lvs.csv");
    emit_coverage(&t, &csv_path);

    if t.fail > 0 {
        panic!("conformance failures");
    }
}
