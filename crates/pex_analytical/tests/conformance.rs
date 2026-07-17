//! PEX conformance binary.
//!
//! Usage: conformance-pex [conformance_dir]   (default: ../../conformance)

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

// --- PEX cases ---

fn run_pex_cases(manifest: &Value, deck: &Deck, layout: &GdsLayout, t: &mut Totals) {
    println!("--- PEX ---");
    let cases = manifest["pex"]["cases"].as_array().unwrap();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let cell = case["cell"].as_str().unwrap();
        let kind = case["kind"].as_str().unwrap();
        let tol = case["tol"].as_f64().unwrap_or(1e-6);
        let expected: &HashMap<String, Value> =
            &serde_json::from_value(case["expected"].clone()).unwrap();

        let expect_mismatch = case
            .get("expect_mismatch")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let store = cell_store(layout, cell);
        let report = run_pex(store, deck);

        if kind == "per_net" {
            let ext =
                extract_netlist(store, deck).expect("extraction requires connectivity config");
            let by_net = run_pex_by_net(store, deck, &ext.net_of_poly);
            let expect_nets = case["expected"].as_object().unwrap();
            let mut ok = true;
            let mut detail = String::new();
            for (net_str, vals) in expect_nets {
                let net_id: u32 = net_str.parse().unwrap_or(u32::MAX);
                let got = by_net.get(&net_id).copied().unwrap_or_default();
                if let Some(er) = vals.get("r_ohm").and_then(|v| v.as_f64()) {
                    if (got.r_ohm - er).abs() > tol.max(er.abs() * 1e-6 + 1e-9) {
                        ok = false;
                        detail = format!("net{net_id} R {:.4} != {:.4}", got.r_ohm, er);
                    }
                }
                if let Some(ec) = vals.get("cap_af").and_then(|v| v.as_f64()) {
                    if (got.cap_af - ec).abs() > tol.max(ec.abs() * 1e-6 + 1e-9) {
                        ok = false;
                        detail = format!("net{net_id} C {:.4} != {:.4}", got.cap_af, ec);
                    }
                }
            }
            if expect_mismatch {
                ok = !ok;
                detail.clear();
            }
            t.record(ok);
            let flag = if ok { "PASS" } else { "FAIL" };
            t.track(kind, id, !expect_mismatch);
            print!("  [{flag}] {id:18} kind={kind:12}");
            if expect_mismatch {
                print!(" (negative)");
            }
            if !detail.is_empty() {
                print!("  ({detail})");
            }
            println!();
            continue;
        }

        let (got, exp, unit) = match kind {
            "resistance" => {
                let g = report.total_resistance("met1");
                (g, expected["r_ohm"].as_f64().unwrap(), "ohm")
            }
            "resistance_met2" => {
                let g = report.total_resistance("met2");
                (g, expected["r_ohm"].as_f64().unwrap(), "ohm")
            }
            "area_cap" => {
                let g = report
                    .area_caps()
                    .iter()
                    .map(|p| match p {
                        Parasitic::AreaCap { af, .. } => *af,
                        _ => 0.0,
                    })
                    .sum::<f64>();
                (g, expected["c_af"].as_f64().unwrap(), "aF")
            }
            "coupling_cap" => {
                let g = report
                    .coupling_caps()
                    .iter()
                    .map(|p| match p {
                        Parasitic::CouplingCap { af, .. } => *af,
                        _ => 0.0,
                    })
                    .sum::<f64>();
                (g, expected["c_af"].as_f64().unwrap(), "aF")
            }
            "coupling_cap_met2" => {
                let g = report
                    .coupling_caps()
                    .iter()
                    .map(|p| match p {
                        Parasitic::CouplingCap { layer, af, .. } if layer == "met2" => *af,
                        _ => 0.0,
                    })
                    .sum::<f64>();
                (g, expected["c_af"].as_f64().unwrap(), "aF")
            }
            "interlayer_cap" => {
                let g = report
                    .interlayer_caps()
                    .iter()
                    .map(|p| match p {
                        Parasitic::InterlayerCap { af, .. } => *af,
                        _ => 0.0,
                    })
                    .sum::<f64>();
                (g, expected["c_af"].as_f64().unwrap(), "aF")
            }
            "via_resistance" => {
                let g = report
                    .via_resistances()
                    .iter()
                    .map(|p| match p {
                        Parasitic::ViaResistance { ohm, .. } => *ohm,
                        _ => 0.0,
                    })
                    .sum::<f64>();
                (g, expected["r_ohm"].as_f64().unwrap(), "ohm")
            }
            _ => (0.0, 0.0, "?"),
        };

        let within = (got - exp).abs() <= tol.max(exp.abs() * 1e-6 + 1e-9);
        let ok = if expect_mismatch { !within } else { within };
        t.record(ok);
        t.track(kind, id, !expect_mismatch);
        let flag = if ok { "PASS" } else { "FAIL" };
        let neg = if expect_mismatch { " (negative)" } else { "" };
        println!("  [{flag}] {id:18} kind={kind:12} got={got:.4}{unit} exp={exp:.4}{unit}{neg}");
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

    println!("== conformance-pex ==");
    println!("cells loaded: {}", layout.cells.len());
    println!();

    let mut t = Totals::new();

    run_pex_cases(&manifest, &deck, &layout, &mut t);

    println!();
    println!("== summary: {} passed, {} failed ==", t.pass, t.fail);

    let csv_path = format!("{dir}/coverage_pex.csv");
    emit_coverage(&t, &csv_path);

    if t.fail > 0 {
        panic!("conformance failures");
    }
}
