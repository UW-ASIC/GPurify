//! ERC conformance binary.
//!
//! Runs ERC cases + unsupported construct audit.
//!
//! Usage: conformance-erc [conformance_dir]   (default: ../../conformance)

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

// --- ERC cases ---

fn run_erc_cases(manifest: &Value, deck: &Deck, layout: &GdsLayout, t: &mut Totals) {
    let cases = match manifest.get("erc").and_then(|e| e["cases"].as_array()) {
        Some(c) if !c.is_empty() => c,
        _ => return,
    };
    println!("--- ERC ---");
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let cell = case["cell"].as_str().unwrap();
        let check = case["check"].as_str().unwrap();
        let expect_n = case["expect_violations"].as_u64().unwrap() as usize;

        let store = cell_store(layout, cell);
        let report = run_erc(store, deck, &SignoffConfig::default());
        let got: Vec<&ErcViolation> = report.by_check(check);

        let ok = got.len() == expect_n;
        t.record(ok);
        t.track(check, id, expect_n == 0);
        let flag = if ok { "PASS" } else { "FAIL" };
        println!(
            "  [{flag}] {id:28} check={check:20} got={} exp={expect_n}",
            got.len()
        );
    }
}

// --- Unsupported audit ---

fn run_unsupported_audit(t: &mut Totals) {
    println!("\n--- UNSUPPORTED AUDIT ---");
    let manifest = gdsverify::manifest::builtin_manifest();
    let unsupported: Vec<_> = manifest
        .iter()
        .filter(|c| c.status == gdsverify::manifest::CapabilityStatus::Unsupported)
        .collect();

    let ok_tracked = !unsupported.is_empty();
    t.record(ok_tracked);
    let flag = if ok_tracked { "PASS" } else { "FAIL" };
    println!(
        "  [{flag}] UNSUP_TRACKED          {} unsupported capabilities in manifest",
        unsupported.len()
    );

    let drc_unsup_params: Vec<(&str, gdsverify::params::DrcRuleParam)> = vec![
        (
            "drc_asymmetric_enclosure",
            gdsverify::params::DrcRuleParam::AsymmetricEnclosure {
                id: "test_asym".into(),
                outer: 0,
                inner: 1,
                min_one_side: 100,
            },
        ),
        (
            "drc_multi_patterning",
            gdsverify::params::DrcRuleParam::MultiPatterning {
                id: "test_mp".into(),
                layer: 0,
                num_colors: 2,
                color_spacing: 100,
            },
        ),
    ];

    for (cap_id, param) in &drc_unsup_params {
        let resolved = gdsverify::drc::rules::FACTORIES
            .iter()
            .find_map(|f| f(param, false));
        let factory_exists = resolved.is_some();
        let in_manifest = unsupported.iter().any(|c| c.id == *cap_id);
        let ok = factory_exists && in_manifest;
        t.record(ok);
        t.track("unsupported_audit", cap_id, false);
        let flag = if ok { "PASS" } else { "FAIL" };
        println!(
            "  [{flag}] UNSUP_{:20} factory={factory_exists} manifest={in_manifest}",
            cap_id.to_uppercase()
        );
    }

    {
        let cap_id = "pex_inductance";
        let in_manifest = unsupported.iter().any(|c| c.id == cap_id);
        t.record(in_manifest);
        t.track("unsupported_audit", cap_id, false);
        let flag = if in_manifest { "PASS" } else { "FAIL" };
        println!(
            "  [{flag}] UNSUP_{:20} manifest={in_manifest}",
            cap_id.to_uppercase()
        );
    }

    let gaps = gdsverify::manifest::validate_no_false_clean(&manifest);
    for g in &gaps {
        println!("    warn: {g}");
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

    println!("== conformance-erc ==");
    println!("cells loaded: {}", layout.cells.len());
    println!();

    let mut t = Totals::new();

    run_erc_cases(&manifest, &deck, &layout, &mut t);
    run_unsupported_audit(&mut t);

    println!();
    println!("== summary: {} passed, {} failed ==", t.pass, t.fail);

    let csv_path = format!("{dir}/coverage_erc.csv");
    emit_coverage(&t, &csv_path);

    if t.fail > 0 {
        panic!("conformance failures");
    }
}
