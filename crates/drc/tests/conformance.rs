//! DRC conformance binary.
//!
//! Runs DRC cases + differential + determinism + metamorphic tests.
//!
//! Usage: conformance-drc [conformance_dir]   (default: ../../conformance)

use gdsverify::gpu;
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

// --- DRC cases ---

fn run_drc_cases(
    manifest: &Value,
    deck: &Deck,
    layout: &GdsLayout,
    backend: gpu::Backend,
    t: &mut Totals,
) {
    println!("--- DRC ---");
    let cases = manifest["drc"]["cases"].as_array().unwrap();
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let cell = case["cell"].as_str().unwrap();
        let rule = case["rule"].as_str().unwrap();
        let expect_n = case["expect_violations"].as_u64().unwrap() as usize;
        let case_strict = case
            .get("strict")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let store = cell_store(layout, cell);
        let report = run_drc_backend_strict(store, deck, backend, case_strict);
        let got: Vec<&Violation> = report
            .violations
            .iter()
            .filter(|v| v.kind == rule)
            .collect();

        let mut ok = got.len() == expect_n;
        let mut detail = String::new();

        if ok && expect_n > 0 {
            let expected_list = case["violations"].as_array().unwrap();
            let mut exp_meas: Vec<i64> = expected_list
                .iter()
                .filter_map(|e| e.get("measured").and_then(|x| x.as_i64()))
                .collect();
            if !exp_meas.is_empty() {
                let mut got_meas: Vec<i64> = got.iter().map(|v| v.measured).collect();
                got_meas.sort_unstable();
                exp_meas.sort_unstable();
                let matched = if exp_meas.len() == got_meas.len() {
                    exp_meas == got_meas
                } else {
                    let mut g = got_meas.clone();
                    exp_meas.iter().all(|m| {
                        g.iter()
                            .position(|x| x == m)
                            .map(|i| {
                                g.remove(i);
                            })
                            .is_some()
                    })
                };
                if !matched {
                    ok = false;
                    detail = format!("measured {got_meas:?} != expected {exp_meas:?}");
                }
            }
            let expected = &expected_list[0];
            if let (Some(mf), Some(_lf)) = (
                expected.get("measured_frac").and_then(|x| x.as_f64()),
                expected.get("limit_frac").and_then(|x| x.as_f64()),
            ) {
                let gm = got[0].measured as f64 / 1_000_000.0;
                if (gm - mf).abs() > 1e-4 {
                    ok = false;
                    detail = format!("frac {gm:.4} != expected {mf:.4}");
                }
            }
        }

        t.record(ok);
        t.track(rule, id, expect_n == 0);
        let flag = if ok { "PASS" } else { "FAIL" };
        print!(
            "  [{flag}] {id:28} rule={rule:16} got={} exp={}",
            got.len(),
            expect_n
        );
        if !detail.is_empty() {
            print!("  ({detail})");
        }
        println!();
    }
}

// --- Differential ---

fn run_differential(deck: &Deck, layout: &GdsLayout, t: &mut Totals) {
    println!("\n--- DIFFERENTIAL ---");
    if let Some(store) = layout.cells.get("LVS_INV") {
        let drc = run_drc(store, deck);
        let drc_clean =
            drc.by_kind("min_width").is_empty() && drc.by_kind("min_spacing").is_empty();

        let ref_inv = RefNetlist {
            devices: vec![
                RefDevice {
                    kind: DeviceKind::Nmos,
                    gate: "A".into(),
                    source: "VSS".into(),
                    drain: "Y".into(),
                    w: 0,
                    l: 0,
                    flavor: DeviceFlavor::Standard,
                    body: None,
                    ad: None,
                    as_: None,
                    pd: None,
                    ps: None,
                },
                RefDevice {
                    kind: DeviceKind::Pmos,
                    gate: "A".into(),
                    source: "VDD".into(),
                    drain: "Y".into(),
                    w: 0,
                    l: 0,
                    flavor: DeviceFlavor::Standard,
                    body: None,
                    ad: None,
                    as_: None,
                    pd: None,
                    ps: None,
                },
            ],
            net_seeds: HashMap::new(),
            ref_two_terminal: Vec::new(),
            ref_bjt: Vec::new(),
        };
        let lvs = run_lvs(store, deck, &ref_inv);
        let erc = run_erc(store, deck, &SignoffConfig::default());
        let erc_no_short = erc.by_check("supply_short").is_empty();
        let pex = run_pex(store, deck);
        let pex_ran = true;
        let _ = pex.total_cap();

        let ok = drc_clean && lvs.matched && erc_no_short && pex_ran;
        t.record(ok);
        t.track("differential", "DIFF_INV_CROSS", true);
        let flag = if ok { "PASS" } else { "FAIL" };
        println!("  [{flag}] DIFF_INV_CROSS          drc_clean={drc_clean} lvs={} erc_clean={erc_no_short} pex_ran={pex_ran}",
                 lvs.matched);

        let ref_wrong = RefNetlist {
            devices: vec![
                RefDevice {
                    kind: DeviceKind::Nmos,
                    gate: "A".into(),
                    source: "VSS".into(),
                    drain: "X".into(),
                    w: 0,
                    l: 0,
                    flavor: DeviceFlavor::Standard,
                    body: None,
                    ad: None,
                    as_: None,
                    pd: None,
                    ps: None,
                },
                RefDevice {
                    kind: DeviceKind::Nmos,
                    gate: "B".into(),
                    source: "X".into(),
                    drain: "Y".into(),
                    w: 0,
                    l: 0,
                    flavor: DeviceFlavor::Standard,
                    body: None,
                    ad: None,
                    as_: None,
                    pd: None,
                    ps: None,
                },
                RefDevice {
                    kind: DeviceKind::Pmos,
                    gate: "A".into(),
                    source: "VDD".into(),
                    drain: "Y".into(),
                    w: 0,
                    l: 0,
                    flavor: DeviceFlavor::Standard,
                    body: None,
                    ad: None,
                    as_: None,
                    pd: None,
                    ps: None,
                },
                RefDevice {
                    kind: DeviceKind::Pmos,
                    gate: "B".into(),
                    source: "VDD".into(),
                    drain: "Y".into(),
                    w: 0,
                    l: 0,
                    flavor: DeviceFlavor::Standard,
                    body: None,
                    ad: None,
                    as_: None,
                    pd: None,
                    ps: None,
                },
            ],
            net_seeds: HashMap::new(),
            ref_two_terminal: Vec::new(),
            ref_bjt: Vec::new(),
        };
        let lvs_neg = run_lvs(store, deck, &ref_wrong);
        let ok_neg = !lvs_neg.matched;
        t.record(ok_neg);
        t.track("differential", "DIFF_INV_NEG", false);
        let flag = if ok_neg { "PASS" } else { "FAIL" };
        println!(
            "  [{flag}] DIFF_INV_NEG            wrong-ref rejected={}",
            !lvs_neg.matched
        );
    }
}

// --- Parity ---

fn run_parity(manifest: &Value, deck: &Deck, layout: &GdsLayout, t: &mut Totals) {
    if !gpu::gpu_ready() {
        println!("\n--- PARITY --- (skipped: no GPU)");
        return;
    }
    println!("\n--- PARITY ---");
    let cases = manifest["drc"]["cases"].as_array().unwrap();
    for case in &cases[..cases.len().min(5)] {
        let id = case["id"].as_str().unwrap();
        let cell = case["cell"].as_str().unwrap();
        let store = cell_store(layout, cell);

        let cpu_report = run_drc_backend(store, deck, gpu::Backend::Cpu);
        let gpu_report = run_drc_backend(store, deck, gpu::Backend::Gpu);

        let cpu_json = cpu_report.to_canonical_json();
        let gpu_json = gpu_report.to_canonical_json();
        let ok = cpu_json == gpu_json;
        t.record(ok);
        let flag = if ok { "PASS" } else { "FAIL" };
        println!("  [{flag}] PARITY_{id}");
    }
}

// --- Determinism ---

fn run_determinism(manifest: &Value, deck: &Deck, layout: &GdsLayout, t: &mut Totals) {
    println!("\n--- DETERMINISM ---");
    let cases = manifest["drc"]["cases"].as_array().unwrap();
    // ponytail: 3 representative cases, 3 runs each
    for case in &cases[..cases.len().min(3)] {
        let id = case["id"].as_str().unwrap();
        let cell = case["cell"].as_str().unwrap();
        let store = cell_store(layout, cell);

        let baseline = run_drc_backend(store, deck, gpu::Backend::Cpu).to_canonical_json();
        let mut ok = true;
        for _ in 1..3 {
            let repeat = run_drc_backend(store, deck, gpu::Backend::Cpu).to_canonical_json();
            if repeat != baseline {
                ok = false;
                break;
            }
        }
        t.record(ok);
        let flag = if ok { "PASS" } else { "FAIL" };
        println!("  [{flag}] DETERM_{id}");
    }

    // Thread-count determinism
    for case in &cases[..cases.len().min(3)] {
        let id = case["id"].as_str().unwrap();
        let cell = case["cell"].as_str().unwrap();
        let store = cell_store(layout, cell);

        let baseline = run_drc_backend(store, deck, gpu::Backend::Cpu).to_canonical_json();
        let thread_counts = [1, 4];
        let mut ok = true;
        for n in thread_counts {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .build()
                .unwrap();
            let result = pool
                .install(|| run_drc_backend(store, deck, gpu::Backend::Cpu).to_canonical_json());
            if result != baseline {
                ok = false;
                break;
            }
        }
        t.record(ok);
        let flag = if ok { "PASS" } else { "FAIL" };
        println!("  [{flag}] DETERM_THREADS_{id}");
    }
}

// --- Metamorphic ---

fn run_metamorphic(deck: &Deck, layout: &GdsLayout, t: &mut Totals) {
    println!("\n--- METAMORPHIC ---");
    if let Some(store) = layout.cells.values().next() {
        let base = run_drc(store, deck);
        let base_count = base.violations.len();

        let mut shifted = GeometryStore::new();
        let offset = 10_000i32;
        for i in 0..store.poly_count() {
            let pid = gdsverify::geometry::PolyId(i as u32);
            let layer = store.poly_layer[i];
            let pts: Vec<(i32, i32)> = store
                .vertices(pid)
                .map(|(x, y)| (x + offset, y + offset))
                .collect();
            shifted.add_polygon(layer, &pts);
        }
        let shifted_report = run_drc(&shifted, deck);
        let ok = shifted_report.violations.len() == base_count;
        t.record(ok);
        let flag = if ok { "PASS" } else { "FAIL" };
        println!(
            "  [{flag}] META_TRANSLATE        base={} shifted={}",
            base_count,
            shifted_report.violations.len()
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

    println!("== conformance-drc ==");
    println!("cells loaded: {}", layout.cells.len());
    println!("active DRC rules: {}", deck.drc_rules.len());
    let backends = gpu::available_backends();
    let backend = *backends.last().unwrap();
    println!("backends available: {backends:?} -> using {backend:?}");
    println!();

    let mut t = Totals::new();

    run_drc_cases(&manifest, &deck, &layout, backend, &mut t);
    run_differential(&deck, &layout, &mut t);
    run_parity(&manifest, &deck, &layout, &mut t);
    run_determinism(&manifest, &deck, &layout, &mut t);
    run_metamorphic(&deck, &layout, &mut t);

    println!();
    println!("== summary: {} passed, {} failed ==", t.pass, t.fail);

    let csv_path = format!("{dir}/coverage_drc.csv");
    emit_coverage(&t, &csv_path);

    if t.fail > 0 {
        panic!("conformance failures");
    }
}
