//! Dump the *complete* report for every fixture in the conformance corpus.
//!
//! Transformation: `(manifest.json, params.json, 160 × .gds)` → one canonical
//! JSON file per case under `tests/golden/<suite>/<id>.json`.
//!
//! These files are the oracle for the `crates_clean/` rewrite. The original
//! suite compared counts and statuses, so a rule could flag the wrong shape at
//! the wrong coordinate with the wrong measurement and still pass; a golden
//! holds every field of every finding, so any logic change shows up as a diff.
//!
//! What this cannot do is prove the original is *correct* — where it is wrong,
//! the golden is wrong identically. That is the job of the property tests and
//! the KLayout oracle. See docs/TESTING.md.
//!
//!   cargo run --release --manifest-path tools/golden_dump/Cargo.toml
//!
//! With the argument `pex_qs` it dumps *only* `tests/golden/pex_qs/`, the
//! quasi-static PEX oracle. That subcommand exists because the no-argument run
//! rewrites `tests/golden/pex/`, whose row order is not reproducible run to run
//! (DIVERGENCES D15) — regenerating the analytical goldens as a side effect of
//! wanting the quasi-static ones would corrupt them.
//!
//!   cargo run --release --manifest-path tools/golden_dump/Cargo.toml -- pex_qs
//!
//! With the argument `lvs_extract` it dumps *only* `tests/golden/lvs_extract/`,
//! the connectivity-extraction oracle. Same reasoning as `pex_qs`: it must never
//! be reachable from the no-argument run.
//!
//!   cargo run --release --manifest-path tools/golden_dump/Cargo.toml -- lvs_extract

use gdsverify::{
    extract_netlist, run_drc_backend_strict, run_erc, run_lvs, run_pex,
    run_pex_by_net_with_accuracy_checked, Accuracy, Backend, Deck, DeviceFlavor, DeviceKind,
    GeometryStore, RefDevice, RefNetlist, SignoffConfig,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tool must live at tools/golden_dump")
        .to_path_buf()
}

fn fixture_root() -> PathBuf {
    repo_root().join("tests/fixtures")
}

fn read_json(path: &Path) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn cases<'a>(manifest: &'a Value, suite: &str) -> &'a [Value] {
    manifest
        .get(suite)
        .and_then(|s| s.get("cases"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn field<'a>(case: &'a Value, key: &str) -> &'a str {
    case.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("case missing string field `{key}`: {case}"))
}

/// Load one fixture's flattened top cell. Mirrors `tests/common.rs` so the
/// goldens describe exactly the stores the conformance suite exercises.
fn load_store(suite: &str, case: &Value, deck: &Deck) -> GeometryStore {
    let id = field(case, "id");
    let cell = field(case, "cell");
    let path = fixture_root().join(suite).join(format!("{id}.gds"));
    let layout = gdsverify::load_gds(path.to_str().expect("fixture path is UTF-8"), deck)
        .unwrap_or_else(|e| panic!("load {}: {e}", path.display()));
    layout
        .cells
        .get(cell)
        .unwrap_or_else(|| panic!("{} has no flattened cell `{cell}`", path.display()))
        .clone()
}

/// Reference netlist for an LVS case, mirroring `tests/test_lvs.rs`.
fn build_reference(value: &Value) -> RefNetlist {
    let devices = value
        .get("devices")
        .and_then(Value::as_array)
        .expect("reference_netlist.devices must be an array")
        .iter()
        .map(|d| RefDevice {
            kind: match d.get("type").and_then(Value::as_str) {
                Some("nmos") => DeviceKind::Nmos,
                Some("pmos") => DeviceKind::Pmos,
                other => panic!("unsupported reference device type {other:?}"),
            },
            gate: d["g"].as_str().expect("reference gate").to_string(),
            source: d["s"].as_str().expect("reference source").to_string(),
            drain: d["d"].as_str().expect("reference drain").to_string(),
            w: d.get("w").and_then(Value::as_i64).unwrap_or(0) as i32,
            l: d.get("l").and_then(Value::as_i64).unwrap_or(0) as i32,
            flavor: match d.get("flavor").and_then(Value::as_str) {
                Some("lvt") => DeviceFlavor::Lvt,
                Some("hvt") => DeviceFlavor::Hvt,
                Some("standard") | None => DeviceFlavor::Standard,
                Some(other) => panic!("unsupported reference flavor `{other}`"),
            },
            body: d.get("b").and_then(Value::as_str).map(str::to_string),
            ad: None,
            as_: None,
            pd: None,
            ps: None,
        })
        .collect();
    RefNetlist {
        devices,
        net_seeds: HashMap::new(),
        ref_two_terminal: Vec::new(),
        ref_bjt: Vec::new(),
    }
}

fn write_golden(suite: &str, id: &str, report: &Value) {
    let dir = repo_root().join("tests/golden").join(suite);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));
    let path = dir.join(format!("{id}.json"));
    // Pretty-printed and newline-terminated so a golden diff is reviewable in a
    // pull request rather than one unreadable line.
    let mut text = serde_json::to_string_pretty(report).expect("serialize report");
    text.push('\n');
    std::fs::write(&path, text).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

/// Reserialize through `Value` so key order is canonical (serde_json's `Value`
/// is a BTreeMap when `preserve_order` is off) rather than struct field order.
fn canonical(value: &impl serde::Serialize) -> Value {
    serde_json::to_value(value).expect("report must serialize")
}

/// Dump the quasi-static PEX oracle: `tests/golden/pex_qs/<id>.json`.
///
/// `tests/fixtures/params.json` pins no `pex_method`, so every fixture runs
/// `PexMethod::Analytical` and the ~4200-line quasi-static half has no oracle at
/// all. `Accuracy::Quasistatic` is therefore forced explicitly here, through the
/// *checked* entry point: `run_pex_by_net_with_accuracy` swallows a solver
/// failure and returns the analytical answer instead, which would make a refused
/// extrusion look like a completed 3-D solve.
///
/// Each file records the INPUT as well as the output. `net_of_poly` comes from
/// `lvs::extract_netlist`, which is not ported to `crates_clean/` yet; storing
/// the column lets the rewrite's quasi-static path be verified in isolation
/// today rather than after the LVS port lands. `net_count` goes with it because
/// the rewrite's `NetTable` is a dense column, not a `HashMap`.
///
/// Ordering is canonical: the result is a `HashMap<u32, NetParasitics>` and is
/// emitted as an array sorted by net id.
fn dump_pex_qs(manifest: &Value, deck: &Deck) {
    let mut ok = 0usize;
    let mut err = 0usize;
    for case in cases(manifest, "pex") {
        let id = field(case, "id");
        let store = load_store("pex", case, deck);
        let extracted = extract_netlist(&store, deck)
            .unwrap_or_else(|e| panic!("{id}: connectivity extraction: {e}"));

        let result = match run_pex_by_net_with_accuracy_checked(
            &store,
            deck,
            &extracted.net_of_poly,
            Accuracy::Quasistatic,
        ) {
            Ok(by_net) => {
                let mut nets: Vec<(u32, _)> = by_net.into_iter().collect();
                nets.sort_unstable_by_key(|(net, _)| *net);
                ok += 1;
                json!({
                    "ok": nets
                        .iter()
                        .map(|(net, p)| json!({
                            "net": net,
                            "r_ohm": p.r_ohm,
                            "cap_af": p.cap_af,
                        }))
                        .collect::<Vec<_>>()
                })
            }
            // Fail-closed behaviour is worth pinning too: the variant, the
            // rendered message and the diagnostic payload all go in the golden.
            Err(error) => {
                err += 1;
                let gdsverify::pex::PexError::UnsupportedGeometry(diagnostics) = &error;
                json!({
                    "err": {
                        "variant": "UnsupportedGeometry",
                        "display": error.to_string(),
                        "diagnostics": canonical(diagnostics),
                    }
                })
            }
        };

        write_golden(
            "pex_qs",
            id,
            &json!({
                "net_of_poly": extracted.net_of_poly,
                "net_count": extracted.net_count,
                "result": result,
            }),
        );
    }
    println!("pex_qs {ok} ok + {err} err written to tests/golden/pex_qs/");
}

/// Dump the extraction oracle: `tests/golden/lvs_extract/<suite>__<id>.json`.
///
/// `extract_netlist` is 2487 lines whose output — net numbering and the device
/// table — feeds LVS, ERC and both PEX paths, and *none* of it is pinned. The 16
/// `tests/golden/lvs/` files record only the final verdict, so a rewrite that
/// renumbers every net but still reports `matched` passes them all while
/// silently invalidating the 27 `tests/golden/pex_qs/` files, which store
/// `net_of_poly` as their input.
///
/// Run over every fixture in every manifest section, not just `lvs`: connectivity
/// is extracted for the DRC/ERC/PEX geometry too, and those stores are where the
/// interesting topologies live.
///
/// Ordering is canonical. `devices`, `bjt_devices` and `two_terminal` keep their
/// `Vec` order — that order is produced by index-ordered loops and is itself part
/// of the contract, so sorting it would hide a real regression. Everything that
/// leaves `extract_netlist` through a `HashMap` is sorted here instead:
///
/// - `floating_nets` — pushed in `HashMap<u32, usize>` iteration order
///   (`crates/lvs/src/extract.rs:1811`), sorted by `net_id`.
/// - `net_names` — a `HashMap<u32, String>`, emitted as an array sorted by net.
/// - `label_conflicts` — built while iterating `store.net_labels`
///   (`crates/lvs/src/extract.rs:1693`), sorted as strings.
fn dump_lvs_extract(manifest: &Value, deck: &Deck) {
    let mut ok = 0usize;
    let mut err = 0usize;
    let mut nets = 0usize;
    let mut devs = 0usize;
    for suite in ["drc", "erc", "lvs", "pex"] {
        for case in cases(manifest, suite) {
            let id = field(case, "id");
            let store = load_store(suite, case, deck);
            let body = match extract_netlist(&store, deck) {
                Ok(e) => {
                    ok += 1;
                    nets += e.net_count;
                    devs += e.devices.len() + e.bjt_devices.len() + e.two_terminal.len();

                    let mut floating: Vec<&_> = e.floating_nets.iter().collect();
                    floating.sort_by_key(|f| f.net_id);
                    let mut names: Vec<(&u32, &String)> = e.net_names.iter().collect();
                    names.sort_unstable();
                    let mut conflicts = e.label_conflicts.clone();
                    conflicts.sort_unstable();

                    json!({
                        "ok": {
                            "net_count": e.net_count,
                            "used_nets": e.used_nets,
                            "net_of_poly": e.net_of_poly,
                            "devices": e.devices.iter().map(|d| json!({
                                "kind": canonical(&d.kind),
                                "gate": d.gate,
                                "source": d.source,
                                "drain": d.drain,
                                "body": d.body,
                                "flavor": canonical(&d.flavor),
                                "w": d.w,
                                "l": d.l,
                                "device_class": d.device_class,
                                "well_provenance": d.well_provenance,
                                "ad": d.ad,
                                "as": d.as_,
                                "pd": d.pd,
                                "ps": d.ps,
                            })).collect::<Vec<_>>(),
                            "bjt_devices": e.bjt_devices.iter().map(|b| json!({
                                "kind": canonical(&b.kind),
                                "collector": b.collector,
                                "base": b.base,
                                "emitter": b.emitter,
                                "name": b.name,
                            })).collect::<Vec<_>>(),
                            "two_terminal": e.two_terminal.iter().map(|t| json!({
                                "kind": canonical(&t.kind),
                                "name": t.name,
                                "terminal_a": t.terminal_a,
                                "terminal_b": t.terminal_b,
                                "value": t.value,
                            })).collect::<Vec<_>>(),
                            "floating_nets": canonical(&floating),
                            "net_names": names
                                .iter()
                                .map(|(net, name)| json!({ "net": net, "name": name }))
                                .collect::<Vec<_>>(),
                            "label_conflicts": conflicts,
                        }
                    })
                }
                // Fail-closed behaviour is pinned too: a fixture whose geometry
                // extraction is refused must go on being refused, with the same
                // message.
                Err(error) => {
                    err += 1;
                    json!({ "err": { "display": error.to_string() } })
                }
            };
            write_golden("lvs_extract", &format!("{suite}__{id}"), &body);
        }
    }
    println!(
        "lvs_extract {ok} ok + {err} err written to tests/golden/lvs_extract/ \
         ({nets} nets, {devs} devices pinned)"
    );
}

fn main() {
    let manifest = read_json(&fixture_root().join("manifest.json"));
    let deck_text = std::fs::read_to_string(fixture_root().join("params.json"))
        .expect("read tests/fixtures/params.json");
    let deck = Deck::from_json(&deck_text).expect("load fixture deck");

    match std::env::args().nth(1).as_deref() {
        Some("pex_qs") => return dump_pex_qs(&manifest, &deck),
        Some("lvs_extract") => return dump_lvs_extract(&manifest, &deck),
        _ => {}
    }

    let mut counts: Vec<(&str, usize)> = Vec::new();

    // --- DRC -------------------------------------------------------------
    let drc = cases(&manifest, "drc");
    for case in drc {
        let id = field(case, "id");
        let strict = case
            .get("strict")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let store = load_store("drc", case, &deck);
        let report = run_drc_backend_strict(&store, &deck, Backend::Cpu, strict);
        // `to_canonical_json` already sorts; go through it so the golden and the
        // in-tree canonical form can never disagree about ordering.
        let sorted: Value =
            serde_json::from_str(&report.to_canonical_json()).expect("canonical DRC json");
        write_golden("drc", id, &json!({ "violations": sorted }));
    }
    counts.push(("drc", drc.len()));

    // --- ERC -------------------------------------------------------------
    let erc = cases(&manifest, "erc");
    for case in erc {
        let id = field(case, "id");
        let store = load_store("erc", case, &deck);
        let report = run_erc(&store, &deck, &SignoffConfig::default());
        write_golden("erc", id, &canonical(&report));
    }
    counts.push(("erc", erc.len()));

    // --- LVS -------------------------------------------------------------
    let lvs = cases(&manifest, "lvs");
    for case in lvs {
        let id = field(case, "id");
        let reference = build_reference(&case["reference_netlist"]);
        let store = load_store("lvs", case, &deck);
        let result = run_lvs(&store, &deck, &reference);
        write_golden("lvs", id, &canonical(&result));
    }
    counts.push(("lvs", lvs.len()));

    // --- PEX -------------------------------------------------------------
    //
    // PEX reports carry f64. Byte equality is the right check within one build
    // (same binary, same bits), but the consumer must compare these numerically
    // with a tolerance when diffing across two trees — a rewrite that reassociates
    // a sum is allowed to move the last ulp. See docs/TESTING.md.
    let pex = cases(&manifest, "pex");
    for case in pex {
        let id = field(case, "id");
        let store = load_store("pex", case, &deck);
        let report = run_pex(&store, &deck);
        write_golden("pex", id, &canonical(&report));
    }
    counts.push(("pex", pex.len()));

    let total: usize = counts.iter().map(|(_, n)| n).sum();
    for (suite, n) in &counts {
        println!("{suite:5} {n:4} goldens");
    }
    println!("----- {total:4} written to tests/golden/");
}
