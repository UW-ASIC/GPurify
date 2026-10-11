//! Floating gates against Yosys `check` (testing-plan §4 L6, ledger O1),
//! net by net, on X4's topology enumeration: every circuit of three nfets on
//! four nets up to renaming (11 051), and every four-terminal nfet and pfet
//! (512).
//!
//! **What Yosys is given.** Each circuit as structural Verilog written from
//! the board's description, never from anything `GPurify` extracted: a wire
//! per net, a cell per transistor of a blackbox module whose gate is an
//! `input` and whose source, drain and bulk are `inout`. It is written twice:
//! once with no ports, for `floating_gate(; labels_are_ports: false)`, and
//! once with each labelled net (VDD, VSS, VDDH) a module `input`, for
//! `labels_are_ports: true`.
//!
//! **Oracle.** Yosys `check` (`passes/cmds/check.cc`): a wire bit some cell
//! input reads ("used") with no driver: no cell output or inout and no module
//! input reaches it ("Wire … is used but has no driver"). On a transistor
//! netlist that is a net every one of whose terminals is a gate, and that no
//! port drives: `GPurify`'s `floating_gate` (role mask exactly GATE, a
//! labelled net a port when `labels_are_ports`).
//!
//! **Compared.** For each circuit and each row, the set of nets Yosys warns
//! about against the set `GPurify` flags. `GPurify`'s net is read off its
//! violation's shape and its extracted nets, and named by the met2 track of
//! each board net.
//!
//! **No open tool defines the rest of this family on a transistor netlist.**
//! Yosys's multiple-driver check (ERC-G3) counts cell `output` ports; a
//! channel has no direction until the design's rails orient it, which is
//! `GPurify`'s own rule (`multiple_drivers`, F28), so a translation would
//! carry `GPurify`'s answer into the oracle. No open tool checks a gate tied
//! to a rail (ERC-G7, `tie_high_low`). Both stay on their naive graph oracle
//! (X4's `Board::expect`) and belong to the beyond-open-source evidence
//! (ledger P1).

use super::{canonical_assignments, dev, three_rails, track_y, Board, Dev, Model, NETS};
use crate::harness;
use gpurify::check::topology::NetId;
use gpurify::geom::PolyId;
use gpurify_testgen::oracle;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Circuits per Yosys process.
const BATCH: usize = 1000;

/// How long one Yosys run may take; it takes seconds.
const LIMIT: Duration = Duration::from_mins(10);

/// The blackbox transistors: the gate an input, the channel ends and the
/// bulk inouts.
const CELLS: &str = "(* blackbox *)
module nfet(input g, inout s, inout d);
endmodule
(* blackbox *)
module pfet(input g, inout s, inout d);
endmodule
(* blackbox *)
module nfet_b(input g, inout s, inout d, inout b);
endmodule
(* blackbox *)
module pfet_b(input g, inout s, inout d, inout b);
endmodule
";

/// The circuits compared: X4's enumeration of three nfets on four nets
/// without intent, and every four-terminal transistor.
fn boards() -> Vec<(String, Board)> {
    let mut out = Vec::new();
    for a in canonical_assignments(9) {
        let mut board = three_rails(false);
        board.devs = a
            .chunks(3)
            .map(|t| dev(Model::Nfet, t[0], t[1], t[2]))
            .collect();
        let name: String = a.iter().map(ToString::to_string).collect();
        out.push((format!("three/{name}"), board));
    }
    for model in [Model::NfetB, Model::PfetB] {
        for code in 0..NETS.pow(4) {
            let digit = |k: u32| code / NETS.pow(k) % NETS;
            let mut board = three_rails(false);
            board.devs = vec![Dev {
                model,
                g: digit(0),
                s: digit(1),
                d: digit(2),
                b: Some(digit(3)),
            }];
            out.push((format!("bulk/{model:?}/{code}"), board));
        }
    }
    out
}

/// The cell name of a model.
fn cell(model: Model) -> &'static str {
    match model {
        Model::Nfet => "nfet",
        Model::Pfet => "pfet",
        Model::Clamp => "clamp",
        Model::NfetB => "nfet_b",
        Model::PfetB => "pfet_b",
    }
}

/// Circuit `i` as module `c<i>_<suffix>`; with `ports`, each labelled net is
/// a module input.
fn module(i: usize, board: &Board, ports: bool) -> String {
    let suffix = if ports { "ports" } else { "bare" };
    let inputs: Vec<String> = (0..NETS)
        .filter(|&n| ports && board.labels[n].is_some())
        .map(|n| format!("input n{n}"))
        .collect();
    let mut s = format!("module c{i}_{suffix}({});\n", inputs.join(", "));
    for n in 0..NETS {
        if !(ports && board.labels[n].is_some()) {
            let _ = writeln!(s, "  wire n{n};");
        }
    }
    for (k, d) in board.devs.iter().enumerate() {
        let bulk = d.b.map(|b| format!(", .b(n{b})")).unwrap_or_default();
        let _ = writeln!(
            s,
            "  {} m{k} (.g(n{}), .s(n{}), .d(n{}){bulk});",
            cell(d.model),
            d.g,
            d.s,
            d.d
        );
    }
    s.push_str("endmodule\n");
    s
}

/// The nets Yosys warns are used with no driver, per module:
/// `Wire c3_bare.\n1 is used but has no driver.`
fn undriven(log: &str) -> BTreeMap<String, BTreeSet<usize>> {
    let mut out: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    for line in log.lines() {
        let Some(rest) = line.split("Wire ").nth(1) else {
            continue;
        };
        let Some(wire) = rest.strip_suffix(" is used but has no driver.") else {
            continue;
        };
        let Some((module, net)) = wire.split_once('.') else {
            continue;
        };
        if let Some(n) = net.trim_start_matches('\\').strip_prefix('n') {
            if let Ok(n) = n.parse() {
                out.entry(module.to_owned()).or_default().insert(n);
            }
        }
    }
    out
}

/// The board nets `GPurify`'s two floating-gate rows flag: `fg` (labels are
/// not ports) and `fgp` (they are).
fn flagged(name: &str, board: &Board) -> (BTreeSet<usize>, BTreeSet<usize>) {
    let fixture = board.fixture(&format!("erc/yosys/{name}"));
    let ran = harness::run(&fixture).unwrap_or_else(|why| panic!("{name}: {why}"));
    let store = &ran.loaded.store;
    let met2 = ran
        .loaded
        .deck
        .layers
        .id(&ran.loaded.strings, "met2")
        .expect("the board deck draws met2");
    // Each board net's extracted net, by its met2 track.
    let mut board_net: BTreeMap<NetId, usize> = BTreeMap::new();
    for row in store.polys_on_layer(met2) {
        let bbox = store.poly_bbox(PolyId(row));
        if let Some(n) = (0..NETS).find(|&n| track_y(n) == bbox.ylo.raw()) {
            board_net.insert(ran.extracted.nets.net_of(PolyId(row)), n);
        }
    }
    let v = &ran.outputs.violations;
    let (mut fg, mut fgp) = (BTreeSet::new(), BTreeSet::new());
    for i in 0..v.len() {
        let into = match ran.loaded.strings.resolve(v.rule[i]) {
            "fg" => &mut fg,
            "fgp" => &mut fgp,
            _ => continue,
        };
        let net = ran.extracted.nets.net_of(v.shape_a[i]);
        let n = board_net
            .get(&net)
            .copied()
            .unwrap_or_else(|| panic!("{name}: a floating gate on a net with no met2 track"));
        into.insert(n);
    }
    (fg, fgp)
}

/// What the comparisons found.
#[derive(Default)]
struct Tally {
    circuits: usize,
    /// Floating nets both tools flag, over both rows.
    agreed: usize,
    broken: Vec<String>,
}

/// One batch: `GPurify` and one Yosys process on every circuit.
fn batch(yosys: &Path, boards: &[(String, Board)]) -> Tally {
    let dir = oracle::scratch("yosys");
    let mut verilog = String::from(CELLS);
    for (i, (_, board)) in boards.iter().enumerate() {
        verilog.push_str(&module(i, board, false));
        verilog.push_str(&module(i, board, true));
    }
    std::fs::write(dir.join("boards.v"), verilog).expect("the scratch directory is writable");
    let log = oracle::run(
        yosys,
        &[
            "-q",
            "-l",
            "yosys.log",
            "-p",
            "read_verilog boards.v; check",
        ],
        &dir,
        LIMIT,
    );
    let text = std::fs::read_to_string(dir.join("yosys.log")).unwrap_or(log);
    let theirs = undriven(&text);
    let mut tally = Tally::default();
    for (i, (name, board)) in boards.iter().enumerate() {
        tally.circuits += 1;
        let (fg, fgp) = flagged(name, board);
        for (ours, suffix) in [(fg, "bare"), (fgp, "ports")] {
            let yosys = theirs
                .get(&format!("c{i}_{suffix}"))
                .cloned()
                .unwrap_or_default();
            if ours == yosys {
                tally.agreed += ours.len();
            } else {
                tally.broken.push(format!(
                    "{name} ({suffix}): GPurify flags nets {ours:?}, Yosys {yosys:?}"
                ));
            }
        }
    }
    if tally.broken.is_empty() {
        let _ = std::fs::remove_dir_all(&dir);
    } else {
        tally.broken.push(super::kept(&dir));
    }
    tally
}

/// Every three-nfet circuit of X4's enumeration and every four-terminal
/// transistor: the nets `GPurify`'s `floating_gate` flags, with and without
/// labels as ports, are the nets Yosys `check` finds used with no driver.
///
/// Oracle: differential against Yosys `check` (module docs). The nightly
/// `oracles` job runs it.
#[test]
#[ignore = "release tier: needs yosys (nix develop .#oracles)"]
fn yosys_differential_on_the_x4_topology_enumeration() {
    let yosys = oracle::tool("yosys");
    let boards = boards();
    let chunks: Vec<&[(String, Board)]> = boards.chunks(BATCH).collect();
    let next = AtomicUsize::new(0);
    let total = Mutex::new(Tally::default());
    std::thread::scope(|scope| {
        for _ in 0..oracle::MAX_RUNNING {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(chunk) = chunks.get(i) else {
                    break;
                };
                let found = batch(&yosys, chunk);
                let mut total = total.lock().expect("not poisoned");
                total.circuits += found.circuits;
                total.agreed += found.agreed;
                total.broken.extend(found.broken);
            });
        }
    });
    let total = total.into_inner().expect("not poisoned");
    println!(
        "yosys: {} circuits, {} floating nets agree, {} broken",
        total.circuits,
        total.agreed,
        total.broken.len()
    );
    assert!(
        total.broken.is_empty(),
        "{} disagreements (first 60):\n{}",
        total.broken.len(),
        total.broken[..total.broken.len().min(60)].join("\n")
    );
    assert_eq!(total.circuits, boards.len(), "every circuit ran");
    assert!(
        total.agreed > 5000,
        "too few floating nets: {}",
        total.agreed
    );
}
