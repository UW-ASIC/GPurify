//! Route-level extraction of a DEF (PEX-014) against `OpenROAD`'s extractor
//! (`OpenRCX`, `extract_parasitics -lef_rc`), on seeded designs of straight
//! two-pin wires.
//!
//! **What each tool is given.** One LEF whose `RESISTANCE RPERSQ`,
//! `CAPACITANCE CPERSQDIST` and `EDGECAPACITANCE` are the deck's `sheet`,
//! `area_cap` and `fringe_cap`, and one DEF: nets on M1 or M2, each one
//! straight wire between two placed pins, far enough apart (over ten
//! thicknesses) that the closed forms couple nothing, and `OpenRCX` with
//! LEF RC extracts no coupling.
//!
//! **Compared.** Per net, read back from `OpenRCX`'s SPEF
//! (`gpurify_extract::foreign`): the resistance, `RPERSQ · L / W` with the
//! wire's half-width extensions in `L`, the same in both to the SPEF's
//! printed digits ([`R_PRINTED`]); and the capacitance, which differs by a
//! defined amount: `OpenRCX` charges the fringe on a wire's two long sides
//! (`2 · EDGECAPACITANCE · L`), the closed form on its whole perimeter, so
//! `GPurify` reads `2 · W · fringe_cap` more, the wire's two ends; to the
//! printed resolution ([`C_PRINTED`]). A coupling between two crossing
//! wires, which `OpenRCX` with LEF RC leaves out, is kept out of the
//! designs: that difference is the closed forms' interlayer term.

use gpurify::engine::pipeline::Inputs;
use gpurify::engine::run::{run, Checks, RunOptions};
use gpurify_extract::foreign;
use gpurify_extract::Parasitic;
use gpurify_testgen::{oracle, Rng};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

/// Designs compared.
const DESIGNS: u64 = 30;

/// `OpenRCX`'s SPEF prints capacitance to 1e-7 pF, 1e-4 fF: half of it,
/// with room for a sum of two.
const C_PRINTED: f64 = 1e-4;

/// Its resistance's printed resolution, relative: five significant digits.
const R_PRINTED: f64 = 1e-4;

/// Per metal: name, width nm, sheet Ω/□, area aF/µm², fringe aF/µm,
/// height nm.
const METALS: [(&str, i64, f64, f64, f64, i64); 2] = [
    ("M1", 100, 0.1, 30.0, 40.0, 1000),
    ("M2", 200, 0.05, 20.0, 30.0, 1400),
];

fn lef() -> String {
    let mut out = String::from(
        "VERSION 5.8 ;\nBUSBITCHARS \"[]\" ;\nDIVIDERCHAR \"/\" ;\n\
         UNITS\n  DATABASE MICRONS 1000 ;\n  CAPACITANCE PICOFARADS 1 ;\n  RESISTANCE OHMS 1 ;\nEND UNITS\n",
    );
    for (k, (name, width, sheet, area, fringe, _)) in METALS.iter().enumerate() {
        let dir = if k == 0 { "HORIZONTAL" } else { "VERTICAL" };
        writeln!(
            out,
            "LAYER {name}\n  TYPE ROUTING ;\n  DIRECTION {dir} ;\n  PITCH 1 ;\n  WIDTH {} ;\n  \
             SPACING 0.1 ;\n  THICKNESS 0.1 ;\n  RESISTANCE RPERSQ {sheet} ;\n  \
             CAPACITANCE CPERSQDIST {:e} ;\n  EDGECAPACITANCE {:e} ;\nEND {name}",
            f64::from(u32::try_from(*width).expect("small")) / 1000.0,
            area * 1e-6,
            fringe * 1e-6
        )
        .expect("a String");
        if k == 0 {
            out.push_str("LAYER V1\n  TYPE CUT ;\n  SPACING 0.1 ;\n  RESISTANCE 2 ;\nEND V1\n");
        }
    }
    out.push_str("END LIBRARY\n");
    out
}

/// The deck, the LEF's layers and RC.
fn deck() -> String {
    let mut out = String::from(
        "grid 1nm\nlayer M1 = gds(1, 0)\nlayer V1 = gds(2, 0)\nlayer M2 = gds(3, 0)\n\
         connect conductors [M1, M2]\nconnect touch_within_layer\nconnect via V1 [M1, M2]\n\
         connect label M1 names M1\nconnect label M2 names M2\n\
         pex V1 thickness 100nm height 1100nm sheet 2ohm dielectric 3.9 area_cap 0aF/um2 fringe_cap 0aF/um\n",
    );
    for (name, _, sheet, area, fringe, height) in METALS {
        writeln!(
            out,
            "pex {name} thickness 100nm height {height}nm sheet {sheet}ohm dielectric 3.9 \
             area_cap {area}aF/um2 fringe_cap {fringe}aF/um"
        )
        .expect("a String");
    }
    out
}

/// A design of straight two-pin nets, each on its own track, 3 µm or more
/// from the next.
fn def(seed: u64) -> (String, BTreeMap<String, usize>) {
    let mut rng = Rng::new(seed);
    let nets = usize::try_from(rng.range(1, 12)).expect("small");
    let (mut pins, mut routes, mut layer_of) = (String::new(), String::new(), BTreeMap::new());
    for n in 0..nets {
        let metal = usize::try_from(rng.range(0, 2)).expect("small");
        let (name, width, ..) = METALS[metal];
        let length = rng.range(20, 400) * 100;
        let start = rng.range(1, 50) * 100;
        // M1 runs along x left of x = 50 µm, M2 along y right of it: no
        // crossing couples them (OpenRCX with LEF RC extracts no coupling).
        let (a, b) = if metal == 0 {
            let track = 10_000 + i64::try_from(n).expect("small") * 5000;
            ((start, track), (start + length, track))
        } else {
            let track = 55_000 + i64::try_from(n).expect("small") * 3000;
            ((track, start), (track, start + length))
        };
        let h = width / 2;
        for (pin, (x, y)) in [("a", a), ("b", b)] {
            writeln!(
                pins,
                "- {pin}{n} + NET n{n} + DIRECTION INPUT + USE SIGNAL + PORT \
                 + LAYER {name} ( -{h} -{h} ) ( {h} {h} ) + PLACED ( {x} {y} ) N ;"
            )
            .expect("a String");
        }
        writeln!(
            routes,
            "- n{n} ( PIN a{n} ) ( PIN b{n} ) + ROUTED {name} ( {} {} ) ( {} {} ) + USE SIGNAL ;",
            a.0, a.1, b.0, b.1
        )
        .expect("a String");
        layer_of.insert(format!("n{n}"), metal);
    }
    let text = format!(
        "VERSION 5.8 ;\nDIVIDERCHAR \"/\" ;\nBUSBITCHARS \"[]\" ;\nDESIGN d{seed} ;\n\
         UNITS DISTANCE MICRONS 1000 ;\nDIEAREA ( 0 0 ) ( 100000 100000 ) ;\n\
         PINS {} ;\n{pins}END PINS\nNETS {nets} ;\n{routes}END NETS\nEND DESIGN\n",
        2 * nets
    );
    (text, layer_of)
}

/// Per net: total capacitance fF and series resistance Ω.
type Totals = BTreeMap<String, (f64, f64)>;

fn ours(dir: &std::path::Path) -> Totals {
    let inputs = Inputs {
        layout: dir.join("top.def"),
        deck: dir.join("top.deck"),
        lef: vec![dir.join("tech.lef")],
        ..Inputs::default()
    };
    let options = RunOptions {
        checks: Checks {
            drc: false,
            erc: false,
            lvs: false,
            pex: true,
        },
        lvs: gpurify_check::lvs::CompareOptions::default(),
        quasistatic_nets: Vec::new(),
    };
    let (loaded, extracted, outputs, _) = run(&inputs, &options).expect("the DEF extracts");
    let network = outputs.parasitics.expect("PEX ran");
    let caps = network.capacitance_per_net();
    let mut out = Totals::new();
    for (net, &cap) in caps.iter().enumerate() {
        let id = gpurify_check::topology::NetId(u32::try_from(net).expect("small"));
        let Some(name) = extracted.ports.name_of(id) else {
            continue;
        };
        let ohms: f64 = (0..network.element_count())
            .filter(|&row| network.node_net[network.from[row].0 as usize] == id)
            .filter_map(|row| match network.value[row] {
                Parasitic::Resistance(r) => Some(r.raw()),
                _ => None,
            })
            .sum();
        out.insert(loaded.strings.resolve(name).to_owned(), (cap, ohms));
    }
    out
}

fn theirs(spef: &str) -> Totals {
    let read = foreign::read_spef(spef).expect("OpenRCX's SPEF reads");
    let caps = read.network.capacitance_per_net();
    read.names
        .iter()
        .enumerate()
        .map(|(k, name)| {
            let ohms: f64 = (0..read.network.element_count())
                .filter(|&row| {
                    read.network.node_net[read.network.from[row].0 as usize].0 as usize == k
                })
                .filter_map(|row| match read.network.value[row] {
                    Parasitic::Resistance(r) => Some(r.raw()),
                    _ => None,
                })
                .sum();
            (name.clone(), (caps[k], ohms))
        })
        .collect()
}

/// Proves catalog PEX-014.
///
/// Oracle: differential against `OpenRCX` with LEF RC (module docs): every
/// net's resistance equal, and its capacitance `2 · W · fringe_cap` above
/// `OpenRCX`'s, on 30 seeded designs.
#[test]
#[ignore = "release tier: needs openroad (nix develop .#oracles)"]
fn openrcx_differential_on_def_wires() {
    let openroad = oracle::tool("openroad");
    let dir = oracle::scratch("openrcx");
    std::fs::write(dir.join("tech.lef"), lef()).expect("writable");
    std::fs::write(dir.join("top.deck"), deck()).expect("writable");
    std::fs::write(
        dir.join("rcx.tcl"),
        "read_lef tech.lef\nread_def top.def\nextract_parasitics -lef_rc -version 2\nwrite_spef out.spef\n",
    )
    .expect("writable");
    let mut disagree = Vec::new();
    let mut compared = 0;
    for seed in 0..DESIGNS {
        let (text, layer_of) = def(seed);
        std::fs::write(dir.join("top.def"), &text).expect("writable");
        let _ = std::fs::remove_file(dir.join("out.spef"));
        oracle::run(
            &openroad,
            &["-no_init", "-no_splash", "-exit", "rcx.tcl"],
            &dir,
            Duration::from_mins(5),
        );
        let spef = std::fs::read_to_string(dir.join("out.spef")).expect("OpenRCX wrote its SPEF");
        let (ours, theirs) = (ours(&dir), theirs(&spef));
        assert_eq!(
            ours.keys().collect::<Vec<_>>(),
            theirs.keys().collect::<Vec<_>>(),
            "design {seed}: the same nets"
        );
        for (net, &(c, r)) in &ours {
            let (_, width, _, _, fringe, _) = METALS[layer_of[net]];
            #[expect(clippy::cast_precision_loss, reason = "a small width")]
            let ends = 2.0 * width as f64 / 1000.0 * fringe / 1000.0;
            let (tc, tr) = theirs[net];
            compared += 1;
            if (r - tr).abs() > R_PRINTED * tr.max(1.0) || (c - ends - tc).abs() > C_PRINTED {
                disagree.push(format!(
                    "design {seed} {net}: R {r} against {tr}; C {c} - {ends} against {tc}"
                ));
            }
        }
    }
    assert!(compared >= DESIGNS, "{compared} nets compared");
    assert!(
        disagree.is_empty(),
        "{} nets disagree (files in {}):\n{}",
        disagree.len(),
        dir.display(),
        disagree.join("\n")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
