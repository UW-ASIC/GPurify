//! A DEF layout through the whole run: read with its LEF, drawn on the
//! deck's layers, checked and extracted like a GDS.

use gpurify::engine::pipeline::{load, Inputs, LoadError};
use gpurify::engine::run::{run, Checks, RunOptions};
use gpurify_extract::Parasitic;
use std::path::PathBuf;

/// Two metals and a cut, named as the deck names them; met1 wires are
/// 0.2 µm wide by default.
pub const LEF: &str = "\
VERSION 5.8 ;
UNITS DATABASE MICRONS 1000 ; END UNITS
LAYER met1 TYPE ROUTING ; DIRECTION HORIZONTAL ; WIDTH 0.2 ; END met1
LAYER via1 TYPE CUT ; END via1
LAYER met2 TYPE ROUTING ; DIRECTION VERTICAL ; WIDTH 0.4 ; END met2
VIA V12 DEFAULT
  LAYER met1 ; RECT -0.2 -0.2 0.2 0.2 ;
  LAYER via1 ; RECT -0.1 -0.1 0.1 0.1 ;
  LAYER met2 ; RECT -0.2 -0.2 0.2 0.2 ;
END V12
END LIBRARY
";

/// The deck: the LEF's layers, a width rule on met1, and the stack.
pub const DECK: &str = "\
grid 1nm
layer met1 = gds(1, 0)
layer via1 = gds(2, 0)
layer met2 = gds(3, 0)
rule m1.w width(met1) >= 300nm
connect conductors [met1, met2]
connect touch_within_layer
connect via via1 [met1, met2]
connect label met1 names met1
connect label met2 names met2
pex met1 thickness 100nm height 1000nm sheet 0.1ohm dielectric 3.9 area_cap 30aF/um2 fringe_cap 40aF/um
pex via1 thickness 100nm height 1100nm sheet 2ohm dielectric 3.9 area_cap 0aF/um2 fringe_cap 0aF/um
pex met2 thickness 100nm height 1200nm sheet 0.05ohm dielectric 3.9 area_cap 20aF/um2 fringe_cap 30aF/um
";

/// Writes the LEF, the deck and `def` to a scratch directory named `tag`.
pub fn inputs(tag: &str, def: &str) -> Inputs {
    let dir = std::env::temp_dir().join(format!("gpurify-def-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let write = |name: &str, text: &str| -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).expect("writable");
        path
    };
    Inputs {
        layout: write("top.def", def),
        deck: write("top.deck", DECK),
        lef: vec![write("tech.lef", LEF)],
        ..Inputs::default()
    }
}

fn design(nets: &str) -> String {
    format!(
        "VERSION 5.8 ;\nDESIGN top ;\nUNITS DISTANCE MICRONS 1000 ;\n\
         DIEAREA ( 0 0 ) ( 200000 200000 ) ;\n{nets}\nEND DESIGN\n"
    )
}

/// A straight DEF wire extracts to its closed form, and its width is
/// checked like a drawn one.
///
/// Oracle: closed form. Net `a` is one met1 wire from x = 0 to 100 µm,
/// 0.2 µm wide, extended 0.1 µm past each end (LEF/DEF 5.8 p. 268): a
/// 100.2 × 0.2 µm bar. `R = 0.1 Ω/□ · 100.2 / 0.2 = 50.1 Ω` and `C = 30
/// aF/µm² · 20.04 µm² + 40 aF/µm · 200.8 µm = 8.6332 fF` (the deck's
/// `pex` row, Weste & Harris ch. 6). At 0.2 µm it is under the 0.3 µm
/// width rule: one finding.
#[test]
fn a_def_wire_extracts_to_its_closed_form_and_is_checked() {
    let inputs = inputs(
        "wire",
        &design("NETS 1 ;\n- a + ROUTED met1 ( 0 0 ) ( 100000 0 ) ;\nEND NETS"),
    );
    let options = RunOptions {
        checks: Checks {
            drc: true,
            erc: false,
            lvs: false,
            pex: true,
        },
        lvs: gpurify_check::lvs::CompareOptions::default(),
        quasistatic_nets: Vec::new(),
    };
    let (loaded, extracted, outputs, _) = run(&inputs, &options).expect("the DEF runs");
    let a = loaded.strings.get("a").expect("net a is named");
    let net = extracted.ports.net_of(a).expect("a is one net");
    let network = outputs.parasitics.expect("PEX ran");
    let ohms: f64 = (0..network.element_count())
        .filter(|&row| network.node_net[network.from[row].0 as usize] == net)
        .filter_map(|row| match network.value[row] {
            Parasitic::Resistance(r) => Some(r.raw()),
            _ => None,
        })
        .sum();
    assert!((ohms - 50.1).abs() < 1e-9, "{ohms}");
    let femtofarads = network.capacitance_per_net()[net.0 as usize];
    assert!((femtofarads - 8.6332).abs() < 1e-9, "{femtofarads}");
    assert_eq!(outputs.violations.len(), 1);
    assert_eq!(loaded.strings.resolve(outputs.violations.rule[0]), "m1.w");
}

/// A DEF whose layer the deck does not have is refused naming it, and an
/// unreadable LEF names its path.
///
/// Oracle: `load`'s `# Errors` (`LoadError::LefDef`) and
/// `gpurify_ingest::lefdef::to_gds`'s refusal of a layer the deck lacks.
#[test]
fn a_def_on_a_layer_the_deck_lacks_is_refused() {
    let mut inputs = inputs(
        "nolayer",
        &design("SPECIALNETS 1 ;\n- p + ROUTED met3 1000 ( 0 0 ) ( 1000 0 ) ;\nEND SPECIALNETS"),
    );
    let Err(LoadError::LefDef(why)) = load(&inputs) else {
        panic!("met3 is no deck layer")
    };
    assert!(why.message.contains("met3"), "{why}");
    inputs.lef = vec![PathBuf::from("/nonexistent/tech.lef")];
    let Err(LoadError::LefDef(why)) = load(&inputs) else {
        panic!("no such LEF")
    };
    assert!(why.message.contains("/nonexistent/tech.lef"), "{why}");
}
