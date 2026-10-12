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

/// The integration checks (FLOW-003) find exactly the faults planted in a
/// DEF, one or two per check, and examine what each check covers.
///
/// Oracle: construct-from-answer, each fault planted by its definition
/// (`gpurify::engine::integration`): of three fills one is inside the
/// die, one crosses its edge and one is outside (2); block `b2`
/// overlaps `b1` by 2 × 2 µm and `b3` runs past the die's right edge; core
/// cell `c2` sits 10 nm off its row's 0.2 µm site pitch; pin `q` is 50 nm
/// off met1's 0.2 µm tracks; one special wire starts 3 nm off the 5 nm
/// manufacturing grid. (The design's die is 200 µm a side.)
#[test]
fn every_integration_fault_planted_in_a_def_is_found() {
    let lef = format!(
        "{}SITE core CLASS CORE ; SIZE 0.2 BY 2 ; END core\n\
         MACRO blk CLASS BLOCK ; SIZE 5 BY 5 ; OBS LAYER met2 ; RECT 0 0 5 5 ; END END blk\n\
         MACRO inv CLASS CORE ; SIZE 0.4 BY 2 ; SITE core ; END inv\n\
         MACRO bump CLASS COVER BUMP ; SIZE 5 BY 5 ; END bump\nEND LIBRARY\n",
        LEF.trim_end().trim_end_matches("END LIBRARY")
    )
    .replace(
        "UNITS DATABASE",
        "MANUFACTURINGGRID 0.005 ;\nUNITS DATABASE",
    );
    let mut inputs = inputs(
        "integration",
        &design(
            "ROW r0 core 0 10000 N DO 50 BY 1 STEP 200 0 ;\n\
             TRACKS Y 100 DO 100 STEP 200 LAYER met1 ;\n\
             COMPONENTS 6 ;\n\
             - b1 blk + FIXED ( 1000 1000 ) N ;\n- b2 blk + PLACED ( 4000 4000 ) N ;\n\
             - b3 blk + PLACED ( 196000 1000 ) N ;\n- bp bump + COVER ( 1000 1000 ) N ;\n\
             - c1 inv + PLACED ( 400 10000 ) N ;\n- c2 inv + PLACED ( 1010 10000 ) FN ;\n\
             END COMPONENTS\n\
             PINS 2 ;\n- p + NET p + LAYER met1 ( -100 -100 ) ( 100 100 ) + PLACED ( 50000 10100 ) N ;\n\
             - q + NET q + LAYER met1 ( -100 -100 ) ( 100 100 ) + PLACED ( 50000 10150 ) N ;\n\
             END PINS\n\
             SPECIALNETS 1 ;\n- v + ROUTED met2 400 ( 1003 150000 ) ( 2005 150000 ) ;\nEND SPECIALNETS\n\
             FILLS 3 ;\n- LAYER met2 RECT ( 100000 100000 ) ( 101000 101000 ) ;\n\
             - LAYER met2 RECT ( 199000 100000 ) ( 201000 101000 ) ;\n\
             - LAYER met2 RECT ( 300000 0 ) ( 301000 1000 ) ;\nEND FILLS",
        ),
    );
    inputs.lef = vec![{
        let path = inputs.lef[0].with_file_name("integration.lef");
        std::fs::write(&path, lef).expect("writable");
        path
    }];
    let options = RunOptions {
        checks: Checks {
            drc: true,
            erc: false,
            lvs: false,
            pex: false,
        },
        lvs: gpurify_check::lvs::CompareOptions::default(),
        quasistatic_nets: Vec::new(),
    };
    let (loaded, _, outputs, _) = run(&inputs, &options).expect("the DEF runs");
    let row = |id: &str| {
        let rule = loaded.strings.get(id).expect("interned");
        let run = outputs
            .runs
            .iter()
            .find(|r| r.rule == rule)
            .expect("a run row per check");
        (run.examined, run.violations)
    };
    assert_eq!(row("def.fill_outside_die"), (3, 2));
    assert_eq!(row("def.component_outside_die"), (6, 1));
    // The COVER bump over b1 is no overlap; b1 and b2 are.
    assert_eq!(row("def.component_overlap"), (5, 1));
    assert_eq!(row("def.off_site"), (2, 1));
    assert_eq!(row("def.pin_off_track"), (2, 1));
    assert_eq!(row("def.off_manufacturing_grid").1, 1);
    let overlap = loaded
        .strings
        .get("def.component_overlap")
        .expect("interned");
    let at = outputs
        .violations
        .rule
        .iter()
        .position(|&r| r == overlap)
        .expect("the overlap row");
    assert_eq!(
        outputs.violations.measured[at],
        gpurify_check::report::Measurement::Area(gpurify_geom::DbuArea::new(2000 * 2000))
    );
}

/// Interface DRC (FLOW-004): a top-level wire is checked against a placed
/// block's abstract, its obstruction and its pin, as drawn by the LEF.
///
/// Oracle: construct-from-answer: block `b` (LEF `CLASS BLOCK`) has an
/// met2 obstruction over (0, 0)-(5, 5) µm and a met1 pin at (4.8, 2)-
/// (5, 2.4) µm, placed at (10, 10) µm. A top-level met2 special wire 0.1 µm
/// from the obstruction's right edge breaks a 0.2 µm met2 spacing (one
/// finding at 100 nm); a met1 wire 0.15 µm wide ending on the pin and one
/// 1 µm away from the block are both legal under the 0.3 µm met1 width
/// rule save for their own width (two findings at 150 nm, neither on the
/// pin, which is 0.4 µm tall).
#[test]
fn a_top_level_wire_is_checked_against_a_block_abstract() {
    let lef = format!(
        "{}MACRO blk CLASS BLOCK ; SIZE 5 BY 5 ;\n\
         PIN A DIRECTION INPUT ; PORT LAYER met1 ; RECT 4.8 2 5 2.4 ; END END A\n\
         OBS LAYER met2 ; RECT 0 0 5 5 ; END END blk\nEND LIBRARY\n",
        LEF.trim_end().trim_end_matches("END LIBRARY")
    );
    let deck = DECK.replace("rule m1.w", "rule m2.s space(met2) >= 200nm\nrule m1.w");
    let mut inputs = inputs(
        "interface",
        &design(
            "COMPONENTS 1 ;\n- b blk + FIXED ( 10000 10000 ) N ;\nEND COMPONENTS\n\
             SPECIALNETS 2 ;\n- v + ROUTED met2 400 ( 15300 10000 ) ( 15300 15000 ) ;\n\
             - w + ROUTED met1 150 ( 14800 12100 ) ( 18000 12100 ) NEW met1 150 ( 16000 9000 ) ( 18000 9000 ) ;\n\
             END SPECIALNETS",
        ),
    );
    inputs.lef = vec![{
        let path = inputs.lef[0].with_file_name("interface.lef");
        std::fs::write(&path, lef).expect("writable");
        path
    }];
    std::fs::write(&inputs.deck, deck).expect("writable");
    let options = RunOptions {
        checks: Checks {
            drc: true,
            erc: false,
            lvs: false,
            pex: false,
        },
        lvs: gpurify_check::lvs::CompareOptions::default(),
        quasistatic_nets: Vec::new(),
    };
    let (loaded, _, outputs, _) = run(&inputs, &options).expect("the DEF runs");
    let found = |id: &str| -> Vec<gpurify_check::report::Measurement> {
        let rule = loaded.strings.get(id).expect("a deck rule");
        (0..outputs.violations.len())
            .filter(|&k| outputs.violations.rule[k] == rule)
            .map(|k| outputs.violations.measured[k])
            .collect()
    };
    use gpurify_check::report::Measurement::Length;
    use gpurify_geom::Dbu;
    assert_eq!(found("m2.s"), [Length(Dbu::new_unchecked(100))]);
    assert_eq!(
        found("m1.w"),
        [
            Length(Dbu::new_unchecked(150)),
            Length(Dbu::new_unchecked(150))
        ]
    );
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
