//! A DEF layout through the whole run: read with its LEF, drawn on the
//! deck's layers, checked and extracted like a GDS.

use gpurify::engine::pipeline::{load, Inputs, LoadError};
use gpurify::engine::run::{run, Checks, RunOptions, StageStatus};
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
    let dir = gpurify_testgen::oracle::scratch(&format!("def-{tag}"));
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
    let length =
        |nm| gpurify_check::report::Measurement::Length(gpurify_geom::Dbu::new_unchecked(nm));
    assert_eq!(found("m2.s"), [length(100)]);
    assert_eq!(found("m1.w"), [length(150), length(150)]);
}

/// Metal fill between two plates, each treatment of `pex_fill` (PEX-012).
///
/// Oracle: closed form. Net `a` on met1 (top at 1.1 µm), a fill piece on
/// `fillm` (1.2 to 1.3 µm) and net `b` on met2 (from 1.4 µm), all 10 × 10
/// µm and stacked, in k = 3.9: each 0.1 µm gap is a parallel plate
/// `C₁ = ε₀k·100 µm²/0.1 µm`, and a–b directly `C₁/3` over 0.3 µm (the
/// closed forms do not shield). Floating fill with no capacitance of its
/// own to ground puts a–fill and fill–b in series: a–b is `C₁/3 + C₁/2`;
/// grounded, a–b is `C₁/3` and each plate gains `C₁` to ground; ignored,
/// a–b is `C₁/3`. Every treatment leaves only nets a and b.
#[test]
fn fill_between_two_plates_is_in_series_grounded_or_gone() {
    let lef = format!(
        "{}LAYER fillm TYPE ROUTING ; DIRECTION HORIZONTAL ; WIDTH 0.2 ; END fillm\nEND LIBRARY\n",
        LEF.trim_end().trim_end_matches("END LIBRARY")
    );
    let deck = |treatment: &str| {
        format!(
            "grid 1nm\nlayer met1 = gds(1, 0)\nlayer via1 = gds(2, 0)\nlayer met2 = gds(3, 0)\n\
             layer fillm = gds(4, 0)\n\
             connect conductors [met1, fillm, met2]\nconnect touch_within_layer\n\
             connect via via1 [met1, met2]\n\
             connect label met1 names met1\nconnect label met2 names met2\n\
             pex met1 thickness 100nm height 1000nm sheet 0.1ohm dielectric 3.9 area_cap 0aF/um2 fringe_cap 0aF/um\n\
             pex fillm thickness 100nm height 1200nm sheet 0.1ohm dielectric 3.9 area_cap 0aF/um2 fringe_cap 0aF/um\n\
             pex met2 thickness 100nm height 1400nm sheet 0.1ohm dielectric 3.9 area_cap 0aF/um2 fringe_cap 0aF/um\n\
             pex via1 thickness 100nm height 1100nm sheet 2ohm dielectric 3.9 area_cap 0aF/um2 fringe_cap 0aF/um\n\
             pex_fill fillm {treatment}\n"
        )
    };
    let c1 = 8.854_187_812_8 * 3.9 * 100.0 / 0.1 / 1000.0;
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
    for (treatment, coupling, ground) in [
        ("floating", c1 / 3.0 + c1 / 2.0, 0.0),
        ("grounded", c1 / 3.0, c1),
        ("ignored", c1 / 3.0, 0.0),
    ] {
        let mut inputs = inputs(
            &format!("fill-{treatment}"),
            &design(
                "SPECIALNETS 2 ;\n- a + RECT met1 ( 0 0 ) ( 10000 10000 ) ;\n\
                 - b + RECT met2 ( 0 0 ) ( 10000 10000 ) ;\nEND SPECIALNETS\n\
                 FILLS 1 ;\n- LAYER fillm RECT ( 0 0 ) ( 10000 10000 ) ;\nEND FILLS",
            ),
        );
        inputs.lef = vec![{
            let path = inputs.lef[0].with_file_name("fill.lef");
            std::fs::write(&path, &lef).expect("writable");
            path
        }];
        std::fs::write(&inputs.deck, deck(treatment)).expect("writable");
        let (loaded, extracted, outputs, _) = run(&inputs, &options).expect("the DEF runs");
        let network = outputs.parasitics.expect("PEX ran");
        let net = |name: &str| {
            extracted
                .ports
                .net_of(loaded.strings.get(name).expect("named"))
                .expect("one net")
        };
        let (a, b) = (net("a"), net("b"));
        let mut nets: Vec<_> = network.node_net.clone();
        nets.dedup();
        assert_eq!(
            nets,
            [a.min(b), a.max(b)],
            "{treatment}: only a and b remain"
        );
        let (mut cc, mut ga) = (0.0, 0.0);
        for row in 0..network.element_count() {
            match network.value[row] {
                Parasitic::CouplingCap(q) => cc += q.raw(),
                Parasitic::GroundCap(q) if network.node_net[network.from[row].0 as usize] == a => {
                    ga += q.raw();
                }
                _ => {}
            }
        }
        assert!(
            (cc - coupling).abs() < 1e-9 * coupling,
            "{treatment}: {cc} against {coupling}"
        );
        assert!(
            (ga - ground).abs() < 1e-9 * c1,
            "{treatment}: {ga} against {ground}"
        );
    }
}

/// The point-to-point and net-to-net reports (PEX-016) on two parallel
/// met1 wires, as the deck's `report` lines state them.
///
/// Oracle: closed forms. Between x = 10 and x = 60 µm along a 0.2 µm wire
/// of 0.1 Ω/□ the resistance is `0.1 · 50 / 0.2 = 25 Ω` (and 0 from a
/// point to itself); the wires, 100.2 µm long and 0.8 µm apart in k = 3.9
/// with met1 0.1 µm thick, couple by `ε₀ k t L / S = 8.854… · 3.9 · 0.1 ·
/// 100.2 / 0.8` aF (Weste & Harris ch. 6). A point off the net, and a net
/// the layout lacks, are refused.
#[test]
fn point_to_point_resistance_and_net_coupling_are_reported() {
    let inputs = inputs(
        "p2p",
        &design(
            "NETS 2 ;\n- a + ROUTED met1 ( 0 0 ) ( 100000 0 ) ;\n\
             - b + ROUTED met1 ( 0 1000 ) ( 100000 1000 ) ;\nEND NETS",
        ),
    );
    let deck = format!(
        "{DECK}report p2p \"a\" at [(10um, 0um), (60um, 50nm), (10um, 0um)]\n\
         report p2p \"a\" at [(10um, 0.5um), (20um, 0um)]\n\
         report coupling \"a\" \"b\"\nreport coupling \"a\" \"zz\"\n"
    );
    std::fs::write(&inputs.deck, deck).expect("writable");
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
    let (loaded, extracted, outputs, _) = run(&inputs, &options).expect("the DEF runs");
    let reports = &loaded.deck.reports;
    let (net, points) = &reports.p2p[0];
    let r = gpurify::engine::p2p::resistance(&loaded, &extracted, net, points)
        .expect("the points are on a");
    assert_eq!(r.len(), 3);
    assert!((r[0].2 - 25.0).abs() < 1e-9, "{r:?}");
    assert_eq!((r[1].0, r[1].1, r[1].2), (0, 2, 0.0));
    let network = outputs.parasitics.expect("PEX ran");
    let (a, b) = &reports.coupling[0];
    let c =
        gpurify::engine::p2p::coupling(&loaded, &extracted, &network, a, b).expect("both are nets");
    let want = 8.854_187_812_8 * 3.9 * 0.1 * 100.2 / 0.8 / 1000.0;
    assert!((c - want).abs() < 1e-9, "{c} against {want}");
    let (net, points) = &reports.p2p[1];
    assert!(
        gpurify::engine::p2p::resistance(&loaded, &extracted, net, points)
            .unwrap_err()
            .contains("no conducting shape")
    );
    let (a, b) = &reports.coupling[1];
    assert!(gpurify::engine::p2p::coupling(&loaded, &extracted, &network, a, b).is_err());
}

/// Two through-silicon vias on one net add their liners' capacitance
/// (PEX-015).
///
/// Oracle: closed form (Katti et al., IEEE TED 57(1), 2010, eq. 2): a 5 ×
/// 5 µm cut is a cylinder of radius `5/√π` µm; 50 µm long in a 0.2 µm
/// liner of k = 3.9 it is `2π ε₀ k L / ln((r + t) / r)` to ground, and two
/// of them twice that. The plates carry no capacitance of their own
/// (`area_cap` and `fringe_cap` 0) and one net couples to nothing, so the
/// net's capacitance is the liners' alone.
#[test]
fn a_through_silicon_via_adds_its_liner_capacitance() {
    let lef = "VERSION 5.8 ;\nUNITS DATABASE MICRONS 1000 ; END UNITS\n\
               LAYER met1 TYPE ROUTING ; WIDTH 0.2 ; END met1\n\
               LAYER tsv TYPE CUT ; END tsv\n\
               LAYER bm TYPE ROUTING ; WIDTH 1 ; END bm\n\
               VIA T1 LAYER met1 ; RECT -3 -3 3 3 ; LAYER tsv ; RECT -2.5 -2.5 2.5 2.5 ;\n\
               LAYER bm ; RECT -3 -3 3 3 ; END T1\nEND LIBRARY\n";
    let deck = "grid 1nm\nlayer met1 = gds(1, 0)\nlayer tsv = gds(2, 0)\nlayer bm = gds(3, 0)\n\
                connect conductors [met1, bm]\nconnect touch_within_layer\n\
                connect via tsv [met1, bm]\n\
                connect label met1 names met1\nconnect label bm names bm\n\
                pex met1 thickness 100nm height 1000nm sheet 0.1ohm dielectric 3.9 area_cap 0aF/um2 fringe_cap 0aF/um\n\
                pex tsv thickness 100nm height 1100nm sheet 0.05ohm dielectric 3.9 area_cap 0aF/um2 fringe_cap 0aF/um\n\
                pex bm thickness 100nm height 1200nm sheet 0.1ohm dielectric 3.9 area_cap 0aF/um2 fringe_cap 0aF/um\n\
                pex_tsv tsv length 50um liner 200nm liner_k 3.9\n";
    let mut inputs = inputs(
        "tsv",
        &design(
            "SPECIALNETS 1 ;\n- t + RECT met1 ( 7000 7000 ) ( 33000 13000 ) \
             + VIA T1 ( 10000 10000 ) ( 30000 10000 ) ;\nEND SPECIALNETS",
        ),
    );
    inputs.lef = vec![{
        let path = inputs.lef[0].with_file_name("tsv.lef");
        std::fs::write(&path, lef).expect("writable");
        path
    }];
    std::fs::write(&inputs.deck, deck).expect("writable");
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
    let (loaded, extracted, outputs, _) = run(&inputs, &options).expect("the DEF runs");
    let net = extracted
        .ports
        .net_of(loaded.strings.get("t").expect("named"))
        .expect("one net");
    let total = outputs.parasitics.expect("PEX ran").capacitance_per_net()[net.0 as usize];
    let r = 5.0 / std::f64::consts::PI.sqrt();
    let one = 2.0 * std::f64::consts::PI * 8.854_187_812_8e-3 * 3.9 * 50.0 / ((r + 0.2) / r).ln();
    assert!(
        (total - 2.0 * one).abs() < 1e-9 * one,
        "{total} against {}",
        2.0 * one
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

/// The substrate network of a DEF whose taps are its only shapes, through
/// the run and both writers (PEX-013).
fn substrate_run(tag: &str, nets: &str, backside: &str) -> (String, String, Vec<(bool, f64)>) {
    let lef = "VERSION 5.8 ;\nUNITS DATABASE MICRONS 1000 ; END UNITS\n\
               LAYER tap TYPE ROUTING ; WIDTH 1 ; END tap\nEND LIBRARY\n";
    let deck = format!(
        "grid 1nm\nlayer tap = gds(1, 0)\nconnect conductors [tap]\n\
         connect touch_within_layer\nconnect label tap names tap\n\
         pex tap thickness 100nm height 0nm sheet 1ohm dielectric 3.9 area_cap 0aF/um2 fringe_cap 0aF/um\n\
         pex_substrate ports [tap] backside {backside} profile [(2um, 1), (5um, 10)]\n"
    );
    let mut inputs = inputs(tag, &design(nets));
    inputs.lef = vec![{
        let path = inputs.lef[0].with_file_name("tap.lef");
        std::fs::write(&path, lef).expect("writable");
        path
    }];
    std::fs::write(&inputs.deck, deck).expect("writable");
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
    let (loaded, extracted, outputs, _) = run(&inputs, &options).expect("the DEF runs");
    let network = outputs.parasitics.expect("PEX ran");
    let header = gpurify::export::Header {
        tool_version: "test",
        deck_path: "top.deck".into(),
        layout_path: "top.def".into(),
        timestamp: None,
    };
    let (mut spef, mut dspf) = (String::new(), String::new());
    gpurify::export::parasitic::write_spef(
        &network,
        &extracted.ports,
        &loaded.strings,
        &header,
        &mut spef,
    )
    .expect("SPEF");
    gpurify::export::parasitic::write_dspf(
        &network,
        &extracted.ports,
        &loaded.strings,
        &header,
        &mut dspf,
    )
    .expect("DSPF");
    let substrate = (0..network.element_count())
        .filter_map(|row| match network.value[row] {
            Parasitic::SubstrateResistance(r) => Some((network.to[row].is_none(), r.raw())),
            _ => None,
        })
        .collect();
    (spef, dspf, substrate)
}

/// A tap covering the whole die over two layers and a grounded backside is
/// one resistor to ground, the layers in series, in both writers (PEX-013).
///
/// Oracle: closed form (Ohm's law): the die is the tap's 10 × 10 µm, so the
/// current runs straight down through 2 µm of 1 Ω·cm and 5 µm of 10 Ω·cm,
/// `(2 · 10⁴ + 5 · 10⁵) Ω·µm / 100 µm² = 5200 Ω`; SPEF carries it as a
/// comment and DSPF as an `R` card to node 0 (the writers' docs).
#[test]
fn a_tap_over_a_layered_substrate_is_its_series_resistance_in_spef_and_dspf() {
    let (spef, dspf, substrate) = substrate_run(
        "substrate-ohm",
        "SPECIALNETS 1 ;\n- vss + RECT tap ( 0 0 ) ( 10000 10000 ) ;\nEND SPECIALNETS",
        "grounded",
    );
    let [(true, ohms)] = substrate[..] else {
        panic!("one resistor to ground: {substrate:?}")
    };
    assert!((ohms - 5200.0).abs() < 1e-9 * 5200.0, "{ohms}");
    assert!(spef.contains("// substrate vss:0 0 5200"), "{spef}");
    assert!(dspf.contains("R1 vss:0 0 5200"), "{dspf}");
}

/// Two taps on a floating backside: one resistor between their nets and
/// none to ground, written as a comment and an `R` card between the nets.
///
/// Oracle: the model's definition (`gpurify_extract::substrate`): with no
/// backside contact every current leaves through another port, so the
/// network is the one conductance between the two ports.
#[test]
fn two_taps_on_a_floating_backside_are_one_resistor_between_their_nets() {
    let (spef, dspf, substrate) = substrate_run(
        "substrate-float",
        "SPECIALNETS 2 ;\n- a + RECT tap ( 0 0 ) ( 2000 2000 ) ;\n\
         - b + RECT tap ( 8000 0 ) ( 10000 2000 ) ;\nEND SPECIALNETS",
        "floating",
    );
    let [(false, ohms)] = substrate[..] else {
        panic!("one resistor between the taps: {substrate:?}")
    };
    assert!(ohms > 0.0);
    assert!(spef.contains("// substrate a:0 b:0 "), "{spef}");
    assert!(
        dspf.lines()
            .any(|card| card.starts_with('R') && card.contains(" a:0 b:0 ")),
        "{dspf}"
    );
}

/// LEF/DEF 5.8 Appendix C's Figure C-20 at the top level, its two gates
/// behind macro pins: cell A's pin `A` (G1) and cell B's pin `B` (G2 with
/// its diode D1), each as the manual's Example 1 writes them, and
/// `extra` added to pin `A`.
fn c20_lef(extra: &str) -> String {
    format!(
        "VERSION 5.8 ;\nUNITS DATABASE MICRONS 1000 ; END UNITS\n\
         LAYER met1 TYPE ROUTING ; WIDTH 0.2 ; END met1\n\
         LAYER via1 TYPE CUT ; END via1\n\
         LAYER met2 TYPE ROUTING ; WIDTH 0.2 ; END met2\n\
         LAYER via2 TYPE CUT ; END via2\n\
         LAYER met3 TYPE ROUTING ; WIDTH 0.2 ; END met3\n\
         MACRO CELLA\n  CLASS CORE ;\n  ORIGIN 0 0 ;\n  SIZE 1 BY 1 ;\n  PIN A\n    DIRECTION INPUT ;\n\
         \x20   ANTENNAGATEAREA 1.0 LAYER met1 ;\n    ANTENNAMAXAREACAR 1.0 LAYER met1 ;\n{extra}\
         \x20   PORT\n      LAYER met1 ;\n        RECT 0 0 0.2 0.2 ;\n    END\n  END A\nEND CELLA\n\
         MACRO CELLB\n  CLASS CORE ;\n  ORIGIN 0 0 ;\n  SIZE 1 BY 1 ;\n  PIN B\n    DIRECTION INPUT ;\n\
         \x20   ANTENNAGATEAREA 2.0 LAYER met1 ;\n    ANTENNADIFFAREA 0.5 LAYER met1 ;\n\
         \x20   ANTENNAMAXAREACAR 1.0 LAYER met1 ;\n\
         \x20   PORT\n      LAYER met1 ;\n        RECT 0 0 0.2 0.2 ;\n    END\n  END B\nEND CELLB\n\
         END LIBRARY\n"
    )
}

/// Figure C-20's metal and cuts (`erc.rs`'s `lef_c20`, 4 µm to the right):
/// M1,1 = 1, M1,2 = 2, M1,3 = 3, M2,1 = 4, M2,2 = 5, M3,1 = 6, M3,2 = 9
/// µm², every cut 0.1 µm²; pin A inside M1,2 and pin B inside M1,3, so
/// they add no area.
const C20_DEF: &str = "VERSION 5.8 ;\nDESIGN top ;\nUNITS DISTANCE MICRONS 1000 ;\n\
    DIEAREA ( 0 0 ) ( 20000 20000 ) ;\n\
    COMPONENTS 2 ;\n- a CELLA + PLACED ( 5500 1400 ) N ;\n- b CELLB + PLACED ( 10000 1500 ) N ;\n\
    END COMPONENTS\n\
    SPECIALNETS 1 ;\n- n ( a A ) ( b B )\n\
    + RECT met1 ( 4000 1250 ) ( 8000 1750 ) + RECT met1 ( 1000 1250 ) ( 2000 2250 )\n\
    + RECT met1 ( 9000 1250 ) ( 12000 2250 )\n\
    + RECT via1 ( 4750 1400 ) ( 5150 1650 ) + RECT via1 ( 7000 1400 ) ( 7400 1650 )\n\
    + RECT via1 ( 1300 1600 ) ( 1700 1850 ) + RECT via1 ( 9200 1900 ) ( 9600 2150 )\n\
    + RECT met2 ( 1200 1400 ) ( 5200 2400 ) + RECT met2 ( 6900 1300 ) ( 11900 2300 )\n\
    + RECT via2 ( 2000 1900 ) ( 2400 2150 ) + RECT via2 ( 8000 1900 ) ( 8400 2150 )\n\
    + RECT met3 ( 1000 1400 ) ( 4000 3400 ) + RECT met3 ( 7000 1300 ) ( 10000 4300 ) ;\n\
    END SPECIALNETS\nEND DESIGN\n";

/// One `antenna_electrical` row over `collectors`, flagging every ratio
/// above a millionth.
fn electrical(id: &str, collectors: &str, diode: &str, minus: f64) -> String {
    format!(
        "rule {id} antenna_electrical(gate, {collectors}; max_ratio: 1e-6, sidewall: none, \
         cut_factor: 10, diode: {diode}, diode_credit: 0, diode_bonus: 0, \
         area_minus_diode: {minus}, gate_plus_diode: 0, diode_reduce: none, \
         diode_max_ratio: none, exempt: none)\n"
    )
}

/// One antenna finding: its rule, its ratio, and where it is.
type Finding = (String, f64, (i64, i64));

/// ERC on [`C20_DEF`] with the [`c20_lef`] of `extra`: its findings, and
/// the stage's status.
fn c20_findings(tag: &str, extra: &str) -> (Vec<Finding>, StageStatus) {
    let all = "met1, via1, met2, via2, met3";
    let deck = format!(
        "grid 1nm\nlayer met1 = gds(1, 0)\nlayer via1 = gds(2, 0)\nlayer met2 = gds(3, 0)\n\
         layer via2 = gds(4, 0)\nlayer met3 = gds(5, 0)\nlayer gate = gds(6, 0)\n\
         layer dio = gds(7, 0)\n\
         connect conductors [met1, met2, met3]\nconnect touch_within_layer\n\
         connect via via1 [met1, met2]\nconnect via via2 [met2, met3]\n\
         connect label met1 names met1\nconnect label met2 names met2\n\
         connect label met3 names met3\n\
         {}{}{}\
         rule par1 antenna(gate, met1; max_ratio: 1e-6, sidewall: none, diode: none, diode_area: none, diode_min: none)\n\
         rule par2 antenna(gate, met2; max_ratio: 1e-6, sidewall: none, diode: none, diode_area: none, diode_min: none)\n",
        electrical("ex1", all, "none", 0.0),
        electrical("ex2", all, "dio", 100.0),
        electrical("ex2v1", "met1, via1", "dio", 100.0),
    );
    let mut inputs = inputs(tag, C20_DEF);
    std::fs::write(&inputs.deck, deck).expect("writable");
    inputs.lef = vec![{
        let path = inputs.lef[0].with_file_name("c20.lef");
        std::fs::write(&path, c20_lef(extra)).expect("writable");
        path
    }];
    let options = RunOptions {
        checks: Checks {
            drc: false,
            erc: true,
            lvs: false,
            pex: false,
        },
        lvs: gpurify_check::lvs::CompareOptions::default(),
        quasistatic_nets: Vec::new(),
    };
    let (loaded, _, outputs, summary) = run(&inputs, &options).expect("the DEF runs");
    let v = &outputs.violations;
    let found = (0..v.len())
        .map(|k| {
            let gpurify_check::report::Measurement::Ratio(r) = v.measured[k] else {
                panic!("an antenna ratio")
            };
            (
                loaded.strings.resolve(v.rule[k]).to_owned(),
                r,
                (v.at[k].x.raw(), v.at[k].y.raw()),
            )
        })
        .collect();
    (found, summary.erc)
}

/// The ratio `rule` reports at `at`, if any.
fn ratio_at(found: &[Finding], rule: &str, at: (i64, i64)) -> Option<f64> {
    found
        .iter()
        .find(|(r, _, p)| r == rule && *p == at)
        .map(|f| f.1)
}

/// Pin A (G1) and pin B (G2) report at their pins' centres.
const PIN_A: (i64, i64) = (5600, 1500);
const PIN_B: (i64, i64) = (10100, 1600);

/// LEF/DEF 5.8 Appendix C's Example 1 and Example 2, the gates behind
/// macro pins (ERC-A14): a top-level net's ratio counts each pin's
/// `ANTENNAGATEAREA`, `ANTENNADIFFAREA` and `ANTENNAMAXAREACAR`.
///
/// Oracle: the manual's steps, hand-derived (Example 1, cut factor 10):
/// G1's CAR is PIN A's CAR 1.0 plus PAR(M1) 2/1, PAR(V1) 10 · 0.2 / 1,
/// PAR(M2) 9/3, PAR(V2) 10 · 0.2/3 and PAR(M3) 15/3: 13⅔ (the manual's
/// steps 3-15; its "12.34" in step 15 is a slip for 5 + 8.67, its "13.67"
/// in step 16). G2's is PIN B's 1.0 plus 3/2, 10 · 0.1/2, 3, ⅔ and 5:
/// 11⅔. A single-layer row is a PAR, no pin CAR in it: 2.0 and 1.5 at
/// met1, 3.0 at met2. Example 2 subtracts 100 × diff: G1's CAR is still
/// 5.0 through via1, every later sum truncates to 0, and G2, whose pin
/// carries D1's 0.5 µm² from met1 up, is 0 from met1 on.
#[test]
fn macro_pin_antenna_data_follows_lef_appendix_c_examples_1_and_2() {
    let (found, erc) = c20_findings("a14-c20", "");
    assert_eq!(erc, StageStatus::Ran);
    let close = |got: Option<f64>, want: f64| got.is_some_and(|g| (g - want).abs() < 1e-9 * want);
    assert!(
        close(ratio_at(&found, "ex1", PIN_A), 13.0 + 2.0 / 3.0),
        "{found:?}"
    );
    assert!(
        close(ratio_at(&found, "ex1", PIN_B), 11.0 + 2.0 / 3.0),
        "{found:?}"
    );
    assert!(close(ratio_at(&found, "par1", PIN_A), 2.0), "{found:?}");
    assert!(close(ratio_at(&found, "par1", PIN_B), 1.5), "{found:?}");
    assert!(close(ratio_at(&found, "par2", PIN_A), 3.0), "{found:?}");
    assert!(close(ratio_at(&found, "ex2v1", PIN_A), 5.0), "{found:?}");
    // Truncated to 0: nothing above the limit, and G1 and G2 once each.
    assert!(found.iter().all(|f| f.0 != "ex2"), "{found:?}");
    assert_eq!(found.iter().filter(|f| f.0 == "ex2v1").count(), 1);
    assert_eq!(found.len(), 6, "{found:?}");
}

/// A pin's partial metal area adds to its layer's collecting area, and a
/// gate area stated per layer is the one joined through that layer.
///
/// Oracle: LEF/DEF 5.8 p. 142 ("Metal area is calculated by adding the
/// pin's geometric metal area and the ANTENNAPARTIALMETALAREA value") and
/// p. 140 (`ANTENNAGATEAREA value LAYER`: the gate area connected to the
/// pin on that layer), hand-derived: 1.0 µm² of partial met1 on pin A
/// makes its met1 PAR (2 + 1)/1 = 3.0; a gate area of 3.0 on met2 makes
/// the met2 PAR 9/(3 + 2) = 1.8 for both gates, met1's still 2.0.
#[test]
fn a_pins_partial_area_and_per_layer_gate_area_count() {
    let (found, _) = c20_findings(
        "a14-partial",
        "    ANTENNAPARTIALMETALAREA 1.0 LAYER met1 ;\n",
    );
    assert!(
        ratio_at(&found, "par1", PIN_A).is_some_and(|r| (r - 3.0).abs() < 1e-9),
        "{found:?}"
    );
    let (found, _) = c20_findings("a14-layered", "    ANTENNAGATEAREA 3.0 LAYER met2 ;\n");
    assert!(
        ratio_at(&found, "par1", PIN_A).is_some_and(|r| (r - 2.0).abs() < 1e-9),
        "{found:?}"
    );
    assert!(
        ratio_at(&found, "par2", PIN_A).is_some_and(|r| (r - 1.8).abs() < 1e-9),
        "{found:?}"
    );
}

/// A pin's antenna statement on a layer the deck lacks refuses ERC, naming
/// the macro, the pin and the layer, rather than dropping the value.
///
/// Oracle: `run_erc`'s refusal (a value no row can place is unknown, not
/// zero).
#[test]
fn a_pin_antenna_value_on_a_layer_the_deck_lacks_refuses_erc() {
    let (found, erc) = c20_findings("a14-nolayer", "    ANTENNAMAXCUTCAR 1.0 LAYER cont ;\n");
    assert!(found.is_empty());
    let StageStatus::Refused(why) = erc else {
        panic!("{erc:?}")
    };
    assert!(
        why.contains("CELLA") && why.contains("pin A") && why.contains("cont"),
        "{why}"
    );
}
