//! Seeded LEF/DEF designs for the LEF/DEF differentials: a three-metal
//! technology with a fixed and a generated via, one macro, and a design that
//! places it in every orientation, routes regular and special nets through
//! both vias with explicit and default extensions, places pins and fill.
//!
//! Everything is written from the seed alone, in DEF units of 1 nm, every
//! coordinate on a 10 nm lattice and every width even, so each tool reads
//! the same exact geometry.

use gpurify_testgen::Rng;
use std::fmt::Write as _;

/// The routing layers bottom-up with their default width in nm, and the
/// cut above each but the last.
pub const METALS: [(&str, i64); 3] = [("M1", 100), ("M2", 140), ("M3", 200)];
/// The cut layers.
pub const CUTS: [&str; 2] = ["V1", "V2"];

/// The technology and the macro, in micrometres.
pub fn lef() -> String {
    let mut out = String::from(
        "VERSION 5.8 ;\nBUSBITCHARS \"[]\" ;\nDIVIDERCHAR \"/\" ;\n\
         UNITS\n  DATABASE MICRONS 1000 ;\nEND UNITS\nMANUFACTURINGGRID 0.005 ;\n\
         SITE core\n  CLASS CORE ;\n  SIZE 0.2 BY 1.0 ;\nEND core\n",
    );
    let um = |nm: i64| format!("{}.{:03}", nm / 1000, nm % 1000);
    for (k, &(name, width)) in METALS.iter().enumerate() {
        let dir = if k % 2 == 0 { "HORIZONTAL" } else { "VERTICAL" };
        writeln!(
            out,
            "LAYER {name}\n  TYPE ROUTING ;\n  DIRECTION {dir} ;\n  PITCH {} ;\n  WIDTH {} ;\nEND {name}",
            um(4 * width),
            um(width)
        )
        .expect("a String");
        if let Some(cut) = CUTS.get(k) {
            writeln!(out, "LAYER {cut}\n  TYPE CUT ;\nEND {cut}").expect("a String");
        }
    }
    out.push_str(
        "VIA VIA12 DEFAULT\n  LAYER M1 ;\n    RECT -0.07 -0.05 0.07 0.05 ;\n  \
         LAYER V1 ;\n    RECT -0.05 -0.05 0.05 0.05 ;\n  LAYER M2 ;\n    RECT -0.07 -0.09 0.07 0.09 ;\nEND VIA12\n\
         VIA VIA23 DEFAULT\n  VIARULE GEN23 ;\n  CUTSIZE 0.1 0.1 ;\n  LAYERS M2 V2 M3 ;\n  \
         CUTSPACING 0.1 0.1 ;\n  ENCLOSURE 0.02 0.04 0.04 0.02 ;\n  ROWCOL 1 2 ;\nEND VIA23\n\
         MACRO cell\n  CLASS CORE ;\n  ORIGIN 0.1 0.2 ;\n  SIZE 2 BY 1 ;\n  SYMMETRY X Y ;\n  SITE core ;\n\
         \x20 PIN A\n    DIRECTION INPUT ;\n    USE SIGNAL ;\n    PORT\n      LAYER M1 ;\n        \
         RECT -0.05 -0.15 0.25 0.05 ;\n    END\n  END A\n\
         \x20 PIN Y\n    DIRECTION OUTPUT ;\n    PORT\n      LAYER M1 ;\n        \
         POLYGON 1.2 0.4 1.6 0.4 1.6 0.7 1.4 0.7 1.4 0.5 1.2 0.5 ;\n      LAYER M2 ;\n        \
         RECT 1.4 0.4 1.6 0.6 ;\n    END\n  END Y\n\
         \x20 OBS\n    LAYER M2 ;\n      RECT 0.3 0.0 0.9 0.6 ;\n    LAYER M1 ;\n      RECT 0.5 0.2 0.7 0.3 ;\n  END\n\
         END cell\nEND LIBRARY\n",
    );
    out
}

const ORIENTS: [&str; 8] = ["N", "S", "W", "E", "FN", "FS", "FW", "FE"];

/// One routed path: from a lattice point, `steps` orthogonal moves, a via
/// now and then. Returns the routing statement after `ROUTED`.
fn path(rng: &mut Rng, special: Option<i64>, origin: (i64, i64)) -> String {
    let mut level = usize::try_from(rng.range(0, 3)).expect("small");
    let width = |level: usize| {
        special.map(|w| format!(" {}", w + 20 * i64::try_from(level).expect("small")))
    };
    let mut out = format!("{}{}", METALS[level].0, width(level).unwrap_or_default());
    let (mut x, mut y) = origin;
    write!(out, " ( {x} {y} )").expect("a String");
    for _ in 0..rng.range(1, 6) {
        match rng.range(0, 6) {
            0 if level < 2 => {
                let via = if level == 0 { "VIA12" } else { "VIA23" };
                level += 1;
                write!(out, " {via}").expect("a String");
                if rng.range(0, 3) == 0 {
                    write!(out, " ( * * {} )", rng.range(0, 6) * 10).expect("a String");
                }
            }
            1 if level > 0 => {
                let via = if level == 1 { "VIA12" } else { "VIA23" };
                level -= 1;
                write!(out, " {via}").expect("a String");
            }
            _ => {
                let step = rng.range(1, 30) * 10 * if rng.range(0, 2) == 0 { 1 } else { -1 };
                let ext = if rng.range(0, 4) == 0 {
                    format!(" {}", rng.range(0, 8) * 10)
                } else {
                    String::new()
                };
                if rng.range(0, 2) == 0 {
                    x += step;
                    write!(out, " ( {x} *{ext} )").expect("a String");
                } else {
                    y += step;
                    write!(out, " ( * {y}{ext} )").expect("a String");
                }
            }
        }
    }
    out
}

/// The seed's design, in a die 40 µm a side.
pub fn def(seed: u64) -> String {
    let mut rng = Rng::new(seed);
    let at = |rng: &mut Rng| (rng.range(10, 390) * 100, rng.range(10, 390) * 100);
    let mut out = format!(
        "VERSION 5.8 ;\nDIVIDERCHAR \"/\" ;\nBUSBITCHARS \"[]\" ;\nDESIGN d{seed} ;\n\
         UNITS DISTANCE MICRONS 1000 ;\nDIEAREA ( 0 0 ) ( 40000 40000 ) ;\n\
         ROW r0 core 0 0 N DO 200 BY 1 STEP 200 0 ;\n\
         TRACKS Y 50 DO 100 STEP 400 LAYER M1 ;\nTRACKS X 70 DO 70 STEP 560 LAYER M2 ;\n"
    );
    // A generated via with a cut pattern, and a fixed one.
    let (rows, cols) = (rng.range(1, 4), rng.range(2, 5));
    let pattern = if rng.range(0, 2) == 0 {
        format!(" + PATTERN {rows:X}_{:X}", rng.range(1, 16))
    } else {
        String::new()
    };
    write!(
        out,
        "VIAS 2 ;\n- gvia + VIARULE GEN12 + CUTSIZE 100 100 + LAYERS M1 V1 M2 \
         + CUTSPACING 100 120 + ENCLOSURE 40 20 20 40 + ROWCOL {rows} {cols}{pattern} \
         + ORIGIN {} {} + OFFSET 0 0 {} {} ;\n\
         - fvia + RECT M2 ( -100 -100 ) ( 100 100 ) + RECT V2 ( -50 -50 ) ( 50 50 ) \
         + RECT M3 ( -150 -100 ) ( 150 100 ) ;\nEND VIAS\n",
        rng.range(-2, 3) * 10,
        rng.range(-2, 3) * 10,
        rng.range(-2, 3) * 10,
        rng.range(-2, 3) * 10,
    )
    .expect("a String");

    let components = usize::try_from(rng.range(1, 9)).expect("small");
    writeln!(out, "COMPONENTS {components} ;").expect("a String");
    for c in 0..components {
        let (x, y) = at(&mut rng);
        let orient = ORIENTS[usize::try_from(rng.range(0, 8)).expect("small")];
        let status = ["PLACED", "FIXED", "COVER"][usize::try_from(rng.range(0, 3)).expect("small")];
        writeln!(
            out,
            "- u{c} cell + SOURCE NETLIST + {status} ( {x} {y} ) {orient} ;"
        )
        .expect("a String");
    }
    out.push_str("END COMPONENTS\n");

    let pins = usize::try_from(rng.range(1, 4)).expect("small");
    writeln!(out, "PINS {pins} ;").expect("a String");
    for p in 0..pins {
        let (x, y) = at(&mut rng);
        let orient = ORIENTS[usize::try_from(rng.range(0, 8)).expect("small")];
        let layer = METALS[usize::try_from(rng.range(0, 3)).expect("small")].0;
        writeln!(
            out,
            "- p{p} + NET n{p} + DIRECTION INPUT + USE SIGNAL\n  + PORT + LAYER {layer} ( -70 0 ) ( 70 {} ) + PLACED ( {x} {y} ) {orient} ;",
            rng.range(1, 20) * 20
        )
        .expect("a String");
    }
    out.push_str("END PINS\n");

    let specials = usize::try_from(rng.range(1, 3)).expect("small");
    writeln!(out, "SPECIALNETS {specials} ;").expect("a String");
    for s in 0..specials {
        let width = rng.range(1, 10) * 40;
        let origin = at(&mut rng);
        write!(
            out,
            "- s{s} ( * A ) + ROUTED {}",
            path(&mut rng, Some(width), origin)
        )
        .expect("a String");
        if rng.range(0, 2) == 0 {
            let origin = at(&mut rng);
            write!(out, "\n  NEW {}", path(&mut rng, Some(width), origin)).expect("a String");
        }
        let (x, y) = at(&mut rng);
        write!(
            out,
            "\n  NEW M2 0 ( {x} {y} ) fvia DO {} BY {} STEP 600 400 + USE POWER ;\n",
            rng.range(1, 4),
            rng.range(1, 3)
        )
        .expect("a String");
    }
    out.push_str("END SPECIALNETS\n");

    let nets = usize::try_from(rng.range(1, 6)).expect("small");
    writeln!(out, "NETS {} ;", nets + pins).expect("a String");
    for n in 0..nets + pins {
        write!(out, "- n{n}").expect("a String");
        if n < components {
            write!(out, " ( u{n} Y )").expect("a String");
        }
        if n < pins {
            write!(out, " ( PIN p{n} )").expect("a String");
        }
        let origin = at(&mut rng);
        write!(out, " + ROUTED {}", path(&mut rng, None, origin)).expect("a String");
        if rng.range(0, 2) == 0 {
            let origin = at(&mut rng);
            write!(out, "\n  NEW {}", path(&mut rng, None, origin)).expect("a String");
        }
        if rng.range(0, 3) == 0 {
            let (x, y) = at(&mut rng);
            write!(out, "\n  NEW M1 ( {x} {y} ) gvia").expect("a String");
        }
        out.push_str(" + USE SIGNAL ;\n");
    }
    out.push_str("END NETS\n");

    let fills = usize::try_from(rng.range(0, 3)).expect("small");
    writeln!(out, "FILLS {fills} ;").expect("a String");
    for _ in 0..fills {
        let (x, y) = at(&mut rng);
        let layer = METALS[usize::try_from(rng.range(0, 3)).expect("small")].0;
        writeln!(
            out,
            "- LAYER {layer} RECT ( {x} {y} ) ( {} {} ) ;",
            x + 500,
            y + 300
        )
        .expect("a String");
    }
    out.push_str("END FILLS\nEND DESIGN\n");
    out
}
