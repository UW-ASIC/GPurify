//! The LEF/DEF reader's special wiring (`gpurify_ingest::lefdef`) against
//! `OpenROAD`'s DEF reader (`OpenDB`), on seeded designs
//! (`tests/common/lefdef_gen.rs`, free mode): special wires that turn
//! corners, extensions on any point and after a via, via arrays.
//!
//! **Compared.** Per special net, the multiset of its wire rectangles (layer
//! and box) and of its vias' boxes, as `OpenDB` stores them (`dbSBox`: a
//! wire segment's box, a via's bounding box, one box per via of a `DO`
//! array), against the same from [`lefdef::read_def`]: each wire segment's
//! [`lefdef::Wire::rect`] and each placed via's shapes' bounding box. Equal,
//! exactly. This is where the reader and `KLayout` part (a special wire's
//! corner, which `KLayout` joins and LEF/DEF 5.8 p. 321 and `OpenDB` leave
//! as two segments), so the reference decides.

use crate::lefdef_gen;
use gpurify_ingest::lefdef;
use gpurify_testgen::oracle;
use std::collections::BTreeMap;
use std::time::Duration;

/// Designs compared.
const DESIGNS: u64 = 100;

/// One special net's boxes: wires as `(layer, box)` and vias as boxes.
type Boxes = (Vec<(String, [i64; 4])>, Vec<[i64; 4]>);

/// The reader's special wiring of `def_text`, per net.
fn ours(lef_text: &str, def_text: &str) -> BTreeMap<String, Boxes> {
    let mut lef = lefdef::Lef::default();
    lefdef::read_lef_into(lef_text, 1000, &mut lef).expect("the LEF reads");
    let def = lefdef::read_def(def_text, &lef).expect("the DEF reads");
    let mut out: BTreeMap<String, Boxes> = BTreeMap::new();
    for net in def.nets.iter().filter(|n| n.special) {
        let entry = out.entry(net.name.clone()).or_default();
        for wire in &net.wires {
            let ((x0, y0), (x1, y1)) = wire.rect();
            if x0 < x1 && y0 < y1 {
                entry.0.push((wire.layer.clone(), [x0, y0, x1, y1]));
            }
        }
        for via in &net.vias {
            let shapes = def
                .vias
                .iter()
                .chain(&lef.vias)
                .find(|(n, _)| *n == via.name)
                .map(|(_, s)| s)
                .expect("a defined via");
            for i in 0..via.array.0 {
                for j in 0..via.array.1 {
                    let at = (via.at.0 + i * via.array.2, via.at.1 + j * via.array.3);
                    let b =
                        shapes
                            .iter()
                            .fold([i64::MAX, i64::MAX, i64::MIN, i64::MIN], |b, shape| {
                                shape.ring.iter().fold(b, |b, &p| {
                                    let (x, y) = via.orient.apply(p);
                                    let (x, y) = (x + at.0, y + at.1);
                                    [b[0].min(x), b[1].min(y), b[2].max(x), b[3].max(y)]
                                })
                            });
                    entry.1.push(b);
                }
            }
        }
        entry.0.sort();
        entry.1.sort_unstable();
    }
    out
}

/// Prints every special net's boxes, wires as `W net layer box` and vias as
/// `V net box`.
const TCL: &str = r#"
set out [open boxes.txt w]
set block [ord::get_db_block]
foreach net [$block getNets] {
  foreach swire [$net getSWires] {
    foreach box [$swire getWires] {
      set b "[$box xMin] [$box yMin] [$box xMax] [$box yMax]"
      if {[$box isVia]} {
        puts $out "V [$net getName] $b"
      } else {
        puts $out "W [$net getName] [[$box getTechLayer] getName] $b"
      }
    }
  }
}
close $out
"#;

/// Oracle: differential against `OpenROAD`'s DEF reader (module docs): the
/// special wiring of 100 seeded designs, box for box.
#[test]
#[ignore = "release tier: needs openroad (nix develop .#oracles)"]
fn openroad_lefdef_differential_on_special_wiring() {
    let openroad = oracle::tool("openroad");
    let dir = oracle::scratch("lefdef-openroad");
    let lef_text = lefdef_gen::lef();
    std::fs::write(dir.join("tech.lef"), &lef_text).expect("writable");
    let mut disagree = Vec::new();
    let mut compared = 0;
    for seed in 0..DESIGNS {
        let def_text = lefdef_gen::def(seed, true);
        std::fs::write(dir.join("top.def"), &def_text).expect("writable");
        std::fs::write(
            dir.join("dump.tcl"),
            format!("read_lef tech.lef\nread_def top.def\n{TCL}"),
        )
        .expect("writable");
        let _ = std::fs::remove_file(dir.join("boxes.txt"));
        oracle::run(
            &openroad,
            &["-no_init", "-no_splash", "-exit", "dump.tcl"],
            &dir,
            Duration::from_mins(5),
        );
        let text = std::fs::read_to_string(dir.join("boxes.txt")).unwrap_or_default();
        let mut theirs: BTreeMap<String, Boxes> = BTreeMap::new();
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            let number = |t: &str| t.parse::<i64>().expect("a coordinate");
            match f[..] {
                ["W", net, layer, a, b, c, d] => {
                    theirs.entry(net.to_owned()).or_default().0.push((
                        layer.to_owned(),
                        [number(a), number(b), number(c), number(d)],
                    ));
                }
                ["V", net, a, b, c, d] => theirs.entry(net.to_owned()).or_default().1.push([
                    number(a),
                    number(b),
                    number(c),
                    number(d),
                ]),
                _ => panic!("unexpected OpenROAD output: {line}"),
            }
        }
        for boxes in theirs.values_mut() {
            boxes.0.sort();
            boxes.1.sort_unstable();
        }
        let ours = ours(&lef_text, &def_text);
        compared += ours.values().map(|b| b.0.len() + b.1.len()).sum::<usize>();
        if ours != theirs {
            disagree.push(format!(
                "design {seed}:\n  GPurify {ours:?}\n  OpenROAD {theirs:?}"
            ));
        }
    }
    assert!(compared > 100, "{compared} boxes compared");
    assert!(
        disagree.is_empty(),
        "{} of {DESIGNS} designs disagree (files in {}):\n{}",
        disagree.len(),
        dir.display(),
        disagree.join("\n")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
