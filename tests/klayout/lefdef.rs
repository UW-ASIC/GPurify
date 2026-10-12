//! The LEF/DEF reader (`gpurify_ingest::lefdef`) against `KLayout`'s LEF/DEF
//! reader, on seeded designs (`tests/common/lefdef_gen.rs`): every orientation
//! of a macro with an `ORIGIN`, a polygon pin and obstructions, regular and
//! special wires with default and explicit extensions, a fixed and two
//! generated vias (one with a cut pattern, an origin and an offset), via
//! arrays, placed pins in every orientation, and fill.
//!
//! **Compared.** Per design and layer, the merged area of the XOR between
//! the shapes `GPurify` draws (`flatten`, then `to_gds`, as a run reads a
//! DEF) and every shape `KLayout` draws on the layer of that name, whatever
//! its purpose (`M1`, `M1.PIN`, `M1.OBS`, `M1.FILL`): 0, exactly, in square
//! nanometres. Labels are text and not shapes; a placement blockage is not
//! drawn by either.

use crate::lefdef_gen;
use gpurify::geom::Grid;
use gpurify_ingest::deck::parse_deck;
use gpurify_ingest::lefdef;
use gpurify_ingest::StrTable;
use gpurify_testgen::oracle;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

/// Designs compared.
const DESIGNS: u64 = 200;

/// The design's five layers as GDS layers 1 to 5.
const DECK: &str = "layer M1 = gds(1, 0)\nlayer V1 = gds(2, 0)\nlayer M2 = gds(3, 0)\n\
                    layer V2 = gds(4, 0)\nlayer M3 = gds(5, 0)\n";

/// `GPurify`'s drawing of the design, as GDSII.
fn ours(lef_text: &str, def_text: &str) -> Vec<u8> {
    let mut lef = lefdef::Lef::default();
    lefdef::read_lef_into(lef_text, 1000, &mut lef).expect("the LEF reads");
    let def = lefdef::read_def(def_text, &lef).expect("the DEF reads");
    let flat = lefdef::flatten(&def, &lef).expect("the design flattens");
    let mut strings = StrTable::default();
    let deck =
        parse_deck(DECK, Grid::new(1000).expect("a grid"), &mut strings).expect("the deck parses");
    lefdef::to_gds(
        &flat,
        1000,
        &def.design,
        &deck.layers,
        &deck.connectivity,
        &strings,
    )
    .expect("the design writes")
}

/// Reads each pair and prints `seed layer xor ours theirs` areas; the
/// first design also lists the layers `KLayout` made.
const RUBY: &str = r##"
LAYERS = [["M1", 1], ["V1", 2], ["M2", 3], ["V2", 4], ["M3", 5]]
DESIGNS.each_with_index do |(seed, gds, def), k|
  a = RBA::Layout::new
  a.read(gds)
  opt = RBA::LoadLayoutOptions::new
  c = opt.lefdef_config
  c.dbu = 0.001
  c.read_lef_with_def = false
  c.lef_files = [File.expand_path("tech.lef")]
  b = RBA::Layout::new
  b.read(def, opt)
  if k == 0
    b.layer_indexes.each { |li| puts "layer #{b.get_info(li).to_s}" }
  end
  LAYERS.each do |name, number|
    index = a.find_layer(number, 0)
    ra = index.nil? ? RBA::Region::new : RBA::Region::new(a.top_cell.begin_shapes_rec(index))
    rb = RBA::Region::new
    b.layer_indexes.each do |li|
      info = b.get_info(li)
      label = info.name.to_s.empty? ? info.to_s : info.name.to_s
      rb.insert(b.top_cell.begin_shapes_rec(li)) if label.split(".")[0] == name
    end
    puts "#{seed} #{name} #{(ra ^ rb).area} #{ra.area} #{rb.area}"
  end
end
"##;

/// Every seeded design is one the reader takes, so the differential below
/// compares drawings rather than refusals.
///
/// Oracle: construct-from-answer: the generator writes only statements the
/// reader's module docs list as read, so each design must read, flatten and
/// write, and each draws on at least three of its five layers.
#[test]
fn every_seeded_design_reads_and_draws() {
    let lef_text = lefdef_gen::lef();
    for seed in 0..DESIGNS {
        let bytes = ours(&lef_text, &lefdef_gen::def(seed));
        let mut strings = StrTable::default();
        let library = gpurify_ingest::layout::gds::Library::parse(&bytes, &mut strings)
            .expect("the stream reads back");
        let deck = parse_deck(DECK, Grid::new(1000).expect("a grid"), &mut strings)
            .expect("the deck parses");
        let (store, _) = library
            .flatten(
                &deck,
                &strings,
                gpurify_ingest::layout::UnknownLayers::Reject,
            )
            .expect("flattens");
        let layers = (0..5)
            .filter(|&l| !store.polys_on_layer(gpurify::geom::LayerId(l)).is_empty())
            .count();
        assert!(layers >= 3, "design {seed} draws on {layers} layers");
    }
}

/// Oracle: differential against `KLayout`'s LEF/DEF reader (module docs):
/// the merged XOR of the two drawings is empty on every layer of 200
/// seeded designs.
#[test]
#[ignore = "release tier: needs klayout (nix develop .#oracles)"]
fn klayout_lefdef_differential_on_seeded_designs() {
    let klayout = oracle::tool("klayout");
    let dir = oracle::scratch("lefdef");
    let lef_text = lefdef_gen::lef();
    std::fs::write(dir.join("tech.lef"), &lef_text).expect("the scratch dir is writable");
    let mut ruby = String::from("DESIGNS = [\n");
    for seed in 0..DESIGNS {
        let def_text = lefdef_gen::def(seed);
        let (gds, def) = (format!("ours{seed}.gds"), format!("d{seed}.def"));
        std::fs::write(dir.join(&gds), ours(&lef_text, &def_text)).expect("writable");
        std::fs::write(dir.join(&def), &def_text).expect("writable");
        writeln!(ruby, "  [{seed}, {gds:?}, {def:?}],").expect("a String");
    }
    ruby.push_str("]\n");
    ruby.push_str(RUBY);
    std::fs::write(dir.join("lefdef.rb"), ruby).expect("writable");
    let stdout = oracle::run(
        &klayout,
        &["-b", "-r", "lefdef.rb"],
        &dir,
        Duration::from_mins(30),
    );

    let mut rows: BTreeMap<(u64, String), [i128; 3]> = BTreeMap::new();
    let mut layers = Vec::new();
    for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
        if let Some(layer) = line.strip_prefix("layer ") {
            layers.push(layer.to_owned());
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [seed, layer, xor, ours, theirs] = fields[..] else {
            panic!("unexpected KLayout output: {line}");
        };
        let area = |t: &str| t.parse::<i128>().expect("an area");
        rows.insert(
            (seed.parse().expect("a seed"), layer.to_owned()),
            [area(xor), area(ours), area(theirs)],
        );
    }
    let total = 5 * usize::try_from(DESIGNS).expect("small");
    assert_eq!(rows.len(), total, "KLayout reported every design and layer");
    let drawn = rows.values().filter(|r| r[1] > 0).count();
    assert!(
        drawn > total / 2,
        "{drawn} of {total} layers draw something"
    );
    let disagree: Vec<String> = rows
        .iter()
        .filter(|(_, r)| r[0] != 0)
        .map(|((seed, layer), r)| {
            format!(
                "design {seed} {layer}: xor {} (GPurify {}, KLayout {})",
                r[0], r[1], r[2]
            )
        })
        .collect();
    assert!(
        disagree.is_empty(),
        "{} of {total} layers disagree (KLayout's layers: {layers:?}; files kept in {}):\n{}",
        disagree.len(),
        dir.display(),
        disagree.join("\n")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
