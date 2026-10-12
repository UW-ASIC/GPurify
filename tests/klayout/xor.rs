//! `gpurify xor` (DRC-068) against `KLayout`'s XOR on random layout pairs.
//!
//! The reference is `RBA::Region#^`, the boolean `KLayout`'s DRC `^`/`xor`
//! and its XOR tool compute, over each layer of the two files as `KLayout`
//! reads them. Per pair and layer, the area of `KLayout`'s merged XOR must
//! equal the sum of the areas `GPurify` reports, exactly: both count square
//! database units of the same 1 nm grid. How the difference splits into
//! regions where pieces meet at a corner is each tool's merge convention, so
//! the count of regions is not compared.

use crate::harness::{self, Fixture, Layout, NONE};
use gpurify::check::report::{Measurement, Outcome};
use gpurify::engine::pipeline::Inputs;
use gpurify_testgen::oracle;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

/// Three drawn layers, each a stream pair the Ruby side reads.
const DECK: &str = "grid 1nm
layer met1 = gds(68, 20)
layer via1 = gds(68, 44)
layer met2 = gds(69, 20)
";

/// The deck's layers: name and GDS layer and datatype.
const LAYERS: [(&str, u16, u16); 3] = [("met1", 68, 20), ("via1", 68, 44), ("met2", 69, 20)];

/// Layout pairs compared.
const PAIRS: u64 = 1000;

/// A layout of random rectangles on a 10 nm lattice, so shapes often touch,
/// abut and overlap, and a revision of it: each shape kept, dropped, or moved
/// by up to two lattice steps each way, and a few shapes added.
fn pair(seed: u64) -> (Layout, Layout) {
    let mut rng = gpurify_testgen::Rng::new(seed);
    let (mut a, mut b) = (Layout::default(), Layout::default());
    for (layer, most, size) in [("met1", 8, 60), ("via1", 6, 10), ("met2", 4, 40)] {
        for _ in 0..rng.range(0, most) {
            let (x, y) = (rng.range(0, 100) * 10, rng.range(0, 100) * 10);
            let (w, h) = (rng.range(1, size) * 10, rng.range(1, size) * 10);
            a = a.rect(layer, x, y, x + w, y + h);
            match rng.range(0, 4) {
                0 => {}
                1 => {
                    let (dx, dy) = (rng.range(-2, 3) * 10, rng.range(-2, 3) * 10);
                    b = b.rect(layer, x + dx, y + dy, x + dx + w, y + dy + h);
                }
                _ => b = b.rect(layer, x, y, x + w, y + h),
            }
        }
        for _ in 0..rng.range(0, 2) {
            let (x, y) = (rng.range(0, 100) * 10, rng.range(0, 100) * 10);
            let (w, h) = (rng.range(1, size) * 10, rng.range(1, size) * 10);
            b = b.rect(layer, x, y, x + w, y + h);
        }
    }
    (a, b)
}

/// `layout` as GDS at `dir/name`, through the harness's writer.
fn write(dir: &Path, name: &str, layout: Layout) {
    let fixture = Fixture::new(name, &[], DECK, NONE).layout(layout);
    let (bytes, ..) = harness::written(&fixture).expect("the layout writes");
    std::fs::write(dir.join(name), bytes).expect("the scratch dir is writable");
}

/// Reads each pair and prints `seed layer datatype area` per layer, the area
/// of the merged XOR in square database units.
const RUBY: &str = r##"
def region(layout, layer, datatype)
  index = layout.find_layer(layer, datatype)
  return RBA::Region::new if index.nil?
  RBA::Region::new(layout.top_cell.begin_shapes_rec(index))
end

PAIRS.each do |seed, a, b|
  la = RBA::Layout::new
  la.read(a)
  lb = RBA::Layout::new
  lb.read(b)
  LAYERS.each do |layer, datatype|
    puts "#{seed} #{layer} #{datatype} #{(region(la, layer, datatype) ^ region(lb, layer, datatype)).area}"
  end
end
"##;

/// Oracle: differential against `KLayout`'s XOR (`RBA::Region#^`, merged
/// area), exactly, per layer, on 1000 random pairs of a layout and its
/// revision.
#[test]
#[ignore = "release tier: needs klayout (nix develop .#oracles)"]
fn random_layout_pairs_agree_with_klayout_xor() {
    let klayout = oracle::tool("klayout");
    let dir = oracle::scratch("xor");
    let deck = dir.join("xor.deck");
    std::fs::write(&deck, DECK).expect("the scratch dir is writable");
    let mut ruby = String::from("PAIRS = [\n");
    let mut ours: BTreeMap<(u64, u16, u16), i128> = BTreeMap::new();
    for seed in 0..PAIRS {
        let (a, b) = pair(seed);
        let (name_a, name_b) = (format!("{seed}a.gds"), format!("{seed}b.gds"));
        write(&dir, &name_a, a);
        write(&dir, &name_b, b);
        writeln!(ruby, "  [{seed}, {name_a:?}, {name_b:?}],").expect("a String");
        let inputs = Inputs {
            layout: dir.join(&name_a),
            deck: deck.clone(),
            reference: Vec::new(),
            intent: None,
        };
        let (loaded, outputs, _) =
            gpurify::engine::xor::run(&inputs, &dir.join(&name_b)).expect("both layouts load");
        assert!(
            outputs.runs.iter().all(|run| run.outcome == Outcome::Ran),
            "{seed}: a rectangle layer is always compared"
        );
        for &(_, layer, datatype) in &LAYERS {
            ours.insert((seed, layer, datatype), 0);
        }
        let v = &outputs.violations;
        for i in 0..v.len() {
            let Measurement::Area(area) = v.measured[i] else {
                panic!("xor measures areas");
            };
            let name = loaded.strings.resolve(v.rule[i]);
            let &(_, layer, datatype) = LAYERS
                .iter()
                .find(|(layer, ..)| name == format!("xor.{layer}"))
                .expect("a row per deck layer");
            *ours.get_mut(&(seed, layer, datatype)).expect("seeded") += area.raw();
        }
    }
    ruby.push_str("]\nLAYERS = [[68, 20], [68, 44], [69, 20]]\n");
    ruby.push_str(RUBY);
    std::fs::write(dir.join("xor.rb"), ruby).expect("the scratch dir is writable");
    let stdout = oracle::run(
        &klayout,
        &["-b", "-r", "xor.rb"],
        &dir,
        Duration::from_secs(900),
    );

    let mut theirs: BTreeMap<(u64, u16, u16), i128> = BTreeMap::new();
    for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [seed, layer, datatype, area] = fields[..] else {
            panic!("unexpected KLayout output: {line}");
        };
        let parse = |text: &str| text.parse::<i128>().expect("an integer");
        theirs.insert(
            (
                seed.parse().expect("a seed"),
                layer.parse().expect("a layer"),
                datatype.parse().expect("a datatype"),
            ),
            parse(area),
        );
    }
    assert_eq!(
        theirs.len(),
        ours.len(),
        "KLayout reported every pair and layer"
    );
    let differing = ours.values().filter(|&&area| area > 0).count();
    assert!(
        differing > 0 && differing < ours.len(),
        "the pairs differ on some layers and not on others ({differing} of {})",
        ours.len()
    );
    let disagree: Vec<String> = ours
        .iter()
        .filter(|&(key, area)| theirs.get(key) != Some(area))
        .map(|(key, area)| format!("{key:?}: GPurify {area}, KLayout {:?}", theirs.get(key)))
        .collect();
    assert!(
        disagree.is_empty(),
        "{} of {} layers disagree:\n{}",
        disagree.len(),
        ours.len(),
        disagree.join("\n")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
