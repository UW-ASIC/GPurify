//! `gpurify fill` (FLOW-007) against `KLayout`'s fill on random layouts.
//!
//! The reference is `RBA::Cell#fill_region`: a 1 um fill cell stepped on a
//! 2 um grid from the die's lower-left corner over the region the deck
//! leaves free, the die less met1 and the no-fill boxes grown by the 1 um
//! keep-out (`Region#sized`, whose default mode keeps a right-angled corner
//! square, as `GPurify` measures it). The deck's minimum density is out of
//! reach, so `GPurify` fills every site it may, as `KLayout` does: the
//! achieved fill area must be equal, exactly.

use crate::harness::{self, Fixture, Layout, NONE};
use gpurify::engine::fill::fill_gds;
use gpurify::engine::pipeline::Inputs;
use gpurify_testgen::oracle;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

const DECK: &str = "grid 1nm
layer met1 = gds(1, 0)
layer fill1 = gds(1, 1)
layer nofill = gds(2, 0)
layer die = gds(3, 0)
layer m1all = met1 or fill1
rule pd density(m1all, die; window: 20um, step: 20um) >= 0.99
fill fill1 for m1all size 1um space 1um keep 1um avoid [met1, nofill]
";

/// Layouts compared.
const LAYOUTS: u64 = 200;

/// A 20 um die with random met1 wires and no-fill boxes on a 100 nm lattice.
fn layout(seed: u64) -> Layout {
    let mut rng = gpurify_testgen::Rng::new(seed);
    let mut layout = Layout::default().rect("die", 0, 0, 20_000, 20_000);
    for (layer, most, size) in [("met1", 8, 60), ("nofill", 3, 50)] {
        for _ in 0..rng.range(0, most) {
            let (x, y) = (rng.range(0, 200) * 100, rng.range(0, 200) * 100);
            let (w, h) = (rng.range(1, size) * 100, rng.range(1, size) * 100);
            layout = layout.rect(layer, x, y, (x + w).min(20_000), (y + h).min(20_000));
        }
    }
    layout
}

/// Per layout, the fill area `KLayout` places, in square database units.
const RUBY: &str = r##"
def region(layout, layer, datatype)
  index = layout.find_layer(layer, datatype)
  return RBA::Region::new if index.nil?
  RBA::Region::new(layout.top_cell.begin_shapes_rec(index))
end

LAYOUTS.each do |seed, path|
  ly = RBA::Layout::new
  ly.read(path)
  top = ly.top_cell
  die = region(ly, 3, 0)
  free = die - (region(ly, 1, 0) + region(ly, 2, 0)).merged.sized(1000)
  cell = ly.create_cell("FILL_#{seed}")
  cell.shapes(ly.layer(1, 1)).insert(RBA::Box::new(0, 0, 1000, 1000))
  corner = RBA::Point::new(die.bbox.left, die.bbox.bottom)
  top.fill_region(free, cell.cell_index, RBA::Box::new(0, 0, 1000, 1000),
                  RBA::Vector::new(2000, 0), RBA::Vector::new(0, 2000), corner,
                  nil, RBA::Vector::new(0, 0), nil, nil)
  top.flatten(true)
  puts "#{seed} #{region(ly, 1, 1).area}"
end
"##;

/// Oracle: differential against `KLayout`'s `Cell#fill_region` (module
/// docs): the same fill area, exactly, on 200 random layouts.
#[test]
#[ignore = "release tier: needs klayout (nix develop .#oracles)"]
fn maximal_fill_agrees_with_klayout_fill_region() {
    let klayout = oracle::tool("klayout");
    let dir = oracle::scratch("fill");
    let deck = dir.join("fill.deck");
    std::fs::write(&deck, DECK).expect("the scratch dir is writable");
    let mut ruby = String::from("LAYOUTS = [\n");
    let mut ours: BTreeMap<u64, i128> = BTreeMap::new();
    for seed in 0..LAYOUTS {
        let name = format!("{seed}.gds");
        let fixture = Fixture::new(&name, &[], DECK, NONE).layout(layout(seed));
        let (bytes, ..) = harness::written(&fixture).expect("the layout writes");
        std::fs::write(dir.join(&name), bytes).expect("writable");
        let inputs = Inputs {
            layout: dir.join(&name),
            deck: deck.clone(),
            ..Inputs::default()
        };
        let (_, squares) = fill_gds(&inputs, &[]).expect("fill runs");
        ours.insert(
            seed,
            i128::try_from(squares[0]).expect("a count") * 1_000_000,
        );
        writeln!(ruby, "  [{seed}, {name:?}],").expect("a String");
    }
    ruby.push_str("]\n");
    ruby.push_str(RUBY);
    std::fs::write(dir.join("fill.rb"), ruby).expect("writable");
    let stdout = oracle::run(
        &klayout,
        &["-b", "-r", "fill.rb"],
        &dir,
        Duration::from_mins(15),
    );
    let mut theirs: BTreeMap<u64, i128> = BTreeMap::new();
    for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
        let (seed, area) = line.split_once(' ').expect("seed and area");
        theirs.insert(
            seed.parse().expect("a seed"),
            area.trim().parse().expect("an area"),
        );
    }
    assert_eq!(theirs.len(), ours.len(), "KLayout answered every layout");
    let differ: Vec<String> = (ours.iter())
        .filter(|(seed, area)| theirs.get(seed) != Some(area))
        .map(|(seed, area)| format!("{seed}: ours {area}, KLayout {:?}", theirs.get(seed)))
        .collect();
    assert!(
        differ.is_empty(),
        "{} of {LAYOUTS} differ (files in {}):\n{}",
        differ.len(),
        dir.display(),
        differ.join("\n")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
