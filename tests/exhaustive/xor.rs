//! `gpurify xor` (DRC-068): two layouts compared layer by layer, against
//! areas worked out by hand. The fixtures above hold one layout each, so these
//! are `#[test]`s; the differential against `KLayout`'s XOR on random pairs is
//! `tests/klayout/xor.rs`.

use crate::harness::{self, Fixture, Layout, NONE};
use gpurify::check::report::{Measurement, Outcome};
use gpurify::engine::pipeline::Inputs;
use gpurify::engine::run::StageStatus;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Three drawn layers and one derived from two of them, which `xor` leaves
/// out.
const DECK: &str = "grid 1nm
layer met1 = gds(68, 20)
layer via1 = gds(68, 44)
layer met2 = gds(69, 20)
layer both = met1 and met2
";

/// Per rule row: its outcome and the areas it measured, ascending, in nm².
type Report = BTreeMap<String, (Outcome, Vec<i128>)>;

/// `layout` written as GDS into `dir`, on the 1 nm grid.
fn write(dir: &Path, name: &str, layout: Layout) -> PathBuf {
    let fixture = Fixture::new(name, &[], DECK, NONE).layout(layout);
    let (bytes, ..) = harness::written(&fixture).expect("the layout writes");
    let path = dir.join(format!("{name}.gds"));
    std::fs::write(&path, bytes).expect("the target dir is writable");
    path
}

/// `gpurify xor a b` through the real reader, as rows, and whether it passed.
fn xor(tag: &str, a: Layout, b: Layout) -> (Report, bool) {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("xor").join(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the target dir is writable");
    let deck = dir.join("xor.deck");
    std::fs::write(&deck, DECK).expect("the target dir is writable");
    let inputs = Inputs {
        layout: write(&dir, "a", a),
        deck,
        reference: None,
        intent: None,
    };
    let (loaded, outputs, summary) =
        gpurify::engine::xor::run(&inputs, &write(&dir, "b", b)).expect("both layouts load");
    assert_eq!(summary.drc, StageStatus::Ran);
    assert_eq!(summary.erc, StageStatus::NotSelected);
    let name = |id| loaded.strings.resolve(id).to_owned();
    let mut report: Report = outputs
        .runs
        .iter()
        .map(|run| (name(run.rule), (run.outcome, Vec::new())))
        .collect();
    let v = &outputs.violations;
    for i in 0..v.len() {
        let Measurement::Area(area) = v.measured[i] else {
            panic!("xor measures areas, not {:?}", v.measured[i]);
        };
        report
            .get_mut(&name(v.rule[i]))
            .expect("a row for every finding")
            .1
            .push(area.raw());
    }
    for (_, areas) in report.values_mut() {
        areas.sort_unstable();
    }
    (report, summary.passed())
}

/// The rows of a run in which no layer differs.
fn clean() -> Report {
    ["xor.met1", "xor.met2", "xor.via1"]
        .into_iter()
        .map(|id| (id.to_owned(), (Outcome::Ran, Vec::new())))
        .collect()
}

/// A layout with a shape on every drawn layer.
fn sample() -> Layout {
    Layout::default()
        .rect("met1", 0, 0, 1000, 200)
        .rect("via1", 50, 50, 150, 150)
        .rect("met2", 0, 0, 200, 1000)
}

/// Oracle: law (`A xor A` is empty): a layout against itself differs nowhere;
/// every drawn layer has a row, the derived one none, and the run passes.
#[test]
fn a_layout_against_itself_differs_nowhere() {
    let (report, passed) = xor("same", sample(), sample());
    assert_eq!(report, clean());
    assert!(passed);
}

/// Oracle: hand-derived areas. met1 `[0, 1000] × [0, 1000]` against
/// `[500, 1500] × [0, 1000]`: the strips `[0, 500]` and `[1000, 1500]`
/// differ, 500 × 1000 = 500000 nm² each. met2, drawn only in `a` as two
/// overlapping 1000 nm squares offset by 500, differs over their union, one
/// region of 1500 × 1000 = 1500000 nm², not 2000000.
#[test]
fn moved_and_missing_shapes_differ_by_their_area() {
    let a = Layout::default()
        .rect("met1", 0, 0, 1000, 1000)
        .rect("met2", 0, 0, 1000, 1000)
        .rect("met2", 500, 0, 1500, 1000);
    let b = Layout::default().rect("met1", 500, 0, 1500, 1000);
    let (report, passed) = xor("moved", a, b);
    assert_eq!(report["xor.met1"], (Outcome::Ran, vec![500_000, 500_000]));
    assert_eq!(report["xor.met2"], (Outcome::Ran, vec![1_500_000]));
    assert_eq!(report["xor.via1"], (Outcome::Ran, Vec::new()));
    assert!(!passed);
}

/// The case sky130's IR-drop rules describe: four 150 nm cuts (`via.1a`'s
/// size) in `a`; in `b` the second is gone and the third slotted to 110 nm,
/// centred.
fn cuts() -> (Layout, Layout) {
    let cut = |layout: Layout, x: i64, size: i64| {
        let o = (150 - size) / 2;
        layout.rect("via1", x + o, o, x + o + size, o + size)
    };
    let a = (0..4).fold(Layout::default(), |layout, i| cut(layout, i * 320, 150));
    let b = cut(cut(cut(Layout::default(), 0, 150), 640, 110), 960, 150);
    (a, b)
}

/// Oracle: construct-from-answer. The lost cut differs by its 22500 nm²; the
/// slotted one by the ring around its slot, 22500 − 12100 = 10400 nm², one
/// region with a hole. Together they are the cut area `b` lost,
/// 4 × 22500 − (3 × 22500 − 10400) = 32900 nm².
#[test]
fn a_lost_and_a_slotted_cut_add_up_to_the_cut_area_lost() {
    let (a, b) = cuts();
    let (report, passed) = xor("cuts", a, b);
    let (outcome, areas) = &report["xor.via1"];
    assert_eq!(*outcome, Outcome::Ran);
    assert_eq!(areas, &[10_400, 22_500]);
    assert_eq!(
        areas.iter().sum::<i128>(),
        4 * 22_500 - (3 * 22_500 - 10_400)
    );
    assert!(!passed);
}

/// Oracle: metamorphic relation (`A xor B = B xor A`): swapping the two
/// layouts of the cases above changes no row.
#[test]
fn swapping_the_layouts_changes_no_row() {
    let moved = (
        Layout::default().rect("met1", 0, 0, 1000, 1000),
        Layout::default()
            .rect("met1", 500, 0, 1500, 1000)
            .rect("met2", 0, 0, 1000, 1000),
    );
    for (tag, (a, b)) in [("swap-moved", moved), ("swap-cuts", cuts())] {
        let forward = xor(&format!("{tag}-ab"), a.clone(), b.clone());
        let back = xor(&format!("{tag}-ba"), b, a);
        assert_eq!(forward, back, "{tag}");
        assert_ne!(forward.0, clean(), "{tag}: the case differs somewhere");
    }
}

/// Oracle: the module's definition: a layer `xor` cannot compare exactly, a
/// 45° edge on via1 here, is refused, which fails the run, and the other
/// layers still compare.
#[test]
fn a_layer_with_a_45_degree_edge_is_refused_not_compared() {
    let a = sample().polygon("via1", &[(400, 400), (600, 400), (400, 600)]);
    let (report, passed) = xor("diagonal", a.clone(), a);
    assert_eq!(report["xor.via1"].0, Outcome::Refused);
    assert_eq!(report["xor.met1"], (Outcome::Ran, Vec::new()));
    assert!(!passed);
}
